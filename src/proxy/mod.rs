pub mod http;
pub mod stdio;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::Utc;

use crate::audit::{AuditDecision, AuditLogger, AuditRecord};
use crate::config::PolicyConfig;
use crate::error::Result;
use crate::jsonrpc::JsonRpcMessage;
use crate::policy::{Decision, PolicyEngine};
use crate::sanitizer::{OutputSanitizer, SanitizeOutcome};

/// Action to take after inspecting an incoming client-to-server JSON-RPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    /// Forward the JSON line to the upstream MCP server.
    Forward(String),
    /// Do not forward; reply immediately to the client with this JSON-RPC error line.
    ImmediateReply(String),
}

#[derive(Debug, Clone)]
struct PendingCall {
    method: String,
    tool: Option<String>,
    started_at: Instant,
}

/// Atomic runtime counters for `/_mcp_guard/metrics` and `/_mcp_guard/health`.
#[derive(Debug)]
pub struct GuardMetrics {
    pub requests_total: AtomicU64,
    pub allowed_total: AtomicU64,
    pub denied_total: AtomicU64,
    pub redacted_total: AtomicU64,
    pub responses_blocked_total: AtomicU64,
    pub tools_filtered_total: AtomicU64,
    pub started_at: Instant,
}

impl Default for GuardMetrics {
    fn default() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            allowed_total: AtomicU64::new(0),
            denied_total: AtomicU64::new(0),
            redacted_total: AtomicU64::new(0),
            responses_blocked_total: AtomicU64::new(0),
            tools_filtered_total: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }
}

/// Shared proxy state combining policy evaluation, output sanitization, and audit logging.
#[derive(Debug, Clone)]
pub struct GuardContext {
    engine: Arc<PolicyEngine>,
    sanitizer: Arc<OutputSanitizer>,
    audit: Arc<AuditLogger>,
    pending: Arc<Mutex<HashMap<String, PendingCall>>>,
    metrics: Arc<GuardMetrics>,
}

impl GuardContext {
    /// Build a `GuardContext` from a `PolicyConfig`.
    pub fn new(config: &PolicyConfig) -> Result<Self> {
        Ok(Self {
            engine: Arc::new(PolicyEngine::new(config)?),
            sanitizer: Arc::new(OutputSanitizer::new(config.sanitizer.clone())?),
            audit: Arc::new(AuditLogger::new(config.audit.clone())?),
            pending: Arc::new(Mutex::new(HashMap::new())),
            metrics: Arc::new(GuardMetrics::default()),
        })
    }

    /// Logical server name from the active policy.
    pub fn server_name(&self) -> &str {
        self.engine.server_name()
    }

    /// Seconds elapsed since this `GuardContext` was created.
    pub fn uptime_secs(&self) -> u64 {
        self.metrics.started_at.elapsed().as_secs()
    }

    /// Render Prometheus text-format metrics for `/_mcp_guard/metrics`.
    pub fn render_prometheus(&self) -> String {
        let server = self.engine.server_name();
        format!(
            "# HELP mcp_guard_requests_total Total client JSON-RPC requests evaluated.\n             # TYPE mcp_guard_requests_total counter\n             mcp_guard_requests_total{{server=\"{server}\"}} {}\n             # HELP mcp_guard_allowed_total Total client requests allowed.\n             # TYPE mcp_guard_allowed_total counter\n             mcp_guard_allowed_total{{server=\"{server}\"}} {}\n             # HELP mcp_guard_denied_total Total client requests denied by policy.\n             # TYPE mcp_guard_denied_total counter\n             mcp_guard_denied_total{{server=\"{server}\"}} {}\n             # HELP mcp_guard_redacted_total Total server responses with redacted secrets.\n             # TYPE mcp_guard_redacted_total counter\n             mcp_guard_redacted_total{{server=\"{server}\"}} {}\n             # HELP mcp_guard_responses_blocked_total Total server responses blocked for prompt injection.\n             # TYPE mcp_guard_responses_blocked_total counter\n             mcp_guard_responses_blocked_total{{server=\"{server}\"}} {}\n             # HELP mcp_guard_tools_filtered_total Total tools stripped from tools/list responses.\n             # TYPE mcp_guard_tools_filtered_total counter\n             mcp_guard_tools_filtered_total{{server=\"{server}\"}} {}\n             # HELP mcp_guard_uptime_seconds Seconds since proxy startup.\n             # TYPE mcp_guard_uptime_seconds gauge\n             mcp_guard_uptime_seconds{{server=\"{server}\"}} {}\n",
            self.metrics.requests_total.load(Ordering::Relaxed),
            self.metrics.allowed_total.load(Ordering::Relaxed),
            self.metrics.denied_total.load(Ordering::Relaxed),
            self.metrics.redacted_total.load(Ordering::Relaxed),
            self.metrics.responses_blocked_total.load(Ordering::Relaxed),
            self.metrics.tools_filtered_total.load(Ordering::Relaxed),
            self.uptime_secs(),
        )
    }

    /// Evaluate an incoming client JSON-RPC line (single message or JSON-RPC batch array).
    pub fn process_client_line(&self, line: &str) -> ClientAction {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ClientAction::Forward(line.to_string());
        }

        if trimmed.starts_with('[') {
            let Ok(batch) = serde_json::from_str::<Vec<JsonRpcMessage>>(trimmed) else {
                return ClientAction::Forward(trimmed.to_string());
            };
            let mut denied_replies = Vec::new();
            let mut any_denied = false;
            let mut denied_reason = String::new();
            for item in &batch {
                if let Err(err_msg) = self.evaluate_single_client_msg(item) {
                    any_denied = true;
                    if denied_reason.is_empty() {
                        denied_reason = err_msg
                            .error
                            .as_ref()
                            .map(|e| e.message.clone())
                            .unwrap_or_else(|| "PolicyDenied".to_string());
                    }
                    if item.id.is_some() {
                        denied_replies.push(*err_msg);
                    }
                }
            }
            if any_denied {
                // Reject the entire batch so partial/disallowed calls never reach upstream.
                let replies = if denied_replies.is_empty() {
                    vec![JsonRpcMessage::policy_denied(None, denied_reason)]
                } else {
                    batch
                        .into_iter()
                        .filter_map(|item| {
                            item.id.as_ref()?;
                            Some(JsonRpcMessage::policy_denied(
                                item.id,
                                denied_reason.clone(),
                            ))
                        })
                        .collect()
                };
                let out = serde_json::to_string(&replies)
                    .unwrap_or_else(|_| r#"[{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"PolicyDenied"}}]"#.to_string());
                return ClientAction::ImmediateReply(out);
            }
            return ClientAction::Forward(trimmed.to_string());
        }

        let Ok(msg) = serde_json::from_str::<JsonRpcMessage>(trimmed) else {
            // Pass through non-standard lines untouched rather than breaking framing.
            return ClientAction::Forward(trimmed.to_string());
        };

        match self.evaluate_single_client_msg(&msg) {
            Ok(()) => ClientAction::Forward(trimmed.to_string()),
            Err(err_msg) => {
                let out = serde_json::to_string(&err_msg)
                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"PolicyDenied"}}"#.to_string());
                ClientAction::ImmediateReply(out)
            }
        }
    }

    fn evaluate_single_client_msg(
        &self,
        msg: &JsonRpcMessage,
    ) -> std::result::Result<(), Box<JsonRpcMessage>> {
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        let start = Instant::now();
        match self.engine.evaluate_request(msg) {
            Decision::Allow => {
                self.metrics.allowed_total.fetch_add(1, Ordering::Relaxed);
                if let (Some(id), Some(method)) = (&msg.id, &msg.method) {
                    let key = serde_json::to_string(id).unwrap_or_default();
                    let call = PendingCall {
                        method: method.clone(),
                        tool: msg.tool_name().map(str::to_string),
                        started_at: start,
                    };
                    if let Ok(mut map) = self.pending.lock() {
                        map.insert(key, call);
                    }
                }
                Ok(())
            }
            Decision::Deny(reason) => {
                self.metrics.denied_total.fetch_add(1, Ordering::Relaxed);
                let latency_us = start.elapsed().as_micros() as u64;
                let _ = self.audit.log(&AuditRecord {
                    timestamp: Utc::now(),
                    server: self.engine.server_name().to_string(),
                    method: msg.method.clone().unwrap_or_else(|| "unknown".to_string()),
                    tool: msg.tool_name().map(str::to_string),
                    decision: AuditDecision::Deny,
                    reason: Some(reason.clone()),
                    latency_us,
                });
                Err(Box::new(JsonRpcMessage::policy_denied(
                    msg.id.clone(),
                    reason,
                )))
            }
        }
    }

    /// Sanitize an outgoing server-to-client JSON-RPC line and record its audit entry.
    pub fn process_server_line(&self, line: &str) -> String {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return line.to_string();
        }

        if trimmed.starts_with('[') {
            let Ok(batch) = serde_json::from_str::<Vec<JsonRpcMessage>>(trimmed) else {
                return trimmed.to_string();
            };
            let processed: Vec<JsonRpcMessage> = batch
                .into_iter()
                .map(|m| self.process_single_server_msg(m))
                .collect();
            return serde_json::to_string(&processed).unwrap_or_else(|_| trimmed.to_string());
        }

        let Ok(msg) = serde_json::from_str::<JsonRpcMessage>(trimmed) else {
            return trimmed.to_string();
        };
        let out = self.process_single_server_msg(msg);
        serde_json::to_string(&out).unwrap_or_else(|_| trimmed.to_string())
    }

    fn process_single_server_msg(&self, mut msg: JsonRpcMessage) -> JsonRpcMessage {
        let pending = msg.id.as_ref().and_then(|id| {
            let key = serde_json::to_string(id).unwrap_or_default();
            self.pending.lock().ok().and_then(|mut m| m.remove(&key))
        });

        let (method, tool, started_at) = match pending {
            Some(p) => (p.method, p.tool, p.started_at),
            None => (
                msg.method.clone().unwrap_or_else(|| "response".to_string()),
                None,
                Instant::now(),
            ),
        };

        if msg.is_response() {
            if method == "tools/list" {
                let filtered = self.engine.filter_tools_list_response(&mut msg);
                if filtered > 0 {
                    self.metrics
                        .tools_filtered_total
                        .fetch_add(filtered as u64, Ordering::Relaxed);
                }
            }
            match self.sanitizer.sanitize_message(&mut msg) {
                SanitizeOutcome::Clean => {
                    let _ = self.audit.log(&AuditRecord {
                        timestamp: Utc::now(),
                        server: self.engine.server_name().to_string(),
                        method,
                        tool,
                        decision: AuditDecision::Allow,
                        reason: None,
                        latency_us: started_at.elapsed().as_micros() as u64,
                    });
                }
                SanitizeOutcome::Redacted(tags) => {
                    self.metrics.redacted_total.fetch_add(1, Ordering::Relaxed);
                    let reason = tags.join(", ");
                    let _ = self.audit.log(&AuditRecord {
                        timestamp: Utc::now(),
                        server: self.engine.server_name().to_string(),
                        method,
                        tool,
                        decision: AuditDecision::Redact,
                        reason: Some(reason),
                        latency_us: started_at.elapsed().as_micros() as u64,
                    });
                }
                SanitizeOutcome::Blocked(reason) => {
                    self.metrics
                        .responses_blocked_total
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = self.audit.log(&AuditRecord {
                        timestamp: Utc::now(),
                        server: self.engine.server_name().to_string(),
                        method,
                        tool,
                        decision: AuditDecision::Deny,
                        reason: Some(reason.clone()),
                        latency_us: started_at.elapsed().as_micros() as u64,
                    });
                    return JsonRpcMessage::policy_denied(msg.id, reason);
                }
            }
        }

        msg
    }
}
