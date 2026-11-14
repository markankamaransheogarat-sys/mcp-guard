pub mod http;
pub mod stdio;

use std::collections::HashMap;
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

/// Shared proxy state combining policy evaluation, output sanitization, and audit logging.
#[derive(Debug, Clone)]
pub struct GuardContext {
    engine: Arc<PolicyEngine>,
    sanitizer: Arc<OutputSanitizer>,
    audit: Arc<AuditLogger>,
    pending: Arc<Mutex<HashMap<String, PendingCall>>>,
}

impl GuardContext {
    /// Build a `GuardContext` from a `PolicyConfig`.
    pub fn new(config: &PolicyConfig) -> Result<Self> {
        Ok(Self {
            engine: Arc::new(PolicyEngine::new(config)?),
            sanitizer: Arc::new(OutputSanitizer::new(config.sanitizer.clone())?),
            audit: Arc::new(AuditLogger::new(config.audit.clone())?),
            pending: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Evaluate an incoming client JSON-RPC line.
    pub fn process_client_line(&self, line: &str) -> ClientAction {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return ClientAction::Forward(line.to_string());
        }

        let Ok(msg) = serde_json::from_str::<JsonRpcMessage>(trimmed) else {
            // Pass through non-standard lines untouched rather than breaking framing.
            return ClientAction::Forward(trimmed.to_string());
        };

        let start = Instant::now();
        match self.engine.evaluate_request(&msg) {
            Decision::Allow => {
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
                ClientAction::Forward(trimmed.to_string())
            }
            Decision::Deny(reason) => {
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

                let err_msg = JsonRpcMessage::policy_denied(msg.id, reason);
                let out = serde_json::to_string(&err_msg)
                    .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"PolicyDenied"}}"#.to_string());
                ClientAction::ImmediateReply(out)
            }
        }
    }

    /// Sanitize an outgoing server-to-client JSON-RPC line and record its audit entry.
    pub fn process_server_line(&self, line: &str) -> String {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return line.to_string();
        }

        let Ok(mut msg) = serde_json::from_str::<JsonRpcMessage>(trimmed) else {
            return trimmed.to_string();
        };

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
                    let _ = self.audit.log(&AuditRecord {
                        timestamp: Utc::now(),
                        server: self.engine.server_name().to_string(),
                        method,
                        tool,
                        decision: AuditDecision::Deny,
                        reason: Some(reason.clone()),
                        latency_us: started_at.elapsed().as_micros() as u64,
                    });
                    let blocked = JsonRpcMessage::policy_denied(msg.id, reason);
                    return serde_json::to_string(&blocked).unwrap_or_else(|_| trimmed.to_string());
                }
            }
            return serde_json::to_string(&msg).unwrap_or_else(|_| trimmed.to_string());
        }

        trimmed.to_string()
    }
}
