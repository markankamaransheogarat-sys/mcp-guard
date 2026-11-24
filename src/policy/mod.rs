pub mod network;
pub mod path;
pub mod ratelimit;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde_json::Value;

use crate::config::PolicyConfig;
use crate::error::Result;
use crate::jsonrpc::JsonRpcMessage;

use self::network::NetworkValidator;
use self::path::PathValidator;
use self::ratelimit::RateLimiter;

/// Policy evaluation decision for an incoming MCP JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
}

/// Evaluates MCP requests (`tools/call`, `resources/read`, etc.) against `PolicyConfig`.
#[derive(Debug)]
pub struct PolicyEngine {
    server_name: String,
    allow_tools: Option<GlobSet>,
    deny_tools: GlobSet,
    filter_tools_list: bool,
    path_validator: PathValidator,
    network_validator: NetworkValidator,
    rate_limiter: RateLimiter,
}

impl PolicyEngine {
    /// Construct a `PolicyEngine` from a `PolicyConfig`.
    pub fn new(config: &PolicyConfig) -> Result<Self> {
        let allow_tools = if config.tools.allow.is_empty() {
            None
        } else {
            let mut builder = GlobSetBuilder::new();
            for pat in &config.tools.allow {
                builder.add(Glob::new(pat)?);
            }
            Some(builder.build()?)
        };

        let mut deny_builder = GlobSetBuilder::new();
        for pat in &config.tools.deny {
            deny_builder.add(Glob::new(pat)?);
        }
        let deny_tools = deny_builder.build()?;

        Ok(Self {
            server_name: config.server.clone(),
            allow_tools,
            deny_tools,
            filter_tools_list: config.tools.filter_tools_list,
            path_validator: PathValidator::new(&config.paths)?,
            network_validator: NetworkValidator::new(&config.network),
            rate_limiter: RateLimiter::new(config.rate_limit.clone()),
        })
    }

    /// Logical server name associated with this engine.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Check whether a tool name is permitted by `tools.deny` and `tools.allow`.
    pub fn check_tool_name(&self, tool: &str) -> std::result::Result<(), String> {
        if self.deny_tools.is_match(tool) {
            return Err(format!("tool '{tool}' is denied by policy"));
        }
        if let Some(allow) = &self.allow_tools {
            if !allow.is_match(tool) {
                return Err(format!("tool '{tool}' is not in tools.allow"));
            }
        }
        Ok(())
    }

    /// Remove disallowed tools from a `tools/list` JSON-RPC response in place.
    /// Returns the number of hidden tools.
    pub fn filter_tools_list_response(&self, msg: &mut JsonRpcMessage) -> usize {
        if !self.filter_tools_list {
            return 0;
        }
        let Some(tools) = msg
            .result
            .as_mut()
            .and_then(|r| r.get_mut("tools"))
            .and_then(Value::as_array_mut)
        else {
            return 0;
        };
        let before = tools.len();
        tools.retain(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .map(|name| self.check_tool_name(name).is_ok())
                .unwrap_or(true)
        });
        before - tools.len()
    }

    /// Evaluate an incoming JSON-RPC message from the client.
    pub fn evaluate_request(&self, msg: &JsonRpcMessage) -> Decision {
        let Some(method) = msg.method.as_deref() else {
            return Decision::Allow;
        };

        match method {
            "tools/call" => self.evaluate_tool_call(msg),
            "resources/read" => self.evaluate_resource_read(msg),
            _ => Decision::Allow,
        }
    }

    fn evaluate_tool_call(&self, msg: &JsonRpcMessage) -> Decision {
        let Some(tool) = msg.tool_name() else {
            return Decision::Deny("missing tool name in tools/call".to_string());
        };

        if let Err(reason) = self.check_tool_name(tool) {
            return Decision::Deny(reason);
        }

        let args = msg.tool_arguments();
        if let Err(e) = self.rate_limiter.check_and_record(tool, args) {
            return Decision::Deny(strip_prefix(&e.to_string()));
        }

        if let Some(args_val) = args {
            if let Err(e) = self.inspect_value(None, args_val) {
                return Decision::Deny(strip_prefix(&e.to_string()));
            }
        }

        Decision::Allow
    }

    fn evaluate_resource_read(&self, msg: &JsonRpcMessage) -> Decision {
        let Some(uri) = msg.resource_uri() else {
            return Decision::Deny("missing uri in resources/read".to_string());
        };

        if let Err(e) = self
            .rate_limiter
            .check_and_record("resources/read", msg.params.as_ref())
        {
            return Decision::Deny(strip_prefix(&e.to_string()));
        }

        if is_network_url(uri) {
            if let Err(e) = self.network_validator.check_url(uri) {
                return Decision::Deny(strip_prefix(&e.to_string()));
            }
        } else if uri.starts_with("file://") || looks_like_path(uri) {
            if let Err(e) = self.path_validator.check(uri) {
                return Decision::Deny(strip_prefix(&e.to_string()));
            }
        }

        Decision::Allow
    }

    fn inspect_value(&self, key_hint: Option<&str>, val: &Value) -> Result<()> {
        match val {
            Value::String(s) => self.inspect_string(key_hint, s),
            Value::Array(items) => {
                for item in items {
                    self.inspect_value(key_hint, item)?;
                }
                Ok(())
            }
            Value::Object(map) => {
                for (k, v) in map {
                    self.inspect_value(Some(k.as_str()), v)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn inspect_string(&self, key_hint: Option<&str>, s: &str) -> Result<()> {
        if is_network_url(s) {
            self.network_validator.check_url(s)?;
            return Ok(());
        }

        let key_is_path = key_hint.is_some_and(is_path_key);
        if key_is_path || s.starts_with("file://") || looks_like_path(s) {
            self.path_validator.check(s)?;
        }

        Ok(())
    }
}

fn strip_prefix(msg: &str) -> String {
    msg.strip_prefix("PolicyDenied: ")
        .unwrap_or(msg)
        .to_string()
}

fn is_network_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
}

fn is_path_key(k: &str) -> bool {
    let lower = k.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "path"
            | "paths"
            | "file"
            | "files"
            | "file_path"
            | "filepath"
            | "dir"
            | "directory"
            | "folder"
            | "target"
            | "source"
            | "src"
            | "dest"
            | "dst"
            | "root"
            | "cwd"
            | "working_directory"
    ) || lower.ends_with("_path")
        || lower.ends_with("_dir")
        || lower.ends_with("_file")
}

fn looks_like_path(s: &str) -> bool {
    s.contains('\0')
        || s.starts_with("~/")
        || s.starts_with("~\\")
        || s.starts_with("../")
        || s.starts_with("..\\")
        || s.contains("/../")
        || s.contains("\\..\\")
        || s.contains("/.ssh")
        || s.contains("/.aws")
        || s.contains("/.gnupg")
        || s.ends_with("/.env")
        || s == ".env"
        || s.starts_with('/')
        || (s.len() >= 3
            && s.as_bytes()[1] == b':'
            && (s.as_bytes()[2] == b'\\' || s.as_bytes()[2] == b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ToolPolicy;

    #[test]
    fn denies_blocked_tool_and_allows_permitted_tool() {
        let cfg = PolicyConfig {
            tools: ToolPolicy {
                allow: vec!["read_*".into()],
                deny: vec!["read_secret".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let engine = PolicyEngine::new(&cfg).unwrap();

        let ok_req = serde_json::from_str::<JsonRpcMessage>(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}"#,
        )
        .unwrap();
        assert_eq!(engine.evaluate_request(&ok_req), Decision::Allow);

        let denied_req = serde_json::from_str::<JsonRpcMessage>(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_secret","arguments":{}}}"#,
        )
        .unwrap();
        assert!(matches!(
            engine.evaluate_request(&denied_req),
            Decision::Deny(_)
        ));

        let unallowed_req = serde_json::from_str::<JsonRpcMessage>(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"cmd":"whoami"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            engine.evaluate_request(&unallowed_req),
            Decision::Deny(_)
        ));
    }
}
