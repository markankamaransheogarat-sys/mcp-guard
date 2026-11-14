use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard `mcp-guard` JSON-RPC error code for policy denials.
pub const POLICY_DENIED_CODE: i64 = -32001;

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A generic JSON-RPC 2.0 message (request, notification, or response).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcMessage {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcMessage {
    /// Returns `true` if this message is a JSON-RPC request (has `method` and `id`).
    pub fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    /// Returns `true` if this message is a JSON-RPC response (has `id` and `result` or `error`).
    pub fn is_response(&self) -> bool {
        self.method.is_none() && self.id.is_some()
    }

    /// Construct a `-32001 PolicyDenied` JSON-RPC 2.0 error response for the given request ID.
    pub fn policy_denied(id: Option<Value>, reason: impl Into<String>) -> Self {
        let reason_str = reason.into();
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: None,
            params: None,
            result: None,
            error: Some(JsonRpcError {
                code: POLICY_DENIED_CODE,
                message: format!("PolicyDenied: {reason_str}"),
                data: Some(serde_json::json!({
                    "guard": "mcp-guard",
                    "reason": reason_str,
                })),
            }),
        }
    }

    /// Extract the tool name if this is a `tools/call` request.
    pub fn tool_name(&self) -> Option<&str> {
        if self.method.as_deref() != Some("tools/call") {
            return None;
        }
        self.params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
    }

    /// Extract the tool arguments if this is a `tools/call` request.
    pub fn tool_arguments(&self) -> Option<&Value> {
        if self.method.as_deref() != Some("tools/call") {
            return None;
        }
        self.params.as_ref().and_then(|p| p.get("arguments"))
    }

    /// Extract the resource URI if this is a `resources/read` request.
    pub fn resource_uri(&self) -> Option<&str> {
        if self.method.as_deref() != Some("resources/read") {
            return None;
        }
        self.params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_denied_builds_valid_jsonrpc_error() {
        let msg =
            JsonRpcMessage::policy_denied(Some(serde_json::json!(42)), "path traversal detected");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["id"], 42);
        assert_eq!(json["error"]["code"], -32001);
        assert_eq!(
            json["error"]["message"],
            "PolicyDenied: path traversal detected"
        );
    }

    #[test]
    fn extracts_tool_name_and_args() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/a.txt"}}}"#;
        let msg: JsonRpcMessage = serde_json::from_str(raw).unwrap();
        assert!(msg.is_request());
        assert_eq!(msg.tool_name(), Some("read_file"));
        assert_eq!(
            msg.tool_arguments().unwrap()["path"].as_str(),
            Some("/tmp/a.txt")
        );
    }
}
