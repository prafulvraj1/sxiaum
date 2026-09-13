use crate::error::JsonRpcError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Standard JSON-RPC 2.0 request structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
    pub id: Value,
}

/// Standard JSON-RPC 2.0 response structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Value,
}

impl JsonRpcRequest {
    /// Validates structural requirements of a JSON-RPC 2.0 request.
    ///
    /// The `id` member is constrained to the spec-legal forms (string, number,
    /// null). Previously any JSON value was accepted and reflected back
    /// verbatim in the response, letting clients stash arbitrarily nested
    /// payloads in `id` purely to inflate response sizes.
    ///
    /// When present, `params` must be an array or object per the spec.
    pub fn validate(&self) -> Result<(), JsonRpcError> {
        if self.jsonrpc != "2.0" {
            return Err(JsonRpcError::invalid_request("Must be '2.0'"));
        }
        if self.method.is_empty() {
            return Err(JsonRpcError::invalid_request("Method name cannot be empty"));
        }
        if !is_valid_id(&self.id) {
            return Err(JsonRpcError::invalid_request(
                "id must be a string, number, or null",
            ));
        }
        match &self.params {
            None | Some(Value::Array(_)) | Some(Value::Object(_)) => {}
            Some(Value::Null) => {}
            Some(_) => {
                return Err(JsonRpcError::invalid_request(
                    "params must be an array or object",
                ))
            }
        }
        Ok(())
    }
}

fn is_valid_id(id: &Value) -> bool {
    matches!(id, Value::Null | Value::String(_) | Value::Number(_))
}

impl JsonRpcResponse {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// Extracts the request id from an already-parsed JSON value when it is one of
/// the spec-legal scalar forms. Used to echo ids on parse/validation failures
/// instead of unconditionally answering with `null`.
pub fn extract_request_id(raw: &Value) -> Value {
    match raw.get("id") {
        Some(id @ (Value::String(_) | Value::Number(_))) => id.clone(),
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_request(json: Value) -> Result<JsonRpcRequest, JsonRpcError> {
        let req: JsonRpcRequest = serde_json::from_value(json).unwrap();
        req.validate()?;
        Ok(req)
    }

    #[test]
    fn valid_requests_pass() {
        assert!(make_request(json!({
            "jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1
        }))
        .is_ok());
        assert!(make_request(json!({
            "jsonrpc": "2.0", "method": "m", "id": "abc"
        }))
        .is_ok());
        assert!(make_request(json!({
            "jsonrpc": "2.0", "method": "m", "id": null
        }))
        .is_ok());
    }

    #[test]
    fn wrong_version_rejected() {
        let err = make_request(json!({"jsonrpc": "1.0", "method": "m", "id": 1})).unwrap_err();
        assert_eq!(err.code, -32600);
    }

    #[test]
    fn empty_method_rejected() {
        let err = make_request(json!({"jsonrpc": "2.0", "method": "", "id": 1})).unwrap_err();
        assert_eq!(err.code, -32600);
    }

    #[test]
    fn object_ids_rejected() {
        // Regression: nested objects/arrays used to be accepted and reflected.
        let err = make_request(json!({
            "jsonrpc": "2.0", "method": "m", "id": {"deep": [1, 2, 3]}
        }))
        .unwrap_err();
        assert_eq!(err.code, -32600);
    }

    #[test]
    fn array_ids_rejected() {
        let err = make_request(json!({"jsonrpc": "2.0", "method": "m", "id": [1]})).unwrap_err();
        assert_eq!(err.code, -32600);
    }

    #[test]
    fn invalid_params_type_rejected() {
        let err = make_request(json!({"jsonrpc": "2.0", "method": "m", "params": "x", "id": 1}))
            .unwrap_err();
        assert_eq!(err.code, -32600);
    }

    #[test]
    fn extract_id_echoes_scalars_only() {
        assert_eq!(extract_request_id(&json!({"id": 42})), json!(42));
        assert_eq!(extract_request_id(&json!({"id": "abc"})), json!("abc"));
        assert_eq!(extract_request_id(&json!({"id": {"a": 1}})), Value::Null);
        assert_eq!(extract_request_id(&json!("not an object")), Value::Null);
    }
}
