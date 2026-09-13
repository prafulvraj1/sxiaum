use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use thiserror::Error;

/// Core RPC error types for SXIAUM.
#[derive(Debug, Error)]
pub enum RpcError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Method not found: {0}")]
    MethodNotFound(String),

    #[error("Invalid params: {0}")]
    InvalidParams(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Block not found: height={0}")]
    BlockNotFound(u64),

    #[error("Transaction rejected: {0}")]
    TransactionRejected(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] anyhow::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// The standard JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn parse_error() -> Self {
        Self {
            code: -32700,
            message: "Parse error".to_string(),
            data: None,
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: Some(Value::String(message.into())),
        }
    }
}

impl RpcError {
    /// Maps the internal RpcError to its standard JSON-RPC 2.0 error code and message.
    pub fn to_json_rpc_error(&self) -> JsonRpcError {
        match self {
            RpcError::ParseError(msg) => JsonRpcError {
                code: -32700,
                message: "Parse error".to_string(),
                data: Some(Value::String(msg.clone())),
            },
            RpcError::InvalidRequest(msg) => JsonRpcError {
                code: -32600,
                message: "Invalid Request".to_string(),
                data: Some(Value::String(msg.clone())),
            },
            RpcError::MethodNotFound(msg) => JsonRpcError {
                code: -32601,
                message: "Method not found".to_string(),
                data: Some(Value::String(msg.clone())),
            },
            RpcError::InvalidParams(msg) => JsonRpcError {
                code: -32602,
                message: "Invalid params".to_string(),
                data: Some(Value::String(msg.clone())),
            },
            RpcError::InternalError(msg) => JsonRpcError {
                code: -32603,
                message: "Internal error".to_string(),
                data: Some(Value::String(msg.clone())),
            },
            RpcError::BlockNotFound(height) => JsonRpcError {
                code: -32001, // Custom blockchain error range (-32099 to -32000)
                message: "Block not found".to_string(),
                data: Some(Value::Number(serde_json::Number::from(*height))),
            },
            RpcError::TransactionRejected(msg) => JsonRpcError {
                code: -32002,
                message: "Transaction rejected".to_string(),
                data: Some(Value::String(msg.clone())),
            },
            RpcError::DatabaseError(err) => {
                tracing::error!("Internal database error during RPC: {:?}", err);
                JsonRpcError {
                    code: -32003,
                    message: "Database error".to_string(),
                    data: None,
                }
            }
            RpcError::SerializationError(err) => {
                tracing::warn!("Serialization error during RPC: {:?}", err);
                JsonRpcError {
                    code: -32004,
                    message: "Serialization error".to_string(),
                    data: None,
                }
            }
        }
    }
}

// Ensure the JsonRpcError can be easily used in responses and displays.
impl fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RPC Error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

// Provide conversions from JsonRpcError to RpcError for certain conditions if needed.
impl From<JsonRpcError> for RpcError {
    fn from(error: JsonRpcError) -> Self {
        match error.code {
            -32700 => RpcError::ParseError(error.message),
            -32600 => RpcError::InvalidRequest(error.message),
            -32601 => RpcError::MethodNotFound(error.message),
            -32602 => RpcError::InvalidParams(error.message),
            _ => RpcError::InternalError(error.message),
        }
    }
}
