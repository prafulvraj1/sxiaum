//! JSON-RPC and REST API server for the SXIAUM blockchain.
//!
//! This crate provides:
//! - JSON-RPC 2.0 endpoint with Ethereum compatibility (`eth_*` methods)
//! - REST API for blocks, health, and status
//! - WebSocket subscriptions for real-time events
//! - JWT authentication with key file reloading
//! - TLS/HTTPS support with certificate validation
//! - DDoS protection with global, per-IP, and per-API-key rate limiting
//! - CORS with fail-closed default
//! - Request body size limits
//! - Sensitive query parameter redaction in logs
//! - Constant-time token comparison (timing side-channel mitigation)
//!
//! # Mainnet Readiness
//!
//! The RPC server enforces:
//! - TLS (HTTPS) in production mode (cert or reverse proxy required)
//! - JWT authentication for admin and write methods
//! - Write auth enforcement for public RPC endpoints
//! - Rate limiting at global, per-IP, and per-API-key levels
//! - Request timeout to prevent slow-loris attacks
//! - Body size limits to prevent OOM attacks
//! - CORS fail-closed (no wildcard origins by default)
//! - `?token=` query parameter rejection (credential leakage prevention)
//! - WebSocket anonymous access restricted to loopback by default

pub mod context;
pub mod error;
pub mod eth;
pub mod hexutil;
pub mod jwt;
pub mod methods;
pub mod metrics;
pub mod middleware;
pub mod protocol;
pub mod routes;
pub mod server;
#[cfg(test)]
pub(crate) mod test_support;
pub mod ws;

pub use crate::context::RpcContext;
pub use crate::error::{JsonRpcError, RpcError};
pub use crate::protocol::{JsonRpcRequest, JsonRpcResponse};
pub use crate::server::{RpcConfig, RpcServer};

// ---------------------------------------------------------------------------
// Mainnet RPC constants
// ---------------------------------------------------------------------------

/// Maximum request body size (10 MB).
/// Prevents OOM attacks from massive JSON-RPC batches.
pub const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default RPC listen address (loopback for security).
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8080";

/// Request timeout in seconds (10s).
/// Prevents slow-loris attacks.
pub const RPC_TIMEOUT_SECS: u64 = 10;

/// Global rate limit: requests per second across the entire node (1000).
pub const GLOBAL_RATE_LIMIT_PER_SEC: u32 = 1000;

/// Per-IP rate limit: requests per second per client IP (20).
pub const IP_RATE_LIMIT_PER_SEC: u32 = 20;

/// Per-API-key rate limit: requests per second per API key (500).
pub const API_KEY_RATE_LIMIT_PER_SEC: u32 = 500;

/// Maximum body size for auth checking (2 MB).
/// Prevents OOM when parsing JSON-RPC requests for method authorization.
pub const AUTH_CHECK_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// Minimum JWT secret length in bytes (32 bytes = 256-bit entropy).
pub const MIN_JWT_SECRET_BYTES: usize = 32;

/// Server version string returned by `web3_clientVersion`.
pub const SERVER_VERSION: &str = "SXIAUM/0.1.0";

/// WebSocket broadcast channel capacity (1024 messages).
pub const WS_BROADCAST_CAPACITY: usize = 1024;

/// Maximum block range allowed in a single `eth_getLogs` query (2,000 blocks).
/// Prevents database and CPU exhaustion DoS attacks.
pub const MAX_LOGS_BLOCK_RANGE: u64 = 2000;

/// Maximum number of logs returned in a single `eth_getLogs` query (10,000 logs).
/// Prevents out-of-memory DoS attacks.
pub const MAX_LOGS_LIMIT: usize = 10000;

/// Maximum number of concurrent subscriptions per WebSocket connection (256).
/// Prevents unbounded memory growth per client.
pub const MAX_WS_SUBSCRIPTIONS_PER_CONN: usize = 256;

/// Maximum page size limit for paginated RPC queries (1,000 items).
/// Prevents unbounded memory allocations in pagination parameters.
pub const MAX_PAGE_LIMIT: usize = 1000;

/// Maximum number of requests accepted in a single JSON-RPC 2.0 batch (32).
///
/// JSON-RPC batching is supported for client compatibility, but unbounded
/// batches are an amplification vector: a single HTTP request could otherwise
/// enqueue thousands of state-heavy lookups while bypassing per-request
/// accounting. Batches larger than this are rejected with a single error.
pub const MAX_BATCH_REQUESTS: usize = 32;
