use axum::{
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use sxiaum_types::SXIAUM_CHAIN_ID;
use tokio::sync::oneshot;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::context::RpcContext;
use crate::error::{JsonRpcError, RpcError};
use crate::metrics;
use crate::middleware::{
    auth_middleware, cors_middleware, ddos_protection_middleware, logging_middleware,
    size_limit_layer, timeout_middleware,
};
use crate::protocol::{extract_request_id, JsonRpcRequest, JsonRpcResponse};
use crate::routes::{blocks, health, network, state, tx};

/// TLS configuration for secure RPC communication.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// P1-1: Validate that TLS cert and key files are present and the cert is parseable.
///
/// On Unix, also checks that the key file is not world-readable (mode 0o600 or 0o400).
/// Returns a human-readable error string listing all problems found.
pub fn validate_tls_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();

    // Check cert file exists and contains a PEM CERTIFICATE block
    match std::fs::read(cert_path) {
        Err(e) => errors.push(format!("TLS cert {:?} is not readable: {}", cert_path, e)),
        Ok(pem_bytes) => {
            let pem_str = String::from_utf8_lossy(&pem_bytes);
            if !pem_str.contains("-----BEGIN CERTIFICATE-----") {
                errors.push(format!(
                    "TLS cert {:?} does not contain a valid PEM CERTIFICATE block.",
                    cert_path
                ));
            }
        }
    }

    // Check key file exists; on Unix additionally verify restrictive permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(key_path) {
            Err(e) => errors.push(format!("TLS key {:?} is not readable: {}", key_path, e)),
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    errors.push(format!(
                        "TLS key {:?} has insecure permissions ({:#o}). \
                         Set to 0600: chmod 600 {:?}",
                        key_path, mode, key_path
                    ));
                }
            }
        }
    }
    #[cfg(not(unix))]
    if let Err(e) = std::fs::metadata(key_path) {
        errors.push(format!("TLS key {:?} is not readable: {}", key_path, e));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Configuration options for the SXIAUM RPC server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub addr: SocketAddr,
    pub max_request_body_size: usize,
    pub tls: Option<TlsConfig>,
    pub cors_allowed_origins: Option<Vec<String>>,
    /// When true, the server binds plain HTTP and assumes an external TLS-terminating
    /// reverse proxy (e.g., nginx, Caddy) sits in front. This is an explicit opt-out
    /// from direct TLS — it does NOT disable authentication or other security checks.
    ///
    /// Setting `SXIAUM_REVERSE_PROXY=true` in the environment also enables trusting
    /// `X-Forwarded-For` and `X-Real-IP` headers for client IP extraction in rate limits.
    ///
    /// This option is mutually exclusive with providing `tls`. Setting both is an error.
    /// In production (`SXIAUM_ENV=production`) this option is only allowed when
    /// `SXIAUM_REVERSE_PROXY=true` is also set in the environment.
    pub allow_reverse_proxy: bool,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            addr: crate::DEFAULT_RPC_ADDR
                .parse()
                .expect("hardcoded default RPC address is valid"),
            max_request_body_size: crate::MAX_REQUEST_BODY_SIZE, // 10MB
            tls: None,
            cors_allowed_origins: None,
            allow_reverse_proxy: false,
        }
    }
}

/// The SXIAUM RPC Server, supporting JSON-RPC, REST, and secure communication.
pub struct RpcServer {
    context: Arc<RpcContext>,
    config: RpcConfig,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl RpcServer {
    /// Creates a new RPC server instance with the specified context and configuration.
    pub fn new(context: Arc<RpcContext>, config: RpcConfig) -> Self {
        Self {
            context,
            config,
            shutdown_tx: None,
        }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        crate::middleware::validate_runtime_environment()?;
        crate::middleware::configure_body_limit(self.config.max_request_body_size);

        let allow_http = crate::middleware::env_flag("SXIAUM_ALLOW_HTTP")?;
        let is_production = crate::middleware::is_production();
        let reverse_proxy_mode =
            self.config.allow_reverse_proxy || crate::middleware::env_flag("SXIAUM_REVERSE_PROXY")?;

        // --- R2.2: Public RPC Write Auth Enforcement ---
        let write_auth_enabled = crate::middleware::write_auth_enabled();
        // --- Hardening pass: visibility into anonymous write exposure ---
        if crate::middleware::anonymous_writes_allowed() && !self.config.addr.ip().is_loopback() {
            tracing::warn!(
                "SXIAUM_RPC_ALLOW_ANON_WRITES=1 with a non-loopback bind ({}):                  ANYONE who can reach this port can submit transactions anonymously.                  This is intended for devnets only.",
                self.config.addr
            );
        }

        if is_production && !self.config.addr.ip().is_loopback() && !write_auth_enabled {
            anyhow::bail!(
                "SECURITY FAILURE: Production RPC server bound to a non-loopback address ({}) \
                 requires SXIAUM_RPC_WRITE_AUTH=1 to be set.",
                self.config.addr
            );
        }

        if reverse_proxy_mode && self.config.tls.is_some() {
            anyhow::bail!(
                "CONFIGURATION FAILURE: `allow_reverse_proxy` and `tls` are mutually exclusive. \
                 Choose direct TLS termination OR an external TLS-terminating proxy, not both."
            );
        }

        // --- P1-1: TLS enforcement ---
        match &self.config.tls {
            Some(tls) => {
                // TLS is configured — validate the files before binding.
                if let Err(e) = validate_tls_files(&tls.cert_path, &tls.key_path) {
                    anyhow::bail!("SECURITY FAILURE: TLS configuration is invalid. {}", e);
                }
            }
            None => {
                if is_production && !reverse_proxy_mode {
                    anyhow::bail!(
                        "SECURITY FAILURE: TLS (HTTPS) must be configured for the RPC server \
                         in production mode. Either set SXIAUM_TLS_CERT_PATH + SXIAUM_TLS_KEY_PATH \
                         or set SXIAUM_REVERSE_PROXY=true if a TLS-terminating proxy is in front."
                    );
                } else if !allow_http && !reverse_proxy_mode {
                    anyhow::bail!(
                        "SECURITY FAILURE: TLS (HTTPS) must be configured for the RPC server. \
                         Explicitly set SXIAUM_ALLOW_HTTP=true to override for local dev, or \
                         SXIAUM_REVERSE_PROXY=true if a TLS-terminating proxy handles encryption."
                    );
                }
                if reverse_proxy_mode {
                    warn!(
                        "RPC server starting in REVERSE PROXY mode (plain HTTP). \
                         An external TLS-terminating proxy MUST handle encryption. \
                         Direct exposure of plain HTTP to the internet is a critical vulnerability."
                    );
                }
            }
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let app = self.build_router();
        let addr = self.config.addr;

        // Graceful handle for axum-server
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_rx.await.ok();
            info!("Graceful shutdown signal received. Stopping RPC server...");
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });

        if let Some(tls) = &self.config.tls {
            info!("Starting SXIAUM SECURE (HTTPS) RPC server on {}...", addr);
            let rustls_config = RustlsConfig::from_pem_file(&tls.cert_path, &tls.key_path).await?;
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        } else {
            info!("Starting SXIAUM (HTTP) RPC server on {}...", addr);
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await?;
        }

        Ok(())
    }

    /// Initializes the Axum router with JSON-RPC handlers, REST routes, and middleware.
    ///
    /// Layer ordering (outermost first): Trace → Timeout → DDoS → Auth →
    /// Logging → BodyLimit → CORS → Routes.
    ///
    /// The auth middleware receives the JWT manager through router state
    /// (`from_fn_with_state`) rather than a request extension. The previous
    /// arrangement inserted the JWT manager via an `Extension` layer placed
    /// INNER relative to the auth layer, so the lookup in `auth_middleware`
    /// always missed and JWT authentication silently never worked through the
    /// real router (only the static `SXIAUM_RPC_AUTH_TOKEN` path functioned).
    pub fn build_router(&self) -> Router {
        Router::new()
            // -----------------------------------------------------------------
            // JSON-RPC Endpoints
            // -----------------------------------------------------------------
            .route("/rpc", post(Self::handle_json_rpc))
            // -----------------------------------------------------------------
            // WebSocket Endpoints
            // -----------------------------------------------------------------
            .route("/ws", get(crate::ws::ws_handler))
            // -----------------------------------------------------------------
            // REST Endpoints
            // -----------------------------------------------------------------
            .route("/health", get(health::health_check))
            .route("/metrics", get(|| async { metrics::render_metrics() }))
            .route("/status", get(Self::handle_status_rest))
            .route("/blocks/:height", get(Self::handle_block_rest))
            // -----------------------------------------------------------------
            // Shared Middleware Stack
            // -----------------------------------------------------------------
            .layer(cors_middleware(self.config.cors_allowed_origins.as_ref()))
            .layer(size_limit_layer(self.config.max_request_body_size))
            .layer(middleware::from_fn(logging_middleware))
            .layer(middleware::from_fn_with_state(
                self.context.clone(),
                auth_middleware,
            ))
            .layer(middleware::from_fn(ddos_protection_middleware))
            .layer(middleware::from_fn(timeout_middleware))
            .layer(TraceLayer::new_for_http())
            .with_state(self.context.clone())
    }

    /// High-level handler for all incoming JSON-RPC 2.0 requests.
    ///
    /// The raw body is parsed manually instead of using the `Json` extractor
    /// so malformed JSON produces a spec-compliant JSON-RPC `-32700 Parse
    /// error` response with HTTP 200 (the extractor answered with an HTTP 422
    /// text body, breaking every standard JSON-RPC client's error handling).
    ///
    /// JSON-RPC 2.0 batches are supported, bounded by [`crate::MAX_BATCH_REQUESTS`].
    async fn handle_json_rpc(
        State(context): State<Arc<RpcContext>>,
        body: axum::body::Bytes,
    ) -> Response {
        let raw: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return Json(
                    serde_json::to_value(JsonRpcResponse::error(
                        Value::Null,
                        JsonRpcError::parse_error(),
                    ))
                    .expect("JsonRpcResponse error is always serializable"),
                )
                .into_response();
            }
        };

        match raw {
            Value::Array(items) => {
                if items.is_empty() {
                    // Per JSON-RPC 2.0: an empty batch yields a single error object.
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32600, "message": "Invalid Request", "data": "empty batch"}
                    }))
                    .into_response();
                }
                if items.len() > crate::MAX_BATCH_REQUESTS {
                    return Json(json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32600, "message": "Invalid Request",
                                  "data": format!("batch size exceeds limit of {} requests", crate::MAX_BATCH_REQUESTS)}
                    }))
                    .into_response();
                }
                let mut responses = Vec::with_capacity(items.len());
                for item in items {
                    responses.push(Self::process_single_request(&context, item).await);
                }
                Json(responses).into_response()
            }
            obj @ Value::Object(_) => {
                Json(Self::process_single_request(&context, obj).await).into_response()
            }
            _ => Json(
                serde_json::to_value(JsonRpcResponse::error(
                    Value::Null,
                    JsonRpcError::parse_error(),
                ))
                .expect("JsonRpcResponse error is always serializable"),
            )
            .into_response(),
        }
    }

    /// Processes one JSON value as a single JSON-RPC request and returns the
    /// serialized response value.
    async fn process_single_request(context: &Arc<RpcContext>, raw: Value) -> Value {
        let request_id = extract_request_id(&raw);

        let request: JsonRpcRequest = match serde_json::from_value(raw) {
            Ok(req) => req,
            Err(_) => {
                return serde_json::to_value(JsonRpcResponse::error(
                    request_id,
                    JsonRpcError::invalid_request("request is not a valid JSON-RPC 2.0 object"),
                ))
                .expect("JsonRpcResponse error is always serializable");
            }
        };

        if let Err(e) = request.validate() {
            return serde_json::to_value(JsonRpcResponse::error(request.id.clone(), e))
                .expect("JsonRpcResponse error is always serializable");
        }

        let method_name = request.method.clone();
        metrics::record_request(&method_name);
        let start_time = std::time::Instant::now();

        let result = Self::dispatch_rpc_method(context, &request.method, request.params).await;

        let response = match result {
            Ok(val) => {
                metrics::record_latency(&method_name, start_time);
                JsonRpcResponse::success(request.id, val)
            }
            Err(e) => {
                let rpc_error = e.to_json_rpc_error();
                metrics::record_error(&method_name, rpc_error.code);
                tracing::debug!(method = %method_name, code = rpc_error.code, "rpc request failed");
                JsonRpcResponse::error(request.id, rpc_error)
            }
        };

        serde_json::to_value(response)
            .expect("JsonRpcResponse with standard types should always serialize successfully")
    }

    /// Dispatches JSON-RPC calls. Ethereum compatibility aliases (`eth_*`,
    /// `web3_*`, `net_*`) resolve first; remaining methods route by the exact
    /// category table in [`crate::methods`], which shares a single source of
    /// truth with the auth middleware.
    async fn dispatch_rpc_method(
        context: &Arc<RpcContext>,
        method: &str,
        params: Option<Value>,
    ) -> Result<Value, RpcError> {
        // --- Early-return methods (no parameters required) ---
        match method {
            "eth_chainId" => return Ok(json!(format!("0x{:x}", SXIAUM_CHAIN_ID))),
            "eth_networkId" | "net_version" => return Ok(json!(SXIAUM_CHAIN_ID.to_string())),
            "net_listening" => return Ok(json!(true)),
            "net_peerCount" => {
                let count = context.networking.lock().await.peer_count();
                return Ok(json!(format!("0x{:x}", count)));
            }
            "eth_gasPrice" => return Ok(json!("0x1")), // 1 wei minimum
            "eth_blockNumber" => {
                let height = context.storage.latest_block_height().map_err(|e| {
                    RpcError::InternalError(format!("failed to fetch block height: {}", e))
                })?;
                return Ok(json!(format!("0x{:x}", height)));
            }
            "eth_accounts" => return Ok(json!([])), // No accounts in RPC-only mode
            "eth_coinbase" => return Ok(json!("0x0000000000000000000000000000000000000000")),
            "eth_mining" => return Ok(json!(false)),
            "eth_hashrate" => return Ok(json!("0x0")),
            "web3_clientVersion" => return Ok(json!(crate::SERVER_VERSION)),
            "web3_sha3" => {
                // Per the Ethereum specification web3_sha3 IS Keccak-256.
                use sha3::Digest;
                let raw = params
                    .and_then(|p| p.get(0).and_then(|v| v.as_str()).map(String::from))
                    .unwrap_or_default();
                let clean = crate::hexutil::strip_hex_prefix(raw.trim());
                let decoded = hex::decode(clean).map_err(|e| {
                    RpcError::InvalidParams(format!("invalid hex in web3_sha3: {}", e))
                })?;
                let digest = sha3::Keccak256::digest(&decoded);
                return Ok(json!(format!("0x{}", hex::encode(digest))));
            }
            _ => {}
        }

        // --- Category-based dispatch (single source of truth) ---
        match crate::methods::dispatch_category(method) {
            crate::methods::MethodCategory::Blocks => {
                blocks::handle_block_method(method, params, context).await
            }
            crate::methods::MethodCategory::Transactions => {
                tx::handle_tx_method(method, params, context).await
            }
            crate::methods::MethodCategory::State => {
                state::handle_state_method(method, params, context).await
            }
            crate::methods::MethodCategory::Network => {
                network::handle_network_method(method, params, context).await
            }
        }
    }

    // --- REST Handlers ---

    async fn handle_status_rest(State(_context): State<Arc<RpcContext>>) -> Json<Value> {
        Json(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "chain_id": SXIAUM_CHAIN_ID,
            "chain_id_hex": format!("0x{:x}", SXIAUM_CHAIN_ID),
            "status": "online"
        }))
    }

    async fn handle_block_rest(
        Path(height): Path<u64>,
        State(context): State<Arc<RpcContext>>,
    ) -> Response {
        match blocks::handle_block_method(
            "sxiaum_getBlockByNumber",
            Some(json!([height])),
            &context,
        )
        .await
        {
            Ok(val) => (StatusCode::OK, Json(val)).into_response(),
            // Previously ALL failures were flattened to an ambiguous
            // {"error": "block not found"} body with HTTP 200.
            Err(e @ RpcError::InvalidParams(_)) => (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
            Err(RpcError::BlockNotFound(height)) => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "block not found", "height": height})),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response(),
        }
    }

    /// Stops the server gracefully by signaling the shutdown channel.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            info!("Stop signal received. Initiating shutdown...");
            let _ = tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::test_context;
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};
    use tempfile::NamedTempFile;
    use tower::ServiceExt;

    /// Simulates the loopback peer info that
    /// `into_make_service_with_connect_info` injects in production; raw
    /// router `oneshot` calls omit it, which the DDoS layer fail-closes on.
    fn with_loopback(req: Request<Body>) -> Request<Body> {
        let (mut parts, body) = req.into_parts();
        parts.extensions.insert(ConnectInfo(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            50123,
        )));
        Request::from_parts(parts, body)
    }

    #[test]
    fn tls_validation_fails_for_missing_cert() {
        let key_file = NamedTempFile::new().unwrap();
        let missing_cert = std::path::Path::new("/nonexistent/cert.pem");
        let result = validate_tls_files(missing_cert, key_file.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cert"));
    }

    #[test]
    fn tls_validation_fails_for_missing_key() {
        let mut cert_file = NamedTempFile::new().unwrap();
        writeln!(
            cert_file,
            "-----BEGIN CERTIFICATE-----\nABCD\n-----END CERTIFICATE-----"
        )
        .unwrap();
        let missing_key = std::path::Path::new("/nonexistent/key.pem");
        let result = validate_tls_files(cert_file.path(), missing_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("key"));
    }

    #[test]
    fn tls_validation_fails_for_invalid_pem_cert() {
        let mut cert_file = NamedTempFile::new().unwrap();
        writeln!(cert_file, "this is not a PEM certificate").unwrap();
        let key_file = NamedTempFile::new().unwrap();
        let result = validate_tls_files(cert_file.path(), key_file.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PEM CERTIFICATE"));
    }

    #[tokio::test]
    async fn malformed_json_returns_parse_error_with_http_200() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let (status, body) = rpc_call(app, "{not json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn chain_id_roundtrip_through_full_stack() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let (status, body) = rpc_call(
            app,
            r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":7}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], 7);
        assert_eq!(body["result"], json!(format!("0x{:x}", SXIAUM_CHAIN_ID)));
    }

    #[tokio::test]
    async fn transaction_count_is_dispatched_to_state_layer() {
        // Regression: the legacy `contains("Transaction")` rule misrouted this
        // method to the tx handler which had no matching arm.
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let (_, body) = rpc_call(
            app,
            r#"{"jsonrpc":"2.0","method":"eth_getTransactionCount","params":["0x1111111111111111111111111111111111111111","latest"],"id":9}"#,
        )
        .await;
        assert_ne!(
            body["error"]["code"], -32601,
            "eth_getTransactionCount must reach its state-layer implementation"
        );
    }

    #[tokio::test]
    async fn batch_requests_are_processed_individually() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let (_, body) = rpc_call(
            app,
            r#"[
                {"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
                {"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":"a"}
            ]"#,
        )
        .await;
        let arr = body.as_array().expect("batch yields array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["result"], json!(format!("0x{:x}", SXIAUM_CHAIN_ID)));
        assert_eq!(arr[1]["result"], json!(crate::SERVER_VERSION));
        assert_eq!(arr[1]["id"], "a");
    }

    #[tokio::test]
    async fn oversized_batch_rejected_with_single_error() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let mut items = Vec::new();
        for i in 0..(crate::MAX_BATCH_REQUESTS + 1) {
            items.push(format!(
                r#"{{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":{}}}"#,
                i
            ));
        }
        let (_, body) = rpc_call(app, &format!("[{}]", items.join(","))).await;
        assert!(body["error"].is_object(), "oversized batch -> single error");
        assert_eq!(body["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn empty_batch_yields_single_invalid_request_error() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();
        let (_, body) = rpc_call(app, "[]").await;
        assert_eq!(body["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn nested_object_ids_rejected_end_to_end() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();
        let (_, body) = rpc_call(
            app,
            r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":{"evil":[1,2]}}"#,
        )
        .await;
        assert_eq!(body["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn admin_methods_rejected_without_token_over_http() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let request = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","method":"admin_addPeer","params":[],"id":1}"#,
            ))
            .unwrap();
        let response = app.oneshot(with_loopback(request)).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rest_block_endpoint_returns_404_for_missing_height() {
        let context = test_context().await;
        let app = RpcServer::new(Arc::clone(&context), RpcConfig::default()).build_router();

        let request = Request::builder()
            .uri("/blocks/999999")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(with_loopback(request)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    async fn rpc_call(app: Router, body: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/rpc")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(with_loopback(request)).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }
}
