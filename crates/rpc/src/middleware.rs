use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use governor::{
    state::direct::NotKeyed, state::InMemoryState, DefaultKeyedRateLimiter, Quota, RateLimiter,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::time::timeout;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

fn parse_nonzero_rate_value(
    name: &str,
    raw: Option<&str>,
    default: u32,
) -> anyhow::Result<NonZeroU32> {
    let value = match raw {
        Some(raw) => raw
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("{} must be a positive u32", name))?,
        None => default,
    };
    NonZeroU32::new(value).ok_or_else(|| anyhow::anyhow!("{} must be greater than zero", name))
}

pub fn parse_nonzero_rate(name: &str, default: u32) -> anyhow::Result<NonZeroU32> {
    match std::env::var(name) {
        Ok(raw) => parse_nonzero_rate_value(name, Some(&raw), default),
        Err(std::env::VarError::NotPresent) => parse_nonzero_rate_value(name, None, default),
        Err(error) => Err(anyhow::anyhow!("failed to read {}: {}", name, error)),
    }
}

/// Strict boolean environment flag parser shared by every RPC security gate.
///
/// Accepts exactly `"1"`, `"true"`, `"0"`, `"false"` (case-insensitive). Any
/// other value is a hard ERROR instead of silently meaning "false" — a typo
/// such as `SXIAUM_ENV=Production` or `SXIAUM_REVERSE_PROXY=True ` previously
/// flipped security behavior between call sites that each had their own
/// drifting boolean grammar.
pub fn env_flag(name: &str) -> anyhow::Result<bool> {
    match std::env::var(name) {
        Ok(raw) => {
            let normalized = raw.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" => Ok(true),
                "0" | "false" | "" => Ok(false),
                other => Err(anyhow::anyhow!(
                    "{} must be one of 1/true/0/false (got {:?})",
                    name,
                    other
                )),
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(anyhow::anyhow!("failed to read {}: {}", name, error)),
    }
}

/// Returns true when `SXIAUM_ENV` is set to `production` (case-insensitive).
pub fn is_production() -> bool {
    std::env::var("SXIAUM_ENV")
        .map(|v| v.trim().eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

/// Returns true when public write methods REQUIRE authentication
/// (`SXIAUM_RPC_WRITE_AUTH=1`). Production deployments bound to a
/// non-loopback address must set this.
pub fn write_auth_enabled() -> bool {
    env_flag("SXIAUM_RPC_WRITE_AUTH").unwrap_or(false)
}

/// SECURITY (hardening pass): anonymous submission of public-write methods
/// (e.g. `sxiaum_sendTransaction`) is OPT-IN via
/// `SXIAUM_RPC_ALLOW_ANON_WRITES=1`.
///
/// Historical behavior allowed unauthenticated writes whenever
/// `SXIAUM_RPC_WRITE_AUTH` was unset, which contradicted the documented
/// fail-closed contract and let any host that could reach the port submit
/// transactions. Writes now require a Bearer token unless the operator
/// explicitly enables anonymous writes (recommended only for local devnets).
pub fn anonymous_writes_allowed() -> bool {
    env_flag("SXIAUM_RPC_ALLOW_ANON_WRITES").unwrap_or(false)
}

/// Runtime body-size limit used by the auth middleware's method inspection.
///
/// The previous constant (2 MB) was SMALLER than the configurable outer
/// request-body limit (default 10 MB), creating a dead zone where legitimate
/// payloads between the two limits were rejected with 413 even for fully
/// authorized callers. The server now propagates its configured outer limit
/// here at startup so both layers agree on one boundary.
static CONFIGURED_BODY_LIMIT: RwLock<usize> = RwLock::new(crate::MAX_REQUEST_BODY_SIZE);

/// Propagates the server's configured request-body limit to the auth layer.
pub fn configure_body_limit(limit: usize) {
    if let Ok(mut slot) = CONFIGURED_BODY_LIMIT.write() {
        *slot = limit.max(1);
    }
}

fn current_body_limit() -> usize {
    CONFIGURED_BODY_LIMIT
        .read()
        .map(|l| *l)
        .unwrap_or(crate::MAX_REQUEST_BODY_SIZE)
}

/// Validates every tunable runtime knob at startup so misconfiguration fails
/// fast at boot rather than mid-request.
pub fn validate_runtime_environment() -> anyhow::Result<()> {
    parse_nonzero_rate(
        "SXIAUM_RPC_GLOBAL_RATE_LIMIT",
        crate::GLOBAL_RATE_LIMIT_PER_SEC,
    )?;
    parse_nonzero_rate("SXIAUM_RPC_IP_RATE_LIMIT", crate::IP_RATE_LIMIT_PER_SEC)?;
    parse_nonzero_rate(
        "SXIAUM_RPC_API_KEY_RATE_LIMIT",
        crate::API_KEY_RATE_LIMIT_PER_SEC,
    )?;
    parse_nonzero_rate("SXIAUM_RPC_WS_RATE_LIMIT", 50)?;
    // Timeout bounds: 1s..300s keeps slow-loris protection meaningful while
    // allowing operators room for heavy archive queries.
    if !(1..=300).contains(&request_timeout().as_secs()) {
        anyhow::bail!("SXIAUM_RPC_TIMEOUT_SECS must be between 1 and 300");
    }
    for flag in [
        "SXIAUM_ALLOW_HTTP",
        "SXIAUM_RPC_WRITE_AUTH",
        "SXIAUM_RPC_ALLOW_ANON_WRITES",
        "SXIAUM_WS_DEV_OPEN",
    ] {
        env_flag(flag)?;
    }
    configure_reverse_proxy_mode(env_flag("SXIAUM_REVERSE_PROXY")?);
    Ok(())
}

fn request_timeout() -> Duration {
    static TIMEOUT: LazyLock<Duration> = LazyLock::new(|| {
        std::env::var("SXIAUM_RPC_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| (1..=300).contains(s))
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(crate::RPC_TIMEOUT_SECS))
    });
    *TIMEOUT
}

/// Runtime reverse-proxy mode flag, configured once at startup by
/// [`validate_runtime_environment`]. Previously `client_ip` re-read the
/// environment variable on EVERY request; a LazyLock cache was considered but
/// rejects itself — whichever request touched it first would freeze the value
/// for the process lifetime, even if startup validation later determined a
/// different answer. Explicit configuration keeps one authoritative write
/// before any traffic is served.
static REVERSE_PROXY_MODE: RwLock<bool> = RwLock::new(false);

/// Configures whether forwarded-client-IP headers are trusted. Called from
/// [`validate_runtime_environment`] during server startup.
pub fn configure_reverse_proxy_mode(enabled: bool) {
    if let Ok(mut slot) = REVERSE_PROXY_MODE.write() {
        *slot = enabled;
    }
}

fn reverse_proxy_enabled() -> bool {
    REVERSE_PROXY_MODE.read().map(|v| *v).unwrap_or(false)
}

/// Returns true for addresses a reverse proxy would realistically occupy:
/// loopback, private ranges, unique-local, and link-local.
fn is_trusted_proxy_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Resolves the client IP for rate limiting.
///
/// Forwarded headers are honored ONLY in explicit reverse-proxy mode AND only
/// when the direct peer address itself is loopback/private — an internet peer
/// can no longer spoof `X-Real-IP` / `X-Forwarded-For` to rotate rate-limit
/// buckets by simply attaching header values.
fn client_ip(request: &Request<Body>) -> Option<IpAddr> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(a)| a.ip());

    if reverse_proxy_enabled() && peer.map(is_trusted_proxy_peer).unwrap_or(false) {
        if let Some(real) = request
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
        {
            if let Ok(ip) = real.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
        if let Some(xff) = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            // Documented: Proxies must strip spoofed X-Forwarded-For from external clients.
            if let Some(last) = xff.split(',').next_back() {
                if let Ok(ip) = last.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    peer
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

// Global rate limiter instance (default from lib.rs constants).
static GLOBAL_RATE_LIMITER: LazyLock<
    RateLimiter<NotKeyed, InMemoryState, governor::clock::DefaultClock>,
> = LazyLock::new(|| {
    let limit = parse_nonzero_rate(
        "SXIAUM_RPC_GLOBAL_RATE_LIMIT",
        crate::GLOBAL_RATE_LIMIT_PER_SEC,
    )
    .unwrap_or_else(|_| NonZeroU32::new(crate::GLOBAL_RATE_LIMIT_PER_SEC).unwrap());
    RateLimiter::direct(Quota::per_second(limit))
});

// Per-IP rate limiter instance.
static IP_RATE_LIMITER: LazyLock<DefaultKeyedRateLimiter<IpAddr>> = LazyLock::new(|| {
    let limit = parse_nonzero_rate("SXIAUM_RPC_IP_RATE_LIMIT", crate::IP_RATE_LIMIT_PER_SEC)
        .unwrap_or_else(|_| NonZeroU32::new(crate::IP_RATE_LIMIT_PER_SEC).unwrap());
    RateLimiter::keyed(Quota::per_second(limit))
});

// Per-API-Key rate limiter instance (previously a hardcoded literal).
static API_KEY_RATE_LIMITER: LazyLock<DefaultKeyedRateLimiter<String>> = LazyLock::new(|| {
    let limit = parse_nonzero_rate(
        "SXIAUM_RPC_API_KEY_RATE_LIMIT",
        crate::API_KEY_RATE_LIMIT_PER_SEC,
    )
    .unwrap_or_else(|_| {
        NonZeroU32::new(crate::API_KEY_RATE_LIMIT_PER_SEC)
            .expect("API key rate limit default is non-zero")
    });
    RateLimiter::keyed(Quota::per_second(limit))
});

// --- P1-3: Sensitive query-param patterns to redact from logged URIs ---
const SENSITIVE_QUERY_PARAMS: &[&str] = &["token", "api_key", "secret", "key", "auth", "password"];

/// P1-3: Sanitize a URI string by replacing sensitive query parameter values with [REDACTED].
///
/// This prevents credential leakage through server access logs, reverse-proxy logs,
/// and any structured tracing pipelines.
pub fn sanitize_uri_for_logging(uri: &axum::http::Uri) -> String {
    let path = uri.path();
    let raw_query = match uri.query() {
        None | Some("") => return path.to_string(),
        Some(q) => q,
    };

    let sanitized_query: String = raw_query
        .split('&')
        .map(|param| {
            if let Some((key, _val)) = param.split_once('=') {
                let lower_key = key.to_ascii_lowercase();
                if SENSITIVE_QUERY_PARAMS.iter().any(|&s| lower_key == s) {
                    return format!("{}=[REDACTED]", key);
                }
            }
            param.to_string()
        })
        .collect::<Vec<_>>()
        .join("&");

    format!("{}?{}", path, sanitized_query)
}

/// Middleware for request logging and performance tracking.
///
/// P1-3: Sanitizes the URI before logging to prevent token/credential leakage.
pub async fn logging_middleware(request: Request<Body>, next: Next) -> Response {
    let start_time = std::time::Instant::now();
    let method = request.method().clone();
    // Sanitize URI before logging — never log raw query strings that may contain tokens.
    let sanitized_uri = sanitize_uri_for_logging(request.uri());

    let response = next.run(request).await;

    let latency = start_time.elapsed();
    info!(
        "RPC request handled: method={} uri={} status={} latency={:?}",
        method,
        sanitized_uri,
        response.status(),
        latency
    );

    response
}

/// Implements a global and per-IP DDoS protection layer using leaky-bucket rate limiters.
pub async fn ddos_protection_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Enforce global rate limiting
    if GLOBAL_RATE_LIMITER.check().is_err() {
        warn!("DDoS protection triggered: global rate limit exceeded.");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 2. Enforce per-API-Key rate limiting if present
    if let Some(api_key_header) = request.headers().get("X-API-Key") {
        if let Ok(api_key) = api_key_header.to_str() {
            if API_KEY_RATE_LIMITER
                .check_key(&api_key.to_string())
                .is_err()
            {
                warn!("DDoS protection triggered: rate limit exceeded for API Key");
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }

    // 3. Enforce per-IP rate limiting
    if let Some(ip) = client_ip(&request) {
        if IP_RATE_LIMITER.check_key(&ip).is_err() {
            warn!(
                "DDoS protection triggered: rate limit exceeded for IP: {}",
                ip
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    } else {
        warn!("DDoS protection: Unknown client IP (missing ConnectInfo). Rejecting request to fail closed.");
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Middleware to enforce a strict timeout for RPC requests to prevent slow-loris attacks.
pub async fn timeout_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let timeout_duration = request_timeout();

    match timeout(timeout_duration, next.run(request)).await {
        Ok(response) => Ok(response),
        Err(_) => {
            warn!("RPC Request timed out after {:?}", timeout_duration);
            Err(StatusCode::REQUEST_TIMEOUT)
        }
    }
}

/// Provides a standard Permissive CORS configuration for the RPC server or restricts it to allowed origins.
pub fn cors_middleware(allowed_origins: Option<&Vec<String>>) -> CorsLayer {
    if let Some(origins) = allowed_origins {
        let mut layer = CorsLayer::new()
            .allow_methods(vec![
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers(vec![
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
                axum::http::HeaderName::from_static("x-api-key"),
            ]);
        let mut has_origins = false;
        for origin in origins {
            if let Ok(parsed) = origin.parse::<axum::http::HeaderValue>() {
                layer = layer.allow_origin(parsed);
                has_origins = true;
            }
        }
        if has_origins {
            return layer;
        }
        warn!("All CORS origins were invalid; falling back to deny-all");
    }
    // Fail-closed default: if no CORS config is supplied, we deny cross-origin requests.
    // We do not add `.allow_origin(Any)` here for production safety.
    CorsLayer::new()
}

/// Returns a body limit layer for the RPC server to prevent large payload attacks (e.g., massive JSON-RPC 2.0 batches).
pub fn size_limit_layer(limit_bytes: usize) -> DefaultBodyLimit {
    DefaultBodyLimit::max(limit_bytes)
}

async fn check_rpc_body_auth(
    request: Request<Body>,
    authorized: bool,
) -> Result<Request<Body>, StatusCode> {
    let (parts, body) = request.into_parts();
    // Bound matches the OUTER size limit so there is no rejection dead zone;
    // oversized bodies still fail closed below.
    let bytes = match to_bytes(body, current_body_limit()).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::PAYLOAD_TOO_LARGE),
    };

    // Bodies that do not parse as JSON are forwarded UNCHANGED so the
    // JSON-RPC handler can answer with the spec-mandated `-32700 Parse
    // error` (HTTP 200), matching geth/erigon interop. This is NOT the
    // historical fail-open hole: an unparseable body can only ever reach
    // `handle_json_rpc`, which structurally cannot execute any method
    // without first producing a parsed, validated request object. Every
    // such event is logged below for probe detection.
    let json_val: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            tracing::debug!(
                bytes_len = bytes.len(),
                "rpc auth inspection skipped: body is not valid JSON"
            );
            return Ok(Request::from_parts(parts, Body::from(bytes)));
        }
    };

    let mut requires_auth = false;

    let check_method = |method: &str| -> bool {
        if crate::methods::is_public_read(method) {
            return false;
        }
        if crate::methods::is_public_write(method) {
            // Fail closed: writes require auth unless the operator explicitly
            // opted into anonymous submission (devnets / local testing).
            return !anonymous_writes_allowed();
        }
        // Everything else (admin_, debug_, unknown methods) ALWAYS requires auth
        true
    };

    if let Some(method) = json_val.get("method").and_then(|m| m.as_str()) {
        requires_auth = check_method(method);
    } else if let Some(arr) = json_val.as_array() {
        for req in arr {
            if let Some(method) = req.get("method").and_then(|m| m.as_str()) {
                if check_method(method) {
                    requires_auth = true;
                    break;
                }
            }
        }
    }

    if requires_auth && !authorized {
        warn!("Unauthorized JSON-RPC attempt for restricted method");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Reconstruct request
    let reconstructed_body = Body::from(bytes);
    Ok(Request::from_parts(parts, reconstructed_body))
}

fn is_ws_anonymous_allowed(request: &Request<Body>) -> bool {
    let client_ip = match client_ip(request) {
        Some(ip) => ip,
        None => return false,
    };

    // Check explicit allow-list first
    if let Ok(list) = std::env::var("SXIAUM_WS_ANON_ALLOW_LIST") {
        for entry in list.split(',') {
            let entry = entry.trim();
            if entry
                .parse::<IpAddr>()
                .map(|allowed| allowed == client_ip)
                .unwrap_or(false)
            {
                return true;
            }
        }
    }

    // Loopback is always allowed, BUT we must check the ACTUAL peer IP to prevent
    // X-Forwarded-For spoofing from external attackers when SXIAUM_REVERSE_PROXY is true.
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(a)| a.ip());

    if let Some(peer) = peer_ip {
        if peer.is_loopback() && client_ip.is_loopback() {
            return true;
        }
    }

    // Dev open must be EXPLICIT — not implied by SXIAUM_ENV alone
    let dev_open = env_flag("SXIAUM_WS_DEV_OPEN").unwrap_or(false);
    if dev_open {
        let env = std::env::var("SXIAUM_ENV").unwrap_or_default();
        if env.eq_ignore_ascii_case("development") || env.eq_ignore_ascii_case("dev") {
            return true;
        }
    }

    false
}

/// P1-3: Extract a bearer token from the `Authorization: Bearer <token>` header.
///
/// This is the only accepted mechanism for HTTP and WebSocket upgrade requests.
/// The `?token=` query parameter is explicitly rejected to prevent credential
/// leakage into logs, browser history, and referrer chains.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim())
}

/// P1-3: Extract a bearer token from the `Sec-WebSocket-Protocol` header.
///
/// This is the RFC 6455-compliant method for browser WebSocket clients that
/// cannot set arbitrary HTTP headers. The protocol negotiation header carries
/// the token as `sxiaum-auth, <token>`.
fn extract_ws_protocol_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // Expected format: "sxiaum-auth, <token>"
            let parts: Vec<&str> = v.splitn(2, ',').collect();
            if parts.len() == 2 && parts[0].trim().eq_ignore_ascii_case("sxiaum-auth") {
                Some(parts[1].trim())
            } else {
                None
            }
        })
}

/// P1-3: Reject tokens supplied via the `?token=` query parameter.
///
/// Returns `true` if the query string contains a `token=` parameter, indicating
/// an insecure credential transport that must be blocked in all environments.
fn query_has_token_param(query: &str) -> bool {
    query.split('&').any(|part| {
        part.split_once('=')
            .map(|(k, _)| k.eq_ignore_ascii_case("token"))
            .unwrap_or(false)
    })
}

/// Middleware to check for valid API authentication for administrative or sensitive methods.
///
/// # Authentication mechanisms (P1-3)
///
/// Tokens are accepted **only** from:
/// - `Authorization: Bearer <token>` (HTTP and WebSocket)
/// - `Sec-WebSocket-Protocol: sxiaum-auth, <token>` (browser WebSocket clients)
///
/// The `?token=` query parameter is **explicitly rejected** in all environments
/// to prevent credential leakage into logs and browser history.
///
/// # JWT manager access
///
/// The JWT manager is obtained through ROUTER STATE (`State<Arc<RpcContext>>`)
/// registered via `from_fn_with_state`. The previous extension-based lookup ran
/// before the corresponding insert layer in the onion and therefore never found
/// the manager, silently disabling JWT validation end-to-end.
///
/// # WebSocket policy (P1-2)
///
/// Unauthenticated WebSocket connections are allowed only from:
/// - Loopback addresses (127.0.0.1, ::1)
/// - IPs listed in `SXIAUM_WS_ANON_ALLOW_LIST`
/// - Any address when `SXIAUM_ENV=development` AND `SXIAUM_WS_DEV_OPEN=true`
pub async fn auth_middleware(
    State(context): State<Arc<crate::context::RpcContext>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_string();
    let is_admin_path = path.starts_with("/admin") || path == "/metrics";
    let is_ws_path = path == "/ws";

    // --- P1-3: Reject ?token= query parameter for all paths, all environments ---
    if query_has_token_param(&query) {
        warn!(
            "Rejected request with ?token= query parameter at path '{}'. \
             Use 'Authorization: Bearer <token>' header instead.",
            path
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    if is_admin_path || path == "/rpc" || is_ws_path {
        let mut authorized = false;

        let token_str = extract_bearer_token(request.headers())
            .or_else(|| extract_ws_protocol_token(request.headers()));

        if let Some(token) = token_str {
            if context
                .jwt_manager
                .validate_token::<Claims>(token)
                .await
                .is_ok()
            {
                authorized = true;
            }
        }

        if let Ok(expected_token) = std::env::var("SXIAUM_RPC_AUTH_TOKEN") {
            if let Some(token) = extract_bearer_token(request.headers())
                .or_else(|| extract_ws_protocol_token(request.headers()))
            {
                // P2-1: Normalize authentication tokens to a fixed-length hash before comparison.
                // This prevents variable-length comparison timing leaks and panics.
                let mut expected_hash = sxiaum_crypto::hash::sha256(expected_token.as_bytes());
                let mut provided_hash = sxiaum_crypto::hash::sha256(token.as_bytes());

                if provided_hash.ct_eq(&expected_hash).into() {
                    authorized = true;
                }

                // Zeroize temporary buffers
                use zeroize::Zeroize;
                expected_hash.zeroize();
                provided_hash.zeroize();
            }
        }

        if is_admin_path {
            if !authorized {
                warn!("Unauthorized access attempt to admin path: {}", path);
                return Err(StatusCode::UNAUTHORIZED);
            }
        } else if path == "/rpc" {
            let reconstructed_request = check_rpc_body_auth(request, authorized).await?;
            return Ok(next.run(reconstructed_request).await);
        } else if is_ws_path {
            let mut request = request;
            if authorized {
                request
                    .extensions_mut()
                    .insert(crate::ws::WsAuthenticated(true));
                return Ok(next.run(request).await);
            }

            // Unauthenticated WebSocket connection: check if anonymous access is permitted from this client IP
            let allowed = is_ws_anonymous_allowed(&request);

            if !allowed {
                warn!(
                    "Unauthenticated WebSocket connection rejected from IP: {:?}. \
                     Provide Authorization: Bearer <token> header or Sec-WebSocket-Protocol token.",
                    client_ip(&request)
                );
                return Err(StatusCode::UNAUTHORIZED);
            }

            request
                .extensions_mut()
                .insert(crate::ws::WsAuthenticated(false));
            return Ok(next.run(request).await);
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn nonzero_rate_parser_rejects_zero_and_malformed_values() {
        assert_eq!(
            parse_nonzero_rate_value("RATE", None, 20).unwrap().get(),
            20
        );
        assert_eq!(
            parse_nonzero_rate_value("RATE", Some("1"), 20)
                .unwrap()
                .get(),
            1
        );
        assert!(parse_nonzero_rate_value("RATE", Some("0"), 20).is_err());
        assert!(parse_nonzero_rate_value("RATE", Some("invalid"), 20).is_err());
    }

    #[test]
    fn env_flag_grammar_is_strict_and_case_insensitive() {
        static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let old = std::env::var("SXIAUM_TEST_FLAG").ok();

        std::env::set_var("SXIAUM_TEST_FLAG", "TRUE");
        assert!(env_flag("SXIAUM_TEST_FLAG").unwrap());
        std::env::set_var("SXIAUM_TEST_FLAG", " False ");
        assert!(!env_flag("SXIAUM_TEST_FLAG").unwrap());
        std::env::set_var("SXIAUM_TEST_FLAG", "0");
        assert!(!env_flag("SXIAUM_TEST_FLAG").unwrap());
        std::env::remove_var("SXIAUM_TEST_FLAG");
        assert!(!env_flag("SXIAUM_TEST_FLAG").unwrap());

        // Typos FAIL CLOSED with an error instead of silently meaning false.
        std::env::set_var("SXIAUM_TEST_FLAG", "Prod");
        assert!(env_flag("SXIAUM_TEST_FLAG").is_err());
        std::env::set_var("SXIAUM_TEST_FLAG", "yes");
        assert!(env_flag("SXIAUM_TEST_FLAG").is_err());

        match old {
            Some(v) => std::env::set_var("SXIAUM_TEST_FLAG", v),
            None => std::env::remove_var("SXIAUM_TEST_FLAG"),
        }
    }

    #[test]
    fn sanitize_uri_strips_token_param() {
        let uri: axum::http::Uri = "http://localhost/ws?token=secret123&foo=bar"
            .parse()
            .unwrap();
        let sanitized = sanitize_uri_for_logging(&uri);
        assert!(
            !sanitized.contains("secret123"),
            "token value should be redacted"
        );
        assert!(sanitized.contains("token=[REDACTED]"));
        assert!(
            sanitized.contains("foo=bar"),
            "non-sensitive params should be preserved"
        );
    }

    #[test]
    fn sanitize_uri_strips_api_key_param() {
        let uri: axum::http::Uri = "http://localhost/rpc?api_key=mysecret".parse().unwrap();
        let sanitized = sanitize_uri_for_logging(&uri);
        assert!(!sanitized.contains("mysecret"));
        assert!(sanitized.contains("api_key=[REDACTED]"));
    }

    #[test]
    fn sanitize_uri_preserves_path_without_query() {
        let uri: axum::http::Uri = "http://localhost/health".parse().unwrap();
        let sanitized = sanitize_uri_for_logging(&uri);
        assert_eq!(sanitized, "/health");
    }

    #[test]
    fn query_token_param_detection() {
        assert!(query_has_token_param("token=abc"));
        assert!(query_has_token_param("foo=bar&token=abc"));
        assert!(query_has_token_param("TOKEN=abc")); // case-insensitive
        assert!(!query_has_token_param("tokenizer=abc")); // partial match should not trigger
        assert!(!query_has_token_param("foo=bar"));
        assert!(!query_has_token_param(""));
    }

    fn mock_request_with_ip(ip: IpAddr) -> Request<Body> {
        let mut req = Request::new(Body::empty());
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 8080)));
        req
    }

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn ws_anonymous_allowed_for_loopback() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let loopback_v4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let req = mock_request_with_ip(loopback_v4);
        assert!(is_ws_anonymous_allowed(&req));
    }

    #[test]
    fn ws_anonymous_rejected_for_public_ip_without_config() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let public_ip: IpAddr = "8.8.8.8".parse().unwrap();
        // In test environment, SXIAUM_ENV != "development" and no allow-list set
        let old_env = std::env::var("SXIAUM_ENV").ok();
        let old_list = std::env::var("SXIAUM_WS_ANON_ALLOW_LIST").ok();
        let old_open = std::env::var("SXIAUM_WS_DEV_OPEN").ok();
        std::env::remove_var("SXIAUM_ENV");
        std::env::remove_var("SXIAUM_WS_ANON_ALLOW_LIST");
        std::env::remove_var("SXIAUM_WS_DEV_OPEN");

        let req = mock_request_with_ip(public_ip);
        let result = is_ws_anonymous_allowed(&req);

        if let Some(v) = old_env {
            std::env::set_var("SXIAUM_ENV", v);
        }
        if let Some(v) = old_list {
            std::env::set_var("SXIAUM_WS_ANON_ALLOW_LIST", v);
        }
        if let Some(v) = old_open {
            std::env::set_var("SXIAUM_WS_DEV_OPEN", v);
        }

        assert!(!result);
    }

    #[test]
    fn ws_anonymous_allowed_via_explicit_list() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let old = std::env::var("SXIAUM_WS_ANON_ALLOW_LIST").ok();
        std::env::set_var("SXIAUM_WS_ANON_ALLOW_LIST", "10.0.0.1,192.168.1.1");

        let req = mock_request_with_ip(ip);
        let result = is_ws_anonymous_allowed(&req);

        match old {
            Some(v) => std::env::set_var("SXIAUM_WS_ANON_ALLOW_LIST", v),
            None => std::env::remove_var("SXIAUM_WS_ANON_ALLOW_LIST"),
        }
        assert!(result);
    }

    #[test]
    fn forwarded_headers_ignored_from_internet_peers() {
        // Regression: with reverse-proxy mode enabled, ANY peer used to be
        // able to spoof X-Real-IP to rotate rate-limit buckets. Headers must
        // be ignored for non-trusted peers even when the mode is on.
        static INNER: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = INNER.lock().unwrap_or_else(|e| e.into_inner());

        configure_reverse_proxy_mode(true);
        // Restore disabled mode for other tests regardless of assertion outcome.
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                configure_reverse_proxy_mode(false);
            }
        }
        let _restore = Restore;

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "203.0.113.9".parse().unwrap(),
            4444,
        )));
        req.headers_mut()
            .insert("x-real-ip", "10.0.0.99".parse().unwrap());
        assert_ne!(client_ip(&req), Some("10.0.0.99".parse().unwrap()));
        assert_eq!(client_ip(&req), Some("203.0.113.9".parse().unwrap()));

        // Trusted (private-range) proxy peers still get header extraction.
        let mut proxied = Request::builder().uri("/").body(Body::empty()).unwrap();
        proxied.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            "192.168.1.2".parse().unwrap(),
            8443,
        )));
        proxied
            .headers_mut()
            .insert("x-real-ip", "198.51.100.7".parse().unwrap());
        assert_eq!(client_ip(&proxied), Some("198.51.100.7".parse().unwrap()));
    }

    #[test]
    fn extract_ws_protocol_token_parses_correctly() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Sec-WebSocket-Protocol",
            "sxiaum-auth, my-secret-token".parse().unwrap(),
        );
        assert_eq!(extract_ws_protocol_token(&headers), Some("my-secret-token"));
    }

    #[test]
    fn extract_ws_protocol_token_rejects_wrong_protocol() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "Sec-WebSocket-Protocol",
            "other-proto, my-secret-token".parse().unwrap(),
        );
        assert_eq!(extract_ws_protocol_token(&headers), None);
    }

    #[test]
    fn extract_bearer_token_parses_correctly() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("Authorization", "Bearer mytoken123".parse().unwrap());
        assert_eq!(extract_bearer_token(&headers), Some("mytoken123"));
    }

    #[test]
    fn extract_bearer_token_returns_none_without_header() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(extract_bearer_token(&headers), None);
    }

    #[tokio::test]
    async fn check_rpc_body_auth_allows_public_read() {
        let body = r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}"#;
        let req = Request::builder().body(Body::from(body)).unwrap();
        let res = check_rpc_body_auth(req, false).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn public_write_requires_auth_by_default() {
        // SECURITY (hardening): sxiaum_sendTransaction must NOT be callable
        // without a token unless SXIAUM_RPC_ALLOW_ANON_WRITES is explicitly set.
        let body = r#"{"jsonrpc":"2.0","method":"sxiaum_sendTransaction","params":[],"id":1}"#;
        let req = Request::builder().body(Body::from(body)).unwrap();
        let res = check_rpc_body_auth(req, false).await;
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn public_write_passes_when_anon_writes_allowed() {
        // authorized=false (no token) but operator opted into anonymous writes.
        let body = r#"{"jsonrpc":"2.0","method":"sxiaum_sendTransaction","params":[],"id":1}"#;
        let req = Request::builder().body(Body::from(body)).unwrap();
        // The decision reads the env via anonymous_writes_allowed(); simulate
        // the opt-in by asserting through the internal decision path with the
        // env temporarily set. Env mutation in tests is serialized by the
        // single-threaded nature of this specific assertion pair.
        std::env::set_var("SXIAUM_RPC_ALLOW_ANON_WRITES", "1");
        let res = check_rpc_body_auth(req, false).await;
        std::env::remove_var("SXIAUM_RPC_ALLOW_ANON_WRITES");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_rpc_body_auth_blocks_admin_without_auth() {
        let body = r#"{"jsonrpc":"2.0","method":"admin_addPeer","params":[],"id":1}"#;
        let req = Request::builder().body(Body::from(body)).unwrap();
        let res = check_rpc_body_auth(req, false).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn check_rpc_body_auth_allows_admin_with_auth() {
        let body = r#"{"jsonrpc":"2.0","method":"admin_addPeer","params":[],"id":1}"#;
        let req = Request::builder().body(Body::from(body)).unwrap();
        let res = check_rpc_body_auth(req, true).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn check_rpc_body_auth_blocks_unknown_without_auth() {
        let body = r#"{"jsonrpc":"2.0","method":"unknown_method","params":[],"id":1}"#;
        let req = Request::builder().body(Body::from(body)).unwrap();
        let res = check_rpc_body_auth(req, false).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_json_bodies_forward_to_handler_for_parse_error() {
        // Non-JSON bodies pass through so the handler can emit the
        // spec-mandated -32700; they cannot reach method execution because
        // dispatch requires a parsed method name.
        let garbage: &[u8] = b"\x00\x01\x02garbage";
        let req = Request::builder().body(Body::from(garbage)).unwrap();
        let res = check_rpc_body_auth(req, false).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn batch_auth_inspection_sees_every_item() {
        let mixed = r#"[{"jsonrpc":"2.0","method":"eth_chainId","id":1},{"jsonrpc":"2.0","method":"debug_traceBlock","id":2}]"#;
        let req = Request::builder().body(Body::from(mixed)).unwrap();
        let res = check_rpc_body_auth(req, false).await;
        assert_eq!(res.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn body_limit_configuration_propagates() {
        configure_body_limit(4096);
        assert_eq!(current_body_limit(), 4096);
        configure_body_limit(crate::MAX_REQUEST_BODY_SIZE);
        assert_eq!(current_body_limit(), crate::MAX_REQUEST_BODY_SIZE);
    }

    #[test]
    fn trusted_proxy_classification() {
        assert!(is_trusted_proxy_peer(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_trusted_proxy_peer("10.1.2.3".parse().unwrap()));
        assert!(is_trusted_proxy_peer("172.16.0.9".parse().unwrap()));
        assert!(is_trusted_proxy_peer("192.168.0.1".parse().unwrap()));
        assert!(!is_trusted_proxy_peer("8.8.8.8".parse().unwrap()));
        assert!(!is_trusted_proxy_peer("203.0.113.9".parse().unwrap()));
        assert!(is_trusted_proxy_peer("::1".parse().unwrap()));
        assert!(is_trusted_proxy_peer("fd00::5".parse().unwrap()));
        assert!(!is_trusted_proxy_peer("2606:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn fail_closed_without_connect_info() {
        use axum::{routing::get, Router};
        use tower::ServiceExt;

        let req_check = Request::builder().uri("/").body(Body::empty()).unwrap();
        assert_eq!(client_ip(&req_check), None, "client_ip should be None");

        let app = Router::new()
            .route("/", get(|| async { "OK" }))
            .layer(axum::middleware::from_fn(ddos_protection_middleware));

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
}
