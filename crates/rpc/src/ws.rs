use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use governor::{
    clock::DefaultClock, state::direct::NotKeyed, state::InMemoryState, Quota, RateLimiter,
};
use serde_json::{json, Value};
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::context::RpcContext;

/// Extension key set by the auth middleware to mark the session as authenticated.
///
/// If the extension is absent the connection is anonymous (allowed only from loopback
/// or explicitly allow-listed IPs, as enforced by `auth_middleware`).
#[derive(Clone, Copy, Debug, Default)]
pub struct WsAuthenticated(pub bool);

/// Upper bound on a single WebSocket text message (1 MiB). Subscription
/// requests are tiny; anything near this size is abusive or broken.
const MAX_WS_MESSAGE_BYTES: usize = 1024 * 1024;

/// Handle incoming WebSocket upgrade requests.
///
/// # P1-2: Authentication enforcement
///
/// The auth middleware runs before this handler and has already:
/// 1. Rejected unauthenticated connections from non-loopback / non-allow-listed IPs.
/// 2. Set the `WsAuthenticated` extension to indicate whether the client has presented
///    a valid JWT or bearer token.
///
/// This handler further enforces that `eth_subscribe` requires an authenticated session.
/// Unauthenticated (anonymous loopback) sessions may only call `eth_unsubscribe`.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(context): State<Arc<RpcContext>>,
    axum::extract::Extension(ws_auth): axum::extract::Extension<WsAuthenticated>,
) -> Response {
    let authenticated = ws_auth.0;
    ws.max_message_size(MAX_WS_MESSAGE_BYTES)
        .max_frame_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, context, authenticated))
}

/// WebSocket error codes (JSON-RPC extension).
const WS_ERR_UNAUTHORIZED: i32 = -32001;
const WS_ERR_RATE_LIMITED: i32 = -32005;
const WS_ERR_INVALID_PARAMS: i32 = -32602;
const WS_ERR_METHOD_NOT_FOUND: i32 = -32601;
const WS_ERR_PARSE_ERROR: i32 = -32700;

async fn handle_socket(socket: WebSocket, context: Arc<RpcContext>, authenticated: bool) {
    let (mut sender, mut receiver) = socket.split();

    info!(
        "New WebSocket connection established (authenticated={})",
        authenticated
    );

    let mut subscription_id_counter = 1u64;
    let mut subscriptions: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut event_rx = context.ws_broadcaster.subscribe();

    // WebSocket connection rate limiting (default 50 messages per second per connection)
    let limit = crate::middleware::parse_nonzero_rate("SXIAUM_RPC_WS_RATE_LIMIT", 50)
        .unwrap_or_else(|_| NonZeroU32::new(50).expect("WS rate limit default is non-zero"));
    let rate_limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock> =
        RateLimiter::direct(Quota::per_second(limit));

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if !handle_text_message(
                            &mut sender,
                            &text,
                            &mut subscriptions,
                            &mut subscription_id_counter,
                            &rate_limiter,
                            limit,
                            authenticated,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {
                        // Binary / Ping / Pong frames carry no RPC semantics;
                        // protocol-level pings are answered by the transport.
                        continue;
                    }
                    Some(Err(e)) => {
                        warn!("WebSocket receive error: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            event = event_rx.recv() => {
                match event {
                    Ok((topic, data)) => {
                        for (sub_id, sub_topic) in &subscriptions {
                            if sub_topic == &topic {
                                let event_payload = json!({
                                    "jsonrpc": "2.0",
                                    "method": "eth_subscription",
                                    "params": {
                                        "subscription": sub_id,
                                        "result": data
                                    }
                                });
                                if sender.send(Message::Text(event_payload.to_string())).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        warn!("WebSocket connection lagged, missed {} events", missed);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        info!("Event broadcaster closed");
                        break;
                    }
                }
            }
        }
    }

    info!("WebSocket connection closed");
}

/// Processes one text message. Returns `false` when the connection should close.
#[allow(clippy::too_many_arguments)]
async fn handle_text_message(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    text: &str,
    subscriptions: &mut std::collections::HashMap<String, String>,
    next_subscription_id: &mut u64,
    rate_limiter: &RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    limit: NonZeroU32,
    authenticated: bool,
) -> bool {
    // Apply per-message rate limit
    if rate_limiter.check().is_err() {
        warn!(
            "WebSocket client exceeded rate limit of {} msgs/sec",
            limit.get()
        );
        send_error(
            sender,
            json!(null),
            WS_ERR_RATE_LIMITED,
            "Rate limit exceeded",
        )
        .await;
        return true;
    }

    let Ok(json_msg) = serde_json::from_str::<Value>(text) else {
        warn!("Failed to parse WebSocket message");
        send_error(sender, json!(null), WS_ERR_PARSE_ERROR, "Parse error").await;
        return true;
    };

    let id = json_msg.get("id").cloned().unwrap_or(json!(null));
    let method = json_msg
        .get("method")
        .and_then(|m| m.as_str())
        .unwrap_or("");

    match method {
        "eth_subscribe" => {
            // P1-2: eth_subscribe requires an authenticated session.
            // Anonymous connections (loopback-only) cannot subscribe
            // to real-time events without a valid JWT/token.
            if !authenticated {
                warn!(
                    "Rejected eth_subscribe from unauthenticated session. \
                     Provide Authorization: Bearer <token> or \
                     Sec-WebSocket-Protocol: sxiaum-auth, <token>."
                );
                send_error(
                    sender,
                    id,
                    WS_ERR_UNAUTHORIZED,
                    "Unauthorized: eth_subscribe requires authentication. \
                     Use Authorization: Bearer <token> or \
                     Sec-WebSocket-Protocol: sxiaum-auth, <token>.",
                )
                .await;
                return true;
            }

            if subscriptions.len() >= crate::MAX_WS_SUBSCRIPTIONS_PER_CONN {
                warn!(
                    "WebSocket client exceeded max subscriptions limit ({})",
                    crate::MAX_WS_SUBSCRIPTIONS_PER_CONN
                );
                send_error(
                    sender,
                    id,
                    WS_ERR_RATE_LIMITED,
                    "Maximum subscriptions limit exceeded",
                )
                .await;
                return true;
            }

            let params = json_msg.get("params").and_then(|p| p.as_array());
            if let Some(params) = params {
                if let Some(topic) = params.first().and_then(|t| t.as_str()) {
                    match topic {
                        "newHeads" | "newPendingTransactions" | "logs" => {
                            debug!("eth_subscribe topic: {}", topic);

                            let sub_id = format!("0x{:016x}", *next_subscription_id);
                            *next_subscription_id += 1;

                            subscriptions.insert(sub_id.clone(), topic.to_string());

                            let response = json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": sub_id
                            });

                            if sender
                                .send(Message::Text(response.to_string()))
                                .await
                                .is_err()
                            {
                                return false;
                            }
                        }
                        _ => {
                            send_error(
                                sender,
                                id,
                                WS_ERR_INVALID_PARAMS,
                                "Unsupported subscription topic. Supported topics: newHeads, newPendingTransactions, logs",
                            )
                            .await;
                        }
                    }
                } else {
                    send_error(
                        sender,
                        id,
                        WS_ERR_INVALID_PARAMS,
                        "Invalid params: topic must be a string",
                    )
                    .await;
                }
            } else {
                send_error(
                    sender,
                    id,
                    WS_ERR_INVALID_PARAMS,
                    "Invalid params: expected array",
                )
                .await;
            }
            true
        }
        "eth_unsubscribe" => {
            // eth_unsubscribe is allowed for all sessions (including anonymous)
            // to enable graceful cleanup of any pre-existing subscriptions.
            if let Some(params) = json_msg.get("params").and_then(|p| p.as_array()) {
                if let Some(sub_id) = params.first().and_then(|i| i.as_str()) {
                    let removed = subscriptions.remove(sub_id).is_some();
                    let response = json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": removed
                    });
                    if sender
                        .send(Message::Text(response.to_string()))
                        .await
                        .is_err()
                    {
                        return false;
                    }
                } else {
                    send_error(sender, id, WS_ERR_INVALID_PARAMS, "Invalid params").await;
                }
            } else {
                send_error(sender, id, WS_ERR_INVALID_PARAMS, "Invalid params").await;
            }
            true
        }
        _ => {
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": WS_ERR_METHOD_NOT_FOUND,
                    "message": "Method not found"
                }
            });
            if sender
                .send(Message::Text(response.to_string()))
                .await
                .is_err()
            {
                return false;
            }
            true
        }
    }
}

async fn send_error(
    sender: &mut futures::stream::SplitSink<WebSocket, Message>,
    id: Value,
    code: i32,
    message: &str,
) {
    let response = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    });
    let _ = sender.send(Message::Text(response.to_string())).await;
}
