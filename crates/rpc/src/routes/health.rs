use crate::context::RpcContext;
use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

/// Computes the node health payload shared by the REST `/health` endpoint and
/// the `sxiaum_health` JSON-RPC method (which was previously allowlisted as a
/// public read but only existed over HTTP).
pub async fn health_payload(context: &Arc<RpcContext>) -> Value {
    let mut health_info = json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "services": {}
    });

    // 1. Check Storage Engine
    let storage_ok = context.storage.get_metrics().is_ok();
    health_info["services"]["storage"] = json!({
        "ok": storage_ok,
    });

    // 2. Check Networking (P2P Connectivity)
    let peer_count = context.networking.lock().await.peer_count();
    health_info["services"]["networking"] = json!({
        "ok": peer_count > 0,
        "peer_count": peer_count,
    });

    // 3. Check Consensus (HotStuff Status)
    let consensus_guard = context.consensus.read().await;
    let current_view = consensus_guard.current_view();
    let validator_count = consensus_guard.validator_set.active_validators().len();
    let consensus_ok = validator_count > 0;
    drop(consensus_guard);
    health_info["services"]["consensus"] = json!({
        "ok": consensus_ok,
        "current_view": current_view,
        "active_validators": validator_count,
    });

    // 4. Mempool
    let mempool_size = context.mempool.pending_count().unwrap_or(0);
    health_info["services"]["mempool"] = json!({
        "ok": true,
        "size": mempool_size,
    });

    // Final Node Status
    if !storage_ok || !consensus_ok {
        health_info["status"] = json!("degraded");
    }

    health_info
}

/// Simple health check handler for REST /health endpoint.
pub async fn health_check(State(context): State<Arc<RpcContext>>) -> Json<Value> {
    Json(health_payload(&context).await)
}
