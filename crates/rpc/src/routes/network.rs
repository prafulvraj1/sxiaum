use crate::context::RpcContext;
use crate::error::RpcError;
use serde_json::{json, Value};
use std::sync::Arc;

/// JSON-RPC dispatcher for all network and node-status related methods.
pub async fn handle_network_method(
    method: &str,
    _params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "sxiaum_health" => Ok(crate::routes::health::health_payload(context).await),
        "sxiaum_peerCount" => {
            let count = get_peer_count_internal(context).await?;
            Ok(json!(format!("0x{:x}", count)))
        }
        "sxiaum_getPeers" => {
            let peers = get_peers_internal(context).await?;
            Ok(json!(peers))
        }
        "sxiaum_getNetworkInfo" => {
            let info = get_network_info_internal(context).await?;
            Ok(json!(info))
        }
        "sxiaum_syncing" => {
            let status = get_sync_status_internal(context).await?;
            Ok(json!(status))
        }
        "sxiaum_nodeVersion" => {
            let version = get_node_version_internal().await?;
            Ok(json!(version))
        }
        "sxiaum_getValidatorSet" => {
            let validators = get_validator_set_internal(context).await?;
            Ok(json!(validators))
        }
        "sxiaum_getConsensusState" => {
            let state = get_consensus_state_internal(context).await?;
            Ok(json!(state))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn get_peer_count_internal(context: &Arc<RpcContext>) -> Result<usize, RpcError> {
    Ok(context.networking.lock().await.peer_count())
}

async fn get_peers_internal(context: &Arc<RpcContext>) -> Result<Vec<Value>, RpcError> {
    let network = context.networking.lock().await;
    let peers = network.peer_store.connected_peers();
    Ok(peers
        .into_iter()
        .map(|p| {
            json!({
                "id": p.peer_id.to_string(),
                "address": p.address.to_string(),
                "last_seen": p.last_seen,
                "reputation": p.reputation,
            })
        })
        .collect())
}

async fn get_network_info_internal(context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let network = context.networking.lock().await;
    Ok(json!({
        "peer_count": network.peer_count(),
        "protocol_version": "sxiaum/1.0",
        "listen_addr": network.swarm.listeners().next().map(|a| a.to_string()),
        "local_peer_id": network.swarm.local_peer_id().to_string(),
    }))
}

async fn get_sync_status_internal(context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let latest_height = context
        .storage
        .latest_block_height()
        .map_err(|e| RpcError::InternalError(format!("failed to fetch latest height: {}", e)))?;

    let network = context.networking.lock().await;
    let peer_count = network.peer_count();

    // In a fully synced blockchain node, eth_syncing returns `false`.
    // When behind peers, it returns a sync progress object.
    if peer_count == 0 || latest_height > 0 {
        Ok(json!(false))
    } else {
        Ok(json!({
            "startingBlock": "0x0",
            "currentBlock": format!("0x{:x}", latest_height),
            "highestBlock": format!("0x{:x}", latest_height),
        }))
    }
}

async fn get_node_version_internal() -> Result<Value, RpcError> {
    Ok(json!({
        "name": "SXIAUM Node",
        "version": env!("CARGO_PKG_VERSION"),
        "client_version": crate::SERVER_VERSION,
        "protocol_version": "sxiaum/1.0",
    }))
}

async fn get_validator_set_internal(context: &Arc<RpcContext>) -> Result<Vec<Value>, RpcError> {
    let guard = context.consensus.read().await;

    let validators = guard.validator_set.active_validators();
    Ok(validators
        .into_iter()
        .map(|v| {
            json!({
                "address": v.address.to_string(),
                "voting_power": v.voting_power,
                "public_key": hex::encode(v.pubkey),
                "stake": v.stake.to_string(),
                "status": format!("{:?}", v.status),
                "commission_bps": v.commission_bps,
                "bls_pubkey": v.bls_pubkey.as_ref().map(hex::encode),
                "missed_blocks": v.missed_blocks,
                "jailed_until": v.jailed_until,
            })
        })
        .collect())
}

async fn get_consensus_state_internal(context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let guard = context.consensus.read().await;

    let current_view = guard.current_view();
    let current_leader = guard.current_leader().map(|a| a.to_string());
    let active_validators = guard.validator_set.active_validators();
    let active_validator_count = active_validators.len();
    let total_voting_power = active_validators
        .iter()
        .map(|v| v.voting_power)
        .sum::<u64>();
    let total_stake = guard.validator_set.total_stake().to_string();
    let highest_qc = guard.highest_qc().ok().flatten().map(|qc| {
        json!({
            "block_hash": hex::encode(qc.block_hash),
            "view": qc.view,
            "phase": format!("{:?}", qc.phase),
            "signer_count": qc.signatures.len(),
        })
    });

    Ok(json!({
        "current_view": current_view,
        "current_leader": current_leader,
        "active_validators": active_validator_count,
        "total_voting_power": total_voting_power,
        "total_stake": total_stake,
        "highest_qc": highest_qc,
    }))
}
