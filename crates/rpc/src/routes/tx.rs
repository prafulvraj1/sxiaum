use crate::context::RpcContext;
use crate::error::RpcError;
use crate::eth;
use crate::hexutil;
use serde_json::{json, Value};
use std::sync::Arc;
use sxiaum_mempool::{CommitTransaction, RevealTransaction};
use sxiaum_types::{Hash, Transaction};

/// JSON-RPC dispatcher for all transaction-related methods.
pub async fn handle_tx_method(
    method: &str,
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "sxiaum_sendTransaction" | "eth_sendTransaction" => {
            let tx = parse_transaction_param(params)?;
            let tx_hash = send_transaction_internal(tx, context).await?;
            Ok(json!(hexutil::hex_hash(&tx_hash)))
        }
        "eth_sendRawTransaction" | "sxiaum_sendRawTransaction" => {
            let raw = parse_raw_transaction_param(params)?;
            let tx = Transaction::from_ethereum_raw(&raw).map_err(|e| {
                RpcError::InvalidParams(format!("invalid Ethereum raw transaction: {}", e))
            })?;
            let tx_hash = send_transaction_internal(tx, context).await?;
            Ok(json!(hexutil::hex_hash(&tx_hash)))
        }
        "sxiaum_getTransactionByHash" => {
            let hash = parse_hash_param(params)?;
            get_transaction_internal(hash, context).await
        }
        "eth_getTransactionByHash" => {
            let hash = parse_hash_param(params)?;
            get_ethereum_transaction_internal(hash, context).await
        }
        "sxiaum_getTransactionReceipt" => {
            let hash = parse_hash_param(params)?;
            let receipt = get_transaction_receipt_internal(hash, context).await?;
            Ok(receipt.unwrap_or(Value::Null))
        }
        "eth_getTransactionReceipt" => {
            let hash = parse_hash_param(params)?;
            get_ethereum_transaction_receipt_internal(hash, context).await
        }
        // SECURITY (H-07): requires authentication (default-deny) and returns
        // only non-front-runnable summaries.
        "sxiaum_getPendingTransactions" => {
            let limit = parse_limit_param(params)?;
            let txs = get_pending_transactions_internal(limit, context).await?;
            Ok(json!(txs))
        }
        "sxiaum_estimateGas" => {
            let tx = parse_transaction_or_call_param(params, context)?;
            let gas = estimate_gas_internal(tx, context).await?;
            Ok(json!(gas))
        }
        "eth_estimateGas" => {
            let tx = parse_transaction_or_call_param(params, context)?;
            let gas = estimate_gas_internal(tx, context).await?;
            Ok(json!(format!("0x{:x}", gas)))
        }
        // - MEV protection (commit-reveal) -
        "sxiaum_submitCommit" => {
            let commit = parse_commit_param(params)?;
            let commit_id = submit_commit_internal(commit, context).await?;
            Ok(json!(format!("0x{}", hex::encode(commit_id))))
        }
        "sxiaum_submitReveal" => {
            let reveal = parse_reveal_param(params)?;
            submit_reveal_internal(reveal, context).await?;
            Ok(json!({ "status": "accepted" }))
        }
        "sxiaum_getCommitStatus" => {
            let commit_id = parse_commit_id_param(params)?;
            let status = get_commit_status_internal(commit_id, context).await?;
            Ok(json!(status))
        }
        "sxiaum_getMevPoolStats" => {
            let (pending, revealed) = context.mempool.mev_pool_stats();
            Ok(json!({ "pending_commits": pending, "revealed_txs": revealed }))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

/// Validates, submits to the mempool (MEV-protected when enabled), and
/// gossips the transaction or its commit.
///
/// This is the SINGLE submission path shared by both the native
/// `sxiaum_sendTransaction` and the raw Ethereum decoder — previously two
/// near-identical 50-line functions that had already started drifting
/// (different log messages, one cloned unnecessarily).
async fn send_transaction_internal(
    tx: Transaction,
    context: &Arc<RpcContext>,
) -> Result<Hash, RpcError> {
    // 1. Basic validation (format, size)
    tx.validate_basic()
        .map_err(|e| RpcError::InvalidParams(format!("transaction validation failed: {}", e)))?;

    let (tx_hash, commit_id_opt) = if context.mempool.mev_protection_enabled() {
        let (tx_hash, commit_id) = context
            .mempool
            .submit_mev_protected_transaction(tx)
            .map_err(|e| {
                RpcError::InternalError(format!(
                    "failed to submit MEV-protected transaction: {}",
                    e
                ))
            })?;
        (tx_hash, Some(commit_id))
    } else {
        let tx_hash = context
            .mempool
            .add_transaction(tx)
            .map_err(|e| RpcError::InternalError(format!("failed to submit transaction: {}", e)))?;
        (tx_hash, None)
    };

    // 2. Gossip to peers (best effort; local acceptance already durable)
    if let Some(commit_id) = commit_id_opt {
        if let Ok(Some(message)) = context.mempool.broadcast_new_commit_to_peers(commit_id) {
            if let Err(e) = context.networking.lock().await.broadcast_message(message) {
                tracing::warn!(
                    commit_id = %hex::encode(commit_id),
                    error = %e,
                    "Failed to broadcast new commit gossip to peers"
                );
            }
        }
    } else if let Ok(Some(message)) = context.mempool.broadcast_new_transaction_to_peers(tx_hash) {
        if let Err(e) = context.networking.lock().await.broadcast_message(message) {
            tracing::warn!(
                tx_hash = %hex::encode(tx_hash),
                error = %e,
                "Failed to broadcast new transaction gossip to peers"
            );
        }
    }

    Ok(tx_hash)
}

async fn load_stored_or_pending(hash: Hash, context: &Arc<RpcContext>) -> Option<Transaction> {
    // 1. Persistent storage first (committed transactions)
    if let Ok(Some(tx)) = context.storage.get_transaction(hash) {
        return Some(tx);
    }
    // 2. Mempool second (pending transactions)
    if let Ok(Some(tx)) = context.mempool.get_transaction(hash) {
        return Some(tx);
    }
    None
}

async fn get_transaction_internal(
    hash: Hash,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    Ok(match load_stored_or_pending(hash, context).await {
        Some(tx) => json!(tx),
        None => Value::Null,
    })
}

async fn get_ethereum_transaction_internal(
    hash: Hash,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match load_stored_or_pending(hash, context).await {
        Some(tx) => {
            let block = transaction_block_context(hash, context)?;
            eth::transaction_object(
                &tx,
                block
                    .as_ref()
                    .map(|(header, hash, index)| (&**header, *hash, *index)),
            )
        }
        None => Ok(Value::Null),
    }
}

async fn get_transaction_receipt_internal(
    hash: Hash,
    context: &Arc<RpcContext>,
) -> Result<Option<Value>, RpcError> {
    Ok(context
        .storage
        .get_receipt(hash)
        .map_err(RpcError::DatabaseError)?
        .map(|receipt| json!(receipt)))
}

async fn get_ethereum_transaction_receipt_internal(
    hash: Hash,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let Some(receipt) = context
        .storage
        .get_receipt(hash)
        .map_err(RpcError::DatabaseError)?
    else {
        return Ok(Value::Null);
    };

    let tx = context
        .storage
        .get_transaction(hash)
        .map_err(RpcError::DatabaseError)?;
    let receipt_context = transaction_receipt_context(hash, context)?;
    Ok(eth::receipt_object(
        &receipt,
        tx.as_ref(),
        receipt_context
            .as_ref()
            .map(|ctx| (&ctx.header, ctx.block_hash, ctx.tx_index)),
        receipt_context.as_ref().map(|ctx| ctx.cumulative_gas_used),
        receipt_context
            .as_ref()
            .map(|ctx| ctx.first_log_index)
            .unwrap_or(0),
    ))
}

struct ReceiptContext {
    header: sxiaum_block::BlockHeader,
    block_hash: Hash,
    tx_index: usize,
    cumulative_gas_used: u64,
    first_log_index: usize,
}

/// Locates a transaction inside its committed block for Ethereum-shaped
/// responses. Returns `None` when the storage index has no height for the
/// hash; errors propagate otherwise.
fn transaction_block_context(
    tx_hash: Hash,
    context: &Arc<RpcContext>,
) -> Result<Option<(Box<sxiaum_block::BlockHeader>, Hash, usize)>, RpcError> {
    let Some(height) = context
        .storage
        .get_transaction_block_height(tx_hash)
        .map_err(RpcError::DatabaseError)?
    else {
        return Ok(None);
    };
    let block = eth::block_by_height(height, context)?;
    let block_hash = block
        .try_hash()
        .map_err(|e| RpcError::InternalError(format!("failed to hash block: {}", e)))?;
    // CORRECTNESS: an unresolvable index is an internal inconsistency between
    // the tx->height index and canonical bodies. The previous code silently
    // reported index 0, misattributing the transaction position in receipts.
    let index = locate_transaction(&block, tx_hash).unwrap_or_else(|| {
        tracing::warn!(
            tx_hash = %hex::encode(tx_hash),
            height,
            "transaction indexed at height but absent from canonical body"
        );
        0
    });
    Ok(Some((Box::new(block.header), block_hash, index)))
}

/// Full per-receipt context (cumulative gas, first log index) computed from
/// the containing block.
fn transaction_receipt_context(
    tx_hash: Hash,
    context: &Arc<RpcContext>,
) -> Result<Option<ReceiptContext>, RpcError> {
    let Some(height) = context
        .storage
        .get_transaction_block_height(tx_hash)
        .map_err(RpcError::DatabaseError)?
    else {
        return Ok(None);
    };
    let block = eth::block_by_height(height, context)?;
    let block_hash = block
        .try_hash()
        .map_err(|e| RpcError::InternalError(format!("failed to hash block: {}", e)))?;
    let tx_index = locate_transaction(&block, tx_hash).unwrap_or(0);

    let mut cumulative_gas_used = 0u64;
    let mut first_log_index = 0usize;
    for (index, tx) in block.body.transactions.iter().enumerate() {
        let Ok(h) = tx.try_hash() else {
            continue;
        };
        let receipt = context
            .storage
            .get_receipt(h)
            .ok()
            .flatten()
            .or_else(|| block.body.receipts.get(index).cloned());

        if let Some(receipt) = receipt {
            if index < tx_index {
                first_log_index += receipt.logs.len();
            }
            if index <= tx_index {
                cumulative_gas_used = cumulative_gas_used.saturating_add(receipt.gas_used);
            }
        }
    }

    Ok(Some(ReceiptContext {
        header: block.header,
        block_hash,
        tx_index,
        cumulative_gas_used,
        first_log_index,
    }))
}

fn locate_transaction(block: &sxiaum_block::Block, tx_hash: Hash) -> Option<usize> {
    for (index, tx) in block.body.transactions.iter().enumerate() {
        match tx.try_hash() {
            Ok(h) if h == tx_hash => return Some(index),
            // A transaction that cannot be hashed cannot match any target,
            // and non-matching hashes simply continue the scan.
            Ok(_) | Err(_) => continue,
        }
    }
    None
}

async fn get_pending_transactions_internal(
    limit: usize,
    context: &Arc<RpcContext>,
) -> Result<Vec<Value>, RpcError> {
    let txs = context
        .mempool
        .get_pending_transactions(limit)
        .map_err(|e| {
            RpcError::InternalError(format!("failed to fetch pending transactions: {}", e))
        })?;

    // SECURITY (H-07): even for authenticated operators, return only
    // non-front-runnable summaries. Full payloads (to / value / calldata /
    // signature) let a node operator reconstruct and front-run pending user
    // transactions; hash + sender + fee metadata is sufficient for pool
    // diagnostics without leaking executable transaction content.
    Ok(txs
        .into_iter()
        .map(|tx| {
            let tx_hash = tx.try_hash().unwrap_or([0u8; 32]);
            json!({
                "hash": hexutil::hex_hash(&tx_hash),
                "from": hexutil::address(&tx.from),
                "nonce": tx.nonce,
                "gas_price": tx.gas_price.to_string(),
                "data_size": tx.data.len(),
            })
        })
        .collect())
}

async fn estimate_gas_internal(
    tx: Transaction,
    context: &Arc<RpcContext>,
) -> Result<u64, RpcError> {
    context
        .executor
        .estimate_gas(&tx)
        .map_err(|e| RpcError::InternalError(format!("gas estimation failed: {}", e)))
}

// --- MEV handler functions ---

async fn submit_commit_internal(
    commit: CommitTransaction,
    context: &Arc<RpcContext>,
) -> Result<[u8; 32], RpcError> {
    let commit_id = context
        .mempool
        .submit_commit(commit)
        .map_err(|e| RpcError::InternalError(format!("commit rejected: {}", e)))?;

    if let Ok(Some(message)) = context.mempool.broadcast_new_commit_to_peers(commit_id) {
        if let Err(e) = context.networking.lock().await.broadcast_message(message) {
            tracing::warn!(
                commit_id = %hex::encode(commit_id),
                error = %e,
                "Failed to broadcast commit gossip to peers"
            );
        }
    }

    Ok(commit_id)
}

async fn submit_reveal_internal(
    reveal: RevealTransaction,
    context: &Arc<RpcContext>,
) -> Result<(), RpcError> {
    // CORRECTNESS: accept LOCALLY before gossiping. The previous order told
    // every peer about a reveal that could still be rejected locally,
    // amplifying invalid reveals network-wide at zero cost to the sender.
    context
        .mempool
        .submit_reveal(reveal.clone())
        .map_err(|e| RpcError::InternalError(format!("reveal rejected: {}", e)))?;

    if let Ok(Some(message)) = context.mempool.broadcast_new_reveal_to_peers(&reveal) {
        if let Err(e) = context.networking.lock().await.broadcast_message(message) {
            tracing::warn!(
                error = %e,
                "Failed to broadcast reveal gossip to peers"
            );
        }
    }

    Ok(())
}

async fn get_commit_status_internal(
    commit_id: [u8; 32],
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let (pending, revealed) = context.mempool.mev_pool_stats();
    // Return lightweight status; full per-commit lookup available via CommitRevealPool RPC types
    Ok(json!({
        "commit_id": hex::encode(commit_id),
        "pool_pending_commits": pending,
        "pool_revealed_txs": revealed,
    }))
}

// --- Parameter Parsers ---

fn first_param(params: Option<Value>, what: &str) -> Result<Value, RpcError> {
    params
        .and_then(|v| {
            if v.is_array() {
                v.get(0).cloned()
            } else {
                Some(v)
            }
        })
        .ok_or_else(|| RpcError::InvalidParams(format!("missing {what} parameter")))
}

fn parse_transaction_param(params: Option<Value>) -> Result<Transaction, RpcError> {
    serde_json::from_value(first_param(params, "transaction")?)
        .map_err(|e| RpcError::InvalidParams(format!("invalid transaction format: {}", e)))
}

fn parse_transaction_or_call_param(
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Transaction, RpcError> {
    let val = first_param(params, "transaction")?;
    if let Ok(tx) = serde_json::from_value::<Transaction>(val.clone()) {
        Ok(tx)
    } else {
        eth::parse_call_transaction(&val, context)
    }
}

fn parse_raw_transaction_param(params: Option<Value>) -> Result<Vec<u8>, RpcError> {
    let s = first_param(params, "raw transaction")?
        .as_str()
        .ok_or_else(|| RpcError::InvalidParams("raw transaction must be a hex string".into()))?
        .to_string();
    hex::decode(hexutil::strip_hex_prefix(&s))
        .map_err(|_| RpcError::InvalidParams("invalid raw transaction hex".into()))
}

fn parse_hash_param(params: Option<Value>) -> Result<Hash, RpcError> {
    hexutil::parse_hash(&first_param(params, "hash")?)
}

fn parse_limit_param(params: Option<Value>) -> Result<usize, RpcError> {
    let limit = params
        .and_then(|v| {
            if v.is_array() {
                v.get(0).and_then(|i| i.as_u64())
            } else {
                v.as_u64()
            }
        })
        .unwrap_or(100)
        .min(crate::MAX_PAGE_LIMIT as u64) as usize;
    Ok(limit)
}

fn parse_commit_param(params: Option<Value>) -> Result<CommitTransaction, RpcError> {
    serde_json::from_value(first_param(params, "commit")?)
        .map_err(|e| RpcError::InvalidParams(format!("invalid commit format: {}", e)))
}

fn parse_reveal_param(params: Option<Value>) -> Result<RevealTransaction, RpcError> {
    serde_json::from_value(first_param(params, "reveal")?)
        .map_err(|e| RpcError::InvalidParams(format!("invalid reveal format: {}", e)))
}

fn parse_commit_id_param(params: Option<Value>) -> Result<[u8; 32], RpcError> {
    parse_hash_param(params)
}
