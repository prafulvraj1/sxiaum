use crate::context::RpcContext;
use crate::error::RpcError;
use crate::eth;
use crate::hexutil;
use serde_json::{json, Value};
use std::sync::Arc;
use sxiaum_block::BlockBody;

/// JSON-RPC dispatcher for all block-related methods.
pub async fn handle_block_method(
    method: &str,
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "sxiaum_getBlockByNumber" => {
            let height = parse_height_param(params)?;
            let header = context
                .storage
                .get_block_header(height)
                .map_err(RpcError::DatabaseError)?
                .ok_or_else(|| RpcError::BlockNotFound(height))?;
            let body = context
                .storage
                .get_block_body(height)
                .map_err(RpcError::DatabaseError)?
                .unwrap_or_else(BlockBody::new);
            Ok(json!({ "header": header, "body": body }))
        }
        "eth_getBlockByNumber" => {
            let (height, full_transactions) = parse_eth_block_by_number_params(params, context)?;
            let block = eth::block_by_height(height, context)?;
            eth::block_object(&block, full_transactions)
        }
        "sxiaum_getBlockByHash" => {
            let hash = parse_hash_param(params)?;
            let (header, body) = context
                .storage
                .get_block_by_hash(hash)
                .map_err(RpcError::DatabaseError)?
                .ok_or_else(|| RpcError::InvalidParams("no block with the given hash".into()))?;
            Ok(json!({ "header": header, "body": body }))
        }
        "eth_getBlockByHash" => {
            let (hash, full_transactions) = parse_eth_block_by_hash_params(params)?;
            let Some(block) = eth::block_by_hash(hash, context)? else {
                return Ok(Value::Null);
            };
            eth::block_object(&block, full_transactions)
        }
        "sxiaum_latestBlock" => {
            let height = context
                .storage
                .latest_block_height()
                .map_err(RpcError::DatabaseError)?;
            let header = context
                .storage
                .get_block_header(height)
                .map_err(RpcError::DatabaseError)?
                .ok_or_else(|| RpcError::BlockNotFound(height))?;
            let body = context
                .storage
                .get_block_body(height)
                .map_err(RpcError::DatabaseError)?
                .unwrap_or_else(BlockBody::new);
            Ok(json!({ "header": header, "body": body }))
        }
        "sxiaum_getBlockHeader" => {
            let height = parse_height_param(params)?;
            get_block_header_internal(height, context).await
        }
        "sxiaum_getBlockTransactions" => {
            let (height, limit, offset) = parse_pagination_params(params)?;
            get_block_transactions_internal(height, limit, offset, context).await
        }
        "sxiaum_getBlockReceipts" => {
            let height = parse_height_param(params)?;
            get_block_receipts_internal(height, context).await
        }
        "eth_getBlockReceipts" => {
            let (height, _) = parse_eth_block_by_number_params(params, context)?;
            let block = eth::block_by_height(height, context)?;
            let block_hash = block
                .try_hash()
                .map_err(|e| RpcError::InternalError(format!("failed to hash block: {}", e)))?;
            let mut cumulative_gas = 0u64;
            let mut first_log_index = 0usize;
            let mut eth_receipts = Vec::new();
            for (idx, tx) in block.body.transactions.iter().enumerate() {
                let tx_hash = tx.try_hash().map_err(|e| {
                    RpcError::InternalError(format!("failed to hash transaction: {}", e))
                })?;
                let receipt = block
                    .body
                    .receipts
                    .get(idx)
                    .cloned()
                    .or_else(|| context.storage.get_receipt(tx_hash).ok().flatten());
                if let Some(r) = receipt {
                    cumulative_gas = cumulative_gas.saturating_add(r.gas_used);
                    let obj = eth::receipt_object(
                        &r,
                        Some(tx),
                        Some((&block.header, block_hash, idx)),
                        Some(cumulative_gas),
                        first_log_index,
                    );
                    first_log_index += r.logs.len();
                    eth_receipts.push(obj);
                }
            }
            Ok(json!(eth_receipts))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

async fn get_block_header_internal(
    height: u64,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let header = context
        .storage
        .get_block_header(height)
        .map_err(RpcError::DatabaseError)?
        .ok_or_else(|| RpcError::BlockNotFound(height))?;

    Ok(json!(header))
}

async fn get_block_transactions_internal(
    height: u64,
    limit: usize,
    offset: usize,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let body = load_body_checked(height, context)?;

    let txs: Vec<_> = body
        .transactions
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect();

    Ok(json!(txs))
}

async fn get_block_receipts_internal(
    height: u64,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let body = load_body_checked(height, context)?;

    let receipts = if !body.receipts.is_empty() {
        body.receipts.into_iter().map(|r| json!(r)).collect()
    } else {
        let mut list = Vec::new();
        for tx in body.transactions {
            if let Ok(tx_hash) = tx.try_hash() {
                if let Ok(Some(receipt)) = context.storage.get_receipt(tx_hash) {
                    list.push(json!(receipt));
                }
            }
        }
        list
    };

    Ok(json!(receipts))
}

fn load_body_checked(height: u64, context: &Arc<RpcContext>) -> Result<BlockBody, RpcError> {
    // Existence check keeps BlockNotFound semantics authoritative even when a
    // missing body would otherwise silently degrade to an empty one.
    context
        .storage
        .get_block_header(height)
        .map_err(RpcError::DatabaseError)?
        .ok_or_else(|| RpcError::BlockNotFound(height))?;

    context
        .storage
        .get_block_body(height)
        .map_err(RpcError::DatabaseError)
        .map(|body| body.unwrap_or_else(BlockBody::new))
}

// --- Internal Parameter Parsers ---

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

fn parse_height_param(params: Option<Value>) -> Result<u64, RpcError> {
    hexutil::parse_height_value(&first_param(params, "height")?)
}

fn parse_hash_param(params: Option<Value>) -> Result<[u8; 32], RpcError> {
    hexutil::parse_hash(&first_param(params, "hash")?)
}

fn parse_pagination_params(params: Option<Value>) -> Result<(u64, usize, usize), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    if !params.is_array() {
        return Err(RpcError::InvalidParams(
            "parameters must be an array".into(),
        ));
    }

    let height = params.get(0).map(hexutil::parse_height_value).transpose()?;
    let limit = params
        .get(1)
        .and_then(|v| v.as_u64())
        .unwrap_or(100)
        .min(crate::MAX_PAGE_LIMIT as u64) as usize;
    let offset = params.get(2).and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    match height {
        Some(height) => Ok((height, limit, offset)),
        None => Err(RpcError::InvalidParams("missing/invalid height".into())),
    }
}

fn parse_eth_block_by_number_params(
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<(u64, bool), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    let items = params
        .as_array()
        .ok_or_else(|| RpcError::InvalidParams("parameters must be an array".into()))?;
    let height = eth::parse_block_number(items.first(), context)?;
    let full_transactions = items.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
    Ok((height, full_transactions))
}

fn parse_eth_block_by_hash_params(params: Option<Value>) -> Result<([u8; 32], bool), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    let items = params
        .as_array()
        .ok_or_else(|| RpcError::InvalidParams("parameters must be an array".into()))?;
    let hash = eth::parse_hash(
        items
            .first()
            .ok_or_else(|| RpcError::InvalidParams("missing block hash".into()))?,
    )?;
    let full_transactions = items.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
    Ok((hash, full_transactions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn height_parsing_supports_decimal_and_hex_strings() {
        assert_eq!(parse_height_param(Some(json!(["42"]))).unwrap(), 42);
        assert_eq!(parse_height_param(Some(json!(["0x2a"]))).unwrap(), 42);
        assert_eq!(parse_height_param(Some(json!([7]))).unwrap(), 7);
        assert!(parse_height_param(None).is_err());
        assert!(parse_height_param(Some(json!(["-3"]))).is_err());
        assert!(parse_height_param(Some(json!([true]))).is_err());
    }

    #[test]
    fn hash_parsing_requires_exact_32_bytes() {
        let good = format!("0x{}", "11".repeat(32));
        assert!(parse_hash_param(Some(json!([good]))).is_ok());
        let short = format!("0x{}", "11".repeat(16));
        assert!(parse_hash_param(Some(json!([short]))).is_err());
    }

    #[test]
    fn pagination_clamps_limit_and_defaults() {
        let (h, l, o) = parse_pagination_params(Some(json!([1, 100000, 5]))).unwrap();
        assert_eq!((h, l, o), (1, crate::MAX_PAGE_LIMIT, 5));
        let (h, l, o) = parse_pagination_params(Some(json!([2]))).unwrap();
        assert_eq!((h, l, o), (2, 100, 0));
        assert!(parse_pagination_params(Some(json!(["abc"]))).is_err());
    }
}
