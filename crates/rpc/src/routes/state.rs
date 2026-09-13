use crate::context::RpcContext;
use crate::error::RpcError;
use crate::eth;
use crate::hexutil;
use primitive_types::U256;
use serde_json::{json, Value};
use std::sync::Arc;
use sxiaum_execution::EvmRuntime;
use sxiaum_types::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofKind {
    Account,
    Storage,
    Minimal,
}

#[derive(Clone, Debug)]
struct ProofRequest {
    kind: ProofKind,
    address: Option<Address>,
    key: Option<[u8; 32]>,
    minimal: bool,
}

/// JSON-RPC dispatcher for all state-related methods.
pub async fn handle_state_method(
    method: &str,
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    match method {
        "sxiaum_getBalance" => {
            let addr = parse_address_param(params)?;
            let balance = get_balance_internal(addr, context).await?;
            Ok(json!(balance.to_string())) // Decimal string: avoids U256 precision issues in JSON
        }
        "eth_getBalance" => {
            let addr = parse_address_param(params)?;
            let balance = get_balance_internal(addr, context).await?;
            Ok(json!(hexutil::quantity(balance)))
        }
        "sxiaum_getAccount" => {
            let addr = parse_address_param(params)?;
            get_account_internal(addr, context).await
        }
        "sxiaum_getNonce" => {
            let addr = parse_address_param(params)?;
            let nonce = get_nonce_internal(addr, context).await?;
            Ok(json!(nonce))
        }
        "eth_getTransactionCount" => {
            let addr = parse_address_param(params)?;
            let nonce = get_nonce_internal(addr, context).await?;
            Ok(json!(format!("0x{:x}", nonce)))
        }
        "sxiaum_getStorageAt" | "eth_getStorageAt" => {
            let (addr, key) = parse_address_and_key_params(params)?;
            let storage = get_storage_internal(addr, key, context).await?;
            Ok(json!(storage))
        }
        "sxiaum_getStateRoot" => {
            let root = get_state_root_internal(context).await?;
            Ok(json!(hexutil::hex_hash(&root)))
        }
        "sxiaum_getProof" => {
            let request = parse_proof_params(params, ProofKind::Account)?;
            get_proof_internal(request, context).await
        }
        "sxiaum_getStorageProof" => {
            let request = parse_proof_params(params, ProofKind::Storage)?;
            get_proof_internal(request, context).await
        }
        "sxiaum_getMinimalProof" => {
            let request = parse_proof_params(params, ProofKind::Minimal)?;
            get_proof_internal(request, context).await
        }
        "sxiaum_getCode" | "eth_getCode" => {
            let addr = parse_address_param(params)?;
            let code = get_contract_code_internal(addr, context).await?;
            Ok(json!(code))
        }
        "eth_call" => {
            let tx = parse_eth_call_params(params, context)?;
            let entropy = *context.executor.block_entropy.lock();
            let evm = EvmRuntime::new(context.executor.evm_config.clone(), entropy);
            let result = evm
                .call_contract_read_only(&context.state, &tx)
                .map_err(|e| RpcError::InternalError(format!("eth_call failed: {}", e)))?;
            if result.success {
                Ok(json!(hexutil::hex_data(&result.return_data)))
            } else {
                Err(RpcError::InternalError(format!(
                    "eth_call reverted: {}",
                    hexutil::hex_data(&result.return_data)
                )))
            }
        }
        "eth_getLogs" => {
            let filter = parse_log_filter_params(params, context)?;
            let logs = get_logs_internal(filter, context).await?;
            Ok(json!(logs))
        }
        // Minimal but spec-shaped fee history: the chain's pricing model is a
        // constant minimum gas price, so every block reports the same base
        // fee. Previously this method was publicly allowlisted yet answered
        // `Method not found`, confusing standard tooling.
        "eth_feeHistory" => {
            let (block_count, newest) = parse_fee_history_params(params, context)?;
            let latest_height = context
                .storage
                .latest_block_height()
                .map_err(RpcError::DatabaseError)?;
            let newest = newest.min(latest_height);
            // oldest = newest - count + 1, clamped at genesis.
            let start = newest.saturating_sub(block_count.saturating_sub(1));
            let count = (newest - start + 1) as usize;
            let base_fees: Vec<String> = (0..count).map(|_| "0x1".to_string()).collect();
            let gas_used_ratios: Vec<f64> = (0..count).map(|_| 0.0).collect();
            Ok(json!({
                "oldestBlock": format!("0x{:x}", start),
                "baseFeePerGas": base_fees,
                "gasUsedRatio": gas_used_ratios,
            }))
        }
        _ => Err(RpcError::MethodNotFound(method.to_string())),
    }
}

#[derive(Clone, Debug)]
struct LogFilter {
    from_block: u64,
    to_block: u64,
    addresses: Option<Vec<Address>>,
    topics: Vec<Option<Vec<[u8; 32]>>>,
}

async fn get_balance_internal(addr: Address, context: &Arc<RpcContext>) -> Result<U256, RpcError> {
    context
        .state
        .get_balance(&addr)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch balance: {}", e)))
}

async fn get_account_internal(addr: Address, context: &Arc<RpcContext>) -> Result<Value, RpcError> {
    let account = context
        .state
        .get_account(&addr)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch account: {}", e)))?;
    Ok(account.map(|a| json!(a)).unwrap_or(Value::Null))
}

async fn get_nonce_internal(addr: Address, context: &Arc<RpcContext>) -> Result<u64, RpcError> {
    context
        .state
        .get_nonce(&addr)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch nonce: {}", e)))
}

async fn get_storage_internal(
    addr: Address,
    key: [u8; 32],
    context: &Arc<RpcContext>,
) -> Result<String, RpcError> {
    let value = context
        .state
        .get_storage(&addr, key)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch storage: {}", e)))?;

    // Normalize output to an exact 32-byte word (Ethereum shape): stored
    // values shorter than a word are left-padded with zeros; absent slots
    // report the zero word.
    const WORD_HEX_LEN: usize = 64;
    match value {
        Some(bytes) if bytes.len() >= 32 => Ok(format!("0x{}", hex::encode(&bytes[..32]))),
        Some(bytes) => {
            let mut hex_str = hex::encode(bytes);
            while hex_str.len() < WORD_HEX_LEN {
                hex_str.insert(0, '0');
            }
            Ok(format!("0x{}", hex_str))
        }
        None => Ok(format!("0x{}", "00".repeat(32))),
    }
}

async fn get_state_root_internal(context: &Arc<RpcContext>) -> Result<[u8; 32], RpcError> {
    Ok(context.state.state_root())
}

async fn get_proof_internal(
    request: ProofRequest,
    context: &Arc<RpcContext>,
) -> Result<Value, RpcError> {
    let state = context.state.as_ref();
    let proof = match request.kind {
        ProofKind::Account => {
            let addr = request.address.ok_or_else(|| {
                RpcError::InvalidParams("missing address for account proof".into())
            })?;
            if request.minimal {
                state.export_minimal_proof_for_rpc(*addr.as_bytes())
            } else {
                state.export_account_proof_for_rpc(&addr)
            }
        }
        ProofKind::Storage => {
            let addr = request.address.ok_or_else(|| {
                RpcError::InvalidParams("missing address for storage proof".into())
            })?;
            let key = request.key.ok_or_else(|| {
                RpcError::InvalidParams("missing storage key for storage proof".into())
            })?;
            if request.minimal {
                state.export_minimal_proof_for_rpc(sxiaum_state::storage_proof_key(&addr, &key))
            } else {
                state.export_storage_proof_for_rpc(&addr, key)
            }
        }
        ProofKind::Minimal => {
            let key = request
                .key
                .ok_or_else(|| RpcError::InvalidParams("missing key for minimal proof".into()))?;
            state.export_minimal_proof_for_rpc(key)
        }
    }
    .map_err(|e| RpcError::InternalError(format!("failed to generate proof: {}", e)))?;

    Ok(json!(proof))
}

async fn get_contract_code_internal(
    addr: Address,
    context: &Arc<RpcContext>,
) -> Result<String, RpcError> {
    let account = context
        .state
        .get_account(&addr)
        .map_err(|e| RpcError::InternalError(format!("failed to fetch account for code: {}", e)))?;

    if let Some(account) = account {
        if account.is_contract() {
            let code_key = [b"contract:code:".as_ref(), account.code_hash.as_slice()].concat();
            let code = context
                .state
                .get_raw(&code_key)
                .map_err(|e| RpcError::InternalError(format!("failed to fetch code: {}", e)))?
                .unwrap_or_default();
            return Ok(hexutil::hex_data(&code));
        }
    }

    Ok("0x".to_string())
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

fn parse_address_param(params: Option<Value>) -> Result<Address, RpcError> {
    hexutil::parse_address(&first_param(params, "address")?)
}

fn parse_eth_call_params(
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<sxiaum_types::Transaction, RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing eth_call params".into()))?;
    let call = if let Some(items) = params.as_array() {
        items
            .first()
            .ok_or_else(|| RpcError::InvalidParams("missing eth_call transaction".into()))?
    } else {
        &params
    };
    eth::parse_call_transaction(call, context)
}

fn parse_fee_history_params(
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<(u64, u64), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    let items = params
        .as_array()
        .ok_or_else(|| RpcError::InvalidParams("parameters must be an array".into()))?;

    let block_count = match items.first() {
        Some(v) => {
            let qty = eth::parse_quantity(v)?;
            if qty > U256::from(u64::MAX) {
                return Err(RpcError::InvalidParams("blockCount exceeds u64".into()));
            }
            qty.as_u64()
        }
        None => return Err(RpcError::InvalidParams("missing blockCount".into())),
    };
    if block_count == 0 || block_count > crate::MAX_PAGE_LIMIT as u64 {
        return Err(RpcError::InvalidParams(format!(
            "blockCount must be between 1 and {}",
            crate::MAX_PAGE_LIMIT
        )));
    }

    let newest = match items.get(1) {
        Some(Value::String(tag)) if tag == "latest" || tag == "pending" => context
            .storage
            .latest_block_height()
            .map_err(RpcError::DatabaseError)?,
        Some(v) => {
            let qty = eth::parse_quantity(v)?;
            if qty > U256::from(u64::MAX) {
                return Err(RpcError::InvalidParams("newestBlock exceeds u64".into()));
            }
            qty.as_u64()
        }
        None => context
            .storage
            .latest_block_height()
            .map_err(RpcError::DatabaseError)?,
    };

    Ok((block_count, newest))
}

fn parse_log_filter_params(
    params: Option<Value>,
    context: &Arc<RpcContext>,
) -> Result<LogFilter, RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing log filter".into()))?;
    let filter = if let Some(items) = params.as_array() {
        items.first().unwrap_or(&Value::Null)
    } else {
        &params
    };
    let obj = filter
        .as_object()
        .ok_or_else(|| RpcError::InvalidParams("log filter must be an object".into()))?;
    let from_block = eth::parse_block_number(obj.get("fromBlock"), context)?;
    let to_block = eth::parse_block_number(obj.get("toBlock"), context)?;
    if to_block >= from_block && (to_block - from_block) > crate::MAX_LOGS_BLOCK_RANGE {
        return Err(RpcError::InvalidParams(format!(
            "query exceeds maximum block range of {} blocks (requested {} blocks)",
            crate::MAX_LOGS_BLOCK_RANGE,
            to_block - from_block + 1
        )));
    }
    let addresses = match obj.get("address") {
        Some(Value::String(_)) => Some(vec![hexutil::parse_address(&obj["address"])?]),
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .map(hexutil::parse_address)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(Value::Null) | None => None,
        Some(_) => {
            return Err(RpcError::InvalidParams(
                "log address must be a string or array".into(),
            ))
        }
    };
    let topics = match obj.get("topics") {
        Some(Value::Array(items)) => items
            .iter()
            .map(parse_topic_filter)
            .collect::<Result<Vec<_>, _>>()?,
        Some(Value::Null) | None => Vec::new(),
        Some(_) => return Err(RpcError::InvalidParams("topics must be an array".into())),
    };

    Ok(LogFilter {
        from_block,
        to_block,
        addresses,
        topics,
    })
}

fn parse_topic_filter(value: &Value) -> Result<Option<Vec<[u8; 32]>>, RpcError> {
    match value {
        Value::Null => Ok(None),
        Value::String(_) => Ok(Some(vec![hexutil::parse_hash(value)?])),
        Value::Array(items) => Ok(Some(
            items
                .iter()
                .map(hexutil::parse_hash)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(RpcError::InvalidParams(
            "topic filters must be null, string, or array".into(),
        )),
    }
}

async fn get_logs_internal(
    filter: LogFilter,
    context: &Arc<RpcContext>,
) -> Result<Vec<Value>, RpcError> {
    if filter.from_block > filter.to_block {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for height in filter.from_block..=filter.to_block {
        let block = match eth::block_by_height(height, context) {
            Ok(block) => block,
            Err(RpcError::BlockNotFound(_)) => continue,
            Err(error) => return Err(error),
        };
        let block_hash = block
            .try_hash()
            .map_err(|e| RpcError::InternalError(e.to_string()))?;
        let mut block_log_index = 0usize;

        for (tx_index, tx) in block.body.transactions.iter().enumerate() {
            let receipt = tx
                .try_hash()
                .ok()
                .and_then(|h| context.storage.get_receipt(h).ok().flatten())
                .or_else(|| block.body.receipts.get(tx_index).cloned());

            if let Some(receipt) = receipt {
                for log in receipt.logs {
                    if log_matches(&log, &filter) {
                        if out.len() >= crate::MAX_LOGS_LIMIT {
                            return Err(RpcError::InvalidParams(format!(
                                "query exceeded maximum log limit of {}",
                                crate::MAX_LOGS_LIMIT
                            )));
                        }
                        out.push(eth::log_object(
                            &log,
                            receipt.tx_hash,
                            block_log_index,
                            Some((&block.header, block_hash, tx_index)),
                            None,
                        ));
                    }
                    block_log_index += 1;
                }
            }
        }
    }

    Ok(out)
}

fn log_matches(log: &sxiaum_types::Log, filter: &LogFilter) -> bool {
    if let Some(addresses) = &filter.addresses {
        if !addresses.iter().any(|addr| addr == &log.address) {
            return false;
        }
    }

    for (index, topic_filter) in filter.topics.iter().enumerate() {
        let Some(allowed) = topic_filter else {
            continue;
        };
        let Some(topic) = log.topics.get(index) else {
            return false;
        };
        if !allowed.iter().any(|candidate| candidate == topic) {
            return false;
        }
    }

    true
}

fn parse_address_and_key_params(params: Option<Value>) -> Result<(Address, [u8; 32]), RpcError> {
    let params = params.ok_or_else(|| RpcError::InvalidParams("missing parameters".into()))?;
    if !params.is_array() {
        return Err(RpcError::InvalidParams(
            "parameters must be an array".into(),
        ));
    }

    let addr_value = params
        .get(0)
        .ok_or_else(|| RpcError::InvalidParams("missing/invalid address".into()))?;
    let key_value = params
        .get(1)
        .ok_or_else(|| RpcError::InvalidParams("missing/invalid storage key".into()))?;

    let addr = hexutil::parse_address(addr_value)?;
    let key = hexutil::parse_word256(key_value)?;

    Ok((addr, key))
}

fn parse_proof_params(
    params: Option<Value>,
    default_kind: ProofKind,
) -> Result<ProofRequest, RpcError> {
    match params {
        None => Err(RpcError::InvalidParams("missing proof parameters".into())),
        Some(Value::String(address)) => Ok(ProofRequest {
            kind: default_kind,
            address: Some(hexutil::parse_address_str(&address)?),
            key: None,
            minimal: matches!(default_kind, ProofKind::Minimal),
        }),
        Some(Value::Array(items)) => parse_proof_params_from_array(items, default_kind),
        Some(Value::Object(map)) => {
            let kind = match map.get("type").and_then(|v| v.as_str()) {
                Some("account") => ProofKind::Account,
                Some("storage") => ProofKind::Storage,
                Some("minimal") => ProofKind::Minimal,
                Some(other) => {
                    return Err(RpcError::InvalidParams(format!(
                        "unsupported proof type: {}",
                        other
                    )))
                }
                None => default_kind,
            };

            let address = map.get("address").map(hexutil::parse_address).transpose()?;
            let key = map.get("key").map(hexutil::parse_word256).transpose()?;
            let minimal = map
                .get("minimal")
                .and_then(|v| v.as_bool())
                .unwrap_or(matches!(kind, ProofKind::Minimal));

            Ok(ProofRequest {
                kind,
                address,
                key,
                minimal,
            })
        }
        Some(_) => Err(RpcError::InvalidParams(
            "unsupported proof parameter format".into(),
        )),
    }
}

fn parse_proof_params_from_array(
    items: Vec<Value>,
    default_kind: ProofKind,
) -> Result<ProofRequest, RpcError> {
    match default_kind {
        ProofKind::Account => {
            let address = items
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid address".into()))?;
            let minimal = items.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(ProofRequest {
                kind: ProofKind::Account,
                address: Some(hexutil::parse_address_str(address)?),
                key: None,
                minimal,
            })
        }
        ProofKind::Storage => {
            let address = items
                .first()
                .and_then(|v| v.as_str())
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid address".into()))?;
            let key = items
                .get(1)
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid storage key".into()))?;
            let minimal = items.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(ProofRequest {
                kind: ProofKind::Storage,
                address: Some(hexutil::parse_address_str(address)?),
                key: Some(hexutil::parse_word256(key)?),
                minimal,
            })
        }
        ProofKind::Minimal => {
            let key = items
                .first()
                .ok_or_else(|| RpcError::InvalidParams("missing/invalid proof key".into()))?;
            Ok(ProofRequest {
                kind: ProofKind::Minimal,
                address: None,
                key: Some(hexutil::parse_word256(key)?),
                minimal: true,
            })
        }
    }
}
