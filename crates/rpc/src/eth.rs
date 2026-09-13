use crate::context::RpcContext;
use crate::error::RpcError;
use crate::hexutil;
use primitive_types::U256;
use serde_json::{json, Value};
use std::sync::Arc;
use sxiaum_block::{Block, BlockBody, BlockHeader};
use sxiaum_execution::compute_contract_address;
use sxiaum_types::{Address, Hash, Log, Receipt, Transaction, SXIAUM_CHAIN_ID};

pub use crate::hexutil::{
    address, hex_data as bytes, hex_hash as hash, parse_address, parse_hash, parse_quantity,
    quantity,
};

pub fn parse_block_number(
    value: Option<&Value>,
    context: &Arc<RpcContext>,
) -> Result<u64, RpcError> {
    match value {
        Some(Value::String(tag)) if tag == "latest" || tag == "pending" => context
            .storage
            .latest_block_height()
            .map_err(RpcError::DatabaseError),
        Some(Value::String(tag)) if tag == "earliest" => Ok(0),
        Some(value) => {
            let qty = parse_quantity(value)?;
            if qty > U256::from(u64::MAX) {
                return Err(RpcError::InvalidParams("block number exceeds u64".into()));
            }
            Ok(qty.as_u64())
        }
        None => context
            .storage
            .latest_block_height()
            .map_err(RpcError::DatabaseError),
    }
}

pub fn block_by_height(height: u64, context: &Arc<RpcContext>) -> Result<Block, RpcError> {
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
    Ok(Block::new(header, body))
}

pub fn block_by_hash(target: Hash, context: &Arc<RpcContext>) -> Result<Option<Block>, RpcError> {
    if let Some((header, body)) = context
        .storage
        .get_block_by_hash(target)
        .map_err(RpcError::DatabaseError)?
    {
        Ok(Some(Block::new(header, body)))
    } else {
        Ok(None)
    }
}

/// Renders a transaction in Ethereum JSON-RPC shape.
///
/// Hashing failures propagate as errors rather than silently emitting the
/// all-zero sentinel hash that previously masked broken inputs.
pub fn transaction_object(
    tx: &Transaction,
    block: Option<(&BlockHeader, Hash, usize)>,
) -> Result<Value, RpcError> {
    let (block_hash, block_number, transaction_index) = match block {
        Some((header, block_hash, index)) => (
            json!(hexutil::hex_hash(&block_hash)),
            json!(quantity(header.height)),
            json!(quantity(index as u64)),
        ),
        None => (Value::Null, Value::Null, Value::Null),
    };

    let tx_hash = tx
        .try_hash()
        .map_err(|e| RpcError::InternalError(format!("failed to hash transaction: {}", e)))?;

    let (v, r, s) = if let Some(sig) = tx.signature {
        if sig.len() < 64 {
            return Err(RpcError::InternalError(
                "transaction signature shorter than 64 bytes".into(),
            ));
        }
        let r_hex = format!("0x{}", hex::encode(&sig[0..32]));
        let s_hex = format!("0x{}", hex::encode(&sig[32..64]));
        let v_val = tx
            .ethereum_y_parity
            .map(|v| quantity(v as u64))
            .unwrap_or_else(|| "0x0".to_string());
        (v_val, r_hex, s_hex)
    } else {
        ("0x0".to_string(), "0x0".to_string(), "0x0".to_string())
    };

    Ok(json!({
        "hash": hexutil::hex_hash(&tx_hash),
        "nonce": quantity(tx.nonce),
        "blockHash": block_hash,
        "blockNumber": block_number,
        "transactionIndex": transaction_index,
        "from": address(&tx.from),
        "to": tx.to.as_ref().map(address),
        "value": quantity(tx.value),
        "gas": quantity(tx.gas_limit),
        "gasPrice": quantity(tx.gas_price),
        "input": hexutil::hex_data(&tx.data),
        "chainId": quantity(tx.chain_id.unwrap_or(SXIAUM_CHAIN_ID)),
        "type": "0x0",
        "v": v,
        "r": r,
        "s": s,
    }))
}

pub fn receipt_object(
    receipt: &Receipt,
    tx: Option<&Transaction>,
    block: Option<(&BlockHeader, Hash, usize)>,
    cumulative_gas_used: Option<u64>,
    first_log_index: usize,
) -> Value {
    let (block_hash, block_number, transaction_index) = match block {
        Some((header, block_hash, index)) => (
            json!(hexutil::hex_hash(&block_hash)),
            json!(quantity(header.height)),
            json!(quantity(index as u64)),
        ),
        None => (Value::Null, Value::Null, Value::Null),
    };
    let default_from = Address::zero();
    let from = tx.map(|tx| &tx.from).unwrap_or(&default_from);
    let to = tx.and_then(|tx| tx.to.as_ref());
    let gas_price = tx.map(|tx| tx.gas_price).unwrap_or_else(U256::one);
    let contract_address = tx
        .filter(|tx| tx.to.is_none())
        .map(|tx| address(&compute_contract_address(&tx.from, tx.nonce)));
    let logs: Vec<Value> = receipt
        .logs
        .iter()
        .enumerate()
        .map(|(index, log)| log_object(log, receipt.tx_hash, first_log_index + index, block, None))
        .collect();
    let receipt_bloom = receipt.bloom();

    json!({
        "transactionHash": hexutil::hex_hash(&receipt.tx_hash),
        "transactionIndex": transaction_index,
        "blockHash": block_hash,
        "blockNumber": block_number,
        "from": address(from),
        "to": to.map(address),
        "cumulativeGasUsed": quantity(cumulative_gas_used.unwrap_or(receipt.gas_used)),
        "gasUsed": quantity(receipt.gas_used),
        "contractAddress": contract_address,
        "logs": logs,
        "logsBloom": hexutil::hex_data(&receipt_bloom),
        "status": if receipt.status { "0x1" } else { "0x0" },
        "effectiveGasPrice": quantity(gas_price),
        "type": "0x0",
    })
}

pub fn log_object(
    log: &Log,
    tx_hash: Hash,
    log_index: usize,
    block: Option<(&BlockHeader, Hash, usize)>,
    transaction_index_override: Option<usize>,
) -> Value {
    let (block_hash, block_number, transaction_index) = match block {
        Some((header, block_hash, index)) => (
            json!(hexutil::hex_hash(&block_hash)),
            json!(quantity(header.height)),
            json!(quantity(transaction_index_override.unwrap_or(index) as u64)),
        ),
        None => (Value::Null, Value::Null, Value::Null),
    };

    json!({
        "address": address(&log.address),
        "topics": log.topics.iter().map(hexutil::hex_hash).collect::<Vec<_>>(),
        "data": hexutil::hex_data(&log.data),
        "blockNumber": block_number,
        "transactionHash": hexutil::hex_hash(&tx_hash),
        "transactionIndex": transaction_index,
        "blockHash": block_hash,
        "logIndex": quantity(log_index as u64),
        "removed": false,
    })
}

/// Renders a block in Ethereum JSON-RPC shape.
///
/// Hashing failures propagate as errors rather than silently emitting the
/// all-zero sentinel hash that previously masked broken blocks.
pub fn block_object(block: &Block, full_transactions: bool) -> Result<Value, RpcError> {
    let block_hash = block
        .try_hash()
        .map_err(|e| RpcError::InternalError(format!("failed to hash block: {}", e)))?;

    let mut transactions: Vec<Value> = Vec::with_capacity(block.body.transactions.len());
    for (index, tx) in block.body.transactions.iter().enumerate() {
        if full_transactions {
            transactions.push(transaction_object(
                tx,
                Some((&block.header, block_hash, index)),
            )?);
        } else {
            let tx_hash = tx.try_hash().map_err(|e| {
                RpcError::InternalError(format!("failed to hash transaction: {}", e))
            })?;
            transactions.push(json!(hexutil::hex_hash(&tx_hash)));
        }
    }

    // Saturating accumulation: gas values originate from consensus data and
    // must never panic on adversarial magnitudes.
    let gas_used = block
        .body
        .receipts
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.gas_used));

    let mut block_bloom = [0u8; 256];
    for receipt in &block.body.receipts {
        let r_bloom = receipt.bloom();
        for i in 0..256 {
            block_bloom[i] |= r_bloom[i];
        }
    }

    Ok(json!({
        "number": quantity(block.header.height),
        "hash": hexutil::hex_hash(&block_hash),
        "parentHash": hexutil::hex_hash(&block.header.parent_hash),
        "nonce": "0x0000000000000000",
        "sha3Uncles": format!("0x{}", "00".repeat(32)),
        "logsBloom": hexutil::hex_data(&block_bloom),
        "transactionsRoot": hexutil::hex_hash(&block.header.tx_root),
        "stateRoot": hexutil::hex_hash(&block.header.state_root),
        "receiptsRoot": hexutil::hex_hash(&block.header.receipts_root),
        "miner": address(&block.header.proposer),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": hexutil::hex_data(&block.header.extra_data),
        "size": quantity(block.size_bytes().unwrap_or(0) as u64),
        "gasLimit": quantity(block.header.gas_limit),
        "gasUsed": quantity(gas_used),
        "timestamp": quantity(block.header.timestamp),
        "transactions": transactions,
        "uncles": [],
        "baseFeePerGas": "0x0",
    }))
}

pub fn parse_call_transaction(
    value: &Value,
    context: &Arc<RpcContext>,
) -> Result<Transaction, RpcError> {
    let obj = value
        .as_object()
        .ok_or_else(|| RpcError::InvalidParams("eth_call transaction must be an object".into()))?;

    let from = obj
        .get("from")
        .map(parse_address)
        .transpose()?
        .unwrap_or_else(Address::zero);
    let to = obj.get("to").map(parse_address).transpose()?;
    // An explicit caller-supplied nonce is honored (Ethereum semantics);
    // otherwise the current account nonce from state is used.
    let nonce = match obj.get("nonce").map(parse_quantity).transpose()? {
        Some(qty) => {
            if qty > U256::from(u64::MAX) {
                return Err(RpcError::InvalidParams("nonce exceeds u64 range".into()));
            }
            qty.as_u64()
        }
        None => context
            .state
            .get_nonce(&from)
            .map_err(|e| RpcError::InternalError(format!("failed to fetch nonce: {}", e)))?,
    };
    let value_ = obj
        .get("value")
        .map(parse_quantity)
        .transpose()?
        .unwrap_or_else(U256::zero);
    let gas_limit = obj
        .get("gas")
        .map(parse_quantity)
        .transpose()?
        .unwrap_or_else(|| U256::from(sxiaum_execution::MAX_TRANSACTION_GAS_LIMIT))
        .min(U256::from(sxiaum_execution::MAX_TRANSACTION_GAS_LIMIT))
        .as_u64();
    let gas_price = obj
        .get("gasPrice")
        .map(parse_quantity)
        .transpose()?
        .filter(|p| !p.is_zero())
        .unwrap_or_else(|| U256::from(1));
    let data = obj
        .get("data")
        .or_else(|| obj.get("input"))
        .map(crate::hexutil::parse_bytes)
        .transpose()?
        .unwrap_or_default();

    Ok(Transaction {
        from,
        to,
        signer_pubkey: None,
        value: value_,
        nonce,
        gas_limit,
        gas_price,
        data,
        signature: None,
        chain_id: Some(SXIAUM_CHAIN_ID),
        ethereum_y_parity: None,
        ethereum_sighash: None,
        ethereum_tx_hash: None,
        ethereum_raw: None,
    })
}
