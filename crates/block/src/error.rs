use sxiaum_types::{Address, BlockHeight, Timestamp};
use thiserror::Error;

/// Top-level error type for block validation, construction, and serialization.
#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Header validation failed: {0}")]
    HeaderError(#[from] HeaderError),

    #[error("Body validation failed: {0}")]
    BodyError(#[from] BodyError),

    #[error("Merkle root mismatch: expected {expected}, computed {computed}")]
    MerkleRootMismatch { expected: String, computed: String },

    #[error("Transaction count {count} exceeds network maximum {max}")]
    TooManyTransactions { count: usize, max: usize },

    #[error("Receipt count {count} exceeds network maximum {max}")]
    TooManyReceipts { count: usize, max: usize },

    #[error("Block size {size_bytes} bytes exceeds network maximum {max_bytes} bytes")]
    BlockSizeExceeded { size_bytes: usize, max_bytes: usize },

    #[error(
        "Gas used mismatch: header specifies {header_gas}, but executed body consumed {body_gas}"
    )]
    GasUsedMismatch { header_gas: u64, body_gas: u64 },

    #[error("Parent linkage failed: expected parent hash {expected_parent}, got {actual_parent}")]
    ParentHashMismatch {
        expected_parent: String,
        actual_parent: String,
    },

    #[error("Height sequence violation: expected height {expected_height}, got {actual_height}")]
    HeightMismatch {
        expected_height: BlockHeight,
        actual_height: BlockHeight,
    },

    #[error("Timestamp sequence violation: child timestamp {child_time} <= parent timestamp {parent_time}")]
    TimestampRegression {
        child_time: Timestamp,
        parent_time: Timestamp,
    },

    #[error(
        "Genesis block (height 0) must have an empty body with zero transactions and receipts"
    )]
    GenesisNonEmptyBody,

    #[error("Proposer verification failed: expected {expected}, got {actual}")]
    ProposerMismatch { expected: Address, actual: Address },

    #[error("Proposer signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Specialized error type for block header validation and cryptography.
#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Block timestamp cannot be zero")]
    ZeroTimestamp,

    #[error("Genesis block (height 0) must have zero parent hash")]
    GenesisParentNonZero,

    #[error("Non-genesis block (height {height}) must have a non-zero parent hash")]
    NonGenesisParentZero { height: BlockHeight },

    #[error("Non-genesis block must have a non-zero proposer address")]
    NonGenesisZeroProposer,

    #[error("Genesis block must have zero proposer address")]
    GenesisNonZeroProposer,

    #[error("Unsupported block version: expected {expected}, got {actual}")]
    InvalidVersion { expected: u32, actual: u32 },

    #[error("Invalid chain ID: expected {expected}, got {actual}")]
    InvalidChainId { expected: u64, actual: u64 },

    #[error("Block gas limit {gas_limit} exceeds network maximum {max}")]
    GasLimitExceeded { gas_limit: u64, max: u64 },

    #[error("Block gas limit {gas_limit} is below minimum required {min}")]
    GasLimitTooLow { gas_limit: u64, min: u64 },

    #[error("Gas used {gas_used} exceeds block gas limit {gas_limit}")]
    GasUsedExceedsLimit { gas_used: u64, gas_limit: u64 },

    #[error("Extra data size {size} exceeds maximum {max} bytes")]
    ExtraDataTooLarge { size: usize, max: usize },

    #[error("ZK validity proof size {size} exceeds maximum {max} bytes")]
    ZkProofTooLarge { size: usize, max: usize },

    #[error("Block timestamp {timestamp} is too far in the future (local time {local_time}, allowed drift {max_drift})")]
    FutureTimestamp {
        timestamp: Timestamp,
        local_time: Timestamp,
        max_drift: u64,
    },

    #[error("Block timestamp {timestamp} is before canonical genesis timestamp {genesis_time}")]
    TimestampBeforeGenesis {
        timestamp: Timestamp,
        genesis_time: Timestamp,
    },

    #[error("Header signature is missing")]
    MissingSignature,

    #[error("Proposer public key does not match header proposer: expected {expected}, derived {derived}")]
    ProposerKeyMismatch { expected: Address, derived: Address },

    #[error("Invalid proposer public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),

    #[error("Cryptographic signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Parent linkage failed: expected parent hash {expected}, got {actual}")]
    ParentHashMismatch { expected: String, actual: String },

    #[error("Height sequence violation: expected height {expected}, got {actual}")]
    HeightMismatch {
        expected: BlockHeight,
        actual: BlockHeight,
    },

    #[error("Height integer overflow at height {height}")]
    HeightOverflow { height: BlockHeight },

    #[error("Timestamp integer overflow at timestamp {timestamp}")]
    TimestampOverflow { timestamp: Timestamp },

    #[error("Timestamp sequence violation: child timestamp {child_time} <= parent timestamp {parent_time}")]
    TimestampRegression {
        child_time: Timestamp,
        parent_time: Timestamp,
    },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Specialized error type for block body and transaction list validation.
#[derive(Error, Debug)]
pub enum BodyError {
    #[error("Duplicate transaction detected in block body: {0}")]
    DuplicateTransaction(String),

    #[error("Receipt count mismatch: {receipt_count} receipts for {tx_count} transactions")]
    ReceiptCountMismatch {
        tx_count: usize,
        receipt_count: usize,
    },

    #[error("Receipt at index {index} tx_hash mismatch: expected {expected}, got {actual}")]
    ReceiptTxHashMismatch {
        index: usize,
        expected: String,
        actual: String,
    },

    #[error(
        "Receipt at index {index} gas used {gas_used} exceeds transaction gas limit {tx_gas_limit}"
    )]
    ReceiptGasExceedsTxLimit {
        index: usize,
        gas_used: u64,
        tx_gas_limit: u64,
    },

    #[error("Total gas used {total_gas_used} exceeds block gas limit {block_gas_limit}")]
    TotalGasUsedExceedsBlockLimit {
        total_gas_used: u64,
        block_gas_limit: u64,
    },

    #[error("Total transaction gas limit {total_tx_gas_limit} exceeds block gas limit {block_gas_limit}")]
    TotalTxGasLimitExceedsBlockLimit {
        total_tx_gas_limit: u64,
        block_gas_limit: u64,
    },

    #[error("Gas accumulation overflow in block body")]
    GasOverflow,

    #[error("Transaction count {count} exceeds network maximum {max}")]
    TooManyTransactions { count: usize, max: usize },

    #[error("Receipt count {count} exceeds network maximum {max}")]
    TooManyReceipts { count: usize, max: usize },

    #[error("Transaction at index {index} failed basic validation: {error}")]
    InvalidTransaction { index: usize, error: String },

    #[error("Transaction index {index} out of bounds (total: {total})")]
    IndexOutOfBounds { index: usize, total: usize },

    #[error("Empty leaves list for Merkle operation")]
    EmptyLeaves,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
