use thiserror::Error;

/// Dedicated strongly-typed error enum for mempool operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Transaction size exceeds maximum allowed: {size} bytes > {max} bytes")]
    TransactionTooLarge { size: usize, max: usize },

    #[error("Transaction missing chain_id (EIP-155 replay protection required)")]
    MissingChainId,

    #[error("Chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },

    #[error("Sender address cannot be the zero address")]
    ZeroSenderAddress,

    #[error("Transaction must be signed")]
    UnsignedTransaction,

    #[error("Contract creation transaction must contain initialization code")]
    EmptyContractCreation,

    #[error("Invalid transaction signature")]
    InvalidSignature,

    #[error("Invalid transaction nonce: expected nonce >= {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Nonce gap exceeds maximum allowed: {actual} > {max}")]
    NonceGapExceeded { actual: u64, max: u64 },

    #[error("Sender has insufficient spendable balance for value and gas")]
    InsufficientBalance,

    #[error("Transaction total cost calculation arithmetic overflow")]
    TotalCostOverflow,

    #[error("Gas limit must be greater than zero")]
    ZeroGasLimit,

    #[error("Gas limit is below intrinsic gas: {gas_limit} < {intrinsic}")]
    GasLimitBelowIntrinsic { gas_limit: u64, intrinsic: u64 },

    #[error("Gas limit exceeds configured maximum: {gas_limit} > {max}")]
    GasLimitExceedsMax { gas_limit: u64, max: u64 },

    #[error("Gas price is below the configured minimum floor")]
    GasPriceBelowMinimum,

    #[error("Duplicate transaction: hash 0x{0} is already in the mempool or recently seen")]
    DuplicateTransaction(String),

    #[error("Account pending transaction limit exceeded: {count} >= {limit}")]
    AccountTxLimitExceeded { count: usize, limit: usize },

    #[error("Mempool is full and incoming transaction priority ({gas_price}) is too low to evict incumbent ({incumbent_gas_price})")]
    PoolFullLowPriority {
        gas_price: String,
        incumbent_gas_price: String,
    },

    #[error("Replace-by-fee rejected: replacement gas price ({replacement}) must exceed incumbent ({incumbent})")]
    ReplaceByFeeRejected {
        replacement: String,
        incumbent: String,
    },

    #[error("Transaction to replace does not exist")]
    ReplacementNotFound,

    #[error("Peer rate limit exceeded ({limit} txs per {window_secs}s)")]
    PeerRateLimitExceeded { limit: usize, window_secs: u64 },

    #[error("Sender rate limit exceeded ({limit} txs per {window_secs}s)")]
    SenderRateLimitExceeded { limit: usize, window_secs: u64 },

    // --- Commit-Reveal / MEV Errors ---
    #[error("MEV protection requires a storage-backed mempool")]
    StorageRequiredForMev,

    #[error("Production validators must use a storage-backed mempool for MEV protection")]
    ProductionValidatorMevRequired,

    #[error("Global pending commit capacity exceeded (max: {0})")]
    PendingCommitCapacityExceeded(usize),

    #[error("Commit ID does not match canonical commit fields")]
    InvalidCommitId,

    #[error("Commit is missing an Ed25519 signature / pubkey binding to its sender")]
    UnsignedCommitRejected,

    #[error("Commit signature does not verify against the claimed sender")]
    InvalidCommitSignature,

    #[error("Commit sender 0x{0} has insufficient balance for the commit fee")]
    InsufficientCommitFee(String),

    #[error("Commit expiry does not match configured reveal policy")]
    InvalidCommitExpiry,

    #[error("Replay rejected: commit 0x{0} already submitted")]
    ReplayCommitRejected(String),

    #[error(
        "Commit submitted_at {submitted_at} is in the future (current height {current_height})"
    )]
    FutureCommitSubmission {
        submitted_at: u64,
        current_height: u64,
    },

    #[error("Commit submission height is stale: submitted_at {submitted_at}, current height {current_height}")]
    StaleCommitSubmission {
        submitted_at: u64,
        current_height: u64,
    },

    #[error("Duplicate commitment from a different sender: possible front-running attempt")]
    FrontRunningDetected,

    #[error("Sender 0x{sender} exceeded maximum pending commits ({limit})")]
    SenderCommitLimitExceeded { sender: String, limit: usize },

    #[error("No pending commit found for commit ID 0x{0}")]
    CommitNotFound(String),

    #[error("Reveal arrived at block {revealed_at}, but reveal deadline was {deadline}")]
    RevealTimeout { revealed_at: u64, deadline: u64 },

    #[error("Reveal payload does not match commit: expected 0x{expected}, computed 0x{computed}")]
    RevealCommitMismatch { expected: String, computed: String },

    #[error("Reveal nonce must not be all zeros")]
    ZeroRevealNonce,

    #[error(
        "Revealed transaction sender 0x{tx_sender} does not match commit sender 0x{commit_sender}"
    )]
    RevealSenderMismatch {
        tx_sender: String,
        commit_sender: String,
    },

    #[error("Block commit root 0x{block_root} does not match pool commit root 0x{pool_root}")]
    BlockCommitRootMismatch {
        block_root: String,
        pool_root: String,
    },

    #[error("Transaction hashing failed: {0}")]
    HashingFailed(String),

    #[error("State database error: {0}")]
    StateDb(String),

    #[error("Storage engine error: {0}")]
    Storage(String),
}
