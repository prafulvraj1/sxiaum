use thiserror::Error;

/// Dedicated strongly-typed error enum for P2P networking and gossip operations.
#[derive(Debug, Error)]
pub enum NetworkingError {
    #[error("Peer {0} not found")]
    PeerNotFound(String),

    #[error("Peer {0} is banned")]
    PeerBanned(String),

    #[error("Maximum peers limit ({0}) reached")]
    MaxPeersReached(usize),

    #[error("IP prefix limit exceeded for address {0} (max {1} per subnet)")]
    IpPrefixLimitExceeded(String, usize),

    #[error("RPC request timed out after {0:?}")]
    RpcTimeout(std::time::Duration),

    #[error("RPC rate limit exceeded for {endpoint}: {limit} requests per {window_secs}s")]
    RpcRateLimitExceeded {
        endpoint: String,
        limit: usize,
        window_secs: u64,
    },

    #[error("Invalid header range: {start}..={end}")]
    InvalidHeaderRange { start: u64, end: u64 },

    #[error("Requested header batch size {batch_size} exceeds max allowed {max}")]
    HeaderBatchSizeExceeded { batch_size: u64, max: u64 },

    #[error("Invalid block range: {start}..={end}")]
    InvalidBlockRange { start: u64, end: u64 },

    #[error("Requested block range size {size} exceeds batch size {max}")]
    BlockBatchSizeExceeded { size: u64, max: u64 },

    #[error("Peer returned {count} blocks, exceeding requested count {expected}")]
    BlockResponseCountMismatch { count: usize, expected: u64 },

    #[error("Peer returned error for range {start}-{end}: {message}")]
    PeerReturnedError {
        start: u64,
        end: u64,
        message: String,
    },

    #[error("Missing block at height {0}")]
    MissingBlock(u64),

    #[error("No RPC request handler registered")]
    NoRpcHandler,

    #[error("Cannot publish to unsubscribed topic: {0}")]
    UnsubscribedTopic(String),

    #[error("Duplicate gossip message: 0x{0}")]
    DuplicateMessage(String),

    #[error("Dropping invalid gossip message: {0}")]
    InvalidGossipMessage(String),

    #[error("Gossip payload cannot be empty")]
    EmptyPayload,

    #[error("Gossip message size {size} bytes exceeds maximum {max} bytes")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Transaction chain_id mismatch: expected {expected}, got {actual:?}")]
    TransactionChainIdMismatch { expected: u64, actual: Option<u64> },

    #[error("Transaction signature is missing")]
    TransactionSignatureMissing,

    #[error("Invalid transaction signature")]
    InvalidTransactionSignature,

    #[error("Block header hash mismatch: computed 0x{computed} != stored 0x{stored}")]
    BlockHeaderHashMismatch { computed: String, stored: String },

    #[error("Block chain_id mismatch: expected {expected}, got {actual}")]
    BlockChainIdMismatch { expected: u64, actual: u64 },

    #[error("Invalid block structure")]
    InvalidBlockStructure,

    #[error("Parent block 0x{0} is unavailable")]
    ParentBlockUnavailable(String),

    #[error("Parent hash mismatch at height {height}: expected 0x{expected}, got 0x{actual}")]
    ParentHashMismatch {
        height: u64,
        expected: String,
        actual: String,
    },

    #[error("Invalid block proposer signature")]
    InvalidBlockSignature,

    #[error("Block at height {0} is missing ZK validity proof")]
    MissingZkProof(u64),

    #[error("Invalid block ZK validity proof at height {0}")]
    InvalidZkProof(u64),

    #[error("Block validator root mismatch: expected 0x{expected}, got 0x{actual}")]
    ValidatorRootMismatch { expected: String, actual: String },

    #[error("Invalid block quorum certificate at height {0}")]
    InvalidQuorumCertificate(u64),

    #[error("Consensus signature verification failed for block at height {0}")]
    ConsensusSignatureVerificationFailed(u64),

    #[error("State root mismatch at height {height}: expected 0x{expected}, got 0x{actual}")]
    StateRootMismatch {
        height: u64,
        expected: String,
        actual: String,
    },

    #[error("Serialization / Deserialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(String),
}
