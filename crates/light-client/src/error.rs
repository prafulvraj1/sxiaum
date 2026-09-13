use sxiaum_types::{Address, BlockHeight};
use thiserror::Error;

/// Dedicated error type for light client operations and cryptographic verifications.
#[derive(Error, Debug)]
pub enum LightClientError {
    #[error("Header linkage verification failed: {0}")]
    HeaderLinkage(String),

    #[error("Candidate header failed basic or mainnet validation: {0}")]
    HeaderValidation(String),

    #[error("Height sequence violation: expected {expected}, got {actual}")]
    HeightMismatch {
        expected: BlockHeight,
        actual: BlockHeight,
    },

    #[error("Parent hash mismatch at height {height}: expected 0x{expected}, got 0x{actual}")]
    ParentHashMismatch {
        height: BlockHeight,
        expected: String,
        actual: String,
    },

    #[error("Timestamp sequence violation at height {height}: header {header_time} <= parent {parent_time}")]
    TimestampRegression {
        height: BlockHeight,
        header_time: u64,
        parent_time: u64,
    },

    #[error("Timestamp drift violation at height {height}: header timestamp {timestamp} exceeds maximum allowed future drift (current {now}, max drift {max_drift}s)")]
    FutureTimestamp {
        height: BlockHeight,
        timestamp: u64,
        now: u64,
        max_drift: u64,
    },

    #[error("Proposer signature verification failed at height {height}: {reason}")]
    InvalidProposerSignature { height: BlockHeight, reason: String },

    #[error("Proposer public key is an invalid all-zero placeholder")]
    ZeroProposerPublicKey,

    #[error(
        "Proposer address mismatch: header specifies {header_proposer}, derived {derived_proposer}"
    )]
    ProposerAddressMismatch {
        header_proposer: Address,
        derived_proposer: Address,
    },

    #[error("BFT consensus quorum failure: verified weight {weight} < required threshold {required} (total active power: {total})")]
    ConsensusQuorumFailed {
        weight: u128,
        required: u128,
        total: u128,
    },

    #[error("BFT signature from validator {validator} is cryptographically invalid for header 0x{header_hash}")]
    InvalidConsensusSignature {
        validator: Address,
        header_hash: String,
    },

    #[error("No consensus signatures provided for header verification at height {height}")]
    MissingConsensusSignatures { height: BlockHeight },

    #[error("Duplicate consensus signature detected from validator {0}")]
    DuplicateConsensusSignature(Address),

    #[error("Consensus signature from unknown, inactive, or zero-power validator: {0}")]
    UnknownOrInactiveValidator(Address),

    #[error("Validator set verification failed: {0}")]
    InvalidValidatorSet(String),

    #[error("Validator root mismatch at height {height}: header has 0x{header_root}, validator set produces 0x{computed_root}")]
    ValidatorRootMismatch {
        height: BlockHeight,
        header_root: String,
        computed_root: String,
    },

    #[error("Unauthorized validator set transition: new set root 0x{new_root} does not match latest verified header validator_root 0x{header_root} at height {height}")]
    ValidatorSetTransitionRejected {
        height: BlockHeight,
        new_root: String,
        header_root: String,
    },

    #[error("ZK validity proof verification failed for header at height {height}: {reason}")]
    ZkVerificationFailed { height: BlockHeight, reason: String },

    #[error("Missing ZK validity proof for header at height {0}")]
    MissingZkProof(BlockHeight),

    #[error("Empty ZK validity proof for header at height {0}")]
    EmptyZkProof(BlockHeight),

    #[error("ZK proof size {size} exceeds network maximum {max}")]
    ZkProofTooLarge { size: usize, max: usize },

    #[error("SP1 verification key is empty or an invalid placeholder")]
    InvalidZkVerificationKey,

    #[error("Chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },

    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Header batch size {size} exceeds maximum allowed {max}")]
    BatchSizeExceeded { size: usize, max: usize },

    #[error("State proof verification failed: {0}")]
    StateProofFailed(String),

    #[error("Stateless execution verification failed: {0}")]
    StatelessExecutionFailed(String),

    #[error("Network RPC error from peer {peer}: {reason}")]
    NetworkRpcError { peer: String, reason: String },

    #[error("Empty header response received from peer {peer} for range [{start}, {end}]")]
    EmptyHeaderResponse {
        peer: String,
        start: BlockHeight,
        end: BlockHeight,
    },

    #[error("Light client uninitialized: no verified header in state")]
    NoVerifiedHeader,

    #[error("Serialization / Deserialization error: {0}")]
    Serialization(String),

    #[error(transparent)]
    BlockError(#[from] sxiaum_block::BlockError),

    #[error(transparent)]
    HeaderError(#[from] sxiaum_block::HeaderError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
