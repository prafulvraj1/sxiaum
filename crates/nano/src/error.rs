//! Strongly-typed errors for the `sxiaum-nano` crate.

use thiserror::Error;

/// Core error type representing any failure during nano-node consensus,
/// state proof validation, or epoch synchronization.
#[derive(Debug, Error)]
pub enum NanoError {
    #[error("invalid header linkage: expected height {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },

    #[error("parent hash mismatch at height {height}: expected {expected}, got {actual}")]
    ParentHashMismatch {
        height: u64,
        expected: String,
        actual: String,
    },

    #[error("timestamp regression at height {height}: header {header_time} <= parent {parent_time}")]
    TimestampRegression {
        height: u64,
        header_time: u64,
        parent_time: u64,
    },

    #[error("future timestamp at height {height}: header time {timestamp} exceeds current time {now} by more than drift {max_drift}s")]
    FutureTimestamp {
        height: u64,
        timestamp: u64,
        now: u64,
        max_drift: u64,
    },

    #[error("invalid proposer signature at height {height}: {reason}")]
    InvalidProposerSignature { height: u64, reason: String },

    #[error("mainnet validation failed at height {height}: {reason}")]
    ValidationFailed { height: u64, reason: String },

    #[error("chain id mismatch at height {height}: expected {expected}, got {actual}")]
    ChainIdMismatch {
        height: u64,
        expected: u64,
        actual: u64,
    },

    #[error("unsupported chain id {configured}: this build is mainnet-locked to canonical chain id {canonical}")]
    UnsupportedChainId { configured: u64, canonical: u64 },

    #[error("proposer address mismatch: header claims {header_proposer}, but public key derives {derived}")]
    ProposerMismatch {
        header_proposer: String,
        derived: String,
    },

    #[error("HotStuff BFT quorum not reached at height {height}: accumulated voting power {accumulated_power} < required threshold {required_threshold} (total active stake: {total_stake})")]
    QuorumNotReached {
        height: u64,
        accumulated_power: u128,
        required_threshold: u128,
        total_stake: u128,
    },

    #[error("duplicate signature by validator {validator} in Quorum Certificate at height {height}")]
    DuplicateSignerInQc { height: u64, validator: String },

    #[error("signer {signer} is not an active validator in epoch validator set")]
    UnknownSigner { signer: String },

    #[error("invalid HotStuff vote signature by validator {validator}: {reason}")]
    InvalidVoteSignature { validator: String, reason: String },

    #[error("epoch handover verification failed for epoch {epoch}: {reason}")]
    EpochHandoverFailed { epoch: u64, reason: String },

    #[error("next validator set hash mismatch: claimed 0x{claimed}, computed 0x{computed}")]
    ValidatorSetHashMismatch { claimed: String, computed: String },

    #[error("weak subjectivity checkpoint is stale: checkpoint timestamp {checkpoint_time} is older than max allowed window {max_window_secs}s (current time: {current_time})")]
    WeakSubjectivityStale {
        checkpoint_time: u64,
        current_time: u64,
        max_window_secs: u64,
    },

    #[error("KZG state proof verification failed: {0}")]
    KzgVerificationFailed(String),

    #[error("computed post-state root 0x{computed} does not match block header state root 0x{expected}")]
    StateRootMismatch { computed: String, expected: String },

    #[error("stateless transaction execution error at index {index} (tx 0x{tx_hash}): {reason}")]
    ExecutionError {
        index: usize,
        tx_hash: String,
        reason: String,
    },

    #[error("missing preimage for account {address} in state witness")]
    MissingAccountPreimage { address: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("internal cryptographic error: {0}")]
    Crypto(String),

    #[error("gap recovery error: {0}")]
    GapRecovery(String),
}

impl From<serde_json::Error> for NanoError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
