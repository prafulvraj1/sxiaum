//! Consensus-critical and storage engine error types.
//!
//! Provides typed errors distinguishing consensus state violations (such as
//! finalized block reversions, invalid canonical mappings, and corruption)
//! from transient system/IO failures.

use thiserror::Error;

/// Core error type for storage and consensus persistence operations.
#[derive(Error, Debug)]
pub enum StorageError {
    /// An attempt was made to revert or rollback a finalized block.
    #[error("Attempted to revert finalized block at height {height} (finalized height: {finalized_height})")]
    FinalizedBlockReversion { height: u64, finalized_height: u64 },

    /// An attempt was made to prune blocks before a height that is not yet finalized.
    #[error("Attempted to prune unfinalized blocks before height {height} (finalized height: {finalized_height:?})")]
    FinalizedBlockPruning {
        height: u64,
        finalized_height: Option<u64>,
    },

    /// A canonical chain invariant violation was detected where the height-to-hash mapping
    /// does not match the indexed block hash.
    #[error("Invalid canonical mapping at height {height}: expected block hash {expected:?}, found {actual:?}")]
    InvalidCanonicalMapping {
        height: u64,
        expected: [u8; 32],
        actual: Option<[u8; 32]>,
    },

    /// A block index entry is corrupted or inconsistent with the underlying block header/body.
    #[error("Corrupt block index for hash {hash:?} at height {height}: {reason}")]
    CorruptBlockIndex {
        hash: [u8; 32],
        height: u64,
        reason: String,
    },

    /// A multi-block or state rollback failed.
    #[error("Rollback failed from current height {current_height} to target height {target_height}: {reason}")]
    RollbackFailure {
        current_height: u64,
        target_height: u64,
        reason: String,
    },

    /// Database schema version is newer than the supported binary version.
    #[error("Database schema version {db_version} is newer than node version {node_version}. Please upgrade your node binary.")]
    SchemaVersionTooNew { db_version: u64, node_version: u64 },

    /// Proven consensus-critical storage corruption detected (e.g. data tampering or unrecoverable invariant failure).
    #[error("Storage consensus corruption detected: {reason}")]
    StorageCorruption { reason: String },

    /// Transient database transaction lock contention / busy state.
    #[error("Database transient transaction conflict: {0}")]
    TransactionConflict(String),

    /// Data serialization or deserialization failure.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Underlying redb database engine error.
    #[error("Database backend error: {0}")]
    Backend(String),

    /// File system or I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for other unexpected storage errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<bincode::Error> for StorageError {
    fn from(err: bincode::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

impl From<redb::Error> for StorageError {
    fn from(err: redb::Error) -> Self {
        StorageError::Backend(err.to_string())
    }
}

impl From<redb::TransactionError> for StorageError {
    fn from(err: redb::TransactionError) -> Self {
        StorageError::Backend(err.to_string())
    }
}

impl From<redb::TableError> for StorageError {
    fn from(err: redb::TableError) -> Self {
        StorageError::Backend(err.to_string())
    }
}

impl From<redb::StorageError> for StorageError {
    fn from(err: redb::StorageError) -> Self {
        let msg = err.to_string();
        if msg.contains("Corrupted") || msg.contains("corrupted") {
            StorageError::StorageCorruption { reason: msg }
        } else {
            StorageError::Backend(msg)
        }
    }
}

impl From<redb::CommitError> for StorageError {
    fn from(err: redb::CommitError) -> Self {
        StorageError::Backend(err.to_string())
    }
}

impl From<redb::DatabaseError> for StorageError {
    fn from(err: redb::DatabaseError) -> Self {
        let msg = err.to_string();
        if msg.contains("Corrupted") || msg.contains("corrupted") {
            StorageError::StorageCorruption { reason: msg }
        } else {
            StorageError::Backend(msg)
        }
    }
}

impl From<sxiaum_block::BlockError> for StorageError {
    fn from(err: sxiaum_block::BlockError) -> Self {
        StorageError::CorruptBlockIndex {
            hash: [0u8; 32],
            height: 0,
            reason: err.to_string(),
        }
    }
}

impl From<sxiaum_block::HeaderError> for StorageError {
    fn from(err: sxiaum_block::HeaderError) -> Self {
        StorageError::CorruptBlockIndex {
            hash: [0u8; 32],
            height: 0,
            reason: err.to_string(),
        }
    }
}

impl From<sxiaum_block::BodyError> for StorageError {
    fn from(err: sxiaum_block::BodyError) -> Self {
        StorageError::CorruptBlockIndex {
            hash: [0u8; 32],
            height: 0,
            reason: err.to_string(),
        }
    }
}

pub type StorageResult<T> = Result<T, StorageError>;
