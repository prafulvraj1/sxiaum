//! Transaction mempool for the SXIAUM blockchain.
//!
//! This crate provides:
//! - Priority-ordered transaction pool with gas-price-based eviction
//! - MEV-protected commit-reveal transaction ordering
//! - Per-peer and per-sender rate limiting (spam prevention)
//! - Transaction TTL expiry and periodic cleanup
//! - Durable storage backend for crash recovery
//! - Parallel signature verification via rayon
//!
//! # Mainnet Readiness
//!
//! The mempool enforces:
//! - Chain ID validation (replay protection)
//! - Gas limit validation (per-transaction maximum)
//! - Minimum gas price floor
//! - Nonce correctness (gap-free ordering)
//! - Balance sufficiency (including vesting lockup awareness)
//! - Transaction size limits
//! - Duplicate detection (bounded LRU cache)
//! - Per-account spam guard (max pending per sender)
//! - Production validator enforcement (MEV protection required)

pub mod error;
pub mod mempool;
pub mod ordering;
pub mod pool;
pub mod validation;

pub use crate::error::MempoolError;

pub use crate::mempool::{Mempool, MempoolConfig, MempoolMetrics};
pub use crate::ordering::{
    compute_commit_hash_from_tx_hash, try_compute_commit_hash, CommitRevealConfig,
    CommitRevealPool, CommitStatusRpc, CommitTransaction, RevealStatusRpc, RevealTransaction,
};
pub use crate::pool::TransactionPool;
pub use crate::validation::{TransactionValidator, TxValidationConfig};

// ---------------------------------------------------------------------------
// Mainnet mempool constants
// ---------------------------------------------------------------------------

/// Maximum number of pending transactions in the mempool (10,000).
pub const MAX_MEMPOOL_SIZE: usize = 10_000;

/// Maximum transaction size in bytes (128 KB).
pub const MAX_TX_SIZE: usize = 128 * 1024;

/// Maximum gas limit for a single transaction (matches block crate).
pub const MAX_TRANSACTION_GAS_LIMIT: u64 = sxiaum_block::MAX_BLOCK_GAS_LIMIT;

/// Default minimum gas price (1 unit per gas).
pub const DEFAULT_MIN_GAS_PRICE: u64 = 1;

/// Default transaction TTL in seconds (1 hour).
pub const DEFAULT_TX_TTL_SECS: u64 = 3_600;

/// Default cleanup interval in seconds (30 seconds).
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 30;

/// Default maximum pending transactions per account (64).
pub const DEFAULT_MAX_TX_PER_ACCOUNT: usize = 64;
