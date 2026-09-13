//! Database schema definitions and table initialisation for SXIAUM.
//!
//! Provides static table definitions for redb backed persistent storage,
//! including block headers, block bodies, transactions, state, accounts,
//! verkle trees, receipts, canonical chain index, and mempool persistence.

use anyhow::{Context, Result};
use redb::{Database, TableDefinition};
use std::path::Path;

// ============================================================================
// Core Ledger Tables
// ============================================================================

/// Stores block headers keyed by block height: `u64 -> bincode(BlockHeader)`.
pub const TABLE_BLOCK_HEADERS: TableDefinition<u64, &[u8]> = TableDefinition::new("block_headers");

/// Stores block bodies keyed by block height: `u64 -> bincode(BlockBody)`.
pub const TABLE_BLOCK_BODIES: TableDefinition<u64, &[u8]> = TableDefinition::new("block_bodies");

/// Maps block hash (32 bytes) to block height (`[u8; 32] -> u64`).
/// Essential for `eth_getBlockByHash`, fast chain sync, and fork resolution.
pub const TABLE_BLOCK_HASH_INDEX: TableDefinition<[u8; 32], u64> =
    TableDefinition::new("block_hash_index");

/// Maps block height to the canonical block hash (`u64 -> [u8; 32]`).
/// Allows unambiguous canonical vs fork block identification during reorganisations.
pub const TABLE_CANONICAL_CHAIN: TableDefinition<u64, [u8; 32]> =
    TableDefinition::new("canonical_chain");

/// Stores non-canonical / fork block headers and bodies keyed by block hash: `[u8; 32] -> bincode((BlockHeader, BlockBody))`.
pub const TABLE_FORK_BLOCKS: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("fork_blocks");

/// Stores finalized block hashes keyed by block height (`u64 -> [u8; 32]`).
/// Used to guard against accidental pruning or rollback of finalized consensus history.
pub const TABLE_FINALIZED_BLOCKS: TableDefinition<u64, [u8; 32]> =
    TableDefinition::new("finalized_blocks");

/// Stores block logs bloom filters keyed by block height (`u64 -> [u8; 256]`).
pub const TABLE_LOGS_BLOOM: TableDefinition<u64, &[u8]> = TableDefinition::new("logs_bloom");

// ============================================================================
// Transaction & Receipt Tables
// ============================================================================

/// Stores raw/bincode transaction payload keyed by transaction hash (`[u8; 32] -> bincode(Transaction)`).
pub const TABLE_TRANSACTIONS: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("transactions");

/// Maps transaction hash to the block height where it was included (`[u8; 32] -> u64`).
pub const TABLE_TX_BLOCK_INDEX: TableDefinition<[u8; 32], u64> =
    TableDefinition::new("tx_block_index");

/// Stores transaction execution receipts keyed by transaction hash (`[u8; 32] -> bincode(Receipt)`).
pub const TABLE_TX_RECEIPTS: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("tx_receipts");

// ============================================================================
// State, Accounts & Verkle Tables
// ============================================================================

/// Core key-value world state (`&[u8] -> &[u8]`).
pub const TABLE_STATE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state");

/// Stores account state records keyed by address (`[u8; 32] -> bincode(Account)`).
pub const TABLE_ACCOUNTS: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("accounts");

/// Stores serialized Verkle tree nodes keyed by commitment hash (`[u8; 32] -> &[u8]`).
pub const TABLE_VERKLE_NODES: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("verkle_nodes_v2");

/// Stores zero-knowledge validity proofs indexed by block height (`u64 -> &[u8]`).
pub const TABLE_ZK_PROOFS: TableDefinition<u64, &[u8]> = TableDefinition::new("zk_proofs");

// ============================================================================
// Consensus, Staking & Slashing Tables
// ============================================================================

/// Stores validator definitions keyed by validator address (`[u8; 32] -> bincode(Validator)`).
pub const TABLE_VALIDATORS: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("validators");

/// Stores validator active staking balances (`[u8; 32] -> [u8; 32]`).
pub const TABLE_STAKING: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("staking");

/// Stores historical validator snapshots by block height (`u64 -> bincode(Vec<Validator>)`).
pub const TABLE_VALIDATOR_SETS: TableDefinition<u64, &[u8]> =
    TableDefinition::new("validator_sets");

/// Stores evidence and slashing records for misbehaving validators (`[u8; 32] -> &[u8]`).
pub const TABLE_SLASHING_RECORDS: TableDefinition<[u8; 32], &[u8]> =
    TableDefinition::new("slashing_records");

// ============================================================================
// Node Metadata & Ephemeral Tables
// ============================================================================

/// Node and chain metadata (`&str -> &[u8]`).
pub const TABLE_METADATA: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata_v2");

/// Node mempool persisted pending transactions (`[u8; 32] -> bincode(Transaction)`).
pub const TABLE_MEMPOOL: TableDefinition<[u8; 32], &[u8]> = TableDefinition::new("mempool");

/// Peer bans table mapping peer ID string to expiry timestamp + reason (`&str -> &[u8]`).
pub const TABLE_PEER_BANS: TableDefinition<&str, &[u8]> = TableDefinition::new("peer_bans");

// ============================================================================
// Schema Initializer
// ============================================================================

/// Database schema initialization and bootstrapping helper.
pub struct Schema;

impl Schema {
    /// Initialize the database, validate existing metadata, and ensure all static tables exist.
    pub fn init(db_path: impl AsRef<Path>) -> Result<Database> {
        let db = Database::builder()
            .create(db_path)
            .context("Failed to create database")?;

        let tx = db
            .begin_write()
            .context("Failed to begin write transaction")?;

        // 1. Validate metadata/schema compatibility before opening the full table set.
        crate::tables::validate_schema(&tx)?;

        // 2. Create tables idempotently after the schema gate passes.
        crate::tables::create_tables(&tx)?;

        tx.commit()
            .context("Failed to commit tables initialization")?;

        Ok(db)
    }
}
