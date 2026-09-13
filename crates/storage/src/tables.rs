//! Table bootstrapping and schema migration management for SXIAUM.
//!
//! Ensures that all required ledger, state, consensus, index, and ephemeral
//! tables exist with proper schema versioning and upgrade hooks.

use crate::schema::*;
use anyhow::{Context, Result};
use redb::{ReadableTable, WriteTransaction};
use tracing::{info, warn};

/// Current on-disk schema version for the SXIAUM node.
pub const SCHEMA_VERSION: u64 = 2;

fn ensure_metadata_table(txn: &WriteTransaction) -> Result<()> {
    txn.open_table(TABLE_METADATA)
        .context("Failed to open metadata table")?;
    Ok(())
}

/// Initialize all database tables on startup. This operation is strictly idempotent.
pub fn create_tables(txn: &WriteTransaction) -> Result<()> {
    info!("Bootstrapping blockchain database tables...");

    // 1. Metadata & Versioning (always initialized first)
    ensure_metadata_table(txn)?;

    // 2. Core ledger & block indexing tables
    txn.open_table(TABLE_BLOCK_HEADERS)
        .context("Failed to open block_headers")?;
    txn.open_table(TABLE_BLOCK_BODIES)
        .context("Failed to open block_bodies")?;
    txn.open_table(TABLE_BLOCK_HASH_INDEX)
        .context("Failed to open block_hash_index")?;
    txn.open_table(TABLE_CANONICAL_CHAIN)
        .context("Failed to open canonical_chain")?;
    txn.open_table(TABLE_FORK_BLOCKS)
        .context("Failed to open fork_blocks")?;
    txn.open_table(TABLE_FINALIZED_BLOCKS)
        .context("Failed to open finalized_blocks")?;
    txn.open_table(TABLE_LOGS_BLOOM)
        .context("Failed to open logs_bloom")?;

    // 3. Transactions & Receipts
    txn.open_table(TABLE_TRANSACTIONS)
        .context("Failed to open transactions")?;
    txn.open_table(TABLE_TX_BLOCK_INDEX)
        .context("Failed to open tx_block_index")?;
    txn.open_table(TABLE_TX_RECEIPTS)
        .context("Failed to open tx_receipts")?;

    // 4. State, Accounts & Verkle trees
    txn.open_table(TABLE_ACCOUNTS)
        .context("Failed to open accounts")?;
    txn.open_table(TABLE_STATE)
        .context("Failed to open state")?;
    txn.open_table(TABLE_VERKLE_NODES)
        .context("Failed to open verkle_nodes")?;
    txn.open_table(TABLE_ZK_PROOFS)
        .context("Failed to open zk_proofs")?;

    // 5. Consensus, Staking & Slashing
    txn.open_table(TABLE_VALIDATORS)
        .context("Failed to open validators")?;
    txn.open_table(TABLE_STAKING)
        .context("Failed to open staking")?;
    txn.open_table(TABLE_VALIDATOR_SETS)
        .context("Failed to open validator_sets")?;
    txn.open_table(TABLE_SLASHING_RECORDS)
        .context("Failed to open slashing_records")?;

    // 6. Node ephemeral & peer management tables
    txn.open_table(TABLE_MEMPOOL)
        .context("Failed to open mempool")?;
    txn.open_table(TABLE_PEER_BANS)
        .context("Failed to open peer_bans")?;

    info!("All database tables registered successfully.");
    Ok(())
}

/// Validate schema compatibility and execute automatic migration steps if necessary.
pub fn validate_schema(txn: &WriteTransaction) -> Result<()> {
    let mut table = txn
        .open_table(TABLE_METADATA)
        .context("Failed to open metadata table")?;
    let version_opt = table
        .get("schema_version")?
        .map(|version_bytes| version_bytes.value().to_vec());

    if let Some(version_bytes) = version_opt {
        let version_str = std::str::from_utf8(&version_bytes).unwrap_or_default();
        let version: u64 = version_str.parse().unwrap_or(0);

        if version < SCHEMA_VERSION {
            warn!(
                "Found legacy schema version {}. Upgrading to {}...",
                version, SCHEMA_VERSION
            );
            drop(table);
            execute_schema_migrations(txn, version, SCHEMA_VERSION)?;
        } else if version > SCHEMA_VERSION {
            return Err(crate::error::StorageError::SchemaVersionTooNew {
                db_version: version,
                node_version: SCHEMA_VERSION,
            }
            .into());
        }
    } else {
        // Brand new database initialization
        let ver = SCHEMA_VERSION.to_string();
        table.insert("schema_version", ver.as_bytes())?;
        let now = chrono::Utc::now().to_rfc3339();
        table.insert("schema_initialized_at", now.as_bytes())?;
    }

    Ok(())
}

/// Execute migration steps between schema versions.
fn execute_schema_migrations(
    txn: &WriteTransaction,
    from_version: u64,
    to_version: u64,
) -> Result<()> {
    info!(
        "Applying database schema migrations from v{} to v{}...",
        from_version, to_version
    );

    // v1 -> v2 Migration: Register block_hash_index, canonical_chain, fork_blocks, finalized_blocks, logs_bloom
    // and backfill canonical indices from any existing block_headers.
    if from_version < 2 && to_version >= 2 {
        info!("Applying migration v1 -> v2 (indexing and canonical chain tables)...");
        let mut hash_index = txn.open_table(TABLE_BLOCK_HASH_INDEX)?;
        let mut canonical = txn.open_table(TABLE_CANONICAL_CHAIN)?;
        txn.open_table(TABLE_FORK_BLOCKS)?;
        txn.open_table(TABLE_FINALIZED_BLOCKS)?;
        txn.open_table(TABLE_LOGS_BLOOM)?;

        // Backfill block_hash_index and canonical_chain from existing block_headers if present
        if let Ok(headers_table) = txn.open_table(TABLE_BLOCK_HEADERS) {
            let mut backfilled = 0usize;
            for row in headers_table.iter()? {
                let (h, header_bytes) = row?;
                let height = h.value();
                let header_res =
                    sxiaum_block::BlockHeader::decode(header_bytes.value()).or_else(|_| {
                        bincode::deserialize::<sxiaum_block::BlockHeader>(header_bytes.value())
                    });
                if let Ok(header) = header_res {
                    if let Ok(block_hash) = header.try_hash() {
                        hash_index.insert(block_hash, height)?;
                        canonical.insert(height, block_hash)?;
                        backfilled += 1;
                    }
                }
            }
            if backfilled > 0 {
                info!(
                    "Backfilled {} canonical block hash indices during v1 -> v2 migration.",
                    backfilled
                );
            }
        }

        info!("Migration v1 -> v2 applied successfully.");
    }

    // Write updated schema version and migration timestamp
    let mut meta = txn.open_table(TABLE_METADATA)?;
    let to_version_str = to_version.to_string();
    meta.insert("schema_version", to_version_str.as_bytes())?;
    let now = chrono::Utc::now().to_rfc3339();
    meta.insert("schema_migrated_at", now.as_bytes())?;

    info!("Schema migration to v{} complete.", to_version);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{create_tables, validate_schema, SCHEMA_VERSION};
    use crate::schema::{
        TABLE_BLOCK_HASH_INDEX, TABLE_BLOCK_HEADERS, TABLE_CANONICAL_CHAIN, TABLE_METADATA,
        TABLE_STATE, TABLE_TX_RECEIPTS,
    };
    use redb::Database;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-storage-tables-{name}-{unique}.redb"))
    }

    #[test]
    fn create_tables_is_idempotent_and_registers_core_tables() {
        let db_path = temp_db_path("bootstrap");
        let db = Database::create(&db_path).expect("database should create");

        let tx = db.begin_write().expect("write tx should open");
        validate_schema(&tx).expect("schema validation should initialize metadata");
        create_tables(&tx).expect("table bootstrap should succeed");
        create_tables(&tx).expect("table bootstrap should be idempotent");
        tx.commit().expect("bootstrap transaction should commit");

        let read_tx = db.begin_read().expect("read tx should open");
        read_tx
            .open_table(TABLE_METADATA)
            .expect("metadata table should exist");
        read_tx
            .open_table(TABLE_BLOCK_HEADERS)
            .expect("block headers table should exist");
        read_tx
            .open_table(TABLE_BLOCK_HASH_INDEX)
            .expect("block hash index table should exist");
        read_tx
            .open_table(TABLE_CANONICAL_CHAIN)
            .expect("canonical chain table should exist");
        read_tx
            .open_table(TABLE_STATE)
            .expect("state table should exist");
        read_tx
            .open_table(TABLE_TX_RECEIPTS)
            .expect("tx receipts table should exist");

        let version_table = read_tx
            .open_table(TABLE_METADATA)
            .expect("metadata table should open");
        let schema_version = version_table
            .get("schema_version")
            .expect("schema version lookup should succeed")
            .expect("schema version should be recorded");
        assert_eq!(
            std::str::from_utf8(schema_version.value()).expect("schema version should be utf8"),
            SCHEMA_VERSION.to_string()
        );

        drop(read_tx);
        drop(db);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn validate_schema_migrates_legacy_v1_to_current() {
        let db_path = temp_db_path("migrate-v1");
        let db = Database::create(&db_path).expect("database should create");

        let tx = db.begin_write().expect("write tx should open");
        {
            let mut meta = tx
                .open_table(TABLE_METADATA)
                .expect("metadata table should open");
            meta.insert("schema_version", b"1".as_slice())
                .expect("write v1 schema");
        }

        validate_schema(&tx).expect("migration from v1 should succeed");
        tx.commit().expect("migration should commit");

        let read_tx = db.begin_read().expect("read tx should open");
        let meta = read_tx
            .open_table(TABLE_METADATA)
            .expect("metadata should open");
        let ver = meta
            .get("schema_version")
            .expect("get version")
            .expect("version exists");
        assert_eq!(
            std::str::from_utf8(ver.value()).expect("utf8"),
            SCHEMA_VERSION.to_string()
        );

        drop(read_tx);
        drop(db);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn validate_schema_rejects_newer_database_versions() {
        let db_path = temp_db_path("future-schema");
        let db = Database::create(&db_path).expect("database should create");

        let tx = db.begin_write().expect("write tx should open");
        create_tables(&tx).expect("table bootstrap should succeed");
        {
            let mut table = tx
                .open_table(TABLE_METADATA)
                .expect("metadata table should open");
            let future_version = (SCHEMA_VERSION + 1).to_string();
            table
                .insert("schema_version", future_version.as_bytes())
                .expect("future schema version should write");
        }

        let error = validate_schema(&tx).expect_err("future schema version should be rejected");
        assert!(error.to_string().contains("newer than node version"));

        drop(tx);
        drop(db);
        let _ = std::fs::remove_file(db_path);
    }
}
