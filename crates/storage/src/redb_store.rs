//! High-performance, crash-resilient `redb`-backed persistent storage engine.
//!
//! Provides transactional ACID storage for all core blockchain components:
//! - Block headers, bodies, canonical chain mapping, and hash index
//! - Transactions, transaction receipts, and block inclusion indices
//! - State table with LRU caching, parallel batch reads, prefix/range scans, and rollbacks
//! - Verkle tree node persistence and zero-knowledge validity proofs
//! - Validator sets, staking balances, and slashing records
//! - Mempool transaction durability with priority-based eviction
//! - Peer ban management and node operational metadata
//! - Online background compaction, atomic snapshot export/restore, and deep integrity checks

use crate::backend::{DatabaseBackend, StateUpdates};
use crate::error::StorageError;
use crate::schema::*;
use crate::util::{
    decode_canonical, encode_peer_ban, parse_peer_ban, select_lowest_priority_evictions,
    verify_canonical_sequence, CanonicalRow,
};
use anyhow::{bail, Context, Result};
use lru::LruCache;
use metrics::counter;
use parking_lot::Mutex;
use primitive_types::U256;
use redb::{Database, ReadTransaction, ReadableTable, TableDefinition, WriteTransaction};
use std::collections::HashSet;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use sxiaum_block::{BlockBody, BlockHeader};
use sxiaum_types::{Account, Canonical, Receipt, Transaction, Validator};
use tracing::{error, info, warn};

/// Current on-disk database engine version.
pub const DB_VERSION: &str = "2.0.0";

// Standard metadata keys
const LATEST_BLOCK_HEIGHT_KEY: &str = "latest_block_height";
const FINALIZED_BLOCK_HEIGHT_KEY: &str = "finalized_block_height";
const SAFE_BLOCK_HEIGHT_KEY: &str = "safe_block_height";
const LAST_SHUTDOWN_CLEAN_KEY: &str = "last_shutdown_clean";
const LAST_OPENED_AT_KEY: &str = "last_opened_at";
const LAST_RECOVERY_AT_KEY: &str = "last_recovery_at";
const LAST_CORRUPTION_ERROR_KEY: &str = "last_corruption_error";
const LAST_COMPACTION_AT_KEY: &str = "last_compaction_at";
const LAST_COMPACTION_PATH_KEY: &str = "last_compaction_path";

const DEFAULT_FLUSH_INTERVAL_SECS: u64 = 5;
/// Default LRU cache capacity for hot state reads.
const DEFAULT_CACHE_CAPACITY: usize = 10_000;
/// Maximum number of buffered state writes before forcing a flush.
const MAX_BUFFERED_WRITES: usize = 100_000;

#[derive(Default)]
struct StorageMetricsInner {
    batch_write_total: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    disk_flush_total: AtomicU64,
    parallel_reads_total: AtomicU64,
    buffered_write_flushes: AtomicU64,
    buffered_writes_enqueued: AtomicU64,
}

/// The core StorageEngine orchestrating redb-backed persistent storage.
pub struct StorageEngine {
    db: Arc<Database>,
    db_path: PathBuf,
    /// Read cache for hot state values. Shared with the background flush
    /// scheduler so buffered-write flushes can invalidate stale entries.
    cache: Arc<Mutex<LruCache<Vec<u8>, Vec<u8>>>>,
    buffered_state_writes: Arc<Mutex<StateUpdates>>,
    /// SECURITY: serializes all buffered-write flushes. Without single-flight
    /// flushing, two concurrent flushers could clone overlapping buffers and
    /// commit them out of production order, letting a stale write overwrite a
    /// newer committed value (lost-update hazard for parallel execution).
    flush_lock: Arc<Mutex<()>>,
    metrics: Arc<StorageMetricsInner>,
    flush_thread_stop: Mutex<Option<mpsc::Sender<()>>>,
    flush_thread_handle: Mutex<Option<JoinHandle<()>>>,
    compaction_handle: Mutex<Option<JoinHandle<()>>>,
    shutdown_recorded: AtomicBool,
    compaction_running: Arc<AtomicBool>,
}

impl std::fmt::Debug for StorageEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageEngine")
            .field("db_path", &self.db_path)
            .field(
                "shutdown_recorded",
                &self.shutdown_recorded.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl StorageEngine {
    /// Initialize the StorageEngine with durable file locking, mmap-backed storage, and schema bootstrap.
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        let db = Self::open_or_create_db_with_retry(&db_path)?;

        let engine = Self {
            db: Arc::new(db),
            db_path,
            cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(DEFAULT_CACHE_CAPACITY)
                    .unwrap_or_else(|| NonZeroUsize::new(1000).expect("non-zero")),
            ))),
            buffered_state_writes: Arc::new(Mutex::new(Vec::new())),
            flush_lock: Arc::new(Mutex::new(())),
            metrics: Arc::new(StorageMetricsInner::default()),
            flush_thread_stop: Mutex::new(None),
            flush_thread_handle: Mutex::new(None),
            compaction_handle: Mutex::new(None),
            shutdown_recorded: AtomicBool::new(false),
            compaction_running: Arc::new(AtomicBool::new(false)),
        };

        // Initialize metadata, schema tables, and background flush scheduler
        engine.init_metadata()?;
        engine.init_schema_tables()?;
        engine.start_flush_scheduler()?;

        Ok(engine)
    }

    fn open_or_create_db_with_retry(path: &Path) -> Result<Database> {
        const MAX_RETRIES: u32 = 10;
        const RETRY_DELAY_MS: u64 = 100;
        let mut last_err = None;
        for attempt in 0..MAX_RETRIES {
            match Self::open_or_create_db(path) {
                Ok(db) => return Ok(db),
                Err(e) => {
                    let err_msg = format!("{:?}", e);
                    if (err_msg.contains("DatabaseAlreadyOpen")
                        || err_msg.contains("Database already open"))
                        && attempt < MAX_RETRIES - 1
                    {
                        std::thread::sleep(Duration::from_millis(
                            RETRY_DELAY_MS * (attempt + 1) as u64,
                        ));
                        continue;
                    }
                    last_err = Some(e);
                    break;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("Failed to open database after {} retries", MAX_RETRIES)
        }))
    }

    fn init_schema_tables(&self) -> Result<()> {
        let tx = self.begin_write()?;
        crate::tables::validate_schema(&tx)?;
        crate::tables::create_tables(&tx)?;
        tx.commit()
            .context("Failed to commit schema table initialization")?;
        Ok(())
    }

    /// Open or create the database with page cache and recovery marker handling.
    fn open_or_create_db(path: &Path) -> Result<Database> {
        info!("Opening database at {:?}", path);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create database directory {:?}", parent))?;
        }

        // Configure builder with 512MB page cache
        let mut builder = Database::builder();
        builder.set_cache_size(512 * 1024 * 1024);

        let db = match builder.create(path) {
            Ok(db) => db,
            Err(e) => {
                let err_msg = format!("{:?}", e);
                let is_corrupted = err_msg.contains("Corrupted")
                    || err_msg.contains("corrupted")
                    || err_msg.contains("InvalidMagic")
                    || err_msg.contains("InvalidMagicHeader")
                    || err_msg.contains("InvalidData");
                if is_corrupted {
                    error!(
                        "Database corruption detected at {:?}: {}. Recording corruption marker...",
                        path, err_msg
                    );
                    let marker_path = path.with_extension("corrupt");
                    let _ = fs::write(&marker_path, err_msg.as_bytes());
                    return Err(StorageError::StorageCorruption { reason: err_msg }.into());
                } else {
                    error!("Failed to open database at {:?}: {:?}", path, e);
                    return Err(StorageError::Backend(err_msg).into());
                }
            }
        };

        Ok(db)
    }

    /// Initialize database versioning and metadata.
    fn init_metadata(&self) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx
                .open_table(TABLE_METADATA)
                .context("Failed to open metadata table")?;

            let was_clean_shutdown = table
                .get(LAST_SHUTDOWN_CLEAN_KEY)?
                .map(|value| value.value() == b"true")
                .unwrap_or(true);

            // Canonical chain ID: 13689 (sxiaum_types::SXIAUM_CHAIN_ID)
            if table.get("chain_id")?.is_none() {
                table.insert("chain_id", sxiaum_types::SXIAUM_CHAIN_ID_STR.as_bytes())?;
            }

            if table.get("version")?.is_none() {
                table.insert("version", DB_VERSION.as_bytes())?;
            }

            let now_str = chrono::Utc::now().to_rfc3339();
            if table.get("created_at")?.is_none() {
                table.insert("created_at", now_str.as_bytes())?;
            }

            table.insert(LAST_OPENED_AT_KEY, now_str.as_bytes())?;
            table.insert(LAST_SHUTDOWN_CLEAN_KEY, b"false".as_slice())?;

            if !was_clean_shutdown {
                warn!(
                    "Detected unclean database shutdown at {:?}. redb crash recovery will be relied on and recovery metadata has been recorded.",
                    self.db_path
                );
                table.insert(LAST_RECOVERY_AT_KEY, now_str.as_bytes())?;
            }

            let corruption_marker = self.db_path.with_extension("corrupt");
            if corruption_marker.exists() {
                if let Ok(error_message) = fs::read_to_string(&corruption_marker) {
                    table.insert(LAST_CORRUPTION_ERROR_KEY, error_message.as_bytes())?;
                }
                let _ = fs::remove_file(corruption_marker);
            }
        }
        tx.commit()
            .context("Failed to commit metadata initialization")?;
        Ok(())
    }

    pub fn db(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Begin a read-only snapshot transaction.
    pub fn begin_read(&self) -> Result<ReadTransaction> {
        self.db
            .begin_read()
            .context("Failed to begin read transaction")
    }

    /// Begin a read/write transaction.
    pub fn begin_write(&self) -> Result<WriteTransaction> {
        self.db
            .begin_write()
            .context("Failed to begin write transaction")
    }

    /// Crash-safe commit wrapper for generic write operations.
    pub fn execute_write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&WriteTransaction) -> Result<()>,
    {
        let tx = self.begin_write()?;
        f(&tx)?;
        tx.commit().context("Transactional commit failed")
    }

    pub fn buffer_block_execution_write(&self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<()> {
        let mut buffered = self.buffered_state_writes.lock();
        if buffered.len() >= MAX_BUFFERED_WRITES {
            drop(buffered);
            self.flush_buffered_block_execution_writes()?;
            buffered = self.buffered_state_writes.lock();
        }
        buffered.push((key, value));
        self.metrics
            .buffered_writes_enqueued
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn flush_buffered_block_execution_writes(&self) -> Result<usize> {
        // Single-flight: serialize with the background scheduler and any
        // concurrent foreground flush so batches commit in take order.
        let _flush_guard = self.flush_lock.lock();
        Self::flush_buffered_state_writes_inner(
            &self.db,
            &self.buffered_state_writes,
            &self.metrics,
            &self.cache,
        )
    }

    /// Retrieve a value from a specific table within a read transaction.
    pub fn get(&self, table: TableDefinition<&[u8], &[u8]>, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(table)?;
        let value = table.get(key)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    // ========================================================================
    // Block Storage & Canonical Indexing
    // ========================================================================

    /// Store a full block (header + body) ensuring full cryptographic and Merkle validation.
    pub fn store_block(&self, block: &sxiaum_block::Block) -> Result<[u8; 32]> {
        let block_hash = block.try_hash()?;
        self.store_canonical_block(block.height(), block_hash, &block.header, &block.body)?;
        Ok(block_hash)
    }

    /// Retrieve full block by block height.
    pub fn get_full_block(&self, height: u64) -> Result<Option<sxiaum_block::Block>> {
        self.get_block_by_height(height)?
            .map(|(header, body)| Ok(sxiaum_block::Block::new(header, body)))
            .transpose()
    }

    /// Retrieve full block by block hash.
    pub fn get_full_block_by_hash(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<sxiaum_block::Block>> {
        self.get_block_by_hash(block_hash)?
            .map(|(header, body)| Ok(sxiaum_block::Block::new(header, body)))
            .transpose()
    }

    pub fn store_block_header(&self, height: u64, header: &BlockHeader) -> Result<()> {
        let header_bytes = header
            .try_encode()
            .context("Failed to encode block header")?;
        self.store_block_header_bytes(height, &header_bytes)
    }

    pub fn get_block_header(&self, height: u64) -> Result<Option<BlockHeader>> {
        self.get_block_header_bytes(height)?
            .map(|header_bytes| decode_canonical::<BlockHeader>(&header_bytes))
            .transpose()
    }

    pub fn store_block_header_bytes(&self, height: u64, header_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_BLOCK_HEADERS)?;
            table.insert(height, header_bytes)?;
            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Failed to commit block header")?;
        Ok(())
    }

    pub fn get_block_header_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_BLOCK_HEADERS)?;
        let value = table.get(height)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    pub fn store_block_body(&self, height: u64, body: &BlockBody) -> Result<()> {
        let body_bytes = body.try_encode().context("Failed to encode block body")?;
        self.store_block_body_bytes(height, &body_bytes)
    }

    pub fn get_block_body(&self, height: u64) -> Result<Option<BlockBody>> {
        self.get_block_body_bytes(height)?
            .map(|body_bytes| decode_canonical::<BlockBody>(&body_bytes))
            .transpose()
    }

    pub fn store_block_body_bytes(&self, height: u64, body_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_BLOCK_BODIES)?;
            table.insert(height, body_bytes)?;
            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Failed to commit block body")?;
        Ok(())
    }

    pub fn get_block_body_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_BLOCK_BODIES)?;
        let value = table.get(height)?;
        Ok(value.map(|v| v.value().to_vec()))
    }

    /// Atomically store a canonical block (header, body, block hash index, canonical chain mapping, and transaction index).
    pub fn store_canonical_block(
        &self,
        height: u64,
        block_hash: [u8; 32],
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<()> {
        if header.height != height {
            bail!(
                "Header height {} does not match storage height {}",
                header.height,
                height
            );
        }
        let computed_hash = header.try_hash()?;
        if block_hash != computed_hash {
            bail!(
                "Block hash {:?} does not match computed header hash {:?}",
                block_hash,
                computed_hash
            );
        }
        let tx_root = body.compute_tx_root()?;
        if header.tx_root != tx_root {
            bail!(
                "Header tx_root {:?} does not match body computed tx_root {:?}",
                header.tx_root,
                tx_root
            );
        }
        let receipt_root = body.compute_receipt_root()?;
        if header.receipts_root != receipt_root {
            bail!(
                "Header receipts_root {:?} does not match body computed receipts_root {:?}",
                header.receipts_root,
                receipt_root
            );
        }
        let gas_used = body.total_gas_used_checked()?;
        if header.gas_used != gas_used {
            bail!(
                "Header gas_used {} does not match body total gas used {}",
                header.gas_used,
                gas_used
            );
        }

        let header_bytes = header.try_encode()?;
        let body_bytes = body.try_encode()?;

        let tx = self.begin_write()?;
        {
            let mut header_table = tx.open_table(TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(TABLE_BLOCK_BODIES)?;
            let mut hash_index = tx.open_table(TABLE_BLOCK_HASH_INDEX)?;
            let mut canonical = tx.open_table(TABLE_CANONICAL_CHAIN)?;
            let mut tx_table = tx.open_table(TABLE_TRANSACTIONS)?;
            let mut tx_index = tx.open_table(TABLE_TX_BLOCK_INDEX)?;
            let mut receipts_table = tx.open_table(TABLE_TX_RECEIPTS)?;

            header_table.insert(height, header_bytes.as_slice())?;
            body_table.insert(height, body_bytes.as_slice())?;
            hash_index.insert(block_hash, height)?;
            canonical.insert(height, block_hash)?;

            for tx_item in &body.transactions {
                let tx_h = tx_item.try_hash()?;
                let tx_b = tx_item.try_encode()?;
                tx_table.insert(tx_h, tx_b.as_slice())?;
                tx_index.insert(tx_h, height)?;
            }

            for receipt in &body.receipts {
                let receipt_b = receipt.try_encode()?;
                receipts_table.insert(receipt.tx_hash, receipt_b.as_slice())?;
            }

            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Failed to commit canonical block")?;
        Ok(())
    }

    /// Retrieve full block (header + body) by block hash.
    /// Verifies canonical mapping before returning canonical block; falls back to fork blocks.
    pub fn get_block_by_hash(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<(BlockHeader, BlockBody)>> {
        let height_opt = self.get_block_height_by_hash(block_hash)?;
        if let Some(h) = height_opt {
            if self.is_canonical_block(h, block_hash)? {
                return self.get_block_by_height(h);
            }
        }
        // Fallback to fork blocks
        self.get_fork_block(block_hash)
    }

    /// Retrieve full block (header + body) by block height.
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<(BlockHeader, BlockBody)>> {
        let header = self.get_block_header(height)?;
        let body = self.get_block_body(height)?;
        match (header, body) {
            (Some(h), Some(b)) => Ok(Some((h, b))),
            _ => Ok(None),
        }
    }

    /// Lookup block hash by canonical height.
    pub fn get_block_hash_by_height(&self, height: u64) -> Result<Option<[u8; 32]>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_CANONICAL_CHAIN)?;
        Ok(table.get(height)?.map(|v| v.value()))
    }

    /// Lookup block height by block hash.
    pub fn get_block_height_by_hash(&self, block_hash: [u8; 32]) -> Result<Option<u64>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_BLOCK_HASH_INDEX)?;
        Ok(table.get(block_hash)?.map(|v| v.value()))
    }

    /// Check if a block hash is canonical at a given height.
    pub fn is_canonical_block(&self, height: u64, block_hash: [u8; 32]) -> Result<bool> {
        let canonical_hash = self.get_block_hash_by_height(height)?;
        Ok(canonical_hash == Some(block_hash))
    }

    /// Store a fork/uncle block without updating the canonical chain tip.
    pub fn store_fork_block(
        &self,
        block_hash: [u8; 32],
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<()> {
        let header_bytes = header.try_encode()?;
        let body_bytes = body.try_encode()?;
        let bytes = bincode::serialize(&(header_bytes, body_bytes))?;
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_FORK_BLOCKS)?;
            table.insert(block_hash, bytes.as_slice())?;
        }
        tx.commit().context("Failed to store fork block")?;
        Ok(())
    }

    /// Store a fork/uncle block from a typed Block structure.
    pub fn store_fork_block_typed(&self, block: &sxiaum_block::Block) -> Result<[u8; 32]> {
        let block_hash = block.try_hash()?;
        self.store_fork_block(block_hash, &block.header, &block.body)?;
        Ok(block_hash)
    }

    /// Retrieve a fork/uncle block by hash.
    pub fn get_fork_block(&self, block_hash: [u8; 32]) -> Result<Option<(BlockHeader, BlockBody)>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_FORK_BLOCKS)?;
        let value = table.get(block_hash)?;
        value
            .map(|v| {
                if let Ok((hb, bb)) = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(v.value()) {
                    let header = decode_canonical::<BlockHeader>(&hb)?;
                    let body = decode_canonical::<BlockBody>(&bb)?;
                    Ok((header, body))
                } else {
                    bincode::deserialize(v.value()).map_err(Into::into)
                }
            })
            .transpose()
    }

    /// Retrieve a fork/uncle block as a typed Block.
    pub fn get_fork_block_typed(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<sxiaum_block::Block>> {
        self.get_fork_block(block_hash)?
            .map(|(header, body)| Ok(sxiaum_block::Block::new(header, body)))
            .transpose()
    }

    /// Atomically commit a block (header and body) and update the latest height.
    pub fn atomic_block_commit(
        &self,
        height: u64,
        header_bytes: Vec<u8>,
        body_bytes: Vec<u8>,
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut header_table = tx.open_table(TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(TABLE_BLOCK_BODIES)?;

            header_table.insert(height, header_bytes.as_slice())?;
            body_table.insert(height, body_bytes.as_slice())?;
            Self::update_latest_height_metadata(&tx, height)?;
        }
        tx.commit().context("Atomic block commit failed")?;
        Ok(())
    }

    pub fn atomic_block_commit_typed(
        &self,
        height: u64,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<()> {
        let header_bytes = header
            .try_encode()
            .context("Failed to encode block header")?;
        let body_bytes = body.try_encode().context("Failed to encode block body")?;
        self.atomic_block_commit(height, header_bytes, body_bytes)
    }

    /// Get the latest processed block height.
    pub fn latest_block_height(&self) -> Result<u64> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_METADATA)?;
        Ok(Self::read_latest_height_metadata(&table)?.unwrap_or(0))
    }

    /// Check if a block exists at a specific height.
    pub fn block_exists(&self, height: u64) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_BLOCK_HEADERS)?;
        Ok(table.get(height)?.is_some())
    }

    // ========================================================================
    // Chain Reorganisation & Block Rollback (Finality Protected & Fully Atomic)
    // ========================================================================

    /// Atomically revert a single block at `height`, cleaning up headers, bodies,
    /// hash indices, canonical chain mappings, logs bloom, zk proofs, and transaction block indices.
    /// Strictly refuses to revert blocks at or below `finalized_height`.
    pub fn revert_block(&self, height: u64) -> Result<()> {
        if let Some(finalized) = self.get_finalized_height()? {
            if height <= finalized {
                return Err(StorageError::FinalizedBlockReversion {
                    height,
                    finalized_height: finalized,
                }
                .into());
            }
        }

        let tx = self.begin_write()?;
        {
            let mut header_table = tx.open_table(TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(TABLE_BLOCK_BODIES)?;
            let mut hash_index = tx.open_table(TABLE_BLOCK_HASH_INDEX)?;
            let mut canonical = tx.open_table(TABLE_CANONICAL_CHAIN)?;
            let mut tx_index = tx.open_table(TABLE_TX_BLOCK_INDEX)?;
            let mut bloom_table = tx.open_table(TABLE_LOGS_BLOOM)?;
            let mut zk_table = tx.open_table(TABLE_ZK_PROOFS)?;
            let mut val_set_table = tx.open_table(TABLE_VALIDATOR_SETS)?;

            header_table.remove(height)?;
            let body_opt = body_table.remove(height)?;
            bloom_table.remove(height)?;
            zk_table.remove(height)?;
            val_set_table.remove(height)?;

            if let Some(canonical_hash) = canonical.remove(height)? {
                hash_index.remove(canonical_hash.value())?;
            }

            if let Some(body_bytes) = body_opt {
                if let Ok(body) = decode_canonical::<BlockBody>(body_bytes.value()) {
                    let mut receipts_table = tx.open_table(TABLE_TX_RECEIPTS)?;
                    for tx_item in body.transactions {
                        if let Ok(hash) = tx_item.try_hash() {
                            tx_index.remove(hash)?;
                        }
                    }
                    for receipt in body.receipts {
                        receipts_table.remove(receipt.tx_hash)?;
                    }
                }
            }

            let new_height = if height > 0 { Some(height - 1) } else { None };
            Self::reconcile_latest_height_metadata(&tx, new_height)?;
        }
        tx.commit().context("Failed to revert block")?;
        Ok(())
    }

    /// Atomically revert all blocks back to `target_height` in a SINGLE write transaction.
    /// Strictly refuses to revert past `finalized_height`.
    pub fn revert_blocks_to(&self, target_height: u64) -> Result<usize> {
        let current_height = self.latest_block_height()?;
        if target_height >= current_height {
            return Ok(0);
        }

        if let Some(finalized) = self.get_finalized_height()? {
            if target_height < finalized {
                return Err(StorageError::FinalizedBlockReversion {
                    height: target_height + 1,
                    finalized_height: finalized,
                }
                .into());
            }
        }

        let tx = self.begin_write()?;
        let mut count = 0;
        {
            let mut header_table = tx.open_table(TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(TABLE_BLOCK_BODIES)?;
            let mut hash_index = tx.open_table(TABLE_BLOCK_HASH_INDEX)?;
            let mut canonical = tx.open_table(TABLE_CANONICAL_CHAIN)?;
            let mut tx_index = tx.open_table(TABLE_TX_BLOCK_INDEX)?;
            let mut receipts_table = tx.open_table(TABLE_TX_RECEIPTS)?;
            let mut bloom_table = tx.open_table(TABLE_LOGS_BLOOM)?;
            let mut zk_table = tx.open_table(TABLE_ZK_PROOFS)?;
            let mut val_set_table = tx.open_table(TABLE_VALIDATOR_SETS)?;

            for h in (target_height + 1..=current_height).rev() {
                header_table.remove(h)?;
                let body_opt = body_table.remove(h)?;
                bloom_table.remove(h)?;
                zk_table.remove(h)?;
                val_set_table.remove(h)?;

                if let Some(canonical_hash) = canonical.remove(h)? {
                    hash_index.remove(canonical_hash.value())?;
                }

                if let Some(body_bytes) = body_opt {
                    if let Ok(body) = decode_canonical::<BlockBody>(body_bytes.value()) {
                        for tx_item in body.transactions {
                            if let Ok(hash) = tx_item.try_hash() {
                                tx_index.remove(hash)?;
                            }
                        }
                        for receipt in body.receipts {
                            receipts_table.remove(receipt.tx_hash)?;
                        }
                    }
                }
                count += 1;
            }

            let new_latest = if target_height > 0 || header_table.get(0)?.is_some() {
                Some(target_height)
            } else {
                None
            };
            Self::reconcile_latest_height_metadata(&tx, new_latest)?;
        }
        tx.commit()
            .context("Failed to atomically commit multi-block rollback")?;

        info!(
            "Successfully atomically reverted {} blocks to height {}",
            count, target_height
        );
        Ok(count)
    }

    // ========================================================================
    // Finality & Pruning Protection
    // ========================================================================

    pub fn set_finalized_height(&self, height: u64, block_hash: [u8; 32]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut finalized_table = tx.open_table(TABLE_FINALIZED_BLOCKS)?;
            finalized_table.insert(height, block_hash)?;
            let mut meta = tx.open_table(TABLE_METADATA)?;
            let bytes = height.to_le_bytes();
            meta.insert(FINALIZED_BLOCK_HEIGHT_KEY, bytes.as_slice())?;
        }
        tx.commit().context("Failed to set finalized height")?;
        Ok(())
    }

    pub fn get_finalized_height(&self) -> Result<Option<u64>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_METADATA)?;
        let val = table.get(FINALIZED_BLOCK_HEIGHT_KEY)?;
        Ok(val.and_then(|v| {
            if v.value().len() == 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(v.value());
                Some(u64::from_le_bytes(b))
            } else {
                None
            }
        }))
    }

    pub fn set_safe_height(&self, height: u64) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut meta = tx.open_table(TABLE_METADATA)?;
            let bytes = height.to_le_bytes();
            meta.insert(SAFE_BLOCK_HEIGHT_KEY, bytes.as_slice())?;
        }
        tx.commit().context("Failed to set safe height")?;
        Ok(())
    }

    pub fn get_safe_height(&self) -> Result<Option<u64>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_METADATA)?;
        let val = table.get(SAFE_BLOCK_HEIGHT_KEY)?;
        Ok(val.and_then(|v| {
            if v.value().len() == 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(v.value());
                Some(u64::from_le_bytes(b))
            } else {
                None
            }
        }))
    }

    /// Prune block headers and bodies before a certain height.
    /// Strictly protects against pruning unfinalized history: the finalized
    /// block itself is never removable, so `height` may be at most the
    /// finalized height.
    pub fn prune_blocks_before(&self, height: u64) -> Result<usize> {
        let finalized_opt = self.get_finalized_height()?;
        // FIX (SEC): reject any prune target above the finalized height so the
        // finalized block itself can never be deleted. Previously
        // `height == finalized + 1` was accepted, which pruned the finalized
        // block along with its ancestors.
        if let Some(finalized) = finalized_opt {
            if height > finalized {
                return Err(StorageError::FinalizedBlockPruning {
                    height,
                    finalized_height: finalized_opt,
                }
                .into());
            }
        } else if height > 1 {
            return Err(StorageError::FinalizedBlockPruning {
                height,
                finalized_height: None,
            }
            .into());
        }

        let previous_latest = self.latest_block_height()?;
        let tx = self.begin_write()?;
        let mut pruned_heights = std::collections::BTreeSet::new();
        {
            let mut header_table = tx.open_table(TABLE_BLOCK_HEADERS)?;
            let mut body_table = tx.open_table(TABLE_BLOCK_BODIES)?;
            let mut canonical_table = tx.open_table(TABLE_CANONICAL_CHAIN)?;
            let mut hash_index = tx.open_table(TABLE_BLOCK_HASH_INDEX)?;
            let mut bloom_table = tx.open_table(TABLE_LOGS_BLOOM)?;
            let mut zk_table = tx.open_table(TABLE_ZK_PROOFS)?;
            let mut val_set_table = tx.open_table(TABLE_VALIDATOR_SETS)?;

            // FIX: gather heights from every per-height table so orphaned
            // auxiliary rows (e.g. a zk proof stored without its block header)
            // are swept as well, not just rows keyed by existing headers.
            for entry in header_table.iter()? {
                let (stored_height, _) = entry?;
                if stored_height.value() < height {
                    pruned_heights.insert(stored_height.value());
                }
            }
            for entry in bloom_table.iter()? {
                let (stored_height, _) = entry?;
                if stored_height.value() < height {
                    pruned_heights.insert(stored_height.value());
                }
            }
            for entry in zk_table.iter()? {
                let (stored_height, _) = entry?;
                if stored_height.value() < height {
                    pruned_heights.insert(stored_height.value());
                }
            }
            for entry in val_set_table.iter()? {
                let (stored_height, _) = entry?;
                if stored_height.value() < height {
                    pruned_heights.insert(stored_height.value());
                }
            }

            for pruned_height in &pruned_heights {
                header_table.remove(*pruned_height)?;
                body_table.remove(*pruned_height)?;
                bloom_table.remove(*pruned_height)?;
                zk_table.remove(*pruned_height)?;
                val_set_table.remove(*pruned_height)?;
                if let Some(hash) = canonical_table.remove(*pruned_height)? {
                    let _ = hash_index.remove(hash.value());
                }
            }
        }
        let latest_after_prune = if previous_latest >= height {
            Some(previous_latest)
        } else {
            None
        };
        Self::reconcile_latest_height_metadata(&tx, latest_after_prune)?;
        tx.commit().context("Block pruning failed")?;
        Ok(pruned_heights.len())
    }

    // ========================================================================
    // Transaction & Receipt Storage
    // ========================================================================

    pub fn store_transaction(&self, tx_hash: [u8; 32], tx: &Transaction) -> Result<()> {
        let expected_hash = tx.try_hash()?;
        if tx_hash != expected_hash {
            bail!(
                "Transaction hash mismatch: provided {:?}, computed {:?}",
                tx_hash,
                expected_hash
            );
        }
        let tx_bytes = tx.try_encode().context("Failed to serialize transaction")?;
        self.store_transaction_bytes(tx_hash, &tx_bytes)
    }

    pub fn store_transaction_auto(&self, tx: &Transaction) -> Result<[u8; 32]> {
        let tx_hash = tx.try_hash()?;
        self.store_transaction(tx_hash, tx)?;
        Ok(tx_hash)
    }

    pub fn get_transaction(&self, tx_hash: [u8; 32]) -> Result<Option<Transaction>> {
        self.get_transaction_bytes(tx_hash)?
            .map(|tx_bytes| decode_canonical::<Transaction>(&tx_bytes))
            .transpose()
    }

    pub fn store_transaction_bytes(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_TRANSACTIONS)?;
            table.insert(tx_hash, tx_bytes)?;
        }
        tx.commit().context("Failed to commit transaction")?;
        Ok(())
    }

    pub fn get_transaction_bytes(&self, tx_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_TRANSACTIONS)?;
        Ok(table.get(tx_hash)?.map(|v| v.value().to_vec()))
    }

    pub fn transaction_exists(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_TRANSACTIONS)?;
        Ok(table.get(tx_hash)?.is_some())
    }

    pub fn store_receipt(&self, tx_hash: [u8; 32], receipt: &Receipt) -> Result<()> {
        if tx_hash != receipt.tx_hash {
            bail!(
                "Receipt transaction hash mismatch: provided {:?}, receipt.tx_hash {:?}",
                tx_hash,
                receipt.tx_hash
            );
        }
        let receipt_bytes = receipt
            .try_encode()
            .context("Failed to serialize receipt")?;
        self.store_receipt_bytes(tx_hash, &receipt_bytes)
    }

    pub fn store_receipt_auto(&self, receipt: &Receipt) -> Result<[u8; 32]> {
        self.store_receipt(receipt.tx_hash, receipt)?;
        Ok(receipt.tx_hash)
    }

    pub fn store_receipt_bytes(&self, tx_hash: [u8; 32], receipt_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_TX_RECEIPTS)?;
            table.insert(tx_hash, receipt_bytes)?;
        }
        tx.commit().context("Failed to commit receipt")?;
        Ok(())
    }

    pub fn get_receipt(&self, tx_hash: [u8; 32]) -> Result<Option<Receipt>> {
        self.get_receipt_bytes(tx_hash)?
            .map(|receipt_bytes| decode_canonical::<Receipt>(&receipt_bytes))
            .transpose()
    }

    pub fn get_receipt_bytes(&self, tx_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_TX_RECEIPTS)?;
        Ok(table.get(tx_hash)?.map(|v| v.value().to_vec()))
    }

    pub fn store_block_transactions_typed(
        &self,
        height: u64,
        transactions: &[Transaction],
    ) -> Result<()> {
        let serialized: Result<Vec<_>> = transactions
            .iter()
            .map(|transaction| {
                let tx_hash = transaction.try_hash()?;
                let tx_bytes = transaction
                    .try_encode()
                    .context("Failed to serialize transaction for batch block insert")?;
                Ok((tx_hash, tx_bytes))
            })
            .collect();
        self.store_block_transactions(height, &serialized?)
    }

    pub fn store_block_transactions(
        &self,
        height: u64,
        transactions: &[([u8; 32], Vec<u8>)],
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut tx_table = tx.open_table(TABLE_TRANSACTIONS)?;
            let mut index_table = tx.open_table(TABLE_TX_BLOCK_INDEX)?;

            for (hash, bytes) in transactions {
                tx_table.insert(*hash, bytes.as_slice())?;
                index_table.insert(*hash, height)?;
            }
        }
        tx.commit().context("Batch transaction insert failed")?;
        Ok(())
    }

    pub fn get_transaction_block_height(&self, tx_hash: [u8; 32]) -> Result<Option<u64>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_TX_BLOCK_INDEX)?;
        Ok(table.get(tx_hash)?.map(|v| v.value()))
    }

    // ========================================================================
    // Account Storage
    // ========================================================================

    pub fn store_account(&self, address: [u8; 32], account: &Account) -> Result<()> {
        if address != account.address.0 {
            bail!(
                "Account address mismatch: provided {:?}, account.address {:?}",
                address,
                account.address.0
            );
        }
        account.validate()?;
        let bytes = account
            .try_encode()
            .context("Failed to serialize account")?;
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_ACCOUNTS)?;
            table.insert(address, bytes.as_slice())?;
        }
        tx.commit().context("Failed to commit account")?;
        Ok(())
    }

    pub fn store_account_auto(&self, account: &Account) -> Result<[u8; 32]> {
        let addr = account.address.0;
        self.store_account(addr, account)?;
        Ok(addr)
    }

    pub fn store_account_for_address(&self, account: &Account) -> Result<()> {
        self.store_account(account.address.0, account)
    }

    pub fn get_account(&self, address: [u8; 32]) -> Result<Option<Account>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_ACCOUNTS)?;
        let Some(val) = table.get(address)? else {
            return Ok(None);
        };
        let account: Account = decode_canonical(val.value())?;
        account.validate()?;
        Ok(Some(account))
    }

    pub fn get_account_by_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<Account>> {
        self.get_account(address.0)
    }

    pub fn delete_account(&self, address: [u8; 32]) -> Result<bool> {
        let tx = self.begin_write()?;
        let removed;
        {
            let mut table = tx.open_table(TABLE_ACCOUNTS)?;
            removed = table.remove(address)?.is_some();
        }
        tx.commit().context("Failed to delete account")?;
        Ok(removed)
    }

    pub fn delete_account_by_address(&self, address: &sxiaum_types::Address) -> Result<bool> {
        self.delete_account(address.0)
    }

    // ========================================================================
    // State Key-Value & Caching
    // ========================================================================

    pub fn state_get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.state_get_bytes(&key)
    }

    pub fn state_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_STATE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    pub fn state_put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.state_put_bytes(&key, &value)
    }

    pub fn state_put_bytes(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_STATE)?;
            table.insert(key, value)?;
        }
        tx.commit().context("Failed to commit state update")?;
        self.invalidate_cache_entry(key);
        Ok(())
    }

    /// Delete a single key from the state table.
    ///
    /// BUGFIX (C-09): required so SELFDESTRUCT tombstones can remove rows
    /// outright instead of persisting undecodable empty account values.
    pub fn state_delete(&self, key: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_STATE)?;
            table.remove(key)?;
        }
        tx.commit().context("Failed to commit state deletion")?;
        self.invalidate_cache_entry(key);
        Ok(())
    }

    pub fn atomic_state_commit(&self, changes: StateUpdates) -> Result<()> {
        self.atomic_state_commit_with_rollback(changes).map(|_| ())
    }

    /// Atomically commits state updates and returns an exact undo diff.
    /// Correctly captures the initial pre-batch state for each unique key even if
    /// the batch modifies the same key multiple times.
    pub fn atomic_state_commit_with_rollback(&self, changes: StateUpdates) -> Result<StateUpdates> {
        let tx = self.begin_write()?;
        let mut rollback_changes = Vec::with_capacity(changes.len());
        let mut seen_keys = HashSet::with_capacity(changes.len());
        {
            let mut table = tx.open_table(TABLE_STATE)?;
            // 1. Snapshot original values for each unique key before mutation
            for (key, _) in &changes {
                if seen_keys.insert(key.clone()) {
                    let previous = table
                        .get(key.as_slice())?
                        .map(|entry| entry.value().to_vec());
                    rollback_changes.push((key.clone(), previous));
                }
            }

            // 2. Apply all updates in order
            for (key, value) in changes {
                if let Some(v) = value {
                    table.insert(key.as_slice(), v.as_slice())?;
                } else {
                    table.remove(key.as_slice())?;
                }
                self.invalidate_cache_entry(&key);
            }
        }
        tx.commit().context("Atomic state commit failed")?;
        Ok(rollback_changes)
    }

    pub fn state_snapshot_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_STATE)?;
        keys.iter()
            .map(|key| {
                Ok(table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec()))
            })
            .collect()
    }

    pub fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.metrics
            .parallel_reads_total
            .fetch_add(keys.len() as u64, Ordering::Relaxed);
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_STATE)?;
        keys.iter()
            .map(|key| {
                Ok(table
                    .get(key.as_slice())?
                    .map(|value| value.value().to_vec()))
            })
            .collect()
    }

    pub fn state_prefix_scan(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_STATE)?;

        let mut results = Vec::new();
        if prefix.is_empty() {
            for item in table.iter()? {
                let (k, v) = item?;
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        } else if let Some(end) = Self::prefix_scan_upper_bound(&prefix) {
            for item in table.range(prefix.as_slice()..end.as_slice())? {
                let (k, v) = item?;
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        } else {
            for item in table.range(prefix.as_slice()..)? {
                let (k, v) = item?;
                if !k.value().starts_with(prefix.as_slice()) {
                    break;
                }
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        }

        Ok(results)
    }

    pub fn state_range_scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_STATE)?;

        let mut results = Vec::new();
        if let Some(end_key) = end {
            for item in table.range(start..end_key)? {
                if results.len() >= limit {
                    break;
                }
                let (k, v) = item?;
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        } else {
            for item in table.range(start..)? {
                if results.len() >= limit {
                    break;
                }
                let (k, v) = item?;
                results.push((k.value().to_vec(), v.value().to_vec()));
            }
        }

        Ok(results)
    }

    // ========================================================================
    // Mempool Persistence & Priority Eviction
    // ========================================================================

    pub fn mempool_insert(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        let wtx = self.begin_write()?;
        {
            let mut table = wtx.open_table(TABLE_MEMPOOL)?;
            table.insert(tx_hash, tx_bytes)?;
        }
        wtx.commit().context("Failed to commit mempool insert")?;
        Ok(())
    }

    pub fn mempool_remove(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let wtx = self.begin_write()?;
        let removed;
        {
            let mut table = wtx.open_table(TABLE_MEMPOOL)?;
            removed = table.remove(tx_hash)?.is_some();
        }
        wtx.commit().context("Failed to commit mempool remove")?;
        Ok(removed)
    }

    pub fn mempool_clear(&self) -> Result<()> {
        let wtx = self.begin_write()?;
        {
            let mut table = wtx.open_table(TABLE_MEMPOOL)?;
            let keys: Vec<[u8; 32]> = table
                .iter()?
                .map(|entry| entry.map(|(k, _)| k.value()))
                .collect::<Result<_, _>>()?;
            for key in keys {
                table.remove(key)?;
            }
        }
        wtx.commit().context("Failed to commit mempool clear")?;
        Ok(())
    }

    pub fn mempool_iterate(&self) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        let rtx = self.begin_read()?;
        let table = rtx.open_table(TABLE_MEMPOOL)?;
        table
            .iter()?
            .map(|entry| {
                entry
                    .map(|(k, v)| (k.value(), v.value().to_vec()))
                    .map_err(Into::into)
            })
            .collect()
    }

    pub fn mempool_contains(&self, tx_hash: [u8; 32]) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_MEMPOOL)?;
        Ok(table.get(tx_hash)?.is_some())
    }

    pub fn mempool_iterate_typed(&self) -> Result<Vec<([u8; 32], Transaction)>> {
        self.mempool_iterate()?
            .into_iter()
            .filter_map(
                |(hash, tx_bytes)| match decode_canonical::<Transaction>(&tx_bytes) {
                    Ok(tx) => Some(Ok((hash, tx))),
                    Err(e) => {
                        warn!("Skipping corrupted mempool tx {:?}: {}", hash, e);
                        None
                    }
                },
            )
            .collect()
    }

    pub fn mempool_evict_lowest_priority(&self, max_entries: usize) -> Result<Vec<[u8; 32]>> {
        let ranked = self.mempool_iterate_typed()?;
        if ranked.len() <= max_entries {
            return Ok(Vec::new());
        }

        let hashes_to_remove = select_lowest_priority_evictions(ranked, max_entries);
        if hashes_to_remove.is_empty() {
            return Ok(Vec::new());
        }

        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_MEMPOOL)?;
            for hash in &hashes_to_remove {
                table.remove(*hash)?;
            }
        }
        tx.commit()
            .context("Failed to evict low-priority mempool transactions")?;
        Ok(hashes_to_remove)
    }

    // ========================================================================
    // Validator & Staking Storage
    // ========================================================================

    pub fn store_validator(&self, address: [u8; 32], validator: &Validator) -> Result<()> {
        if address != validator.address.0 {
            bail!(
                "Validator address mismatch: provided {:?}, validator.address {:?}",
                address,
                validator.address.0
            );
        }
        let validator_bytes = validator
            .try_encode()
            .context("Failed to serialize validator")?;
        self.store_validator_bytes(address, &validator_bytes)
    }

    pub fn store_validator_auto(&self, validator: &Validator) -> Result<[u8; 32]> {
        let addr = validator.address.0;
        self.store_validator(addr, validator)?;
        Ok(addr)
    }

    pub fn store_validator_for_address(&self, validator: &Validator) -> Result<()> {
        self.store_validator(validator.address.0, validator)
    }

    pub fn store_validator_bytes(&self, address: [u8; 32], validator_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_VALIDATORS)?;
            table.insert(address, validator_bytes)?;
        }
        tx.commit().context("Failed to commit validator")?;
        Ok(())
    }

    pub fn get_validator(&self, address: [u8; 32]) -> Result<Option<Validator>> {
        self.get_validator_bytes(address)?
            .map(|validator_bytes| decode_canonical::<Validator>(&validator_bytes))
            .transpose()
    }

    pub fn get_validator_by_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<Validator>> {
        self.get_validator(address.0)
    }

    pub fn get_validator_bytes(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_VALIDATORS)?;
        Ok(table.get(address)?.map(|v| v.value().to_vec()))
    }

    pub fn delete_validator(&self, address: [u8; 32]) -> Result<bool> {
        let tx = self.begin_write()?;
        let removed;
        {
            let mut table = tx.open_table(TABLE_VALIDATORS)?;
            removed = table.remove(address)?.is_some();
        }
        tx.commit().context("Failed to delete validator")?;
        Ok(removed)
    }

    pub fn delete_validator_by_address(&self, address: &sxiaum_types::Address) -> Result<bool> {
        self.delete_validator(address.0)
    }

    pub fn get_all_validators(&self) -> Result<Vec<Validator>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_VALIDATORS)?;
        let mut list = Vec::new();
        for item in table.iter()? {
            let (_, v) = item?;
            list.push(decode_canonical::<Validator>(v.value())?);
        }
        Ok(list)
    }

    pub fn store_validator_set(&self, height: u64, validators: &[Validator]) -> Result<()> {
        let set_bytes =
            bincode::serialize(validators).context("Failed to serialize validator set")?;
        self.store_validator_set_bytes(height, &set_bytes)
    }

    pub fn store_validator_set_bytes(&self, height: u64, set_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_VALIDATOR_SETS)?;
            table.insert(height, set_bytes)?;
        }
        tx.commit().context("Failed to commit validator set")?;
        Ok(())
    }

    pub fn load_validator_set(&self, height: u64) -> Result<Option<Vec<Validator>>> {
        self.load_validator_set_bytes(height)?
            .map(|set_bytes| {
                bincode::deserialize(&set_bytes).context("Failed to deserialize validator set")
            })
            .transpose()
    }

    pub fn load_validator_set_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_VALIDATOR_SETS)?;
        Ok(table.get(height)?.map(|v| v.value().to_vec()))
    }

    pub fn store_staking_balance(&self, address: [u8; 32], balance: U256) -> Result<()> {
        let mut balance_bytes = [0u8; 32];
        balance.to_big_endian(&mut balance_bytes);
        self.store_staking_balance_bytes(address, &balance_bytes)
    }

    pub fn store_staking_balance_for_address(
        &self,
        address: &sxiaum_types::Address,
        balance: U256,
    ) -> Result<()> {
        self.store_staking_balance(address.0, balance)
    }

    pub fn store_staking_balance_bytes(
        &self,
        address: [u8; 32],
        balance_bytes: &[u8],
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_STAKING)?;
            table.insert(address, balance_bytes)?;
        }
        tx.commit().context("Failed to commit staking balance")?;
        Ok(())
    }

    pub fn get_staking_balance(&self, address: [u8; 32]) -> Result<Option<U256>> {
        self.get_staking_balance_bytes(address)?
            .map(|balance_bytes| {
                if balance_bytes.len() != 32 {
                    bail!("invalid staking balance length: {}", balance_bytes.len());
                }
                Ok(U256::from_big_endian(&balance_bytes))
            })
            .transpose()
    }

    pub fn get_staking_balance_for_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<U256>> {
        self.get_staking_balance(address.0)
    }

    pub fn get_staking_balance_bytes(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_STAKING)?;
        Ok(table.get(address)?.map(|v| v.value().to_vec()))
    }

    pub fn store_slashing_record(&self, address: [u8; 32], record_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_SLASHING_RECORDS)?;
            table.insert(address, record_bytes)?;
        }
        tx.commit().context("Failed to commit slashing record")?;
        Ok(())
    }

    pub fn store_slashing_record_for_address(
        &self,
        address: &sxiaum_types::Address,
        record_bytes: &[u8],
    ) -> Result<()> {
        self.store_slashing_record(address.0, record_bytes)
    }

    pub fn get_slashing_record(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_SLASHING_RECORDS)?;
        Ok(table.get(address)?.map(|v| v.value().to_vec()))
    }

    pub fn get_slashing_record_for_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<Vec<u8>>> {
        self.get_slashing_record(address.0)
    }

    // ========================================================================
    // Verkle Tree & ZK Proof Storage
    // ========================================================================

    pub fn store_verkle_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) -> Result<()> {
        self.store_verkle_node_bytes(node_hash, &node_bytes)
    }

    pub fn store_verkle_node_bytes(&self, node_hash: [u8; 32], node_bytes: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_VERKLE_NODES)?;
            table.insert(node_hash, node_bytes)?;
        }
        tx.commit().context("Failed to commit verkle node")?;
        Ok(())
    }

    pub fn load_verkle_node(&self, node_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_VERKLE_NODES)?;
        Ok(table.get(node_hash)?.map(|v| v.value().to_vec()))
    }

    pub fn batch_store_verkle_nodes(&self, nodes: &[([u8; 32], Vec<u8>)]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_VERKLE_NODES)?;
            for (hash, bytes) in nodes {
                table.insert(*hash, bytes.as_slice())?;
            }
        }
        tx.commit().context("Batch verkle node store failed")?;
        Ok(())
    }

    pub fn store_zk_proof(&self, height: u64, proof_bytes: Vec<u8>) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_ZK_PROOFS)?;
            table.insert(height, proof_bytes.as_slice())?;
        }
        tx.commit().context("Failed to commit zk proof")?;
        Ok(())
    }

    pub fn get_zk_proof(&self, height: u64) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_ZK_PROOFS)?;
        Ok(table.get(height)?.map(|value| value.value().to_vec()))
    }

    pub fn zk_proof_exists(&self, height: u64) -> Result<bool> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_ZK_PROOFS)?;
        Ok(table.get(height)?.is_some())
    }

    // ========================================================================
    // Peer Bans & Node Security
    // ========================================================================

    pub fn store_peer_ban(&self, peer_id: &str, expiry_unix: u64, reason: &str) -> Result<()> {
        let data = encode_peer_ban(expiry_unix, reason);
        self.put_metadata_for_table(TABLE_PEER_BANS, peer_id, &data)
    }

    pub fn get_peer_ban(&self, peer_id: &str) -> Result<Option<(u64, String)>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_PEER_BANS)?;
        if let Some(val) = table.get(peer_id)? {
            return Ok(parse_peer_ban(val.value()));
        }
        Ok(None)
    }

    pub fn remove_peer_ban(&self, peer_id: &str) -> Result<bool> {
        let tx = self.begin_write()?;
        let removed;
        {
            let mut table = tx.open_table(TABLE_PEER_BANS)?;
            removed = table.remove(peer_id)?.is_some();
        }
        tx.commit()?;
        Ok(removed)
    }

    pub fn list_peer_bans(&self) -> Result<Vec<(String, u64, String)>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_PEER_BANS)?;
        let mut bans = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            if let Some((exp, reason)) = parse_peer_ban(v.value()) {
                bans.push((k.value().to_string(), exp, reason));
            }
        }
        Ok(bans)
    }

    fn put_metadata_for_table(
        &self,
        table_def: TableDefinition<&str, &[u8]>,
        key: &str,
        value: &[u8],
    ) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(table_def)?;
            table.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }

    // ========================================================================
    // Performance & Caching
    // ========================================================================

    pub fn batch_write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&WriteTransaction) -> Result<()>,
    {
        self.execute_write(|txn| {
            f(txn)?;
            self.metrics
                .batch_write_total
                .fetch_add(1, Ordering::Relaxed);
            counter!("storage.batch_write_total").increment(1);
            Ok(())
        })
    }

    pub fn state_get_cached(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        {
            let mut cache = self.cache.lock();
            if let Some(value) = cache.get(&key) {
                self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                counter!("storage.cache_hit_total").increment(1);
                return Ok(Some(value.clone()));
            }
        }

        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        counter!("storage.cache_miss_total").increment(1);
        if let Some(val) = self.state_get(key.clone())? {
            let mut cache = self.cache.lock();
            cache.put(key, val.clone());
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    pub fn flush_to_disk(&self) -> Result<()> {
        info!("Synching storage cache to persistent disk storage...");
        self.flush_buffered_block_execution_writes()?;
        self.metrics
            .disk_flush_total
            .fetch_add(1, Ordering::Relaxed);
        counter!("storage.disk_flush_total").increment(1);
        Ok(())
    }

    pub fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "cache_size": self.cache.lock().len(),
            "database_open": true,
            "batch_write_total": self.metrics.batch_write_total.load(Ordering::Relaxed),
            "cache_hits": self.metrics.cache_hits.load(Ordering::Relaxed),
            "cache_misses": self.metrics.cache_misses.load(Ordering::Relaxed),
            "disk_flush_total": self.metrics.disk_flush_total.load(Ordering::Relaxed),
            "parallel_reads_total": self.metrics.parallel_reads_total.load(Ordering::Relaxed),
            "buffered_write_flushes": self.metrics.buffered_write_flushes.load(Ordering::Relaxed),
            "buffered_writes_pending": self.buffered_state_writes.lock().len(),
            "buffered_writes_enqueued": self.metrics.buffered_writes_enqueued.load(Ordering::Relaxed),
        }))
    }

    // ========================================================================
    // Snapshots, Compaction & Deep Integrity Checks
    // ========================================================================

    pub fn export_snapshot(&self, dest: impl AsRef<Path>) -> Result<()> {
        info!("Exporting database snapshot to {:?}...", dest.as_ref());
        self.flush_to_disk()?;
        Self::copy_database_to_path(self.db.clone(), dest.as_ref())?;
        Ok(())
    }

    pub fn restore_from_snapshot(
        snapshot_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
    ) -> Result<()> {
        let snapshot_path = snapshot_path.as_ref();
        let target_path = target_path.as_ref();
        info!("Restoring database from snapshot {:?}...", snapshot_path);

        if !snapshot_path.exists() {
            bail!("snapshot file does not exist: {:?}", snapshot_path);
        }

        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create restore target directory {:?}", parent)
            })?;
        }

        let backup_path = target_path.with_extension("bak");
        if target_path.exists() {
            if backup_path.exists() {
                let _ = fs::remove_file(&backup_path);
            }
            fs::rename(target_path, &backup_path).with_context(|| {
                format!("Failed to back up existing database {:?}", target_path)
            })?;
        }

        if let Err(error) = fs::copy(snapshot_path, target_path).with_context(|| {
            format!(
                "Failed to copy snapshot {:?} to {:?}",
                snapshot_path, target_path
            )
        }) {
            if backup_path.exists() {
                let _ = fs::rename(&backup_path, target_path);
            }
            return Err(error);
        }

        if let Err(error) = Self::open_or_create_db(target_path) {
            let _ = fs::remove_file(target_path);
            if backup_path.exists() {
                let _ = fs::rename(&backup_path, target_path);
            }
            return Err(error).context("Restored snapshot failed validation");
        }

        if backup_path.exists() {
            let _ = fs::remove_file(backup_path);
        }

        Ok(())
    }

    pub fn check_integrity(&self) -> Result<bool> {
        info!("Starting full database integrity check...");

        let read_tx = self.begin_read()?;
        Self::verify_str_bytes_table(&read_tx, TABLE_METADATA)?;
        Self::verify_u64_bytes_table(&read_tx, TABLE_BLOCK_HEADERS)?;
        Self::verify_u64_bytes_table(&read_tx, TABLE_BLOCK_BODIES)?;
        Self::verify_hash_u64_table(&read_tx, TABLE_BLOCK_HASH_INDEX)?;
        Self::verify_u64_hash_table(&read_tx, TABLE_CANONICAL_CHAIN)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_FORK_BLOCKS)?;
        Self::verify_u64_hash_table(&read_tx, TABLE_FINALIZED_BLOCKS)?;
        Self::verify_u64_bytes_table(&read_tx, TABLE_LOGS_BLOOM)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_TRANSACTIONS)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_ACCOUNTS)?;
        Self::verify_slice_bytes_table(&read_tx, TABLE_STATE)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_VALIDATORS)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_STAKING)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_MEMPOOL)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_VERKLE_NODES)?;
        Self::verify_u64_bytes_table(&read_tx, TABLE_ZK_PROOFS)?;
        Self::verify_hash_u64_table(&read_tx, TABLE_TX_BLOCK_INDEX)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_TX_RECEIPTS)?;
        Self::verify_u64_bytes_table(&read_tx, TABLE_VALIDATOR_SETS)?;
        Self::verify_hash_bytes_table(&read_tx, TABLE_SLASHING_RECORDS)?;
        Self::verify_str_bytes_table(&read_tx, TABLE_PEER_BANS)?;

        drop(read_tx);
        self.check_chain_invariants()?;
        Ok(true)
    }

    /// Verifies relational and cryptographic integrity across canonical chain,
    /// block hash index, block headers, block bodies, and parent linkages.
    pub fn check_chain_invariants(&self) -> Result<bool> {
        let read_tx = self.begin_read()?;
        let canonical_table = read_tx.open_table(TABLE_CANONICAL_CHAIN)?;
        let hash_index_table = read_tx.open_table(TABLE_BLOCK_HASH_INDEX)?;
        let headers_table = read_tx.open_table(TABLE_BLOCK_HEADERS)?;
        let bodies_table = read_tx.open_table(TABLE_BLOCK_BODIES)?;

        let rows = canonical_table
            .iter()?
            .map(|row| -> Result<CanonicalRow> {
                let (h_entry, hash_entry) = row?;
                let height = h_entry.value();
                let hash = hash_entry.value();

                let header_bytes = headers_table
                    .get(height)?
                    .map(|v| v.value().to_vec())
                    .ok_or_else(|| StorageError::StorageCorruption {
                        reason: format!("Canonical block at height {} missing header", height),
                    })?;

                let body_bytes = bodies_table
                    .get(height)?
                    .map(|v| v.value().to_vec())
                    .ok_or_else(|| StorageError::StorageCorruption {
                        reason: format!("Canonical block at height {} missing body", height),
                    })?;

                Ok(CanonicalRow {
                    height,
                    hash,
                    header_bytes,
                    body_bytes,
                    indexed_height: hash_index_table.get(hash)?.map(|v| v.value()),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        drop(read_tx);
        verify_canonical_sequence(rows)?;
        Ok(true)
    }

    pub fn disk_usage_bytes(&self) -> Result<u64> {
        let db_size = fs::metadata(&self.db_path)?.len();
        let corruption_marker_size = self
            .db_path
            .with_extension("corrupt")
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(0);
        let backup_size = self
            .db_path
            .with_extension("bak")
            .metadata()
            .map(|meta| meta.len())
            .unwrap_or(0);
        Ok(db_size + corruption_marker_size + backup_size)
    }

    pub fn compact_database(&self) -> Result<()> {
        info!("Initiating database compaction...");

        if self.compaction_running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let db = self.db.clone();
        let db_path = self.db_path.clone();
        let compaction_running = Arc::clone(&self.compaction_running);
        let handle = thread::spawn(move || {
            let compacted_path = db_path.with_extension("compacted.redb");
            let compaction_result = Self::copy_database_to_path(db.clone(), &compacted_path);

            if let Err(compaction_error) = compaction_result {
                error!(
                    "background compaction failed for {:?}: {:?}",
                    db_path, compaction_error
                );
            } else {
                let timestamp = chrono::Utc::now().to_rfc3339();
                if let Ok(tx) = db.begin_write() {
                    if let Ok(mut table) = tx.open_table(TABLE_METADATA) {
                        let compacted_path_str = compacted_path.to_string_lossy().to_string();
                        let _ = table.insert(LAST_COMPACTION_AT_KEY, timestamp.as_bytes());
                        let _ =
                            table.insert(LAST_COMPACTION_PATH_KEY, compacted_path_str.as_bytes());
                    }
                    let _ = tx.commit();
                }
            }

            compaction_running.store(false, Ordering::SeqCst);
        });

        *self.compaction_handle.lock() = Some(handle);
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        info!("Gracefully shutting down StorageEngine...");
        self.stop_flush_scheduler()?;
        self.join_compaction_thread()?;
        self.flush_to_disk()?;
        if !self.shutdown_recorded.swap(true, Ordering::SeqCst) {
            self.record_clean_shutdown()?;
        }
        Ok(())
    }

    pub fn rollback_state_batch(
        &self,
        undo_changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<()> {
        info!(
            "Executing atomic state rollback of {} records...",
            undo_changes.len()
        );
        let mut reversed = undo_changes;
        reversed.reverse();
        self.atomic_state_commit(reversed)?;
        self.cache.lock().clear();
        Ok(())
    }

    // ========================================================================
    // Metadata Helpers
    // ========================================================================

    fn update_latest_height_metadata(tx: &WriteTransaction, height: u64) -> Result<()> {
        let mut meta_table = tx.open_table(TABLE_METADATA)?;
        let current_height = Self::read_latest_height_metadata(&meta_table)?.unwrap_or(0);

        if height > current_height || meta_table.get(LATEST_BLOCK_HEIGHT_KEY)?.is_none() {
            let height_bytes = height.to_le_bytes();
            meta_table.insert(LATEST_BLOCK_HEIGHT_KEY, height_bytes.as_slice())?;
        }

        Ok(())
    }

    fn reconcile_latest_height_metadata(
        tx: &WriteTransaction,
        latest_height: Option<u64>,
    ) -> Result<()> {
        let mut meta_table = tx.open_table(TABLE_METADATA)?;
        if let Some(height) = latest_height {
            let height_bytes = height.to_le_bytes();
            meta_table.insert(LATEST_BLOCK_HEIGHT_KEY, height_bytes.as_slice())?;
        } else {
            meta_table.remove(LATEST_BLOCK_HEIGHT_KEY)?;
        }

        Ok(())
    }

    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let tx = self.begin_read()?;
        let table = tx.open_table(TABLE_METADATA)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    pub fn get_metadata_str(&self, key: &str) -> Result<Option<String>> {
        let bytes_opt = self.get_metadata(key)?;
        Ok(bytes_opt.and_then(|b| String::from_utf8(b).ok()))
    }

    pub fn put_metadata(&self, key: &str, value: &[u8]) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx.open_table(TABLE_METADATA)?;
            table.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn put_metadata_str(&self, key: &str, value: &str) -> Result<()> {
        self.put_metadata(key, value.as_bytes())
    }

    fn read_latest_height_metadata<T>(table: &T) -> Result<Option<u64>>
    where
        T: ReadableTable<&'static str, &'static [u8]>,
    {
        let value = table.get(LATEST_BLOCK_HEIGHT_KEY)?;
        let Some(value) = value else {
            return Ok(None);
        };

        let bytes = value.value();
        if bytes.len() != std::mem::size_of::<u64>() {
            bail!(
                "invalid latest_block_height metadata length: {}",
                bytes.len()
            );
        }

        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(bytes);
        Ok(Some(u64::from_le_bytes(height_bytes)))
    }

    fn record_clean_shutdown(&self) -> Result<()> {
        let tx = self.begin_write()?;
        {
            let mut table = tx
                .open_table(TABLE_METADATA)
                .context("Failed to open metadata table for shutdown bookkeeping")?;
            table.insert(LAST_SHUTDOWN_CLEAN_KEY, b"true".as_slice())?;
        }
        tx.commit()
            .context("Failed to record clean database shutdown")?;
        Ok(())
    }

    fn join_compaction_thread(&self) -> Result<()> {
        if let Some(handle) = self.compaction_handle.lock().take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("storage compaction thread panicked"))?;
        }
        Ok(())
    }

    fn prefix_scan_upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
        let mut end = prefix.to_vec();
        for index in (0..end.len()).rev() {
            if end[index] != u8::MAX {
                end[index] = end[index].saturating_add(1);
                end.truncate(index + 1);
                return Some(end);
            }
        }
        None
    }

    fn invalidate_cache_entry(&self, key: &[u8]) {
        self.cache.lock().pop(&key.to_vec());
    }

    fn start_flush_scheduler(&self) -> Result<()> {
        let (stop_tx, stop_rx) = mpsc::channel();
        let db = self.db.clone();
        let buffered_state_writes = Arc::clone(&self.buffered_state_writes);
        let metrics = Arc::clone(&self.metrics);
        // Share the engine's live read cache so flushed buffered writes
        // invalidate stale cached values in the background thread too.
        let cache = Arc::clone(&self.cache);
        let flush_lock = Arc::clone(&self.flush_lock);
        let handle = thread::spawn(move || loop {
            match stop_rx.recv_timeout(Duration::from_secs(DEFAULT_FLUSH_INTERVAL_SECS)) {
                Ok(_) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let _flush_guard = flush_lock.lock();
                    let _ = Self::flush_buffered_state_writes_inner(
                        &db,
                        &buffered_state_writes,
                        &metrics,
                        &cache,
                    );
                    metrics.disk_flush_total.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        });

        *self.flush_thread_stop.lock() = Some(stop_tx);
        *self.flush_thread_handle.lock() = Some(handle);
        Ok(())
    }

    fn stop_flush_scheduler(&self) -> Result<()> {
        if let Some(stop_tx) = self.flush_thread_stop.lock().take() {
            let _ = stop_tx.send(());
        }

        if let Some(handle) = self.flush_thread_handle.lock().take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("storage flush scheduler thread panicked"))?;
        }

        Ok(())
    }

    fn flush_buffered_state_writes_inner(
        db: &Arc<Database>,
        buffered_state_writes: &Arc<Mutex<StateUpdates>>,
        metrics: &Arc<StorageMetricsInner>,
        cache: &Mutex<LruCache<Vec<u8>, Vec<u8>>>,
    ) -> Result<usize> {
        // SECURITY: atomically take ownership of the ENTIRE buffer instead of
        // clone-then-drain-by-count. The previous scheme desynchronized under
        // concurrent producers (the drain count no longer matched the cloned
        // prefix) and concurrent flushers could commit overlapping snapshots
        // out of order, letting a stale write win over a newer committed one.
        // Callers must hold `flush_lock` so batches commit in take order.
        let pending = std::mem::take(&mut *buffered_state_writes.lock());
        if pending.is_empty() {
            return Ok(0);
        }

        let restore_on_failure = |pending: StateUpdates| {
            // Prepend the failed batch ahead of anything produced while the
            // commit was in flight, preserving original FIFO order.
            let mut guard = buffered_state_writes.lock();
            let mut restored = pending;
            restored.extend(guard.drain(..));
            *guard = restored;
        };

        let tx = match db.begin_write() {
            Ok(tx) => tx,
            Err(e) => {
                let err_msg = format!("{:?}", e);
                if err_msg.contains("DatabaseAlreadyOpen")
                    || err_msg.contains("TransactionAlreadyExists")
                    || err_msg.contains("already open")
                {
                    // Non-fatal transient lock contention: retain buffered items for next flush
                    restore_on_failure(pending);
                    return Ok(0);
                }
                restore_on_failure(pending);
                return Err(e.into());
            }
        };

        let commit_res: Result<()> = (|| {
            {
                let mut table = tx.open_table(TABLE_STATE)?;
                for (key, value) in &pending {
                    if let Some(value) = value {
                        table.insert(key.as_slice(), value.as_slice())?;
                    } else {
                        table.remove(key.as_slice())?;
                    }
                }
            }
            tx.commit()
                .context("Failed to commit buffered state writes")?;
            Ok(())
        })();

        match commit_res {
            Ok(()) => {
                // FIX (SEC): evict every flushed key from the read cache.
                // Buffered writes previously landed in the state table
                // without invalidating cached values, so `state_get_cached`
                // could keep serving pre-commit (stale) state — a
                // consensus-correctness hazard for parallel execution.
                {
                    let mut lru = cache.lock();
                    for (key, _) in &pending {
                        lru.pop(key);
                    }
                }
                metrics
                    .buffered_write_flushes
                    .fetch_add(1, Ordering::Relaxed);
                Ok(pending.len())
            }
            Err(e) => {
                warn!(
                    "Buffered state flush failed: {}. Retaining {} updates for subsequent retry.",
                    e,
                    pending.len()
                );
                restore_on_failure(pending);
                Err(e)
            }
        }
    }

    fn copy_database_to_path(db: Arc<Database>, dest: &Path) -> Result<()> {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create snapshot directory {:?}", parent))?;
        }

        if dest.exists() {
            fs::remove_file(dest)
                .with_context(|| format!("Failed to remove existing snapshot {:?}", dest))?;
        }

        let snapshot_db = crate::schema::Schema::init(dest)?;
        let read_tx = db
            .begin_read()
            .context("Failed to begin read transaction for snapshot")?;
        let write_tx = snapshot_db
            .begin_write()
            .context("Failed to begin write transaction for snapshot")?;

        Self::copy_str_bytes_table(&read_tx, &write_tx, TABLE_METADATA)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, TABLE_BLOCK_HEADERS)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, TABLE_BLOCK_BODIES)?;
        Self::copy_hash_u64_table(&read_tx, &write_tx, TABLE_BLOCK_HASH_INDEX)?;
        Self::copy_u64_hash_table(&read_tx, &write_tx, TABLE_CANONICAL_CHAIN)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_FORK_BLOCKS)?;
        Self::copy_u64_hash_table(&read_tx, &write_tx, TABLE_FINALIZED_BLOCKS)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, TABLE_LOGS_BLOOM)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_TRANSACTIONS)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_ACCOUNTS)?;
        Self::copy_slice_bytes_table(&read_tx, &write_tx, TABLE_STATE)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_VALIDATORS)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_STAKING)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_MEMPOOL)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_VERKLE_NODES)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, TABLE_ZK_PROOFS)?;
        Self::copy_hash_u64_table(&read_tx, &write_tx, TABLE_TX_BLOCK_INDEX)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_TX_RECEIPTS)?;
        Self::copy_u64_bytes_table(&read_tx, &write_tx, TABLE_VALIDATOR_SETS)?;
        Self::copy_hash_bytes_table(&read_tx, &write_tx, TABLE_SLASHING_RECORDS)?;
        Self::copy_str_bytes_table(&read_tx, &write_tx, TABLE_PEER_BANS)?;

        write_tx
            .commit()
            .context("Failed to commit snapshot database")?;
        Ok(())
    }

    fn copy_str_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<&str, &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_u64_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<u64, &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_hash_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<[u8; 32], &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_slice_bytes_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<&[u8], &[u8]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_hash_u64_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<[u8; 32], u64>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn copy_u64_hash_table(
        read_tx: &ReadTransaction,
        write_tx: &WriteTransaction,
        table_def: TableDefinition<u64, [u8; 32]>,
    ) -> Result<()> {
        let read_table = read_tx.open_table(table_def)?;
        let mut write_table = write_tx.open_table(table_def)?;
        for row in read_table.iter()? {
            let (key, value) = row?;
            write_table.insert(key.value(), value.value())?;
        }
        Ok(())
    }

    fn verify_str_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<&str, &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_u64_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<u64, &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_hash_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<[u8; 32], &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_slice_bytes_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<&[u8], &[u8]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_hash_u64_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<[u8; 32], u64>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }

    fn verify_u64_hash_table(
        read_tx: &ReadTransaction,
        table_def: TableDefinition<u64, [u8; 32]>,
    ) -> Result<()> {
        let table = read_tx.open_table(table_def)?;
        for row in table.iter()? {
            let _ = row?;
        }
        Ok(())
    }
}

impl Drop for StorageEngine {
    fn drop(&mut self) {
        if !self.shutdown_recorded.load(Ordering::SeqCst) {
            let _ = self.shutdown();
        }
    }
}

impl DatabaseBackend for StorageEngine {
    fn latest_block_height(&self) -> Result<u64> {
        self.latest_block_height()
    }

    fn state_get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        self.state_get(key)
    }

    fn state_put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.state_put(key, value)
    }

    fn state_delete(&self, key: Vec<u8>) -> Result<()> {
        self.state_delete(&key)
    }

    fn atomic_state_commit(&self, changes: StateUpdates) -> Result<()> {
        self.atomic_state_commit(changes)
    }

    fn atomic_state_commit_async(&self, changes: StateUpdates) -> Result<()> {
        let mut buffered = self.buffered_state_writes.lock();
        if buffered.len() + changes.len() >= MAX_BUFFERED_WRITES {
            drop(buffered);
            self.flush_buffered_block_execution_writes()?;
            buffered = self.buffered_state_writes.lock();
        }
        let count = changes.len() as u64;
        buffered.extend(changes);
        self.metrics
            .buffered_writes_enqueued
            .fetch_add(count, Ordering::Relaxed);
        Ok(())
    }

    fn state_snapshot_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.state_snapshot_reads(keys)
    }

    fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.parallel_state_reads(keys)
    }

    fn state_prefix_scan(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.state_prefix_scan(prefix)
    }

    fn state_range_scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.state_range_scan(start, end, limit)
    }

    fn rollback_state_batch(&self, undo_changes: StateUpdates) -> Result<()> {
        self.rollback_state_batch(undo_changes)
    }

    fn flush_to_disk(&self) -> Result<()> {
        self.flush_to_disk()
    }

    fn load_verkle_node(&self, node_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        self.load_verkle_node(node_hash)
    }

    fn store_verkle_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) -> Result<()> {
        self.store_verkle_node(node_hash, node_bytes)
    }

    fn batch_store_verkle_nodes(&self, nodes: &[([u8; 32], Vec<u8>)]) -> Result<()> {
        self.batch_store_verkle_nodes(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::StorageEngine;
    use crate::backend::DatabaseBackend;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_block::{BlockBody, BlockHeader};
    use sxiaum_types::{Account, Address};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-storage-{name}-{unique}.redb"))
    }

    #[test]
    fn stores_and_loads_typed_block_parts() {
        let db_path = temp_db_path("typed-block-parts");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");
        let header = BlockHeader::new([1u8; 32], 7);
        let mut body = BlockBody::new();
        body.receipts = Vec::new();

        engine
            .store_block_header(7, &header)
            .expect("header should store");
        engine
            .store_block_body(7, &body)
            .expect("body should store");

        let loaded_header = engine
            .get_block_header(7)
            .expect("header read should succeed")
            .expect("header should exist");
        let loaded_body = engine
            .get_block_body(7)
            .expect("body read should succeed")
            .expect("body should exist");

        assert_eq!(loaded_header, header);
        assert_eq!(loaded_body, body);
        assert!(engine
            .block_exists(7)
            .expect("existence check should succeed"));
        assert_eq!(
            engine
                .latest_block_height()
                .expect("latest height should load"),
            7
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn canonical_blocks_indexing_and_reorg() {
        let db_path = temp_db_path("canonical-reorg");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let h1 = BlockHeader::new([0x11; 32], 1);
        let b1 = BlockBody::new();
        let h1_hash = h1.try_hash().unwrap();

        let h2 = BlockHeader::new(h1_hash, 2);
        let b2 = BlockBody::new();
        let h2_hash = h2.try_hash().unwrap();

        engine
            .store_canonical_block(1, h1_hash, &h1, &b1)
            .expect("store block 1");
        engine
            .store_canonical_block(2, h2_hash, &h2, &b2)
            .expect("store block 2");

        assert_eq!(engine.latest_block_height().unwrap(), 2);
        assert_eq!(engine.get_block_hash_by_height(1).unwrap(), Some(h1_hash));
        assert_eq!(engine.get_block_height_by_hash(h1_hash).unwrap(), Some(1));
        assert!(engine.is_canonical_block(1, h1_hash).unwrap());

        // Revert block 2
        engine.revert_block(2).expect("revert block 2");
        assert_eq!(engine.latest_block_height().unwrap(), 1);
        assert_eq!(engine.get_block_hash_by_height(2).unwrap(), None);
        assert_eq!(engine.get_block_height_by_hash(h2_hash).unwrap(), None);

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn finality_protection_prevents_rollback_and_pruning() {
        let db_path = temp_db_path("finality-protect");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let h1 = BlockHeader::new([0x11; 32], 1);
        let b1 = BlockBody::new();
        let h1_hash = h1.try_hash().unwrap();

        let h2 = BlockHeader::new(h1_hash, 2);
        let b2 = BlockBody::new();
        let h2_hash = h2.try_hash().unwrap();

        engine.store_canonical_block(1, h1_hash, &h1, &b1).unwrap();
        engine.store_canonical_block(2, h2_hash, &h2, &b2).unwrap();
        engine.set_finalized_height(2, h2_hash).unwrap();

        // Attempting to revert finalized block 2 must fail
        let err = engine.revert_block(2).unwrap_err();
        assert!(err.to_string().contains("finalized block"));

        // Attempting multi-block revert past finalized height must fail
        let err2 = engine.revert_blocks_to(1).unwrap_err();
        assert!(err2.to_string().contains("finalized block"));

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn state_rollback_with_intra_batch_duplicate_keys() {
        let db_path = temp_db_path("state-rollback-dup");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        engine
            .state_put(b"test_key".to_vec(), b"v0".to_vec())
            .unwrap();

        // Single batch updates test_key to v1, then to v2
        let undo = engine
            .atomic_state_commit_with_rollback(vec![
                (b"test_key".to_vec(), Some(b"v1".to_vec())),
                (b"test_key".to_vec(), Some(b"v2".to_vec())),
            ])
            .unwrap();

        assert_eq!(
            engine.state_get(b"test_key".to_vec()).unwrap().as_deref(),
            Some(b"v2".as_slice())
        );

        engine.rollback_state_batch(undo).unwrap();
        assert_eq!(
            engine.state_get(b"test_key".to_vec()).unwrap().as_deref(),
            Some(b"v0".as_slice())
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn account_crud_operations() {
        let db_path = temp_db_path("account-crud");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        let addr = [0x55; 32];
        let mut account = Account::new(Address(addr));
        account
            .checked_add_balance(U256::from(100_000u64))
            .expect("balance credit must succeed");

        engine.store_account(addr, &account).unwrap();
        let loaded = engine.get_account(addr).unwrap().unwrap();
        assert_eq!(loaded.balance, U256::from(100_000u64));

        assert!(engine.delete_account(addr).unwrap());
        assert_eq!(engine.get_account(addr).unwrap(), None);

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn state_range_scan_with_bounds() {
        let db_path = temp_db_path("range-scan");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        engine
            .atomic_state_commit(vec![
                (b"key:1".to_vec(), Some(b"v1".to_vec())),
                (b"key:2".to_vec(), Some(b"v2".to_vec())),
                (b"key:3".to_vec(), Some(b"v3".to_vec())),
                (b"key:4".to_vec(), Some(b"v4".to_vec())),
            ])
            .unwrap();

        let scanned = engine
            .state_range_scan(b"key:2", Some(b"key:4"), 10)
            .unwrap();
        assert_eq!(scanned.len(), 2);
        assert_eq!(scanned[0].0, b"key:2");
        assert_eq!(scanned[1].0, b"key:3");

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn peer_bans_lifecycle() {
        let db_path = temp_db_path("peer-bans");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        engine
            .store_peer_ban("12D3KooWTest", 1750000000, "invalid block proposal")
            .unwrap();

        let ban = engine.get_peer_ban("12D3KooWTest").unwrap().unwrap();
        assert_eq!(ban.0, 1750000000);
        assert_eq!(ban.1, "invalid block proposal");

        // Reasons containing ':' must round-trip without truncation.
        engine
            .store_peer_ban("12D3KooWColon", 111, "reason: with: colons")
            .unwrap();
        assert_eq!(
            engine.get_peer_ban("12D3KooWColon").unwrap(),
            Some((111, "reason: with: colons".to_string()))
        );

        let all_bans = engine.list_peer_bans().unwrap();
        assert_eq!(all_bans.len(), 2);

        assert!(engine.remove_peer_ban("12D3KooWTest").unwrap());
        assert_eq!(engine.get_peer_ban("12D3KooWTest").unwrap(), None);

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    /// REGRESSION: buffered async writes previously landed in the state table
    /// without invalidating the LRU read cache, so `state_get_cached` kept
    /// serving pre-commit (stale) state — a consensus-correctness hazard.
    #[test]
    fn buffered_async_commit_invalidates_read_cache() {
        let db_path = temp_db_path("buffered-cache-freshness");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        engine
            .state_put(b"cache_key".to_vec(), b"v1".to_vec())
            .unwrap();

        // Prime the read cache with the old value.
        assert_eq!(
            engine
                .state_get_cached(b"cache_key".to_vec())
                .unwrap()
                .as_deref(),
            Some(b"v1".as_slice())
        );

        // Buffer an async commit (update + delete of a second cached key) and
        // force it to disk through the flush path.
        engine
            .state_put(b"doomed_key".to_vec(), b"d1".to_vec())
            .unwrap();
        let _ = engine.state_get_cached(b"doomed_key".to_vec()).unwrap();
        engine
            .atomic_state_commit_async(vec![
                (b"cache_key".to_vec(), Some(b"v2".to_vec())),
                (b"doomed_key".to_vec(), None),
            ])
            .unwrap();
        engine.flush_buffered_block_execution_writes().unwrap();

        // Cached values must reflect committed state, not stale entries.
        assert_eq!(
            engine
                .state_get_cached(b"cache_key".to_vec())
                .unwrap()
                .as_deref(),
            Some(b"v2".as_slice())
        );
        assert_eq!(
            engine.state_get_cached(b"doomed_key".to_vec()).unwrap(),
            None
        );

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    /// REGRESSION (flush single-flight): concurrent producers and flushers
    /// previously raced via clone-then-drain-by-count, so overlapping batches
    /// could commit out of order and a stale value could win over a newer one.
    /// With single-flight flushing and atomic take semantics the LAST produced
    /// value per key must always survive.
    #[test]
    fn concurrent_producers_and_flushers_never_lose_updates() {
        let db_path = temp_db_path("flush-race");
        let engine =
            std::sync::Arc::new(StorageEngine::new(&db_path).expect("storage should initialize"));

        const PRODUCERS: usize = 4;
        const ROUNDS: u64 = 150;

        let mut handles = Vec::new();
        for producer in 0..PRODUCERS {
            let engine = std::sync::Arc::clone(&engine);
            handles.push(std::thread::spawn(move || {
                let key = format!("race_key_{producer}").into_bytes();
                for round in 1..=ROUNDS {
                    engine
                        .atomic_state_commit_async(vec![(
                            key.clone(),
                            Some(round.to_le_bytes().to_vec()),
                        )])
                        .unwrap();
                    if round % 7 == 0 {
                        // Interleave foreground flushes with the background scheduler.
                        engine.flush_buffered_block_execution_writes().unwrap();
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("producer thread should not panic");
        }
        engine.flush_buffered_block_execution_writes().unwrap();

        for producer in 0..PRODUCERS {
            let key = format!("race_key_{producer}").into_bytes();
            let value = engine.state_get(key.clone()).unwrap().unwrap();
            assert_eq!(
                value,
                ROUNDS.to_le_bytes(),
                "stale write won the flush race for key {key:?}"
            );
            // The read cache must also reflect committed state.
            assert_eq!(
                engine.state_get_cached(key).unwrap().unwrap(),
                ROUNDS.to_le_bytes()
            );
        }

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }

    /// REGRESSION: pruning was allowed up to `finalized + 1`, which deleted
    /// the finalized block itself. The finalized block must stay intact.
    #[test]
    fn prune_never_deletes_finalized_block() {
        let db_path = temp_db_path("prune-finality");
        let engine = StorageEngine::new(&db_path).expect("storage should initialize");

        for h in 1..=4u64 {
            let header = BlockHeader::new([h as u8; 32], h);
            let hash = header.try_hash().unwrap();
            engine
                .store_canonical_block(h, hash, &header, &BlockBody::new())
                .unwrap();
        }
        let finalized_hash = engine
            .get_block_hash_by_height(3)
            .unwrap()
            .expect("block 3 hash should exist");
        engine.set_finalized_height(3, finalized_hash).unwrap();

        // height == finalized + 1 must now be rejected...
        let err = engine.prune_blocks_before(4).unwrap_err();
        assert!(err.to_string().contains("finalized"), "unexpected: {err}");

        // ...and an accepted prune must keep the finalized block readable.
        let pruned = engine.prune_blocks_before(2).unwrap();
        assert_eq!(pruned, 1); // only height 1 lies below the prune target
        assert!(engine.block_exists(3).unwrap());
        assert!(!engine.block_exists(1).unwrap());

        drop(engine);
        let _ = std::fs::remove_file(db_path);
    }
}
