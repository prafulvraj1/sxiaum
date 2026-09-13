//! In-memory [`DatabaseBackend`] for ephemeral / stateless execution and testing.
//!
//! Provides full behavioral parity with [`StorageEngine`](crate::StorageEngine),
//! including canonical block indexing, chain reorganisations, finality protection,
//! state caching, verkle trees, receipts, validator snapshots, and mempool persistence.

use crate::backend::{DatabaseBackend, StateUpdates};
use crate::error::StorageError;
use crate::util::{
    decode_canonical, select_lowest_priority_evictions, verify_canonical_sequence, CanonicalRow,
};
use anyhow::{bail, Result};
use parking_lot::RwLock;
use primitive_types::U256;
use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use sxiaum_block::{BlockBody, BlockHeader};
use sxiaum_types::{Account, Canonical, Receipt, Transaction, Validator};

/// Thread-safe, full-featured in-memory key-value blockchain backend.
#[derive(Debug, Default)]
pub struct MemoryDatabaseBackend {
    state: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
    verkle: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    block_headers: RwLock<BTreeMap<u64, Vec<u8>>>,
    block_bodies: RwLock<BTreeMap<u64, Vec<u8>>>,
    block_hash_index: RwLock<BTreeMap<[u8; 32], u64>>,
    canonical_chain: RwLock<BTreeMap<u64, [u8; 32]>>,
    fork_blocks: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    finalized_blocks: RwLock<BTreeMap<u64, [u8; 32]>>,
    logs_bloom: RwLock<BTreeMap<u64, Vec<u8>>>,
    transactions: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    tx_block_index: RwLock<BTreeMap<[u8; 32], u64>>,
    receipts: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    accounts: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    validators: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    staking: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    validator_sets: RwLock<BTreeMap<u64, Vec<u8>>>,
    slashing_records: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    zk_proofs: RwLock<BTreeMap<u64, Vec<u8>>>,
    mempool: RwLock<BTreeMap<[u8; 32], Vec<u8>>>,
    peer_bans: RwLock<BTreeMap<String, (u64, String)>>,
    metadata: RwLock<BTreeMap<String, Vec<u8>>>,
    height: AtomicU64,
    finalized_height: AtomicU64,
    safe_height: AtomicU64,
}

impl MemoryDatabaseBackend {
    /// Create a new in-memory database instance.
    pub fn new() -> Self {
        let backend = Self::default();
        backend.put_metadata("chain_id", sxiaum_types::SXIAUM_CHAIN_ID_STR.as_bytes());
        backend.put_metadata("version", b"2.0.0");
        backend
    }

    /// Create an in-memory database initialized to a specific block height.
    pub fn with_height(height: u64) -> Self {
        let backend = Self::new();
        backend.height.store(height, Ordering::SeqCst);
        backend
    }

    pub fn set_latest_height(&self, height: u64) {
        self.height.store(height, Ordering::SeqCst);
    }

    pub fn set_finalized_height(&self, height: u64, block_hash: [u8; 32]) -> Result<()> {
        self.finalized_blocks.write().insert(height, block_hash);
        self.finalized_height.store(height, Ordering::SeqCst);
        self.put_metadata("finalized_block_height", &height.to_le_bytes());
        Ok(())
    }

    pub fn get_finalized_height(&self) -> Result<Option<u64>> {
        let h = self.finalized_height.load(Ordering::SeqCst);
        if h == 0 && !self.finalized_blocks.read().contains_key(&0) {
            Ok(None)
        } else {
            Ok(Some(h))
        }
    }

    pub fn set_safe_height(&self, height: u64) -> Result<()> {
        self.safe_height.store(height, Ordering::SeqCst);
        self.put_metadata("safe_block_height", &height.to_le_bytes());
        Ok(())
    }

    pub fn get_safe_height(&self) -> Result<Option<u64>> {
        let h = self.safe_height.load(Ordering::SeqCst);
        if h == 0 {
            Ok(None)
        } else {
            Ok(Some(h))
        }
    }

    /// Number of state keys currently stored.
    pub fn state_len(&self) -> usize {
        self.state.read().len()
    }

    // ========================================================================
    // Metadata Helpers
    // ========================================================================

    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.metadata.read().get(key).cloned())
    }

    pub fn get_metadata_str(&self, key: &str) -> Result<Option<String>> {
        let bytes_opt = self.get_metadata(key)?;
        Ok(bytes_opt.and_then(|b| String::from_utf8(b).ok()))
    }

    pub fn put_metadata(&self, key: &str, value: &[u8]) {
        self.metadata
            .write()
            .insert(key.to_string(), value.to_vec());
    }

    pub fn put_metadata_str(&self, key: &str, value: &str) -> Result<()> {
        self.put_metadata(key, value.as_bytes());
        Ok(())
    }

    // ========================================================================
    // Block Operations
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
        let bytes = header.try_encode()?;
        self.store_block_header_bytes(height, &bytes)
    }

    pub fn store_block_header_bytes(&self, height: u64, header_bytes: &[u8]) -> Result<()> {
        self.block_headers
            .write()
            .insert(height, header_bytes.to_vec());
        if height > self.height.load(Ordering::SeqCst) {
            self.height.store(height, Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn get_block_header(&self, height: u64) -> Result<Option<BlockHeader>> {
        let guard = self.block_headers.read();
        guard
            .get(&height)
            .map(|bytes| decode_canonical::<BlockHeader>(bytes))
            .transpose()
    }

    pub fn get_block_header_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.block_headers.read().get(&height).cloned())
    }

    pub fn store_block_body(&self, height: u64, body: &BlockBody) -> Result<()> {
        let bytes = body.try_encode()?;
        self.store_block_body_bytes(height, &bytes)
    }

    pub fn store_block_body_bytes(&self, height: u64, body_bytes: &[u8]) -> Result<()> {
        self.block_bodies
            .write()
            .insert(height, body_bytes.to_vec());
        Ok(())
    }

    pub fn get_block_body(&self, height: u64) -> Result<Option<BlockBody>> {
        let guard = self.block_bodies.read();
        guard
            .get(&height)
            .map(|bytes| decode_canonical::<BlockBody>(bytes))
            .transpose()
    }

    pub fn get_block_body_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.block_bodies.read().get(&height).cloned())
    }

    pub fn block_exists(&self, height: u64) -> Result<bool> {
        Ok(self.block_headers.read().contains_key(&height))
    }

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

        self.block_headers.write().insert(height, header_bytes);
        self.block_bodies.write().insert(height, body_bytes);
        self.block_hash_index.write().insert(block_hash, height);
        self.canonical_chain.write().insert(height, block_hash);

        // Index transactions and receipts
        let mut tx_guard = self.transactions.write();
        let mut idx_guard = self.tx_block_index.write();
        let mut receipt_guard = self.receipts.write();
        for tx in &body.transactions {
            let tx_hash = tx.try_hash()?;
            let tx_bytes = tx.try_encode()?;
            tx_guard.insert(tx_hash, tx_bytes);
            idx_guard.insert(tx_hash, height);
        }
        for receipt in &body.receipts {
            let receipt_bytes = receipt.try_encode()?;
            receipt_guard.insert(receipt.tx_hash, receipt_bytes);
        }

        if height > self.height.load(Ordering::SeqCst) {
            self.height.store(height, Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn atomic_block_commit(
        &self,
        height: u64,
        header_bytes: Vec<u8>,
        body_bytes: Vec<u8>,
    ) -> Result<()> {
        self.block_headers.write().insert(height, header_bytes);
        self.block_bodies.write().insert(height, body_bytes);
        if height > self.height.load(Ordering::SeqCst) {
            self.height.store(height, Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn atomic_block_commit_typed(
        &self,
        height: u64,
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<()> {
        let header_bytes = header.try_encode()?;
        let body_bytes = body.try_encode()?;
        self.atomic_block_commit(height, header_bytes, body_bytes)
    }

    pub fn get_block_by_height(&self, height: u64) -> Result<Option<(BlockHeader, BlockBody)>> {
        let header = self.get_block_header(height)?;
        let body = self.get_block_body(height)?;
        match (header, body) {
            (Some(h), Some(b)) => Ok(Some((h, b))),
            _ => Ok(None),
        }
    }

    pub fn get_block_by_hash(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<(BlockHeader, BlockBody)>> {
        if let Some(height) = self.get_block_height_by_hash(block_hash)? {
            if self.is_canonical_block(height, block_hash)? {
                return self.get_block_by_height(height);
            }
        }
        self.get_fork_block(block_hash)
    }

    pub fn get_block_hash_by_height(&self, height: u64) -> Result<Option<[u8; 32]>> {
        Ok(self.canonical_chain.read().get(&height).copied())
    }

    pub fn get_block_height_by_hash(&self, block_hash: [u8; 32]) -> Result<Option<u64>> {
        Ok(self.block_hash_index.read().get(&block_hash).copied())
    }

    pub fn is_canonical_block(&self, height: u64, block_hash: [u8; 32]) -> Result<bool> {
        Ok(self.canonical_chain.read().get(&height) == Some(&block_hash))
    }

    pub fn store_fork_block(
        &self,
        block_hash: [u8; 32],
        header: &BlockHeader,
        body: &BlockBody,
    ) -> Result<()> {
        let header_bytes = header.try_encode()?;
        let body_bytes = body.try_encode()?;
        let data = bincode::serialize(&(header_bytes, body_bytes))?;
        self.fork_blocks.write().insert(block_hash, data);
        Ok(())
    }

    pub fn store_fork_block_typed(&self, block: &sxiaum_block::Block) -> Result<[u8; 32]> {
        let block_hash = block.try_hash()?;
        self.store_fork_block(block_hash, &block.header, &block.body)?;
        Ok(block_hash)
    }

    pub fn get_fork_block(&self, block_hash: [u8; 32]) -> Result<Option<(BlockHeader, BlockBody)>> {
        let guard = self.fork_blocks.read();
        guard
            .get(&block_hash)
            .map(|bytes| {
                if let Ok((hb, bb)) = bincode::deserialize::<(Vec<u8>, Vec<u8>)>(bytes) {
                    let header = BlockHeader::decode(&hb).or_else(|_| bincode::deserialize(&hb))?;
                    let body = BlockBody::decode(&bb).or_else(|_| bincode::deserialize(&bb))?;
                    Ok((header, body))
                } else {
                    bincode::deserialize(bytes).map_err(Into::into)
                }
            })
            .transpose()
    }

    pub fn get_fork_block_typed(
        &self,
        block_hash: [u8; 32],
    ) -> Result<Option<sxiaum_block::Block>> {
        self.get_fork_block(block_hash)?
            .map(|(header, body)| Ok(sxiaum_block::Block::new(header, body)))
            .transpose()
    }

    // ========================================================================
    // Reorg & Rollback with Finality Protection
    // ========================================================================

    pub fn revert_block(&self, height: u64) -> Result<()> {
        // Enforce finality protection
        if let Some(finalized) = self.get_finalized_height()? {
            if height <= finalized {
                return Err(StorageError::FinalizedBlockReversion {
                    height,
                    finalized_height: finalized,
                }
                .into());
            }
        }

        self.block_headers.write().remove(&height);
        let body_bytes = self.block_bodies.write().remove(&height);
        self.logs_bloom.write().remove(&height);
        self.zk_proofs.write().remove(&height);
        self.validator_sets.write().remove(&height);

        if let Some(hash) = self.canonical_chain.write().remove(&height) {
            self.block_hash_index.write().remove(&hash);
        }

        if let Some(body_data) = body_bytes {
            // FIX (SEC): decode via the canonical path with legacy-bincode
            // fallback. Blocks are persisted with `try_encode()`, so decoding
            // only through plain bincode silently skipped tx/receipt index
            // cleanup whenever the encodings differ.
            if let Ok(body) = decode_canonical::<BlockBody>(&body_data) {
                let mut tx_idx = self.tx_block_index.write();
                let mut receipts_guard = self.receipts.write();
                for tx in body.transactions {
                    if let Ok(hash) = tx.try_hash() {
                        tx_idx.remove(&hash);
                    }
                }
                for receipt in body.receipts {
                    receipts_guard.remove(&receipt.tx_hash);
                }
            }
        }

        let current = self.height.load(Ordering::SeqCst);
        if current >= height {
            self.height
                .store(height.saturating_sub(1), Ordering::SeqCst);
        }
        Ok(())
    }

    pub fn revert_blocks_to(&self, target_height: u64) -> Result<usize> {
        let current = self.latest_block_height()?;
        if target_height >= current {
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

        let count = (current - target_height) as usize;
        for h in (target_height + 1..=current).rev() {
            self.revert_block(h)?;
        }
        Ok(count)
    }

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

        let mut headers = self.block_headers.write();
        let mut bodies = self.block_bodies.write();
        let mut canonical = self.canonical_chain.write();
        let mut hash_index = self.block_hash_index.write();
        // FIX: prune auxiliary per-height tables too, matching StorageEngine
        // parity so stale blooms / zk proofs / validator snapshots cannot
        // outlive their blocks on the in-memory backend. Heights are gathered
        // from every per-height table so orphaned rows (e.g. a zk proof
        // stored without its block header) are swept as well.
        let mut bloom = self.logs_bloom.write();
        let mut zk = self.zk_proofs.write();
        let mut val_sets = self.validator_sets.write();

        let mut heights: Vec<u64> = headers.keys().copied().collect();
        heights.extend(bloom.keys().copied());
        heights.extend(zk.keys().copied());
        heights.extend(val_sets.keys().copied());
        heights.retain(|&h| h < height);
        heights.sort_unstable();
        heights.dedup();

        let mut pruned = 0usize;
        for h in heights {
            headers.remove(&h);
            bodies.remove(&h);
            if let Some(hash) = canonical.remove(&h) {
                hash_index.remove(&hash);
            }
            bloom.remove(&h);
            zk.remove(&h);
            val_sets.remove(&h);
            pruned += 1;
        }

        Ok(pruned)
    }

    // ========================================================================
    // Transaction & Receipt Operations
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
        let bytes = tx.try_encode()?;
        self.store_transaction_bytes(tx_hash, &bytes)
    }

    pub fn store_transaction_auto(&self, tx: &Transaction) -> Result<[u8; 32]> {
        let tx_hash = tx.try_hash()?;
        self.store_transaction(tx_hash, tx)?;
        Ok(tx_hash)
    }

    pub fn store_transaction_bytes(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        self.transactions.write().insert(tx_hash, tx_bytes.to_vec());
        Ok(())
    }

    pub fn get_transaction(&self, tx_hash: [u8; 32]) -> Result<Option<Transaction>> {
        let guard = self.transactions.read();
        guard
            .get(&tx_hash)
            .map(|bytes| decode_canonical::<Transaction>(bytes))
            .transpose()
    }

    pub fn get_transaction_bytes(&self, tx_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.transactions.read().get(&tx_hash).cloned())
    }

    pub fn transaction_exists(&self, tx_hash: [u8; 32]) -> Result<bool> {
        Ok(self.transactions.read().contains_key(&tx_hash))
    }

    pub fn store_receipt(&self, tx_hash: [u8; 32], receipt: &Receipt) -> Result<()> {
        if tx_hash != receipt.tx_hash {
            bail!(
                "Receipt transaction hash mismatch: provided {:?}, receipt.tx_hash {:?}",
                tx_hash,
                receipt.tx_hash
            );
        }
        let bytes = receipt.try_encode()?;
        self.store_receipt_bytes(tx_hash, &bytes)
    }

    pub fn store_receipt_auto(&self, receipt: &Receipt) -> Result<[u8; 32]> {
        self.store_receipt(receipt.tx_hash, receipt)?;
        Ok(receipt.tx_hash)
    }

    pub fn store_receipt_bytes(&self, tx_hash: [u8; 32], receipt_bytes: &[u8]) -> Result<()> {
        self.receipts
            .write()
            .insert(tx_hash, receipt_bytes.to_vec());
        Ok(())
    }

    pub fn get_receipt(&self, tx_hash: [u8; 32]) -> Result<Option<Receipt>> {
        let guard = self.receipts.read();
        guard
            .get(&tx_hash)
            .map(|bytes| decode_canonical::<Receipt>(bytes))
            .transpose()
    }

    pub fn get_receipt_bytes(&self, tx_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.receipts.read().get(&tx_hash).cloned())
    }

    pub fn store_block_transactions(
        &self,
        height: u64,
        transactions: &[([u8; 32], Vec<u8>)],
    ) -> Result<()> {
        let mut tx_table = self.transactions.write();
        let mut index_table = self.tx_block_index.write();
        for (hash, bytes) in transactions {
            tx_table.insert(*hash, bytes.clone());
            index_table.insert(*hash, height);
        }
        Ok(())
    }

    pub fn store_block_transactions_typed(
        &self,
        height: u64,
        transactions: &[Transaction],
    ) -> Result<()> {
        let mut serialized = Vec::with_capacity(transactions.len());
        for tx in transactions {
            let hash = tx.try_hash()?;
            let bytes = tx.try_encode()?;
            serialized.push((hash, bytes));
        }
        self.store_block_transactions(height, &serialized)
    }

    pub fn get_transaction_block_height(&self, tx_hash: [u8; 32]) -> Result<Option<u64>> {
        Ok(self.tx_block_index.read().get(&tx_hash).copied())
    }

    // ========================================================================
    // Account Operations
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
        let bytes = account.try_encode()?;
        self.accounts.write().insert(address, bytes);
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
        let guard = self.accounts.read();
        let Some(bytes) = guard.get(&address) else {
            return Ok(None);
        };
        let account: Account = decode_canonical(bytes)?;
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
        Ok(self.accounts.write().remove(&address).is_some())
    }

    pub fn delete_account_by_address(&self, address: &sxiaum_types::Address) -> Result<bool> {
        self.delete_account(address.0)
    }

    // ========================================================================
    // State Operations
    // ========================================================================

    pub fn state_get_bytes(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.state.read().get(key).cloned())
    }

    pub fn state_put_bytes(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.state.write().insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    // ========================================================================
    // Mempool Operations
    // ========================================================================

    pub fn mempool_insert(&self, tx_hash: [u8; 32], tx_bytes: &[u8]) -> Result<()> {
        self.mempool.write().insert(tx_hash, tx_bytes.to_vec());
        Ok(())
    }

    pub fn mempool_remove(&self, tx_hash: [u8; 32]) -> Result<bool> {
        Ok(self.mempool.write().remove(&tx_hash).is_some())
    }

    pub fn mempool_clear(&self) -> Result<()> {
        self.mempool.write().clear();
        Ok(())
    }

    pub fn mempool_iterate(&self) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        Ok(self
            .mempool
            .read()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect())
    }

    pub fn mempool_contains(&self, tx_hash: [u8; 32]) -> Result<bool> {
        Ok(self.mempool.read().contains_key(&tx_hash))
    }

    pub fn mempool_iterate_typed(&self) -> Result<Vec<([u8; 32], Transaction)>> {
        let mem = self.mempool.read();
        Ok(mem
            .iter()
            .filter_map(
                |(hash, bytes)| match decode_canonical::<Transaction>(bytes) {
                    Ok(tx) => Some((*hash, tx)),
                    Err(_) => None,
                },
            )
            .collect())
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

        let mut mem = self.mempool.write();
        for hash in &hashes_to_remove {
            mem.remove(hash);
        }
        Ok(hashes_to_remove)
    }

    // ========================================================================
    // Peer Ban Management
    // ========================================================================

    pub fn store_peer_ban(&self, peer_id: &str, expiry_unix: u64, reason: &str) -> Result<()> {
        self.peer_bans
            .write()
            .insert(peer_id.to_string(), (expiry_unix, reason.to_string()));
        Ok(())
    }

    pub fn get_peer_ban(&self, peer_id: &str) -> Result<Option<(u64, String)>> {
        Ok(self.peer_bans.read().get(peer_id).cloned())
    }

    pub fn remove_peer_ban(&self, peer_id: &str) -> Result<bool> {
        Ok(self.peer_bans.write().remove(peer_id).is_some())
    }

    pub fn list_peer_bans(&self) -> Result<Vec<(String, u64, String)>> {
        Ok(self
            .peer_bans
            .read()
            .iter()
            .map(|(k, (exp, r))| (k.clone(), *exp, r.clone()))
            .collect())
    }

    // ========================================================================
    // Validator & Staking Operations
    // ========================================================================

    pub fn store_validator(&self, address: [u8; 32], validator: &Validator) -> Result<()> {
        if address != validator.address.0 {
            bail!(
                "Validator address mismatch: provided {:?}, validator.address {:?}",
                address,
                validator.address.0
            );
        }
        let bytes = validator.try_encode()?;
        self.store_validator_bytes(address, &bytes)
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
        self.validators
            .write()
            .insert(address, validator_bytes.to_vec());
        Ok(())
    }

    pub fn get_validator(&self, address: [u8; 32]) -> Result<Option<Validator>> {
        let guard = self.validators.read();
        guard
            .get(&address)
            .map(|bytes| decode_canonical::<Validator>(bytes))
            .transpose()
    }

    pub fn get_validator_by_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<Validator>> {
        self.get_validator(address.0)
    }

    pub fn get_validator_bytes(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.validators.read().get(&address).cloned())
    }

    pub fn delete_validator(&self, address: [u8; 32]) -> Result<bool> {
        Ok(self.validators.write().remove(&address).is_some())
    }

    pub fn delete_validator_by_address(&self, address: &sxiaum_types::Address) -> Result<bool> {
        self.delete_validator(address.0)
    }

    pub fn get_all_validators(&self) -> Result<Vec<Validator>> {
        let guard = self.validators.read();
        let mut list = Vec::new();
        for bytes in guard.values() {
            list.push(decode_canonical::<Validator>(bytes)?);
        }
        Ok(list)
    }

    pub fn store_staking_balance(&self, address: [u8; 32], balance: U256) -> Result<()> {
        let mut bytes = [0u8; 32];
        balance.to_big_endian(&mut bytes);
        self.store_staking_balance_bytes(address, &bytes)
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
        self.staking.write().insert(address, balance_bytes.to_vec());
        Ok(())
    }

    pub fn get_staking_balance(&self, address: [u8; 32]) -> Result<Option<U256>> {
        Ok(self.staking.read().get(&address).and_then(|bytes| {
            if bytes.len() == 32 {
                Some(U256::from_big_endian(bytes))
            } else {
                None
            }
        }))
    }

    pub fn get_staking_balance_for_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<U256>> {
        self.get_staking_balance(address.0)
    }

    pub fn get_staking_balance_bytes(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.staking.read().get(&address).cloned())
    }

    pub fn store_validator_set(&self, height: u64, validators: &[Validator]) -> Result<()> {
        let bytes = bincode::serialize(validators)?;
        self.store_validator_set_bytes(height, &bytes)
    }

    pub fn store_validator_set_bytes(&self, height: u64, set_bytes: &[u8]) -> Result<()> {
        self.validator_sets
            .write()
            .insert(height, set_bytes.to_vec());
        Ok(())
    }

    pub fn load_validator_set(&self, height: u64) -> Result<Option<Vec<Validator>>> {
        let guard = self.validator_sets.read();
        guard
            .get(&height)
            .map(|bytes| bincode::deserialize(bytes).map_err(Into::into))
            .transpose()
    }

    pub fn load_validator_set_bytes(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.validator_sets.read().get(&height).cloned())
    }

    pub fn store_slashing_record(&self, address: [u8; 32], record: &[u8]) -> Result<()> {
        self.slashing_records
            .write()
            .insert(address, record.to_vec());
        Ok(())
    }

    pub fn store_slashing_record_for_address(
        &self,
        address: &sxiaum_types::Address,
        record: &[u8],
    ) -> Result<()> {
        self.store_slashing_record(address.0, record)
    }

    pub fn get_slashing_record(&self, address: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.slashing_records.read().get(&address).cloned())
    }

    pub fn get_slashing_record_for_address(
        &self,
        address: &sxiaum_types::Address,
    ) -> Result<Option<Vec<u8>>> {
        self.get_slashing_record(address.0)
    }

    // ========================================================================
    // ZK Proof Storage
    // ========================================================================

    pub fn store_zk_proof(&self, height: u64, proof_bytes: Vec<u8>) -> Result<()> {
        self.zk_proofs.write().insert(height, proof_bytes);
        Ok(())
    }

    pub fn get_zk_proof(&self, height: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.zk_proofs.read().get(&height).cloned())
    }

    pub fn zk_proof_exists(&self, height: u64) -> Result<bool> {
        Ok(self.zk_proofs.read().contains_key(&height))
    }

    pub fn store_verkle_node_bytes(&self, node_hash: [u8; 32], node_bytes: &[u8]) -> Result<()> {
        self.verkle.write().insert(node_hash, node_bytes.to_vec());
        Ok(())
    }

    // ========================================================================
    // Atomic Commit With Rollback Correctness
    // ========================================================================

    /// Atomically commit state changes and generate a deterministic undo batch.
    /// Captures the true initial state for each touched key before any mutation,
    /// correctly handling intra-batch duplicate updates.
    pub fn atomic_state_commit_with_rollback(&self, changes: StateUpdates) -> Result<StateUpdates> {
        let mut map = self.state.write();
        let mut seen = HashSet::with_capacity(changes.len());
        let mut rollback = Vec::with_capacity(changes.len());

        // 1. Capture snapshot of original pre-state for unique keys
        for (key, _) in &changes {
            if seen.insert(key.clone()) {
                let previous = map.get(key).cloned();
                rollback.push((key.clone(), previous));
            }
        }

        // 2. Apply updates in order
        for (key, value) in changes {
            match value {
                Some(v) => {
                    map.insert(key, v);
                }
                None => {
                    map.remove(&key);
                }
            }
        }

        Ok(rollback)
    }

    // ========================================================================
    // Integrity & Chain Invariants
    // ========================================================================

    pub fn check_integrity(&self) -> Result<bool> {
        self.check_chain_invariants()
    }

    pub fn check_chain_invariants(&self) -> Result<bool> {
        let canonical = self.canonical_chain.read();
        let hash_index = self.block_hash_index.read();
        let headers = self.block_headers.read();
        let bodies = self.block_bodies.read();

        let rows = canonical
            .iter()
            .map(|(&height, &hash)| -> Result<CanonicalRow> {
                let header_bytes = headers.get(&height).cloned().ok_or_else(|| {
                    StorageError::StorageCorruption {
                        reason: format!("Canonical block at height {} missing header", height),
                    }
                })?;
                let body_bytes = bodies.get(&height).cloned().ok_or_else(|| {
                    StorageError::StorageCorruption {
                        reason: format!("Canonical block at height {} missing body", height),
                    }
                })?;
                Ok(CanonicalRow {
                    height,
                    hash,
                    header_bytes,
                    body_bytes,
                    indexed_height: hash_index.get(&hash).copied(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        verify_canonical_sequence(rows)?;
        Ok(true)
    }
}

impl DatabaseBackend for MemoryDatabaseBackend {
    fn latest_block_height(&self) -> Result<u64> {
        Ok(self.height.load(Ordering::SeqCst))
    }

    fn state_get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        Ok(self.state.read().get(&key).cloned())
    }

    fn state_put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.state.write().insert(key, value);
        Ok(())
    }

    fn state_delete(&self, key: Vec<u8>) -> Result<()> {
        self.state.write().remove(&key);
        Ok(())
    }

    fn atomic_state_commit(&self, changes: StateUpdates) -> Result<()> {
        let mut map = self.state.write();
        for (key, value) in changes {
            match value {
                Some(v) => {
                    map.insert(key, v);
                }
                None => {
                    map.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn atomic_state_commit_async(&self, changes: StateUpdates) -> Result<()> {
        self.atomic_state_commit(changes)
    }

    fn state_snapshot_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        let map = self.state.read();
        Ok(keys.iter().map(|k| map.get(k).cloned()).collect())
    }

    fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.state_snapshot_reads(keys)
    }

    fn state_prefix_scan(&self, prefix: Vec<u8>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let map = self.state.read();
        if prefix.is_empty() {
            return Ok(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        }
        Ok(map
            .range(prefix.clone()..)
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn state_range_scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let map = self.state.read();
        let start_bound = Bound::Included(start.to_vec());
        let end_bound = match end {
            Some(e) => Bound::Excluded(e.to_vec()),
            None => Bound::Unbounded,
        };

        Ok(map
            .range((start_bound, end_bound))
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }

    fn flush_to_disk(&self) -> Result<()> {
        Ok(())
    }
    fn load_verkle_node(&self, node_hash: [u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.verkle.read().get(&node_hash).cloned())
    }

    fn store_verkle_node(&self, node_hash: [u8; 32], node_bytes: Vec<u8>) -> Result<()> {
        self.verkle.write().insert(node_hash, node_bytes);
        Ok(())
    }

    fn batch_store_verkle_nodes(&self, nodes: &[([u8; 32], Vec<u8>)]) -> Result<()> {
        let mut map = self.verkle.write();
        for (hash, bytes) in nodes {
            map.insert(*hash, bytes.clone());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_and_prefix_scan() {
        let db = MemoryDatabaseBackend::new();
        db.state_put(b"account:a".to_vec(), b"1".to_vec()).unwrap();
        db.state_put(b"account:b".to_vec(), b"2".to_vec()).unwrap();
        db.state_put(b"other".to_vec(), b"3".to_vec()).unwrap();

        assert_eq!(
            db.state_get(b"account:a".to_vec()).unwrap().as_deref(),
            Some(b"1".as_slice())
        );
        let scanned = db.state_prefix_scan(b"account:".to_vec()).unwrap();
        assert_eq!(scanned.len(), 2);
    }

    #[test]
    fn state_range_scan_with_bounds() {
        let db = MemoryDatabaseBackend::new();
        db.state_put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
        db.state_put(b"k2".to_vec(), b"v2".to_vec()).unwrap();
        db.state_put(b"k3".to_vec(), b"v3".to_vec()).unwrap();
        db.state_put(b"k4".to_vec(), b"v4".to_vec()).unwrap();

        let range = db.state_range_scan(b"k2", Some(b"k4"), 10).unwrap();
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].0, b"k2");
        assert_eq!(range[1].0, b"k3");
    }

    #[test]
    fn atomic_commit_and_rollback() {
        let db = MemoryDatabaseBackend::new();
        db.state_put(b"k1".to_vec(), b"v1".to_vec()).unwrap();
        let undo = db
            .atomic_state_commit_with_rollback(vec![
                (b"k1".to_vec(), None),
                (b"k2".to_vec(), Some(b"v2".to_vec())),
            ])
            .unwrap();
        assert!(db.state_get(b"k1".to_vec()).unwrap().is_none());
        assert_eq!(
            db.state_get(b"k2".to_vec()).unwrap().as_deref(),
            Some(b"v2".as_slice())
        );

        db.rollback_state_batch(undo).unwrap();
        assert_eq!(
            db.state_get(b"k1".to_vec()).unwrap().as_deref(),
            Some(b"v1".as_slice())
        );
        assert!(db.state_get(b"k2".to_vec()).unwrap().is_none());
    }

    #[test]
    fn state_rollback_with_intra_batch_duplicate_keys() {
        let db = MemoryDatabaseBackend::new();
        db.state_put(b"key_dup".to_vec(), b"initial_v0".to_vec())
            .unwrap();

        // Batch modifies the same key twice: key_dup -> v1, then key_dup -> v2
        let undo = db
            .atomic_state_commit_with_rollback(vec![
                (b"key_dup".to_vec(), Some(b"v1".to_vec())),
                (b"key_dup".to_vec(), Some(b"v2".to_vec())),
            ])
            .unwrap();

        assert_eq!(
            db.state_get(b"key_dup".to_vec()).unwrap().as_deref(),
            Some(b"v2".as_slice())
        );

        db.rollback_state_batch(undo).unwrap();
        assert_eq!(
            db.state_get(b"key_dup".to_vec()).unwrap().as_deref(),
            Some(b"initial_v0".as_slice())
        );
    }

    #[test]
    fn canonical_blocks_reorg_and_hash_index() {
        let db = MemoryDatabaseBackend::new();
        let h1 = BlockHeader::new([0x11; 32], 1);
        let b1 = BlockBody::new();
        let h1_hash = h1.try_hash().unwrap();

        db.store_canonical_block(1, h1_hash, &h1, &b1).unwrap();
        assert_eq!(db.latest_block_height().unwrap(), 1);
        assert_eq!(db.get_block_hash_by_height(1).unwrap(), Some(h1_hash));
        assert_eq!(db.get_block_height_by_hash(h1_hash).unwrap(), Some(1));
        assert!(db.is_canonical_block(1, h1_hash).unwrap());

        // Revert block 1
        db.revert_block(1).unwrap();
        assert_eq!(db.latest_block_height().unwrap(), 0);
        assert_eq!(db.get_block_hash_by_height(1).unwrap(), None);
        assert_eq!(db.get_block_height_by_hash(h1_hash).unwrap(), None);
    }

    #[test]
    fn finality_protection_prevents_rollback() {
        let db = MemoryDatabaseBackend::new();
        let h1 = BlockHeader::new([0x11; 32], 1);
        let b1 = BlockBody::new();
        let h1_hash = h1.try_hash().unwrap();

        db.store_canonical_block(1, h1_hash, &h1, &b1).unwrap();
        db.set_finalized_height(1, h1_hash).unwrap();

        let err = db.revert_block(1).unwrap_err();
        assert!(err.to_string().contains("finalized block"));

        let err2 = db.revert_blocks_to(0).unwrap_err();
        assert!(err2.to_string().contains("finalized block"));
    }

    #[test]
    fn peer_bans_operations() {
        let db = MemoryDatabaseBackend::new();
        db.store_peer_ban("peer-123", 1999999999, "malformed handshake")
            .unwrap();
        assert_eq!(
            db.get_peer_ban("peer-123").unwrap(),
            Some((1999999999, "malformed handshake".to_string()))
        );
        assert!(db.remove_peer_ban("peer-123").unwrap());
        assert_eq!(db.get_peer_ban("peer-123").unwrap(), None);
    }

    /// REGRESSION: the in-memory backend must prune the same auxiliary
    /// per-height tables as StorageEngine (logs bloom, zk proofs, validator
    /// sets), and must never delete the finalized block itself.
    #[test]
    fn prune_blocks_before_clears_auxiliary_tables_and_respects_finality() {
        let db = MemoryDatabaseBackend::new();
        let h1 = BlockHeader::new([0x11; 32], 1);
        let h1_hash = h1.try_hash().unwrap();
        db.store_canonical_block(1, h1_hash, &h1, &BlockBody::new())
            .unwrap();

        db.store_zk_proof(0, vec![0xAA; 16]).unwrap();
        db.store_validator_set_bytes(0, b"validators-at-0").unwrap();

        // Without finality info, prune targets above genesis are rejected.
        assert!(db.prune_blocks_before(2).is_err());

        // Pruning before height 1 removes height-0 aux rows (no block header
        // exists at 0, but orphaned aux rows must still be swept).
        assert_eq!(db.prune_blocks_before(1).unwrap(), 1);
        assert!(db.get_zk_proof(0).unwrap().is_none());
        assert!(db.load_validator_set_bytes(0).unwrap().is_none());
        assert!(!db.block_exists(0).unwrap());
        assert!(db.block_exists(1).unwrap());

        // With a finalized block at height 1, target 2 (== finalized + 1)
        // must be rejected so the finalized block cannot be deleted.
        db.set_finalized_height(1, h1_hash).unwrap();
        let err = db.prune_blocks_before(2).unwrap_err();
        assert!(
            err.to_string().contains("finalized"),
            "unexpected error: {err}"
        );
    }
}
