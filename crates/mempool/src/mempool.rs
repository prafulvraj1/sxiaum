use crate::error::MempoolError;
use crate::ordering::{CommitRevealPool, CommitTransaction, RevealTransaction};
use crate::pool::TransactionPool;
use crate::validation::{TransactionValidator, TxValidationConfig, MAX_TX_SIZE};
use anyhow::Result;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use primitive_types::U256;
use rand::{rngs::OsRng, RngCore};
use std::collections::{HashMap, HashSet, VecDeque};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sxiaum_block::Block;
use sxiaum_execution::TransactionSource;
use sxiaum_networking::{CommitPoolSink, GossipMessage, RevealPoolSink, TransactionPoolSink};
use sxiaum_state::StateDb;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Account, Address, Canonical, Hash, ReservationId, Transaction};
use tracing::info;

#[derive(Clone, Debug)]
pub struct MempoolConfig {
    pub max_pending_transactions: usize,
    /// How long (seconds) a transaction may stay in the pool before expiry.
    pub transaction_ttl_secs: u64,
    /// Minimum interval (seconds) between periodic cleanup sweeps.
    pub cleanup_interval_secs: u64,
    /// Maximum pending transactions per sender address (spam guard).
    pub max_transactions_per_account: usize,
    /// Maximum transactions accepted from a single peer per rate-limit window.
    pub max_transactions_per_peer_per_window: usize,
    /// Duration (seconds) of the per-peer rate-limit sliding window.
    pub peer_rate_limit_window_secs: u64,
    /// Maximum admitted transactions per sender in one sender token-bucket window.
    pub max_transactions_per_sender_per_window: usize,
    /// Duration (seconds) of the sender token-bucket window.
    pub sender_rate_limit_window_secs: u64,
    /// Commit-reveal economics configuration.
    pub commit_reveal: crate::ordering::CommitRevealConfig,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_pending_transactions: crate::MAX_MEMPOOL_SIZE,
            transaction_ttl_secs: 60 * 60,
            cleanup_interval_secs: 30,
            max_transactions_per_account: 64,
            max_transactions_per_peer_per_window: 128,
            peer_rate_limit_window_secs: 1,
            max_transactions_per_sender_per_window: 64,
            sender_rate_limit_window_secs: 1,
            commit_reveal: crate::ordering::CommitRevealConfig {
                commit_fee: 10_000_000_000_000_000,
                reveal_window_blocks: 5,
                commit_expiry_blocks: 20,
                no_show_slash: 10,
                max_commits_per_sender: 16,
            },
        }
    }
}

#[derive(Clone, Debug)]
struct TokenBucket {
    capacity: usize,
    tokens: f64,
    refill_per_second: f64,
    last_refill_at: u64,
}

impl TokenBucket {
    fn new(capacity: usize, window_secs: u64, now: u64) -> Self {
        let window_secs = window_secs.max(1);
        Self {
            capacity,
            tokens: capacity as f64,
            refill_per_second: capacity as f64 / window_secs as f64,
            last_refill_at: now,
        }
    }

    fn try_consume(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last_refill_at);
        if elapsed > 0 {
            let refilled = elapsed as f64 * self.refill_per_second;
            self.tokens = (self.tokens + refilled).min(self.capacity as f64);
            self.last_refill_at = now;
        }

        if self.tokens < 1.0 {
            return false;
        }

        self.tokens -= 1.0;
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct MempoolMetrics {
    /// Current number of transactions in the pool.
    pub mempool_size: usize,
    /// Transactions received per second (rolling 1-second window).
    pub transaction_arrival_rate: f64,
    /// Cumulative count of rejected transactions since startup.
    pub rejected_transactions: u64,
    /// Mean gas price across all pending transactions.
    pub average_gas_price: U256,
}

pub struct Mempool {
    pool: RwLock<TransactionPool>,
    validator: TransactionValidator,
    config: MempoolConfig,
    /// Optional durable storage backend for crash recovery.
    storage: Option<Arc<StorageEngine>>,
    /// Unix timestamp of the last expired-transaction sweep.
    last_cleanup_at: Mutex<u64>,
    /// Hashes received from peers (to suppress re-broadcast) and already
    /// broadcast by us; plus per-peer rate-limit counters.
    gossip_tracker: Mutex<GossipTracker>,
    /// In-process metrics state.
    metrics_tracker: Mutex<MetricsTracker>,
    /// MEV-protection commit-reveal pool. Present only when storage is available.
    commit_reveal: Option<Mutex<CommitRevealPool>>,
}

/// Tracks gossip state to prevent broadcast loops and enforce peer rate limits.
struct GossipTracker {
    /// Hashes of transactions we received from any peer (bounded LRU).
    received_from_peers: LruCache<Hash, ()>,
    /// Hashes of transactions we have already broadcast ourselves (bounded LRU).
    broadcasted: LruCache<Hash, ()>,
    /// Commit IDs we received from any peer (bounded LRU).
    received_commits: LruCache<[u8; 32], ()>,
    /// Commit IDs we have already broadcast ourselves (bounded LRU).
    broadcasted_commits: LruCache<[u8; 32], ()>,
    /// Reveal commit IDs we received from any peer (bounded LRU).
    received_reveals: LruCache<[u8; 32], ()>,
    /// Reveal commit IDs we have already broadcast ourselves (bounded LRU).
    broadcasted_reveals: LruCache<[u8; 32], ()>,
    /// peer_id -> token bucket
    peer_buckets: HashMap<String, TokenBucket>,
    /// sender address -> token bucket
    sender_buckets: HashMap<[u8; 32], TokenBucket>,
}

impl GossipTracker {
    fn new(cache_size: usize) -> Self {
        let size = NonZeroUsize::new(cache_size)
            .or_else(|| NonZeroUsize::new(50_000))
            .unwrap_or(NonZeroUsize::MIN);
        Self {
            received_from_peers: LruCache::new(size),
            broadcasted: LruCache::new(size),
            received_commits: LruCache::new(size),
            broadcasted_commits: LruCache::new(size),
            received_reveals: LruCache::new(size),
            broadcasted_reveals: LruCache::new(size),
            peer_buckets: HashMap::new(),
            sender_buckets: HashMap::new(),
        }
    }

    fn prune_idle_buckets(&mut self, now: u64) {
        self.peer_buckets
            .retain(|_, b| now.saturating_sub(b.last_refill_at) < 300);
        self.sender_buckets
            .retain(|_, b| now.saturating_sub(b.last_refill_at) < 300);

        const MAX_PEER_BUCKETS: usize = 2000;
        const MAX_SENDER_BUCKETS: usize = 10_000;
        if self.peer_buckets.len() > MAX_PEER_BUCKETS {
            let to_remove = self.peer_buckets.len().saturating_sub(MAX_PEER_BUCKETS);
            let keys: Vec<String> = self.peer_buckets.keys().take(to_remove).cloned().collect();
            for k in keys {
                self.peer_buckets.remove(&k);
            }
        }
        if self.sender_buckets.len() > MAX_SENDER_BUCKETS {
            let to_remove = self.sender_buckets.len().saturating_sub(MAX_SENDER_BUCKETS);
            let keys: Vec<[u8; 32]> = self
                .sender_buckets
                .keys()
                .take(to_remove)
                .copied()
                .collect();
            for k in keys {
                self.sender_buckets.remove(&k);
            }
        }
    }
}

/// Rolling counters for the public metrics snapshot.
#[derive(Default)]
struct MetricsTracker {
    rejected_transactions: u64,
    /// Timestamps (Unix secs) of recent arrivals for rate calculation.
    arrival_timestamps: VecDeque<u64>,
}

impl Mempool {
    pub fn new(config: MempoolConfig, state: Arc<StateDb>) -> Self {
        Self {
            pool: RwLock::new(TransactionPool::new()),
            validator: TransactionValidator::new(state, TxValidationConfig::default()),
            config,
            storage: None,
            last_cleanup_at: Mutex::new(unix_timestamp()),
            gossip_tracker: Mutex::new(GossipTracker::new(50_000)),
            metrics_tracker: Mutex::new(MetricsTracker::default()),
            commit_reveal: None,
        }
    }

    /// Construct a `Mempool` backed by durable storage.
    pub fn with_storage(
        config: MempoolConfig,
        state: Arc<StateDb>,
        storage: Arc<StorageEngine>,
    ) -> Self {
        let cr_pool = CommitRevealPool::new(config.commit_reveal.clone(), Arc::clone(&storage));
        Self {
            pool: RwLock::new(TransactionPool::new()),
            validator: TransactionValidator::new(state, TxValidationConfig::default()),
            config,
            storage: Some(storage),
            last_cleanup_at: Mutex::new(unix_timestamp()),
            gossip_tracker: Mutex::new(GossipTracker::new(50_000)),
            metrics_tracker: Mutex::new(MetricsTracker::default()),
            commit_reveal: Some(Mutex::new(cr_pool)),
        }
    }

    /// Start the mempool. Restores persisted mempool and commit-reveal transactions from disk.
    pub fn start(&self) -> Result<()> {
        let restored_mempool = self.restore_from_disk()?;
        if let Some(cr) = &self.commit_reveal {
            cr.lock().restore_from_storage()?;
        }
        info!(
            "mempool started with capacity {}, restored {} transactions",
            self.config.max_pending_transactions, restored_mempool
        );
        Ok(())
    }

    /// Validate and insert a transaction into the mempool.
    pub fn add_transaction(&self, tx: Transaction) -> Result<Hash> {
        // 1. Hard size cap before any expensive checks.
        let tx_size = tx.size_bytes()?;
        if tx_size > MAX_TX_SIZE {
            self.record_rejected();
            return Err(MempoolError::TransactionTooLarge {
                size: tx_size,
                max: MAX_TX_SIZE,
            }
            .into());
        }

        // 2. Full validation (signature, nonce, balance, gas, duplicates).
        self.validator.validate(&tx).inspect_err(|_| {
            self.record_rejected();
        })?;

        // SECURITY (H-05): the per-sender rate-limit token is consumed only
        // AFTER signature verification succeeds. Charging the bucket first
        // (keyed on the attacker-chosen `from`) let anyone spray invalid
        // transactions bearing a victim's address and drain the victim's
        // send budget costlessly.
        self.enforce_sender_transaction_rate_limit(&tx)?;

        // 3. Capacity enforcement with priority-based eviction.
        let mut pool = self.pool.write();

        // Per-account spam guard.
        let sender_count = pool.sender_transaction_count(&tx.from);
        let replacing_existing = pool.contains_sender_nonce(&tx.from, tx.nonce);
        if !replacing_existing && sender_count >= self.config.max_transactions_per_account {
            drop(pool);
            self.record_rejected();
            return Err(MempoolError::AccountTxLimitExceeded {
                count: sender_count,
                limit: self.config.max_transactions_per_account,
            }
            .into());
        }

        let mut evicted_hash_to_clean = None;
        if !replacing_existing && pool.len() >= self.config.max_pending_transactions {
            let Some((evicted_hash, evicted_tx)) = pool.lowest_priority_transaction() else {
                drop(pool);
                return Err(MempoolError::PoolFullLowPriority {
                    gas_price: tx.gas_price.to_string(),
                    incumbent_gas_price: "none".into(),
                }
                .into());
            };

            // Incoming transaction must offer strictly higher gas price to evict incumbent
            if tx.gas_price <= evicted_tx.gas_price {
                drop(pool);
                self.record_rejected();
                return Err(MempoolError::PoolFullLowPriority {
                    gas_price: tx.gas_price.to_string(),
                    incumbent_gas_price: evicted_tx.gas_price.to_string(),
                }
                .into());
            }

            pool.remove(&evicted_hash);
            evicted_hash_to_clean = Some(evicted_hash);
        }

        let (hash, replaced_hash) = pool.insert_with_replaced(tx)?;
        let pending = pool.len();
        drop(pool);

        // Mark seen in duplicate cache upon successful admission
        self.validator.mark_seen(&hash);

        // Clean up evicted / replaced transactions from disk and unmark seen
        if let Some(evicted) = evicted_hash_to_clean {
            let _ = self.remove_persisted_transaction(evicted);
            self.validator.unmark_seen(&evicted);
        }
        if let Some(replaced) = replaced_hash {
            let _ = self.remove_persisted_transaction(replaced);
            self.validator.unmark_seen(&replaced);
        }

        self.record_arrival(unix_timestamp());
        let _ = self.persist_transaction_to_disk(hash);

        // 4. Opportunistic TTL cleanup (no-op if interval hasn't elapsed).
        let _ = self.remove_expired_transactions_periodically();

        info!("transaction added to mempool: pending_count={}", pending);
        Ok(hash)
    }

    /// Internal insert for restored transactions that bypasses gossip rate limits.
    fn insert_restored_transaction(&self, tx: Transaction) -> Result<Hash> {
        let tx_size = tx.size_bytes()?;
        if tx_size > MAX_TX_SIZE {
            return Err(MempoolError::TransactionTooLarge {
                size: tx_size,
                max: MAX_TX_SIZE,
            }
            .into());
        }
        self.validator.validate(&tx)?;
        let mut pool = self.pool.write();
        let (hash, _) = pool.insert_with_replaced(tx)?;
        self.validator.mark_seen(&hash);
        Ok(hash)
    }

    /// Validate a wallet transaction and submit it through the private
    /// commit-reveal path used by `eth_sendRawTransaction`.
    /// Returns `(Hash, [u8; 32])` where the first is transaction hash and second is commit ID.
    pub fn submit_mev_protected_transaction(&self, tx: Transaction) -> Result<(Hash, [u8; 32])> {
        let tx_size = tx.size_bytes()?;
        if tx_size > MAX_TX_SIZE {
            self.record_rejected();
            return Err(MempoolError::TransactionTooLarge {
                size: tx_size,
                max: MAX_TX_SIZE,
            }
            .into());
        }

        self.validator.validate(&tx).inspect_err(|_| {
            self.record_rejected();
        })?;

        // SECURITY (H-05): consume the sender rate-limit token only after
        // signature verification (see `add_transaction`).
        self.enforce_sender_transaction_rate_limit(&tx)?;

        let cr = self
            .commit_reveal
            .as_ref()
            .ok_or(MempoolError::StorageRequiredForMev)?;

        let mut reveal_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut reveal_nonce);
        let (tx_hash, commit_id) = cr
            .lock()
            .submit_protected_transaction(tx, reveal_nonce)
            .inspect_err(|_| {
                self.record_rejected();
            })?;

        self.record_arrival(unix_timestamp());
        Ok((tx_hash, commit_id))
    }

    /// Remove transactions that have exceeded their TTL.
    /// Only performs a sweep when `cleanup_interval_secs` have elapsed since
    /// the last sweep; otherwise returns an empty list immediately.
    pub fn remove_expired_transactions_periodically(&self) -> Result<Vec<Hash>> {
        let now = unix_timestamp();
        let mut last_cleanup = self.last_cleanup_at.lock();

        if now.saturating_sub(*last_cleanup) < self.config.cleanup_interval_secs {
            return Ok(Vec::new());
        }

        let mut pool = self.pool.write();
        let removed = pool.remove_expired_transactions(self.config.transaction_ttl_secs, now);
        *last_cleanup = now;
        drop(pool);

        for hash in &removed {
            let _ = self.remove_persisted_transaction(*hash);
            self.validator.unmark_seen(hash);
        }

        Ok(removed)
    }

    /// Select up to `limit` transactions for inclusion in a block.
    pub fn select_transactions_for_block(&self, limit: usize) -> Result<Vec<Transaction>> {
        let pool = self.pool.read();

        let mut selected = Vec::with_capacity(limit);
        let mut last_nonce_per_sender: HashMap<Address, u64> = HashMap::new();
        let mut remaining_balance_per_sender: HashMap<Address, U256> = HashMap::new();

        for tx in pool.prioritized_transactions() {
            if selected.len() >= limit {
                break;
            }

            // Filter out transactions that are no longer valid.
            if self
                .validator
                .validate_transaction_for_selection(&tx)
                .is_err()
            {
                continue;
            }

            // Check sender starting state nonce and cumulative sequence
            let account = self
                .validator
                .state
                .get_account(&tx.from)
                .map_err(|e| MempoolError::StateDb(e.to_string()))?
                .unwrap_or_else(|| Account::new(tx.from));
            let is_valid_nonce = match last_nonce_per_sender.get(&tx.from).copied() {
                None => tx.nonce == account.nonce,
                Some(last) => tx.nonce == last.saturating_add(1),
            };

            if !is_valid_nonce {
                continue;
            }

            // Check cumulative spendable balance for this sender
            let (total_cost, overflowed) = tx.value.overflowing_add(tx.gas_cost());
            if overflowed {
                continue;
            }

            let mut spendable = *remaining_balance_per_sender
                .entry(tx.from)
                .or_insert_with(|| {
                    let mut bal = account.balance;
                    if let Ok(Some(schedule)) = self.validator.state.get_vesting_schedule(&tx.from)
                    {
                        let now = unix_timestamp();
                        let locked = schedule.locked_amount(now);
                        bal = bal.saturating_sub(locked);
                    }
                    bal
                });

            if spendable < total_cost {
                continue;
            }

            spendable = spendable.saturating_sub(total_cost);
            remaining_balance_per_sender.insert(tx.from, spendable);
            last_nonce_per_sender.insert(tx.from, tx.nonce);
            selected.push(tx);
        }

        Ok(selected)
    }

    // - Disk persistence -

    /// Write every pending transaction to the storage backend.
    /// Returns the number of transactions persisted.
    pub fn persist_transactions_to_disk(&self) -> Result<usize> {
        let Some(storage) = &self.storage else {
            return Ok(0);
        };
        storage
            .mempool_clear()
            .map_err(|e| MempoolError::Storage(e.to_string()))?;
        let transactions = {
            let pool = self.pool.read();
            pool.all_transactions()
        };
        for tx in &transactions {
            let bytes = tx.try_encode()?;
            storage
                .mempool_insert(tx.try_hash()?, &bytes)
                .map_err(|e| MempoolError::Storage(e.to_string()))?;
        }
        Ok(transactions.len())
    }

    /// Read any previously persisted transactions from the storage backend
    /// and reinsert them into the in-memory pool.
    pub fn restore_from_disk(&self) -> Result<usize> {
        let Some(storage) = &self.storage else {
            return Ok(0);
        };
        let entries = storage
            .mempool_iterate()
            .map_err(|e| MempoolError::Storage(e.to_string()))?;
        let mut restored = 0usize;
        let mut invalid_hashes = Vec::new();
        for (hash, tx_bytes) in entries {
            match Transaction::decode(&tx_bytes) {
                Ok(tx) => {
                    // A single corrupt entry must never abort the whole
                    // restore: hash failures mark the entry invalid instead.
                    let tx_hash = match tx.try_hash() {
                        Ok(h) => h,
                        Err(_) => {
                            invalid_hashes.push(hash);
                            continue;
                        }
                    };
                    if self.contains(tx_hash)? {
                        continue;
                    }
                    if self.insert_restored_transaction(tx).is_ok() {
                        restored = restored.saturating_add(1);
                    } else {
                        invalid_hashes.push(hash);
                    }
                }
                Err(_) => invalid_hashes.push(hash),
            }
        }
        for hash in invalid_hashes {
            let _ = storage.mempool_remove(hash);
        }
        Ok(restored)
    }

    /// Persist a single transaction. Called after every successful insertion.
    fn persist_transaction_to_disk(&self, tx_hash: Hash) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let tx = self
            .get_transaction(tx_hash)?
            .ok_or_else(|| anyhow::anyhow!("transaction not found after insert"))?;
        let bytes = tx.try_encode()?;
        storage
            .mempool_insert(tx_hash, &bytes)
            .map_err(|e| MempoolError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Remove a single transaction from persistent storage after removal from pool.
    fn remove_persisted_transaction(&self, tx_hash: Hash) -> Result<()> {
        if let Some(storage) = &self.storage {
            let _ = storage.mempool_remove(tx_hash);
        }
        Ok(())
    }

    // - Revalidation -

    /// Revalidate pending transactions for specific sender addresses against the current state DB.
    pub fn revalidate_senders(&self, senders: &[Address]) -> Result<Vec<Hash>> {
        let mut evicted_hashes = Vec::new();
        let mut pool = self.pool.write();

        for sender in senders {
            let txs = pool.transactions_by_sender(sender);
            for tx in txs {
                let hash = match tx.try_hash() {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if self
                    .validator
                    .validate_transaction_for_selection(&tx)
                    .is_err()
                {
                    pool.remove(&hash);
                    evicted_hashes.push(hash);
                }
            }
        }
        drop(pool);

        for hash in &evicted_hashes {
            let _ = self.remove_persisted_transaction(*hash);
            self.validator.unmark_seen(hash);
        }

        if !evicted_hashes.is_empty() {
            info!(
                "revalidated senders: evicted {} invalid transactions",
                evicted_hashes.len()
            );
        }
        Ok(evicted_hashes)
    }

    /// Revalidate the entire pending pool against the current state DB.
    pub fn revalidate_pool(&self) -> Result<Vec<Hash>> {
        let mut evicted_hashes = Vec::new();
        let mut pool = self.pool.write();
        let all_txs = pool.all_transactions();

        for tx in all_txs {
            let hash = match tx.try_hash() {
                Ok(h) => h,
                Err(_) => continue,
            };
            if self
                .validator
                .validate_transaction_for_selection(&tx)
                .is_err()
            {
                pool.remove(&hash);
                evicted_hashes.push(hash);
            }
        }
        drop(pool);

        for hash in &evicted_hashes {
            let _ = self.remove_persisted_transaction(*hash);
            self.validator.unmark_seen(hash);
        }

        if !evicted_hashes.is_empty() {
            info!(
                "revalidated pool: evicted {} invalid transactions",
                evicted_hashes.len()
            );
        }
        Ok(evicted_hashes)
    }

    // - Metrics -

    /// Return a point-in-time snapshot of the tracked metrics.
    pub fn metrics_snapshot(&self) -> MempoolMetrics {
        let now = unix_timestamp();
        let mempool_size = self.pending_count().unwrap_or(0);
        let average_gas_price = self.average_gas_price();

        let mut tracker = self.metrics_tracker.lock();
        tracker.prune_arrival_window(now);
        MempoolMetrics {
            mempool_size,
            transaction_arrival_rate: tracker.arrival_timestamps.len() as f64,
            rejected_transactions: tracker.rejected_transactions,
            average_gas_price,
        }
    }

    /// Average gas price across all transactions currently in the pool.
    fn average_gas_price(&self) -> U256 {
        let pool = self.pool.read();
        if pool.txs.is_empty() {
            return U256::zero();
        }
        let total = pool
            .txs
            .values()
            .fold(U256::zero(), |sum, tx| sum.saturating_add(tx.gas_price));
        total / U256::from(pool.txs.len())
    }

    fn record_arrival(&self, timestamp: u64) {
        let mut t = self.metrics_tracker.lock();
        t.arrival_timestamps.push_back(timestamp);
        t.prune_arrival_window(timestamp);
    }

    fn record_rejected(&self) {
        let mut t = self.metrics_tracker.lock();
        t.rejected_transactions = t.rejected_transactions.saturating_add(1);
    }

    /// Accept a transaction that arrived via P2P gossip (no known source peer).
    pub fn receive_transaction_from_p2p_gossip(&self, tx: Transaction) -> Result<Hash> {
        self.receive_transaction_from_p2p_gossip_from_peer(None, tx)
    }

    /// Accept a transaction that arrived via P2P gossip from a specific peer.
    pub fn receive_transaction_from_p2p_gossip_from_peer(
        &self,
        source_peer: Option<String>,
        tx: Transaction,
    ) -> Result<Hash> {
        if let Some(ref peer_id) = source_peer {
            self.enforce_peer_transaction_rate_limit(peer_id)?;
        }

        let hash = self.add_transaction(tx)?;

        let mut tracker = self.gossip_tracker.lock();
        tracker.received_from_peers.put(hash, ());
        tracker.broadcasted.pop(&hash);
        Ok(hash)
    }

    /// Build a `GossipMessage` for `tx_hash` if it should be broadcast to peers.
    pub fn broadcast_new_transaction_to_peers(
        &self,
        tx_hash: Hash,
    ) -> Result<Option<GossipMessage>> {
        let transaction = self
            .get_transaction(tx_hash)?
            .ok_or_else(|| anyhow::anyhow!("transaction not found in mempool"))?;

        let mut tracker = self.gossip_tracker.lock();

        if tracker.received_from_peers.contains(&tx_hash) || tracker.broadcasted.contains(&tx_hash)
        {
            return Ok(None);
        }

        tracker.broadcasted.put(tx_hash, ());
        Ok(Some(GossipMessage::Transaction(transaction.try_encode()?)))
    }

    /// Accept a commit that arrived via P2P gossip from a specific peer.
    pub fn receive_commit_from_p2p_gossip_from_peer(
        &self,
        source_peer: Option<String>,
        commit: CommitTransaction,
    ) -> Result<[u8; 32]> {
        if let Some(ref peer_id) = source_peer {
            self.enforce_peer_transaction_rate_limit(peer_id)?;
        }

        let commit_id = commit.id;
        let submitted_id = self.submit_commit(commit)?;

        let mut tracker = self.gossip_tracker.lock();
        tracker.received_commits.put(commit_id, ());
        tracker.broadcasted_commits.pop(&commit_id);
        Ok(submitted_id)
    }

    /// Build a `GossipMessage` for `commit_id` if it should be broadcast to peers.
    pub fn broadcast_new_commit_to_peers(
        &self,
        commit_id: [u8; 32],
    ) -> Result<Option<GossipMessage>> {
        let cr = self
            .commit_reveal
            .as_ref()
            .ok_or(MempoolError::StorageRequiredForMev)?;

        let commit = cr
            .lock()
            .get_pending_commit(&commit_id)
            .ok_or_else(|| MempoolError::CommitNotFound(hex::encode(commit_id)))?;

        let mut tracker = self.gossip_tracker.lock();
        if tracker.received_commits.contains(&commit_id)
            || tracker.broadcasted_commits.contains(&commit_id)
        {
            return Ok(None);
        }

        tracker.broadcasted_commits.put(commit_id, ());
        let bytes = commit.try_encode()?;
        Ok(Some(GossipMessage::Commit(bytes)))
    }

    /// Accept a reveal that arrived via P2P gossip from a specific peer.
    pub fn receive_reveal_from_p2p_gossip_from_peer(
        &self,
        source_peer: Option<String>,
        reveal: RevealTransaction,
    ) -> Result<()> {
        if let Some(ref peer_id) = source_peer {
            self.enforce_peer_transaction_rate_limit(peer_id)?;
        }

        let commit_id = reveal.commit_id;
        self.submit_reveal(reveal)?;

        let mut tracker = self.gossip_tracker.lock();
        tracker.received_reveals.put(commit_id, ());
        tracker.broadcasted_reveals.pop(&commit_id);
        Ok(())
    }

    /// Build a `GossipMessage` for `reveal` if it should be broadcast to peers.
    pub fn broadcast_new_reveal_to_peers(
        &self,
        reveal: &RevealTransaction,
    ) -> Result<Option<GossipMessage>> {
        let commit_id = reveal.commit_id;
        let mut tracker = self.gossip_tracker.lock();
        if tracker.received_reveals.contains(&commit_id)
            || tracker.broadcasted_reveals.contains(&commit_id)
        {
            return Ok(None);
        }

        tracker.broadcasted_reveals.put(commit_id, ());
        let bytes = reveal.try_encode()?;
        Ok(Some(GossipMessage::Reveal(bytes)))
    }

    // - Spam-prevention helpers -

    /// Enforce a sliding-window rate limit per peer.
    fn enforce_peer_transaction_rate_limit(&self, peer_id: &str) -> Result<()> {
        let now = unix_timestamp();
        let mut tracker = self.gossip_tracker.lock();

        if tracker.peer_buckets.len() > 1000 {
            tracker.prune_idle_buckets(now);
        }

        let bucket = tracker
            .peer_buckets
            .entry(peer_id.to_owned())
            .or_insert_with(|| {
                TokenBucket::new(
                    self.config.max_transactions_per_peer_per_window,
                    self.config.peer_rate_limit_window_secs,
                    now,
                )
            });

        if !bucket.try_consume(now) {
            return Err(MempoolError::PeerRateLimitExceeded {
                limit: self.config.max_transactions_per_peer_per_window,
                window_secs: self.config.peer_rate_limit_window_secs,
            }
            .into());
        }
        Ok(())
    }

    fn enforce_sender_transaction_rate_limit(&self, tx: &Transaction) -> Result<()> {
        let now = unix_timestamp();
        let mut tracker = self.gossip_tracker.lock();

        if tracker.sender_buckets.len() > 5000 {
            tracker.prune_idle_buckets(now);
        }

        let sender = *tx.from.as_bytes();
        let bucket = tracker.sender_buckets.entry(sender).or_insert_with(|| {
            TokenBucket::new(
                self.config.max_transactions_per_sender_per_window,
                self.config.sender_rate_limit_window_secs,
                now,
            )
        });

        if !bucket.try_consume(now) {
            return Err(MempoolError::SenderRateLimitExceeded {
                limit: self.config.max_transactions_per_sender_per_window,
                window_secs: self.config.sender_rate_limit_window_secs,
            }
            .into());
        }

        Ok(())
    }

    /// Returns the removed transaction, or `None` if it was not present.
    pub fn remove_transaction(&self, tx_hash: Hash) -> Result<Option<Transaction>> {
        let mut pool = self.pool.write();
        let removed = pool.remove(&tx_hash);
        drop(pool);
        if removed.is_some() {
            let _ = self.remove_persisted_transaction(tx_hash);
            self.validator.unmark_seen(&tx_hash);
        }
        Ok(removed)
    }

    /// Look up a transaction by hash without removing it.
    pub fn get_transaction(&self, tx_hash: Hash) -> Result<Option<Transaction>> {
        let pool = self.pool.read();
        if let Some(tx) = pool.get(&tx_hash).cloned() {
            return Ok(Some(tx));
        }
        drop(pool);

        if let Some(cr) = &self.commit_reveal {
            return Ok(cr.lock().get_revealed_transaction(tx_hash));
        }

        Ok(None)
    }

    /// Return `true` if the pool currently holds a transaction with the given hash.
    pub fn contains(&self, tx_hash: Hash) -> Result<bool> {
        let pool = self.pool.read();
        Ok(pool.contains(&tx_hash))
    }

    /// Return the number of transactions currently in the pool.
    pub fn pending_count(&self) -> Result<usize> {
        let pool = self.pool.read();
        Ok(pool.len())
    }

    /// Remove all transactions from the pool.
    pub fn clear(&self) -> Result<()> {
        let mut pool = self.pool.write();
        let all_hashes: Vec<Hash> = pool.txs.keys().copied().collect();
        pool.clear();
        drop(pool);
        for hash in all_hashes {
            let _ = self.remove_persisted_transaction(hash);
            self.validator.unmark_seen(&hash);
        }
        Ok(())
    }

    /// Return up to `limit` transactions ordered by priority.
    pub fn get_pending_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
        let pool = self.pool.read();
        Ok(pool.get_top_n(limit))
    }

    // - Node integration aliases -

    /// Alias for `persist_transactions_to_disk` - called by `Node::stop()`.
    pub fn persist_mempool_transactions_to_disk(&self) -> Result<usize> {
        self.persist_transactions_to_disk()
    }

    /// Called by block proposers to obtain the canonical transaction list.
    pub fn provide_transactions_to_block_proposer(
        &self,
        limit: usize,
        parent_hash: &[u8; 32],
        beacon_randomness: &[u8; 32],
    ) -> Result<Vec<Transaction>> {
        let (txs, _) =
            self.build_mev_protected_transactions(limit, parent_hash, beacon_randomness)?;
        Ok(txs)
    }

    // - MEV protection: commit-reveal interface -

    /// Submit a commit during the commit phase.
    pub fn submit_commit(&self, commit: CommitTransaction) -> Result<[u8; 32]> {
        let cr = self
            .commit_reveal
            .as_ref()
            .ok_or(MempoolError::StorageRequiredForMev)?;
        cr.lock().submit_commit(commit)
    }

    /// Submit a reveal that matches a previously submitted commit.
    pub fn submit_reveal(&self, reveal: RevealTransaction) -> Result<()> {
        let tx_size = reveal.transaction.size_bytes()?;
        if tx_size > MAX_TX_SIZE {
            return Err(MempoolError::TransactionTooLarge {
                size: tx_size,
                max: MAX_TX_SIZE,
            }
            .into());
        }
        self.validator.validate(&reveal.transaction)?;
        let cr = self
            .commit_reveal
            .as_ref()
            .ok_or(MempoolError::StorageRequiredForMev)?;
        cr.lock().submit_reveal(reveal)
    }

    /// Advance the commit-reveal pool's block height, evicting expired commits
    /// and returning all newly released `RevealTransaction`s.
    pub fn on_block_height(&self, height: u64) -> Result<Vec<RevealTransaction>> {
        if let Some(cr) = &self.commit_reveal {
            cr.lock().on_new_block(height)
        } else {
            Ok(Vec::new())
        }
    }

    pub fn release_mev_reservation(&self, res_id: ReservationId) {
        if let Some(commit_reveal) = &self.commit_reveal {
            commit_reveal.lock().release_reserved_transactions(res_id);
        }
    }

    /// Build an ordered, MEV-protected transaction list for the next block.
    pub fn build_mev_protected_transactions(
        &self,
        limit: usize,
        parent_hash: &[u8; 32],
        beacon_randomness: &[u8; 32],
    ) -> Result<(Vec<Transaction>, ReservationId)> {
        if let Some(cr) = &self.commit_reveal {
            let (txs, res_id) =
                cr.lock()
                    .build_block_transactions(limit, parent_hash, beacon_randomness);
            return Ok((txs, res_id));
        }

        if std::env::var("SXIAUM_PRODUCTION_VALIDATOR").unwrap_or_default() == "true" {
            return Err(MempoolError::ProductionValidatorMevRequired.into());
        }

        let txs = self.select_transactions_for_block(limit)?;
        Ok((txs, ReservationId(0)))
    }

    /// Return the current commit-reveal pool statistics for monitoring.
    pub fn mev_pool_stats(&self) -> (usize, usize) {
        self.commit_reveal
            .as_ref()
            .map(|cr| {
                let pool = cr.lock();
                (pool.pending_commit_count(), pool.revealed_tx_count())
            })
            .unwrap_or((0, 0))
    }

    /// The commit fee that must be covered by a sender's balance before a
    /// commit is accepted. Zero when MEV protection is disabled.
    pub fn commit_fee(&self) -> u128 {
        self.commit_reveal
            .as_ref()
            .map(|cr| cr.lock().config.commit_fee)
            .unwrap_or(0)
    }

    /// Returns true when storage-backed commit-reveal protection is available.
    pub fn mev_protection_enabled(&self) -> bool {
        self.commit_reveal.is_some()
    }

    /// Remove all transactions that were included in a committed block from both
    /// the in-memory pool and the durable storage backend.
    pub fn remove_transactions_after_block_commit(&self, block: &Block) -> Result<()> {
        let mut senders: HashSet<Address> = HashSet::new();
        let hashes: Vec<Hash> = block
            .body
            .transactions
            .iter()
            .filter_map(|tx| {
                senders.insert(tx.from);
                tx.try_hash().ok()
            })
            .collect();
        if let Some(commit_reveal) = &self.commit_reveal {
            let hash_set: HashSet<Hash> = hashes.iter().copied().collect();
            commit_reveal.lock().acknowledge_transactions(&hash_set);
        }
        let mut pool = self.pool.write();
        pool.remove_many(&hashes);
        drop(pool);
        for hash in &hashes {
            let _ = self.remove_persisted_transaction(*hash);
            self.validator.unmark_seen(hash);
        }

        // Automatically revalidate remaining transactions from affected senders
        let sender_list: Vec<Address> = senders.into_iter().collect();
        let _ = self.revalidate_senders(&sender_list);

        Ok(())
    }
}

impl TransactionPoolSink for Mempool {
    fn contains_transaction(&self, tx: &Transaction) -> Result<bool> {
        self.contains(
            tx.try_hash()
                .map_err(|e| MempoolError::HashingFailed(e.to_string()))?,
        )
    }

    fn insert_transaction(&self, tx: Transaction, source_peer: Option<String>) -> Result<()> {
        self.receive_transaction_from_p2p_gossip_from_peer(source_peer, tx)
            .map(|_| ())
    }
}

impl CommitPoolSink for Mempool {
    fn contains_commit(&self, commit_id: &[u8; 32]) -> Result<bool> {
        if let Some(cr) = &self.commit_reveal {
            Ok(cr.lock().contains_commit(commit_id))
        } else {
            Ok(false)
        }
    }

    fn insert_commit_payload(
        &self,
        payload: &[u8],
        source_peer: Option<String>,
    ) -> Result<[u8; 32]> {
        let commit = CommitTransaction::decode(payload)
            .map_err(|e| anyhow::anyhow!("invalid commit payload: {}", e))?;
        self.receive_commit_from_p2p_gossip_from_peer(source_peer, commit)
    }
}

impl RevealPoolSink for Mempool {
    fn insert_reveal_payload(&self, payload: &[u8], source_peer: Option<String>) -> Result<()> {
        let reveal = RevealTransaction::decode(payload)
            .map_err(|e| anyhow::anyhow!("invalid reveal payload: {}", e))?;
        self.receive_reveal_from_p2p_gossip_from_peer(source_peer, reveal)
    }
}

impl TransactionSource for Mempool {
    fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
        self.provide_transactions_to_block_proposer(limit, &[0u8; 32], &[0u8; 32])
    }

    fn pull_mev_transactions(
        &self,
        limit: usize,
        parent_hash: &[u8; 32],
        beacon_randomness: &[u8; 32],
    ) -> Result<(Vec<Transaction>, ReservationId)> {
        self.build_mev_protected_transactions(limit, parent_hash, beacon_randomness)
    }

    fn release_transaction_reservation(&self, reservation_id: ReservationId) -> Result<()> {
        self.release_mev_reservation(reservation_id);
        Ok(())
    }

    fn acknowledge_transactions(&self, hashes: &[[u8; 32]]) -> Result<()> {
        if let Some(commit_reveal) = &self.commit_reveal {
            let hash_set: HashSet<Hash> = hashes.iter().copied().collect();
            commit_reveal.lock().acknowledge_transactions(&hash_set);
        }
        let mut pool = self.pool.write();
        pool.remove_many(hashes);
        drop(pool);
        for hash in hashes {
            let _ = self.remove_persisted_transaction(*hash);
            self.validator.unmark_seen(hash);
        }
        Ok(())
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl MetricsTracker {
    fn prune_arrival_window(&mut self, now: u64) {
        // Keep only timestamps within the last 1-second window.
        while let Some(&oldest) = self.arrival_timestamps.front() {
            if now.saturating_sub(oldest) >= 1 {
                self.arrival_timestamps.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Mempool, MempoolConfig};
    use crate::ordering::{try_compute_commit_hash, CommitTransaction};
    use crate::RevealTransaction;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_state::StateDb;
    use sxiaum_storage::StorageEngine;
    use sxiaum_types::{Address, Transaction};

    fn unique_db(name: &str) -> (PathBuf, Arc<StorageEngine>) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sxiaum-mempool-{}-{}.redb", name, unique));
        let storage = Arc::new(StorageEngine::new(&path).expect("storage should initialize"));
        (path, storage)
    }

    fn signed_transfer(seed: u8, nonce: u64) -> Transaction {
        let (private_key, public_key) = sxiaum_crypto::keypair_from_seed([seed; 32]);
        let public_key_bytes = public_key.to_bytes();
        let from = Address::from_public_key(&public_key_bytes);
        let to = Address([seed.saturating_add(1); 32]);
        let mut tx = Transaction::new_transfer(from, to, U256::from(1u64), nonce);
        tx.signer_pubkey = Some(public_key_bytes);
        tx.signature =
            Some(sxiaum_crypto::sign(&private_key.0, &tx.try_hash().unwrap()).to_bytes());
        tx
    }

    fn storage_backed_mempool(name: &str) -> (PathBuf, Arc<StorageEngine>, Arc<StateDb>, Mempool) {
        let (path, storage) = unique_db(name);
        let state = Arc::new(StateDb::new(
            Arc::clone(&storage) as Arc<dyn sxiaum_storage::DatabaseBackend>
        ));
        let mempool = Mempool::with_storage(
            MempoolConfig::default(),
            Arc::clone(&state),
            Arc::clone(&storage),
        );
        (path, storage, state, mempool)
    }

    #[test]
    fn storage_backed_proposer_does_not_fallback_to_cleartext_pool() {
        let (path, storage, state, mempool) = storage_backed_mempool("no-cleartext-fallback");
        let tx = signed_transfer(7, 0);
        state
            .set_balance(&tx.from, U256::from(10_000u64))
            .expect("sender should be funded");

        mempool
            .add_transaction(tx)
            .expect("cleartext transaction should enter pending pool");

        let selected = mempool
            .provide_transactions_to_block_proposer(10, &[0u8; 32], &[0u8; 32])
            .expect("selection should succeed");
        assert!(
            selected.is_empty(),
            "storage-backed block production must not include cleartext mempool transactions"
        );

        drop(mempool);
        drop(state);
        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn storage_backed_proposer_selects_revealed_commit_transactions() {
        let (path, storage, state, mempool) = storage_backed_mempool("revealed-selection");
        let tx = signed_transfer(11, 0);
        state
            .set_balance(&tx.from, U256::from(10_000u64))
            .expect("sender should be funded");

        let config = crate::ordering::CommitRevealConfig {
            commit_fee: 10_000_000_000_000_000,
            reveal_window_blocks: 5,
            commit_expiry_blocks: 20,
            no_show_slash: 10,
            max_commits_per_sender: 16,
        };
        let reveal_nonce = [42u8; 32];
        let (commit_private_key, _commit_public_key) = sxiaum_crypto::keypair_from_seed([11u8; 32]);
        let mut commit = CommitTransaction::new(
            try_compute_commit_hash(&reveal_nonce, &tx).expect("tx hashing must succeed"),
            *tx.from.as_bytes(),
            0,
            config.reveal_window_blocks,
            config.commit_expiry_blocks,
        );
        // SECURITY (C-13): externally submitted commits must be signed.
        commit
            .sign(&commit_private_key)
            .expect("commit should sign with its sender key");
        let commit_id = mempool
            .submit_commit(commit)
            .expect("commit should be accepted");
        mempool
            .submit_reveal(RevealTransaction::new(
                commit_id,
                tx.clone(),
                reveal_nonce,
                1,
            ))
            .expect("reveal should be accepted");

        let selected = mempool
            .provide_transactions_to_block_proposer(10, &[0u8; 32], &[0u8; 32])
            .expect("selection should succeed");
        assert_eq!(selected, vec![tx]);

        drop(mempool);
        drop(state);
        drop(storage);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn storage_backed_raw_wallet_submission_uses_commit_reveal_not_cleartext_pool() {
        let (path, storage, state, mempool) = storage_backed_mempool("raw-wallet-commit-reveal");
        let tx = signed_transfer(13, 0);
        state
            .set_balance(&tx.from, U256::from(10_000u64))
            .expect("sender should be funded");

        let (tx_hash, _commit_id) = mempool
            .submit_mev_protected_transaction(tx.clone())
            .expect("wallet transaction should enter commit-reveal flow");

        assert_eq!(
            mempool.pending_count().expect("pending count should load"),
            0,
            "transparent wallet submissions must not enter the cleartext pool"
        );
        assert_eq!(
            mempool
                .get_transaction(tx_hash)
                .expect("revealed tx lookup should succeed"),
            None
        );

        let (pending_commits, revealed_txs) = mempool.mev_pool_stats();
        assert_eq!(pending_commits, 1);
        assert_eq!(revealed_txs, 0);

        let released = mempool
            .on_block_height(1)
            .expect("reveal should release on next block");
        assert_eq!(released.len(), 1);

        assert_eq!(
            mempool
                .get_transaction(tx_hash)
                .expect("revealed tx lookup should succeed"),
            Some(tx.clone())
        );

        let (pending_commits, revealed_txs) = mempool.mev_pool_stats();
        assert_eq!(pending_commits, 0);
        assert_eq!(revealed_txs, 1);

        let selected = mempool
            .provide_transactions_to_block_proposer(10, &[0u8; 32], &[0u8; 32])
            .expect("selection should succeed");
        assert_eq!(selected, vec![tx]);

        drop(mempool);
        drop(state);
        drop(storage);
        let _ = fs::remove_file(path);
    }
}
