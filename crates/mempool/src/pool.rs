use crate::error::MempoolError;
use anyhow::Result;
use primitive_types::U256;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use sxiaum_types::{Address, Hash, Transaction};

pub struct TransactionPool {
    pub txs: HashMap<Hash, Transaction>,
    /// sender -> nonce -> hash
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    /// monotonic arrival sequence -> hash
    by_arrival_time: BTreeMap<u64, Hash>,
    /// hash -> arrival sequence (O(1) reverse lookup)
    hash_to_arrival_seq: HashMap<Hash, u64>,
    /// hash -> wall-clock insertion timestamp (secs)
    timestamps: HashMap<Hash, u64>,
    arrival_sequence: u64,
}

impl TransactionPool {
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            by_sender: HashMap::new(),
            by_arrival_time: BTreeMap::new(),
            hash_to_arrival_seq: HashMap::new(),
            timestamps: HashMap::new(),
            arrival_sequence: 0,
        }
    }

    /// Insert a transaction, maintaining all secondary indexes.
    /// If a transaction from the same sender with the same nonce already exists,
    /// replace-by-fee is validated and applied atomically.
    /// Returns the new transaction hash and the optional replaced transaction hash.
    pub fn insert_with_replaced(&mut self, tx: Transaction) -> Result<(Hash, Option<Hash>)> {
        let hash = tx
            .try_hash()
            .map_err(|e| MempoolError::HashingFailed(e.to_string()))?;

        if self.txs.contains_key(&hash) {
            return Err(MempoolError::DuplicateTransaction(hex::encode(hash)).into());
        }

        // Replace-by-fee: validate incumbent replacement price before any removal
        let mut replaced_hash = None;
        if let Some(existing_hash) = self.lookup_by_sender_and_nonce(&tx.from, tx.nonce) {
            let existing = self
                .get(&existing_hash)
                .ok_or(MempoolError::ReplacementNotFound)?;
            self.validate_replacement_gas_price(existing, &tx)?;
            self.remove(&existing_hash);
            replaced_hash = Some(existing_hash);
        }

        let seq = self.arrival_sequence;
        // Secondary index maintenance
        self.by_sender
            .entry(tx.from)
            .or_default()
            .insert(tx.nonce, hash);
        self.by_arrival_time.insert(seq, hash);
        self.hash_to_arrival_seq.insert(hash, seq);
        self.timestamps.insert(hash, unix_timestamp());
        self.arrival_sequence = self.arrival_sequence.saturating_add(1);

        self.txs.insert(hash, tx);
        Ok((hash, replaced_hash))
    }

    /// Insert a transaction, returning only the transaction hash.
    pub fn insert(&mut self, tx: Transaction) -> Result<Hash> {
        self.insert_with_replaced(tx).map(|(hash, _)| hash)
    }

    /// Remove a transaction by hash, cleaning all secondary indexes.
    pub fn remove(&mut self, hash: &Hash) -> Option<Transaction> {
        let tx = self.txs.remove(hash)?;
        self.remove_from_sender_index(tx.from, tx.nonce);
        self.remove_from_arrival_index(hash);
        self.timestamps.remove(hash);
        Some(tx)
    }

    /// Look up a transaction by hash without removing it.
    pub fn get(&self, hash: &Hash) -> Option<&Transaction> {
        self.txs.get(hash)
    }

    /// Return `true` if the pool contains a transaction with the given hash.
    pub fn contains(&self, hash: &Hash) -> bool {
        self.txs.contains_key(hash)
    }

    /// Return the number of transactions currently in the pool.
    pub fn size(&self) -> usize {
        self.txs.len()
    }

    /// Remove all transactions and reset all indexes.
    pub fn clear(&mut self) {
        self.txs.clear();
        self.by_sender.clear();
        self.by_arrival_time.clear();
        self.hash_to_arrival_seq.clear();
        self.timestamps.clear();
        self.arrival_sequence = 0;
    }

    /// Return all transactions (order unspecified).
    pub fn all_transactions(&self) -> Vec<Transaction> {
        self.txs.values().cloned().collect()
    }

    // Index-based lookups

    /// All transactions from a given sender, ordered by nonce (ascending).
    pub fn transactions_by_sender(&self, sender: &Address) -> Vec<Transaction> {
        self.by_sender
            .get(sender)
            .into_iter()
            .flat_map(|nonces| nonces.values())
            .filter_map(|hash| self.txs.get(hash))
            .cloned()
            .collect()
    }

    /// All transactions in arrival order (oldest first).
    pub fn transactions_by_arrival_time(&self) -> Vec<Transaction> {
        self.by_arrival_time
            .values()
            .filter_map(|hash| self.txs.get(hash))
            .cloned()
            .collect()
    }

    /// Return the hash of the transaction from `sender` with `nonce`, if any.
    pub fn lookup_by_sender_and_nonce(&self, sender: &Address, nonce: u64) -> Option<Hash> {
        self.by_sender
            .get(sender)
            .and_then(|nonces| nonces.get(&nonce))
            .copied()
    }

    /// Number of pending transactions from a given sender.
    pub fn sender_transaction_count(&self, sender: &Address) -> usize {
        self.by_sender
            .get(sender)
            .map(|nonces| nonces.len())
            .unwrap_or(0)
    }

    /// `true` if the pool contains a transaction from `sender` at `nonce`.
    pub fn contains_sender_nonce(&self, sender: &Address, nonce: u64) -> bool {
        self.lookup_by_sender_and_nonce(sender, nonce).is_some()
    }

    // - Replace-by-fee -

    /// Return an error if `replacement` does not offer a strictly higher gas
    /// price than `existing`.
    pub fn validate_replacement_gas_price(
        &self,
        existing: &Transaction,
        replacement: &Transaction,
    ) -> Result<()> {
        if replacement.gas_price <= existing.gas_price {
            return Err(MempoolError::ReplaceByFeeRejected {
                replacement: replacement.gas_price.to_string(),
                incumbent: existing.gas_price.to_string(),
            }
            .into());
        }
        Ok(())
    }

    // Private index helpers

    fn remove_from_sender_index(&mut self, sender: Address, nonce: u64) {
        if let Some(nonces) = self.by_sender.get_mut(&sender) {
            nonces.remove(&nonce);
            if nonces.is_empty() {
                self.by_sender.remove(&sender);
            }
        }
    }

    fn remove_from_arrival_index(&mut self, hash: &Hash) {
        if let Some(seq) = self.hash_to_arrival_seq.remove(hash) {
            self.by_arrival_time.remove(&seq);
        }
    }

    pub fn arrival_seq_for_hash(&self, hash: &Hash) -> Option<u64> {
        self.hash_to_arrival_seq.get(hash).copied()
    }

    // Convenience aliases used by Mempool

    pub fn len(&self) -> usize {
        self.size()
    }

    pub fn is_empty(&self) -> bool {
        self.size() == 0
    }

    pub fn add(&mut self, tx: Transaction) -> Result<Hash> {
        self.insert(tx)
    }

    pub fn get_top_n(&self, n: usize) -> Vec<Transaction> {
        self.block_selection_ordering(n)
    }

    pub fn remove_many(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove(hash);
        }
    }

    /// The transaction with the lowest priority (candidate for eviction).
    /// Priority key (ascending worst-first): gas_price asc, arrival_seq desc,
    /// sender desc, nonce desc, hash desc - fully deterministic.
    pub fn lowest_priority_transaction(&self) -> Option<(Hash, Transaction)> {
        self.txs
            .iter()
            .filter_map(|(hash, tx)| {
                let seq = self.arrival_seq_for_hash(hash)?;
                Some((*hash, tx.gas_price, tx.from, tx.nonce, seq))
            })
            .min_by(|a, b| {
                a.1.cmp(&b.1) // lowest gas price first (worst)
                    .then_with(|| b.4.cmp(&a.4)) // latest arrival first (worst)
                    .then_with(|| b.2.cmp(&a.2)) // highest sender addr first (worst)
                    .then_with(|| b.3.cmp(&a.3)) // highest nonce first (worst)
                    .then_with(|| b.0.cmp(&a.0)) // lexicographically largest hash
            })
            .and_then(|(hash, _, _, _, _)| self.txs.get(&hash).cloned().map(|tx| (hash, tx)))
    }

    /// All transactions in deterministic priority order (best first).
    ///
    /// Sort key (descending best-first):
    ///   1. gas_price DESC  - higher fee preferred
    ///   2. arrival_seq ASC - earlier arrival preferred among equals
    ///   3. sender ASC      - tie-break by address for determinism
    ///   4. nonce ASC       - lower nonce executes first within a sender
    ///   5. hash ASC        - final byte-level tie-break
    pub fn prioritized_transactions(&self) -> Vec<Transaction> {
        let mut ordered: Vec<(U256, u64, Address, u64, Hash)> = self
            .txs
            .iter()
            .filter_map(|(hash, tx)| {
                let seq = self.arrival_seq_for_hash(hash)?;
                Some((tx.gas_price, seq, tx.from, tx.nonce, *hash))
            })
            .collect();

        ordered.sort_by(|a, b| {
            b.0.cmp(&a.0) // gas_price DESC
                .then_with(|| a.1.cmp(&b.1)) // arrival_seq ASC
                .then_with(|| a.2.cmp(&b.2)) // sender ASC
                .then_with(|| a.3.cmp(&b.3)) // nonce ASC
                .then_with(|| a.4.cmp(&b.4)) // hash ASC
        });

        ordered
            .into_iter()
            .filter_map(|(_, _, _, _, hash)| self.txs.get(&hash).cloned())
            .collect()
    }

    // - TTL / timestamp helpers -

    /// Return the wall-clock insertion timestamp (Unix seconds) for `hash`.
    pub fn transaction_timestamp(&self, hash: &Hash) -> Option<u64> {
        self.timestamps.get(hash).copied()
    }

    /// Return the hashes of all transactions older than `ttl_secs` seconds.
    pub fn expired_transactions(&self, ttl_secs: u64, now: u64) -> Vec<Hash> {
        self.timestamps
            .iter()
            .filter_map(|(hash, ts)| (now.saturating_sub(*ts) >= ttl_secs).then_some(*hash))
            .collect()
    }

    /// Remove all transactions whose TTL has elapsed and return their hashes.
    pub fn remove_expired_transactions(&mut self, ttl_secs: u64, now: u64) -> Vec<Hash> {
        let expired = self.expired_transactions(ttl_secs, now);
        self.remove_many(&expired);
        expired
    }

    /// Select up to `limit` transactions suitable for a block proposal.
    ///
    /// Rules enforced:
    /// - Transactions are visited in priority order (see `prioritized_transactions`).
    /// - Per sender, transactions are admitted strictly in gap-free ascending nonce
    ///   order starting from the lowest pending nonce in the pool.
    /// - Multi-pass selection ensures higher-gas descendant transactions are not
    ///   skipped when evaluating parent transactions.
    /// - Selection stops once `limit` is reached.
    pub fn block_selection_ordering(&self, limit: usize) -> Vec<Transaction> {
        let mut selected = Vec::with_capacity(limit);
        let mut last_nonce_per_sender: HashMap<Address, u64> = HashMap::new();
        let mut included_hashes: HashSet<Hash> = HashSet::new();

        let prioritized = self.prioritized_transactions();

        loop {
            let mut progress = false;
            for tx in &prioritized {
                if selected.len() >= limit {
                    break;
                }
                let hash = match tx.try_hash() {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if included_hashes.contains(&hash) {
                    continue;
                }

                let is_valid_nonce = match last_nonce_per_sender.get(&tx.from).copied() {
                    None => {
                        let min_nonce = self
                            .by_sender
                            .get(&tx.from)
                            .and_then(|nonces| nonces.keys().next().copied());
                        min_nonce == Some(tx.nonce)
                    }
                    Some(last) => tx.nonce == last.saturating_add(1),
                };

                if is_valid_nonce {
                    last_nonce_per_sender.insert(tx.from, tx.nonce);
                    included_hashes.insert(hash);
                    selected.push(tx.clone());
                    progress = true;
                }
            }

            if !progress || selected.len() >= limit {
                break;
            }
        }

        selected
    }
}

impl Default for TransactionPool {
    fn default() -> Self {
        Self::new()
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_tx(from: Address, to: Address, nonce: u64, gas_price: u64) -> Transaction {
        let mut tx = Transaction::new_transfer(from, to, U256::from(100), nonce);
        tx.gas_price = U256::from(gas_price);
        tx
    }

    #[test]
    fn test_pool_insert_remove_and_indices() {
        let mut pool = TransactionPool::new();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);

        let tx1 = make_test_tx(addr1, addr2, 0, 10);
        let hash1 = pool.insert(tx1.clone()).unwrap();

        assert_eq!(pool.size(), 1);
        assert!(pool.contains(&hash1));
        assert_eq!(pool.get(&hash1).unwrap().nonce, 0);

        let by_sender = pool.transactions_by_sender(&addr1);
        assert_eq!(by_sender.len(), 1);

        let removed = pool.remove(&hash1);
        assert!(removed.is_some());
        assert_eq!(pool.size(), 0);
        assert!(!pool.contains(&hash1));
        assert!(pool.transactions_by_sender(&addr1).is_empty());
    }

    #[test]
    fn test_replace_by_fee() {
        let mut pool = TransactionPool::new();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);

        let tx_low = make_test_tx(addr1, addr2, 0, 10);
        let hash_low = pool.insert(tx_low).unwrap();

        // Replacement with lower or equal gas price -> error
        let tx_equal = make_test_tx(addr1, addr2, 0, 10);
        assert!(pool.insert(tx_equal).is_err());

        // Replacement with higher gas price -> success
        let tx_high = make_test_tx(addr1, addr2, 0, 20);
        let hash_high = pool.insert(tx_high).unwrap();

        assert_ne!(hash_low, hash_high);
        assert_eq!(pool.size(), 1);
        assert_eq!(pool.get(&hash_high).unwrap().gas_price, U256::from(20));
    }

    #[test]
    fn test_block_selection_gap_free_ordering() {
        let mut pool = TransactionPool::new();
        let addr1 = Address([1u8; 32]);
        let addr2 = Address([2u8; 32]);

        // Senders with various nonces and gas prices
        let tx1 = make_test_tx(addr1, addr2, 0, 50); // sender 1, nonce 0 (highest gas price)
        let tx2 = make_test_tx(addr1, addr2, 1, 40); // sender 1, nonce 1 (consecutive)
        let tx3 = make_test_tx(addr2, addr1, 0, 35); // sender 2, nonce 0
        let tx4 = make_test_tx(addr1, addr2, 3, 30); // sender 1, nonce 3 (gap! nonce 2 missing)

        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();
        pool.insert(tx3).unwrap();
        pool.insert(tx4).unwrap();

        let selected = pool.block_selection_ordering(10);
        // tx4 should NOT be included because nonce 2 is missing (gap-free invariant)
        assert_eq!(selected.len(), 3);
        assert_eq!(selected[0].from, addr1);
        assert_eq!(selected[0].nonce, 0);
        assert_eq!(selected[1].from, addr1);
        assert_eq!(selected[1].nonce, 1);
        assert_eq!(selected[2].from, addr2);
        assert_eq!(selected[2].nonce, 0);
    }
}
