/// Commit-reveal ordering scheme for MEV protection.
///
/// Flow:
///   1. Sender broadcasts a `CommitTransaction` containing only a hash commitment.
///   2. The mempool stores the commit and waits for the reveal window.
///   3. Within the window, sender broadcasts a `RevealTransaction` containing the
///      pre-image (original transaction + nonce).
///   4. The mempool matches the reveal against the stored commit hash, validates
///      the pre-image, and promotes the transaction to the ready pool.
///   5. The block builder picks from the *revealed* set in randomized order,
///      preventing gas-price front-running (items 11-12).
use crate::error::MempoolError;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Hash, ReservationId, Transaction};
use tracing::{debug, info, warn};

// - storage keys -

const COMMIT_PREFIX: &[u8] = b"cr:commit:";
const REVEAL_PREFIX: &[u8] = b"cr:reveal:";
const SEEN_COMMITS_PREFIX: &[u8] = b"cr:seen:";
const MAX_PENDING_COMMITS: usize = 10_000;

// - item 1: CommitTransaction struct -

/// The payload a sender broadcasts during the *commit* phase.
/// It contains only a cryptographic commitment to the real transaction -
/// hiding the transaction data until reveal (item 13).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitTransaction {
    /// SHA-256(reveal_nonce || tx_hash) - the commitment (item 2).
    pub commit_hash: [u8; 32],
    /// The sender's address (not hidden; needed for spam-rate limiting).
    pub sender: [u8; 32],
    /// Block height at which this commit was submitted.
    pub submitted_at: u64,
    /// Block height after which the commit expires (item 14).
    pub expires_at: u64,
    /// Unique commit ID = SHA-256(commit_hash || sender || submitted_at).
    pub id: [u8; 32],
    /// SECURITY (C-13): sender's Ed25519 public key. Must hash-derive to
    /// `sender`; binds the signature below to the claimed identity.
    #[serde(default)]
    pub pubkey: Option<[u8; 32]>,
    /// SECURITY (C-13): Ed25519 signature over [`CommitTransaction::signing_payload`].
    /// Without it any peer could spoof a victim as `sender` and jam their
    /// commit slots for the full expiry window.
    #[serde(with = "serde_sig64", default = "default_commit_signature")]
    pub signature: [u8; 64],
}

fn default_commit_signature() -> [u8; 64] {
    [0u8; 64]
}

/// Serde support for fixed 64-byte signatures (byte-sequence wire format).
mod serde_sig64 {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig.as_slice())
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| Error::custom("expected 64 bytes"))
    }
}

impl CommitTransaction {
    pub fn new(
        commit_hash: [u8; 32],
        sender: [u8; 32],
        submitted_at: u64,
        reveal_window: u64,
        commit_expiry: u64,
    ) -> Self {
        let expires_at = submitted_at
            .saturating_add(reveal_window)
            .saturating_add(commit_expiry);
        let mut c = Self {
            commit_hash,
            sender,
            submitted_at,
            expires_at,
            id: [0u8; 32],
            pubkey: None,
            signature: default_commit_signature(),
        };
        c.id = c.compute_id();
        c
    }

    /// Canonical byte sequence committed to by `signature`.
    pub fn signing_payload(&self) -> Vec<u8> {
        const DOMAIN: &[u8] = b"sxiaum:mempool:commit:v1";
        let mut payload = Vec::with_capacity(DOMAIN.len() + 32 + 32 + 8 + 8 + 32);
        payload.extend_from_slice(DOMAIN);
        payload.extend_from_slice(&self.commit_hash);
        payload.extend_from_slice(&self.sender);
        payload.extend_from_slice(&self.submitted_at.to_be_bytes());
        payload.extend_from_slice(&self.expires_at.to_be_bytes());
        // NOTE: `id` is derived from the fields above, so excluding it keeps
        // the signed preimage minimal and non-circular.
        payload
    }

    /// Sign this commit with the given Ed25519 key. The key must correspond
    /// to `sender`.
    pub fn sign(&mut self, private_key: &sxiaum_crypto::ed25519::PrivateKey) -> Result<()> {
        let pubkey = private_key.public_key().0;
        if Address::from_public_key(&pubkey).as_bytes() != &self.sender {
            anyhow::bail!(
                "commit signing key does not correspond to sender 0x{}",
                hex::encode(self.sender)
            );
        }
        self.pubkey = Some(pubkey);
        let signature =
            sxiaum_crypto::ed25519::sign(private_key.as_bytes(), &self.signing_payload());
        self.signature = signature.0;
        Ok(())
    }

    /// SECURITY (C-13): verify that this commit is cryptographically bound
    /// to its claimed sender.
    pub fn verify_signature(&self) -> Result<()> {
        let pubkey = self.pubkey.ok_or(MempoolError::UnsignedCommitRejected)?;
        if Address::from_public_key(&pubkey).as_bytes() != &self.sender {
            return Err(MempoolError::InvalidCommitSignature.into());
        }
        if !sxiaum_crypto::ed25519::verify(&pubkey, &self.signing_payload(), &self.signature) {
            return Err(MempoolError::InvalidCommitSignature.into());
        }
        Ok(())
    }

    pub fn compute_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.commit_hash);
        h.update(self.sender);
        h.update(self.submitted_at.to_le_bytes());
        h.finalize().into()
    }

    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as sxiaum_types::Canonical>::try_encode(self)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        <Self as sxiaum_types::Canonical>::try_encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as sxiaum_types::Canonical>::decode(bytes)
    }
}

// - RevealTransaction -

/// The payload a sender broadcasts during the *reveal* phase.
/// It contains the original transaction and the randomness used to build the
/// commit hash, so the mempool can re-derive and verify the commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealTransaction {
    /// The commit ID this reveal corresponds to.
    pub commit_id: [u8; 32],
    /// The actual transaction being revealed.
    pub transaction: Transaction,
    /// The random nonce used during commit: commit_hash = SHA-256(nonce || tx_hash).
    pub reveal_nonce: [u8; 32],
    /// Block height at which this reveal was submitted.
    pub revealed_at: u64,
}

impl RevealTransaction {
    pub fn new(
        commit_id: [u8; 32],
        transaction: Transaction,
        reveal_nonce: [u8; 32],
        revealed_at: u64,
    ) -> Self {
        Self {
            commit_id,
            transaction,
            reveal_nonce,
            revealed_at,
        }
    }

    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as sxiaum_types::Canonical>::try_encode(self)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        <Self as sxiaum_types::Canonical>::try_encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as sxiaum_types::Canonical>::decode(bytes)
    }
}

// - item 2: hash transaction payload -

/// Compute the commitment: SHA-256(reveal_nonce || tx_hash).
pub fn compute_commit_hash_from_tx_hash(reveal_nonce: &[u8; 32], tx_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(reveal_nonce);
    h.update(tx_hash);
    h.finalize().into()
}

/// Fallible commitment derivation: returns an error if tx serialization fails.
///
/// SECURITY: commitment derivation is deliberately fallible. A previous
/// infallible wrapper silently substituted a weaker digest
/// (`SHA-256(nonce || sender || nonce)`) whenever transaction hashing failed,
/// which would have bound the commitment to attacker-influenced metadata
/// instead of the actual transaction bytes. Callers must handle the error.
pub fn try_compute_commit_hash(reveal_nonce: &[u8; 32], tx: &Transaction) -> Result<[u8; 32]> {
    let tx_hash = tx
        .try_hash()
        .map_err(|e| MempoolError::HashingFailed(e.to_string()))?;
    Ok(compute_commit_hash_from_tx_hash(reveal_nonce, &tx_hash))
}

// - config -

#[derive(Clone, Debug)]
pub struct CommitRevealConfig {
    /// The required base fee to submit a commit transaction.
    pub commit_fee: u128,
    /// Number of blocks a sender has to submit their reveal after committing (item 5).
    pub reveal_window_blocks: u64,
    /// Additional blocks after the reveal window before the commit is fully evicted (item 14).
    pub commit_expiry_blocks: u64,
    /// The penalty applied to a validator's stake if they fail to reveal a valid proof within the window.
    /// Configured no-show penalty in atomic units. Enforcement is not yet
    /// active; operators must not treat this field as an applied debit.
    pub no_show_slash: u64,
    /// Maximum pending commits per sender (anti-spam).
    pub max_commits_per_sender: usize,
}

// - RPC types (item 20) -

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitStatusRpc {
    pub commit_id: String,
    pub sender: String,
    pub submitted_at: u64,
    pub expires_at: u64,
    pub revealed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevealStatusRpc {
    pub commit_id: String,
    pub tx_hash: String,
    pub revealed_at: u64,
}

// - CommitRevealPool -

pub struct CommitRevealPool {
    pub(crate) config: CommitRevealConfig,
    storage: Arc<StorageEngine>,
    /// pending commits by commit_id (item 4).
    pending_commits: HashMap<[u8; 32], CommitTransaction>,
    /// reveals queued for a later block height.
    queued_reveals: HashMap<[u8; 32], RevealTransaction>,
    /// revealed + validated transactions ready for block inclusion (item 10).
    revealed_txs: VecDeque<(CommitTransaction, Transaction)>,
    /// Transactions reserved per active reservation handle.
    reserved_txs: HashMap<ReservationId, Vec<(CommitTransaction, Transaction)>>,
    /// Currently reserved transaction hashes across all active handles (for dedup).
    active_reserved_hashes: HashSet<[u8; 32]>,
    /// Monotonically increasing reservation identifier.
    next_reservation_id: u64,
    /// commit IDs that have been revealed (for lookup).
    revealed_ids: HashSet<[u8; 32]>,
    /// commit_ids pending per sender for spam limiting.
    sender_commit_count: HashMap<[u8; 32], usize>,
    /// The Merkle root of all pending commit hashes (item 18).
    commit_root: [u8; 32],
    /// Current block height (updated by caller on each block).
    current_height: u64,
}

impl CommitRevealPool {
    pub fn new(config: CommitRevealConfig, storage: Arc<StorageEngine>) -> Self {
        Self {
            config,
            storage,
            pending_commits: HashMap::new(),
            queued_reveals: HashMap::new(),
            revealed_txs: VecDeque::new(),
            reserved_txs: HashMap::new(),
            active_reserved_hashes: HashSet::new(),
            next_reservation_id: 1,
            revealed_ids: HashSet::new(),
            sender_commit_count: HashMap::new(),
            commit_root: [0u8; 32],
            current_height: 0,
        }
    }

    /// Advance the pool's view of the current chain height, evict expired commits,
    /// and release queued reveals. Returns all newly released `RevealTransaction`s.
    pub fn on_new_block(&mut self, height: u64) -> Result<Vec<RevealTransaction>> {
        self.current_height = height;
        self.drop_unrevealed_commits()?; // item 15
        let released = self.release_ready_reveals()?;

        // Bound replay-marker storage growth (every 64 blocks is ample).
        if height.is_multiple_of(64) {
            self.prune_seen_commits()?;
        }
        Ok(released)
    }

    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    pub fn commit_for_transaction(
        &self,
        transaction: &Transaction,
        reveal_nonce: [u8; 32],
    ) -> Result<CommitTransaction> {
        let commit_hash = try_compute_commit_hash(&reveal_nonce, transaction)?;
        // The protected-transaction path is local-only: the transaction was
        // fully validated (signature binds `from`), so the commit inherits
        // sender authenticity and is inserted via the local (unsigned)
        // commit path. Remote commits must be Ed25519-signed (C-13).
        Ok(CommitTransaction::new(
            commit_hash,
            *transaction.from.as_bytes(),
            self.current_height,
            self.config.reveal_window_blocks,
            self.config.commit_expiry_blocks,
        ))
    }

    pub fn submit_protected_transaction(
        &mut self,
        transaction: Transaction,
        reveal_nonce: [u8; 32],
    ) -> Result<(Hash, [u8; 32])> {
        let tx_hash = transaction
            .try_hash()
            .map_err(|e| MempoolError::HashingFailed(e.to_string()))?;
        let commit = self.commit_for_transaction(&transaction, reveal_nonce)?;
        let commit_id = self.insert_commit_locally(commit)?;
        let reveal = RevealTransaction::new(
            commit_id,
            transaction,
            reveal_nonce,
            self.current_height + 1,
        );
        self.queued_reveals.insert(commit_id, reveal);
        self.release_ready_reveals()?;
        Ok((tx_hash, commit_id))
    }

    // - item 3: broadcast commit transaction (returns encoded bytes) -

    // - item 4: store commit in mempool -

    /// Submit an EXTERNALLY received commit (gossip or RPC).
    ///
    /// SECURITY (C-13): the commit MUST carry a valid Ed25519 signature from
    /// its claimed sender. Previously `sender` was fully attacker-chosen, so
    /// a single gossip message could jam a victim's per-sender slots for the
    /// entire expiry window at zero cost.
    pub fn submit_commit(&mut self, commit: CommitTransaction) -> Result<[u8; 32]> {
        commit.verify_signature()?;
        self.insert_commit_locally(commit)
    }

    /// Insert a commit whose sender authenticity was established by another
    /// means. Used ONLY for locally generated commits created after the
    /// caller fully validated (signature-included) the protected transaction
    /// itself — the reveal re-validates that signature before inclusion.
    pub(crate) fn insert_commit_locally(&mut self, commit: CommitTransaction) -> Result<[u8; 32]> {
        if self.pending_commits.len() >= MAX_PENDING_COMMITS {
            return Err(MempoolError::PendingCommitCapacityExceeded(MAX_PENDING_COMMITS).into());
        }
        if commit.id != commit.compute_id() {
            return Err(MempoolError::InvalidCommitId.into());
        }
        let expected_expiry = commit
            .submitted_at
            .saturating_add(self.config.reveal_window_blocks)
            .saturating_add(self.config.commit_expiry_blocks);
        if commit.expires_at != expected_expiry {
            return Err(MempoolError::InvalidCommitExpiry.into());
        }
        // item 16: prevent replay - reject if we have seen this commit_id before
        if self.is_seen_commit(&commit.id)? {
            return Err(MempoolError::ReplayCommitRejected(hex::encode(commit.id)).into());
        }

        // item 17: anti-front-running - reject commits submitted too late
        // (commit must arrive at or before its submitted_at height + 1)
        if commit.submitted_at > self.current_height.saturating_add(1) {
            return Err(MempoolError::FutureCommitSubmission {
                submitted_at: commit.submitted_at,
                current_height: self.current_height,
            }
            .into());
        }
        if commit.submitted_at.saturating_add(1) < self.current_height {
            return Err(MempoolError::StaleCommitSubmission {
                submitted_at: commit.submitted_at,
                current_height: self.current_height,
            }
            .into());
        }
        if self.detect_front_running(&commit) {
            return Err(MempoolError::FrontRunningDetected.into());
        }

        // Spam guard per sender (checked before any state mutation).
        let sender_count = self
            .sender_commit_count
            .get(&commit.sender)
            .copied()
            .unwrap_or(0);
        if sender_count >= self.config.max_commits_per_sender {
            return Err(MempoolError::SenderCommitLimitExceeded {
                sender: hex::encode(commit.sender),
                limit: self.config.max_commits_per_sender,
            }
            .into());
        }

        // Persist to storage BEFORE mutating in-memory counters: if the
        // storage write fails, the sender's spam budget must not be silently
        // consumed by an operation that never took effect.
        let key = commit_storage_key(&commit.id);
        self.storage
            .state_put(key, commit.encode()?)
            .map_err(|e| MempoolError::Storage(e.to_string()))?;

        // Mark as seen (item 16), recording submitted_at so replay markers can
        // be pruned once every possible commit with that height has expired.
        self.mark_seen_commit(&commit.id, commit.submitted_at)?;

        self.sender_commit_count
            .insert(commit.sender, sender_count + 1);

        let id = commit.id;
        self.pending_commits.insert(id, commit);

        // Recompute commit root (item 18)
        self.recompute_commit_root();

        info!(
            "commit {:?} stored; pool size={}",
            id,
            self.pending_commits.len()
        );
        metrics::counter!("mev.commit.received").increment(1);
        Ok(id)
    }

    // - item 5: wait reveal window / item 6: submit reveal transaction -

    /// Restore pending commits and revealed transactions from storage upon restart.
    pub fn restore_from_storage(&mut self) -> Result<()> {
        let commit_entries = self
            .storage
            .state_prefix_scan(COMMIT_PREFIX.to_vec())
            .map_err(|e| MempoolError::Storage(e.to_string()))?;
        let mut expired_keys = Vec::new();
        for (key, val) in commit_entries {
            if let Ok(commit) = CommitTransaction::decode(&val) {
                if self.is_commit_expired(&commit) {
                    expired_keys.push((key, None));
                } else {
                    let sender_count = self.sender_commit_count.entry(commit.sender).or_insert(0);
                    *sender_count = sender_count.saturating_add(1);
                    self.pending_commits.insert(commit.id, commit);
                }
            }
        }

        let reveal_entries = self
            .storage
            .state_prefix_scan(REVEAL_PREFIX.to_vec())
            .map_err(|e| MempoolError::Storage(e.to_string()))?;
        for (_key, val) in reveal_entries {
            if let Ok(reveal) = RevealTransaction::decode(&val) {
                let commit = if let Some(c) = self.pending_commits.remove(&reveal.commit_id) {
                    if let Some(count) = self.sender_commit_count.get_mut(&c.sender) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.sender_commit_count.remove(&c.sender);
                        }
                    }
                    c
                } else {
                    let commit_hash =
                        match try_compute_commit_hash(&reveal.reveal_nonce, &reveal.transaction) {
                            Ok(h) => h,
                            // Unrecoverable bookkeeping entry: skip it rather
                            // than fabricating a commitment from partial data.
                            Err(_) => continue,
                        };
                    CommitTransaction::new(
                        commit_hash,
                        *reveal.transaction.from.as_bytes(),
                        reveal.revealed_at.saturating_sub(1),
                        self.config.reveal_window_blocks,
                        self.config.commit_expiry_blocks,
                    )
                };
                self.revealed_ids.insert(reveal.commit_id);
                self.revealed_txs.push_back((commit, reveal.transaction));
            }
        }

        if !expired_keys.is_empty() {
            let _ = self.storage.atomic_state_commit(expired_keys);
        }

        self.recompute_commit_root();
        Ok(())
    }

    pub fn submit_reveal(&mut self, reveal: RevealTransaction) -> Result<()> {
        // item 5: enforce reveal window - must arrive within reveal_window_blocks
        let commit = self
            .pending_commits
            .get(&reveal.commit_id)
            .ok_or_else(|| MempoolError::CommitNotFound(hex::encode(reveal.commit_id)))?
            .clone();

        let deadline = commit
            .submitted_at
            .saturating_add(self.config.reveal_window_blocks);
        if self.current_height < commit.submitted_at
            || self.current_height > deadline
            || reveal.revealed_at > deadline
        {
            return Err(MempoolError::RevealTimeout {
                revealed_at: reveal.revealed_at,
                deadline,
            }
            .into());
        }

        // item 7: match reveal with commit hash
        self.verify_reveal_matches_commit(&reveal, &commit)?;

        // item 19: verify reveal validity during execution
        self.verify_reveal_validity(&reveal)?;

        // Promote to revealed set
        let reveal_key = reveal_storage_key(&reveal.commit_id);
        let bytes = reveal.try_encode()?;
        self.storage
            .state_put(reveal_key, bytes)
            .map_err(|e| MempoolError::Storage(e.to_string()))?;

        // Clean up commit from storage as it is now revealed
        let commit_key = commit_storage_key(&commit.id);
        let _ = self.storage.atomic_state_commit(vec![(commit_key, None)]);

        self.revealed_ids.insert(commit.id);
        self.revealed_txs
            .push_back((commit.clone(), reveal.transaction));

        // Decrement sender count
        if let Some(count) = self.sender_commit_count.get_mut(&commit.sender) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.sender_commit_count.remove(&commit.sender);
            }
        }
        self.pending_commits.remove(&reveal.commit_id);
        self.recompute_commit_root();

        let time_to_reveal = reveal.revealed_at.saturating_sub(commit.submitted_at);
        metrics::histogram!("mev.reveal.latency.blocks").record(time_to_reveal as f64);
        metrics::counter!("mev.reveal.success").increment(1);

        debug!("reveal accepted for commit {:?}", reveal.commit_id);
        Ok(())
    }

    pub fn release_ready_reveals(&mut self) -> Result<Vec<RevealTransaction>> {
        let ready_ids: Vec<[u8; 32]> = self
            .queued_reveals
            .iter()
            .filter_map(|(commit_id, reveal)| {
                (reveal.revealed_at <= self.current_height).then_some(*commit_id)
            })
            .collect();

        let mut released = Vec::new();
        for commit_id in ready_ids {
            if let Some(reveal) = self.queued_reveals.remove(&commit_id) {
                if let Err(e) = self.submit_reveal(reveal.clone()) {
                    warn!(
                        "queued reveal for commit {:?} rejected during release: {}",
                        commit_id, e
                    );
                    metrics::counter!("mev.reveal.rejected").increment(1);
                } else {
                    released.push(reveal);
                }
            }
        }

        Ok(released)
    }

    // - item 7: match reveal with commit hash -

    pub fn verify_reveal_matches_commit(
        &self,
        reveal: &RevealTransaction,
        commit: &CommitTransaction,
    ) -> Result<()> {
        let computed = try_compute_commit_hash(&reveal.reveal_nonce, &reveal.transaction)?;
        if computed != commit.commit_hash {
            return Err(MempoolError::RevealCommitMismatch {
                expected: hex::encode(commit.commit_hash),
                computed: hex::encode(computed),
            }
            .into());
        }
        Ok(())
    }

    // - item 10: build block using revealed transactions -

    pub fn build_block_transactions(
        &mut self,
        limit: usize,
        parent_hash: &[u8; 32],
        beacon_randomness: &[u8; 32],
    ) -> (Vec<Transaction>, ReservationId) {
        let mut pairs = Vec::with_capacity(limit);
        let mut skipped = Vec::new();

        while pairs.len() < limit {
            match self.revealed_txs.pop_front() {
                Some(pair) => {
                    let tx_hash = match pair.1.try_hash() {
                        Ok(h) => h,
                        Err(_) => continue,
                    };
                    if self.active_reserved_hashes.contains(&tx_hash) {
                        skipped.push(pair);
                    } else {
                        pairs.push(pair);
                    }
                }
                None => break,
            }
        }

        // Put skipped transactions back to the front of revealed_txs
        for pair in skipped.into_iter().rev() {
            self.revealed_txs.push_front(pair);
        }

        if pairs.is_empty() {
            return (Vec::new(), ReservationId(0));
        }

        // 1. Sort deterministically by commit_hash
        pairs.sort_unstable_by(|a, b| a.0.commit_hash.cmp(&b.0.commit_hash));

        // 2. Compute the deterministic ordering seed
        let mut hasher = Sha256::new();
        hasher.update(parent_hash);
        hasher.update(self.current_height.to_le_bytes());
        hasher.update(beacon_randomness);
        let seed: [u8; 32] = hasher.finalize().into();

        // 3. Apply randomized execution ordering (item 11) using the seed
        randomize_ordering(&mut pairs, &seed, self.current_height);

        // 4. Enforce intra-sender strictly ascending nonces across the randomized slots allocated to each sender
        let mut sender_slots: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
        for (idx, (commit, _)) in pairs.iter().enumerate() {
            sender_slots.entry(commit.sender).or_default().push(idx);
        }
        for (_, slots) in sender_slots {
            if slots.len() > 1 {
                let mut sender_pairs: Vec<(CommitTransaction, Transaction)> =
                    slots.iter().map(|&i| pairs[i].clone()).collect();
                sender_pairs.sort_by_key(|(_, tx)| tx.nonce);
                for (slot, pair) in slots.into_iter().zip(sender_pairs) {
                    pairs[slot] = pair;
                }
            }
        }

        let res_id = ReservationId(self.next_reservation_id);
        self.next_reservation_id = self.next_reservation_id.saturating_add(1);

        for (_, tx) in &pairs {
            if let Ok(h) = tx.try_hash() {
                self.active_reserved_hashes.insert(h);
            }
        }

        self.reserved_txs.insert(res_id, pairs.clone());
        let txs = pairs.into_iter().map(|(_, tx)| tx).collect();
        (txs, res_id)
    }

    pub fn release_reserved_transactions(&mut self, res_id: ReservationId) {
        if let Some(pairs) = self.reserved_txs.remove(&res_id) {
            for (_, tx) in &pairs {
                if let Ok(h) = tx.try_hash() {
                    self.active_reserved_hashes.remove(&h);
                }
            }
            for pair in pairs.into_iter().rev() {
                self.revealed_txs.push_front(pair);
            }
        }
    }

    pub fn acknowledge_transactions(&mut self, hashes: &HashSet<[u8; 32]>) {
        let mut keys_to_delete = Vec::new();
        let mut acked_commit_ids = Vec::new();

        for h in hashes {
            self.active_reserved_hashes.remove(h);
        }

        let mut retain_pair = |commit: &CommitTransaction,
                               tx: &Transaction,
                               acked_commit_ids: &mut Vec<[u8; 32]>|
         -> bool {
            let is_ack = tx
                .try_hash()
                .map(|hash| hashes.contains(&hash))
                .unwrap_or(false);
            if is_ack {
                keys_to_delete.push((reveal_storage_key(&commit.id), None));
                keys_to_delete.push((commit_storage_key(&commit.id), None));
                acked_commit_ids.push(commit.id);
            }
            !is_ack
        };

        // First pass over reserved handles (immutable borrow for collection).
        let mut reserved_updates: HashMap<ReservationId, Vec<(CommitTransaction, Transaction)>> =
            HashMap::new();
        for (res_id, pairs) in self.reserved_txs.iter() {
            let kept: Vec<(CommitTransaction, Transaction)> = pairs
                .iter()
                .filter(|(commit, tx)| retain_pair(commit, tx, &mut acked_commit_ids))
                .cloned()
                .collect();
            reserved_updates.insert(*res_id, kept);
        }
        for (res_id, kept) in reserved_updates {
            if kept.is_empty() {
                self.reserved_txs.remove(&res_id);
            } else {
                self.reserved_txs.insert(res_id, kept);
            }
        }

        self.revealed_txs
            .retain(|(commit, tx)| retain_pair(commit, tx, &mut acked_commit_ids));

        // Included reveals are permanently settled: drop their ids so the
        // in-memory revealed set stays bounded.
        for id in acked_commit_ids {
            self.revealed_ids.remove(&id);
        }

        if !keys_to_delete.is_empty() {
            let _ = self.storage.atomic_state_commit(keys_to_delete);
        }
    }

    pub fn get_revealed_transaction(&self, tx_hash: [u8; 32]) -> Option<Transaction> {
        self.revealed_txs
            .iter()
            .chain(self.reserved_txs.values().flatten())
            .find_map(|(_, tx)| (tx.try_hash().ok() == Some(tx_hash)).then(|| tx.clone()))
    }

    // - item 14: enforce commit expiry -

    pub fn is_commit_expired(&self, commit: &CommitTransaction) -> bool {
        self.current_height > commit.expires_at
    }

    // - item 15: drop unrevealed commits -

    pub fn drop_unrevealed_commits(&mut self) -> Result<()> {
        let expired_ids: Vec<[u8; 32]> = self
            .pending_commits
            .values()
            .filter(|c| self.is_commit_expired(c))
            .map(|c| c.id)
            .collect();

        let mut dropped = 0usize;
        let mut keys_to_delete = Vec::new();
        for id in &expired_ids {
            if let Some(commit) = self.pending_commits.remove(id) {
                if let Some(count) = self.sender_commit_count.get_mut(&commit.sender) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.sender_commit_count.remove(&commit.sender);
                    }
                }
                self.queued_reveals.remove(id);
                // The commit was never revealed, so its revealed marker (if
                // any bookkeeping slipped) is meaningless — drop it.
                self.revealed_ids.remove(id);
                keys_to_delete.push((commit_storage_key(id), None));
                warn!(
                    "dropped unrevealed commit {:?} (expired at {})",
                    id, commit.expires_at
                );
                dropped += 1;
            }
        }

        if !keys_to_delete.is_empty() {
            let _ = self.storage.atomic_state_commit(keys_to_delete);
        }

        if dropped > 0 {
            metrics::counter!("mev.commit.dropped").increment(dropped as u64);
            self.recompute_commit_root();
        }
        Ok(())
    }

    // - item 16: prevent replay attacks -

    fn is_seen_commit(&self, id: &[u8; 32]) -> Result<bool> {
        let key = seen_commit_key(id);
        self.storage
            .state_get(key)
            .map(|opt| opt.is_some())
            .map_err(|e| MempoolError::Storage(e.to_string()).into())
    }

    /// Mark a commit id as seen, storing `submitted_at` so the marker can be
    /// pruned once every commit bearing that height has certainly expired.
    fn mark_seen_commit(&self, id: &[u8; 32], submitted_at: u64) -> Result<()> {
        let key = seen_commit_key(id);
        self.storage
            .state_put(key, submitted_at.to_le_bytes().to_vec())
            .map_err(|e| MempoolError::Storage(e.to_string()).into())
    }

    /// Prune replay-protection markers whose commits can no longer be live.
    ///
    /// Without this the `cr:seen:` namespace grows without bound on a
    /// long-running mainnet node. A marker with `submitted_at = H` is deleted
    /// once `current_height > H + window + expiry + slack`, because any
    /// re-submission of that exact commit id would already fail the staleness
    /// check in [`Self::insert_commit_locally`].
    fn prune_seen_commits(&mut self) -> Result<()> {
        let horizon = self.current_height.saturating_sub(
            self.config
                .reveal_window_blocks
                .saturating_add(self.config.commit_expiry_blocks)
                .saturating_add(64), // slack for clock/height skew
        );
        if self.current_height <= 64 {
            return Ok(());
        }

        let entries = self
            .storage
            .state_prefix_scan(SEEN_COMMITS_PREFIX.to_vec())
            .map_err(|e| MempoolError::Storage(e.to_string()))?;

        let mut keys_to_delete = Vec::new();
        for (key, value) in entries {
            let submitted_at = match <[u8; 8]>::try_from(value.as_slice()).map(u64::from_le_bytes) {
                Ok(v) => v,
                Err(_) => {
                    // Legacy/unknown marker format: drop it once safely past
                    // the maximum possible commit lifetime.
                    keys_to_delete.push((key, None));
                    continue;
                }
            };
            if submitted_at < horizon {
                keys_to_delete.push((key, None));
            }
        }

        if !keys_to_delete.is_empty() {
            self.storage
                .atomic_state_commit(keys_to_delete)
                .map_err(|e| MempoolError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    // - item 17: anti-front-running checks -

    /// Returns `true` when the commit could be a front-running attempt.
    /// Rejects any duplicate commitment with the same commit_hash from a different sender across all pending commits.
    pub fn detect_front_running(&self, candidate: &CommitTransaction) -> bool {
        self.pending_commits.values().any(|existing| {
            existing.commit_hash == candidate.commit_hash && existing.sender != candidate.sender
        })
    }

    // - item 18: commit root in block header -

    pub fn current_commit_root(&self) -> [u8; 32] {
        self.commit_root
    }

    fn recompute_commit_root(&mut self) {
        let mut hashes: Vec<[u8; 32]> = self
            .pending_commits
            .values()
            .map(|c| c.commit_hash)
            .collect();
        // Deterministic ordering before hashing
        hashes.sort_unstable();
        let mut h = Sha256::new();
        for hash in &hashes {
            h.update(hash);
        }
        self.commit_root = h.finalize().into();
    }

    // - item 19: verify reveal validity during execution -

    pub fn verify_reveal_validity(&self, reveal: &RevealTransaction) -> Result<()> {
        // Ensure the embedded transaction is minimally valid (not zero-value no-op).
        if reveal.reveal_nonce == [0u8; 32] {
            return Err(MempoolError::ZeroRevealNonce.into());
        }
        reveal.transaction.validate_basic()?;

        // SECURITY (H-06): cryptographically verify the embedded
        // transaction's signature. `validate_basic` is structural only and
        // the `from` field below is attacker-chosen data; without signature
        // verification a crafted reveal could bind ANY signed-up-front-free
        // transaction to an honest sender's commit.
        if !reveal.transaction.verify_signature()? {
            return Err(MempoolError::InvalidSignature.into());
        }

        let commit = self
            .pending_commits
            .get(&reveal.commit_id)
            .ok_or_else(|| MempoolError::CommitNotFound(hex::encode(reveal.commit_id)))?;
        if reveal.transaction.from.as_bytes() != &commit.sender {
            return Err(MempoolError::RevealSenderMismatch {
                tx_sender: hex::encode(reveal.transaction.from),
                commit_sender: hex::encode(commit.sender),
            }
            .into());
        }
        Ok(())
    }

    /// Verify that a block's commit_root matches the pool's view (item 18 / 19).
    pub fn verify_block_commit_root(&self, block_commit_root: &[u8; 32]) -> Result<()> {
        if &self.commit_root != block_commit_root {
            return Err(MempoolError::BlockCommitRootMismatch {
                block_root: hex::encode(block_commit_root),
                pool_root: hex::encode(self.commit_root),
            }
            .into());
        }
        Ok(())
    }

    // - item 20: RPC getters -

    pub fn get_pending_commit(&self, commit_id: &[u8; 32]) -> Option<CommitTransaction> {
        self.pending_commits.get(commit_id).cloned()
    }

    pub fn contains_commit(&self, commit_id: &[u8; 32]) -> bool {
        self.pending_commits.contains_key(commit_id)
    }

    pub fn commit_status_rpc(&self, commit_id: &[u8; 32]) -> Option<CommitStatusRpc> {
        self.pending_commits
            .get(commit_id)
            .map(|c| CommitStatusRpc {
                commit_id: hex::encode(c.id),
                sender: hex::encode(c.sender),
                submitted_at: c.submitted_at,
                expires_at: c.expires_at,
                revealed: self.revealed_ids.contains(&c.id),
            })
    }

    pub fn reveal_status_rpc(&self, commit_id: &[u8; 32]) -> Option<RevealStatusRpc> {
        if !self.revealed_ids.contains(commit_id) {
            return None;
        }
        let key = reveal_storage_key(commit_id);
        let bytes = self.storage.state_get(key).ok()??;
        let reveal: RevealTransaction = RevealTransaction::decode(&bytes).ok()?;
        let tx_hash = reveal.transaction.try_hash().ok()?;
        Some(RevealStatusRpc {
            commit_id: hex::encode(commit_id),
            tx_hash: hex::encode(tx_hash),
            revealed_at: reveal.revealed_at,
        })
    }

    pub fn all_pending_commits_rpc(&self) -> Vec<CommitStatusRpc> {
        self.pending_commits
            .values()
            .map(|c| CommitStatusRpc {
                commit_id: hex::encode(c.id),
                sender: hex::encode(c.sender),
                submitted_at: c.submitted_at,
                expires_at: c.expires_at,
                revealed: self.revealed_ids.contains(&c.id),
            })
            .collect()
    }

    pub fn pending_commit_count(&self) -> usize {
        self.pending_commits.len()
    }

    pub fn revealed_tx_count(&self) -> usize {
        self.revealed_txs.len()
    }
}

// - item 11: randomization helper -

fn randomize_ordering(
    pairs: &mut [(CommitTransaction, Transaction)],
    seed: &[u8; 32],
    height: u64,
) {
    // Deterministic Fisher-Yates using SHA-256 derived pseudorandom u64s.
    let n = pairs.len();
    for i in (1..n).rev() {
        let mut h = Sha256::new();
        h.update(seed);
        h.update(height.to_le_bytes());
        h.update((i as u64).to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let mut num_bytes = [0u8; 8];
        num_bytes.copy_from_slice(&digest[..8]);
        let r = u64::from_le_bytes(num_bytes);
        let j = (r as usize) % (i + 1);
        pairs.swap(i, j);
    }
}

// - storage key helpers -

fn commit_storage_key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = COMMIT_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

fn reveal_storage_key(commit_id: &[u8; 32]) -> Vec<u8> {
    let mut key = REVEAL_PREFIX.to_vec();
    key.extend_from_slice(commit_id);
    key
}

fn seen_commit_key(id: &[u8; 32]) -> Vec<u8> {
    let mut key = SEEN_COMMITS_PREFIX.to_vec();
    key.extend_from_slice(id);
    key
}

// - tests -

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_storage::StorageEngine;
    use sxiaum_types::{Address, Transaction};

    /// Create a uniquely named storage file under the OS temp dir.
    /// The returned guard deletes the file on drop so panicking tests cannot
    /// leak `.redb` artifacts into the source tree.
    struct DbFile(PathBuf);

    impl Drop for DbFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn unique_db(name: &str) -> (DbFile, Arc<StorageEngine>) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sxiaum-ordering-{name}-{ts}.redb"));
        let storage = Arc::new(StorageEngine::new(&path).unwrap());
        (DbFile(path), storage)
    }

    fn sample_tx(nonce: u64) -> Transaction {
        Transaction::new_transfer(
            Address::from([1u8; 32]),
            Address::from([2u8; 32]),
            U256::from(1000u64),
            nonce,
        )
    }

    fn make_commit(
        tx: &Transaction,
        nonce: [u8; 32],
        signer: &sxiaum_crypto::ed25519::PrivateKey,
        height: u64,
        config: &CommitRevealConfig,
    ) -> CommitTransaction {
        let commit_hash = try_compute_commit_hash(&nonce, tx).unwrap();
        let sender = *Address::from_public_key(&signer.public_key().0).as_bytes();
        let mut commit = CommitTransaction::new(
            commit_hash,
            sender,
            height,
            config.reveal_window_blocks,
            config.commit_expiry_blocks,
        );
        // SECURITY (C-13): externally submitted commits must be signed.
        commit.sign(signer).expect("commit should sign");
        commit
    }

    pub fn mock_cr_config() -> CommitRevealConfig {
        CommitRevealConfig {
            commit_fee: 10_000_000_000_000_000,
            reveal_window_blocks: 5,
            commit_expiry_blocks: 20,
            no_show_slash: 10,
            max_commits_per_sender: 16,
        }
    }

    fn default_pool(storage: Arc<StorageEngine>) -> CommitRevealPool {
        CommitRevealPool::new(mock_cr_config(), storage)
    }

    #[test]
    fn commit_hash_is_deterministic_and_nonce_dependent() {
        let tx = sample_tx(0);
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        assert_eq!(
            try_compute_commit_hash(&nonce1, &tx).unwrap(),
            try_compute_commit_hash(&nonce1, &tx).unwrap()
        );
        assert_ne!(
            try_compute_commit_hash(&nonce1, &tx).unwrap(),
            try_compute_commit_hash(&nonce2, &tx).unwrap()
        );
    }

    #[test]
    fn submit_commit_stores_and_computes_root() {
        let (path, storage) = unique_db("submit");
        let mut pool = default_pool(storage.clone());
        let config = mock_cr_config();
        let tx = sample_tx(1);
        let nonce = [42u8; 32];
        let commit = make_commit(
            &tx,
            nonce,
            &sxiaum_crypto::ed25519::PrivateKey([9u8; 32]),
            0,
            &config,
        );
        let _id = pool.submit_commit(commit).unwrap();
        assert_eq!(pool.pending_commit_count(), 1);
        assert_ne!(pool.current_commit_root(), [0u8; 32]);
        drop(storage);
        drop(path);
    }

    #[test]
    fn unsigned_and_spoofed_commits_are_rejected() {
        let (path, storage) = unique_db("spoof");
        let mut pool = default_pool(storage.clone());
        let config = mock_cr_config();
        let tx = sample_tx(1);
        let nonce = [42u8; 32];
        let signer = sxiaum_crypto::ed25519::PrivateKey([9u8; 32]);
        let sender = *Address::from_public_key(&signer.public_key().0).as_bytes();

        // 1. Unsigned commit (zero signature) must be rejected.
        let unsigned = CommitTransaction::new(
            try_compute_commit_hash(&nonce, &tx).unwrap(),
            sender,
            0,
            config.reveal_window_blocks,
            config.commit_expiry_blocks,
        );
        assert!(pool.submit_commit(unsigned).is_err());

        // 2. Valid key but SPOOFED sender field must be rejected: the pubkey
        //    does not derive to the claimed sender.
        let victim = [0xABu8; 32];
        let mut spoofed = CommitTransaction::new(
            try_compute_commit_hash(&nonce, &tx).unwrap(),
            victim,
            0,
            config.reveal_window_blocks,
            config.commit_expiry_blocks,
        );
        assert!(
            spoofed.sign(&signer).is_err(),
            "sign must refuse to sign for a non-matching sender"
        );
        // Forge the binding manually as an attacker would: real pubkey+sig
        // over the payload, but victim as sender.
        spoofed.pubkey = Some(signer.public_key().0);
        let signature = sxiaum_crypto::ed25519::sign(signer.as_bytes(), &spoofed.signing_payload());
        spoofed.signature = signature.0;
        assert!(pool.submit_commit(spoofed).is_err());

        drop(storage);
        drop(path);
    }

    #[test]
    fn replay_commit_rejected() {
        let (path, storage) = unique_db("replay");
        let mut pool = default_pool(storage.clone());
        let config = mock_cr_config();
        let tx = sample_tx(2);
        let nonce = [3u8; 32];
        let commit = make_commit(
            &tx,
            nonce,
            &sxiaum_crypto::ed25519::PrivateKey([9u8; 32]),
            0,
            &config,
        );
        pool.submit_commit(commit.clone()).unwrap();
        assert!(pool.submit_commit(commit).is_err());
        drop(storage);
        drop(path);
    }
}
