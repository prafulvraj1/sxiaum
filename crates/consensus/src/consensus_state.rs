use crate::hotstuff::pacemaker::{NewViewMessage, Pacemaker};
use crate::hotstuff::vote::QuorumCertificate;
use crate::pos::validator_set::ValidatorSet;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use sxiaum_block::Block;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Canonical, Validator};
use tracing::{info, warn};

// - storage key constants -

const STATE_KEY: &[u8] = b"cstate:snapshot";
const LOCKED_BLOCK_KEY: &[u8] = b"cstate:locked_block";
const HIGHEST_QC_KEY: &[u8] = b"cstate:highest_qc";
const CHECKPOINT_PREFIX: &[u8] = b"cstate:checkpoint:";
const INTEGRITY_KEY: &[u8] = b"cstate:integrity";
const PROPOSAL_GUARD_KEY: &[u8] = b"cstate:proposal_guard";

// - items 1-4: ConsensusState struct -

/// Snapshot of all durable consensus state that must survive node restarts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusState {
    /// current HotStuff view - restored into Pacemaker on startup.
    pub current_view: u64,
    /// locked block hash (safety rule: never vote below this block).
    pub locked_block: Option<[u8; 32]>,
    /// highest known quorum certificate (liveness rule).
    pub highest_qc: Option<QuorumCertificate>,
    /// Height of the last finalized block (used for checkpoint / audit).
    pub finalized_height: u64,
    /// Active validator set fingerprint - used to detect inconsistency.
    pub validator_set_hash: [u8; 32],
    /// Flag set when safe-recovery mode is active.
    pub safe_recovery_mode: bool,
}

impl ConsensusState {
    pub fn new() -> Self {
        Self {
            current_view: 0,
            locked_block: None,
            highest_qc: None,
            finalized_height: 0,
            validator_set_hash: [0u8; 32],
            safe_recovery_mode: false,
        }
    }

    /// Advance the view counter (called after each round).
    pub fn advance_view(&mut self) -> u64 {
        self.current_view = self.current_view.saturating_add(1);
        self.current_view
    }

    /// Update locked block (safety lock).
    pub fn set_locked_block(&mut self, block_hash: [u8; 32]) {
        self.locked_block = Some(block_hash);
    }

    /// Update highest QC.
    pub fn set_highest_qc(&mut self, qc: QuorumCertificate) {
        self.highest_qc = Some(qc);
    }

    /// Compute a SHA-256 fingerprint of the sorted validator addresses.
    pub fn compute_validator_set_hash(validators: &[Validator]) -> [u8; 32] {
        let mut addrs: Vec<&Address> = validators.iter().map(|v| &v.address).collect();
        addrs.sort_by_key(|a| a.as_bytes());
        let mut hasher = Sha256::new();
        for addr in addrs {
            hasher.update(addr.as_bytes());
        }
        hasher.finalize().into()
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

// - items 5-6: persist + store in redb -

pub fn persist_consensus_state(storage: &StorageEngine, state: &ConsensusState) -> Result<()> {
    let snapshot = state.try_encode()?;

    // Store snapshot
    storage.state_put(STATE_KEY.to_vec(), snapshot)?;

    // Store locked block separately for fast lookup
    if let Some(locked) = state.locked_block {
        storage.state_put(LOCKED_BLOCK_KEY.to_vec(), locked.to_vec())?;
    }

    // Store highest QC separately
    if let Some(ref qc) = state.highest_qc {
        storage.state_put(HIGHEST_QC_KEY.to_vec(), qc.encode())?;
    }

    // Write integrity hash so we can detect corruption
    let integrity = compute_state_integrity(state)?;
    storage.state_put(INTEGRITY_KEY.to_vec(), integrity.to_vec())?;

    Ok(())
}

// - items 7-10: load and restore -

pub fn load_consensus_state(storage: &StorageEngine) -> Result<Option<ConsensusState>> {
    let Some(snapshot) = storage.state_get(STATE_KEY.to_vec())? else {
        return Ok(None);
    };

    let state: ConsensusState =
        ConsensusState::decode(&snapshot).or_else(|_| bincode::deserialize(&snapshot))?;

    // Verify integrity before trusting the snapshot
    verify_state_integrity(storage, &state)?;

    Ok(Some(state))
}

/// Restore pacemaker view from persisted state.
pub fn restore_pacemaker_view(pacemaker: &mut Pacemaker, state: &ConsensusState) {
    if state.current_view > pacemaker.current_view {
        info!(
            "restoring pacemaker view from {} to {}",
            pacemaker.current_view, state.current_view
        );
        pacemaker.current_view = state.current_view;
    }
}

/// Restore locked block from storage (returns the hash if present).
pub fn restore_locked_block(storage: &StorageEngine) -> Result<Option<[u8; 32]>> {
    let Some(bytes) = storage.state_get(LOCKED_BLOCK_KEY.to_vec())? else {
        return Ok(None);
    };
    if bytes.len() != 32 {
        bail!("locked block key has unexpected length {}", bytes.len());
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Ok(Some(hash))
}

/// Persist the locked block hash to storage.
pub fn persist_locked_block(storage: &StorageEngine, block_hash: [u8; 32]) -> Result<()> {
    storage.state_put(LOCKED_BLOCK_KEY.to_vec(), block_hash.to_vec())
}

/// Restore quorum certificate from storage.
pub fn restore_highest_qc(storage: &StorageEngine) -> Result<Option<QuorumCertificate>> {
    let Some(bytes) = storage.state_get(HIGHEST_QC_KEY.to_vec())? else {
        return Ok(None);
    };
    let qc = QuorumCertificate::decode(&bytes).or_else(|_| bincode::deserialize(&bytes))?;
    Ok(Some(qc))
}

// - full startup restoration -

pub struct RestoredConsensus {
    pub state: ConsensusState,
    pub pacemaker_view: u64,
    pub locked_block: Option<[u8; 32]>,
    pub highest_qc: Option<QuorumCertificate>,
}

pub fn restore_full_consensus(
    storage: &StorageEngine,
    pacemaker: &mut Pacemaker,
) -> Result<Option<RestoredConsensus>> {
    let Some(mut state) = load_consensus_state(storage)? else {
        return Ok(None);
    };

    restore_pacemaker_view(pacemaker, &state);

    if let Ok(Some(locked)) = restore_locked_block(storage) {
        state.locked_block = Some(locked);
    }

    if let Ok(Some(qc)) = restore_highest_qc(storage) {
        state.highest_qc = Some(qc);
    }

    let view = state.current_view;
    let locked_block = state.locked_block;
    let highest_qc = state.highest_qc.clone();

    Ok(Some(RestoredConsensus {
        state,
        pacemaker_view: view,
        locked_block,
        highest_qc,
    }))
}

// - item 11: reject proposals below locked block -

pub fn reject_proposal_below_locked_block(
    locked_block_hash: Option<[u8; 32]>,
    locked_block_height: Option<u64>,
    proposal: &Block,
) -> Result<()> {
    let Some(locked_height) = locked_block_height else {
        return Ok(()); // no lock yet - all heights acceptable
    };

    if proposal.height() < locked_height {
        bail!(
            "proposal at height {} rejected: below locked block at height {}",
            proposal.height(),
            locked_height
        );
    }

    // Also reject a proposal whose parent is not the locked block when at the same height
    if let Some(locked_hash) = locked_block_hash {
        let proposal_hash = proposal.try_hash()?;
        if proposal.height() == locked_height && proposal_hash != locked_hash {
            bail!(
                "proposal hash {:?} conflicts with locked block {:?} at height {}",
                proposal_hash,
                locked_hash,
                locked_height
            );
        }
    }

    Ok(())
}

// - item 12: resume consensus from restored view -

pub fn resume_from_restored_view(
    pacemaker: &mut Pacemaker,
    restored_view: u64,
    validator_count: usize,
) -> NewViewMessage {
    pacemaker.current_view = restored_view;
    pacemaker.broadcast_new_view(validator_count)
}

// - item 13: verify validator set consistency -

pub fn verify_validator_set_consistency(
    state: &ConsensusState,
    validator_set: &ValidatorSet,
) -> Result<()> {
    let validators = validator_set.active_validators();
    let current_hash = ConsensusState::compute_validator_set_hash(&validators);

    if state.validator_set_hash != [0u8; 32] && state.validator_set_hash != current_hash {
        bail!(
            "validator set inconsistency: persisted hash {:?} != current hash {:?}",
            state.validator_set_hash,
            current_hash
        );
    }

    Ok(())
}

// - item 14: detect inconsistent consensus state -

#[derive(Debug, PartialEq, Eq)]
pub enum ConsistencyCheck {
    Ok,
    IntegrityHashMismatch,
    ViewRegressedFromStorage,
    MissingLockedBlock,
    InvalidQcView,
}

pub fn detect_inconsistent_state(
    storage: &StorageEngine,
    state: &ConsensusState,
) -> Result<ConsistencyCheck> {
    // Integrity hash check
    if let Ok(stored_hash) = load_integrity_hash(storage) {
        let computed = compute_state_integrity(state)?;
        if stored_hash != computed {
            return Ok(ConsistencyCheck::IntegrityHashMismatch);
        }
    }

    // View must be non-regressive (detect rolled-back storage)
    if let Some(bytes) = storage.state_get(b"consensus:current_view".to_vec())? {
        if bytes.len() == 8 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes);
            let old_view = u64::from_le_bytes(arr);
            if state.current_view < old_view {
                return Ok(ConsistencyCheck::ViewRegressedFromStorage);
            }
        }
    }

    // If highest_qc is present, its view must be <= current_view
    if let Some(ref qc) = state.highest_qc {
        if qc.view > state.current_view {
            return Ok(ConsistencyCheck::InvalidQcView);
        }
    }

    // If state has a locked block, verify it matches storage
    if let Some(state_locked) = state.locked_block {
        if let Some(bytes) = storage.state_get(LOCKED_BLOCK_KEY.to_vec())? {
            if bytes.len() != 32 || bytes.as_slice() != state_locked.as_slice() {
                return Ok(ConsistencyCheck::MissingLockedBlock);
            }
        } else {
            return Ok(ConsistencyCheck::MissingLockedBlock);
        }
    }

    Ok(ConsistencyCheck::Ok)
}

// - item 15: fallback to safe recovery mode -

pub fn enter_safe_recovery_mode(state: &mut ConsensusState, storage: &StorageEngine) -> Result<()> {
    warn!("entering safe recovery mode at view {}", state.current_view);
    state.safe_recovery_mode = true;
    persist_consensus_state(storage, state)?;
    Ok(())
}

pub fn exit_safe_recovery_mode(state: &mut ConsensusState, storage: &StorageEngine) -> Result<()> {
    info!("exiting safe recovery mode at view {}", state.current_view);
    state.safe_recovery_mode = false;
    persist_consensus_state(storage, state)?;
    Ok(())
}

// - item 16: broadcast new-view message -

pub fn build_new_view_message(pacemaker: &Pacemaker, validator_count: usize) -> NewViewMessage {
    pacemaker.broadcast_new_view(validator_count)
}

// - item 17: synchronize view with peers -

pub fn synchronize_view_with_peers(
    pacemaker: &mut Pacemaker,
    peer_views: &[u64],
    state: &mut ConsensusState,
    storage: &StorageEngine,
) -> Result<u64> {
    // SECURITY (C-07): adopt the MEDIAN peer-reported view, not the raw max.
    // The max is attacker-controlled — a single lying peer could drag the
    // view counter arbitrarily far into the future (view poisoning). The
    // median resists a Byzantine minority, and the pacemaker additionally
    // rejects any jump beyond the unauthenticated window.
    if peer_views.is_empty() {
        return Ok(pacemaker.current_view);
    }
    let mut sorted = peer_views.to_vec();
    sorted.sort_unstable();
    let median_peer_view = sorted[sorted.len() / 2];
    if median_peer_view > pacemaker.current_view {
        info!(
            "advancing view from {} to {} via peer synchronization",
            pacemaker.current_view, median_peer_view
        );
        let advanced = pacemaker.sync_view_with_network(median_peer_view);
        state.current_view = advanced;
        persist_consensus_state(storage, state)?;
    }
    Ok(pacemaker.current_view)
}

// - item 18: avoid double proposal after restart -

/// Returns `true` if this node has already broadcast a proposal for `(view, proposer)`.
pub fn has_proposed_in_view(
    storage: &StorageEngine,
    view: u64,
    proposer: &Address,
) -> Result<bool> {
    let key = proposal_guard_key(view, proposer);
    Ok(storage.state_get(key)?.is_some())
}

/// Record that a proposal was broadcast for `(view, proposer)`.
pub fn record_proposal_in_view(
    storage: &StorageEngine,
    view: u64,
    proposer: &Address,
) -> Result<()> {
    let key = proposal_guard_key(view, proposer);
    storage.state_put(key, vec![1u8])
}

fn proposal_guard_key(view: u64, proposer: &Address) -> Vec<u8> {
    let mut key = PROPOSAL_GUARD_KEY.to_vec();
    key.extend_from_slice(&view.to_le_bytes());
    key.extend_from_slice(proposer.as_bytes());
    key
}

// - item 19: checkpoint finalized blocks -

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub view: u64,
    pub validator_set_hash: [u8; 32],
}

impl Checkpoint {
    pub fn from_block(block: &Block, view: u64, validator_set_hash: [u8; 32]) -> Self {
        Self {
            height: block.height(),
            block_hash: block.try_hash().unwrap_or_default(),
            state_root: block.header.state_root,
            view,
            validator_set_hash,
        }
    }

    pub fn from_block_checked(
        block: &Block,
        view: u64,
        validator_set_hash: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            height: block.height(),
            block_hash: block.try_hash()?,
            state_root: block.header.state_root,
            view,
            validator_set_hash,
        })
    }
}

pub fn checkpoint_finalized_block(
    storage: &StorageEngine,
    block: &Block,
    view: u64,
    validator_set_hash: [u8; 32],
) -> Result<()> {
    let checkpoint = Checkpoint::from_block_checked(block, view, validator_set_hash)?;
    let key = checkpoint_key(block.height());
    let bytes = checkpoint.try_encode()?;
    storage.state_put(key, bytes)?;
    info!(
        "checkpointed finalized block at height {} hash {:?}",
        block.height(),
        checkpoint.block_hash
    );
    Ok(())
}

pub fn load_checkpoint(storage: &StorageEngine, height: u64) -> Result<Option<Checkpoint>> {
    let Some(bytes) = storage.state_get(checkpoint_key(height))? else {
        return Ok(None);
    };
    let cp: Checkpoint = Checkpoint::decode(&bytes)?;
    Ok(Some(cp))
}

pub fn latest_checkpoint(storage: &StorageEngine) -> Result<Option<Checkpoint>> {
    let entries = storage.state_prefix_scan(CHECKPOINT_PREFIX.to_vec())?;
    let best = entries
        .into_iter()
        .filter_map(|(_, bytes)| Checkpoint::decode(&bytes).ok())
        .max_by_key(|cp| cp.height);
    Ok(best)
}

fn checkpoint_key(height: u64) -> Vec<u8> {
    let mut key = CHECKPOINT_PREFIX.to_vec();
    key.extend_from_slice(&height.to_be_bytes()); // big-endian for lexicographic order
    key
}

// - item 20: audit consensus state integrity -

fn compute_state_integrity(state: &ConsensusState) -> Result<[u8; 32]> {
    let bytes = state.try_encode()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

fn load_integrity_hash(storage: &StorageEngine) -> Result<[u8; 32]> {
    let bytes = storage
        .state_get(INTEGRITY_KEY.to_vec())?
        .ok_or_else(|| anyhow!("no integrity hash found in storage"))?;
    if bytes.len() != 32 {
        bail!("integrity hash has unexpected length {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn verify_state_integrity(storage: &StorageEngine, state: &ConsensusState) -> Result<()> {
    // If no integrity hash has been stored yet, skip the check (first run).
    let Ok(stored_hash) = load_integrity_hash(storage) else {
        return Ok(());
    };
    let computed = compute_state_integrity(state)?;
    if stored_hash != computed {
        bail!(
            "consensus state integrity check failed: stored {:?} != computed {:?}",
            stored_hash,
            computed
        );
    }
    Ok(())
}

pub fn audit_consensus_state_integrity(
    storage: &StorageEngine,
    state: &ConsensusState,
) -> Result<()> {
    verify_state_integrity(storage, state)?;
    info!(
        "consensus state integrity audit passed at view {}",
        state.current_view
    );
    Ok(())
}

// - ConsensusStateManager: encapsulates all of the above -

pub struct ConsensusStateManager {
    pub state: ConsensusState,
    storage: Arc<StorageEngine>,
}

impl ConsensusStateManager {
    pub fn new(storage: Arc<StorageEngine>) -> Self {
        Self {
            state: ConsensusState::new(),
            storage,
        }
    }

    /// Load from redb on startup; falls back to fresh state.
    pub fn load_or_init(storage: Arc<StorageEngine>) -> Result<Self> {
        let state = load_consensus_state(&storage)?.unwrap_or_default();
        Ok(Self { state, storage })
    }

    /// Persist after every round.
    pub fn persist(&self) -> Result<()> {
        persist_consensus_state(&self.storage, &self.state)
    }

    pub fn advance_view(&mut self) -> Result<u64> {
        let view = self.state.advance_view();
        self.persist()?;
        Ok(view)
    }

    pub fn set_locked_block(&mut self, block_hash: [u8; 32]) -> Result<()> {
        self.state.set_locked_block(block_hash);
        self.persist()
    }

    pub fn set_highest_qc(&mut self, qc: QuorumCertificate) -> Result<()> {
        self.state.set_highest_qc(qc);
        self.persist()
    }

    pub fn set_finalized_height(&mut self, height: u64) -> Result<()> {
        self.state.finalized_height = height;
        self.persist()
    }

    pub fn update_validator_set_hash(&mut self, validators: &[Validator]) -> Result<()> {
        self.state.validator_set_hash = ConsensusState::compute_validator_set_hash(validators);
        self.persist()
    }

    pub fn restore_pacemaker(&self, pacemaker: &mut Pacemaker) {
        restore_pacemaker_view(pacemaker, &self.state);
    }

    pub fn reject_proposal_below_lock(
        &self,
        locked_height: Option<u64>,
        proposal: &Block,
    ) -> Result<()> {
        reject_proposal_below_locked_block(self.state.locked_block, locked_height, proposal)
    }

    pub fn verify_validator_consistency(&self, set: &ValidatorSet) -> Result<()> {
        verify_validator_set_consistency(&self.state, set)
    }

    pub fn detect_inconsistency(&self) -> Result<ConsistencyCheck> {
        detect_inconsistent_state(&self.storage, &self.state)
    }

    pub fn enter_recovery(&mut self) -> Result<()> {
        enter_safe_recovery_mode(&mut self.state, &self.storage)
    }

    pub fn has_proposed(&self, view: u64, proposer: &Address) -> Result<bool> {
        has_proposed_in_view(&self.storage, view, proposer)
    }

    pub fn record_proposal(&self, view: u64, proposer: &Address) -> Result<()> {
        record_proposal_in_view(&self.storage, view, proposer)
    }

    pub fn checkpoint_block(&self, block: &Block) -> Result<()> {
        checkpoint_finalized_block(
            &self.storage,
            block,
            self.state.current_view,
            self.state.validator_set_hash,
        )
    }

    pub fn audit(&self) -> Result<()> {
        audit_consensus_state_integrity(&self.storage, &self.state)
    }
}

// - tests -

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hotstuff::pacemaker::Pacemaker;
    use crate::hotstuff::vote::QuorumCertificate;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_storage::StorageEngine;
    use sxiaum_types::{Address, Validator};

    fn unique_db(name: &str) -> (PathBuf, Arc<StorageEngine>) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from(format!("target/tmp/cstate_test_{name}_{ts}.redb"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let storage = Arc::new(StorageEngine::new(&path).unwrap());
        (path, storage)
    }

    fn make_block(parent_hash: [u8; 32], height: u64) -> Block {
        let header = BlockHeader::new(parent_hash, height);
        let mut block = Block::new(header, BlockBody::empty());
        block.try_compute_roots().unwrap();
        block
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let (path, storage) = unique_db("roundtrip");
        let mut state = ConsensusState::new();
        state.current_view = 7;
        state.locked_block = Some([1u8; 32]);
        state.highest_qc = Some(QuorumCertificate {
            aggregated_entropy: [0u8; 32],
            block_hash: [2u8; 32],
            view: 6,
            phase: Default::default(),
            signatures: vec![],
            validators: vec![],
        });

        persist_consensus_state(&storage, &state).unwrap();

        let loaded = load_consensus_state(&storage).unwrap().unwrap();
        assert_eq!(loaded.current_view, 7);
        assert_eq!(loaded.locked_block, Some([1u8; 32]));
        assert!(loaded.highest_qc.is_some());

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn restore_pacemaker_view_advances_view() {
        let (path, storage) = unique_db("pacemaker");
        let mut state = ConsensusState::new();
        state.current_view = 15;
        persist_consensus_state(&storage, &state).unwrap();

        let mut pacemaker = Pacemaker::new(Duration::from_secs(5));
        restore_pacemaker_view(&mut pacemaker, &state);
        assert_eq!(pacemaker.current_view, 15);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn restore_locked_block_from_storage() {
        let (path, storage) = unique_db("locked");
        storage
            .state_put(LOCKED_BLOCK_KEY.to_vec(), [42u8; 32].to_vec())
            .unwrap();
        let lock = restore_locked_block(&storage).unwrap().unwrap();
        assert_eq!(lock, [42u8; 32]);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn restore_highest_qc_from_storage() {
        let (path, storage) = unique_db("qc");
        let qc = QuorumCertificate {
            aggregated_entropy: [0u8; 32],
            block_hash: [9u8; 32],
            view: 3,
            phase: Default::default(),
            signatures: vec![],
            validators: vec![],
        };
        storage
            .state_put(HIGHEST_QC_KEY.to_vec(), qc.encode())
            .unwrap();
        let restored = restore_highest_qc(&storage).unwrap().unwrap();
        assert_eq!(restored.block_hash, [9u8; 32]);
        assert_eq!(restored.view, 3);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reject_proposal_below_locked_block_rejects_lower() {
        let block = make_block([0u8; 32], 3);
        assert!(reject_proposal_below_locked_block(None, Some(5), &block).is_err());
        assert!(reject_proposal_below_locked_block(None, Some(3), &block).is_ok());
        assert!(reject_proposal_below_locked_block(None, Some(2), &block).is_ok());
    }

    #[test]
    fn validator_set_hash_changes_on_different_sets() {
        let a = Address::from([1u8; 32]);
        let b = Address::from([2u8; 32]);
        let val_a = Validator::new(a, [1u8; 32], primitive_types::U256::from(100u64));
        let val_b = Validator::new(b, [2u8; 32], primitive_types::U256::from(200u64));

        let hash1 = ConsensusState::compute_validator_set_hash(std::slice::from_ref(&val_a));
        let hash2 = ConsensusState::compute_validator_set_hash(std::slice::from_ref(&val_b));
        let hash12 = ConsensusState::compute_validator_set_hash(&[val_a.clone(), val_b.clone()]);
        let hash21 = ConsensusState::compute_validator_set_hash(&[val_b, val_a]);

        assert_ne!(hash1, hash2);
        assert_ne!(hash1, hash12);
        // Order-independent: sorted before hashing
        assert_eq!(hash12, hash21);
    }

    #[test]
    fn detect_inconsistency_integrity_mismatch() {
        let (path, storage) = unique_db("integrity");
        let mut state = ConsensusState::new();
        state.current_view = 5;
        persist_consensus_state(&storage, &state).unwrap();

        // Tamper with stored integrity hash
        storage
            .state_put(INTEGRITY_KEY.to_vec(), vec![0u8; 32])
            .unwrap();

        let check = detect_inconsistent_state(&storage, &state).unwrap();
        assert_eq!(check, ConsistencyCheck::IntegrityHashMismatch);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn detect_inconsistency_invalid_qc_view() {
        let (path, storage) = unique_db("qcview");
        let mut state = ConsensusState::new();
        state.current_view = 3;
        state.highest_qc = Some(QuorumCertificate {
            aggregated_entropy: [0u8; 32],
            block_hash: [0u8; 32],
            view: 99, // ahead of current_view
            phase: Default::default(),
            signatures: vec![],
            validators: vec![],
        });
        // Skip persisting integrity so only QC check fires
        let check = detect_inconsistent_state(&storage, &state).unwrap();
        assert_eq!(check, ConsistencyCheck::InvalidQcView);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn safe_recovery_mode_flag_persists() {
        let (path, storage) = unique_db("recovery");
        let mut state = ConsensusState::new();
        assert!(!state.safe_recovery_mode);
        enter_safe_recovery_mode(&mut state, &storage).unwrap();
        assert!(state.safe_recovery_mode);
        exit_safe_recovery_mode(&mut state, &storage).unwrap();
        assert!(!state.safe_recovery_mode);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn proposal_guard_prevents_double_proposal() {
        let (path, storage) = unique_db("doublep");
        let proposer = Address::from([3u8; 32]);
        assert!(!has_proposed_in_view(&storage, 4, &proposer).unwrap());
        record_proposal_in_view(&storage, 4, &proposer).unwrap();
        assert!(has_proposed_in_view(&storage, 4, &proposer).unwrap());
        // Different view or different proposer must be independent
        assert!(!has_proposed_in_view(&storage, 5, &proposer).unwrap());
        let other = Address::from([4u8; 32]);
        assert!(!has_proposed_in_view(&storage, 4, &other).unwrap());

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn checkpoint_and_load_finalized_block() {
        let (path, storage) = unique_db("checkpoint");
        let block = make_block([0u8; 32], 10);
        let vs_hash = [7u8; 32];
        checkpoint_finalized_block(&storage, &block, 8, vs_hash).unwrap();

        let cp = load_checkpoint(&storage, 10).unwrap().unwrap();
        assert_eq!(cp.height, 10);
        assert_eq!(cp.block_hash, block.try_hash().unwrap());
        assert_eq!(cp.view, 8);
        assert_eq!(cp.validator_set_hash, vs_hash);

        let latest = latest_checkpoint(&storage).unwrap().unwrap();
        assert_eq!(latest.height, 10);

        drop(storage);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn state_manager_full_lifecycle() {
        let (path, storage) = unique_db("manager");
        let mut mgr = ConsensusStateManager::new(storage.clone());

        mgr.advance_view().unwrap();
        mgr.advance_view().unwrap();
        assert_eq!(mgr.state.current_view, 2);

        mgr.set_locked_block([5u8; 32]).unwrap();
        assert_eq!(mgr.state.locked_block, Some([5u8; 32]));

        mgr.audit().unwrap();

        let block = make_block([0u8; 32], 5);
        mgr.set_finalized_height(5).unwrap();
        mgr.checkpoint_block(&block).unwrap();

        let proposer = Address::from([20u8; 32]);
        assert!(!mgr.has_proposed(2, &proposer).unwrap());
        mgr.record_proposal(2, &proposer).unwrap();
        assert!(mgr.has_proposed(2, &proposer).unwrap());

        drop(storage);
        let _ = fs::remove_file(&path);
    }
}
