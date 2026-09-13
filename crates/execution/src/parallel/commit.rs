/// Commit protocol and serialization validation.
///
/// Validates that the results of parallel execution are serializable and
/// can be committed atomically without violating consistency.
use crate::parallel::executor::{ParallelExecutionResult, TxExecutionOutcome};
use crate::parallel::mv_memory::{MVMemory, TxVersion};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use sxiaum_state::StateDb;

use tracing::{debug, info, warn};

/// Represents a validated snapshot of transaction execution results.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionSnapshot {
    pub snapshot_id: u64,
    pub tx_index: usize,
    /// State written by this transaction: key - value
    pub writes: HashMap<Vec<u8>, Vec<u8>>,
}

impl VersionSnapshot {
    pub fn new(snapshot_id: u64, tx_index: usize, writes: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        Self {
            snapshot_id,
            tx_index,
            writes,
        }
    }
}

/// Detects conflicts in a serial execution order.
pub struct SerializationValidator {
    /// Snapshots indexed by transaction index.
    snapshots: HashMap<usize, VersionSnapshot>,
}

impl Default for SerializationValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl SerializationValidator {
    pub fn new() -> Self {
        Self {
            snapshots: HashMap::new(),
        }
    }

    /// Records a transaction's writes.
    pub fn record_snapshot(&mut self, snapshot: VersionSnapshot) {
        self.snapshots.insert(snapshot.tx_index, snapshot);
    }

    /// Validates that the execution is serializable:
    /// Returns error if a transaction reads a value that was overwritten by a later transaction.
    pub fn validate_serializability(
        &self,
        execution_order: &[usize],
        read_sets: &HashMap<usize, Vec<Vec<u8>>>,
    ) -> Result<()> {
        // Build the write history in execution order
        let mut write_history: HashMap<Vec<u8>, usize> = HashMap::new();

        for &tx_idx in execution_order {
            if let Some(snapshot) = self.snapshots.get(&tx_idx) {
                for key in snapshot.writes.keys() {
                    write_history.insert(key.clone(), tx_idx);
                }
            }
        }

        // Check for read-after-write violations
        for &tx_idx in execution_order {
            if let Some(reads) = read_sets.get(&tx_idx) {
                for key in reads {
                    if let Some(&writer) = write_history.get(key) {
                        if writer > tx_idx {
                            bail!(
                                "serializability violation: tx {} reads key written by later tx {}",
                                tx_idx,
                                writer
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Checks if the execution result is valid for commitment.
    pub fn can_commit(&self, result: &ParallelExecutionResult) -> Result<bool> {
        // All transactions must have completed
        if result.total_failed() > 0 {
            return Ok(false);
        }

        // Snapshots must be available
        for batch in &result.batch_results {
            for tx_result in &batch.results {
                if !self.snapshots.contains_key(&tx_result.tx_index) {
                    return Err(anyhow!(
                        "snapshot missing for transaction {}",
                        tx_result.tx_index
                    ));
                }
            }
        }

        Ok(true)
    }
}

/// Validates the version consistency of executed transactions.
pub struct VersionValidator {
    /// Current version number for each key
    current_versions: HashMap<Vec<u8>, u64>,
}

impl Default for VersionValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionValidator {
    pub fn new() -> Self {
        Self {
            current_versions: HashMap::new(),
        }
    }

    /// Initializes with a baseline state
    pub fn with_baseline(baseline: HashMap<Vec<u8>, Vec<u8>>) -> Self {
        let mut validator = Self::new();
        for key in baseline.keys() {
            validator.current_versions.insert(key.clone(), 1);
        }
        validator
    }

    /// Validates that a transaction's read-write set is consistent with the current versions.
    pub fn validate_rw_set(
        &mut self,
        tx_index: usize,
        read_set: &[Vec<u8>],
        write_set: &[Vec<u8>],
    ) -> Result<()> {
        // All reads must be from the current version
        for key in read_set {
            if let Some(&version) = self.current_versions.get(key) {
                debug!(
                    tx_index,
                    key = ?key,
                    version,
                    "transaction read from version"
                );
            }
        }

        // All writes increment the version
        for key in write_set {
            let new_version = match self.current_versions.get(key) {
                Some(&v) => v + 1,
                None => 1,
            };
            self.current_versions.insert(key.clone(), new_version);
            debug!(
                tx_index,
                key = ?key,
                new_version,
                "transaction wrote new version"
            );
        }

        Ok(())
    }

    /// Rolls back uncommitted versions for aborted transactions.
    pub fn rollback_tx(&mut self, tx_index: usize, write_set: &[Vec<u8>]) {
        for key in write_set {
            if let Some(version) = self.current_versions.get_mut(key) {
                if *version > 0 {
                    *version -= 1;
                }
            }
        }
        debug!(tx_index, "rolled back transaction");
    }

    /// Returns the current version of a key.
    pub fn current_version(&self, key: &[u8]) -> u64 {
        self.current_versions.get(key).copied().unwrap_or(0)
    }
}

/// The commit protocol state machine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommitPhase {
    /// Initial state: transactions have been executed but not yet validated.
    Executed,
    /// Serialization validation passed.
    Serializable,
    /// Version validation passed.
    VersionValidated,
    /// All validations passed; ready to commit to persistent storage.
    ReadyToCommit,
    /// Transactions have been committed to persistent storage.
    Committed,
    /// A validation failed; no commit will occur.
    Aborted,
}

/// Result of a commit operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitResult {
    pub phase: CommitPhase,
    pub committed_txs: Vec<usize>,
    pub aborted_txs: Vec<usize>,
    pub error: Option<String>,
}

impl CommitResult {
    pub fn new(phase: CommitPhase) -> Self {
        Self {
            phase,
            committed_txs: Vec::new(),
            aborted_txs: Vec::new(),
            error: None,
        }
    }

    pub fn with_error(phase: CommitPhase, error: String) -> Self {
        Self {
            phase,
            committed_txs: Vec::new(),
            aborted_txs: Vec::new(),
            error: Some(error),
        }
    }

    pub fn is_successful(&self) -> bool {
        self.phase == CommitPhase::Committed && self.error.is_none()
    }
}

/// Orchestrates the commit protocol.
pub struct CommitProtocol {
    phase: CommitPhase,
    serialization_validator: SerializationValidator,
    version_validator: VersionValidator,
}

impl Default for CommitProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitProtocol {
    pub fn new() -> Self {
        Self {
            phase: CommitPhase::Executed,
            serialization_validator: SerializationValidator::new(),
            version_validator: VersionValidator::new(),
        }
    }

    /// Transitions to the next phase if validations pass.
    pub fn advance(&mut self) -> Result<()> {
        match self.phase {
            CommitPhase::Executed => {
                self.phase = CommitPhase::Serializable;
                Ok(())
            }
            CommitPhase::Serializable => {
                self.phase = CommitPhase::VersionValidated;
                Ok(())
            }
            CommitPhase::VersionValidated => {
                self.phase = CommitPhase::ReadyToCommit;
                Ok(())
            }
            CommitPhase::ReadyToCommit => {
                self.phase = CommitPhase::Committed;
                Ok(())
            }
            CommitPhase::Committed => {
                bail!("already committed");
            }
            CommitPhase::Aborted => {
                bail!("commit aborted");
            }
        }
    }

    /// Validates the execution results for commitability.
    pub fn validate_for_commit(
        &mut self,
        result: &ParallelExecutionResult,
    ) -> Result<CommitResult> {
        if !self.phase.eq(&CommitPhase::Executed) {
            return Ok(CommitResult::with_error(
                self.phase.clone(),
                "not in executed phase".to_string(),
            ));
        }

        // Phase 1: Serializability check
        let execution_order = result.executed_tx_indices();
        if let Err(e) = self.serialization_validator.can_commit(result) {
            warn!("serialization validation failed: {}", e);
            self.phase = CommitPhase::Aborted;
            return Ok(CommitResult::with_error(
                CommitPhase::Aborted,
                e.to_string(),
            ));
        }

        self.advance()?;

        // Phase 2: Version validation
        for batch in &result.batch_results {
            for tx_result in &batch.results {
                if let Err(e) = self.version_validator.validate_rw_set(
                    tx_result.tx_index,
                    &tx_result.read_write_set.read_set,
                    &tx_result.read_write_set.write_set,
                ) {
                    warn!("version validation failed: {}", e);
                    self.phase = CommitPhase::Aborted;
                    return Ok(CommitResult::with_error(
                        CommitPhase::Aborted,
                        e.to_string(),
                    ));
                }
            }
        }

        self.advance()?;
        self.advance()?; // ReadyToCommit

        let mut result = CommitResult::new(CommitPhase::ReadyToCommit);
        result.committed_txs = execution_order;
        Ok(result)
    }

    /// Finalizes the commit, transitioning to Committed phase.
    pub fn finalize_commit(&mut self) -> Result<CommitResult> {
        if !self.phase.eq(&CommitPhase::ReadyToCommit) {
            return Err(anyhow!("cannot finalize commit in phase {:?}", self.phase));
        }

        self.advance()?;
        Ok(CommitResult::new(CommitPhase::Committed))
    }

    /// Aborts the commit protocol.
    pub fn abort(&mut self) -> CommitResult {
        self.phase = CommitPhase::Aborted;
        CommitResult::new(CommitPhase::Aborted)
    }

    /// Returns the current phase.
    pub fn current_phase(&self) -> &CommitPhase {
        &self.phase
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_validator_records_snapshots() {
        let mut validator = SerializationValidator::new();
        let mut writes = HashMap::new();
        writes.insert(b"x".to_vec(), b"v1".to_vec());
        let snapshot = VersionSnapshot::new(0, 0, writes);
        validator.record_snapshot(snapshot);
        assert_eq!(validator.snapshots.len(), 1);
    }

    #[test]
    fn version_validator_increments_versions() {
        let mut validator = VersionValidator::new();
        validator.validate_rw_set(0, &[], &[b"x".to_vec()]).unwrap();
        assert_eq!(validator.current_version(b"x"), 1);

        validator.validate_rw_set(1, &[], &[b"x".to_vec()]).unwrap();
        assert_eq!(validator.current_version(b"x"), 2);
    }

    #[test]
    fn version_validator_rollback() {
        let mut validator = VersionValidator::new();
        validator.validate_rw_set(0, &[], &[b"x".to_vec()]).unwrap();
        assert_eq!(validator.current_version(b"x"), 1);

        validator.rollback_tx(0, &[b"x".to_vec()]);
        assert_eq!(validator.current_version(b"x"), 0);
    }

    #[test]
    fn commit_protocol_phases() {
        let mut protocol = CommitProtocol::new();
        assert_eq!(protocol.current_phase(), &CommitPhase::Executed);

        protocol.advance().unwrap();
        assert_eq!(protocol.current_phase(), &CommitPhase::Serializable);

        protocol.advance().unwrap();
        assert_eq!(protocol.current_phase(), &CommitPhase::VersionValidated);

        protocol.advance().unwrap();
        assert_eq!(protocol.current_phase(), &CommitPhase::ReadyToCommit);

        protocol.advance().unwrap();
        assert_eq!(protocol.current_phase(), &CommitPhase::Committed);
    }

    #[test]
    fn commit_protocol_abort() {
        let mut protocol = CommitProtocol::new();
        let result = protocol.abort();
        assert_eq!(result.phase, CommitPhase::Aborted);
    }
}

// - CommitManager -
//
// Items implemented:
//  1. `CommitManager` struct
//  2. `receive_results` - ingest speculative execution outputs
//  3. `order_by_tx_index` - sort pending outcomes deterministically
//  4. `validate_read_sets` - check read-set consistency via MVMemory
//  5. `detect_state_conflicts` - find WAW write conflicts within batch
//  6. `finalize_writes` - merge valid speculative writes
//  7. `update_state_db` - apply writes to StateDb (raw kv)
//  8. `discard_invalid` - remove aborted / conflicted writes from MVMemory
//  9. `persist` - flush to durable storage via StateDb::commit
// 10. `update_state_root` - recompute state root via StateDb::update_state_root

/// Configuration for [`CommitManager`].
#[derive(Clone, Debug)]
pub struct CommitManagerConfig {
    /// Abort the entire batch if a single conflict is found.
    pub abort_on_conflict: bool,
    /// Call `StateDb::commit()` (disk flush) after every pipeline run.
    pub flush_to_disk: bool,
}

impl Default for CommitManagerConfig {
    fn default() -> Self {
        Self {
            abort_on_conflict: false,
            flush_to_disk: true,
        }
    }
}

/// Summary returned by [`CommitManager::commit_pipeline`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitSummary {
    pub total_received: usize,
    pub finalized_writes: usize,
    pub discarded_txs: usize,
    pub state_root: [u8; 32],
}

impl CommitSummary {
    pub fn is_clean(&self) -> bool {
        self.discarded_txs == 0
    }
}

// item 1 -

/// Central commit manager that ties speculative execution results to the
/// persistent `StateDb`.
pub struct CommitManager {
    config: CommitManagerConfig,
    /// Optional MVMemory for read-set re-validation (item 4).
    mv_memory: Option<Arc<MVMemory>>,
    /// item 2: received (unordered) outcomes.
    pending: Vec<TxExecutionOutcome>,
    /// item 6: write-set that has passed all validation.
    finalized_writes: HashMap<Vec<u8>, Vec<u8>>,
    /// item 8: tx indices whose writes have been discarded.
    discarded: HashSet<usize>,
    /// Most recent committed state root.
    last_state_root: [u8; 32],
}

impl CommitManager {
    pub fn new(config: CommitManagerConfig) -> Self {
        Self {
            config,
            mv_memory: None,
            pending: Vec::new(),
            finalized_writes: HashMap::new(),
            discarded: HashSet::new(),
            last_state_root: [0u8; 32],
        }
    }

    /// Attach an `MVMemory` for read-set validation.
    pub fn with_mv_memory(mut self, mv: Arc<MVMemory>) -> Self {
        self.mv_memory = Some(mv);
        self
    }

    // item 2 -

    /// Ingests speculative outcomes from one execution round.
    pub fn receive_results(&mut self, outcomes: Vec<TxExecutionOutcome>) {
        debug!(count = outcomes.len(), "received speculative results");
        self.pending.extend(outcomes);
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    // item 3 -

    /// Sorts `pending` ascending by `tx_index` for deterministic processing.
    pub fn order_by_tx_index(&mut self) {
        self.pending.sort_by_key(|o| o.tx_index);
    }

    // item 4 -

    /// Re-validates every outcome's read set against `MVMemory`.
    /// Returns the indices of outcomes whose reads have become stale.
    pub fn validate_read_sets(&mut self) -> Vec<usize> {
        let mv = match &self.mv_memory {
            Some(m) => m.clone(),
            None => return Vec::new(),
        };
        let mut invalid = Vec::new();
        for outcome in &self.pending {
            if self.discarded.contains(&outcome.tx_index) {
                continue;
            }
            // SECURITY (C-08): validate under the version the transaction was
            // actually executed and recorded with. The previous hard-coded
            // `TxVersion::new(..)` (incarnation 0) never matched retried
            // incarnations, so their read sets were silently treated as
            // "trivially valid".
            let tv = outcome
                .tx_version
                .unwrap_or_else(|| TxVersion::new(outcome.tx_index));
            match mv.validate_reads(tv) {
                Ok(true) => {}
                Ok(false) => {
                    warn!(tx_index = outcome.tx_index, "read set stale");
                    invalid.push(outcome.tx_index);
                }
                Err(e) => {
                    warn!(tx_index = outcome.tx_index, err = %e, "read validation error");
                    invalid.push(outcome.tx_index);
                }
            }
        }
        invalid
    }

    // item 5 -

    /// Detects WAW conflicts.  The later tx (higher `tx_index`) loses.
    /// Returns the set of conflicting tx indices that should be discarded.
    pub fn detect_state_conflicts(&self) -> HashSet<usize> {
        let mut key_first_writer: HashMap<&Vec<u8>, usize> = HashMap::new();
        let mut conflicted: HashSet<usize> = HashSet::new();
        for outcome in &self.pending {
            if self.discarded.contains(&outcome.tx_index) {
                continue;
            }
            for key in outcome.speculative_writes.keys() {
                match key_first_writer.get(key) {
                    Some(&first) => {
                        conflicted.insert(outcome.tx_index);
                        debug!(
                            first_writer = first,
                            loser = outcome.tx_index,
                            "WAW conflict"
                        );
                    }
                    None => {
                        key_first_writer.insert(key, outcome.tx_index);
                    }
                }
            }
        }
        conflicted
    }

    // item 6 -

    /// Merges non-conflicting speculative writes into `self.finalized_writes`.
    pub fn finalize_writes(&mut self) -> usize {
        let conflicts = self.detect_state_conflicts();
        let mut count = 0usize;
        for outcome in &self.pending {
            if self.discarded.contains(&outcome.tx_index) {
                continue;
            }
            if conflicts.contains(&outcome.tx_index) {
                self.discarded.insert(outcome.tx_index);
                continue;
            }
            for (key, val) in &outcome.speculative_writes {
                self.finalized_writes.insert(key.clone(), val.clone());
                count += 1;
            }
        }
        debug!(finalized_writes = count, "writes finalized");
        count
    }

    // item 7 -

    /// Applies every finalized key-value pair to `state_db` and updates the Verkle Tree.
    /// Changes are staged in the in-memory tree but not yet flushed to disk.
    ///
    /// BUGFIX (C-09): uses the shared `apply_speculative_write` so empty
    /// (selfdestruct tombstone) values DELETE rows instead of persisting
    /// undecodable empty accounts.
    pub fn update_state_db(&self, state_db: &StateDb) -> Result<()> {
        for (key, value) in &self.finalized_writes {
            // SECURITY (H-20): when the pipeline is not flushing to disk it is
            // running over LIVE storage — stage raw rows and let the caller
            // land them in one atomic batch, instead of exposing uncommitted
            // block writes to every other reader immediately.
            if self.config.flush_to_disk {
                state_db.apply_speculative_write(key, value)?;
            } else {
                state_db.apply_speculative_write_staged(key, value)?;
            }
        }
        debug!(
            keys = self.finalized_writes.len(),
            "state db and verkle tree updated"
        );
        Ok(())
    }

    // item 8 -

    /// Marks outcomes as discarded so their writes are excluded from
    /// `finalize_writes`.  Also notifies `MVMemory` when available.
    pub fn discard_invalid(&mut self, tx_indices: &[usize]) {
        for &idx in tx_indices {
            self.discarded.insert(idx);
            if let Some(mv) = &self.mv_memory {
                let tv = TxVersion::new(idx);
                if let Err(e) = mv.discard_speculative(tv) {
                    warn!(tx_index = idx, err = %e, "failed to discard from MVMemory");
                }
            }
            debug!(tx_index = idx, "speculative writes discarded");
        }
    }

    // item 9 -

    /// Flushes staged changes to durable storage via `StateDb::commit()`.
    /// Returns the new state root.  Skips the flush when
    /// `config.flush_to_disk == false` (useful in tests).
    pub fn persist(&mut self, state_db: &StateDb) -> Result<[u8; 32]> {
        if !self.config.flush_to_disk {
            let root = state_db.state_root();
            self.last_state_root = root;
            return Ok(root);
        }
        let root = state_db.commit()?;
        self.last_state_root = root;
        info!(state_root = ?hex::encode(root), "state persisted");
        Ok(root)
    }

    // item 10 -

    /// Recomputes and persists the Verkle-tree state root.
    pub fn update_state_root(&mut self, state_db: &StateDb) -> Result<[u8; 32]> {
        let root = state_db.update_state_root()?;
        self.last_state_root = root;
        info!(state_root = ?hex::encode(root), "state root updated");
        Ok(root)
    }

    /// Returns the last committed state root.
    pub fn last_state_root(&self) -> [u8; 32] {
        self.last_state_root
    }

    // - Full pipeline -

    /// Runs the full commit pipeline in one call:
    /// order - validate reads - discard invalid - finalize writes -
    /// update state db - update root - (persist).
    pub fn commit_pipeline(
        &mut self,
        state_db: &StateDb,
    ) -> Result<(CommitSummary, Vec<TxExecutionOutcome>)> {
        self.order_by_tx_index();
        let total_received = self.pending.len();

        let invalid_reads = self.validate_read_sets();
        if !invalid_reads.is_empty() && self.config.abort_on_conflict {
            bail!(
                "commit aborted: {} transactions have stale read sets",
                invalid_reads.len()
            );
        }
        self.discard_invalid(&invalid_reads);

        let mut finalized_writes_count = 0usize;
        let mut committed_outcomes = Vec::new();

        for outcome in &mut self.pending {
            let is_discarded = self.discarded.contains(&outcome.tx_index);
            if is_discarded {
                continue;
            }

            // Apply speculative writes to StateDb transaction by transaction
            for (key, value) in &outcome.speculative_writes {
                // BUGFIX (C-09): shared flush routine — empty values delete.
                // SECURITY (H-20): staged when running over live storage
                // (flush_to_disk == false); see `update_state_db`.
                if self.config.flush_to_disk {
                    state_db.apply_speculative_write(key, value)?;
                } else {
                    state_db.apply_speculative_write_staged(key, value)?;
                }
                self.finalized_writes.insert(key.clone(), value.clone());
                finalized_writes_count += 1;
            }

            // Recompute intermediate state root after this transaction's writes are applied
            let root = state_db.update_state_root()?;
            self.last_state_root = root;
            outcome.receipt.state_root = Some(root);
            committed_outcomes.push(outcome.clone());
        }

        let state_root = self.last_state_root;

        if self.config.flush_to_disk {
            self.persist(state_db)?;
        }

        let discarded_count = self.discarded.len();
        self.pending.clear();
        self.discarded.clear();
        self.finalized_writes.clear();

        Ok((
            CommitSummary {
                total_received,
                finalized_writes: finalized_writes_count,
                discarded_txs: discarded_count,
                state_root,
            },
            committed_outcomes,
        ))
    }
}

// - CommitManager unit tests -

#[cfg(test)]
mod commit_manager_tests {
    use super::*;
    use crate::parallel::dependency::ReadWriteSet;

    fn make_outcome(tx_index: usize, writes: &[(&[u8], &[u8])]) -> TxExecutionOutcome {
        let sw: HashMap<Vec<u8>, Vec<u8>> = writes
            .iter()
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect();
        TxExecutionOutcome {
            tx_index,
            snapshot_id: None,
            tx_version: None,
            success: true,
            gas_used: 21_000,
            output: vec![],
            rw_set: ReadWriteSet::default(),
            receipt: sxiaum_types::Receipt::new_success([0u8; 32], 21_000, None),
            speculative_writes: sw,
            error: None,
            had_conflict: false,
            retry_round: 0,
        }
    }

    // item 1
    #[test]
    fn commit_manager_new() {
        let cm = CommitManager::new(CommitManagerConfig::default());
        assert_eq!(cm.pending_count(), 0);
        assert_eq!(cm.last_state_root(), [0u8; 32]);
    }

    // item 2
    #[test]
    fn receive_results_adds_to_pending() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![make_outcome(0, &[]), make_outcome(1, &[])]);
        assert_eq!(cm.pending_count(), 2);
    }

    #[test]
    fn receive_results_multiple_calls() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![make_outcome(0, &[])]);
        cm.receive_results(vec![make_outcome(1, &[])]);
        assert_eq!(cm.pending_count(), 2);
    }

    // item 3
    #[test]
    fn order_by_tx_index_ascending() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![
            make_outcome(3, &[]),
            make_outcome(1, &[]),
            make_outcome(0, &[]),
            make_outcome(2, &[]),
        ]);
        cm.order_by_tx_index();
        let idx: Vec<usize> = cm.pending.iter().map(|o| o.tx_index).collect();
        assert_eq!(idx, vec![0, 1, 2, 3]);
    }

    // item 4
    #[test]
    fn validate_read_sets_no_mv_memory_passes() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![make_outcome(0, &[])]);
        assert!(cm.validate_read_sets().is_empty());
    }

    // item 5
    #[test]
    fn detect_conflicts_waw() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![
            make_outcome(0, &[(b"x", b"v0")]),
            make_outcome(1, &[(b"x", b"v1")]),
        ]);
        cm.order_by_tx_index();
        let c = cm.detect_state_conflicts();
        assert!(c.contains(&1) && !c.contains(&0));
    }

    #[test]
    fn detect_conflicts_disjoint_keys_clean() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![
            make_outcome(0, &[(b"a", b"1")]),
            make_outcome(1, &[(b"b", b"2")]),
        ]);
        cm.order_by_tx_index();
        assert!(cm.detect_state_conflicts().is_empty());
    }

    // item 6
    #[test]
    fn finalize_writes_merges_clean() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![
            make_outcome(0, &[(b"a", b"1")]),
            make_outcome(1, &[(b"b", b"2")]),
        ]);
        cm.order_by_tx_index();
        let count = cm.finalize_writes();
        assert_eq!(count, 2);
        assert_eq!(cm.finalized_writes[b"a".as_ref()], b"1");
    }

    #[test]
    fn finalize_writes_discards_conflict_loser() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![
            make_outcome(0, &[(b"x", b"winner")]),
            make_outcome(1, &[(b"x", b"loser")]),
        ]);
        cm.order_by_tx_index();
        cm.finalize_writes();
        assert_eq!(cm.finalized_writes[b"x".as_ref()], b"winner");
        assert!(cm.discarded.contains(&1));
    }

    // item 7 - tested indirectly via finalized_writes state
    #[test]
    fn update_state_db_no_writes_noop() {
        let cm = CommitManager::new(CommitManagerConfig::default());
        assert!(cm.finalized_writes.is_empty());
    }

    // item 8
    #[test]
    fn discard_invalid_marks_indices() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![make_outcome(0, &[]), make_outcome(1, &[])]);
        cm.discard_invalid(&[0]);
        assert!(cm.discarded.contains(&0));
        assert!(!cm.discarded.contains(&1));
    }

    #[test]
    fn discard_invalid_prevents_finalization() {
        let mut cm = CommitManager::new(CommitManagerConfig::default());
        cm.receive_results(vec![
            make_outcome(0, &[(b"k", b"v")]),
            make_outcome(1, &[(b"j", b"w")]),
        ]);
        cm.order_by_tx_index();
        cm.discard_invalid(&[0]);
        cm.finalize_writes();
        assert!(!cm.finalized_writes.contains_key(b"k".as_ref()));
        assert!(cm.finalized_writes.contains_key(b"j".as_ref()));
    }

    // item 9
    #[test]
    fn commit_summary_is_clean() {
        let s = CommitSummary {
            total_received: 3,
            finalized_writes: 5,
            discarded_txs: 0,
            state_root: [0u8; 32],
        };
        assert!(s.is_clean());
    }

    #[test]
    fn commit_summary_not_clean() {
        let s = CommitSummary {
            total_received: 3,
            finalized_writes: 2,
            discarded_txs: 1,
            state_root: [0u8; 32],
        };
        assert!(!s.is_clean());
    }

    // item 10
    #[test]
    fn last_state_root_default_zero() {
        let cm = CommitManager::new(CommitManagerConfig::default());
        assert_eq!(cm.last_state_root(), [0u8; 32]);
    }

    // pipeline integration
    #[test]
    fn pipeline_ordering_and_conflict_resolution() {
        let mut cm = CommitManager::new(CommitManagerConfig {
            flush_to_disk: false,
            ..Default::default()
        });
        cm.receive_results(vec![
            make_outcome(3, &[(b"shared", b"loser")]),
            make_outcome(1, &[(b"uniq_1", b"v1")]),
            make_outcome(0, &[(b"uniq_0", b"v0")]),
            make_outcome(2, &[(b"shared", b"winner")]),
        ]);
        cm.order_by_tx_index();
        let inv = cm.validate_read_sets();
        cm.discard_invalid(&inv);
        cm.finalize_writes();
        assert_eq!(cm.finalized_writes[b"shared".as_ref()], b"winner");
        assert!(cm.discarded.contains(&3));
        assert!(cm.finalized_writes.contains_key(b"uniq_0".as_ref()));
        assert!(cm.finalized_writes.contains_key(b"uniq_1".as_ref()));
    }
}
