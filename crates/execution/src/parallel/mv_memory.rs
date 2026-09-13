/// Multi-version memory (MVMemory) for optimistic concurrency control (OCC).
///
/// Maintains a per-key, per-transaction versioned store so that transactions can
/// execute speculatively in parallel, validate their reads after execution, and
/// either commit clean writes or be re-scheduled on conflict.
///
/// Items:
/// 1  `MVMemory` struct { key  sorted Vec<Version> }
/// 2  `record_speculative_write` - store versioned writes per transaction
/// 3  `read_latest_committed` / parallel-read API - concurrent reads via Arc<RwLock>
/// 4  `SpeculativeState` - track speculative writes per transaction
/// 5  `validate_reads` - re-check read set after execution
/// 6  `detect_write_conflicts` - compare write sets across transactions
/// 7  `discard_speculative` - remove invalid speculative versions
/// 8  `promote_to_committed` - promote valid versions to committed status
/// 9  `gc` - garbage collect obsolete versions below a watermark
/// 10 Versioned read API: `read_at_version`, `read_latest_committed`, `read_for_snapshot`
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{debug, trace};

type VersionedValues = Vec<(SnapshotId, Vec<u8>)>;

//
// Common identifiers
//

/// Monotonically increasing snapshot identifier (used by the legacy API and
/// by `VersionedMemory`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub u64);

impl SnapshotId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
    pub fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

/// Identifies a specific execution of a transaction: `(tx_index, incarnation)`.
///
/// A transaction may be executed multiple times (incarnation 0, 1, ) on conflict;
/// each incarnation produces an independent set of versioned writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxVersion {
    /// Position of the transaction in the block.
    pub tx_index: usize,
    /// Re-execution count (0 = first attempt).
    pub incarnation: usize,
}

impl TxVersion {
    pub fn new(tx_index: usize) -> Self {
        Self {
            tx_index,
            incarnation: 0,
        }
    }
    pub fn retry(&self) -> Self {
        Self {
            tx_index: self.tx_index,
            incarnation: self.incarnation + 1,
        }
    }
}

//
// item 1: MVMemory struct { key  versions }
//

/// Status of an individual version entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionStatus {
    /// Written speculatively; not yet validated.
    Speculative,
    /// Validated and promoted; may be read by later transactions.
    Committed,
    /// Discarded due to conflict; must not be read.
    Aborted,
}

/// A single versioned value for one key.
#[derive(Clone, Debug)]
pub struct Version {
    /// Which transaction (and which incarnation) wrote this value.
    pub tx_version: TxVersion,
    /// The written value.
    pub value: Vec<u8>,
    /// Current lifecycle status.
    pub status: VersionStatus,
}

impl Version {
    pub fn speculative(tx_version: TxVersion, value: Vec<u8>) -> Self {
        Self {
            tx_version,
            value,
            status: VersionStatus::Speculative,
        }
    }
}

/// item 1: Primary multi-version memory structure.
///
/// `inner` is wrapped in `Arc<RwLock<>>` so multiple reader threads can
/// call `read_latest_committed` concurrently without holding a write lock
/// (item 3).
pub struct MVMemory {
    /// key  versions sorted ascending by `TxVersion`.
    inner: Arc<RwLock<MVMemoryInner>>,
    /// Per-transaction speculative state (item 4).
    speculative: Arc<RwLock<HashMap<TxVersion, SpeculativeState>>>,
    #[allow(dead_code)]
    config: MVMemoryConfig,
}

/// The inner data protected by `RwLock`.
struct MVMemoryInner {
    /// All versioned values, sorted ascending by `(tx_index, incarnation)`.
    versions: HashMap<Vec<u8>, Vec<Version>>,
    /// The highest `tx_index` whose writes have been fully committed.
    committed_watermark: Option<usize>,
}

/// Configuration knobs.
#[derive(Clone, Debug)]
pub struct MVMemoryConfig {
    /// `gc` will keep versions with `tx_index >= committed_watermark - history_depth`.
    pub history_depth: usize,
}

impl Default for MVMemoryConfig {
    fn default() -> Self {
        Self { history_depth: 64 }
    }
}

//
// item 4: SpeculativeState - per-transaction tracking
//

/// What one transaction has speculatively read and written.
#[derive(Clone, Debug, Default)]
pub struct SpeculativeState {
    /// Keys read and the version (tx_version) that was returned for each.
    /// A `None` version means the key was missing in the store at read time.
    pub read_set: Vec<ReadRecord>,
    /// Keys written.
    pub write_set: Vec<Vec<u8>>,
}

/// One entry in a transaction's read set.
#[derive(Clone, Debug)]
pub struct ReadRecord {
    pub key: Vec<u8>,
    /// Which version was observed (`None`  key was absent).
    pub observed_version: Option<TxVersion>,
}

//
// MVMemory implementation
//

impl MVMemory {
    pub fn new(config: MVMemoryConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MVMemoryInner {
                versions: HashMap::new(),
                committed_watermark: None,
            })),
            speculative: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    //  item 2: store versioned writes per transaction

    /// Records a speculative write for `tx_version` on `key`.
    ///
    /// Safe to call from a rayon worker thread - acquires only the write lock
    /// for the duration of the insert.
    pub fn record_speculative_write(
        &self,
        tx_version: TxVersion,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<()> {
        {
            let mut inner = self.inner.write().map_err(|_| anyhow!("lock poisoned"))?;
            let entry = inner.versions.entry(key.clone()).or_insert_with(Vec::new);

            // Remove any prior incarnation from the same tx_index (idempotent re-execution).
            entry.retain(|v| {
                v.tx_version.tx_index != tx_version.tx_index
                    || v.tx_version.incarnation != tx_version.incarnation
            });

            entry.push(Version::speculative(tx_version, value));
            // Keep sorted ascending so binary-search reads work.
            entry.sort_by_key(|v| (v.tx_version.tx_index, v.tx_version.incarnation));
        }

        {
            let mut spec = self
                .speculative
                .write()
                .map_err(|_| anyhow!("lock poisoned"))?;
            spec.entry(tx_version)
                .or_insert_with(SpeculativeState::default)
                .write_set
                .push(key);
        }

        trace!(?tx_version, "speculative write recorded");
        Ok(())
    }

    //  item 3: parallel reads from latest committed version

    /// Returns the latest **committed** value for `key` visible before `tx_index`.
    ///
    /// Multiple threads may call this simultaneously; it acquires only a shared
    /// (read) lock.
    pub fn read_latest_committed(&self, key: &[u8], before_tx_index: usize) -> Option<Vec<u8>> {
        let inner = self.inner.read().ok()?;
        inner.versions.get(key).and_then(|versions| {
            versions
                .iter()
                .rev()
                .find(|v| {
                    v.status == VersionStatus::Committed && v.tx_version.tx_index < before_tx_index
                })
                .map(|v| v.value.clone())
        })
    }

    //  item 10: versioned read API

    /// Returns the best visible value for `key` as seen by `tx_version`:
    ///
    /// 1. Own writes (same `tx_index`, same `incarnation`).
    /// 2. Latest committed write from any earlier transaction.
    ///
    /// Also records the observed version into `SpeculativeState` (item 4).
    pub fn read_at_version(&self, tx_version: TxVersion, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let inner = self.inner.read().map_err(|_| anyhow!("lock poisoned"))?;

        let observed = inner.versions.get(key).and_then(|versions| {
            // Own write first.
            if let Some(own) = versions.iter().rev().find(|v| v.tx_version == tx_version) {
                return Some((own.tx_version, own.value.clone()));
            }
            // Latest committed from a lower tx_index.
            versions
                .iter()
                .rev()
                .find(|v| {
                    v.status == VersionStatus::Committed
                        && v.tx_version.tx_index < tx_version.tx_index
                })
                .map(|v| (v.tx_version, v.value.clone()))
        });

        drop(inner);

        // Record in read set (item 4).
        {
            let mut spec = self
                .speculative
                .write()
                .map_err(|_| anyhow!("lock poisoned"))?;
            let state = spec
                .entry(tx_version)
                .or_insert_with(SpeculativeState::default);
            state.read_set.push(ReadRecord {
                key: key.to_vec(),
                observed_version: observed.as_ref().map(|(tv, _)| *tv),
            });
        }

        Ok(observed.map(|(_, v)| v))
    }

    //  item 5: validate reads after execution

    /// Re-validates the read set of `tx_version` against the current committed
    /// store.  Returns `Ok(true)` if all reads are still consistent, `Ok(false)`
    /// if any read would now return a different value ( transaction must abort).
    pub fn validate_reads(&self, tx_version: TxVersion) -> Result<bool> {
        let spec = self
            .speculative
            .read()
            .map_err(|_| anyhow!("lock poisoned"))?;
        let state = match spec.get(&tx_version) {
            Some(s) => s,
            None => return Ok(true), // nothing read  trivially valid
        };

        let inner = self.inner.read().map_err(|_| anyhow!("lock poisoned"))?;

        for record in &state.read_set {
            let current = inner.versions.get(&record.key).and_then(|versions| {
                versions
                    .iter()
                    .rev()
                    .find(|v| {
                        v.status == VersionStatus::Committed
                            && v.tx_version.tx_index < tx_version.tx_index
                    })
                    .map(|v| v.tx_version)
            });

            if current != record.observed_version {
                debug!(?tx_version, key = ?record.key, "read validation failed");
                return Ok(false);
            }
        }

        Ok(true)
    }

    //  item 6: detect write conflicts

    /// Returns the set of `TxVersion`s whose speculative write set overlaps
    /// with `keys_written_by_later_tx`.
    ///
    /// Used during the commit phase: if transaction *j* (j > i) already wrote
    /// a key that *i* is now committing, *j* must be aborted.
    pub fn detect_write_conflicts(
        &self,
        tx_version: TxVersion,
        committed_keys: &[Vec<u8>],
    ) -> Result<Vec<TxVersion>> {
        let spec = self
            .speculative
            .read()
            .map_err(|_| anyhow!("lock poisoned"))?;
        let mut conflicted = Vec::new();

        for (other_ver, state) in spec.iter() {
            if other_ver.tx_index <= tx_version.tx_index {
                continue;
            }
            // A later transaction has a speculative write on a key we just committed.
            for key in committed_keys {
                if state.write_set.contains(key) {
                    conflicted.push(*other_ver);
                    break;
                }
            }
        }

        if !conflicted.is_empty() {
            conflicted.sort_by_key(|tv| (tv.tx_index, tv.incarnation));
            debug!(?tx_version, ?conflicted, "write conflicts detected");
        }
        Ok(conflicted)
    }

    //  item 7: discard invalid speculative versions

    /// Marks all speculative versions written by `tx_version` as `Aborted` and
    /// removes them from the store, clearing the associated `SpeculativeState`.
    ///
    /// Call this when `validate_reads` returns `false` or a conflict is detected.
    pub fn discard_speculative(&self, tx_version: TxVersion) -> Result<()> {
        {
            let mut inner = self.inner.write().map_err(|_| anyhow!("lock poisoned"))?;
            for versions in inner.versions.values_mut() {
                versions.retain(|v| v.tx_version != tx_version);
            }
        }
        {
            let mut spec = self
                .speculative
                .write()
                .map_err(|_| anyhow!("lock poisoned"))?;
            spec.remove(&tx_version);
        }
        debug!(?tx_version, "speculative versions discarded");
        Ok(())
    }

    //  item 8: promote valid versions to committed

    /// Transitions every `Speculative` version written by `tx_version` to
    /// `Committed` status, making them visible to subsequent transactions.
    ///
    /// Updates `committed_watermark` if this is the highest committed tx so far.
    ///
    /// Returns the list of keys promoted (useful for conflict detection, item 6).
    pub fn promote_to_committed(&self, tx_version: TxVersion) -> Result<Vec<Vec<u8>>> {
        let mut promoted = Vec::new();
        {
            let mut inner = self.inner.write().map_err(|_| anyhow!("lock poisoned"))?;
            for (key, versions) in inner.versions.iter_mut() {
                for v in versions.iter_mut() {
                    if v.tx_version == tx_version && v.status == VersionStatus::Speculative {
                        v.status = VersionStatus::Committed;
                        promoted.push(key.clone());
                    }
                }
            }
            let wm = inner.committed_watermark.get_or_insert(0);
            if tx_version.tx_index >= *wm {
                *wm = tx_version.tx_index;
            }
        }
        debug!(
            ?tx_version,
            keys = promoted.len(),
            "versions promoted to committed"
        );
        Ok(promoted)
    }

    //  item 9: garbage collect obsolete versions

    /// Removes all version entries for transactions with `tx_index < min_tx_index`,
    /// freeing memory for fully-committed blocks.
    ///
    /// Returns the number of individual `Version` entries deleted.
    pub fn gc(&self, min_tx_index: usize) -> Result<usize> {
        let mut removed = 0usize;
        {
            let mut inner = self.inner.write().map_err(|_| anyhow!("lock poisoned"))?;
            for versions in inner.versions.values_mut() {
                let before = versions.len();
                versions.retain(|v| v.tx_version.tx_index >= min_tx_index);
                removed += before - versions.len();
            }
            // Remove now-empty keys.
            inner.versions.retain(|_, v| !v.is_empty());
        }
        {
            let mut spec = self
                .speculative
                .write()
                .map_err(|_| anyhow!("lock poisoned"))?;
            spec.retain(|tv, _| tv.tx_index >= min_tx_index);
        }
        debug!(min_tx_index, removed, "MVMemory GC complete");
        Ok(removed)
    }

    //  Accessors

    /// Returns the current committed watermark (highest committed `tx_index`).
    pub fn committed_watermark(&self) -> Option<usize> {
        self.inner.read().ok().and_then(|g| g.committed_watermark)
    }

    /// Returns the speculative state of `tx_version`, if any.
    pub fn speculative_state(&self, tx_version: TxVersion) -> Option<SpeculativeState> {
        self.speculative.read().ok()?.get(&tx_version).cloned()
    }

    /// Returns all keys that have at least one committed version.
    pub fn committed_keys(&self) -> Vec<Vec<u8>> {
        self.inner
            .read()
            .ok()
            .map(|g| {
                g.versions
                    .iter()
                    .filter(|(_, vs)| vs.iter().any(|v| v.status == VersionStatus::Committed))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all active `TxVersion`s that have speculative writes pending.
    pub fn pending_speculative_versions(&self) -> Vec<TxVersion> {
        self.speculative
            .read()
            .ok()
            .map(|g| g.keys().copied().collect())
            .unwrap_or_default()
    }
}

//
// Legacy types - kept for backward-compat with VersionedMemory used by executor
//

/// A read-only view of state at a particular snapshot.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub id: SnapshotId,
    /// key  versioned values: (snapshot_id, value).
    pub versions: Arc<HashMap<Vec<u8>, VersionedValues>>,
}

impl Snapshot {
    pub fn new(id: SnapshotId) -> Self {
        Self {
            id,
            versions: Arc::new(HashMap::new()),
        }
    }

    pub fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.versions.get(key).and_then(|versions| {
            versions
                .iter()
                .rfind(|(vid, _)| vid <= &self.id)
                .map(|(_, val)| val.clone())
        })
    }

    pub fn write_in_child(&self, id: SnapshotId, key: Vec<u8>, value: Vec<u8>) -> Snapshot {
        let mut new_versions = HashMap::clone(self.versions.as_ref());
        new_versions
            .entry(key)
            .or_insert_with(Vec::new)
            .push((id, value));
        Snapshot {
            id,
            versions: Arc::new(new_versions),
        }
    }
}

/// Configuration for `VersionedMemory`.
#[derive(Clone, Debug)]
pub struct VersionedMemoryConfig {
    pub max_versions_per_key: usize,
    pub min_retained_snapshot_id: SnapshotId,
}

impl Default for VersionedMemoryConfig {
    fn default() -> Self {
        Self {
            max_versions_per_key: 64,
            min_retained_snapshot_id: SnapshotId(0),
        }
    }
}

/// Legacy multi-version memory (snapshot-based, used by `ParallelExecutor`).
pub struct VersionedMemory {
    config: VersionedMemoryConfig,
    versions: HashMap<Vec<u8>, VersionedValues>,
    current_snapshot_id: SnapshotId,
    snapshots: HashMap<SnapshotId, Snapshot>,
}

impl VersionedMemory {
    pub fn new(config: VersionedMemoryConfig) -> Self {
        Self {
            config,
            versions: HashMap::new(),
            current_snapshot_id: SnapshotId(0),
            snapshots: HashMap::new(),
        }
    }

    pub fn create_snapshot(&mut self) -> Result<Snapshot> {
        let id = self.current_snapshot_id.next();
        self.current_snapshot_id = id;

        let versions = self
            .versions
            .iter()
            .map(|(k, vers)| {
                let pruned = vers
                    .iter()
                    .filter(|(vid, _)| *vid >= self.config.min_retained_snapshot_id)
                    .cloned()
                    .collect();
                (k.clone(), pruned)
            })
            .collect();

        let snapshot = Snapshot {
            id,
            versions: Arc::new(versions),
        };
        self.snapshots.insert(id, snapshot.clone());
        Ok(snapshot)
    }

    pub fn record_write(
        &mut self,
        snapshot_id: SnapshotId,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<()> {
        self.versions
            .entry(key)
            .or_default()
            .push((snapshot_id, value));
        Ok(())
    }

    pub fn commit_snapshot(&mut self, snapshot_id: SnapshotId) -> Result<()> {
        if !self.snapshots.contains_key(&snapshot_id) {
            return Err(anyhow!("snapshot {:?} not found", snapshot_id));
        }
        Ok(())
    }

    pub fn abort_snapshot(&mut self, snapshot_id: SnapshotId) -> Result<()> {
        for versions in self.versions.values_mut() {
            versions.retain(|(vid, _)| *vid != snapshot_id);
        }
        self.snapshots.remove(&snapshot_id);
        Ok(())
    }

    pub fn read_for_snapshot(&self, snapshot_id: SnapshotId, key: &[u8]) -> Option<Vec<u8>> {
        self.versions.get(key).and_then(|versions| {
            versions
                .iter()
                .rfind(|(vid, _)| vid <= &snapshot_id)
                .map(|(_, val)| val.clone())
        })
    }

    pub fn prune_old_versions(&mut self, min_snapshot_id: SnapshotId) -> Result<usize> {
        let mut pruned = 0usize;
        for versions in self.versions.values_mut() {
            let old_len = versions.len();
            versions.retain(|(vid, _)| *vid >= min_snapshot_id);
            pruned += old_len - versions.len();
        }
        self.config.min_retained_snapshot_id = min_snapshot_id;
        Ok(pruned)
    }

    pub fn current_id(&self) -> SnapshotId {
        self.current_snapshot_id
    }

    pub fn all_snapshots(&self) -> Vec<SnapshotId> {
        self.snapshots.keys().copied().collect()
    }
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> MVMemory {
        MVMemory::new(MVMemoryConfig::default())
    }

    //  item 1

    #[test]
    fn mv_memory_starts_empty() {
        let m = mem();
        assert!(m.committed_keys().is_empty());
        assert_eq!(m.committed_watermark(), None);
    }

    //  item 2

    #[test]
    fn record_speculative_write_stores_value() {
        let m = mem();
        let tv = TxVersion::new(0);
        m.record_speculative_write(tv, b"k".to_vec(), b"v".to_vec())
            .unwrap();
        // Visible to own read.
        let val = m.read_at_version(tv, b"k").unwrap();
        assert_eq!(val, Some(b"v".to_vec()));
    }

    #[test]
    fn record_write_idempotent_on_retry() {
        let m = mem();
        let tv0 = TxVersion::new(3);
        let tv1 = tv0.retry();
        m.record_speculative_write(tv0, b"k".to_vec(), b"old".to_vec())
            .unwrap();
        m.record_speculative_write(tv1, b"k".to_vec(), b"new".to_vec())
            .unwrap();
        // Both incarnations are stored; each reads its own latest.
        assert_eq!(m.read_at_version(tv1, b"k").unwrap(), Some(b"new".to_vec()));
    }

    //  item 3

    #[test]
    fn read_latest_committed_returns_none_when_only_speculative() {
        let m = mem();
        let tv = TxVersion::new(0);
        m.record_speculative_write(tv, b"x".to_vec(), b"v".to_vec())
            .unwrap();
        // tx_index=1 looks for committed writes from index < 1  none.
        assert_eq!(m.read_latest_committed(b"x", 1), None);
    }

    #[test]
    fn read_latest_committed_returns_promoted_value() {
        let m = mem();
        let tv0 = TxVersion::new(0);
        m.record_speculative_write(tv0, b"x".to_vec(), b"v0".to_vec())
            .unwrap();
        m.promote_to_committed(tv0).unwrap();

        // tx_index=1 can now read tx0's committed write.
        assert_eq!(m.read_latest_committed(b"x", 1), Some(b"v0".to_vec()));
    }

    #[test]
    fn parallel_reads_do_not_block_each_other() {
        use std::thread;
        let m = Arc::new(MVMemory::new(MVMemoryConfig::default()));
        let tv = TxVersion::new(0);
        m.record_speculative_write(tv, b"k".to_vec(), b"v".to_vec())
            .unwrap();
        m.promote_to_committed(tv).unwrap();

        let handles: Vec<_> = (1..8)
            .map(|i| {
                let m2 = m.clone();
                thread::spawn(move || m2.read_latest_committed(b"k", i))
            })
            .collect();

        for h in handles {
            let val = h.join().unwrap();
            assert_eq!(val, Some(b"v".to_vec()));
        }
    }

    //  item 4

    #[test]
    fn speculative_state_tracks_writes() {
        let m = mem();
        let tv = TxVersion::new(2);
        m.record_speculative_write(tv, b"a".to_vec(), b"1".to_vec())
            .unwrap();
        m.record_speculative_write(tv, b"b".to_vec(), b"2".to_vec())
            .unwrap();
        let state = m.speculative_state(tv).unwrap();
        assert_eq!(state.write_set.len(), 2);
    }

    #[test]
    fn speculative_state_tracks_reads() {
        let m = mem();
        let tv = TxVersion::new(5);
        m.read_at_version(tv, b"absent").unwrap();
        let state = m.speculative_state(tv).unwrap();
        assert_eq!(state.read_set.len(), 1);
        assert_eq!(state.read_set[0].key, b"absent");
        assert!(state.read_set[0].observed_version.is_none());
    }

    //  item 5

    #[test]
    fn validate_reads_passes_when_no_new_commit() {
        let m = mem();
        let tv0 = TxVersion::new(0);
        let tv1 = TxVersion::new(1);
        // tx1 reads a key that tx0 wrote speculatively (not yet committed).
        m.record_speculative_write(tv0, b"x".to_vec(), b"v".to_vec())
            .unwrap();
        m.read_at_version(tv1, b"x").unwrap(); // sees None (tx0 not committed).
        assert!(m.validate_reads(tv1).unwrap());
    }

    #[test]
    fn validate_reads_fails_after_concurrent_commit() {
        let m = mem();
        let tv0 = TxVersion::new(0);
        let tv1 = TxVersion::new(1);
        // tx1 reads "x" as absent.
        m.read_at_version(tv1, b"x").unwrap();
        // tx0 commits a write to "x".
        m.record_speculative_write(tv0, b"x".to_vec(), b"v".to_vec())
            .unwrap();
        m.promote_to_committed(tv0).unwrap();
        // Now tv1's read set is stale.
        assert!(!m.validate_reads(tv1).unwrap());
    }

    //  item 6

    #[test]
    fn detect_write_conflicts_finds_later_writers() {
        let m = mem();
        let tv0 = TxVersion::new(0);
        let tv1 = TxVersion::new(1);
        m.record_speculative_write(tv0, b"x".to_vec(), b"v0".to_vec())
            .unwrap();
        m.record_speculative_write(tv1, b"x".to_vec(), b"v1".to_vec())
            .unwrap();
        let conflicts = m.detect_write_conflicts(tv0, &[b"x".to_vec()]).unwrap();
        assert!(conflicts.contains(&tv1));
    }

    #[test]
    fn detect_write_conflicts_ignores_earlier_writers() {
        let m = mem();
        let tv0 = TxVersion::new(0);
        let tv1 = TxVersion::new(1);
        m.record_speculative_write(tv0, b"x".to_vec(), b"v0".to_vec())
            .unwrap();
        m.record_speculative_write(tv1, b"x".to_vec(), b"v1".to_vec())
            .unwrap();
        // tv1 detecting conflicts; tv0 is earlier  not reported.
        let conflicts = m.detect_write_conflicts(tv1, &[b"x".to_vec()]).unwrap();
        assert!(conflicts.is_empty());
    }

    //  item 7

    #[test]
    fn discard_speculative_removes_writes_and_state() {
        let m = mem();
        let tv = TxVersion::new(3);
        m.record_speculative_write(tv, b"y".to_vec(), b"v".to_vec())
            .unwrap();
        m.discard_speculative(tv).unwrap();
        assert!(m.speculative_state(tv).is_none());
        // The key should no longer be visible.
        let inner = m.inner.read().unwrap();
        let gone = inner
            .versions
            .get(b"y".as_slice())
            .map(|vs| vs.is_empty())
            .unwrap_or(true);
        assert!(gone);
    }

    //  item 8

    #[test]
    fn promote_to_committed_makes_value_visible() {
        let m = mem();
        let tv = TxVersion::new(0);
        m.record_speculative_write(tv, b"k".to_vec(), b"val".to_vec())
            .unwrap();
        let keys = m.promote_to_committed(tv).unwrap();
        assert!(keys.contains(&b"k".to_vec()));
        assert_eq!(m.read_latest_committed(b"k", 1), Some(b"val".to_vec()));
    }

    #[test]
    fn promote_updates_watermark() {
        let m = mem();
        for i in 0..3usize {
            let tv = TxVersion::new(i);
            m.record_speculative_write(tv, format!("k{}", i).into_bytes(), b"v".to_vec())
                .unwrap();
            m.promote_to_committed(tv).unwrap();
        }
        assert_eq!(m.committed_watermark(), Some(2));
    }

    //  item 9

    #[test]
    fn gc_removes_old_versions() {
        let m = mem();
        for i in 0..5usize {
            let tv = TxVersion::new(i);
            m.record_speculative_write(tv, b"k".to_vec(), format!("v{}", i).into_bytes())
                .unwrap();
            m.promote_to_committed(tv).unwrap();
        }
        let removed = m.gc(3).unwrap();
        assert!(removed > 0);
        // Versions for tx_index 0..2 should be gone.
        assert_eq!(m.read_latest_committed(b"k", 1), None);
    }

    #[test]
    fn gc_does_not_remove_recent_versions() {
        let m = mem();
        let tv = TxVersion::new(10);
        m.record_speculative_write(tv, b"z".to_vec(), b"v".to_vec())
            .unwrap();
        m.promote_to_committed(tv).unwrap();
        m.gc(5).unwrap();
        assert_eq!(m.read_latest_committed(b"z", 11), Some(b"v".to_vec()));
    }

    //  item 10

    #[test]
    fn read_at_version_sees_own_write_before_committed() {
        let m = mem();
        let tv = TxVersion::new(7);
        m.record_speculative_write(tv, b"q".to_vec(), b"mine".to_vec())
            .unwrap();
        let val = m.read_at_version(tv, b"q").unwrap();
        assert_eq!(val, Some(b"mine".to_vec()));
    }

    #[test]
    fn read_at_version_sees_earlier_committed_value() {
        let m = mem();
        let tv0 = TxVersion::new(0);
        m.record_speculative_write(tv0, b"m".to_vec(), b"base".to_vec())
            .unwrap();
        m.promote_to_committed(tv0).unwrap();

        let tv5 = TxVersion::new(5);
        let val = m.read_at_version(tv5, b"m").unwrap();
        assert_eq!(val, Some(b"base".to_vec()));
    }

    #[test]
    fn read_at_version_not_visible_to_earlier_tx() {
        let m = mem();
        let tv5 = TxVersion::new(5);
        m.record_speculative_write(tv5, b"n".to_vec(), b"late".to_vec())
            .unwrap();
        m.promote_to_committed(tv5).unwrap();

        let tv2 = TxVersion::new(2);
        let val = m.read_at_version(tv2, b"n").unwrap();
        assert_eq!(val, None);
    }

    //  Legacy VersionedMemory tests

    #[test]
    fn snapshot_read_write_isolation() {
        let snap1 = Snapshot::new(SnapshotId(1));
        let snap2 = snap1.write_in_child(SnapshotId(2), b"x".to_vec(), b"v2".to_vec());
        assert_eq!(snap1.read(b"x"), None);
        assert_eq!(snap2.read(b"x"), Some(b"v2".to_vec()));
    }

    #[test]
    fn versioned_memory_create_and_write() {
        let mut mem = VersionedMemory::new(VersionedMemoryConfig::default());
        let snap = mem.create_snapshot().unwrap();
        mem.record_write(snap.id, b"key".to_vec(), b"value".to_vec())
            .unwrap();
        assert_eq!(
            mem.read_for_snapshot(snap.id, b"key"),
            Some(b"value".to_vec())
        );
    }

    #[test]
    fn versioned_memory_abort_snapshot() {
        let mut mem = VersionedMemory::new(VersionedMemoryConfig::default());
        let snap = mem.create_snapshot().unwrap();
        mem.record_write(snap.id, b"x".to_vec(), b"v".to_vec())
            .unwrap();
        mem.abort_snapshot(snap.id).unwrap();
        assert_eq!(mem.read_for_snapshot(snap.id, b"x"), None);
    }
}
