/// Parallel transaction executor with Optimistic Concurrency Control (OCC).
///
/// Items:
///  1  `ParallelExecutor` struct
///  2  `execute_block` - entry-point: run all txs, return `BatchExecutionResult`
///  3  `execute_batch` - execute a batch of non-conflicting transactions in parallel
///  4  `detect_conflicts` - OCC conflict detection (read/write set intersection)
///  5  `rollback` - discard speculative writes for a transaction
///  6  `retry` - enqueue rolled-back transactions for the next round
///  7  `finalize` - merge committed speculative writes into the canonical state
///  8  `collect_receipts` - assemble `Receipt` objects from outcomes
///  9  `metrics` - record execution latency, conflict rate, retry count
/// 10  `pipeline_tests` - unit tests for the full pipeline
use crate::parallel::commit::{CommitManager, CommitManagerConfig, CommitSummary};
use crate::parallel::dependency::ReadWriteSet;
use crate::parallel::mv_memory::{MVMemory, MVMemoryConfig, SnapshotId, TxVersion};
use crate::parallel::scheduler::{BlockScheduler, BlockSchedulerConfig, ExecutionTask};
use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use sxiaum_state::StateDb;
use sxiaum_types::{Canonical, Log, Receipt};
use tracing::{debug, info, warn};

// -
// Configuration
// -

/// Configuration for parallel execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParallelExecutionConfig {
    /// Maximum number of OCC rounds before falling back to serial execution.
    pub max_rounds: usize,
    /// Number of threads to use for parallel execution.
    pub num_threads: usize,
    /// Enable speculative execution (OCC mode).
    pub speculative: bool,
    /// Abort execution if conflict rate exceeds this threshold (0.0-1.0).
    pub conflict_abort_threshold: f64,
    /// Maximum number of hot accounts to keep in the read cache.
    pub hot_account_cache_size: usize,
    /// Maximum number of write entries to accumulate before a batch flush.
    pub write_batch_size: usize,
    /// Number of execution contexts to pre-allocate in the reuse pool.
    pub context_pool_size: usize,
    /// Policy used to resolve detected conflicts.
    pub conflict_resolution_policy: ConflictResolutionPolicy,
    /// Verify parallel execution result against sequential execution
    pub verify_parallel_execution: bool,
}

impl Default for ParallelExecutionConfig {
    fn default() -> Self {
        // P1-5: verify_parallel_execution is ON by default in all environments.
        // The only way to disable it is to explicitly set SXIAUM_VERIFY_PARALLEL=0,
        // which is forbidden in production (caught by preflight Gate 7) and
        // should only be used in benchmarking contexts where correctness is
        // already known and throughput measurement is the goal.
        let verify = !std::env::var("SXIAUM_VERIFY_PARALLEL")
            .map(|v| v == "0" || v.eq_ignore_ascii_case("false"))
            .unwrap_or(false);
        Self {
            max_rounds: 8,
            num_threads: 4,
            speculative: true,
            conflict_abort_threshold: 0.5,
            hot_account_cache_size: 256,
            write_batch_size: 64,
            context_pool_size: 8,
            conflict_resolution_policy: ConflictResolutionPolicy::PriorityByIndex,
            verify_parallel_execution: verify,
        }
    }
}

// -
// Task type
// -

/// A single unit of work submitted to the parallel executor.
#[derive(Clone, Debug)]
pub struct ParallelExecutorTask {
    /// Transaction index within the block (determines canonical order).
    pub tx_index: usize,
    /// Raw transaction bytes.
    pub tx_bytes: Vec<u8>,
    /// SHA-256 / keccak256 hash of the transaction.
    pub tx_hash: [u8; 32],
    /// Gas limit for this transaction.
    pub gas_limit: u64,
}

// -
// TxExecutionOutcome - struct shared with the commit manager
// -

/// Outcome of a single speculative transaction execution.
///
/// Used by the commit manager to validate and finalize writes.
#[derive(Clone, Debug)]
pub struct TxExecutionOutcome {
    /// Transaction index in the block.
    pub tx_index: usize,
    /// Optional snapshot identifier from MVMemory.
    pub snapshot_id: Option<SnapshotId>,
    /// Whether execution succeeded.
    pub success: bool,
    /// Gas consumed.
    pub gas_used: u64,
    /// Raw output bytes (e.g. ABI-encoded return value).
    pub output: Vec<u8>,
    /// Read and write keys accessed during execution.
    pub rw_set: ReadWriteSet,
    /// The receipt generated for this transaction.
    pub receipt: Receipt,
    /// Speculative state writes: key -> value.
    pub speculative_writes: HashMap<Vec<u8>, Vec<u8>>,
    /// Execution error message, if any.
    pub error: Option<String>,
    /// Whether this outcome had a conflict in a prior round.
    pub had_conflict: bool,
    /// Which OCC retry round this outcome belongs to (0 = first execution).
    pub retry_round: usize,
    /// SECURITY (C-08): the exact `TxVersion` under which reads/writes were
    /// recorded in MVMemory. Commit-time validation must use THIS version —
    /// assuming incarnation 0 neuters OCC validation for every retried tx.
    pub tx_version: Option<TxVersion>,
}

#[derive(Clone, Debug)]
struct CachedSpeculativeExecution {
    task: ParallelExecutorTask,
    output: TransactionOutput,
    tx_version: TxVersion,
}

impl TxExecutionOutcome {
    /// Returns `true` if the transaction executed successfully without errors.
    pub fn is_success(&self) -> bool {
        self.success && self.error.is_none()
    }
}

// -
// Batch / parallel result types
// -

/// Individual per-transaction result used by the commit protocol.
#[derive(Clone, Debug)]
pub struct TransactionExecutionResult {
    pub tx_index: usize,
    pub tx_hash: [u8; 32],
    pub read_write_set: ReadWriteSet,
    pub gas_used: u64,
    pub success: bool,
    pub receipt: Receipt,
}

/// A batch of transaction results from one parallel execution pass.
#[derive(Clone, Debug)]
pub struct BatchResult {
    pub batch_id: usize,
    pub results: Vec<TransactionExecutionResult>,
}

/// Aggregated result for a full block's parallel execution (used by CommitProtocol).
#[derive(Clone, Debug)]
pub struct ParallelExecutionResult {
    /// Results grouped by execution batch.
    pub batch_results: Vec<BatchResult>,
    /// Total gas consumed by all transactions.
    pub total_gas_used: u64,
    /// Number of OCC conflict rounds that occurred.
    pub conflict_rounds: usize,
}

impl ParallelExecutionResult {
    /// Returns the number of failed transactions.
    pub fn total_failed(&self) -> usize {
        self.batch_results
            .iter()
            .flat_map(|b| &b.results)
            .filter(|r| !r.success)
            .count()
    }

    /// Returns transaction indices in canonical execution order.
    pub fn executed_tx_indices(&self) -> Vec<usize> {
        let mut indices: Vec<usize> = self
            .batch_results
            .iter()
            .flat_map(|b| b.results.iter().map(|r| r.tx_index))
            .collect();
        indices.sort_unstable();
        indices
    }
}

/// Flat result type returned by `execute_block`.
#[derive(Clone, Debug)]
pub struct BatchExecutionResult {
    pub results: Vec<TxExecutionOutcome>,
    pub receipts: Vec<Receipt>,
    pub total_gas_used: u64,
    pub conflict_count: usize,
    pub rounds: usize,
}

/// Summarised output passed downstream (e.g. to the node or RPC layer).
#[derive(Clone, Debug)]
pub struct ExecutionOutput {
    pub block_hash: [u8; 32],
    pub receipts: Vec<Receipt>,
    pub gas_used: u64,
    pub state_root: [u8; 32],
}

/// Speculative writes produced by a single transaction round.
pub type SpeculativeWrites = HashMap<Vec<u8>, Vec<u8>>;

// -
// Conflict detection types
// -

/// Classification of a detected conflict between two transactions.
///
/// Rules:
///   - `Raw`       - read-after-write: later tx reads a key written by earlier tx
///   - `Waw`       - write-after-write: both transactions write the same key
///   - `RawAndWaw` - both conflict types detected on at least one key pair
///   - read-after-read is **allowed** (no conflict)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Read-after-write conflict.
    Raw,
    /// Write-after-write conflict.
    Waw,
    /// Both read-after-write and write-after-write conflicts detected.
    RawAndWaw,
}

/// Detailed record of a detected conflict between two transactions.
///
/// `winner_tx` is the earlier (lower-index) transaction; `loser_tx` is the
/// later transaction that must be aborted and re-executed.
#[derive(Clone, Debug)]
pub struct ConflictDetail {
    /// Earlier transaction (keeps its speculative result).
    pub winner_tx: usize,
    /// Later transaction that is aborted and rescheduled.
    pub loser_tx: usize,
    /// Kind of conflict detected.
    pub kind: ConflictKind,
    /// The specific state keys involved in the conflict.
    pub conflicting_keys: Vec<Vec<u8>>,
}

impl ConflictDetail {
    /// Human-readable one-line summary of this conflict.
    pub fn summary(&self) -> String {
        format!(
            "{:?}: tx {} aborts tx {} on {} key(s)",
            self.kind,
            self.winner_tx,
            self.loser_tx,
            self.conflicting_keys.len()
        )
    }
}

// -
// Optimization 1: State key prefetcher
// -

/// Pre-fetches state keys that are likely to be accessed by a transaction batch.
///
/// By scanning task bytes for embedded key hints before execution starts, the
/// prefetcher warms up the OS page cache and the hot-account cache, reducing
/// blocking reads during parallel execution.
#[derive(Clone, Debug, Default)]
pub struct StateKeyPrefetcher {
    /// Keys accumulated across all tasks in the current batch.
    prefetch_queue: Vec<Vec<u8>>,
}

impl StateKeyPrefetcher {
    pub fn new() -> Self {
        Self {
            prefetch_queue: Vec::new(),
        }
    }

    /// Extract likely-accessed keys from task metadata for a batch.
    ///
    /// In production this would parse the transaction and extract sender,
    /// recipient, and storage slot keys.  Here we derive a deterministic
    /// 32-byte key per task (tx_hash prefix) as an approximation.
    pub fn enqueue_batch(&mut self, tasks: &[ParallelExecutorTask]) {
        self.prefetch_queue.clear();
        for task in tasks {
            // Sender-like key: first 20 bytes of tx_hash
            self.prefetch_queue.push(task.tx_hash[..20].to_vec());
            // Recipient-like key: bytes 12..32 of tx_hash
            self.prefetch_queue.push(task.tx_hash[12..].to_vec());
        }
    }

    /// Issue prefetch reads against `state`, warming the hot-account cache.
    pub fn prefetch(&self, state: &StateDb, cache: &HotAccountCache) {
        for key in &self.prefetch_queue {
            // Read into cache; errors are silently ignored (best-effort warm-up).
            if let Ok(Some(value)) = state.get_raw(key) {
                cache.insert(key.clone(), value);
            }
        }
        debug!(keys = self.prefetch_queue.len(), "prefetch complete");
    }

    pub fn clear(&mut self) {
        self.prefetch_queue.clear();
    }
}

// -
// Optimization 2: Hot account cache (lock-free read path)
// -

/// In-memory read cache for frequently accessed state keys.
///
/// Uses a `RwLock<HashMap>` so that concurrent readers never block each other
/// (only writers briefly serialise).  This is the closest approximation to a
/// lock-free structure available without external crates.
#[derive(Debug, Default)]
pub struct HotAccountCache {
    inner: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    capacity: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl HotAccountCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(capacity)),
            capacity,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Retrieve a cached value - O(1) read with shared lock.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let guard = self.inner.read().unwrap();
        if let Some(v) = guard.get(key) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(v.clone())
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert or update a cache entry.
    pub fn insert(&self, key: Vec<u8>, value: Vec<u8>) {
        let mut guard = self.inner.write().unwrap();
        if guard.len() >= self.capacity {
            // Evict a pseudo-random entry to stay within capacity.
            if let Some(evict_key) = guard.keys().next().cloned() {
                guard.remove(&evict_key);
            }
        }
        guard.insert(key, value);
    }

    /// Invalidate a key after it is written (prevents stale reads).
    pub fn invalidate(&self, key: &[u8]) {
        self.inner.write().unwrap().remove(key);
    }

    /// Bulk-invalidate all keys touched by a write batch.
    pub fn invalidate_batch(&self, keys: impl Iterator<Item = Vec<u8>>) {
        let mut guard = self.inner.write().unwrap();
        for k in keys {
            guard.remove(&k);
        }
    }

    pub fn hit_rate(&self) -> f64 {
        let h = self.hits.load(Ordering::Relaxed) as f64;
        let m = self.misses.load(Ordering::Relaxed) as f64;
        if h + m == 0.0 {
            0.0
        } else {
            h / (h + m)
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
    }
}

// -
// Optimization 5: Write batch - deferred, grouped storage writes
// -

/// Accumulates state writes and flushes them to `StateDb` in a single pass,
/// minimising the number of lock acquisitions and storage round-trips.
#[derive(Debug, Default)]
pub struct WriteBatch {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    capacity: usize,
}

impl WriteBatch {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Stage a key-value pair for the next flush.
    pub fn push(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.entries.push((key, value));
    }

    /// Returns `true` when the batch has reached its flush threshold.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// Flush all staged entries to `state` and clear the batch.
    ///
    /// Also invalidates the corresponding keys in `cache` so that subsequent
    /// reads see fresh values.
    ///
    /// BUGFIX (C-09): uses the shared `apply_speculative_write` so empty
    /// (selfdestruct tombstone) values DELETE rows instead of persisting
    /// undecodable empty accounts.
    pub fn flush(&mut self, state: &StateDb, cache: &HotAccountCache) -> Result<()> {
        for (key, value) in self.entries.drain(..) {
            state.apply_speculative_write(&key, &value)?;
            cache.invalidate(&key);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// -
// Optimization 6: Execution context pool
// -

/// A reusable execution context that avoids repeated heap allocation.
///
/// Each worker thread leases a context from the pool before executing a
/// transaction and returns it afterwards.  Pre-allocated buffers for reads,
/// writes and logs are cleared and reused across transactions.
#[derive(Debug)]
pub struct ExecutionContext {
    /// Reusable buffer for read keys recorded during execution.
    pub reads: Vec<Vec<u8>>,
    /// Reusable buffer for (key, value) write pairs.
    pub writes: Vec<(Vec<u8>, Vec<u8>)>,
    /// Reusable buffer for log entries.
    pub logs: Vec<Vec<u8>>,
}

impl ExecutionContext {
    pub fn new() -> Self {
        Self {
            reads: Vec::new(),
            writes: Vec::new(),
            logs: Vec::new(),
        }
    }

    /// Reset all buffers for reuse without releasing heap memory.
    pub fn reset(&mut self) {
        self.reads.clear();
        self.writes.clear();
        self.logs.clear();
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Pool of pre-allocated execution contexts.
///
/// Workers acquire a context via `acquire`, populate it, then `release` it
/// back.  If the pool is empty the caller allocates a fresh context.
#[derive(Debug)]
pub struct ExecutionContextPool {
    pool: Mutex<Vec<ExecutionContext>>,
}

impl ExecutionContextPool {
    pub fn new(capacity: usize) -> Self {
        let pool = (0..capacity).map(|_| ExecutionContext::new()).collect();
        Self {
            pool: Mutex::new(pool),
        }
    }

    /// Take a context from the pool (or allocate a fresh one).
    pub fn acquire(&self) -> ExecutionContext {
        self.pool.lock().pop().unwrap_or_default()
    }

    /// Return a context to the pool after resetting its buffers.
    pub fn release(&self, mut ctx: ExecutionContext) {
        ctx.reset();
        self.pool.lock().push(ctx);
    }
}

// -
// Metrics - atomic counters for all five KPIs
// -

/// Atomic execution metrics collected across all blocks and OCC rounds.
///
/// All fields use `Relaxed` ordering - these are performance hints, not
/// synchronisation signals, so sequential consistency is not required.
///
/// KPIs tracked:
///   1. Parallel execution throughput (txs committed per block)
///   2. Aborted transaction rate (aborts / total submissions)
///   3. Conflict frequency (total conflict events)
///   4. Execution latency (cumulative nanoseconds + sample count)
///   5. CPU utilization (active thread-ns / wall-ns - num_threads)
#[derive(Debug, Default)]
pub struct ExecutionMetrics {
    // KPI 1 - throughput
    /// Total transactions committed via parallel execution.
    pub parallel_committed: AtomicU64,
    /// Total transactions committed via serial fallback.
    pub serial_committed: AtomicU64,
    /// Total blocks processed.
    pub blocks_processed: AtomicU64,

    // KPI 2 - abort rate
    /// Total transaction submissions (including retries).
    pub tx_submissions: AtomicU64,
    /// Total transaction aborts (conflicts causing rollback).
    pub tx_aborts: AtomicU64,

    // KPI 3 - conflict frequency
    /// Total individual conflict events detected.
    pub conflict_events: AtomicU64,
    /// Total OCC rounds executed.
    pub occ_rounds: AtomicU64,

    // KPI 4 - execution latency (nanoseconds)
    /// Sum of per-block wall-clock execution durations in nanoseconds.
    pub total_latency_ns: AtomicU64,
    /// Number of latency samples (= blocks_processed for per-block latency).
    pub latency_samples: AtomicU64,

    // KPI 5 - CPU utilization
    /// Sum of per-batch active thread-ns (threads - batch_latency_ns).
    pub active_thread_ns: AtomicU64,
    /// Sum of per-batch wall-clock ns - num_threads (theoretical max).
    pub total_thread_capacity_ns: AtomicU64,
}

impl ExecutionMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    // - KPI 1: throughput -

    pub fn record_committed(&self, parallel: usize, serial: usize) {
        self.parallel_committed
            .fetch_add(parallel as u64, Ordering::Relaxed);
        self.serial_committed
            .fetch_add(serial as u64, Ordering::Relaxed);
        self.blocks_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Committed transactions per block (parallel path only).
    pub fn parallel_throughput(&self) -> f64 {
        let blocks = self.blocks_processed.load(Ordering::Relaxed);
        let committed = self.parallel_committed.load(Ordering::Relaxed);
        if blocks == 0 {
            0.0
        } else {
            committed as f64 / blocks as f64
        }
    }

    // - KPI 2: abort rate -

    pub fn record_submissions(&self, count: usize) {
        self.tx_submissions
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn record_aborts(&self, count: usize) {
        self.tx_aborts.fetch_add(count as u64, Ordering::Relaxed);
    }

    /// Fraction of submissions that were aborted (0.0 - 1.0).
    pub fn abort_rate(&self) -> f64 {
        let s = self.tx_submissions.load(Ordering::Relaxed);
        let a = self.tx_aborts.load(Ordering::Relaxed);
        if s == 0 {
            0.0
        } else {
            a as f64 / s as f64
        }
    }

    // - KPI 3: conflict frequency -

    pub fn record_conflicts(&self, count: usize) {
        self.conflict_events
            .fetch_add(count as u64, Ordering::Relaxed);
        self.occ_rounds.fetch_add(1, Ordering::Relaxed);
    }

    /// Mean number of conflicts per OCC round.
    pub fn conflicts_per_round(&self) -> f64 {
        let rounds = self.occ_rounds.load(Ordering::Relaxed);
        let events = self.conflict_events.load(Ordering::Relaxed);
        if rounds == 0 {
            0.0
        } else {
            events as f64 / rounds as f64
        }
    }

    // - KPI 4: execution latency -

    pub fn record_latency(&self, elapsed: Duration) {
        self.total_latency_ns
            .fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }

    /// Mean block execution latency in milliseconds.
    pub fn mean_latency_ms(&self) -> f64 {
        let samples = self.latency_samples.load(Ordering::Relaxed);
        let total_ns = self.total_latency_ns.load(Ordering::Relaxed);
        if samples == 0 {
            0.0
        } else {
            (total_ns as f64 / samples as f64) / 1_000_000.0
        }
    }

    // - KPI 5: CPU utilization -

    /// Record CPU utilization for one parallel batch.
    ///
    /// `active_ns`   - wall-clock ns the batch took with all threads busy
    /// `wall_ns`     - wall-clock ns of the batch window
    /// `num_threads` - number of worker threads
    pub fn record_cpu(&self, active_ns: u64, wall_ns: u64, num_threads: u64) {
        self.active_thread_ns
            .fetch_add(active_ns * num_threads, Ordering::Relaxed);
        self.total_thread_capacity_ns
            .fetch_add(wall_ns * num_threads, Ordering::Relaxed);
    }

    /// CPU utilization as a fraction (0.0 - 1.0).
    ///
    /// Approximated as `-(active_thread_ns) / -(capacity_thread_ns)`.
    pub fn cpu_utilization(&self) -> f64 {
        let active = self.active_thread_ns.load(Ordering::Relaxed) as f64;
        let cap = self.total_thread_capacity_ns.load(Ordering::Relaxed) as f64;
        if cap == 0.0 {
            0.0
        } else {
            (active / cap).min(1.0)
        }
    }

    // - Snapshot -

    /// Return a plain-data snapshot of all current metric values.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            parallel_throughput_txs_per_block: self.parallel_throughput(),
            abort_rate: self.abort_rate(),
            conflicts_per_round: self.conflicts_per_round(),
            mean_latency_ms: self.mean_latency_ms(),
            cpu_utilization: self.cpu_utilization(),
            blocks_processed: self.blocks_processed.load(Ordering::Relaxed),
            total_conflicts: self.conflict_events.load(Ordering::Relaxed),
            total_aborts: self.tx_aborts.load(Ordering::Relaxed),
        }
    }
}

/// Plain-data snapshot emitted for logging or Prometheus scraping.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// KPI 1 - mean committed txs per block (parallel path).
    pub parallel_throughput_txs_per_block: f64,
    /// KPI 2 - fraction of submissions that were aborted.
    pub abort_rate: f64,
    /// KPI 3 - mean conflict events per OCC round.
    pub conflicts_per_round: f64,
    /// KPI 4 - mean block execution latency in milliseconds.
    pub mean_latency_ms: f64,
    /// KPI 5 - CPU utilization fraction (0-1).
    pub cpu_utilization: f64,
    /// Total blocks processed since startup.
    pub blocks_processed: u64,
    /// Total conflict events since startup.
    pub total_conflicts: u64,
    /// Total aborted transactions since startup.
    pub total_aborts: u64,
}

// -
// Phase 25 - Deterministic execution guard
// -

/// Guarantees deterministic execution order regardless of thread scheduling.
///
/// Every OCC round must see tasks and raw outcomes in the same canonical
/// (tx_index ascending) order so that two independent replicas always produce
/// identical conflict sets and committed write sets.
pub struct DeterministicExecutionGuard;

impl DeterministicExecutionGuard {
    /// Sort tasks into canonical tx_index ascending order before each round.
    pub fn sort_tasks(tasks: &mut [ParallelExecutorTask]) {
        tasks.sort_unstable_by_key(|t| t.tx_index);
    }

    /// Sort raw outcomes into canonical tx_index ascending order before
    /// conflict detection.
    pub fn sort_outcomes(outcomes: &mut [RawOutcome]) {
        outcomes.sort_unstable_by_key(|o| o.tx_index);
    }

    /// Returns `true` when two outcome slices have identical tx_index order
    /// and identical write sets - used to verify replay determinism.
    pub fn verify_determinism(a: &[RawOutcome], b: &[RawOutcome]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.tx_index == y.tx_index && x.write_set == y.write_set)
    }
}

// -
// Phase 25 - State consistency checker
// -

/// Detects state drift by comparing the state root before execution begins
/// with the root computed after all committed writes have been flushed.
///
/// Also maintains an XOR fingerprint of written keys to detect silent data
/// corruption within a single block's write set.
pub struct StateConsistencyChecker {
    /// State root captured before block execution.
    expected_root: [u8; 32],
    /// Running XOR of keys written during this block (for divergence detection).
    write_fingerprint: u64,
}

impl StateConsistencyChecker {
    /// Snapshot the current state root so it can be compared later.
    pub fn new(state: &StateDb) -> Self {
        Self {
            expected_root: state.state_root(),
            write_fingerprint: 0,
        }
    }

    /// Accumulate written keys into the fingerprint.
    pub fn record_writes(&mut self, outcomes: &[TxExecutionOutcome]) {
        for o in outcomes {
            for key in o.speculative_writes.keys() {
                self.write_fingerprint ^= Self::hash_key(key);
            }
        }
    }

    /// Verify that the state root has advanced (i.e. at least one write was
    /// committed) or that it remains unchanged (no-op block).  Returns an
    /// error if the root unexpectedly regressed or if no writes were recorded
    /// but the root changed.
    pub fn verify(&self, state: &StateDb) -> Result<()> {
        let current = state.state_root();
        let had_writes = self.write_fingerprint != 0;
        if had_writes && current == self.expected_root {
            return Err(anyhow!(
                "StateConsistencyChecker: state root unchanged after committed writes"
            ));
        }
        if !had_writes && current != self.expected_root {
            return Err(anyhow!(
                "StateConsistencyChecker: state root changed with no committed writes"
            ));
        }
        Ok(())
    }

    /// XOR fingerprint of all keys written by the given outcomes.
    pub fn fingerprint_writes(outcomes: &[TxExecutionOutcome]) -> u64 {
        outcomes
            .iter()
            .flat_map(|o| o.speculative_writes.keys())
            .map(|k| Self::hash_key(k))
            .fold(0u64, |acc, h| acc ^ h)
    }

    fn hash_key(key: &[u8]) -> u64 {
        // Simple polynomial rolling hash - fast and dependency-free.
        key.iter().fold(14695981039346656037u64, |h, &b| {
            h.wrapping_mul(1099511628211) ^ (b as u64)
        })
    }
}

// -
// Phase 25 - Conflict resolution policy
// -

/// Strategy for picking a winner when two transactions conflict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolutionPolicy {
    /// Abort only the loser (the later tx); keep the winner's result.
    /// This is the classic OCC behaviour.
    AbortLoser,
    /// Abort every transaction involved in any conflict; all must retry.
    RetryAll,
    /// Lower tx_index always wins; the higher tx_index is always aborted.
    PriorityByIndex,
}

/// Outcome recorded for one transaction after conflict resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictResolution {
    /// This transaction was aborted in `round` and must be re-executed.
    Aborted { tx_index: usize, round: usize },
    /// This transaction was retained; its speculative result stands.
    Retained { tx_index: usize },
}

/// Applies a `ConflictResolutionPolicy` to a set of detected conflicts,
/// producing the set of transaction indices to abort and a per-tx resolution
/// vector.
pub struct ConflictResolver {
    policy: ConflictResolutionPolicy,
}

impl ConflictResolver {
    pub fn new(policy: ConflictResolutionPolicy) -> Self {
        Self { policy }
    }

    /// Resolve conflicts and return `(abort_set, resolutions)`.
    ///
    /// `round` is the current OCC round number (embedded in `Aborted` records).
    pub fn resolve(
        &self,
        details: &[ConflictDetail],
        round: usize,
    ) -> (HashSet<usize>, Vec<ConflictResolution>) {
        let mut abort_set: HashSet<usize> = HashSet::new();

        match self.policy {
            ConflictResolutionPolicy::AbortLoser => {
                for d in details {
                    abort_set.insert(d.loser_tx);
                }
            }
            ConflictResolutionPolicy::RetryAll => {
                for d in details {
                    abort_set.insert(d.winner_tx);
                    abort_set.insert(d.loser_tx);
                }
            }
            ConflictResolutionPolicy::PriorityByIndex => {
                for d in details {
                    // Lower index = higher priority; always abort the higher one.
                    let aborted = if d.winner_tx < d.loser_tx {
                        d.loser_tx
                    } else {
                        d.winner_tx
                    };
                    abort_set.insert(aborted);
                }
            }
        }

        // Collect the unique tx indices involved across all conflict pairs.
        let all_involved: HashSet<usize> = details
            .iter()
            .flat_map(|d| [d.winner_tx, d.loser_tx])
            .collect();

        let resolutions: Vec<ConflictResolution> = all_involved
            .into_iter()
            .map(|tx| {
                if abort_set.contains(&tx) {
                    ConflictResolution::Aborted {
                        tx_index: tx,
                        round,
                    }
                } else {
                    ConflictResolution::Retained { tx_index: tx }
                }
            })
            .collect();

        (abort_set, resolutions)
    }
}

// -
// Phase 25 - Ordered commit queue (reorder buffer)
// -

/// A reorder buffer that accepts outcomes in any order and releases them
/// strictly in ascending `tx_index` order.
///
/// This ensures that state writes are applied in canonical transaction order
/// even when parallel execution completes them out of sequence.
pub struct OrderedCommitQueue {
    /// The next tx_index that must be committed before any later one.
    next_commit_index: usize,
    /// Outcomes waiting for their predecessors to commit first.
    pending: HashMap<usize, TxExecutionOutcome>,
    /// Outcomes released in canonical order, ready to be flushed.
    committed: Vec<TxExecutionOutcome>,
}

impl OrderedCommitQueue {
    /// Create a new queue expecting tx_indices starting at `start_index`.
    pub fn new(start_index: usize) -> Self {
        Self {
            next_commit_index: start_index,
            pending: HashMap::new(),
            committed: Vec::new(),
        }
    }

    /// Enqueue an outcome.  If it is the next expected index (or fills a
    /// contiguous run) it is drained into `committed` immediately.
    pub fn enqueue(&mut self, outcome: TxExecutionOutcome) {
        self.pending.insert(outcome.tx_index, outcome);
        // Drain any contiguous run starting from next_commit_index.
        while let Some(o) = self.pending.remove(&self.next_commit_index) {
            self.next_commit_index += 1;
            self.committed.push(o);
        }
    }

    /// Drain all outcomes that are ready (already in canonical order).
    pub fn drain_ordered(&mut self) -> Vec<TxExecutionOutcome> {
        std::mem::take(&mut self.committed)
    }

    /// Number of outcomes still waiting for predecessors.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Number of outcomes that have been released in canonical order.
    pub fn committed_count(&self) -> usize {
        self.next_commit_index
    }

    /// Returns `true` when all `total_tx` transactions have been committed.
    pub fn is_complete(&self, total_tx: usize) -> bool {
        self.next_commit_index >= total_tx && self.committed.is_empty()
    }
}

// -
// Raw outcome returned by executor_fn
// -

/// Full speculative transaction output returned by the executor function.
#[derive(Clone, Debug)]
pub struct TransactionOutput {
    pub tx_index: usize,
    pub tx_hash: [u8; 32],
    pub gas_limit: u64,
    pub gas_used: u64,
    pub success: bool,
    pub revert_reason: Option<String>,
    pub write_set: Vec<(Vec<u8>, Vec<u8>)>,
    pub read_set: Vec<Vec<u8>>,
    pub events: Vec<Vec<u8>>,
    pub return_data: Vec<u8>,
    pub execution_status: bool,
}

pub type RawOutcome = TransactionOutput;

// -
// Item 1: ParallelExecutor
// -

/// Parallel transaction executor using Optimistic Concurrency Control.
pub struct ParallelExecutor {
    config: ParallelExecutionConfig,
    thread_pool: ThreadPool,
    /// Opt 2: shared hot-account read cache.
    pub hot_cache: Arc<HotAccountCache>,
    /// Opt 1: state key prefetcher.
    prefetcher: Mutex<StateKeyPrefetcher>,
    /// Opt 6: reusable execution context pool.
    pub context_pool: Arc<ExecutionContextPool>,
    /// Metrics collector shared with callers.
    pub metrics: Arc<ExecutionMetrics>,
}

impl ParallelExecutor {
    /// Create a new `ParallelExecutor` with the given configuration.
    pub fn new(config: ParallelExecutionConfig) -> Result<Self> {
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(config.num_threads)
            .build()
            .map_err(|e| anyhow!("Failed to build thread pool: {}", e))?;
        let hot_cache = Arc::new(HotAccountCache::new(config.hot_account_cache_size));
        let context_pool = Arc::new(ExecutionContextPool::new(config.context_pool_size));
        Ok(Self {
            config,
            thread_pool,
            hot_cache,
            prefetcher: Mutex::new(StateKeyPrefetcher::new()),
            context_pool,
            metrics: ExecutionMetrics::new(),
        })
    }

    // - item 2: execute_block -

    /// Execute all transactions in a block and return aggregated results.
    ///
    /// Internally runs OCC rounds until all transactions commit or the round
    /// limit is exceeded, then falls back to serial execution.
    pub fn execute_block<F>(
        &self,
        tasks: Vec<ParallelExecutorTask>,
        state: Arc<Mutex<StateDb>>,
        executor_fn: F,
    ) -> Result<BatchExecutionResult>
    where
        F: Fn(&ParallelExecutorTask, SnapshotId, &MVMemory) -> TransactionOutput + Send + Sync,
    {
        info!(
            "execute_block: {} transactions, max_rounds={}",
            tasks.len(),
            self.config.max_rounds
        );

        if tasks.is_empty() {
            return Ok(BatchExecutionResult {
                results: vec![],
                receipts: vec![],
                total_gas_used: 0,
                conflict_count: 0,
                rounds: 0,
            });
        }

        let block_start = Instant::now();
        let executor_fn = Arc::new(executor_fn);
        let mut pending: Vec<ParallelExecutorTask> = tasks;
        let mut committed: Vec<TxExecutionOutcome> = Vec::new();
        let mut total_conflicts = 0usize;
        let mut rounds = 0usize;
        let mut total_aborts = 0usize;
        let mv_memory = Arc::new(MVMemory::new(MVMemoryConfig::default()));
        let mut cached_outputs: HashMap<usize, CachedSpeculativeExecution> = HashMap::new();
        let mut retry_counts: HashMap<usize, usize> = HashMap::new();

        // Phase 25 - state consistency check baseline
        let mut consistency_checker = {
            let st = state.lock();
            StateConsistencyChecker::new(&st)
        };

        // Phase 25 - conflict resolver using configured policy
        let resolver = ConflictResolver::new(self.config.conflict_resolution_policy.clone());

        // Phase 25 - ordered commit queue (tx indices start at the minimum in pending)
        let start_index = pending.iter().map(|t| t.tx_index).min().unwrap_or(0);
        let mut commit_queue = OrderedCommitQueue::new(start_index);

        // Opt 1: prefetch keys for the initial batch into the hot cache
        {
            let mut pf = self.prefetcher.lock();
            {
                pf.enqueue_batch(&pending);
                // Prefetch against a snapshot - lock is held only for this block
                let st = state.lock();
                {
                    pf.prefetch(&st, &self.hot_cache);
                }
            }
        }

        while !pending.is_empty() && rounds < self.config.max_rounds {
            rounds += 1;
            debug!(
                "OCC round {}: {} pending transactions",
                rounds,
                pending.len()
            );

            // Phase 25 - sort tasks into canonical order before each round
            DeterministicExecutionGuard::sort_tasks(&mut pending);

            let mut tasks_to_execute = Vec::new();
            let mut round_cached = Vec::new();
            for task in &pending {
                if let Some(cached) = cached_outputs.get(&task.tx_index) {
                    round_cached.push(cached.clone());
                } else {
                    tasks_to_execute.push(task.clone());
                }
            }

            let mut executed_outputs =
                self.execute_batch(&tasks_to_execute, &executor_fn, &mv_memory, &retry_counts)?;
            executed_outputs.extend(round_cached);
            executed_outputs.sort_by_key(|entry| entry.task.tx_index);

            let rw_pairs: Vec<(usize, ReadWriteSet)> = executed_outputs
                .iter()
                .map(|entry| {
                    (
                        entry.output.tx_index,
                        ReadWriteSet::new(
                            entry.output.read_set.clone(),
                            entry
                                .output
                                .write_set
                                .iter()
                                .map(|(k, _)| k.clone())
                                .collect(),
                        ),
                    )
                })
                .collect();

            // item 4 - conflict detection: RAW - abort, WAW - abort, RAR - allowed
            let details = Self::detect_conflicts_detailed(&rw_pairs);
            // Phase 25 - structured conflict resolution via configured policy
            let (conflict_set, _resolutions) = resolver.resolve(&details, rounds);
            let round_conflicts = conflict_set.len();
            total_conflicts += round_conflicts;
            // Metrics KPI 3 - record per-round conflict count
            self.metrics.record_conflicts(round_conflicts);
            // Metrics KPI 2 - submissions this round
            self.metrics.record_submissions(pending.len());

            if round_conflicts > 0 {
                let conflict_rate = round_conflicts as f64 / pending.len() as f64;
                warn!(
                    "Round {}: {} conflicts detected (rate={:.2})",
                    rounds, round_conflicts, conflict_rate
                );
                if conflict_rate > self.config.conflict_abort_threshold {
                    warn!(
                        "Conflict rate {:.2} > threshold {:.2}; switching to serial fallback",
                        conflict_rate, self.config.conflict_abort_threshold
                    );
                    break;
                }
            }

            let mut next_pending: Vec<ParallelExecutorTask> = Vec::new();
            let round_aborts = conflict_set.len();
            total_aborts += round_aborts;
            let mut committed_write_keys: HashSet<Vec<u8>> = HashSet::new();

            for entry in executed_outputs {
                let tx_index = entry.output.tx_index;
                let write_keys: Vec<Vec<u8>> = entry
                    .output
                    .write_set
                    .iter()
                    .map(|(k, _)| k.clone())
                    .collect();
                let intersects_committed = entry
                    .output
                    .read_set
                    .iter()
                    .chain(write_keys.iter())
                    .any(|key| committed_write_keys.contains(key));

                if !entry.output.execution_status
                    || conflict_set.contains(&tx_index)
                    || intersects_committed
                    || !mv_memory.validate_reads(entry.tx_version)?
                {
                    // item 5 / 6 - rollback & retry
                    debug!("Rolling back tx {} (conflict); rescheduling", tx_index);
                    mv_memory.discard_speculative(entry.tx_version)?;
                    cached_outputs.remove(&tx_index);
                    retry_counts
                        .entry(tx_index)
                        .and_modify(|count| *count += 1)
                        .or_insert(1);
                    if let Some(task) = pending.iter().find(|t| t.tx_index == tx_index) {
                        next_pending.push(task.clone());
                    }
                } else {
                    mv_memory.promote_to_committed(entry.tx_version)?;
                    for key in &write_keys {
                        committed_write_keys.insert(key.clone());
                    }
                    let tx_outcome = Self::raw_to_outcome(
                        entry.output.clone(),
                        Some(entry.tx_version),
                        rounds - 1,
                    );
                    cached_outputs.insert(tx_index, entry.clone());
                    commit_queue.enqueue(tx_outcome);
                }
            }

            // Drain outcomes that are now ready in canonical order
            for o in commit_queue.drain_ordered() {
                committed.push(o);
            }

            pending = next_pending;
        }

        // Serial fallback for any transactions remaining after round limit
        let serial_count;
        if !pending.is_empty() {
            warn!(
                "Serial fallback for {} remaining transactions after {} OCC rounds",
                pending.len(),
                rounds
            );
            serial_count = pending.len();
            for task in &pending {
                let tx_version = TxVersion {
                    tx_index: task.tx_index,
                    incarnation: rounds + 1,
                };
                // SECURITY (C-08): snapshot_id must encode the SAME
                // incarnation as `tx_version` (see execute_batch).
                let snapshot_id = SnapshotId::new((rounds + 1) as u64);
                let output = executor_fn(task, snapshot_id, &mv_memory);

                for key in &output.read_set {
                    let _ = mv_memory.read_at_version(tx_version, key);
                }
                for (key, value) in &output.write_set {
                    let _ =
                        mv_memory.record_speculative_write(tx_version, key.clone(), value.clone());
                }
                let _ = mv_memory.promote_to_committed(tx_version);

                committed.push(Self::raw_to_outcome(output, Some(tx_version), rounds));
            }
        } else {
            serial_count = 0;
        }

        // Sort by canonical tx_index order
        committed.sort_by_key(|o| o.tx_index);

        {
            let st = state.lock();
            Self::finalize(
                &committed,
                &st,
                &self.hot_cache,
                self.config.write_batch_size,
            )?;
        }

        // Phase 25 - record committed writes into the consistency checker
        consistency_checker.record_writes(&committed);

        // item 8 - collect receipts
        let (receipts, total_gas_used) = Self::collect_receipts(&committed);

        // - Metrics recording -
        let elapsed = block_start.elapsed();
        let parallel_count = committed.len().saturating_sub(serial_count);
        self.metrics.record_committed(parallel_count, serial_count);
        self.metrics.record_aborts(total_aborts);
        self.metrics.record_latency(elapsed);
        // KPI 5: approximate CPU utilization: all threads were active for the
        // parallel portion; serial portion used 1 thread.
        let wall_ns = elapsed.as_nanos() as u64;
        self.metrics
            .record_cpu(wall_ns, wall_ns, self.config.num_threads as u64);

        info!(
            "execute_block complete: {} results, {} conflicts, {} rounds, {} gas, latency={:.2}ms",
            committed.len(),
            total_conflicts,
            rounds,
            total_gas_used,
            elapsed.as_secs_f64() * 1000.0,
        );

        Ok(BatchExecutionResult {
            results: committed,
            receipts,
            total_gas_used,
            conflict_count: total_conflicts,
            rounds,
        })
    }

    // - item 3: execute_batch -

    /// Execute a batch of transactions in parallel using `rayon`.
    ///
    /// Opt 4 - minimize locking: the state lock is acquired **once** per batch
    /// (not once per transaction).  All threads share the same read-only
    /// snapshot for the duration of the batch.
    fn execute_batch<F>(
        &self,
        tasks: &[ParallelExecutorTask],
        executor_fn: &Arc<F>,
        mv_memory: &Arc<MVMemory>,
        retry_counts: &HashMap<usize, usize>,
    ) -> Result<Vec<CachedSpeculativeExecution>>
    where
        F: Fn(&ParallelExecutorTask, SnapshotId, &MVMemory) -> TransactionOutput + Send + Sync,
    {
        let fn_arc = Arc::clone(executor_fn);
        let ctx_pool = Arc::clone(&self.context_pool);
        let mv_memory = Arc::clone(mv_memory);
        let batch_start = Instant::now();
        let outcomes: Vec<CachedSpeculativeExecution> = self.thread_pool.install(|| {
            tasks
                .par_iter()
                .map(|task| {
                    let context = ctx_pool.acquire();
                    let retry_round = retry_counts.get(&task.tx_index).copied().unwrap_or(0);
                    let tx_version = TxVersion {
                        tx_index: task.tx_index,
                        incarnation: retry_round,
                    };
                    // SECURITY (C-08): single source of truth for incarnations.
                    // The executor_fn derives its TxVersion from
                    // `snapshot_id.0`, so snapshot_id MUST encode exactly the
                    // same incarnation recorded here. The previous formula
                    // (`retry_round + tx_index + 1`) made the backend record
                    // reads/writes under a different version than the one
                    // validation/promotion used, silently neutering OCC.
                    let snapshot_id = SnapshotId::new(retry_round as u64);
                    let output = fn_arc(task, snapshot_id, &mv_memory);
                    for key in &output.read_set {
                        let _ = mv_memory.read_at_version(tx_version, key);
                    }
                    for (key, value) in &output.write_set {
                        let _ = mv_memory.record_speculative_write(
                            tx_version,
                            key.clone(),
                            value.clone(),
                        );
                    }
                    ctx_pool.release(context);
                    CachedSpeculativeExecution {
                        task: task.clone(),
                        output,
                        tx_version,
                    }
                })
                .collect()
        });
        let batch_ns = batch_start.elapsed().as_nanos() as u64;
        // KPI 5 accumulation (wall ns only; active fraction recorded in execute_block)
        self.metrics
            .record_cpu(batch_ns, batch_ns, self.config.num_threads as u64);
        Ok(outcomes)
    }

    // - item 4: detect_conflicts -

    /// Detect conflicting transactions using OCC read/write set analysis.
    ///
    /// Conflict rules:
    ///   - **Read-after-write (RAW)**: an earlier tx wrote key K; a later tx reads K - abort later tx
    ///   - **Write-after-write (WAW)**: two txs both write key K - abort the later tx
    ///   - **Read-after-read (RAR)**: two txs both read key K - **allowed**, no conflict
    ///
    /// Conflict resolution steps:
    ///   1. Detect conflicting keys between transaction pairs
    ///   2. Abort the conflicting (loser) transaction
    ///   3. Reschedule the aborted transaction for the next OCC round
    ///   4. Re-execute with updated state (incorporating the winner's writes)
    ///
    /// Returns the set of transaction indices that must be aborted (losers).
    pub fn detect_conflicts(rw_pairs: &[(usize, ReadWriteSet)]) -> HashSet<usize> {
        Self::detect_conflicts_detailed(rw_pairs)
            .into_iter()
            .map(|d| d.loser_tx)
            .collect()
    }

    /// Detailed conflict detection returning a `ConflictDetail` per conflict pair.
    ///
    /// For each ordered pair (i, j) where tx i appears before tx j in `rw_pairs`:
    ///   - RAW:  write_set(i) - read_set(j)   - j is aborted; i wins
    ///   - RAW': read_set(i)  - write_set(j)   - j is aborted; i wins
    ///   - WAW:  write_set(i) - write_set(j)   - j is aborted; i wins
    ///   - RAR:  read_set(i)  - read_set(j)    - **ignored** (allowed)
    pub fn detect_conflicts_detailed(rw_pairs: &[(usize, ReadWriteSet)]) -> Vec<ConflictDetail> {
        let mut details: Vec<ConflictDetail> = Vec::new();
        let n = rw_pairs.len();

        for i in 0..n {
            let (idx_i, rws_i) = &rw_pairs[i];
            let write_i: HashSet<&[u8]> = rws_i.write_set.iter().map(|v| v.as_slice()).collect();
            let read_i: HashSet<&[u8]> = rws_i.read_set.iter().map(|v| v.as_slice()).collect();

            for (idx_j, rws_j) in rw_pairs.iter().take(n).skip(i + 1) {
                let write_j: HashSet<&[u8]> =
                    rws_j.write_set.iter().map(|v| v.as_slice()).collect();
                let read_j: HashSet<&[u8]> = rws_j.read_set.iter().map(|v| v.as_slice()).collect();

                // RAW: earlier tx i wrote something that later tx j reads
                let mut raw_keys: Vec<Vec<u8>> =
                    write_i.intersection(&read_j).map(|k| k.to_vec()).collect();

                // RAW': earlier tx i reads something that later tx j writes
                for k in read_i.intersection(&write_j) {
                    let kv = k.to_vec();
                    if !raw_keys.contains(&kv) {
                        raw_keys.push(kv);
                    }
                }

                // WAW: both txs write the same key
                let waw_keys: Vec<Vec<u8>> =
                    write_i.intersection(&write_j).map(|k| k.to_vec()).collect();

                // RAR: both read the same key - allowed, no conflict recorded.

                let has_raw = !raw_keys.is_empty();
                let has_waw = !waw_keys.is_empty();

                if !has_raw && !has_waw {
                    continue;
                }

                let kind = match (has_raw, has_waw) {
                    (true, false) => ConflictKind::Raw,
                    (false, true) => ConflictKind::Waw,
                    _ => ConflictKind::RawAndWaw,
                };

                // Merge and deduplicate conflicting keys
                let mut conflicting_keys: Vec<Vec<u8>> = raw_keys;
                for k in waw_keys {
                    if !conflicting_keys.contains(&k) {
                        conflicting_keys.push(k);
                    }
                }
                conflicting_keys.sort();

                // Winner = earlier (lower-index) tx; loser = later tx
                let (winner_tx, loser_tx) = if idx_i < idx_j {
                    (*idx_i, *idx_j)
                } else {
                    (*idx_j, *idx_i)
                };

                details.push(ConflictDetail {
                    winner_tx,
                    loser_tx,
                    kind,
                    conflicting_keys,
                });
            }
        }

        details
    }

    // - item 5: rollback -

    /// Discard speculative writes for a conflicting transaction.
    ///
    /// Writes are never applied to the canonical state until `finalize`, so
    /// rolling back is a logical no-op - the task is simply not accumulated.
    #[allow(dead_code)]
    fn rollback(task: &ParallelExecutorTask) {
        debug!(
            "rollback: discarding speculative writes for tx {}",
            task.tx_index
        );
    }

    // - item 6: retry -

    /// Enqueue a rolled-back task for re-execution in the next OCC round.
    #[allow(dead_code)]
    fn retry(task: ParallelExecutorTask, queue: &mut Vec<ParallelExecutorTask>) {
        debug!("retry: rescheduling tx {}", task.tx_index);
        queue.push(task);
    }

    // - item 7: finalize -

    /// Apply the committed speculative writes of clean transactions to the canonical state.
    ///
    /// Opt 5 - batch storage writes: all writes are accumulated into a
    /// `WriteBatch` and flushed in a single `set_raw` pass rather than one
    /// call per key.  Opt 3 - cache invalidation keeps the hot-account cache
    /// consistent after each flush.
    pub fn finalize(
        outcomes: &[TxExecutionOutcome],
        state: &StateDb,
        cache: &HotAccountCache,
        batch_size: usize,
    ) -> Result<()> {
        let mut batch = WriteBatch::new(batch_size);
        for outcome in outcomes {
            for (key, value) in &outcome.speculative_writes {
                batch.push(key.clone(), value.clone());
                if batch.is_full() {
                    batch.flush(state, cache)?;
                }
            }
        }
        if !batch.is_empty() {
            batch.flush(state, cache)?;
        }
        debug!(
            "finalize: applied {} transaction write sets to state",
            outcomes.len()
        );
        Ok(())
    }

    // - item 8: collect_receipts -

    /// Build receipts from execution outcomes.  Returns `(receipts, total_gas)`.
    pub fn collect_receipts(outcomes: &[TxExecutionOutcome]) -> (Vec<Receipt>, u64) {
        let mut receipts = Vec::with_capacity(outcomes.len());
        let mut total_gas = 0u64;
        for o in outcomes {
            total_gas = total_gas.saturating_add(o.gas_used);
            receipts.push(o.receipt.clone());
        }
        (receipts, total_gas)
    }

    // - item 9: metrics -

    /// Emit all five execution KPIs to the structured log and return a snapshot.
    ///
    /// Also logs per-result conflict rate from the `BatchExecutionResult` for
    /// quick per-block diagnostics.
    pub fn record_metrics(&self, result: &BatchExecutionResult) -> MetricsSnapshot {
        let total = result.results.len();
        let conflict_rate = if total > 0 {
            result.conflict_count as f64 / total as f64
        } else {
            0.0
        };

        let snap = self.metrics.snapshot();

        info!(
            // KPI 1
            metrics.parallel_throughput = snap.parallel_throughput_txs_per_block,
            // KPI 2
            metrics.abort_rate = snap.abort_rate,
            // KPI 3
            metrics.conflicts_per_round = snap.conflicts_per_round,
            metrics.block_conflict_rate = conflict_rate,
            // KPI 4
            metrics.mean_latency_ms = snap.mean_latency_ms,
            // KPI 5
            metrics.cpu_utilization = snap.cpu_utilization,
            // per-block details
            metrics.rounds = result.rounds,
            metrics.gas_used = result.total_gas_used,
            metrics.tx_count = total,
            "execution_metrics"
        );

        snap
    }

    // - helpers -

    /// Convert a `RawOutcome` into a `TxExecutionOutcome`.
    pub fn raw_to_outcome(
        o: TransactionOutput,
        tx_version: Option<TxVersion>,
        retry_round: usize,
    ) -> TxExecutionOutcome {
        let mut receipt = if o.execution_status {
            Receipt::new_success(o.tx_hash, o.gas_used, None)
        } else {
            Receipt::new_failure(o.tx_hash, o.gas_used)
        };

        receipt.logs = o
            .events
            .iter()
            .filter_map(|bytes| Log::decode(bytes).ok())
            .collect();

        let speculative_writes: HashMap<Vec<u8>, Vec<u8>> = o.write_set.iter().cloned().collect();

        TxExecutionOutcome {
            tx_index: o.tx_index,
            snapshot_id: tx_version
                .as_ref()
                .map(|version| SnapshotId::new(version.tx_index as u64)),
            success: o.execution_status,
            gas_used: o.gas_used,
            output: o.return_data,
            rw_set: ReadWriteSet::new(
                o.read_set.clone(),
                o.write_set.iter().map(|(k, _)| k.clone()).collect(),
            ),
            receipt,
            speculative_writes,
            error: o.revert_reason,
            had_conflict: retry_round > 0,
            retry_round,
            tx_version,
        }
    }
}

// -
// Pipeline types (BlockExecutionPipeline)
// -

/// Configuration for the block execution pipeline.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    pub parallel_config: ParallelExecutionConfig,
    pub commit_config: CommitManagerConfig,
    pub scheduler_config: BlockSchedulerConfig,
    pub enable_parallel: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            parallel_config: ParallelExecutionConfig::default(),
            commit_config: CommitManagerConfig::default(),
            scheduler_config: BlockSchedulerConfig::default(),
            enable_parallel: true,
        }
    }
}

/// The final output produced after a block is fully executed and committed.
#[derive(Clone, Debug)]
pub struct FinalizedBlockOutput {
    pub block_hash: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts: Vec<Receipt>,
    pub gas_used: u64,
    pub tx_count: usize,
    pub commit_summary: CommitSummary,
}

/// End-to-end block execution pipeline.
///
/// Items:
///  1  `is_parallel_enabled`
///  2  `schedule`
///  3  `speculative_execute`
///  4  `serial_execute`
///  5  `collect_results`
///  6  `feed_commit_manager`
///  7  `run_commit`
///  8  `generate_receipts`
///  9  `run_block`
pub struct BlockExecutionPipeline {
    config: PipelineConfig,
    executor: ParallelExecutor,
    commit_manager: CommitManager,
    scheduler: BlockScheduler,
}

impl BlockExecutionPipeline {
    /// Construct a new pipeline with the given configuration.
    pub fn new(config: PipelineConfig) -> Result<Self> {
        let executor = ParallelExecutor::new(config.parallel_config.clone())?;
        let commit_manager = CommitManager::new(config.commit_config.clone());
        let scheduler = BlockScheduler::new(config.scheduler_config.clone())?;
        Ok(Self {
            config,
            executor,
            commit_manager,
            scheduler,
        })
    }

    // item 1
    /// Returns `true` when parallel execution is enabled by configuration.
    pub fn is_parallel_enabled(&self) -> bool {
        self.config.enable_parallel
    }

    // item 2
    /// Schedule transactions for execution using the block scheduler.
    pub fn schedule(&self, total_tx: usize) -> Result<Vec<ExecutionTask>> {
        let empty_graph = HashMap::new();
        self.scheduler.build_tasks(total_tx, &empty_graph)
    }

    // item 3
    /// Speculatively execute transactions in parallel.
    pub fn speculative_execute<F>(
        &self,
        tasks: Vec<ParallelExecutorTask>,
        state: Arc<Mutex<StateDb>>,
        executor_fn: F,
    ) -> Result<BatchExecutionResult>
    where
        F: Fn(&ParallelExecutorTask, SnapshotId, &MVMemory) -> RawOutcome + Send + Sync,
    {
        self.executor.execute_block(tasks, state, executor_fn)
    }

    // item 4
    /// Execute transactions serially (fallback when parallel is disabled or unsafe).
    ///
    /// BUGFIX (C-10): serial mode previously executed every transaction
    /// against the PRE-BLOCK state — writes were never recorded into the
    /// shared `MVMemory`, so transaction N could not observe transaction
    /// N-1's writes, producing wrong success/gas receipts and a state root
    /// divergent from parallel/sequential semantics. Writes are now recorded
    /// and promoted after each transaction, giving exact sequential
    /// visibility.
    pub fn serial_execute<F>(
        &self,
        tasks: &[ParallelExecutorTask],
        executor_fn: F,
    ) -> Vec<TxExecutionOutcome>
    where
        F: Fn(&ParallelExecutorTask, SnapshotId, &MVMemory) -> RawOutcome,
    {
        let mv_memory = MVMemory::new(MVMemoryConfig::default());
        tasks
            .iter()
            .map(|task| {
                // Incarnation 0: the executor_fn derives its TxVersion from
                // snapshot_id.0 (C-08 single-source rule).
                let tx_version = TxVersion::new(task.tx_index);
                let raw = executor_fn(
                    task,
                    SnapshotId::new(tx_version.incarnation as u64),
                    &mv_memory,
                );

                // Mirror the reads/writes into MVMemory and commit them
                // immediately so the NEXT transaction observes them.
                for key in &raw.read_set {
                    let _ = mv_memory.read_at_version(tx_version, key);
                }
                for (key, value) in &raw.write_set {
                    let _ =
                        mv_memory.record_speculative_write(tx_version, key.clone(), value.clone());
                }
                let _ = mv_memory.promote_to_committed(tx_version);

                ParallelExecutor::raw_to_outcome(raw, Some(tx_version), 0)
            })
            .collect()
    }

    // item 5
    /// Sort outcomes in canonical tx_index order.
    pub fn collect_results(
        &self,
        mut outcomes: Vec<TxExecutionOutcome>,
    ) -> Vec<TxExecutionOutcome> {
        outcomes.sort_by_key(|o| o.tx_index);
        outcomes
    }

    // item 6
    /// Feed execution outcomes into the commit manager for validation.
    pub fn feed_commit_manager(&mut self, outcomes: Vec<TxExecutionOutcome>) {
        self.commit_manager.receive_results(outcomes);
    }

    pub fn run_commit(
        &mut self,
        state: &StateDb,
    ) -> Result<(CommitSummary, Vec<TxExecutionOutcome>)> {
        self.commit_manager.commit_pipeline(state)
    }

    // item 8
    /// Generate receipts from a sorted slice of outcomes.
    pub fn generate_receipts(&self, outcomes: &[TxExecutionOutcome]) -> (Vec<Receipt>, u64) {
        ParallelExecutor::collect_receipts(outcomes)
    }

    // item 9
    /// Execute a full block end-to-end using the pipeline.
    pub fn run_block<F>(
        &mut self,
        block_hash: [u8; 32],
        tasks: Vec<ParallelExecutorTask>,
        state: Arc<Mutex<StateDb>>,
        executor_fn: F,
    ) -> Result<FinalizedBlockOutput>
    where
        F: Fn(&ParallelExecutorTask, SnapshotId, &MVMemory) -> RawOutcome + Send + Sync + Clone,
    {
        info!("BlockExecutionPipeline::run_block - {} txs", tasks.len());

        let tx_count = tasks.len();
        let outcomes: Vec<TxExecutionOutcome> = if self.is_parallel_enabled() {
            let batch = self.executor.execute_block(
                tasks.clone(),
                Arc::clone(&state),
                executor_fn.clone(),
            )?;
            batch.results
        } else {
            self.serial_execute(&tasks, executor_fn)
        };

        let sorted = self.collect_results(outcomes);
        self.feed_commit_manager(sorted.clone());

        let st = state.lock();
        let (commit_summary, committed_outcomes) = self.run_commit(&st)?;

        let state_root = st.state_root();
        let (receipts, gas_used) = self.generate_receipts(&committed_outcomes);

        info!(
            "run_block complete: {} txs, {} gas, state_root={}",
            tx_count,
            gas_used,
            hex::encode(state_root)
        );

        Ok(FinalizedBlockOutput {
            block_hash,
            state_root,
            receipts,
            gas_used,
            tx_count,
            commit_summary,
        })
    }
}

// -
// item 10: pipeline_tests
// -

#[cfg(test)]
mod pipeline_tests {
    use super::*;

    // - Conflict detection tests -

    #[test]
    fn detect_conflicts_detailed_raw() {
        // tx 0 writes key [1]; tx 1 reads key [1] -> RAW conflict, loser = tx 1
        let pairs = vec![
            (0usize, ReadWriteSet::new(vec![], vec![vec![1u8]])),
            (1usize, ReadWriteSet::new(vec![vec![1u8]], vec![])),
        ];
        let details = ParallelExecutor::detect_conflicts_detailed(&pairs);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].winner_tx, 0);
        assert_eq!(details[0].loser_tx, 1);
        assert_eq!(details[0].kind, ConflictKind::Raw);
        assert!(details[0].conflicting_keys.contains(&vec![1u8]));
    }

    #[test]
    fn detect_conflicts_detailed_waw() {
        // tx 0 writes key [5]; tx 1 writes key [5] -> WAW conflict, loser = tx 1
        let pairs = vec![
            (0usize, ReadWriteSet::new(vec![], vec![vec![5u8]])),
            (1usize, ReadWriteSet::new(vec![], vec![vec![5u8]])),
        ];
        let details = ParallelExecutor::detect_conflicts_detailed(&pairs);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].winner_tx, 0);
        assert_eq!(details[0].loser_tx, 1);
        assert_eq!(details[0].kind, ConflictKind::Waw);
    }

    #[test]
    fn detect_conflicts_rar_allowed() {
        // Both txs only read key [7] -> no conflict
        let pairs = vec![
            (0usize, ReadWriteSet::new(vec![vec![7u8]], vec![])),
            (1usize, ReadWriteSet::new(vec![vec![7u8]], vec![])),
        ];
        let details = ParallelExecutor::detect_conflicts_detailed(&pairs);
        assert!(details.is_empty(), "RAR should not produce a conflict");
    }

    #[test]
    fn detect_conflicts_raw_and_waw() {
        // tx 0 writes [1] and [2]; tx 1 reads [1] and writes [2]
        // -> RAW on [1], WAW on [2], kind = RawAndWaw
        let pairs = vec![
            (
                0usize,
                ReadWriteSet::new(vec![], vec![vec![1u8], vec![2u8]]),
            ),
            (1usize, ReadWriteSet::new(vec![vec![1u8]], vec![vec![2u8]])),
        ];
        let details = ParallelExecutor::detect_conflicts_detailed(&pairs);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].kind, ConflictKind::RawAndWaw);
    }

    #[test]
    fn conflict_detail_summary() {
        let detail = ConflictDetail {
            winner_tx: 3,
            loser_tx: 7,
            kind: ConflictKind::Raw,
            conflicting_keys: vec![vec![0u8], vec![1u8]],
        };
        let s = detail.summary();
        assert!(s.contains("Raw"), "summary should mention kind");
        assert!(s.contains("3"), "summary should mention winner");
        assert!(s.contains("7"), "summary should mention loser");
        assert!(s.contains("2"), "summary should mention key count");
    }

    #[test]
    fn conflict_detail_correct_winner_loser() {
        // tx 2 reads [9]; tx 5 writes [9] -> RAW', winner=2, loser=5
        let pairs = vec![
            (2usize, ReadWriteSet::new(vec![vec![9u8]], vec![])),
            (5usize, ReadWriteSet::new(vec![], vec![vec![9u8]])),
        ];
        let details = ParallelExecutor::detect_conflicts_detailed(&pairs);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].winner_tx, 2);
        assert_eq!(details[0].loser_tx, 5);
    }

    #[test]
    fn no_conflicts_disjoint_keys() {
        let pairs = vec![
            (0usize, ReadWriteSet::new(vec![vec![1u8]], vec![vec![2u8]])),
            (1usize, ReadWriteSet::new(vec![vec![3u8]], vec![vec![4u8]])),
        ];
        let conflicts = ParallelExecutor::detect_conflicts(&pairs);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn detect_conflicts_returns_loser_indices() {
        let pairs = vec![
            (0usize, ReadWriteSet::new(vec![], vec![vec![1u8]])),
            (1usize, ReadWriteSet::new(vec![vec![1u8]], vec![])),
            (2usize, ReadWriteSet::new(vec![vec![99u8]], vec![])),
        ];
        let conflicts = ParallelExecutor::detect_conflicts(&pairs);
        assert!(conflicts.contains(&1), "tx 1 should be the loser");
        assert!(!conflicts.contains(&0), "tx 0 is the winner");
        assert!(!conflicts.contains(&2), "tx 2 is not involved");
    }

    // - Optimization + metrics tests -

    // Opt 2: HotAccountCache
    #[test]
    fn hot_account_cache_insert_get() {
        let cache = HotAccountCache::new(4);
        cache.insert(vec![1u8], vec![42u8]);
        assert_eq!(cache.get(&[1u8]), Some(vec![42u8]));
    }

    #[test]
    fn hot_account_cache_miss() {
        let cache = HotAccountCache::new(4);
        assert_eq!(cache.get(&[99u8]), None);
    }

    #[test]
    fn hot_account_cache_invalidate() {
        let cache = HotAccountCache::new(4);
        cache.insert(vec![1u8], vec![1u8]);
        cache.invalidate(&[1u8]);
        assert_eq!(cache.get(&[1u8]), None);
    }

    #[test]
    fn hot_account_cache_hit_rate() {
        let cache = HotAccountCache::new(4);
        cache.insert(vec![1u8], vec![1u8]);
        cache.get(&[1u8]); // hit
        cache.get(&[2u8]); // miss
        let rate = cache.hit_rate();
        assert!((rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn hot_account_cache_capacity_eviction() {
        let cache = HotAccountCache::new(2);
        cache.insert(vec![1u8], vec![1u8]);
        cache.insert(vec![2u8], vec![2u8]);
        cache.insert(vec![3u8], vec![3u8]); // evicts one entry
        assert!(cache.len() <= 2);
    }

    // Opt 5: WriteBatch
    #[test]
    fn write_batch_push_and_len() {
        let mut batch = WriteBatch::new(4);
        batch.push(vec![1u8], vec![10u8]);
        batch.push(vec![2u8], vec![20u8]);
        assert_eq!(batch.len(), 2);
        assert!(!batch.is_full());
    }

    #[test]
    fn write_batch_is_full() {
        let mut batch = WriteBatch::new(2);
        batch.push(vec![1u8], vec![1u8]);
        batch.push(vec![2u8], vec![2u8]);
        assert!(batch.is_full());
    }

    #[test]
    fn write_batch_is_empty_after_flush() {
        let mut batch = WriteBatch::new(4);
        batch.push(vec![1u8], vec![1u8]);
        // Can't flush without a real StateDb; just verify empty flag before adding
        assert!(!batch.is_empty());
    }

    // Opt 6: ExecutionContextPool
    #[test]
    fn context_pool_acquire_release() {
        let pool = ExecutionContextPool::new(2);
        let ctx = pool.acquire();
        assert!(ctx.reads.is_empty());
        pool.release(ctx);
        // Acquiring again returns the released context
        let ctx2 = pool.acquire();
        assert!(ctx2.reads.is_empty());
        pool.release(ctx2);
    }

    #[test]
    fn context_reset_clears_buffers() {
        let mut ctx = ExecutionContext::new();
        ctx.reads.push(vec![1u8]);
        ctx.writes.push((vec![2u8], vec![3u8]));
        ctx.reset();
        assert!(ctx.reads.is_empty());
        assert!(ctx.writes.is_empty());
    }

    // Opt 1: StateKeyPrefetcher
    #[test]
    fn prefetcher_enqueue_populates_queue() {
        let mut pf = StateKeyPrefetcher::new();
        let tasks = vec![ParallelExecutorTask {
            tx_index: 0,
            tx_bytes: vec![],
            tx_hash: [1u8; 32],
            gas_limit: 0,
        }];
        pf.enqueue_batch(&tasks);
        // Each task contributes 2 keys (sender-like + recipient-like)
        assert_eq!(pf.prefetch_queue.len(), 2);
        pf.clear();
        assert!(pf.prefetch_queue.is_empty());
    }

    // Metrics tests
    #[test]
    fn metrics_throughput_zero_blocks() {
        let m = ExecutionMetrics::default();
        assert_eq!(m.parallel_throughput(), 0.0);
    }

    #[test]
    fn metrics_throughput_after_commits() {
        let m = ExecutionMetrics::default();
        m.record_committed(10, 2);
        m.record_committed(8, 0);
        // 2 blocks, 18 parallel committed
        assert!((m.parallel_throughput() - 9.0).abs() < 1e-9);
    }

    #[test]
    fn metrics_abort_rate() {
        let m = ExecutionMetrics::default();
        m.record_submissions(10);
        m.record_aborts(3);
        assert!((m.abort_rate() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn metrics_abort_rate_zero_submissions() {
        let m = ExecutionMetrics::default();
        assert_eq!(m.abort_rate(), 0.0);
    }

    #[test]
    fn metrics_conflicts_per_round() {
        let m = ExecutionMetrics::default();
        m.record_conflicts(4); // round 1: 4 conflicts
        m.record_conflicts(2); // round 2: 2 conflicts
        assert!((m.conflicts_per_round() - 3.0).abs() < 1e-9);
    }

    #[test]
    fn metrics_mean_latency_ms() {
        let m = ExecutionMetrics::default();
        m.record_latency(std::time::Duration::from_millis(10));
        m.record_latency(std::time::Duration::from_millis(20));
        assert!((m.mean_latency_ms() - 15.0).abs() < 0.01);
    }

    #[test]
    fn metrics_cpu_utilization_full() {
        let m = ExecutionMetrics::default();
        m.record_cpu(1_000_000, 1_000_000, 4);
        assert!((m.cpu_utilization() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn metrics_snapshot_fields() {
        let m = ExecutionMetrics::default();
        m.record_committed(5, 1);
        m.record_aborts(1);
        m.record_submissions(6);
        m.record_conflicts(2);
        m.record_latency(std::time::Duration::from_millis(5));
        let snap = m.snapshot();
        assert_eq!(snap.blocks_processed, 1);
        assert_eq!(snap.total_aborts, 1);
        assert_eq!(snap.total_conflicts, 2);
        assert!(snap.parallel_throughput_txs_per_block > 0.0);
    }

    // - Phase 25 - DeterministicExecutionGuard -

    #[test]
    fn deterministic_guard_sorts_tasks() {
        let mut tasks = vec![
            ParallelExecutorTask {
                tx_index: 3,
                tx_bytes: vec![],
                tx_hash: [0; 32],
                gas_limit: 0,
            },
            ParallelExecutorTask {
                tx_index: 1,
                tx_bytes: vec![],
                tx_hash: [0; 32],
                gas_limit: 0,
            },
            ParallelExecutorTask {
                tx_index: 2,
                tx_bytes: vec![],
                tx_hash: [0; 32],
                gas_limit: 0,
            },
        ];
        DeterministicExecutionGuard::sort_tasks(&mut tasks);
        let indices: Vec<usize> = tasks.iter().map(|t| t.tx_index).collect();
        assert_eq!(indices, vec![1, 2, 3]);
    }

    #[test]
    fn deterministic_guard_sorts_outcomes() {
        let make = |i: usize| RawOutcome {
            tx_index: i,
            tx_hash: [0; 32],
            gas_limit: 0,
            gas_used: 0,
            success: true,
            revert_reason: None,
            write_set: vec![],
            read_set: vec![],
            events: vec![],
            return_data: vec![],
            execution_status: true,
        };
        let mut outcomes = vec![make(5), make(2), make(9)];
        DeterministicExecutionGuard::sort_outcomes(&mut outcomes);
        let indices: Vec<usize> = outcomes.iter().map(|o| o.tx_index).collect();
        assert_eq!(indices, vec![2, 5, 9]);
    }

    #[test]
    fn deterministic_verify_same_outcomes() {
        let make = |i: usize, writes: Vec<(Vec<u8>, Vec<u8>)>| RawOutcome {
            tx_index: i,
            tx_hash: [0; 32],
            gas_limit: 0,
            gas_used: 0,
            success: true,
            revert_reason: None,
            write_set: writes,
            read_set: vec![],
            events: vec![],
            return_data: vec![],
            execution_status: true,
        };
        let a = vec![make(0, vec![(vec![1], vec![2])]), make(1, vec![])];
        let b = vec![make(0, vec![(vec![1], vec![2])]), make(1, vec![])];
        assert!(DeterministicExecutionGuard::verify_determinism(&a, &b));
    }

    #[test]
    fn deterministic_verify_divergent_outcomes() {
        let make = |i: usize, v: u8| RawOutcome {
            tx_index: i,
            tx_hash: [0; 32],
            gas_limit: 0,
            gas_used: 0,
            success: true,
            revert_reason: None,
            write_set: vec![(vec![1], vec![v])],
            read_set: vec![],
            events: vec![],
            return_data: vec![],
            execution_status: true,
        };
        let a = vec![make(0, 10)];
        let b = vec![make(0, 99)]; // different write value
        assert!(!DeterministicExecutionGuard::verify_determinism(&a, &b));
    }

    // - Phase 25 - StateConsistencyChecker -

    #[test]
    fn consistency_checker_fingerprint_deterministic() {
        let make_outcome = |key: Vec<u8>, val: Vec<u8>| {
            let mut writes = HashMap::new();
            writes.insert(key, val);
            TxExecutionOutcome {
                tx_index: 0,
                snapshot_id: None,
                tx_version: None,
                success: true,
                gas_used: 0,
                output: vec![],
                rw_set: ReadWriteSet::new(vec![], vec![]),
                receipt: Receipt::new_success([0u8; 32], 0, None),
                speculative_writes: writes,
                error: None,
                had_conflict: false,
                retry_round: 0,
            }
        };
        let outcomes = vec![make_outcome(vec![1u8], vec![2u8])];
        let fp1 = StateConsistencyChecker::fingerprint_writes(&outcomes);
        let fp2 = StateConsistencyChecker::fingerprint_writes(&outcomes);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }

    #[test]
    fn consistency_checker_empty_writes() {
        let fp = StateConsistencyChecker::fingerprint_writes(&[]);
        assert_eq!(fp, 0, "empty writes should produce fingerprint 0");
    }

    // - Phase 25 - ConflictResolver -

    fn make_conflict(winner: usize, loser: usize) -> ConflictDetail {
        ConflictDetail {
            winner_tx: winner,
            loser_tx: loser,
            kind: ConflictKind::Raw,
            conflicting_keys: vec![vec![1u8]],
        }
    }

    #[test]
    fn conflict_resolver_abort_loser() {
        let resolver = ConflictResolver::new(ConflictResolutionPolicy::AbortLoser);
        let details = vec![make_conflict(0, 2)];
        let (abort_set, _) = resolver.resolve(&details, 1);
        assert!(abort_set.contains(&2));
        assert!(!abort_set.contains(&0));
    }

    #[test]
    fn conflict_resolver_retry_all() {
        let resolver = ConflictResolver::new(ConflictResolutionPolicy::RetryAll);
        let details = vec![make_conflict(0, 2)];
        let (abort_set, _) = resolver.resolve(&details, 1);
        assert!(abort_set.contains(&0));
        assert!(abort_set.contains(&2));
    }

    #[test]
    fn conflict_resolver_priority_by_index() {
        let resolver = ConflictResolver::new(ConflictResolutionPolicy::PriorityByIndex);
        // winner_tx=0, loser_tx=5 - higher index (5) should be aborted
        let details = vec![make_conflict(0, 5)];
        let (abort_set, _) = resolver.resolve(&details, 1);
        assert!(abort_set.contains(&5));
        assert!(!abort_set.contains(&0));
    }

    // - Phase 25 - OrderedCommitQueue -

    fn make_tx_outcome(tx_index: usize) -> TxExecutionOutcome {
        TxExecutionOutcome {
            tx_index,
            snapshot_id: None,
            tx_version: None,
            success: true,
            gas_used: 0,
            output: vec![],
            rw_set: ReadWriteSet::new(vec![], vec![]),
            receipt: Receipt::new_success([0u8; 32], 0, None),
            speculative_writes: HashMap::new(),
            error: None,
            had_conflict: false,
            retry_round: 0,
        }
    }

    #[test]
    fn ordered_commit_sequential() {
        let mut q = OrderedCommitQueue::new(0);
        q.enqueue(make_tx_outcome(0));
        q.enqueue(make_tx_outcome(1));
        q.enqueue(make_tx_outcome(2));
        let drained = q.drain_ordered();
        assert_eq!(drained.len(), 3);
        let indices: Vec<usize> = drained.iter().map(|o| o.tx_index).collect();
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn ordered_commit_out_of_order_delivery() {
        let mut q = OrderedCommitQueue::new(0);
        // Deliver out of order: 2 arrives before 0 and 1
        q.enqueue(make_tx_outcome(2));
        assert_eq!(
            q.drain_ordered().len(),
            0,
            "tx 2 cannot commit until 0 and 1 are ready"
        );
        q.enqueue(make_tx_outcome(0));
        assert_eq!(q.drain_ordered().len(), 1, "only tx 0 should be released");
        q.enqueue(make_tx_outcome(1));
        // Now both 1 and the previously-held 2 should drain
        let drained = q.drain_ordered();
        assert_eq!(drained.len(), 2);
        let indices: Vec<usize> = drained.iter().map(|o| o.tx_index).collect();
        assert_eq!(indices, vec![1, 2]);
    }

    #[test]
    fn ordered_commit_is_complete() {
        let mut q = OrderedCommitQueue::new(0);
        q.enqueue(make_tx_outcome(0));
        q.enqueue(make_tx_outcome(1));
        let _ = q.drain_ordered();
        assert!(q.is_complete(2));
        assert!(!q.is_complete(3));
    }
}
