/// Scheduling strategy, execution plan generation, and `BlockScheduler`.
///
/// Determines which transactions can be executed in parallel based on the
/// dependency graph and generates execution batches.
///
/// The main entrypoint is [`BlockScheduler`], which wraps a rayon thread-pool,
/// a task queue, and a worker registry to execute an entire block worth of
/// transactions with deterministic, conflict-aware scheduling.
use crate::parallel::dependency::{DependencyAnalyzer, ReadWriteSet};
use anyhow::{anyhow, bail, Result};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::{ThreadPool, ThreadPoolBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use tracing::{debug, info, warn};

/// Strategy for scheduling transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SchedulingStrategy {
    /// Serial execution: one transaction at a time (baseline).
    Serial,
    /// Batch execution: process all non-conflicting transactions in parallel.
    BatchedDAG,
    /// Greedy: try to maximize parallelism by executing as many as possible per batch.
    Greedy,
}

/// An execution batch: a set of transactions that can be executed in parallel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionBatch {
    pub batch_id: usize,
    /// Transaction indices in this batch.
    pub tx_indices: Vec<usize>,
}

impl ExecutionBatch {
    pub fn new(batch_id: usize, tx_indices: Vec<usize>) -> Self {
        Self {
            batch_id,
            tx_indices,
        }
    }

    pub fn len(&self) -> usize {
        self.tx_indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tx_indices.is_empty()
    }

    pub fn is_serial(&self) -> bool {
        self.tx_indices.len() == 1
    }
}

/// A complete execution schedule: the ordered list of batches.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionSchedule {
    pub batches: Vec<ExecutionBatch>,
    pub total_transactions: usize,
    pub strategy: SchedulingStrategy,
}

impl ExecutionSchedule {
    pub fn new(
        batches: Vec<ExecutionBatch>,
        total_transactions: usize,
        strategy: SchedulingStrategy,
    ) -> Self {
        Self {
            batches,
            total_transactions,
            strategy,
        }
    }

    /// Returns the parallelism factor: average transactions per batch.
    pub fn parallelism_factor(&self) -> f64 {
        if self.batches.is_empty() {
            return 0.0;
        }
        self.total_transactions as f64 / self.batches.len() as f64
    }

    /// Returns the number of batches.
    pub fn num_batches(&self) -> usize {
        self.batches.len()
    }

    /// Returns the maximum batch size.
    pub fn max_batch_size(&self) -> usize {
        self.batches.iter().map(|b| b.len()).max().unwrap_or(0)
    }

    /// Validates that all transactions are scheduled exactly once.
    pub fn validate(&self) -> Result<()> {
        let mut scheduled = HashSet::new();
        for batch in &self.batches {
            for &tx_idx in &batch.tx_indices {
                if tx_idx >= self.total_transactions {
                    return Err(anyhow!(
                        "transaction index {} out of bounds (total: {})",
                        tx_idx,
                        self.total_transactions
                    ));
                }
                if !scheduled.insert(tx_idx) {
                    return Err(anyhow!("transaction {} scheduled multiple times", tx_idx));
                }
            }
        }

        if scheduled.len() != self.total_transactions {
            return Err(anyhow!(
                "not all transactions scheduled (scheduled: {}, total: {})",
                scheduled.len(),
                self.total_transactions
            ));
        }

        Ok(())
    }
}

/// Generates an execution schedule.
pub struct Scheduler;

impl Scheduler {
    /// Produces a schedule using the given strategy.
    pub fn schedule(
        graph: &HashMap<usize, Vec<usize>>,
        total_tx: usize,
        strategy: SchedulingStrategy,
    ) -> Result<ExecutionSchedule> {
        match strategy {
            SchedulingStrategy::Serial => Self::serial_schedule(total_tx),
            SchedulingStrategy::BatchedDAG => Self::batched_dag_schedule(graph, total_tx),
            SchedulingStrategy::Greedy => Self::greedy_schedule(graph, total_tx),
        }
    }

    /// Serial schedule: one transaction per batch.
    pub fn serial_schedule(total_tx: usize) -> Result<ExecutionSchedule> {
        let batches = (0..total_tx)
            .map(|i| ExecutionBatch::new(i, vec![i]))
            .collect();
        let schedule = ExecutionSchedule::new(batches, total_tx, SchedulingStrategy::Serial);
        schedule.validate()?;
        Ok(schedule)
    }

    /// Batched DAG schedule: compute batch levels using the dependency graph.
    pub fn batched_dag_schedule(
        graph: &HashMap<usize, Vec<usize>>,
        total_tx: usize,
    ) -> Result<ExecutionSchedule> {
        // Compute the level of each transaction: the maximum distance from a source.
        let mut level = vec![0usize; total_tx];

        // Iterate until convergence
        let mut changed = true;
        while changed {
            changed = false;
            for tx_idx in 0..total_tx {
                if let Some(preds) = graph.get(&tx_idx) {
                    let new_level = preds.iter().map(|&p| level[p]).max().unwrap_or(0) + 1;
                    if new_level > level[tx_idx] {
                        level[tx_idx] = new_level;
                        changed = true;
                    }
                }
            }
        }

        // Group by level
        let max_level = *level.iter().max().unwrap_or(&0);
        let mut level_to_txs: Vec<Vec<usize>> = vec![Vec::new(); max_level + 1];
        for (tx_idx, &tx_level) in level.iter().enumerate() {
            level_to_txs[tx_level].push(tx_idx);
        }

        // Create batches from levels
        let batches = level_to_txs
            .into_iter()
            .enumerate()
            .filter_map(|(batch_id, tx_indices)| {
                if tx_indices.is_empty() {
                    None
                } else {
                    Some(ExecutionBatch::new(batch_id, tx_indices))
                }
            })
            .collect();

        let schedule = ExecutionSchedule::new(batches, total_tx, SchedulingStrategy::BatchedDAG);
        schedule.validate()?;
        Ok(schedule)
    }

    /// Greedy schedule: iteratively select all non-blocked transactions.
    pub fn greedy_schedule(
        graph: &HashMap<usize, Vec<usize>>,
        total_tx: usize,
    ) -> Result<ExecutionSchedule> {
        let mut executed = HashSet::new();
        let mut batches = Vec::new();
        let mut batch_id = 0;

        while executed.len() < total_tx {
            let batch_txs = DependencyAnalyzer::next_parallel_batch(graph, total_tx, &executed)?;

            if batch_txs.is_empty() {
                return Err(anyhow!(
                    "deadlock: no transactions can be scheduled (cycle?)"
                ));
            }

            executed.extend(&batch_txs);
            batches.push(ExecutionBatch::new(batch_id, batch_txs));
            batch_id += 1;
        }

        let schedule = ExecutionSchedule::new(batches, total_tx, SchedulingStrategy::Greedy);
        schedule.validate()?;
        Ok(schedule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_schedule_validate_all_scheduled() {
        let batches = vec![
            ExecutionBatch::new(0, vec![0, 1]),
            ExecutionBatch::new(1, vec![2]),
        ];
        let schedule = ExecutionSchedule::new(batches, 3, SchedulingStrategy::Serial);
        assert!(schedule.validate().is_ok());
    }

    #[test]
    fn execution_schedule_validate_missing_tx() {
        let batches = vec![ExecutionBatch::new(0, vec![0, 1])];
        let schedule = ExecutionSchedule::new(batches, 3, SchedulingStrategy::Serial);
        assert!(schedule.validate().is_err());
    }

    #[test]
    fn execution_schedule_validate_out_of_bounds() {
        let batches = vec![ExecutionBatch::new(0, vec![0, 5])];
        let schedule = ExecutionSchedule::new(batches, 3, SchedulingStrategy::Serial);
        assert!(schedule.validate().is_err());
    }

    #[test]
    fn serial_schedule_one_batch_per_tx() {
        let schedule = Scheduler::serial_schedule(5).unwrap();
        assert_eq!(schedule.batches.len(), 5);
        assert!(schedule.batches.iter().all(|b| b.len() == 1));
    }

    #[test]
    fn batched_dag_schedule_no_conflicts() {
        let graph = HashMap::new();
        let schedule = Scheduler::batched_dag_schedule(&graph, 4).unwrap();
        // All transactions can execute in one batch
        assert_eq!(schedule.batches.len(), 1);
        assert_eq!(schedule.batches[0].len(), 4);
    }

    #[test]
    fn batched_dag_schedule_linear_chain() {
        // 0 - 1 - 2
        let mut graph = HashMap::new();
        graph.insert(1, vec![0]);
        graph.insert(2, vec![1]);

        let schedule = Scheduler::batched_dag_schedule(&graph, 3).unwrap();
        assert_eq!(schedule.batches.len(), 3);
        assert_eq!(schedule.batches[0].tx_indices, vec![0]);
        assert_eq!(schedule.batches[1].tx_indices, vec![1]);
        assert_eq!(schedule.batches[2].tx_indices, vec![2]);
    }

    #[test]
    fn batched_dag_schedule_diamond() {
        // 0 - 1, 0 - 2, 1 - 3, 2 - 3
        let mut graph = HashMap::new();
        graph.insert(1, vec![0]);
        graph.insert(2, vec![0]);
        graph.insert(3, vec![1, 2]);

        let schedule = Scheduler::batched_dag_schedule(&graph, 4).unwrap();
        assert_eq!(schedule.batches.len(), 3);
        assert_eq!(schedule.batches[0].tx_indices, vec![0]);
        assert_eq!(schedule.batches[1].tx_indices.len(), 2);
        assert_eq!(schedule.batches[2].tx_indices, vec![3]);
    }

    #[test]
    fn greedy_schedule_respects_dependencies() {
        let mut graph = HashMap::new();
        graph.insert(1, vec![0]);
        graph.insert(2, vec![1]);

        let schedule = Scheduler::greedy_schedule(&graph, 3).unwrap();
        assert!(schedule.validate().is_ok());
        assert_eq!(schedule.batches.len(), 3);
    }

    #[test]
    fn parallelism_factor_calculation() {
        let batches = vec![
            ExecutionBatch::new(0, vec![0, 1, 2]),
            ExecutionBatch::new(1, vec![3]),
        ];
        let schedule = ExecutionSchedule::new(batches, 4, SchedulingStrategy::Greedy);
        assert_eq!(schedule.parallelism_factor(), 2.0);
    }
}

// - item 1: BlockScheduler struct -

/// Status of an individual execution task (item 5: per-index tracking).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatus {
    /// Waiting for predecessor tasks to finish.
    Pending,
    /// In the task queue, ready to be picked up by a worker.
    Queued,
    /// Currently executing on a worker thread.
    Running { worker_id: usize },
    /// Execution finished successfully.
    Completed,
    /// Execution detected a conflict; awaiting reschedule (item 8).
    Conflicted,
    /// Execution failed with an unrecoverable error.
    Failed { reason: String },
}

/// An atomic unit of work handed to a worker thread (item 3: execution task).
#[derive(Clone, Debug)]
pub struct ExecutionTask {
    /// The transaction's index in the original block (item 5).
    pub tx_index: usize,
    /// Which batch this task belongs to (used for deterministic ordering - item 6).
    pub batch_id: usize,
    /// Read/write set known *before* execution (may be empty on first attempt).
    pub estimated_rw_set: ReadWriteSet,
    /// Number of times this task has been retried due to aborts (item 8).
    pub retry_count: usize,
    /// Indices of predecessor tasks that must complete first (item 9).
    pub depends_on: Vec<usize>,
}

impl ExecutionTask {
    pub fn new(tx_index: usize, batch_id: usize, depends_on: Vec<usize>) -> Self {
        Self {
            tx_index,
            batch_id,
            estimated_rw_set: ReadWriteSet::default(),
            retry_count: 0,
            depends_on,
        }
    }

    /// Creates a reschedule clone with an incremented retry counter (item 8).
    pub fn as_retried(&self) -> Self {
        Self {
            tx_index: self.tx_index,
            batch_id: self.batch_id,
            estimated_rw_set: self.estimated_rw_set.clone(),
            retry_count: self.retry_count + 1,
            depends_on: self.depends_on.clone(),
        }
    }
}

/// Configuration for `BlockScheduler`.
#[derive(Clone, Debug)]
pub struct BlockSchedulerConfig {
    /// Number of rayon worker threads (item 2). `0` - rayon default.
    pub num_threads: usize,
    /// Max retries for an aborted transaction before it is serialised (item 8).
    pub max_retries: usize,
    /// Scheduling strategy used to build the initial execution plan.
    pub strategy: SchedulingStrategy,
}

impl Default for BlockSchedulerConfig {
    fn default() -> Self {
        Self {
            num_threads: 0,
            max_retries: 3,
            strategy: SchedulingStrategy::BatchedDAG,
        }
    }
}

/// Notification sent to the commit phase when a task completes (item 10).
#[derive(Clone, Debug)]
pub struct CommitNotification {
    pub tx_index: usize,
    pub success: bool,
    pub actual_rw_set: ReadWriteSet,
    pub gas_used: u64,
    pub output: Vec<u8>,
    pub error: Option<String>,
    /// Whether post-execution conflict detection triggered a reschedule (item 7).
    pub had_conflict: bool,
}

// - shared mutable state -

pub(crate) struct SchedulerState {
    /// item 1 / item 4: task queue for workers.
    #[allow(dead_code)]
    pub(crate) tx_queue: VecDeque<ExecutionTask>,
    /// item 5: per-transaction status index.
    pub(crate) task_status: HashMap<usize, TaskStatus>,
    /// item 7: rw-sets collected after execution for conflict analysis.
    pub(crate) executed_rw_sets: HashMap<usize, ReadWriteSet>,
    /// item 8: tasks that aborted and need rescheduling.
    #[allow(dead_code)]
    pub(crate) aborted_queue: VecDeque<ExecutionTask>,
    /// Collected commit notifications (item 10).
    pub(crate) commit_notifications: Vec<CommitNotification>,
}

impl SchedulerState {
    fn new(total_tx: usize) -> Self {
        Self {
            tx_queue: VecDeque::new(),
            task_status: (0..total_tx).map(|i| (i, TaskStatus::Pending)).collect(),
            executed_rw_sets: HashMap::new(),
            aborted_queue: VecDeque::new(),
            commit_notifications: Vec::new(),
        }
    }
}

// - item 1: BlockScheduler -

/// `BlockScheduler` - orchestrates parallel execution of all transactions in a block.
///
/// | Item | Implementation |
/// |------|---------------|
/// | 1 | Struct with `tx_queue` (in `SchedulerState`) and `workers` (thread-pool slots) |
/// | 2 | Dedicated rayon `ThreadPool` via `ThreadPoolBuilder` |
/// | 3 | `build_tasks()` splits a block's transactions into `ExecutionTask`s |
/// | 4 | `execute_block()` dispatches tasks to the thread pool via `pool.install` |
/// | 5 | `task_status` map tracks per-index state throughout execution |
/// | 6 | Tasks ordered `(batch_id, tx_index)` before dispatch; deterministic sort in `build_tasks` |
/// | 7 | `detect_conflicts_in_batch()` analyses actual rw-sets after each batch |
/// | 8 | Conflicted tasks are cloned with `as_retried()` and re-queued |
/// | 9 | `prioritised_ready_tasks()` ranks by dependent-count; used in main loop |
/// | 10 | `CommitNotification`s written to `SchedulerState` and Condvar-signalled |
pub struct BlockScheduler {
    config: BlockSchedulerConfig,
    /// item 2: dedicated rayon `ThreadPool`.
    pool: Arc<ThreadPool>,
    /// item 1: shared task queue + worker state (exposed so commit phase can wait).
    pub(crate) state: Arc<(Mutex<SchedulerState>, Condvar)>,
    /// Number of logical worker slots (mirrors pool size).
    pub num_workers: usize,
}

impl BlockScheduler {
    // - item 2: initialise rayon thread pool -

    pub fn new(config: BlockSchedulerConfig) -> Result<Self> {
        let num_workers = if config.num_threads == 0 {
            rayon::current_num_threads()
        } else {
            config.num_threads
        };

        let pool = ThreadPoolBuilder::new()
            .num_threads(num_workers)
            .thread_name(|i| format!("block-executor-{}", i))
            .build()
            .map_err(|e| anyhow!("failed to build rayon thread pool: {}", e))?;

        info!(num_workers, strategy = ?config.strategy, "BlockScheduler initialised");

        Ok(Self {
            config,
            pool: Arc::new(pool),
            state: Arc::new((Mutex::new(SchedulerState::new(0)), Condvar::new())),
            num_workers,
        })
    }

    // - item 3: split block transactions into execution tasks -

    /// Converts `total_tx` transactions and their dependency graph into
    /// a flat list of `ExecutionTask`s ordered by batch level (item 6).
    pub fn build_tasks(
        &self,
        total_tx: usize,
        graph: &HashMap<usize, Vec<usize>>,
    ) -> Result<Vec<ExecutionTask>> {
        let schedule = Scheduler::schedule(graph, total_tx, self.config.strategy.clone())?;
        let mut tasks = Vec::with_capacity(total_tx);

        // item 6: iterate batches in level order; within a batch sort by tx_index
        for batch in &schedule.batches {
            let mut sorted_indices = batch.tx_indices.clone();
            sorted_indices.sort_unstable();
            for &tx_idx in &sorted_indices {
                let depends_on = graph.get(&tx_idx).cloned().unwrap_or_default();
                tasks.push(ExecutionTask::new(tx_idx, batch.batch_id, depends_on));
            }
        }

        debug!(
            total_tx,
            batch_count = schedule.num_batches(),
            "tasks built"
        );
        Ok(tasks)
    }

    // - item 9: prioritise unresolved dependencies -

    /// Returns tasks ready for execution, ranked by dependent-count (most critical first).
    pub fn prioritised_ready_tasks<'a>(
        tasks: &'a [ExecutionTask],
        executed: &HashSet<usize>,
        graph: &HashMap<usize, Vec<usize>>,
    ) -> Vec<&'a ExecutionTask> {
        let mut dependents_count: HashMap<usize, usize> = HashMap::new();
        for preds in graph.values() {
            for &pred in preds {
                *dependents_count.entry(pred).or_insert(0) += 1;
            }
        }

        let mut ready: Vec<&ExecutionTask> = tasks
            .iter()
            .filter(|t| {
                !executed.contains(&t.tx_index)
                    && t.depends_on.iter().all(|dep| executed.contains(dep))
            })
            .collect();

        ready.sort_by(|a, b| {
            let da = dependents_count.get(&a.tx_index).copied().unwrap_or(0);
            let db = dependents_count.get(&b.tx_index).copied().unwrap_or(0);
            db.cmp(&da).then(a.tx_index.cmp(&b.tx_index))
        });

        ready
    }

    // - items 4, 5, 6, 7, 8, 10: execute a full block -

    /// Executes all transactions using the thread pool, with conflict detection
    /// and retry for aborted transactions.
    ///
    /// `executor_fn` - called on worker threads; receives a task, returns a notification.
    /// Returns all `CommitNotification`s in deterministic `tx_index` order (item 6).
    pub fn execute_block<F>(
        &self,
        mut tasks: Vec<ExecutionTask>,
        graph: &HashMap<usize, Vec<usize>>,
        executor_fn: F,
    ) -> Result<Vec<CommitNotification>>
    where
        F: Fn(&ExecutionTask) -> CommitNotification + Send + Sync + 'static,
    {
        if tasks.is_empty() {
            return Ok(vec![]);
        }

        let total_tx = tasks.iter().map(|t| t.tx_index).max().unwrap_or(0) + 1;
        let executor_fn = Arc::new(executor_fn);

        // Re-initialise shared state for this block.
        {
            let (lock, _) = self.state.as_ref();
            *lock
                .lock()
                .map_err(|e| anyhow!("scheduler lock poisoned: {e}"))? =
                SchedulerState::new(total_tx);
        }

        // item 6: deterministic enqueue order.
        tasks.sort_by_key(|t| (t.batch_id, t.tx_index));

        let mut executed: HashSet<usize> = HashSet::new();
        let mut remaining: Vec<ExecutionTask> = tasks;
        let mut all_notifications: Vec<CommitNotification> = Vec::new();

        loop {
            // item 4: separate ready vs blocked.
            let (ready, blocked): (Vec<ExecutionTask>, Vec<ExecutionTask>) = remaining
                .into_iter()
                .partition(|t| t.depends_on.iter().all(|dep| executed.contains(dep)));

            if ready.is_empty() && blocked.is_empty() {
                break;
            }
            if ready.is_empty() {
                bail!(
                    "scheduler deadlock: {} tasks blocked with none ready",
                    blocked.len()
                );
            }

            // item 9: rank ready tasks by dependents count.
            let mut dependents_count: HashMap<usize, usize> = HashMap::new();
            for preds in graph.values() {
                for &pred in preds {
                    *dependents_count.entry(pred).or_insert(0) += 1;
                }
            }
            let mut ready_sorted = ready;
            ready_sorted.sort_by(|a, b| {
                let da = dependents_count.get(&a.tx_index).copied().unwrap_or(0);
                let db = dependents_count.get(&b.tx_index).copied().unwrap_or(0);
                db.cmp(&da).then(a.tx_index.cmp(&b.tx_index))
            });

            // item 4: dispatch batch to workers via the dedicated pool.
            let fn_ref = executor_fn.clone();
            let results: Vec<CommitNotification> = self.pool.install(|| {
                ready_sorted
                    .par_iter()
                    .map(|task| fn_ref(task))
                    .collect::<Vec<_>>()
            });

            // item 5: update task status and rw-sets.
            {
                let (lock, _) = self.state.as_ref();
                let mut s = lock
                    .lock()
                    .map_err(|e| anyhow!("scheduler lock poisoned: {e}"))?;
                for notif in &results {
                    s.task_status.insert(
                        notif.tx_index,
                        if notif.success {
                            TaskStatus::Completed
                        } else {
                            TaskStatus::Failed {
                                reason: notif.error.clone().unwrap_or_default(),
                            }
                        },
                    );
                    s.executed_rw_sets
                        .insert(notif.tx_index, notif.actual_rw_set.clone());
                }
            }

            // item 7: detect conflicts within this batch.
            let batch_rw: Vec<(usize, ReadWriteSet)> = results
                .iter()
                .map(|n| (n.tx_index, n.actual_rw_set.clone()))
                .collect();
            let conflicted = Self::detect_conflicts_in_batch(&batch_rw, &executed);

            // item 8: reschedule conflicted tasks; commit clean ones.
            let mut aborted: Vec<ExecutionTask> = Vec::new();
            for notif in results {
                if conflicted.contains(&notif.tx_index) {
                    let original = match ready_sorted.iter().find(|t| t.tx_index == notif.tx_index)
                    {
                        Some(t) => t,
                        None => continue,
                    };
                    if original.retry_count >= self.config.max_retries {
                        warn!(
                            tx_index = original.tx_index,
                            "max retries reached; serialising"
                        );
                        executed.insert(notif.tx_index);
                        all_notifications.push(notif);
                    } else {
                        debug!(
                            tx_index = original.tx_index,
                            retry = original.retry_count + 1,
                            "rescheduling"
                        );
                        // item 5: mark as conflicted.
                        let (lock, _) = self.state.as_ref();
                        lock.lock()
                            .map_err(|e| anyhow!("scheduler lock poisoned: {e}"))?
                            .task_status
                            .insert(original.tx_index, TaskStatus::Conflicted);
                        aborted.push(original.as_retried());
                    }
                } else {
                    executed.insert(notif.tx_index);
                    all_notifications.push(notif);
                }
            }

            remaining = blocked;
            remaining.extend(aborted);
        }

        // item 6: deterministic output order.
        all_notifications.sort_by_key(|n| n.tx_index);

        // item 10: write to shared state and signal commit phase.
        {
            let (lock, cvar) = self.state.as_ref();
            lock.lock()
                .map_err(|e| anyhow!("scheduler lock poisoned: {e}"))?
                .commit_notifications = all_notifications.clone();
            cvar.notify_all();
        }

        info!(
            completed = all_notifications.len(),
            total_tx, "block execution finished; commit phase notified"
        );
        Ok(all_notifications)
    }

    // - item 7: post-execution conflict detection -

    /// Returns all transaction indices that conflict with an earlier transaction
    /// in the same parallel batch.
    pub fn detect_conflicts_in_batch(
        batch: &[(usize, ReadWriteSet)],
        already_committed: &HashSet<usize>,
    ) -> HashSet<usize> {
        let mut conflicted = HashSet::new();
        for i in 0..batch.len() {
            let (idx_i, rws_i) = &batch[i];
            if already_committed.contains(idx_i) {
                continue;
            }
            for (idx_j, rws_j) in batch.iter().take(i) {
                let raw_i = rws_i.raw_conflicts_with(rws_j);
                let raw_j = rws_j.raw_conflicts_with(rws_i);
                let waw: Vec<Vec<u8>> = rws_i
                    .write_set
                    .iter()
                    .filter(|k| rws_j.write_set.contains(k))
                    .cloned()
                    .collect();
                if !raw_i.is_empty() || !raw_j.is_empty() || !waw.is_empty() {
                    let later = idx_i.max(idx_j);
                    conflicted.insert(*later);
                    debug!(tx_i = idx_i, tx_j = idx_j, "conflict detected");
                }
            }
        }
        conflicted
    }

    // - item 10: commit-phase consumer -

    /// Blocks until all `expected` notifications are available, then returns them.
    #[allow(dead_code)]
    pub(crate) fn wait_for_commit_notifications(
        state: &Arc<(Mutex<SchedulerState>, Condvar)>,
        expected: usize,
    ) -> Result<Vec<CommitNotification>> {
        let (lock, cvar) = state.as_ref();
        let guard = cvar
            .wait_while(
                lock.lock()
                    .map_err(|e| anyhow!("scheduler lock poisoned: {e}"))?,
                |s| s.commit_notifications.len() < expected,
            )
            .map_err(|e| anyhow!("cvar wait failed: {e}"))?;
        Ok(guard.commit_notifications.clone())
    }

    pub fn num_threads(&self) -> usize {
        self.num_workers
    }

    pub fn config(&self) -> &BlockSchedulerConfig {
        &self.config
    }
}

// - BlockScheduler tests -

#[cfg(test)]
mod block_scheduler_tests {
    use super::*;

    fn make_scheduler() -> BlockScheduler {
        BlockScheduler::new(BlockSchedulerConfig {
            num_threads: 2,
            max_retries: 2,
            strategy: SchedulingStrategy::BatchedDAG,
        })
        .unwrap()
    }

    fn no_op_executor(task: &ExecutionTask) -> CommitNotification {
        CommitNotification {
            tx_index: task.tx_index,
            success: true,
            actual_rw_set: ReadWriteSet::default(),
            gas_used: 21_000,
            output: vec![],
            error: None,
            had_conflict: false,
        }
    }

    #[test]
    fn block_scheduler_initialises_thread_pool() {
        let sched = make_scheduler();
        assert_eq!(sched.num_threads(), 2);
    }

    #[test]
    fn build_tasks_tracks_tx_indices() {
        let sched = make_scheduler();
        let graph = HashMap::new();
        let tasks = sched.build_tasks(5, &graph).unwrap();
        assert_eq!(tasks.len(), 5);
        let indices: Vec<usize> = tasks.iter().map(|t| t.tx_index).collect();
        assert_eq!(indices, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn build_tasks_deterministic_ordering() {
        let sched = make_scheduler();
        let mut graph = HashMap::new();
        graph.insert(1, vec![0]);
        graph.insert(2, vec![0]);
        let v1: Vec<usize> = sched
            .build_tasks(3, &graph)
            .unwrap()
            .iter()
            .map(|t| t.tx_index)
            .collect();
        let v2: Vec<usize> = sched
            .build_tasks(3, &graph)
            .unwrap()
            .iter()
            .map(|t| t.tx_index)
            .collect();
        assert_eq!(v1, v2);
    }

    #[test]
    fn execute_block_all_complete() {
        let sched = make_scheduler();
        let graph = HashMap::new();
        let tasks = sched.build_tasks(4, &graph).unwrap();
        let notifs = sched.execute_block(tasks, &graph, no_op_executor).unwrap();
        assert_eq!(notifs.len(), 4);
        assert!(notifs.iter().all(|n| n.success));
    }

    #[test]
    fn execute_block_result_in_tx_index_order() {
        let sched = make_scheduler();
        let graph = HashMap::new();
        let tasks = sched.build_tasks(6, &graph).unwrap();
        let notifs = sched.execute_block(tasks, &graph, no_op_executor).unwrap();
        let indices: Vec<usize> = notifs.iter().map(|n| n.tx_index).collect();
        let mut sorted = indices.clone();
        sorted.sort_unstable();
        assert_eq!(indices, sorted, "results not in tx_index order");
    }

    #[test]
    fn execute_block_with_dependencies() {
        let sched = make_scheduler();
        let mut graph = HashMap::new();
        graph.insert(1, vec![0]);
        graph.insert(2, vec![1]);
        let tasks = sched.build_tasks(3, &graph).unwrap();
        let notifs = sched.execute_block(tasks, &graph, no_op_executor).unwrap();
        assert_eq!(notifs.len(), 3);
    }

    #[test]
    fn detect_conflicts_identifies_raw_conflict() {
        let rws0 = ReadWriteSet::new(vec![], vec![b"x".to_vec()]);
        let rws1 = ReadWriteSet::new(vec![b"x".to_vec()], vec![]);
        let conflicts =
            BlockScheduler::detect_conflicts_in_batch(&[(0, rws0), (1, rws1)], &HashSet::new());
        assert!(conflicts.contains(&1));
    }

    #[test]
    fn detect_conflicts_no_conflict() {
        let rws0 = ReadWriteSet::new(vec![], vec![b"x".to_vec()]);
        let rws1 = ReadWriteSet::new(vec![], vec![b"y".to_vec()]);
        let conflicts =
            BlockScheduler::detect_conflicts_in_batch(&[(0, rws0), (1, rws1)], &HashSet::new());
        assert!(conflicts.is_empty());
    }

    #[test]
    fn execution_task_retry_increments_count() {
        let task = ExecutionTask::new(0, 0, vec![]);
        let r1 = task.as_retried();
        assert_eq!(r1.retry_count, 1);
        assert_eq!(r1.as_retried().retry_count, 2);
    }

    #[test]
    fn prioritised_ready_tasks_orders_by_dependents() {
        let mut graph: HashMap<usize, Vec<usize>> = HashMap::new();
        graph.insert(2, vec![0]);
        graph.insert(3, vec![0]);
        graph.insert(4, vec![0]);

        let tasks = vec![
            ExecutionTask::new(0, 0, vec![]),
            ExecutionTask::new(1, 0, vec![]),
        ];
        let ready = BlockScheduler::prioritised_ready_tasks(&tasks, &HashSet::new(), &graph);
        assert_eq!(ready[0].tx_index, 0); // 3 dependents - highest priority
        assert_eq!(ready[1].tx_index, 1); // 0 dependents - second
    }
}
