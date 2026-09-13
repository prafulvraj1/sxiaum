/// Parallel transaction execution with conflict detection and multi-version semantics.
///
/// This module enables concurrent execution of transactions from a single block by:
/// 1. **Dependency Analysis**: Detecting read/write conflicts between transactions
/// 2. **Multi-Version Memory**: Maintaining snapshots for speculative execution
/// 3. **Scheduling**: Determining which transactions can execute in parallel (DAG-based)
/// 4. **Parallel Execution**: Running non-conflicting transactions concurrently via rayon
/// 5. **Atomic Commit**: Validating and atomically committing execution results
///
/// The outcome is a permutation of transactions free of conflicts, executed faster
/// than serial execution.
pub mod commit;
pub mod dependency;
pub mod executor;
pub mod mv_memory;
pub mod scheduler;

pub use crate::parallel::commit::{
    CommitManager, CommitManagerConfig, CommitPhase, CommitProtocol, CommitResult, CommitSummary,
    SerializationValidator, VersionSnapshot, VersionValidator,
};
pub use crate::parallel::dependency::{
    ConflictDetector, Dependency, DependencyAnalyzer, DependencyGraph, DependencyGraphExport,
    EdgeExport, KeyOverlap, NodeExport, OverlapExport, OverlapType, ReadWriteSet,
    TransactionConflict,
};
pub use crate::parallel::executor::{
    BatchExecutionResult, BatchResult, BlockExecutionPipeline, ConflictDetail, ConflictKind,
    ConflictResolution, ConflictResolutionPolicy, ConflictResolver, DeterministicExecutionGuard,
    ExecutionContext, ExecutionContextPool, ExecutionMetrics, ExecutionOutput,
    FinalizedBlockOutput, HotAccountCache, MetricsSnapshot, OrderedCommitQueue,
    ParallelExecutionConfig, ParallelExecutionResult, ParallelExecutor, ParallelExecutorTask,
    PipelineConfig, RawOutcome, SpeculativeWrites, StateConsistencyChecker, StateKeyPrefetcher,
    TransactionExecutionResult, TxExecutionOutcome, WriteBatch,
};
pub use crate::parallel::mv_memory::{
    MVMemory, MVMemoryConfig, ReadRecord, Snapshot, SnapshotId, SpeculativeState, TxVersion,
    VersionStatus, VersionedMemory,
};
pub use crate::parallel::scheduler::{
    BlockScheduler, BlockSchedulerConfig, CommitNotification, ExecutionBatch, ExecutionSchedule,
    ExecutionTask, Scheduler, SchedulingStrategy, TaskStatus,
};

#[derive(Clone, Debug)]
pub enum ParallelExecutionStrategy {
    /// Execute transactions serially (baseline).
    Serial,
    /// Execute in parallel batches determined by dependency graph.
    BatchedDAG,
    /// Aggressive parallelism with optimistic concurrency control (OCC).
    OptimisticConcurrencyControl,
}
