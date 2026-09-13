//! Transaction execution engine for the SXIAUM blockchain.
//!
//! This crate provides:
//! - EVM-compatible contract execution via `revm`
//! - Parallel transaction execution pipeline (Block-STM inspired)
//! - Gas metering and fee calculation (memory expansion, storage, refunds, precompiles)
//! - State transition management
//! - Stateless execution from witnesses
//!
//! # Mainnet Readiness
//!
//! All execution paths enforce:
//! - Chain ID validation (replay-protection)
//! - Gas limit enforcement (per-transaction and per-block)
//! - Full execution gas accounting:
//!   - Memory expansion (Yellow Paper `C_mem`)
//!   - Cold/warm storage access and net-metered `SSTORE`
//!   - EIP-3529 refund cap (`gas_used / 5`)
//!   - Cancun precompile gas schedule
//! - Nonce correctness
//! - Balance sufficiency (including vesting lockup awareness)
//! - Contract bytecode size limits
//! - Storage access boundaries
//!
//! The parallel execution pipeline uses optimistic concurrency control
//! with conflict detection and deterministic serial fallback.

pub mod evm_runtime;
pub mod executor;
pub mod gas;
pub mod parallel;
pub mod stateless;

pub use crate::evm_runtime::{compute_contract_address, EvmConfig, EvmExecutionResult, EvmRuntime};
pub use crate::executor::{
    ConsensusSink, ExecutionMetrics, ExecutionResult, Executor, OptimisticExecutionResult,
    TransactionSource,
};
pub use crate::gas::{
    account_access_gas, calculate_intrinsic_gas, calculate_intrinsic_gas_ex, code_deposit_cost,
    copy_gas, initcode_cost, is_precompile, keccak256_gas, memory_cost, memory_expansion_cost,
    memory_words_for_range, num_words, precompile_gas, sload_gas, sstore_gas, validate_gas_limit,
    GasMeter, GasSchedule, SStoreGas, CALLDATA_GAS, CALLDATA_ZERO_GAS, CODE_DEPOSIT_GAS,
    COLD_ACCOUNT_ACCESS_COST, COLD_SLOAD_COST, COPY_GAS, ECRECOVER_GAS, INTRINSIC_GAS,
    KECCAK256_GAS, KECCAK256_WORD_GAS, MAX_REFUND_QUOTIENT, MEMORY_GAS, MODEXP_MIN_GAS,
    POINT_EVALUATION_GAS, SSTORE_CLEARS_SCHEDULE, SSTORE_RESET_GAS, SSTORE_SENTRY_GAS,
    SSTORE_SET_GAS, STORAGE_READ_GAS, STORAGE_WRITE_GAS, TX_CREATE_GAS, VALUE_TRANSFER_GAS,
    WARM_ACCOUNT_ACCESS_COST, WARM_STORAGE_READ_COST,
};
pub use crate::parallel::{
    BlockExecutionPipeline, BlockScheduler, BlockSchedulerConfig, CommitNotification,
    CommitProtocol, CommitResult, ConflictDetector, Dependency, DependencyAnalyzer, ExecutionBatch,
    ExecutionSchedule, ExecutionTask, FinalizedBlockOutput, ParallelExecutionConfig,
    ParallelExecutionResult, ParallelExecutionStrategy, ParallelExecutor, ParallelExecutorTask,
    PipelineConfig, ReadWriteSet, Scheduler, SchedulingStrategy, SerializationValidator, Snapshot,
    SnapshotId, TaskStatus, TransactionConflict, VersionValidator, VersionedMemory,
};
pub use crate::stateless::StatelessDbBackend;

// ---------------------------------------------------------------------------
// Mainnet execution constants
// ---------------------------------------------------------------------------

/// Maximum gas limit for a single transaction on mainnet.
/// Individual transactions may not request more gas than this.
pub const MAX_TRANSACTION_GAS_LIMIT: u64 = sxiaum_block::MAX_BLOCK_GAS_LIMIT;

/// Maximum contract bytecode size (24 KB, matching EIP-170).
///
/// Enforced by `revm` at `SpecId::CANCUN` during contract creation and
/// re-checked as defense-in-depth in [`crate::evm_runtime::EvmRuntime::
/// deploy_contract`] before execution begins.
pub const MAX_CONTRACT_SIZE: usize = 24 * 1024;

/// Maximum contract initcode size (48 KB, matching EIP-3860: twice the
/// deployed-code limit). Checked explicitly in both deploy paths.
pub const MAX_INITCODE_SIZE: usize = 2 * MAX_CONTRACT_SIZE;

/// Domain separation tag for execution result hashing.
pub const DOMAIN_EXECUTION_RESULT: &str = "SXIAUM_EXEC_RESULT";
