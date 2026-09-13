use crate::evm_runtime::{l1_addr_to_revm, revm_u256_to_prim, EvmRuntime, OccStateDbBackend};
use crate::gas::{self, GasMeter};
use crate::parallel::executor::{
    BlockExecutionPipeline, ParallelExecutorTask, PipelineConfig, RawOutcome,
};
use crate::parallel::{mv_memory::MVMemory, TxVersion};
use anyhow::{bail, Result};
use parking_lot::Mutex;
use primitive_types::U256;
use rayon::prelude::*;
use revm::Database;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use sxiaum_block::Block;
use sxiaum_state::{ReadOnlyStateSnapshot, StateBatchOp, StateDB, StateDb};
use sxiaum_storage::StorageEngine;
use sxiaum_types::{
    Account, AccountError, Canonical, Log, Receipt, ReservationId, Transaction, TxError,
};
use tracing::{error, info, warn};

/// Result of executing a transaction, containing status, gas used, logs, and return bytes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub status: bool,
    pub gas_used: u64,
    pub logs: Vec<Log>,
    pub return_data: Vec<u8>,
}

impl ExecutionResult {
    pub fn success(gas_used: u64, return_data: Vec<u8>) -> Self {
        Self {
            status: true,
            gas_used,
            logs: Vec::new(),
            return_data,
        }
    }

    pub fn failure(gas_used: u64, return_data: Vec<u8>) -> Self {
        Self {
            status: false,
            gas_used,
            logs: Vec::new(),
            return_data,
        }
    }

    pub fn add_log(&mut self, log: Log) {
        self.logs.push(log);
    }

    pub fn try_encode(&self) -> Result<Vec<u8>> {
        <Self as Canonical>::try_encode(self)
    }

    pub fn encode(&self) -> Vec<u8> {
        <Self as Canonical>::try_encode(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        <Self as Canonical>::decode(bytes)
    }

    pub fn try_hash(&self) -> Result<[u8; 32]> {
        let bytes = self.try_encode()?;
        Ok(sxiaum_crypto::hash::domain_hash(
            crate::DOMAIN_EXECUTION_RESULT,
            &bytes,
        ))
    }
}

type AccessSet = (Vec<Vec<u8>>, Vec<Vec<u8>>);

#[derive(Clone, Debug, Default, Serialize)]
pub struct ExecutionMetrics {
    pub executed_transactions: usize,
    pub executed_blocks: usize,
    pub failed_transactions: usize,
    pub gas_used: u64,
    pub receipts_collected: usize,
}

#[derive(Clone, Debug)]
pub struct TransactionDependency {
    pub index: usize,
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
    pub depends_on: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct OptimisticExecutionResult {
    pub index: usize,
    pub tx_hash: [u8; 32],
    pub receipt: Option<Receipt>,
    pub execution_result: ExecutionResult,
    pub snapshot: ReadOnlyStateSnapshot,
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
    pub conflicted: bool,
}

pub trait TransactionSource {
    fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>>;
    fn acknowledge_transactions(&self, hashes: &[[u8; 32]]) -> Result<()>;

    fn pull_mev_transactions(
        &self,
        limit: usize,
        _parent_hash: &[u8; 32],
        _beacon_randomness: &[u8; 32],
    ) -> Result<(Vec<Transaction>, ReservationId)> {
        let txs = self.pull_transactions(limit)?;
        Ok((txs, ReservationId(0)))
    }

    fn release_transaction_reservation(&self, _reservation_id: ReservationId) -> Result<()> {
        Ok(())
    }
}

pub trait ConsensusSink {
    fn submit_finalized_block(&self, block: Block) -> Result<()>;
}

pub trait BlockProofVerifier: Send + Sync {
    fn verify_proof(&self, block: &Block, previous_state_root: [u8; 32]) -> Result<()>;
}

pub struct Executor {
    pub state: Arc<StateDB>,
    pub evm_config: crate::evm_runtime::EvmConfig,
    pub block_entropy: Mutex<[u8; 32]>,
    pub block_timestamp: Mutex<u64>,
    gas_meter: Mutex<GasMeter>,
    receipts: Mutex<Vec<Receipt>>,
    metrics: Mutex<ExecutionMetrics>,
    pub proof_verifier: Option<Arc<dyn BlockProofVerifier>>,
}

const EXECUTION_RESULT_PREFIX: &[u8] = b"execution:result:";
const BLOCK_RECEIPTS_ROOT_PREFIX: &[u8] = b"execution:block:receipts_root:";
const BLOCK_STATE_ROOT_PREFIX: &[u8] = b"execution:block:state_root:";

/// How the caller must reconcile its in-memory `sender` view after
/// `perform_transfer_or_contract_execution`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SenderSync {
    /// Executor-owned mutations (upfront debit, nonce bump) must be
    /// finalized locally (plain transfer path).
    Local,
    /// SECURITY (H-21): revm's `DatabaseCommit` already applied value
    /// transfer, nonce bump, and all inner-call effects to CANONICAL
    /// state; the in-memory view was reloaded from canonical state. The
    /// caller must not persist the stale pre-EVM snapshot or re-increment
    /// the nonce — only outer gas accounting remains.
    Canonical,
}

impl Executor {
    pub fn new(state_db: Arc<StateDB>, evm_config: crate::evm_runtime::EvmConfig) -> Self {
        Self {
            state: state_db,
            evm_config,
            block_entropy: Mutex::new([0u8; 32]),
            block_timestamp: Mutex::new(0),
            gas_meter: Mutex::new(GasMeter::default()),
            receipts: Mutex::new(Vec::new()),
            metrics: Mutex::new(ExecutionMetrics::default()),
            proof_verifier: None,
        }
    }

    pub fn with_proof_verifier(mut self, verifier: Arc<dyn BlockProofVerifier>) -> Self {
        self.proof_verifier = Some(verifier);
        self
    }

    pub fn execute_transaction_speculative(
        &self,
        tx: &Transaction,
        tx_version: TxVersion,
        mv_memory: &MVMemory,
    ) -> Result<RawOutcome> {
        let mut backend = OccStateDbBackend::new(self.state.clone(), tx_version, mv_memory);
        backend.register_address(&tx.from)?;
        if let Some(ref to) = tx.to {
            backend.register_address(to)?;
        }

        let sender_revm_addr = l1_addr_to_revm(&tx.from);
        let sender_info = backend.basic(sender_revm_addr)?.unwrap_or_default();

        let sender_balance = revm_u256_to_prim(sender_info.balance);
        let sender_nonce = sender_info.nonce;

        if sender_nonce != tx.nonce {
            return Err(TxError::InvalidNonce(sender_nonce, tx.nonce).into());
        }

        // SECURITY (H-18): fee/cost computation uses CHECKED arithmetic. The
        // previous `saturating_mul`/`saturating_add` silently clamped at the
        // U256 maximum, so an overflowed upfront cost passed the affordability
        // check below and the sender evaded fees entirely.
        let upfront_gas_fee = U256::from(tx.gas_limit)
            .checked_mul(tx.gas_price)
            .ok_or::<anyhow::Error>(TxError::InsufficientBalance.into())?;
        let upfront_cost = tx
            .value
            .checked_add(upfront_gas_fee)
            .ok_or::<anyhow::Error>(TxError::InsufficientBalance.into())?;

        let mut sender_spendable = sender_balance;
        if let Ok(Some(schedule)) = self.state.get_vesting_schedule(&tx.from) {
            let locked = schedule.locked_amount(*self.block_timestamp.lock());
            sender_spendable = sender_spendable.checked_sub(locked).unwrap_or(U256::zero());
        }

        if sender_spendable < upfront_cost {
            return Err(TxError::InsufficientBalance.into());
        }

        if tx.is_contract_creation() || tx.is_contract_call() {
            let entropy = *self.block_entropy.lock();
            let evm = EvmRuntime::new(self.evm_config.clone(), entropy);
            let (evm_result, mut occ_backend) = if tx.is_contract_creation() {
                evm.deploy_contract_speculative(&self.state, tx, tx_version, mv_memory)?
            } else {
                evm.execute_contract_call_speculative(&self.state, tx, tx_version, mv_memory)?
            };

            let sender_key = [b"account:".as_ref(), tx.from.as_bytes()].concat();
            let gas_fee = U256::from(evm_result.gas_used)
                .checked_mul(tx.gas_price)
                .ok_or_else(|| anyhow::anyhow!("gas fee multiplication overflow"))?;

            if evm_result.success {
                let mut caller_account = if let Some(val) = occ_backend.write_set.get(&sender_key) {
                    crate::evm_runtime::decode_account_bytes(val)?
                } else if let Some(acc) = occ_backend.get_account(&tx.from)? {
                    acc
                } else {
                    let mut acc = Account::new(tx.from);
                    acc.nonce = sender_nonce + 1;
                    // SECURITY (H-18): checked subtraction — the pre-check
                    // above guarantees affordability; an underflow here means
                    // corrupted state and must abort, not silently zero out.
                    acc.balance = sender_balance
                        .checked_sub(tx.value)
                        .ok_or::<anyhow::Error>(AccountError::Underflow.into())?;
                    acc
                };
                caller_account.balance = caller_account
                    .balance
                    .checked_sub(gas_fee)
                    .ok_or::<anyhow::Error>(AccountError::Underflow.into())?;
                let sender_bytes = caller_account.try_encode()?;
                occ_backend.write_set.insert(sender_key, sender_bytes);
            } else {
                occ_backend.write_set.clear();
                let mut caller_account = match occ_backend.get_account(&tx.from)? {
                    Some(acc) => acc,
                    None => Account::new(tx.from),
                };
                caller_account.nonce = sender_nonce + 1;
                caller_account.balance = caller_account
                    .balance
                    .checked_sub(gas_fee)
                    .ok_or::<anyhow::Error>(AccountError::Underflow.into())?;
                let sender_bytes = caller_account.try_encode()?;
                occ_backend.write_set.insert(sender_key, sender_bytes);
            }

            let mut write_set_vec: Vec<(Vec<u8>, Vec<u8>)> =
                occ_backend.write_set.into_iter().collect();
            write_set_vec.sort_by(|a, b| a.0.cmp(&b.0));
            let mut read_set_vec: Vec<Vec<u8>> = occ_backend.read_set.into_iter().collect();
            read_set_vec.sort_unstable();

            let unused_gas = tx
                .gas_limit
                .checked_sub(evm_result.gas_used)
                .ok_or_else(|| anyhow::anyhow!("gas used exceeds gas limit"))?;
            let gas_refund = U256::from(unused_gas)
                .checked_mul(tx.gas_price)
                .ok_or_else(|| anyhow::anyhow!("gas refund multiplication overflow"))?;
            let logs = self.emit_execution_logs(tx, evm_result.gas_used, gas_refund)?;
            let events: Vec<Vec<u8>> = logs
                .iter()
                .map(|log| log.try_encode())
                .collect::<Result<Vec<_>>>()?;

            Ok(RawOutcome {
                tx_index: tx_version.tx_index,
                tx_hash: tx.try_hash()?,
                gas_limit: tx.gas_limit,
                gas_used: evm_result.gas_used,
                success: evm_result.success,
                revert_reason: if evm_result.success {
                    None
                } else {
                    Some("execution reverted".to_string())
                },
                write_set: write_set_vec,
                read_set: read_set_vec,
                events,
                return_data: evm_result.return_data.clone(),
                execution_status: evm_result.success,
            })
        } else {
            // Standard value transfer speculatively
            let mut sender_account = match backend.get_account(&tx.from)? {
                Some(acc) => acc,
                None => Account::new(tx.from),
            };
            sender_account.nonce = sender_nonce + 1;
            // SECURITY (H-18): checked balance movements — see above.
            sender_account.balance = sender_account
                .balance
                .checked_sub(tx.value)
                .and_then(|b| b.checked_sub(upfront_gas_fee))
                .ok_or::<anyhow::Error>(AccountError::Underflow.into())?;

            if let Some(recipient_addr) = tx.to {
                let recipient_revm_addr = l1_addr_to_revm(&recipient_addr);
                let recipient_info = backend.basic(recipient_revm_addr)?.unwrap_or_default();

                let mut recipient_account = match backend.get_account(&recipient_addr)? {
                    Some(acc) => acc,
                    None => Account::new(recipient_addr),
                };
                recipient_account.balance = revm_u256_to_prim(recipient_info.balance)
                    .checked_add(tx.value)
                    .ok_or::<anyhow::Error>(AccountError::Overflow.into())?;
                recipient_account.nonce = recipient_info.nonce;

                let recipient_key = [b"account:".as_ref(), recipient_addr.as_bytes()].concat();
                let recipient_bytes = recipient_account.try_encode()?;
                backend.write_set.insert(recipient_key, recipient_bytes);
            }

            let intrinsic_gas = gas::calculate_intrinsic_gas(&tx.data);
            let gas_used = intrinsic_gas;
            let unused_gas = tx
                .gas_limit
                .checked_sub(gas_used)
                .ok_or_else(|| anyhow::anyhow!("gas used exceeds gas limit"))?;
            let gas_refund = U256::from(unused_gas)
                .checked_mul(tx.gas_price)
                .ok_or_else(|| anyhow::anyhow!("gas refund multiplication overflow"))?;

            sender_account.balance = sender_account
                .balance
                .checked_add(gas_refund)
                .ok_or::<anyhow::Error>(AccountError::Overflow.into())?;

            let sender_key = [b"account:".as_ref(), tx.from.as_bytes()].concat();
            let sender_bytes = sender_account.try_encode()?;
            backend.write_set.insert(sender_key, sender_bytes);

            let mut write_set_vec: Vec<(Vec<u8>, Vec<u8>)> =
                backend.write_set.into_iter().collect();
            write_set_vec.sort_by(|a, b| a.0.cmp(&b.0));
            let mut read_set_vec: Vec<Vec<u8>> = backend.read_set.into_iter().collect();
            read_set_vec.sort_unstable();

            let logs = self.emit_execution_logs(tx, gas_used, gas_refund)?;
            let events: Vec<Vec<u8>> = logs
                .iter()
                .map(|log| log.try_encode())
                .collect::<Result<Vec<_>>>()?;

            Ok(RawOutcome {
                tx_index: tx_version.tx_index,
                tx_hash: tx.try_hash()?,
                gas_limit: tx.gas_limit,
                gas_used,
                success: true,
                revert_reason: None,
                write_set: write_set_vec,
                read_set: read_set_vec,
                events,
                return_data: vec![],
                execution_status: true,
            })
        }
    }

    pub fn execute_transaction(&self, tx: &Transaction) -> Result<Receipt> {
        self.execute_pipeline(tx)
    }

    /// SECURITY (H-19): classify a speculative-execution failure.
    ///
    /// Returns the failed outcome plus a flag telling the caller whether the
    /// error was TRANSIENT INFRASTRUCTURE (storage I/O, poisoned locks, …).
    /// Previously EVERY error — including transient DB failures — was
    /// committed as `success:false, gas_used:0`, letting failed transactions
    /// occupy blocks for free and diverging from sequential semantics.
    /// Deterministic business failures (TxError/AccountError) now pay at
    /// least intrinsic gas; infrastructure failures must abort the block.
    fn classify_speculative_failure(
        &self,
        task: &ParallelExecutorTask,
        error: &anyhow::Error,
        tx_data: &[u8],
    ) -> (RawOutcome, bool) {
        let business = error.downcast_ref::<TxError>().is_some()
            || error.downcast_ref::<AccountError>().is_some();
        let gas_used = if business {
            gas::calculate_intrinsic_gas(tx_data).min(task.gas_limit)
        } else {
            0
        };
        (
            Self::failed_outcome(task, error.to_string(), gas_used),
            !business,
        )
    }

    /// Build a canonical failed [`RawOutcome`] (single source of truth for
    /// deserialization errors, classified failures, and abort paths).
    fn failed_outcome(task: &ParallelExecutorTask, reason: String, gas_used: u64) -> RawOutcome {
        RawOutcome {
            tx_index: task.tx_index,
            tx_hash: task.tx_hash,
            gas_limit: task.gas_limit,
            gas_used,
            success: false,
            revert_reason: Some(reason),
            write_set: vec![],
            read_set: vec![],
            events: vec![],
            return_data: vec![],
            execution_status: false,
        }
    }

    /// Validate signatures, account existence, gas bounds, and strictly
    /// sequential per-sender nonces for a batch of transactions against
    /// canonical state.
    ///
    /// Single source of truth shared by block validation and batch block
    /// production so the two paths can never drift apart.
    fn validate_transaction_batch(&self, transactions: &[Transaction]) -> Result<()> {
        let mut expected_nonces: std::collections::HashMap<sxiaum_types::Address, u64> =
            std::collections::HashMap::new();
        for tx in transactions {
            tx.validate_basic()?;
            self.verify_transaction_signature(tx)?;
            self.validate_account_existence(tx)?;
            self.validate_gas_limit(tx)?;

            let current_nonce = match expected_nonces.get(&tx.from) {
                Some(&n) => n,
                None => {
                    let sender = self.state.get_account(&tx.from)?.ok_or_else(|| {
                        anyhow::anyhow!("sender account does not exist: {}", tx.from)
                    })?;
                    sender.nonce
                }
            };

            if tx.nonce != current_nonce {
                bail!(
                    "nonce mismatch for {}: expected {}, got {}",
                    tx.from,
                    current_nonce,
                    tx.nonce
                );
            }
            expected_nonces.insert(
                tx.from,
                current_nonce
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("sender nonce exhausted: {}", tx.from))?,
            );
        }
        Ok(())
    }

    pub fn execute_transactions(&self, transactions: Vec<Transaction>) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::with_capacity(transactions.len());
        for tx in transactions {
            receipts.push(self.execute_transaction(&tx)?);
        }
        Ok(receipts)
    }

    pub fn execute_block(&self, block: Block) -> Result<[u8; 32]> {
        self.execute_block_pipeline(block)
    }

    pub fn receive_transactions_from_mempool<T: TransactionSource>(
        &self,
        source: &T,
        limit: usize,
    ) -> Result<Vec<Transaction>> {
        source.pull_transactions(limit)
    }

    pub fn produce_block_from_transactions(
        &self,
        mut block: Block,
        transactions: Vec<Transaction>,
    ) -> Result<Block> {
        *self.block_entropy.lock() = block.header.randomness_beacon;
        *self.block_timestamp.lock() = block.header.timestamp;
        block.body.transactions = transactions;
        let receipts = self.parallel_execute_batch(block.body.transactions.clone())?;
        block.body.receipts = receipts;
        block.try_compute_roots()?;
        block.header.state_root = self.state.update_state_root()?;
        Ok(block)
    }

    pub fn pass_finalized_block_to_consensus<C: ConsensusSink>(
        &self,
        sink: &C,
        block: Block,
    ) -> Result<()> {
        sink.submit_finalized_block(block)
    }

    pub fn execute_block_pipeline(&self, block: Block) -> Result<[u8; 32]> {
        *self.block_entropy.lock() = block.header.randomness_beacon;
        *self.block_timestamp.lock() = block.header.timestamp;
        block.validate_mainnet(current_unix_timestamp())?;
        self.validate_block_header(&block)?;
        let previous_root = self.load_previous_state_root();

        if let Some(verifier) = &self.proof_verifier {
            verifier.verify_proof(&block, previous_root)?;
        } else if cfg!(not(test)) {
            return Err(anyhow::anyhow!(
                "CRITICAL: ZK proof verifier not configured. Cannot import block under Policy A."
            ));
        }

        self.validate_block_transactions(&block)?;
        self.execute_system_transactions()?;

        info!(
            height = block.header.height,
            tx_count = block.body.transactions.len(),
            "starting parallel block execution pipeline"
        );

        let mut tasks: Vec<ParallelExecutorTask> =
            Vec::with_capacity(block.body.transactions.len());
        for (idx, tx) in block.body.transactions.iter().enumerate() {
            tasks.push(ParallelExecutorTask {
                tx_index: idx,
                tx_bytes: tx.try_encode()?,
                tx_hash: tx.try_hash()?,
                gas_limit: tx.gas_limit,
            });
        }

        let state_db = StateDb::new(self.state.storage());
        // SECURITY (H-34): rebuild-only initialization. The previous call to
        // `initialize_backend` could replay a persisted snapshot OVER live
        // rows, silently rolling the chain state backwards mid-operation.
        state_db.initialize_backend_rebuild_only()?;
        let state_mutex = Arc::new(Mutex::new(state_db));
        let mut pipeline_config = PipelineConfig::default();
        pipeline_config.commit_config.flush_to_disk = false;
        let mut pipeline = BlockExecutionPipeline::new(pipeline_config)?;

        let block_output_result = {
            // SECURITY (H-19): transient infrastructure errors observed inside
            // the speculative closure are collected here; the pipeline result
            // is rejected afterwards (see below).
            let infra_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let result = pipeline.run_block(
                block.try_hash()?,
                tasks,
                Arc::clone(&state_mutex),
                |task, snapshot_id, mv_memory| {
                    let tx: Transaction = match Transaction::decode(&task.tx_bytes) {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!(
                                "Failed to deserialize transaction for speculative execution: {:?}",
                                e
                            );
                            return Self::failed_outcome(
                                task,
                                format!("Deserialization error: {:?}", e),
                                0,
                            );
                        }
                    };
                    let tx_version = TxVersion {
                        tx_index: task.tx_index,
                        incarnation: snapshot_id.0 as usize,
                    };
                    let infra_errors = Arc::clone(&infra_errors);
                    self.execute_transaction_speculative(&tx, tx_version, mv_memory)
                        .unwrap_or_else(|e| {
                            warn!("SPECULATIVE_EXECUTION_FAILED_PAR: {:?}", e);
                            let (outcome, infra) =
                                self.classify_speculative_failure(task, &e, &tx.data);
                            if infra {
                                infra_errors.lock().push(e.to_string());
                            }
                            outcome
                        })
                },
            );
            let infra = infra_errors.lock().clone();
            if !infra.is_empty() {
                self.rollback_pipeline_state(&state_mutex)?;
                bail!(
                    "transient infrastructure failure(s) during parallel block execution: {:?}",
                    infra
                );
            }
            result
        };
        let block_output = match block_output_result {
            Ok(output) => output,
            Err(error) => {
                self.rollback_pipeline_state(&state_mutex)?;
                return Err(error);
            }
        };

        let receipts = block_output.receipts;
        let receipts_root = self.compute_receipts_merkle_root(&receipts)?;

        tracing::debug!(
            "execute_block_pipeline receipts_root={:?}, count={}",
            receipts_root,
            receipts.len()
        );

        let computed_state_root = block_output.state_root;

        tracing::debug!(
            "execute_block_pipeline computed_state_root={:?}",
            computed_state_root
        );

        if block.header.receipts_root != receipts_root {
            self.rollback_pipeline_state(&state_mutex)?;
            bail!("computed receipts root does not match block header");
        }

        if block.header.state_root != computed_state_root {
            self.rollback_pipeline_state(&state_mutex)?;
            bail!("computed state root does not match block header");
        }

        if block.header.gas_used != block_output.gas_used {
            self.rollback_pipeline_state(&state_mutex)?;
            bail!(
                "computed block gas used {} does not match block header {}",
                block_output.gas_used,
                block.header.gas_used
            );
        }

        // All header checks passed: land the staged raw-row writes in ONE
        // atomic batch (SECURITY H-20) before finalizing the block.
        {
            let pipeline_state = state_mutex.lock();
            pipeline_state.flush_staged_writes()?;
            pipeline_state.commit()?;
        }
        self.state.rebuild_tree_from_storage()?;

        let committed_root = self.commit_block_state()?;
        self.store_block_execution_results(
            block.header.height,
            &receipts,
            receipts_root,
            committed_root,
        )?;

        *self.receipts.lock() = receipts;
        self.metrics.lock().executed_blocks += 1;
        if !self.verify_state_root(committed_root)? {
            bail!("committed state root verification failed");
        }

        Ok(committed_root)
    }

    fn rollback_pipeline_state(&self, state: &Arc<Mutex<StateDb>>) -> Result<()> {
        let pipeline_state = state.lock();
        // SECURITY (H-20): staged raw rows must never leak on failure paths.
        pipeline_state.discard_staged_writes();
        pipeline_state.rollback()?;
        drop(pipeline_state);
        self.state.rebuild_tree_from_storage()?;
        Ok(())
    }

    pub fn execute_from_mempool_to_consensus<T: TransactionSource, C: ConsensusSink>(
        &self,
        source: &T,
        sink: &C,
        block: Block,
        limit: usize,
    ) -> Result<Block> {
        let (transactions, reservation) = source.pull_mev_transactions(
            limit,
            &block.header.parent_hash,
            &block.header.randomness_beacon,
        )?;
        let finalized_block = match self.produce_block_from_transactions(block, transactions) {
            Ok(b) => b,
            Err(e) => {
                let _ = source.release_transaction_reservation(reservation);
                return Err(e);
            }
        };

        let mut tx_hashes: Vec<[u8; 32]> =
            Vec::with_capacity(finalized_block.body.transactions.len());
        for t in &finalized_block.body.transactions {
            match t.try_hash() {
                Ok(h) => tx_hashes.push(h),
                Err(e) => {
                    let _ = source.release_transaction_reservation(reservation);
                    return Err(e);
                }
            }
        }

        if let Err(e) = self.pass_finalized_block_to_consensus(sink, finalized_block.clone()) {
            let _ = source.release_transaction_reservation(reservation);
            return Err(e);
        }
        source.acknowledge_transactions(&tx_hashes)?;
        Ok(finalized_block)
    }

    pub fn apply_receipts(&self, receipts: Vec<Receipt>) -> Result<()> {
        let mut stored = self.receipts.lock();
        stored.extend(receipts);
        self.metrics.lock().receipts_collected = stored.len();
        Ok(())
    }

    pub fn reset_state(&self, snapshot: u64) -> Result<[u8; 32]> {
        self.state.load_snapshot(snapshot)
    }

    pub fn commit_state(&self) -> Result<[u8; 32]> {
        self.state.commit()
    }

    pub fn rollback_state(&self) -> Result<[u8; 32]> {
        self.state.rollback()
    }

    pub fn collect_receipts(&self) -> Vec<Receipt> {
        self.receipts.lock().clone()
    }

    /// Execute protocol-level system transactions (e.g., validator staking rewards,
    /// consensus epoch transitions, or hard fork state migrations).
    ///
    /// System transactions execute at the start of a block without signature checks
    /// and produce deterministic receipts.
    pub fn execute_system_transactions(&self) -> Result<Vec<Receipt>> {
        Ok(Vec::new())
    }

    pub fn validate_block_transactions(&self, block: &Block) -> Result<()> {
        block.validate_basic()?;
        self.validate_transaction_batch(&block.body.transactions)
    }

    pub fn verify_state_root(&self, previous_root: [u8; 32]) -> Result<bool> {
        self.state.verify_state_root(previous_root)
    }

    pub fn generate_block_receipts(&self, block: &Block) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::with_capacity(block.body.transactions.len());
        for tx in &block.body.transactions {
            receipts.push(self.execute_transaction(tx)?);
        }
        Ok(receipts)
    }

    pub fn compute_block_state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    pub fn execute_pipeline(&self, tx: &Transaction) -> Result<Receipt> {
        self.pre_execution_checks(tx)?;
        self.verify_transaction_signature(tx)?;

        let mut sender = self.load_sender_account_state(tx)?;
        let mut recipient = self.load_recipient_account_state(tx)?;

        self.check_nonce_correctness(tx, &sender)?;
        self.validate_gas_limit(tx)?;

        let upfront_gas_fee = self.deduct_upfront_gas_fee(&mut sender, tx)?;
        let (gas_used, success, sender_sync) =
            self.perform_transfer_or_contract_execution(tx, &mut sender, recipient.as_mut())?;
        if sender_sync == SenderSync::Canonical {
            // SECURITY (H-21): the stale view was replaced by the post-EVM
            // canonical account; value/nonce are already applied and the
            // outer gas fee was charged during the sync. Nothing to do.
        } else {
            self.update_sender_nonce(&mut sender)?;
        }

        sender.validate()?;
        self.state.update_account(&tx.from, &sender)?;
        if success {
            if let (Some(address), Some(account)) = (tx.to, recipient.as_ref()) {
                if !tx.is_contract_call() {
                    account.validate()?;
                    self.state.update_account(&address, account)?;
                }
            }
        }

        let refund = self.refund_unused_gas(&tx.from, tx, upfront_gas_fee, gas_used)?;
        let mut receipt = if success {
            self.generate_execution_receipt(tx, gas_used)?
        } else {
            Receipt::new_failure(tx.try_hash()?, gas_used)
        };
        let logs = self.emit_execution_logs(tx, gas_used, refund)?;
        receipt.logs = logs;

        self.post_execution_updates(tx)?;
        self.commit_state()?;

        {
            let mut gas_meter = self.gas_meter.lock();
            gas_meter.gas_used = gas_meter.gas_used.saturating_add(gas_used);
            gas_meter.gas_limit = gas_meter.gas_limit.saturating_add(tx.gas_limit);
        }

        self.receipts.lock().push(receipt.clone());
        let mut metrics = self.metrics.lock();
        metrics.executed_transactions += 1;
        metrics.gas_used = metrics.gas_used.saturating_add(gas_used);
        metrics.receipts_collected = self.receipts.lock().len();

        Ok(receipt)
    }

    pub fn pre_execution_checks(&self, tx: &Transaction) -> Result<()> {
        tx.validate_basic()?;
        self.verify_transaction_signature(tx)?;
        let sender = self
            .state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))?;
        self.check_nonce_correctness(tx, &sender)?;
        self.validate_account_existence(tx)?;
        self.validate_gas_limit(tx)?;
        Ok(())
    }

    pub fn post_execution_updates(&self, _tx: &Transaction) -> Result<()> {
        self.state.update_state_root()?;
        Ok(())
    }

    pub fn detect_execution_failure(&self) -> bool {
        self.metrics.lock().failed_transactions > 0
    }

    pub fn parallel_execute_batch(&self, tx_batch: Vec<Transaction>) -> Result<Vec<Receipt>> {
        self.validate_transaction_batch(&tx_batch)?;

        let dependencies = self.detect_transaction_dependencies(&tx_batch);
        let optimistic_results = self.optimistic_execute_transactions(&tx_batch, &dependencies)?;
        self.commit_optimistic_results(&tx_batch, optimistic_results)
    }

    pub fn execution_metrics(&self) -> ExecutionMetrics {
        self.metrics.lock().clone()
    }

    pub fn detect_transaction_dependencies(
        &self,
        transactions: &[Transaction],
    ) -> Vec<TransactionDependency> {
        let access_sets: Vec<AccessSet> = transactions
            .iter()
            .map(|tx| {
                let read_set = self.transaction_read_set(tx);
                let write_set = self.transaction_write_set(tx);
                (read_set, write_set)
            })
            .collect();

        access_sets
            .iter()
            .enumerate()
            .map(|(index, (read_set, write_set))| {
                let depends_on = access_sets
                    .iter()
                    .take(index)
                    .enumerate()
                    .filter_map(|(prior_index, (prior_reads, prior_writes))| {
                        if Self::sets_overlap(read_set, prior_writes)
                            || Self::sets_overlap(write_set, prior_writes)
                            || Self::sets_overlap(write_set, prior_reads)
                        {
                            Some(prior_index)
                        } else {
                            None
                        }
                    })
                    .collect();

                TransactionDependency {
                    index,
                    read_set: read_set.clone(),
                    write_set: write_set.clone(),
                    depends_on,
                }
            })
            .collect()
    }

    pub fn detect_conflicts<'a, I>(&self, snapshot: &ReadOnlyStateSnapshot, keys: I) -> Result<bool>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        self.state.detect_conflicts(snapshot, keys)
    }

    pub fn optimistic_execute_transactions(
        &self,
        transactions: &[Transaction],
        dependencies: &[TransactionDependency],
    ) -> Result<Vec<OptimisticExecutionResult>> {
        let results: Result<Vec<_>> = transactions
            .par_iter()
            .enumerate()
            .map(|(index, tx)| {
                let dependency = &dependencies[index];
                let snapshot = self.state.begin_read_only_snapshot();
                let _parallel_reads = self.parallel_state_reads(&dependency.read_set)?;
                let dry_run_receipt = self.simulate_transaction(tx, &snapshot)?;
                let conflicted = self.detect_conflicts(
                    &snapshot,
                    dependency
                        .read_set
                        .iter()
                        .chain(dependency.write_set.iter())
                        .map(|k| k.as_slice()),
                )?;

                Ok(OptimisticExecutionResult {
                    index,
                    tx_hash: tx.try_hash()?,
                    receipt: Some(dry_run_receipt.clone()),
                    execution_result: ExecutionResult {
                        status: dry_run_receipt.status,
                        gas_used: dry_run_receipt.gas_used,
                        logs: dry_run_receipt.logs.clone(),
                        return_data: dry_run_receipt.state_root.unwrap_or_default().to_vec(),
                    },
                    snapshot,
                    read_set: dependency.read_set.clone(),
                    write_set: dependency.write_set.clone(),
                    conflicted,
                })
            })
            .collect();

        results
    }

    pub fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.state.parallel_state_reads(keys)
    }

    pub fn rollback_on_conflict(&self) -> Result<[u8; 32]> {
        self.rollback_state()
    }

    fn verify_transaction_signature(&self, tx: &Transaction) -> Result<()> {
        if tx.signature.is_none() {
            bail!("transaction must be signed");
        }

        if !tx.verify_signature()? {
            bail!("transaction signature verification failed");
        }

        Ok(())
    }

    fn check_nonce_correctness(&self, tx: &Transaction, sender: &Account) -> Result<()> {
        if sender.nonce != tx.nonce {
            bail!(
                "nonce mismatch for {}: expected {}, got {}",
                tx.from,
                sender.nonce,
                tx.nonce
            );
        }
        Ok(())
    }

    fn validate_gas_limit(&self, tx: &Transaction) -> Result<()> {
        gas::validate_gas_limit(tx)
    }

    fn validate_account_existence(&self, tx: &Transaction) -> Result<()> {
        if self.state.get_account(&tx.from)?.is_none() {
            bail!("sender account does not exist: {}", tx.from);
        }

        // In EVM, transferring to a new address automatically creates the account.
        // We only require the sender account to exist.

        Ok(())
    }

    fn deduct_upfront_gas_fee(&self, sender: &mut Account, tx: &Transaction) -> Result<U256> {
        let upfront_fee = tx.gas_cost();
        sender.checked_sub_balance(upfront_fee)?;
        Ok(upfront_fee)
    }

    fn load_sender_account_state(&self, tx: &Transaction) -> Result<Account> {
        self.state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))
    }

    fn load_recipient_account_state(&self, tx: &Transaction) -> Result<Option<Account>> {
        match tx.to {
            Some(address) => Ok(Some(
                self.state
                    .get_account(&address)?
                    .unwrap_or_else(|| Account::new(address)),
            )),
            None => Ok(None),
        }
    }

    /// How the caller must reconcile its in-memory `sender` view after
    /// `perform_transfer_or_contract_execution`.
    fn perform_transfer_or_contract_execution(
        &self,
        tx: &Transaction,
        sender: &mut Account,
        recipient: Option<&mut Account>,
    ) -> Result<(u64, bool, SenderSync)> {
        self.validate_transfer_overflow(sender, tx, recipient.as_deref())?;

        let mut gas_used = gas::calculate_intrinsic_gas(&tx.data);
        let mut success = true;

        if tx.is_contract_creation() {
            let entropy = *self.block_entropy.lock();
            let evm = crate::evm_runtime::EvmRuntime::new(self.evm_config.clone(), entropy);
            let evm_result = evm.deploy_contract(&self.state, tx)?;
            gas_used = evm_result.gas_used;
            success = evm_result.success;
            // SECURITY (H-21): revm already committed value/nonce/effects to
            // canonical state; reload instead of re-applying from the stale
            // snapshot (which previously OVERWROTE revm's caller updates).
            self.sync_sender_to_canonical(tx, sender, gas_used, success)?;
            Ok((gas_used, success, SenderSync::Canonical))
        } else if tx.is_contract_call() {
            let entropy = *self.block_entropy.lock();
            let evm = crate::evm_runtime::EvmRuntime::new(self.evm_config.clone(), entropy);
            let evm_result = evm.execute_contract_call(&self.state, tx)?;
            gas_used = evm_result.gas_used;
            success = evm_result.success;
            self.sync_sender_to_canonical(tx, sender, gas_used, success)?;
            Ok((gas_used, success, SenderSync::Canonical))
        } else if let Some(rec) = recipient {
            self.update_balances(sender, rec, tx.value)?;
            Ok((gas_used, success, SenderSync::Local))
        } else {
            sender.checked_sub_balance(tx.value)?;
            Ok((gas_used, success, SenderSync::Local))
        }
    }

    /// SECURITY (H-21): replace the caller's stale in-memory sender view with
    /// the post-EVM canonical account, charging the outer gas fee (revm runs
    /// with gas_price = 0 so it never debits gas itself).
    fn sync_sender_to_canonical(
        &self,
        tx: &Transaction,
        sender: &mut Account,
        gas_used: u64,
        _success: bool,
    ) -> Result<()> {
        *sender = self
            .state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))?;
        let expected_nonce = tx
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("sender nonce exhausted for {}", tx.from))?;
        if sender.nonce != expected_nonce {
            bail!(
                "post-EVM nonce divergence for {}: expected {}, got {}",
                tx.from,
                expected_nonce,
                sender.nonce
            );
        }
        let used_fee = tx
            .gas_price
            .checked_mul(U256::from(gas_used))
            .ok_or_else(|| anyhow::anyhow!("gas fee multiplication overflow"))?;
        sender.checked_sub_balance(used_fee)?;
        Ok(())
    }

    fn update_balances(
        &self,
        sender: &mut Account,
        recipient: &mut Account,
        amount: U256,
    ) -> Result<()> {
        let debited = sender
            .balance
            .checked_sub(amount)
            .ok_or(AccountError::Underflow)?;
        let credited = recipient
            .balance
            .checked_add(amount)
            .ok_or(AccountError::Overflow)?;
        sender.balance = debited;
        recipient.balance = credited;
        Ok(())
    }

    fn update_sender_nonce(&self, sender: &mut Account) -> Result<()> {
        sender.checked_increment_nonce()?;
        Ok(())
    }

    fn emit_execution_logs(
        &self,
        tx: &Transaction,
        gas_used: u64,
        refund: U256,
    ) -> Result<Vec<Log>> {
        let mut data = Vec::new();
        data.extend_from_slice(&gas_used.to_le_bytes());
        let mut refund_bytes = [0u8; 32];
        refund.to_big_endian(&mut refund_bytes);
        data.extend_from_slice(&refund_bytes);
        Ok(vec![Log::new(tx.from, vec![tx.try_hash()?], data)])
    }

    fn generate_execution_receipt(&self, tx: &Transaction, gas_used: u64) -> Result<Receipt> {
        Ok(Receipt::new_success(
            tx.try_hash()?,
            gas_used,
            Some(self.state.state_root()),
        ))
    }

    fn refund_unused_gas(
        &self,
        sender_address: &sxiaum_types::Address,
        tx: &Transaction,
        upfront_fee: U256,
        gas_used: u64,
    ) -> Result<U256> {
        let used_fee = tx
            .gas_price
            .checked_mul(U256::from(gas_used))
            .ok_or_else(|| anyhow::anyhow!("gas fee multiplication overflow"))?;
        let refund = upfront_fee
            .checked_sub(used_fee)
            .ok_or_else(|| anyhow::anyhow!("used fee exceeds the upfront gas fee"))?;
        if refund > U256::zero() {
            let mut sender = self
                .state
                .get_account(sender_address)?
                .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {sender_address}"))?;
            sender.checked_add_balance(refund)?;
            self.state.update_account(sender_address, &sender)?;
        }
        Ok(refund)
    }

    fn validate_block_header(&self, block: &Block) -> Result<()> {
        block.header.validate_basic()?;

        // Mainnet chain_id validation (replay protection).
        if block.header.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            bail!(
                "block chain_id {} does not match mainnet {}",
                block.header.chain_id,
                sxiaum_types::SXIAUM_CHAIN_ID
            );
        }

        // Mainnet block version validation.
        if block.header.version != sxiaum_block::BLOCK_VERSION_CURRENT {
            bail!(
                "block version {} does not match current protocol version {}",
                block.header.version,
                sxiaum_block::BLOCK_VERSION_CURRENT
            );
        }

        // Mainnet gas bounds validation.
        if block.header.gas_limit > sxiaum_block::MAX_BLOCK_GAS_LIMIT {
            bail!(
                "block gas limit {} exceeds maximum allowable {}",
                block.header.gas_limit,
                sxiaum_block::MAX_BLOCK_GAS_LIMIT
            );
        }
        if block.header.gas_limit < sxiaum_block::MIN_BLOCK_GAS_LIMIT {
            bail!(
                "block gas limit {} is below minimum allowable {}",
                block.header.gas_limit,
                sxiaum_block::MIN_BLOCK_GAS_LIMIT
            );
        }
        if block.header.gas_used > block.header.gas_limit {
            bail!(
                "block gas used {} exceeds gas limit {}",
                block.header.gas_used,
                block.header.gas_limit
            );
        }

        if block.body.compute_tx_root()? != block.header.tx_root {
            bail!("computed transaction root does not match block header");
        }
        Ok(())
    }

    fn load_previous_state_root(&self) -> [u8; 32] {
        self.state.state_root()
    }

    pub fn execute_transactions_sequentially(&self, block: &Block) -> Result<Vec<Receipt>> {
        *self.block_entropy.lock() = block.header.randomness_beacon;
        *self.block_timestamp.lock() = block.header.timestamp;
        let mut tasks: Vec<ParallelExecutorTask> =
            Vec::with_capacity(block.body.transactions.len());
        for (idx, tx) in block.body.transactions.iter().enumerate() {
            tasks.push(ParallelExecutorTask {
                tx_index: idx,
                tx_bytes: tx.try_encode()?,
                tx_hash: tx.try_hash()?,
                gas_limit: tx.gas_limit,
            });
        }

        let state_db = StateDb::new(self.state.storage());
        // SECURITY (H-34): rebuild-only initialization (see parallel site).
        state_db.initialize_backend_rebuild_only()?;
        let state_mutex = Arc::new(Mutex::new(state_db));
        let mut pipeline_config = PipelineConfig::default();
        pipeline_config.commit_config.flush_to_disk = false;
        let mut pipeline = BlockExecutionPipeline::new(pipeline_config)?;

        let block_output = {
            // SECURITY (H-19): see parallel site — infrastructure failures
            // abort instead of committing free failed outcomes.
            let infra_errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
            let result = pipeline.run_block(
                block.try_hash()?,
                tasks,
                state_mutex.clone(),
                |task, snapshot_id, mv_memory| {
                    let tx: Transaction = match Transaction::decode(&task.tx_bytes) {
                        Ok(tx) => tx,
                        Err(e) => {
                            return Self::failed_outcome(
                                task,
                                format!("Deserialization error: {:?}", e),
                                0,
                            );
                        }
                    };
                    let tx_version = TxVersion {
                        tx_index: task.tx_index,
                        incarnation: snapshot_id.0 as usize,
                    };
                    let infra_errors = Arc::clone(&infra_errors);
                    self.execute_transaction_speculative(&tx, tx_version, mv_memory)
                        .unwrap_or_else(|e| {
                            warn!("SPECULATIVE_EXECUTION_FAILED_SEQ: {:?}", e);
                            let (outcome, infra) =
                                self.classify_speculative_failure(task, &e, &tx.data);
                            if infra {
                                infra_errors.lock().push(e.to_string());
                            }
                            outcome
                        })
                },
            )?;
            let infra = infra_errors.lock().clone();
            if !infra.is_empty() {
                self.rollback_pipeline_state(&state_mutex)?;
                bail!(
                    "transient infrastructure failure(s) during block execution: {:?}",
                    infra
                );
            }
            result
        };

        // SECURITY (H-20): land staged rows in one atomic batch before commit.
        let pipeline_state = state_mutex.lock();
        pipeline_state.flush_staged_writes()?;
        pipeline_state.commit()?;
        drop(pipeline_state);
        self.state.rebuild_tree_from_storage()?;
        Ok(block_output.receipts)
    }

    pub fn compute_receipts_merkle_root(&self, receipts: &[Receipt]) -> Result<[u8; 32]> {
        let body = sxiaum_block::BlockBody {
            transactions: vec![],
            receipts: receipts.to_vec(),
        };
        body.compute_receipt_root()
    }

    fn commit_block_state(&self) -> Result<[u8; 32]> {
        self.commit_state()
    }

    fn store_block_execution_results(
        &self,
        height: u64,
        receipts: &[Receipt],
        receipts_root: [u8; 32],
        state_root: [u8; 32],
    ) -> Result<()> {
        let mut operations = Vec::with_capacity(receipts.len() + 2);
        operations.push(StateBatchOp::Put(
            Self::block_receipts_root_key(height),
            receipts_root.to_vec(),
        ));
        operations.push(StateBatchOp::Put(
            Self::block_state_root_key(height),
            state_root.to_vec(),
        ));

        for receipt in receipts {
            let result = ExecutionResult {
                status: receipt.status,
                gas_used: receipt.gas_used,
                logs: receipt.logs.clone(),
                return_data: receipt.state_root.unwrap_or_default().to_vec(),
            };
            operations.push(StateBatchOp::Put(
                Self::execution_result_key(&receipt.tx_hash),
                result.encode(),
            ));
        }

        self.state.write_batch(operations)?;
        self.metrics.lock().receipts_collected = self.receipts.lock().len();
        Ok(())
    }

    fn commit_optimistic_results(
        &self,
        transactions: &[Transaction],
        mut results: Vec<OptimisticExecutionResult>,
    ) -> Result<Vec<Receipt>> {
        results.sort_by_key(|result| result.index);

        let mut committed_receipts = Vec::with_capacity(results.len());
        for result in results {
            let mut conflict_keys = result.read_set.clone();
            conflict_keys.extend(result.write_set.clone());

            let has_runtime_conflict = result.conflicted
                || self.detect_conflicts(
                    &result.snapshot,
                    conflict_keys.iter().map(|k| k.as_slice()),
                )?;
            if has_runtime_conflict {
                self.rollback_on_conflict()?;
                committed_receipts.push(self.execute_transaction(&transactions[result.index])?);
                continue;
            }

            committed_receipts.push(self.execute_transaction(&transactions[result.index])?);
        }

        Ok(committed_receipts)
    }

    /// Dry-run `tx` against the current state snapshot and return the estimated
    /// gas used. Used by the RPC `sxiaum_estimateGas` endpoint so that callers
    /// get an execution-based estimate rather than a static formula.
    pub fn estimate_gas(&self, tx: &Transaction) -> Result<u64> {
        let receipt = self.simulate_transaction_on_temporary_state(tx)?;
        Ok(receipt.gas_used)
    }

    pub fn simulate_transaction_on_temporary_state(&self, tx: &Transaction) -> Result<Receipt> {
        let (isolated_path, isolated_storage, isolated_state) =
            self.create_isolated_state_copy()?;
        let isolated_executor = Executor::new(isolated_state, self.evm_config.clone());
        let res = isolated_executor.execute_simulation(tx);
        drop(isolated_executor);
        drop(isolated_storage);
        let _ = std::fs::remove_file(&isolated_path);
        res
    }

    pub fn execute_simulation(&self, tx: &Transaction) -> Result<Receipt> {
        tx.validate_basic()?;
        if tx.signature.is_some() || tx.ethereum_raw.is_some() {
            self.verify_transaction_signature(tx)?;
        }

        let mut sender = self.load_sender_account_state(tx)?;
        let mut recipient = self.load_recipient_account_state(tx)?;

        self.validate_gas_limit(tx)?;

        let upfront_gas_fee = self.deduct_upfront_gas_fee(&mut sender, tx)?;
        let (gas_used, success, sender_sync) =
            self.perform_transfer_or_contract_execution(tx, &mut sender, recipient.as_mut())?;
        if sender_sync == SenderSync::Canonical {
            // SECURITY (H-21): canonical reload — see execute_pipeline.
        } else {
            self.update_sender_nonce(&mut sender)?;
        }

        let refund = self.refund_unused_gas(&tx.from, tx, upfront_gas_fee, gas_used)?;
        let mut receipt = if success {
            self.generate_execution_receipt(tx, gas_used)?
        } else {
            Receipt::new_failure(tx.try_hash()?, gas_used)
        };
        let logs = self.emit_execution_logs(tx, gas_used, refund)?;
        receipt.logs = logs;

        Ok(receipt)
    }

    fn create_isolated_state_copy(&self) -> Result<(PathBuf, Arc<StorageEngine>, Arc<StateDB>)> {
        let path = self.temp_isolated_db_path("block-pipeline");
        let storage = Arc::new(StorageEngine::new(&path)?);

        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"account:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"storage:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"contract:code:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"vesting:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        for (key, value) in self
            .state
            .storage()
            .state_prefix_scan(b"block:hash:".to_vec())?
        {
            storage.state_put(key, value)?;
        }
        if let Some(root) = self
            .state
            .storage()
            .state_get(b"metadata:state_root".to_vec())?
        {
            storage.state_put(b"metadata:state_root".to_vec(), root)?;
        }

        let state = Arc::new(StateDB::new(storage.clone()));
        state.initialize_backend(0, None)?;
        Ok((path, storage, state))
    }

    fn temp_isolated_db_path(&self, name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-{name}-{unique}.redb"))
    }

    fn simulate_transaction(
        &self,
        tx: &Transaction,
        snapshot: &ReadOnlyStateSnapshot,
    ) -> Result<Receipt> {
        let _sender = self
            .state
            .get_account(&tx.from)?
            .ok_or_else(|| anyhow::anyhow!("sender account does not exist: {}", tx.from))?;
        self.validate_account_existence(tx)?;
        self.validate_gas_limit(tx)?;

        let gas_used = gas::calculate_intrinsic_gas(&tx.data);
        let logs = self.emit_execution_logs(tx, gas_used, U256::zero())?;
        let mut receipt = Receipt::new_success(tx.try_hash()?, gas_used, Some(snapshot.root));
        receipt.logs = logs;
        Ok(receipt)
    }

    fn transaction_read_set(&self, tx: &Transaction) -> Vec<Vec<u8>> {
        let mut keys = vec![Self::account_state_key(&tx.from)];
        if let Some(to) = tx.to {
            keys.push(Self::account_state_key(&to));
            if tx.is_contract_call() {
                keys.push(Self::contract_storage_prefix(&to));
            }
        }
        keys
    }

    fn transaction_write_set(&self, tx: &Transaction) -> Vec<Vec<u8>> {
        let mut keys = vec![Self::account_state_key(&tx.from)];
        if let Some(to) = tx.to {
            keys.push(Self::account_state_key(&to));
            if tx.is_contract_call() {
                keys.push(Self::contract_storage_prefix(&to));
            }
        } else {
            let contract_address = crate::evm_runtime::compute_contract_address(&tx.from, tx.nonce);
            keys.push(Self::account_state_key(&contract_address));
            keys.push(Self::contract_storage_prefix(&contract_address));
        }
        keys
    }

    fn account_state_key(address: &sxiaum_types::Address) -> Vec<u8> {
        let mut key = b"account:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    fn contract_storage_prefix(address: &sxiaum_types::Address) -> Vec<u8> {
        let mut key = b"storage:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    fn sets_overlap(left: &[Vec<u8>], right: &[Vec<u8>]) -> bool {
        let right_set: HashSet<&[u8]> = right.iter().map(Vec::as_slice).collect();
        left.iter().any(|key| right_set.contains(key.as_slice()))
    }

    fn validate_transfer_overflow(
        &self,
        sender: &Account,
        tx: &Transaction,
        recipient: Option<&Account>,
    ) -> Result<()> {
        let mut sender_spendable = sender.balance;
        if let Some(schedule) = self.state.get_vesting_schedule(&tx.from)? {
            let locked = schedule.locked_amount(*self.block_timestamp.lock());
            sender_spendable = sender_spendable.saturating_sub(locked);
        }

        if sender_spendable < tx.value {
            return Err(TxError::InsufficientBalance.into());
        }

        if let Some(recipient) = recipient {
            recipient
                .balance
                .checked_add(tx.value)
                .ok_or(AccountError::Overflow)?;
        }

        Ok(())
    }

    fn execution_result_key(tx_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = Vec::with_capacity(EXECUTION_RESULT_PREFIX.len() + tx_hash.len());
        key.extend_from_slice(EXECUTION_RESULT_PREFIX);
        key.extend_from_slice(tx_hash);
        key
    }

    fn block_receipts_root_key(height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_RECEIPTS_ROOT_PREFIX.len() + 20);
        key.extend_from_slice(BLOCK_RECEIPTS_ROOT_PREFIX);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }

    fn block_state_root_key(height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(BLOCK_STATE_ROOT_PREFIX.len() + 20);
        key.extend_from_slice(BLOCK_STATE_ROOT_PREFIX);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }
}

fn current_unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{ConsensusSink, ExecutionResult, Executor, TransactionSource};
    use crate::gas;
    use crate::parallel::{MVMemory, MVMemoryConfig, TxVersion};
    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use parking_lot::Mutex;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_state::StateDB;
    use sxiaum_storage::{Schema, StorageEngine};
    use sxiaum_types::{Account, Address, Canonical, Transaction};

    fn test_address(val: u8) -> Address {
        let mut bytes = [0u8; 32];
        bytes[12..32].fill(val);
        Address(bytes)
    }

    #[derive(Clone)]
    struct MockTransactionSource {
        transactions: Vec<Transaction>,
        acknowledged: Arc<Mutex<Vec<[u8; 32]>>>,
    }

    impl MockTransactionSource {
        fn new(transactions: Vec<Transaction>) -> Self {
            Self {
                transactions,
                acknowledged: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl TransactionSource for MockTransactionSource {
        fn pull_transactions(&self, limit: usize) -> Result<Vec<Transaction>> {
            Ok(self.transactions.iter().take(limit).cloned().collect())
        }

        fn acknowledge_transactions(&self, hashes: &[[u8; 32]]) -> Result<()> {
            self.acknowledged.lock().extend_from_slice(hashes);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MockConsensusSink {
        submitted_blocks: Arc<Mutex<Vec<Block>>>,
    }

    impl ConsensusSink for MockConsensusSink {
        fn submit_finalized_block(&self, block: Block) -> Result<()> {
            self.submitted_blocks.lock().push(block);
            Ok(())
        }
    }

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-execution-{name}-{unique}.redb"))
    }

    fn test_executor(name: &str) -> (Arc<StorageEngine>, Arc<StateDB>, Executor, PathBuf) {
        let db_path = temp_db_path(name);
        Schema::init(&db_path).expect("schema should initialize");
        let storage = Arc::new(StorageEngine::new(&db_path).expect("storage should initialize"));
        let state = Arc::new(StateDB::new(storage.clone()));
        let executor = Executor::new(
            state.clone(),
            crate::evm_runtime::EvmConfig::new(sxiaum_types::SXIAUM_CHAIN_ID),
        );
        (storage, state, executor, db_path)
    }

    fn cleanup(
        storage: Arc<StorageEngine>,
        state: Arc<StateDB>,
        executor: Executor,
        path: PathBuf,
    ) {
        drop(executor);
        drop(state);
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn signed_transfer(from_key: &SigningKey, to: Address, value: u64, nonce: u64) -> Transaction {
        let from = Address::from_public_key(&from_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(from, to, U256::from(value), nonce);
        tx.sign(from_key)
            .expect("transaction signing should succeed");
        tx
    }

    fn funded_account(address: Address, balance: u64) -> Account {
        let mut account = Account::new(address);
        account.balance = U256::from(balance);
        account
    }

    fn signed_contract_call(
        from_key: &SigningKey,
        to: Address,
        value: u64,
        nonce: u64,
        data: Vec<u8>,
    ) -> Transaction {
        let from = Address::from_public_key(&from_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_contract_call(from, to, U256::from(value), nonce, data);
        tx.gas_limit = 100000;
        tx.sign(from_key)
            .expect("transaction signing should succeed");
        tx
    }

    #[test]
    fn new_initializes_executor_and_basic_helpers_work() {
        let (storage, state, executor, path) = test_executor("new");
        let committed_root = executor
            .commit_state()
            .expect("initial commit should succeed");

        assert_eq!(executor.collect_receipts().len(), 0);
        assert_eq!(executor.execution_metrics().executed_transactions, 0);
        assert_eq!(executor.compute_block_state_root(), state.state_root());
        assert!(executor
            .execute_system_transactions()
            .expect("system tx execution should succeed")
            .is_empty());
        assert!(executor
            .verify_state_root(committed_root)
            .expect("state root verification should succeed"));
        assert!(!executor.detect_execution_failure());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn execute_transaction_and_execute_transactions_update_state_receipts_and_metrics() {
        let (storage, state, executor, path) = test_executor("execute-transactions");
        let sender_key = signing_key(1);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = test_address(1);

        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 100))
            .expect("recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 1_000, 0);
        executor
            .pre_execution_checks(&tx)
            .expect("pre-execution checks should succeed");
        let receipt = executor
            .execute_transaction(&tx)
            .expect("transaction execution should succeed");

        assert!(receipt.status);
        assert_eq!(receipt.tx_hash, tx.try_hash().unwrap());
        assert_eq!(receipt.gas_used, gas::calculate_intrinsic_gas(&tx.data));
        assert_eq!(executor.collect_receipts().len(), 1);
        assert_eq!(executor.execution_metrics().executed_transactions, 1);

        let sender_account = state
            .get_account(&sender)
            .expect("sender lookup should succeed")
            .expect("sender should exist");
        let recipient_account = state
            .get_account(&recipient)
            .expect("recipient lookup should succeed")
            .expect("recipient should exist");
        let expected_sender_balance = U256::from(500_000u64)
            - tx.value
            - tx.gas_price * U256::from(gas::calculate_intrinsic_gas(&tx.data));
        assert_eq!(sender_account.balance, expected_sender_balance);
        assert_eq!(sender_account.nonce, 1);
        assert_eq!(recipient_account.balance, U256::from(1_100u64));

        let next_tx = signed_transfer(&sender_key, recipient, 500, 1);
        let receipts = executor
            .execute_transactions(vec![next_tx.clone()])
            .expect("batch execution should succeed");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].tx_hash, next_tx.try_hash().unwrap());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn helper_steps_validate_signature_accounts_nonce_gas_and_refunds() {
        let (storage, state, executor, path) = test_executor("pipeline-helpers");
        let sender_key = signing_key(11);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = test_address(2);

        state
            .update_account(&sender, &funded_account(sender, 300_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 10))
            .expect("recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 2_500, 0);
        let unsigned_tx = Transaction::new_transfer(sender, recipient, U256::from(1u64), 0);
        assert!(executor.verify_transaction_signature(&unsigned_tx).is_err());
        executor
            .verify_transaction_signature(&tx)
            .expect("signed transaction should verify");

        let sender_state = executor
            .load_sender_account_state(&tx)
            .expect("sender load should succeed");
        let recipient_state = executor
            .load_recipient_account_state(&tx)
            .expect("recipient load should succeed")
            .expect("recipient should exist");
        assert_eq!(sender_state.address, sender);
        assert_eq!(recipient_state.address, recipient);

        executor
            .check_nonce_correctness(&tx, &sender_state)
            .expect("nonce check should succeed");
        executor
            .validate_gas_limit(&tx)
            .expect("gas validation should succeed");

        let mut gas_sender = sender_state.clone();
        let upfront_fee = executor
            .deduct_upfront_gas_fee(&mut gas_sender, &tx)
            .expect("upfront gas deduction should succeed");
        assert_eq!(upfront_fee, tx.gas_cost());
        assert_eq!(gas_sender.balance, sender_state.balance - tx.gas_cost());

        let mut transfer_sender = sender_state.clone();
        let mut transfer_recipient = recipient_state.clone();
        executor
            .perform_transfer_or_contract_execution(
                &tx,
                &mut transfer_sender,
                Some(&mut transfer_recipient),
            )
            .expect("transfer step should succeed");
        assert_eq!(transfer_sender.balance, sender_state.balance - tx.value);
        assert_eq!(
            transfer_recipient.balance,
            recipient_state.balance + tx.value
        );

        executor
            .update_sender_nonce(&mut transfer_sender)
            .expect("nonce update should succeed");
        assert_eq!(transfer_sender.nonce, sender_state.nonce + 1);

        let logs = executor
            .emit_execution_logs(
                &tx,
                gas::calculate_intrinsic_gas(&tx.data),
                U256::from(123u64),
            )
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, tx.from);
        assert_eq!(logs[0].topics, vec![tx.try_hash().unwrap()]);

        let receipt = executor
            .generate_execution_receipt(&tx, gas::calculate_intrinsic_gas(&tx.data))
            .expect("receipt generation should succeed");
        assert_eq!(receipt.tx_hash, tx.try_hash().unwrap());
        assert!(receipt.status);

        let refund = executor
            .refund_unused_gas(
                &sender,
                &tx,
                tx.gas_cost(),
                gas::calculate_intrinsic_gas(&tx.data),
            )
            .expect("refund should succeed");
        assert_eq!(
            refund,
            tx.gas_cost() - U256::from(gas::calculate_intrinsic_gas(&tx.data))
        );
        assert_eq!(
            state
                .get_balance(&sender)
                .expect("sender balance read should succeed"),
            U256::from(300_000u64) + refund
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn execute_pipeline_contract_call_updates_storage_logs_receipt_and_commits() {
        let (storage, state, executor, path) = test_executor("pipeline-contract-call");
        let sender_key = signing_key(12);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let contract = test_address(3);
        let call_data = vec![1u8, 2, 3, 4, 5];

        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        let mut contract_account = funded_account(contract, 0);
        let code_bytes = vec![0x00u8];
        let code_hash = sxiaum_crypto::hash::sha256(&code_bytes);
        state
            .set_code(&code_hash, code_bytes)
            .expect("contract code must persist");
        contract_account
            .set_code_hash(code_hash)
            .expect("code hash must be accepted");
        state
            .update_account(&contract, &contract_account)
            .expect("contract account update should succeed");

        let tx = signed_contract_call(&sender_key, contract, 750, 0, call_data.clone());
        let receipt = executor
            .execute_pipeline(&tx)
            .expect("contract call pipeline should succeed");

        assert_eq!(
            state
                .get_balance(&contract)
                .expect("contract balance read should succeed"),
            U256::from(750u64)
        );
        assert_eq!(
            state
                .get_nonce(&sender)
                .expect("sender nonce read should succeed"),
            1
        );
        assert!(receipt.status);
        assert!(executor
            .verify_state_root(state.state_root())
            .expect("state root verification should succeed"));

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn pre_execution_checks_reject_missing_sender_bad_nonce_and_low_gas() {
        let (storage, state, executor, path) = test_executor("pre-execution-failures");
        let sender_key = signing_key(13);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = test_address(4);

        state
            .update_account(&recipient, &funded_account(recipient, 0))
            .expect("recipient update should succeed");

        let missing_sender_tx = signed_transfer(&sender_key, recipient, 1, 0);
        assert!(executor.pre_execution_checks(&missing_sender_tx).is_err());

        state
            .update_account(&sender, &funded_account(sender, 100_000))
            .expect("sender update should succeed");
        let wrong_nonce_tx = signed_transfer(&sender_key, recipient, 1, 1);
        assert!(executor.pre_execution_checks(&wrong_nonce_tx).is_err());

        let mut low_gas_tx = signed_transfer(&sender_key, recipient, 1, 0);
        low_gas_tx.gas_limit = gas::calculate_intrinsic_gas(&low_gas_tx.data) - 1;
        assert!(executor.pre_execution_checks(&low_gas_tx).is_err());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn apply_receipts_commit_reset_and_rollback_round_trip_state() {
        let (storage, state, executor, path) = test_executor("state-round-trip");
        let address = test_address(5);
        let receipt =
            sxiaum_types::Receipt::new_success([7u8; 32], 21_000, Some(state.state_root()));

        executor
            .apply_receipts(vec![receipt.clone()])
            .expect("apply receipts should succeed");
        assert_eq!(executor.collect_receipts(), vec![receipt]);

        state
            .update_account(&address, &funded_account(address, 75))
            .expect("account update should succeed");
        let committed_root = executor.commit_state().expect("commit should succeed");
        assert!(executor
            .verify_state_root(committed_root)
            .expect("committed root verification should succeed"));

        state
            .set_balance(&address, U256::from(5u64))
            .expect("balance update should succeed");
        let rolled_back_root = executor.rollback_state().expect("rollback should succeed");
        assert_eq!(rolled_back_root, committed_root);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(75u64)
        );

        state.snapshot_state(0).expect("snapshot should succeed");
        state
            .set_balance(&address, U256::from(125u64))
            .expect("balance update should succeed");
        let reset_root = executor.reset_state(0).expect("reset state should succeed");
        assert_eq!(reset_root, committed_root);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(75u64)
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn generate_receipts_validate_block_and_execute_block_work_for_empty_and_non_empty_paths() {
        let (storage, state, executor, path) = test_executor("execute-block");
        let sender_key = signing_key(2);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = test_address(6);
        state
            .update_account(&sender, &funded_account(sender, 500_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 0))
            .expect("recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 1_000, 0);
        let mut non_empty_header = BlockHeader::new([1u8; 32], 1);
        non_empty_header.proposer = test_address(1);
        let generated_receipts = executor
            .generate_block_receipts(&Block::new(
                non_empty_header,
                BlockBody {
                    transactions: vec![tx.clone()],
                    receipts: vec![sxiaum_types::Receipt::new_success(
                        tx.try_hash().unwrap(),
                        gas::calculate_intrinsic_gas(&tx.data),
                        Some(state.state_root()),
                    )],
                },
            ))
            .expect("receipt generation should succeed");
        assert_eq!(generated_receipts.len(), 1);

        let empty_root = state.state_root();
        let mut empty_header = BlockHeader::new([1u8; 32], 1);
        empty_header.proposer = test_address(1);
        let mut empty_block = Block::new(empty_header, BlockBody::empty());
        empty_block.try_compute_roots().unwrap();
        empty_block.header.state_root = empty_root;

        executor
            .validate_block_transactions(&empty_block)
            .expect("empty block validation should succeed");
        let executed_root = executor
            .execute_block(empty_block)
            .expect("empty block execution should succeed");
        assert_eq!(executed_root, empty_root);

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn execute_block_pipeline_validates_header_executes_transactions_and_persists_results() {
        let (storage, state, executor, path) = test_executor("execute-block-pipeline");
        let (preview_storage, preview_state, preview_executor, preview_path) =
            test_executor("execute-block-pipeline-preview");
        let sender_key = signing_key(21);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = test_address(7);

        state
            .update_account(&sender, &funded_account(sender, 900_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 250))
            .expect("recipient update should succeed");
        executor
            .commit_state()
            .expect("initial commit should succeed");
        preview_state
            .update_account(&sender, &funded_account(sender, 900_000))
            .expect("preview sender update should succeed");
        preview_state
            .update_account(&recipient, &funded_account(recipient, 250))
            .expect("preview recipient update should succeed");
        preview_executor
            .commit_state()
            .expect("preview initial commit should succeed");

        let tx = signed_transfer(&sender_key, recipient, 2_000, 0);
        let mut header = BlockHeader::new([7u8; 32], 1);
        header.proposer = test_address(1);
        let mut body = BlockBody {
            transactions: vec![tx.clone()],
            receipts: vec![sxiaum_types::Receipt::new_success(
                tx.try_hash().unwrap(),
                gas::calculate_intrinsic_gas(&tx.data),
                Some(state.state_root()),
            )],
        };
        header.tx_root = body.compute_tx_root().unwrap();

        let preview_receipts = preview_executor
            .execute_transactions_sequentially(&Block::new(header.clone(), body.clone()))
            .expect("preview execution should succeed");
        body.receipts = preview_receipts.clone();
        let receipts_root = preview_executor
            .compute_receipts_merkle_root(&preview_receipts)
            .unwrap();
        let computed_state_root = preview_state.state_root();
        header.receipts_root = receipts_root;
        header.state_root = computed_state_root;
        header.gas_used = body.total_gas_used();

        let block = Block::new(header.clone(), body);

        executor
            .validate_block_header(&block)
            .expect("block header validation should succeed");
        let committed_root = executor
            .execute_block_pipeline(block)
            .expect("block pipeline execution should succeed");
        let receipts = executor.collect_receipts();

        assert_eq!(committed_root, computed_state_root);
        assert_eq!(receipts.len(), 1);
        assert_eq!(executor.execution_metrics().executed_blocks, 1);
        assert!(executor
            .verify_state_root(committed_root)
            .expect("committed state root verification should succeed"));

        let stored_receipts_root = storage
            .state_get(Executor::block_receipts_root_key(header.height))
            .expect("stored receipts root read should succeed")
            .expect("stored receipts root should exist");
        assert_eq!(stored_receipts_root, receipts_root.to_vec());

        let stored_state_root = storage
            .state_get(Executor::block_state_root_key(header.height))
            .expect("stored state root read should succeed")
            .expect("stored state root should exist");
        assert_eq!(stored_state_root, committed_root.to_vec());

        let encoded_result = storage
            .state_get(Executor::execution_result_key(&tx.try_hash().unwrap()))
            .expect("execution result read should succeed")
            .expect("execution result should exist");
        let decoded_result = ExecutionResult::decode(&encoded_result)
            .expect("execution result decode should succeed");
        assert!(decoded_result.status);
        assert_eq!(
            decoded_result.gas_used,
            gas::calculate_intrinsic_gas(&tx.data)
        );
        assert_eq!(decoded_result.logs.len(), 1);
        assert_eq!(decoded_result.return_data, committed_root.to_vec());

        cleanup(
            preview_storage,
            preview_state,
            preview_executor,
            preview_path,
        );
        cleanup(storage, state, executor, path);
    }

    #[test]
    fn post_execution_failure_parallel_batch_and_metrics_behave_as_expected() {
        let (storage, state, executor, path) = test_executor("parallel-batch");
        let sender_key = signing_key(3);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let other_sender_key = signing_key(4);
        let other_sender = Address::from_public_key(&other_sender_key.verifying_key().to_bytes());
        let recipient_a = test_address(8);
        let recipient_b = test_address(9);

        state
            .update_account(&sender, &funded_account(sender, 800_000))
            .expect("sender update should succeed");
        state
            .update_account(&other_sender, &funded_account(other_sender, 800_000))
            .expect("other sender update should succeed");
        state
            .update_account(&recipient_a, &funded_account(recipient_a, 0))
            .expect("recipient A update should succeed");
        state
            .update_account(&recipient_b, &funded_account(recipient_b, 0))
            .expect("recipient B update should succeed");

        let first = signed_transfer(&sender_key, recipient_a, 1_000, 0);
        let second = signed_transfer(&other_sender_key, recipient_b, 2_000, 0);

        let dependencies =
            executor.detect_transaction_dependencies(&[first.clone(), second.clone()]);
        assert_eq!(dependencies.len(), 2);
        assert!(dependencies[1].depends_on.is_empty());

        let committed = executor
            .parallel_execute_batch(vec![first.clone(), second.clone()])
            .expect("parallel batch execution should succeed");
        assert_eq!(committed.len(), 2);

        executor
            .post_execution_updates(&second)
            .expect("post execution updates should succeed");
        let metrics = executor.execution_metrics();
        assert_eq!(metrics.executed_transactions, 2);
        assert_eq!(metrics.receipts_collected, 2);
        assert_eq!(
            metrics.gas_used,
            gas::calculate_intrinsic_gas(&first.data) + gas::calculate_intrinsic_gas(&second.data)
        );

        executor.metrics.lock().failed_transactions = 1;
        assert!(executor.detect_execution_failure());

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn mempool_to_consensus_flow_receives_transactions_updates_state_and_submits_block() {
        let (storage, state, executor, path) = test_executor("mempool-to-consensus");
        let (preview_storage, preview_state, preview_executor, preview_path) =
            test_executor("mempool-to-consensus-preview");
        let sender_key = signing_key(41);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let recipient = test_address(10);

        state
            .update_account(&sender, &funded_account(sender, 600_000))
            .expect("sender update should succeed");
        state
            .update_account(&recipient, &funded_account(recipient, 50))
            .expect("recipient update should succeed");
        preview_state
            .update_account(&sender, &funded_account(sender, 600_000))
            .expect("preview sender update should succeed");
        preview_state
            .update_account(&recipient, &funded_account(recipient, 50))
            .expect("preview recipient update should succeed");

        let tx = signed_transfer(&sender_key, recipient, 1_500, 0);
        let source = MockTransactionSource::new(vec![tx.clone()]);
        let sink = MockConsensusSink::default();
        let mut block_header = BlockHeader::new([12u8; 32], 1);
        block_header.proposer = test_address(1);
        let block = Block::new(block_header, BlockBody::empty());

        let received = executor
            .receive_transactions_from_mempool(&source, 10)
            .expect("receiving transactions should succeed");
        assert_eq!(received, vec![tx.clone()]);

        let produced = preview_executor
            .produce_block_from_transactions(block.clone(), received)
            .expect("block production should succeed");
        assert_eq!(produced.body.transactions, vec![tx.clone()]);
        assert_eq!(produced.body.receipts.len(), 1);
        assert_eq!(produced.body.receipts[0].tx_hash, tx.try_hash().unwrap());
        assert_eq!(
            produced.header.tx_root,
            produced.body.compute_tx_root().unwrap()
        );
        assert_eq!(
            produced.header.receipts_root,
            produced.body.compute_receipt_root().unwrap()
        );
        assert_eq!(produced.header.state_root, preview_state.state_root());

        executor
            .pass_finalized_block_to_consensus(&sink, produced.clone())
            .expect("passing finalized block should succeed");
        assert_eq!(sink.submitted_blocks.lock().len(), 1);
        assert_eq!(sink.submitted_blocks.lock()[0], produced);

        let final_block = executor
            .execute_from_mempool_to_consensus(&source, &sink, block, 10)
            .expect("mempool to consensus flow should succeed");
        assert_eq!(final_block.body.transactions.len(), 1);
        assert_eq!(final_block.body.receipts.len(), 1);
        assert_eq!(
            final_block.header.tx_root,
            final_block.body.compute_tx_root().unwrap()
        );
        assert_eq!(
            final_block.header.receipts_root,
            final_block.body.compute_receipt_root().unwrap()
        );
        assert_eq!(sink.submitted_blocks.lock().len(), 2);
        assert_eq!(
            source.acknowledged.lock().as_slice(),
            &[tx.try_hash().unwrap()]
        );
        assert_eq!(
            state
                .get_nonce(&sender)
                .expect("sender nonce read should succeed"),
            1
        );
        assert!(
            state
                .get_balance(&recipient)
                .expect("recipient balance read should succeed")
                > U256::from(50u64)
        );

        cleanup(
            preview_storage,
            preview_state,
            preview_executor,
            preview_path,
        );
        cleanup(storage, state, executor, path);
    }

    #[test]
    fn dependency_detection_identifies_read_write_and_write_write_overlaps() {
        let (storage, state, executor, path) = test_executor("dependency-detection");
        let sender_key = signing_key(31);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let receiver_a = test_address(11);
        let receiver_b = test_address(12);
        let contract = test_address(13);

        state
            .update_account(&sender, &funded_account(sender, 1_000_000))
            .expect("sender update should succeed");
        state
            .update_account(&receiver_a, &funded_account(receiver_a, 0))
            .expect("receiver A update should succeed");
        state
            .update_account(&receiver_b, &funded_account(receiver_b, 0))
            .expect("receiver B update should succeed");
        let mut contract_account = funded_account(contract, 0);
        contract_account
            .set_code_hash([55u8; 32])
            .expect("code hash must be accepted");
        state
            .update_account(&contract, &contract_account)
            .expect("contract update should succeed");

        let first = signed_transfer(&sender_key, receiver_a, 10, 0);
        let second = signed_transfer(&sender_key, receiver_b, 20, 1);
        let third = signed_contract_call(&sender_key, contract, 0, 2, vec![1u8, 2, 3]);

        let dependencies = executor.detect_transaction_dependencies(&[
            first.clone(),
            second.clone(),
            third.clone(),
        ]);
        assert_eq!(dependencies.len(), 3);
        assert!(dependencies[0].depends_on.is_empty());
        assert_eq!(dependencies[1].depends_on, vec![0]);
        assert_eq!(dependencies[2].depends_on, vec![0, 1]);

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn conflict_detection_and_parallel_state_reads_use_snapshot_and_key_versions() {
        let (storage, state, executor, path) = test_executor("conflict-detection");
        let address = test_address(14);
        let other = test_address(15);
        state
            .update_account(&address, &funded_account(address, 10))
            .expect("address update should succeed");
        state
            .update_account(&other, &funded_account(other, 20))
            .expect("other update should succeed");
        state.commit().expect("initial commit should succeed");

        let snapshot = state.begin_read_only_snapshot();
        let keys = vec![
            b"account:"
                .iter()
                .copied()
                .chain(address.as_bytes().iter().copied())
                .collect::<Vec<u8>>(),
            b"account:"
                .iter()
                .copied()
                .chain(other.as_bytes().iter().copied())
                .collect::<Vec<u8>>(),
        ];
        let reads = executor
            .parallel_state_reads(&keys)
            .expect("parallel state reads should succeed");
        assert_eq!(reads.len(), 2);
        assert!(reads.iter().all(Option::is_some));
        assert!(!executor
            .detect_conflicts(&snapshot, keys.iter().map(|k| k.as_slice()))
            .expect("conflict detection should succeed"));

        state
            .set_balance(&address, U256::from(99u64))
            .expect("balance update should succeed");
        assert!(executor
            .detect_conflicts(&snapshot, keys.iter().map(|k| k.as_slice()))
            .expect("conflict detection should succeed"));

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn optimistic_execution_produces_receipts_and_deterministic_commit_order() {
        let (storage, state, executor, path) = test_executor("optimistic-execution");
        let first_sender_key = signing_key(32);
        let second_sender_key = signing_key(33);
        let first_sender = Address::from_public_key(&first_sender_key.verifying_key().to_bytes());
        let second_sender = Address::from_public_key(&second_sender_key.verifying_key().to_bytes());
        let receiver_a = test_address(16);
        let receiver_b = test_address(17);

        state
            .update_account(&first_sender, &funded_account(first_sender, 500_000))
            .expect("first sender update should succeed");
        state
            .update_account(&second_sender, &funded_account(second_sender, 500_000))
            .expect("second sender update should succeed");
        state
            .update_account(&receiver_a, &funded_account(receiver_a, 0))
            .expect("receiver A update should succeed");
        state
            .update_account(&receiver_b, &funded_account(receiver_b, 0))
            .expect("receiver B update should succeed");

        let first = signed_transfer(&first_sender_key, receiver_a, 1_000, 0);
        let second = signed_transfer(&second_sender_key, receiver_b, 2_000, 0);
        let transactions = vec![first.clone(), second.clone()];
        let dependencies = executor.detect_transaction_dependencies(&transactions);
        let optimistic = executor
            .optimistic_execute_transactions(&transactions, &dependencies)
            .expect("optimistic execution should succeed");

        assert_eq!(optimistic.len(), 2);
        assert_eq!(optimistic[0].index, 0);
        assert_eq!(optimistic[1].index, 1);
        assert!(!optimistic[0].conflicted);
        assert!(!optimistic[1].conflicted);
        assert_eq!(
            optimistic[0]
                .receipt
                .as_ref()
                .expect("first receipt should exist")
                .tx_hash,
            first.try_hash().unwrap()
        );
        assert_eq!(
            optimistic[1]
                .receipt
                .as_ref()
                .expect("second receipt should exist")
                .tx_hash,
            second.try_hash().unwrap()
        );

        let committed = executor
            .commit_optimistic_results(
                &transactions,
                vec![optimistic[1].clone(), optimistic[0].clone()],
            )
            .expect("optimistic commit should succeed");
        assert_eq!(committed.len(), 2);
        assert_eq!(committed[0].tx_hash, first.try_hash().unwrap());
        assert_eq!(committed[1].tx_hash, second.try_hash().unwrap());
        assert_eq!(
            state
                .get_nonce(&first_sender)
                .expect("first sender nonce read should succeed"),
            1
        );
        assert_eq!(
            state
                .get_nonce(&second_sender)
                .expect("second sender nonce read should succeed"),
            1
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn rollback_on_conflict_restores_committed_state() {
        let (storage, state, executor, path) = test_executor("rollback-on-conflict");
        let address = test_address(18);
        state
            .update_account(&address, &funded_account(address, 123))
            .expect("account update should succeed");
        let committed_root = state.commit().expect("commit should succeed");

        state
            .set_balance(&address, U256::from(456u64))
            .expect("balance mutation should succeed");
        let rolled_back_root = executor
            .rollback_on_conflict()
            .expect("rollback on conflict should succeed");

        assert_eq!(rolled_back_root, committed_root);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(123u64)
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn test_differential_execution() {
        let (storage, state, executor, path) = test_executor("differential-execution");

        let tx_count = 100;
        let mut transactions = Vec::with_capacity(tx_count);
        let mut sender_keys = Vec::with_capacity(tx_count);

        // Setup state
        for i in 0..tx_count {
            let key = signing_key(i as u8 + 100);
            let address = Address::from_public_key(&key.verifying_key().to_bytes());
            sender_keys.push(key);
            state
                .update_account(&address, &funded_account(address, 10_000_000))
                .expect("account update should succeed");
        }
        let contract_addr = test_address(99);
        let mut contract_acc = funded_account(contract_addr, 0);
        let code_bytes = vec![0x00u8];
        let code_hash = sxiaum_crypto::hash::sha256(&code_bytes);
        state
            .set_code(&code_hash, code_bytes)
            .expect("contract code must persist");
        contract_acc
            .set_code_hash(code_hash)
            .expect("code hash must be accepted");
        state
            .update_account(&contract_addr, &contract_acc)
            .expect("contract account update should succeed");

        state.commit().expect("commit should succeed");

        // Generate transactions
        for i in 0..tx_count {
            let sender_key = &sender_keys[i];
            // 50% transfers, 50% mock contract calls (if target is a contract)
            let tx = if i % 2 == 0 {
                let to = Address::from_public_key(
                    &sender_keys[(i + 1) % tx_count].verifying_key().to_bytes(),
                );
                signed_transfer(sender_key, to, 100, 0)
            } else {
                let to = test_address(99);
                signed_contract_call(sender_key, to, 100, 0, vec![i as u8, 1, 2, 3])
            };
            transactions.push(tx);
        }

        let mut block_header = sxiaum_block::BlockHeader::new([1u8; 32], 1);
        block_header.proposer = test_address(1);
        let mut block = Block::new(block_header, sxiaum_block::BlockBody::empty());
        block.body.transactions = transactions.clone();

        // 1. Sequential execution
        let seq_receipts = executor
            .execute_transactions(transactions.clone())
            .expect("sequential execution should succeed");
        let seq_state_root = executor.state.update_state_root().unwrap();

        // 2. Setup again for parallel execution
        let (par_storage, par_state, par_executor, par_path) =
            test_executor("differential-execution-par");
        for key in sender_keys.iter().take(tx_count) {
            let address = Address::from_public_key(&key.verifying_key().to_bytes());
            par_executor
                .state
                .update_account(&address, &funded_account(address, 10_000_000))
                .expect("account update should succeed");
        }
        let mut contract_acc_par = funded_account(contract_addr, 0);
        let code_bytes_par = vec![0x00u8];
        let code_hash_par = sxiaum_crypto::hash::sha256(&code_bytes_par);
        par_executor
            .state
            .set_code(&code_hash_par, code_bytes_par)
            .expect("contract code must persist");
        contract_acc_par
            .set_code_hash(code_hash_par)
            .expect("code hash must be accepted");
        par_executor
            .state
            .update_account(&contract_addr, &contract_acc_par)
            .expect("contract account update should succeed");

        par_executor.state.commit().expect("commit should succeed");

        // 3. Parallel execution
        let par_receipts = par_executor
            .parallel_execute_batch(transactions)
            .expect("parallel execution should succeed");
        let par_state_root = par_executor.state.update_state_root().unwrap();

        // 4. Assert Equivalence
        assert_eq!(
            seq_receipts.len(),
            par_receipts.len(),
            "Receipt counts should match"
        );
        for (i, (seq, par)) in seq_receipts.iter().zip(par_receipts.iter()).enumerate() {
            assert_eq!(seq.tx_hash, par.tx_hash, "Tx hash mismatch at index {}", i);
            assert_eq!(seq.status, par.status, "Status mismatch at index {}", i);
            assert_eq!(
                seq.gas_used, par.gas_used,
                "Gas used mismatch at index {}",
                i
            );
            assert_eq!(
                seq.logs.len(),
                par.logs.len(),
                "Logs length mismatch at index {}",
                i
            );
        }

        assert_eq!(
            seq_state_root, par_state_root,
            "Differential Execution Failed: Sequential and Parallel state roots do not match!"
        );

        cleanup(storage, state, executor, path);
        cleanup(par_storage, par_state, par_executor, par_path);
    }

    #[test]
    fn evm_prevrandao_matches_block_entropy() {
        let (storage, state, executor, path) = test_executor("prevrandao-test");
        let sender_key = signing_key(42);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());

        state
            .update_account(&sender, &funded_account(sender, 1_000_000))
            .expect("sender update should succeed");

        // Contract init code: PREVRANDAO (0x44), PUSH1 0 (0x60, 0x00), MSTORE (0x52), PUSH1 32 (0x60, 0x20), PUSH1 0 (0x60, 0x00), RETURN (0xf3)
        let init_code = hex::decode("4460005260206000f3").unwrap();

        let mut tx =
            sxiaum_types::Transaction::new_contract_deploy(sender, U256::zero(), 0, init_code);
        tx.gas_limit = 100_000;
        tx.sign(&sender_key).unwrap();

        let entropy = [7u8; 32];
        let evm = crate::evm_runtime::EvmRuntime::new(executor.evm_config.clone(), entropy);
        let result = evm.deploy_contract(&state, &tx).unwrap();
        assert!(result.success, "execution should succeed");
        assert_eq!(
            result.return_data,
            entropy.to_vec(),
            "PREVRANDAO must match block entropy"
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn speculative_contract_execution_charges_gas_and_updates_nonce_on_success() {
        let (storage, state, executor, path) = test_executor("spec-contract-gas-success");
        let sender_key = signing_key(101);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let initial_balance = U256::from(10_000_000u64);

        state
            .update_account(&sender, &funded_account(sender, initial_balance.as_u64()))
            .expect("sender update should succeed");
        state.commit().unwrap();

        // Bytecode: PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN (returns 32 bytes of 0x42)
        let init_code = hex::decode("604260005260206000f3").unwrap();
        let mut tx = Transaction::new_contract_deploy(sender, U256::zero(), 0, init_code);
        tx.gas_limit = 100_000;
        tx.gas_price = U256::from(10u64);
        tx.sign(&sender_key).unwrap();

        let mv_memory = MVMemory::new(MVMemoryConfig::default());
        let tx_version = TxVersion::new(0);

        let outcome = executor
            .execute_transaction_speculative(&tx, tx_version, &mv_memory)
            .expect("speculative execution should succeed");

        assert!(outcome.success, "execution should succeed");
        assert!(outcome.gas_used > 0, "gas_used must be > 0");

        // Verify sender account in write set
        let sender_key_bytes = [b"account:".as_ref(), sender.as_bytes()].concat();
        let sender_write = outcome
            .write_set
            .iter()
            .find(|(k, _)| k == &sender_key_bytes)
            .expect("sender write must be present in write_set");

        let updated_sender: Account = Account::decode(&sender_write.1)
            .expect("write-set account must use the canonical encoding");
        updated_sender
            .validate()
            .expect("write-set account must satisfy account invariants");
        assert_eq!(updated_sender.nonce, 1, "nonce must be incremented to 1");
        let expected_fee = U256::from(outcome.gas_used)
            .checked_mul(tx.gas_price)
            .expect("gas fee must not overflow");
        assert_eq!(
            updated_sender.balance,
            initial_balance
                .checked_sub(expected_fee)
                .expect("initial balance must cover the gas fee"),
            "sender balance must be charged for gas_used"
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn speculative_contract_execution_charges_gas_and_updates_nonce_on_revert() {
        let (storage, state, executor, path) = test_executor("spec-contract-gas-revert");
        let sender_key = signing_key(102);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let initial_balance = U256::from(10_000_000u64);

        state
            .update_account(&sender, &funded_account(sender, initial_balance.as_u64()))
            .expect("sender update should succeed");
        state.commit().unwrap();

        // Reverting initcode: INVALID opcode 0xFE
        let init_code = hex::decode("fe").unwrap();
        let mut tx = Transaction::new_contract_deploy(sender, U256::zero(), 0, init_code);
        tx.gas_limit = 100_000;
        tx.gas_price = U256::from(10u64);
        tx.sign(&sender_key).unwrap();

        let mv_memory = MVMemory::new(MVMemoryConfig::default());
        let tx_version = TxVersion::new(0);

        let outcome = executor
            .execute_transaction_speculative(&tx, tx_version, &mv_memory)
            .expect("speculative execution should return outcome even on revert");

        assert!(!outcome.success, "execution should fail/revert");
        assert!(outcome.gas_used > 0, "gas_used must be > 0 on revert");

        // Verify sender account in write set
        let sender_key_bytes = [b"account:".as_ref(), sender.as_bytes()].concat();
        let sender_write = outcome
            .write_set
            .iter()
            .find(|(k, _)| k == &sender_key_bytes)
            .expect("sender write must be present in write_set even on revert");

        let updated_sender: Account = Account::decode(&sender_write.1)
            .expect("write-set account must use the canonical encoding");
        updated_sender
            .validate()
            .expect("write-set account must satisfy account invariants");
        assert_eq!(
            updated_sender.nonce, 1,
            "nonce must be incremented on revert"
        );
        let expected_fee = U256::from(outcome.gas_used)
            .checked_mul(tx.gas_price)
            .expect("gas fee must not overflow");
        assert_eq!(
            updated_sender.balance,
            initial_balance
                .checked_sub(expected_fee)
                .expect("initial balance must cover the gas fee"),
            "sender balance must be charged for gas_used on revert"
        );

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn speculative_contract_execution_rejects_invalid_nonce_and_insufficient_balance() {
        let (storage, state, executor, path) = test_executor("spec-contract-rejects");
        let sender_key = signing_key(103);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());

        state
            .update_account(&sender, &funded_account(sender, 100))
            .expect("sender update should succeed");
        state.commit().unwrap();

        let init_code = hex::decode("6000").unwrap();
        let mut tx_wrong_nonce =
            Transaction::new_contract_deploy(sender, U256::zero(), 5, init_code.clone());
        tx_wrong_nonce.gas_limit = 100_000;
        tx_wrong_nonce.gas_price = U256::from(1u64);
        tx_wrong_nonce.sign(&sender_key).unwrap();

        let mv_memory = MVMemory::new(MVMemoryConfig::default());
        let tx_version = TxVersion::new(0);

        let err_nonce =
            executor.execute_transaction_speculative(&tx_wrong_nonce, tx_version, &mv_memory);
        assert!(err_nonce.is_err(), "wrong nonce must be rejected");

        let mut tx_low_balance =
            Transaction::new_contract_deploy(sender, U256::from(1000u64), 0, init_code);
        tx_low_balance.gas_limit = 100_000;
        tx_low_balance.gas_price = U256::from(100u64);
        tx_low_balance.sign(&sender_key).unwrap();

        let err_bal =
            executor.execute_transaction_speculative(&tx_low_balance, tx_version, &mv_memory);
        assert!(err_bal.is_err(), "insufficient balance must be rejected");

        cleanup(storage, state, executor, path);
    }

    #[test]
    fn contract_deployment_and_call_dependency_conflict_detected() {
        let (storage, state, executor, path) = test_executor("contract-dep-conflict");
        let sender_key = signing_key(104);
        let sender = Address::from_public_key(&sender_key.verifying_key().to_bytes());

        state
            .update_account(&sender, &funded_account(sender, 1_000_000))
            .expect("sender update should succeed");
        state.commit().unwrap();

        let init_code = hex::decode("604260005260206000f3").unwrap();
        let mut deploy_tx = Transaction::new_contract_deploy(sender, U256::zero(), 0, init_code);
        deploy_tx.gas_limit = 100_000;
        deploy_tx.sign(&sender_key).unwrap();

        let contract_addr = crate::evm_runtime::compute_contract_address(&sender, 0);

        let mut call_tx = Transaction::new_contract_call(
            sender,
            contract_addr,
            U256::zero(),
            1,
            vec![0x12, 0x34],
        );
        call_tx.gas_limit = 100_000;
        call_tx.sign(&sender_key).unwrap();

        let write_set = executor.transaction_write_set(&deploy_tx);
        let read_set = executor.transaction_read_set(&call_tx);

        let contract_account_key = Executor::account_state_key(&contract_addr);
        assert!(
            write_set.contains(&contract_account_key),
            "deploy write set must contain contract account"
        );
        assert!(
            read_set.contains(&contract_account_key),
            "call read set must contain contract account"
        );

        let deps = executor.detect_transaction_dependencies(&[deploy_tx, call_tx]);
        assert_eq!(deps.len(), 2);
        assert!(
            deps[1].depends_on.contains(&0),
            "call tx must depend on deploy tx"
        );

        cleanup(storage, state, executor, path);
    }
}
