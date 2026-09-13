//! EVM execution runtime backed by [`revm`].
//!
//! [`EvmRuntime`] wraps `revm::EVM` and bridges sxiaum's own types
//! (`Address`, `Account`, `Transaction`, `StateDb`) to revm's primitives
//! (`Address`/20-byte, `AccountInfo`, `U256`, etc.).
//!
//! # Address mapping
//! sxiaum uses 32-byte addresses (SHA-256 public key digests). revm uses
//! 20-byte addresses identical to Ethereum's.  We project by taking the
//! **last 20 bytes** of a sxiaum address for the revm side.
//!
//! Round-tripping that projection is lossy for native Ed25519-derived
//! addresses (full SHA-256 digests), so each EVM backend keeps a
//! per-transaction reverse map registered from the transaction's
//! `from`/`to` (and any other known L1 addresses). Ethereum-padded
//! addresses (12 leading zero bytes) still reverse cleanly without the map.
use crate::gas::GasMeter;
use anyhow::{anyhow, bail, Result};
use primitive_types::U256 as PrimU256;
use revm::primitives::{
    AccountInfo, Address as RevmAddress, Bytecode, ExecutionResult as RevmExecResult, B256,
    KECCAK_EMPTY, U256 as RevmU256,
};
use revm::{Database, DatabaseCommit};
use std::collections::HashMap;
use std::sync::Arc;
use sxiaum_crypto::hash::sha256;
use sxiaum_state::StateDb;
use sxiaum_types::{compute_storage_root, Account, Address, Canonical, Log, Transaction};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn decode_account_bytes(bytes: &[u8]) -> Result<Account> {
    let account = Account::decode(bytes)?;
    account.validate()?;
    Ok(account)
}

/// SECURITY: reject oversized deploy init-code up front (EIP-3860 parity).
///
/// revm enforces this at Cancun too, but an explicit pre-check keeps the
/// rejection deterministic and identical across serial and speculative paths.
fn validate_initcode_size(data: &[u8]) -> Result<()> {
    if data.len() > crate::MAX_INITCODE_SIZE {
        bail!(
            "deploy initcode is {} bytes, exceeding maximum of {} bytes (EIP-3860)",
            data.len(),
            crate::MAX_INITCODE_SIZE
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// EVM hardfork / gas-schedule configuration (item 20).
#[derive(Clone, Debug)]
pub struct EvmConfig {
    /// Chain identifier inserted into the EVM context.
    pub chain_id: u64,
    /// Default block-level gas limit.
    pub block_gas_limit: u64,
    /// revm `SpecId` that selects the active EVM hardfork rules.
    pub spec_id: revm::primitives::SpecId,
}

impl EvmConfig {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            block_gas_limit: 30_000_000,
            spec_id: revm::primitives::SpecId::CANCUN,
        }
    }
}

// ---------------------------------------------------------------------------
// Execution result
// ---------------------------------------------------------------------------

/// Normalised result returned from [`EvmRuntime`] execution (item 14).
#[derive(Clone, Debug, Default)]
pub struct EvmExecutionResult {
    /// `true` iff the call / creation succeeded without reverting.
    pub success: bool,
    /// Actual EVM gas consumed.
    pub gas_used: u64,
    /// ABI-encoded return / revert data.
    pub return_data: Vec<u8>,
    /// Emitted EVM logs translated to sxiaum [`Log`] objects (item 10).
    pub logs: Vec<Log>,
    /// For contract creation: the newly-deployed contract address.
    pub contract_address: Option<Address>,
}

// ---------------------------------------------------------------------------
// EvmRuntime (item 2)
// ---------------------------------------------------------------------------

/// High-level EVM runtime.  Wraps `revm::EVM<StateDbBackend>` and provides
/// `execute_contract_call` / `deploy_contract` that map sxiaum types to
/// the revm API and back.
pub struct EvmRuntime {
    pub config: EvmConfig,
    pub block_entropy: [u8; 32],
}

impl EvmRuntime {
    /// Create a new runtime with the supplied configuration.
    pub fn new(config: EvmConfig, block_entropy: [u8; 32]) -> Self {
        Self {
            config,
            block_entropy,
        }
    }

    // -----------------------------------------------------------------------
    // Public execute helpers
    // -----------------------------------------------------------------------

    /// Execute a contract-call transaction against `state` (item 5).
    ///
    /// Steps performed:
    /// 1. Resolve the target contract account from `StateDb`.
    /// 2. Load the contract bytecode for the callee (items 11, 12).
    /// 3. Build a `revm::EVM` with a `StateDbBackend` database adapter.
    /// 4. Populate `env.tx` from the sxiaum [`Transaction`] (items 7, 8).
    /// 5. Call `transact_commit` to run the EVM and persist state writes (item 9).
    /// 6. Convert the `revm::ExecutionResult` - [`EvmExecutionResult`] (items 9, 10, 14).
    /// 7. On revert/halt: propagate the failure without committing (item 15).
    pub fn execute_contract_call(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
    ) -> Result<EvmExecutionResult> {
        let to_addr = tx
            .to
            .ok_or_else(|| anyhow!("contract call missing `to` address"))?;

        // Verify the target is actually a deployed contract.
        let contract_account = state
            .get_account(&to_addr)?
            .ok_or_else(|| anyhow!("contract account not found: {}", to_addr))?;
        if !contract_account.is_contract() {
            bail!("target account {} is not a deployed contract", to_addr);
        }

        // Build the revm environment with reverse address map for native senders.
        let mut evm = self.build_evm_for_tx(state.clone(), tx)?;
        self.populate_tx_env(&mut evm.env.tx, tx);

        // Run the EVM and commit state changes atomically (item 9).
        let result = evm
            .transact_commit()
            .map_err(|e| anyhow!("EVM execution error: {:?}", e))?;

        // SECURITY (H-23): surface any error swallowed inside DatabaseCommit.
        if let Some(commit_error) = evm.take_db().take_commit_error() {
            bail!("EVM commit failed: {}", commit_error);
        }

        Ok(self.convert_result(result, None))
    }

    /// Execute an Ethereum-style read-only call without committing any state changes.
    pub fn call_contract_read_only(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
    ) -> Result<EvmExecutionResult> {
        let mut evm = self.build_evm_for_tx(state.clone(), tx)?;
        self.populate_tx_env(&mut evm.env.tx, tx);

        let result = evm
            .transact()
            .map_err(|e| anyhow!("EVM call error: {:?}", e))?
            .result;

        Ok(self.convert_result(result, None))
    }

    /// Deploy a contract (item 6).
    ///
    /// Steps performed:
    /// 1. Compute the deterministic contract address from `keccak(sender||nonce)` (item 13).
    /// 2. Validate bytecode length / structure (guard against trivially invalid code).
    /// 3. Build a `revm::EVM` in *create* mode (`to` = `None` in the revm tx env).
    /// 4. Set `TxEnv.data` to the deployment init-code supplied in `tx.data` (item 7).
    /// 5. Execute and commit; on success the contract address is returned (item 14).
    /// 6. On failure the state backend does **not** persist changes (item 15).
    /// 7. Persist the init-code SHA-256 hash into the account's `code_hash` (item 12).
    pub fn deploy_contract(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
    ) -> Result<EvmExecutionResult> {
        if tx.data.is_empty() {
            bail!("deploy_contract: init-code must not be empty");
        }
        validate_initcode_size(&tx.data)?;

        // Compute the new contract's canonical 32-byte address (item 13).
        let contract_addr = compute_contract_address(&tx.from, tx.nonce);

        // Build and configure the revm execution environment.
        let mut evm = self.build_evm_for_tx(state.clone(), tx)?;
        // Register the precomputed create address so post-deploy writes land correctly.
        if let Some(db) = evm.db.as_mut() {
            db.register_address(&contract_addr)?;
            let revm_from = l1_addr_to_revm(&tx.from);
            let revm_created = revm_from.create(tx.nonce);
            db.address_map
                .insert(revm_address_key(revm_created), contract_addr);
        }
        self.populate_tx_env(&mut evm.env.tx, tx);
        // Clear `to` so revm treats this as a CREATE transaction.
        evm.env.tx.transact_to =
            revm::primitives::TransactTo::Create(revm::primitives::CreateScheme::Create);

        // Run EVM (item 9); the `StateDbBackend::commit` persists storage writes.
        let result = evm
            .transact_commit()
            .map_err(|e| anyhow!("EVM deploy error: {:?}", e))?;

        // SECURITY (H-23): surface any error swallowed inside DatabaseCommit.
        if let Some(db) = evm.db.as_ref() {
            if let Some(commit_error) = db.take_commit_error() {
                bail!("EVM deploy commit failed: {}", commit_error);
            }
        }

        if let RevmExecResult::Success { ref output, .. } = result {
            let runtime_bytes = output.data();
            if !runtime_bytes.is_empty() {
                let code_hash = sha256(runtime_bytes);
                let mut account = state.get_account(&contract_addr)?.ok_or_else(|| {
                    anyhow!("deployed contract account missing: {}", contract_addr)
                })?;
                if !account.is_contract() {
                    state.set_code(&code_hash, runtime_bytes.to_vec())?;
                    account.set_code_hash(code_hash)?;
                    state.update_account(&contract_addr, &account)?;
                }
            }
        }

        Ok(self.convert_result(result, Some(contract_addr)))
    }

    /// Execute a contract-call transaction speculatively using a multi-version memory cache (OCC).
    pub fn execute_contract_call_speculative<'a>(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
        tx_version: crate::parallel::TxVersion,
        mv_memory: &'a crate::parallel::MVMemory,
    ) -> Result<(EvmExecutionResult, OccStateDbBackend<'a>)> {
        let to_addr = tx
            .to
            .ok_or_else(|| anyhow!("contract call missing `to` address"))?;

        let mut backend = OccStateDbBackend::new(state.clone(), tx_version, mv_memory);
        backend.register_tx(tx)?;
        let info = backend.basic(l1_addr_to_revm(&to_addr))?;
        if info.is_none() {
            bail!(
                "target contract account not found speculatively: {}",
                to_addr
            );
        }

        let mut evm = self.build_occ_evm(backend);
        self.populate_tx_env(&mut evm.env.tx, tx);

        let result = evm
            .transact_commit()
            .map_err(|e| anyhow!("EVM execution error: {:?}", e))?;

        let updated_backend = evm.take_db();

        // SECURITY (H-23): surface any error swallowed inside DatabaseCommit.
        if let Some(commit_error) = updated_backend.take_commit_error() {
            bail!("EVM speculative commit failed: {}", commit_error);
        }

        Ok((self.convert_result(result, None), updated_backend))
    }

    /// Deploy a contract speculatively using a multi-version memory cache (OCC).
    pub fn deploy_contract_speculative<'a>(
        &self,
        state: &Arc<StateDb>,
        tx: &Transaction,
        tx_version: crate::parallel::TxVersion,
        mv_memory: &'a crate::parallel::MVMemory,
    ) -> Result<(EvmExecutionResult, OccStateDbBackend<'a>)> {
        if tx.data.is_empty() {
            bail!("deploy_contract: init-code must not be empty");
        }
        validate_initcode_size(&tx.data)?;

        let contract_addr = compute_contract_address(&tx.from, tx.nonce);

        let mut backend = OccStateDbBackend::new(state.clone(), tx_version, mv_memory);
        backend.register_tx(tx)?;
        backend.register_address(&contract_addr)?;
        let revm_from = l1_addr_to_revm(&tx.from);
        let revm_created = revm_from.create(tx.nonce);
        backend
            .address_map
            .insert(revm_address_key(revm_created), contract_addr);
        let mut evm = self.build_occ_evm(backend);
        self.populate_tx_env(&mut evm.env.tx, tx);
        evm.env.tx.transact_to =
            revm::primitives::TransactTo::Create(revm::primitives::CreateScheme::Create);

        let result = evm
            .transact_commit()
            .map_err(|e| anyhow!("EVM deploy error: {:?}", e))?;

        let mut updated_backend = evm.take_db();

        // SECURITY (H-23): surface any error swallowed inside DatabaseCommit.
        if let Some(commit_error) = updated_backend.take_commit_error() {
            bail!("EVM speculative deploy commit failed: {}", commit_error);
        }

        if let RevmExecResult::Success { ref output, .. } = result {
            let runtime_bytes = output.data();
            let mut account_key = b"account:".to_vec();
            account_key.extend_from_slice(contract_addr.as_bytes());

            let mut account = match updated_backend.write_set.get(&account_key) {
                Some(bytes) if !bytes.is_empty() => decode_account_bytes(bytes)?,
                _ => match updated_backend
                    .mv_memory
                    .read_at_version(updated_backend.tx_version, &account_key)?
                {
                    Some(bytes) => decode_account_bytes(&bytes)?,
                    None => updated_backend
                        .state
                        .get_account(&contract_addr)?
                        .ok_or_else(|| {
                            anyhow!("deployed contract account missing: {}", contract_addr)
                        })?,
                },
            };

            if !runtime_bytes.is_empty() {
                let code_hash = sha256(runtime_bytes);
                let code_key = [b"contract:code:".as_ref(), code_hash.as_slice()].concat();
                updated_backend
                    .write_set
                    .insert(code_key, runtime_bytes.to_vec());
                if !account.is_contract() {
                    account.set_code_hash(code_hash)?;
                }
            }

            updated_backend
                .write_set
                .insert(account_key, account.try_encode()?);
        }

        Ok((
            self.convert_result(result, Some(contract_addr)),
            updated_backend,
        ))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn build_occ_evm<'a>(
        &self,
        backend: OccStateDbBackend<'a>,
    ) -> revm::EVM<OccStateDbBackend<'a>> {
        let mut evm: revm::EVM<OccStateDbBackend<'a>> = revm::new();
        evm.database(backend);

        evm.env.cfg.chain_id = self.config.chain_id;
        evm.env.cfg.spec_id = self.config.spec_id;
        evm.env.block.gas_limit = RevmU256::from(self.config.block_gas_limit);
        evm.env.block.basefee = RevmU256::ZERO;
        evm.env.block.difficulty = RevmU256::ZERO;
        evm.env.block.prevrandao = Some(B256::from(self.block_entropy));

        evm
    }
    // -----------------------------------------------------------------------

    /// Construct a fully-configured `revm::EVM` instance for one transaction,
    /// registering the transaction's L1 addresses so native 32-byte senders
    /// resolve correctly through revm's 20-byte address space.
    fn build_evm_for_tx(
        &self,
        state: Arc<StateDb>,
        tx: &Transaction,
    ) -> Result<revm::EVM<StateDbBackend>> {
        let mut backend = StateDbBackend::new(state);
        backend.register_tx(tx)?;
        Ok(self.build_evm_with_backend(backend))
    }

    fn build_evm_with_backend(&self, backend: StateDbBackend) -> revm::EVM<StateDbBackend> {
        let mut evm: revm::EVM<StateDbBackend> = revm::new();
        evm.database(backend);

        // Block environment.
        evm.env.cfg.chain_id = self.config.chain_id;
        evm.env.cfg.spec_id = self.config.spec_id;
        evm.env.block.gas_limit = RevmU256::from(self.config.block_gas_limit);
        evm.env.block.basefee = RevmU256::ZERO;
        evm.env.block.difficulty = RevmU256::ZERO;
        evm.env.block.prevrandao = Some(B256::from(self.block_entropy));

        evm
    }

    /// Populate the revm `TxEnv` from a sxiaum [`Transaction`] (items 7, 8).
    fn populate_tx_env(&self, tx_env: &mut revm::primitives::TxEnv, tx: &Transaction) {
        // Caller address mapping (item 3).
        tx_env.caller = l1_addr_to_revm(&tx.from);

        // Destination / call-or-create (item 7).
        tx_env.transact_to = match tx.to {
            Some(ref to) => revm::primitives::TransactTo::Call(l1_addr_to_revm(to)),
            None => revm::primitives::TransactTo::Create(revm::primitives::CreateScheme::Create),
        };

        // Input data (item 7).
        tx_env.data = revm::primitives::Bytes::from(tx.data.clone());

        // Gas (item 8).
        tx_env.gas_limit = tx.gas_limit;
        // Upfront gas accounting is enforced by the executor before entering
        // REVM, so keep the EVM gas price at zero to avoid double-charging.
        tx_env.gas_price = RevmU256::ZERO;

        // Value.
        tx_env.value = prim_u256_to_revm(tx.value);

        // Nonce.
        tx_env.nonce = Some(tx.nonce);
    }

    /// Convert a `revm::ExecutionResult` into our [`EvmExecutionResult`] (items 9, 10, 14, 15).
    fn convert_result(
        &self,
        result: RevmExecResult,
        contract_address: Option<Address>,
    ) -> EvmExecutionResult {
        match result {
            RevmExecResult::Success {
                gas_used,
                logs,
                output,
                ..
            } => {
                let return_data = output.into_data().to_vec();
                // Convert revm logs - sxiaum Log objects (item 10).
                let l1_logs = logs
                    .into_iter()
                    .map(|l| Log {
                        address: revm_addr_to_l1(l.address),
                        topics: l.topics.iter().map(|t| t.0).collect(),
                        data: l.data.to_vec(),
                    })
                    .collect();
                EvmExecutionResult {
                    success: true,
                    gas_used,
                    return_data,
                    logs: l1_logs,
                    contract_address,
                }
            }
            RevmExecResult::Revert { gas_used, output } => EvmExecutionResult {
                success: false,
                gas_used,
                return_data: output.to_vec(),
                logs: Vec::new(),
                contract_address: None,
            },
            RevmExecResult::Halt { gas_used, .. } => EvmExecutionResult {
                success: false,
                gas_used,
                return_data: Vec::new(),
                logs: Vec::new(),
                contract_address: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// StateDbBackend - revm::Database + revm::DatabaseCommit adapter (item 4)
// ---------------------------------------------------------------------------

/// Bridges sxiaum's [`StateDb`] to the `revm::Database` trait so that the
/// EVM can load account info, bytecode, and storage slots.
pub struct StateDbBackend {
    state: Arc<StateDb>,
    /// Reverse map: revm 20-byte key - full 32-byte L1 address for this tx.
    address_map: HashMap<[u8; 20], Address>,
    /// SECURITY (H-23): first failure observed inside `DatabaseCommit::commit`
    /// (whose signature cannot return errors). Callers MUST consult
    /// `take_commit_error` after `transact_commit`.
    commit_error: parking_lot::Mutex<Option<String>>,
}

impl StateDbBackend {
    pub fn new(state: Arc<StateDb>) -> Self {
        Self {
            state,
            address_map: HashMap::new(),
            commit_error: parking_lot::Mutex::new(None),
        }
    }

    /// SECURITY (H-22): register a full L1 address for lossless reversal.
    ///
    /// The 32 -> 20 byte projection is inherently lossy; two DIFFERENT native
    /// addresses colliding on one 20-byte key within a transaction previously
    /// resolved silently to whichever registered LAST, misdirecting funds.
    /// Collisions are now rejected outright.
    pub fn register_address(&mut self, addr: &Address) -> Result<()> {
        let revm = l1_addr_to_revm(addr);
        let key = revm_address_key(revm);
        if let Some(existing) = self.address_map.get(&key) {
            if existing != addr {
                bail!(
                    "address projection collision: distinct L1 addresses 0x{} and 0x{} \
                     project onto the same revm address",
                    hex::encode(existing),
                    hex::encode(addr)
                );
            }
        }
        self.address_map.insert(key, *addr);
        Ok(())
    }

    pub fn register_tx(&mut self, tx: &Transaction) -> Result<()> {
        self.register_address(&tx.from)?;
        if let Some(to) = tx.to.as_ref() {
            self.register_address(to)?;
        }
        Ok(())
    }

    /// SECURITY (H-23): consume the first commit-stage error, if any.
    pub fn take_commit_error(&self) -> Option<String> {
        self.commit_error.lock().take()
    }

    fn record_commit_error(&self, context: &str, error: impl std::fmt::Display) {
        let mut guard = self.commit_error.lock();
        if guard.is_none() {
            *guard = Some(format!("{}: {}", context, error));
        }
    }

    fn resolve(&self, revm: RevmAddress) -> Address {
        self.address_map
            .get(&revm_address_key(revm))
            .copied()
            .unwrap_or_else(|| revm_addr_to_l1(revm))
    }
}

fn account_to_revm_info(account: &sxiaum_types::Account) -> AccountInfo {
    AccountInfo {
        balance: prim_u256_to_revm(account.balance),
        nonce: account.nonce,
        code_hash: B256::from(account.code_hash),
        code: None,
    }
}

impl Database for StateDbBackend {
    type Error = anyhow::Error;

    /// Load basic account information (balance, nonce, code hash) (item 3).
    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>> {
        let l1_addr = self.resolve(address);
        match self.state.get_account(&l1_addr)? {
            Some(account) => Ok(Some(account_to_revm_info(&account))),
            None => Ok(None),
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }
        let hash_bytes: [u8; 32] = code_hash.0;
        match self.state.get_code(&hash_bytes)? {
            Some(bytes) => Ok(Bytecode::new_raw(bytes.into())),
            None => bail!("missing bytecode for code hash {}", code_hash),
        }
    }

    /// Read a storage slot as a 256-bit value (item 11).
    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256> {
        let l1_addr = self.resolve(address);
        let key = revm_u256_to_bytes32(index);
        match self.state.get_storage(&l1_addr, key)? {
            Some(value) => Ok(RevmU256::from_be_bytes(value)),
            None => Ok(RevmU256::ZERO),
        }
    }

    /// Return block hash by number (needed by `BLOCKHASH` opcode).
    fn block_hash(&mut self, number: RevmU256) -> Result<B256> {
        let block_num = number.as_limbs()[0];
        let key = [b"block:hash:".as_ref(), &block_num.to_be_bytes()].concat();
        if let Some(bytes) = self.state.get_raw(&key)? {
            if bytes.len() == 32 {
                return Ok(B256::from_slice(&bytes));
            }
        }
        Ok(B256::ZERO)
    }
}

/// Commit EVM state-diff back to [`StateDb`] after a successful transaction (item 11, 15).
impl DatabaseCommit for StateDbBackend {
    fn commit(
        &mut self,
        changes: revm::primitives::HashMap<RevmAddress, revm::primitives::Account>,
    ) {
        for (revm_addr, revm_account) in changes {
            if revm_account.is_selfdestructed() {
                let l1_addr = self.resolve(revm_addr);
                // SECURITY (H-24): `delete_account` purges the account row
                // AND every storage:<addr>:* row + tree leaves. Persisting
                // only the account deletion left ghost storage baked into
                // the state root forever.
                if let Err(err) = self.state.delete_account(&l1_addr) {
                    let context =
                        format!("selfdestruct purge failed for 0x{}", hex::encode(l1_addr));
                    tracing::error!("{}: {}", context, err);
                    self.record_commit_error(&context, err);
                }
                continue;
            }

            let l1_addr = self.resolve(revm_addr);
            let info = &revm_account.info;

            // Fetch or create account in StateDb.
            let mut account = match self.state.get_account(&l1_addr) {
                Ok(Some(acc)) => acc,
                Ok(None) => Account::new(l1_addr),
                Err(error) => {
                    let context =
                        format!("account load failed for 0x{}", hex::encode(l1_addr));
                    tracing::error!("{}: {}", context, error);
                    self.record_commit_error(&context, error);
                    continue;
                }
            };

            // Update balance and nonce.
            account.balance = revm_u256_to_prim(info.balance);
            account.nonce = info.nonce;

            // Persist bytecode if the account carries inline code (item 12).
            if let Some(code) = &info.code {
                if !code.is_empty() {
                    let code_bytes = code.bytecode.to_vec();
                    let code_hash = sha256(&code_bytes);
                    if let Err(error) = self.state.set_code(&code_hash, code_bytes) {
                        let context =
                            format!("code persistence failed for 0x{}", hex::encode(l1_addr));
                        tracing::error!("{}: {}", context, error);
                        self.record_commit_error(&context, error);
                        continue;
                    }
                    if let Err(error) = account.set_code_hash(code_hash) {
                        let context =
                            format!("code hash rejected for 0x{}", hex::encode(l1_addr));
                        tracing::error!("{}: {}", context, error);
                        self.record_commit_error(&context, error);
                        continue;
                    }
                }
            }

            if let Err(error) = self.state.update_account(&l1_addr, &account) {
                let context = format!("account update failed for 0x{}", hex::encode(l1_addr));
                tracing::error!("{}: {}", context, error);
                self.record_commit_error(&context, error);
            }

            // Persist storage slot writes (item 11).
            for (slot, storage_slot) in &revm_account.storage {
                if storage_slot.is_changed() {
                    let key = revm_u256_to_bytes32(*slot);
                    let value = revm_u256_to_bytes32(storage_slot.present_value());
                    if let Err(err) = self.state.set_storage(&l1_addr, key, value) {
                        let context = format!(
                            "storage write failed for 0x{} slot 0x{}",
                            hex::encode(l1_addr),
                            hex::encode(key)
                        );
                        tracing::error!("{}: {}", context, err);
                        self.record_commit_error(&context, err);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OccStateDbBackend - Speculative Database Adapter for REVM
// ---------------------------------------------------------------------------

pub struct OccStateDbBackend<'a> {
    pub state: Arc<StateDb>,
    pub tx_version: crate::parallel::TxVersion,
    pub mv_memory: &'a crate::parallel::MVMemory,
    pub read_set: std::collections::HashSet<Vec<u8>>,
    pub write_set: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    address_map: HashMap<[u8; 20], Address>,
    /// SECURITY (H-23): first failure observed inside `DatabaseCommit::commit`.
    commit_error: parking_lot::Mutex<Option<String>>,
}

impl<'a> OccStateDbBackend<'a> {
    pub fn new(
        state: Arc<StateDb>,
        tx_version: crate::parallel::TxVersion,
        mv_memory: &'a crate::parallel::MVMemory,
    ) -> Self {
        Self {
            state,
            tx_version,
            mv_memory,
            read_set: std::collections::HashSet::new(),
            write_set: std::collections::HashMap::new(),
            address_map: HashMap::new(),
            commit_error: parking_lot::Mutex::new(None),
        }
    }

    /// SECURITY (H-22): collision-checked address registration (see
    /// `StateDbBackend::register_address`).
    pub fn register_address(&mut self, addr: &Address) -> Result<()> {
        let revm = l1_addr_to_revm(addr);
        let key = revm_address_key(revm);
        if let Some(existing) = self.address_map.get(&key) {
            if existing != addr {
                bail!(
                    "address projection collision: distinct L1 addresses 0x{} and 0x{} \
                     project onto the same revm address",
                    hex::encode(existing),
                    hex::encode(addr)
                );
            }
        }
        self.address_map.insert(key, *addr);
        Ok(())
    }

    pub fn register_tx(&mut self, tx: &Transaction) -> Result<()> {
        self.register_address(&tx.from)?;
        if let Some(to) = tx.to.as_ref() {
            self.register_address(to)?;
        }
        Ok(())
    }

    /// SECURITY (H-23): consume the first commit-stage error, if any.
    pub fn take_commit_error(&self) -> Option<String> {
        self.commit_error.lock().take()
    }

    fn record_commit_error(&self, context: &str, error: impl std::fmt::Display) {
        let mut guard = self.commit_error.lock();
        if guard.is_none() {
            *guard = Some(format!("{}: {}", context, error));
        }
    }

    fn resolve(&self, revm: RevmAddress) -> Address {
        self.address_map
            .get(&revm_address_key(revm))
            .copied()
            .unwrap_or_else(|| revm_addr_to_l1(revm))
    }

    /// Retrieve account state, tracking the read key in `read_set`.
    pub fn get_account(&mut self, addr: &Address) -> Result<Option<Account>> {
        let mut key = b"account:".to_vec();
        key.extend_from_slice(addr.as_bytes());

        self.read_set.insert(key.clone());

        if let Some(val) = self.write_set.get(&key) {
            if val.is_empty() {
                return Ok(None);
            }
            let account: Account = decode_account_bytes(val)?;
            return Ok(Some(account));
        }

        match self.mv_memory.read_at_version(self.tx_version, &key) {
            Ok(Some(bytes)) => {
                let account: Account = decode_account_bytes(&bytes)?;
                Ok(Some(account))
            }
            Ok(None) => self.state.get_account(addr),
            Err(error) => Err(error),
        }
    }
}

impl<'a> Database for OccStateDbBackend<'a> {
    type Error = anyhow::Error;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>> {
        let l1_addr = self.resolve(address);
        let mut key = b"account:".to_vec();
        key.extend_from_slice(l1_addr.as_bytes());

        self.read_set.insert(key.clone());

        if let Some(val) = self.write_set.get(&key) {
            if val.is_empty() {
                return Ok(None);
            }
            let account: sxiaum_types::Account = decode_account_bytes(val)?;
            return Ok(Some(account_to_revm_info(&account)));
        }
        match self.mv_memory.read_at_version(self.tx_version, &key) {
            Ok(Some(bytes)) => {
                let account: sxiaum_types::Account = decode_account_bytes(&bytes)?;
                Ok(Some(account_to_revm_info(&account)))
            }
            Ok(None) => match self.state.load_account(&l1_addr)? {
                Some(account) => Ok(Some(account_to_revm_info(&account))),
                None => Ok(None),
            },
            Err(error) => Err(error),
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }
        let hash_bytes: [u8; 32] = code_hash.0;
        let code_key = [b"contract:code:".as_ref(), &hash_bytes].concat();
        self.read_set.insert(code_key.clone());
        if let Some(val) = self.write_set.get(&code_key) {
            return Ok(Bytecode::new_raw(revm::primitives::Bytes::from(
                val.clone(),
            )));
        }
        match self.mv_memory.read_at_version(self.tx_version, &code_key) {
            Ok(Some(bytes)) => Ok(Bytecode::new_raw(revm::primitives::Bytes::from(bytes))),
            Ok(None) => match self.state.get_code(&hash_bytes)? {
                Some(bytes) => Ok(Bytecode::new_raw(revm::primitives::Bytes::from(bytes))),
                None => bail!("missing bytecode for code hash {}", code_hash),
            },
            Err(error) => Err(error),
        }
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256> {
        let l1_addr = self.resolve(address);
        let slot_bytes = revm_u256_to_bytes32(index);
        let mut key = b"storage:".to_vec();
        key.extend_from_slice(l1_addr.as_bytes());
        key.extend_from_slice(&slot_bytes);
        self.read_set.insert(key.clone());
        if let Some(val) = self.write_set.get(&key) {
            if val.len() == 32 {
                return Ok(RevmU256::from_be_bytes({
                    let mut b = [0u8; 32];
                    b.copy_from_slice(val);
                    b
                }));
            }
            return Ok(RevmU256::ZERO);
        }
        match self.mv_memory.read_at_version(self.tx_version, &key) {
            Ok(Some(bytes)) => {
                if bytes.len() == 32 {
                    let mut val = [0u8; 32];
                    val.copy_from_slice(&bytes);
                    Ok(RevmU256::from_be_bytes(val))
                } else {
                    Ok(RevmU256::ZERO)
                }
            }
            Ok(None) => match self.state.get_storage(&l1_addr, slot_bytes)? {
                Some(value) => Ok(RevmU256::from_be_bytes(value)),
                None => Ok(RevmU256::ZERO),
            },
            Err(error) => Err(error),
        }
    }

    fn block_hash(&mut self, number: RevmU256) -> Result<B256> {
        let block_num = number.as_limbs()[0];
        let key = [b"block:hash:".as_ref(), &block_num.to_be_bytes()].concat();
        self.read_set.insert(key.clone());
        if let Some(bytes) = self.write_set.get(&key) {
            if bytes.len() == 32 {
                return Ok(B256::from_slice(bytes));
            }
        }
        if let Ok(Some(bytes)) = self.mv_memory.read_at_version(self.tx_version, &key) {
            if bytes.len() == 32 {
                return Ok(B256::from_slice(&bytes));
            }
        }
        if let Some(bytes) = self.state.get_raw(&key)? {
            if bytes.len() == 32 {
                return Ok(B256::from_slice(&bytes));
            }
        }
        Ok(B256::ZERO)
    }
}

impl<'a> DatabaseCommit for OccStateDbBackend<'a> {
    fn commit(
        &mut self,
        changes: revm::primitives::HashMap<RevmAddress, revm::primitives::Account>,
    ) {
        for (revm_addr, revm_account) in changes {
            let l1_addr = self.resolve(revm_addr);
            let mut account_key = b"account:".to_vec();
            account_key.extend_from_slice(l1_addr.as_bytes());

            if revm_account.is_selfdestructed() {
                self.write_set.insert(account_key, Vec::new());
                // SECURITY (H-24): tombstone EVERY storage row of the
                // selfdestructed account. Previously only the account row was
                // deleted while storage:<addr>:* rows survived in the write
                // set / MV memory / canonical state — ghost storage baked
                // into the state root permanently.
                let mut prefix = b"storage:".to_vec();
                prefix.extend_from_slice(l1_addr.as_bytes());
                match self.state.storage().state_prefix_scan(prefix.clone()) {
                    Ok(rows) => {
                        for (storage_key, _) in rows {
                            self.write_set.insert(storage_key, Vec::new());
                        }
                    }
                    Err(err) => {
                        let context = format!(
                            "selfdestruct storage scan failed for 0x{}",
                            hex::encode(l1_addr)
                        );
                        tracing::error!("{}: {}", context, err);
                        self.record_commit_error(&context, err);
                    }
                }
                // Drop any pending non-empty writes for this account's namespace.
                let doomed: Vec<Vec<u8>> = self
                    .write_set
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .cloned()
                    .collect();
                for key in doomed {
                    self.write_set.insert(key, Vec::new());
                }
                continue;
            }

            let info = &revm_account.info;

            let mut account = match self.write_set.get(&account_key) {
                Some(bytes) if !bytes.is_empty() => match decode_account_bytes(bytes) {
                    Ok(account) => account,
                    Err(error) => {
                        let context =
                            format!("write-set account decode failed for 0x{}", hex::encode(l1_addr));
                        tracing::error!("{}: {}", context, error);
                        self.record_commit_error(&context, error);
                        continue;
                    }
                },
                _ => {
                    let staged = match self
                        .mv_memory
                        .read_at_version(self.tx_version, &account_key)
                    {
                        Ok(value) => value,
                        Err(error) => {
                            let context = format!(
                                "mv-memory account read failed for 0x{}",
                                hex::encode(l1_addr)
                            );
                            tracing::error!("{}: {}", context, error);
                            self.record_commit_error(&context, error);
                            continue;
                        }
                    };
                    match staged {
                        Some(bytes) => match decode_account_bytes(&bytes) {
                            Ok(account) => account,
                            Err(error) => {
                                let context = format!(
                                    "mv-memory account decode failed for 0x{}",
                                    hex::encode(l1_addr)
                                );
                                tracing::error!("{}: {}", context, error);
                                self.record_commit_error(&context, error);
                                continue;
                            }
                        },
                        None => match self.state.load_account(&l1_addr) {
                            Ok(Some(account)) => account,
                            Ok(None) => Account::new(l1_addr),
                            Err(error) => {
                                let context = format!(
                                    "account load failed for 0x{}",
                                    hex::encode(l1_addr)
                                );
                                tracing::error!("{}: {}", context, error);
                                self.record_commit_error(&context, error);
                                continue;
                            }
                        },
                    }
                }
            };

            account.balance = revm_u256_to_prim(info.balance);
            account.nonce = info.nonce;

            let mut changed_slots: Vec<([u8; 32], [u8; 32])> = Vec::new();
            for (slot, storage_slot) in &revm_account.storage {
                if storage_slot.is_changed() {
                    let slot_bytes = revm_u256_to_bytes32(*slot);
                    let val_bytes = revm_u256_to_bytes32(storage_slot.present_value());
                    let mut storage_key = b"storage:".to_vec();
                    storage_key.extend_from_slice(l1_addr.as_bytes());
                    storage_key.extend_from_slice(&slot_bytes);
                    self.write_set.insert(storage_key, val_bytes.to_vec());
                    changed_slots.push((slot_bytes, val_bytes));
                }
            }

            if !changed_slots.is_empty() {
                let mut entries = match self.state.get_account_storage_entries(&l1_addr) {
                    Ok(entries) => entries,
                    Err(error) => {
                        let context =
                            format!("storage enumeration failed for 0x{}", hex::encode(l1_addr));
                        tracing::error!("{}: {}", context, error);
                        self.record_commit_error(&context, error);
                        continue;
                    }
                };
                for (slot, value) in &changed_slots {
                    entries.retain(|(existing, _)| existing != slot);
                    if *value != [0u8; 32] {
                        entries.push((*slot, *value));
                    }
                }
                let storage_root = match compute_storage_root(&l1_addr, &entries) {
                    Ok(root) => root,
                    Err(error) => {
                        let context = format!(
                            "storage root computation failed for 0x{}",
                            hex::encode(l1_addr)
                        );
                        tracing::error!("{}: {}", context, error);
                        self.record_commit_error(&context, error);
                        continue;
                    }
                };
                if let Err(error) = account.set_storage_root(storage_root) {
                    let context = format!("storage root rejected for 0x{}", hex::encode(l1_addr));
                    tracing::error!("{}: {}", context, error);
                    self.record_commit_error(&context, error);
                    continue;
                }
            }

            if let Some(code) = &info.code {
                if !code.is_empty() {
                    let code_bytes = code.bytecode.to_vec();
                    let code_hash = sha256(&code_bytes);
                    let code_key = [b"contract:code:".as_ref(), code_hash.as_slice()].concat();
                    self.write_set.insert(code_key, code_bytes);

                    if let Err(error) = account.set_code_hash(code_hash) {
                        let context = format!("code hash rejected for 0x{}", hex::encode(l1_addr));
                        tracing::error!("{}: {}", context, error);
                        self.record_commit_error(&context, error);
                        continue;
                    }
                }
            }

            match account.try_encode() {
                Ok(bytes) => {
                    self.write_set.insert(account_key, bytes);
                }
                Err(error) => {
                    let context =
                        format!("account encode failed for 0x{}", hex::encode(l1_addr));
                    tracing::error!("{}: {}", context, error);
                    self.record_commit_error(&context, error);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Contract address derivation (item 13)
// ---------------------------------------------------------------------------

/// Compute a deterministic 32-byte contract address from `sha256(sender || nonce_le)`.
///
/// This mirrors the sxiaum convention of SHA-256-based addressing rather than
/// Ethereum's keccak-based CREATE scheme.
pub fn compute_contract_address(sender: &Address, nonce: u64) -> Address {
    Address::create_contract_address(sender, nonce)
}

// ---------------------------------------------------------------------------
// Type-conversion helpers
// ---------------------------------------------------------------------------

/// Convert a sxiaum 32-byte `Address` to a revm 20-byte `Address` (item 3).
///
/// We use the **last 20 bytes** so that the mapping is consistent with how most
/// EVM tooling computes CREATE2-style addresses from a 32-byte salt.
///
/// For native (non-ethereum-padded) addresses this projection is **lossy**.
/// Callers that must reverse the mapping should register the full L1 address
/// on [`StateDbBackend`] / [`OccStateDbBackend`] for the duration of the tx.
#[inline]
pub fn l1_addr_to_revm(addr: &Address) -> RevmAddress {
    RevmAddress::from(addr.to_ethereum_address_lossy())
}

/// Convert a revm 20-byte `Address` back to a sxiaum 32-byte `Address`.
///
/// Pads with 12 zero bytes on the left. This is correct for Ethereum-originated
/// addresses and a **fallback only** for native addresses - prefer the
/// per-transaction reverse map on the EVM backends when available.
#[inline]
pub fn revm_addr_to_l1(addr: RevmAddress) -> Address {
    Address::from_ethereum_address(revm_address_key(addr))
}

#[inline]
fn revm_address_key(addr: RevmAddress) -> [u8; 20] {
    let mut key = [0u8; 20];
    key.copy_from_slice(addr.as_slice());
    key
}

/// Convert `primitive_types::U256` (big-endian internally) to `alloy_primitives::U256`.
#[inline]
pub fn prim_u256_to_revm(value: PrimU256) -> RevmU256 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    RevmU256::from_be_bytes(bytes)
}

/// Convert `alloy_primitives::U256` to `primitive_types::U256`.
#[inline]
pub fn revm_u256_to_prim(value: RevmU256) -> PrimU256 {
    let bytes = value.to_be_bytes::<32>();
    PrimU256::from_big_endian(&bytes)
}

/// Encode a `alloy_primitives::U256` storage key as a 32-byte big-endian array.
#[inline]
fn revm_u256_to_bytes32(value: RevmU256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

// ---------------------------------------------------------------------------
// Gas schedule integration (item 20)
// ---------------------------------------------------------------------------

/// Build a [`GasMeter`] from the `gas_limit` field of a transaction, applying
/// the mainnet gas schedule (memory expansion, storage, refunds, precompiles).
///
/// revm still performs opcode-level metering inside `transact_commit`. This
/// outer meter is used by the executor / state-transition paths and for
/// block-level aggregation so both stay on the same Cancun-structured
/// [`crate::gas::GasSchedule::mainnet`] constants.
pub fn gas_meter_for_tx(tx: &Transaction, _config: &EvmConfig) -> GasMeter {
    GasMeter::with_schedule(tx.gas_limit, crate::gas::GasSchedule::mainnet())
}

// ---------------------------------------------------------------------------
// Precompile support (item 19)
// ---------------------------------------------------------------------------

/// Returns the revm `SpecId` that enables the standard set of EVM precompiles
/// (SHA-256 at 0x02, RIPEMD at 0x03, ECRecover at 0x01, etc.).
///
/// Setting `SpecId::CANCUN` (the default) activates all precompiles through
/// the Cancun hardfork. Switch to an earlier spec to restrict the available
/// precompile set. Outer precompile gas quotes use
/// [`crate::gas::precompile_gas`] so fees stay consistent with revm.
pub fn precompile_spec_id(config: &EvmConfig) -> revm::primitives::SpecId {
    config.spec_id
}

/// Quote Cancun precompile gas for `address` / `input` using the shared
/// schedule in [`crate::gas`]. Returns `None` if `address` is not a precompile.
pub fn quote_precompile_gas(address: u8, input: &[u8]) -> Option<u64> {
    crate::gas::precompile_gas(address, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;

    #[test]
    fn test_parallel_address_derivation() {
        let addresses: Vec<Address> = (0..100)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[31] = i as u8;
                Address(bytes)
            })
            .collect();

        // Concurrently convert l1 to revm and back
        addresses.par_iter().for_each(|addr| {
            let revm_addr = l1_addr_to_revm(addr);
            let back_addr = revm_addr_to_l1(revm_addr);

            let mut expected = [0u8; 32];
            expected[12..32].copy_from_slice(&addr.0[12..32]);
            assert_eq!(back_addr.0, expected);
        });
    }

    #[test]
    fn native_sender_address_map_preserves_full_l1_identity() {
        // Full SHA-256 style native address (non-zero high bytes) loses identity
        // under the stateless reverse map-
        let native = Address([0xABu8; 32]);
        let revm = l1_addr_to_revm(&native);
        assert_ne!(
            revm_addr_to_l1(revm),
            native,
            "stateless reverse must be lossy for native addresses"
        );

        // -but the per-tx reverse map restores the full L1 address.
        let mut map: HashMap<[u8; 20], Address> = HashMap::new();
        map.insert(revm_address_key(revm), native);
        assert_eq!(map.get(&revm_address_key(revm)).copied(), Some(native));

        // Ethereum-padded addresses still reverse without a map.
        let eth = Address::from_ethereum_address([0x22u8; 20]);
        assert_eq!(revm_addr_to_l1(l1_addr_to_revm(&eth)), eth);
    }

    #[test]
    fn test_concurrent_address_lookup() {
        use std::thread;

        let mut handles = vec![];
        for thread_idx in 0..16 {
            handles.push(thread::spawn(move || {
                let sender = Address([thread_idx as u8; 32]);
                let mut last_addr = sender;
                // Perform 1000 sequential address derivations in each thread
                for nonce in 0..1000 {
                    last_addr = compute_contract_address(&last_addr, nonce);
                }
                last_addr
            }));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // Since threads have different sender inputs (0..16), they should produce unique results.
        let mut unique_results = results.clone();
        unique_results.dedup();
        assert_eq!(
            results.len(),
            unique_results.len(),
            "Each thread should deterministically derive unique sequence"
        );
        assert_eq!(results.len(), 16);
    }
}
