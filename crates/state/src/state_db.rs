use crate::node::VerkleNode;
use crate::proof::{storage_proof_key, RpcVerkleProof, VerkleProof};
use crate::verkle_tree::VerkleTree;
use anyhow::{bail, Result};
use parking_lot::Mutex;
use primitive_types::U256;
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use sxiaum_block::Block;
use sxiaum_storage::DatabaseBackend;
use sxiaum_types::vesting::VestingSchedule;
use sxiaum_types::{
    compute_storage_root, Account, AccountError, Address, Canonical, Transaction, TxError,
};

type HistoricalState = (VerkleTree, HashMap<Vec<u8>, Vec<u8>>, [u8; 32]);

fn decode_account(bytes: &[u8]) -> Result<Account> {
    let account = Account::decode(bytes)?;
    account.validate()?;
    Ok(account)
}
fn keccak256_bytes(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let digest = sha3::Keccak256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

const ACCOUNT_PREFIX: &[u8] = b"account:";
const STORAGE_PREFIX: &[u8] = b"storage:";
const VESTING_PREFIX: &[u8] = b"vesting:";
const CONTRACT_CODE_PREFIX: &[u8] = b"contract:code:";
const STATE_ROOT_KEY: &[u8] = b"metadata:state_root";
const SNAPSHOT_META_PREFIX: &[u8] = b"snapshot:meta:";
const SNAPSHOT_FULL_PREFIX: &[u8] = b"snapshot:full:";
const SNAPSHOT_INCREMENTAL_PREFIX: &[u8] = b"snapshot:incremental:";
const SNAPSHOT_ROOT_SUFFIX: &[u8] = b":root";
const SNAPSHOT_TREE_SUFFIX: &[u8] = b":tree";
const SNAPSHOT_BASE_SUFFIX: &[u8] = b":base";
const SNAPSHOT_TYPE_SUFFIX: &[u8] = b":type";
const SNAPSHOT_KEY_PREFIX: &[u8] = b":key:";
const SNAPSHOT_TOMBSTONE: &[u8] = b"__deleted__";
const SNAPSHOT_RETAIN_COUNT: usize = 8;
pub const MAX_VERKLE_PROOF_DEPTH: usize = 32;

#[derive(Clone, Debug)]
pub struct ReadOnlyStateSnapshot {
    pub root: [u8; 32],
    pub revision: u64,
}

#[derive(Clone, Debug)]
pub enum StateBatchOp {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// A single staged raw-row write: key with `None` meaning delete.
pub type DeferredWrite = (Vec<u8>, Option<Vec<u8>>);
/// Buffered raw-row writes staged for one atomic batch flush.
pub type DeferredWrites = Vec<DeferredWrite>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PruningMode {
    #[default]
    Archive, // Keeps everything forever
    Pruned(u64), // Keeps only the last N state revisions
    Minimal,
}

pub struct StateDb {
    storage: Arc<dyn DatabaseBackend>,
    tree: Mutex<VerkleTree>,
    committed_tree: Mutex<VerkleTree>,
    undo_log: Mutex<HashMap<Vec<u8>, Option<Vec<u8>>>>,
    dirty_keys: Mutex<BTreeSet<Vec<u8>>>,
    key_versions: Mutex<HashMap<Vec<u8>, u64>>,
    node_cache: Mutex<HashMap<[u8; 32], VerkleNode>>,
    revision: AtomicU64,
    pruning_mode: PruningMode,
    /// SECURITY (H-20): buffered raw-row writes for pipeline execution over
    /// LIVE storage. Rows staged here are invisible to other readers until
    /// `flush_staged_writes` lands them in ONE atomic batch, so a crash
    /// mid-block can no longer leave half-applied foreign rows behind.
    deferred_writes: Mutex<DeferredWrites>,
}

impl StateDb {
    pub fn new(storage: Arc<dyn DatabaseBackend>) -> Self {
        Self::with_pruning(storage, PruningMode::Archive)
    }

    pub fn with_pruning(storage: Arc<dyn DatabaseBackend>, pruning_mode: PruningMode) -> Self {
        let tree = VerkleTree::new();
        Self {
            storage,
            tree: Mutex::new(tree.clone()),
            committed_tree: Mutex::new(tree),
            undo_log: Mutex::new(HashMap::new()),
            dirty_keys: Mutex::new(BTreeSet::new()),
            key_versions: Mutex::new(HashMap::new()),
            node_cache: Mutex::new(HashMap::new()),
            revision: AtomicU64::new(0),
            pruning_mode,
            deferred_writes: Mutex::new(Vec::new()),
        }
    }

    pub fn storage(&self) -> Arc<dyn DatabaseBackend> {
        Arc::clone(&self.storage)
    }

    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        self.load_account(address)
    }

    pub fn get_balance(&self, address: &Address) -> Result<U256> {
        Ok(self
            .load_account(address)?
            .map(|account| account.balance)
            .unwrap_or_else(U256::zero))
    }

    pub fn get_nonce(&self, address: &Address) -> Result<u64> {
        Ok(self
            .load_account(address)?
            .map(|account| account.nonce)
            .unwrap_or(0))
    }

    pub fn get_storage(&self, address: &Address, key: [u8; 32]) -> Result<Option<[u8; 32]>> {
        let storage_key = Self::storage_key(address, &key);
        match self.storage.state_get(storage_key)? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    bail!("corrupt storage value length");
                }
                let mut value = [0u8; 32];
                value.copy_from_slice(&bytes);
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub fn account_exists(&self, address: &Address) -> Result<bool> {
        Ok(self.load_account(address)?.is_some())
    }

    pub fn load_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = Self::account_key(address);
        if let Some(bytes) = self.storage.state_get(key)? {
            return Ok(Some(decode_account(&bytes)?));
        }
        Ok(None)
    }

    pub fn get_vesting_schedule(&self, address: &Address) -> Result<Option<VestingSchedule>> {
        let key = Self::vesting_key(address);
        match self.storage.state_get(key)? {
            Some(v) => {
                let schedule = VestingSchedule::decode(&v)?;
                schedule.validate()?;
                Ok(Some(schedule))
            }
            None => Ok(None),
        }
    }

    pub fn set_vesting_schedule(&self, address: &Address, schedule: VestingSchedule) -> Result<()> {
        schedule.validate()?;
        let key = Self::vesting_key(address);
        self.mark_dirty(key.clone())?;
        let bytes = schedule.try_encode()?;
        self.storage.state_put(key.clone(), bytes)?;
        self.bump_key_version(key);
        Ok(())
    }

    pub fn update_account(&self, address: &Address, account: &Account) -> Result<()> {
        account.validate()?;
        if account.address != *address {
            bail!("account address mismatch");
        }
        let key = Self::account_key(address);
        self.mark_dirty(key.clone())?;
        let bytes = account.try_encode()?;
        self.storage.state_put(key.clone(), bytes)?;
        self.bump_key_version(key);

        let mut tree = self.tree.lock();
        let account_hash = account.try_hash()?;
        if tree.get(*address.as_bytes())?.is_some() {
            tree.update(*address.as_bytes(), account_hash)?;
        } else {
            tree.insert(*address.as_bytes(), account_hash)?;
        }

        Ok(())
    }

    pub fn create_account(&self, address: Address) -> Result<Account> {
        if let Some(account) = self.load_account(&address)? {
            return Ok(account);
        }

        let account = Account::new(address);
        self.update_account(&address, &account)?;
        Ok(account)
    }

    pub fn set_balance(&self, address: &Address, amount: U256) -> Result<()> {
        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        account.balance = amount;
        account.validate()?;
        self.update_account(address, &account)
    }

    pub fn increment_nonce(&self, address: &Address) -> Result<u64> {
        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        account.checked_increment_nonce()?;
        let nonce = account.nonce;
        self.update_account(address, &account)?;
        Ok(nonce)
    }

    pub fn set_storage(&self, address: &Address, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        let storage_key = Self::storage_key(address, &key);
        self.mark_dirty(storage_key.clone())?;

        let tree_key = storage_proof_key(address, &key);
        let mut tree = self.tree.lock();
        if value == [0u8; 32] {
            self.storage
                .atomic_state_commit(vec![(storage_key.clone(), None)])?;
            if tree.get(tree_key)?.is_some() {
                tree.delete(tree_key)?;
            }
        } else {
            self.storage
                .state_put(storage_key.clone(), value.to_vec())?;
            if tree.get(tree_key)?.is_some() {
                tree.update(tree_key, value)?;
            } else {
                tree.insert(tree_key, value)?;
            }
        }
        drop(tree);
        self.bump_key_version(storage_key);

        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        let entries = self.get_account_storage_entries(address)?;
        account.set_storage_root(compute_storage_root(address, &entries)?)?;
        self.update_account(address, &account)
    }

    pub fn delete_storage(&self, address: &Address, key: [u8; 32]) -> Result<()> {
        self.set_storage(address, key, [0u8; 32])
    }

    pub fn get_account_storage_entries(
        &self,
        address: &Address,
    ) -> Result<Vec<([u8; 32], [u8; 32])>> {
        let mut storage_prefix = Vec::with_capacity(STORAGE_PREFIX.len() + 32);
        storage_prefix.extend_from_slice(STORAGE_PREFIX);
        storage_prefix.extend_from_slice(address.as_bytes());

        let mut entries = Vec::new();
        for (storage_key, value) in self.storage.state_prefix_scan(storage_prefix)? {
            if storage_key.len() == STORAGE_PREFIX.len() + 64 {
                if value.len() != 32 {
                    bail!("corrupt storage value length");
                }
                let mut slot = [0u8; 32];
                slot.copy_from_slice(&storage_key[STORAGE_PREFIX.len() + 32..]);
                let mut slot_val = [0u8; 32];
                slot_val.copy_from_slice(&value);
                entries.push((slot, slot_val));
            }
        }
        Ok(entries)
    }

    pub fn get_code(&self, code_hash: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let mut key = Vec::with_capacity(CONTRACT_CODE_PREFIX.len() + 32);
        key.extend_from_slice(CONTRACT_CODE_PREFIX);
        key.extend_from_slice(code_hash);
        self.storage.state_get(key)
    }

    pub fn set_code(&self, code_hash: &[u8; 32], code: Vec<u8>) -> Result<()> {
        if code.is_empty() {
            bail!("contract code must not be empty");
        }
        if code.len() > 24576 {
            bail!("contract code exceeds maximum size");
        }
        if code_hash == &[0u8; 32] {
            bail!("invalid code hash");
        }
        let mut key = Vec::with_capacity(CONTRACT_CODE_PREFIX.len() + 32);
        key.extend_from_slice(CONTRACT_CODE_PREFIX);
        key.extend_from_slice(code_hash);
        self.mark_dirty(key.clone())?;
        self.storage.state_put(key.clone(), code)?;
        self.bump_key_version(key);
        Ok(())
    }

    pub fn get_code_by_address(&self, address: &Address) -> Result<Option<Vec<u8>>> {
        let account = match self.load_account(address)? {
            Some(acc) => acc,
            None => return Ok(None),
        };
        if !account.is_contract() {
            return Ok(None);
        }
        self.get_code(&account.code_hash)
    }

    pub fn set_code_for_address(&self, address: &Address, code: Vec<u8>) -> Result<[u8; 32]> {
        if code.is_empty() {
            bail!("contract code must not be empty");
        }
        if code.len() > 24576 {
            bail!("contract code exceeds maximum size");
        }
        let code_hash = keccak256_bytes(&code);
        self.set_code(&code_hash, code)?;
        let mut account = self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address));
        account.set_code_hash(code_hash)?;
        self.update_account(address, &account)?;
        Ok(code_hash)
    }

    pub fn delete_account(&self, address: &Address) -> Result<()> {
        let account_key = Self::account_key(address);
        self.mark_dirty(account_key.clone())?;
        let mut changes = vec![(account_key.clone(), None)];
        self.bump_key_version(account_key);

        // Delete all storage entries associated with this account
        let mut storage_prefix = Vec::with_capacity(STORAGE_PREFIX.len() + 32);
        storage_prefix.extend_from_slice(STORAGE_PREFIX);
        storage_prefix.extend_from_slice(address.as_bytes());

        let mut tree = self.tree.lock();
        for (storage_key, _) in self.storage.state_prefix_scan(storage_prefix)? {
            if storage_key.len() == STORAGE_PREFIX.len() + 64 {
                let mut slot = [0u8; 32];
                slot.copy_from_slice(&storage_key[STORAGE_PREFIX.len() + 32..]);
                let tree_key = storage_proof_key(address, &slot);
                if tree.get(tree_key)?.is_some() {
                    tree.delete(tree_key)?;
                }
            }
            self.mark_dirty(storage_key.clone())?;
            changes.push((storage_key, None));
        }

        // Delete vesting schedule if present
        let vesting_key = Self::vesting_key(address);
        if self.storage.state_get(vesting_key.clone())?.is_some() {
            self.mark_dirty(vesting_key.clone())?;
            changes.push((vesting_key.clone(), None));
            self.bump_key_version(vesting_key);
        }

        self.storage.atomic_state_commit(changes)?;

        if tree.get(*address.as_bytes())?.is_some() {
            tree.delete(*address.as_bytes())?;
        }

        Ok(())
    }

    pub fn apply_transaction(&self, tx: &Transaction) -> Result<()> {
        self.state_transition(tx).map(|_| ())
    }

    pub fn apply_block(&self, block: &Block) -> Result<[u8; 32]> {
        block.validate_basic()?;

        for tx in &block.body.transactions {
            if let Err(e) = self.apply_transaction(tx) {
                let _ = self.rollback();
                return Err(e);
            }
        }

        self.update_state_root()
    }

    pub fn state_transition(&self, transaction: &Transaction) -> Result<[u8; 32]> {
        transaction.validate_basic()?;

        let tx_hash = transaction.try_hash()?;

        let mut sender = self
            .load_account(&transaction.from)?
            .unwrap_or_else(|| Account::new(transaction.from));
        self.validate_state_transition_checks(transaction, &sender)?;

        self.deduct_gas(&mut sender, transaction)?;
        sender.checked_sub_balance(transaction.value)?;
        sender.checked_increment_nonce()?;
        sender.validate()?;

        if let Some(recipient_address) = transaction.to {
            let mut recipient =
                self.plan_counterparty(&recipient_address, &transaction.from, &sender)?;
            let staged_storage = if transaction.is_contract_call() {
                Some((keccak256_bytes(&transaction.data), tx_hash))
            } else {
                None
            };

            self.apply_balance_update(&mut recipient, transaction.value)?;
            recipient.validate()?;

            self.update_account(&transaction.from, &sender)?;
            self.update_account(&recipient_address, &recipient)?;
            if let Some((storage_key, storage_value)) = staged_storage {
                self.set_storage(&recipient_address, storage_key, storage_value)?;
            }
        } else {
            let contract_address =
                Address::create_contract_address(&transaction.from, transaction.nonce);
            let mut contract =
                self.plan_counterparty(&contract_address, &transaction.from, &sender)?;
            self.apply_balance_update(&mut contract, transaction.value)?;
            let code_hash = keccak256_bytes(&transaction.data);
            contract.set_code_hash(code_hash)?;
            contract.validate()?;

            self.update_account(&transaction.from, &sender)?;
            self.set_code(&code_hash, transaction.data.clone())?;
            self.update_account(&contract_address, &contract)?;
        }

        self.update_state_root()
    }

    /// Load the counterparty account for transition planning.
    ///
    /// Self-transfer / self-deploy guard: when the counterparty IS the sender,
    /// planning continues from the already-debited in-memory sender instead of
    /// reloading the pre-state from disk. Persisting two independently-planned
    /// rows for one account would be last-write-wins — the recipient row would
    /// silently erase the gas debit and nonce increment.
    fn plan_counterparty(
        &self,
        address: &Address,
        from: &Address,
        sender: &Account,
    ) -> Result<Account> {
        if address == from {
            return Ok(sender.clone());
        }
        Ok(self
            .load_account(address)?
            .unwrap_or_else(|| Account::new(*address)))
    }

    /// Read an arbitrary key-value pair from state storage by raw key bytes.
    pub fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.storage.state_get(key.to_vec())
    }
    /// Write an arbitrary key-value pair to state storage by raw key bytes.
    pub fn set_raw(&self, key: &[u8], value: Vec<u8>) -> Result<()> {
        self.mark_dirty(key.to_vec())?;
        self.storage.state_put(key.to_vec(), value)?;
        self.bump_key_version(key.to_vec());
        Ok(())
    }

    /// Delete an arbitrary key from state storage by raw key bytes.
    ///
    /// BUGFIX (C-09): SELFDESTRUCT tombstones must REMOVE rows, not persist
    /// empty values (an empty value fails every account decoder on
    /// `load_account` and permanently bricks the account).
    pub fn delete_raw(&self, key: &[u8]) -> Result<()> {
        self.mark_dirty(key.to_vec())?;
        self.storage.state_delete(key.to_vec())?;
        self.bump_key_version(key.to_vec());
        Ok(())
    }

    /// Apply a finalized speculative write to storage and the Verkle tree.
    ///
    /// Single shared flush routine (BUGFIX C-09): an EMPTY value is a
    /// SELFDESTRUCT tombstone. It must DELETE the raw row and the tree leaf.
    /// The three previous copy-pasted flush sites persisted the empty value
    /// via `set_raw`, producing an undecodable account row that made every
    /// later `load_account` fail and bricked the account forever.
    pub fn apply_speculative_write(&self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.starts_with(b"account:") && key.len() == 40 {
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(&key[8..40]);
            if value.is_empty() {
                self.delete_tree_leaf(addr_bytes)?;
                self.delete_raw(key)?;
            } else {
                let account = decode_account(value)?;
                self.update_tree_leaf(addr_bytes, account.try_hash()?)?;
                self.set_raw(key, value.to_vec())?;
            }
            return Ok(());
        }

        if key.starts_with(b"storage:") && key.len() == 72 {
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(&key[8..40]);
            let address = Address::from(addr_bytes);
            let mut slot_bytes = [0u8; 32];
            slot_bytes.copy_from_slice(&key[40..72]);
            let tree_key = crate::storage_proof_key(&address, &slot_bytes);
            if value.is_empty() {
                self.delete_tree_leaf(tree_key)?;
                self.delete_raw(key)?;
            } else {
                if value.len() != 32 {
                    bail!("corrupt storage value length");
                }
                let mut val_bytes = [0u8; 32];
                val_bytes.copy_from_slice(value);
                self.update_tree_leaf(tree_key, val_bytes)?;
                self.set_raw(key, value.to_vec())?;
            }
            return Ok(());
        }

        // Other namespaces: plain write or delete by convention.
        if value.is_empty() {
            self.delete_raw(key)?;
        } else {
            self.set_raw(key, value.to_vec())?;
        }
        Ok(())
    }

    /// SECURITY (H-20): staged variant of `apply_speculative_write` for
    /// pipelines running over LIVE storage. The in-memory Verkle tree is
    /// updated immediately (crash-safe: purely volatile), but raw rows are
    /// buffered and only land via `flush_staged_writes` in a single atomic
    /// batch — eliminating the window where uncommitted block writes were
    /// visible to every other reader of the shared storage engine.
    pub fn apply_speculative_write_staged(&self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.starts_with(b"account:") && key.len() == 40 {
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(&key[8..40]);
            if value.is_empty() {
                self.delete_tree_leaf(addr_bytes)?;
            } else {
                let account = decode_account(value)?;
                self.update_tree_leaf(addr_bytes, account.try_hash()?)?;
            }
        } else if key.starts_with(b"storage:") && key.len() == 72 {
            let mut addr_bytes = [0u8; 32];
            addr_bytes.copy_from_slice(&key[8..40]);
            let address = Address::from(addr_bytes);
            let mut slot_bytes = [0u8; 32];
            slot_bytes.copy_from_slice(&key[40..72]);
            let tree_key = crate::storage_proof_key(&address, &slot_bytes);
            if value.is_empty() {
                self.delete_tree_leaf(tree_key)?;
            } else {
                if value.len() != 32 {
                    bail!("corrupt storage value length");
                }
                let mut val_bytes = [0u8; 32];
                val_bytes.copy_from_slice(value);
                self.update_tree_leaf(tree_key, val_bytes)?;
            }
        }

        if value.is_empty() {
            self.deferred_writes.lock().push((key.to_vec(), None));
        } else {
            self.deferred_writes
                .lock()
                .push((key.to_vec(), Some(value.to_vec())));
        }
        Ok(())
    }

    /// SECURITY (H-20): land all staged raw-row writes in ONE atomic batch.
    pub fn flush_staged_writes(&self) -> Result<()> {
        let batch = std::mem::take(&mut *self.deferred_writes.lock());
        if batch.is_empty() {
            return Ok(());
        }
        for (key, _) in &batch {
            self.mark_dirty(key.clone())?;
            self.bump_key_version(key.clone());
        }
        self.storage.atomic_state_commit(batch)
    }

    /// SECURITY (H-20): drop all staged raw-row writes (rollback path).
    pub fn discard_staged_writes(&self) {
        self.deferred_writes.lock().clear();
    }

    /// SECURITY (H-34): non-destructive backend initialization for pipelines
    /// running over LIVE storage. Unlike `initialize_backend`, this NEVER
    /// replays a persisted snapshot over current rows — a lagging snapshot
    /// used to silently roll the live state backwards at pipeline start.
    pub fn initialize_backend_rebuild_only(&self) -> Result<[u8; 32]> {
        self.rebuild_tree_from_storage()
    }

    /// Update a specific key commitment in the in-memory Verkle Tree.
    pub fn update_tree_leaf(&self, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        let mut tree = self.tree.lock();
        if tree.get(key)?.is_some() {
            tree.update(key, value)?;
        } else {
            tree.insert(key, value)?;
        }
        Ok(())
    }

    /// Delete a specific key commitment from the in-memory Verkle Tree.
    pub fn delete_tree_leaf(&self, key: [u8; 32]) -> Result<()> {
        let mut tree = self.tree.lock();
        if tree.get(key)?.is_some() {
            tree.delete(key)?;
        }
        Ok(())
    }

    pub fn get_node(&self, hash: [u8; 32]) -> Result<Option<VerkleNode>> {
        self.lazy_load_node(hash)
    }

    pub fn put_node(&self, hash: [u8; 32], node: &VerkleNode) -> Result<()> {
        self.store_node(hash, node)
    }

    pub fn load_node_from_storage(&self, hash: [u8; 32]) -> Result<Option<VerkleNode>> {
        if let Some(bytes) = self.storage.load_verkle_node(hash)? {
            let node = VerkleNode::deserialize(&bytes)?;
            self.node_cache.lock().insert(hash, node.clone());
            return Ok(Some(node));
        }
        Ok(None)
    }

    pub fn store_node(&self, hash: [u8; 32], node: &VerkleNode) -> Result<()> {
        self.storage.store_verkle_node(hash, node.serialize()?)?;
        self.node_cache.lock().insert(hash, node.clone());
        Ok(())
    }

    pub fn batch_node_writes(&self, nodes: &Vec<([u8; 32], VerkleNode)>) -> Result<()> {
        let encoded_nodes: Vec<([u8; 32], Vec<u8>)> = nodes
            .iter()
            .map(|(hash, node)| Ok((*hash, node.serialize()?)))
            .collect::<Result<_>>()?;
        self.storage.batch_store_verkle_nodes(&encoded_nodes)?;

        let mut cache = self.node_cache.lock();
        for (hash, node) in nodes {
            cache.insert(*hash, node.clone());
        }
        Ok(())
    }

    pub fn lazy_load_node(&self, hash: [u8; 32]) -> Result<Option<VerkleNode>> {
        if let Some(node) = self.node_cache.lock().get(&hash).cloned() {
            return Ok(Some(node));
        }

        self.load_node_from_storage(hash)
    }

    pub fn tree_root(&self) -> [u8; 32] {
        self.tree.lock().root_commitment()
    }

    pub fn state_root(&self) -> [u8; 32] {
        self.tree_root()
    }

    pub fn initialize_backend(
        &self,
        latest_height: u64,
        expected_root: Option<[u8; 32]>,
    ) -> Result<[u8; 32]> {
        let restored_root = if latest_height > 0
            && self
                .storage
                .state_get(Self::snapshot_type_key(latest_height))?
                .is_some()
        {
            self.load_snapshot(latest_height)?
        } else {
            self.rebuild_tree_from_storage()?
        };

        if let Some(expected_root) = expected_root {
            if restored_root != expected_root {
                bail!(
                    "restored state root mismatch: expected 0x{}, got 0x{}",
                    hex::encode(expected_root),
                    hex::encode(restored_root)
                );
            }
        }

        Ok(restored_root)
    }

    pub fn update_state_root(&self) -> Result<[u8; 32]> {
        let root = self.tree_root();
        self.storage
            .state_put(STATE_ROOT_KEY.to_vec(), root.to_vec())?;
        Ok(root)
    }

    pub fn verify_state_root(&self, root: [u8; 32]) -> Result<bool> {
        let in_memory_root = self.state_root();
        if in_memory_root != root {
            return Ok(false);
        }

        match self.storage.state_get(STATE_ROOT_KEY.to_vec())? {
            Some(bytes) if bytes.len() == 32 => {
                let mut persisted = [0u8; 32];
                persisted.copy_from_slice(&bytes);
                Ok(persisted == root)
            }
            Some(_) => Ok(false),
            None => Ok(root == [0u8; 32]),
        }
    }

    pub fn commit(&self) -> Result<[u8; 32]> {
        let root = self.update_state_root()?;
        let snapshot = self.tree.lock().clone();
        *self.committed_tree.lock() = snapshot;
        self.undo_log.lock().clear();
        self.dirty_keys.lock().clear();
        self.storage.flush_to_disk()?;
        Ok(root)
    }

    pub fn rollback(&self) -> Result<[u8; 32]> {
        let committed = self.committed_tree.lock().clone();
        let root = committed.root_commitment();

        // SECURITY (lock-ordering): drain the undo log under a scoped guard and
        // release it BEFORE taking any other lock. `mark_dirty` acquires
        // `dirty_keys` -> `undo_log`; holding `undo_log` here while later
        // locking `dirty_keys` inverted that order and could deadlock against
        // a concurrent writer.
        let changes: Vec<(Vec<u8>, Option<Vec<u8>>)> = {
            let mut undo_log = self.undo_log.lock();
            undo_log.drain().collect()
        };
        self.storage.atomic_state_commit(changes)?;

        *self.tree.lock() = committed;
        self.node_cache.lock().clear();
        self.storage
            .state_put(STATE_ROOT_KEY.to_vec(), root.to_vec())?;
        self.dirty_keys.lock().clear();
        Ok(root)
    }

    pub fn generate_account_proof(&self, address: &Address) -> Result<VerkleProof> {
        let tree = self.tree.lock();
        VerkleProof::generate_account_proof(&tree, address)
    }

    /// Build a [`crate::proof::StateWitness`] suitable for **stateless execution**
    /// of a block that only touches `addresses` (and optional storage slots).
    ///
    /// Includes Verkle multiproofs against the current state root plus full
    /// account (and optional storage) preimages required by the EVM / state
    /// transition function.
    pub fn build_execution_witness(
        &self,
        addresses: &[Address],
        storage_slots: &[(Address, [u8; 32])],
    ) -> Result<crate::proof::StateWitness> {
        use crate::proof::{StateWitness, StoragePreimage};

        let root = self.state_root();
        let mut proofs = Vec::new();
        let mut account_preimages = Vec::new();
        let mut storage_preimages = Vec::new();

        for address in addresses {
            if let Some(account) = self.load_account(address)? {
                let proof = self.generate_account_proof(address)?;
                // Sanity: proof leaf must bind to account hash.
                let leaf = proof.values.last().copied().unwrap_or([0u8; 32]);
                if leaf != account.try_hash()? {
                    bail!(
                        "account proof leaf mismatch for {}: proof={:x?}, account={}",
                        address,
                        &leaf[..4],
                        hex::encode(account.try_hash()?)
                    );
                }
                // Root anchor check.
                if proof.commitments.first().copied() != Some(root) {
                    bail!("account proof root mismatch for {}", address);
                }
                proofs.push(proof);
                account_preimages.push(account);
            }
        }

        for (address, slot) in storage_slots {
            if let Some(value) = self.get_storage(address, *slot)? {
                let tree = self.tree.lock();
                let proof = VerkleProof::generate_storage_proof(&tree, address, *slot)?;
                drop(tree);
                proofs.push(proof);
                storage_preimages.push(StoragePreimage {
                    address: *address,
                    slot: *slot,
                    value,
                });
            }
        }

        let mut code_preimages = Vec::new();
        for account in &account_preimages {
            if account.is_contract() {
                if let Some(bytecode) = self.get_code(&account.code_hash)? {
                    code_preimages.push(crate::proof::CodePreimage {
                        code_hash: account.code_hash,
                        bytecode,
                    });
                }
            }
        }

        Ok(StateWitness {
            proofs,
            account_preimages,
            storage_preimages,
            code_preimages,
        })
    }

    /// Collect every address referenced by a block's transactions (from / to).
    pub fn addresses_touched_by_block(block: &Block) -> Vec<Address> {
        let mut set = BTreeSet::new();
        for tx in &block.body.transactions {
            set.insert(tx.from);
            if let Some(to) = tx.to {
                set.insert(to);
            }
        }
        set.into_iter().collect()
    }

    pub fn export_account_proof_for_rpc(&self, address: &Address) -> Result<RpcVerkleProof> {
        let proof = self.generate_account_proof(address)?;
        Ok(proof.export_for_rpc(self.state_root()))
    }

    pub fn export_account_proof_for_height(
        &self,
        height: u64,
        address: &Address,
        max_depth: usize,
    ) -> Result<(Account, RpcVerkleProof)> {
        self.ensure_supported_proof_depth(max_depth)?;
        let (tree, entries, root) = self.rebuild_tree_for_height(height)?;
        let key = Self::account_key(address);
        let value = entries
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("account {} not found at height {}", address, height))?;
        let account = decode_account(value)?;
        let proof = VerkleProof::generate_account_proof(&tree, address)?;
        self.ensure_proof_depth(&proof, max_depth)?;
        Ok((account, proof.export_for_rpc(root)))
    }

    pub fn generate_storage_proof(&self, address: &Address, key: [u8; 32]) -> Result<VerkleProof> {
        let tree = self.tree.lock();
        VerkleProof::generate_storage_proof(&tree, address, key)
    }

    pub fn export_storage_proof_for_rpc(
        &self,
        address: &Address,
        key: [u8; 32],
    ) -> Result<RpcVerkleProof> {
        let proof = self.generate_storage_proof(address, key)?;
        Ok(proof.export_for_rpc(self.state_root()))
    }

    pub fn export_storage_proof_for_height(
        &self,
        height: u64,
        address: &Address,
        key: [u8; 32],
        max_depth: usize,
    ) -> Result<([u8; 32], RpcVerkleProof)> {
        self.ensure_supported_proof_depth(max_depth)?;
        let (tree, entries, root) = self.rebuild_tree_for_height(height)?;
        let storage_key = Self::storage_key(address, &key);
        let raw_value = entries
            .get(&storage_key)
            .ok_or_else(|| anyhow::anyhow!("storage key not found at height {}", height))?;
        if raw_value.len() != 32 {
            bail!("corrupt storage value length");
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(raw_value);
        let proof = VerkleProof::generate_storage_proof(&tree, address, key)?;
        self.ensure_proof_depth(&proof, max_depth)?;
        Ok((value, proof.export_for_rpc(root)))
    }

    pub fn generate_minimal_proof(&self, key: [u8; 32]) -> Result<VerkleProof> {
        let tree = self.tree.lock();
        tree.generate_minimal_proof(key)
    }

    pub fn export_minimal_proof_for_rpc(&self, key: [u8; 32]) -> Result<RpcVerkleProof> {
        let proof = self.generate_minimal_proof(key)?;
        Ok(proof.export_minimal_for_rpc(self.state_root()))
    }

    pub fn export_minimal_proof_for_height(
        &self,
        height: u64,
        key: [u8; 32],
        max_depth: usize,
    ) -> Result<([u8; 32], RpcVerkleProof)> {
        self.ensure_supported_proof_depth(max_depth)?;
        let (tree, _, root) = self.rebuild_tree_for_height(height)?;
        let proof = VerkleProof::generate_minimal_proof(&tree, key)?;
        self.ensure_proof_depth(&proof, max_depth)?;
        let value = proof.values.last().copied().unwrap_or([0u8; 32]);
        Ok((value, proof.export_minimal_for_rpc(root)))
    }

    pub fn verify_account_proof(&self, proof: &VerkleProof, address: &Address) -> Result<bool> {
        let account = match self.load_account(address)? {
            Some(account) => account,
            None => return Ok(false),
        };
        proof.verify_account_proof(address, &account, self.state_root())
    }

    pub fn verify_storage_proof(
        &self,
        proof: &VerkleProof,
        address: &Address,
        key: [u8; 32],
    ) -> Result<bool> {
        let value = match self.get_storage(address, key)? {
            Some(value) => value,
            None => return Ok(false),
        };
        proof.verify_storage_proof(address, key, value, self.state_root())
    }

    pub fn batch_proof_generation(&self, keys: &[[u8; 32]]) -> Result<Vec<VerkleProof>> {
        let tree = self.tree.lock();
        tree.batch_proof_generation(keys)
    }

    pub fn begin_read_only_snapshot(&self) -> ReadOnlyStateSnapshot {
        ReadOnlyStateSnapshot {
            root: self.state_root(),
            revision: self.revision.load(Ordering::SeqCst),
        }
    }

    pub fn parallel_state_reads(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>> {
        self.storage.parallel_state_reads(keys)
    }

    pub fn state_prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.storage.state_prefix_scan(prefix.to_vec())
    }

    pub fn state_range_scan(
        &self,
        start: &[u8],
        end: Option<&[u8]>,
        limit: usize,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.storage.state_range_scan(start, end, limit)
    }

    pub fn write_batch(&self, operations: Vec<StateBatchOp>) -> Result<()> {
        let mut changes = Vec::with_capacity(operations.len());
        for operation in operations {
            match operation {
                StateBatchOp::Put(key, value) => changes.push((key, Some(value))),
                StateBatchOp::Delete(key) => changes.push((key, None)),
            }
        }

        // Undo-log bookkeeping must happen BEFORE the batch lands so a
        // concurrent `rollback` can still restore the prior values.
        for (key, _) in &changes {
            self.mark_dirty(key.clone())?;
        }
        self.storage.atomic_state_commit(changes.clone())?;
        for (key, _) in &changes {
            self.bump_key_version(key.clone());
        }

        Ok(())
    }

    pub fn detect_conflicts<'a, I>(&self, snapshot: &ReadOnlyStateSnapshot, keys: I) -> Result<bool>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        if snapshot.root != self.state_root() {
            return Ok(true);
        }

        let key_versions = self.key_versions.lock();
        Ok(keys
            .into_iter()
            .any(|key| key_versions.get(key).copied().unwrap_or(0) > snapshot.revision))
    }

    pub fn snapshot_state(&self, height: u64) -> Result<[u8; 32]> {
        let root = self.state_root();
        let committed_tree = self.tree.lock().clone();
        let dirty_keys: Vec<Vec<u8>> = self.dirty_keys.lock().iter().cloned().collect();
        let has_previous_snapshot = height > 0
            && self
                .storage
                .state_get(Self::snapshot_type_key(height - 1))?
                .is_some();

        if height == 0 || dirty_keys.is_empty() || !has_previous_snapshot {
            self.write_full_snapshot(height, &committed_tree, root)?;
        } else {
            self.write_incremental_snapshot(height, root, &dirty_keys)?;
        }

        *self.committed_tree.lock() = committed_tree;
        self.dirty_keys.lock().clear();
        Ok(root)
    }

    pub fn load_snapshot(&self, height: u64) -> Result<[u8; 32]> {
        let mut chain = self.snapshot_chain(height)?;
        if chain.is_empty() {
            bail!("snapshot at height {} not found", height);
        }

        let base_height = chain.remove(0);
        let _tree_bytes = self
            .storage
            .state_get(Self::snapshot_tree_key(base_height))?
            .ok_or_else(|| anyhow::anyhow!("missing tree data for snapshot {}", base_height))?;
        self.apply_full_snapshot(base_height)?;

        for snapshot_height in chain {
            self.apply_incremental_snapshot(snapshot_height)?;
        }

        let expected_root = self
            .read_snapshot_root(height)?
            .ok_or_else(|| anyhow::anyhow!("missing snapshot root for height {}", height))?;
        let restored_root = self.rebuild_tree_from_storage()?;
        if restored_root != expected_root {
            bail!(
                "restored snapshot root mismatch at height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(expected_root),
                hex::encode(restored_root)
            );
        }

        self.dirty_keys.lock().clear();
        Ok(restored_root)
    }

    pub fn prune_old_state(&self) -> Result<usize> {
        self.prune_state_versions(SNAPSHOT_RETAIN_COUNT)
    }

    pub fn prune_state_versions(&self, retain_count: usize) -> Result<usize> {
        let heights = self.list_snapshot_heights()?;

        if heights.len() <= retain_count {
            return Ok(0);
        }

        let removable: BTreeSet<u64> = heights
            .iter()
            .copied()
            .take(heights.len() - retain_count)
            .collect();

        // Materialize the oldest retained height if it depends on a removable base.
        if let Some(&oldest_keep) = heights.iter().nth(heights.len() - retain_count) {
            if let Some(&max_removable) = removable.iter().next_back() {
                if self.snapshot_chain_needs_height_at_or_below(oldest_keep, max_removable)? {
                    self.materialize_full_snapshot_at(oldest_keep)?;
                }
            }
        }

        let entries = self.storage.state_prefix_scan(b"snapshot:".to_vec())?;
        let mut changes = Vec::new();
        for (key, _) in entries {
            if let Some(height) = Self::parse_snapshot_height(&key) {
                if removable.contains(&height) {
                    changes.push((key, None));
                }
            }
        }
        let pruned = changes.len();
        if pruned > 0 {
            self.storage.atomic_state_commit(changes)?;
        }
        Ok(pruned)
    }

    fn account_key(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(ACCOUNT_PREFIX.len() + 32);
        key.extend_from_slice(ACCOUNT_PREFIX);
        key.extend_from_slice(address.as_bytes());
        key
    }

    fn vesting_key(address: &Address) -> Vec<u8> {
        let mut key = Vec::with_capacity(VESTING_PREFIX.len() + 32);
        key.extend_from_slice(VESTING_PREFIX);
        key.extend_from_slice(address.as_bytes());
        key
    }

    fn storage_key(address: &Address, key: &[u8; 32]) -> Vec<u8> {
        let mut storage_key =
            Vec::with_capacity(STORAGE_PREFIX.len() + address.as_bytes().len() + key.len());
        storage_key.extend_from_slice(STORAGE_PREFIX);
        storage_key.extend_from_slice(address.as_bytes());
        storage_key.extend_from_slice(key);
        storage_key
    }

    pub fn mark_dirty(&self, key: Vec<u8>) -> Result<()> {
        let mut dirty = self.dirty_keys.lock();
        if !dirty.contains(&key) {
            let old_val = self.storage.state_get(key.clone())?;
            self.undo_log.lock().insert(key.clone(), old_val);
            dirty.insert(key);
        }
        Ok(())
    }

    fn bump_key_version(&self, key: Vec<u8>) {
        let version = self.revision.fetch_add(1, Ordering::SeqCst) + 1;
        self.key_versions.lock().insert(key, version);
    }

    fn deduct_gas(&self, sender: &mut Account, transaction: &Transaction) -> Result<()> {
        let gas_cost = transaction.gas_cost();
        sender.checked_sub_balance(gas_cost)?;
        Ok(())
    }

    fn apply_balance_update(&self, account: &mut Account, amount: U256) -> Result<()> {
        account.checked_add_balance(amount)?;
        account.validate()?;
        Ok(())
    }

    fn validate_state_transition_checks(
        &self,
        transaction: &Transaction,
        sender: &Account,
    ) -> Result<()> {
        if sender.nonce != transaction.nonce {
            bail!(
                "nonce mismatch for {}: expected {}, got {}",
                transaction.from,
                sender.nonce,
                transaction.nonce
            );
        }

        let total_cost = transaction
            .value
            .checked_add(transaction.gas_cost())
            .ok_or(AccountError::Overflow)?;
        if sender.balance < total_cost {
            return Err(TxError::InsufficientBalance.into());
        }

        if transaction.is_contract_call() {
            if let Some(recipient) = transaction.to {
                let contract = self
                    .load_account(&recipient)?
                    .unwrap_or_else(|| Account::new(recipient));
                if !contract.is_contract() && !transaction.data.is_empty() {
                    bail!(
                        "contract storage update requires contract account at {}",
                        recipient
                    );
                }
            }
        }

        sender.validate()?;
        Ok(())
    }

    pub fn rebuild_tree_from_storage(&self) -> Result<[u8; 32]> {
        let mut rebuilt_tree = VerkleTree::new();

        for (key, value) in self.storage.state_prefix_scan(ACCOUNT_PREFIX.to_vec())? {
            let Some(address_bytes) = key.strip_prefix(ACCOUNT_PREFIX) else {
                continue;
            };
            if address_bytes.len() != 32 {
                continue;
            }

            let account = decode_account(&value)?;
            let mut address = [0u8; 32];
            address.copy_from_slice(address_bytes);
            rebuilt_tree.insert(address, account.try_hash()?)?;
        }

        for (key, value) in self.storage.state_prefix_scan(STORAGE_PREFIX.to_vec())? {
            let Some(storage_key) = key.strip_prefix(STORAGE_PREFIX) else {
                continue;
            };
            if storage_key.len() != 64 {
                continue;
            }

            let mut address_bytes = [0u8; 32];
            address_bytes.copy_from_slice(&storage_key[..32]);
            let address = Address::from(address_bytes);

            let mut slot = [0u8; 32];
            slot.copy_from_slice(&storage_key[32..]);

            if value.len() != 32 {
                bail!("corrupt storage value length");
            }
            let mut slot_value = [0u8; 32];
            slot_value.copy_from_slice(&value);

            let proof_key = storage_proof_key(&address, &slot);
            rebuilt_tree.insert(proof_key, slot_value)?;
        }

        let restored_root = rebuilt_tree.root_commitment();
        *self.tree.lock() = rebuilt_tree.clone();
        *self.committed_tree.lock() = rebuilt_tree;
        self.node_cache.lock().clear();
        self.dirty_keys.lock().clear();
        self.undo_log.lock().clear();
        self.storage
            .state_put(STATE_ROOT_KEY.to_vec(), restored_root.to_vec())?;
        Ok(restored_root)
    }

    fn write_full_snapshot(&self, height: u64, tree: &VerkleTree, root: [u8; 32]) -> Result<()> {
        let mut changes = vec![
            (Self::snapshot_type_key(height), Some(b"full".to_vec())),
            (Self::snapshot_root_key(height), Some(root.to_vec())),
            (
                Self::snapshot_tree_key(height),
                Some(tree.root.serialize()?),
            ),
        ];

        for prefix in [ACCOUNT_PREFIX, STORAGE_PREFIX, VESTING_PREFIX] {
            for (key, value) in self.storage.state_prefix_scan(prefix.to_vec())? {
                changes.push((
                    Self::snapshot_state_entry_key(SNAPSHOT_FULL_PREFIX, height, &key),
                    Some(value),
                ));
            }
        }

        self.storage.atomic_state_commit(changes)
    }

    fn apply_full_snapshot(&self, height: u64) -> Result<()> {
        let prefix = Self::snapshot_prefix_for_height(SNAPSHOT_FULL_PREFIX, height);
        let entries = self.storage.state_prefix_scan(prefix)?;
        let mut changes = Vec::new();

        // 1. Wipe all current live account, storage, and vesting keys to prevent leakage of newer revisions
        for key_prefix in [ACCOUNT_PREFIX, STORAGE_PREFIX, VESTING_PREFIX] {
            for (key, _) in self.storage.state_prefix_scan(key_prefix.to_vec())? {
                changes.push((key, None));
            }
        }

        // 2. Insert the snapshot entries
        for (snapshot_key, value) in entries {
            if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                changes.push((original_key, Some(value)));
            }
        }

        if !changes.is_empty() {
            self.storage.atomic_state_commit(changes)?;
        }

        Ok(())
    }

    fn write_incremental_snapshot(
        &self,
        height: u64,
        root: [u8; 32],
        dirty_keys: &[Vec<u8>],
    ) -> Result<()> {
        let base_height = height.saturating_sub(1);
        let mut changes = vec![
            (
                Self::snapshot_type_key(height),
                Some(b"incremental".to_vec()),
            ),
            (Self::snapshot_root_key(height), Some(root.to_vec())),
            (
                Self::snapshot_base_key(height),
                Some(base_height.to_le_bytes().to_vec()),
            ),
        ];

        for key in dirty_keys {
            let value = match self.storage.state_get(key.clone())? {
                Some(value) => Some(value),
                None => Some(SNAPSHOT_TOMBSTONE.to_vec()),
            };
            changes.push((
                Self::snapshot_state_entry_key(SNAPSHOT_INCREMENTAL_PREFIX, height, key),
                value,
            ));
        }

        self.storage.atomic_state_commit(changes)
    }

    fn apply_incremental_snapshot(&self, height: u64) -> Result<()> {
        let prefix = Self::snapshot_prefix_for_height(SNAPSHOT_INCREMENTAL_PREFIX, height);
        let entries = self.storage.state_prefix_scan(prefix)?;
        let mut changes = Vec::new();

        for (snapshot_key, value) in entries {
            if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                if value == SNAPSHOT_TOMBSTONE {
                    changes.push((original_key, None));
                } else {
                    changes.push((original_key, Some(value)));
                }
            }
        }

        if !changes.is_empty() {
            self.storage.atomic_state_commit(changes)?;
        }

        Ok(())
    }

    fn snapshot_chain(&self, mut height: u64) -> Result<Vec<u64>> {
        let mut chain = Vec::new();

        loop {
            let snapshot_type = self
                .storage
                .state_get(Self::snapshot_type_key(height))?
                .ok_or_else(|| anyhow::anyhow!("snapshot {} not found", height))?;
            chain.push(height);

            if snapshot_type == b"full" {
                break;
            }

            let base_bytes = self
                .storage
                .state_get(Self::snapshot_base_key(height))?
                .ok_or_else(|| anyhow::anyhow!("incremental snapshot {} missing base", height))?;
            if base_bytes.len() != 8 {
                bail!("invalid base pointer for snapshot {}", height);
            }

            let mut array = [0u8; 8];
            array.copy_from_slice(&base_bytes);
            height = u64::from_le_bytes(array);
        }

        chain.reverse();
        Ok(chain)
    }

    fn read_snapshot_root(&self, height: u64) -> Result<Option<[u8; 32]>> {
        match self.storage.state_get(Self::snapshot_root_key(height))? {
            Some(bytes) if bytes.len() == 32 => {
                let mut root = [0u8; 32];
                root.copy_from_slice(&bytes);
                Ok(Some(root))
            }
            Some(_) => Ok(None),
            None => Ok(None),
        }
    }

    fn snapshot_prefix_for_height(prefix: &[u8], height: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(prefix.len() + 20);
        key.extend_from_slice(prefix);
        key.extend_from_slice(height.to_string().as_bytes());
        key
    }

    fn snapshot_root_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_ROOT_SUFFIX);
        key
    }

    fn snapshot_tree_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_TREE_SUFFIX);
        key
    }

    fn snapshot_base_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_BASE_SUFFIX);
        key
    }

    fn snapshot_type_key(height: u64) -> Vec<u8> {
        let mut key = Self::snapshot_prefix_for_height(SNAPSHOT_META_PREFIX, height);
        key.extend_from_slice(SNAPSHOT_TYPE_SUFFIX);
        key
    }

    fn snapshot_state_entry_key(prefix: &[u8], height: u64, original_key: &[u8]) -> Vec<u8> {
        let mut snapshot_key = Self::snapshot_prefix_for_height(prefix, height);
        snapshot_key.extend_from_slice(SNAPSHOT_KEY_PREFIX);
        snapshot_key.extend_from_slice(original_key);
        snapshot_key
    }

    fn decode_snapshot_state_entry_key(snapshot_key: &[u8]) -> Option<Vec<u8>> {
        let marker = snapshot_key
            .windows(SNAPSHOT_KEY_PREFIX.len())
            .position(|window| window == SNAPSHOT_KEY_PREFIX)?;
        Some(snapshot_key[marker + SNAPSHOT_KEY_PREFIX.len()..].to_vec())
    }

    fn rebuild_tree_for_height(&self, height: u64) -> Result<HistoricalState> {
        let root = self
            .read_snapshot_root(height)?
            .ok_or_else(|| anyhow::anyhow!("missing snapshot root for height {}", height))?;
        let entries = self.snapshot_entries(height)?;
        let tree = Self::build_tree_from_entries(&entries)?;
        if tree.root_commitment() != root {
            bail!(
                "historical snapshot root mismatch at height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(root),
                hex::encode(tree.root_commitment())
            );
        }
        Ok((tree, entries, root))
    }

    fn snapshot_entries(&self, height: u64) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        let mut chain = self.snapshot_chain(height)?;
        if chain.is_empty() {
            bail!("snapshot at height {} not found", height);
        }

        let base_height = chain.remove(0);
        let mut entries = HashMap::new();
        let full_prefix = Self::snapshot_prefix_for_height(SNAPSHOT_FULL_PREFIX, base_height);
        for (snapshot_key, value) in self.storage.state_prefix_scan(full_prefix)? {
            if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                entries.insert(original_key, value);
            }
        }

        for snapshot_height in chain {
            let prefix =
                Self::snapshot_prefix_for_height(SNAPSHOT_INCREMENTAL_PREFIX, snapshot_height);
            for (snapshot_key, value) in self.storage.state_prefix_scan(prefix)? {
                if let Some(original_key) = Self::decode_snapshot_state_entry_key(&snapshot_key) {
                    if value == SNAPSHOT_TOMBSTONE {
                        entries.remove(&original_key);
                    } else {
                        entries.insert(original_key, value);
                    }
                }
            }
        }

        Ok(entries)
    }

    fn build_tree_from_entries(entries: &HashMap<Vec<u8>, Vec<u8>>) -> Result<VerkleTree> {
        let mut rebuilt_tree = VerkleTree::new();

        for (key, value) in entries {
            if let Some(address_bytes) = key.strip_prefix(ACCOUNT_PREFIX) {
                if address_bytes.len() != 32 {
                    continue;
                }
                let account = decode_account(value)?;
                let mut address = [0u8; 32];
                address.copy_from_slice(address_bytes);
                rebuilt_tree.insert(address, account.try_hash()?)?;
                continue;
            }

            if let Some(storage_key) = key.strip_prefix(STORAGE_PREFIX) {
                if storage_key.len() != 64 {
                    continue;
                }
                if value.len() != 32 {
                    bail!("corrupt storage value length");
                }
                let mut address_bytes = [0u8; 32];
                address_bytes.copy_from_slice(&storage_key[..32]);
                let address = Address::from(address_bytes);

                let mut slot = [0u8; 32];
                slot.copy_from_slice(&storage_key[32..]);

                let mut slot_value = [0u8; 32];
                slot_value.copy_from_slice(value);

                rebuilt_tree.insert(storage_proof_key(&address, &slot), slot_value)?;
            }
        }

        Ok(rebuilt_tree)
    }

    fn ensure_supported_proof_depth(&self, max_depth: usize) -> Result<()> {
        if max_depth > MAX_VERKLE_PROOF_DEPTH {
            bail!(
                "requested proof depth {} exceeds maximum tree depth {}",
                max_depth,
                MAX_VERKLE_PROOF_DEPTH
            );
        }
        Ok(())
    }

    fn ensure_proof_depth(&self, proof: &VerkleProof, max_depth: usize) -> Result<()> {
        if proof.path.len() > max_depth {
            bail!(
                "proof depth {} exceeds requested max_depth {}",
                proof.path.len(),
                max_depth
            );
        }
        Ok(())
    }

    fn parse_snapshot_height(key: &[u8]) -> Option<u64> {
        for prefix in [
            SNAPSHOT_META_PREFIX,
            SNAPSHOT_FULL_PREFIX,
            SNAPSHOT_INCREMENTAL_PREFIX,
        ] {
            if let Some(rest) = key.strip_prefix(prefix) {
                let height_bytes: Vec<u8> = rest
                    .iter()
                    .copied()
                    .take_while(|byte| byte.is_ascii_digit())
                    .collect();
                if height_bytes.is_empty() {
                    return None;
                }
                let height_str = String::from_utf8(height_bytes).ok()?;
                return height_str.parse::<u64>().ok();
            }
        }
        None
    }

    /// Hook invoked during block finalization to enforce the node's pruning policy.
    ///
    /// * **Archive** - no-op; keep every historical snapshot.
    /// * **Pruned(N)** - delete snapshots at heights `- finalized_height - N - 1`,
    ///   retaining roughly the last `N` finalized heights of history.
    /// * **Minimal** - delete all snapshots strictly older than `finalized_height`
    ///   (live `account:` / `storage:` keys are never removed).
    ///
    /// Before deleting, if the oldest retained snapshot is incremental and depends
    /// on a base that would be removed, that height is **materialized as a full
    /// snapshot** so later `load_snapshot` / proof export still works.
    ///
    /// Returns the number of storage keys deleted.
    pub fn prune_historical_state(&self, finalized_height: u64) -> Result<usize> {
        let retain_limit = match self.pruning_mode {
            PruningMode::Archive => return Ok(0),
            PruningMode::Pruned(limit) => limit,
            PruningMode::Minimal => 0,
        };

        if finalized_height <= retain_limit {
            return Ok(0);
        }

        // Inclusive maximum height whose snapshot data may be deleted.
        let prune_target = finalized_height
            .saturating_sub(retain_limit)
            .saturating_sub(1);

        tracing::info!(
            prune_target,
            finalized_height,
            retain_limit,
            mode = ?self.pruning_mode,
            "pruning historical state snapshots"
        );

        let heights = self.list_snapshot_heights()?;
        if heights.is_empty() {
            return Ok(0);
        }

        // Ensure retained range still has a self-contained full base.
        let oldest_keep = prune_target.saturating_add(1);
        if heights
            .iter()
            .any(|&h| h >= oldest_keep && h <= finalized_height)
        {
            // Prefer materializing the oldest kept height that still exists.
            if let Some(&keep_height) = heights.iter().find(|&&h| h >= oldest_keep) {
                if self
                    .storage
                    .state_get(Self::snapshot_type_key(keep_height))?
                    .is_some()
                {
                    // Only materialize when the restore chain would touch pruned heights.
                    if self.snapshot_chain_needs_height_at_or_below(keep_height, prune_target)? {
                        self.materialize_full_snapshot_at(keep_height)?;
                    }
                }
            }
        }

        let deleted = self.delete_snapshots_at_or_below(prune_target)?;
        tracing::info!(deleted, prune_target, "historical state pruning complete");
        Ok(deleted)
    }

    /// List every height that has a snapshot type record.
    pub fn list_snapshot_heights(&self) -> Result<BTreeSet<u64>> {
        let entries = self.storage.state_prefix_scan(b"snapshot:".to_vec())?;
        let mut heights = BTreeSet::new();
        for (key, _) in entries {
            if let Some(height) = Self::parse_snapshot_height(&key) {
                heights.insert(height);
            }
        }
        Ok(heights)
    }

    /// True if restoring `height` walks through any snapshot `- max_height`.
    fn snapshot_chain_needs_height_at_or_below(
        &self,
        height: u64,
        max_height: u64,
    ) -> Result<bool> {
        match self.snapshot_chain(height) {
            Ok(chain) => Ok(chain.iter().any(|&h| h <= max_height)),
            // Missing chain - nothing to preserve; treat as no dependency.
            Err(_) => Ok(false),
        }
    }

    /// Rewrite snapshot `height` as a self-contained full snapshot using its
    /// current restoreable entries (must be called while the old chain still exists).
    fn materialize_full_snapshot_at(&self, height: u64) -> Result<()> {
        let (tree, entries, root) = self.rebuild_tree_for_height(height)?;

        let mut changes: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();

        // Drop previous full/incremental payload keys for this height.
        for prefix in [SNAPSHOT_FULL_PREFIX, SNAPSHOT_INCREMENTAL_PREFIX] {
            let scan_prefix = Self::snapshot_prefix_for_height(prefix, height);
            for (key, _) in self.storage.state_prefix_scan(scan_prefix)? {
                changes.push((key, None));
            }
        }

        // Drop incremental base pointer (if any).
        changes.push((Self::snapshot_base_key(height), None));

        // Write full snapshot metadata + payload.
        changes.push((Self::snapshot_type_key(height), Some(b"full".to_vec())));
        changes.push((Self::snapshot_root_key(height), Some(root.to_vec())));
        changes.push((
            Self::snapshot_tree_key(height),
            Some(tree.root.serialize()?),
        ));

        for (key, value) in entries {
            changes.push((
                Self::snapshot_state_entry_key(SNAPSHOT_FULL_PREFIX, height, &key),
                Some(value),
            ));
        }

        self.storage.atomic_state_commit(changes)?;
        tracing::debug!(height, "materialized full snapshot before historical prune");
        Ok(())
    }

    /// Delete every snapshot-related key whose height is `- max_height`.
    /// Returns the number of keys removed.
    pub fn delete_snapshots_at_or_below(&self, max_height: u64) -> Result<usize> {
        let entries = self.storage.state_prefix_scan(b"snapshot:".to_vec())?;
        let mut changes = Vec::new();

        for (key, _) in entries {
            if let Some(height) = Self::parse_snapshot_height(&key) {
                if height <= max_height {
                    changes.push((key, None));
                }
            }
        }

        let deleted = changes.len();
        if deleted > 0 {
            self.storage.atomic_state_commit(changes)?;
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::{keccak256_bytes, StateBatchOp, StateDb};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_storage::{DatabaseBackend, Schema, StorageEngine};
    use sxiaum_types::{Account, Address, Receipt, Transaction};

    use crate::{verkle_tree::VerkleTree, VerkleNode};

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-state-{name}-{unique}.redb"))
    }

    fn test_db(name: &str) -> (Arc<dyn DatabaseBackend>, StateDb, PathBuf) {
        let db_path = temp_db_path(name);
        Schema::init(&db_path).expect("schema should initialize");
        let storage = Arc::new(StorageEngine::new(&db_path).expect("storage should initialize"));
        let state = StateDb::new(storage.clone());
        (storage, state, db_path)
    }

    fn cleanup(storage: Arc<dyn DatabaseBackend>, path: PathBuf) {
        // We can't directly shut down via dyn DatabaseBackend,
        // but Arc drop will handle db drop.
        drop(storage);
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn new_initializes_state_db_with_empty_tree() {
        let (storage, state, path) = test_db("new");

        assert_eq!(state.state_root(), VerkleTree::new().root_commitment());
        assert_eq!(
            state
                .get_balance(&Address([1u8; 32]))
                .expect("balance read should succeed"),
            U256::zero()
        );
        assert_eq!(
            state
                .get_nonce(&Address([1u8; 32]))
                .expect("nonce read should succeed"),
            0
        );

        cleanup(storage, path);
    }

    #[test]
    fn account_reads_return_persisted_account_data() {
        let (storage, state, path) = test_db("account-reads");
        let address = Address([2u8; 32]);
        let mut account = Account::new(address);
        account.balance = U256::from(55u64);
        account.nonce = 7;

        state
            .update_account(&address, &account)
            .expect("account update should succeed");

        assert_eq!(
            state
                .load_account(&address)
                .expect("load account should succeed"),
            Some(account.clone())
        );
        assert_eq!(
            state
                .get_account(&address)
                .expect("get account should succeed"),
            Some(account.clone())
        );
        assert_eq!(
            state
                .get_balance(&address)
                .expect("get balance should succeed"),
            U256::from(55u64)
        );
        assert_eq!(
            state.get_nonce(&address).expect("get nonce should succeed"),
            7
        );
        assert!(state
            .account_exists(&address)
            .expect("existence check should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn missing_account_reads_fall_back_to_empty_values() {
        let (storage, state, path) = test_db("missing-account");
        let address = Address([3u8; 32]);

        assert_eq!(
            state
                .load_account(&address)
                .expect("load account should succeed"),
            None
        );
        assert_eq!(
            state
                .get_account(&address)
                .expect("get account should succeed"),
            None
        );
        assert_eq!(
            state
                .get_balance(&address)
                .expect("get balance should succeed"),
            U256::zero()
        );
        assert_eq!(
            state.get_nonce(&address).expect("get nonce should succeed"),
            0
        );
        assert!(!state
            .account_exists(&address)
            .expect("existence check should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn storage_reads_return_written_values_and_none_when_absent() {
        let (storage, state, path) = test_db("storage-reads");
        let address = Address([4u8; 32]);
        let storage_key = [5u8; 32];
        let storage_value = [6u8; 32];

        assert_eq!(
            state
                .get_storage(&address, storage_key)
                .expect("missing storage read should succeed"),
            None
        );

        state
            .set_storage(&address, storage_key, storage_value)
            .expect("storage write should succeed");

        assert_eq!(
            state
                .get_storage(&address, storage_key)
                .expect("storage read should succeed"),
            Some(storage_value)
        );

        cleanup(storage, path);
    }

    #[test]
    fn create_account_set_balance_and_increment_nonce_work() {
        let (storage, state, path) = test_db("account-writes");
        let address = Address([7u8; 32]);

        let created = state
            .create_account(address)
            .expect("account creation should succeed");
        assert_eq!(created.address, address);
        assert!(state
            .account_exists(&address)
            .expect("existence check should succeed"));

        state
            .set_balance(&address, U256::from(99u64))
            .expect("balance update should succeed");
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(99u64)
        );

        let nonce = state
            .increment_nonce(&address)
            .expect("nonce increment should succeed");
        assert_eq!(nonce, 1);
        assert_eq!(
            state
                .get_nonce(&address)
                .expect("nonce read should succeed"),
            1
        );

        cleanup(storage, path);
    }

    #[test]
    fn set_storage_updates_slot_and_account_storage_root() {
        let (storage, state, path) = test_db("set-storage");
        let address = Address([8u8; 32]);
        let slot = [9u8; 32];
        let value = [10u8; 32];

        state
            .set_storage(&address, slot, value)
            .expect("storage write should succeed");

        let account = state
            .load_account(&address)
            .expect("account load should succeed")
            .expect("account should exist after storage write");

        assert_eq!(
            state
                .get_storage(&address, slot)
                .expect("storage read should succeed"),
            Some(value)
        );
        assert_ne!(account.storage_root, [0u8; 32]);

        cleanup(storage, path);
    }

    #[test]
    fn delete_account_removes_persisted_state() {
        let (storage, state, path) = test_db("delete-account");
        let address = Address([11u8; 32]);

        state
            .create_account(address)
            .expect("account creation should succeed");
        state
            .delete_account(&address)
            .expect("account deletion should succeed");

        assert!(!state
            .account_exists(&address)
            .expect("existence check should succeed"));
        assert_eq!(
            state
                .get_account(&address)
                .expect("account read should succeed"),
            None
        );

        cleanup(storage, path);
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn signed_transfer(signing_key: &SigningKey, to: Address, value: u64, nonce: u64) -> Transaction {
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(from, to, U256::from(value), nonce);
        tx.sign(signing_key)
            .expect("sample transaction must sign with its sender key");
        tx
    }

    #[test]
    fn apply_transaction_transfers_balance_and_updates_nonce() {
        let (storage, state, path) = test_db("apply-transaction");
        let sender_key = signing_key(0x11);
        let from = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let to = Address([13u8; 32]);
        let mut sender = Account::new(from);
        sender.balance = U256::from(100_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let tx = signed_transfer(&sender_key, to, 500, 0);
        let gas_cost = tx.gas_cost();
        state
            .apply_transaction(&tx)
            .expect("transaction application should succeed");

        assert_eq!(
            state
                .get_balance(&from)
                .expect("sender balance read should succeed"),
            U256::from(100_000u64) - U256::from(500u64) - gas_cost
        );
        assert_eq!(
            state
                .get_nonce(&from)
                .expect("sender nonce read should succeed"),
            1
        );
        assert_eq!(
            state
                .get_balance(&to)
                .expect("recipient balance read should succeed"),
            U256::from(500u64)
        );

        cleanup(storage, path);
    }

    #[test]
    fn apply_block_processes_transactions_and_updates_state_root() {
        let (storage, state, path) = test_db("apply-block");
        let sender_key = signing_key(0x12);
        let from = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let to = Address([15u8; 32]);
        let mut sender = Account::new(from);
        sender.balance = U256::from(200_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let tx = signed_transfer(&sender_key, to, 750, 0);
        let receipt = Receipt::new_success(tx.try_hash().unwrap(), tx.gas_limit, None);
        let mut body = BlockBody::new();
        body.add_transaction(tx.clone());
        body.add_receipt(receipt);

        let mut header = BlockHeader::new([1u8; 32], 1);
        header.set_state_root(state.state_root());
        let mut block = Block::new(header, body);
        block.try_compute_roots().unwrap();

        let resulting_root = state
            .apply_block(&block)
            .expect("block application should succeed");

        assert_eq!(resulting_root, state.state_root());
        assert_eq!(
            state
                .get_nonce(&from)
                .expect("sender nonce read should succeed"),
            1
        );
        assert_eq!(
            state
                .get_balance(&to)
                .expect("recipient balance read should succeed"),
            U256::from(750u64)
        );

        cleanup(storage, path);
    }

    #[test]
    fn state_root_update_and_verify_round_trip() {
        let (storage, state, path) = test_db("state-root");
        let address = Address([16u8; 32]);

        state
            .set_balance(&address, U256::from(42u64))
            .expect("balance update should succeed");
        let root = state
            .update_state_root()
            .expect("state root update should succeed");

        assert_eq!(root, state.state_root());
        assert!(state
            .verify_state_root(root)
            .expect("state root verification should succeed"));
        assert!(!state
            .verify_state_root([0u8; 32])
            .expect("mismatched root verification should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn commit_persists_snapshot_and_rollback_restores_it() {
        let (_storage, state, _path) = test_db("commit-rollback");
        let address = Address([17u8; 32]);

        state
            .set_balance(&address, U256::from(100u64))
            .expect("initial balance update should succeed");
        let committed_root = state.commit().expect("commit should succeed");
        assert_eq!(committed_root, state.state_root());

        state
            .set_balance(&address, U256::from(250u64))
            .expect("second balance update should succeed");
        let updated_root = state.state_root();
        assert_ne!(updated_root, committed_root);

        let rolled_back_root = state.rollback().expect("rollback should succeed");

        assert_eq!(rolled_back_root, committed_root);
        assert_eq!(state.state_root(), committed_root);
        assert!(state
            .verify_state_root(committed_root)
            .expect("rolled back root verification should succeed"));
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(100u64)
        );
    }

    #[test]
    fn snapshot_state_writes_full_then_incremental_snapshots() {
        let (storage, state, path) = test_db("snapshots");
        let address = Address([18u8; 32]);

        state
            .set_balance(&address, U256::from(10u64))
            .expect("initial balance update should succeed");
        let full_root = state
            .snapshot_state(0)
            .expect("full snapshot should succeed");

        let snapshot_type_zero = storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .expect("snapshot type read should succeed")
            .expect("snapshot type should exist");
        assert_eq!(snapshot_type_zero, b"full".to_vec());

        state
            .set_balance(&address, U256::from(25u64))
            .expect("second balance update should succeed");
        let incremental_root = state
            .snapshot_state(1)
            .expect("incremental snapshot should succeed");

        let snapshot_type_one = storage
            .state_get(b"snapshot:meta:1:type".to_vec())
            .expect("snapshot type read should succeed")
            .expect("incremental snapshot type should exist");
        assert_eq!(snapshot_type_one, b"incremental".to_vec());
        assert_ne!(full_root, incremental_root);

        cleanup(storage, path);
    }

    #[test]
    fn load_snapshot_restores_historical_state() {
        let (storage, state, path) = test_db("load-snapshot");
        let address = Address([19u8; 32]);

        state
            .set_balance(&address, U256::from(50u64))
            .expect("initial balance update should succeed");
        let root_zero = state
            .snapshot_state(0)
            .expect("snapshot zero should succeed");

        state
            .set_balance(&address, U256::from(75u64))
            .expect("second balance update should succeed");
        let root_one = state
            .snapshot_state(1)
            .expect("snapshot one should succeed");

        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(75u64)
        );

        let restored_zero = state
            .load_snapshot(0)
            .expect("loading first snapshot should succeed");
        assert_eq!(restored_zero, root_zero);
        assert_eq!(state.state_root(), root_zero);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(50u64)
        );

        let restored_one = state
            .load_snapshot(1)
            .expect("loading second snapshot should succeed");
        assert_eq!(restored_one, root_one);
        assert_eq!(state.state_root(), root_one);
        assert_eq!(
            state
                .get_balance(&address)
                .expect("balance read should succeed"),
            U256::from(75u64)
        );

        cleanup(storage, path);
    }

    #[test]
    fn prune_old_state_removes_snapshots_beyond_retention_window() {
        let (storage, state, path) = test_db("prune-snapshots");
        let address = Address([20u8; 32]);

        for height in 0..10u64 {
            state
                .set_balance(&address, U256::from(height + 1))
                .expect("balance update should succeed");
            state
                .snapshot_state(height)
                .expect("snapshot creation should succeed");
        }

        let pruned = state
            .prune_old_state()
            .expect("snapshot pruning should succeed");
        assert!(pruned > 0);

        assert!(storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .expect("snapshot lookup should succeed")
            .is_none());
        assert!(storage
            .state_get(b"snapshot:meta:9:type".to_vec())
            .expect("latest snapshot lookup should succeed")
            .is_some());

        cleanup(storage, path);
    }

    #[test]
    fn read_only_snapshot_captures_root_and_revision() {
        let (_storage, state, _path) = test_db("read-only-snapshot");
        let address = Address([21u8; 32]);
        let initial = state.begin_read_only_snapshot();

        state
            .set_balance(&address, U256::from(5u64))
            .expect("balance update should succeed");
        let updated = state.begin_read_only_snapshot();

        assert_eq!(initial.root, VerkleTree::new().root_commitment());
        assert!(updated.revision > initial.revision);
        assert_ne!(updated.root, initial.root);
    }

    #[test]
    fn parallel_state_reads_return_values_in_key_order() {
        let (storage, state, path) = test_db("parallel-reads");
        let first_key = b"custom:key:1".to_vec();
        let second_key = b"custom:key:2".to_vec();

        state
            .write_batch(vec![
                StateBatchOp::Put(first_key.clone(), b"one".to_vec()),
                StateBatchOp::Put(second_key.clone(), b"two".to_vec()),
            ])
            .expect("write batch should succeed");

        let values = state
            .parallel_state_reads(&[first_key.clone(), b"missing".to_vec(), second_key.clone()])
            .expect("parallel reads should succeed");

        assert_eq!(
            values,
            vec![Some(b"one".to_vec()), None, Some(b"two".to_vec())]
        );

        cleanup(storage, path);
    }

    #[test]
    fn write_batch_applies_puts_and_deletes() {
        let (storage, state, path) = test_db("write-batch");
        let key = b"batch:key".to_vec();
        let other_key = b"batch:other".to_vec();

        state
            .write_batch(vec![
                StateBatchOp::Put(key.clone(), b"value".to_vec()),
                StateBatchOp::Put(other_key.clone(), b"other".to_vec()),
            ])
            .expect("initial batch should succeed");
        state
            .write_batch(vec![StateBatchOp::Delete(other_key.clone())])
            .expect("delete batch should succeed");

        assert_eq!(
            storage.state_get(key).expect("state read should succeed"),
            Some(b"value".to_vec())
        );
        assert_eq!(
            storage
                .state_get(other_key)
                .expect("state read should succeed"),
            None
        );

        cleanup(storage, path);
    }

    #[test]
    fn conflict_detection_uses_root_and_key_versions() {
        let (storage, state, path) = test_db("conflict-detection");
        let watched_key = b"watched:key".to_vec();
        let untouched_key = b"untouched:key".to_vec();

        let snapshot = state.begin_read_only_snapshot();
        assert!(!state
            .detect_conflicts(
                &snapshot,
                std::slice::from_ref(&watched_key)
                    .iter()
                    .map(|k| k.as_slice())
            )
            .expect("conflict detection should succeed"));

        state
            .write_batch(vec![StateBatchOp::Put(
                watched_key.clone(),
                b"value".to_vec(),
            )])
            .expect("write batch should succeed");
        assert!(state
            .detect_conflicts(
                &snapshot,
                std::slice::from_ref(&watched_key)
                    .iter()
                    .map(|k| k.as_slice())
            )
            .expect("conflict detection should succeed"));

        let fresh_snapshot = state.begin_read_only_snapshot();
        assert!(!state
            .detect_conflicts(
                &fresh_snapshot,
                std::slice::from_ref(&untouched_key)
                    .iter()
                    .map(|k| k.as_slice())
            )
            .expect("conflict detection should succeed"));

        state
            .set_balance(&Address([22u8; 32]), U256::from(1u64))
            .expect("balance update should succeed");
        assert!(state
            .detect_conflicts(
                &fresh_snapshot,
                std::slice::from_ref(&untouched_key)
                    .iter()
                    .map(|k| k.as_slice())
            )
            .expect("conflict detection should succeed"));

        cleanup(storage, path);
    }

    #[test]
    fn store_and_load_verkle_node_round_trip() {
        let (storage, state, path) = test_db("node-store-load");
        let hash = [23u8; 32];
        let mut node = VerkleNode::new_internal(0);
        node.set_child(1, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        state
            .store_node(hash, &node)
            .expect("node store should succeed");

        let loaded = state
            .load_node_from_storage(hash)
            .expect("node load should succeed")
            .expect("node should exist in storage");

        assert_eq!(loaded.commitment(), node.commitment());
        assert_eq!(loaded.children_count(), node.children_count());

        cleanup(storage, path);
    }

    #[test]
    fn batch_node_writes_persist_all_nodes() {
        let (storage, state, path) = test_db("batch-node-writes");
        let first_hash = [24u8; 32];
        let second_hash = [25u8; 32];
        let first_node = VerkleNode::new_internal(0);
        let mut second_node = VerkleNode::new_internal(0);
        second_node
            .set_child(2, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        state
            .batch_node_writes(&vec![
                (first_hash, first_node.clone()),
                (second_hash, second_node.clone()),
            ])
            .expect("batch node write should succeed");

        assert!(state
            .load_node_from_storage(first_hash)
            .expect("first node load should succeed")
            .is_some());
        let loaded_second = state
            .load_node_from_storage(second_hash)
            .expect("second node load should succeed")
            .expect("second node should exist");
        assert_eq!(loaded_second.commitment(), second_node.commitment());

        cleanup(storage, path);
    }

    #[test]
    fn lazy_load_node_uses_cache_after_storage_fetch() {
        let (storage, state, path) = test_db("lazy-node-load");
        let hash = [26u8; 32];
        let mut node = VerkleNode::new_internal(0);
        node.set_child(3, VerkleNode::new_internal(1))
            .expect("set_child should succeed");

        storage
            .store_verkle_node(hash, node.serialize().expect("serialize should succeed"))
            .expect("raw node store should succeed");

        let first = state
            .lazy_load_node(hash)
            .expect("initial lazy load should succeed")
            .expect("node should load from storage");
        let second = state
            .lazy_load_node(hash)
            .expect("cached lazy load should succeed")
            .expect("node should load from cache");

        assert_eq!(first.commitment(), node.commitment());
        assert_eq!(second.commitment(), node.commitment());
        assert!(state
            .lazy_load_node([27u8; 32])
            .expect("missing lazy load should succeed")
            .is_none());

        cleanup(storage, path);
    }

    #[test]
    fn state_transition_deducts_gas_and_updates_balances() {
        let (storage, state, path) = test_db("state-transition-transfer");
        let sender_key = signing_key(0x13);
        let from = Address::from_public_key(&sender_key.verifying_key().to_bytes());
        let to = Address([29u8; 32]);
        let mut sender = Account::new(from);
        sender.balance = U256::from(100_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let tx = signed_transfer(&sender_key, to, 1_000, 0);
        let gas_cost = tx.gas_cost();
        let root = state
            .state_transition(&tx)
            .expect("state transition should succeed");

        assert_eq!(root, state.state_root());
        assert_eq!(
            state
                .get_balance(&from)
                .expect("sender balance read should succeed"),
            U256::from(100_000u64) - U256::from(1_000u64) - gas_cost
        );
        assert_eq!(
            state
                .get_nonce(&from)
                .expect("sender nonce read should succeed"),
            1
        );
        assert_eq!(
            state
                .get_balance(&to)
                .expect("recipient balance read should succeed"),
            U256::from(1_000u64)
        );

        cleanup(storage, path);
    }

    #[test]
    fn state_transition_updates_contract_storage_for_contract_calls() {
        let (storage, state, path) = test_db("state-transition-contract-call");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[30u8; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let contract = Address([31u8; 32]);

        let mut sender = Account::new(from);
        sender.balance = U256::from(200_000u64);
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let mut contract_account = Account::new(contract);
        contract_account
            .set_code_hash([1u8; 32])
            .expect("code hash must be accepted");
        state
            .update_account(&contract, &contract_account)
            .expect("contract account update should succeed");

        let data = vec![1u8, 2, 3, 4];
        let mut tx =
            Transaction::new_contract_call(from, contract, U256::from(500u64), 0, data.clone());
        tx.sign(&signing_key).expect("tx must be signed");
        let expected_storage_key = keccak256_bytes(&data);
        let expected_storage_value = tx.try_hash().unwrap();

        state
            .state_transition(&tx)
            .expect("contract call state transition should succeed");

        assert_eq!(
            state
                .get_storage(&contract, expected_storage_key)
                .expect("storage read should succeed"),
            Some(expected_storage_value)
        );
        assert_eq!(
            state
                .get_balance(&contract)
                .expect("contract balance read should succeed"),
            U256::from(500u64)
        );

        cleanup(storage, path);
    }

    #[test]
    fn state_transition_rejects_nonce_and_balance_violations() {
        let (storage, state, path) = test_db("state-transition-validation");
        let from = Address([32u8; 32]);
        let to = Address([33u8; 32]);

        let mut sender = Account::new(from);
        sender.balance = U256::from(500u64);
        sender.nonce = 3;
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        let wrong_nonce_tx = Transaction::new_transfer(from, to, U256::from(1u64), 0);
        assert!(state.state_transition(&wrong_nonce_tx).is_err());

        let insufficient_balance_tx = Transaction::new_transfer(from, to, U256::from(10_000u64), 3);
        assert!(state.state_transition(&insufficient_balance_tx).is_err());

        cleanup(storage, path);
    }

    /// REGRESSION (transition atomicity): `state_transition` previously
    /// persisted the debited sender BEFORE deriving the canonical tx hash.
    /// For Ethereum-wrapped transactions hash derivation re-verifies the
    /// signed envelope and can fail — a poisoned envelope therefore burned
    /// gas and value while never crediting the counterparty. All fallible
    /// validation now runs before any persistence.
    #[test]
    fn state_transition_poisoned_envelope_leaves_no_side_effects() {
        let (storage, state, path) = test_db("state-transition-atomicity");
        let from = Address([34u8; 32]);
        let to = Address([35u8; 32]);

        let mut sender = Account::new(from);
        let initial_balance = U256::from(1_000_000u64);
        sender.balance = initial_balance;
        state
            .update_account(&from, &sender)
            .expect("sender update should succeed");

        // A native transfer carrying a CORRUPT Ethereum envelope marker:
        // validate_basic passes (native fields are well-formed), but
        // try_hash() re-verifies ethereum_raw strictly and fails.
        let mut poisoned = Transaction::new_transfer(from, to, U256::from(100u64), 0);
        poisoned.ethereum_raw = Some(vec![0xde, 0xad, 0xbe, 0xef]);
        poisoned.ethereum_sighash = Some([7u8; 32]);
        assert!(poisoned.try_hash().is_err());

        assert!(state.state_transition(&poisoned).is_err());

        // The ledger must be untouched: no gas burn, no nonce increment,
        // no partial debit.
        let after = state.load_account(&from).unwrap().expect("sender exists");
        assert_eq!(after.balance, initial_balance, "sender must not be debited");
        assert_eq!(after.nonce, 0, "nonce must not advance");
        assert!(
            state.load_account(&to).unwrap().is_none(),
            "no phantom recipient"
        );

        cleanup(storage, path);
    }

    /// REGRESSION (self-transfer): when recipient == sender, planning must
    /// continue from the already-debited in-memory sender. Persisting two
    /// independently-planned rows for one account would be last-write-wins —
    /// the recipient row silently erasing the gas debit and nonce increment.
    #[test]
    fn self_transfer_charges_gas_and_advances_nonce_exactly_once() {
        let (storage, state, path) = test_db("self-transfer");
        let sender_key = signing_key(0x14);
        let from = Address::from_public_key(&sender_key.verifying_key().to_bytes());

        let mut sender = Account::new(from);
        sender.balance = U256::from(10_000_000u64);
        state.update_account(&from, &sender).expect("seed account");

        let value = U256::from(500u64);
        let mut tx = Transaction::new_transfer(from, from, value, 0);
        tx.gas_limit = 21_000;
        tx.gas_price = primitive_types::U256::one();
        tx.sign(&sender_key)
            .expect("sample transaction must sign with its sender key");
        let expected_gas = tx.gas_cost();

        state
            .state_transition(&tx)
            .expect("self transfer should execute");

        let after = state.load_account(&from).unwrap().expect("account exists");
        assert_eq!(
            after.balance,
            U256::from(10_000_000u64) - expected_gas,
            "value returns to sender; only gas is consumed"
        );
        assert_eq!(after.nonce, 1, "nonce advances exactly once");

        cleanup(storage, path);
    }

    #[test]
    fn prune_historical_state_respects_archive_mode() {
        let (storage, state, path) = test_db("pruning-archive");
        let address = Address([40u8; 32]);
        for height in 0..5u64 {
            state
                .set_balance(&address, U256::from(height + 1))
                .expect("balance");
            state.snapshot_state(height).expect("snapshot");
        }
        // Default mode is Archive.
        let deleted = state.prune_historical_state(4).expect("prune");
        assert_eq!(deleted, 0);
        assert!(storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .unwrap()
            .is_some());
        cleanup(storage, path);
    }

    #[test]
    fn prune_historical_state_pruned_mode_deletes_old_snapshots() {
        let (storage, mut state, path) = test_db("pruning-pruned-mode");
        state.pruning_mode = super::PruningMode::Pruned(2);
        let address = Address([41u8; 32]);

        for height in 0..6u64 {
            state
                .set_balance(&address, U256::from(100 + height))
                .expect("balance");
            state.snapshot_state(height).expect("snapshot");
        }

        // finalized=5, retain=2 - prune_target = 5-2-1 = 2 - delete heights - 2
        let deleted = state.prune_historical_state(5).expect("prune");
        assert!(deleted > 0, "expected snapshot keys to be deleted");

        assert!(storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .unwrap()
            .is_none());
        assert!(storage
            .state_get(b"snapshot:meta:2:type".to_vec())
            .unwrap()
            .is_none());
        // Retained window should still have recent snapshots.
        assert!(storage
            .state_get(b"snapshot:meta:5:type".to_vec())
            .unwrap()
            .is_some());

        // Live account state must survive pruning.
        assert_eq!(state.get_balance(&address).unwrap(), U256::from(105u64));

        cleanup(storage, path);
    }

    #[test]
    fn prune_historical_state_minimal_keeps_only_latest_snapshot() {
        let (storage, mut state, path) = test_db("pruning-minimal");
        state.pruning_mode = super::PruningMode::Minimal;
        let address = Address([42u8; 32]);

        for height in 0..4u64 {
            state
                .set_balance(&address, U256::from(height + 1))
                .expect("balance");
            state.snapshot_state(height).expect("snapshot");
        }

        // finalized=3 - prune_target=2 - delete -2, keep 3
        let deleted = state.prune_historical_state(3).expect("prune");
        assert!(deleted > 0);

        assert!(storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .unwrap()
            .is_none());
        assert!(storage
            .state_get(b"snapshot:meta:2:type".to_vec())
            .unwrap()
            .is_none());
        assert!(storage
            .state_get(b"snapshot:meta:3:type".to_vec())
            .unwrap()
            .is_some());

        // Latest snapshot must still load.
        let restored = state.load_snapshot(3).expect("load latest");
        assert_eq!(restored, state.state_root());

        cleanup(storage, path);
    }

    #[test]
    fn prune_historical_materializes_full_base_for_retained_incremental() {
        let (storage, mut state, path) = test_db("pruning-materialize");
        state.pruning_mode = super::PruningMode::Pruned(1);
        let address = Address([43u8; 32]);

        // height 0 is full; 1..=3 are incremental (dirty keys each step).
        for height in 0..4u64 {
            state
                .set_balance(&address, U256::from(10 + height))
                .expect("balance");
            state.snapshot_state(height).expect("snapshot");
        }

        // Confirm height 3 is incremental before prune.
        let ty = storage
            .state_get(b"snapshot:meta:3:type".to_vec())
            .unwrap()
            .unwrap();
        assert_eq!(ty, b"incremental");

        // finalized=3, retain=1 - prune_target=1; keep 2,3.
        // Chain for 3 is full@0 + incr@1..3; materialize oldest keep (2).
        state.prune_historical_state(3).expect("prune");

        assert!(storage
            .state_get(b"snapshot:meta:0:type".to_vec())
            .unwrap()
            .is_none());
        assert!(storage
            .state_get(b"snapshot:meta:1:type".to_vec())
            .unwrap()
            .is_none());

        // Oldest kept should now be full (materialized).
        let keep_ty = storage
            .state_get(b"snapshot:meta:2:type".to_vec())
            .unwrap()
            .expect("height 2 retained");
        assert_eq!(keep_ty.as_slice(), b"full");

        // Can still restore height 3 after base materialization.
        let root = state.load_snapshot(3).expect("restore after prune");
        assert_eq!(root, state.state_root());

        cleanup(storage, path);
    }

    #[test]
    fn delete_account_cleans_up_contract_storage_slots_and_vesting() {
        let (storage, state, path) = test_db("delete-account-storage");
        let address = Address([88u8; 32]);
        let slot = [89u8; 32];
        let val = [90u8; 32];

        state.create_account(address).expect("create");
        state.set_storage(&address, slot, val).expect("storage");
        state
            .set_vesting_schedule(
                &address,
                sxiaum_types::vesting::VestingSchedule::new(U256::from(100u64), 0, 0, 100).expect("valid vesting"),
            )
            .expect("vesting");

        assert!(state.account_exists(&address).unwrap());
        assert_eq!(state.get_storage(&address, slot).unwrap(), Some(val));
        assert!(state.get_vesting_schedule(&address).unwrap().is_some());

        state.delete_account(&address).expect("delete");

        assert!(!state.account_exists(&address).unwrap());
        assert_eq!(state.get_storage(&address, slot).unwrap(), None);
        assert!(state.get_vesting_schedule(&address).unwrap().is_none());

        // Rebuilding from storage should not resurrect deleted contract storage
        let rebuilt = state.rebuild_tree_from_storage().unwrap();
        assert_eq!(rebuilt, state.state_root());

        cleanup(storage, path);
    }

    #[test]
    fn vesting_schedule_respects_undo_log_on_rollback() {
        let (_storage, state, path) = test_db("vesting-undo");
        let address = Address([91u8; 32]);
        let initial_root = state.commit().expect("commit");

        state
            .set_vesting_schedule(
                &address,
                sxiaum_types::vesting::VestingSchedule::new(U256::from(1234u64), 50, 10, 100).expect("valid vesting"),
            )
            .expect("vesting");

        assert!(state.get_vesting_schedule(&address).unwrap().is_some());
        state.rollback().expect("rollback");
        assert_eq!(state.get_vesting_schedule(&address).unwrap(), None);
        assert_eq!(state.state_root(), initial_root);

        cleanup(_storage, path);
    }
}
