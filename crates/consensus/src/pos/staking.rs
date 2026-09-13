use anyhow::{bail, Result};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Canonical, Validator};

const STAKING_STATE_PREFIX: &[u8] = b"staking:";
const DEFAULT_LOCKUP_PERIOD_EPOCHS: u64 = 7;

/// Minimum validator self-stake (in smallest units) required to
/// participate in consensus on mainnet.
pub const MIN_VALIDATOR_STAKE: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Stake {
    pub validator: Address,
    pub amount: U256,
}

pub struct StakingManager {
    stakes: HashMap<Address, Stake>,
    delegations: HashMap<(Address, Address), U256>,
    /// SECURITY (H-10): epoch at which each validator position was created or
    /// last topped up. Lockup maturity is measured against THIS value, not
    /// the global epoch counter (which after ~`lockup_epochs` epochs made
    /// every future deposit instantly withdrawable).
    deposit_epochs: HashMap<Address, u64>,
    /// Per-delegation deposit epochs (same rationale as `deposit_epochs`).
    delegation_epochs: HashMap<(Address, Address), u64>,
    current_epoch: u64,
    lockup_epochs: u64,
    storage: Option<Arc<StorageEngine>>,
    /// SECURITY (H-11): set only after a FULL successful restore. A failed or
    /// partial restore must never enable the diff-based stale-key deletion in
    /// `staking_state_persistence`, because every storage row absent from the
    /// (empty/partial) memory maps would be deleted — one transient boot
    /// error converting the next write into mass deletion of all stakes.
    fully_restored: bool,
}

impl Default for StakingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StakingManager {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            delegations: HashMap::new(),
            deposit_epochs: HashMap::new(),
            delegation_epochs: HashMap::new(),
            current_epoch: 0,
            lockup_epochs: DEFAULT_LOCKUP_PERIOD_EPOCHS,
            storage: None,
            fully_restored: false,
        }
    }

    pub fn with_storage(storage: Arc<StorageEngine>) -> Self {
        let mut manager = Self::new();
        manager.storage = Some(storage);
        if let Err(e) = manager.restore() {
            // SECURITY (H-11): never proceed as if state were loaded. The
            // `fully_restored` flag stays false so persistence refuses to
            // issue deletions for rows we failed to load.
            tracing::error!(
                "Failed to restore StakingManager state (deletion-diff disabled \
                 until a clean restart): {:?}",
                e
            );
        }
        manager
    }

    pub fn load_or_init(storage: Arc<StorageEngine>) -> Result<Self> {
        let mut manager = Self::new();
        manager.storage = Some(storage);
        manager.restore()?;
        Ok(manager)
    }

    pub fn restore(&mut self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };

        // 1. Restore epoch
        if let Some(bytes) = storage.state_get(Self::epoch_key())? {
            if bytes.len() == 8 {
                let mut epoch_bytes = [0u8; 8];
                epoch_bytes.copy_from_slice(&bytes);
                self.current_epoch = u64::from_le_bytes(epoch_bytes);
            }
        }

        // 2. Restore stakes (+ their deposit epochs)
        let stakes_scan = storage.state_prefix_scan(Self::stake_prefix())?;
        for (key, bytes) in stakes_scan {
            if let Some(addr_bytes) = Self::decode_stake_key(&key) {
                let stake: Stake = <Stake as Canonical>::decode(&bytes)
                    .or_else(|_| bincode::deserialize(&bytes))?;
                self.stakes.insert(addr_bytes, stake);
            }
        }
        let deposit_epochs_scan = storage.state_prefix_scan(Self::stake_epoch_prefix())?;
        for (key, bytes) in deposit_epochs_scan {
            if let Some(addr_bytes) = Self::decode_stake_epoch_key(&key) {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    self.deposit_epochs
                        .insert(addr_bytes, u64::from_le_bytes(arr));
                }
            }
        }

        // 3. Restore delegations (+ their deposit epochs)
        let delegations_scan = storage.state_prefix_scan(Self::delegation_prefix())?;
        for (key, bytes) in delegations_scan {
            if let Some((delegator, validator)) = Self::decode_delegation_key(&key) {
                let amount: U256 = <U256 as Canonical>::decode(&bytes)
                    .or_else(|_| bincode::deserialize(&bytes))?;
                self.delegations.insert((delegator, validator), amount);
            }
        }
        let delegation_epochs_scan = storage.state_prefix_scan(Self::delegation_epoch_prefix())?;
        for (key, bytes) in delegation_epochs_scan {
            if let Some((del, val)) = Self::decode_delegation_epoch_key(&key) {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    self.delegation_epochs
                        .insert((del, val), u64::from_le_bytes(arr));
                }
            }
        }

        self.fully_restored = true;
        Ok(())
    }

    pub fn stake_tokens(&mut self, validator: Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            bail!("stake amount must be greater than zero");
        }
        if amount < U256::from(MIN_VALIDATOR_STAKE) {
            bail!(
                "stake amount {} below minimum {}",
                amount,
                MIN_VALIDATOR_STAKE
            );
        }

        // SECURITY (H-10): any top-up re-locks the whole position from the
        // current epoch. This is conservative by design: without per-amount
        // maturity tracking, a fresh deposit could otherwise ride an old
        // position's timer and be withdrawn before punishment matures.
        self.deposit_epochs.insert(validator, self.current_epoch);

        let entry = self.stakes.entry(validator).or_insert(Stake {
            validator,
            amount: U256::zero(),
        });
        entry.amount = entry.amount.saturating_add(amount);
        self.staking_state_persistence()
    }

    pub fn unstake_tokens(&mut self, validator: &Address, amount: U256) -> Result<()> {
        if amount.is_zero() {
            bail!("unstake amount must be greater than zero");
        }
        // SECURITY (H-10): lockup maturity is measured against the epoch at
        // which THIS position was deposited, not the global epoch counter.
        let deposit_epoch = *self
            .deposit_epochs
            .get(validator)
            .ok_or_else(|| anyhow::anyhow!("validator {} has no stake", validator))?;
        let unlock_epoch = deposit_epoch.saturating_add(self.lockup_period());
        if self.current_epoch < unlock_epoch {
            bail!(
                "stake is still locked until epoch {} (current epoch {}, deposited at epoch {})",
                unlock_epoch,
                self.current_epoch,
                deposit_epoch
            );
        }

        let entry = self
            .stakes
            .get_mut(validator)
            .ok_or_else(|| anyhow::anyhow!("validator {} has no stake", validator))?;
        if entry.amount < amount {
            bail!("insufficient stake for validator {}", validator);
        }

        entry.amount -= amount;
        if entry.amount.is_zero() {
            self.stakes.remove(validator);
            self.deposit_epochs.remove(validator);
        }

        self.staking_state_persistence()
    }

    pub fn delegate_stake(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            bail!("delegation amount must be greater than zero");
        }

        // SECURITY (H-10): track delegation deposit epoch (see stake_tokens).
        self.delegation_epochs
            .insert((delegator, validator), self.current_epoch);

        let entry = self.stakes.entry(validator).or_insert(Stake {
            validator,
            amount: U256::zero(),
        });
        entry.amount = entry.amount.saturating_add(amount);

        let key = (delegator, validator);
        let delegated = self.delegations.entry(key).or_insert(U256::zero());
        *delegated = delegated.saturating_add(amount);

        self.staking_state_persistence()
    }

    pub fn slash_validator(&mut self, validator: &Address, amount: U256) -> Result<()> {
        let stake = self
            .stakes
            .get_mut(validator)
            .ok_or_else(|| anyhow::anyhow!("validator {} has no stake", validator))?;
        stake.amount = stake.amount.saturating_sub(amount);
        if stake.amount.is_zero() {
            self.stakes.remove(validator);
            self.deposit_epochs.remove(validator);
        }
        self.staking_state_persistence()
    }

    pub fn undelegate_stake(
        &mut self,
        delegator: Address,
        validator: Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            bail!("undelegation amount must be greater than zero");
        }
        // SECURITY (H-10): per-delegation lockup maturity.
        let key = (delegator, validator);
        let deposit_epoch = *self
            .delegation_epochs
            .get(&key)
            .ok_or_else(|| anyhow::anyhow!("no delegation found for delegator {}", delegator))?;
        let unlock_epoch = deposit_epoch.saturating_add(self.lockup_period());
        if self.current_epoch < unlock_epoch {
            bail!(
                "stake is still locked until epoch {} (current epoch {}, delegated at epoch {})",
                unlock_epoch,
                self.current_epoch,
                deposit_epoch
            );
        }

        let delegated = self
            .delegations
            .get_mut(&key)
            .ok_or_else(|| anyhow::anyhow!("no delegation found for delegator {}", delegator))?;
        if *delegated < amount {
            bail!("insufficient delegated stake: {} < {}", *delegated, amount);
        }

        let entry = self
            .stakes
            .get_mut(&validator)
            .ok_or_else(|| anyhow::anyhow!("validator {} has no stake", validator))?;
        if entry.amount < amount {
            bail!("insufficient stake for validator {}", validator);
        }

        *delegated = delegated.saturating_sub(amount);
        if delegated.is_zero() {
            self.delegations.remove(&key);
            self.delegation_epochs.remove(&key);
        }

        entry.amount -= amount;
        if entry.amount.is_zero() {
            self.stakes.remove(&validator);
            self.deposit_epochs.remove(&validator);
        }

        self.staking_state_persistence()
    }

    pub fn reward_validator(&mut self, validator: &Address, amount: U256) -> Result<()> {
        let entry = self.stakes.entry(*validator).or_insert(Stake {
            validator: *validator,
            amount: U256::zero(),
        });
        entry.amount = entry.amount.saturating_add(amount);
        self.staking_state_persistence()
    }

    pub fn calculate_voting_power(&self, validator: &Address) -> u64 {
        self.stakes
            .get(validator)
            .map(|stake| Validator::calculate_voting_power(stake.amount))
            .unwrap_or(0)
    }

    pub fn staking_epoch_update(&mut self) -> Result<u64> {
        self.current_epoch = self.current_epoch.saturating_add(1);
        self.staking_state_persistence()?;
        Ok(self.current_epoch)
    }

    pub fn lockup_period(&self) -> u64 {
        self.lockup_epochs
    }

    pub fn staking_state_persistence(&self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };

        // Scan existing keys in storage to detect deleted stakes and delegations
        let existing_stakes = storage.state_prefix_scan(Self::stake_prefix())?;
        let existing_delegations = storage.state_prefix_scan(Self::delegation_prefix())?;
        // SECURITY (H-11): deletion diffs are only computed when memory holds
        // a FULL successful restore of on-disk state. Otherwise "not in
        // memory" means "failed to load", not "deleted", and issuing `None`
        // deletions would wipe every stake/delegation row.
        let deletion_diffs_enabled = self.fully_restored;

        let mut changes = Vec::with_capacity(
            self.stakes.len()
                + self.delegations.len()
                + self.deposit_epochs.len()
                + self.delegation_epochs.len()
                + existing_stakes.len()
                + existing_delegations.len()
                + 1,
        );

        changes.push((
            Self::epoch_key(),
            Some(self.current_epoch.to_le_bytes().to_vec()),
        ));

        // 1. Persist active stakes
        for (validator, stake) in &self.stakes {
            changes.push((
                Self::stake_key(validator),
                <Stake as Canonical>::try_encode(stake).ok(),
            ));
            if let Some(epoch) = self.deposit_epochs.get(validator) {
                changes.push((
                    Self::stake_epoch_key(validator),
                    Some(epoch.to_le_bytes().to_vec()),
                ));
            }
        }

        // 2. Delete any stale stakes previously persisted in storage
        if deletion_diffs_enabled {
            for (key, _) in existing_stakes {
                if let Some(addr) = Self::decode_stake_key(&key) {
                    if !self.stakes.contains_key(&addr) {
                        changes.push((key, None));
                        changes.push((Self::stake_epoch_key(&addr), None));
                    }
                }
            }
        }

        // 3. Persist active delegations
        for ((delegator, validator), amount) in &self.delegations {
            changes.push((
                Self::delegation_key(delegator, validator),
                <U256 as Canonical>::try_encode(amount).ok(),
            ));
            if let Some(epoch) = self.delegation_epochs.get(&(*delegator, *validator)) {
                changes.push((
                    Self::delegation_epoch_key(delegator, validator),
                    Some(epoch.to_le_bytes().to_vec()),
                ));
            }
        }

        // 4. Delete any stale delegations previously persisted in storage
        if deletion_diffs_enabled {
            for (key, _) in existing_delegations {
                if let Some((del, val)) = Self::decode_delegation_key(&key) {
                    if !self.delegations.contains_key(&(del, val)) {
                        changes.push((key, None));
                        changes.push((Self::delegation_epoch_key(&del, &val), None));
                    }
                }
            }
        }

        if !deletion_diffs_enabled {
            tracing::warn!(
                "staking persistence running with deletions disabled (restore incomplete)"
            );
        }

        storage.atomic_state_commit(changes)
    }

    pub fn stake(&mut self, address: Address, amount: U256) {
        let _ = self.stake_tokens(address, amount);
    }

    pub fn get_stake(&self, address: &Address) -> U256 {
        self.stakes
            .get(address)
            .map(|stake| stake.amount)
            .unwrap_or_else(U256::zero)
    }

    pub fn validator_stake(&self, validator: &Validator) -> U256 {
        self.get_stake(&validator.address)
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    fn stake_key(validator: &Address) -> Vec<u8> {
        let mut key = Self::stake_prefix();
        key.extend_from_slice(validator.as_bytes());
        key
    }

    fn delegation_key(delegator: &Address, validator: &Address) -> Vec<u8> {
        let mut key = Self::delegation_prefix();
        key.extend_from_slice(delegator.as_bytes());
        key.extend_from_slice(validator.as_bytes());
        key
    }

    fn epoch_key() -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"epoch");
        key
    }

    fn stake_prefix() -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"stake:");
        key
    }

    fn stake_epoch_prefix() -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"stakeepoch:");
        key
    }

    fn stake_epoch_key(validator: &Address) -> Vec<u8> {
        let mut key = Self::stake_epoch_prefix();
        key.extend_from_slice(validator.as_bytes());
        key
    }

    fn delegation_epoch_prefix() -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"delegateepoch:");
        key
    }

    fn delegation_epoch_key(delegator: &Address, validator: &Address) -> Vec<u8> {
        let mut key = Self::delegation_epoch_prefix();
        key.extend_from_slice(delegator.as_bytes());
        key.extend_from_slice(validator.as_bytes());
        key
    }

    fn delegation_prefix() -> Vec<u8> {
        let mut key = STAKING_STATE_PREFIX.to_vec();
        key.extend_from_slice(b"delegate:");
        key
    }

    fn decode_stake_key(key: &[u8]) -> Option<Address> {
        let prefix = Self::stake_prefix();
        if key.starts_with(&prefix) && key.len() == prefix.len() + 32 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&key[prefix.len()..]);
            Some(Address(addr))
        } else {
            None
        }
    }

    fn decode_stake_epoch_key(key: &[u8]) -> Option<Address> {
        let prefix = Self::stake_epoch_prefix();
        if key.starts_with(&prefix) && key.len() == prefix.len() + 32 {
            let mut addr = [0u8; 32];
            addr.copy_from_slice(&key[prefix.len()..]);
            Some(Address(addr))
        } else {
            None
        }
    }

    fn decode_delegation_epoch_key(key: &[u8]) -> Option<(Address, Address)> {
        let prefix = Self::delegation_epoch_prefix();
        if key.starts_with(&prefix) && key.len() == prefix.len() + 64 {
            let mut del = [0u8; 32];
            let mut val = [0u8; 32];
            del.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
            val.copy_from_slice(&key[prefix.len() + 32..]);
            Some((Address(del), Address(val)))
        } else {
            None
        }
    }

    fn decode_delegation_key(key: &[u8]) -> Option<(Address, Address)> {
        let prefix = Self::delegation_prefix();
        if key.starts_with(&prefix) && key.len() == prefix.len() + 64 {
            let mut del = [0u8; 32];
            let mut val = [0u8; 32];
            del.copy_from_slice(&key[prefix.len()..prefix.len() + 32]);
            val.copy_from_slice(&key[prefix.len() + 32..]);
            Some((Address(del), Address(val)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Stake, StakingManager};
    use primitive_types::U256;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use sxiaum_storage::StorageEngine;
    use sxiaum_types::{Address, Canonical, Validator};

    fn unique_storage_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!("sxiaum-{name}-{unique}.redb"))
    }

    fn test_storage(name: &str) -> (Arc<StorageEngine>, PathBuf) {
        let path = unique_storage_path(name);
        let storage = Arc::new(
            StorageEngine::new(path.to_string_lossy().as_ref())
                .expect("test storage should initialize"),
        );
        (storage, path)
    }

    fn cleanup_storage(path: PathBuf) {
        let _ = fs::remove_file(path);
    }

    fn addr(seed: u8) -> Address {
        Address([seed; 32])
    }

    fn amount(units: u64) -> U256 {
        U256::from(units) * U256::from(10u64.pow(18))
    }

    fn validator(seed: u8) -> Validator {
        Validator::new(addr(seed), [seed; 32], amount(1))
    }

    #[test]
    fn stake_struct_and_basic_stake_reward_slash_flows_work() {
        let validator_address = addr(1);
        let sample = Stake {
            validator: validator_address,
            amount: amount(2),
        };
        assert_eq!(sample.validator, validator_address);
        assert_eq!(sample.amount, amount(2));

        let mut manager = StakingManager::new();
        manager
            .stake_tokens(validator_address, amount(3))
            .expect("staking should succeed");
        manager
            .reward_validator(&validator_address, amount(2))
            .expect("reward should succeed");
        manager
            .slash_validator(&validator_address, amount(1))
            .expect("slash should succeed");

        assert_eq!(manager.get_stake(&validator_address), amount(4));
        assert_eq!(manager.calculate_voting_power(&validator_address), 4);
    }

    #[test]
    fn unstake_respects_lockup_and_removes_zeroed_stake() {
        let validator_address = addr(2);
        let mut manager = StakingManager::new();
        manager
            .stake_tokens(validator_address, amount(2))
            .expect("staking should succeed");

        assert_eq!(manager.lockup_period(), 7);
        assert!(manager
            .unstake_tokens(&validator_address, amount(1))
            .is_err());

        for _ in 0..manager.lockup_period() {
            manager
                .staking_epoch_update()
                .expect("epoch update should succeed");
        }

        manager
            .unstake_tokens(&validator_address, amount(2))
            .expect("unstake after lockup should succeed");
        assert_eq!(manager.get_stake(&validator_address), U256::zero());
        assert_eq!(manager.calculate_voting_power(&validator_address), 0);
    }

    #[test]
    fn delegate_stake_increases_delegatee_stake_and_voting_power() {
        let delegator = addr(3);
        let validator_address = addr(4);
        let mut manager = StakingManager::new();

        manager
            .delegate_stake(delegator, validator_address, amount(5))
            .expect("delegation should succeed");

        assert_eq!(manager.get_stake(&validator_address), amount(5));
        assert_eq!(manager.calculate_voting_power(&validator_address), 5);
    }

    #[test]
    fn staking_epoch_update_and_validator_helpers_reflect_state() {
        let validator = validator(5);
        let mut manager = StakingManager::new();

        manager.stake(validator.address, amount(6));
        assert_eq!(manager.validator_stake(&validator), amount(6));
        assert_eq!(
            manager
                .staking_epoch_update()
                .expect("epoch should advance"),
            1
        );
        assert_eq!(
            manager
                .staking_epoch_update()
                .expect("epoch should advance"),
            2
        );
    }

    #[test]
    fn staking_state_persistence_writes_epoch_stakes_and_delegations() {
        let (storage, path) = test_storage("staking-persistence");
        let validator_address = addr(6);
        let delegator = addr(7);
        let mut manager = StakingManager::with_storage(storage.clone());

        manager
            .stake_tokens(validator_address, amount(2))
            .expect("staking should succeed");
        manager
            .delegate_stake(delegator, validator_address, amount(1))
            .expect("delegation should succeed");
        manager
            .staking_epoch_update()
            .expect("epoch update should persist");

        let epoch_key = [b"staking:".as_slice(), b"epoch".as_slice()].concat();
        let epoch_bytes = storage
            .state_get(epoch_key)
            .expect("epoch read should succeed")
            .expect("epoch should be stored");
        let mut epoch_arr = [0u8; 8];
        epoch_arr.copy_from_slice(&epoch_bytes);
        assert_eq!(u64::from_le_bytes(epoch_arr), 1);

        let mut stake_key = b"staking:stake:".to_vec();
        stake_key.extend_from_slice(validator_address.as_bytes());
        let stored_stake: Stake = <Stake as Canonical>::decode(
            &storage
                .state_get(stake_key)
                .expect("stake read should succeed")
                .expect("stake should be stored"),
        )
        .expect("stake should deserialize");
        assert_eq!(stored_stake.amount, amount(3));

        let mut delegation_key = b"staking:delegate:".to_vec();
        delegation_key.extend_from_slice(delegator.as_bytes());
        delegation_key.extend_from_slice(validator_address.as_bytes());
        let stored_delegation: U256 = <U256 as Canonical>::decode(
            &storage
                .state_get(delegation_key)
                .expect("delegation read should succeed")
                .expect("delegation should be stored"),
        )
        .expect("delegation should deserialize");
        assert_eq!(stored_delegation, amount(1));

        cleanup_storage(path);
    }

    #[test]
    fn unstake_and_restore_does_not_resurrect_stake() {
        let (storage, path) = test_storage("staking-unstake-restore");
        let validator_address = addr(8);
        let mut manager = StakingManager::with_storage(storage.clone());

        manager
            .stake_tokens(validator_address, amount(5))
            .expect("stake should succeed");
        assert_eq!(manager.get_stake(&validator_address), amount(5));

        // Advance epochs past lockup
        for _ in 0..manager.lockup_period() {
            manager.staking_epoch_update().unwrap();
        }

        // Completely unstake
        manager
            .unstake_tokens(&validator_address, amount(5))
            .expect("unstake should succeed");
        assert_eq!(manager.get_stake(&validator_address), U256::zero());

        // Simulate reboot: create new manager and restore from storage
        let restored = StakingManager::with_storage(storage.clone());
        assert_eq!(
            restored.get_stake(&validator_address),
            U256::zero(),
            "unstaked validator must not be resurrected upon restore"
        );

        cleanup_storage(path);
    }

    #[test]
    fn undelegate_stake_flow_works() {
        let delegator = addr(9);
        let validator_address = addr(10);
        let mut manager = StakingManager::new();

        manager
            .delegate_stake(delegator, validator_address, amount(4))
            .unwrap();
        assert_eq!(manager.get_stake(&validator_address), amount(4));

        // Attempting undelegate before lockup fails
        assert!(manager
            .undelegate_stake(delegator, validator_address, amount(2))
            .is_err());

        for _ in 0..manager.lockup_period() {
            manager.staking_epoch_update().unwrap();
        }

        // Partial undelegate
        manager
            .undelegate_stake(delegator, validator_address, amount(2))
            .unwrap();
        assert_eq!(manager.get_stake(&validator_address), amount(2));

        // Full undelegate
        manager
            .undelegate_stake(delegator, validator_address, amount(2))
            .unwrap();
        assert_eq!(manager.get_stake(&validator_address), U256::zero());
    }

    // SECURITY REGRESSION (H-10): lockup maturity must be measured from the
    // DEPOSIT epoch. Previously the check compared the GLOBAL epoch against a
    // constant, so after epoch ~7 every future deposit was instantly
    // withdrawable (stake -> vote -> unstake before punishment matures).
    #[test]
    fn fresh_deposit_is_locked_even_when_global_epoch_exceeds_lockup() {
        let validator_address = addr(11);
        let mut manager = StakingManager::new();

        // Push the GLOBAL epoch far past the lockup constant BEFORE staking.
        for _ in 0..(manager.lockup_period() * 3) {
            manager.staking_epoch_update().unwrap();
        }
        assert!(manager.current_epoch() > manager.lockup_period());

        manager
            .stake_tokens(validator_address, amount(3))
            .expect("staking should succeed");

        // The brand-new position must still be locked despite global epoch.
        assert!(
            manager
                .unstake_tokens(&validator_address, amount(1))
                .is_err(),
            "fresh deposit must not be withdrawable just because the global epoch is old"
        );

        // Advancing exactly lockup-period epochs from the deposit unlocks it.
        for _ in 0..manager.lockup_period() {
            manager.staking_epoch_update().unwrap();
        }
        manager
            .unstake_tokens(&validator_address, amount(1))
            .expect("stake should unlock after its own lockup window");
    }
}
