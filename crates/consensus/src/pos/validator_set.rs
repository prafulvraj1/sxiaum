use anyhow::{bail, Result};
use primitive_types::U256;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use sxiaum_crypto::bls::{verify_proof_of_possession, BlsPublicKey, BlsSignature};
use sxiaum_types::{Address, Validator};

/// Maximum number of active validators allowed on mainnet.
/// This limits the consensus message overhead and ensures
/// the BLS aggregate signature verification stays performant.
pub const MAX_ACTIVE_VALIDATORS: usize = 200;

pub struct ValidatorSet {
    validators: HashMap<Address, Validator>,
    total_stake: U256,
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            total_stake: U256::zero(),
        }
    }

    pub fn add_validator(&mut self, validator: Validator) -> Result<()> {
        let is_new = !self.validators.contains_key(&validator.address);
        if is_new
            && validator.is_active()
            && self.active_validators().len() >= MAX_ACTIVE_VALIDATORS
        {
            bail!(
                "maximum active validator count {} reached",
                MAX_ACTIVE_VALIDATORS
            );
        }
        self.validate_validator(&validator)?;
        self.enforce_bls_pop(&validator)?;

        // Prevent rogue-key / duplicate BLS public key attacks across distinct validator addresses
        if let Some(ref bls_pk) = validator.bls_pubkey {
            for (existing_addr, existing_val) in &self.validators {
                if existing_addr != &validator.address {
                    if let Some(ref existing_bls) = existing_val.bls_pubkey {
                        if existing_bls == bls_pk {
                            bail!(
                                "duplicate BLS public key already registered by validator {}",
                                existing_addr
                            );
                        }
                    }
                }
            }
        }

        if let Some(existing) = self.validators.insert(validator.address, validator.clone()) {
            self.total_stake = self.total_stake.saturating_sub(existing.stake);
        }

        self.total_stake = self.total_stake.saturating_add(validator.stake);
        Ok(())
    }

    /// When a BLS public key is present, a valid Proof-of-Possession is mandatory
    /// (rogue-key protection for aggregate signatures).
    ///
    /// Every validator **must** carry a verified BLS PoP.
    fn enforce_bls_pop(&self, validator: &Validator) -> Result<()> {
        match (&validator.bls_pubkey, &validator.bls_pop) {
            (None, None) | (None, _) | (_, None) => {
                bail!(
                    "validator {} missing BLS pubkey + PoP (required for consensus)",
                    validator.address
                );
            }

            (Some(pk_bytes), Some(pop_bytes)) => {
                let pk = BlsPublicKey(pk_bytes.clone());
                let pop = BlsSignature(pop_bytes.clone());
                if !verify_proof_of_possession(&pk, &pop) {
                    bail!(
                        "validator {} BLS Proof-of-Possession verification failed",
                        validator.address
                    );
                }
                Ok(())
            }
        }
    }

    pub fn remove_validator(&mut self, address: &Address) -> Option<Validator> {
        let removed = self.validators.remove(address)?;
        self.total_stake = self.total_stake.saturating_sub(removed.stake);
        Some(removed)
    }

    pub fn total_stake(&self) -> U256 {
        self.total_stake
    }

    pub fn voting_power(&self, address: &Address) -> u64 {
        self.validators
            .get(address)
            .map(|validator| validator.voting_power)
            .unwrap_or(0)
    }

    pub fn validator(&self, address: &Address) -> Option<&Validator> {
        self.validators.get(address)
    }

    pub fn jail_validator(&mut self, address: &Address) -> Result<()> {
        if let Some(val) = self.validators.get_mut(address) {
            val.status = sxiaum_types::validator::ValidatorStatus::Jailed;
            val.voting_power = 0;
            Ok(())
        } else {
            bail!("Validator {} not found in set", address);
        }
    }

    pub fn slash_validator(&mut self, address: &Address, slash_amount: U256) -> Result<()> {
        if let Some(val) = self.validators.get_mut(address) {
            let old_stake = val.stake;
            val.slash(slash_amount);
            self.total_stake = self
                .total_stake
                .saturating_sub(old_stake)
                .saturating_add(val.stake);
            if val.stake.is_zero() {
                self.validators.remove(address);
            }
            Ok(())
        } else {
            bail!("Validator {} not found in set", address);
        }
    }

    pub fn leader_selection(&self, view: u64, seed: [u8; 32]) -> Option<Address> {
        let active = self.active_validators();
        if active.is_empty() {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(view.to_le_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let random_num = u64::from_le_bytes(bytes);

        let index = (random_num as usize) % active.len();
        Some(active[index].address)
    }

    pub fn quorum_threshold(&self) -> usize {
        let count = self.active_validators().len();
        if count == 0 {
            return 0;
        }
        ((count * 2) / 3) + 1
    }

    pub fn validate_validator(&self, validator: &Validator) -> Result<()> {
        validator.validate()?;
        if validator.pubkey == [0u8; 32] {
            bail!("validator {} has an empty public key", validator.address);
        }
        if validator.is_jailed() {
            bail!("validator {} is jailed", validator.address);
        }
        if validator.stake.is_zero() {
            bail!("validator {} has zero stake", validator.address);
        }
        Ok(())
    }

    pub fn active_validators(&self) -> Vec<Validator> {
        let mut active: Vec<Validator> = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .cloned()
            .collect();
        active.sort_by(|left, right| {
            right
                .voting_power
                .cmp(&left.voting_power)
                .then_with(|| left.address.as_bytes().cmp(right.address.as_bytes()))
        });
        active
    }

    pub fn all_validators(&self) -> Vec<Validator> {
        self.validators.values().cloned().collect()
    }

    /// Replace the entire validator set atomically.
    ///
    /// SECURITY (C-06): the whole incoming set is validated and staged in a
    /// temporary map BEFORE touching live state. The previous implementation
    /// cleared the live set and inserted one-by-one with `?`, so a single
    /// invalid element mid-loop aborted leaving an empty or partial set —
    /// bricking rotation, restart restore, and epoch transitions.
    pub fn replace_validators(&mut self, validators: Vec<Validator>) -> Result<()> {
        let mut staged: HashMap<Address, Validator> = HashMap::with_capacity(validators.len());
        let mut active_count = 0usize;
        let mut total_stake = U256::zero();

        for validator in validators {
            self.validate_validator(&validator)?;
            self.enforce_bls_pop(&validator)?;

            // Duplicate addresses inside one rotation are ambiguous → reject.
            if staged.contains_key(&validator.address) {
                bail!(
                    "duplicate validator address {} in replacement set",
                    validator.address
                );
            }

            // Duplicate BLS keys across distinct addresses enable rogue-key
            // aggregate-signature forgery; enforce within the new set too.
            if let Some(ref bls_pk) = validator.bls_pubkey {
                for existing in staged.values() {
                    if let Some(ref existing_bls) = existing.bls_pubkey {
                        if existing_bls == bls_pk {
                            bail!(
                                "duplicate BLS public key in replacement set (validator {})",
                                validator.address
                            );
                        }
                    }
                }
            }

            if validator.is_active() {
                active_count += 1;
                if active_count > MAX_ACTIVE_VALIDATORS {
                    bail!(
                        "maximum active validator count {} reached",
                        MAX_ACTIVE_VALIDATORS
                    );
                }
            }

            total_stake = total_stake.saturating_add(validator.stake);
            staged.insert(validator.address, validator);
        }

        // Commit point: only reached when every element validated cleanly.
        self.validators = staged;
        self.total_stake = total_stake;
        Ok(())
    }

    pub fn active_validator_count(&self) -> usize {
        self.active_validators().len()
    }

    /// Total voting power across active validators.
    ///
    /// SECURITY (H-12): saturating accumulation. Voting power derives from
    /// U256 stake truncated to u64; a plain `.sum()` can wrap on a large set,
    /// shrinking the total and collapsing the 2/3 quorum threshold toward 1.
    pub fn total_active_voting_power(&self) -> u64 {
        self.active_validators()
            .iter()
            .fold(0u64, |acc, validator| {
                acc.saturating_add(validator.voting_power)
            })
    }

    /// Returns the elected block proposer for a given view and randomness seed
    /// using deterministic stake-weighted VRF leader election.
    pub fn get_proposer(&self, view: u64, seed: [u8; 32]) -> Option<Address> {
        self.select_leader_weighted(view, seed)
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for validator in self.active_validators() {
            hasher.update(validator.address.as_bytes());
            hasher.update(validator.pubkey);
            let mut stake_bytes = [0u8; 32];
            validator.stake.to_little_endian(&mut stake_bytes);
            hasher.update(stake_bytes);
        }
        hasher.finalize().into()
    }

    /// Deterministic leader election using VRF-like stake-weighted selection.
    ///
    /// The selection is deterministic based on the view number and a seed,
    /// weighted by validator stake. This ensures:
    /// - Higher stake = higher probability of selection
    /// - Deterministic and verifiable by all nodes
    /// - Unpredictable without knowing the seed
    pub fn select_leader_weighted(&self, view: u64, seed: [u8; 32]) -> Option<Address> {
        let active = self.active_validators();
        if active.is_empty() {
            return None;
        }

        // SECURITY (H-12): saturating accumulation — see
        // `total_active_voting_power`. A wrapped total would skew the
        // election modulus and bias leader selection.
        let total_power: u64 = active
            .iter()
            .fold(0u64, |acc, v| acc.saturating_add(v.voting_power));
        if total_power == 0 {
            return self.leader_selection(view, seed);
        }

        // Generate deterministic random value from seed + view
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(view.to_le_bytes());
        let hash = hasher.finalize();

        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&hash[0..8]);
        let random_value = u64::from_le_bytes(bytes) % total_power;

        // Select validator using weighted random selection
        let mut cumulative = 0u64;
        for validator in &active {
            cumulative = cumulative.saturating_add(validator.voting_power);
            if random_value < cumulative {
                return Some(validator.address);
            }
        }

        // Fallback to last validator (should not happen)
        active.last().map(|v| v.address)
    }

    /// Check if a validator change should occur at this height (epoch boundary).
    pub fn is_epoch_boundary(&self, height: u64, epoch_length: u64) -> bool {
        height > 0 && height.is_multiple_of(epoch_length)
    }

    /// Apply epoch transition: update validator set at epoch boundaries.
    ///
    /// This ensures validator changes only happen at epoch boundaries,
    /// preventing mid-epoch validator set manipulation.
    pub fn apply_epoch_transition(
        &mut self,
        new_validators: Vec<Validator>,
        height: u64,
        epoch_length: u64,
    ) -> Result<bool> {
        if !self.is_epoch_boundary(height, epoch_length) {
            return Ok(false);
        }

        self.replace_validators(new_validators)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::ValidatorSet;
    use primitive_types::U256;
    use sxiaum_types::validator::ValidatorStatus;
    use sxiaum_types::{Address, Validator};

    fn validator(seed: u8, active: bool, stake_units: u64) -> Validator {
        use ed25519_dalek::SigningKey;
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let address = Address::from_public_key(&pubkey);
        let mut validator = Validator::new(
            address,
            pubkey,
            U256::from(stake_units) * U256::from(10u64.pow(18)),
        );
        validator.status = if active {
            ValidatorStatus::Active
        } else {
            ValidatorStatus::Inactive
        };

        // Attach valid BLS PoP so ValidatorSet accepts it unconditionally
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).unwrap();
        validator = validator.with_bls_pop(pk.0, pop.0);

        validator
    }

    #[test]
    fn add_remove_and_total_stake_track_validator_set_state() {
        let mut set = ValidatorSet::new();
        let first = validator(1, true, 2);
        let second = validator(2, false, 3);

        set.add_validator(first.clone())
            .expect("first validator should be accepted");
        set.add_validator(second.clone())
            .expect("second validator should be accepted");

        assert_eq!(set.total_stake(), first.stake + second.stake);
        assert_eq!(
            set.validator(&first.address)
                .map(|validator| validator.address),
            Some(first.address)
        );
        assert_eq!(set.voting_power(&second.address), second.voting_power);

        let removed = set
            .remove_validator(&second.address)
            .expect("validator should be removed");
        assert_eq!(removed.address, second.address);
        assert_eq!(set.total_stake(), first.stake);
    }

    #[test]
    fn leader_selection_and_get_proposer_only_use_active_validators() {
        let mut set = ValidatorSet::new();
        let first = validator(3, true, 1);
        let second = validator(4, false, 1);
        let third = validator(5, true, 1);

        set.add_validator(first.clone())
            .expect("first validator should be added");
        set.add_validator(second)
            .expect("second validator should be added");
        set.add_validator(third.clone())
            .expect("third validator should be added");

        let active = set.active_validators();
        assert_eq!(active.len(), 2);
        assert!(active.iter().all(|validator| validator.is_active()));
        assert_eq!(set.active_validator_count(), 2);

        // With length 2, indices are 0 and 1.
        // We just assert that it returns one of the active validators.
        let seed = [0u8; 32];
        let p0 = set.leader_selection(0, seed).unwrap();
        let p1 = set.leader_selection(1, seed).unwrap();
        let p2 = set.get_proposer(2, seed).unwrap();

        assert!(p0 == first.address || p0 == third.address);
        assert!(p1 == first.address || p1 == third.address);
        assert!(p2 == first.address || p2 == third.address);
    }

    #[test]
    fn quorum_threshold_and_voting_power_cover_zero_one_and_multiple_active_validators() {
        let mut empty = ValidatorSet::new();
        let seed = [0u8; 32];
        assert_eq!(empty.quorum_threshold(), 0);
        assert_eq!(empty.total_active_voting_power(), 0);
        assert_eq!(empty.get_proposer(0, seed), None);

        let one = validator(6, true, 2);
        empty
            .add_validator(one.clone())
            .expect("validator should be added");
        assert_eq!(empty.quorum_threshold(), 1);
        assert_eq!(empty.total_active_voting_power(), one.voting_power);

        let two = validator(7, true, 3);
        let three = validator(8, true, 4);
        empty
            .add_validator(two.clone())
            .expect("validator should be added");
        empty
            .add_validator(three.clone())
            .expect("validator should be added");
        assert_eq!(empty.quorum_threshold(), 3);
        assert_eq!(
            empty.total_active_voting_power(),
            one.voting_power + two.voting_power + three.voting_power
        );
    }

    #[test]
    fn replace_validators_and_validation_reject_invalid_entries() {
        let mut set = ValidatorSet::new();
        let active = validator(9, true, 1);
        let jailed = {
            let mut validator = validator(10, true, 1);
            validator.status = ValidatorStatus::Jailed;
            validator
        };
        let zero_stake = validator(11, true, 0);
        let empty_key = Validator::new(Address([12u8; 32]), [0u8; 32], U256::from(10u64.pow(18)));

        assert!(set.validate_validator(&jailed).is_err());
        assert!(set.validate_validator(&zero_stake).is_err());
        assert!(set.validate_validator(&empty_key).is_err());

        set.replace_validators(vec![active.clone()])
            .expect("replacement should succeed with valid validators");
        assert_eq!(set.active_validator_count(), 1);
        assert_eq!(set.total_stake(), active.stake);
    }

    #[test]
    fn bls_pop_required_when_pubkey_present_and_verified() {
        use sxiaum_crypto::bls::{bls_generate_keypair, create_proof_of_possession};

        let mut set = ValidatorSet::new();
        let (sk, pk) = bls_generate_keypair();
        let pop = create_proof_of_possession(&sk, &pk).expect("pop");
        let mut v = validator(20, true, 1);
        v = v.with_bls_pop(pk.0.clone(), pop.0.clone());
        set.add_validator(v).expect("valid pop accepted");

        let mut bad = validator(21, true, 1);
        bad.bls_pubkey = Some(pk.0);
        bad.bls_pop = Some(vec![0u8; 96]);
        assert!(set.add_validator(bad).is_err());
    }
}
