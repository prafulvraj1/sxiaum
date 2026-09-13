use crate::{Address, ValidatorError};
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Jailed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    pub address: Address,
    pub pubkey: [u8; 32],
    pub stake: U256,
    pub voting_power: u64,
    pub status: ValidatorStatus,
    #[serde(default)]
    pub bls_pubkey: Option<Vec<u8>>,
    #[serde(default)]
    pub bls_pop: Option<Vec<u8>>,
    #[serde(default)]
    pub commission_bps: u16,
    #[serde(default)]
    pub missed_blocks: u64,
    #[serde(default)]
    pub jailed_until: Option<u64>,
}
pub const BLS_PUBKEY_LEN: usize = 48;
pub const BLS_POP_LEN: usize = 96;
pub const MAX_COMMISSION_BPS: u16 = 10_000;
impl Validator {
    pub const STAKE_UNIT: u128 = 1_000_000_000_000_000_000;
    pub fn new(address: Address, pubkey: [u8; 32], stake: U256) -> Self {
        let voting_power = Self::calculate_voting_power(stake);
        Self {
            address,
            pubkey,
            stake,
            voting_power,
            status: ValidatorStatus::Inactive,
            bls_pubkey: None,
            bls_pop: None,
            commission_bps: 0,
            missed_blocks: 0,
            jailed_until: None,
        }
    }
    pub fn new_checked(address: Address, pubkey: [u8; 32], stake: U256) -> Result<Self> {
        let v = Self::new(address, pubkey, stake);
        v.validate()?;
        Ok(v)
    }
    pub fn try_with_bls_pop(mut self, bls_pubkey: Vec<u8>, bls_pop: Vec<u8>) -> Result<Self> {
        if bls_pubkey.len() != BLS_PUBKEY_LEN {
            bail!(
                "invalid BLS public key length: expected {} bytes, got {}",
                BLS_PUBKEY_LEN,
                bls_pubkey.len()
            );
        }
        if bls_pop.len() != BLS_POP_LEN {
            bail!(
                "invalid BLS Proof-of-Possession length: expected {} bytes, got {}",
                BLS_POP_LEN,
                bls_pop.len()
            );
        }
        self.bls_pubkey = Some(bls_pubkey);
        self.bls_pop = Some(bls_pop);
        Ok(self)
    }
    pub fn with_bls_pop(mut self, bls_pubkey: Vec<u8>, bls_pop: Vec<u8>) -> Self {
        self.bls_pubkey = Some(bls_pubkey);
        self.bls_pop = Some(bls_pop);
        self
    }
    pub fn with_commission(mut self, bps: u16) -> Result<Self> {
        if bps > MAX_COMMISSION_BPS {
            bail!(
                "commission rate cannot exceed {} basis points (100%)",
                MAX_COMMISSION_BPS
            );
        }
        self.commission_bps = bps;
        Ok(self)
    }
    pub fn calculate_voting_power(stake: U256) -> u64 {
        let unit = U256::from(Self::STAKE_UNIT);
        if stake < unit {
            0
        } else {
            let units = stake / unit;
            if units > U256::from(u64::MAX) {
                u64::MAX
            } else {
                units.as_u64()
            }
        }
    }
    pub fn update_voting_power(&mut self) {
        self.voting_power = Self::calculate_voting_power(self.stake);
    }
    pub fn increase_stake(&mut self, amount: U256) {
        self.stake = self.stake.saturating_add(amount);
        self.update_voting_power();
    }
    pub fn decrease_stake(&mut self, amount: U256) -> Result<()> {
        if self.stake < amount {
            bail!(
                "Insufficient stake to decrease from validator {}",
                self.address
            );
        }
        self.stake = self.stake.saturating_sub(amount);
        self.update_voting_power();
        Ok(())
    }
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }
    #[must_use]
    pub fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed)
    }
    pub fn slash(&mut self, amount: U256) {
        self.slash_until(amount, None);
    }
    pub fn slash_until(&mut self, amount: U256, jail_until_height: Option<u64>) {
        self.stake = self.stake.saturating_sub(amount);
        self.update_voting_power();
        self.status = ValidatorStatus::Jailed;
        self.jailed_until = jail_until_height;
    }
    pub fn unjail(&mut self, current_height: u64) -> Result<()> {
        if !self.is_jailed() {
            return Ok(());
        }
        if let Some(until) = self.jailed_until {
            if current_height < until {
                bail!(
                    "Validator {} is jailed until height {}, current height is {}",
                    self.address,
                    until,
                    current_height
                );
            }
        }
        self.status = ValidatorStatus::Inactive;
        self.jailed_until = None;
        self.missed_blocks = 0;
        Ok(())
    }
    pub fn reward(&mut self, amount: U256) {
        self.stake = self.stake.saturating_add(amount);
        self.update_voting_power();
        self.missed_blocks = 0;
    }
    pub fn record_missed_block(&mut self) -> u64 {
        self.missed_blocks = self.missed_blocks.saturating_add(1);
        self.missed_blocks
    }
    pub fn verify_signature(&self, message: &[u8], sig_bytes: &[u8; 64]) -> Result<bool> {
        let public_key = VerifyingKey::from_bytes(&self.pubkey)
            .map_err(|e| anyhow::anyhow!("Invalid validator pubkey: {:?}", e))?;
        let sig = Signature::from_bytes(sig_bytes);
        public_key
            .verify_strict(message, &sig)
            .map(|_| true)
            .map_err(|e| anyhow::anyhow!("Validator signature verification failed: {:?}", e))
    }
    pub fn stake_ratio(&self, total_stake: U256) -> f64 {
        if total_stake.is_zero() || self.stake.is_zero() {
            return 0.0;
        }
        if self.stake >= total_stake {
            return 1.0;
        }
        let total_bits = total_stake.bits();
        if total_bits > 64 {
            let shift = total_bits - 64;
            let self_shifted = (self.stake >> shift).as_u64() as f64;
            let total_shifted = (total_stake >> shift).as_u64() as f64;
            if total_shifted == 0.0 {
                0.0
            } else {
                (self_shifted / total_shifted).clamp(0.0, 1.0)
            }
        } else {
            let self_f = self.stake.as_u64() as f64;
            let total_f = total_stake.as_u64() as f64;
            if total_f == 0.0 {
                0.0
            } else {
                (self_f / total_f).clamp(0.0, 1.0)
            }
        }
    }
    pub fn validate_minimum_stake(&self, min_stake: U256) -> Result<(), ValidatorError> {
        if self.stake < min_stake {
            return Err(ValidatorError::InsufficientStake);
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        self.validate_strict().map_err(|e| anyhow::anyhow!("{}", e))
    }
    pub fn validate_strict(&self) -> Result<(), ValidatorError> {
        if is_placeholder_pubkey(&self.pubkey) {
            return Err(ValidatorError::InvalidPublicKey);
        }
        VerifyingKey::from_bytes(&self.pubkey).map_err(|_| ValidatorError::InvalidPublicKey)?;
        let derived_addr = Address::from_public_key(&self.pubkey);
        if self.address != derived_addr {
            return Err(ValidatorError::AddressMismatch {
                expected: self.address.to_string(),
                derived: derived_addr.to_string(),
            });
        }
        if self.commission_bps > MAX_COMMISSION_BPS {
            return Err(ValidatorError::CommissionExceeded {
                actual: self.commission_bps,
                max: MAX_COMMISSION_BPS,
            });
        }
        let expected_power = Self::calculate_voting_power(self.stake);
        if self.voting_power != expected_power {
            return Err(ValidatorError::VotingPowerMismatch {
                expected: expected_power,
                actual: self.voting_power,
            });
        }
        match (&self.bls_pubkey, &self.bls_pop) {
            (Some(pk), Some(pop)) => {
                if pk.len() != BLS_PUBKEY_LEN {
                    return Err(ValidatorError::InvalidBlsPublicKeyLength {
                        expected: BLS_PUBKEY_LEN,
                        actual: pk.len(),
                    });
                }
                if pop.len() != BLS_POP_LEN {
                    return Err(ValidatorError::InvalidBlsPopLength {
                        expected: BLS_POP_LEN,
                        actual: pop.len(),
                    });
                }
            }
            (None, None) => {}
            _ => {
                return Err(ValidatorError::IncompleteBlsCredentials);
            }
        }
        if self.is_active() {
            if self.voting_power == 0 {
                return Err(ValidatorError::ZeroVotingPower);
            }
            if self.jailed_until.is_some() {
                return Err(ValidatorError::ActiveWithJailWindow);
            }
        }
        Ok(())
    }
    pub fn try_hash(&self) -> Result<[u8; 32]> {
        <Self as crate::Canonical>::try_hash(self)
    }
    #[cfg(test)]
    pub fn hash(&self) -> [u8; 32] {
        self.try_hash().unwrap()
    }
    pub fn update_pubkey(&mut self, new_pubkey: [u8; 32]) {
        self.pubkey = new_pubkey;
        self.address = Address::from_public_key(&new_pubkey);
    }
    pub fn try_update_pubkey(&mut self, new_pubkey: [u8; 32]) -> Result<()> {
        if is_placeholder_pubkey(&new_pubkey) {
            bail!("invalid Ed25519 public key: placeholder pattern rejected");
        }
        VerifyingKey::from_bytes(&new_pubkey)
            .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {:?}", e))?;
        self.pubkey = new_pubkey;
        self.address = Address::from_public_key(&new_pubkey);
        Ok(())
    }
}
fn is_placeholder_pubkey(pubkey: &[u8; 32]) -> bool {
    let first = pubkey[0];
    let mut i = 1usize;
    while i < 32 {
        if pubkey[i] != first {
            return false;
        }
        i += 1;
    }
    true
}
#[cfg(test)]
mod tests {
    use super::{Validator, ValidatorStatus, BLS_POP_LEN, BLS_PUBKEY_LEN};
    use crate::{Address, ValidatorError};
    use ed25519_dalek::{Signer, SigningKey};
    use primitive_types::U256;
    fn unit() -> U256 {
        U256::from(Validator::STAKE_UNIT)
    }
    fn keypair(seed: u8) -> (SigningKey, [u8; 32], Address) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        let addr = Address::from_public_key(&pk);
        (sk, pk, addr)
    }
    #[test]
    fn new_validator_initializes_expected_fields() {
        let (_sk, pk, addr) = keypair(11);
        let validator = Validator::new(addr, pk, unit() * U256::from(3u64));
        assert_eq!(validator.address, addr);
        assert_eq!(validator.pubkey, pk);
        assert_eq!(validator.stake, unit() * U256::from(3u64));
        assert_eq!(validator.voting_power, 3);
        assert_eq!(validator.status, ValidatorStatus::Inactive);
        assert_eq!(validator.commission_bps, 0);
        assert_eq!(validator.missed_blocks, 0);
        validator.validate().expect("fresh validator must validate");
    }
    #[test]
    fn stake_updates_refresh_voting_power() {
        let (_sk, pk, addr) = keypair(12);
        let mut validator = Validator::new(addr, pk, unit());
        validator.increase_stake(unit() * U256::from(2u64));
        assert_eq!(validator.voting_power, 3);
        validator
            .decrease_stake(unit())
            .expect("stake decrease should succeed");
        assert_eq!(validator.voting_power, 2);
        assert!(validator.decrease_stake(unit() * U256::from(3u64)).is_err());
    }
    #[test]
    fn status_helpers_reflect_validator_state() {
        let (_sk, pk, addr) = keypair(13);
        let mut validator = Validator::new(addr, pk, unit());
        assert!(!validator.is_active());
        assert!(!validator.is_jailed());
        validator.status = ValidatorStatus::Active;
        assert!(validator.is_active());
        validator.status = ValidatorStatus::Jailed;
        assert!(validator.is_jailed());
    }
    #[test]
    fn slash_and_reward_and_unjail() {
        let (_sk, pk, addr) = keypair(14);
        let mut validator =
            Validator::new(addr, pk, unit() * U256::from(5u64));
        validator.reward(unit());
        assert_eq!(validator.stake, unit() * U256::from(6u64));
        validator.slash_until(unit() * U256::from(2u64), Some(100));
        assert_eq!(validator.stake, unit() * U256::from(4u64));
        assert_eq!(validator.voting_power, 4);
        assert!(validator.is_jailed());
        assert!(validator.unjail(99).is_err());
        validator.unjail(100).expect("unjail should succeed");
        assert_eq!(validator.status, ValidatorStatus::Inactive);
        assert_eq!(validator.jailed_until, None);
    }
    #[test]
    fn verify_signature_accepts_valid_messages() {
        let (sk, pk, addr) = keypair(15);
        let validator = Validator::new(addr, pk, unit());
        let message = b"hotstuff-vote";
        let signature = sk.sign(message).to_bytes();
        assert!(validator
            .verify_signature(message, &signature)
            .expect("signature verification should succeed"));
        let mut bad = signature;
        bad[0] ^= 0xFF;
        assert!(validator.verify_signature(message, &bad).is_err());
        assert!(validator.verify_signature(b"other", &signature).is_err());
    }
    #[test]
    fn stake_ratio_and_hash_are_deterministic() {
        let (_sk, pk, addr) = keypair(16);
        let validator = Validator::new(addr, pk, unit() * U256::from(2u64));
        assert_eq!(validator.stake_ratio(unit() * U256::from(4u64)), 0.5);
        assert_eq!(validator.stake_ratio(U256::zero()), 0.0);
        assert_eq!(validator.try_hash().unwrap(), validator.try_hash().unwrap());
    }
    #[test]
    fn minimum_stake_validation() {
        let (_sk, pk, addr) = keypair(17);
        let validator = Validator::new(addr, pk, unit() * U256::from(5u64));
        assert!(validator
            .validate_minimum_stake(unit() * U256::from(4u64))
            .is_ok());
        assert_eq!(
            validator.validate_minimum_stake(unit() * U256::from(6u64)),
            Err(ValidatorError::InsufficientStake)
        );
    }
    #[test]
    fn bincode_round_trip_and_pubkey_update_keeps_invariant() {
        let (_sk, _pk, addr) = keypair(18);
        let (_sk2, pk2, addr2) = keypair(19);
        let mut validator = Validator::new(addr, _pk, unit());
        validator.update_pubkey(pk2);
        assert_eq!(validator.pubkey, pk2);
        assert_eq!(validator.address, addr2);
        validator.validate().expect("updated validator must validate");
        let encoded = bincode::serialize(&validator).expect("bincode serialization should work");
        let decoded: Validator =
            bincode::deserialize(&encoded).expect("bincode deserialization should work");
        assert_eq!(decoded, validator);
        assert!(validator.try_update_pubkey([0xFFu8; 32]).is_err());
    }
    #[test]
    fn bls_lengths_are_enforced_without_panic() {
        let (_sk, pk, addr) = keypair(20);
        let v = Validator::new(addr, pk, unit());
        assert!(v.clone().try_with_bls_pop(vec![1u8; BLS_PUBKEY_LEN], vec![2u8; BLS_POP_LEN]).is_ok());
        assert!(v.clone().try_with_bls_pop(vec![1u8; 10], vec![2u8; BLS_POP_LEN]).is_err());
        assert!(v.clone().try_with_bls_pop(vec![1u8; BLS_PUBKEY_LEN], vec![2u8; 10]).is_err());
        let bad = v.clone().with_bls_pop(vec![1u8; 10], vec![2u8; 10]);
        assert!(bad.validate().is_err());
        assert_eq!(
            bad.validate_strict().unwrap_err(),
            ValidatorError::InvalidBlsPublicKeyLength { expected: BLS_PUBKEY_LEN, actual: 10 }
        );
        let half = Validator {
            bls_pubkey: Some(vec![1u8; BLS_PUBKEY_LEN]),
            bls_pop: None,
            ..v.clone()
        };
        assert_eq!(
            half.validate_strict().unwrap_err(),
            ValidatorError::IncompleteBlsCredentials
        );
    }
    #[test]
    fn active_requires_power_and_clean_jail_state() {
        let (_sk, pk, addr) = keypair(21);
        let mut v = Validator::new(addr, pk, U256::zero());
        v.status = ValidatorStatus::Active;
        assert_eq!(v.validate_strict().unwrap_err(), ValidatorError::ZeroVotingPower);
        let (_sk2, pk2, addr2) = keypair(22);
        let mut v2 = Validator::new(addr2, pk2, unit());
        v2.status = ValidatorStatus::Active;
        v2.jailed_until = Some(100);
        assert_eq!(v2.validate_strict().unwrap_err(), ValidatorError::ActiveWithJailWindow);
        v2.jailed_until = None;
        v2.validate().expect("active with power must validate");
    }
    #[test]
    fn commission_and_address_mismatch_are_rejected() {
        let (_sk, pk, addr) = keypair(23);
        let mut v = Validator::new(addr, pk, unit());
        v.commission_bps = 10_001;
        assert!(v.validate().is_err());
        assert!(v.clone().validate_strict().is_err());
        v.commission_bps = 500;
        v.validate().expect("valid commission");
        v.address = Address([0xFFu8; 32]);
        assert!(v.validate().is_err());
        assert!(matches!(
            v.validate_strict().unwrap_err(),
            ValidatorError::AddressMismatch { .. }
        ));
    }
}
