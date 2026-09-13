use crate::{AccountError, Address};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
pub const EMPTY_CODE_HASH: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];
pub const EMPTY_STORAGE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];
pub const MAX_STORAGE_ENTRIES: usize = 4096;
const ZERO_HASH: [u8; 32] = [0u8; 32];
const STORAGE_ROOT_DOMAIN: &[u8] = b"sxiaum:account:storage-root:v1";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: [u8; 32],
    pub storage_root: [u8; 32],
}
impl Account {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            balance: U256::zero(),
            nonce: 0,
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_STORAGE_ROOT,
        }
    }
    pub fn new_with_balance(address: Address, balance: U256) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
            code_hash: EMPTY_CODE_HASH,
            storage_root: EMPTY_STORAGE_ROOT,
        }
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.balance.is_zero()
            && self.nonce == 0
            && self.code_hash == EMPTY_CODE_HASH
            && self.storage_root == EMPTY_STORAGE_ROOT
    }
    #[must_use]
    pub fn is_contract(&self) -> bool {
        self.code_hash != EMPTY_CODE_HASH
    }
    pub fn checked_add_balance(&mut self, amount: U256) -> Result<(), AccountError> {
        self.balance = self
            .balance
            .checked_add(amount)
            .ok_or(AccountError::Overflow)?;
        Ok(())
    }
    pub fn checked_sub_balance(&mut self, amount: U256) -> Result<(), AccountError> {
        self.balance = self
            .balance
            .checked_sub(amount)
            .ok_or(AccountError::Underflow)?;
        Ok(())
    }
    pub fn checked_increment_nonce(&mut self) -> Result<(), AccountError> {
        self.nonce = self
            .nonce
            .checked_add(1)
            .ok_or(AccountError::NonceExhausted)?;
        Ok(())
    }
    pub fn set_code_hash(&mut self, code_hash: [u8; 32]) -> Result<(), AccountError> {
        if code_hash == ZERO_HASH {
            return Err(AccountError::InvalidCodeHash);
        }
        self.code_hash = code_hash;
        Ok(())
    }
    pub fn clear_code(&mut self) {
        self.code_hash = EMPTY_CODE_HASH;
        self.storage_root = EMPTY_STORAGE_ROOT;
    }
    pub fn set_storage_root(&mut self, storage_root: [u8; 32]) -> Result<(), AccountError> {
        if storage_root == ZERO_HASH {
            return Err(AccountError::InvalidStorageRoot);
        }
        self.storage_root = storage_root;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), AccountError> {
        if self.code_hash == ZERO_HASH {
            return Err(AccountError::InvalidCodeHash);
        }
        if self.storage_root == ZERO_HASH {
            return Err(AccountError::InvalidStorageRoot);
        }
        Ok(())
    }
    pub fn try_hash(&self) -> anyhow::Result<[u8; 32]> {
        let mut balance_bytes = [0u8; 32];
        self.balance.to_big_endian(&mut balance_bytes);
        let mut hasher = Keccak256::new();
        hasher.update(self.address.as_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(balance_bytes);
        hasher.update(self.storage_root);
        hasher.update(self.code_hash);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }
    pub fn try_encode_canonical(&self) -> anyhow::Result<Vec<u8>> {
        <Self as crate::Canonical>::try_encode(self)
    }
}
pub fn compute_storage_root(
    address: &Address,
    entries: &[([u8; 32], [u8; 32])],
) -> anyhow::Result<[u8; 32]> {
    if entries.len() > MAX_STORAGE_ENTRIES {
        return Err(AccountError::TooManyStorageEntries.into());
    }
    let mut live: Vec<([u8; 32], [u8; 32])> = entries
        .iter()
        .copied()
        .filter(|(_, value)| *value != ZERO_HASH)
        .collect();
    if live.is_empty() {
        return Ok(EMPTY_STORAGE_ROOT);
    }
    if live.len() > MAX_STORAGE_ENTRIES {
        return Err(AccountError::TooManyStorageEntries.into());
    }
    live.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut idx = 1usize;
    while idx < live.len() {
        if live[idx].0 == live[idx - 1].0 {
            return Err(AccountError::DuplicateStorageSlot.into());
        }
        idx += 1;
    }
    let mut hasher = Keccak256::new();
    hasher.update(STORAGE_ROOT_DOMAIN);
    hasher.update(address.as_bytes());
    hasher.update((live.len() as u64).to_be_bytes());
    for (slot, value) in live {
        hasher.update(slot);
        hasher.update(value);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::{compute_storage_root, Account, EMPTY_CODE_HASH, EMPTY_STORAGE_ROOT, MAX_STORAGE_ENTRIES};
    use crate::{AccountError, Address, Canonical};
    use primitive_types::U256;
    use sha3::{Digest as _, Keccak256};
    fn address(byte: u8) -> Address {
        Address([byte; 32])
    }
    #[test]
    fn empty_code_hash_is_keccak256_of_empty_input() {
        let expected: [u8; 32] = Keccak256::digest(b"").into();
        assert_eq!(EMPTY_CODE_HASH, expected);
    }
    #[test]
    fn empty_storage_root_is_keccak256_of_rlp_empty_string() {
        let rlp_empty = rlp::encode(&Vec::<u8>::new());
        assert_eq!(rlp_empty.as_ref(), &[0x80]);
        let expected: [u8; 32] = Keccak256::digest(&rlp_empty).into();
        assert_eq!(EMPTY_STORAGE_ROOT, expected);
        assert_ne!(EMPTY_STORAGE_ROOT, [0u8; 32]);
    }
    #[test]
    fn new_account_is_canonically_empty() {
        let account = Account::new(address(9));
        assert_eq!(account.address, address(9));
        assert_eq!(account.balance, U256::zero());
        assert_eq!(account.nonce, 0);
        assert_eq!(account.code_hash, EMPTY_CODE_HASH);
        assert_eq!(account.storage_root, EMPTY_STORAGE_ROOT);
        assert!(account.is_empty());
        assert!(!account.is_contract());
        account.validate().expect("fresh account must be valid");
    }
    #[test]
    fn new_with_balance_is_not_empty_and_stays_valid() {
        let account = Account::new_with_balance(address(8), U256::from(500u64));
        assert_eq!(account.balance, U256::from(500u64));
        assert!(!account.is_empty());
        account.validate().expect("funded account must be valid");
    }
    #[test]
    fn balance_arithmetic_is_checked_and_never_saturates() {
        let mut account = Account::new(address(1));
        account
            .checked_add_balance(U256::from(100u64))
            .expect("credit must succeed");
        assert_eq!(account.balance, U256::from(100u64));
        account
            .checked_sub_balance(U256::from(40u64))
            .expect("debit must succeed");
        assert_eq!(account.balance, U256::from(60u64));
        assert_eq!(
            account.checked_sub_balance(U256::from(61u64)),
            Err(AccountError::Underflow)
        );
        assert_eq!(account.balance, U256::from(60u64));
        account.balance = U256::MAX;
        assert_eq!(
            account.checked_add_balance(U256::from(1u64)),
            Err(AccountError::Overflow)
        );
        assert_eq!(account.balance, U256::MAX);
        account.balance = U256::MAX - U256::one();
        account
            .checked_add_balance(U256::one())
            .expect("exact-max credit must succeed");
        assert_eq!(account.balance, U256::MAX);
    }
    #[test]
    fn nonce_increment_is_checked_and_reports_exhaustion() {
        let mut account = Account::new(address(2));
        account
            .checked_increment_nonce()
            .expect("first increment must succeed");
        assert_eq!(account.nonce, 1);
        account.nonce = u64::MAX - 1;
        account
            .checked_increment_nonce()
            .expect("increment to u64::MAX must succeed");
        assert_eq!(account.nonce, u64::MAX);
        assert_eq!(
            account.checked_increment_nonce(),
            Err(AccountError::NonceExhausted)
        );
        assert_eq!(account.nonce, u64::MAX);
    }
    #[test]
    fn code_hash_rejects_zero_and_accepts_real_hashes() {
        let mut account = Account::new(address(3));
        assert_eq!(
            account.set_code_hash([0u8; 32]),
            Err(AccountError::InvalidCodeHash)
        );
        let deployed = [5u8; 32];
        account
            .set_code_hash(deployed)
            .expect("deployment hash must be accepted");
        assert_eq!(account.code_hash, deployed);
        assert!(account.is_contract());
        assert!(!account.is_empty());
        account
            .set_code_hash(EMPTY_CODE_HASH)
            .expect("canonical empty hash must be accepted");
        assert!(!account.is_contract());
    }
    #[test]
    fn clearing_code_resets_storage_root() {
        let mut account = Account::new(address(4));
        account.set_code_hash([6u8; 32]).expect("set code");
        account
            .set_storage_root([7u8; 32])
            .expect("set storage root");
        assert_ne!(account.storage_root, EMPTY_STORAGE_ROOT);
        account.clear_code();
        assert_eq!(account.code_hash, EMPTY_CODE_HASH);
        assert_eq!(account.storage_root, EMPTY_STORAGE_ROOT);
        account.validate().expect("cleared account must be valid");
    }
    #[test]
    fn storage_root_rejects_non_canonical_encoding() {
        let mut eoa = Account::new(address(5));
        assert_eq!(
            eoa.set_storage_root([0u8; 32]),
            Err(AccountError::InvalidStorageRoot)
        );
        eoa.set_storage_root(EMPTY_STORAGE_ROOT)
            .expect("empty root is always allowed");
        eoa.set_storage_root([9u8; 32])
            .expect("commitment root must be accepted");
        eoa.validate().expect("account with storage is valid");
        let mut contract = Account::new(address(6));
        contract.set_code_hash([8u8; 32]).expect("set code");
        contract
            .set_storage_root([9u8; 32])
            .expect("contract may hold storage");
        contract.validate().expect("contract with storage is valid");
    }
    #[test]
    fn validate_rejects_non_canonical_hashes() {
        let mut account = Account::new(address(7));
        account.code_hash = [0u8; 32];
        assert_eq!(account.validate(), Err(AccountError::InvalidCodeHash));
        let mut account = Account::new(address(7));
        account.storage_root = [0u8; 32];
        assert_eq!(account.validate(), Err(AccountError::InvalidStorageRoot));
    }
    #[test]
    fn storage_root_commits_to_every_slot_and_ignores_order() {
        let owner = address(11);
        let a = ([1u8; 32], [0xAAu8; 32]);
        let b = ([2u8; 32], [0xBBu8; 32]);
        let forward = compute_storage_root(&owner, &[a, b]).expect("root");
        let reversed = compute_storage_root(&owner, &[b, a]).expect("root");
        assert_eq!(forward, reversed);
        assert_ne!(forward, EMPTY_STORAGE_ROOT);
        assert_ne!(forward, [0u8; 32]);
        let other_owner = compute_storage_root(&address(12), &[a, b]).expect("root");
        assert_ne!(forward, other_owner);
        let changed = compute_storage_root(&owner, &[a, ([2u8; 32], [0xCCu8; 32])]).expect("root");
        assert_ne!(forward, changed);
        let dropped = compute_storage_root(&owner, &[a]).expect("root");
        assert_ne!(forward, dropped);
    }
    #[test]
    fn storage_root_treats_zero_values_as_absent() {
        let owner = address(13);
        let live = ([1u8; 32], [0xAAu8; 32]);
        assert_eq!(
            compute_storage_root(&owner, &[(live.0, [0u8; 32])]).expect("root"),
            EMPTY_STORAGE_ROOT
        );
        assert_eq!(compute_storage_root(&owner, &[]).expect("root"), EMPTY_STORAGE_ROOT);
        assert_eq!(
            compute_storage_root(&owner, &[live, ([2u8; 32], [0u8; 32])]).expect("root"),
            compute_storage_root(&owner, &[live]).expect("root")
        );
    }
    #[test]
    fn storage_root_rejects_duplicate_slots() {
        let owner = address(14);
        let slot = [3u8; 32];
        let entries = [(slot, [0xAAu8; 32]), (slot, [0xBBu8; 32])];
        let err = compute_storage_root(&owner, &entries).unwrap_err();
        let typed = err.downcast::<AccountError>().expect("typed error");
        assert_eq!(typed, AccountError::DuplicateStorageSlot);
    }
    #[test]
    fn storage_root_rejects_oversized_input() {
        let owner = address(15);
        let mut entries = Vec::new();
        let mut i = 0u32;
        while (entries.len() as u32) < (MAX_STORAGE_ENTRIES as u32 + 1) {
            let mut slot = [0u8; 32];
            slot[0..4].copy_from_slice(&i.to_be_bytes());
            slot[4] = 0x01;
            entries.push((slot, [0xAAu8; 32]));
            i += 1;
        }
        let err = compute_storage_root(&owner, &entries).unwrap_err();
        let typed = err.downcast::<AccountError>().expect("typed error");
        assert_eq!(typed, AccountError::TooManyStorageEntries);
    }
    #[test]
    fn storage_root_is_bound_to_owner_and_uses_keccak_domain() {
        let owner_a = address(16);
        let owner_b = address(17);
        let entries = [([9u8; 32], [0x11u8; 32])];
        let root_a = compute_storage_root(&owner_a, &entries).expect("root");
        let root_b = compute_storage_root(&owner_b, &entries).expect("root");
        assert_ne!(root_a, root_b);
        assert_ne!(root_a, EMPTY_STORAGE_ROOT);
        let mut hasher = Keccak256::new();
        hasher.update(b"sxiaum:account:storage-root:v1");
        hasher.update(owner_a.as_bytes());
        hasher.update(1u64.to_be_bytes());
        hasher.update([9u8; 32]);
        hasher.update([0x11u8; 32]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(root_a, expected);
    }
    #[test]
    fn account_hash_binds_address_balance_nonce_and_roots() {
        let mut first = Account::new(address(21));
        first
            .checked_add_balance(U256::from(99u64))
            .expect("credit");
        first.checked_increment_nonce().expect("nonce");
        let mut second = first.clone();
        second.address = address(22);
        let mut third = first.clone();
        third.set_code_hash([0x11u8; 32]).expect("code");
        third
            .set_storage_root([0x22u8; 32])
            .expect("storage root");
        let mut fourth = first.clone();
        fourth.checked_add_balance(U256::from(1u64)).expect("credit");
        let h1 = first.try_hash().expect("hash");
        let h2 = second.try_hash().expect("hash");
        let h3 = third.try_hash().expect("hash");
        let h4 = fourth.try_hash().expect("hash");
        assert_eq!(h1, first.try_hash().expect("hash"));
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_ne!(h1, h4);
        assert_ne!(h2, h3);
        let mut hasher = Keccak256::new();
        let mut bal = [0u8; 32];
        first.balance.to_big_endian(&mut bal);
        hasher.update(first.address.as_bytes());
        hasher.update(first.nonce.to_be_bytes());
        hasher.update(bal);
        hasher.update(first.storage_root);
        hasher.update(first.code_hash);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(h1, expected);
    }
    #[test]
    fn canonical_encoding_round_trips_exactly() {
        let mut account = Account::new(address(31));
        account
            .checked_add_balance(U256::from(123u64))
            .expect("credit");
        account.checked_increment_nonce().expect("nonce");
        account.set_code_hash([0x33u8; 32]).expect("code");
        account
            .set_storage_root([0x44u8; 32])
            .expect("storage root");
        let encoded = account.try_encode().expect("encode");
        let decoded: Account = Account::decode(&encoded).expect("decode");
        assert_eq!(decoded, account);
        decoded.validate().expect("decoded account must validate");
        assert_eq!(
            decoded.try_hash().expect("hash"),
            account.try_hash().expect("hash")
        );
    }
    #[test]
    fn serde_json_round_trip_preserves_account_fields() {
        let mut account = Account::new(address(41));
        account
            .checked_add_balance(U256::from(123u64))
            .expect("credit");
        account.nonce = 9;
        account.set_code_hash([0x55u8; 32]).expect("code");
        account
            .set_storage_root([0x66u8; 32])
            .expect("storage root");
        let json = serde_json::to_string(&account).expect("json encode");
        let decoded: Account = serde_json::from_str(&json).expect("json decode");
        assert_eq!(decoded, account);
        decoded.validate().expect("decoded account must validate");
    }
    #[test]
    fn externally_supplied_account_with_zeroed_hashes_is_rejected() {
        let mut forged = serde_json::to_value(Account::new(address(61))).expect("json value");
        forged["code_hash"] = serde_json::json!(vec![0u8; 32]);
        forged["storage_root"] = serde_json::json!(vec![0u8; 32]);
        let decoded: Account = serde_json::from_value(forged).expect("json decode");
        assert_eq!(decoded.validate(), Err(AccountError::InvalidCodeHash));
        let mut forged = serde_json::to_value(Account::new(address(62))).expect("json value");
        forged["storage_root"] = serde_json::json!(vec![0u8; 32]);
        let decoded: Account = serde_json::from_value(forged).expect("json decode");
        assert_eq!(decoded.validate(), Err(AccountError::InvalidStorageRoot));
    }
    #[test]
    fn empty_detection_matches_canonical_definition() {
        let mut account = Account::new(address(51));
        assert!(account.is_empty());
        account.balance = U256::one();
        assert!(!account.is_empty());
        account.balance = U256::zero();
        account.nonce = 1;
        assert!(!account.is_empty());
        account.nonce = 0;
        account.set_code_hash([0x77u8; 32]).expect("code");
        assert!(!account.is_empty());
        assert!(account.is_contract());
    }
}
