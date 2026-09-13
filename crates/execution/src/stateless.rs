//! revm-backed database hydrated from a compressed / execution witness for
//! EVM-level stateless execution (contract calls & deploys).

use anyhow::Result;
use revm::primitives::{
    AccountInfo, Address as RevmAddress, Bytecode, HashMap as RevmHashMap, B256, KECCAK_EMPTY,
    U256 as RevmU256,
};
use revm::{Database, DatabaseCommit};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use sxiaum_state::proof::StateWitness;
use sxiaum_state::CompressedStateWitness;
use sxiaum_types::Account;

/// A revm `Database` backend that resolves state strictly from a verified
/// witness. This allows a validator or light client to execute EVM bytecode
/// statelessly without a local `StateDb`.
pub struct StatelessDbBackend {
    pub accounts: HashMap<RevmAddress, AccountInfo>,
    pub storage: HashMap<RevmAddress, HashMap<RevmU256, RevmU256>>,
    pub code: HashMap<B256, Bytecode>,
    pub block_hash: B256,
}

impl StatelessDbBackend {
    /// Hydrate from a compressed multiproof witness (structural; balances default to zero
    /// unless account preimages are supplied via [`Self::from_execution_witness`]).
    pub fn new(
        witness: &CompressedStateWitness,
        _state_root: [u8; 32],
        block_hash: [u8; 32],
    ) -> Result<Self> {
        let mut accounts = HashMap::new();
        let mut storage = HashMap::new();

        for (key, _value) in &witness.values {
            if key.len() < 32 {
                continue;
            }
            let addr = match sxiaum_types::Address::try_from(&key[..32]) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let revm_addr = RevmAddress::from(addr.to_ethereum_address_lossy());

            accounts.entry(revm_addr).or_insert_with(|| AccountInfo {
                balance: RevmU256::ZERO,
                nonce: 0,
                code_hash: KECCAK_EMPTY,
                code: None,
            });
            storage.entry(revm_addr).or_insert_with(HashMap::new);
        }

        Ok(Self {
            accounts,
            storage,
            code: HashMap::new(),
            block_hash: B256::from(block_hash),
        })
    }

    /// Hydrate from a full [`StateWitness`] including account / storage / code preimages.
    pub fn from_execution_witness(witness: &StateWitness, block_hash: [u8; 32]) -> Result<Self> {
        let mut accounts = HashMap::new();
        let mut storage: HashMap<RevmAddress, HashMap<RevmU256, RevmU256>> = HashMap::new();
        let mut code = HashMap::new();

        for account in &witness.account_preimages {
            account.validate()?;
            let revm_addr = account_to_revm_address(account);
            let code_hash = B256::from(account.code_hash);
            accounts.insert(
                revm_addr,
                AccountInfo {
                    balance: crate::evm_runtime::prim_u256_to_revm(account.balance),
                    nonce: account.nonce,
                    code_hash,
                    code: None,
                },
            );
            storage.entry(revm_addr).or_default();
        }

        for entry in &witness.storage_preimages {
            let revm_addr = address_to_revm(&entry.address);
            let slot = RevmU256::from_be_bytes(entry.slot);
            let value = RevmU256::from_be_bytes(entry.value);
            storage.entry(revm_addr).or_default().insert(slot, value);
        }

        for pre in &witness.code_preimages {
            let hash = B256::from(pre.code_hash);
            let bytecode = Bytecode::new_raw(pre.bytecode.clone().into());
            // Attach code to any account that references this hash.
            for info in accounts.values_mut() {
                if info.code_hash == hash {
                    info.code = Some(bytecode.clone());
                }
            }
            code.insert(hash, bytecode);
        }

        Ok(Self {
            accounts,
            storage,
            code,
            block_hash: B256::from(block_hash),
        })
    }
}

fn account_to_revm_address(account: &Account) -> RevmAddress {
    address_to_revm(&account.address)
}

fn address_to_revm(address: &sxiaum_types::Address) -> RevmAddress {
    RevmAddress::from(address.to_ethereum_address_lossy())
}

impl Database for StatelessDbBackend {
    type Error = anyhow::Error;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("stateless: missing bytecode for hash {code_hash}"))
    }

    fn storage(&mut self, address: RevmAddress, index: RevmU256) -> Result<RevmU256, Self::Error> {
        if let Some(account_storage) = self.storage.get(&address) {
            Ok(account_storage
                .get(&index)
                .copied()
                .unwrap_or(RevmU256::ZERO))
        } else {
            Ok(RevmU256::ZERO)
        }
    }

    fn block_hash(&mut self, _number: RevmU256) -> Result<B256, Self::Error> {
        Ok(self.block_hash)
    }
}

impl DatabaseCommit for StatelessDbBackend {
    fn commit(&mut self, changes: RevmHashMap<RevmAddress, revm::primitives::Account>) {
        for (address, account) in changes {
            if account.is_selfdestructed() {
                self.accounts.remove(&address);
                self.storage.remove(&address);
                continue;
            }

            let info = account.info;
            self.accounts.insert(address, info);

            let account_storage = self.storage.entry(address).or_default();
            for (slot, storage_slot) in account.storage {
                if storage_slot.is_changed() {
                    account_storage.insert(slot, storage_slot.present_value());
                }
            }
        }
    }
}

/// Domain-separated commitment over post-execution account set (diagnostic).
pub fn sparse_accounts_commitment(accounts: &[Account]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"sxiaum:stateless:accounts:v1");
    let mut sorted = accounts.to_vec();
    sorted.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
    for a in sorted {
        hasher.update(a.address.as_bytes());
        hasher.update(a.try_hash()?);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;
    use sxiaum_types::Address;

    #[test]
    fn from_execution_witness_loads_balance_and_nonce() {
        let mut account = Account::new(Address::from_public_key(&[7u8; 32]));
        account.balance = U256::from(12345u64);
        account.nonce = 3;
        let witness = StateWitness {
            proofs: vec![],
            account_preimages: vec![account.clone()],
            storage_preimages: vec![],
            code_preimages: vec![],
        };
        let backend = StatelessDbBackend::from_execution_witness(&witness, [9u8; 32]).unwrap();
        let revm_addr = address_to_revm(&account.address);
        let info = backend.accounts.get(&revm_addr).expect("account present");
        assert_eq!(info.nonce, 3);
        assert_eq!(info.balance, RevmU256::from(12345u64));
    }

    #[test]
    fn code_by_hash_errors_when_missing() {
        let mut backend = StatelessDbBackend {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
            block_hash: B256::ZERO,
        };
        let err = backend.code_by_hash(B256::from([1u8; 32])).unwrap_err();
        assert!(err.to_string().contains("missing bytecode"));
    }

    #[test]
    fn stateless_backend_compressed_witness_instantiation() {
        let compressed = CompressedStateWitness {
            unique_commitments: vec![],
            partial_tree_nodes: vec![],
            values: vec![([1u8; 32], [2u8; 32]), ([3u8; 32], [4u8; 32])],
        };
        let backend = StatelessDbBackend::new(&compressed, [0u8; 32], [0u8; 32]).unwrap();
        assert_eq!(backend.accounts.len(), 2);
    }
}
