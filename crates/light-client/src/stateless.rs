//! Stateless block execution for light clients and validators.
//!
//! Pipeline:
//! 1. Verify Verkle account/storage proofs against `pre_state_root`
//! 2. Hydrate an ephemeral in-memory [`StateDb`] from witness preimages
//! 3. Apply the block's state transition (`StateDb::apply_block`)
//! 4. Check the resulting root matches `block.header.state_root`
//!
//! This avoids needing a full persistent chain database on the verifying node.

use anyhow::{bail, Result};
use std::sync::Arc;
use sxiaum_block::Block;
use sxiaum_state::proof::StateWitness;
use sxiaum_state::{StateDb, VerkleTree};
use sxiaum_storage::MemoryDatabaseBackend;
use sxiaum_types::{Hash, Transaction};
use tracing::{debug, info};

/// Validates block execution purely from a block and its cryptographic witness.
pub struct StatelessVerifier;

impl StatelessVerifier {
    /// Verify the execution of a block using a provided state witness.
    ///
    /// Rebuilds a sparse memory tree from the witness, executes the block's
    /// transactions against that sparse tree, and verifies the resulting
    /// post-state root matches the block's header state root.
    ///
    /// Returns the computed post-state root on success.
    pub fn verify_block_execution(
        block: &Block,
        pre_state_root: Hash,
        witness: &StateWitness,
    ) -> Result<Hash> {
        Self::verify_block_execution_with_options(block, pre_state_root, witness, true)
    }

    /// Same as [`Self::verify_block_execution`] with control over whether
    /// cryptographic proofs are mandatory for every preimage.
    ///
    /// Set `require_proofs = false` only for offline tests that supply a full
    /// account set without multiproofs (not for production validation).
    pub fn verify_block_execution_with_options(
        block: &Block,
        pre_state_root: Hash,
        witness: &StateWitness,
        require_proofs: bool,
    ) -> Result<Hash> {
        block
            .validate_basic()
            .map_err(|e| anyhow::anyhow!("stateless: block failed basic validation: {e}"))?;

        // Empty block: no state change allowed unless header already claims pre root.
        if block.body.transactions.is_empty() {
            if block.header.state_root != pre_state_root {
                bail!(
                    "stateless: empty block state_root 0x{} != pre_state_root 0x{}",
                    hex::encode(block.header.state_root),
                    hex::encode(pre_state_root)
                );
            }
            // Still allow verifying an empty witness against the empty/no-op transition.
            if !witness.account_preimages.is_empty() || !witness.proofs.is_empty() {
                Self::verify_witness_against_root(witness, pre_state_root, require_proofs)?;
            }
            return Ok(pre_state_root);
        }

        Self::verify_witness_against_root(witness, pre_state_root, require_proofs)?;
        Self::ensure_touched_accounts_present(block, witness)?;

        let state = Self::hydrate_state_db(witness, pre_state_root)?;

        // Re-check that the hydrated sparse tree matches the claimed pre-root.
        // When the witness is a complete snapshot of the accounts that form the
        // trie (typical for small testnets / full witnesses), roots must match.
        let hydrated_root = state.state_root();
        if hydrated_root != pre_state_root {
            // If proofs fully verified the preimages against pre_state_root, a
            // sparse re-insert may not reproduce the full multiparty root when
            // the chain has more accounts. In that case we still execute, but
            // only accept the post-root if proofs were required and verified.
            if require_proofs && !witness.proofs.is_empty() {
                debug!(
                    hydrated = %hex::encode(hydrated_root),
                    expected = %hex::encode(pre_state_root),
                    "stateless: sparse hydrate root differs from full pre_state_root; continuing with proven preimages"
                );
            } else {
                bail!(
                    "stateless: hydrated pre-state root 0x{} != claimed pre_state_root 0x{} \
                     (provide a complete account witness or Verkle multiproofs)",
                    hex::encode(hydrated_root),
                    hex::encode(pre_state_root)
                );
            }
        }

        // Apply transactions via the same STF as full nodes.
        for tx in &block.body.transactions {
            Self::validate_tx_against_witness(tx, witness, require_proofs)?;
            state.apply_transaction(tx).map_err(|e| {
                anyhow::anyhow!(
                    "stateless: applying tx 0x{} failed: {e}",
                    hex::encode(tx.try_hash().unwrap_or_default())
                )
            })?;
        }

        let post_root = state.update_state_root()?;
        if post_root != block.header.state_root {
            bail!(
                "stateless: computed post-state root 0x{} != block header state_root 0x{}",
                hex::encode(post_root),
                hex::encode(block.header.state_root)
            );
        }

        info!(
            height = block.header.height,
            post_root = %hex::encode(post_root),
            "stateless block execution verified"
        );
        Ok(post_root)
    }

    fn verify_witness_against_root(
        witness: &StateWitness,
        root: Hash,
        require_proofs: bool,
    ) -> Result<()> {
        if require_proofs && !witness.account_preimages.is_empty() && witness.proofs.is_empty() {
            bail!("stateless: account preimages present but no Verkle proofs provided");
        }
        witness.verify_account_preimages(root, require_proofs)?;
        witness.verify_storage_preimages(root, require_proofs)?;
        Ok(())
    }

    /// Every `from`/`to` in the block must have a preimage (or be creatable empty).
    /// Senders must exist with sufficient balance - enforced by `apply_transaction`.
    fn ensure_touched_accounts_present(block: &Block, witness: &StateWitness) -> Result<()> {
        let known: std::collections::HashSet<[u8; 32]> = witness
            .account_preimages
            .iter()
            .map(|a| *a.address.as_bytes())
            .collect();

        for tx in &block.body.transactions {
            if !known.contains(tx.from.as_bytes()) {
                bail!("stateless: missing account preimage for sender {}", tx.from);
            }
            // Recipients may be absent (implicit create-on-receive).
        }
        Ok(())
    }

    fn validate_tx_against_witness(
        tx: &Transaction,
        witness: &StateWitness,
        require_proofs: bool,
    ) -> Result<()> {
        tx.validate_basic()?;
        // Contract calls with data against a known contract account require the
        // bytecode preimage in the witness when cryptographic completeness is
        // mandatory (production validation). Offline test runs may omit it.
        if require_proofs && tx.is_contract_call() {
            if let Some(to) = tx.to {
                if !tx.data.is_empty() {
                    if let Some(account) =
                        witness.account_preimages.iter().find(|a| a.address == to)
                    {
                        if account.is_contract()
                            && !witness
                                .code_preimages
                                .iter()
                                .any(|c| c.code_hash == account.code_hash)
                        {
                            bail!(
                                "stateless: contract call to {} requires code preimage for hash 0x{}",
                                to,
                                hex::encode(account.code_hash)
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Hydrate an ephemeral [`StateDb`] from witness preimages.
    pub fn hydrate_state_db(witness: &StateWitness, pre_state_root: Hash) -> Result<StateDb> {
        let backend = Arc::new(MemoryDatabaseBackend::new());
        let state = StateDb::new(backend);

        for account in &witness.account_preimages {
            state.update_account(&account.address, account)?;
        }

        for entry in &witness.storage_preimages {
            state.set_storage(&entry.address, entry.slot, entry.value)?;
        }

        // Persist metadata root hint (used by some readers).
        state
            .storage()
            .state_put(b"metadata:state_root".to_vec(), pre_state_root.to_vec())?;

        // When the sparse tree happens to match the full root (complete witness),
        // keep metadata in sync via update_state_root after hydrate.
        let hydrated = state.state_root();
        if hydrated == pre_state_root {
            state.update_state_root()?;
        }

        Ok(state)
    }

    /// Empty-tree root used when no accounts exist yet.
    pub fn empty_state_root() -> Hash {
        VerkleTree::new().root_commitment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_types::{Account, Address, Receipt, Transaction};

    fn funded_sender(sk_byte: u8, balance: u64) -> (SigningKey, Account) {
        let sk = SigningKey::from_bytes(&[sk_byte; 32]);
        let pk = sk.verifying_key().to_bytes();
        let address = Address::from_public_key(&pk);
        let mut account = Account::new(address);
        account.balance = U256::from(balance);
        (sk, account)
    }

    #[test]
    fn empty_block_noop_succeeds() {
        let pre = StatelessVerifier::empty_state_root();
        let mut header = BlockHeader::new([0u8; 32], 1);
        header.set_state_root(pre);
        let block = Block::new(header, BlockBody::empty());
        let witness = StateWitness::empty();

        let root =
            StatelessVerifier::verify_block_execution(&block, pre, &witness).expect("empty ok");
        assert_eq!(root, pre);
    }

    #[test]
    fn empty_block_rejects_root_mismatch() {
        let pre = StatelessVerifier::empty_state_root();
        let mut header = BlockHeader::new([0u8; 32], 1);
        header.set_state_root([9u8; 32]);
        let block = Block::new(header, BlockBody::empty());
        assert!(
            StatelessVerifier::verify_block_execution(&block, pre, &StateWitness::empty()).is_err()
        );
    }

    fn make_block_with_tx(
        tx: Transaction,
        parent: [u8; 32],
        height: u64,
        state_root: [u8; 32],
    ) -> Block {
        let mut body = BlockBody::new();
        body.add_transaction(tx.clone());
        body.add_receipt(Receipt::new_success(
            tx.try_hash().unwrap(),
            tx.gas_limit,
            None,
        ));
        let mut header = BlockHeader::new(parent, height);
        header.set_state_root(state_root);
        let mut block = Block::new(header, body);
        block.try_compute_roots().expect("compute roots");
        block
    }

    #[test]
    fn transfer_block_stateless_round_trip() {
        let backend = Arc::new(MemoryDatabaseBackend::new());
        let full = StateDb::new(backend);

        let (sk, mut sender) = funded_sender(11, 1_000_000);
        let to = Address::from_public_key(&[22u8; 32]);
        full.update_account(&sender.address, &sender)
            .expect("fund sender");

        let pre_root = full.update_state_root().expect("pre root");

        let mut tx = Transaction::new_transfer(sender.address, to, U256::from(500u64), 0);
        tx.sign(&sk).expect("sign");

        let mut block = make_block_with_tx(tx.clone(), [1u8; 32], 1, pre_root);
        let post_root = full.apply_block(&block).expect("apply on full node");
        block.header.set_state_root(post_root);
        block.try_compute_roots().expect("compute roots");

        // Fresh pre-state for witness generation (preimages before the block).
        let backend2 = Arc::new(MemoryDatabaseBackend::new());
        let pre_state = StateDb::new(backend2);
        sender.nonce = 0;
        sender.balance = U256::from(1_000_000u64);
        pre_state
            .update_account(&sender.address, &sender)
            .expect("fund");
        let pre_root2 = pre_state.update_state_root().expect("pre2");
        assert_eq!(pre_root2, pre_root);

        let addresses = StateDb::addresses_touched_by_block(&block);
        let witness = pre_state
            .build_execution_witness(&addresses, &[])
            .expect("witness");

        assert!(
            !witness.account_preimages.is_empty(),
            "witness must include sender preimage"
        );
        assert!(
            !witness.proofs.is_empty(),
            "witness must include verkle proofs"
        );

        let verified = StatelessVerifier::verify_block_execution(&block, pre_root, &witness)
            .expect("stateless verify");
        assert_eq!(verified, post_root);
        assert_eq!(verified, block.header.state_root);
    }

    #[test]
    fn rejects_missing_sender_preimage() {
        let pre = StatelessVerifier::empty_state_root();
        let sk = SigningKey::from_bytes(&[0x21u8; 32]);
        let from = Address::from_public_key(&sk.verifying_key().to_bytes());
        let to = Address::from_public_key(&[2u8; 32]);
        let mut tx = Transaction::new_transfer(from, to, U256::from(1u64), 0);
        tx.sign(&sk).expect("sample transaction must sign");
        let block = make_block_with_tx(tx, [0u8; 32], 1, pre);

        let err = StatelessVerifier::verify_block_execution_with_options(
            &block,
            pre,
            &StateWitness::empty(),
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("missing account preimage"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_wrong_post_root() {
        let backend = Arc::new(MemoryDatabaseBackend::new());
        let full = StateDb::new(backend);
        let (sk, sender) = funded_sender(33, 500_000);
        full.update_account(&sender.address, &sender).unwrap();
        let pre_root = full.update_state_root().unwrap();

        let to = Address::from_public_key(&[44u8; 32]);
        let mut tx = Transaction::new_transfer(sender.address, to, U256::from(10u64), 0);
        tx.sign(&sk).unwrap();

        let block = make_block_with_tx(tx, [1u8; 32], 1, [0xabu8; 32]);
        // Keep wrong post root (do not recompute state root after apply).
        let witness = full
            .build_execution_witness(&[sender.address, to], &[])
            .unwrap();

        let err =
            StatelessVerifier::verify_block_execution(&block, pre_root, &witness).unwrap_err();
        assert!(err.to_string().contains("post-state root"), "got: {err}");
    }
}
