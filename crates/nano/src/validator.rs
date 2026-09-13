//! Profile 2: `NanoStatelessValidator` (Full In-Memory Stateless Validator).
//!
//! Designed for Tesla/EV edge nodes, Raspberry Pi validators, and serverless
//! verification workers. Verifies block headers, BFT Quorum Certificates,
//! batched KZG Verkle multiproofs, and re-executes block transactions against
//! an ephemeral in-memory state with **0 MB disk storage**.

use crate::epoch_sync::{EpochSyncManager, ValidatorSignature};
use crate::error::NanoError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use sxiaum_block::Block;
use sxiaum_state::proof::StateWitness;
use sxiaum_state::StateDb;
use sxiaum_storage::MemoryDatabaseBackend;
use sxiaum_types::{Address, Hash, Validator};

/// Serde default pinning nano configs to the canonical mainnet chain id.
fn default_config_chain_id() -> u64 {
    sxiaum_types::SXIAUM_CHAIN_ID
}

/// Configuration for `NanoStatelessValidator`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NanoValidatorConfig {
    pub genesis_state_root: Hash,
    pub initial_validator_set: Vec<Validator>,
    pub max_timestamp_drift_secs: u64,
    /// Replay-protection chain identifier. Must equal the canonical
    /// [`sxiaum_types::SXIAUM_CHAIN_ID`] (13689) on mainnet; constructors
    /// reject any other value.
    #[serde(default = "default_config_chain_id")]
    pub chain_id: u64,
}

impl Default for NanoValidatorConfig {
    fn default() -> Self {
        Self {
            genesis_state_root: [0u8; 32],
            initial_validator_set: Vec::new(),
            max_timestamp_drift_secs: crate::light_client::DEFAULT_MAX_TIMESTAMP_DRIFT,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
        }
    }
}

/// Full stateless block validation node operating purely in memory.
#[derive(Clone, Debug)]
pub struct NanoStatelessValidator {
    pub epoch_manager: EpochSyncManager,
    pub config: NanoValidatorConfig,
}

impl NanoStatelessValidator {
    /// Create a new `NanoStatelessValidator`.
    ///
    /// Mainnet-ready: rejects configurations pinning a chain id other than the
    /// canonical [`sxiaum_types::SXIAUM_CHAIN_ID`].
    pub fn new(config: NanoValidatorConfig) -> Result<Self, NanoError> {
        if config.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            return Err(NanoError::UnsupportedChainId {
                configured: config.chain_id,
                canonical: sxiaum_types::SXIAUM_CHAIN_ID,
            });
        }
        let epoch_manager = EpochSyncManager::new(0, config.initial_validator_set.clone())?;
        Ok(Self {
            epoch_manager,
            config,
        })
    }

    /// Perform complete in-memory stateless verification of a candidate block:
    /// 1. Header structural and timestamp validation.
    /// 2. Proposer Ed25519 signature verification against active validator set.
    /// 3. BFT Quorum Certificate verification (>= 2f + 1 stake weight).
    /// 4. Verkle witness verification against `pre_state_root`.
    /// 5. Hydrate ephemeral `StateDb` (`MemoryDatabaseBackend`).
    /// 6. Execute all transactions in block body.
    /// 7. Assert computed post-state root equals `block.header.state_root`.
    pub fn verify_block_stateless(
        &self,
        block: &Block,
        pre_state_root: Hash,
        witness: &StateWitness,
        signatures: &[ValidatorSignature],
        hotstuff_meta: Option<(u64, u8)>,
        current_time: u64,
    ) -> Result<Hash, NanoError> {
        // 1. Mainnet-strict validation of header + body: canonical protocol
        //    version, replay-protection chain id, gas limit bounds, gas-used
        //    consistency, genesis timestamp floor, proposer presence, and the
        //    canonical 5s future-time bound.
        block
            .validate_mainnet(current_time)
            .map_err(|e| NanoError::ValidationFailed {
                height: block.header.height,
                reason: e.to_string(),
            })?;

        // 1b. Explicit chain-id replay protection (defense in depth).
        if block.header.chain_id != self.config.chain_id {
            return Err(NanoError::ChainIdMismatch {
                height: block.header.height,
                expected: self.config.chain_id,
                actual: block.header.chain_id,
            });
        }

        // 2. Configurable future timestamp check (stricter overlay; the
        //    canonical mainnet bound was already enforced in step 1).
        if block.header.timestamp
            > current_time.saturating_add(self.config.max_timestamp_drift_secs)
        {
            return Err(NanoError::FutureTimestamp {
                height: block.header.height,
                timestamp: block.header.timestamp,
                now: current_time,
                max_drift: self.config.max_timestamp_drift_secs,
            });
        }

        // 3. Proposer signature check
        let proposer_val = self
            .epoch_manager
            .active_validator_set
            .iter()
            .find(|v| v.address == block.header.proposer && v.is_active())
            .ok_or_else(|| NanoError::UnknownSigner {
                signer: block.header.proposer.to_string(),
            })?;

        let derived = Address::from_public_key(&proposer_val.pubkey);
        if derived != block.header.proposer {
            return Err(NanoError::ProposerMismatch {
                header_proposer: block.header.proposer.to_string(),
                derived: derived.to_string(),
            });
        }

        block
            .header
            .verify_signature(&proposer_val.pubkey)
            .map_err(|e| NanoError::InvalidProposerSignature {
                height: block.header.height,
                reason: e.to_string(),
            })?;

        // 4. BFT Quorum Certificate verification
        let block_hash = block
            .header
            .try_hash()
            .map_err(|e| NanoError::Crypto(e.to_string()))?;
        self.epoch_manager.verify_quorum_signatures(
            &block_hash,
            block.header.height,
            signatures,
            hotstuff_meta,
        )?;

        // 5. Handle empty blocks
        if block.body.transactions.is_empty() {
            if block.header.state_root != pre_state_root {
                return Err(NanoError::StateRootMismatch {
                    computed: hex::encode(pre_state_root),
                    expected: hex::encode(block.header.state_root),
                });
            }
            return Ok(pre_state_root);
        }

        // 6. Verify witness proofs against pre_state_root
        if !witness.account_preimages.is_empty() && witness.proofs.is_empty() {
            return Err(NanoError::KzgVerificationFailed(
                "account preimages present but no Verkle proofs provided in witness".into(),
            ));
        }

        witness
            .verify_account_preimages(pre_state_root, true)
            .map_err(|e| NanoError::KzgVerificationFailed(e.to_string()))?;
        witness
            .verify_storage_preimages(pre_state_root, true)
            .map_err(|e| NanoError::KzgVerificationFailed(e.to_string()))?;

        // 7. Hydrate ephemeral in-memory StateDb (0 MB disk footprint)
        let state = Self::hydrate_ephemeral_state(witness, pre_state_root)?;

        // 8. Re-execute block transactions statelessly
        for (idx, tx) in block.body.transactions.iter().enumerate() {
            tx.validate_basic().map_err(|e| NanoError::ExecutionError {
                index: idx,
                tx_hash: hex::encode(tx.try_hash().unwrap_or_default()),
                reason: e.to_string(),
            })?;

            state
                .apply_transaction(tx)
                .map_err(|e| NanoError::ExecutionError {
                    index: idx,
                    tx_hash: hex::encode(tx.try_hash().unwrap_or_default()),
                    reason: e.to_string(),
                })?;
        }

        // 9. Assert computed post-state root equals block header state root
        let post_root = state
            .update_state_root()
            .map_err(|e| NanoError::Crypto(e.to_string()))?;

        if post_root != block.header.state_root {
            return Err(NanoError::StateRootMismatch {
                computed: hex::encode(post_root),
                expected: hex::encode(block.header.state_root),
            });
        }

        tracing::info!(
            height = block.header.height,
            post_root = %hex::encode(post_root),
            tx_count = block.body.transactions.len(),
            "Stateless block re-execution verified successfully in memory"
        );

        Ok(post_root)
    }

    /// Overload accepting raw address and signature slice tuples.
    pub fn verify_block_stateless_raw(
        &self,
        block: &Block,
        pre_state_root: Hash,
        witness: &StateWitness,
        signatures: &[(Address, [u8; 64])],
        hotstuff_meta: Option<(u64, u8)>,
        current_time: u64,
    ) -> Result<Hash, NanoError> {
        let sigs: Vec<ValidatorSignature> = signatures
            .iter()
            .map(|(addr, s)| ValidatorSignature::new(*addr, *s))
            .collect();
        self.verify_block_stateless(
            block,
            pre_state_root,
            witness,
            &sigs,
            hotstuff_meta,
            current_time,
        )
    }

    /// Hydrate an ephemeral [`StateDb`] from witness preimages purely in memory.
    pub fn hydrate_ephemeral_state(
        witness: &StateWitness,
        pre_state_root: Hash,
    ) -> Result<StateDb, NanoError> {
        let backend = Arc::new(MemoryDatabaseBackend::new());
        let state = StateDb::new(backend);

        for account in &witness.account_preimages {
            state
                .update_account(&account.address, account)
                .map_err(|e| NanoError::Crypto(e.to_string()))?;
        }

        for entry in &witness.storage_preimages {
            state
                .set_storage(&entry.address, entry.slot, entry.value)
                .map_err(|e| NanoError::Crypto(e.to_string()))?;
        }

        let _ = state.storage().state_put(
            b"metadata:state_root".to_vec(),
            pre_state_root.to_vec(),
        );

        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    use sxiaum_block::BlockHeader;
    use sxiaum_types::{SXIAUM_CHAIN_ID, ValidatorStatus};

    /// Build a structurally valid, ACTIVE validator (address derived from pubkey).
    fn test_validator(id: u8, voting_power: u64) -> Validator {
        let pubkey = [id; 32];
        let mut v = Validator::new(Address::from_public_key(&pubkey), pubkey, U256::from(1_000));
        v.voting_power = voting_power;
        v.status = ValidatorStatus::Active;
        v
    }

    #[test]
    fn default_validator_config_is_mainnet_pinned() {
        assert_eq!(NanoValidatorConfig::default().chain_id, SXIAUM_CHAIN_ID);
    }

    #[test]
    fn stateless_validator_rejects_non_mainnet_chain_id() {
        let config = NanoValidatorConfig {
            initial_validator_set: vec![test_validator(1, 10)],
            chain_id: 5,
            ..Default::default()
        };
        assert!(matches!(
            NanoStatelessValidator::new(config),
            Err(NanoError::UnsupportedChainId { .. })
        ));
    }

    #[test]
    fn stateless_validator_accepts_canonical_chain_id() {
        let config = NanoValidatorConfig {
            initial_validator_set: vec![test_validator(1, 10)],
            ..Default::default()
        };
        assert!(NanoStatelessValidator::new(config).is_ok());
    }

    #[test]
    fn verify_block_rejects_foreign_chain_id() {
        let config = NanoValidatorConfig {
            initial_validator_set: vec![test_validator(1, 10)],
            ..Default::default()
        };
        let validator = NanoStatelessValidator::new(config).expect("canonical chain id");

        let mut block = Block::new(
            BlockHeader::genesis(),
            sxiaum_block::BlockBody::new(),
        );
        block.header.chain_id = 999;

        let now = block.header.timestamp.max(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        let err = validator
            .verify_block_stateless(
                &block,
                [0u8; 32],
                &sxiaum_state::proof::StateWitness::default(),
                &[],
                None,
                now,
            )
            .expect_err("foreign chain id must be rejected");
        assert!(matches!(
            err,
            NanoError::ValidationFailed { .. } | NanoError::ChainIdMismatch { .. }
        ));
    }

    #[test]
    fn test_stateless_validator_executes_real_block() {
        std::env::set_var("SXIAUM_SRS_MODE", "dev");
        let (sk, pubkey, address) = {
            let seed = [1u8; 32];
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            let pubkey = sk.verifying_key().to_bytes();
            let address = Address::from_public_key(&pubkey);
            (sk, pubkey, address)
        };
        let mut val = Validator::new(address, pubkey, U256::from(1_000));
        val.voting_power = 100;
        val.status = ValidatorStatus::Active;

        let config = NanoValidatorConfig {
            initial_validator_set: vec![val.clone()],
            ..Default::default()
        };
        let validator = NanoStatelessValidator::new(config).expect("validator");

        let sk_tx = SigningKey::from_bytes(&[0x64u8; 32]);
        let from = Address::from_public_key(&sk_tx.verifying_key().to_bytes());
        let to = Address([13u8; 32]);
        let mut sender = sxiaum_types::Account::new(from);
        sender.balance = U256::from(1_000_000u64);
        let mut receiver = sxiaum_types::Account::new(to);

        let mut pre_tree = sxiaum_state::VerkleTree::new();
        pre_tree.insert(*from.as_bytes(), sender.try_hash().unwrap()).unwrap();
        pre_tree.insert(*to.as_bytes(), receiver.try_hash().unwrap()).unwrap();
        let pre_state_root = pre_tree.root_commitment();

        let proof_from = sxiaum_state::proof::VerkleProof::generate_account_proof(&pre_tree, &from).unwrap();
        let proof_to = sxiaum_state::proof::VerkleProof::generate_account_proof(&pre_tree, &to).unwrap();
        let witness = sxiaum_state::proof::StateWitness {
            proofs: vec![proof_from, proof_to],
            account_preimages: vec![sender.clone(), receiver.clone()],
            storage_preimages: vec![],
            code_preimages: vec![],
        };

        let mut tx = sxiaum_types::Transaction::new_transfer(from, to, U256::from(500u64), 0);
        tx.gas_limit = 21_000;
        tx.sign(&sk_tx)
            .expect("sample transaction must sign with its sender key");
        let gas_cost = tx.gas_cost();

        sender.balance = sender.balance - U256::from(500u64) - gas_cost;
        sender.nonce = 1;
        receiver.balance = U256::from(500u64);

        let mut post_tree = sxiaum_state::VerkleTree::new();
        post_tree.insert(*from.as_bytes(), sender.try_hash().unwrap()).unwrap();
        post_tree.insert(*to.as_bytes(), receiver.try_hash().unwrap()).unwrap();
        let post_state_root = post_tree.root_commitment();

        let mut body = sxiaum_block::BlockBody::new();
        let tx_hash = tx.try_hash().expect("tx hash");
        let receipt = sxiaum_types::Receipt::new_success(tx_hash, 21_000, Some(post_state_root));
        body.transactions.push(tx);
        body.receipts.push(receipt);

        let mut header = BlockHeader::new([1u8; 32], 1);
        let now = sxiaum_block::GENESIS_TIMESTAMP + 10;
        header.timestamp = now;
        header.proposer = val.address;
        header.chain_id = sxiaum_types::SXIAUM_CHAIN_ID;
        header.gas_limit = 30_000_000;
        header.gas_used = 21_000;
        header.tx_root = body.compute_tx_root().expect("tx root");
        header.receipts_root = body.compute_receipt_root().expect("receipt root");
        header.state_root = post_state_root;
        header.sign(&sk).expect("sign");

        let block = Block::new(header, body);

        let block_hash = block.header.try_hash().expect("hash");
        let sig = sxiaum_crypto::ed25519::sign(&sk.to_bytes(), &block_hash);
        let qc_sigs = vec![ValidatorSignature::new(val.address, sig.0)];

        let res = validator.verify_block_stateless(
            &block,
            pre_state_root,
            &witness,
            &qc_sigs,
            None,
            now,
        );
        match &res {
            Ok(post_root) => println!("Success: post_root = {}", hex::encode(post_root)),
            Err(e) => println!("Error: {e:?}"),
        }
        assert!(res.is_ok());
    }
}
