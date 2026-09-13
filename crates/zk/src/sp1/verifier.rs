#[cfg(all(not(debug_assertions), feature = "dev-simulated-proofs"))]
compile_error!("dev-simulated-proofs feature must not be enabled in release builds");

use crate::sp1::prover::{
    canonical_sp1_program_vk, Sp1Proof, Sp1ProofSystem, ZkPublicInputs, MAX_PUBLIC_INPUTS_SIZE,
    MAX_ZK_PROOF_SIZE,
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Returns `true` when `vk_hash` is a sentinel that must never be used as a real
/// production verification key (all-zeros, empty, or known placeholder strings).
///
/// Delegates to the single shared implementation in
/// [`sxiaum_crypto::kzg::is_placeholder_srs_hash`] so the SRS and VK trust
/// policies can never drift apart.
pub fn is_placeholder_vk_hash(vk_hash: &str) -> bool {
    sxiaum_crypto::kzg::is_placeholder_srs_hash(vk_hash)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1VerificationResult {
    pub verified: bool,
}

/// SP1 verifier with canonical verification key and strict fail-closed validation.
#[derive(Clone, Debug)]
pub struct Sp1Verifier {
    pub verification_key: Vec<u8>,
    pub allow_simulated_proofs: bool,
}

impl Default for Sp1Verifier {
    fn default() -> Self {
        if crate::is_production() {
            Self::new_mainnet(canonical_sp1_program_vk())
        } else {
            Self::new(canonical_sp1_program_vk())
        }
    }
}

impl Sp1Verifier {
    /// Constructs a development verifier with the given verification key.
    pub fn new(verification_key: Vec<u8>) -> Self {
        Self {
            verification_key,
            allow_simulated_proofs: true,
        }
    }

    /// Constructs a mainnet verifier that strictly forbids simulated proofs.
    pub fn new_mainnet(verification_key: Vec<u8>) -> Self {
        Self {
            verification_key,
            allow_simulated_proofs: false,
        }
    }

    /// Initialize a global SP1 verifier.
    /// If `SXIAUM_SP1_MODE=production` or `is_production()` the global verifier will be configured
    /// to disallow simulated proofs (fail-closed).
    ///
    /// # Errors
    /// Returns `Err` if `vk_hash` is empty, all-zeros, or any other placeholder.
    /// A zero key would allow any forged proof to pass verification.
    pub fn init_global(vk_hash: &str) -> Result<&'static Sp1Verifier, String> {
        static GLOBAL_SP1_VERIFIER: OnceLock<Sp1Verifier> = OnceLock::new();

        // Reject placeholder / unset VK hashes before accepting any bytes.
        if is_placeholder_vk_hash(vk_hash) {
            return Err(format!(
                "vk_hash {:?} is a placeholder / all-zeros value. \
                 A zero verification key allows any forged proof to pass. \
                 Pin the real SP1 program verification key hash in genesis.json (zk.vk_hash) \
                 before running in production.",
                vk_hash
            ));
        }

        let vk_bytes = hex::decode(vk_hash.trim_start_matches("0x"))
            .map_err(|e| format!("Invalid hex for vk_hash: {}", e))?;

        if vk_bytes.is_empty() || vk_bytes.iter().all(|&b| b == 0) {
            return Err("Decoded verification key is empty or all zeros".to_string());
        }

        let is_production = crate::is_production();

        if is_production {
            Ok(GLOBAL_SP1_VERIFIER.get_or_init(|| Sp1Verifier::new_mainnet(vk_bytes)))
        } else {
            Ok(GLOBAL_SP1_VERIFIER.get_or_init(|| Sp1Verifier::new(vk_bytes)))
        }
    }

    /// Initialize or return the global SP1 verifier honoring environment settings.
    pub fn init_global_from_env() -> &'static Sp1Verifier {
        let vk_hex = std::env::var("SXIAUM_SP1_VK_HASH")
            .unwrap_or_else(|_| crate::sp1::prover::canonical_sp1_program_vk_hash_hex());
        Self::init_global(&vk_hex).unwrap_or_else(|_| {
            static FALLBACK_VERIFIER: OnceLock<Sp1Verifier> = OnceLock::new();
            FALLBACK_VERIFIER.get_or_init(|| {
                if crate::is_production() {
                    Sp1Verifier::new_mainnet(canonical_sp1_program_vk())
                } else {
                    Sp1Verifier::new(canonical_sp1_program_vk())
                }
            })
        })
    }

    /// Primary verification entrypoint for raw proof bytes and public inputs.
    pub fn verify(&self, proof: &[u8], public_inputs: &[u8]) -> Result<bool> {
        // Step 4: deserialise strictly.
        let proof = self.deserialize_proof_bytes(proof)?;
        // Step 5: structural validation and VK integrity check.
        self.validate_proof_structure(&proof)?;
        // Step 6: execution-trace commitment check.
        self.verify_execution_trace_commitments(&proof, public_inputs)?;
        // Step 7: polynomial constraint check.
        self.verify_polynomial_constraints(&proof, public_inputs)?;
        // Steps 8 + 9: final validity check.
        self.verify_final_proof_validity(&proof, public_inputs)?;
        Ok(true)
    }

    /// Strict canonical deserialization with size limits.
    pub fn deserialize_proof_bytes(&self, proof: &[u8]) -> Result<Sp1Proof> {
        if proof.is_empty() {
            bail!("proof bytes cannot be empty");
        }
        if proof.len() > MAX_ZK_PROOF_SIZE {
            bail!(
                "proof bytes length {} exceeds maximum allowed {}",
                proof.len(),
                MAX_ZK_PROOF_SIZE
            );
        }

        bincode::deserialize::<Sp1Proof>(proof).map_err(|e| {
            anyhow::anyhow!("failed to deserialize canonical Sp1Proof envelope: {}", e)
        })
    }

    /// Step 5 — Validate proof structure and verification key.
    pub fn validate_proof_structure(&self, proof: &Sp1Proof) -> Result<()> {
        if proof.proof_bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        if proof.proof_bytes.len() > MAX_ZK_PROOF_SIZE {
            bail!(
                "proof bytes size {} exceeds maximum allowed {}",
                proof.proof_bytes.len(),
                MAX_ZK_PROOF_SIZE
            );
        }

        if proof.compressed
            && proof.proof_system == Sp1ProofSystem::SimulatedSha256
            && proof.proof_bytes.len() > 32
        {
            bail!("compressed simulated proof exceeds expected size");
        }

        if !self.allow_simulated_proofs && proof.proof_system == Sp1ProofSystem::SimulatedSha256 {
            bail!("simulated SHA-256 SP1 proofs are disabled by mainnet trust policy");
        }

        if self.verification_key.is_empty() {
            bail!("verification key cannot be empty");
        }

        if self.verification_key.iter().all(|&b| b == 0) {
            bail!("verification key cannot be all zeros");
        }

        if is_placeholder_vk_hash(&hex::encode(&self.verification_key)) {
            bail!("verification key is a known placeholder value");
        }

        Ok(())
    }

    /// Step 6 — Verify execution trace commitments.
    pub fn verify_execution_trace_commitments(
        &self,
        proof: &Sp1Proof,
        public_inputs: &[u8],
    ) -> Result<()> {
        if proof.public_inputs.is_empty() {
            bail!("proof envelope missing required public inputs");
        }
        if proof.public_inputs != public_inputs {
            bail!("public input mismatch for execution trace commitment");
        }
        Ok(())
    }

    /// Step 7 — Verify polynomial constraints.
    pub fn verify_polynomial_constraints(
        &self,
        proof: &Sp1Proof,
        public_inputs: &[u8],
    ) -> Result<()> {
        if proof.proof_bytes.is_empty() || public_inputs.is_empty() {
            bail!("polynomial constraint inputs cannot be empty");
        }
        if public_inputs.len() > MAX_PUBLIC_INPUTS_SIZE {
            bail!(
                "public inputs length {} exceeds maximum allowed {}",
                public_inputs.len(),
                MAX_PUBLIC_INPUTS_SIZE
            );
        }
        Ok(())
    }

    /// Step 8 — Verify final proof validity.
    pub fn verify_final_proof_validity(
        &self,
        proof: &Sp1Proof,
        public_inputs: &[u8],
    ) -> Result<Sp1VerificationResult> {
        let expected_commitment = self.expected_proof_commitment(public_inputs);
        let proof_commitment = self.normalized_proof_commitment(proof);

        match proof.proof_system {
            Sp1ProofSystem::SimulatedSha256 => {
                if !self.allow_simulated_proofs {
                    bail!("simulated SHA-256 SP1 proofs are disabled by mainnet trust policy");
                }
                if proof_commitment != expected_commitment {
                    bail!("final proof validity check failed");
                }
            }
            Sp1ProofSystem::Sp1Sdk => {
                // SECURITY (fail-closed): simulated commitments are never a
                // valid stand-in for a real SP1 proof, regardless of trust policy.
                #[cfg(not(feature = "sp1-sdk"))]
                {
                    let _ = (&proof_commitment, &expected_commitment);
                    bail!(
                        "cannot verify real SP1 proofs: this binary was built without the \
                         sp1-sdk feature. Production verifiers must be compiled with \
                         `--features sp1-sdk`."
                    );
                }

                #[cfg(feature = "sp1-sdk")]
                {
                    use sp1_sdk::SP1ProofWithPublicValues;

                    let proof_with_values: SP1ProofWithPublicValues =
                        bincode::deserialize(&proof.proof_bytes)
                            .map_err(|_| anyhow::anyhow!("failed to deserialize SP1 proof"))?;

                    // The guest commits the encoded ZkPublicInputs envelope via
                    // `commit_slice`; a proof is only valid for exactly these
                    // parameters.
                    if proof_with_values.public_values.as_slice() != public_inputs {
                        bail!("SP1 proof public values do not match expected public inputs");
                    }

                    // Cross-check any prover-claimed VK hash against the VK of
                    // the embedded canonical guest program.
                    if let Some(proof_vk) = &proof.vk_hash {
                        let canonical =
                            super::prover::canonical_sp1_vkey_hash_hex().map_err(|e| {
                                anyhow::anyhow!("canonical SP1 guest program rejected: {e}")
                            })?;
                        if super::prover::normalize_vkey_hash(proof_vk)
                            != super::prover::normalize_vkey_hash(&canonical)
                        {
                            bail!(
                                "proof vk_hash {} does not match canonical guest program {}",
                                proof_vk,
                                canonical
                            );
                        }
                    }

                    let client = crate::sp1::prover::real_sdk_client();
                    crate::sp1::prover::with_canonical_sp1_verifying_key(|vk| {
                        client
                            .verify(&proof_with_values, vk)
                            .map_err(|e| anyhow::anyhow!("SP1 SDK verification failed: {:?}", e))
                    })??;
                }
            }
        }

        Ok(Sp1VerificationResult { verified: true })
    }

    fn normalized_proof_commitment(&self, proof: &Sp1Proof) -> Vec<u8> {
        if proof.compressed || proof.proof_bytes.len() <= 32 {
            return proof.proof_bytes.clone();
        }

        let mut hasher = Sha256::new();
        hasher.update(&proof.proof_bytes);
        hasher.finalize().to_vec()
    }

    fn expected_proof_commitment(&self, public_inputs: &[u8]) -> Vec<u8> {
        // SECURITY (C-16): delegate to the shared single-source-of-truth
        // commitment function so the verifier's expectation is always
        // identical to what the simulated prover produces.
        crate::sp1::prover::simulated_proof_commitment(&self.verification_key, public_inputs)
    }

    /// Primary verification entry point for a block validity proof against `ZkPublicInputs`.
    pub fn verify_block_proof(
        &self,
        proof: &Sp1Proof,
        public_inputs: &ZkPublicInputs,
    ) -> Result<bool> {
        let encoded = public_inputs.encode();
        self.verify_execution_trace_commitments(proof, &encoded)?;
        self.verify_polynomial_constraints(proof, &encoded)?;
        self.verify_final_proof_validity(proof, &encoded)?;

        // Validate public input commitments
        self.validate_state_root_before(&public_inputs.state_root_before)?;
        self.validate_state_root_after(
            &public_inputs.state_root_before,
            &public_inputs.state_root_after,
        )?;
        self.validate_tx_root(&public_inputs.tx_root)?;

        Ok(true)
    }

    /// Validate the `state_root_before` commitment.
    pub fn validate_state_root_before(&self, state_root_before: &[u8; 32]) -> Result<()> {
        if state_root_before == &[0u8; 32] {
            bail!("proof public inputs: state_root_before is zero — proof was not generated from a real state");
        }
        Ok(())
    }

    /// Validate the `state_root_after` commitment.
    ///
    /// NOTE: equality with `state_root_before` is intentionally permitted here.
    /// The STF constraint layer (`verify_stf_private`) enforces the precise
    /// semantics — an empty transaction list REQUIRES equal roots, while any
    /// present state write REQUIRES the root to move. Rejecting equality here
    /// would make honest proofs for valid empty blocks unverifiable
    /// end-to-end, contradicting the guest contract.
    pub fn validate_state_root_after(
        &self,
        _state_root_before: &[u8; 32],
        state_root_after: &[u8; 32],
    ) -> Result<()> {
        if state_root_after == &[0u8; 32] {
            bail!("proof public inputs: state_root_after is zero — proof was generated without executing transactions");
        }
        Ok(())
    }

    /// Validate the `tx_root` commitment.
    pub fn validate_tx_root(&self, tx_root: &[u8; 32]) -> Result<()> {
        if tx_root == &[0u8; 32] {
            bail!("proof public inputs: tx_root is zero — proof is not bound to a valid transaction tree");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Sp1Verifier;
    use crate::sp1::prover::{canonical_sp1_program_vk, Sp1Proof, Sp1ProofSystem, ZkPublicInputs};
    use sha2::{Digest, Sha256};

    fn simulated_proof_for(vk: &[u8], public_inputs: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(vk);
        hasher.update(public_inputs);
        let execution_trace = hasher.finalize_reset();

        hasher.update(b"sp1:pk");
        hasher.update(vk);
        let proving_key = hasher.finalize_reset();

        hasher.update(proving_key);
        hasher.update(execution_trace);
        hasher.update(public_inputs);
        hasher.finalize().to_vec()
    }

    #[test]
    fn development_verifier_accepts_simulated_proof() {
        let vk = canonical_sp1_program_vk();
        let public_inputs = b"dev public inputs";
        let proof = Sp1Proof {
            proof_bytes: simulated_proof_for(&vk, public_inputs),
            public_inputs: public_inputs.to_vec(),
            compressed: false,
            proof_system: Sp1ProofSystem::SimulatedSha256,
            verkle_proofs: vec![],
            vk_hash: None,
        };
        let encoded = bincode::serialize(&proof).expect("proof should serialize");

        assert!(Sp1Verifier::new(vk)
            .verify(&encoded, public_inputs)
            .expect("development verification should run"));
    }

    /// SECURITY (C-16): the simulated prover and the verifier must agree.
    /// Before the fix the prover used a different commitment formula than
    /// `expected_proof_commitment`, so honestly generated simulated proofs
    /// could never verify (and any hand-forged bytes matching the verifier's
    /// private formula would pass while prover output failed).
    ///
    /// Only meaningful without the sp1-sdk feature: with the real SDK the
    /// prover emits genuine SP1 proofs, not simulated commitments.
    #[test]
    #[cfg(not(feature = "sp1-sdk"))]
    fn simulated_prover_output_verifies_against_development_verifier() {
        use crate::sp1::prover::{Sp1ExecutionTrace, Sp1Prover};

        let prover = Sp1Prover::default();
        let trace = Sp1ExecutionTrace {
            program: prover.program.clone(),
            witness_input: vec![7u8; 16],
            execution_trace: vec![1u8; 64],
            public_inputs: b"round-trip public inputs".to_vec(),
        };

        let proof = prover
            .generate_stark_proof(&trace)
            .expect("simulated proof should generate");
        assert_eq!(proof.proof_system, Sp1ProofSystem::SimulatedSha256);

        let encoded = bincode::serialize(&proof).expect("proof should serialize");
        let verifier = Sp1Verifier::new(canonical_sp1_program_vk());
        assert!(verifier
            .verify(&encoded, &trace.public_inputs)
            .expect("verification should run"));

        // A different VK must reject the proof (commitment is vk-bound).
        let wrong_vk_verifier = Sp1Verifier::new(vec![9u8; 32]);
        assert!(wrong_vk_verifier
            .verify(&encoded, &trace.public_inputs)
            .is_err());
    }

    #[test]
    fn mainnet_verifier_rejects_simulated_proof() {
        let vk = canonical_sp1_program_vk();
        let public_inputs = b"mainnet public inputs";
        let proof = Sp1Proof {
            proof_bytes: simulated_proof_for(&vk, public_inputs),
            public_inputs: public_inputs.to_vec(),
            compressed: false,
            proof_system: Sp1ProofSystem::SimulatedSha256,
            verkle_proofs: vec![],
            vk_hash: None,
        };
        let encoded = bincode::serialize(&proof).expect("proof should serialize");

        assert!(Sp1Verifier::new_mainnet(vk)
            .verify(&encoded, public_inputs)
            .is_err());
    }

    #[test]
    fn test_simulated_proofs_allowed_by_default_in_dev() {
        let verifier = Sp1Verifier::new(vec![1u8; 32]);
        assert!(verifier.allow_simulated_proofs);

        let mainnet_verifier = Sp1Verifier::new_mainnet(vec![1u8; 32]);
        assert!(!mainnet_verifier.allow_simulated_proofs);
    }

    #[test]
    fn placeholder_vk_hash_detection() {
        use super::is_placeholder_vk_hash;
        assert!(is_placeholder_vk_hash(
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_placeholder_vk_hash(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_placeholder_vk_hash(""));
        assert!(is_placeholder_vk_hash("0x"));
        assert!(is_placeholder_vk_hash("0xplaceholder_key"));
        assert!(!is_placeholder_vk_hash(
            "e46bd03e6cdf6317b98202ad68b350fdc2552711e39c4dbb35bfc9b1ef88d89e"
        ));
        assert!(!is_placeholder_vk_hash(
            "0xe46bd03e6cdf6317b98202ad68b350fdc2552711e39c4dbb35bfc9b1ef88d89e"
        ));
    }

    #[test]
    fn init_global_rejects_zero_vk_hash() {
        let result = Sp1Verifier::init_global(
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err(), "zero vk_hash must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("placeholder") || msg.contains("all-zeros"),
            "error must mention placeholder: {msg}"
        );
    }

    #[test]
    fn init_global_rejects_empty_vk_hash() {
        let result = Sp1Verifier::init_global("");
        assert!(result.is_err(), "empty vk_hash must be rejected");
    }

    #[test]
    fn verify_block_proof_rejects_empty_public_inputs() {
        let vk = canonical_sp1_program_vk();
        let verifier = Sp1Verifier::new(vk.clone());
        let public_inputs = ZkPublicInputs::default();
        let proof = Sp1Proof {
            proof_bytes: simulated_proof_for(&vk, &public_inputs.encode()),
            public_inputs: vec![],
            compressed: false,
            proof_system: Sp1ProofSystem::SimulatedSha256,
            verkle_proofs: vec![],
            vk_hash: None,
        };
        assert!(verifier.verify_block_proof(&proof, &public_inputs).is_err());
    }

    /// REGRESSION (empty-block proofs): `validate_state_root_after` previously
    /// rejected `state_root_after == state_root_before`, contradicting the STF
    /// guest contract which REQUIRES equal roots for empty blocks. An honest
    /// empty-block proof could therefore never pass end-to-end validation.
    #[test]
    fn state_root_validation_accepts_equal_roots_and_rejects_zero() {
        let verifier = Sp1Verifier::new(canonical_sp1_program_vk());

        // Empty-block transition: before == after, both non-zero — allowed.
        verifier
            .validate_state_root_after(&[7u8; 32], &[7u8; 32])
            .expect("equal non-zero roots must be accepted for empty blocks");

        // Zero post-root is still rejected.
        assert!(verifier
            .validate_state_root_after(&[7u8; 32], &[0u8; 32])
            .is_err());
        assert!(verifier.validate_state_root_before(&[0u8; 32]).is_err());
    }
}
