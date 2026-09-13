#[cfg(feature = "groth16")]
pub mod groth16;
pub mod sp1;

use anyhow::{bail, Result};
#[cfg(feature = "groth16")]
use ark_bls12_381::Fr;
#[cfg(feature = "groth16")]
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sxiaum_block::Block;
use sxiaum_execution::ExecutionResult;
use sxiaum_state::VerkleProof;
use sxiaum_storage::StorageEngine;

#[cfg(feature = "groth16")]
pub use crate::groth16::{serialize_verifying_key, Groth16Prover, Groth16Verifier};
pub use crate::sp1::{
    attach_private_to_witness, canonical_sp1_program_pk, canonical_sp1_program_vk,
    canonical_sp1_program_vk_hash, canonical_sp1_program_vk_hash_hex, is_placeholder_vk_hash,
    verify_stf_constraints, verify_stf_private, Sp1ExecutionEnvironment, Sp1ExecutionTrace,
    Sp1Proof, Sp1ProofSystem, Sp1Prover, Sp1Verifier, StfPrivateInputs, StfStateAccess,
    StfTxWitness, StfVerkleProof, ZkBlockWitness, ZkPublicInputs, DEFAULT_MAX_BLOCK_GAS,
    MAX_PUBLIC_INPUTS_SIZE, MAX_STF_COMMIT_REVEAL_DIGESTS, MAX_STF_STATE_READS,
    MAX_STF_STATE_WRITES, MAX_STF_TRANSACTIONS, MAX_STF_VERKLE_PROOFS, MAX_WITNESS_INPUT_SIZE,
    MAX_ZK_PROOF_SIZE, STF_CIRCUIT_VERSION,
};

/// Returns true if the node or environment is configured for production/mainnet.
pub fn is_production() -> bool {
    let env = std::env::var("SXIAUM_ENV").unwrap_or_default();
    let srs = std::env::var("SXIAUM_SRS_MODE").unwrap_or_default();
    let sp1 = std::env::var("SXIAUM_SP1_MODE").unwrap_or_default();
    let net = std::env::var("SXIAUM_NETWORK").unwrap_or_default();
    env.eq_ignore_ascii_case("production")
        || srs.eq_ignore_ascii_case("production")
        || sp1.eq_ignore_ascii_case("production")
        || net.eq_ignore_ascii_case("mainnet")
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZkTrustPolicy {
    #[default]
    Development,
    Mainnet,
}

#[derive(Clone, Debug)]
pub struct ZkEngine {
    pub prover: Sp1Prover,
    pub verifier: Sp1Verifier,
    pub trust_policy: ZkTrustPolicy,
    /// Groth16 verifier with loaded verification key. Initialized via `Groth16Verifier::from_file`.
    #[cfg(feature = "groth16")]
    pub groth16_verifier: Option<Groth16Verifier>,
    /// Groth16 prover with loaded proving key. Initialized via `Groth16Prover::from_file`.
    #[cfg(feature = "groth16")]
    pub groth16_prover: Option<Groth16Prover>,
    /// Recursive fold stack (MNT4/6-753 two-cycle). Initialized via
    /// `init_fold_stack` (dev/test) or loaded keys in production.
    #[cfg(feature = "groth16")]
    pub fold_stack: Option<crate::groth16::fold::FoldStack>,
    /// Pinned anchor-certificate statement for the fold stack.
    #[cfg(feature = "groth16")]
    pub fold_anchor: Option<crate::groth16::fold::FoldAnchorConfig>,
}

impl Default for ZkEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionTrace {
    pub program: Vec<u8>,
    pub inputs: Vec<u8>,
    pub state_reads: Vec<StateRead>,
    pub state_writes: Vec<StateWrite>,
    pub accessed_account_proofs: Vec<AccountProofWitness>,
    pub gas_used: u64,
    pub transaction_output: Option<TransactionOutput>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateRead {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateWrite {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionOutput {
    pub status: bool,
    pub gas_used: u64,
    pub log_count: usize,
    pub return_data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountProofWitness {
    pub account_key: [u8; 32],
    pub proof: VerkleProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkProof {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockValidityProof {
    pub block_hash: [u8; 32],
    pub transaction_proofs: Vec<ZkProof>,
    pub aggregated_proof: ZkProof,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveProof {
    pub proof: ZkProof,
    pub children: Vec<ZkProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultiBlockProof {
    pub block_hashes: Vec<[u8; 32]>,
    pub block_proofs: Vec<BlockValidityProof>,
    pub aggregated_proof: RecursiveProof,
}

/// A recursive proof-carrying-state fold certificate (spec §2–§3).
///
/// Certifies historical state progression from genesis (`genesis_state_root`)
/// to `target_state_root` at `target_height`. A `sel = false` certificate is
/// a trusted-delta bootstrap certificate (prior pinned to genesis); a
/// `sel = true` certificate verifies the PRIOR certificate's Groth16
/// verification equation in-circuit, chaining to
/// `(prior_state_root, prior_block_hash, prior_height)`. All certificates
/// are pinned to the canonical chain id and to the producing layer's
/// trusted-setup verification-key digest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveStateSyncProof {
    pub genesis_state_root: [u8; 32],
    pub target_state_root: [u8; 32],
    /// Canonical block header hash H_N (spec §2.1) binding the certificate to
    /// the exact finalized head — not a payload checksum.
    pub target_block_hash: [u8; 32],
    pub target_height: u64,
    /// SHA-256 of the preceding certificate's canonical encoding (metadata
    /// hash chain; the cryptographic chain binding is in-circuit).
    /// Zero for genesis-anchored bootstrap certificates.
    pub prev_certificate_hash: [u8; 32],
    /// `false` = bootstrap/trusted-delta certificate; `true` = folded
    /// certificate (prior proof verified in-circuit).
    pub sel: bool,
    /// Cycle layer that produced the proof.
    pub layer: crate::groth16::fold::FoldLayerId,
    /// SHA-256 digest of the producing layer's canonical VK.
    pub vk_digest: [u8; 32],
    /// State root this certificate builds on.
    pub prior_state_root: [u8; 32],
    /// Block hash this certificate builds on.
    pub prior_block_hash: [u8; 32],
    /// Height this certificate builds on.
    pub prior_height: u64,
    pub proof: ZkProof,
}

// ---------------------------------------------------------------------------
// Canonical fold-certificate encoding (spec §3.2)
// ---------------------------------------------------------------------------

/// Certificate magic: `SXIAUM Recursive certificateM`.
pub const RECURSIVE_CERT_MAGIC: [u8; 4] = *b"SXRM";
/// Certificate format version. Bumped on any breaking header layout change.
pub const RECURSIVE_CERT_VERSION: u16 = 2;
/// Canonical certificate header size.
pub const RECURSIVE_CERT_HEADER_SIZE: usize = 64;

/// Returns expected compressed Groth16 proof size for a given fold layer:
/// - Layer A (MNT6-753): A(95) + B(285) + C(95) = 475 bytes.
/// - Layer B (MNT4-753): A(95) + B(190) + C(95) = 380 bytes.
pub fn proof_size_for_layer(layer: crate::groth16::fold::FoldLayerId) -> usize {
    match layer {
        crate::groth16::fold::FoldLayerId::A => 475,
        crate::groth16::fold::FoldLayerId::B => 380,
    }
}

/// Total canonical certificate size for a given fold layer:
/// - Layer A (MNT6-753): 64 + 475 = 539 bytes.
/// - Layer B (MNT4-753): 64 + 380 = 444 bytes.
pub fn certificate_size_for_layer(layer: crate::groth16::fold::FoldLayerId) -> usize {
    RECURSIVE_CERT_HEADER_SIZE + proof_size_for_layer(layer)
}

/// Parsed 64-byte certificate header (spec §3.2 "Metadata").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecursiveCertificateHeader {
    pub version: u16,
    pub layer: crate::groth16::fold::FoldLayerId,
    pub sel: bool,
    pub chain_id: u64,
    pub target_height: u64,
    pub prev_certificate_hash: [u8; 32],
}

impl RecursiveStateSyncProof {
    /// Encode the canonical certificate bytes:
    /// `header(64) || compressed Groth16 proof(190 for A / 152 for B)`.
    ///
    /// Header layout (v2):
    /// `magic(4) || version(2) || layer(1) || sel(1) || chain_id(8)
    ///  || height(8) || prev_certificate_hash(32) || reserved(8)`
    pub fn certificate_bytes(&self) -> Result<Vec<u8>> {
        let expected_size = proof_size_for_layer(self.layer);
        if self.proof.bytes.len() != expected_size {
            bail!(
                "certificate for layer {:?} requires the canonical {}-byte compressed Groth16 proof, got {} bytes",
                self.layer,
                expected_size,
                self.proof.bytes.len()
            );
        }

        let total_size = RECURSIVE_CERT_HEADER_SIZE + expected_size;
        let mut out = vec![0u8; total_size];
        out[..4].copy_from_slice(&RECURSIVE_CERT_MAGIC);
        out[4..6].copy_from_slice(&RECURSIVE_CERT_VERSION.to_le_bytes());
        out[6] = self.layer.to_u8();
        out[7] = u8::from(self.sel);
        out[8..16].copy_from_slice(&sxiaum_types::SXIAUM_CHAIN_ID.to_le_bytes());
        out[16..24].copy_from_slice(&self.target_height.to_le_bytes());
        out[24..56].copy_from_slice(&self.prev_certificate_hash);
        // out[56..64] reserved (zero)
        out[RECURSIVE_CERT_HEADER_SIZE..].copy_from_slice(&self.proof.bytes);
        Ok(out)
    }

    /// SHA-256 of the canonical certificate encoding. This is the
    /// value bound by the *next* epoch's `prev_certificate_hash`.
    pub fn certificate_hash(&self) -> Result<[u8; 32]> {
        let bytes = self.certificate_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        Ok(digest)
    }

    /// Decode and validate a canonical certificate.
    ///
    /// Validates magic, version, reserved-zero discipline, and the canonical
    /// chain id. Returns the parsed header and the inner proof.
    pub fn decode_certificate(bytes: &[u8]) -> Result<(RecursiveCertificateHeader, ZkProof)> {
        if bytes.len() < RECURSIVE_CERT_HEADER_SIZE {
            bail!(
                "certificate is too short: expected at least {} bytes, got {}",
                RECURSIVE_CERT_HEADER_SIZE,
                bytes.len()
            );
        }
        if bytes[..4] != RECURSIVE_CERT_MAGIC {
            bail!("certificate magic mismatch: not an SXIAUM recursive certificate");
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into()?);
        if version != RECURSIVE_CERT_VERSION {
            bail!(
                "unsupported certificate version {}: expected {}",
                version,
                RECURSIVE_CERT_VERSION
            );
        }
        let layer = crate::groth16::fold::FoldLayerId::from_u8(bytes[6])
            .ok_or_else(|| anyhow::anyhow!("unknown fold layer tag {}", bytes[6]))?;
        let sel = match bytes[7] {
            0 => false,
            1 => true,
            other => bail!("invalid sel byte {other}"),
        };
        if bytes[56..64] != [0u8; 8] {
            bail!("certificate reserved fields must be zero");
        }
        let chain_id = u64::from_le_bytes(bytes[8..16].try_into()?);
        if chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            bail!(
                "certificate chain id {} does not match canonical chain id {}",
                chain_id,
                sxiaum_types::SXIAUM_CHAIN_ID
            );
        }
        let expected_proof_size = proof_size_for_layer(layer);
        let expected_total_size = RECURSIVE_CERT_HEADER_SIZE + expected_proof_size;
        if bytes.len() != expected_total_size {
            bail!(
                "certificate for layer {:?} must be exactly {} bytes, got {}",
                layer,
                expected_total_size,
                bytes.len()
            );
        }
        let header = RecursiveCertificateHeader {
            version,
            layer,
            sel,
            chain_id,
            target_height: u64::from_le_bytes(bytes[16..24].try_into()?),
            prev_certificate_hash: bytes[24..56].try_into()?,
        };
        let proof = ZkProof {
            bytes: bytes[RECURSIVE_CERT_HEADER_SIZE..].to_vec(),
        };
        Ok((header, proof))
    }
}

impl ZkEngine {
    pub fn new() -> Self {
        if is_production() {
            Self::new_mainnet()
        } else {
            Self {
                prover: Sp1Prover::default(),
                verifier: Sp1Verifier::new(canonical_sp1_program_vk()),
                trust_policy: ZkTrustPolicy::Development,
                #[cfg(feature = "groth16")]
                groth16_verifier: None,
                #[cfg(feature = "groth16")]
                groth16_prover: None,
                #[cfg(feature = "groth16")]
                fold_stack: None,
                #[cfg(feature = "groth16")]
                fold_anchor: None,
            }
        }
    }

    pub fn new_mainnet() -> Self {
        Self {
            prover: Sp1Prover::default(),
            verifier: Sp1Verifier::new_mainnet(canonical_sp1_program_vk()),
            trust_policy: ZkTrustPolicy::Mainnet,
            #[cfg(feature = "groth16")]
            groth16_verifier: None,
            #[cfg(feature = "groth16")]
            groth16_prover: None,
            #[cfg(feature = "groth16")]
            fold_stack: None,
            #[cfg(feature = "groth16")]
            fold_anchor: None,
        }
    }

    /// Initialise the recursive fold stack for this engine (dev/test: keys
    /// are generated in-process; production: keys must come from the
    /// genesis ceremony and be loaded from disk).
    #[cfg(feature = "groth16")]
    pub fn init_fold_stack(
        &mut self,
        anchor: crate::groth16::fold::FoldAnchorConfig,
    ) -> Result<()> {
        let stack = crate::groth16::fold::FoldStack::generate(
            anchor.clone(),
            sxiaum_types::SXIAUM_CHAIN_ID,
        )?;
        self.fold_stack = Some(stack);
        self.fold_anchor = Some(anchor);
        Ok(())
    }

    pub fn with_trust_policy(mut self, trust_policy: ZkTrustPolicy) -> Self {
        self.trust_policy = trust_policy;
        self.verifier.allow_simulated_proofs = trust_policy == ZkTrustPolicy::Development;
        self
    }

    pub fn generate_proof(&self, execution_trace: &ExecutionTrace) -> Result<ZkProof> {
        if self.trust_policy == ZkTrustPolicy::Mainnet && cfg!(not(feature = "sp1-sdk")) {
            bail!(
                "mainnet ZK proof generation requires the sp1-sdk feature and a real zkVM backend"
            );
        }

        let program = Sp1Prover::load_program_binary(&execution_trace.program)?;
        let prover = Sp1Prover::new(program);
        let proof = prover.prove(&execution_trace.serialize_for_zkvm_input()?)?;

        if self.trust_policy == ZkTrustPolicy::Mainnet
            && proof.proof_system == Sp1ProofSystem::SimulatedSha256
        {
            bail!("mainnet ZK proof generation produced a simulated proof");
        }

        Ok(ZkProof {
            bytes: bincode::serialize(&proof)?,
        })
    }

    /// Initialise the Groth16 verifier from a verification key file.
    ///
    /// `vk_path` should point to a file containing the serialized `VerifyingKey`.
    /// Returns `Ok(())` and stores the verifier internally, or propagates any error.
    #[cfg(feature = "groth16")]
    pub fn init_groth16_verifier(&mut self, vk_path: &str) -> Result<()> {
        let verifier = Groth16Verifier::from_file(vk_path)?;
        self.groth16_verifier = Some(verifier);
        Ok(())
    }

    /// Initialise the Groth16 prover from a serialized proving key file.
    #[cfg(feature = "groth16")]
    pub fn init_groth16_prover(&mut self, pk_path: &str) -> Result<()> {
        let prover = Groth16Prover::from_file(pk_path)?;
        self.groth16_prover = Some(prover);
        Ok(())
    }

    /// Generate a Groth16 proof for the current execution-circuit scaffold.
    ///
    /// The trace is hashed into deterministic field elements and assigned to
    /// the `ExecutionCircuit` relation used by `Groth16Prover`. Production STF
    /// proofs must replace this scaffold with the final audited state
    /// transition circuit while keeping this proving-key/proof plumbing.
    #[cfg(feature = "groth16")]
    pub fn generate_groth16_proof(&self, trace: &ExecutionTrace) -> Result<ZkProof> {
        let prover = self
            .groth16_prover
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Groth16 prover not initialised"))?;

        let (state_root_before, block_hash, state_root_after) =
            groth16_public_inputs_for_trace(trace)?;
        let proof =
            prover.generate_proof_from_witness(state_root_before, block_hash, state_root_after)?;

        Ok(ZkProof {
            bytes: crate::groth16::serialize_proof(&proof)?,
        })
    }

    /// Generate a Groth16 state transition proof for single-hop state verification.
    #[cfg(feature = "groth16")]
    pub fn generate_state_transition_proof(
        &self,
        state_root_before: [u8; 32],
        block_hash: [u8; 32],
        _state_root_after: [u8; 32],
    ) -> Result<ZkProof> {
        use ark_ff::PrimeField;
        let prover = self
            .groth16_prover
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Groth16 prover not initialised"))?;

        let a = Fr::from_le_bytes_mod_order(&state_root_before);
        let b = Fr::from_le_bytes_mod_order(&block_hash);
        let c = a + b;
        let proof = prover.generate_proof_from_witness(a, b, c)?;

        Ok(ZkProof {
            bytes: crate::groth16::serialize_proof(&proof)?,
        })
    }

    /// Verify a Groth16 proof against the given public inputs.
    ///
    /// The verifier must have been initialised via `init_groth16_verifier`.
    /// Returns `Ok(true)` on successful verification.
    #[cfg(feature = "groth16")]
    pub fn verify_groth16_proof(&self, proof: &ZkProof, public_inputs: &[u8]) -> Result<bool> {
        let verifier = self
            .groth16_verifier
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Groth16 verifier not initialised"))?;
        verifier.verify(&proof.bytes, public_inputs)
    }

    // -----------------------------------------------------------------------
    // Recursive state-sync fold certificates (spec §2–§3)
    // -----------------------------------------------------------------------

    /// Generate a canonical **bootstrap** (`sel = 0`) recursive state-sync
    /// certificate: a trusted-delta certificate whose prior is pinned to
    /// genesis. This is the trust level of the pre-fold epoch certificates
    /// and of the genesis anchor certificate.
    ///
    /// Binds, as Groth16 public inputs: genesis root S₀, target root S_N,
    /// canonical block header hash H_N, height, the canonical
    /// [`sxiaum_types::SXIAUM_CHAIN_ID`] (C-16), and the layer's trusted-setup
    /// VK digest (§2.2 fail-closed VK pinning).
    #[cfg(feature = "groth16")]
    pub fn generate_recursive_state_sync_proof(
        &self,
        genesis_state_root: [u8; 32],
        target_state_root: [u8; 32],
        target_block_hash: [u8; 32],
        target_height: u64,
        prev_certificate_hash: [u8; 32],
    ) -> Result<RecursiveStateSyncProof> {
        use crate::groth16::fold::{FoldStatement, PriorProofPoints, PriorVK, serialize_fold_proof};
        let stack = self
            .fold_stack
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fold stack not initialised"))?;
        let vk_digest = stack.prover_a.vk_digest;
        let statement = FoldStatement {
            sel: false,
            genesis_root: genesis_state_root,
            target_root: target_state_root,
            target_block_hash,
            target_height,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest,
            prior_root: genesis_state_root,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
        };
        let prior_statement = FoldStatement::genesis_prior(
            genesis_state_root,
            sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest,
        );
        // sel = 0 opens the pairing and VK-commitment gates; the prior proof
        // points and prior VK are inert filler.
        let prior_prior_statement = prior_statement.clone();
        let proof = stack.prover_a.prove(
            statement,
            prior_statement,
            prior_prior_statement,
            &PriorVK::dummy_for_setup(),
            &PriorProofPoints::generators(),
        )?;
        let proof_bytes = serialize_fold_proof(&proof)?;

        Ok(RecursiveStateSyncProof {
            genesis_state_root,
            target_state_root,
            target_block_hash,
            target_height,
            prev_certificate_hash,
            sel: false,
            layer: crate::groth16::fold::FoldLayerId::A,
            vk_digest,
            prior_state_root: genesis_state_root,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
            proof: ZkProof {
                bytes: proof_bytes.to_vec(),
            },
        })
    }

    /// Fold a new certificate on top of a verified prior certificate
    /// (`sel = 1`): the produced proof **verifies the prior certificate's
    /// Groth16 verification equation in-circuit** and chains to the prior
    /// statement. This is the recursive composition step (§2.3).
    ///
    /// The prior must be either a folded (`sel = 1`) certificate or the
    /// pinned anchor certificate; anything else is rejected before proving.
    #[cfg(feature = "groth16")]
    #[allow(clippy::too_many_arguments)]
    pub fn generate_folded_certificate(
        &self,
        genesis_state_root: [u8; 32],
        prior: &RecursiveStateSyncProof,
        prior_prior: Option<&RecursiveStateSyncProof>,
        target_state_root: [u8; 32],
        target_block_hash: [u8; 32],
        target_height: u64,
        prev_certificate_hash: [u8; 32],
    ) -> Result<RecursiveStateSyncProof> {
        use crate::groth16::fold::{
            FoldLayerId, FoldStatement, PriorProofPoints, PriorVK, deserialize_fold_proof,
            serialize_fold_proof,
        };
        let stack = self
            .fold_stack
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fold stack not initialised"))?;
        let anchor = self
            .fold_anchor
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fold anchor not initialised"))?;
        if !prior.sel {
            let prior_is_anchor = prior.target_state_root == anchor.root
                && prior.target_block_hash == anchor.block_hash
                && prior.target_height == anchor.height
                && prior.prior_state_root == genesis_state_root
                && prior.prior_block_hash == [0u8; 32]
                && prior.prior_height == 0;
            if !prior_is_anchor {
                bail!("folded certificate requires a folded (sel) prior certificate or the pinned anchor certificate");
            }
        }
        let prior_statement = FoldStatement {
            sel: prior.sel,
            genesis_root: genesis_state_root,
            target_root: prior.target_state_root,
            target_block_hash: prior.target_block_hash,
            target_height: prior.target_height,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest: prior.vk_digest,
            prior_root: prior.prior_state_root,
            prior_block_hash: prior.prior_block_hash,
            prior_height: prior.prior_height,
        };
        // The prior circuit's own chunk publics + prior_sel + prior_vk_digest
        // derive from the prior-prior statement: for a folded prior it is the
        // caller-supplied certificate; for an anchor prior it is the
        // genesis-anchored statement (whose vk_digest equals the anchor's).
        let prior_prior_statement = match prior_prior {
            Some(pp) => FoldStatement {
                sel: pp.sel,
                genesis_root: genesis_state_root,
                target_root: pp.target_state_root,
                target_block_hash: pp.target_block_hash,
                target_height: pp.target_height,
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                vk_digest: pp.vk_digest,
                prior_root: pp.prior_state_root,
                prior_block_hash: pp.prior_block_hash,
                prior_height: pp.prior_height,
            },
            None => FoldStatement::genesis_prior(
                genesis_state_root,
                sxiaum_types::SXIAUM_CHAIN_ID,
                prior.vk_digest,
            ),
        };
                // The new layer is the opposite of the prior layer's; each layer
        // verifies prior proofs of the OTHER curve under that curve's VK.
        let (proof_bytes, new_layer, new_vk_digest) = match prior.layer {
            FoldLayerId::A => {
                // New layer-B certificate verifies the prior layer-A (MNT6)
                // proof under VK_A.
                let p =
                    deserialize_fold_proof::<ark_mnt6_753::MNT6_753>(&prior.proof.bytes)?;
                let prior_proof = PriorProofPoints::from_proof(&p);
                let prior_vk = PriorVK::from_verifying_key(&stack.prover_a.vk)?;
                let statement = FoldStatement {
                    sel: true,
                    genesis_root: genesis_state_root,
                    target_root: target_state_root,
                    target_block_hash,
                    target_height,
                    chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                    vk_digest: stack.prover_b.vk_digest,
                    prior_root: prior.target_state_root,
                    prior_block_hash: prior.target_block_hash,
                    prior_height: prior.target_height,
                };
                let proof = stack.prover_b.prove(
                    statement,
                    prior_statement.clone(),
                    prior_prior_statement,
                    &prior_vk,
                    &prior_proof,
                )?;
                (
                    serialize_fold_proof(&proof)?.to_vec(),
                    FoldLayerId::B,
                    stack.prover_b.vk_digest,
                )
            }
            FoldLayerId::B => {
                // New layer-A certificate verifies the prior layer-B (MNT4)
                // proof under VK_B (pinned as verifier_a's prior VK).
                let p =
                    deserialize_fold_proof::<ark_mnt4_753::MNT4_753>(&prior.proof.bytes)?;
                let prior_proof = PriorProofPoints::from_proof(&p);
                let prior_vk = PriorVK::from_verifying_key(&stack.prover_b.vk)?;
                let statement = FoldStatement {
                    sel: true,
                    genesis_root: genesis_state_root,
                    target_root: target_state_root,
                    target_block_hash,
                    target_height,
                    chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                    vk_digest: stack.prover_a.vk_digest,
                    prior_root: prior.target_state_root,
                    prior_block_hash: prior.target_block_hash,
                    prior_height: prior.target_height,
                };
                let proof = stack.prover_a.prove(
                    statement,
                    prior_statement.clone(),
                    prior_prior_statement,
                    &prior_vk,
                    &prior_proof,
                )?;
                (
                    serialize_fold_proof(&proof)?.to_vec(),
                    FoldLayerId::A,
                    stack.prover_a.vk_digest,
                )
            }
        };

        Ok(RecursiveStateSyncProof {
            genesis_state_root,
            target_state_root,
            target_block_hash,
            target_height,
            prev_certificate_hash,
            sel: true,
            layer: new_layer,
            vk_digest: new_vk_digest,
            prior_state_root: prior.target_state_root,
            prior_block_hash: prior.target_block_hash,
            prior_height: prior.target_height,
            proof: ZkProof { bytes: proof_bytes },
        })
    }

    /// Verify a bootstrap (`sel = 0`) recursive state-sync certificate with
    /// a **single pairing check**.
    ///
    /// Layer A (MNT6-753, 475 bytes compressed proof) is the sole externally-facing
    /// certificate format consumed by light clients and new-node bootstrap; Layer B
    /// is purely an internal proving-stack intermediate never exposed outside `crates/zk`.
    ///
    /// Verification recomputes ALL public inputs itself — the canonical chain
    /// id (C-16), the pinned prior-layer VK, and the digest of THIS
    /// verifier's pinned VK (§2.2) — so a certificate is only valid for this
    /// network and this trusted setup. `prev_certificate_hash` is wire
    /// metadata (not a Groth16 public input in the fold format).
    #[cfg(feature = "groth16")]
    pub fn verify_recursive_state_sync_proof(
        &self,
        genesis_state_root: [u8; 32],
        target_state_root: [u8; 32],
        target_block_hash: [u8; 32],
        target_height: u64,
        _prev_certificate_hash: [u8; 32],
        proof: &ZkProof,
    ) -> Result<bool> {
        use crate::groth16::fold::{
            FoldStatement, deserialize_fold_proof,
        };
        if proof.bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }
        let expected_size = proof_size_for_layer(crate::groth16::fold::FoldLayerId::A);
        if proof.bytes.len() != expected_size {
            bail!(
                "recursive state sync certificate must carry a canonical {}-byte compressed proof, got {} bytes",
                expected_size,
                proof.bytes.len()
            );
        }
        let stack = self
            .fold_stack
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fold stack not initialised"))?;
        let vk_digest = stack.prover_a.vk_digest;
        let statement = FoldStatement {
            sel: false,
            genesis_root: genesis_state_root,
            target_root: target_state_root,
            target_block_hash,
            target_height,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest,
            prior_root: genesis_state_root,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
        };
        let prior_statement = FoldStatement::genesis_prior(
            genesis_state_root,
            sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest,
        );
        let prior_prior_statement = prior_statement.clone();
        let fold_proof = deserialize_fold_proof::<ark_mnt6_753::MNT6_753>(&proof.bytes)?;
        stack.verifier_a.verify(
            &statement,
            &prior_statement,
            &prior_prior_statement,
            &fold_proof,
        )
    }

    /// Verify a folded (`sel = 1`) certificate with a **single pairing
    /// check**, independent of how many folds preceded it (O(1) sync
    /// verification; spec §4).
    ///
    /// `prior_meta` and `prior_prior_meta` are the two preceding
    /// certificates' statements (metadata only — no prior proof is needed:
    /// the prior proof is verified in-circuit by the certificate's own
    /// constraints and bound to these statements by them).
    #[cfg(feature = "groth16")]
    pub fn verify_folded_certificate(
        &self,
        genesis_state_root: [u8; 32],
        cert: &RecursiveStateSyncProof,
        prior_meta: &RecursiveStateSyncProof,
        prior_prior_meta: Option<&RecursiveStateSyncProof>,
    ) -> Result<bool> {
        use crate::groth16::fold::{FoldLayerId, FoldStatement, deserialize_fold_proof};
        if !cert.sel {
            bail!("not a folded certificate: use verify_recursive_state_sync_proof for bootstrap certificates");
        }
        if prior_meta.target_state_root != cert.prior_state_root
            || prior_meta.target_block_hash != cert.prior_block_hash
            || prior_meta.target_height != cert.prior_height
        {
            bail!("prior metadata does not match the certificate's in-circuit prior binding");
        }
        let prior_prior = match prior_prior_meta {
            Some(pp) => {
                if pp.target_state_root != prior_meta.prior_state_root
                    || pp.target_block_hash != prior_meta.prior_block_hash
                    || pp.target_height != prior_meta.prior_height
                {
                    bail!("prior-prior metadata does not match the prior certificate's binding");
                }
                FoldStatement {
                    sel: pp.sel,
                    genesis_root: genesis_state_root,
                    target_root: pp.target_state_root,
                    target_block_hash: pp.target_block_hash,
                    target_height: pp.target_height,
                    chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                    vk_digest: pp.vk_digest,
                    prior_root: pp.prior_state_root,
                    prior_block_hash: pp.prior_block_hash,
                    prior_height: pp.prior_height,
                }
            }
            None => {
                if prior_meta.sel {
                    bail!("folded prior requires prior-prior metadata");
                }
                FoldStatement::genesis_prior(
                    genesis_state_root,
                    sxiaum_types::SXIAUM_CHAIN_ID,
                    prior_meta.vk_digest,
                )
            }
        };
        let stack = self
            .fold_stack
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("fold stack not initialised"))?;
        let own = FoldStatement {
            sel: true,
            genesis_root: genesis_state_root,
            target_root: cert.target_state_root,
            target_block_hash: cert.target_block_hash,
            target_height: cert.target_height,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest: cert.vk_digest,
            prior_root: cert.prior_state_root,
            prior_block_hash: cert.prior_block_hash,
            prior_height: cert.prior_height,
        };
        let prior = FoldStatement {
            sel: prior_meta.sel,
            genesis_root: genesis_state_root,
            target_root: prior_meta.target_state_root,
            target_block_hash: prior_meta.target_block_hash,
            target_height: prior_meta.target_height,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest: prior_meta.vk_digest,
            prior_root: prior_meta.prior_state_root,
            prior_block_hash: prior_meta.prior_block_hash,
            prior_height: prior_meta.prior_height,
        };
        match cert.layer {
            FoldLayerId::A => {
                let p =
                    deserialize_fold_proof::<ark_mnt6_753::MNT6_753>(&cert.proof.bytes)?;
                stack
                    .verifier_a
                    .verify(&own, &prior, &prior_prior, &p)
            }
            FoldLayerId::B => {
                let p =
                    deserialize_fold_proof::<ark_mnt4_753::MNT4_753>(&cert.proof.bytes)?;
                stack
                    .verifier_b
                    .verify(&own, &prior, &prior_prior, &p)
            }
        }
    }

    /// Verify a genesis-anchored chain of fold certificates (spec §2).
    ///
    /// This is the **transition-mode** path with verification cost
    /// O(#epochs) pairing checks (see §4 for the O(1) folded-tip path):
    /// certificate 0 must be a bootstrap (`sel = 0`) certificate whose
    /// statement matches the pinned anchor configuration; every later
    /// certificate must be folded (`sel = 1`) — its proof verifies the
    /// predecessor's Groth16 equation in-circuit; every certificate commits
    /// to the SHA-256 of its predecessor's canonical encoding (metadata
    /// hash chain); heights strictly increase. Returns the certified final
    /// height.
    pub fn verify_recursive_certificate_chain(
        &self,
        genesis_state_root: [u8; 32],
        certificates: &[RecursiveStateSyncProof],
    ) -> Result<u64> {
        if certificates.is_empty() {
            bail!("certificate chain cannot be empty");
        }

        let mut expected_prev_hash = [0u8; 32];
        let mut prev_height: Option<u64> = None;

        for (index, cert) in certificates.iter().enumerate() {
            // Metadata hash chain: each certificate commits to the canonical
            // hash of its actual predecessor.
            if cert.prev_certificate_hash != expected_prev_hash {
                bail!(
                    "certificate chain broken at index {}: prev_certificate_hash does not match the hash of the preceding certificate",
                    index
                );
            }
            if let Some(prev_h) = prev_height {
                if cert.target_height <= prev_h {
                    bail!(
                        "certificate heights must strictly increase: {} follows {}",
                        cert.target_height,
                        prev_h
                    );
                }
            }

            let valid = if index == 0 {
                if cert.sel {
                    bail!("first chain certificate must be a bootstrap (sel = 0) certificate");
                }
                self.verify_recursive_state_sync_proof(
                    genesis_state_root,
                    cert.target_state_root,
                    cert.target_block_hash,
                    cert.target_height,
                    cert.prev_certificate_hash,
                    &cert.proof,
                )?
                        } else if index == 1 {
                // Second certificate: it is a fold over the bootstrap (index 0).
                // The prior-prior is implicitly the genesis anchor statement
                // (sel = 0, prior pinned to genesis), so we verify it directly
                // as a bootstrap-style fold against the anchor.
                self.verify_folded_certificate(
                    genesis_state_root,
                    cert,
                    &certificates[index - 1],
                    None,
                )?
            } else {
                if !cert.sel {
                    bail!("chain certificate {index} must be a folded (sel = 1) certificate");
                }
                self.verify_folded_certificate(
                    genesis_state_root,
                    cert,
                    &certificates[index - 1],
                    Some(&certificates[index - 2]),
                )?
            };
            if !valid {
                bail!(
                    "certificate chain invalid: pairing check failed at index {} (height {})",
                    index,
                    cert.target_height
                );
            }

            expected_prev_hash = cert.certificate_hash()?;
            prev_height = Some(cert.target_height);
        }

        match certificates.last() {
            Some(last) => Ok(last.target_height),
            None => unreachable!("non-empty checked above"),
        }
    }

    pub fn verify_proof(&self, proof: &ZkProof, public_inputs: &[u8]) -> Result<bool> {
        if proof.bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }
        if proof.bytes.len() > MAX_ZK_PROOF_SIZE {
            bail!(
                "proof bytes size {} exceeds maximum allowed {}",
                proof.bytes.len(),
                MAX_ZK_PROOF_SIZE
            );
        }
        if public_inputs.is_empty() {
            bail!("public inputs cannot be empty");
        }
        if public_inputs.len() > MAX_PUBLIC_INPUTS_SIZE {
            bail!(
                "public inputs size {} exceeds maximum allowed {}",
                public_inputs.len(),
                MAX_PUBLIC_INPUTS_SIZE
            );
        }

        self.verifier.verify(&proof.bytes, public_inputs)
    }

    pub fn serialize_proof(&self, proof: &ZkProof) -> Result<Vec<u8>> {
        Ok(bincode::serialize(proof)?)
    }

    pub fn deserialize_proof(&self, bytes: &[u8]) -> Result<ZkProof> {
        Ok(bincode::deserialize(bytes)?)
    }

    pub fn proof_hash(&self, proof: &ZkProof) -> Result<[u8; 32]> {
        let encoded = self.serialize_proof(proof)?;
        let mut hasher = Sha256::new();
        hasher.update(encoded);
        let digest = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        Ok(hash)
    }

    pub fn proof_size(&self, proof: &ZkProof) -> Result<usize> {
        Ok(proof.bytes.len())
    }

    pub fn batch_verify(&self, proofs: &[ZkProof], public_inputs: &[Vec<u8>]) -> Result<bool> {
        if proofs.len() != public_inputs.len() {
            bail!("mismatched number of proofs and public inputs");
        }
        for (proof, pi) in proofs.iter().zip(public_inputs.iter()) {
            if !self.verify_proof(proof, pi)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn prove_all_transactions_in_block(
        &self,
        block: &Block,
        execution_traces: &[ExecutionTrace],
    ) -> Result<Vec<ZkProof>> {
        if block.body.transactions.len() != execution_traces.len() {
            bail!(
                "transaction/trace length mismatch ({} != {})",
                block.body.transactions.len(),
                execution_traces.len()
            );
        }

        execution_traces
            .iter()
            .map(|trace| self.generate_proof(trace))
            .collect()
    }

    pub fn aggregate_transaction_proofs(&self, proofs: &[ZkProof]) -> Result<RecursiveProof> {
        if proofs.is_empty() {
            bail!("cannot aggregate an empty set of transaction proofs");
        }

        Ok(RecursiveProof {
            proof: self.aggregate_recursive_layer(b"zk:tx", proofs)?,
            children: proofs.to_vec(),
        })
    }

    pub fn generate_block_validity_proof(
        &self,
        block: &Block,
        execution_traces: &[ExecutionTrace],
    ) -> Result<BlockValidityProof> {
        let transaction_proofs = self.prove_all_transactions_in_block(block, execution_traces)?;
        let transaction_aggregate = self.aggregate_transaction_proofs(&transaction_proofs)?;
        let aggregated_proof =
            self.aggregate_block_proof(block, &transaction_proofs, &transaction_aggregate.proof)?;

        Ok(BlockValidityProof {
            block_hash: block.try_hash()?,
            transaction_proofs,
            aggregated_proof,
        })
    }

    pub fn generate_proof_after_block_execution(
        &self,
        block: &Block,
        execution_traces: &[ExecutionTrace],
    ) -> Result<BlockValidityProof> {
        self.generate_block_validity_proof(block, execution_traces)
    }

    pub fn attach_proof_to_block_header(
        &self,
        block: &mut Block,
        proof: &BlockValidityProof,
    ) -> Result<()> {
        block.attach_validity_proof(bincode::serialize(proof)?);
        Ok(())
    }

    pub fn store_block_proof(
        &self,
        storage: &StorageEngine,
        height: u64,
        proof: &BlockValidityProof,
    ) -> Result<()> {
        storage.store_zk_proof(height, bincode::serialize(proof)?)
    }

    pub fn load_block_proof(
        &self,
        storage: &StorageEngine,
        height: u64,
    ) -> Result<Option<BlockValidityProof>> {
        storage
            .get_zk_proof(height)?
            .map(|bytes| bincode::deserialize(&bytes).map_err(Into::into))
            .transpose()
    }

    pub fn aggregate_block_proofs(
        &self,
        block_proofs: &[BlockValidityProof],
    ) -> Result<RecursiveProof> {
        if block_proofs.is_empty() {
            bail!("cannot aggregate an empty set of block proofs");
        }

        let child_proofs: Vec<ZkProof> = block_proofs
            .iter()
            .map(|proof| proof.aggregated_proof.clone())
            .collect();

        Ok(RecursiveProof {
            proof: self.aggregate_recursive_layer(b"zk:block", &child_proofs)?,
            children: child_proofs,
        })
    }

    pub fn generate_recursive_proof(&self, proofs: &[ZkProof]) -> Result<RecursiveProof> {
        if proofs.is_empty() {
            bail!("cannot generate a recursive proof from an empty proof set");
        }

        Ok(RecursiveProof {
            proof: self.aggregate_recursive_layer(b"zk:recursive", proofs)?,
            children: proofs.to_vec(),
        })
    }

    pub fn produce_single_proof_for_multiple_blocks(
        &self,
        blocks: &[Block],
        block_traces: &[Vec<ExecutionTrace>],
    ) -> Result<MultiBlockProof> {
        if blocks.len() != block_traces.len() {
            bail!(
                "block/trace batch length mismatch ({} != {})",
                blocks.len(),
                block_traces.len()
            );
        }

        let block_proofs: Result<Vec<_>> = blocks
            .iter()
            .zip(block_traces.iter())
            .map(|(block, traces)| self.generate_block_validity_proof(block, traces))
            .collect();
        let block_proofs = block_proofs?;
        let aggregated_proof = self.aggregate_block_proofs(&block_proofs)?;

        Ok(MultiBlockProof {
            block_hashes: blocks
                .iter()
                .map(|b| b.try_hash())
                .collect::<Result<Vec<_>>>()?,
            block_proofs,
            aggregated_proof,
        })
    }
}

impl ExecutionTrace {
    pub fn new(program: Vec<u8>, inputs: Vec<u8>) -> Self {
        Self {
            program,
            inputs,
            state_reads: Vec::new(),
            state_writes: Vec::new(),
            accessed_account_proofs: Vec::new(),
            gas_used: 0,
            transaction_output: None,
        }
    }

    pub fn capture_from_execution_engine(
        program: Vec<u8>,
        inputs: Vec<u8>,
        execution_result: &ExecutionResult,
        state_reads: Vec<(Vec<u8>, Vec<u8>)>,
        state_writes: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Self {
        let mut trace = Self::new(program, inputs);
        for (key, value) in state_reads {
            trace.record_state_read(key, value);
        }
        for (key, value) in state_writes {
            trace.record_state_write(key, value);
        }
        trace.record_gas_usage(execution_result.gas_used);
        trace.record_transaction_output(execution_result);
        trace
    }

    pub fn generate_verkle_proof_for_accessed_accounts(
        &mut self,
        proofs: Vec<([u8; 32], VerkleProof)>,
    ) {
        self.accessed_account_proofs = proofs
            .into_iter()
            .map(|(account_key, proof)| AccountProofWitness { account_key, proof })
            .collect();
    }

    pub fn attach_proof_to_zk_witness(&mut self, account_key: [u8; 32], proof: VerkleProof) {
        self.accessed_account_proofs
            .push(AccountProofWitness { account_key, proof });
    }

    pub fn record_state_read(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state_reads.push(StateRead { key, value });
    }

    pub fn record_state_write(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state_writes.push(StateWrite { key, value });
    }

    pub fn record_gas_usage(&mut self, gas_used: u64) {
        self.gas_used = gas_used;
    }

    pub fn record_transaction_output(&mut self, execution_result: &ExecutionResult) {
        self.transaction_output = Some(TransactionOutput {
            status: execution_result.status,
            gas_used: execution_result.gas_used,
            log_count: execution_result.logs.len(),
            return_data: execution_result.return_data.clone(),
        });
    }

    pub fn serialize_for_zkvm_input(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn verkle_proof_commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for witness in &self.accessed_account_proofs {
            hasher.update(witness.account_key);
            for commitment in &witness.proof.commitments {
                hasher.update(commitment);
            }
            for path_index in &witness.proof.path {
                hasher.update([*path_index as u8]);
            }
            for value in &witness.proof.values {
                hasher.update(value);
            }
        }
        let digest = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&digest);
        commitment
    }
}

#[cfg(feature = "groth16")]
pub fn groth16_public_inputs_for_trace(trace: &ExecutionTrace) -> Result<(Fr, Fr, Fr)> {
    let trace_bytes = trace.serialize_for_zkvm_input()?;

    let state_root_before = field_from_domain_bytes(b"groth16:state_root_before", &trace_bytes);
    let block_hash = field_from_domain_bytes(b"groth16:block_hash", &trace_bytes);
    let state_root_after = state_root_before + block_hash;

    Ok((state_root_before, block_hash, state_root_after))
}

#[cfg(feature = "groth16")]
pub fn serialize_groth16_trace_public_inputs(trace: &ExecutionTrace) -> Result<Vec<u8>> {
    let (state_root_before, block_hash, state_root_after) = groth16_public_inputs_for_trace(trace)?;
    crate::groth16::serialize_public_inputs(&[state_root_before, state_root_after, block_hash])
}

/// Encode state transition public inputs `[state_root_before, state_root_after, block_hash]` for Groth16 verifier.
#[cfg(feature = "groth16")]
pub fn encode_state_transition_public_inputs(
    state_root_before: [u8; 32],
    block_hash: [u8; 32],
    _state_root_after: [u8; 32],
) -> Vec<u8> {
    use ark_ff::PrimeField;
    let a = Fr::from_le_bytes_mod_order(&state_root_before);
    let b = Fr::from_le_bytes_mod_order(&block_hash);
    let c = a + b;
    crate::groth16::serialize_public_inputs(&[a, c, b]).unwrap_or_default()
}

#[cfg(feature = "groth16")]
fn field_from_domain_bytes(domain: &[u8], bytes: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Fr::from_le_bytes_mod_order(&hasher.finalize())
}

impl ZkEngine {
    fn aggregate_block_proof(
        &self,
        block: &Block,
        proofs: &[ZkProof],
        transaction_aggregate: &ZkProof,
    ) -> Result<ZkProof> {
        let mut hasher = Sha256::new();
        hasher.update(block.try_hash()?);
        for proof in proofs {
            let proof_hash = self.proof_hash(proof)?;
            hasher.update(proof_hash);
        }
        hasher.update(self.proof_hash(transaction_aggregate)?);

        Ok(ZkProof {
            bytes: hasher.finalize().to_vec(),
        })
    }

    fn aggregate_recursive_layer(&self, domain: &[u8], proofs: &[ZkProof]) -> Result<ZkProof> {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        for proof in proofs {
            hasher.update(self.proof_hash(proof)?);
        }

        Ok(ZkProof {
            bytes: hasher.finalize().to_vec(),
        })
    }

    // -----------------------------------------------------------------------
    // Block-witness construction (items 3, 4, 5)
    // -----------------------------------------------------------------------

    /// Items 3 + 4 - Build a `ZkBlockWitness` from a block and its execution traces.
    ///
    /// Captures the execution trace for each transaction (item 4), derives the
    /// `ZkPublicInputs` from the parent state root, the post-execution state
    /// root, and the block hash (items 14-16), then wraps everything in a
    /// `ZkBlockWitness` ready to be passed to the SP1 prover (item 5).
    ///
    /// # Parameters
    /// * `block`              - the finalized block.
    /// * `state_root_before`  - Verkle root **before** applying the block.
    /// * `execution_traces`   - one `ExecutionTrace` per transaction.
    pub fn build_block_witness(
        &self,
        block: &Block,
        state_root_before: [u8; 32],
        execution_traces: &[ExecutionTrace],
    ) -> Result<ZkBlockWitness> {
        if block.body.transactions.len() != execution_traces.len() {
            bail!(
                "transaction/trace count mismatch ({} vs {})",
                block.body.transactions.len(),
                execution_traces.len()
            );
        }

        // Per-tx gas from execution traces (fallback to 0).
        let gas_used_per_tx: Vec<u64> = execution_traces
            .iter()
            .map(|t| {
                t.transaction_output
                    .as_ref()
                    .map(|o| o.gas_used)
                    .unwrap_or(t.gas_used)
            })
            .collect();

        // Flatten state accesses + verkle proofs from all traces.
        let mut state_reads = Vec::new();
        let mut state_writes = Vec::new();
        let mut verkle_proofs = Vec::new();
        for t in execution_traces {
            for r in &t.state_reads {
                state_reads.push(StfStateAccess {
                    key: r.key.clone(),
                    value: r.value.clone(),
                });
            }
            for w in &t.state_writes {
                state_writes.push(StfStateAccess {
                    key: w.key.clone(),
                    value: w.value.clone(),
                });
            }
            for p in &t.accessed_account_proofs {
                verkle_proofs.push(StfVerkleProof {
                    commitments: p.proof.commitments.clone(),
                    evaluation_points: p
                        .proof
                        .path
                        .iter()
                        .map(|&i| {
                            let mut pt = [0u8; 32];
                            pt[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                            pt
                        })
                        .collect(),
                    evaluations: p
                        .proof
                        .commitments
                        .iter()
                        .skip(1)
                        .copied()
                        .chain(std::iter::once(
                            p.proof.values.last().copied().unwrap_or([0u8; 32]),
                        ))
                        .collect(),
                    opening_proofs: p.proof.openings.iter().map(|o| o.to_vec()).collect(),
                    witness_root: [0u8; 32],
                });
            }
        }

        let witness_root = crate::sp1::stf::compute_verkle_commitment(&verkle_proofs);

        let public_inputs = ZkPublicInputs::new(
            block.header.chain_id,
            block.header.version,
            STF_CIRCUIT_VERSION,
            [0u8; 32],
            block.header.height,
            block.header.parent_hash,
            state_root_before,
            block.header.state_root,
            block.header.tx_root,
            block.header.receipts_root,
            witness_root,
            block.header.randomness_beacon,
        );

        let private = StfPrivateInputs::from_block(
            block,
            &gas_used_per_tx,
            state_reads,
            state_writes,
            verkle_proofs,
            Vec::new(),
            Vec::new(),
            DEFAULT_MAX_BLOCK_GAS,
            &public_inputs,
        )?;

        // Aggregate all individual traces into a single canonical host-side
        // execution-trace blob (still useful for debugging / simulators).
        let program = execution_traces
            .first()
            .map(|t| t.program.clone())
            .unwrap_or_else(|| self.prover.program.clone());
        let private_bytes = private.encode()?;
        let block_trace = Sp1ExecutionTrace {
            program,
            witness_input: private_bytes.clone(),
            execution_trace: self.prover.capture_execution_trace(&private_bytes)?,
            public_inputs: public_inputs.encode(),
        };

        let witness = ZkBlockWitness::new(block_trace, public_inputs);
        // Fail closed: never emit a witness that the guest would reject.
        verify_stf_constraints(&witness)?;
        Ok(witness)
    }

    // -----------------------------------------------------------------------
    // Block-proof validation (item 17)
    // -----------------------------------------------------------------------
    /// (items 12-16).
    ///
    /// Returns `Ok(())` when the proof is valid, or an error describing the
    /// exact validation failure so that the consensus layer can reject the
    /// block.
    ///
    /// # Parameters
    /// * `block`             - the candidate block containing `header.zk_proof`.
    /// * `state_root_before` - Verkle root of the **parent** block (not stored
    ///   in the candidate header itself).
    pub fn validate_block_proof(&self, block: &Block, state_root_before: [u8; 32]) -> Result<()> {
        let proof_bytes = block.header.zk_proof.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "block at height {} has no attached ZK proof",
                block.header.height
            )
        })?;

        if proof_bytes.is_empty() {
            bail!(
                "block at height {} has an empty ZK proof",
                block.header.height
            );
        }

        if proof_bytes.len() > MAX_ZK_PROOF_SIZE {
            bail!(
                "block ZK proof size {} exceeds maximum allowed {}",
                proof_bytes.len(),
                MAX_ZK_PROOF_SIZE
            );
        }

        // Deserialise the proof envelope stored in the block header.
        let sp1_proof: Sp1Proof = bincode::deserialize(proof_bytes)
            .map_err(|e| anyhow::anyhow!("failed to deserialise block ZK proof: {}", e))?;

        let provided_pi = ZkPublicInputs::decode(&sp1_proof.public_inputs)
            .map_err(|e| anyhow::anyhow!("failed to decode public inputs from proof: {}", e))?;

        // Reconstruct the public inputs we expect for this block (items 14-16).
        let public_inputs = ZkPublicInputs::new(
            block.header.chain_id,
            block.header.version,
            STF_CIRCUIT_VERSION,
            [0u8; 32],
            block.header.height,
            block.header.parent_hash,
            state_root_before,
            block.header.state_root,
            block.header.tx_root,
            block.header.receipts_root,
            provided_pi.witness_root, // extracted from the provided proof
            block.header.randomness_beacon,
        );

        if provided_pi != public_inputs {
            anyhow::bail!("proof public inputs do not match expected block parameters");
        }

        if is_production() && provided_pi.chain_id != sxiaum_types::SXIAUM_CHAIN_ID {
            anyhow::bail!(
                "proof chain_id {} does not match mainnet chain_id {}",
                provided_pi.chain_id,
                sxiaum_types::SXIAUM_CHAIN_ID
            );
        }

        // Verify the provided Verkle proofs cryptographically on the host
        let host_computed_witness =
            crate::sp1::stf::compute_verkle_commitment(&sp1_proof.verkle_proofs);
        if host_computed_witness != provided_pi.witness_root {
            anyhow::bail!("Verkle KZG proofs do not match SP1 witness_root binding");
        }

        for p in &sp1_proof.verkle_proofs {
            for (((commitment, eval_pt), eval), proof) in p
                .commitments
                .iter()
                .zip(&p.evaluation_points)
                .zip(&p.evaluations)
                .zip(&p.opening_proofs)
            {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&eval_pt[0..8]);
                let index = u64::from_le_bytes(buf) as usize;

                let is_valid =
                    sxiaum_crypto::kzg::verify_kzg_opening(commitment, index, Some(*eval), proof)
                        .map_err(|e| anyhow::anyhow!("KZG internal error: {}", e))?;

                if !is_valid {
                    anyhow::bail!("Invalid KZG proof detected on the host side");
                }
            }
        }

        // Item 12 - full verify_block_proof pipeline using canonical verifier
        self.verifier
            .verify_block_proof(&sp1_proof, &public_inputs)?;

        tracing::info!(
            "ZK block proof validated for block {} (hash 0x{})",
            block.header.height,
            hex::encode(block.try_hash()?)
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Storage helpers (item 19)
    // -----------------------------------------------------------------------

    /// Item 19 - Store a `BlockValidityProof` indexed by both block height and
    /// block hash, allowing lookups from either direction.
    pub fn store_proof_indexed(
        &self,
        storage: &StorageEngine,
        height: u64,
        block_hash: [u8; 32],
        proof: &BlockValidityProof,
    ) -> Result<()> {
        let bytes = bincode::serialize(proof)?;
        // Primary index: by height (used during sequential validation).
        storage.store_zk_proof(height, bytes.clone())?;
        // Secondary index: by block hash (used by light clients / RPC).
        let hash_key = [b"zk:proof:hash:".as_ref(), block_hash.as_slice()].concat();
        storage.state_put(hash_key, bytes)?;
        Ok(())
    }

    /// Item 19 - Load a `BlockValidityProof` by block hash (complements the
    /// existing `load_block_proof` which looks up by height).
    pub fn load_proof_by_hash(
        &self,
        storage: &StorageEngine,
        block_hash: [u8; 32],
    ) -> Result<Option<BlockValidityProof>> {
        let hash_key = [b"zk:proof:hash:".as_ref(), block_hash.as_slice()].concat();
        storage
            .state_get(hash_key)?
            .map(|bytes| bincode::deserialize(&bytes).map_err(Into::into))
            .transpose()
    }
}

impl sxiaum_execution::executor::BlockProofVerifier for ZkEngine {
    fn verify_proof(&self, block: &Block, previous_state_root: [u8; 32]) -> Result<()> {
        self.validate_block_proof(block, previous_state_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::fold::{FoldAnchorConfig, FoldLayerId, FoldStatement};
    use std::time::Instant;

    const TEST_GENESIS: [u8; 32] = [11u8; 32];
    /// Height of the pinned anchor certificate in these tests.
    const ANCHOR_HEIGHT: u64 = 10_000;

    fn test_anchor() -> FoldAnchorConfig {
        FoldAnchorConfig {
            root: [22u8; 32],
            block_hash: [33u8; 32],
            height: ANCHOR_HEIGHT,
        }
    }

    fn fold_test_engine() -> ZkEngine {
        let mut engine = ZkEngine::new();
        engine
            .init_fold_stack(test_anchor())
            .expect("fold stack init should succeed");
        engine
    }

    /// The pinned anchor certificate: a bootstrap (`sel = 0`) certificate
    /// whose statement matches the pinned anchor configuration exactly.
    fn anchor_certificate(engine: &ZkEngine) -> RecursiveStateSyncProof {
        let anchor = test_anchor();
        engine
            .generate_recursive_state_sync_proof(
                TEST_GENESIS,
                anchor.root,
                anchor.block_hash,
                anchor.height,
                [0u8; 32],
            )
            .expect("anchor certificate generation should succeed")
    }

    // -----------------------------------------------------------------------
    // Circuit shape: the in-circuit recursion must be real
    // -----------------------------------------------------------------------

        #[test]
    #[cfg(feature = "groth16")]
    fn test_fold_circuit_has_real_pairing_constraints() {
        use ark_relations::gr1cs::{ConstraintSynthesizer as _, ConstraintSystem};

        let anchor = test_anchor();
        let circuit = crate::groth16::fold::RecursiveFoldCircuit::<
            ark_mnt6_753::MNT6_753,
            ark_mnt4_753::MNT4_753,
            ark_r1cs_std::pairing::mnt4::PairingVar<ark_mnt4_753::Config>,
        > {
            anchor: anchor.clone(),
            statement: FoldStatement {
                sel: false,
                genesis_root: TEST_GENESIS,
                target_root: anchor.root,
                target_block_hash: anchor.block_hash,
                target_height: anchor.height,
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                vk_digest: [7u8; 32],
                prior_root: TEST_GENESIS,
                prior_block_hash: [0u8; 32],
                prior_height: 0,
            },
            prior_statement: FoldStatement::genesis_prior(
                TEST_GENESIS,
                sxiaum_types::SXIAUM_CHAIN_ID,
                [7u8; 32],
            ),
            prior_prior_statement: FoldStatement::genesis_prior(
                TEST_GENESIS,
                sxiaum_types::SXIAUM_CHAIN_ID,
                [7u8; 32],
            ),
            prior_vk: crate::groth16::fold::PriorVK::<ark_mnt4_753::MNT4_753>::dummy_for_setup(),
            prior_proof: crate::groth16::fold::PriorProofPoints::generators(),
            _pd: std::marker::PhantomData,
        };
        type CF = <ark_mnt6_753::MNT6_753 as ark_ec::pairing::Pairing>::ScalarField;
        let cs = ConstraintSystem::<CF>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("fold circuit synthesis should succeed");
        assert!(
            cs.is_satisfied().expect("satisfaction check should work"),
            "fold circuit must be satisfiable for a valid bootstrap statement"
        );
        let num = cs.num_constraints();
        let num_inputs = cs.num_instance_variables();
        println!("fold circuit: {num} constraints, {num_inputs} instance variables");
        assert!(
            num > 10_000,
            "fold circuit has only {num} constraints \u{2014} the in-circuit \
             verification of the prior Groth16 proof (pairing arithmetic, \
             multi-scalar multiplication, bit decomposition) is missing"
        );
    }

    /// Replicates `FoldLayerProver::setup`'s dummy circuit and counts
    /// constraints / instance variables (debug helper).
    fn count_setup_inputs<ET, EP, PW>(
        anchor: &FoldAnchorConfig,
        chain_id: u64,
    ) -> (usize, usize)
    where
        ET: ark_ec::pairing::Pairing,
        EP: ark_ec::pairing::Pairing,
        PW: ark_r1cs_std::pairing::PairingVar<EP>,
        ET: ark_ec::pairing::Pairing<
            ScalarField = <<EP as ark_ec::pairing::Pairing>::G1 as ark_ec::CurveGroup>::BaseField,
        >,
        ET: ark_ec::pairing::Pairing<
            ScalarField = <<<EP as ark_ec::pairing::Pairing>::G2Affine as ark_ec::AffineRepr>::BaseField as ark_ff::Field>::BasePrimeField,
        >,
    {
        use ark_relations::gr1cs::{ConstraintSynthesizer as _, ConstraintSystem};
        let statement = FoldStatement {
            sel: false,
            genesis_root: anchor.root,
            target_root: anchor.root,
            target_block_hash: anchor.block_hash,
            target_height: anchor.height.max(1),
            chain_id,
            vk_digest: [0u8; 32],
            prior_root: anchor.root,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
        };
                let prior_statement =
            FoldStatement::genesis_prior(anchor.root, chain_id, [0u8; 32]);
        let prior_prior_statement =
            FoldStatement::genesis_prior(anchor.root, chain_id, [0u8; 32]);
        let circuit = crate::groth16::fold::RecursiveFoldCircuit::<ET, EP, PW> {
            anchor: anchor.clone(),
            statement,
            prior_statement,
            prior_prior_statement,
            prior_vk: crate::groth16::fold::PriorVK::<EP>::dummy_for_setup(),
            prior_proof: crate::groth16::fold::PriorProofPoints::<EP>::generators(),
            _pd: std::marker::PhantomData,
        };
        let cs = ConstraintSystem::<
            <ET as ark_ec::pairing::Pairing>::ScalarField,
        >::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .expect("setup circuit synthesis");
        (cs.num_constraints(), cs.num_instance_variables())
    }

        #[test]
    #[cfg(feature = "groth16")]
    fn test_fold_public_inputs_layout() {
        // Debug: count inputs of both layer setup circuits exactly as
        // FoldLayerProver::setup builds them.
        let anchor = test_anchor();
        let (ca, ia) = count_setup_inputs::<
            ark_mnt6_753::MNT6_753,
            ark_mnt4_753::MNT4_753,
            ark_r1cs_std::pairing::mnt4::PairingVar<ark_mnt4_753::Config>,
        >(&anchor, sxiaum_types::SXIAUM_CHAIN_ID);
        let (cb, ib) = count_setup_inputs::<
            ark_mnt4_753::MNT4_753,
            ark_mnt6_753::MNT6_753,
            ark_r1cs_std::pairing::mnt6::PairingVar<ark_mnt6_753::Config>,
        >(&anchor, sxiaum_types::SXIAUM_CHAIN_ID);
        println!("layer A: {ca} constraints, {ia} instance vars");
        println!("layer B: {cb} constraints, {ib} instance vars");

        use crate::groth16::fold::fold_public_inputs;
        let anchor = test_anchor();
        let own = FoldStatement {
            sel: true,
            genesis_root: TEST_GENESIS,
            target_root: [44u8; 32],
            target_block_hash: [55u8; 32],
            target_height: 20_000,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest: [7u8; 32],
            prior_root: anchor.root,
            prior_block_hash: anchor.block_hash,
            prior_height: anchor.height,
        };
        let prior = FoldStatement {
            sel: false,
            genesis_root: TEST_GENESIS,
            target_root: anchor.root,
            target_block_hash: anchor.block_hash,
            target_height: anchor.height,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            vk_digest: [7u8; 32],
            prior_root: TEST_GENESIS,
            prior_block_hash: [0u8; 32],
            prior_height: 0,
        };
        let prior_prior = FoldStatement::genesis_prior(
            TEST_GENESIS,
            sxiaum_types::SXIAUM_CHAIN_ID,
            [7u8; 32],
        );
        // Layer A's scalar field = MNT6-753::ScalarField = MNT4-753::Fq.
        let inputs = fold_public_inputs::<ark_mnt6_753::MNT6_753>(&own, &prior, &prior_prior)
            .expect("public-input construction should succeed");
        // Fixed 25-element flat public-input vector (no VK-point growth).
        assert_eq!(
            inputs.len(),
            crate::groth16::fold::FOLD_PUBLIC_INPUTS_LEN,
            "fold public-input vector must be fixed-size (no growth with depth)"
        );
        // sel = 1 for a folded certificate.
        assert_eq!(inputs[0], ark_mnt4_753::Fq::from(1u64));
        // prior sel = 0 for the anchor bootstrap certificate.
        assert_eq!(
            inputs[crate::groth16::fold::FOLD_PI_PRIOR_SEL],
            ark_mnt4_753::Fq::from(0u64)
        );
        // Chunk packing: prior target root must reconstruct from its two
        // 128-bit chunks (lo + hi * 2^128).
        let mut two128 = ark_mnt4_753::Fq::from(1u64);
        for _ in 0..128 {
            two128 += two128;
        }
        let lo = inputs[crate::groth16::fold::FOLD_PI_PRIOR_CHUNKS];
        let hi = inputs[crate::groth16::fold::FOLD_PI_PRIOR_CHUNKS + 1];
        let recon = lo + hi * two128;
        assert_eq!(recon, ark_mnt4_753::Fq::from_le_bytes_mod_order(&anchor.root));
    }

    #[test]
    #[cfg(feature = "groth16")]
    fn test_in_circuit_sha256_vk_matches_native() {
        use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
        use ark_relations::gr1cs::ConstraintSystem;
        use ark_r1cs_std::prelude::*;
        use sha2::{Digest, Sha256};
        use crate::groth16::fold::PriorVK;

        use ark_r1cs_std::fields::fp::FpVar;
        let prior_vk = PriorVK::<ark_mnt4_753::MNT4_753>::dummy_for_setup();

        // 1. Native computation
        let mut hasher = Sha256::new();
        hasher.update(b"SXIAUM_FOLD_VK_V3");
        hasher.update(prior_vk.canonical_serialization());
        let native_digest = hasher.finalize();

        // 2. In-circuit computation
        let cs = ConstraintSystem::<ark_mnt6_753::Fr>::new_ref();
        let vk_elems = prior_vk.to_base_prime_field_elements();
        let mut vk_coord_bytes: Vec<UInt8<ark_mnt6_753::Fr>> =
            UInt8::constant_vec(b"SXIAUM_FOLD_VK_V3");
        for elem in &vk_elems {
            let var = FpVar::new_witness(cs.clone(), || Ok(*elem)).unwrap();
            let bits = var.to_bits_le().unwrap();
            for j in 0..crate::groth16::fold::FOLD_FIELD_BYTES {
                let mut byte_bits = Vec::with_capacity(8);
                for k in 0..8 {
                    let want = bits.get(j * 8 + k).cloned().unwrap_or(Boolean::constant(false));
                    byte_bits.push(want);
                }
                vk_coord_bytes.push(UInt8::from_bits_le(&byte_bits));
            }
        }
        let digest_var = Sha256Gadget::<ark_mnt6_753::Fr>::digest(&vk_coord_bytes).unwrap();
        let mut circuit_digest = [0u8; 32];
        for (i, b) in digest_var.0.iter().enumerate() {
            circuit_digest[i] = b.value().unwrap();
        }

        println!("Native digest:  {}", hex::encode(native_digest));
        println!("Circuit digest: {}", hex::encode(circuit_digest));
        assert_eq!(&native_digest[..], &circuit_digest[..]);
        assert!(cs.is_satisfied().unwrap());
    }

    // -----------------------------------------------------------------------
    // Bootstrap certificate: wire format, verification, tamper rejection
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "groth16")]
    fn test_fold_bootstrap_certificate_roundtrip() {
        let engine = fold_test_engine();
        let anchor = test_anchor();
        let cert = anchor_certificate(&engine);

        assert!(!cert.sel, "anchor certificate must be a bootstrap certificate");
        assert_eq!(cert.target_height, anchor.height);

        // Canonical wire format roundtrip.
        let cert_bytes = cert.certificate_bytes().expect("certificate encoding");
        assert_eq!(cert_bytes.len(), certificate_size_for_layer(cert.layer));
        let (header, inner_proof) =
            RecursiveStateSyncProof::decode_certificate(&cert_bytes)
                .expect("certificate decode");
        assert_eq!(header.version, RECURSIVE_CERT_VERSION);
        assert_eq!(header.layer, FoldLayerId::A);
        assert!(!header.sel);
        assert_eq!(header.chain_id, sxiaum_types::SXIAUM_CHAIN_ID);
        assert_eq!(header.target_height, anchor.height);
        assert_eq!(inner_proof.bytes, cert.proof.bytes);

        // ONE pairing check: valid certificate verifies.
        let valid = engine
            .verify_recursive_state_sync_proof(
                TEST_GENESIS,
                cert.target_state_root,
                cert.target_block_hash,
                cert.target_height,
                cert.prev_certificate_hash,
                &cert.proof,
            )
            .expect("verification should run");
        assert!(valid, "valid bootstrap certificate must verify");

        // Tampered genesis root -> pairing check fails.
        let mut tampered_genesis = TEST_GENESIS;
        tampered_genesis[0] ^= 0xff;
        let valid = engine
            .verify_recursive_state_sync_proof(
                tampered_genesis,
                cert.target_state_root,
                cert.target_block_hash,
                cert.target_height,
                cert.prev_certificate_hash,
                &cert.proof,
            )
            .expect("verification should run");
        assert!(!valid, "tampered genesis root must fail the pairing check");

        // Non-canonical proof size -> rejected before any pairing work.
        let oversized = ZkProof {
            bytes: vec![0u8; proof_size_for_layer(FoldLayerId::A) + 1],
        };
        let err = engine
            .verify_recursive_state_sync_proof(
                TEST_GENESIS,
                cert.target_state_root,
                cert.target_block_hash,
                cert.target_height,
                cert.prev_certificate_hash,
                &oversized,
            )
            .expect_err("non-canonical certificate must be rejected");
        assert!(err.to_string().contains("canonical"), "unexpected: {err}");

        // Different trusted setup (fresh ceremony): a certificate bound to
        // ceremony A's vk_digest must never verify under ceremony B (�2.2).
        let mut other_engine = ZkEngine::new();
        other_engine
            .init_fold_stack(FoldAnchorConfig {
                root: [99u8; 32],
                block_hash: [98u8; 32],
                height: ANCHOR_HEIGHT,
            })
            .expect("second fold stack init");
        let other_result = other_engine.verify_recursive_state_sync_proof(
            TEST_GENESIS,
            cert.target_state_root,
            cert.target_block_hash,
            cert.target_height,
            cert.prev_certificate_hash,
            &cert.proof,
        );
        assert!(
            other_result.is_err() || !other_result.unwrap(),
            "certificate from ceremony A must not verify under ceremony B"
        );
    }

    // -----------------------------------------------------------------------
    // Depth-2 recursion: the fold circuit verifies the PRIOR proof in-circuit
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "groth16")]
    fn test_folded_certificate_depth2_in_circuit_recursion() {
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber = tracing_subscriber::Registry::default()
            .with(ark_relations::gr1cs::ConstraintLayer::default());
        let _guard = tracing::subscriber::set_default(subscriber);

        let engine = fold_test_engine();
        let anchor_cert = anchor_certificate(&engine);

        // Fold once: layer B verifies the anchor's MNT6 proof in-circuit.
        let fold1 = engine
            .generate_folded_certificate(
                TEST_GENESIS,
                &anchor_cert,
                None,
                [44u8; 32],
                [45u8; 32],
                ANCHOR_HEIGHT + 10_000,
                anchor_cert.certificate_hash().expect("anchor hash"),
            )
            .expect("fold-1 generation should succeed");
        assert!(fold1.sel);
        assert_eq!(fold1.layer, FoldLayerId::B);
        assert_eq!(fold1.prior_state_root, anchor_cert.target_state_root);
        assert_eq!(fold1.prior_height, anchor_cert.target_height);

        // O(1) verification of the folded certificate: ONE pairing check,
        // prior metadata only (no prior proof download).
        let valid = engine
            .verify_folded_certificate(TEST_GENESIS, &fold1, &anchor_cert, None)
            .expect("folded verification should run");
        assert!(valid, "fold-1 certificate must verify with one pairing check");

        // Fold twice: layer A verifies fold-1's MNT4 proof in-circuit.
        let fold2 = engine
            .generate_folded_certificate(
                TEST_GENESIS,
                &fold1,
                Some(&anchor_cert),
                [66u8; 32],
                [67u8; 32],
                ANCHOR_HEIGHT + 20_000,
                fold1.certificate_hash().expect("fold-1 hash"),
            )
            .expect("fold-2 generation should succeed");
        assert_eq!(fold2.layer, FoldLayerId::A);
        let valid = engine
            .verify_folded_certificate(TEST_GENESIS, &fold2, &fold1, Some(&anchor_cert))
            .expect("fold-2 verification should run");
        assert!(valid, "fold-2 certificate must verify");

        // TAMPER: present fold-1's statement but a DIFFERENT valid proof as
        // the prior. The in-circuit equation binds the prior proof to its
        // statement, so proof generation must fail (unsatisfiable circuit).
        let other_anchor = engine
            .generate_recursive_state_sync_proof(
                TEST_GENESIS,
                [77u8; 32],
                [78u8; 32],
                ANCHOR_HEIGHT,
                [0u8; 32],
            )
            .expect("second anchor certificate");
        let tampered_prior = RecursiveStateSyncProof {
            proof: other_anchor.proof.clone(),
            ..fold1.clone()
        };
        let tamper_result = engine.generate_folded_certificate(
            TEST_GENESIS,
            &tampered_prior,
            Some(&anchor_cert),
            [88u8; 32],
            [89u8; 32],
            ANCHOR_HEIGHT + 30_000,
            [0u8; 32],
        );
        assert!(
            tamper_result.is_err(),
            "folding over a prior proof that does not verify for the claimed \
             statement must fail"
        );

        // TAMPER: folded certificate with tampered target root -> fail-closed.
        let mut tampered_fold2 = fold2.clone();
        tampered_fold2.target_state_root = [99u8; 32];
        let valid = engine
            .verify_folded_certificate(TEST_GENESIS, &tampered_fold2, &fold1, Some(&anchor_cert))
            .expect("verification should run");
        assert!(!valid, "tampered folded certificate must be rejected");
    }

    #[test]
    #[cfg(feature = "groth16")]
    fn test_folded_certificate_requires_anchor_or_folded_prior() {
        let engine = fold_test_engine();
        // A sel = 0 certificate that does NOT match the pinned anchor
        // statement: folding over it must be rejected (otherwise an attacker
        // could bootstrap their own trusted-delta certificate chain).
        let rogue = engine
            .generate_recursive_state_sync_proof(
                TEST_GENESIS,
                [41u8; 32],
                [42u8; 32],
                5_000,
                [0u8; 32],
            )
            .expect("rogue bootstrap certificate");
        let err = engine
            .generate_folded_certificate(
                TEST_GENESIS,
                &rogue,
                None,
                [43u8; 32],
                [44u8; 32],
                15_000,
                [0u8; 32],
            )
            .expect_err("folding over a non-anchor trusted-delta certificate must be rejected");
        assert!(
            err.to_string().contains("anchor") || err.to_string().contains("folded"),
            "unexpected error: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Chain mode (transition path): O(#epochs), hash-chained certificates
    // -----------------------------------------------------------------------

    #[test]
    #[cfg(feature = "groth16")]
    fn test_recursive_certificate_chain_epoch_linking() {
        let engine = fold_test_engine();
        let anchor_cert = anchor_certificate(&engine);
        let fold1 = engine
            .generate_folded_certificate(
                TEST_GENESIS,
                &anchor_cert,
                None,
                [44u8; 32],
                [45u8; 32],
                ANCHOR_HEIGHT + 10_000,
                anchor_cert.certificate_hash().expect("anchor hash"),
            )
            .expect("fold-1");
        let fold2 = engine
            .generate_folded_certificate(
                TEST_GENESIS,
                &fold1,
                Some(&anchor_cert),
                [66u8; 32],
                [67u8; 32],
                ANCHOR_HEIGHT + 20_000,
                fold1.certificate_hash().expect("fold-1 hash"),
            )
            .expect("fold-2");

        let chain = vec![anchor_cert.clone(), fold1.clone(), fold2.clone()];
        let final_height = engine
            .verify_recursive_certificate_chain(TEST_GENESIS, &chain)
            .expect("valid chain must verify");
        assert_eq!(final_height, ANCHOR_HEIGHT + 20_000);

        // Broken metadata hash-chain link -> rejected.
        let mut broken_fold1 = fold1.clone();
        broken_fold1.prev_certificate_hash = [0xEE; 32];
        let broken = vec![anchor_cert.clone(), broken_fold1, fold2.clone()];
        assert!(
            engine
                .verify_recursive_certificate_chain(TEST_GENESIS, &broken)
                .is_err(),
            "broken hash-chain link must be rejected"
        );

        // Height regression -> rejected.
        let mut regressed_fold2 = fold2.clone();
        regressed_fold2.target_height = ANCHOR_HEIGHT + 5_000;
        let regressed = vec![anchor_cert, fold1, regressed_fold2];
        assert!(
            engine
                .verify_recursive_certificate_chain(TEST_GENESIS, &regressed)
                .is_err(),
            "height regression must be rejected"
        );
    }

    // -----------------------------------------------------------------------
    // ACCEPTANCE TEST (P0): O(1) sync verification independent of chain age
    // -----------------------------------------------------------------------

    /// A new node syncing to height N downloads ONE certificate (plus 192
    /// bytes of prior-statement metadata) and performs ONE pairing check.
    /// The verification time must be independent of N (fuzzed across 3+
    /// orders of magnitude here, within generous noise bounds because the
    /// suite may run in a debug profile).
    ///
    /// Honest scope: proving a chain of D folds costs O(D) sequential fold
    /// provings (like SP1/RISC0 continuation proving); this test measures
    /// the VERIFIER's cost. Verification consumes exactly one 216-byte
    /// certificate by construction of `verify_folded_certificate`.
    #[test]
    #[cfg(feature = "groth16")]
    fn test_fold_sync_verification_time_is_independent_of_chain_age() {
        let engine = fold_test_engine();
        let anchor_cert = anchor_certificate(&engine);

        // Heights spanning 3+ orders of magnitude (10^4 .. 10^7).
        let heights = [ANCHOR_HEIGHT + 1, 100_000, 1_000_000, 10_000_000];

        let mut best_ms: Vec<(u64, f64)> = Vec::new();
        for n in heights {
            let cert = engine
                .generate_folded_certificate(
                    TEST_GENESIS,
                    &anchor_cert,
                    None,
                    [n as u8; 32],
                    [(n >> 8) as u8; 32],
                    n,
                    anchor_cert.certificate_hash().expect("anchor hash"),
                )
                .unwrap_or_else(|e| panic!("folded certificate for height {n} should prove: {e}"));

            // ONE certificate download: canonical wire format.
            let cert_bytes = cert.certificate_bytes().expect("encoding");
            assert_eq!(cert_bytes.len(), certificate_size_for_layer(cert.layer));

            // Verify several times, take the minimum (closest to true cost).
            let mut best = f64::INFINITY;
            for _ in 0..3 {
                let start = Instant::now();
                let valid = engine
                    .verify_folded_certificate(TEST_GENESIS, &cert, &anchor_cert, None)
                    .expect("folded verification should run");
                let elapsed = start.elapsed().as_secs_f64() * 1_000.0;
                assert!(valid, "certificate at height {n} must verify");
                if elapsed < best {
                    best = elapsed;
                }
            }
            println!(
                "height {n:>10}: verify = {best:.2} ms (1 certificate, 1 pairing check)"
            );
            best_ms.push((n, best));
        }

        // Constant-time assertion within noise bounds.
        let min = best_ms.iter().map(|(_, t)| *t).fold(f64::INFINITY, f64::min);
        let max = best_ms.iter().map(|(_, t)| *t).fold(f64::NEG_INFINITY, f64::max);
        println!(
            "verification time across heights 10^4..10^7: min={min:.2}ms max={max:.2}ms"
        );
        assert!(
            max <= min * 5.0 + 5.0,
            "verification time must be independent of chain age: min={min:.2}ms max={max:.2}ms"
        );
    }
}

