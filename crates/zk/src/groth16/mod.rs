//! Groth16 proof verification and proving helpers.
//!
//! The verifier loads an arkworks `VerifyingKey<Bls12_381>` from disk, prepares
//! it once, and verifies compressed Groth16 proofs against compressed field
//! element public inputs. Verification keys should be generated during a trusted
//! setup ceremony for the exact R1CS circuit being verified; test-only setup is
//! acceptable for local development but must not be reused in production.
//!
//! NOTE (recursive folding): the legacy `RecursiveSyncCircuit` that lived in
//! `circuit.rs` was a 7-constraint linear placeholder and has been removed.
//! Recursive state-sync certificates are now produced and verified by the
//! real in-circuit recursion in [`crate::groth16::fold`] (MNT4/6-753
//! two-cycle Groth16 recursion). The BLS12-381 Groth16 stack below remains
//! for the block-execution proof path (execution circuit).

pub mod circuit;
pub mod fold;
pub mod prover;

use anyhow::{anyhow, bail, Context, Result};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

pub use prover::Groth16Prover;

/// BLS12-381 Groth16 verifier backed by a prepared arkworks verification key.
#[derive(Debug, Clone)]
pub struct Groth16Verifier {
    verifying_key: PreparedVerifyingKey<Bls12_381>,
    /// Canonical compressed serialization of the verifying key. Used to
    /// compute the VK digest bound into recursive sync certificates (§2.2).
    canonical_vk_bytes: Vec<u8>,
    public_input_size: usize,
}

impl Groth16Verifier {
    /// Load a compressed or uncompressed serialized `VerifyingKey<Bls12_381>`
    /// from `path` and prepare it for repeated proof verification.
    pub fn from_file(path: &str) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read Groth16 verifying key from {}", path))?;
        Self::from_verifying_key_bytes(&bytes)
    }

    /// Construct a verifier from serialized verification-key bytes.
    pub fn from_verifying_key_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            bail!("Groth16 verifying key bytes cannot be empty");
        }
        if bytes.len() > crate::sp1::prover::MAX_WITNESS_INPUT_SIZE {
            bail!(
                "Groth16 verifying key bytes size {} exceeds maximum allowed {}",
                bytes.len(),
                crate::sp1::prover::MAX_WITNESS_INPUT_SIZE
            );
        }

        let vk = deserialize_verifying_key(bytes)?;
        let public_input_size = vk.gamma_abc_g1.len().saturating_sub(1);
        // Canonical compressed form: the VK digest must be identical whether
        // the key was loaded from a compressed or uncompressed file.
        let mut canonical_vk_bytes = Vec::new();
        vk.serialize_compressed(&mut canonical_vk_bytes)
            .map_err(|error| anyhow!("failed to canonicalize verifying key: {:?}", error))?;
        let verifying_key = Groth16::<Bls12_381>::process_vk(&vk)
            .map_err(|error| anyhow!("failed to prepare Groth16 verifying key: {:?}", error))?;

        Ok(Self {
            verifying_key,
            canonical_vk_bytes,
            public_input_size,
        })
    }

    /// SHA-256 digest of the canonical compressed verifying key.
    ///
    /// Recursive state-sync certificates bind this digest as a public input,
    /// pinning every proof to this exact trusted-setup ceremony (§2.2).
    pub fn verifying_key_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_vk_bytes);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }

    /// Verify a serialized proof against serialized public inputs.
    ///
    /// `proof_bytes` may be compressed or uncompressed. `public_inputs` must be
    /// a concatenation of compressed canonical `Fr` encodings in verification
    /// key order.
    pub fn verify(&self, proof_bytes: &[u8], public_inputs: &[u8]) -> Result<bool> {
        let proof = deserialize_proof(proof_bytes)?;
        let inputs = deserialize_public_inputs(public_inputs)?;

        if inputs.len() != self.public_input_size {
            bail!(
                "Groth16 public input count mismatch: expected {}, got {}",
                self.public_input_size,
                inputs.len()
            );
        }

        Groth16::<Bls12_381>::verify_with_processed_vk(&self.verifying_key, &inputs, &proof)
            .map_err(|error| anyhow!("Groth16 verification failed: {:?}", error))
    }

    pub fn public_input_size(&self) -> usize {
        self.public_input_size
    }
}

pub fn serialize_verifying_key(verifying_key: &VerifyingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    verifying_key
        .serialize_compressed(&mut bytes)
        .map_err(|error| anyhow!("failed to serialize Groth16 verifying key: {:?}", error))?;
    Ok(bytes)
}

pub fn serialize_verifying_key_to_file(
    verifying_key: &VerifyingKey<Bls12_381>,
    path: impl AsRef<Path>,
) -> Result<()> {
    let bytes = serialize_verifying_key(verifying_key)?;
    fs::write(path.as_ref(), bytes).with_context(|| {
        format!(
            "failed to write Groth16 verifying key to {}",
            path.as_ref().display()
        )
    })
}

pub fn serialize_proof(proof: &Proof<Bls12_381>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    proof
        .serialize_compressed(&mut bytes)
        .map_err(|error| anyhow!("failed to serialize Groth16 proof: {:?}", error))?;
    Ok(bytes)
}

pub fn serialize_public_inputs(inputs: &[Fr]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for input in inputs {
        input
            .serialize_compressed(&mut bytes)
            .map_err(|error| anyhow!("failed to serialize Groth16 public input: {:?}", error))?;
    }
    Ok(bytes)
}

pub fn deserialize_public_inputs(bytes: &[u8]) -> Result<Vec<Fr>> {
    if bytes.len() > crate::sp1::prover::MAX_PUBLIC_INPUTS_SIZE {
        bail!(
            "Groth16 public inputs length {} exceeds maximum allowed {}",
            bytes.len(),
            crate::sp1::prover::MAX_PUBLIC_INPUTS_SIZE
        );
    }

    let element_size = Fr::from(0u64).serialized_size(Compress::Yes);
    if !bytes.len().is_multiple_of(element_size) {
        bail!(
            "Groth16 public inputs length {} is not a multiple of field element size {}",
            bytes.len(),
            element_size
        );
    }

    bytes
        .chunks(element_size)
        .map(|chunk| {
            Fr::deserialize_compressed(chunk)
                .map_err(|error| anyhow!("invalid Groth16 public input encoding: {:?}", error))
        })
        .collect()
}

fn deserialize_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bls12_381>> {
    VerifyingKey::<Bls12_381>::deserialize_compressed(bytes)
        .or_else(|_| VerifyingKey::<Bls12_381>::deserialize_uncompressed(bytes))
        .map_err(|error| anyhow!("invalid Groth16 verifying key encoding: {:?}", error))
}

fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bls12_381>> {
    if bytes.is_empty() {
        bail!("Groth16 proof bytes cannot be empty");
    }
    if bytes.len() > crate::sp1::prover::MAX_ZK_PROOF_SIZE {
        bail!(
            "Groth16 proof bytes length {} exceeds maximum allowed {}",
            bytes.len(),
            crate::sp1::prover::MAX_ZK_PROOF_SIZE
        );
    }

    Proof::<Bls12_381>::deserialize_compressed(bytes)
        .or_else(|_| Proof::<Bls12_381>::deserialize_uncompressed(bytes))
        .map_err(|error| anyhow!("invalid Groth16 proof encoding: {:?}", error))
}

/// Serialize a `ProvingKey<Bls12_381>` to `path` in compressed form.
pub fn serialize_proving_key_to_file(
    proving_key: &ProvingKey<Bls12_381>,
    path: impl AsRef<Path>,
) -> Result<()> {
    let mut bytes = Vec::new();
    proving_key
        .serialize_compressed(&mut bytes)
        .map_err(|error| anyhow!("failed to serialize Groth16 proving key: {:?}", error))?;
    fs::write(path.as_ref(), bytes).with_context(|| {
        format!(
            "failed to write Groth16 proving key to {}",
            path.as_ref().display()
        )
    })
}

/// Verify that a proving key file and verifying key file correspond to the
/// same circuit by comparing the verifying key embedded in the PK with the
/// provided VK bytes.
pub fn verify_proving_key_matches_vk(pk_path: &str, vk_path: &str) -> Result<bool> {
    let pk_bytes =
        fs::read(pk_path).with_context(|| format!("failed to read proving key {}", pk_path))?;
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
        .or_else(|_| ProvingKey::<Bls12_381>::deserialize_uncompressed(&pk_bytes[..]))
        .map_err(|e| anyhow!("failed to deserialize proving key: {:?}", e))?;

    let vk_bytes =
        fs::read(vk_path).with_context(|| format!("failed to read verifying key {}", vk_path))?;
    let vk = deserialize_verifying_key(&vk_bytes)?;

    // Compare canonical compressed encodings of both verifying keys
    let mut a = Vec::new();
    let mut b = Vec::new();
    pk.vk
        .serialize_compressed(&mut a)
        .map_err(|e| anyhow!("failed to serialize pk.vk: {:?}", e))?;
    vk.serialize_compressed(&mut b)
        .map_err(|e| anyhow!("failed to serialize vk: {:?}", e))?;
    Ok(a == b)
}

static GLOBAL_GROTH16_VERIFIER: OnceLock<Groth16Verifier> = OnceLock::new();

/// Initialize a global Groth16 verifier from environment variables.
///
/// - If `SXIAUM_GROTH16_MODE=production` then `SXIAUM_GROTH16_VK_PATH` MUST be set
///   and the call will fail if the key cannot be loaded (fail-closed).
/// - If `SXIAUM_GROTH16_VK_PATH` is set in non-production mode, it will be
///   loaded and stored for global use.
///
/// Returns `Ok(Some(&Groth16Verifier))` when a verifier was loaded, `Ok(None)`
/// when no verifier was configured for development, or `Err(_)` on fatal errors.
pub fn init_global_verifier_from_env() -> Result<Option<&'static Groth16Verifier>> {
    let mode = env::var("SXIAUM_GROTH16_MODE").unwrap_or_default();
    match env::var("SXIAUM_GROTH16_VK_PATH") {
        Ok(path) => {
            let verifier = Groth16Verifier::from_file(&path)
                .map_err(|e| anyhow!("failed to load groth16 vk from {}: {:?}", path, e))?;
            let _ = GLOBAL_GROTH16_VERIFIER.set(verifier);
            Ok(GLOBAL_GROTH16_VERIFIER.get())
        }
        Err(_) => {
            if mode == "production" {
                bail!("SXIAUM_GROTH16_VK_PATH must be set when SXIAUM_GROTH16_MODE=production");
            }
            Ok(None)
        }
    }
}

/// Return the global verifier if initialized.
pub fn global_verifier() -> Option<&'static Groth16Verifier> {
    GLOBAL_GROTH16_VERIFIER.get()
}
