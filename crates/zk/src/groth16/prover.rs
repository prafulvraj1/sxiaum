use crate::groth16::circuit::ExecutionCircuit;
use anyhow::{anyhow, Result};
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::fs;

/// Step 1 - `Groth16Prover` struct.
///
/// Holds the circuit-specific `ProvingKey` produced during the trusted setup
/// (step 3).  All proof-generation methods are implemented on this type so
/// the key is loaded once and reused across many calls.
///
/// | Field        | Role                                                        |
/// |--------------|-------------------------------------------------------------|
/// | `proving_key`| BLS12-381 Groth16 proving key derived from the R1CS circuit.|
#[derive(Clone, Debug)]
pub struct Groth16Prover {
    pub proving_key: ProvingKey<Bls12_381>,
}

impl Groth16Prover {
    /// Step 2 - Constructor.
    ///
    /// Wraps a pre-generated `ProvingKey` (obtained from step 3 or 4) into a
    /// `Groth16Prover` instance ready for proof generation.
    pub fn new(proving_key: ProvingKey<Bls12_381>) -> Self {
        Self { proving_key }
    }

    /// Load a compressed or uncompressed serialized `ProvingKey<Bls12_381>`.
    pub fn from_file(path: &str) -> Result<Self> {
        let bytes = fs::read(path)
            .map_err(|e| anyhow!("failed to read Groth16 proving key {}: {}", path, e))?;
        let proving_key = ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..])
            .or_else(|_| ProvingKey::<Bls12_381>::deserialize_uncompressed(&bytes[..]))
            .map_err(|e| anyhow!("failed to deserialize Groth16 proving key: {:?}", e))?;
        Ok(Self::new(proving_key))
    }

    /// Step 3 - Generate trusted setup parameters.
    ///
    /// Entry point for the one-time trusted setup ceremony.  Delegates to
    /// `generate_proving_key` (step 4) which runs `circuit_specific_setup`
    /// with a fresh random-number generator, producing the proving key and
    /// (discarded) verification key.
    ///
    /// In production this should be replaced with a multi-party computation
    /// ceremony; the single-party version here is suitable for development.
    pub fn generate_trusted_setup_parameters() -> Result<ProvingKey<Bls12_381>> {
        Self::generate_proving_key()
    }

    /// Generate both proving and verifying keys for recursive state sync testing/development.
    pub fn generate_recursive_sync_setup_parameters() -> Result<(ProvingKey<Bls12_381>, ark_groth16::VerifyingKey<Bls12_381>)> {
        let circuit = Self::build_constraint_system(Fr::from(1u64), Fr::from(1u64), Fr::from(2u64));
        let mut rng = thread_rng();
        let (proving_key, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| anyhow!("Groth16 trusted setup failed: {:?}", e))?;
        Ok((proving_key, vk))
    }

    /// Step 4 - Generate proving key.
    ///
    /// Instantiates a dummy `ExecutionCircuit` (step 5) with unit field
    /// elements to define the R1CS structure, then calls
    /// `Groth16::circuit_specific_setup` to derive the proving key bound to
    /// that exact constraint system.  The returned key must be kept secret
    /// from the verifier (it contains toxic waste).
    pub fn generate_proving_key() -> Result<ProvingKey<Bls12_381>> {
        // Use canonical unit values (a=1, b=1, c=2=a+b) to define the shape
        // of the R1CS without committing to any real witness data.
        let circuit = Self::build_constraint_system(Fr::from(1u64), Fr::from(1u64), Fr::from(2u64));
        let mut rng = thread_rng();
        let (proving_key, _) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
            .map_err(|e| anyhow!("Groth16 trusted setup failed: {:?}", e))?;
        Ok(proving_key)
    }

    /// Step 5 - Build constraint system.
    ///
    /// Constructs a fully-assigned `ExecutionCircuit<Fr>` from raw field
    /// elements.  The mapping mirrors the circuit's public-input / witness
    /// layout defined in `circuit.rs`:
    ///
    /// | Argument | Circuit field               |
    /// |----------|-----------------------------|
    /// | `a`      | `state_root_before`         |
    /// | `c`      | `state_root_after`          |
    /// | `b`      | `block_hash`                |
    /// | `c - a`  | `execution_trace`           |
    /// | `b`      | `transaction_rule_commitment`|
    /// | `b`      | `gas_used`                  |
    /// | `b`      | `gas_limit`                 |
    /// | `a`      | `merkle_state_inclusion`    |
    /// | `a`      | `verkle_proof_commitment`   |
    pub fn build_constraint_system(a: Fr, b: Fr, c: Fr) -> ExecutionCircuit<Fr> {
        ExecutionCircuit::new(
            Some(a),
            Some(c),
            Some(b),
            Some(c - a),
            Some(b),
            Some(b),
            Some(b),
            Some(a),
            Some(a),
        )
    }

    /// Step 6 - Generate proof from witness.
    ///
    /// Builds the fully-assigned constraint system (step 5) from the caller's
    /// field-element witness `(a, b, c)` and calls `Groth16::prove` with the
    /// stored proving key to produce a succinct zk-SNARK proof.
    ///
    /// The proof can subsequently be serialized (step 7) and broadcast to
    /// verifiers.
    pub fn generate_proof_from_witness(&self, a: Fr, b: Fr, c: Fr) -> Result<Proof<Bls12_381>> {
        let circuit = Self::build_constraint_system(a, b, c);
        let mut rng = thread_rng();
        Groth16::<Bls12_381>::prove(&self.proving_key, circuit, &mut rng)
            .map_err(|e| anyhow!("Groth16 proof generation failed: {:?}", e))
    }

    /// Convenience wrapper - constructs a temporary `Groth16Prover` from `pk`
    /// and delegates to `generate_proof_from_witness` (step 6).
    pub fn prove(pk: &ProvingKey<Bls12_381>, a: Fr, b: Fr, c: Fr) -> Result<Proof<Bls12_381>> {
        Self::new(pk.clone()).generate_proof_from_witness(a, b, c)
    }

    /// Step 7 - Serialize proof.
    ///
    /// Encodes the Groth16 `Proof` struct into a compressed byte vector using
    /// `ark-serialize`'s `CanonicalSerialize`.  The compressed form drops one
    /// coordinate of each curve point, halving the wire size compared to
    /// uncompressed encoding.
    pub fn serialize_proof(&self, proof: &Proof<Bls12_381>) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|e| anyhow!("Groth16 proof serialization failed: {:?}", e))?;
        Ok(bytes)
    }

    /// Step 8 - Export proof bytes.
    ///
    /// Public alias for `serialize_proof` (step 7).  Returns the compressed
    /// proof bytes ready for storage, network transmission, or inclusion in a
    /// block header.
    pub fn export_proof_bytes(&self, proof: &Proof<Bls12_381>) -> Result<Vec<u8>> {
        self.serialize_proof(proof)
    }

    /// Step 9 - Batch proof generation.
    ///
    /// Iterates over a slice of `(a, b, c)` witness tuples and calls
    /// `generate_proof_from_witness` (step 6) for each one, collecting the
    /// results. Returns an error on the first failing witness; all
    /// successfully generated proofs up to that point are discarded.
    ///
    /// Used by the block proposer to prove all transactions in a block in one
    /// call before broadcasting the block proposal.
    pub fn batch_proof_generation(
        &self,
        witnesses: &[(Fr, Fr, Fr)],
    ) -> Result<Vec<Proof<Bls12_381>>> {
        witnesses
            .iter()
            .map(|(a, b, c)| self.generate_proof_from_witness(*a, *b, *c))
            .collect()
    }

    /// Compute the canonical VK digest bound into every recursive certificate.
    ///
    /// This is SHA-256 over the *canonical compressed* serialization of the
    /// circuit's verifying key â€” identical on the prover side (from
    /// `proving_key.vk`) and the verifier side (from the pinned VK file),
    /// which is what makes the binding enforceable.
    pub fn verifying_key_digest(&self) -> Result<[u8; 32]> {
        let mut vk_bytes = Vec::new();
        self.proving_key
            .vk
            .serialize_compressed(&mut vk_bytes)
            .map_err(|e| anyhow!("failed to serialize verifying key: {:?}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(&vk_bytes);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        Ok(digest)
    }

}
