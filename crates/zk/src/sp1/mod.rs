pub mod prover;
pub mod stf;
pub mod verifier;

pub use prover::{
    canonical_sp1_program_pk, canonical_sp1_program_vk, canonical_sp1_program_vk_hash,
    canonical_sp1_program_vk_hash_hex, normalize_vkey_hash, real_proof_mode,
    Sp1ExecutionEnvironment, Sp1ExecutionTrace, Sp1Proof, Sp1ProofSystem, Sp1Prover,
    Sp1RealProofMode, ZkBlockWitness, ZkPublicInputs, MAX_PUBLIC_INPUTS_SIZE,
    MAX_WITNESS_INPUT_SIZE, MAX_ZK_PROOF_SIZE, SP1_ELF,
};
#[cfg(feature = "sp1-sdk")]
pub use prover::{canonical_sp1_vkey_hash_hex, real_sdk_client, with_canonical_sp1_verifying_key};
pub use stf::{
    attach_private_to_witness, verify_stf_constraints, verify_stf_private, StfPrivateInputs,
    StfStateAccess, StfTxWitness, StfVerkleProof, DEFAULT_MAX_BLOCK_GAS,
    MAX_STF_COMMIT_REVEAL_DIGESTS, MAX_STF_STATE_READS, MAX_STF_STATE_WRITES, MAX_STF_TRANSACTIONS,
    MAX_STF_VERKLE_PROOFS, STF_CIRCUIT_VERSION,
};
pub use verifier::{is_placeholder_vk_hash, Sp1VerificationResult, Sp1Verifier};
