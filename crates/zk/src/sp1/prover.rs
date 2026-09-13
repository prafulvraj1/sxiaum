use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Public-input envelope (items 3, 14, 15, 16)
// ---------------------------------------------------------------------------

pub const SP1_ELF: &[u8] = include_bytes!("../../guest/elf/riscv32im-succinct-zkvm-elf");

/// Maximum proof size in bytes (256 KiB, canonical single source of truth: `sxiaum_block::MAX_ZK_PROOF_SIZE`).
pub const MAX_ZK_PROOF_SIZE: usize = sxiaum_block::MAX_ZK_PROOF_SIZE;

/// Maximum serialized public inputs size in bytes (1 KiB; ZkPublicInputs is 280 bytes).
pub const MAX_PUBLIC_INPUTS_SIZE: usize = 1024;

/// Maximum witness size in bytes (16 MiB).
pub const MAX_WITNESS_INPUT_SIZE: usize = 16 * 1024 * 1024;

/// Canonical proving key for the embedded SP1 guest program.
pub fn canonical_sp1_program_pk() -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"sp1:pk:v1");
    hasher.update(SP1_ELF);
    hasher.finalize().to_vec()
}

/// Canonical verification key for the embedded SP1 guest program.
pub fn canonical_sp1_program_vk() -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"sp1:vk:v1");
    hasher.update(SP1_ELF);
    hasher.finalize().to_vec()
}

/// 32-byte hash digest of the canonical SP1 guest program verification key.
pub fn canonical_sp1_program_vk_hash() -> [u8; 32] {
    let vk = canonical_sp1_program_vk();
    let mut hasher = Sha256::new();
    hasher.update(&vk);
    hasher.finalize().into()
}

/// 64-character lowercase hex string of the canonical SP1 VK hash.
pub fn canonical_sp1_program_vk_hash_hex() -> String {
    hex::encode(canonical_sp1_program_vk_hash())
}

/// Canonical verification key derivation for an arbitrary guest program:
/// `H("sp1:vk:v1" || program)`. For the embedded ELF this equals
/// [`canonical_sp1_program_vk`], so provers built from the canonical program
/// interoperate with verifiers built from [`canonical_sp1_program_vk`].
pub fn derive_verification_key(program: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"sp1:vk:v1");
    hasher.update(program);
    hasher.finalize().to_vec()
}

/// SECURITY (C-16): single source of truth for the simulated SHA-256 proof
/// commitment, used by BOTH the simulated prover and the verifier.
///
/// Previously the prover computed `H(pk_raw || trace_raw || public_inputs)`
/// while the verifier expected
/// `H(H("sp1:pk"||vk) || H("sp1:trace"||vk||public_inputs) || public_inputs)`.
/// The two formulas could never agree, so any "verified" simulated proof was
/// meaningless (and honest proofs were unverifiable). Both sides now call this
/// one function; keep them in lockstep by construction.
pub fn simulated_proof_commitment(verification_key: &[u8], public_inputs: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();

    hasher.update(b"sp1:pk");
    hasher.update(verification_key);
    let proving_key_commitment = hasher.finalize_reset();

    hasher.update(b"sp1:trace");
    hasher.update(verification_key);
    hasher.update(public_inputs);
    let execution_trace_commitment = hasher.finalize_reset();

    hasher.update(proving_key_commitment);
    hasher.update(execution_trace_commitment);
    hasher.update(public_inputs);
    hasher.finalize().to_vec()
}

/// Normalize a hex SP1 verifying-key hash for comparison (strip `0x`, lowercase).
pub fn normalize_vkey_hash(hash: &str) -> String {
    hash.trim().trim_start_matches("0x").to_ascii_lowercase()
}

/// Validate that `bytes` look like an SP1-compatible RISC-V **32-bit** ELF
/// (`riscv32im-succinct-zkvm`).
///
/// The SP1 executor internally unwraps on malformed programs, so the host
/// must reject invalid artifacts *before* handing them to the SDK. Checks:
/// ELF magic, 32-bit class (`ELFCLASS32`), little-endian, and
/// `EM_RISCV (243)` machine type.
pub fn validate_sp1_elf(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 20 {
        bail!("SP1 program too small to be an ELF ({})", bytes.len());
    }
    if &bytes[0..4] != b"\x7fELF" {
        bail!("SP1 program is missing the ELF magic bytes");
    }
    // e_ident[EI_CLASS] == ELFCLASS32 (SP1 zkVM is riscv32im only).
    if bytes[4] != 1 {
        bail!(
            "SP1 program must be a 32-bit ELF (riscv32im); found class byte {} \
             (2 = ELF64). Rebuild the guest with `cargo prove build`.",
            bytes[4]
        );
    }
    // e_machine == EM_RISCV (243).
    let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if machine != 243 {
        bail!("SP1 program has unsupported machine type {machine} (expected 243 = RISC-V)");
    }
    Ok(())
}

/// Proof mode used by the real sp1-sdk prover.
///
/// Selected via `SXIAUM_SP1_PROOF_MODE` (`compressed` | `core` | `plonk` | `groth16`).
/// Defaults to `compressed`: constant-size, verifiable everywhere, and does not
/// require the external Groth16/PLONK wrapping stack (docker + gnark) that
/// `groth16`/`plonk` modes need on the proving host.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Sp1RealProofMode {
    #[default]
    Compressed,
    Core,
    Plonk,
    Groth16,
}

impl Sp1RealProofMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Sp1RealProofMode::Compressed => "compressed",
            Sp1RealProofMode::Core => "core",
            Sp1RealProofMode::Plonk => "plonk",
            Sp1RealProofMode::Groth16 => "groth16",
        }
    }
}

/// Read the configured real proof mode from the environment.
pub fn real_proof_mode() -> Sp1RealProofMode {
    match std::env::var("SXIAUM_SP1_PROOF_MODE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "core" => Sp1RealProofMode::Core,
        "plonk" => Sp1RealProofMode::Plonk,
        "groth16" => Sp1RealProofMode::Groth16,
        "" | "compressed" => Sp1RealProofMode::Compressed,
        other => {
            tracing::warn!("unknown SXIAUM_SP1_PROOF_MODE={other:?}; falling back to compressed");
            Sp1RealProofMode::Compressed
        }
    }
}

/// Real sp1-sdk backend: one process-wide [`ProverClient`] plus a proving /
/// verifying key cache keyed by the guest program digest, so repeated proofs
/// skip redundant `setup` work while still supporting non-canonical programs
/// in development.
#[cfg(feature = "sp1-sdk")]
mod real_sdk {
    use super::{normalize_vkey_hash, SP1_ELF};
    use anyhow::{bail, Context, Result};
    use sha2::{Digest, Sha256};
    use sp1_sdk::{ProverClient, SP1ProvingKey, SP1VerifyingKey};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    type KeyCache = HashMap<[u8; 32], (SP1ProvingKey, SP1VerifyingKey)>;

    static CLIENT: OnceLock<ProverClient> = OnceLock::new();
    static KEY_CACHE: OnceLock<Mutex<KeyCache>> = OnceLock::new();

    pub fn client() -> &'static ProverClient {
        CLIENT.get_or_init(|| {
            tracing::info!("initializing SP1 ProverClient (backend from SP1_PROVER env)");
            ProverClient::new()
        })
    }

    pub fn key_cache() -> &'static Mutex<KeyCache> {
        KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn program_digest(program: &[u8]) -> [u8; 32] {
        Sha256::digest(program).into()
    }

    /// Host-side guard: reject invalid guest artifacts before the SDK can
    /// panic on them internally (fail closed, clear operator error).
    fn ensure_canonical_elf() -> Result<()> {
        super::validate_sp1_elf(SP1_ELF)
    }

    /// Run `f` with the verifying key derived from the canonical embedded ELF.
    pub fn with_canonical_verifying_key<R>(f: impl FnOnce(&SP1VerifyingKey) -> R) -> Result<R> {
        use sp1_sdk::HashableKey;

        super::validate_sp1_elf(SP1_ELF)?;

        // An operator-provided serialized VK must byte-identically match the
        // canonical guest program before it may be trusted for verification.
        if let Ok(path) = std::env::var("SXIAUM_SP1_VK_FILE") {
            let bytes = std::fs::read(&path)
                .with_context(|| format!("failed to read SXIAUM_SP1_VK_FILE {}", path))?;
            let vk: SP1VerifyingKey = bincode::deserialize(&bytes)
                .context("failed to deserialize SP1VerifyingKey from SXIAUM_SP1_VK_FILE")?;
            if normalize_vkey_hash(&vk.bytes32()) != canonical_vkey_hash_hex()? {
                bail!(
                    "SXIAUM_SP1_VK_FILE verification key does not match the canonical \
                     SP1 guest program (bytes32 hash mismatch)"
                );
            }
            return Ok(f(&vk));
        }

        let mut cache = key_cache().lock().expect("sp1 key cache poisoned");
        let digest = program_digest(SP1_ELF);
        if !cache.contains_key(&digest) {
            cache.insert(digest, client().setup(SP1_ELF));
        }
        Ok(f(&cache.get(&digest).expect("canonical keys").1))
    }

    /// Hex `HashableKey::bytes32()` of the canonical guest program's VK.
    pub fn canonical_vkey_hash_hex() -> Result<String> {
        use sp1_sdk::HashableKey;
        super::validate_sp1_elf(SP1_ELF)?;
        let mut cache = key_cache().lock().expect("sp1 key cache poisoned");
        let digest = program_digest(SP1_ELF);
        if !cache.contains_key(&digest) {
            cache.insert(digest, client().setup(SP1_ELF));
        }
        Ok(cache.get(&digest).expect("canonical keys").1.bytes32())
    }
}

#[cfg(feature = "sp1-sdk")]
use real_sdk::canonical_vkey_hash_hex;

/// Hex `HashableKey::bytes32()` of the SP1 verifying key derived from the
/// embedded canonical guest program. Available when built with `sp1-sdk`.
#[cfg(feature = "sp1-sdk")]
pub fn canonical_sp1_vkey_hash_hex() -> Result<String> {
    canonical_vkey_hash_hex()
}

/// Shared process-wide SP1 [`ProverClient`] (feature `sp1-sdk`).
#[cfg(feature = "sp1-sdk")]
pub use real_sdk::client as real_sdk_client;

/// Run `f` with the canonical guest program's verifying key, resolving an
/// operator-supplied `SXIAUM_SP1_VK_FILE` (validated against the embedded ELF)
/// or deriving the key from the ELF directly (feature `sp1-sdk`).
#[cfg(feature = "sp1-sdk")]
pub use real_sdk::with_canonical_verifying_key as with_canonical_sp1_verifying_key;

/// The values committed to by a block-validity ZK proof.
///
/// Both the prover and the verifier derive the same `ZkPublicInputs` from the
/// block so they can independently confirm the proof covers the expected state
/// transition.
///
/// * `state_root_before` - Verkle / Merkle root **before** the block was applied (item 14).
/// * `state_root_after`  - Verkle / Merkle root **after** the block was applied (item 15).
/// * `block_hash`        - SHA-256 hash of the block header (item 16).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkPublicInputs {
    pub chain_id: u64,
    pub protocol_version: u32,
    pub circuit_version: u32,
    pub genesis_hash: [u8; 32],
    pub block_height: u64,
    pub parent_hash: [u8; 32],
    pub state_root_before: [u8; 32],
    pub state_root_after: [u8; 32],
    pub tx_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub witness_root: [u8; 32],
    pub beacon_randomness: [u8; 32],
}

impl ZkPublicInputs {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        protocol_version: u32,
        circuit_version: u32,
        genesis_hash: [u8; 32],
        block_height: u64,
        parent_hash: [u8; 32],
        state_root_before: [u8; 32],
        state_root_after: [u8; 32],
        tx_root: [u8; 32],
        receipts_root: [u8; 32],
        witness_root: [u8; 32],
        beacon_randomness: [u8; 32],
    ) -> Self {
        Self {
            chain_id,
            protocol_version,
            circuit_version,
            genesis_hash,
            block_height,
            parent_hash,
            state_root_before,
            state_root_after,
            tx_root,
            receipts_root,
            witness_root,
            beacon_randomness,
        }
    }

    /// Deterministic byte encoding used as the public-input wire format passed
    /// into the SP1 verifier and committed to in the proof.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        bytes.extend_from_slice(&self.circuit_version.to_le_bytes());
        bytes.extend_from_slice(&self.genesis_hash);
        bytes.extend_from_slice(&self.block_height.to_le_bytes());
        bytes.extend_from_slice(&self.parent_hash);
        bytes.extend_from_slice(&self.state_root_before);
        bytes.extend_from_slice(&self.state_root_after);
        bytes.extend_from_slice(&self.tx_root);
        bytes.extend_from_slice(&self.receipts_root);
        bytes.extend_from_slice(&self.witness_root);
        bytes.extend_from_slice(&self.beacon_randomness);
        bytes
    }

    /// Decode the 280-byte wire format back into `ZkPublicInputs`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 280 {
            anyhow::bail!(
                "invalid encoded ZkPublicInputs length: expected 280, got {}",
                bytes.len()
            );
        }

        let chain_id = u64::from_le_bytes(bytes[0..8].try_into()?);
        let protocol_version = u32::from_le_bytes(bytes[8..12].try_into()?);
        let circuit_version = u32::from_le_bytes(bytes[12..16].try_into()?);
        let genesis_hash = bytes[16..48].try_into()?;
        let block_height = u64::from_le_bytes(bytes[48..56].try_into()?);
        let parent_hash = bytes[56..88].try_into()?;
        let state_root_before = bytes[88..120].try_into()?;
        let state_root_after = bytes[120..152].try_into()?;
        let tx_root = bytes[152..184].try_into()?;
        let receipts_root = bytes[184..216].try_into()?;
        let witness_root = bytes[216..248].try_into()?;
        let beacon_randomness = bytes[248..280].try_into()?;

        Ok(Self {
            chain_id,
            protocol_version,
            circuit_version,
            genesis_hash,
            block_height,
            parent_hash,
            state_root_before,
            state_root_after,
            tx_root,
            receipts_root,
            witness_root,
            beacon_randomness,
        })
    }
}

// ---------------------------------------------------------------------------
// zkVM witness (items 3, 4, 5)
// ---------------------------------------------------------------------------

/// A complete zkVM witness for a single block, combining the captured
/// execution trace with the public inputs that the proof commits to.
///
/// The prover serialises this into a byte slice and passes it to
/// `SP1Stdin::write_vec` (or the SHA-256 simulation fallback) as the
/// sole witness input to the guest program (item 5).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkBlockWitness {
    /// Raw execution trace captured from the execution engine (item 4).
    pub trace: Sp1ExecutionTrace,
    /// Public inputs that will be committed to in the resulting proof (item 3).
    pub public_inputs: ZkPublicInputs,
}

impl ZkBlockWitness {
    pub fn new(trace: Sp1ExecutionTrace, public_inputs: ZkPublicInputs) -> Self {
        Self {
            trace,
            public_inputs,
        }
    }
}

// ---------------------------------------------------------------------------
// Existing supporting structs (unchanged)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1ExecutionEnvironment {
    pub witness_input: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1ExecutionTrace {
    pub program: Vec<u8>,
    pub witness_input: Vec<u8>,
    pub execution_trace: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum Sp1ProofSystem {
    #[default]
    SimulatedSha256,
    Sp1Sdk,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sp1Proof {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub compressed: bool,
    #[serde(default)]
    pub proof_system: Sp1ProofSystem,
    /// Host-side verified Verkle proofs that bind to the witness_root in the public_inputs.
    #[serde(default)]
    pub verkle_proofs: Vec<crate::sp1::stf::StfVerkleProof>,
    /// Hex `bytes32` hash (`HashableKey`) of the SP1 verifying key the proof
    /// was produced with. Set only by the real sp1-sdk prover; verifiers
    /// cross-check it against the canonical guest program VK.
    #[serde(default)]
    pub vk_hash: Option<String>,
}

/// Step 1 - `Sp1Prover` struct { program, proving_key }.
///
/// `program`     - raw ELF binary of the guest program executed inside the
///                SP1 ZKVM.  Loaded once and reused across proofs.
/// `proving_key` - deterministic key derived from the program binary via
///                SHA-256; uniquely identifies the circuit so that proofs can
///                only verify against the same compiled program.
#[derive(Clone, Debug)]
pub struct Sp1Prover {
    pub program: Vec<u8>,
    pub proving_key: Vec<u8>,
}

impl Default for Sp1Prover {
    fn default() -> Self {
        Self::new(SP1_ELF.to_vec())
    }
}

impl Sp1Prover {
    /// Step 2 - `Sp1Prover::new(program)`.
    ///
    /// Accepts the raw guest program bytes and derives the proving key
    /// (`SHA-256("sp1:pk" || program)`) so the key is always consistent with
    /// the circuit.  Cheap to construct; no heavy setup is required.
    pub fn new(program: Vec<u8>) -> Self {
        let proving_key = Self::derive_proving_key(&program);
        Self {
            program,
            proving_key,
        }
    }

    /// Item 2 - Load and validate an ELF binary for the SP1 zkVM.
    ///
    /// In SP1 the guest program is compiled with `cargo prove build` and the
    /// resulting ELF is embedded via `include_bytes!` at compile time.  This
    /// method validates the ELF magic bytes (`\x7fELF`) so obviously invalid
    /// inputs are rejected before the expensive prover setup.
    pub fn load_elf_program(elf_bytes: &[u8]) -> Result<Vec<u8>> {
        validate_sp1_elf(elf_bytes)?;
        Ok(elf_bytes.to_vec())
    }

    /// Step 3 - Load zkVM program binary.
    ///
    /// Validates that the supplied slice is non-empty (a common mistake when
    /// a program path resolves to an absent file) and returns an owned copy
    /// ready for `Sp1Prover::new`.  Returns an error for empty input.
    pub fn load_program_binary(program: &[u8]) -> Result<Vec<u8>> {
        if program.is_empty() {
            bail!("zkVM program binary cannot be empty");
        }
        Ok(program.to_vec())
    }

    /// Step 4 - Initialize execution environment.
    ///
    /// Wraps the raw witness bytes in an `Sp1ExecutionEnvironment` and
    /// validates that a program has been loaded.  The environment is a
    /// lightweight container - no ZKVM state is allocated until
    /// `execute_program_with_witness` is called.
    pub fn initialize_execution_environment(
        &self,
        witness_input: &[u8],
    ) -> Result<Sp1ExecutionEnvironment> {
        if self.program.is_empty() {
            bail!("prover program must be initialized before execution");
        }
        if witness_input.len() > MAX_WITNESS_INPUT_SIZE {
            bail!(
                "witness input size {} exceeds maximum allowed {}",
                witness_input.len(),
                MAX_WITNESS_INPUT_SIZE
            );
        }

        Ok(Sp1ExecutionEnvironment {
            witness_input: witness_input.to_vec(),
        })
    }

    /// Step 5 - Execute program with witness input.
    ///
    /// Initialises the execution environment for the given witness, runs the
    /// guest program to produce an `Sp1ExecutionTrace`, and derives the
    /// public inputs that will be committed to in the proof.  This is the
    /// main entry point for single-transaction proving.
    pub fn execute_program_with_witness(&self, witness_input: &[u8]) -> Result<Sp1ExecutionTrace> {
        let environment = self.initialize_execution_environment(witness_input)?;
        let execution_trace = self.capture_execution_trace(&environment.witness_input)?;
        let public_inputs = Self::derive_public_inputs(&self.program, &environment.witness_input);

        Ok(Sp1ExecutionTrace {
            program: self.program.clone(),
            witness_input: environment.witness_input,
            execution_trace,
            public_inputs,
        })
    }

    /// Step 6 - Capture execution trace.
    ///
    /// Produces a deterministic byte representation of the guest program's
    /// register and memory transcript for the given witness via
    /// `SHA-256("sp1:trace" || program || witness)`.  The trace is the
    /// primary input to the STARK prover in step 7.
    pub fn capture_execution_trace(&self, witness_input: &[u8]) -> Result<Vec<u8>> {
        if self.program.is_empty() {
            bail!("cannot capture execution trace without a loaded program");
        }

        Ok(Self::derive_trace_bytes(&self.program, witness_input))
    }

    /// Item 5 - Serialize a `ZkBlockWitness` into a compact zkVM witness blob.
    ///
    /// `bincode` provides a deterministic, compact encoding that SP1's
    /// `SP1Stdin::write_vec` can ingest directly when the `sp1-sdk` feature is
    /// enabled.  The blob carries every field the guest program needs to
    /// reconstruct and re-verify the execution inside the ZKVM sandbox.
    pub fn build_zkvm_witness(witness: &ZkBlockWitness) -> Result<Vec<u8>> {
        bincode::serialize(witness).map_err(Into::into)
    }

    /// Items 6 + 7 - Initialize the SP1 prover and execute the guest against a
    /// block witness.
    ///
    /// When compiled with `--features sp1-sdk` the real `ProverClient` (in
    /// mock mode, requiring no network or GPU) is used: it parses the ELF,
    /// runs the RISC-V guest on the witness, and records the full execution
    /// transcript.  Without the feature the existing SHA-256 commitment
    /// simulation is used so the rest of the pipeline stays functional.
    ///
    /// Returns an `Sp1ExecutionTrace` that `generate_stark_proof` consumes to
    /// produce the STARK proof (item 8).
    pub fn execute(&self, witness: &ZkBlockWitness) -> Result<Sp1ExecutionTrace> {
        // Enforce Phase-1 STF constraints before any proof work (host precheck).
        crate::sp1::stf::verify_stf_constraints(witness)?;

        let witness_bytes = Self::build_zkvm_witness(witness)?;

        #[cfg(feature = "sp1-sdk")]
        {
            use sp1_sdk::{ProverClient, SP1Stdin};
            // Fail closed on invalid guest artifacts before SDK internals.
            validate_sp1_elf(&self.program)?;
            // Item 6 - Initialize SP1Prover with the compiled ELF.
            let client = ProverClient::new();
            // Item 7 - Run the guest program with the witness as stdin.
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(witness_bytes.clone());
            let (_, _) = client.execute(&self.program, stdin).run()?;
        }

        // Derive deterministic trace commitment (both the sp1-sdk and
        // simulation paths end here so the STARK generation step is uniform).
        let execution_trace = Self::derive_trace_bytes(&self.program, &witness_bytes);
        let public_inputs = witness.public_inputs.encode();

        Ok(Sp1ExecutionTrace {
            program: self.program.clone(),
            witness_input: witness_bytes,
            execution_trace,
            public_inputs,
        })
    }

    /// Step 7 - Generate STARK proof (item 8).
    ///
    /// When `sp1-sdk` feature is active, the real [`ProverClient`] proves the
    /// guest program on the witness (proof mode from `SXIAUM_SP1_PROOF_MODE`,
    /// default `compressed`), self-verifies the result against the real
    /// verifying key, and binds the encoded public-input envelope to the
    /// committed SP1 public values. Without the feature, the SHA-256
    /// commitment simulation keeps CI and unit tests running without the
    /// heavyweight prover infrastructure.
    pub fn generate_stark_proof(&self, trace: &Sp1ExecutionTrace) -> Result<Sp1Proof> {
        if trace.execution_trace.is_empty() {
            bail!("execution trace cannot be empty");
        }

        #[cfg(feature = "sp1-sdk")]
        {
            return self.generate_real_sdk_proof(trace);
        }

        // SHA-256 simulation fallback (never compiled with sp1-sdk).
        #[cfg(not(feature = "sp1-sdk"))]
        #[allow(unreachable_code)]
        {
            // SECURITY (C-16): derive the verification key from this prover's
            // program with the canonical vk formula, then produce the proof
            // commitment via the SHARED `simulated_proof_commitment` function
            // so a simulated prover's output always matches what
            // `Sp1Verifier::expected_proof_commitment` recomputes.
            let verification_key = derive_verification_key(&self.program);
            let proof_bytes = simulated_proof_commitment(&verification_key, &trace.public_inputs);

            Ok(Sp1Proof {
                proof_bytes,
                public_inputs: trace.public_inputs.clone(),
                compressed: false,
                proof_system: Sp1ProofSystem::SimulatedSha256,
                verkle_proofs: vec![],
                vk_hash: None,
            })
        }
    }

    /// Real SP1 SDK proving pipeline (requires `sp1-sdk`).
    ///
    /// - Runs `client.setup` on this prover's program (cached per program digest),
    /// - generates a proof in the configured mode (`SXIAUM_SP1_PROOF_MODE`,
    ///   default: `compressed`),
    /// - re-verifies the proof locally with the same verifying key before it may
    ///   leave the prover host,
    /// - asserts the guest's committed public values equal the expected
    ///   `ZkPublicInputs` envelope (280 bytes) so a proof can never be attached
    ///   to different block parameters than those it was generated for.
    #[cfg(feature = "sp1-sdk")]
    fn generate_real_sdk_proof(&self, trace: &Sp1ExecutionTrace) -> Result<Sp1Proof> {
        use sp1_sdk::{HashableKey, SP1Stdin};

        if self.program.is_empty() {
            bail!("prover program must be initialized before proving");
        }
        // Fail closed before the SDK can panic on a malformed program.
        validate_sp1_elf(&self.program)?;
        if trace.witness_input.len() > MAX_WITNESS_INPUT_SIZE {
            bail!(
                "witness input size {} exceeds maximum allowed {}",
                trace.witness_input.len(),
                MAX_WITNESS_INPUT_SIZE
            );
        }

        let mode = real_proof_mode();
        let client = real_sdk::client();

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(trace.witness_input.clone());

        // Cache setup per program digest. The guard is held across prove +
        // self-verify because both need references into the cache; proving is
        // heavyweight anyway, so serializing provers here is intentional.
        let mut cache = real_sdk::key_cache()
            .lock()
            .expect("sp1 key cache poisoned");
        let digest = Sha256::digest(&self.program).into();
        if !cache.contains_key(&digest) {
            tracing::info!(
                "SP1 setup for guest program sha256:{} ({} KiB ELF)",
                hex::encode(digest),
                self.program.len() / 1024
            );
            cache.insert(digest, client.setup(&self.program));
        }
        let (pk, vk) = cache.get(&digest).expect("keys just inserted");

        let request = match mode {
            Sp1RealProofMode::Compressed => client.prove(pk, stdin).compressed(),
            Sp1RealProofMode::Core => client.prove(pk, stdin).core(),
            Sp1RealProofMode::Plonk => client.prove(pk, stdin).plonk(),
            Sp1RealProofMode::Groth16 => client.prove(pk, stdin).groth16(),
        };
        let proof = request.run()?;

        // Defense in depth: never emit a proof that does not verify with the
        // exact verifying key derived from the program we just proved.
        client
            .verify(&proof, vk)
            .map_err(|e| anyhow::anyhow!("SP1 SDK self-verification failed: {:?}", e))?;

        // The guest commits the 280-byte ZkPublicInputs envelope via
        // `commit_slice`; bind the proof to exactly those parameters.
        if proof.public_values.as_slice() != trace.public_inputs.as_slice() {
            bail!(
                "SP1 public values ({}) do not match expected public inputs ({})",
                proof.public_values.as_slice().len(),
                trace.public_inputs.len()
            );
        }

        tracing::info!(
            "real SP1 proof generated (mode={}, vk={})",
            mode.as_str(),
            vk.bytes32()
        );

        Ok(Sp1Proof {
            proof_bytes: bincode::serialize(&proof)?,
            public_inputs: trace.public_inputs.clone(),
            compressed: matches!(mode, Sp1RealProofMode::Compressed),
            proof_system: Sp1ProofSystem::Sp1Sdk,
            verkle_proofs: vec![],
            vk_hash: Some(vk.bytes32()),
        })
    }

    /// Item 9 - Compress proof for network broadcast.
    ///
    /// Truncates the proof to at most 32 bytes and sets `compressed = true`.
    /// Full STARK proofs are typically hundreds of kilobytes; the compressed
    /// form is used when gossiping block proposals over the P2P layer where
    /// bandwidth is a concern.  Verifiers accept both forms.
    pub fn compress_proof_for_network_transmission(&self, proof: &Sp1Proof) -> Result<Sp1Proof> {
        if proof.proof_bytes.is_empty() {
            bail!("proof bytes cannot be empty");
        }

        if proof.proof_system == Sp1ProofSystem::Sp1Sdk {
            return Ok(proof.clone());
        }

        let compressed_bytes = if proof.proof_bytes.len() > 32 {
            proof.proof_bytes[..32].to_vec()
        } else {
            proof.proof_bytes.clone()
        };

        Ok(Sp1Proof {
            proof_bytes: compressed_bytes,
            public_inputs: proof.public_inputs.clone(),
            compressed: true,
            proof_system: proof.proof_system,
            verkle_proofs: proof.verkle_proofs.clone(),
            vk_hash: proof.vk_hash.clone(),
        })
    }

    /// Item 10 - Serialize proof bytes.
    ///
    /// Returns the raw proof bytes for serialisation or transmission.  Callers
    /// that need the full `Sp1Proof` envelope (including public inputs and the
    /// compression flag) should clone the struct directly.
    pub fn export_proof_bytes(&self, proof: &Sp1Proof) -> Vec<u8> {
        proof.proof_bytes.clone()
    }

    /// Step 10 - Export public inputs.
    ///
    /// Returns the public inputs committed to by the proof.  Verifiers use
    /// these to derive the verification key and to check that the proof
    /// corresponds to the expected computation.
    pub fn export_public_inputs(&self, proof: &Sp1Proof) -> Vec<u8> {
        proof.public_inputs.clone()
    }

    /// High-level prove helper: executes steps 5-8 in one call.
    ///
    /// Runs the guest program with `witness_input`, generates a STARK proof
    /// from the resulting trace, and returns the compressed form ready for
    /// gossip or storage.
    pub fn prove(&self, witness_input: &[u8]) -> Result<Sp1Proof> {
        let trace = self.execute_program_with_witness(witness_input)?;
        let proof = self.generate_stark_proof(&trace)?;
        self.compress_proof_for_network_transmission(&proof)
    }

    /// High-level prove helper for block witnesses (uses `execute` + `generate_stark_proof`).
    ///
    /// Preferred entry point when a full `ZkBlockWitness` is available (items 6-9).
    pub fn prove_block(&self, witness: &ZkBlockWitness) -> Result<Sp1Proof> {
        let trace = self.execute(witness)?;
        let proof = self.generate_stark_proof(&trace)?;
        self.compress_proof_for_network_transmission(&proof)
    }

    /// Item 18 - Batch proof generation.
    ///
    /// Calls `prove` for each witness in the slice and collects the results.
    /// Errors on the first failing witness, returning its error immediately.
    /// Used by `ZkEngine::prove_all_transactions_in_block` to prove every
    /// transaction in a block in sequence.
    pub fn batch_proof_generation(&self, witness_inputs: &[Vec<u8>]) -> Result<Vec<Sp1Proof>> {
        witness_inputs
            .iter()
            .map(|witness| self.prove(witness))
            .collect()
    }

    fn derive_proving_key(program: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:pk");
        hasher.update(program);
        hasher.finalize().to_vec()
    }

    fn derive_trace_bytes(program: &[u8], witness_input: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(program);
        hasher.update(witness_input);
        hasher.finalize().to_vec()
    }

    /// Derive the public-input envelope bound into the proof.
    ///
    /// When the witness payload is a canonical `ZkBlockWitness`, the encoded
    /// `ZkPublicInputs` (280 bytes) are returned - exactly what the guest
    /// program commits via `commit_slice`, so real SP1 proofs stay bound to
    /// the block parameters. Arbitrary (non-STF) dev payloads fall back to a
    /// domain-separated hash commitment.
    fn derive_public_inputs(program: &[u8], witness_input: &[u8]) -> Vec<u8> {
        if let Ok(witness) = bincode::deserialize::<ZkBlockWitness>(witness_input) {
            return witness.public_inputs.encode();
        }

        let mut hasher = Sha256::new();
        hasher.update(b"sp1:public");
        hasher.update(program);
        hasher.update(witness_input);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp1_prover_default_and_simulate() {
        let prover = Sp1Prover::default();
        assert!(!prover.program.is_empty(), "Program should not be empty");

        // Empty private payload + matching roots = valid no-op STF witness.
        let public = ZkPublicInputs::default();
        let witness = ZkBlockWitness::new(
            Sp1ExecutionTrace {
                program: prover.program.clone(),
                witness_input: Vec::new(),
                execution_trace: Vec::new(),
                public_inputs: public.encode(),
            },
            public,
        );

        // With the real SDK the guest ELF actually executes; heavy proving is
        // gated behind SXIAUM_SP1_TEST_REAL so ordinary `cargo test` is fast.
        #[cfg(feature = "sp1-sdk")]
        {
            if std::env::var("SXIAUM_SP1_TEST_REAL")
                .unwrap_or_default()
                .is_empty()
            {
                eprintln!(
                    "skipping real SP1 proof generation (set SXIAUM_SP1_TEST_REAL=1 and \
                     provide a valid riscv32im ELF to enable)"
                );
                return;
            }
        }

        let proof = prover
            .prove_block(&witness)
            .expect("Proof generation failed");
        #[cfg(not(feature = "sp1-sdk"))]
        assert_eq!(proof.proof_system, Sp1ProofSystem::SimulatedSha256);
        #[cfg(feature = "sp1-sdk")]
        assert_eq!(proof.proof_system, Sp1ProofSystem::Sp1Sdk);
        assert_eq!(proof.public_inputs, witness.public_inputs.encode());
    }

    #[test]
    #[cfg(feature = "sp1-sdk")]
    fn print_canonical_sp1_vkey_hash() {
        // Operator utility: prints the SP1 `HashableKey::bytes32()` of the
        // embedded guest program for pinning in genesis `zk.vk_hash`.
        // Run with: cargo test -p sxiaum-zk --features sp1-sdk \
        //           print_canonical_sp1_vkey_hash -- --nocapture
        let h = canonical_sp1_vkey_hash_hex().expect("canonical SP1 vkey derivation");
        println!("SP1_VKEY_BYTES32={h}");
    }

    #[test]
    fn test_sp1_prover_rejects_malformed_stf_witness() {
        let prover = Sp1Prover::default();
        let witness = ZkBlockWitness::new(
            Sp1ExecutionTrace {
                program: prover.program.clone(),
                // Non-empty garbage cannot decode as StfPrivateInputs.
                witness_input: vec![1, 2, 3],
                execution_trace: Vec::new(),
                public_inputs: Vec::new(),
            },
            ZkPublicInputs::default(),
        );
        assert!(
            prover.prove_block(&witness).is_err(),
            "malformed STF witness must be rejected before proving"
        );
    }

    #[test]
    #[cfg(feature = "sp1-sdk")]
    fn test_sp1_prover_real_sdk() {
        // Runs when the sp1-sdk feature is enabled: validates that the host
        // handles the embedded guest artifact gracefully - either executing
        // it (valid riscv32im ELF) or failing closed with a clear error
        // (stale/wrong-architecture artifact). Neither may panic the host.
        let prover = Sp1Prover::default();
        assert!(!prover.program.is_empty(), "Program should not be empty");

        let public = ZkPublicInputs::default();
        let witness = ZkBlockWitness::new(
            Sp1ExecutionTrace {
                program: prover.program.clone(),
                witness_input: Vec::new(),
                execution_trace: Vec::new(),
                public_inputs: public.encode(),
            },
            public,
        );

        match prover.execute(&witness) {
            Ok(_) => eprintln!("guest ELF executed successfully"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("32-bit") || msg.contains("ELF") || msg.contains("RISC-V"),
                    "unexpected execute failure: {msg}"
                );
                eprintln!("guest ELF rejected by host validation: {msg}");
            }
        }

        // Cycle accounting straight from the SDK executor.
        use sp1_sdk::SP1Stdin;
        let client = crate::sp1::prover::real_sdk_client();
        let stdin_bytes = bincode::serialize(&witness).expect("serialize witness");
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(stdin_bytes);
        let (_, report) = client.execute(SP1_ELF, stdin).run().expect("sdk execute");
        println!("SP1_EXECUTION_REPORT={report:?}");
    }
}
