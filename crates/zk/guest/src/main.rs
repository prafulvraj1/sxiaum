//! SXIAUM State Transition ZKVM Guest Program
//!
//! Proves Phase-1 state transition validity:
//! `(state_root_before, block) - state_root_after`
//!
//! Constraints (see `stf` module and host `sxiaum_zk::sp1::stf`):
//! 1. Transaction signatures (Ed25519; Ethereum sighash binding)
//! 2. Gas accounting vs block/tx limits
//! 3. Deterministic transaction ordering commitment
//! 4. Commit-reveal digest integrity
//! 5. State access structure + Verkle proof fragments
//! 6. Binding of public inputs to private witness aggregates
//!
//! Rebuild the ELF after changes:
//!   `cd crates/zk/guest && cargo prove build`
//! then copy the artifact to `guest/elf/riscv32im-succinct-zkvm-elf`.

#![no_main]

mod stf;

use stf::{verify_block_witness, ZkBlockWitness};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Host writes `bincode(ZkBlockWitness)` via `SP1Stdin::write_vec`.
    let witness_bytes = sp1_zkvm::io::read_vec();

    let witness: ZkBlockWitness =
        bincode::deserialize(&witness_bytes).expect("guest: invalid ZkBlockWitness encoding");

    // Panic on constraint failure - invalid execution trace - proof fails.
    if let Err(reason) = verify_block_witness(&witness) {
        panic!("STF constraint failure: {reason}");
    }

    // Commit the 280-byte public input envelope for the verifier.
    let public_bytes = witness.public_inputs.encode();
    sp1_zkvm::io::commit_slice(&public_bytes);
}
