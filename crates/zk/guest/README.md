# SXIAUM SP1 Guest (State Transition Circuit)

This package is the **SP1 zkVM guest** that enforces Phase-1 state transition
function (STF) constraints for SXIAUM blocks.

## What it proves

Given a `ZkBlockWitness` (public roots/hash + private `StfPrivateInputs`):

1. Ed25519 signatures (native txs) / Ethereum sighash binding
2. Per-tx and block gas limits
3. Deterministic tx ordering commitment
4. Commit-reveal digests (if present)
5. State read/write structure and Verkle proof fragments
6. Binding hash linking public inputs to private aggregates

It does **not** re-execute the full EVM (see `docs/specs/core_protocol.md`).

## Rebuild ELF (required after guest source changes)

Install the SP1 toolchain (v3.x, matching `sp1-sdk = "3"` in the workspace),
then:

```bash
cd sxiaum/crates/zk/guest
cargo prove build
# Copy the produced ELF over the embedded artifact:
# cp <output>/riscv32im-succinct-zkvm-elf elf/riscv32im-succinct-zkvm-elf
```

**The artifact MUST be a 32-bit RISC-V ELF (`riscv32im`, machine 243).**
The currently checked-in file is a stale **riscv64 / ELF64** build and is
rejected by host-side validation (`validate_sp1_elf`) with a clear error.
Until it is rebuilt, real SP1 proving/verification fails closed while
development simulations keep working. Verify an artifact before committing:

```bash
python -c "b=open('elf/riscv32im-succinct-zkvm-elf','rb').read(20); \
print('OK' if b[:4]==b'\x7fELF' and b[4]==1 and int.from_bytes(b[18:20],'little')==243 else 'INVALID')"
```

Host code embeds the ELF via `include_bytes!` in `sxiaum_zk::sp1::prover::SP1_ELF`.

## Host alignment

Constraint logic is mirrored in `sxiaum/crates/zk/src/sp1/stf.rs`. Host
`Sp1Prover::execute` / `ZkEngine::build_block_witness` call the same checks
before proving so invalid witnesses never reach the prover.
