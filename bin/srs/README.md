# Sxiaum SRS ceremony tools

Tools for producing, verifying and rotating the KZG/Verkle structured
reference string (SRS), plus Groth16 key management helpers.

## Multi-party Powers-of-Tau ceremony (mainnet)

The `ceremony-*` commands run a sequential multi-party computation. Every
participant's transform is publicly verifiable with BLS12-381 pairings, the
transcript hash-chains all rounds, and each round publishes a hiding
commitment to its secret ratio. As long as **one** honest participant destroys
its secret, the final toxic waste is unknown.

### 1. Coordinator: initialize

```bash
cargo run --release -p sxiaum-srs -- ceremony-init \
  --path srs_round0.srs --transcript transcript.json
```

Publish `srs_round0.srs` (generator-only state, no secret) and
`transcript.json` to participants.

### 2. Participants: contribute in order

Each participant receives the current head SRS file, then runs:

```bash
cargo run --release -p sxiaum-srs -- ceremony-contribute \
  --input srs_roundN.srs --output srs_roundN+1.srs \
  --transcript transcript.json --participant <unique-id>
```

The command refuses to run if the incoming state fails structural pairing
verification or does not match the transcript head. Publish **only** your
`--output` file; destroy your input copy. The tool never persists your secret.

### 3. Anyone: verify and pin for mainnet

```bash
cargo run --release -p sxiaum-srs -- ceremony-finalize \
  --path srs_final.srs --transcript transcript.json
```

Verification checks (offline, trustless):

- transcript hash-chain linkage + unique participant IDs,
- per-round attestation digests,
- per-round ratio commitments (`e(C_i, g2) == e(C_{i-1}, W_i)`),
- full structural verification of the final SRS (all 256 powers),
- development-trapdoor rejection,
- minimum participant count (default 3; `--min-participants` to override).

Pin the printed SHA-256 as `kzg.srs_hash` in `configs/mainnet.json` and set:

```bash
export SXIAUM_SRS_MODE=production
export SXIAUM_KZG_SRS_PATH=/secure/path/srs_final.srs
export SXIAUM_SRS_CEREMONY_TRANSCRIPT=/secure/path/transcript.json   # optional hard gate
```

## Single-party tools (testnet / dry-runs only)

Commands:

- `export --path <file>`: Export a discarded-trapdoor SRS to a file (never writes dev_tau42 / tau=42).
- `verify --path <file>`: Verify an SRS file can be loaded, is not the development trapdoor, and print its SHA-256.
- `verify-vk --path <file>`: Verify a Groth16 VK loads.
- `import-pk --path <file>`: Import a proving key (checks readability).
- `export-pk --path <file>`: Export a development proving key.
- `verify-pk --pk <file> --vk <file>`: Verify a proving key matches a verifying key.
- `import-vk --path <file>`: Import a verification key (checks readability).
- `export-vk --path <file>`: Export a development verification key.
- `rotate-pk --src <file> --dst <file> [--vk <file>]`: Atomically rotate a proving key into place.
- `rotate-vk --src <file> --dst <file> [--pk <file>]`: Atomically rotate a verifying key into place.
- `verify-sp1 --path <file>`: Verify an SP1 proof envelope (honors `SXIAUM_SP1_MODE`; build with `--features sp1-sdk` for real proofs).
- `generate-sim-sp1 --out <file>`: Generate a simulated SP1 proof (development only).
- Keystore: `store-key`, `fetch-key`, `delete-key` (fs / Vault backends).

CI recommendation:

- Add a GitHub Actions job that sets `SXIAUM_SP1_MODE=production` and runs `cargo test -p sxiaum-zk` to ensure mainnet policies reject simulated proofs.
- Add a CI job running `ceremony-finalize` against the published transcript whenever the SRS changes.

Example (dev dry-run):

```powershell
cd sxiaum/bin/srs
cargo run --release -- export --path ../srs.bin
cargo run --release -- verify --path ../srs.bin
```
