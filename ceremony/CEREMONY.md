# SXIAUM KZG SRS Ceremony Record

- Date: 2026-08-25
- Tool: `sxiaum-srs ceremony-*` (workspace, transcript version 1)
- Branching factor: 256 G1 powers (BLS12-381)
- Participants (sequential order):
  1. `genesis-factory-01`
  2. `genesis-factory-02`
  3. `genesis-factory-03`
  4. `genesis-factory-04`

## Result

| Item | Value |
|------|-------|
| Final SRS file | `ceremony/srs_final.srs` |
| **Final SHA-256 (genesis pin)** | `0x1ba9f33eea925fa2448220646092449daceadfc36367fa6472200e28b94cf24d` |
| Transcript | `ceremony/transcript.json` |
| Dev-trapdoor check | rejected by construction (verified at finalize) |

Every contribution was verified with BLS12-381 pairings before transformation;
each participant published a hiding `[tau_i]_2` commitment and a cumulative
`[tau_1..tau_i]_1`; all secrets were zeroized in-process after use.

## Verification

Anyone can re-verify offline:

```bash
cargo build --release -p sxiaum-srs
target/release/sxiaum-srs ceremony-finalize \
  --path ceremony/srs_final.srs --transcript ceremony/transcript.json
```

## Operational note

All four rounds ran on one machine. Cryptographically this is sound only if at
least one round's secret was destroyed honestly — which the tool guarantees by
construction — but mainnet-grade decentralization is stronger when rounds are
run by independent operators on independent hosts. Re-running the ceremony with
external participants before genesis is recommended; the pinned hash in
`configs/mainnet.json` must then be updated to the new final hash.
