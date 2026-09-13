use anyhow::Result;
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use sxiaum_zk::groth16::fold::{
    deserialize_fold_proof, fold_vk_digest, FoldAnchorConfig, FoldLayerId, FoldLayerVerifier,
    FoldStatement,
};
use sxiaum_zk::{
    proof_size_for_layer, RecursiveCertificateHeader, RecursiveStateSyncProof, ZkEngine, ZkProof,
    RECURSIVE_CERT_VERSION,
};

#[derive(Parser, Debug)]
#[command(name = "verify_fold_proof")]
#[command(about = "Standalone empirical verifier for SXIAUM recursive fold certificates")]
struct Args {
    /// Path to certificate binary (.bin) or JSON (.json) file
    cert_path: PathBuf,

    /// Optional path to prior certificate (required for folded sel=1 certificates)
    #[arg(long)]
    prior_cert: Option<PathBuf>,

    /// Optional path to prior-prior certificate (for multi-fold chains)
    #[arg(long)]
    prior_prior_cert: Option<PathBuf>,

    /// Genesis state root in hex (32 bytes)
    #[arg(
        long,
        default_value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )]
    genesis_root: String,

    /// Anchor / Target state root in hex (32 bytes)
    #[arg(
        long,
        default_value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )]
    target_root: String,

    /// Anchor / Target block hash in hex (32 bytes)
    #[arg(
        long,
        default_value = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )]
    target_hash: String,

    /// Anchor state root in hex (32 bytes)
    #[arg(
        long,
        default_value = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    )]
    anchor_root: String,

    /// Anchor block hash in hex (32 bytes)
    #[arg(
        long,
        default_value = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )]
    anchor_hash: String,

    /// Anchor block height
    #[arg(long, default_value_t = 10000)]
    anchor_height: u64,

    /// Directory containing precomputed verifying keys (vk_layer_a_mnt6.bin, vk_layer_b_mnt4.bin)
    #[arg(long)]
    vk_dir: Option<PathBuf>,

    /// Profile mode: display hardware execution cycles (RDTSC) and cryptographic operation breakdown
    #[arg(long)]
    profile: bool,

    /// Verbose output with diagnostic information
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode: only print VALID or REJECTED
    #[arg(short, long)]
    quiet: bool,
}

fn parse_hex_32(s: &str, field_name: &str) -> Result<[u8; 32]> {
    let clean = s.trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| anyhow::anyhow!("failed to parse {field_name} hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{field_name} must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_json_or_bin_cert(
    path: &PathBuf,
) -> Result<([u8; 32], [u8; 32], RecursiveCertificateHeader, ZkProof, Option<RecursiveStateSyncProof>)> {
    let raw_bytes = fs::read(path)?;
    if path.extension().and_then(|s| s.to_str()) == Some("json") {
        let full_cert: RecursiveStateSyncProof = serde_json::from_slice(&raw_bytes)?;
        let header = RecursiveCertificateHeader {
            version: RECURSIVE_CERT_VERSION,
            layer: full_cert.layer,
            sel: full_cert.sel,
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            target_height: full_cert.target_height,
            prev_certificate_hash: full_cert.prev_certificate_hash,
        };
        Ok((
            full_cert.target_state_root,
            full_cert.target_block_hash,
            header,
            full_cert.proof.clone(),
            Some(full_cert),
        ))
    } else {
        let (header, proof) = RecursiveStateSyncProof::decode_certificate(&raw_bytes)?;
        Ok(([0u8; 32], [0u8; 32], header, proof, None))
    }
}

fn run_verification(args: &Args) -> Result<bool> {
    if !args.quiet {
        println!("[SXIAUM-VERIFIER] Reading certificate: {}", args.cert_path.display());
    }

    let genesis_root = parse_hex_32(&args.genesis_root, "genesis_root")?;
    let default_target_root = parse_hex_32(&args.target_root, "target_root")?;
    let default_target_hash = parse_hex_32(&args.target_hash, "target_hash")?;
    let anchor_root = parse_hex_32(&args.anchor_root, "anchor_root")?;
    let anchor_hash = parse_hex_32(&args.anchor_hash, "anchor_hash")?;

    let (mut target_root, mut target_hash, header, proof, maybe_full_cert) =
        load_json_or_bin_cert(&args.cert_path)?;

    if target_root == [0u8; 32] {
        target_root = default_target_root;
    }
    if target_hash == [0u8; 32] {
        target_hash = default_target_hash;
    }

    if args.verbose {
        println!("  • Header Version:       {}", header.version);
        println!("  • Layer:                {:?}", header.layer);
        println!("  • Sel (0=boot, 1=fold): {}", header.sel);
        println!("  • Chain ID:             {}", header.chain_id);
        println!("  • Target Height:        {}", header.target_height);
        println!("  • Prev Cert Hash:       {}", hex::encode(header.prev_certificate_hash));
        println!("  • Proof Size:           {} bytes", proof.bytes.len());
    }

    // Verify expected proof size for layer
    let expected_proof_size = proof_size_for_layer(header.layer);
    if proof.bytes.len() != expected_proof_size {
        anyhow::bail!(
            "invalid proof size for layer {:?}: expected {} bytes, got {}",
            header.layer,
            expected_proof_size,
            proof.bytes.len()
        );
    }

    let anchor_config = FoldAnchorConfig {
        root: anchor_root,
        block_hash: anchor_hash,
        height: args.anchor_height,
    };

    // Locate precomputed verifying keys if available (allows O(1) instant verification)
    let candidate_dirs = vec![
        args.vk_dir.clone(),
        args.cert_path.parent().map(|p| p.to_path_buf()),
        Some(PathBuf::from("test_artifacts")),
        Some(PathBuf::from("artifacts_zk")),
    ];

    let mut precomputed_vks = None;
    for cand in candidate_dirs.into_iter().flatten() {
        let vka_path = cand.join("vk_layer_a_mnt6.bin");
        let vkb_path = cand.join("vk_layer_b_mnt4.bin");
        if vka_path.exists() && vkb_path.exists() {
            if args.verbose {
                println!("  • Loading precomputed verifying keys from {}", cand.display());
            }
            let vka_bytes = fs::read(&vka_path)?;
            let vkb_bytes = fs::read(&vkb_path)?;
            let vk_a =
                VerifyingKey::<ark_mnt6_753::MNT6_753>::deserialize_compressed(&vka_bytes[..])?;
            let vk_b =
                VerifyingKey::<ark_mnt4_753::MNT4_753>::deserialize_compressed(&vkb_bytes[..])?;
            let vk_digest_a = fold_vk_digest(&vk_a);
            let vk_digest_b = fold_vk_digest(&vk_b);
            let verifier_a = FoldLayerVerifier::new(
                &vk_a,
                vk_digest_b,
                anchor_config.clone(),
                sxiaum_types::SXIAUM_CHAIN_ID,
            )?;
            let verifier_b = FoldLayerVerifier::new(
                &vk_b,
                vk_digest_a,
                anchor_config.clone(),
                sxiaum_types::SXIAUM_CHAIN_ID,
            )?;
            precomputed_vks = Some((verifier_a, verifier_b, vk_digest_a, vk_digest_b));
            break;
        }
    }

    if let Some((verifier_a, verifier_b, vk_digest_a, _)) = precomputed_vks {
        if !header.sel {
            if !args.quiet {
                println!("[SXIAUM-VERIFIER] Executing fast single pairing check (Layer A, MNT6-753)...");
            }
            let statement = FoldStatement {
                sel: false,
                genesis_root,
                target_root,
                target_block_hash: target_hash,
                target_height: header.target_height,
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                vk_digest: vk_digest_a,
                prior_root: genesis_root,
                prior_block_hash: [0u8; 32],
                prior_height: 0,
            };
            let prior_statement = FoldStatement::genesis_prior(
                genesis_root,
                sxiaum_types::SXIAUM_CHAIN_ID,
                vk_digest_a,
            );
            let fold_proof =
                deserialize_fold_proof::<ark_mnt6_753::MNT6_753>(&proof.bytes)?;

            #[cfg(target_arch = "x86_64")]
            let t0_cycles = unsafe { core::arch::x86_64::_rdtsc() };
            let t0_time = std::time::Instant::now();

            let valid = verifier_a.verify(
                &statement,
                &prior_statement,
                &prior_statement,
                &fold_proof,
            )?;

            #[cfg(target_arch = "x86_64")]
            let elapsed_cycles = unsafe { core::arch::x86_64::_rdtsc() } - t0_cycles;
            let elapsed_time = t0_time.elapsed();

            if args.profile {
                println!("============================================================");
                println!(" SXIAUM Cryptographic Hardware Performance Profile");
                println!("============================================================");
                println!("  • Verification Target:      Layer A (MNT6-753 Groth16 Pairing)");
                println!("  • Base Field / Scalar Bit:  753-bit prime (MNT6-753)");
                println!("  • G1 Scalar Multiplications: 25 public input bases (753-bit BigInt MSM)");
                println!("  • Miller Loops (Fp6):       1 (degree-6 extension field arithmetic)");
                println!("  • Final Exponentiation:     1 ((q^6 - 1)/r power on 753-bit field)");
                #[cfg(target_arch = "x86_64")]
                println!("  • Elapsed CPU Cycles (TSC): {} cycles", elapsed_cycles);
                println!("  • Wall-Clock Verification:  {:?}", elapsed_time);
                println!("============================================================");
            }

            Ok(valid)
        } else {
            let prior_path = args.prior_cert.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "folded certificate (sel=1) requires --prior-cert to provide inductive statement bindings"
                )
            })?;
            let (_, _, _, _, maybe_prior_full) = load_json_or_bin_cert(prior_path)?;
            let prior_cert = maybe_prior_full.ok_or_else(|| {
                anyhow::anyhow!("prior certificate must be provided as full JSON metadata for fold verification")
            })?;
            let maybe_prior_prior = if let Some(pp_path) = &args.prior_prior_cert {
                let (_, _, _, _, maybe_pp) = load_json_or_bin_cert(pp_path)?;
                maybe_pp
            } else {
                None
            };
            let current_full = match maybe_full_cert {
                Some(c) => c,
                None => {
                    anyhow::bail!("folded certificate requires full statement metadata to verify in-circuit fold ties")
                }
            };
            let prior_prior_statement = match maybe_prior_prior {
                Some(pp) => FoldStatement {
                    sel: pp.sel,
                    genesis_root,
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
                    genesis_root,
                    sxiaum_types::SXIAUM_CHAIN_ID,
                    prior_cert.vk_digest,
                ),
            };

            let own = FoldStatement {
                sel: true,
                genesis_root,
                target_root: current_full.target_state_root,
                target_block_hash: current_full.target_block_hash,
                target_height: current_full.target_height,
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                vk_digest: current_full.vk_digest,
                prior_root: current_full.prior_state_root,
                prior_block_hash: current_full.prior_block_hash,
                prior_height: current_full.prior_height,
            };
            let prior = FoldStatement {
                sel: prior_cert.sel,
                genesis_root,
                target_root: prior_cert.target_state_root,
                target_block_hash: prior_cert.target_block_hash,
                target_height: prior_cert.target_height,
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                vk_digest: prior_cert.vk_digest,
                prior_root: prior_cert.prior_state_root,
                prior_block_hash: prior_cert.prior_block_hash,
                prior_height: prior_cert.prior_height,
            };

            if !args.quiet {
                println!("[SXIAUM-VERIFIER] Executing fast single pairing check on folded certificate (Layer B, MNT4-753)...");
            }

            match current_full.layer {
                FoldLayerId::A => {
                    let p =
                        deserialize_fold_proof::<ark_mnt6_753::MNT6_753>(&current_full.proof.bytes)?;
                    verifier_a.verify(&own, &prior, &prior_prior_statement, &p)
                }
                FoldLayerId::B => {
                    let p =
                        deserialize_fold_proof::<ark_mnt4_753::MNT4_753>(&current_full.proof.bytes)?;
                    verifier_b.verify(&own, &prior, &prior_prior_statement, &p)
                }
            }
        }
    } else {
        if args.verbose {
            println!("  • Initializing in-process fold stack verifier (fallback)...");
        }
        let mut engine = ZkEngine::new();
        engine.init_fold_stack(anchor_config)?;

        if !header.sel {
            if !args.quiet {
                println!("[SXIAUM-VERIFIER] Executing single pairing check (Layer A, MNT6-753)...");
            }
            let valid = engine.verify_recursive_state_sync_proof(
                genesis_root,
                target_root,
                target_hash,
                header.target_height,
                header.prev_certificate_hash,
                &proof,
            )?;
            Ok(valid)
        } else {
            let prior_path = args.prior_cert.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "folded certificate (sel=1) requires --prior-cert to provide inductive statement bindings"
                )
            })?;
            let (_, _, _, _, maybe_prior_full) = load_json_or_bin_cert(prior_path)?;
            let prior_cert = maybe_prior_full.ok_or_else(|| {
                anyhow::anyhow!("prior certificate must be provided as full JSON metadata for fold verification")
            })?;
            let maybe_prior_prior = if let Some(pp_path) = &args.prior_prior_cert {
                let (_, _, _, _, maybe_pp) = load_json_or_bin_cert(pp_path)?;
                maybe_pp
            } else {
                None
            };
            let current_full = match maybe_full_cert {
                Some(c) => c,
                None => {
                    anyhow::bail!("folded certificate requires full statement metadata to verify in-circuit fold ties")
                }
            };
            if !args.quiet {
                println!("[SXIAUM-VERIFIER] Executing single pairing check on folded certificate (Layer B, MNT4-753)...");
            }
            let valid = engine.verify_folded_certificate(
                genesis_root,
                &current_full,
                &prior_cert,
                maybe_prior_prior.as_ref(),
            )?;
            Ok(valid)
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    match run_verification(&args) {
        Ok(true) => {
            println!("VALID");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("REJECTED: cryptographic pairing check returned false");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("REJECTED: {e}");
            ExitCode::FAILURE
        }
    }
}
