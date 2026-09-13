use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use clap::Parser;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use sxiaum_zk::groth16::fold::{fold_public_inputs, FoldAnchorConfig, FoldStatement};
use sxiaum_zk::ZkEngine;

#[derive(Parser, Debug)]
#[command(name = "generate_fold_cert")]
#[command(about = "Generate real SXIAUM recursive fold certificates and keys")]
struct Args {
    /// Directory to output generated certificate binaries and metadata
    #[arg(short, long, default_value = "artifacts_zk")]
    out_dir: PathBuf,

    /// Genesis state root in hex (32 bytes)
    #[arg(
        long,
        default_value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )]
    genesis_root: String,

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

    /// Target state root for folded certificate in hex (32 bytes)
    #[arg(
        long,
        default_value = "1111111111111111111111111111111111111111111111111111111111111111"
    )]
    target_root: String,

    /// Target block hash for folded certificate in hex (32 bytes)
    #[arg(
        long,
        default_value = "2222222222222222222222222222222222222222222222222222222222222222"
    )]
    target_hash: String,

    /// Target block height for folded certificate
    #[arg(long, default_value_t = 20000)]
    target_height: u64,
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

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)?;

    let genesis_root = parse_hex_32(&args.genesis_root, "genesis_root")?;
    let anchor_root = parse_hex_32(&args.anchor_root, "anchor_root")?;
    let anchor_hash = parse_hex_32(&args.anchor_hash, "anchor_hash")?;
    let target_root = parse_hex_32(&args.target_root, "target_root")?;
    let target_hash = parse_hex_32(&args.target_hash, "target_hash")?;

    println!("============================================================");
    println!(" SXIAUM Recursive Fold Certificate Generator (Groth16/MNT)");
    println!("============================================================");
    println!("Chain ID:       {}", sxiaum_types::SXIAUM_CHAIN_ID);
    println!("Output dir:     {}", args.out_dir.display());
    println!("Anchor Height:  {}", args.anchor_height);
    println!("Target Height:  {}", args.target_height);
    println!("------------------------------------------------------------");

    println!("[1/5] Initializing MNT4-753 / MNT6-753 2-cycle fold stack trusted setup...");
    let t_setup_start = std::time::Instant::now();
    let anchor_config = FoldAnchorConfig {
        root: anchor_root,
        block_hash: anchor_hash,
        height: args.anchor_height,
    };

    let mut engine = ZkEngine::new();
    engine.init_fold_stack(anchor_config.clone())?;
    let t_setup = t_setup_start.elapsed();
    println!("      ✓ Trusted setup complete for Layer A (MNT6) and Layer B (MNT4) in {:.2?}", t_setup);

    let stack = engine.fold_stack.as_ref().expect("fold stack initialized");

    println!("[2/5] Generating Bootstrap Certificate (Layer A, MNT6-753, sel=0)...");
    let t_prov_a_start = std::time::Instant::now();
    let anchor_cert = engine.generate_recursive_state_sync_proof(
        genesis_root,
        anchor_root,
        anchor_hash,
        args.anchor_height,
        [0u8; 32],
    )?;
    let t_prov_a = t_prov_a_start.elapsed();
    let anchor_bin = anchor_cert.certificate_bytes()?;
    let anchor_hash_val = anchor_cert.certificate_hash()?;
    println!(
        "      ✓ Bootstrap cert generated: {} bytes in {:.2?}, SHA-256: {}",
        anchor_bin.len(),
        t_prov_a,
        hex::encode(anchor_hash_val)
    );

    println!("[3/5] Generating Folded Certificate (Layer B, MNT4-753, sel=1)...");
    let t_prov_b_start = std::time::Instant::now();
    let folded_cert = engine.generate_folded_certificate(
        genesis_root,
        &anchor_cert,
        None,
        target_root,
        target_hash,
        args.target_height,
        anchor_hash_val,
    )?;
    let t_prov_b = t_prov_b_start.elapsed();
    let folded_bin = folded_cert.certificate_bytes()?;
    let folded_hash_val = folded_cert.certificate_hash()?;
    println!(
        "      ✓ Folded cert generated: {} bytes in {:.2?}, SHA-256: {}",
        folded_bin.len(),
        t_prov_b,
        hex::encode(folded_hash_val)
    );

    println!("[4/5] Exporting raw verification keys and public inputs for cross-verification...");
    let vk_a_path = args.out_dir.join("vk_layer_a_mnt6.bin");
    let mut f_vka = File::create(&vk_a_path)?;
    stack.prover_a.vk.serialize_compressed(&mut f_vka)?;

    let vk_b_path = args.out_dir.join("vk_layer_b_mnt4.bin");
    let mut f_vkb = File::create(&vk_b_path)?;
    stack.prover_b.vk.serialize_compressed(&mut f_vkb)?;

    // Public inputs for Layer A bootstrap cert
    let statement_a = FoldStatement {
        sel: false,
        genesis_root,
        target_root: anchor_root,
        target_block_hash: anchor_hash,
        target_height: args.anchor_height,
        chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
        vk_digest: stack.prover_a.vk_digest,
        prior_root: genesis_root,
        prior_block_hash: [0u8; 32],
        prior_height: 0,
    };
    let prior_stmt_a = FoldStatement::genesis_prior(
        genesis_root,
        sxiaum_types::SXIAUM_CHAIN_ID,
        stack.prover_a.vk_digest,
    );
    let public_inputs_a = fold_public_inputs::<ark_mnt6_753::MNT6_753>(
        &statement_a,
        &prior_stmt_a,
        &prior_stmt_a,
    )?;
    let public_inputs_hex: Vec<String> = public_inputs_a
        .iter()
        .map(|elem| {
            let mut b = Vec::new();
            elem.serialize_compressed(&mut b).unwrap();
            hex::encode(b)
        })
        .collect();
    let pub_inputs_path = args.out_dir.join("public_inputs_layer_a.json");
    fs::write(
        &pub_inputs_path,
        serde_json::to_string_pretty(&public_inputs_hex)?,
    )?;

    println!("[5/5] Writing binary and JSON certificate files to disk...");
    let cert_bin_path = args.out_dir.join("cert.bin");
    let mut f_cert_bin = File::create(&cert_bin_path)?;
    f_cert_bin.write_all(&anchor_bin)?;

    let cert_json_path = args.out_dir.join("cert.json");
    fs::write(&cert_json_path, serde_json::to_string_pretty(&anchor_cert)?)?;

    let cert_folded_bin_path = args.out_dir.join("cert_folded.bin");
    let mut f_folded_bin = File::create(&cert_folded_bin_path)?;
    f_folded_bin.write_all(&folded_bin)?;

    let cert_folded_json_path = args.out_dir.join("cert_folded.json");
    fs::write(
        &cert_folded_json_path,
        serde_json::to_string_pretty(&folded_cert)?,
    )?;

    println!("------------------------------------------------------------");
    println!(" Artifacts successfully created:");
    println!("   - Bootstrap Cert (Binary): {}", cert_bin_path.display());
    println!("   - Bootstrap Cert (JSON):   {}", cert_json_path.display());
    println!("   - Folded Cert (Binary):    {}", cert_folded_bin_path.display());
    println!("   - Folded Cert (JSON):      {}", cert_folded_json_path.display());
    println!("   - VK Layer A (MNT6):       {}", vk_a_path.display());
    println!("   - VK Layer B (MNT4):       {}", vk_b_path.display());
    println!("   - Public Inputs (JSON):    {}", pub_inputs_path.display());
    println!("============================================================");

    Ok(())
}
