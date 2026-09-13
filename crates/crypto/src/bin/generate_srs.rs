//! Generate a discarded-trapdoor SRS file for operator dry-runs and testnets.
//!
//! **Not a multi-party ceremony.** For mainnet, replace this file with a real
//! Powers-of-Tau / MPC artifact and pin its SHA-256 in genesis `kzg.srs_hash`.
//!
//! Usage:
//!   cargo run -p sxiaum-crypto --bin generate_srs -- [output_path]
//!
//! Prints the SHA-256 of the written file for genesis pinning.

use anyhow::Result;
use sha2::{Digest, Sha256};
use std::env;
use std::path::PathBuf;
use sxiaum_crypto::kzg::{
    generate_discarded_trapdoor_srs, is_placeholder_srs_hash, srs_file_sha256_hex,
    validate_srs_is_not_dev, write_srs_to_file, DEV_SRS_MARKER,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("production_srs.bin")
    };

    println!("Generating discarded-trapdoor SRS (NOT a multi-party ceremony)...");
    println!("  output: {}", path.display());
    println!(
        "  note: this tool never writes {} (tau=42). Mainnet still requires a real ceremony.",
        DEV_SRS_MARKER
    );

    let srs = generate_discarded_trapdoor_srs()?;
    write_srs_to_file(&srs, &path)?;
    validate_srs_is_not_dev(&path)?;

    let hash = srs_file_sha256_hex(&path)?;
    if is_placeholder_srs_hash(&hash) {
        anyhow::bail!("internal error: generated hash looks like a placeholder");
    }

    // Double-check file bytes hash the same way operators will pin in genesis.
    let raw = std::fs::read(&path)?;
    let rehash = hex::encode(Sha256::digest(&raw));
    assert_eq!(hash, rehash);

    println!("Successfully wrote SRS.");
    println!("SHA-256 (pin in genesis kzg.srs_hash): 0x{hash}");
    println!("Set:");
    println!("  export SXIAUM_SRS_MODE=production");
    println!("  export SXIAUM_KZG_SRS_PATH={}", path.display());
    Ok(())
}
