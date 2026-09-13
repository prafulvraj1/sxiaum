use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

use sxiaum_crypto::kzg::{
    generate_discarded_trapdoor_srs, load_srs_from_file, srs_file_sha256_hex,
    validate_srs_is_not_dev, write_srs_to_file, DEV_SRS_MARKER,
};
use sxiaum_keystore::{fs_adapter::FsKeyStore, vault_adapter::VaultKeyStore, KeyEntry, KeyStore};
use sxiaum_zk::groth16::{init_global_verifier_from_env, Groth16Verifier};

#[derive(Parser)]
#[command(name = "sxiaum-srs", about = "SRS ceremony tools for SXIAUM")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a multi-party Powers-of-Tau ceremony (generator-only state,
    /// no secret). Creates the initial SRS file and the public transcript.
    CeremonyInit {
        /// Path for the initial SRS file.
        #[arg(long, short)]
        path: PathBuf,
        /// Path for the public ceremony transcript (JSON).
        #[arg(long, short)]
        transcript: PathBuf,
    },
    /// Contribute entropy to an existing ceremony. Verifies the incoming SRS
    /// structurally (pairings) before transforming it, records a verifiable
    /// commitment, and destroys the secret in-memory. Publish the OUTPUT file
    /// to the next participant; never publish your input file or secrets.
    CeremonyContribute {
        /// The current head SRS file you received.
        #[arg(long, short)]
        input: PathBuf,
        /// Where your transformed SRS is written (publish this).
        #[arg(long, short)]
        output: PathBuf,
        #[arg(long, short)]
        transcript: PathBuf,
        #[arg(long, short)]
        participant: String,
    },
    /// Verify a completed ceremony end-to-end and print the genesis pin
    /// (SHA-256 of the final SRS for `kzg.srs_hash`).
    CeremonyFinalize {
        /// Final SRS file of the last round.
        #[arg(long, short)]
        path: PathBuf,
        #[arg(long, short)]
        transcript: PathBuf,
        #[arg(long, default_value_t = sxiaum_crypto::MIN_CEREMONY_PARTICIPANTS)]
        min_participants: usize,
    },
    /// Generate a discarded-trapdoor SRS file (never writes dev_tau42 / tau=42).
    /// Not a multi-party ceremony — pin SHA-256 in genesis after a real MPC for mainnet.
    Export {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Verify an SRS file can be loaded, is not the development trapdoor, and print its hash
    Verify {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Verify a Groth16 verification key file can be loaded
    VerifyVk {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Validate a Groth16 proving key file deserializes correctly (import readiness check)
    ImportPk {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Verify a proving key file matches a verifying key file
    VerifyPk {
        #[arg(long, short)]
        pk: PathBuf,
        #[arg(long, short)]
        vk: PathBuf,
    },
    /// Verify an SP1 proof file (will honor SXIAUM_SP1_MODE env)
    VerifySp1 {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Generate a simulated SP1 proof (development) and write to file
    GenerateSimSp1 {
        #[arg(long, short)]
        out: PathBuf,
    },
    /// Export a Groth16 proving key to a file (development-only generator)
    ExportPk {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Export a Groth16 verifying key to a file (development-only)
    ExportVk {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Import a verifying key (checks readability)
    ImportVk {
        #[arg(long, short)]
        path: PathBuf,
    },
    /// Rotate a proving key file into place (atomic replace)
    RotatePk {
        #[arg(long, short)]
        src: PathBuf,
        #[arg(long, short)]
        dst: PathBuf,
        #[arg(long)]
        vk: Option<PathBuf>,
    },
    /// Rotate a verifying key file into place (atomic replace)
    RotateVk {
        #[arg(long, short)]
        src: PathBuf,
        #[arg(long, short)]
        dst: PathBuf,
        #[arg(long)]
        pk: Option<PathBuf>,
    },
    /// Store a raw key blob in a keystore backend
    StoreKey {
        #[arg(long)]
        id: String,
        #[arg(long)]
        kind: String,
        #[arg(long)]
        path: PathBuf,
        #[arg(long, default_value = "fs")]
        backend: String,
        #[arg(long)]
        store_path: Option<PathBuf>,
        #[arg(long)]
        vault_url: Option<String>,
        #[arg(long)]
        vault_token: Option<String>,
        #[arg(long)]
        vault_namespace: Option<String>,
        #[arg(long = "vault-header", value_parser = parse_key_value, num_args = 0..)]
        vault_headers: Vec<(String, String)>,
    },
    /// Fetch a raw key blob from a keystore backend
    FetchKey {
        #[arg(long)]
        id: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "fs")]
        backend: String,
        #[arg(long)]
        store_path: Option<PathBuf>,
        #[arg(long)]
        vault_url: Option<String>,
        #[arg(long)]
        vault_token: Option<String>,
        #[arg(long)]
        vault_namespace: Option<String>,
        #[arg(long = "vault-header", value_parser = parse_key_value, num_args = 0..)]
        vault_headers: Vec<(String, String)>,
    },
    /// Delete a key from a keystore backend
    DeleteKey {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "fs")]
        backend: String,
        #[arg(long)]
        store_path: Option<PathBuf>,
        #[arg(long)]
        vault_url: Option<String>,
        #[arg(long)]
        vault_token: Option<String>,
        #[arg(long)]
        vault_namespace: Option<String>,
        #[arg(long = "vault-header", value_parser = parse_key_value, num_args = 0..)]
        vault_headers: Vec<(String, String)>,
    },
}

fn parse_key_value(input: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = input
        .split_once('=')
        .ok_or_else(|| "expected NAME=VALUE".to_string())?;
    if key.is_empty() || value.is_empty() {
        return Err("expected NAME=VALUE".to_string());
    }
    Ok((key.to_string(), value.to_string()))
}

fn apply_vault_headers(
    mut store: VaultKeyStore,
    vault_namespace: Option<String>,
    vault_headers: &[(String, String)],
) -> Result<VaultKeyStore> {
    if let Some(namespace) = vault_namespace {
        store = store.with_namespace(namespace);
    }

    for (name, value) in vault_headers {
        store = store.with_header(name, value)?;
    }

    Ok(store)
}

fn verify_and_rotate_file(src: &PathBuf, dst: &PathBuf, backup: Option<PathBuf>) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    if let Some(backup_path) = backup {
        if dst.exists() {
            if let Some(parent) = backup_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(dst, &backup_path)?;
        }
    }

    let tmp = dst.with_extension("tmp");
    fs::copy(src, &tmp)?;
    // POSIX rename atomically replaces the destination; on Windows a
    // remove-then-rename window is unavoidable, so keep the fallback there.
    #[cfg(unix)]
    let replace_result = fs::rename(&tmp, dst);
    #[cfg(not(unix))]
    let replace_result = {
        if dst.exists() {
            fs::remove_file(dst)?;
        }
        fs::rename(&tmp, dst)
    };
    if let Err(e) = replace_result {
        // Best-effort cleanup of the staging copy; the backup retains the old key.
        let _ = fs::remove_file(&tmp);
        return Err(anyhow::anyhow!(
            "rotate failed while replacing {} (previous key preserved in .bak): {}",
            dst.display(),
            e
        ));
    }
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::CeremonyInit { path, transcript } => {
            println!("Initializing multi-party SRS ceremony...");
            let hash = sxiaum_crypto::ceremony::ceremony_init(&path, &transcript)?;
            println!("Initial (generator-only) SRS: {}", path.display());
            println!("Public transcript:           {}", transcript.display());
            println!("Initial state hash: 0x{}", hex::encode(hash));
            println!();
            println!("Next: send the SRS file to the first participant, who runs:");
            println!(
                "  sxiaum-srs ceremony-contribute --input {} --output <round1.srs> --transcript {} --participant <id>",
                path.display(),
                transcript.display()
            );
        }
        Commands::CeremonyContribute {
            input,
            output,
            transcript,
            participant,
        } => {
            println!("Verifying incoming ceremony state and contributing as {participant:?}...");
            let c = sxiaum_crypto::ceremony::ceremony_contribute(
                &input,
                &output,
                &transcript,
                &participant,
            )?;
            println!(
                "Contribution recorded in transcript {}",
                transcript.display()
            );
            println!("New state hash: 0x{}", hex::encode(c.new_state_hash));
            println!("Attestation:    0x{}", hex::encode(c.attestation));
            println!();
            println!("Publish ONLY {} to the next participant.", output.display());
            println!("Destroy your input copy and any local secret material.");
        }
        Commands::CeremonyFinalize {
            path,
            transcript,
            min_participants,
        } => {
            println!("Verifying completed ceremony ({min_participants}+ participants)...");
            let report =
                sxiaum_crypto::ceremony::ceremony_verify(&path, &transcript, min_participants)?;
            println!("Participants:");
            for (i, p) in report.participants.iter().enumerate() {
                println!("  {:>2}. {}", i + 1, p);
            }
            println!("Transcript version: {}", report.transcript_version);
            println!();
            println!("FINAL SRS SHA-256 (pin in genesis kzg.srs_hash):");
            println!("  0x{}", hex::encode(report.final_state_hash));
            println!();
            println!("Operator setup:");
            println!("  export SXIAUM_SRS_MODE=production");
            println!("  export SXIAUM_KZG_SRS_PATH={}", path.display());
            println!("Then pin the hash above as `kzg.srs_hash` in configs/mainnet.json.");
        }
        Commands::Export { path } => {
            println!(
                "Generating discarded-trapdoor SRS to {} (never {})...",
                path.display(),
                DEV_SRS_MARKER
            );
            let srs = generate_discarded_trapdoor_srs()?;
            write_srs_to_file(&srs, &path)?;
            validate_srs_is_not_dev(&path)?;
            let hash = srs_file_sha256_hex(&path)?;
            println!("Export complete");
            println!("SHA-256 (pin in genesis kzg.srs_hash): 0x{hash}");
        }
        Commands::VerifyVk { path } => {
            println!("Verifying Groth16 VK at {}", path.display());
            let path_str = path.to_str().context("invalid UTF-8 path")?;
            let v = Groth16Verifier::from_file(path_str)?;
            println!(
                "Loaded Groth16 verifier; public input size = {}",
                v.public_input_size()
            );
            // initialize global verifier if desired
            let _ = init_global_verifier_from_env();
            println!("Verification OK");
        }
        Commands::ImportPk { path } => {
            println!("Importing proving key to {}", path.display());
            let path_str = path.to_str().context("invalid UTF-8 path")?;
            // Load via Prover to ensure it deserializes
            let _p = sxiaum_zk::groth16::Groth16Prover::from_file(path_str)?;
            println!("Proving key imported (file readable)");
        }
        Commands::VerifyPk { pk, vk } => {
            println!(
                "Verifying proving key {} matches vk {}",
                pk.display(),
                vk.display()
            );
            let pk_str = pk.to_str().context("invalid UTF-8 path for pk")?;
            let vk_str = vk.to_str().context("invalid UTF-8 path for vk")?;
            let ok = sxiaum_zk::groth16::verify_proving_key_matches_vk(pk_str, vk_str)?;
            if ok {
                println!("PK and VK match");
            } else {
                anyhow::bail!("PK and VK DO NOT match");
            }
        }
        Commands::VerifySp1 { path } => {
            println!("Verifying SP1 proof at {}", path.display());
            let bytes = std::fs::read(&path)
                .with_context(|| format!("Failed to read proof file {}", path.display()))?;
            let proof: sxiaum_zk::sp1::prover::Sp1Proof = bincode::deserialize(&bytes)
                .context("Failed to deserialize canonical Sp1Proof envelope from file")?;

            let gv = sxiaum_zk::sp1::verifier::Sp1Verifier::init_global_from_env();
            let ok = gv.verify(&bytes, &proof.public_inputs)?;
            if ok {
                println!("SP1 proof verified");
            } else {
                anyhow::bail!("SP1 proof verification failed (returned false)");
            }
        }
        Commands::GenerateSimSp1 { out } => {
            println!("Generating simulated SP1 proof to {}", out.display());
            // Build a dummy program and witness with non-zero roots
            let program = b"dev-sp1-elf".to_vec();
            let prover = sxiaum_zk::sp1::prover::Sp1Prover::new(program.clone());

            let state_root_before = [1u8; 32];
            let state_root_after = [2u8; 32];
            let block_hash = [3u8; 32];
            let public_inputs = sxiaum_zk::sp1::prover::ZkPublicInputs::new(
                sxiaum_types::SXIAUM_CHAIN_ID,
                1,
                sxiaum_zk::STF_CIRCUIT_VERSION,
                [0u8; 32],
                1,
                [0u8; 32],
                state_root_before,
                state_root_after,
                block_hash,
                [0u8; 32],
                [0u8; 32],
                [0u8; 32],
            );

            let trace = sxiaum_zk::sp1::prover::Sp1ExecutionTrace {
                program: program.clone(),
                witness_input: vec![],
                execution_trace: vec![],
                public_inputs: public_inputs.encode(),
            };
            let witness = sxiaum_zk::sp1::prover::ZkBlockWitness::new(trace, public_inputs);

            let proof = prover.prove_block(&witness)?;
            let bytes = bincode::serialize(&proof)?;
            fs::write(&out, &bytes)?;
            println!("Wrote simulated SP1 proof");
        }
        Commands::ExportPk { path } => {
            println!(
                "Generating development proving key and exporting to {}",
                path.display()
            );
            let pk = sxiaum_zk::groth16::Groth16Prover::generate_proving_key()?;
            sxiaum_zk::groth16::serialize_proving_key_to_file(&pk, &path)?;
            println!("Exported proving key");
        }
        Commands::ExportVk { path } => {
            println!("Generating development proving+verifying keypair and exporting verifying key to {}", path.display());
            let pk = sxiaum_zk::groth16::Groth16Prover::generate_proving_key()?;
            // ProvingKey contains the verifying key as `.vk`
            sxiaum_zk::groth16::serialize_verifying_key_to_file(&pk.vk, &path)?;
            println!("Exported verifying key");
        }
        Commands::ImportVk { path } => {
            println!("Importing verifying key {}", path.display());
            let path_str = path.to_str().context("invalid UTF-8 path")?;
            let _v = sxiaum_zk::groth16::Groth16Verifier::from_file(path_str)?;
            println!("Verifying key imported (file readable)");
        }
        Commands::RotatePk { src, dst, vk } => {
            println!(
                "Rotating proving key from {} to {}",
                src.display(),
                dst.display()
            );
            let src_str = src.to_str().context("invalid UTF-8 path for src")?;
            let _ = sxiaum_zk::groth16::Groth16Prover::from_file(src_str)?;
            if let Some(vk) = vk {
                let vk_str = vk.to_str().context("invalid UTF-8 path for vk")?;
                let ok = sxiaum_zk::groth16::verify_proving_key_matches_vk(src_str, vk_str)?;
                if !ok {
                    anyhow::bail!("proving key does not match verifying key");
                }
            }
            verify_and_rotate_file(&src, &dst, Some(dst.with_extension("bak")))?;
            println!("Rotate complete");
        }
        Commands::RotateVk { src, dst, pk } => {
            println!(
                "Rotating verifying key from {} to {}",
                src.display(),
                dst.display()
            );
            let src_str = src.to_str().context("invalid UTF-8 path for src")?;
            let _ = sxiaum_zk::groth16::Groth16Verifier::from_file(src_str)?;
            if let Some(pk) = pk {
                let pk_str = pk.to_str().context("invalid UTF-8 path for pk")?;
                let ok = sxiaum_zk::groth16::verify_proving_key_matches_vk(pk_str, src_str)?;
                if !ok {
                    anyhow::bail!("proving key does not match verifying key");
                }
            }
            verify_and_rotate_file(&src, &dst, Some(dst.with_extension("bak")))?;
            println!("Rotate complete");
        }
        Commands::StoreKey {
            id,
            kind,
            path,
            backend,
            store_path,
            vault_url,
            vault_token,
            vault_namespace,
            vault_headers,
        } => {
            let data = fs::read(&path)?;
            let entry = KeyEntry {
                id: id.clone(),
                kind,
                data,
            };
            match backend.as_str() {
                "fs" => {
                    let dir = store_path.unwrap_or_else(|| PathBuf::from("./keystore"));
                    let store = FsKeyStore::new(dir);
                    store.put(entry).await?;
                }
                "vault" => {
                    let url = vault_url.unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
                    let token = vault_token.unwrap_or_default();
                    let store = apply_vault_headers(
                        VaultKeyStore::new(url, token)?,
                        vault_namespace,
                        &vault_headers,
                    )?;
                    store.put(entry).await?;
                }
                other => anyhow::bail!("unsupported backend: {}", other),
            }
            println!("Stored key {}", id);
        }
        Commands::FetchKey {
            id,
            out,
            backend,
            store_path,
            vault_url,
            vault_token,
            vault_namespace,
            vault_headers,
        } => {
            let entry = match backend.as_str() {
                "fs" => {
                    let dir = store_path.unwrap_or_else(|| PathBuf::from("./keystore"));
                    let store = FsKeyStore::new(dir);
                    store.get(&id).await?
                }
                "vault" => {
                    let url = vault_url.unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
                    let token = vault_token.unwrap_or_default();
                    let store = apply_vault_headers(
                        VaultKeyStore::new(url, token)?,
                        vault_namespace,
                        &vault_headers,
                    )?;
                    store.get(&id).await?
                }
                other => anyhow::bail!("unsupported backend: {}", other),
            };
            let entry = entry.ok_or_else(|| anyhow::anyhow!("key not found: {}", id))?;
            fs::write(out, &entry.data)?;
            println!("Fetched key {}", id);
        }
        Commands::DeleteKey {
            id,
            backend,
            store_path,
            vault_url,
            vault_token,
            vault_namespace,
            vault_headers,
        } => {
            match backend.as_str() {
                "fs" => {
                    let dir = store_path.unwrap_or_else(|| PathBuf::from("./keystore"));
                    let store = FsKeyStore::new(dir);
                    store.delete(&id).await?;
                }
                "vault" => {
                    let url = vault_url.unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
                    let token = vault_token.unwrap_or_default();
                    let store = apply_vault_headers(
                        VaultKeyStore::new(url, token)?,
                        vault_namespace,
                        &vault_headers,
                    )?;
                    store.delete(&id).await?;
                }
                other => anyhow::bail!("unsupported backend: {}", other),
            }
            println!("Deleted key {}", id);
        }
        Commands::Verify { path } => {
            println!("Verifying SRS at {}", path.display());

            // Check file size meets minimum for a real ceremony SRS.
            let meta = std::fs::metadata(&path)
                .with_context(|| format!("cannot stat SRS file: {}", path.display()))?;
            if meta.len() < sxiaum_crypto::kzg::MIN_PRODUCTION_SRS_BYTES {
                anyhow::bail!(
                    "SRS file is only {} bytes — too small for a ceremony SRS (minimum {} bytes)",
                    meta.len(),
                    sxiaum_crypto::kzg::MIN_PRODUCTION_SRS_BYTES
                );
            }

            validate_srs_is_not_dev(&path)?;
            let srs = load_srs_from_file(&path)?;
            if srs.is_dev_trapdoor() {
                anyhow::bail!(
                    "{} trapdoor fingerprint detected after load",
                    DEV_SRS_MARKER
                );
            }
            let hash = srs_file_sha256_hex(&path)?;
            println!("Loaded SRS: g1 powers = {} entries", srs.g1_powers.len());
            println!("SHA-256: 0x{hash}");
            println!("Verification OK (not {})", DEV_SRS_MARKER);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_value() {
        assert_eq!(
            parse_key_value("foo=bar").unwrap(),
            ("foo".to_string(), "bar".to_string())
        );
        assert_eq!(
            parse_key_value("X-Vault-Namespace=sxiaum").unwrap(),
            ("X-Vault-Namespace".to_string(), "sxiaum".to_string())
        );
        assert!(parse_key_value("invalid").is_err());
        assert!(parse_key_value("=value").is_err());
        assert!(parse_key_value("key=").is_err());
    }

    #[test]
    fn test_discarded_trapdoor_srs_generation() {
        let srs = generate_discarded_trapdoor_srs().expect("Failed to generate SRS");
        assert!(!srs.is_dev_trapdoor());
        assert!(!srs.g1_powers.is_empty());
    }

    #[test]
    fn test_verify_and_rotate_file() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("sxiaum-srs-test-{}", timestamp));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let src = temp_dir.join("source.key");
        let dst = temp_dir.join("dest.key");
        let bak = temp_dir.join("dest.bak");

        std::fs::write(&src, b"new-key-material").unwrap();
        std::fs::write(&dst, b"old-key-material").unwrap();

        verify_and_rotate_file(&src, &dst, Some(bak.clone())).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), b"new-key-material");
        assert_eq!(std::fs::read(&bak).unwrap(), b"old-key-material");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
