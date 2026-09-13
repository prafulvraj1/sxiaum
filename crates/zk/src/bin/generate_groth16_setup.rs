use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use std::env;
use std::fs::File;
use sxiaum_zk::groth16::Groth16Prover;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let path = if args.len() > 1 {
        args[1].clone()
    } else {
        "groth16_pk.bin".to_string()
    };

    println!("Starting Groth16 trusted setup for ExecutionCircuit...");
    let proving_key = Groth16Prover::generate_trusted_setup_parameters()?;

    println!("Saving proving key to {}...", path);
    let mut f = File::create(&path)?;
    proving_key.serialize_compressed(&mut f)?;

    println!("Successfully generated Groth16 proving key.");
    Ok(())
}
