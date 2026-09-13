//! Operator utility: build and sign a native SXIAUM transfer transaction and
//! print it as JSON ready for `sxiaum_sendTransaction`.
//!
//! Usage:
//!   cargo run -p sxiaum-cli --example sign_tx -- \
//!     --private-key 0x0101...01 --to 0xADDR --value-asx 1000000000000000000 \
//!     [--nonce 0] [--gas-limit 210000] [--gas-price 1] [--data-hex 0x...]

use clap::Parser;
use ed25519_dalek::SigningKey;
use std::str::FromStr;
use sxiaum_types::{Address, Transaction};

#[derive(Parser)]
struct Args {
    /// Sender private key (0x-prefixed 32-byte hex).
    #[arg(long)]
    private_key: String,
    /// Recipient address (0x-prefixed).
    #[arg(long)]
    to: String,
    /// Amount in aSXI (decimal).
    #[arg(long)]
    value_asx: String,
    #[arg(long, default_value_t = 0)]
    nonce: u64,
    #[arg(long, default_value_t = 210)]
    gas_limit: u64,
    #[arg(long, default_value_t = 1)]
    gas_price: u128,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let key_hex = args.private_key.trim().trim_start_matches("0x");
    let mut seed = [0u8; 32];
    hex::decode_to_slice(key_hex, &mut seed)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();
    let from = Address::from_public_key(&pubkey);

    let to = Address::from_str(args.to.trim())?;
    let value = primitive_types::U256::from_dec_str(args.value_asx.trim())?;

    let mut tx = Transaction::new_transfer(from, to, value, args.nonce);
    tx.gas_limit = args.gas_limit;
    tx.gas_price = primitive_types::U256::from(args.gas_price);
    tx.sign(&signing_key)?;

    tx.verify_signature()?;
    let hash = tx.try_hash()?;

    println!("{}", serde_json::to_string(&tx)?);
    eprintln!("TX_HASH=0x{}", hex::encode(hash));
    Ok(())
}
