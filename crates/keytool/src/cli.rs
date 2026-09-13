//! Clap CLI definitions, arguments, subcommands, and flags.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "keytool",
    author = "SXIAUM Core Engineering Team",
    version,
    about = "SXIAUM Production Key Management & Validator Tool",
    long_about = "Mission-critical CLI for generating, encrypting, inspecting, signing, and converting SXIAUM validator keys, consensus BLS keys, and account keys."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeyType {
    /// Ed25519 account signing and validator proposer key (default)
    Ed25519,
    /// BLS12-381 consensus voting, aggregation, and threshold signing key
    Bls,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum KeystoreFormat {
    /// Native SXIAUM v2 format (Argon2id + AES-256-GCM authenticated)
    Native,
    /// EIP-2335 v4 standard format (Ethereum consensus validator standard)
    Eip2335,
    /// Web3 Secret Storage v3 format (Ethereum execution account standard)
    Web3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum WordCount {
    /// 12 words (128 bits entropy)
    #[value(name = "12")]
    Words12,
    /// 18 words (192 bits entropy)
    #[value(name = "18")]
    Words18,
    /// 24 words (256 bits entropy)
    #[value(name = "24")]
    Words24,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a new validator or account keypair.
    Generate {
        /// Output path for the generated keypair JSON file.
        #[arg(short, long, default_value = "validator_key.json")]
        out: PathBuf,

        /// Key type to generate (ed25519 or bls).
        #[arg(long = "key-type", value_enum, default_value_t = KeyType::Ed25519)]
        key_type: KeyType,

        /// Keystore storage format.
        #[arg(long = "format", value_enum, default_value_t = KeystoreFormat::Native)]
        format: KeystoreFormat,

        /// Path to password file (avoids interactive prompt).
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,

        /// Export the raw private key in plaintext (DANGEROUS).
        #[arg(long = "unsafe-export", default_value_t = false)]
        unsafe_export: bool,

        /// Allow plaintext export even when SXIAUM_ENV=production.
        #[arg(long = "allow-insecure-production-plaintext", default_value_t = false)]
        allow_insecure_production_plaintext: bool,

        /// Automatically confirm security prompts without interactive input.
        #[arg(short = 'y', long = "yes", default_value_t = false)]
        yes: bool,
    },

    /// Batch-generate multiple sequential validator keys for enterprise staking.
    GenerateBatch {
        /// Directory where generated key files will be stored.
        #[arg(short, long, default_value = "validator_keys")]
        out_dir: PathBuf,

        /// Number of keypairs to generate.
        #[arg(short, long, default_value_t = 1)]
        count: usize,

        /// Key type to generate (ed25519 or bls).
        #[arg(long = "key-type", value_enum, default_value_t = KeyType::Bls)]
        key_type: KeyType,

        /// Keystore storage format.
        #[arg(long = "format", value_enum, default_value_t = KeystoreFormat::Eip2335)]
        format: KeystoreFormat,

        /// Password file used to encrypt all generated keystores.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,

        /// Automatically confirm prompts.
        #[arg(short = 'y', long = "yes", default_value_t = false)]
        yes: bool,
    },

    /// BIP-39 mnemonic phrase operations (generate & derive keys).
    Mnemonic {
        #[command(subcommand)]
        subcommand: MnemonicCommands,
    },

    /// Generate an on-chain validator staking deposit registration payload (BLS key + PoP).
    ValidatorDeposit {
        /// Output path for the deposit payload JSON.
        #[arg(short, long, default_value = "deposit_data.json")]
        out: PathBuf,

        /// Output path for the encrypted validator keystore.
        #[arg(long = "keystore-out", default_value = "validator_keystore.json")]
        keystore_out: PathBuf,

        /// SXIAUM withdrawal address (receives staking rewards and principal).
        #[arg(long = "withdrawal-address")]
        withdrawal_address: String,

        /// Staking deposit amount in SXIAUM.
        #[arg(long = "amount", default_value = "32.0")]
        amount: String,

        /// Password file for keystore encryption.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,

        /// Automatically confirm prompts.
        #[arg(short = 'y', long = "yes", default_value_t = false)]
        yes: bool,
    },

    /// BLS12-381 Proof-of-Possession (PoP) generation and verification.
    Pop {
        #[command(subcommand)]
        subcommand: PopCommands,
    },

    /// Sign an arbitrary message using a key file.
    Sign {
        /// Path to the keypair file.
        #[arg(short, long)]
        file: PathBuf,

        /// Message string to sign.
        #[arg(short, long)]
        message: String,

        /// Treat message string as hex-encoded bytes.
        #[arg(long = "hex", default_value_t = false)]
        hex_message: bool,

        /// Password file for decryption.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
    },

    /// Verify a signature against a public key and message.
    Verify {
        /// Public key in hex.
        #[arg(short, long)]
        public_key: String,

        /// Message string that was signed.
        #[arg(short, long)]
        message: String,

        /// Treat message string as hex-encoded bytes.
        #[arg(long = "hex", default_value_t = false)]
        hex_message: bool,

        /// Signature in hex.
        #[arg(short, long)]
        signature: String,

        /// Key type (ed25519 or bls).
        #[arg(long = "key-type", value_enum, default_value_t = KeyType::Ed25519)]
        key_type: KeyType,
    },

    /// Inspect an existing keypair or keystore file.
    Inspect {
        /// Path to the keypair file.
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Derive and display the SXIAUM address from a public key or keypair file.
    DeriveAddress {
        /// Hex-encoded 32-byte Ed25519 public key.
        #[arg(short, long)]
        public_key: Option<String>,

        /// Path to a keypair JSON file.
        #[arg(short, long)]
        file: Option<PathBuf>,
    },

    /// Export the raw private key in hex from an encrypted key file.
    #[command(name = "export-private-key")]
    ExportPrivateKey {
        /// Path to the encrypted key file.
        #[arg(short, long)]
        file: PathBuf,

        /// Password file for decryption.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,

        /// Acknowledge that exporting a raw private key is dangerous.
        #[arg(long = "unsafe-export", required = true)]
        unsafe_export: bool,

        /// Allow export in production.
        #[arg(long = "allow-insecure-production-plaintext", default_value_t = false)]
        allow_insecure_production_plaintext: bool,

        /// Automatically confirm security prompts.
        #[arg(short = 'y', long = "yes", default_value_t = false)]
        yes: bool,
    },

    /// Re-encrypt a key file with a new passphrase.
    ChangePassword {
        /// Path to the key file.
        #[arg(short, long)]
        file: PathBuf,

        /// Old password file.
        #[arg(long = "old-password-file")]
        old_password_file: Option<PathBuf>,

        /// New password file.
        #[arg(long = "new-password-file")]
        new_password_file: Option<PathBuf>,
    },

    /// Import a key file directly into an FsKeyStore directory.
    ImportKeystore {
        /// Path to the key file.
        #[arg(short, long)]
        file: PathBuf,

        /// Destination keystore directory.
        #[arg(short = 'k', long)]
        keystore_dir: PathBuf,

        /// Key ID to register in the keystore.
        #[arg(short = 'i', long = "key-id")]
        key_id: String,

        /// Password file for current key decryption.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,

        /// Destination keystore password file.
        #[arg(long = "dest-password-file")]
        dest_password_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum MnemonicCommands {
    /// Generate a new random BIP-39 recovery mnemonic phrase.
    Generate {
        /// Number of words in the mnemonic (12, 18, or 24).
        #[arg(long = "words", value_enum, default_value_t = WordCount::Words24)]
        words: WordCount,
    },

    /// Derive an account or validator key from a BIP-39 mnemonic phrase.
    Derive {
        /// The BIP-39 mnemonic phrase (space-separated words).
        #[arg(short, long)]
        phrase: String,

        /// Optional mnemonic passphrase (salt).
        #[arg(long = "passphrase", default_value = "")]
        passphrase: String,

        /// Key type to derive (ed25519 or bls).
        #[arg(long = "key-type", value_enum, default_value_t = KeyType::Ed25519)]
        key_type: KeyType,

        /// Output path for the derived key JSON.
        #[arg(short, long, default_value = "derived_key.json")]
        out: PathBuf,

        /// Keystore storage format.
        #[arg(long = "format", value_enum, default_value_t = KeystoreFormat::Native)]
        format: KeystoreFormat,

        /// Password file for keystore encryption.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,

        /// Export private key in plaintext.
        #[arg(long = "unsafe-export", default_value_t = false)]
        unsafe_export: bool,

        /// Automatically confirm security prompts.
        #[arg(short = 'y', long = "yes", default_value_t = false)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PopCommands {
    /// Generate an RFC 9380 Proof-of-Possession for a BLS validator key.
    Generate {
        /// Path to the BLS key file.
        #[arg(short, long)]
        file: PathBuf,

        /// Password file for decrypting the key.
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
    },

    /// Verify an RFC 9380 Proof-of-Possession signature against a BLS public key.
    Verify {
        /// BLS public key in hex.
        #[arg(short = 'k', long)]
        public_key: String,

        /// Proof-of-Possession signature in hex.
        #[arg(short = 'o', long)]
        pop: String,
    },
}
