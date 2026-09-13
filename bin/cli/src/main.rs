use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod commands;
mod keystore;
#[cfg(test)]
mod keystore_tests;
mod ui;
mod units;
mod utils;

use commands::{account, node, query, transaction, wallet};

#[derive(Parser)]
#[command(name = "sxiaum-cli")]
#[command(about = "SXIAUM L1 CLI - Manage encrypted wallets, send SXI, query chain state")]
#[command(version = "0.4.0")]
struct Cli {
    /// URL of the SXIAUM RPC node
    #[arg(
        short,
        long,
        global = true,
        default_value = "http://127.0.0.1:8080/rpc"
    )]
    rpc_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// - Account generation and key management
    Account {
        #[command(subcommand)]
        action: AccountCommands,
    },

    /// - Send and inspect transactions
    Transaction {
        #[command(subcommand)]
        action: TransactionCommands,
    },

    /// -  Node control and status
    Node {
        #[command(subcommand)]
        action: NodeCommands,
    },

    /// - Query on-chain state (balance, blocks, nonce)
    Query {
        #[command(subcommand)]
        action: QueryCommands,
    },

    /// - Encrypted wallet & address book management
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },
}

// - Account subcommands -

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Generate new Ed25519 keypair(s)
    Generate {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long, default_value = "1")]
        count: usize,
        /// Password file for keystore encryption (avoids the interactive
        /// prompt; required in non-interactive environments).
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
    },
    /// Derive an address from a private key
    Derive {
        #[arg(help = "Private key (0x-prefixed 32-byte hex)")]
        private_key: String,
    },
    /// List pre-funded devnet genesis accounts
    ListDevnet,
    /// Import an account from a private key file
    Import {
        #[arg(help = "Private key (0x-prefixed hex)")]
        private_key: String,
        #[arg(short, long, help = "Save to JSON file")]
        output: Option<PathBuf>,
    },
    /// Show account details
    Show {
        #[arg(help = "Account address (0x-prefixed)")]
        address: String,
    },
}

// - Transaction subcommands -

#[derive(Subcommand)]
pub enum TransactionCommands {
    /// Sign and broadcast a transfer
    Send {
        #[arg(
            long,
            default_value = "",
            help = "Sender address (auto-derived if omitted)"
        )]
        from: String,

        /// Recipient address (0x-prefixed) or address-book label
        #[arg(long, help = "Recipient address or address-book label")]
        to: String,

        /// Amount - plain aSXI integer  OR  SXI notation (e.g. 1.5SX)
        #[arg(long, help = "Amount: plain aSXI integer or SXI notation (e.g. 2.5SX)")]
        value: String,

        #[arg(long, help = "Encrypted wallet alias to sign with")]
        wallet: Option<String>,

        #[arg(long, default_value = "0", help = "Transaction nonce")]
        nonce: u64,

        #[arg(long, default_value = "210", help = "Gas limit")]
        gas: u64,

        /// Skip the interactive confirmation prompt (use in scripts)
        #[arg(long, short = 'y', help = "Skip confirmation prompt")]
        yes: bool,
    },

    /// Poll and display the status of a submitted transaction
    Status {
        #[arg(help = "Transaction hash (0x-prefixed)")]
        hash: String,
        #[arg(short, long, default_value = "1")]
        poll_interval: u64,
        #[arg(long, default_value = "20")]
        poll_max: u32,
    },

    /// List pending transactions in the mempool
    Pending {
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
}

// - Node subcommands -

#[derive(Subcommand)]
pub enum NodeCommands {
    Start {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(short, long)]
        log_level: Option<String>,
    },
    Status,
    Peers,
}

// - Query subcommands -

#[derive(Subcommand)]
pub enum QueryCommands {
    /// Get the SXI balance of an address
    Balance {
        #[arg(help = "Address (0x-prefixed)")]
        address: String,
    },
    /// Get the transaction nonce of an address
    Nonce {
        #[arg(help = "Address (0x-prefixed)")]
        address: String,
    },
    /// Get block details by height
    Block {
        #[arg(help = "Block height")]
        height: u64,
    },
    /// Get the current Verkle state root
    StateRoot,
}

// - Wallet subcommands -

#[derive(Subcommand)]
pub enum WalletCommands {
    /// Create a new AES-256-GCM encrypted wallet (first-time setup)
    Init,

    /// Import a private key (encrypted with your wallet password)
    Import {
        #[arg(help = "Alias name (e.g. 'validator1')")]
        alias: String,
        #[arg(help = "Private key (0x-prefixed 32-byte hex)")]
        private_key: String,
    },

    /// Export a private key (encrypted file by default; stdout only with explicit flags)
    Export {
        #[arg(help = "Alias to export")]
        alias: String,
        /// Write an encrypted keystore JSON instead of printing plaintext
        #[arg(long, value_name = "PATH")]
        output: Option<std::path::PathBuf>,
        /// Required to print the raw private key to stdout (dangerous)
        #[arg(long = "i-understand-plaintext")]
        allow_plaintext: bool,
    },

    /// Delete a key alias from the wallet (requires password)
    Remove {
        #[arg(help = "Alias to delete")]
        alias: String,
    },

    /// List all aliases (requires password)
    List,

    /// Change the wallet encryption password
    ChangePassword,

    /// Show on-chain SXI balances for all wallet aliases (requires password)
    Balance,

    /// Show wallet metadata (encryption details, path)
    Info,

    /// Address book management
    Addr {
        #[command(subcommand)]
        action: AddrCommands,
    },
}

#[derive(Subcommand)]
pub enum AddrCommands {
    /// Add a labelled address to the address book
    Add {
        #[arg(help = "Label (e.g. 'treasury')")]
        label: String,
        #[arg(help = "Address (0x-prefixed 32-byte hex)")]
        address: String,
    },
    /// Remove a label from the address book
    Remove {
        #[arg(help = "Label to remove")]
        label: String,
    },
    /// List all address book entries
    List,
}

// - Main -

#[tokio::main]
async fn main() -> Result<()> {
    ui::print_banner();

    let cli = Cli::parse();

    match cli.command {
        Commands::Account { action } => account::handle_account_command(action).await?,

        Commands::Transaction { action } => {
            transaction::handle_transaction_command(&cli.rpc_url, action).await?
        }

        Commands::Node { action } => node::handle_node_command(action).await?,

        Commands::Query { action } => {
            let client = reqwest::Client::new();
            match action {
                QueryCommands::Balance { address } => {
                    query::query_balance(&client, &cli.rpc_url, &address).await?;
                }
                QueryCommands::Nonce { address } => {
                    query::query_nonce(&client, &cli.rpc_url, &address).await?;
                }
                QueryCommands::Block { height } => {
                    query::query_block(&client, &cli.rpc_url, height).await?;
                }
                QueryCommands::StateRoot => {
                    query::query_state_root(&client, &cli.rpc_url).await?;
                }
            }
        }

        Commands::Wallet { action } => match action {
            WalletCommands::Init => {
                wallet::init_wallet()?;
            }
            WalletCommands::Import { alias, private_key } => {
                wallet::import_key(&alias, &private_key)?;
            }
            WalletCommands::Export {
                alias,
                output,
                allow_plaintext,
            } => {
                wallet::export_key(&alias, output.as_deref(), allow_plaintext)?;
            }
            WalletCommands::Remove { alias } => {
                wallet::remove_key(&alias)?;
            }
            WalletCommands::List => {
                wallet::list_keys()?;
            }
            WalletCommands::ChangePassword => {
                wallet::change_password()?;
            }
            WalletCommands::Balance => {
                wallet::show_all_balances(&cli.rpc_url).await?;
            }
            WalletCommands::Info => {
                wallet::wallet_info()?;
            }
            WalletCommands::Addr { action } => match action {
                AddrCommands::Add { label, address } => {
                    wallet::addr_add(&label, &address)?;
                }
                AddrCommands::Remove { label } => {
                    wallet::addr_remove(&label)?;
                }
                AddrCommands::List => {
                    wallet::addr_list()?;
                }
            },
        },
    }

    Ok(())
}
