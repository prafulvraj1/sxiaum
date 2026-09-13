//! P2P networking layer for the SXIAUM blockchain.
//!
//! This crate provides:
//! - libp2p-based gossipsub messaging (blocks, transactions, votes, QCs)
//! - Request-response RPC for chain synchronization and state proofs
//! - Peer discovery via Kademlia DHT and mDNS (dev only)
//! - Peer reputation system with automatic banning
//! - Rate limiting for RPC requests (per-peer sliding windows)
//! - IP prefix limits to prevent Sybil attacks
//! - Bloom filter for duplicate message suppression
//! - Persistent ban storage via redb
//!
//! # Mainnet Readiness
//!
//! The networking layer enforces:
//! - mDNS discovery disabled in production (`SXIAUM_ENV=production`)
//! - Peer banning with 7-day TTL for malicious peers
//! - IP prefix limits (max 16 peers per /24 subnet)
//! - RPC message size limits (16 MB max)
//! - RPC request timeouts (10 seconds)
//! - Per-peer rate limiting for header and state proof requests
//! - Gossip message validation (signatures, structure, duplicates)
//! - Chain ID validation on received block headers (replay protection)

pub mod chain_sync;
pub mod error;
pub mod gossip;
pub mod metrics;
pub mod p2p;
pub mod peer;
pub mod rpc;

pub use crate::error::NetworkingError;

pub use crate::chain_sync::{
    BlockExecutor, BlockFetcher, BlockRequest, BlockResponse, ChainStore, ChainSyncConfig,
    ChainSyncEngine, ChainSyncResult, ConsensusSignatureVerifier,
};
pub use crate::gossip::{
    AddressBoundBlockVerifier, AddressBoundTransactionVerifier, BlockConsensusSink,
    BlockGossipOutcome, BlockParentLookup, BlockPoolSink, BlockProofVerifier,
    BlockQuorumCertificateVerifier, BlockSignatureVerifier, BlockValidatorSetVerifier,
    CommitGossipOutcome, CommitPoolSink, Gossip, GossipMessage, HeaderBoundBlockProofVerifier,
    QuorumCertificateBroadcaster, QuorumCertificateConsensusSink, QuorumCertificateGossipOutcome,
    QuorumCertificateVerifier, RevealGossipOutcome, RevealPoolSink, TransactionGossipOutcome,
    TransactionPoolSink, TransactionSignatureVerifier, VoteConsensusSink, VoteGossipOutcome,
    VoteSignatureVerifier,
};
pub use crate::metrics::NetworkingMetrics;
pub use crate::p2p::{
    ChainSyncOutcome, ChainSyncState, P2PConfig, P2PNetwork, RpcRequestHandler, RpcSyncClient,
};
pub use crate::peer::{Peer, PeerStore};
pub use crate::rpc::{
    L1Codec, L1Request, L1Response, RpcStateProofQuery, RpcStateProofRequest,
    RpcStateProofResponse, RpcStateProofValue, RpcVerifiedHeaderEnvelope,
};

// ---------------------------------------------------------------------------
// Mainnet networking constants
// ---------------------------------------------------------------------------

/// Maximum number of peers connected to this node.
pub const MAX_PEERS: usize = 50;

/// Maximum number of peers allowed per IP subnet (/24 for IPv4, /64 for IPv6).
/// Prevents Sybil attacks from a single IP range.
pub const MAX_PEERS_PER_SUBNET: usize = 16;

/// Reputation threshold below which a peer is automatically banned.
pub const BANNED_REPUTATION_THRESHOLD: i32 = -100;

/// Ban duration in seconds (7 days).
pub const BAN_DURATION_SECS: u64 = 7 * 24 * 60 * 60;

/// Maximum RPC message size (16 MB).
pub const MAX_RPC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Default RPC timeout (10 seconds).
pub const DEFAULT_RPC_TIMEOUT_SECS: u64 = 10;

/// Maximum header batch size per RPC request (128 headers).
pub const MAX_HEADER_BATCH_SIZE: u64 = 128;

/// Maximum header requests per peer per rate-limit window.
pub const MAX_HEADER_REQUESTS_PER_WINDOW: usize = 32;

/// Rate-limit window for header requests (1 second).
pub const HEADER_REQUEST_WINDOW_SECS: u64 = 1;

/// Maximum state proof requests per peer per rate-limit window.
pub const MAX_STATE_PROOF_REQUESTS_PER_WINDOW: usize = 32;

/// Rate-limit window for state proof requests (1 second).
pub const STATE_PROOF_REQUEST_WINDOW_SECS: u64 = 1;

/// Maximum block / block proof requests per peer per rate-limit window.
pub const MAX_BLOCK_REQUESTS_PER_WINDOW: usize = 64;

/// Rate-limit window for block / block proof requests (1 second).
pub const BLOCK_REQUEST_WINDOW_SECS: u64 = 1;

/// Maximum transaction queries per peer per rate-limit window.
pub const MAX_TRANSACTION_REQUESTS_PER_WINDOW: usize = 128;

/// Rate-limit window for transaction queries (1 second).
pub const TRANSACTION_REQUEST_WINDOW_SECS: u64 = 1;

/// Bloom filter capacity for duplicate message detection (100,000 entries).
pub const BLOOM_FILTER_CAPACITY: usize = 100_000;

/// Number of hash functions in the bloom filter.
pub const BLOOM_FILTER_HASH_FUNCTIONS: usize = 3;

/// RPC response poll interval in milliseconds.
pub const RPC_RESPONSE_POLL_SLICE_MS: u64 = 25;
