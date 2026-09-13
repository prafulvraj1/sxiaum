//! Test-only construction of a fully wired [`RpcContext`].
//!
//! Builds real component instances against ephemeral storage (no network
//! listeners are opened; the P2P swarm is constructed inert). A single shared
//! context is created lazily and reused by every test in the binary to keep
//! socket/thread usage bounded.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sxiaum_consensus::Consensus;
use sxiaum_execution::{EvmConfig, Executor};
use sxiaum_mempool::Mempool;
use sxiaum_networking::P2PNetwork;
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use tokio::sync::{Mutex, RwLock};

use crate::context::RpcContext;

/// Builds (once) and returns the shared test [`RpcContext`].
pub(crate) async fn test_context() -> Arc<RpcContext> {
    static CONTEXT: tokio::sync::OnceCell<Arc<crate::context::RpcContext>> =
        tokio::sync::OnceCell::const_new();
    CONTEXT.get_or_init(build_context).await.clone()
}

async fn build_context() -> Arc<crate::context::RpcContext> {
    // Persistent temp storage; intentionally leaked so the backing files
    // outlive every test in the process.
    let db_dir: &'static tempfile::TempDir =
        Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
    let mut db_path: PathBuf = db_dir.path().to_path_buf();
    db_path.push("rpc-test-db");

    let storage = Arc::new(StorageEngine::new(&db_path).expect("storage engine"));
    let state = Arc::new(StateDB::new(storage.clone()));
    let mempool = Arc::new(Mempool::new(Default::default(), state.clone()));
    let consensus = Arc::new(RwLock::new(Consensus::with_storage(storage.clone())));
    let executor = Arc::new(Executor::new(
        state.clone(),
        EvmConfig::new(sxiaum_types::SXIAUM_CHAIN_ID),
    ));

    // Constructing the P2P stack with mDNS disabled avoids opening discovery
    // sockets on developer machines / CI runners.
    let previous_env = std::env::var("SXIAUM_ENV").ok();
    std::env::set_var("SXIAUM_ENV", "production");
    let networking_result = P2PNetwork::new(sxiaum_networking::P2PConfig {
        local_key: libp2p::identity::Keypair::generate_ed25519(),
        bootstrap_peers: Vec::new(),
        discovery_interval: Duration::from_secs(3600),
        discovery_backoff: Duration::from_secs(3600),
        max_peers: 8,
        max_header_batch: 16,
        max_header_requests_per_peer_per_window: 64,
        header_request_window_secs: 10,
        max_state_proof_requests_per_peer_per_window: 64,
        state_proof_request_window_secs: 10,
        db: None,
    })
    .await;
    match previous_env {
        Some(v) => std::env::set_var("SXIAUM_ENV", v),
        None => std::env::remove_var("SXIAUM_ENV"),
    }
    let networking = Arc::new(Mutex::new(
        networking_result.expect("inert p2p network for tests"),
    ));

    let jwt_manager = Arc::new(crate::jwt::JwtManager::new(None));

    Arc::new(crate::context::RpcContext::new(
        networking,
        mempool,
        consensus,
        state,
        storage,
        executor,
        jwt_manager,
    ))
}
