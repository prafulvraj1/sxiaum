use std::sync::Arc;
use sxiaum_consensus::Consensus;
use sxiaum_execution::Executor;
use sxiaum_mempool::Mempool;
use sxiaum_networking::P2PNetwork;
use sxiaum_state::StateDB;
use sxiaum_storage::StorageEngine;
use tokio::sync::{broadcast, Mutex, RwLock};

/// Global context shared across all JSON-RPC handlers, providing thread-safe
/// access to the core node components.
///
/// Fields are intentionally public and accessed directly (`context.storage`,
/// `context.mempool`, ...). The former accessor methods (`storage()`,
/// `mempool()`, ...) were redundant aliases that handlers used
/// interchangeably with field access — two spellings for every component with
/// zero behavioral difference. One canonical form removes the drift surface.
pub struct RpcContext {
    /// Thread-safe reference to the P2P Networking layer.
    pub networking: Arc<Mutex<P2PNetwork>>,
    /// Thread-safe reference to the Mempool.
    pub mempool: Arc<Mempool>,
    /// Thread-safe, mutable access to Consensus state.
    pub consensus: Arc<RwLock<Consensus>>,
    /// Thread-safe reference to the State Database (Verkle Tree).
    pub state: Arc<StateDB>,
    /// Thread-safe reference to the permanent storage backend.
    pub storage: Arc<StorageEngine>,
    /// Execution engine - used for gas estimation and dry-runs.
    pub executor: Arc<Executor>,
    /// Broadcaster for WebSocket subscriptions. (topic, data)
    pub ws_broadcaster: broadcast::Sender<(String, serde_json::Value)>,
    /// Single shared JWT Manager.
    pub jwt_manager: Arc<crate::jwt::JwtManager>,
}

impl RpcContext {
    pub fn new(
        networking: Arc<Mutex<P2PNetwork>>,
        mempool: Arc<Mempool>,
        consensus: Arc<RwLock<Consensus>>,
        state: Arc<StateDB>,
        storage: Arc<StorageEngine>,
        executor: Arc<Executor>,
        jwt_manager: Arc<crate::jwt::JwtManager>,
    ) -> Self {
        let (ws_broadcaster, _) = broadcast::channel(crate::WS_BROADCAST_CAPACITY);
        Self {
            networking,
            mempool,
            consensus,
            state,
            storage,
            executor,
            ws_broadcaster,
            jwt_manager,
        }
    }
}
