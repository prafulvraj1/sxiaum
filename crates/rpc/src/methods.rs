//! Single source of truth for JSON-RPC method classification.
//!
//! Every supported method is registered exactly once here. Both the
//! authentication middleware (`is_public_read` / `is_public_write`) and the
//! request dispatcher ([`dispatch_category`]) derive their decisions from this
//! table, which makes it impossible for a method to be publicly callable but
//! unimplemented, or implementable but unreachable due to routing drift.
//!
//! Security policy (default-deny):
//! - Methods listed in [`PUBLIC_READ_METHODS`] never require authentication.
//! - Methods listed in [`PUBLIC_WRITE_METHODS`] require authentication only
//!   when `SXIAUM_RPC_WRITE_AUTH` is enabled (public write-auth enforcement).
//! - Everything else (admin_*, debug_*, unknown methods) ALWAYS requires a
//!   valid bearer token / JWT.

/// Dispatch category for a JSON-RPC method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MethodCategory {
    /// Block queries (`sxiaum_getBlock*`, `eth_getBlock*`, ...).
    Blocks,
    /// Transaction submission, lookup, gas estimation and MEV commit/reveal.
    Transactions,
    /// Account/state queries, contract calls and log filters.
    State,
    /// Node, network, consensus and health information.
    Network,
}

use std::collections::HashSet;
use std::sync::LazyLock;

fn set<const N: usize>(items: [&'static str; N]) -> HashSet<&'static str> {
    items.into_iter().collect()
}

/// Methods that never require authentication (safe public reads).
pub static PUBLIC_READ_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    set([
        // --- Chain / node metadata ---
        "eth_chainId",
        "eth_networkId",
        "net_version",
        "net_listening",
        "net_peerCount",
        "web3_clientVersion",
        "web3_sha3",
        "eth_accounts",
        "eth_coinbase",
        "eth_mining",
        "eth_hashrate",
        "eth_gasPrice",
        "eth_syncing",
        "sxiaum_nodeVersion",
        "sxiaum_health",
        "sxiaum_peerCount",
        "sxiaum_syncing",
        // SECURITY: `sxiaum_getPeers` / `sxiaum_getNetworkInfo` deliberately
        // absent from the public allowlist — exposing the peer table and local
        // listener addresses to anonymous callers enables topology
        // reconnaissance for eclipse attacks. They remain available to
        // authenticated operators via default-deny fallthrough.
        // --- Consensus ---
        "sxiaum_getValidatorSet",
        "sxiaum_getConsensusState",
        // --- Blocks ---
        "eth_blockNumber",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getBlockReceipts",
        "sxiaum_latestBlock",
        "sxiaum_getBlockByNumber",
        "sxiaum_getBlockByHash",
        "sxiaum_getBlockHeader",
        "sxiaum_getBlockTransactions",
        "sxiaum_getBlockReceipts",
        // --- Transactions ---
        "eth_getTransactionByHash",
        "eth_getTransactionReceipt",
        "eth_estimateGas",
        "sxiaum_getTransactionByHash",
        "sxiaum_getTransactionReceipt",
        "sxiaum_getCommitStatus",
        "sxiaum_getMevPoolStats",
        // SECURITY (H-07): `sxiaum_getPendingTransactions` removed from the
        // public read allowlist. Unauthenticated access let anyone dump pending
        // queue metadata, a direct MEV / front-running reconnaissance surface.
        // The method now falls through to default-deny.
        // --- State ---
        "eth_getBalance",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getTransactionCount",
        "eth_call",
        "eth_getLogs",
        "eth_feeHistory",
        "sxiaum_getBalance",
        "sxiaum_getNonce",
        "sxiaum_getAccount",
        "sxiaum_getStorageAt",
        "sxiaum_getProof",
        "sxiaum_getStorageProof",
        "sxiaum_getMinimalProof",
        "sxiaum_getCode",
        "sxiaum_getStateRoot",
    ])
});

/// Write methods (transaction submission, MEV commit/reveal).
///
/// SECURITY (hardening pass): these ALWAYS require authentication unless the
/// operator explicitly sets `SXIAUM_RPC_ALLOW_ANON_WRITES=1` (recommended only
/// for local devnets). Setting `SXIAUM_RPC_WRITE_AUTH=1` additionally forces
/// token auth for writes and is REQUIRED in production on non-loopback binds.
pub static PUBLIC_WRITE_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    set([
        "sxiaum_sendTransaction",
        "sxiaum_sendRawTransaction",
        "eth_sendRawTransaction",
        "sxiaum_submitCommit",
        "sxiaum_submitReveal",
    ])
});

/// Returns true if the method is classified as a safe public read.
pub fn is_public_read(method: &str) -> bool {
    PUBLIC_READ_METHODS.contains(method)
}

/// Returns true if the method is a public write subject to `SXIAUM_RPC_WRITE_AUTH`.
pub fn is_public_write(method: &str) -> bool {
    PUBLIC_WRITE_METHODS.contains(method)
}

/// Returns true if the method requires authentication regardless of policy flags
/// (i.e., it is neither a public read nor a policy-gated public write).
pub fn always_requires_auth(method: &str) -> bool {
    !is_public_read(method) && !is_public_write(method)
}

/// Resolves the dispatch category for a method name.
///
/// Unknown methods map to [`MethodCategory::Network`], whose handler returns a
/// proper `Method not found` error for unrecognized names.
pub fn dispatch_category(method: &str) -> MethodCategory {
    const BLOCKS: &[&str] = &[
        "sxiaum_latestBlock",
        "sxiaum_getBlockByNumber",
        "sxiaum_getBlockByHash",
        "sxiaum_getBlockHeader",
        "sxiaum_getBlockTransactions",
        "sxiaum_getBlockReceipts",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getBlockReceipts",
    ];
    const TRANSACTIONS: &[&str] = &[
        "sxiaum_sendTransaction",
        "sxiaum_sendRawTransaction",
        "eth_sendRawTransaction",
        "sxiaum_submitCommit",
        "sxiaum_submitReveal",
        "sxiaum_getCommitStatus",
        "sxiaum_getMevPoolStats",
        "sxiaum_getPendingTransactions",
        "sxiaum_estimateGas",
        "eth_estimateGas",
        "sxiaum_getTransactionByHash",
        "eth_getTransactionByHash",
        "sxiaum_getTransactionReceipt",
        "eth_getTransactionReceipt",
    ];
    const STATE: &[&str] = &[
        "sxiaum_getBalance",
        "eth_getBalance",
        "sxiaum_getNonce",
        "eth_getTransactionCount",
        "sxiaum_getAccount",
        "sxiaum_getStorageAt",
        "eth_getStorageAt",
        "sxiaum_getCode",
        "eth_getCode",
        "sxiaum_getStateRoot",
        "sxiaum_getProof",
        "sxiaum_getStorageProof",
        "sxiaum_getMinimalProof",
        "eth_call",
        "eth_getLogs",
        "eth_feeHistory",
    ];

    if BLOCKS.contains(&method) {
        MethodCategory::Blocks
    } else if TRANSACTIONS.contains(&method) {
        MethodCategory::Transactions
    } else if STATE.contains(&method) {
        MethodCategory::State
    } else {
        MethodCategory::Network
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RpcError;
    use crate::routes::{blocks, network, state, tx};
    use serde_json::Value;
    use std::sync::Arc;

    /// Every method reachable through [`dispatch_category`] must have an
    /// implementation arm in its target handler, otherwise the router would
    /// advertise a category yet answer `MethodNotFound`.
    #[tokio::test]
    async fn dispatched_methods_are_implemented() {
        let context = crate::test_support::test_context().await;
        let ctx = Arc::clone(&context);

        let mut methods: Vec<&'static str> = PUBLIC_READ_METHODS
            .union(&PUBLIC_WRITE_METHODS)
            .copied()
            .collect();
        methods.extend([
            "sxiaum_getPendingTransactions",
            "sxiaum_getPeers",
            "sxiaum_getNetworkInfo",
        ]);

        for method in methods {
            let category = dispatch_category(method);
            // Early-return methods handled directly by the server dispatcher
            // are validated separately in server tests; skip them here.
            if matches!(
                method,
                "eth_chainId"
                    | "eth_networkId"
                    | "net_version"
                    | "net_listening"
                    | "net_peerCount"
                    | "web3_clientVersion"
                    | "web3_sha3"
                    | "eth_accounts"
                    | "eth_coinbase"
                    | "eth_mining"
                    | "eth_hashrate"
                    | "eth_gasPrice"
                    | "eth_blockNumber"
                    | "eth_syncing"
            ) {
                continue;
            }

            let params: Option<Value> = None;
            let result = match category {
                MethodCategory::Blocks => blocks::handle_block_method(method, params, &ctx).await,
                MethodCategory::Transactions => tx::handle_tx_method(method, params, &ctx).await,
                MethodCategory::State => state::handle_state_method(method, params, &ctx).await,
                MethodCategory::Network => {
                    network::handle_network_method(method, params, &ctx).await
                }
            };

            // Missing parameters are acceptable (InvalidParams proves an arm
            // exists); only MethodNotFound indicates a routing gap.
            assert!(
                !matches!(result, Err(RpcError::MethodNotFound(_))),
                "method {method} routed to {category:?} but not implemented"
            );
        }
    }

    #[test]
    fn sensitive_network_methods_require_auth() {
        assert!(!is_public_read("sxiaum_getPeers"));
        assert!(!is_public_read("sxiaum_getNetworkInfo"));
        assert!(always_requires_auth("sxiaum_getPeers"));
    }

    #[test]
    fn pending_transactions_requires_auth() {
        assert!(always_requires_auth("sxiaum_getPendingTransactions"));
    }

    #[test]
    fn transaction_count_routes_to_state_not_tx() {
        // Regression: the legacy `contains("Transaction")` rule misrouted
        // `eth_getTransactionCount` into the tx handler which had no arm.
        assert_eq!(
            dispatch_category("eth_getTransactionCount"),
            MethodCategory::State
        );
    }

    #[test]
    fn unknown_methods_default_deny() {
        assert!(always_requires_auth("admin_addPeer"));
        assert!(always_requires_auth("debug_traceBlock"));
        assert!(always_requires_auth("totally_unknown"));
    }
}
