#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use sxiaum_mempool::{CommitTransaction, Mempool, MempoolConfig, RevealTransaction};
use sxiaum_state::StateDb;
use sxiaum_storage::MemoryDatabaseBackend;
use sxiaum_types::Transaction;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let storage = Arc::new(MemoryDatabaseBackend::new());
    let state = Arc::new(StateDb::new(storage));
    let mempool = Mempool::new(MempoolConfig::default(), state);

    // 1. Fuzz standard transaction decoding and admission
    if let Ok(tx) = bincode::deserialize::<Transaction>(data) {
        let _ = mempool.add_transaction(tx.clone());
        let dummy_nonce = [7u8; 32];
        // Current commit-hash API surface (fallible over tx hash derivation).
        if let Ok(tx_hash) = tx.try_hash() {
            let _ = sxiaum_mempool::compute_commit_hash_from_tx_hash(&dummy_nonce, &tx_hash);
        }
        let _ = sxiaum_mempool::try_compute_commit_hash(&dummy_nonce, &tx);
    }

    // 2. Fuzz CommitTransaction decoding and encoding
    if let Ok(commit) = bincode::deserialize::<CommitTransaction>(data) {
        let _ = commit.compute_id();
        let _ = commit.try_encode();
    }

    if let Ok(commit) = CommitTransaction::decode(data) {
        let _ = commit.compute_id();
        let _ = commit.try_encode();
    }

    // 3. Fuzz RevealTransaction decoding and encoding
    if let Ok(reveal) = bincode::deserialize::<RevealTransaction>(data) {
        let _ = reveal.try_encode();
    }

    if let Ok(reveal) = RevealTransaction::decode(data) {
        let _ = reveal.try_encode();
    }
});
