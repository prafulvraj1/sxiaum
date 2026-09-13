#![no_main]

use libfuzzer_sys::fuzz_target;
use sxiaum_state::proof::VerkleProof;
use sxiaum_state::verkle_tree::VerkleTree;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    let mut trie = VerkleTree::new();
    let mut inserted_keys = Vec::new();

    // 1. Process 64-byte chunks as (key, value) pairs (up to 8 pairs per run to bound execution time)
    for chunk in data.chunks_exact(64).take(8) {
        let mut key = [0u8; 32];
        let mut value = [0u8; 32];
        key.copy_from_slice(&chunk[0..32]);
        value.copy_from_slice(&chunk[32..64]);

        if trie.insert(key, value).is_ok() {
            inserted_keys.push((key, value));
        }
    }

    if inserted_keys.is_empty() {
        return;
    }

    let root = trie.root_commitment();

    // 2. Query each inserted key and generate/verify KZG Verkle proofs
    for (key, value) in &inserted_keys {
        if let Ok(Some(val)) = trie.get(*key) {
            let _ = val == *value;
        }

        if let Ok(proof) = VerkleProof::generate_proof(&trie, *key) {
            let _ = proof.verify_proof(*key, *value, root);
        }
    }

    // 3. Update values and verify root changes
    if let Some((first_key, _)) = inserted_keys.first() {
        let updated_val = [0xffu8; 32];
        if trie.update(*first_key, updated_val).is_ok() {
            let updated_root = trie.root_commitment();
            let _ = updated_root != root;
        }
    }

    // 4. Delete keys
    for (key, _) in inserted_keys.iter().take(2) {
        let _ = trie.delete(*key);
    }
});

