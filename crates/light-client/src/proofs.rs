use anyhow::Result;
use sxiaum_state::{RpcVerkleProof, VerkleProof};
use sxiaum_types::{Account, Address};
use tracing::{debug, warn};

/// A utility for light clients to verify cryptographic proofs of state inclusion
/// against a verified block header root.
pub struct ProofVerifier;

impl ProofVerifier {
    /// Verify a single Verkle inclusion proof for an arbitrary key-value pair against a trusted root.
    pub fn verify_inclusion_proof(
        proof: &VerkleProof,
        key: [u8; 32],
        value: [u8; 32],
        root_hash: [u8; 32],
    ) -> Result<bool> {
        debug!(
            "Verifying Verkle inclusion proof for key 0x{} against root 0x{}",
            hex::encode(key),
            hex::encode(root_hash)
        );
        proof.verify_proof(key, value, root_hash)
    }

    /// Verify an account's state (balance, nonce, etc.) using a Verkle proof against a trusted root.
    pub fn verify_account_state(
        proof: &VerkleProof,
        address: &Address,
        account: &Account,
        root_hash: [u8; 32],
    ) -> Result<bool> {
        debug!(
            "Verifying account state proof for address {} against root 0x{}",
            address,
            hex::encode(root_hash)
        );
        proof.verify_account_proof(address, account, root_hash)
    }

    /// Verify the value of a specific contract storage slot against a trusted root.
    pub fn verify_contract_storage(
        proof: &VerkleProof,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
        root_hash: [u8; 32],
    ) -> Result<bool> {
        debug!(
            "Verifying storage proof for contract {} at key 0x{} against root 0x{}",
            address,
            hex::encode(storage_key),
            hex::encode(root_hash)
        );
        proof.verify_storage_proof(address, storage_key, storage_value, root_hash)
    }

    /// Verify a proof received via the RPC layer against an explicit expected trusted root.
    pub fn verify_rpc_proof_against_root(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
        expected_root: [u8; 32],
    ) -> Result<bool> {
        if rpc_proof.root != expected_root {
            warn!(
                "RPC proof root mismatch: expected 0x{}, got 0x{}",
                hex::encode(expected_root),
                hex::encode(rpc_proof.root)
            );
            return Ok(false);
        }
        VerkleProof::verify_for_light_client(rpc_proof, key, value)
    }

    /// Verify an account proof received via RPC against an explicit expected trusted root.
    pub fn verify_rpc_account_proof_against_root(
        rpc_proof: &RpcVerkleProof,
        address: &Address,
        account: &Account,
        expected_root: [u8; 32],
    ) -> Result<bool> {
        Self::verify_rpc_proof_against_root(
            rpc_proof,
            *address.as_bytes(),
            account.try_hash()?,
            expected_root,
        )
    }

    /// Verify a storage proof received via RPC against an explicit expected trusted root.
    pub fn verify_rpc_storage_proof_against_root(
        rpc_proof: &RpcVerkleProof,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
        expected_root: [u8; 32],
    ) -> Result<bool> {
        Self::verify_rpc_proof_against_root(
            rpc_proof,
            sxiaum_state::storage_proof_key(address, &storage_key),
            storage_value,
            expected_root,
        )
    }

    /// Verify a proof received via RPC (root checked internally against proof.root).
    pub fn verify_rpc_proof(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        VerkleProof::verify_for_light_client(rpc_proof, key, value)
    }

    pub fn verify_rpc_account_proof(
        rpc_proof: &RpcVerkleProof,
        address: &Address,
        account: &Account,
    ) -> Result<bool> {
        Self::verify_rpc_proof(rpc_proof, *address.as_bytes(), account.try_hash()?)
    }

    pub fn verify_rpc_storage_proof(
        rpc_proof: &RpcVerkleProof,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
    ) -> Result<bool> {
        Self::verify_rpc_proof(
            rpc_proof,
            sxiaum_state::storage_proof_key(address, &storage_key),
            storage_value,
        )
    }

    pub fn verify_minimal_rpc_proof(
        rpc_proof: &RpcVerkleProof,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<bool> {
        Self::verify_rpc_proof(rpc_proof, key, value)
    }
}

#[cfg(test)]
mod tests {
    use super::ProofVerifier;
    use sxiaum_state::{storage_proof_key, VerkleProof, VerkleTree};
    use sxiaum_types::{Account, Address};

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn verifies_rpc_account_proofs() {
        let mut tree = VerkleTree::new();
        let address = Address(hash(1));
        let account = Account::new(address);
        tree.insert(*address.as_bytes(), account.try_hash().unwrap())
            .expect("account insert should succeed");

        let proof = VerkleProof::generate_account_proof(&tree, &address)
            .expect("account proof generation should succeed")
            .export_for_rpc(tree.root_commitment());

        assert!(
            ProofVerifier::verify_rpc_account_proof(&proof, &address, &account)
                .expect("rpc account proof verification should succeed")
        );

        // Explicit root check
        assert!(ProofVerifier::verify_rpc_account_proof_against_root(
            &proof,
            &address,
            &account,
            tree.root_commitment()
        )
        .unwrap());

        // Wrong root fails
        assert!(!ProofVerifier::verify_rpc_account_proof_against_root(
            &proof, &address, &account, [0xff; 32]
        )
        .unwrap());
    }

    #[test]
    fn verifies_rpc_storage_proofs() {
        let mut tree = VerkleTree::new();
        let address = Address(hash(2));
        let storage_key = hash(3);
        let storage_value = hash(4);
        tree.insert(storage_proof_key(&address, &storage_key), storage_value)
            .expect("storage insert should succeed");

        let proof = VerkleProof::generate_storage_proof(&tree, &address, storage_key)
            .expect("storage proof generation should succeed")
            .export_for_rpc(tree.root_commitment());

        assert!(ProofVerifier::verify_rpc_storage_proof(
            &proof,
            &address,
            storage_key,
            storage_value
        )
        .expect("rpc storage proof verification should succeed"));

        // Explicit root check
        assert!(ProofVerifier::verify_rpc_storage_proof_against_root(
            &proof,
            &address,
            storage_key,
            storage_value,
            tree.root_commitment()
        )
        .unwrap());

        // Wrong root fails
        assert!(!ProofVerifier::verify_rpc_storage_proof_against_root(
            &proof,
            &address,
            storage_key,
            storage_value,
            [0xee; 32]
        )
        .unwrap());
    }

    #[test]
    fn rejects_minimal_rpc_proofs() {
        let mut tree = VerkleTree::new();
        let key = hash(5);
        let value = hash(6);
        tree.insert(key, value).expect("tree insert should succeed");

        // SECURITY (C-11): even a correctly generated minimal proof must be
        // rejected — the format is forgeable by construction.
        let proof = VerkleProof::generate_minimal_proof(&tree, key)
            .expect("minimal proof generation should succeed")
            .export_minimal_for_rpc(tree.root_commitment());

        assert!(
            ProofVerifier::verify_minimal_rpc_proof(&proof, key, value).is_err(),
            "minimal proofs must be rejected"
        );
    }
}
