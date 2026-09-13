use anyhow::Result;
use libp2p::PeerId;
use std::sync::Arc;
use sxiaum_block::BlockHeader;
use sxiaum_networking::{
    P2PNetwork, RpcStateProofQuery, RpcStateProofRequest, RpcStateProofValue, RpcSyncClient,
    RpcVerifiedHeaderEnvelope,
};
use sxiaum_types::{Account, Address, BlockHeight, Hash, Validator};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::error::LightClientError;
use crate::header_sync::HeaderSync;
use crate::proofs::ProofVerifier;

/// A lightweight client for the SXIAUM blockchain that verifies block headers
/// and maintains a trusted view of the chain without storing the full state.
pub struct LightClient {
    /// The most recent header that has been cryptographically verified.
    latest_header: Arc<RwLock<Option<BlockHeader>>>,
    /// Networking handle used for request-response header discovery.
    networking: Arc<Mutex<P2PNetwork>>,
    /// The primary peer used for fetching new headers.
    peer: Arc<RwLock<PeerId>>,
    /// A trusted block height used as a synchronization anchor (checkpoint).
    trusted_checkpoint: Option<BlockHeight>,
    /// The underlying synchronization engine.
    sync_engine: Arc<RwLock<HeaderSync>>,
}

impl LightClient {
    /// Creates a new light client instance anchored at a trusted header with
    /// an explicit validator set.
    ///
    /// The validator set is mandatory: quorum verification is impossible
    /// without one, so there is no empty-set constructor.
    pub fn new_with_validator_set(
        networking: Arc<Mutex<P2PNetwork>>,
        peer: PeerId,
        trusted_header: BlockHeader,
        validator_set: Vec<Validator>,
    ) -> Result<Self> {
        info!(
            "Initializing SXIAUM light client... Primary peer: {}, Trusted Checkpoint: {}",
            peer, trusted_header.height
        );

        let zk_verification_key = crate::verifier::HeaderVerifier::load_zk_verification_key()?;

        Self::new_trusted(
            networking,
            peer,
            trusted_header,
            validator_set,
            zk_verification_key,
        )
    }

    pub fn new_trusted(
        networking: Arc<Mutex<P2PNetwork>>,
        peer: PeerId,
        trusted_header: BlockHeader,
        validator_set: Vec<Validator>,
        zk_verification_key: Vec<u8>,
    ) -> Result<Self> {
        let checkpoint = trusted_header.height;
        let initial_header = trusted_header.clone();
        let sync =
            HeaderSync::new_trusted(peer, trusted_header, validator_set, zk_verification_key)?;
        Ok(Self {
            latest_header: Arc::new(RwLock::new(Some(initial_header))),
            networking,
            peer: Arc::new(RwLock::new(peer)),
            trusted_checkpoint: Some(checkpoint),
            sync_engine: Arc::new(RwLock::new(sync)),
        })
    }

    /// Returns the height and hash of the latest verified block header.
    pub async fn get_chain_tip(&self) -> (BlockHeight, Option<Hash>) {
        let header_guard = self.latest_header.read().await;
        if let Some(header) = &*header_guard {
            (header.height, header.try_hash().ok())
        } else {
            (self.trusted_checkpoint.unwrap_or(0), None)
        }
    }

    /// Detects the target network height from the primary peer.
    pub async fn detect_network_head(&self) -> Result<BlockHeight> {
        let peer = *self.peer.read().await;
        debug!("Detecting latest chain head from primary peer: {}", peer);

        let mut network = self.networking.lock().await;
        let remote_height = network.request_latest_block_height(peer).await?;

        debug!("Peer {} reported network height {}", peer, remote_height);
        Ok(remote_height)
    }

    /// LC Step 1 - Light client downloads block headers and verifies them.
    ///
    /// Full sync pipeline:
    /// 1. Detect the network head from the primary peer.
    /// 2. Download missing headers in bounded batches up to `MAX_HEADER_BATCH_SIZE`.
    /// 3. Verify each header's linkage, proposer signature, ZK proof, and consensus signatures.
    /// 4. Advance trusted tip atomically upon complete batch verification.
    pub async fn run_sync_loop(&self) -> Result<()> {
        info!("Initiating light client synchronization sequence...");
        let peer = *self.peer.read().await;

        // LC Step 1a - detect network head height from the primary peer.
        let target_height = self.detect_network_head().await?;
        let (current_height, _) = self.get_chain_tip().await;

        if target_height <= current_height {
            info!(
                "Light client is already at the network tip (height={})",
                current_height
            );
            return Ok(());
        }

        // Bounded batch request to prevent sync stall when gap > MAX_HEADER_BATCH_SIZE
        let batch_end = std::cmp::min(
            target_height,
            current_height.saturating_add(crate::MAX_HEADER_BATCH_SIZE as u64),
        );
        let start_height = current_height.saturating_add(1);

        info!(
            "Sync gap detected: local={}, target={}, batch=[{}, {}]. Fetching verified headers...",
            current_height, target_height, start_height, batch_end
        );

        let headers = {
            let mut network = self.networking.lock().await;
            network
                .request_headers(peer, start_height, batch_end)
                .await?
        }
        .unwrap_or_default();

        if headers.is_empty() {
            return Err(LightClientError::EmptyHeaderResponse {
                peer: peer.to_string(),
                start: start_height,
                end: batch_end,
            }
            .into());
        }

        let mut sync_guard = self.sync_engine.write().await;
        sync_guard.update_peer(peer);
        let envelopes = headers
            .into_iter()
            .map(Self::to_verified_header_envelope)
            .collect::<Result<Vec<_>>>()?;
        sync_guard.receive_verified_headers(envelopes)?;

        // LC Step 4 - accept block: advance the trusted tip to the latest
        // verified header so future queries reflect the new chain state.
        if let Some(header) = sync_guard.latest_verified_header() {
            let mut header_guard = self.latest_header.write().await;
            *header_guard = Some(header.clone());
            info!(
                "Trusted state updated to height {}: Hash={}",
                header.height,
                hex::encode(header.try_hash().unwrap_or_default())
            );
        }

        Ok(())
    }

    /// Convert a wire envelope into the internal verification envelope.
    ///
    /// Fail-closed: any consensus signature whose byte length is not exactly
    /// 64 rejects the entire envelope instead of being silently dropped — a
    /// malicious peer must not be able to strip chosen validators' signatures
    /// by truncating them.
    fn to_verified_header_envelope(
        envelope: RpcVerifiedHeaderEnvelope,
    ) -> Result<crate::header_sync::VerifiedHeaderEnvelope> {
        let mut consensus_signatures = Vec::with_capacity(envelope.consensus_signatures.len());
        for (address, signature) in envelope.consensus_signatures {
            let sig_arr: [u8; 64] = signature.try_into().map_err(|bad: Vec<u8>| {
                LightClientError::InvalidConsensusSignature {
                    validator: address,
                    header_hash: format!("malformed signature length {} (expected 64)", bad.len()),
                }
            })?;
            consensus_signatures.push((address, sig_arr));
        }

        Ok(crate::header_sync::VerifiedHeaderEnvelope {
            header: envelope.header,
            consensus_signatures,
            hotstuff_view_phase: envelope.hotstuff_view_phase,
        })
    }

    /// Proactively updates the light client state with a new batch of verified header envelopes.
    pub async fn update_verified_headers(
        &self,
        headers: Vec<crate::header_sync::VerifiedHeaderEnvelope>,
    ) -> Result<()> {
        if headers.is_empty() {
            return Ok(());
        }

        let mut sync_guard = self.sync_engine.write().await;
        sync_guard.receive_verified_headers(headers)?;

        if let Some(header) = sync_guard.latest_verified_header() {
            let mut header_guard = self.latest_header.write().await;
            *header_guard = Some(header.clone());
        }

        Ok(())
    }

    pub async fn verify_account_state(
        &self,
        address: &Address,
        account: &Account,
        proof: &sxiaum_state::VerkleProof,
    ) -> Result<bool> {
        let header = self
            .latest_header
            .read()
            .await
            .clone()
            .ok_or_else(|| LightClientError::NoVerifiedHeader)?;
        ProofVerifier::verify_account_state(proof, address, account, header.state_root)
    }

    pub async fn verify_storage_state(
        &self,
        address: &Address,
        storage_key: [u8; 32],
        storage_value: [u8; 32],
        proof: &sxiaum_state::VerkleProof,
    ) -> Result<bool> {
        let header = self
            .latest_header
            .read()
            .await
            .clone()
            .ok_or_else(|| LightClientError::NoVerifiedHeader)?;
        ProofVerifier::verify_contract_storage(
            proof,
            address,
            storage_key,
            storage_value,
            header.state_root,
        )
    }

    pub async fn request_account_state_at_height(
        &self,
        height: BlockHeight,
        address: Address,
        max_depth: usize,
    ) -> Result<(Account, sxiaum_state::RpcVerkleProof)> {
        let bounded_depth = max_depth.clamp(1, 64);
        let peer = *self.peer.read().await;
        let response = {
            let mut network = self.networking.lock().await;
            network
                .request_state_proof(
                    peer,
                    RpcStateProofRequest {
                        height,
                        max_depth: bounded_depth,
                        query: RpcStateProofQuery::Account { address },
                    },
                )
                .await?
        }
        .ok_or_else(|| {
            LightClientError::StateProofFailed("peer did not return an account state proof".into())
        })?;

        let header = self
            .verified_header_at_height(height)
            .await
            .ok_or_else(|| {
                LightClientError::StateProofFailed(format!(
                    "light client has not synced header {}",
                    height
                ))
            })?;

        if response.proof.root != header.state_root {
            return Err(LightClientError::StateProofFailed(format!(
                "state proof root mismatch for height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(header.state_root),
                hex::encode(response.proof.root)
            ))
            .into());
        }

        let RpcStateProofValue::Account(account) = response.value else {
            return Err(LightClientError::StateProofFailed(
                "peer returned non-account proof value for account query".into(),
            )
            .into());
        };

        if account.address != address {
            return Err(LightClientError::StateProofFailed(format!(
                "peer returned account for {} while {} was requested",
                account.address, address
            ))
            .into());
        }

        account.validate().map_err(|e| {
            LightClientError::StateProofFailed(format!(
                "peer returned a non-canonical account for {}: {e}",
                address
            ))
        })?;

        if !ProofVerifier::verify_rpc_account_proof_against_root(
            &response.proof,
            &address,
            &account,
            header.state_root,
        )? {
            return Err(LightClientError::StateProofFailed(format!(
                "account state proof verification failed at height {}",
                height
            ))
            .into());
        }

        Ok((account, response.proof))
    }

    pub async fn request_storage_state_at_height(
        &self,
        height: BlockHeight,
        address: Address,
        storage_key: [u8; 32],
        max_depth: usize,
    ) -> Result<([u8; 32], sxiaum_state::RpcVerkleProof)> {
        let bounded_depth = max_depth.clamp(1, 64);
        let peer = *self.peer.read().await;
        let response = {
            let mut network = self.networking.lock().await;
            network
                .request_state_proof(
                    peer,
                    RpcStateProofRequest {
                        height,
                        max_depth: bounded_depth,
                        query: RpcStateProofQuery::Storage {
                            address,
                            key: storage_key,
                        },
                    },
                )
                .await?
        }
        .ok_or_else(|| {
            LightClientError::StateProofFailed("peer did not return a storage state proof".into())
        })?;

        let header = self
            .verified_header_at_height(height)
            .await
            .ok_or_else(|| {
                LightClientError::StateProofFailed(format!(
                    "light client has not synced header {}",
                    height
                ))
            })?;

        if response.proof.root != header.state_root {
            return Err(LightClientError::StateProofFailed(format!(
                "storage proof root mismatch for height {}: expected 0x{}, got 0x{}",
                height,
                hex::encode(header.state_root),
                hex::encode(response.proof.root)
            ))
            .into());
        }

        let RpcStateProofValue::Storage(storage_value) = response.value else {
            return Err(LightClientError::StateProofFailed(
                "peer returned non-storage proof value for storage query".into(),
            )
            .into());
        };

        if !ProofVerifier::verify_rpc_storage_proof_against_root(
            &response.proof,
            &address,
            storage_key,
            storage_value,
            header.state_root,
        )? {
            return Err(LightClientError::StateProofFailed(format!(
                "storage state proof verification failed at height {}",
                height
            ))
            .into());
        }

        Ok((storage_value, response.proof))
    }

    /// Returns the current trusted checkpoint height.
    pub fn trusted_checkpoint(&self) -> Option<BlockHeight> {
        self.trusted_checkpoint
    }

    /// Returns the PeerId of the node this light client is tracking.
    pub async fn tracking_peer(&self) -> PeerId {
        *self.peer.read().await
    }

    pub async fn update_tracking_peer(&self, peer: PeerId) {
        *self.peer.write().await = peer;
        self.sync_engine.write().await.update_peer(peer);
    }

    /// Verifies if the current state of the light client is consistent with the chain.
    pub async fn verify_state_integrity(&self) -> Result<bool> {
        let (height, hash) = self.get_chain_tip().await;
        if hash.is_none() && height > 0 {
            warn!("Light client state is uninitialized at height {}", height);
            return Ok(false);
        }

        debug!("Light client state integrity verified at height {}", height);
        Ok(true)
    }

    async fn verified_header_at_height(&self, height: BlockHeight) -> Option<BlockHeader> {
        let latest = self.latest_header.read().await;
        if let Some(header) = &*latest {
            if header.height == height {
                return Some(header.clone());
            }
        }
        drop(latest);

        let sync_guard = self.sync_engine.read().await;
        sync_guard
            .verified_headers
            .iter()
            .find(|header| header.height == height)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::LightClient;
    use anyhow::Result;
    use ed25519_dalek::{Signer, SigningKey};
    use libp2p::{identity::Keypair, Multiaddr, PeerId};
    use primitive_types::U256;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    use std::time::Duration;
    use sxiaum_block::{BlockBody, BlockHeader};
    use sxiaum_networking::{
        L1Request, L1Response, P2PConfig, P2PNetwork, RpcStateProofResponse, RpcStateProofValue,
        RpcVerifiedHeaderEnvelope,
    };
    use sxiaum_state::{VerkleProof, VerkleTree};
    use sxiaum_types::{validator::ValidatorStatus, Account, Address, Validator};
    use tokio::sync::Mutex;

    fn test_config() -> P2PConfig {
        P2PConfig {
            local_key: Keypair::generate_ed25519(),
            bootstrap_peers: Vec::new(),
            discovery_interval: Duration::from_millis(25),
            discovery_backoff: Duration::from_millis(10),
            max_peers: 8,
            max_header_batch: 128,
            max_header_requests_per_peer_per_window: 4,
            header_request_window_secs: 10,
            max_state_proof_requests_per_peer_per_window: 4,
            state_proof_request_window_secs: 10,
            db: None,
        }
    }

    fn tcp_addr(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}")
            .parse()
            .expect("tcp multiaddr should parse")
    }

    fn expected_sp1_commitment(public_inputs: &[u8]) -> Vec<u8> {
        let verification_key = vec![0x11; 128];
        let mut hasher = Sha256::new();
        hasher.update(b"sp1:trace");
        hasher.update(&verification_key);
        hasher.update(public_inputs);
        let execution_trace = hasher.finalize_reset();

        hasher.update(b"sp1:pk");
        hasher.update(&verification_key);
        let proving_key = hasher.finalize_reset();

        hasher.update(proving_key);
        hasher.update(execution_trace);
        hasher.update(public_inputs);
        hasher.finalize().to_vec()
    }

    struct TestRpcHandler {
        envelope: RpcVerifiedHeaderEnvelope,
        state_proof: Option<RpcStateProofResponse>,
    }

    impl sxiaum_networking::RpcRequestHandler for TestRpcHandler {
        fn handle_request(&self, _peer: PeerId, req: L1Request) -> Result<L1Response> {
            match req {
                L1Request::GetLatestBlockHeight => Ok(L1Response::respond_latest_block_height(
                    Some(self.envelope.header.height),
                )),
                L1Request::GetHeaders { .. } => Ok(L1Response::respond_headers(Some(vec![self
                    .envelope
                    .clone()]))),
                L1Request::GetStateProof(_) => {
                    Ok(L1Response::respond_state_proof(self.state_proof.clone()))
                }
                _ => Ok(L1Response::Error("unsupported".into())),
            }
        }
    }

    #[tokio::test]
    async fn run_sync_loop_accepts_qc_backed_verified_headers() -> Result<()> {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let proposer_pubkey = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&proposer_pubkey);
        let zk_vk = vec![0x11; 128];

        let mut validator = Validator::new(proposer, proposer_pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 1;
        let validator_set = vec![validator.clone()];

        let genesis = BlockHeader::genesis();
        let mut header = BlockHeader::new(genesis.try_hash().unwrap(), 1);
        header.proposer = proposer;
        header.timestamp = genesis.timestamp + 1;
        header.validator_root =
            BlockBody::compute_validator_root(&validator_set).expect("validator root");
        let unsigned_hash = header.try_hash().unwrap();
        header.zk_proof = Some(expected_sp1_commitment(&unsigned_hash));
        let header_hash = header.try_hash().unwrap();
        header.signature = Some(signer.sign(&header_hash).to_bytes());

        let envelope = RpcVerifiedHeaderEnvelope {
            header: header.clone(),
            consensus_signatures: vec![(proposer, signer.sign(&header_hash).to_bytes().to_vec())],
            hotstuff_view_phase: None,
        };

        let peer_id = PeerId::random();
        let mut network = P2PNetwork::new(test_config()).await?;
        network
            .peer_store
            .add_peer(sxiaum_networking::Peer::new(peer_id, tcp_addr(22000)));
        network.set_test_loopback_rpc_responder(Arc::new(TestRpcHandler {
            envelope: envelope.clone(),
            state_proof: None,
        }));

        let client = LightClient::new_trusted(
            Arc::new(Mutex::new(network)),
            peer_id,
            genesis,
            validator_set,
            zk_vk,
        )?;

        client.run_sync_loop().await?;

        let (height, hash) = client.get_chain_tip().await;
        assert_eq!(height, 1);
        assert_eq!(hash, Some(header.try_hash().unwrap()));

        Ok(())
    }

    #[tokio::test]
    async fn light_client_requests_account_state_proof_against_synced_header() -> Result<()> {
        let signer = SigningKey::from_bytes(&[2u8; 32]);
        let proposer_pubkey = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&proposer_pubkey);
        let zk_vk = vec![0x11; 128];

        let mut validator = Validator::new(proposer, proposer_pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 1;
        let validator_set = vec![validator.clone()];

        let account = {
            let mut account = Account::new(proposer);
            account
                .checked_add_balance(U256::from(777u64))
                .expect("balance credit must succeed");
            account
        };
        let mut tree = VerkleTree::new();
        tree.insert(*proposer.as_bytes(), account.try_hash().unwrap())?;
        let rpc_account_proof = VerkleProof::generate_account_proof(&tree, &proposer)?
            .export_for_rpc(tree.root_commitment());

        let genesis = BlockHeader::genesis();
        let mut header = BlockHeader::new(genesis.try_hash().unwrap(), 1);
        header.proposer = proposer;
        header.timestamp = genesis.timestamp + 1;
        header.validator_root =
            BlockBody::compute_validator_root(&validator_set).expect("validator root");
        header.state_root = tree.root_commitment();
        let unsigned_hash = header.try_hash().unwrap();
        header.zk_proof = Some(expected_sp1_commitment(&unsigned_hash));
        let header_hash = header.try_hash().unwrap();
        header.signature = Some(signer.sign(&header_hash).to_bytes());

        let envelope = RpcVerifiedHeaderEnvelope {
            header: header.clone(),
            consensus_signatures: vec![(proposer, signer.sign(&header_hash).to_bytes().to_vec())],
            hotstuff_view_phase: None,
        };

        let state_proof_resp = RpcStateProofResponse {
            height: 1,
            proof: rpc_account_proof,
            value: RpcStateProofValue::Account(account.clone()),
        };

        let peer_id = PeerId::random();
        let mut network = P2PNetwork::new(test_config()).await?;
        network
            .peer_store
            .add_peer(sxiaum_networking::Peer::new(peer_id, tcp_addr(22001)));
        network.set_test_loopback_rpc_responder(Arc::new(TestRpcHandler {
            envelope: envelope.clone(),
            state_proof: Some(state_proof_resp),
        }));

        let client = LightClient::new_trusted(
            Arc::new(Mutex::new(network)),
            peer_id,
            genesis,
            validator_set,
            zk_vk,
        )?;
        client.run_sync_loop().await?;

        let (proved_account, proof) = client
            .request_account_state_at_height(1, proposer, 32)
            .await?;

        assert_eq!(proved_account.balance, U256::from(777u64));
        assert_eq!(proof.root, header.state_root);
        Ok(())
    }

    #[tokio::test]
    async fn update_tracking_peer_preserves_verified_tip() -> Result<()> {
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let proposer_pubkey = signer.verifying_key().to_bytes();
        let proposer = Address::from_public_key(&proposer_pubkey);
        let zk_vk = vec![0x11; 128];

        let mut validator = Validator::new(proposer, proposer_pubkey, U256::from(10u64.pow(18)));
        validator.status = ValidatorStatus::Active;
        validator.voting_power = 1;
        let validator_set = vec![validator.clone()];

        let peer_id = PeerId::random();
        let replacement_peer = PeerId::random();
        let mut network = P2PNetwork::new(test_config()).await?;
        let genesis = BlockHeader::genesis();
        let mut header = BlockHeader::new(genesis.try_hash().unwrap(), 1);
        header.proposer = proposer;
        header.timestamp = genesis.timestamp + 1;
        header.validator_root =
            BlockBody::compute_validator_root(&validator_set).expect("validator root");
        let unsigned_hash = header.try_hash().unwrap();
        header.zk_proof = Some(expected_sp1_commitment(&unsigned_hash));
        let header_hash = header.try_hash().unwrap();
        header.signature = Some(signer.sign(&header_hash).to_bytes());

        let envelope = RpcVerifiedHeaderEnvelope {
            header: header.clone(),
            consensus_signatures: vec![(proposer, signer.sign(&header_hash).to_bytes().to_vec())],
            hotstuff_view_phase: None,
        };

        network
            .peer_store
            .add_peer(sxiaum_networking::Peer::new(peer_id, tcp_addr(22002)));
        network.set_test_loopback_rpc_responder(Arc::new(TestRpcHandler {
            envelope: envelope.clone(),
            state_proof: None,
        }));

        let client = LightClient::new_trusted(
            Arc::new(Mutex::new(network)),
            peer_id,
            genesis,
            validator_set,
            zk_vk,
        )?;
        client.run_sync_loop().await?;

        client.update_tracking_peer(replacement_peer).await;

        let (height, hash) = client.get_chain_tip().await;
        assert_eq!(client.tracking_peer().await, replacement_peer);
        assert_eq!(height, 1);
        assert_eq!(hash, Some(header.try_hash().unwrap()));

        Ok(())
    }
}
