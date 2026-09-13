use crate::peer::PeerStore;
use anyhow::{bail, Context, Result};
use libp2p::{gossipsub::IdentTopic, PeerId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use sxiaum_block::Block;
use sxiaum_block::BlockBody;
use sxiaum_consensus::hotstuff::vote::{QuorumCertificate, Vote};
use sxiaum_types::Transaction;
use sxiaum_types::Validator;
use sxiaum_types::MAX_CANONICAL_MESSAGE_SIZE;
use sxiaum_zk::{BlockValidityProof, Sp1Verifier};

pub const TOPIC_BLOCKS: &str = "l1/blocks";
pub const TOPIC_TRANSACTIONS: &str = "l1/txs";
pub const TOPIC_VOTES: &str = "l1/votes";
pub const TOPIC_QUORUM_CERTIFICATES: &str = "l1/quorum_certificates";
pub const TOPIC_COMMITS: &str = "l1/commits";
pub const TOPIC_REVEALS: &str = "l1/reveals";
pub const TOPIC_STATE_SYNC: &str = "l1/state_sync";
const MESSAGE_CACHE_LIMIT: usize = 1024;
const RATE_LIMIT_WINDOW_SECS: u64 = 1;
const RATE_LIMIT_MAX_MESSAGES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageValidationFailure {
    RateLimitExceeded,
    EmptyPayload,
    MessageTooLarge,
    UnsubscribedTopic,
    DuplicateMessage,
    InvalidPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    Block(Vec<u8>),
    Transaction(Vec<u8>),
    Commit(Vec<u8>),
    Reveal(Vec<u8>),
    Vote(Vec<u8>),
    QuorumCertificate(Vec<u8>),
    StateSync(Vec<u8>),
}

pub trait TransactionPoolSink {
    fn contains_transaction(&self, tx: &Transaction) -> Result<bool>;
    fn insert_transaction(&self, tx: Transaction, source_peer: Option<String>) -> Result<()>;
}

pub trait CommitPoolSink {
    fn contains_commit(&self, commit_id: &[u8; 32]) -> Result<bool>;
    fn insert_commit_payload(
        &self,
        payload: &[u8],
        source_peer: Option<String>,
    ) -> Result<[u8; 32]>;
}

pub trait RevealPoolSink {
    fn insert_reveal_payload(&self, payload: &[u8], source_peer: Option<String>) -> Result<()>;
}

pub trait TransactionSignatureVerifier {
    fn verify_transaction_signature(&self, tx: &Transaction) -> Result<bool>;
}

pub trait BlockPoolSink {
    fn contains_block(&self, hash: &[u8; 32]) -> Result<bool>;
    fn insert_block(&self, block: Block) -> Result<()>;
}

pub trait BlockParentLookup {
    fn has_block(&self, hash: &[u8; 32]) -> Result<bool>;
}

pub trait BlockConsensusSink {
    fn forward_block_to_consensus(&self, block: Block) -> Result<()>;
}

pub trait BlockSignatureVerifier {
    fn verify_block_signature(&self, block: &Block) -> Result<bool>;
}

pub trait BlockProofVerifier {
    fn verify_block_proof(&self, block: &Block) -> Result<bool>;
}

pub trait BlockValidatorSetVerifier {
    fn active_validators(&self) -> Result<Vec<Validator>>;
}

pub trait BlockQuorumCertificateVerifier {
    fn verify_block_quorum_certificate(&self, block: &Block) -> Result<bool>;
}

pub trait VoteConsensusSink {
    fn forward_vote_to_consensus(&self, vote: Vote) -> Result<()>;
}

pub trait VoteSignatureVerifier {
    fn verify_vote_signature(&self, vote: &Vote) -> Result<bool>;
}

pub trait QuorumCertificateConsensusSink {
    fn forward_quorum_certificate_to_consensus(&self, qc: QuorumCertificate) -> Result<()>;
}

pub trait QuorumCertificateVerifier {
    fn verify_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<bool>;
}

pub trait QuorumCertificateBroadcaster {
    fn broadcast_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AddressBoundTransactionVerifier;

impl TransactionSignatureVerifier for AddressBoundTransactionVerifier {
    fn verify_transaction_signature(&self, tx: &Transaction) -> Result<bool> {
        tx.verify_signature()
    }
}

#[derive(Clone, Debug)]
pub struct TransactionGossipOutcome {
    pub transaction: Transaction,
    pub inserted: bool,
    pub rebroadcast: Option<GossipMessage>,
}

#[derive(Clone, Debug)]
pub struct CommitGossipOutcome {
    pub commit_payload: Vec<u8>,
    pub commit_id: [u8; 32],
    pub inserted: bool,
    pub rebroadcast: Option<GossipMessage>,
}

#[derive(Clone, Debug)]
pub struct RevealGossipOutcome {
    pub reveal_payload: Vec<u8>,
    pub inserted: bool,
    pub rebroadcast: Option<GossipMessage>,
}

#[derive(Clone, Debug)]
pub struct BlockGossipOutcome {
    pub block: Block,
    pub inserted: bool,
    pub forwarded_to_consensus: bool,
    pub rebroadcast: Option<GossipMessage>,
}

#[derive(Clone, Debug)]
pub struct VoteGossipOutcome {
    pub vote: Vote,
    pub forwarded_to_consensus: bool,
}

#[derive(Clone, Debug)]
pub struct QuorumCertificateGossipOutcome {
    pub quorum_certificate: QuorumCertificate,
    pub forwarded_to_consensus: bool,
    pub broadcast_to_validators: bool,
    pub rebroadcast: Option<GossipMessage>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AddressBoundBlockVerifier;

impl BlockSignatureVerifier for AddressBoundBlockVerifier {
    fn verify_block_signature(&self, block: &Block) -> Result<bool> {
        block.verify_header_signature(block.header.proposer.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HeaderBoundBlockProofVerifier;

impl BlockProofVerifier for HeaderBoundBlockProofVerifier {
    fn verify_block_proof(&self, block: &Block) -> Result<bool> {
        let proof_bytes = block
            .zk_proof_bytes()
            .ok_or_else(|| anyhow::anyhow!("block header does not contain a zk proof"))?;

        let block_proof: BlockValidityProof =
            bincode::deserialize(proof_bytes).context("invalid block zk proof payload")?;

        let block_hash = block.try_hash()?;
        if block_proof.block_hash != block_hash {
            bail!("block zk proof hash does not match block header hash");
        }

        let vk = sxiaum_zk::canonical_sp1_program_vk();
        let verifier = if sxiaum_zk::is_production() {
            Sp1Verifier::new_mainnet(vk)
        } else {
            Sp1Verifier::new(vk)
        };

        verifier.verify(&block_proof.aggregated_proof.bytes, &block_hash)
    }
}

impl GossipMessage {
    pub fn topic(&self) -> IdentTopic {
        match self {
            GossipMessage::Block(_) => IdentTopic::new(TOPIC_BLOCKS),
            GossipMessage::Transaction(_) => IdentTopic::new(TOPIC_TRANSACTIONS),
            GossipMessage::Commit(_) => IdentTopic::new(TOPIC_COMMITS),
            GossipMessage::Reveal(_) => IdentTopic::new(TOPIC_REVEALS),
            GossipMessage::Vote(_) => IdentTopic::new(TOPIC_VOTES),
            GossipMessage::QuorumCertificate(_) => IdentTopic::new(TOPIC_QUORUM_CERTIFICATES),
            GossipMessage::StateSync(_) => IdentTopic::new(TOPIC_STATE_SYNC),
        }
    }

    pub fn try_encode(&self) -> Result<Vec<u8>, crate::error::NetworkingError> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::NetworkingError::Serialization(e.to_string()))
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        serde_json::from_slice(data).ok()
    }

    /// One-byte discriminator per message variant. Mixed into dedup hashes so
    /// identical inner payloads published under different topics can never
    /// suppress each other (cross-topic duplicate DoS).
    fn variant_tag(&self) -> u8 {
        match self {
            GossipMessage::Block(_) => 0,
            GossipMessage::Transaction(_) => 1,
            GossipMessage::Commit(_) => 2,
            GossipMessage::Reveal(_) => 3,
            GossipMessage::Vote(_) => 4,
            GossipMessage::QuorumCertificate(_) => 5,
            GossipMessage::StateSync(_) => 6,
        }
    }

    fn payload(&self) -> &[u8] {
        match self {
            GossipMessage::Block(bytes)
            | GossipMessage::Transaction(bytes)
            | GossipMessage::Commit(bytes)
            | GossipMessage::Reveal(bytes)
            | GossipMessage::Vote(bytes)
            | GossipMessage::QuorumCertificate(bytes)
            | GossipMessage::StateSync(bytes) => bytes,
        }
    }
}

pub struct Gossip {
    pub topic_subscriptions: HashSet<String>,
    seen_messages: HashSet<[u8; 32]>,
    cached_hashes: VecDeque<[u8; 32]>,
    pub peer_windows: HashMap<PeerId, (u64, usize)>,
    /// Optional peer reputation store. When present, peers are penalized for
    /// rate-limit violations, duplicate messages, and invalid payloads.
    peer_store: Option<Arc<Mutex<PeerStore>>>,
}

impl Default for Gossip {
    fn default() -> Self {
        Self::new()
    }
}

impl Gossip {
    pub fn new() -> Self {
        Self {
            topic_subscriptions: HashSet::new(),
            seen_messages: HashSet::new(),
            cached_hashes: VecDeque::new(),
            peer_windows: HashMap::new(),
            peer_store: None,
        }
    }

    /// Attach a peer reputation store so that invalid/rate-limited messages
    /// automatically lower the sender's score.
    pub fn with_peer_store(mut self, peer_store: Arc<Mutex<PeerStore>>) -> Self {
        self.peer_store = Some(peer_store);
        self
    }

    pub fn subscribe(&mut self, topic: impl Into<String>) -> bool {
        self.topic_subscriptions.insert(topic.into())
    }

    pub fn unsubscribe(&mut self, topic: &str) -> bool {
        self.topic_subscriptions.remove(topic)
    }

    pub fn publish(&mut self, topic: &str, message: GossipMessage) -> Result<GossipMessage> {
        if !self.topic_subscriptions.contains(topic) {
            bail!("cannot publish to unsubscribed topic {}", topic);
        }
        self.validate_message(&message)?;
        if self.deduplicate_messages(&message) {
            bail!("duplicate gossip message");
        }
        self.message_cache(&message);
        Ok(self.propagate_message(message))
    }

    pub fn handle_message(
        &mut self,
        peer_id: PeerId,
        message: GossipMessage,
    ) -> Result<GossipMessage> {
        if !self.rate_limit_messages(peer_id) {
            self.penalize_peer(&peer_id, MessageValidationFailure::RateLimitExceeded);
            return self.drop_invalid_messages(MessageValidationFailure::RateLimitExceeded);
        }

        if let Err(e) = self.validate_message(&message) {
            let reason = Self::classify_message_error(&e);
            self.penalize_peer(&peer_id, reason);
            return Err(e);
        }

        if self.deduplicate_messages(&message) {
            // Normal duplicate gossip delivery across mesh topology - drop without reputation penalty
            return self.drop_invalid_messages(MessageValidationFailure::DuplicateMessage);
        }

        self.message_cache(&message);
        Ok(self.propagate_message(message))
    }

    /// Apply the appropriate reputation penalty to a peer based on the failure
    /// reason. Does nothing if no peer_store has been attached.
    fn penalize_peer(&self, peer_id: &PeerId, reason: MessageValidationFailure) {
        let Some(ref store) = self.peer_store else {
            return;
        };
        if let Ok(mut store) = store.lock() {
            match reason {
                MessageValidationFailure::RateLimitExceeded => {
                    store.penalize_rate_limit_violation(peer_id);
                }
                MessageValidationFailure::DuplicateMessage => {
                    store.penalize_duplicate_message(peer_id);
                }
                _ => {
                    store.penalize_invalid_message(peer_id);
                }
            }
        }
    }

    pub fn validate_message(&self, message: &GossipMessage) -> Result<()> {
        if message.payload().is_empty() {
            return self.drop_invalid_messages(MessageValidationFailure::EmptyPayload);
        }

        if message.payload().len() > MAX_CANONICAL_MESSAGE_SIZE {
            return self.drop_invalid_messages(MessageValidationFailure::MessageTooLarge);
        }

        let topic = match message {
            GossipMessage::Block(_) => TOPIC_BLOCKS,
            GossipMessage::Transaction(_) => TOPIC_TRANSACTIONS,
            GossipMessage::Commit(_) => TOPIC_COMMITS,
            GossipMessage::Reveal(_) => TOPIC_REVEALS,
            GossipMessage::Vote(_) => TOPIC_VOTES,
            GossipMessage::QuorumCertificate(_) => TOPIC_QUORUM_CERTIFICATES,
            GossipMessage::StateSync(_) => TOPIC_STATE_SYNC,
        };
        if !self.topic_subscriptions.contains(topic) {
            return self.drop_invalid_messages(MessageValidationFailure::UnsubscribedTopic);
        }

        Ok(())
    }

    pub fn propagate_message(&self, message: GossipMessage) -> GossipMessage {
        message
    }

    pub fn message_hash(message: &GossipMessage) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([message.variant_tag()]);
        hasher.update(message.payload());
        hasher.finalize().into()
    }

    pub fn deduplicate_messages(&mut self, message: &GossipMessage) -> bool {
        let hash = Self::message_hash(message);
        if self.seen_messages.contains(&hash) {
            return true;
        }
        self.seen_messages.insert(hash);
        false
    }

    pub fn message_cache(&mut self, message: &GossipMessage) {
        let hash = Self::message_hash(message);
        if self.cached_hashes.len() >= MESSAGE_CACHE_LIMIT {
            if let Some(evicted) = self.cached_hashes.pop_front() {
                self.seen_messages.remove(&evicted);
            }
        }
        self.cached_hashes.push_back(hash);
        self.seen_messages.insert(hash);
    }

    pub fn rate_limit_messages(&mut self, peer_id: PeerId) -> bool {
        let now = unix_timestamp();

        // Prune stale windows if map gets large, and enforce hard capacity bound
        const MAX_RATE_LIMIT_ENTRIES: usize = 4096;
        if self.peer_windows.len() >= MAX_RATE_LIMIT_ENTRIES
            && !self.peer_windows.contains_key(&peer_id)
        {
            self.peer_windows
                .retain(|_, (ts, _)| now.saturating_sub(*ts) < RATE_LIMIT_WINDOW_SECS * 10);
            if self.peer_windows.len() >= MAX_RATE_LIMIT_ENTRIES {
                if let Some(oldest) = self.peer_windows.keys().next().copied() {
                    self.peer_windows.remove(&oldest);
                }
            }
        }

        let entry = self.peer_windows.entry(peer_id).or_insert((now, 0));

        if now.saturating_sub(entry.0) >= RATE_LIMIT_WINDOW_SECS {
            *entry = (now, 0);
        }

        if entry.1 >= RATE_LIMIT_MAX_MESSAGES {
            return false;
        }

        entry.1 += 1;
        true
    }

    pub fn drop_invalid_messages<T>(&self, reason: MessageValidationFailure) -> Result<T> {
        bail!("dropping invalid gossip message: {:?}", reason)
    }

    pub fn classify_message_error(error: &anyhow::Error) -> MessageValidationFailure {
        let message = error.to_string();
        if message.contains("RateLimitExceeded") || message.contains("rate limit exceeded") {
            MessageValidationFailure::RateLimitExceeded
        } else if message.contains("MessageTooLarge")
            || message.contains("exceeds max size")
            || message.contains("payload too large")
        {
            MessageValidationFailure::MessageTooLarge
        } else if message.contains("DuplicateMessage") || message.contains("duplicate gossip") {
            MessageValidationFailure::DuplicateMessage
        } else if message.contains("EmptyPayload") || message.contains("cannot be empty") {
            MessageValidationFailure::EmptyPayload
        } else if message.contains("UnsubscribedTopic") || message.contains("not subscribed") {
            MessageValidationFailure::UnsubscribedTopic
        } else {
            MessageValidationFailure::InvalidPayload
        }
    }

    pub fn receive_transaction_gossip_message<P, V>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        mempool: &P,
        signature_verifier: &V,
    ) -> Result<TransactionGossipOutcome>
    where
        P: TransactionPoolSink,
        V: TransactionSignatureVerifier,
    {
        let message = GossipMessage::Transaction(payload.to_vec());
        self.handle_message(peer_id, message.clone())?;

        let transaction = Self::decode_transaction_payload(payload)?;
        Self::validate_transaction_format(&transaction)?;
        Self::verify_transaction_signature(&transaction, signature_verifier)?;

        if mempool.contains_transaction(&transaction)? {
            return Ok(TransactionGossipOutcome {
                transaction,
                inserted: false,
                rebroadcast: None,
            });
        }

        mempool.insert_transaction(transaction.clone(), Some(peer_id.to_string()))?;

        Ok(TransactionGossipOutcome {
            transaction,
            inserted: true,
            rebroadcast: None,
        })
    }

    pub fn validate_transaction_format(tx: &Transaction) -> Result<()> {
        tx.validate_basic()?;
        if tx.chain_id != Some(sxiaum_types::SXIAUM_CHAIN_ID) {
            bail!(
                "transaction chain_id mismatch: expected Some({}), got {:?}",
                sxiaum_types::SXIAUM_CHAIN_ID,
                tx.chain_id
            );
        }
        if tx.signature.is_none() {
            bail!("transaction signature is missing");
        }
        Ok(())
    }

    pub fn verify_transaction_signature<V>(tx: &Transaction, signature_verifier: &V) -> Result<()>
    where
        V: TransactionSignatureVerifier,
    {
        if !signature_verifier.verify_transaction_signature(tx)? {
            bail!("invalid transaction signature");
        }
        Ok(())
    }

    fn decode_transaction_payload(payload: &[u8]) -> Result<Transaction> {
        <Transaction as sxiaum_types::Canonical>::decode(payload)
            .or_else(|_| bincode::deserialize(payload))
            .context("invalid transaction gossip payload")
    }

    pub fn receive_commit_gossip_message<P>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        commit_pool: &P,
    ) -> Result<CommitGossipOutcome>
    where
        P: CommitPoolSink,
    {
        let message = GossipMessage::Commit(payload.to_vec());
        self.handle_message(peer_id, message)?;

        let commit_id = commit_pool.insert_commit_payload(payload, Some(peer_id.to_string()))?;

        Ok(CommitGossipOutcome {
            commit_payload: payload.to_vec(),
            commit_id,
            inserted: true,
            rebroadcast: None,
        })
    }

    pub fn receive_reveal_gossip_message<P>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        reveal_pool: &P,
    ) -> Result<RevealGossipOutcome>
    where
        P: RevealPoolSink,
    {
        let message = GossipMessage::Reveal(payload.to_vec());
        self.handle_message(peer_id, message)?;

        reveal_pool.insert_reveal_payload(payload, Some(peer_id.to_string()))?;

        Ok(RevealGossipOutcome {
            reveal_payload: payload.to_vec(),
            inserted: true,
            rebroadcast: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_block_gossip_message<P, L, C, V, S, Q>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        block_pool: &P,
        parent_lookup: &L,
        consensus: &C,
        signature_verifier: &V,
        proof_verifier: &impl BlockProofVerifier,
        validator_set_verifier: &S,
        quorum_certificate_verifier: &Q,
    ) -> Result<BlockGossipOutcome>
    where
        P: BlockPoolSink,
        L: BlockParentLookup,
        C: BlockConsensusSink,
        V: BlockSignatureVerifier,
        S: BlockValidatorSetVerifier,
        Q: BlockQuorumCertificateVerifier,
    {
        let message = GossipMessage::Block(payload.to_vec());
        self.handle_message(peer_id, message.clone())?;

        let block = Self::decode_block_payload(payload)?;
        Self::verify_block_header_hash(&block)?;
        Self::validate_block_structure(&block)?;
        Self::check_parent_block_availability(&block, parent_lookup)?;
        Self::validate_block_validator_root(&block, validator_set_verifier)?;
        Self::validate_block_quorum_certificate(&block, quorum_certificate_verifier)?;
        Self::validate_block_proof(&block, proof_verifier)?;

        let block_hash = block.try_hash()?;
        if block_pool.contains_block(&block_hash)? {
            return Ok(BlockGossipOutcome {
                block,
                inserted: false,
                forwarded_to_consensus: false,
                rebroadcast: None,
            });
        }

        Self::verify_block_signature(&block, signature_verifier)?;
        block_pool.insert_block(block.clone())?;
        consensus.forward_block_to_consensus(block.clone())?;

        Ok(BlockGossipOutcome {
            block,
            inserted: true,
            forwarded_to_consensus: true,
            rebroadcast: Some(self.propagate_message(message)),
        })
    }

    pub fn verify_block_header_hash(block: &Block) -> Result<()> {
        let computed_hash = block.header.try_hash()?;
        if block.try_hash()? != computed_hash {
            bail!("block header hash mismatch");
        }
        Ok(())
    }

    pub fn validate_block_structure(block: &Block) -> Result<()> {
        block.validate_basic()?;
        if block.chain_id() != sxiaum_types::SXIAUM_CHAIN_ID {
            bail!(
                "block chain_id mismatch: expected {}, got {}",
                sxiaum_types::SXIAUM_CHAIN_ID,
                block.chain_id()
            );
        }
        if !block.verify_block_structure() {
            bail!("invalid block structure");
        }
        Ok(())
    }

    pub fn check_parent_block_availability<L>(block: &Block, parent_lookup: &L) -> Result<()>
    where
        L: BlockParentLookup,
    {
        if block.is_genesis() {
            return Ok(());
        }

        if !parent_lookup.has_block(&block.parent_hash())? {
            bail!("parent block is unavailable");
        }

        Ok(())
    }

    pub fn verify_block_signature<V>(block: &Block, signature_verifier: &V) -> Result<()>
    where
        V: BlockSignatureVerifier,
    {
        if !signature_verifier.verify_block_signature(block)? {
            bail!("invalid block signature");
        }
        Ok(())
    }

    pub fn validate_block_proof<V>(block: &Block, proof_verifier: &V) -> Result<()>
    where
        V: BlockProofVerifier,
    {
        if !block.has_zk_proof() {
            bail!("block is missing zk proof");
        }

        if !proof_verifier.verify_block_proof(block)? {
            bail!("invalid block zk proof");
        }

        Ok(())
    }

    pub fn validate_block_validator_root<V>(block: &Block, validator_set_verifier: &V) -> Result<()>
    where
        V: BlockValidatorSetVerifier,
    {
        let validators = validator_set_verifier.active_validators()?;
        let expected_root = BlockBody::compute_validator_root(&validators)?;
        if block.header.validator_root != expected_root {
            bail!("block validator root mismatch");
        }
        Ok(())
    }

    pub fn validate_block_quorum_certificate<V>(block: &Block, verifier: &V) -> Result<()>
    where
        V: BlockQuorumCertificateVerifier,
    {
        if !verifier.verify_block_quorum_certificate(block)? {
            bail!("invalid block quorum certificate");
        }
        Ok(())
    }

    fn decode_block_payload(payload: &[u8]) -> Result<Block> {
        bincode::deserialize(payload)
            .or_else(|_| Block::decode_network(payload))
            .context("invalid block gossip payload")
    }

    pub fn receive_vote_gossip_message<C, V>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        consensus: &C,
        signature_verifier: &V,
    ) -> Result<VoteGossipOutcome>
    where
        C: VoteConsensusSink,
        V: VoteSignatureVerifier,
    {
        let message = GossipMessage::Vote(payload.to_vec());
        self.handle_message(peer_id, message)?;

        let vote = Self::decode_vote_payload(payload)?;
        Self::validate_vote_signature(&vote, signature_verifier)?;
        consensus.forward_vote_to_consensus(vote.clone())?;

        Ok(VoteGossipOutcome {
            vote,
            forwarded_to_consensus: true,
        })
    }

    pub fn receive_quorum_certificate_gossip_message<C, V, B>(
        &mut self,
        peer_id: PeerId,
        payload: &[u8],
        consensus: &C,
        verifier: &V,
        broadcaster: &B,
    ) -> Result<QuorumCertificateGossipOutcome>
    where
        C: QuorumCertificateConsensusSink,
        V: QuorumCertificateVerifier,
        B: QuorumCertificateBroadcaster,
    {
        let message = GossipMessage::QuorumCertificate(payload.to_vec());
        self.handle_message(peer_id, message.clone())?;

        let quorum_certificate = Self::decode_quorum_certificate_payload(payload)?;
        Self::validate_quorum_certificate(&quorum_certificate, verifier)?;
        consensus.forward_quorum_certificate_to_consensus(quorum_certificate.clone())?;
        broadcaster.broadcast_quorum_certificate(&quorum_certificate)?;

        Ok(QuorumCertificateGossipOutcome {
            quorum_certificate,
            forwarded_to_consensus: true,
            broadcast_to_validators: true,
            rebroadcast: Some(self.propagate_message(message)),
        })
    }

    pub fn validate_vote_signature<V>(vote: &Vote, signature_verifier: &V) -> Result<()>
    where
        V: VoteSignatureVerifier,
    {
        if !signature_verifier.verify_vote_signature(vote)? {
            bail!("invalid vote signature");
        }
        Ok(())
    }

    pub fn validate_quorum_certificate<V>(qc: &QuorumCertificate, verifier: &V) -> Result<()>
    where
        V: QuorumCertificateVerifier,
    {
        if !verifier.verify_quorum_certificate(qc)? {
            bail!("invalid quorum certificate aggregated signatures");
        }
        Ok(())
    }

    fn decode_vote_payload(payload: &[u8]) -> Result<Vote> {
        Vote::decode(payload).context("invalid vote gossip payload")
    }

    fn decode_quorum_certificate_payload(payload: &[u8]) -> Result<QuorumCertificate> {
        QuorumCertificate::decode(payload).context("invalid quorum certificate gossip payload")
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{
        BlockConsensusSink, BlockParentLookup, BlockPoolSink, BlockProofVerifier,
        BlockQuorumCertificateVerifier, BlockSignatureVerifier, BlockValidatorSetVerifier, Gossip,
        GossipMessage, MessageValidationFailure, QuorumCertificateBroadcaster,
        QuorumCertificateConsensusSink, QuorumCertificateVerifier, TransactionGossipOutcome,
        TransactionPoolSink, TransactionSignatureVerifier, VoteConsensusSink,
        VoteSignatureVerifier, TOPIC_BLOCKS, TOPIC_QUORUM_CERTIFICATES, TOPIC_STATE_SYNC,
        TOPIC_TRANSACTIONS, TOPIC_VOTES,
    };
    use anyhow::Result;
    use libp2p::{identity::Keypair, PeerId};
    use primitive_types::U256;
    use std::cell::RefCell;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_consensus::hotstuff::vote::{QuorumCertificate, Vote};
    use sxiaum_types::MAX_CANONICAL_MESSAGE_SIZE;
    use sxiaum_types::{Address, Transaction, Validator};

    #[derive(Default)]
    struct MockTransactionPool {
        seen_hashes: RefCell<std::collections::HashSet<[u8; 32]>>,
        inserted: RefCell<Vec<(Transaction, Option<String>)>>,
    }

    impl TransactionPoolSink for MockTransactionPool {
        fn contains_transaction(&self, tx: &Transaction) -> Result<bool> {
            Ok(self.seen_hashes.borrow().contains(&tx.try_hash()?))
        }

        fn insert_transaction(&self, tx: Transaction, source_peer: Option<String>) -> Result<()> {
            self.seen_hashes.borrow_mut().insert(tx.try_hash()?);
            self.inserted.borrow_mut().push((tx, source_peer));
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockTransactionVerifier {
        valid: bool,
    }

    impl TransactionSignatureVerifier for MockTransactionVerifier {
        fn verify_transaction_signature(&self, _tx: &Transaction) -> Result<bool> {
            Ok(self.valid)
        }
    }

    #[derive(Default)]
    struct MockBlockPool {
        known: RefCell<std::collections::HashSet<[u8; 32]>>,
        inserted: RefCell<Vec<Block>>,
    }

    impl BlockPoolSink for MockBlockPool {
        fn contains_block(&self, hash: &[u8; 32]) -> Result<bool> {
            Ok(self.known.borrow().contains(hash))
        }

        fn insert_block(&self, block: Block) -> Result<()> {
            self.known
                .borrow_mut()
                .insert(block.try_hash().unwrap_or_default());
            self.inserted.borrow_mut().push(block);
            Ok(())
        }
    }

    struct MockParentLookup {
        available: bool,
    }

    impl BlockParentLookup for MockParentLookup {
        fn has_block(&self, _hash: &[u8; 32]) -> Result<bool> {
            Ok(self.available)
        }
    }

    #[derive(Default)]
    struct MockBlockConsensus {
        forwarded: RefCell<Vec<Block>>,
    }

    impl BlockConsensusSink for MockBlockConsensus {
        fn forward_block_to_consensus(&self, block: Block) -> Result<()> {
            self.forwarded.borrow_mut().push(block);
            Ok(())
        }
    }

    struct MockBlockVerifier {
        valid: bool,
    }

    impl BlockSignatureVerifier for MockBlockVerifier {
        fn verify_block_signature(&self, _block: &Block) -> Result<bool> {
            Ok(self.valid)
        }
    }

    struct MockProofVerifier {
        valid: bool,
    }

    impl BlockProofVerifier for MockProofVerifier {
        fn verify_block_proof(&self, _block: &Block) -> Result<bool> {
            Ok(self.valid)
        }
    }

    struct MockValidatorSetVerifier {
        validators: Vec<Validator>,
    }

    impl BlockValidatorSetVerifier for MockValidatorSetVerifier {
        fn active_validators(&self) -> Result<Vec<Validator>> {
            Ok(self.validators.clone())
        }
    }

    struct MockBlockQcVerifier {
        valid: bool,
    }

    impl BlockQuorumCertificateVerifier for MockBlockQcVerifier {
        fn verify_block_quorum_certificate(&self, _block: &Block) -> Result<bool> {
            Ok(self.valid)
        }
    }

    #[derive(Default)]
    struct MockVoteConsensus {
        forwarded: RefCell<Vec<Vote>>,
    }

    impl VoteConsensusSink for MockVoteConsensus {
        fn forward_vote_to_consensus(&self, vote: Vote) -> Result<()> {
            self.forwarded.borrow_mut().push(vote);
            Ok(())
        }
    }

    struct MockVoteVerifier {
        valid: bool,
    }

    impl VoteSignatureVerifier for MockVoteVerifier {
        fn verify_vote_signature(&self, _vote: &Vote) -> Result<bool> {
            Ok(self.valid)
        }
    }

    #[derive(Default)]
    struct MockQcConsensus {
        forwarded: RefCell<Vec<QuorumCertificate>>,
    }

    impl QuorumCertificateConsensusSink for MockQcConsensus {
        fn forward_quorum_certificate_to_consensus(&self, qc: QuorumCertificate) -> Result<()> {
            self.forwarded.borrow_mut().push(qc);
            Ok(())
        }
    }

    struct MockQcVerifier {
        valid: bool,
    }

    impl QuorumCertificateVerifier for MockQcVerifier {
        fn verify_quorum_certificate(&self, _qc: &QuorumCertificate) -> Result<bool> {
            Ok(self.valid)
        }
    }

    #[derive(Default)]
    struct MockQcBroadcaster {
        broadcasted: RefCell<Vec<QuorumCertificate>>,
    }

    impl QuorumCertificateBroadcaster for MockQcBroadcaster {
        fn broadcast_quorum_certificate(&self, qc: &QuorumCertificate) -> Result<()> {
            self.broadcasted.borrow_mut().push(qc.clone());
            Ok(())
        }
    }

    fn peer_id(seed: u8) -> PeerId {
        let mut bytes = [seed; 32];
        bytes[0] = bytes[0].max(1);
        PeerId::from(
            Keypair::ed25519_from_bytes(bytes)
                .expect("keypair should build")
                .public(),
        )
    }

    fn signed_transaction(seed: u8, nonce: u64) -> Transaction {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let from = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(
            from,
            Address([seed.saturating_add(1); 32]),
            U256::from(1u64),
            nonce,
        );
        tx.sign(&signing_key).expect("transaction should sign");
        tx
    }

    fn signed_vote(seed: u8, block_hash: [u8; 32], view: u64) -> Vote {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let validator = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut vote = Vote::new(validator, block_hash, view);
        vote.sign(&signing_key).expect("vote should sign");
        vote
    }

    fn gossip_block(parent_hash: [u8; 32], height: u64) -> Block {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut validator = sxiaum_types::Validator::new(
            proposer,
            signing_key.verifying_key().to_bytes(),
            U256::from(10u64.pow(18)),
        );
        validator.status = sxiaum_types::validator::ValidatorStatus::Active;
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        header.validator_root =
            BlockBody::compute_validator_root(&[validator]).expect("validator root");
        let mut block = Block::new(header, BlockBody::empty());
        block.try_compute_roots().expect("compute roots");
        block.attach_validity_proof(vec![1, 2, 3]);
        block.header.sign(&signing_key).expect("block should sign");
        block
    }

    #[test]
    fn new_subscribe_and_unsubscribe_manage_topics() {
        let mut gossip = Gossip::new();

        assert!(gossip.topic_subscriptions.is_empty());
        assert!(gossip.subscribe(TOPIC_BLOCKS));
        assert_eq!(TOPIC_TRANSACTIONS, "l1/txs");
        assert_eq!(TOPIC_BLOCKS, "l1/blocks");
        assert_eq!(TOPIC_VOTES, "l1/votes");
        assert_eq!(TOPIC_QUORUM_CERTIFICATES, "l1/quorum_certificates");
        assert_eq!(TOPIC_STATE_SYNC, "l1/state_sync");
        assert!(!gossip.subscribe(TOPIC_BLOCKS));
        assert!(gossip.topic_subscriptions.contains(TOPIC_BLOCKS));
        assert!(gossip.unsubscribe(TOPIC_BLOCKS));
        assert!(!gossip.unsubscribe(TOPIC_BLOCKS));
    }

    #[test]
    fn publish_validates_caches_and_rejects_duplicates() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_TRANSACTIONS);
        let message = GossipMessage::Transaction(vec![1, 2, 3]);

        let propagated = gossip
            .publish(TOPIC_TRANSACTIONS, message.clone())
            .expect("publish should succeed");
        assert!(matches!(propagated, GossipMessage::Transaction(bytes) if bytes == vec![1, 2, 3]));

        assert!(gossip.publish(TOPIC_TRANSACTIONS, message).is_err());
    }

    #[test]
    fn handle_message_applies_rate_limit_validation_and_deduplication() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_STATE_SYNC);
        let peer = peer_id(1);
        let message = GossipMessage::StateSync(vec![9, 9, 9]);

        let propagated = gossip
            .handle_message(peer, message.clone())
            .expect("handle message should succeed");
        assert!(matches!(propagated, GossipMessage::StateSync(bytes) if bytes == vec![9, 9, 9]));

        let duplicate = gossip
            .handle_message(peer, message)
            .expect_err("duplicate should fail");
        assert_eq!(
            Gossip::classify_message_error(&duplicate),
            MessageValidationFailure::DuplicateMessage
        );
    }

    #[test]
    fn validate_message_rejects_empty_oversized_and_unsubscribed_payloads() {
        let mut gossip = Gossip::new();
        let unsubscribed = GossipMessage::Block(vec![1]);
        let unsubscribed_error = gossip
            .validate_message(&unsubscribed)
            .expect_err("unsubscribed topic should fail");
        assert_eq!(
            Gossip::classify_message_error(&unsubscribed_error),
            MessageValidationFailure::UnsubscribedTopic
        );

        gossip.subscribe(TOPIC_BLOCKS);
        let empty = GossipMessage::Block(Vec::new());
        let empty_error = gossip
            .validate_message(&empty)
            .expect_err("empty payload should fail");
        assert_eq!(
            Gossip::classify_message_error(&empty_error),
            MessageValidationFailure::EmptyPayload
        );

        let oversized = GossipMessage::Block(vec![7u8; MAX_CANONICAL_MESSAGE_SIZE + 1]);
        let oversized_error = gossip
            .validate_message(&oversized)
            .expect_err("oversized payload should fail");
        assert_eq!(
            Gossip::classify_message_error(&oversized_error),
            MessageValidationFailure::MessageTooLarge
        );
    }

    #[test]
    fn propagate_and_deduplicate_return_expected_values() {
        let mut gossip = Gossip::new();
        let message = GossipMessage::StateSync(vec![4, 5]);

        let propagated = gossip.propagate_message(message.clone());
        assert!(matches!(propagated, GossipMessage::StateSync(bytes) if bytes == vec![4, 5]));

        assert!(!gossip.deduplicate_messages(&message));
        assert!(gossip.deduplicate_messages(&message));
    }

    #[test]
    fn message_cache_eviction_and_rate_limit_work() {
        let mut gossip = Gossip::new();
        for index in 0..1025 {
            let msg = GossipMessage::Transaction(vec![index as u8]);
            gossip.message_cache(&msg);
        }
        assert_eq!(gossip.cached_hashes.len(), 1024);
        let first_expected_hash = Gossip::message_hash(&GossipMessage::Transaction(vec![1]));
        assert_eq!(
            gossip.cached_hashes.front().copied(),
            Some(first_expected_hash)
        );

        let peer = peer_id(2);
        for _ in 0..128 {
            assert!(gossip.rate_limit_messages(peer));
        }
        assert!(!gossip.rate_limit_messages(peer));
    }

    #[test]
    fn drop_invalid_messages_returns_categorized_error() {
        let gossip = Gossip::new();
        let error = gossip
            .drop_invalid_messages::<()>(MessageValidationFailure::InvalidPayload)
            .expect_err("invalid message drop should return an error");

        assert_eq!(
            Gossip::classify_message_error(&error),
            MessageValidationFailure::InvalidPayload
        );
    }

    #[test]
    fn receive_transaction_gossip_validates_verifies_inserts_and_deduplicates() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_TRANSACTIONS);
        let pool = MockTransactionPool::default();
        let verifier = MockTransactionVerifier { valid: true };
        let peer = peer_id(3);
        let tx = signed_transaction(4, 0);
        let payload = bincode::serialize(&tx).expect("transaction should serialize");

        let outcome: TransactionGossipOutcome = gossip
            .receive_transaction_gossip_message(peer, &payload, &pool, &verifier)
            .expect("transaction gossip should succeed");
        assert!(outcome.inserted);
        assert_eq!(
            outcome.transaction.try_hash().unwrap(),
            tx.try_hash().unwrap()
        );
        assert!(outcome.rebroadcast.is_none());
        assert_eq!(pool.inserted.borrow().len(), 1);
        assert_eq!(
            pool.inserted.borrow()[0].1.as_deref(),
            Some(peer.to_string().as_str())
        );

        let duplicate = gossip
            .receive_transaction_gossip_message(peer, &payload, &pool, &verifier)
            .expect_err("duplicate gossip should be rejected by message deduplication");
        assert_eq!(
            Gossip::classify_message_error(&duplicate),
            MessageValidationFailure::DuplicateMessage
        );
    }

    #[test]
    fn transaction_gossip_rejects_bad_format_and_bad_signature() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_TRANSACTIONS);
        let pool = MockTransactionPool::default();
        let peer = peer_id(4);

        let mut unsigned_tx =
            Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
        unsigned_tx.signer_pubkey = Some([1u8; 32]);
        let unsigned_payload =
            bincode::serialize(&unsigned_tx).expect("unsigned tx should serialize");
        assert!(gossip
            .receive_transaction_gossip_message(
                peer,
                &unsigned_payload,
                &pool,
                &MockTransactionVerifier { valid: true }
            )
            .is_err());

        let signed_tx = signed_transaction(5, 1);
        let signed_payload = bincode::serialize(&signed_tx).expect("signed tx should serialize");
        assert!(gossip
            .receive_transaction_gossip_message(
                peer_id(5),
                &signed_payload,
                &pool,
                &MockTransactionVerifier { valid: false }
            )
            .is_err());
    }

    #[test]
    fn receive_block_gossip_validates_inserts_forwards_and_rebroadcasts() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_BLOCKS);
        let pool = MockBlockPool::default();
        let parent_lookup = MockParentLookup { available: true };
        let consensus = MockBlockConsensus::default();
        let verifier = MockBlockVerifier { valid: true };
        let proof_verifier = MockProofVerifier { valid: true };
        let validator_set_verifier = MockValidatorSetVerifier {
            validators: vec![{
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
                let mut validator = sxiaum_types::Validator::new(
                    Address::from_public_key(&signing_key.verifying_key().to_bytes()),
                    signing_key.verifying_key().to_bytes(),
                    U256::from(10u64.pow(18)),
                );
                validator.status = sxiaum_types::validator::ValidatorStatus::Active;
                validator
            }],
        };
        let qc_verifier = MockBlockQcVerifier { valid: true };
        let block = gossip_block([9u8; 32], 2);
        let payload = bincode::serialize(&block).expect("block should serialize");

        let outcome = gossip
            .receive_block_gossip_message(
                peer_id(6),
                &payload,
                &pool,
                &parent_lookup,
                &consensus,
                &verifier,
                &proof_verifier,
                &validator_set_verifier,
                &qc_verifier,
            )
            .expect("block gossip should succeed");

        assert!(outcome.inserted);
        assert!(outcome.forwarded_to_consensus);
        assert_eq!(pool.inserted.borrow().len(), 1);
        assert_eq!(consensus.forwarded.borrow().len(), 1);
        assert!(
            matches!(outcome.rebroadcast, Some(GossipMessage::Block(bytes)) if bytes == payload)
        );
    }

    #[test]
    fn block_gossip_checks_parent_signature_and_proof() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_BLOCKS);
        let block = gossip_block([5u8; 32], 3);
        let payload = bincode::serialize(&block).expect("block should serialize");
        let pool = MockBlockPool::default();
        let consensus = MockBlockConsensus::default();
        let validator_set_verifier = MockValidatorSetVerifier {
            validators: vec![{
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
                let mut validator = sxiaum_types::Validator::new(
                    Address::from_public_key(&signing_key.verifying_key().to_bytes()),
                    signing_key.verifying_key().to_bytes(),
                    U256::from(10u64.pow(18)),
                );
                validator.status = sxiaum_types::validator::ValidatorStatus::Active;
                validator
            }],
        };

        assert!(gossip
            .receive_block_gossip_message(
                peer_id(7),
                &payload,
                &pool,
                &MockParentLookup { available: false },
                &consensus,
                &MockBlockVerifier { valid: true },
                &MockProofVerifier { valid: true },
                &validator_set_verifier,
                &MockBlockQcVerifier { valid: true }
            )
            .is_err());
        assert!(gossip
            .receive_block_gossip_message(
                peer_id(8),
                &payload,
                &pool,
                &MockParentLookup { available: true },
                &consensus,
                &MockBlockVerifier { valid: false },
                &MockProofVerifier { valid: true },
                &validator_set_verifier,
                &MockBlockQcVerifier { valid: true }
            )
            .is_err());
        assert!(gossip
            .receive_block_gossip_message(
                peer_id(9),
                &payload,
                &pool,
                &MockParentLookup { available: true },
                &consensus,
                &MockBlockVerifier { valid: true },
                &MockProofVerifier { valid: false },
                &validator_set_verifier,
                &MockBlockQcVerifier { valid: true }
            )
            .is_err());
        assert!(gossip
            .receive_block_gossip_message(
                peer_id(10),
                &payload,
                &pool,
                &MockParentLookup { available: true },
                &consensus,
                &MockBlockVerifier { valid: true },
                &MockProofVerifier { valid: true },
                &validator_set_verifier,
                &MockBlockQcVerifier { valid: false }
            )
            .is_err());
    }

    #[test]
    fn receive_vote_gossip_validates_and_forwards_votes() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_VOTES);
        let consensus = MockVoteConsensus::default();
        let vote = signed_vote(8, [3u8; 32], 4);
        let payload = vote.encode();

        let outcome = gossip
            .receive_vote_gossip_message(
                peer_id(10),
                &payload,
                &consensus,
                &MockVoteVerifier { valid: true },
            )
            .expect("vote gossip should succeed");

        assert!(outcome.forwarded_to_consensus);
        assert_eq!(outcome.vote.block_hash, vote.block_hash);
        assert_eq!(consensus.forwarded.borrow().len(), 1);
        assert!(gossip
            .receive_vote_gossip_message(
                peer_id(11),
                &payload,
                &consensus,
                &MockVoteVerifier { valid: false }
            )
            .is_err());
    }

    #[test]
    fn receive_quorum_certificate_validates_forwards_broadcasts_and_rebroadcasts() {
        let mut gossip = Gossip::new();
        gossip.subscribe(TOPIC_QUORUM_CERTIFICATES);
        let consensus = MockQcConsensus::default();
        let broadcaster = MockQcBroadcaster::default();
        let vote = signed_vote(9, [4u8; 32], 5);
        let qc = QuorumCertificate::new(
            vote.block_hash,
            vote.view,
            vec![vote.signature.to_vec()],
            vec![vote.validator],
        );
        let payload = qc.encode();

        let outcome = gossip
            .receive_quorum_certificate_gossip_message(
                peer_id(12),
                &payload,
                &consensus,
                &MockQcVerifier { valid: true },
                &broadcaster,
            )
            .expect("qc gossip should succeed");

        assert!(outcome.forwarded_to_consensus);
        assert!(outcome.broadcast_to_validators);
        assert_eq!(consensus.forwarded.borrow().len(), 1);
        assert_eq!(broadcaster.broadcasted.borrow().len(), 1);
        assert!(
            matches!(outcome.rebroadcast, Some(GossipMessage::QuorumCertificate(bytes)) if bytes == payload)
        );

        assert!(gossip
            .receive_quorum_certificate_gossip_message(
                peer_id(13),
                &payload,
                &consensus,
                &MockQcVerifier { valid: false },
                &broadcaster
            )
            .is_err());
    }
}
