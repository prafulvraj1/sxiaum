use crate::{Canonical, Transaction};
use serde::{Deserialize, Serialize};
pub const CANONICAL_MESSAGE_VERSION: u8 = 1;
pub const MAX_CANONICAL_MESSAGE_SIZE: usize = 2 * 1024 * 1024;
pub const MAX_HEADERS_PER_MESSAGE: u64 = 512;
pub const MAX_SYNC_BLOCKS_PER_MESSAGE: u64 = 512;
pub const MAX_CONSENSUS_SIGNATURES: usize = 512;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkMessage {
    GossipTransaction(Box<Transaction>),
    GossipProposedBlock(Vec<u8>),
    ConsensusVote {
        validator: [u8; 32],
        block_hash: [u8; 32],
        signature: Vec<u8>,
    },
    ConsensusProposal {
        block_bytes: Vec<u8>,
        view: u64,
        proposer: [u8; 32],
        signature: Vec<u8>,
    },
    TimeoutCertificate {
        view: u64,
        signatures: Vec<([u8; 32], Vec<u8>)>,
    },
    GetBlockHeaders {
        start_height: u64,
        limit: u64,
    },
    BlockHeaders(Vec<Vec<u8>>),
    SyncRequest {
        from_height: u64,
        max_blocks: u64,
    },
    SyncResponse {
        blocks: Vec<Vec<u8>>,
    },
    GetStateProof(Vec<u8>),
    StateProof(Vec<u8>),
}
impl NetworkMessage {
    pub fn try_encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate()?;
        <Self as Canonical>::try_encode(self)
    }
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() > MAX_CANONICAL_MESSAGE_SIZE {
            anyhow::bail!("network message exceeds maximum size");
        }
        let msg = <Self as Canonical>::decode(bytes)?;
        msg.validate()?;
        Ok(msg)
    }
    pub fn try_hash(&self) -> anyhow::Result<[u8; 32]> {
        self.validate()?;
        <Self as Canonical>::try_hash(self)
    }
    #[cfg(test)]
    pub fn hash(&self) -> [u8; 32] {
        self.try_hash().unwrap()
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            NetworkMessage::GossipTransaction(tx) => {
                let size = tx.size_bytes()?;
                if size > MAX_CANONICAL_MESSAGE_SIZE {
                    anyhow::bail!("transaction gossip exceeds maximum size");
                }
                tx.validate_basic()?;
                Ok(())
            }
            NetworkMessage::GossipProposedBlock(bytes) => {
                if bytes.is_empty() {
                    anyhow::bail!("proposed block must not be empty");
                }
                if bytes.len() > MAX_CANONICAL_MESSAGE_SIZE {
                    anyhow::bail!("proposed block exceeds maximum size");
                }
                Ok(())
            }
            NetworkMessage::ConsensusVote {
                validator: _,
                block_hash: _,
                signature,
            } => {
                if signature.len() != 64 {
                    anyhow::bail!("consensus vote signature must be 64 bytes");
                }
                Ok(())
            }
            NetworkMessage::ConsensusProposal {
                block_bytes,
                view: _,
                proposer: _,
                signature,
            } => {
                if block_bytes.is_empty() {
                    anyhow::bail!("proposal block must not be empty");
                }
                if block_bytes.len() > MAX_CANONICAL_MESSAGE_SIZE {
                    anyhow::bail!("proposal block exceeds maximum size");
                }
                if signature.len() != 64 {
                    anyhow::bail!("proposal signature must be 64 bytes");
                }
                Ok(())
            }
            NetworkMessage::TimeoutCertificate { view: _, signatures } => {
                if signatures.is_empty() {
                    anyhow::bail!("timeout certificate must carry signatures");
                }
                if signatures.len() > MAX_CONSENSUS_SIGNATURES {
                    anyhow::bail!("timeout certificate carries too many signatures");
                }
                for (_, sig) in signatures {
                    if sig.len() != 64 {
                        anyhow::bail!("timeout signature must be 64 bytes");
                    }
                }
                Ok(())
            }
            NetworkMessage::GetBlockHeaders { start_height: _, limit } => {
                if *limit == 0 || *limit > MAX_HEADERS_PER_MESSAGE {
                    anyhow::bail!("headers limit out of bounds");
                }
                Ok(())
            }
            NetworkMessage::BlockHeaders(headers) => {
                if headers.len() as u64 > MAX_HEADERS_PER_MESSAGE {
                    anyhow::bail!("too many headers in message");
                }
                for h in headers {
                    if h.is_empty() {
                        anyhow::bail!("header entry must not be empty");
                    }
                    if h.len() > MAX_CANONICAL_MESSAGE_SIZE {
                        anyhow::bail!("header entry too large");
                    }
                }
                Ok(())
            }
            NetworkMessage::SyncRequest { from_height: _, max_blocks } => {
                if *max_blocks == 0 || *max_blocks > MAX_SYNC_BLOCKS_PER_MESSAGE {
                    anyhow::bail!("sync max_blocks out of bounds");
                }
                Ok(())
            }
            NetworkMessage::SyncResponse { blocks } => {
                if blocks.len() as u64 > MAX_SYNC_BLOCKS_PER_MESSAGE {
                    anyhow::bail!("too many blocks in sync response");
                }
                for b in blocks {
                    if b.is_empty() {
                        anyhow::bail!("sync block must not be empty");
                    }
                    if b.len() > MAX_CANONICAL_MESSAGE_SIZE {
                        anyhow::bail!("sync block too large");
                    }
                }
                Ok(())
            }
            NetworkMessage::GetStateProof(key) => {
                if key.is_empty() {
                    anyhow::bail!("state proof request must not be empty");
                }
                if key.len() > MAX_CANONICAL_MESSAGE_SIZE {
                    anyhow::bail!("state proof request too large");
                }
                Ok(())
            }
            NetworkMessage::StateProof(proof) => {
                if proof.is_empty() {
                    anyhow::bail!("state proof must not be empty");
                }
                if proof.len() > MAX_CANONICAL_MESSAGE_SIZE {
                    anyhow::bail!("state proof too large");
                }
                Ok(())
            }
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CanonicalMessage {
    pub version: u8,
    pub compressed: bool,
    pub payload: Vec<u8>,
}
impl CanonicalMessage {
    pub fn new(payload: Vec<u8>) -> anyhow::Result<Self> {
        if payload.len() > MAX_CANONICAL_MESSAGE_SIZE {
            anyhow::bail!("payload exceeds maximum canonical size");
        }
        let compressed_payload = compress_payload(&payload);
        let (compressed, payload) = if compressed_payload.len() < payload.len() {
            (true, compressed_payload)
        } else {
            (false, payload)
        };
        let message = Self {
            version: CANONICAL_MESSAGE_VERSION,
            compressed,
            payload,
        };
        message.validate_size()?;
        Ok(message)
    }
    pub fn from_network_message(message: &NetworkMessage) -> anyhow::Result<Self> {
        let payload = message.try_encode()?;
        Self::new(payload)
    }
    pub fn to_network_message(&self) -> anyhow::Result<NetworkMessage> {
        if self.version != CANONICAL_MESSAGE_VERSION {
            anyhow::bail!("unsupported canonical message version {}", self.version);
        }
        let payload = if self.compressed {
            decompress_payload(&self.payload)?
        } else {
            self.payload.clone()
        };
        NetworkMessage::decode(&payload)
    }
    pub fn try_encode(&self) -> anyhow::Result<Vec<u8>> {
        self.validate_size()?;
        <Self as Canonical>::try_encode(self)
    }
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let message = <Self as Canonical>::decode(bytes)?;
        message.validate_size()?;
        Ok(message)
    }
    pub fn validate_size(&self) -> anyhow::Result<()> {
        if self.payload.len() > MAX_CANONICAL_MESSAGE_SIZE {
            anyhow::bail!(
                "canonical message payload exceeds max size: {} > {}",
                self.payload.len(),
                MAX_CANONICAL_MESSAGE_SIZE
            );
        }
        Ok(())
    }
}
fn compress_payload(payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return Vec::new();
    }
    let mut compressed = Vec::with_capacity(payload.len());
    let mut index = 0usize;
    while index < payload.len() {
        let byte = payload[index];
        let mut run_len = 1u8;
        while index + (run_len as usize) < payload.len()
            && payload[index + (run_len as usize)] == byte
            && run_len < u8::MAX
        {
            run_len = run_len.saturating_add(1);
        }
        compressed.push(run_len);
        compressed.push(byte);
        index += run_len as usize;
    }
    compressed
}
fn decompress_payload(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if !payload.len().is_multiple_of(2) {
        anyhow::bail!("invalid compressed payload length");
    }
    let mut decompressed = Vec::new();
    for chunk in payload.chunks_exact(2) {
        let run_len = chunk[0] as usize;
        let byte = chunk[1];
        if run_len == 0 {
            anyhow::bail!("invalid compressed payload run length");
        }
        if decompressed.len().saturating_add(run_len) > MAX_CANONICAL_MESSAGE_SIZE {
            anyhow::bail!("decompressed payload exceeds max canonical message size");
        }
        decompressed.extend(std::iter::repeat_n(byte, run_len));
    }
    Ok(decompressed)
}
#[cfg(test)]
mod tests {
    use super::{
        CanonicalMessage, NetworkMessage, CANONICAL_MESSAGE_VERSION, MAX_CANONICAL_MESSAGE_SIZE,
        MAX_HEADERS_PER_MESSAGE, MAX_SYNC_BLOCKS_PER_MESSAGE,
    };
    use crate::{Address, Transaction};
    use ed25519_dalek::SigningKey;
    use primitive_types::U256;
    fn signed_tx() -> Transaction {
        let sk = SigningKey::from_bytes(&[77u8; 32]);
        let from = Address::from_public_key(&sk.verifying_key().to_bytes());
        let mut tx = Transaction::new_transfer(from, Address([2u8; 32]), U256::from(10u64), 4);
        tx.sign(&sk).expect("sign");
        tx
    }
    fn assert_canonical_round_trip(original: NetworkMessage) {
        let canonical = CanonicalMessage::from_network_message(&original)
            .expect("canonical message creation should succeed");
        let encoded = canonical
            .try_encode()
            .expect("canonical encode should succeed");
        let decoded = CanonicalMessage::decode(&encoded).expect("canonical decode should succeed");
        let restored = decoded
            .to_network_message()
            .expect("network message should restore");
        assert_eq!(decoded.version, CANONICAL_MESSAGE_VERSION);
        assert_eq!(
            restored.try_encode().unwrap(),
            original.try_encode().unwrap()
        );
        assert_eq!(restored, original);
    }
    #[test]
    fn canonical_message_round_trips_network_payloads() {
        let tx = signed_tx();
        assert_canonical_round_trip(NetworkMessage::GossipTransaction(Box::new(tx)));
    }
    #[test]
    fn canonical_message_encoding_is_deterministic() {
        let message = CanonicalMessage::new(vec![7u8; 32]).expect("message should build");
        let first = message.try_encode().expect("first encode should succeed");
        let second = message.try_encode().expect("second encode should succeed");
        let decoded = CanonicalMessage::decode(&first).expect("decode should succeed");
        assert_eq!(first, second);
        assert_eq!(decoded.version, CANONICAL_MESSAGE_VERSION);
        assert_eq!(decoded.compressed, message.compressed);
        assert_eq!(decoded.payload, message.payload);
    }
    #[test]
    fn network_message_hash_and_encode_are_deterministic() {
        let message = NetworkMessage::ConsensusVote {
            validator: [3u8; 32],
            block_hash: [4u8; 32],
            signature: vec![5u8; 64],
        };
        let first_encoded = message.try_encode().unwrap();
        let second_encoded = message.try_encode().unwrap();
        let decoded = NetworkMessage::decode(&first_encoded).expect("decode should succeed");
        assert_eq!(first_encoded, second_encoded);
        assert_eq!(message.try_hash().unwrap(), message.try_hash().unwrap());
        assert_eq!(decoded, message);
    }
    #[test]
    fn network_message_validation_is_fail_closed() {
        let bad_vote = NetworkMessage::ConsensusVote {
            validator: [1u8; 32],
            block_hash: [2u8; 32],
            signature: vec![1u8; 10],
        };
        assert!(bad_vote.validate().is_err());
        assert!(bad_vote.try_encode().is_err());
        let bad_headers = NetworkMessage::GetBlockHeaders { start_height: 0, limit: 0 };
        assert!(bad_headers.validate().is_err());
        let too_many = NetworkMessage::GetBlockHeaders { start_height: 0, limit: MAX_HEADERS_PER_MESSAGE + 1 };
        assert!(too_many.validate().is_err());
        let bad_sync = NetworkMessage::SyncRequest { from_height: 0, max_blocks: MAX_SYNC_BLOCKS_PER_MESSAGE + 1 };
        assert!(bad_sync.validate().is_err());
        let unsigned = Transaction::new_transfer(Address([1u8; 32]), Address([2u8; 32]), U256::from(1u64), 0);
        let gossip = NetworkMessage::GossipTransaction(Box::new(unsigned));
        assert!(gossip.validate().is_err());
        let empty_block = NetworkMessage::GossipProposedBlock(Vec::new());
        assert!(empty_block.validate().is_err());
    }
    #[test]
    fn canonical_message_prefers_compression_when_payload_shrinks() {
        let payload = vec![9u8; 512];
        let message = CanonicalMessage::new(payload.clone()).expect("message should build");
        assert!(message.compressed);
        assert!(message.payload.len() < payload.len());
        assert!(message.to_network_message().is_err());
    }
    #[test]
    fn canonical_message_bincode_round_trip_preserves_compression_metadata() {
        let network = NetworkMessage::BlockHeaders(vec![vec![1u8; 64], vec![2u8; 64]]);
        let canonical = CanonicalMessage::from_network_message(&network)
            .expect("canonical message creation should succeed");
        let encoded = canonical
            .try_encode()
            .expect("canonical encode should succeed");
        let decoded = CanonicalMessage::decode(&encoded).expect("canonical decode should succeed");
        let restored = decoded
            .to_network_message()
            .expect("network message should restore");
        assert_eq!(decoded.version, CANONICAL_MESSAGE_VERSION);
        assert_eq!(decoded.compressed, canonical.compressed);
        assert_eq!(decoded.payload, canonical.payload);
        assert_eq!(restored, network);
    }
    #[test]
    fn canonical_message_rejects_oversized_payloads_and_decompression_bombs() {
        let oversized = CanonicalMessage {
            version: CANONICAL_MESSAGE_VERSION,
            compressed: false,
            payload: vec![0u8; MAX_CANONICAL_MESSAGE_SIZE + 1],
        };
        assert!(oversized.validate_size().is_err());
        assert!(oversized.try_encode().is_err());
        let decompression_bomb = CanonicalMessage {
            version: CANONICAL_MESSAGE_VERSION,
            compressed: true,
            payload: vec![255, 1, 255, 1, 255, 1],
        };
        assert!(decompression_bomb.validate_size().is_ok());
        assert!(decompression_bomb.to_network_message().is_err());
    }
    #[test]
    fn canonical_message_round_trips_multiple_network_variants_exactly() {
        let tx = signed_tx();
        let cases = vec![
            NetworkMessage::GossipTransaction(Box::new(tx.clone())),
            NetworkMessage::GossipProposedBlock(vec![7u8; 256]),
            NetworkMessage::ConsensusVote {
                validator: [1u8; 32],
                block_hash: [2u8; 32],
                signature: vec![3u8; 64],
            },
            NetworkMessage::ConsensusProposal {
                block_bytes: vec![1, 2, 3],
                view: 10,
                proposer: [4u8; 32],
                signature: vec![5u8; 64],
            },
            NetworkMessage::TimeoutCertificate {
                view: 12,
                signatures: vec![([1u8; 32], vec![2u8; 64])],
            },
            NetworkMessage::GetBlockHeaders {
                start_height: 12,
                limit: 4,
            },
            NetworkMessage::BlockHeaders(vec![vec![4u8; 80], vec![5u8; 96]]),
            NetworkMessage::SyncRequest {
                from_height: 100,
                max_blocks: 50,
            },
            NetworkMessage::SyncResponse {
                blocks: vec![vec![1, 2, 3]],
            },
            NetworkMessage::GetStateProof(vec![6u8; 128]),
            NetworkMessage::StateProof(vec![7u8; 192]),
        ];
        for original in cases {
            assert_canonical_round_trip(original);
        }
    }
}
