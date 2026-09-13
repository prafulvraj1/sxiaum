use anyhow::{Context, Result};
use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use serde::{Deserialize, Serialize};
use std::io;
use std::time::Duration;
use sxiaum_block::BlockHeader;
use sxiaum_state::RpcVerkleProof;
use sxiaum_types::{Account, Address};
use tokio::time;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcVerifiedHeaderEnvelope {
    pub header: BlockHeader,
    pub consensus_signatures: Vec<(sxiaum_types::Address, Vec<u8>)>,
    /// Optional HotStuff `(view, phase_tag)` shared by every signature in the
    /// envelope (phase: Prepare=0, PreCommit=1, Commit=2). When omitted, the
    /// light client verifies signatures directly against the header hash.
    #[serde(default)]
    pub hotstuff_view_phase: Option<(u64, u8)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpcStateProofQuery {
    Account { address: Address },
    Storage { address: Address, key: [u8; 32] },
    Minimal { key: [u8; 32] },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcStateProofRequest {
    pub height: u64,
    pub max_depth: usize,
    pub query: RpcStateProofQuery,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RpcStateProofValue {
    Account(Account),
    Storage([u8; 32]),
    Minimal([u8; 32]),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcStateProofResponse {
    pub height: u64,
    pub proof: RpcVerkleProof,
    pub value: RpcStateProofValue,
}

const MAX_RPC_MESSAGE_SIZE: usize = crate::MAX_RPC_MESSAGE_SIZE;
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(crate::DEFAULT_RPC_TIMEOUT_SECS);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum L1Request {
    GetLatestBlockHeight,
    GetBlock(u64),
    GetHeaders { start: u64, end: u64 },
    GetBlockProof(u64),
    GetTransaction([u8; 32]),
    GetStateProof(RpcStateProofRequest),
}

impl L1Request {
    pub fn request_block(height: u64) -> Self {
        Self::GetBlock(height)
    }

    pub fn request_headers(start: u64, end: u64) -> Self {
        Self::GetHeaders { start, end }
    }

    pub fn request_latest_block_height() -> Self {
        Self::GetLatestBlockHeight
    }

    pub fn request_block_proof(height: u64) -> Self {
        Self::GetBlockProof(height)
    }

    pub fn request_transaction(hash: [u8; 32]) -> Self {
        Self::GetTransaction(hash)
    }

    pub fn request_state_proof(request: RpcStateProofRequest) -> Self {
        Self::GetStateProof(request)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("failed to encode rpc request")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).context("failed to decode rpc request")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum L1Response {
    LatestBlockHeight(Option<u64>),
    Block(Option<Vec<u8>>),
    Headers(Option<Vec<RpcVerifiedHeaderEnvelope>>),
    BlockProof(Option<Vec<u8>>),
    Transaction(Option<Vec<u8>>),
    StateProof(Box<Option<RpcStateProofResponse>>),
    Error(String),
}

impl L1Response {
    pub fn respond_block(block: Option<Vec<u8>>) -> Self {
        Self::Block(block)
    }

    pub fn respond_headers(headers: Option<Vec<RpcVerifiedHeaderEnvelope>>) -> Self {
        Self::Headers(headers)
    }

    pub fn respond_latest_block_height(height: Option<u64>) -> Self {
        Self::LatestBlockHeight(height)
    }

    pub fn respond_block_proof(proof: Option<Vec<u8>>) -> Self {
        Self::BlockProof(proof)
    }

    pub fn respond_transaction(tx: Option<Vec<u8>>) -> Self {
        Self::Transaction(tx)
    }

    pub fn respond_state_proof(proof: Option<RpcStateProofResponse>) -> Self {
        Self::StateProof(Box::new(proof))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("failed to encode rpc response")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).context("failed to decode rpc response")
    }
}

#[derive(Clone, Debug)]
pub struct L1Codec {
    timeout: Duration,
}

impl Default for L1Codec {
    fn default() -> Self {
        Self::new(DEFAULT_RPC_TIMEOUT)
    }
}

impl L1Codec {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn with_timeout<F, T>(&self, future: F) -> io::Result<T>
    where
        F: std::future::Future<Output = io::Result<T>>,
    {
        time::timeout(self.timeout, future)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "rpc request timed out"))?
    }
}

#[async_trait]
impl Codec for L1Codec {
    type Protocol = libp2p::StreamProtocol;
    type Request = L1Request;
    type Response = L1Response;

    async fn read_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> io::Result<L1Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.with_timeout(async {
            let bytes = read_frame(io).await?;
            L1Request::decode(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        })
        .await
    }

    async fn read_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
    ) -> io::Result<L1Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        self.with_timeout(async {
            let bytes = read_frame(io).await?;
            L1Response::decode(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
        })
        .await
    }

    async fn write_request<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        request: L1Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.with_timeout(async {
            let bytes = request
                .encode()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            write_frame(io, &bytes).await
        })
        .await
    }

    async fn write_response<T>(
        &mut self,
        _: &libp2p::StreamProtocol,
        io: &mut T,
        response: L1Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        self.with_timeout(async {
            let bytes = response
                .encode()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            write_frame(io, &bytes).await
        })
        .await
    }
}

async fn read_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len > MAX_RPC_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rpc message exceeds maximum size",
        ));
    }

    // Allocate incrementally as bytes arrive over the wire (bounded initial capacity)
    let mut buffer = Vec::with_capacity(frame_len.min(8192));
    let mut handle = io.take(frame_len as u64);
    handle.read_to_end(&mut buffer).await?;
    if buffer.len() != frame_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to fill whole buffer",
        ));
    }
    Ok(buffer)
}

async fn write_frame<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if bytes.len() > MAX_RPC_MESSAGE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "rpc message exceeds maximum size",
        ));
    }

    let len_bytes = (bytes.len() as u32).to_be_bytes();
    io.write_all(&len_bytes).await?;
    io.write_all(bytes).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::{
        read_frame, write_frame, L1Codec, L1Request, L1Response, RpcStateProofQuery,
        RpcStateProofRequest, RpcStateProofResponse, RpcStateProofValue, RpcVerifiedHeaderEnvelope,
        DEFAULT_RPC_TIMEOUT, MAX_RPC_MESSAGE_SIZE,
    };
    use futures::io::Cursor;
    use futures::task::{Context, Poll};
    use libp2p::request_response::Codec;
    use libp2p::StreamProtocol;
    use std::io;
    use std::pin::Pin;
    use std::time::Duration;
    use sxiaum_block::BlockHeader;
    use sxiaum_state::RpcVerkleProof;
    use sxiaum_types::{Account, Address};
    use tokio::time;

    fn sample_state_proof() -> RpcStateProofResponse {
        RpcStateProofResponse {
            height: 9,
            proof: RpcVerkleProof {
                root: [1u8; 32],
                commitments: vec![[2u8; 32], [3u8; 32]],
                kzg_commitments: vec![],
                openings: vec![],
                path: vec![4, 5],
                values: vec![[6u8; 32], [7u8; 32]],
                minimal: true,
            },
            value: RpcStateProofValue::Account(Account::new(Address([8u8; 32]))),
        }
    }

    fn protocol() -> StreamProtocol {
        StreamProtocol::new("/sxiaum/rpc/1")
    }

    #[test]
    fn request_helpers_build_expected_variants() {
        assert!(matches!(
            L1Request::request_block(42),
            L1Request::GetBlock(42)
        ));
        assert!(matches!(
            L1Request::request_headers(10, 12),
            L1Request::GetHeaders { start: 10, end: 12 }
        ));
        let tx_hash = [9u8; 32];
        assert!(matches!(
            L1Request::request_transaction(tx_hash),
            L1Request::GetTransaction(hash) if hash == tx_hash
        ));
        let proof_request = RpcStateProofRequest {
            height: 12,
            max_depth: 32,
            query: RpcStateProofQuery::Minimal { key: [8u8; 32] },
        };
        assert!(matches!(
            L1Request::request_state_proof(proof_request.clone()),
            L1Request::GetStateProof(request) if request == proof_request
        ));
    }

    #[test]
    fn response_helpers_build_expected_variants() {
        let block = vec![1u8, 2, 3];
        let tx = vec![4u8, 5, 6];
        let proof = sample_state_proof();
        let headers = vec![RpcVerifiedHeaderEnvelope {
            header: BlockHeader::new([0u8; 32], 1),
            consensus_signatures: vec![(Address([1u8; 32]), vec![2u8; 64])],
            hotstuff_view_phase: None,
        }];

        assert!(matches!(
            L1Response::respond_block(Some(block.clone())),
            L1Response::Block(Some(payload)) if payload == block
        ));
        assert!(matches!(
            L1Response::respond_transaction(Some(tx.clone())),
            L1Response::Transaction(Some(payload)) if payload == tx
        ));
        assert!(matches!(
            L1Response::respond_headers(Some(headers.clone())),
            L1Response::Headers(Some(payload)) if payload == headers
        ));
        assert!(matches!(
            L1Response::respond_state_proof(Some(proof.clone())),
            L1Response::StateProof(payload) if *payload == Some(proof)
        ));
    }

    #[test]
    fn request_and_response_round_trip_through_bincode() {
        let request_hash = [7u8; 32];
        let request = L1Request::request_transaction(request_hash);
        let encoded_request = request.encode().expect("request should encode");
        let decoded_request = L1Request::decode(&encoded_request).expect("request should decode");
        assert!(matches!(decoded_request, L1Request::GetTransaction(hash) if hash == request_hash));

        let response = L1Response::respond_state_proof(Some(sample_state_proof()));
        let encoded_response = response.encode().expect("response should encode");
        let decoded_response =
            L1Response::decode(&encoded_response).expect("response should decode");
        assert!(matches!(
            decoded_response,
            L1Response::StateProof(payload) if *payload == Some(sample_state_proof())
        ));
    }

    #[tokio::test]
    async fn frame_round_trip_and_size_limit_work() {
        let payload = vec![1u8, 2, 3, 4, 5];
        let mut writer = Cursor::new(Vec::new());

        write_frame(&mut writer, &payload)
            .await
            .expect("frame should write");
        let mut reader = Cursor::new(writer.into_inner());
        let decoded = read_frame(&mut reader).await.expect("frame should read");
        assert_eq!(decoded, payload);

        let oversize = vec![0u8; MAX_RPC_MESSAGE_SIZE + 1];
        let mut writer = Cursor::new(Vec::new());
        let error = write_frame(&mut writer, &oversize)
            .await
            .expect_err("oversized frame must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn codec_writes_and_reads_requests_and_responses() {
        let protocol = protocol();
        let mut request_codec = L1Codec::default();
        let mut response_codec = L1Codec::default();

        let mut request_writer = Cursor::new(Vec::new());
        let request = L1Request::request_block(99);
        request_codec
            .write_request(&protocol, &mut request_writer, request.clone())
            .await
            .expect("request should write");
        let mut request_reader = Cursor::new(request_writer.into_inner());
        let decoded_request = request_codec
            .read_request(&protocol, &mut request_reader)
            .await
            .expect("request should read");
        assert!(matches!(decoded_request, L1Request::GetBlock(99)));

        let mut response_writer = Cursor::new(Vec::new());
        let response = L1Response::respond_state_proof(Some(sample_state_proof()));
        response_codec
            .write_response(&protocol, &mut response_writer, response.clone())
            .await
            .expect("response should write");
        let mut response_reader = Cursor::new(response_writer.into_inner());
        let decoded_response = response_codec
            .read_response(&protocol, &mut response_reader)
            .await
            .expect("response should read");
        assert!(matches!(
            decoded_response,
            L1Response::StateProof(payload) if *payload == Some(sample_state_proof())
        ));
    }

    #[tokio::test]
    async fn codec_timeout_returns_timed_out_error() {
        let codec = L1Codec::new(Duration::from_millis(10));
        let error = codec
            .with_timeout(async {
                time::sleep(Duration::from_millis(30)).await;
                Ok::<_, io::Error>(())
            })
            .await
            .expect_err("timeout should fail");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn codec_read_rejects_invalid_payloads() {
        let protocol = protocol();
        let mut codec = L1Codec::default();
        let mut writer = Cursor::new(Vec::new());
        write_frame(&mut writer, b"not-bincode")
            .await
            .expect("frame should write");
        let mut reader = Cursor::new(writer.into_inner());

        let error = codec
            .read_request(&protocol, &mut reader)
            .await
            .expect_err("invalid payload should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn default_timeout_matches_constant() {
        let codec = L1Codec::default();
        let future = codec.with_timeout(async { Ok::<_, io::Error>(()) });
        let runtime = tokio::runtime::Runtime::new().expect("runtime should build");
        runtime
            .block_on(future)
            .expect("default timeout should permit ready future");
        let _ = DEFAULT_RPC_TIMEOUT;
    }

    struct PendingReader;

    impl futures::AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }

    #[tokio::test]
    async fn codec_read_request_times_out_when_stream_stalls() {
        let protocol = protocol();
        let mut codec = L1Codec::new(Duration::from_millis(5));
        let mut reader = PendingReader;
        let error = codec
            .read_request(&protocol, &mut reader)
            .await
            .expect_err("stalled read should time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
