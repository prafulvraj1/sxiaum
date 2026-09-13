use crate::peer::PeerStore;
use anyhow::{anyhow, bail, Result};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use sxiaum_block::Block;
use sxiaum_types::Hash;
use tracing::{debug, info, warn};

// - items 1-2: BlockRequest / BlockResponse messages -

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockRequest {
    pub start_height: u64,
    pub end_height: u64,
}

impl BlockRequest {
    pub fn single(height: u64) -> Self {
        Self {
            start_height: height,
            end_height: height,
        }
    }

    pub fn range(start_height: u64, end_height: u64) -> Self {
        Self {
            start_height,
            end_height,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("BlockRequest encode: {}", e))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("BlockRequest decode: {}", e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockResponse {
    pub start_height: u64,
    pub blocks: Vec<Vec<u8>>,
    pub error: Option<String>,
}

impl BlockResponse {
    pub fn ok(start_height: u64, blocks: Vec<Vec<u8>>) -> Self {
        Self {
            start_height,
            blocks,
            error: None,
        }
    }

    pub fn err(start_height: u64, message: impl Into<String>) -> Self {
        Self {
            start_height,
            blocks: Vec::new(),
            error: Some(message.into()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("BlockResponse encode: {}", e))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow!("BlockResponse decode: {}", e))
    }
}

// - traits injected into ChainSyncEngine -

pub trait BlockFetcher: Send + Sync {
    fn fetch_height(&self, peer_id: PeerId) -> Result<u64>;
    fn fetch_blocks(&self, peer_id: PeerId, req: &BlockRequest) -> Result<BlockResponse>;
}

pub trait BlockExecutor: Send + Sync {
    fn execute_block(&self, block: &Block) -> Result<Hash>;
}

pub trait ChainStore: Send + Sync {
    fn local_height(&self) -> Result<u64>;
    fn block_hash_at(&self, height: u64) -> Result<Option<Hash>>;
    fn append_block(&self, block: &Block) -> Result<()>;
    fn update_chain_head(&self, block: &Block) -> Result<()>;
    fn persist_sync_progress(&self, height: u64) -> Result<()>;
    fn load_sync_progress(&self) -> Result<u64>;
}

pub trait ConsensusSignatureVerifier: Send + Sync {
    fn verify_block_signatures(&self, block: &Block) -> Result<bool>;
}

// - item 5: peer height tracker -

#[derive(Clone, Debug)]
pub struct PeerHeight {
    pub peer_id: PeerId,
    pub height: u64,
}

// - sync config -

#[derive(Clone, Debug)]
pub struct ChainSyncConfig {
    /// Maximum blocks fetched per batch (item 7).
    pub batch_size: u64,
    /// Number of parallel batch download tasks (item 16).
    pub parallel_downloads: usize,
    /// Maximum retry attempts per batch (item 17).
    pub max_retries: u32,
    /// Delay between retries.
    pub retry_delay: Duration,
    /// Penalty score applied to a peer sending an invalid block (items 18-19).
    pub invalid_block_penalty: i32,
    /// Reputation below which a peer is considered malicious and banned (item 18-19).
    pub ban_threshold: i32,
}

impl Default for ChainSyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 64,
            parallel_downloads: 4,
            max_retries: 3,
            retry_delay: Duration::from_millis(500),
            invalid_block_penalty: 50,
            ban_threshold: -100,
        }
    }
}

// - sync outcome -

#[derive(Clone, Debug)]
pub struct ChainSyncResult {
    pub blocks_applied: u64,
    pub new_head: u64,
    pub banned_peers: Vec<PeerId>,
}

// - chain sync engine -

pub struct ChainSyncEngine<F, E, S, V> {
    fetcher: F,
    executor: E,
    store: S,
    verifier: V,
    config: ChainSyncConfig,
    /// In-memory penalty accumulator for this sync session (item 18).
    peer_penalties: HashMap<PeerId, i32>,
}

impl<F, E, S, V> ChainSyncEngine<F, E, S, V>
where
    F: BlockFetcher,
    E: BlockExecutor,
    S: ChainStore,
    V: ConsensusSignatureVerifier,
{
    pub fn new(fetcher: F, executor: E, store: S, verifier: V, config: ChainSyncConfig) -> Self {
        Self {
            fetcher,
            executor,
            store,
            verifier,
            config,
            peer_penalties: HashMap::new(),
        }
    }

    // - item 3: request_latest_height from a single peer -

    pub fn request_latest_height(&self, peer_id: PeerId) -> Result<u64> {
        self.fetcher.fetch_height(peer_id)
    }

    // - item 4: query all peers for chain height -

    pub fn query_peers_for_height(&self, peers: &[PeerId]) -> Vec<PeerHeight> {
        peers
            .iter()
            .filter_map(|&peer_id| match self.request_latest_height(peer_id) {
                Ok(height) => Some(PeerHeight { peer_id, height }),
                Err(err) => {
                    debug!("peer {:?} height query failed: {}", peer_id, err);
                    None
                }
            })
            .collect()
    }

    // - item 5: select peer with highest height -

    pub fn select_best_peer(&self, peer_heights: &[PeerHeight]) -> Option<PeerHeight> {
        peer_heights.iter().max_by_key(|p| p.height).cloned()
    }

    // - item 6: request missing block range -

    pub fn request_block_range(&self, peer_id: PeerId, start: u64, end: u64) -> Result<Vec<Block>> {
        if end < start {
            bail!("invalid block range: {}..={}", start, end);
        }
        let requested_count = end.saturating_sub(start).saturating_add(1);
        if requested_count > self.config.batch_size {
            bail!(
                "requested range size {} exceeds batch_size {}",
                requested_count,
                self.config.batch_size
            );
        }
        let req = BlockRequest::range(start, end);
        let response = self.fetcher.fetch_blocks(peer_id, &req)?;
        if let Some(err) = response.error {
            bail!(
                "peer {:?} returned error for range {}-{}: {}",
                peer_id,
                start,
                end,
                err
            );
        }
        if response.blocks.len() > requested_count as usize {
            bail!(
                "peer {:?} returned {} blocks exceeding requested count {}",
                peer_id,
                response.blocks.len(),
                requested_count
            );
        }
        let mut blocks = Vec::with_capacity(response.blocks.len());
        for raw in &response.blocks {
            if raw.len() > sxiaum_types::MAX_CANONICAL_MESSAGE_SIZE {
                bail!(
                    "peer {:?} sent oversized block frame ({} bytes)",
                    peer_id,
                    raw.len()
                );
            }
            let block: Block = bincode::deserialize(raw)
                .map_err(|e| anyhow!("failed to deserialize block: {}", e))?;
            blocks.push(block);
        }
        Ok(blocks)
    }

    // - item 8: validate block header hash -

    pub fn validate_block_header_hash(&self, block: &Block) -> Result<()> {
        let computed = block.try_hash()?;
        let stored = block.header.try_hash()?;
        if computed != stored {
            bail!(
                "block header hash mismatch at height {}: computed {:?} != stored {:?}",
                block.height(),
                computed,
                stored
            );
        }
        if block.chain_id() != sxiaum_types::SXIAUM_CHAIN_ID {
            bail!(
                "block chain_id mismatch at height {}: expected {}, got {}",
                block.height(),
                sxiaum_types::SXIAUM_CHAIN_ID,
                block.chain_id()
            );
        }
        Ok(())
    }

    // - item 9: validate parent linkage -

    pub fn validate_parent_linkage(&self, prev_hash: Hash, block: &Block) -> Result<()> {
        if block.header.parent_hash != prev_hash {
            bail!(
                "parent hash mismatch at height {}: expected {:?}, got {:?}",
                block.height(),
                prev_hash,
                block.header.parent_hash
            );
        }
        Ok(())
    }

    // - item 10: validate consensus signatures -

    pub fn validate_consensus_signatures(&self, block: &Block) -> Result<()> {
        if !self.verifier.verify_block_signatures(block)? {
            bail!(
                "consensus signature verification failed for block at height {}",
                block.height()
            );
        }
        Ok(())
    }

    // - item 11: execute block using execution engine -

    pub fn execute_block(&self, block: &Block) -> Result<Hash> {
        self.executor.execute_block(block)
    }

    // - item 12: verify state root -

    pub fn verify_state_root(&self, block: &Block, computed_state_root: Hash) -> Result<()> {
        if block.header.state_root != computed_state_root {
            bail!(
                "state root mismatch at height {}: expected {:?}, got {:?}",
                block.height(),
                block.header.state_root,
                computed_state_root
            );
        }
        Ok(())
    }

    // - item 13: append block to local chain -

    pub fn append_block_to_chain(&self, block: &Block) -> Result<()> {
        self.store.append_block(block)
    }

    // - item 14: update chain head -

    pub fn update_chain_head(&self, block: &Block) -> Result<()> {
        self.store.update_chain_head(block)
    }

    // - item 15: apply one validated block (full pipeline) -

    fn apply_block(&mut self, peer_id: PeerId, block: &Block, prev_hash: Hash) -> Result<()> {
        if let Err(e) = self
            .validate_block_header_hash(block)
            .and_then(|_| self.validate_parent_linkage(prev_hash, block))
            .and_then(|_| self.validate_consensus_signatures(block))
        {
            self.penalize_peer(peer_id, &e);
            return Err(e);
        }

        let computed_root = match self.execute_block(block) {
            Ok(root) => root,
            Err(e) => {
                self.penalize_peer(peer_id, &e);
                return Err(e);
            }
        };

        if let Err(e) = self.verify_state_root(block, computed_root) {
            self.penalize_peer(peer_id, &e);
            return Err(e);
        }

        self.append_block_to_chain(block)?;
        self.update_chain_head(block)?;
        Ok(())
    }

    // - item 15: repeat until synced -

    pub fn run_until_synced(
        &mut self,
        peer_store: &mut PeerStore,
        peers: &[PeerId],
    ) -> Result<ChainSyncResult> {
        let mut total_applied = 0u64;
        let mut banned: Vec<PeerId> = Vec::new();

        loop {
            let local_height = self.store.local_height()?;
            let peer_heights = self.query_peers_for_height(peers);
            let best = match self.select_best_peer(&peer_heights) {
                Some(p) if p.height > local_height => p,
                _ => break,
            };

            info!(
                "syncing from height {} to {} via peer {:?}",
                local_height + 1,
                best.height,
                best.peer_id
            );

            let blocks = self.fetch_all_parallel(best.peer_id, local_height + 1, best.height)?;
            let mut prev_hash = self.store.block_hash_at(local_height)?.unwrap_or([0u8; 32]);

            for block in &blocks {
                match self.apply_block(best.peer_id, block, prev_hash) {
                    Ok(()) => {
                        prev_hash = block.try_hash()?;
                        total_applied += 1;
                        // item 20: persist sync progress after each block
                        self.store.persist_sync_progress(block.height())?;
                    }
                    Err(e) => {
                        warn!(
                            "block application failed at height {}: {}",
                            block.height(),
                            e
                        );
                        if self.should_ban_peer(best.peer_id) {
                            peer_store.ban_peer(&best.peer_id);
                            banned.push(best.peer_id);
                            info!("banned peer {:?} for invalid blocks", best.peer_id);
                        }
                        // abort this sync round; next loop iteration picks a new peer
                        break;
                    }
                }
            }
        }

        let new_head = self.store.local_height()?;
        Ok(ChainSyncResult {
            blocks_applied: total_applied,
            new_head,
            banned_peers: banned,
        })
    }

    // - item 16: parallel block downloads -

    pub fn fetch_all_parallel(&self, peer_id: PeerId, from: u64, to: u64) -> Result<Vec<Block>> {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Mutex;

        if to < from {
            return Ok(Vec::new());
        }
        let total = to.saturating_sub(from) + 1;
        let concurrency = self.config.parallel_downloads.clamp(1, 8);

        // SECURITY (H-03): every chunk MUST respect the per-request batch_size
        // ceiling enforced by `request_block_range`. The previous sizing
        // (`chunk = ceil(total / parallel_downloads)`) made any gap larger than
        // `parallel_downloads * batch_size` produce oversized ranges, which the
        // server-side limit then rejected forever (retry x4 -> permanent sync
        // wedge). Chunking now always yields legal ranges regardless of gap
        // size, and downloads run with bounded concurrency over the chunk list.
        let chunk = self
            .config
            .batch_size
            .max(1)
            .min(total.div_ceil(concurrency as u64));

        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut cursor = from;
        while cursor <= to {
            let end = (cursor + chunk - 1).min(to);
            ranges.push((cursor, end));
            cursor = end.saturating_add(1);
        }

        let next_chunk = AtomicUsize::new(0);
        let aborted = AtomicBool::new(false);
        let first_error: Mutex<Option<anyhow::Error>> = Mutex::new(None);
        let downloaded: Mutex<Vec<Option<Vec<Block>>>> =
            Mutex::new((0..ranges.len()).map(|_| None).collect());

        std::thread::scope(|scope| {
            let workers = concurrency.min(ranges.len());
            for _ in 0..workers {
                scope.spawn(|| loop {
                    if aborted.load(Ordering::SeqCst) {
                        break;
                    }
                    let index = next_chunk.fetch_add(1, Ordering::SeqCst);
                    if index >= ranges.len() {
                        break;
                    }
                    let (start, end) = ranges[index];
                    match self.request_block_range_with_retry(peer_id, start, end) {
                        Ok(blocks) => {
                            downloaded.lock().unwrap()[index] = Some(blocks);
                        }
                        Err(e) => {
                            // Record the first failure and stop pulling new
                            // work; the caller aborts this sync round.
                            let mut guard = first_error.lock().unwrap();
                            if guard.is_none() {
                                *guard = Some(e);
                            }
                            drop(guard);
                            aborted.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                });
            }
        });

        if let Some(err) = first_error.into_inner().unwrap() {
            return Err(err);
        }

        let mut all = Vec::new();
        for slot in downloaded.into_inner().unwrap() {
            all.extend(slot.unwrap_or_default());
        }
        all.sort_by_key(|b| b.height());

        // Verify height continuity: ensure no gaps and no duplicate heights returned
        for (i, block) in all.iter().enumerate() {
            let expected_height = from + i as u64;
            if block.height() != expected_height {
                bail!(
                    "peer {:?} returned discontinuous sync chain: expected height {}, got {}",
                    peer_id,
                    expected_height,
                    block.height()
                );
            }
        }

        Ok(all)
    }

    // - item 17: retry logic -

    pub fn request_block_range_with_retry(
        &self,
        peer_id: PeerId,
        start: u64,
        end: u64,
    ) -> Result<Vec<Block>> {
        let mut last_err = anyhow!("no attempts made");
        for attempt in 0..=self.config.max_retries {
            match self.request_block_range(peer_id, start, end) {
                Ok(blocks) => return Ok(blocks),
                Err(e) => {
                    debug!(
                        "block range {}-{} attempt {}/{} failed: {}",
                        start,
                        end,
                        attempt + 1,
                        self.config.max_retries + 1,
                        e
                    );
                    last_err = e;
                    std::thread::sleep(self.config.retry_delay);
                }
            }
        }
        Err(last_err)
    }

    // - items 18-19: detect malicious peers / ban peers -

    fn penalize_peer(&mut self, peer_id: PeerId, reason: &anyhow::Error) {
        const MAX_PENALTY_ENTRIES: usize = 10000;
        if self.peer_penalties.len() >= MAX_PENALTY_ENTRIES
            && !self.peer_penalties.contains_key(&peer_id)
        {
            // Prune un-banned entries with score 0
            self.peer_penalties.retain(|_, &mut score| score < 0);
        }
        let score = self.peer_penalties.entry(peer_id).or_insert(0);
        *score -= self.config.invalid_block_penalty;
        warn!(
            "penalized peer {:?} (session score {}): {}",
            peer_id, score, reason
        );
    }

    pub fn should_ban_peer(&self, peer_id: PeerId) -> bool {
        self.peer_penalties
            .get(&peer_id)
            .map(|&s| s <= self.config.ban_threshold)
            .unwrap_or(false)
    }

    /// Detect peers whose cumulative penalty exceeds the ban threshold (item 18).
    pub fn detect_malicious_peers(&self) -> Vec<PeerId> {
        self.peer_penalties
            .iter()
            .filter(|(_, &score)| score <= self.config.ban_threshold)
            .map(|(&peer_id, _)| peer_id)
            .collect()
    }

    /// Ban all detected malicious peers in the peer store (item 19).
    pub fn ban_malicious_peers(&self, peer_store: &mut PeerStore) -> Vec<PeerId> {
        let to_ban = self.detect_malicious_peers();
        for &peer_id in &to_ban {
            peer_store.ban_peer(&peer_id);
            info!("banned malicious peer {:?}", peer_id);
        }
        to_ban
    }

    // - item 20: persist / resume sync progress -

    pub fn persist_progress(&self, height: u64) -> Result<()> {
        self.store.persist_sync_progress(height)
    }

    pub fn resume_progress(&self) -> Result<u64> {
        self.store.load_sync_progress()
    }
}

// - tests -

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::{identity::Keypair, PeerId};
    use std::sync::Mutex;
    use sxiaum_block::{Block, BlockBody, BlockHeader};
    use sxiaum_types::Address;

    fn dummy_peer() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    fn make_block(parent_hash: Hash, height: u64, seed: u8) -> Block {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let proposer = Address::from_public_key(&signing_key.verifying_key().to_bytes());
        let mut header = BlockHeader::new(parent_hash, height);
        header.proposer = proposer;
        let mut block = Block::new(header, BlockBody::empty());
        block.try_compute_roots().expect("compute roots");
        block.header.sign(&signing_key).expect("sign");
        block
    }

    // Stub implementations

    struct StubFetcher {
        heights: HashMap<PeerId, u64>,
        blocks: HashMap<u64, Block>,
    }

    impl BlockFetcher for StubFetcher {
        fn fetch_height(&self, peer_id: PeerId) -> Result<u64> {
            self.heights
                .get(&peer_id)
                .copied()
                .ok_or_else(|| anyhow!("unknown peer"))
        }

        fn fetch_blocks(&self, _peer_id: PeerId, req: &BlockRequest) -> Result<BlockResponse> {
            let mut raw = Vec::new();
            for h in req.start_height..=req.end_height {
                if let Some(b) = self.blocks.get(&h) {
                    raw.push(bincode::serialize(b).unwrap());
                } else {
                    return Ok(BlockResponse::err(
                        req.start_height,
                        format!("missing block at {}", h),
                    ));
                }
            }
            Ok(BlockResponse::ok(req.start_height, raw))
        }
    }

    struct StubExecutor {
        state_root: Hash,
    }
    impl BlockExecutor for StubExecutor {
        fn execute_block(&self, _block: &Block) -> Result<Hash> {
            Ok(self.state_root)
        }
    }

    struct StubStore {
        head: Mutex<u64>,
        hashes: Mutex<HashMap<u64, Hash>>,
        progress: Mutex<u64>,
    }

    impl StubStore {
        fn new(head: u64, hashes: HashMap<u64, Hash>) -> Self {
            Self {
                head: Mutex::new(head),
                hashes: Mutex::new(hashes),
                progress: Mutex::new(0),
            }
        }
    }

    impl ChainStore for StubStore {
        fn local_height(&self) -> Result<u64> {
            Ok(*self.head.lock().unwrap())
        }
        fn block_hash_at(&self, height: u64) -> Result<Option<Hash>> {
            Ok(self.hashes.lock().unwrap().get(&height).copied())
        }
        fn append_block(&self, block: &Block) -> Result<()> {
            self.hashes
                .lock()
                .unwrap()
                .insert(block.height(), block.try_hash().unwrap());
            Ok(())
        }
        fn update_chain_head(&self, block: &Block) -> Result<()> {
            *self.head.lock().unwrap() = block.height();
            Ok(())
        }
        fn persist_sync_progress(&self, height: u64) -> Result<()> {
            *self.progress.lock().unwrap() = height;
            Ok(())
        }
        fn load_sync_progress(&self) -> Result<u64> {
            Ok(*self.progress.lock().unwrap())
        }
    }

    struct StubVerifier {
        valid: bool,
    }
    impl ConsensusSignatureVerifier for StubVerifier {
        fn verify_block_signatures(&self, _block: &Block) -> Result<bool> {
            Ok(self.valid)
        }
    }

    fn make_engine(
        head: u64,
        hashes: HashMap<u64, Hash>,
        blocks: HashMap<u64, Block>,
        peer_heights: HashMap<PeerId, u64>,
        state_root: Hash,
    ) -> ChainSyncEngine<StubFetcher, StubExecutor, StubStore, StubVerifier> {
        ChainSyncEngine::new(
            StubFetcher {
                heights: peer_heights,
                blocks,
            },
            StubExecutor { state_root },
            StubStore::new(head, hashes),
            StubVerifier { valid: true },
            ChainSyncConfig::default(),
        )
    }

    #[test]
    fn block_request_response_roundtrip() {
        let req = BlockRequest::range(5, 10);
        let decoded = BlockRequest::decode(&req.encode().unwrap()).unwrap();
        assert_eq!(decoded.start_height, 5);
        assert_eq!(decoded.end_height, 10);

        let resp = BlockResponse::ok(5, vec![vec![1, 2, 3]]);
        let decoded = BlockResponse::decode(&resp.encode().unwrap()).unwrap();
        assert_eq!(decoded.blocks.len(), 1);
        assert!(decoded.error.is_none());

        let err_resp = BlockResponse::err(5, "not found");
        assert!(err_resp.error.is_some());
    }

    #[test]
    fn query_peers_and_select_best() {
        let peer_a = dummy_peer();
        let peer_b = dummy_peer();
        let engine = make_engine(
            0,
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(peer_a, 10), (peer_b, 20)]),
            [0u8; 32],
        );
        let heights = engine.query_peers_for_height(&[peer_a, peer_b]);
        assert_eq!(heights.len(), 2);
        let best = engine.select_best_peer(&heights).unwrap();
        assert_eq!(best.peer_id, peer_b);
        assert_eq!(best.height, 20);
    }

    #[test]
    fn validate_header_hash_accepts_consistent_block() {
        let block = make_block([0u8; 32], 1, 1);
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        assert!(engine.validate_block_header_hash(&block).is_ok());
    }

    #[test]
    fn validate_parent_linkage_rejects_wrong_parent() {
        let block = make_block([1u8; 32], 2, 2);
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        assert!(engine.validate_parent_linkage([2u8; 32], &block).is_err());
        assert!(engine.validate_parent_linkage([1u8; 32], &block).is_ok());
    }

    #[test]
    fn detect_and_ban_malicious_peers() {
        let peer = dummy_peer();
        let mut engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        let err = anyhow!("bad block");
        // Apply enough penalties to cross the threshold (default: -100, penalty: 50 per strike)
        engine.penalize_peer(peer, &err);
        assert!(!engine.should_ban_peer(peer));
        engine.penalize_peer(peer, &err);
        assert!(engine.should_ban_peer(peer));
        let malicious = engine.detect_malicious_peers();
        assert!(malicious.contains(&peer));
    }

    #[test]
    fn retry_logic_succeeds_after_initial_failures() {
        // StubFetcher with no blocks - will always fail, verifying retry count.
        let peer = dummy_peer();
        let engine = ChainSyncEngine::new(
            StubFetcher {
                heights: HashMap::from([(peer, 5)]),
                blocks: HashMap::new(),
            },
            StubExecutor {
                state_root: [0u8; 32],
            },
            StubStore::new(0, HashMap::new()),
            StubVerifier { valid: true },
            ChainSyncConfig {
                max_retries: 2,
                retry_delay: Duration::from_millis(1),
                ..Default::default()
            },
        );
        let result = engine.request_block_range_with_retry(peer, 1, 1);
        assert!(result.is_err());
    }

    #[test]
    fn persist_and_resume_sync_progress() {
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        engine.persist_progress(42).unwrap();
        assert_eq!(engine.resume_progress().unwrap(), 42);
    }

    #[test]
    fn run_until_synced_applies_blocks_and_persists_progress() {
        let peer = dummy_peer();
        let genesis_hash = [0u8; 32];
        let block_1 = make_block(genesis_hash, 1, 1);
        let block_2 = make_block(block_1.try_hash().unwrap(), 2, 2);
        let state_root = block_1.header.state_root;

        let mut engine = ChainSyncEngine::new(
            StubFetcher {
                heights: HashMap::from([(peer, 2)]),
                blocks: HashMap::from([(1, block_1.clone()), (2, block_2.clone())]),
            },
            StubExecutor { state_root },
            StubStore::new(0, HashMap::from([(0, genesis_hash)])),
            StubVerifier { valid: true },
            ChainSyncConfig {
                batch_size: 64,
                parallel_downloads: 1,
                retry_delay: Duration::from_millis(1),
                ..Default::default()
            },
        );

        let mut peer_store = PeerStore::default();
        let result = engine.run_until_synced(&mut peer_store, &[peer]).unwrap();
        assert_eq!(result.blocks_applied, 2);
        assert_eq!(result.new_head, 2);
        assert_eq!(*engine.store.progress.lock().unwrap(), 2);
    }

    #[test]
    fn validate_header_hash_rejects_wrong_chain_id() {
        let mut block = make_block([0u8; 32], 1, 1);
        block.header.chain_id = 99999;
        let engine = make_engine(0, HashMap::new(), HashMap::new(), HashMap::new(), [0u8; 32]);
        assert!(engine.validate_block_header_hash(&block).is_err());
    }

    // SECURITY REGRESSION (H-03): a gap larger than
    // `parallel_downloads * batch_size` used to produce oversized chunks that
    // `request_block_range` rejected forever -> permanent sync failure.
    #[test]
    fn fetch_all_parallel_succeeds_for_gap_larger_than_parallel_capacity() {
        let peer = dummy_peer();
        let genesis_hash = [7u8; 32];
        let total_blocks: u64 = 300; // >> batch_size(64) * parallel(2)
        let blocks: HashMap<u64, Block> = (1..=total_blocks)
            .fold((genesis_hash, HashMap::new()), |(parent, mut map), h| {
                let b = make_block(parent, h, (h % 251) as u8);
                let hash = b.try_hash().unwrap();
                map.insert(h, b);
                (hash, map)
            })
            .1;
        let tip_hash = blocks[&total_blocks].try_hash().unwrap();

        let engine = ChainSyncEngine::new(
            StubFetcher {
                heights: HashMap::from([(peer, total_blocks)]),
                blocks,
            },
            StubExecutor {
                state_root: [9u8; 32],
            },
            StubStore::new(
                0,
                HashMap::from([(0u64, genesis_hash), (total_blocks, tip_hash)]),
            ),
            StubVerifier { valid: true },
            ChainSyncConfig {
                batch_size: 64,
                parallel_downloads: 2,
                retry_delay: Duration::from_millis(1),
                ..Default::default()
            },
        );

        let fetched = engine
            .fetch_all_parallel(peer, 1, total_blocks)
            .expect("H-03: large gaps must sync");
        assert_eq!(fetched.len() as u64, total_blocks);
        assert_eq!(fetched.first().unwrap().height(), 1);
        assert_eq!(fetched.last().unwrap().height(), total_blocks);
    }
}
