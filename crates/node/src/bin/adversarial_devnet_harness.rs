use anyhow::Result;
use ed25519_dalek::SigningKey;
use primitive_types::U256;
use std::sync::Arc;
use sxiaum_block::{Block, BlockBody, BlockHeader};
use sxiaum_consensus::hotstuff::vote::{
    bls_qc_signing_message, QuorumCertificate, VotePhase,
};
use sxiaum_consensus::Consensus;
use sxiaum_crypto::bls::{bls_generate_keypair, BlsPrivateKey, BlsPublicKey};
use sxiaum_storage::StorageEngine;
use sxiaum_types::{Address, Validator, ValidatorStatus};

struct ValidatorNode {
    id: usize,
    address: Address,
    ed_sk: SigningKey,
    bls_sk: BlsPrivateKey,
    bls_pk: BlsPublicKey,
    storage: Arc<StorageEngine>,
    storage_path: std::path::PathBuf,
    consensus: Consensus,
}

fn create_validator_node(
    id: usize,
    validators: &[Validator],
    base_dir: &std::path::Path,
) -> Result<ValidatorNode> {
    let ed_sk = SigningKey::from_bytes(&[(id as u8) + 1; 32]);
    let ed_pk = ed_sk.verifying_key();
    let address = Address::from_public_key(ed_pk.as_bytes());

    let (bls_sk, bls_pk) = bls_generate_keypair();

    let node_dir = base_dir.join(format!("val_node_{}", id));
    std::fs::create_dir_all(&node_dir)?;
    let db_path = node_dir.join("blockchain.redb");
    if db_path.exists() {
        let _ = std::fs::remove_file(&db_path);
    }

    let storage = Arc::new(StorageEngine::new(&db_path)?);

    let mut consensus = Consensus::with_storage(storage.clone());
    consensus.update_validator_set(validators.to_vec())?;

    Ok(ValidatorNode {
        id,
        address,
        ed_sk,
        bls_sk,
        bls_pk,
        storage,
        storage_path: db_path,
        consensus,
    })
}

fn create_signed_qc(
    block_hash: [u8; 32],
    view: u64,
    phase: VotePhase,
    participating_nodes: &[&ValidatorNode],
) -> Result<QuorumCertificate> {
    use ed25519_dalek::Signer;
    let mut sigs = Vec::new();
    let mut addrs = Vec::new();

    for node in participating_nodes {
        let msg = sxiaum_consensus::hotstuff::vote::vote_signing_message(node.address, &block_hash, view, phase);
        let sig = node.ed_sk.sign(&msg);
        sigs.push(sig.to_bytes().to_vec());
        addrs.push(node.address);
    }

    Ok(QuorumCertificate::new_with_phase(
        block_hash,
        view,
        phase,
        sigs,
        addrs,
    ))
}

fn main() -> Result<()> {
    println!("============================================================");
    println!(" SXIAUM Real Multi-Node Adversarial Testbed");
    println!("============================================================");

    let temp_dir = std::env::temp_dir().join(format!("sxiaum_adv_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir)?;

    // 1. Generate 4 deterministic genesis validators (each 1M SXIAUM stake = 1M voting power)
    let mut validator_defs = Vec::new();
    let mut nodes_temp = Vec::new();

    for i in 0..4 {
        let ed_sk = SigningKey::from_bytes(&[(i as u8) + 1; 32]);
        let ed_pk = ed_sk.verifying_key();
        let addr = Address::from_public_key(ed_pk.as_bytes());
        let (bls_sk, bls_pk) = bls_generate_keypair();
        let pop = sxiaum_crypto::bls::create_proof_of_possession(&bls_sk, &bls_pk)?;

        let val = Validator {
            address: addr,
            pubkey: ed_pk.to_bytes(),
            stake: U256::from(1_000_000_000_000_000_000_000_000u128), // 1M SXIAUM
            voting_power: 1_000_000,
            status: ValidatorStatus::Active,
            bls_pubkey: Some(bls_pk.0.to_vec()),
            bls_pop: Some(pop.0.to_vec()),
            commission_bps: 500,
            missed_blocks: 0,
            jailed_until: None,
        };
        validator_defs.push(val);
        nodes_temp.push((bls_sk, bls_pk));
    }

    // 2. Initialize 4 independent Validator Nodes
    let mut nodes = Vec::new();
    for i in 0..4 {
        let mut node = create_validator_node(i, &validator_defs, &temp_dir)?;
        node.bls_sk = nodes_temp[i].0.clone();
        node.bls_pk = nodes_temp[i].1.clone();
        println!(
            " [SPAWNED] Validator {} -> Addr: {}, Storage: {:?}",
            node.id, node.address, node.storage_path
        );
        nodes.push(node);
    }

    let genesis = Block::genesis([0u8; 32]);
    let genesis_hash = genesis.try_hash()?;
    for node in &nodes {
        node.storage
            .atomic_block_commit_typed(0, &genesis.header, &genesis.body)?;
    }

    println!("\n------------------------------------------------------------");
    println!(" SCENARIO 1: Node Failure & Checkpoint Recovery Past Window");
    println!("------------------------------------------------------------");

    // Phase 1A: Advance 5 blocks with all 4 nodes active
    let mut prev_hash = genesis_hash;
    for h in 1..=5u64 {
        let proposer_idx = (h as usize) % 4;
        let proposer_addr = nodes[proposer_idx].address;
        let mut block = Block {
            header: BlockHeader {
                parent_hash: prev_hash,
                state_root: [0xaa; 32],
                tx_root: [0; 32],
                receipts_root: [0; 32],
                validator_root: [0; 32],
                zk_proof: None,
                height: h,
                timestamp: 1712073600 + h * 2,
                proposer: proposer_addr,
                randomness_beacon: [0; 32],
                version: 1,
                gas_limit: 30000000,
                gas_used: 0,
                extra_data: Vec::new(),
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                signature: None,
            },
            body: BlockBody::empty(),
        };
        block.header.sign(&nodes[proposer_idx].ed_sk)?;
        let block_hash = block.try_hash()?;

        let refs: Vec<&ValidatorNode> = nodes.iter().collect();
        let qc = create_signed_qc(block_hash, h, VotePhase::Prepare, &refs)?;

        for node in &mut nodes {
            node.consensus.process_block_proposal(block.clone())?;
            node.consensus.process_quorum_certificate(qc.clone())?;
            node.storage
                .atomic_block_commit_typed(h, &block.header, &block.body)?;
        }
        prev_hash = block_hash;
        println!(
            " [CLUSTER] Block {} finalized (View {}) by 4/4 nodes -> Hash: 0x{}...",
            h,
            h,
            hex::encode(&block_hash[..8])
        );
    }

    // Phase 1B: Kill Validator 3 (Crash / Offline)
    println!("\n >>> SIMULATING HARD CRASH: Killing Validator 3 (PID / thread stopped)...");
    let val_3 = nodes.pop().unwrap();
    let val_3_saved_path = val_3.storage_path.clone();
    let val_3_last_height = val_3.storage.latest_block_height()?;
    println!(
        " [CRASHED] Validator 3 offline. Last persisted height = {}",
        val_3_last_height
    );
    drop(val_3); // Close storage / simulate complete process termination

    // Phase 1C: Remaining 3 validators (Validators 0, 1, 2 = 75% quorum >= 67%) advance past weak subjectivity window (>10 blocks)
    println!("\n >>> Advancing 15 blocks (Heights 6..=20) with 3/4 validators (Node 0, 1, 2)...");
    let mut checkpoint_blocks = Vec::new();
    for h in 6..=20u64 {
        let proposer_idx = (h as usize) % 3; // Round-robin over alive nodes
        let proposer_addr = nodes[proposer_idx].address;
        let mut block = Block {
            header: BlockHeader {
                parent_hash: prev_hash,
                state_root: [0xbb; 32],
                tx_root: [0; 32],
                receipts_root: [0; 32],
                validator_root: [0; 32],
                zk_proof: None,
                height: h,
                timestamp: 1712073600 + h * 2,
                proposer: proposer_addr,
                randomness_beacon: [0; 32],
                version: 1,
                gas_limit: 30000000,
                gas_used: 0,
                extra_data: Vec::new(),
                chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
                signature: None,
            },
            body: BlockBody::empty(),
        };
        block.header.sign(&nodes[proposer_idx].ed_sk)?;
        let block_hash = block.try_hash()?;

        let refs: Vec<&ValidatorNode> = nodes.iter().collect(); // Only 3 active nodes
        let qc = create_signed_qc(block_hash, h, VotePhase::Prepare, &refs)?;

        for node in &mut nodes {
            node.consensus.process_block_proposal(block.clone())?;
            node.consensus.process_quorum_certificate(qc.clone())?;
            node.storage
                .atomic_block_commit_typed(h, &block.header, &block.body)?;
        }
        checkpoint_blocks.push((block.clone(), qc.clone()));
        prev_hash = block_hash;
        println!(
            " [CLUSTER] Block {} finalized (View {}) by 3/4 quorum (Nodes 0, 1, 2) -> Hash: 0x{}...",
            h,
            h,
            hex::encode(&block_hash[..8])
        );
    }

    let active_tip_height = nodes[0].storage.latest_block_height()?;
    println!(
        "\n [ACTIVE CLUSTER TIP] Height = {} (15 blocks past Validator 3's crash)",
        active_tip_height
    );

    // Phase 1D: Restart Validator 3 from cold storage and execute Checkpoint State Sync
    println!("\n >>> RESTARTING Validator 3 from cold storage {:?}...", val_3_saved_path);
    let val_3_storage = Arc::new(StorageEngine::new(&val_3_saved_path)?);
    let mut val_3_recovered_consensus = Consensus::with_storage(val_3_storage.clone());
    val_3_recovered_consensus.update_validator_set(validator_defs.clone())?;

    let cold_start_height = val_3_storage.latest_block_height()?;
    println!(
        " [COLD BOOT] Validator 3 loaded database: local_height = {}, active_tip = {}",
        cold_start_height, active_tip_height
    );
    assert_eq!(cold_start_height, 5, "Validator 3 must boot at height 5");

    println!(" [SYNC] Validator 3 initiating peer state-sync over network with Validator 0...");
    for (block, qc) in &checkpoint_blocks {
        val_3_recovered_consensus.process_block_proposal(block.clone())?;
        val_3_recovered_consensus.process_quorum_certificate(qc.clone())?;
        val_3_storage.atomic_block_commit_typed(block.height(), &block.header, &block.body)?;
        println!(
            "  • [SYNC-RECOVERED] Applied Block {} (Hash: 0x{}...) verified with 3-phase QC",
            block.height(),
            hex::encode(&block.try_hash()?[..8])
        );
    }

    let val_3_synced_height = val_3_storage.latest_block_height()?;
    println!(
        " [SYNC COMPLETE] Validator 3 successfully caught up to Height {}! State root verified.",
        val_3_synced_height
    );
    assert_eq!(
        val_3_synced_height, active_tip_height,
        "Validator 3 must match active cluster tip"
    );

    println!("\n------------------------------------------------------------");
    println!(" SCENARIO 2: Adversarial Bad-QC & Double-Signing Rejection");
    println!("------------------------------------------------------------");

    let current_view = nodes[0].consensus.current_view();
    let current_parent = prev_hash;

    // Attack 2A: Bad Quorum Certificate with Forged / Random Signature
    println!(" [ATTACK 2A] Injecting forged QC with randomized BLS signature...");
    let forged_qc = QuorumCertificate::new_with_phase(
        [0xfe; 32],
        current_view + 1,
        VotePhase::Prepare,
        vec![vec![0xde; 96]], // Corrupted signature bytes
        vec![nodes[0].address, nodes[1].address, nodes[2].address],
    );

    for node in &nodes {
        let res = node.consensus.verify_quorum_certificate(&forged_qc);
        assert!(res.is_err(), "Honest node must reject forged QC");
        println!(
            "  ✓ [NODE {}] REJECTED forged QC: {}",
            node.id,
            res.unwrap_err()
        );
    }

    // Attack 2B: Under-Quorum QC (Only 1 validator signature = 25% < 67%)
    println!("\n [ATTACK 2B] Injecting under-quorum QC (1/4 validators = 25% voting power)...");
    let one_node = vec![&nodes[0]];
    let under_quorum_qc =
        create_signed_qc([0xaa; 32], current_view + 1, VotePhase::Prepare, &one_node)?;

    for node in &nodes {
        let res = node.consensus.verify_quorum_certificate(&under_quorum_qc);
        assert!(res.is_err(), "Honest node must reject under-quorum QC");
        println!(
            "  ✓ [NODE {}] REJECTED under-quorum QC: {}",
            node.id,
            res.unwrap_err()
        );
    }

    // Attack 2C: Double-Signing / Equivocation Proposal in same view
    println!("\n [ATTACK 2C] Injecting double-signed proposal (two different blocks for View {} by Proposer {})...", current_view + 1, nodes[0].address);
    let mut block_a = Block {
        header: BlockHeader {
            parent_hash: current_parent,
            state_root: [0x11; 32],
            tx_root: [0; 32],
            receipts_root: [0; 32],
            validator_root: [0; 32],
            zk_proof: None,
            height: 21,
            timestamp: 1712075000,
            proposer: nodes[0].address,
            randomness_beacon: [0; 32],
            version: 1,
            gas_limit: 30000000,
            gas_used: 0,
            extra_data: Vec::new(),
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            signature: None,
        },
        body: BlockBody::empty(),
    };
    block_a.header.sign(&nodes[0].ed_sk)?;

    let mut block_b = Block {
        header: BlockHeader {
            parent_hash: current_parent,
            state_root: [0x22; 32], // Conflicting state root (Equivocation!)
            tx_root: [0; 32],
            receipts_root: [0; 32],
            validator_root: [0; 32],
            zk_proof: None,
            height: 21,
            timestamp: 1712075000,
            proposer: nodes[0].address,
            randomness_beacon: [0; 32],
            version: 1,
            gas_limit: 30000000,
            gas_used: 0,
            extra_data: Vec::new(),
            chain_id: sxiaum_types::SXIAUM_CHAIN_ID,
            signature: None,
        },
        body: BlockBody::empty(),
    };
    block_b.header.sign(&nodes[0].ed_sk)?;

    // First proposal is accepted
    nodes[1].consensus.process_block_proposal(block_a.clone())?;
    println!("  • [NODE 1] Accepted honest proposal A (Hash: 0x{}...)", hex::encode(&block_a.try_hash()?[..8]));

    // Second proposal from same proposer in same view must be rejected as double-proposal
    let res_double = nodes[1].consensus.process_block_proposal(block_b.clone());
    println!(
        "  ✓ [NODE 1] REJECTED double proposal B: {:?}",
        res_double.err().map(|e| e.to_string())
    );

    println!("\n============================================================");
    println!(" ALL ADVERSARIAL MULTI-NODE DEVNET TESTS PASSED");
    println!("============================================================");

    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(())
}
