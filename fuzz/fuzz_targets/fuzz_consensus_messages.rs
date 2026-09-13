#![no_main]

use libfuzzer_sys::fuzz_target;
use primitive_types::U256;
use sxiaum_consensus::hotstuff::vote::{
    QuorumCertificate, TimeoutVote, ViewChangeCertificate, Vote,
};
use sxiaum_types::Validator;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Fuzz Vote deserialization, phase transitions, and encoding
    if let Ok(vote) = bincode::deserialize::<Vote>(data) {
        let _ = vote.encode();
        let _ = vote.signing_message();
        let _ = vote.phase.as_byte();
        let _ = vote.phase.next();

        // Exercise verification against mock validator
        let val = Validator::new(vote.validator, [2u8; 32], U256::from(1000));
        let _ = vote.verify_signature(&val);
    }

    if let Ok(decoded_vote) = Vote::decode(data) {
        let _ = decoded_vote.encode();
    }

    // 2. Fuzz QuorumCertificate
    if let Ok(qc) = bincode::deserialize::<QuorumCertificate>(data) {
        let _ = qc.encode();
        let _ = qc.validator_bitmap();
        let _ = qc.is_genesis();
        let _ = qc.phase.as_byte();
        let _ = qc.aggregate_bls_signature();

        let mock_vals: Vec<Validator> = qc
            .validators
            .iter()
            .map(|&addr| Validator::new(addr, [3u8; 32], U256::from(1000)))
            .collect();
        let _ = qc.verify(&mock_vals, 1);
        let _ = qc.verify_with_voting_power(&mock_vals, 1, 1);
    }

    if let Ok(decoded_qc) = QuorumCertificate::decode(data) {
        let _ = decoded_qc.encode();
    }

    // 3. Fuzz TimeoutVote & ViewChangeCertificate
    if let Ok(tv) = bincode::deserialize::<TimeoutVote>(data) {
        let _ = tv.signing_message();
        let val = Validator::new(tv.validator, [2u8; 32], U256::from(1000));
        let _ = tv.verify_signature(&val);

        let mut vcc = ViewChangeCertificate::new(tv.view, tv.view.saturating_add(1));
        vcc.add_timeout_vote(tv);
    }

    if let Ok(vcc) = bincode::deserialize::<ViewChangeCertificate>(data) {
        let _ = vcc.view;
        let _ = vcc.new_view;
        let _ = vcc.timeout_votes.len();
    }
});

