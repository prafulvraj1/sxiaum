//! Criterion benchmarks for the SXIAUM 128-bit MNT4-753 / MNT6-753 recursive folding engine.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sxiaum_zk::groth16::fold::FoldAnchorConfig;
use sxiaum_zk::ZkEngine;

const BENCH_GENESIS: [u8; 32] = [0xAA; 32];
const BENCH_ANCHOR_HEIGHT: u64 = 10_000;

fn bench_anchor() -> FoldAnchorConfig {
    FoldAnchorConfig {
        root: [0xBB; 32],
        block_hash: [0xCC; 32],
        height: BENCH_ANCHOR_HEIGHT,
    }
}

fn bench_fold_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_128bit_verification");
    let anchor = bench_anchor();
    let mut engine = ZkEngine::new();
    engine
        .init_fold_stack(anchor.clone())
        .expect("fold stack init");

    let anchor_cert = engine
        .generate_recursive_state_sync_proof(
            BENCH_GENESIS,
            anchor.root,
            anchor.block_hash,
            anchor.height,
            [0u8; 32],
        )
        .expect("anchor cert");

    let folded_cert = engine
        .generate_folded_certificate(
            BENCH_GENESIS,
            &anchor_cert,
            None,
            [0x11; 32],
            [0x22; 32],
            BENCH_ANCHOR_HEIGHT + 10_000,
            anchor_cert.certificate_hash().expect("hash"),
        )
        .expect("folded cert");

    group.bench_function("verify_bootstrap_layer_a_single_pairing", |b| {
        b.iter(|| {
            let valid = engine
                .verify_recursive_state_sync_proof(
                    black_box(BENCH_GENESIS),
                    black_box(anchor_cert.target_state_root),
                    black_box(anchor_cert.target_block_hash),
                    black_box(anchor_cert.target_height),
                    black_box(anchor_cert.prev_certificate_hash),
                    black_box(&anchor_cert.proof),
                )
                .expect("verification");
            assert!(valid);
        });
    });

    group.bench_function("verify_folded_layer_b_single_pairing", |b| {
        b.iter(|| {
            let valid = engine
                .verify_folded_certificate(
                    black_box(BENCH_GENESIS),
                    black_box(&folded_cert),
                    black_box(&anchor_cert),
                    black_box(None),
                )
                .expect("verification");
            assert!(valid);
        });
    });

    group.finish();
}

fn bench_fold_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("fold_128bit_proving");
    group.sample_size(10);

    let anchor = bench_anchor();
    let mut engine = ZkEngine::new();
    engine
        .init_fold_stack(anchor.clone())
        .expect("fold stack init");

    let anchor_cert = engine
        .generate_recursive_state_sync_proof(
            BENCH_GENESIS,
            anchor.root,
            anchor.block_hash,
            anchor.height,
            [0u8; 32],
        )
        .expect("anchor cert");

    group.bench_function("prove_folded_certificate_layer_b", |b| {
        b.iter(|| {
            let cert = engine
                .generate_folded_certificate(
                    black_box(BENCH_GENESIS),
                    black_box(&anchor_cert),
                    black_box(None),
                    black_box([0x11; 32]),
                    black_box([0x22; 32]),
                    black_box(BENCH_ANCHOR_HEIGHT + 10_000),
                    black_box(anchor_cert.certificate_hash().expect("hash")),
                )
                .expect("proving");
            black_box(cert);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_fold_verification, bench_fold_proving);
criterion_main!(benches);
