#![feature(generic_const_exprs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use curve25519_dalek::ristretto::RistrettoPoint;
use sp::{Secret, Statement};

fn bench_statement_creation<const M: usize, const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("Statement Creation M={} N={}", M, N));

    group.bench_function("random", |b| {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        b.iter(|| Statement::<M, N, RistrettoPoint>::random(black_box(&mut rng)));
    });

    group.finish();
}

fn bench_public_computation<const M: usize, const N: usize>(c: &mut Criterion) {
    let mut group = c.benchmark_group(format!("Public Computation M={} N={}", M, N));
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
    let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);

    group.bench_function("compute_public", |b| {
        b.iter(|| statement.compute_public(black_box(&secret)));
    });

    group.finish();
}

fn bench_sign<const M: usize, const N: usize>(c: &mut Criterion) 
where
    [(); 32 * N]:, // Required for generic_const_exprs
    RistrettoPoint: group::Group + serde::Serialize + Default,
{
    let mut group = c.benchmark_group(format!("Signing M={} N={}", M, N));
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
    let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
    let message = b"benchmark test message";

    group.bench_function("sign", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            statement.sign(black_box(&secret), black_box(message), black_box(&mut rng))
        });
    });

    group.finish();
}

fn bench_verify<const M: usize, const N: usize>(c: &mut Criterion) 
where
    [(); 32 * N]:, // Required for generic_const_exprs
    RistrettoPoint: group::Group + serde::Serialize + Default,
{
    let mut group = c.benchmark_group(format!("Verification M={} N={}", M, N));
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    
    let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
    let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
    let public = statement.compute_public(&secret);
    let message = b"benchmark test message";
    let proof = statement.sign(&secret, message, &mut rng);

    group.bench_function("verify", |b| {
        b.iter(|| statement.verify(
            black_box(&proof), 
            black_box(message), 
            black_box(&public)
        ));
    });

    group.finish();
}

fn bench_e2e<const M: usize, const N: usize>(c: &mut Criterion) 
where
    [(); 32 * N]:, // Required for generic_const_exprs
    RistrettoPoint: group::Group + serde::Serialize + Default,
{
    let mut group = c.benchmark_group(format!("End-to-End M={} N={}", M, N));
    
    group.bench_function("full_cycle", |b| {
        b.iter(|| {
            let mut rng = ChaCha20Rng::seed_from_u64(42);
            let secret = Secret::<N, RistrettoPoint>::random(&mut rng);
            let statement = Statement::<M, N, RistrettoPoint>::random(&mut rng);
            let public = statement.compute_public(&secret);
            let message = b"benchmark test message";
            let proof = statement.sign(&secret, message, &mut rng);
            statement.verify(&proof, message, &public)
        });
    });

    group.finish();
}

// Small statement benchmarks (M=1, N=1)
fn bench_small_statement_creation(c: &mut Criterion) { bench_statement_creation::<1, 1>(c); }
fn bench_small_public_computation(c: &mut Criterion) { bench_public_computation::<1, 1>(c); }
fn bench_small_sign(c: &mut Criterion) { bench_sign::<1, 1>(c); }
fn bench_small_verify(c: &mut Criterion) { bench_verify::<1, 1>(c); }
fn bench_small_e2e(c: &mut Criterion) { bench_e2e::<1, 1>(c); }

// Medium statement benchmarks (M=2, N=3)
fn bench_medium_statement_creation(c: &mut Criterion) { bench_statement_creation::<2, 3>(c); }
fn bench_medium_public_computation(c: &mut Criterion) { bench_public_computation::<2, 3>(c); }
fn bench_medium_sign(c: &mut Criterion) { bench_sign::<2, 3>(c); }
fn bench_medium_verify(c: &mut Criterion) { bench_verify::<2, 3>(c); }
fn bench_medium_e2e(c: &mut Criterion) { bench_e2e::<2, 3>(c); }

// Large statement benchmarks (M=5, N=10)
fn bench_large_statement_creation(c: &mut Criterion) { bench_statement_creation::<5, 10>(c); }
fn bench_large_public_computation(c: &mut Criterion) { bench_public_computation::<5, 10>(c); }
fn bench_large_sign(c: &mut Criterion) { bench_sign::<5, 10>(c); }
fn bench_large_verify(c: &mut Criterion) { bench_verify::<5, 10>(c); }
fn bench_large_e2e(c: &mut Criterion) { bench_e2e::<5, 10>(c); }

// Very large statement benchmarks (M=10, N=20)
fn bench_very_large_statement_creation(c: &mut Criterion) { bench_statement_creation::<10, 20>(c); }
fn bench_very_large_public_computation(c: &mut Criterion) { bench_public_computation::<10, 20>(c); }
fn bench_very_large_sign(c: &mut Criterion) { bench_sign::<10, 20>(c); }
fn bench_very_large_verify(c: &mut Criterion) { bench_verify::<10, 20>(c); }
fn bench_very_large_e2e(c: &mut Criterion) { bench_e2e::<10, 20>(c); }

// Huge statement benchmarks (M=100, N=100)
fn bench_huge_statement_creation(c: &mut Criterion) { bench_statement_creation::<50, 50>(c); }
fn bench_huge_public_computation(c: &mut Criterion) { bench_public_computation::<50, 50>(c); }
fn bench_huge_sign(c: &mut Criterion) { bench_sign::<50, 50>(c); }
fn bench_huge_verify(c: &mut Criterion) { bench_verify::<50, 50>(c); }
fn bench_huge_e2e(c: &mut Criterion) { bench_e2e::<50, 50>(c); }

criterion_group!(
    benches,
    // Small statement benchmarks
    bench_small_statement_creation,
    bench_small_public_computation,
    bench_small_sign,
    bench_small_verify,
    bench_small_e2e,
    
    // Medium statement benchmarks
    bench_medium_statement_creation,
    bench_medium_public_computation,
    bench_medium_sign,
    bench_medium_verify,
    bench_medium_e2e,
    
    // Large statement benchmarks
    bench_large_statement_creation,
    bench_large_public_computation,
    bench_large_sign,
    bench_large_verify,
    bench_large_e2e,
    
    // Very large statement benchmarks
    bench_very_large_statement_creation,
    bench_very_large_public_computation,
    bench_very_large_sign,
    bench_very_large_verify,
    bench_very_large_e2e,
    
    // Huge statement benchmarks
    bench_huge_statement_creation,
    bench_huge_public_computation,
    bench_huge_sign,
    bench_huge_verify,
    bench_huge_e2e,
);

criterion_main!(benches);
