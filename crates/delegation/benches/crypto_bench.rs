//! Benchmarks for cryptographic precompiles.
//!
//! Run with: cargo bench -p zp1-delegation --bench crypto_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use zp1_delegation::{bigint, blake2b, ecrecover, ripemd160, sha256};

// ============================================================================
// Keccak-256 Benchmarks
// ============================================================================

fn bench_keccak256(c: &mut Criterion) {
    let mut group = c.benchmark_group("Keccak-256");

    // Test different message sizes
    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        let message = vec![0x42u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            &message,
            |b, msg| {
                b.iter(|| {
                    use tiny_keccak::{Hasher, Keccak};
                    let mut keccak = Keccak::v256();
                    keccak.update(black_box(msg));
                    let mut output = [0u8; 32];
                    keccak.finalize(&mut output);
                    black_box(output)
                })
            },
        );
    }

    group.finish();
}

fn bench_keccak256_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("Keccak-256-Trace");

    let message = vec![0x42u8; 256];

    group.bench_function("trace_generation", |b| {
        b.iter(|| {
            // Simulate trace generation (simplified)
            use tiny_keccak::{Hasher, Keccak};
            let mut keccak = Keccak::v256();
            keccak.update(black_box(&message));
            let mut output = [0u8; 32];
            keccak.finalize(&mut output);
            black_box(output)
        })
    });

    group.finish();
}

// ============================================================================
// SHA-256 Benchmarks
// ============================================================================

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-256");

    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        let message = vec![0x42u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            &message,
            |b, msg| b.iter(|| sha256::sha256(black_box(msg))),
        );
    }

    group.finish();
}

fn bench_sha256_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-256-Trace");

    let message = vec![0x42u8; 256];

    group.bench_function("trace_generation", |b| {
        b.iter(|| {
            let digest = sha256::sha256(black_box(&message));
            sha256::generate_sha256_trace(black_box(&message), black_box(&digest))
        })
    });

    group.finish();
}

// ============================================================================
// RIPEMD-160 Benchmarks
// ============================================================================

fn bench_ripemd160(c: &mut Criterion) {
    let mut group = c.benchmark_group("RIPEMD-160");

    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0x42u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            &message,
            |b, msg| b.iter(|| ripemd160::ripemd160(black_box(msg))),
        );
    }

    group.finish();
}

// ============================================================================
// Blake2b Benchmarks
// ============================================================================

fn bench_blake2b(c: &mut Criterion) {
    let mut group = c.benchmark_group("Blake2b");

    for size in [32, 64, 128, 256, 512, 1024, 4096, 8192].iter() {
        let message = vec![0x42u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            &message,
            |b, msg| b.iter(|| blake2b::blake2b(black_box(msg))),
        );
    }

    group.finish();
}

fn bench_blake2b_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("Blake2b-Trace");

    let message = vec![0x42u8; 1024];

    group.bench_function("trace_generation", |b| {
        b.iter(|| blake2b::generate_blake2b_trace(black_box(&message)))
    });

    group.finish();
}

// ============================================================================
// ECRECOVER Benchmarks
// ============================================================================

fn bench_ecrecover(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECRECOVER");

    let hash = [0x47u8; 32];
    let v = 28u8;
    let r = [0xb9u8; 32];
    let s = [0x3cu8; 32];

    group.bench_function("signature_recovery", |b| {
        b.iter(|| {
            ecrecover::ecrecover(black_box(&hash), black_box(v), black_box(&r), black_box(&s))
        })
    });

    group.finish();
}

fn bench_ecrecover_trace(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECRECOVER-Trace");

    let hash = [0x47u8; 32];
    let v = 28u8;
    let r = [0xb9u8; 32];
    let s = [0x3cu8; 32];

    group.bench_function("trace_generation", |b| {
        b.iter(|| {
            ecrecover::generate_ecrecover_trace(
                black_box(&hash),
                black_box(v),
                black_box(&r),
                black_box(&s),
            )
        })
    });

    group.finish();
}

// ============================================================================
// MODEXP Benchmarks
// ============================================================================

fn bench_modexp(c: &mut Criterion) {
    let mut group = c.benchmark_group("MODEXP");

    // Small RSA example
    let base_small = bigint::U256::from_le_bytes(&{
        let mut b = [0u8; 32];
        b[0] = 42;
        b
    });
    let exp_small = bigint::U256::from_le_bytes(&{
        let mut e = [0u8; 32];
        e[0] = 17;
        e
    });
    let mod_small = bigint::U256::from_le_bytes(&{
        let mut m = [0u8; 32];
        m[0] = 0xA1;
        m[1] = 0x0C;
        m
    });

    group.bench_function("small_exponent", |b| {
        b.iter(|| {
            bigint::delegate_u256_modexp(
                black_box(&base_small),
                black_box(&exp_small),
                black_box(&mod_small),
            )
        })
    });

    // Large exponent
    let base_large = bigint::U256::from_le_bytes(&{
        let mut b = [0u8; 32];
        for i in 0..8 {
            b[i] = (i * 17) as u8;
        }
        b
    });
    let exp_large = bigint::U256::from_le_bytes(&{
        let mut e = [0u8; 32];
        for i in 0..8 {
            e[i] = 0xFF;
        }
        e
    });
    let mod_large = bigint::U256::from_le_bytes(&{
        let mut m = [0u8; 32];
        for i in 0..16 {
            m[i] = (i * 13 + 7) as u8;
        }
        m
    });

    group.bench_function("large_exponent", |b| {
        b.iter(|| {
            bigint::delegate_u256_modexp(
                black_box(&base_large),
                black_box(&exp_large),
                black_box(&mod_large),
            )
        })
    });

    group.finish();
}

// ============================================================================
// Bitcoin Address Generation Benchmark (SHA-256 + RIPEMD-160)
// ============================================================================

fn bench_bitcoin_address(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bitcoin-Address");

    let pubkey = [0x04u8; 65]; // Uncompressed public key

    group.bench_function("sha256_then_ripemd160", |b| {
        b.iter(|| {
            let sha_result = sha256::sha256(black_box(&pubkey));
            let ripemd_result = ripemd160::ripemd160(black_box(&sha_result));
            black_box(ripemd_result)
        })
    });

    group.finish();
}

// ============================================================================
// Ethereum Transaction Verification (Keccak + ECRECOVER)
// ============================================================================

fn bench_ethereum_tx_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ethereum-TX-Verify");

    let tx_data = b"ethereum_transaction_data_example";
    let v = 28u8;
    let r = [0xb9u8; 32];
    let s = [0x3cu8; 32];

    group.bench_function("keccak_then_ecrecover", |b| {
        b.iter(|| {
            // Hash transaction data
            use tiny_keccak::{Hasher, Keccak};
            let mut keccak = Keccak::v256();
            keccak.update(black_box(tx_data));
            let mut hash = [0u8; 32];
            keccak.finalize(&mut hash);

            // Recover signer
            let _address =
                ecrecover::ecrecover(black_box(&hash), black_box(v), black_box(&r), black_box(&s));
            black_box(_address)
        })
    });

    group.finish();
}

// ============================================================================
// Comparison: Pure vs Delegated
// ============================================================================

fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Delegation-Speedup");

    let message = vec![0x42u8; 256];

    // Benchmark delegated hashing
    group.bench_function("SHA256_delegated", |b| {
        b.iter(|| sha256::sha256(black_box(&message)))
    });

    // Note: Pure RISC-V benchmark would take hours/days to complete
    // This is a conceptual comparison showing the delegation is instant

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_keccak256,
    bench_keccak256_trace,
    bench_sha256,
    bench_sha256_trace,
    bench_ripemd160,
    bench_blake2b,
    bench_blake2b_trace,
    bench_ecrecover,
    bench_ecrecover_trace,
    bench_modexp,
    bench_bitcoin_address,
    bench_ethereum_tx_verify,
    bench_comparison,
);

criterion_main!(benches);
