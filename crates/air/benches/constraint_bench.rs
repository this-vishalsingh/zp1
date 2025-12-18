//! Benchmarks for AIR constraint evaluation.
//!
//! Run with: cargo bench -p zp1-air
//!
//! This benchmark compares bit-based vs lookup-based bitwise constraints.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zp1_air::rv32im::{ConstraintEvaluator, CpuTraceRow};
use zp1_primitives::M31;

/// Create a test row for bitwise AND operation.
fn create_and_row() -> CpuTraceRow {
    let mut row = CpuTraceRow::default();

    // AND: 0x12345678 & 0x0F0F0F0F = 0x02040608
    row.is_and = M31::ONE;

    // rs1 = 0x12345678
    row.rs1_val_lo = M31::new(0x5678);
    row.rs1_val_hi = M31::new(0x1234);

    // rs2 = 0x0F0F0F0F
    row.rs2_val_lo = M31::new(0x0F0F);
    row.rs2_val_hi = M31::new(0x0F0F);

    // Result = 0x02040608
    row.rd_val_lo = M31::new(0x0608);
    row.rd_val_hi = M31::new(0x0204);

    // Bit decomposition for bit-based constraints
    let rs1: u32 = 0x12345678;
    let rs2: u32 = 0x0F0F0F0F;
    let result = rs1 & rs2;

    for i in 0..32 {
        row.rs1_bits[i] = M31::new(((rs1 >> i) & 1) as u32);
        row.rs2_bits[i] = M31::new(((rs2 >> i) & 1) as u32);
        row.and_bits[i] = M31::new(((result >> i) & 1) as u32);
    }

    // Byte decomposition for lookup-based constraints
    row.rs1_bytes[0] = M31::new(0x78);
    row.rs1_bytes[1] = M31::new(0x56);
    row.rs1_bytes[2] = M31::new(0x34);
    row.rs1_bytes[3] = M31::new(0x12);

    row.rs2_bytes[0] = M31::new(0x0F);
    row.rs2_bytes[1] = M31::new(0x0F);
    row.rs2_bytes[2] = M31::new(0x0F);
    row.rs2_bytes[3] = M31::new(0x0F);

    row.and_result_bytes[0] = M31::new(0x08);
    row.and_result_bytes[1] = M31::new(0x06);
    row.and_result_bytes[2] = M31::new(0x04);
    row.and_result_bytes[3] = M31::new(0x02);

    row
}

/// Create a test row for bitwise XOR operation.
fn create_xor_row() -> CpuTraceRow {
    let mut row = CpuTraceRow::default();

    // XOR: 0xAAAAAAAA ^ 0x55555555 = 0xFFFFFFFF
    row.is_xor = M31::ONE;

    row.rs1_val_lo = M31::new(0xAAAA);
    row.rs1_val_hi = M31::new(0xAAAA);

    row.rs2_val_lo = M31::new(0x5555);
    row.rs2_val_hi = M31::new(0x5555);

    row.rd_val_lo = M31::new(0xFFFF);
    row.rd_val_hi = M31::new(0xFFFF);

    // Bit decomposition
    let rs1: u32 = 0xAAAAAAAA;
    let rs2: u32 = 0x55555555;
    let result = rs1 ^ rs2;

    for i in 0..32 {
        row.rs1_bits[i] = M31::new(((rs1 >> i) & 1) as u32);
        row.rs2_bits[i] = M31::new(((rs2 >> i) & 1) as u32);
        row.xor_bits[i] = M31::new(((result >> i) & 1) as u32);
    }

    // Byte decomposition
    row.rs1_bytes[0] = M31::new(0xAA);
    row.rs1_bytes[1] = M31::new(0xAA);
    row.rs1_bytes[2] = M31::new(0xAA);
    row.rs1_bytes[3] = M31::new(0xAA);

    row.rs2_bytes[0] = M31::new(0x55);
    row.rs2_bytes[1] = M31::new(0x55);
    row.rs2_bytes[2] = M31::new(0x55);
    row.rs2_bytes[3] = M31::new(0x55);

    row.xor_result_bytes[0] = M31::new(0xFF);
    row.xor_result_bytes[1] = M31::new(0xFF);
    row.xor_result_bytes[2] = M31::new(0xFF);
    row.xor_result_bytes[3] = M31::new(0xFF);

    row
}

fn bench_and_bit_based(c: &mut Criterion) {
    let row = create_and_row();

    c.bench_function("AND_bit_based", |b| {
        b.iter(|| ConstraintEvaluator::and_constraint(black_box(&row)))
    });
}

fn bench_and_lookup_based(c: &mut Criterion) {
    let row = create_and_row();

    c.bench_function("AND_lookup_based", |b| {
        b.iter(|| ConstraintEvaluator::and_constraint_lookup(black_box(&row)))
    });
}

fn bench_xor_bit_based(c: &mut Criterion) {
    let row = create_xor_row();

    c.bench_function("XOR_bit_based", |b| {
        b.iter(|| ConstraintEvaluator::xor_constraint(black_box(&row)))
    });
}

fn bench_xor_lookup_based(c: &mut Criterion) {
    let row = create_xor_row();

    c.bench_function("XOR_lookup_based", |b| {
        b.iter(|| ConstraintEvaluator::xor_constraint_lookup(black_box(&row)))
    });
}

fn bench_bitwise_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bitwise_Constraints");

    let and_row = create_and_row();
    let xor_row = create_xor_row();

    group.bench_function("AND/bit_based", |b| {
        b.iter(|| ConstraintEvaluator::and_constraint(black_box(&and_row)))
    });

    group.bench_function("AND/lookup_based", |b| {
        b.iter(|| ConstraintEvaluator::and_constraint_lookup(black_box(&and_row)))
    });

    group.bench_function("XOR/bit_based", |b| {
        b.iter(|| ConstraintEvaluator::xor_constraint(black_box(&xor_row)))
    });

    group.bench_function("XOR/lookup_based", |b| {
        b.iter(|| ConstraintEvaluator::xor_constraint_lookup(black_box(&xor_row)))
    });

    group.finish();
}

/// Benchmark evaluating many rows (simulating trace evaluation)
fn bench_batch_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch_Evaluation");

    for num_rows in [100, 1000, 10000] {
        let rows: Vec<CpuTraceRow> = (0..num_rows).map(|_| create_and_row()).collect();

        group.bench_with_input(BenchmarkId::new("bit_based", num_rows), &rows, |b, rows| {
            b.iter(|| {
                let mut sum = M31::ZERO;
                for row in rows.iter() {
                    sum = sum + ConstraintEvaluator::and_constraint(black_box(row));
                }
                sum
            })
        });

        group.bench_with_input(
            BenchmarkId::new("lookup_based", num_rows),
            &rows,
            |b, rows| {
                b.iter(|| {
                    let mut sum = M31::ZERO;
                    for row in rows.iter() {
                        sum = sum + ConstraintEvaluator::and_constraint_lookup(black_box(row));
                    }
                    sum
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_and_bit_based,
    bench_and_lookup_based,
    bench_xor_bit_based,
    bench_xor_lookup_based,
    bench_bitwise_comparison,
    bench_batch_evaluation,
);
criterion_main!(benches);
