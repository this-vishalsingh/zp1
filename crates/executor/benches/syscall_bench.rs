//! Benchmarks for cryptographic syscalls in the executor.
//!
//! Run with: cargo bench -p zp1-executor --bench syscall_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zp1_executor::Cpu;

// Syscall numbers
const KECCAK256_SYSCALL: u32 = 0x1000;
const ECRECOVER_SYSCALL: u32 = 0x1001;
const SHA256_SYSCALL: u32 = 0x1002;
const RIPEMD160_SYSCALL: u32 = 0x1003;
const MODEXP_SYSCALL: u32 = 0x1004;
const BLAKE2B_SYSCALL: u32 = 0x1005;

// ============================================================================
// Helper Functions
// ============================================================================

fn setup_cpu_with_program(syscall_num: u32) -> Cpu {
    let mut cpu = Cpu::new();
    cpu.enable_tracing();

    // Create program: ecall, then exit
    let program: Vec<u32> = vec![
        0x00000073, // ecall (crypto operation)
        0x05d00893, // li a7, 93 (exit syscall)
        0x00000073, // ecall (exit)
    ];

    let program_bytes: Vec<u8> = program
        .iter()
        .flat_map(|instr| instr.to_le_bytes())
        .collect();
    cpu.memory.load_program(0, &program_bytes).unwrap();

    cpu.set_reg(17, syscall_num);
    cpu
}

// ============================================================================
// Keccak-256 Syscall Benchmark
// ============================================================================

fn bench_keccak256_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Syscall-Keccak256");

    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            size,
            |b, _| {
                b.iter(|| {
                    let mut cpu = setup_cpu_with_program(KECCAK256_SYSCALL);

                    let input_ptr = 0x1000;
                    let output_ptr = 0x2000;

                    // Write message to memory
                    for (i, &byte) in message.iter().enumerate() {
                        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
                    }

                    cpu.set_reg(10, input_ptr);
                    cpu.set_reg(11, message.len() as u32);
                    cpu.set_reg(12, output_ptr);

                    // Execute syscall
                    for _ in 0..5 {
                        if cpu.pc == 4 {
                            break;
                        }
                        let _ = cpu.step();
                    }

                    black_box(cpu)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// SHA-256 Syscall Benchmark
// ============================================================================

fn bench_sha256_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Syscall-SHA256");

    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            size,
            |b, _| {
                b.iter(|| {
                    let mut cpu = setup_cpu_with_program(SHA256_SYSCALL);

                    let input_ptr = 0x1000;
                    let output_ptr = 0x2000;

                    for (i, &byte) in message.iter().enumerate() {
                        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
                    }

                    cpu.set_reg(10, input_ptr);
                    cpu.set_reg(11, message.len() as u32);
                    cpu.set_reg(12, output_ptr);

                    for _ in 0..5 {
                        if cpu.pc == 4 {
                            break;
                        }
                        let _ = cpu.step();
                    }

                    black_box(cpu)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// RIPEMD-160 Syscall Benchmark
// ============================================================================

fn bench_ripemd160_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Syscall-RIPEMD160");

    let message = vec![0x42u8; 256];

    group.bench_function("256B", |b| {
        b.iter(|| {
            let mut cpu = setup_cpu_with_program(RIPEMD160_SYSCALL);

            let input_ptr = 0x1000;
            let output_ptr = 0x2000;

            for (i, &byte) in message.iter().enumerate() {
                cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
            }

            cpu.set_reg(10, input_ptr);
            cpu.set_reg(11, message.len() as u32);
            cpu.set_reg(12, output_ptr);

            for _ in 0..5 {
                if cpu.pc == 4 {
                    break;
                }
                let _ = cpu.step();
            }

            black_box(cpu)
        })
    });

    group.finish();
}

// ============================================================================
// Blake2b Syscall Benchmark
// ============================================================================

fn bench_blake2b_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Syscall-Blake2b");

    for size in [32, 64, 128, 256, 512, 1024].iter() {
        let message = vec![0x42u8; *size];

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}B", size)),
            size,
            |b, _| {
                b.iter(|| {
                    let mut cpu = setup_cpu_with_program(BLAKE2B_SYSCALL);

                    let input_ptr = 0x1000;
                    let output_ptr = 0x2000;

                    for (i, &byte) in message.iter().enumerate() {
                        cpu.memory.write_byte(input_ptr + i as u32, byte).unwrap();
                    }

                    cpu.set_reg(10, input_ptr);
                    cpu.set_reg(11, message.len() as u32);
                    cpu.set_reg(12, output_ptr);

                    for _ in 0..5 {
                        if cpu.pc == 4 {
                            break;
                        }
                        let _ = cpu.step();
                    }

                    black_box(cpu)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// ECRECOVER Syscall Benchmark
// ============================================================================

fn bench_ecrecover_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Syscall-ECRECOVER");

    let hash: [u8; 32] = [0x47; 32];
    let v = 28u8;
    let r: [u8; 32] = [0xb9; 32];
    let s: [u8; 32] = [0x3c; 32];

    group.bench_function("signature_recovery", |b| {
        b.iter(|| {
            let mut cpu = setup_cpu_with_program(ECRECOVER_SYSCALL);

            let hash_ptr = 0x1000;
            let output_ptr = 0x2000;

            // Write inputs to memory
            for (i, &byte) in hash.iter().enumerate() {
                cpu.memory.write_byte(hash_ptr + i as u32, byte).unwrap();
            }

            let r_ptr = hash_ptr + 32;
            for (i, &byte) in r.iter().enumerate() {
                cpu.memory.write_byte(r_ptr + i as u32, byte).unwrap();
            }

            let s_ptr = r_ptr + 32;
            for (i, &byte) in s.iter().enumerate() {
                cpu.memory.write_byte(s_ptr + i as u32, byte).unwrap();
            }

            cpu.set_reg(10, hash_ptr);
            cpu.set_reg(11, (v as u32) | ((r_ptr) << 8));
            cpu.set_reg(12, (s_ptr) | ((output_ptr) << 16));

            for _ in 0..5 {
                if cpu.pc == 4 {
                    break;
                }
                let _ = cpu.step();
            }

            black_box(cpu)
        })
    });

    group.finish();
}

// ============================================================================
// MODEXP Syscall Benchmark
// ============================================================================

fn bench_modexp_syscall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Syscall-MODEXP");

    group.bench_function("small_exponent", |b| {
        b.iter(|| {
            let mut cpu = setup_cpu_with_program(MODEXP_SYSCALL);

            let base_ptr = 0x1000;
            let exp_ptr = 0x1020;
            let mod_ptr = 0x1040;
            let result_ptr = 0x2000;

            // Write base = 2
            cpu.memory.write_byte(base_ptr, 2).unwrap();
            // Write exp = 3
            cpu.memory.write_byte(exp_ptr, 3).unwrap();
            // Write mod = 5
            cpu.memory.write_byte(mod_ptr, 5).unwrap();

            cpu.set_reg(10, base_ptr);
            cpu.set_reg(11, exp_ptr);
            cpu.set_reg(12, mod_ptr);
            cpu.set_reg(13, result_ptr);

            for _ in 0..5 {
                if cpu.pc == 4 {
                    break;
                }
                let _ = cpu.step();
            }

            black_box(cpu)
        })
    });

    group.finish();
}

// ============================================================================
// End-to-End Workflow Benchmarks
// ============================================================================

fn bench_bitcoin_address_workflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("Workflow-Bitcoin-Address");

    let pubkey = [0x04u8; 65];

    group.bench_function("sha256_then_ripemd160", |b| {
        b.iter(|| {
            // SHA-256 syscall
            let mut cpu1 = setup_cpu_with_program(SHA256_SYSCALL);
            let input_ptr = 0x1000;
            let sha_out = 0x2000;

            for (i, &byte) in pubkey.iter().enumerate() {
                cpu1.memory.write_byte(input_ptr + i as u32, byte).unwrap();
            }

            cpu1.set_reg(10, input_ptr);
            cpu1.set_reg(11, 65);
            cpu1.set_reg(12, sha_out);

            for _ in 0..5 {
                if cpu1.pc == 4 {
                    break;
                }
                let _ = cpu1.step();
            }

            // RIPEMD-160 syscall
            let mut cpu2 = setup_cpu_with_program(RIPEMD160_SYSCALL);
            let ripemd_out = 0x3000;

            cpu2.set_reg(10, sha_out);
            cpu2.set_reg(11, 32);
            cpu2.set_reg(12, ripemd_out);

            for _ in 0..5 {
                if cpu2.pc == 4 {
                    break;
                }
                let _ = cpu2.step();
            }

            black_box((cpu1, cpu2))
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_keccak256_syscall,
    bench_sha256_syscall,
    bench_ripemd160_syscall,
    bench_blake2b_syscall,
    bench_ecrecover_syscall,
    bench_modexp_syscall,
    bench_bitcoin_address_workflow,
);

criterion_main!(benches);
