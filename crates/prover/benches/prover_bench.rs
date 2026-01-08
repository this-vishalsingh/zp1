//! Benchmarks for prover components.
//!
//! Run with: cargo bench -p zp1-prover

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use zp1_primitives::{CirclePoint, M31, QM31};
use zp1_prover::parallel::{
    parallel_batch_inverse, parallel_evaluate_poly, parallel_fri_fold, parallel_lde,
    parallel_merkle_tree,
};

fn bench_parallel_lde(c: &mut Criterion) {
    let mut group = c.benchmark_group("LDE");

    for log_size in [10, 12, 14, 16] {
        let size = 1 << log_size;
        let column: Vec<M31> = (0..size).map(|i| M31::new(i as u32)).collect();
        let columns = vec![column];

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("2^{}", log_size)),
            &columns,
            |b, cols| b.iter(|| parallel_lde(black_box(cols), 4)),
        );
    }

    group.finish();
}

fn bench_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("MerkleTree");

    for log_size in [10, 12, 14, 16] {
        let size = 1 << log_size;
        let values: Vec<M31> = (0..size).map(|i| M31::new(i as u32)).collect();

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("2^{}", log_size)),
            &values,
            |b, vals| b.iter(|| parallel_merkle_tree(black_box(vals))),
        );
    }

    group.finish();
}

fn bench_fri_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("FRI_Fold");

    for log_size in [10, 12, 14, 16] {
        let size = 1 << log_size;
        let values: Vec<M31> = (0..size).map(|i| M31::new(i as u32)).collect();
        let alpha = M31::new(12345);

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("2^{}", log_size)),
            &values,
            |b, vals| b.iter(|| parallel_fri_fold(black_box(vals), black_box(alpha))),
        );
    }

    group.finish();
}

fn bench_batch_inverse(c: &mut Criterion) {
    let mut group = c.benchmark_group("BatchInverse");

    for log_size in [10, 12, 14, 16] {
        let size = 1 << log_size;
        let values: Vec<M31> = (1..=size).map(|i| M31::new(i as u32)).collect();

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("2^{}", log_size)),
            &values,
            |b, vals| b.iter(|| parallel_batch_inverse(black_box(vals))),
        );
    }

    group.finish();
}

fn bench_poly_eval(c: &mut Criterion) {
    let mut group = c.benchmark_group("PolyEval");

    for log_degree in [8, 10, 12] {
        let degree = 1 << log_degree;
        let coeffs: Vec<M31> = (0..degree).map(|i| M31::new(i as u32)).collect();
        let num_points = 1024;
        let points: Vec<M31> = (0..num_points).map(|i| M31::new(i as u32)).collect();

        group.bench_with_input(
            BenchmarkId::new("parallel", format!("deg=2^{},pts=1024", log_degree)),
            &(&coeffs, &points),
            |b, (c, p)| b.iter(|| parallel_evaluate_poly(black_box(*c), black_box(*p))),
        );
    }

    group.finish();
}

fn bench_m31_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("M31");

    let a = M31::new(123456789);
    let b = M31::new(987654321);

    group.bench_function("add", |bench| bench.iter(|| black_box(a) + black_box(b)));

    group.bench_function("mul", |bench| bench.iter(|| black_box(a) * black_box(b)));

    group.bench_function("inv", |bench| bench.iter(|| black_box(a).inv()));

    group.finish();
}

fn bench_qm31_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("QM31");

    let a = QM31::new(
        M31::new(123456789),
        M31::new(987654321),
        M31::new(111111111),
        M31::new(222222222),
    );
    let b = QM31::new(
        M31::new(333333333),
        M31::new(444444444),
        M31::new(555555555),
        M31::new(666666666),
    );

    group.bench_function("add", |bench| bench.iter(|| black_box(a) + black_box(b)));

    group.bench_function("mul", |bench| bench.iter(|| black_box(a) * black_box(b)));

    group.bench_function("inv", |bench| bench.iter(|| black_box(a).inv()));

    group.finish();
}

fn bench_circle_fft(c: &mut Criterion) {
    use zp1_primitives::CircleFFT;

    let mut group = c.benchmark_group("CircleFFT");

    for log_size in [8, 10, 12] {
        let size = 1 << log_size;
        let values: Vec<M31> = (0..size).map(|i| M31::new(i as u32)).collect();
        let fft = CircleFFT::new(log_size);

        group.bench_with_input(
            BenchmarkId::new("fft", format!("2^{}", log_size)),
            &values,
            |b, vals| {
                let mut v = vals.clone();
                b.iter(|| {
                    v.clone_from(vals);
                    fft.fft(black_box(&mut v));
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("ifft", format!("2^{}", log_size)),
            &values,
            |b, vals| {
                let mut v = vals.clone();
                b.iter(|| {
                    v.clone_from(vals);
                    fft.ifft(black_box(&mut v));
                })
            },
        );
    }

    group.finish();
}

// =============== GPU vs CPU Benchmarks ===============

fn bench_gpu_ntt(c: &mut Criterion) {
    use zp1_prover::gpu::{get_backend_for_device, DeviceType};

    let mut group = c.benchmark_group("GPU_NTT");

    // Get backends (CPU always available, Metal on macOS)
    let cpu_backend = get_backend_for_device(DeviceType::Cpu).unwrap();

    #[cfg(target_os = "macos")]
    let metal_backend = get_backend_for_device(DeviceType::Metal).ok();
    #[cfg(not(target_os = "macos"))]
    let metal_backend: Option<Box<dyn zp1_prover::gpu::GpuBackend>> = None;

    for log_size in [10, 12, 14] {
        let size = 1 << log_size;
        let values: Vec<u32> = (0..size).map(|i| i as u32 % ((1 << 31) - 1)).collect();

        // CPU benchmark
        group.bench_with_input(
            BenchmarkId::new("CPU", format!("2^{}", log_size)),
            &values,
            |b, vals| {
                let mut v = vals.clone();
                b.iter(|| {
                    v.clone_from(vals);
                    cpu_backend.ntt_m31(black_box(&mut v), log_size).unwrap();
                })
            },
        );

        // Metal benchmark (macOS only)
        if let Some(ref backend) = metal_backend {
            group.bench_with_input(
                BenchmarkId::new("Metal", format!("2^{}", log_size)),
                &values,
                |b, vals| {
                    let mut v = vals.clone();
                    b.iter(|| {
                        v.clone_from(vals);
                        backend.ntt_m31(black_box(&mut v), log_size).unwrap();
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_gpu_lde(c: &mut Criterion) {
    use zp1_prover::gpu::{get_backend_for_device, DeviceType};

    let mut group = c.benchmark_group("GPU_LDE");

    let cpu_backend = get_backend_for_device(DeviceType::Cpu).unwrap();

    #[cfg(target_os = "macos")]
    let metal_backend = get_backend_for_device(DeviceType::Metal).ok();
    #[cfg(not(target_os = "macos"))]
    let metal_backend: Option<Box<dyn zp1_prover::gpu::GpuBackend>> = None;

    for log_size in [8, 10, 12] {
        let size = 1 << log_size;
        let coeffs: Vec<u32> = (0..size).map(|i| i as u32 % ((1 << 31) - 1)).collect();
        let blowup = 4;

        // CPU benchmark
        group.bench_with_input(
            BenchmarkId::new("CPU", format!("2^{}", log_size)),
            &coeffs,
            |b, c| b.iter(|| cpu_backend.lde(black_box(c), black_box(blowup)).unwrap()),
        );

        // Metal benchmark (macOS only)
        if let Some(ref backend) = metal_backend {
            group.bench_with_input(
                BenchmarkId::new("Metal", format!("2^{}", log_size)),
                &coeffs,
                |b, c| b.iter(|| backend.lde(black_box(c), black_box(blowup)).unwrap()),
            );
        }
    }

    group.finish();
}

fn bench_gpu_merkle(c: &mut Criterion) {
    use zp1_prover::gpu::{get_backend_for_device, DeviceType};

    let mut group = c.benchmark_group("GPU_Merkle");

    let cpu_backend = get_backend_for_device(DeviceType::Cpu).unwrap();

    #[cfg(target_os = "macos")]
    let metal_backend = get_backend_for_device(DeviceType::Metal).ok();
    #[cfg(not(target_os = "macos"))]
    let metal_backend: Option<Box<dyn zp1_prover::gpu::GpuBackend>> = None;

    for log_size in [10, 12, 14] {
        let size = 1 << log_size;
        let leaves: Vec<[u8; 32]> = (0..size)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                h
            })
            .collect();

        // CPU benchmark
        group.bench_with_input(
            BenchmarkId::new("CPU", format!("2^{}", log_size)),
            &leaves,
            |b, l| b.iter(|| cpu_backend.merkle_tree(black_box(l)).unwrap()),
        );

        // Metal benchmark (macOS only)
        if let Some(ref backend) = metal_backend {
            group.bench_with_input(
                BenchmarkId::new("Metal", format!("2^{}", log_size)),
                &leaves,
                |b, l| b.iter(|| backend.merkle_tree(black_box(l)).unwrap()),
            );
        }
    }

    group.finish();
}

fn bench_gpu_batch_eval(c: &mut Criterion) {
    use zp1_prover::gpu::{get_backend_for_device, DeviceType};

    let mut group = c.benchmark_group("GPU_BatchEval");

    let cpu_backend = get_backend_for_device(DeviceType::Cpu).unwrap();

    #[cfg(target_os = "macos")]
    let metal_backend = get_backend_for_device(DeviceType::Metal).ok();
    #[cfg(not(target_os = "macos"))]
    let metal_backend: Option<Box<dyn zp1_prover::gpu::GpuBackend>> = None;

    for log_degree in [8, 10, 12] {
        let degree = 1 << log_degree;
        let coeffs: Vec<u32> = (0..degree).map(|i| i as u32 % ((1 << 31) - 1)).collect();
        let num_points = 1024;
        let points: Vec<u32> = (0..num_points).map(|i| i as u32).collect();

        // CPU benchmark
        group.bench_with_input(
            BenchmarkId::new("CPU", format!("deg=2^{},pts=1024", log_degree)),
            &(&coeffs, &points),
            |b, (c, p)| {
                let mut results = vec![0u32; num_points];
                b.iter(|| {
                    cpu_backend
                        .batch_evaluate(black_box(*c), black_box(*p), &mut results)
                        .unwrap()
                })
            },
        );

        // Metal benchmark (macOS only)
        if let Some(ref backend) = metal_backend {
            group.bench_with_input(
                BenchmarkId::new("Metal", format!("deg=2^{},pts=1024", log_degree)),
                &(&coeffs, &points),
                |b, (c, p)| {
                    let mut results = vec![0u32; num_points];
                    b.iter(|| {
                        backend
                            .batch_evaluate(black_box(*c), black_box(*p), &mut results)
                            .unwrap()
                    })
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_m31_ops,
    bench_qm31_ops,
    bench_parallel_lde,
    bench_merkle_tree,
    bench_fri_fold,
    bench_batch_inverse,
    bench_poly_eval,
    bench_circle_fft,
    bench_gpu_ntt,
    bench_gpu_lde,
    bench_gpu_merkle,
    bench_gpu_batch_eval,
);
criterion_main!(benches);
