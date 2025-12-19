//! zp1-primitives: Field arithmetic and core types for the zk RISC-V prover.
//!
//! This crate provides:
//! - Mersenne31 (M31) base field arithmetic
//! - Quartic extension field (QM31) for security-critical operations
//! - 16-bit limb utilities for 32-bit word decomposition
//! - Circle group and O(n log n) Circle FFT via Plonky3
//! - Range-check helpers
//! - Plonky3 interoperability for SIMD-optimized operations
//!
//! # Performance
//!
//! Circle FFT operations now use Plonky3's optimized O(n log n) implementation
//! with SIMD acceleration (NEON on Apple Silicon, AVX2/512 on x86).

pub mod field;
pub mod extension;
pub mod limbs;
pub mod circle;
pub mod p3_interop;

pub use field::M31;
pub use extension::{CM31, QM31, U_SQUARED};
pub use limbs::{to_limbs, from_limbs};
pub use circle::{
    CirclePoint, CircleDomain, CircleFFT, Coset, FastCircleFFT,
    // Plonky3 re-exports for advanced usage
    P3CircleDomain, P3CircleEvaluations,
    // Polynomial utilities
    evaluate_poly, poly_mul, poly_add, poly_sub, poly_scale, poly_degree,
    bit_reverse, bit_reverse_permutation, sqrt_m31,
    // Circle FRI folding utilities
    compute_y_twiddle_inverses, compute_x_twiddle_inverses, batch_inverse,
    fold_y, fold_x, fold_y_single, fold_x_single,
    get_y_twiddle_inv, get_x_twiddle_inv,
};
pub use p3_interop::{to_p3, from_p3, to_p3_vec, from_p3_vec, P3M31};
