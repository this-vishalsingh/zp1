//! zp1-primitives: Field arithmetic and core types for the zk RISC-V prover.
//!
//! This crate provides:
//! - Mersenne31 (M31) base field arithmetic
//! - Quartic extension field (QM31) for security-critical operations
//! - 16-bit limb utilities for 32-bit word decomposition
//! - Circle group and Circle FFT for M31-native polynomial operations
//! - Range-check helpers
//! - Plonky3 interoperability for SIMD-optimized operations

pub mod field;
pub mod extension;
pub mod limbs;
pub mod circle;
pub mod p3_interop;

pub use field::M31;
pub use extension::{CM31, QM31, U_SQUARED};
pub use limbs::{to_limbs, from_limbs};
pub use circle::{CirclePoint, CircleDomain, CircleFFT, Coset, FastCircleFFT};
pub use p3_interop::{to_p3, from_p3, P3M31};
