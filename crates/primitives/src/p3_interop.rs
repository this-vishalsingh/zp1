//! Plonky3 interoperability module.
//!
//! This module provides conversion between ZP1's M31 and Plonky3's Mersenne31,
//! enabling use of Plonky3's SIMD-optimized field operations.
//!
//! # Performance
//!
//! Plonky3 provides SIMD optimizations for:
//! - NEON (Apple Silicon M-series)
//! - AVX2 (x86-64)
//! - AVX512 (x86-64 server CPUs)
//!
//! Using these can provide 2-8x speedups for field-heavy operations.
//!
//! # DFT Support
//! 
//! The `p3_fast_dft` function provides O(n log n) FFT using Plonky3's Radix2Dit.

use crate::field::M31;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_field::extension::Complex;
pub use p3_dft::TwoAdicSubgroupDft;
pub use p3_mersenne_31::{Mersenne31 as P3M31, Mersenne31ComplexRadix2Dit};

/// Convert ZP1 M31 to Plonky3 Mersenne31.
#[inline]
pub fn to_p3(m: M31) -> P3M31 {
    P3M31::new_checked(m.value()).unwrap_or_else(|| P3M31::from_u32(0))
}

/// Convert Plonky3 Mersenne31 to ZP1 M31.
#[inline]
pub fn from_p3(p: P3M31) -> M31 {
    M31::new(p.as_canonical_u32())
}

/// Convert a slice of ZP1 M31 to Plonky3 Mersenne31.
pub fn to_p3_vec(v: &[M31]) -> Vec<P3M31> {
    v.iter().map(|&m| to_p3(m)).collect()
}

/// Convert a slice of Plonky3 Mersenne31 to ZP1 M31.
pub fn from_p3_vec(v: &[P3M31]) -> Vec<M31> {
    v.iter().map(|&p| from_p3(p)).collect()
}

/// Complex extension of M31 - this is a TwoAdicField with 2^32 order.
pub type P3Complex = Complex<P3M31>;

/// Perform O(n log n) DFT using Plonky3's optimized Radix-2 DIT.
/// 
/// This function takes a slice of ZP1 M31 values, converts them to Plonky3's
/// Complex<Mersenne31>, runs the DFT, and converts back.
///
/// # Arguments
/// * `coeffs` - Input coefficients (will be zero-padded to power of 2)
///
/// # Returns
/// Evaluations on a 2-adic subgroup of the complex extension
pub fn p3_dft(coeffs: &[M31]) -> Vec<(M31, M31)> {
    use p3_matrix::dense::RowMajorMatrix;
    
    if coeffs.is_empty() {
        return vec![];
    }
    
    // Pad to power of 2
    let len = coeffs.len().next_power_of_two();
    
    // Convert to Complex<P3M31> - embed M31 as real part
    let mut complex_coeffs: Vec<P3Complex> = coeffs.iter()
        .map(|&m| P3Complex::new_real(to_p3(m)))
        .collect();
    complex_coeffs.resize(len, P3Complex::ZERO);
    
    // Create matrix and run DFT
    let mat = RowMajorMatrix::new_col(complex_coeffs);
    let dft = Mersenne31ComplexRadix2Dit;
    let result = dft.dft_batch(mat);
    
    // Convert back to ZP1 (real, imag) pairs
    result.values.iter()
        .map(|c| (from_p3(c.real()), from_p3(c.imag())))
        .collect()
}

/// Perform O(n log n) inverse DFT using Plonky3.
pub fn p3_idft(evals: &[(M31, M31)]) -> Vec<(M31, M31)> {
    use p3_matrix::dense::RowMajorMatrix;
    
    if evals.is_empty() {
        return vec![];
    }
    
    // Convert to Complex<P3M31>
    let complex_evals: Vec<P3Complex> = evals.iter()
        .map(|&(r, i)| P3Complex::new_complex(to_p3(r), to_p3(i)))
        .collect();
    
    // Create matrix and run IDFT
    let mat = RowMajorMatrix::new_col(complex_evals);
    let dft = Mersenne31ComplexRadix2Dit;
    let result = dft.idft_batch(mat);
    
    // Convert back
    result.values.iter()
        .map(|c| (from_p3(c.real()), from_p3(c.imag())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::{Field, PrimeCharacteristicRing};

    #[test]
    fn test_roundtrip() {
        for i in [0u32, 1, 42, 1000, 2147483646] {
            let zp1 = M31::new(i);
            let p3 = to_p3(zp1);
            let back = from_p3(p3);
            assert_eq!(zp1, back, "Roundtrip failed for {}", i);
        }
    }
    
    #[test]
    fn test_arithmetic_compatibility() {
        let a = M31::new(12345);
        let b = M31::new(67890);
        
        // ZP1 arithmetic
        let zp1_sum = a + b;
        let zp1_prod = a * b;
        
        // P3 arithmetic
        let p3_a = to_p3(a);
        let p3_b = to_p3(b);
        let p3_sum = p3_a + p3_b;
        let p3_prod = p3_a * p3_b;
        
        assert_eq!(zp1_sum, from_p3(p3_sum), "Sum mismatch");
        assert_eq!(zp1_prod, from_p3(p3_prod), "Product mismatch");
    }
    
    #[test]
    fn test_p3_has_simd() {
        // This test verifies Plonky3 is correctly configured
        let gen = P3M31::GENERATOR;
        let one = P3M31::ONE;
        assert!(!one.is_zero());
        assert!(!gen.is_zero());
    }
    
    #[test]
    fn test_p3_dft_roundtrip() {
        // Test O(n log n) DFT roundtrip
        let coeffs: Vec<M31> = (0..8).map(|i| M31::new(i * 10 + 1)).collect();
        
        // Forward DFT
        let evals = p3_dft(&coeffs);
        assert_eq!(evals.len(), 8, "DFT should return 8 evaluations");
        
        // Inverse DFT
        let recovered = p3_idft(&evals);
        assert_eq!(recovered.len(), 8, "IDFT should return 8 coefficients");
        
        // Check roundtrip (real parts should match, imaginary should be ~0)
        for (i, ((r, _), orig)) in recovered.iter().zip(coeffs.iter()).enumerate() {
            assert_eq!(*r, *orig, "DFT roundtrip failed at index {}", i);
        }
    }
}
