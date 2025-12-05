//! Low-degree extension (LDE) via NTT/FFT.
//!
//! For Mersenne31, we use a different approach than standard NTT since
//! M31 doesn't have large 2-adic subgroups. Options:
//! 1. Circle STARKs (evaluation on a circle group)
//! 2. Extension field NTT
//! 3. Additive FFT
//!
//! This module provides a placeholder implementation.

use zp1_primitives::M31;

/// LDE domain configuration.
#[derive(Clone, Debug)]
pub struct LdeDomain {
    /// Log2 of the trace length.
    pub log_trace_len: usize,
    /// Blowup factor (typically 8 or 16).
    pub blowup: usize,
    /// Log2 of the LDE domain size.
    pub log_domain_size: usize,
}

impl LdeDomain {
    /// Create a new LDE domain.
    pub fn new(trace_len: usize, blowup: usize) -> Self {
        let log_trace_len = trace_len.trailing_zeros() as usize;
        let log_domain_size = log_trace_len + (blowup.trailing_zeros() as usize);

        Self {
            log_trace_len,
            blowup,
            log_domain_size,
        }
    }

    /// Get the trace length.
    pub fn trace_len(&self) -> usize {
        1 << self.log_trace_len
    }

    /// Get the LDE domain size.
    pub fn domain_size(&self) -> usize {
        1 << self.log_domain_size
    }
}

/// Perform low-degree extension of a column.
///
/// This is a placeholder that uses naive polynomial evaluation.
/// A production implementation would use Circle FFT or extension-field NTT.
pub fn low_degree_extend(values: &[M31], domain: &LdeDomain) -> Vec<M31> {
    let trace_len = domain.trace_len();
    let domain_size = domain.domain_size();

    assert_eq!(values.len(), trace_len, "Input must match trace length");

    // Naive implementation: interpolate polynomial, then evaluate on larger domain.
    // This is O(n^2) and only for testing. Production uses FFT.

    if trace_len <= 16 {
        // Very small case: use Lagrange interpolation + evaluation
        let poly = interpolate_naive(values);
        let mut result = Vec::with_capacity(domain_size);

        for i in 0..domain_size {
            // Evaluate at point i (using index as evaluation point for simplicity)
            let x = M31::new(i as u32);
            result.push(evaluate_poly(&poly, x));
        }

        result
    } else {
        // For larger inputs, just extend with the original values repeated
        // (placeholder for proper FFT implementation)
        let mut result = values.to_vec();
        result.resize(domain_size, M31::ZERO);
        result
    }
}

/// Naive polynomial interpolation (Lagrange).
fn interpolate_naive(values: &[M31]) -> Vec<M31> {
    let n = values.len();
    let mut coeffs = vec![M31::ZERO; n];

    // Compute Lagrange basis polynomials and sum
    for i in 0..n {
        let xi = M31::new(i as u32);
        let yi = values[i];

        // Compute the i-th Lagrange basis polynomial
        let mut basis = vec![M31::ZERO; n];
        basis[0] = M31::ONE;

        let mut denom = M31::ONE;
        for j in 0..n {
            if i == j {
                continue;
            }
            let xj = M31::new(j as u32);
            denom *= xi - xj;

            // Multiply basis by (x - xj)
            for k in (1..n).rev() {
                basis[k] = basis[k - 1] - xj * basis[k];
            }
            basis[0] = -xj * basis[0];
        }

        // Scale by yi / denom
        let scale = yi * denom.inv();
        for k in 0..n {
            coeffs[k] += scale * basis[k];
        }
    }

    coeffs
}

/// Evaluate a polynomial at a point.
fn evaluate_poly(coeffs: &[M31], x: M31) -> M31 {
    let mut result = M31::ZERO;
    let mut power = M31::ONE;

    for &c in coeffs {
        result += c * power;
        power *= x;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpolate_evaluate() {
        let values = vec![M31::new(1), M31::new(4), M31::new(9), M31::new(16)];
        let poly = interpolate_naive(&values);

        // Should interpolate through the original points
        for (i, &v) in values.iter().enumerate() {
            let x = M31::new(i as u32);
            let y = evaluate_poly(&poly, x);
            assert_eq!(y, v, "Mismatch at index {}", i);
        }
    }

    #[test]
    fn test_lde_domain() {
        let domain = LdeDomain::new(8, 8);
        assert_eq!(domain.trace_len(), 8);
        assert_eq!(domain.domain_size(), 64);
    }
}
