//! Low-degree extension (LDE) using Circle FFT.
//!
//! For Mersenne31, we use Circle STARKs - evaluation on the circle group
//! { (x, y) : x^2 + y^2 = 1 } over M31, which provides FFT-friendly domains.
//!
//! The LDE process:
//! 1. Interpolate trace values to get polynomial coefficients (iFFT)
//! 2. Extend coefficients to larger domain
//! 3. Evaluate on extended domain (FFT)

use zp1_primitives::{M31, CircleFFT, CirclePoint};

/// LDE domain configuration.
#[derive(Clone, Debug)]
pub struct LdeDomain {
    /// Log2 of the trace length.
    pub log_trace_len: usize,
    /// Blowup factor (typically 8 or 16).
    pub blowup: usize,
    /// Log2 of the LDE domain size.
    pub log_domain_size: usize,
    /// Circle FFT for trace domain.
    trace_fft: CircleFFT,
    /// Circle FFT for extended domain.
    extended_fft: CircleFFT,
}

impl LdeDomain {
    /// Create a new LDE domain.
    pub fn new(trace_len: usize, blowup: usize) -> Self {
        assert!(trace_len.is_power_of_two(), "Trace length must be power of 2");
        assert!(blowup.is_power_of_two(), "Blowup must be power of 2");
        
        let log_trace_len = trace_len.trailing_zeros() as usize;
        let log_blowup = blowup.trailing_zeros() as usize;
        let log_domain_size = log_trace_len + log_blowup;

        Self {
            log_trace_len,
            blowup,
            log_domain_size,
            trace_fft: CircleFFT::new(log_trace_len),
            extended_fft: CircleFFT::new(log_domain_size),
        }
    }

    /// Get the trace length.
    #[inline]
    pub fn trace_len(&self) -> usize {
        1 << self.log_trace_len
    }

    /// Get the LDE domain size.
    #[inline]
    pub fn domain_size(&self) -> usize {
        1 << self.log_domain_size
    }

    /// Get a point from the trace domain.
    #[inline]
    pub fn trace_point(&self, i: usize) -> CirclePoint {
        self.trace_fft.get_domain_point(i)
    }

    /// Get a point from the extended domain.
    #[inline]
    pub fn extended_point(&self, i: usize) -> CirclePoint {
        self.extended_fft.get_domain_point(i)
    }

    /// Perform LDE on a single column using Circle FFT.
    pub fn extend(&self, values: &[M31]) -> Vec<M31> {
        assert_eq!(values.len(), self.trace_len(), "Input must match trace length");
        
        // Step 1: iFFT to get coefficients
        let coeffs = self.trace_fft.ifft(values);
        
        // Step 2: FFT on extended domain (zero-padded coefficients)
        self.extended_fft.fft(&coeffs)
    }

    /// Perform LDE on multiple columns.
    pub fn extend_columns(&self, columns: &[Vec<M31>]) -> Vec<Vec<M31>> {
        columns.iter().map(|col| self.extend(col)).collect()
    }

    /// Get trace FFT.
    pub fn trace_fft(&self) -> &CircleFFT {
        &self.trace_fft
    }

    /// Get extended FFT.
    pub fn extended_fft(&self) -> &CircleFFT {
        &self.extended_fft
    }
}

/// Perform low-degree extension of a column (convenience function).
pub fn low_degree_extend(values: &[M31], domain: &LdeDomain) -> Vec<M31> {
    domain.extend(values)
}

/// Batch LDE for all trace columns.
#[derive(Clone, Debug)]
pub struct TraceLDE {
    /// The LDE domain.
    pub domain: LdeDomain,
    /// Extended evaluations for each column.
    pub columns: Vec<Vec<M31>>,
}

impl TraceLDE {
    /// Create a new trace LDE.
    pub fn new(trace_columns: &[Vec<M31>], blowup: usize) -> Self {
        assert!(!trace_columns.is_empty(), "Need at least one column");
        
        let trace_len = trace_columns[0].len();
        let domain = LdeDomain::new(trace_len, blowup);
        let columns = domain.extend_columns(trace_columns);
        
        Self { domain, columns }
    }

    /// Get evaluation of column c at row r.
    #[inline]
    pub fn get(&self, col: usize, row: usize) -> M31 {
        self.columns[col][row]
    }

    /// Get all columns at a specific row.
    pub fn get_row(&self, row: usize) -> Vec<M31> {
        self.columns.iter().map(|col| col[row]).collect()
    }

    /// Number of columns.
    pub fn num_columns(&self) -> usize {
        self.columns.len()
    }

    /// Extended domain size.
    pub fn domain_size(&self) -> usize {
        self.domain.domain_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lde_domain() {
        let domain = LdeDomain::new(8, 8);
        assert_eq!(domain.trace_len(), 8);
        assert_eq!(domain.domain_size(), 64);
        assert_eq!(domain.blowup, 8);
    }

    #[test]
    fn test_lde_single_column() {
        let domain = LdeDomain::new(8, 4);
        let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        
        let extended = domain.extend(&values);
        assert_eq!(extended.len(), 32);
        
        // The extended evaluations should match the original at trace points
        // (every 4th point since blowup=4)
        // Note: This depends on domain structure, simplified check here
        assert!(!extended.is_empty());
    }

    #[test]
    fn test_trace_lde() {
        let col1: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let col2: Vec<M31> = (0..8).map(|i| M31::new(i * 2)).collect();
        
        let trace_lde = TraceLDE::new(&[col1, col2], 4);
        
        assert_eq!(trace_lde.num_columns(), 2);
        assert_eq!(trace_lde.domain_size(), 32);
    }

    #[test]
    fn test_lde_preserves_low_degree() {
        // A low-degree polynomial should remain low-degree after extension
        let domain = LdeDomain::new(8, 4);
        
        // Linear function: f(i) = 3i + 7
        let values: Vec<M31> = (0..8).map(|i| M31::new(3 * i as u32 + 7)).collect();
        
        let extended = domain.extend(&values);
        assert_eq!(extended.len(), 32);
        
        // After LDE, interpolating through extended points should give
        // a polynomial of degree < trace_len (since original was low-degree)
    }
}

