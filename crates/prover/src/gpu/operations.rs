//! GPU-accelerated cryptographic operations.

use crate::gpu::{GpuBackend, GpuError};

/// GPU-accelerated Number Theoretic Transform operations.
pub trait GpuNtt {
    /// Perform forward NTT in-place.
    fn ntt_inplace(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError>;
    
    /// Perform inverse NTT in-place.
    fn intt_inplace(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError>;
    
    /// Perform forward NTT, returning new array.
    fn ntt(&self, values: &[u32], log_n: usize) -> Result<Vec<u32>, GpuError> {
        let mut result = values.to_vec();
        self.ntt_inplace(&mut result, log_n)?;
        Ok(result)
    }
    
    /// Perform inverse NTT, returning new array.
    fn intt(&self, values: &[u32], log_n: usize) -> Result<Vec<u32>, GpuError> {
        let mut result = values.to_vec();
        self.intt_inplace(&mut result, log_n)?;
        Ok(result)
    }
    
    /// Batch NTT on multiple polynomials.
    fn batch_ntt(&self, polys: &mut [Vec<u32>], log_n: usize) -> Result<(), GpuError> {
        for poly in polys.iter_mut() {
            self.ntt_inplace(poly, log_n)?;
        }
        Ok(())
    }
}

/// GPU-accelerated polynomial operations.
pub trait GpuPolynomial {
    /// Multiply two polynomials using NTT.
    fn poly_mul(&self, a: &[u32], b: &[u32]) -> Result<Vec<u32>, GpuError>;
    
    /// Add two polynomials.
    fn poly_add(&self, a: &[u32], b: &[u32]) -> Result<Vec<u32>, GpuError>;
    
    /// Evaluate polynomial at a single point.
    fn poly_eval(&self, coeffs: &[u32], point: u32) -> Result<u32, GpuError>;
    
    /// Evaluate polynomial at multiple points.
    fn poly_eval_batch(
        &self,
        coeffs: &[u32],
        points: &[u32],
    ) -> Result<Vec<u32>, GpuError>;
    
    /// Low Degree Extension.
    fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError>;
    
    /// Interpolate polynomial from evaluations.
    fn interpolate(&self, evaluations: &[u32]) -> Result<Vec<u32>, GpuError>;
}

/// GPU-accelerated Merkle tree operations.
pub trait GpuMerkle {
    /// Compute Merkle root from leaves.
    fn merkle_root(&self, leaves: &[[u8; 32]]) -> Result<[u8; 32], GpuError>;
    
    /// Build full Merkle tree from leaves.
    fn merkle_tree(&self, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError>;
    
    /// Compute Merkle path for a leaf.
    fn merkle_path(&self, tree: &[[u8; 32]], leaf_index: usize) -> Result<Vec<[u8; 32]>, GpuError>;
    
    /// Verify Merkle path.
    fn verify_merkle_path(
        &self,
        root: &[u8; 32],
        leaf: &[u8; 32],
        path: &[[u8; 32]],
        leaf_index: usize,
    ) -> Result<bool, GpuError>;
}

// Implement traits for any GpuBackend

impl<T: GpuBackend + ?Sized> GpuNtt for T {
    fn ntt_inplace(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
        self.ntt_m31(values, log_n)
    }
    
    fn intt_inplace(&self, values: &mut [u32], log_n: usize) -> Result<(), GpuError> {
        self.intt_m31(values, log_n)
    }
}

impl<T: GpuBackend + ?Sized> GpuPolynomial for T {
    fn poly_mul(&self, a: &[u32], b: &[u32]) -> Result<Vec<u32>, GpuError> {
        use zp1_primitives::field::M31;
        
        let n = (a.len() + b.len() - 1).next_power_of_two();
        let log_n = n.trailing_zeros() as usize;
        
        let mut a_ext = vec![0u32; n];
        let mut b_ext = vec![0u32; n];
        a_ext[..a.len()].copy_from_slice(a);
        b_ext[..b.len()].copy_from_slice(b);
        
        // Transform to NTT domain
        self.ntt_m31(&mut a_ext, log_n)?;
        self.ntt_m31(&mut b_ext, log_n)?;
        
        // Pointwise multiply
        for i in 0..n {
            let av = M31::new(a_ext[i]);
            let bv = M31::new(b_ext[i]);
            a_ext[i] = (av * bv).value();
        }
        
        // Transform back
        self.intt_m31(&mut a_ext, log_n)?;
        
        Ok(a_ext)
    }
    
    fn poly_add(&self, a: &[u32], b: &[u32]) -> Result<Vec<u32>, GpuError> {
        use zp1_primitives::field::M31;
        
        let n = a.len().max(b.len());
        let mut result = vec![0u32; n];
        
        for i in 0..n {
            let av = if i < a.len() { M31::new(a[i]) } else { M31::ZERO };
            let bv = if i < b.len() { M31::new(b[i]) } else { M31::ZERO };
            result[i] = (av + bv).value();
        }
        
        Ok(result)
    }
    
    fn poly_eval(&self, coeffs: &[u32], point: u32) -> Result<u32, GpuError> {
        let mut results = vec![0u32; 1];
        self.batch_evaluate(coeffs, &[point], &mut results)?;
        Ok(results[0])
    }
    
    fn poly_eval_batch(
        &self,
        coeffs: &[u32],
        points: &[u32],
    ) -> Result<Vec<u32>, GpuError> {
        let mut results = vec![0u32; points.len()];
        self.batch_evaluate(coeffs, points, &mut results)?;
        Ok(results)
    }
    
    fn lde(&self, coeffs: &[u32], blowup_factor: usize) -> Result<Vec<u32>, GpuError> {
        GpuBackend::lde(self, coeffs, blowup_factor)
    }
    
    fn interpolate(&self, evaluations: &[u32]) -> Result<Vec<u32>, GpuError> {
        // For now, use the INTT as interpolation
        let log_n = evaluations.len().trailing_zeros() as usize;
        let mut result = evaluations.to_vec();
        self.intt_m31(&mut result, log_n)?;
        Ok(result)
    }
}

impl<T: GpuBackend + ?Sized> GpuMerkle for T {
    fn merkle_root(&self, leaves: &[[u8; 32]]) -> Result<[u8; 32], GpuError> {
        let tree = self.merkle_tree(leaves)?;
        if tree.is_empty() {
            return Err(GpuError::InvalidBufferSize { expected: 1, actual: 0 });
        }
        Ok(tree[0])
    }
    
    fn merkle_tree(&self, leaves: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, GpuError> {
        GpuBackend::merkle_tree(self, leaves)
    }
    
    fn merkle_path(&self, tree: &[[u8; 32]], leaf_index: usize) -> Result<Vec<[u8; 32]>, GpuError> {
        let n = (tree.len() + 1) / 2; // Number of leaves
        if leaf_index >= n {
            return Err(GpuError::InvalidBufferSize {
                expected: n,
                actual: leaf_index,
            });
        }
        
        let mut path = Vec::new();
        let mut idx = tree.len() - n + leaf_index;
        
        while idx > 0 {
            let sibling = if idx % 2 == 0 { idx - 1 } else { idx + 1 };
            if sibling < tree.len() {
                path.push(tree[sibling]);
            }
            idx = (idx - 1) / 2;
        }
        
        Ok(path)
    }
    
    fn verify_merkle_path(
        &self,
        root: &[u8; 32],
        leaf: &[u8; 32],
        path: &[[u8; 32]],
        leaf_index: usize,
    ) -> Result<bool, GpuError> {
        use sha2::{Sha256, Digest};
        
        let mut current = *leaf;
        let mut idx = leaf_index;
        
        for sibling in path {
            let mut hasher = Sha256::new();
            if idx % 2 == 0 {
                hasher.update(current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(current);
            }
            current.copy_from_slice(&hasher.finalize());
            idx /= 2;
        }
        
        Ok(current == *root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gpu::backend::CpuBackend;
    
    #[test]
    fn test_poly_add() {
        let backend = CpuBackend::new();
        
        let a = vec![1, 2, 3];
        let b = vec![4, 5];
        
        let result = backend.poly_add(&a, &b).unwrap();
        assert_eq!(result, vec![5, 7, 3]);
    }
    
    #[test]
    fn test_poly_eval() {
        let backend = CpuBackend::new();
        
        // Polynomial: 1 + 2x
        let coeffs = vec![1, 2];
        let result = GpuPolynomial::poly_eval(&backend, &coeffs, 5).unwrap();
        assert_eq!(result, 11); // 1 + 2*5 = 11
    }
    
    #[test]
    fn test_merkle_operations() {
        let backend = CpuBackend::new();
        
        // Create some leaves
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| {
                let mut leaf = [0u8; 32];
                leaf[0] = i as u8;
                leaf
            })
            .collect();
        
        let tree = GpuBackend::merkle_tree(&backend, &leaves).unwrap();
        assert!(!tree.is_empty());
        
        let root = GpuMerkle::merkle_root(&backend, &leaves).unwrap();
        assert_eq!(root, tree[0]);
    }
}
