//! Parallel CPU prover using Rayon.
//!
//! Parallelizes:
//! - Polynomial evaluation (LDE)
//! - Merkle tree construction
//! - FRI layer folding
//! - Constraint evaluation

use rayon::prelude::*;
use zp1_primitives::M31;

/// Parallel polynomial evaluation at multiple points.
pub fn parallel_evaluate_poly(coeffs: &[M31], points: &[M31]) -> Vec<M31> {
    points
        .par_iter()
        .map(|&x| evaluate_at_point(coeffs, x))
        .collect()
}

/// Evaluate polynomial at a single point using Horner's method.
fn evaluate_at_point(coeffs: &[M31], x: M31) -> M31 {
    let mut result = M31::ZERO;
    for &c in coeffs.iter().rev() {
        result = result * x + c;
    }
    result
}

/// Parallel LDE: extend trace columns to larger domain.
pub fn parallel_lde(columns: &[Vec<M31>], blowup: usize) -> Vec<Vec<M31>> {
    columns
        .par_iter()
        .map(|col| extend_column(col, blowup))
        .collect()
}

/// Extend a single column by blowup factor.
fn extend_column(column: &[M31], blowup: usize) -> Vec<M31> {
    let n = column.len();
    let extended_len = n * blowup;
    
    // Simple extension: interpolate then evaluate on extended domain
    // In production, use Circle FFT for proper LDE
    let mut extended = vec![M31::ZERO; extended_len];
    
    // For now, copy original values at stride positions
    for (i, &val) in column.iter().enumerate() {
        extended[i * blowup] = val;
    }
    
    // Fill intermediate values using linear interpolation (placeholder)
    for i in 0..n {
        let start_idx = i * blowup;
        let _end_idx = ((i + 1) % n) * blowup;
        let start_val = column[i];
        let end_val = column[(i + 1) % n];
        
        for j in 1..blowup {
            let t = M31::new(j as u32);
            let inv_blowup = M31::new(blowup as u32).inv();
            let idx = start_idx + j;
            // Linear interpolation (placeholder for proper polynomial extension)
            extended[idx] = start_val + (end_val - start_val) * t * inv_blowup;
        }
    }
    
    extended
}

// Domain separation prefixes (must match commitment.rs)
const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// Parallel Merkle tree leaf hashing with domain separation.
pub fn parallel_hash_leaves(values: &[M31]) -> Vec<[u8; 32]> {
    values
        .par_iter()
        .map(|v| {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(&[LEAF_PREFIX]);
            hasher.update(&v.as_u32().to_le_bytes());
            *hasher.finalize().as_bytes()
        })
        .collect()
}

/// Parallel Merkle tree layer computation with domain separation.
pub fn parallel_merkle_layer(children: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = children.len() / 2;
    (0..n)
        .into_par_iter()
        .map(|i| {
            use blake3::Hasher;
            let mut hasher = Hasher::new();
            hasher.update(&[INTERNAL_PREFIX]);
            hasher.update(&children[2 * i]);
            hasher.update(&children[2 * i + 1]);
            *hasher.finalize().as_bytes()
        })
        .collect()
}

/// Build Merkle tree in parallel.
/// Returns (all_layers_flattened, root).
pub fn parallel_merkle_tree(values: &[M31]) -> (Vec<[u8; 32]>, [u8; 32]) {
    if values.is_empty() {
        return (vec![[0u8; 32]], [0u8; 32]);
    }
    
    let n = values.len().next_power_of_two();
    
    // Hash leaves in parallel
    let mut leaves = parallel_hash_leaves(values);
    
    // Pad to power of two
    while leaves.len() < n {
        leaves.push([0u8; 32]);
    }
    
    // Build tree layers
    let mut layers = vec![leaves.clone()];
    let mut current = leaves;
    
    while current.len() > 1 {
        current = parallel_merkle_layer(&current);
        layers.push(current.clone());
    }
    
    let root = if current.is_empty() {
        [0u8; 32]
    } else {
        current[0]
    };
    
    (layers.into_iter().flatten().collect(), root)
}

/// Parallel FRI folding.
pub fn parallel_fri_fold(evals: &[M31], alpha: M31) -> Vec<M31> {
    let half = evals.len() / 2;
    (0..half)
        .into_par_iter()
        .map(|i| {
            let even = evals[i];
            let odd = evals[i + half];
            even + alpha * odd
        })
        .collect()
}

/// Parallel constraint evaluation.
pub fn parallel_evaluate_constraints<F>(
    trace_lde: &[Vec<M31>],
    evaluator: F,
    domain_size: usize,
) -> Vec<M31>
where
    F: Fn(usize, &[M31], &[M31]) -> M31 + Sync,
{
    let blowup = domain_size / trace_lde[0].len().max(1);
    
    (0..domain_size)
        .into_par_iter()
        .map(|i| {
            // Get current row values
            let row: Vec<M31> = trace_lde.iter().map(|col| col[i]).collect();
            
            // Get next row values (with wraparound)
            let next_idx = (i + blowup) % domain_size;
            let next_row: Vec<M31> = trace_lde.iter().map(|col| col[next_idx]).collect();
            
            evaluator(i, &row, &next_row)
        })
        .collect()
}

/// Parallel batch inversion using Montgomery's trick.
pub fn parallel_batch_inverse(values: &[M31]) -> Vec<M31> {
    if values.is_empty() {
        return vec![];
    }
    
    // For large batches, split and process in parallel
    const CHUNK_SIZE: usize = 1024;
    
    if values.len() <= CHUNK_SIZE {
        batch_inverse_sequential(values)
    } else {
        values
            .par_chunks(CHUNK_SIZE)
            .flat_map(|chunk| batch_inverse_sequential(chunk))
            .collect()
    }
}

/// Sequential batch inversion using Montgomery's trick.
fn batch_inverse_sequential(values: &[M31]) -> Vec<M31> {
    let n = values.len();
    if n == 0 {
        return vec![];
    }
    
    // Compute prefix products
    let mut prefix = vec![M31::ONE; n];
    prefix[0] = values[0];
    for i in 1..n {
        prefix[i] = prefix[i - 1] * values[i];
    }
    
    // Compute inverse of product
    let mut inv_prod = prefix[n - 1].inv();
    
    // Compute individual inverses
    let mut result = vec![M31::ZERO; n];
    for i in (1..n).rev() {
        result[i] = inv_prod * prefix[i - 1];
        inv_prod = inv_prod * values[i];
    }
    result[0] = inv_prod;
    
    result
}

/// Configuration for parallel prover.
#[derive(Clone, Debug)]
pub struct ParallelConfig {
    /// Number of threads to use (0 = auto-detect).
    pub num_threads: usize,
    /// Chunk size for parallel operations.
    pub chunk_size: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_threads: 0, // Auto-detect
            chunk_size: 4096,
        }
    }
}

impl ParallelConfig {
    /// Create config with specific thread count.
    pub fn with_threads(num_threads: usize) -> Self {
        Self {
            num_threads,
            ..Default::default()
        }
    }
    
    /// Initialize Rayon thread pool.
    pub fn init_thread_pool(&self) -> Result<(), rayon::ThreadPoolBuildError> {
        if self.num_threads > 0 {
            rayon::ThreadPoolBuilder::new()
                .num_threads(self.num_threads)
                .build_global()
        } else {
            Ok(()) // Use default thread count
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_evaluate_poly() {
        let coeffs = vec![M31::new(1), M31::new(2), M31::new(3)]; // 1 + 2x + 3x^2
        let points = vec![M31::ZERO, M31::ONE, M31::new(2)];
        
        let results = parallel_evaluate_poly(&coeffs, &points);
        
        assert_eq!(results[0].as_u32(), 1); // p(0) = 1
        assert_eq!(results[1].as_u32(), 6); // p(1) = 1 + 2 + 3 = 6
        assert_eq!(results[2].as_u32(), 17); // p(2) = 1 + 4 + 12 = 17
    }

    #[test]
    fn test_parallel_merkle_tree() {
        let values: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let (_, root) = parallel_merkle_tree(&values);
        
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_parallel_fri_fold() {
        let evals: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let alpha = M31::new(3);
        
        let folded = parallel_fri_fold(&evals, alpha);
        
        assert_eq!(folded.len(), 4);
        // folded[0] = evals[0] + alpha * evals[4] = 0 + 3*4 = 12
        assert_eq!(folded[0].as_u32(), 12);
    }

    #[test]
    fn test_batch_inverse() {
        let values = vec![M31::new(2), M31::new(3), M31::new(5), M31::new(7)];
        let inverses = parallel_batch_inverse(&values);
        
        for (v, inv) in values.iter().zip(inverses.iter()) {
            let product = *v * *inv;
            assert_eq!(product.as_u32(), 1);
        }
    }

    #[test]
    fn test_parallel_lde() {
        let columns = vec![
            vec![M31::new(0), M31::new(1), M31::new(2), M31::new(3)],
        ];
        
        let extended = parallel_lde(&columns, 4);
        
        assert_eq!(extended.len(), 1);
        assert_eq!(extended[0].len(), 16);
    }
}
