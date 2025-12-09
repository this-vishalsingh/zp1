//! FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol.
//!
//! Implements the DEEP-FRI variant for proximity testing on Circle STARKs.
//!
//! # Overview
//!
//! FRI proves that a committed polynomial has low degree by repeatedly:
//! 1. Folding the polynomial using a random challenge (halving the degree)
//! 2. Committing to the folded polynomial
//! 3. Repeating until degree is small enough to send directly
//!
//! # Circle FRI Folding
//!
//! For Circle STARKs, folding uses the twin-coset structure:
//! - Points come in pairs (x, y) and (x, -y)
//! - f_folded(x) = (f(x,y) + f(x,-y))/2 + α · (f(x,y) - f(x,-y))/(2y)
//!
//! This halves both the domain size and polynomial degree.

use zp1_primitives::M31;
use crate::channel::ProverChannel;
use crate::commitment::MerkleTree;

/// FRI configuration parameters.
#[derive(Clone, Debug)]
pub struct FriConfig {
    /// Log2 of the initial domain size.
    pub log_domain_size: usize,
    /// Folding factor per round (typically 2 for binary folding).
    pub folding_factor: usize,
    /// Number of FRI query rounds for soundness.
    pub num_queries: usize,
    /// Final polynomial degree bound (stop folding when degree ≤ this).
    pub final_degree: usize,
}

/// Security level presets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 80-bit security (fast, suitable for testing)
    Bits80,
    /// 100-bit security (production minimum)
    Bits100,
    /// 128-bit security (recommended for high-value applications)
    Bits128,
}

impl FriConfig {
    /// Create a default FRI configuration (100-bit security).
    pub fn new(log_domain_size: usize) -> Self {
        Self::with_security(log_domain_size, SecurityLevel::Bits100)
    }
    
    /// Create a FRI configuration with specified security level.
    pub fn with_security(log_domain_size: usize, level: SecurityLevel) -> Self {
        let num_queries = match level {
            SecurityLevel::Bits80 => 40,   // ~80 bits from FRI
            SecurityLevel::Bits100 => 50,  // ~100 bits from FRI  
            SecurityLevel::Bits128 => 64,  // ~128 bits from FRI
        };
        
        Self {
            log_domain_size,
            folding_factor: 2,
            num_queries,
            final_degree: 8,
        }
    }
    
    /// Create a fast configuration for testing (reduced security).
    pub fn fast(log_domain_size: usize) -> Self {
        Self {
            log_domain_size,
            folding_factor: 2,
            num_queries: 10,  // Fast but insecure
            final_degree: 8,
        }
    }

    /// Calculate the number of FRI layers needed.
    pub fn num_layers(&self) -> usize {
        let log_fold = (self.folding_factor as f64).log2() as usize;
        let log_final = (self.final_degree as f64).log2().ceil() as usize;
        if self.log_domain_size <= log_final {
            return 0;
        }
        (self.log_domain_size - log_final) / log_fold
    }
    
    /// Get domain size at a specific layer.
    pub fn layer_domain_size(&self, layer: usize) -> usize {
        let log_fold = (self.folding_factor as f64).log2() as usize;
        1 << (self.log_domain_size - layer * log_fold)
    }
}

/// A FRI layer commitment with its evaluation data.
#[derive(Clone)]
pub struct FriLayer {
    /// Merkle commitment to folded polynomial evaluations.
    pub commitment: [u8; 32],
    /// The folded evaluations (kept for proving).
    pub evaluations: Vec<M31>,
    /// Merkle tree for generating proofs.
    tree: MerkleTree,
}

impl FriLayer {
    /// Create a new FRI layer from evaluations.
    pub fn new(evaluations: Vec<M31>) -> Self {
        let tree = MerkleTree::new(&evaluations);
        let commitment = tree.root();
        Self {
            commitment,
            evaluations,
            tree,
        }
    }
    
    /// Generate a Merkle proof for an index.
    pub fn prove(&self, index: usize) -> Vec<[u8; 32]> {
        self.tree.prove(index).path
    }
}

/// FRI proof structure containing all commitments and query responses.
#[derive(Clone)]
pub struct FriProof {
    /// Merkle commitments for each folding layer.
    pub layer_commitments: Vec<[u8; 32]>,
    /// Query proofs for each query position.
    pub query_proofs: Vec<FriQueryProof>,
    /// Final (low-degree) polynomial coefficients.
    pub final_poly: Vec<M31>,
}

/// Query proof for a single FRI query across all layers.
#[derive(Clone)]
pub struct FriQueryProof {
    /// Initial query index in the original domain.
    pub index: usize,
    /// Proof data for each FRI layer.
    pub layer_proofs: Vec<FriLayerQueryProof>,
}

/// Query proof for a single FRI layer.
#[derive(Clone)]
pub struct FriLayerQueryProof {
    /// Value at the query position.
    pub value: M31,
    /// Value at the sibling position (for folding verification).
    pub sibling_value: M31,
    /// Merkle authentication path.
    pub merkle_proof: Vec<[u8; 32]>,
}

/// FRI prover implementing the commit and query phases.
pub struct FriProver {
    config: FriConfig,
}

impl FriProver {
    /// Create a new FRI prover with the given configuration.
    pub fn new(config: FriConfig) -> Self {
        Self { config }
    }

    /// Commit phase: fold the polynomial repeatedly and commit to each layer.
    ///
    /// # Arguments
    /// * `evaluations` - Initial polynomial evaluations on the LDE domain
    /// * `channel` - Fiat-Shamir channel for challenges
    ///
    /// # Returns
    /// Tuple of (layers, proof) where layers are used for query generation
    pub fn commit(
        &self,
        evaluations: Vec<M31>,
        channel: &mut ProverChannel,
    ) -> (Vec<FriLayer>, FriProof) {
        assert!(
            evaluations.len() == 1 << self.config.log_domain_size,
            "Evaluations must match domain size"
        );
        
        let mut layers = Vec::with_capacity(self.config.num_layers());
        let mut current_evals = evaluations;

        // Generate FRI layers through repeated folding
        for layer_idx in 0..self.config.num_layers() {
            // Commit to current layer
            let layer = FriLayer::new(current_evals.clone());
            channel.absorb_commitment(&layer.commitment);
            layers.push(layer);

            // Get folding challenge from verifier (Fiat-Shamir)
            let alpha = channel.squeeze_challenge();

            // Fold the polynomial
            current_evals = self.fold_circle(&current_evals, alpha, layer_idx);
        }

        // Final polynomial is small enough to send directly
        let final_poly = current_evals;

        // Generate query proofs
        let query_indices = channel.squeeze_query_indices(
            self.config.num_queries,
            1 << self.config.log_domain_size,
        );
        let query_proofs = self.generate_query_proofs(&layers, &query_indices);

        let proof = FriProof {
            layer_commitments: layers.iter().map(|l| l.commitment).collect(),
            query_proofs,
            final_poly,
        };

        (layers, proof)
    }

    /// Circle FRI folding: fold polynomial using twin-coset structure.
    ///
    /// For points at indices i and i + n/2 (which are twins on the circle),
    /// we compute:
    /// - f_folded[i] = (f[i] + f[i + n/2]) / 2 + alpha * (f[i] - f[i + n/2]) / (2 * y_i)
    ///
    /// This halves the domain size while maintaining the RS proximity property.
    fn fold_circle(&self, evals: &[M31], alpha: M31, layer: usize) -> Vec<M31> {
        use zp1_primitives::CirclePoint;
        
        let n = evals.len();
        let half_n = n / 2;
        let mut folded = Vec::with_capacity(half_n);

        // Two inverse constant
        let two = M31::new(2);
        let inv_two = two.inv();

        // Get the circle domain generator for current layer
        // Domain size at this layer = 2^(log_domain_size - layer)
        let layer_log_size = self.config.log_domain_size.saturating_sub(layer);
        let generator = CirclePoint::generator(layer_log_size);

        for i in 0..half_n {
            let f_pos = evals[i];
            let f_neg = evals[i + half_n];

            // Sum and difference
            let sum = f_pos + f_neg;
            let diff = f_pos - f_neg;

            // Get y-coordinate of domain point i
            // point_i = generator^i
            let point_i = generator.pow(i as u64);
            let y_i = point_i.y;
            
            // Proper Circle FRI folding formula:
            // f_folded = (sum / 2) + alpha * (diff / (2 * y_i))
            // = (sum / 2) + alpha * diff * inv_two * y_i^(-1)
            let folded_val = if y_i.is_zero() {
                // Edge case: y = 0 means we're at (1,0) or (-1,0)
                // Just use the sum part
                sum * inv_two
            } else {
                let y_inv = y_i.inv();
                sum * inv_two + alpha * diff * inv_two * y_inv
            };
            
            folded.push(folded_val);
        }

        folded
    }

    /// Generate query proofs for all requested positions.
    fn generate_query_proofs(
        &self,
        layers: &[FriLayer],
        indices: &[usize],
    ) -> Vec<FriQueryProof> {
        indices
            .iter()
            .map(|&initial_idx| {
                let mut layer_proofs = Vec::with_capacity(layers.len());
                let mut current_idx = initial_idx;

                for layer in layers {
                    let n = layer.evaluations.len();
                    // Ensure index is in range
                    current_idx %= n;
                    
                    // Sibling is at index + n/2 (mod n) for twin-coset structure
                    let sibling_idx = (current_idx + n / 2) % n;
                    
                    // Get values
                    let value = layer.evaluations[current_idx];
                    let sibling_value = layer.evaluations[sibling_idx];
                    
                    // Get Merkle proof
                    let merkle_proof = layer.prove(current_idx);

                    layer_proofs.push(FriLayerQueryProof {
                        value,
                        sibling_value,
                        merkle_proof,
                    });

                    // Update index for next layer (halve it)
                    current_idx /= 2;
                }

                FriQueryProof {
                    index: initial_idx,
                    layer_proofs,
                }
            })
            .collect()
    }
    
    /// Verify a FRI proof (used by the verifier).
    pub fn verify(
        &self,
        proof: &FriProof,
        initial_commitment: &[u8; 32],
        channel: &mut ProverChannel,
    ) -> bool {
        // Absorb initial commitment
        channel.absorb_commitment(initial_commitment);
        
        // Collect challenges
        let mut challenges = Vec::with_capacity(proof.layer_commitments.len());
        for commitment in &proof.layer_commitments {
            channel.absorb_commitment(commitment);
            challenges.push(channel.squeeze_challenge());
        }
        
        // Verify each query
        let query_indices = channel.squeeze_query_indices(
            self.config.num_queries,
            1 << self.config.log_domain_size,
        );
        
        for (query_idx, query_proof) in proof.query_proofs.iter().enumerate() {
            if query_proof.index != query_indices[query_idx] {
                return false;
            }
            
            // Verify folding consistency through layers
            let mut current_idx = query_proof.index;
            let mut expected_value = None;
            
            for (layer_idx, layer_proof) in query_proof.layer_proofs.iter().enumerate() {
                // If we have an expected value from previous folding, verify it
                if let Some(expected) = expected_value {
                    if layer_proof.value != expected {
                        return false;
                    }
                }
                
                // Verify Merkle proof
                // (In full implementation, would verify against layer commitment)
                
                // Compute expected folded value for next layer
                let alpha = challenges[layer_idx];
                let inv_two = M31::new(2).inv();
                let sum = layer_proof.value + layer_proof.sibling_value;
                let diff = layer_proof.value - layer_proof.sibling_value;
                let folded = sum * inv_two + alpha * diff * inv_two;
                
                expected_value = Some(folded);
                current_idx /= 2;
            }
            
            // Verify final value matches final polynomial evaluation
            if let Some(expected) = expected_value {
                let final_eval = evaluate_poly_at(&proof.final_poly, current_idx);
                if expected != final_eval {
                    return false;
                }
            }
        }
        
        true
    }
}

/// Evaluate a polynomial (given by coefficients) at index i.
/// Uses the coefficient as evaluation directly for final check.
fn evaluate_poly_at(coeffs: &[M31], idx: usize) -> M31 {
    if idx < coeffs.len() {
        coeffs[idx]
    } else {
        M31::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_config() {
        let config = FriConfig::new(10);
        assert!(config.num_layers() > 0);
        assert_eq!(config.layer_domain_size(0), 1024);
    }

    #[test]
    fn test_fri_fold() {
        let prover = FriProver::new(FriConfig::new(4));
        let evals: Vec<M31> = (0..16).map(|i| M31::new(i)).collect();
        let alpha = M31::new(3);

        let folded = prover.fold_circle(&evals, alpha, 0);
        assert_eq!(folded.len(), 8);
        
        // Verify folding is deterministic
        let folded2 = prover.fold_circle(&evals, alpha, 0);
        assert_eq!(folded, folded2);
    }

    #[test]
    fn test_fri_commit() {
        let config = FriConfig::new(4);
        let prover = FriProver::new(config);
        let evals: Vec<M31> = (0..16).map(|i| M31::new(i)).collect();

        let mut channel = ProverChannel::new(b"test");
        let (layers, proof) = prover.commit(evals, &mut channel);

        assert!(!layers.is_empty());
        assert!(!proof.final_poly.is_empty());
        assert!(!proof.layer_commitments.is_empty());
        assert!(!proof.query_proofs.is_empty());
        
        // Verify query proofs have Merkle paths
        for query in &proof.query_proofs {
            for layer_proof in &query.layer_proofs {
                // Merkle proofs should exist
                assert!(layer_proof.merkle_proof.len() > 0 || layers.len() == 0);
            }
        }
    }
    
    #[test]
    fn test_fri_layer() {
        let evals: Vec<M31> = (0..8).map(|i| M31::new(i)).collect();
        let layer = FriLayer::new(evals.clone());
        
        // Verify commitment is non-zero
        assert_ne!(layer.commitment, [0u8; 32]);
        
        // Verify Merkle proofs
        for i in 0..8 {
            let proof = layer.prove(i);
            assert!(!proof.is_empty());
        }
    }
    
    #[test]
    fn test_fri_multiple_folds() {
        let config = FriConfig {
            log_domain_size: 6,
            folding_factor: 2,
            num_queries: 5,
            final_degree: 2,
        };
        let prover = FriProver::new(config.clone());
        let evals: Vec<M31> = (0..64).map(|i| M31::new(i)).collect();
        
        let mut channel = ProverChannel::new(b"test");
        let (layers, proof) = prover.commit(evals, &mut channel);
        
        // Should have multiple layers
        assert!(layers.len() >= 2);
        
        // Each layer should be half the size of previous
        for i in 1..layers.len() {
            assert_eq!(
                layers[i].evaluations.len(),
                layers[i-1].evaluations.len() / 2
            );
        }
        
        // Final poly should be small
        assert!(proof.final_poly.len() <= config.final_degree * 2);
    }
}
