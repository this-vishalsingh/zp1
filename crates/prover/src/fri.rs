//! FRI (Fast Reed-Solomon Interactive Oracle Proof) protocol.
//!
//! Implements the DEEP-FRI variant for proximity testing.

use zp1_primitives::M31;
use crate::channel::ProverChannel;
use crate::commitment::MerkleTree;

/// FRI configuration parameters.
#[derive(Clone, Debug)]
pub struct FriConfig {
    /// Log2 of the initial domain size.
    pub log_domain_size: usize,
    /// Folding factor per round (typically 2 or 4).
    pub folding_factor: usize,
    /// Number of FRI query rounds.
    pub num_queries: usize,
    /// Final polynomial degree bound.
    pub final_degree: usize,
}

impl FriConfig {
    /// Create a default FRI configuration.
    pub fn new(log_domain_size: usize) -> Self {
        Self {
            log_domain_size,
            folding_factor: 2,
            num_queries: 30,
            final_degree: 8,
        }
    }

    /// Calculate the number of FRI layers.
    pub fn num_layers(&self) -> usize {
        let log_fold = (self.folding_factor as f64).log2() as usize;
        let log_final = (self.final_degree as f64).log2().ceil() as usize;
        (self.log_domain_size - log_final) / log_fold
    }
}

/// A FRI layer commitment.
#[derive(Clone)]
pub struct FriLayer {
    /// Merkle commitment to folded polynomial evaluations.
    pub commitment: [u8; 32],
    /// The folded evaluations (for proving).
    pub evaluations: Vec<M31>,
}

/// FRI proof structure.
#[derive(Clone)]
pub struct FriProof {
    /// Layer commitments.
    pub layer_commitments: Vec<[u8; 32]>,
    /// Query responses for each layer.
    pub query_proofs: Vec<FriQueryProof>,
    /// Final polynomial coefficients.
    pub final_poly: Vec<M31>,
}

/// Query proof for a single FRI query.
#[derive(Clone)]
pub struct FriQueryProof {
    /// Query index.
    pub index: usize,
    /// Values and Merkle proofs for each layer.
    pub layer_proofs: Vec<FriLayerQueryProof>,
}

/// Query proof for a single FRI layer.
#[derive(Clone)]
pub struct FriLayerQueryProof {
    /// Sibling value for folding.
    pub sibling_value: M31,
    /// Merkle proof for the queried value.
    pub merkle_proof: Vec<[u8; 32]>,
}

/// FRI prover.
pub struct FriProver {
    config: FriConfig,
}

impl FriProver {
    /// Create a new FRI prover.
    pub fn new(config: FriConfig) -> Self {
        Self { config }
    }

    /// Commit to a polynomial (via its evaluations) and generate FRI layers.
    pub fn commit(
        &self,
        evaluations: Vec<M31>,
        channel: &mut ProverChannel,
    ) -> (Vec<FriLayer>, FriProof) {
        let mut layers = Vec::new();
        let mut current = evaluations;

        // Generate FRI layers
        for _layer_idx in 0..self.config.num_layers() {
            // Commit to current layer
            let tree = MerkleTree::new(&current);
            let commitment = tree.root();
            channel.absorb_commitment(&commitment);

            layers.push(FriLayer {
                commitment,
                evaluations: current.clone(),
            });

            // Get folding challenge
            let alpha = channel.squeeze_challenge();

            // Fold the polynomial
            current = self.fold(&current, alpha);
        }

        // Final polynomial (small enough to send directly)
        let final_poly = current.clone();

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

    /// Fold a polynomial by the folding factor using challenge alpha.
    fn fold(&self, evals: &[M31], alpha: M31) -> Vec<M31> {
        let half = evals.len() / 2;
        let mut folded = Vec::with_capacity(half);

        // For factor-2 folding: f'(x^2) = f_even(x^2) + alpha * f_odd(x^2)
        // where f(x) = f_even(x^2) + x * f_odd(x^2)
        for i in 0..half {
            let even = evals[i];
            let odd = evals[i + half];
            folded.push(even + alpha * odd);
        }

        folded
    }

    /// Generate query proofs for the given indices.
    fn generate_query_proofs(
        &self,
        layers: &[FriLayer],
        indices: &[usize],
    ) -> Vec<FriQueryProof> {
        indices
            .iter()
            .map(|&idx| {
                let mut layer_proofs = Vec::new();
                let mut current_idx = idx;

                for layer in layers {
                    let n = layer.evaluations.len();
                    current_idx %= n;
                    let sibling_idx = (current_idx + n / 2) % n;

                    layer_proofs.push(FriLayerQueryProof {
                        sibling_value: layer.evaluations[sibling_idx],
                        merkle_proof: Vec::new(), // Simplified; real impl would include Merkle path
                    });

                    current_idx /= 2;
                }

                FriQueryProof {
                    index: idx,
                    layer_proofs,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_config() {
        let config = FriConfig::new(10);
        assert!(config.num_layers() > 0);
    }

    #[test]
    fn test_fri_fold() {
        let prover = FriProver::new(FriConfig::new(4));
        let evals: Vec<M31> = (0..16).map(|i| M31::new(i)).collect();
        let alpha = M31::new(3);

        let folded = prover.fold(&evals, alpha);
        assert_eq!(folded.len(), 8);
    }

    #[test]
    fn test_fri_commit() {
        let config = FriConfig::new(4);
        let prover = FriProver::new(config);
        let evals: Vec<M31> = (0..16).map(|i| M31::new(i)).collect();

        let mut channel = ProverChannel::new();
        let (layers, proof) = prover.commit(evals, &mut channel);

        assert!(!layers.is_empty());
        assert!(!proof.final_poly.is_empty());
    }
}
