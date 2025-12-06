//! Verifier channel (mirrors prover channel for Fiat-Shamir).

use sha2::{Digest, Sha256};
use zp1_primitives::{M31, QM31};

/// Verifier channel for Fiat-Shamir transcript replay.
pub struct VerifierChannel {
    hasher: Sha256,
}

impl VerifierChannel {
    /// Create a new verifier channel with domain separator.
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain_separator);
        Self { hasher }
    }

    /// Absorb bytes into the transcript.
    pub fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Absorb a commitment.
    pub fn absorb_commitment(&mut self, commitment: &[u8; 32]) {
        self.absorb(commitment);
    }

    /// Absorb a field element.
    pub fn absorb_felt(&mut self, felt: M31) {
        self.absorb(&felt.as_u32().to_le_bytes());
    }

    /// Squeeze a challenge.
    pub fn squeeze_challenge(&mut self) -> M31 {
        let hash = self.hasher.clone().finalize();
        self.hasher.update(&hash);

        let bytes: [u8; 4] = hash[0..4].try_into().unwrap();
        let val = u32::from_le_bytes(bytes);
        M31::new(val % M31::P)
    }

    /// Squeeze an extension field challenge.
    pub fn squeeze_extension_challenge(&mut self) -> QM31 {
        let c0 = self.squeeze_challenge();
        let c1 = self.squeeze_challenge();
        let c2 = self.squeeze_challenge();
        let c3 = self.squeeze_challenge();
        QM31::new(c0, c1, c2, c3)
    }

    /// Squeeze query indices.
    pub fn squeeze_query_indices(&mut self, n: usize, domain_size: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(n);
        while indices.len() < n {
            let hash = self.hasher.clone().finalize();
            self.hasher.update(&hash);

            for chunk in hash.chunks(4) {
                if indices.len() >= n {
                    break;
                }
                let bytes: [u8; 4] = chunk.try_into().unwrap();
                let val = u32::from_le_bytes(bytes) as usize;
                indices.push(val % domain_size);
            }
        }
        indices.truncate(n);
        indices
    }
}

impl Default for VerifierChannel {
    fn default() -> Self {
        Self::new(b"zp1-stark-v1")
    }
}
