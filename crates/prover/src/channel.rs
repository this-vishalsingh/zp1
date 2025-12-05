//! Fiat-Shamir transcript channel for the prover.

use sha2::{Digest, Sha256};
use zp1_primitives::{M31, QM31};

/// Prover channel for Fiat-Shamir transcript.
#[derive(Clone)]
pub struct ProverChannel {
    /// SHA256 state.
    hasher: Sha256,
    /// Transcript bytes for debugging.
    transcript: Vec<u8>,
}

impl ProverChannel {
    /// Create a new prover channel.
    pub fn new(domain_separator: &[u8]) -> Self {
        let mut ch = Self {
            hasher: Sha256::new(),
            transcript: Vec::new(),
        };
        ch.absorb(domain_separator);
        ch
    }

    /// Absorb bytes into the transcript.
    pub fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.transcript.extend_from_slice(data);
    }

    /// Absorb a 32-byte commitment.
    pub fn absorb_commitment(&mut self, commitment: &[u8; 32]) {
        self.absorb(commitment);
    }

    /// Absorb an M31 field element.
    pub fn absorb_felt(&mut self, felt: M31) {
        self.absorb(&felt.as_u32().to_le_bytes());
    }

    /// Squeeze a challenge in M31.
    pub fn squeeze_challenge(&mut self) -> M31 {
        let hash = self.hasher.clone().finalize();
        self.hasher.update(&hash);

        // Take first 4 bytes, reduce mod P
        let bytes: [u8; 4] = hash[0..4].try_into().unwrap();
        let val = u32::from_le_bytes(bytes);
        M31::new(val % M31::P)
    }

    /// Squeeze a challenge in QM31 (extension field).
    pub fn squeeze_extension_challenge(&mut self) -> QM31 {
        let c0 = self.squeeze_challenge();
        let c1 = self.squeeze_challenge();
        let c2 = self.squeeze_challenge();
        let c3 = self.squeeze_challenge();
        QM31::new(c0, c1, c2, c3)
    }

    /// Alias for squeeze_extension_challenge.
    pub fn squeeze_qm31(&mut self) -> QM31 {
        self.squeeze_extension_challenge()
    }

    /// Squeeze n query indices in range [0, domain_size).
    pub fn squeeze_query_indices(&mut self, n: usize, domain_size: usize) -> Vec<usize> {
        let mut indices = Vec::with_capacity(n);
        while indices.len() < n {
            let hash = self.hasher.clone().finalize();
            self.hasher.update(&hash);

            // Extract multiple indices from each hash
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

    /// Get the current transcript length.
    pub fn transcript_len(&self) -> usize {
        self.transcript.len()
    }
}

impl Default for ProverChannel {
    fn default() -> Self {
        Self::new(b"zp1-default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_deterministic() {
        let mut ch1 = ProverChannel::new(b"test");
        let mut ch2 = ProverChannel::new(b"test");

        ch1.absorb(b"test data");
        ch2.absorb(b"test data");

        let c1 = ch1.squeeze_challenge();
        let c2 = ch2.squeeze_challenge();

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_query_indices() {
        let mut ch = ProverChannel::new(b"test");
        ch.absorb(b"seed");

        let indices = ch.squeeze_query_indices(10, 1024);
        assert_eq!(indices.len(), 10);
        for &idx in &indices {
            assert!(idx < 1024);
        }
    }
}
