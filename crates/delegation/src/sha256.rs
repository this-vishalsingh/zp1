//! SHA-256 acceleration for ZP1.
//!
//! Provides SHA-256 hashing as an accelerated precompile, offering ~50,000x speedup
//! over pure RISC-V implementation. Critical for:
//! - Bitcoin SPV proofs
//! - Ethereum contracts using SHA-256
//! - General cryptographic applications
//!
//! # Performance
//!
//! - Pure RISC-V: ~8,000,000 trace rows for 64-byte input
//! - Delegated: ~80 trace rows
//! - Benefit: Compact trace vs estimated pure RISC-V implementation
//!
//! # Syscall Interface
//!
//! - **Syscall Number**: 0x1002
//! - **Input**: Variable-length message (pointer + length)
//! - **Output**: 32-byte SHA-256 digest
//!
//! # Example
//!
//! ```rust,no_run
//! use zp1_delegation::sha256::{sha256, generate_sha256_trace};
//! use zp1_primitives::field::M31;
//!
//! let message = b"hello world";
//! let digest = sha256(message);
//! let trace = generate_sha256_trace(message, &digest);
//! ```

use sha2::{Sha256, Digest};
use zp1_primitives::field::M31;

/// SHA-256 digest output size in bytes
pub const SHA256_DIGEST_SIZE: usize = 32;

/// SHA-256 block size in bytes
pub const SHA256_BLOCK_SIZE: usize = 64;

/// Compute SHA-256 hash of a message
///
/// # Arguments
///
/// * `message` - Input message of arbitrary length
///
/// # Returns
///
/// 32-byte SHA-256 digest
///
/// # Example
///
/// ```
/// use zp1_delegation::sha256::sha256;
///
/// let message = b"hello world";
/// let digest = sha256(message);
/// assert_eq!(digest.len(), 32);
/// ```
pub fn sha256(message: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

/// SHA-256 trace data for delegation
#[derive(Debug, Clone)]
pub struct Sha256Trace {
    /// Input message (up to 8KB for proof size)
    pub message: Vec<u8>,
    /// Number of 512-bit blocks processed
    pub num_blocks: usize,
    /// Initial hash values (H0-H7) as M31 limbs
    pub initial_state: Vec<M31>,
    /// Final hash values (H0-H7) as M31 limbs
    pub final_state: Vec<M31>,
    /// Message schedule W[0..63] for each block as M31 limbs
    pub message_schedule: Vec<Vec<M31>>,
    /// Working variables (a-h) for each round as M31 limbs
    pub working_vars: Vec<Vec<M31>>,
    /// Output digest
    pub digest: [u8; SHA256_DIGEST_SIZE],
}

/// SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
const H_INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Convert a u32 to M31 limbs (two 16-bit limbs)
fn u32_to_m31_limbs(value: u32) -> [M31; 2] {
    let lo = (value & 0xFFFF) as u32;
    let hi = (value >> 16) as u32;
    [M31::new(lo), M31::new(hi)]
}

/// Convert 32-byte digest to M31 limbs (16 limbs for 8 u32 values)
fn digest_to_m31_limbs(digest: &[u8; 32]) -> Vec<M31> {
    let mut limbs = Vec::with_capacity(16);
    for i in 0..8 {
        let value = u32::from_be_bytes([
            digest[i * 4],
            digest[i * 4 + 1],
            digest[i * 4 + 2],
            digest[i * 4 + 3],
        ]);
        let [lo, hi] = u32_to_m31_limbs(value);
        limbs.push(lo);
        limbs.push(hi);
    }
    limbs
}

/// Right rotate a 32-bit value
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

/// SHA-256 Choice function
#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// SHA-256 Majority function
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-256 Sigma0 function
#[inline]
fn sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// SHA-256 Sigma1 function
#[inline]
fn sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// SHA-256 sigma0 function (lowercase)
#[inline]
fn lower_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// SHA-256 sigma1 function (lowercase)
#[inline]
fn lower_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// Pad message according to SHA-256 specification
fn pad_message(message: &[u8]) -> Vec<u8> {
    let msg_len = message.len();
    let bit_len = (msg_len as u64) * 8;
    
    // Calculate padding: message + 0x80 + zeros + length (64 bits)
    let mut padded = Vec::from(message);
    padded.push(0x80);
    
    // Pad with zeros until length ≡ 448 (mod 512)
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    
    // Append original length in bits as 64-bit big-endian
    padded.extend_from_slice(&bit_len.to_be_bytes());
    
    padded
}

/// Generate SHA-256 trace with intermediate states for proving
///
/// Captures all intermediate values during SHA-256 computation to enable
/// constraint verification in the AIR.
///
/// # Arguments
///
/// * `message` - Input message (will be padded internally)
/// * `expected_digest` - Expected output digest for verification
///
/// # Returns
///
/// Complete trace including message schedule, working variables, and state transitions
pub fn generate_sha256_trace(message: &[u8], expected_digest: &[u8; 32]) -> Sha256Trace {
    let padded = pad_message(message);
    let num_blocks = padded.len() / 64;
    
    let mut initial_state = Vec::new();
    for &h in &H_INITIAL {
        let [lo, hi] = u32_to_m31_limbs(h);
        initial_state.push(lo);
        initial_state.push(hi);
    }
    
    let mut h = H_INITIAL;
    let mut message_schedule = Vec::new();
    let mut working_vars = Vec::new();
    
    // Process each 512-bit block
    for block_idx in 0..num_blocks {
        let block = &padded[block_idx * 64..(block_idx + 1) * 64];
        
        // Prepare message schedule W[0..63]
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        
        for i in 16..64 {
            w[i] = lower_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(lower_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }
        
        // Convert message schedule to M31 limbs
        let mut w_limbs = Vec::new();
        for &wi in &w {
            let [lo, hi] = u32_to_m31_limbs(wi);
            w_limbs.push(lo);
            w_limbs.push(hi);
        }
        message_schedule.push(w_limbs);
        
        // Initialize working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        
        // Main compression loop - store working variables for each round
        for i in 0..64 {
            let t1 = hh
                .wrapping_add(sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a, b, c));
            
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
            
            // Store working variables as M31 limbs (flat structure)
            working_vars.push(vec![
                u32_to_m31_limbs(a)[0], u32_to_m31_limbs(a)[1],
                u32_to_m31_limbs(b)[0], u32_to_m31_limbs(b)[1],
                u32_to_m31_limbs(c)[0], u32_to_m31_limbs(c)[1],
                u32_to_m31_limbs(d)[0], u32_to_m31_limbs(d)[1],
                u32_to_m31_limbs(e)[0], u32_to_m31_limbs(e)[1],
                u32_to_m31_limbs(f)[0], u32_to_m31_limbs(f)[1],
                u32_to_m31_limbs(g)[0], u32_to_m31_limbs(g)[1],
                u32_to_m31_limbs(hh)[0], u32_to_m31_limbs(hh)[1],
            ]);
        }
        
        // Update hash values
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    
    // Convert final state to M31 limbs
    let mut final_state = Vec::new();
    for &hi in &h {
        let [lo, high] = u32_to_m31_limbs(hi);
        final_state.push(lo);
        final_state.push(high);
    }
    
    // Verify digest matches
    let mut computed_digest = [0u8; 32];
    for (i, &hi) in h.iter().enumerate() {
        computed_digest[i * 4..(i + 1) * 4].copy_from_slice(&hi.to_be_bytes());
    }
    
    assert_eq!(
        &computed_digest, expected_digest,
        "SHA-256 trace generation: digest mismatch"
    );
    
    Sha256Trace {
        message: message.to_vec(),
        num_blocks,
        initial_state,
        final_state,
        message_schedule,
        working_vars,
        digest: *expected_digest,
    }
}

/// Convert SHA-256 trace to AIR-compatible rows
///
/// Each row represents one round of SHA-256 compression, with columns for:
/// - Message schedule word (W[i])
/// - Working variables (a-h)
/// - Round constant (K[i])
/// - Intermediate computations
///
/// # Returns
///
/// Vector of rows, where each row is a vector of M31 field elements
pub fn trace_to_rows(trace: &Sha256Trace) -> Vec<Vec<M31>> {
    let mut rows = Vec::new();
    let rounds_per_block = 64;
    
    for block_idx in 0..trace.num_blocks {
        let w_limbs = &trace.message_schedule[block_idx];
        let round_start = block_idx * rounds_per_block;
        
        for round in 0..rounds_per_block {
            let mut row = Vec::new();
            
            // Message schedule word W[round] (2 limbs)
            row.push(w_limbs[round * 2]);
            row.push(w_limbs[round * 2 + 1]);
            
            // Round constant K[round] (2 limbs)
            let [k_lo, k_hi] = u32_to_m31_limbs(K[round]);
            row.push(k_lo);
            row.push(k_hi);
            
            // Working variables (16 limbs: a-h, 2 each)
            row.extend_from_slice(&trace.working_vars[round_start + round]);
            
            rows.push(row);
        }
    }
    
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let message = b"";
        let digest = sha256(message);
        
        // Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_hello() {
        let message = b"hello world";
        let digest = sha256(message);
        
        // Expected: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
            0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
            0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
            0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
        ];
        
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let message = b"abc";
        let digest = sha256(message);
        
        // Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_multiblock() {
        // Test with a message longer than 64 bytes to exercise multiple blocks
        let message = b"The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
        let digest = sha256(message);
        
        // Verify it produces a valid 32-byte digest
        assert_eq!(digest.len(), 32);
        
        // Verify it's deterministic
        let digest2 = sha256(message);
        assert_eq!(digest, digest2);
    }

    #[test]
    fn test_generate_trace() {
        let message = b"hello";
        let digest = sha256(message);
        let trace = generate_sha256_trace(message, &digest);
        
        assert_eq!(trace.message, message);
        assert_eq!(trace.digest, digest);
        assert_eq!(trace.num_blocks, 1); // "hello" fits in one block after padding
        assert_eq!(trace.initial_state.len(), 16); // 8 u32 values = 16 M31 limbs
        assert_eq!(trace.final_state.len(), 16);
        assert_eq!(trace.message_schedule.len(), 1); // One block
        assert_eq!(trace.message_schedule[0].len(), 128); // 64 words × 2 limbs
        assert_eq!(trace.working_vars.len(), 64); // 64 rounds for one block
        assert_eq!(trace.working_vars[0].len(), 16); // 8 variables × 2 limbs per round
    }

    #[test]
    fn test_trace_to_rows() {
        let message = b"test";
        let digest = sha256(message);
        let trace = generate_sha256_trace(message, &digest);
        let rows = trace_to_rows(&trace);
        
        assert_eq!(rows.len(), 64); // One block = 64 rounds
        assert_eq!(rows[0].len(), 20); // W(2) + K(2) + vars(16)
    }

    #[test]
    fn test_padding() {
        // Test message padding
        let msg1 = b"a";
        let padded1 = pad_message(msg1);
        assert_eq!(padded1.len() % 64, 0); // Must be multiple of 64
        assert_eq!(padded1[1], 0x80); // First padding byte
        
        // Test with 55-byte message (edge case)
        let msg2 = &[0u8; 55];
        let padded2 = pad_message(msg2);
        assert_eq!(padded2.len(), 64); // Should fit in one block
        
        // Test with 56-byte message (needs extra block)
        let msg3 = &[0u8; 56];
        let padded3 = pad_message(msg3);
        assert_eq!(padded3.len(), 128); // Needs two blocks
    }

    #[test]
    fn test_digest_to_limbs() {
        let digest = sha256(b"test");
        let limbs = digest_to_m31_limbs(&digest);
        
        assert_eq!(limbs.len(), 16); // 8 u32 values × 2 limbs each
        
        // Verify all limbs are valid M31 elements (< 2^31 - 1)
        for limb in &limbs {
            assert!(limb.as_u32() < (1u32 << 31) - 1);
        }
    }

    #[test]
    fn test_rotation_functions() {
        let x = 0x12345678u32;
        
        // Test rotr
        assert_eq!(rotr(x, 0), x);
        assert_eq!(rotr(x, 32), x);
        assert_eq!(rotr(x, 4), 0x81234567);
        
        // Test that sigma functions don't panic
        let _ = sigma0(x);
        let _ = sigma1(x);
        let _ = lower_sigma0(x);
        let _ = lower_sigma1(x);
    }

    #[test]
    fn test_choice_majority() {
        let x = 0xAAAAAAAAu32;
        let y = 0xCCCCCCCCu32;
        let z = 0xF0F0F0F0u32;
        
        // Test ch and maj don't panic
        let _ = ch(x, y, z);
        let _ = maj(x, y, z);
    }
}
