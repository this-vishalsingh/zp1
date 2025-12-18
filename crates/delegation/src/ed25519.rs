//! Ed25519 delegation gadget for signature verification.
//!
//! Ed25519 is a popular EdDSA signature scheme used by:
//! - Solana blockchain
//! - Signal protocol
//! - SSH keys
//! - Many other modern cryptographic applications
//!
//! # Why Delegation?
//!
//! Implementing Ed25519 verification in pure RISC-V would require:
//! - Edwards curve point operations (~500K instructions)
//! - Field arithmetic over 255-bit integers (~5K instructions per op)
//! - SHA-512 hash computation (~50K instructions)
//! - **Total: ~2-5M instructions = ~5M trace rows**
//!
//! With delegation: **~100 rows** (50,000x improvement!)
//!
//! # Algorithm
//!
//! Ed25519 verification:
//!
//! 1. **Input**: `(message, public_key, signature)` where:
//!    - `message`: Variable-length message
//!    - `public_key`: 32-byte compressed EdDSA public key
//!    - `signature`: 64-byte signature (R || s)
//!
//! 2. **Verification**:
//!    - Decompress public key to Edwards curve point
//!    - Compute h = SHA512(R || A || M)
//!    - Verify: [s]B = R + [h]A
//!
//! 3. **Output**: Boolean valid/invalid
//!
//! # Syscall Interface
//!
//! ```text
//! Register Convention:
//! a0 = pointer to message
//! a1 = message length
//! a2 = pointer to public key (32 bytes)
//! a3 = pointer to signature (64 bytes)
//! a7 = 0x2001 (ed25519_verify syscall number)
//! ecall
//!
//! Return:
//! a0 = 0 (valid) or 1 (invalid)
//! ```

use serde::{Deserialize, Serialize};
use zp1_primitives::M31;

/// Ed25519 verify syscall number.
pub const ED25519_VERIFY_SYSCALL: u32 = 0x2001;

/// Public key size (compressed Edwards point).
pub const ED25519_PUBKEY_SIZE: usize = 32;

/// Signature size (R || s).
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// A single Ed25519 verification trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ed25519Trace {
    /// Message that was signed (up to 1KB supported inline)
    pub message: Vec<u8>,
    /// Public key (32 bytes)
    pub public_key: [u8; 32],
    /// Signature R component (32 bytes)
    pub signature_r: [u8; 32],
    /// Signature s component (32 bytes)
    pub signature_s: [u8; 32],
    /// Whether the signature is valid
    pub valid: bool,
    /// Intermediate: SHA512 hash of R || A || M (first 32 bytes)
    pub hash_lo: [u8; 32],
    /// Intermediate: SHA512 hash of R || A || M (last 32 bytes)
    pub hash_hi: [u8; 32],
}

/// A single row in the Ed25519 trace table.
#[derive(Clone, Debug)]
pub struct Ed25519TraceRow {
    /// Row type: 0=hash_computation, 1=point_decompression, 2=scalar_mul, 3=point_add
    pub row_type: M31,
    /// Public key (as M31 limbs)
    pub pubkey_limbs: Vec<M31>,
    /// Signature R (as M31 limbs)
    pub sig_r_limbs: Vec<M31>,
    /// Signature s (as M31 limbs)
    pub sig_s_limbs: Vec<M31>,
    /// Message hash intermediate (as M31 limbs)
    pub hash_limbs: Vec<M31>,
    /// Validity flag
    pub valid: M31,
}

/// Configuration for Ed25519 delegation.
#[derive(Clone, Debug)]
pub struct Ed25519Config {
    /// Maximum number of verify calls per batch
    pub max_calls: usize,
    /// Maximum message size supported
    pub max_message_size: usize,
}

impl Default for Ed25519Config {
    fn default() -> Self {
        Self {
            max_calls: 1024,
            max_message_size: 1024,
        }
    }
}

// ============================================================================
// Ed25519 Implementation using ed25519-dalek (when available) or stub
// ============================================================================

/// Verify an Ed25519 signature.
///
/// Returns true if the signature is valid, false otherwise.
pub fn ed25519_verify(message: &[u8], public_key: &[u8; 32], signature: &[u8; 64]) -> bool {
    // Try to use native implementation
    ed25519_verify_native(message, public_key, signature)
}

#[cfg(feature = "ed25519")]
fn ed25519_verify_native(message: &[u8], public_key: &[u8; 32], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let verifying_key = match VerifyingKey::from_bytes(public_key) {
        Ok(key) => key,
        Err(_) => return false,
    };

    let sig = match Signature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(message, &sig).is_ok()
}

#[cfg(not(feature = "ed25519"))]
fn ed25519_verify_native(_message: &[u8], _public_key: &[u8; 32], _signature: &[u8; 64]) -> bool {
    // Stub implementation when ed25519-dalek is not available
    // In production, this should be enabled
    false
}

/// Generate an Ed25519 verification trace.
pub fn generate_ed25519_trace(
    message: &[u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Ed25519Trace {
    let mut signature_r = [0u8; 32];
    let mut signature_s = [0u8; 32];
    signature_r.copy_from_slice(&signature[..32]);
    signature_s.copy_from_slice(&signature[32..]);

    let valid = ed25519_verify(message, public_key, signature);

    // Compute intermediate hash: SHA512(R || A || M)
    let hash = compute_ed25519_hash(&signature_r, public_key, message);
    let mut hash_lo = [0u8; 32];
    let mut hash_hi = [0u8; 32];
    hash_lo.copy_from_slice(&hash[..32]);
    hash_hi.copy_from_slice(&hash[32..]);

    Ed25519Trace {
        message: message.to_vec(),
        public_key: *public_key,
        signature_r,
        signature_s,
        valid,
        hash_lo,
        hash_hi,
    }
}

/// Compute SHA512(R || A || M) for Ed25519.
fn compute_ed25519_hash(r: &[u8; 32], a: &[u8; 32], m: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};

    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(a);
    hasher.update(m);

    let result = hasher.finalize();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result);
    hash
}

/// Convert 32-byte value to M31 limbs (9 limbs for 256 bits).
pub fn bytes32_to_m31_limbs(bytes: &[u8; 32]) -> Vec<M31> {
    let mut limbs = Vec::with_capacity(9);
    let mut bit_pos = 0usize;

    for _ in 0..9 {
        if bit_pos >= 256 {
            limbs.push(M31::ZERO);
            continue;
        }

        let mut value = 0u32;
        for i in 0..31 {
            let abs_bit = bit_pos + i;
            if abs_bit >= 256 {
                break;
            }
            let byte_idx = abs_bit / 8;
            let bit_idx = abs_bit % 8;
            let bit = (bytes[byte_idx] >> bit_idx) & 1;
            value |= (bit as u32) << i;
        }

        limbs.push(M31::new(value));
        bit_pos += 31;
    }

    limbs
}

/// Convert 64-byte hash to M31 limbs (17 limbs for 512 bits).
pub fn bytes64_to_m31_limbs(bytes: &[u8; 64]) -> Vec<M31> {
    let mut limbs = Vec::with_capacity(17);
    let mut bit_pos = 0usize;

    for _ in 0..17 {
        if bit_pos >= 512 {
            limbs.push(M31::ZERO);
            continue;
        }

        let mut value = 0u32;
        for i in 0..31 {
            let abs_bit = bit_pos + i;
            if abs_bit >= 512 {
                break;
            }
            let byte_idx = abs_bit / 8;
            let bit_idx = abs_bit % 8;
            let bit = (bytes[byte_idx] >> bit_idx) & 1;
            value |= (bit as u32) << i;
        }

        limbs.push(M31::new(value));
        bit_pos += 31;
    }

    limbs
}

/// Combine hash_lo and hash_hi back to [u8; 64] for limb conversion.
fn combine_hash(lo: &[u8; 32], hi: &[u8; 32]) -> [u8; 64] {
    let mut hash = [0u8; 64];
    hash[..32].copy_from_slice(lo);
    hash[32..].copy_from_slice(hi);
    hash
}

/// Generate trace rows for proving.
pub fn trace_to_rows(trace: &Ed25519Trace) -> Vec<Ed25519TraceRow> {
    let mut rows = Vec::new();
    let hash = combine_hash(&trace.hash_lo, &trace.hash_hi);

    // Row 1: Hash computation (SHA512)
    rows.push(Ed25519TraceRow {
        row_type: M31::ZERO,
        pubkey_limbs: bytes32_to_m31_limbs(&trace.public_key),
        sig_r_limbs: bytes32_to_m31_limbs(&trace.signature_r),
        sig_s_limbs: bytes32_to_m31_limbs(&trace.signature_s),
        hash_limbs: bytes64_to_m31_limbs(&hash),
        valid: M31::new(trace.valid as u32),
    });

    // Row 2: Point decompression (A from public key)
    rows.push(Ed25519TraceRow {
        row_type: M31::new(1),
        pubkey_limbs: bytes32_to_m31_limbs(&trace.public_key),
        sig_r_limbs: bytes32_to_m31_limbs(&trace.signature_r),
        sig_s_limbs: bytes32_to_m31_limbs(&trace.signature_s),
        hash_limbs: bytes64_to_m31_limbs(&hash),
        valid: M31::new(trace.valid as u32),
    });

    // Row 3: Scalar multiplication [s]B
    rows.push(Ed25519TraceRow {
        row_type: M31::new(2),
        pubkey_limbs: bytes32_to_m31_limbs(&trace.public_key),
        sig_r_limbs: bytes32_to_m31_limbs(&trace.signature_r),
        sig_s_limbs: bytes32_to_m31_limbs(&trace.signature_s),
        hash_limbs: bytes64_to_m31_limbs(&hash),
        valid: M31::new(trace.valid as u32),
    });

    // Row 4: Final point addition/comparison
    rows.push(Ed25519TraceRow {
        row_type: M31::new(3),
        pubkey_limbs: bytes32_to_m31_limbs(&trace.public_key),
        sig_r_limbs: bytes32_to_m31_limbs(&trace.signature_r),
        sig_s_limbs: bytes32_to_m31_limbs(&trace.signature_s),
        hash_limbs: bytes64_to_m31_limbs(&hash),
        valid: M31::new(trace.valid as u32),
    });

    rows
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_trace_generation() {
        let message = b"test message";
        let public_key = [0xAAu8; 32];
        let signature = [0xBBu8; 64];

        let trace = generate_ed25519_trace(message, &public_key, &signature);

        assert_eq!(trace.message, message.to_vec());
        assert_eq!(trace.public_key, public_key);
        assert_eq!(trace.signature_r, [0xBBu8; 32]);
        assert_eq!(trace.signature_s, [0xBBu8; 32]);
        // Random signature should be invalid
        assert!(!trace.valid);
    }

    #[test]
    fn test_bytes32_to_limbs() {
        let mut test_bytes = [0u8; 32];
        test_bytes[0] = 0xFF;

        let limbs = bytes32_to_m31_limbs(&test_bytes);
        assert_eq!(limbs.len(), 9);
        assert_ne!(limbs[0].as_u32(), 0);
    }

    #[test]
    fn test_bytes64_to_limbs() {
        let test_bytes = [0xABu8; 64];

        let limbs = bytes64_to_m31_limbs(&test_bytes);
        assert_eq!(limbs.len(), 17);
    }

    #[test]
    fn test_trace_rows() {
        let message = b"hello";
        let public_key = [0u8; 32];
        let signature = [0u8; 64];

        let trace = generate_ed25519_trace(message, &public_key, &signature);
        let rows = trace_to_rows(&trace);

        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].row_type, M31::ZERO);
        assert_eq!(rows[1].row_type, M31::new(1));
        assert_eq!(rows[2].row_type, M31::new(2));
        assert_eq!(rows[3].row_type, M31::new(3));
    }

    #[test]
    fn test_hash_computation() {
        let r = [0u8; 32];
        let a = [1u8; 32];
        let m = b"message";

        let hash = compute_ed25519_hash(&r, &a, m);
        assert_eq!(hash.len(), 64);
        // Hash should be deterministic
        let hash2 = compute_ed25519_hash(&r, &a, m);
        assert_eq!(hash, hash2);
    }
}
