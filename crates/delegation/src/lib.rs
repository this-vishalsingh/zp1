//! zp1-delegation: Delegated gadgets for precompiles.
//!
//! BLAKE2s/BLAKE3 hash circuits, Keccak-256 for Ethereum, ECRECOVER for signatures,
//! SHA-256, RIPEMD-160, Ed25519, Secp256R1, and U256 bigint operations.

pub mod bigint;
pub mod blake;
pub mod blake2b;
pub mod ecrecover;
pub mod ed25519;
pub mod keccak;
pub mod ripemd160;
pub mod secp256r1;
pub mod sha256;
