//! zp1-delegation: Delegated gadgets for precompiles.
//!
//! BLAKE2s/BLAKE3 hash circuits, Keccak-256 for Ethereum, ECRECOVER for signatures, SHA-256, RIPEMD-160, and U256 bigint operations.

pub mod blake;
pub mod blake2b;
pub mod bigint;
pub mod keccak;
pub mod ecrecover;
pub mod sha256;
pub mod ripemd160;
