//! zp1-verifier: STARK proof verification.
//!
//! Rust verifier for base proofs and recursive aggregation.

pub mod channel;
pub mod verify;

pub use verify::Verifier;
