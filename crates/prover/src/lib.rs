//! zp1-prover: STARK prover with DEEP FRI.
//!
//! CPU backend for commitment, LDE, constraint evaluation, and FRI.

pub mod channel;
pub mod commitment;
pub mod fri;
pub mod lde;

pub use commitment::MerkleTree;
pub use channel::ProverChannel;
