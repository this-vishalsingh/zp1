//! zp1-prover: STARK prover with DEEP FRI.
//!
//! CPU backend for commitment, LDE, constraint evaluation, and FRI.

pub mod channel;
pub mod commitment;
pub mod fri;
pub mod lde;
pub mod logup;
pub mod stark;

pub use commitment::MerkleTree;
pub use channel::ProverChannel;
pub use stark::{StarkConfig, StarkProver, StarkProof, QueryProof};
pub use lde::{LdeDomain, TraceLDE};
pub use logup::{LookupTable, LogUpProver, RangeCheck, PermutationArgument};
