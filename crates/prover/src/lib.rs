//! zp1-prover: STARK prover with DEEP FRI.
//!
//! CPU and GPU backends for commitment, LDE, constraint evaluation, and FRI.

pub mod channel;
pub mod commitment;
pub mod delegation;
pub mod fri;
pub mod gpu;
pub mod lde;
pub mod logup;
pub mod memory;
pub mod memory_old;
pub mod parallel;
pub mod ram;
pub mod ram_old;
pub mod recursion;
pub mod serialize;
pub mod snark;
pub mod stark;

pub use commitment::MerkleTree;
pub use channel::ProverChannel;
pub use stark::{StarkConfig, StarkProver, StarkProof, QueryProof};
pub use lde::{LdeDomain, TraceLDE};
pub use logup::{LookupTable, LogUpProver, RangeCheck, PermutationArgument};
pub use memory::{MemoryConsistencyProver, MemoryAccess, MemoryOp, MemoryColumns};
pub use parallel::{ParallelConfig, parallel_lde, parallel_merkle_tree, parallel_fri_fold};
pub use serialize::{SerializableProof, VerificationKey, ProofConfig};
pub use gpu::{GpuBackend, GpuDevice, GpuError, DeviceType, detect_devices};
pub use recursion::{RecursiveProver, RecursiveProof, RecursionConfig, SegmentedProver};
pub use ram::{RamArgumentProver, RamAccess, RamOp, RamColumns, ChunkMemorySubtree};
pub use delegation::{DelegationArgumentProver, DelegationCall, DelegationResult, DelegationType, DelegationColumns, DelegationSubtree};
pub use snark::{SnarkWrapper, SnarkProof, SnarkVerifier, SnarkSystem, SnarkConfig, SnarkError, groth16_wrapper, plonk_wrapper, halo2_wrapper};
