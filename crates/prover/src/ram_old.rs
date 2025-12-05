//! RAM Argument using "Two Shuffles Make a RAM" permutation argument.
//!
//! This module implements memory consistency across execution chunks using a
//! permutation argument based on the paper "Two Shuffles Make a RAM".
//!
//! # Key Features
//!
//! - **Lazy Init/Teardown**: Memory is initialized on first access, finalized on last
//! - **Chunk-Parallel Proving**: Each chunk has its own memory subtree for pre-commitment
//! - **Two-Shuffle Protocol**: Uses two permutation arguments to prove memory consistency
//!
//! # Protocol Overview
//!
//! 1. **Access Trace**: Record all memory accesses (addr, value, timestamp, op)
//! 2. **Sorted Trace**: Sort by (address, timestamp) to group accesses
//! 3. **Init/Final Tuples**: Extract initial and final values per address
//! 4. **Two Shuffles**:
//!    - Shuffle 1: Access trace ↔ Sorted trace (permutation)
//!    - Shuffle 2: Init tuples ↔ Final tuples (multiset equality with modifications)
//!
//! This approach allows proving memory consistency without knowing the full memory
//! state upfront, enabling parallel proving of execution chunks.

use zp1_primitives::{M31, QM31};
use std::collections::BTreeMap;

/// M31 modulus for reduction.
const M31_MOD: u32 = (1 << 31) - 1;

/// RAM operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamOp {
    /// Initialize memory (first access to address)
    Init,
    /// Read from memory
    Read,
    /// Write to memory
    Write,
    /// Finalize memory (last access to address)
    Final,
}

impl RamOp {
    /// Convert to field element.
    pub fn to_field(self) -> M31 {
        match self {
            RamOp::Init => M31::ZERO,
            RamOp::Read => M31::ONE,
            RamOp::Write => M31::new(2),
            RamOp::Final => M31::new(3),
        }
    }

    /// Is this an initializing operation?
    pub fn is_init(self) -> bool {
        matches!(self, RamOp::Init)
    }

    /// Is this a finalizing operation?
    pub fn is_final(self) -> bool {
        matches!(self, RamOp::Final)
    }
}

/// A single RAM access tuple.
#[derive(Debug, Clone, Copy)]
pub struct RamAccess {
    /// Memory address
    pub address: u32,
    /// Value read or written
    pub value: u32,
    /// Global timestamp (cycle number across all chunks)
    pub timestamp: u64,
    /// Operation type
    pub op: RamOp,
    /// Chunk index (for parallel proving)
    pub chunk_id: u32,
}

impl RamAccess {
    /// Create a new RAM access.
    pub fn new(address: u32, value: u32, timestamp: u64, op: RamOp, chunk_id: u32) -> Self {
        Self { address, value, timestamp, op, chunk_id }
    }

    /// Create a read access.
    pub fn read(address: u32, value: u32, timestamp: u64, chunk_id: u32) -> Self {
        Self::new(address, value, timestamp, RamOp::Read, chunk_id)
    }

    /// Create a write access.
    pub fn write(address: u32, value: u32, timestamp: u64, chunk_id: u32) -> Self {
        Self::new(address, value, timestamp, RamOp::Write, chunk_id)
    }

    /// Compute fingerprint for LogUp argument.
    pub fn fingerprint(&self, alpha: QM31, beta: QM31) -> QM31 {
        let alpha2 = alpha * alpha;
        let alpha3 = alpha2 * alpha;
        let alpha4 = alpha3 * alpha;
        
        let addr = QM31::from(M31::new(self.address));
        let val = QM31::from(M31::new(self.value));
        let ts_lo = QM31::from(M31::new((self.timestamp & 0x7FFFFFFF) as u32));
        let ts_hi = QM31::from(M31::new(((self.timestamp >> 31) & 0x7FFFFFFF) as u32));
        let op = QM31::from(self.op.to_field());
        
        alpha4 * addr + alpha3 * val + alpha2 * ts_lo + alpha * ts_hi + op + beta
    }
}

/// RAM argument prover implementing "Two Shuffles Make a RAM".
pub struct RamArgumentProver {
    /// All memory accesses in execution order
    accesses: Vec<RamAccess>,
    /// Number of chunks for parallel proving
    num_chunks: u32,
    /// LogUp challenges
    alpha: QM31,
    beta: QM31,
}

impl RamArgumentProver {
    /// Create a new RAM argument prover.
    pub fn new(num_chunks: u32) -> Self {
        Self {
            accesses: Vec::new(),
            num_chunks,
            alpha: QM31::ZERO,
            beta: QM31::ZERO,
        }
    }

    /// Add a memory access.
    pub fn add_access(&mut self, access: RamAccess) {
        self.accesses.push(access);
    }

    /// Add multiple accesses from an execution trace.
    pub fn add_trace(&mut self, accesses: impl IntoIterator<Item = RamAccess>) {
        self.accesses.extend(accesses);
    }

    /// Set LogUp challenges.
    pub fn set_challenges(&mut self, alpha: QM31, beta: QM31) {
        self.alpha = alpha;
        self.beta = beta;
    }

    /// Generate sorted trace (by address, then timestamp).
    pub fn sorted_trace(&self) -> Vec<RamAccess> {
        let mut sorted = self.accesses.clone();
        sorted.sort_by_key(|a| (a.address, a.timestamp));
        sorted
    }

    /// Extract initial and final tuples for each address.
    /// 
    /// Returns (init_tuples, final_tuples) where:
    /// - init_tuples: First access to each address (with Init op)
    /// - final_tuples: Last access to each address (with Final op)
    pub fn extract_init_final(&self) -> (Vec<RamAccess>, Vec<RamAccess>) {
        let sorted = self.sorted_trace();
        
        // Group by address
        let mut by_address: BTreeMap<u32, Vec<&RamAccess>> = BTreeMap::new();
        for access in &sorted {
            by_address.entry(access.address).or_default().push(access);
        }
        
        let mut init_tuples = Vec::new();
        let mut final_tuples = Vec::new();
        
        for (addr, accesses) in by_address {
            if let Some(first) = accesses.first() {
                // Init tuple: first access, mark as Init
                init_tuples.push(RamAccess {
                    address: addr,
                    value: first.value,
                    timestamp: first.timestamp,
                    op: RamOp::Init,
                    chunk_id: first.chunk_id,
                });
            }
            
            if let Some(last) = accesses.last() {
                // Final tuple: last access, mark as Final
                final_tuples.push(RamAccess {
                    address: addr,
                    value: last.value,
                    timestamp: last.timestamp,
                    op: RamOp::Final,
                    chunk_id: last.chunk_id,
                });
            }
        }
        
        (init_tuples, final_tuples)
    }

    /// Generate RAM argument columns for proving.
    pub fn generate_columns(&self) -> RamColumns {
        let n = self.accesses.len();
        let sorted = self.sorted_trace();
        let (init_tuples, final_tuples) = self.extract_init_final();
        
        // Execution order columns
        let mut exec_addr = Vec::with_capacity(n);
        let mut exec_value = Vec::with_capacity(n);
        let mut exec_ts = Vec::with_capacity(n);
        let mut exec_op = Vec::with_capacity(n);
        let mut exec_chunk = Vec::with_capacity(n);
        
        // Sorted order columns
        let mut sorted_addr = Vec::with_capacity(n);
        let mut sorted_value = Vec::with_capacity(n);
        let mut sorted_ts = Vec::with_capacity(n);
        let mut sorted_op = Vec::with_capacity(n);
        let mut sorted_chunk = Vec::with_capacity(n);
        
        for access in &self.accesses {
            exec_addr.push(M31::new(access.address));
            exec_value.push(M31::new(access.value));
            exec_ts.push(M31::new((access.timestamp % M31_MOD as u64) as u32));
            exec_op.push(access.op.to_field());
            exec_chunk.push(M31::new(access.chunk_id));
        }
        
        for access in &sorted {
            sorted_addr.push(M31::new(access.address));
            sorted_value.push(M31::new(access.value));
            sorted_ts.push(M31::new((access.timestamp % M31_MOD as u64) as u32));
            sorted_op.push(access.op.to_field());
            sorted_chunk.push(M31::new(access.chunk_id));
        }
        
        // Compute LogUp running products for permutation argument
        let (perm_num, perm_denom) = self.compute_permutation_columns(&sorted);
        
        // Compute init/final multiset columns
        let (init_fingerprints, final_fingerprints) = 
            self.compute_init_final_columns(&init_tuples, &final_tuples);
        
        RamColumns {
            // Execution order
            exec_address: exec_addr,
            exec_value,
            exec_timestamp: exec_ts,
            exec_op,
            exec_chunk,
            // Sorted order
            sorted_address: sorted_addr,
            sorted_value,
            sorted_timestamp: sorted_ts,
            sorted_op,
            sorted_chunk,
            // Permutation argument
            perm_numerator: perm_num,
            perm_denominator: perm_denom,
            // Init/final multiset
            init_fingerprints,
            final_fingerprints,
        }
    }

    /// Compute LogUp columns for permutation argument (Shuffle 1).
    fn compute_permutation_columns(&self, sorted: &[RamAccess]) -> (Vec<QM31>, Vec<QM31>) {
        let n = self.accesses.len();
        let mut numerator = vec![QM31::ONE; n];
        let mut denominator = vec![QM31::ONE; n];
        
        // Running product: ∏(exec_fp + β) / ∏(sorted_fp + β) = 1
        for i in 0..n {
            let exec_fp = self.accesses[i].fingerprint(self.alpha, self.beta);
            let sorted_fp = sorted[i].fingerprint(self.alpha, self.beta);
            
            if i == 0 {
                numerator[i] = exec_fp;
                denominator[i] = sorted_fp;
            } else {
                numerator[i] = numerator[i - 1] * exec_fp;
                denominator[i] = denominator[i - 1] * sorted_fp;
            }
        }
        
        (numerator, denominator)
    }

    /// Compute init/final multiset columns (Shuffle 2).
    fn compute_init_final_columns(
        &self,
        init_tuples: &[RamAccess],
        final_tuples: &[RamAccess],
    ) -> (Vec<QM31>, Vec<QM31>) {
        let n = init_tuples.len();
        let mut init_fps = Vec::with_capacity(n);
        let mut final_fps = Vec::with_capacity(n);
        
        for init in init_tuples {
            init_fps.push(init.fingerprint(self.alpha, self.beta));
        }
        
        for fin in final_tuples {
            final_fps.push(fin.fingerprint(self.alpha, self.beta));
        }
        
        (init_fps, final_fps)
    }

    /// Verify RAM consistency (for testing/debugging).
    pub fn verify_consistency(&self) -> Result<(), RamError> {
        let sorted = self.sorted_trace();
        
        let mut prev_addr = None;
        let mut prev_value = None;
        let mut prev_ts = None;
        
        for (i, access) in sorted.iter().enumerate() {
            if let Some(pa) = prev_addr {
                if access.address == pa {
                    // Same address - check ordering
                    if let Some(pts) = prev_ts {
                        if access.timestamp < pts {
                            return Err(RamError::TimestampOrder {
                                address: access.address,
                                prev_ts: pts,
                                curr_ts: access.timestamp,
                            });
                        }
                    }
                    
                    // If read, must see previous value
                    if access.op == RamOp::Read {
                        if let Some(pv) = prev_value {
                            if access.value != pv {
                                return Err(RamError::ReadMismatch {
                                    address: access.address,
                                    expected: pv,
                                    actual: access.value,
                                    timestamp: access.timestamp,
                                    row: i,
                                });
                            }
                        }
                    }
                }
            }
            
            prev_addr = Some(access.address);
            prev_value = Some(access.value);
            prev_ts = Some(access.timestamp);
        }
        
        Ok(())
    }

    /// Get accesses grouped by chunk (for parallel proving).
    pub fn by_chunk(&self) -> Vec<Vec<&RamAccess>> {
        let mut chunks = vec![Vec::new(); self.num_chunks as usize];
        for access in &self.accesses {
            if (access.chunk_id as usize) < chunks.len() {
                chunks[access.chunk_id as usize].push(access);
            }
        }
        chunks
    }
}

/// Generated RAM argument columns.
#[derive(Debug, Clone)]
pub struct RamColumns {
    // Execution order columns
    pub exec_address: Vec<M31>,
    pub exec_value: Vec<M31>,
    pub exec_timestamp: Vec<M31>,
    pub exec_op: Vec<M31>,
    pub exec_chunk: Vec<M31>,
    
    // Sorted order columns
    pub sorted_address: Vec<M31>,
    pub sorted_value: Vec<M31>,
    pub sorted_timestamp: Vec<M31>,
    pub sorted_op: Vec<M31>,
    pub sorted_chunk: Vec<M31>,
    
    // Permutation argument columns
    pub perm_numerator: Vec<QM31>,
    pub perm_denominator: Vec<QM31>,
    
    // Init/final multiset columns
    pub init_fingerprints: Vec<QM31>,
    pub final_fingerprints: Vec<QM31>,
}

/// RAM consistency error.
#[derive(Debug, Clone)]
pub enum RamError {
    /// Timestamp ordering violation
    TimestampOrder {
        address: u32,
        prev_ts: u64,
        curr_ts: u64,
    },
    /// Read value mismatch
    ReadMismatch {
        address: u32,
        expected: u32,
        actual: u32,
        timestamp: u64,
        row: usize,
    },
    /// Invalid chunk boundary
    InvalidChunkBoundary {
        chunk_id: u32,
        message: String,
    },
}

impl std::fmt::Display for RamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RamError::TimestampOrder { address, prev_ts, curr_ts } => {
                write!(f, "Timestamp order violation at {:#x}: {} -> {}", address, prev_ts, curr_ts)
            }
            RamError::ReadMismatch { address, expected, actual, timestamp, row } => {
                write!(f, "Read mismatch at {:#x} ts {}, row {}: expected {}, got {}", 
                       address, timestamp, row, expected, actual)
            }
            RamError::InvalidChunkBoundary { chunk_id, message } => {
                write!(f, "Invalid chunk {} boundary: {}", chunk_id, message)
            }
        }
    }
}

impl std::error::Error for RamError {}

/// Memory subtree for chunk-parallel proving.
/// 
/// Each chunk has its own memory subtree that can be committed independently.
/// The subtrees are then linked via the init/final multiset argument.
#[derive(Debug, Clone)]
pub struct ChunkMemorySubtree {
    /// Chunk identifier
    pub chunk_id: u32,
    /// Memory accesses in this chunk
    pub accesses: Vec<RamAccess>,
    /// Commitment to this chunk's memory operations
    pub commitment: [u8; 32],
    /// Initial memory state (address -> value) at chunk start
    pub init_state: BTreeMap<u32, u32>,
    /// Final memory state (address -> value) at chunk end
    pub final_state: BTreeMap<u32, u32>,
}

impl ChunkMemorySubtree {
    /// Create a new chunk memory subtree.
    pub fn new(chunk_id: u32) -> Self {
        Self {
            chunk_id,
            accesses: Vec::new(),
            commitment: [0u8; 32],
            init_state: BTreeMap::new(),
            final_state: BTreeMap::new(),
        }
    }

    /// Add an access to this chunk.
    pub fn add_access(&mut self, access: RamAccess) {
        // Track first and last values per address
        let addr = access.address;
        let val = access.value;
        
        self.init_state.entry(addr).or_insert(val);
        self.final_state.insert(addr, val);
        
        self.accesses.push(access);
    }

    /// Get columns for this chunk's memory subtree.
    pub fn get_columns(&self) -> Vec<Vec<M31>> {
        let n = self.accesses.len();
        let mut addr_col = Vec::with_capacity(n);
        let mut val_col = Vec::with_capacity(n);
        let mut ts_col = Vec::with_capacity(n);
        let mut op_col = Vec::with_capacity(n);
        
        for access in &self.accesses {
            addr_col.push(M31::new(access.address));
            val_col.push(M31::new(access.value));
            ts_col.push(M31::new((access.timestamp % M31_MOD as u64) as u32));
            op_col.push(access.op.to_field());
        }
        
        vec![addr_col, val_col, ts_col, op_col]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_access_creation() {
        let read = RamAccess::read(0x1000, 42, 100, 0);
        assert_eq!(read.address, 0x1000);
        assert_eq!(read.value, 42);
        assert_eq!(read.op, RamOp::Read);
        
        let write = RamAccess::write(0x1000, 99, 101, 0);
        assert_eq!(write.op, RamOp::Write);
    }

    #[test]
    fn test_ram_sorted_trace() {
        let mut prover = RamArgumentProver::new(1);
        
        // Add accesses out of order
        prover.add_access(RamAccess::write(0x2000, 20, 200, 0));
        prover.add_access(RamAccess::write(0x1000, 10, 100, 0));
        prover.add_access(RamAccess::read(0x1000, 10, 150, 0));
        prover.add_access(RamAccess::write(0x1000, 15, 175, 0));
        
        let sorted = prover.sorted_trace();
        
        // Should be sorted by (address, timestamp)
        assert_eq!(sorted[0].address, 0x1000);
        assert_eq!(sorted[0].timestamp, 100);
        assert_eq!(sorted[1].address, 0x1000);
        assert_eq!(sorted[1].timestamp, 150);
        assert_eq!(sorted[2].address, 0x1000);
        assert_eq!(sorted[2].timestamp, 175);
        assert_eq!(sorted[3].address, 0x2000);
    }

    #[test]
    fn test_ram_init_final_extraction() {
        let mut prover = RamArgumentProver::new(1);
        
        prover.add_access(RamAccess::write(0x1000, 10, 100, 0));
        prover.add_access(RamAccess::read(0x1000, 10, 150, 0));
        prover.add_access(RamAccess::write(0x1000, 20, 200, 0));
        prover.add_access(RamAccess::write(0x2000, 30, 125, 0));
        
        let (init, fin) = prover.extract_init_final();
        
        // Init: first access to each address
        assert_eq!(init.len(), 2);
        assert_eq!(init[0].address, 0x1000);
        assert_eq!(init[0].value, 10);
        assert_eq!(init[0].op, RamOp::Init);
        
        // Final: last access to each address  
        assert_eq!(fin.len(), 2);
        assert_eq!(fin[0].address, 0x1000);
        assert_eq!(fin[0].value, 20); // Last write
        assert_eq!(fin[0].op, RamOp::Final);
    }

    #[test]
    fn test_ram_consistency_valid() {
        let mut prover = RamArgumentProver::new(1);
        
        prover.add_access(RamAccess::write(0x1000, 10, 100, 0));
        prover.add_access(RamAccess::read(0x1000, 10, 150, 0));  // Read sees write
        prover.add_access(RamAccess::write(0x1000, 20, 200, 0));
        prover.add_access(RamAccess::read(0x1000, 20, 250, 0));  // Read sees second write
        
        assert!(prover.verify_consistency().is_ok());
    }

    #[test]
    fn test_ram_consistency_invalid_read() {
        let mut prover = RamArgumentProver::new(1);
        
        prover.add_access(RamAccess::write(0x1000, 10, 100, 0));
        prover.add_access(RamAccess::read(0x1000, 99, 150, 0));  // Wrong value!
        
        let result = prover.verify_consistency();
        assert!(result.is_err());
        
        if let Err(RamError::ReadMismatch { expected, actual, .. }) = result {
            assert_eq!(expected, 10);
            assert_eq!(actual, 99);
        }
    }

    #[test]
    fn test_chunk_memory_subtree() {
        let mut subtree = ChunkMemorySubtree::new(0);
        
        subtree.add_access(RamAccess::write(0x1000, 10, 100, 0));
        subtree.add_access(RamAccess::write(0x1000, 20, 200, 0));
        subtree.add_access(RamAccess::write(0x2000, 30, 150, 0));
        
        // Init state should have first values
        assert_eq!(subtree.init_state.get(&0x1000), Some(&10));
        assert_eq!(subtree.init_state.get(&0x2000), Some(&30));
        
        // Final state should have last values
        assert_eq!(subtree.final_state.get(&0x1000), Some(&20));
        assert_eq!(subtree.final_state.get(&0x2000), Some(&30));
    }

    #[test]
    fn test_by_chunk() {
        let mut prover = RamArgumentProver::new(2);
        
        prover.add_access(RamAccess::write(0x1000, 10, 100, 0));
        prover.add_access(RamAccess::write(0x2000, 20, 200, 1));
        prover.add_access(RamAccess::read(0x1000, 10, 150, 0));
        prover.add_access(RamAccess::read(0x2000, 20, 250, 1));
        
        let chunks = prover.by_chunk();
        
        assert_eq!(chunks[0].len(), 2);
        assert_eq!(chunks[1].len(), 2);
        assert!(chunks[0].iter().all(|a| a.chunk_id == 0));
        assert!(chunks[1].iter().all(|a| a.chunk_id == 1));
    }
}
