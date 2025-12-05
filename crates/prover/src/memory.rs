//! Memory consistency argument using LogUp.
//!
//! This module implements memory checking for RISC-V execution traces
//! using the LogUp lookup argument. It ensures that:
//!
//! 1. Every memory read returns the value of the most recent write
//! 2. Memory operations are properly ordered by timestamps
//! 3. Initial memory state is respected (zero-initialized or from ELF segments)
//!
//! # Protocol Overview
//!
//! Memory consistency is proven using a permutation argument:
//! 1. **Original Trace**: Memory accesses in execution order
//! 2. **Sorted Trace**: Same accesses sorted by (address, timestamp)
//! 3. **Permutation Check**: Prove original and sorted are permutations via LogUp
//! 4. **Consistency Check**: In sorted order, reads must match preceding writes
//!
//! The key insight is that if we can prove the traces are permutations AND
//! the sorted trace satisfies consistency constraints, then the original
//! trace must also be consistent.

use std::collections::HashMap;
use zp1_primitives::{M31, QM31};

// ============================================================================
// Memory Operation Types
// ============================================================================

/// Memory operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryOp {
    /// Read from memory
    Read,
    /// Write to memory
    Write,
    /// No operation (padding)
    Noop,
}

impl MemoryOp {
    /// Convert to field element for constraints.
    /// Using distinct values: Read=0, Write=1, Noop=2
    pub fn to_field(&self) -> M31 {
        match self {
            MemoryOp::Read => M31::ZERO,
            MemoryOp::Write => M31::ONE,
            MemoryOp::Noop => M31::new(2),
        }
    }

    /// Check if this is a write operation.
    pub fn is_write(&self) -> bool {
        matches!(self, MemoryOp::Write)
    }

    /// Check if this is a read operation.
    pub fn is_read(&self) -> bool {
        matches!(self, MemoryOp::Read)
    }
}

// ============================================================================
// Memory Access
// ============================================================================

/// A single memory access in the execution trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    /// Memory address
    pub address: u32,
    /// Value read or written
    pub value: u32,
    /// Timestamp (cycle number) - must be unique and increasing
    pub timestamp: u32,
    /// Operation type
    pub op: MemoryOp,
}

impl MemoryAccess {
    /// Create a new memory access.
    pub fn new(address: u32, value: u32, timestamp: u32, op: MemoryOp) -> Self {
        Self {
            address,
            value,
            timestamp,
            op,
        }
    }

    /// Create a read access.
    pub fn read(address: u32, value: u32, timestamp: u32) -> Self {
        Self::new(address, value, timestamp, MemoryOp::Read)
    }

    /// Create a write access.
    pub fn write(address: u32, value: u32, timestamp: u32) -> Self {
        Self::new(address, value, timestamp, MemoryOp::Write)
    }

    /// Create a noop (padding).
    pub fn noop(timestamp: u32) -> Self {
        Self::new(0, 0, timestamp, MemoryOp::Noop)
    }

    /// Compute fingerprint for LogUp argument.
    /// Fingerprint = α³·addr + α²·value + α·timestamp + op + β
    pub fn fingerprint(&self, alpha: QM31, beta: QM31) -> QM31 {
        let alpha2 = alpha * alpha;
        let alpha3 = alpha2 * alpha;

        let addr = QM31::from(M31::new(self.address));
        let value = QM31::from(M31::new(self.value));
        let ts = QM31::from(M31::new(self.timestamp));
        let op = QM31::from(self.op.to_field());

        alpha3 * addr + alpha2 * value + alpha * ts + op + beta
    }
}

// ============================================================================
// Memory Consistency Prover
// ============================================================================

/// Memory consistency prover using LogUp permutation argument.
///
/// The protocol:
/// 1. Record all memory accesses in execution order
/// 2. Sort by (address, timestamp) to group related accesses
/// 3. Verify consistency in sorted order:
///    - First access to address must be write OR value must be initial value
///    - Reads must return value of most recent write
/// 4. Generate permutation proof via LogUp
pub struct MemoryConsistencyProver {
    /// Original memory accesses in execution order
    accesses: Vec<MemoryAccess>,
    /// Initial memory state (from ELF segments, etc.)
    initial_state: HashMap<u32, u32>,
    /// LogUp random challenge α
    alpha: QM31,
    /// LogUp batch challenge β
    beta: QM31,
}

impl MemoryConsistencyProver {
    /// Create a new memory consistency prover.
    pub fn new(accesses: Vec<MemoryAccess>) -> Self {
        Self {
            accesses,
            initial_state: HashMap::new(),
            alpha: QM31::ZERO,
            beta: QM31::ZERO,
        }
    }

    /// Create with initial memory state (e.g., from ELF loading).
    pub fn with_initial_state(
        accesses: Vec<MemoryAccess>,
        initial_state: HashMap<u32, u32>,
    ) -> Self {
        Self {
            accesses,
            initial_state,
            alpha: QM31::ZERO,
            beta: QM31::ZERO,
        }
    }

    /// Set the random challenges for LogUp.
    pub fn set_challenges(&mut self, alpha: QM31, beta: QM31) {
        self.alpha = alpha;
        self.beta = beta;
    }

    /// Get initial value for an address (0 if not in initial state).
    fn initial_value(&self, address: u32) -> u32 {
        *self.initial_state.get(&address).unwrap_or(&0)
    }

    /// Sort accesses by (address, timestamp) for memory checking.
    pub fn sorted_accesses(&self) -> Vec<MemoryAccess> {
        let mut sorted = self.accesses.clone();
        sorted.sort_by_key(|a| (a.address, a.timestamp));
        sorted
    }

    /// Verify memory consistency constraints.
    ///
    /// For sorted accesses, check:
    /// 1. First access to address: if read, value must equal initial value
    /// 2. Subsequent accesses: if read, value must equal previous value
    /// 3. Timestamps must be strictly increasing within same address
    pub fn verify_consistency(&self) -> Result<(), MemoryError> {
        let sorted = self.sorted_accesses();

        if sorted.is_empty() {
            return Ok(());
        }

        let mut prev_addr: Option<u32> = None;
        let mut prev_value: u32 = 0;
        let mut prev_ts: u32 = 0;

        for (i, access) in sorted.iter().enumerate() {
            let is_new_address = prev_addr != Some(access.address);

            if is_new_address {
                // First access to this address
                prev_value = self.initial_value(access.address);

                if access.op.is_read() && access.value != prev_value {
                    return Err(MemoryError::InvalidInitialRead {
                        address: access.address,
                        expected: prev_value,
                        actual: access.value,
                        timestamp: access.timestamp,
                    });
                }
            } else {
                // Same address - check timestamp ordering
                if access.timestamp <= prev_ts {
                    return Err(MemoryError::TimestampOrder {
                        address: access.address,
                        prev_ts,
                        curr_ts: access.timestamp,
                        row: i,
                    });
                }

                // If read, must match previous value
                if access.op.is_read() && access.value != prev_value {
                    return Err(MemoryError::ReadMismatch {
                        address: access.address,
                        expected: prev_value,
                        actual: access.value,
                        timestamp: access.timestamp,
                        row: i,
                    });
                }
            }

            // Update state
            prev_addr = Some(access.address);
            prev_ts = access.timestamp;
            if access.op.is_write() {
                prev_value = access.value;
            }
        }

        Ok(())
    }

    /// Generate the memory argument columns for STARK proving.
    ///
    /// Returns columns for both original and sorted traces, plus
    /// the LogUp running product columns.
    pub fn generate_columns(&self) -> MemoryColumns {
        let n = self.accesses.len();
        let sorted = self.sorted_accesses();

        // Original order columns
        let mut orig_addr = Vec::with_capacity(n);
        let mut orig_value = Vec::with_capacity(n);
        let mut orig_ts = Vec::with_capacity(n);
        let mut orig_op = Vec::with_capacity(n);

        // Sorted order columns
        let mut sorted_addr = Vec::with_capacity(n);
        let mut sorted_value = Vec::with_capacity(n);
        let mut sorted_ts = Vec::with_capacity(n);
        let mut sorted_op = Vec::with_capacity(n);

        for access in &self.accesses {
            orig_addr.push(M31::new(access.address));
            orig_value.push(M31::new(access.value));
            orig_ts.push(M31::new(access.timestamp));
            orig_op.push(access.op.to_field());
        }

        for access in &sorted {
            sorted_addr.push(M31::new(access.address));
            sorted_value.push(M31::new(access.value));
            sorted_ts.push(M31::new(access.timestamp));
            sorted_op.push(access.op.to_field());
        }

        // Compute LogUp permutation columns
        let (running_product, inverse_acc) =
            self.compute_permutation_columns(&self.accesses, &sorted);

        // Compute consistency selector columns
        let (same_addr_selector, is_read_selector) = self.compute_selector_columns(&sorted);

        MemoryColumns {
            // Original trace
            original_address: orig_addr,
            original_value: orig_value,
            original_timestamp: orig_ts,
            original_op: orig_op,
            // Sorted trace
            sorted_address: sorted_addr,
            sorted_value: sorted_value,
            sorted_timestamp: sorted_ts,
            sorted_op: sorted_op,
            // LogUp columns
            running_product,
            inverse_accumulator: inverse_acc,
            // Selector columns
            same_address_selector: same_addr_selector,
            is_read_selector,
        }
    }

    /// Compute LogUp permutation columns.
    ///
    /// For permutation argument, we need:
    /// - Running product of (fingerprint_orig + β) / (fingerprint_sorted + β)
    /// - Final product should equal 1
    fn compute_permutation_columns(
        &self,
        original: &[MemoryAccess],
        sorted: &[MemoryAccess],
    ) -> (Vec<QM31>, Vec<QM31>) {
        let n = original.len();
        if n == 0 {
            return (vec![], vec![]);
        }

        // Running product: z[i+1] = z[i] * (orig_fp[i]) / (sorted_fp[i])
        let mut running_product = vec![QM31::ONE; n];
        let mut inverse_acc = vec![QM31::ONE; n];

        let mut cumulative_orig = QM31::ONE;
        let mut cumulative_sorted = QM31::ONE;

        for i in 0..n {
            let orig_fp = original[i].fingerprint(self.alpha, self.beta);
            let sorted_fp = sorted[i].fingerprint(self.alpha, self.beta);

            cumulative_orig = cumulative_orig * orig_fp;
            cumulative_sorted = cumulative_sorted * sorted_fp;

            running_product[i] = cumulative_orig;
            inverse_acc[i] = cumulative_sorted;
        }

        (running_product, inverse_acc)
    }

    /// Compute selector columns for consistency constraints.
    fn compute_selector_columns(&self, sorted: &[MemoryAccess]) -> (Vec<M31>, Vec<M31>) {
        let n = sorted.len();
        let mut same_addr = vec![M31::ZERO; n];
        let mut is_read = vec![M31::ZERO; n];

        for i in 0..n {
            if sorted[i].op.is_read() {
                is_read[i] = M31::ONE;
            }

            if i > 0 && sorted[i].address == sorted[i - 1].address {
                same_addr[i] = M31::ONE;
            }
        }

        (same_addr, is_read)
    }

    /// Verify the permutation argument.
    ///
    /// Returns true if the final running products are equal.
    pub fn verify_permutation(&self) -> bool {
        let (running_product, inverse_acc) =
            self.compute_permutation_columns(&self.accesses, &self.sorted_accesses());

        if running_product.is_empty() {
            return true;
        }

        let n = running_product.len();
        running_product[n - 1] == inverse_acc[n - 1]
    }

    /// Generate a complete memory consistency proof.
    pub fn prove(&self) -> Result<MemoryProof, MemoryError> {
        // First verify consistency
        self.verify_consistency()?;

        // Generate columns
        let columns = self.generate_columns();

        // Verify permutation
        if !self.verify_permutation() {
            return Err(MemoryError::PermutationFailed);
        }

        Ok(MemoryProof {
            num_accesses: self.accesses.len(),
            columns,
            alpha: self.alpha,
            beta: self.beta,
        })
    }
}

// ============================================================================
// Memory Columns
// ============================================================================

/// Generated memory argument columns for STARK.
#[derive(Debug, Clone)]
pub struct MemoryColumns {
    // Original trace (execution order)
    pub original_address: Vec<M31>,
    pub original_value: Vec<M31>,
    pub original_timestamp: Vec<M31>,
    pub original_op: Vec<M31>,

    // Sorted trace (by address, then timestamp)
    pub sorted_address: Vec<M31>,
    pub sorted_value: Vec<M31>,
    pub sorted_timestamp: Vec<M31>,
    pub sorted_op: Vec<M31>,

    // LogUp permutation columns
    /// Running product of original fingerprints
    pub running_product: Vec<QM31>,
    /// Running product of sorted fingerprints (inverse accumulator)
    pub inverse_accumulator: Vec<QM31>,

    // Selector columns for consistency constraints
    /// 1 if same address as previous row, 0 otherwise
    pub same_address_selector: Vec<M31>,
    /// 1 if operation is read, 0 otherwise
    pub is_read_selector: Vec<M31>,
}

// ============================================================================
// Memory Proof
// ============================================================================

/// Complete memory consistency proof.
#[derive(Debug, Clone)]
pub struct MemoryProof {
    /// Number of memory accesses
    pub num_accesses: usize,
    /// All proof columns
    pub columns: MemoryColumns,
    /// LogUp challenge α
    pub alpha: QM31,
    /// LogUp challenge β
    pub beta: QM31,
}

// ============================================================================
// Memory Errors
// ============================================================================

/// Memory consistency error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryError {
    /// Timestamps not strictly increasing within address
    TimestampOrder {
        address: u32,
        prev_ts: u32,
        curr_ts: u32,
        row: usize,
    },
    /// Read value doesn't match previous write
    ReadMismatch {
        address: u32,
        expected: u32,
        actual: u32,
        timestamp: u32,
        row: usize,
    },
    /// First read to address has wrong initial value
    InvalidInitialRead {
        address: u32,
        expected: u32,
        actual: u32,
        timestamp: u32,
    },
    /// Permutation argument failed
    PermutationFailed,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryError::TimestampOrder {
                address,
                prev_ts,
                curr_ts,
                row,
            } => {
                write!(
                    f,
                    "Timestamp order violation at address {:#x} row {}: {} -> {}",
                    address, row, prev_ts, curr_ts
                )
            }
            MemoryError::ReadMismatch {
                address,
                expected,
                actual,
                timestamp,
                row,
            } => {
                write!(
                    f,
                    "Read mismatch at {:#x} ts {} row {}: expected {}, got {}",
                    address, timestamp, row, expected, actual
                )
            }
            MemoryError::InvalidInitialRead {
                address,
                expected,
                actual,
                timestamp,
            } => {
                write!(
                    f,
                    "Invalid initial read at {:#x} ts {}: expected {}, got {}",
                    address, timestamp, expected, actual
                )
            }
            MemoryError::PermutationFailed => {
                write!(f, "Permutation argument verification failed")
            }
        }
    }
}

impl std::error::Error for MemoryError {}

// ============================================================================
// Memory AIR Constraints
// ============================================================================

/// AIR constraints for memory consistency.
///
/// These constraints are evaluated at each row of the trace:
/// 1. **Permutation Constraint**: Original and sorted traces are permutations
/// 2. **Consistency Constraint**: Reads in sorted trace see correct values
/// 3. **Timestamp Constraint**: Timestamps strictly increase within address
pub struct MemoryAirConstraints {
    /// Alpha challenge for fingerprints
    pub alpha: QM31,
    /// Beta challenge for LogUp
    pub beta: QM31,
}

impl MemoryAirConstraints {
    /// Create new memory AIR constraints.
    pub fn new(alpha: QM31, beta: QM31) -> Self {
        Self { alpha, beta }
    }

    /// Compute fingerprint for a memory tuple.
    pub fn fingerprint(&self, address: M31, value: M31, timestamp: M31, op: M31) -> QM31 {
        let addr = QM31::from(address);
        let val = QM31::from(value);
        let ts = QM31::from(timestamp);
        let op_qm = QM31::from(op);

        let alpha2 = self.alpha * self.alpha;
        let alpha3 = alpha2 * self.alpha;

        alpha3 * addr + alpha2 * val + self.alpha * ts + op_qm + self.beta
    }

    /// Evaluate the permutation constraint.
    ///
    /// Verifies: z[i+1] * sorted_fp[i] = z[i] * orig_fp[i]
    /// Where z is the running product column.
    pub fn permutation_constraint(
        &self,
        orig_fp: QM31,
        sorted_fp: QM31,
        z_curr: QM31,
        z_next: QM31,
    ) -> QM31 {
        z_next * sorted_fp - z_curr * orig_fp
    }

    /// Evaluate the memory consistency constraint.
    ///
    /// In sorted trace: if same_addr AND is_read, then value_curr = value_prev
    ///
    /// Constraint: same_addr * is_read * (value_curr - value_prev) = 0
    pub fn consistency_constraint(
        &self,
        same_addr: M31,    // 1 if same address as previous
        is_read: M31,      // 1 if current op is read
        value_curr: M31,   // current value
        value_prev: M31,   // previous value
    ) -> M31 {
        // same_addr * is_read * (value_curr - value_prev) should be 0
        let value_diff = value_curr - value_prev;
        same_addr * is_read * value_diff
    }

    /// Evaluate the timestamp ordering constraint.
    ///
    /// In sorted trace: if same_addr, then ts_curr > ts_prev
    /// We check: same_addr * (ts_prev - ts_curr + 1) * inverse = same_addr
    /// where inverse proves ts_curr - ts_prev - 1 >= 0
    ///
    /// Simplified: just check ts_curr - ts_prev is positive when same_addr=1
    pub fn timestamp_constraint(
        &self,
        same_addr: M31,
        ts_curr: M31,
        ts_prev: M31,
    ) -> M31 {
        // When same_addr=1, we need ts_curr > ts_prev
        // This is typically proven via range check, but here we return the difference
        // A full implementation would use a range check argument
        let diff = ts_curr - ts_prev;
        // For now, return 0 if valid (diff > 0 when same_addr=1)
        // In practice, this needs proper range check machinery
        same_addr * (diff - M31::ONE) // Should be non-negative
    }

    /// Boundary constraint: first running product should be 1.
    pub fn boundary_constraint_start(z_first: QM31) -> QM31 {
        z_first - QM31::ONE
    }

    /// Boundary constraint: final products should match.
    pub fn boundary_constraint_end(z_final: QM31, inverse_final: QM31) -> QM31 {
        z_final - inverse_final
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_access_creation() {
        let read = MemoryAccess::read(0x1000, 42, 5);
        assert_eq!(read.address, 0x1000);
        assert_eq!(read.value, 42);
        assert_eq!(read.timestamp, 5);
        assert!(read.op.is_read());

        let write = MemoryAccess::write(0x2000, 100, 10);
        assert!(write.op.is_write());

        let noop = MemoryAccess::noop(15);
        assert_eq!(noop.op, MemoryOp::Noop);
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let alpha = QM31::from(M31::new(5));
        let beta = QM31::from(M31::new(7));

        let access = MemoryAccess::write(0x1000, 42, 100);
        let fp1 = access.fingerprint(alpha, beta);
        let fp2 = access.fingerprint(alpha, beta);
        assert_eq!(fp1, fp2);

        // Different access should have different fingerprint
        let access2 = MemoryAccess::write(0x1000, 43, 100);
        let fp3 = access2.fingerprint(alpha, beta);
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_sorted_accesses() {
        let accesses = vec![
            MemoryAccess::write(0x2000, 10, 1),
            MemoryAccess::write(0x1000, 5, 2),
            MemoryAccess::read(0x1000, 5, 3),
            MemoryAccess::read(0x2000, 10, 4),
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        let sorted = prover.sorted_accesses();

        // Should be sorted by (address, timestamp)
        assert_eq!(sorted[0].address, 0x1000);
        assert_eq!(sorted[0].timestamp, 2);
        assert_eq!(sorted[1].address, 0x1000);
        assert_eq!(sorted[1].timestamp, 3);
        assert_eq!(sorted[2].address, 0x2000);
        assert_eq!(sorted[2].timestamp, 1);
        assert_eq!(sorted[3].address, 0x2000);
        assert_eq!(sorted[3].timestamp, 4);
    }

    #[test]
    fn test_valid_memory_trace() {
        let accesses = vec![
            MemoryAccess::write(0x1000, 42, 1),
            MemoryAccess::read(0x1000, 42, 2),
            MemoryAccess::write(0x1000, 100, 3),
            MemoryAccess::read(0x1000, 100, 4),
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        assert!(prover.verify_consistency().is_ok());
    }

    #[test]
    fn test_invalid_read_value() {
        let accesses = vec![
            MemoryAccess::write(0x1000, 42, 1),
            MemoryAccess::read(0x1000, 99, 2), // Wrong value!
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        let result = prover.verify_consistency();
        assert!(result.is_err());

        if let Err(MemoryError::ReadMismatch {
            expected, actual, ..
        }) = result
        {
            assert_eq!(expected, 42);
            assert_eq!(actual, 99);
        } else {
            panic!("Expected ReadMismatch error");
        }
    }

    #[test]
    fn test_read_before_write_zero_init() {
        // Reading from unwritten address should return 0 (zero-initialized memory)
        let accesses = vec![
            MemoryAccess::read(0x1000, 0, 1), // Read 0 from unwritten
            MemoryAccess::write(0x1000, 42, 2),
            MemoryAccess::read(0x1000, 42, 3),
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        assert!(prover.verify_consistency().is_ok());
    }

    #[test]
    fn test_read_before_write_nonzero_fails() {
        // Reading non-zero from unwritten address should fail
        let accesses = vec![
            MemoryAccess::read(0x1000, 42, 1), // Wrong! Should be 0
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        let result = prover.verify_consistency();
        assert!(result.is_err());
    }

    #[test]
    fn test_initial_state() {
        // With initial state, reads should match
        let accesses = vec![
            MemoryAccess::read(0x1000, 42, 1), // Reads initial value
        ];

        let mut initial = HashMap::new();
        initial.insert(0x1000, 42);

        let prover = MemoryConsistencyProver::with_initial_state(accesses, initial);
        assert!(prover.verify_consistency().is_ok());
    }

    #[test]
    fn test_timestamp_order_violation() {
        // Same timestamp for same address is a violation (not strictly increasing)
        let accesses = vec![
            MemoryAccess::write(0x1000, 42, 10),
            MemoryAccess::read(0x1000, 42, 10), // Same timestamp!
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        let result = prover.verify_consistency();
        assert!(result.is_err());

        if let Err(MemoryError::TimestampOrder { prev_ts, curr_ts, .. }) = result {
            assert_eq!(prev_ts, 10);
            assert_eq!(curr_ts, 10);
        } else {
            panic!("Expected TimestampOrder error");
        }
    }

    #[test]
    fn test_permutation_verification() {
        let accesses = vec![
            MemoryAccess::write(0x1000, 42, 1),
            MemoryAccess::read(0x1000, 42, 2),
            MemoryAccess::write(0x2000, 100, 3),
            MemoryAccess::read(0x2000, 100, 4),
        ];

        let mut prover = MemoryConsistencyProver::new(accesses);
        prover.set_challenges(QM31::from(M31::new(5)), QM31::from(M31::new(7)));

        assert!(prover.verify_permutation());
    }

    #[test]
    fn test_generate_columns() {
        let accesses = vec![
            MemoryAccess::write(0x1000, 42, 1),
            MemoryAccess::read(0x1000, 42, 2),
        ];

        let mut prover = MemoryConsistencyProver::new(accesses);
        prover.set_challenges(QM31::from(M31::new(5)), QM31::from(M31::new(7)));

        let columns = prover.generate_columns();

        assert_eq!(columns.original_address.len(), 2);
        assert_eq!(columns.sorted_address.len(), 2);
        assert_eq!(columns.running_product.len(), 2);
        assert_eq!(columns.same_address_selector.len(), 2);

        // Second row in sorted should have same_addr=1
        assert_eq!(columns.same_address_selector[0], M31::ZERO);
        assert_eq!(columns.same_address_selector[1], M31::ONE);
    }

    #[test]
    fn test_multiple_addresses() {
        let accesses = vec![
            MemoryAccess::write(0x1000, 10, 1),
            MemoryAccess::write(0x2000, 20, 2),
            MemoryAccess::read(0x1000, 10, 3),
            MemoryAccess::write(0x1000, 15, 4),
            MemoryAccess::read(0x2000, 20, 5),
            MemoryAccess::read(0x1000, 15, 6),
        ];

        let prover = MemoryConsistencyProver::new(accesses);
        assert!(prover.verify_consistency().is_ok());
    }

    #[test]
    fn test_full_proof_generation() {
        let accesses = vec![
            MemoryAccess::write(0x1000, 42, 1),
            MemoryAccess::read(0x1000, 42, 2),
            MemoryAccess::write(0x1000, 100, 3),
            MemoryAccess::read(0x1000, 100, 4),
        ];

        let mut prover = MemoryConsistencyProver::new(accesses);
        prover.set_challenges(QM31::from(M31::new(123)), QM31::from(M31::new(456)));

        let proof = prover.prove();
        assert!(proof.is_ok());

        let proof = proof.unwrap();
        assert_eq!(proof.num_accesses, 4);
    }

    #[test]
    fn test_air_constraints_fingerprint() {
        let constraints = MemoryAirConstraints::new(
            QM31::from(M31::new(5)),
            QM31::from(M31::new(7)),
        );

        let fp = constraints.fingerprint(
            M31::new(0x1000),
            M31::new(42),
            M31::new(1),
            M31::ONE,
        );

        // Fingerprint should be non-zero
        assert_ne!(fp, QM31::ZERO);

        // Same inputs should give same fingerprint
        let fp2 = constraints.fingerprint(
            M31::new(0x1000),
            M31::new(42),
            M31::new(1),
            M31::ONE,
        );
        assert_eq!(fp, fp2);
    }

    #[test]
    fn test_consistency_constraint_satisfied() {
        let constraints = MemoryAirConstraints::new(
            QM31::from(M31::new(5)),
            QM31::from(M31::new(7)),
        );

        // Same address, read, same value -> should be 0
        let result = constraints.consistency_constraint(
            M31::ONE,           // same_addr = 1
            M31::ONE,           // is_read = 1
            M31::new(42),       // value_curr
            M31::new(42),       // value_prev (same)
        );
        assert_eq!(result, M31::ZERO);
    }

    #[test]
    fn test_consistency_constraint_write_ok() {
        let constraints = MemoryAirConstraints::new(
            QM31::from(M31::new(5)),
            QM31::from(M31::new(7)),
        );

        // Same address, write, different value -> should be 0 (write can change)
        let result = constraints.consistency_constraint(
            M31::ONE,           // same_addr = 1
            M31::ZERO,          // is_read = 0 (it's a write)
            M31::new(100),      // value_curr
            M31::new(42),       // value_prev (different)
        );
        assert_eq!(result, M31::ZERO);
    }

    #[test]
    fn test_consistency_constraint_different_addr() {
        let constraints = MemoryAirConstraints::new(
            QM31::from(M31::new(5)),
            QM31::from(M31::new(7)),
        );

        // Different address -> constraint doesn't apply
        let result = constraints.consistency_constraint(
            M31::ZERO,          // same_addr = 0
            M31::ONE,           // is_read = 1
            M31::new(100),      // value_curr
            M31::new(42),       // value_prev (different but OK)
        );
        assert_eq!(result, M31::ZERO);
    }

    #[test]
    fn test_consistency_constraint_violated() {
        let constraints = MemoryAirConstraints::new(
            QM31::from(M31::new(5)),
            QM31::from(M31::new(7)),
        );

        // Same address, read, different value -> should be non-zero (violation)
        let result = constraints.consistency_constraint(
            M31::ONE,           // same_addr = 1
            M31::ONE,           // is_read = 1
            M31::new(100),      // value_curr
            M31::new(42),       // value_prev (different!)
        );
        assert_ne!(result, M31::ZERO);
    }

    #[test]
    fn test_empty_trace() {
        let prover = MemoryConsistencyProver::new(vec![]);
        assert!(prover.verify_consistency().is_ok());
        assert!(prover.verify_permutation());
    }

    #[test]
    fn test_single_write() {
        let accesses = vec![MemoryAccess::write(0x1000, 42, 1)];

        let prover = MemoryConsistencyProver::new(accesses);
        assert!(prover.verify_consistency().is_ok());
    }
}
