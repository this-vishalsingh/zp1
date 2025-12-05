//! LogUp lookup argument implementation.
//!
//! LogUp (Logarithmic Derivative Lookup) is a lookup argument based on
//! the logarithmic derivative of characteristic polynomials. It proves
//! that a multiset of lookup values is contained in a lookup table.
//!
//! # Mathematical Foundation
//!
//! Given:
//! - Table T = {t₁, t₂, ..., tₙ} with multiplicities {m₁, m₂, ..., mₙ}
//! - Lookups L = {l₁, l₂, ..., lₖ}
//!
//! The LogUp identity states that for a random challenge α:
//!
//! ∑ᵢ 1/(α - lᵢ) = ∑ⱼ mⱼ/(α - tⱼ)
//!
//! This is because both sides equal the logarithmic derivative of:
//! ∏ᵢ (α - lᵢ) / ∏ⱼ (α - tⱼ)^mⱼ
//!
//! # Protocol
//!
//! 1. Prover commits to the lookup values and table multiplicities
//! 2. Verifier sends random challenge α
//! 3. Prover computes auxiliary columns containing 1/(α - v) terms
//! 4. Prover shows that the running sum equals zero
//!
//! # Usage
//!
//! ```ignore
//! use zp1_prover::logup::{LogUpProver, LookupTable};
//! use zp1_primitives::{M31, QM31};
//!
//! // Create table and record lookups
//! let mut table = LookupTable::new(vec![M31::new(0), M31::new(1), M31::new(2)]);
//! let lookups = vec![M31::new(1), M31::new(0), M31::new(1)];
//! for &v in &lookups { table.lookup(v); }
//!
//! // Generate LogUp proof
//! let alpha = QM31::from_base(M31::new(12345));
//! let prover = LogUpProver::new(alpha);
//! let proof = prover.prove_lookup(&lookups, &table);
//! assert!(proof.verify());
//! ```
//!
//! # References
//!
//! - [LogUp Paper](https://eprint.iacr.org/2022/1530)
//! - [Plookup](https://eprint.iacr.org/2020/315)

use std::collections::HashMap;
use zp1_primitives::{M31, QM31};

// ============================================================================
// Lookup Table
// ============================================================================

/// A lookup table with multiplicity tracking.
///
/// The table stores a set of values that can be looked up. Each lookup
/// increments the multiplicity count for that value.
#[derive(Clone, Debug)]
pub struct LookupTable {
    /// The values in the table.
    values: Vec<M31>,
    /// Multiplicities (how many times each value is looked up).
    multiplicities: Vec<u32>,
    /// Index for O(1) lookups.
    index: HashMap<u32, usize>,
}

impl LookupTable {
    /// Create a new lookup table from values.
    pub fn new(values: Vec<M31>) -> Self {
        let mut index = HashMap::with_capacity(values.len());
        for (i, &v) in values.iter().enumerate() {
            index.insert(v.as_u32(), i);
        }
        let len = values.len();
        Self {
            values,
            multiplicities: vec![0; len],
            index,
        }
    }

    /// Create a range check table for values in [0, 2^bits).
    pub fn range_table(bits: usize) -> Self {
        assert!(bits <= 24, "Range table too large");
        let size = 1 << bits;
        let values = (0..size).map(|i| M31::new(i as u32)).collect();
        Self::new(values)
    }

    /// Create a table from explicit (value, multiplicity) pairs.
    pub fn with_multiplicities(entries: Vec<(M31, u32)>) -> Self {
        let mut index = HashMap::with_capacity(entries.len());
        let mut values = Vec::with_capacity(entries.len());
        let mut multiplicities = Vec::with_capacity(entries.len());
        
        for (i, (v, m)) in entries.into_iter().enumerate() {
            index.insert(v.as_u32(), i);
            values.push(v);
            multiplicities.push(m);
        }
        
        Self { values, multiplicities, index }
    }

    /// Record a lookup of value v, incrementing its multiplicity.
    /// Returns the index where v was found, or None if not in table.
    pub fn lookup(&mut self, v: M31) -> Option<usize> {
        if let Some(&idx) = self.index.get(&v.as_u32()) {
            self.multiplicities[idx] += 1;
            Some(idx)
        } else {
            None
        }
    }

    /// Record multiple lookups.
    pub fn lookup_all(&mut self, values: &[M31]) -> bool {
        for &v in values {
            if self.lookup(v).is_none() {
                return false;
            }
        }
        true
    }

    /// Get value at index.
    pub fn get(&self, index: usize) -> Option<M31> {
        self.values.get(index).copied()
    }

    /// Get multiplicity at index.
    pub fn multiplicity(&self, index: usize) -> u32 {
        self.multiplicities.get(index).copied().unwrap_or(0)
    }

    /// Get the table size.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if table is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get all values.
    pub fn values(&self) -> &[M31] {
        &self.values
    }

    /// Get all multiplicities.
    pub fn multiplicities(&self) -> &[u32] {
        &self.multiplicities
    }

    /// Reset all multiplicities to zero.
    pub fn reset(&mut self) {
        self.multiplicities.fill(0);
    }

    /// Check if value exists in table.
    pub fn contains(&self, v: M31) -> bool {
        self.index.contains_key(&v.as_u32())
    }

    /// Total count of all lookups (sum of multiplicities).
    pub fn total_lookups(&self) -> u64 {
        self.multiplicities.iter().map(|&m| m as u64).sum()
    }
}

// ============================================================================
// LogUp Accumulator
// ============================================================================

/// LogUp running sum accumulator.
///
/// Accumulates 1/(α - v) terms for the lookup argument.
/// The running sum column allows polynomial constraints to verify
/// the accumulation is correct.
#[derive(Clone, Debug)]
pub struct LogUpAccumulator {
    /// The random challenge α.
    alpha: QM31,
    /// Running sum at each step.
    running_sum: Vec<QM31>,
    /// Individual inverse terms (for debugging/verification).
    terms: Vec<QM31>,
}

impl LogUpAccumulator {
    /// Create a new accumulator with the given challenge.
    pub fn new(alpha: QM31) -> Self {
        Self {
            alpha,
            running_sum: vec![QM31::ZERO], // Start with 0
            terms: Vec::new(),
        }
    }

    /// Add a lookup value: accumulate +1/(α - v).
    pub fn add(&mut self, v: M31) {
        let v_ext = QM31::from_base(v);
        let diff = self.alpha - v_ext;
        
        // Handle case where v = α (shouldn't happen with good challenges)
        if diff == QM31::ZERO {
            panic!("LogUp: lookup value equals challenge");
        }
        
        let inv = diff.inv();
        let prev = *self.running_sum.last().unwrap();
        self.running_sum.push(prev + inv);
        self.terms.push(inv);
    }

    /// Subtract a multiplicity-weighted table entry: accumulate -m/(α - v).
    pub fn sub_weighted(&mut self, v: M31, multiplicity: u32) {
        if multiplicity == 0 {
            // No contribution, but we still need a running sum entry
            let prev = *self.running_sum.last().unwrap();
            self.running_sum.push(prev);
            self.terms.push(QM31::ZERO);
            return;
        }
        
        let v_ext = QM31::from_base(v);
        let diff = self.alpha - v_ext;
        
        if diff == QM31::ZERO {
            panic!("LogUp: table value equals challenge");
        }
        
        let inv = diff.inv();
        let mult = QM31::from_base(M31::new(multiplicity));
        let term = mult * inv;
        
        let prev = *self.running_sum.last().unwrap();
        self.running_sum.push(prev - term);
        self.terms.push(term);
    }

    /// Get the final sum value.
    pub fn final_sum(&self) -> QM31 {
        *self.running_sum.last().unwrap_or(&QM31::ZERO)
    }

    /// Get the running sum column (for trace).
    pub fn running_sum_column(&self) -> &[QM31] {
        &self.running_sum
    }

    /// Get the individual terms.
    pub fn terms(&self) -> &[QM31] {
        &self.terms
    }

    /// Verify that the final sum is zero.
    pub fn verify(&self) -> bool {
        self.final_sum() == QM31::ZERO
    }
}

// ============================================================================
// LogUp Proof
// ============================================================================

/// Complete LogUp proof data.
#[derive(Clone, Debug)]
pub struct LogUpProof {
    /// Running sum column for lookups.
    pub lookup_running_sum: Vec<QM31>,
    /// Running sum column for table.
    pub table_running_sum: Vec<QM31>,
    /// Individual lookup terms.
    pub lookup_terms: Vec<QM31>,
    /// Individual table terms.
    pub table_terms: Vec<QM31>,
    /// Final sum (should be zero for valid proof).
    pub final_sum: QM31,
}

impl LogUpProof {
    /// Verify that the LogUp argument is satisfied.
    pub fn verify(&self) -> bool {
        self.final_sum == QM31::ZERO
    }

    /// Get the degree of the lookup polynomial.
    pub fn lookup_degree(&self) -> usize {
        self.lookup_terms.len()
    }

    /// Get the degree of the table polynomial.
    pub fn table_degree(&self) -> usize {
        self.table_terms.len()
    }
}

// ============================================================================
// LogUp Prover
// ============================================================================

/// LogUp lookup prover.
///
/// Generates the auxiliary columns needed to prove a LogUp argument.
#[derive(Clone, Debug)]
pub struct LogUpProver {
    /// The random challenge α.
    alpha: QM31,
}

impl LogUpProver {
    /// Create a new LogUp prover with the given challenge.
    pub fn new(alpha: QM31) -> Self {
        Self { alpha }
    }

    /// Prove that all lookup values exist in the table.
    ///
    /// The LogUp identity:
    /// ∑ᵢ 1/(α - lᵢ) = ∑ⱼ mⱼ/(α - tⱼ)
    pub fn prove_lookup(&self, lookups: &[M31], table: &LookupTable) -> LogUpProof {
        let mut lookup_acc = LogUpAccumulator::new(self.alpha);
        let mut table_acc = LogUpAccumulator::new(self.alpha);

        // Accumulate lookup terms: ∑ 1/(α - lᵢ)
        for &v in lookups {
            lookup_acc.add(v);
        }

        // Accumulate table terms: ∑ mⱼ/(α - tⱼ)
        for (i, &t) in table.values().iter().enumerate() {
            table_acc.sub_weighted(t, table.multiplicity(i));
        }

        // Final sum = lookup_sum - table_sum (should be zero)
        let final_sum = lookup_acc.final_sum() + table_acc.final_sum();

        LogUpProof {
            lookup_running_sum: lookup_acc.running_sum_column().to_vec(),
            table_running_sum: table_acc.running_sum_column().to_vec(),
            lookup_terms: lookup_acc.terms().to_vec(),
            table_terms: table_acc.terms().to_vec(),
            final_sum,
        }
    }

    /// Generate columns for the LogUp argument (legacy interface).
    pub fn generate_columns(
        &self,
        lookups: &[M31],
        table: &LookupTable,
    ) -> (Vec<QM31>, Vec<QM31>, QM31) {
        let proof = self.prove_lookup(lookups, table);
        (proof.lookup_terms, proof.table_terms, proof.final_sum)
    }
}

// ============================================================================
// Multi-Column LogUp
// ============================================================================

/// LogUp for multiple columns combined with random linear combination.
///
/// When looking up tuples (a, b, c, ...), we combine them:
/// combined = a + β·b + β²·c + ...
#[derive(Clone, Debug)]
pub struct MultiColumnLogUp {
    /// Challenge for inverse computation.
    alpha: QM31,
    /// Challenge for column combination.
    beta: QM31,
}

impl MultiColumnLogUp {
    /// Create multi-column LogUp with challenges.
    pub fn new(alpha: QM31, beta: QM31) -> Self {
        Self { alpha, beta }
    }

    /// Combine multiple columns into a single value.
    pub fn combine(&self, values: &[M31]) -> QM31 {
        let mut result = QM31::ZERO;
        let mut beta_power = QM31::ONE;
        
        for &v in values {
            result = result + QM31::from_base(v) * beta_power;
            beta_power = beta_power * self.beta;
        }
        
        result
    }

    /// Prove lookup for multi-column tuples.
    pub fn prove(
        &self,
        lookup_tuples: &[Vec<M31>],
        table_tuples: &[Vec<M31>],
        multiplicities: &[u32],
    ) -> LogUpProof {
        assert_eq!(table_tuples.len(), multiplicities.len());

        let mut lookup_acc = LogUpAccumulator::new(self.alpha);
        let mut table_acc = LogUpAccumulator::new(self.alpha);

        // Process lookups
        for tuple in lookup_tuples {
            let combined = self.combine(tuple);
            // Add as QM31 value
            let diff = self.alpha - combined;
            let inv = diff.inv();
            let prev = *lookup_acc.running_sum.last().unwrap();
            lookup_acc.running_sum.push(prev + inv);
            lookup_acc.terms.push(inv);
        }

        // Process table
        for (tuple, &mult) in table_tuples.iter().zip(multiplicities) {
            let combined = self.combine(tuple);
            if mult == 0 {
                let prev = *table_acc.running_sum.last().unwrap();
                table_acc.running_sum.push(prev);
                table_acc.terms.push(QM31::ZERO);
            } else {
                let diff = self.alpha - combined;
                let inv = diff.inv();
                let m = QM31::from_base(M31::new(mult));
                let term = m * inv;
                let prev = *table_acc.running_sum.last().unwrap();
                table_acc.running_sum.push(prev - term);
                table_acc.terms.push(term);
            }
        }

        let final_sum = lookup_acc.final_sum() + table_acc.final_sum();

        LogUpProof {
            lookup_running_sum: lookup_acc.running_sum_column().to_vec(),
            table_running_sum: table_acc.running_sum_column().to_vec(),
            lookup_terms: lookup_acc.terms().to_vec(),
            table_terms: table_acc.terms().to_vec(),
            final_sum,
        }
    }
}

// ============================================================================
// Range Check
// ============================================================================

/// Range check constraint generator using LogUp.
///
/// Proves that values are in the range [0, 2^bits).
#[derive(Clone, Debug)]
pub struct RangeCheck {
    /// Number of bits for the range.
    bits: usize,
    /// Lookup table.
    table: LookupTable,
}

impl RangeCheck {
    /// Create a new range check for b-bit values.
    pub fn new(bits: usize) -> Self {
        Self {
            bits,
            table: LookupTable::range_table(bits),
        }
    }

    /// Check if a value is in range and record the lookup.
    pub fn check(&mut self, value: M31) -> bool {
        let v = value.as_u32();
        if v >= (1 << self.bits) {
            return false;
        }
        self.table.lookup(value);
        true
    }

    /// Check multiple values.
    pub fn check_all(&mut self, values: &[M31]) -> bool {
        values.iter().all(|&v| self.check(v))
    }

    /// Get the number of bits.
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Get the table for LogUp proof generation.
    pub fn table(&self) -> &LookupTable {
        &self.table
    }

    /// Get mutable reference to table.
    pub fn table_mut(&mut self) -> &mut LookupTable {
        &mut self.table
    }

    /// Generate LogUp proof for the range checks.
    pub fn prove(&self, values: &[M31], alpha: QM31) -> LogUpProof {
        let prover = LogUpProver::new(alpha);
        prover.prove_lookup(values, &self.table)
    }
}

// ============================================================================
// Permutation Argument
// ============================================================================

/// Permutation argument using LogUp.
///
/// Proves that two lists A and B are permutations of each other.
/// The LogUp identity becomes:
/// ∑ᵢ 1/(α - aᵢ) = ∑ᵢ 1/(α - bᵢ)
#[derive(Clone, Debug)]
pub struct PermutationArgument {
    alpha: QM31,
}

impl PermutationArgument {
    /// Create a new permutation argument.
    pub fn new(alpha: QM31) -> Self {
        Self { alpha }
    }

    /// Prove that `a` and `b` are permutations of each other.
    pub fn prove(&self, a: &[M31], b: &[M31]) -> LogUpProof {
        assert_eq!(a.len(), b.len(), "Permutation lists must have equal length");

        let mut a_acc = LogUpAccumulator::new(self.alpha);
        let mut b_acc = LogUpAccumulator::new(self.alpha);

        // Accumulate 1/(α - aᵢ)
        for &v in a {
            a_acc.add(v);
        }

        // Accumulate 1/(α - bᵢ)
        for &v in b {
            b_acc.add(v);
        }

        // If a and b are permutations, the sums are equal
        let final_sum = a_acc.final_sum() - b_acc.final_sum();

        LogUpProof {
            lookup_running_sum: a_acc.running_sum_column().to_vec(),
            table_running_sum: b_acc.running_sum_column().to_vec(),
            lookup_terms: a_acc.terms().to_vec(),
            table_terms: b_acc.terms().to_vec(),
            final_sum,
        }
    }

    /// Verify a permutation proof.
    pub fn verify(proof: &LogUpProof) -> bool {
        proof.final_sum == QM31::ZERO
    }
}

// ============================================================================
// Memory Consistency (Address-Ordered)
// ============================================================================

/// Memory operation for consistency checking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryOp {
    /// Memory address.
    pub addr: M31,
    /// Value read/written.
    pub value: M31,
    /// Operation timestamp (for ordering).
    pub timestamp: u32,
    /// True if write, false if read.
    pub is_write: bool,
}

impl MemoryOp {
    /// Create a new memory operation.
    pub fn new(addr: M31, value: M31, timestamp: u32, is_write: bool) -> Self {
        Self { addr, value, timestamp, is_write }
    }

    /// Create a read operation.
    pub fn read(addr: M31, value: M31, timestamp: u32) -> Self {
        Self::new(addr, value, timestamp, false)
    }

    /// Create a write operation.
    pub fn write(addr: M31, value: M31, timestamp: u32) -> Self {
        Self::new(addr, value, timestamp, true)
    }
}

/// Memory consistency checker using LogUp.
///
/// Uses the "address-ordered" memory checking technique:
/// 1. Sort operations by (address, timestamp)
/// 2. Check that reads match the most recent write to that address
#[derive(Clone, Debug)]
pub struct MemoryConsistency {
    /// All memory operations.
    operations: Vec<MemoryOp>,
}

impl MemoryConsistency {
    /// Create a new memory consistency checker.
    pub fn new() -> Self {
        Self { operations: Vec::new() }
    }

    /// Add a memory operation.
    pub fn add_operation(&mut self, op: MemoryOp) {
        self.operations.push(op);
    }

    /// Add a read operation.
    pub fn read(&mut self, addr: M31, value: M31, timestamp: u32) {
        self.add_operation(MemoryOp::read(addr, value, timestamp));
    }

    /// Add a write operation.
    pub fn write(&mut self, addr: M31, value: M31, timestamp: u32) {
        self.add_operation(MemoryOp::write(addr, value, timestamp));
    }

    /// Check memory consistency and generate LogUp proof.
    ///
    /// Uses two challenges:
    /// - alpha: for LogUp inverse computation
    /// - beta: for combining (addr, value, timestamp) into single value
    pub fn prove(&self, alpha: QM31, beta: QM31) -> Result<LogUpProof, &'static str> {
        if self.operations.is_empty() {
            return Ok(LogUpProof {
                lookup_running_sum: vec![QM31::ZERO],
                table_running_sum: vec![QM31::ZERO],
                lookup_terms: vec![],
                table_terms: vec![],
                final_sum: QM31::ZERO,
            });
        }

        // Sort by (address, timestamp)
        let mut sorted = self.operations.clone();
        sorted.sort_by(|a, b| {
            match a.addr.as_u32().cmp(&b.addr.as_u32()) {
                std::cmp::Ordering::Equal => a.timestamp.cmp(&b.timestamp),
                ord => ord,
            }
        });

        // Check consistency: for each address, reads must match preceding writes
        let mut current_addr = sorted[0].addr;
        let mut current_value = M31::ZERO; // Initial value is 0
        let mut had_write = false;

        for op in &sorted {
            if op.addr != current_addr {
                // New address - reset
                current_addr = op.addr;
                current_value = M31::ZERO;
                had_write = false;
            }

            if op.is_write {
                current_value = op.value;
                had_write = true;
            } else {
                // Read must match current value
                if !had_write && op.value != M31::ZERO {
                    return Err("Read before write with non-zero value");
                }
                if had_write && op.value != current_value {
                    return Err("Read value doesn't match most recent write");
                }
            }
        }

        // Generate LogUp proof using multi-column approach
        let mc_logup = MultiColumnLogUp::new(alpha, beta);
        
        // Original order tuples (addr, value, timestamp)
        let original_tuples: Vec<Vec<M31>> = self.operations.iter()
            .map(|op| vec![op.addr, op.value, M31::new(op.timestamp)])
            .collect();

        // Sorted order tuples
        let sorted_tuples: Vec<Vec<M31>> = sorted.iter()
            .map(|op| vec![op.addr, op.value, M31::new(op.timestamp)])
            .collect();

        // Both should be permutations of each other
        let n = original_tuples.len();
        let multiplicities = vec![1u32; n];

        Ok(mc_logup.prove(&original_tuples, &sorted_tuples, &multiplicities))
    }

    /// Get the operations.
    pub fn operations(&self) -> &[MemoryOp] {
        &self.operations
    }
}

impl Default for MemoryConsistency {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_alpha() -> QM31 {
        QM31::new(M31::new(1000), M31::new(7), M31::new(3), M31::new(1))
    }

    fn test_beta() -> QM31 {
        QM31::new(M31::new(2000), M31::new(11), M31::new(5), M31::new(2))
    }

    // ========== LookupTable Tests ==========

    #[test]
    fn test_lookup_table_basic() {
        let table = LookupTable::new(vec![
            M31::new(10), M31::new(20), M31::new(30)
        ]);
        
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
        assert!(table.contains(M31::new(10)));
        assert!(!table.contains(M31::new(15)));
    }

    #[test]
    fn test_lookup_table_lookup() {
        let mut table = LookupTable::new(vec![
            M31::new(0), M31::new(1), M31::new(2), M31::new(3)
        ]);

        // Lookup existing values
        assert_eq!(table.lookup(M31::new(1)), Some(1));
        assert_eq!(table.lookup(M31::new(1)), Some(1)); // Second lookup
        assert_eq!(table.lookup(M31::new(3)), Some(3));

        // Lookup non-existing value
        assert_eq!(table.lookup(M31::new(100)), None);

        // Check multiplicities
        assert_eq!(table.multiplicity(0), 0);
        assert_eq!(table.multiplicity(1), 2);
        assert_eq!(table.multiplicity(3), 1);
    }

    #[test]
    fn test_lookup_table_range() {
        let table = LookupTable::range_table(4);
        assert_eq!(table.len(), 16);
        
        for i in 0..16 {
            assert!(table.contains(M31::new(i)));
        }
        assert!(!table.contains(M31::new(16)));
    }

    #[test]
    fn test_lookup_table_with_multiplicities() {
        let table = LookupTable::with_multiplicities(vec![
            (M31::new(5), 3),
            (M31::new(10), 2),
            (M31::new(15), 1),
        ]);

        assert_eq!(table.multiplicity(0), 3);
        assert_eq!(table.multiplicity(1), 2);
        assert_eq!(table.multiplicity(2), 1);
    }

    // ========== LogUpAccumulator Tests ==========

    #[test]
    fn test_logup_accumulator_add() {
        let alpha = test_alpha();
        let mut acc = LogUpAccumulator::new(alpha);

        acc.add(M31::new(5));
        acc.add(M31::new(10));

        assert_eq!(acc.terms().len(), 2);
        assert_eq!(acc.running_sum_column().len(), 3); // Initial 0 + 2 steps
    }

    #[test]
    fn test_logup_accumulator_sub_weighted() {
        let alpha = test_alpha();
        let mut acc = LogUpAccumulator::new(alpha);

        acc.sub_weighted(M31::new(5), 2);
        acc.sub_weighted(M31::new(10), 0); // Zero multiplicity

        assert_eq!(acc.terms().len(), 2);
    }

    // ========== LogUpProver Tests ==========

    #[test]
    fn test_logup_valid_lookup() {
        let alpha = test_alpha();
        let prover = LogUpProver::new(alpha);

        // Create table [0, 1, 2, 3]
        let mut table = LookupTable::new(vec![
            M31::new(0), M31::new(1), M31::new(2), M31::new(3)
        ]);

        // Lookup values that are in the table
        let lookups = vec![M31::new(1), M31::new(2), M31::new(1)];

        // Record lookups in table
        for &v in &lookups {
            table.lookup(v);
        }

        let proof = prover.prove_lookup(&lookups, &table);

        assert!(proof.verify(), "Valid lookup should verify");
        assert_eq!(proof.lookup_degree(), lookups.len());
        assert_eq!(proof.table_degree(), table.len());
    }

    #[test]
    fn test_logup_invalid_lookup() {
        let alpha = test_alpha();
        let prover = LogUpProver::new(alpha);

        let mut table = LookupTable::new(vec![
            M31::new(0), M31::new(1), M31::new(2)
        ]);

        // Lookup value NOT in table (don't record it)
        let lookups = vec![M31::new(1), M31::new(99)]; // 99 not in table

        // Only record valid lookups
        table.lookup(M31::new(1));
        // table.lookup(M31::new(99)) would return None

        let proof = prover.prove_lookup(&lookups, &table);

        // This should NOT verify because multiplicities don't match
        assert!(!proof.verify(), "Invalid lookup should not verify");
    }

    #[test]
    fn test_logup_generate_columns_legacy() {
        let alpha = test_alpha();
        let prover = LogUpProver::new(alpha);

        let mut table = LookupTable::new(vec![M31::new(0), M31::new(1)]);
        let lookups = vec![M31::new(0), M31::new(1), M31::new(0)];

        for &v in &lookups {
            table.lookup(v);
        }

        let (lookup_col, table_col, final_sum) = prover.generate_columns(&lookups, &table);

        assert_eq!(lookup_col.len(), 3);
        assert_eq!(table_col.len(), 2);
        assert_eq!(final_sum, QM31::ZERO);
    }

    // ========== RangeCheck Tests ==========

    #[test]
    fn test_range_check_valid() {
        let mut rc = RangeCheck::new(8); // [0, 256)

        assert!(rc.check(M31::new(0)));
        assert!(rc.check(M31::new(127)));
        assert!(rc.check(M31::new(255)));
    }

    #[test]
    fn test_range_check_invalid() {
        let mut rc = RangeCheck::new(8);

        assert!(!rc.check(M31::new(256)));
        assert!(!rc.check(M31::new(1000)));
    }

    #[test]
    fn test_range_check_proof() {
        let mut rc = RangeCheck::new(4); // [0, 16)
        
        let values = vec![M31::new(1), M31::new(5), M31::new(1), M31::new(15)];
        assert!(rc.check_all(&values));

        let proof = rc.prove(&values, test_alpha());
        assert!(proof.verify());
    }

    // ========== PermutationArgument Tests ==========

    #[test]
    fn test_permutation_valid() {
        let alpha = test_alpha();
        let perm = PermutationArgument::new(alpha);

        let a = vec![M31::new(1), M31::new(2), M31::new(3), M31::new(4)];
        let b = vec![M31::new(3), M31::new(1), M31::new(4), M31::new(2)];

        let proof = perm.prove(&a, &b);
        assert!(PermutationArgument::verify(&proof));
    }

    #[test]
    fn test_permutation_with_duplicates() {
        let alpha = test_alpha();
        let perm = PermutationArgument::new(alpha);

        let a = vec![M31::new(1), M31::new(1), M31::new(2), M31::new(3)];
        let b = vec![M31::new(3), M31::new(1), M31::new(1), M31::new(2)];

        let proof = perm.prove(&a, &b);
        assert!(PermutationArgument::verify(&proof));
    }

    #[test]
    fn test_permutation_invalid() {
        let alpha = test_alpha();
        let perm = PermutationArgument::new(alpha);

        let a = vec![M31::new(1), M31::new(2), M31::new(3)];
        let b = vec![M31::new(1), M31::new(2), M31::new(4)]; // Different!

        let proof = perm.prove(&a, &b);
        assert!(!PermutationArgument::verify(&proof));
    }

    // ========== MultiColumnLogUp Tests ==========

    #[test]
    fn test_multi_column_combine() {
        let mc = MultiColumnLogUp::new(test_alpha(), test_beta());

        let combined1 = mc.combine(&[M31::new(1), M31::new(2)]);
        let combined2 = mc.combine(&[M31::new(1), M31::new(2)]);
        let combined3 = mc.combine(&[M31::new(1), M31::new(3)]);

        assert_eq!(combined1, combined2);
        assert_ne!(combined1, combined3);
    }

    #[test]
    fn test_multi_column_lookup() {
        let mc = MultiColumnLogUp::new(test_alpha(), test_beta());

        // Table entries: (0, 0), (0, 1), (1, 0), (1, 1)
        let table_tuples: Vec<Vec<M31>> = vec![
            vec![M31::new(0), M31::new(0)],
            vec![M31::new(0), M31::new(1)],
            vec![M31::new(1), M31::new(0)],
            vec![M31::new(1), M31::new(1)],
        ];

        // Lookups: (0, 1), (1, 0)
        let lookup_tuples: Vec<Vec<M31>> = vec![
            vec![M31::new(0), M31::new(1)],
            vec![M31::new(1), M31::new(0)],
        ];

        let multiplicities = vec![0, 1, 1, 0]; // Only (0,1) and (1,0) looked up

        let proof = mc.prove(&lookup_tuples, &table_tuples, &multiplicities);
        assert!(proof.verify());
    }

    // ========== MemoryConsistency Tests ==========

    #[test]
    fn test_memory_consistency_simple() {
        let mut mem = MemoryConsistency::new();

        // Write 42 to address 0
        mem.write(M31::new(0), M31::new(42), 0);
        // Read 42 from address 0
        mem.read(M31::new(0), M31::new(42), 1);

        let proof = mem.prove(test_alpha(), test_beta());
        assert!(proof.is_ok());
        assert!(proof.unwrap().verify());
    }

    #[test]
    fn test_memory_consistency_multiple_addresses() {
        let mut mem = MemoryConsistency::new();

        // Write to multiple addresses
        mem.write(M31::new(0), M31::new(10), 0);
        mem.write(M31::new(1), M31::new(20), 1);
        mem.write(M31::new(2), M31::new(30), 2);

        // Read back
        mem.read(M31::new(1), M31::new(20), 3);
        mem.read(M31::new(0), M31::new(10), 4);
        mem.read(M31::new(2), M31::new(30), 5);

        let proof = mem.prove(test_alpha(), test_beta());
        assert!(proof.is_ok());
    }

    #[test]
    fn test_memory_consistency_overwrite() {
        let mut mem = MemoryConsistency::new();

        // Write 10, then overwrite with 20
        mem.write(M31::new(0), M31::new(10), 0);
        mem.write(M31::new(0), M31::new(20), 1);
        // Read should get latest value
        mem.read(M31::new(0), M31::new(20), 2);

        let proof = mem.prove(test_alpha(), test_beta());
        assert!(proof.is_ok());
    }

    #[test]
    fn test_memory_consistency_invalid_read() {
        let mut mem = MemoryConsistency::new();

        // Write 10
        mem.write(M31::new(0), M31::new(10), 0);
        // Read wrong value
        mem.read(M31::new(0), M31::new(99), 1); // Wrong!

        let proof = mem.prove(test_alpha(), test_beta());
        assert!(proof.is_err());
    }

    #[test]
    fn test_memory_consistency_read_before_write() {
        let mut mem = MemoryConsistency::new();

        // Read from uninitialized address (should be 0)
        mem.read(M31::new(0), M31::new(0), 0);
        // Now write
        mem.write(M31::new(0), M31::new(42), 1);

        let proof = mem.prove(test_alpha(), test_beta());
        assert!(proof.is_ok());
    }

    #[test]
    fn test_memory_consistency_read_nonzero_before_write() {
        let mut mem = MemoryConsistency::new();

        // Read non-zero from uninitialized address - invalid!
        mem.read(M31::new(0), M31::new(5), 0);

        let proof = mem.prove(test_alpha(), test_beta());
        assert!(proof.is_err());
    }
}
