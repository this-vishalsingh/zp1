//! LogUp lookup argument implementation.
//!
//! LogUp is a logarithmic derivative-based lookup argument that proves
//! that a set of values appears in a lookup table. It's used for:
//! - Memory consistency (read/write operations match)
//! - Range checks (values fit in specified bit widths)
//! - Permutation arguments
//!
//! The key insight: if multiset A ⊆ multiset B, then for random α:
//! ∑_{a ∈ A} 1/(α - a) = ∑_{b ∈ B} m_b/(α - b)
//! where m_b is the multiplicity of b in A.

use zp1_primitives::{M31, QM31};

/// A lookup table entry with multiplicities.
#[derive(Clone, Debug)]
pub struct LookupTable {
    /// The values in the table.
    pub values: Vec<M31>,
    /// Multiplicities (how many times each value is looked up).
    pub multiplicities: Vec<u32>,
}

impl LookupTable {
    /// Create a new lookup table.
    pub fn new(values: Vec<M31>) -> Self {
        let len = values.len();
        Self {
            values,
            multiplicities: vec![0; len],
        }
    }

    /// Create a range check table for values in [0, 2^bits).
    pub fn range_table(bits: usize) -> Self {
        let size = 1 << bits;
        let values = (0..size).map(|i| M31::new(i as u32)).collect();
        Self::new(values)
    }

    /// Record a lookup of value v, incrementing its multiplicity.
    /// Returns the index where v was found, or None if not in table.
    pub fn lookup(&mut self, v: M31) -> Option<usize> {
        for (i, &val) in self.values.iter().enumerate() {
            if val == v {
                self.multiplicities[i] += 1;
                return Some(i);
            }
        }
        None
    }

    /// Get the table size.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Check if table is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// LogUp column accumulator.
/// Accumulates 1/(α - v) terms for the lookup argument.
#[derive(Clone, Debug)]
pub struct LogUpAccumulator {
    /// The random challenge α.
    alpha: QM31,
    /// Running sum of 1/(α - v) terms.
    running_sum: QM31,
    /// Individual column values (for commitment).
    column: Vec<QM31>,
}

impl LogUpAccumulator {
    /// Create a new accumulator with the given challenge.
    pub fn new(alpha: QM31) -> Self {
        Self {
            alpha,
            running_sum: QM31::ZERO,
            column: Vec::new(),
        }
    }

    /// Add a lookup value to the accumulator.
    /// Computes 1/(α - v) and adds it to the running sum.
    pub fn add_lookup(&mut self, v: M31) {
        let v_ext = QM31::from_base(v);
        let diff = self.alpha - v_ext;
        let inv = diff.inv();
        self.running_sum = self.running_sum + inv;
        self.column.push(inv);
    }

    /// Subtract a multiplicity-weighted table entry.
    /// Computes m/(α - v) and subtracts it from the running sum.
    pub fn sub_table_entry(&mut self, v: M31, multiplicity: u32) {
        if multiplicity == 0 {
            self.column.push(QM31::ZERO);
            return;
        }
        let v_ext = QM31::from_base(v);
        let diff = self.alpha - v_ext;
        let inv = diff.inv();
        let mult_ext = QM31::from_base(M31::new(multiplicity));
        let term = mult_ext * inv;
        self.running_sum = self.running_sum - term;
        self.column.push(term);
    }

    /// Get the final sum (should be zero if lookup argument is satisfied).
    pub fn final_sum(&self) -> QM31 {
        self.running_sum
    }

    /// Get the accumulated column.
    pub fn column(&self) -> &[QM31] {
        &self.column
    }

    /// Verify that the final sum is zero.
    pub fn verify(&self) -> bool {
        self.running_sum == QM31::ZERO
    }
}

/// LogUp lookup prover.
/// Generates the LogUp columns for proving lookup arguments.
pub struct LogUpProver {
    /// The random challenge.
    alpha: QM31,
}

impl LogUpProver {
    /// Create a new LogUp prover with the given challenge.
    pub fn new(alpha: QM31) -> Self {
        Self { alpha }
    }

    /// Generate LogUp columns for a set of lookups against a table.
    ///
    /// Returns (lookup_column, table_column, final_sum).
    /// If the lookups are valid, final_sum should be zero.
    pub fn generate_columns(
        &self,
        lookups: &[M31],
        table: &LookupTable,
    ) -> (Vec<QM31>, Vec<QM31>, QM31) {
        let mut lookup_acc = LogUpAccumulator::new(self.alpha);
        let mut table_acc = LogUpAccumulator::new(self.alpha);

        // Accumulate lookup terms: ∑ 1/(α - v)
        for &v in lookups {
            lookup_acc.add_lookup(v);
        }

        // Accumulate table terms: ∑ m/(α - t)
        for (i, &t) in table.values.iter().enumerate() {
            table_acc.sub_table_entry(t, table.multiplicities[i]);
        }

        // The final sum should be lookup_sum - table_sum = 0
        let final_sum = lookup_acc.final_sum() + table_acc.final_sum();

        (
            lookup_acc.column().to_vec(),
            table_acc.column().to_vec(),
            final_sum,
        )
    }

    /// Generate LogUp trace for memory consistency.
    ///
    /// Memory operations are (addr, value, is_write) tuples.
    /// Reads must match previous writes to the same address.
    pub fn memory_consistency(
        &self,
        operations: &[(M31, M31, bool)], // (addr, value, is_write)
    ) -> (Vec<QM31>, QM31) {
        let mut acc = LogUpAccumulator::new(self.alpha);

        // Encode each operation as a single value for lookup
        // Simple encoding: addr * 2^32 + value (in extension field)
        for &(addr, value, is_write) in operations {
            // Combine addr and value into a single lookup key
            let key = combine_addr_value(addr, value);
            
            if is_write {
                // Writes contribute positively
                acc.add_lookup(key);
            } else {
                // Reads contribute negatively (must cancel with a write)
                let key_ext = QM31::from_base(key);
                let diff = self.alpha - key_ext;
                let inv = diff.inv();
                acc.running_sum = acc.running_sum - inv;
                acc.column.push(-inv);
            }
        }

        (acc.column().to_vec(), acc.final_sum())
    }
}

/// Combine address and value into a single field element for lookup.
fn combine_addr_value(addr: M31, value: M31) -> M31 {
    // Simple combination: addr + value * 2^16
    // This works if addr < 2^16 and value < 2^16
    M31::new(addr.as_u32() + (value.as_u32() << 16) % M31::P)
}

/// Range check constraint generator.
/// Ensures values are in a specified range.
pub struct RangeCheck {
    /// Number of bits for the range [0, 2^bits).
    bits: usize,
    /// Lookup table for range values.
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

    /// Get the table for LogUp proof generation.
    pub fn table(&self) -> &LookupTable {
        &self.table
    }

    /// Get mutable reference to table.
    pub fn table_mut(&mut self) -> &mut LookupTable {
        &mut self.table
    }
}

/// Permutation argument using LogUp.
/// Proves that two lists are permutations of each other.
pub struct PermutationArgument {
    alpha: QM31,
}

impl PermutationArgument {
    /// Create a new permutation argument.
    pub fn new(alpha: QM31) -> Self {
        Self { alpha }
    }

    /// Generate columns proving that `a` and `b` are permutations.
    /// Returns (a_column, b_column, final_sum).
    pub fn prove(&self, a: &[M31], b: &[M31]) -> (Vec<QM31>, Vec<QM31>, QM31) {
        assert_eq!(a.len(), b.len(), "Permutation arguments must have same length");

        let mut a_acc = LogUpAccumulator::new(self.alpha);
        let mut b_acc = LogUpAccumulator::new(self.alpha);

        // Sum over a: ∑ 1/(α - a_i)
        for &v in a {
            a_acc.add_lookup(v);
        }

        // Sum over b: ∑ 1/(α - b_i)  
        for &v in b {
            b_acc.add_lookup(v);
        }

        // If a and b are permutations, the sums are equal
        let final_sum = a_acc.final_sum() - b_acc.final_sum();

        (
            a_acc.column().to_vec(),
            b_acc.column().to_vec(),
            final_sum,
        )
    }

    /// Verify that the final sum is zero.
    pub fn verify(final_sum: QM31) -> bool {
        final_sum == QM31::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_table() {
        let mut table = LookupTable::range_table(4); // [0, 16)
        assert_eq!(table.len(), 16);

        // Lookup some values
        assert!(table.lookup(M31::new(5)).is_some());
        assert!(table.lookup(M31::new(5)).is_some());
        assert!(table.lookup(M31::new(10)).is_some());

        // Check multiplicities
        assert_eq!(table.multiplicities[5], 2);
        assert_eq!(table.multiplicities[10], 1);
    }

    #[test]
    fn test_logup_accumulator() {
        let alpha = QM31::new(M31::new(42), M31::new(1), M31::ZERO, M31::ZERO);
        let mut acc = LogUpAccumulator::new(alpha);

        // Add a value
        acc.add_lookup(M31::new(5));
        assert!(!acc.column().is_empty());
    }

    #[test]
    fn test_logup_valid_lookup() {
        let alpha = QM31::new(M31::new(1000), M31::new(7), M31::new(3), M31::new(1));
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

        let (lookup_col, table_col, final_sum) = prover.generate_columns(&lookups, &table);

        // The columns should be non-empty
        assert_eq!(lookup_col.len(), lookups.len());
        assert_eq!(table_col.len(), table.len());

        // Final sum should be zero for valid lookups
        assert_eq!(final_sum, QM31::ZERO, "LogUp sum should be zero for valid lookups");
    }

    #[test]
    fn test_range_check() {
        let mut rc = RangeCheck::new(8); // [0, 256)

        assert!(rc.check(M31::new(0)));
        assert!(rc.check(M31::new(255)));
        assert!(!rc.check(M31::new(256)));
        assert!(!rc.check(M31::new(1000)));
    }

    #[test]
    fn test_permutation_argument() {
        let alpha = QM31::new(M31::new(999), M31::new(13), M31::new(7), M31::new(2));
        let perm = PermutationArgument::new(alpha);

        let a = vec![M31::new(1), M31::new(2), M31::new(3), M31::new(4)];
        let b = vec![M31::new(3), M31::new(1), M31::new(4), M31::new(2)]; // permutation of a

        let (_, _, final_sum) = perm.prove(&a, &b);

        assert!(PermutationArgument::verify(final_sum), "Permutation should verify");
    }

    #[test]
    fn test_permutation_argument_invalid() {
        let alpha = QM31::new(M31::new(999), M31::new(13), M31::new(7), M31::new(2));
        let perm = PermutationArgument::new(alpha);

        let a = vec![M31::new(1), M31::new(2), M31::new(3), M31::new(4)];
        let b = vec![M31::new(5), M31::new(1), M31::new(4), M31::new(2)]; // NOT a permutation

        let (_, _, final_sum) = perm.prove(&a, &b);

        assert!(!PermutationArgument::verify(final_sum), "Non-permutation should fail");
    }
}
