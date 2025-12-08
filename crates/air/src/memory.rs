//! Memory AIR constraints and RAM permutation argument.

use zp1_primitives::M31;

/// Memory AIR for RAM consistency via permutation argument.
pub struct MemoryAir;

impl MemoryAir {
    /// Memory read/write consistency constraint using LogUp argument.
    ///
    /// Enforces RAM permutation via running sum: sum' = sum + 1/(fingerprint + beta)
    /// where fingerprint = α³·addr + α²·value + α·timestamp + is_write
    ///
    /// This constraint checks the running sum increment is correct.
    /// 
    /// # Arguments
    /// * `addr` - Memory address
    /// * `value` - Memory value (32-bit)
    /// * `timestamp` - Timestamp of access
    /// * `is_write` - 1 if write, 0 if read
    /// * `prev_sum` - Running sum from previous row
    /// * `curr_sum` - Running sum at current row
    /// * `alpha` - Challenge for fingerprint combination
    /// * `beta` - Challenge for denominator shift
    /// 
    /// # Returns
    /// Constraint: (fingerprint + beta) * (curr_sum - prev_sum) - 1 = 0
    #[inline]
    pub fn memory_logup_constraint(
        addr: M31,
        value: M31,
        timestamp: M31,
        is_write: M31,
        prev_sum: M31,
        curr_sum: M31,
        alpha: M31,
        beta: M31,
    ) -> M31 {
        // Compute fingerprint: α³·addr + α²·value + α·timestamp + is_write
        let alpha2 = alpha * alpha;
        let alpha3 = alpha2 * alpha;
        let fingerprint = alpha3 * addr + alpha2 * value + alpha * timestamp + is_write;
        
        // LogUp increment: 1/(fingerprint + beta)
        // Constraint: (fingerprint + beta) * (curr_sum - prev_sum) = 1
        // Rearranged: (fingerprint + beta) * (curr_sum - prev_sum) - 1 = 0
        let denom = fingerprint + beta;
        let delta = curr_sum - prev_sum;
        denom * delta - M31::ONE
    }

    /// Address alignment constraint.
    /// For word access: addr mod 4 = 0.
    #[inline]
    pub fn word_alignment_constraint(addr_lo: M31, is_word: M31) -> M31 {
        // Check 4-byte alignment: addr % 4 == 0
        // In M31 field: compute addr_lo mod 4
        // We extract bottom 2 bits by: addr_lo - 4 * floor(addr_lo / 4)
        
        let four = M31::new(4);
        let quotient = M31::new(addr_lo.as_u32() / 4);  // Integer division
        let remainder = addr_lo - quotient * four;       // addr_lo % 4
        
        // Constraint: when is_word = 1, remainder must be 0
        // If remainder != 0, constraint is non-zero → proof fails
        is_word * remainder
    }
}
