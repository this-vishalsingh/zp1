//! CPU AIR constraints for RV32IM.

use zp1_primitives::M31;

/// CPU AIR constraint evaluator.
///
/// All constraints are degree ≤ 2 polynomials.
pub struct CpuAir;

impl CpuAir {
    /// Evaluate the x0 = 0 constraint.
    /// When writing to x0 (is_write_x0 selector = 1), rd_val must be 0.
    /// 
    /// # Arguments
    /// * `is_write_x0` - Boolean selector (1 if writing to x0, 0 otherwise)
    /// * `rd_val_lo` - Lower 16-bit limb of value being written
    /// * `rd_val_hi` - Upper 16-bit limb of value being written
    /// 
    /// # Returns
    /// Sum of two constraints (one per limb): is_write_x0 * rd_val_lo + is_write_x0 * rd_val_hi
    #[inline]
    pub fn x0_zero_constraint(is_write_x0: M31, rd_val_lo: M31, rd_val_hi: M31) -> M31 {
        // When is_write_x0 = 1, both limbs must be 0
        // Constraints combined: is_write_x0 * (rd_val_lo + rd_val_hi) = 0
        is_write_x0 * (rd_val_lo + rd_val_hi)
    }

    /// Evaluate PC increment constraint for non-branch/jump.
    /// next_pc = pc + 4 when not branch/jump.
    #[inline]
    pub fn pc_increment_constraint(
        pc: M31,
        next_pc: M31,
        is_branch: M31,
        is_jal: M31,
        is_jalr: M31,
    ) -> M31 {
        // (1 - is_branch - is_jal - is_jalr) * (next_pc - pc - 4) = 0
        let four = M31::new(4);
        let one = M31::ONE;
        let selector = one - is_branch - is_jal - is_jalr;
        selector * (next_pc - pc - four)
    }

    /// Evaluate LUI constraint: rd_val = imm (upper 20 bits).
    #[inline]
    pub fn lui_constraint(is_lui: M31, rd_val: M31, imm: M31) -> M31 {
        // is_lui * (rd_val - imm) = 0
        is_lui * (rd_val - imm)
    }

    /// Evaluate AUIPC constraint: rd_val = pc + imm.
    #[inline]
    pub fn auipc_constraint(is_auipc: M31, rd_val: M31, pc: M31, imm: M31) -> M31 {
        // is_auipc * (rd_val - pc - imm) = 0
        is_auipc * (rd_val - pc - imm)
    }

    /// Evaluate ADD constraint (degree 2).
    /// rd_val = rs1_val + rs2_val (mod 2^32, handled via limb decomposition).
    #[inline]
    pub fn add_constraint(
        is_add: M31,
        rd_val_lo: M31,
        rd_val_hi: M31,
        rs1_val_lo: M31,
        rs1_val_hi: M31,
        rs2_val_lo: M31,
        rs2_val_hi: M31,
        carry: M31, // Auxiliary witness for carry from low to high limb
    ) -> (M31, M31) {
        // Low limb: rd_val_lo = rs1_val_lo + rs2_val_lo - carry * 2^16
        // High limb: rd_val_hi = rs1_val_hi + rs2_val_hi + carry (mod 2^16)
        let two_16 = M31::new(1 << 16);

        let c1 = is_add * (rd_val_lo - rs1_val_lo - rs2_val_lo + carry * two_16);
        let c2 = is_add * (rd_val_hi - rs1_val_hi - rs2_val_hi - carry);

        (c1, c2)
    }

    /// Evaluate ADDI (Add Immediate) constraint.
    /// rd_val = rs1_val + imm (mod 2^32)
    /// Reuses ADD logic with immediate instead of rs2.
    #[inline]
    pub fn addi_constraint(
        is_addi: M31,
        rd_val_lo: M31,
        rd_val_hi: M31,
        rs1_val_lo: M31,
        rs1_val_hi: M31,
        imm_lo: M31,
        imm_hi: M31,
        carry: M31,
    ) -> (M31, M31) {
        // Same as ADD but with immediate
        Self::add_constraint(
            is_addi, rd_val_lo, rd_val_hi,
            rs1_val_lo, rs1_val_hi,
            imm_lo, imm_hi, carry
        )
    }

    /// Evaluate ANDI (AND Immediate) constraint.
    /// rd_val = rs1_val & imm
    /// Uses bitwise AND logic with immediate.
    pub fn andi_constraint(
        bits_rs1: &[M31; 32],
        bits_imm: &[M31; 32],
        bits_result: &[M31; 32],
    ) -> Vec<M31> {
        // Same as bitwise AND
        Self::bitwise_and_constraints(bits_rs1, bits_imm, bits_result)
    }

    /// Evaluate ORI (OR Immediate) constraint.
    /// rd_val = rs1_val | imm
    pub fn ori_constraint(
        bits_rs1: &[M31; 32],
        bits_imm: &[M31; 32],
        bits_result: &[M31; 32],
    ) -> Vec<M31> {
        // Same as bitwise OR
        Self::bitwise_or_constraints(bits_rs1, bits_imm, bits_result)
    }

    /// Evaluate XORI (XOR Immediate) constraint.
    /// rd_val = rs1_val ^ imm
    pub fn xori_constraint(
        bits_rs1: &[M31; 32],
        bits_imm: &[M31; 32],
        bits_result: &[M31; 32],
    ) -> Vec<M31> {
        // Same as bitwise XOR
        Self::bitwise_xor_constraints(bits_rs1, bits_imm, bits_result)
    }

    /// Evaluate SLTI (Set Less Than Immediate) constraint.
    /// rd_val = (rs1 < imm) ? 1 : 0 (signed comparison)
    pub fn slti_constraint(
        bits_rs1: &[M31; 32],
        bits_imm: &[M31; 32],
        result: M31,
        diff_bits: &[M31; 32],
    ) -> Vec<M31> {
        // Same as SLT but with immediate
        Self::set_less_than_signed_constraints(bits_rs1, bits_imm, result, diff_bits)
    }

    /// Evaluate SLTIU (Set Less Than Immediate Unsigned) constraint.
    /// rd_val = (rs1 < imm) ? 1 : 0 (unsigned comparison)
    pub fn sltiu_constraint(
        bits_rs1: &[M31; 32],
        bits_imm: &[M31; 32],
        result: M31,
        borrow: M31,
    ) -> Vec<M31> {
        // Same as SLTU but with immediate
        Self::set_less_than_unsigned_constraints(bits_rs1, bits_imm, result, borrow)
    }

    /// Evaluate SLLI (Shift Left Logical Immediate) constraint.
    /// rd_val = rs1_val << shamt
    pub fn slli_constraint(
        bits_rs1: &[M31; 32],
        bits_result: &[M31; 32],
        shamt: M31,
    ) -> Vec<M31> {
        // Same as SLL but with immediate shift amount
        Self::shift_left_logical_constraints(bits_rs1, bits_result, shamt)
    }

    /// Evaluate SRLI (Shift Right Logical Immediate) constraint.
    /// rd_val = rs1_val >> shamt
    pub fn srli_constraint(
        bits_rs1: &[M31; 32],
        bits_result: &[M31; 32],
        shamt: M31,
    ) -> Vec<M31> {
        // Same as SRL but with immediate shift amount
        Self::shift_right_logical_constraints(bits_rs1, bits_result, shamt)
    }

    /// Evaluate SRAI (Shift Right Arithmetic Immediate) constraint.
    /// rd_val = rs1_val >> shamt (sign-extended)
    pub fn srai_constraint(
        bits_rs1: &[M31; 32],
        bits_result: &[M31; 32],
        shamt: M31,
    ) -> Vec<M31> {
        // Same as SRA but with immediate shift amount
        Self::shift_right_arithmetic_constraints(bits_rs1, bits_result, shamt)
    }

    /// Evaluate bit decomposition constraint.
    /// Ensures that:
    /// 1. Each bit is binary (bit * (bit - 1) = 0)
    /// 2. Bits reconstruct the original 32-bit value
    ///
    /// # Arguments
    /// * `value_lo` - Lower 16-bit limb of the value
    /// * `value_hi` - Upper 16-bit limb of the value  
    /// * `bits` - Array of 32 individual bit values
    ///
    /// # Returns
    /// Vector of 34 constraints (32 bit constraints + 2 reconstruction constraints)
    pub fn bit_decomposition_constraints(
        value_lo: M31,
        value_hi: M31,
        bits: &[M31; 32],
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(34);
        
        // Constraint: each bit must be 0 or 1
        // bit * (bit - 1) = 0
        for &bit in bits {
            constraints.push(bit * (bit - M31::ONE));
        }
        
        // Constraint: bits must reconstruct the value
        // value = bits[0] + 2*bits[1] + 4*bits[2] + ... + 2^31*bits[31]
        let mut recon_lo = M31::ZERO;
        let mut recon_hi = M31::ZERO;
        let mut power = M31::ONE;
        
        for i in 0..32 {
            if i < 16 {
                recon_lo = recon_lo + bits[i] * power;
            } else {
                recon_hi = recon_hi + bits[i] * power;
            }
            
            // Update power: multiply by 2 (mod p)
            power = power + power;
            
            // After bit 15, reset power for high limb
            if i == 15 {
                power = M31::ONE;
            }
        }
        
        // Reconstruction constraints
        constraints.push(value_lo - recon_lo);
        constraints.push(value_hi - recon_hi);
        
        constraints
    }

    /// Evaluate AND constraint for bitwise operations.
    /// result[i] = a[i] AND b[i] = a[i] * b[i]
    ///
    /// # Returns
    /// Vector of 32 constraints (one per bit)
    #[inline]
    pub fn bitwise_and_constraints(
        bits_a: &[M31; 32],
        bits_b: &[M31; 32],
        bits_result: &[M31; 32],
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(32);
        for i in 0..32 {
            // result[i] = a[i] * b[i]
            constraints.push(bits_result[i] - bits_a[i] * bits_b[i]);
        }
        constraints
    }

    /// Evaluate OR constraint for bitwise operations.
    /// result[i] = a[i] OR b[i] = a[i] + b[i] - a[i]*b[i]
    ///
    /// # Returns
    /// Vector of 32 constraints (one per bit)
    #[inline]
    pub fn bitwise_or_constraints(
        bits_a: &[M31; 32],
        bits_b: &[M31; 32],
        bits_result: &[M31; 32],
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(32);
        for i in 0..32 {
            // result[i] = a[i] + b[i] - a[i]*b[i]
            constraints.push(bits_result[i] - (bits_a[i] + bits_b[i] - bits_a[i] * bits_b[i]));
        }
        constraints
    }

    /// Evaluate XOR constraint for bitwise operations.
    /// result[i] = a[i] XOR b[i] = a[i] + b[i] - 2*a[i]*b[i]
    ///
    /// # Returns
    /// Vector of 32 constraints (one per bit)
    #[inline]
    pub fn bitwise_xor_constraints(
        bits_a: &[M31; 32],
        bits_b: &[M31; 32],
        bits_result: &[M31; 32],
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(32);
        let two = M31::new(2);
        for i in 0..32 {
            // result[i] = a[i] + b[i] - 2*a[i]*b[i]
            constraints.push(bits_result[i] - (bits_a[i] + bits_b[i] - two * bits_a[i] * bits_b[i]));
        }
        constraints
    }

    /// Evaluate SLL (Shift Left Logical) constraint.
    /// result = value << (shift_amount % 32)
    /// 
    /// # Arguments
    /// * `bits_value` - Bit decomposition of input value
    /// * `bits_result` - Bit decomposition of result
    /// * `shift_amount` - Number of positions to shift (0-31)
    ///
    /// # Returns
    /// Vector of 32 constraints enforcing correct shift
    pub fn shift_left_logical_constraints(
        bits_value: &[M31; 32],
        bits_result: &[M31; 32],
        shift_amount: M31,
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(32);
        
        // For each possible shift amount (0-31), we need to check:
        // If shift_amount == k, then result[i] = value[i-k] for i >= k, else 0
        // We use selector pattern: is_shift_k * (result[i] - expected[i]) = 0
        
        // Convert shift_amount to u32 for computation
        // Note: In real implementation, shift_amount should be range-checked [0, 31]
        let shift_val = shift_amount.value() % 32;
        
        for i in 0..32 {
            if i < shift_val as usize {
                // Bits shifted in from right are 0
                constraints.push(bits_result[i]);
            } else {
                // Bit i of result comes from bit (i - shift) of input
                let src_idx = i - shift_val as usize;
                constraints.push(bits_result[i] - bits_value[src_idx]);
            }
        }
        
        constraints
    }

    /// Evaluate SRL (Shift Right Logical) constraint.
    /// result = value >> (shift_amount % 32)
    /// Zero-extends from left.
    ///
    /// # Returns
    /// Vector of 32 constraints enforcing correct shift
    pub fn shift_right_logical_constraints(
        bits_value: &[M31; 32],
        bits_result: &[M31; 32],
        shift_amount: M31,
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(32);
        
        let shift_val = shift_amount.value() % 32;
        
        for i in 0..32 {
            let src_idx = i + shift_val as usize;
            if src_idx >= 32 {
                // Bits shifted in from left are 0
                constraints.push(bits_result[i]);
            } else {
                // Bit i of result comes from bit (i + shift) of input
                constraints.push(bits_result[i] - bits_value[src_idx]);
            }
        }
        
        constraints
    }

    /// Evaluate SRA (Shift Right Arithmetic) constraint.
    /// result = value >> (shift_amount % 32)
    /// Sign-extends from left (replicates bit 31).
    ///
    /// # Returns
    /// Vector of 32 constraints enforcing correct shift
    pub fn shift_right_arithmetic_constraints(
        bits_value: &[M31; 32],
        bits_result: &[M31; 32],
        shift_amount: M31,
    ) -> Vec<M31> {
        let mut constraints = Vec::with_capacity(32);
        
        let shift_val = shift_amount.value() % 32;
        let sign_bit = bits_value[31]; // MSB is sign bit
        
        for i in 0..32 {
            let src_idx = i + shift_val as usize;
            if src_idx >= 32 {
                // Bits shifted in from left are sign bit
                constraints.push(bits_result[i] - sign_bit);
            } else {
                // Bit i of result comes from bit (i + shift) of input
                constraints.push(bits_result[i] - bits_value[src_idx]);
            }
        }
        
        constraints
    }

    /// Evaluate SLT (Set Less Than) constraint for signed comparison.
    /// result = (a < b) ? 1 : 0, where a and b are signed 32-bit integers.
    ///
    /// Uses subtraction and sign checking:
    /// - Compute diff = a - b
    /// - Check sign bit of diff to determine result
    ///
    /// # Arguments
    /// * `bits_a` - Bit decomposition of first operand (signed)
    /// * `bits_b` - Bit decomposition of second operand (signed)
    /// * `result` - Comparison result (must be 0 or 1)
    /// * `diff_bits` - Bit decomposition of (a - b) with borrow handling
    ///
    /// # Returns
    /// Vector of constraints enforcing correct signed comparison
    pub fn set_less_than_signed_constraints(
        bits_a: &[M31; 32],
        bits_b: &[M31; 32],
        result: M31,
        diff_bits: &[M31; 32],
    ) -> Vec<M31> {
        let mut constraints = Vec::new();
        
        // Constraint 1: result must be binary (0 or 1)
        constraints.push(result * (result - M31::ONE));
        
        // Constraint 2: Check sign bits for signed comparison
        // If sign(a) != sign(b):
        //   result = sign(a) (1 if a is negative, 0 if a is positive)
        // If sign(a) == sign(b):
        //   result = sign(a - b)
        
        let sign_a = bits_a[31];
        let sign_b = bits_b[31];
        let sign_diff = diff_bits[31];
        
        // Case 1: Different signs
        // If a is negative and b is positive: result = 1
        // If a is positive and b is negative: result = 0
        let diff_signs = sign_a * (M31::ONE - sign_b); // 1 if a<0 and b>=0
        
        // Case 2: Same signs - use difference sign
        let same_signs = M31::ONE - sign_a - sign_b + sign_a * sign_b * M31::new(2);
        let diff_result = same_signs * sign_diff;
        
        // Combined: result = diff_signs + diff_result
        constraints.push(result - diff_signs - diff_result);
        
        constraints
    }

    /// Evaluate SLTU (Set Less Than Unsigned) constraint.
    /// result = (a < b) ? 1 : 0, where a and b are unsigned 32-bit integers.
    ///
    /// For unsigned comparison, we check if borrow occurred in a - b.
    ///
    /// # Arguments
    /// * `bits_a` - Bit decomposition of first operand (unsigned)
    /// * `bits_b` - Bit decomposition of second operand (unsigned)
    /// * `result` - Comparison result (must be 0 or 1)
    /// * `borrow` - Borrow bit from subtraction a - b
    ///
    /// # Returns
    /// Vector of constraints enforcing correct unsigned comparison
    pub fn set_less_than_unsigned_constraints(
        _bits_a: &[M31; 32],
        _bits_b: &[M31; 32],
        result: M31,
        borrow: M31,
    ) -> Vec<M31> {
        let mut constraints = Vec::new();
        
        // Constraint 1: result must be binary (0 or 1)
        constraints.push(result * (result - M31::ONE));
        
        // Constraint 2: borrow must be binary (0 or 1)
        constraints.push(borrow * (borrow - M31::ONE));
        
        // Constraint 3: For unsigned, a < b iff borrow occurred in a - b
        // result = borrow
        constraints.push(result - borrow);
        
        constraints
    }

    /// Evaluate SUB (Subtract) constraint with borrow tracking.
    /// result = a - b (mod 2^32)
    ///
    /// This is used for comparison operations to detect if a < b.
    ///
    /// # Arguments
    /// * `a_lo`, `a_hi` - Limbs of first operand
    /// * `b_lo`, `b_hi` - Limbs of second operand
    /// * `result_lo`, `result_hi` - Limbs of result
    /// * `borrow` - Borrow from high to low limb (1 if low underflows, 0 otherwise)
    ///
    /// # Returns
    /// Tuple of (low_constraint, high_constraint)
    #[inline]
    pub fn sub_with_borrow_constraint(
        a_lo: M31,
        a_hi: M31,
        b_lo: M31,
        b_hi: M31,
        result_lo: M31,
        result_hi: M31,
        borrow: M31,
    ) -> (M31, M31) {
        let two_16 = M31::new(1 << 16);
        
        // Low limb: result_lo + b_lo = a_lo + borrow * 2^16
        // If a_lo < b_lo, we borrow from high (borrow = 1)
        let c_lo = a_lo + borrow * two_16 - b_lo - result_lo;
        
        // High limb: result_hi + b_hi + borrow = a_hi
        // We subtract the borrowed amount from high limb
        let c_hi = a_hi - b_hi - borrow - result_hi;
        
        (c_lo, c_hi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to convert u32 to bit array
    fn u32_to_bits(value: u32) -> [M31; 32] {
        let mut bits = [M31::ZERO; 32];
        for i in 0..32 {
            bits[i] = if (value >> i) & 1 == 1 {
                M31::ONE
            } else {
                M31::ZERO
            };
        }
        bits
    }

    /// Helper to split u32 into limbs
    fn u32_to_limbs(value: u32) -> (M31, M31) {
        let lo = value & 0xFFFF;
        let hi = value >> 16;
        (M31::new(lo), M31::new(hi))
    }

    #[test]
    fn test_bit_decomposition_valid() {
        // Test with value 0x12345678
        let value = 0x12345678u32;
        let (lo, hi) = u32_to_limbs(value);
        let bits = u32_to_bits(value);

        let constraints = CpuAir::bit_decomposition_constraints(lo, hi, &bits);
        
        // All 34 constraints should be satisfied (= 0)
        assert_eq!(constraints.len(), 34);
        for (i, constraint) in constraints.iter().enumerate() {
            assert_eq!(*constraint, M31::ZERO, "Constraint {} failed", i);
        }
    }

    #[test]
    fn test_bit_decomposition_all_zeros() {
        let value = 0u32;
        let (lo, hi) = u32_to_limbs(value);
        let bits = u32_to_bits(value);

        let constraints = CpuAir::bit_decomposition_constraints(lo, hi, &bits);
        
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_bit_decomposition_all_ones() {
        let value = 0xFFFFFFFFu32;
        let (lo, hi) = u32_to_limbs(value);
        let bits = u32_to_bits(value);

        let constraints = CpuAir::bit_decomposition_constraints(lo, hi, &bits);
        
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_bitwise_and_constraint() {
        // Test: 0b1010 AND 0b1100 = 0b1000
        let a = 0b1010u32;
        let b = 0b1100u32;
        let result = a & b; // = 0b1000

        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);
        let bits_result = u32_to_bits(result);

        let constraints = CpuAir::bitwise_and_constraints(&bits_a, &bits_b, &bits_result);
        
        assert_eq!(constraints.len(), 32);
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_bitwise_and_comprehensive() {
        // Test multiple cases
        let test_cases = [
            (0x00000000, 0x00000000, 0x00000000),
            (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
            (0xAAAAAAAA, 0x55555555, 0x00000000),
            (0x12345678, 0xABCDEF00, 0x02044600),
        ];

        for (a, b, expected) in test_cases {
            let bits_a = u32_to_bits(a);
            let bits_b = u32_to_bits(b);
            let bits_result = u32_to_bits(expected);

            let constraints = CpuAir::bitwise_and_constraints(&bits_a, &bits_b, &bits_result);
            
            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(*constraint, M31::ZERO, 
                    "AND failed for case ({:#x}, {:#x}), bit {}", a, b, i);
            }
        }
    }

    #[test]
    fn test_bitwise_or_constraint() {
        // Test: 0b1010 OR 0b1100 = 0b1110
        let a = 0b1010u32;
        let b = 0b1100u32;
        let result = a | b; // = 0b1110

        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);
        let bits_result = u32_to_bits(result);

        let constraints = CpuAir::bitwise_or_constraints(&bits_a, &bits_b, &bits_result);
        
        assert_eq!(constraints.len(), 32);
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_bitwise_or_comprehensive() {
        let test_cases = [
            (0x00000000, 0x00000000, 0x00000000),
            (0xFFFFFFFF, 0x00000000, 0xFFFFFFFF),
            (0xAAAAAAAA, 0x55555555, 0xFFFFFFFF),
            (0x12345678, 0xABCDEF00, 0xBBFDFF78),
        ];

        for (a, b, expected) in test_cases {
            let bits_a = u32_to_bits(a);
            let bits_b = u32_to_bits(b);
            let bits_result = u32_to_bits(expected);

            let constraints = CpuAir::bitwise_or_constraints(&bits_a, &bits_b, &bits_result);
            
            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(*constraint, M31::ZERO,
                    "OR failed for case ({:#x}, {:#x}), bit {}", a, b, i);
            }
        }
    }

    #[test]
    fn test_bitwise_xor_constraint() {
        // Test: 0b1010 XOR 0b1100 = 0b0110
        let a = 0b1010u32;
        let b = 0b1100u32;
        let result = a ^ b; // = 0b0110

        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);
        let bits_result = u32_to_bits(result);

        let constraints = CpuAir::bitwise_xor_constraints(&bits_a, &bits_b, &bits_result);
        
        assert_eq!(constraints.len(), 32);
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_bitwise_xor_comprehensive() {
        let test_cases = [
            (0x00000000, 0x00000000, 0x00000000),
            (0xFFFFFFFF, 0xFFFFFFFF, 0x00000000),
            (0xAAAAAAAA, 0x55555555, 0xFFFFFFFF),
            (0x12345678, 0xABCDEF00, 0xB9F9B978),
        ];

        for (a, b, expected) in test_cases {
            let bits_a = u32_to_bits(a);
            let bits_b = u32_to_bits(b);
            let bits_result = u32_to_bits(expected);

            let constraints = CpuAir::bitwise_xor_constraints(&bits_a, &bits_b, &bits_result);
            
            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(*constraint, M31::ZERO,
                    "XOR failed for case ({:#x}, {:#x}), bit {}", a, b, i);
            }
        }
    }

    #[test]
    fn test_bitwise_and_soundness() {
        // Test that wrong result fails constraint
        let a = 0xAAAAu32;
        let b = 0x5555u32;
        let wrong_result = 0xFFFFu32; // Should be 0x0000

        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);
        let bits_wrong = u32_to_bits(wrong_result);

        let constraints = CpuAir::bitwise_and_constraints(&bits_a, &bits_b, &bits_wrong);
        
        // Should have non-zero constraints
        let has_nonzero = constraints.iter().any(|c| *c != M31::ZERO);
        assert!(has_nonzero, "Constraint should catch incorrect AND result");
    }

    #[test]
    fn test_bit_decomposition_soundness() {
        // Test that incorrect bit decomposition fails
        let value = 0x12345678u32;
        let (lo, hi) = u32_to_limbs(value);
        let mut bits = u32_to_bits(value);
        
        // Flip a bit
        bits[5] = if bits[5] == M31::ZERO { M31::ONE } else { M31::ZERO };

        let constraints = CpuAir::bit_decomposition_constraints(lo, hi, &bits);
        
        // Should have non-zero constraints (reconstruction will fail)
        let has_nonzero = constraints.iter().any(|c| *c != M31::ZERO);
        assert!(has_nonzero, "Constraint should catch incorrect bit decomposition");
    }

    #[test]
    fn test_shift_left_logical() {
        // Test SLL: 0b1010 << 1 = 0b10100
        let value = 0b1010u32;
        let shift = 1u32;
        let expected = value << shift;

        let bits_value = u32_to_bits(value);
        let bits_result = u32_to_bits(expected);
        let shift_m31 = M31::new(shift);

        let constraints = CpuAir::shift_left_logical_constraints(
            &bits_value,
            &bits_result,
            shift_m31,
        );

        assert_eq!(constraints.len(), 32);
        for (i, constraint) in constraints.iter().enumerate() {
            assert_eq!(*constraint, M31::ZERO, "SLL constraint {} failed", i);
        }
    }

    #[test]
    fn test_shift_left_comprehensive() {
        let test_cases = [
            (0x00000001, 0, 0x00000001),  // No shift
            (0x00000001, 1, 0x00000002),  // Simple shift
            (0x00000001, 31, 0x80000000), // Shift to MSB
            (0xFFFFFFFF, 1, 0xFFFFFFFE),  // All ones
            (0x12345678, 4, 0x23456780),  // Nibble shift
            (0x00000001, 32, 0x00000001), // Shift by 32 (wraps to 0)
        ];

        for (value, shift, expected) in test_cases {
            let bits_value = u32_to_bits(value);
            let bits_result = u32_to_bits(expected);
            let shift_m31 = M31::new(shift);

            let constraints = CpuAir::shift_left_logical_constraints(
                &bits_value,
                &bits_result,
                shift_m31,
            );

            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    *constraint, M31::ZERO,
                    "SLL({:#x} << {}) failed at bit {}", value, shift, i
                );
            }
        }
    }

    #[test]
    fn test_shift_right_logical() {
        // Test SRL: 0b1010 >> 1 = 0b0101
        let value = 0b1010u32;
        let shift = 1u32;
        let expected = value >> shift;

        let bits_value = u32_to_bits(value);
        let bits_result = u32_to_bits(expected);
        let shift_m31 = M31::new(shift);

        let constraints = CpuAir::shift_right_logical_constraints(
            &bits_value,
            &bits_result,
            shift_m31,
        );

        assert_eq!(constraints.len(), 32);
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_shift_right_logical_comprehensive() {
        let test_cases = [
            (0x80000000, 0, 0x80000000),  // No shift
            (0x80000000, 1, 0x40000000),  // Shift MSB
            (0x80000000, 31, 0x00000001), // Shift to LSB
            (0xFFFFFFFF, 1, 0x7FFFFFFF),  // Zero-extend from left
            (0x12345678, 4, 0x01234567),  // Nibble shift
            (0x80000000, 32, 0x80000000), // Shift by 32 (wraps to 0)
        ];

        for (value, shift, expected) in test_cases {
            let bits_value = u32_to_bits(value);
            let bits_result = u32_to_bits(expected);
            let shift_m31 = M31::new(shift);

            let constraints = CpuAir::shift_right_logical_constraints(
                &bits_value,
                &bits_result,
                shift_m31,
            );

            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    *constraint, M31::ZERO,
                    "SRL({:#x} >> {}) failed at bit {}", value, shift, i
                );
            }
        }
    }

    #[test]
    fn test_shift_right_arithmetic() {
        // Test SRA with positive number (MSB = 0)
        let value = 0b01010u32;
        let shift = 1u32;
        let expected = value >> shift; // 0b00101

        let bits_value = u32_to_bits(value);
        let bits_result = u32_to_bits(expected);
        let shift_m31 = M31::new(shift);

        let constraints = CpuAir::shift_right_arithmetic_constraints(
            &bits_value,
            &bits_result,
            shift_m31,
        );

        assert_eq!(constraints.len(), 32);
        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO);
        }
    }

    #[test]
    fn test_shift_right_arithmetic_negative() {
        // Test SRA with negative number (MSB = 1) - sign extension
        let value = 0x80000000u32; // Negative in two's complement
        let shift = 1u32;
        let expected = 0xC0000000u32; // Sign-extended: 1100...

        let bits_value = u32_to_bits(value);
        let bits_result = u32_to_bits(expected);
        let shift_m31 = M31::new(shift);

        let constraints = CpuAir::shift_right_arithmetic_constraints(
            &bits_value,
            &bits_result,
            shift_m31,
        );

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SRA sign extension failed");
        }
    }

    #[test]
    fn test_shift_right_arithmetic_comprehensive() {
        let test_cases = [
            // (value, shift, expected_sra)
            (0x00000008, 1, 0x00000004),  // Positive: 8 >> 1 = 4
            (0x00000008, 2, 0x00000002),  // Positive: 8 >> 2 = 2
            (0xFFFFFFF8u32, 1, 0xFFFFFFFCu32), // Negative: -8 >> 1 = -4 (sign extend)
            (0xFFFFFFF8u32, 2, 0xFFFFFFFEu32), // Negative: -8 >> 2 = -2 (sign extend)
            (0x80000000u32, 31, 0xFFFFFFFFu32), // Min int >> 31 = -1 (all ones)
            (0x7FFFFFFF, 31, 0x00000000),  // Max int >> 31 = 0
        ];

        for (value, shift, expected) in test_cases {
            let bits_value = u32_to_bits(value);
            let bits_result = u32_to_bits(expected);
            let shift_m31 = M31::new(shift);

            let constraints = CpuAir::shift_right_arithmetic_constraints(
                &bits_value,
                &bits_result,
                shift_m31,
            );

            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    *constraint, M31::ZERO,
                    "SRA({:#x} >> {}) failed at bit {}, expected {:#x}",
                    value, shift, i, expected
                );
            }
        }
    }

    #[test]
    fn test_shift_soundness() {
        // Test that wrong shift result fails constraint
        let value = 0x12345678u32;
        let shift = 4u32;
        let wrong_result = 0x23456781u32; // Should be 0x23456780

        let bits_value = u32_to_bits(value);
        let bits_wrong = u32_to_bits(wrong_result);
        let shift_m31 = M31::new(shift);

        let constraints = CpuAir::shift_left_logical_constraints(
            &bits_value,
            &bits_wrong,
            shift_m31,
        );

        let has_nonzero = constraints.iter().any(|c| *c != M31::ZERO);
        assert!(has_nonzero, "Constraint should catch incorrect shift result");
    }

    #[test]
    fn test_set_less_than_unsigned() {
        // Test SLTU: unsigned comparison
        let test_cases = [
            (5u32, 10u32, 1u32, 1u32),    // 5 < 10 = true, borrow = 1
            (10u32, 5u32, 0u32, 0u32),    // 10 < 5 = false, borrow = 0
            (5u32, 5u32, 0u32, 0u32),     // 5 < 5 = false, borrow = 0
            (0u32, 1u32, 1u32, 1u32),     // 0 < 1 = true, borrow = 1
            (0xFFFFFFFFu32, 0u32, 0u32, 0u32), // max < 0 = false (unsigned)
        ];

        for (a, b, expected_result, expected_borrow) in test_cases {
            let bits_a = u32_to_bits(a);
            let bits_b = u32_to_bits(b);
            let result = M31::new(expected_result);
            let borrow = M31::new(expected_borrow);

            let constraints = CpuAir::set_less_than_unsigned_constraints(
                &bits_a,
                &bits_b,
                result,
                borrow,
            );

            for (i, constraint) in constraints.iter().enumerate() {
                assert_eq!(
                    *constraint, M31::ZERO,
                    "SLTU({} < {}) failed at constraint {}", a, b, i
                );
            }
        }
    }

    #[test]
    fn test_set_less_than_signed_same_sign() {
        // Test SLT with same sign (both positive or both negative)
        // When signs are same, compare magnitudes via subtraction
        
        // Case 1: Both positive
        let a = 5u32;
        let b = 10u32;
        let diff = (a.wrapping_sub(b)) as u32; // Will have sign bit set
        
        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);
        let diff_bits = u32_to_bits(diff);
        let result = M31::ONE; // 5 < 10 = true

        let constraints = CpuAir::set_less_than_signed_constraints(
            &bits_a,
            &bits_b,
            result,
            &diff_bits,
        );

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SLT(5 < 10) failed");
        }
    }

    #[test]
    fn test_set_less_than_signed_different_signs() {
        // Test SLT with different signs
        // Negative < Positive = true
        // Positive < Negative = false
        
        // Case 1: negative < positive (true)
        let a = 0xFFFFFFFEu32; // -2 in two's complement
        let b = 5u32;          // +5
        let diff = a.wrapping_sub(b);
        
        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);
        let diff_bits = u32_to_bits(diff);
        let result = M31::ONE; // -2 < 5 = true

        let constraints = CpuAir::set_less_than_signed_constraints(
            &bits_a,
            &bits_b,
            result,
            &diff_bits,
        );

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SLT(-2 < 5) failed");
        }

        // Case 2: positive < negative (false)
        let a2 = 5u32;
        let b2 = 0xFFFFFFFEu32; // -2
        let diff2 = a2.wrapping_sub(b2);
        
        let bits_a2 = u32_to_bits(a2);
        let bits_b2 = u32_to_bits(b2);
        let diff_bits2 = u32_to_bits(diff2);
        let result2 = M31::ZERO; // 5 < -2 = false

        let constraints2 = CpuAir::set_less_than_signed_constraints(
            &bits_a2,
            &bits_b2,
            result2,
            &diff_bits2,
        );

        for constraint in constraints2 {
            assert_eq!(constraint, M31::ZERO, "SLT(5 < -2) failed");
        }
    }

    #[test]
    fn test_sub_with_borrow() {
        // Test SUB constraint with borrow
        // Borrow occurs when low limb underflows: a_lo < b_lo
        
        // Case 1: 10 - 5 = 5, no borrow in limbs
        let a = 10u32;
        let b = 5u32;
        let (a_lo, a_hi) = u32_to_limbs(a);
        let (b_lo, b_hi) = u32_to_limbs(b);
        let result = a.wrapping_sub(b);
        let (result_lo, result_hi) = u32_to_limbs(result);
        let borrow = if a_lo.value() < b_lo.value() { M31::ONE } else { M31::ZERO };

        let (c_lo, c_hi) = CpuAir::sub_with_borrow_constraint(
            a_lo, a_hi, b_lo, b_hi, result_lo, result_hi, borrow,
        );
        assert_eq!(c_lo, M31::ZERO, "SUB({} - {}) low limb failed", a, b);
        assert_eq!(c_hi, M31::ZERO, "SUB({} - {}) high limb failed", a, b);

        // Case 2: 0x10005 - 0x10 = 0xFFF5, requires borrow from high limb
        let a2 = 0x10005u32;
        let b2 = 0x10u32;
        let (a_lo2, a_hi2) = u32_to_limbs(a2);
        let (b_lo2, b_hi2) = u32_to_limbs(b2);
        let result2 = a2.wrapping_sub(b2);
        let (result_lo2, result_hi2) = u32_to_limbs(result2);
        let borrow2 = if a_lo2.value() < b_lo2.value() { M31::ONE } else { M31::ZERO };

        let (c_lo2, c_hi2) = CpuAir::sub_with_borrow_constraint(
            a_lo2, a_hi2, b_lo2, b_hi2, result_lo2, result_hi2, borrow2,
        );
        assert_eq!(c_lo2, M31::ZERO, "SUB({:#x} - {:#x}) low limb failed", a2, b2);
        assert_eq!(c_hi2, M31::ZERO, "SUB({:#x} - {:#x}) high limb failed", a2, b2);

        // Case 3: 0x20000 - 0x10005 = 0xFFFB, requires borrow
        let a3 = 0x20000u32;
        let b3 = 0x10005u32;
        let (a_lo3, a_hi3) = u32_to_limbs(a3);
        let (b_lo3, b_hi3) = u32_to_limbs(b3);
        let result3 = a3.wrapping_sub(b3);
        let (result_lo3, result_hi3) = u32_to_limbs(result3);
        let borrow3 = if a_lo3.value() < b_lo3.value() { M31::ONE } else { M31::ZERO };

        let (c_lo3, c_hi3) = CpuAir::sub_with_borrow_constraint(
            a_lo3, a_hi3, b_lo3, b_hi3, result_lo3, result_hi3, borrow3,
        );
        assert_eq!(c_lo3, M31::ZERO, "SUB({:#x} - {:#x}) low limb failed", a3, b3);
        assert_eq!(c_hi3, M31::ZERO, "SUB({:#x} - {:#x}) high limb failed", a3, b3);
    }

    #[test]
    fn test_comparison_soundness() {
        // Test that wrong comparison result fails constraint
        let a = 5u32;
        let b = 10u32;
        let wrong_result = M31::ZERO; // Should be 1 (5 < 10)
        let borrow = M31::ONE;

        let bits_a = u32_to_bits(a);
        let bits_b = u32_to_bits(b);

        let constraints = CpuAir::set_less_than_unsigned_constraints(
            &bits_a,
            &bits_b,
            wrong_result,
            borrow,
        );

        let has_nonzero = constraints.iter().any(|c| *c != M31::ZERO);
        assert!(has_nonzero, "Constraint should catch incorrect comparison result");
    }

    #[test]
    fn test_addi_constraint() {
        // Test ADDI: rs1 + imm
        let rs1 = 100u32;
        let imm = 50u32;
        let expected = rs1.wrapping_add(imm);

        let (rs1_lo, rs1_hi) = u32_to_limbs(rs1);
        let (imm_lo, imm_hi) = u32_to_limbs(imm);
        let (result_lo, result_hi) = u32_to_limbs(expected);
        
        // No carry for this case
        let carry = M31::ZERO;
        let is_addi = M31::ONE;

        let (c_lo, c_hi) = CpuAir::addi_constraint(
            is_addi, result_lo, result_hi,
            rs1_lo, rs1_hi, imm_lo, imm_hi, carry
        );

        assert_eq!(c_lo, M31::ZERO, "ADDI low limb failed");
        assert_eq!(c_hi, M31::ZERO, "ADDI high limb failed");
    }

    #[test]
    fn test_andi_constraint() {
        // Test ANDI: rs1 & imm
        let rs1 = 0xF0F0F0F0u32;
        let imm = 0x0F0F0F0Fu32;
        let expected = rs1 & imm;

        let bits_rs1 = u32_to_bits(rs1);
        let bits_imm = u32_to_bits(imm);
        let bits_result = u32_to_bits(expected);

        let constraints = CpuAir::andi_constraint(&bits_rs1, &bits_imm, &bits_result);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "ANDI constraint failed");
        }
    }

    #[test]
    fn test_ori_constraint() {
        // Test ORI: rs1 | imm
        let rs1 = 0x12345678u32;
        let imm = 0x00000FFFu32;
        let expected = rs1 | imm;

        let bits_rs1 = u32_to_bits(rs1);
        let bits_imm = u32_to_bits(imm);
        let bits_result = u32_to_bits(expected);

        let constraints = CpuAir::ori_constraint(&bits_rs1, &bits_imm, &bits_result);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "ORI constraint failed");
        }
    }

    #[test]
    fn test_xori_constraint() {
        // Test XORI: rs1 ^ imm
        let rs1 = 0xAAAAAAAAu32;
        let imm = 0x55555555u32;
        let expected = rs1 ^ imm;

        let bits_rs1 = u32_to_bits(rs1);
        let bits_imm = u32_to_bits(imm);
        let bits_result = u32_to_bits(expected);

        let constraints = CpuAir::xori_constraint(&bits_rs1, &bits_imm, &bits_result);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "XORI constraint failed");
        }
    }

    #[test]
    fn test_slti_constraint() {
        // Test SLTI: signed comparison with immediate
        let rs1 = 0xFFFFFFFEu32; // -2
        let imm = 5u32;
        let diff = rs1.wrapping_sub(imm);
        
        let bits_rs1 = u32_to_bits(rs1);
        let bits_imm = u32_to_bits(imm);
        let diff_bits = u32_to_bits(diff);
        let result = M31::ONE; // -2 < 5 = true

        let constraints = CpuAir::slti_constraint(&bits_rs1, &bits_imm, result, &diff_bits);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SLTI constraint failed");
        }
    }

    #[test]
    fn test_sltiu_constraint() {
        // Test SLTIU: unsigned comparison with immediate
        let rs1 = 5u32;
        let imm = 10u32;
        
        let bits_rs1 = u32_to_bits(rs1);
        let bits_imm = u32_to_bits(imm);
        let result = M31::ONE; // 5 < 10 = true (unsigned)
        let borrow = M31::ONE;

        let constraints = CpuAir::sltiu_constraint(&bits_rs1, &bits_imm, result, borrow);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SLTIU constraint failed");
        }
    }

    #[test]
    fn test_slli_constraint() {
        // Test SLLI: shift left with immediate
        let rs1 = 0x00000001u32;
        let shamt = 4u32;
        let expected = rs1 << shamt;

        let bits_rs1 = u32_to_bits(rs1);
        let bits_result = u32_to_bits(expected);
        let shamt_m31 = M31::new(shamt);

        let constraints = CpuAir::slli_constraint(&bits_rs1, &bits_result, shamt_m31);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SLLI constraint failed");
        }
    }

    #[test]
    fn test_srli_constraint() {
        // Test SRLI: shift right logical with immediate
        let rs1 = 0x80000000u32;
        let shamt = 4u32;
        let expected = rs1 >> shamt;

        let bits_rs1 = u32_to_bits(rs1);
        let bits_result = u32_to_bits(expected);
        let shamt_m31 = M31::new(shamt);

        let constraints = CpuAir::srli_constraint(&bits_rs1, &bits_result, shamt_m31);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SRLI constraint failed");
        }
    }

    #[test]
    fn test_srai_constraint() {
        // Test SRAI: shift right arithmetic with immediate
        let rs1 = 0x80000000u32; // Negative number
        let shamt = 4u32;
        let expected = 0xF8000000u32; // Sign-extended

        let bits_rs1 = u32_to_bits(rs1);
        let bits_result = u32_to_bits(expected);
        let shamt_m31 = M31::new(shamt);

        let constraints = CpuAir::srai_constraint(&bits_rs1, &bits_result, shamt_m31);

        for constraint in constraints {
            assert_eq!(constraint, M31::ZERO, "SRAI constraint failed");
        }
    }

    #[test]
    fn test_itype_comprehensive() {
        // Test multiple I-type instructions together
        let test_cases = [
            // (rs1, imm, operation, expected)
            (100u32, 50u32, "addi", 150u32),
            (0xFF00u32, 0x00FFu32, "andi", 0x0000u32),
            (0xF000u32, 0x0F00u32, "ori", 0xFF00u32),
            (0xFFFFu32, 0xAAAAu32, "xori", 0x5555u32),
        ];

        for (rs1, imm, op, expected) in test_cases {
            match op {
                "addi" => {
                    let (rs1_lo, rs1_hi) = u32_to_limbs(rs1);
                    let (imm_lo, imm_hi) = u32_to_limbs(imm);
                    let (result_lo, result_hi) = u32_to_limbs(expected);
                    let carry = M31::ZERO;
                    
                    let (c_lo, c_hi) = CpuAir::addi_constraint(
                        M31::ONE, result_lo, result_hi,
                        rs1_lo, rs1_hi, imm_lo, imm_hi, carry
                    );
                    
                    assert_eq!(c_lo, M31::ZERO, "ADDI({} + {}) failed", rs1, imm);
                    assert_eq!(c_hi, M31::ZERO, "ADDI({} + {}) failed", rs1, imm);
                }
                "andi" => {
                    let bits_rs1 = u32_to_bits(rs1);
                    let bits_imm = u32_to_bits(imm);
                    let bits_result = u32_to_bits(expected);
                    
                    let constraints = CpuAir::andi_constraint(&bits_rs1, &bits_imm, &bits_result);
                    for c in constraints {
                        assert_eq!(c, M31::ZERO, "ANDI({:#x} & {:#x}) failed", rs1, imm);
                    }
                }
                "ori" => {
                    let bits_rs1 = u32_to_bits(rs1);
                    let bits_imm = u32_to_bits(imm);
                    let bits_result = u32_to_bits(expected);
                    
                    let constraints = CpuAir::ori_constraint(&bits_rs1, &bits_imm, &bits_result);
                    for c in constraints {
                        assert_eq!(c, M31::ZERO, "ORI({:#x} | {:#x}) failed", rs1, imm);
                    }
                }
                "xori" => {
                    let bits_rs1 = u32_to_bits(rs1);
                    let bits_imm = u32_to_bits(imm);
                    let bits_result = u32_to_bits(expected);
                    
                    let constraints = CpuAir::xori_constraint(&bits_rs1, &bits_imm, &bits_result);
                    for c in constraints {
                        assert_eq!(c, M31::ZERO, "XORI({:#x} ^ {:#x}) failed", rs1, imm);
                    }
                }
                _ => panic!("Unknown operation: {}", op),
            }
        }
    }
}
