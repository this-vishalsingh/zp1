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
}
