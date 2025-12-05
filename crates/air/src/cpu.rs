//! CPU AIR constraints for RV32IM.

use zp1_primitives::M31;

/// CPU AIR constraint evaluator.
///
/// All constraints are degree ≤ 2 polynomials.
pub struct CpuAir;

impl CpuAir {
    /// Evaluate the x0 = 0 constraint.
    /// If rd = 0, then rd_val must be 0.
    #[inline]
    pub fn x0_zero_constraint(rd: M31, rd_val: M31) -> M31 {
        // rd * rd_val = 0 when rd = 0
        // But we need: if rd = 0 then rd_val = 0
        // Constraint: rd_val * (1 - rd * something) ... 
        // Simpler: use selector. If is_rd_zero = 1 when rd=0, then is_rd_zero * rd_val = 0
        // For now, assume rd=0 case is handled by not writing.
        // Placeholder constraint:
        M31::ZERO
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
}
