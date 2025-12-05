//! U256 bigint delegation gadgets.
//!
//! Provides trace generation and constraints for 256-bit integer operations.

use zp1_primitives::M31;

/// A 256-bit unsigned integer represented as 16 x 16-bit limbs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct U256 {
    /// Limbs in little-endian order (limbs[0] is least significant).
    pub limbs: [u16; 16],
}

impl U256 {
    /// Zero.
    pub const ZERO: Self = Self { limbs: [0; 16] };

    /// One.
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };

    /// Create from bytes (little-endian).
    pub fn from_le_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u16; 16];
        for i in 0..16 {
            limbs[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
        }
        Self { limbs }
    }

    /// Convert to bytes (little-endian).
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..16 {
            let limb_bytes = self.limbs[i].to_le_bytes();
            bytes[2 * i] = limb_bytes[0];
            bytes[2 * i + 1] = limb_bytes[1];
        }
        bytes
    }

    /// Convert to M31 limbs (for AIR).
    pub fn to_m31_limbs(&self) -> [M31; 16] {
        let mut result = [M31::ZERO; 16];
        for i in 0..16 {
            result[i] = M31::new(self.limbs[i] as u32);
        }
        result
    }

    /// Create from M31 limbs.
    pub fn from_m31_limbs(limbs: &[M31; 16]) -> Self {
        let mut result = Self::ZERO;
        for i in 0..16 {
            result.limbs[i] = limbs[i].as_u32() as u16;
        }
        result
    }
}

/// Trace row for U256 addition.
#[derive(Clone, Debug)]
pub struct U256AddTrace {
    /// First operand limbs.
    pub a: [M31; 16],
    /// Second operand limbs.
    pub b: [M31; 16],
    /// Result limbs.
    pub result: [M31; 16],
    /// Carry bits (intermediate).
    pub carries: [M31; 16],
    /// Overflow bit.
    pub overflow: M31,
}

/// Generate trace for U256 addition.
pub fn u256_add_trace(a: &U256, b: &U256) -> (U256, U256AddTrace) {
    let mut result = U256::ZERO;
    let mut carries = [M31::ZERO; 16];
    let mut carry = 0u32;

    for i in 0..16 {
        let sum = (a.limbs[i] as u32) + (b.limbs[i] as u32) + carry;
        result.limbs[i] = (sum & 0xFFFF) as u16;
        carry = sum >> 16;
        carries[i] = M31::new(carry);
    }

    let overflow = M31::new(carry);

    let trace = U256AddTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result: result.to_m31_limbs(),
        carries,
        overflow,
    };

    (result, trace)
}

/// Trace row for U256 multiplication (produces 512-bit result).
#[derive(Clone, Debug)]
pub struct U256MulTrace {
    /// First operand limbs.
    pub a: [M31; 16],
    /// Second operand limbs.
    pub b: [M31; 16],
    /// Result low 256 bits.
    pub result_lo: [M31; 16],
    /// Result high 256 bits.
    pub result_hi: [M31; 16],
    /// Intermediate partial products and carries.
    pub partials: Vec<M31>,
}

/// Generate trace for U256 multiplication (schoolbook).
pub fn u256_mul_trace(a: &U256, b: &U256) -> (U256, U256, U256MulTrace) {
    // Full 512-bit result
    let mut result = [0u64; 32];

    for i in 0..16 {
        for j in 0..16 {
            let prod = (a.limbs[i] as u64) * (b.limbs[j] as u64);
            let idx = i + j;
            result[idx] += prod;
        }
    }

    // Propagate carries
    for i in 0..31 {
        result[i + 1] += result[i] >> 16;
        result[i] &= 0xFFFF;
    }

    // Split into low and high
    let mut result_lo = U256::ZERO;
    let mut result_hi = U256::ZERO;

    for i in 0..16 {
        result_lo.limbs[i] = result[i] as u16;
        result_hi.limbs[i] = result[i + 16] as u16;
    }

    let trace = U256MulTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result_lo: result_lo.to_m31_limbs(),
        result_hi: result_hi.to_m31_limbs(),
        partials: Vec::new(), // Would contain intermediate values for full constraint
    };

    (result_lo, result_hi, trace)
}

/// Constraint for U256 addition (degree 2).
/// For each limb i: result[i] + carry[i] * 2^16 = a[i] + b[i] + carry[i-1]
pub fn u256_add_constraint(
    a: M31,
    b: M31,
    result: M31,
    carry_in: M31,
    carry_out: M31,
) -> M31 {
    let two_16 = M31::new(1 << 16);
    result + carry_out * two_16 - a - b - carry_in
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_add() {
        let a = U256 {
            limbs: [0xFFFF, 0xFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b = U256::ONE;

        let (result, _trace) = u256_add_trace(&a, &b);

        // 0xFFFF_FFFF + 1 = 0x1_0000_0000
        assert_eq!(result.limbs[0], 0);
        assert_eq!(result.limbs[1], 0);
        assert_eq!(result.limbs[2], 1);
    }

    #[test]
    fn test_u256_mul() {
        let a = U256 {
            limbs: [100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let b = U256 {
            limbs: [200, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };

        let (result_lo, result_hi, _trace) = u256_mul_trace(&a, &b);

        // 100 * 200 = 20000
        assert_eq!(result_lo.limbs[0], 20000);
        assert_eq!(result_hi.limbs[0], 0);
    }
}
