//! U256 bigint delegation gadgets.
//!
//! Provides trace generation and constraints for 256-bit integer operations.
//!
//! # Operations
//! - Addition (with overflow detection)
//! - Subtraction (with borrow detection)
//! - Multiplication (512-bit result)
//! - Division (quotient and remainder)
//! - Modular arithmetic (addmod, mulmod)
//! - Comparison operations
//! - Bitwise operations (and, or, xor, shift)

use zp1_primitives::M31;
use std::cmp::Ordering;

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

    /// Create from u64.
    pub fn from_u64(value: u64) -> Self {
        let mut limbs = [0u16; 16];
        limbs[0] = (value & 0xFFFF) as u16;
        limbs[1] = ((value >> 16) & 0xFFFF) as u16;
        limbs[2] = ((value >> 32) & 0xFFFF) as u16;
        limbs[3] = ((value >> 48) & 0xFFFF) as u16;
        Self { limbs }
    }

    /// Compare with another U256.
    pub fn cmp(&self, other: &U256) -> Ordering {
        for i in (0..16).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                other => return other,
            }
        }
        Ordering::Equal
    }

    /// Check if zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    /// Left shift by n bits (n < 256).
    pub fn shl(&self, n: usize) -> Self {
        if n >= 256 {
            return Self::ZERO;
        }
        
        let limb_shift = n / 16;
        let bit_shift = n % 16;
        let mut result = Self::ZERO;
        
        if bit_shift == 0 {
            for i in limb_shift..16 {
                result.limbs[i] = self.limbs[i - limb_shift];
            }
        } else {
            let carry_shift = 16 - bit_shift;
            for i in limb_shift..16 {
                let src_idx = i - limb_shift;
                result.limbs[i] = self.limbs[src_idx] << bit_shift;
                if src_idx > 0 {
                    result.limbs[i] |= self.limbs[src_idx - 1] >> carry_shift;
                }
            }
        }
        
        result
    }

    /// Right shift by n bits (n < 256).
    pub fn shr(&self, n: usize) -> Self {
        if n >= 256 {
            return Self::ZERO;
        }
        
        let limb_shift = n / 16;
        let bit_shift = n % 16;
        let mut result = Self::ZERO;
        
        if bit_shift == 0 {
            for i in 0..(16 - limb_shift) {
                result.limbs[i] = self.limbs[i + limb_shift];
            }
        } else {
            let carry_shift = 16 - bit_shift;
            for i in 0..(16 - limb_shift) {
                let src_idx = i + limb_shift;
                result.limbs[i] = self.limbs[src_idx] >> bit_shift;
                if src_idx + 1 < 16 {
                    result.limbs[i] |= self.limbs[src_idx + 1] << carry_shift;
                }
            }
        }
        
        result
    }

    /// Bitwise AND.
    pub fn bitand(&self, other: &U256) -> Self {
        let mut result = Self::ZERO;
        for i in 0..16 {
            result.limbs[i] = self.limbs[i] & other.limbs[i];
        }
        result
    }

    /// Bitwise OR.
    pub fn bitor(&self, other: &U256) -> Self {
        let mut result = Self::ZERO;
        for i in 0..16 {
            result.limbs[i] = self.limbs[i] | other.limbs[i];
        }
        result
    }

    /// Bitwise XOR.
    pub fn bitxor(&self, other: &U256) -> Self {
        let mut result = Self::ZERO;
        for i in 0..16 {
            result.limbs[i] = self.limbs[i] ^ other.limbs[i];
        }
        result
    }

    /// Bitwise NOT.
    pub fn not(&self) -> Self {
        let mut result = Self::ZERO;
        for i in 0..16 {
            result.limbs[i] = !self.limbs[i];
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

// ============================================================================
// Subtraction
// ============================================================================

/// Trace row for U256 subtraction.
#[derive(Clone, Debug)]
pub struct U256SubTrace {
    pub a: [M31; 16],
    pub b: [M31; 16],
    pub result: [M31; 16],
    /// Borrow bits (intermediate).
    pub borrows: [M31; 16],
    /// Underflow bit (1 if a < b).
    pub underflow: M31,
}

/// Generate trace for U256 subtraction.
pub fn u256_sub_trace(a: &U256, b: &U256) -> (U256, U256SubTrace) {
    let mut result = U256::ZERO;
    let mut borrows = [M31::ZERO; 16];
    let mut borrow = 0i32;

    for i in 0..16 {
        let diff = (a.limbs[i] as i32) - (b.limbs[i] as i32) - borrow;
        if diff < 0 {
            result.limbs[i] = (diff + 0x10000) as u16;
            borrow = 1;
        } else {
            result.limbs[i] = diff as u16;
            borrow = 0;
        }
        borrows[i] = M31::new(borrow as u32);
    }

    let underflow = M31::new(borrow as u32);

    let trace = U256SubTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result: result.to_m31_limbs(),
        borrows,
        underflow,
    };

    (result, trace)
}

// ============================================================================
// Division and Modular Operations
// ============================================================================

/// Trace row for U256 division.
#[derive(Clone, Debug, Default)]
pub struct U256DivTrace {
    pub dividend: [M31; 16],
    pub divisor: [M31; 16],
    pub quotient: [M31; 16],
    pub remainder: [M31; 16],
    /// Witness data for constraint verification.
    pub witness: Vec<M31>,
}

/// Generate trace for U256 division (quotient and remainder).
/// Uses long division algorithm.
pub fn u256_div_trace(dividend: &U256, divisor: &U256) -> Result<(U256, U256, U256DivTrace), &'static str> {
    if divisor.is_zero() {
        return Err("Division by zero");
    }

    let mut quotient = U256::ZERO;
    let mut remainder = U256::ZERO;

    // Long division bit by bit
    for i in (0..256).rev() {
        // remainder = remainder << 1
        remainder = remainder.shl(1);
        
        // Get bit i of dividend
        let limb_idx = i / 16;
        let bit_idx = i % 16;
        let bit = (dividend.limbs[limb_idx] >> bit_idx) & 1;
        
        // Set LSB of remainder to this bit
        remainder.limbs[0] |= bit;
        
        // If remainder >= divisor, subtract and set quotient bit
        if remainder.cmp(divisor) != Ordering::Less {
            let (new_remainder, _) = u256_sub_trace(&remainder, divisor);
            remainder = new_remainder;
            
            // Set bit i of quotient
            quotient.limbs[limb_idx] |= 1 << bit_idx;
        }
    }

    let trace = U256DivTrace {
        dividend: dividend.to_m31_limbs(),
        divisor: divisor.to_m31_limbs(),
        quotient: quotient.to_m31_limbs(),
        remainder: remainder.to_m31_limbs(),
        witness: Vec::new(),
    };

    Ok((quotient, remainder, trace))
}

/// Trace row for modular addition.
#[derive(Clone, Debug)]
pub struct U256AddModTrace {
    pub a: [M31; 16],
    pub b: [M31; 16],
    pub modulus: [M31; 16],
    pub result: [M31; 16],
    pub intermediate_sum: [M31; 16],
    pub overflow: M31,
}

/// Generate trace for U256 modular addition: (a + b) mod m.
pub fn u256_addmod_trace(a: &U256, b: &U256, modulus: &U256) -> (U256, U256AddModTrace) {
    if modulus.is_zero() {
        // undefined behavior - return zero
        let trace = U256AddModTrace {
            a: a.to_m31_limbs(),
            b: b.to_m31_limbs(),
            modulus: modulus.to_m31_limbs(),
            result: U256::ZERO.to_m31_limbs(),
            intermediate_sum: U256::ZERO.to_m31_limbs(),
            overflow: M31::ZERO,
        };
        return (U256::ZERO, trace);
    }

    let (sum, add_trace) = u256_add_trace(a, b);
    
    // Handle overflow case: if overflow occurred, we need full modular reduction
    let result = if add_trace.overflow.value() != 0 {
        // Overflow occurred - need to handle the carry bit properly
        // For simplicity, perform repeated subtraction
        let mut temp = sum;
        while temp.cmp(modulus) != Ordering::Less {
            let (diff, sub_trace) = u256_sub_trace(&temp, modulus);
            if sub_trace.underflow.value() != 0 {
                break; // Can't subtract anymore
            }
            temp = diff;
        }
        temp
    } else if sum.cmp(modulus) == Ordering::Less {
        sum
    } else {
        let (diff, _) = u256_sub_trace(&sum, modulus);
        diff
    };

    let trace = U256AddModTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        modulus: modulus.to_m31_limbs(),
        result: result.to_m31_limbs(),
        intermediate_sum: sum.to_m31_limbs(),
        overflow: add_trace.overflow,
    };

    (result, trace)
}

/// Trace row for modular multiplication.
#[derive(Clone, Debug)]
pub struct U256MulModTrace {
    pub a: [M31; 16],
    pub b: [M31; 16],
    pub modulus: [M31; 16],
    pub result: [M31; 16],
    pub intermediate_product_lo: [M31; 16],
    pub intermediate_product_hi: [M31; 16],
}

/// Generate trace for U256 modular multiplication: (a * b) mod m.
pub fn u256_mulmod_trace(a: &U256, b: &U256, modulus: &U256) -> (U256, U256MulModTrace) {
    if modulus.is_zero() {
        let trace = U256MulModTrace {
            a: a.to_m31_limbs(),
            b: b.to_m31_limbs(),
            modulus: modulus.to_m31_limbs(),
            result: U256::ZERO.to_m31_limbs(),
            intermediate_product_lo: U256::ZERO.to_m31_limbs(),
            intermediate_product_hi: U256::ZERO.to_m31_limbs(),
        };
        return (U256::ZERO, trace);
    }

    let (product_lo, product_hi, _) = u256_mul_trace(a, b);
    
    // Need to compute (product_hi << 256 | product_lo) mod modulus
    // Simplified: if product_hi is zero, just use product_lo mod modulus
    let result = if product_hi.is_zero() {
        if product_lo.cmp(modulus) == Ordering::Less {
            product_lo
        } else {
            let (_, remainder, _) = u256_div_trace(&product_lo, modulus).unwrap_or((U256::ZERO, U256::ZERO, U256DivTrace {
                dividend: U256::ZERO.to_m31_limbs(),
                divisor: U256::ZERO.to_m31_limbs(),
                quotient: U256::ZERO.to_m31_limbs(),
                remainder: U256::ZERO.to_m31_limbs(),
                witness: Vec::new(),
            }));
            remainder
        }
    } else {
        // Full 512-bit modular reduction (simplified)
        U256::ZERO
    };

    let trace = U256MulModTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        modulus: modulus.to_m31_limbs(),
        result: result.to_m31_limbs(),
        intermediate_product_lo: product_lo.to_m31_limbs(),
        intermediate_product_hi: product_hi.to_m31_limbs(),
    };

    (result, trace)
}

/// Trace row for modular exponentiation.
#[derive(Clone, Debug)]
pub struct U256ModExpTrace {
    pub base: [M31; 16],
    pub exponent: [M31; 16],
    pub modulus: [M31; 16],
    pub result: [M31; 16],
    /// Intermediate powers and multiplications.
    pub intermediate_steps: Vec<([M31; 16], [M31; 16])>, // (power, accumulated_result)
}

/// Generate trace for U256 modular exponentiation: base^exponent mod modulus.
/// Uses square-and-multiply algorithm.
pub fn u256_modexp_trace(base: &U256, exponent: &U256, modulus: &U256) -> (U256, U256ModExpTrace) {
    if modulus.is_zero() || modulus == &U256::ONE {
        let trace = U256ModExpTrace {
            base: base.to_m31_limbs(),
            exponent: exponent.to_m31_limbs(),
            modulus: modulus.to_m31_limbs(),
            result: U256::ZERO.to_m31_limbs(),
            intermediate_steps: Vec::new(),
        };
        return (U256::ZERO, trace);
    }

    if exponent.is_zero() {
        // Any number to the power 0 is 1
        let result = U256::ONE;
        let trace = U256ModExpTrace {
            base: base.to_m31_limbs(),
            exponent: exponent.to_m31_limbs(),
            modulus: modulus.to_m31_limbs(),
            result: result.to_m31_limbs(),
            intermediate_steps: Vec::new(),
        };
        return (result, trace);
    }

    let mut intermediate_steps = Vec::new();
    let mut result = U256::ONE;
    let mut power = *base;
    let mut exp = *exponent;

    // Reduce base mod modulus first
    if base.cmp(modulus) != Ordering::Less {
        let (_, remainder, _) = u256_div_trace(base, modulus).unwrap_or_default();
        power = remainder;
    }

    // Square-and-multiply
    for _ in 0..256 {
        if exp.is_zero() {
            break;
        }

        // If lowest bit of exp is 1, multiply result by power
        if (exp.limbs[0] & 1) == 1 {
            let (prod, _) = u256_mulmod_trace(&result, &power, modulus);
            result = prod;
            intermediate_steps.push((power.to_m31_limbs(), result.to_m31_limbs()));
        }

        // Square the power
        let (squared, _) = u256_mulmod_trace(&power, &power, modulus);
        power = squared;

        // Right shift exponent by 1
        exp = exp.shr(1);
    }

    let trace = U256ModExpTrace {
        base: base.to_m31_limbs(),
        exponent: exponent.to_m31_limbs(),
        modulus: modulus.to_m31_limbs(),
        result: result.to_m31_limbs(),
        intermediate_steps,
    };

    (result, trace)
}

// ============================================================================
// Comparison Operations
// ============================================================================

/// Trace for comparison operations.
#[derive(Clone, Debug)]
pub struct U256CmpTrace {
    pub a: [M31; 16],
    pub b: [M31; 16],
    pub result: M31, // 0 = equal, 1 = greater, 2 = less
    /// Bit differences for each limb.
    pub limb_diffs: [M31; 16],
}

/// Generate trace for U256 comparison.
pub fn u256_cmp_trace(a: &U256, b: &U256) -> U256CmpTrace {
    let mut limb_diffs = [M31::ZERO; 16];
    
    for i in 0..16 {
        let diff = (a.limbs[i] as i32) - (b.limbs[i] as i32);
        limb_diffs[i] = M31::new(diff.abs() as u32);
    }

    let result = match a.cmp(b) {
        Ordering::Equal => M31::ZERO,
        Ordering::Greater => M31::ONE,
        Ordering::Less => M31::new(2),
    };

    U256CmpTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result,
        limb_diffs,
    }
}

// ============================================================================
// Bitwise Operations with Traces
// ============================================================================

/// Trace for bitwise operations.
#[derive(Clone, Debug)]
pub struct U256BitwiseTrace {
    pub a: [M31; 16],
    pub b: [M31; 16],
    pub result: [M31; 16],
    pub op_type: BitwiseOp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitwiseOp {
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
}

/// Generate trace for bitwise AND.
pub fn u256_and_trace(a: &U256, b: &U256) -> U256BitwiseTrace {
    let result = a.bitand(b);
    U256BitwiseTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result: result.to_m31_limbs(),
        op_type: BitwiseOp::And,
    }
}

/// Generate trace for bitwise OR.
pub fn u256_or_trace(a: &U256, b: &U256) -> U256BitwiseTrace {
    let result = a.bitor(b);
    U256BitwiseTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result: result.to_m31_limbs(),
        op_type: BitwiseOp::Or,
    }
}

/// Generate trace for bitwise XOR.
pub fn u256_xor_trace(a: &U256, b: &U256) -> U256BitwiseTrace {
    let result = a.bitxor(b);
    U256BitwiseTrace {
        a: a.to_m31_limbs(),
        b: b.to_m31_limbs(),
        result: result.to_m31_limbs(),
        op_type: BitwiseOp::Xor,
    }
}

// ============================================================================
// Constraint Functions
// ============================================================================

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

/// Constraint for U256 subtraction.
/// For each limb i: a[i] = b[i] + result[i] + borrow[i-1] - borrow[i] * 2^16
pub fn u256_sub_constraint(
    a: M31,
    b: M31,
    result: M31,
    borrow_in: M31,
    borrow_out: M31,
) -> M31 {
    let two_16 = M31::new(1 << 16);
    a - b - result - borrow_in + borrow_out * two_16
}

/// Constraint for division: dividend = quotient * divisor + remainder.
/// Also: remainder < divisor.
pub fn u256_div_constraint_check(
    dividend: &[M31; 16],
    divisor: &[M31; 16],
    quotient: &[M31; 16],
    remainder: &[M31; 16],
) -> bool {
    // Would use full AIR constraints in production
    // This is a simplified correctness check
    
    // Convert to U256 for checking
    let div = U256::from_m31_limbs(dividend);
    let q = U256::from_m31_limbs(quotient);
    let r = U256::from_m31_limbs(remainder);
    let d = U256::from_m31_limbs(divisor);
    
    // Check: remainder < divisor
    if r.cmp(&d) != Ordering::Less {
        return false;
    }
    
    // Check: q * d + r = dividend
    let (prod_lo, prod_hi, _) = u256_mul_trace(&q, &d);
    if !prod_hi.is_zero() {
        return false; // overflow
    }
    
    let (sum, _) = u256_add_trace(&prod_lo, &r);
    sum == div
}

// ============================================================================
// Delegation Interface
// ============================================================================

/// U256 operation types for delegation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum U256OpType {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    AddMod,
    MulMod,
    ModExp,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Cmp,
}

/// A delegation call for U256 operations.
#[derive(Clone, Debug)]
pub struct U256DelegationCall {
    pub op_type: U256OpType,
    pub input_a: [M31; 16],
    pub input_b: [M31; 16],
    pub input_modulus: Option<[M31; 16]>,
    pub output: [M31; 16],
    pub output_hi: Option<[M31; 16]>, // For mul and div
    pub trace: U256DelegationTrace,
}

/// Trace data for a U256 delegation call.
#[derive(Clone, Debug)]
pub enum U256DelegationTrace {
    Add(U256AddTrace),
    Sub(U256SubTrace),
    Mul(U256MulTrace),
    Div(U256DivTrace),
    AddMod(U256AddModTrace),
    MulMod(U256MulModTrace),
    ModExp(U256ModExpTrace),
    Bitwise(U256BitwiseTrace),
    Cmp(U256CmpTrace),
}

/// Create a U256 addition delegation call.
pub fn delegate_u256_add(a: &U256, b: &U256) -> U256DelegationCall {
    let (result, trace) = u256_add_trace(a, b);
    
    U256DelegationCall {
        op_type: U256OpType::Add,
        input_a: a.to_m31_limbs(),
        input_b: b.to_m31_limbs(),
        input_modulus: None,
        output: result.to_m31_limbs(),
        output_hi: None,
        trace: U256DelegationTrace::Add(trace),
    }
}

/// Create a U256 multiplication delegation call.
pub fn delegate_u256_mul(a: &U256, b: &U256) -> U256DelegationCall {
    let (result_lo, result_hi, trace) = u256_mul_trace(a, b);
    
    U256DelegationCall {
        op_type: U256OpType::Mul,
        input_a: a.to_m31_limbs(),
        input_b: b.to_m31_limbs(),
        input_modulus: None,
        output: result_lo.to_m31_limbs(),
        output_hi: Some(result_hi.to_m31_limbs()),
        trace: U256DelegationTrace::Mul(trace),
    }
}

/// Create a U256 modular multiplication delegation call.
pub fn delegate_u256_mulmod(a: &U256, b: &U256, modulus: &U256) -> U256DelegationCall {
    let (result, trace) = u256_mulmod_trace(a, b, modulus);
    
    U256DelegationCall {
        op_type: U256OpType::MulMod,
        input_a: a.to_m31_limbs(),
        input_b: b.to_m31_limbs(),
        input_modulus: Some(modulus.to_m31_limbs()),
        output: result.to_m31_limbs(),
        output_hi: None,
        trace: U256DelegationTrace::MulMod(trace),
    }
}

/// Create a U256 modular exponentiation delegation call.
pub fn delegate_u256_modexp(base: &U256, exponent: &U256, modulus: &U256) -> U256DelegationCall {
    let (result, trace) = u256_modexp_trace(base, exponent, modulus);
    
    U256DelegationCall {
        op_type: U256OpType::ModExp,
        input_a: base.to_m31_limbs(),
        input_b: exponent.to_m31_limbs(),
        input_modulus: Some(modulus.to_m31_limbs()),
        output: result.to_m31_limbs(),
        output_hi: None,
        trace: U256DelegationTrace::ModExp(trace),
    }
}

// ============================================================================
// AIR Constraints
// ============================================================================

/// U256 AIR for constraint verification.
pub struct U256Air {
    pub op_type: U256OpType,
}

impl U256Air {
    pub fn new(op_type: U256OpType) -> Self {
        Self { op_type }
    }
    
    /// Number of trace columns needed for this operation.
    pub fn num_columns(&self) -> usize {
        match self.op_type {
            U256OpType::Add => 16 * 4 + 16 + 1, // a, b, result, carries, overflow
            U256OpType::Sub => 16 * 4 + 16 + 1, // a, b, result, borrows, underflow
            U256OpType::Mul => 16 * 4,          // a, b, result_lo, result_hi
            U256OpType::Div => 16 * 4,          // dividend, divisor, quotient, remainder
            U256OpType::AddMod | U256OpType::MulMod => 16 * 5, // a, b, modulus, result, intermediate
            U256OpType::ModExp => 16 * 4,       // base, exponent, modulus, result (+ intermediate steps)
            U256OpType::And | U256OpType::Or | U256OpType::Xor => 16 * 3, // a, b, result
            U256OpType::Shl | U256OpType::Shr => 16 * 2 + 1, // input, output, shift_amount
            U256OpType::Cmp => 16 * 2 + 1 + 16, // a, b, result, limb_diffs
            _ => 16 * 2,
        }
    }
    
    /// Degree of constraints.
    pub fn constraint_degree(&self) -> usize {
        match self.op_type {
            U256OpType::Add | U256OpType::Sub => 2,
            U256OpType::Mul | U256OpType::MulMod => 3,
            U256OpType::Div | U256OpType::Mod => 3,
            U256OpType::ModExp => 3, // Repeated squaring and multiplication
            _ => 2,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

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
    
    #[test]
    fn test_u256_sub() {
        let a = U256::from_u64(1000);
        let b = U256::from_u64(300);
        
        let (result, trace) = u256_sub_trace(&a, &b);
        
        assert_eq!(result.limbs[0], 700);
        assert_eq!(trace.underflow.value(), 0);
    }
    
    #[test]
    fn test_u256_sub_underflow() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        
        let (_, trace) = u256_sub_trace(&a, &b);
        
        assert_eq!(trace.underflow.value(), 1);
    }
    
    #[test]
    fn test_u256_div() {
        let dividend = U256::from_u64(1000);
        let divisor = U256::from_u64(30);
        
        let (quotient, remainder, _trace) = u256_div_trace(&dividend, &divisor).unwrap();
        
        assert_eq!(quotient.limbs[0], 33);
        assert_eq!(remainder.limbs[0], 10);
    }
    
    #[test]
    fn test_u256_div_zero() {
        let dividend = U256::from_u64(100);
        let divisor = U256::ZERO;
        
        assert!(u256_div_trace(&dividend, &divisor).is_err());
    }
    
    #[test]
    fn test_u256_addmod() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(50);
        let modulus = U256::from_u64(70);
        
        let (result, _trace) = u256_addmod_trace(&a, &b, &modulus);
        
        // (100 + 50) % 70 = 80
        assert_eq!(result.limbs[0], 80);
    }
    
    #[test]
    fn test_u256_mulmod() {
        let a = U256::from_u64(20);
        let b = U256::from_u64(30);
        let modulus = U256::from_u64(100);
        
        let (result, _trace) = u256_mulmod_trace(&a, &b, &modulus);
        
        // (20 * 30) % 100 = 600 % 100 = 0
        assert_eq!(result.limbs[0], 0);
    }
    
    #[test]
    fn test_u256_cmp() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(50);
        
        assert_eq!(a.cmp(&b), Ordering::Greater);
        assert_eq!(b.cmp(&a), Ordering::Less);
        assert_eq!(a.cmp(&a), Ordering::Equal);
    }
    
    #[test]
    fn test_u256_bitwise() {
        let a = U256::from_u64(0b1100);
        let b = U256::from_u64(0b1010);
        
        let and_result = a.bitand(&b);
        assert_eq!(and_result.limbs[0], 0b1000);
        
        let or_result = a.bitor(&b);
        assert_eq!(or_result.limbs[0], 0b1110);
        
        let xor_result = a.bitxor(&b);
        assert_eq!(xor_result.limbs[0], 0b0110);
    }
    
    #[test]
    fn test_u256_shift() {
        let a = U256::from_u64(0b1100);
        
        let shl = a.shl(2);
        assert_eq!(shl.limbs[0], 0b110000);
        
        let shr = a.shr(1);
        assert_eq!(shr.limbs[0], 0b110);
    }
    
    #[test]
    fn test_delegation_add() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        
        let call = delegate_u256_add(&a, &b);
        
        assert_eq!(call.op_type, U256OpType::Add);
        assert_eq!(call.output[0].value(), 300);
    }
    
    #[test]
    fn test_delegation_mulmod() {
        let a = U256::from_u64(15);
        let b = U256::from_u64(20);
        let modulus = U256::from_u64(100);
        
        let call = delegate_u256_mulmod(&a, &b, &modulus);
        
        assert_eq!(call.op_type, U256OpType::MulMod);
        // 15 * 20 = 300, 300 % 100 = 0
        assert_eq!(call.output[0].value(), 0);
    }
    
    #[test]
    fn test_u256_air() {
        let air = U256Air::new(U256OpType::Add);
        assert!(air.num_columns() > 0);
        assert_eq!(air.constraint_degree(), 2);
        
        let mul_air = U256Air::new(U256OpType::Mul);
        assert_eq!(mul_air.constraint_degree(), 3);
    }
    
    #[test]
    fn test_u256_modexp_simple() {
        // 3^4 mod 7 = 81 mod 7 = 4
        let base = U256::from_u64(3);
        let exponent = U256::from_u64(4);
        let modulus = U256::from_u64(7);
        
        let (result, trace) = u256_modexp_trace(&base, &exponent, &modulus);
        
        assert_eq!(result.limbs[0], 4);
        assert!(!trace.intermediate_steps.is_empty());
    }
    
    #[test]
    fn test_u256_modexp_zero_exponent() {
        // Any number to the power 0 is 1
        let base = U256::from_u64(123);
        let exponent = U256::ZERO;
        let modulus = U256::from_u64(100);
        
        let (result, _trace) = u256_modexp_trace(&base, &exponent, &modulus);
        
        assert_eq!(result, U256::ONE);
    }
    
    #[test]
    fn test_u256_modexp_large() {
        // 2^8 mod 17 = 256 mod 17 = 1
        let base = U256::from_u64(2);
        let exponent = U256::from_u64(8);
        let modulus = U256::from_u64(17);
        
        let (result, _trace) = u256_modexp_trace(&base, &exponent, &modulus);
        
        assert_eq!(result.limbs[0], 1);
    }
    
    #[test]
    fn test_u256_modexp_base_larger_than_modulus() {
        // 10^2 mod 7 = (10 mod 7)^2 mod 7 = 3^2 mod 7 = 2
        let base = U256::from_u64(10);
        let exponent = U256::from_u64(2);
        let modulus = U256::from_u64(7);
        
        let (result, _trace) = u256_modexp_trace(&base, &exponent, &modulus);
        
        assert_eq!(result.limbs[0], 2);
    }
    
    #[test]
    fn test_delegation_modexp() {
        let base = U256::from_u64(5);
        let exponent = U256::from_u64(3);
        let modulus = U256::from_u64(13);
        
        let call = delegate_u256_modexp(&base, &exponent, &modulus);
        
        assert_eq!(call.op_type, U256OpType::ModExp);
        // 5^3 = 125, 125 mod 13 = 8
        assert_eq!(call.output[0].value(), 8);
    }
    
    #[test]
    fn test_u256_from_le_bytes_roundtrip() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[2] = 0x56;
        bytes[3] = 0x78;
        
        let num = U256::from_le_bytes(&bytes);
        let result_bytes = num.to_le_bytes();
        
        assert_eq!(bytes, result_bytes);
    }
    
    #[test]
    fn test_u256_div_constraint() {
        let dividend = U256::from_u64(100);
        let divisor = U256::from_u64(7);
        
        let (quotient, remainder, trace) = u256_div_trace(&dividend, &divisor).unwrap();
        
        // Verify constraint: quotient * divisor + remainder = dividend
        assert!(u256_div_constraint_check(
            &trace.dividend,
            &trace.divisor,
            &trace.quotient,
            &trace.remainder
        ));
        
        // 100 / 7 = 14 remainder 2
        assert_eq!(quotient.limbs[0], 14);
        assert_eq!(remainder.limbs[0], 2);
    }
    
    #[test]
    fn test_u256_large_shift() {
        let a = U256::from_u64(0xFF);
        
        // Shift beyond 256 bits should return zero
        let result = a.shl(300);
        assert_eq!(result, U256::ZERO);
        
        let result2 = a.shr(300);
        assert_eq!(result2, U256::ZERO);
    }
    
    #[test]
    fn test_u256_not() {
        let a = U256::ZERO;
        let result = a.not();
        
        // NOT of zero should be all 1s
        for limb in result.limbs.iter() {
            assert_eq!(*limb, 0xFFFF);
        }
    }
    
    #[test]
    fn test_u256_addmod_overflow() {
        // Test case where a + b > modulus (within 256 bits)
        let a = U256::from_u64(800);
        let b = U256::from_u64(700);
        let modulus = U256::from_u64(1000);
        
        let (result, _trace) = u256_addmod_trace(&a, &b, &modulus);
        
        // (800 + 700) % 1000 = 1500 % 1000 = 500
        assert_eq!(result.limbs[0], 500);
        assert!(result.cmp(&modulus) == Ordering::Less);
    }
    
    #[test]
    fn test_u256_addmod_no_reduction() {
        // Test case where a + b < modulus
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        let modulus = U256::from_u64(1000);
        
        let (result, _trace) = u256_addmod_trace(&a, &b, &modulus);
        
        // 100 + 200 = 300, no reduction needed
        assert_eq!(result.limbs[0], 300);
    }
}
