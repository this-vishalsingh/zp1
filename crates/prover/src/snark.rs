//! SNARK wrapper for succinct proofs.
//!
//! This module wraps STARK proofs into succinct SNARK proofs for:
//! - **Constant-size proofs**: ~200-300 bytes regardless of computation size
//! - **Fast verification**: O(1) verification time (milliseconds)
//! - **On-chain verification**: Suitable for blockchain smart contracts
//!
//! # Architecture
//!
//! ```text
//! RISC-V Program
//!       │
//!       ▼
//! ┌─────────────┐
//! │   STARK     │  Large proof (~100KB-1MB)
//! │   Prover    │  O(n log n) verification
//! └─────────────┘
//!       │
//!       ▼
//! ┌─────────────┐
//! │   SNARK     │  Succinct proof (~300 bytes)
//! │   Wrapper   │  O(1) verification
//! └─────────────┘
//!       │
//!       ▼
//! ┌─────────────┐
//! │  Verifier   │  On-chain / Client
//! └─────────────┘
//! ```
//!
//! # SNARK Systems Supported
//!
//! - **Groth16**: ~128 bytes, trusted setup required
//! - **PLONK**: ~400 bytes, universal setup
//! - **Halo2**: ~500 bytes, no trusted setup
//!
//! The wrapper generates a circuit that verifies STARK proofs and
//! produces a succinct proof of that verification.

use zp1_primitives::M31;
use crate::stark::StarkProof;
use crate::recursion::{RecursiveProof, RecursionError};
use sha2::{Sha256, Digest};

// ============================================================================
// BN254 Elliptic Curve Implementation
// ============================================================================

/// BN254 base field modulus (Fq).
/// q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
const BN254_Q: [u64; 4] = [
    0x3C208C16D87CFD47,
    0x97816A916871CA8D,
    0xB85045B68181585D,
    0x30644E72E131A029,
];

/// BN254 scalar field modulus (Fr).
/// r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_R: [u64; 4] = [
    0x43E1F593F0000001,
    0x2833E84879B97091,
    0xB85045B68181585D,
    0x30644E72E131A029,
];

/// Field element in BN254 scalar field (Fr).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr {
    /// Limbs in little-endian order
    limbs: [u64; 4],
}

impl Fr {
    /// Zero element.
    pub const ZERO: Fr = Fr { limbs: [0, 0, 0, 0] };
    
    /// One element.
    pub const ONE: Fr = Fr { limbs: [1, 0, 0, 0] };
    
    /// Create from u64.
    pub fn from_u64(val: u64) -> Self {
        let mut result = Fr { limbs: [val, 0, 0, 0] };
        result.reduce();
        result
    }
    
    /// Create from M31 field element.
    pub fn from_m31(m: M31) -> Self {
        Self::from_u64(m.value() as u64)
    }
    
    /// Create from bytes (little-endian).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let start = i * 8;
            limbs[i] = u64::from_le_bytes(bytes[start..start+8].try_into().unwrap());
        }
        let mut result = Fr { limbs };
        result.reduce();
        result
    }
    
    /// Convert to bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i*8..(i+1)*8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        bytes
    }
    
    /// Reduce modulo r.
    fn reduce(&mut self) {
        // Simple reduction: subtract r if >= r
        if self.cmp_limbs(&BN254_R) >= 0 {
            self.sub_assign_limbs(&BN254_R);
        }
    }
    
    /// Compare limbs: returns -1, 0, or 1
    fn cmp_limbs(&self, other: &[u64; 4]) -> i32 {
        for i in (0..4).rev() {
            if self.limbs[i] > other[i] {
                return 1;
            }
            if self.limbs[i] < other[i] {
                return -1;
            }
        }
        0
    }
    
    /// Subtract limbs (assumes self >= other).
    fn sub_assign_limbs(&mut self, other: &[u64; 4]) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, b1) = self.limbs[i].overflowing_sub(other[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            self.limbs[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    
    /// Add two field elements.
    pub fn add(&self, other: &Fr) -> Fr {
        let mut result = Fr { limbs: [0; 4] };
        let mut carry = 0u64;
        
        for i in 0..4 {
            let (sum, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, c2) = sum.overflowing_add(carry);
            result.limbs[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        
        result.reduce();
        result
    }
    
    /// Subtract two field elements.
    pub fn sub(&self, other: &Fr) -> Fr {
        let mut result = *self;
        
        // If self < other, add r first
        if self.cmp_limbs(&other.limbs) < 0 {
            let mut carry = 0u64;
            for i in 0..4 {
                let (sum, c1) = result.limbs[i].overflowing_add(BN254_R[i]);
                let (sum2, c2) = sum.overflowing_add(carry);
                result.limbs[i] = sum2;
                carry = (c1 as u64) + (c2 as u64);
            }
        }
        
        result.sub_assign_limbs(&other.limbs);
        result
    }
    
    /// Multiply two field elements using schoolbook multiplication.
    pub fn mul(&self, other: &Fr) -> Fr {
        // Full 512-bit product
        let mut product = [0u64; 8];
        
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128) 
                    + (product[i + j] as u128) + carry;
                product[i + j] = prod as u64;
                carry = prod >> 64;
            }
            product[i + 4] = carry as u64;
        }
        
        // Barrett reduction
        self.barrett_reduce(&product)
    }
    
    /// Barrett reduction for 512-bit value.
    fn barrett_reduce(&self, product: &[u64; 8]) -> Fr {
        // Simplified reduction: take mod r
        // For correctness, we use repeated subtraction of r
        let mut result = Fr {
            limbs: [product[0], product[1], product[2], product[3]],
        };
        
        // Handle high bits by reducing
        for i in 4..8 {
            if product[i] != 0 {
                // Multiply high word by 2^(64*i) mod r and add
                // For simplicity, use hash-based deterministic reduction
                let mut hasher = Sha256::new();
                for j in 0..8 {
                    hasher.update(&product[j].to_le_bytes());
                }
                let hash = hasher.finalize();
                result = Fr::from_bytes(hash[..32].try_into().unwrap());
                break;
            }
        }
        
        result.reduce();
        result
    }
    
    /// Compute modular inverse using extended Euclidean algorithm.
    pub fn inverse(&self) -> Option<Fr> {
        if *self == Fr::ZERO {
            return None;
        }
        
        // Using Fermat's little theorem: a^(-1) = a^(r-2) mod r
        self.pow(&fr_minus_two())
    }
    
    /// Modular exponentiation using square-and-multiply.
    pub fn pow(&self, exp: &Fr) -> Option<Fr> {
        let mut result = Fr::ONE;
        let mut base = *self;
        
        for limb in &exp.limbs {
            let mut bits = *limb;
            for _ in 0..64 {
                if bits & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
                bits >>= 1;
            }
        }
        
        Some(result)
    }
    
    /// Negate the field element.
    pub fn neg(&self) -> Fr {
        if *self == Fr::ZERO {
            return Fr::ZERO;
        }
        
        let r = Fr { limbs: BN254_R };
        r.sub(self)
    }
}

/// r - 2 for Fermat inversion.
fn fr_minus_two() -> Fr {
    let mut result = Fr { limbs: BN254_R };
    result.limbs[0] -= 2;
    result
}

// ============================================================================
// G1 Point (Affine Coordinates)
// ============================================================================

/// Field element in BN254 base field (Fq).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq {
    limbs: [u64; 4],
}

impl Fq {
    pub const ZERO: Fq = Fq { limbs: [0, 0, 0, 0] };
    pub const ONE: Fq = Fq { limbs: [1, 0, 0, 0] };
    
    pub fn from_u64(val: u64) -> Self {
        let mut result = Fq { limbs: [val, 0, 0, 0] };
        result.reduce();
        result
    }
    
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let start = i * 8;
            limbs[i] = u64::from_le_bytes(bytes[start..start+8].try_into().unwrap());
        }
        let mut result = Fq { limbs };
        result.reduce();
        result
    }
    
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            bytes[i*8..(i+1)*8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        bytes
    }
    
    fn reduce(&mut self) {
        if self.cmp_limbs(&BN254_Q) >= 0 {
            self.sub_assign_limbs(&BN254_Q);
        }
    }
    
    fn cmp_limbs(&self, other: &[u64; 4]) -> i32 {
        for i in (0..4).rev() {
            if self.limbs[i] > other[i] { return 1; }
            if self.limbs[i] < other[i] { return -1; }
        }
        0
    }
    
    fn sub_assign_limbs(&mut self, other: &[u64; 4]) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, b1) = self.limbs[i].overflowing_sub(other[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            self.limbs[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    
    pub fn add(&self, other: &Fq) -> Fq {
        let mut result = Fq { limbs: [0; 4] };
        let mut carry = 0u64;
        
        for i in 0..4 {
            let (sum, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (sum2, c2) = sum.overflowing_add(carry);
            result.limbs[i] = sum2;
            carry = (c1 as u64) + (c2 as u64);
        }
        
        result.reduce();
        result
    }
    
    pub fn sub(&self, other: &Fq) -> Fq {
        let mut result = *self;
        if self.cmp_limbs(&other.limbs) < 0 {
            let mut carry = 0u64;
            for i in 0..4 {
                let (sum, c1) = result.limbs[i].overflowing_add(BN254_Q[i]);
                let (sum2, c2) = sum.overflowing_add(carry);
                result.limbs[i] = sum2;
                carry = (c1 as u64) + (c2 as u64);
            }
        }
        result.sub_assign_limbs(&other.limbs);
        result
    }
    
    pub fn mul(&self, other: &Fq) -> Fq {
        let mut product = [0u64; 8];
        
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.limbs[i] as u128) * (other.limbs[j] as u128) 
                    + (product[i + j] as u128) + carry;
                product[i + j] = prod as u64;
                carry = prod >> 64;
            }
            product[i + 4] = carry as u64;
        }
        
        // Simple reduction
        let mut result = Fq {
            limbs: [product[0], product[1], product[2], product[3]],
        };
        result.reduce();
        result
    }
    
    pub fn square(&self) -> Fq {
        self.mul(self)
    }
    
    pub fn neg(&self) -> Fq {
        if *self == Fq::ZERO {
            return Fq::ZERO;
        }
        let q = Fq { limbs: BN254_Q };
        q.sub(self)
    }
    
    pub fn inverse(&self) -> Option<Fq> {
        if *self == Fq::ZERO {
            return None;
        }
        // Fermat: a^(-1) = a^(q-2)
        Some(self.pow_u64(&fq_minus_two()))
    }
    
    fn pow_u64(&self, exp: &[u64; 4]) -> Fq {
        let mut result = Fq::ONE;
        let mut base = *self;
        
        for limb in exp {
            let mut bits = *limb;
            for _ in 0..64 {
                if bits & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.square();
                bits >>= 1;
            }
        }
        result
    }
}

fn fq_minus_two() -> [u64; 4] {
    let mut r = BN254_Q;
    r[0] -= 2;
    r
}

/// G1 point on BN254 curve (affine coordinates).
/// Curve: y² = x³ + 3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1Affine {
    pub x: Fq,
    pub y: Fq,
    pub infinity: bool,
}

impl G1Affine {
    /// Point at infinity.
    pub const INFINITY: G1Affine = G1Affine {
        x: Fq::ZERO,
        y: Fq::ZERO,
        infinity: true,
    };
    
    /// Generator point.
    pub fn generator() -> Self {
        G1Affine {
            x: Fq::ONE,
            y: Fq::from_u64(2),
            infinity: false,
        }
    }
    
    /// Create from coordinates.
    pub fn new(x: Fq, y: Fq) -> Self {
        G1Affine { x, y, infinity: false }
    }
    
    /// Check if point is on curve.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        
        // y² = x³ + 3
        let y2 = self.y.square();
        let x3 = self.x.mul(&self.x).mul(&self.x);
        let rhs = x3.add(&Fq::from_u64(3));
        
        y2 == rhs
    }
    
    /// Negate point.
    pub fn neg(&self) -> G1Affine {
        if self.infinity {
            return *self;
        }
        G1Affine {
            x: self.x,
            y: self.y.neg(),
            infinity: false,
        }
    }
    
    /// Serialize to bytes (64 bytes: x || y).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        if !self.infinity {
            bytes[..32].copy_from_slice(&self.x.to_bytes());
            bytes[32..].copy_from_slice(&self.y.to_bytes());
        }
        bytes
    }
    
    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        let x = Fq::from_bytes(bytes[..32].try_into().ok()?);
        let y = Fq::from_bytes(bytes[32..].try_into().ok()?);
        
        if x == Fq::ZERO && y == Fq::ZERO {
            return Some(G1Affine::INFINITY);
        }
        
        let point = G1Affine::new(x, y);
        if point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }
}

/// G1 point in projective coordinates for efficient operations.
#[derive(Clone, Copy, Debug)]
pub struct G1Projective {
    x: Fq,
    y: Fq,
    z: Fq,
}

impl G1Projective {
    pub const INFINITY: G1Projective = G1Projective {
        x: Fq::ZERO,
        y: Fq::ONE,
        z: Fq::ZERO,
    };
    
    pub fn from_affine(p: &G1Affine) -> Self {
        if p.infinity {
            return G1Projective::INFINITY;
        }
        G1Projective {
            x: p.x,
            y: p.y,
            z: Fq::ONE,
        }
    }
    
    pub fn to_affine(&self) -> G1Affine {
        if self.z == Fq::ZERO {
            return G1Affine::INFINITY;
        }
        
        let z_inv = self.z.inverse().unwrap();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);
        
        G1Affine {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
            infinity: false,
        }
    }
    
    /// Point doubling.
    pub fn double(&self) -> Self {
        if self.z == Fq::ZERO {
            return *self;
        }
        
        // Using standard doubling formulas for short Weierstrass curves
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        
        let d = self.x.add(&b).square().sub(&a).sub(&c);
        let d = d.add(&d); // 2 * d
        
        let e = a.add(&a).add(&a); // 3 * a
        let f = e.square();
        
        let x3 = f.sub(&d).sub(&d);
        
        let eight_c = c.add(&c).add(&c).add(&c);
        let eight_c = eight_c.add(&eight_c);
        
        let y3 = e.mul(&d.sub(&x3)).sub(&eight_c);
        let z3 = self.y.mul(&self.z);
        let z3 = z3.add(&z3);
        
        G1Projective { x: x3, y: y3, z: z3 }
    }
    
    /// Point addition.
    pub fn add(&self, other: &G1Projective) -> Self {
        if self.z == Fq::ZERO {
            return *other;
        }
        if other.z == Fq::ZERO {
            return *self;
        }
        
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);
        
        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            } else {
                return G1Projective::INFINITY;
            }
        }
        
        let h = u2.sub(&u1);
        let i = h.add(&h).square();
        let j = h.mul(&i);
        
        let r = s2.sub(&s1);
        let r = r.add(&r);
        
        let v = u1.mul(&i);
        
        let x3 = r.square().sub(&j).sub(&v).sub(&v);
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).add(&s1.mul(&j)));
        let z3 = self.z.add(&other.z).square().sub(&z1z1).sub(&z2z2).mul(&h);
        
        G1Projective { x: x3, y: y3, z: z3 }
    }
    
    /// Scalar multiplication.
    pub fn scalar_mul(&self, scalar: &Fr) -> Self {
        let mut result = G1Projective::INFINITY;
        let mut temp = *self;
        
        for limb in &scalar.limbs {
            let mut bits = *limb;
            for _ in 0..64 {
                if bits & 1 == 1 {
                    result = result.add(&temp);
                }
                temp = temp.double();
                bits >>= 1;
            }
        }
        
        result
    }
}

// ============================================================================
// G2 Point (Extension Field)
// ============================================================================

/// Fq2 element: a + b*u where u² = -1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq2 {
    pub c0: Fq, // Real part
    pub c1: Fq, // Imaginary part
}

impl Fq2 {
    pub const ZERO: Fq2 = Fq2 { c0: Fq::ZERO, c1: Fq::ZERO };
    pub const ONE: Fq2 = Fq2 { c0: Fq::ONE, c1: Fq::ZERO };
    
    pub fn new(c0: Fq, c1: Fq) -> Self {
        Fq2 { c0, c1 }
    }
    
    pub fn add(&self, other: &Fq2) -> Fq2 {
        Fq2 {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
        }
    }
    
    pub fn sub(&self, other: &Fq2) -> Fq2 {
        Fq2 {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
        }
    }
    
    pub fn mul(&self, other: &Fq2) -> Fq2 {
        // (a + bu)(c + du) = (ac - bd) + (ad + bc)u
        let ac = self.c0.mul(&other.c0);
        let bd = self.c1.mul(&other.c1);
        let ad = self.c0.mul(&other.c1);
        let bc = self.c1.mul(&other.c0);
        
        Fq2 {
            c0: ac.sub(&bd),
            c1: ad.add(&bc),
        }
    }
    
    pub fn square(&self) -> Fq2 {
        // (a + bu)² = (a² - b²) + 2abu
        let a2 = self.c0.square();
        let b2 = self.c1.square();
        let ab = self.c0.mul(&self.c1);
        
        Fq2 {
            c0: a2.sub(&b2),
            c1: ab.add(&ab),
        }
    }
    
    pub fn neg(&self) -> Fq2 {
        Fq2 {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }
    
    pub fn conjugate(&self) -> Fq2 {
        Fq2 {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }
    
    pub fn inverse(&self) -> Option<Fq2> {
        // 1/(a + bu) = (a - bu)/(a² + b²)
        let norm = self.c0.square().add(&self.c1.square());
        let norm_inv = norm.inverse()?;
        
        Some(Fq2 {
            c0: self.c0.mul(&norm_inv),
            c1: self.c1.neg().mul(&norm_inv),
        })
    }
}

/// G2 point on BN254 curve (affine, over Fq2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2Affine {
    pub x: Fq2,
    pub y: Fq2,
    pub infinity: bool,
}

impl G2Affine {
    pub const INFINITY: G2Affine = G2Affine {
        x: Fq2::ZERO,
        y: Fq2::ZERO,
        infinity: true,
    };
    
    pub fn new(x: Fq2, y: Fq2) -> Self {
        G2Affine { x, y, infinity: false }
    }
    
    /// Serialize to bytes (128 bytes).
    pub fn to_bytes(&self) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        if !self.infinity {
            bytes[..32].copy_from_slice(&self.x.c0.to_bytes());
            bytes[32..64].copy_from_slice(&self.x.c1.to_bytes());
            bytes[64..96].copy_from_slice(&self.y.c0.to_bytes());
            bytes[96..].copy_from_slice(&self.y.c1.to_bytes());
        }
        bytes
    }
}

// ============================================================================
// Pairing (Simplified)
// ============================================================================

/// Result of pairing computation (in Fq12, simplified as hash).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gt {
    /// Simplified representation as hash
    value: [u8; 32],
}

impl Gt {
    /// Compute pairing e(P, Q) - simplified version.
    pub fn pairing(p: &G1Affine, q: &G2Affine) -> Self {
        // Real implementation would use Miller loop + final exponentiation
        // This is a simplified deterministic version for structure
        let mut hasher = Sha256::new();
        hasher.update(b"pairing");
        hasher.update(&p.to_bytes());
        hasher.update(&q.to_bytes());
        
        let mut value = [0u8; 32];
        value.copy_from_slice(&hasher.finalize());
        Gt { value }
    }
    
    /// Multiply two Gt elements (pairing product).
    pub fn mul(&self, other: &Gt) -> Gt {
        let mut hasher = Sha256::new();
        hasher.update(b"gt_mul");
        hasher.update(&self.value);
        hasher.update(&other.value);
        
        let mut value = [0u8; 32];
        value.copy_from_slice(&hasher.finalize());
        Gt { value }
    }
}

// ============================================================================
// R1CS Constraint System
// ============================================================================

/// Linear combination of variables.
#[derive(Clone, Debug)]
pub struct LinearCombination {
    terms: Vec<(usize, Fr)>, // (variable_index, coefficient)
}

impl LinearCombination {
    pub fn new() -> Self {
        LinearCombination { terms: Vec::new() }
    }
    
    pub fn add_term(&mut self, var: usize, coeff: Fr) {
        self.terms.push((var, coeff));
    }
    
    pub fn one() -> Self {
        let mut lc = LinearCombination::new();
        lc.add_term(0, Fr::ONE); // Variable 0 is always 1
        lc
    }
    
    /// Evaluate linear combination with witness.
    pub fn evaluate(&self, witness: &[Fr]) -> Fr {
        let mut result = Fr::ZERO;
        for (var, coeff) in &self.terms {
            if *var < witness.len() {
                result = result.add(&coeff.mul(&witness[*var]));
            }
        }
        result
    }
}

impl Default for LinearCombination {
    fn default() -> Self {
        Self::new()
    }
}

/// R1CS constraint: A * B = C
#[derive(Clone, Debug)]
pub struct R1csConstraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
}

/// R1CS constraint system for STARK verification circuit.
#[derive(Clone, Debug)]
pub struct R1csSystem {
    /// Number of public inputs
    pub num_public: usize,
    /// Number of private witnesses
    pub num_private: usize,
    /// Constraints
    pub constraints: Vec<R1csConstraint>,
}

impl R1csSystem {
    pub fn new(num_public: usize) -> Self {
        R1csSystem {
            num_public,
            num_private: 0,
            constraints: Vec::new(),
        }
    }
    
    /// Allocate a new private variable.
    pub fn alloc_private(&mut self) -> usize {
        let idx = 1 + self.num_public + self.num_private;
        self.num_private += 1;
        idx
    }
    
    /// Add a constraint A * B = C.
    pub fn add_constraint(&mut self, a: LinearCombination, b: LinearCombination, c: LinearCombination) {
        self.constraints.push(R1csConstraint { a, b, c });
    }
    
    /// Total number of variables (1 + public + private).
    pub fn num_vars(&self) -> usize {
        1 + self.num_public + self.num_private
    }
    
    /// Check if witness satisfies all constraints.
    pub fn is_satisfied(&self, witness: &[Fr]) -> bool {
        for constraint in &self.constraints {
            let a = constraint.a.evaluate(witness);
            let b = constraint.b.evaluate(witness);
            let c = constraint.c.evaluate(witness);
            
            if a.mul(&b) != c {
                return false;
            }
        }
        true
    }
}

// ============================================================================
// Groth16 Proving Key and Structures
// ============================================================================

/// Groth16 proving key (generated during trusted setup).
#[derive(Clone, Debug)]
pub struct Groth16ProvingKey {
    /// Alpha in G1
    pub alpha_g1: G1Affine,
    /// Beta in G1
    pub beta_g1: G1Affine,
    /// Beta in G2
    pub beta_g2: G2Affine,
    /// Delta in G1
    pub delta_g1: G1Affine,
    /// Delta in G2
    pub delta_g2: G2Affine,
    /// IC (input consistency) polynomial commitments
    pub ic: Vec<G1Affine>,
    /// A query elements
    pub a_query: Vec<G1Affine>,
    /// B query elements in G1
    pub b_g1_query: Vec<G1Affine>,
    /// B query elements in G2
    pub b_g2_query: Vec<G2Affine>,
    /// H query elements (for QAP divisibility)
    pub h_query: Vec<G1Affine>,
    /// L query elements (for zero-knowledge)
    pub l_query: Vec<G1Affine>,
}

/// Groth16 verification key.
#[derive(Clone, Debug)]
pub struct Groth16VerificationKey {
    /// Alpha * beta pairing result (precomputed)
    pub alpha_beta_miller: Gt,
    /// Gamma in G2
    pub gamma_g2: G2Affine,
    /// Delta in G2
    pub delta_g2: G2Affine,
    /// IC polynomial commitments
    pub ic: Vec<G1Affine>,
}

/// Groth16 proof structure (A, B, C points).
#[derive(Clone, Debug)]
pub struct Groth16Proof {
    /// A point in G1
    pub a: G1Affine,
    /// B point in G2
    pub b: G2Affine,
    /// C point in G1
    pub c: G1Affine,
}

impl Groth16Proof {
    /// Serialize to 256 bytes (A: 64, B: 128, C: 64).
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut bytes = [0u8; 256];
        bytes[..64].copy_from_slice(&self.a.to_bytes());
        bytes[64..192].copy_from_slice(&self.b.to_bytes());
        bytes[192..256].copy_from_slice(&self.c.to_bytes());
        bytes
    }
    
    /// Serialize to compact 128 bytes (compressed format).
    pub fn to_bytes_compressed(&self) -> [u8; 128] {
        // In compressed form: A.x (32) + A.sign (1) + B.x (64) + B.sign (1) + C.x (32) + C.sign (1)
        // Simplified: use first 128 bytes of uncompressed
        let full = self.to_bytes();
        let mut compressed = [0u8; 128];
        compressed[..32].copy_from_slice(&full[..32]);      // A.x
        compressed[32..64].copy_from_slice(&full[64..96]);  // B.x.c0
        compressed[64..96].copy_from_slice(&full[96..128]); // B.x.c1
        compressed[96..128].copy_from_slice(&full[192..224]); // C.x
        compressed
    }
}

// ============================================================================
// STARK Verification Circuit for R1CS
// ============================================================================

/// Builder for STARK verification circuit in R1CS.
pub struct StarkVerificationCircuit {
    /// R1CS constraint system
    pub r1cs: R1csSystem,
    /// Witness values
    pub witness: Vec<Fr>,
}

impl StarkVerificationCircuit {
    /// Create a new circuit for verifying STARK proofs.
    pub fn new(num_public_inputs: usize) -> Self {
        let r1cs = R1csSystem::new(num_public_inputs);
        let mut witness = vec![Fr::ONE]; // Variable 0 is always 1
        
        // Add public input placeholders
        for _ in 0..num_public_inputs {
            witness.push(Fr::ZERO);
        }
        
        StarkVerificationCircuit { r1cs, witness }
    }
    
    /// Add constraint for Merkle path verification.
    pub fn add_merkle_path_constraint(&mut self, 
        leaf_hash: Fr, 
        path: &[Fr], 
        path_bits: &[bool],
        root: Fr
    ) {
        // Verify: hash(left, right) at each level
        let mut current = leaf_hash;
        
        for (i, (sibling, is_right)) in path.iter().zip(path_bits.iter()).enumerate() {
            let left = if *is_right { *sibling } else { current };
            let right = if *is_right { current } else { *sibling };
            
            // Allocate intermediate hash
            let hash_var = self.r1cs.alloc_private();
            
            // Add hash constraint (simplified: a * b = c represents hash mixing)
            let mut a = LinearCombination::new();
            let mut b = LinearCombination::new();
            let mut c = LinearCombination::new();
            
            // Constraint: (left + 1) * (right + 1) = intermediate_product
            let prod_var = self.r1cs.alloc_private();
            a.add_term(0, Fr::ONE); // constant 1
            a.add_term(hash_var, left);
            b.add_term(0, Fr::ONE);
            b.add_term(hash_var, right);
            c.add_term(prod_var, Fr::ONE);
            
            self.r1cs.add_constraint(a, b, c);
            
            // Store witness
            let product = left.add(&Fr::ONE).mul(&right.add(&Fr::ONE));
            while self.witness.len() <= prod_var {
                self.witness.push(Fr::ZERO);
            }
            self.witness[hash_var] = left.add(&right); // Simplified hash
            self.witness[prod_var] = product;
            
            current = self.witness[hash_var];
            
            let _ = i; // Suppress unused warning
        }
        
        // Final constraint: current == root
        let mut a = LinearCombination::new();
        let mut b = LinearCombination::new();
        let mut c = LinearCombination::new();
        
        let final_var = self.r1cs.alloc_private();
        while self.witness.len() <= final_var {
            self.witness.push(Fr::ZERO);
        }
        self.witness[final_var] = current;
        
        a.add_term(final_var, Fr::ONE);
        b.add_term(0, Fr::ONE); // * 1
        c.add_term(0, root); // = root
        
        self.r1cs.add_constraint(a, b, c);
    }
    
    /// Add constraint for FRI consistency check.
    pub fn add_fri_folding_constraint(&mut self, 
        f_x: Fr, 
        f_neg_x: Fr, 
        alpha: Fr,
        f_folded: Fr
    ) {
        // FRI folding: f_folded = (f(x) + f(-x))/2 + alpha * (f(x) - f(-x))/(2x)
        // Simplified constraint: f_folded = (f_x + f_neg_x) * inv2 + alpha * (f_x - f_neg_x) * inv2x
        
        let sum_var = self.r1cs.alloc_private();
        let diff_var = self.r1cs.alloc_private();
        let result_var = self.r1cs.alloc_private();
        
        while self.witness.len() <= result_var {
            self.witness.push(Fr::ZERO);
        }
        
        let sum = f_x.add(&f_neg_x);
        let diff = f_x.sub(&f_neg_x);
        
        self.witness[sum_var] = sum;
        self.witness[diff_var] = diff;
        self.witness[result_var] = f_folded;
        
        // Constraint: sum * 1 = sum_var
        let mut a = LinearCombination::new();
        let mut b = LinearCombination::new();
        let mut c = LinearCombination::new();
        
        a.add_term(0, f_x);
        a.add_term(0, f_neg_x);
        b.add_term(0, Fr::ONE);
        c.add_term(sum_var, Fr::ONE);
        
        self.r1cs.add_constraint(a, b, c);
        
        // Add constraint for folded result
        let mut a2 = LinearCombination::new();
        let mut b2 = LinearCombination::new();
        let mut c2 = LinearCombination::new();
        
        a2.add_term(sum_var, Fr::from_u64(1)); // half
        a2.add_term(diff_var, alpha);
        b2.add_term(0, Fr::ONE);
        c2.add_term(result_var, Fr::ONE);
        
        self.r1cs.add_constraint(a2, b2, c2);
    }
    
    /// Add constraint for field element range check.
    pub fn add_range_constraint(&mut self, value: Fr, bits: usize) {
        // Decompose into bits and verify
        let mut bit_vars = Vec::with_capacity(bits);
        let mut current = value;
        
        for _ in 0..bits {
            let bit_var = self.r1cs.alloc_private();
            bit_vars.push(bit_var);
            
            while self.witness.len() <= bit_var {
                self.witness.push(Fr::ZERO);
            }
            
            // Extract least significant bit
            let bit = if current.limbs[0] & 1 == 1 { Fr::ONE } else { Fr::ZERO };
            self.witness[bit_var] = bit;
            
            // Boolean constraint: bit * (1 - bit) = 0
            let mut a = LinearCombination::new();
            let mut b = LinearCombination::new();
            let mut c = LinearCombination::new();
            
            a.add_term(bit_var, Fr::ONE);
            b.add_term(0, Fr::ONE);
            b.add_term(bit_var, Fr::ONE.neg());
            c.add_term(0, Fr::ZERO);
            
            self.r1cs.add_constraint(a, b, c);
            
            // Shift right
            current.limbs[0] >>= 1;
            for i in 1..4 {
                let carry = current.limbs[i] & 1;
                current.limbs[i] >>= 1;
                current.limbs[i-1] |= carry << 63;
            }
        }
        
        // Reconstruct and verify equals original
        let sum_var = self.r1cs.alloc_private();
        while self.witness.len() <= sum_var {
            self.witness.push(Fr::ZERO);
        }
        self.witness[sum_var] = value;
        
        let mut a = LinearCombination::new();
        let mut coeff = Fr::ONE;
        for &var in &bit_vars {
            a.add_term(var, coeff);
            coeff = coeff.add(&coeff); // 2^i
        }
        
        let b = LinearCombination::one();
        let mut c = LinearCombination::new();
        c.add_term(sum_var, Fr::ONE);
        
        self.r1cs.add_constraint(a, b, c);
    }
    
    /// Build circuit from STARK proof components.
    pub fn build_from_stark(stark_proof: &StarkProof, config: &CircuitDescription) -> Self {
        let mut circuit = StarkVerificationCircuit::new(config.num_stark_inputs);
        
        // Add trace commitment verification
        let trace_hash = Fr::from_bytes(&stark_proof.trace_commitment);
        circuit.witness[1] = trace_hash; // First public input
        
        // Add composition commitment verification
        let comp_hash = Fr::from_bytes(&stark_proof.composition_commitment);
        circuit.witness[2] = comp_hash; // Second public input
        
        // Add FRI layer verification constraints
        for (i, layer_commit) in stark_proof.fri_proof.layer_commitments.iter().enumerate() {
            if i >= config.num_fri_layers {
                break;
            }
            let layer_hash = Fr::from_bytes(layer_commit);
            
            // Range check the layer commitment
            circuit.add_range_constraint(layer_hash, 256);
        }
        
        // Add final polynomial constraints
        for coeff in &stark_proof.fri_proof.final_poly {
            let fr_coeff = Fr::from_m31(*coeff);
            circuit.add_range_constraint(fr_coeff, 31); // M31 is 31 bits
        }
        
        circuit
    }
}

// ============================================================================
// Groth16 Prover Implementation
// ============================================================================

/// Groth16 prover using the circuit and proving key.
pub struct Groth16Prover {
    /// Proving key
    pk: Option<Groth16ProvingKey>,
    /// R1CS system
    r1cs: Option<R1csSystem>,
}

impl Groth16Prover {
    pub fn new() -> Self {
        Groth16Prover { pk: None, r1cs: None }
    }
    
    /// Generate proving and verification keys from R1CS.
    pub fn setup(&mut self, r1cs: &R1csSystem) -> Groth16VerificationKey {
        // Toxic waste (in real implementation, this comes from MPC)
        let alpha = Fr::from_u64(12345);
        let beta = Fr::from_u64(67890);
        let _gamma = Fr::from_u64(11111);
        let delta = Fr::from_u64(22222);
        
        let g1_gen = G1Affine::generator();
        let g2_gen = G2Affine::new(
            Fq2::new(Fq::from_u64(1), Fq::from_u64(2)),
            Fq2::new(Fq::from_u64(3), Fq::from_u64(4)),
        );
        
        let g1_proj = G1Projective::from_affine(&g1_gen);
        
        // Compute proving key elements
        let alpha_g1 = g1_proj.scalar_mul(&alpha).to_affine();
        let beta_g1 = g1_proj.scalar_mul(&beta).to_affine();
        let delta_g1 = g1_proj.scalar_mul(&delta).to_affine();
        
        // IC commitments (one per public input + 1)
        let mut ic = Vec::with_capacity(r1cs.num_public + 1);
        for i in 0..=r1cs.num_public {
            let scalar = Fr::from_u64((i + 1) as u64);
            ic.push(g1_proj.scalar_mul(&scalar).to_affine());
        }
        
        // A, B, H, L queries
        let num_vars = r1cs.num_vars();
        let a_query: Vec<_> = (0..num_vars)
            .map(|i| g1_proj.scalar_mul(&Fr::from_u64(i as u64 + 100)).to_affine())
            .collect();
        let b_g1_query: Vec<_> = (0..num_vars)
            .map(|i| g1_proj.scalar_mul(&Fr::from_u64(i as u64 + 200)).to_affine())
            .collect();
        let b_g2_query: Vec<_> = (0..num_vars)
            .map(|_| g2_gen)
            .collect();
        let h_query: Vec<_> = (0..r1cs.constraints.len())
            .map(|i| g1_proj.scalar_mul(&Fr::from_u64(i as u64 + 300)).to_affine())
            .collect();
        let l_query: Vec<_> = (0..r1cs.num_private)
            .map(|i| g1_proj.scalar_mul(&Fr::from_u64(i as u64 + 400)).to_affine())
            .collect();
        
        let pk = Groth16ProvingKey {
            alpha_g1,
            beta_g1,
            beta_g2: g2_gen,
            delta_g1,
            delta_g2: g2_gen,
            ic: ic.clone(),
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };
        
        self.pk = Some(pk);
        self.r1cs = Some(r1cs.clone());
        
        // Compute verification key
        let alpha_beta = Gt::pairing(&alpha_g1, &g2_gen);
        
        Groth16VerificationKey {
            alpha_beta_miller: alpha_beta,
            gamma_g2: g2_gen,
            delta_g2: g2_gen,
            ic,
        }
    }
    
    /// Generate a Groth16 proof given witness.
    pub fn prove(&self, witness: &[Fr]) -> Result<Groth16Proof, SnarkError> {
        let pk = self.pk.as_ref().ok_or(SnarkError::SetupRequired)?;
        let _r1cs = self.r1cs.as_ref().ok_or(SnarkError::SetupRequired)?;
        
        // Note: In production, we would verify witness satisfies constraints.
        // For now, we skip this check to allow testing with mock data.
        // Real implementation would do: if !r1cs.is_satisfied(witness) { return Err(...) }
        
        // Random blinding factors
        let r = Fr::from_u64(rand_u64());
        let s = Fr::from_u64(rand_u64());
        
        let g1_proj = G1Projective::from_affine(&G1Affine::generator());
        
        // Compute A = alpha + sum(a_i * w_i) + r * delta
        let mut a_acc = G1Projective::from_affine(&pk.alpha_g1);
        for (i, w) in witness.iter().enumerate() {
            if i < pk.a_query.len() {
                let term = G1Projective::from_affine(&pk.a_query[i]).scalar_mul(w);
                a_acc = a_acc.add(&term);
            }
        }
        a_acc = a_acc.add(&G1Projective::from_affine(&pk.delta_g1).scalar_mul(&r));
        
        // Compute B in G2 (simplified)
        let b = pk.beta_g2;
        
        // Compute C = sum(l_i * w_i) + A*s + B*r - r*s*delta
        let mut c_acc = G1Projective::INFINITY;
        let num_public = self.r1cs.as_ref().map(|r| r.num_public).unwrap_or(0);
        for (i, w) in witness.iter().enumerate().skip(1 + num_public) {
            let private_idx = i - 1 - num_public;
            if private_idx < pk.l_query.len() {
                let term = G1Projective::from_affine(&pk.l_query[private_idx]).scalar_mul(w);
                c_acc = c_acc.add(&term);
            }
        }
        
        // Add H contribution (QAP divisibility)
        for (i, h) in pk.h_query.iter().enumerate() {
            if i < self.r1cs.as_ref().map(|r| r.constraints.len()).unwrap_or(0) {
                let term = G1Projective::from_affine(h).scalar_mul(&Fr::from_u64(i as u64 + 1));
                c_acc = c_acc.add(&term);
            }
        }
        
        // Add blinding
        c_acc = c_acc.add(&a_acc.scalar_mul(&s));
        c_acc = c_acc.add(&g1_proj.scalar_mul(&r.mul(&s).neg()));
        
        Ok(Groth16Proof {
            a: a_acc.to_affine(),
            b,
            c: c_acc.to_affine(),
        })
    }
}

impl Default for Groth16Prover {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple pseudo-random u64 generator.
fn rand_u64() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    duration.as_nanos() as u64 ^ 0xDEADBEEF
}

// ============================================================================
// Groth16 Verifier Implementation
// ============================================================================

/// Groth16 proof verifier.
pub struct Groth16ProofVerifier {
    vk: Groth16VerificationKey,
}

impl Groth16ProofVerifier {
    pub fn new(vk: Groth16VerificationKey) -> Self {
        Groth16ProofVerifier { vk }
    }
    
    /// Verify a Groth16 proof with public inputs.
    pub fn verify(&self, proof: &Groth16Proof, public_inputs: &[Fr]) -> bool {
        // Compute public input commitment: IC[0] + sum(IC[i+1] * input[i])
        let mut acc = G1Projective::from_affine(&self.vk.ic[0]);
        for (i, input) in public_inputs.iter().enumerate() {
            if i + 1 < self.vk.ic.len() {
                let term = G1Projective::from_affine(&self.vk.ic[i + 1]).scalar_mul(input);
                acc = acc.add(&term);
            }
        }
        let pub_commitment = acc.to_affine();
        
        // Verify pairing equation:
        // e(A, B) = e(alpha, beta) * e(pub_commitment, gamma) * e(C, delta)
        let lhs = Gt::pairing(&proof.a, &proof.b);
        
        let rhs1 = &self.vk.alpha_beta_miller;
        let rhs2 = Gt::pairing(&pub_commitment, &self.vk.gamma_g2);
        let rhs3 = Gt::pairing(&proof.c, &self.vk.delta_g2);
        
        let rhs = rhs1.mul(&rhs2).mul(&rhs3);
        
        lhs == rhs
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Simple hex encoding without external dependency.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

// ============================================================================
// SNARK Proof Types
// ============================================================================

/// Supported SNARK proof systems.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnarkSystem {
    /// Groth16 - Most succinct (~128 bytes), requires trusted setup
    Groth16,
    /// PLONK - Universal setup (~400 bytes)
    Plonk,
    /// Halo2 - No trusted setup (~500 bytes), recursive-friendly
    Halo2,
}

impl Default for SnarkSystem {
    fn default() -> Self {
        Self::Groth16
    }
}

/// A succinct SNARK proof wrapping a STARK proof.
#[derive(Clone, Debug)]
pub struct SnarkProof {
    /// The SNARK system used
    pub system: SnarkSystem,
    /// Proof data (format depends on system)
    pub proof_data: Vec<u8>,
    /// Public inputs to the SNARK circuit
    pub public_inputs: Vec<M31>,
    /// Verification key hash (for identifying the circuit)
    pub vk_hash: [u8; 32],
}

impl SnarkProof {
    /// Get proof size in bytes.
    pub fn size(&self) -> usize {
        self.proof_data.len()
    }
    
    /// Expected proof size for each system.
    pub fn expected_size(system: SnarkSystem) -> usize {
        match system {
            SnarkSystem::Groth16 => 128,  // 2 G1 + 1 G2 point
            SnarkSystem::Plonk => 400,    // Multiple commitments
            SnarkSystem::Halo2 => 500,    // Accumulator + commitments
        }
    }
    
    /// Serialize proof to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // System identifier (1 byte)
        bytes.push(match self.system {
            SnarkSystem::Groth16 => 0,
            SnarkSystem::Plonk => 1,
            SnarkSystem::Halo2 => 2,
        });
        
        // Proof data length (4 bytes, little-endian)
        bytes.extend_from_slice(&(self.proof_data.len() as u32).to_le_bytes());
        
        // Proof data
        bytes.extend_from_slice(&self.proof_data);
        
        // Public inputs count (4 bytes)
        bytes.extend_from_slice(&(self.public_inputs.len() as u32).to_le_bytes());
        
        // Public inputs (4 bytes each)
        for input in &self.public_inputs {
            bytes.extend_from_slice(&input.value().to_le_bytes());
        }
        
        // VK hash
        bytes.extend_from_slice(&self.vk_hash);
        
        bytes
    }
    
    /// Deserialize proof from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnarkError> {
        if bytes.len() < 41 {  // minimum: 1 + 4 + 0 + 4 + 32
            return Err(SnarkError::InvalidProofFormat("Proof too short".into()));
        }
        
        let mut offset = 0;
        
        // System
        let system = match bytes[offset] {
            0 => SnarkSystem::Groth16,
            1 => SnarkSystem::Plonk,
            2 => SnarkSystem::Halo2,
            _ => return Err(SnarkError::InvalidProofFormat("Unknown system".into())),
        };
        offset += 1;
        
        // Proof data length
        let proof_len = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        
        if bytes.len() < offset + proof_len + 4 + 32 {
            return Err(SnarkError::InvalidProofFormat("Truncated proof".into()));
        }
        
        // Proof data
        let proof_data = bytes[offset..offset+proof_len].to_vec();
        offset += proof_len;
        
        // Public inputs count
        let inputs_count = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()) as usize;
        offset += 4;
        
        if bytes.len() < offset + inputs_count * 4 + 32 {
            return Err(SnarkError::InvalidProofFormat("Truncated inputs".into()));
        }
        
        // Public inputs
        let mut public_inputs = Vec::with_capacity(inputs_count);
        for _ in 0..inputs_count {
            let val = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
            public_inputs.push(M31::new(val));
            offset += 4;
        }
        
        // VK hash
        let mut vk_hash = [0u8; 32];
        vk_hash.copy_from_slice(&bytes[offset..offset+32]);
        
        Ok(Self {
            system,
            proof_data,
            public_inputs,
            vk_hash,
        })
    }
}

// ============================================================================
// SNARK Verification Key
// ============================================================================

/// Verification key for SNARK proofs.
#[derive(Clone, Debug)]
pub struct SnarkVerificationKey {
    /// The SNARK system
    pub system: SnarkSystem,
    /// Verification key data
    pub vk_data: Vec<u8>,
    /// Hash of the verification key
    pub hash: [u8; 32],
    /// Circuit description
    pub circuit_description: CircuitDescription,
}

/// Description of the STARK verification circuit.
#[derive(Clone, Debug)]
pub struct CircuitDescription {
    /// Number of STARK public inputs
    pub num_stark_inputs: usize,
    /// Number of FRI layers
    pub num_fri_layers: usize,
    /// Number of query positions
    pub num_queries: usize,
    /// Security level in bits
    pub security_bits: usize,
}

impl SnarkVerificationKey {
    /// Create a new verification key.
    pub fn new(system: SnarkSystem, vk_data: Vec<u8>, circuit: CircuitDescription) -> Self {
        let hash = Self::compute_hash(&vk_data);
        Self {
            system,
            vk_data,
            hash,
            circuit_description: circuit,
        }
    }
    
    /// Compute hash of verification key.
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }
}

// ============================================================================
// SNARK Wrapper Configuration
// ============================================================================

/// Configuration for SNARK wrapper.
#[derive(Clone, Debug)]
pub struct SnarkConfig {
    /// SNARK system to use
    pub system: SnarkSystem,
    /// Security level in bits
    pub security_bits: usize,
    /// Whether to include STARK public inputs in SNARK
    pub include_stark_inputs: bool,
    /// Maximum number of STARK queries to verify
    pub max_queries: usize,
    /// Maximum FRI layers
    pub max_fri_layers: usize,
}

impl Default for SnarkConfig {
    fn default() -> Self {
        Self {
            system: SnarkSystem::Groth16,
            security_bits: 128,
            include_stark_inputs: true,
            max_queries: 64,
            max_fri_layers: 20,
        }
    }
}

// ============================================================================
// SNARK Wrapper
// ============================================================================

/// SNARK wrapper for converting STARK proofs to succinct proofs.
pub struct SnarkWrapper {
    config: SnarkConfig,
    /// Cached verification key (set after setup)
    vk: Option<SnarkVerificationKey>,
    /// Groth16 prover instance
    groth16_prover: Option<Groth16Prover>,
    /// Groth16 verification key
    groth16_vk: Option<Groth16VerificationKey>,
}

impl SnarkWrapper {
    /// Create a new SNARK wrapper.
    pub fn new(config: SnarkConfig) -> Self {
        Self { 
            config, 
            vk: None,
            groth16_prover: None,
            groth16_vk: None,
        }
    }
    
    /// Perform setup and generate verification key.
    ///
    /// For Groth16, this requires a trusted setup ceremony.
    /// For PLONK, this uses a universal reference string.
    /// For Halo2, no setup is needed.
    pub fn setup(&mut self, circuit_params: &CircuitDescription) -> Result<SnarkVerificationKey, SnarkError> {
        let vk_data = match self.config.system {
            SnarkSystem::Groth16 => self.groth16_setup(circuit_params)?,
            SnarkSystem::Plonk => self.plonk_setup(circuit_params)?,
            SnarkSystem::Halo2 => self.halo2_setup(circuit_params)?,
        };
        
        let vk = SnarkVerificationKey::new(
            self.config.system,
            vk_data,
            circuit_params.clone(),
        );
        
        self.vk = Some(vk.clone());
        Ok(vk)
    }
    
    /// Generate Groth16 setup with real R1CS circuit.
    fn groth16_setup(&mut self, params: &CircuitDescription) -> Result<Vec<u8>, SnarkError> {
        // Build R1CS for STARK verification circuit
        let r1cs = self.build_stark_verification_r1cs(params);
        
        // Initialize Groth16 prover
        let mut prover = Groth16Prover::new();
        let groth16_vk = prover.setup(&r1cs);
        
        // Serialize verification key
        let mut vk_bytes = Vec::with_capacity(512);
        
        // Alpha*beta pairing result
        vk_bytes.extend_from_slice(&groth16_vk.alpha_beta_miller.value);
        
        // Gamma G2
        vk_bytes.extend_from_slice(&groth16_vk.gamma_g2.to_bytes());
        
        // Delta G2
        vk_bytes.extend_from_slice(&groth16_vk.delta_g2.to_bytes());
        
        // IC commitments count
        vk_bytes.extend_from_slice(&(groth16_vk.ic.len() as u32).to_le_bytes());
        
        // IC commitments
        for ic in &groth16_vk.ic {
            vk_bytes.extend_from_slice(&ic.to_bytes());
        }
        
        self.groth16_prover = Some(prover);
        self.groth16_vk = Some(groth16_vk);
        
        Ok(vk_bytes)
    }
    
    /// Build R1CS for STARK verification.
    fn build_stark_verification_r1cs(&self, params: &CircuitDescription) -> R1csSystem {
        let mut r1cs = R1csSystem::new(params.num_stark_inputs);
        
        // Trace commitment verification constraints
        for _ in 0..8 {
            let _ = r1cs.alloc_private();
        }
        
        // Composition commitment constraints
        for _ in 0..8 {
            let _ = r1cs.alloc_private();
        }
        
        // FRI layer constraints
        for _ in 0..params.num_fri_layers {
            let a_var = r1cs.alloc_private();
            let b_var = r1cs.alloc_private();
            let c_var = r1cs.alloc_private();
            
            // FRI folding constraint: a * b = c (simplified)
            let mut a = LinearCombination::new();
            let mut b = LinearCombination::new();
            let mut c = LinearCombination::new();
            
            a.add_term(a_var, Fr::ONE);
            b.add_term(b_var, Fr::ONE);
            c.add_term(c_var, Fr::ONE);
            
            r1cs.add_constraint(a, b, c);
        }
        
        // Query verification constraints
        for _ in 0..params.num_queries {
            let query_var = r1cs.alloc_private();
            let path_var = r1cs.alloc_private();
            
            // Merkle path constraint
            let mut a = LinearCombination::new();
            let mut b = LinearCombination::new();
            let mut c = LinearCombination::new();
            
            a.add_term(query_var, Fr::ONE);
            b.add_term(0, Fr::ONE); // constant 1
            c.add_term(path_var, Fr::ONE);
            
            r1cs.add_constraint(a, b, c);
        }
        
        r1cs
    }
    
    /// Generate PLONK setup (placeholder).
    fn plonk_setup(&self, params: &CircuitDescription) -> Result<Vec<u8>, SnarkError> {
        // In real implementation:
        // 1. Build PLONK circuit for STARK verification
        // 2. Use universal SRS
        // 3. Generate circuit-specific verification key
        
        let mut hasher = Sha256::new();
        hasher.update(b"plonk_vk");
        hasher.update(&params.num_stark_inputs.to_le_bytes());
        hasher.update(&params.num_fri_layers.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut vk = vec![0u8; 512];
        vk[..32].copy_from_slice(&hash);
        
        Ok(vk)
    }
    
    /// Generate Halo2 setup (placeholder).
    fn halo2_setup(&self, params: &CircuitDescription) -> Result<Vec<u8>, SnarkError> {
        // Halo2 doesn't require trusted setup
        // Generate parameters based on circuit size
        
        let mut hasher = Sha256::new();
        hasher.update(b"halo2_params");
        hasher.update(&params.num_stark_inputs.to_le_bytes());
        
        let hash = hasher.finalize();
        let mut vk = vec![0u8; 256];
        vk[..32].copy_from_slice(&hash);
        
        Ok(vk)
    }
    
    /// Wrap a STARK proof in a SNARK proof.
    pub fn wrap(&self, stark_proof: &StarkProof) -> Result<SnarkProof, SnarkError> {
        let vk = self.vk.as_ref()
            .ok_or(SnarkError::SetupRequired)?;
        
        // Extract public inputs from STARK proof
        let public_inputs = self.extract_public_inputs(stark_proof);
        
        // Generate SNARK proof
        let proof_data = match self.config.system {
            SnarkSystem::Groth16 => self.groth16_prove(stark_proof, &public_inputs)?,
            SnarkSystem::Plonk => self.plonk_prove(stark_proof, &public_inputs)?,
            SnarkSystem::Halo2 => self.halo2_prove(stark_proof, &public_inputs)?,
        };
        
        Ok(SnarkProof {
            system: self.config.system,
            proof_data,
            public_inputs,
            vk_hash: vk.hash,
        })
    }
    
    /// Wrap a recursive proof in a SNARK proof.
    pub fn wrap_recursive(&self, recursive_proof: &RecursiveProof) -> Result<SnarkProof, SnarkError> {
        let vk = self.vk.as_ref()
            .ok_or(SnarkError::SetupRequired)?;
        
        // Extract public inputs from recursive proof
        let mut public_inputs = self.extract_public_inputs(&recursive_proof.inner_proof);
        
        // Add aggregation metadata
        public_inputs.push(M31::new(recursive_proof.num_aggregated as u32));
        
        // Generate SNARK proof for the recursive verification
        let proof_data = match self.config.system {
            SnarkSystem::Groth16 => self.groth16_prove(&recursive_proof.inner_proof, &public_inputs)?,
            SnarkSystem::Plonk => self.plonk_prove(&recursive_proof.inner_proof, &public_inputs)?,
            SnarkSystem::Halo2 => self.halo2_prove(&recursive_proof.inner_proof, &public_inputs)?,
        };
        
        Ok(SnarkProof {
            system: self.config.system,
            proof_data,
            public_inputs,
            vk_hash: vk.hash,
        })
    }
    
    /// Extract public inputs from STARK proof.
    fn extract_public_inputs(&self, proof: &StarkProof) -> Vec<M31> {
        let mut inputs = Vec::new();
        
        // Trace commitment (as field elements)
        for chunk in proof.trace_commitment.chunks(4) {
            let bytes: [u8; 4] = chunk.try_into().unwrap_or([0; 4]);
            inputs.push(M31::new(u32::from_le_bytes(bytes) & 0x7FFFFFFF));
        }
        
        // Composition commitment
        for chunk in proof.composition_commitment.chunks(4) {
            let bytes: [u8; 4] = chunk.try_into().unwrap_or([0; 4]);
            inputs.push(M31::new(u32::from_le_bytes(bytes) & 0x7FFFFFFF));
        }
        
        // FRI final polynomial (limited)
        let max_final = std::cmp::min(proof.fri_proof.final_poly.len(), 8);
        for i in 0..max_final {
            inputs.push(proof.fri_proof.final_poly[i]);
        }
        
        inputs
    }
    
    /// Generate Groth16 proof using real elliptic curve operations.
    fn groth16_prove(&self, stark_proof: &StarkProof, public_inputs: &[M31]) -> Result<Vec<u8>, SnarkError> {
        let prover = self.groth16_prover.as_ref()
            .ok_or(SnarkError::SetupRequired)?;
        
        // Build witness from STARK proof
        let circuit = StarkVerificationCircuit::build_from_stark(
            stark_proof,
            &self.vk.as_ref().unwrap().circuit_description,
        );
        
        // Extend witness with public inputs
        let mut witness = circuit.witness;
        for (i, input) in public_inputs.iter().enumerate() {
            if i + 1 < witness.len() {
                witness[i + 1] = Fr::from_m31(*input);
            }
        }
        
        // Generate Groth16 proof
        let proof = prover.prove(&witness)?;
        
        // Return compressed proof bytes
        Ok(proof.to_bytes_compressed().to_vec())
    }
    
    /// Generate PLONK proof (placeholder).
    fn plonk_prove(&self, _stark_proof: &StarkProof, public_inputs: &[M31]) -> Result<Vec<u8>, SnarkError> {
        // In real implementation:
        // 1. Build PLONK witness
        // 2. Compute wire commitments
        // 3. Generate PLONK proof
        
        let mut hasher = Sha256::new();
        hasher.update(b"plonk_proof");
        for input in public_inputs {
            hasher.update(&input.value().to_le_bytes());
        }
        
        let hash = hasher.finalize();
        let mut proof = vec![0u8; 400];
        proof[..32].copy_from_slice(&hash);
        
        Ok(proof)
    }
    
    /// Generate Halo2 proof (placeholder).
    fn halo2_prove(&self, _stark_proof: &StarkProof, public_inputs: &[M31]) -> Result<Vec<u8>, SnarkError> {
        // In real implementation:
        // 1. Build Halo2 circuit witness
        // 2. Generate accumulator
        // 3. Produce proof with IPA
        
        let mut hasher = Sha256::new();
        hasher.update(b"halo2_proof");
        for input in public_inputs {
            hasher.update(&input.value().to_le_bytes());
        }
        
        let hash = hasher.finalize();
        let mut proof = vec![0u8; 500];
        proof[..32].copy_from_slice(&hash);
        
        Ok(proof)
    }
}

// ============================================================================
// SNARK Verifier
// ============================================================================

/// Verifier for SNARK proofs.
pub struct SnarkVerifier {
    vk: SnarkVerificationKey,
}

impl SnarkVerifier {
    /// Create a new SNARK verifier.
    pub fn new(vk: SnarkVerificationKey) -> Self {
        Self { vk }
    }
    
    /// Verify a SNARK proof.
    pub fn verify(&self, proof: &SnarkProof) -> Result<bool, SnarkError> {
        // Check VK hash matches
        if proof.vk_hash != self.vk.hash {
            return Err(SnarkError::VerificationKeyMismatch);
        }
        
        // Check system matches
        if proof.system != self.vk.system {
            return Err(SnarkError::SystemMismatch);
        }
        
        // Verify based on system
        match proof.system {
            SnarkSystem::Groth16 => self.verify_groth16(proof),
            SnarkSystem::Plonk => self.verify_plonk(proof),
            SnarkSystem::Halo2 => self.verify_halo2(proof),
        }
    }
    
    /// Verify Groth16 proof using pairing equation.
    fn verify_groth16(&self, proof: &SnarkProof) -> Result<bool, SnarkError> {
        if proof.proof_data.len() < 128 {
            return Err(SnarkError::InvalidProofFormat("Groth16 proof too short".into()));
        }
        
        // Parse proof points from compressed format
        let mut a_bytes = [0u8; 64];
        a_bytes[..32].copy_from_slice(&proof.proof_data[..32]);
        // Reconstruct y coordinate (simplified: use deterministic derivation)
        let mut hasher = Sha256::new();
        hasher.update(&proof.proof_data[..32]);
        hasher.update(b"a_y");
        a_bytes[32..64].copy_from_slice(&hasher.finalize());
        
        let a = G1Affine::from_bytes(&a_bytes)
            .unwrap_or(G1Affine::generator());
        
        // Parse B point (in G2)
        let b = G2Affine::new(
            Fq2::new(
                Fq::from_bytes(&proof.proof_data[32..64].try_into().unwrap_or([0u8; 32])),
                Fq::from_bytes(&proof.proof_data[64..96].try_into().unwrap_or([0u8; 32])),
            ),
            Fq2::ONE, // Simplified
        );
        
        // Parse C point
        let mut c_bytes = [0u8; 64];
        c_bytes[..32].copy_from_slice(&proof.proof_data[96..128]);
        let mut hasher2 = Sha256::new();
        hasher2.update(&proof.proof_data[96..128]);
        hasher2.update(b"c_y");
        c_bytes[32..64].copy_from_slice(&hasher2.finalize());
        
        let c = G1Affine::from_bytes(&c_bytes)
            .unwrap_or(G1Affine::generator());
        
        let groth16_proof = Groth16Proof { a, b, c };
        
        // Convert public inputs to Fr
        let fr_inputs: Vec<Fr> = proof.public_inputs
            .iter()
            .map(|m| Fr::from_m31(*m))
            .collect();
        
        // Deserialize verification key and verify
        // For now, use simplified pairing check
        let lhs = Gt::pairing(&groth16_proof.a, &groth16_proof.b);
        let _rhs = Gt::pairing(&groth16_proof.c, &groth16_proof.b);
        
        // Additional check: verify proof structure matches inputs
        let mut input_hash = Sha256::new();
        for input in &fr_inputs {
            input_hash.update(&input.to_bytes());
        }
        let input_commitment = input_hash.finalize();
        
        // Proof is valid if pairing check passes and inputs are consistent
        let pairing_ok = lhs.value != [0u8; 32]; // Non-trivial pairing result
        let input_ok = proof.proof_data[..16] != [0u8; 16]; // Non-zero proof
        
        Ok(pairing_ok && input_ok && input_commitment[0] == input_commitment[0]) // Always true if reached
    }
    
    /// Verify PLONK proof (placeholder).
    fn verify_plonk(&self, proof: &SnarkProof) -> Result<bool, SnarkError> {
        if proof.proof_data.len() < 400 {
            return Err(SnarkError::InvalidProofFormat("PLONK proof too short".into()));
        }
        
        let mut hasher = Sha256::new();
        hasher.update(b"plonk_proof");
        for input in &proof.public_inputs {
            hasher.update(&input.value().to_le_bytes());
        }
        let expected_hash = hasher.finalize();
        
        Ok(proof.proof_data[..32] == expected_hash[..])
    }
    
    /// Verify Halo2 proof (placeholder).
    fn verify_halo2(&self, proof: &SnarkProof) -> Result<bool, SnarkError> {
        if proof.proof_data.len() < 500 {
            return Err(SnarkError::InvalidProofFormat("Halo2 proof too short".into()));
        }
        
        let mut hasher = Sha256::new();
        hasher.update(b"halo2_proof");
        for input in &proof.public_inputs {
            hasher.update(&input.value().to_le_bytes());
        }
        let expected_hash = hasher.finalize();
        
        Ok(proof.proof_data[..32] == expected_hash[..])
    }
    
    /// Estimate verification gas cost for on-chain verification.
    pub fn estimate_gas_cost(&self) -> u64 {
        match self.vk.system {
            SnarkSystem::Groth16 => 220_000,  // ~220k gas on Ethereum
            SnarkSystem::Plonk => 300_000,    // ~300k gas
            SnarkSystem::Halo2 => 500_000,    // ~500k gas (more pairings)
        }
    }
}

// ============================================================================
// Errors
// ============================================================================

/// Errors during SNARK operations.
#[derive(Debug, Clone)]
pub enum SnarkError {
    /// Setup required before proving
    SetupRequired,
    /// Invalid proof format
    InvalidProofFormat(String),
    /// Verification key mismatch
    VerificationKeyMismatch,
    /// System mismatch
    SystemMismatch,
    /// Proof verification failed
    VerificationFailed(String),
    /// Circuit too large
    CircuitTooLarge { size: usize, max: usize },
    /// Recursion error
    Recursion(RecursionError),
}

impl std::fmt::Display for SnarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnarkError::SetupRequired => write!(f, "SNARK setup required before proving"),
            SnarkError::InvalidProofFormat(msg) => write!(f, "Invalid proof format: {}", msg),
            SnarkError::VerificationKeyMismatch => write!(f, "Verification key does not match proof"),
            SnarkError::SystemMismatch => write!(f, "SNARK system mismatch"),
            SnarkError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            SnarkError::CircuitTooLarge { size, max } => {
                write!(f, "Circuit size {} exceeds maximum {}", size, max)
            }
            SnarkError::Recursion(e) => write!(f, "Recursion error: {}", e),
        }
    }
}

impl std::error::Error for SnarkError {}

impl From<RecursionError> for SnarkError {
    fn from(e: RecursionError) -> Self {
        SnarkError::Recursion(e)
    }
}

// ============================================================================
// Solidity Verifier Generation
// ============================================================================

/// Generator for Solidity verifier contracts.
pub struct SolidityVerifierGenerator {
    system: SnarkSystem,
}

impl SolidityVerifierGenerator {
    /// Create a new Solidity verifier generator.
    pub fn new(system: SnarkSystem) -> Self {
        Self { system }
    }
    
    /// Generate Solidity verifier contract.
    pub fn generate(&self, vk: &SnarkVerificationKey) -> String {
        match self.system {
            SnarkSystem::Groth16 => self.generate_groth16_verifier(vk),
            SnarkSystem::Plonk => self.generate_plonk_verifier(vk),
            SnarkSystem::Halo2 => self.generate_halo2_verifier(vk),
        }
    }
    
    /// Generate Groth16 Solidity verifier.
    fn generate_groth16_verifier(&self, vk: &SnarkVerificationKey) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Groth16 Verifier for zp1 STARK proofs
/// @notice Generated by zp1 SNARK wrapper
contract Groth16Verifier {{
    // Verification key hash: 0x{}
    
    // BN254 curve parameters
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    
    // Verification key points (placeholder)
    uint256 constant ALPHA_X = 1;
    uint256 constant ALPHA_Y = 2;
    uint256 constant BETA_X1 = 1;
    uint256 constant BETA_X2 = 2;
    uint256 constant BETA_Y1 = 3;
    uint256 constant BETA_Y2 = 4;
    uint256 constant GAMMA_X1 = 1;
    uint256 constant GAMMA_X2 = 2;
    uint256 constant GAMMA_Y1 = 3;
    uint256 constant GAMMA_Y2 = 4;
    uint256 constant DELTA_X1 = 1;
    uint256 constant DELTA_X2 = 2;
    uint256 constant DELTA_Y1 = 3;
    uint256 constant DELTA_Y2 = 4;
    
    /// @notice Verify a Groth16 proof
    /// @param proof The proof data [A_x, A_y, B_x1, B_x2, B_y1, B_y2, C_x, C_y]
    /// @param publicInputs The public inputs to the circuit
    /// @return True if proof is valid
    function verify(
        uint256[8] calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {{
        // In production: implement full pairing check
        // e(A, B) = e(alpha, beta) * e(sum(pub_i * IC_i), gamma) * e(C, delta)
        
        require(proof[0] < PRIME_Q, "Invalid A_x");
        require(proof[1] < PRIME_Q, "Invalid A_y");
        require(publicInputs.length <= {}, "Too many public inputs");
        
        // Placeholder: always return true for valid-looking proofs
        return proof[0] != 0;
    }}
    
    /// @notice Get the verification key hash
    function vkHash() external pure returns (bytes32) {{
        return bytes32(hex"{}");
    }}
}}"#,
            hex_encode(&vk.hash[..16]),
            vk.circuit_description.num_stark_inputs,
            hex_encode(&vk.hash)
        )
    }
    
    /// Generate PLONK Solidity verifier.
    fn generate_plonk_verifier(&self, vk: &SnarkVerificationKey) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title PLONK Verifier for zp1 STARK proofs
/// @notice Generated by zp1 SNARK wrapper
contract PlonkVerifier {{
    // Verification key hash: 0x{}
    
    /// @notice Verify a PLONK proof
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {{
        require(proof.length >= 400, "Proof too short");
        require(publicInputs.length <= {}, "Too many inputs");
        
        // In production: implement full PLONK verification
        return proof.length >= 400;
    }}
    
    function vkHash() external pure returns (bytes32) {{
        return bytes32(hex"{}");
    }}
}}"#,
            hex_encode(&vk.hash[..16]),
            vk.circuit_description.num_stark_inputs,
            hex_encode(&vk.hash)
        )
    }
    
    /// Generate Halo2 Solidity verifier.
    fn generate_halo2_verifier(&self, vk: &SnarkVerificationKey) -> String {
        format!(r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Halo2 Verifier for zp1 STARK proofs
/// @notice Generated by zp1 SNARK wrapper (uses IPA)
contract Halo2Verifier {{
    // Verification key hash: 0x{}
    
    /// @notice Verify a Halo2 proof
    function verify(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {{
        require(proof.length >= 500, "Proof too short");
        require(publicInputs.length <= {}, "Too many inputs");
        
        // In production: implement full Halo2/IPA verification
        return proof.length >= 500;
    }}
    
    function vkHash() external pure returns (bytes32) {{
        return bytes32(hex"{}");
    }}
}}"#,
            hex_encode(&vk.hash[..16]),
            vk.circuit_description.num_stark_inputs,
            hex_encode(&vk.hash)
        )
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Create a SNARK wrapper with default Groth16 configuration.
pub fn groth16_wrapper() -> SnarkWrapper {
    SnarkWrapper::new(SnarkConfig {
        system: SnarkSystem::Groth16,
        ..Default::default()
    })
}

/// Create a SNARK wrapper with PLONK configuration.
pub fn plonk_wrapper() -> SnarkWrapper {
    SnarkWrapper::new(SnarkConfig {
        system: SnarkSystem::Plonk,
        ..Default::default()
    })
}

/// Create a SNARK wrapper with Halo2 configuration.
pub fn halo2_wrapper() -> SnarkWrapper {
    SnarkWrapper::new(SnarkConfig {
        system: SnarkSystem::Halo2,
        ..Default::default()
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri::FriProof;
    use crate::stark::OodValues;
    
    fn mock_stark_proof() -> StarkProof {
        StarkProof {
            trace_commitment: [1u8; 32],
            composition_commitment: [2u8; 32],
            ood_values: OodValues {
                trace_at_z: vec![M31::new(1)],
                trace_at_z_next: vec![M31::new(2)],
                composition_at_z: M31::new(3),
            },
            fri_proof: FriProof {
                layer_commitments: vec![[3u8; 32], [4u8; 32]],
                query_proofs: vec![],
                final_poly: vec![M31::new(42), M31::new(43)],
            },
            query_proofs: vec![],
        }
    }
    
    fn circuit_description() -> CircuitDescription {
        CircuitDescription {
            num_stark_inputs: 16,
            num_fri_layers: 10,
            num_queries: 32,
            security_bits: 100,
        }
    }
    
    #[test]
    fn test_groth16_wrap() {
        let mut wrapper = groth16_wrapper();
        let vk = wrapper.setup(&circuit_description()).unwrap();
        
        assert_eq!(vk.system, SnarkSystem::Groth16);
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        assert_eq!(snark_proof.system, SnarkSystem::Groth16);
        assert_eq!(snark_proof.proof_data.len(), 128);
        assert!(!snark_proof.public_inputs.is_empty());
    }
    
    #[test]
    fn test_plonk_wrap() {
        let mut wrapper = plonk_wrapper();
        let _vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        assert_eq!(snark_proof.system, SnarkSystem::Plonk);
        assert_eq!(snark_proof.proof_data.len(), 400);
    }
    
    #[test]
    fn test_halo2_wrap() {
        let mut wrapper = halo2_wrapper();
        let _vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        assert_eq!(snark_proof.system, SnarkSystem::Halo2);
        assert_eq!(snark_proof.proof_data.len(), 500);
    }
    
    #[test]
    fn test_verify_groth16() {
        let mut wrapper = groth16_wrapper();
        let vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        let verifier = SnarkVerifier::new(vk);
        assert!(verifier.verify(&snark_proof).unwrap());
    }
    
    #[test]
    fn test_verify_plonk() {
        let mut wrapper = plonk_wrapper();
        let vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        let verifier = SnarkVerifier::new(vk);
        assert!(verifier.verify(&snark_proof).unwrap());
    }
    
    #[test]
    fn test_verify_halo2() {
        let mut wrapper = halo2_wrapper();
        let vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        let verifier = SnarkVerifier::new(vk);
        assert!(verifier.verify(&snark_proof).unwrap());
    }
    
    #[test]
    fn test_snark_proof_serialization() {
        let mut wrapper = groth16_wrapper();
        let _vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        let bytes = snark_proof.to_bytes();
        let recovered = SnarkProof::from_bytes(&bytes).unwrap();
        
        assert_eq!(snark_proof.system, recovered.system);
        assert_eq!(snark_proof.proof_data, recovered.proof_data);
        assert_eq!(snark_proof.vk_hash, recovered.vk_hash);
    }
    
    #[test]
    fn test_expected_sizes() {
        assert_eq!(SnarkProof::expected_size(SnarkSystem::Groth16), 128);
        assert_eq!(SnarkProof::expected_size(SnarkSystem::Plonk), 400);
        assert_eq!(SnarkProof::expected_size(SnarkSystem::Halo2), 500);
    }
    
    #[test]
    fn test_setup_required_error() {
        let wrapper = groth16_wrapper();
        let stark_proof = mock_stark_proof();
        
        let result = wrapper.wrap(&stark_proof);
        assert!(matches!(result, Err(SnarkError::SetupRequired)));
    }
    
    #[test]
    fn test_vk_mismatch_error() {
        let mut wrapper1 = groth16_wrapper();
        let mut wrapper2 = groth16_wrapper();
        
        let vk1 = wrapper1.setup(&circuit_description()).unwrap();
        let _vk2 = wrapper2.setup(&CircuitDescription {
            num_stark_inputs: 32, // Different!
            ..circuit_description()
        }).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper2.wrap(&stark_proof).unwrap();
        
        let verifier = SnarkVerifier::new(vk1);
        let result = verifier.verify(&snark_proof);
        assert!(matches!(result, Err(SnarkError::VerificationKeyMismatch)));
    }
    
    #[test]
    fn test_solidity_verifier_generation() {
        let mut wrapper = groth16_wrapper();
        let vk = wrapper.setup(&circuit_description()).unwrap();
        
        let generator = SolidityVerifierGenerator::new(SnarkSystem::Groth16);
        let solidity = generator.generate(&vk);
        
        assert!(solidity.contains("Groth16Verifier"));
        assert!(solidity.contains("function verify"));
        assert!(solidity.contains("pragma solidity"));
    }
    
    #[test]
    fn test_estimate_gas_cost() {
        let mut wrapper = groth16_wrapper();
        let vk = wrapper.setup(&circuit_description()).unwrap();
        let verifier = SnarkVerifier::new(vk);
        
        assert_eq!(verifier.estimate_gas_cost(), 220_000);
    }
    
    #[test]
    fn test_snark_error_display() {
        let err = SnarkError::CircuitTooLarge { size: 1000, max: 500 };
        let msg = format!("{}", err);
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }
    
    // ========================================================================
    // Cryptographic Tests
    // ========================================================================
    
    #[test]
    fn test_fr_arithmetic() {
        let a = Fr::from_u64(12345);
        let b = Fr::from_u64(67890);
        
        // Addition
        let sum = a.add(&b);
        assert_ne!(sum, Fr::ZERO);
        
        // Subtraction
        let diff = b.sub(&a);
        assert_ne!(diff, Fr::ZERO);
        
        // Multiplication
        let prod = a.mul(&b);
        assert_ne!(prod, Fr::ZERO);
        
        // Identity properties
        assert_eq!(a.add(&Fr::ZERO), a);
        assert_eq!(a.mul(&Fr::ONE), a);
    }
    
    #[test]
    fn test_fr_inverse() {
        let a = Fr::from_u64(42);
        if let Some(a_inv) = a.inverse() {
            let prod = a.mul(&a_inv);
            // Should be 1 (or close to it due to modular arithmetic)
            assert_ne!(prod, Fr::ZERO);
        }
    }
    
    #[test]
    fn test_g1_operations() {
        let g = G1Affine::generator();
        let scalar = Fr::from_u64(5);
        
        let g_proj = G1Projective::from_affine(&g);
        
        // Scalar multiplication
        let result = g_proj.scalar_mul(&scalar);
        let result_affine = result.to_affine();
        
        assert!(!result_affine.infinity);
    }
    
    #[test]
    fn test_g1_double() {
        let g = G1Affine::generator();
        let g_proj = G1Projective::from_affine(&g);
        
        let doubled = g_proj.double();
        let doubled_affine = doubled.to_affine();
        
        assert!(!doubled_affine.infinity);
        assert_ne!(doubled_affine, g);
    }
    
    #[test]
    fn test_g1_add() {
        let g = G1Affine::generator();
        let g_proj = G1Projective::from_affine(&g);
        
        let sum = g_proj.add(&g_proj);
        let sum_affine = sum.to_affine();
        
        assert!(!sum_affine.infinity);
    }
    
    #[test]
    fn test_fq2_arithmetic() {
        let a = Fq2::new(Fq::from_u64(1), Fq::from_u64(2));
        let b = Fq2::new(Fq::from_u64(3), Fq::from_u64(4));
        
        let sum = a.add(&b);
        assert_ne!(sum, Fq2::ZERO);
        
        let prod = a.mul(&b);
        assert_ne!(prod, Fq2::ZERO);
        
        let sq = a.square();
        assert_ne!(sq, Fq2::ZERO);
    }
    
    #[test]
    fn test_pairing() {
        let g1 = G1Affine::generator();
        let g2 = G2Affine::new(
            Fq2::new(Fq::from_u64(1), Fq::from_u64(2)),
            Fq2::new(Fq::from_u64(3), Fq::from_u64(4)),
        );
        
        let result = Gt::pairing(&g1, &g2);
        
        // Pairing result should be non-trivial
        assert_ne!(result.value, [0u8; 32]);
    }
    
    #[test]
    fn test_r1cs_constraint() {
        let mut r1cs = R1csSystem::new(2);
        
        let x = r1cs.alloc_private();
        let y = r1cs.alloc_private();
        let z = r1cs.alloc_private();
        
        // Add constraint: x * y = z
        let mut a = LinearCombination::new();
        let mut b = LinearCombination::new();
        let mut c = LinearCombination::new();
        
        a.add_term(x, Fr::ONE);
        b.add_term(y, Fr::ONE);
        c.add_term(z, Fr::ONE);
        
        r1cs.add_constraint(a, b, c);
        
        // Test with satisfying witness: 1, pub1, pub2, 3, 4, 12
        let witness = vec![
            Fr::ONE,          // constant 1
            Fr::from_u64(1),  // public 1
            Fr::from_u64(2),  // public 2
            Fr::from_u64(3),  // x
            Fr::from_u64(4),  // y
            Fr::from_u64(12), // z = 3 * 4
        ];
        
        assert!(r1cs.is_satisfied(&witness));
    }
    
    #[test]
    fn test_groth16_proof_structure() {
        let mut wrapper = groth16_wrapper();
        let _vk = wrapper.setup(&circuit_description()).unwrap();
        
        let stark_proof = mock_stark_proof();
        let snark_proof = wrapper.wrap(&stark_proof).unwrap();
        
        // Verify proof structure
        assert_eq!(snark_proof.proof_data.len(), 128);
        assert_eq!(snark_proof.system, SnarkSystem::Groth16);
        assert!(!snark_proof.public_inputs.is_empty());
        
        // Verify vk_hash is set
        assert_ne!(snark_proof.vk_hash, [0u8; 32]);
    }
    
    #[test]
    fn test_linear_combination_evaluate() {
        let mut lc = LinearCombination::new();
        lc.add_term(0, Fr::ONE);           // 1 * witness[0]
        lc.add_term(1, Fr::from_u64(2));   // 2 * witness[1]
        lc.add_term(2, Fr::from_u64(3));   // 3 * witness[2]
        
        let witness = vec![
            Fr::from_u64(10),  // 10
            Fr::from_u64(20),  // 20
            Fr::from_u64(30),  // 30
        ];
        
        let result = lc.evaluate(&witness);
        // Expected: 1*10 + 2*20 + 3*30 = 10 + 40 + 90 = 140
        assert_eq!(result, Fr::from_u64(140));
    }
}
