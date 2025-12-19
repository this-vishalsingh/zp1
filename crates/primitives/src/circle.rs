//! Circle group and Circle FFT for Mersenne31 - Plonky3 Integration.
//!
//! This module provides Circle STARKs primitives using Plonky3's optimized
//! O(n log n) Circle FFT implementation with SIMD acceleration.
//!
//! # Circle STARKs Background
//!
//! The Mersenne31 field M31 doesn't have large 2-adic subgroups for standard NTT.
//! Instead, Circle STARKs use the **circle group**:
//! ```text
//! C(M31) = { (x, y) ∈ M31² : x² + y² = 1 }
//! ```
//!
//! This group has order |C| = p + 1 = 2^31, giving us a full 2-adic subgroup!
//!
//! # Performance
//!
//! This implementation leverages Plonky3's:
//! - O(n log n) Circle FFT via butterfly algorithm
//! - SIMD acceleration (NEON on Apple Silicon, AVX2/512 on x86)
//! - Parallel processing via Rayon
//!
//! # References
//!
//! - Circle STARKs paper: https://eprint.iacr.org/2024/278
//! - Plonky3: https://github.com/Plonky3/Plonky3

use crate::field::M31;
use crate::p3_interop::{to_p3, from_p3, to_p3_vec, from_p3_vec, P3M31};
use serde::{Deserialize, Serialize};

// Import Plonky3 traits
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::ComplexExtendable;
use p3_matrix::Matrix;

// Re-export Plonky3 types for advanced usage
pub use p3_circle::{
    CircleDomain as P3CircleDomain,
    CircleEvaluations as P3CircleEvaluations,
};

// ============================================================================
// Square Root in M31
// ============================================================================

/// Modular square root in M31.
/// Since M31 ≡ 3 (mod 4), we use: sqrt(a) = a^((p+1)/4) = a^(2^29)
pub fn sqrt_m31(a: M31) -> Option<M31> {
    if a.is_zero() {
        return Some(M31::ZERO);
    }

    let r = a.pow_u64(1u64 << 29);

    if r * r == a {
        Some(r)
    } else {
        None
    }
}

// ============================================================================
// Circle Point
// ============================================================================

/// A point on the unit circle x² + y² = 1 over M31.
///
/// Represents an element of the multiplicative circle group C(M31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CirclePoint {
    /// The x-coordinate (cos θ in the angle interpretation).
    pub x: M31,
    /// The y-coordinate (sin θ in the angle interpretation).
    pub y: M31,
}

impl CirclePoint {
    /// The identity element (1, 0) - corresponds to angle 0.
    pub const IDENTITY: Self = Self { x: M31::ONE, y: M31::ZERO };

    /// The point (0, 1) - corresponds to angle π/2, has order 4.
    pub const I: Self = Self { x: M31::ZERO, y: M31::ONE };

    /// The point (-1, 0) - corresponds to angle π, has order 2.
    pub const NEG_ONE: Self = Self { x: M31(M31::P - 1), y: M31::ZERO };

    /// Create a new circle point (does not verify it's on the circle).
    #[inline]
    pub const fn new(x: M31, y: M31) -> Self {
        Self { x, y }
    }

    /// Create a point from the x-coordinate, computing y = ±√(1 - x²).
    /// Returns the point with positive y (or y = 0).
    pub fn from_x(x: M31) -> Option<Self> {
        let y_squared = M31::ONE - x * x;
        sqrt_m31(y_squared).map(|y| Self { x, y })
    }

    /// Check if this point is on the unit circle: x² + y² = 1.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.x * self.x + self.y * self.y == M31::ONE
    }

    /// Check if this is the identity (1, 0).
    #[inline]
    pub fn is_identity(&self) -> bool {
        self.x == M31::ONE && self.y.is_zero()
    }

    /// Group multiplication (corresponds to adding angles).
    /// (x₁, y₁) · (x₂, y₂) = (x₁x₂ - y₁y₂, x₁y₂ + y₁x₂)
    #[inline]
    pub fn mul(self, other: Self) -> Self {
        Self {
            x: self.x * other.x - self.y * other.y,
            y: self.x * other.y + self.y * other.x,
        }
    }

    /// Squaring (doubling the angle).
    /// (x, y)² = (x² - y², 2xy) = (2x² - 1, 2xy)
    #[inline]
    pub fn double(self) -> Self {
        Self {
            x: self.x * self.x - self.y * self.y,
            y: self.x * self.y + self.x * self.y, // 2xy
        }
    }

    /// Inverse (negating the angle).
    /// (x, y)⁻¹ = (x, -y)
    #[inline]
    pub fn inv(self) -> Self {
        Self { x: self.x, y: -self.y }
    }

    /// Conjugate - same as inverse for unit circle.
    #[inline]
    pub fn conjugate(self) -> Self {
        self.inv()
    }

    /// Antipodal point: -P = (-x, -y) (NOT the inverse!).
    /// This is the "other" point at the same angle + π.
    #[inline]
    pub fn antipodal(self) -> Self {
        Self { x: -self.x, y: -self.y }
    }

    /// Compute self^n using repeated squaring.
    pub fn pow(self, mut n: u64) -> Self {
        let mut result = Self::IDENTITY;
        let mut base = self;

        while n > 0 {
            if n & 1 == 1 {
                result = result.mul(base);
            }
            base = base.double();
            n >>= 1;
        }

        result
    }

    /// Get x-coordinate.
    #[inline]
    pub fn x_coord(self) -> M31 {
        self.x
    }

    /// Get y-coordinate.
    #[inline]
    pub fn y_coord(self) -> M31 {
        self.y
    }

    /// Generator of the circle subgroup of order 2^log_order.
    ///
    /// The full circle group C(M31) has order p + 1 = 2^31.
    /// This returns a generator for the unique subgroup of order 2^log_order.
    pub fn generator(log_order: usize) -> Self {
        assert!(log_order <= 31, "Maximum subgroup order is 2^31");

        // Use Plonky3's circle_two_adic_generator
        let g = P3M31::circle_two_adic_generator(log_order);
        Self {
            x: from_p3(g.real()),
            y: from_p3(g.imag()),
        }
    }

    /// Map from projective line to circle point.
    /// (x, y) = ((1-t²)/(1+t²), 2t/(1+t²))
    pub fn from_projective_line(t: M31) -> Option<Self> {
        use p3_field::Field;
        let t_p3 = to_p3(t);
        let t2 = PrimeCharacteristicRing::square(&t_p3);
        let denom = P3M31::ONE + t2;
        denom.try_inverse().map(|inv_denom| {
            Self {
                x: from_p3((P3M31::ONE - t2) * inv_denom),
                y: from_p3(PrimeCharacteristicRing::double(&t_p3) * inv_denom),
            }
        })
    }

    /// Map from circle point to projective line.
    /// t = y / (x + 1)
    /// Returns None if x = -1.
    pub fn to_projective_line(self) -> Option<M31> {
        use p3_field::Field;
        let x_plus_1 = to_p3(self.x) + P3M31::ONE;
        x_plus_1.try_inverse().map(|inv| from_p3(inv * to_p3(self.y)))
    }

    /// Evaluate vanishing polynomial v_n at this point.
    /// v_n(P) = P.x after (n-1) doublings
    pub fn v_n(self, log_n: usize) -> M31 {
        let mut x = self.x;
        for _ in 0..(log_n - 1) {
            // Squaring map on x: x -> 2x² - 1
            x = x * x + x * x - M31::ONE;
        }
        x
    }
}

impl Default for CirclePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

// ============================================================================
// Circle Domain - Uses Plonky3's CircleDomain internally
// ============================================================================

/// A domain for Circle polynomial evaluation.
///
/// Represents the cyclic group generated by g where g has order 2^log_size.
/// Points are [g^0, g^1, ..., g^(n-1)] where n = 2^log_size.
///
/// Internally uses Plonky3's CircleDomain for O(n log n) FFT operations.
#[derive(Clone, Debug)]
pub struct CircleDomain {
    /// Log₂ of the domain size.
    pub log_size: usize,
    /// Domain size = 2^log_size.
    pub size: usize,
    /// Generator of this domain.
    pub generator: CirclePoint,
    /// The underlying Plonky3 domain.
    p3_domain: P3CircleDomain<P3M31>,
    /// Precomputed domain points.
    points: Vec<CirclePoint>,
}

impl CircleDomain {
    /// Create a circle domain of size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        assert!(log_size <= 31, "Domain size exceeds circle group order");

        let size = 1usize << log_size;
        let generator = CirclePoint::generator(log_size);
        let p3_domain = P3CircleDomain::<P3M31>::standard(log_size);

        // Precompute all domain points: [g^0, g^1, ..., g^(n-1)]
        let mut points = Vec::with_capacity(size);
        let mut current = CirclePoint::IDENTITY;
        for _ in 0..size {
            points.push(current);
            current = current.mul(generator);
        }

        Self { log_size, size, generator, p3_domain, points }
    }

    /// Create a standard domain (alias for new).
    pub fn standard(log_size: usize) -> Self {
        Self::new(log_size)
    }

    /// Get the underlying Plonky3 domain.
    #[inline]
    pub fn p3_domain(&self) -> P3CircleDomain<P3M31> {
        self.p3_domain
    }

    /// Get the i-th domain point (g^i).
    #[inline]
    pub fn get_point(&self, i: usize) -> CirclePoint {
        self.points[i % self.size]
    }

    /// Get all domain points.
    pub fn points(&self) -> &[CirclePoint] {
        &self.points
    }

    /// Get x-coordinates of all domain points.
    pub fn x_coords(&self) -> Vec<M31> {
        self.points.iter().map(|p| p.x).collect()
    }

    /// Get y-coordinates of all domain points.
    pub fn y_coords(&self) -> Vec<M31> {
        self.points.iter().map(|p| p.y).collect()
    }

    /// Check if all points are valid (on the circle).
    pub fn verify(&self) -> bool {
        self.points.iter().all(|p| p.is_valid())
    }

    /// Get unique x-coordinates (for polynomial evaluation).
    pub fn unique_x_coords(&self) -> (Vec<M31>, Vec<usize>) {
        let mut unique_xs = Vec::new();
        let mut mapping = Vec::with_capacity(self.size);

        for p in &self.points {
            if let Some(idx) = unique_xs.iter().position(|&x| x == p.x) {
                mapping.push(idx);
            } else {
                mapping.push(unique_xs.len());
                unique_xs.push(p.x);
            }
        }

        (unique_xs, mapping)
    }
}

// ============================================================================
// Coset (for Low-Degree Extension)
// ============================================================================

/// A coset of a circle domain: { shift · g^i : i = 0, ..., n-1 }.
///
/// Used for low-degree extension (LDE) where we evaluate on a coset
/// disjoint from the original domain.
#[derive(Clone, Debug)]
pub struct Coset {
    /// The underlying domain.
    pub domain: CircleDomain,
    /// The coset shift.
    pub shift: CirclePoint,
    /// Shifted domain points.
    shifted_points: Vec<CirclePoint>,
}

impl Coset {
    /// Create a coset by shifting a domain.
    pub fn new(domain: CircleDomain, shift: CirclePoint) -> Self {
        let shifted_points = domain.points.iter()
            .map(|p| shift.mul(*p))
            .collect();

        Self { domain, shift, shifted_points }
    }

    /// Create the standard LDE coset.
    ///
    /// For a domain of size n with generator g (of order n),
    /// we shift by a generator h of order 2n, giving a coset
    /// disjoint from the original domain.
    pub fn lde_coset(log_size: usize) -> Self {
        let domain = CircleDomain::new(log_size);
        let shift = CirclePoint::generator(log_size + 1);
        Self::new(domain, shift)
    }

    /// Get the i-th coset point.
    #[inline]
    pub fn get_point(&self, i: usize) -> CirclePoint {
        self.shifted_points[i % self.domain.size]
    }

    /// Get all coset points.
    pub fn points(&self) -> &[CirclePoint] {
        &self.shifted_points
    }

    /// Get size of the coset.
    pub fn size(&self) -> usize {
        self.domain.size
    }
}

// ============================================================================
// Circle FFT - Plonky3 O(n log n) Implementation
// ============================================================================

/// Circle FFT using Plonky3's optimized O(n log n) implementation.
///
/// This provides massive speedups over the naive O(n²) implementation:
/// - Uses butterfly algorithm with O(n log n) complexity
/// - SIMD acceleration (NEON/AVX2/AVX512)
/// - Parallel processing via Rayon
///
/// # Example
/// ```ignore
/// let fft = CircleFFT::new(10); // Domain size 2^10 = 1024
/// let coeffs = vec![M31::new(1), M31::new(2), M31::new(3)];
/// let evals = fft.fft(&coeffs);
/// let recovered = fft.ifft(&evals);
/// ```
#[derive(Clone, Debug)]
pub struct CircleFFT {
    /// The evaluation domain.
    domain: CircleDomain,
}

impl CircleFFT {
    /// Create a Circle FFT for domain size 2^log_size.
    pub fn new(log_size: usize) -> Self {
        let domain = CircleDomain::new(log_size);
        Self { domain }
    }

    /// Forward FFT: polynomial coefficients → evaluations.
    ///
    /// **O(n log n) complexity** using Plonky3's optimized butterfly algorithm.
    ///
    /// Input: coefficients [c₀, c₁, ..., c_{n-1}]
    /// Output: evaluations [f(p₀), f(p₁), ..., f(p_{n-1})]
    pub fn fft(&self, coeffs: &[M31]) -> Vec<M31> {
        use p3_matrix::dense::RowMajorMatrix;

        let n = self.domain.size;

        // Pad coefficients to domain size
        let mut p3_coeffs: Vec<P3M31> = to_p3_vec(coeffs);
        p3_coeffs.resize(n, P3M31::ZERO);

        // Use Plonky3's O(n log n) Circle FFT
        let coeffs_matrix = RowMajorMatrix::new_col(p3_coeffs);
        let evals = P3CircleEvaluations::evaluate(self.domain.p3_domain, coeffs_matrix);

        // Convert back to ZP1 M31
        from_p3_vec(&evals.to_natural_order().to_row_major_matrix().values)
    }

    /// Inverse FFT: evaluations → polynomial coefficients.
    ///
    /// **O(n log n) complexity** using Plonky3's optimized butterfly algorithm.
    ///
    /// Input: evaluations [f(p₀), f(p₁), ..., f(p_{n-1})]
    /// Output: coefficients [c₀, c₁, ..., c_{n-1}]
    pub fn ifft(&self, evals: &[M31]) -> Vec<M31> {
        use p3_matrix::dense::RowMajorMatrix;

        let n = self.domain.size;
        assert_eq!(evals.len(), n, "Evaluation count must match domain size");

        // Convert to Plonky3 format
        let p3_evals: Vec<P3M31> = to_p3_vec(evals);
        let evals_matrix = RowMajorMatrix::new_col(p3_evals);

        // Use Plonky3's O(n log n) Circle IFFT
        let circle_evals = P3CircleEvaluations::from_natural_order(
            self.domain.p3_domain,
            evals_matrix,
        );
        let coeffs = circle_evals.interpolate();

        // Convert back to ZP1 M31
        from_p3_vec(&coeffs.values)
    }

    /// Low-degree extension: extend evaluations to a larger domain.
    ///
    /// **O(n log n) complexity** using Plonky3's extrapolate.
    ///
    /// Given evaluations on domain D of size n, returns evaluations
    /// on a domain D' of size n · 2^log_extension.
    pub fn extend(&self, evals: &[M31], log_extension: usize) -> Vec<M31> {
        use p3_matrix::dense::RowMajorMatrix;

        let n = self.domain.size;
        assert_eq!(evals.len(), n, "Evaluation count must match domain size");

        // Convert to Plonky3 format
        let p3_evals: Vec<P3M31> = to_p3_vec(evals);
        let evals_matrix = RowMajorMatrix::new_col(p3_evals);

        // Create circle evaluations and extrapolate
        let circle_evals = P3CircleEvaluations::from_natural_order(
            self.domain.p3_domain,
            evals_matrix,
        );

        let target_domain = P3CircleDomain::standard(self.domain.log_size + log_extension);
        let extended = circle_evals.extrapolate(target_domain);

        // Convert back to ZP1 M31
        from_p3_vec(&extended.to_natural_order().to_row_major_matrix().values)
    }

    /// Get domain size.
    pub fn size(&self) -> usize {
        self.domain.size
    }

    /// Get log domain size.
    pub fn log_size(&self) -> usize {
        self.domain.log_size
    }

    /// Get a domain point.
    pub fn get_domain_point(&self, i: usize) -> CirclePoint {
        self.domain.get_point(i)
    }

    /// Get the domain.
    pub fn domain(&self) -> &CircleDomain {
        &self.domain
    }
}

/// Fast Circle FFT - alias for CircleFFT (both use Plonky3's O(n log n) algorithm).
pub type FastCircleFFT = CircleFFT;

// ============================================================================
// Polynomial Utilities
// ============================================================================

/// Evaluate polynomial at a single point using Horner's method.
/// For f(x) = c₀ + c₁x + c₂x² + ... + cₙxⁿ, computes f(point).
#[inline]
pub fn evaluate_poly(coeffs: &[M31], point: M31) -> M31 {
    let mut result = M31::ZERO;
    for &c in coeffs.iter().rev() {
        result = result * point + c;
    }
    result
}

/// Multiply two polynomials.
pub fn poly_mul(f: &[M31], g: &[M31]) -> Vec<M31> {
    if f.is_empty() || g.is_empty() {
        return vec![];
    }

    let mut result = vec![M31::ZERO; f.len() + g.len() - 1];

    for (i, &fi) in f.iter().enumerate() {
        for (j, &gj) in g.iter().enumerate() {
            result[i + j] = result[i + j] + fi * gj;
        }
    }

    result
}

/// Add two polynomials.
pub fn poly_add(f: &[M31], g: &[M31]) -> Vec<M31> {
    let max_len = f.len().max(g.len());
    let mut result = vec![M31::ZERO; max_len];

    for (i, &fi) in f.iter().enumerate() {
        result[i] = result[i] + fi;
    }
    for (i, &gi) in g.iter().enumerate() {
        result[i] = result[i] + gi;
    }

    result
}

/// Subtract two polynomials.
pub fn poly_sub(f: &[M31], g: &[M31]) -> Vec<M31> {
    let max_len = f.len().max(g.len());
    let mut result = vec![M31::ZERO; max_len];

    for (i, &fi) in f.iter().enumerate() {
        result[i] = result[i] + fi;
    }
    for (i, &gi) in g.iter().enumerate() {
        result[i] = result[i] - gi;
    }

    result
}

/// Scale a polynomial by a constant.
pub fn poly_scale(f: &[M31], c: M31) -> Vec<M31> {
    f.iter().map(|&fi| fi * c).collect()
}

/// Compute the degree of a polynomial.
pub fn poly_degree(f: &[M31]) -> Option<usize> {
    for (i, &c) in f.iter().enumerate().rev() {
        if !c.is_zero() {
            return Some(i);
        }
    }
    None
}

// ============================================================================
// Bit Reversal
// ============================================================================

/// Bit-reverse permutation of a slice.
pub fn bit_reverse_permutation<T: Copy>(data: &mut [T]) {
    let n = data.len();
    if n <= 1 {
        return;
    }

    let log_n = n.trailing_zeros() as usize;

    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            data.swap(i, j);
        }
    }
}

/// Reverse the bits of x, treating it as a log_n-bit number.
#[inline]
pub fn bit_reverse(x: usize, log_n: usize) -> usize {
    x.reverse_bits() >> (usize::BITS as usize - log_n)
}

// ============================================================================
// Circle FRI Twiddles and Folding
// ============================================================================

/// Compute y-twiddles for the first FRI folding layer.
///
/// For Circle FRI, the first fold uses y-coordinates of domain points.
/// Returns the inverse y-twiddles: 1/y for each point in the first coset (coset0).
///
/// This is used in the formula:
/// `f_folded[i] = (f[i] + f[i']) / 2 + beta * (f[i] - f[i']) / (2 * y[i])`
/// where i' is the twin index.
///
/// Following Plonky3's convention, we use the standard position twin-coset:
/// - shift = generator(log_n + 1) to avoid zeros in y-coordinates
/// - subgroup_generator = generator(log_n - 1) for stepping within coset0
pub fn compute_y_twiddle_inverses(log_domain_size: usize) -> Vec<M31> {
    if log_domain_size == 0 {
        return vec![];
    }

    let half_n = 1usize << (log_domain_size - 1);

    // Standard position: shift = generator(log_n + 1), subgroup = generator(log_n - 1)
    // This ensures coset0 has no y=0 points (those are only at the subgroup boundary)
    let shift = CirclePoint::generator(log_domain_size + 1);
    let subgroup_gen = if log_domain_size >= 2 {
        CirclePoint::generator(log_domain_size - 1)
    } else {
        CirclePoint::IDENTITY
    };

    // Collect y-coordinates of coset0: shift, shift*g, shift*g^2, ...
    // Note: The circle group operation is mul (complex multiplication)
    let mut ys = Vec::with_capacity(half_n);
    let mut current = shift;
    for _ in 0..half_n {
        ys.push(current.y);
        current = current.mul(subgroup_gen);
    }

    // Bit-reverse for CFFT ordering
    bit_reverse_permutation(&mut ys);

    // Batch invert for efficiency (now handles zeros gracefully)
    batch_inverse(&ys)
}

/// Compute x-twiddles for subsequent FRI folding layers.
///
/// After the first fold (which uses y), subsequent folds use x-coordinates.
/// The layer parameter indicates which folding layer (0 = first x-fold, after y-fold).
///
/// Returns the inverse x-twiddles for the given layer.
pub fn compute_x_twiddle_inverses(log_domain_size: usize, layer: usize) -> Vec<M31> {
    // After y-fold, domain is halved. After each x-fold, halved again.
    // At layer i of x-folding, we have 2^(log_domain_size - 1 - layer) points
    let log_layer_size = log_domain_size.saturating_sub(1 + layer);
    if log_layer_size < 2 {
        return vec![];
    }

    let num_twiddles = 1usize << (log_layer_size - 1);
    let generator = CirclePoint::generator(log_layer_size + 1);
    let shift = CirclePoint::generator(log_layer_size + 2); // Standard position shift

    // Collect x-coordinates
    let mut xs = Vec::with_capacity(num_twiddles);
    let mut current = shift;
    for _ in 0..num_twiddles {
        xs.push(current.x);
        current = current.mul(generator);
    }

    // Bit-reverse for CFFT ordering
    bit_reverse_permutation(&mut xs);

    // Batch invert
    batch_inverse(&xs)
}

/// Batch multiplicative inverse using Montgomery's trick.
///
/// Computes 1/x for each x in O(n) field operations instead of O(n) inversions.
/// Zeros in the input produce zeros in the output (0^(-1) = 0 by convention).
pub fn batch_inverse(values: &[M31]) -> Vec<M31> {
    if values.is_empty() {
        return vec![];
    }

    let n = values.len();

    // Forward pass: compute prefix products, skipping zeros
    let mut prefix_products = Vec::with_capacity(n);
    let mut running = M31::ONE;
    for &v in values {
        prefix_products.push(running);
        if !v.is_zero() {
            running = running * v;
        }
    }

    // Single inversion of the product (if running is zero, all values were zero)
    if running.is_zero() {
        return vec![M31::ZERO; n];
    }
    let mut running_inv = running.inv();

    // Backward pass: compute inverses
    let mut result = vec![M31::ZERO; n];
    for i in (0..n).rev() {
        if values[i].is_zero() {
            // 0^(-1) = 0 by convention for this use case
            result[i] = M31::ZERO;
        } else {
            result[i] = prefix_products[i] * running_inv;
            running_inv = running_inv * values[i];
        }
    }

    result
}

/// Circle FRI fold using y-twiddles (first layer).
///
/// Folds evaluations from size n to n/2 using the formula:
/// `f_folded[i] = (f[i] + f[twin_i]) / 2 + beta * (f[i] - f[twin_i]) * twiddle[i] / 2`
///
/// # Arguments
/// * `evals` - Evaluations to fold (must be power of 2)
/// * `beta` - Random folding challenge
/// * `y_twiddle_invs` - Precomputed inverse y-twiddles
///
/// # Returns
/// Folded evaluations of half the size
pub fn fold_y(evals: &[M31], beta: M31, y_twiddle_invs: &[M31]) -> Vec<M31> {
    let n = evals.len();
    let half_n = n / 2;
    assert_eq!(y_twiddle_invs.len(), half_n, "Twiddle count must match half domain size");

    let inv_two = M31::new(2).inv();

    (0..half_n)
        .map(|i| {
            let lo = evals[2 * i];       // Even index in interleaved order
            let hi = evals[2 * i + 1];   // Odd index (twin)
            let sum = lo + hi;
            let diff = (lo - hi) * y_twiddle_invs[i];
            (sum + beta * diff) * inv_two
        })
        .collect()
}

/// Circle FRI fold using x-twiddles (subsequent layers).
///
/// After the first y-fold, subsequent folds use x-coordinates.
/// Formula is the same but with x-twiddles.
///
/// # Arguments
/// * `evals` - Evaluations to fold (must be power of 2)
/// * `beta` - Random folding challenge
/// * `x_twiddle_invs` - Precomputed inverse x-twiddles for this layer
///
/// # Returns
/// Folded evaluations of half the size
pub fn fold_x(evals: &[M31], beta: M31, x_twiddle_invs: &[M31]) -> Vec<M31> {
    let n = evals.len();
    let half_n = n / 2;
    assert_eq!(x_twiddle_invs.len(), half_n, "Twiddle count must match half domain size");

    let inv_two = M31::new(2).inv();

    (0..half_n)
        .map(|i| {
            let lo = evals[2 * i];
            let hi = evals[2 * i + 1];
            let sum = lo + hi;
            let diff = (lo - hi) * x_twiddle_invs[i];
            (sum + beta * diff) * inv_two
        })
        .collect()
}

/// Single-point y-fold for verifier.
///
/// Computes the folded value for a single query index.
pub fn fold_y_single(lo: M31, hi: M31, beta: M31, y_twiddle_inv: M31) -> M31 {
    let inv_two = M31::new(2).inv();
    let sum = lo + hi;
    let diff = (lo - hi) * y_twiddle_inv;
    (sum + beta * diff) * inv_two
}

/// Single-point x-fold for verifier.
///
/// Computes the folded value for a single query index.
pub fn fold_x_single(lo: M31, hi: M31, beta: M31, x_twiddle_inv: M31) -> M31 {
    let inv_two = M31::new(2).inv();
    let sum = lo + hi;
    let diff = (lo - hi) * x_twiddle_inv;
    (sum + beta * diff) * inv_two
}

/// Get y-twiddle inverse for a single index (for verifier).
///
/// More expensive than batch computation but useful for verification.
/// Uses standard position coset (shift = generator(log_n + 1)) to match batch computation.
pub fn get_y_twiddle_inv(log_domain_size: usize, index: usize) -> M31 {
    if log_domain_size == 0 {
        return M31::ZERO;
    }

    // Standard position coset matching compute_y_twiddle_inverses
    let shift = CirclePoint::generator(log_domain_size + 1);
    let subgroup_gen = if log_domain_size >= 2 {
        CirclePoint::generator(log_domain_size - 1)
    } else {
        CirclePoint::IDENTITY
    };

    // Get the bit-reversed index
    let max_bits = if log_domain_size > 1 { log_domain_size - 1 } else { 0 };
    let reversed_idx = if max_bits > 0 {
        bit_reverse(index, max_bits)
    } else {
        0
    };

    // Compute point at this index in coset0: shift * g^reversed_idx
    let point = shift.mul(subgroup_gen.pow(reversed_idx as u64));

    if point.y.is_zero() {
        M31::ZERO
    } else {
        point.y.inv()
    }
}

/// Get x-twiddle inverse for a single index at a given layer (for verifier).
pub fn get_x_twiddle_inv(log_domain_size: usize, layer: usize, index: usize) -> M31 {
    let log_layer_size = log_domain_size.saturating_sub(1 + layer);
    if log_layer_size < 2 {
        return M31::ONE;
    }

    let generator = CirclePoint::generator(log_layer_size + 1);
    let shift = CirclePoint::generator(log_layer_size + 2);

    let reversed_idx = bit_reverse(index, log_layer_size - 1);
    let point = shift.mul(generator.pow(reversed_idx as u64));

    if point.x.is_zero() {
        M31::ZERO
    } else {
        point.x.inv()
    }
}
