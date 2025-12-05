//! Generic AIR constraint infrastructure.

use zp1_primitives::M31;

/// A single AIR constraint that evaluates to zero on valid traces.
pub trait AirConstraint {
    /// Evaluate the constraint at a given row.
    /// Returns zero if satisfied.
    fn evaluate(&self, row: &[M31], next_row: &[M31]) -> M31;

    /// The degree of this constraint (must be ≤ 2 for this system).
    fn degree(&self) -> usize;

    /// Name for debugging.
    fn name(&self) -> &str;
}

/// A collection of AIR constraints.
#[derive(Default)]
pub struct ConstraintSet {
    constraints: Vec<Box<dyn AirConstraint>>,
}

impl ConstraintSet {
    /// Create an empty constraint set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a constraint to the set.
    pub fn add(&mut self, constraint: Box<dyn AirConstraint>) {
        assert!(constraint.degree() <= 2, "Constraint degree must be ≤ 2");
        self.constraints.push(constraint);
    }

    /// Evaluate all constraints at a given row.
    pub fn evaluate_all(&self, row: &[M31], next_row: &[M31]) -> Vec<M31> {
        self.constraints
            .iter()
            .map(|c| c.evaluate(row, next_row))
            .collect()
    }

    /// Check if all constraints are satisfied (all evaluate to zero).
    pub fn check(&self, row: &[M31], next_row: &[M31]) -> bool {
        self.constraints
            .iter()
            .all(|c| c.evaluate(row, next_row).is_zero())
    }

    /// Get the number of constraints.
    pub fn len(&self) -> usize {
        self.constraints.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.constraints.is_empty()
    }
}

/// A simple linear constraint: sum of coefficients * columns = 0.
pub struct LinearConstraint {
    /// Column indices and their coefficients.
    pub terms: Vec<(usize, M31)>,
    /// Constant term.
    pub constant: M31,
    /// Name.
    pub name: String,
}

impl AirConstraint for LinearConstraint {
    fn evaluate(&self, row: &[M31], _next_row: &[M31]) -> M31 {
        let mut sum = self.constant;
        for (col, coeff) in &self.terms {
            sum += *coeff * row[*col];
        }
        sum
    }

    fn degree(&self) -> usize {
        1
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A quadratic constraint: sum of (coeff * col_a * col_b) = 0.
pub struct QuadraticConstraint {
    /// Linear terms: (column, coefficient).
    pub linear_terms: Vec<(usize, M31)>,
    /// Quadratic terms: (col_a, col_b, coefficient).
    pub quadratic_terms: Vec<(usize, usize, M31)>,
    /// Constant term.
    pub constant: M31,
    /// Name.
    pub name: String,
}

impl AirConstraint for QuadraticConstraint {
    fn evaluate(&self, row: &[M31], _next_row: &[M31]) -> M31 {
        let mut sum = self.constant;

        for (col, coeff) in &self.linear_terms {
            sum += *coeff * row[*col];
        }

        for (col_a, col_b, coeff) in &self.quadratic_terms {
            sum += *coeff * row[*col_a] * row[*col_b];
        }

        sum
    }

    fn degree(&self) -> usize {
        if self.quadratic_terms.is_empty() {
            1
        } else {
            2
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// A transition constraint involving the next row.
pub struct TransitionConstraint {
    /// Column index in current row.
    pub current_col: usize,
    /// Column index in next row.
    pub next_col: usize,
    /// Expected difference (next - current).
    pub expected_diff: M31,
    /// Selector column (constraint only active when selector = 1).
    pub selector_col: Option<usize>,
    /// Name.
    pub name: String,
}

impl AirConstraint for TransitionConstraint {
    fn evaluate(&self, row: &[M31], next_row: &[M31]) -> M31 {
        let diff = next_row[self.next_col] - row[self.current_col] - self.expected_diff;

        if let Some(sel) = self.selector_col {
            row[sel] * diff
        } else {
            diff
        }
    }

    fn degree(&self) -> usize {
        if self.selector_col.is_some() {
            2
        } else {
            1
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}
