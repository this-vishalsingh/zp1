//! zp1-air: AIR constraint definitions for CPU, memory, and delegation.
//!
//! All constraints are kept at degree ≤ 2 for efficient STARK proving.

pub mod cpu;
pub mod memory;
pub mod constraints;

pub use constraints::{AirConstraint, ConstraintSet};
