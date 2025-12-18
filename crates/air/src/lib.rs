//! zp1-air: AIR constraint definitions for CPU, memory, and delegation.
//!
//! All constraints are kept at degree ≤ 2 for efficient STARK proving.

pub mod constraints;
pub mod cpu;
pub mod memory;
pub mod rv32im;

pub use constraints::{AirConstraint, ConstraintSet};
pub use rv32im::{Constraint, ConstraintEvaluator, CpuTraceRow, Rv32imAir};
