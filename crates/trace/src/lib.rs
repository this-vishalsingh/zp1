//! zp1-trace: Trace builder and column serialization.
//!
//! Converts executor output into columnar form for AIR constraints.

pub mod columns;

pub use columns::TraceColumns;
