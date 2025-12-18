//! zp1-executor: Deterministic RISC-V RV32IM executor with trace emission.
//!
//! This crate provides:
//! - A minimal RV32IM CPU emulator (no MMU, no privileged modes)
//! - Execution trace output for proving
//! - ELF binary loader
//! - Syscall/precompile hooks for delegation

pub mod cpu;
pub mod decode;
pub mod elf;
pub mod error;
pub mod memory;
pub mod syscall;
pub mod trace;

pub use cpu::Cpu;
pub use elf::ElfLoader;
pub use error::ExecutorError;
pub use memory::Memory;
pub use syscall::SyscallCode;
pub use trace::{ExecutionTrace, TraceRow};
