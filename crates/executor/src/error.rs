//! Executor errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("Invalid instruction at pc={pc:#x}: {bits:#010x}")]
    InvalidInstruction { pc: u32, bits: u32 },

    #[error("Unaligned memory access at address {addr:#x}")]
    UnalignedAccess { addr: u32 },

    #[error("Memory access out of bounds: address {addr:#x}")]
    OutOfBounds { addr: u32 },

    #[error("Division by zero at pc={pc:#x}")]
    DivisionByZero { pc: u32 },

    #[error("Execution halted: reached max steps ({max_steps})")]
    MaxStepsReached { max_steps: u64 },

    #[error("ECALL: syscall {syscall_id}")]
    Syscall { syscall_id: u32 },

    #[error("EBREAK: debug breakpoint at pc={pc:#x}")]
    Ebreak { pc: u32 },

    #[error("Program halted normally")]
    Halted,
}
