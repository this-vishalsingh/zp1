//! Executor errors.
//!
//! Errors are categorized by their impact on proving:
//! - **Unprovable traps**: Cause prover failure (ECALL, EBREAK, WFI, FENCE, misaligned access)
//! - **Execution errors**: Invalid instructions, out of bounds, division by zero
//! - **Normal termination**: Program halted, max steps reached

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExecutorError {
    // === Unprovable Traps ===
    // These errors indicate operations that cannot be proven in our constraint system.
    // Programs containing these will fail during proving.
    /// ECALL instruction encountered - only specific syscalls are supported (0x1000=Keccak256, 93=exit).
    /// This is an unprovable trap that will cause prover failure.
    #[error(
        "Unprovable trap: ECALL (syscall {syscall_id}) at pc={pc:#x} - unsupported system call"
    )]
    Ecall { pc: u32, syscall_id: u32 },

    /// EBREAK instruction encountered - debug breakpoints not supported.
    /// This is an unprovable trap that will cause prover failure.
    #[error("Unprovable trap: EBREAK at pc={pc:#x} - debug breakpoints not supported")]
    Ebreak { pc: u32 },

    /// WFI (Wait For Interrupt) instruction encountered - not supported.
    /// This is an unprovable trap that will cause prover failure.
    #[error("Unprovable trap: WFI at pc={pc:#x} - interrupts not supported in machine-mode-only execution")]
    Wfi { pc: u32 },

    /// FENCE instruction encountered - memory ordering not needed in single-threaded prover.
    /// This is an unprovable trap that will cause prover failure.
    #[error("Unprovable trap: FENCE at pc={pc:#x} - memory barriers not supported")]
    Fence { pc: u32 },

    /// Unaligned memory access - words must be 4-byte aligned, halfwords 2-byte aligned.
    /// This is an unprovable trap that will cause prover failure.
    #[error("Unprovable trap: Unaligned {access_type} access at addr={addr:#x} (alignment required: {required} bytes)")]
    UnalignedAccess {
        addr: u32,
        access_type: &'static str,
        required: u8,
    },

    // === Execution Errors ===
    #[error("Invalid instruction at pc={pc:#x}: {bits:#010x}")]
    InvalidInstruction { pc: u32, bits: u32 },

    #[error("Memory access out of bounds: address {addr:#x}")]
    OutOfBounds { addr: u32 },

    #[error("Division by zero at pc={pc:#x}")]
    DivisionByZero { pc: u32 },

    #[error("Unknown syscall {syscall_code:#x} at pc={pc:#x}")]
    UnknownSyscall { pc: u32, syscall_code: u32 },

    // === Normal Termination ===
    #[error("Execution halted: reached max steps ({max_steps})")]
    MaxStepsReached { max_steps: u64 },

    #[error("Program halted normally")]
    Halted,

    #[error("Invalid ELF file: {0}")]
    InvalidElf(String),
}

impl ExecutorError {
    /// Returns true if this error represents an unprovable trap.
    /// Programs that trigger these errors cannot be proven.
    pub fn is_unprovable_trap(&self) -> bool {
        matches!(
            self,
            ExecutorError::Ecall { .. }
                | ExecutorError::Ebreak { .. }
                | ExecutorError::Wfi { .. }
                | ExecutorError::Fence { .. }
                | ExecutorError::UnalignedAccess { .. }
        )
    }
}
