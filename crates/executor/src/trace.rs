//! Execution trace for proving.
//!
//! Each step of execution produces a TraceRow capturing the CPU state,
//! instruction, and any memory operations.

use serde::{Deserialize, Serialize};
use crate::decode::DecodedInstr;

/// Memory operation type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemOp {
    /// No memory operation this cycle.
    None,
    /// Load byte (LB/LBU).
    LoadByte { addr: u32, value: u8, signed: bool },
    /// Load halfword (LH/LHU).
    LoadHalf { addr: u32, value: u16, signed: bool },
    /// Load word (LW).
    LoadWord { addr: u32, value: u32 },
    /// Store byte (SB).
    StoreByte { addr: u32, value: u8 },
    /// Store halfword (SH).
    StoreHalf { addr: u32, value: u16 },
    /// Store word (SW).
    StoreWord { addr: u32, value: u32 },
    /// Keccak256 hash operation (delegated to specialized circuit).
    Keccak256 { input_ptr: u32, input_len: u32, output_ptr: u32 },
    /// ECRECOVER signature verification (delegated to specialized circuit).
    Ecrecover { input_ptr: u32, output_ptr: u32 },
    /// SHA-256 hash operation (delegated to specialized circuit).
    Sha256 { message_ptr: usize, message_len: usize, digest_ptr: usize },
    /// RIPEMD-160 hash operation (delegated to specialized circuit).
    Ripemd160 { message_ptr: usize, message_len: usize, digest_ptr: usize },
    /// Modular exponentiation (delegated to specialized circuit for RSA/crypto).
    Modexp { base_ptr: usize, exp_ptr: usize, mod_ptr: usize, result_ptr: usize },
    /// Blake2b hash operation (delegated to specialized circuit).
    Blake2b { message_ptr: usize, message_len: usize, digest_ptr: usize },
}

/// Flags indicating instruction class for AIR constraint selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrFlags {
    /// ALU operation (ADD, SUB, AND, OR, XOR, SLT, etc.)
    pub is_alu: bool,
    /// ALU immediate operation (ADDI, ANDI, etc.)
    pub is_alu_imm: bool,
    /// Load instruction.
    pub is_load: bool,
    /// Store instruction.
    pub is_store: bool,
    /// Branch instruction.
    pub is_branch: bool,
    /// JAL instruction.
    pub is_jal: bool,
    /// JALR instruction.
    pub is_jalr: bool,
    /// LUI instruction.
    pub is_lui: bool,
    /// AUIPC instruction.
    pub is_auipc: bool,
    /// M-extension multiply (MUL, MULH, MULHU, MULHSU).
    pub is_mul: bool,
    /// M-extension divide (DIV, DIVU).
    pub is_div: bool,
    /// M-extension remainder (REM, REMU).
    pub is_rem: bool,
    /// ECALL instruction.
    pub is_ecall: bool,
    /// EBREAK instruction.
    pub is_ebreak: bool,
}

/// A single row of the execution trace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceRow {
    /// Clock cycle / step number.
    pub clk: u64,
    /// Program counter before this instruction.
    pub pc: u32,
    /// Next program counter (after this instruction).
    pub next_pc: u32,
    /// Decoded instruction.
    pub instr: DecodedInstr,
    /// Instruction classification flags.
    pub flags: InstrFlags,
    /// Register values BEFORE this instruction (x0..x31).
    pub regs: [u32; 32],
    /// Destination register index (0 if no write).
    pub rd: u8,
    /// Value written to rd (if any).
    pub rd_val: u32,
    /// Memory operation (if any).
    pub mem_op: MemOp,
    /// For M-extension: low 32 bits of 64-bit intermediate (for MUL verification).
    pub mul_lo: u32,
    /// For M-extension: high 32 bits of 64-bit intermediate.
    pub mul_hi: u32,
    /// Shift amount (rs2 & 0x1F or imm[4:0]) for shift instructions.
    pub shamt: u32,
    /// Bit decomposition of rs1 for shift verification.
    pub rs1_bits: [u8; 32],
    /// Bit decomposition of shift result.
    pub rd_bits: [u8; 32],
}

impl TraceRow {
    /// Create a new trace row with default values.
    pub fn new(clk: u64, pc: u32, regs: [u32; 32]) -> Self {
        Self {
            clk,
            pc,
            next_pc: pc + 4,
            instr: DecodedInstr::decode(0x00000013), // NOP
            flags: InstrFlags::default(),
            regs,
            rd: 0,
            rd_val: 0,
            mem_op: MemOp::None,
            mul_lo: 0,
            mul_hi: 0,
            shamt: 0,
            rs1_bits: [0; 32],
            rd_bits: [0; 32],
        }
    }
}

/// Complete execution trace.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// All trace rows.
    pub rows: Vec<TraceRow>,
    /// Final register state.
    pub final_regs: [u32; 32],
    /// Final PC.
    pub final_pc: u32,
    /// Total cycles executed.
    pub total_cycles: u64,
    /// Halt reason (if any).
    pub halt_reason: Option<String>,
}

impl ExecutionTrace {
    /// Create a new empty trace.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a row to the trace.
    pub fn push(&mut self, row: TraceRow) {
        self.rows.push(row);
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Check if the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}
