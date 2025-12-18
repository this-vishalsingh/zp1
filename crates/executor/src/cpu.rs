//! RV32IM CPU executor with execution trace generation.
//!
//! This module provides a complete, deterministic implementation of the RISC-V
//! RV32IM instruction set architecture, optimized for zero-knowledge proof generation.
//!
//! # Complete RV32IM Implementation
//!
//! All 47 instructions are fully implemented:
//!
//! ## RV32I Base (40 instructions)
//!
//! **Arithmetic** (10): ADD, SUB, ADDI, LUI, AUIPC, AND, OR, XOR, ANDI, ORI, XORI
//! **Shifts** (6): SLL, SRL, SRA, SLLI, SRLI, SRAI
//! **Comparisons** (6): SLT, SLTU, SLTI, SLTIU
//! **Branches** (6): BEQ, BNE, BLT, BGE, BLTU, BGEU
//! **Jumps** (2): JAL, JALR
//! **Loads** (5): LB, LH, LW, LBU, LHU
//! **Stores** (3): SB, SH, SW
//! **System** (2): ECALL, EBREAK
//!
//! ## M Extension (8 instructions)
//!
//! **Multiply** (4): MUL, MULH, MULHSU, MULHU
//! **Divide/Remainder** (4): DIV, DIVU, REM, REMU
//!
//! # Execution Model
//!
//! The CPU operates in **machine mode only** (M-mode, highest RISC-V privilege level).
//! This simplified model enables efficient proof generation.
//!
//! ## Key Properties
//!
//! - **Deterministic execution**: Same input always produces same trace
//! - **Single-threaded**: No concurrency or interrupts
//! - **No MMU**: Direct physical memory access
//! - **No CSRs**: Control/Status Registers not supported
//! - **Strict alignment**: Word (4B) and halfword (2B) aligned only
//!
//! ## Supported Operations
//!
//! - ✅ Standard fetch-decode-execute loop
//! - ✅ All integer arithmetic and logic operations
//! - ✅ All memory load/store operations
//! - ✅ All control flow (branches, jumps)
//! - ✅ All M-extension multiply/divide operations
//! - ✅ Register x0 hardwired to zero
//! - ✅ Execution trace generation for proving
//!
//! ## Unsupported/Simplified
//!
//! - ❌ **CSR instructions**: Cause `InvalidInstruction` error
//! - ❌ **ECALL/EBREAK**: Halt execution (used for program termination)
//! - ⚠️ **FENCE/FENCE.I**: Treated as NOP (single-threaded, no cache)
//! - ❌ **Unaligned access**: Causes `UnalignedAccess` error
//! - ❌ **Interrupts/traps**: Not supported (deterministic model)
//!
//! ## Why These Restrictions?
//!
//! The proving system requires deterministic, fully constrained execution.
//! System calls, interrupts, privilege levels, and complex trap handling
//! would require additional AIR constraints that significantly increase
//! proof complexity and generation time.
//!
//! # Trace Generation
//!
//! The CPU can optionally generate an execution trace suitable for STARK proving:
//!
//! ```rust,ignore
//! use zp1_executor::Cpu;
//!
//! let mut cpu = Cpu::new();
//! cpu.enable_tracing();
//! cpu.load_program(0x1000, &program_bytes)?;
//!
//! // Execute program
//! while cpu.step()?.is_some() {
//!     // Each step records: pc, registers, memory ops, instruction
//! }
//!
//! // Get complete execution trace
//! let trace = cpu.take_trace().unwrap();
//! ```
//!
//! The trace captures every CPU state transition and is used by the prover
//! to generate a zero-knowledge proof of correct execution.

use crate::decode::{
    branch_funct3, funct7, load_funct3, op_funct3, op_imm_funct3, opcode, store_funct3,
    system_funct3, DecodedInstr,
};
use crate::error::ExecutorError;
use crate::memory::Memory;
use crate::trace::{ExecutionTrace, InstrFlags, MemOp, TraceRow};
use serde::{Deserialize, Serialize};

/// RV32IM CPU state.
#[derive(Clone, Serialize, Deserialize)]
pub struct Cpu {
    /// General-purpose registers x0..x31.
    /// x0 is hardwired to zero.
    pub regs: [u32; 32],
    /// Program counter.
    pub pc: u32,
    /// Cycle counter.
    pub cycle: u64,
    /// Memory subsystem.
    pub memory: Memory,
    /// Execution trace (if tracing is enabled).
    trace: Option<ExecutionTrace>,
    /// Tracing enabled flag.
    tracing: bool,
}

impl Cpu {
    /// Create a new CPU with default memory size (16 MB).
    pub fn new() -> Self {
        Self {
            regs: [0; 32],
            pc: 0,
            cycle: 0,
            memory: Memory::with_default_size(),
            trace: None,
            tracing: false,
        }
    }

    /// Create a new CPU with custom memory size.
    pub fn with_memory_size(size: usize) -> Self {
        Self {
            regs: [0; 32],
            pc: 0,
            cycle: 0,
            memory: Memory::new(size),
            trace: None,
            tracing: false,
        }
    }

    /// Enable execution tracing.
    pub fn enable_tracing(&mut self) {
        self.tracing = true;
        self.trace = Some(ExecutionTrace::new());
    }

    /// Disable tracing and return the collected trace.
    pub fn take_trace(&mut self) -> Option<ExecutionTrace> {
        self.tracing = false;
        self.trace.take()
    }

    /// Load a program into memory at the given address and set PC.
    pub fn load_program(&mut self, addr: u32, program: &[u8]) -> Result<(), ExecutorError> {
        self.memory.load_program(addr, program)?;
        self.pc = addr;
        Ok(())
    }

    /// Set a register value (x0 writes are ignored).
    #[inline]
    pub fn set_reg(&mut self, rd: u8, val: u32) {
        if rd != 0 {
            self.regs[rd as usize] = val;
        }
        // x0 is always 0, writes are silently ignored
    }

    /// Get a register value (x0 always returns 0).
    #[inline]
    pub fn get_reg(&self, rs: u8) -> u32 {
        if rs == 0 {
            0 // x0 is hardwired to zero
        } else {
            self.regs[rs as usize]
        }
    }

    /// Execute a single instruction, returning the trace row if tracing.
    pub fn step(&mut self) -> Result<Option<TraceRow>, ExecutorError> {
        // Fetch instruction
        let instr_bits = self.memory.read_u32(self.pc)?;
        let instr = DecodedInstr::decode(instr_bits);

        // Prepare trace row with pre-instruction state
        let mut row = TraceRow::new(self.cycle, self.pc, self.regs);
        row.instr = instr;

        // Default next_pc (sequential execution)
        let mut next_pc = self.pc.wrapping_add(4);
        let mut rd_val = 0u32;
        let mut mem_op = MemOp::None;
        let mut flags = InstrFlags::default();
        let mut mul_lo = 0u32;
        let mut mul_hi = 0u32;

        // Execute based on opcode
        match instr.opcode {
            // ========== U-type Instructions ==========
            opcode::LUI => {
                // LUI: Load Upper Immediate
                // rd = imm << 12 (already shifted in decoder)
                flags.is_lui = true;
                rd_val = instr.imm as u32;
            }

            opcode::AUIPC => {
                // AUIPC: Add Upper Immediate to PC
                // rd = pc + (imm << 12)
                flags.is_auipc = true;
                rd_val = self.pc.wrapping_add(instr.imm as u32);
            }

            // ========== J-type Instructions ==========
            opcode::JAL => {
                // JAL: Jump and Link
                // rd = pc + 4; pc = pc + imm
                flags.is_jal = true;
                rd_val = self.pc.wrapping_add(4);
                next_pc = self.pc.wrapping_add(instr.imm as u32);
            }

            // ========== I-type Jump ==========
            opcode::JALR => {
                // JALR: Jump and Link Register
                // rd = pc + 4; pc = (rs1 + imm) & ~1
                flags.is_jalr = true;
                rd_val = self.pc.wrapping_add(4);
                let base = self.get_reg(instr.rs1);
                next_pc = base.wrapping_add(instr.imm as u32) & !1;
            }

            // ========== B-type Instructions ==========
            opcode::BRANCH => {
                flags.is_branch = true;
                let rs1_val = self.get_reg(instr.rs1);
                let rs2_val = self.get_reg(instr.rs2);

                let taken = match instr.funct3 {
                    branch_funct3::BEQ => rs1_val == rs2_val,
                    branch_funct3::BNE => rs1_val != rs2_val,
                    branch_funct3::BLT => (rs1_val as i32) < (rs2_val as i32),
                    branch_funct3::BGE => (rs1_val as i32) >= (rs2_val as i32),
                    branch_funct3::BLTU => rs1_val < rs2_val,
                    branch_funct3::BGEU => rs1_val >= rs2_val,
                    _ => {
                        return Err(ExecutorError::InvalidInstruction {
                            pc: self.pc,
                            bits: instr_bits,
                        })
                    }
                };

                if taken {
                    next_pc = self.pc.wrapping_add(instr.imm as u32);
                }
            }

            // ========== Load Instructions ==========
            opcode::LOAD => {
                flags.is_load = true;
                let addr = self.get_reg(instr.rs1).wrapping_add(instr.imm as u32);

                match instr.funct3 {
                    load_funct3::LB => {
                        // LB: Load Byte (sign-extended)
                        let val = self.memory.read_u8(addr)?;
                        rd_val = (val as i8) as i32 as u32;
                        mem_op = MemOp::LoadByte {
                            addr,
                            value: val,
                            signed: true,
                        };
                    }
                    load_funct3::LH => {
                        // LH: Load Halfword (sign-extended)
                        let val = self.memory.read_u16(addr)?;
                        rd_val = (val as i16) as i32 as u32;
                        mem_op = MemOp::LoadHalf {
                            addr,
                            value: val,
                            signed: true,
                        };
                    }
                    load_funct3::LW => {
                        // LW: Load Word
                        let val = self.memory.read_u32(addr)?;
                        rd_val = val;
                        mem_op = MemOp::LoadWord { addr, value: val };
                    }
                    load_funct3::LBU => {
                        // LBU: Load Byte Unsigned
                        let val = self.memory.read_u8(addr)?;
                        rd_val = val as u32;
                        mem_op = MemOp::LoadByte {
                            addr,
                            value: val,
                            signed: false,
                        };
                    }
                    load_funct3::LHU => {
                        // LHU: Load Halfword Unsigned
                        let val = self.memory.read_u16(addr)?;
                        rd_val = val as u32;
                        mem_op = MemOp::LoadHalf {
                            addr,
                            value: val,
                            signed: false,
                        };
                    }
                    _ => {
                        return Err(ExecutorError::InvalidInstruction {
                            pc: self.pc,
                            bits: instr_bits,
                        })
                    }
                }
            }

            // ========== Store Instructions ==========
            opcode::STORE => {
                flags.is_store = true;
                let addr = self.get_reg(instr.rs1).wrapping_add(instr.imm as u32);
                let val = self.get_reg(instr.rs2);

                match instr.funct3 {
                    store_funct3::SB => {
                        // SB: Store Byte
                        let byte = val as u8;
                        self.memory.write_u8(addr, byte)?;
                        mem_op = MemOp::StoreByte { addr, value: byte };
                    }
                    store_funct3::SH => {
                        // SH: Store Halfword
                        let half = val as u16;
                        self.memory.write_u16(addr, half)?;
                        mem_op = MemOp::StoreHalf { addr, value: half };
                    }
                    store_funct3::SW => {
                        // SW: Store Word
                        self.memory.write_u32(addr, val)?;
                        mem_op = MemOp::StoreWord { addr, value: val };
                    }
                    _ => {
                        return Err(ExecutorError::InvalidInstruction {
                            pc: self.pc,
                            bits: instr_bits,
                        })
                    }
                }
            }

            // ========== I-type ALU Instructions ==========
            opcode::OP_IMM => {
                flags.is_alu_imm = true;
                let rs1_val = self.get_reg(instr.rs1);
                let imm = instr.imm as u32;

                rd_val = match instr.funct3 {
                    op_imm_funct3::ADDI => {
                        // ADDI: Add Immediate
                        rs1_val.wrapping_add(imm)
                    }
                    op_imm_funct3::SLTI => {
                        // SLTI: Set Less Than Immediate (signed)
                        ((rs1_val as i32) < (instr.imm)) as u32
                    }
                    op_imm_funct3::SLTIU => {
                        // SLTIU: Set Less Than Immediate Unsigned
                        (rs1_val < imm) as u32
                    }
                    op_imm_funct3::XORI => {
                        // XORI: XOR Immediate
                        rs1_val ^ imm
                    }
                    op_imm_funct3::ORI => {
                        // ORI: OR Immediate
                        rs1_val | imm
                    }
                    op_imm_funct3::ANDI => {
                        // ANDI: AND Immediate
                        rs1_val & imm
                    }
                    op_imm_funct3::SLLI => {
                        // SLLI: Shift Left Logical Immediate
                        let shamt = instr.shamt();
                        rs1_val << shamt
                    }
                    op_imm_funct3::SRLI_SRAI => {
                        let shamt = instr.shamt();
                        if instr.funct7 & 0x20 != 0 {
                            // SRAI: Shift Right Arithmetic Immediate
                            ((rs1_val as i32) >> shamt) as u32
                        } else {
                            // SRLI: Shift Right Logical Immediate
                            rs1_val >> shamt
                        }
                    }
                    _ => {
                        return Err(ExecutorError::InvalidInstruction {
                            pc: self.pc,
                            bits: instr_bits,
                        })
                    }
                };
            }

            // ========== R-type ALU Instructions ==========
            opcode::OP => {
                let rs1_val = self.get_reg(instr.rs1);
                let rs2_val = self.get_reg(instr.rs2);

                if instr.funct7 == funct7::MULDIV {
                    // ========== M Extension ==========
                    match instr.funct3 {
                        op_funct3::ADD_SUB_MUL => {
                            // MUL: Multiply (lower 32 bits)
                            flags.is_mul = true;
                            let prod = (rs1_val as i32 as i64).wrapping_mul(rs2_val as i32 as i64);
                            rd_val = prod as u32;
                            mul_lo = prod as u32;
                            mul_hi = (prod >> 32) as u32;
                        }
                        op_funct3::SLL_MULH => {
                            // MULH: Multiply High (signed × signed)
                            flags.is_mul = true;
                            let prod = (rs1_val as i32 as i64).wrapping_mul(rs2_val as i32 as i64);
                            rd_val = (prod >> 32) as u32;
                            mul_lo = prod as u32;
                            mul_hi = rd_val;
                        }
                        op_funct3::SLT_MULHSU => {
                            // MULHSU: Multiply High (signed × unsigned)
                            flags.is_mul = true;
                            let prod = (rs1_val as i32 as i64).wrapping_mul(rs2_val as u64 as i64);
                            rd_val = (prod >> 32) as u32;
                            mul_lo = prod as u32;
                            mul_hi = rd_val;
                        }
                        op_funct3::SLTU_MULHU => {
                            // MULHU: Multiply High Unsigned
                            flags.is_mul = true;
                            let prod = (rs1_val as u64).wrapping_mul(rs2_val as u64);
                            rd_val = (prod >> 32) as u32;
                            mul_lo = prod as u32;
                            mul_hi = rd_val;
                        }
                        op_funct3::XOR_DIV => {
                            // DIV: Signed Division
                            flags.is_div = true;
                            rd_val = if rs2_val == 0 {
                                // Division by zero: result is -1
                                u32::MAX
                            } else if rs1_val == 0x80000000 && rs2_val == 0xFFFFFFFF {
                                // Overflow: MIN_INT / -1 = MIN_INT
                                0x80000000
                            } else {
                                ((rs1_val as i32).wrapping_div(rs2_val as i32)) as u32
                            };
                        }
                        op_funct3::SRL_SRA_DIVU => {
                            // DIVU: Unsigned Division
                            flags.is_div = true;
                            rd_val = if rs2_val == 0 {
                                // Division by zero: result is MAX
                                u32::MAX
                            } else {
                                rs1_val / rs2_val
                            };
                        }
                        op_funct3::OR_REM => {
                            // REM: Signed Remainder
                            flags.is_rem = true;
                            rd_val = if rs2_val == 0 {
                                // Division by zero: result is dividend
                                rs1_val
                            } else if rs1_val == 0x80000000 && rs2_val == 0xFFFFFFFF {
                                // Overflow: MIN_INT % -1 = 0
                                0
                            } else {
                                ((rs1_val as i32).wrapping_rem(rs2_val as i32)) as u32
                            };
                        }
                        op_funct3::AND_REMU => {
                            // REMU: Unsigned Remainder
                            flags.is_rem = true;
                            rd_val = if rs2_val == 0 {
                                // Division by zero: result is dividend
                                rs1_val
                            } else {
                                rs1_val % rs2_val
                            };
                        }
                        _ => {
                            return Err(ExecutorError::InvalidInstruction {
                                pc: self.pc,
                                bits: instr_bits,
                            })
                        }
                    }
                } else {
                    // ========== Base RV32I OP ==========
                    flags.is_alu = true;
                    rd_val = match (instr.funct3, instr.funct7) {
                        (op_funct3::ADD_SUB_MUL, funct7::NORMAL) => {
                            // ADD
                            rs1_val.wrapping_add(rs2_val)
                        }
                        (op_funct3::ADD_SUB_MUL, funct7::SUB_SRA) => {
                            // SUB
                            rs1_val.wrapping_sub(rs2_val)
                        }
                        (op_funct3::SLL_MULH, funct7::NORMAL) => {
                            // SLL: Shift Left Logical
                            rs1_val << (rs2_val & 0x1F)
                        }
                        (op_funct3::SLT_MULHSU, funct7::NORMAL) => {
                            // SLT: Set Less Than (signed)
                            ((rs1_val as i32) < (rs2_val as i32)) as u32
                        }
                        (op_funct3::SLTU_MULHU, funct7::NORMAL) => {
                            // SLTU: Set Less Than Unsigned
                            (rs1_val < rs2_val) as u32
                        }
                        (op_funct3::XOR_DIV, funct7::NORMAL) => {
                            // XOR
                            rs1_val ^ rs2_val
                        }
                        (op_funct3::SRL_SRA_DIVU, funct7::NORMAL) => {
                            // SRL: Shift Right Logical
                            rs1_val >> (rs2_val & 0x1F)
                        }
                        (op_funct3::SRL_SRA_DIVU, funct7::SUB_SRA) => {
                            // SRA: Shift Right Arithmetic
                            ((rs1_val as i32) >> (rs2_val & 0x1F)) as u32
                        }
                        (op_funct3::OR_REM, funct7::NORMAL) => {
                            // OR
                            rs1_val | rs2_val
                        }
                        (op_funct3::AND_REMU, funct7::NORMAL) => {
                            // AND
                            rs1_val & rs2_val
                        }
                        _ => {
                            return Err(ExecutorError::InvalidInstruction {
                                pc: self.pc,
                                bits: instr_bits,
                            })
                        }
                    };
                }
            }

            // ========== SYSTEM Instructions ==========
            opcode::SYSTEM => {
                match instr.funct3 {
                    system_funct3::PRIV => {
                        // Privileged instructions
                        match instr.imm as u32 & 0xFFF {
                            0x000 => {
                                // ECALL - Environment Call
                                flags.is_ecall = true;
                                let syscall_id = self.get_reg(17); // a7 register

                                // Handle specific supported syscalls
                                match syscall_id {
                                    0x1000 => {
                                        // Keccak256 syscall
                                        // a0 = input pointer
                                        // a1 = input length
                                        // a2 = output pointer (32 bytes)
                                        let input_ptr = self.get_reg(10);
                                        let input_len = self.get_reg(11);
                                        let output_ptr = self.get_reg(12);

                                        // Validate pointers
                                        if !self.memory.is_valid_range(input_ptr, input_len) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: input_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(output_ptr, 32) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: output_ptr,
                                            });
                                        }

                                        // Extract input data
                                        let input_data = self
                                            .memory
                                            .slice(input_ptr, input_len as usize)
                                            .ok_or(ExecutorError::OutOfBounds {
                                                addr: input_ptr,
                                            })?;

                                        // Compute Keccak256 hash using delegation module
                                        let hash = zp1_delegation::keccak::keccak256(input_data);

                                        // Write output to memory
                                        self.memory.write_slice(output_ptr, &hash)?;

                                        // Record the delegation in trace
                                        mem_op = MemOp::Keccak256 {
                                            input_ptr,
                                            input_len,
                                            output_ptr,
                                        };

                                        // Return success (a0 = 0)
                                        self.set_reg(10, 0);
                                        next_pc = self.pc.wrapping_add(4);
                                    }
                                    0x1001 => {
                                        // ECRECOVER syscall (signature recovery)
                                        // a0 = input pointer (97 bytes: hash(32) || v(1) || r(32) || s(32))
                                        // a1 = output pointer (20 bytes: address)
                                        let input_ptr = self.get_reg(10);
                                        let output_ptr = self.get_reg(11);

                                        // Validate pointers
                                        if !self.memory.is_valid_range(input_ptr, 97) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: input_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(output_ptr, 20) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: output_ptr,
                                            });
                                        }

                                        // Extract input data
                                        let input_data = self.memory.slice(input_ptr, 97).ok_or(
                                            ExecutorError::OutOfBounds { addr: input_ptr },
                                        )?;

                                        let mut hash = [0u8; 32];
                                        let mut r = [0u8; 32];
                                        let mut s = [0u8; 32];
                                        hash.copy_from_slice(&input_data[0..32]);
                                        let v = input_data[32];
                                        r.copy_from_slice(&input_data[33..65]);
                                        s.copy_from_slice(&input_data[65..97]);

                                        // Perform ECRECOVER using delegation module
                                        let address =
                                            zp1_delegation::ecrecover::ecrecover(&hash, v, &r, &s);

                                        // Write output to memory
                                        match address {
                                            Some(addr) => {
                                                self.memory.write_slice(output_ptr, &addr)?;
                                                self.set_reg(10, 0); // Success
                                            }
                                            None => {
                                                // Invalid signature - write zero address
                                                self.memory.write_slice(output_ptr, &[0u8; 20])?;
                                                self.set_reg(10, 1); // Failure
                                            }
                                        }

                                        // Record the delegation in trace
                                        mem_op = MemOp::Ecrecover {
                                            input_ptr,
                                            output_ptr,
                                        };

                                        next_pc = self.pc.wrapping_add(4);
                                    }
                                    0x1002 => {
                                        // SHA-256 syscall
                                        // a0 = message pointer
                                        // a1 = message length
                                        // a2 = digest pointer (32 bytes)

                                        let message_ptr = self.get_reg(10);
                                        let message_len = self.get_reg(11);
                                        let digest_ptr = self.get_reg(12);

                                        // Validate pointers
                                        if !self.memory.is_valid_range(message_ptr, message_len) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: message_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(digest_ptr, 32) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: digest_ptr,
                                            });
                                        }

                                        // Extract input data
                                        let message = self
                                            .memory
                                            .slice(message_ptr, message_len as usize)
                                            .ok_or(ExecutorError::OutOfBounds {
                                                addr: message_ptr,
                                            })?;

                                        // Compute SHA-256 hash using delegation module
                                        let digest = zp1_delegation::sha256::sha256(message);

                                        // Write digest to memory
                                        self.memory.write_slice(digest_ptr, &digest)?;

                                        // Record the delegation in trace
                                        mem_op = MemOp::Sha256 {
                                            message_ptr: message_ptr as usize,
                                            message_len: message_len as usize,
                                            digest_ptr: digest_ptr as usize,
                                        };

                                        // Return success (a0 = 0)
                                        self.set_reg(10, 0);
                                        next_pc = self.pc.wrapping_add(4);
                                    }
                                    0x1003 => {
                                        // RIPEMD-160 syscall
                                        // a0 = message pointer
                                        // a1 = message length
                                        // a2 = digest pointer (20 bytes)

                                        let message_ptr = self.get_reg(10);
                                        let message_len = self.get_reg(11);
                                        let digest_ptr = self.get_reg(12);

                                        // Validate pointers
                                        if !self.memory.is_valid_range(message_ptr, message_len) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: message_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(digest_ptr, 20) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: digest_ptr,
                                            });
                                        }

                                        // Extract input data
                                        let message = self
                                            .memory
                                            .slice(message_ptr, message_len as usize)
                                            .ok_or(ExecutorError::OutOfBounds {
                                                addr: message_ptr,
                                            })?;

                                        // Compute RIPEMD-160 hash using delegation module
                                        let digest = zp1_delegation::ripemd160::ripemd160(message);

                                        // Write digest to memory
                                        self.memory.write_slice(digest_ptr, &digest)?;

                                        // Record the delegation in trace
                                        mem_op = MemOp::Ripemd160 {
                                            message_ptr: message_ptr as usize,
                                            message_len: message_len as usize,
                                            digest_ptr: digest_ptr as usize,
                                        };

                                        // Return success (a0 = 0)
                                        self.set_reg(10, 0);
                                        next_pc = self.pc.wrapping_add(4);
                                    }
                                    0x1004 => {
                                        // MODEXP syscall (modular exponentiation for RSA/crypto)
                                        // a0 = base pointer (32 bytes)
                                        // a1 = exponent pointer (32 bytes)
                                        // a2 = modulus pointer (32 bytes)
                                        // a3 = result pointer (32 bytes)

                                        let base_ptr = self.get_reg(10);
                                        let exp_ptr = self.get_reg(11);
                                        let mod_ptr = self.get_reg(12);
                                        let result_ptr = self.get_reg(13);

                                        // Validate pointers
                                        if !self.memory.is_valid_range(base_ptr, 32) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: base_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(exp_ptr, 32) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: exp_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(mod_ptr, 32) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: mod_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(result_ptr, 32) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: result_ptr,
                                            });
                                        }

                                        // Extract input data
                                        let base_bytes = self
                                            .memory
                                            .slice(base_ptr, 32)
                                            .ok_or(ExecutorError::OutOfBounds { addr: base_ptr })?;
                                        let exp_bytes = self
                                            .memory
                                            .slice(exp_ptr, 32)
                                            .ok_or(ExecutorError::OutOfBounds { addr: exp_ptr })?;
                                        let mod_bytes = self
                                            .memory
                                            .slice(mod_ptr, 32)
                                            .ok_or(ExecutorError::OutOfBounds { addr: mod_ptr })?;

                                        // Convert to U256
                                        let base = zp1_delegation::bigint::U256::from_le_bytes(
                                            base_bytes.try_into().unwrap(),
                                        );
                                        let exponent = zp1_delegation::bigint::U256::from_le_bytes(
                                            exp_bytes.try_into().unwrap(),
                                        );
                                        let modulus = zp1_delegation::bigint::U256::from_le_bytes(
                                            mod_bytes.try_into().unwrap(),
                                        );

                                        // Compute modular exponentiation using delegation
                                        let delegation_call =
                                            zp1_delegation::bigint::delegate_u256_modexp(
                                                &base, &exponent, &modulus,
                                            );

                                        // Convert M31 output limbs back to U256
                                        let result = zp1_delegation::bigint::U256::from_m31_limbs(
                                            &delegation_call.output,
                                        );

                                        // Write result to memory
                                        let result_bytes = result.to_le_bytes();
                                        self.memory.write_slice(result_ptr, &result_bytes)?;

                                        // Record the delegation in trace
                                        mem_op = MemOp::Modexp {
                                            base_ptr: base_ptr as usize,
                                            exp_ptr: exp_ptr as usize,
                                            mod_ptr: mod_ptr as usize,
                                            result_ptr: result_ptr as usize,
                                        };

                                        // Return success (a0 = 0)
                                        self.set_reg(10, 0);
                                        next_pc = self.pc.wrapping_add(4);
                                    }
                                    0x1005 => {
                                        // Blake2b syscall (64-byte output)
                                        // a0 = message pointer
                                        // a1 = message length
                                        // a2 = digest pointer (64 bytes)

                                        let message_ptr = self.get_reg(10);
                                        let message_len = self.get_reg(11);
                                        let digest_ptr = self.get_reg(12);

                                        // Validate pointers
                                        if !self.memory.is_valid_range(message_ptr, message_len) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: message_ptr,
                                            });
                                        }
                                        if !self.memory.is_valid_range(digest_ptr, 64) {
                                            return Err(ExecutorError::OutOfBounds {
                                                addr: digest_ptr,
                                            });
                                        }

                                        // Extract input data
                                        let message = self
                                            .memory
                                            .slice(message_ptr, message_len as usize)
                                            .ok_or(ExecutorError::OutOfBounds {
                                                addr: message_ptr,
                                            })?;

                                        // Compute Blake2b hash using delegation module
                                        let digest = zp1_delegation::blake2b::blake2b(message);

                                        // Write digest to memory
                                        self.memory.write_slice(digest_ptr, &digest)?;

                                        // Record the delegation in trace
                                        mem_op = MemOp::Blake2b {
                                            message_ptr: message_ptr as usize,
                                            message_len: message_len as usize,
                                            digest_ptr: digest_ptr as usize,
                                        };

                                        // Return success (a0 = 0)
                                        self.set_reg(10, 0);
                                        next_pc = self.pc.wrapping_add(4);
                                    }
                                    93 => {
                                        // Linux exit syscall - allow this for program termination
                                        return Err(ExecutorError::Ecall {
                                            pc: self.pc,
                                            syscall_id,
                                        });
                                    }
                                    _ => {
                                        // Unsupported syscall
                                        return Err(ExecutorError::Ecall {
                                            pc: self.pc,
                                            syscall_id,
                                        });
                                    }
                                }
                            }
                            0x001 => {
                                // EBREAK - Breakpoint
                                flags.is_ebreak = true;
                                return Err(ExecutorError::Ebreak { pc: self.pc });
                            }
                            0x105 => {
                                // WFI - Wait For Interrupt (not supported)
                                return Err(ExecutorError::Wfi { pc: self.pc });
                            }
                            0x302 => {
                                // MRET - Machine Return (not supported in single-mode)
                                return Err(ExecutorError::InvalidInstruction {
                                    pc: self.pc,
                                    bits: instr_bits,
                                });
                            }
                            _ => {
                                // Unknown privileged instruction
                                return Err(ExecutorError::InvalidInstruction {
                                    pc: self.pc,
                                    bits: instr_bits,
                                });
                            }
                        }
                    }
                    // CSR instructions are not supported in this minimal implementation
                    system_funct3::CSRRW
                    | system_funct3::CSRRS
                    | system_funct3::CSRRC
                    | system_funct3::CSRRWI
                    | system_funct3::CSRRSI
                    | system_funct3::CSRRCI => {
                        return Err(ExecutorError::InvalidInstruction {
                            pc: self.pc,
                            bits: instr_bits,
                        });
                    }
                    _ => {
                        return Err(ExecutorError::InvalidInstruction {
                            pc: self.pc,
                            bits: instr_bits,
                        });
                    }
                }
            }

            // ========== Memory Fence Instructions ==========
            opcode::MISC_MEM => {
                // FENCE and FENCE.I
                // In single-threaded deterministic execution, these are NOPs
                // No memory reordering or cache coherency needed
                // Just advance to next instruction (already set above)

                // Mark in flags for tracing purposes
                flags.is_alu = false; // Not an ALU op, just a NOP-like fence
            }

            _ => {
                return Err(ExecutorError::InvalidInstruction {
                    pc: self.pc,
                    bits: instr_bits,
                });
            }
        }

        // Write back to register (x0 writes are ignored, stores don't write, branches don't write)
        if instr.rd != 0
            && !instr.is_store()
            && !instr.is_branch()
            && instr.opcode != opcode::SYSTEM
        {
            self.set_reg(instr.rd, rd_val);
        }

        // Update trace row
        row.next_pc = next_pc;
        row.rd = instr.rd;
        row.rd_val = rd_val;
        row.mem_op = mem_op;
        row.flags = flags;
        row.mul_lo = mul_lo;
        row.mul_hi = mul_hi;

        // Update CPU state
        self.pc = next_pc;
        self.cycle += 1;

        // Record trace if enabled
        if self.tracing {
            if let Some(trace) = &mut self.trace {
                trace.push(row.clone());
            }
        }

        Ok(if self.tracing { Some(row) } else { None })
    }

    /// Run until halt, error, or max_steps reached.
    ///
    /// # Arguments
    /// * `max_steps` - Maximum number of instructions to execute
    ///
    /// # Returns
    /// The execution trace on success, or an error.
    ///
    /// # Note
    /// ECALL with syscall_id=93 (Linux exit) is treated as normal termination.
    pub fn run(&mut self, max_steps: u64) -> Result<ExecutionTrace, ExecutorError> {
        self.enable_tracing();

        for _ in 0..max_steps {
            match self.step() {
                Ok(_) => {}
                Err(ExecutorError::Ecall { syscall_id, .. }) => {
                    // Handle halt syscall (syscall_id = 93 is exit in Linux ABI)
                    if syscall_id == 93 {
                        let mut trace = self.take_trace().unwrap_or_default();
                        trace.final_regs = self.regs;
                        trace.final_pc = self.pc;
                        trace.total_cycles = self.cycle;
                        let exit_code = self.get_reg(10); // a0 register
                        trace.halt_reason = Some(format!("exit({})", exit_code));
                        return Ok(trace);
                    }
                    // For other syscalls, return the error
                    return Err(ExecutorError::Ecall {
                        pc: self.pc,
                        syscall_id,
                    });
                }
                Err(e) => return Err(e),
            }
        }

        Err(ExecutorError::MaxStepsReached { max_steps })
    }

    /// Reset the CPU to initial state.
    pub fn reset(&mut self) {
        self.regs = [0; 32];
        self.pc = 0;
        self.cycle = 0;
        self.trace = None;
        self.tracing = false;
    }

    /// Get current cycle count.
    pub fn cycles(&self) -> u64 {
        self.cycle
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Instruction Assembler Helpers (for testing)
// ============================================================================

/// Assemble an R-type instruction.
pub fn assemble_r(opcode: u8, rd: u8, funct3: u8, rs1: u8, rs2: u8, funct7: u8) -> u32 {
    ((funct7 as u32) << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((rd as u32) << 7)
        | (opcode as u32)
}

/// Assemble an I-type instruction.
pub fn assemble_i(opcode: u8, rd: u8, funct3: u8, rs1: u8, imm: i32) -> u32 {
    (((imm as u32) & 0xFFF) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | ((rd as u32) << 7)
        | (opcode as u32)
}

/// Assemble a S-type instruction.
pub fn assemble_s(opcode: u8, funct3: u8, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    let imm11_5 = (imm >> 5) & 0x7F;
    let imm4_0 = imm & 0x1F;
    (imm11_5 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | (imm4_0 << 7)
        | (opcode as u32)
}

/// Assemble a B-type instruction.
pub fn assemble_b(opcode: u8, funct3: u8, rs1: u8, rs2: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    let imm12 = (imm >> 12) & 1;
    let imm10_5 = (imm >> 5) & 0x3F;
    let imm4_1 = (imm >> 1) & 0xF;
    let imm11 = (imm >> 11) & 1;
    (imm12 << 31)
        | (imm10_5 << 25)
        | ((rs2 as u32) << 20)
        | ((rs1 as u32) << 15)
        | ((funct3 as u32) << 12)
        | (imm4_1 << 8)
        | (imm11 << 7)
        | (opcode as u32)
}

/// Assemble a U-type instruction.
pub fn assemble_u(opcode: u8, rd: u8, imm: u32) -> u32 {
    (imm & 0xFFFFF000) | ((rd as u32) << 7) | (opcode as u32)
}

/// Assemble a J-type instruction.
pub fn assemble_j(opcode: u8, rd: u8, imm: i32) -> u32 {
    let imm = imm as u32;
    let imm20 = (imm >> 20) & 1;
    let imm10_1 = (imm >> 1) & 0x3FF;
    let imm11 = (imm >> 11) & 1;
    let imm19_12 = (imm >> 12) & 0xFF;
    (imm20 << 31)
        | (imm10_1 << 21)
        | (imm11 << 20)
        | (imm19_12 << 12)
        | ((rd as u32) << 7)
        | (opcode as u32)
}

// Convenience assembler functions
pub fn assemble_add(rd: u8, rs1: u8, rs2: u8) -> u32 {
    assemble_r(opcode::OP, rd, 0b000, rs1, rs2, 0x00)
}

pub fn assemble_sub(rd: u8, rs1: u8, rs2: u8) -> u32 {
    assemble_r(opcode::OP, rd, 0b000, rs1, rs2, 0x20)
}

pub fn assemble_addi(rd: u8, rs1: u8, imm: i32) -> u32 {
    assemble_i(opcode::OP_IMM, rd, 0b000, rs1, imm)
}

pub fn assemble_lui(rd: u8, imm: u32) -> u32 {
    assemble_u(opcode::LUI, rd, imm)
}

pub fn assemble_auipc(rd: u8, imm: u32) -> u32 {
    assemble_u(opcode::AUIPC, rd, imm)
}

pub fn assemble_jal(rd: u8, imm: i32) -> u32 {
    assemble_j(opcode::JAL, rd, imm)
}

pub fn assemble_jalr(rd: u8, rs1: u8, imm: i32) -> u32 {
    assemble_i(opcode::JALR, rd, 0b000, rs1, imm)
}

pub fn assemble_beq(rs1: u8, rs2: u8, imm: i32) -> u32 {
    assemble_b(opcode::BRANCH, 0b000, rs1, rs2, imm)
}

pub fn assemble_bne(rs1: u8, rs2: u8, imm: i32) -> u32 {
    assemble_b(opcode::BRANCH, 0b001, rs1, rs2, imm)
}

pub fn assemble_lw(rd: u8, rs1: u8, imm: i32) -> u32 {
    assemble_i(opcode::LOAD, rd, 0b010, rs1, imm)
}

pub fn assemble_sw(rs1: u8, rs2: u8, imm: i32) -> u32 {
    assemble_s(opcode::STORE, 0b010, rs1, rs2, imm)
}

pub fn assemble_mul(rd: u8, rs1: u8, rs2: u8) -> u32 {
    assemble_r(opcode::OP, rd, 0b000, rs1, rs2, 0x01)
}

pub fn assemble_div(rd: u8, rs1: u8, rs2: u8) -> u32 {
    assemble_r(opcode::OP, rd, 0b100, rs1, rs2, 0x01)
}

pub fn assemble_nop() -> u32 {
    assemble_addi(0, 0, 0)
}

pub fn assemble_ecall() -> u32 {
    0x00000073
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addi() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_addi(1, 0, 42).to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 42);
        assert_eq!(cpu.pc, 4);
    }

    #[test]
    fn test_addi_negative() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_addi(1, 0, -1).to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 0xFFFFFFFF);
    }

    #[test]
    fn test_add() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 10), // x1 = 10
            assemble_addi(2, 0, 20), // x2 = 20
            assemble_add(3, 1, 2),   // x3 = x1 + x2 = 30
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(3), 30);
    }

    #[test]
    fn test_sub() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 100),
            assemble_addi(2, 0, 30),
            assemble_sub(3, 1, 2),
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(3), 70);
    }

    #[test]
    fn test_x0_always_zero() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_addi(0, 0, 42).to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(0), 0);
    }

    #[test]
    fn test_lui() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_lui(1, 0x12345000).to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 0x12345000);
    }

    #[test]
    fn test_auipc() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_auipc(1, 0x1000).to_le_bytes();
        cpu.load_program(0x100, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 0x100 + 0x1000);
    }

    #[test]
    fn test_jal() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_jal(1, 8).to_le_bytes();
        cpu.load_program(0x100, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 0x104); // Return address
        assert_eq!(cpu.pc, 0x108); // Jump target
    }

    #[test]
    fn test_jalr() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(2, 0, 0x200), // x2 = 0x200
            assemble_jalr(1, 2, 4),     // x1 = pc+4; pc = x2 + 4 = 0x204
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 8); // Return address (0 + 4 + 4)
        assert_eq!(cpu.pc, 0x204); // Jump target
    }

    #[test]
    fn test_beq_taken() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 5),
            assemble_addi(2, 0, 5),
            assemble_beq(1, 2, 8), // Branch if x1 == x2 (should branch)
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.pc, 8 + 8); // Branched: pc = 8 + offset(8) = 16
    }

    #[test]
    fn test_beq_not_taken() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 5),
            assemble_addi(2, 0, 10),
            assemble_beq(1, 2, 8), // Branch if x1 == x2 (should NOT branch)
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.pc, 12); // Not branched: pc = 8 + 4 = 12
    }

    #[test]
    fn test_load_store() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 0x42), // x1 = 0x42
            assemble_sw(0, 1, 0x100),  // mem[0x100] = x1
            assemble_lw(2, 0, 0x100),  // x2 = mem[0x100]
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(2), 0x42);
    }

    #[test]
    fn test_mul() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 6),
            assemble_addi(2, 0, 7),
            assemble_mul(3, 1, 2),
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(3), 42);
    }

    #[test]
    fn test_div() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 100),
            assemble_addi(2, 0, 7),
            assemble_div(3, 1, 2),
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(3), 14); // 100 / 7 = 14
    }

    #[test]
    fn test_div_by_zero() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 100),
            assemble_div(2, 1, 0), // Divide by x0 (which is 0)
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(2), u32::MAX); // Division by zero returns -1
    }

    #[test]
    fn test_nop() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_nop().to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.pc, 4);
        assert_eq!(cpu.get_reg(0), 0);
    }

    #[test]
    fn test_fence_as_nop() {
        let mut cpu = Cpu::with_memory_size(4096);
        // FENCE instruction
        let program = 0x0ff0000fu32.to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.pc, 4); // Should just advance PC
    }

    #[test]
    fn test_sll() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 1),
            assemble_addi(2, 0, 4),
            assemble_r(opcode::OP, 3, 0b001, 1, 2, 0x00), // SLL x3, x1, x2
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(3), 16); // 1 << 4 = 16
    }

    #[test]
    fn test_sra() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, -16), // x1 = 0xFFFFFFF0
            assemble_addi(2, 0, 2),
            assemble_r(opcode::OP, 3, 0b101, 1, 2, 0x20), // SRA x3, x1, x2
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(3), 0xFFFFFFFC); // Arithmetic shift preserves sign
    }

    #[test]
    fn test_slti() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 5),
            assemble_i(opcode::OP_IMM, 2, 0b010, 1, 10), // SLTI x2, x1, 10
            assemble_i(opcode::OP_IMM, 3, 0b010, 1, 3),  // SLTI x3, x1, 3
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(2), 1); // 5 < 10
        assert_eq!(cpu.get_reg(3), 0); // 5 >= 3
    }

    #[test]
    fn test_xori() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 0b1010),
            assemble_i(opcode::OP_IMM, 2, 0b100, 1, 0b1100), // XORI
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(2), 0b0110);
    }

    #[test]
    fn test_blt() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, -5),                    // x1 = -5 (signed)
            assemble_addi(2, 0, 5),                     // x2 = 5
            assemble_b(opcode::BRANCH, 0b100, 1, 2, 8), // BLT x1, x2, 8
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.pc, 16); // Branch taken: -5 < 5
    }

    #[test]
    fn test_bltu() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, -5),                    // x1 = 0xFFFFFFFB (unsigned)
            assemble_addi(2, 0, 5),                     // x2 = 5
            assemble_b(opcode::BRANCH, 0b110, 1, 2, 8), // BLTU x1, x2, 8
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.pc, 12); // Branch NOT taken: 0xFFFFFFFB > 5 (unsigned)
    }

    #[test]
    fn test_load_byte_signed() {
        let mut cpu = Cpu::with_memory_size(4096);
        // Store 0xFF at address 0x100
        cpu.memory.write_u8(0x100, 0xFF).unwrap();

        let program: Vec<u8> = [
            assemble_i(opcode::LOAD, 1, 0b000, 0, 0x100), // LB x1, 0x100(x0)
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 0xFFFFFFFF); // Sign-extended
    }

    #[test]
    fn test_load_byte_unsigned() {
        let mut cpu = Cpu::with_memory_size(4096);
        cpu.memory.write_u8(0x100, 0xFF).unwrap();

        let program: Vec<u8> = [
            assemble_i(opcode::LOAD, 1, 0b100, 0, 0x100), // LBU x1, 0x100(x0)
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 0xFF); // Zero-extended
    }

    #[test]
    fn test_tracing() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 10),
            assemble_addi(2, 0, 20),
            assemble_add(3, 1, 2),
        ]
        .iter()
        .flat_map(|i| i.to_le_bytes())
        .collect();

        cpu.load_program(0, &program).unwrap();
        cpu.enable_tracing();

        cpu.step().unwrap();
        cpu.step().unwrap();
        cpu.step().unwrap();

        let trace = cpu.take_trace().unwrap();
        assert_eq!(trace.len(), 3);
        assert_eq!(trace.rows[0].rd_val, 10);
        assert_eq!(trace.rows[1].rd_val, 20);
        assert_eq!(trace.rows[2].rd_val, 30);
    }
}
