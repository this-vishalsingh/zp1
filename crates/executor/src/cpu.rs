//! RV32IM CPU implementation.
//!
//! # Execution Model
//!
//! The CPU operates in **machine mode only** (M-mode, highest RISC-V privilege level).
//!
//! ## Constraints
//!
//! - Standard fetch-decode-execute loop enforced at each cycle
//! - **No support for ECALL/EBREAK/WFI/FENCE** system-level opcodes
//!   - These cause `UnprovableTrap` errors that will fail proving
//! - **No unaligned memory accesses**:
//!   - Full-word (32-bit) accesses must be 4-byte aligned
//!   - Half-word (16-bit) accesses must be 2-byte aligned
//! - All traps are converted to unprovable constraints (causing prover failure)
//!
//! ## Why These Restrictions?
//!
//! The proving system requires deterministic, fully constrained execution.
//! System calls, interrupts, and misaligned accesses would require complex
//! trap handling circuits that significantly increase proof complexity.

use crate::decode::{opcode, DecodedInstr};
use crate::error::ExecutorError;
use crate::memory::Memory;
use crate::trace::{ExecutionTrace, InstrFlags, MemOp, TraceRow};
use serde::{Deserialize, Serialize};

/// RV32IM CPU state.
#[derive(Clone, Serialize, Deserialize)]
pub struct Cpu {
    /// General-purpose registers x0..x31.
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
    /// Create a new CPU with default memory size.
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
    }

    /// Get a register value.
    #[inline]
    pub fn get_reg(&self, rs: u8) -> u32 {
        self.regs[rs as usize]
    }

    /// Execute a single instruction, returning the trace row if tracing.
    pub fn step(&mut self) -> Result<Option<TraceRow>, ExecutorError> {
        // Fetch instruction
        let instr_bits = self.memory.read_u32(self.pc)?;
        let instr = DecodedInstr::decode(instr_bits);

        // Prepare trace row
        let mut row = TraceRow::new(self.cycle, self.pc, self.regs);
        row.instr = instr;

        // Default next_pc
        let mut next_pc = self.pc.wrapping_add(4);
        let mut rd_val = 0u32;
        let mut mem_op = MemOp::None;
        let mut flags = InstrFlags::default();
        let mut mul_lo = 0u32;
        let mut mul_hi = 0u32;

        // Execute based on opcode
        match instr.opcode {
            opcode::LUI => {
                flags.is_lui = true;
                rd_val = instr.imm as u32;
            }
            opcode::AUIPC => {
                flags.is_auipc = true;
                rd_val = self.pc.wrapping_add(instr.imm as u32);
            }
            opcode::JAL => {
                flags.is_jal = true;
                rd_val = self.pc.wrapping_add(4);
                next_pc = self.pc.wrapping_add(instr.imm as u32);
            }
            opcode::JALR => {
                flags.is_jalr = true;
                rd_val = self.pc.wrapping_add(4);
                let base = self.get_reg(instr.rs1);
                next_pc = base.wrapping_add(instr.imm as u32) & !1;
            }
            opcode::BRANCH => {
                flags.is_branch = true;
                let rs1_val = self.get_reg(instr.rs1);
                let rs2_val = self.get_reg(instr.rs2);
                let taken = match instr.funct3 {
                    0b000 => rs1_val == rs2_val,                           // BEQ
                    0b001 => rs1_val != rs2_val,                           // BNE
                    0b100 => (rs1_val as i32) < (rs2_val as i32),          // BLT
                    0b101 => (rs1_val as i32) >= (rs2_val as i32),         // BGE
                    0b110 => rs1_val < rs2_val,                            // BLTU
                    0b111 => rs1_val >= rs2_val,                           // BGEU
                    _ => false,
                };
                if taken {
                    next_pc = self.pc.wrapping_add(instr.imm as u32);
                }
            }
            opcode::LOAD => {
                flags.is_load = true;
                let addr = self.get_reg(instr.rs1).wrapping_add(instr.imm as u32);
                match instr.funct3 {
                    0b000 => {
                        // LB
                        let val = self.memory.read_u8(addr)?;
                        rd_val = (val as i8) as i32 as u32;
                        mem_op = MemOp::LoadByte { addr, value: val, signed: true };
                    }
                    0b001 => {
                        // LH
                        let val = self.memory.read_u16(addr)?;
                        rd_val = (val as i16) as i32 as u32;
                        mem_op = MemOp::LoadHalf { addr, value: val, signed: true };
                    }
                    0b010 => {
                        // LW
                        let val = self.memory.read_u32(addr)?;
                        rd_val = val;
                        mem_op = MemOp::LoadWord { addr, value: val };
                    }
                    0b100 => {
                        // LBU
                        let val = self.memory.read_u8(addr)?;
                        rd_val = val as u32;
                        mem_op = MemOp::LoadByte { addr, value: val, signed: false };
                    }
                    0b101 => {
                        // LHU
                        let val = self.memory.read_u16(addr)?;
                        rd_val = val as u32;
                        mem_op = MemOp::LoadHalf { addr, value: val, signed: false };
                    }
                    _ => return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits }),
                }
            }
            opcode::STORE => {
                flags.is_store = true;
                let addr = self.get_reg(instr.rs1).wrapping_add(instr.imm as u32);
                let val = self.get_reg(instr.rs2);
                match instr.funct3 {
                    0b000 => {
                        // SB
                        let byte = val as u8;
                        self.memory.write_u8(addr, byte)?;
                        mem_op = MemOp::StoreByte { addr, value: byte };
                    }
                    0b001 => {
                        // SH
                        let half = val as u16;
                        self.memory.write_u16(addr, half)?;
                        mem_op = MemOp::StoreHalf { addr, value: half };
                    }
                    0b010 => {
                        // SW
                        self.memory.write_u32(addr, val)?;
                        mem_op = MemOp::StoreWord { addr, value: val };
                    }
                    _ => return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits }),
                }
            }
            opcode::OP_IMM => {
                flags.is_alu_imm = true;
                let rs1_val = self.get_reg(instr.rs1);
                let imm = instr.imm as u32;
                rd_val = match instr.funct3 {
                    0b000 => rs1_val.wrapping_add(imm),                     // ADDI
                    0b010 => ((rs1_val as i32) < (imm as i32)) as u32,      // SLTI
                    0b011 => (rs1_val < imm) as u32,                        // SLTIU
                    0b100 => rs1_val ^ imm,                                 // XORI
                    0b110 => rs1_val | imm,                                 // ORI
                    0b111 => rs1_val & imm,                                 // ANDI
                    0b001 => {
                        // SLLI
                        let shamt = (imm & 0x1F) as u32;
                        rs1_val << shamt
                    }
                    0b101 => {
                        let shamt = (imm & 0x1F) as u32;
                        if instr.funct7 & 0x20 != 0 {
                            // SRAI
                            ((rs1_val as i32) >> shamt) as u32
                        } else {
                            // SRLI
                            rs1_val >> shamt
                        }
                    }
                    _ => return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits }),
                };
            }
            opcode::OP => {
                let rs1_val = self.get_reg(instr.rs1);
                let rs2_val = self.get_reg(instr.rs2);

                if instr.funct7 == 0x01 {
                    // M-extension
                    match instr.funct3 {
                        0b000 => {
                            // MUL
                            flags.is_mul = true;
                            let prod = (rs1_val as i32 as i64) * (rs2_val as i32 as i64);
                            rd_val = prod as u32;
                            mul_lo = prod as u32;
                            mul_hi = (prod >> 32) as u32;
                        }
                        0b001 => {
                            // MULH
                            flags.is_mul = true;
                            let prod = (rs1_val as i32 as i64) * (rs2_val as i32 as i64);
                            rd_val = (prod >> 32) as u32;
                            mul_lo = prod as u32;
                            mul_hi = (prod >> 32) as u32;
                        }
                        0b010 => {
                            // MULHSU
                            flags.is_mul = true;
                            let prod = (rs1_val as i32 as i64) * (rs2_val as u64 as i64);
                            rd_val = (prod >> 32) as u32;
                            mul_lo = prod as u32;
                            mul_hi = (prod >> 32) as u32;
                        }
                        0b011 => {
                            // MULHU
                            flags.is_mul = true;
                            let prod = (rs1_val as u64) * (rs2_val as u64);
                            rd_val = (prod >> 32) as u32;
                            mul_lo = prod as u32;
                            mul_hi = (prod >> 32) as u32;
                        }
                        0b100 => {
                            // DIV
                            flags.is_div = true;
                            if rs2_val == 0 {
                                rd_val = u32::MAX;
                            } else if rs1_val == 0x80000000 && rs2_val == 0xFFFFFFFF {
                                rd_val = 0x80000000; // Overflow case
                            } else {
                                rd_val = ((rs1_val as i32) / (rs2_val as i32)) as u32;
                            }
                        }
                        0b101 => {
                            // DIVU
                            flags.is_div = true;
                            if rs2_val == 0 {
                                rd_val = u32::MAX;
                            } else {
                                rd_val = rs1_val / rs2_val;
                            }
                        }
                        0b110 => {
                            // REM
                            flags.is_rem = true;
                            if rs2_val == 0 {
                                rd_val = rs1_val;
                            } else if rs1_val == 0x80000000 && rs2_val == 0xFFFFFFFF {
                                rd_val = 0;
                            } else {
                                rd_val = ((rs1_val as i32) % (rs2_val as i32)) as u32;
                            }
                        }
                        0b111 => {
                            // REMU
                            flags.is_rem = true;
                            if rs2_val == 0 {
                                rd_val = rs1_val;
                            } else {
                                rd_val = rs1_val % rs2_val;
                            }
                        }
                        _ => return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits }),
                    }
                } else {
                    // Base RV32I OP
                    flags.is_alu = true;
                    rd_val = match (instr.funct3, instr.funct7) {
                        (0b000, 0x00) => rs1_val.wrapping_add(rs2_val),     // ADD
                        (0b000, 0x20) => rs1_val.wrapping_sub(rs2_val),     // SUB
                        (0b001, 0x00) => rs1_val << (rs2_val & 0x1F),       // SLL
                        (0b010, 0x00) => ((rs1_val as i32) < (rs2_val as i32)) as u32, // SLT
                        (0b011, 0x00) => (rs1_val < rs2_val) as u32,        // SLTU
                        (0b100, 0x00) => rs1_val ^ rs2_val,                 // XOR
                        (0b101, 0x00) => rs1_val >> (rs2_val & 0x1F),       // SRL
                        (0b101, 0x20) => ((rs1_val as i32) >> (rs2_val & 0x1F)) as u32, // SRA
                        (0b110, 0x00) => rs1_val | rs2_val,                 // OR
                        (0b111, 0x00) => rs1_val & rs2_val,                 // AND
                        _ => return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits }),
                    };
                }
            }
            opcode::SYSTEM => {
                // System instructions are unprovable traps in machine-mode-only execution
                match instr.imm as u32 & 0xFFF {
                    0x000 => {
                        // ECALL - system call (unprovable trap)
                        flags.is_ecall = true;
                        let syscall_id = self.get_reg(17); // a7
                        return Err(ExecutorError::Ecall { pc: self.pc, syscall_id });
                    }
                    0x001 => {
                        // EBREAK - debug breakpoint (unprovable trap)
                        flags.is_ebreak = true;
                        return Err(ExecutorError::Ebreak { pc: self.pc });
                    }
                    0x105 => {
                        // WFI - Wait For Interrupt (unprovable trap)
                        return Err(ExecutorError::Wfi { pc: self.pc });
                    }
                    _ => {
                        // CSR instructions and other system ops not supported
                        return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits });
                    }
                }
            }
            opcode::MISC_MEM => {
                // FENCE instructions (opcode 0x0F) - memory barriers (unprovable trap)
                // Not needed in single-threaded deterministic execution
                return Err(ExecutorError::Fence { pc: self.pc });
            }
            _ => {
                return Err(ExecutorError::InvalidInstruction { pc: self.pc, bits: instr_bits });
            }
        }

        // Write back to register (rd=0 writes are no-ops)
        if instr.rd != 0 && !flags.is_store && !flags.is_branch {
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

        // Update state
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

    /// Run until halt, unprovable trap, or max_steps reached.
    /// 
    /// Note: ECALL/EBREAK/WFI/FENCE are unprovable traps that will cause prover failure.
    /// Programs should not use these instructions if they need to be proven.
    pub fn run(&mut self, max_steps: u64) -> Result<ExecutionTrace, ExecutorError> {
        self.enable_tracing();

        for _ in 0..max_steps {
            match self.step() {
                Ok(_) => {}
                Err(ExecutorError::Ecall { syscall_id, .. }) => {
                    // Handle halt syscall (syscall_id = 93 is exit in Linux)
                    // Note: This is an unprovable trap - execution can continue but proving will fail
                    if syscall_id == 93 {
                        let mut trace = self.take_trace().unwrap_or_default();
                        trace.final_regs = self.regs;
                        trace.final_pc = self.pc;
                        trace.total_cycles = self.cycle;
                        trace.halt_reason = Some(format!("exit({}) - WARNING: unprovable trap", self.get_reg(10)));
                        return Ok(trace);
                    }
                    // For other syscalls, return the error (unprovable)
                    return Err(ExecutorError::Ecall { pc: self.pc, syscall_id });
                }
                Err(e) => return Err(e),
            }
        }

        Err(ExecutorError::MaxStepsReached { max_steps })
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble_addi(rd: u8, rs1: u8, imm: i32) -> u32 {
        let imm = (imm as u32) & 0xFFF;
        (imm << 20) | ((rs1 as u32) << 15) | (0b000 << 12) | ((rd as u32) << 7) | 0b0010011
    }

    fn assemble_add(rd: u8, rs1: u8, rs2: u8) -> u32 {
        ((rs2 as u32) << 20) | ((rs1 as u32) << 15) | (0b000 << 12) | ((rd as u32) << 7) | 0b0110011
    }

    #[test]
    fn test_addi() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_addi(1, 0, 42).to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(1), 42);
    }

    #[test]
    fn test_add() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program: Vec<u8> = [
            assemble_addi(1, 0, 10),  // x1 = 10
            assemble_addi(2, 0, 20),  // x2 = 20
            assemble_add(3, 1, 2),    // x3 = x1 + x2
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
    fn test_x0_always_zero() {
        let mut cpu = Cpu::with_memory_size(4096);
        let program = assemble_addi(0, 0, 42).to_le_bytes();
        cpu.load_program(0, &program).unwrap();
        cpu.step().unwrap();
        assert_eq!(cpu.get_reg(0), 0);
    }
}
