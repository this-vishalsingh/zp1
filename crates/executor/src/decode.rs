//! RISC-V instruction decoder for RV32IM.
//!
//! Implements complete decoding for all RV32IM instructions including:
//! - RV32I base integer instruction set
//! - M extension (multiply/divide)
//! - Zicsr extension (CSR instructions) - decoded but execution causes trap
//! - Zifencei extension (FENCE.I) - decoded but treated as NOP

use serde::{Deserialize, Serialize};

/// Decoded RISC-V instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedInstr {
    /// Raw 32-bit instruction bits.
    pub bits: u32,
    /// Opcode (bits [6:0]).
    pub opcode: u8,
    /// Destination register (rd).
    pub rd: u8,
    /// Function code 3 (funct3).
    pub funct3: u8,
    /// Source register 1 (rs1).
    pub rs1: u8,
    /// Source register 2 (rs2).
    pub rs2: u8,
    /// Function code 7 (funct7).
    pub funct7: u8,
    /// Immediate value (sign-extended as appropriate for the format).
    pub imm: i32,
    /// Instruction format.
    pub format: InstrFormat,
}

/// RISC-V instruction formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstrFormat {
    R, // Register-register (ADD, SUB, MUL, etc.)
    I, // Immediate (ADDI, LOAD, JALR)
    S, // Store (SW, SH, SB)
    B, // Branch (BEQ, BNE, BLT, etc.)
    U, // Upper immediate (LUI, AUIPC)
    J, // Jump (JAL)
}

/// Opcode constants for RV32IM.
pub mod opcode {
    /// LUI - Load Upper Immediate
    pub const LUI: u8 = 0b0110111;
    /// AUIPC - Add Upper Immediate to PC
    pub const AUIPC: u8 = 0b0010111;
    /// JAL - Jump and Link
    pub const JAL: u8 = 0b1101111;
    /// JALR - Jump and Link Register
    pub const JALR: u8 = 0b1100111;
    /// Branch instructions (BEQ, BNE, BLT, BGE, BLTU, BGEU)
    pub const BRANCH: u8 = 0b1100011;
    /// Load instructions (LB, LH, LW, LBU, LHU)
    pub const LOAD: u8 = 0b0000011;
    /// Store instructions (SB, SH, SW)
    pub const STORE: u8 = 0b0100011;
    /// ALU immediate instructions (ADDI, SLTI, etc.)
    pub const OP_IMM: u8 = 0b0010011;
    /// ALU register instructions (ADD, SUB, MUL, etc.)
    pub const OP: u8 = 0b0110011;
    /// System instructions (ECALL, EBREAK, CSR*)
    pub const SYSTEM: u8 = 0b1110011;
    /// Memory fence instructions (FENCE, FENCE.I)
    pub const MISC_MEM: u8 = 0b0001111;
}

/// funct3 values for branch instructions
pub mod branch_funct3 {
    pub const BEQ: u8 = 0b000;
    pub const BNE: u8 = 0b001;
    pub const BLT: u8 = 0b100;
    pub const BGE: u8 = 0b101;
    pub const BLTU: u8 = 0b110;
    pub const BGEU: u8 = 0b111;
}

/// funct3 values for load instructions
pub mod load_funct3 {
    pub const LB: u8 = 0b000;
    pub const LH: u8 = 0b001;
    pub const LW: u8 = 0b010;
    pub const LBU: u8 = 0b100;
    pub const LHU: u8 = 0b101;
}

/// funct3 values for store instructions
pub mod store_funct3 {
    pub const SB: u8 = 0b000;
    pub const SH: u8 = 0b001;
    pub const SW: u8 = 0b010;
}

/// funct3 values for ALU immediate instructions
pub mod op_imm_funct3 {
    pub const ADDI: u8 = 0b000;
    pub const SLTI: u8 = 0b010;
    pub const SLTIU: u8 = 0b011;
    pub const XORI: u8 = 0b100;
    pub const ORI: u8 = 0b110;
    pub const ANDI: u8 = 0b111;
    pub const SLLI: u8 = 0b001;
    pub const SRLI_SRAI: u8 = 0b101;
}

/// funct3 values for ALU register instructions
pub mod op_funct3 {
    pub const ADD_SUB_MUL: u8 = 0b000;
    pub const SLL_MULH: u8 = 0b001;
    pub const SLT_MULHSU: u8 = 0b010;
    pub const SLTU_MULHU: u8 = 0b011;
    pub const XOR_DIV: u8 = 0b100;
    pub const SRL_SRA_DIVU: u8 = 0b101;
    pub const OR_REM: u8 = 0b110;
    pub const AND_REMU: u8 = 0b111;
}

/// funct3 values for SYSTEM instructions
pub mod system_funct3 {
    pub const PRIV: u8 = 0b000; // ECALL, EBREAK, WFI, MRET, etc.
    pub const CSRRW: u8 = 0b001;
    pub const CSRRS: u8 = 0b010;
    pub const CSRRC: u8 = 0b011;
    pub const CSRRWI: u8 = 0b101;
    pub const CSRRSI: u8 = 0b110;
    pub const CSRRCI: u8 = 0b111;
}

/// funct7 values
pub mod funct7 {
    pub const NORMAL: u8 = 0x00;
    pub const SUB_SRA: u8 = 0x20;
    pub const MULDIV: u8 = 0x01;
}

impl DecodedInstr {
    /// Decode a 32-bit instruction word.
    pub fn decode(bits: u32) -> Self {
        let opcode = (bits & 0x7F) as u8;
        let rd = ((bits >> 7) & 0x1F) as u8;
        let funct3 = ((bits >> 12) & 0x7) as u8;
        let rs1 = ((bits >> 15) & 0x1F) as u8;
        let rs2 = ((bits >> 20) & 0x1F) as u8;
        let funct7 = ((bits >> 25) & 0x7F) as u8;

        let (imm, format) = match opcode {
            opcode::LUI | opcode::AUIPC => {
                // U-type: imm[31:12] stored in upper 20 bits
                let imm = (bits & 0xFFFFF000) as i32;
                (imm, InstrFormat::U)
            }
            opcode::JAL => {
                // J-type: imm[20|10:1|11|19:12]
                let imm20 = ((bits >> 31) & 1) as i32;
                let imm10_1 = ((bits >> 21) & 0x3FF) as i32;
                let imm11 = ((bits >> 20) & 1) as i32;
                let imm19_12 = ((bits >> 12) & 0xFF) as i32;
                let imm = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
                // Sign extend from bit 20
                let imm = (imm << 11) >> 11;
                (imm, InstrFormat::J)
            }
            opcode::JALR | opcode::LOAD | opcode::OP_IMM | opcode::SYSTEM | opcode::MISC_MEM => {
                // I-type: imm[11:0] sign-extended
                let imm = (bits as i32) >> 20;
                (imm, InstrFormat::I)
            }
            opcode::BRANCH => {
                // B-type: imm[12|10:5|4:1|11]
                let imm12 = ((bits >> 31) & 1) as i32;
                let imm10_5 = ((bits >> 25) & 0x3F) as i32;
                let imm4_1 = ((bits >> 8) & 0xF) as i32;
                let imm11 = ((bits >> 7) & 1) as i32;
                let imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
                // Sign extend from bit 12
                let imm = (imm << 19) >> 19;
                (imm, InstrFormat::B)
            }
            opcode::STORE => {
                // S-type: imm[11:5|4:0]
                let imm11_5 = ((bits >> 25) & 0x7F) as i32;
                let imm4_0 = ((bits >> 7) & 0x1F) as i32;
                let imm = (imm11_5 << 5) | imm4_0;
                // Sign extend from bit 11
                let imm = (imm << 20) >> 20;
                (imm, InstrFormat::S)
            }
            opcode::OP => {
                // R-type: no immediate
                (0, InstrFormat::R)
            }
            _ => {
                // Unknown opcode, treat as R-type with zero immediate
                (0, InstrFormat::R)
            }
        };

        Self {
            bits,
            opcode,
            rd,
            funct3,
            rs1,
            rs2,
            funct7,
            imm,
            format,
        }
    }

    /// Check if this is a NOP (ADDI x0, x0, 0).
    #[inline]
    pub fn is_nop(&self) -> bool {
        self.bits == 0x00000013
            || (self.opcode == opcode::OP_IMM
                && self.funct3 == 0
                && self.rd == 0
                && self.rs1 == 0
                && self.imm == 0)
    }

    /// Check if this is an M-extension instruction (multiply/divide).
    #[inline]
    pub fn is_m_extension(&self) -> bool {
        self.opcode == opcode::OP && self.funct7 == funct7::MULDIV
    }

    /// Check if this is a load instruction.
    #[inline]
    pub fn is_load(&self) -> bool {
        self.opcode == opcode::LOAD
    }

    /// Check if this is a store instruction.
    #[inline]
    pub fn is_store(&self) -> bool {
        self.opcode == opcode::STORE
    }

    /// Check if this is a branch instruction.
    #[inline]
    pub fn is_branch(&self) -> bool {
        self.opcode == opcode::BRANCH
    }

    /// Check if this is a jump instruction (JAL or JALR).
    #[inline]
    pub fn is_jump(&self) -> bool {
        self.opcode == opcode::JAL || self.opcode == opcode::JALR
    }

    /// Check if this is a CSR instruction.
    #[inline]
    pub fn is_csr(&self) -> bool {
        self.opcode == opcode::SYSTEM && self.funct3 != 0
    }

    /// Check if this is a FENCE or FENCE.I instruction.
    #[inline]
    pub fn is_fence(&self) -> bool {
        self.opcode == opcode::MISC_MEM
    }

    /// Get the CSR address for CSR instructions.
    #[inline]
    pub fn csr_addr(&self) -> u16 {
        (self.imm as u32 & 0xFFF) as u16
    }

    /// Get shift amount for shift instructions.
    #[inline]
    pub fn shamt(&self) -> u32 {
        (self.imm as u32) & 0x1F
    }

    /// Get the instruction mnemonic (for debugging).
    pub fn mnemonic(&self) -> &'static str {
        match self.opcode {
            opcode::LUI => "LUI",
            opcode::AUIPC => "AUIPC",
            opcode::JAL => "JAL",
            opcode::JALR => "JALR",
            opcode::BRANCH => match self.funct3 {
                branch_funct3::BEQ => "BEQ",
                branch_funct3::BNE => "BNE",
                branch_funct3::BLT => "BLT",
                branch_funct3::BGE => "BGE",
                branch_funct3::BLTU => "BLTU",
                branch_funct3::BGEU => "BGEU",
                _ => "BRANCH?",
            },
            opcode::LOAD => match self.funct3 {
                load_funct3::LB => "LB",
                load_funct3::LH => "LH",
                load_funct3::LW => "LW",
                load_funct3::LBU => "LBU",
                load_funct3::LHU => "LHU",
                _ => "LOAD?",
            },
            opcode::STORE => match self.funct3 {
                store_funct3::SB => "SB",
                store_funct3::SH => "SH",
                store_funct3::SW => "SW",
                _ => "STORE?",
            },
            opcode::OP_IMM => match self.funct3 {
                op_imm_funct3::ADDI => {
                    if self.is_nop() {
                        "NOP"
                    } else {
                        "ADDI"
                    }
                }
                op_imm_funct3::SLTI => "SLTI",
                op_imm_funct3::SLTIU => "SLTIU",
                op_imm_funct3::XORI => "XORI",
                op_imm_funct3::ORI => "ORI",
                op_imm_funct3::ANDI => "ANDI",
                op_imm_funct3::SLLI => "SLLI",
                op_imm_funct3::SRLI_SRAI => {
                    if self.funct7 & 0x20 != 0 {
                        "SRAI"
                    } else {
                        "SRLI"
                    }
                }
                _ => "OP_IMM?",
            },
            opcode::OP => {
                if self.funct7 == funct7::MULDIV {
                    match self.funct3 {
                        0b000 => "MUL",
                        0b001 => "MULH",
                        0b010 => "MULHSU",
                        0b011 => "MULHU",
                        0b100 => "DIV",
                        0b101 => "DIVU",
                        0b110 => "REM",
                        0b111 => "REMU",
                        _ => "MULDIV?",
                    }
                } else {
                    match (self.funct3, self.funct7) {
                        (0b000, 0x00) => "ADD",
                        (0b000, 0x20) => "SUB",
                        (0b001, 0x00) => "SLL",
                        (0b010, 0x00) => "SLT",
                        (0b011, 0x00) => "SLTU",
                        (0b100, 0x00) => "XOR",
                        (0b101, 0x00) => "SRL",
                        (0b101, 0x20) => "SRA",
                        (0b110, 0x00) => "OR",
                        (0b111, 0x00) => "AND",
                        _ => "OP?",
                    }
                }
            }
            opcode::SYSTEM => match self.funct3 {
                system_funct3::PRIV => match self.imm as u32 & 0xFFF {
                    0x000 => "ECALL",
                    0x001 => "EBREAK",
                    0x105 => "WFI",
                    0x302 => "MRET",
                    _ => "PRIV?",
                },
                system_funct3::CSRRW => "CSRRW",
                system_funct3::CSRRS => "CSRRS",
                system_funct3::CSRRC => "CSRRC",
                system_funct3::CSRRWI => "CSRRWI",
                system_funct3::CSRRSI => "CSRRSI",
                system_funct3::CSRRCI => "CSRRCI",
                _ => "SYSTEM?",
            },
            opcode::MISC_MEM => {
                if self.funct3 == 0 {
                    "FENCE"
                } else {
                    "FENCE.I"
                }
            }
            _ => "???",
        }
    }
}

impl std::fmt::Display for DecodedInstr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_add() {
        // ADD x1, x2, x3 = 0x003100b3
        let instr = DecodedInstr::decode(0x003100b3);
        assert_eq!(instr.opcode, opcode::OP);
        assert_eq!(instr.rd, 1);
        assert_eq!(instr.rs1, 2);
        assert_eq!(instr.rs2, 3);
        assert_eq!(instr.funct3, 0);
        assert_eq!(instr.funct7, 0);
        assert_eq!(instr.format, InstrFormat::R);
        assert_eq!(instr.mnemonic(), "ADD");
    }

    #[test]
    fn test_decode_addi() {
        // ADDI x1, x2, 100 = 0x06410093
        let instr = DecodedInstr::decode(0x06410093);
        assert_eq!(instr.opcode, opcode::OP_IMM);
        assert_eq!(instr.rd, 1);
        assert_eq!(instr.rs1, 2);
        assert_eq!(instr.funct3, 0);
        assert_eq!(instr.imm, 100);
        assert_eq!(instr.format, InstrFormat::I);
        assert_eq!(instr.mnemonic(), "ADDI");
    }

    #[test]
    fn test_decode_lui() {
        // LUI x1, 0x12345 = 0x123450b7
        let instr = DecodedInstr::decode(0x123450b7);
        assert_eq!(instr.opcode, opcode::LUI);
        assert_eq!(instr.rd, 1);
        assert_eq!(instr.imm, 0x12345000u32 as i32);
        assert_eq!(instr.format, InstrFormat::U);
        assert_eq!(instr.mnemonic(), "LUI");
    }

    #[test]
    fn test_decode_beq() {
        // BEQ x1, x2, offset (example encoding)
        let instr = DecodedInstr::decode(0x00208463); // BEQ x1, x2, 8
        assert_eq!(instr.opcode, opcode::BRANCH);
        assert_eq!(instr.rs1, 1);
        assert_eq!(instr.rs2, 2);
        assert_eq!(instr.funct3, 0); // BEQ
        assert_eq!(instr.format, InstrFormat::B);
        assert_eq!(instr.mnemonic(), "BEQ");
    }

    #[test]
    fn test_decode_nop() {
        // NOP = ADDI x0, x0, 0 = 0x00000013
        let instr = DecodedInstr::decode(0x00000013);
        assert!(instr.is_nop());
        assert_eq!(instr.mnemonic(), "NOP");
    }

    #[test]
    fn test_decode_mul() {
        // MUL x1, x2, x3
        let instr = DecodedInstr::decode(0x023100b3);
        assert!(instr.is_m_extension());
        assert_eq!(instr.mnemonic(), "MUL");
    }

    #[test]
    fn test_decode_fence() {
        // FENCE
        let instr = DecodedInstr::decode(0x0ff0000f);
        assert!(instr.is_fence());
        assert_eq!(instr.mnemonic(), "FENCE");
    }

    #[test]
    fn test_negative_immediate() {
        // ADDI x1, x0, -1
        let instr = DecodedInstr::decode(0xfff00093);
        assert_eq!(instr.imm, -1);
    }

    #[test]
    fn test_jal_immediate() {
        // JAL x1, offset
        let instr = DecodedInstr::decode(0x008000ef); // JAL x1, 8
        assert_eq!(instr.opcode, opcode::JAL);
        assert_eq!(instr.imm, 8);
    }
}
