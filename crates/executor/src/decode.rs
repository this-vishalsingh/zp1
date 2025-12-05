//! RISC-V instruction decoder for RV32IM.

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
    R,  // Register-register (ADD, SUB, MUL, etc.)
    I,  // Immediate (ADDI, LOAD, JALR)
    S,  // Store (SW, SH, SB)
    B,  // Branch (BEQ, BNE, BLT, etc.)
    U,  // Upper immediate (LUI, AUIPC)
    J,  // Jump (JAL)
}

/// Opcode constants for RV32I.
pub mod opcode {
    pub const LUI: u8 = 0b0110111;
    pub const AUIPC: u8 = 0b0010111;
    pub const JAL: u8 = 0b1101111;
    pub const JALR: u8 = 0b1100111;
    pub const BRANCH: u8 = 0b1100011;
    pub const LOAD: u8 = 0b0000011;
    pub const STORE: u8 = 0b0100011;
    pub const OP_IMM: u8 = 0b0010011;
    pub const OP: u8 = 0b0110011;
    pub const SYSTEM: u8 = 0b1110011;
    pub const MISC_MEM: u8 = 0b0001111; // FENCE instructions
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
                // U-type: imm[31:12]
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
            opcode::JALR | opcode::LOAD | opcode::OP_IMM | opcode::SYSTEM => {
                // I-type: imm[11:0]
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

    /// Check if this is an M-extension instruction (multiply/divide).
    #[inline]
    pub fn is_m_extension(&self) -> bool {
        self.opcode == opcode::OP && self.funct7 == 0x01
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
    }

    #[test]
    fn test_decode_lui() {
        // LUI x1, 0x12345 = 0x123450b7
        let instr = DecodedInstr::decode(0x123450b7);
        assert_eq!(instr.opcode, opcode::LUI);
        assert_eq!(instr.rd, 1);
        assert_eq!(instr.imm, 0x12345000u32 as i32);
        assert_eq!(instr.format, InstrFormat::U);
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
    }
}
