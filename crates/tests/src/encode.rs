//! RISC-V instruction encoders for test programs.

/// ADDI rd, rs1, imm - I-type encoding
pub fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    let imm = (imm as u32) & 0xFFF;
    (imm << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0010011
}

/// ADD rd, rs1, rs2 - R-type encoding
pub fn add(rd: u32, rs1: u32, rs2: u32) -> u32 {
    (0b0000000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0110011
}

/// SUB rd, rs1, rs2 - R-type encoding  
pub fn sub(rd: u32, rs1: u32, rs2: u32) -> u32 {
    (0b0100000 << 25) | (rs2 << 20) | (rs1 << 15) | (0b000 << 12) | (rd << 7) | 0b0110011
}

/// BEQ rs1, rs2, offset - B-type encoding
pub fn beq(rs1: u32, rs2: u32, offset: i32) -> u32 {
    let offset = offset as u32;
    let imm12 = (offset >> 12) & 1;
    let imm11 = (offset >> 11) & 1;
    let imm10_5 = (offset >> 5) & 0x3F;
    let imm4_1 = (offset >> 1) & 0xF;
    (imm12 << 31)
        | (imm10_5 << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (0b000 << 12)
        | (imm4_1 << 8)
        | (imm11 << 7)
        | 0b1100011
}

/// BNE rs1, rs2, offset - B-type encoding
pub fn bne(rs1: u32, rs2: u32, offset: i32) -> u32 {
    let offset = offset as u32;
    let imm12 = (offset >> 12) & 1;
    let imm11 = (offset >> 11) & 1;
    let imm10_5 = (offset >> 5) & 0x3F;
    let imm4_1 = (offset >> 1) & 0xF;
    (imm12 << 31)
        | (imm10_5 << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (0b001 << 12)
        | (imm4_1 << 8)
        | (imm11 << 7)
        | 0b1100011
}

/// JAL rd, offset - J-type encoding
pub fn jal(rd: u32, offset: i32) -> u32 {
    let offset = offset as u32;
    let imm20 = (offset >> 20) & 1;
    let imm19_12 = (offset >> 12) & 0xFF;
    let imm11 = (offset >> 11) & 1;
    let imm10_1 = (offset >> 1) & 0x3FF;
    (imm20 << 31) | (imm10_1 << 21) | (imm11 << 20) | (imm19_12 << 12) | (rd << 7) | 0b1101111
}

/// ECALL - system call to halt
pub fn ecall() -> u32 {
    0b000000000000_00000_000_00000_1110011
}

/// EBREAK - breakpoint (also halts)
pub fn ebreak() -> u32 {
    0b000000000001_00000_000_00000_1110011
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addi_encoding() {
        // ADDI x1, x0, 5
        let instr = addi(1, 0, 5);
        assert_eq!(instr & 0x7F, 0b0010011); // opcode
        assert_eq!((instr >> 7) & 0x1F, 1); // rd
        assert_eq!((instr >> 15) & 0x1F, 0); // rs1
        assert_eq!((instr >> 20) & 0xFFF, 5); // imm
    }

    #[test]
    fn test_add_encoding() {
        // ADD x3, x1, x2
        let instr = add(3, 1, 2);
        assert_eq!(instr & 0x7F, 0b0110011); // opcode
        assert_eq!((instr >> 7) & 0x1F, 3); // rd
        assert_eq!((instr >> 15) & 0x1F, 1); // rs1
        assert_eq!((instr >> 20) & 0x1F, 2); // rs2
    }

    #[test]
    fn test_ecall_encoding() {
        let instr = ecall();
        assert_eq!(instr & 0x7F, 0b1110011);
        assert_eq!(instr >> 20, 0);
    }
}
