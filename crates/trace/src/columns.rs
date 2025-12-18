//! Execution trace column definitions and conversion.
//!
//! This module converts raw execution traces from the CPU emulator into
//! structured column format suitable for STARK proving. The trace uses
//! 77 columns organized for efficient constraint evaluation.
//!
//! # Column Organization
//!
//! The trace is organized into groups:
//!
//! ## Control Flow (5 columns)
//! - `clk`: Clock cycle counter
//! - `pc`: Current program counter
//! - `next_pc`: Next program counter (for branch/jump verification)
//! - `instr`: Raw 32-bit instruction
//! - `opcode`: Extracted opcode field
//!
//! ## Registers (3 columns)
//! - `rd`, `rs1`, `rs2`: Register indices (0-31)
//!
//! ## Immediates (2 columns)
//! - `imm_lo`, `imm_hi`: 16-bit limbs of immediate value
//!
//! ## Register Values (6 columns)
//! - `rd_val_lo/hi`: Destination register value (written)
//! - `rs1_val_lo/hi`: Source register 1 value (read)
//! - `rs2_val_lo/hi`: Source register 2 value (read)
//!
//! ## Instruction Selectors (46 columns)
//! One-hot encoded flags for each instruction type:
//! - R-type: `is_add`, `is_sub`, `is_and`, `is_or`, `is_xor`, etc.
//! - I-type: `is_addi`, `is_andi`, `is_ori`, `is_xori`, etc.
//! - Branches: `is_beq`, `is_bne`, `is_blt`, `is_bge`, etc.
//! - Memory: `is_lb`, `is_lh`, `is_lw`, `is_sb`, `is_sh`, `is_sw`, etc.
//! - M-extension: `is_mul`, `is_div`, `is_rem`, etc.
//!
//! ## Memory (4 columns)
//! - `mem_addr_lo/hi`: Memory address for load/store
//! - `mem_val_lo/hi`: Memory value read/written
//!
//! ## Witness Columns (9 columns)
//! Auxiliary values for constraint satisfaction:
//! - `sb_carry`: Byte extraction witness for SB instruction
//! - `mul_lo/hi`: Multiplication product witnesses
//! - `carry`: Carry flag for addition
//! - `borrow`: Borrow flag for subtraction
//! - `quotient_lo/hi`: Division quotient
//! - `remainder_lo/hi`: Division remainder
//!
//! ## Comparison Results (3 columns)
//! - `lt_result`: Less-than comparison result (0 or 1)
//! - `eq_result`: Equality comparison result (0 or 1)
//! - `branch_taken`: Branch taken flag (0 or 1)
//!
//! # Usage
//!
//! ```rust,ignore
//! use zp1_trace::TraceColumns;
//! use zp1_executor::Cpu;
//!
//! // Execute program and capture trace
//! let mut cpu = Cpu::new();
//! cpu.enable_tracing();
//! // ... execute program ...
//! let exec_trace = cpu.take_trace().unwrap();
//!
//! // Convert to column format
//! let columns = TraceColumns::from_execution_trace(&exec_trace);
//!
//! // Convert to flat vector for prover
//! let column_vec = columns.to_columns(); // Vec<Vec<M31>>
//! assert_eq!(column_vec.len(), 77);
//! ```

use zp1_executor::ExecutionTrace;
use zp1_primitives::M31;

/// Number of columns in the CPU trace.
pub const NUM_CPU_COLUMNS: usize = 77;

/// Complete trace columns for RV32IM AIR constraints.
///
/// This structure holds all 77 columns of the execution trace in a format
/// optimized for constraint evaluation. Each field is a vector where the
/// i-th element corresponds to the i-th execution step.
///
/// # Column Count: 77
///
/// The structure is organized into logical groups as documented in the
/// module-level documentation. All columns must have the same length,
/// which must be a power of 2 for FFT operations.
///
/// # Padding
///
/// Use `pad_to()` to extend all columns to a power-of-2 length with zeros.
///
/// # Conversion
///
/// - `from_execution_trace()`: Convert from CPU execution trace
/// - `to_columns()`: Convert to flat Vec<Vec<M31>> for prover
#[derive(Clone, Debug)]
pub struct TraceColumns {
    /// Clock cycle.
    pub clk: Vec<M31>,
    /// Program counter.
    pub pc: Vec<M31>,
    /// Next program counter.
    pub next_pc: Vec<M31>,
    /// Instruction bits (can be decomposed further).
    pub instr: Vec<M31>,
    /// Opcode.
    pub opcode: Vec<M31>,
    /// rd index.
    pub rd: Vec<M31>,
    /// rs1 index.
    pub rs1: Vec<M31>,
    /// rs2 index.
    pub rs2: Vec<M31>,
    /// Immediate value (low 16 bits).
    pub imm_lo: Vec<M31>,
    /// Immediate value (high 16 bits).
    pub imm_hi: Vec<M31>,
    /// rd value written.
    pub rd_val_lo: Vec<M31>,
    pub rd_val_hi: Vec<M31>,
    /// rs1 value read.
    pub rs1_val_lo: Vec<M31>,
    pub rs1_val_hi: Vec<M31>,
    /// rs2 value read.
    pub rs2_val_lo: Vec<M31>,
    pub rs2_val_hi: Vec<M31>,
    /// Instruction flags (selectors).
    // R-type
    pub is_add: Vec<M31>,
    pub is_sub: Vec<M31>,
    pub is_and: Vec<M31>,
    pub is_or: Vec<M31>,
    pub is_xor: Vec<M31>,
    pub is_sll: Vec<M31>,
    pub is_srl: Vec<M31>,
    pub is_sra: Vec<M31>,
    pub is_slt: Vec<M31>,
    pub is_sltu: Vec<M31>,
    // I-type
    pub is_addi: Vec<M31>,
    pub is_andi: Vec<M31>,
    pub is_ori: Vec<M31>,
    pub is_xori: Vec<M31>,
    pub is_slti: Vec<M31>,
    pub is_sltiu: Vec<M31>,
    pub is_slli: Vec<M31>,
    pub is_srli: Vec<M31>,
    pub is_srai: Vec<M31>,
    // Upper
    pub is_lui: Vec<M31>,
    pub is_auipc: Vec<M31>,
    // Branch
    pub is_beq: Vec<M31>,
    pub is_bne: Vec<M31>,
    pub is_blt: Vec<M31>,
    pub is_bge: Vec<M31>,
    pub is_bltu: Vec<M31>,
    pub is_bgeu: Vec<M31>,
    // Jump
    pub is_jal: Vec<M31>,
    pub is_jalr: Vec<M31>,
    // M-extension
    pub is_mul: Vec<M31>,
    pub is_mulh: Vec<M31>,
    pub is_mulhsu: Vec<M31>,
    pub is_mulhu: Vec<M31>,
    pub is_div: Vec<M31>,
    pub is_divu: Vec<M31>,
    pub is_rem: Vec<M31>,
    pub is_remu: Vec<M31>,
    /// Load/Store variants
    pub is_lb: Vec<M31>,
    pub is_lbu: Vec<M31>,
    pub is_lh: Vec<M31>,
    pub is_lhu: Vec<M31>,
    pub is_lw: Vec<M31>,
    pub is_sb: Vec<M31>,
    pub is_sh: Vec<M31>,
    pub is_sw: Vec<M31>,
    /// Memory address (if load/store).
    pub mem_addr_lo: Vec<M31>,
    pub mem_addr_hi: Vec<M31>,
    /// Memory value (if load/store).
    pub mem_val_lo: Vec<M31>,
    pub mem_val_hi: Vec<M31>,
    /// Store byte carry witness.
    pub sb_carry: Vec<M31>,
    /// Multiply intermediate (64-bit product).
    pub mul_lo: Vec<M31>,
    pub mul_hi: Vec<M31>,

    // Auxiliary witnesses
    pub carry: Vec<M31>,
    pub borrow: Vec<M31>,
    pub quotient_lo: Vec<M31>,
    pub quotient_hi: Vec<M31>,
    pub remainder_lo: Vec<M31>,
    pub remainder_hi: Vec<M31>,
    pub lt_result: Vec<M31>,
    pub eq_result: Vec<M31>,
    pub branch_taken: Vec<M31>,

    // Bitwise operation bit decompositions (32 bits each)
    // INPUT decompositions (needed for proper constraint verification)
    pub rs1_bits: [Vec<M31>; 32], // Bit decomposition of rs1
    pub rs2_bits: [Vec<M31>; 32], // Bit decomposition of rs2
    pub imm_bits: [Vec<M31>; 32], // Bit decomposition of immediate (for ANDI/ORI/XORI)
    // OUTPUT decompositions (result bits)
    pub and_bits: [Vec<M31>; 32], // Bit decomposition of AND result
    pub xor_bits: [Vec<M31>; 32], // Bit decomposition of XOR result
    pub or_bits: [Vec<M31>; 32],  // Bit decomposition of OR result

    // =========================================================================
    // Byte decomposition for 8-bit lookup tables (NEW - replaces bit constraints)
    // These columns enable 4 lookups per 32-bit operation instead of 32 polynomial constraints
    // =========================================================================
    /// Input byte decomposition: rs1 = rs1_bytes[0] + 256*rs1_bytes[1] + ...
    pub rs1_bytes: [Vec<M31>; 4],
    /// Input byte decomposition: rs2 = rs2_bytes[0] + 256*rs2_bytes[1] + ...
    pub rs2_bytes: [Vec<M31>; 4],
    /// AND result bytes for lookup verification
    pub and_result_bytes: [Vec<M31>; 4],
    /// OR result bytes for lookup verification  
    pub or_result_bytes: [Vec<M31>; 4],
    /// XOR result bytes for lookup verification
    pub xor_result_bytes: [Vec<M31>; 4],
}

impl TraceColumns {
    /// Create empty trace columns.
    pub fn new() -> Self {
        Self {
            clk: Vec::new(),
            pc: Vec::new(),
            next_pc: Vec::new(),
            instr: Vec::new(),
            opcode: Vec::new(),
            rd: Vec::new(),
            rs1: Vec::new(),
            rs2: Vec::new(),
            imm_lo: Vec::new(),
            imm_hi: Vec::new(),
            rd_val_lo: Vec::new(),
            rd_val_hi: Vec::new(),
            rs1_val_lo: Vec::new(),
            rs1_val_hi: Vec::new(),
            rs2_val_lo: Vec::new(),
            rs2_val_hi: Vec::new(),
            is_add: Vec::new(),
            is_sub: Vec::new(),
            is_and: Vec::new(),
            is_or: Vec::new(),
            is_xor: Vec::new(),
            is_sll: Vec::new(),
            is_srl: Vec::new(),
            is_sra: Vec::new(),
            is_slt: Vec::new(),
            is_sltu: Vec::new(),
            is_addi: Vec::new(),
            is_andi: Vec::new(),
            is_ori: Vec::new(),
            is_xori: Vec::new(),
            is_slti: Vec::new(),
            is_sltiu: Vec::new(),
            is_slli: Vec::new(),
            is_srli: Vec::new(),
            is_srai: Vec::new(),
            is_lui: Vec::new(),
            is_auipc: Vec::new(),
            is_beq: Vec::new(),
            is_bne: Vec::new(),
            is_blt: Vec::new(),
            is_bge: Vec::new(),
            is_bltu: Vec::new(),
            is_bgeu: Vec::new(),
            is_jal: Vec::new(),
            is_jalr: Vec::new(),
            is_mul: Vec::new(),
            is_mulh: Vec::new(),
            is_mulhsu: Vec::new(),
            is_mulhu: Vec::new(),
            is_div: Vec::new(),
            is_divu: Vec::new(),
            is_rem: Vec::new(),
            is_remu: Vec::new(),
            is_lb: Vec::new(),
            is_lbu: Vec::new(),
            is_lh: Vec::new(),
            is_lhu: Vec::new(),
            is_lw: Vec::new(),
            is_sb: Vec::new(),
            is_sh: Vec::new(),
            is_sw: Vec::new(),
            mem_addr_lo: Vec::new(),
            mem_addr_hi: Vec::new(),
            mem_val_lo: Vec::new(),
            mem_val_hi: Vec::new(),
            sb_carry: Vec::new(),
            mul_lo: Vec::new(),
            mul_hi: Vec::new(),
            carry: Vec::new(),
            borrow: Vec::new(),
            quotient_lo: Vec::new(),
            quotient_hi: Vec::new(),
            remainder_lo: Vec::new(),
            remainder_hi: Vec::new(),
            lt_result: Vec::new(),
            eq_result: Vec::new(),
            branch_taken: Vec::new(),

            // Initialize bit arrays (32 empty vectors for each)
            rs1_bits: std::array::from_fn(|_| Vec::new()),
            rs2_bits: std::array::from_fn(|_| Vec::new()),
            imm_bits: std::array::from_fn(|_| Vec::new()),
            and_bits: std::array::from_fn(|_| Vec::new()),
            xor_bits: std::array::from_fn(|_| Vec::new()),
            or_bits: std::array::from_fn(|_| Vec::new()),

            // Initialize byte arrays (4 bytes per 32-bit value)
            rs1_bytes: std::array::from_fn(|_| Vec::new()),
            rs2_bytes: std::array::from_fn(|_| Vec::new()),
            and_result_bytes: std::array::from_fn(|_| Vec::new()),
            or_result_bytes: std::array::from_fn(|_| Vec::new()),
            xor_result_bytes: std::array::from_fn(|_| Vec::new()),
        }
    }

    /// Build trace columns from an execution trace.
    pub fn from_execution_trace(trace: &ExecutionTrace) -> Self {
        let mut cols = Self::new();

        for row in &trace.rows {
            // Clock and PC
            cols.clk.push(M31::from_u64(row.clk));
            cols.pc.push(M31::new(row.pc & 0x7FFFFFFF)); // Truncate to M31 range
            cols.next_pc.push(M31::new(row.next_pc & 0x7FFFFFFF));

            // Instruction
            cols.instr.push(M31::new(row.instr.bits & 0x7FFFFFFF));
            cols.opcode.push(M31::new(row.instr.opcode as u32));
            cols.rd.push(M31::new(row.instr.rd as u32));
            cols.rs1.push(M31::new(row.instr.rs1 as u32));
            cols.rs2.push(M31::new(row.instr.rs2 as u32));

            // Immediate (16-bit limbs)
            let imm = row.instr.imm as u32;
            cols.imm_lo.push(M31::new(imm & 0xFFFF));
            cols.imm_hi.push(M31::new((imm >> 16) & 0xFFFF));

            // Register values (16-bit limbs)
            let rs1_val = row.regs[row.instr.rs1 as usize];
            let rs2_val = row.regs[row.instr.rs2 as usize];
            cols.rs1_val_lo.push(M31::new(rs1_val & 0xFFFF));
            cols.rs1_val_hi.push(M31::new((rs1_val >> 16) & 0xFFFF));
            cols.rs2_val_lo.push(M31::new(rs2_val & 0xFFFF));
            cols.rs2_val_hi.push(M31::new((rs2_val >> 16) & 0xFFFF));
            cols.rd_val_lo.push(M31::new(row.rd_val & 0xFFFF));
            cols.rd_val_hi.push(M31::new((row.rd_val >> 16) & 0xFFFF));

            // Decode instruction for specific selectors
            let opcode = row.instr.opcode;
            let funct3 = (row.instr.bits >> 12) & 0x7;
            let funct7 = (row.instr.bits >> 25) & 0x7F;

            let mut is_add = 0;
            let mut is_sub = 0;
            let mut is_and = 0;
            let mut is_or = 0;
            let mut is_xor = 0;
            let mut is_sll = 0;
            let mut is_srl = 0;
            let mut is_sra = 0;
            let mut is_slt = 0;
            let mut is_sltu = 0;
            let mut is_addi = 0;
            let mut is_andi = 0;
            let mut is_ori = 0;
            let mut is_xori = 0;
            let mut is_slti = 0;
            let mut is_sltiu = 0;
            let mut is_slli = 0;
            let mut is_srli = 0;
            let mut is_srai = 0;
            let mut is_lui = 0;
            let mut is_auipc = 0;
            let mut is_beq = 0;
            let mut is_bne = 0;
            let mut is_blt = 0;
            let mut is_bge = 0;
            let mut is_bltu = 0;
            let mut is_bgeu = 0;
            let mut is_jal = 0;
            let mut is_jalr = 0;
            let mut is_mul = 0;
            let mut is_mulh = 0;
            let mut is_mulhsu = 0;
            let mut is_mulhu = 0;
            let mut is_div = 0;
            let mut is_divu = 0;
            let mut is_rem = 0;
            let mut is_remu = 0;

            match opcode {
                0x33 => {
                    // R-Type
                    match (funct3, funct7) {
                        (0x0, 0x00) => is_add = 1,
                        (0x0, 0x20) => is_sub = 1,
                        (0x1, 0x00) => is_sll = 1,
                        (0x2, 0x00) => is_slt = 1,
                        (0x3, 0x00) => is_sltu = 1,
                        (0x4, 0x00) => is_xor = 1,
                        (0x5, 0x00) => is_srl = 1,
                        (0x5, 0x20) => is_sra = 1,
                        (0x6, 0x00) => is_or = 1,
                        (0x7, 0x00) => is_and = 1,
                        (0x0, 0x01) => is_mul = 1,
                        (0x1, 0x01) => is_mulh = 1,
                        (0x2, 0x01) => is_mulhsu = 1,
                        (0x3, 0x01) => is_mulhu = 1,
                        (0x4, 0x01) => is_div = 1,
                        (0x5, 0x01) => is_divu = 1,
                        (0x6, 0x01) => is_rem = 1,
                        (0x7, 0x01) => is_remu = 1,
                        _ => {}
                    }
                }
                0x13 => {
                    // I-Type
                    match funct3 {
                        0x0 => is_addi = 1,
                        0x1 => is_slli = 1,
                        0x2 => is_slti = 1,
                        0x3 => is_sltiu = 1,
                        0x4 => is_xori = 1,
                        0x5 => {
                            if funct7 == 0x00 {
                                is_srli = 1
                            } else if funct7 == 0x20 {
                                is_srai = 1
                            }
                        }
                        0x6 => is_ori = 1,
                        0x7 => is_andi = 1,
                        _ => {}
                    }
                }
                0x63 => {
                    // Branch
                    match funct3 {
                        0x0 => is_beq = 1,
                        0x1 => is_bne = 1,
                        0x4 => is_blt = 1,
                        0x5 => is_bge = 1,
                        0x6 => is_bltu = 1,
                        0x7 => is_bgeu = 1,
                        _ => {}
                    }
                }
                0x37 => is_lui = 1,
                0x17 => is_auipc = 1,
                0x6F => is_jal = 1,
                0x67 => is_jalr = 1,
                _ => {} // Loads and Stores handled in mem_op section
            }

            cols.is_add.push(M31::new(is_add));
            cols.is_sub.push(M31::new(is_sub));
            cols.is_and.push(M31::new(is_and));
            cols.is_or.push(M31::new(is_or));
            cols.is_xor.push(M31::new(is_xor));
            cols.is_sll.push(M31::new(is_sll));
            cols.is_srl.push(M31::new(is_srl));
            cols.is_sra.push(M31::new(is_sra));
            cols.is_slt.push(M31::new(is_slt));
            cols.is_sltu.push(M31::new(is_sltu));
            cols.is_addi.push(M31::new(is_addi));
            cols.is_andi.push(M31::new(is_andi));
            cols.is_ori.push(M31::new(is_ori));
            cols.is_xori.push(M31::new(is_xori));
            cols.is_slti.push(M31::new(is_slti));
            cols.is_sltiu.push(M31::new(is_sltiu));
            cols.is_slli.push(M31::new(is_slli));
            cols.is_srli.push(M31::new(is_srli));
            cols.is_srai.push(M31::new(is_srai));
            cols.is_lui.push(M31::new(is_lui));
            cols.is_auipc.push(M31::new(is_auipc));
            cols.is_beq.push(M31::new(is_beq));
            cols.is_bne.push(M31::new(is_bne));
            cols.is_blt.push(M31::new(is_blt));
            cols.is_bge.push(M31::new(is_bge));
            cols.is_bltu.push(M31::new(is_bltu));
            cols.is_bgeu.push(M31::new(is_bgeu));
            cols.is_jal.push(M31::new(is_jal));
            cols.is_jalr.push(M31::new(is_jalr));
            cols.is_mul.push(M31::new(is_mul));
            cols.is_mulh.push(M31::new(is_mulh));
            cols.is_mulhsu.push(M31::new(is_mulhsu));
            cols.is_mulhu.push(M31::new(is_mulhu));
            cols.is_div.push(M31::new(is_div));
            cols.is_divu.push(M31::new(is_divu));
            cols.is_rem.push(M31::new(is_rem));
            cols.is_remu.push(M31::new(is_remu));

            // Memory operation
            let (
                mem_addr,
                mem_val,
                is_lb,
                is_lbu,
                is_lh,
                is_lhu,
                is_lw,
                is_sb,
                is_sh,
                is_sw,
                sb_carry_val,
            ) = match row.mem_op {
                zp1_executor::trace::MemOp::None => (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                zp1_executor::trace::MemOp::LoadByte {
                    addr,
                    value,
                    signed,
                } => {
                    if signed {
                        (addr, value as u32, 1, 0, 0, 0, 0, 0, 0, 0, 0)
                    } else {
                        (addr, value as u32, 0, 1, 0, 0, 0, 0, 0, 0, 0)
                    }
                }
                zp1_executor::trace::MemOp::LoadHalf {
                    addr,
                    value,
                    signed,
                } => {
                    if signed {
                        (addr, value as u32, 0, 0, 1, 0, 0, 0, 0, 0, 0)
                    } else {
                        (addr, value as u32, 0, 0, 0, 1, 0, 0, 0, 0, 0)
                    }
                }
                zp1_executor::trace::MemOp::LoadWord { addr, value } => {
                    (addr, value, 0, 0, 0, 0, 1, 0, 0, 0, 0)
                }
                zp1_executor::trace::MemOp::StoreByte { addr, value } => {
                    // sb_carry = (rs2_val_lo - mem_val_lo) / 256
                    // rs2_val_lo is the lower 16 bits of rs2.
                    // mem_val_lo is the byte value (0..255).
                    // So sb_carry is effectively (rs2 & 0xFFFF) >> 8.
                    let rs2_val = row.regs[row.instr.rs2 as usize];
                    let carry = (rs2_val & 0xFFFF) >> 8;
                    (addr, value as u32, 0, 0, 0, 0, 0, 1, 0, 0, carry)
                }
                zp1_executor::trace::MemOp::StoreHalf { addr, value } => {
                    (addr, value as u32, 0, 0, 0, 0, 0, 0, 1, 0, 0)
                }
                zp1_executor::trace::MemOp::StoreWord { addr, value } => {
                    (addr, value, 0, 0, 0, 0, 0, 0, 0, 1, 0)
                }
                // Keccak256 is delegated to a separate circuit, so it doesn't appear in the main trace
                // The delegation link is recorded separately
                zp1_executor::trace::MemOp::Keccak256 { .. } => {
                    (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
                // ECRECOVER is also delegated to a separate circuit
                zp1_executor::trace::MemOp::Ecrecover { .. } => {
                    (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
                // SHA-256 is also delegated to a separate circuit
                zp1_executor::trace::MemOp::Sha256 { .. } => {
                    (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
                // RIPEMD-160 is also delegated to a separate circuit
                zp1_executor::trace::MemOp::Ripemd160 { .. } => {
                    (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
                zp1_executor::trace::MemOp::Modexp { .. } => {
                    (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
                zp1_executor::trace::MemOp::Blake2b { .. } => {
                    (0u32, 0u32, 0, 0, 0, 0, 0, 0, 0, 0, 0)
                }
            };
            cols.mem_addr_lo.push(M31::new(mem_addr & 0xFFFF));
            cols.mem_addr_hi.push(M31::new((mem_addr >> 16) & 0xFFFF));
            cols.mem_val_lo.push(M31::new(mem_val & 0xFFFF));
            cols.mem_val_hi.push(M31::new((mem_val >> 16) & 0xFFFF));

            cols.is_lb.push(M31::new(is_lb));
            cols.is_lbu.push(M31::new(is_lbu));
            cols.is_lh.push(M31::new(is_lh));
            cols.is_lhu.push(M31::new(is_lhu));
            cols.is_lw.push(M31::new(is_lw));
            cols.is_sb.push(M31::new(is_sb));
            cols.is_sh.push(M31::new(is_sh));
            cols.is_sw.push(M31::new(is_sw));
            cols.sb_carry.push(M31::new(sb_carry_val));

            // Multiply intermediates
            cols.mul_lo.push(M31::new(row.mul_lo & 0x7FFFFFFF));
            cols.mul_hi.push(M31::new(row.mul_hi & 0x7FFFFFFF));

            // Auxiliary witnesses
            let rs1_val = row.regs[row.instr.rs1 as usize];
            let rs2_val = row.regs[row.instr.rs2 as usize];

            // Carry (ADD)
            let carry = if is_add == 1 {
                let rs1_lo = rs1_val & 0xFFFF;
                let rs2_lo = rs2_val & 0xFFFF;
                if rs1_lo + rs2_lo > 0xFFFF {
                    1
                } else {
                    0
                }
            } else {
                0
            };
            cols.carry.push(M31::new(carry));

            // Borrow (SUB)
            let borrow = if is_sub == 1 {
                let rs1_lo = rs1_val & 0xFFFF;
                let rs2_lo = rs2_val & 0xFFFF;
                if rs1_lo < rs2_lo {
                    1
                } else {
                    0
                }
            } else {
                0
            };
            cols.borrow.push(M31::new(borrow));

            // Quotient/Remainder (DIV/REM)
            let (quot, rem) = if is_div == 1 || is_divu == 1 || is_rem == 1 || is_remu == 1 {
                // Simplified: assume signed division for DIV/REM, unsigned for DIVU/REMU
                // But for now, just use signed logic as placeholder or match instruction
                if rs2_val == 0 {
                    (0xFFFFFFFF, rs1_val)
                } else {
                    let q = (rs1_val as i32).wrapping_div(rs2_val as i32) as u32;
                    let r = (rs1_val as i32).wrapping_rem(rs2_val as i32) as u32;
                    (q, r)
                }
            } else {
                (0, 0)
            };
            cols.quotient_lo.push(M31::new(quot & 0xFFFF));
            cols.quotient_hi.push(M31::new((quot >> 16) & 0xFFFF));
            cols.remainder_lo.push(M31::new(rem & 0xFFFF));
            cols.remainder_hi.push(M31::new((rem >> 16) & 0xFFFF));

            // Comparison results
            let lt = if is_slt == 1 || is_sltu == 1 || is_slti == 1 || is_sltiu == 1 {
                row.rd_val
            } else if is_blt == 1 || is_bge == 1 || is_bltu == 1 || is_bgeu == 1 {
                match funct3 {
                    4 | 5 => {
                        if (rs1_val as i32) < (rs2_val as i32) {
                            1
                        } else {
                            0
                        }
                    }
                    6 | 7 => {
                        if rs1_val < rs2_val {
                            1
                        } else {
                            0
                        }
                    }
                    _ => 0,
                }
            } else {
                0
            };
            cols.lt_result.push(M31::new(lt));

            let eq = if is_beq == 1 || is_bne == 1 {
                if rs1_val == rs2_val {
                    1
                } else {
                    0
                }
            } else {
                0
            };
            cols.eq_result.push(M31::new(eq));

            let branch_taken = if is_beq == 1
                || is_bne == 1
                || is_blt == 1
                || is_bge == 1
                || is_bltu == 1
                || is_bgeu == 1
            {
                if row.next_pc != row.pc.wrapping_add(4) {
                    1
                } else {
                    0
                }
            } else {
                0
            };
            cols.branch_taken.push(M31::new(branch_taken));

            // Bitwise operation bit decomposition
            // INPUT decomposition (rs1, rs2, and immediate)
            let imm_val = row.instr.imm as u32;
            for i in 0..32 {
                cols.rs1_bits[i].push(M31::new((rs1_val >> i) & 1));
                cols.rs2_bits[i].push(M31::new((rs2_val >> i) & 1));
                cols.imm_bits[i].push(M31::new((imm_val >> i) & 1));
            }

            // OUTPUT decomposition (AND/XOR/OR results)
            let and_result = rs1_val & rs2_val;
            let xor_result = rs1_val ^ rs2_val;
            let or_result = rs1_val | rs2_val;
            for i in 0..32 {
                cols.and_bits[i].push(M31::new((and_result >> i) & 1));
                cols.xor_bits[i].push(M31::new((xor_result >> i) & 1));
                cols.or_bits[i].push(M31::new((or_result >> i) & 1));
            }

            // BYTE decomposition for 8-bit lookup table verification
            // Each 32-bit value is split into 4 bytes for efficient lookup
            for i in 0..4 {
                let shift = i * 8;
                cols.rs1_bytes[i].push(M31::new((rs1_val >> shift) & 0xFF));
                cols.rs2_bytes[i].push(M31::new((rs2_val >> shift) & 0xFF));
                cols.and_result_bytes[i].push(M31::new((and_result >> shift) & 0xFF));
                cols.or_result_bytes[i].push(M31::new((or_result >> shift) & 0xFF));
                cols.xor_result_bytes[i].push(M31::new((xor_result >> shift) & 0xFF));
            }
        }

        cols
    }

    /// Get the number of rows.
    pub fn len(&self) -> usize {
        self.clk.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.clk.is_empty()
    }

    /// Pad to a power of two length.
    pub fn pad_to_power_of_two(&mut self) {
        let len = self.len();
        if len == 0 {
            return;
        }
        let target = len.next_power_of_two();
        if target == len {
            return;
        }

        // Pad with copies of the last row (or zeros for most columns)
        let _pad_count = target - len;

        // For simplicity, pad with zeros (will need proper padding logic for constraints)
        self.clk.resize(target, M31::ZERO);
        self.pc.resize(target, M31::ZERO);
        self.next_pc.resize(target, M31::ZERO);
        self.instr.resize(target, M31::ZERO);
        self.opcode.resize(target, M31::ZERO);
        self.rd.resize(target, M31::ZERO);
        self.rs1.resize(target, M31::ZERO);
        self.rs2.resize(target, M31::ZERO);
        self.imm_lo.resize(target, M31::ZERO);
        self.imm_hi.resize(target, M31::ZERO);
        self.rd_val_lo.resize(target, M31::ZERO);
        self.rd_val_hi.resize(target, M31::ZERO);
        self.rs1_val_lo.resize(target, M31::ZERO);
        self.rs1_val_hi.resize(target, M31::ZERO);
        self.rs2_val_lo.resize(target, M31::ZERO);
        self.rs2_val_hi.resize(target, M31::ZERO);
        self.is_add.resize(target, M31::ZERO);
        self.is_sub.resize(target, M31::ZERO);
        self.is_and.resize(target, M31::ZERO);
        self.is_or.resize(target, M31::ZERO);
        self.is_xor.resize(target, M31::ZERO);
        self.is_sll.resize(target, M31::ZERO);
        self.is_srl.resize(target, M31::ZERO);
        self.is_sra.resize(target, M31::ZERO);
        self.is_slt.resize(target, M31::ZERO);
        self.is_sltu.resize(target, M31::ZERO);
        self.is_addi.resize(target, M31::ZERO);
        self.is_andi.resize(target, M31::ZERO);
        self.is_ori.resize(target, M31::ZERO);
        self.is_xori.resize(target, M31::ZERO);
        self.is_slti.resize(target, M31::ZERO);
        self.is_sltiu.resize(target, M31::ZERO);
        self.is_slli.resize(target, M31::ZERO);
        self.is_srli.resize(target, M31::ZERO);
        self.is_srai.resize(target, M31::ZERO);
        self.is_lui.resize(target, M31::ZERO);
        self.is_auipc.resize(target, M31::ZERO);
        self.is_beq.resize(target, M31::ZERO);
        self.is_bne.resize(target, M31::ZERO);
        self.is_blt.resize(target, M31::ZERO);
        self.is_bge.resize(target, M31::ZERO);
        self.is_bltu.resize(target, M31::ZERO);
        self.is_bgeu.resize(target, M31::ZERO);
        self.is_jal.resize(target, M31::ZERO);
        self.is_jalr.resize(target, M31::ZERO);
        self.is_mul.resize(target, M31::ZERO);
        self.is_mulh.resize(target, M31::ZERO);
        self.is_mulhsu.resize(target, M31::ZERO);
        self.is_mulhu.resize(target, M31::ZERO);
        self.is_div.resize(target, M31::ZERO);
        self.is_divu.resize(target, M31::ZERO);
        self.is_rem.resize(target, M31::ZERO);
        self.is_remu.resize(target, M31::ZERO);
        self.is_lb.resize(target, M31::ZERO);
        self.is_lbu.resize(target, M31::ZERO);
        self.is_lh.resize(target, M31::ZERO);
        self.is_lhu.resize(target, M31::ZERO);
        self.is_lw.resize(target, M31::ZERO);
        self.is_sb.resize(target, M31::ZERO);
        self.is_sh.resize(target, M31::ZERO);
        self.is_sw.resize(target, M31::ZERO);
        self.mem_addr_lo.resize(target, M31::ZERO);
        self.mem_addr_hi.resize(target, M31::ZERO);
        self.mem_val_lo.resize(target, M31::ZERO);
        self.mem_val_hi.resize(target, M31::ZERO);
        self.sb_carry.resize(target, M31::ZERO);
        self.mul_lo.resize(target, M31::ZERO);
        self.mul_hi.resize(target, M31::ZERO);
        self.carry.resize(target, M31::ZERO);
        self.borrow.resize(target, M31::ZERO);
        self.quotient_lo.resize(target, M31::ZERO);
        self.quotient_hi.resize(target, M31::ZERO);
        self.remainder_lo.resize(target, M31::ZERO);
        self.remainder_hi.resize(target, M31::ZERO);
        self.lt_result.resize(target, M31::ZERO);
        self.eq_result.resize(target, M31::ZERO);
        self.branch_taken.resize(target, M31::ZERO);

        // Pad bit arrays (32 bits each for rs1/rs2 inputs and AND/XOR/OR outputs)
        for i in 0..32 {
            self.rs1_bits[i].resize(target, M31::ZERO);
            self.rs2_bits[i].resize(target, M31::ZERO);
            self.imm_bits[i].resize(target, M31::ZERO);
            self.and_bits[i].resize(target, M31::ZERO);
            self.xor_bits[i].resize(target, M31::ZERO);
            self.or_bits[i].resize(target, M31::ZERO);
        }

        // Pad byte arrays (4 bytes each for lookup table integration)
        for i in 0..4 {
            self.rs1_bytes[i].resize(target, M31::ZERO);
            self.rs2_bytes[i].resize(target, M31::ZERO);
            self.and_result_bytes[i].resize(target, M31::ZERO);
            self.or_result_bytes[i].resize(target, M31::ZERO);
            self.xor_result_bytes[i].resize(target, M31::ZERO);
        }
    }

    /// Convert to a vector of columns for the prover.
    pub fn to_columns(&self) -> Vec<Vec<M31>> {
        vec![
            self.clk.clone(),
            self.pc.clone(),
            self.next_pc.clone(),
            self.instr.clone(),
            self.opcode.clone(),
            self.rd.clone(),
            self.rs1.clone(),
            self.rs2.clone(),
            self.imm_lo.clone(),
            self.imm_hi.clone(),
            self.rd_val_lo.clone(),
            self.rd_val_hi.clone(),
            self.rs1_val_lo.clone(),
            self.rs1_val_hi.clone(),
            self.rs2_val_lo.clone(),
            self.rs2_val_hi.clone(),
            self.is_add.clone(),
            self.is_sub.clone(),
            self.is_and.clone(),
            self.is_or.clone(),
            self.is_xor.clone(),
            self.is_sll.clone(),
            self.is_srl.clone(),
            self.is_sra.clone(),
            self.is_slt.clone(),
            self.is_sltu.clone(),
            self.is_addi.clone(),
            self.is_andi.clone(),
            self.is_ori.clone(),
            self.is_xori.clone(),
            self.is_slti.clone(),
            self.is_sltiu.clone(),
            self.is_slli.clone(),
            self.is_srli.clone(),
            self.is_srai.clone(),
            self.is_lui.clone(),
            self.is_auipc.clone(),
            self.is_beq.clone(),
            self.is_bne.clone(),
            self.is_blt.clone(),
            self.is_bge.clone(),
            self.is_bltu.clone(),
            self.is_bgeu.clone(),
            self.is_jal.clone(),
            self.is_jalr.clone(),
            self.is_mul.clone(),
            self.is_mulh.clone(),
            self.is_mulhsu.clone(),
            self.is_mulhu.clone(),
            self.is_div.clone(),
            self.is_divu.clone(),
            self.is_rem.clone(),
            self.is_remu.clone(),
            self.is_lb.clone(),
            self.is_lbu.clone(),
            self.is_lh.clone(),
            self.is_lhu.clone(),
            self.is_lw.clone(),
            self.is_sb.clone(),
            self.is_sh.clone(),
            self.is_sw.clone(),
            self.mem_addr_lo.clone(),
            self.mem_addr_hi.clone(),
            self.mem_val_lo.clone(),
            self.mem_val_hi.clone(),
            self.sb_carry.clone(),
            self.mul_lo.clone(),
            self.mul_hi.clone(),
            self.carry.clone(),
            self.borrow.clone(),
            self.quotient_lo.clone(),
            self.quotient_hi.clone(),
            self.remainder_lo.clone(),
            self.remainder_hi.clone(),
            self.lt_result.clone(),
            self.eq_result.clone(),
            self.branch_taken.clone(),
        ]
        .into_iter()
        // Add bitwise bit decompositions (192 columns: 96 input + 96 output)
        .chain(self.rs1_bits.iter().map(|v| v.clone()))
        .chain(self.rs2_bits.iter().map(|v| v.clone()))
        .chain(self.imm_bits.iter().map(|v| v.clone()))
        .chain(self.and_bits.iter().map(|v| v.clone()))
        .chain(self.xor_bits.iter().map(|v| v.clone()))
        .chain(self.or_bits.iter().map(|v| v.clone()))
        // Add byte decompositions for lookup table integration (20 columns: 8 input + 12 output)
        .chain(self.rs1_bytes.iter().map(|v| v.clone()))
        .chain(self.rs2_bytes.iter().map(|v| v.clone()))
        .chain(self.and_result_bytes.iter().map(|v| v.clone()))
        .chain(self.or_result_bytes.iter().map(|v| v.clone()))
        .chain(self.xor_result_bytes.iter().map(|v| v.clone()))
        .collect()
    }

    // =========================================================================
    // MEMORY-EFFICIENT ACCESS METHODS
    // These methods avoid cloning data, reducing memory usage by ~50%
    // =========================================================================

    /// Convert to columns by taking ownership (no cloning).
    ///
    /// This is 2x more memory-efficient than `to_columns()` because it
    /// moves the data instead of cloning it. Use this when you don't need
    /// to keep the TraceColumns after conversion.
    ///
    /// # Example
    /// ```ignore
    /// let columns = trace.into_columns(); // trace is consumed
    /// ```
    pub fn into_columns(self) -> Vec<Vec<M31>> {
        let mut result = Vec::with_capacity(NUM_CPU_COLUMNS);

        // Core columns (moved, not cloned)
        result.push(self.clk);
        result.push(self.pc);
        result.push(self.next_pc);
        result.push(self.instr);
        result.push(self.opcode);
        result.push(self.rd);
        result.push(self.rs1);
        result.push(self.rs2);
        result.push(self.imm_lo);
        result.push(self.imm_hi);
        result.push(self.rd_val_lo);
        result.push(self.rd_val_hi);
        result.push(self.rs1_val_lo);
        result.push(self.rs1_val_hi);
        result.push(self.rs2_val_lo);
        result.push(self.rs2_val_hi);
        result.push(self.is_add);
        result.push(self.is_sub);
        result.push(self.is_and);
        result.push(self.is_or);
        result.push(self.is_xor);
        result.push(self.is_sll);
        result.push(self.is_srl);
        result.push(self.is_sra);
        result.push(self.is_slt);
        result.push(self.is_sltu);
        result.push(self.is_addi);
        result.push(self.is_andi);
        result.push(self.is_ori);
        result.push(self.is_xori);
        result.push(self.is_slti);
        result.push(self.is_sltiu);
        result.push(self.is_slli);
        result.push(self.is_srli);
        result.push(self.is_srai);
        result.push(self.is_lui);
        result.push(self.is_auipc);
        result.push(self.is_beq);
        result.push(self.is_bne);
        result.push(self.is_blt);
        result.push(self.is_bge);
        result.push(self.is_bltu);
        result.push(self.is_bgeu);
        result.push(self.is_jal);
        result.push(self.is_jalr);
        result.push(self.is_mul);
        result.push(self.is_mulh);
        result.push(self.is_mulhsu);
        result.push(self.is_mulhu);
        result.push(self.is_div);
        result.push(self.is_divu);
        result.push(self.is_rem);
        result.push(self.is_remu);
        result.push(self.is_lb);
        result.push(self.is_lbu);
        result.push(self.is_lh);
        result.push(self.is_lhu);
        result.push(self.is_lw);
        result.push(self.is_sb);
        result.push(self.is_sh);
        result.push(self.is_sw);
        result.push(self.mem_addr_lo);
        result.push(self.mem_addr_hi);
        result.push(self.mem_val_lo);
        result.push(self.mem_val_hi);
        result.push(self.sb_carry);
        result.push(self.mul_lo);
        result.push(self.mul_hi);
        result.push(self.carry);
        result.push(self.borrow);
        result.push(self.quotient_lo);
        result.push(self.quotient_hi);
        result.push(self.remainder_lo);
        result.push(self.remainder_hi);
        result.push(self.lt_result);
        result.push(self.eq_result);
        result.push(self.branch_taken);

        // Bit columns
        for col in self.rs1_bits {
            result.push(col);
        }
        for col in self.rs2_bits {
            result.push(col);
        }
        for col in self.imm_bits {
            result.push(col);
        }
        for col in self.and_bits {
            result.push(col);
        }
        for col in self.xor_bits {
            result.push(col);
        }
        for col in self.or_bits {
            result.push(col);
        }

        // Byte columns
        for col in self.rs1_bytes {
            result.push(col);
        }
        for col in self.rs2_bytes {
            result.push(col);
        }
        for col in self.and_result_bytes {
            result.push(col);
        }
        for col in self.or_result_bytes {
            result.push(col);
        }
        for col in self.xor_result_bytes {
            result.push(col);
        }

        result
    }

    /// Estimate memory usage in bytes.
    ///
    /// Useful for monitoring and deciding when to use streaming.
    pub fn memory_usage(&self) -> usize {
        let rows = self.len();
        let m31_size = std::mem::size_of::<M31>();

        // Count all columns
        let base_cols = 77; // Base trace columns
        let bit_cols = 32 * 6; // 6 bit arrays × 32 bits
        let byte_cols = 4 * 5; // 5 byte arrays × 4 bytes
        let total_cols = base_cols + bit_cols + byte_cols;

        rows * m31_size * total_cols
    }

    /// Estimate memory usage in MB.
    pub fn memory_usage_mb(&self) -> f64 {
        self.memory_usage() as f64 / (1024.0 * 1024.0)
    }

    /// Check if trace fits in available memory with given margin.
    ///
    /// Returns true if estimated memory usage is less than (available_mb - margin_mb).
    pub fn fits_in_memory(&self, available_mb: f64, margin_mb: f64) -> bool {
        self.memory_usage_mb() < (available_mb - margin_mb)
    }

    /// Get the number of rows that would fit in given memory budget.
    ///
    /// Useful for chunking large traces.
    pub fn rows_for_memory_budget(memory_mb: f64) -> usize {
        let m31_size = std::mem::size_of::<M31>();
        let total_cols = 77 + 32 * 6 + 4 * 5; // 269 columns
        let bytes_per_row = m31_size * total_cols;

        let memory_bytes = (memory_mb * 1024.0 * 1024.0) as usize;
        memory_bytes / bytes_per_row
    }
}

impl Default for TraceColumns {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// STREAMING TRACE BUILDER
// For processing large traces that don't fit in memory
// ============================================================================

/// Configuration for streaming trace processing.
#[derive(Clone, Debug)]
pub struct StreamingConfig {
    /// Maximum rows to process at once
    pub chunk_size: usize,
    /// Memory budget in MB
    pub memory_budget_mb: f64,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            chunk_size: TraceColumns::rows_for_memory_budget(1024.0), // 1GB default
            memory_budget_mb: 1024.0,
        }
    }
}

impl StreamingConfig {
    /// Create config for specific memory budget.
    pub fn with_memory_mb(memory_mb: f64) -> Self {
        Self {
            chunk_size: TraceColumns::rows_for_memory_budget(memory_mb),
            memory_budget_mb: memory_mb,
        }
    }

    /// Create config for M4 Mac with 24GB RAM (leaves 8GB for system).
    pub fn for_m4_mac() -> Self {
        Self::with_memory_mb(16.0 * 1024.0) // 16GB for prover
    }
}
