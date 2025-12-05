//! Trace column definitions and builder.

use zp1_primitives::M31;
use zp1_executor::ExecutionTrace;

/// Number of columns in the CPU trace.
pub const NUM_CPU_COLUMNS: usize = 64;

/// Trace columns for the CPU AIR.
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
    pub is_alu: Vec<M31>,
    pub is_alu_imm: Vec<M31>,
    pub is_load: Vec<M31>,
    pub is_store: Vec<M31>,
    pub is_branch: Vec<M31>,
    pub is_jal: Vec<M31>,
    pub is_jalr: Vec<M31>,
    pub is_lui: Vec<M31>,
    pub is_auipc: Vec<M31>,
    pub is_mul: Vec<M31>,
    pub is_div: Vec<M31>,
    pub is_rem: Vec<M31>,
    /// Memory address (if load/store).
    pub mem_addr_lo: Vec<M31>,
    pub mem_addr_hi: Vec<M31>,
    /// Memory value (if load/store).
    pub mem_val_lo: Vec<M31>,
    pub mem_val_hi: Vec<M31>,
    /// Multiply intermediate (64-bit product).
    pub mul_lo: Vec<M31>,
    pub mul_hi: Vec<M31>,
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
            is_alu: Vec::new(),
            is_alu_imm: Vec::new(),
            is_load: Vec::new(),
            is_store: Vec::new(),
            is_branch: Vec::new(),
            is_jal: Vec::new(),
            is_jalr: Vec::new(),
            is_lui: Vec::new(),
            is_auipc: Vec::new(),
            is_mul: Vec::new(),
            is_div: Vec::new(),
            is_rem: Vec::new(),
            mem_addr_lo: Vec::new(),
            mem_addr_hi: Vec::new(),
            mem_val_lo: Vec::new(),
            mem_val_hi: Vec::new(),
            mul_lo: Vec::new(),
            mul_hi: Vec::new(),
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

            // Flags
            let f = &row.flags;
            cols.is_alu.push(M31::new(f.is_alu as u32));
            cols.is_alu_imm.push(M31::new(f.is_alu_imm as u32));
            cols.is_load.push(M31::new(f.is_load as u32));
            cols.is_store.push(M31::new(f.is_store as u32));
            cols.is_branch.push(M31::new(f.is_branch as u32));
            cols.is_jal.push(M31::new(f.is_jal as u32));
            cols.is_jalr.push(M31::new(f.is_jalr as u32));
            cols.is_lui.push(M31::new(f.is_lui as u32));
            cols.is_auipc.push(M31::new(f.is_auipc as u32));
            cols.is_mul.push(M31::new(f.is_mul as u32));
            cols.is_div.push(M31::new(f.is_div as u32));
            cols.is_rem.push(M31::new(f.is_rem as u32));

            // Memory operation
            let (mem_addr, mem_val) = match row.mem_op {
                zp1_executor::trace::MemOp::None => (0u32, 0u32),
                zp1_executor::trace::MemOp::LoadByte { addr, value, .. } => (addr, value as u32),
                zp1_executor::trace::MemOp::LoadHalf { addr, value, .. } => (addr, value as u32),
                zp1_executor::trace::MemOp::LoadWord { addr, value } => (addr, value),
                zp1_executor::trace::MemOp::StoreByte { addr, value } => (addr, value as u32),
                zp1_executor::trace::MemOp::StoreHalf { addr, value } => (addr, value as u32),
                zp1_executor::trace::MemOp::StoreWord { addr, value } => (addr, value),
            };
            cols.mem_addr_lo.push(M31::new(mem_addr & 0xFFFF));
            cols.mem_addr_hi.push(M31::new((mem_addr >> 16) & 0xFFFF));
            cols.mem_val_lo.push(M31::new(mem_val & 0xFFFF));
            cols.mem_val_hi.push(M31::new((mem_val >> 16) & 0xFFFF));

            // Multiply intermediates
            cols.mul_lo.push(M31::new(row.mul_lo & 0x7FFFFFFF));
            cols.mul_hi.push(M31::new(row.mul_hi & 0x7FFFFFFF));
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
        let pad_count = target - len;

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
        self.is_alu.resize(target, M31::ZERO);
        self.is_alu_imm.resize(target, M31::ZERO);
        self.is_load.resize(target, M31::ZERO);
        self.is_store.resize(target, M31::ZERO);
        self.is_branch.resize(target, M31::ZERO);
        self.is_jal.resize(target, M31::ZERO);
        self.is_jalr.resize(target, M31::ZERO);
        self.is_lui.resize(target, M31::ZERO);
        self.is_auipc.resize(target, M31::ZERO);
        self.is_mul.resize(target, M31::ZERO);
        self.is_div.resize(target, M31::ZERO);
        self.is_rem.resize(target, M31::ZERO);
        self.mem_addr_lo.resize(target, M31::ZERO);
        self.mem_addr_hi.resize(target, M31::ZERO);
        self.mem_val_lo.resize(target, M31::ZERO);
        self.mem_val_hi.resize(target, M31::ZERO);
        self.mul_lo.resize(target, M31::ZERO);
        self.mul_hi.resize(target, M31::ZERO);
    }
}

impl Default for TraceColumns {
    fn default() -> Self {
        Self::new()
    }
}
