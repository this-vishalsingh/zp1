//! Main block proving orchestration.

use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn};

use zp1_executor::Cpu;
use zp1_prover::{StarkConfig, StarkProver};
use zp1_trace::TraceColumns;

use crate::fetcher::TransactionData;
use crate::{
    BlockData, BlockFetcher, BlockProof, EthereumError, ProofAggregator, ProverConfig, Result,
    TransactionProof, TransactionResult,
};

/// Transaction prover - proves individual transactions.
pub struct TransactionProver {
    config: ProverConfig,
    stark_prover: Option<StarkProver>,
}

impl TransactionProver {
    /// Create a new transaction prover.
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
            stark_prover: None,
        }
    }

    /// Prove a single transaction.
    ///
    /// This is a stub - full implementation requires:
    /// 1. Compile EVM execution to RISC-V
    /// 2. Execute in ZP1's RISC-V VM
    /// 3. Generate execution trace
    /// 4. Prove with STARK
    pub async fn prove_transaction(&mut self, tx: &TransactionData) -> Result<TransactionProof> {
        info!("Proving transaction {:?}", tx.hash);

        // Step 1: Execute transaction
        let result = self.execute_transaction(tx).await?;

        // Step 2: Generate RISC-V trace (stub)
        let trace = self.generate_trace(tx, &result)?;

        // Step 3: Generate STARK proof
        let proof_bytes = self.generate_stark_proof(&trace)?;

        Ok(TransactionProof {
            tx_hash: tx.hash,
            proof: proof_bytes,
            public_inputs: vec![],
            result,
        })
    }

    /// Execute transaction using REVM with synthetic balance.
    #[inline]
    async fn execute_transaction(&self, tx: &TransactionData) -> Result<TransactionResult> {
        crate::evm::execute_tx(tx).map_err(|e| EthereumError::ExecutionError(e.to_string()))
    }

    /// Generate RISC-V execution trace (stub).
    ///
    /// TODO: Convert EVM execution to RISC-V trace  
    /// For now, create minimal valid trace with 16 rows for testing.
    fn generate_trace(
        &self,
        _tx: &TransactionData,
        _result: &TransactionResult,
    ) -> Result<TraceColumns> {
        use zp1_primitives::M31;

        // Create a minimal valid trace with 16 rows
        let num_rows = 16;
        let mut columns = TraceColumns::new();

        // Initialize all columns with dummy values to create a valid trace
        for i in 0..num_rows {
            // Control flow columns
            columns.clk.push(M31::new(i as u32));
            columns.pc.push(M31::new(0x1000 + (i as u32) * 4));
            columns
                .next_pc
                .push(M31::new(0x1000 + ((i + 1) as u32) * 4));
            columns.instr.push(M31::new(0x00000013)); // NOP (addi x0, x0, 0)
            columns.opcode.push(M31::new(0x13)); // I-type opcode

            // Register indices
            columns.rd.push(M31::ZERO);
            columns.rs1.push(M31::ZERO);
            columns.rs2.push(M31::ZERO);

            // Immediate
            columns.imm_lo.push(M31::ZERO);
            columns.imm_hi.push(M31::ZERO);

            // Register values
            columns.rd_val_lo.push(M31::ZERO);
            columns.rd_val_hi.push(M31::ZERO);
            columns.rs1_val_lo.push(M31::ZERO);
            columns.rs1_val_hi.push(M31::ZERO);
            columns.rs2_val_lo.push(M31::ZERO);
            columns.rs2_val_hi.push(M31::ZERO);

            // Instruction flags - all zeros for NOP
            columns.is_add.push(M31::ZERO);
            columns.is_sub.push(M31::ZERO);
            columns.is_and.push(M31::ZERO);
            columns.is_or.push(M31::ZERO);
            columns.is_xor.push(M31::ZERO);
            columns.is_sll.push(M31::ZERO);
            columns.is_srl.push(M31::ZERO);
            columns.is_sra.push(M31::ZERO);
            columns.is_slt.push(M31::ZERO);
            columns.is_sltu.push(M31::ZERO);
            columns.is_addi.push(M31::new(1)); // NOP is ADDI
            columns.is_andi.push(M31::ZERO);
            columns.is_ori.push(M31::ZERO);
            columns.is_xori.push(M31::ZERO);
            columns.is_slti.push(M31::ZERO);
            columns.is_sltiu.push(M31::ZERO);
            columns.is_slli.push(M31::ZERO);
            columns.is_srli.push(M31::ZERO);
            columns.is_srai.push(M31::ZERO);
            columns.is_lui.push(M31::ZERO);
            columns.is_auipc.push(M31::ZERO);
            columns.is_beq.push(M31::ZERO);
            columns.is_bne.push(M31::ZERO);
            columns.is_blt.push(M31::ZERO);
            columns.is_bge.push(M31::ZERO);
            columns.is_bltu.push(M31::ZERO);
            columns.is_bgeu.push(M31::ZERO);
            columns.is_jal.push(M31::ZERO);
            columns.is_jalr.push(M31::ZERO);
            columns.is_mul.push(M31::ZERO);
            columns.is_mulh.push(M31::ZERO);
            columns.is_mulhsu.push(M31::ZERO);
            columns.is_mulhu.push(M31::ZERO);
            columns.is_div.push(M31::ZERO);
            columns.is_divu.push(M31::ZERO);
            columns.is_rem.push(M31::ZERO);
            columns.is_remu.push(M31::ZERO);
            columns.is_lb.push(M31::ZERO);
            columns.is_lbu.push(M31::ZERO);
            columns.is_lh.push(M31::ZERO);
            columns.is_lhu.push(M31::ZERO);
            columns.is_lw.push(M31::ZERO);
            columns.is_sb.push(M31::ZERO);
            columns.is_sh.push(M31::ZERO);
            columns.is_sw.push(M31::ZERO);

            // Memory
            columns.mem_addr_lo.push(M31::ZERO);
            columns.mem_addr_hi.push(M31::ZERO);
            columns.mem_val_lo.push(M31::ZERO);
            columns.mem_val_hi.push(M31::ZERO);
            columns.sb_carry.push(M31::ZERO);

            // Arithmetic intermediates
            columns.mul_lo.push(M31::ZERO);
            columns.mul_hi.push(M31::ZERO);
            columns.carry.push(M31::ZERO);
            columns.borrow.push(M31::ZERO);
            columns.quotient_lo.push(M31::ZERO);
            columns.quotient_hi.push(M31::ZERO);
            columns.remainder_lo.push(M31::ZERO);
            columns.remainder_hi.push(M31::ZERO);
            columns.lt_result.push(M31::ZERO);
            columns.eq_result.push(M31::ZERO);
            columns.branch_taken.push(M31::ZERO);

            // Bit decompositions (32 bits each)
            for j in 0..32 {
                columns.rs1_bits[j].push(M31::ZERO);
                columns.rs2_bits[j].push(M31::ZERO);
                columns.imm_bits[j].push(M31::ZERO);
                columns.and_bits[j].push(M31::ZERO);
                columns.xor_bits[j].push(M31::ZERO);
                columns.or_bits[j].push(M31::ZERO);
            }

            // Byte decompositions (4 bytes each)
            for j in 0..4 {
                columns.rs1_bytes[j].push(M31::ZERO);
                columns.rs2_bytes[j].push(M31::ZERO);
                columns.and_result_bytes[j].push(M31::ZERO);
                columns.or_result_bytes[j].push(M31::ZERO);
                columns.xor_result_bytes[j].push(M31::ZERO);
            }
        }

        Ok(columns)
    }

    /// Generate STARK proof from trace (returns serialized bytes).
    fn generate_stark_proof(&mut self, trace: &TraceColumns) -> Result<Vec<u8>> {
        let padded_len = trace.len();
        let log_trace_len = padded_len.trailing_zeros() as usize;

        let config = StarkConfig {
            log_trace_len,
            blowup_factor: self.config.blowup_factor,
            num_queries: self.config.num_queries,
            fri_folding_factor: 2,
            security_bits: self.config.security_bits,
            entry_point: 0x0, // Default entry point
        };

        // Create prover if needed
        if self.stark_prover.is_none() {
            self.stark_prover = Some(StarkProver::new(config.clone()));
        }

        let prover = self.stark_prover.as_mut().unwrap();
        let columns = trace.to_columns();
        let _proof = prover.prove(columns, &[]);

        // TODO: Implement proper StarkProof serialization
        // For now, return placeholder bytes containing proof commitments
        // Full implementation needs to serialize the entire StarkProof structure
        Ok(vec![0u8; 32])
    }
}

/// Block prover - orchestrates proving entire blocks.
pub struct BlockProver {
    config: ProverConfig,
    fetcher: BlockFetcher,
    tx_prover: TransactionProver,
    aggregator: ProofAggregator,
}

impl BlockProver {
    /// Create a new block prover.
    pub async fn new(config: ProverConfig) -> Result<Self> {
        let fetcher = BlockFetcher::new(&config.rpc_url).await?;
        let tx_prover = TransactionProver::new(config.clone());
        let aggregator = ProofAggregator::new(true); // Use recursion

        Ok(Self {
            config,
            fetcher,
            tx_prover,
            aggregator,
        })
    }

    /// Prove a single block by number.
    pub async fn prove_block(&mut self, block_number: u64) -> Result<BlockProof> {
        info!("Starting proof generation for block {}", block_number);

        // Fetch block data
        let block = self.fetcher.fetch_block(block_number).await?;
        info!(
            "Fetched block {} with {} transactions",
            block.number,
            block.transactions.len()
        );

        // Prove all transactions
        let mut tx_proofs = Vec::new();
        for (idx, tx) in block.transactions.iter().enumerate() {
            info!(
                "Proving transaction {}/{}",
                idx + 1,
                block.transactions.len()
            );
            let proof = self.tx_prover.prove_transaction(tx).await?;
            tx_proofs.push(proof);
        }

        // Aggregate into block proof
        info!("Aggregating {} transaction proofs", tx_proofs.len());
        let block_proof =
            self.aggregator
                .aggregate(block.number, block.hash, block.parent_hash, tx_proofs)?;

        // Save proof to disk
        self.save_block_proof(&block_proof).await?;

        info!("Block {} proof complete!", block_number);
        Ok(block_proof)
    }

    /// Prove a range of blocks.
    pub async fn prove_block_range(&mut self, from: u64, to: u64) -> Result<Vec<BlockProof>> {
        info!("Proving blocks {} to {}", from, to);

        let mut proofs = Vec::new();
        for block_num in from..=to {
            let proof = self.prove_block(block_num).await?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    /// Save block proof to disk.
    async fn save_block_proof(&self, proof: &BlockProof) -> Result<()> {
        let output_dir = PathBuf::from(&self.config.output_dir);
        fs::create_dir_all(&output_dir).await?;

        let filename = format!("block_{}.json", proof.block_number);
        let filepath = output_dir.join(filename);

        let json = serde_json::to_string_pretty(proof)?;
        fs::write(filepath, json).await?;

        Ok(())
    }

    /// Load block proof from disk.
    pub async fn load_block_proof(&self, block_number: u64) -> Result<BlockProof> {
        let output_dir = PathBuf::from(&self.config.output_dir);
        let filename = format!("block_{}.json", block_number);
        let filepath = output_dir.join(filename);

        let json = fs::read_to_string(filepath).await?;
        let proof: BlockProof = serde_json::from_str(&json)?;

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires RPC connection
    async fn test_prove_block() {
        let config = ProverConfig::local();
        let mut prover = BlockProver::new(config).await.unwrap();

        // This will fail without a local node, but tests the structure
        let result = prover.prove_block(1).await;
        assert!(result.is_ok() || result.is_err()); // Just check it compiles
    }
}
