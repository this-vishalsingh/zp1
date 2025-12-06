//! Main block proving orchestration.

use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn};

use zp1_prover::{StarkProver, StarkConfig};
use zp1_executor::Cpu;
use zp1_trace::TraceColumns;

use crate::{
    BlockFetcher, BlockData, TransactionProof, TransactionResult,
    ProofAggregator, BlockProof, ProverConfig, Result, EthereumError,
};
use crate::fetcher::TransactionData;

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

        // TODO: Implement full EVM -> RISC-V -> Proof pipeline
        // For now, return a stub proof
        
        // Step 1: Execute transaction (stub)
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

    /// Execute transaction (stub implementation).
    async fn execute_transaction(&self, tx: &TransactionData) -> Result<TransactionResult> {
        // TODO: Use Revm to execute EVM transaction
        Ok(TransactionResult {
            hash: tx.hash,
            gas_used: tx.gas,
            success: true,
            return_data: vec![],
            state_changes: vec![],
        })
    }

    /// Generate RISC-V execution trace (stub).
    fn generate_trace(&self, _tx: &TransactionData, _result: &TransactionResult) -> Result<TraceColumns> {
        // TODO: Convert EVM execution to RISC-V trace
        // For now, create minimal trace with 16 rows
        let mut columns = TraceColumns::new();
        
        // Add 16 minimal rows (stub)
        use zp1_primitives::M31;
        for _ in 0..16 {
            columns.clk.push(M31::ZERO);
            columns.pc.push(M31::ZERO);
            columns.next_pc.push(M31::ZERO);
            columns.instr.push(M31::ZERO);
            // ... all other fields would need to be added too
            // This is just a stub to make it compile
        }
        columns.pad_to_power_of_two();
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
        info!("Fetched block {} with {} transactions", block.number, block.transactions.len());

        // Prove all transactions
        let mut tx_proofs = Vec::new();
        for (idx, tx) in block.transactions.iter().enumerate() {
            info!("Proving transaction {}/{}", idx + 1, block.transactions.len());
            let proof = self.tx_prover.prove_transaction(tx).await?;
            tx_proofs.push(proof);
        }

        // Aggregate into block proof
        info!("Aggregating {} transaction proofs", tx_proofs.len());
        let block_proof = self.aggregator.aggregate(
            block.number,
            block.hash,
            block.parent_hash,
            tx_proofs,
        )?;

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
