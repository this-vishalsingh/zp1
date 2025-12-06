# Ethereum Block Proving with ZP1

**Goal:** Generate STARK proofs for Ethereum block execution using ZP1's RISC-V zkVM.

---

## Architecture Overview

```
Ethereum Block → Revm → RISC-V Binary → ZP1 Executor → STARK Proof → On-chain Verifier
```

### Components Needed

1. **Ethereum Block Fetcher** - Download block data from RPC
2. **Revm EVM Executor** - Execute EVM transactions in RISC-V
3. **Block Prover** - Orchestrate proving pipeline
4. **Proof Aggregation** - Combine proofs for full block
5. **Verifier Contract** - On-chain proof verification

---

## Implementation Plan

### Phase 1: Block Data Pipeline

**Goal:** Fetch and prepare Ethereum block data for proving

**Components:**
- Block fetcher (Ethers-rs)
- Transaction parser
- State trie integration
- Block witness generation

**Dependencies:**
```toml
ethers = "2.0"
revm = "3.5"
alloy-primitives = "0.7"
```

### Phase 2: EVM in RISC-V

**Goal:** Compile EVM execution to RISC-V for proving

**Approach:**
- Use `revm` as EVM execution engine
- Compile to RISC-V (riscv32im-unknown-none-elf)
- Generate execution trace for each transaction
- Prove each transaction separately

**Challenges:**
- Memory layout for EVM state
- Precompile delegation (SHA256, ECRECOVER, etc.)
- Storage proof verification in RISC-V

### Phase 3: Transaction Proving

**Goal:** Generate proofs for individual transactions

**Workflow:**
```rust
Transaction → Execute in Revm → Generate RISC-V trace → STARK Proof
```

**Per Transaction:**
1. Execute transaction in Revm
2. Generate execution trace (gas, state changes)
3. Create RISC-V binary that validates execution
4. Prove with ZP1
5. Store proof + metadata

### Phase 4: Block Aggregation

**Goal:** Aggregate transaction proofs into single block proof

**Techniques:**
- Sequential proof composition
- Merkle tree of transaction proofs
- Recursive STARK proving (already in codebase)
- Final SNARK for on-chain verification

### Phase 5: On-chain Verification

**Goal:** Deploy Solidity verifier for block proofs

**Components:**
- FRI verifier contract
- Merkle proof verifier
- Block header validator
- State root checker

---

## Current Status

✅ **Already Implemented:**
- RISC-V executor with full RV32IM
- STARK prover with FRI
- Recursive proving infrastructure
- SNARK wrapper (Groth16 mentioned in code)
- GPU acceleration framework

⏳ **Need to Implement:**
- Ethereum block fetching
- Revm integration
- Transaction batching
- Proof aggregation pipeline
- Verifier contracts

---

## Quick Start Implementation

Let me create the basic structure:

### 1. Add Ethereum Dependencies

```toml
[dependencies]
# Ethereum integration
ethers = { version = "2.0", features = ["ws", "ipc"] }
revm = { version = "3.5", features = ["std", "serde"] }
alloy-primitives = "0.7"
alloy-rlp = "0.3"

# Async runtime
tokio = { version = "1.35", features = ["full"] }
```

### 2. Block Fetcher Module

```rust
use ethers::providers::{Provider, Http};
use ethers::types::{Block, Transaction};

pub async fn fetch_block(rpc_url: &str, block_number: u64) -> Result<Block<Transaction>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    let block = provider.get_block_with_txs(block_number).await?;
    Ok(block.unwrap())
}
```

### 3. Transaction Prover

```rust
pub struct TransactionProver {
    zp1_prover: StarkProver,
    revm_executor: Revm,
}

impl TransactionProver {
    pub fn prove_transaction(&mut self, tx: &Transaction) -> Result<StarkProof> {
        // 1. Execute in Revm
        let result = self.revm_executor.execute(tx)?;
        
        // 2. Generate RISC-V trace
        let trace = self.generate_riscv_trace(&result)?;
        
        // 3. Prove with ZP1
        let proof = self.zp1_prover.prove(trace, &[])?;
        
        Ok(proof)
    }
}
```

### 4. Block Prover

```rust
pub struct BlockProver {
    tx_prover: TransactionProver,
    aggregator: ProofAggregator,
}

impl BlockProver {
    pub async fn prove_block(&mut self, block: Block<Transaction>) -> Result<BlockProof> {
        let mut tx_proofs = Vec::new();
        
        // Prove each transaction
        for tx in block.transactions {
            let proof = self.tx_prover.prove_transaction(&tx)?;
            tx_proofs.push(proof);
        }
        
        // Aggregate into block proof
        let block_proof = self.aggregator.aggregate(tx_proofs)?;
        
        Ok(block_proof)
    }
}
```

---

## CLI Integration

Add new commands:

```bash
# Prove single transaction
zp1 prove-tx --rpc-url http://localhost:8545 --tx-hash 0x123...

# Prove entire block
zp1 prove-block --rpc-url http://localhost:8545 --block-number 12345

# Prove block range (batch mode)
zp1 prove-blocks --rpc-url http://localhost:8545 --from 12345 --to 12350

# Verify block proof
zp1 verify-block --proof block_12345.proof
```

---

## Performance Estimates

### Single Transaction
- **Execution:** ~10ms (Revm)
- **Trace Generation:** ~50ms
- **STARK Proving:** ~1-5s (depends on trace size)
- **Total:** ~1-5s per transaction

### Full Block (150 transactions)
- **Sequential:** ~2.5-12.5 minutes
- **Parallel (16 cores):** ~10-50 seconds
- **With GPU:** ~5-20 seconds

### Proof Size
- **Transaction proof:** ~50-200 KB
- **Aggregated block proof:** ~500 KB - 2 MB
- **SNARK (on-chain):** ~200 bytes (Groth16)

---

## Security Considerations

1. **Precompiles:** Need to delegate or prove
   - SHA256, KECCAK256
   - ECRECOVER, ECADD, ECMUL
   - Pairing operations

2. **State Root Validation:**
   - Merkle Patricia Trie proofs
   - Storage slot verification
   - Account state transitions

3. **Consensus Rules:**
   - Block gas limit
   - Timestamp validation
   - Difficulty/PoS validation

---

## Next Steps

**Immediate (Can do now):**
1. Create `crates/ethereum` module
2. Add Ethers.rs and Revm dependencies
3. Implement block fetcher
4. Create transaction prover stub

**Short-term (1-2 weeks):**
1. Integrate Revm with ZP1 executor
2. Generate RISC-V traces from EVM execution
3. Test with simple transactions

**Medium-term (1 month):**
1. Full transaction proving
2. Proof aggregation
3. Block prover pipeline
4. CLI integration

**Long-term (2-3 months):**
1. Precompile delegation
2. State proof verification
3. On-chain verifier contracts
4. Production optimization

---

## Would you like me to:

1. **Start implementing the Ethereum module?**
   - Add dependencies
   - Create block fetcher
   - Set up basic structure

2. **Create detailed implementation plan?**
   - Week-by-week roadmap
   - Resource requirements
   - Performance targets

3. **Build a prototype?**
   - Single transaction prover
   - End-to-end demo
   - Benchmark results

Let me know which direction you'd like to take!
