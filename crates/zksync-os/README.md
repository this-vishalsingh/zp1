# ZP1 ZKsync OS Integration

This crate provides integration between ZP1 (a RISC-V zkVM) and [ZKsync OS](https://github.com/matter-labs/zksync-os), enabling ZP1 to execute and prove ZKsync OS RISC-V binaries.

## Overview

ZKsync OS is a state transition function for ZKsync that supports multiple execution environments (EVM, EraVM, WASM, etc.). It's compiled to RISC-V and designed to be proven by a RISC-V prover.

This integration allows you to:
- **Run** ZKsync OS binaries using ZP1's RISC-V executor
- **Generate witnesses** for proof generation
- **Prove** execution using ZP1's Circle STARK prover
- **Verify** proofs of ZKsync OS state transitions

## Architecture

Both ZP1 and ZKsync OS use the **Mersenne-31** field for their proving systems, making them compatible:

```
ZKsync OS                    ZP1
┌──────────────────┐        ┌──────────────────┐
│ Rust Program     │        │                  │
│ (EVM, System)    │        │                  │
└────────┬─────────┘        │                  │
         │ compile          │                  │
         ▼                  │                  │
┌──────────────────┐        │  ZP1 Executor    │
│ RISC-V Binary    │───────►│  (RV32IM)        │
│ (for_tests.bin)  │        │                  │
└──────────────────┘        └────────┬─────────┘
                                     │
┌──────────────────┐                 │
│ Witness/Oracle   │────────────────►│
│ (CSR reads)      │                 │
└──────────────────┘                 │
                                     ▼
                            ┌──────────────────┐
                            │ Execution Trace  │
                            └────────┬─────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │ ZP1 STARK Prover │
                            │ (Circle STARKs)  │
                            └────────┬─────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │ Validity Proof   │
                            └──────────────────┘
```

## Usage

### Basic Execution

```rust
use zp1_zksync_os::{ZkSyncOsRunner, OracleSource, RunConfig, WitnessBuilder};

// Load the ZKsync OS binary
let binary = std::fs::read("zksync_os/for_tests.bin")?;

// Create witness/oracle data
let witness = WitnessBuilder::new()
    .with_block_context(block_context)
    .with_data(&storage_reads)
    .build();

// Run the binary
let config = RunConfig::default();
let result = ZkSyncOsRunner::run(&binary, witness.to_oracle(), config)?;

// Check execution result
if result.is_success() {
    println!("Output: {:?}", result.output);
}
```

### Proof Generation

```rust
use zp1_zksync_os::{ZkSyncOsProver, ProverConfig};

// Create prover
let prover = ZkSyncOsProver::new(ProverConfig::default());

// Generate proof from execution result
let binary_hash = blake3::hash(&binary).into();
let proof = prover.prove(&result, binary_hash)?;

// Save proof
proof.save("proof.json")?;
```

### Proof Verification

```rust
use zp1_zksync_os::ZkSyncOsVerifier;

let proof = ZkSyncOsProof::load("proof.json")?;
let valid = ZkSyncOsVerifier::verify(&proof)?;
```

## Building ZKsync OS

To use this integration, you need a ZKsync OS RISC-V binary. From the [zksync-os repository](https://github.com/matter-labs/zksync-os):

```bash
# One-time setup
rustup target add riscv32i-unknown-none-elf
cargo install cargo-binutils && rustup component add llvm-tools-preview

# Build for RISC-V
cd zksync_os
./dump_bin.sh --type for-tests
```

This produces `for_tests.bin` which can be executed with ZP1.

## Witness Format

ZKsync OS uses a CSR (Control and Status Register) based oracle interface. The witness is a sequence of `u32` words that provide:

- Block metadata (number, timestamp, gas limit, coinbase, etc.)
- Transaction data
- Storage reads (address, key, value)
- Preimages for hashing

The `WitnessBuilder` and `OracleSource` types help construct properly formatted witness data.

## Features

- `default` - Basic functionality
- `rpc` - Enable RPC-based witness fetching (requires `reqwest`, `tokio`)

## Compatibility

This integration is compatible with:
- ZKsync OS v0.2.x
- ZP1 using Mersenne-31 Circle STARKs
- RISC-V target: `riscv32i-unknown-none-elf`

## Differences from zksync-airbender

This integration uses ZP1's prover instead of zksync-airbender. Key differences:

| Feature | zksync-airbender | ZP1 |
|---------|------------------|-----|
| Field | Mersenne-31 | Mersenne-31 |
| STARK type | Standard | Circle STARK |
| FFT | Standard (Mersenne group) | Circle FFT |
| Extension | M31 Quartic | QM31 |
| GPU Support | CUDA | Metal + CUDA |

Both produce valid proofs of ZKsync OS execution, but the proof formats are different.

## Examples

See the [examples](../examples/) directory for:
- `zksync_os_basic.rs` - Basic execution
- `zksync_os_prove.rs` - Proof generation and verification
- `zksync_os_evm.rs` - EVM transaction execution

## License

MIT OR Apache-2.0

## References

- [ZKsync OS](https://github.com/matter-labs/zksync-os)
- [ZKsync Airbender](https://github.com/matter-labs/zksync-airbender)
- [ZP1 Documentation](../docs/)
