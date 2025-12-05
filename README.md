# zp1 - RISC-V STARK Prover

A zero-knowledge proving system for RISC-V RV32IM program execution using STARK/FRI proofs over the Mersenne31 field.

## Features

- **STARK Proofs**: DEEP STARK with FRI commitment scheme
- **Circle FFT**: Uses circle group over M31 (order 2^32) for FFT-friendly polynomial operations
- **Mersenne31 Field**: Fast prime field (p = 2^31 - 1) with QM31 quartic extension
- **RV32IM Executor**: Full RISC-V RV32IM instruction set with ELF loader
- **Memory Consistency**: LogUp-based memory argument for provable memory access
- **Lookup Arguments**: LogUp protocol for efficient range checks and table lookups
- **Recursive Proofs**: Proof aggregation and compression for scalability
- **GPU Backend**: Trait-based GPU acceleration with CPU fallback
- **Parallel Proving**: Rayon-based multi-threaded prover

## Project Structure

```
crates/
├── primitives/   # M31/QM31 fields, Circle FFT, Merkle trees, FRI
├── executor/     # RV32IM CPU emulator with tracing, ELF loader
├── trace/        # Execution trace to column conversion
├── air/          # AIR constraints for CPU, memory, lookups
├── prover/       # STARK prover, LDE, GPU backend, recursion
├── verifier/     # Proof verification, DEEP queries
├── cli/          # Command-line interface
└── tests/        # Integration tests
```

## Installation

```bash
git clone https://github.com/this-vishalsingh/zp1.git
cd zp1
cargo build --release
```

## Usage

### CLI Commands

```bash
# Execute a RISC-V ELF and generate trace
zp1 execute program.elf --output trace.json

# Generate a STARK proof
zp1 prove program.elf --output proof.json

# Verify a proof
zp1 verify proof.json

# Show ELF information
zp1 info program.elf

# Run benchmarks
zp1 bench
```

### Library Usage

```rust
use zp1_executor::Cpu;
use zp1_prover::{StarkProver, StarkConfig};
use zp1_verifier::StarkVerifier;

// Execute program
let mut cpu = Cpu::new();
cpu.enable_tracing();
cpu.load_program(0x1000, &program_bytes)?;
while cpu.step()?.is_some() {}
let trace = cpu.take_trace()?;

// Generate proof
let config = StarkConfig::default();
let mut prover = StarkProver::new(config);
let proof = prover.prove(trace_columns);

// Verify proof
let verifier = StarkVerifier::new(config);
assert!(verifier.verify(&proof));
```

## Architecture

### Execution Model

The executor operates in **machine mode only** (M-mode, highest RISC-V privilege level):

- Standard fetch-decode-execute loop enforced at each cycle
- **No support for system-level opcodes**: ECALL, EBREAK, WFI, FENCE
  - These cause unprovable traps that fail proving
- **Strict memory alignment**:
  - Word (32-bit) accesses must be 4-byte aligned
  - Halfword (16-bit) accesses must be 2-byte aligned
- All traps converted to unprovable constraints (causing prover failure)

This design ensures deterministic, fully constrained execution suitable for zero-knowledge proving.

### Field Arithmetic
- **M31**: Mersenne prime field (p = 2^31 - 1) with SIMD-friendly operations
- **QM31**: Degree-4 extension for FRI security (irreducible: x^4 + x + 2)

### Proof System
- **Circle STARK**: Uses circle group for evaluation domain (|C| = 2^32)
- **DEEP Method**: Out-of-domain sampling for constraint verification
- **FRI**: Fast Reed-Solomon IOPP with configurable folding factor
- **LogUp**: Logarithmic derivative lookup argument for memory/tables

### Memory and Delegation Arguments

| Argument | Purpose | Implementation |
|----------|---------|----------------|
| **RAM Argument** | Memory consistency across chunks | "Two Shuffles Make a RAM" permutation with lazy init/teardown |
| **Delegation Argument** | Precompile circuit calls | Set equality via log-derivative lookup, triggered by CSRRW opcode |

Both arguments use separate memory subtrees for pre-commitment, enabling parallel proving of chunks and delegation circuits.

#### RAM Argument Protocol
1. Record all memory accesses (addr, value, timestamp, op)
2. Sort by (address, timestamp) to group accesses
3. Extract initial/final values per address
4. Two shuffles prove consistency: exec↔sorted and init↔final

#### Delegation CSR Addresses
| CSR | Name | Function |
|-----|------|----------|
| 0xC00 | DELEG_BLAKE2S | BLAKE2s hash delegation |
| 0xC01 | DELEG_BLAKE3 | BLAKE3 hash delegation |
| 0xC10 | DELEG_U256_ADD | U256 addition |
| 0xC11 | DELEG_U256_MUL | U256 multiplication |
| 0xC12 | DELEG_U256_MOD | U256 modular reduction |

### Constraint System
- 37 AIR constraints for RV32IM instructions
- Memory read/write consistency via sorted permutation
- Range checks for 8/16/32-bit values

## Testing

```bash
# Run all tests
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run specific crate tests
cargo test -p zp1-prover
```

## Benchmarks

```bash
# Run criterion benchmarks
cargo bench

# Quick CLI benchmark
cargo run --release -p zp1-cli -- bench
```

## Status

✅ **Implemented**:
- Mersenne31 field with QM31 extension
- Circle FFT and polynomial operations
- STARK prover with FRI commitment
- RV32IM executor with full instruction set
- ELF loader for standard binaries
- Merkle tree commitments (Blake3)
- LogUp lookup arguments
- Memory consistency proofs
- DEEP STARK verifier
- Recursive proof aggregation
- GPU backend traits (CPU fallback)
- CLI with execute/prove/verify commands

📋 **Planned**:
- Metal/CUDA GPU kernels
- BLAKE2s/BLAKE3 delegation gadgets
- U256 bigint precompiles
- SNARK wrapper for succinct proofs

## License

MIT

## References

- [Circle STARKs](https://eprint.iacr.org/2024/278) - Polygon/StarkWare
- [LogUp](https://eprint.iacr.org/2022/1530) - Lookup argument
- [RISC-V ISA](https://riscv.org/specifications/) - RV32IM specification
