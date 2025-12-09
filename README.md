# ZP1 - RISC-V zkVM

A zero-knowledge virtual machine for RISC-V programs using Circle STARKs over Mersenne31.

> ⚠️ **Experimental**: Not audited. Do not use in production.

## Quick Start

```bash
# Install
git clone https://github.com/this-vishalsingh/zp1
cd zp1
cargo build --release

# Run tests
cargo test --workspace

# Run demo
cargo run --release --example demo_benchmark -p zp1-prover
```

## Architecture

```
ELF Binary → Executor → Trace → Prover → Proof
               ↓          ↓        ↓
            RV32IM    77 cols   STARK/FRI
```

**Stack**: Mersenne31 → Circle STARKs → FRI → DEEP-ALI

## Features

- ✅ **RV32IM ISA**: All 47 base + multiply/divide instructions
- ✅ **Circle STARKs**: Mersenne31 field with QM31 extension
- ✅ **FRI**: Fast Reed-Solomon IOP with DEEP-ALI
- ✅ **Memory**: LogUp permutation argument
- ✅ **Parallel**: Rayon-based constraint evaluation
- ✅ **Range Checks**: 16-bit witness validation

## Documentation

- [Architecture](ARCHITECTURE.md) - System design
- [User Guide](docs/USER_GUIDE.md) - How to use ZP1
- [Examples](examples/) - Sample programs
- [Contributing](CONTRIBUTING.md) - Development guide

## Crates

| Crate | Description |
|-------|-------------|
| `primitives` | M31/QM31 fields, Circle FFT, Merkle trees |
| `executor` | RV32IM emulator with trace generation |
| `air` | Constraint functions for all instructions |
| `prover` | STARK prover with FRI |
| `verifier` | Proof verification |
| `delegation` | Precompile circuits (Keccak, SHA2, ECRECOVER) |
| `trace` | Trace generation data structures |
| `ethereum` | Ethereum integration and verification |
| `cli` | Command line interface |

## Status

**Test Coverage**: 162 prover tests + 16 integration tests passing

**Recent Fixes**:
- ✅ DEEP quotient domain points (security fix)
- ✅ OOD evaluation with full QM31 (31→128 bit security)
- ✅ Trace commitment (all 77 columns)
- ✅ Memory consistency integration
- ✅ Range constraints (16-bit validation)
- ✅ FRI folding (y-coordinate division)
- ✅ Cryptographic precompiles (Keccak, SHA2, etc.)
- ✅ Bitwise lookup tables (8-10x speedup)

**Known Limitations**:
- Circle FFT is O(n²) - needs butterfly optimization
- GPU: Metal implemented (`--features gpu-metal`), CUDA scaffolded
- No recursion/aggregation

## License

MIT OR Apache-2.0
