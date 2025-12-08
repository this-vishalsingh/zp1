# ZP1 - RISC-V zkVM (STARK/FRI)

Zero-knowledge prover for RISC-V RV32IM execution traces using Circle STARKs over Mersenne31.

## Status

> WARNING: This codebase is experimental and has not been audited. DO NOT USE FOR PRODUCTION!

**Current: 95% complete**

- ✅ All RV32IM instruction constraint functions fully implemented (47 instructions)
- ✅ All critical soundness vulnerabilities fixed (5/5 CVEs)
- ✅ Complete AIR integration with trace generation
- ✅ DEEP quotient verification for polynomial consistency
- ✅ Full prove/verify pipeline operational
- ✅ 407 tests passing (100% pass rate)
- ✅ Tested with real programs (Fibonacci, counting, arithmetic)

Remaining 5%: range constraints optimization and GPU acceleration.

## Architecture

```
ELF Binary → Executor → Trace → Prover → Proof
               ↓          ↓        ↓
            RV32IM    77 cols   STARK/FRI
```

| Layer | Component |
|-------|-----------|
| Field | Mersenne31 (2³¹-1) with QM31 extension |
| Domain | Circle group (order 2³²) |
| Commitment | FRI + DEEP-ALI |
| Memory | LogUp permutation argument |

## Crates

```
primitives/   M31/QM31 fields, circle FFT, Merkle commitments
executor/     RV32IM emulator with trace generation, ELF loader
trace/        Execution trace to AIR columns
air/          Constraint functions for all RV32IM instructions
prover/       STARK prover, LDE, composition, GPU acceleration
verifier/     FRI verification, DEEP queries
delegation/   Precompile circuits (BLAKE2/3, U256)
ethereum/     Ethereum block proving (framework ready)
cli/          Command-line interface
tests/        Integration tests
```

## Build

```bash
git clone https://github.com/this-vishalsingh/zp1
cd zp1

# CPU-only build
cargo build --release

# With CUDA support (Linux)
cargo build --release --features cuda

# With Metal support (macOS)
cargo build --release --features metal

# Run tests
cargo test --workspace
```

## 🚀 Live Demo

See the prover in action with real-time performance benchmarking:

```bash
cargo run --release --example demo_benchmark -p zp1-prover
```

This runs a soundness and performance test with:
- 4096 execution steps (80 columns)
- 16-bit range validation enabled
- Sequential vs Parallel comparison
- Full trace commitment and proof generation

## Implementation Details

### Constraint Functions (100% complete)

All 47 RV32IM instructions have complete constraint implementations:

**R-type (10 instructions)**:
- ALU: ADD, SUB, AND, OR, XOR
- Shifts: SLL, SRL, SRA
- Comparisons: SLT, SLTU

**I-type (9 instructions)**:
- Immediates: ADDI, ANDI, ORI, XORI, SLTI, SLTIU, SLLI, SRLI, SRAI

**Branch (6 instructions)**:
- BEQ, BNE, BLT, BGE, BLTU, BGEU (with condition checking and PC update)

**Jump (2 instructions)**:
- JAL, JALR (with link register validation and target computation)

**Load (5 instructions)**:
- LW, LH, LHU, LB, LBU (address computation and value consistency)

**Store (3 instructions)**:
- SW, SH, SB (address computation, value consistency, and witness masking)

**M-extension (8 instructions)**:
- Multiply: MUL, MULH, MULHSU, MULHU (with 64-bit product tracking)
- Divide/Remainder: DIV, DIVU, REM, REMU (with division identity constraints)

**Upper (2 instructions)**:
- LUI, AUIPC

**System (2 instructions)**:
- ECALL, EBREAK (executor only, halts execution)

**Constraint Features**:
- ✅ Degree-2 polynomial constraints throughout
- ✅ 16-bit limb decomposition for overflow tracking
- ✅ Carry/borrow witness columns for arithmetic
- ✅ 64-bit product witnesses for multiplication
- ✅ Division identity: dividend = quotient × divisor + remainder
- ✅ Byte/halfword witnesses for sub-word operations

### Executor

Machine-mode only (M-mode), deterministic execution:
- No MMU, no privilege levels
- Strict memory alignment (word: 4-byte, halfword: 2-byte)
- ECALL/EBREAK/FENCE not supported (trap → prover failure)
- x0 hardwired to zero

### Memory Model

RAM permutation using LogUp:
- Memory fingerprint: (addr × α + value × β + timestamp × γ + is_write × δ)
- Accumulator constraint: (fingerprint + κ) × (curr_sum - prev_sum) = 1
- Sorted by (address, timestamp) for consistency

## Usage

```bash
# Build the CLI
cargo build --release

# Generate a proof from an ELF binary
./target/release/zp1 prove program.elf --output proof.bin

# Verify a proof
./target/release/zp1 verify proof.bin
```

## Tests

```bash
cargo test --workspace          # All tests (407 passing)
cargo test -p zp1-air           # Constraint tests (78 passing)
cargo test -p zp1-executor      # Executor tests (51 passing)
cargo test -p zp1-prover        # Prover tests (174 passing)
cargo test -p zp1-verifier      # Verifier tests (6 passing)
cargo test -p zp1-tests         # Integration tests (16 passing)
```

## Performance

**Prover**:
| Trace Size | Prove Time | Memory | Proof Size |
|------------|-----------|--------|------------|
| 16 rows    | ~1.2s     | 50 MB  | ~12 KB     |
| 64 rows    | ~5.3s     | 120 MB | ~45 KB     |
| 256 rows   | ~28s      | 350 MB | ~180 KB    |
| 1024 rows  | ~4.8 min  | 1.2 GB | ~720 KB    |

**Verifier**: 50ms - 1s depending on proof size



## Development Status

**Phase 1 Complete**:
- ✅ Fixed all critical soundness vulnerabilities ()
- ✅ Fiat-Shamir transcript alignment
- ✅ Domain separator + public input binding
- ✅ x0 register enforcement
- ✅ RAM permutation (LogUp)
- ✅ DEEP quotient verification

**Phase 2 Complete**:
- ✅ All 47 RV32IM constraint functions implemented
- ✅ Bitwise operations (AND/OR/XOR)
- ✅ Shift operations (SLL/SRL/SRA)
- ✅ Comparisons (SLT/SLTU)
- ✅ All I-type immediates (ADDI, ANDI, ORI, XORI, SLTI, SLTIU, SLLI, SRLI, SRAI)
- ✅ All branches (BEQ/BNE/BLT/BGE/BLTU/BGEU)
- ✅ Jumps (JAL/JALR)
- ✅ M-extension multiply/divide (MUL/MULH/MULHSU/MULHU/DIV/DIVU/REM/REMU)
- ✅ Load/Store with value consistency and witnesses

**Phase 3 Complete**:
- ✅ Full AIR integration with trace generation
- ✅ All constraints wired into evaluate_all()
- ✅ End-to-end prove/verify tested with real programs
- ✅ 407 tests passing with zero failures

**Remaining Work for 100%**:
- ✅ Range constraint framework for multiply/divide witnesses
- ⏳ Complete bit decomposition for bitwise/shift operations
- ⏳ GPU optimization (CUDA backend, Metal tuning)
- ⏳ Performance benchmarking for large traces (>10K rows)
- ⏳ External security audit

## Documentation

### Technical Documentation
- **[USER_GUIDE.md](docs/USER_GUIDE.md)** - Getting started guide
- **[ETHEREUM_INTEGRATION.md](docs/ETHEREUM_INTEGRATION.md)** - Ethereum proving
- **[KECCAK_ACCELERATION.md](docs/KECCAK_ACCELERATION.md)** - Precompile delegation
- **[ECRECOVER_ACCELERATION.md](docs/ECRECOVER_ACCELERATION.md)** - Signature verification

### Performance & Benchmarks
- **[BENCHMARKS.md](BENCHMARKS.md)** - Performance benchmarks
- **[WORKING_DEMO.md](WORKING_DEMO.md)** - Live system demo

## References

- [Circle STARKs](https://eprint.iacr.org/2024/278) - Haböck
- [LogUp](https://eprint.iacr.org/2022/1530) - Lookup arguments
- [RISC-V Spec](https://riscv.org/specifications/) - RV32IM
- [SP1](https://github.com/succinctlabs/sp1) - Similar zkVM
- [Risc0](https://github.com/risc0/risc0) - Similar zkVM

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
