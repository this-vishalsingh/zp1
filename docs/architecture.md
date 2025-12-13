# ZP1 Architecture

## Overview
Circle STARK prover for RISC-V RV32IM over Mersenne31 ($p = 2^{31} - 1$).
- DEEP composition with FRI polynomial commitment
- LogUp lookup arguments for memory/register consistency
- AIR constraints for RV32IM instruction set
- Delegation circuits for BLAKE2s/BLAKE3, U256 ops

## Field & Constraints
- **M31 base field** ($2^{31} - 1$), quartic extension for security
- **Degree-2 constraints** for all AIR operations
- **16-bit limb decomposition** for range checks
- **Circle group domains** for FFT evaluation

## Execution Pipeline
1. **Execute**: RV32IM executor captures trace (pc, registers, memory, syscalls)
2. **Encode**: Convert trace to AIR columns with domain padding
3. **Prove**: STARK prover via DEEP FRI + LogUp + RAM permutation
4. **Verify**: Check polynomial commitments and constraint satisfaction

## Components
- **Executor** (`zp1-executor`): Deterministic RV32IM emulator, no MMU
- **AIR** (`zp1-air`): Constraint functions for all 47 RV32IM instructions
- **Prover** (`zp1-prover`): STARK with FRI, Merkle commitments, Fiat-Shamir transcript
- **Verifier**: Base + recursive proof verification
- **Delegation**: BLAKE2s/BLAKE3 circuits, U256 bigint ops (future)

## CPU AIR
**State per step**: 77 columns
- Control: clk, pc, next_pc, instr, opcode
- Registers: rd, rs1, rs2 indices
- Immediates: imm_lo, imm_hi (16-bit limbs)
- Register values: rd_val, rs1_val, rs2_val (hi/lo limbs each)
- Instruction selectors: 46 one-hot flags (is_add, is_sub, is_beq, etc.)
- Memory: mem_addr (hi/lo), mem_val (hi/lo)
- Witnesses: carry, borrow, quotient (hi/lo), remainder (hi/lo), sb_carry
- Comparisons: lt_result, eq_result, branch_taken

**Constraints** (40+ functions, 100% implemented):
- **Basic**: x0 = 0 enforcement, PC increment
- **Arithmetic**: ADD, SUB (with carry/borrow tracking)
- **Bitwise**: AND, OR, XOR (lookup-table based)
- **Shifts**: SLL, SRL, SRA
- **Comparisons**: SLT, SLTU (signed/unsigned)
- **I-type**: ADDI, ANDI, ORI, XORI, SLTI, SLTIU, SLLI, SRLI, SRAI
- **Branches**: BEQ, BNE, BLT, BGE, BLTU, BGEU (condition + PC update)
- **Jumps**: JAL, JALR (link register + target)
- **Upper**: LUI, AUIPC
- **Memory**: Load/store address computation and value consistency
- **M-extension**: MUL, MULH, MULHSU, MULHU (64-bit product), DIV, DIVU, REM, REMU (division identity)
- **Invariant**: x0 = 0 enforced every step

## Memory Consistency
- **RAM permutation**: LogUp argument sorts by (addr, timestamp)
- **Read/write**: Consistency via grand product accumulation
- **Width handling**: Word proven; sub-word paths share value constraints pending extraction/masking wiring
- **Init table**: Program image + static data preloaded

## FRI Commitment
- **Domain**: Circle group, power-of-two sized with padding
- **Blowup**: 8x-16x for degree-2 constraints
- **DEEP**: Out-of-domain sampling with quotient polynomial
- **Folding**: Multi-round with Fiat-Shamir challenges

## Prover Pipeline
1. Trace ingestion
2. Low-degree extension (Circle FFT)
3. Constraint evaluation over domain
4. DEEP composition polynomial
5. FRI folding + Merkle commitments
6. Query openings

GPU support planned for FFT/Merkle operations.

## Implementation Status

**Core Components Implemented**:
- RV32IM instruction constraints (47 ops)
- Fiat-Shamir transcript with domain separators
- Public input binding
- RAM permutation (LogUp)
- DEEP quotient verification
- x0 invariant enforcement
- AIR integration with trace generation
- Constraints wired into evaluate_all()
- Basic prove/verify pipeline
- Test coverage for components

**Known Incomplete / In Progress**:
- EVM→RISC-V guest execution (ethereum crate)
- Full range constraints for multiply/divide witnesses
- Bit decomposition for bitwise/shift operations
- GPU optimization (CUDA backend scaffolding exists)
- Performance tuning for large traces
- Circle FFT optimization (currently O(n²))
- Recursion/aggregation
- External security audit
