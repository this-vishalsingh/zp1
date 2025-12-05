# zk RISC-V Prover Architecture (STARK/FRI)

## Scope
- DEEP STARK/FRI arguments for efficient proof generation.
- Lookup/RAM/Delegation arguments for memory consistency and precompile calls.
- AIR constraints for RISC-V CPU and delegation circuits (BLAKE2s/Blake3, U256 BigInt operations).
- Custom Rust verifier program for proof recursion.
- CPU and GPU prover implementations for performance optimization.

## Field Arithmetic and Constraints
All arithmetization is performed over **Mersenne31 (M31)** field elements ($p = 2^{31} - 1$), with extension field operations used where security requires it (e.g., lookup finalization, FRI folding challenges).

- **Degree-2 polynomial constraints** maximum for all AIR constraints. Keeping constraint degree at most 2 streamlines STARK/FRI proving optimizations and simplifies circuit performance analysis.
- **16-bit limb decomposition** for 32-bit words. Each 32-bit value is represented as two 16-bit limbs; range checks via lookup tables or permutation arguments.
- **Separate address space for registers**, accessed via a RAM argument. The 32 general-purpose registers live in a distinct memory region, reducing lookup collisions and allowing efficient permutation proofs.

## System overview
1) **Compile + execute**: Build RISC-V binaries (Rust or other) -> run in an instrumented RV32IM executor -> capture deterministic trace (registers, pc, memory ops, syscalls/precompiles).
2) **Trace to AIR**: Convert execution trace to AIR columns (CPU core, memory, delegation circuits, lookup logs). Apply trace compression (permutation, boundary randomization) for DEEP composition.
3) **Prove**: STARK prover (CPU or GPU) produces proof using DEEP FRI + lookup/RAM arguments + delegation gadgets.
4) **Verify**: Rust verifier for base proofs and recursive aggregation. Final proofs can be wrapped into a SNARK for on-chain verification.

## Core components
- **Executor**: Deterministic RV32IM runner (no MMU/privileged modes). Emits columns: pc, instr, flags, registers, memory addr/value/opcode, gas/step counter, syscall/delegation hints.
- **Trace builder**: Normalizes executor output into columnar form; enforces padding/alignment to evaluation domain; handles challenge-driven randomization (e.g., memory permutation challenges, composition polynomial seeds).
- **AIR definitions**:
  - CPU AIR for RV32IM (see constraint sketch below).
  - Memory AIR with RAM permutation argument and lookups for load/store consistency.
  - Delegation AIR for precompiles (BLAKE2s/BLAKE3, U256 ops) using lookup tables or dedicated sub-circuits.
- **Commitment & channel**: Fiat-Shamir transcript, Merkle commitments over low-degree codewords, DEEP composition queries.
- **FRI**: Multi-round folding; DEEP variant with out-of-domain sampling; prover supports GPU acceleration for FFT/NTT and Merkle hashing.
- **Verifier**: Rust verifier library; supports base proof verification and recursive aggregation (verifier-as-circuit). Exposes serialization for SNARK wrapper.
- **Aggregator**: Batches multiple proofs, folds accumulators, outputs a single recursive proof ready for SNARK compression.

## AIR sketch (CPU)
- **State vector per step** (examples):
  - pc, instr, opcode class, rd/rs1/rs2, imm, flags (branch, jump, mem, mul/div, csr-none), gas/clk.
  - regs[32] (can be packed into multiple columns with sparsity/selectors).
  - mem_addr, mem_value, mem_is_load, mem_is_store, mem_width.
- **Transition constraints** (non-exhaustive):
  - pc': pc + 4 or branch target conditioned on flag.
  - Register write-back matches ALU/M extension semantics; x0 = 0 invariant.
  - MUL/MULH/MULHU/MULHSU, DIV/REM constraints using 64-bit intermediate columns or delegated lookup (for high radices, prefer delegated gadget to reduce degree).
  - Memory op emits a row in memory log with addr/value/width/opcode.
  - Clock/gas increments and step counter bounds.
- **Boundary constraints**: initial pc/regs, final halting flag or step bound reached.

## Memory consistency
- **RAM permutation argument**: Sort memory log by (address, timestamp) using a permutation/lookup to enforce consistency between consecutive accesses; enforce read values equal prior write, with initialization table for program/data memory.
- **Range/width handling**: Separate lookup tables per width (byte, half, word); enforce aligned accesses via constraints.
- **Decommit tables**: Preload program image and static data as a table to seed RAM argument.

## Delegation / precompiles
- **Hash (BLAKE2s/BLAKE3)**: Provide trace/log for precompile calls; verify via dedicated AIR sub-circuit or lookup to precomputed sponge rounds. Option: succinctly verify with a packed-round lookup (state, round constants).
- **U256 bigint ops**: Expose add/sub/mul/modexp as delegated gadgets. For mul/modexp, use range-decomposed limbs with lookups for carries; ensure deterministic gas/step accounting.
- **Interface**: Executor emits a delegation log (op-id, inputs, outputs). Main AIR includes a lookup into delegation table to bind CPU row to gadget rows.

## Lookup argument choices
- Use logarithmic-derivative or multiplicative grand product for table consistency.
- Shared lookup challenges across CPU, memory, delegation to reduce blowup.
- Batch lookups where possible; use column compression (e.g., random linear combination) before commitment.

## FRI / field / domain
- **Field**: Mersenne31 ($p = 2^{31} - 1$) as the base field for fast native arithmetic and efficient NTT via Circle STARKs or two-adic extension tower. Extension field (e.g., quartic M31) used for lookup grand products and FRI folding challenges to meet security targets.
- **Roots of unity**: Power-of-two domain sized to trace length + padding; blowup factor 8×–16× depending on security/performance trade-off. With degree-2 constraints, a lower blowup is viable.
- **DEEP composition**: Out-of-domain sampling for boundary + transition polynomials; evaluation combined via random extension-field coefficients from Fiat-Shamir transcript.

## Prover pipeline (CPU/GPU)
- Trace ingestion -> column hashing -> low-degree extension (NTT) -> constraint evaluation -> composition polynomial -> DEEP queries -> FRI folding -> Merkle openings.
- GPU acceleration focus: NTT/LDE, Merkle hashing; optional GPU constraint eval kernels for CPU/MEM lookups.
- Chunked execution to fit GPU memory; overlap compute and I/O via streams.

## Verifier and recursion
- Standalone Rust verifier: validates commitments, constraint degrees, FRI rounds, query openings, lookup products, RAM permutation proofs.
- Recursive verifier: represent verifier as circuit-friendly gates; use folding/accumulation to aggregate many proofs; final artifact fed to a SNARK (Plonkish or Groth16) for L1 verification.
- Deterministic serialization for proofs and public inputs; versioned proof header with parameter commitments.

## Interfaces and IO
- **Inputs**: program image, initial memory, public inputs, max steps, prover params (field, blowup, FRI rounds, hash), prover mode (cpu/gpu).
- **Outputs**: STARK proof bytes, public input commitment, optional execution trace commitments for audit.
- **APIs**: Rust library functions `prove(program, inputs, params) -> Proof`, `verify(proof, params)`, `aggregate(proofs) -> Proof`.

## Testing and validation
- Golden tests with small RISC-V programs (alu, branches, mul/div, memory patterns, hash precompile calls).
- Differential testing: executor trace vs reference ISA simulator.
- Algebraic checks: degree bounds, soundness of lookups/ram permutations; fuzz transcript challenges.
- Performance benchmarks on CPU and GPU (trace size, proof time, memory footprint).

## Open questions / tunables
- Lookup style: multiplicative vs additive (LogUp) grand product; evaluate constraint degree impact on M31.
- Delegation coverage: which BLAKE variant first (BLAKE2s vs BLAKE3) and limb sizes for U256.
- On-chain target: which SNARK wrapper (Groth16, Plonkish) and circuit size budget for recursive verifier.
- Extension degree for security: quartic M31 vs sextic for higher security margins.
