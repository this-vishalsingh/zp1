# zk RISC-V Prover Architecture (STARK/FRI)

## Scope
- RISC-V RV32IM execution tracing and proving using DEEP STARK/FRI.
- Lookup/RAM arguments for memory consistency and delegated precompiles (BLAKE2s/BLAKE3, U256 bigint ops).
- Recursion-ready proofs, with a custom Rust verifier and SNARK compression target.
- CPU and GPU prover backends for performance.

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
- **Field**: Start with Goldilocks (2^64 - 2^32 + 1) for GPU-friendly NTT; keep abstraction layer for alt fields (e.g., BN254 scalar) for recursion friendliness.
- **Roots of unity**: Power-of-two domain sized to trace length + padding; enforce blowup >= 8x-16x depending on constraint degree.
- **DEEP composition**: Out-of-domain sampling for boundary + transition polynomials; evaluation combined via random coefficients from transcript.

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
- Field choice for recursion: stay in Goldilocks with custom SNARK, or switch to a 255-bit field for recursion friendliness.
- Lookup style: multiplicative vs additive grand product; evaluate constraint degree impact.
- Delegation coverage: which BLAKE variant first (BLAKE2s vs BLAKE3) and limb sizes for U256.
- On-chain target: which SNARK wrapper (Groth16, Plonkish) and circuit size budget for recursive verifier.
