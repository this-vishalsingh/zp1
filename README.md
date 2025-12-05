# zk RISC-V STARK Prover (RV32IM)

A RISC-V RV32IM proving system that generates zero-knowledge STARK proofs of program execution, with DEEP FRI, lookup/RAM arguments, delegated precompiles (BLAKE2s/BLAKE3, U256 bigint), recursive Rust verifier, and CPU/GPU provers.

## Status
- Planning and architecture phase. Implementation to follow.

## Proposed repository layout
- `docs/` — design notes, protocol specs, and param docs.
- `executor/` — RV32IM execution engine and trace emitter.
- `trace/` — trace builder/normalizer, padding/alignment, column serialization.
- `air/` — AIR definitions for CPU, memory, delegation gadgets, lookup wiring.
- `prover/` — STARK prover (commitment, DEEP FRI, lookup/RAM arguments); CPU backend.
- `prover-gpu/` — GPU acceleration (NTT/LDE, Merkle hashing, optional constraint kernels).
- `verifier/` — Rust verifier for base proofs and recursion.
- `recursion/` — recursive verifier circuits and SNARK wrapper integrations.
- `delegation/` — gadgets for BLAKE2s/BLAKE3, U256 bigint, other precompiles.
- `ffi/` — language bindings or host integrations.
- `scripts/` — tooling for building, benchmarking, fixtures.
- `bench/` — benchmark programs and reporting harness.
- `tests/` — end-to-end and algebraic tests (golden traces, lookup/RAM soundness).

## Immediate next steps
1) Decide field/parameters for the first milestone (likely Goldilocks, blowup/FRI rounds).
2) Implement the RV32IM executor + trace emission (golden correctness against ISA reference).
3) Define column layout and AIR for CPU + memory permutation + delegated precompiles.
4) Build minimal prover skeleton (commitment, LDE, constraint eval, DEEP FRI) on CPU.
5) Stand up Rust verifier for the minimal proof; add harness for recursive embedding.
6) Add GPU acceleration for NTT/Merkle once CPU path is stable.
7) Add delegated gadgets incrementally (BLAKE2s first, then BLAKE3, then U256 limb ops).

See `docs/architecture.md` for the detailed protocol sketch.
