# ZP1 Examples

Collection of example programs demonstrating ZP1's zkVM capabilities.

## Examples Overview

### 1. **fibonacci** - Basic Computation
Simple Fibonacci number calculation showing basic RISC-V execution.
- **Complexity**: Beginner
- **Instructions**: ~100 cycles
- **Demonstrates**: Arithmetic, loops, memory writes

### 2. **keccak** - Keccak-256 Hashing
Demonstrates accelerated Keccak-256 precompile with delegation.
- **Complexity**: Intermediate
- **Benefit**: Compact trace representation
- **Demonstrates**: Syscalls, delegation, cryptographic acceleration

### 3. **sha256** - SHA-256 Hashing
Shows SHA-256 precompile performance improvements.
- **Complexity**: Intermediate
- **Benefit**: Compact trace representation
- **Demonstrates**: SHA-256 delegation, multiple hashes

### 4. **ecrecover** - Ethereum Signature Recovery
Critical for Ethereum: recovers addresses from signatures.
- **Complexity**: Advanced
- **Benefit**: Compact trace representation
- **Demonstrates**: ECRECOVER, EIP-155 support, Ethereum integration

### 5. **memory-test** - Memory Operations
Comprehensive test of all load/store instructions.
- **Complexity**: Intermediate
- **Demonstrates**: Memory model, LogUp argument, consistency proofs

### 6. **guest-hello** - Guest Program Template
Starting template for writing your own guest programs.
- **Complexity**: Beginner
- **Demonstrates**: Project structure, no_std Rust

### 7. **blake2b** - Blake2b-512 Hashing (NEW)
Zcash-compatible Blake2b-512 hash function.
- **Complexity**: Intermediate
- **Demonstrates**: Blake2b syscall, Zcash compatibility

### 8. **json-parser** - JSON Field Extraction (NEW)
Prove JSON field extraction without revealing full document.
- **Complexity**: Intermediate
- **Demonstrates**: Pure Rust parsing, private data proofs

### 9. **merkle-proof** - Merkle Tree Verification (NEW)
Verify Merkle tree inclusion proofs using Keccak256.
- **Complexity**: Advanced
- **Demonstrates**: Merkle trees, cryptographic proofs, Ethereum compatibility

### 10. **password-hash** - ZK Password Verification (NEW)
Prove knowledge of password preimage without revealing it.
- **Complexity**: Intermediate
- **Demonstrates**: SHA256, ZK authentication patterns

## Quick Start

### Prerequisites

```bash
# Install RISC-V target
rustup target add riscv32im-unknown-none-elf

# Install cargo-binutils for objcopy
cargo install cargo-binutils
rustup component add llvm-tools-preview
```

### Building an Example

```bash
cd examples/fibonacci
cargo build --release --target riscv32im-unknown-none-elf
cargo objcopy --release -- -O binary fibonacci.bin
```

### Running with ZP1

```bash
cd /Users/zippellabs/Developer/zp1
cargo run --release -- prove fibonacci examples/fibonacci/fibonacci.bin
```

## Build All Examples

```bash
./examples/build_all.sh
```

This will build all examples and create `.bin` files ready for proving.

## Performance Comparison

| Example | Pure RISC-V Cycles | With Delegation | Speedup |
### 11. **ed25519-verify** - Ed25519 Signature (NEW)
Demonstrates structure for Ed25519 signature verification.
- **Complexity**: Advanced
- **Demonstrates**: Signature verification flow (Tier 1)

### 12. **rsa-verify** - RSA Verification (NEW)
Verify RSA-2048 signatures using MODEXP syscall.
- **Complexity**: Advanced
- **Demonstrates**: MODEXP syscall (0x1004)

### 13. **eth-header** - Ethereum Header (NEW)
Verify Ethereum block headers using Keccak-256.
- **Complexity**: Advanced
- **Demonstrates**: RLP decoding logic, Keccak syscall (0x1000)

### 14. **ripemd160** - Bitcoin Addressing (NEW)
Generate Bitcoin address hash (RIPEMD160(SHA256(pubkey))).
- **Complexity**: Intermediate
- **Demonstrates**: RIPEMD160 syscall (0x1003), syscall chaining

### 15. **wordle** - ZK Wordle (NEW)
Prove you solved a Wordle puzzle without revealing the word.
- **Complexity**: Intermediate
- **Demonstrates**: Logic puzzles, private input protection (Tier 2)

### 16. **chess-checkmate** - ZK Chess (NEW)
Prove checkmate condition on a board without revealing the move.
- **Complexity**: Intermediate
- **Demonstrates**: Game state verification (Tier 2)

### 17. **range-proof** - Range Check (NEW)
Prove a secret value lies within a public range.
- **Complexity**: Basic
- **Demonstrates**: Basic numeric constraints (Tier 2)

### 18. **waldo-proof** - Where's Waldo (NEW)
Prove an image exists within a larger grid without revealing location.
- **Complexity**: Intermediate
- **Demonstrates**: 2D grid search, pattern matching (Tier 2)

## Quick Start
(... section omitted for brevity ...)

## Syscall Reference

### Available Syscalls

| Syscall | Number | Description |
|---------|--------|-------------|
| HALT | 0x00 | Terminate program |
| WRITE | 0x01 | Output data |
| READ | 0x02 | Input data |
| COMMIT | 0x03 | Commit to journal |
| KECCAK256 | 0x1000 | Keccak-256 hash |
| SHA256 | 0x1002 | SHA-256 hash |
| RIPEMD160 | 0x1003 | RIPEMD-160 hash |
| BLAKE2B | 0x1005 | Blake2b hash |
| ECRECOVER | 0x1001 | Ethereum signature recovery |
| MODEXP | 0x1004 | Modular exponentiation |

### Syscall Convention

```rust
unsafe {
    core::arch::asm!(
        "ecall",
        in("a7") syscall_number,  // Syscall ID
        in("a0") arg0,             // First argument
        in("a1") arg1,             // Second argument
        in("a2") arg2,             // Third argument
        options(nostack)
    );
}
```

## Troubleshooting

### "cannot find crate for `std`"
Make sure you have `#![no_std]` at the top of your file.

### "undefined reference to `_start`"
Add `#![no_main]` and define your own `_start` function.

### Binary too large
Use release mode with LTO:
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
```

### Syscall not working
Check that:
1. Syscall number matches the table above
2. Using correct register conventions (a7, a0-a6)
3. Arguments are properly formatted (pointers, lengths)

## Further Reading

- [ZP1 User Guide](../docs/USER_GUIDE.md)
- [Architecture Overview](../docs/architecture.md)
- [Keccak Acceleration](../docs/KECCAK_ACCELERATION.md)
- [ECRECOVER Delegation](../docs/ECRECOVER_ACCELERATION.md)

## Inspiration

These examples are inspired by [ZKsync Airbender](https://github.com/matter-labs/zksync-airbender/tree/main/examples), adapted for ZP1's architecture and delegation model.
