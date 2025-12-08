# zp1-zkvm

Guest library for writing zkVM programs that run inside ZP1.

## Overview

This library provides the interface for writing guest programs - RISC-V binaries that are executed and proven by the ZP1 zkVM. Guest programs can perform computations, invoke cryptographic precompiles, and commit results to the public journal.

## Features

- **I/O Operations**: Read inputs from host, commit outputs to public journal
- **Cryptographic Precompiles**: Keccak256, SHA256, ECRECOVER, RIPEMD160, Blake2b, MODEXP
- **no_std Compatible**: Works in bare-metal RISC-V environment
- **Easy Entry Point**: Simple macro for guest program setup

## Usage

### Basic Guest Program

```rust
#![no_std]
#![no_main]

use zp1_zkvm::prelude::*;

#[no_mangle]
fn main() {
    // Read inputs from host
    let a: u32 = read();
    let b: u32 = read();
    
    // Perform computation
    let sum = a + b;
    
    // Commit output to public journal
    commit(&sum);
}

// Set up entry point and panic handler
zp1_zkvm::entry!(main);
```

### Using Cryptographic Precompiles

```rust
#![no_std]
#![no_main]

use zp1_zkvm::prelude::*;

#[no_mangle]
fn main() {
    // Read transaction data
    let data: Vec<u8> = read();
    
    // Compute Keccak256 hash (delegated to precompile)
    let hash = keccak256(&data);
    
    // Compute SHA256 hash
    let sha_hash = sha256(&data);
    
    // Commit both hashes
    commit(&hash);
    commit(&sha_hash);
}

zp1_zkvm::entry!(main);
```

### ECRECOVER Example

```rust
#![no_std]
#![no_main]

use zp1_zkvm::prelude::*;

#[no_mangle]
fn main() {
    // Read signature components
    let msg_hash: [u8; 32] = read();
    let v: u8 = read();
    let r: [u8; 32] = read();
    let s: [u8; 32] = read();
    
    // Recover Ethereum address from signature
    match ecrecover(&msg_hash, v, &r, &s) {
        Some(address) => {
            commit(&address);
        }
        None => {
            // Invalid signature
            commit(&[0u8; 20]);
        }
    }
}

zp1_zkvm::entry!(main);
```

## Compilation

Guest programs must be compiled to the `riscv32im-unknown-none-elf` target:

```bash
# Add the target (one time setup)
rustup target add riscv32im-unknown-none-elf

# Compile your guest program
cargo build --target riscv32im-unknown-none-elf --release
```

The resulting ELF binary can be executed and proven by the ZP1 zkVM.

## API Reference

### I/O Functions

- **`read<T>()`** - Read typed input from host
- **`commit<T>(value)`** - Commit output to public journal
- **`hint<T>(value)`** - Provide unverified hint to prover
- **`print(msg)`** - Debug output (not verified)

### Cryptographic Functions

- **`keccak256(data: &[u8]) -> [u8; 32]`** - Keccak-256 hash
- **`sha256(data: &[u8]) -> [u8; 32]`** - SHA-256 hash
- **`ecrecover(hash, v, r, s) -> Option<[u8; 20]>`** - Ethereum signature recovery
- **`ripemd160(data: &[u8]) -> [u8; 20]`** - RIPEMD-160 hash
- **`blake2b(data: &[u8]) -> [u8; 64]`** - Blake2b hash
- **`modexp(base, exp, mod) -> [u8; 32]`** - Modular exponentiation

### Entry Macro

```rust
zp1_zkvm::entry!(main);
```

Sets up the RISC-V entry point (`_start`) and panic handler for your guest program.

## Implementation Status

### ✅ Implemented

- Library structure and API
- Syscall definitions (inline assembly)
- Entry point macro
- no_std compatibility
- Documentation
- I/O functions (read, commit, hint) with syscall protocol
- Raw byte I/O variants (read_slice, commit_slice, hint_slice, peek_input_size)

### 🚧 In Progress

- Host-side I/O syscall handlers in executor
- Integration testing with actual guest programs

### 📋 Planned

- More precompiles (BN254, BLS12-381, Ed25519)
- Alloc support for dynamic memory
- Standard library compatibility mode
- Debugging utilities

## Architecture

Guest programs invoke syscalls via the RISC-V `ECALL` instruction:

1. Set syscall code in register `a7` (x17)
2. Set arguments in registers `a0-a6` (x10-x16)
3. Execute `ECALL`
4. Return value in `a0` (x10)

The executor intercepts ECALL instructions and dispatches to the appropriate handler (precompile circuits, I/O operations, etc.).

## Security Considerations

- **Deterministic Execution**: Guest programs must be deterministic
- **No Side Effects**: No file I/O, network, or system calls (except provided syscalls)
- **Memory Safety**: Use Rust's safety guarantees
- **Hint Data**: Never trust `hint()` data - always verify within guest

## Examples

See `examples/` directory for complete guest program examples:

- `fibonacci` - Simple recursive computation
- `keccak_hash` - Cryptographic hashing
- `signature_verify` - ECRECOVER signature verification

## License

See workspace license.
