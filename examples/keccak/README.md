# Keccak-256 Precompile Example

Demonstrates ZP1's accelerated Keccak-256 precompile using delegation.

## What It Does

1. Computes Keccak-256("hello world")
2. Computes Keccak-256("zkVM proving")
3. Stores results in memory

## Expected Outputs

- **"hello world"**: `0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad`
- First word (little-endian): `0x85321747`

## Performance

- **Estimated Pure RISC-V**: ~10,000,000 cycles
- **With Delegation**: ~100 trace rows
- **Trace Reduction**: ~100,000x (estimated)

## Building

```bash
cargo build --release --target riscv32im-unknown-none-elf
cargo objcopy --release -- -O binary keccak.bin
```

## Testing

```bash
cd /Users/zippellabs/Developer/zp1
cargo run --release -- prove keccak examples/keccak/keccak.bin
```

This demonstrates:
- Syscall interface usage
- Keccak-256 delegation
- Compact trace representation vs estimated pure RISC-V
- Efficient cryptographic precompile execution
