# SHA-256 Precompile Example

Demonstrates ZP1's accelerated SHA-256 precompile.

## Test Vectors

### Input: "abc"
- Expected: `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`
- First word: `0xbf1678ba`

### Input: "The quick brown fox jumps over the lazy dog"
- Expected: `d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592`

## Performance

| Implementation | Cycles | Trace Rows |
|----------------|---------|------------|
| Estimated Pure RISC-V | ~8,000,000 | ~8M |
| Delegated | ~200 | ~80 |
| **Reduction** | **~40,000x** | **~100,000x** |

## Building

```bash
cargo build --release --target riscv32im-unknown-none-elf
cargo objcopy --release -- -O binary sha256.bin
```

## Testing

```bash
cd /Users/zippellabs/Developer/zp1
cargo run --release -- prove sha256 examples/sha256/sha256.bin
```

This demonstrates:
- SHA-256 delegation syscall
- Multiple hash computations
- Proper output verification
- Dramatic performance improvement
