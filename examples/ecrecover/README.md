# ECRECOVER Precompile Example

Demonstrates Ethereum signature recovery (ECRECOVER) using ZP1's delegation.

## What It Does

Recovers an Ethereum address from:
- Message hash (32 bytes)
- Signature components: v, r, s

## Performance

| Implementation | Cycles | Trace Rows |
|----------------|---------|------------|
| Estimated Pure RISC-V | ~10,000,000 | ~10M |
| Delegated | ~200 | ~100 |
| **Reduction** | **~50,000x** | **~100,000x** |

## EIP-155 Support

The implementation supports:
- Legacy signatures (v = 27, 28)
- EIP-155 chain-specific signatures
- Proper address recovery

## Building

```bash
cargo build --release --target riscv32im-unknown-none-elf
cargo objcopy --release -- -O binary ecrecover.bin
```

## Testing

```bash
cd /Users/zippellabs/Developer/zp1
cargo run --release -- prove ecrecover examples/ecrecover/ecrecover.bin
```

## Use Cases

- Ethereum transaction verification
- Signature validation
- Address recovery
- Essential for Ethereum block proving

This is critical for proving Ethereum blocks, where every transaction signature must be verified.
