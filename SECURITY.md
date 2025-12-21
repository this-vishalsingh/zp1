# ZP1 Security Analysis

## Summary

ZP1 targets **128-bit security** using:
- **Field**: Mersenne-31 (M31) with quartic extension QM31
- **FRI**: DEEP-FRI with Circle STARK structure
- **Hash**: Blake3 (256-bit output)

## Field Security

### Base Field: M31
- Prime: p = 2^31 - 1
- Field size: ~31 bits
- **Not sufficient alone for 128-bit security**

### Extension Field: QM31
- Quartic extension of M31
- Order: (2^31 - 1)^4 ≈ 2^124
- **Provides ~124 bits of security against algebraic attacks**

## FRI Security Parameters

Current configuration in `fri.rs`:
```rust
num_queries: 30        // Query soundness
final_degree: 8        // Final layer polynomial degree
folding_factor: 2      // Binary folding
```

### Soundness Analysis

FRI soundness error is approximately:
```
ε_FRI ≤ (1 - ρ)^num_queries * max(d/|D|, ε_proximity)
```

Where:
- ρ = rate = degree/domain_size (typically 1/4 with 4x blowup)
- num_queries = 30
- d = polynomial degree
- |D| = domain size

With 30 queries and rate of 1/4:
- Per-query soundness: ~2 bits
- Total FRI soundness: ~60 bits from queries alone

### Combined Security

| Component | Bits |
|-----------|------|
| QM31 algebraic security | 124 |
| FRI query soundness | 60 |
| Merkle/hash security | 128+ |
| **Effective security** | **~60** (limited by FRI) |

## Recommendations for 128-bit Security

### Option 1: Increase FRI Queries (Simple)
```rust
// In fri.rs FriConfig::new()
num_queries: 60,  // Changed from 30
```
This doubles soundness bits from FRI.

### Option 2: Use QM31 in FRI (Preferred)
Perform FRI over QM31 instead of M31 for challenges:
- Each query provides ~4 bits (vs ~2 with M31)
- 32 queries → ~128 bits

### Option 3: Additional Grinding (POW)
Add proof-of-work requirement:
- Require `grinding_factor` leading zeros
- Adds `grinding_factor` bits of security

## Current Status

| Aspect | Status | Notes |
|--------|--------|-------|
| Field security (QM31) | ✅ 124-bit | Near target |
| FRI queries | ⚠️ 60-bit | Needs increase |
| Hash function | ✅ 128-bit | Blake3 sufficient |
| DEEP-ALI | ✅ Correct | Implemented properly |

## Action Items

1. **Increase num_queries to 60** for immediate 120-bit security
2. **Document security assumptions** for audit preparation
3. **Add configurable security levels** (80/100/128 bit options)

## References

- [Circle STARK Paper](https://eprint.iacr.org/2024/278)
- [DEEP-FRI Security](https://eprint.iacr.org/2019/336)
- [ZisK 128-bit Analysis](https://github.com/0xPolygonHermez/zisk)
