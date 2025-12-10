#!/usr/bin/env bash
# Build all ZP1 examples

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔨 Building all ZP1 examples..."
echo ""

# Check prerequisites
if ! rustup target list | grep -q "riscv32im-unknown-none-elf (installed)"; then
    echo "❌ RISC-V target not installed"
    echo "Run: rustup target add riscv32im-unknown-none-elf"
    exit 1
fi

# Try to find objcopy tool
OBJCOPY=""
if command -v rust-objcopy &> /dev/null; then
    OBJCOPY="rust-objcopy"
elif command -v llvm-objcopy &> /dev/null; then
    OBJCOPY="llvm-objcopy"
else
    # Try to find rust-objcopy in rustup toolchains
    OBJCOPY=$(find ~/.rustup/toolchains -name "rust-objcopy" 2>/dev/null | head -1)
    if [ -z "$OBJCOPY" ]; then
        echo "❌ objcopy tool not found"
        echo "Run: rustup component add llvm-tools-preview"
        exit 1
    fi
fi

echo "Using objcopy: $OBJCOPY"
echo ""

# Build each example
EXAMPLES=("fibonacci" "keccak" "sha256" "ecrecover" "memory-test" "blake2b" "json-parser" "merkle-proof" "password-hash" "ed25519-verify" "rsa-verify" "eth-header" "ripemd160" "wordle" "chess-checkmate" "range-proof" "waldo-proof" "sudoku" "age-proof" "voting" "regex-match" "hash-chain" "hello-zkvm" "nullifier" "commitment")

for example in "${EXAMPLES[@]}"; do
    if [ -d "$example" ]; then
        echo "📦 Building $example..."
        
        # Build (from workspace root for shared target/)
        cargo build --release --target riscv32im-unknown-none-elf -p "$example" 2>&1 | grep -v "warning:" || true
        
        # Extract binary
        ELF_PATH="$SCRIPT_DIR/target/riscv32im-unknown-none-elf/release/$example"
        BIN_PATH="$SCRIPT_DIR/$example/$example.bin"
        $OBJCOPY -O binary "$ELF_PATH" "$BIN_PATH"
        
        # Show binary size
        SIZE=$(wc -c < "$BIN_PATH")
        echo "   ✓ Built $example.bin ($SIZE bytes)"
        echo ""
    fi
done

echo "✅ All examples built successfully!"
echo ""
echo "Run an example:"
echo "  cd /Users/zippellabs/Developer/zp1"
echo "  cargo run --release -- prove fibonacci examples/fibonacci/fibonacci.bin"
