//! Guest program integration for EVM execution.
//!
//! This module handles loading and executing the EVM guest program inside the zkVM.

use crate::fetcher::TransactionData;
use crate::transaction::TransactionResult;
use anyhow::Result;

/// Execute a transaction by running the guest program inside the zkVM.
///
/// This is the industry-standard approach used by SP1, Risc0, and OpenVM:
/// - The guest program (containing revm) runs INSIDE the zkVM
/// - The host prepares transaction data and provides it to the guest
/// - The guest executes the transaction and produces provable output
/// - The zkVM generates a proof of the guest's execution
pub async fn execute_tx_in_guest(_tx: &TransactionData) -> Result<TransactionResult> {
    // TODO: Full implementation when guest compilation is set up
    //
    // Steps:
    // 1. Load the guest ELF binary:
    //    const GUEST_ELF: &[u8] = include_bytes!("../guest/target/riscv32im-zp1-zkvm-elf/release/zp1-ethereum-guest");
    //
    // 2. Prepare guest input:
    //    let guest_input = TxInput {
    //        from: tx.from.as_bytes(),
    //        to: tx.to.map(|a| a.as_bytes()),
    //        value: tx.value.to_be_bytes(),
    //        gas: tx.gas,
    //        gas_price: tx.gas_price.map(|p| p.to_be_bytes()),
    //        input: tx.input.clone(),
    //        nonce: tx.nonce,
    //    };
    //
    // 3. Execute in zkVM:
    //    let mut cpu = Cpu::new(GUEST_ELF);
    //    cpu.write_input(&guest_input)?;
    //    let trace = cpu.execute()?;
    //
    // 4. Read output from journal:
    //    let guest_output: TxOutput = cpu.read_output()?;
    //
    // 5. Convert to TransactionResult:
    //    Ok(TransactionResult {
    //        hash: tx.hash,
    //        gas_used: guest_output.gas_used,
    //        success: guest_output.success,
    //        return_data: guest_output.return_data,
    //        state_changes: vec![],
    //    })

    unimplemented!("Guest execution will be implemented once guest build system is integrated")
}

/// Builder for guest program compilation.
///
/// This will integrate with the zp1 build system to:
/// - Compile the guest Rust code to RISC-V
/// - Generate the guest ELF binary
/// - Embed it in the host binary for execution
pub struct GuestBuilder {
    guest_path: std::path::PathBuf,
}

impl GuestBuilder {
    pub fn new() -> Self {
        Self {
            guest_path: std::path::PathBuf::from("crates/ethereum/guest"),
        }
    }

    /// Build the guest program to RISC-V ELF.
    pub fn build(&self) -> Result<Vec<u8>> {
        // TODO: Integrate with cargo-zp1 or build.rs
        // This would:
        // 1. Run: cargo build --target riscv32im-unknown-none-elf --release
        // 2. Read the resulting ELF file
        // 3. Return the bytes
        unimplemented!("Guest build system integration pending")
    }
}

impl Default for GuestBuilder {
    fn default() -> Self {
        Self::new()
    }
}
