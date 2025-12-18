//! Example: Running ZKsync OS with ZP1
//!
//! This example demonstrates how to:
//! 1. Load a ZKsync OS RISC-V binary
//! 2. Create witness/oracle data
//! 3. Execute the binary using ZP1's executor
//! 4. (Optional) Generate a proof
//!
//! To run this example:
//! ```bash
//! # First, build ZKsync OS binary (from zksync-os repo):
//! # cd zksync_os && ./dump_bin.sh --type for-tests
//!
//! # Then run this example:
//! cargo run --example zksync_os_demo --package zp1-zksync-os
//! ```

use std::path::Path;
use zp1_zksync_os::{
    BlockContext, OracleBuilder, ProgramOutput, ProverConfig, RunConfig, WitnessBuilder,
    ZkSyncOsProver, ZkSyncOsRunner, ZkSyncOsVerifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZP1 ZKsync OS Integration Demo ===\n");

    // Check if we have a zksync-os binary to run
    let binary_path = find_zksync_os_binary();

    match binary_path {
        Some(path) => {
            println!("Found ZKsync OS binary at: {}", path.display());
            run_with_binary(&path)?;
        }
        None => {
            println!("No ZKsync OS binary found. Running with demo data.\n");
            run_demo()?;
        }
    }

    Ok(())
}

/// Try to find a ZKsync OS binary in common locations.
fn find_zksync_os_binary() -> Option<std::path::PathBuf> {
    let paths = [
        "../zksync-os/zksync_os/for_tests.bin",
        "../../zksync-os/zksync_os/for_tests.bin",
        "zksync_os/for_tests.bin",
    ];

    for p in &paths {
        let path = Path::new(p);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    // Check environment variable
    if let Ok(p) = std::env::var("ZKSYNC_OS_BIN") {
        let path = Path::new(&p);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    None
}

/// Run with an actual ZKsync OS binary.
fn run_with_binary(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading binary from: {}", path.display());

    // Load binary
    let binary = std::fs::read(path)?;
    println!(
        "Binary size: {} bytes ({} words)",
        binary.len(),
        binary.len() / 4
    );

    // Create a minimal block context
    let block_context = BlockContext {
        block_number: 1,
        timestamp: 1700000000,
        gas_limit: 30_000_000,
        chain_id: 324, // zkSync Era
        ..Default::default()
    };

    // Build oracle with block context
    let oracle = OracleBuilder::new()
        .with_block_context(&block_context)
        .build();

    // Configure execution
    let config = RunConfig {
        max_cycles: 1 << 25, // Limit cycles for demo
        enable_tracing: true,
        ..Default::default()
    };

    println!("\nExecuting ZKsync OS binary...");
    let start = std::time::Instant::now();

    match ZkSyncOsRunner::run(&binary, oracle, config) {
        Ok(result) => {
            let elapsed = start.elapsed();

            println!("\n=== Execution Result ===");
            println!("Success: {}", result.success);
            println!("Output: {}", result.output.to_hex());
            println!("Cycles: {}", result.stats.cycles);
            println!("Oracle reads: {}", result.stats.oracle_reads);
            println!("Execution time: {:?}", elapsed);

            if result.trace.is_some() {
                println!("Trace collected: yes");
            }

            // Optionally generate proof (commented out for speed)
            // generate_proof(&result)?;
        }
        Err(e) => {
            println!("\nExecution error: {}", e);
            println!("\nThis is expected if the binary requires more witness data.");
            println!("For a complete execution, provide proper block/transaction data.");
        }
    }

    Ok(())
}

/// Run a demo without an actual ZKsync OS binary.
fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Demo Mode ===\n");
    println!("This demo shows the API without an actual ZKsync OS binary.\n");

    // Demonstrate oracle/witness creation
    println!("1. Creating oracle data...");
    let block_context = BlockContext {
        block_number: 12345,
        timestamp: 1700000000,
        gas_limit: 30_000_000,
        coinbase: [
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        base_fee: 1_000_000_000, // 1 gwei
        chain_id: 324,
        ..Default::default()
    };

    let oracle = OracleBuilder::new()
        .with_block_context(&block_context)
        .build();

    println!("   Block number: {}", block_context.block_number);
    println!("   Timestamp: {}", block_context.timestamp);
    println!("   Chain ID: {}", block_context.chain_id);
    println!("   Oracle words: {}", oracle.len());

    // Demonstrate witness builder
    println!("\n2. Building witness...");
    let witness = WitnessBuilder::new()
        .with_block_context(block_context)
        .push(0x12345678) // Some additional data
        .push_u64(0xDEADBEEFCAFEBABE)
        .push_bytes(&[1, 2, 3, 4, 5, 6, 7, 8])
        .build();

    println!("   Witness size: {} words", witness.len());

    // Show how to convert to oracle
    let oracle = witness.to_oracle();
    println!("   Oracle created with {} words", oracle.len());

    // Demonstrate config options
    println!("\n3. Run configurations:");
    println!("   Default: {:?} cycles", RunConfig::default().max_cycles);
    println!(
        "   Testing: {:?} cycles",
        RunConfig::for_testing().max_cycles
    );
    println!(
        "   Proving: {:?} cycles",
        RunConfig::for_proving().max_cycles
    );

    // Demonstrate program output
    println!("\n4. Program output format:");
    let output = ProgramOutput([1, 2, 3, 4, 5, 6, 7, 8]);
    println!("   Raw: {:?}", output.0);
    println!("   Hex: {}", output.to_hex());
    println!("   Is success: {}", output.is_success());

    let zero_output = ProgramOutput::zero();
    println!("   Zero output is success: {}", zero_output.is_success());

    // Show prover config
    println!("\n5. Prover configurations:");
    let cpu_config = ProverConfig::with_cpu(8);
    println!("   CPU threads: {}", cpu_config.num_threads);

    let gpu_config = ProverConfig::with_gpu();
    println!("   GPU enabled: {}", gpu_config.use_gpu);

    println!("\n=== Demo Complete ===");
    println!("\nTo run with an actual ZKsync OS binary:");
    println!("1. Clone https://github.com/matter-labs/zksync-os");
    println!("2. Build: cd zksync_os && ./dump_bin.sh --type for-tests");
    println!("3. Set ZKSYNC_OS_BIN=path/to/for_tests.bin");
    println!("4. Re-run this example");

    Ok(())
}

/// Generate a proof from execution result (optional).
#[allow(dead_code)]
fn generate_proof(result: &zp1_zksync_os::RunResult) -> Result<(), Box<dyn std::error::Error>> {
    if !result.trace.is_some() {
        println!("No trace available for proof generation");
        return Ok(());
    }

    println!("\nGenerating proof...");
    let prover = ZkSyncOsProver::new(ProverConfig::with_cpu(rayon::current_num_threads()));

    // Compute binary hash (you would use the actual binary hash)
    let binary_hash = [0u8; 32];

    let start = std::time::Instant::now();
    let proof = prover.prove(result, binary_hash)?;
    let elapsed = start.elapsed();

    println!("Proof generated in {:?}", elapsed);
    println!("Verifying proof...");

    let valid = ZkSyncOsVerifier::verify(&proof)?;
    println!("Proof valid: {}", valid);

    // Save proof
    proof.save(Path::new("zksync_os_proof.json"))?;
    println!("Proof saved to zksync_os_proof.json");

    Ok(())
}
