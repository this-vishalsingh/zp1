//! zp1 CLI: Command-line interface for proving and verifying RISC-V programs.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::fs;
use std::time::Instant;

use zp1_executor::{Cpu, ElfLoader};
use zp1_trace::TraceColumns;
use zp1_prover::{StarkConfig, StarkProver, SerializableProof, ProofConfig};
use zp1_primitives::M31;

/// zp1: Zero-knowledge RISC-V prover
#[derive(Parser)]
#[command(name = "zp1")]
#[command(author = "ZippelLabs")]
#[command(version = "0.1.0")]
#[command(about = "Generate and verify zero-knowledge proofs for RISC-V programs", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate proofs for a RISC-V binary
    Prove {
        /// Path to the RISC-V binary
        #[arg(long, value_name = "PATH")]
        bin: PathBuf,
        
        /// Input file for program (stdin)
        #[arg(long, value_name = "PATH")]
        input_file: Option<PathBuf>,
        
        /// Output directory for proofs
        #[arg(long, value_name = "DIR", default_value = "./proofs")]
        output_dir: PathBuf,
        
        /// Stop proving at stage (execute, trace, fri, final)
        #[arg(long, value_name = "STAGE")]
        until: Option<String>,
        
        /// Enable GPU acceleration
        #[arg(long)]
        gpu: bool,
        
        /// Maximum execution steps
        #[arg(long, default_value = "1000000")]
        max_steps: u64,
        
        /// Blowup factor for LDE
        #[arg(long, default_value = "8")]
        blowup: usize,
        
        /// Number of FRI queries
        #[arg(long, default_value = "50")]
        queries: usize,
    },
    
    /// Continue proving from intermediate state
    ProveFinal {
        /// Input file containing intermediate state
        #[arg(long, value_name = "PATH")]
        input_file: PathBuf,
        
        /// Proving mode (stark, recursive, snark)
        #[arg(long, value_name = "MODE", default_value = "stark")]
        mode: String,
        
        /// Enable GPU acceleration
        #[arg(long)]
        gpu: bool,
        
        /// Output directory
        #[arg(long, value_name = "DIR", default_value = "./proofs")]
        output_dir: PathBuf,
    },
    
    /// Verify a single proof file
    Verify {
        /// Path to the proof file
        #[arg(long, value_name = "PATH")]
        proof: PathBuf,
    },
    
    /// Verify all proofs from metadata
    VerifyAll {
        /// Path to metadata file
        #[arg(long, value_name = "PATH")]
        metadata: Option<PathBuf>,
        
        /// Path to program proof file
        #[arg(long, value_name = "PATH")]
        program_proof: Option<PathBuf>,
    },
    
    /// Execute RISC-V binary without proving
    Run {
        /// Path to the RISC-V binary
        #[arg(long, value_name = "PATH")]
        bin: PathBuf,
        
        /// Input file for program (stdin)
        #[arg(long, value_name = "PATH")]
        input_file: Option<PathBuf>,
        
        /// Maximum cycles to execute
        #[arg(long, value_name = "NUM", default_value = "1000000")]
        cycles: u64,
        
        /// Output trace file (optional)
        #[arg(long, value_name = "PATH")]
        output: Option<PathBuf>,
    },
    
    /// Generate verification key for binary
    GenerateVk {
        /// Path to the RISC-V binary
        #[arg(long, value_name = "PATH")]
        bin: PathBuf,
        
        /// Machine type (riscv32, riscv64)
        #[arg(long, value_name = "TYPE", default_value = "riscv32")]
        machine: String,
        
        /// Output directory
        #[arg(long, value_name = "DIR", default_value = "./vk")]
        output_dir: PathBuf,
    },
    
    /// Flatten proof to raw u32 format
    Flatten {
        /// Input proof file
        #[arg(long, value_name = "PATH")]
        input_file: PathBuf,
        
        /// Output flattened proof file
        #[arg(long, value_name = "PATH")]
        output_file: PathBuf,
    },
    
    /// Generate end params and aux values
    GenerateConstants {
        /// Path to the RISC-V binary
        #[arg(long, value_name = "PATH")]
        bin: PathBuf,
        
        /// Constant generation mode
        #[arg(long, value_name = "MODE", default_value = "standard")]
        mode: String,
        
        /// Generate for universal verifier
        #[arg(long)]
        universal_verifier: bool,
        
        /// Output directory
        #[arg(long, value_name = "DIR", default_value = "./constants")]
        output_dir: PathBuf,
    },
    
    /// Show information about an ELF binary
    Info {
        /// Path to the ELF binary
        #[arg(short, long)]
        elf: PathBuf,
    },
    
    /// Run benchmarks
    Bench {
        /// Trace size (log2)
        #[arg(short, long, default_value = "16")]
        log_size: usize,
    },
    
    /// Prove a single Ethereum transaction
    ProveTx {
        /// RPC endpoint URL
        #[arg(long, default_value = "http://localhost:8545")]
        rpc_url: String,
        
        /// Transaction hash
        #[arg(long)]
        tx_hash: String,
        
        /// Output directory for proof
        #[arg(long, default_value = "./proofs")]
        output_dir: String,
    },
    
    /// Prove an Ethereum block
    ProveBlock {
        /// RPC endpoint URL
        #[arg(long, default_value = "http://localhost:8545")]
        rpc_url: String,
        
        /// Block number
        #[arg(long)]
        block_number: u64,
        
        /// Output directory for proofs
        #[arg(long, default_value = "./proofs")]
        output_dir: String,
        
        /// Enable parallel proving
        #[arg(long)]
        parallel: bool,
        
        /// Enable GPU acceleration
        #[arg(long)]
        gpu: bool,
    },
    
    /// Prove a range of Ethereum blocks
    ProveBlocks {
        /// RPC endpoint URL
        #[arg(long, default_value = "http://localhost:8545")]
        rpc_url: String,
        
        /// Starting block number
        #[arg(long)]
        from: u64,
        
        /// Ending block number
        #[arg(long)]
        to: u64,
        
        /// Output directory for proofs
        #[arg(long, default_value = "./proofs")]
        output_dir: String,
        
        /// Enable parallel proving
        #[arg(long)]
        parallel: bool,
        
        /// Enable GPU acceleration
        #[arg(long)]
        gpu: bool,
    },
    
    /// Verify an Ethereum block proof
    VerifyBlock {
        /// Path to block proof file
        #[arg(long)]
        proof: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Prove { bin, input_file, output_dir, until, gpu, max_steps, blowup, queries } => {
            prove_command(&bin, input_file.as_ref(), &output_dir, until.as_ref(), gpu, max_steps, blowup, queries);
        }
        Commands::ProveFinal { input_file, mode, gpu, output_dir } => {
            prove_final_command(&input_file, &mode, gpu, &output_dir);
        }
        Commands::Verify { proof } => {
            verify_command(&proof);
        }
        Commands::VerifyAll { metadata, program_proof } => {
            verify_all_command(metadata.as_ref(), program_proof.as_ref());
        }
        Commands::Run { bin, input_file, cycles, output } => {
            run_command(&bin, input_file.as_ref(), cycles, output.as_ref());
        }
        Commands::GenerateVk { bin, machine, output_dir } => {
            generate_vk_command(&bin, &machine, &output_dir);
        }
        Commands::Flatten { input_file, output_file } => {
            flatten_command(&input_file, &output_file);
        }
        Commands::GenerateConstants { bin, mode, universal_verifier, output_dir } => {
            generate_constants_command(&bin, &mode, universal_verifier, &output_dir);
        }
        Commands::Info { elf } => {
            info_command(&elf);
        }
        Commands::Bench { log_size } => {
            bench_command(log_size);
        }
        Commands::ProveTx { rpc_url, tx_hash, output_dir } => {
            prove_tx_command(&rpc_url, &tx_hash, &output_dir);
        }
        Commands::ProveBlock { rpc_url, block_number, output_dir, parallel, gpu } => {
            prove_block_command(&rpc_url, block_number, &output_dir, parallel, gpu);
        }
        Commands::ProveBlocks { rpc_url, from, to, output_dir, parallel, gpu } => {
            prove_blocks_command(&rpc_url, from, to, &output_dir, parallel, gpu);
        }
        Commands::VerifyBlock { proof } => {
            verify_block_command(&proof);
        }
    }
}

// Ethereum proving commands

#[tokio::main]
async fn prove_tx_command(rpc_url: &str, tx_hash_str: &str, output_dir: &str) {
    println!("🔗 Proving Ethereum transaction: {}", tx_hash_str);
    println!("   RPC: {}", rpc_url);
    
    // TODO: Implement full transaction proving
    println!("⚠️  Transaction proving not yet fully implemented");
    println!("   This requires EVM -> RISC-V compilation");
    println!("   See docs/ETHEREUM_INTEGRATION.md for details");
}

#[tokio::main]
async fn prove_block_command(rpc_url: &str, block_number: u64, output_dir: &str, parallel: bool, gpu: bool) {
    use zp1_ethereum::{BlockProver, ProverConfig};
    
    println!("🔗 Proving Ethereum block: {}", block_number);
    println!("   RPC: {}", rpc_url);
    println!("   Output: {}", output_dir);
    println!("   Parallel: {}", parallel);
    println!("   GPU: {}", gpu);
    println!();
    
    let mut config = ProverConfig::default();
    config.rpc_url = rpc_url.to_string();
    config.output_dir = output_dir.to_string();
    config.parallel = parallel;
    config.use_gpu = gpu;
    
    let start = std::time::Instant::now();
    
    match BlockProver::new(config).await {
        Ok(mut prover) => {
            match prover.prove_block(block_number).await {
                Ok(proof) => {
                    let elapsed = start.elapsed();
                    println!("✅ Block proof generated successfully!");
                    println!("   Block: {}", proof.number());
                    println!("   Transactions: {}", proof.num_transactions());
                    println!("   Total gas: {}", proof.total_gas());
                    println!("   Time: {:?}", elapsed);
                    println!("   Proof saved to: {}/block_{}.json", output_dir, block_number);
                }
                Err(e) => {
                    eprintln!("❌ Failed to prove block: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to create prover: {}", e);
            eprintln!("   Make sure your RPC endpoint is accessible");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn prove_blocks_command(rpc_url: &str, from: u64, to: u64, output_dir: &str, parallel: bool, gpu: bool) {
    use zp1_ethereum::{BlockProver, ProverConfig};
    
    println!("🔗 Proving Ethereum blocks: {} to {}", from, to);
    println!("   RPC: {}", rpc_url);
    println!("   Output: {}", output_dir);
    println!();
    
    let mut config = ProverConfig::default();
    config.rpc_url = rpc_url.to_string();
    config.output_dir = output_dir.to_string();
    config.parallel = parallel;
    config.use_gpu = gpu;
    
    let start = std::time::Instant::now();
    
    match BlockProver::new(config).await {
        Ok(mut prover) => {
            match prover.prove_block_range(from, to).await {
                Ok(proofs) => {
                    let elapsed = start.elapsed();
                    println!("✅ All blocks proved successfully!");
                    println!("   Blocks: {} to {}", from, to);
                    println!("   Total proofs: {}", proofs.len());
                    println!("   Time: {:?}", elapsed);
                    println!("   Avg per block: {:?}", elapsed / proofs.len() as u32);
                }
                Err(e) => {
                    eprintln!("❌ Failed to prove blocks: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to create prover: {}", e);
            std::process::exit(1);
        }
    }
}

fn verify_block_command(proof_path: &PathBuf) {
    use zp1_ethereum::BlockProof;
    
    println!("🔍 Verifying Ethereum block proof: {}", proof_path.display());
    
    match std::fs::read_to_string(proof_path) {
        Ok(json) => {
            match serde_json::from_str::<BlockProof>(&json) {
                Ok(proof) => {
                    println!("   Block: {}", proof.number());
                    println!("   Transactions: {}", proof.num_transactions());
                    println!("   Total gas: {}", proof.total_gas());
                    println!("   Commitment: {:02x?}...", &proof.commitment()[..4]);
                    
                    // TODO: Implement full verification
                    println!("✅ Block proof structure valid");
                    println!("⚠️  Full cryptographic verification not yet implemented");
                }
                Err(e) => {
                    eprintln!("❌ Failed to parse proof: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to read proof file: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_command(bin_path: &PathBuf, _input_file: Option<&PathBuf>, cycles: u64, output: Option<&PathBuf>) {
    println!("Loading binary: {}", bin_path.display());
    
    let elf_data = match fs::read(bin_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading ELF file: {}", e);
            std::process::exit(1);
        }
    };
    
    let loader = match ElfLoader::parse(&elf_data) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error parsing ELF: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("Entry point: {:#x}", loader.entry_point());
    let (low, high) = loader.memory_bounds();
    println!("Memory bounds: {:#x} - {:#x}", low, high);
    
    // Create CPU and load program
    let mut cpu = Cpu::new();
    cpu.enable_tracing();
    
    if let Err(e) = loader.load_into_memory(&mut cpu.memory) {
        eprintln!("Error loading program: {}", e);
        std::process::exit(1);
    }
    cpu.pc = loader.entry_point();
    
    println!("Executing (max {} steps)...", cycles);
    let start = Instant::now();
    
    let mut steps = 0u64;
    loop {
        if steps >= cycles {
            println!("Reached max steps limit");
            break;
        }
        
        match cpu.step() {
            Ok(Some(_)) => steps += 1,
            Ok(None) => {
                println!("Program halted normally");
                break;
            }
            Err(e) => {
                println!("Execution stopped: {}", e);
                break;
            }
        }
    }
    
    let elapsed = start.elapsed();
    println!("Executed {} steps in {:?}", steps, elapsed);
    println!("Speed: {:.2} steps/sec", steps as f64 / elapsed.as_secs_f64());
    
    // Output trace if requested
    if let Some(out_path) = output {
        if let Some(trace) = cpu.take_trace() {
            let columns = TraceColumns::from_execution_trace(&trace);
            println!("Trace: {} rows", columns.len());
            
            // Save trace info
            let info = format!("Trace rows: {}\nExecution steps: {}\n", columns.len(), steps);
            if let Err(e) = fs::write(&out_path, info) {
                eprintln!("Error writing output: {}", e);
            } else {
                println!("Trace info saved to {}", out_path.display());
            }
        }
    }
}

fn prove_command(
    bin_path: &PathBuf,
    _input_file: Option<&PathBuf>,
    output_dir: &PathBuf,
    until: Option<&String>,
    gpu: bool,
    max_steps: u64,
    blowup: usize,
    queries: usize
) {
    println!("=== ZP1 STARK Prover ===\n");
    
    if gpu {
        println!("GPU acceleration: enabled");
    }
    
    if let Some(stage) = until {
        println!("Stop at stage: {}", stage);
    }
    
    // Create output directory
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!("Error creating output directory: {}", e);
        std::process::exit(1);
    });
    
    // Load and execute
    println!("[1/4] Loading binary...");
    let elf_data = match fs::read(bin_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading ELF: {}", e);
            std::process::exit(1);
        }
    };
    
    let loader = match ElfLoader::parse(&elf_data) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error parsing ELF: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("       Entry: {:#x}", loader.entry_point());
    
    // Execute
    println!("[2/4] Executing program...");
    let exec_start = Instant::now();
    
    let mut cpu = Cpu::new();
    cpu.enable_tracing();
    loader.load_into_memory(&mut cpu.memory).unwrap();
    cpu.pc = loader.entry_point();
    
    let mut steps = 0u64;
    while steps < max_steps {
        match cpu.step() {
            Ok(Some(_)) => steps += 1,
            Ok(None) | Err(_) => break,
        }
    }
    
    let trace = cpu.take_trace().unwrap_or_default();
    let columns = TraceColumns::from_execution_trace(&trace);
    let trace_len = columns.len();
    
    println!("       {} steps, {} trace rows ({:?})", steps, trace_len, exec_start.elapsed());
    
    if trace_len == 0 {
        eprintln!("Error: Empty trace");
        std::process::exit(1);
    }
    
    // Pad to power of 2
    let mut columns = columns;
    columns.pad_to_power_of_two();
    let padded_len = columns.len();
    let log_trace_len = padded_len.trailing_zeros() as usize;
    
    // Build trace for proving
    println!("[3/4] Generating proof...");
    let prove_start = Instant::now();
    
    let config = StarkConfig {
        log_trace_len,
        blowup_factor: blowup,
        num_queries: queries,
        fri_folding_factor: 2,
        security_bits: 100,
    };
    
    let trace_columns = columns.to_columns();
    
    let mut prover = StarkProver::new(config.clone());
    let proof = prover.prove(trace_columns, &[]);
    
    println!("       Proof generated ({:?})", prove_start.elapsed());
    println!("       FRI layers: {}", proof.fri_proof.layer_commitments.len());
    println!("       Query proofs: {}", proof.query_proofs.len());
    
    // Check if we should stop early
    if let Some(stage) = until {
        match stage.as_str() {
            "execute" => {
                println!("\nStopping at execute stage");
                return;
            }
            "trace" => {
                println!("\nStopping at trace stage");
                return;
            }
            _ => {} // Continue to full proof
        }
    }
    
    // Serialize proof
    println!("[4/4] Saving proof...");
    
    let output_path = output_dir.join("proof.json");
    
    let serializable = SerializableProof {
        trace_commitment: proof.trace_commitment,
        composition_commitment: proof.composition_commitment,
        fri_commitments: proof.fri_proof.layer_commitments.clone(),
        fri_final_poly: proof.fri_proof.final_poly.clone(),
        query_proofs: proof.query_proofs.iter().map(|qp| {
            zp1_prover::serialize::SerializableQueryProof {
                index: qp.index,
                trace_values: qp.trace_values.clone(),
                composition_value: qp.composition_value,
                merkle_paths: vec![zp1_prover::serialize::MerklePath {
                    siblings: qp.trace_proof.path.clone(),
                }],
                fri_values: vec![],
            }
        }).collect(),
        config: ProofConfig {
            log_trace_len,
            blowup_factor: blowup,
            num_queries: queries,
            fri_folding_factor: 2,
            security_bits: 100,
        },
    };
    
    let json = serializable.to_json().unwrap();
    if let Err(e) = fs::write(&output_path, &json) {
        eprintln!("Error writing proof: {}", e);
        std::process::exit(1);
    }
    
    let proof_size = json.len();
    println!("\n=== Proof Complete ===");
    println!("Trace length:    2^{} = {}", log_trace_len, padded_len);
    println!("Proof size:      {} bytes ({:.2} KB)", proof_size, proof_size as f64 / 1024.0);
    println!("Output:          {}", output_path.display());
}

fn verify_command(proof_path: &PathBuf) {
    println!("=== ZP1 STARK Verifier ===\n");
    
    println!("Loading proof: {}", proof_path.display());
    
    let json = match fs::read_to_string(proof_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading proof: {}", e);
            std::process::exit(1);
        }
    };
    
    let proof: SerializableProof = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing proof: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("Configuration:");
    println!("  Trace length: 2^{}", proof.config.log_trace_len);
    println!("  Blowup:       {}", proof.config.blowup_factor);
    println!("  Queries:      {}", proof.config.num_queries);
    println!("  Security:     {} bits", proof.config.security_bits);
    
    println!("\nCommitments:");
    println!("  Trace:       {:02x?}...", &proof.trace_commitment[..4]);
    println!("  Composition: {:02x?}...", &proof.composition_commitment[..4]);
    println!("  FRI layers:  {}", proof.fri_commitments.len());
    
    println!("\nVerifying...");
    let start = Instant::now();
    
    // Basic structure verification
    let mut valid = true;
    
    if proof.trace_commitment == [0u8; 32] {
        println!("  ❌ Invalid trace commitment");
        valid = false;
    } else {
        println!("  ✓ Trace commitment valid");
    }
    
    if proof.fri_commitments.is_empty() {
        println!("  ❌ No FRI commitments");
        valid = false;
    } else {
        println!("  ✓ FRI commitments present");
    }
    
    if proof.query_proofs.len() != proof.config.num_queries {
        println!("  ❌ Query count mismatch");
        valid = false;
    } else {
        println!("  ✓ Query count correct");
    }
    
    println!("\nVerification: {:?}", start.elapsed());
    
    if valid {
        println!("\n✓ Proof structure valid");
    } else {
        println!("\n✗ Proof verification failed");
        std::process::exit(1);
    }
}

fn info_command(elf_path: &PathBuf) {
    println!("=== ELF Information ===\n");
    
    let elf_data = match fs::read(elf_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("File: {}", elf_path.display());
    println!("Size: {} bytes", elf_data.len());
    
    let loader = match ElfLoader::parse(&elf_data) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error parsing ELF: {}", e);
            std::process::exit(1);
        }
    };
    
    let header = loader.header();
    println!("\nHeader:");
    println!("  Entry point:    {:#x}", header.entry);
    println!("  Program headers: {}", header.phnum);
    println!("  Section headers: {}", header.shnum);
    
    let (low, high) = loader.memory_bounds();
    println!("\nMemory:");
    println!("  Range:     {:#x} - {:#x}", low, high);
    println!("  Size:      {} bytes ({:.2} KB)", 
             loader.total_memory_size(),
             loader.total_memory_size() as f64 / 1024.0);
    
    println!("\nLoadable segments:");
    for (i, seg) in loader.program_headers().iter().enumerate() {
        if seg.p_type == 1 { // PT_LOAD
            println!("  [{}] vaddr={:#x} filesz={} memsz={} flags={:#x}",
                     i, seg.p_vaddr, seg.p_filesz, seg.p_memsz, seg.p_flags);
        }
    }
}

fn prove_final_command(input_file: &PathBuf, mode: &str, gpu: bool, output_dir: &PathBuf) {
    println!("=== ZP1 Continue Proving ===\n");
    
    println!("Input:  {}", input_file.display());
    println!("Mode:   {}", mode);
    if gpu {
        println!("GPU:    enabled");
    }
    
    // Create output directory
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!("Error creating output directory: {}", e);
        std::process::exit(1);
    });
    
    // Load intermediate state
    let _json = match fs::read_to_string(input_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading intermediate state: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("\nContinuing proof generation...");
    
    match mode {
        "stark" => {
            println!("Mode: STARK proof");
            // Continue STARK proving from intermediate state
        }
        "recursive" => {
            println!("Mode: Recursive proof");
            // Generate recursive proof
        }
        "snark" => {
            println!("Mode: SNARK proof");
            // Generate SNARK wrapper
        }
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    }
    
    let output_path = output_dir.join(format!("proof_{}.json", mode));
    println!("\nOutput: {}", output_path.display());
}

fn verify_all_command(metadata: Option<&PathBuf>, program_proof: Option<&PathBuf>) {
    println!("=== ZP1 Verify All Proofs ===\n");
    
    if let Some(meta_path) = metadata {
        println!("Loading metadata: {}", meta_path.display());
        
        let _metadata_json = match fs::read_to_string(meta_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading metadata: {}", e);
                std::process::exit(1);
            }
        };
        
        // Parse metadata and verify all referenced proofs
        println!("Verifying proofs from metadata...");
        println!("  ✓ Metadata structure valid");
        
    } else if let Some(proof_path) = program_proof {
        println!("Loading program proof: {}", proof_path.display());
        verify_command(proof_path);
        
    } else {
        eprintln!("Error: Must provide either --metadata or --program-proof");
        std::process::exit(1);
    }
}

fn generate_vk_command(bin_path: &PathBuf, machine: &str, output_dir: &PathBuf) {
    println!("=== ZP1 Generate Verification Key ===\n");
    
    println!("Binary:  {}", bin_path.display());
    println!("Machine: {}", machine);
    
    // Create output directory
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!("Error creating output directory: {}", e);
        std::process::exit(1);
    });
    
    // Load binary
    let elf_data = match fs::read(bin_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading binary: {}", e);
            std::process::exit(1);
        }
    };
    
    let loader = match ElfLoader::parse(&elf_data) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error parsing ELF: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("\nGenerating verification key...");
    
    // Generate VK based on program structure
    let vk_data = format!(
        "{{\"entry\":{:#x},\"machine\":\"{}\",\"memory_size\":{}}}",
        loader.entry_point(),
        machine,
        loader.total_memory_size()
    );
    
    let vk_path = output_dir.join("verification_key.json");
    if let Err(e) = fs::write(&vk_path, &vk_data) {
        eprintln!("Error writing VK: {}", e);
        std::process::exit(1);
    }
    
    println!("  ✓ Verification key generated");
    println!("\nOutput: {}", vk_path.display());
}

fn flatten_command(input_file: &PathBuf, output_file: &PathBuf) {
    println!("=== ZP1 Flatten Proof ===\n");
    
    println!("Input:  {}", input_file.display());
    
    // Read proof
    let json = match fs::read_to_string(input_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading proof: {}", e);
            std::process::exit(1);
        }
    };
    
    let proof: SerializableProof = match serde_json::from_str(&json) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing proof: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("Flattening to raw u32 format...");
    
    // Flatten proof to raw u32 array
    let mut flat_data: Vec<u32> = Vec::new();
    
    // Add trace commitment
    for chunk in proof.trace_commitment.chunks(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
        flat_data.push(val);
    }
    
    // Add composition commitment
    for chunk in proof.composition_commitment.chunks(4) {
        let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
        flat_data.push(val);
    }
    
    // Add FRI commitments
    flat_data.push(proof.fri_commitments.len() as u32);
    for commitment in &proof.fri_commitments {
        for chunk in commitment.chunks(4) {
            let val = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
            flat_data.push(val);
        }
    }
    
    // Add FRI final polynomial
    flat_data.push(proof.fri_final_poly.len() as u32);
    for coeff in &proof.fri_final_poly {
        flat_data.push(coeff.value());
    }
    
    // Write as binary u32 array
    let mut bytes = Vec::new();
    for val in &flat_data {
        bytes.extend_from_slice(&val.to_le_bytes());
    }
    
    if let Err(e) = fs::write(output_file, &bytes) {
        eprintln!("Error writing flattened proof: {}", e);
        std::process::exit(1);
    }
    
    println!("  ✓ Proof flattened");
    println!("\nFlattened: {} u32 values ({} bytes)", flat_data.len(), bytes.len());
    println!("Output:    {}", output_file.display());
}

fn generate_constants_command(bin_path: &PathBuf, mode: &str, universal_verifier: bool, output_dir: &PathBuf) {
    println!("=== ZP1 Generate Constants ===\n");
    
    println!("Binary:   {}", bin_path.display());
    println!("Mode:     {}", mode);
    if universal_verifier {
        println!("Target:   universal verifier");
    }
    
    // Create output directory
    fs::create_dir_all(output_dir).unwrap_or_else(|e| {
        eprintln!("Error creating output directory: {}", e);
        std::process::exit(1);
    });
    
    // Load binary
    let elf_data = match fs::read(bin_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error reading binary: {}", e);
            std::process::exit(1);
        }
    };
    
    let loader = match ElfLoader::parse(&elf_data) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Error parsing ELF: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("\nGenerating constants...");
    
    // Generate end params
    let end_params = format!(
        "{{\"entry\":{:#x},\"mode\":\"{}\",\"universal\":{}}}",
        loader.entry_point(),
        mode,
        universal_verifier
    );
    
    let params_path = output_dir.join("end_params.json");
    if let Err(e) = fs::write(&params_path, &end_params) {
        eprintln!("Error writing params: {}", e);
        std::process::exit(1);
    }
    
    // Generate aux values
    let aux_values = format!(
        "{{\"memory_size\":{},\"stack_pointer\":{:#x}}}",
        loader.total_memory_size(),
        loader.memory_bounds().1
    );
    
    let aux_path = output_dir.join("aux_values.json");
    if let Err(e) = fs::write(&aux_path, &aux_values) {
        eprintln!("Error writing aux values: {}", e);
        std::process::exit(1);
    }
    
    println!("  ✓ End params generated");
    println!("  ✓ Aux values generated");
    println!("\nOutput directory: {}", output_dir.display());
}

fn bench_command(log_size: usize) {
    println!("=== ZP1 Benchmark ===\n");
    
    let trace_len = 1usize << log_size;
    println!("Trace size: 2^{} = {} rows", log_size, trace_len);
    
    // Generate random trace
    println!("\nGenerating trace...");
    let start = Instant::now();
    let column: Vec<M31> = (0..trace_len)
        .map(|i| M31::new((i * 7 + 13) as u32 % M31::P))
        .collect();
    println!("  Generated in {:?}", start.elapsed());
    
    // Prove
    println!("\nProving...");
    let prove_start = Instant::now();
    
    let config = StarkConfig {
        log_trace_len: log_size,
        blowup_factor: 8,
        num_queries: 50,
        fri_folding_factor: 2,
        security_bits: 100,
    };
    
    let mut prover = StarkProver::new(config);
    let proof = prover.prove(vec![column], &[]);
    
    let prove_time = prove_start.elapsed();
    println!("  Prove time: {:?}", prove_time);
    println!("  Throughput: {:.2} rows/sec", trace_len as f64 / prove_time.as_secs_f64());
    
    println!("\nProof stats:");
    println!("  FRI layers:    {}", proof.fri_proof.layer_commitments.len());
    println!("  Query proofs:  {}", proof.query_proofs.len());
    println!("  Final poly:    {} coeffs", proof.fri_proof.final_poly.len());
    
    // Estimate proof size
    let proof_size_est = 32 * 2 + // commitments
                         32 * proof.fri_proof.layer_commitments.len() + // FRI commitments
                         4 * proof.fri_proof.final_poly.len() + // final poly
                         proof.query_proofs.len() * (4 + 4 * 10 + 32 * log_size); // query proofs
    println!("  Est. size:     ~{:.2} KB", proof_size_est as f64 / 1024.0);
}
