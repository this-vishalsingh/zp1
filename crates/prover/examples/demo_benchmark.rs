//! ZP1 Prover Benchmark
//! 
//! Compares sequential vs parallel proving performance.

use std::time::Instant;
use zp1_primitives::M31;
use zp1_prover::{StarkConfig, StarkProver};

fn main() {
    println!("ZP1 Prover Benchmark\n");

    // Configuration: small trace for quick testing
    let log_trace_len = 10; // 1024 rows (use 8 for faster demo)
    let trace_len = 1 << log_trace_len;
    let num_cols = 77;
    
    let config = StarkConfig {
        log_trace_len,
        blowup_factor: 4,
        num_queries: 10,
        fri_folding_factor: 2,
        security_bits: 80,
        entry_point: 0x1000,
    };
    
    println!("Config: {} rows × {} cols, {}x blowup", trace_len, num_cols, config.blowup_factor);

    // Generate trace with valid range-checked values
    let trace_columns: Vec<Vec<M31>> = (0..num_cols)
        .map(|col| {
            (0..trace_len)
                .map(|row| M31::new(((row + col) % 60000) as u32))
                .collect()
        })
        .collect();

    let public_inputs = vec![M31::new(0x1000)];

    // Sequential
    let mut prover = StarkProver::new(config.clone());
    prover.enable_range_checks();
    
    let t0 = Instant::now();
    let proof = prover.prove(trace_columns.clone(), &public_inputs);
    let seq_time = t0.elapsed();

    // Parallel  
    let mut prover = StarkProver::new(config);
    prover.enable_range_checks();
    prover.enable_parallel();
    
    let t0 = Instant::now();
    let _proof_par = prover.prove(trace_columns, &public_inputs);
    let par_time = t0.elapsed();

    // Results
    println!("\nSequential: {:?}", seq_time);
    println!("Parallel:   {:?}", par_time);
    println!("Speedup:    {:.2}x", seq_time.as_secs_f64() / par_time.as_secs_f64());
    println!("\nProof: {} FRI layers, {} queries", 
        proof.fri_proof.layer_commitments.len(),
        proof.query_proofs.len()
    );
}
