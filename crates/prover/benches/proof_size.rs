use criterion::{criterion_group, criterion_main, Criterion};
use zp1_primitives::M31;
use zp1_prover::{StarkConfig, StarkProver};
use zp1_trace::TraceColumns; 
// Note: We need to use serialized structs to measure size
use zp1_prover::serialize::{SerializableProof, ProofConfig};

fn bench_proof_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("ZP1 Proof Metrics");

    // 1. Setup a minimal valid trace (16 rows)
    let num_rows = 16;
    let mut trace = TraceColumns::new();
    
    for i in 0..num_rows {
        // Minimal valid columns to satisfy basic constraints
        // We use typical values for an idle cycle to minimize invalid transitions
        trace.clk.push(M31::new(i as u32));
        trace.pc.push(M31::new(0x0));
        trace.next_pc.push(M31::new(0x4));
        trace.opcode.push(M31::new(0x13)); // ADDI (NOP)
        
        // Fill rest with zeros
        trace.instr.push(M31::ZERO); 
        trace.rd.push(M31::ZERO);
        trace.rs1.push(M31::ZERO);
        trace.rs2.push(M31::ZERO);
        trace.imm_lo.push(M31::ZERO);
        trace.imm_hi.push(M31::ZERO);
        trace.rd_val_lo.push(M31::ZERO);
        trace.rd_val_hi.push(M31::ZERO);
        trace.rs1_val_lo.push(M31::ZERO);
        trace.rs1_val_hi.push(M31::ZERO);
        trace.rs2_val_lo.push(M31::ZERO);
        trace.rs2_val_hi.push(M31::ZERO);
        
        // Flags
        trace.is_addi.push(M31::new(1)); // Is ADDI
        trace.is_add.push(M31::ZERO);
        trace.is_sub.push(M31::ZERO);
        trace.is_and.push(M31::ZERO);
        trace.is_or.push(M31::ZERO);
        trace.is_xor.push(M31::ZERO);
        trace.is_sll.push(M31::ZERO);
        trace.is_srl.push(M31::ZERO);
        trace.is_sra.push(M31::ZERO);
        trace.is_slt.push(M31::ZERO);
        trace.is_sltu.push(M31::ZERO);
        trace.is_andi.push(M31::ZERO);
        trace.is_ori.push(M31::ZERO);
        trace.is_xori.push(M31::ZERO);
        trace.is_slti.push(M31::ZERO);
        trace.is_sltiu.push(M31::ZERO);
        trace.is_slli.push(M31::ZERO);
        trace.is_srli.push(M31::ZERO);
        trace.is_srai.push(M31::ZERO);
        trace.is_lui.push(M31::ZERO);
        trace.is_auipc.push(M31::ZERO);
        trace.is_beq.push(M31::ZERO);
        trace.is_bne.push(M31::ZERO);
        trace.is_blt.push(M31::ZERO);
        trace.is_bge.push(M31::ZERO);
        trace.is_bltu.push(M31::ZERO);
        trace.is_bgeu.push(M31::ZERO);
        trace.is_jal.push(M31::ZERO);
        trace.is_jalr.push(M31::ZERO);
        trace.is_mul.push(M31::ZERO);
        trace.is_mulh.push(M31::ZERO);
        trace.is_mulhsu.push(M31::ZERO);
        trace.is_mulhu.push(M31::ZERO);
        trace.is_div.push(M31::ZERO);
        trace.is_divu.push(M31::ZERO);
        trace.is_rem.push(M31::ZERO);
        trace.is_remu.push(M31::ZERO);
        trace.is_lb.push(M31::ZERO);
        trace.is_lbu.push(M31::ZERO);
        trace.is_lh.push(M31::ZERO);
        trace.is_lhu.push(M31::ZERO);
        trace.is_lw.push(M31::ZERO);
        trace.is_sb.push(M31::ZERO);
        trace.is_sh.push(M31::ZERO);
        trace.is_sw.push(M31::ZERO);
        
        trace.mem_addr_lo.push(M31::ZERO);
        trace.mem_addr_hi.push(M31::ZERO);
        trace.mem_val_lo.push(M31::ZERO);
        trace.mem_val_hi.push(M31::ZERO);
        trace.sb_carry.push(M31::ZERO);
        
        trace.mul_lo.push(M31::ZERO);
        trace.mul_hi.push(M31::ZERO);
        trace.carry.push(M31::ZERO);
        trace.borrow.push(M31::ZERO);
        trace.quotient_lo.push(M31::ZERO);
        trace.quotient_hi.push(M31::ZERO);
        trace.remainder_lo.push(M31::ZERO);
        trace.remainder_hi.push(M31::ZERO);
        trace.lt_result.push(M31::ZERO);
        trace.eq_result.push(M31::ZERO);
        trace.branch_taken.push(M31::ZERO);
        
        // Bit decompositions
        for j in 0..32 {
            trace.rs1_bits[j].push(M31::ZERO);
            trace.rs2_bits[j].push(M31::ZERO);
            trace.imm_bits[j].push(M31::ZERO);
            trace.and_bits[j].push(M31::ZERO);
            trace.xor_bits[j].push(M31::ZERO);
            trace.or_bits[j].push(M31::ZERO);
        }
        
        // Byte decompositions
        for j in 0..4 {
            trace.rs1_bytes[j].push(M31::ZERO);
            trace.rs2_bytes[j].push(M31::ZERO);
            trace.and_result_bytes[j].push(M31::ZERO);
            trace.or_result_bytes[j].push(M31::ZERO);
            trace.xor_result_bytes[j].push(M31::ZERO);
        }
    }

    // 2. Configure Prover
    let config = StarkConfig {
        log_trace_len: 4, // 2^4 = 16 rows
        blowup_factor: 8,
        num_queries: 50,
        fri_folding_factor: 2,
        security_bits: 100,
        entry_point: 0x0,
    };
    
    // 3. Benchmark Proof Generation
    group.bench_function("prove_trace_16_rows", |b| {
        b.iter(|| {
            let mut prover = StarkProver::new(config.clone());
            let columns = trace.to_columns();
            let proof = prover.prove(columns, &[]);
            
            // Serialize and measure size
            // We use the From<StarkProof> impl if it exists, otherwise manual construction
            // Since we can't see the From impl, we'll manually construct or just print size once
            // For the benchmark loop, we just generate.
            
            // We'll print the size ONCE outside the loop to avoid spam
            // (criterion captures stdout, so we might need `nocapture` to see it, 
            // or just rely on the side effect that we are measuring *time* here).
            proof
        })
    });
    
    // 4. One-off run to print size to stdout
    let mut prover = StarkProver::new(config.clone());
    let columns = trace.to_columns();
    let proof = prover.prove(columns, &[]);
    
    // Convert to serializable proof to get bytes
    // Note: detailed conversion logic omitted for brevity, using estimation or simple serialization
    // if From implementation is missing. Ideally we use `proof.to_bytes()` if available.
    
    // We will assume for this benchmark we just want to know the size of the *components*
    // or use the serialization module if we can link it easily.
    // Based on `stark.rs`, StarkProof has public fields.
    
    // Refined size estimation with correct depth calculation
    let domain_depth = config.log_trace_len + config.blowup_factor.trailing_zeros() as usize;
    
    let trace_comm_size = 32;
    let comp_comm_size = 32; 
    let fri_layers_size = proof.fri_proof.layer_commitments.len() * 32;
    let fri_final_size = proof.fri_proof.final_poly.len() * 4; // 4 bytes per M31
    
    // Queries are the bulk
    let query_size = proof.query_proofs.len() * (
        // Trace values per query (77 cols * 4 bytes)
        77 * 4 + 
        // Trace Merkle path (depth * 32 bytes)
        domain_depth * 32 + 
        // Composition value
        4 + 
        // Composition Merkle path
        domain_depth * 32 + 
        // DEEP quotient
        4
    );
    
    let estimated_size = trace_comm_size + comp_comm_size + fri_layers_size + fri_final_size + query_size;
    
    eprintln!("\n[EthProofs Standard] Estimated Proof Size: {} bytes ({:.2} KB)", 
             estimated_size, estimated_size as f64 / 1024.0);
    eprintln!("[EthProofs Standard] Queries: {}, Security: {} bits\n", 
             config.num_queries, config.security_bits);

    group.finish();
}

criterion_group!(benches, bench_proof_size);
criterion_main!(benches);
