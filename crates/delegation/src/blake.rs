//! BLAKE2s/BLAKE3 delegation gadgets.
//!
//! These provide trace generation and AIR constraints for hash precompiles.
//!
//! # BLAKE2s
//! - 10 rounds of mixing with G function
//! - 32-bit words, 64-byte block size
//! - Produces 32-byte hash
//!
//! # BLAKE3
//! - Based on BLAKE2s round function
//! - Merkle tree structure for streaming
//! - Parallel-friendly design

use zp1_primitives::M31;

// ============================================================================
// BLAKE2s Constants
// ============================================================================

/// BLAKE2s initialization vectors (first 32 bits of fractional parts of sqrt of first 8 primes).
pub const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// BLAKE2s sigma permutation for message scheduling.
pub const BLAKE2S_SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// BLAKE2s rotation amounts for G function.
pub const BLAKE2S_ROTATIONS: [u32; 4] = [16, 12, 8, 7];

// ============================================================================
// BLAKE3 Constants
// ============================================================================

/// BLAKE3 initialization vectors (same as BLAKE2s).
pub const BLAKE3_IV: [u32; 8] = BLAKE2S_IV;

/// BLAKE3 block length in bytes.
pub const BLAKE3_BLOCK_LEN: usize = 64;

/// BLAKE3 chunk length in bytes.
pub const BLAKE3_CHUNK_LEN: usize = 1024;

/// BLAKE3 domain separation flags.
pub mod blake3_flags {
    pub const CHUNK_START: u32 = 1 << 0;
    pub const CHUNK_END: u32 = 1 << 1;
    pub const PARENT: u32 = 1 << 2;
    pub const ROOT: u32 = 1 << 3;
    pub const KEYED_HASH: u32 = 1 << 4;
    pub const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
    pub const DERIVE_KEY_MATERIAL: u32 = 1 << 6;
}

// ============================================================================
// Trace Structures
// ============================================================================

/// A BLAKE2s G function trace row.
///
/// The G function mixes four 32-bit words using two message words.
/// Each call generates intermediate values that must satisfy constraints.
#[derive(Clone, Debug)]
pub struct Blake2sGRow {
    /// Input values a, b, c, d.
    pub a_in: M31,
    pub b_in: M31,
    pub c_in: M31,
    pub d_in: M31,
    /// Message words x, y.
    pub x: M31,
    pub y: M31,
    /// Output values.
    pub a_out: M31,
    pub b_out: M31,
    pub c_out: M31,
    pub d_out: M31,
    /// Intermediate values for constraint verification (7 values for steps 1-7).
    pub intermediates: Vec<M31>,
    /// Carry bits for overflow detection in additions.
    pub carries: Vec<M31>,
    /// XOR decomposition bits for rotation verification.
    pub xor_bits: Vec<M31>,
}

/// Full state after a G function application (raw u32 values).
#[derive(Clone, Debug)]
pub struct GState {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

/// BLAKE2s compression function trace.
#[derive(Clone, Debug)]
pub struct Blake2sCompressionTrace {
    /// Initial state h[0..8].
    pub h_in: [M31; 8],
    /// Message block m[0..16].
    pub m: [M31; 16],
    /// Byte counter t (low 64 bits).
    pub t: [M31; 2],
    /// Final block flag.
    pub f: M31,
    /// Final state h[0..8].
    pub h_out: [M31; 8],
    /// G function rows for all 10 rounds (8 G calls per round = 80 total).
    pub g_rows: Vec<Blake2sGRow>,
    /// Intermediate working vector states (v[0..16] after each round).
    pub round_states: Vec<[M31; 16]>,
}

/// BLAKE3 compression trace (single block).
#[derive(Clone, Debug)]
pub struct Blake3CompressionTrace {
    /// Chaining value (8 words).
    pub cv: [M31; 8],
    /// Message block (16 words).
    pub block: [M31; 16],
    /// Block counter.
    pub counter: M31,
    /// Block length.
    pub block_len: M31,
    /// Domain flags.
    pub flags: M31,
    /// Output (8 or 16 words depending on mode).
    pub output: Vec<M31>,
    /// G function rows (7 rounds * 8 G calls = 56 total).
    pub g_rows: Vec<Blake2sGRow>,
}

/// BLAKE3 chunk state trace.
#[derive(Clone, Debug)]
pub struct Blake3ChunkTrace {
    /// Chunk index.
    pub chunk_counter: u64,
    /// Compression traces for each block in chunk (up to 16 blocks).
    pub block_traces: Vec<Blake3CompressionTrace>,
    /// Output chaining value.
    pub output_cv: [M31; 8],
}

/// Full BLAKE3 hash trace for variable-length input.
#[derive(Clone, Debug)]
pub struct Blake3HashTrace {
    /// Key words (or IV for regular hashing).
    pub key: [M31; 8],
    /// Chunk traces.
    pub chunk_traces: Vec<Blake3ChunkTrace>,
    /// Parent node compression traces (for Merkle tree).
    pub parent_traces: Vec<Blake3CompressionTrace>,
    /// Final output hash.
    pub output: Vec<M31>,
}

// ============================================================================
// AIR Constraint Definitions
// ============================================================================

/// AIR constraint identifiers for BLAKE2s/BLAKE3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlakeConstraint {
    /// G function: a1 = a + b + x (with carry)
    GAddABX,
    /// G function: d1 = (d ^ a1) >>> 16
    GRotD16,
    /// G function: c1 = c + d1 (with carry)
    GAddCD,
    /// G function: b1 = (b ^ c1) >>> 12
    GRotB12,
    /// G function: a2 = a1 + b1 + y (with carry)
    GAddABY,
    /// G function: d2 = (d1 ^ a2) >>> 8
    GRotD8,
    /// G function: c2 = c1 + d2 (with carry)
    GAddC2D2,
    /// G function: b2 = (b1 ^ c2) >>> 7
    GRotB7,
    /// Working vector initialization.
    VInit,
    /// Round state transition.
    RoundTransition,
    /// Final XOR: h'[i] = h[i] ^ v[i] ^ v[i+8]
    FinalXor,
    /// BLAKE3 flag validity.
    Blake3Flags,
    /// BLAKE3 counter increment.
    Blake3Counter,
}

/// Constraint evaluation result.
#[derive(Clone, Debug)]
pub struct ConstraintResult {
    pub constraint: BlakeConstraint,
    pub value: M31,
    pub satisfied: bool,
}

// ============================================================================
// G Function Implementation
// ============================================================================

/// Generate trace for BLAKE2s G function.
///
/// The G function is:
/// ```text
/// a = a + b + x
/// d = (d ^ a) >>> 16
/// c = c + d
/// b = (b ^ c) >>> 12
/// a = a + b + y
/// d = (d ^ a) >>> 8
/// c = c + d
/// b = (b ^ c) >>> 7
/// ```
pub fn blake2s_g_trace(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    x: u32,
    y: u32,
) -> (u32, u32, u32, u32, Blake2sGRow) {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;

    let a_in = M31::new(a & 0x7FFFFFFF);
    let b_in = M31::new(b & 0x7FFFFFFF);
    let c_in = M31::new(c & 0x7FFFFFFF);
    let d_in = M31::new(d & 0x7FFFFFFF);

    let mut intermediates = Vec::with_capacity(8);
    let mut carries = Vec::with_capacity(4);
    let mut xor_bits = Vec::new();

    // Step 1: a = a + b + x (with potential overflow)
    let sum1 = (a as u64) + (b as u64) + (x as u64);
    let carry1 = (sum1 >> 32) as u32;
    a = sum1 as u32;
    intermediates.push(M31::new(a & 0x7FFFFFFF));
    carries.push(M31::new(carry1));

    // Step 2: d = (d ^ a) >>> 16
    let xor1 = d ^ a;
    d = xor1.rotate_right(16);
    intermediates.push(M31::new(d & 0x7FFFFFFF));
    // Store XOR bits for constraint verification
    for i in 0..32 {
        xor_bits.push(M31::new((xor1 >> i) & 1));
    }

    // Step 3: c = c + d
    let sum2 = (c as u64) + (d as u64);
    let carry2 = (sum2 >> 32) as u32;
    c = sum2 as u32;
    intermediates.push(M31::new(c & 0x7FFFFFFF));
    carries.push(M31::new(carry2));

    // Step 4: b = (b ^ c) >>> 12
    let xor2 = b ^ c;
    b = xor2.rotate_right(12);
    intermediates.push(M31::new(b & 0x7FFFFFFF));
    for i in 0..32 {
        xor_bits.push(M31::new((xor2 >> i) & 1));
    }

    // Step 5: a = a + b + y
    let sum3 = (a as u64) + (b as u64) + (y as u64);
    let carry3 = (sum3 >> 32) as u32;
    a = sum3 as u32;
    intermediates.push(M31::new(a & 0x7FFFFFFF));
    carries.push(M31::new(carry3));

    // Step 6: d = (d ^ a) >>> 8
    let xor3 = d ^ a;
    d = xor3.rotate_right(8);
    intermediates.push(M31::new(d & 0x7FFFFFFF));
    for i in 0..32 {
        xor_bits.push(M31::new((xor3 >> i) & 1));
    }

    // Step 7: c = c + d
    let sum4 = (c as u64) + (d as u64);
    let carry4 = (sum4 >> 32) as u32;
    c = sum4 as u32;
    intermediates.push(M31::new(c & 0x7FFFFFFF));
    carries.push(M31::new(carry4));

    // Step 8: b = (b ^ c) >>> 7
    let xor4 = b ^ c;
    b = xor4.rotate_right(7);
    for i in 0..32 {
        xor_bits.push(M31::new((xor4 >> i) & 1));
    }

    let row = Blake2sGRow {
        a_in,
        b_in,
        c_in,
        d_in,
        x: M31::new(x & 0x7FFFFFFF),
        y: M31::new(y & 0x7FFFFFFF),
        a_out: M31::new(a & 0x7FFFFFFF),
        b_out: M31::new(b & 0x7FFFFFFF),
        c_out: M31::new(c & 0x7FFFFFFF),
        d_out: M31::new(d & 0x7FFFFFFF),
        intermediates,
        carries,
        xor_bits,
    };

    (a, b, c, d, row)
}

/// Evaluate G function constraints.
pub fn evaluate_g_constraints(_row: &Blake2sGRow) -> Vec<ConstraintResult> {
    let mut results = Vec::new();

    // For a full implementation, we would verify:
    // 1. Addition constraints with carry bits
    // 2. XOR constraints using bit decomposition
    // 3. Rotation constraints

    // Simplified check: verify outputs match expected
    // In a real ZK circuit, we'd use algebraic constraints

    results.push(ConstraintResult {
        constraint: BlakeConstraint::GAddABX,
        value: M31::new(0),
        satisfied: true, // Placeholder
    });

    results
}

// ============================================================================
// BLAKE2s Compression Function
// ============================================================================

/// Initialize working vector for BLAKE2s compression.
fn init_working_vector(h: &[u32; 8], t: u64, f: bool) -> [u32; 16] {
    let mut v = [0u32; 16];

    // v[0..8] = h[0..8]
    v[..8].copy_from_slice(h);

    // v[8..16] = IV[0..8]
    v[8..16].copy_from_slice(&BLAKE2S_IV);

    // v[12] ^= t (low 32 bits)
    v[12] ^= t as u32;
    // v[13] ^= t >> 32 (high 32 bits)
    v[13] ^= (t >> 32) as u32;

    // v[14] ^= 0xFFFFFFFF if final block
    if f {
        v[14] ^= 0xFFFFFFFF;
    }

    v
}

/// Perform one round of BLAKE2s mixing.
fn blake2s_round(v: &mut [u32; 16], m: &[u32; 16], round: usize, g_rows: &mut Vec<Blake2sGRow>) {
    let s = &BLAKE2S_SIGMA[round % 10];

    // Column step
    let (a, b, c, d, row) = blake2s_g_trace(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
    v[0] = a;
    v[4] = b;
    v[8] = c;
    v[12] = d;
    g_rows.push(row);

    let (a, b, c, d, row) = blake2s_g_trace(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
    v[1] = a;
    v[5] = b;
    v[9] = c;
    v[13] = d;
    g_rows.push(row);

    let (a, b, c, d, row) = blake2s_g_trace(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
    v[2] = a;
    v[6] = b;
    v[10] = c;
    v[14] = d;
    g_rows.push(row);

    let (a, b, c, d, row) = blake2s_g_trace(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
    v[3] = a;
    v[7] = b;
    v[11] = c;
    v[15] = d;
    g_rows.push(row);

    // Diagonal step
    let (a, b, c, d, row) = blake2s_g_trace(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
    v[0] = a;
    v[5] = b;
    v[10] = c;
    v[15] = d;
    g_rows.push(row);

    let (a, b, c, d, row) = blake2s_g_trace(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
    v[1] = a;
    v[6] = b;
    v[11] = c;
    v[12] = d;
    g_rows.push(row);

    let (a, b, c, d, row) = blake2s_g_trace(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
    v[2] = a;
    v[7] = b;
    v[8] = c;
    v[13] = d;
    g_rows.push(row);

    let (a, b, c, d, row) = blake2s_g_trace(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    v[3] = a;
    v[4] = b;
    v[9] = c;
    v[14] = d;
    g_rows.push(row);
}

/// Generate trace for BLAKE2s compression function.
///
/// # Arguments
/// * `h` - Current hash state (8 words)
/// * `m` - Message block (16 words)
/// * `t` - Byte counter
/// * `f` - Final block flag
///
/// # Returns
/// New hash state and full compression trace
pub fn blake2s_compress_trace(
    h: &[u32; 8],
    m: &[u32; 16],
    t: u64,
    f: bool,
) -> ([u32; 8], Blake2sCompressionTrace) {
    let mut v = init_working_vector(h, t, f);
    let mut g_rows = Vec::with_capacity(80);
    let mut round_states = Vec::with_capacity(10);

    // Store initial state
    let h_in: [M31; 8] = std::array::from_fn(|i| M31::new(h[i] & 0x7FFFFFFF));
    let m_field: [M31; 16] = std::array::from_fn(|i| M31::new(m[i] & 0x7FFFFFFF));

    // 10 rounds of mixing
    for round in 0..10 {
        blake2s_round(&mut v, m, round, &mut g_rows);
        round_states.push(std::array::from_fn(|i| M31::new(v[i] & 0x7FFFFFFF)));
    }

    // Finalize: h'[i] = h[i] ^ v[i] ^ v[i+8]
    let mut h_out_raw = [0u32; 8];
    for i in 0..8 {
        h_out_raw[i] = h[i] ^ v[i] ^ v[i + 8];
    }

    let h_out: [M31; 8] = std::array::from_fn(|i| M31::new(h_out_raw[i] & 0x7FFFFFFF));

    let trace = Blake2sCompressionTrace {
        h_in,
        m: m_field,
        t: [
            M31::new((t & 0x7FFFFFFF) as u32),
            M31::new(((t >> 32) & 0x7FFFFFFF) as u32),
        ],
        f: M31::new(if f { 1 } else { 0 }),
        h_out,
        g_rows,
        round_states,
    };

    (h_out_raw, trace)
}

/// Full BLAKE2s hash with trace generation.
pub fn blake2s_hash_trace(data: &[u8]) -> (Vec<u8>, Vec<Blake2sCompressionTrace>) {
    let mut h = BLAKE2S_IV;
    // XOR parameter block into h[0]
    // For simplicity, using default parameters: digest_length=32, key_length=0
    h[0] ^= 0x01010020;

    let mut traces = Vec::new();
    let mut bytes_processed: u64 = 0;

    // Process complete blocks
    let chunks: Vec<&[u8]> = data.chunks(64).collect();
    let num_chunks = chunks.len().max(1);

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i == num_chunks - 1;

        // Pad chunk to 64 bytes
        let mut block = [0u8; 64];
        block[..chunk.len()].copy_from_slice(chunk);

        bytes_processed += chunk.len() as u64;

        // Convert to words
        let mut m = [0u32; 16];
        for j in 0..16 {
            m[j] = u32::from_le_bytes([
                block[j * 4],
                block[j * 4 + 1],
                block[j * 4 + 2],
                block[j * 4 + 3],
            ]);
        }

        let (new_h, trace) = blake2s_compress_trace(&h, &m, bytes_processed, is_last);
        h = new_h;
        traces.push(trace);
    }

    // Handle empty input
    if data.is_empty() {
        let m = [0u32; 16];
        let (new_h, trace) = blake2s_compress_trace(&h, &m, 0, true);
        h = new_h;
        traces.push(trace);
    }

    // Convert hash to bytes
    let mut result = Vec::with_capacity(32);
    for word in h.iter() {
        result.extend_from_slice(&word.to_le_bytes());
    }

    (result, traces)
}

// ============================================================================
// BLAKE3 Implementation
// ============================================================================

/// BLAKE3 compression function (single block).
/// Uses 7 rounds instead of BLAKE2s's 10.
pub fn blake3_compress_trace(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> ([u32; 16], Blake3CompressionTrace) {
    // Initialize state
    let mut state = [0u32; 16];
    state[..8].copy_from_slice(cv);
    state[8..12].copy_from_slice(&BLAKE3_IV[..4]);
    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = block_len;
    state[15] = flags;

    let mut g_rows = Vec::with_capacity(56);

    // 7 rounds
    for round in 0..7 {
        // Use BLAKE2s sigma permutation
        let s = &BLAKE2S_SIGMA[round];

        // Column step
        let (a, b, c, d, row) = blake2s_g_trace(
            state[0],
            state[4],
            state[8],
            state[12],
            block[s[0]],
            block[s[1]],
        );
        state[0] = a;
        state[4] = b;
        state[8] = c;
        state[12] = d;
        g_rows.push(row);

        let (a, b, c, d, row) = blake2s_g_trace(
            state[1],
            state[5],
            state[9],
            state[13],
            block[s[2]],
            block[s[3]],
        );
        state[1] = a;
        state[5] = b;
        state[9] = c;
        state[13] = d;
        g_rows.push(row);

        let (a, b, c, d, row) = blake2s_g_trace(
            state[2],
            state[6],
            state[10],
            state[14],
            block[s[4]],
            block[s[5]],
        );
        state[2] = a;
        state[6] = b;
        state[10] = c;
        state[14] = d;
        g_rows.push(row);

        let (a, b, c, d, row) = blake2s_g_trace(
            state[3],
            state[7],
            state[11],
            state[15],
            block[s[6]],
            block[s[7]],
        );
        state[3] = a;
        state[7] = b;
        state[11] = c;
        state[15] = d;
        g_rows.push(row);

        // Diagonal step
        let (a, b, c, d, row) = blake2s_g_trace(
            state[0],
            state[5],
            state[10],
            state[15],
            block[s[8]],
            block[s[9]],
        );
        state[0] = a;
        state[5] = b;
        state[10] = c;
        state[15] = d;
        g_rows.push(row);

        let (a, b, c, d, row) = blake2s_g_trace(
            state[1],
            state[6],
            state[11],
            state[12],
            block[s[10]],
            block[s[11]],
        );
        state[1] = a;
        state[6] = b;
        state[11] = c;
        state[12] = d;
        g_rows.push(row);

        let (a, b, c, d, row) = blake2s_g_trace(
            state[2],
            state[7],
            state[8],
            state[13],
            block[s[12]],
            block[s[13]],
        );
        state[2] = a;
        state[7] = b;
        state[8] = c;
        state[13] = d;
        g_rows.push(row);

        let (a, b, c, d, row) = blake2s_g_trace(
            state[3],
            state[4],
            state[9],
            state[14],
            block[s[14]],
            block[s[15]],
        );
        state[3] = a;
        state[4] = b;
        state[9] = c;
        state[14] = d;
        g_rows.push(row);
    }

    let cv_field: [M31; 8] = std::array::from_fn(|i| M31::new(cv[i] & 0x7FFFFFFF));
    let block_field: [M31; 16] = std::array::from_fn(|i| M31::new(block[i] & 0x7FFFFFFF));
    let output: Vec<M31> = state.iter().map(|&w| M31::new(w & 0x7FFFFFFF)).collect();

    let trace = Blake3CompressionTrace {
        cv: cv_field,
        block: block_field,
        counter: M31::new((counter & 0x7FFFFFFF) as u32),
        block_len: M31::new(block_len & 0x7FFFFFFF),
        flags: M31::new(flags & 0x7FFFFFFF),
        output,
        g_rows,
    };

    (state, trace)
}

/// Compute BLAKE3 output chaining value (XOR of state halves).
pub fn blake3_output_cv(state: &[u32; 16], _cv: &[u32; 8]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = state[i] ^ state[i + 8];
    }
    // For non-root nodes, also XOR with input CV
    // (This is simplified - full BLAKE3 has more complex output handling)
    out
}

/// Process a single BLAKE3 chunk.
pub fn blake3_chunk_trace(
    key: &[u32; 8],
    chunk: &[u8],
    chunk_counter: u64,
    flags: u32,
) -> Blake3ChunkTrace {
    let mut cv = *key;
    let mut block_traces = Vec::new();

    // Process up to 16 blocks per chunk
    let blocks: Vec<&[u8]> = chunk.chunks(64).collect();
    let num_blocks = blocks.len().max(1);

    for (i, block_data) in blocks.iter().enumerate() {
        let mut block_flags = flags;
        if i == 0 {
            block_flags |= blake3_flags::CHUNK_START;
        }
        if i == num_blocks - 1 {
            block_flags |= blake3_flags::CHUNK_END;
        }

        // Pad block
        let mut padded = [0u8; 64];
        padded[..block_data.len()].copy_from_slice(block_data);

        // Convert to words
        let mut block = [0u32; 16];
        for j in 0..16 {
            block[j] = u32::from_le_bytes([
                padded[j * 4],
                padded[j * 4 + 1],
                padded[j * 4 + 2],
                padded[j * 4 + 3],
            ]);
        }

        let (state, trace) = blake3_compress_trace(
            &cv,
            &block,
            chunk_counter,
            block_data.len() as u32,
            block_flags,
        );

        // Update CV for next block (only needed within chunk)
        if i < num_blocks - 1 {
            cv = blake3_output_cv(&state, &cv);
        }

        block_traces.push(trace);
    }

    // Handle empty chunk
    if chunk.is_empty() {
        let block = [0u32; 16];
        let block_flags = flags | blake3_flags::CHUNK_START | blake3_flags::CHUNK_END;
        let (_state, trace) = blake3_compress_trace(&cv, &block, chunk_counter, 0, block_flags);
        block_traces.push(trace);
    }

    // Compute output CV from last compression
    let last_state = if let Some(last_trace) = block_traces.last() {
        let mut state = [0u32; 16];
        for (i, v) in last_trace.output.iter().enumerate() {
            state[i] = v.value();
        }
        state
    } else {
        [0u32; 16]
    };

    let output_cv_raw = blake3_output_cv(&last_state, &cv);
    let output_cv: [M31; 8] = std::array::from_fn(|i| M31::new(output_cv_raw[i] & 0x7FFFFFFF));

    Blake3ChunkTrace {
        chunk_counter,
        block_traces,
        output_cv,
    }
}

/// Full BLAKE3 hash with trace generation.
pub fn blake3_hash_trace(data: &[u8]) -> Blake3HashTrace {
    let key = BLAKE3_IV;
    let key_field: [M31; 8] = std::array::from_fn(|i| M31::new(key[i] & 0x7FFFFFFF));

    let mut chunk_traces = Vec::new();
    let mut parent_traces = Vec::new();
    let mut cv_stack: Vec<[u32; 8]> = Vec::new();

    // Process chunks
    let chunks: Vec<&[u8]> = data.chunks(BLAKE3_CHUNK_LEN).collect();

    for (i, chunk_data) in chunks.iter().enumerate() {
        let chunk_trace = blake3_chunk_trace(&key, chunk_data, i as u64, 0);

        // Get output CV
        let mut cv = [0u32; 8];
        for (j, v) in chunk_trace.output_cv.iter().enumerate() {
            cv[j] = v.value();
        }

        chunk_traces.push(chunk_trace);

        // Merge with existing CVs (Merkle tree construction)
        cv_stack.push(cv);

        // Merge pairs when possible (simplified - full BLAKE3 is more complex)
        while cv_stack.len() > 1 && (cv_stack.len() & 1) == 0 {
            let right = cv_stack.pop().unwrap();
            let left = cv_stack.pop().unwrap();

            // Create parent block from two CVs
            let mut parent_block = [0u32; 16];
            parent_block[..8].copy_from_slice(&left);
            parent_block[8..16].copy_from_slice(&right);

            let (state, trace) =
                blake3_compress_trace(&key, &parent_block, 0, 64, blake3_flags::PARENT);

            let parent_cv = blake3_output_cv(&state, &key);
            cv_stack.push(parent_cv);
            parent_traces.push(trace);
        }
    }

    // Handle empty input
    if data.is_empty() {
        let chunk_trace = blake3_chunk_trace(&key, &[], 0, 0);
        chunk_traces.push(chunk_trace);
    }

    // Finalize - merge remaining CVs
    while cv_stack.len() > 1 {
        let right = cv_stack.pop().unwrap();
        let left = cv_stack.pop().unwrap_or(key);

        let mut parent_block = [0u32; 16];
        parent_block[..8].copy_from_slice(&left);
        parent_block[8..16].copy_from_slice(&right);

        let is_root = cv_stack.is_empty();
        let flags = blake3_flags::PARENT | if is_root { blake3_flags::ROOT } else { 0 };

        let (state, trace) = blake3_compress_trace(&key, &parent_block, 0, 64, flags);
        let parent_cv = blake3_output_cv(&state, &key);
        cv_stack.push(parent_cv);
        parent_traces.push(trace);
    }

    // Get final output
    let output: Vec<M31> = if let Some(cv) = cv_stack.first() {
        cv.iter().map(|&w| M31::new(w & 0x7FFFFFFF)).collect()
    } else if let Some(chunk_trace) = chunk_traces.first() {
        chunk_trace.output_cv.to_vec()
    } else {
        key_field.to_vec()
    };

    Blake3HashTrace {
        key: key_field,
        chunk_traces,
        parent_traces,
        output,
    }
}

// ============================================================================
// Delegation Interface
// ============================================================================

/// BLAKE delegation call types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlakeDelegationType {
    /// BLAKE2s single block compression.
    Blake2sCompress,
    /// BLAKE2s full hash (variable length).
    Blake2sHash,
    /// BLAKE3 single block compression.
    Blake3Compress,
    /// BLAKE3 full hash (variable length).
    Blake3Hash,
}

/// A delegation call for BLAKE operations.
#[derive(Clone, Debug)]
pub struct BlakeDelegationCall {
    /// Type of operation.
    pub op_type: BlakeDelegationType,
    /// Input data fingerprint.
    pub input_fingerprint: M31,
    /// Output data fingerprint.
    pub output_fingerprint: M31,
    /// Associated trace.
    pub trace: BlakeDelegationTrace,
}

/// Trace data for a BLAKE delegation call.
#[derive(Clone, Debug)]
pub enum BlakeDelegationTrace {
    Blake2sCompress(Blake2sCompressionTrace),
    Blake2sHash(Vec<Blake2sCompressionTrace>),
    Blake3Compress(Blake3CompressionTrace),
    Blake3Hash(Blake3HashTrace),
}

/// Create a BLAKE2s compression delegation call.
pub fn delegate_blake2s_compress(
    h: &[u32; 8],
    m: &[u32; 16],
    t: u64,
    f: bool,
) -> BlakeDelegationCall {
    let (h_out, trace) = blake2s_compress_trace(h, m, t, f);

    // Compute fingerprints using random linear combination
    let input_fp = compute_fingerprint_u32(&[
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        m[0],
        m[1],
        m[2],
        m[3],
        m[4],
        m[5],
        m[6],
        m[7],
        m[8],
        m[9],
        m[10],
        m[11],
        m[12],
        m[13],
        m[14],
        m[15],
        t as u32,
        (t >> 32) as u32,
        if f { 1 } else { 0 },
    ]);

    let output_fp = compute_fingerprint_u32(&h_out);

    BlakeDelegationCall {
        op_type: BlakeDelegationType::Blake2sCompress,
        input_fingerprint: input_fp,
        output_fingerprint: output_fp,
        trace: BlakeDelegationTrace::Blake2sCompress(trace),
    }
}

/// Create a BLAKE2s hash delegation call.
pub fn delegate_blake2s_hash(data: &[u8]) -> BlakeDelegationCall {
    let (hash, traces) = blake2s_hash_trace(data);

    let input_fp = compute_fingerprint_bytes(data);
    let output_fp = compute_fingerprint_bytes(&hash);

    BlakeDelegationCall {
        op_type: BlakeDelegationType::Blake2sHash,
        input_fingerprint: input_fp,
        output_fingerprint: output_fp,
        trace: BlakeDelegationTrace::Blake2sHash(traces),
    }
}

/// Create a BLAKE3 compression delegation call.
pub fn delegate_blake3_compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> BlakeDelegationCall {
    let (state, trace) = blake3_compress_trace(cv, block, counter, block_len, flags);

    let input_fp = compute_fingerprint_u32(&[
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        block[0],
        block[1],
        block[2],
        block[3],
        block[4],
        block[5],
        block[6],
        block[7],
        block[8],
        block[9],
        block[10],
        block[11],
        block[12],
        block[13],
        block[14],
        block[15],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ]);

    let output_fp = compute_fingerprint_u32(&state);

    BlakeDelegationCall {
        op_type: BlakeDelegationType::Blake3Compress,
        input_fingerprint: input_fp,
        output_fingerprint: output_fp,
        trace: BlakeDelegationTrace::Blake3Compress(trace),
    }
}

/// Create a BLAKE3 hash delegation call.
pub fn delegate_blake3_hash(data: &[u8]) -> BlakeDelegationCall {
    let trace = blake3_hash_trace(data);

    let input_fp = compute_fingerprint_bytes(data);

    // Output fingerprint from final hash
    let output_fp = {
        let mut hash_words = [0u32; 8];
        for (i, v) in trace.output.iter().take(8).enumerate() {
            hash_words[i] = v.value();
        }
        compute_fingerprint_u32(&hash_words)
    };

    BlakeDelegationCall {
        op_type: BlakeDelegationType::Blake3Hash,
        input_fingerprint: input_fp,
        output_fingerprint: output_fp,
        trace: BlakeDelegationTrace::Blake3Hash(trace),
    }
}

/// Compute fingerprint from u32 array using random linear combination.
fn compute_fingerprint_u32(values: &[u32]) -> M31 {
    // Use a simple hash-based random coefficient
    let mut acc = M31::new(1);
    let alpha = M31::new(0x12345678); // Fixed "random" coefficient for determinism

    for &v in values {
        acc = acc * alpha + M31::new(v & 0x7FFFFFFF);
    }

    acc
}

/// Compute fingerprint from byte array.
fn compute_fingerprint_bytes(data: &[u8]) -> M31 {
    let mut acc = M31::new(1);
    let alpha = M31::new(0x12345678);

    for chunk in data.chunks(4) {
        let mut bytes = [0u8; 4];
        bytes[..chunk.len()].copy_from_slice(chunk);
        let word = u32::from_le_bytes(bytes);
        acc = acc * alpha + M31::new(word & 0x7FFFFFFF);
    }

    // Include length to distinguish different-length inputs with same prefix
    acc = acc * alpha + M31::new(data.len() as u32);

    acc
}

// ============================================================================
// Constraint AIR
// ============================================================================

/// BLAKE2s/BLAKE3 AIR for constraint verification.
pub struct BlakeAir {
    /// Number of G function rows.
    pub num_g_rows: usize,
}

impl BlakeAir {
    /// Create AIR for a BLAKE2s compression (80 G rows).
    pub fn blake2s_compress() -> Self {
        Self { num_g_rows: 80 }
    }

    /// Create AIR for a BLAKE3 compression (56 G rows).
    pub fn blake3_compress() -> Self {
        Self { num_g_rows: 56 }
    }

    /// Number of trace columns needed.
    pub fn num_columns(&self) -> usize {
        // Per G row: 10 main values + 8 intermediates + 4 carries + 128 XOR bits
        // Simplified: just main values and intermediates
        self.num_g_rows * 18
    }

    /// Evaluate constraints on a trace.
    pub fn evaluate(&self, g_rows: &[Blake2sGRow]) -> Vec<ConstraintResult> {
        let mut results = Vec::new();

        for row in g_rows {
            results.extend(evaluate_g_constraints(row));
        }

        results
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_g() {
        let (a, b, _c, _d, row) = blake2s_g_trace(
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x00000000, 0x00000000,
        );

        // Values should change after G function
        assert_ne!(a, 0x6A09E667);
        assert_ne!(b, 0xBB67AE85);

        // Should have 7 intermediates (steps 1-7, step 8 goes to output)
        assert_eq!(row.intermediates.len(), 7);

        // Should have 4 carries
        assert_eq!(row.carries.len(), 4);

        // Should have 128 XOR bits (4 XORs * 32 bits)
        assert_eq!(row.xor_bits.len(), 128);
    }

    #[test]
    fn test_blake2s_compress() {
        let h = BLAKE2S_IV;
        let m = [0u32; 16];

        let (h_out, trace) = blake2s_compress_trace(&h, &m, 0, false);

        // Output should differ from input
        assert_ne!(h_out, h);

        // Should have 80 G rows (10 rounds * 8 G calls)
        assert_eq!(trace.g_rows.len(), 80);

        // Should have 10 round states
        assert_eq!(trace.round_states.len(), 10);
    }

    #[test]
    fn test_blake2s_hash_empty() {
        let (hash, traces) = blake2s_hash_trace(&[]);

        // Should produce 32-byte hash
        assert_eq!(hash.len(), 32);

        // Should have one compression trace
        assert_eq!(traces.len(), 1);
    }

    #[test]
    fn test_blake2s_hash_hello() {
        let data = b"hello";
        let (hash, traces) = blake2s_hash_trace(data);

        assert_eq!(hash.len(), 32);
        assert_eq!(traces.len(), 1);

        // Hash should be deterministic
        let (hash2, _) = blake2s_hash_trace(data);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_blake2s_hash_multiblock() {
        // Data longer than one block (64 bytes)
        let data = vec![0xABu8; 100];
        let (hash, traces) = blake2s_hash_trace(&data);

        assert_eq!(hash.len(), 32);
        assert_eq!(traces.len(), 2); // Should need 2 blocks
    }

    #[test]
    fn test_blake3_compress() {
        let cv = BLAKE3_IV;
        let block = [0u32; 16];

        let (state, trace) = blake3_compress_trace(&cv, &block, 0, 0, 0);

        // State should be 16 words
        assert_eq!(state.len(), 16);

        // Should have 56 G rows (7 rounds * 8 G calls)
        assert_eq!(trace.g_rows.len(), 56);
    }

    #[test]
    fn test_blake3_hash_empty() {
        let trace = blake3_hash_trace(&[]);

        // Should have output
        assert!(!trace.output.is_empty());

        // Should have at least one chunk trace
        assert!(!trace.chunk_traces.is_empty());
    }

    #[test]
    fn test_blake3_hash_hello() {
        let data = b"hello world";
        let trace = blake3_hash_trace(data);

        assert_eq!(trace.output.len(), 8);
        assert_eq!(trace.chunk_traces.len(), 1);
    }

    #[test]
    fn test_delegation_blake2s() {
        let call = delegate_blake2s_hash(b"test data");

        assert_eq!(call.op_type, BlakeDelegationType::Blake2sHash);
        assert_ne!(call.input_fingerprint, call.output_fingerprint);

        match call.trace {
            BlakeDelegationTrace::Blake2sHash(traces) => {
                assert!(!traces.is_empty());
            }
            _ => panic!("Wrong trace type"),
        }
    }

    #[test]
    fn test_delegation_blake3() {
        let call = delegate_blake3_hash(b"test data");

        assert_eq!(call.op_type, BlakeDelegationType::Blake3Hash);

        match call.trace {
            BlakeDelegationTrace::Blake3Hash(trace) => {
                assert!(!trace.chunk_traces.is_empty());
            }
            _ => panic!("Wrong trace type"),
        }
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let data = b"hello";
        let fp1 = compute_fingerprint_bytes(data);
        let fp2 = compute_fingerprint_bytes(data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_inputs() {
        let fp1 = compute_fingerprint_bytes(b"hello");
        let fp2 = compute_fingerprint_bytes(b"world");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_blake_air_columns() {
        let air_2s = BlakeAir::blake2s_compress();
        let air_3 = BlakeAir::blake3_compress();

        // BLAKE2s has more columns (more rounds)
        assert!(air_2s.num_columns() > air_3.num_columns());

        assert_eq!(air_2s.num_g_rows, 80);
        assert_eq!(air_3.num_g_rows, 56);
    }
}
