//! BLAKE2s/BLAKE3 delegation gadgets.
//!
//! These provide trace generation and AIR constraints for hash precompiles.

use zp1_primitives::M31;

/// BLAKE2s round constants.
pub const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// BLAKE2s sigma permutation.
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

/// A BLAKE2s G function trace row.
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
    /// Intermediate values for constraint verification.
    pub intermediates: Vec<M31>,
}

/// Generate trace for BLAKE2s G function.
///
/// The G function is:
/// a = a + b + x
/// d = (d ^ a) >>> 16
/// c = c + d
/// b = (b ^ c) >>> 12
/// a = a + b + y
/// d = (d ^ a) >>> 8
/// c = c + d
/// b = (b ^ c) >>> 7
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

    let mut intermediates = Vec::new();

    // Step 1: a = a + b + x
    a = a.wrapping_add(b).wrapping_add(x);
    intermediates.push(M31::new(a & 0x7FFFFFFF));

    // Step 2: d = (d ^ a) >>> 16
    d = (d ^ a).rotate_right(16);
    intermediates.push(M31::new(d & 0x7FFFFFFF));

    // Step 3: c = c + d
    c = c.wrapping_add(d);
    intermediates.push(M31::new(c & 0x7FFFFFFF));

    // Step 4: b = (b ^ c) >>> 12
    b = (b ^ c).rotate_right(12);
    intermediates.push(M31::new(b & 0x7FFFFFFF));

    // Step 5: a = a + b + y
    a = a.wrapping_add(b).wrapping_add(y);
    intermediates.push(M31::new(a & 0x7FFFFFFF));

    // Step 6: d = (d ^ a) >>> 8
    d = (d ^ a).rotate_right(8);
    intermediates.push(M31::new(d & 0x7FFFFFFF));

    // Step 7: c = c + d
    c = c.wrapping_add(d);
    intermediates.push(M31::new(c & 0x7FFFFFFF));

    // Step 8: b = (b ^ c) >>> 7
    b = (b ^ c).rotate_right(7);

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
    };

    (a, b, c, d, row)
}

/// BLAKE2s compression function trace.
#[derive(Clone, Debug)]
pub struct Blake2sCompressionTrace {
    /// Initial state.
    pub h_in: [M31; 8],
    /// Message block.
    pub m: [M31; 16],
    /// Final state.
    pub h_out: [M31; 8],
    /// G function rows for all rounds.
    pub g_rows: Vec<Blake2sGRow>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_g() {
        let (a, b, c, d, _row) = blake2s_g_trace(
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x00000000,
            0x00000000,
        );

        // Basic sanity check - values should change
        assert_ne!(a, 0x6A09E667);
        assert_ne!(b, 0xBB67AE85);
    }
}
