//! Hardware-Accelerated FIPS 180-4 SHA-256 Kernel (`kintsugi_core::kernels::sha256_hw`).
//!
//! - `aarch64`: Runtime `is_aarch64_feature_detected!("sha2")` dispatch to ARMv8 Crypto
//!   Extensions (`vsha256hq_u32`, `vsha256h2q_u32`, `vsha256su0q_u32`, `vsha256su1q_u32`).
//! - Streaming block processing with zero heap copies (`data.to_vec()` avoided).
//! - Explicit `disable_hw_sha256` parameter for deterministic scalar fallback benchmarking
//!   and differential testing against hardware acceleration.

use std::hint::black_box;
use std::time::Instant;

const SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Return the active SHA-256 backend string for this CPU and mode.
pub fn active_sha256_backend(disable_hw_sha256: bool) -> &'static str {
    if disable_hw_sha256 {
        return "rust_scalar_fallback";
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            return "aarch64_feat_sha256";
        }
    }
    "rust_scalar"
}

#[inline(always)]
fn compress_block_scalar(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        let off = i * 4;
        w[i] = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[inline]
fn finish_padding_and_finalize<F>(total_len: usize, rem: &[u8], mut compress_fn: F) -> [u8; 32]
where
    F: FnMut(&[u8; 64]),
{
    let mut tail = [0u8; 128];
    let rlen = rem.len();
    tail[..rlen].copy_from_slice(rem);
    tail[rlen] = 0x80;
    let total_blocks = if rlen < 56 { 1 } else { 2 };
    let bit_len = (total_len as u64).wrapping_mul(8);
    let len_off = total_blocks * 64 - 8;
    tail[len_off..len_off + 8].copy_from_slice(&bit_len.to_be_bytes());

    let b0: &[u8; 64] = tail[0..64].try_into().expect("fixed 64-byte block");
    compress_fn(b0);
    if total_blocks == 2 {
        let b1: &[u8; 64] = tail[64..128].try_into().expect("fixed 64-byte block");
        compress_fn(b1);
    }
    [0u8; 32]
}

#[inline]
fn words_to_digest(state: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Safe pure-Rust scalar FIPS 180-4 SHA-256 digest (zero heap allocations).
pub fn sha256_bytes_scalar(data: &[u8]) -> [u8; 32] {
    let mut state = SHA256_INIT;
    let chunks = data.chunks_exact(64);
    let rem = chunks.remainder();
    for chunk in chunks {
        let block: &[u8; 64] = chunk.try_into().expect("chunks_exact(64)");
        compress_block_scalar(&mut state, block);
    }
    let _ = finish_padding_and_finalize(data.len(), rem, |block| {
        compress_block_scalar(&mut state, block);
    });
    words_to_digest(&state)
}

/// Hardware-accelerated AArch64 `FEAT_SHA256` SHA-256 digest (`vsha256*` intrinsics).
///
/// # Safety
/// Caller must ensure `std::arch::is_aarch64_feature_detected!("sha2")` is true.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
pub unsafe fn sha256_bytes_aarch64_hw(data: &[u8]) -> [u8; 32] {
    use std::arch::aarch64::*;

    #[inline(always)]
    unsafe fn load_be_words(ptr: *const u8) -> uint32x4_t {
        let raw = unsafe { vld1q_u8(ptr) };
        #[cfg(target_endian = "little")]
        {
            vreinterpretq_u32_u8(vrev32q_u8(raw))
        }
        #[cfg(target_endian = "big")]
        {
            vreinterpretq_u32_u8(raw)
        }
    }

    #[inline(always)]
    unsafe fn sha256_block_hw(state0: &mut uint32x4_t, state1: &mut uint32x4_t, ptr: *const u8) {
        // SAFETY: caller guarantees `ptr` points to at least 64 readable bytes and `SHA256_K` has 64 entries.
        let k_ptr = SHA256_K.as_ptr();
        let mut w0 = unsafe { load_be_words(ptr) };
        let mut w1 = unsafe { load_be_words(ptr.add(16)) };
        let mut w2 = unsafe { load_be_words(ptr.add(32)) };
        let mut w3 = unsafe { load_be_words(ptr.add(48)) };

        let mut abcd = *state0;
        let mut efgh = *state1;

        macro_rules! round4 {
            ($w:expr, $k_off:expr) => {{
                let k = unsafe { vld1q_u32(k_ptr.add($k_off)) };
                let wk = vaddq_u32($w, k);
                let prev = abcd;
                abcd = vsha256hq_u32(abcd, efgh, wk);
                efgh = vsha256h2q_u32(efgh, prev, wk);
            }};
        }

        macro_rules! schedule_next {
            ($wa:expr, $wb:expr, $wc:expr, $wd:expr) => {{
                let t0 = vsha256su0q_u32($wa, $wb);
                $wa = vsha256su1q_u32(t0, $wc, $wd);
            }};
        }

        // Rounds 0..15 + schedule 16..31
        round4!(w0, 0);
        schedule_next!(w0, w1, w2, w3);
        round4!(w1, 4);
        schedule_next!(w1, w2, w3, w0);
        round4!(w2, 8);
        schedule_next!(w2, w3, w0, w1);
        round4!(w3, 12);
        schedule_next!(w3, w0, w1, w2);

        // Rounds 16..31 + schedule 32..47
        round4!(w0, 16);
        schedule_next!(w0, w1, w2, w3);
        round4!(w1, 20);
        schedule_next!(w1, w2, w3, w0);
        round4!(w2, 24);
        schedule_next!(w2, w3, w0, w1);
        round4!(w3, 28);
        schedule_next!(w3, w0, w1, w2);

        // Rounds 32..47 + schedule 48..63
        round4!(w0, 32);
        schedule_next!(w0, w1, w2, w3);
        round4!(w1, 36);
        schedule_next!(w1, w2, w3, w0);
        round4!(w2, 40);
        schedule_next!(w2, w3, w0, w1);
        round4!(w3, 44);
        schedule_next!(w3, w0, w1, w2);

        // Rounds 48..63
        round4!(w0, 48);
        round4!(w1, 52);
        round4!(w2, 56);
        round4!(w3, 60);

        *state0 = vaddq_u32(*state0, abcd);
        *state1 = vaddq_u32(*state1, efgh);
    }

    // SAFETY: `SHA256_INIT` has 8 elements; two 4-word aligned vector loads stay within bounds.
    let mut state0 = unsafe { vld1q_u32(SHA256_INIT.as_ptr()) };
    let mut state1 = unsafe { vld1q_u32(SHA256_INIT.as_ptr().add(4)) };

    let chunks = data.chunks_exact(64);
    let rem = chunks.remainder();
    for chunk in chunks {
        // SAFETY: `chunks_exact(64)` guarantees 64 readable bytes.
        unsafe { sha256_block_hw(&mut state0, &mut state1, chunk.as_ptr()) };
    }

    let _ = finish_padding_and_finalize(data.len(), rem, |block| {
        // SAFETY: `block` is `[u8; 64]`.
        unsafe { sha256_block_hw(&mut state0, &mut state1, block.as_ptr()) };
    });

    let mut words = [0u32; 8];
    // SAFETY: `words` is `[u32; 8]` with 8 writable u32 elements.
    unsafe {
        vst1q_u32(words.as_mut_ptr(), state0);
        vst1q_u32(words.as_mut_ptr().add(4), state1);
    }
    words_to_digest(&words)
}

/// Compute SHA-256 32-byte digest using hardware `FEAT_SHA256` when available (unless `disable_hw_sha256` is true).
#[inline]
pub fn sha256_bytes_with_mode(data: &[u8], disable_hw_sha256: bool) -> [u8; 32] {
    if !disable_hw_sha256 {
        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("sha2") {
                // SAFETY: `is_aarch64_feature_detected!("sha2")` verified hardware FEAT_SHA256 support.
                return unsafe { sha256_bytes_aarch64_hw(data) };
            }
        }
    }
    sha256_bytes_scalar(data)
}

/// Compute SHA-256 32-byte digest using the fastest verified backend on this CPU.
#[inline]
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    sha256_bytes_with_mode(data, false)
}

/// Encode 32-byte SHA-256 digest into 64 lowercase ASCII hex bytes without heap allocation.
#[inline]
pub fn digest_to_hex_into(digest: &[u8; 32], out: &mut [u8; 64]) {
    for (i, &b) in digest.iter().enumerate() {
        out[i * 2] = HEX_LOWER[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_LOWER[(b & 0x0f) as usize];
    }
}

/// Compute SHA-256 directly into a 64-byte lowercase ASCII hex buffer (zero heap allocation).
#[inline]
pub fn sha256_hex_into(data: &[u8], out: &mut [u8; 64], disable_hw_sha256: bool) {
    let digest = sha256_bytes_with_mode(data, disable_hw_sha256);
    digest_to_hex_into(&digest, out);
}

/// Compute SHA-256 lowercase hex digest using hardware `FEAT_SHA256` when available.
#[inline]
pub fn sha256_hex_fast(data: &[u8]) -> String {
    sha256_hex_with_mode(data, false)
}

/// Compute SHA-256 lowercase hex digest with explicit hardware acceleration toggle.
#[inline]
pub fn sha256_hex_with_mode(data: &[u8], disable_hw_sha256: bool) -> String {
    let mut hex_bytes = [0u8; 64];
    sha256_hex_into(data, &mut hex_bytes, disable_hw_sha256);
    // SAFETY: `HEX_LOWER` consists strictly of ASCII hex digits `0-9`, `a-f`.
    String::from_utf8(hex_bytes.to_vec()).expect("valid ASCII hex")
}

/// Timing summary for one SHA-256 backend.
#[derive(Debug, Clone)]
pub struct Sha256BenchStats {
    pub backend: &'static str,
    pub min_us: f64,
    pub median_us: f64,
    pub p95_us: f64,
    pub mean_us: f64,
    pub throughput_gbps: f64,
}

/// Reproducible SHA-256 benchmark comparing hardware `FEAT_SHA256` vs scalar fallback.
#[derive(Debug, Clone)]
pub struct Sha256BenchReport {
    pub size_bytes: usize,
    pub warmup: usize,
    pub iters: usize,
    pub parity_ok: bool,
    pub digest_hex: String,
    pub hw: Sha256BenchStats,
    pub scalar: Sha256BenchStats,
    pub speedup_hw_vs_scalar: f64,
}

fn measure_sha256_stats<F>(
    backend: &'static str,
    data: &[u8],
    warmup: usize,
    iters: usize,
    mut f: F,
) -> (Sha256BenchStats, [u8; 32])
where
    F: FnMut(&[u8]) -> [u8; 32],
{
    for _ in 0..warmup {
        black_box(f(black_box(data)));
    }
    let mut samples = Vec::with_capacity(iters.max(1));
    let mut last = [0u8; 32];
    for _ in 0..iters.max(1) {
        let t0 = Instant::now();
        let d = f(black_box(data));
        let us = (t0.elapsed().as_nanos() as f64) / 1000.0;
        black_box(d);
        samples.push(us);
        last = d;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples.len();
    let min_us = samples[0];
    let median_us = if n % 2 == 1 {
        samples[n / 2]
    } else {
        0.5 * (samples[n / 2 - 1] + samples[n / 2])
    };
    let p95_idx = ((n as f64) * 0.95).ceil() as usize;
    let p95_us = samples[p95_idx.saturating_sub(1).min(n - 1)];
    let mean_us = samples.iter().sum::<f64>() / (n as f64);
    let secs = median_us * 1e-6;
    let throughput_gbps = if secs > 0.0 {
        (data.len() as f64) / secs / 1e9
    } else {
        0.0
    };
    (
        Sha256BenchStats {
            backend,
            min_us,
            median_us,
            p95_us,
            mean_us,
            throughput_gbps,
        },
        last,
    )
}

/// Run reproducible warmup + measured SHA-256 hardware vs scalar benchmark.
pub fn run_sha256_benchmark(size_bytes: usize, warmup: usize, iters: usize, seed: u64) -> Sha256BenchReport {
    let mut state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
    let mut data = vec![0u8; size_bytes];
    for chunk in data.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }

    let (hw_stats, hw_digest) =
        measure_sha256_stats(active_sha256_backend(false), &data, warmup, iters, sha256_bytes);
    let (sc_stats, sc_digest) = measure_sha256_stats(
        active_sha256_backend(true),
        &data,
        warmup,
        iters,
        sha256_bytes_scalar,
    );

    let mut hex_buf = [0u8; 64];
    digest_to_hex_into(&hw_digest, &mut hex_buf);
    let digest_hex = String::from_utf8(hex_buf.to_vec()).expect("valid hex");
    let speedup = if hw_stats.median_us > 0.0 {
        sc_stats.median_us / hw_stats.median_us
    } else {
        1.0
    };

    Sha256BenchReport {
        size_bytes,
        warmup,
        iters: iters.max(1),
        parity_ok: hw_digest == sc_digest,
        digest_hex,
        hw: hw_stats,
        scalar: sc_stats,
        speedup_hw_vs_scalar: speedup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_fips_180_4_vectors_match_hw_and_scalar() {
        let cases: [(&[u8], &str); 4] = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(sha256_hex_with_mode(input, false), expected, "hw len={}", input.len());
            assert_eq!(sha256_hex_with_mode(input, true), expected, "scalar len={}", input.len());
        }

        let one_million_a = vec![b'a'; 1_000_000];
        let exp_million = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        assert_eq!(sha256_hex_with_mode(&one_million_a, false), exp_million);
        assert_eq!(sha256_hex_with_mode(&one_million_a, true), exp_million);
    }

    #[test]
    fn block_boundaries_unaligned_and_500_random_inputs_parity() {
        let mut raw = vec![0u8; 4096];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = ((i * 131 + 17) & 0xFF) as u8;
        }
        for shift in [0usize, 1, 3, 7, 15] {
            for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257] {
                let slice = &raw[shift..shift + len];
                assert_eq!(
                    sha256_bytes_with_mode(slice, false),
                    sha256_bytes_with_mode(slice, true),
                    "shift={shift} len={len}"
                );
            }
        }

        let mut state: u64 = 20_261_121;
        let next_u64 = |s: &mut u64| -> u64 {
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
            *s
        };
        for idx in 0..500usize {
            let len = (next_u64(&mut state) as usize) % 2048;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                *b = (next_u64(&mut state) & 0xFF) as u8;
            }
            let hw = sha256_bytes_with_mode(&buf, false);
            let sc = sha256_bytes_with_mode(&buf, true);
            assert_eq!(hw, sc, "random idx={idx} len={len}");
        }
    }
}
