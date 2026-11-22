//! Tier 3: Architecture-Accelerated SIMD Byte Scanner (`kintsugi_core::kernels::byte_scanner`).
//!
//! - `aarch64`: 64-byte unrolled + 16-byte tail ARM64 NEON intrinsics (`std::arch::aarch64`)
//!   using `vld1q_u8` / `vceqq_u8` / `vpaddq_u8` compressed bitmask extraction.
//! - `x86_64`: Runtime `is_x86_feature_detected!("avx2")` 64-byte/32-byte AVX2 intrinsics.
//! - Explicit `disable_simd: bool` override routes straight to `scalar::*` so the
//!   fallback path can be benchmarked and differential-tested independently.

use crate::kernels::scalar;

#[cfg(target_arch = "aarch64")]
const NEON_BIT_WEIGHTS: [u8; 16] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
];

/// Return the canonical backend identifier that will be used on this host.
pub fn active_simd_backend(disable_simd: bool) -> &'static str {
    if disable_simd {
        return "rust_scalar_fallback";
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return "aarch64_neon_intrinsics";
        }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            return "x86_64_avx2_intrinsics";
        }
    }
    "rust_scalar"
}

/// Scan `data` for exact byte offsets of `delim`, honoring `disable_simd`.
#[inline]
pub fn scan_delimiters(data: &[u8], delim: u8, disable_simd: bool) -> Vec<usize> {
    let mut out = Vec::new();
    scan_delimiters_into(data, delim, disable_simd, &mut out);
    out
}

/// Scan `data` for exact byte offsets of `delim`, returning `(offsets, backend_name)`.
#[inline]
pub fn scan_delimiters_with_backend(
    data: &[u8],
    delim: u8,
    disable_simd: bool,
) -> (Vec<usize>, &'static str) {
    let backend = active_simd_backend(disable_simd);
    let offsets = scan_delimiters(data, delim, disable_simd);
    (offsets, backend)
}

/// Append exact byte offsets of `delim` in `data` into `out`, honoring `disable_simd`.
#[inline]
pub fn scan_delimiters_into(data: &[u8], delim: u8, disable_simd: bool, out: &mut Vec<usize>) {
    if data.is_empty() {
        return;
    }
    if disable_simd {
        scalar::scan_delimiters_scalar_into(data, delim, out);
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON feature availability was verified immediately above and
            // `scan_delimiters_neon_into` enforces exact slice length bounds before every load.
            unsafe {
                scan_delimiters_neon_into(data, delim, out);
            }
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 runtime support was verified via `is_x86_feature_detected!("avx2")`.
            unsafe {
                scan_delimiters_avx2_into(data, delim, out);
            }
            return;
        }
    }

    scalar::scan_delimiters_scalar_into(data, delim, out);
}

/// Count exact occurrences of `delim` in `data`, honoring `disable_simd`.
#[inline]
pub fn count_delimiters(data: &[u8], delim: u8, disable_simd: bool) -> usize {
    if data.is_empty() {
        return 0;
    }
    if disable_simd {
        return scalar::count_delimiters_scalar(data, delim);
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON feature availability was verified immediately above and
            // `count_delimiters_neon` checks slice bounds before every vector load.
            unsafe {
                return count_delimiters_neon(data, delim);
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 runtime support was verified via `is_x86_feature_detected!("avx2")`.
            unsafe {
                return count_delimiters_avx2(data, delim);
            }
        }
    }

    scalar::count_delimiters_scalar(data, delim)
}

/// Scan `data` left-to-right for non-overlapping occurrences of `pattern`.
#[inline]
pub fn scan_multibyte_delimiters(data: &[u8], pattern: &[u8], disable_simd: bool) -> Vec<usize> {
    let mut out = Vec::new();
    scan_multibyte_delimiters_into(data, pattern, disable_simd, &mut out);
    out
}

/// Append non-overlapping left-to-right byte offsets of `pattern` in `data` into `out`.
#[inline]
pub fn scan_multibyte_delimiters_into(
    data: &[u8],
    pattern: &[u8],
    disable_simd: bool,
    out: &mut Vec<usize>,
) {
    let m = pattern.len();
    if m == 0 || data.len() < m {
        return;
    }
    if m == 1 {
        scan_delimiters_into(data, pattern[0], disable_simd, out);
        return;
    }
    if disable_simd {
        scalar::scan_multibyte_delimiters_scalar_into(data, pattern, out);
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON availability verified above; `scan_multibyte_neon_into` bounds-checks
            // `search_end = data.len() - (m - 1)` so both `pos` and `pos + m - 1` loads stay in bounds.
            unsafe {
                scan_multibyte_neon_into(data, pattern, out);
            }
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 availability verified above; bounds-checked via `search_end`.
            unsafe {
                scan_multibyte_avx2_into(data, pattern, out);
            }
            return;
        }
    }

    scalar::scan_multibyte_delimiters_scalar_into(data, pattern, out);
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn emit_mask_u64(base: usize, mut mask: u64, out: &mut Vec<usize>) {
    while mask != 0 {
        let tz = mask.trailing_zeros() as usize;
        out.push(base + tz);
        mask &= mask - 1;
    }
}

/// ARM64 NEON 64-byte unrolled + 16-byte tail delimiter offset scanner.
///
/// # Safety
/// Caller must ensure AArch64 NEON is available on the executing CPU.
/// All pointer offsets are bounds-checked against `data.len()`.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn scan_delimiters_neon_into(data: &[u8], delim: u8, out: &mut Vec<usize>) {
    use std::arch::aarch64::*;

    let len = data.len();
    let ptr = data.as_ptr();
    let needle = vdupq_n_u8(delim);
    // SAFETY: `NEON_BIT_WEIGHTS` is a static 16-byte array; `vld1q_u8` permits 1-byte alignment.
    let weights = unsafe { vld1q_u8(NEON_BIT_WEIGHTS.as_ptr()) };

    let mut offset = 0usize;
    while offset + 64 <= len {
        // SAFETY: `offset + 64 <= len` guarantees 64 readable bytes from `ptr.add(offset)`.
        let v0 = unsafe { vld1q_u8(ptr.add(offset)) };
        let v1 = unsafe { vld1q_u8(ptr.add(offset + 16)) };
        let v2 = unsafe { vld1q_u8(ptr.add(offset + 32)) };
        let v3 = unsafe { vld1q_u8(ptr.add(offset + 48)) };

        let eq0 = vceqq_u8(v0, needle);
        let eq1 = vceqq_u8(v1, needle);
        let eq2 = vceqq_u8(v2, needle);
        let eq3 = vceqq_u8(v3, needle);

        let m0 = vandq_u8(eq0, weights);
        let m1 = vandq_u8(eq1, weights);
        let m2 = vandq_u8(eq2, weights);
        let m3 = vandq_u8(eq3, weights);

        let p0 = vpaddq_u8(m0, m1);
        let p1 = vpaddq_u8(m2, m3);
        let p2 = vpaddq_u8(p0, p1);
        let p3 = vpaddq_u8(p2, p2);

        #[allow(unused_mut)]
        let mut mask = vgetq_lane_u64(vreinterpretq_u64_u8(p3), 0);
        #[cfg(target_endian = "big")]
        {
            mask = mask.swap_bytes();
        }
        if mask != 0 {
            // SAFETY: Bit indices `0..64` map directly to `offset..offset + 64`.
            unsafe { emit_mask_u64(offset, mask, out) };
        }
        offset += 64;
    }

    while offset + 16 <= len {
        // SAFETY: `offset + 16 <= len` guarantees 16 readable bytes from `ptr.add(offset)`.
        let v = unsafe { vld1q_u8(ptr.add(offset)) };
        let eq = vceqq_u8(v, needle);
        let masked = vandq_u8(eq, weights);
        let p0 = vpaddq_u8(masked, masked);
        let p1 = vpaddq_u8(p0, p0);
        let p2 = vpaddq_u8(p1, p1);
        #[allow(unused_mut)]
        let mut mask16 = vgetq_lane_u16(vreinterpretq_u16_u8(p2), 0);
        #[cfg(target_endian = "big")]
        {
            mask16 = mask16.swap_bytes();
        }
        while mask16 != 0 {
            let tz = mask16.trailing_zeros() as usize;
            out.push(offset + tz);
            mask16 &= mask16 - 1;
        }
        offset += 16;
    }

    while offset < len {
        // SAFETY: `offset < len`.
        if unsafe { *ptr.add(offset) } == delim {
            out.push(offset);
        }
        offset += 1;
    }
}

/// Safe public wrapper for invoking the `aarch64` NEON delimiter scanner directly in tests/benchmarks.
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn scan_delimiters_neon(data: &[u8], delim: u8) -> Vec<usize> {
    let mut out = Vec::new();
    if !data.is_empty() && std::arch::is_aarch64_feature_detected!("neon") {
        // SAFETY: NEON support verified via runtime detection.
        unsafe { scan_delimiters_neon_into(data, delim, &mut out) };
    } else {
        scalar::scan_delimiters_scalar_into(data, delim, &mut out);
    }
    out
}

/// ARM64 NEON pure-SIMD delimiter counter (accumulates in vector lanes, zero bitmask unpack).
///
/// # Safety
/// Caller must ensure AArch64 NEON is available on the executing CPU.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub unsafe fn count_delimiters_neon(data: &[u8], delim: u8) -> usize {
    use std::arch::aarch64::*;

    let len = data.len();
    let ptr = data.as_ptr();
    let needle = vdupq_n_u8(delim);
    let mut total = 0usize;
    let mut offset = 0usize;

    // Accumulate up to 63 64-byte blocks (<= 252 per lane) in u8 lanes before widening to u16.
    while offset + 64 <= len {
        let mut acc0 = vdupq_n_u8(0);
        let mut acc1 = vdupq_n_u8(0);
        let mut acc2 = vdupq_n_u8(0);
        let mut acc3 = vdupq_n_u8(0);
        let mut rounds = 0usize;
        while rounds < 252 && offset + 64 <= len {
            // SAFETY: `offset + 64 <= len`.
            let v0 = unsafe { vld1q_u8(ptr.add(offset)) };
            let v1 = unsafe { vld1q_u8(ptr.add(offset + 16)) };
            let v2 = unsafe { vld1q_u8(ptr.add(offset + 32)) };
            let v3 = unsafe { vld1q_u8(ptr.add(offset + 48)) };
            // `vceqq_u8` yields 0xFF (-1 in u8 wrapping arithmetic); subtracting adds +1 per match.
            acc0 = vsubq_u8(acc0, vceqq_u8(v0, needle));
            acc1 = vsubq_u8(acc1, vceqq_u8(v1, needle));
            acc2 = vsubq_u8(acc2, vceqq_u8(v2, needle));
            acc3 = vsubq_u8(acc3, vceqq_u8(v3, needle));
            offset += 64;
            rounds += 1;
        }
        let sum16 = vaddq_u16(
            vaddq_u16(vpaddlq_u8(acc0), vpaddlq_u8(acc1)),
            vaddq_u16(vpaddlq_u8(acc2), vpaddlq_u8(acc3)),
        );
        total += vaddlvq_u16(sum16) as usize;
    }

    while offset + 16 <= len {
        // SAFETY: `offset + 16 <= len`.
        let v = unsafe { vld1q_u8(ptr.add(offset)) };
        let eq = vceqq_u8(v, needle);
        let ones = vsubq_u8(vdupq_n_u8(0), eq);
        total += vaddvq_u8(ones) as usize;
        offset += 16;
    }

    while offset < len {
        // SAFETY: `offset < len`.
        if unsafe { *ptr.add(offset) } == delim {
            total += 1;
        }
        offset += 1;
    }

    total
}

/// ARM64 NEON first+last byte SIMD prefilter for multi-byte delimiter scanning.
///
/// # Safety
/// Caller must ensure AArch64 NEON is available and `pattern.len() >= 2` and `data.len() >= pattern.len()`.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn scan_multibyte_neon_into(data: &[u8], pattern: &[u8], out: &mut Vec<usize>) {
    use std::arch::aarch64::*;

    let m = pattern.len();
    let len = data.len();
    let search_end = len - (m - 1);
    let ptr = data.as_ptr();
    let first_vec = vdupq_n_u8(pattern[0]);
    let last_vec = vdupq_n_u8(pattern[m - 1]);
    // SAFETY: `NEON_BIT_WEIGHTS` is a static 16-byte array.
    let weights = unsafe { vld1q_u8(NEON_BIT_WEIGHTS.as_ptr()) };

    let mut pos = 0usize;
    let mut next_allowed = 0usize;

    while pos + 64 <= search_end {
        // SAFETY: `pos + 64 <= len - (m - 1)` implies both `pos + 64 <= len` and `pos + (m - 1) + 64 <= len`.
        let f0 = unsafe { vld1q_u8(ptr.add(pos)) };
        let f1 = unsafe { vld1q_u8(ptr.add(pos + 16)) };
        let f2 = unsafe { vld1q_u8(ptr.add(pos + 32)) };
        let f3 = unsafe { vld1q_u8(ptr.add(pos + 48)) };

        let l0 = unsafe { vld1q_u8(ptr.add(pos + m - 1)) };
        let l1 = unsafe { vld1q_u8(ptr.add(pos + m - 1 + 16)) };
        let l2 = unsafe { vld1q_u8(ptr.add(pos + m - 1 + 32)) };
        let l3 = unsafe { vld1q_u8(ptr.add(pos + m - 1 + 48)) };

        let eq0 = vandq_u8(vceqq_u8(f0, first_vec), vceqq_u8(l0, last_vec));
        let eq1 = vandq_u8(vceqq_u8(f1, first_vec), vceqq_u8(l1, last_vec));
        let eq2 = vandq_u8(vceqq_u8(f2, first_vec), vceqq_u8(l2, last_vec));
        let eq3 = vandq_u8(vceqq_u8(f3, first_vec), vceqq_u8(l3, last_vec));

        let m0 = vandq_u8(eq0, weights);
        let m1 = vandq_u8(eq1, weights);
        let m2 = vandq_u8(eq2, weights);
        let m3 = vandq_u8(eq3, weights);

        let p0 = vpaddq_u8(m0, m1);
        let p1 = vpaddq_u8(m2, m3);
        let p2 = vpaddq_u8(p0, p1);
        let p3 = vpaddq_u8(p2, p2);

        #[allow(unused_mut)]
        let mut mask = vgetq_lane_u64(vreinterpretq_u64_u8(p3), 0);
        #[cfg(target_endian = "big")]
        {
            mask = mask.swap_bytes();
        }
        while mask != 0 {
            let tz = mask.trailing_zeros() as usize;
            let cand = pos + tz;
            if cand >= next_allowed && &data[cand..cand + m] == pattern {
                out.push(cand);
                next_allowed = cand + m;
            }
            mask &= mask - 1;
        }
        pos = (pos + 64).max(next_allowed);
    }

    while pos + 16 <= search_end {
        // SAFETY: `pos + 16 <= len - (m - 1)` keeps both 16-byte loads strictly inside `data`.
        let f = unsafe { vld1q_u8(ptr.add(pos)) };
        let l = unsafe { vld1q_u8(ptr.add(pos + m - 1)) };
        let eq = vandq_u8(vceqq_u8(f, first_vec), vceqq_u8(l, last_vec));
        let masked = vandq_u8(eq, weights);
        let p0 = vpaddq_u8(masked, masked);
        let p1 = vpaddq_u8(p0, p0);
        let p2 = vpaddq_u8(p1, p1);
        #[allow(unused_mut)]
        let mut mask16 = vgetq_lane_u16(vreinterpretq_u16_u8(p2), 0);
        #[cfg(target_endian = "big")]
        {
            mask16 = mask16.swap_bytes();
        }
        while mask16 != 0 {
            let tz = mask16.trailing_zeros() as usize;
            let cand = pos + tz;
            if cand >= next_allowed && &data[cand..cand + m] == pattern {
                out.push(cand);
                next_allowed = cand + m;
            }
            mask16 &= mask16 - 1;
        }
        pos = (pos + 16).max(next_allowed);
    }

    let mut idx = pos.max(next_allowed);
    while idx < search_end {
        if &data[idx..idx + m] == pattern {
            out.push(idx);
            idx += m;
        } else {
            idx += 1;
        }
    }
}

/// x86_64 AVX2 64-byte unrolled + 32-byte tail delimiter offset scanner.
///
/// # Safety
/// Caller must ensure runtime CPU support via `is_x86_feature_detected!("avx2")`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_delimiters_avx2_into(data: &[u8], delim: u8, out: &mut Vec<usize>) {
    use std::arch::x86_64::*;

    let len = data.len();
    let ptr = data.as_ptr();
    let needle = _mm256_set1_epi8(delim as i8);
    let mut offset = 0usize;

    while offset + 64 <= len {
        // SAFETY: `offset + 64 <= len`; `_mm256_loadu_si256` allows arbitrary alignment.
        let v0 = unsafe { _mm256_loadu_si256(ptr.add(offset) as *const __m256i) };
        let v1 = unsafe { _mm256_loadu_si256(ptr.add(offset + 32) as *const __m256i) };
        let m0 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, needle)) as u32 as u64;
        let m1 = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, needle)) as u32 as u64;
        let mut mask = m0 | (m1 << 32);
        while mask != 0 {
            let tz = mask.trailing_zeros() as usize;
            out.push(offset + tz);
            mask &= mask - 1;
        }
        offset += 64;
    }

    while offset + 32 <= len {
        // SAFETY: `offset + 32 <= len`.
        let v = unsafe { _mm256_loadu_si256(ptr.add(offset) as *const __m256i) };
        let mut mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, needle)) as u32;
        while mask != 0 {
            let tz = mask.trailing_zeros() as usize;
            out.push(offset + tz);
            mask &= mask - 1;
        }
        offset += 32;
    }

    while offset < len {
        // SAFETY: `offset < len`.
        if unsafe { *ptr.add(offset) } == delim {
            out.push(offset);
        }
        offset += 1;
    }
}

/// x86_64 AVX2 delimiter counter.
///
/// # Safety
/// Caller must ensure runtime CPU support via `is_x86_feature_detected!("avx2")`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn count_delimiters_avx2(data: &[u8], delim: u8) -> usize {
    use std::arch::x86_64::*;

    let len = data.len();
    let ptr = data.as_ptr();
    let needle = _mm256_set1_epi8(delim as i8);
    let mut total = 0usize;
    let mut offset = 0usize;

    while offset + 32 <= len {
        // SAFETY: `offset + 32 <= len`.
        let v = unsafe { _mm256_loadu_si256(ptr.add(offset) as *const __m256i) };
        let mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, needle)) as u32;
        total += mask.count_ones() as usize;
        offset += 32;
    }
    while offset < len {
        // SAFETY: `offset < len`.
        if unsafe { *ptr.add(offset) } == delim {
            total += 1;
        }
        offset += 1;
    }
    total
}

/// x86_64 AVX2 first+last byte SIMD prefilter for multi-byte delimiter scanning.
///
/// # Safety
/// Caller must ensure runtime CPU support via `is_x86_feature_detected!("avx2")`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn scan_multibyte_avx2_into(data: &[u8], pattern: &[u8], out: &mut Vec<usize>) {
    use std::arch::x86_64::*;

    let m = pattern.len();
    let search_end = data.len() - (m - 1);
    let ptr = data.as_ptr();
    let first_vec = _mm256_set1_epi8(pattern[0] as i8);
    let last_vec = _mm256_set1_epi8(pattern[m - 1] as i8);

    let mut pos = 0usize;
    let mut next_allowed = 0usize;

    while pos + 32 <= search_end {
        // SAFETY: `pos + 32 <= data.len() - (m - 1)`.
        let f = unsafe { _mm256_loadu_si256(ptr.add(pos) as *const __m256i) };
        let l = unsafe { _mm256_loadu_si256(ptr.add(pos + m - 1) as *const __m256i) };
        let eq = _mm256_and_si256(
            _mm256_cmpeq_epi8(f, first_vec),
            _mm256_cmpeq_epi8(l, last_vec),
        );
        let mut mask = _mm256_movemask_epi8(eq) as u32;
        while mask != 0 {
            let tz = mask.trailing_zeros() as usize;
            let cand = pos + tz;
            if cand >= next_allowed && &data[cand..cand + m] == pattern {
                out.push(cand);
                next_allowed = cand + m;
            }
            mask &= mask - 1;
        }
        pos = (pos + 32).max(next_allowed);
    }

    let mut idx = pos.max(next_allowed);
    while idx < search_end {
        if &data[idx..idx + m] == pattern {
            out.push(idx);
            idx += m;
        } else {
            idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neon_and_scalar_parity_on_boundaries_and_unaligned_slices() {
        // Build a deterministic 256-byte buffer with delimiters at prime/boundary indices.
        let mut buf = vec![b'x'; 256];
        for i in [0, 1, 14, 15, 16, 17, 30, 31, 32, 33, 62, 63, 64, 65, 127, 128, 129, 255] {
            buf[i] = b'\n';
        }
        for shift in [0usize, 1, 3, 7, 15] {
            for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 63, 65, 129, buf.len() - shift] {
                let slice = &buf[shift..shift + len];
                let scalar_res = scalar::scan_delimiters_scalar(slice, b'\n');
                let simd_res = scan_delimiters(slice, b'\n', false);
                let fallback_res = scan_delimiters(slice, b'\n', true);
                assert_eq!(simd_res, scalar_res, "shift={shift} len={len}");
                assert_eq!(fallback_res, scalar_res, "fallback shift={shift} len={len}");
                assert_eq!(count_delimiters(slice, b'\n', false), scalar_res.len());
                assert_eq!(count_delimiters(slice, b'\n', true), scalar_res.len());
            }
        }
    }

    #[test]
    fn multibyte_simd_and_scalar_parity() {
        let payload = b"aa||bb||cc||||dd\r\naa||ee\r\n|||||x||";
        for pat in [b"||".as_slice(), b"\r\n".as_slice(), b"|||".as_slice(), b"|".as_slice()] {
            let s = scalar::scan_multibyte_delimiters_scalar(payload, pat);
            let a = scan_multibyte_delimiters(payload, pat, false);
            let f = scan_multibyte_delimiters(payload, pat, true);
            assert_eq!(a, s);
            assert_eq!(f, s);
        }
    }

    #[test]
    fn seeded_fuzz_600_cases_parity() {
        let mut state: u64 = 20_261_121;
        let next_u64 = |s: &mut u64| -> u64 {
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
            *s
        };
        for case_idx in 0..600usize {
            let len = if case_idx < 300 {
                (next_u64(&mut state) as usize) % 260
            } else {
                260 + ((next_u64(&mut state) as usize) % 2048)
            };
            let delim = match case_idx % 4 {
                0 => b'\n',
                1 => b'\0',
                2 => b'|',
                _ => (next_u64(&mut state) & 0xFF) as u8,
            };
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                let r = next_u64(&mut state);
                *b = if (r & 7) == 0 { delim } else { (r >> 8) as u8 };
            }
            let shift = (next_u64(&mut state) as usize) % 16;
            let slice = if shift < buf.len() { &buf[shift..] } else { &buf[..] };
            let exp = scalar::scan_delimiters_scalar(slice, delim);
            assert_eq!(scan_delimiters(slice, delim, false), exp, "case {case_idx}");
            assert_eq!(scan_delimiters(slice, delim, true), exp, "fb case {case_idx}");
            assert_eq!(count_delimiters(slice, delim, false), exp.len());

            let pat = [delim, delim ^ 0x55];
            let exp_mb = scalar::scan_multibyte_delimiters_scalar(slice, &pat);
            assert_eq!(scan_multibyte_delimiters(slice, &pat, false), exp_mb);
            assert_eq!(scan_multibyte_delimiters(slice, &pat, true), exp_mb);
        }
    }
}
