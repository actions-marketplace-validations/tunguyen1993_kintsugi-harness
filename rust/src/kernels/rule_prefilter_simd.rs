//! Architecture-specific ARM64 NEON & x86_64 AVX2 Trigram Nibble-Lookup Kernels (`rule_prefilter_simd.rs`).

use super::{RulePrefilter, ScanCtx};

#[cfg(target_arch = "aarch64")]
pub(super) const NEON_BIT_WEIGHTS: [u8; 16] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
];


/// Scalar reference: bit i = `nz0[i] != 0`, bit 16 + i = `nz1[i] != 0`.
#[cfg(any(all(target_arch = "aarch64", debug_assertions), test))]
pub(super) fn pack_32_lane_mask_bits_ref(nz0: &[u8; 16], nz1: &[u8; 16]) -> u32 { (0..32).fold(0u32, |m, i| m | (u32::from((if i < 16 { nz0[i] } else { nz1[i - 16] }) != 0) << i)) }

/// Step 0: `nz = !(cand == 0)` (0xFF/0x00), `nz & weights` maps lane i to `1 << (i % 8)`. Steps 1-3: `vpaddq_u8` sums adjacent
/// pairs 16→8→4→2→1 per 8-lane group; weights are disjoint bits so sum == OR (≤ 0xFF, no carry).
/// Result bytes 0..4 = [cand0 0-7, cand0 8-15, cand1 0-7, cand1 8-15], read little-endian (endian-agnostic via store).
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub(super) unsafe fn pack_32_lane_mask_neon(cand0: std::arch::aarch64::uint8x16_t, cand1: std::arch::aarch64::uint8x16_t, weights: std::arch::aarch64::uint8x16_t) -> u32 {
    use std::arch::aarch64::*;
    let (nz0, nz1) = (vmvnq_u8(vceqzq_u8(cand0)), vmvnq_u8(vceqzq_u8(cand1)));
    let p0 = vpaddq_u8(vandq_u8(nz0, weights), vandq_u8(nz1, weights)); // 16→8 per input: lanes 0..8 = cand0, 8..16 = cand1
    let p2 = { let p1 = vpaddq_u8(p0, p0); vpaddq_u8(p1, p1) }; // 8→4→2→1: one mask byte per 8-lane group
    let mut out = [0u8; 16];
    // SAFETY: `out` is a live, writable 16-byte stack array and `vst1q_u8` writes exactly 16 bytes.
    unsafe { vst1q_u8(out.as_mut_ptr(), p2); }
    let mask = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    #[cfg(debug_assertions)]
    {
        let (mut a, mut b) = ([0u8; 16], [0u8; 16]);
        // SAFETY: `a` and `b` are live, writable 16-byte stack arrays.
        unsafe { vst1q_u8(a.as_mut_ptr(), nz0); vst1q_u8(b.as_mut_ptr(), nz1); }
        debug_assert_eq!(mask, pack_32_lane_mask_bits_ref(&a, &b));
    }
    mask
}

impl RulePrefilter {
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn scan_trigrams_neon(&self, haystack: &[u8], ctx: &mut ScanCtx<'_>) {
        use std::arch::aarch64::*;

        #[inline(always)]
        unsafe fn nibble_filter_16_neon(
            bytes: uint8x16_t, v_lo: uint8x16_t, v_hi: uint8x16_t, mask_0f: uint8x16_t
        ) -> uint8x16_t {
            // SAFETY: All arguments are NEON register values; vqtbl1q_u8/vandq_u8/vshrq_n_u8 are baseline intrinsics.
            unsafe {
                vandq_u8(
                    vqtbl1q_u8(v_lo, vandq_u8(bytes, mask_0f)),
                    vqtbl1q_u8(v_hi, vshrq_n_u8::<4>(bytes)),
                )
            }
        }

        let len = haystack.len();
        if len < 3 {
            return;
        }
        let ptr = haystack.as_ptr();
        // SAFETY: `lo0..hi2` and `NEON_BIT_WEIGHTS` are fixed 16-byte arrays.
        let v_lo0 = unsafe { vld1q_u8(self.lo0.as_ptr()) };
        let v_hi0 = unsafe { vld1q_u8(self.hi0.as_ptr()) };
        let v_lo1 = unsafe { vld1q_u8(self.lo1.as_ptr()) };
        let v_hi1 = unsafe { vld1q_u8(self.hi1.as_ptr()) };
        let v_lo2 = unsafe { vld1q_u8(self.lo2.as_ptr()) };
        let v_hi2 = unsafe { vld1q_u8(self.hi2.as_ptr()) };
        let weights = unsafe { vld1q_u8(NEON_BIT_WEIGHTS.as_ptr()) };
        let mask_0f = vdupq_n_u8(0x0F);

        let mut pos = 0usize;
        while pos + 48 <= len {
            // SAFETY: `pos + 48 <= len` guarantees 3 consecutive 16-byte vector loads stay in-bounds.
            let v0 = unsafe { vld1q_u8(ptr.add(pos)) };
            let v1 = unsafe { vld1q_u8(ptr.add(pos + 16)) };
            let v2 = unsafe { vld1q_u8(ptr.add(pos + 32)) };

            let p0_a = v0;
            let p1_a = vextq_u8::<1>(v0, v1);
            let p2_a = vextq_u8::<2>(v0, v1);
            // SAFETY: nibble_filter_16_neon is a local wrapper; all args are NEON registers.
            let m0_a = unsafe { nibble_filter_16_neon(p0_a, v_lo0, v_hi0, mask_0f) };
            let m1_a = unsafe { nibble_filter_16_neon(p1_a, v_lo1, v_hi1, mask_0f) };
            let m2_a = unsafe { nibble_filter_16_neon(p2_a, v_lo2, v_hi2, mask_0f) };
            let cand0 = vandq_u8(vandq_u8(m0_a, m1_a), m2_a);

            let p0_b = v1;
            let p1_b = vextq_u8::<1>(v1, v2);
            let p2_b = vextq_u8::<2>(v1, v2);
            // SAFETY: nibble_filter_16_neon is a local wrapper; all args are NEON registers.
            let m0_b = unsafe { nibble_filter_16_neon(p0_b, v_lo0, v_hi0, mask_0f) };
            let m1_b = unsafe { nibble_filter_16_neon(p1_b, v_lo1, v_hi1, mask_0f) };
            let m2_b = unsafe { nibble_filter_16_neon(p2_b, v_lo2, v_hi2, mask_0f) };
            let cand1 = vandq_u8(vandq_u8(m0_b, m1_b), m2_b);

            if vmaxvq_u8(vorrq_u8(cand0, cand1)) != 0 {
                // SAFETY: NEON is baseline on aarch64 (enabled for this kernel); arguments are plain register values.
                let mut mask32 = unsafe { pack_32_lane_mask_neon(cand0, cand1, weights) };
                while mask32 != 0 {
                    let lane = mask32.trailing_zeros() as usize;
                    self.verify_trigram_at(haystack, pos + lane, ctx);
                    mask32 &= mask32 - 1;
                }
            }
            pos += 32;
        }

        while pos + 18 <= len {
            // SAFETY: `pos + 18 <= len` guarantees 16-byte loads at `pos`, `pos+1`, `pos+2` are in-bounds.
            let c0 = unsafe { vld1q_u8(ptr.add(pos)) };
            let c1 = unsafe { vld1q_u8(ptr.add(pos + 1)) };
            let c2 = unsafe { vld1q_u8(ptr.add(pos + 2)) };
            // SAFETY: nibble_filter_16_neon is a local wrapper; all args are NEON registers.
            let ma = unsafe { nibble_filter_16_neon(c0, v_lo0, v_hi0, mask_0f) };
            let mb = unsafe { nibble_filter_16_neon(c1, v_lo1, v_hi1, mask_0f) };
            let mc = unsafe { nibble_filter_16_neon(c2, v_lo2, v_hi2, mask_0f) };
            let cand = vandq_u8(vandq_u8(ma, mb), mc);
            if vmaxvq_u8(cand) != 0 {
                // SAFETY: pack_32_lane_mask_neon is baseline for aarch64; vdupq_n_u8(0) is a plain zero register.
                let mut mask16 = unsafe { pack_32_lane_mask_neon(cand, vdupq_n_u8(0), weights) } as u16;
                while mask16 != 0 {
                    let lane = mask16.trailing_zeros() as usize;
                    self.verify_trigram_at(haystack, pos + lane, ctx);
                    mask16 &= mask16 - 1;
                }
            }
            pos += 16;
        }

        while pos + 2 < len {
            self.verify_trigram_at(haystack, pos, ctx);
            pos += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn nibble_filter_32_avx2(
        c: std::arch::x86_64::__m256i,
        v_lo: std::arch::x86_64::__m256i,
        v_hi: std::arch::x86_64::__m256i,
        mask_0f: std::arch::x86_64::__m256i,
    ) -> std::arch::x86_64::__m256i {
        use std::arch::x86_64::*;
        _mm256_and_si256(
            _mm256_shuffle_epi8(v_lo, _mm256_and_si256(c, mask_0f)),
            _mm256_shuffle_epi8(v_hi, _mm256_and_si256(_mm256_srli_epi16(c, 4), mask_0f)),
        )
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[inline]
    pub(super) unsafe fn pack_32_lane_mask_avx2(cand: std::arch::x86_64::__m256i) -> u32 {
        use std::arch::x86_64::*;
        let eqz = _mm256_cmpeq_epi8(cand, _mm256_setzero_si256());
        !(_mm256_movemask_epi8(eqz) as u32)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn scan_trigrams_avx2(&self, haystack: &[u8], ctx: &mut ScanCtx<'_>) {
        use std::arch::x86_64::*;

        let len = haystack.len();
        if len < 3 {
            return;
        }
        let ptr = haystack.as_ptr();
        // SAFETY: `lo0..hi2` are fixed 16-byte arrays valid for unaligned 128-bit loads.
        let v_lo0 = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(self.lo0.as_ptr() as *const __m128i) });
        // SAFETY: `hi0` is a fixed 16-byte array.
        let v_hi0 = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(self.hi0.as_ptr() as *const __m128i) });
        // SAFETY: `lo1` is a fixed 16-byte array.
        let v_lo1 = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(self.lo1.as_ptr() as *const __m128i) });
        // SAFETY: `hi1` is a fixed 16-byte array.
        let v_hi1 = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(self.hi1.as_ptr() as *const __m128i) });
        // SAFETY: `lo2` is a fixed 16-byte array.
        let v_lo2 = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(self.lo2.as_ptr() as *const __m128i) });
        // SAFETY: `hi2` is a fixed 16-byte array.
        let v_hi2 = _mm256_broadcastsi128_si256(unsafe { _mm_loadu_si128(self.hi2.as_ptr() as *const __m128i) });
        let mask_0f = _mm256_set1_epi8(0x0F);

        let mut pos = 0usize;
        while pos + 34 <= len {
            // SAFETY: `pos + 34 <= len` guarantees 32-byte unaligned loads at `pos`, `pos+1`, `pos+2` stay in-bounds.
            let (c0, c1, c2) = unsafe {
                (
                    _mm256_loadu_si256(ptr.add(pos) as *const __m256i),
                    _mm256_loadu_si256(ptr.add(pos + 1) as *const __m256i),
                    _mm256_loadu_si256(ptr.add(pos + 2) as *const __m256i),
                )
            };
            // SAFETY: AVX2 is enabled for this function (`#[target_feature(enable = "avx2")]`).
            let cand = unsafe {
                let m0 = Self::nibble_filter_32_avx2(c0, v_lo0, v_hi0, mask_0f);
                let m1 = Self::nibble_filter_32_avx2(c1, v_lo1, v_hi1, mask_0f);
                let m2 = Self::nibble_filter_32_avx2(c2, v_lo2, v_hi2, mask_0f);
                _mm256_and_si256(_mm256_and_si256(m0, m1), m2)
            };
            // SAFETY: AVX2 is enabled for this function.
            let mut mask = unsafe { Self::pack_32_lane_mask_avx2(cand) };
            while mask != 0 {
                let lane = mask.trailing_zeros() as usize;
                self.verify_trigram_at(haystack, pos + lane, ctx);
                mask &= mask - 1;
            }
            pos += 32;
        }
        while pos + 2 < len {
            self.verify_trigram_at(haystack, pos, ctx);
            pos += 1;
        }
    }
}
