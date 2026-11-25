//! Vectorized ARM64 NEON / AVX2 Multi-Literal Flat-CSR Rule Prefilter (`kintsugi_core::kernels::rule_prefilter`).
//!
//! Guarantees 100% recall (ZERO false negatives): a rule is eliminated ONLY when its
//! required literal tokens are provably absent from the input buffer.
//!
//! Two-Stage Filtering Architecture:
//! - **Stage 1 (Register-Speed Coarse Modulo-8 SIMD Nibble Filter)**: Uses `vqtbl1q_u8` (`aarch64` NEON)
//!   or `_mm256_shuffle_epi8` (`x86_64` AVX2) over 3-byte anchor trigrams mapped to `1 << (lit_idx & 7)`
//!   8-bit bucket masks (`coarse_lane_hits`). Rejects 16B/32B chunks at register speed for small/medium
//!   rule sets (`<= 256` rules). As literal count grows toward `1,797` KML rules, the 8 modulo-8 bucket
//!   bits saturate across common ASCII nibbles and cleanly hand off selectivity to Stage 2.
//! - **Stage 2 (Exact Flat-CSR Second-Stage Verification)**: Every coarse lane hit probes an L1-resident
//!   `2 KiB` (`16,384`-bit) `trigram_bitset` (`candidate_hits`), indexing contiguous Flat-CSR `bucket_offsets`
//!   (`Box<[u32; 16385]>`) and `bucket_entries` (`Box<[u32]>`) before full slice verification (`full_verifications`),
//!   alongside a single-pass `O(N)` 2-byte digram table and zero-allocation `[u64; 4]` stack bitsets for `<= 256` rules.

use std::sync::OnceLock;

pub use crate::kernels::prefilter_tables::*;

/// Cached runtime SIMD backend selected once per process via `cached_prefilter_backend()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefilterBackend { Aarch64NeonTeddy, X86Avx2Teddy, RustScalar }

///Specification of one required literal token belonging to `rule_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiteralSpec { pub rule_index: usize, pub pattern: Vec<u8>, pub case_insensitive: bool }

/// Telemetry counters returned by `RulePrefilter::scan_stats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefilterStats {
    pub bytes_scanned: usize,
    /// Positions passing the Stage-1 8-bit modulo-8 SIMD nibble filter (or scalar window probe).
    pub coarse_lane_hits: usize,
    /// Total CSR bucket hits across both 2-byte digrams and 3-byte trigrams.
    pub candidate_hits: usize,
    /// Positions hitting the Stage-2 14-bit `trigram_bitset` specifically (excluding 2-byte digrams).
    pub trigram_candidates: usize,
    /// Exact slice comparisons executed against `CompiledLiteral::pattern`.
    pub full_verifications: usize,
}

/// Packed digram entry: 2 B key + 4 B index + 2 B padding = 8 B per entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SmallDigramEntry { key: u16, lit_idx: u32 }

const _: () = assert!(std::mem::size_of::<SmallDigramEntry>() == 8);

/// Bit-width of the Stage-2 trigram hash (`2^14 = 16,384` buckets = `2 KiB` single-hash occupancy bitset).
pub const TRIGRAM_HASH_BITS: u32 = 14;
/// Total number of Stage-2 trigram CSR buckets (`1 << TRIGRAM_HASH_BITS == 16,384`).
pub const TRIGRAM_BUCKETS: usize = 1usize << TRIGRAM_HASH_BITS;
/// Max digrams kept in `DigramMode::Small`: 16 × 8 B = 128 B = 2 × 64 B L1 cache lines; linear scan beats allocating `DigramMode::Full` (8 KiB bitset + 256 KiB CSR offsets).
pub const SMALL_DIGRAM_LINEAR_CAP: usize = 16;
/// Trigram CSR occupancy over the 16,384 buckets; `collision_bucket_pct` = colliding (depth >= 2) / occupied × 100.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BucketCollisionStats { pub total_buckets: usize, pub occupied_buckets: usize, pub total_entries: usize, pub max_bucket_depth: usize, pub colliding_buckets: usize, pub collision_bucket_pct: f64 }

#[derive(Debug, Clone)]
struct CompiledLiteral { rule_index: usize, pattern: Vec<u8>, anchor_offset: usize, case_insensitive: bool }

struct ScanCtx<'a> { bits: &'a mut [u64], coarse_lane_hits: usize, trigram_candidates: usize, candidate_hits: usize, full_verifications: usize }

#[derive(Debug, Clone)]
enum DigramMode {
    None,
    Small {
        first_byte_mask: [u64; 4],
        entries: Vec<SmallDigramEntry>,
    },
    Full {
        present: Box<[u64; 1024]>,
        offsets: Box<[u32; 65537]>,
        entries: Box<[u32]>,
    },
}

/// Conservative multi-literal Flat-CSR SIMD prefilter over `num_rules` rules.
#[derive(Debug, Clone)]
pub struct RulePrefilter {
    num_rules: usize,
    always_active: Vec<usize>,
    single_bytes: Vec<(u8, usize, bool)>,
    has_single_bytes: bool,
    digram_lits: Vec<CompiledLiteral>,
    digram_mode: DigramMode,
    trigram_lits: Vec<CompiledLiteral>,
    has_trigrams: bool,
    lo0: [u8; 16],
    hi0: [u8; 16],
    lo1: [u8; 16],
    hi1: [u8; 16],
    lo2: [u8; 16],
    hi2: [u8; 16],
    trigram_bitset: Box<[u64; 256]>,
    bucket_offsets: Box<[u32; 16385]>,
    bucket_entries: Box<[u32]>,
}

#[path = "rule_prefilter_simd.rs"]
mod simd_arch;
#[cfg(test)]
use simd_arch::pack_32_lane_mask_bits_ref;
#[cfg(all(test, target_arch = "aarch64"))]
use simd_arch::{pack_32_lane_mask_neon, NEON_BIT_WEIGHTS};

impl RulePrefilter {
    /// Bucket depth(b) = `bucket_offsets[b + 1] - bucket_offsets[b]` (prefix-summed CSR, 16,385 offsets → 16,384 buckets).
    pub fn collision_stats(&self) -> BucketCollisionStats {
        let (mut occupied_buckets, mut max_bucket_depth, mut colliding_buckets) = (0usize, 0usize, 0usize);
        for d in self.bucket_offsets.windows(2).map(|w| (w[1] - w[0]) as usize) { occupied_buckets += usize::from(d > 0); colliding_buckets += usize::from(d > 1); max_bucket_depth = max_bucket_depth.max(d); }
        let collision_bucket_pct = if occupied_buckets == 0 { 0.0 } else { colliding_buckets as f64 * 100.0 / occupied_buckets as f64 };
        BucketCollisionStats { total_buckets: self.bucket_offsets.len() - 1, occupied_buckets, total_entries: self.bucket_entries.len(), max_bucket_depth, colliding_buckets, collision_bucket_pct }
    }
}

#[inline]
pub fn cached_prefilter_backend() -> PrefilterBackend {
    static BACKEND: OnceLock<PrefilterBackend> = OnceLock::new();
    *BACKEND.get_or_init(|| {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("neon") {
            return PrefilterBackend::Aarch64NeonTeddy;
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("avx2") {
            return PrefilterBackend::X86Avx2Teddy;
        }
        PrefilterBackend::RustScalar
    })
}

/// Return the active prefilter backend string on this CPU (reusing `cached_prefilter_backend()`).
pub fn active_prefilter_backend(disable_simd: bool) -> &'static str {
    if disable_simd {
        return "rust_scalar_fallback";
    }
    match cached_prefilter_backend() {
        PrefilterBackend::Aarch64NeonTeddy => "aarch64_neon_teddy",
        PrefilterBackend::X86Avx2Teddy => "x86_64_avx2_teddy",
        PrefilterBackend::RustScalar => "rust_scalar",
    }
}

#[inline]
fn byte_rarity_score(b: u8, case_insensitive: bool) -> u16 {
    if !case_insensitive && b.is_ascii_uppercase() {
        return 22;
    }
    match b.to_ascii_lowercase() {
        b' ' | b'e' | b't' | b'a' | b'i' | b'o' | b'n' | b's' | b'r' => 1,
        b'l' | b'c' | b'u' | b'd' | b'p' | b'm' | b'h' | b'g' | b'_' => 3,
        b'a'..=b'z' => 10,
        b'0'..=b'9' => 16,
        b'(' | b')' | b'=' | b'.' | b':' | b'-' | b'/' | b'<' | b'>' | b'$' | b'@' | b'[' | b']'
        | b'{' | b'}' | b'|' | b'"' | b'\'' | b'\\' | b'#' => 20,
        _ => 32,
    }
}

fn pick_best_trigram_offset(pat: &[u8], case_insensitive: bool, win_freq: &[u16]) -> usize {
    debug_assert!(pat.len() >= 3);
    let mut best_off = 0usize;
    let mut best_score = i32::MIN;
    for off in 0..(pat.len() - 2) {
        let mut score = i32::from(byte_rarity_score(pat[off], case_insensitive))
            + i32::from(byte_rarity_score(pat[off + 1], case_insensitive))
            + i32::from(byte_rarity_score(pat[off + 2], case_insensitive));
        if pat[off] != pat[off + 1] && pat[off + 1] != pat[off + 2] {
            score += 3;
        }
        let h = trigram_hash(
            pat[off].to_ascii_lowercase(),
            pat[off + 1].to_ascii_lowercase(),
            pat[off + 2].to_ascii_lowercase(),
        );
        score -= i32::from(win_freq[h].saturating_sub(1)) * 12;
        if score > best_score {
            best_score = score;
            best_off = off;
        }
    }
    best_off
}

#[inline(always)]
fn trigram_hash(b0_lo: u8, b1_lo: u8, b2_lo: u8) -> usize {
    let k = (b0_lo as u32) | ((b1_lo as u32) << 8) | ((b2_lo as u32) << 16);
    let mut h = k.wrapping_mul(0xcc9e_2d51).rotate_left(15).wrapping_mul(0x1b87_3593);
    // fmix32 finalizer (MurmurHash3 32-bit)
    h ^= 3; // length = 3 bytes
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    (h as usize) & (TRIGRAM_BUCKETS - 1)
}

#[inline(always)]
fn digram_index(b0: u8, b1: u8) -> usize {
    ((b0.to_ascii_lowercase() as usize) << 8) | (b1.to_ascii_lowercase() as usize)
}

#[inline(always)]
fn add_nibble_byte(lo: &mut [u8; 16], hi: &mut [u8; 16], byte: u8, bucket_bit: u8) {
    lo[(byte & 0x0F) as usize] |= bucket_bit;
    hi[((byte >> 4) & 0x0F) as usize] |= bucket_bit;
}

impl RulePrefilter {
    /// Build a conservative Flat-CSR SIMD prefilter from `literals` over `0..num_rules`.
    ///
    /// Rules in `always_active` are never eliminated (e.g., rules with no fixed literal anchor).
    pub fn new(num_rules: usize, literals: &[LiteralSpec], always_active: &[usize]) -> Self {
        let mut single_bytes = Vec::new();
        let mut digram_lits = Vec::new();
        let mut trigram_lits = Vec::new();
        let mut trigram_hashes = Vec::new();

        let mut lo0 = [0u8; 16];
        let mut hi0 = [0u8; 16];
        let mut lo1 = [0u8; 16];
        let mut hi1 = [0u8; 16];
        let mut lo2 = [0u8; 16];
        let mut hi2 = [0u8; 16];

        let mut trigram_bitset_vec = vec![0u64; 256];
        let mut bucket_counts = vec![0u32; 16385];

        let mut digram_keys = Vec::new();
        let mut win_freq = vec![0u16; TRIGRAM_BUCKETS];
        for spec in literals {
            if spec.rule_index < num_rules && spec.pattern.len() >= 3 {
                for w in spec.pattern.windows(3) {
                    let h = trigram_hash(w[0].to_ascii_lowercase(), w[1].to_ascii_lowercase(), w[2].to_ascii_lowercase());
                    win_freq[h] = win_freq[h].saturating_add(1);
                }
            }
        }

        for spec in literals {
            if spec.rule_index >= num_rules || spec.pattern.is_empty() {
                continue;
            }
            if spec.pattern.len() == 1 {
                single_bytes.push((spec.pattern[0], spec.rule_index, spec.case_insensitive));
                continue;
            }
            if spec.pattern.len() == 2 {
                let d_idx = digram_index(spec.pattern[0], spec.pattern[1]);
                digram_keys.push(d_idx);
                digram_lits.push(CompiledLiteral {
                    rule_index: spec.rule_index,
                    pattern: spec.pattern.clone(),
                    anchor_offset: 0,
                    case_insensitive: spec.case_insensitive,
                });
                continue;
            }

            let off = pick_best_trigram_offset(&spec.pattern, spec.case_insensitive, &win_freq);
            let b0 = spec.pattern[off];
            let b1 = spec.pattern[off + 1];
            let b2 = spec.pattern[off + 2];
            let b0_lo = b0.to_ascii_lowercase();
            let b1_lo = b1.to_ascii_lowercase();
            let b2_lo = b2.to_ascii_lowercase();
            let h = trigram_hash(b0_lo, b1_lo, b2_lo);
            let lit_idx = trigram_lits.len() as u32;
            let bucket_bit = 1u8 << ((lit_idx as usize) & 7);

            if spec.case_insensitive {
                add_nibble_byte(&mut lo0, &mut hi0, b0_lo, bucket_bit);
                add_nibble_byte(&mut lo0, &mut hi0, b0.to_ascii_uppercase(), bucket_bit);
                add_nibble_byte(&mut lo1, &mut hi1, b1_lo, bucket_bit);
                add_nibble_byte(&mut lo1, &mut hi1, b1.to_ascii_uppercase(), bucket_bit);
                add_nibble_byte(&mut lo2, &mut hi2, b2_lo, bucket_bit);
                add_nibble_byte(&mut lo2, &mut hi2, b2.to_ascii_uppercase(), bucket_bit);
            } else {
                add_nibble_byte(&mut lo0, &mut hi0, b0, bucket_bit);
                add_nibble_byte(&mut lo1, &mut hi1, b1, bucket_bit);
                add_nibble_byte(&mut lo2, &mut hi2, b2, bucket_bit);
            }

            trigram_bitset_vec[h >> 6] |= 1u64 << (h & 63);
            bucket_counts[h + 1] += 1;
            trigram_hashes.push(h);
            trigram_lits.push(CompiledLiteral {
                rule_index: spec.rule_index,
                pattern: spec.pattern.clone(),
                anchor_offset: off,
                case_insensitive: spec.case_insensitive,
            });
        }

        // Prefix-sum & scatter flat CSR for 3-byte trigram buckets (zero Vec<Vec<u32>> allocations)
        for i in 1..16385 { bucket_counts[i] += bucket_counts[i - 1]; }
        let mut trigram_cursors = bucket_counts.clone();
        let mut bucket_entries_vec = vec![0u32; trigram_lits.len()];
        for (lit_idx, &h) in trigram_hashes.iter().enumerate() {
            bucket_entries_vec[trigram_cursors[h] as usize] = lit_idx as u32;
            trigram_cursors[h] += 1;
        }

        let digram_mode = if digram_lits.is_empty() {
            DigramMode::None
        } else if digram_lits.len() <= SMALL_DIGRAM_LINEAR_CAP {
            let entries: Vec<SmallDigramEntry> = digram_keys
                .iter()
                .enumerate()
                .map(|(lit_idx, &d_idx)| SmallDigramEntry {
                    key: d_idx as u16,
                    lit_idx: lit_idx as u32,
                })
                .collect();
            let mut first_byte_mask = [0u64; 4];
            for lit in &digram_lits {
                let b0 = lit.pattern[0].to_ascii_lowercase();
                first_byte_mask[(b0 >> 6) as usize] |= 1u64 << (b0 & 63);
            }
            DigramMode::Small { first_byte_mask, entries }
        } else {
            let (mut digram_present_vec, mut digram_counts) = (vec![0u64; 1024], vec![0u32; 65537]);
            for &d_idx in &digram_keys {
                digram_present_vec[d_idx >> 6] |= 1u64 << (d_idx & 63);
                digram_counts[d_idx + 1] += 1;
            }
            for i in 1..65537 { digram_counts[i] += digram_counts[i - 1]; }
            let mut digram_cursors = digram_counts.clone();
            let mut digram_entries_vec = vec![0u32; digram_lits.len()];
            for (lit_idx, &d_idx) in digram_keys.iter().enumerate() {
                digram_entries_vec[digram_cursors[d_idx] as usize] = lit_idx as u32;
                digram_cursors[d_idx] += 1;
            }
            DigramMode::Full {
                present: digram_present_vec.into_boxed_slice().try_into().expect("1024 u64"),
                offsets: digram_counts.into_boxed_slice().try_into().expect("65537 u32"),
                entries: digram_entries_vec.into_boxed_slice(),
            }
        };

        assert!(
            always_active.iter().all(|&idx| idx < num_rules || num_rules == 0),
            "always_active rule index out of range"
        );
        let mut clean_always: Vec<usize> = always_active
            .iter()
            .copied()
            .filter(|&idx| idx < num_rules)
            .collect();
        clean_always.sort_unstable();
        clean_always.dedup();

        Self {
            num_rules,
            always_active: clean_always,
            has_single_bytes: !single_bytes.is_empty(),
            single_bytes,
            digram_lits,
            digram_mode,
            has_trigrams: !trigram_lits.is_empty(),
            trigram_lits,
            lo0,
            hi0,
            lo1,
            hi1,
            lo2,
            hi2,
            trigram_bitset: trigram_bitset_vec.into_boxed_slice().try_into().expect("256 u64"),
            bucket_offsets: bucket_counts.into_boxed_slice().try_into().expect("16385 u32"),
            bucket_entries: bucket_entries_vec.into_boxed_slice(),
        }
    }

    pub fn num_rules(&self) -> usize {
        self.num_rules
    }

    pub fn num_literals(&self) -> usize {
        self.trigram_lits.len() + self.digram_lits.len() + self.single_bytes.len()
    }

    #[inline(always)]
    fn verify_trigram_at(&self, haystack: &[u8], pos: usize, ctx: &mut ScanCtx<'_>) {
        ctx.coarse_lane_hits += 1;
        let h = trigram_hash(
            haystack[pos].to_ascii_lowercase(),
            haystack[pos + 1].to_ascii_lowercase(),
            haystack[pos + 2].to_ascii_lowercase(),
        );
        if (self.trigram_bitset[h >> 6] & (1u64 << (h & 63))) == 0 {
            return;
        }
        ctx.trigram_candidates += 1;
        ctx.candidate_hits += 1;
        let (start, end) = (self.bucket_offsets[h] as usize, self.bucket_offsets[h + 1] as usize);
        for &lit_idx in &self.bucket_entries[start..end] {
            let lit = &self.trigram_lits[lit_idx as usize];
            let r_idx = lit.rule_index;
            if (ctx.bits[r_idx >> 6] & (1u64 << (r_idx & 63))) != 0 || pos < lit.anchor_offset {
                continue;
            }
            let cand_start = pos - lit.anchor_offset;
            let cand_end = cand_start + lit.pattern.len();
            if cand_end > haystack.len() {
                continue;
            }
            ctx.full_verifications += 1;
            let win = &haystack[cand_start..cand_end];
            if if lit.case_insensitive { win.eq_ignore_ascii_case(&lit.pattern) } else { win == lit.pattern.as_slice() } {
                ctx.bits[r_idx >> 6] |= 1u64 << (r_idx & 63);
            }
        }
    }

    /// Single-pass `O(N)` 2-byte digram lookup (Small <= 16: linear scan, Full: 8 KB bitset + Flat-CSR).
    fn scan_digram_literals(&self, haystack: &[u8], ctx: &mut ScanCtx<'_>) {
        if self.digram_lits.is_empty() || haystack.len() < 2 {
            return;
        }
        match &self.digram_mode {
            DigramMode::None => {}
            DigramMode::Small { first_byte_mask, entries } => {
                for w in haystack.windows(2) {
                    let b0 = w[0].to_ascii_lowercase();
                    if (first_byte_mask[(b0 >> 6) as usize] & (1u64 << (b0 & 63))) == 0 {
                        continue;
                    }
                    let idx = digram_index(w[0], w[1]);
                    for &SmallDigramEntry { key: d_key, lit_idx } in entries {
                        if d_key as usize == idx {
                            ctx.candidate_hits += 1;
                            let lit = &self.digram_lits[lit_idx as usize];
                            let r_idx = lit.rule_index;
                            if (ctx.bits[r_idx >> 6] & (1u64 << (r_idx & 63))) != 0 {
                                continue;
                            }
                            ctx.full_verifications += 1;
                            if if lit.case_insensitive { w.eq_ignore_ascii_case(&lit.pattern) } else { w[0] == lit.pattern[0] && w[1] == lit.pattern[1] } {
                                ctx.bits[r_idx >> 6] |= 1u64 << (r_idx & 63);
                            }
                        }
                    }
                }
            }
            DigramMode::Full { present, offsets, entries } => {
                for w in haystack.windows(2) {
                    let idx = digram_index(w[0], w[1]);
                    if (present[idx >> 6] & (1u64 << (idx & 63))) == 0 {
                        continue;
                    }
                    ctx.candidate_hits += 1;
                    let (start, end) = (offsets[idx] as usize, offsets[idx + 1] as usize);
                    for &lit_idx in &entries[start..end] {
                        let lit = &self.digram_lits[lit_idx as usize];
                        let r_idx = lit.rule_index;
                        if (ctx.bits[r_idx >> 6] & (1u64 << (r_idx & 63))) != 0 {
                            continue;
                        }
                        ctx.full_verifications += 1;
                        if if lit.case_insensitive { w.eq_ignore_ascii_case(&lit.pattern) } else { w[0] == lit.pattern[0] && w[1] == lit.pattern[1] } {
                            ctx.bits[r_idx >> 6] |= 1u64 << (r_idx & 63);
                        }
                    }
                }
            }
        }
    }

    fn scan_single_bytes(&self, haystack: &[u8], bits: &mut [u64]) {
        if !self.has_single_bytes || haystack.is_empty() {
            return;
        }
        if self.single_bytes.len() == 1 {
            let (needle, rule_idx, ci) = self.single_bytes[0];
            let hit = if ci {
                haystack.contains(&needle.to_ascii_lowercase())
                    || haystack.contains(&needle.to_ascii_uppercase())
            } else {
                haystack.contains(&needle)
            };
            if hit {
                bits[rule_idx >> 6] |= 1u64 << (rule_idx & 63);
            }
            return;
        }
        let mut seen = [0u64; 4];
        for &b in haystack {
            seen[(b >> 6) as usize] |= 1u64 << (b & 63);
        }
        for &(needle, rule_idx, ci) in &self.single_bytes {
            let hit = if ci {
                let lo = needle.to_ascii_lowercase();
                let hi = needle.to_ascii_uppercase();
                (seen[(lo >> 6) as usize] & (1u64 << (lo & 63))) != 0
                    || (seen[(hi >> 6) as usize] & (1u64 << (hi & 63))) != 0
            } else {
                (seen[(needle >> 6) as usize] & (1u64 << (needle & 63))) != 0
            };
            if hit {
                bits[rule_idx >> 6] |= 1u64 << (rule_idx & 63);
            }
        }
    }

    fn scan_trigrams_scalar(&self, haystack: &[u8], ctx: &mut ScanCtx<'_>) {
        if haystack.len() < 3 {
            return;
        }
        for pos in 0..(haystack.len() - 2) {
            self.verify_trigram_at(haystack, pos, ctx);
        }
    }


    fn scan_into_bitset(&self, haystack: &[u8], disable_simd: bool, bits: &mut [u64]) -> PrefilterStats {
        for &r_idx in &self.always_active {
            bits[r_idx >> 6] |= 1u64 << (r_idx & 63);
        }
        self.scan_single_bytes(haystack, bits);
        let mut ctx = ScanCtx { bits, coarse_lane_hits: 0, trigram_candidates: 0, candidate_hits: 0, full_verifications: 0 };
        self.scan_digram_literals(haystack, &mut ctx);

        if self.has_trigrams && haystack.len() >= 3 {
            match if disable_simd { PrefilterBackend::RustScalar } else { cached_prefilter_backend() } {
                #[cfg(target_arch = "aarch64")]
                PrefilterBackend::Aarch64NeonTeddy => {
                    // SAFETY: `cached_prefilter_backend()` verified NEON; slice bounds checked inside.
                    unsafe { self.scan_trigrams_neon(haystack, &mut ctx) };
                }
                #[cfg(target_arch = "x86_64")]
                PrefilterBackend::X86Avx2Teddy => {
                    // SAFETY: `cached_prefilter_backend()` verified AVX2; slice bounds checked inside.
                    unsafe { self.scan_trigrams_avx2(haystack, &mut ctx) };
                }
                _ => self.scan_trigrams_scalar(haystack, &mut ctx),
            }
        }

        PrefilterStats {
            bytes_scanned: haystack.len(),
            coarse_lane_hits: ctx.coarse_lane_hits,
            candidate_hits: ctx.candidate_hits,
            trigram_candidates: ctx.trigram_candidates,
            full_verifications: ctx.full_verifications,
        }
    }

    #[inline]
    fn collect_set_bits(bits: &[u64], num_rules: usize, out: &mut Vec<usize>) {
        for (wi, &w) in bits.iter().enumerate() {
            let mut cur = w;
            while cur != 0 {
                let idx = wi * 64 + (cur.trailing_zeros() as usize);
                if idx < num_rules { out.push(idx); }
                cur &= cur - 1;
            }
        }
    }

    #[inline]
    fn with_bitset<R>(&self, f: impl FnOnce(&mut [u64]) -> R) -> R {
        if self.num_rules <= 256 {
            let words_len = self.num_rules.div_ceil(64).max(1);
            let mut stack_words = [0u64; 4];
            f(&mut stack_words[..words_len])
        } else {
            let mut words = vec![0u64; self.num_rules.div_ceil(64)];
            f(&mut words)
        }
    }

    /// Candidate bitmask for the first 64-rule word (`0..64`).
    /// Zero heap allocation (`[u64; 4]` stack bitset) for `<= 256` rules; heap `Vec<u64>` bitset for `> 256` rules.
    pub fn candidate_mask_first_word_u64(&self, haystack: &[u8], disable_simd: bool) -> u64 {
        self.with_bitset(|bits| {
            let _ = self.scan_into_bitset(haystack, disable_simd, bits);
            bits[0]
        })
    }

    /// Legacy alias for [`RulePrefilter::candidate_mask_first_word_u64`].
    #[deprecated(since = "2.4.1", note = "Use candidate_mask_first_word_u64 or candidate_rule_indices")]
    pub fn candidate_mask_u64(&self, haystack: &[u8], disable_simd: bool) -> u64 {
        self.candidate_mask_first_word_u64(haystack, disable_simd)
    }

    /// Populate `out` (clearing prior contents) with sorted candidate rule indices using reusable `scratch_bits`.
    pub fn candidate_rule_indices_into(
        &self, haystack: &[u8], disable_simd: bool, scratch_bits: &mut Vec<u64>, out: &mut Vec<usize>,
    ) {
        scratch_bits.clear();
        scratch_bits.resize(self.num_rules.div_ceil(64), 0u64);
        out.clear();
        let _ = self.scan_into_bitset(haystack, disable_simd, scratch_bits);
        Self::collect_set_bits(scratch_bits, self.num_rules, out);
    }

    /// Return sorted candidate rule indices (`[u64; 4]` zero-alloc stack bitset for `<= 256` rules; heap bitset for `> 256`).
    pub fn candidate_rule_indices(&self, haystack: &[u8], disable_simd: bool) -> Vec<usize> {
        let mut out = Vec::new();
        self.with_bitset(|bits| {
            let _ = self.scan_into_bitset(haystack, disable_simd, bits);
            Self::collect_set_bits(bits, self.num_rules, &mut out);
        });
        out
    }

    /// Run candidate scan and return sorted candidate indices + `PrefilterStats` (stack bitset for `<= 256` rules; heap for `> 256`).
    pub fn scan_stats(&self, haystack: &[u8], disable_simd: bool) -> (Vec<usize>, PrefilterStats) {
        let mut out = Vec::new();
        let stats = self.with_bitset(|bits| {
            let st = self.scan_into_bitset(haystack, disable_simd, bits);
            Self::collect_set_bits(bits, self.num_rules, &mut out);
            st
        });
        (out, stats)
    }

    /// Independent raw-specification reference oracle evaluating `haystack` directly against `&[LiteralSpec]`
    /// and `always_active` without touching any compiled `RulePrefilter` tables.
    pub fn raw_spec_oracle_rule_indices(
        num_rules: usize, literals: &[LiteralSpec], always_active: &[usize], haystack: &[u8],
    ) -> Vec<usize> {
        let mut bits = vec![0u64; num_rules.div_ceil(64)];
        for &r_idx in always_active {
            if r_idx < num_rules { bits[r_idx >> 6] |= 1u64 << (r_idx & 63); }
        }
        for spec in literals {
            let r_idx = spec.rule_index;
            if r_idx >= num_rules || spec.pattern.is_empty() || (bits[r_idx >> 6] & (1u64 << (r_idx & 63))) != 0 {
                continue;
            }
            if haystack.len() < spec.pattern.len() { continue; }
            let hit = haystack.windows(spec.pattern.len()).any(|w| {
                if spec.case_insensitive { w.eq_ignore_ascii_case(&spec.pattern) } else { w == spec.pattern.as_slice() }
            });
            if hit { bits[r_idx >> 6] |= 1u64 << (r_idx & 63); }
        }
        let mut out = Vec::new();
        Self::collect_set_bits(&bits, num_rules, &mut out);
        out
    }

    /// Build a non-overlapping, alignment-varied probe buffer from `literals` safe for arbitrary pattern lengths.
    pub fn build_aligned_probe_buffer(literals: &[LiteralSpec]) -> Vec<u8> {
        let total_hint: usize = literals.iter().map(|s| s.pattern.len() + 48).sum::<usize>() + 64;
        let mut buf = Vec::with_capacity(total_hint);
        buf.resize(16, b'.');
        for (idx, spec) in literals.iter().enumerate() {
            if spec.pattern.is_empty() { continue; }
            buf.resize(buf.len() + (idx % 33), b'.');
            buf.extend_from_slice(&spec.pattern);
            buf.resize(buf.len() + 16, b'.');
        }
        buf
    }

    /// Naive reference scalar oracle returning sorted matching rule indices for differential tests.
    pub fn scalar_oracle_rule_indices(&self, haystack: &[u8]) -> Vec<usize> {
        let mut bits = vec![0u64; self.num_rules.div_ceil(64)];
        for &r_idx in &self.always_active { bits[r_idx >> 6] |= 1u64 << (r_idx & 63); }
        for &(needle, r_idx, ci) in &self.single_bytes {
            let hit = if ci { haystack.iter().any(|b| b.eq_ignore_ascii_case(&needle)) } else { haystack.contains(&needle) };
            if hit { bits[r_idx >> 6] |= 1u64 << (r_idx & 63); }
        }
        for lit in self.digram_lits.iter().chain(self.trigram_lits.iter()) {
            let r_idx = lit.rule_index;
            if (bits[r_idx >> 6] & (1u64 << (r_idx & 63))) != 0 || haystack.len() < lit.pattern.len() { continue; }
            if haystack.windows(lit.pattern.len()).any(|w| if lit.case_insensitive { w.eq_ignore_ascii_case(&lit.pattern) } else { w == lit.pattern.as_slice() }) {
                bits[r_idx >> 6] |= 1u64 << (r_idx & 63);
            }
        }
        let mut out = Vec::new();
        Self::collect_set_bits(&bits, self.num_rules, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_kml_or_synthetic_specs() -> (usize, Vec<LiteralSpec>, Vec<usize>) {
        let kml_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".kintsugi/scars.kml");
        if let Ok(raw) = std::fs::read_to_string(kml_path) {
            let records = crate::kml::parse_kml_corpus(&raw);
            assert!(records.len() >= 1797);
            let (mut kml_specs, mut always) = (Vec::new(), Vec::new());
            for (idx, r) in records.iter().enumerate() {
                if r.neg.is_empty() { always.push(idx); }
                else { kml_specs.push(LiteralSpec { rule_index: idx, pattern: r.neg.as_bytes().to_vec(), case_insensitive: false }); }
            }
            (records.len(), kml_specs, always)
        } else {
            let specs: Vec<LiteralSpec> = (0..1797)
                .map(|i| LiteralSpec { rule_index: i, pattern: format!("KML_FALLBACK_{i:04}(").into_bytes(), case_insensitive: false })
                .collect();
            (1797, specs, Vec::new())
        }
    }

    #[test]
    fn flat_csr_digram_and_trigram_zero_alloc_into_and_stats() {
        let specs = vec![
            LiteralSpec { rule_index: 0, pattern: vec![b'@'], case_insensitive: false },
            LiteralSpec { rule_index: 1, pattern: b"==".to_vec(), case_insensitive: false },
            LiteralSpec { rule_index: 2, pattern: b"SELECT".to_vec(), case_insensitive: true },
            LiteralSpec { rule_index: 3, pattern: b"Ab".to_vec(), case_insensitive: false },
            LiteralSpec { rule_index: 4, pattern: b"ab".to_vec(), case_insensitive: true },
            LiteralSpec { rule_index: 5, pattern: b"yaml.load(".to_vec(), case_insensitive: false },
        ];
        let pf = RulePrefilter::new(7, &specs, &[6]);
        let (mut scratch, mut out) = (Vec::new(), vec![99usize]);

        let hay1 = b"padding ab == select * from t";
        pf.candidate_rule_indices_into(hay1, false, &mut scratch, &mut out);
        assert_eq!(out, RulePrefilter::raw_spec_oracle_rule_indices(7, &specs, &[6], hay1));
        assert_eq!(out, vec![1, 2, 4, 6]);

        let hay2 = b"Ab and yaml.load(x) @end";
        let (stats_hits, stats) = pf.scan_stats(hay2, false);
        pf.candidate_rule_indices_into(hay2, true, &mut scratch, &mut out);
        assert_eq!(stats_hits, out);
        assert_eq!(out, RulePrefilter::raw_spec_oracle_rule_indices(7, &specs, &[6], hay2));
        assert_eq!(out, vec![0, 3, 4, 5, 6]);
        assert_eq!(stats.bytes_scanned, hay2.len());
        assert!(stats.coarse_lane_hits >= 1 && stats.candidate_hits >= 2 && stats.full_verifications >= 2);
    }

    #[test]
    fn collision_stats_and_benign_selectivity_36_256_and_1797_rules() {
        let benign = "fn compute_checksum(values: &[u32]) -> u64 {\n    let mut acc = 0u64;\n    for &v in values { acc = acc.wrapping_add(v as u64); }\n    acc\n}\n".repeat(16);
        let benign_b = benign.as_bytes();

        let pf36 = crate::kernels::builtin_rule_prefilter();
        let (hits36, st36) = pf36.scan_stats(benign_b, false);
        assert_eq!(hits36, pf36.scalar_oracle_rule_indices(benign_b));
        assert!(st36.full_verifications * 10 <= st36.bytes_scanned);

        let specs256: Vec<LiteralSpec> = (0..256)
            .map(|i| LiteralSpec { rule_index: i, pattern: format!("KS_SIG_{i:03}(").into_bytes(), case_insensitive: false })
            .collect();
        let pf256 = RulePrefilter::new(256, &specs256, &[]);
        let (hits256, st256) = pf256.scan_stats(benign_b, false);
        assert!(hits256.is_empty() && st256.full_verifications * 20 <= st256.bytes_scanned);
        assert_eq!(pf256.candidate_mask_first_word_u64(b"call KS_SIG_007() and KS_SIG_255()", false), 1u64 << 7);
        assert_eq!(pf256.candidate_rule_indices(b"call KS_SIG_007() and KS_SIG_255()", false), vec![7, 255]);

        let (n_kml, kml_specs, always) = load_kml_or_synthetic_specs();
        let pf_kml = RulePrefilter::new(n_kml, &kml_specs, &always);
        let (hits_kml, st_kml) = pf_kml.scan_stats(benign_b, false);
        assert_eq!(hits_kml, RulePrefilter::raw_spec_oracle_rule_indices(n_kml, &kml_specs, &always, benign_b));
        assert!(st_kml.full_verifications * 15 <= st_kml.bytes_scanned, "st_kml={st_kml:?}");

        let coll_ok = |s: BucketCollisionStats, n: usize, max_pct: f64, max_depth: usize| {
            assert!(
                s.total_buckets == TRIGRAM_BUCKETS && s.total_entries == n && s.occupied_buckets <= n.min(TRIGRAM_BUCKETS)
                    && s.colliding_buckets <= s.occupied_buckets && s.max_bucket_depth <= max_depth
                    && (n == 0 || s.max_bucket_depth >= 1) && (0.0..=max_pct).contains(&s.collision_bucket_pct),
                "{s:?}"
            );
        };
        coll_ok(pf36.collision_stats(), pf36.trigram_lits.len(), 5.0, 2);
        coll_ok(pf256.collision_stats(), pf256.trigram_lits.len(), 0.0, 1);
        coll_ok(pf_kml.collision_stats(), pf_kml.trigram_lits.len(), 40.0, 8);
    }

    #[test]
    fn differential_boundary_sweep_0_to_80_and_long_kml_raw_oracle() {
        let pf36 = crate::kernels::builtin_rule_prefilter();
        let specs256: Vec<LiteralSpec> = (0..256)
            .map(|i| LiteralSpec { rule_index: i, pattern: format!("KS_SIG_{i:03}(").into_bytes(), case_insensitive: false })
            .collect();
        let pf256 = RulePrefilter::new(256, &specs256, &[]);

        fn sweep(pf: &RulePrefilter, needles: &[&[u8]], tag: &str) {
            for len in 0..=80usize {
                for needle in needles.iter().filter(|n| n.len() <= len) {
                    for at in 0..=(len - needle.len()) {
                        let mut h = vec![b'x'; len];
                        h[at..at + needle.len()].copy_from_slice(needle);
                        let (simd, scalar, oracle) = (pf.candidate_rule_indices(&h, false), pf.candidate_rule_indices(&h, true), pf.scalar_oracle_rule_indices(&h));
                        assert_eq!(simd, scalar, "{tag} scalar mismatch len={len} at={at}");
                        for rule in &oracle { assert!(simd.contains(rule), "{tag} missed rule {rule} len={len} at={at}"); }
                    }
                }
            }
        }
        sweep(&pf36, &[b"yaml.load(" as &[u8], b"SELECT", b"select", b"==", b"Ab", b"@"], "pf36");
        sweep(&pf256, &[b"KS_SIG_007(" as &[u8], b"KS_SIG_255("], "pf256");

        let (mut n_kml, mut kml_specs, always) = load_kml_or_synthetic_specs();
        // Also append a >64-byte literal to verify dynamic non-overlapping probe handles arbitrary lengths!
        kml_specs.push(LiteralSpec { rule_index: n_kml, pattern: b"LONG_LITERAL_EXCEEDING_64_BYTES_BOUNDARY_CHECK_0123456789_ABCDEFGHIJKLMN()".to_vec(), case_insensitive: false });
        n_kml += 1;
        let pf_kml = RulePrefilter::new(n_kml, &kml_specs, &always);
        let kml_probe = RulePrefilter::build_aligned_probe_buffer(&kml_specs);
        let kml_simd = pf_kml.candidate_rule_indices(&kml_probe, false);
        let kml_scalar = pf_kml.candidate_rule_indices(&kml_probe, true);
        let kml_raw_oracle = RulePrefilter::raw_spec_oracle_rule_indices(n_kml, &kml_specs, &always, &kml_probe);
        assert_eq!(kml_simd, kml_scalar);
        assert_eq!(kml_simd, kml_raw_oracle);
    }

    #[test]
    fn simd_lane_mask_packing_and_digram_small_vs_full_modes() {
        for m in (0..32).map(|i| 1u32 << i).chain([0, u32::MAX, 0x8000_0001, 0xAAAA_5555, 0x1234_5678, 0xFFFF_0000]) {
            let (c0, c1): ([u8; 16], [u8; 16]) = (std::array::from_fn(|i| ((m >> i) & 1) as u8 * (0x41 + i as u8)), std::array::from_fn(|i| ((m >> (16 + i)) & 1) as u8 * (0x81 + i as u8)));
            // SAFETY: NEON is baseline on aarch64; each vld1q_u8 reads exactly 16 bytes from a live stack array.
            #[cfg(target_arch = "aarch64")] unsafe { use std::arch::aarch64::*; assert_eq!(pack_32_lane_mask_neon(vld1q_u8(c0.as_ptr()), vld1q_u8(c1.as_ptr()), vld1q_u8(NEON_BIT_WEIGHTS.as_ptr())), m, "neon m={m:#010x}"); }
            #[cfg(target_arch = "x86_64")] if std::arch::is_x86_feature_detected!("avx2") {
                let mut c32 = [0u8; 32]; c32[..16].copy_from_slice(&c0); c32[16..].copy_from_slice(&c1);
                // SAFETY: AVX2 runtime support was verified above; `c32` is a live 32-byte stack buffer.
                unsafe { use std::arch::x86_64::*; assert_eq!(RulePrefilter::pack_32_lane_mask_avx2(_mm256_loadu_si256(c32.as_ptr() as *const __m256i)), m, "avx2 m={m:#010x}"); }
            }
            assert_eq!(pack_32_lane_mask_bits_ref(&c0, &c1), m, "ref m={m:#010x}");
        }
        for (n, small) in [(SMALL_DIGRAM_LINEAR_CAP, true), (SMALL_DIGRAM_LINEAR_CAP + 1, false)] {
            let specs: Vec<LiteralSpec> = (0..n).map(|i| LiteralSpec { rule_index: i, pattern: vec![b'A' + i as u8, b'z'], case_insensitive: false }).collect();
            let (pf, hay) = (RulePrefilter::new(n, &specs, &[]), specs.iter().flat_map(|s| [s.pattern[0], b'z', b' ']).collect::<Vec<u8>>());
            assert!(matches!((&pf.digram_mode, small), (DigramMode::Small { entries, .. }, true) if entries.len() == n) || matches!((&pf.digram_mode, small), (DigramMode::Full { .. }, false)));
            let oracle = RulePrefilter::raw_spec_oracle_rule_indices(n, &specs, &[], &hay);
            assert_eq!(pf.candidate_rule_indices(&hay, false), oracle);
            assert_eq!(pf.candidate_rule_indices(&hay, true), oracle);
        }
    }

    #[test]
    fn trigram_hash_murmur3_fmix32_strict_avalanche_24x14_matrix() {
        const SAC_SAMPLES: u32 = 512;
        let mut sac = [[0u32; TRIGRAM_HASH_BITS as usize]; 24];
        for sample in 0..SAC_SAMPLES {
            let s_in = sample.wrapping_mul(0x9E37_79) & 0x00FF_FFFF;
            let base_out = trigram_hash(s_in as u8, (s_in >> 8) as u8, (s_in >> 16) as u8);
            for (in_bit, row) in sac.iter_mut().enumerate() {
                let f_in = s_in ^ (1u32 << in_bit);
                let diff = base_out ^ trigram_hash(f_in as u8, (f_in >> 8) as u8, (f_in >> 16) as u8);
                for (out_bit, cell) in row.iter_mut().enumerate() { *cell += ((diff >> out_bit) & 1) as u32; }
            }
        }
        let mut total_flips = 0u32;
        for (ib, row) in sac.iter().enumerate() {
            for (ob, &flips) in row.iter().enumerate() {
                total_flips += flips;
                let p = (flips as f64) / (SAC_SAMPLES as f64);
                assert!((0.40..=0.60).contains(&p), "SAC cell ({ib},{ob}) flip probability {p:.4} outside [0.40, 0.60]");
            }
        }
        let mean_sac = (total_flips as f64) / ((24 * (TRIGRAM_HASH_BITS as usize) * (SAC_SAMPLES as usize)) as f64);
        assert!((0.48..=0.52).contains(&mean_sac), "SAC mean {mean_sac:.4} outside [0.48, 0.52]");
    }
}
