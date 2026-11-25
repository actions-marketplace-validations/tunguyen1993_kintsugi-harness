//! Reproducible In-Process LogForge Benchmark Harness (`kintsugi_core::kernels::bench`).
//!
//! - Reports unambiguous decimal `throughput_gb_per_s` (`bytes / secs / 1e9`, decimal GB/s) and
//!   `throughput_bytes_per_sec` (`bytes / secs`), retaining `throughput_gbps` solely as an
//!   explicitly listed deprecated JSON alias (`"deprecated_fields":["throughput_gbps"]`).
//! - Measures pure zero-allocation `*_into` reused-buffer paths for BOTH `scalar_reused_buf` and
//!   `simd_reused_buf` (plus multi-byte reused buffers) so kernel speedup ratios never mix `Vec`
//!   heap allocation overhead into scalar-vs-SIMD comparisons.
//! - Dynamically verifies `false_negative_count == 0` under the prefilter contract
//!   `"false_positives_permitted_zero_false_negatives_guaranteed"`.

use std::hint::black_box;
use std::time::Instant;

use crate::io_json::fnv1a_64_hex;
use crate::kernels::byte_scanner::{
    active_simd_backend, scan_delimiters, scan_delimiters_into, scan_multibyte_delimiters,
    scan_multibyte_delimiters_into,
};
use crate::kernels::rule_prefilter::{builtin_rule_prefilter, LiteralSpec, RulePrefilter};
use crate::kernels::scalar;

/// Canonical prefilter soundness contract string emitted in benchmark reports.
pub const PREFILTER_CONTRACT: &str = "false_positives_permitted_zero_false_negatives_guaranteed";

/// Benchmark metrics summary for a single kernel execution tier (`schema_version = "1.1"`).
#[derive(Debug, Clone)]
pub struct KernelTierStats {
    pub tier: &'static str,
    pub backend: &'static str,
    pub min_us: f64,
    pub median_us: f64,
    pub p95_us: f64,
    pub mean_us: f64,
    /// Unambiguous decimal gigabytes per second (`bytes / secs / 1e9`).
    pub throughput_gb_per_s: f64,
    /// Unambiguous raw bytes per second (`bytes / secs`).
    pub throughput_bytes_per_sec: f64,
    /// Deprecated alias equal to `throughput_gb_per_s` (retained for v1.0 JSON consumers).
    #[deprecated(since = "2.4.1", note = "Ambiguous GB/s vs Gbit/s name; use throughput_gb_per_s or throughput_bytes_per_sec")]
    pub throughput_gbps: f64,
    pub matches: usize,
}

/// Backward-compatible type alias for [`KernelTierStats`].
pub type KernelBenchStats = KernelTierStats;

/// Complete reproducible benchmark result produced by `run_logforge_benchmark`.
#[derive(Debug, Clone)]
pub struct LogForgeBenchReport {
    pub arch: &'static str,
    pub os: &'static str,
    pub size_bytes: usize,
    pub warmup: usize,
    pub iters: usize,
    pub seed: u64,
    pub delim: u8,
    pub input_fnv1a64: String,
    pub parity_ok: bool,
    pub false_negative_count: usize,
    pub prefilter_contract: &'static str,
    pub scalar: KernelTierStats,
    pub scalar_reused_buf: KernelTierStats,
    pub simd: KernelTierStats,
    pub simd_reused_buf: KernelTierStats,
    pub simd_fallback: KernelTierStats,
    pub multibyte_scalar: KernelTierStats,
    pub multibyte_scalar_reused_buf: KernelTierStats,
    pub multibyte_simd: KernelTierStats,
    pub multibyte_simd_reused_buf: KernelTierStats,
    /// Pure zero-allocation kernel speedup (`scalar_reused_buf.median_us / simd_reused_buf.median_us`).
    /// Legacy alias for `speedup_reused_simd_vs_scalar`; retained for schema compatibility.
    #[deprecated(since = "2.4.1", note = "Use speedup_reused_simd_vs_scalar or speedup_allocating_simd_vs_scalar")]
    pub speedup_simd_vs_scalar: f64,
    pub speedup_reused_simd_vs_scalar: f64,
    pub speedup_allocating_simd_vs_scalar: f64,
    /// Number of non-vacuous oracle hits checked against scalar and SIMD prefilters.
    pub verified_oracle_hits: usize,
    /// Origin of the 1,797-rule KML benchmark probe (`"scars_kml_corpus"` or `"synthetic_fallback"`).
    pub kml_probe_source: &'static str,
}

fn generate_synthetic_log_buffer(size_bytes: usize, seed: u64, delim: u8) -> Vec<u8> {
    let templates: [&[u8]; 4] = [
        b"{\"timestamp\":\"2026-11-21T18:26:00.123456+07:00\",\"level\":\"info\",\"message\":\"gateway request accepted\",\"latency_us\":42}",
        b"2026-11-21 18:26:01.005Z WARN stream chunk alignment verified||ok",
        b"ts=1795266362.500 level=error msg=\"retry backoff\" host=node-01",
        b"{\"ts\":1795266363123456,\"severity\":\"debug\",\"event\":\"heartbeat\",\"ok\":true}",
    ];
    let mut state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
    let mut out = Vec::with_capacity(size_bytes);
    while out.len() < size_bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let line = templates[((state >> 62) as usize) & 3];
        let remaining = size_bytes - out.len();
        if remaining > line.len() {
            out.extend_from_slice(line);
            out.push(delim);
        } else {
            out.extend_from_slice(&line[..remaining]);
        }
    }
    out
}

#[allow(deprecated)]
fn compute_stats(
    tier: &'static str,
    backend: &'static str,
    mut samples_us: Vec<f64>,
    size_bytes: usize,
    matches: usize,
) -> KernelTierStats {
    if samples_us.is_empty() {
        return KernelTierStats {
            tier,
            backend,
            min_us: 0.0,
            median_us: 0.0,
            p95_us: 0.0,
            mean_us: 0.0,
            throughput_gb_per_s: 0.0,
            throughput_bytes_per_sec: 0.0,
            throughput_gbps: 0.0,
            matches,
        };
    }
    samples_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples_us.len();
    let min_us = samples_us[0];
    let median_us = if n % 2 == 1 {
        samples_us[n / 2]
    } else {
        0.5 * (samples_us[n / 2 - 1] + samples_us[n / 2])
    };
    let p95_idx = ((n as f64) * 0.95).ceil() as usize;
    let p95_us = samples_us[p95_idx.saturating_sub(1).min(n - 1)];
    let mean_us = samples_us.iter().sum::<f64>() / (n as f64);
    let secs = median_us * 1e-6;
    let throughput_bytes_per_sec = if secs > 0.0 { (size_bytes as f64) / secs } else { 0.0 };
    let throughput_gb_per_s = throughput_bytes_per_sec * 1e-9;
    KernelTierStats {
        tier,
        backend,
        min_us,
        median_us,
        p95_us,
        mean_us,
        throughput_gb_per_s,
        throughput_bytes_per_sec,
        throughput_gbps: throughput_gb_per_s,
        matches,
    }
}

fn bench_alloc_loop<F>(warmup: usize, iters: usize, batch_k: usize, mut f: F) -> (Vec<f64>, Vec<usize>)
where
    F: FnMut() -> Vec<usize>,
{
    let batch_k = batch_k.max(1);
    for _ in 0..warmup {
        let res = f();
        black_box(res.len());
    }
    let mut times = Vec::with_capacity(iters);
    let mut last_res = Vec::new();
    for _ in 0..iters {
        let t0 = Instant::now();
        for _ in 0..batch_k {
            let res = f();
            black_box(res.as_ptr());
            black_box(res.len());
            last_res = res;
        }
        let dt = ((t0.elapsed().as_nanos() as f64) / 1000.0) / (batch_k as f64);
        times.push(dt);
    }
    (times, last_res)
}

fn bench_reused_into_loop<F>(
    warmup: usize,
    iters: usize,
    batch_k: usize,
    cap_hint: usize,
    mut f: F,
) -> (Vec<f64>, Vec<usize>)
where
    F: FnMut(&mut Vec<usize>),
{
    let batch_k = batch_k.max(1);
    let mut reused = Vec::with_capacity(cap_hint.saturating_add(16));
    for _ in 0..warmup {
        reused.clear();
        f(&mut reused);
        black_box(reused.len());
    }
    let mut times = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        for _ in 0..batch_k {
            reused.clear();
            f(&mut reused);
            black_box(reused.as_ptr());
            black_box(reused.len());
        }
        let dt = ((t0.elapsed().as_nanos() as f64) / 1000.0) / (batch_k as f64);
        times.push(dt);
    }
    (times, reused)
}

fn count_missing_sorted(oracle: &[usize], candidate: &[usize]) -> usize {
    let (mut i, mut j, mut missing) = (0usize, 0usize, 0usize);
    while i < oracle.len() {
        while j < candidate.len() && candidate[j] < oracle[i] {
            j += 1;
        }
        if j < candidate.len() && candidate[j] == oracle[i] {
            j += 1;
        } else {
            missing += 1;
        }
        i += 1;
    }
    missing
}

/// Run an honest, reproducible warmup + measured benchmark across Scalar, Reused-Buffer, SIMD, and Fallback tiers.
pub fn run_logforge_benchmark(
    size_bytes: usize,
    warmup: usize,
    iters: usize,
    seed: u64,
    delim: u8,
) -> LogForgeBenchReport {
    let data = generate_synthetic_log_buffer(size_bytes, seed, delim);
    let input_fnv1a64 = fnv1a_64_hex(&data);
    let iters = iters.max(1);
    // Adaptive inner batching amortizes clock resolution noise on sub-32KiB buffers.
    let batch_k = (32_768usize / size_bytes.max(1)).clamp(1, 32);

    let (scalar_times, scalar_out) =
        bench_alloc_loop(warmup, iters, batch_k, || scalar::scan_delimiters_scalar(black_box(&data), delim));
    let (scalar_reused_times, scalar_reused_out) =
        bench_reused_into_loop(warmup, iters, batch_k, scalar_out.len(), |out| {
            scalar::scan_delimiters_scalar_into(black_box(&data), delim, out);
        });
    let (simd_times, simd_out) =
        bench_alloc_loop(warmup, iters, batch_k, || scan_delimiters(black_box(&data), delim, false));
    let (simd_reused_times, simd_reused_out) =
        bench_reused_into_loop(warmup, iters, batch_k, scalar_out.len(), |out| {
            scan_delimiters_into(black_box(&data), delim, false, out);
        });
    let (fb_times, fb_out) =
        bench_alloc_loop(warmup, iters, batch_k, || scan_delimiters(black_box(&data), delim, true));

    let mb_pat = b"||";
    let (mb_scalar_times, mb_scalar_out) = bench_alloc_loop(warmup, iters, batch_k, || {
        scalar::scan_multibyte_delimiters_scalar(black_box(&data), mb_pat)
    });
    let (mb_scalar_reused_times, mb_scalar_reused_out) =
        bench_reused_into_loop(warmup, iters, batch_k, mb_scalar_out.len(), |out| {
            scalar::scan_multibyte_delimiters_scalar_into(black_box(&data), mb_pat, out);
        });
    let (mb_simd_times, mb_simd_out) = bench_alloc_loop(warmup, iters, batch_k, || {
        scan_multibyte_delimiters(black_box(&data), mb_pat, false)
    });
    let (mb_simd_reused_times, mb_simd_reused_out) =
        bench_reused_into_loop(warmup, iters, batch_k, mb_scalar_out.len(), |out| {
            scan_multibyte_delimiters_into(black_box(&data), mb_pat, false, out);
        });

    let pf = builtin_rule_prefilter();
    let verify_prefilter_raw = |prefilter: &RulePrefilter, num_rules: usize, raw_specs: &[LiteralSpec], always: &[usize], probes: &[Vec<u8>]| {
        let mut missed = 0usize;
        let mut verified_hits = 0usize;
        for probe in probes {
            let oracle = RulePrefilter::raw_spec_oracle_rule_indices(num_rules, raw_specs, always, probe);
            let scalar = prefilter.candidate_rule_indices(probe, true);
            let simd = prefilter.candidate_rule_indices(probe, false);
            verified_hits += oracle.len();
            missed += count_missing_sorted(&oracle, &scalar);
            missed += count_missing_sorted(&oracle, &simd);
        }
        (missed, verified_hits)
    };
    let verify_prefilter = |prefilter: &RulePrefilter, probes: &[Vec<u8>]| {
        let mut missed = 0usize;
        let mut verified_hits = 0usize;
        for probe in probes {
            let oracle = prefilter.scalar_oracle_rule_indices(probe);
            let scalar = prefilter.candidate_rule_indices(probe, true);
            let simd = prefilter.candidate_rule_indices(probe, false);
            verified_hits += oracle.len();
            missed += count_missing_sorted(&oracle, &scalar);
            missed += count_missing_sorted(&oracle, &simd);
        }
        (missed, verified_hits)
    };
    let (pf_missed_bits, data_hits) = verify_prefilter(&pf, std::slice::from_ref(&data));

    let builtin_probes = vec![
        b"................yaml.load(................".to_vec(),
        b".................SELECT...................".to_vec(),
        b".........................==...............".to_vec(),
        b"................................@.........".to_vec(),
    ];
    let (builtin_missed, builtin_hits) = verify_prefilter(&pf, &builtin_probes);

    let specs256: Vec<LiteralSpec> = (0..256)
        .map(|i| LiteralSpec {
            rule_index: i,
            pattern: format!("KS_SIG_{i:03}(").into_bytes(),
            case_insensitive: false,
        })
        .collect();
    let pf256 = RulePrefilter::new(256, &specs256, &[]);
    let probe256 = RulePrefilter::build_aligned_probe_buffer(&specs256);
    let (hits256_missed, hits256) = verify_prefilter_raw(&pf256, 256, &specs256, &[], &[probe256]);

    let (pf1797, kml_n, specs1797, always1797, probe1797, kml_probe_source) = {
        let kml_p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".kintsugi/scars.kml");
        let (mut specs, mut always) = (Vec::with_capacity(1797), Vec::new());
        if let Ok(raw) = std::fs::read_to_string(&kml_p) {
            let recs = crate::kml::parse_kml_corpus(&raw);
            let n = recs.len();
            for (idx, r) in recs.iter().enumerate() {
                if r.neg.is_empty() { always.push(idx); }
                else { specs.push(LiteralSpec { rule_index: idx, pattern: r.neg.as_bytes().to_vec(), case_insensitive: false }); }
            }
            let pf_k = RulePrefilter::new(n, &specs, &always);
            let pr = RulePrefilter::build_aligned_probe_buffer(&specs);
            (pf_k, n, specs, always, pr, "scars_kml_corpus")
        } else {
            for i in 0..1797 {
                specs.push(LiteralSpec { rule_index: i, pattern: format!("KML_SIG_{i:04}(").into_bytes(), case_insensitive: false });
            }
            let pf_k = RulePrefilter::new(1797, &specs, &[]);
            let pr = RulePrefilter::build_aligned_probe_buffer(&specs);
            (pf_k, 1797, specs, always, pr, "synthetic_fallback")
        }
    };
    let (hits1797_missed, hits1797) = verify_prefilter_raw(&pf1797, kml_n, &specs1797, &always1797, &[probe1797]);

    let verified_oracle_hits = data_hits + builtin_hits + hits256 + hits1797;
    let delimiter_parity_ok = scalar_out == scalar_reused_out
        && scalar_out == simd_out
        && scalar_out == simd_reused_out
        && scalar_out == fb_out
        && mb_scalar_out == mb_scalar_reused_out
        && mb_scalar_out == mb_simd_out
        && mb_scalar_out == mb_simd_reused_out;
    // Strictly counts RulePrefilter oracle rules missed by scalar or SIMD prefilter (separated from delimiter parity).
    let false_negative_count = pf_missed_bits + builtin_missed + hits256_missed + hits1797_missed;
    let parity_ok = false_negative_count == 0 && delimiter_parity_ok;

    let scalar_stats = compute_stats("tier2_rust_scalar", "rust_scalar", scalar_times, size_bytes, scalar_out.len());
    let scalar_reused_stats = compute_stats(
        "tier2_rust_scalar_reused_buf",
        "rust_scalar",
        scalar_reused_times,
        size_bytes,
        scalar_reused_out.len(),
    );
    let simd_stats = compute_stats("tier3_rust_simd", active_simd_backend(false), simd_times, size_bytes, simd_out.len());
    let simd_reused_stats = compute_stats(
        "tier3_rust_simd_reused_buf",
        active_simd_backend(false),
        simd_reused_times,
        size_bytes,
        simd_reused_out.len(),
    );
    let fb_stats = compute_stats("tier3_rust_simd_disabled", active_simd_backend(true), fb_times, size_bytes, fb_out.len());
    let mb_scalar_stats = compute_stats("multibyte_rust_scalar", "rust_scalar", mb_scalar_times, size_bytes, mb_scalar_out.len());
    let mb_scalar_reused_stats = compute_stats(
        "multibyte_rust_scalar_reused_buf",
        "rust_scalar",
        mb_scalar_reused_times,
        size_bytes,
        mb_scalar_reused_out.len(),
    );
    let mb_simd_stats = compute_stats("multibyte_rust_simd", active_simd_backend(false), mb_simd_times, size_bytes, mb_simd_out.len());
    let mb_simd_reused_stats = compute_stats(
        "multibyte_rust_simd_reused_buf",
        active_simd_backend(false),
        mb_simd_reused_times,
        size_bytes,
        mb_simd_reused_out.len(),
    );

    let speedup_reused = if simd_reused_stats.median_us > 0.0 {
        scalar_reused_stats.median_us / simd_reused_stats.median_us
    } else {
        1.0
    };
    let speedup_alloc = if simd_stats.median_us > 0.0 {
        scalar_stats.median_us / simd_stats.median_us
    } else {
        1.0
    };

    #[allow(deprecated)]
    LogForgeBenchReport {
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        size_bytes,
        warmup,
        iters,
        seed,
        delim,
        input_fnv1a64,
        parity_ok,
        false_negative_count,
        prefilter_contract: PREFILTER_CONTRACT,
        scalar: scalar_stats,
        scalar_reused_buf: scalar_reused_stats,
        simd: simd_stats,
        simd_reused_buf: simd_reused_stats,
        simd_fallback: fb_stats,
        multibyte_scalar: mb_scalar_stats,
        multibyte_scalar_reused_buf: mb_scalar_reused_stats,
        multibyte_simd: mb_simd_stats,
        multibyte_simd_reused_buf: mb_simd_reused_stats,
        speedup_simd_vs_scalar: speedup_reused,
        speedup_reused_simd_vs_scalar: speedup_reused,
        speedup_allocating_simd_vs_scalar: speedup_alloc,
        verified_oracle_hits,
        kml_probe_source,
    }
}

/// Format `LogForgeBenchReport` as deterministic `schema_version = "1.1"` JSON.
#[allow(deprecated)]
pub fn render_bench_report_json(rep: &LogForgeBenchReport) -> String {
    let fmt_stat = |s: &KernelTierStats| -> String {
        format!(
            "{{\"tier\":\"{}\",\"backend\":\"{}\",\"min_us\":{:.3},\"median_us\":{:.3},\"p95_us\":{:.3},\"mean_us\":{:.3},\"throughput_gb_per_s\":{:.4},\"throughput_bytes_per_sec\":{:.1},\"throughput_gbps\":{:.4},\"matches\":{}}}",
            s.tier,
            s.backend,
            s.min_us,
            s.median_us,
            s.p95_us,
            s.mean_us,
            s.throughput_gb_per_s,
            s.throughput_bytes_per_sec,
            s.throughput_gbps,
            s.matches
        )
    };
    format!(
        "{{\"schema_version\":\"1.1\",\"deprecated_fields\":[\"throughput_gbps\",\"speedup_simd_vs_scalar\"],\"tool\":\"LogForge\",\"arch\":\"{}\",\"os\":\"{}\",\"size_bytes\":{},\"warmup\":{},\"iters\":{},\"seed\":{},\"delim\":{},\"input_fnv1a64\":\"{}\",\"parity_ok\":{},\"false_negative_count\":{},\"verified_oracle_hits\":{},\"kml_probe_source\":\"{}\",\"prefilter_contract\":\"{}\",\"speedup_simd_vs_scalar\":{:.3},\"speedup_reused_simd_vs_scalar\":{:.3},\"speedup_allocating_simd_vs_scalar\":{:.3},\"scalar_reused_buf_description\":\"zero-allocation reused Vec<usize> output; excludes result allocation\",\"results\":{{\"scalar\":{},\"scalar_reused_buf\":{},\"simd\":{},\"simd_reused_buf\":{},\"simd_fallback\":{},\"multibyte_scalar\":{},\"multibyte_scalar_reused_buf\":{},\"multibyte_simd\":{},\"multibyte_simd_reused_buf\":{}}}}}",
        rep.arch,
        rep.os,
        rep.size_bytes,
        rep.warmup,
        rep.iters,
        rep.seed,
        rep.delim,
        rep.input_fnv1a64,
        rep.parity_ok,
        rep.false_negative_count,
        rep.verified_oracle_hits,
        rep.kml_probe_source,
        rep.prefilter_contract,
        rep.speedup_simd_vs_scalar,
        rep.speedup_reused_simd_vs_scalar,
        rep.speedup_allocating_simd_vs_scalar,
        fmt_stat(&rep.scalar),
        fmt_stat(&rep.scalar_reused_buf),
        fmt_stat(&rep.simd),
        fmt_stat(&rep.simd_reused_buf),
        fmt_stat(&rep.simd_fallback),
        fmt_stat(&rep.multibyte_scalar),
        fmt_stat(&rep.multibyte_scalar_reused_buf),
        fmt_stat(&rep.multibyte_simd),
        fmt_stat(&rep.multibyte_simd_reused_buf),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn empty_samples_reused_buf_units_and_zero_false_negatives_contract() {
        let zero = compute_stats("tier_empty", "none", Vec::new(), 1024, 0);
        assert_eq!(zero.min_us, 0.0);
        assert_eq!(zero.median_us, 0.0);
        assert_eq!(zero.p95_us, 0.0);
        assert_eq!(zero.throughput_gb_per_s, 0.0);
        assert_eq!(zero.throughput_bytes_per_sec, 0.0);
        assert_eq!(zero.throughput_gbps, 0.0);

        let unit_stat = compute_stats("tier_unit", "scalar", vec![1000.0], 2_000_000, 12);
        assert!((unit_stat.throughput_bytes_per_sec - 2_000_000_000.0).abs() < 1.0);
        assert!((unit_stat.throughput_gb_per_s - 2.0).abs() < 1e-6);

        let rep = run_logforge_benchmark(4096, 1, 2, 42, b'\n');
        assert!(rep.parity_ok);
        assert_eq!(rep.false_negative_count, 0);
        assert_eq!(rep.prefilter_contract, PREFILTER_CONTRACT);
        assert_eq!(rep.scalar.matches, rep.scalar_reused_buf.matches);
        assert_eq!(rep.scalar.matches, rep.simd_reused_buf.matches);
        assert_eq!(rep.multibyte_scalar.matches, rep.multibyte_simd_reused_buf.matches);

        let json = render_bench_report_json(&rep);
        assert!(json.contains("\"schema_version\":\"1.1\""));
        assert!(json.contains("\"deprecated_fields\":[\"throughput_gbps\""));
        assert!(json.contains("\"false_negative_count\":0"));
        assert!(json.contains("\"prefilter_contract\":\"false_positives_permitted_zero_false_negatives_guaranteed\""));
        assert!(json.contains("\"scalar_reused_buf\":{"));
        assert!(json.contains("\"throughput_gb_per_s\":"));
        assert!(json.contains("\"throughput_bytes_per_sec\":"));
    }
}
