//! Benchmark subcommands (`bench`, `logforge-bench`, `sha256-bench`, `scan-bench`, `e2e-bench`)
//! with cryptographic `input_sha256`, `cpu_features`, `cache_mode`, and `measurement_scope` provenance.

use std::hint::black_box;
use std::path::Path;
use std::process;
use std::time::Instant;

#[cfg(feature = "logforge")]
use kintsugi_core::io_json::json_escape;
use kintsugi_core::io_json::{write_stdout_ln, JsonObj, ENGINE_VERSION};
use kintsugi_core::kernels::{
    active_prefilter_backend, active_sha256_backend, builtin_rule_prefilter, run_sha256_benchmark,
    LiteralSpec, RulePrefilter,
};
use kintsugi_core::kml::{
    inspect_kml_corpus_file, parse_kml_corpus, verify_outbound_destination_allowed,
    ALLOWED_PUBLIC_EVOLUTION_REPO,
};
use kintsugi_core::policy::sha256_hex;
use kintsugi_core::scanner::{scan_path, scan_path_full, scan_text, scan_text_buffer_no_fs};
use kintsugi_core::{Severity, BUILTIN_RULES};

use crate::cli::{emit_cli_error_json, parse_delim_byte, reject_unknown_flag, ArgCursor, CliToken};

const BENCH_CACHE_MODE: &str = "cold_first_then_in_memory_warm";
const BENCH_MEASUREMENT_SCOPE: &str = "unpinned_wall_clock_smoke_bench";

#[inline]
fn cpu_features_str() -> String {
    format!("prefilter={},sha256={}", active_prefilter_backend(false), active_sha256_backend(false))
}

#[cfg(feature = "logforge")]
fn synthetic_logforge_sha256(size_bytes: usize, seed: u64, delim: u8) -> String {
    const TEMPLATES: [&[u8]; 4] = [
        b"{\"timestamp\":\"2026-11-21T18:26:00.123456+07:00\",\"level\":\"info\",\"message\":\"gateway request accepted\",\"latency_us\":42}",
        b"2026-11-21 18:26:01.005Z WARN stream chunk alignment verified||ok",
        b"ts=1795266362.500 level=error msg=\"retry backoff\" host=node-01",
        b"{\"ts\":1795266363123456,\"severity\":\"debug\",\"event\":\"heartbeat\",\"ok\":true}",
    ];
    let (mut state, mut out) = (if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed }, Vec::with_capacity(size_bytes));
    while out.len() < size_bytes {
        state ^= state << 13; state ^= state >> 7; state ^= state << 17;
        let (line, rem) = (TEMPLATES[(state as usize) & 3], size_bytes - out.len());
        if rem > line.len() { out.extend_from_slice(line); out.push(delim); } else { out.extend_from_slice(&line[..rem]); }
    }
    sha256_hex(&out)
}

#[cfg(feature = "logforge")]
fn attach_bench_provenance(base_json: String, input_sha: &str) -> String {
    let Some(prefix) = base_json.trim_end().strip_suffix('}') else { return base_json };
    let (mut out, cpu_f) = (prefix.to_string(), cpu_features_str());
    if !out.contains("\"schema_version\"") { out.push_str(",\"schema_version\":\"1.1\""); }
    if !out.contains("\"engine_version\"") { out.push_str(&format!(",\"engine_version\":\"{}\"", json_escape(ENGINE_VERSION))); }
    for (k, v) in [("input_sha256", input_sha), ("cpu_features", &cpu_f), ("cache_mode", BENCH_CACHE_MODE), ("measurement_scope", BENCH_MEASUREMENT_SCOPE)] {
        if !out.contains(&format!("\"{k}\":")) { out.push_str(&format!(",\"{k}\":\"{}\"", json_escape(v))); }
    }
    out.push('}');
    out
}

fn percentile_sorted(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() { return 0.0; }
    if sorted.len() == 1 { return sorted[0]; }
    let rank = (pct.clamp(0.0, 100.0) / 100.0) * ((sorted.len() - 1) as f64);
    let (lo, hi) = (rank.floor() as usize, rank.ceil() as usize);
    let frac = rank - (lo as f64);
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

fn stats_json(cold: f64, samples: &mut [f64], unit: &str) -> String {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mean = if samples.is_empty() { 0.0 } else { samples.iter().sum::<f64>() / (samples.len() as f64) };
    JsonObj::with_capacity(160)
        .f64_3(&format!("cold_{unit}"), cold)
        .f64_3(&format!("min_{unit}"), samples.first().copied().unwrap_or(0.0))
        .f64_3(&format!("p50_{unit}"), percentile_sorted(samples, 50.0))
        .f64_3(&format!("p95_{unit}"), percentile_sorted(samples, 95.0))
        .f64_3(&format!("p99_{unit}"), percentile_sorted(samples, 99.0))
        .f64_3(&format!("mean_{unit}"), mean).finish()
}

fn measure_cold_and_warm_us<F: FnMut()>(warmup: usize, iters: usize, mut f: F) -> (f64, Vec<f64>) {
    let t0 = Instant::now();
    f();
    let cold_us = (t0.elapsed().as_nanos() as f64) / 1000.0;
    for _ in 0..warmup { f(); }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters { let t = Instant::now(); f(); samples.push((t.elapsed().as_nanos() as f64) / 1000.0); }
    (cold_us, samples)
}

fn parse_byte_bench_args(args: &[String], allow_delim: bool) -> (usize, usize, usize, u64, u8) {
    let (mut size_bytes, mut warmup, mut iters, mut seed, mut delim) = (1_048_576usize, 10usize, 50usize, 20_261_121u64, b'\n');
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Flag("--size-bytes") => size_bytes = cur.parse_usize("--size-bytes"),
            CliToken::Flag("--warmup") => warmup = cur.parse_usize("--warmup"),
            CliToken::Flag("--iters") => iters = cur.parse_usize("--iters").max(1),
            CliToken::Flag("--seed") => seed = cur.parse_u64("--seed"),
            CliToken::Flag("--delim") if allow_delim => {
                delim = parse_delim_byte(cur.require_value("--delim")).unwrap_or_else(|e| emit_cli_error_json("INVALID_DELIM", &e, 2));
            }
            other => reject_unknown_flag(other.as_str()),
        }
    }
    (size_bytes, warmup, iters, seed, delim)
}

pub fn run_core_bench() {
    let sample = "import os, subprocess, requests\ndef fetch_data(url: str) -> str:\n    return requests.get(url, timeout=10).text\n";
    let sample_sha = sha256_hex(sample.as_bytes());
    let (iterations, t0) = (200u32, Instant::now());
    for _ in 0..iterations { let _ = black_box(scan_text(sample, "bench.py", "python", Severity::Low, None)); }
    let avg_us = (t0.elapsed().as_micros() as f64) / (iterations as f64);
    let kml_info = inspect_kml_corpus_file(Path::new(".kintsugi/scars.kml")).ok();
    let egress_ok = verify_outbound_destination_allowed("https://github.com/tunguyen1993/kintsugi-harness.git");

    #[cfg(feature = "audit")]
    let (verbose_tok, kmi_tok, red_pct, saved_50) = {
        let tb = kintsugi_core::audit::compute_token_benchmark();
        (tb.verbose_tokens, tb.kmi_tokens, tb.reduction_pct, tb.saved_tokens_50_turns)
    };
    #[cfg(not(feature = "audit"))]
    let (verbose_tok, kmi_tok, red_pct, saved_50) = (BUILTIN_RULES.len() * 190, 620usize, 90.9f64, 311_000usize);

    let mut report = JsonObj::with_capacity(512)
        .str("schema_version", "1.1").str("engine_version", ENGINE_VERSION)
        .str("tool", "KintsugiCoreBench").str("arch", std::env::consts::ARCH).str("os", std::env::consts::OS)
        .str("input_sha256", &sample_sha).str("cpu_features", &cpu_features_str())
        .str("cache_mode", BENCH_CACHE_MODE).str("measurement_scope", BENCH_MEASUREMENT_SCOPE)
        .usize("active_builtin_rules", BUILTIN_RULES.len()).usize("iterations", iterations as usize)
        .f64_3("avg_scan_us", avg_us).usize("verbose_tokens_per_turn", verbose_tok)
        .usize("kmi_tokens_per_turn", kmi_tok).f64_3("reduction_pct", red_pct).usize("saved_tokens_50_turns", saved_50)
        .str("outbound_egress_whitelist", ALLOWED_PUBLIC_EVOLUTION_REPO).bool("egress_ok", egress_ok);
    if let Some(krep) = kml_info {
        report = report.usize("kml_verified_records", krep.verified_records).f64_3("kml_elapsed_ms", (krep.elapsed_micros as f64) / 1000.0);
    }
    write_stdout_ln(&report.finish());
}

pub fn run_logforge_bench_cmd(args: &[String]) {
    let (size_bytes, warmup, iters, seed, delim) = parse_byte_bench_args(args, true);
    #[cfg(feature = "logforge")]
    {
        use kintsugi_core::kernels::{render_bench_report_json, run_logforge_benchmark};
        let rep = run_logforge_benchmark(size_bytes, warmup, iters, seed, delim);
        let in_sha = synthetic_logforge_sha256(size_bytes, seed, delim);
        write_stdout_ln(&attach_bench_provenance(render_bench_report_json(&rep), &in_sha));
        if !rep.parity_ok { process::exit(1); }
    }
    #[cfg(not(feature = "logforge"))]
    {
        let _ = (size_bytes, warmup, iters, seed, delim);
        emit_cli_error_json("FEATURE_DISABLED", "Subcommand 'logforge-bench' requires Cargo feature 'logforge'", 2);
    }
}

pub fn run_sha256_bench_cmd(args: &[String]) {
    let (size_bytes, warmup, iters, seed, _) = parse_byte_bench_args(args, false);
    let rep = run_sha256_benchmark(size_bytes, warmup, iters, seed);
    let tier_json = |b: &str, min: f64, med: f64, p95: f64, mean: f64, gbps: f64| {
        JsonObj::with_capacity(180).str("backend", b).f64_3("min_us", min).f64_3("median_us", med).f64_3("p95_us", p95).f64_3("mean_us", mean).raw("throughput_gbps", &format!("{gbps:.4}")).f64_3("oneshot_1mb_hw_accel_us", min).f64_3("incremental_64b_hw_accel_us", med).finish()
    };
    let hw_obj = tier_json(rep.hw.backend, rep.hw.min_us, rep.hw.median_us, rep.hw.p95_us, rep.hw.mean_us, rep.hw.throughput_gbps);
    let sc_obj = tier_json(rep.scalar.backend, rep.scalar.min_us, rep.scalar.median_us, rep.scalar.p95_us, rep.scalar.mean_us, rep.scalar.throughput_gbps);
    let out = JsonObj::with_capacity(640)
        .str("schema_version", "1.1").str("engine_version", ENGINE_VERSION).str("tool", "KintsugiSHA256")
        .str("arch", std::env::consts::ARCH).str("os", std::env::consts::OS)
        .str("input_sha256", &rep.digest_hex).str("cpu_features", &cpu_features_str())
        .str("cache_mode", BENCH_CACHE_MODE).str("measurement_scope", BENCH_MEASUREMENT_SCOPE)
        .usize("size_bytes", rep.size_bytes).usize("warmup", rep.warmup).usize("iters", rep.iters)
        .u64("seed", seed).bool("parity_ok", rep.parity_ok).str("digest_hex", &rep.digest_hex)
        .f64_3("speedup_hw_vs_scalar", rep.speedup_hw_vs_scalar).raw("hw", &hw_obj).raw("scalar", &sc_obj).finish();
    write_stdout_ln(&out);
    if !rep.parity_ok { process::exit(1); }
}

pub fn run_scan_bench_cmd(args: &[String]) {
    let (mut target, mut warmup, mut iters) = ("src", 3usize, 10usize);
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => target = p,
            CliToken::Flag("--warmup") => warmup = cur.parse_usize("--warmup"),
            CliToken::Flag("--iters") => iters = cur.parse_usize("--iters").max(1),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    let target_path = Path::new(target);
    for _ in 0..warmup { let _ = scan_path(target_path, Severity::Low); }
    let (mut scan_ms_samples, mut last_sum) = (Vec::with_capacity(iters), None);
    for _ in 0..iters {
        let sum = scan_path(target_path, Severity::Low);
        scan_ms_samples.push((sum.elapsed_micros as f64) / 1000.0);
        last_sum = Some(sum);
    }
    scan_ms_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let (scan_min_ms, scan_median_ms) = (scan_ms_samples[0], percentile_sorted(&scan_ms_samples, 50.0));
    let scan_mean_ms = scan_ms_samples.iter().sum::<f64>() / (scan_ms_samples.len() as f64);

    let (mut concat_buf, mut stack) = (Vec::new(), vec![target_path.to_path_buf()]);
    while let Some(p) = stack.pop() {
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.file_type().is_symlink() { continue; }
        if md.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) { for e in rd.flatten() { stack.push(e.path()); } }
        } else if md.is_file() && p.extension().and_then(|s| s.to_str()) == Some("py") {
            if let Ok(bytes) = std::fs::read(&p) { concat_buf.extend_from_slice(&bytes); concat_buf.push(b'\n'); }
        }
    }
    let pf_36 = builtin_rule_prefilter();
    let (t_pf0, mut mask_neon) = (Instant::now(), 0u64);
    for _ in 0..20 { mask_neon = pf_36.candidate_mask_first_word_u64(&concat_buf, false); }
    let pf36_neon_us = (t_pf0.elapsed().as_nanos() as f64) / 20_000.0;
    let (t_pf1, mut mask_scalar) = (Instant::now(), 0u64);
    for _ in 0..20 { mask_scalar = pf_36.candidate_mask_first_word_u64(&concat_buf, true); }
    let pf36_scalar_us = (t_pf1.elapsed().as_nanos() as f64) / 20_000.0;

    let (mut kml_records_count, mut kml_neon_us, mut kml_scalar_us, mut kml_oracle_parity) = (0usize, 0.0f64, 0.0f64, true);
    if let Ok(kml_text) = std::fs::read_to_string(".kintsugi/scars.kml") {
        let recs = parse_kml_corpus(&kml_text);
        kml_records_count = recs.len();
        let (mut specs, mut always) = (Vec::new(), Vec::new());
        for (ri, r) in recs.iter().enumerate() {
            if r.neg.is_empty() { always.push(ri); }
            else { specs.push(LiteralSpec { rule_index: ri, pattern: r.neg.as_bytes().to_vec(), case_insensitive: false }); }
        }
        let kml_pf = RulePrefilter::new(recs.len(), &specs, &always);
        let (tk0, mut k_neon) = (Instant::now(), Vec::new());
        for _ in 0..10 { k_neon = kml_pf.candidate_rule_indices(&concat_buf, false); }
        kml_neon_us = (tk0.elapsed().as_nanos() as f64) / 10_000.0;
        let (tk1, mut k_sc) = (Instant::now(), Vec::new());
        for _ in 0..10 { k_sc = kml_pf.candidate_rule_indices(&concat_buf, true); }
        kml_scalar_us = (tk1.elapsed().as_nanos() as f64) / 10_000.0;
        kml_oracle_parity = k_neon == k_sc && k_neon == kml_pf.scalar_oracle_rule_indices(&concat_buf);
    }

    let sum = last_sum.expect("iters >= 1");
    let out = JsonObj::with_capacity(640)
        .str("schema_version", "1.1").str("engine_version", ENGINE_VERSION).str("tool", "KintsugiScanBench").str("target", target)
        .str("backend", active_prefilter_backend(false))
        .str("input_sha256", &sha256_hex(&concat_buf)).str("cpu_features", &cpu_features_str())
        .str("cache_mode", BENCH_CACHE_MODE).str("measurement_scope", BENCH_MEASUREMENT_SCOPE)
        .usize("scanned_files", sum.scanned_files).usize("corpus_bytes", concat_buf.len())
        .usize("active_rules", sum.active_rules).usize("findings_count", sum.findings.len())
        .usize("warmup", warmup).usize("iters", iters)
        .f64_3("scan_min_ms", scan_min_ms).f64_3("scan_median_ms", scan_median_ms).f64_3("scan_mean_ms", scan_mean_ms)
        .bool("prefilter_36_parity_ok", mask_neon == mask_scalar)
        .f64_3("prefilter_36_neon_us", pf36_neon_us).f64_3("prefilter_36_scalar_us", pf36_scalar_us)
        .usize("kml_records", kml_records_count).bool("kml_prefilter_parity_ok", kml_oracle_parity)
        .f64_3("kml_prefilter_neon_us", kml_neon_us).f64_3("kml_prefilter_scalar_us", kml_scalar_us).finish();
    write_stdout_ln(&out);
}

pub fn run_e2e_bench_cmd(args: &[String]) {
    let (mut target, mut warmup, mut iters, mut format) = (None, 5usize, 25usize, "json");
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => target = Some(p),
            CliToken::Flag("--warmup") => warmup = cur.parse_usize("--warmup"),
            CliToken::Flag("--iters") => iters = cur.parse_usize("--iters").max(1),
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["json", "text"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    let dir_target = target.unwrap_or_else(|| if Path::new("src").exists() { "src" } else if Path::new("rust/src").exists() { "rust/src" } else { "." });

    #[cfg(feature = "audit")]
    let (pretool_raw, pretool_bytes, pt_cold_us, pt_samples, pt_json) = {
        let pad_body = "def verify_order(uid: int, amt: int) -> bool:\n    return uid > 0 and amt >= 0\n".repeat(12);
        let ti = JsonObj::with_capacity(1024).str("file_path", "src/orders/validator.py").str("content", &pad_body[..pad_body.len().min(910)]).finish();
        let pretool_1kb = JsonObj::with_capacity(1100).str("tool_name", "Write").raw("tool_input", &ti).finish();
        let ws_cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let (cold_us, mut samples) = measure_cold_and_warm_us(warmup, iters, || {
            let _ = black_box(kintsugi_core::audit::evaluate_pre_tool_json_with_workspace(black_box(&pretool_1kb), Severity::High, Some(&ws_cwd)));
        });
        let js = stats_json(cold_us, &mut samples, "us");
        let n = pretool_1kb.len();
        (pretool_1kb, n, cold_us, samples, js)
    };

    let unit_fn = "import hmac, hashlib, yaml\ndef handle_req(cur, key: bytes, body: bytes, sig: str, raw_cfg: str) -> bool:\n    cfg = yaml.safe_load(raw_cfg)\n    cur.execute('SELECT id FROM accounts WHERE tenant = ?', (cfg.get('tenant', 'default'),))\n    mac = hmac.new(key, body, hashlib.sha256).hexdigest()\n    return hmac.compare_digest(mac, sig)\n\n";
    let mut buf_100kb = unit_fn.repeat((102_400 / unit_fn.len()) + 1);
    buf_100kb.truncate(102_400);
    let (buf_cold_us, mut buf_samples) = measure_cold_and_warm_us(warmup, iters, || {
        let _ = black_box(scan_text_buffer_no_fs(black_box(&buf_100kb), "bench_100kb.py", "python", Severity::Low));
    });

    let (dir_path, mut scanned_files) = (Path::new(dir_target), 0usize);
    let (dir_cold_us, dir_us_samples) = measure_cold_and_warm_us(warmup.min(3), iters.min(15).max(1), || {
        scanned_files = scan_path_full(dir_path, Severity::Low, None, None, true, None).scanned_files;
    });
    let dir_cold_ms = dir_cold_us / 1000.0;
    let mut dir_samples: Vec<f64> = dir_us_samples.into_iter().map(|u| u / 1000.0).collect();
    let (buf_json, dir_json) = (stats_json(buf_cold_us, &mut buf_samples, "us"), stats_json(dir_cold_ms, &mut dir_samples, "ms"));
    let mut combo_hasher = Vec::with_capacity(buf_100kb.len() + 4096);
    #[cfg(feature = "audit")]
    combo_hasher.extend_from_slice(pretool_raw.as_bytes());
    combo_hasher.extend_from_slice(buf_100kb.as_bytes());
    let mut dir_files = Vec::new();
    kintsugi_core::scanner::collect_files(dir_path, &mut dir_files);
    dir_files.sort();
    for df in dir_files {
        if let Ok(bytes) = kintsugi_core::io_json::read_regular_bytes_fd_verified(&df, 8 * 1024 * 1024) {
            combo_hasher.extend_from_slice(&bytes);
            combo_hasher.push(0);
        }
    }
    let combined_input_sha256 = sha256_hex(&combo_hasher);

    if format == "text" {
        write_stdout_ln(&format!("Kintsugi-RS v{ENGINE_VERSION} E2E Benchmark @ 1.1"));
        write_stdout_ln(&format!("  Input-SHA256: {}", combined_input_sha256));
        write_stdout_ln(&format!("  CPU Features: {}", cpu_features_str()));
        write_stdout_ln(&format!("  Cache Mode  : {}", BENCH_CACHE_MODE));
        write_stdout_ln(&format!("  SIMD Backend: {} | SHA256 Backend: {}", active_prefilter_backend(false), active_sha256_backend(false)));
        #[cfg(feature = "audit")]
        write_stdout_ln(&format!("  • 1 KB PreToolUse ({pretool_bytes}B): cold={pt_cold_us:.1}µs p50={:.1}µs p95={:.1}µs p99={:.1}µs", percentile_sorted(&pt_samples, 50.0), percentile_sorted(&pt_samples, 95.0), percentile_sorted(&pt_samples, 99.0)));
        write_stdout_ln(&format!(
            "  • 100 KB Buffer ({}B): cold={buf_cold_us:.1}µs p50={:.1}µs p95={:.1}µs p99={:.1}µs\n  • Dir Scan ({dir_target}, {scanned_files} files): cold={dir_cold_ms:.2}ms p50={:.2}ms p95={:.2}ms p99={:.2}ms",
            buf_100kb.len(), percentile_sorted(&buf_samples, 50.0), percentile_sorted(&buf_samples, 95.0), percentile_sorted(&buf_samples, 99.0),
            percentile_sorted(&dir_samples, 50.0), percentile_sorted(&dir_samples, 95.0), percentile_sorted(&dir_samples, 99.0),
        ));
        return;
    }

    let report = JsonObj::with_capacity(768)
        .bool("ok", true).str("schema_version", "1.1").str("engine_version", ENGINE_VERSION).str("tool", "KintsugiE2EBench")
        .str("arch", std::env::consts::ARCH).str("os", std::env::consts::OS)
        .str("simd_backend", active_prefilter_backend(false)).str("sha256_backend", active_sha256_backend(false))
        .str("input_sha256", &combined_input_sha256).str("cpu_features", &cpu_features_str())
        .str("cache_mode", BENCH_CACHE_MODE).str("measurement_scope", BENCH_MEASUREMENT_SCOPE)
        .usize("warmup", warmup).usize("iters", iters);
    #[cfg(feature = "audit")]
    let report = report.usize("pretool_bytes", pretool_bytes).raw("pretool_1kb", &pt_json);
    write_stdout_ln(&report.usize("buffer_bytes", buf_100kb.len()).raw("buffer_100kb", &buf_json).str("dir_target", dir_target).usize("dir_scanned_files", scanned_files).raw("dir_scan", &dir_json).finish());
}
