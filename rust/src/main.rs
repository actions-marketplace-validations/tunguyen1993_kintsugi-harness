//! `kintsugi-rs` v2.4.0 — Native Rust CLI for sub-millisecond PreToolUse hooks,
//! Grade S3 `@CT2` Seam Auditing, Read-Only Memory Integrity Verification,
//! git-diff scanning, and `KMI/1` Ultra-Low-Token compression.

use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process;
use std::time::Instant;

use kintsugi_core::kernels::{
    active_prefilter_backend, active_simd_backend, builtin_rule_prefilter, normalize_log_records,
    render_bench_report_json, run_logforge_benchmark, run_sha256_benchmark, scan_delimiters,
    scan_multibyte_delimiters,
};
use kintsugi_core::{
    audit_step_economics_path, compute_token_benchmark, estimate_tokens,
    evaluate_pre_tool_json_with_workspace, evaluate_rule_ir_json, inspect_kml_corpus_file,
    json_escape, parse_kml_corpus, render_creed_json, render_kmi_compact_header,
    render_kml_builtin_corpus, render_step_audit_json, render_swarm_plan_json, s3_audit_path,
    scan_git_staged_with_shadow, scan_path, scan_path_with_policy_sha_and_shadow, scan_text,
    validate_rule_ir_json, validate_rule_ir_json_strict, verify_memories_readonly,
    verify_outbound_destination_allowed, Finding, S3AuditSummary, ScanSummary, Severity,
    ALLOWED_PUBLIC_EVOLUTION_REPO, BUILTIN_RULES,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn require_flag_value(flag: &str, idx: &mut usize, args: &[String]) -> String {
    if *idx + 1 >= args.len() {
        eprintln!("Error: Missing value for option '{flag}'");
        process::exit(2);
    }
    *idx += 1;
    args[*idx].clone()
}

fn reject_unknown_flag(arg: &str) {
    if arg.starts_with('-') {
        eprintln!("Error: Unknown option '{arg}'");
        process::exit(2);
    }
}

fn parse_delim_byte(spec: &str) -> Result<u8, String> {
    match spec {
        "\\n" | "\n" | "lf" | "LF" | "newline" => Ok(b'\n'),
        "\\0" | "\0" | "nul" | "NUL" | "null" => Ok(b'\0'),
        "\\r" | "\r" | "cr" | "CR" => Ok(b'\r'),
        "\\t" | "\t" | "tab" | "TAB" => Ok(b'\t'),
        _ if spec.starts_with("0x") || spec.starts_with("0X") => {
            u8::from_str_radix(&spec[2..], 16)
                .map_err(|e| format!("Invalid hex delimiter '{spec}': {e}"))
        }
        _ if spec.as_bytes().len() == 1 => Ok(spec.as_bytes()[0]),
        _ => spec
            .parse::<u8>()
            .map_err(|e| format!("Invalid delimiter '{spec}': {e}")),
    }
}

fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim();
    if clean.len() % 2 != 0 {
        return Err(format!("Hex pattern must have even length: '{clean}'"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let b = clean.as_bytes();
    let mut idx = 0usize;
    while idx < b.len() {
        let pair = std::str::from_utf8(&b[idx..idx + 2]).map_err(|e| e.to_string())?;
        let val = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("Invalid hex byte '{pair}': {e}"))?;
        out.push(val);
        idx += 2;
    }
    Ok(out)
}

fn print_help() {
    println!(
        "kintsugi-rs {VERSION} — Native Rust @KML/1 & Grade-S3 Guardrail Engine\n\
         \n\
         USAGE:\n\
         \x20 kintsugi-rs scan [PATH...] [--staged] [--shadow-arm-c] [--gate-compact] [--format text|json] [--min-severity LEVEL] [--fail-on LEVEL] [--policy-file PATH] [--policy-sha256 HEX] [-- <PATH...>]\n\
         \x20 kintsugi-rs s3-audit [PATH...] [--format text|json] [-- <PATH...>]\n\
         \x20 kintsugi-rs memories-verify [WORKSPACE_ROOT] [--format text|json]\n\
         \x20 kintsugi-rs creed\n\
         \x20 kintsugi-rs swarm-plan [TASK_DESC]\n\
         \x20 kintsugi-rs step-audit [PATH] [--max-sessions N] [--sub-cap 12] [--task-cap 25] [--wire]\n\
         \x20 kintsugi-rs hook claude-pre-tool [--block-on HIGH] [--workspace PATH]\n\
         \x20 kintsugi-rs rule-ir-check [PATH|-] [--strict-hash]\n\
         \x20 kintsugi-rs rule-ir-eval --rule PATH|- [--lang LANG] [CODE_PATH|-]\n\
         \x20 kintsugi-rs kml [PATH_TO_SCARS_KML]\n\
         \x20 kintsugi-rs compress [--kml]\n\
         \x20 kintsugi-rs scan-bytes [PATH|-] [--delim SPEC] [--pattern STR] [--pattern-hex HEX] [--disable-simd] [--normalize] [--format json|offsets]\n\
         \x20 kintsugi-rs logforge-bench [--size-bytes N] [--warmup N] [--iters N] [--seed N] [--delim SPEC]\n\
         \x20 kintsugi-rs sha256-bench [--size-bytes N] [--warmup N] [--iters N] [--seed N]\n\
         \x20 kintsugi-rs scan-bench [PATH] [--warmup N] [--iters N]\n\
         \x20 kintsugi-rs bench\n\
         \x20 kintsugi-rs --version"
    );
}

fn render_gate_compact(findings: &[Finding], max_tokens: usize) -> String {
    if findings.is_empty() || max_tokens == 0 {
        return String::new();
    }
    let mut kept: Vec<String> = Vec::new();
    for (idx, f) in findings.iter().enumerate() {
        let mut entry = format!("[{}@{}] {}", f.scar_id, f.line, f.fix_hint);
        let remaining = findings.len().saturating_sub(idx + 1);
        let suffix = if remaining > 0 {
            format!("\n... (+{remaining} more)")
        } else {
            String::new()
        };
        let mut candidate = if kept.is_empty() {
            entry.clone()
        } else {
            format!("{}\n{}", kept.join("\n"), entry)
        };
        if !suffix.is_empty() {
            candidate.push_str(&suffix);
        }
        if estimate_tokens(&candidate) <= max_tokens {
            kept.push(entry);
            continue;
        }
        if kept.is_empty() {
            // Trim single finding line until it fits strictly within `max_tokens`
            while estimate_tokens(&entry) > max_tokens && entry.chars().count() > 8 {
                let mut chars: Vec<char> = entry.chars().collect();
                let new_len = chars.len().saturating_sub(8);
                chars.truncate(new_len);
                entry = format!("{}...", chars.into_iter().collect::<String>());
            }
            kept.push(entry);
        } else {
            let omitted = findings.len().saturating_sub(kept.len());
            if omitted > 0 {
                let tail = format!("... (+{omitted} more)");
                let with_tail = format!("{}\n{tail}", kept.join("\n"));
                if estimate_tokens(&with_tail) <= max_tokens {
                    kept.push(tail);
                }
            }
            break;
        }
    }
    let mut out = kept.join("\n");
    if kept.len() < findings.len() && !out.contains("more)") {
        let omitted = findings.len().saturating_sub(kept.len());
        let tail = format!("... (+{omitted} more)");
        let with_tail = format!("{out}\n{tail}");
        if estimate_tokens(&with_tail) <= max_tokens {
            out = with_tail;
        }
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print_help();
        return;
    }
    if args[0] == "-V" || args[0] == "--version" {
        println!("kintsugi-rs {VERSION}");
        return;
    }

    match args[0].as_str() {
        "scan" => {
            let mut targets: Vec<String> = Vec::new();
            let mut staged = false;
            let mut shadow_arm_c = false;
            let mut gate_compact = false;
            let mut format = "text".to_string();
            let mut min_sev = Severity::Low;
            let mut fail_on = Some(Severity::High);
            let mut policy_file: Option<String> = None;
            let mut policy_sha256: Option<String> = None;
            let mut after_double_dash = false;

            let mut i = 1;
            while i < args.len() {
                if after_double_dash {
                    targets.push(args[i].clone());
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "--" => {
                        after_double_dash = true;
                    }
                    "--staged" => staged = true,
                    "--shadow-arm-c" => shadow_arm_c = true,
                    "--gate-compact" => gate_compact = true,
                    "--format" => {
                        format = require_flag_value("--format", &mut i, &args);
                    }
                    "--policy-file" => {
                        policy_file = Some(require_flag_value("--policy-file", &mut i, &args));
                    }
                    "--policy-sha256" => {
                        policy_sha256 = Some(require_flag_value("--policy-sha256", &mut i, &args));
                    }
                    "--min-severity" => {
                        let v = require_flag_value("--min-severity", &mut i, &args);
                        min_sev = Severity::from_str(&v);
                    }
                    "--fail-on" => {
                        let v = require_flag_value("--fail-on", &mut i, &args);
                        if v.eq_ignore_ascii_case("NONE") {
                            fail_on = None;
                        } else {
                            fail_on = Some(Severity::from_str(&v));
                        }
                    }
                    arg if !arg.starts_with('-') => {
                        targets.push(arg.to_string());
                    }
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            if targets.is_empty() {
                targets.push(".".to_string());
            }

            let summary = if staged {
                scan_git_staged_with_shadow(Path::new(&targets[0]), min_sev, shadow_arm_c)
            } else if targets.len() == 1 {
                scan_path_with_policy_sha_and_shadow(
                    Path::new(&targets[0]),
                    min_sev,
                    policy_file.as_deref().map(Path::new),
                    policy_sha256.as_deref(),
                    shadow_arm_c,
                )
            } else {
                let mut total = ScanSummary {
                    scanned_files: 0,
                    active_rules: BUILTIN_RULES.len() + if shadow_arm_c { 5 } else { 0 },
                    elapsed_micros: 0,
                    findings: Vec::new(),
                };
                for t in &targets {
                    let mut sub = scan_path_with_policy_sha_and_shadow(
                        Path::new(t),
                        min_sev,
                        policy_file.as_deref().map(Path::new),
                        policy_sha256.as_deref(),
                        shadow_arm_c,
                    );
                    total.scanned_files += sub.scanned_files;
                    total.active_rules = sub.active_rules;
                    total.elapsed_micros += sub.elapsed_micros;
                    total.findings.append(&mut sub.findings);
                }
                total
            };

            if gate_compact {
                if summary.findings.is_empty() {
                    return;
                }
                println!("{}", render_gate_compact(&summary.findings, 150));
                process::exit(1);
            }

            let ms = (summary.elapsed_micros as f64) / 1000.0;
            if format == "json" {
                let items: Vec<String> = summary
                    .findings
                    .iter()
                    .map(|f| {
                        let is_shadow = f.scar_id.starts_with("KC-C");
                        format!(
                            "{{\"scar_id\":\"{}\",\"severity\":\"{}\",\"category\":\"{}\",\"shadow\":{},\"file_path\":\"{}\",\"line\":{},\"column\":{},\"title\":\"{}\",\"snippet\":\"{}\",\"good_code_hint\":\"{}\"}}",
                            json_escape(&f.scar_id),
                            f.severity.as_str(),
                            json_escape(&f.category),
                            is_shadow,
                            json_escape(&f.file_path),
                            f.line,
                            f.column,
                            json_escape(&f.title),
                            json_escape(&f.snippet),
                            json_escape(&f.fix_hint)
                        )
                    })
                    .collect();
                println!(
                    "{{\"schema_version\":\"2.4.0\",\"engine\":\"kintsugi-rs\",\"engine_version\":\"{}\",\"shadow_arm_c\":{},\"scanned_files\":{},\"active_scars\":{},\"elapsed_ms\":{:.3},\"findings\":[{}]}}",
                    VERSION,
                    shadow_arm_c,
                    summary.scanned_files,
                    summary.active_rules,
                    ms,
                    items.join(",")
                );
            } else {
                println!(
                    "Kintsugi-RS Native Scan: {} file(s) checked against {} scars in {:.3}ms ({} µs)",
                    summary.scanned_files, summary.active_rules, ms, summary.elapsed_micros
                );
                if summary.findings.is_empty() {
                    println!("PASS: 0 anti-pattern violations found.");
                } else {
                    for f in &summary.findings {
                        println!(
                            "  [{}] {} {}:{} — {}\n    Snippet : {}\n    Fix     : {}",
                            f.severity.as_str(),
                            f.scar_id,
                            f.file_path,
                            f.line,
                            f.title,
                            f.snippet,
                            f.fix_hint
                        );
                    }
                }
            }

            if let Some(threshold) = fail_on {
                if summary.findings.iter().any(|f| f.severity >= threshold) {
                    process::exit(1);
                }
            }
        }
        "s3-audit" => {
            let mut targets: Vec<String> = Vec::new();
            let mut format = "json".to_string();
            let mut after_double_dash = false;
            let mut i = 1;
            while i < args.len() {
                if after_double_dash {
                    targets.push(args[i].clone());
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "--" => after_double_dash = true,
                    "--format" => {
                        format = require_flag_value("--format", &mut i, &args);
                    }
                    arg if !arg.starts_with('-') => {
                        targets.push(arg.to_string());
                    }
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            if targets.is_empty() {
                targets.push(".".to_string());
            }
            let rep = if targets.len() == 1 {
                s3_audit_path(Path::new(&targets[0]))
            } else {
                let mut merged = S3AuditSummary {
                    target: targets.join(","),
                    files_scanned: 0,
                    total_functions: 0,
                    total_classes: 0,
                    total_seams: 0,
                    s3_locked_seams: 0,
                    unguarded_s0_seams: 0,
                    elapsed_ms: 0.0,
                    verdict: "PASS_S3_LOCKED",
                    files: Vec::new(),
                };
                for t in &targets {
                    let mut sub = s3_audit_path(Path::new(t));
                    merged.files_scanned += sub.files_scanned;
                    merged.total_functions += sub.total_functions;
                    merged.total_classes += sub.total_classes;
                    merged.total_seams += sub.total_seams;
                    merged.s3_locked_seams += sub.s3_locked_seams;
                    merged.unguarded_s0_seams += sub.unguarded_s0_seams;
                    merged.elapsed_ms += sub.elapsed_ms;
                    merged.files.append(&mut sub.files);
                }
                if merged.unguarded_s0_seams > 0 {
                    merged.verdict = "FAIL_S0_EXPOSED";
                }
                merged
            };
            if format == "text" {
                println!(
                    "Kintsugi-RS v{VERSION} Grade-S3 Seam Audit: files={} functions={} classes={} seams={}/{} S0_unguarded={} elapsed={:.3}ms verdict={}",
                    rep.files_scanned,
                    rep.total_functions,
                    rep.total_classes,
                    rep.s3_locked_seams,
                    rep.total_seams,
                    rep.unguarded_s0_seams,
                    rep.elapsed_ms,
                    rep.verdict
                );
                for f in &rep.files {
                    println!(
                        "  {} | sha={} | {:.2}ms | fn/cls={}/{} | seams={}/{} | S0={} | {}",
                        f.file_path,
                        f.manifest_sha,
                        f.elapsed_ms,
                        f.functions_count,
                        f.classes_count,
                        f.s3_locked_seams,
                        f.total_seams,
                        f.unguarded_s0_seams,
                        f.verdict
                    );
                }
            } else {
                let file_objs: Vec<String> = rep
                    .files
                    .iter()
                    .map(|f| {
                        format!(
                            "{{\"file_path\":\"{}\",\"manifest_sha\":\"{}\",\"elapsed_ms\":{:.3},\"functions_count\":{},\"classes_count\":{},\"total_seams\":{},\"s3_locked_seams\":{},\"unguarded_s0_seams\":{},\"verdict\":\"{}\"}}",
                            json_escape(&f.file_path),
                            json_escape(&f.manifest_sha),
                            f.elapsed_ms,
                            f.functions_count,
                            f.classes_count,
                            f.total_seams,
                            f.s3_locked_seams,
                            f.unguarded_s0_seams,
                            f.verdict
                        )
                    })
                    .collect();
                println!(
                    "{{\"ok\":{},\"schema_version\":\"2.4.0\",\"engine\":\"kintsugi-rs\",\"engine_version\":\"{}\",\"target\":\"{}\",\"files_scanned\":{},\"total_functions\":{},\"total_classes\":{},\"total_seams\":{},\"s3_locked_seams\":{},\"unguarded_s0_seams\":{},\"elapsed_ms\":{:.3},\"verdict\":\"{}\",\"files\":[{}]}}",
                    rep.unguarded_s0_seams == 0,
                    VERSION,
                    json_escape(&rep.target),
                    rep.files_scanned,
                    rep.total_functions,
                    rep.total_classes,
                    rep.total_seams,
                    rep.s3_locked_seams,
                    rep.unguarded_s0_seams,
                    rep.elapsed_ms,
                    rep.verdict,
                    file_objs.join(",")
                );
            }
            if rep.unguarded_s0_seams > 0 {
                process::exit(1);
            }
        }
        "memories-verify" => {
            let mut workspace = ".".to_string();
            let mut format = "json".to_string();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--format" => {
                        format = require_flag_value("--format", &mut i, &args);
                    }
                    arg if !arg.starts_with('-') => {
                        workspace = arg.to_string();
                    }
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            let _ = format;
            let rep = verify_memories_readonly(Path::new(&workspace));
            println!(
                "{{\"ok\":{},\"read_only_enforced\":{},\"engine\":\"kintsugi-rs\",\"engine_version\":\"{}\",\"workspace_root\":\"{}\",\"memories_index_exists\":{},\"memories_index_bytes\":{},\"memories_index_fnv64\":\"{}\",\"lessons_count\":{},\"archive_files_count\":{},\"changelogs_count\":{},\"backups_dirs_count\":{},\"symlinks_detected\":{},\"empty_or_corrupt_files\":{},\"elapsed_ms\":{:.3},\"status\":\"{}\"}}",
                rep.ok,
                rep.read_only_enforced,
                VERSION,
                json_escape(&rep.workspace_root),
                rep.memories_index_exists,
                rep.memories_index_bytes,
                json_escape(&rep.memories_index_fnv64),
                rep.lessons_count,
                rep.archive_files_count,
                rep.changelogs_count,
                rep.backups_dirs_count,
                rep.symlinks_detected,
                rep.empty_or_corrupt_files,
                rep.elapsed_ms,
                rep.status
            );
            if !rep.ok {
                process::exit(1);
            }
        }
        "creed" => {
            println!("{}", render_creed_json());
        }
        "swarm-plan" => {
            let task_desc = if args.len() > 1 {
                args[1..].join(" ")
            } else {
                "multi-workstream task".to_string()
            };
            println!("{}", render_swarm_plan_json(&task_desc));
        }
        "step-audit" => {
            let mut target = ".".to_string();
            let mut max_sessions: usize = 25;
            let mut sub_cap: usize = 12;
            let mut task_cap: usize = 25;
            let mut wire_only = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--max-sessions" => {
                        let v = require_flag_value("--max-sessions", &mut i, &args);
                        max_sessions = v.parse::<usize>().unwrap_or(25).max(1);
                    }
                    "--sub-cap" => {
                        let v = require_flag_value("--sub-cap", &mut i, &args);
                        sub_cap = v.parse::<usize>().unwrap_or(12).max(1);
                    }
                    "--task-cap" => {
                        let v = require_flag_value("--task-cap", &mut i, &args);
                        task_cap = v.parse::<usize>().unwrap_or(25).max(1);
                    }
                    "--wire" => {
                        wire_only = true;
                    }
                    arg if !arg.starts_with('-') => {
                        target = arg.to_string();
                    }
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            let rep = audit_step_economics_path(Path::new(&target), max_sessions, sub_cap, task_cap, 60.0);
            if wire_only {
                println!("{}", rep.wire);
            } else {
                println!("{}", render_step_audit_json(&rep));
            }
            if !rep.ok {
                process::exit(1);
            }
        }
        "hook" => {
            let mut block_on = Severity::High;
            let mut workspace: Option<String> = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--block-on" => {
                        let v = require_flag_value("--block-on", &mut i, &args);
                        block_on = Severity::from_str(&v);
                    }
                    "--workspace" => {
                        workspace = Some(require_flag_value("--workspace", &mut i, &args));
                    }
                    "claude-pre-tool" => {}
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            let mut stdin_buf = String::new();
            let _ = io::stdin().read_to_string(&mut stdin_buf);
            let decision = evaluate_pre_tool_json_with_workspace(
                &stdin_buf,
                block_on,
                workspace.as_deref().map(Path::new),
            );
            println!("{decision}");
        }
        "kml" => {
            let kml_path = if args.len() > 1 {
                args[1].clone()
            } else {
                ".kintsugi/scars.kml".to_string()
            };
            match inspect_kml_corpus_file(Path::new(&kml_path)) {
                Ok(rep) => {
                    println!(
                        "{{\"engine\":\"kintsugi-rs\",\"protocol\":\"@KML/1.0\",\"path\":\"{}\",\"total_records\":{},\"verified_records\":{},\"quarantined_records\":{},\"elapsed_us\":{},\"elapsed_ms\":{:.3},\"kml_bytes\":{},\"estimated_tokens\":{},\"allowed_egress_repo\":\"{}\"}}",
                        json_escape(&kml_path),
                        rep.total_records,
                        rep.verified_records,
                        rep.quarantined_records,
                        rep.elapsed_micros,
                        (rep.elapsed_micros as f64) / 1000.0,
                        rep.kml_bytes,
                        rep.estimated_tokens,
                        ALLOWED_PUBLIC_EVOLUTION_REPO
                    );
                    if rep.quarantined_records > 0 {
                        process::exit(1);
                    }
                }
                Err(err) => {
                    eprintln!("{{\"error\":\"{}\"}}", json_escape(&err));
                    process::exit(1);
                }
            }
        }
        "compress" => {
            if args.iter().any(|a| a == "--kml") {
                print!("{}", render_kml_builtin_corpus());
            } else {
                println!("{}", render_kmi_compact_header());
            }
        }
        "bench" => {
            let sample_code = "\
import os, subprocess, requests
def fetch_data(url: str) -> str:
    resp = requests.get(url, timeout=10)
    return resp.text
";
            let iterations = 200u32;
            let t0 = Instant::now();
            for _ in 0..iterations {
                let _ = scan_text(sample_code, "bench.py", "python", Severity::Low, None);
            }
            let total_us = t0.elapsed().as_micros();
            let avg_us = (total_us as f64) / (iterations as f64);

            let tb = compute_token_benchmark();
            let kml_info = inspect_kml_corpus_file(Path::new(".kintsugi/scars.kml")).ok();
            let egress_ok = verify_outbound_destination_allowed(
                "https://github.com/tunguyen1993/kintsugi-harness.git",
            );
            println!(
                "=== Kintsugi-RS v{VERSION} Native @KML/1 Performance & Token Benchmark ===\n\
                 • Active Builtin Rules          : {}\n\
                 • Native Rust Scan Latency      : {:.2} µs/call ({:.4} ms) over {} iterations\n\
                 • Verbose Markdown Context      : ~{} tokens/turn (standard harnesses)\n\
                 • Kintsugi KMI/1 Wire Index     : ~{} tokens/turn\n\
                 • Per-Turn Token Reduction      : {:.1}%\n\
                 • Tokens Saved per 50-Turn Run  : ~{} tokens\n\
                 • Outbound Egress Whitelist     : {} (verified={})",
                BUILTIN_RULES.len(),
                avg_us,
                avg_us / 1000.0,
                iterations,
                tb.verbose_tokens,
                tb.kmi_tokens,
                tb.reduction_pct,
                tb.saved_tokens_50_turns,
                ALLOWED_PUBLIC_EVOLUTION_REPO,
                egress_ok
            );
            if let Some(krep) = kml_info {
                println!(
                    " • @KML/1 Corpus (.kintsugi/scars.kml) : {} verified records parsed & shielded in {} µs ({:.3} ms)",
                    krep.verified_records,
                    krep.elapsed_micros,
                    (krep.elapsed_micros as f64) / 1000.0
                );
            }
        }
        "rule-ir-check" => {
            let mut src_arg = "-".to_string();
            let mut strict_hash = false;
            for a in args.iter().skip(1) {
                if a == "-" {
                    src_arg = "-".to_string();
                } else if a == "--strict-hash" {
                    strict_hash = true;
                } else if !a.starts_with('-') {
                    src_arg = a.clone();
                } else {
                    reject_unknown_flag(a);
                }
            }
            let raw = if src_arg == "-" {
                let mut buf = String::new();
                let _ = io::stdin().read_to_string(&mut buf);
                buf
            } else {
                match std::fs::read_to_string(&src_arg) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string()));
                        process::exit(1);
                    }
                }
            };
            let res = if strict_hash {
                validate_rule_ir_json_strict(&raw)
            } else {
                validate_rule_ir_json(&raw)
            };
            match res {
                Ok(out) => println!("{out}"),
                Err(err) => {
                    eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&err));
                    process::exit(1);
                }
            }
        }
        "rule-ir-eval" => {
            let mut rule_arg: Option<String> = None;
            let mut code_arg = "-".to_string();
            let mut lang = "python".to_string();
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--rule" => {
                        rule_arg = Some(require_flag_value("--rule", &mut i, &args));
                    }
                    "--lang" => {
                        lang = require_flag_value("--lang", &mut i, &args);
                    }
                    "-" => code_arg = "-".to_string(),
                    arg if !arg.starts_with('-') => code_arg = arg.to_string(),
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            let Some(rule_src) = rule_arg else {
                eprintln!("Error: Missing required option '--rule'");
                process::exit(2);
            };
            let rule_raw = if rule_src == "-" {
                let mut buf = String::new();
                let _ = io::stdin().read_to_string(&mut buf);
                buf
            } else {
                match std::fs::read_to_string(&rule_src) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string()));
                        process::exit(1);
                    }
                }
            };
            let code_raw = if code_arg == "-" {
                let mut buf = String::new();
                let _ = io::stdin().read_to_string(&mut buf);
                buf
            } else {
                match std::fs::read_to_string(&code_arg) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string()));
                        process::exit(1);
                    }
                }
            };
            match evaluate_rule_ir_json(&rule_raw, &code_raw, &lang) {
                Ok(out) => println!("{out}"),
                Err(err) => {
                    eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&err));
                    process::exit(1);
                }
            }
        }
        "scan-bytes" => {
            let mut src_arg = "-".to_string();
            let mut delim: u8 = b'\n';
            let mut pattern: Option<Vec<u8>> = None;
            let mut disable_simd = false;
            let mut normalize = false;
            let mut format = "json".to_string();
            let mut after_double_dash = false;

            let mut i = 1;
            while i < args.len() {
                if after_double_dash {
                    src_arg = args[i].clone();
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "--" => after_double_dash = true,
                    "--delim" => {
                        let v = require_flag_value("--delim", &mut i, &args);
                        match parse_delim_byte(&v) {
                            Ok(b) => delim = b,
                            Err(err) => {
                                eprintln!("Error: {err}");
                                process::exit(2);
                            }
                        }
                    }
                    "--pattern" => {
                        let v = require_flag_value("--pattern", &mut i, &args);
                        pattern = Some(v.into_bytes());
                    }
                    "--pattern-hex" => {
                        let v = require_flag_value("--pattern-hex", &mut i, &args);
                        match decode_hex_bytes(&v) {
                            Ok(bytes) => pattern = Some(bytes),
                            Err(err) => {
                                eprintln!("Error: {err}");
                                process::exit(2);
                            }
                        }
                    }
                    "--disable-simd" => disable_simd = true,
                    "--normalize" => normalize = true,
                    "--format" => {
                        format = require_flag_value("--format", &mut i, &args);
                        if format != "json" && format != "offsets" {
                            eprintln!("Error: Unsupported --format '{format}' (expected json or offsets)");
                            process::exit(2);
                        }
                    }
                    "-" => src_arg = "-".to_string(),
                    arg if !arg.starts_with('-') => src_arg = arg.to_string(),
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }

            let raw_bytes = if src_arg == "-" {
                let mut buf = Vec::new();
                if let Err(e) = io::stdin().read_to_end(&mut buf) {
                    eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string()));
                    process::exit(1);
                }
                buf
            } else {
                match std::fs::read(&src_arg) {
                    Ok(buf) => buf,
                    Err(e) => {
                        eprintln!("{{\"ok\":false,\"error\":\"{}\"}}", json_escape(&e.to_string()));
                        process::exit(1);
                    }
                }
            };

            let t0 = Instant::now();
            let backend = active_simd_backend(disable_simd);
            let offsets = if let Some(ref pat) = pattern {
                scan_multibyte_delimiters(&raw_bytes, pat, disable_simd)
            } else {
                scan_delimiters(&raw_bytes, delim, disable_simd)
            };
            let elapsed_us = (t0.elapsed().as_nanos() as f64) / 1000.0;

            if format == "offsets" {
                for off in &offsets {
                    println!("{off}");
                }
            } else {
                let off_str: Vec<String> = offsets.iter().map(|o| o.to_string()).collect();
                let events_json = if normalize && pattern.is_none() {
                    let evs = normalize_log_records(&raw_bytes, delim, disable_simd);
                    let strs: Vec<String> = evs.iter().map(|e| e.to_json()).collect();
                    format!(",\"events\":[{}]", strs.join(","))
                } else {
                    String::new()
                };
                println!(
                    "{{\"ok\":true,\"schema_version\":\"1.0\",\"tool\":\"LogForge\",\"backend\":\"{}\",\"disable_simd\":{},\"delim\":{},\"multibyte_pattern_len\":{},\"input_bytes\":{},\"delimiter_count\":{},\"elapsed_us\":{:.3},\"offsets\":[{}]{}}}",
                    backend,
                    disable_simd,
                    delim,
                    pattern.as_ref().map(|p| p.len()).unwrap_or(1),
                    raw_bytes.len(),
                    offsets.len(),
                    elapsed_us,
                    off_str.join(","),
                    events_json,
                );
            }
        }
        "logforge-bench" => {
            let mut size_bytes: usize = 1_048_576;
            let mut warmup: usize = 10;
            let mut iters: usize = 50;
            let mut seed: u64 = 20_261_121;
            let mut delim: u8 = b'\n';

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--size-bytes" => {
                        let v = require_flag_value("--size-bytes", &mut i, &args);
                        size_bytes = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --size-bytes '{v}'");
                            process::exit(2);
                        });
                    }
                    "--warmup" => {
                        let v = require_flag_value("--warmup", &mut i, &args);
                        warmup = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --warmup '{v}'");
                            process::exit(2);
                        });
                    }
                    "--iters" => {
                        let v = require_flag_value("--iters", &mut i, &args);
                        iters = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --iters '{v}'");
                            process::exit(2);
                        }).max(1);
                    }
                    "--seed" => {
                        let v = require_flag_value("--seed", &mut i, &args);
                        seed = v.parse::<u64>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --seed '{v}'");
                            process::exit(2);
                        });
                    }
                    "--delim" => {
                        let v = require_flag_value("--delim", &mut i, &args);
                        match parse_delim_byte(&v) {
                            Ok(b) => delim = b,
                            Err(err) => {
                                eprintln!("Error: {err}");
                                process::exit(2);
                            }
                        }
                    }
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }

            let rep = run_logforge_benchmark(size_bytes, warmup, iters, seed, delim);
            println!("{}", render_bench_report_json(&rep));
            if !rep.parity_ok {
                process::exit(1);
            }
        }
        "sha256-bench" => {
            let mut size_bytes: usize = 1_048_576;
            let mut warmup: usize = 10;
            let mut iters: usize = 50;
            let mut seed: u64 = 20_261_121;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--size-bytes" => {
                        let v = require_flag_value("--size-bytes", &mut i, &args);
                        size_bytes = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --size-bytes '{v}'");
                            process::exit(2);
                        });
                    }
                    "--warmup" => {
                        let v = require_flag_value("--warmup", &mut i, &args);
                        warmup = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --warmup '{v}'");
                            process::exit(2);
                        });
                    }
                    "--iters" => {
                        let v = require_flag_value("--iters", &mut i, &args);
                        iters = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --iters '{v}'");
                            process::exit(2);
                        }).max(1);
                    }
                    "--seed" => {
                        let v = require_flag_value("--seed", &mut i, &args);
                        seed = v.parse::<u64>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --seed '{v}'");
                            process::exit(2);
                        });
                    }
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            let rep = run_sha256_benchmark(size_bytes, warmup, iters, seed);
            println!(
                "{{\"schema_version\":\"1.0\",\"tool\":\"KintsugiSHA256\",\"arch\":\"{}\",\"os\":\"{}\",\"size_bytes\":{},\"warmup\":{},\"iters\":{},\"seed\":{},\"parity_ok\":{},\"digest_hex\":\"{}\",\"speedup_hw_vs_scalar\":{:.3},\"hw\":{{\"backend\":\"{}\",\"min_us\":{:.3},\"median_us\":{:.3},\"p95_us\":{:.3},\"mean_us\":{:.3},\"throughput_gbps\":{:.4}}},\"scalar\":{{\"backend\":\"{}\",\"min_us\":{:.3},\"median_us\":{:.3},\"p95_us\":{:.3},\"mean_us\":{:.3},\"throughput_gbps\":{:.4}}}}}",
                std::env::consts::ARCH,
                std::env::consts::OS,
                rep.size_bytes,
                rep.warmup,
                rep.iters,
                seed,
                rep.parity_ok,
                rep.digest_hex,
                rep.speedup_hw_vs_scalar,
                rep.hw.backend,
                rep.hw.min_us,
                rep.hw.median_us,
                rep.hw.p95_us,
                rep.hw.mean_us,
                rep.hw.throughput_gbps,
                rep.scalar.backend,
                rep.scalar.min_us,
                rep.scalar.median_us,
                rep.scalar.p95_us,
                rep.scalar.mean_us,
                rep.scalar.throughput_gbps,
            );
            if !rep.parity_ok {
                process::exit(1);
            }
        }
        "scan-bench" => {
            let mut target = "src".to_string();
            let mut warmup: usize = 3;
            let mut iters: usize = 10;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--warmup" => {
                        let v = require_flag_value("--warmup", &mut i, &args);
                        warmup = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --warmup '{v}'");
                            process::exit(2);
                        });
                    }
                    "--iters" => {
                        let v = require_flag_value("--iters", &mut i, &args);
                        iters = v.parse::<usize>().unwrap_or_else(|_| {
                            eprintln!("Error: Invalid --iters '{v}'");
                            process::exit(2);
                        }).max(1);
                    }
                    arg if !arg.starts_with('-') => target = arg.to_string(),
                    arg => reject_unknown_flag(arg),
                }
                i += 1;
            }
            let target_path = Path::new(&target);
            for _ in 0..warmup {
                let _ = scan_path(target_path, Severity::Low);
            }
            let mut scan_ms_samples = Vec::with_capacity(iters);
            let mut last_sum = None;
            for _ in 0..iters {
                let sum = scan_path(target_path, Severity::Low);
                scan_ms_samples.push((sum.elapsed_micros as f64) / 1000.0);
                last_sum = Some(sum);
            }
            scan_ms_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let n = scan_ms_samples.len();
            let scan_min_ms = scan_ms_samples[0];
            let scan_median_ms = if n % 2 == 1 {
                scan_ms_samples[n / 2]
            } else {
                0.5 * (scan_ms_samples[n / 2 - 1] + scan_ms_samples[n / 2])
            };
            let scan_mean_ms = scan_ms_samples.iter().sum::<f64>() / (n as f64);

            // Benchmark RulePrefilter on concatenated corpus + KML 1797+ literals
            let mut concat_buf = Vec::new();
            let mut stack = vec![target_path.to_path_buf()];
            while let Some(p) = stack.pop() {
                if let Ok(md) = std::fs::symlink_metadata(&p) {
                    if md.file_type().is_symlink() {
                        continue;
                    }
                    if md.is_dir() {
                        if let Ok(rd) = std::fs::read_dir(&p) {
                            for e in rd.flatten() {
                                stack.push(e.path());
                            }
                        }
                    } else if md.is_file() && p.extension().and_then(|s| s.to_str()) == Some("py") {
                        if let Ok(bytes) = std::fs::read(&p) {
                            concat_buf.extend_from_slice(&bytes);
                            concat_buf.push(b'\n');
                        }
                    }
                }
            }
            let pf_36 = builtin_rule_prefilter();
            let t_pf0 = Instant::now();
            let mut mask_neon = 0u64;
            for _ in 0..20 {
                mask_neon = pf_36.candidate_mask_u64(&concat_buf, false);
            }
            let pf36_neon_us = (t_pf0.elapsed().as_nanos() as f64) / 1000.0 / 20.0;

            let t_pf1 = Instant::now();
            let mut mask_scalar = 0u64;
            for _ in 0..20 {
                mask_scalar = pf_36.candidate_mask_u64(&concat_buf, true);
            }
            let pf36_scalar_us = (t_pf1.elapsed().as_nanos() as f64) / 1000.0 / 20.0;

            let mut kml_records_count = 0usize;
            let mut kml_neon_us = 0.0f64;
            let mut kml_scalar_us = 0.0f64;
            let mut kml_oracle_parity = true;
            if let Ok(kml_text) = std::fs::read_to_string(".kintsugi/scars.kml") {
                let recs = parse_kml_corpus(&kml_text);
                kml_records_count = recs.len();
                let mut specs = Vec::new();
                let mut always = Vec::new();
                for (ri, r) in recs.iter().enumerate() {
                    if r.neg.is_empty() {
                        always.push(ri);
                    } else {
                        specs.push(kintsugi_core::kernels::LiteralSpec {
                            rule_index: ri,
                            pattern: r.neg.as_bytes().to_vec(),
                            case_insensitive: false,
                        });
                    }
                }
                let kml_pf = kintsugi_core::kernels::RulePrefilter::new(recs.len(), &specs, &always);
                let tk0 = Instant::now();
                let mut k_neon = Vec::new();
                for _ in 0..10 {
                    k_neon = kml_pf.candidate_rule_indices(&concat_buf, false);
                }
                kml_neon_us = (tk0.elapsed().as_nanos() as f64) / 1000.0 / 10.0;
                let tk1 = Instant::now();
                let mut k_sc = Vec::new();
                for _ in 0..10 {
                    k_sc = kml_pf.candidate_rule_indices(&concat_buf, true);
                }
                kml_scalar_us = (tk1.elapsed().as_nanos() as f64) / 1000.0 / 10.0;
                let k_ora = kml_pf.scalar_oracle_rule_indices(&concat_buf);
                kml_oracle_parity = k_neon == k_sc && k_neon == k_ora;
            }

            let sum = last_sum.unwrap();
            println!(
                "{{\"schema_version\":\"1.0\",\"tool\":\"KintsugiScanBench\",\"target\":\"{}\",\"backend\":\"{}\",\"scanned_files\":{},\"corpus_bytes\":{},\"active_rules\":{},\"findings_count\":{},\"warmup\":{},\"iters\":{},\"scan_min_ms\":{:.3},\"scan_median_ms\":{:.3},\"scan_mean_ms\":{:.3},\"prefilter_36_parity_ok\":{},\"prefilter_36_neon_us\":{:.3},\"prefilter_36_scalar_us\":{:.3},\"kml_records\":{},\"kml_prefilter_parity_ok\":{},\"kml_prefilter_neon_us\":{:.3},\"kml_prefilter_scalar_us\":{:.3}}}",
                json_escape(&target),
                active_prefilter_backend(false),
                sum.scanned_files,
                concat_buf.len(),
                sum.active_rules,
                sum.findings.len(),
                warmup,
                iters,
                scan_min_ms,
                scan_median_ms,
                scan_mean_ms,
                mask_neon == mask_scalar,
                pf36_neon_us,
                pf36_scalar_us,
                kml_records_count,
                kml_oracle_parity,
                kml_neon_us,
                kml_scalar_us,
            );
        }
        _ => {
            print_help();
            process::exit(1);
        }
    }
}
