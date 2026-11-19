//! `kintsugi-rs` v2.4.0 — Native Rust CLI for sub-millisecond PreToolUse hooks,
//! Grade S3 `@CT2` Seam Auditing, Read-Only Memory Integrity Verification,
//! git-diff scanning, and `KMI/1` Ultra-Low-Token compression.

use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process;
use std::time::Instant;

use kintsugi_core::{
    audit_step_economics_path, compute_token_benchmark, evaluate_pre_tool_json,
    inspect_kml_corpus_file, json_escape, render_creed_json, render_kmi_compact_header,
    render_kml_builtin_corpus, render_step_audit_json, render_swarm_plan_json, s3_audit_path,
    scan_git_staged, scan_path, scan_text, verify_memories_readonly,
    verify_outbound_destination_allowed, Severity, ALLOWED_PUBLIC_EVOLUTION_REPO, BUILTIN_RULES,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!(
        "kintsugi-rs {VERSION} — Native Rust @KML/1 & Grade-S3 Guardrail Engine\n\
         \n\
         USAGE:\n\
         \x20 kintsugi-rs scan [PATH] [--staged] [--format text|json] [--fail-on HIGH] [-- <PATH>]\n\
         \x20 kintsugi-rs s3-audit [PATH] [--format text|json] [-- <PATH>]\n\
         \x20 kintsugi-rs memories-verify [WORKSPACE_ROOT] [--format text|json]\n\
         \x20 kintsugi-rs creed\n\
         \x20 kintsugi-rs swarm-plan [TASK_DESC]\n\
         \x20 kintsugi-rs step-audit [PATH] [--max-sessions N] [--sub-cap 12] [--task-cap 25] [--wire]\n\
         \x20 kintsugi-rs hook claude-pre-tool [--block-on HIGH]\n\
         \x20 kintsugi-rs kml [PATH_TO_SCARS_KML]\n\
         \x20 kintsugi-rs compress [--kml]\n\
         \x20 kintsugi-rs bench\n\
         \x20 kintsugi-rs --version"
    );
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
            let mut target = ".".to_string();
            let mut staged = false;
            let mut format = "text".to_string();
            let mut min_sev = Severity::Low;
            let mut fail_on = Some(Severity::High);
            let mut after_double_dash = false;

            let mut i = 1;
            while i < args.len() {
                if after_double_dash {
                    target = args[i].clone();
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "--" => {
                        after_double_dash = true;
                    }
                    "--staged" => staged = true,
                    "--format" if i + 1 < args.len() => {
                        format = args[i + 1].clone();
                        i += 1;
                    }
                    "--min-severity" if i + 1 < args.len() => {
                        min_sev = Severity::from_str(&args[i + 1]);
                        i += 1;
                    }
                    "--fail-on" if i + 1 < args.len() => {
                        if args[i + 1].eq_ignore_ascii_case("NONE") {
                            fail_on = None;
                        } else {
                            fail_on = Some(Severity::from_str(&args[i + 1]));
                        }
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        target = arg.to_string();
                    }
                    _ => {}
                }
                i += 1;
            }

            let summary = if staged {
                scan_git_staged(Path::new(&target), min_sev)
            } else {
                scan_path(Path::new(&target), min_sev)
            };

            let ms = (summary.elapsed_micros as f64) / 1000.0;
            if format == "json" {
                let items: Vec<String> = summary
                    .findings
                    .iter()
                    .map(|f| {
                        format!(
                            "{{\"scar_id\":\"{}\",\"severity\":\"{}\",\"category\":\"{}\",\"file_path\":\"{}\",\"line\":{},\"column\":{},\"title\":\"{}\",\"snippet\":\"{}\",\"good_code_hint\":\"{}\"}}",
                            json_escape(&f.scar_id),
                            f.severity.as_str(),
                            json_escape(&f.category),
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
                    "{{\"schema_version\":\"2.4.0\",\"engine\":\"kintsugi-rs\",\"engine_version\":\"{}\",\"scanned_files\":{},\"active_scars\":{},\"elapsed_ms\":{:.3},\"findings\":[{}]}}",
                    VERSION,
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
            let mut target = ".".to_string();
            let mut format = "json".to_string();
            let mut after_double_dash = false;
            let mut i = 1;
            while i < args.len() {
                if after_double_dash {
                    target = args[i].clone();
                    i += 1;
                    continue;
                }
                match args[i].as_str() {
                    "--" => after_double_dash = true,
                    "--format" if i + 1 < args.len() => {
                        format = args[i + 1].clone();
                        i += 1;
                    }
                    arg if !arg.starts_with('-') => {
                        target = arg.to_string();
                    }
                    _ => {}
                }
                i += 1;
            }
            let rep = s3_audit_path(Path::new(&target));
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
            let mut i = 1;
            while i < args.len() {
                if !args[i].starts_with('-') {
                    workspace = args[i].clone();
                }
                i += 1;
            }
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
                    "--max-sessions" if i + 1 < args.len() => {
                        max_sessions = args[i + 1].parse::<usize>().unwrap_or(25).max(1);
                        i += 1;
                    }
                    "--sub-cap" if i + 1 < args.len() => {
                        sub_cap = args[i + 1].parse::<usize>().unwrap_or(12).max(1);
                        i += 1;
                    }
                    "--task-cap" if i + 1 < args.len() => {
                        task_cap = args[i + 1].parse::<usize>().unwrap_or(25).max(1);
                        i += 1;
                    }
                    "--wire" => {
                        wire_only = true;
                    }
                    arg if !arg.starts_with('-') => {
                        target = arg.to_string();
                    }
                    _ => {}
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
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--block-on" && i + 1 < args.len() {
                    block_on = Severity::from_str(&args[i + 1]);
                    i += 1;
                }
                i += 1;
            }
            let mut stdin_buf = String::new();
            let _ = io::stdin().read_to_string(&mut stdin_buf);
            let decision = evaluate_pre_tool_json(&stdin_buf, block_on);
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
        _ => {
            print_help();
            process::exit(1);
        }
    }
}
