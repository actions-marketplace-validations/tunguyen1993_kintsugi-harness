//! `kintsugi-rs` — Native Rust CLI for sub-millisecond PreToolUse hooks,
//! git-diff scanning, and `KMI/1` Ultra-Low-Token compression.

use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process;
use std::time::Instant;

use kintsugi_core::{
    compute_token_benchmark, evaluate_pre_tool_json, inspect_kml_corpus_file, json_escape,
    render_kmi_compact_header, render_kml_builtin_corpus, scan_git_staged, scan_path, scan_text,
    verify_outbound_destination_allowed, Severity, ALLOWED_PUBLIC_EVOLUTION_REPO, BUILTIN_RULES,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn print_help() {
    println!(
        "kintsugi-rs {VERSION} — Native Rust @KML/1 Machine-Language Guardrail Engine\n\
         \n\
         USAGE:\n\
         \x20 kintsugi-rs scan [PATH] [--staged] [--format text|json] [--fail-on HIGH]\n\
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

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
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
                    "{{\"engine\":\"kintsugi-rs\",\"scanned_files\":{},\"active_scars\":{},\"elapsed_ms\":{:.3},\"findings\":[{}]}}",
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
