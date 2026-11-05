//! `kintsugi-rs` — Native Rust CLI for sub-millisecond PreToolUse hooks,
//! git-diff scanning, and `KMI/1` Ultra-Low-Token compression.

use std::env;
use std::io::{self, Read};
use std::path::Path;
use std::process;
use std::time::Instant;

use kintsugi_core::{
    compute_token_benchmark, evaluate_pre_tool_json, json_escape, render_kmi_compact_header,
    scan_git_staged, scan_path, scan_text, Severity, BUILTIN_RULES,
};

const VERSION: &str = "0.3.0";

fn print_help() {
    println!(
        "kintsugi-rs {VERSION} — Native Rust Guardrail Engine & KMI/1 Token Compressor\n\
         \n\
         USAGE:\n\
         \x20 kintsugi-rs scan [PATH] [--staged] [--format text|json] [--fail-on HIGH]\n\
         \x20 kintsugi-rs hook claude-pre-tool [--block-on HIGH]\n\
         \x20 kintsugi-rs compress\n\
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
        "compress" => {
            println!("{}", render_kmi_compact_header());
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
            println!(
                "=== Kintsugi-RS v{VERSION} Native Performance & Token Benchmark ===\n\
                 • Active Guardrail Rules        : {}\n\
                 • Native Rust Scan Latency      : {:.2} µs/call ({:.4} ms) over {} iterations\n\
                 • Verbose Markdown Context      : ~{} tokens/turn (standard harnesses)\n\
                 • Kintsugi KMI/1 Wire Index     : ~{} tokens/turn\n\
                 • Per-Turn Token Reduction      : {:.1}%\n\
                 • Tokens Saved per 50-Turn Run  : ~{} tokens",
                BUILTIN_RULES.len(),
                avg_us,
                avg_us / 1000.0,
                iterations,
                tb.verbose_tokens,
                tb.kmi_tokens,
                tb.reduction_pct,
                tb.saved_tokens_50_turns
            );
        }
        _ => {
            print_help();
            process::exit(1);
        }
    }
}
