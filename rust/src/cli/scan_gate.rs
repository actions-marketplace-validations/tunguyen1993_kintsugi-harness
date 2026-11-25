//! `scan` and `gate` CLI subcommands with multi-target `--staged`, global dedup/cap,
//! feature-gated `sarif`, and `--gate-telemetry-json` (`rust/src/cli/scan_gate.rs`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

#[cfg(feature = "rule-ir")]
use kintsugi_core::dynamic_rules::DynamicRuleRegistry;
use kintsugi_core::io_json::{write_stdout_ln, write_stdout_str, JsonObj};
use kintsugi_core::model::{Finding, ScanSummary, Severity};
#[cfg(feature = "sarif")]
use kintsugi_core::output::render_findings_sarif;
use kintsugi_core::output::{
    render_findings_jsonl, render_gate_compact,
    render_gate_compact_detailed, render_scan_json,
};
use kintsugi_core::policy::find_enclosing_repo_root;
use kintsugi_core::scanner::{scan_git_staged_full, scan_path_full};
use kintsugi_core::{ARM_C_SHADOW_RULES, BUILTIN_RULES};

use super::{emit_cli_error_json, reject_unknown_flag, ArgCursor, CliToken};

#[cfg(feature = "rule-ir")]
type DynRules = DynamicRuleRegistry;
#[cfg(not(feature = "rule-ir"))]
type DynRules = ();

/// System diagnostic findings that must never be silently dropped by `--min-severity` filtering.
const SYSTEM_DIAGNOSTIC_SCAR_IDS: [&str; 5] = [
    "KS-SCAN-WORKER-FAILED",
    "KS-GIT-STAGED-FAILED",
    "KS-GIT-STAGED-BLOB-MISSING",
    "KS-SCAN-FILE-TOO-LARGE",
    "KS-SCAN-FINDINGS-TRUNCATED",
];

#[inline]
fn is_system_diagnostic(f: &Finding) -> bool {
    SYSTEM_DIAGNOSTIC_SCAR_IDS.contains(&f.scar_id.as_str())
}

fn load_dynamic_rules_or_exit(rules_dir: Option<&str>) -> Option<DynRules> {
    let path_str = rules_dir?;
    #[cfg(feature = "rule-ir")]
    {
        DynamicRuleRegistry::load_from_path(Path::new(path_str))
            .map(Some)
            .unwrap_or_else(|err| emit_cli_error_json("DYNAMIC_RULES_ERROR", &err, 2))
    }
    #[cfg(not(feature = "rule-ir"))]
    {
        let _ = path_str;
        emit_cli_error_json("FEATURE_DISABLED", "Option '--rules-dir' requires Cargo feature 'rule-ir'", 2)
    }
}

#[cfg(feature = "rule-ir")]
#[inline]
fn dyn_rules_len(reg: Option<&DynRules>) -> usize { reg.map(|d| d.len()).unwrap_or(0) }
#[cfg(not(feature = "rule-ir"))]
#[inline]
fn dyn_rules_len(_reg: Option<&DynRules>) -> usize { 0 }

fn emit_sarif_or_exit(findings: &[Finding]) {
    #[cfg(feature = "sarif")]
    write_stdout_ln(&render_findings_sarif(findings));
    #[cfg(not(feature = "sarif"))]
    {
        let _ = findings;
        emit_cli_error_json("FEATURE_DISABLED", "Output format 'sarif' requires Cargo feature 'sarif'", 2);
    }
}

fn run_multi_target_scan(
    targets: &[&str], staged: bool, min_sev: Severity, policy_file: Option<&str>,
    policy_sha256: Option<&str>, shadow_arm_c: bool, dyn_reg: Option<&DynRules>,
) -> ScanSummary {
    let wall_t0 = Instant::now();
    let active_rules = BUILTIN_RULES.len() + if shadow_arm_c { ARM_C_SHADOW_RULES.len() } else { 0 } + dyn_rules_len(dyn_reg);
    let mut total = ScanSummary { scanned_files: 0, active_rules, elapsed_micros: 0, findings: Vec::new() };

    if staged {
        let (mut seen_roots, mut staged_roots) = (BTreeSet::new(), Vec::with_capacity(targets.len()));
        for &t in targets {
            let p = Path::new(t);
            let root: PathBuf = std::fs::canonicalize(p).map(|c| find_enclosing_repo_root(&c)).unwrap_or_else(|_| p.to_path_buf());
            if seen_roots.insert(root.clone()) { staged_roots.push(root); }
        }
        for root in &staged_roots {
            let mut sub = scan_git_staged_full(root, min_sev, shadow_arm_c, dyn_reg);
            total.scanned_files += sub.scanned_files;
            total.active_rules = sub.active_rules;
            total.findings.append(&mut sub.findings);
        }
    } else {
        let pol_path = policy_file.map(Path::new);
        let mut seen_paths: BTreeSet<PathBuf> = BTreeSet::new();
        for &t in targets {
            let p = PathBuf::from(t);
            let canon = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
            if !seen_paths.insert(canon) { continue; }
            let mut sub = scan_path_full(&p, min_sev, pol_path, policy_sha256, shadow_arm_c, dyn_reg);
            total.scanned_files += sub.scanned_files;
            total.active_rules = sub.active_rules;
            total.findings.append(&mut sub.findings);
        }
    }

    kintsugi_core::scanner::enforce_findings_cap_idempotent(&mut total.findings, false, &targets.join(","));
    total.elapsed_micros = wall_t0.elapsed().as_micros();
    total
}

pub fn run_scan_cmd(args: &[String]) {
    let mut targets: Vec<&str> = Vec::new();
    let (mut staged, mut shadow_arm_c, mut gate_compact) = (false, false, false);
    let (mut format, mut min_sev, mut fail_on) = ("text", Severity::Low, Some(Severity::High));
    let (mut policy_file, mut policy_sha256, mut rules_dir) = (None, None, None);

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => targets.push(p),
            CliToken::Flag("--staged") => staged = true,
            CliToken::Flag("--shadow-arm-c") => shadow_arm_c = true,
            CliToken::Flag("--no-shadow-arm-c") => shadow_arm_c = false,
            CliToken::Flag("--gate-compact") => gate_compact = true,
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["text", "json", "jsonl", "sarif", "compact"]),
            CliToken::Flag("--rules-dir") => rules_dir = Some(cur.require_value("--rules-dir")),
            CliToken::Flag("--policy-file") => policy_file = Some(cur.require_value("--policy-file")),
            CliToken::Flag("--policy-sha256") => policy_sha256 = Some(cur.require_value("--policy-sha256")),
            CliToken::Flag("--min-severity") => min_sev = cur.parse_severity("--min-severity"),
            CliToken::Flag("--fail-on") => fail_on = cur.parse_fail_on("--fail-on"),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    if targets.is_empty() { targets.push("."); }

    let dyn_reg = load_dynamic_rules_or_exit(rules_dir);
    let dyn_count = dyn_rules_len(dyn_reg.as_ref());
    let summary = run_multi_target_scan(&targets, staged, min_sev, policy_file, policy_sha256, shadow_arm_c, dyn_reg.as_ref());

    if gate_compact {
        if summary.findings.is_empty() { return; }
        write_stdout_ln(&render_gate_compact(&summary.findings, 150));
        process::exit(1);
    }

    match format {
        "json" => write_stdout_ln(&render_scan_json(&summary, shadow_arm_c, dyn_count)),
        "jsonl" => { let jl = render_findings_jsonl(&summary.findings); if !jl.is_empty() { write_stdout_str(&jl); } }
        "sarif" => emit_sarif_or_exit(&summary.findings),
        "compact" => { if !summary.findings.is_empty() { write_stdout_ln(&render_gate_compact(&summary.findings, 150)); } }
        _ => {
            write_stdout_ln(&format!(
                "Kintsugi-RS Native Scan: {} file(s) checked against {} scars in {:.3}ms ({} µs)",
                summary.scanned_files, summary.active_rules, (summary.elapsed_micros as f64) / 1000.0, summary.elapsed_micros
            ));
            if summary.findings.is_empty() {
                write_stdout_ln("PASS: 0 anti-pattern violations found.");
            } else {
                for f in &summary.findings {
                    write_stdout_ln(&format!("  [{}] {} {}:{} — {}\n    Snippet : {}\n    Fix     : {}", f.severity.as_str(), f.scar_id, f.file_path, f.line, f.title, f.snippet, f.fix_hint));
                }
            }
        }
    }
    if fail_on.is_some_and(|thr| summary.findings.iter().any(|f| f.severity >= thr)) { process::exit(1); }
}

pub fn run_gate_cmd(args: &[String]) {
    let mut targets: Vec<&str> = Vec::new();
    let (mut staged, mut run_s3, mut strict_proven, mut shadow_arm_c, mut gate_telemetry_json) = (false, false, false, true, false);
    let (mut rules_dir, mut policy_file, mut policy_sha256) = (None, None, None);
    let (mut min_sev, mut fail_on, mut max_tokens, mut format) = (None, Some(Severity::High), 80usize, "compact");

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => targets.push(p),
            CliToken::Flag("--staged") => staged = true,
            CliToken::Flag("--s3") => run_s3 = true,
            CliToken::Flag("--strict-proven") => { run_s3 = true; strict_proven = true; }
            CliToken::Flag("--shadow-arm-c") => shadow_arm_c = true,
            CliToken::Flag("--no-shadow-arm-c") => shadow_arm_c = false,
            CliToken::Flag("--gate-telemetry-json") => gate_telemetry_json = true,
            CliToken::Flag("--rules-dir") => rules_dir = Some(cur.require_value("--rules-dir")),
            CliToken::Flag("--policy-file") => policy_file = Some(cur.require_value("--policy-file")),
            CliToken::Flag("--policy-sha256") => policy_sha256 = Some(cur.require_value("--policy-sha256")),
            CliToken::Flag("--min-severity") => min_sev = Some(cur.parse_severity("--min-severity")),
            CliToken::Flag("--fail-on") => fail_on = cur.parse_fail_on("--fail-on"),
            CliToken::Flag("--max-tokens") => {
                max_tokens = cur.parse_usize("--max-tokens");
                if max_tokens == 0 { emit_cli_error_json("INVALID_MAX_TOKENS", "--max-tokens must be > 0", 2); }
            }
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["compact", "json", "jsonl", "sarif"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    if targets.is_empty() { targets.push("."); }

    let dyn_reg = load_dynamic_rules_or_exit(rules_dir);
    let dyn_count = dyn_rules_len(dyn_reg.as_ref());
    let effective_min_sev = min_sev.unwrap_or_else(|| fail_on.unwrap_or(Severity::Low));
    let mut summary = run_multi_target_scan(&targets, staged, effective_min_sev, policy_file, policy_sha256, shadow_arm_c, dyn_reg.as_ref());

    if run_s3 && Severity::High >= effective_min_sev {
        #[cfg(feature = "audit")]
        {
            let mode_tag = if strict_proven { "strict-proven" } else { "standard" };
            for t in &targets {
                for f in kintsugi_core::audit::s3_audit_path_with_mode(Path::new(t), strict_proven).files {
                    if f.verdict != "PASS_S3_LOCKED" {
                        if !f.failing_seams.is_empty() {
                            for fs in f.failing_seams.iter().take(8) {
                                summary.findings.push(Finding {
                                    scar_id: "KS-S3-SEAM".to_string(),
                                    title: format!(
                                        "@CT2 Grade-S3 {} ({}): {}",
                                        fs.seam_kind, fs.tier, fs.reason
                                    ),
                                    severity: if fs.tier == "S0_EXPOSED" { Severity::Critical } else { Severity::High },
                                    category: "s3-seam".to_string(),
                                    file_path: f.file_path.clone(),
                                    line: fs.seam_line,
                                    column: 1,
                                    snippet: format!("tier={} seam={}", fs.tier, fs.seam_kind),
                                    fix_hint: fs.fix_hint.to_string(),
                                });
                            }
                        } else {
                            let (s0, unp) = (f.unguarded_s0_seams, f.unproven_seams);
                            summary.findings.push(Finding {
                                scar_id: "KS-S3-SEAM".to_string(),
                                title: format!("@CT2 Grade-S3 seam audit ({mode_tag}): {s0} S0 exposed, {unp} unproven seam(s)"),
                                severity: Severity::High, category: "s3-seam".to_string(), file_path: f.file_path, line: 1, column: 1,
                                snippet: format!("proven={}/{} unproven={unp} unguarded_s0={s0} verdict={}", f.proven_s3_seams, f.total_seams, f.verdict),
                                fix_hint: "Prove all seams with canonical S3 parameterization/confinement locks".to_string(),
                            });
                        }
                    }
                }
            }
        }
        #[cfg(not(feature = "audit"))]
        {
            let _ = strict_proven;
            emit_cli_error_json("FEATURE_DISABLED", "Options '--s3' / '--strict-proven' require Cargo feature 'audit'", 2);
        }
    }

    summary.findings.retain(|f| f.severity >= effective_min_sev || is_system_diagnostic(f));
    kintsugi_core::scanner::enforce_findings_cap_idempotent(&mut summary.findings, false, &targets.join(","));
    let has_blocking = fail_on.is_some_and(|thr| summary.findings.iter().any(|f| f.severity >= thr));

    if gate_telemetry_json {
        if !summary.findings.is_empty() {
            let det = render_gate_compact_detailed(&summary.findings, max_tokens);
            write_stdout_ln(&JsonObj::with_capacity(det.text.len() + 128)
                .usize("kept_findings", det.kept_findings).usize("omitted_findings", det.omitted_findings)
                .usize("estimated_tokens", det.estimated_tokens).str("compact", &det.text).finish());
        }
    } else {
        match (summary.findings.is_empty(), format) {
            (_, "json") => write_stdout_ln(&render_scan_json(&summary, shadow_arm_c, dyn_count)),
            (_, "sarif") => emit_sarif_or_exit(&summary.findings),
            (false, "compact") => write_stdout_ln(&render_gate_compact(&summary.findings, max_tokens)),
            (false, "jsonl") => write_stdout_str(&render_findings_jsonl(&summary.findings)),
            _ => {}
        }
    }
    if has_blocking { process::exit(1); }
}
