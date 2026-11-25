//! High-throughput bounded buffer, directory, and git-staged scanner with conservative SIMD
//! prefiltering, panic-isolated multi-core work-stealing, and strict staged-index blob verification.

use std::{
    collections::{BTreeMap, BTreeSet}, env, fs,
    io::{self, BufRead, BufReader, Read, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use crate::io_json::read_regular_file_fd_verified;
use crate::kernels::rule_prefilter::{
    builtin_rule_prefilter, pi_flags_can_trigger, pi_keyword_prefilter, pi_line_flags,
};
use crate::model::{Finding, ScanSummary, Severity};
use crate::output::deduplicate_findings;
use crate::parsers::scan_arm_c_shadow_text_with_options;
use crate::policy::load_trusted_policy_files_explicit_sha;
use crate::rules::{
    builtin::{ALIAS_CALL_RULE_MASK, IDX_KS_013, IDX_KS_014, IDX_KS_019, IDX_KS_029, IDX_KS_S3_03},
    check_ks013_with_lines, check_line_against_rule_lang_with_ctx,
    check_line_against_rule_with_aliases, contains_bidi_control_at_line,
    contains_prompt_injection_text, detect_language, is_fixture_definition_line, line_ignores_rule,
    FileAliasMap, ARM_C_SHADOW_RULES, BUILTIN_RULES,
};

/// Optional dynamic `RuleIR/1` registry reference when `feature = "rule-ir"` is enabled.
#[cfg(feature = "rule-ir")]
pub type OptDynRules<'a> = Option<&'a crate::dynamic_rules::DynamicRuleRegistry>;
/// Zero-sized placeholder when `feature = "rule-ir"` is disabled (`--no-default-features`).
#[cfg(not(feature = "rule-ir"))]
pub type OptDynRules<'a> = Option<&'a ()>;

/// Maximum source file size (`8 MiB`) read into memory during directory/staged scans.
pub const MAX_SOURCE_FILE_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum changed lines expanded per git diff hunk (`100,000`) to prevent crafted-diff DoS.
pub const MAX_DIFF_HUNK_LINES: usize = 100_000;
/// Hard ceiling on findings returned per repository or bounded buffer scan (`10,000`).
pub const MAX_REPO_FINDINGS: usize = 10_000;

const WORK_CHUNK_SIZE: usize = 16;
const MAX_STITCH_CONTINUATION_LINES: usize = 32;
const MAX_STITCH_BUFFER_BYTES: usize = 4_096;
const MAX_GIT_STDERR_BYTES: u64 = 64 * 1024;

const fn builtin_rule_idx(target_id: &str) -> usize {
    let (tb, mut i) = (target_id.as_bytes(), 0);
    while i < BUILTIN_RULES.len() {
        let rb = BUILTIN_RULES[i].id.as_bytes();
        if rb.len() == tb.len() {
            let mut k = 0;
            while k < tb.len() && rb[k] == tb[k] { k += 1; }
            if k == tb.len() { return i; }
        }
        i += 1;
    }
    panic!("Missing BUILTIN_RULES id")
}

const IDX_KS_009: usize = builtin_rule_idx("KS-009");
const IDX_KS_026: usize = builtin_rule_idx("KS-026");
const IDX_KS_030: usize = builtin_rule_idx("KS-030");
const IDX_KS_S3_01: usize = builtin_rule_idx("KS-S3-01");

const _: () = {
    assert!(IDX_KS_013 == builtin_rule_idx("KS-013") && IDX_KS_014 == builtin_rule_idx("KS-014"));
    assert!(IDX_KS_019 == builtin_rule_idx("KS-019") && IDX_KS_029 == builtin_rule_idx("KS-029"));
    assert!(IDX_KS_S3_03 == builtin_rule_idx("KS-S3-03"));
};

fn has_file_ignore_header(content: &str) -> bool {
    let tag = concat!("kintsugi", ":ignore-file");
    content.lines().take(8).any(|header_line| {
        let s = header_line.trim_start_matches('\u{feff}').trim_start();
        if !(s.starts_with('#') || s.starts_with("//") || s.starts_with("/*")) {
            return false;
        }
        let compact: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        compact.to_ascii_lowercase().contains(tag)
    })
}

pub fn scan_text(content: &str, file_path: &str, lang: &str, min_severity: Severity, allowed_lines: Option<&BTreeSet<usize>>) -> Vec<Finding> {
    scan_text_with_policy(content, file_path, lang, min_severity, allowed_lines, true, false)
}

pub fn scan_text_with_options(
    content: &str, file_path: &str, lang: &str, min_severity: Severity, allowed_lines: Option<&BTreeSet<usize>>, allow_inline_ignores: bool,
) -> Vec<Finding> {
    scan_text_with_policy(content, file_path, lang, min_severity, allowed_lines, allow_inline_ignores, false)
}

pub fn scan_text_with_policy(
    content: &str, file_path: &str, lang: &str, min_severity: Severity,
    allowed_lines: Option<&BTreeSet<usize>>, allow_inline_ignores: bool, allow_file_ignores: bool,
) -> Vec<Finding> {
    scan_text_with_policy_impl(content, file_path, lang, min_severity, allowed_lines, allow_inline_ignores, allow_file_ignores, None, false, usize::MAX).0
}

/// Pure-buffer scanner with zero filesystem/network syscalls (fail-closed untrusted mode).
pub fn scan_text_buffer_no_fs(content: &str, file_path: &str, lang: &str, min_severity: Severity) -> Vec<Finding> {
    scan_text_with_policy_impl(content, file_path, lang, min_severity, None, false, false, None, true, usize::MAX).0
}

/// Pure-buffer bounded scanner for C-ABI FFI (`<ffi:buffer>`), stopping inner-loop allocation at `max_findings`.
pub fn scan_text_buffer_bounded(content: &str, language: &str, min_severity: Severity, max_findings: usize) -> (Vec<Finding>, bool) {
    scan_text_with_policy_impl(content, "<ffi:buffer>", language, min_severity, None, false, false, None, true, max_findings)
}

fn code_and_paren_delta<'a>(line: &'a str, lang: &str) -> (&'a str, i32, bool) {
    let bytes = line.as_bytes();
    let (mut in_sq, mut in_dq, mut in_bt) = (false, false, false);
    let (is_hash, is_py) = (matches!(lang, "python" | "shell" | "dockerfile"), lang == "python");
    let (mut delta, mut has_call_lparen, mut end, mut i) = (0i32, false, bytes.len(), 0usize);

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && (in_sq || in_dq || in_bt) { i += 2; continue; }
        if !in_sq && !in_dq && !in_bt {
            if (is_hash && b == b'#') || (!is_hash && b == b'/' && bytes.get(i + 1) == Some(&b'/')) { end = i; break; }
            if b == b'(' {
                delta += 1;
                let mut p = i;
                while p > 0 && matches!(bytes[p - 1], b' ' | b'\t') { p -= 1; }
                if p > 0 && (bytes[p - 1].is_ascii_alphanumeric() || bytes[p - 1] == b'_') {
                    let mut s = p - 1;
                    while s > 0 && (bytes[s - 1].is_ascii_alphanumeric() || bytes[s - 1] == b'_') { s -= 1; }
                    if !matches!(&line[s..p], "if" | "elif" | "while" | "for" | "return" | "assert" | "with" | "except" | "def" | "class" | "from" | "import" | "fn" | "match") {
                        has_call_lparen = true;
                    }
                }
            } else if b == b')' {
                delta -= 1;
            }
        }
        if b == b'\'' && !in_dq && !in_bt { in_sq = !in_sq; }
        else if b == b'"' && !in_sq && !in_bt { in_dq = !in_dq; }
        else if !is_py && b == b'`' && !in_sq && !in_dq { in_bt = !in_bt; }
        i += 1;
    }
    (line[..end].trim(), delta, has_call_lparen)
}

fn stitch_multiline_call(lines: &[&str], idx: usize, lang: &str) -> Option<String> {
    let (code0, delta, has_call_lparen) = code_and_paren_delta(lines[idx], lang);
    if delta <= 0 || !has_call_lparen || code0.len() > MAX_STITCH_BUFFER_BYTES
        || ["def ", "async def ", "class ", "from ", "import ", "fn "].iter().any(|p| code0.starts_with(p))
    {
        return None;
    }
    let mut stitched = String::with_capacity(code0.len().saturating_add(128).min(MAX_STITCH_BUFFER_BYTES));
    stitched.push_str(code0);
    let (mut depth, upper) = (delta, lines.len().min(idx + 1 + MAX_STITCH_CONTINUATION_LINES));
    for &cont in &lines[idx + 1..upper] {
        let ct = cont.trim();
        if ct.is_empty() || ct.starts_with('#') || ct.starts_with("//") || is_fixture_definition_line(ct) { continue; }
        let (ck, dk, _) = code_and_paren_delta(cont, lang);
        if !ck.is_empty() {
            if stitched.len() + 1 + ck.len() > MAX_STITCH_BUFFER_BYTES {
                let mut cut = MAX_STITCH_BUFFER_BYTES.saturating_sub(stitched.len() + 1).min(ck.len());
                while cut > 0 && !ck.is_char_boundary(cut) { cut -= 1; }
                if cut > 0 { stitched.push(' '); stitched.push_str(&ck[..cut]); }
                break;
            }
            stitched.push(' ');
            stitched.push_str(ck);
        }
        depth += dk;
        if depth <= 0 { break; }
    }
    Some(stitched)
}

#[allow(clippy::too_many_arguments)]
pub fn scan_text_with_policy_impl(
    content: &str, file_path: &str, lang: &str, min_severity: Severity,
    allowed_lines: Option<&BTreeSet<usize>>, allow_inline_ignores: bool,
    allow_file_ignores: bool, pre_ws_root: Option<&Path>, no_fs: bool, max_findings: usize,
) -> (Vec<Finding>, bool) {
    if allow_file_ignores && has_file_ignore_header(content) { return (Vec::new(), false); }

    let mut lang_sev_mask = 0u64;
    for (r_idx, rule) in BUILTIN_RULES.iter().enumerate() {
        if rule.severity.ge(&min_severity) && rule.languages.contains(&lang) { lang_sev_mask |= 1u64 << r_idx; }
    }
    if lang_sev_mask == 0 { return (Vec::new(), false); }

    let ks_s3_01_bit = 1u64 << IDX_KS_S3_01;
    let mut prefilter_mask = builtin_rule_prefilter().candidate_mask_first_word_u64(content.as_bytes(), false);
    if (lang_sev_mask & prefilter_mask & ks_s3_01_bit) != 0 {
        let file_pi_flags = pi_keyword_prefilter().candidate_mask_first_word_u64(content.as_bytes(), false) as u16;
        if !pi_flags_can_trigger(file_pi_flags) { prefilter_mask &= !ks_s3_01_bit; }
    }
    let active_mask = lang_sev_mask & prefilter_mask;
    if active_mask == 0 { return (Vec::new(), false); }

    let ks_s3_01_active = (active_mask & ks_s3_01_bit) != 0;
    let ks_013_active = (active_mask & (1u64 << IDX_KS_013)) != 0;
    let alias_active = (active_mask & ALIAS_CALL_RULE_MASK) != 0;
    let alias_map = if alias_active { FileAliasMap::from_source(content, lang) } else { FileAliasMap::empty() };

    let lines_vec: Vec<&str> = if ks_s3_01_active || ks_013_active || alias_active { content.lines().collect() } else { Vec::new() };
    let pi_flags_vec: Vec<u16> = if ks_s3_01_active {
        lines_vec.iter().map(|l| {
            let t = l.trim();
            if t.is_empty() || is_fixture_definition_line(t) { 0 } else { pi_line_flags(t) }
        }).collect()
    } else {
        Vec::new()
    };
    let mut ks_s3_01_hit: Vec<bool> = if ks_s3_01_active { vec![false; lines_vec.len()] } else { Vec::new() };
    let mut ws_cache: Option<Option<PathBuf>> = if no_fs { Some(None) } else { pre_ws_root.map(|p| Some(p.to_path_buf())) };

    let mut findings = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_fixture_definition_line(trimmed) { continue; }
        let lineno = idx + 1;
        if allowed_lines.is_some_and(|allowed| !allowed.contains(&lineno)) { continue; }
        let has_ignore = allow_inline_ignores && (line.contains("kintsugi:") || line.contains("KINTSUGI:"));
        let is_comment = trimmed.starts_with('#') || trimmed.starts_with("//");
        let stitched_call = if alias_active && !is_comment { stitch_multiline_call(&lines_vec, idx, lang) } else { None };

        let mut m = active_mask;
        while m != 0 {
            let r_idx = m.trailing_zeros() as usize;
            m &= m - 1;
            let rule = &BUILTIN_RULES[r_idx];
            if has_ignore && line_ignores_rule(line, rule.id) { continue; }
            let matched = if r_idx == IDX_KS_019 {
                contains_bidi_control_at_line(line, idx == 0)
            } else if r_idx == IDX_KS_S3_01 {
                let hit = pi_flags_can_trigger(pi_flags_vec[idx]) && contains_prompt_injection_text(trimmed);
                if hit { ks_s3_01_hit[idx] = true; }
                hit
            } else if r_idx == IDX_KS_013 {
                !is_comment && check_ks013_with_lines(&lines_vec, idx, lang)
            } else if is_comment && !matches!(r_idx, IDX_KS_009 | IDX_KS_026 | IDX_KS_030) {
                false
            } else if (ALIAS_CALL_RULE_MASK & (1u64 << r_idx)) != 0 {
                check_line_against_rule_with_aliases(rule.id, stitched_call.as_deref().unwrap_or(line), lang, &alias_map)
            } else {
                check_line_against_rule_lang_with_ctx(rule.id, line, trimmed, lang, &mut ws_cache, no_fs)
            };
            if matched {
                if findings.len() >= max_findings { return (findings, true); }
                findings.push(Finding::from_rule(rule, file_path, lineno, 1, trimmed));
            }
        }
    }

    if ks_s3_01_active {
        let ks_pi = &BUILTIN_RULES[IDX_KS_S3_01];
        let mut pair_buf = String::new();
        for idx in 0..lines_vec.len().saturating_sub(1) {
            let lineno = idx + 1;
            if allowed_lines.is_some_and(|allowed| !allowed.contains(&lineno)) || ks_s3_01_hit[idx] { continue; }
            if !pi_flags_can_trigger(pi_flags_vec[idx] | pi_flags_vec[idx + 1]) { continue; }
            let (t0, t1) = (lines_vec[idx].trim(), lines_vec[idx + 1].trim());
            if is_fixture_definition_line(t0) || is_fixture_definition_line(t1) { continue; }
            pair_buf.clear();
            pair_buf.reserve(t0.len() + 1 + t1.len());
            pair_buf.push_str(t0);
            pair_buf.push(' ');
            pair_buf.push_str(t1);
            if contains_prompt_injection_text(&pair_buf) && !(allow_inline_ignores && line_ignores_rule(lines_vec[idx], ks_pi.id)) {
                if findings.len() >= max_findings { return (findings, true); }
                findings.push(Finding::from_rule(ks_pi, file_path, lineno, 1, t0));
            }
        }
    }
    (findings, false)
}

pub fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | ".kintsugi" | ".claude" | ".cursor" | "__pycache__"
            | ".pytest_cache" | "node_modules" | "target" | "dist" | "build" | ".venv" | "venv" | "backups"
    )
}

#[inline]
fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() { return true; }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & 0x0400) != 0 { return true; }
    }
    false
}

fn walk_dir_confined(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut sorted_entries: Vec<_> = entries.flatten().collect();
    sorted_entries.sort_by_key(|e| e.file_name());
    for entry in sorted_entries {
        let name = entry.file_name();
        if !Path::new(&name).components().all(|c| matches!(c, Component::Normal(_))) { continue; }
        let path = dir.join(&name);
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if is_symlink_or_reparse(&meta) { continue; }
        if meta.is_dir() {
            if name.to_str().is_some_and(|s| !should_skip_dir(s)) { walk_dir_confined(&path, out); }
        } else if meta.is_file() && detect_language(&path).is_some() {
            out.push(path);
        }
    }
}

pub fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(meta) = fs::symlink_metadata(root) else { return };
    if is_symlink_or_reparse(&meta) { return; }
    if let Ok(canon_root) = fs::canonicalize(root) { collect_files_confined(root, &canon_root, out); }
}

pub fn collect_files_confined(node: &Path, root_canon: &Path, out: &mut Vec<PathBuf>) {
    if node.components().any(|c| matches!(c, Component::ParentDir)) { return; }
    let Ok(meta) = fs::symlink_metadata(node) else { return };
    if is_symlink_or_reparse(&meta) { return; }
    if !fs::canonicalize(node).is_ok_and(|nc| nc == *root_canon || nc.starts_with(root_canon)) { return; }
    if meta.is_file() { out.push(node.to_path_buf()); } else if meta.is_dir() { walk_dir_confined(node, out); }
}

pub fn scan_path(target: &Path, min_severity: Severity) -> ScanSummary { scan_path_full(target, min_severity, None, None, false, None) }
pub fn scan_path_with_policy(target: &Path, min_severity: Severity, explicit_policy: Option<&Path>) -> ScanSummary { scan_path_full(target, min_severity, explicit_policy, None, false, None) }
pub fn scan_path_with_policy_sha(target: &Path, min_severity: Severity, explicit_policy: Option<&Path>, expected_sha256: Option<&str>) -> ScanSummary { scan_path_full(target, min_severity, explicit_policy, expected_sha256, false, None) }
pub fn scan_path_with_shadow(target: &Path, min_severity: Severity, explicit_policy: Option<&Path>, include_arm_c_shadow: bool) -> ScanSummary { scan_path_full(target, min_severity, explicit_policy, None, include_arm_c_shadow, None) }
pub fn scan_path_with_policy_sha_and_shadow(target: &Path, min_severity: Severity, explicit_policy: Option<&Path>, expected_sha256: Option<&str>, include_arm_c_shadow: bool) -> ScanSummary {
    scan_path_full(target, min_severity, explicit_policy, expected_sha256, include_arm_c_shadow, None)
}

enum BoundedReadOutcome { Content(String), TooLarge(u64), Skip }

fn read_bounded_regular_file(file: &Path) -> BoundedReadOutcome {
    match read_regular_file_fd_verified(file, MAX_SOURCE_FILE_BYTES) {
        Ok(s) => BoundedReadOutcome::Content(s),
        Err(err) => match err.strip_prefix("FILE_TOO_LARGE:") {
            Some(rest) => BoundedReadOutcome::TooLarge(rest.split(':').next().and_then(|n| n.parse::<u64>().ok()).unwrap_or(MAX_SOURCE_FILE_BYTES + 1)),
            None => BoundedReadOutcome::Skip,
        },
    }
}

fn make_diag_finding(scar_id: &str, severity: Severity, category: &str, file_path: String, title: String, snippet: String, fix_hint: &str) -> Finding {
    Finding { scar_id: scar_id.to_string(), title, severity, category: category.to_string(), file_path, line: 1, column: 1, snippet, fix_hint: fix_hint.to_string() }
}

fn make_too_large_finding(display: String, sz: u64) -> Finding {
    make_diag_finding(
        "KS-SCAN-FILE-TOO-LARGE", Severity::High, "reliability", display,
        format!("Source file exceeds {MAX_SOURCE_FILE_BYTES} byte scan cap ({sz} bytes)"),
        format!("size={sz}B > max={MAX_SOURCE_FILE_BYTES}B"),
        "Split oversized file or move generated bundle under build/dist",
    )
}

#[inline]
fn dyn_rule_count(dynamic_registry: OptDynRules<'_>) -> usize {
    #[cfg(feature = "rule-ir")]
    { dynamic_registry.map(|d| d.len()).unwrap_or(0) }
    #[cfg(not(feature = "rule-ir"))]
    { let _ = dynamic_registry; 0 }
}

#[inline]
fn extend_bounded<I: IntoIterator<Item = Finding>>(out: &mut Vec<Finding>, iter: I, max_findings: usize, truncated: &mut bool) {
    for f in iter {
        if out.len() >= max_findings { *truncated = true; break; }
        out.push(f);
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_loaded_content(
    content: &str, display: &str, lang: &'static str, min_severity: Severity,
    allowed_lines: Option<&BTreeSet<usize>>, is_trusted: bool, ws_root: &Path,
    include_arm_c_shadow: bool, dynamic_registry: OptDynRules<'_>, max_findings: usize,
) -> (Vec<Finding>, bool) {
    let (mut out, mut truncated) = scan_text_with_policy_impl(
        content, display, lang, min_severity, allowed_lines, is_trusted, is_trusted, Some(ws_root), false, max_findings,
    );
    if !truncated && include_arm_c_shadow && lang == "python" {
        extend_bounded(&mut out, scan_arm_c_shadow_text_with_options(content, display, lang, min_severity, allowed_lines, is_trusted, is_trusted), max_findings, &mut truncated);
    }
    #[cfg(feature = "rule-ir")]
    if !truncated {
        if let Some(dyn_reg) = dynamic_registry {
            if !dyn_reg.is_empty() && !(is_trusted && has_file_ignore_header(content)) {
                let mut dyn_hits = dyn_reg.scan_buffer(content, display, lang, min_severity);
                let raw_lines: Vec<&str> = if is_trusted && !dyn_hits.is_empty() { content.lines().collect() } else { Vec::new() };
                dyn_hits.retain(|f| {
                    allowed_lines.map_or(true, |lines| lines.contains(&f.line))
                        && (!is_trusted || raw_lines.get(f.line.saturating_sub(1)).map(|ln| !line_ignores_rule(ln, &f.scar_id)).unwrap_or(true))
                });
                extend_bounded(&mut out, dyn_hits, max_findings, &mut truncated);
            }
        }
    }
    #[cfg(not(feature = "rule-ir"))]
    let _ = dynamic_registry;
    (out, truncated)
}

#[allow(clippy::too_many_arguments)]
fn scan_single_file_item(
    file: &Path, lang: &'static str, min_severity: Severity, trusted_files: &BTreeSet<PathBuf>,
    scan_cwd: &Path, include_arm_c_shadow: bool, dynamic_registry: OptDynRules<'_>,
) -> Option<(Vec<Finding>, bool)> {
    let display = file.to_string_lossy().to_string();
    let content = match read_bounded_regular_file(file) {
        BoundedReadOutcome::Content(s) => s,
        BoundedReadOutcome::TooLarge(sz) => return Some((if Severity::High >= min_severity { vec![make_too_large_finding(display, sz)] } else { Vec::new() }, false)),
        BoundedReadOutcome::Skip => return None,
    };
    let is_trusted = !trusted_files.is_empty() && fs::canonicalize(file).map(|c| trusted_files.contains(&c)).unwrap_or(false);
    Some(scan_loaded_content(&content, &display, lang, min_severity, None, is_trusted, scan_cwd, include_arm_c_shadow, dynamic_registry, MAX_REPO_FINDINGS))
}

/// Deduplicates, then keeps the `cap` most severe findings (ties broken by path/line/id/column),
/// restoring canonical order afterwards. Returns `true` if any distinct finding was dropped.
fn retain_highest_severity_findings(findings: &mut Vec<Finding>, cap: usize) -> bool {
    deduplicate_findings(findings);
    if findings.len() <= cap { return false; }
    findings.sort_by(|a, b| {
        b.severity.partial_cmp(&a.severity).unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.scar_id.cmp(&b.scar_id))
            .then_with(|| a.column.cmp(&b.column))
    });
    findings.truncate(cap);
    deduplicate_findings(findings);
    true
}

#[inline]
fn append_file_batch(findings: &mut Vec<Finding>, mut batch: Vec<Finding>, batch_trunc: bool, any_truncated: &mut bool) {
    *any_truncated |= batch_trunc;
    findings.append(&mut batch);
    if findings.len() > MAX_REPO_FINDINGS.saturating_mul(2) && retain_highest_severity_findings(findings, MAX_REPO_FINDINGS) {
        *any_truncated = true;
    }
}

const TRUNCATED_MARKER_ID: &str = "KS-SCAN-FINDINGS-TRUNCATED";

/// Single source of truth for the repo-wide findings cap. Idempotent: any pre-existing
/// truncation marker is stripped and re-emitted exactly once at `Severity::High`, so merged
/// multi-target results and repeated calls (same `target_disp`) yield byte-identical output.
pub fn enforce_findings_cap_idempotent(findings: &mut Vec<Finding>, force_truncated: bool, target_disp: &str) {
    let had_marker = findings.iter().any(|f| f.scar_id == TRUNCATED_MARKER_ID);
    findings.retain(|f| f.scar_id != TRUNCATED_MARKER_ID);
    deduplicate_findings(findings);
    if force_truncated || had_marker || findings.len() > MAX_REPO_FINDINGS {
        retain_highest_severity_findings(findings, MAX_REPO_FINDINGS.saturating_sub(1));
        findings.push(make_diag_finding(
            TRUNCATED_MARKER_ID, Severity::High, "reliability", target_disp.to_string(),
            format!("Scan findings capped at {MAX_REPO_FINDINGS} to prevent DoS via crafted corpus"),
            format!("findings_truncated_at={MAX_REPO_FINDINGS}"), "Resolve reported violations incrementally and re-scan",
        ));
        deduplicate_findings(findings);
    }
}

fn finalize_bounded_findings(mut findings: Vec<Finding>, any_truncated: bool, panicked_workers: usize, _min_severity: Severity, target: &Path) -> Vec<Finding> {
    deduplicate_findings(&mut findings);
    let disp = target.to_string_lossy().to_string();
    let mut force = any_truncated;
    if panicked_workers > 0 {
        // Reserve one slot for WORKER-FAILED and one for the marker so the Critical
        // fail-closed diagnostic can never be evicted by the cap.
        if force || findings.len() + 1 > MAX_REPO_FINDINGS {
            force = true;
            retain_highest_severity_findings(&mut findings, MAX_REPO_FINDINGS.saturating_sub(2));
        }
        findings.push(make_diag_finding(
            "KS-SCAN-WORKER-FAILED", Severity::Critical, "reliability", disp.clone(),
            format!("Fail-closed: {panicked_workers} scanner worker thread(s) panicked during scan"),
            format!("panicked_workers={panicked_workers}"), "Inspect inputs triggering scanner worker panic; fail-closed gate active",
        ));
    }
    enforce_findings_cap_idempotent(&mut findings, force, &disp);
    findings
}

fn run_parallel_worker_batches<T: Send, F: Fn(usize) -> Option<T> + Sync>(item_count: usize, workers: usize, scan_item: F) -> (Vec<(usize, T)>, usize) {
    let cursor = AtomicUsize::new(0);
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            handles.push(s.spawn(|| {
                catch_unwind(AssertUnwindSafe(|| {
                    let mut local = Vec::new();
                    loop {
                        let start_idx = cursor.fetch_add(WORK_CHUNK_SIZE, Ordering::Relaxed);
                        if start_idx >= item_count { break; }
                        for idx in start_idx..(start_idx + WORK_CHUNK_SIZE).min(item_count) {
                            if let Some(res) = scan_item(idx) { local.push((idx, res)); }
                        }
                    }
                    local
                }))
            }));
        }
        let (mut merged, mut panicked_workers) = (Vec::with_capacity(item_count), 0usize);
        for h in handles {
            match h.join() {
                Ok(Ok(local)) => merged.extend(local),
                Ok(Err(_)) | Err(_) => panicked_workers += 1,
            }
        }
        (merged, panicked_workers)
    })
}

pub fn scan_path_full(
    target: &Path, min_severity: Severity, explicit_policy: Option<&Path>,
    expected_sha256: Option<&str>, include_arm_c_shadow: bool, dynamic_registry: OptDynRules<'_>,
) -> ScanSummary {
    let start = Instant::now();
    let active_rules = BUILTIN_RULES.len() + if include_arm_c_shadow { ARM_C_SHADOW_RULES.len() } else { 0 } + dyn_rule_count(dynamic_registry);
    let trusted_files = load_trusted_policy_files_explicit_sha(target, explicit_policy, expected_sha256);
    let scan_cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut raw_files = Vec::new();
    collect_files(target, &mut raw_files);

    let mut work_items: Vec<(PathBuf, &'static str)> = raw_files.into_iter().filter_map(|f| detect_language(&f).map(|lang| (f, lang))).collect();
    work_items.sort_by(|a, b| a.0.cmp(&b.0));

    let (mut findings, mut scanned_files, mut any_truncated, mut panicked_workers) = (Vec::new(), 0usize, false, 0usize);
    if work_items.len() < 8 {
        for (file, lang) in &work_items {
            if let Some((ff, trunc)) = scan_single_file_item(file, lang, min_severity, &trusted_files, &scan_cwd, include_arm_c_shadow, dynamic_registry) {
                scanned_files += 1;
                append_file_batch(&mut findings, ff, trunc, &mut any_truncated);
            }
        }
    } else {
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 8).min(work_items.len());
        let (mut batches, pw) = run_parallel_worker_batches(work_items.len(), workers, |idx| {
            let (ref file, lang) = work_items[idx];
            scan_single_file_item(file, lang, min_severity, &trusted_files, &scan_cwd, include_arm_c_shadow, dynamic_registry)
        });
        panicked_workers = pw;
        batches.sort_unstable_by_key(|entry| entry.0);
        for (_, (ff, trunc)) in batches {
            scanned_files += 1;
            append_file_batch(&mut findings, ff, trunc, &mut any_truncated);
        }
    }

    let findings = finalize_bounded_findings(findings, any_truncated, panicked_workers, min_severity, target);
    ScanSummary { scanned_files, active_rules, elapsed_micros: start.elapsed().as_micros(), findings }
}

fn unquote_git_diff_path(raw: &str) -> Option<String> {
    let s = raw.trim();
    if !s.starts_with('"') { return Some(s.split('\t').next().unwrap_or(s).trim().to_string()); }
    let bytes = s.as_bytes();
    let (mut out, mut i, mut closed) = (Vec::with_capacity(bytes.len()), 1usize, false);
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' { closed = true; break; }
        if b == b'\\' {
            i += 1;
            let esc = *bytes.get(i)?;
            match esc {
                b'\\' => out.push(b'\\'), b'"' => out.push(b'"'), b't' => out.push(b'\t'),
                b'n' => out.push(b'\n'), b'r' => out.push(b'\r'), b'a' => out.push(0x07),
                b'b' => out.push(0x08), b'f' => out.push(0x0c), b'v' => out.push(0x0b),
                b'0'..=b'7' => {
                    let mut val = (esc - b'0') as u16;
                    for _ in 0..2 {
                        if let Some(&d) = bytes.get(i + 1).filter(|&&d| (b'0'..=b'7').contains(&d)) {
                            val = val * 8 + (d - b'0') as u16;
                            i += 1;
                        } else { break; }
                    }
                    out.push((val & 0xff) as u8);
                }
                other => out.push(other),
            }
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    closed.then(|| String::from_utf8(out).ok()).flatten()
}

fn join_repo_relative(repo_root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() || rel.contains('\0') || Path::new(rel).is_absolute() { return None; }
    let mut clean_rel = PathBuf::new();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(seg) => clean_rel.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!clean_rel.as_os_str().is_empty()).then(|| repo_root.join(clean_rel))
}

pub fn parse_git_diff_lines(diff_text: &str, repo_root: &Path) -> BTreeMap<PathBuf, BTreeSet<usize>> {
    let mut map: BTreeMap<PathBuf, BTreeSet<usize>> = BTreeMap::new();
    let (mut current_file, mut expect_plus_header) = (None, false);

    for line in diff_text.lines() {
        if line.starts_with("diff --git ") {
            current_file = None;
            expect_plus_header = false;
        } else if line.starts_with("--- ") {
            current_file = None;
            expect_plus_header = true;
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            if expect_plus_header {
                expect_plus_header = false;
                let parsed = match unquote_git_diff_path(rest) {
                    Some(ref u) if u != "/dev/null" => u.strip_prefix("b/").and_then(|rel| join_repo_relative(repo_root, rel)),
                    _ => None,
                };
                if let Some(ref p) = parsed { map.entry(p.clone()).or_default(); }
                current_file = parsed;
            }
        } else {
            expect_plus_header = false;
            if let (Some(ref file), Some(rest)) = (&current_file, line.strip_prefix("@@ ")) {
                if let Some(plus_idx) = rest.find('+') {
                    let after_plus = &rest[plus_idx + 1..];
                    let end_tok = after_plus.find(' ').unwrap_or(after_plus.len());
                    let mut parts = after_plus[..end_tok].split(',');
                    if let Some(Ok(start_ln)) = parts.next().map(|s| s.parse::<usize>()) {
                        let count = parts.next().and_then(|c| c.parse::<usize>().ok()).unwrap_or(1);
                        if start_ln == 0 || count == 0 { continue; }
                        let end_ln = start_ln.saturating_add(count.min(MAX_DIFF_HUNK_LINES));
                        let set = map.entry(file.clone()).or_default();
                        for ln in start_ln..end_ln { set.insert(ln); }
                    }
                }
            }
        }
    }
    map
}

pub fn scan_git_staged(repo_root: &Path, min_severity: Severity) -> ScanSummary { scan_git_staged_full(repo_root, min_severity, false, None) }
pub fn scan_git_staged_with_shadow(repo_root: &Path, min_severity: Severity, include_arm_c_shadow: bool) -> ScanSummary { scan_git_staged_full(repo_root, min_severity, include_arm_c_shadow, None) }

#[derive(Debug, PartialEq, Eq)]
enum BatchBlobOutcome { Utf8(String), TooLarge(u64), BinarySkip, Missing }

fn batch_read_git_staged_blobs(repo_root: &Path, rel_paths: &[String]) -> Vec<BatchBlobOutcome> {
    let mut outcomes: Vec<BatchBlobOutcome> = (0..rel_paths.len()).map(|_| BatchBlobOutcome::Missing).collect();
    let (mut query_indices, mut stdin_payload) = (Vec::with_capacity(rel_paths.len()), Vec::new());
    for (idx, rel) in rel_paths.iter().enumerate() {
        if !rel.is_empty() && !rel.contains('\n') && !rel.contains('\r') {
            stdin_payload.push(b':');
            stdin_payload.extend_from_slice(rel.as_bytes());
            stdin_payload.push(b'\n');
            query_indices.push(idx);
        }
    }
    if query_indices.is_empty() { return outcomes; }

    let Ok(mut child) = Command::new("git")
        .arg("-C").arg(repo_root).args(["cat-file", "--batch"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
    else { return outcomes; };
    let (Some(mut child_stdin), Some(child_stdout), Some(mut child_stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else { let _ = child.kill(); let _ = child.wait(); return outcomes; };

    std::thread::scope(|s| {
        s.spawn(move || { let _ = child_stdin.write_all(&stdin_payload); let _ = child_stdin.flush(); });
        s.spawn(move || {
            let mut stderr_cap = Vec::with_capacity(4096);
            let _ = (&mut child_stderr).take(MAX_GIT_STDERR_BYTES).read_to_end(&mut stderr_cap);
            let _ = io::copy(&mut child_stderr, &mut io::sink());
        });
        let (mut reader, mut hdr, mut aborted_early) = (BufReader::new(child_stdout), String::new(), false);
        for &slot in &query_indices {
            hdr.clear();
            if reader.read_line(&mut hdr).ok().filter(|&n| n > 0).is_none() { aborted_early = true; break; }
            let hdr_t = hdr.trim_end_matches(['\r', '\n']);
            if hdr_t.ends_with(" missing") { continue; }
            let mut rev = hdr_t.rsplitn(3, ' ');
            let (Some(sz_s), Some(obj_type)) = (rev.next(), rev.next()) else { aborted_early = true; break };
            let Ok(size) = sz_s.parse::<u64>() else { aborted_early = true; break };
            if size > MAX_SOURCE_FILE_BYTES {
                if io::copy(&mut (&mut reader).take(size + 1), &mut io::sink()).ok() != Some(size + 1) { aborted_early = true; break; }
                outcomes[slot] = BatchBlobOutcome::TooLarge(size);
                continue;
            }
            let (mut buf, mut lf) = (vec![0u8; size as usize], [0u8; 1]);
            if reader.read_exact(&mut buf).is_err() || reader.read_exact(&mut lf).is_err() { aborted_early = true; break; }
            outcomes[slot] = if obj_type == "blob" {
                String::from_utf8(buf).map_or(BatchBlobOutcome::BinarySkip, BatchBlobOutcome::Utf8)
            } else {
                BatchBlobOutcome::BinarySkip
            };
        }
        if aborted_early { let _ = child.kill(); }
    });
    let _ = child.wait();
    outcomes
}

fn staged_error_summary(repo_root: &Path, active_rules: usize, start: Instant, title: String, snippet: String, fix_hint: &str) -> ScanSummary {
    ScanSummary {
        scanned_files: 0, active_rules, elapsed_micros: start.elapsed().as_micros(),
        findings: vec![make_diag_finding("KS-GIT-STAGED-FAILED", Severity::Critical, "security", repo_root.to_string_lossy().to_string(), title, snippet, fix_hint)],
    }
}

/// Scans only the lines touched in the Git index (`git diff --staged -U0`).
///
/// Trust and policy sources:
/// - `.kintsugi/policy.json` and the trusted baseline are always read from `repo_root`.
///   No explicit policy path or expected SHA-256 is accepted here, so a caller cannot
///   redirect trust outside the repository being scanned.
/// - Content is read only from index blobs (`git cat-file --batch`, `:<path>`). A missing
///   or unreadable blob becomes a `Severity::Critical` finding (`KS-GIT-STAGED-BLOB-MISSING`).
///   The scanner never falls back to the working tree.
///
/// Path normalization: every staged path goes through `unquote_git_diff_path` and then
/// `join_repo_relative`. That rejects absolute paths, `..`, root/prefix components and NUL,
/// and drops `.`. The `:<path>` query is then rebuilt from `Component::Normal` segments
/// joined with `/`. Paths containing CR/LF are never sent to `git cat-file` and resolve
/// to `Missing` (fail-closed).
pub fn scan_git_staged_full(
    repo_root: &Path, min_severity: Severity, include_arm_c_shadow: bool, dynamic_registry: OptDynRules<'_>,
) -> ScanSummary {
    let start = Instant::now();
    let active_rules = BUILTIN_RULES.len() + if include_arm_c_shadow { ARM_C_SHADOW_RULES.len() } else { 0 } + dyn_rule_count(dynamic_registry);

    let proc_out = match Command::new("git")
        .arg("-C").arg(repo_root)
        .args(["-c", "core.quotepath=true", "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--staged"])
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(out) => return staged_error_summary(
            repo_root, active_rules, start,
            format!("Fail-closed: `git diff --staged` failed with exit code {}", out.status.code().unwrap_or(-1)),
            String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or("git diff failed").to_string(),
            "Run staged scan inside a valid Git repository with readable index",
        ),
        Err(err) => return staged_error_summary(
            repo_root, active_rules, start,
            "Fail-closed: unable to execute `git diff --staged`".to_string(), err.to_string(),
            "Ensure `git` is installed on PATH and repository is accessible",
        ),
    };

    let diff_str = String::from_utf8_lossy(&proc_out.stdout);
    scan_git_staged_from_diff(repo_root, &diff_str, min_severity, include_arm_c_shadow, dynamic_registry, start, active_rules)
}

fn scan_git_staged_from_diff(
    repo_root: &Path, diff_str: &str, min_severity: Severity,
    include_arm_c_shadow: bool, dynamic_registry: OptDynRules<'_>, start: Instant, active_rules: usize,
) -> ScanSummary {
    let touched = parse_git_diff_lines(diff_str, repo_root);
    let mut staged_items: Vec<(PathBuf, BTreeSet<usize>, &'static str, String)> = Vec::new();
    for (file, lines) in touched {
        if lines.is_empty() { continue; }
        let Some(lang) = detect_language(&file) else { continue };
        let rel_slash = file.strip_prefix(repo_root).unwrap_or(&file).components()
            .filter_map(|c| match c { Component::Normal(s) => s.to_str(), _ => None }).collect::<Vec<_>>().join("/");
        staged_items.push((file, lines, lang, rel_slash));
    }

    let rel_list: Vec<String> = staged_items.iter().map(|it| it.3.clone()).collect();
    let blob_outcomes = batch_read_git_staged_blobs(repo_root, &rel_list);
    let trusted_files = load_trusted_policy_files_explicit_sha(repo_root, None, None);
    let (mut findings, mut scanned_files, mut any_truncated) = (Vec::new(), 0usize, false);

    for ((file, lines, lang, rel_slash), blob) in staged_items.into_iter().zip(blob_outcomes) {
        let display = file.to_string_lossy().to_string();
        let content = match blob {
            BatchBlobOutcome::Utf8(s) => s,
            BatchBlobOutcome::BinarySkip => continue,
            BatchBlobOutcome::TooLarge(sz) => {
                scanned_files += 1;
                if Severity::High >= min_severity { findings.push(make_too_large_finding(display, sz)); }
                continue;
            }
            BatchBlobOutcome::Missing => {
                if Severity::Critical >= min_severity {
                    findings.push(make_diag_finding(
                        "KS-GIT-STAGED-BLOB-MISSING", Severity::Critical, "security", display,
                        "Git index blob missing or unreadable in git cat-file --batch".to_string(),
                        format!("missing_index_blob=:{rel_slash}"),
                        "Re-stage file (`git add`) or run `git fsck`; working-tree fallback is forbidden",
                    ));
                }
                continue;
            }
        };
        scanned_files += 1;
        let is_trusted = !trusted_files.is_empty() && fs::canonicalize(&file).map(|c| trusted_files.contains(&c)).unwrap_or(false);
        let (ff, trunc) = scan_loaded_content(&content, &display, lang, min_severity, Some(&lines), is_trusted, repo_root, include_arm_c_shadow, dynamic_registry, MAX_REPO_FINDINGS);
        append_file_batch(&mut findings, ff, trunc, &mut any_truncated);
    }

    let findings = finalize_bounded_findings(findings, any_truncated, 0, min_severity, repo_root);
    ScanSummary { scanned_files, active_rules, elapsed_micros: start.elapsed().as_micros(), findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_multiline_stitch_bom_line2_bounded_scan_and_worker_panic_guard() {
        let mut deep_call = String::from("import yaml as ym\ncfg = ym.load(\n");
        for k in 0..18 { deep_call.push_str(&format!("    arg_{k} if cond_{k} else default_{k},\n")); }
        deep_call.push_str("    Loader=ym.Loader,\n)\n");
        let hits = scan_text(&deep_call, "cfg.py", "python", Severity::High, None);
        assert!(hits.iter().any(|f| f.scar_id == "KS-020" && f.line == 2), "{hits:?}");

        assert!(scan_text("\u{FEFF}x = 1\n", "bom1.py", "python", Severity::High, None).is_empty());
        let bom2 = scan_text("x = 1\n\u{FEFF}y = 2\n", "bom2.py", "python", Severity::High, None);
        assert!(bom2.iter().any(|f| f.scar_id == "KS-019" && f.line == 2), "{bom2:?}");

        let flood = "import os\n".to_string() + &"os.system(cmd)\n".repeat(25);
        let (bounded, trunc) = scan_text_buffer_bounded(&flood, "python", Severity::High, 7);
        assert_eq!(bounded.len(), 7);
        assert!(trunc);

        let (_, panicked) = run_parallel_worker_batches(4, 2, |idx| -> Option<usize> {
            if idx == 1 { panic!("synthetic worker fault"); }
            Some(idx)
        });
        assert!(panicked >= 1);
        let capped = finalize_bounded_findings(Vec::new(), true, panicked, Severity::Low, Path::new("repo"));
        assert!(capped.iter().any(|f| f.scar_id == "KS-SCAN-WORKER-FAILED" && f.severity == Severity::Critical));
        assert!(capped.iter().any(|f| f.scar_id == "KS-SCAN-FINDINGS-TRUNCATED"));
    }

    #[test]
    fn parse_git_diff_requires_minus_header_rejects_zero_start_and_decodes_octal() {
        let repo = Path::new("/repo");
        let diff = "commit msg\n+++ b/spoof.py\n@@ -1,1 +1,3 @@\n--- \"a/b\\303\\241o.py\"\n+++ \"b/b\\303\\241o\\t1.py\"\n@@ -0,0 +0,2 @@\n@@ -1,1 +4,2 @@\n+++ b/hunk_spoof.py\n@@ -10,1 +10,1 @@\n";
        let m = parse_git_diff_lines(diff, repo);
        assert!(!m.contains_key(&repo.join("spoof.py")));
        assert!(!m.contains_key(&repo.join("hunk_spoof.py")));
        let lines = m.get(&repo.join("báo\t1.py")).expect("octal UTF-8 + tab path decoded");
        assert_eq!(lines.iter().copied().collect::<Vec<_>>(), vec![4, 5, 10]);
    }

    #[test]
    fn batch_read_git_staged_blobs_handles_missing_objects_without_working_tree_fallback() {
        let repo = env::temp_dir().join(format!("kintsugi_staged_blob_{}", std::process::id()));
        let _ = fs::remove_dir_all(&repo);
        fs::create_dir_all(&repo).unwrap();
        let init = Command::new("git").arg("init").arg("-q").arg(&repo).status()
            .expect("git binary must be installed for scanner staged tests");
        assert!(init.success(), "git init failed for staged blob test repo");
        fs::write(repo.join("clean.py"), "x = 1\n").unwrap();
        fs::write(repo.join("vanished.py"), "unique_staged_blob_42 = 2\n").unwrap();
        assert!(Command::new("git").arg("-C").arg(&repo).args(["add", "clean.py", "vanished.py"]).status().unwrap().success());
        let poisoned = "import yaml\ncfg = yaml.load(raw, Loader=yaml.Loader)\n";
        fs::write(repo.join("clean.py"), poisoned).unwrap();
        fs::write(repo.join("vanished.py"), poisoned).unwrap();
        let pre_diff = Command::new("git").arg("-C").arg(&repo)
            .args(["-c", "core.quotepath=true", "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--staged"])
            .output().expect("git diff before object removal");
        assert!(pre_diff.status.success());
        let pre_diff_str = String::from_utf8_lossy(&pre_diff.stdout).into_owned();
        let rev = Command::new("git").arg("-C").arg(&repo).args(["rev-parse", ":vanished.py"]).output()
            .expect("git binary must be installed for scanner staged tests");
        assert!(rev.status.success(), "git rev-parse :vanished.py failed");
        let oid = String::from_utf8_lossy(&rev.stdout).trim().to_string();
        assert!(oid.len() == 40 || oid.len() == 64, "unexpected object id: {oid}");
        fs::remove_file(repo.join(".git/objects").join(&oid[..2]).join(&oid[2..]))
            .expect("loose object for vanished.py must exist right after git add");

        let queries = vec!["clean.py".into(), "vanished.py".into(), "untracked.py".into(), "bad\ninj.py".into()];
        let res = batch_read_git_staged_blobs(&repo, &queries);
        assert_eq!(res, vec![BatchBlobOutcome::Utf8("x = 1\n".into()), BatchBlobOutcome::Missing, BatchBlobOutcome::Missing, BatchBlobOutcome::Missing]);
        let post_diff_scan = scan_git_staged_from_diff(&repo, &pre_diff_str, Severity::Critical, false, None, Instant::now(), BUILTIN_RULES.len());
        assert!(!post_diff_scan.findings.iter().any(|f| f.scar_id == "KS-020"), "working-tree fallback leaked: {:?}", post_diff_scan.findings);
        assert!(post_diff_scan.findings.iter().any(|f| f.scar_id == "KS-GIT-STAGED-BLOB-MISSING" && f.severity == Severity::Critical), "{:?}", post_diff_scan.findings);
        let full_staged = scan_git_staged(&repo, Severity::Critical);
        assert!(!full_staged.findings.iter().any(|f| f.scar_id == "KS-020"), "working-tree fallback leaked: {:?}", full_staged.findings);
        assert!(full_staged.findings.iter().any(|f| f.scar_id == "KS-GIT-STAGED-FAILED" && f.severity == Severity::Critical), "{:?}", full_staged.findings);
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn finalize_bounded_findings_keeps_trailing_critical_after_low_flood() {
        let mut flood: Vec<_> = (0..10_050usize)
            .map(|i| make_diag_finding(
                "KS-TEST-LOW-FLOOD", Severity::Low, "security", format!("low_{i}.py"),
                "synthetic low finding".to_string(), format!("idx={i}"), "none",
            ))
            .collect();
        flood.push(make_diag_finding(
            "KS-TEST-TAIL-CRITICAL", Severity::Critical, "security", "tail.py".to_string(),
            "synthetic critical finding".to_string(), "tail".to_string(), "none",
        ));
        let over_cap = flood.len() > MAX_REPO_FINDINGS;
        let out = finalize_bounded_findings(flood, over_cap, 0, Severity::Low, Path::new("repo"));
        assert!(out.iter().any(|f| f.scar_id == "KS-TEST-TAIL-CRITICAL" && f.severity == Severity::Critical), "trailing critical dropped");
        assert!(out.iter().any(|f| f.scar_id == "KS-SCAN-FINDINGS-TRUNCATED"), "truncation marker missing");
    }

    #[test]
    fn enforce_findings_cap_merged_targets_single_marker_idempotent() {
        let build = |tag: &str| -> Vec<Finding> {
            let mut v: Vec<_> = (0..10_050usize)
                .map(|i| make_diag_finding(
                    "KS-TEST-LOW-FLOOD", Severity::Low, "security", format!("{tag}/low_{i}.py"),
                    "synthetic low finding".to_string(), format!("idx={i}"), "none",
                ))
                .collect();
            v.push(make_diag_finding(
                "KS-TEST-TAIL-CRITICAL", Severity::Critical, "security", format!("{tag}/tail.py"),
                "synthetic critical finding".to_string(), "tail".to_string(), "none",
            ));
            enforce_findings_cap_idempotent(&mut v, false, tag);
            v
        };
        let mut merged = build("a");
        merged.append(&mut build("b"));
        assert_eq!(merged.iter().filter(|f| f.scar_id == "KS-SCAN-FINDINGS-TRUNCATED").count(), 2);
        enforce_findings_cap_idempotent(&mut merged, false, "a,b");
        let out_once = format!("{merged:?}");
        enforce_findings_cap_idempotent(&mut merged, false, "a,b");
        let out_twice = format!("{merged:?}");
        assert_eq!(out_once, out_twice, "cap enforcement not idempotent");
        let markers: Vec<_> = merged.iter().filter(|f| f.scar_id == "KS-SCAN-FINDINGS-TRUNCATED").collect();
        assert_eq!(markers.len(), 1, "expected exactly one truncation marker");
        assert_eq!(markers[0].severity, Severity::High);
        assert_eq!(markers[0].file_path, "a,b");
        assert!(merged.len() <= MAX_REPO_FINDINGS);
        assert_eq!(merged.iter().filter(|f| f.scar_id == "KS-TEST-TAIL-CRITICAL").count(), 2, "critical evicted");
    }
}
