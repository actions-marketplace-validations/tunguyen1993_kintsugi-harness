//! Grade S3 `@CT2` Seam & Lock Auditor (`kintsugi-rs s3-audit`).
//!
//! Stateful lexical seam auditor (`stateful_lexical_seam_auditor`) with strict `QUARANTINED_IGNORE_OVERRIDE`
//! quarantine, confinement-verified `PATH_LFI`/`SQL_EXEC` checks, and structured [`SeamEvidence`] chains.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

use crate::audit::ct2_seams::StatefulMasker;
use crate::audit::obligation_prover::{
    prove_file_obligations, Obligation, ObligationState, OBLIGATION_PROVER_KIND,
};
use crate::io_json::{read_regular_file_fd_verified, JsonArr, JsonObj, ENGINE_VERSION};
use crate::policy::sha256_hex;
use crate::rules::matcher::{has_unquoted_call, has_unsafe_shell_kwarg, is_fixture_definition_line};
use crate::scanner::{collect_files, MAX_SOURCE_FILE_BYTES};

pub const S3_AUDITOR_KIND: &str = "stateful_lexical_seam_auditor";
pub const S3_EVIDENCE_MODEL: &str = "stateful_lex_pre_sink_var_bound_v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeamEvidence {
    pub seam_line: usize,
    pub seam_col: usize,
    pub guard_line: usize,
    pub seam_kind: &'static str,
    pub bound_vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailingSeam {
    pub seam_line: usize,
    pub seam_col: usize,
    pub seam_kind: &'static str,
    pub tier: &'static str,
    pub reason: &'static str,
    pub fix_hint: &'static str,
}

#[derive(Debug, Clone)]
pub struct S3FileAudit {
    pub file_path: String,
    pub manifest_sha: String,
    pub elapsed_ms: f64,
    pub functions_count: usize,
    pub classes_count: usize,
    pub total_seams: usize,
    pub s3_locked_seams: usize,
    pub proven_s3_seams: usize,
    pub unproven_seams: usize,
    pub unguarded_s0_seams: usize,
    pub ignored_override: bool,
    pub assurance_tier: &'static str,
    pub verdict: &'static str,
    pub strict_verdict: &'static str,
    pub evidence_chains: Vec<SeamEvidence>,
    pub failing_seams: Vec<FailingSeam>,
    pub obligations: Vec<Obligation>,
    pub unsupported_seams: usize,
}

#[derive(Debug, Clone)]
pub struct S3AuditSummary {
    pub target: String,
    pub strict_proven: bool,
    pub files_scanned: usize,
    pub total_functions: usize,
    pub total_classes: usize,
    pub total_seams: usize,
    pub s3_locked_seams: usize,
    pub proven_s3_seams: usize,
    pub unproven_seams: usize,
    pub unguarded_s0_seams: usize,
    pub ignored_override: bool,
    pub ignored_override_files: usize,
    pub missing_targets: Vec<String>,
    pub elapsed_ms: f64,
    pub assurance_tier: &'static str,
    pub verdict: &'static str,
    pub strict_verdict: &'static str,
    pub files: Vec<S3FileAudit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeamTier { ExposedS0, ProvenS3, Unproven }

#[derive(Debug, Clone, Copy)]
enum LegacySuppression {
    /// Suppress ONLY the exact call matching `(line, kind)` at `start_col` OR `paren_col`
    /// so nested calls inside arguments (e.g. `open(safe_p, "w", encoding=open(evil_p)...)`) are NEVER hidden.
    ExactCall { line: usize, start_col: usize, paren_col: usize, kind: &'static str },
    /// Suppress legacy seams within a line/column span (used for whole-line `CRYPTO_MAC_BIDI` spans).
    ColRange { line: usize, start_col: usize, end_col: usize, kind: &'static str },
}

/// Compute `(assurance_tier, verdict, strict_verdict)`; `ignored_override` NEVER returns `PASS_S3_LOCKED`.
#[inline]
pub fn compute_s3_verdicts(s0: usize, unproven: usize, ignored_override: bool, strict: bool) -> (&'static str, &'static str, &'static str) {
    if s0 > 0 {
        ("FAIL_S0_EXPOSED", "FAIL_S0_EXPOSED", "FAIL_S0_EXPOSED")
    } else if ignored_override {
        ("QUARANTINED_IGNORE_OVERRIDE", "QUARANTINED_IGNORE_OVERRIDE", "QUARANTINED_IGNORE_OVERRIDE")
    } else if unproven > 0 {
        (
            "NO_S0_DETECTED_WITH_UNPROVEN",
            if strict { "FAIL_UNPROVEN_SEAMS" } else { "PASS_S3_LOCKED" },
            if strict { "FAIL_UNPROVEN_SEAMS" } else { "PASS_S3_UNPROVEN_ALLOWED" },
        )
    } else {
        ("PROVEN_S3", "PASS_S3_LOCKED", "PASS_S3_PROVEN")
    }
}

#[inline]
fn has_bare_call(masked: &str, needle: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = masked[from..].find(needle) {
        let idx = from + rel;
        if idx == 0 || !matches!(masked.as_bytes()[idx - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.') { return true; }
        from = idx + needle.len();
    }
    false
}

fn is_non_var_token(tok: &str) -> bool {
    matches!(
        tok,
        "true" | "false" | "True" | "False" | "None" | "null" | "self" | "this" | "let" | "mut" | "const" | "var"
            | "return" | "await" | "async" | "new" | "os" | "fs" | "std" | "path" | "Path" | "crypto" | "hmac"
            | "hashlib" | "subprocess" | "Command" | "O_RDONLY" | "O_WRONLY" | "O_RDWR" | "O_CREAT" | "O_TRUNC"
            | "O_APPEND" | "O_NOFOLLOW" | "RESOLVE_BENEATH" | "shell" | "check"
    )
}

fn extract_var_tokens(masked_slice: &str) -> BTreeSet<String> {
    let (mut vars, mut cur) = (BTreeSet::new(), String::new());
    for c in masked_slice.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            cur.push(c);
        } else {
            if !cur.is_empty() && !cur.as_bytes()[0].is_ascii_digit() && !is_non_var_token(&cur) { vars.insert(cur.clone()); }
            cur.clear();
        }
    }
    vars
}

fn extract_sink_arg_vars(raw_seam: &str, mask_seam: &str, needles: &[&str]) -> Vec<String> {
    if raw_seam.is_empty() {
        return Vec::new();
    }
    for &needle in needles {
        let pos_opt = if needle.starts_with('.') || needle.contains('.') || needle.contains("::") {
            mask_seam.find(needle)
        } else {
            let (mut from, mut found) = (0usize, None);
            while let Some(rel) = mask_seam[from..].find(needle) {
                let idx = from + rel;
                if idx == 0 || !matches!(mask_seam.as_bytes()[idx - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.') {
                    found = Some(idx);
                    break;
                }
                from = idx + needle.len();
            }
            found
        };
        if let Some(idx) = pos_opt {
            let rest = &mask_seam[idx + needle.len()..];
            let (mut depth, mut end_rel) = (1usize, rest.len());
            for (bi, b) in rest.bytes().enumerate() {
                match b {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end_rel = bi;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            return extract_var_tokens(&rest[..end_rel]).into_iter().collect();
        }
    }
    Vec::new()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LegacySeamHit {
    kind: &'static str,
    start_byte: usize,
    paren_byte: usize,
    end_byte: usize,
}

fn find_call_end(masked: &str, open_paren_byte: usize) -> usize {
    let bytes = masked.as_bytes();
    if open_paren_byte >= bytes.len() || bytes[open_paren_byte] != b'(' {
        return open_paren_byte.min(bytes.len());
    }
    let mut depth = 0usize;
    for (bi, &b) in bytes[open_paren_byte..].iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return open_paren_byte + bi + 1;
                }
            }
            _ => {}
        }
    }
    bytes.len()
}

fn collect_call_hits(
    masked: &str,
    kind: &'static str,
    needles: &[&str],
    bare_needles: &[&str],
    out: &mut Vec<LegacySeamHit>,
) {
    let mb = masked.as_bytes();
    for &needle in needles {
        let mut from = 0usize;
        while from < masked.len() {
            let Some(rel) = masked[from..].find(needle) else { break };
            let idx = from + rel;
            let left_ok = needle.starts_with('.')
                || idx == 0
                || !matches!(mb[idx - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_');
            if left_ok {
                let (paren_byte, end_byte) = if needle.ends_with('(') {
                    let pb = idx + needle.len() - 1;
                    (pb, find_call_end(masked, pb))
                } else {
                    let mut e = idx + needle.len();
                    while e < mb.len() && matches!(mb[e], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_') {
                        e += 1;
                    }
                    if mb.get(e) == Some(&b'(') {
                        (e, find_call_end(masked, e))
                    } else {
                        (idx, e)
                    }
                };
                out.push(LegacySeamHit { kind, start_byte: idx, paren_byte, end_byte });
            }
            from = idx + needle.len();
        }
    }
    for &needle in bare_needles {
        let mut from = 0usize;
        while from < masked.len() {
            let Some(rel) = masked[from..].find(needle) else { break };
            let idx = from + rel;
            let left_ok = idx == 0
                || !matches!(mb[idx - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'.');
            if left_ok {
                let pb = idx + needle.len() - 1;
                out.push(LegacySeamHit {
                    kind,
                    start_byte: idx,
                    paren_byte: pb,
                    end_byte: find_call_end(masked, pb),
                });
            }
            from = idx + needle.len();
        }
    }
}

fn classify_s3_seam_occurrences(raw_line: &str, masked_line: &str) -> Vec<LegacySeamHit> {
    let raw_t = raw_line.trim();
    let mask_t = masked_line.trim();
    if mask_t.is_empty()
        || ["*", "fix_hint:", "title:", "kmi_token:", "let bad_", "let ignored_", "poisoned."].iter().any(|p| raw_t.starts_with(p))
        || raw_t.contains(".contains(\"") || is_fixture_definition_line(raw_t)
    {
        return Vec::new();
    }
    const CMD_CALLS: &[&str] = &[
        "spawnSync(", "execFileSync(", "execFile(", "execSync(", "child_process.exec(", "subprocess.run(",
        "subprocess.Popen(", "subprocess.call(", "subprocess.check_call(", "subprocess.check_output(",
        "Command::new(", "authorizeCommand(", "runProcess(", "runCommand(", "os.system(", "os.popen(",
    ];
    const SQL_CALLS: &[&str] = &[
        ".execute(", ".executemany(", "executeQuery(", "prepareStatement(", "mysqli_query(", "mysql_query(",
    ];
    const PATH_CALLS: &[&str] = &[
        "resolveInside(", "realpathSync(", "lstatSync(", "symlink_metadata(", "canonicalize(",
        "read_regular_file_fd_verified(", "readSanitizedOutboundFileS3(", "assert_not_symlink(", "os.open(",
        "fs.readFileSync(",
    ];
    const STATE_CALLS: &[&str] = &[
        "writeJsonAtomic(", "atomicWriteJsonS3(", "atomic_write", "locked_cortex_transaction(", "writeFileSync(",
    ];
    const CRYPTO_CALLS: &[&str] = &[
        "createHash(", "hashlib.sha256(", "hmac.new(", "hmac.digest(", "compare_digest(", "timingSafeEqual(",
    ];

    let mut raw_hits = Vec::new();
    collect_call_hits(masked_line, "CMD_EXEC", CMD_CALLS, &["spawn(", "eval("], &mut raw_hits);
    collect_call_hits(masked_line, "SQL_EXEC", SQL_CALLS, &[], &mut raw_hits);
    collect_call_hits(masked_line, "PATH_LFI", PATH_CALLS, &["open("], &mut raw_hits);
    collect_call_hits(masked_line, "STATE_MUTATION", STATE_CALLS, &[], &mut raw_hits);
    let crypto_before = raw_hits.len();
    collect_call_hits(masked_line, "CRYPTO_VERIFY", CRYPTO_CALLS, &[], &mut raw_hits);
    if raw_hits.len() == crypto_before && has_unsafe_hmac_secret_eq(mask_t) {
        let first_non_ws = masked_line.len() - masked_line.trim_start().len();
        raw_hits.push(LegacySeamHit {
            kind: "CRYPTO_VERIFY",
            start_byte: first_non_ws,
            paren_byte: first_non_ws,
            end_byte: masked_line.len(),
        });
    }

    raw_hits.sort_by_key(|h| (h.paren_byte, h.kind, h.start_byte));
    let mut deduped: Vec<LegacySeamHit> = Vec::with_capacity(raw_hits.len());
    for hit in raw_hits {
        if !deduped.iter().any(|prev| prev.kind == hit.kind && prev.paren_byte == hit.paren_byte) {
            deduped.push(hit);
        }
    }
    deduped.sort_by_key(|h| (h.start_byte, h.paren_byte, h.kind));
    deduped
}

fn has_sql_fstring_or_concat(raw_t: &str, mask_t: &str) -> bool {
    let upper = raw_t.to_ascii_uppercase();
    ["SELECT ", "INSERT ", "UPDATE ", "DELETE "].iter().any(|verb| {
        upper.contains(&format!("F\"{verb}")) || upper.contains(&format!("F'{verb}"))
            || (raw_t.contains("${") && upper.contains(verb))
            || ((upper.contains(&format!("\"{verb}")) || upper.contains(&format!("'{verb}")))
                && (mask_t.contains('+') || mask_t.contains('%') || mask_t.contains(".format(") || mask_t.contains("format!("))
                && !raw_t.contains("'?'") && !raw_t.contains("\"?\""))
    })
}

fn has_unsafe_hmac_secret_eq(mask_t: &str) -> bool {
    let secret_names = ["hmac", "secret", "header_sig", "expected_sig", "expected_mac", "webhook_sig"];
    let mut clauses = Vec::new();

    for semi_clause in mask_t.split(';') {
        for and_clause in semi_clause.split("&&") {
            for or_clause in and_clause.split("||") {
                for clause in or_clause.split(" and ") {
                    for sub_clause in clause.split(" or ") {
                        clauses.push(sub_clause);
                    }
                }
            }
        }
    }

    clauses.into_iter().any(|clause| {
        let lower = clause.to_ascii_lowercase();
        let has_comparison = ["!==", "===", "!=", "=="].iter().any(|op| lower.contains(op));
        if !has_comparison || !secret_names.iter().any(|name| lower.contains(name)) {
            return false;
        }

        let comparison = ["!==", "===", "!=", "=="].iter().find_map(|op| {
            lower.find(op).map(|pos| (&lower[..pos], &lower[pos + op.len()..]))
        });

        if let Some((left, right)) = comparison {
            let left = left.trim();
            let right = right.trim();
            let both_lengths = (left.contains("len(") || left.contains(".len(") || left.contains(".length"))
                && (right.contains("len(") || right.contains(".len(") || right.contains(".length"));
            let length_vs_int = ((left.contains("len(") || left.contains(".len(") || left.contains(".length"))
                && right.bytes().all(|b| b.is_ascii_digit()) && !right.is_empty())
                || ((right.contains("len(") || right.contains(".len(") || right.contains(".length"))
                    && left.bytes().all(|b| b.is_ascii_digit()) && !left.is_empty());
            let compares_empty_or_null = ["none", "null", "\"\"", "''", "b\"\"", "b''"].iter().any(|value| {
                left == *value || right == *value
            });
            if both_lengths || length_vs_int || compares_empty_or_null {
                return false;
            }
        }

        true
    })
}

#[inline]
fn has_path_confinement_guard(mask_l: &str) -> bool {
    ["starts_with(", "startsWith(", "startswith(", "resolveInside(", "read_regular_file_fd_verified(",
     "read_regular_bytes_fd_verified(", "readSanitizedOutboundFileS3(", "assert_not_symlink(", "O_NOFOLLOW", "RESOLVE_BENEATH"]
        .iter().any(|g| mask_l.contains(g))
}

fn line_matches_guard(seam_kind: &str, raw_l: &str, mask_l: &str) -> bool {
    match seam_kind {
        "PATH_LFI" => has_path_confinement_guard(mask_l),
        "STATE_MUTATION" => ["atomic_write", "writeJsonAtomic", "atomicWriteJsonS3", "locked_cortex_transaction", "0o600", "rename("].iter().any(|g| mask_l.contains(g)) || raw_l.contains("0o600"),
        "SQL_EXEC" => !mask_l.contains('+') && !mask_l.contains('%') && !mask_l.contains(".format(") && !mask_l.contains("format!(") && !raw_l.contains("${")
            && (["bindParam(", "bindValue(", "setString(", "setInt("].iter().any(|g| mask_l.contains(g))
                || ((raw_l.contains(".execute(\"") || raw_l.contains(".execute('")) && (raw_l.contains('?') || raw_l.contains("%s") || raw_l.contains("$1")) && raw_l.contains(','))),
        "CRYPTO_VERIFY" => [
            "compare_digest",
            "timingSafeEqual",
            "timingsafeequal",
            "constant_time_eq",
            "constanttimeeq",
            "hmac.verify",
            "verify_signature",
        ]
        .iter()
        .any(|g| mask_l.to_ascii_lowercase().contains(g)),
        _ => false,
    }
}

fn is_intrinsic_safe_seam_call(seam_kind: &str, raw_seam: &str, mask_seam: &str) -> bool {
    match seam_kind {
        "PATH_LFI" => ["resolveInside(", "read_regular_file_fd_verified(", "read_regular_bytes_fd_verified(", "readSanitizedOutboundFileS3(", "assert_not_symlink(", "O_NOFOLLOW", "RESOLVE_BENEATH"]
            .iter().any(|g| mask_seam.contains(g)),
        "STATE_MUTATION" => ["writeJsonAtomic(", "atomicWriteJsonS3(", "atomic_write", "locked_cortex_transaction("].iter().any(|g| mask_seam.contains(g)),
        "SQL_EXEC" => {
            let no_concat = !mask_seam.contains('+')
                && !mask_seam.contains('%')
                && !mask_seam.contains(".format(")
                && !mask_seam.contains("format!(")
                && !raw_seam.contains("${");
            let safe_prep = mask_seam.contains("prepareStatement(") && no_concat
                && (raw_seam.contains("prepareStatement(\"") || raw_seam.contains("prepareStatement('"))
                && (raw_seam.contains('?') || extract_sink_arg_vars(raw_seam, mask_seam, &["prepareStatement("]).is_empty());
            let safe_exec = no_concat && (raw_seam.contains(".execute(\"") || raw_seam.contains(".execute('"))
                && (raw_seam.contains('?') || raw_seam.contains("%s") || raw_seam.contains("$1")) && raw_seam.contains(',');
            safe_prep || safe_exec
        }
        "CRYPTO_VERIFY" => ["compare_digest(", "timingSafeEqual(", "createHash(", "hashlib.sha256(", "hmac.new(", "hmac.digest("].iter().any(|g| mask_seam.contains(g)),
        _ => false,
    }
}

fn grade_seam_window(
    hit: LegacySeamHit, seam_offset: usize, win_start_line0: usize,
    raw_win: &[&str], masked_win: &[String], file_ignored: bool,
) -> (SeamTier, bool, Option<SeamEvidence>) {
    let seam_kind = hit.kind;
    let has_ignore = file_ignored || raw_win.iter().any(|wl| wl.to_ascii_lowercase().contains("kintsugi: ignore"));
    let raw_exposed_s0 = raw_win.iter().zip(masked_win.iter()).any(|(raw_l, mask_l)| {
        let (wt, mt) = (raw_l.trim(), mask_l.trim());
        if mt.is_empty() || is_fixture_definition_line(wt) { return false; }
        match seam_kind {
            "CMD_EXEC" => (has_unquoted_call(wt, "shell=") && has_unsafe_shell_kwarg(wt))
                || has_unquoted_call(wt, "shell: true") || ["os.system(", "os.popen(", "child_process.exec("].iter().any(|k| mt.contains(k)) || has_bare_call(mt, "eval("),
            "SQL_EXEC" => has_sql_fstring_or_concat(wt, mt),
            "CRYPTO_VERIFY" => has_unsafe_hmac_secret_eq(mt),
            _ => false,
        }
    });
    if raw_exposed_s0 { return if has_ignore { (SeamTier::Unproven, true, None) } else { (SeamTier::ExposedS0, false, None) }; }
    if file_ignored { return (SeamTier::Unproven, true, None); }

    let seam_line = win_start_line0 + seam_offset + 1;
    let seam_col = hit.start_byte + 1;
    let full_raw_seam = raw_win[seam_offset];
    let full_mask_seam = masked_win[seam_offset].as_str();
    let (raw_seam, mask_seam) = if hit.start_byte < hit.end_byte
        && hit.end_byte <= full_mask_seam.len()
        && full_mask_seam.is_char_boundary(hit.start_byte)
        && full_mask_seam.is_char_boundary(hit.end_byte)
    {
        let r_end = hit.end_byte.min(full_raw_seam.len());
        let r_slice = if hit.start_byte <= r_end
            && full_raw_seam.is_char_boundary(hit.start_byte)
            && full_raw_seam.is_char_boundary(r_end)
        {
            &full_raw_seam[hit.start_byte..r_end]
        } else {
            full_raw_seam
        };
        (r_slice, &full_mask_seam[hit.start_byte..hit.end_byte])
    } else {
        (full_raw_seam, full_mask_seam)
    };
    let seam_vars: Vec<String> = extract_var_tokens(mask_seam).into_iter().take(6).collect();

    match seam_kind {
        "CMD_EXEC" => {
            let end_call = raw_win.len().min(seam_offset + 4);
            let raw_call = &raw_win[seam_offset..end_call];
            let is_rust_sh_c = mask_seam.contains("Command::new(")
                && raw_call.iter().any(|r| ["\"sh\"", "\"/bin/sh\"", "\"bash\"", "\"zsh\""].iter().any(|s| r.contains(s))) && raw_call.iter().any(|r| r.contains("\"-c\""));
            let guard_off = (seam_offset..end_call)
                .find(|&gi| { let wt = raw_win[gi].trim(); has_unquoted_call(wt, "shell=False") || has_unquoted_call(wt, "shell: false") })
                .or_else(|| (["execFile(", "execFileSync(", "authorizeCommand("].iter().any(|g| mask_seam.contains(g))
                    || (mask_seam.contains("Command::new(") && !is_rust_sh_c)).then_some(seam_offset))
                .or_else(|| (0..seam_offset).rev().find(|&gi| masked_win[gi].contains("authorizeCommand(") || masked_win[gi].contains("escapeshellarg")));
            if let Some(goff) = guard_off {
                return (SeamTier::ProvenS3, false, Some(SeamEvidence { seam_line, seam_col, guard_line: win_start_line0 + goff + 1, seam_kind, bound_vars: seam_vars }));
            }
        }
        "PATH_LFI" | "STATE_MUTATION" | "SQL_EXEC" | "CRYPTO_VERIFY" => {
            if is_intrinsic_safe_seam_call(seam_kind, raw_seam, mask_seam) {
                return (SeamTier::ProvenS3, false, Some(SeamEvidence { seam_line, seam_col, guard_line: seam_line, seam_kind, bound_vars: seam_vars }));
            }
            let sink_needles: &[&str] = match seam_kind {
                "PATH_LFI" => &["canonicalize(", "realpathSync(", "lstatSync(", "symlink_metadata(", "os.open(", "fs.readFileSync(", "open("],
                "STATE_MUTATION" => &["writeFileSync("],
                "SQL_EXEC" => &["prepareStatement(", ".executemany(", ".execute(", "executeQuery(", "mysqli_query(", "mysql_query("],
                _ => &["hmac.new(", "hmac.digest("],
            };
            let mut bound_candidates = extract_sink_arg_vars(raw_seam, mask_seam, sink_needles);
            if mask_seam.contains("prepareStatement(") {
                bound_candidates.extend(extract_var_tokens(mask_seam));
            }

            let mut canonical_points: Vec<(usize, BTreeSet<String>)> = Vec::new();
            if seam_kind == "PATH_LFI" {
                for ci in 0..seam_offset {
                    if ["canonicalize(", "realpathSync(", "resolveInside(", "lstatSync(", "symlink_metadata("]
                        .iter()
                        .any(|call| masked_win[ci].contains(call))
                    {
                        let vars = extract_sink_arg_vars(
                            raw_win[ci],
                            &masked_win[ci],
                            &["canonicalize(", "realpathSync(", "resolveInside(", "lstatSync(", "symlink_metadata("],
                        )
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                        if !vars.is_empty() {
                            canonical_points.push((ci, vars));
                        }
                    }
                }
            }

            for gi in 0..=seam_offset {
                if line_matches_guard(seam_kind, raw_win[gi], &masked_win[gi]) {
                    let guard_vars = extract_var_tokens(&masked_win[gi]);
                    let linked_canonical = canonical_points.iter().any(|(ci, canon_vars)| {
                        *ci < gi && !canon_vars.is_disjoint(&guard_vars)
                    });
                    if !canonical_points.is_empty() && !linked_canonical {
                        continue;
                    }

                    let shared: Vec<String> = guard_vars
                        .into_iter()
                        .filter(|v| bound_candidates.contains(v))
                        .take(6)
                        .collect();
                    let guard_binds_sink = if seam_kind == "PATH_LFI" {
                        !shared.is_empty()
                    } else {
                        bound_candidates.is_empty() || !shared.is_empty()
                    };
                    if guard_binds_sink {
                        let bvars = if shared.is_empty() { seam_vars } else { shared };
                        return (
                            SeamTier::ProvenS3,
                            false,
                            Some(SeamEvidence {
                                seam_line,
                                seam_col,
                                guard_line: win_start_line0 + gi + 1,
                                seam_kind,
                                bound_vars: bvars,
                            }),
                        );
                    }
                }
            }
        }
        _ => {}
    }
    (SeamTier::Unproven, false, None)
}

fn s3_failing_reason_and_hint(seam_kind: &'static str, exposed_s0: bool) -> (&'static str, &'static str) {
    match (seam_kind, exposed_s0) {
        ("CMD_EXEC", true) => (
            "unsafe shell=True or command-string execution",
            "Use argv list with shell=False (or Command::new without sh -c)",
        ),
        ("CMD_EXEC", false) => (
            "missing explicit shell=False or command allowlist guard near call",
            "Pass shell=False on subprocess call or authorizeCommand() before spawn",
        ),
        ("SQL_EXEC", true) => (
            "dynamic SQL interpolation (+/%/.format/f-string)",
            "Use static literal SQL string with parameterized placeholder (?, %s, $1)",
        ),
        ("SQL_EXEC", false) => (
            "missing static parameterized SQL placeholder proof",
            "Pass static SQL literal with ?/%s/$1 and bind tuple/params on .execute()",
        ),
        ("PATH_LFI", _) => (
            "missing canonicalize/realpath linked with starts_with/O_NOFOLLOW guard before open",
            "Canonicalize path with realpath/canonicalize and check starts_with/O_NOFOLLOW on the same var",
        ),
        ("STATE_MUTATION", _) => (
            "missing atomic write or 0o600 confinement lock",
            "Use tempfile + 0o600 + os.replace / writeJsonAtomic / atomicWriteJsonS3",
        ),
        ("CRYPTO_VERIFY", true) => (
            "non-constant-time ==/!= comparison on secret/HMAC signature",
            "Use hmac.compare_digest() or crypto.timingSafeEqual()",
        ),
        ("CRYPTO_VERIFY", false) => (
            "missing constant-time verification guard near HMAC/crypto seam",
            "Verify signatures via hmac.compare_digest() / timingSafeEqual()",
        ),
        _ => (
            "unproven security seam under strict S3 audit",
            "Prove all seams with canonical S3 parameterization/confinement locks",
        ),
    }
}

pub fn s3_audit_file(file: &Path, display_root: Option<&Path>) -> Option<S3FileAudit> {
    s3_audit_file_with_mode(file, display_root, false)
}

pub fn s3_audit_file_with_mode(file: &Path, display_root: Option<&Path>, strict_proven: bool) -> Option<S3FileAudit> {
    let t0 = Instant::now();
    let content = read_regular_file_fd_verified(file, MAX_SOURCE_FILE_BYTES).ok()?;
    let sha_hex = sha256_hex(content.as_bytes())[..16].to_string();
    let lines: Vec<&str> = content.lines().collect();
    let file_ignored = lines.iter().take(8).any(|hl| {
        let s = hl.trim_start_matches('\u{feff}').trim_start();
        (s.starts_with('#') || s.starts_with("//") || s.starts_with("/*")) && s.to_ascii_lowercase().contains("kintsugi: ignore-file")
    });
    let masked_lines = StatefulMasker::mask_file_lines(&content);

    let (mut fn_count, mut cls_count, mut ignored_override) = (0usize, 0usize, file_ignored);
    let (mut total_seams, mut proven_s3, mut unproven, mut unguarded_s0, mut unsupported_seams) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut evidence_chains = Vec::new();
    let mut failing_seams = Vec::new();

    // Kintsugi v3.0 Typed Obligation Prover handles CMD_EXEC, SQL_EXEC, and extended obligations
    // (TSX_XSS, PATH_CONFINE, CRYPTO_MAC_BIDI, SOL_REENTRANCY_CEI, SOL_SAFE_ERC20).
    let obligations = prove_file_obligations(file, &content, &masked_lines);
    let mut ob_suppressed_legacy: Vec<LegacySuppression> = Vec::new();
    for ob in &obligations {
        let line_idx0 = ob.sink_span.start_line.saturating_sub(1);
        let span_start_col = ob.sink_span.start_col.max(1);
        let span_end_col = if ob.sink_span.end_line > ob.sink_span.start_line {
            lines.get(line_idx0).map_or(usize::MAX, |s| s.len().max(span_start_col))
        } else {
            ob.sink_span.end_col.max(span_start_col)
        };
        let ob_paren_col = masked_lines
            .get(line_idx0)
            .and_then(|ml| {
                let s0 = span_start_col.saturating_sub(1);
                ml.get(s0..)?.find('(').map(|rel| s0 + rel + 1)
            })
            .unwrap_or(span_start_col);
        match ob.rule {
            "CMD_EXEC" | "SQL_EXEC" => {
                ob_suppressed_legacy.push(LegacySuppression::ExactCall {
                    line: line_idx0,
                    start_col: span_start_col,
                    paren_col: span_start_col,
                    kind: ob.rule,
                });
            }
            "PATH_CONFINE" => {
                ob_suppressed_legacy.push(LegacySuppression::ExactCall {
                    line: line_idx0,
                    start_col: span_start_col,
                    paren_col: ob_paren_col,
                    kind: "PATH_LFI",
                });
                // Only suppress legacy STATE_MUTATION when atomic write or 0o600 confinement is genuinely proven.
                let sink_raw = lines.get(line_idx0).copied().unwrap_or("");
                let sink_mask = masked_lines.get(line_idx0).map(|s| s.as_str()).unwrap_or("");
                let atomic_proven = is_intrinsic_safe_seam_call("STATE_MUTATION", sink_raw, sink_mask)
                    || (line_idx0.saturating_sub(6)..=line_idx0).any(|l| {
                        let rl = lines.get(l).copied().unwrap_or("");
                        let ml = masked_lines.get(l).map(|s| s.as_str()).unwrap_or("");
                        line_matches_guard("STATE_MUTATION", rl, ml)
                    });
                if atomic_proven {
                    ob_suppressed_legacy.push(LegacySuppression::ExactCall {
                        line: line_idx0,
                        start_col: span_start_col,
                        paren_col: ob_paren_col,
                        kind: "STATE_MUTATION",
                    });
                }
                // Suppress ONLY exact canonicalize/lstat helper calls on supporting lines, NEVER intermediate or nested open() calls.
                let lo = ob.witness_span.map(|w| w.start_line.saturating_sub(1)).unwrap_or(line_idx0).min(line_idx0);
                let scan_lo = lo.min(line_idx0.saturating_sub(8));
                for l in scan_lo..line_idx0 {
                    let lm = masked_lines.get(l).map(|s| s.as_str()).unwrap_or("");
                    for helper in ["realpathSync(", "lstatSync(", "canonicalize(", "symlink_metadata("] {
                        let mut from = 0usize;
                        while from < lm.len() {
                            let Some(rel) = lm[from..].find(helper) else { break };
                            let pos = from + rel;
                            let pb = pos + helper.len() - 1;
                            ob_suppressed_legacy.push(LegacySuppression::ExactCall {
                                line: l,
                                start_col: pos + 1,
                                paren_col: pb + 1,
                                kind: "PATH_LFI",
                            });
                            from = pos + helper.len();
                        }
                    }
                }
            }
            "CRYPTO_MAC_BIDI" => {
                // Suppress ONLY the exact sink and witness spans, never intermediate lines between them.
                ob_suppressed_legacy.push(LegacySuppression::ColRange {
                    line: line_idx0,
                    start_col: span_start_col,
                    end_col: span_end_col,
                    kind: "CRYPTO_VERIFY",
                });
                if let Some(w) = ob.witness_span {
                    let w0 = w.start_line.saturating_sub(1);
                    let w_start = w.start_col.max(1);
                    let w_end = if w.end_line > w.start_line {
                        lines.get(w0).map_or(usize::MAX, |s| s.len().max(w_start))
                    } else {
                        w.end_col.max(w_start)
                    };
                    ob_suppressed_legacy.push(LegacySuppression::ColRange {
                        line: w0,
                        start_col: w_start,
                        end_col: w_end,
                        kind: "CRYPTO_VERIFY",
                    });
                }
            }
            _ => {}
        }
        total_seams += 1;
        let win_lo = line_idx0.saturating_sub(2).min(lines.len());
        let win_hi = (line_idx0 + 2).min(lines.len());
        let line_ignored = file_ignored
            || lines[win_lo..win_hi]
                .iter()
                .any(|wl| wl.to_ascii_lowercase().contains("kintsugi: ignore"));
        if line_ignored {
            ignored_override = true;
            unproven += 1;
            failing_seams.push(FailingSeam {
                seam_line: ob.sink_span.start_line,
                seam_col: span_start_col,
                seam_kind: ob.rule,
                tier: "UNPROVEN",
                reason: "inline kintsugi: ignore override quarantined",
                fix_hint: ob.fix_hint,
            });
            continue;
        }
        match ob.state {
            ObligationState::Proven => {
                proven_s3 += 1;
                let guard_line = ob.witness_span.map(|w| w.start_line).unwrap_or(ob.sink_span.start_line);
                let bound_vars = ob.binding.iter().cloned().collect();
                evidence_chains.push(SeamEvidence {
                    seam_line: ob.sink_span.start_line,
                    seam_col: span_start_col,
                    guard_line,
                    seam_kind: ob.rule,
                    bound_vars,
                });
            }
            ObligationState::Violated => {
                unguarded_s0 += 1;
                failing_seams.push(FailingSeam {
                    seam_line: ob.sink_span.start_line,
                    seam_col: span_start_col,
                    seam_kind: ob.rule,
                    tier: "S0_EXPOSED",
                    reason: ob.reason,
                    fix_hint: ob.fix_hint,
                });
            }
            ObligationState::Unknown => {
                unproven += 1;
                failing_seams.push(FailingSeam {
                    seam_line: ob.sink_span.start_line,
                    seam_col: span_start_col,
                    seam_kind: ob.rule,
                    tier: "UNPROVEN",
                    reason: ob.reason,
                    fix_hint: ob.fix_hint,
                });
            }
            ObligationState::Unsupported => {
                unsupported_seams += 1;
                unproven += 1;
                failing_seams.push(FailingSeam {
                    seam_line: ob.sink_span.start_line,
                    seam_col: span_start_col,
                    seam_kind: ob.rule,
                    tier: "UNSUPPORTED",
                    reason: ob.reason,
                    fix_hint: ob.fix_hint,
                });
            }
        }
    }

    let mut seen_legacy: BTreeSet<(usize, usize, &'static str)> = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let mt = masked_lines[idx].trim();
        if ["def ", "async def ", "function ", "async function ", "export function ", "export async function ", "pub fn ", "fn "].iter().any(|p| mt.starts_with(p)) { fn_count += 1; }
        if ["class ", "export class ", "pub struct ", "struct ", "contract ", "library ", "interface "].iter().any(|p| mt.starts_with(p)) { cls_count += 1; }
        for hit in classify_s3_seam_occurrences(line, &masked_lines[idx]) {
            let seam_col = hit.start_byte + 1;
            let paren_col = hit.paren_byte + 1;
            // Skip legacy seams whose exact call identity is already graded by the v3 Typed Obligation Prover
            let suppressed = ob_suppressed_legacy.iter().any(|sup| match *sup {
                LegacySuppression::ExactCall { line, start_col, paren_col: ob_pcol, kind } => {
                    line == idx && kind == hit.kind && (seam_col == start_col || paren_col == ob_pcol)
                }
                LegacySuppression::ColRange { line, start_col, end_col, kind } => {
                    line == idx
                        && kind == hit.kind
                        && ((seam_col >= start_col && seam_col <= end_col)
                            || (paren_col >= start_col && paren_col <= end_col))
                }
            });
            if suppressed || !seen_legacy.insert((idx, seam_col, hit.kind)) {
                continue;
            }
            total_seams += 1;
            let (win_start, win_end) = (idx.saturating_sub(6), (idx + 7).min(lines.len()));
            let (tier, used_ignore, ev_opt) = grade_seam_window(hit, idx - win_start, win_start, &lines[win_start..win_end], &masked_lines[win_start..win_end], file_ignored);
            if used_ignore { ignored_override = true; }
            if let Some(ev) = ev_opt { evidence_chains.push(ev); }
            match tier {
                SeamTier::ExposedS0 => {
                    unguarded_s0 += 1;
                    let (reason, fix_hint) = s3_failing_reason_and_hint(hit.kind, true);
                    failing_seams.push(FailingSeam { seam_line: idx + 1, seam_col, seam_kind: hit.kind, tier: "S0_EXPOSED", reason, fix_hint });
                }
                SeamTier::ProvenS3 => proven_s3 += 1,
                SeamTier::Unproven => {
                    unproven += 1;
                    let (reason, fix_hint) = s3_failing_reason_and_hint(hit.kind, false);
                    failing_seams.push(FailingSeam { seam_line: idx + 1, seam_col, seam_kind: hit.kind, tier: "UNPROVEN", reason, fix_hint });
                }
            }
        }
    }

    let rel_display = display_root.and_then(|root| file.strip_prefix(root).ok()).unwrap_or(file).to_string_lossy().to_string();
    let (assurance_tier, verdict, strict_verdict) = compute_s3_verdicts(unguarded_s0, unproven, ignored_override, strict_proven);

    Some(S3FileAudit {
        file_path: rel_display, manifest_sha: sha_hex, elapsed_ms: (t0.elapsed().as_micros() as f64) / 1000.0,
        functions_count: fn_count, classes_count: cls_count, total_seams,
        s3_locked_seams: proven_s3, proven_s3_seams: proven_s3, unproven_seams: unproven, unguarded_s0_seams: unguarded_s0,
        ignored_override, assurance_tier, verdict, strict_verdict, evidence_chains, failing_seams,
        obligations, unsupported_seams,
    })
}

pub fn s3_audit_path(target: &Path) -> S3AuditSummary { s3_audit_path_with_mode(target, false) }

pub fn s3_audit_path_with_mode(target: &Path, strict_proven: bool) -> S3AuditSummary {
    let t0 = Instant::now();
    let target_display = target.to_string_lossy().to_string();
    let mut missing_targets = Vec::new();
    let has_parent_dir = target.components().any(|c| matches!(c, std::path::Component::ParentDir));
    let sym_meta = std::fs::symlink_metadata(target);
    let target_meta = std::fs::metadata(target);
    let target_unreadable = if has_parent_dir {
        true
    } else {
        match (&sym_meta, &target_meta) {
            (Ok(sm), Ok(tm)) => {
                if sm.file_type().is_symlink() {
                    true
                } else if tm.is_dir() {
                    std::fs::read_dir(target).is_err()
                } else {
                    !tm.is_file()
                }
            }
            _ => true,
        }
    };

    let mut files = Vec::new();
    if !target_unreadable {
        collect_files(target, &mut files);
    }
    let base_root = if target.is_dir() { Some(target) } else { target.parent() };

    let mut audits = Vec::new();
    let (mut total_functions, mut total_classes, mut ignored_override_files) = (0usize, 0usize, 0usize);
    let (mut total_seams, mut proven_s3_seams, mut unproven_seams, mut unguarded_s0_seams) = (0, 0, 0, 0);

    for f in files {
        if let Some(a) = s3_audit_file_with_mode(&f, base_root, strict_proven) {
            total_functions += a.functions_count;
            total_classes += a.classes_count;
            total_seams += a.total_seams;
            proven_s3_seams += a.proven_s3_seams;
            unproven_seams += a.unproven_seams;
            unguarded_s0_seams += a.unguarded_s0_seams;
            if a.ignored_override { ignored_override_files += 1; }
            audits.push(a);
        }
    }

    if target_unreadable || audits.is_empty() {
        missing_targets.push(target_display.clone());
    }

    let ignored_override = ignored_override_files > 0;
    let (assurance_tier, verdict, strict_verdict) = if !missing_targets.is_empty() {
        ("NO_INPUT", "FAIL_NO_INPUT", "NO_INPUT")
    } else {
        compute_s3_verdicts(unguarded_s0_seams, unproven_seams, ignored_override, strict_proven)
    };

    S3AuditSummary {
        target: target_display, strict_proven, files_scanned: audits.len(),
        total_functions, total_classes, total_seams, s3_locked_seams: proven_s3_seams, proven_s3_seams,
        unproven_seams, unguarded_s0_seams, ignored_override, ignored_override_files, missing_targets,
        elapsed_ms: (t0.elapsed().as_micros() as f64) / 1000.0, assurance_tier, verdict, strict_verdict, files: audits,
    }
}

pub fn render_s3_audit_json(rep: &S3AuditSummary) -> String {
    let (mut files_arr, mut total_ev) = (JsonArr::with_capacity(rep.files.len().saturating_mul(320)), 0usize);
    for f in &rep.files {
        total_ev += f.evidence_chains.len();
        let mut ev_arr = JsonArr::new();
        for ev in f.evidence_chains.iter().take(8) {
            let mut bv = JsonArr::new();
            for v in &ev.bound_vars { bv = bv.str(v); }
            ev_arr = ev_arr.obj(
                JsonObj::new()
                    .usize("seam_line", ev.seam_line)
                    .usize("seam_col", ev.seam_col)
                    .usize("guard_line", ev.guard_line)
                    .str("seam_kind", ev.seam_kind)
                    .arr("bound_vars", bv),
            );
        }
        let mut fail_arr = JsonArr::new();
        for fs in f.failing_seams.iter().take(16) {
            fail_arr = fail_arr.obj(
                JsonObj::new()
                    .usize("seam_line", fs.seam_line)
                    .usize("seam_col", fs.seam_col)
                    .str("seam_kind", fs.seam_kind)
                    .str("tier", fs.tier)
                    .str("reason", fs.reason)
                    .str("fix_hint", fs.fix_hint),
            );
        }
        let mut ob_arr = JsonArr::new();
        for ob in f.obligations.iter().take(24) {
            let mut oobj = JsonObj::new()
                .str("rule", ob.rule)
                .str("lang", ob.lang)
                .str("state", ob.state.as_str())
                .usize("start_line", ob.sink_span.start_line)
                .usize("end_line", ob.sink_span.end_line)
                .str("source_hash", &ob.source_hash)
                .str("reason", ob.reason);
            if let Some(w) = ob.witness_span {
                oobj = oobj.usize("witness_line", w.start_line);
            }
            if let Some(b) = &ob.binding {
                oobj = oobj.str("binding", b);
            }
            ob_arr = ob_arr.obj(oobj);
        }
        files_arr = files_arr.obj(
            JsonObj::with_capacity(480)
                .str("file_path", &f.file_path).str("manifest_sha", &f.manifest_sha).f64_3("elapsed_ms", f.elapsed_ms)
                .usize("functions_count", f.functions_count).usize("classes_count", f.classes_count)
                .usize("total_seams", f.total_seams).usize("s3_locked_seams", f.s3_locked_seams)
                .usize("proven_s3_seams", f.proven_s3_seams).usize("unproven_seams", f.unproven_seams)
                .usize("unsupported_seams", f.unsupported_seams)
                .usize("unguarded_s0_seams", f.unguarded_s0_seams).bool("ignored_override", f.ignored_override)
                .usize("evidence_chains_count", f.evidence_chains.len()).arr("evidence_sample", ev_arr)
                .usize("failing_seams_count", f.failing_seams.len()).arr("failing_seams", fail_arr)
                .usize("obligations_count", f.obligations.len()).arr("obligations", ob_arr)
                .str("assurance_tier", f.assurance_tier).str("verdict", f.verdict).str("strict_verdict", f.strict_verdict),
        );
    }
    let mut missing_arr = JsonArr::new();
    for m in &rep.missing_targets {
        missing_arr = missing_arr.str(m);
    }
    JsonObj::with_capacity(780 + rep.files.len().saturating_mul(360))
        .bool("ok", rep.verdict == "PASS_S3_LOCKED").str("schema_version", ENGINE_VERSION)
        .str("engine", "kintsugi-rs").str("engine_version", ENGINE_VERSION)
        .str("auditor_kind", S3_AUDITOR_KIND).str("obligation_prover_kind", OBLIGATION_PROVER_KIND)
        .str("evidence_model", S3_EVIDENCE_MODEL)
        .arr("deprecated_aliases", JsonArr::new().str("s3_locked_seams"))
        .str("target", &rep.target).bool("strict_proven", rep.strict_proven)
        .usize("files_scanned", rep.files_scanned).usize("total_functions", rep.total_functions)
        .usize("total_classes", rep.total_classes).usize("total_seams", rep.total_seams)
        .usize("s3_locked_seams", rep.s3_locked_seams).usize("proven_s3_seams", rep.proven_s3_seams)
        .usize("unproven_seams", rep.unproven_seams).usize("unguarded_s0_seams", rep.unguarded_s0_seams)
        .usize("evidence_chains_count", total_ev)
        .bool("ignored_override", rep.ignored_override).usize("ignored_override_files", rep.ignored_override_files)
        .arr("missing_targets", missing_arr)
        .f64_3("elapsed_ms", rep.elapsed_ms).str("assurance_tier", rep.assurance_tier)
        .str("verdict", rep.verdict).str("strict_verdict", rep.strict_verdict).arr("files", files_arr).finish()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use super::*;
    use crate::json_dom::parse_json_value;

    #[test]
    fn quarantine_ignore_override_strict_confinement_and_evidence_chains() {
        let uniq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let base = std::env::temp_dir().join(format!("kintsugi_s3_v3_{}_{uniq}", std::process::id()));
        fs::create_dir_all(&base).unwrap();

        let bare_canon = base.join("bare_canon.rs");
        fs::write(&bare_canon, "pub fn f(p: &std::path::Path) {\n    let _ = std::fs::canonicalize(p);\n}\n").unwrap();
        let rep_bare = s3_audit_path(&bare_canon);
        assert_eq!((rep_bare.proven_s3_seams, rep_bare.unproven_seams), (0, 1));
        assert_eq!(rep_bare.files[0].failing_seams.len(), 1);
        assert_eq!(rep_bare.files[0].failing_seams[0].seam_line, 2);
        assert_eq!(rep_bare.files[0].failing_seams[0].seam_kind, "PATH_LFI");

        let confined = base.join("confined.py");
        fs::write(&confined, "import os\ndef f(root, p):\n    p = os.path.realpath(p)\n    assert p.startswith(root)\n    return open(p)\n").unwrap();
        let r_conf = s3_audit_path_with_mode(&confined, true);
        assert_eq!((r_conf.verdict, r_conf.strict_verdict, r_conf.files[0].evidence_chains.len()), ("PASS_S3_LOCKED", "PASS_S3_PROVEN", r_conf.proven_s3_seams));

        let ign_py = base.join("ignored.py");
        fs::write(&ign_py, "// kintsugi: ignore-file\nimport os\nos.system(cmd)\n").unwrap();
        assert_eq!(s3_audit_path(&ign_py).verdict, "QUARANTINED_IGNORE_OVERRIDE");
        assert_eq!(s3_audit_path_with_mode(&ign_py, true).verdict, "QUARANTINED_IGNORE_OVERRIDE");
        assert!(parse_json_value(&render_s3_audit_json(&r_conf)).is_ok());
        let _ = fs::remove_dir_all(&base);
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let uniq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("kintsugi_s3_{tag}_{}_{uniq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn assert_not_proven(rep: &S3AuditSummary, label: &str) {
        assert_eq!(rep.proven_s3_seams, 0, "{label}: must never be ProvenS3");
        assert!(rep.unguarded_s0_seams >= 1 || rep.unproven_seams >= 1, "{label}: seam must be flagged S0 or unproven");
        assert_ne!(rep.verdict, "PASS_S3_LOCKED", "{label}: verdict must not pass");
        assert_ne!(rep.strict_verdict, "PASS_S3_PROVEN", "{label}: strict verdict must not pass");
    }

    #[test]
    fn sql_percent_and_format_interpolation_never_proven() {
        let base = scratch_dir("sqlfmt");
        let pct = base.join("sql_pct.py");
        fs::write(&pct, "def q(cur, a, b):\n    cur.execute(\"SELECT * FROM u WHERE n='%s'\" % (a, b))\n").unwrap();
        assert_not_proven(&s3_audit_path(&pct), "sql %-format");
        assert_not_proven(&s3_audit_path_with_mode(&pct, true), "sql %-format strict");

        let fmt = base.join("sql_fmt.py");
        fs::write(&fmt, "def q(cur, a):\n    cur.execute(\"SELECT * FROM u WHERE n='{}'\".format(a))\n").unwrap();
        assert_not_proven(&s3_audit_path(&fmt), "sql .format");
        assert_not_proven(&s3_audit_path_with_mode(&fmt, true), "sql .format strict");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn hmac_double_bypass_len_then_eq_is_unguarded_s0() {
        let base = scratch_dir("hmac");
        let f = base.join("hmac_cmp.py");
        fs::write(&f, "def verify(sig, expected_hmac):\n    if len(sig) == len(expected_hmac) and sig == expected_hmac:\n        return True\n    return False\n").unwrap();
        let rep = s3_audit_path_with_mode(&f, true);
        assert_eq!(rep.unguarded_s0_seams, 1);
        assert_eq!(rep.proven_s3_seams, 0);
        assert_ne!(rep.verdict, "PASS_S3_LOCKED");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn late_guard_and_name_only_guard_not_promoted() {
        let base = scratch_dir("fakeguard");
        let late = base.join("late_guard.py");
        fs::write(&late, "import os\ndef f(root, p):\n    fh = open(p)\n    p = os.path.realpath(p)\n    assert p.startswith(root)\n    return fh\n").unwrap();
        let r_late = s3_audit_path_with_mode(&late, true);
        assert_eq!(r_late.proven_s3_seams, 0, "guard after sink must not prove the seam");
        assert_ne!(r_late.strict_verdict, "PASS_S3_PROVEN");

        let alias = base.join("name_only.py");
        fs::write(&alias, "import os\nclass C:\n    def f(self, p):\n        os.getcwd()\n        self.checked = True\n        return open(p)\n").unwrap();
        let r_alias = s3_audit_path_with_mode(&alias, true);
        assert_eq!(r_alias.proven_s3_seams, 0, "bare os/self mention is not a guard");
        assert_ne!(r_alias.strict_verdict, "PASS_S3_PROVEN");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ignore_file_with_zero_seams_still_quarantined() {
        let base = scratch_dir("ign0");
        let f = base.join("ignored_clean.py");
        fs::write(&f, "# kintsugi: ignore-file\nx = 1 + 2\n").unwrap();
        for strict in [false, true] {
            let rep = s3_audit_path_with_mode(&f, strict);
            assert_eq!(rep.total_seams, 0);
            assert!(rep.ignored_override);
            assert_eq!(rep.ignored_override_files, 1);
            assert_eq!(rep.verdict, "QUARANTINED_IGNORE_OVERRIDE");
            assert_eq!(rep.strict_verdict, "QUARANTINED_IGNORE_OVERRIDE");
            let json = render_s3_audit_json(&rep);
            assert!(parse_json_value(&json).is_ok());
            assert!(json.contains("\"ok\":false"), "quarantined report must never be ok");
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn extended_obligations_grade_seamlessly_in_s3_with_zero_double_count() {
        let base = scratch_dir("ext_obs");
        let safe_hmac = base.join("safe_hmac.py");
        fs::write(&safe_hmac, "import hmac, hashlib\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return hmac.compare_digest(sig, mac)\n").unwrap();
        let r_h = s3_audit_path_with_mode(&safe_hmac, true);
        assert_eq!((r_h.proven_s3_seams, r_h.unguarded_s0_seams, r_h.unproven_seams), (1, 0, 0));
        assert_eq!(r_h.strict_verdict, "PASS_S3_PROVEN");

        let bad_hmac = base.join("bad_hmac.py");
        fs::write(&bad_hmac, "import hmac, hashlib\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return sig == mac\n").unwrap();
        let r_bh = s3_audit_path_with_mode(&bad_hmac, true);
        assert_eq!((r_bh.proven_s3_seams, r_bh.unguarded_s0_seams), (0, 1));
        assert_eq!(r_bh.verdict, "FAIL_S0_EXPOSED");

        let bad_sib = base.join("sib_write.py");
        fs::write(&bad_sib, "import os\ndef save(root, rel, d):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    if not t.startswith(r): raise ValueError()\n    with open(t, 'w') as f: f.write(d)\n").unwrap();
        let r_sib = s3_audit_path_with_mode(&bad_sib, true);
        assert_eq!((r_sib.proven_s3_seams, r_sib.unguarded_s0_seams), (0, 1));
        assert_eq!(r_sib.verdict, "FAIL_S0_EXPOSED");

        let sol_bad = base.join("Vault.sol");
        fs::write(&sol_bad, "contract V {\n  function withdraw(uint256 a) external {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n    balances[msg.sender] -= a;\n  }\n}\n").unwrap();
        let r_sol = s3_audit_path_with_mode(&sol_bad, true);
        assert_eq!((r_sol.proven_s3_seams, r_sol.unguarded_s0_seams), (0, 1));
        assert_eq!(r_sol.verdict, "FAIL_S0_EXPOSED");

        let tsx_mixed = base.join("App.tsx");
        fs::write(&tsx_mixed, "import DOMPurify from 'dompurify';\nexport function App({ h, db, id }: any) {\n  db.query('SELECT 1 WHERE id = ?', [id]);\n  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />;\n}\n").unwrap();
        let r_tsx = s3_audit_path_with_mode(&tsx_mixed, true);
        assert_eq!(r_tsx.proven_s3_seams, 1);
        assert_eq!(r_tsx.files[0].unsupported_seams, 1);
        assert!(parse_json_value(&render_s3_audit_json(&r_tsx)).is_ok());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn legacy_suppression_does_not_hide_intermediate_lfi_state_mutation_or_secret_eq() {
        let base = scratch_dir("suppression_soundness");

        // PoC #7a: Intermediate unguarded open(evil_read) inside a PATH_CONFINE function MUST NOT be suppressed!
        let mid_open = base.join("mid_open.py");
        fs::write(
            &mid_open,
            "import os\ndef save(root, rel, evil_read, d):\n    r = os.path.realpath(root)\n    leaked = open(evil_read).read()\n    t = os.path.realpath(os.path.join(r, rel))\n    if not t.startswith(r + os.sep) or os.path.islink(t): raise ValueError()\n    with open(t, 'w') as f: f.write(d + leaked)\n",
        )
        .unwrap();
        let r_open = s3_audit_path_with_mode(&mid_open, true);
        assert!(
            r_open.files[0].failing_seams.iter().any(|f| f.seam_kind == "PATH_LFI" && f.seam_line == 4),
            "intermediate open(evil_read) on line 4 must not be suppressed: {:?}",
            r_open.files[0].failing_seams
        );
        assert_ne!(r_open.strict_verdict, "PASS_S3_PROVEN");

        // PoC #7b: Bare writeFileSync without atomic write / 0o600 MUST keep STATE_MUTATION unsuppressed!
        let bare_wfs = base.join("bare_wfs.ts");
        fs::write(
            &bare_wfs,
            "import fs from 'fs';\nimport path from 'path';\nfunction save(root: string, rel: string, data: string) {\n  const r = fs.realpathSync(root);\n  const t = fs.realpathSync(path.join(r, rel));\n  if (!t.startsWith(r + path.sep) || fs.lstatSync(t).isSymbolicLink()) throw new Error('esc');\n  fs.writeFileSync(t, data);\n}\n",
        )
        .unwrap();
        let r_wfs = s3_audit_path_with_mode(&bare_wfs, true);
        assert!(
            r_wfs.files[0].failing_seams.iter().any(|f| f.seam_kind == "STATE_MUTATION" && f.seam_line == 7),
            "writeFileSync without atomic write / 0o600 must still report STATE_MUTATION: {:?}",
            r_wfs.files[0].failing_seams
        );
        assert_ne!(r_wfs.strict_verdict, "PASS_S3_PROVEN");

        // PoC #7c: Intermediate `if caller_token == api_secret:` between hmac.new() and compare_digest() MUST be caught as S0_EXPOSED!
        let mid_sec = base.join("mid_secret.py");
        fs::write(
            &mid_sec,
            "import hmac, hashlib\ndef verify(k, m, sig, caller_token, api_secret):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    if caller_token == api_secret:\n        return True\n    return hmac.compare_digest(sig, mac)\n",
        )
        .unwrap();
        let r_sec = s3_audit_path_with_mode(&mid_sec, true);
        assert!(r_sec.unguarded_s0_seams >= 1, "intermediate caller_token == api_secret must be S0_EXPOSED");
        assert_eq!(r_sec.verdict, "FAIL_S0_EXPOSED");
        assert!(
            r_sec.files[0].failing_seams.iter().any(|f| f.tier == "S0_EXPOSED" && f.seam_line == 4),
            "line 4 must be reported as S0_EXPOSED: {:?}",
            r_sec.files[0].failing_seams
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn nonexistent_or_unreadable_target_returns_fail_no_input_never_pass_s3_proven() {
        let missing = Path::new(".kintsugi/nonexistent-review-target.py");
        for strict in [false, true] {
            let rep = s3_audit_path_with_mode(missing, strict);
            assert_eq!(rep.files_scanned, 0);
            assert_eq!(rep.verdict, "FAIL_NO_INPUT");
            assert_eq!(rep.strict_verdict, "NO_INPUT");
            assert_eq!(rep.assurance_tier, "NO_INPUT");
            assert_eq!(rep.missing_targets, vec![".kintsugi/nonexistent-review-target.py".to_string()]);
            assert_ne!(rep.verdict, "PASS_S3_LOCKED");
            assert_ne!(rep.strict_verdict, "PASS_S3_PROVEN");
            let json = render_s3_audit_json(&rep);
            assert!(parse_json_value(&json).is_ok());
            assert!(json.contains("\"ok\":false"), "missing target JSON must not be ok: {json}");
            assert!(json.contains("\"missing_targets\":[\".kintsugi/nonexistent-review-target.py\"]"), "{json}");
        }

        // Valid readable clean file with 0 seams MUST STILL pass S3 cleanly!
        let base = scratch_dir("clean_zero_seams");
        let clean = base.join("model.py");
        fs::write(&clean, "from dataclasses import dataclass\n\n@dataclass\nclass Item:\n    name: str\n    qty: int\n").unwrap();
        let rep_clean = s3_audit_path_with_mode(&clean, true);
        assert_eq!(rep_clean.files_scanned, 1);
        assert_eq!(rep_clean.total_seams, 0);
        assert!(rep_clean.missing_targets.is_empty());
        assert_eq!(rep_clean.verdict, "PASS_S3_LOCKED");
        assert_eq!(rep_clean.strict_verdict, "PASS_S3_PROVEN");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn multi_call_same_line_records_each_distinct_column_seam_and_column_scoped_suppression() {
        let base = scratch_dir("multi_col");

        // Finding #4: `open("a"), open("b")` on ONE line MUST record 2 distinct PATH_LFI seams at distinct columns!
        let x_py = base.join("x.py");
        fs::write(&x_py, "open(\"a\"), open(\"b\")\n").unwrap();
        let rep = s3_audit_path_with_mode(&x_py, true);
        assert_eq!(rep.total_seams, 2, "both open() calls must be counted: {:?}", rep.files[0].failing_seams);
        assert_eq!(rep.unproven_seams, 2);
        assert_eq!(rep.files[0].failing_seams.len(), 2);
        assert_eq!(rep.files[0].failing_seams[0].seam_kind, "PATH_LFI");
        assert_eq!(rep.files[0].failing_seams[1].seam_kind, "PATH_LFI");
        assert_eq!(rep.files[0].failing_seams[0].seam_line, 1);
        assert_eq!(rep.files[0].failing_seams[1].seam_line, 1);
        assert_eq!(rep.files[0].failing_seams[0].seam_col, 1);
        assert_eq!(rep.files[0].failing_seams[1].seam_col, 12);
        assert_ne!(rep.files[0].failing_seams[0].seam_col, rep.files[0].failing_seams[1].seam_col);

        // Guarded 1st open(safe_p) + unguarded 2nd open(evil_p) on ONE line must not promote evil_p!
        let mixed = base.join("mixed_col.py");
        fs::write(
            &mixed,
            "import os\ndef f(root, safe_p, evil_p):\n    safe_p = os.path.realpath(safe_p)\n    assert safe_p.startswith(root)\n    return open(safe_p), open(evil_p)\n",
        )
        .unwrap();
        let rep_mix = s3_audit_path_with_mode(&mixed, true);
        assert_eq!(rep_mix.total_seams, 2);
        assert_eq!(rep_mix.proven_s3_seams, 1);
        assert_eq!(rep_mix.unproven_seams, 1);
        assert_eq!(rep_mix.files[0].failing_seams.len(), 1);
        assert_eq!(rep_mix.files[0].failing_seams[0].seam_line, 5);
        assert_eq!(rep_mix.files[0].failing_seams[0].seam_col, 26);

        // Typed PATH_CONFINE write open(t, 'w') on same line as unguarded read open("a") must NOT suppress open("a")!
        let col_sup = base.join("col_sup.py");
        fs::write(
            &col_sup,
            "import os\ndef save(root, rel, d):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    if not t.startswith(r + os.sep) or os.path.islink(t): raise ValueError()\n    raw = open(\"a\").read(); open(t, 'w').write(d + raw)\n",
        )
        .unwrap();
        let rep_sup = s3_audit_path_with_mode(&col_sup, true);
        assert_eq!(rep_sup.proven_s3_seams, 1, "confined write open(t, 'w') stays PROVEN");
        assert!(
            rep_sup.files[0].failing_seams.iter().any(|f| f.seam_kind == "PATH_LFI" && f.seam_line == 6 && f.seam_col == 11),
            "read-only open(\"a\") at col 11 must remain unsuppressed: {:?}",
            rep_sup.files[0].failing_seams
        );
        assert_ne!(rep_sup.strict_verdict, "PASS_S3_PROVEN");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn parent_dir_and_empty_dir_targets_fail_closed_no_input_never_pass_s3_proven() {
        let base = scratch_dir("parent_dir_no_input");
        let sub = base.join("nested");
        fs::create_dir_all(&sub).unwrap();
        let dotdot = sub.join("..").join("nested");
        for strict in [false, true] {
            let rep_dd = s3_audit_path_with_mode(&dotdot, strict);
            assert_eq!(rep_dd.files_scanned, 0);
            assert_eq!(rep_dd.verdict, "FAIL_NO_INPUT");
            assert_eq!(rep_dd.strict_verdict, "NO_INPUT");
            assert_eq!(rep_dd.assurance_tier, "NO_INPUT");
            assert!(!rep_dd.missing_targets.is_empty());

            let rep_rel = s3_audit_path_with_mode(Path::new("../kintsugi-harness"), strict);
            assert_eq!(rep_rel.files_scanned, 0);
            assert_eq!(rep_rel.verdict, "FAIL_NO_INPUT");
            assert_eq!(rep_rel.strict_verdict, "NO_INPUT");
            assert_eq!(rep_rel.assurance_tier, "NO_INPUT");
            assert_eq!(rep_rel.missing_targets, vec!["../kintsugi-harness".to_string()]);

            // Empty directory with 0 auditable files must ALSO fail closed (NO_INPUT), never PASS_S3_PROVEN!
            let rep_empty = s3_audit_path_with_mode(&sub, strict);
            assert_eq!(rep_empty.files_scanned, 0);
            assert_eq!(rep_empty.verdict, "FAIL_NO_INPUT");
            assert_eq!(rep_empty.strict_verdict, "NO_INPUT");
            assert_eq!(rep_empty.assurance_tier, "NO_INPUT");
            assert!(!rep_empty.missing_targets.is_empty());
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn nested_unguarded_read_inside_path_confine_write_is_never_suppressed() {
        let base = scratch_dir("nested_read_inside_write");

        // Round-2 HIGH #4 (Python): inner `open(evil_p)` inside `open(safe_p, "w", encoding=open(evil_p)...)` MUST remain flagged!
        let py_nested = base.join("nested_py.py");
        fs::write(
            &py_nested,
            "import os\ndef save(root, rel, evil_p, d):\n    r = os.path.realpath(root)\n    safe_p = os.path.realpath(os.path.join(r, rel))\n    if not safe_p.startswith(r + os.sep) or os.path.islink(safe_p): raise ValueError()\n    with open(safe_p, \"w\", encoding=open(evil_p).read().strip()) as f:\n        f.write(d)\n",
        )
        .unwrap();
        let r_py = s3_audit_path_with_mode(&py_nested, true);
        assert_ne!(r_py.strict_verdict, "PASS_S3_PROVEN", "inner open(evil_p) must never be hidden");
        assert!(
            r_py.files[0].failing_seams.iter().any(|f| f.seam_kind == "PATH_LFI" && f.seam_line == 6),
            "expected failing PATH_LFI seam for inner open(evil_p) on line 6: {:?}",
            r_py.files[0].failing_seams
        );

        // Round-2 HIGH #4 (JS/TS): inner `fs.readFileSync(evil_p)` inside `fs.writeFileSync(safe_p, ...)` MUST remain flagged!
        let ts_nested = base.join("nested_ts.ts");
        fs::write(
            &ts_nested,
            "import fs from 'fs';\nimport path from 'path';\nfunction save(root: string, rel: string, evil_p: string) {\n  const r = fs.realpathSync(root);\n  const safe_p = fs.realpathSync(path.join(r, rel));\n  if (!safe_p.startsWith(r + path.sep) || fs.lstatSync(safe_p).isSymbolicLink()) throw new Error('esc');\n  fs.writeFileSync(safe_p, fs.readFileSync(evil_p));\n}\n",
        )
        .unwrap();
        let r_ts = s3_audit_path_with_mode(&ts_nested, true);
        assert_ne!(r_ts.strict_verdict, "PASS_S3_PROVEN", "inner fs.readFileSync(evil_p) must never be hidden");
        assert!(
            r_ts.files[0].failing_seams.iter().any(|f| f.seam_kind == "PATH_LFI" && f.seam_line == 7),
            "expected failing PATH_LFI seam for inner fs.readFileSync(evil_p) on line 7: {:?}",
            r_ts.files[0].failing_seams
        );

        let _ = fs::remove_dir_all(&base);
    }
}
