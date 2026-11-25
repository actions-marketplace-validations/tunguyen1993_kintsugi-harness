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
    pub guard_line: usize,
    pub seam_kind: &'static str,
    pub bound_vars: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailingSeam {
    pub seam_line: usize,
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
    pub elapsed_ms: f64,
    pub assurance_tier: &'static str,
    pub verdict: &'static str,
    pub strict_verdict: &'static str,
    pub files: Vec<S3FileAudit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeamTier { ExposedS0, ProvenS3, Unproven }

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

fn classify_s3_seam_line(raw_t: &str, mask_t: &str) -> Option<&'static str> {
    if mask_t.is_empty()
        || ["*", "fix_hint:", "title:", "kmi_token:", "let bad_", "let ignored_", "poisoned."].iter().any(|p| raw_t.starts_with(p))
        || raw_t.contains(".contains(\"") || is_fixture_definition_line(raw_t)
    {
        return None;
    }
    const CMD_CALLS: &[&str] = &[
        "spawnSync(", "execFileSync(", "execFile(", "execSync(", "child_process.exec(", "subprocess.run(",
        "subprocess.Popen(", "subprocess.call(", "subprocess.check_call(", "subprocess.check_output(",
        "Command::new(", "authorizeCommand(", "runProcess(", "runCommand(", "os.system(", "os.popen(",
    ];
    if CMD_CALLS.iter().any(|c| mask_t.contains(c)) || has_bare_call(mask_t, "spawn(") || has_bare_call(mask_t, "eval(") { return Some("CMD_EXEC"); }
    if [".execute(", ".executemany(", "executeQuery(", "prepareStatement(", "mysqli_query(", "mysql_query("].iter().any(|c| mask_t.contains(c)) { return Some("SQL_EXEC"); }
    const PATH_CALLS: &[&str] = &[
        "resolveInside(", "realpathSync(", "lstatSync(", "symlink_metadata(", "canonicalize(",
        "read_regular_file_fd_verified(", "readSanitizedOutboundFileS3(", "assert_not_symlink(", "os.open(",
    ];
    if PATH_CALLS.iter().any(|c| mask_t.contains(c)) || has_bare_call(mask_t, "open(") { return Some("PATH_LFI"); }
    if ["writeJsonAtomic(", "atomicWriteJsonS3(", "atomic_write", "locked_cortex_transaction(", "writeFileSync("].iter().any(|c| mask_t.contains(c)) { return Some("STATE_MUTATION"); }
    if ["createHash(", "hashlib.sha256(", "hmac.new(", "hmac.digest(", "compare_digest(", "timingSafeEqual("].iter().any(|c| mask_t.contains(c))
        || has_unsafe_hmac_secret_eq(mask_t)
    {
        return Some("CRYPTO_VERIFY");
    }
    None
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
    seam_kind: &'static str, seam_offset: usize, win_start_line0: usize,
    raw_win: &[&str], masked_win: &[String], file_ignored: bool,
) -> (SeamTier, bool, Option<SeamEvidence>) {
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
    let seam_vars: Vec<String> = extract_var_tokens(&masked_win[seam_offset]).into_iter().take(6).collect();

    match seam_kind {
        "CMD_EXEC" => {
            let end_call = raw_win.len().min(seam_offset + 4);
            let raw_call = &raw_win[seam_offset..end_call];
            let is_rust_sh_c = masked_win[seam_offset].contains("Command::new(")
                && raw_call.iter().any(|r| ["\"sh\"", "\"/bin/sh\"", "\"bash\"", "\"zsh\""].iter().any(|s| r.contains(s))) && raw_call.iter().any(|r| r.contains("\"-c\""));
            let guard_off = (seam_offset..end_call)
                .find(|&gi| { let wt = raw_win[gi].trim(); has_unquoted_call(wt, "shell=False") || has_unquoted_call(wt, "shell: false") })
                .or_else(|| (["execFile(", "execFileSync(", "authorizeCommand("].iter().any(|g| masked_win[seam_offset].contains(g))
                    || (masked_win[seam_offset].contains("Command::new(") && !is_rust_sh_c)).then_some(seam_offset))
                .or_else(|| (0..seam_offset).rev().find(|&gi| masked_win[gi].contains("authorizeCommand(") || masked_win[gi].contains("escapeshellarg")));
            if let Some(goff) = guard_off {
                return (SeamTier::ProvenS3, false, Some(SeamEvidence { seam_line, guard_line: win_start_line0 + goff + 1, seam_kind, bound_vars: seam_vars }));
            }
        }
        "PATH_LFI" | "STATE_MUTATION" | "SQL_EXEC" | "CRYPTO_VERIFY" => {
            let (raw_seam, mask_seam) = (raw_win[seam_offset], masked_win[seam_offset].as_str());
            if is_intrinsic_safe_seam_call(seam_kind, raw_seam, mask_seam) {
                return (SeamTier::ProvenS3, false, Some(SeamEvidence { seam_line, guard_line: seam_line, seam_kind, bound_vars: seam_vars }));
            }
            let sink_needles: &[&str] = match seam_kind {
                "PATH_LFI" => &["canonicalize(", "realpathSync(", "lstatSync(", "symlink_metadata(", "os.open(", "open("],
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
                    if bound_candidates.is_empty() || !shared.is_empty() {
                        let bvars = if shared.is_empty() { seam_vars } else { shared };
                        return (
                            SeamTier::ProvenS3,
                            false,
                            Some(SeamEvidence {
                                seam_line,
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

    // Kintsugi v3.0 Typed Obligation Prover handles CMD_EXEC and SQL_EXEC with full multi-line
    // call spans, intra-function scope/alias resolution, and multi-sink-per-line precision.
    let obligations = prove_file_obligations(file, &content, &masked_lines);
    let mut ob_covered_lines: BTreeSet<(usize, &'static str)> = BTreeSet::new();
    for ob in &obligations {
        let line_idx0 = ob.sink_span.start_line.saturating_sub(1);
        ob_covered_lines.insert((line_idx0, ob.rule));
        total_seams += 1;
        let line_ignored = file_ignored
            || lines[line_idx0.saturating_sub(2)..(line_idx0 + 2).min(lines.len())]
                .iter()
                .any(|wl| wl.to_ascii_lowercase().contains("kintsugi: ignore"));
        if line_ignored {
            ignored_override = true;
            unproven += 1;
            failing_seams.push(FailingSeam {
                seam_line: ob.sink_span.start_line,
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
                    guard_line,
                    seam_kind: ob.rule,
                    bound_vars,
                });
            }
            ObligationState::Violated => {
                unguarded_s0 += 1;
                failing_seams.push(FailingSeam {
                    seam_line: ob.sink_span.start_line,
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
                    seam_kind: ob.rule,
                    tier: "UNSUPPORTED",
                    reason: ob.reason,
                    fix_hint: ob.fix_hint,
                });
            }
        }
    }

    for (idx, line) in lines.iter().enumerate() {
        let (t, mt) = (line.trim(), masked_lines[idx].trim());
        if ["def ", "async def ", "function ", "async function ", "export function ", "export async function ", "pub fn ", "fn "].iter().any(|p| mt.starts_with(p)) { fn_count += 1; }
        if ["class ", "export class ", "pub struct ", "struct "].iter().any(|p| mt.starts_with(p)) { cls_count += 1; }
        if let Some(seam_kind) = classify_s3_seam_line(t, mt) {
            // Skip CMD_EXEC / SQL_EXEC lines already graded by the v3 Typed Obligation Prover
            if matches!(seam_kind, "CMD_EXEC" | "SQL_EXEC") && ob_covered_lines.contains(&(idx, seam_kind)) {
                continue;
            }
            total_seams += 1;
            let (win_start, win_end) = (idx.saturating_sub(6), (idx + 7).min(lines.len()));
            let (tier, used_ignore, ev_opt) = grade_seam_window(seam_kind, idx - win_start, win_start, &lines[win_start..win_end], &masked_lines[win_start..win_end], file_ignored);
            if used_ignore { ignored_override = true; }
            if let Some(ev) = ev_opt { evidence_chains.push(ev); }
            match tier {
                SeamTier::ExposedS0 => {
                    unguarded_s0 += 1;
                    let (reason, fix_hint) = s3_failing_reason_and_hint(seam_kind, true);
                    failing_seams.push(FailingSeam { seam_line: idx + 1, seam_kind, tier: "S0_EXPOSED", reason, fix_hint });
                }
                SeamTier::ProvenS3 => proven_s3 += 1,
                SeamTier::Unproven => {
                    unproven += 1;
                    let (reason, fix_hint) = s3_failing_reason_and_hint(seam_kind, false);
                    failing_seams.push(FailingSeam { seam_line: idx + 1, seam_kind, tier: "UNPROVEN", reason, fix_hint });
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
    let mut files = Vec::new();
    collect_files(target, &mut files);
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

    let ignored_override = ignored_override_files > 0;
    let (assurance_tier, verdict, strict_verdict) = compute_s3_verdicts(unguarded_s0_seams, unproven_seams, ignored_override, strict_proven);

    S3AuditSummary {
        target: target.to_string_lossy().to_string(), strict_proven, files_scanned: audits.len(),
        total_functions, total_classes, total_seams, s3_locked_seams: proven_s3_seams, proven_s3_seams,
        unproven_seams, unguarded_s0_seams, ignored_override, ignored_override_files,
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
            ev_arr = ev_arr.obj(JsonObj::new().usize("seam_line", ev.seam_line).usize("guard_line", ev.guard_line).str("seam_kind", ev.seam_kind).arr("bound_vars", bv));
        }
        let mut fail_arr = JsonArr::new();
        for fs in f.failing_seams.iter().take(16) {
            fail_arr = fail_arr.obj(
                JsonObj::new()
                    .usize("seam_line", fs.seam_line)
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
}
