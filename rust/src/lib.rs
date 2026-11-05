// kintsugi: ignore-file
//! Kintsugi Core (`kintsugi_core`) — Native Rust sub-millisecond scanner,
//! Claude Code `PreToolUse` JIT hook evaluator, and `KMI/1` Ultra-Low-Token Compressor.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn from_str(raw: &str) -> Self {
        match raw.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            _ => Severity::Low,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }

    pub fn short_tag(&self) -> &'static str {
        match self {
            Severity::Critical => "CRIT",
            Severity::High => "HIGH",
            Severity::Medium => "MED",
            Severity::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NativeRule {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub kmi_token: &'static str,
    pub languages: &'static [&'static str],
    pub fix_hint: &'static str,
    pub premium_only: bool,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub scar_id: String,
    pub title: String,
    pub severity: Severity,
    pub category: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub fix_hint: String,
}

#[derive(Debug, Clone)]
pub struct ScanSummary {
    pub scanned_files: usize,
    pub active_rules: usize,
    pub elapsed_micros: u128,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct TokenBenchmark {
    pub rules_count: usize,
    pub verbose_tokens: usize,
    pub kmi_tokens: usize,
    pub reduction_pct: f64,
    pub saved_tokens_50_turns: usize,
}

pub const BUILTIN_RULES: &[NativeRule] = &[
    NativeRule {
        id: "KS-001",
        title: "Hardcoded API key, bearer token, or private credential literal",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-001(secret!=literal->os.environ)",
        languages: &["python", "javascript", "typescript", "go", "rust", "shell"],
        fix_hint: "api_key = os.environ[\"SERVICE_API_KEY\"]",
        premium_only: false,
    },
    NativeRule {
        id: "KS-002",
        title: "Subprocess invocation with shell=True enables command injection",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-002(subprocess!shell=True->argv_list)",
        languages: &["python"],
        fix_hint: "subprocess.run([\"git\", \"status\"], shell=False, check=True)",
        premium_only: false,
    },
    NativeRule {
        id: "KS-003",
        title: "Unsafe dynamic code execution or untrusted pickle/yaml deserialization",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-003(no_eval_exec_pickle->literal_eval)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "data = json.loads(raw_payload)",
        premium_only: false,
    },
    NativeRule {
        id: "KS-004",
        title: "Mutable default argument in Python function signature",
        severity: Severity::High,
        category: "correctness",
        kmi_token: "KS-004(py!mutable_default->None)",
        languages: &["python"],
        fix_hint: "def append_item(item: str, bucket: list[str] | None = None):",
        premium_only: false,
    },
    NativeRule {
        id: "KS-005",
        title: "Silent bare except or pass-only exception handler swallows failures",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-005(py!bare_except_pass->log_raise)",
        languages: &["python"],
        fix_hint: "except Exception as exc:\n    logger.exception(\"Operation failed: %s\", exc)\n    raise",
        premium_only: false,
    },
    NativeRule {
        id: "KS-006",
        title: "Synchronous HTTP request without an explicit timeout parameter",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-006(http!missing_timeout->timeout=10)",
        languages: &["python"],
        fix_hint: "resp = requests.get(url, timeout=10)",
        premium_only: false,
    },
    NativeRule {
        id: "KS-007",
        title: "SQL query constructed via string interpolation or f-string",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-007(sql!fstring->param_query)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "cursor.execute(\"SELECT * FROM users WHERE email = ?\", (email,))",
        premium_only: false,
    },
    NativeRule {
        id: "KS-008",
        title: "Non-cryptographic random module used for security token or key generation",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-008(crypto!random->secrets.token_urlsafe)",
        languages: &["python"],
        fix_hint: "reset_token = secrets.token_urlsafe(32)",
        premium_only: false,
    },
    NativeRule {
        id: "KS-009",
        title: "Unfinished TODO/FIXME stub or placeholder left in deliverable code",
        severity: Severity::Medium,
        category: "quality",
        kmi_token: "KS-009(no_todo_placeholder_stub)",
        languages: &["python", "javascript", "typescript", "go", "rust"],
        fix_hint: "Implement concrete production logic before committing.",
        premium_only: false,
    },
    NativeRule {
        id: "KS-010",
        title: "Destructive overwrite of immutable audit or historical capture files",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-010(audit!no_truncate_overwrite->append)",
        languages: &["python"],
        fix_hint: "with open(audit_log_path, \"a\", encoding=\"utf-8\") as f:",
        premium_only: false,
    },
    NativeRule {
        id: "KS-011",
        title: "TLS certificate verification disabled in HTTP client",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-011(tls!verify=False->verify=True)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "requests.get(url, verify=True, timeout=10)",
        premium_only: false,
    },
    NativeRule {
        id: "KS-012",
        title: "Unescaped DOM innerHTML assignment enables Cross-Site Scripting (XSS)",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-012(dom!innerHTML->textContent)",
        languages: &["javascript", "typescript"],
        fix_hint: "panel.textContent = userComment;",
        premium_only: false,
    },
    NativeRule {
        id: "KS-013",
        title: "Headless browser launched without guaranteed teardown in finally block",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-013(browser!launch->close_in_finally)",
        languages: &["javascript", "typescript", "python"],
        fix_hint: "try { ... } finally { await browser.close(); }",
        premium_only: false,
    },
    NativeRule {
        id: "KS-014",
        title: "Destructive git push --force or recursive root rm -rf in automation script",
        severity: Severity::Critical,
        category: "safety",
        kmi_token: "KS-014(sh!no_force_push_or_rm_rf_root)",
        languages: &["shell", "python", "javascript", "typescript"],
        fix_hint: "git push --force-with-lease origin main",
        premium_only: false,
    },
    NativeRule {
        id: "KS-015",
        title: "Ignored error return value in Go function call",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-015(go!no_blank_error_discard)",
        languages: &["go"],
        fix_hint: "if err := json.Unmarshal(payload, &cfg); err != nil { return err }",
        premium_only: false,
    },
    NativeRule {
        id: "KS-016",
        title: "Unvalidated URL scheme in server-side fetch allows file:// or metadata SSRF",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-016(ssrf!allowlist_https_scheme)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "Validate parsed.scheme == 'https' and block 169.254.169.254.",
        premium_only: false,
    },
    NativeRule {
        id: "KS-017",
        title: "Unfiltered tarfile.extractall() allows arbitrary path traversal (CVE-2007-4559)",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-017(tar!extractall->filter='data')",
        languages: &["python"],
        fix_hint: "tar.extractall(path=dest_dir, filter=\"data\")",
        premium_only: false,
    },
    NativeRule {
        id: "KS-018",
        title: "Unpinned `:latest` container image tag breaks build reproducibility",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-018(docker!no_latest->pin_sha256)",
        languages: &["dockerfile", "shell"],
        fix_hint: "FROM python:3.12-slim@sha256:4c100f870...",
        premium_only: false,
    },
];

pub fn detect_language(path: &Path) -> Option<&'static str> {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if name.eq_ignore_ascii_case("Dockerfile") || name.starts_with("Dockerfile.") {
            return Some("dockerfile");
        }
    }
    match path.extension().and_then(|e| e.to_str())?.to_ascii_lowercase().as_str() {
        "py" | "pyi" => Some("python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "go" => Some("go"),
        "rs" => Some("rust"),
        "sh" | "bash" | "zsh" => Some("shell"),
        "dockerfile" => Some("dockerfile"),
        _ => None,
    }
}

fn line_ignores_rule(line: &str, rule_id: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if let Some(idx) = lower.find("kintsugi:") {
        let tail = &lower[idx + "kintsugi:".len()..].trim_start();
        if tail.starts_with("ignore") {
            if let Some(open) = tail.find('[') {
                if let Some(close) = tail[open + 1..].find(']') {
                    let inside = &tail[open + 1..open + 1 + close];
                    return inside
                        .split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case(rule_id));
                }
            }
            return true;
        }
    }
    false
}

fn check_line_against_rule(rule_id: &str, line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if rule_id != "KS-009" && (trimmed.starts_with('#') || trimmed.starts_with("//")) {
        return false;
    }
    if trimmed.starts_with("bad_code=")
        || trimmed.starts_with("good_code=")
        || trimmed.starts_with("offending_snippet=")
        || trimmed.starts_with("regex_pattern=")
    {
        return false;
    }
    match rule_id {
        "KS-001" => {
            if trimmed.contains("os.environ") || trimmed.contains("os.getenv") {
                return false;
            }
            let has_secret_prefix = trimmed.contains("sk-live-")
                || trimmed.contains("sk-proj-")
                || trimmed.contains("ghp_")
                || trimmed.contains("github_pat_")
                || trimmed.contains("xoxb-")
                || trimmed.contains("AIzaSy");
            has_secret_prefix && (trimmed.contains('=') || trimmed.contains(':'))
        }
        "KS-002" => {
            (trimmed.contains("subprocess.") || trimmed.contains("Popen("))
                && trimmed.contains("shell=True")
        }
        "KS-003" => {
            trimmed.contains("eval(")
                || trimmed.contains("exec(")
                || trimmed.contains("pickle.loads(")
                || trimmed.contains("pickle.load(")
                || trimmed.contains("marshal.loads(")
        }
        "KS-004" => {
            trimmed.starts_with("def ")
                && (trimmed.contains("=[]")
                    || trimmed.contains("= []")
                    || trimmed.contains("={}")
                    || trimmed.contains("= {}"))
        }
        "KS-005" => {
            trimmed == "except:"
                || trimmed.starts_with("except: pass")
                || (trimmed.starts_with("except ") && trimmed.ends_with(": pass"))
        }
        "KS-006" => {
            (trimmed.contains("requests.get(")
                || trimmed.contains("requests.post(")
                || trimmed.contains("requests.put(")
                || trimmed.contains("urllib.request.urlopen("))
                && !trimmed.contains("timeout=")
        }
        "KS-007" => {
            let upper = trimmed.to_ascii_uppercase();
            let has_sql = upper.contains("SELECT ")
                || upper.contains("INSERT INTO ")
                || upper.contains("UPDATE ")
                || upper.contains("DELETE FROM ");
            has_sql
                && (trimmed.contains("f\"")
                    || trimmed.contains("f'")
                    || (trimmed.contains("${") && trimmed.contains('`')))
        }
        "KS-008" => {
            let lower = trimmed.to_ascii_lowercase();
            let security_var = lower.contains("token")
                || lower.contains("secret")
                || lower.contains("nonce")
                || lower.contains("api_key")
                || lower.contains("password")
                || lower.contains("otp");
            security_var
                && (trimmed.contains("random.choice(")
                    || trimmed.contains("random.randint(")
                    || trimmed.contains("random.random(")
                    || trimmed.contains("random.choices("))
        }
        "KS-009" => {
            trimmed.contains("# TODO: implement")
                || trimmed.contains("// TODO: implement")
                || trimmed.contains("PLACEHOLDER_STUB")
                || trimmed.contains("NotImplementedError(\"TODO")
        }
        "KS-010" => {
            let lower = trimmed.to_ascii_lowercase();
            (lower.contains("audit_log") || lower.contains("history_log") || lower.contains("pull1_raw"))
                && (trimmed.contains(", \"w\"") || trimmed.contains(", 'w'") || trimmed.contains(".write_text("))
        }
        "KS-011" => {
            trimmed.contains("verify=False")
                || trimmed.contains("rejectUnauthorized: false")
                || trimmed.contains("NODE_TLS_REJECT_UNAUTHORIZED = \"0\"")
                || trimmed.contains("NODE_TLS_REJECT_UNAUTHORIZED = '0'")
        }
        "KS-012" => trimmed.contains(".innerHTML =") || trimmed.contains(".innerHTML="),
        "KS-014" => {
            (trimmed.contains("git push") && trimmed.contains("--force") && !trimmed.contains("--force-with-lease"))
                || trimmed.contains("rm -rf /")
                || trimmed.contains("rm -rf ~")
        }
        "KS-015" => {
            (trimmed.starts_with("_, _ =") || trimmed.starts_with("_ ="))
                && (trimmed.contains("Unmarshal(")
                    || trimmed.contains("Write(")
                    || trimmed.contains("Read(")
                    || trimmed.contains("Exec("))
        }
        "KS-016" => {
            trimmed.contains("169.254.169.254")
                || trimmed.contains("file:///etc/passwd")
                || trimmed.contains("urlopen(user_supplied_url)")
        }
        "KS-017" => {
            trimmed.contains(".extractall(") && !trimmed.contains("filter=")
        }
        "KS-018" => {
            let upper = trimmed.to_ascii_uppercase();
            upper.starts_with("FROM ") && trimmed.contains(":latest")
        }
        _ => false,
    }
}

pub fn scan_text(
    content: &str,
    file_path: &str,
    lang: &str,
    min_severity: Severity,
    allowed_lines: Option<&BTreeSet<usize>>,
) -> Vec<Finding> {
    let lines: Vec<&str> = content.lines().collect();
    for header_line in lines.iter().take(5) {
        if header_line.to_ascii_lowercase().contains("kintsugi: ignore-file") {
            return Vec::new();
        }
    }

    let mut findings = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let lineno = idx + 1;
        if let Some(allowed) = allowed_lines {
            if !allowed.contains(&lineno) {
                continue;
            }
        }
        for rule in BUILTIN_RULES {
            if !rule.severity.ge(&min_severity) {
                continue;
            }
            if !rule.languages.contains(&lang) {
                continue;
            }
            if line_ignores_rule(line, rule.id) {
                continue;
            }
            if check_line_against_rule(rule.id, line) {
                findings.push(Finding {
                    scar_id: rule.id.to_string(),
                    title: rule.title.to_string(),
                    severity: rule.severity,
                    category: rule.category.to_string(),
                    file_path: file_path.to_string(),
                    line: lineno,
                    column: 1,
                    snippet: line.trim().to_string(),
                    fix_hint: rule.fix_hint.to_string(),
                });
            }
        }
    }
    findings
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | ".kintsugi"
            | ".claude"
            | ".cursor"
            | "__pycache__"
            | ".pytest_cache"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".venv"
            | "venv"
    )
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut sorted_entries: Vec<_> = entries.flatten().collect();
    sorted_entries.sort_by_key(|e| e.path());
    for entry in sorted_entries {
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if !should_skip_dir(name) {
                    collect_files(&path, out);
                }
            }
        } else if path.is_file() && detect_language(&path).is_some() {
            out.push(path);
        }
    }
}

pub fn scan_path(target: &Path, min_severity: Severity) -> ScanSummary {
    let start = Instant::now();
    let mut files = Vec::new();
    collect_files(target, &mut files);
    let mut findings = Vec::new();
    let mut scanned_files = 0usize;

    for file in files {
        let Some(lang) = detect_language(&file) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        scanned_files += 1;
        let display = file.to_string_lossy().to_string();
        let mut f = scan_text(&content, &display, lang, min_severity, None);
        findings.append(&mut f);
    }

    ScanSummary {
        scanned_files,
        active_rules: BUILTIN_RULES.len(),
        elapsed_micros: start.elapsed().as_micros(),
        findings,
    }
}

pub fn parse_git_diff_lines(diff_text: &str, repo_root: &Path) -> BTreeMap<PathBuf, BTreeSet<usize>> {
    let mut map: BTreeMap<PathBuf, BTreeSet<usize>> = BTreeMap::new();
    let mut current_file: Option<PathBuf> = None;

    for line in diff_text.lines() {
        if let Some(rel) = line.strip_prefix("+++ b/") {
            let p = repo_root.join(rel.trim());
            current_file = Some(p.clone());
            map.entry(p).or_default();
        } else if line.starts_with("+++ /dev/null") {
            current_file = None;
        } else if let Some(ref file) = current_file {
            if let Some(rest) = line.strip_prefix("@@ ") {
                if let Some(plus_idx) = rest.find('+') {
                    let after_plus = &rest[plus_idx + 1..];
                    let end_tok = after_plus.find(' ').unwrap_or(after_plus.len());
                    let range_spec = &after_plus[..end_tok];
                    let mut parts = range_spec.split(',');
                    if let Some(start_s) = parts.next() {
                        if let Ok(start_ln) = start_s.parse::<usize>() {
                            let count = parts
                                .next()
                                .and_then(|c| c.parse::<usize>().ok())
                                .unwrap_or(1);
                            if count > 0 {
                                let set = map.entry(file.clone()).or_default();
                                for ln in start_ln..(start_ln + count) {
                                    set.insert(ln);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

pub fn scan_git_staged(repo_root: &Path, min_severity: Severity) -> ScanSummary {
    let start = Instant::now();
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["diff", "-U0", "--no-color", "--staged"])
        .output();

    let Ok(proc_out) = output else {
        return ScanSummary {
            scanned_files: 0,
            active_rules: BUILTIN_RULES.len(),
            elapsed_micros: start.elapsed().as_micros(),
            findings: Vec::new(),
        };
    };

    let diff_str = String::from_utf8_lossy(&proc_out.stdout);
    let touched = parse_git_diff_lines(&diff_str, repo_root);
    let mut findings = Vec::new();
    let mut scanned_files = 0usize;

    for (file, lines) in touched {
        if lines.is_empty() || !file.is_file() {
            continue;
        }
        let Some(lang) = detect_language(&file) else {
            continue;
        };
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };
        scanned_files += 1;
        let display = file.to_string_lossy().to_string();
        let mut f = scan_text(&content, &display, lang, min_severity, Some(&lines));
        findings.append(&mut f);
    }

    ScanSummary {
        scanned_files,
        active_rules: BUILTIN_RULES.len(),
        elapsed_micros: start.elapsed().as_micros(),
        findings,
    }
}

/// Render the `KMI/1` (Kintsugi Micro-Index v1) ultra-compact prompt governance header.
/// Cuts context consumption by >92% compared to verbose Markdown skill files.
pub fn render_kmi_compact_header() -> String {
    let mut by_tier: BTreeMap<u8, Vec<&'static str>> = BTreeMap::new();
    for rule in BUILTIN_RULES {
        let rank = rule.severity as u8;
        by_tier.entry(rank).or_default().push(rule.kmi_token);
    }
    let mut out = String::from(
        "<!-- KINTSUGI:KMI/1 START -->\n\
         # KINTSUGI-KMI/1 (Ultra-Low-Token Wire Index | JIT PreToolUse Active)\n",
    );
    for (rank, label) in [(4u8, "@CRIT"), (3u8, "@HIGH"), (2u8, "@MED "), (1u8, "@LOW ")] {
        if let Some(tokens) = by_tier.get(&rank) {
            if !tokens.is_empty() {
                out.push_str(label);
                out.push_str(": ");
                out.push_str(&tokens.join(" | "));
                out.push('\n');
            }
        }
    }
    out.push_str("<!-- KINTSUGI:KMI/1 END -->");
    out
}

pub fn estimate_tokens(text: &str) -> usize {
    let chars = text.chars().count();
    let words = text.split_whitespace().count();
    let by_chars = (chars + 3) / 4;
    if words > by_chars { words } else { by_chars }
}

pub fn compute_token_benchmark() -> TokenBenchmark {
    let kmi = render_kmi_compact_header();
    let kmi_tokens = estimate_tokens(&kmi);
    // Standard verbose harnesses (~190 tokens per full rule with prose + Bad/Good blocks)
    let verbose_tokens = BUILTIN_RULES.len() * 190;
    let reduction_pct = if verbose_tokens > 0 {
        ((verbose_tokens.saturating_sub(kmi_tokens)) as f64 / verbose_tokens as f64) * 100.0
    } else {
        0.0
    };
    let saved_tokens_50_turns = verbose_tokens.saturating_sub(kmi_tokens) * 50;
    TokenBenchmark {
        rules_count: BUILTIN_RULES.len(),
        verbose_tokens,
        kmi_tokens,
        reduction_pct,
        saved_tokens_50_turns,
    }
}

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Evaluate a raw JSON string from Claude Code `PreToolUse` stdin and return
/// a deterministic JSON decision with Just-In-Time (JIT) single-rule remediation.
pub fn evaluate_pre_tool_json(raw_json: &str, min_block: Severity) -> String {
    let findings = scan_text(raw_json, "PreToolUse:stdin", "python", min_block, None);
    let mut sh_findings = scan_text(raw_json, "PreToolUse:stdin", "shell", min_block, None);
    let mut all = findings;
    for sf in sh_findings.drain(..) {
        if !all.iter().any(|existing| existing.scar_id == sf.scar_id) {
            all.push(sf);
        }
    }
    if all.is_empty() {
        return "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}".to_string();
    }
    let first = &all[0];
    let reason = format!(
        "[Kintsugi JIT Guard] Blocked {} ({}): {} | Verified Fix: {}",
        first.scar_id, first.severity.as_str(), first.title, first.fix_hint
    );
    format!(
        "{{\"hookSpecificOutput\":{{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"{}\"}}}}",
        json_escape(&reason)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_critical_rules_and_respects_inline_ignore() {
        let bad_py = "import subprocess\nsubprocess.run(cmd, shell=True)\n";
        let res = scan_text(bad_py, "app.py", "python", Severity::High, None);
        assert!(!res.is_empty());
        assert_eq!(res[0].scar_id, "KS-002");

        let ignored_py = "subprocess.run(cmd, shell=True)  # kintsugi: ignore[KS-002]\n";
        let res_ignored = scan_text(ignored_py, "app.py", "python", Severity::High, None);
        assert!(res_ignored.is_empty());
    }

    #[test]
    fn kmi_token_compression_exceeds_90_percent() {
        let bench = compute_token_benchmark();
        assert!(bench.reduction_pct >= 90.0, "Expected >=90% reduction, got {}", bench.reduction_pct);
        assert!(bench.kmi_tokens < 260);
    }

    #[test]
    fn pre_tool_use_jit_hook_blocks_destructive_push() {
        let payload = r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#;
        let decision = evaluate_pre_tool_json(payload, Severity::High);
        assert!(decision.contains("\"permissionDecision\":\"deny\""));
        assert!(decision.contains("KS-014"));
    }
}
