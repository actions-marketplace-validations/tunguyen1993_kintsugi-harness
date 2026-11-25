//! Canonical output formatters (`compact`, `json`, `jsonl`, `sarif`) and deterministic
//! finding deduplication for `kintsugi-rs` and `kintsugi_core::ffi` (zero `audit` dependency).

#[cfg(feature = "sarif")]
use std::collections::BTreeMap;

use crate::io_json::{json_escape_into, ENGINE_VERSION};
use crate::model::{Finding, ScanSummary};
#[cfg(feature = "sarif")]
use crate::model::Severity;
#[cfg(feature = "sarif")]
use crate::policy::sha256_hex;
use crate::token_est::estimate_tokens;

#[cfg(feature = "sarif")]
const SARIF_RULES_HELP_URI: &str = "https://github.com/tunguyen1993/kintsugi-harness#rules";

/// Detailed token-bounded compact gate rendering telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedGate {
    pub text: String,
    pub estimated_tokens: usize,
    pub kept_findings: usize,
    pub omitted_findings: usize,
    /// `true` if the very first finding had to be truncated to fit `max_tokens`.
    pub first_line_clipped: bool,
}

/// Deterministically sort and deduplicate findings in-place by `(file_path, line, scar_id)`.
pub fn deduplicate_findings(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.scar_id.cmp(&b.scar_id))
            .then_with(|| a.column.cmp(&b.column))
    });
    findings.dedup_by(|a, b| {
        a.file_path == b.file_path && a.line == b.line && a.scar_id == b.scar_id
    });
}

#[inline]
fn normalize_display_path(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(stripped) = trimmed.strip_prefix("./") {
        if !stripped.is_empty() {
            return stripped;
        }
    }
    trimmed
}

#[inline]
fn single_line_hint(f: &Finding) -> String {
    let src = if f.fix_hint.trim().is_empty() { f.title.as_str() } else { f.fix_hint.as_str() };
    let mut out = String::with_capacity(src.len());
    let mut prev_ws = false;
    for ch in src.trim().chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out
}

/// Truncate a single line via binary search on `char_indices` so `estimate_tokens(out) <= max_tokens`.
fn truncate_line_to_tokens(line: &str, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return String::new();
    }
    if estimate_tokens(line) <= max_tokens {
        return line.to_string();
    }
    let indices: Vec<usize> = line.char_indices().map(|(i, ch)| i + ch.len_utf8()).collect();
    if indices.is_empty() {
        return String::new();
    }
    let ellipsis_tokens = estimate_tokens("...");
    if max_tokens <= ellipsis_tokens {
        let mut out = String::new();
        for ch in line.chars().filter(|c| !c.is_whitespace()) {
            let mut next = out.clone();
            next.push(ch);
            if estimate_tokens(&next) > max_tokens {
                break;
            }
            out = next;
        }
        return if out.is_empty() { ".".to_string() } else { out };
    }

    let (mut lo, mut hi, mut best) = (0usize, indices.len(), String::new());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let prefix = line[..indices[mid]].trim_end();
        let cand = if prefix.is_empty() { "...".to_string() } else { format!("{prefix}...") };
        if estimate_tokens(&cand) <= max_tokens {
            best = cand;
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if best.is_empty() { "...".to_string() } else { best }
}

/// Self-deduplicating, deterministically sorted compact gate renderer within `max_tokens`.
///
/// Internally clones and invokes [`deduplicate_findings`] before budgeting so `kept_findings`,
/// `omitted_findings`, and rendered lines are always exact and invariant to caller input order.
///
/// **Performance**: `O(n)` time and space with incremental token counting; handles 2000+ findings
/// in single-digit milliseconds.
pub fn render_gate_compact_detailed(findings: &[Finding], max_tokens: usize) -> RenderedGate {
    if findings.is_empty() {
        return RenderedGate {
            text: String::new(),
            estimated_tokens: 0,
            kept_findings: 0,
            omitted_findings: 0,
            first_line_clipped: false,
        };
    }
    let mut clean = findings.to_vec();
    deduplicate_findings(&mut clean);
    let total = clean.len();
    if max_tokens == 0 {
        return RenderedGate {
            text: String::new(),
            estimated_tokens: 0,
            kept_findings: 0,
            omitted_findings: total,
            first_line_clipped: false,
        };
    }

    let mut lines = Vec::with_capacity(total);
    for f in &clean {
        let path = normalize_display_path(&f.file_path);
        let hint = single_line_hint(f);
        let entry = if path.is_empty() || path.starts_with('<') {
            format!("[{}@{}] {}", f.scar_id, f.line, hint)
        } else {
            format!("[{}@{}:{}] {}", f.scar_id, path, f.line, hint)
        };
        lines.push(entry);
    }

    let newline_tokens = estimate_tokens("\n");
    let mut used_tokens = 0usize;
    let mut kept_count = 0usize;
    let first_line_clipped = false;

    for (idx, line) in lines.iter().enumerate() {
        let line_tokens = estimate_tokens(line);
        let sep_tokens = if kept_count == 0 { 0 } else { newline_tokens };
        let next_total = used_tokens + sep_tokens + line_tokens;

        if next_total <= max_tokens {
            used_tokens = next_total;
            kept_count += 1;
            continue;
        }

        if kept_count == 0 {
            let truncated = truncate_line_to_tokens(line, max_tokens);
            let est = estimate_tokens(&truncated);
            let kept = usize::from(!truncated.is_empty());
            return RenderedGate {
                text: truncated,
                estimated_tokens: est,
                kept_findings: kept,
                omitted_findings: total.saturating_sub(kept),
                first_line_clipped: true,
            };
        }

        let omitted = total - idx;
        let tail = format!("... (+{omitted} more)");
        let tail_tokens = estimate_tokens(&tail);
        if used_tokens + newline_tokens + tail_tokens <= max_tokens {
            used_tokens += newline_tokens + tail_tokens;
        }
        break;
    }

    let mut out = String::with_capacity(used_tokens * 4);
    for (i, line) in lines.iter().enumerate().take(kept_count) {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }

    let omitted = total - kept_count;
    if omitted > 0 {
        let tail = format!("\n... (+{omitted} more)");
        if estimate_tokens(&format!("{out}{tail}")) <= max_tokens {
            out.push_str(&tail);
        }
    }

    let estimated_tokens = estimate_tokens(&out);
    RenderedGate {
        text: out,
        estimated_tokens,
        kept_findings: kept_count,
        omitted_findings: omitted,
        first_line_clipped,
    }
}

/// Render deduplicated findings into an ultra-compact agent-native string within `max_tokens`.
#[inline]
pub fn render_gate_compact(findings: &[Finding], max_tokens: usize) -> String {
    render_gate_compact_detailed(findings, max_tokens).text
}

#[inline]
fn append_finding_json(out: &mut String, f: &Finding) {
    out.push_str("{\"scar_id\":\"");
    json_escape_into(&f.scar_id, out);
    out.push_str("\",\"severity\":\"");
    out.push_str(f.severity.as_str());
    out.push_str("\",\"category\":\"");
    json_escape_into(&f.category, out);
    out.push_str("\",\"file_path\":\"");
    json_escape_into(&f.file_path, out);
    out.push_str("\",\"line\":");
    out.push_str(&f.line.to_string());
    out.push_str(",\"column\":");
    out.push_str(&f.column.to_string());
    out.push_str(",\"title\":\"");
    json_escape_into(&f.title, out);
    out.push_str("\",\"snippet\":\"");
    json_escape_into(&f.snippet, out);
    out.push_str("\",\"good_code_hint\":\"");
    json_escape_into(&f.fix_hint, out);
    out.push_str("\"}");
}

/// Serialize findings as a canonical JSON array shared by `ffi.rs` and `main.rs`.
pub fn render_findings_json_array(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "[]".to_string();
    }
    let mut out = String::with_capacity(findings.len().saturating_mul(220) + 2);
    out.push('[');
    for (idx, f) in findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        append_finding_json(&mut out, f);
    }
    out.push(']');
    out
}

/// Render the canonical JSON summary with explicit `shadow_arm_c` and `dynamic_rules` metadata.
pub fn render_scan_json_with_meta(
    summary: &ScanSummary,
    shadow_arm_c: bool,
    dynamic_rules: usize,
) -> String {
    let ms = (summary.elapsed_micros as f64) / 1000.0;
    format!(
        "{{\"schema_version\":\"{}\",\"engine\":\"kintsugi-rs\",\"engine_version\":\"{}\",\"shadow_arm_c\":{},\"dynamic_rules\":{},\"scanned_files\":{},\"active_scars\":{},\"elapsed_ms\":{:.3},\"findings\":{}}}",
        ENGINE_VERSION,
        ENGINE_VERSION,
        shadow_arm_c,
        dynamic_rules,
        summary.scanned_files,
        summary.active_rules,
        ms,
        render_findings_json_array(&summary.findings),
    )
}

/// Render the canonical JSON summary for `kintsugi-rs scan` and `kintsugi-rs gate --format json`.
#[inline]
pub fn render_scan_json(summary: &ScanSummary, shadow_arm_c: bool, dynamic_rules: usize) -> String {
    render_scan_json_with_meta(summary, shadow_arm_c, dynamic_rules)
}

/// Render the canonical JSON summary from `ScanSummary` alone, inferring `shadow_arm_c = active_rules > 36`.
#[inline]
pub fn render_scan_summary_json(summary: &ScanSummary) -> String {
    render_scan_json_with_meta(summary, summary.active_rules > 36, 0)
}

/// Render findings as newline-delimited JSONL (1 compact JSON object per line, `""` if empty).
pub fn render_findings_jsonl(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(findings.len().saturating_mul(224));
    for f in findings {
        append_finding_json(&mut out, f);
        out.push('\n');
    }
    out
}

#[cfg(feature = "sarif")]
#[inline]
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[cfg(feature = "sarif")]
#[inline]
fn normalize_sarif_uri(path: &str) -> String {
    let clean = normalize_display_path(path);
    if clean.contains('\\') { clean.replace('\\', "/") } else { clean.to_string() }
}

#[cfg(feature = "sarif")]
fn sarif_primary_line_hash(scar_id: &str, uri: &str, line: usize, snippet: &str) -> String {
    let mut preimage = String::with_capacity(scar_id.len() + uri.len() + snippet.len() + 24);
    preimage.push_str(scar_id);
    preimage.push('\0');
    preimage.push_str(uri);
    preimage.push('\0');
    preimage.push_str(&line.max(1).to_string());
    preimage.push('\0');
    preimage.push_str(snippet);
    sha256_hex(preimage.as_bytes())[..16].to_string()
}

/// Render findings as 100% deterministic OASIS SARIF 2.1.0 JSON (`#[cfg(feature = "sarif")]`).
///
/// Findings are cloned and deterministically sorted by `(file_path, line, column, scar_id, fingerprint)`
/// BEFORE building both `tool.driver.rules` and `results`, guaranteeing byte-for-byte identical
/// SARIF output regardless of multi-core worker or multi-target input ordering.
#[cfg(feature = "sarif")]
pub fn render_findings_sarif(findings: &[Finding]) -> String {
    struct PreparedSarifItem {
        finding: Finding,
        uri: String,
        start_line: usize,
        start_col: usize,
        fp_hash: String,
    }

    let mut prepared: Vec<PreparedSarifItem> = findings
        .iter()
        .cloned()
        .map(|f| {
            let uri = normalize_sarif_uri(&f.file_path);
            let start_line = f.line.max(1);
            let start_col = f.column.max(1);
            let fp_hash = sarif_primary_line_hash(&f.scar_id, &uri, start_line, &f.snippet);
            PreparedSarifItem { finding: f, uri, start_line, start_col, fp_hash }
        })
        .collect();

    prepared.sort_by(|a, b| {
        a.uri
            .cmp(&b.uri)
            .then_with(|| a.start_line.cmp(&b.start_line))
            .then_with(|| a.start_col.cmp(&b.start_col))
            .then_with(|| a.finding.scar_id.cmp(&b.finding.scar_id))
            .then_with(|| a.fp_hash.cmp(&b.fp_hash))
            .then_with(|| a.finding.title.cmp(&b.finding.title))
    });

    let mut sorted_exemplars: BTreeMap<&str, &Finding> = BTreeMap::new();
    for item in &prepared {
        sorted_exemplars.entry(item.finding.scar_id.as_str()).or_insert(&item.finding);
    }
    let mut rule_indices: BTreeMap<&str, usize> = BTreeMap::new();
    for (sorted_idx, &scar_id) in sorted_exemplars.keys().enumerate() {
        rule_indices.insert(scar_id, sorted_idx);
    }

    let mut rules_json = String::with_capacity(sorted_exemplars.len().saturating_mul(256));
    for (idx, rf) in sorted_exemplars.values().enumerate() {
        if idx > 0 {
            rules_json.push(',');
        }
        let lvl = sarif_level(rf.severity);
        rules_json.push_str("{\"id\":\"");
        json_escape_into(&rf.scar_id, &mut rules_json);
        rules_json.push_str("\",\"shortDescription\":{\"text\":\"");
        json_escape_into(&rf.title, &mut rules_json);
        rules_json.push_str("\"},\"helpUri\":\"");
        rules_json.push_str(SARIF_RULES_HELP_URI);
        rules_json.push_str("\",\"help\":{\"text\":\"");
        json_escape_into(&rf.fix_hint, &mut rules_json);
        rules_json.push_str("\"},\"defaultConfiguration\":{\"level\":\"");
        rules_json.push_str(lvl);
        rules_json.push_str("\"},\"properties\":{\"category\":\"");
        json_escape_into(&rf.category, &mut rules_json);
        rules_json.push_str("\",\"severity\":\"");
        rules_json.push_str(rf.severity.as_str());
        rules_json.push_str("\"}}");
    }

    let mut results_json = String::with_capacity(prepared.len().saturating_mul(360));
    for (idx, item) in prepared.iter().enumerate() {
        if idx > 0 {
            results_json.push(',');
        }
        let f = &item.finding;
        let rule_idx = rule_indices.get(f.scar_id.as_str()).copied().unwrap_or(0);
        let lvl = sarif_level(f.severity);
        let msg = if f.fix_hint.is_empty() {
            f.title.clone()
        } else {
            format!("{} — Fix: {}", f.title, f.fix_hint)
        };
        results_json.push_str("{\"ruleId\":\"");
        json_escape_into(&f.scar_id, &mut results_json);
        results_json.push_str("\",\"ruleIndex\":");
        results_json.push_str(&rule_idx.to_string());
        results_json.push_str(",\"level\":\"");
        results_json.push_str(lvl);
        results_json.push_str("\",\"message\":{\"text\":\"");
        json_escape_into(&msg, &mut results_json);
        results_json.push_str("\"},\"partialFingerprints\":{\"primaryLocationLineHash\":\"");
        results_json.push_str(&item.fp_hash);
        results_json.push_str("\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"");
        json_escape_into(&item.uri, &mut results_json);
        results_json.push_str("\"},\"region\":{\"startLine\":");
        results_json.push_str(&item.start_line.to_string());
        results_json.push_str(",\"startColumn\":");
        results_json.push_str(&item.start_col.to_string());
        results_json.push_str(",\"snippet\":{\"text\":\"");
        json_escape_into(&f.snippet, &mut results_json);
        results_json.push_str("\"}}}}]}");
    }

    format!(
        "{{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{{\"automationDetails\":{{\"id\":\"kintsugi-rs/v{}\"}},\"tool\":{{\"driver\":{{\"name\":\"kintsugi-rs\",\"version\":\"{}\",\"informationUri\":\"https://github.com/tunguyen1993/kintsugi-harness\",\"rules\":[{}]}}}},\"results\":[{}]}}]}}",
        ENGINE_VERSION, ENGINE_VERSION, rules_json, results_json
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn sample_finding(id: &str, sev: Severity, path: &str, line: usize, hint: &str) -> Finding {
        Finding {
            scar_id: id.to_string(),
            title: format!("Title for {id}"),
            severity: sev,
            category: "security".to_string(),
            file_path: path.to_string(),
            line,
            column: 4,
            snippet: "bad_call(x)".to_string(),
            fix_hint: hint.to_string(),
        }
    }

    #[test]
    fn dedup_self_protecting_gate_compact_and_scan_json_meta() {
        assert_eq!(render_gate_compact(&[], 80), "");
        let raw_dups = vec![
            sample_finding("KS-020", Severity::High, "b.py", 10, "use safe_load"),
            sample_finding("KS-002", Severity::Critical, "a.py", 5, "shell=False"),
            sample_finding("KS-002", Severity::Critical, "a.py", 5, "shell=False"),
            sample_finding("KS-001", Severity::High, "a.py", 5, "env secrets"),
        ];
        let mut deduped = raw_dups.clone();
        deduplicate_findings(&mut deduped);
        assert_eq!(deduped.len(), 3);

        let det_raw = render_gate_compact_detailed(&raw_dups, 120);
        let det_clean = render_gate_compact_detailed(&deduped, 120);
        assert_eq!(det_raw, det_clean);
        assert_eq!(det_raw.kept_findings + det_raw.omitted_findings, 3);
        assert!(!det_raw.first_line_clipped);

        let zero_budget = render_gate_compact_detailed(&raw_dups, 0);
        assert_eq!(zero_budget.omitted_findings, 3);
        assert!(!zero_budget.first_line_clipped);

        let tiny_budget = render_gate_compact_detailed(&raw_dups, 5);
        assert!(tiny_budget.first_line_clipped);
        assert!(tiny_budget.kept_findings <= 1);

        let sum36 = ScanSummary { scanned_files: 2, active_rules: 36, elapsed_micros: 500, findings: Vec::new() };
        let sum41 = ScanSummary { scanned_files: 2, active_rules: 41, elapsed_micros: 500, findings: Vec::new() };
        assert!(render_scan_summary_json(&sum36).contains("\"shadow_arm_c\":false"));
        assert!(render_scan_summary_json(&sum41).contains("\"shadow_arm_c\":true"));
        assert!(render_scan_json_with_meta(&sum36, true, 2).contains("\"shadow_arm_c\":true,\"dynamic_rules\":2"));

        let many: Vec<Finding> = (0..120)
            .map(|i| sample_finding("KS-020", Severity::High, "./src/loader.py", i + 1, "Replace yaml.load with safe_load"))
            .collect();
        for budget in [4usize, 12, 30, 80, 150] {
            let det = render_gate_compact_detailed(&many, budget);
            assert!(!det.text.is_empty());
            assert_eq!(det.estimated_tokens, estimate_tokens(&det.text));
            assert!(det.estimated_tokens <= budget);
            assert_eq!(det.kept_findings + det.omitted_findings, many.len());
        }
    }

    #[test]
    fn render_gate_compact_scales_linearly_2000_findings() {
        use std::time::Instant;

        let bulk: Vec<Finding> = (0..2000)
            .map(|i| {
                sample_finding(
                    "KS-077",
                    Severity::Medium,
                    &format!("src/module_{}.py", i % 50),
                    (i / 50) + 1,
                    "Avoid hardcoded timeout",
                )
            })
            .collect();

        let start = Instant::now();
        let result = render_gate_compact_detailed(&bulk, 500);
        let elapsed = start.elapsed();

        assert!(elapsed.as_millis() < 150, "O(n) render took {:?} in debug profile (expected < 150ms)", elapsed);
        assert!(result.kept_findings > 0);
        assert_eq!(result.kept_findings + result.omitted_findings, 2000);
        assert!(result.estimated_tokens <= 500);
        assert_eq!(result.estimated_tokens, estimate_tokens(&result.text));
        assert!(!result.first_line_clipped || result.kept_findings == 1);
    }

    #[cfg(feature = "sarif")]
    #[test]
    fn sarif_sorted_results_byte_identical_across_permutations() {
        let a = sample_finding("KS-002", Severity::Critical, "src/run.py", 12, "Use shell=False");
        let b = sample_finding("KS-099", Severity::Medium, "src/cfg.py", 8, "Pin timeout");
        let c = sample_finding("KS-100", Severity::Low, "src/log.py", 3, "Avoid debug print");

        let sarif_fwd = render_findings_sarif(&[a.clone(), b.clone(), c.clone()]);
        let sarif_rev = render_findings_sarif(&[c.clone(), b.clone(), a.clone()]);
        let sarif_mid = render_findings_sarif(&[b.clone(), c.clone(), a.clone()]);
        assert_eq!(sarif_fwd, sarif_rev);
        assert_eq!(sarif_fwd, sarif_mid);
        assert!(sarif_fwd.contains("\"automationDetails\":{\"id\":\"kintsugi-rs/v2.4.1\"}"));
        assert!(sarif_fwd.contains("\"helpUri\":\"https://github.com/tunguyen1993/kintsugi-harness#rules\""));
        assert!(sarif_fwd.contains("\"partialFingerprints\":{\"primaryLocationLineHash\":\""));
        assert!(sarif_fwd.contains("\"ruleId\":\"KS-002\",\"ruleIndex\":0"));
        assert!(sarif_fwd.contains("\"ruleId\":\"KS-100\",\"ruleIndex\":2"));

        let many: Vec<Finding> = (0..300)
            .map(|i| sample_finding("KS-050", Severity::High, &format!("lib/mod{}.py", i), i + 1, "Use allow list"))
            .collect();
        let sarif_bulk = render_findings_sarif(&many);
        assert!(sarif_bulk.contains("\"rules\":[{\"id\":\"KS-050\""));
        assert!(sarif_bulk.contains("\"results\":[{\"ruleId\":\"KS-050\""));
    }
}
