//! `P2.6` Dynamic Runtime Rule Registry (`DynamicRuleRegistry`) — Zero-Recompile Extensibility
//! with fail-closed duplicate-ID rejection, strict 9-field KML validation, and `manifest_sha256` attestation.

use std::fs;
use std::path::{Path, PathBuf};

use crate::bounded_regex::BoundedRegex;
use crate::io_json::JsonObj;
use crate::json_dom::{parse_json_value, JsonValue};
use crate::kernels::rule_prefilter::{LiteralSpec, RulePrefilter};
use crate::kml::{audit_kml_record_security, validate_kml_line_strict, KmlRecord};
use crate::model::{Finding, Severity};
use crate::policy::sha256_hex;
use crate::rule_ir::{compile_rule_ir_strict, rule_matches_language, CompiledPredicate, CompiledRuleIr};
use crate::unicode_policy::contains_security_unicode_control;

pub const MAX_DYNAMIC_RULES: usize = 512;
pub const MAX_DYNAMIC_RULE_FILE_BYTES: usize = 512 * 1024;
pub const MAX_DYNAMIC_STEPS_PER_SCAN: usize = 500_000;
pub const MAX_DYNAMIC_FINDINGS_PER_FILE: usize = 128;

const MAX_RULES_DIR_DEPTH: usize = 16;
const MANIFEST_DOMAIN_TAG: &[u8] = b"kintsugi-dynamic-manifest-v1@2.4.1\n";

#[derive(Debug, Clone)]
enum DynamicMatcher { RuleIr(CompiledRuleIr), Literal(String), Regex(BoundedRegex) }

#[derive(Debug, Clone)]
struct DynamicRuleEntry {
    id: String, title: String, severity: Severity, category: String,
    languages: Vec<String>, fix_hint: String, anchor_literals: Vec<Vec<u8>>, matcher: DynamicMatcher,
}

impl DynamicRuleEntry {
    fn canonical_manifest_line(&self) -> String {
        let mut langs = self.languages.clone();
        langs.sort();
        let (kind, spec) = match &self.matcher {
            DynamicMatcher::RuleIr(ir) => {
                let pred_str = match &ir.predicate {
                    CompiledPredicate::AstPattern(m) => JsonValue::Object(m.clone()).to_canonical_json(),
                    CompiledPredicate::BoundedRegex(rx) => rx.as_str().to_string(),
                    CompiledPredicate::PathPolicy { workspace_root } => workspace_root.clone(),
                };
                ("rule_ir", format!("{}:{}", ir.reason_code, pred_str))
            }
            DynamicMatcher::Literal(lit) => ("literal", lit.clone()),
            DynamicMatcher::Regex(rx) => ("bounded_regex", rx.as_str().to_string()),
        };
        JsonObj::new()
            .str("id", &self.id).str("sev", self.severity.as_str()).str("cat", &self.category)
            .str("langs", &langs.join(",")).str("kind", kind).str("spec", &spec).str("fix", &self.fix_hint)
            .finish()
    }
}

fn compute_entries_manifest_sha256(entries: &[DynamicRuleEntry]) -> String {
    let mut lines: Vec<String> = entries.iter().map(DynamicRuleEntry::canonical_manifest_line).collect();
    lines.sort();
    let mut buf = Vec::with_capacity(MANIFEST_DOMAIN_TAG.len() + lines.iter().map(|s| s.len() + 1).sum::<usize>());
    buf.extend_from_slice(MANIFEST_DOMAIN_TAG);
    for ln in &lines {
        buf.extend_from_slice(ln.as_bytes());
        buf.push(b'\n');
    }
    sha256_hex(&buf)
}

#[derive(Debug, Clone)]
pub struct DynamicRuleRegistry {
    entries: Vec<DynamicRuleEntry>,
    prefilter: RulePrefilter,
    manifest_sha256: String,
}

fn parse_kml_severity(sev: &str) -> Severity {
    match sev.trim().to_ascii_uppercase().as_str() {
        "C" | "CRIT" | "CRITICAL" => Severity::Critical,
        "H" | "HIGH" => Severity::High,
        "M" | "MED" | "MEDIUM" => Severity::Medium,
        _ => Severity::Low,
    }
}

fn collect_rule_files_strict(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if depth > MAX_RULES_DIR_DEPTH {
        return Err(format!("Dynamic rules directory nesting exceeds {MAX_RULES_DIR_DEPTH}"));
    }
    let rd = fs::read_dir(dir).map_err(|e| format!("Failed reading {}: {e}", dir.display()))?;
    let mut paths: Vec<PathBuf> = rd
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Directory entry error: {e}"))?
        .into_iter()
        .map(|e| e.path())
        .collect();
    paths.sort();

    for p in paths {
        let meta = fs::symlink_metadata(&p).map_err(|e| format!("Cannot stat {}: {e}", p.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink refused inside dynamic rules directory: {}", p.display()));
        }
        if meta.is_dir() {
            if p.file_name().and_then(|n| n.to_str()) != Some(".git") {
                collect_rule_files_strict(&p, depth + 1, out)?;
            }
        } else if meta.is_file() {
            if meta.len() > MAX_DYNAMIC_RULE_FILE_BYTES as u64 {
                return Err(format!("File {} exceeds {MAX_DYNAMIC_RULE_FILE_BYTES} bytes", p.display()));
            }
            if p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("json") || e.eq_ignore_ascii_case("kml")) {
                out.push(p);
            }
        }
    }
    Ok(())
}

fn entry_from_compiled_ir(compiled: CompiledRuleIr) -> DynamicRuleEntry {
    DynamicRuleEntry {
        id: compiled.rule_id.clone(),
        title: format!("@RULE_IR/1[ID:{}|REASON:{}]", compiled.rule_id, compiled.reason_code),
        severity: compiled.severity,
        category: "dynamic-rule-ir".to_string(),
        languages: compiled.languages.clone(),
        fix_hint: format!("Remediate dynamic RuleIR/1 violation ({})", compiled.reason_code),
        anchor_literals: compiled.anchor_literals.clone(),
        matcher: DynamicMatcher::RuleIr(compiled),
    }
}

fn entry_from_kml_record(rec: KmlRecord) -> Result<DynamicRuleEntry, String> {
    audit_kml_record_security(&rec)
        .map_err(|code| format!("KML record {} failed security audit: {code}", rec.id))?;
    if contains_security_unicode_control(&rec.neg, false) {
        return Err(format!("KML record {} contains trojan-source unicode in neg field", rec.id));
    }

    if let Some(ir_raw) = rec
        .neg
        .strip_prefix("rule_ir_json:")
        .or_else(|| rec.neg.strip_prefix("RULE_IR:"))
        .or_else(|| rec.guard.strip_prefix("RULE_IR:"))
    {
        let mut ir_entry = entry_from_compiled_ir(compile_rule_ir_strict(ir_raw.trim())?);
        if ir_entry.id != rec.id {
            return Err(format!("KML record id '{}' mismatches embedded RuleIR id '{}'", rec.id, ir_entry.id));
        }
        if !rec.cat.is_empty() {
            ir_entry.category = rec.cat;
        }
        return Ok(ir_entry);
    }

    let severity = parse_kml_severity(&rec.sev);
    let languages: Vec<String> = rec.lang.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
    let title = if rec.op.is_empty() { format!("@KML/1[ID:{}]", rec.id) } else { format!("@KML/1[ID:{}|OP:{}]", rec.id, rec.op) };
    let fix_hint = if rec.pos.is_empty() { format!("Apply safe remediation for {}", rec.id) } else { rec.pos };
    let category = if rec.cat.is_empty() { "dynamic-kml".to_string() } else { rec.cat };

    if let Some(rx_pat) = rec.neg.strip_prefix("bounded_regex:").or_else(|| rec.neg.strip_prefix("regex:")) {
        let rx = BoundedRegex::compile(rx_pat.trim())?;
        let anchors = rx.required_anchor_literals();
        return Ok(DynamicRuleEntry {
            id: rec.id, title, severity, category, languages, fix_hint,
            anchor_literals: anchors, matcher: DynamicMatcher::Regex(rx),
        });
    }

    let raw_lit = rec.neg.strip_prefix("neg_literal:").unwrap_or(&rec.neg).trim();
    if raw_lit.len() < 4 || raw_lit.contains('\0') || raw_lit.starts_with("ANTI_PATTERN_") {
        return Err(format!("KML dynamic rule {} requires safe literal >= 4 bytes", rec.id));
    }
    let needle = raw_lit.to_string();
    Ok(DynamicRuleEntry {
        id: rec.id, title, severity, category, languages, fix_hint,
        anchor_literals: vec![needle.as_bytes().to_vec()], matcher: DynamicMatcher::Literal(needle),
    })
}

impl DynamicRuleRegistry {
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            prefilter: RulePrefilter::new(0, &[], &[]),
            manifest_sha256: compute_entries_manifest_sha256(&[]),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the 64-char lowercase hex SHA-256 manifest digest over all loaded canonical rules.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    fn build_from_entries(entries: Vec<DynamicRuleEntry>) -> Result<Self, String> {
        if entries.len() > MAX_DYNAMIC_RULES {
            return Err(format!("Dynamic rule count ({}) exceeds MAX_DYNAMIC_RULES ({MAX_DYNAMIC_RULES})", entries.len()));
        }
        let mut specs = Vec::new();
        let mut always_active = Vec::new();
        for (idx, entry) in entries.iter().enumerate() {
            let mut has_anchor = false;
            for lit in &entry.anchor_literals {
                if lit.len() >= 2 {
                    specs.push(LiteralSpec { rule_index: idx, pattern: lit.clone(), case_insensitive: false });
                    has_anchor = true;
                }
            }
            if !has_anchor {
                always_active.push(idx);
            }
        }
        let prefilter = RulePrefilter::new(entries.len(), &specs, &always_active);
        let manifest_sha256 = compute_entries_manifest_sha256(&entries);
        Ok(Self { entries, prefilter, manifest_sha256 })
    }

    fn push_entry(entries: &mut Vec<DynamicRuleEntry>, entry: DynamicRuleEntry) -> Result<(), String> {
        if entries.iter().any(|e| e.id == entry.id) {
            return Err(format!("Duplicate dynamic rule ID '{}'", entry.id));
        }
        if entries.len() >= MAX_DYNAMIC_RULES {
            return Err(format!("Dynamic rule count exceeds MAX_DYNAMIC_RULES ({MAX_DYNAMIC_RULES})"));
        }
        entries.push(entry);
        Ok(())
    }

    pub fn from_rule_ir_json_list(jsons: &[String]) -> Result<Self, String> {
        if jsons.len() > MAX_DYNAMIC_RULES {
            return Err(format!("RuleIR list length ({}) exceeds MAX_DYNAMIC_RULES ({MAX_DYNAMIC_RULES})", jsons.len()));
        }
        let mut entries = Vec::with_capacity(jsons.len());
        for raw in jsons {
            if raw.len() > MAX_DYNAMIC_RULE_FILE_BYTES {
                return Err(format!("RuleIR JSON payload exceeds {MAX_DYNAMIC_RULE_FILE_BYTES} bytes"));
            }
            Self::push_entry(&mut entries, entry_from_compiled_ir(compile_rule_ir_strict(raw)?))?;
        }
        Self::build_from_entries(entries)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("Cannot access dynamic rules path {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!("Symlink dynamic rules path refused: {}", path.display()));
        }

        let mut rule_files = Vec::new();
        if meta.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("json") && !ext.eq_ignore_ascii_case("kml") {
                return Err(format!("Unsupported dynamic rule file extension: {}", path.display()));
            }
            rule_files.push(path.to_path_buf());
        } else if meta.is_dir() {
            collect_rule_files_strict(path, 0, &mut rule_files)?;
        } else {
            return Err(format!("Unsupported dynamic rules path type: {}", path.display()));
        }

        let mut entries = Vec::new();
        for file in rule_files {
            let raw = crate::io_json::read_regular_file_fd_verified(&file, MAX_DYNAMIC_RULE_FILE_BYTES as u64)?;
            let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext.eq_ignore_ascii_case("json") {
                match parse_json_value(raw.trim())? {
                    JsonValue::Object(_) => {
                        Self::push_entry(&mut entries, entry_from_compiled_ir(compile_rule_ir_strict(raw.trim())?))?;
                    }
                    JsonValue::Array(items) if !items.is_empty() => {
                        for item in items {
                            let ir = compile_rule_ir_strict(&item.to_canonical_json())?;
                            Self::push_entry(&mut entries, entry_from_compiled_ir(ir))?;
                        }
                    }
                    _ => return Err(format!("Dynamic JSON rule file must be non-empty object or array: {}", file.display())),
                }
            } else {
                let mut file_loaded = 0usize;
                for (ln_idx, line) in raw.lines().enumerate() {
                    let t = line.trim();
                    if t.is_empty() || t.starts_with('#') {
                        continue;
                    }
                    let inline_ir = t
                        .strip_prefix("RULE_IR:")
                        .or_else(|| t.strip_prefix("@DYNAMIC_RULE|"))
                        .or_else(|| t.strip_prefix("@DYNAMIC_RULE:"))
                        .or_else(|| t.strip_prefix("@DYNAMIC_RULE").map(str::trim).filter(|s| s.starts_with('{')));
                    if let Some(ir_body) = inline_ir {
                        Self::push_entry(&mut entries, entry_from_compiled_ir(compile_rule_ir_strict(ir_body.trim())?))?;
                        file_loaded += 1;
                    } else {
                        let rec = validate_kml_line_strict(t)
                            .map_err(|e| format!("Invalid KML syntax at {}:{}: {e}", file.display(), ln_idx + 1))?;
                        Self::push_entry(&mut entries, entry_from_kml_record(rec)?)?;
                        file_loaded += 1;
                    }
                }
                if file_loaded == 0 {
                    return Err(format!("No valid @KML/1 or RULE_IR rules found in {}", file.display()));
                }
            }
        }
        Self::build_from_entries(entries)
    }

    pub fn scan_buffer(
        &self,
        content: &str,
        file_path: &str,
        lang: &str,
        min_severity: Severity,
    ) -> Vec<Finding> {
        if self.entries.is_empty() || content.is_empty() {
            return Vec::new();
        }
        let candidates = self.prefilter.candidate_rule_indices(content.as_bytes(), false);
        if candidates.is_empty() {
            return Vec::new();
        }

        let mut step_budget = MAX_DYNAMIC_STEPS_PER_SCAN;
        let mut findings = Vec::new();
        let mut lines_cache: Option<Vec<&str>> = None;
        let (mut budget_exhausted, mut findings_truncated) = (false, false);

        let push_hits = |out: &mut Vec<Finding>, truncated: &mut bool, entry: &DynamicRuleEntry, hits: Vec<(usize, String)>| {
            for (line_no, snip) in hits {
                if out.len() >= MAX_DYNAMIC_FINDINGS_PER_FILE {
                    *truncated = true;
                    break;
                }
                out.push(Finding {
                    scar_id: entry.id.clone(),
                    title: entry.title.clone(),
                    severity: entry.severity,
                    category: entry.category.clone(),
                    file_path: file_path.to_string(),
                    line: line_no.max(1),
                    column: 1,
                    snippet: snip,
                    fix_hint: entry.fix_hint.clone(),
                });
            }
        };

        for rule_idx in candidates {
            if findings.len() >= MAX_DYNAMIC_FINDINGS_PER_FILE {
                findings_truncated = true;
                break;
            }
            if step_budget == 0 {
                budget_exhausted = true;
                break;
            }
            let entry = &self.entries[rule_idx];
            if entry.severity < min_severity || !rule_matches_language(&entry.languages, lang) {
                continue;
            }
            match &entry.matcher {
                DynamicMatcher::RuleIr(compiled) => match compiled.eval_compiled_no_fs(content, lang, &mut step_budget) {
                    Ok(hits) => push_hits(&mut findings, &mut findings_truncated, entry, hits),
                    Err(_) => {
                        budget_exhausted = true;
                        break;
                    }
                },
                DynamicMatcher::Regex(rx) => match rx.find_all_with_budget(content, &mut step_budget) {
                    Ok(hits) => push_hits(&mut findings, &mut findings_truncated, entry, hits),
                    Err(_) => {
                        budget_exhausted = true;
                        break;
                    }
                },
                DynamicMatcher::Literal(needle) => {
                    let lines = lines_cache.get_or_insert_with(|| content.lines().collect());
                    for (idx, line) in lines.iter().enumerate() {
                        if step_budget == 0 {
                            budget_exhausted = true;
                            break;
                        }
                        if findings.len() >= MAX_DYNAMIC_FINDINGS_PER_FILE {
                            findings_truncated = true;
                            break;
                        }
                        step_budget -= 1;
                        if let Some(byte_col) = line.find(needle.as_str()) {
                            findings.push(Finding {
                                scar_id: entry.id.clone(),
                                title: entry.title.clone(),
                                severity: entry.severity,
                                category: entry.category.clone(),
                                file_path: file_path.to_string(),
                                line: idx + 1,
                                column: line[..byte_col].chars().count() + 1,
                                snippet: line.trim().chars().take(120).collect(),
                                fix_hint: entry.fix_hint.clone(),
                            });
                        }
                    }
                }
            }
        }

        if budget_exhausted && Severity::High >= min_severity {
            findings.push(Finding {
                scar_id: "KS-DYN-BUDGET-EXHAUSTED".to_string(),
                title: format!("Fail-closed: dynamic rule evaluation exhausted {MAX_DYNAMIC_STEPS_PER_SCAN} step budget"),
                severity: Severity::High, category: "security".to_string(), file_path: file_path.to_string(),
                line: 1, column: 1, snippet: "dynamic_rule_step_budget_exhausted".to_string(),
                fix_hint: "Simplify dynamic regex/AST rules or split oversized input file".to_string(),
            });
        } else if findings_truncated && Severity::Medium >= min_severity {
            findings.push(Finding {
                scar_id: "KS-DYN-FINDINGS-TRUNCATED".to_string(),
                title: format!("Dynamic rule findings capped at {MAX_DYNAMIC_FINDINGS_PER_FILE} for file"),
                severity: Severity::Medium, category: "reliability".to_string(), file_path: file_path.to_string(),
                line: 1, column: 1, snippet: "dynamic_findings_truncated".to_string(),
                fix_hint: "Resolve reported dynamic violations and re-run scan for remaining hits".to_string(),
            });
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sha256_deterministic_and_duplicate_rule_ids_fail_closed() {
        let empty = DynamicRuleRegistry::empty();
        assert_eq!(empty.manifest_sha256().len(), 64);
        let r1 = entry_from_kml_record(KmlRecord {
            id: "KS-DYN-T1".into(), sev: "H".into(), cat: "security".into(), lang: "py".into(),
            op: "op1".into(), guard: "KML".into(), neg: "neg_literal:danger_call(".into(), pos: "safe_call()".into(), fp: "f1".into(),
        }).unwrap();
        let mut list = Vec::new();
        DynamicRuleRegistry::push_entry(&mut list, r1.clone()).unwrap();
        let dup_err = DynamicRuleRegistry::push_entry(&mut list, r1.clone()).unwrap_err();
        assert!(dup_err.contains("Duplicate dynamic rule ID 'KS-DYN-T1'"), "{dup_err}");

        let reg_a = DynamicRuleRegistry::build_from_entries(vec![r1.clone()]).unwrap();
        let reg_b = DynamicRuleRegistry::build_from_entries(vec![r1]).unwrap();
        assert_eq!(reg_a.manifest_sha256(), reg_b.manifest_sha256());
        assert_ne!(reg_a.manifest_sha256(), empty.manifest_sha256());
    }
}
