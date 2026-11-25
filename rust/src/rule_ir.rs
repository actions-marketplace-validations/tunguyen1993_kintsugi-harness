//! Declarative `RuleIR/1` validator, pre-compiler (`CompiledRuleIr`), decoupled `PathPolicyEvaluator`,
//! strict closed-schema field enforcement, size bounds, and fail-closed deterministic evaluator.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::bounded_regex::BoundedRegex;
use crate::io_json::JsonObj;
use crate::json_dom::{compute_rule_ir_canonical_hash, parse_json_value, JsonValue};
use crate::model::Severity;
use crate::policy::is_dangerous_rm_target_with_ws_opt;
use crate::scanner::MAX_SOURCE_FILE_BYTES;

/// Maximum serialized byte size of a single `RuleIR/1` JSON payload (`256 KiB`).
pub const MAX_RULE_IR_JSON_BYTES: usize = 256 * 1024;

const ALLOWED_ROOT_KEYS: &[&str] = &[
    "schema", "schema_version", "rule_id", "id", "revision", "language", "languages",
    "severity", "predicate_kind", "predicate", "match", "conditions", "response", "reason",
    "source_trace_ids", "negative_corpus_digest", "rule_hash", "canonical_sha256", "provenance",
];
const ALLOWED_AST_MATCH_KEYS: &[&str] = &[
    "node", "target", "forbidden_value", "callee", "mode", "kwarg", "allowed_values",
];
const ALLOWED_CONDITIONS_KEYS: &[&str] = &["inside_string_literal", "note", "description", "scope"];
const ALLOWED_RESPONSE_KEYS: &[&str] = &["decision", "reason_code", "message"];
const ALLOWED_PROVENANCE_KEYS: &[&str] = &[
    "synthesizer", "strategy", "human_approved", "stage", "promoted_at", "author", "source", "note",
];

/// Decoupled path-safety policy trait allowing `RuleIR/1` evaluation with or without host FS access.
pub trait PathPolicyEvaluator {
    fn is_dangerous_path(&self, target: &str) -> bool;
}

/// Pure-lexical zero-syscall path policy evaluator for untrusted/sandboxed buffer evaluation.
#[derive(Debug, Clone, Default)]
pub struct NoFsPathPolicy {
    pub workspace_root: Option<PathBuf>,
}

impl PathPolicyEvaluator for NoFsPathPolicy {
    fn is_dangerous_path(&self, target: &str) -> bool {
        is_dangerous_rm_target_with_ws_opt(target, self.workspace_root.as_deref(), false, false)
    }
}

/// Workspace-anchored symlink-aware path policy evaluator for host CLI/FFI evaluation.
#[derive(Debug, Clone, Copy)]
pub struct WorkspacePathPolicy<'a> {
    pub workspace_root: &'a Path,
}

impl PathPolicyEvaluator for WorkspacePathPolicy<'_> {
    fn is_dangerous_path(&self, target: &str) -> bool {
        is_dangerous_rm_target_with_ws_opt(target, Some(self.workspace_root), false, true)
    }
}

#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    AstPattern(BTreeMap<String, JsonValue>),
    BoundedRegex(BoundedRegex),
    PathPolicy { workspace_root: String },
}

#[derive(Debug, Clone)]
pub struct CompiledRuleIr {
    pub rule_id: String,
    pub severity: Severity,
    pub languages: Vec<String>,
    pub reason_code: String,
    pub predicate: CompiledPredicate,
    pub anchor_literals: Vec<Vec<u8>>,
}

pub fn normalize_rule_lang(raw: &str) -> &'static str {
    match raw.trim().to_ascii_lowercase().as_str() {
        "py" | "python" => "python",
        "js" | "mjs" | "cjs" | "jsx" | "javascript" => "javascript",
        "ts" | "tsx" | "typescript" => "typescript",
        "sh" | "bash" | "zsh" | "shell" => "shell",
        "rs" | "rust" => "rust", "go" | "golang" => "go",
        "md" | "mark" | "markdown" => "markdown",
        "java" => "java", "php" => "php", "sol" | "solidity" => "solidity",
        "*" | "all" | "any" => "*", _ => "other",
    }
}

pub fn rule_matches_language(rule_langs: &[String], target_lang: &str) -> bool {
    if rule_langs.is_empty() || target_lang.trim().is_empty() { return true; }
    let norm_target = normalize_rule_lang(target_lang);
    rule_langs.iter().any(|rl| {
        let nr = normalize_rule_lang(rl);
        nr == "*" || (nr != "other" && nr == norm_target) || rl.trim().eq_ignore_ascii_case(target_lang.trim())
    })
}

#[derive(Debug, Clone, PartialEq)]
enum PyTokenKind {
    Ident(String), Str(String), Int(i64), Float(f64),
    LParen, RParen, LBracket, RBracket, LBrace, RBrace,
    Comma, Dot, Colon, Eq, EqEq, NotEq, Semi, Newline, Other(char),
}

#[derive(Debug, Clone)]
struct PyToken { kind: PyTokenKind, line: usize }

fn tokenize_python_subset(code: &str) -> Result<Vec<PyToken>, ()> {
    let chars: Vec<char> = code.chars().collect();
    let mut tokens = Vec::new();
    let (mut i, mut line, mut bracket_depth) = (0usize, 1usize, 0usize);

    while i < chars.len() {
        let ch = chars[i];
        if matches!(ch, ' ' | '\t' | '\r') { i += 1; continue; }
        if ch == '\\' && chars.get(i + 1) == Some(&'\n') { line += 1; i += 2; continue; }
        if ch == '\n' {
            if bracket_depth == 0 { tokens.push(PyToken { kind: PyTokenKind::Newline, line }); }
            line += 1; i += 1; continue;
        }
        if ch == '#' { while i < chars.len() && chars[i] != '\n' { i += 1; } continue; }

        let (mut str_quote_idx, mut is_raw) = (None, false);
        if ch == '\'' || ch == '"' {
            str_quote_idx = Some(i);
        } else if matches!(ch, 'r' | 'R' | 'f' | 'F' | 'b' | 'B' | 'u' | 'U') {
            if chars.get(i + 1).is_some_and(|&q| q == '\'' || q == '"') {
                is_raw = matches!(ch, 'r' | 'R');
                str_quote_idx = Some(i + 1);
            } else if chars.get(i + 1).is_some_and(|c| matches!(c, 'r' | 'R' | 'f' | 'F' | 'b' | 'B'))
                && chars.get(i + 2).is_some_and(|&q| q == '\'' || q == '"')
            {
                is_raw = matches!(ch, 'r' | 'R') || matches!(chars[i + 1], 'r' | 'R');
                str_quote_idx = Some(i + 2);
            }
        }
        if let Some(q_idx) = str_quote_idx {
            let quote = chars[q_idx];
            let triple = chars.get(q_idx + 1) == Some(&quote) && chars.get(q_idx + 2) == Some(&quote);
            let start_ln = line;
            let mut p = q_idx + if triple { 3 } else { 1 };
            let (mut s, mut closed) = (String::new(), false);
            while p < chars.len() {
                let c = chars[p];
                if c == '\n' { if !triple { return Err(()); } line += 1; }
                if c == '\\' && p + 1 < chars.len() {
                    let nxt = chars[p + 1];
                    if is_raw {
                        s.push(c); s.push(nxt);
                        if nxt == '\n' { line += 1; }
                    } else {
                        match nxt {
                            'n' => s.push('\n'), 'r' => s.push('\r'), 't' => s.push('\t'),
                            '\\' => s.push('\\'), '\'' => s.push('\''), '"' => s.push('"'),
                            '\n' => line += 1, other => { s.push('\\'); s.push(other); }
                        }
                    }
                    p += 2; continue;
                }
                if triple && chars.get(p + 1) == Some(&quote) && chars.get(p + 2) == Some(&quote) && c == quote {
                    p += 3; closed = true; break;
                } else if !triple && c == quote {
                    p += 1; closed = true; break;
                }
                s.push(c); p += 1;
            }
            if !closed { return Err(()); }
            tokens.push(PyToken { kind: PyTokenKind::Str(s), line: start_ln });
            i = p; continue;
        }

        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') { i += 1; }
            tokens.push(PyToken { kind: PyTokenKind::Ident(chars[start..i].iter().collect()), line });
            continue;
        }

        if ch.is_ascii_digit() {
            let (start, mut is_float) = (i, false);
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '_') { i += 1; }
            if chars.get(i) == Some(&'.') && chars.get(i + 1).is_some_and(|c| c.is_ascii_digit()) {
                is_float = true; i += 1;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '_') { i += 1; }
            }
            let raw_num: String = chars[start..i].iter().filter(|&&c| c != '_').collect();
            let kind = if is_float { PyTokenKind::Float(raw_num.parse::<f64>().map_err(|_| ())?) } else { PyTokenKind::Int(raw_num.parse::<i64>().map_err(|_| ())?) };
            tokens.push(PyToken { kind, line });
            continue;
        }

        let (kind, step) = match ch {
            '(' => { bracket_depth += 1; (PyTokenKind::LParen, 1) }
            ')' => { bracket_depth = bracket_depth.checked_sub(1).ok_or(())?; (PyTokenKind::RParen, 1) }
            '[' => { bracket_depth += 1; (PyTokenKind::LBracket, 1) }
            ']' => { bracket_depth = bracket_depth.checked_sub(1).ok_or(())?; (PyTokenKind::RBracket, 1) }
            '{' => { bracket_depth += 1; (PyTokenKind::LBrace, 1) }
            '}' => { bracket_depth = bracket_depth.checked_sub(1).ok_or(())?; (PyTokenKind::RBrace, 1) }
            ',' => (PyTokenKind::Comma, 1), '.' => (PyTokenKind::Dot, 1),
            ':' => (PyTokenKind::Colon, 1), ';' => (PyTokenKind::Semi, 1),
            '=' if chars.get(i + 1) == Some(&'=') => (PyTokenKind::EqEq, 2),
            '=' => (PyTokenKind::Eq, 1),
            '!' if chars.get(i + 1) == Some(&'=') => (PyTokenKind::NotEq, 2),
            other => (PyTokenKind::Other(other), 1),
        };
        tokens.push(PyToken { kind, line });
        i += step;
    }
    (bracket_depth == 0).then_some(tokens).ok_or(())
}

#[derive(Debug, Clone, PartialEq)]
enum PyConstVal { None, Bool(bool), Int(i64), Float(f64), Str(String) }

impl PyConstVal {
    fn truthy(&self) -> bool {
        match self {
            PyConstVal::None => false, PyConstVal::Bool(b) => *b,
            PyConstVal::Int(n) => *n != 0, PyConstVal::Float(f) => *f != 0.0,
            PyConstVal::Str(s) => !s.is_empty(),
        }
    }

    fn py_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PyConstVal::None, PyConstVal::None) => true,
            (PyConstVal::Bool(a), PyConstVal::Bool(b)) => a == b,
            (PyConstVal::Bool(a), PyConstVal::Int(b)) => (*a as i64) == *b,
            (PyConstVal::Int(a), PyConstVal::Bool(b)) => *a == (*b as i64),
            (PyConstVal::Int(a), PyConstVal::Int(b)) => a == b,
            (PyConstVal::Float(a), PyConstVal::Float(b)) => a == b,
            (PyConstVal::Int(a), PyConstVal::Float(b)) => (*a as f64) == *b,
            (PyConstVal::Float(a), PyConstVal::Int(b)) => *a == (*b as f64),
            (PyConstVal::Str(a), PyConstVal::Str(b)) => a == b,
            _ => false,
        }
    }

    fn matches_json_exact_type(&self, json: &JsonValue) -> bool {
        match (self, json) {
            (PyConstVal::None, JsonValue::Null) => true,
            (PyConstVal::Bool(b), JsonValue::Bool(jb)) => b == jb,
            (PyConstVal::Str(s), JsonValue::Str(js)) => s == js,
            (PyConstVal::Int(n), JsonValue::Number(raw)) => raw.parse::<i64>().is_ok_and(|jn| *n == jn),
            (PyConstVal::Float(f), JsonValue::Number(raw)) => raw.parse::<f64>().is_ok_and(|jf| *f == jf),
            _ => false,
        }
    }

    fn matches_json_in_list(&self, json: &JsonValue) -> bool {
        match (self, json) {
            (PyConstVal::Bool(b), JsonValue::Number(raw)) => raw.parse::<i64>().is_ok_and(|n| (*b as i64) == n),
            (PyConstVal::Int(n), JsonValue::Bool(jb)) => *n == (*jb as i64),
            _ => self.matches_json_exact_type(json),
        }
    }
}

fn find_matching_paren(tokens: &[PyToken], lp_idx: usize) -> Option<usize> {
    if !matches!(tokens.get(lp_idx).map(|t| &t.kind), Some(PyTokenKind::LParen)) { return None; }
    let mut depth = 0usize;
    for (idx, tok) in tokens.iter().enumerate().skip(lp_idx) {
        match tok.kind {
            PyTokenKind::LParen | PyTokenKind::LBracket | PyTokenKind::LBrace => depth += 1,
            PyTokenKind::RParen | PyTokenKind::RBracket | PyTokenKind::RBrace => {
                depth = depth.saturating_sub(1);
                if depth == 0 { return Some(idx); }
            }
            _ => {}
        }
    }
    None
}

fn strip_outer_parens(mut slice: &[PyToken]) -> &[PyToken] {
    while slice.len() >= 2 && matches!(slice[0].kind, PyTokenKind::LParen) && find_matching_paren(slice, 0) == Some(slice.len() - 1) {
        slice = &slice[1..slice.len() - 1];
    }
    slice
}

fn eval_py_simple_const_bounded(tokens: &[PyToken], env: &BTreeMap<String, PyConstVal>, depth: usize) -> Option<PyConstVal> {
    if depth > 32 { return None; }
    let slice = strip_outer_parens(tokens);
    if slice.is_empty() { return None; }

    let mut bdepth = 0usize;
    for (idx, tok) in slice.iter().enumerate() {
        match tok.kind {
            PyTokenKind::LParen | PyTokenKind::LBracket | PyTokenKind::LBrace => bdepth += 1,
            PyTokenKind::RParen | PyTokenKind::RBracket | PyTokenKind::RBrace => bdepth = bdepth.saturating_sub(1),
            PyTokenKind::EqEq | PyTokenKind::NotEq if bdepth == 0 => {
                let lhs = eval_py_simple_const_bounded(&slice[..idx], env, depth + 1)?;
                let rhs = eval_py_simple_const_bounded(&slice[idx + 1..], env, depth + 1)?;
                let eq = lhs.py_eq(&rhs);
                return Some(PyConstVal::Bool(if matches!(tok.kind, PyTokenKind::EqEq) { eq } else { !eq }));
            }
            _ => {}
        }
    }

    if let PyTokenKind::Ident(ref kw) = slice[0].kind {
        if kw == "not" && slice.len() > 1 {
            return Some(PyConstVal::Bool(!eval_py_simple_const_bounded(&slice[1..], env, depth + 1)?.truthy()));
        }
        if kw == "bool" && slice.len() >= 4 && matches!(slice[1].kind, PyTokenKind::LParen) && find_matching_paren(slice, 1) == Some(slice.len() - 1) {
            return Some(PyConstVal::Bool(eval_py_simple_const_bounded(&slice[2..slice.len() - 1], env, depth + 1)?.truthy()));
        }
    }

    if slice.len() == 2 && matches!(slice[0].kind, PyTokenKind::Other('-')) {
        match slice[1].kind {
            PyTokenKind::Int(n) => return Some(PyConstVal::Int(-n)),
            PyTokenKind::Float(f) => return Some(PyConstVal::Float(-f)),
            _ => {}
        }
    }

    if slice.len() == 1 {
        return match &slice[0].kind {
            PyTokenKind::Ident(id) => match id.as_str() {
                "None" => Some(PyConstVal::None), "True" => Some(PyConstVal::Bool(true)),
                "False" => Some(PyConstVal::Bool(false)), other => env.get(other).cloned(),
            },
            PyTokenKind::Str(s) => Some(PyConstVal::Str(s.clone())),
            PyTokenKind::Int(n) => Some(PyConstVal::Int(*n)),
            PyTokenKind::Float(f) => Some(PyConstVal::Float(*f)),
            _ => None,
        };
    }

    if slice.len() >= 3 && slice.len() % 2 == 1
        && slice.iter().enumerate().all(|(idx, tok)| if idx % 2 == 0 { matches!(tok.kind, PyTokenKind::Ident(_)) } else { matches!(tok.kind, PyTokenKind::Dot) })
    {
        if let PyTokenKind::Ident(ref leaf) = slice.last().unwrap().kind {
            return Some(PyConstVal::Str(format!("attr:{leaf}")));
        }
    }
    None
}

fn is_python_non_call_keyword(ident: &str) -> bool {
    matches!(
        ident,
        "if" | "elif" | "while" | "for" | "return" | "assert" | "yield" | "del" | "raise" | "with"
            | "except" | "and" | "or" | "not" | "in" | "is" | "lambda" | "class" | "def"
            | "import" | "from" | "as" | "pass" | "break" | "continue"
    )
}

fn parse_py_dotted_name(tokens: &[PyToken], start: usize) -> Option<(Vec<String>, usize)> {
    let PyTokenKind::Ident(ref first) = tokens.get(start)?.kind else { return None };
    let mut parts = vec![first.clone()];
    let mut idx = start + 1;
    while idx + 1 < tokens.len() && matches!(tokens[idx].kind, PyTokenKind::Dot) {
        if let PyTokenKind::Ident(ref seg) = tokens[idx + 1].kind { parts.push(seg.clone()); idx += 2; } else { break; }
    }
    Some((parts, idx))
}

fn extract_import_aliases(tokens: &[PyToken]) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    let mut i = 0usize;
    while i < tokens.len() {
        let is_start = i == 0 || matches!(tokens[i - 1].kind, PyTokenKind::Newline | PyTokenKind::Semi | PyTokenKind::Colon);
        if is_start {
            if let PyTokenKind::Ident(ref kw) = tokens[i].kind {
                if kw == "import" {
                    let mut p = i + 1;
                    while p < tokens.len() && !matches!(tokens[p].kind, PyTokenKind::Newline | PyTokenKind::Semi) {
                        let Some((parts, next_p)) = parse_py_dotted_name(tokens, p) else { break };
                        let full_mod = parts.join(".");
                        p = next_p;
                        if matches!(tokens.get(p).map(|t| &t.kind), Some(PyTokenKind::Ident(s)) if s == "as") {
                            if let Some(PyTokenKind::Ident(alias)) = tokens.get(p + 1).map(|t| &t.kind) {
                                aliases.insert(alias.clone(), full_mod);
                                p += 2;
                            }
                        } else {
                            aliases.insert(parts[0].clone(), full_mod);
                        }
                        if matches!(tokens.get(p).map(|t| &t.kind), Some(PyTokenKind::Comma)) { p += 1; } else { break; }
                    }
                    i = p; continue;
                } else if kw == "from" {
                    if let Some((mod_parts, mut p)) = parse_py_dotted_name(tokens, i + 1) {
                        if matches!(tokens.get(p).map(|t| &t.kind), Some(PyTokenKind::Ident(s)) if s == "import") {
                            let mod_name = mod_parts.join(".");
                            p += 1;
                            let end_p = if matches!(tokens.get(p).map(|t| &t.kind), Some(PyTokenKind::LParen)) {
                                let rp = find_matching_paren(tokens, p).unwrap_or(tokens.len());
                                p += 1; rp
                            } else {
                                (p..tokens.len()).find(|&k| matches!(tokens[k].kind, PyTokenKind::Newline | PyTokenKind::Semi)).unwrap_or(tokens.len())
                            };
                            while p < end_p {
                                if let PyTokenKind::Ident(ref item) = tokens[p].kind {
                                    p += 1;
                                    if p + 1 < end_p && matches!(&tokens[p].kind, PyTokenKind::Ident(s) if s == "as") {
                                        if let PyTokenKind::Ident(ref alias) = tokens[p + 1].kind {
                                            aliases.insert(alias.clone(), format!("{mod_name}.{item}"));
                                            p += 2;
                                        }
                                    } else {
                                        aliases.insert(item.clone(), format!("{mod_name}.{item}"));
                                    }
                                    if p < end_p && matches!(tokens[p].kind, PyTokenKind::Comma) { p += 1; }
                                } else {
                                    p += 1;
                                }
                            }
                            i = end_p; continue;
                        }
                    }
                }
            }
        }
        i += 1;
    }
    aliases
}

fn make_hit(ln: usize, fields: &[(&str, &str)]) -> (usize, BTreeMap<String, JsonValue>) {
    let mut h = BTreeMap::new();
    h.insert("line".to_string(), JsonValue::Number(ln.to_string()));
    for &(k, v) in fields { h.insert(k.to_string(), JsonValue::Str(v.to_string())); }
    (ln, h)
}

fn eval_python_ast_pattern_tokens(
    match_obj: &BTreeMap<String, JsonValue>,
    tokens: &[PyToken],
) -> Vec<(usize, BTreeMap<String, JsonValue>)> {
    let aliases = extract_import_aliases(tokens);
    let mut assigns: Vec<(usize, String, Vec<PyToken>)> = Vec::new();
    for idx in 0..tokens.len() {
        let is_start = idx == 0 || matches!(tokens[idx - 1].kind, PyTokenKind::Newline | PyTokenKind::Semi | PyTokenKind::Colon);
        if is_start && idx + 2 < tokens.len() {
            if let (PyTokenKind::Ident(ref target), PyTokenKind::Eq) = (&tokens[idx].kind, &tokens[idx + 1].kind) {
                if !is_python_non_call_keyword(target) {
                    let (mut end, mut depth, mut has_extra_eq) = (idx + 2, 0usize, false);
                    while end < tokens.len() {
                        match tokens[end].kind {
                            PyTokenKind::LParen | PyTokenKind::LBracket | PyTokenKind::LBrace => depth += 1,
                            PyTokenKind::RParen | PyTokenKind::RBracket | PyTokenKind::RBrace => depth = depth.saturating_sub(1),
                            PyTokenKind::Newline | PyTokenKind::Semi if depth == 0 => break,
                            PyTokenKind::Eq if depth == 0 => has_extra_eq = true,
                            _ => {}
                        }
                        end += 1;
                    }
                    if !has_extra_eq { assigns.push((tokens[idx].line, target.clone(), tokens[idx + 2..end].to_vec())); }
                }
            }
        }
    }

    let mut env: BTreeMap<String, PyConstVal> = BTreeMap::new();
    for _ in 0..3 {
        let mut changed = false;
        for (_, var, rhs) in &assigns {
            if let Some(val) = eval_py_simple_const_bounded(rhs, &env, 0) {
                if env.insert(var.clone(), val.clone()).as_ref() != Some(&val) { changed = true; }
            }
        }
        if !changed { break; }
    }

    let node_type = match_obj.get("node").and_then(|v| v.as_str()).unwrap_or("");
    let mut hits = Vec::new();
    if node_type == "Assign" {
        let target_var = match_obj.get("target").and_then(|v| v.as_str()).unwrap_or("");
        let Some(forbidden_val) = match_obj.get("forbidden_value") else { return hits };
        for (ln, var, rhs) in &assigns {
            if var == target_var && eval_py_simple_const_bounded(rhs, &env, 0).is_some_and(|v| v.matches_json_exact_type(forbidden_val)) {
                hits.push(make_hit(*ln, &[("target", target_var)]));
            }
        }
        return hits;
    }

    if node_type == "Call" {
        let target_callee = match_obj.get("callee").and_then(|v| v.as_str()).unwrap_or("");
        let mode = match_obj.get("mode").and_then(|v| v.as_str()).unwrap_or("forbidden_callee");
        let kw_name = match_obj.get("kwarg").and_then(|v| v.as_str()).unwrap_or("");
        let allowed_values = match_obj.get("allowed_values").and_then(|v| v.as_array()).unwrap_or(&[]);

        for ti in 0..tokens.len() {
            if ti > 0 && matches!(&tokens[ti - 1].kind, PyTokenKind::Dot) { continue; }
            if ti > 0 && matches!(&tokens[ti - 1].kind, PyTokenKind::Ident(k) if k == "def" || k == "class") { continue; }
            let PyTokenKind::Ident(ref head) = tokens[ti].kind else { continue };
            if is_python_non_call_keyword(head) { continue; }
            let Some((parts, after_name)) = parse_py_dotted_name(tokens, ti) else { continue };
            let Some(rp_idx) = find_matching_paren(tokens, after_name) else { continue };
            let resolved = match aliases.get(&parts[0]) {
                Some(mapped) if parts.len() > 1 => format!("{mapped}.{}", parts[1..].join(".")),
                Some(mapped) => mapped.clone(),
                None => parts.join("."),
            };
            if resolved != target_callee { continue; }
            let call_ln = tokens[ti].line;
            if mode == "forbidden_callee" {
                hits.push(make_hit(call_ln, &[("callee", target_callee)]));
            } else if mode == "kwarg_not_in" {
                let arg_slice = &tokens[after_name + 1..rp_idx];
                let (mut kw_val_slice, mut seg_start, mut depth) = (None, 0usize, 0usize);
                for k in 0..=arg_slice.len() {
                    if k == arg_slice.len() || (depth == 0 && matches!(arg_slice[k].kind, PyTokenKind::Comma)) {
                        let arg = &arg_slice[seg_start..k];
                        if arg.len() >= 3 && matches!((&arg[0].kind, &arg[1].kind), (PyTokenKind::Ident(kwn), PyTokenKind::Eq) if kwn == kw_name) {
                            kw_val_slice = Some(&arg[2..]);
                            break;
                        }
                        seg_start = k + 1;
                    } else {
                        match arg_slice[k].kind {
                            PyTokenKind::LParen | PyTokenKind::LBracket | PyTokenKind::LBrace => depth += 1,
                            PyTokenKind::RParen | PyTokenKind::RBracket | PyTokenKind::RBrace => depth = depth.saturating_sub(1),
                            _ => {}
                        }
                    }
                }
                let is_hit = match kw_val_slice {
                    None => !allowed_values.iter().any(|av| av.as_str() == Some("__MISSING__")),
                    Some(val_toks) => eval_py_simple_const_bounded(val_toks, &env, 0)
                        .map_or(true, |folded| !allowed_values.iter().any(|av| folded.matches_json_in_list(av))),
                };
                if is_hit { hits.push(make_hit(call_ln, &[("callee", target_callee), ("kwarg", kw_name)])); }
            }
        }
    }
    hits
}

fn ensure_only_keys(map: &BTreeMap<String, JsonValue>, allowed: &[&str], ctx: &str) -> Result<(), String> {
    for k in map.keys() {
        if !allowed.contains(&k.as_str()) { return Err(format!("Unknown RuleIR {ctx} field '{k}'")); }
    }
    Ok(())
}

fn validate_rule_ir_subschemas(obj: &BTreeMap<String, JsonValue>, predicate_kind: &str) -> Result<(), String> {
    ensure_only_keys(obj, ALLOWED_ROOT_KEYS, "root")?;
    for (k1, k2) in [("rule_id", "id"), ("rule_hash", "canonical_sha256"), ("language", "languages")] {
        if let (Some(a), Some(b)) = (obj.get(k1), obj.get(k2)) {
            if a != b { return Err(format!("Conflicting RuleIR '{k1}' and '{k2}' fields")); }
        }
    }
    if let Some(m_val) = obj.get("match") {
        let m = m_val.as_object().ok_or_else(|| "RuleIR 'match' must be a JSON object".to_string())?;
        match predicate_kind {
            "bounded_regex" => {
                ensure_only_keys(m, &["regex"], "match[bounded_regex]")?;
                if !m.get("regex").is_some_and(|v| v.as_str().is_some()) {
                    return Err("RuleIR bounded_regex requires string 'match.regex'".to_string());
                }
            }
            "path_policy" => {
                ensure_only_keys(m, &["workspace_root"], "match[path_policy]")?;
                if m.get("workspace_root").is_some_and(|ws| ws.as_str().is_none()) {
                    return Err("RuleIR match.workspace_root must be string".to_string());
                }
            }
            "ast_pattern" => {
                ensure_only_keys(m, ALLOWED_AST_MATCH_KEYS, "match[ast_pattern]")?;
                if let Some(n) = m.get("node").and_then(|v| v.as_str()) {
                    if !matches!(n, "Assign" | "Call") { return Err(format!("Unsupported RuleIR ast_pattern node '{n}'")); }
                }
            }
            _ => {}
        }
    }
    for (field, allowed) in [
        ("conditions", ALLOWED_CONDITIONS_KEYS),
        ("response", ALLOWED_RESPONSE_KEYS),
        ("provenance", ALLOWED_PROVENANCE_KEYS),
    ] {
        if let Some(val) = obj.get(field).filter(|v| !matches!(v, JsonValue::Null)) {
            let sub = val.as_object().ok_or_else(|| format!("RuleIR '{field}' must be a JSON object"))?;
            ensure_only_keys(sub, allowed, field)?;
        }
    }
    Ok(())
}

fn parse_validated_rule_ir_object(
    raw_json: &str,
    strict_hash: bool,
) -> Result<(BTreeMap<String, JsonValue>, String, bool), String> {
    if raw_json.len() > MAX_RULE_IR_JSON_BYTES {
        return Err(format!("RuleIR/1 payload exceeds MAX_RULE_IR_JSON_BYTES ({MAX_RULE_IR_JSON_BYTES})"));
    }
    let trimmed = raw_json.trim();
    if trimmed.is_empty() || !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err("Malformed JSON RuleIR/1 object".to_string());
    }
    let obj = parse_json_value(trimmed)?.as_object().cloned().ok_or_else(|| "RuleIR/1 payload must be a JSON object".to_string())?;
    let schema = obj.get("schema").or_else(|| obj.get("schema_version")).and_then(|v| v.as_str()).unwrap_or_default();
    if schema != "RuleIR/1" { return Err(format!("Unsupported RuleIR schema: {schema}")); }
    let rule_id = obj.get("rule_id").or_else(|| obj.get("id")).and_then(|v| v.as_str()).unwrap_or_default();
    if rule_id.is_empty() || rule_id.contains('/') || rule_id.contains('\\') || rule_id.contains("..") {
        return Err(format!("Invalid RuleIR rule_id: {rule_id}"));
    }
    let predicate_kind = obj.get("predicate_kind").or_else(|| obj.get("predicate")).and_then(|v| v.as_str()).unwrap_or_default();
    if !matches!(predicate_kind, "ast_pattern" | "path_policy" | "bounded_regex") {
        return Err(format!("Unsupported RuleIR predicate_kind: {predicate_kind}"));
    }
    validate_rule_ir_subschemas(&obj, predicate_kind)?;

    let rule_hash = obj.get("rule_hash").or_else(|| obj.get("canonical_sha256")).and_then(|v| v.as_str()).unwrap_or_default();
    let hash_hex = rule_hash.strip_prefix("sha256:").unwrap_or("");
    if hash_hex.len() != 64 || !hash_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("Invalid RuleIR rule_hash: {rule_hash}"));
    }
    if strict_hash && !obj.get("match").is_some_and(|v| v.as_object().is_some()) {
        return Err("RuleIR/1 missing required 'match' object".to_string());
    }
    if predicate_kind == "bounded_regex" && (strict_hash || obj.contains_key("match")) {
        let pat = obj.get("match").and_then(|v| v.as_object()).and_then(|m| m.get("regex")).and_then(|v| v.as_str()).unwrap_or_default();
        let _ = BoundedRegex::compile(pat)?;
    }
    let has_core = ["match", "language", "languages", "severity", "conditions", "response"].iter().any(|k| obj.contains_key(*k));
    let (canonical_hash, verified) = if strict_hash || has_core {
        let expected = compute_rule_ir_canonical_hash(&obj)?;
        if rule_hash != expected { return Err(format!("RuleIR hash mismatch: {rule_hash} != {expected}")); }
        (expected, true)
    } else {
        (rule_hash.to_string(), false)
    };
    Ok((obj, canonical_hash, verified))
}

fn extract_ast_anchor_literals(match_obj: &BTreeMap<String, JsonValue>) -> Vec<Vec<u8>> {
    match match_obj.get("node").and_then(|v| v.as_str()).unwrap_or("") {
        "Assign" => match_obj.get("target").and_then(|v| v.as_str()).filter(|t| t.len() >= 2).map(|t| vec![t.as_bytes().to_vec()]).unwrap_or_default(),
        "Call" => match_obj.get("callee").and_then(|v| v.as_str()).and_then(|c| c.rsplit('.').next()).filter(|l| l.len() >= 2).map(|l| vec![l.as_bytes().to_vec()]).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Strictly validate and pre-compile a `RuleIR/1` JSON payload once at startup.
pub fn compile_rule_ir_strict(raw_json: &str) -> Result<CompiledRuleIr, String> {
    if raw_json.len() > MAX_RULE_IR_JSON_BYTES {
        return Err(format!("RuleIR/1 JSON exceeds MAX_RULE_IR_JSON_BYTES ({MAX_RULE_IR_JSON_BYTES})"));
    }
    let (obj, _, _) = parse_validated_rule_ir_object(raw_json, true)?;
    let rule_id = obj.get("rule_id").or_else(|| obj.get("id")).and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let predicate_kind = obj.get("predicate_kind").or_else(|| obj.get("predicate")).and_then(|v| v.as_str()).unwrap_or_default();
    let match_obj = obj.get("match").and_then(|v| v.as_object()).ok_or_else(|| "Missing match object".to_string())?;
    let languages: Vec<String> = match obj.get("language").or_else(|| obj.get("languages")) {
        Some(JsonValue::Array(arr)) if !arr.is_empty() => arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        _ => vec!["python".to_string()],
    };
    let severity = Severity::from_str(obj.get("severity").and_then(|v| v.as_str()).unwrap_or("HIGH"));
    let reason_code = obj.get("response").and_then(|v| v.as_object()).and_then(|r| r.get("reason_code")).or_else(|| obj.get("reason")).and_then(|v| v.as_str()).unwrap_or("EVOLVED_GUARD").to_string();

    let (predicate, anchor_literals) = match predicate_kind {
        "bounded_regex" => {
            let rx = BoundedRegex::compile(match_obj.get("regex").and_then(|v| v.as_str()).unwrap_or_default())?;
            let lits = rx.required_anchor_literals();
            (CompiledPredicate::BoundedRegex(rx), lits)
        }
        "ast_pattern" => (CompiledPredicate::AstPattern(match_obj.clone()), extract_ast_anchor_literals(match_obj)),
        "path_policy" => (
            CompiledPredicate::PathPolicy { workspace_root: match_obj.get("workspace_root").and_then(|v| v.as_str()).unwrap_or(".").to_string() },
            Vec::new(),
        ),
        other => return Err(format!("Unsupported RuleIR predicate_kind: {other}")),
    };
    Ok(CompiledRuleIr { rule_id, severity, languages, reason_code, predicate, anchor_literals })
}

impl CompiledRuleIr {
    pub fn compile_rule_ir_strict(raw_json: &str) -> Result<Self, String> { compile_rule_ir_strict(raw_json) }

    pub fn eval_with_policy(
        &self,
        code_text: &str,
        lang: &str,
        step_budget: &mut usize,
        path_eval: &dyn PathPolicyEvaluator,
    ) -> Result<Vec<(usize, String)>, String> {
        if (code_text.len() as u64) > MAX_SOURCE_FILE_BYTES {
            return Err(format!("RuleIR input exceeds MAX_SOURCE_FILE_BYTES ({MAX_SOURCE_FILE_BYTES})"));
        }
        if *step_budget == 0 { return Err("CompiledRuleIr step budget exhausted".to_string()); }
        if !rule_matches_language(&self.languages, lang) { return Ok(Vec::new()); }
        match &self.predicate {
            CompiledPredicate::BoundedRegex(rx) => rx
                .find_all_with_budget(code_text, step_budget)
                .map_err(|_| "CompiledRuleIr bounded_regex resource limit exceeded".to_string()),
            CompiledPredicate::AstPattern(match_obj) => {
                if !lang.is_empty() && normalize_rule_lang(lang) != "python" { return Ok(Vec::new()); }
                let Ok(tokens) = tokenize_python_subset(code_text) else {
                    *step_budget = step_budget.saturating_sub(1);
                    return Ok(Vec::new());
                };
                let cost = tokens.len().max(1);
                if cost > *step_budget { *step_budget = 0; return Err("CompiledRuleIr AST step budget exhausted".to_string()); }
                *step_budget -= cost;
                let lines: Vec<&str> = code_text.lines().collect();
                Ok(eval_python_ast_pattern_tokens(match_obj, &tokens)
                    .into_iter()
                    .map(|(ln, _)| {
                        let snip = lines.get(ln.saturating_sub(1)).map(|s| s.trim().chars().take(120).collect()).unwrap_or_else(|| self.rule_id.clone());
                        (ln, snip)
                    })
                    .collect())
            }
            CompiledPredicate::PathPolicy { .. } => {
                *step_budget = step_budget.saturating_sub(1);
                let cmd = code_text.trim();
                Ok(if path_eval.is_dangerous_path(cmd) { vec![(1, cmd.chars().take(120).collect())] } else { Vec::new() })
            }
        }
    }

    pub fn eval_compiled_no_fs(&self, code_text: &str, lang: &str, step_budget: &mut usize) -> Result<Vec<(usize, String)>, String> {
        self.eval_with_policy(code_text, lang, step_budget, &NoFsPathPolicy { workspace_root: None })
    }
}

pub fn validate_rule_ir_json(raw_json: &str) -> Result<String, String> { validate_rule_ir_json_with_mode(raw_json, false) }
pub fn validate_rule_ir_json_strict(raw_json: &str) -> Result<String, String> { validate_rule_ir_json_with_mode(raw_json, true) }

fn validate_rule_ir_json_with_mode(raw_json: &str, strict_hash: bool) -> Result<String, String> {
    let (obj, canonical_hash, hash_verified) = parse_validated_rule_ir_object(raw_json, strict_hash)?;
    let rule_id = obj.get("rule_id").or_else(|| obj.get("id")).and_then(|v| v.as_str()).unwrap_or_default();
    let pred = obj.get("predicate_kind").or_else(|| obj.get("predicate")).and_then(|v| v.as_str()).unwrap_or_default();
    let rhash = obj.get("rule_hash").or_else(|| obj.get("canonical_sha256")).and_then(|v| v.as_str()).unwrap_or_default();
    Ok(JsonObj::new()
        .bool("ok", true).str("schema", "RuleIR/1").str("rule_id", rule_id)
        .str("predicate_kind", pred).str("rule_hash", rhash)
        .str("canonical_hash", &canonical_hash).bool("hash_verified", hash_verified)
        .finish())
}

pub fn evaluate_rule_ir_json(rule_json: &str, code_text: &str, lang: &str) -> Result<String, String> {
    evaluate_rule_ir_json_with_fs(rule_json, code_text, lang, true)
}

pub fn evaluate_rule_ir_json_no_fs(rule_json: &str, code_text: &str, lang: &str) -> Result<String, String> {
    evaluate_rule_ir_json_with_fs(rule_json, code_text, lang, false)
}

fn evaluate_rule_ir_json_with_fs(rule_json: &str, code_text: &str, lang: &str, allow_fs: bool) -> Result<String, String> {
    if (code_text.len() as u64) > MAX_SOURCE_FILE_BYTES {
        return Err(format!("RuleIR evaluation code_text exceeds MAX_SOURCE_FILE_BYTES ({MAX_SOURCE_FILE_BYTES})"));
    }
    let (obj, _, _) = parse_validated_rule_ir_object(rule_json, true)?;
    let rule_id = obj.get("rule_id").or_else(|| obj.get("id")).and_then(|v| v.as_str()).unwrap_or_default();
    let rule_hash = obj.get("rule_hash").or_else(|| obj.get("canonical_sha256")).and_then(|v| v.as_str()).unwrap_or_default();
    let predicate_kind = obj.get("predicate_kind").or_else(|| obj.get("predicate")).and_then(|v| v.as_str()).unwrap_or_default();
    let severity = obj.get("severity").and_then(|v| v.as_str()).unwrap_or("HIGH");
    let resp_obj = obj.get("response").and_then(|v| v.as_object());
    let deny_decision = resp_obj.and_then(|r| r.get("decision")).and_then(|v| v.as_str()).unwrap_or("DENY");
    let reason_code = resp_obj.and_then(|r| r.get("reason_code")).or_else(|| obj.get("reason")).and_then(|v| v.as_str()).unwrap_or("EVOLVED_GUARD");
    let match_obj = obj.get("match").and_then(|v| v.as_object()).ok_or_else(|| "Missing match object".to_string())?;

    let hits: Vec<BTreeMap<String, JsonValue>> = match predicate_kind {
        "ast_pattern" if lang.eq_ignore_ascii_case("python") => tokenize_python_subset(code_text)
            .map(|toks| eval_python_ast_pattern_tokens(match_obj, &toks).into_iter().map(|(_, m)| m).collect())
            .unwrap_or_default(),
        "ast_pattern" => Vec::new(),
        "bounded_regex" => {
            let rx = BoundedRegex::compile(match_obj.get("regex").and_then(|v| v.as_str()).unwrap_or_default())?;
            rx.try_find_all(code_text)?.into_iter().map(|(ln, snip)| make_hit(ln, &[("snippet", &snip)]).1).collect()
        }
        "path_policy" => {
            let cmd = code_text.trim();
            let ws_path = Path::new(match_obj.get("workspace_root").and_then(|v| v.as_str()).unwrap_or("."));
            let no_fs_pol = NoFsPathPolicy { workspace_root: None };
            let ws_pol = WorkspacePathPolicy { workspace_root: ws_path };
            let eval: &dyn PathPolicyEvaluator = if allow_fs { &ws_pol } else { &no_fs_pol };
            if eval.is_dangerous_path(cmd) { vec![make_hit(1, &[("target", cmd)]).1] } else { Vec::new() }
        }
        other => return Err(format!("Unsupported predicate_kind: {other}")),
    };

    let (hits_count, matched) = (hits.len(), !hits.is_empty());
    let hits_json = JsonValue::Array(hits.into_iter().map(JsonValue::Object).collect()).to_canonical_json();
    Ok(JsonObj::new()
        .bool("ok", true).str("schema", "RuleIR/1").str("rule_id", rule_id).str("rule_hash", rule_hash)
        .str("decision", if matched { deny_decision } else { "ALLOW" })
        .str("severity", severity).str("reason_code", reason_code)
        .bool("matched", matched).usize("hits_count", hits_count).raw("hits", &hits_json)
        .finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::sha256_hex;

    #[test]
    fn rejects_unknown_shadow_fields_and_oversized_payloads() {
        let core = "{\"conditions\":{},\"language\":[\"python\"],\"match\":{\"regex\":\"eval\\\\(\"},\"predicate_kind\":\"bounded_regex\",\"response\":{\"decision\":\"DENY\",\"reason_code\":\"G\"},\"severity\":\"HIGH\"}";
        let h = format!("sha256:{}", sha256_hex(core.as_bytes()));
        let shadow = format!("{{\"schema\":\"RuleIR/1\",\"rule_id\":\"KS-T1\",\"language\":[\"python\"],\"severity\":\"HIGH\",\"predicate_kind\":\"bounded_regex\",\"match\":{{\"regex\":\"eval\\\\(\"}},\"conditions\":{{}},\"response\":{{\"decision\":\"DENY\",\"reason_code\":\"G\"}},\"rule_hash\":\"{h}\",\"shadow_exec\":\"evil\"}}");
        assert!(compile_rule_ir_strict(&shadow).unwrap_err().contains("Unknown RuleIR root field"));
        assert!(compile_rule_ir_strict(&" ".repeat(MAX_RULE_IR_JSON_BYTES + 16)).is_err());
        let valid = format!("{{\"schema\":\"RuleIR/1\",\"rule_id\":\"KS-T2\",\"language\":[\"python\"],\"severity\":\"HIGH\",\"predicate_kind\":\"bounded_regex\",\"match\":{{\"regex\":\"eval\\\\(\"}},\"conditions\":{{}},\"response\":{{\"decision\":\"DENY\",\"reason_code\":\"G\"}},\"rule_hash\":\"{h}\"}}");
        assert!(evaluate_rule_ir_json_no_fs(&valid, &"x".repeat((MAX_SOURCE_FILE_BYTES as usize) + 1), "python").is_err());
    }
}
