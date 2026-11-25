// kintsugi: ignore-file
//! Language detection, inline ignore parsing, whitespace-normalized call compaction,
//! scope- & rebind-aware import alias resolution (`FileAliasMap`), single-line rule matchers,
//! `KS-013` receiver-aware browser `finally` verifier, and `KS-S3-03` ledger DDL detector.

use std::env;
use std::path::{Path, PathBuf};

use crate::io_json::{fnv1a_64, FNV1A_64_INIT};
use crate::kernels::rule_prefilter::{ks014_line_may_match, pi_flags_can_trigger, pi_line_flags};
use crate::policy::audit_shell_command_argv_inner;
use crate::rules::prompt_injection::contains_prompt_injection_text;
use crate::unicode_policy::contains_security_unicode_control;

#[inline]
fn is_ident_byte(b: u8) -> bool { b.is_ascii_alphanumeric() || b == b'_' }

fn is_valid_ident(s: &str) -> bool {
    !s.is_empty() && !s.as_bytes()[0].is_ascii_digit() && s.bytes().all(is_ident_byte)
}

pub fn detect_language(path: &Path) -> Option<&'static str> {
    if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.eq_ignore_ascii_case("Dockerfile") || n.starts_with("Dockerfile.")) {
        return Some("dockerfile");
    }
    match path.extension().and_then(|e| e.to_str())?.to_ascii_lowercase().as_str() {
        "py" | "pyi" => Some("python"), "js" | "mjs" | "cjs" | "jsx" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"), "sol" => Some("solidity"), "go" => Some("go"), "rs" => Some("rust"), "sql" => Some("sql"),
        "sh" | "bash" | "zsh" => Some("shell"), "dockerfile" => Some("dockerfile"),
        "md" | "markdown" | "mdc" => Some("markdown"), _ => None,
    }
}

pub fn line_ignores_rule(line: &str, rule_id: &str) -> bool {
    if !line.contains("kintsugi:") && !line.contains("KINTSUGI:") { return false; }
    let lower = line.to_ascii_lowercase();
    let Some(idx) = lower.find("kintsugi:") else { return false };
    let tail = lower[idx + "kintsugi:".len()..].trim_start();
    if !tail.starts_with("ignore") { return false; }
    tail.find('[').and_then(|o| tail[o + 1..].find(']').map(|c| (o, c)))
        .map_or(true, |(o, c)| tail[o + 1..o + 1 + c].split(',').any(|t| t.trim().eq_ignore_ascii_case(rule_id)))
}

#[inline]
pub fn contains_bidi_control(s: &str) -> bool { contains_security_unicode_control(s, true) }

/// Line-aware Unicode security check (`KS-019`): permits `U+FEFF` BOM ONLY at byte offset 0 of line 0 (`is_first_line`).
#[inline]
pub fn contains_bidi_control_at_line(line: &str, is_first_line: bool) -> bool { contains_security_unicode_control(line, is_first_line) }

pub fn is_fixture_definition_line(trimmed: &str) -> bool {
    ["bad_code=", "good_code=", "offending_snippet=", "regex_pattern=", "root_cause=", "rationale=",
     "cognitive_trap=", "mental_model=", "title=", "poison_web_snippet", "\"bad_code\"", "\"good_code\"",
     "\"regex_pattern\"", "\"KS-", "\"no_", "r\"("].iter().any(|p| trimmed.starts_with(p))
}

pub fn has_unsafe_shell_kwarg(trimmed: &str) -> bool {
    let Some(pos) = trimmed.find("shell=") else { return false };
    let rest = trimmed[pos + "shell=".len()..].trim_start();
    let (mut depth, mut end_idx) = (0i32, rest.len());
    for (idx, ch) in rest.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth == 0 => { end_idx = idx; break; }
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => { end_idx = idx; break; }
            _ => {}
        }
    }
    let val = rest[..end_idx].trim();
    !val.is_empty() && !matches!(val, "False" | "0" | "None" | "(False)" | "(0)" | "(None)")
}

#[derive(Default)]
struct QuoteState { sq: bool, dq: bool, bt: bool }

impl QuoteState {
    #[inline]
    fn in_quote(&self) -> bool { self.sq || self.dq || self.bt }
    #[inline]
    fn toggle(&mut self, b: u8, allow_bt: bool) -> bool {
        match b {
            b'\'' if !self.dq && !self.bt => { self.sq = !self.sq; true }
            b'"' if !self.sq && !self.bt => { self.dq = !self.dq; true }
            b'`' if allow_bt && !self.sq && !self.dq => { self.bt = !self.bt; true }
            _ => false,
        }
    }
}

pub fn has_unquoted_call(line: &str, needle: &str) -> bool {
    let (bytes, nbytes) = (line.as_bytes(), needle.as_bytes());
    if bytes.len() < nbytes.len() { return false; }
    let (mut qs, mut i) = (QuoteState::default(), 0usize);
    while i < bytes.len() {
        if bytes[i] == b'\\' && qs.in_quote() { i += 2; continue; }
        if !qs.toggle(bytes[i], true) && !qs.in_quote() && bytes[i..].starts_with(nbytes) { return true; }
        i += 1;
    }
    false
}

pub fn has_standalone_call(haystack: &str, needle: &str) -> bool {
    let mut start = 0usize;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        if abs == 0 || !(is_ident_byte(haystack.as_bytes()[abs - 1]) || haystack.as_bytes()[abs - 1] == b'.') { return true; }
        start = abs + needle.len();
    }
    false
}

fn ends_with_stmt_keyword(out: &[u8]) -> bool {
    let mut end = out.len();
    while end > 0 && matches!(out[end - 1], b' ' | b'\t') { end -= 1; }
    let mut start = end;
    while start > 0 && is_ident_byte(out[start - 1]) { start -= 1; }
    matches!(&out[start..end], b"if" | b"elif" | b"while" | b"for" | b"return" | b"with" | b"assert" | b"import" | b"except" | b"yield" | b"await" | b"case" | b"catch")
}

/// Strip spaces/tabs around `.` / `?.` and before/after `(` outside quotes and trailing comments.
pub fn compact_call_outside_quotes(line: &str, lang: &str) -> String {
    let bytes = line.as_bytes();
    let (mut out, mut qs, mut i) = (Vec::with_capacity(bytes.len()), QuoteState::default(), 0usize);
    let (hash_cmt, allow_bt) = (matches!(lang, "python" | "shell" | "dockerfile"), lang != "python");
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && qs.in_quote() {
            out.push(b);
            if i + 1 < bytes.len() { out.push(bytes[i + 1]); }
            i += 2;
            continue;
        }
        if !qs.in_quote() {
            if (hash_cmt && b == b'#') || (!hash_cmt && b == b'/' && bytes.get(i + 1) == Some(&b'/')) { break; }
            if !hash_cmt && b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') { i += 1; }
                i = (i + 2).min(bytes.len());
                continue;
            }
        }
        if qs.toggle(b, allow_bt) { out.push(b); i += 1; continue; }
        if !qs.in_quote() && b == b'?' {
            let mut k = i + 1;
            while k < bytes.len() && matches!(bytes[k], b' ' | b'\t') { k += 1; }
            if bytes.get(k) == Some(&b'.') {
                let mut t = out.len();
                while t > 0 && matches!(out[t - 1], b' ' | b'\t') { t -= 1; }
                if t > 0 && (is_ident_byte(out[t - 1]) || matches!(out[t - 1], b')' | b']')) { out.truncate(t); }
                out.extend_from_slice(b"?.");
                i = k + 1;
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') { i += 1; }
                continue;
            }
        }
        if !qs.in_quote() && (b == b'.' || b == b'(') {
            if b == b'.' || !ends_with_stmt_keyword(&out) {
                let mut t = out.len();
                while t > 0 && matches!(out[t - 1], b' ' | b'\t') { t -= 1; }
                if t > 0 && (is_ident_byte(out[t - 1]) || (b == b'.' && matches!(out[t - 1], b')' | b']'))) {
                    out.truncate(t);
                }
            }
            out.push(b);
            i += 1;
            while i < bytes.len() && matches!(bytes[i], b' ' | b'\t') { i += 1; }
            continue;
        }
        out.push(b);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| line.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AliasAction { Module(&'static str), Call(&'static str), ShadowKill }

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedAliasEntry { alias: String, action: AliasAction, start_line: usize, end_line_exclusive: usize, indent_or_depth: usize }

/// Scope- and rebind-aware per-file import alias resolver for Python and JavaScript/TypeScript.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileAliasMap { entries: Vec<ScopedAliasEntry>, content_addr: usize, content_len: usize, line_meta: Vec<(usize, usize, u64)> }

const PY_MODULES: &[&str] = &["yaml", "torch", "os", "jwt", "tempfile", "subprocess", "requests", "pickle", "marshal", "urllib.request"];
const PY_FROM_SYMBOLS: &[(&str, &str, &str, bool)] = &[
    ("os", "system", "os.system", true), ("os", "popen", "os.popen", true), ("yaml", "load", "yaml.load", true),
    ("torch", "load", "torch.load", true), ("tempfile", "mktemp", "tempfile.mktemp", true), ("jwt", "decode", "jwt.decode", true),
    ("subprocess", "run", "subprocess.run", true), ("subprocess", "Popen", "subprocess.Popen", true), ("subprocess", "call", "subprocess.call", true),
    ("subprocess", "check_output", "subprocess.check_output", true), ("subprocess", "check_call", "subprocess.check_call", true),
    ("requests", "get", "requests.get", true), ("requests", "post", "requests.post", true), ("requests", "put", "requests.put", true),
    ("urllib.request", "urlopen", "urllib.request.urlopen", true), ("pickle", "load", "pickle.load", true),
    ("pickle", "loads", "pickle.loads", true), ("marshal", "loads", "marshal.loads", true), ("urllib", "request", "urllib.request", false),
];

fn canonical_js_module(spec: &str) -> Option<&'static str> {
    match spec {
        "child_process" | "node:child_process" => Some("child_process"),
        "js-yaml" | "yaml" => Some("yaml"), "jsonwebtoken" => Some("jwt"), "puppeteer" | "puppeteer-core" => Some("puppeteer"),
        _ => None,
    }
}

fn extract_quoted_literal(s: &str) -> Option<&str> {
    ['\'', '"'].into_iter().find_map(|q| { let st = s.find(q)?; Some(&s[st + 1..st + 1 + s[st + 1..].find(q)?]) })
}

fn find_py_scope_end(lines: &[&str], start_idx: usize, scope_indent: usize) -> usize {
    if scope_indent == 0 { return usize::MAX; }
    let mut paren_depth = 0i32;
    for (idx, &ln) in lines.iter().enumerate().skip(start_idx) {
        let unq = strip_code_outside_quotes_and_comments(ln, "python");
        let ut = unq.trim();
        if idx > start_idx && paren_depth <= 0 && !ut.is_empty() && py_indent(ln) < scope_indent { return idx; }
        for &b in ut.as_bytes() {
            if matches!(b, b'(' | b'[' | b'{') { paren_depth += 1; }
            else if matches!(b, b')' | b']' | b'}') { paren_depth = (paren_depth - 1).max(0); }
        }
    }
    lines.len()
}

fn find_js_scope_end(unquoted_lines: &[String], start_idx: usize, entry_depth: i32) -> usize {
    if entry_depth <= 0 { return usize::MAX; }
    let mut depth = entry_depth;
    for (idx, unq) in unquoted_lines.iter().enumerate().skip(start_idx) {
        for &b in unq.as_bytes() {
            if b == b'{' { depth += 1; }
            else if b == b'}' { depth -= 1; if depth < entry_depth { return idx + 1; } }
        }
    }
    unquoted_lines.len()
}

fn extract_rebind_lhs<'a>(unquoted_trimmed: &'a str, lang: &str) -> Option<(&'a str, &'a str)> {
    let s = if matches!(lang, "javascript" | "typescript") {
        ["const ", "let ", "var "].iter().find_map(|p| unquoted_trimmed.strip_prefix(p)).unwrap_or(unquoted_trimmed).trim_start()
    } else { unquoted_trimmed };
    let eq_pos = s.find('=')?;
    let bytes = s.as_bytes();
    if matches!(bytes.get(eq_pos + 1), Some(b'=' | b'>')) { return None; }
    if eq_pos > 0 && matches!(bytes[eq_pos - 1], b'=' | b'!' | b'<' | b'>' | b'+' | b'-' | b'*' | b'/' | b'|' | b'&') { return None; }
    let lhs_raw = s[..eq_pos].trim();
    if lhs_raw.contains(['(', '[', '.']) { return None; }
    let ident = lhs_raw.split(':').next().unwrap_or(lhs_raw).trim();
    is_valid_ident(ident).then_some((ident, s[eq_pos + 1..].trim()))
}

impl FileAliasMap {
    pub const fn empty() -> Self { Self { entries: Vec::new(), content_addr: 0, content_len: 0, line_meta: Vec::new() } }
    pub fn is_empty(&self) -> bool { !self.entries.iter().any(|e| !matches!(e.action, AliasAction::ShadowKill)) }

    fn push_entry(&mut self, alias: &str, action: AliasAction, start: usize, end: usize, depth: usize) {
        if !is_valid_ident(alias) || matches!(action, AliasAction::Module(c) if c == alias) { return; }
        self.entries.push(ScopedAliasEntry { alias: alias.to_string(), action, start_line: start, end_line_exclusive: end, indent_or_depth: depth });
    }

    fn has_known_alias(&self, ident: &str) -> bool {
        self.entries.iter().any(|e| e.alias == ident && !matches!(e.action, AliasAction::ShadowKill))
    }

    fn register_js_bindings(&mut self, canon: &'static str, lhs: &str, kv_sep: &str, start: usize, end: usize, depth: usize) {
        let l = lhs.trim();
        if let Some(alias) = l.strip_prefix("* as ") {
            self.push_entry(alias.trim(), AliasAction::Module(canon), start, end, depth);
        } else if l.starts_with('{') && l.ends_with('}') {
            for item in l[1..l.len() - 1].split(',') {
                let it = item.trim();
                let (orig, local) = it.split_once(kv_sep).map_or((it, it), |(o, a)| (o.trim(), a.trim()));
                match (canon, orig) {
                    ("child_process", "exec") => self.push_entry(local, AliasAction::Call("child_process.exec"), start, end, depth),
                    ("child_process", "execSync") => self.push_entry(local, AliasAction::Call("execSync"), start, end, depth),
                    ("yaml", "load") => self.push_entry(local, AliasAction::Call("yaml.load"), start, end, depth),
                    ("jwt", "decode") => self.push_entry(local, AliasAction::Call("jwt.decode"), start, end, depth),
                    _ => {}
                }
            }
        } else {
            self.push_entry(l, AliasAction::Module(canon), start, end, depth);
        }
    }

    pub fn from_source(content: &str, lang: &str) -> Self {
        let mut map = Self::empty();
        if !matches!(lang, "python" | "javascript" | "typescript") { return map; }
        let lines: Vec<&str> = content.lines().collect();
        map.content_addr = content.as_ptr() as usize;
        map.content_len = content.len();
        map.line_meta = lines.iter().map(|ln| ((ln.as_ptr() as usize).saturating_sub(map.content_addr), ln.len(), fnv1a_64(ln.as_bytes(), FNV1A_64_INIT))).collect();

        if lang == "python" {
            let (mut idx, mut paren_depth) = (0usize, 0i32);
            while idx < lines.len() {
                let (ind, unq) = (py_indent(lines[idx]), strip_code_outside_quotes_and_comments(lines[idx], "python"));
                let (t, scope_end) = (lines[idx].split('#').next().unwrap_or("").trim(), find_py_scope_end(&lines, idx, ind));
                if let Some(rest) = t.strip_prefix("import ") {
                    for part in rest.split(',') {
                        if let Some((m, a)) = part.trim().split_once(" as ") {
                            if let Some(&canon) = PY_MODULES.iter().find(|&&k| k == m.trim()) {
                                map.push_entry(a.trim(), AliasAction::Module(canon), idx, scope_end, ind);
                            }
                        }
                    }
                } else if let Some((mod_part, imp_part)) = t.strip_prefix("from ").and_then(|r| r.split_once(" import ")) {
                    let (module, mut joined) = (mod_part.trim(), imp_part.trim().to_string());
                    while joined.starts_with('(') && !joined.contains(')') && idx + 1 < lines.len() {
                        idx += 1;
                        joined.push(' ');
                        joined.push_str(lines[idx].split('#').next().unwrap_or("").trim());
                    }
                    for item in joined.trim().trim_start_matches('(').trim_end_matches(')').split(',') {
                        let it = item.trim();
                        if it.is_empty() { continue; }
                        let (orig, local) = it.split_once(" as ").map_or((it, it), |(o, l)| (o.trim(), l.trim()));
                        if let Some(&(_, _, canon, is_call)) = PY_FROM_SYMBOLS.iter().find(|&&(m, s, _, _)| m == module && s == orig) {
                            map.push_entry(local, if is_call { AliasAction::Call(canon) } else { AliasAction::Module(canon) }, idx, scope_end, ind);
                        }
                    }
                } else if paren_depth == 0 {
                    if let Some((lhs, rhs)) = extract_rebind_lhs(unq.trim(), "python") {
                        if map.has_known_alias(lhs) && !PY_MODULES.contains(&rhs) {
                            map.push_entry(lhs, AliasAction::ShadowKill, idx, scope_end, ind);
                        }
                    }
                }
                for &b in unq.as_bytes() {
                    if matches!(b, b'(' | b'[' | b'{') { paren_depth += 1; }
                    else if matches!(b, b')' | b']' | b'}') { paren_depth = (paren_depth - 1).max(0); }
                }
                idx += 1;
            }
        } else {
            let unq_lines: Vec<String> = lines.iter().map(|l| strip_code_outside_quotes_and_comments(l, lang)).collect();
            let (mut brace_depth, mut paren_depth) = (0i32, 0i32);
            for (idx, raw) in lines.iter().enumerate() {
                let t = raw.split("//").next().unwrap_or("").trim().trim_end_matches(';');
                let (scope_end, depth_u, mut handled) = (find_js_scope_end(&unq_lines, idx, brace_depth), brace_depth.max(0) as usize, false);
                if let Some((lhs, rhs)) = t.strip_prefix("import ").and_then(|r| r.split_once(" from ")) {
                    if let Some(canon) = extract_quoted_literal(rhs).and_then(canonical_js_module) {
                        map.register_js_bindings(canon, lhs, " as ", idx, scope_end, depth_u);
                        handled = true;
                    }
                } else if let Some((lhs, rhs)) = ["const ", "let ", "var "].iter().find_map(|p| t.strip_prefix(p)).and_then(|d| d.split_once('=')) {
                    if rhs.trim().starts_with("require(") {
                        if let Some(canon) = extract_quoted_literal(rhs).and_then(canonical_js_module) {
                            map.register_js_bindings(canon, lhs, ":", idx, scope_end, depth_u);
                            handled = true;
                        }
                    }
                }
                if !handled && paren_depth == 0 {
                    if let Some((lhs, rhs)) = extract_rebind_lhs(unq_lines[idx].trim().trim_end_matches(';'), lang) {
                        if map.has_known_alias(lhs) && !rhs.starts_with("require(") {
                            map.push_entry(lhs, AliasAction::ShadowKill, idx, scope_end, depth_u);
                        }
                    }
                }
                for &b in unq_lines[idx].as_bytes() {
                    match b {
                        b'{' => brace_depth += 1, b'}' => brace_depth = (brace_depth - 1).max(0),
                        b'(' | b'[' => paren_depth += 1, b')' | b']' => paren_depth = (paren_depth - 1).max(0),
                        _ => {}
                    }
                }
            }
        }
        map
    }

    fn resolve_at(&self, ident: &str, want_call: bool, line_idx: usize) -> Option<&'static str> {
        let mut best: Option<(usize, usize, AliasAction)> = None;
        for e in &self.entries {
            if e.alias == ident && e.start_line <= line_idx && line_idx < e.end_line_exclusive
                && best.map_or(true, |(d, s, _)| (e.indent_or_depth, e.start_line) >= (d, s))
            {
                best = Some((e.indent_or_depth, e.start_line, e.action));
            }
        }
        match (best?.2, want_call) { (AliasAction::Module(c), false) | (AliasAction::Call(c), true) => Some(c), _ => None }
    }

    fn infer_line_idx(&self, raw_line: &str) -> Option<usize> {
        if self.content_len == 0 || self.line_meta.is_empty() { return None; }
        let addr = raw_line.as_ptr() as usize;
        if addr < self.content_addr || addr.saturating_add(raw_line.len()) > self.content_addr.saturating_add(self.content_len) { return None; }
        let idx = self.line_meta.binary_search_by_key(&(addr - self.content_addr), |&(off, _, _)| off).ok()?;
        let (_, len, hash) = self.line_meta[idx];
        (len == raw_line.len() && hash == fnv1a_64(raw_line.as_bytes(), FNV1A_64_INIT)).then_some(idx)
    }

    pub fn normalize_line_at(&self, compact_unquoted: &str, line_idx: usize) -> String {
        if self.is_empty() || compact_unquoted.is_empty() { return compact_unquoted.to_string(); }
        let t = compact_unquoted.trim_start();
        if ["import ", "from ", "def ", "async def ", "function "].iter().any(|p| t.starts_with(p)) {
            return compact_unquoted.to_string();
        }
        let bytes = compact_unquoted.as_bytes();
        let (mut out, mut qs, mut i) = (String::with_capacity(bytes.len() + 8), QuoteState::default(), 0usize);
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\\' && qs.in_quote() {
                out.push('\\');
                if i + 1 < bytes.len() {
                    let ch = compact_unquoted[i + 1..].chars().next().unwrap_or(' ');
                    out.push(ch);
                    i += 1 + ch.len_utf8();
                } else { i += 1; }
                continue;
            }
            if qs.toggle(b, true) { out.push(b as char); i += 1; continue; }
            if !qs.in_quote() && (b.is_ascii_alphabetic() || b == b'_') && (i == 0 || !is_ident_byte(bytes[i - 1])) {
                let start = i;
                while i < bytes.len() && is_ident_byte(bytes[i]) { i += 1; }
                let ident = &compact_unquoted[start..i];
                let prev_dot = start > 0 && bytes[start - 1] == b'.';
                let rewritten = match (!prev_dot, bytes.get(i).copied()) {
                    (true, Some(b'.')) => self.resolve_at(ident, false, line_idx),
                    (true, Some(b'(')) => self.resolve_at(ident, true, line_idx),
                    _ => None,
                };
                out.push_str(rewritten.unwrap_or(ident));
                continue;
            }
            let ch = compact_unquoted[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
        out
    }

    pub fn normalize_line(&self, compact_unquoted: &str) -> String {
        self.normalize_line_at(compact_unquoted, usize::MAX - 1)
    }
}

fn strip_code_outside_quotes_and_comments(line: &str, lang: &str) -> String {
    let bytes = line.as_bytes();
    let (mut out, mut qs, is_py, mut i) = (Vec::with_capacity(bytes.len()), QuoteState::default(), lang == "python", 0usize);
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && qs.in_quote() {
            out.push(b' ');
            if i + 1 < bytes.len() { out.push(b' '); }
            i += 2;
            continue;
        }
        if !qs.in_quote() && ((is_py && b == b'#') || (!is_py && b == b'/' && matches!(bytes.get(i + 1), Some(b'/' | b'*')))) { break; }
        if qs.toggle(b, !is_py) { out.push(b' '); i += 1; continue; }
        out.push(if qs.in_quote() { b' ' } else { b });
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

pub fn is_browser_launch_line(trimmed: &str, lang: &str) -> bool {
    if !matches!(lang, "javascript" | "typescript" | "python")
        || trimmed.is_empty()
        || ["#", "//", "/*", "*"].iter().any(|p| trimmed.starts_with(p))
        || is_fixture_definition_line(trimmed)
        || (lang == "python" && (trimmed.starts_with("with ") || trimmed.starts_with("async with ")))
        || !trimmed.contains(".launch(")
    {
        return false;
    }
    let unquoted = strip_code_outside_quotes_and_comments(trimmed, lang);
    let ub = unquoted.as_bytes();
    for engine in ["puppeteer.launch(", "chromium.launch(", "firefox.launch(", "webkit.launch("] {
        let mut from = 0usize;
        while let Some(rel) = unquoted[from..].find(engine) {
            let abs = from + rel;
            if abs == 0 || !is_ident_byte(ub[abs - 1]) { return true; }
            from = abs + engine.len();
        }
    }
    false
}

fn extract_launch_receiver(line: &str, lang: &str) -> Option<String> {
    let unq = strip_code_outside_quotes_and_comments(line, lang);
    let ut = unq.trim_start();
    let decl = if matches!(lang, "javascript" | "typescript") {
        ["const ", "let ", "var "].iter().find_map(|p| ut.strip_prefix(p)).unwrap_or(ut).trim_start()
    } else { ut };
    let eq_pos = decl.find('=')?;
    if decl.as_bytes().get(eq_pos + 1) == Some(&b'=') { return None; }
    let lhs = decl[..eq_pos].split(':').next().unwrap_or("").trim();
    if is_valid_ident(lhs) { return Some(lhs.to_string()); }
    ["self.", "this."].into_iter().find_map(|pfx| {
        let attr = lhs.strip_prefix(pfx)?.trim();
        is_valid_ident(attr).then(|| format!("{pfx}{attr}"))
    })
}

fn line_closes_browser_receiver(raw_line: &str, lang: &str, receiver: Option<&str>) -> bool {
    let compact = compact_call_outside_quotes(raw_line, lang);
    let cb = compact.as_bytes();
    let check_recv = |recv: &str| -> bool {
        [".close(", ".quit(", "?.close(", "?.quit("].iter().any(|sfx| {
            let pat = format!("{recv}{sfx}");
            let mut from = 0usize;
            while let Some(rel) = compact[from..].find(&pat) {
                let abs = from + rel;
                if abs == 0 || (!is_ident_byte(cb[abs - 1]) && cb[abs - 1] != b'.') { return true; }
                from = abs + 1;
            }
            false
        })
    };
    match receiver {
        Some(r) => check_recv(r),
        None => ["browser", "driver", "context", "self.browser", "this.browser"].iter().any(|g| check_recv(g)),
    }
}

fn py_indent(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ' || *c == '\t').map(|c| if c == '\t' { 4 } else { 1 }).sum()
}

fn contains_word_token(code: &str, word: &str) -> bool {
    let (bytes, wlen) = (code.as_bytes(), word.len());
    let mut from = 0usize;
    while let Some(rel) = code[from..].find(word) {
        let (abs, end) = (from + rel, from + rel + wlen);
        if (abs == 0 || !is_ident_byte(bytes[abs - 1])) && (end == bytes.len() || !is_ident_byte(bytes[end])) { return true; }
        from = abs + 1;
    }
    false
}

fn scope_has_finally_close_python(lines: &[&str], launch_idx: usize) -> bool {
    let receiver = extract_launch_receiver(lines[launch_idx], "python");
    let recv_ref = receiver.as_deref();
    let (launch_indent, back_start) = (py_indent(lines[launch_idx]), launch_idx.saturating_sub(80));
    let mut min_probe_indent = launch_indent;
    for b in (back_start..launch_idx).rev() {
        let bt = lines[b].trim();
        if bt.is_empty() || bt.starts_with('#') { continue; }
        let bi = py_indent(lines[b]);
        if bi < min_probe_indent {
            min_probe_indent = bi;
            if (bt.starts_with("with ") || bt.starts_with("async with ")) && (bt.contains("sync_playwright") || bt.contains("async_playwright")) {
                for f_line in &lines[b + 1..(launch_idx + 80).min(lines.len())] {
                    let ft = f_line.trim();
                    if ft.is_empty() || ft.starts_with('#') { continue; }
                    if py_indent(f_line) <= bi { break; }
                    if line_closes_browser_receiver(ft, "python", recv_ref) { return true; }
                }
            }
            if ["def ", "async def ", "class "].iter().any(|p| bt.starts_with(p)) { break; }
        }
    }

    let (mut min_allowed_indent, mut cur_ceil) = (launch_indent, launch_indent);
    for b in (back_start..launch_idx).rev() {
        let bt = lines[b].trim();
        if bt.is_empty() || bt.starts_with('#') { continue; }
        let bi = py_indent(lines[b]);
        if bi < cur_ceil {
            cur_ceil = bi;
            if bt.starts_with("try:") { min_allowed_indent = bi; break; }
            if ["def ", "async def ", "class "].iter().any(|p| bt.starts_with(p)) { break; }
        }
    }

    let mut active_finally_indent: Option<usize> = None;
    for line in &lines[launch_idx + 1..(launch_idx + 80).min(lines.len())] {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        let ind = py_indent(line);
        if let Some(fin_ind) = active_finally_indent {
            if ind > fin_ind {
                if line_closes_browser_receiver(t, "python", recv_ref) { return true; }
                continue;
            }
            active_finally_indent = None;
        }
        if ind < min_allowed_indent || (ind == min_allowed_indent && ["def ", "async def ", "class "].iter().any(|p| t.starts_with(p))) { break; }
        let unq = strip_code_outside_quotes_and_comments(t, "python");
        if unq.trim().starts_with("finally:") {
            if line_closes_browser_receiver(&t["finally:".len().min(t.len())..], "python", recv_ref) { return true; }
            active_finally_indent = Some(ind);
        }
    }
    false
}

fn next_js_code_starts_catch_or_finally(lines: &[&str], after_idx: usize, tail_on_line: &str, lang: &str) -> bool {
    let check = |s: &str| (s.starts_with("catch") && contains_word_token(s, "catch")) || (s.starts_with("finally") && contains_word_token(s, "finally"));
    let tt = tail_on_line.trim_start();
    if !tt.is_empty() { return check(tt); }
    for ln in &lines[after_idx..(after_idx + 4).min(lines.len())] {
        let unq = strip_code_outside_quotes_and_comments(ln, lang);
        if !unq.trim().is_empty() { return check(unq.trim()); }
    }
    false
}

fn scope_has_finally_close_js(lines: &[&str], launch_idx: usize, lang: &str) -> bool {
    let receiver = extract_launch_receiver(lines[launch_idx], lang);
    let recv_ref = receiver.as_deref();
    let first_unq = strip_code_outside_quotes_and_comments(lines[launch_idx], lang);
    if let Some(fin_pos) = first_unq.find("finally") {
        if contains_word_token(&first_unq[fin_pos..], "finally") && line_closes_browser_receiver(&lines[launch_idx][fin_pos..], lang, recv_ref) {
            return true;
        }
    }
    let (mut brace_depth, mut finally_floor_depth, mut in_finally, mut awaiting_cont) = (0i32, 0i32, false, false);

    for idx in (launch_idx + 1)..(launch_idx + 80).min(lines.len()) {
        let raw_trimmed = lines[idx].trim();
        if raw_trimmed.is_empty() || ["//", "/*", "*"].iter().any(|p| raw_trimmed.starts_with(p)) { continue; }
        let unq = strip_code_outside_quotes_and_comments(lines[idx], lang);
        let ut = unq.trim();
        if ut.is_empty() { continue; }
        if !in_finally && brace_depth == 0 && ["function ", "async function ", "export function ", "export async function "].iter().any(|p| ut.starts_with(p)) {
            break;
        }
        if contains_word_token(ut, "finally") { in_finally = true; finally_floor_depth = brace_depth; }
        if in_finally && line_closes_browser_receiver(lines[idx], lang, recv_ref) { return true; }

        let mut exited = false;
        for (bi, &b) in ut.as_bytes().iter().enumerate() {
            if b == b'{' { brace_depth += 1; awaiting_cont = false; }
            else if b == b'}' {
                if brace_depth == 0 && !awaiting_cont {
                    let tail = &ut[bi + 1..];
                    if next_js_code_starts_catch_or_finally(lines, idx + 1, tail, lang) {
                        brace_depth -= 1;
                        awaiting_cont = true;
                        if contains_word_token(tail, "finally") { in_finally = true; finally_floor_depth = brace_depth; }
                    } else { exited = true; break; }
                } else {
                    brace_depth -= 1;
                    if in_finally && brace_depth <= finally_floor_depth && !contains_word_token(&ut[bi + 1..], "finally") { in_finally = false; }
                }
            }
        }
        if exited { break; }
    }
    false
}

pub fn scope_has_finally_browser_close(lines: &[&str], launch_idx: usize, lang: &str) -> bool {
    if launch_idx >= lines.len() { return false; }
    match lang {
        "python" => scope_has_finally_close_python(lines, launch_idx),
        "javascript" | "typescript" => scope_has_finally_close_js(lines, launch_idx, lang),
        _ => false,
    }
}

pub fn check_ks013_with_lines(lines: &[&str], idx: usize, lang: &str) -> bool {
    lines.get(idx).is_some_and(|l| is_browser_launch_line(l.trim(), lang) && !scope_has_finally_browser_close(lines, idx, lang))
}

fn strip_optional_sql_quote(s: &str) -> (&str, bool) {
    s.strip_prefix("\\\"").or_else(|| s.strip_prefix('"')).map_or((s, false), |r| (r, true))
}
fn consume_closing_sql_quote(s: &str, was_quoted: bool) -> Option<&str> {
    if !was_quoted { Some(s) } else { s.strip_prefix("\\\"").or_else(|| s.strip_prefix('"')) }
}

fn has_ledger_events_target(upper: &str, kw: &str) -> bool {
    let mut from = 0usize;
    while let Some(rel) = upper[from..].find(kw) {
        let raw_tail = &upper[from + rel + kw.len()..];
        if kw == "ALTER TABLE" && !raw_tail.starts_with(char::is_whitespace) { from += rel + kw.len(); continue; }
        let mut cur = raw_tail.trim_start();
        if kw == "ALTER TABLE" {
            if let Some(r) = cur.strip_prefix("IF EXISTS ") { cur = r.trim_start(); }
            if let Some(r) = cur.strip_prefix("ONLY ") { cur = r.trim_start(); }
        }
        let (after_q1, q1) = strip_optional_sql_quote(cur);
        if let Some(after_dot) = after_q1.strip_prefix("PUBLIC").and_then(|p| consume_closing_sql_quote(p, q1)).and_then(|p| p.strip_prefix('.')) { cur = after_dot; }
        let (table_cand, tq) = strip_optional_sql_quote(cur);
        if let Some(rem) = table_cand.strip_prefix("LEDGER_EVENTS").and_then(|t| consume_closing_sql_quote(t, tq)) {
            if rem.as_bytes().first().map_or(true, |&b| !is_ident_byte(b)) { return true; }
        }
        from += rel + kw.len();
    }
    false
}

fn strip_sql_comments_and_strings(sql: &str) -> String {
    let (mut out, bytes, mut i) = (String::with_capacity(sql.len()), sql.as_bytes(), 0usize);
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' { i += 1; }
            if i < bytes.len() { out.push('\n'); i += 1; }
            continue;
        }
        if bytes[i] == b'\'' {
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    if bytes.get(i + 1) == Some(&b'\'') { i += 2; } else { i += 1; break; }
                } else { i += 1; }
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn matches_ks_s3_03_ledger_ddl(trimmed: &str) -> bool {
    if !trimmed.as_bytes().windows(13).any(|w| w.eq_ignore_ascii_case(b"ledger_events")) { return false; }
    let upper = strip_sql_comments_and_strings(trimmed).to_ascii_uppercase();
    let create_idx = (upper.contains("CREATE INDEX") || upper.contains("CREATE UNIQUE INDEX")) && !upper.contains("CONCURRENTLY") && has_ledger_events_target(&upper, " ON ");
    let alter_tbl = upper.contains("ALTER TABLE") && !upper.contains("CONCURRENTLY") && has_ledger_events_target(&upper, "ALTER TABLE");
    create_idx || alter_tbl || (upper.contains("DROP TRIGGER") && has_ledger_events_target(&upper, " ON "))
}

const EMPTY_ALIASES: FileAliasMap = FileAliasMap::empty();

pub fn check_line_against_rule(rule_id: &str, line: &str) -> bool { check_line_against_rule_lang(rule_id, line, "python") }
pub fn check_line_against_rule_lang(rule_id: &str, line: &str, lang: &str) -> bool {
    check_line_against_rule_lang_with_ctx(rule_id, line, line.trim(), lang, &mut None, false)
}
pub fn check_line_against_rule_at_line(rule_id: &str, line: &str, lang: &str, line_idx: usize) -> bool {
    check_line_against_rule_lang_with_ctx_and_aliases_at_line(rule_id, line, line.trim(), lang, &mut None, false, &EMPTY_ALIASES, Some(line_idx))
}
pub fn check_line_against_rule_with_aliases(rule_id: &str, line: &str, lang: &str, aliases: &FileAliasMap) -> bool {
    check_line_against_rule_lang_with_ctx_and_aliases_at_line(rule_id, line, line.trim(), lang, &mut None, false, aliases, aliases.infer_line_idx(line))
}
pub fn check_line_against_rule_with_aliases_at_line(rule_id: &str, line: &str, lang: &str, aliases: &FileAliasMap, line_idx: usize) -> bool {
    check_line_against_rule_lang_with_ctx_and_aliases_at_line(rule_id, line, line.trim(), lang, &mut None, false, aliases, Some(line_idx))
}
pub fn check_line_against_rule_lang_with_ctx(rule_id: &str, line: &str, trimmed: &str, lang: &str, ws_cache: &mut Option<Option<PathBuf>>, no_fs: bool) -> bool {
    check_line_against_rule_lang_with_ctx_and_aliases_at_line(rule_id, line, trimmed, lang, ws_cache, no_fs, &EMPTY_ALIASES, None)
}
pub fn check_line_against_rule_lang_with_ctx_and_aliases(rule_id: &str, line: &str, trimmed: &str, lang: &str, ws_cache: &mut Option<Option<PathBuf>>, no_fs: bool, aliases: &FileAliasMap) -> bool {
    check_line_against_rule_lang_with_ctx_and_aliases_at_line(rule_id, line, trimmed, lang, ws_cache, no_fs, aliases, aliases.infer_line_idx(line))
}

#[allow(clippy::too_many_arguments)]
pub fn check_line_against_rule_lang_with_ctx_and_aliases_at_line(
    rule_id: &str, line: &str, trimmed: &str, lang: &str,
    ws_cache: &mut Option<Option<PathBuf>>, no_fs: bool, aliases: &FileAliasMap, line_idx: Option<usize>,
) -> bool {
    if rule_id == "KS-019" { return contains_bidi_control_at_line(line, line_idx.unwrap_or(0) == 0); }
    if trimmed.is_empty() { return false; }
    if rule_id == "KS-S3-01" { return pi_flags_can_trigger(pi_line_flags(trimmed)) && contains_prompt_injection_text(trimmed); }
    if !matches!(rule_id, "KS-009" | "KS-026" | "KS-030") && (trimmed.starts_with('#') || trimmed.starts_with("//")) { return false; }
    if is_fixture_definition_line(trimmed) { return false; }

    let normalized_call = || -> String {
        let compact = compact_call_outside_quotes(trimmed, lang);
        if aliases.is_empty() { compact }
        else if let Some(idx) = line_idx { aliases.normalize_line_at(&compact, idx) }
        else { aliases.normalize_line(&compact) }
    };

    match rule_id {
        "KS-001" => !["os.environ", "os.getenv", "process.env"].iter().any(|e| trimmed.contains(e))
            && ["sk-live-", "sk-proj-", "ghp_", "github_pat_", "xoxb-", "AIzaSy"].iter().any(|p| trimmed.contains(p))
            && (trimmed.contains('=') || trimmed.contains(':')),
        "KS-002" => { let n = normalized_call(); (n.contains("subprocess.") || has_standalone_call(&n, "Popen(")) && has_unsafe_shell_kwarg(&n) }
        "KS-003" => {
            let n = normalized_call();
            has_standalone_call(&n, "eval(") || has_standalone_call(&n, "exec(") || ["pickle.loads(", "pickle.load(", "marshal.loads("].iter().any(|c| has_unquoted_call(&n, c))
        }
        "KS-004" => trimmed.starts_with("def ") && ["=[]", "= []", "={}", "= {}"].iter().any(|p| trimmed.contains(p)),
        "KS-005" => trimmed == "except:" || trimmed.starts_with("except: pass") || (trimmed.starts_with("except ") && trimmed.ends_with(": pass")),
        "KS-006" => { let n = normalized_call(); ["requests.get(", "requests.post(", "requests.put(", "urllib.request.urlopen("].iter().any(|c| has_unquoted_call(&n, c)) && !n.contains("timeout=") }
        "KS-007" => {
            if !(trimmed.contains("f\"") || trimmed.contains("f'") || (trimmed.contains("${") && trimmed.contains('`'))) { return false; }
            let u = trimmed.to_ascii_uppercase();
            (u.contains("SELECT ") && u.contains(" FROM ")) || u.contains("INSERT INTO ") || (u.contains("UPDATE ") && u.contains(" SET ")) || u.contains("DELETE FROM ")
        }
        "KS-008" => ["random.choice(", "random.randint(", "random.random(", "random.choices("].iter().any(|c| trimmed.contains(c))
            && { let l = trimmed.to_ascii_lowercase(); ["token", "secret", "nonce", "api_key", "password", "otp"].iter().any(|k| l.contains(k)) },
        "KS-009" => ["# TODO: implement", "// TODO: implement", "PLACEHOLDER_STUB", "NotImplementedError(\"TODO"].iter().any(|p| trimmed.contains(p)),
        "KS-010" => [", \"w\"", ", 'w'", ".write_text("].iter().any(|p| trimmed.contains(p))
            && { let l = trimmed.to_ascii_lowercase(); ["audit_log", "history_log", "pull1_raw"].iter().any(|k| l.contains(k)) },
        "KS-011" => ["verify=False", "rejectUnauthorized: false", "NODE_TLS_REJECT_UNAUTHORIZED = \"0\"", "NODE_TLS_REJECT_UNAUTHORIZED = '0'"].iter().any(|p| trimmed.contains(p)),
        "KS-012" => trimmed.contains(".innerHTML =") || trimmed.contains(".innerHTML="),
        "KS-013" => is_browser_launch_line(trimmed, lang),
        "KS-014" => {
            if (trimmed.contains("git push") && trimmed.contains("--force") && !trimmed.contains("--force-with-lease"))
                || trimmed.contains("rm -rf /") || trimmed.contains("rm -rf ~") { return true; }
            if !ks014_line_may_match(trimmed) { return false; }
            if ws_cache.is_none() { *ws_cache = Some(if no_fs { None } else { Some(env::current_dir().unwrap_or_else(|_| PathBuf::from("."))) }); }
            audit_shell_command_argv_inner(trimmed, 0, ws_cache.as_ref().and_then(|o| o.as_deref()), false).is_some()
        }
        "KS-015" => ((trimmed.starts_with("_, _ =") || trimmed.starts_with("_ =")) && ["Unmarshal(", "Write(", "Read(", "Exec("].iter().any(|c| trimmed.contains(c)))
            || (trimmed.contains("allow_origins=[\"*\"]") && trimmed.contains("allow_credentials=True")),
        "KS-016" => ["169.254.169.254", "file:///etc/passwd", "urlopen(user_supplied_url)"].iter().any(|p| trimmed.contains(p)),
        "KS-017" => { let n = normalized_call(); has_unquoted_call(&n, ".extractall(") && !n.contains("filter=") }
        "KS-018" => trimmed.contains(":latest") && trimmed.to_ascii_uppercase().starts_with("FROM "),
        "KS-020" => { let n = normalized_call(); has_unquoted_call(&n, "yaml.load(") && !n.contains("SafeLoader") && !n.contains("CSafeLoader") }
        "KS-021" => { let n = normalized_call(); has_unquoted_call(&n, "torch.load(") && !n.contains("weights_only=True") && !n.contains("weights_only = True") }
        "KS-022" => { let n = normalized_call(); has_unquoted_call(&n, "os.system(") || has_unquoted_call(&n, "os.popen(") }
        "KS-023" => (trimmed.contains("XMLParser(") && trimmed.contains("resolve_entities=True")) || (lang == "rust" && trimmed.contains("mem::transmute") && !trimmed.contains("SAFETY")),
        "KS-024" => {
            let n = normalized_call();
            (has_unquoted_call(&n, "jwt.decode(")
                && ["\"verify_signature\": False", "'verify_signature': False", "\"verify_signature\":False", "'verify_signature':False", "algorithms=[\"none\"]", "algorithms=['none']"].iter().any(|p| n.contains(p)))
                || (trimmed.contains("new ObjectInputStream(") && trimmed.contains(".readObject()"))
        }
        "KS-025" => ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----"].iter().any(|p| trimmed.contains(p)),
        "KS-026" => trimmed.starts_with("while True:") && trimmed.contains("UNBOUNDED_AGENT_LOOP"),
        "KS-027" => ["webhook_signature ==", "hmac_sig ==", "expected_hmac_digest =="].iter().any(|p| trimmed.contains(p)) && !trimmed.contains("compare_digest"),
        "KS-028" => { let n = normalized_call(); (n.contains("execSync(`") || n.contains("child_process.exec(`")) && n.contains("${") }
        "KS-029" => trimmed.contains("chmod 777 ") || trimmed.contains("chmod -R 777 "),
        "KS-030" => trimmed.contains("time.sleep(") && trimmed.contains("BLOCKING_ASYNC_SLEEP"),
        "KS-031" => has_unquoted_call(&normalized_call(), "tempfile.mktemp("),
        "KS-032" => trimmed.contains("StrictHostKeyChecking=no") || trimmed.contains("AutoAddPolicy()"),
        "KS-S3-02" => (["ssh ", "scp ", "sftp "].iter().any(|p| trimmed.starts_with(p)) || trimmed.contains("s's'h ") || trimmed.contains("tun-up"))
            && ["0x7c9e", "0x55d3", "0x7f000001", "vpn.corp.example.internal"].iter().any(|p| trimmed.contains(p)),
        "KS-S3-03" => matches_ks_s3_03_ledger_ddl(trimmed),
        "KS-S3-04" => trimmed.contains("readFileSync(\".secrets/private-credentials.local.md\")") || trimmed.contains("readFileSync('.secrets/private-credentials.local.md')"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bom_at_file_start_allowed_vs_line_two_and_mid_line_blocked() {
        assert!(!contains_bidi_control_at_line("\u{FEFF}def ok(): pass", true));
        assert!(contains_bidi_control_at_line("\u{FEFF}def smuggled(): pass", false));
        assert!(contains_bidi_control_at_line("x = '\u{FEFF}'", true));
        assert!(!check_line_against_rule_at_line("KS-019", "\u{FEFF}x = 1", "python", 0));
        assert!(check_line_against_rule_at_line("KS-019", "\u{FEFF}x = 1", "python", 1));
        assert!(check_line_against_rule_at_line("KS-019", "x = '\u{FEFF}'", "python", 0));
    }

    #[test]
    fn scoped_alias_rebind_and_ks013_receiver_matching() {
        let scoped_py = "def f(raw):\n    import yaml as ym\n    return ym.load(raw)\ndef g(raw):\n    return ym.load(raw)\n";
        let map_sc = FileAliasMap::from_source(scoped_py, "python");
        let sc_lines: Vec<&str> = scoped_py.lines().collect();
        assert!(check_line_against_rule_with_aliases("KS-020", sc_lines[2], "python", &map_sc));
        assert!(!check_line_against_rule_with_aliases("KS-020", sc_lines[4], "python", &map_sc));

        let rebind_py = "import yaml as ym\ndef safe(raw):\n    ym = SafeWrapper()\n    return ym.load(raw)\nbad = ym.load(raw)\n";
        let map_rb = FileAliasMap::from_source(rebind_py, "python");
        let rb_lines: Vec<&str> = rebind_py.lines().collect();
        assert!(!check_line_against_rule_with_aliases("KS-020", rb_lines[3], "python", &map_rb));
        assert!(check_line_against_rule_with_aliases("KS-020", rb_lines[4], "python", &map_rb));

        let wrong_py: Vec<&str> = "def s(p):\n    browser = p.chromium.launch()\n    try:\n        work()\n    finally:\n        log_file.close()\n".lines().collect();
        assert!(check_ks013_with_lines(&wrong_py, 1, "python"));
        let right_py: Vec<&str> = "def s(p):\n    br = p.chromium.launch()\n    try:\n        work()\n    finally:\n        br.close()\n".lines().collect();
        assert!(!check_ks013_with_lines(&right_py, 1, "python"));
    }
}
