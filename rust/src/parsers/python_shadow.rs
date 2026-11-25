// kintsugi: ignore-file
//! Lexical, string-span, indentation-scope, and balanced-expression Python shadow parser.

use std::collections::BTreeMap;

use crate::rules::is_fixture_definition_line;

#[derive(Debug, Clone)]
pub struct PyLineInfo {
    pub lineno: usize,
    pub raw: String,
    pub trimmed: String,
    pub masked: String,
    pub is_non_exec: bool,
}

#[derive(Debug, Clone)]
pub struct PyStringSpan {
    pub start_line_idx: usize,
    pub end_line_idx: usize,
    pub end_byte_after: usize,
    pub is_fstring: bool,
    pub inner: String,
}

#[derive(Debug, Clone)]
pub struct PyParsedFile {
    pub lines: Vec<PyLineInfo>,
    pub scope_lines: BTreeMap<usize, Vec<usize>>,
    pub string_spans: Vec<PyStringSpan>,
}

pub fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub fn is_fixture_block_start(trimmed: &str) -> bool {
    is_fixture_definition_line(trimmed)
        || trimmed.starts_with("\"breach_code\"")
        || trimmed.starts_with("\"safe_lookalike\"")
        || trimmed.starts_with("\"unseen_polymorphic_variant\"")
        || trimmed.starts_with("'breach_code'")
        || trimmed.starts_with("'safe_lookalike'")
        || trimmed.starts_with("'unseen_polymorphic_variant'")
        || trimmed.starts_with("bad_code =")
        || trimmed.starts_with("good_code =")
}

fn update_fixture_paren_depth(masked: &str, depth: &mut usize) {
    for &b in masked.as_bytes() {
        match b {
            b'(' | b'[' | b'{' => *depth += 1,
            b')' | b']' | b'}' => *depth = depth.saturating_sub(1),
            _ => {}
        }
    }
}

pub fn is_fstring_quote_prefix(bytes: &[u8], q_pos: usize) -> bool {
    let mut start = q_pos;
    let mut steps = 0usize;
    while start > 0 && steps < 2 {
        let ch = bytes[start - 1];
        if matches!(ch, b'f' | b'F' | b'r' | b'R' | b'b' | b'B' | b'u' | b'U') {
            start -= 1;
            steps += 1;
        } else {
            break;
        }
    }
    if start == q_pos || (start > 0 && is_ident_byte(bytes[start - 1])) {
        return false;
    }
    bytes[start..q_pos].iter().any(|&c| c == b'f' || c == b'F')
}

pub fn parse_python_file(content: &str) -> PyParsedFile {
    let raw_lines: Vec<&str> = content.lines().collect();
    let mut parsed_lines = Vec::with_capacity(raw_lines.len());
    let mut scope_lines: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut string_spans: Vec<PyStringSpan> = Vec::new();

    let mut triple_state: Option<(u8, bool, usize, String)> = None;
    let mut fixture_paren_depth = 0usize;
    let mut scope_stack: Vec<(usize, usize)> = Vec::new();
    let mut next_func_id = 1usize;
    let mut paren_balance: isize = 0;

    for (line_idx, raw_line) in raw_lines.iter().enumerate() {
        let raw = raw_line.trim_end_matches('\r').to_string();
        let trimmed = raw.trim().to_string();
        let bytes = raw.as_bytes();
        let mut masked_bytes = bytes.to_vec();
        let mut started_in_non_f_triple = matches!(triple_state, Some((_, false, _, _)));
        let mut i = 0usize;

        while i < bytes.len() {
            if let Some((q, is_f, s_line, ref mut buf)) = triple_state {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    masked_bytes[i] = b' ';
                    masked_bytes[i + 1] = b' ';
                    buf.push(bytes[i] as char);
                    buf.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if i + 2 < bytes.len() && bytes[i] == q && bytes[i + 1] == q && bytes[i + 2] == q {
                    let inner = std::mem::take(buf);
                    string_spans.push(PyStringSpan {
                        start_line_idx: s_line,
                        end_line_idx: line_idx,
                        end_byte_after: i + 3,
                        is_fstring: is_f,
                        inner,
                    });
                    triple_state = None;
                    i += 3;
                    continue;
                }
                masked_bytes[i] = b' ';
                let next_ch = raw[i..].chars().next().unwrap_or(' ');
                buf.push(next_ch);
                let ch_len = next_ch.len_utf8();
                for k in 1..ch_len {
                    if i + k < masked_bytes.len() {
                        masked_bytes[i + k] = b' ';
                    }
                }
                i += ch_len;
                continue;
            }

            if bytes[i] == b'#' {
                for b in &mut masked_bytes[i..] {
                    *b = b' ';
                }
                break;
            }

            if bytes[i] == b'"' || bytes[i] == b'\'' {
                let q = bytes[i];
                let is_f = is_fstring_quote_prefix(bytes, i);
                if i + 2 < bytes.len() && bytes[i + 1] == q && bytes[i + 2] == q {
                    triple_state = Some((q, is_f, line_idx, String::new()));
                    started_in_non_f_triple = false;
                    i += 3;
                    continue;
                }
                i += 1;
                let inner_start = i;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        masked_bytes[i] = b' ';
                        masked_bytes[i + 1] = b' ';
                        i += 2;
                        continue;
                    }
                    if bytes[i] == q {
                        break;
                    }
                    masked_bytes[i] = b' ';
                    i += 1;
                }
                let inner_end = i.min(bytes.len());
                if i < bytes.len() && bytes[i] == q {
                    string_spans.push(PyStringSpan {
                        start_line_idx: line_idx,
                        end_line_idx: line_idx,
                        end_byte_after: i + 1,
                        is_fstring: is_f,
                        inner: raw[inner_start..inner_end].to_string(),
                    });
                    i += 1;
                }
                continue;
            }
            i += 1;
        }

        if let Some((_, _, _, ref mut buf)) = triple_state {
            buf.push('\n');
        }

        let masked = String::from_utf8(masked_bytes).unwrap_or_else(|_| " ".repeat(raw.len()));
        let masked_trimmed = masked.trim();

        let in_fixture = if fixture_paren_depth > 0 {
            update_fixture_paren_depth(&masked, &mut fixture_paren_depth);
            true
        } else if is_fixture_block_start(&trimmed) {
            update_fixture_paren_depth(&masked, &mut fixture_paren_depth);
            true
        } else {
            false
        };

        let is_non_exec = started_in_non_f_triple || masked_trimmed.is_empty() || in_fixture;
        let indent: usize = raw
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .map(|c| if c == '\t' { 4 } else { 1 })
            .sum();

        if !is_non_exec && paren_balance <= 0 {
            while scope_stack.last().is_some_and(|&(di, _)| indent <= di) {
                scope_stack.pop();
            }
            if masked_trimmed.starts_with("def ") || masked_trimmed.starts_with("async def ") {
                let fid = next_func_id;
                next_func_id += 1;
                scope_stack.push((indent, fid));
            }
        }

        let func_id = scope_stack.last().map(|&(_, id)| id).unwrap_or(0);
        if !is_non_exec {
            for &b in masked.as_bytes() {
                match b {
                    b'(' | b'[' | b'{' => paren_balance += 1,
                    b')' | b']' | b'}' => paren_balance = (paren_balance - 1).max(0),
                    _ => {}
                }
            }
        }
        scope_lines.entry(func_id).or_default().push(line_idx);
        parsed_lines.push(PyLineInfo { lineno: line_idx + 1, raw, trimmed, masked, is_non_exec });
    }

    PyParsedFile { lines: parsed_lines, scope_lines, string_spans }
}

pub fn find_standalone_ident_call(masked: &str, needle: &str, start_from: usize) -> Option<usize> {
    let bytes = masked.as_bytes();
    let mut pos = start_from;
    while let Some(rel) = masked[pos..].find(needle) {
        let abs = pos + rel;
        if abs == 0 || (!is_ident_byte(bytes[abs - 1]) && bytes[abs - 1] != b'.') {
            return Some(abs);
        }
        pos = abs + 1;
    }
    None
}

pub fn find_dotted_call(masked: &str, needle: &str, start_from: usize) -> Option<usize> {
    let bytes = masked.as_bytes();
    let mut pos = start_from;
    while let Some(rel) = masked[pos..].find(needle) {
        let abs = pos + rel;
        if abs == 0 || !is_ident_byte(bytes[abs - 1]) {
            return Some(abs);
        }
        pos = abs + 1;
    }
    None
}

/// Extract balanced `(...)` / `[...]` / `{...}` content starting at `open_paren_byte`
/// in `lines[start_line_idx].masked`, looking ahead up to 128 lines.
pub fn collect_balanced_parens(
    lines: &[PyLineInfo],
    start_line_idx: usize,
    open_paren_byte: usize,
) -> Option<(String, String)> {
    let max_end = (start_line_idx + 128).min(lines.len());
    let mut raw_buf = String::new();
    let mut mask_buf = String::new();
    let mut depth = 0usize;

    for (offset, line) in lines[start_line_idx..max_end].iter().enumerate() {
        let begin = if offset == 0 { open_paren_byte } else { 0 };
        if offset > 0 {
            raw_buf.push('\n');
            mask_buf.push('\n');
        }
        let mbytes = line.masked.as_bytes();
        let mut idx = begin;
        while idx < mbytes.len() {
            match mbytes[idx] {
                b'(' | b'[' | b'{' => {
                    depth += 1;
                    if depth == 1 && offset == 0 && idx == open_paren_byte {
                        idx += 1;
                        continue;
                    }
                }
                b')' | b']' | b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let slice_start = if offset == 0 { begin + 1 } else { 0 };
                        raw_buf.push_str(&line.raw[slice_start..idx]);
                        mask_buf.push_str(&line.masked[slice_start..idx]);
                        return Some((raw_buf, mask_buf));
                    }
                }
                _ => {}
            }
            idx += 1;
        }
        let slice_start = if offset == 0 { begin + 1 } else { 0 };
        if slice_start <= line.raw.len() {
            raw_buf.push_str(&line.raw[slice_start..]);
            mask_buf.push_str(&line.masked[slice_start..]);
        }
    }
    None
}

/// Split top-level comma-separated items where `masked.len() == raw.len()`.
pub fn split_top_level_args(raw: &str, masked: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = masked.as_bytes();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (idx, &b) in bytes.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                let r_slice = raw[start..idx].trim();
                let m_slice = masked[start..idx].trim();
                if !r_slice.is_empty() {
                    out.push((r_slice.to_string(), m_slice.to_string()));
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start < raw.len() {
        let r_slice = raw[start..].trim();
        let m_slice = masked[start..].trim();
        if !r_slice.is_empty() {
            out.push((r_slice.to_string(), m_slice.to_string()));
        }
    }
    out
}

pub fn unquote_simple_py_str(raw: &str) -> Option<String> {
    let t = raw.trim();
    let body = t.strip_prefix('r').or_else(|| t.strip_prefix('R')).unwrap_or(t);
    if body.len() >= 2
        && ((body.starts_with('"') && body.ends_with('"')) || (body.starts_with('\'') && body.ends_with('\'')))
    {
        return Some(body[1..body.len() - 1].to_string());
    }
    None
}

pub fn is_single_ident(s: &str) -> Option<&str> {
    let t = s.trim();
    if !t.is_empty() && !t.as_bytes()[0].is_ascii_digit() && t.bytes().all(is_ident_byte) {
        Some(t)
    } else {
        None
    }
}

pub fn extract_bracket_list_items(raw_expr: &str, masked_expr: &str) -> Option<Vec<(String, String)>> {
    let rt = raw_expr.trim();
    let mt = masked_expr.trim();
    if !(mt.starts_with('[') && mt.ends_with(']')) {
        return None;
    }
    Some(split_top_level_args(&rt[1..rt.len() - 1], &mt[1..mt.len() - 1]))
}

/// Byte-accurate Python f-string interpolation check handling escaped `{{` and `}}`.
pub fn has_fstring_interpolation(inner: &str) -> bool {
    let bytes = inner.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                i += 2;
                continue;
            }
            let mut j = i + 1;
            while j < bytes.len() {
                if bytes[j] == b'}' {
                    if j + 1 < bytes.len() && bytes[j + 1] == b'}' {
                        j += 2;
                        continue;
                    }
                    return true;
                }
                j += 1;
            }
            return false;
        }
        if bytes[i] == b'}' && i + 1 < bytes.len() && bytes[i + 1] == b'}' {
            i += 2;
            continue;
        }
        i += 1;
    }
    false
}

pub fn tail_after_string_is_pct_or_format(
    lines: &[PyLineInfo],
    end_line_idx: usize,
    end_byte_after: usize,
) -> bool {
    let max_end = (end_line_idx + 3).min(lines.len());
    let mut tail = String::new();
    for (off, line) in lines[end_line_idx..max_end].iter().enumerate() {
        let start = if off == 0 { end_byte_after } else { 0 };
        if start <= line.masked.len() {
            tail.push_str(&line.masked[start..]);
        }
        tail.push('\n');
    }
    let trimmed = tail.trim_start();
    (trimmed.starts_with('%') && !trimmed.starts_with("%=")) || trimmed.starts_with(".format(")
}

pub fn gap_between_spans_is_whitespace(lines: &[PyLineInfo], prev: &PyStringSpan, next: &PyStringSpan) -> bool {
    if next.start_line_idx < prev.end_line_idx || next.start_line_idx > prev.end_line_idx + 1 {
        return false;
    }
    if prev.end_line_idx == next.start_line_idx {
        let line_m = &lines[prev.end_line_idx].masked;
        let trimmed = line_m[prev.end_byte_after.min(line_m.len())..].trim_start();
        return trimmed.starts_with('"') || trimmed.starts_with('\'');
    }
    lines[prev.end_line_idx].masked.get(prev.end_byte_after..).unwrap_or("").trim().is_empty()
}

pub fn extract_identifiers(code: &str) -> Vec<String> {
    let (mut out, bytes, mut i) = (Vec::new(), code.as_bytes(), 0usize);
    while i < bytes.len() {
        if (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_') && (i == 0 || !is_ident_byte(bytes[i - 1])) {
            let start = i;
            while i < bytes.len() && is_ident_byte(bytes[i]) { i += 1; }
            out.push(code[start..i].to_string());
        } else { i += 1; }
    }
    out
}

pub fn slice_cmp_sides(line_masked: &str, op_pos: usize) -> (&str, &str) {
    let left_all = &line_masked[..op_pos];
    let (mut l_start, lb, mut depth, mut i) = (0usize, left_all.as_bytes(), 0usize, left_all.len());
    while i > 0 {
        i -= 1;
        match lb[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth == 0 => { l_start = i + 1; break; }
            b'(' | b'[' | b'{' => depth -= 1,
            b',' | b':' | b';' if depth == 0 => { l_start = i + 1; break; }
            _ => {}
        }
    }
    let mut lhs = left_all[l_start..].trim();
    for kw in ["if ", "elif ", "return ", "while ", "assert ", "and ", "or ", "not "] {
        if let Some(pos) = lhs.rfind(kw) {
            if pos == 0 || !is_ident_byte(lhs.as_bytes()[pos - 1]) { lhs = lhs[pos + kw.len()..].trim(); }
        }
    }

    let right_all = &line_masked[op_pos + 2..];
    let (rb, mut r_end) = (right_all.as_bytes(), right_all.len());
    depth = 0;
    for (idx, &b) in rb.iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => { r_end = idx; break; }
            b')' | b']' | b'}' => depth -= 1,
            b',' | b':' | b';' if depth == 0 => { r_end = idx; break; }
            _ => {}
        }
    }
    let mut rhs = right_all[..r_end].trim();
    for kw in [" and ", " or "] {
        if let Some(pos) = rhs.find(kw) { rhs = rhs[..pos].trim(); }
    }
    (lhs, rhs)
}

pub fn extract_method_receiver(lines: &[PyLineInfo], line_idx: usize, dot_pos: usize) -> String {
    let start_idx = line_idx.saturating_sub(3);
    let (mut joined_raw, mut joined_mask) = (String::new(), String::new());
    for idx in start_idx..=line_idx {
        if idx > start_idx { joined_raw.push('\n'); joined_mask.push('\n'); }
        if idx == line_idx {
            joined_raw.push_str(&lines[idx].raw[..dot_pos]);
            joined_mask.push_str(&lines[idx].masked[..dot_pos]);
        } else {
            joined_raw.push_str(&lines[idx].raw);
            joined_mask.push_str(&lines[idx].masked);
        }
    }
    let (mb, mut depth, mut start, mut i) = (joined_mask.as_bytes(), 0usize, 0usize, joined_mask.len());
    while i > 0 {
        i -= 1;
        match mb[i] {
            b')' | b']' | b'}' => depth += 1,
            b'(' | b'[' | b'{' if depth == 0 => { start = i + 1; break; }
            b'(' | b'[' | b'{' => depth -= 1,
            b'=' | b',' | b':' | b';' | b'\n' if depth == 0 => { start = i + 1; break; }
            _ => {}
        }
    }
    joined_raw[start..].trim().to_string()
}

pub fn unwrap_git_var_expr(raw: &str) -> &str {
    let mut t = raw.trim();
    if let Some(rest) = t.strip_prefix('*') { t = rest.trim(); }
    if let Some(inner) = t.strip_prefix("str(").and_then(|s| s.strip_suffix(')')) { t = inner.trim(); }
    if let Some(inner) = t.strip_suffix(".strip()") { t = inner.trim(); }
    t
}

pub fn extract_def_func_name(masked_trimmed: &str) -> Option<&str> {
    let after = masked_trimmed.strip_prefix("def ").or_else(|| masked_trimmed.strip_prefix("async def "))?;
    is_single_ident(after.split('(').next()?.trim())
}

pub fn extract_lstrip_dash_source(raw_rhs: &str) -> Option<&str> {
    let recv = raw_rhs.trim().strip_suffix(".lstrip('-')").or_else(|| raw_rhs.trim().strip_suffix(".lstrip(\"-\")"))?;
    is_single_ident(unwrap_git_var_expr(recv))
}

pub fn extract_git_guard_vars_on_line(raw: &str, masked: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pat in [".startswith('-')", ".startswith(\"-\")", ".startswith(('-'", ".startswith((\"-"] {
        let mut from = 0usize;
        while let Some(rel) = raw[from..].find(pat) {
            let dot_pos = from + rel;
            let prefix = &raw[..dot_pos];
            let start = prefix.rfind(|c: char| !is_ident_byte(c as u8) && !matches!(c, '(' | ')' | '.')).map_or(0, |i| i + 1);
            if let Some(id) = is_single_ident(unwrap_git_var_expr(&prefix[start..])) { out.push(id.to_string()); }
            from = dot_pos + pat.len();
        }
    }
    for helper in ["validate_git_ref(", "_validate_git_ref(", "check_ref(", "_check_ref(", "validate_ref(", "_validate_ref("] {
        let mut from = 0usize;
        while let Some(pos) = find_standalone_ident_call(masked, helper, from) {
            let after = &masked[pos + helper.len()..];
            if let Some(end_p) = after.find([')', ',']) {
                if let Some(id) = is_single_ident(unwrap_git_var_expr(&after[..end_p])) { out.push(id.to_string()); }
            }
            from = pos + helper.len();
        }
    }
    out
}

pub fn extract_fstring_expr_idents(raw_fstr: &str) -> Vec<String> {
    let (bytes, mut out, mut i) = (raw_fstr.as_bytes(), Vec::new(), 0usize);
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if bytes.get(i + 1) == Some(&b'{') { i += 2; continue; }
            let (start, mut j) = (i + 1, i + 1);
            while j < bytes.len() && bytes[j] != b'}' { j += 1; }
            if j < bytes.len() {
                out.extend(extract_identifiers(raw_fstr[start..j].split([':', '!']).next().unwrap_or("")));
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn is_safe_path_join_rhs(rhs_raw: &str, rhs_masked: &str) -> bool {
    if rhs_raw.contains(".relative_to(") { return true; }
    let rt = rhs_raw.trim();
    if let Some(lit) = unquote_simple_py_str(rt) { return !lit.starts_with('-'); }
    rhs_masked.rfind('/').and_then(|sp| unquote_simple_py_str(rt[sp + 1..].trim())).is_some_and(|lit| !lit.starts_with('-'))
}

pub fn is_trivial_cmp_operand(raw_op: &str, masked_op: &str) -> bool {
    let (mt, rt) = (masked_op.trim(), raw_op.trim());
    if mt.is_empty() || matches!(mt, "None" | "True" | "False" | "\"\"" | "''") || matches!(rt, "\"\"" | "''")
        || mt.chars().all(|c| c.is_ascii_digit())
        || ["len(", "type(", "isinstance("].iter().any(|p| mt.starts_with(p))
    {
        return true;
    }
    is_single_ident(mt).is_some_and(|id| id.len() >= 3 && id.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()))
}

pub fn has_sensitive_file_token(expr: &str) -> bool {
    expr.to_ascii_lowercase().split(|c: char| !c.is_ascii_alphanumeric()).any(|tok| {
        !tok.is_empty()
            && (matches!(tok, "key" | "keys" | "manifest" | "manifests" | "secret" | "secrets" | "cred" | "creds" | "token" | "tokens" | "attestation" | "policy" | "policies" | "registry")
                || tok.ends_with("key")
                || ["keyfile", "keystore", "manifest", "secret", "credential", "credfile", "token", "attestation", "policy", "registry"].iter().any(|p| tok.starts_with(p)))
    })
}
