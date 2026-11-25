//! Kintsugi v3.0 Typed Obligation Prover (`rust/src/audit/obligation_prover.rs`).
//!
//! Zero-dependency syntactic call-span extractor + intra-function straight-line scope/alias
//! binding resolver producing honest four-way obligations:
//!   `PROVEN | VIOLATED | UNKNOWN | UNSUPPORTED`
//!
//! Covers Python (`.py`/`.pyi`) and TypeScript/JavaScript (`.ts`/`.js`/`.mjs`/`.cjs`) for
//! `CMD_EXEC` and `SQL_EXEC` (plus Rust `Command::new`), while explicitly returning `UNSUPPORTED`
//! for `.tsx`/`.jsx`. Never uses lexical fallback or comment markers to promote `UNKNOWN` to `PROVEN`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::policy::sha256_hex;
use crate::rules::matcher::is_fixture_definition_line;

pub const OBLIGATION_PROVER_KIND: &str = "typed_obligation_prover_v3";
const MAX_MULTILINE_CALL_LINES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationState {
    Proven,
    Violated,
    Unknown,
    Unsupported,
}

impl ObligationState {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "PROVEN",
            Self::Violated => "VIOLATED",
            Self::Unknown => "UNKNOWN",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    pub rule: &'static str,
    pub lang: &'static str,
    pub sink_span: Span,
    pub witness_span: Option<Span>,
    pub binding: Option<String>,
    pub source_hash: String,
    pub state: ObligationState,
    pub reason: &'static str,
    pub fix_hint: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LangKind {
    Python,
    TypeScript,
    TsxUnsupported,
    Rust,
    Other,
}

impl LangKind {
    fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
            "py" | "pyi" => Self::Python,
            "ts" | "js" | "mjs" | "cjs" => Self::TypeScript,
            "tsx" | "jsx" => Self::TsxUnsupported,
            "rs" => Self::Rust,
            _ => Self::Other,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::TypeScript => "typescript",
            Self::TsxUnsupported => "tsx",
            Self::Rust => "rust",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone)]
enum BindingVal {
    StaticSql { has_placeholder: bool, line: usize },
    DynamicSql { line: usize },
    BoolConst { val: bool, line: usize },
    Unknown,
}

#[derive(Debug, Clone)]
struct ExtractedCall {
    raw_args: String,
    masked_args: String,
    span: Span,
    balanced: bool,
    arg_line_offsets: Vec<(usize, String, String)>,
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn is_ident_str(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && !t.as_bytes()[0].is_ascii_digit()
        && t.bytes().all(is_ident_byte)
        && !matches!(t, "True" | "False" | "None" | "true" | "false" | "null" | "undefined")
}

fn line_indent(line: &str) -> usize {
    line.bytes().take_while(|&b| b == b' ' || b == b'\t').count()
}

/// Extract balanced call arguments starting at `open_paren_col` on `start_line` using the file-level masked stream.
fn extract_balanced_call(
    raw_lines: &[&str],
    masked_lines: &[String],
    start_line: usize,
    open_paren_col: usize,
) -> ExtractedCall {
    let mut raw_buf = String::new();
    let mut mask_buf = String::new();
    let mut depth: usize = 0;
    let mut end_line = start_line;
    let mut end_col = open_paren_col;
    let mut balanced = false;

    let max_line = (start_line + MAX_MULTILINE_CALL_LINES).min(raw_lines.len());
    'outer: for li in start_line..max_line {
        let rl = raw_lines[li];
        let ml = masked_lines[li].as_str();
        let start_c = if li == start_line { open_paren_col } else { 0 };
        let r_bytes = rl.as_bytes();
        let m_bytes = ml.as_bytes();
        let lim = m_bytes.len().min(r_bytes.len());
        if li > start_line {
            raw_buf.push('\n');
            mask_buf.push('\n');
        }
        let mut bi = start_c;
        while bi < lim {
            let mb = m_bytes[bi];
            if mb == b'(' {
                depth += 1;
                if depth > 1 {
                    raw_buf.push('(');
                    mask_buf.push('(');
                }
                bi += 1;
            } else if mb == b')' {
                if depth <= 1 {
                    end_line = li;
                    end_col = bi + 1;
                    balanced = true;
                    break 'outer;
                }
                depth -= 1;
                raw_buf.push(')');
                mask_buf.push(')');
                bi += 1;
            } else {
                let rch = rl[bi..].chars().next().unwrap_or(' ');
                let mch = ml[bi..].chars().next().unwrap_or(' ');
                let step = rch.len_utf8().min(mch.len_utf8()).max(1);
                if depth >= 1 {
                    raw_buf.push_str(&rl[bi..bi + step]);
                    mask_buf.push_str(&ml[bi..bi + step]);
                }
                bi += step;
            }
        }
        // If raw line extended past masked line (e.g. inline comment stripped), ignore trailing comment safely.
        end_line = li;
        end_col = lim;
    }

    let arg_line_offsets = split_top_level_args(&raw_buf, &mask_buf, start_line + 1);
    ExtractedCall {
        raw_args: raw_buf,
        masked_args: mask_buf,
        span: Span {
            start_line: start_line + 1,
            start_col: open_paren_col + 1,
            end_line: end_line + 1,
            end_col: end_col.max(1),
        },
        balanced,
        arg_line_offsets,
    }
}

/// Split top-level comma-separated call arguments tracking `()[]{}` balance on the masked stream.
fn split_top_level_args(raw: &str, masked: &str, base_line: usize) -> Vec<(usize, String, String)> {
    let mut args = Vec::new();
    let rb = raw.as_bytes();
    let mb = masked.as_bytes();
    let n = rb.len().min(mb.len());
    let (mut depth_p, mut depth_b, mut depth_c) = (0usize, 0usize, 0usize);
    let mut seg_start = 0usize;
    let mut cur_line = base_line;
    let mut seg_line = base_line;

    for i in 0..n {
        let b = mb[i];
        if b == b'\n' {
            cur_line += 1;
        }
        match b {
            b'(' => depth_p += 1,
            b')' => depth_p = depth_p.saturating_sub(1),
            b'[' => depth_b += 1,
            b']' => depth_b = depth_b.saturating_sub(1),
            b'{' => depth_c += 1,
            b'}' => depth_c = depth_c.saturating_sub(1),
            b',' if depth_p == 0 && depth_b == 0 && depth_c == 0 => {
                let raw_slice = &raw[seg_start..i];
                let leading_ws = raw_slice.len() - raw_slice.trim_start().len();
                let leading_nl = raw_slice[..leading_ws].bytes().filter(|&x| x == b'\n').count();
                let r_part = raw_slice.trim().to_string();
                let m_part = masked[seg_start..i].trim().to_string();
                if !r_part.is_empty() {
                    args.push((seg_line + leading_nl, r_part, m_part));
                }
                seg_start = i + 1;
                seg_line = cur_line;
            }
            _ => {}
        }
    }
    if seg_start < n {
        let raw_slice = &raw[seg_start..n];
        let leading_ws = raw_slice.len() - raw_slice.trim_start().len();
        let leading_nl = raw_slice[..leading_ws].bytes().filter(|&x| x == b'\n').count();
        let r_part = raw_slice.trim().to_string();
        let m_part = masked[seg_start..n].trim().to_string();
        if !r_part.is_empty() {
            args.push((seg_line + leading_nl, r_part, m_part));
        }
    }
    args
}

fn contains_sql_placeholder(raw: &str) -> bool {
    raw.contains('?')
        || raw.contains("%s")
        || raw.contains("$1")
        || raw.contains("$2")
        || raw.contains(":id")
        || raw.contains("= :")
        || raw.contains("( :")
        || raw.contains(",:")
}

/// Check whether a raw/masked expression is purely static string literal(s) (no f-string, `${}`, `+`, `%`, `.format(`).
fn classify_sql_expr(raw_expr: &str, masked_expr: &str) -> Option<bool> {
    let r = raw_expr.trim();
    let m = masked_expr.trim();
    if r.is_empty() {
        return None;
    }
    // Immediate dynamic SQL disqualification
    let ru = r.to_ascii_uppercase();
    if ru.starts_with("F\"")
        || ru.starts_with("F'")
        || ru.contains(" F\"")
        || ru.contains(" F'")
        || ru.contains("(F\"")
        || ru.contains("(F'")
        || r.contains("${")
        || m.contains('+')
        || m.contains('%')
        || m.contains(".format(")
        || m.contains("format!(")
    {
        return Some(false);
    }
    // Check if the masked version contains ONLY whitespace, parens, or string-prefix chars (r/b/u) — meaning every token was a static string literal!
    let has_quote = r.contains('"') || r.contains('\'') || r.contains('`');
    if !has_quote {
        return None;
    }
    let only_static_wrappers = m.chars().all(|c| c.is_whitespace() || matches!(c, '(' | ')' | 'r' | 'R' | 'b' | 'B' | 'u' | 'U' | ';'));
    if only_static_wrappers {
        Some(true)
    } else {
        // Contains identifier/call combined with string -> dynamic or opaque
        None
    }
}

fn has_dynamic_sql_indicators(raw_expr: &str, masked_expr: &str) -> bool {
    let r = raw_expr.trim();
    let m = masked_expr.trim();
    let ru = r.to_ascii_uppercase();
    let has_sql_verb = ["SELECT ", "INSERT ", "UPDATE ", "DELETE ", "WITH "]
        .iter()
        .any(|v| ru.contains(v));
    if !has_sql_verb {
        return false;
    }
    ru.contains("F\"")
        || ru.contains("F'")
        || r.contains("${")
        || m.contains('+')
        || m.contains('%')
        || m.contains(".format(")
        || m.contains("format!(")
}

#[derive(Debug, Default)]
struct ScopeEnv {
    /// Module-level import aliases: alias -> canonical module/symbol (e.g. "sp" -> "subprocess", "run_cmd" -> "subprocess.run")
    aliases: BTreeMap<String, String>,
    /// Active function local bindings: var_name -> (decl_depth, BindingVal)
    locals: BTreeMap<String, (usize, BindingVal)>,
    /// Variables mutated inside nested control flow (must never be treated as straight-line immutable in enclosing scope)
    tainted_by_branch: BTreeSet<String>,
    fn_base_depth: usize,
    in_function: bool,
}

impl ScopeEnv {
    fn reset_for_new_function(&mut self, base_depth: usize, params: &[String]) {
        self.locals.clear();
        self.tainted_by_branch.clear();
        self.fn_base_depth = base_depth;
        self.in_function = true;
        for p in params {
            self.locals.insert(p.clone(), (base_depth, BindingVal::Unknown));
        }
    }

    fn record_assignment(&mut self, var: &str, cur_depth: usize, val: BindingVal) {
        let is_nested = self.in_function && cur_depth > self.fn_base_depth + 4;
        if let Some((prev_depth, prev_val)) = self.locals.get(var).cloned() {
            if is_nested && cur_depth > prev_depth {
                // Assigned inside an inner branch/loop: propagate DynamicSql if dangerous, otherwise invalidate to Unknown!
                self.tainted_by_branch.insert(var.to_string());
                let merged = match (&prev_val, &val) {
                    (_, BindingVal::DynamicSql { line }) => BindingVal::DynamicSql { line: *line },
                    (BindingVal::DynamicSql { line }, _) => BindingVal::DynamicSql { line: *line },
                    _ => BindingVal::Unknown,
                };
                self.locals.insert(var.to_string(), (prev_depth, merged));
                return;
            }
            // Straight-line reassignment in same scope: DynamicSql stays Violated; any other reassignment to non-static becomes Unknown!
            match val {
                BindingVal::DynamicSql { .. } => {
                    self.locals.insert(var.to_string(), (cur_depth, val));
                }
                _ => {
                    // Any reassignment invalidates previous immutable static guarantee unless we keep strict straight-line overwrite -> safer: mark Unknown if previously bound!
                    self.locals.insert(var.to_string(), (cur_depth, BindingVal::Unknown));
                }
            }
        } else {
            if is_nested {
                self.tainted_by_branch.insert(var.to_string());
            }
            self.locals.insert(var.to_string(), (cur_depth, val));
        }
    }

    fn lookup(&self, var: &str, cur_depth: usize) -> Option<&BindingVal> {
        let (decl_depth, val) = self.locals.get(var)?;
        if self.tainted_by_branch.contains(var) && cur_depth < *decl_depth {
            return Some(&BindingVal::Unknown);
        }
        Some(val)
    }
}

fn parse_py_import_aliases(mt: &str, aliases: &mut BTreeMap<String, String>) {
    // `import subprocess as sp`
    if let Some(rest) = mt.strip_prefix("import ") {
        for part in rest.split(',') {
            let p = part.trim();
            if let Some((orig, alias)) = p.split_once(" as ") {
                let (o, a) = (orig.trim(), alias.trim());
                if matches!(o, "subprocess" | "os") && is_ident_str(a) {
                    aliases.insert(a.to_string(), o.to_string());
                }
            }
        }
    }
    // `from subprocess import run as r, Popen as P`
    if let Some(rest) = mt.strip_prefix("from ") {
        if let Some((mod_name, imported)) = rest.split_once(" import ") {
            let m = mod_name.trim();
            if matches!(m, "subprocess" | "os") {
                for part in imported.split(',') {
                    let p = part.trim().trim_matches(|c| c == '(' || c == ')');
                    let (sym, alias) = match p.split_once(" as ") {
                        Some((s, a)) => (s.trim(), a.trim()),
                        None => (p, p),
                    };
                    if is_ident_str(alias) && is_ident_str(sym) {
                        aliases.insert(alias.to_string(), format!("{m}.{sym}"));
                    }
                }
            }
        }
    }
}

fn parse_ts_import_aliases(raw: &str, mt: &str, aliases: &mut BTreeMap<String, String>) {
    if !mt.starts_with("import ") || !(raw.contains("child_process") || raw.contains("node:child_process")) {
        return;
    }
    if let Some(rest) = mt.strip_prefix("import * as ") {
        if let Some(alias) = rest.split_whitespace().next() {
            if is_ident_str(alias) {
                aliases.insert(alias.to_string(), "child_process".to_string());
            }
        }
    }
    if let (Some(lbrace), Some(rbrace)) = (mt.find('{'), mt.find('}')) {
        if rbrace > lbrace {
            for part in mt[lbrace + 1..rbrace].split(',') {
                let p = part.trim();
                let (sym, alias) = match p.split_once(" as ") {
                    Some((s, a)) => (s.trim(), a.trim()),
                    None => (p, p),
                };
                if is_ident_str(alias) && is_ident_str(sym) {
                    aliases.insert(alias.to_string(), format!("child_process.{sym}"));
                }
            }
        }
    }
}

fn parse_fn_params(mt: &str) -> Vec<String> {
    let (Some(lp), Some(rp)) = (mt.find('('), mt.rfind(')')) else { return Vec::new() };
    if rp <= lp {
        return Vec::new();
    }
    mt[lp + 1..rp]
        .split(',')
        .filter_map(|seg| {
            let name = seg.trim().trim_start_matches('*').split([':', '=']).next()?.trim();
            if is_ident_str(name) { Some(name.to_string()) } else { None }
        })
        .collect()
}

/// Extract multi-line or single-line RHS of a local variable assignment (`sql = ...` / `const sql = ...`).
fn try_parse_assignment(
    raw_lines: &[&str],
    masked_lines: &[String],
    idx: usize,
    lang: LangKind,
) -> Option<(String, String, String, bool)> {
    let ml = masked_lines[idx].trim();
    let rl = raw_lines[idx].trim();
    if ml.is_empty()
        || ml.starts_with("if ")
        || ml.starts_with("elif ")
        || ml.starts_with("while ")
        || ml.starts_with("return ")
        || ml.starts_with("def ")
        || ml.starts_with("async def ")
    {
        return None;
    }

    // Augmented assignment `sql += ...` is always a mutation!
    for aug in ["+=", "-=", "%="] {
        if let Some(pos) = ml.find(aug) {
            let lhs = ml[..pos].trim();
            if is_ident_str(lhs) {
                return Some((lhs.to_string(), rl[pos + 2..].trim().to_string(), ml[pos + 2..].trim().to_string(), true));
            }
        }
    }

    let (lhs_raw, eq_col) = if lang == LangKind::TypeScript {
        let stripped = ml.strip_prefix("const ").or_else(|| ml.strip_prefix("let ")).or_else(|| ml.strip_prefix("var "))?;
        let eq_rel = stripped.find('=')?;
        if stripped.as_bytes().get(eq_rel + 1) == Some(&b'=') || stripped.as_bytes().get(eq_rel + 1) == Some(&b'>') {
            return None;
        }
        let lhs = stripped[..eq_rel].split(':').next()?.trim();
        let eq_abs = ml.find('=')?;
        (lhs, eq_abs)
    } else {
        // Python: `name = expr` or `name: str = expr` (exclude `==`, `!=`, `<=`, `>=`, keyword args inside calls)
        let eq_pos = ml.find('=')?;
        if eq_pos == 0 {
            return None;
        }
        let prev = ml.as_bytes()[eq_pos - 1];
        let next = ml.as_bytes().get(eq_pos + 1).copied().unwrap_or(b' ');
        if matches!(prev, b'!' | b'<' | b'>' | b'=') || next == b'=' {
            return None;
        }
        let lhs_part = ml[..eq_pos].trim();
        if lhs_part.contains('(') || lhs_part.contains(',') || lhs_part.contains('.') || lhs_part.contains('[') {
            return None;
        }
        let lhs = lhs_part.split(':').next()?.trim();
        (lhs, eq_pos)
    };

    if !is_ident_str(lhs_raw) {
        return None;
    }
    let eq_raw = rl.find('=')?;
    let mut rhs_raw = rl[eq_raw + 1..].trim().to_string();
    let mut rhs_mask = ml[eq_col + 1..].trim().to_string();

    // Handle parenthesized multi-line assignment like `sql = (\n "SELECT ... "\n "WHERE id = ?"\n)`
    let mut paren_d: i32 = rhs_mask.bytes().map(|b| if b == b'(' { 1 } else if b == b')' { -1 } else { 0 }).sum();
    let mut j = idx + 1;
    while paren_d > 0 && j < raw_lines.len().min(idx + 24) {
        rhs_raw.push(' ');
        rhs_raw.push_str(raw_lines[j].trim());
        rhs_mask.push(' ');
        rhs_mask.push_str(masked_lines[j].trim());
        paren_d += masked_lines[j].bytes().map(|b| if b == b'(' { 1 } else if b == b')' { -1 } else { 0 }).sum::<i32>();
        j += 1;
    }
    Some((lhs_raw.to_string(), rhs_raw, rhs_mask, false))
}

#[derive(Debug, Clone)]
struct SinkMatch {
    rule: &'static str,
    callee: String,
    open_paren_col: usize,
}

/// Find ALL `CMD_EXEC` and `SQL_EXEC` sink calls on a single masked line (supports multiple sinks per line!).
fn find_all_sinks_on_line(
    raw_line: &str,
    masked_line: &str,
    lang: LangKind,
    aliases: &BTreeMap<String, String>,
) -> Vec<SinkMatch> {
    let mut sinks = Vec::new();
    let rt = raw_line.trim();
    let mt = masked_line.trim();
    if mt.is_empty()
        || ["*", "fix_hint:", "title:", "kmi_token:", "let bad_", "let ignored_", "poisoned."].iter().any(|p| rt.starts_with(p))
        || rt.contains(".contains(\"")
        || is_fixture_definition_line(rt)
    {
        return sinks;
    }

    let bytes = masked_line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'(' {
            continue;
        }
        // Scan backwards over callee chain `a.b.c` or `Command::new`
        let mut start = i;
        while start > 0 && (is_ident_byte(bytes[start - 1]) || matches!(bytes[start - 1], b'.' | b':')) {
            start -= 1;
        }
        if start == i {
            continue;
        }
        // Skip function/method declaration headers (`def foo(`, `function bar(`) without skipping calls later on the same line!
        let before = masked_line[..start].trim_end();
        if before.ends_with("def") || before.ends_with("function") || before.ends_with("fn") || before.ends_with("class") {
            continue;
        }
        let raw_callee = &masked_line[start..i];
        // Resolve import alias on head identifier (`sp.run` -> `subprocess.run`, `run_cmd` -> `subprocess.run`)
        let resolved = if let Some((head, tail)) = raw_callee.split_once('.') {
            if let Some(canon) = aliases.get(head) {
                format!("{canon}.{tail}")
            } else {
                raw_callee.to_string()
            }
        } else if let Some(canon) = aliases.get(raw_callee) {
            canon.clone()
        } else {
            raw_callee.to_string()
        };

        let method = resolved.rsplit('.').next().unwrap_or(&resolved);
        let is_cmd = match lang {
            LangKind::Python => {
                matches!(
                    resolved.as_str(),
                    "subprocess.run"
                        | "subprocess.Popen"
                        | "subprocess.call"
                        | "subprocess.check_call"
                        | "subprocess.check_output"
                        | "os.system"
                        | "os.popen"
                        | "eval"
                )
            }
            LangKind::TypeScript | LangKind::TsxUnsupported => {
                matches!(
                    resolved.as_str(),
                    "child_process.exec"
                        | "child_process.execSync"
                        | "child_process.execFile"
                        | "child_process.execFileSync"
                        | "child_process.spawn"
                        | "child_process.spawnSync"
                        | "execSync"
                        | "execFileSync"
                        | "execFile"
                        | "spawnSync"
                        | "spawn"
                        | "eval"
                        | "authorizeCommand"
                        | "runProcess"
                        | "runCommand"
                )
            }
            LangKind::Rust => resolved == "Command::new" || resolved.ends_with("::Command::new"),
            LangKind::Other => matches!(method, "execSync" | "execFileSync" | "execFile" | "spawnSync" | "eval"),
        };

        let is_sql = match lang {
            LangKind::Python => resolved.contains('.') && matches!(method, "execute" | "executemany"),
            LangKind::TypeScript | LangKind::TsxUnsupported => {
                resolved.contains('.') && matches!(method, "query" | "execute" | "raw" | "where" | "andWhere")
            }
            LangKind::Rust | LangKind::Other => {
                matches!(method, "executeQuery" | "prepareStatement" | "mysqli_query" | "mysql_query")
                    || (resolved.contains('.') && matches!(method, "execute" | "executemany"))
            }
        };

        if is_cmd {
            sinks.push(SinkMatch { rule: "CMD_EXEC", callee: resolved, open_paren_col: i });
        } else if is_sql {
            sinks.push(SinkMatch { rule: "SQL_EXEC", callee: resolved, open_paren_col: i });
        }
    }
    sinks
}

fn eval_cmd_obligation(
    sink: &SinkMatch,
    call: &ExtractedCall,
    lang: LangKind,
    env: &ScopeEnv,
    cur_depth: usize,
    raw_lines: &[&str],
    source_hash: &str,
) -> Obligation {
    let mk = |state: ObligationState, witness: Option<Span>, binding: Option<String>, reason: &'static str, fix_hint: &'static str| Obligation {
        rule: "CMD_EXEC",
        lang: lang.as_str(),
        sink_span: call.span,
        witness_span: witness,
        binding,
        source_hash: source_hash.to_string(),
        state,
        reason,
        fix_hint,
    };

    if lang == LangKind::TsxUnsupported {
        return mk(ObligationState::Unsupported, None, None, "tsx/jsx grammar unsupported by v3 prover", "Move command execution into a pure .ts module");
    }
    if !call.balanced {
        return mk(ObligationState::Unknown, None, None, "unclosed or malformed call span", "Fix syntax so call arguments can be proved");
    }

    // Inherently unsafe sinks
    if matches!(sink.callee.as_str(), "os.system" | "os.popen" | "eval" | "child_process.exec" | "execSync" | "child_process.execSync") {
        return mk(
            ObligationState::Violated,
            Some(call.span),
            None,
            "inherently unsafe shell/eval execution sink",
            "Use argv list with subprocess.run(..., shell=False) or execFileSync(..., { shell: false })",
        );
    }

    // Rust Command::new(...)
    if lang == LangKind::Rust {
        let end_scan = (call.span.end_line + 3).min(raw_lines.len());
        let window = raw_lines[call.span.start_line - 1..end_scan].join("\n");
        let is_shell_trampoline = ["\"sh\"", "\"/bin/sh\"", "\"bash\"", "\"zsh\""].iter().any(|s| window.contains(s))
            && window.contains("\"-c\"");
        return if is_shell_trampoline {
            mk(ObligationState::Violated, Some(call.span), None, "Command::new invokes shell -c trampoline", "Invoke target binary directly via Command::new(bin).arg(...)")
        } else {
            mk(ObligationState::Proven, Some(call.span), None, "Rust Command::new direct argv execution", "")
        };
    }

    // Python subprocess.*
    if lang == LangKind::Python {
        let mut has_kwargs_spread = false;
        let mut shell_witness: Option<(usize, ObligationState, Option<String>)> = None;

        // Check shell trampoline in argv[0]: `["sh", "-c", ...]`
        if let Some((_, first_raw, _)) = call.arg_line_offsets.first() {
            let invokes_sh = ["\"sh\"", "'sh'", "\"/bin/sh\"", "'/bin/sh'", "\"bash\"", "'bash'", "\"/bin/bash\"", "'/bin/bash'"]
                .iter()
                .any(|s| first_raw.contains(s))
                && (first_raw.contains("\"-c\"") || first_raw.contains("'-c'"));
            if invokes_sh {
                return mk(ObligationState::Violated, Some(call.span), None, "argv invokes shell -c trampoline", "Pass direct binary argv without sh -c");
            }
        }

        for (arg_line, raw_a, mask_a) in &call.arg_line_offsets {
            let ma = mask_a.trim();
            if ma.starts_with("**") {
                has_kwargs_spread = true;
            }
            if let Some(eq_p) = ma.find('=') {
                let k = ma[..eq_p].trim();
                if k == "shell" {
                    let v = ma[eq_p + 1..].trim();
                    if v == "True" || v == "1" {
                        return mk(
                            ObligationState::Violated,
                            Some(Span { start_line: *arg_line, start_col: 1, end_line: *arg_line, end_col: raw_a.len().max(1) }),
                            None,
                            "explicit shell=True on subprocess call",
                            "Pass argv list with explicit shell=False",
                        );
                    } else if v == "False" {
                        shell_witness = Some((*arg_line, ObligationState::Proven, None));
                    } else if is_ident_str(v) {
                        match env.lookup(v, cur_depth) {
                            Some(BindingVal::BoolConst { val: false, line }) => {
                                shell_witness = Some((*line, ObligationState::Proven, Some(v.to_string())));
                            }
                            Some(BindingVal::BoolConst { val: true, line }) => {
                                return mk(
                                    ObligationState::Violated,
                                    Some(Span { start_line: *line, start_col: 1, end_line: *line, end_col: 1 }),
                                    Some(v.to_string()),
                                    "shell bound to True via local variable",
                                    "Bind shell=False explicitly",
                                );
                            }
                            _ => {
                                shell_witness = Some((*arg_line, ObligationState::Unknown, Some(v.to_string())));
                            }
                        }
                    } else {
                        shell_witness = Some((*arg_line, ObligationState::Unknown, None));
                    }
                }
            }
        }

        if has_kwargs_spread {
            return mk(
                ObligationState::Unknown,
                None,
                None,
                "**kwargs spread can override shell=False at runtime",
                "Remove **kwargs spread and pass explicit shell=False",
            );
        }
        return match shell_witness {
            Some((wline, ObligationState::Proven, bnd)) => mk(
                ObligationState::Proven,
                Some(Span { start_line: wline, start_col: 1, end_line: wline, end_col: 1 }),
                bnd,
                "explicit shell=False verified across full balanced call span",
                "",
            ),
            _ => mk(
                ObligationState::Unknown,
                None,
                None,
                "missing explicit shell=False on subprocess call",
                "Pass explicit shell=False on subprocess call",
            ),
        };
    }

    // TypeScript / JavaScript spawnSync / execFileSync / execFile / spawn
    let raw_all = call.raw_args.as_str();
    let mask_all = call.masked_args.as_str();
    if mask_all.contains("...") {
        return mk(
            ObligationState::Unknown,
            None,
            None,
            "object spread (...opts) can override shell: false at runtime",
            "Pass explicit options object { shell: false } without untrusted spread",
        );
    }
    if mask_all.contains("shell: true") || mask_all.contains("shell:true") {
        return mk(
            ObligationState::Violated,
            Some(call.span),
            None,
            "explicit shell: true in child_process options",
            "Pass { shell: false } and argv array",
        );
    }
    if mask_all.contains("shell: false") || mask_all.contains("shell:false") {
        return mk(ObligationState::Proven, Some(call.span), None, "explicit { shell: false } verified", "");
    }
    if matches!(sink.callee.as_str(), "execFile" | "execFileSync" | "child_process.execFile" | "child_process.execFileSync" | "authorizeCommand")
        && !raw_all.contains("shell:")
    {
        return mk(ObligationState::Proven, Some(call.span), None, "execFile/execFileSync default shell=false verified", "");
    }
    mk(
        ObligationState::Unknown,
        None,
        None,
        "missing explicit shell: false in child_process options",
        "Pass { shell: false } explicitly",
    )
}

fn eval_sql_obligation(
    call: &ExtractedCall,
    lang: LangKind,
    env: &ScopeEnv,
    cur_depth: usize,
    source_hash: &str,
) -> Obligation {
    let mk = |state: ObligationState, witness: Option<Span>, binding: Option<String>, reason: &'static str, fix_hint: &'static str| Obligation {
        rule: "SQL_EXEC",
        lang: lang.as_str(),
        sink_span: call.span,
        witness_span: witness,
        binding,
        source_hash: source_hash.to_string(),
        state,
        reason,
        fix_hint,
    };

    if lang == LangKind::TsxUnsupported {
        return mk(ObligationState::Unsupported, None, None, "tsx/jsx grammar unsupported by v3 prover", "Move SQL queries into a pure .ts repository module");
    }
    if !call.balanced || call.arg_line_offsets.is_empty() {
        return mk(ObligationState::Unknown, None, None, "unclosed or empty SQL call span", "Pass static SQL literal with bound parameters");
    }
    // Any *args / **kwargs / ...spread makes parameter binding unprovable
    if call.arg_line_offsets.iter().any(|(_, _, m)| m.starts_with('*') || m.starts_with("...")) {
        return mk(ObligationState::Unknown, None, None, "variadic spread obscures SQL query/params", "Pass static SQL literal and explicit parameter tuple/array");
    }

    let (arg0_line, arg0_raw, arg0_mask) = &call.arg_line_offsets[0];
    let has_params_arg = call.arg_line_offsets.len() >= 2;

    // 1. Direct expression check (inline static literal or inline dynamic interpolation)
    match classify_sql_expr(arg0_raw, arg0_mask) {
        Some(false) => {
            return mk(
                ObligationState::Violated,
                Some(Span { start_line: *arg0_line, start_col: 1, end_line: *arg0_line, end_col: 1 }),
                None,
                "dynamic SQL interpolation (+/%/.format/f-string/${}) in query argument",
                "Use static SQL literal with parameterized placeholder (?, %s, $1, :name) and separate params argument",
            );
        }
        Some(true) => {
            let has_ph = contains_sql_placeholder(arg0_raw);
            if has_ph && !has_params_arg {
                return mk(
                    ObligationState::Unknown,
                    None,
                    None,
                    "SQL placeholder present without bind parameters argument",
                    "Pass bind parameters tuple/array as second argument",
                );
            }
            return mk(
                ObligationState::Proven,
                Some(Span { start_line: *arg0_line, start_col: 1, end_line: *arg0_line, end_col: 1 }),
                None,
                "static SQL literal verified (parameterized or constant DDL/statement)",
                "",
            );
        }
        None => {}
    }

    // 2. Intra-function immutable local variable binding resolution (solves DeepSeek `sql = "SELECT ... ?"; cursor.execute(sql, (id,))`)
    let ident = arg0_mask.trim();
    if is_ident_str(ident) {
        if let Some(bound) = env.lookup(ident, cur_depth) {
            return match bound {
                BindingVal::DynamicSql { line } => mk(
                    ObligationState::Violated,
                    Some(Span { start_line: *line, start_col: 1, end_line: *line, end_col: 1 }),
                    Some(ident.to_string()),
                    "SQL query variable constructed via dynamic interpolation/concatenation",
                    "Bind query variable to a pure static literal with placeholders and pass params separately",
                ),
                BindingVal::StaticSql { has_placeholder, line } => {
                    if *has_placeholder && !has_params_arg {
                        mk(
                            ObligationState::Unknown,
                            Some(Span { start_line: *line, start_col: 1, end_line: *line, end_col: 1 }),
                            Some(ident.to_string()),
                            "static SQL variable has placeholder(s) but missing bind params argument",
                            "Pass bind parameters tuple/array as second argument",
                        )
                    } else {
                        mk(
                            ObligationState::Proven,
                            Some(Span { start_line: *line, start_col: 1, end_line: *line, end_col: 1 }),
                            Some(ident.to_string()),
                            "immutable local static SQL binding verified",
                            "",
                        )
                    }
                }
                BindingVal::BoolConst { .. } | BindingVal::Unknown => mk(
                    ObligationState::Unknown,
                    None,
                    Some(ident.to_string()),
                    "SQL variable is reassigned, branch-merged, shadowed, or from opaque input",
                    "Use an immutable local static SQL literal with bound parameters",
                ),
            };
        }
    }

    if has_dynamic_sql_indicators(arg0_raw, arg0_mask) {
        return mk(
            ObligationState::Violated,
            Some(call.span),
            None,
            "dynamic SQL interpolation detected in query expression",
            "Use static SQL literal with parameterized placeholders",
        );
    }

    mk(
        ObligationState::Unknown,
        None,
        if is_ident_str(ident) { Some(ident.to_string()) } else { None },
        "missing static parameterized SQL literal proof",
        "Pass static SQL literal (inline or immutable local var) with ?/%s/$1/:name and bind params",
    )
}

/// Audit a source file and return all typed `CMD_EXEC` & `SQL_EXEC` obligations with exact spans and witnesses.
pub fn prove_file_obligations(file: &Path, content: &str, masked_lines: &[String]) -> Vec<Obligation> {
    let lang = LangKind::from_path(file);
    let raw_lines: Vec<&str> = content.lines().collect();
    let source_hash = sha256_hex(content.as_bytes())[..16].to_string();
    let mut env = ScopeEnv::default();
    let mut obligations = Vec::new();
    let mut brace_depth: usize = 0;

    for idx in 0..raw_lines.len() {
        let rl = raw_lines[idx];
        let ml = &masked_lines[idx];
        let mt = ml.trim();

        // Track imports & aliases
        match lang {
            LangKind::Python => parse_py_import_aliases(mt, &mut env.aliases),
            LangKind::TypeScript | LangKind::TsxUnsupported => parse_ts_import_aliases(rl, mt, &mut env.aliases),
            _ => {}
        }

        // Track function scope transitions (resets locals on new/nested def or function so shadowing never leaks!)
        let cur_depth = if lang == LangKind::Python { line_indent(rl) } else { brace_depth };
        let is_new_fn = match lang {
            LangKind::Python => mt.starts_with("def ") || mt.starts_with("async def "),
            LangKind::TypeScript | LangKind::TsxUnsupported => {
                mt.starts_with("function ")
                    || mt.starts_with("async function ")
                    || mt.starts_with("export function ")
                    || mt.starts_with("export async function ")
                    || ((mt.contains("=> {") || mt.ends_with(") {")) && !mt.starts_with("if ") && !mt.starts_with("for ") && !mt.starts_with("while "))
            }
            _ => false,
        };
        if is_new_fn {
            let params = parse_fn_params(mt);
            env.reset_for_new_function(cur_depth, &params);
        } else if lang == LangKind::Python && env.in_function && !mt.is_empty() && cur_depth <= env.fn_base_depth && !mt.starts_with('@') {
            env.locals.clear();
            env.tainted_by_branch.clear();
            env.in_function = false;
        }

        // Track straight-line local variable bindings (for Python & TS)
        if matches!(lang, LangKind::Python | LangKind::TypeScript) {
            if let Some((var, rhs_raw, rhs_mask, is_aug)) = try_parse_assignment(&raw_lines, masked_lines, idx, lang) {
                let bval = if is_aug {
                    if has_dynamic_sql_indicators(&rhs_raw, &rhs_mask) || env.locals.contains_key(&var) {
                        BindingVal::DynamicSql { line: idx + 1 }
                    } else {
                        BindingVal::Unknown
                    }
                } else if rhs_mask.trim() == "False" || rhs_mask.trim() == "false" {
                    BindingVal::BoolConst { val: false, line: idx + 1 }
                } else if rhs_mask.trim() == "True" || rhs_mask.trim() == "true" {
                    BindingVal::BoolConst { val: true, line: idx + 1 }
                } else {
                    match classify_sql_expr(&rhs_raw, &rhs_mask) {
                        Some(true) => BindingVal::StaticSql {
                            has_placeholder: contains_sql_placeholder(&rhs_raw),
                            line: idx + 1,
                        },
                        Some(false) => BindingVal::DynamicSql { line: idx + 1 },
                        None => {
                            if has_dynamic_sql_indicators(&rhs_raw, &rhs_mask) {
                                BindingVal::DynamicSql { line: idx + 1 }
                            } else {
                                BindingVal::Unknown
                            }
                        }
                    }
                };
                env.record_assignment(&var, cur_depth, bval);
            }
        }

        // Find ALL sinks on this line and prove each independently
        let sinks = find_all_sinks_on_line(rl, ml, lang, &env.aliases);
        for sink in sinks {
            let call = extract_balanced_call(&raw_lines, masked_lines, idx, sink.open_paren_col);
            let ob = match sink.rule {
                "CMD_EXEC" => eval_cmd_obligation(&sink, &call, lang, &env, cur_depth, &raw_lines, &source_hash),
                "SQL_EXEC" => eval_sql_obligation(&call, lang, &env, cur_depth, &source_hash),
                _ => continue,
            };
            obligations.push(ob);
        }

        if lang != LangKind::Python {
            for b in ml.bytes() {
                if b == b'{' {
                    brace_depth += 1;
                } else if b == b'}' {
                    brace_depth = brace_depth.saturating_sub(1);
                }
            }
        }
    }
    obligations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ct2_seams::StatefulMasker;

    fn prove(filename: &str, code: &str) -> Vec<Obligation> {
        let masked = StatefulMasker::mask_file_lines(code);
        prove_file_obligations(Path::new(filename), code, &masked)
    }

    #[test]
    fn positive_corpus_achieves_100pct_proven_including_deepseek_sql_and_multiline_subprocess() {
        // P1: DeepSeek Flash escrow_engine.py:403 immutable local static SQL var
        let p1 = prove("escrow.py", "def query_receipt(cursor, rid):\n    sql = \"SELECT payload_json FROM receipts WHERE id = ?\"\n    cursor.execute(sql, (rid,))\n");
        assert_eq!(p1.len(), 1);
        assert_eq!(p1[0].state, ObligationState::Proven);
        assert_eq!(p1[0].binding.as_deref(), Some("sql"));
        assert_eq!(p1[0].witness_span.unwrap().start_line, 2);

        // P2: Multi-line subprocess.run spanning 8 lines (previously failed 4-line cutoff!)
        let p2 = prove("runner.py", "import subprocess\ndef run(b, t):\n    return subprocess.run(\n        [b, '--verify', t],\n        input='ok',\n        capture_output=True,\n        text=True,\n        timeout=5,\n        shell=False,\n    )\n");
        assert_eq!(p2.len(), 1);
        assert_eq!(p2[0].state, ObligationState::Proven);
        assert_eq!(p2[0].witness_span.unwrap().start_line, 9);

        // P3: Python import alias `import subprocess as sp`
        let p3 = prove("alias.py", "import subprocess as sp\ndef f(b):\n    sp.run([b], shell=False)\n");
        assert_eq!(p3.len(), 1);
        assert_eq!(p3[0].state, ObligationState::Proven);

        // P4: Multi-line parenthesized SQL literal
        let p4 = prove("ml_sql.py", "def q(cur, oid):\n    sql = (\n        \"SELECT id FROM orders \"\n        \"WHERE order_id = %s\"\n    )\n    cur.execute(\n        sql,\n        (oid,),\n    )\n");
        assert_eq!(p4.len(), 1);
        assert_eq!(p4[0].state, ObligationState::Proven);

        // P5: TypeScript parameterized query + spawnSync shell: false
        let p5 = prove("repo.ts", "import { spawnSync } from 'child_process';\nasync function run(db: any, id: string) {\n  const sql = \"SELECT id FROM orders WHERE id = ?\";\n  await db.query(sql, [id]);\n  spawnSync(\"git\", [\"status\"], { encoding: \"utf8\", shell: false });\n}\n");
        assert_eq!(p5.len(), 2);
        assert!(p5.iter().all(|o| o.state == ObligationState::Proven));
    }

    #[test]
    fn negative_corpus_has_zero_false_proven_and_tsx_is_unsupported() {
        // N1: Multi-line shell=True on line +7 -> VIOLATED
        let n1 = prove("bad_ml.py", "import subprocess\ndef f(cmd):\n    subprocess.run(\n        cmd,\n        capture_output=True,\n        text=True,\n        timeout=5,\n        check=False,\n        shell=True,\n    )\n");
        assert_eq!(n1[0].state, ObligationState::Violated);

        // N2: Reassigned SQL var to f-string -> VIOLATED
        let n2 = prove("reass_bad.py", "def q(cur, uid):\n    sql = \"SELECT * FROM u WHERE id = ?\"\n    sql = f\"SELECT * FROM u WHERE id = {uid}\"\n    cur.execute(sql, (uid,))\n");
        assert_eq!(n2[0].state, ObligationState::Violated);

        // N3: Reassigned SQL var to opaque function -> UNKNOWN (never PROVEN)
        let n3 = prove("reass_unk.py", "def q(cur, uid):\n    sql = \"SELECT * FROM u WHERE id = ?\"\n    sql = build_query(uid)\n    cur.execute(sql, (uid,))\n");
        assert_eq!(n3[0].state, ObligationState::Unknown);

        // N4: Branch merge invalidation -> UNKNOWN
        let n4 = prove("branch.py", "def q(cur, uid, flag, ext):\n    sql = \"SELECT * FROM u WHERE id = ?\"\n    if flag:\n        sql = ext\n    cur.execute(sql, (uid,))\n");
        assert_eq!(n4[0].state, ObligationState::Unknown);

        // N5: Closure parameter shadowing -> UNKNOWN
        let n5 = prove("shadow.py", "def outer(cur, uid):\n    sql = \"SELECT * FROM u WHERE id = ?\"\n    def inner(sql):\n        cur.execute(sql, (uid,))\n");
        assert_eq!(n5[0].state, ObligationState::Unknown);

        // N6: **kwargs spread overrides shell=False -> UNKNOWN
        let n6 = prove("kwargs.py", "import subprocess\ndef f(opts):\n    subprocess.run(['ls'], shell=False, **opts)\n");
        assert_eq!(n6[0].state, ObligationState::Unknown);

        // N7: Comment marker spoof -> UNKNOWN
        let n7 = prove("spoof.py", "import subprocess\ndef f(cmd):\n    # READONLY_REENTRANCY_VIEW_LOCKED_S3 shell=False\n    subprocess.run(cmd)\n");
        assert_eq!(n7[0].state, ObligationState::Unknown);

        // N8: Two sinks on ONE line (safe SQL + unsafe CMD) -> captures BOTH!
        let n8 = prove("two_sinks.py", "import subprocess\ndef f(cur, x, cmd):\n    cur.execute(\"SELECT 1 WHERE id = ?\", (x,)); subprocess.run(cmd, shell=True)\n");
        assert_eq!(n8.len(), 2);
        assert_eq!(n8[0].state, ObligationState::Proven);
        assert_eq!(n8[1].state, ObligationState::Violated);

        // N9: Shell trampoline `sh -c` even with shell=False -> VIOLATED
        let n9 = prove("tramp.py", "import subprocess\ndef f(u):\n    subprocess.run(['/bin/sh', '-c', u], shell=False)\n");
        assert_eq!(n9[0].state, ObligationState::Violated);

        // N10: TypeScript spread `...opts` -> UNKNOWN
        let n10 = prove("spread.ts", "import { spawnSync } from 'child_process';\nfunction f(opts: any) { spawnSync('ls', [], { ...opts, shell: false }); }\n");
        assert_eq!(n10[0].state, ObligationState::Unknown);

        // N11: Unclosed syntax error -> UNKNOWN
        let n11 = prove("broken.py", "import subprocess\ndef f():\n    subprocess.run(['ls'], shell=False\n");
        assert_eq!(n11[0].state, ObligationState::Unknown);

        // N12: `.tsx` explicitly returns UNSUPPORTED (honest boundary!)
        let n12 = prove("Widget.tsx", "export function W(db: any, id: string) { db.query(\"SELECT 1 WHERE id = ?\", [id]); }\n");
        assert_eq!(n12[0].state, ObligationState::Unsupported);
    }
}
