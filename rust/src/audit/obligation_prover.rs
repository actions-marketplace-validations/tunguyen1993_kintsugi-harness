//! Kintsugi v3.0 Typed Obligation Prover (`rust/src/audit/obligation_prover.rs`).
//!
//! Zero-dependency syntactic call-span extractor + intra-function straight-line scope/alias
//! binding resolver producing honest four-way obligations:
//!   `PROVEN | VIOLATED | UNKNOWN | UNSUPPORTED`
//!
//! Covers Python (`.py`/`.pyi`) and TypeScript/JavaScript (`.ts`/`.js`/`.mjs`/`.cjs`) for
//! `CMD_EXEC` and `SQL_EXEC` (plus Rust `Command::new`), while explicitly returning `UNSUPPORTED`
//! for `.tsx`/`.jsx` `CMD_EXEC`/`SQL_EXEC` and delegating extended obligations (`TSX_XSS`,
//! `PATH_CONFINE`, `CRYPTO_MAC_BIDI`, `SOL_REENTRANCY_CEI`, `SOL_SAFE_ERC20`) to
//! `prover_extensions`. Never uses lexical fallback or comment markers to promote `UNKNOWN` to `PROVEN`.

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
        let mut lim = m_bytes.len().min(r_bytes.len());
        while lim > 0 && (!rl.is_char_boundary(lim) || !ml.is_char_boundary(lim)) {
            lim -= 1;
        }
        if li > start_line {
            raw_buf.push('\n');
            mask_buf.push('\n');
        }
        let mut bi = start_c;
        while bi < lim && (!rl.is_char_boundary(bi) || !ml.is_char_boundary(bi)) {
            bi += 1;
        }
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
                let r_step = rl[bi..].chars().next().map_or(1, char::len_utf8);
                let next_bi = (bi + r_step).min(lim);
                if rl.is_char_boundary(next_bi) && ml.is_char_boundary(next_bi) {
                    if depth >= 1 {
                        raw_buf.push_str(&rl[bi..next_bi]);
                        mask_buf.push_str(&ml[bi..next_bi]);
                    }
                    bi = next_bi;
                } else {
                    let mut sync = (bi + 1).min(lim);
                    while sync < lim && (!rl.is_char_boundary(sync) || !ml.is_char_boundary(sync)) {
                        sync += 1;
                    }
                    if depth >= 1 && rl.is_char_boundary(sync) && ml.is_char_boundary(sync) {
                        raw_buf.push_str(&rl[bi..sync]);
                        mask_buf.push_str(&ml[bi..sync]);
                    }
                    bi = sync;
                }
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
    let mut n = rb.len().min(mb.len());
    while n > 0 && (!raw.is_char_boundary(n) || !masked.is_char_boundary(n)) {
        n -= 1;
    }
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
            b',' if depth_p == 0 && depth_b == 0 && depth_c == 0
                && raw.is_char_boundary(seg_start)
                && raw.is_char_boundary(i)
                && masked.is_char_boundary(seg_start)
                && masked.is_char_boundary(i) =>
            {
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
    if seg_start < n
        && raw.is_char_boundary(seg_start)
        && raw.is_char_boundary(n)
        && masked.is_char_boundary(seg_start)
        && masked.is_char_boundary(n)
    {
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
    let ml_line = masked_lines[idx].as_str();
    let rl_line = raw_lines[idx];
    let ml = ml_line.trim();
    let rl = rl_line.trim();
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
        if let Some(abs_pos) = ml_line.find(aug) {
            let lhs = ml_line[..abs_pos].trim();
            if is_ident_str(lhs) {
                let raw_rhs = rl_line
                    .get(abs_pos + 2..)
                    .or_else(|| rl.find(aug).and_then(|p| rl.get(p + 2..)))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let mask_rhs = ml_line.get(abs_pos + 2..).unwrap_or("").trim().to_string();
                return Some((lhs.to_string(), raw_rhs, mask_rhs, true));
            }
        }
    }

    let (lhs_raw, eq_col_abs) = if lang == LangKind::TypeScript {
        let stripped = ml.strip_prefix("const ").or_else(|| ml.strip_prefix("let ")).or_else(|| ml.strip_prefix("var "))?;
        let eq_rel = stripped.find('=')?;
        if stripped.as_bytes().get(eq_rel + 1) == Some(&b'=') || stripped.as_bytes().get(eq_rel + 1) == Some(&b'>') {
            return None;
        }
        let lhs = stripped[..eq_rel].split(':').next()?.trim();
        let eq_abs = ml_line.find('=')?;
        (lhs, eq_abs)
    } else {
        // Python: `name = expr` or `name: str = expr` (exclude `==`, `!=`, `<=`, `>=`, keyword args inside calls)
        let eq_pos = ml_line.find('=')?;
        if eq_pos == 0 {
            return None;
        }
        let prev = ml_line.as_bytes()[eq_pos - 1];
        let next = ml_line.as_bytes().get(eq_pos + 1).copied().unwrap_or(b' ');
        if matches!(prev, b'!' | b'<' | b'>' | b'=') || next == b'=' {
            return None;
        }
        let lhs_part = ml_line[..eq_pos].trim();
        if lhs_part.contains('(') || lhs_part.contains(',') || lhs_part.contains('.') || lhs_part.contains('[') {
            return None;
        }
        let lhs = lhs_part.split(':').next()?.trim();
        (lhs, eq_pos)
    };

    if !is_ident_str(lhs_raw) {
        return None;
    }
    let mut rhs_raw = rl_line
        .get(eq_col_abs + 1..)
        .or_else(|| rl.find('=').and_then(|p| rl.get(p + 1..)))?
        .trim()
        .to_string();
    let mut rhs_mask = ml_line.get(eq_col_abs + 1..)?.trim().to_string();

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

    // Shell trampoline check (`sh`/`/bin/sh`/`bash`/`zsh`/`cmd`/`powershell` + `-c`/`/c`)
    let raw_lo = raw_all.to_ascii_lowercase();
    let invokes_shell_bin = [
        "\"sh\"", "'sh'", "`sh`",
        "\"/bin/sh\"", "'/bin/sh'", "`/bin/sh`",
        "\"bash\"", "'bash'", "`bash`",
        "\"/bin/bash\"", "'/bin/bash'", "`/bin/bash`",
        "\"zsh\"", "'zsh'", "`zsh`",
        "\"/bin/zsh\"", "'/bin/zsh'", "`/bin/zsh`",
        "\"cmd\"", "'cmd'", "`cmd`",
        "\"cmd.exe\"", "'cmd.exe'", "`cmd.exe`",
        "\"powershell\"", "'powershell'", "`powershell`",
        "\"powershell.exe\"", "'powershell.exe'", "`powershell.exe`",
        "\"pwsh\"", "'pwsh'", "`pwsh`",
    ]
    .iter()
    .any(|s| raw_lo.contains(s));
    let has_shell_flag = [
        "\"-c\"", "'-c'", "`-c`",
        "\"/c\"", "'/c'", "`/c`",
        "\"-command\"", "'-command'", "`-command`",
    ]
    .iter()
    .any(|f| raw_lo.contains(f));
    if invokes_shell_bin && has_shell_flag {
        return mk(
            ObligationState::Violated,
            Some(call.span),
            None,
            "child_process argv invokes shell -c / /c trampoline",
            "Invoke target binary directly without sh/bash/zsh/cmd/powershell trampoline",
        );
    }

    if matches!(
        sink.callee.as_str(),
        "execFile" | "execFileSync" | "child_process.execFile" | "child_process.execFileSync"
    ) {
        let arg_count = call.arg_line_offsets.len();
        if arg_count == 0 {
            return mk(
                ObligationState::Unknown,
                None,
                None,
                "empty execFile/execFileSync call lacks verifiable command arguments",
                "Pass command binary and argv array or explicit { shell: false }",
            );
        }
        // If 3-arg call is `execFile(file, { shell: true }, cb)`, arg1 itself can be an unsafe options literal.
        if arg_count == 3 && parse_ts_options_object(&call.arg_line_offsets[1].1) == TsShellOptionState::Violated {
            return mk(
                ObligationState::Violated,
                Some(call.span),
                None,
                "explicit shell: true or shell path in child_process options",
                "Pass { shell: false } and argv array",
            );
        }
        if arg_count == 1 {
            if mask_all.contains("...") {
                return mk(
                    ObligationState::Unknown,
                    None,
                    None,
                    "object spread (...opts) can override shell: false at runtime",
                    "Pass explicit options object { shell: false } without untrusted spread",
                );
            }
            return mk(
                ObligationState::Proven,
                Some(call.span),
                None,
                "execFile/execFileSync default shell=false verified",
                "",
            );
        }
        if arg_count == 2 {
            let r1 = call.arg_line_offsets[1].1.as_str();
            let m1 = call.arg_line_offsets[1].2.trim();
            return match parse_ts_options_object(r1) {
                TsShellOptionState::Violated => mk(
                    ObligationState::Violated,
                    Some(call.span),
                    None,
                    "explicit shell: true or shell path in child_process options",
                    "Pass { shell: false } and argv array",
                ),
                TsShellOptionState::Unknown => mk(
                    ObligationState::Unknown,
                    None,
                    None,
                    "dynamic, shorthand, getter, computed, or spread shell option in child_process options",
                    "Pass literal { shell: false } explicitly",
                ),
                TsShellOptionState::SafeExplicitFalse => {
                    if mask_all.contains("...") {
                        mk(
                            ObligationState::Unknown,
                            None,
                            None,
                            "object spread (...opts) can override shell: false at runtime",
                            "Pass explicit options object { shell: false } without untrusted spread",
                        )
                    } else {
                        mk(
                            ObligationState::Proven,
                            Some(call.span),
                            None,
                            "explicit { shell: false } verified",
                            "",
                        )
                    }
                }
                TsShellOptionState::SafeDefault => {
                    if mask_all.contains("...") {
                        mk(
                            ObligationState::Unknown,
                            None,
                            None,
                            "object spread (...opts) can override shell: false at runtime",
                            "Pass explicit options object { shell: false } without untrusted spread",
                        )
                    } else {
                        mk(
                            ObligationState::Proven,
                            Some(call.span),
                            None,
                            "execFile/execFileSync default shell=false verified",
                            "",
                        )
                    }
                }
                TsShellOptionState::NotAnObjectLiteral => {
                    if !mask_all.contains("...") && is_single_balanced_delim(m1, b'[', b']') {
                        mk(
                            ObligationState::Proven,
                            Some(call.span),
                            None,
                            "execFile/execFileSync default shell=false verified",
                            "",
                        )
                    } else {
                        mk(
                            ObligationState::Unknown,
                            None,
                            None,
                            "opaque 2nd argument on execFile/execFileSync may be an options object enabling shell: true",
                            "Pass inline argv array [...] or inline options object literal with explicit { shell: false }",
                        )
                    }
                }
            };
        }
        // arg_count >= 3: inspect ONLY the 3rd argument (index 2) as the options object literal (never arg1 or 4th-arg callback).
        let r_opt = call.arg_line_offsets[2].1.as_str();
        return match parse_ts_options_object(r_opt) {
            TsShellOptionState::Violated => mk(
                ObligationState::Violated,
                Some(call.span),
                None,
                "explicit shell: true or shell path in child_process options",
                "Pass { shell: false } and argv array",
            ),
            TsShellOptionState::Unknown => mk(
                ObligationState::Unknown,
                None,
                None,
                "dynamic, shorthand, getter, computed, or spread shell option in child_process options",
                "Pass literal { shell: false } explicitly",
            ),
            TsShellOptionState::SafeExplicitFalse => {
                if mask_all.contains("...") {
                    mk(
                        ObligationState::Unknown,
                        None,
                        None,
                        "object spread (...opts) can override shell: false at runtime",
                        "Pass explicit options object { shell: false } without untrusted spread",
                    )
                } else {
                    mk(
                        ObligationState::Proven,
                        Some(call.span),
                        None,
                        "explicit { shell: false } verified",
                        "",
                    )
                }
            }
            TsShellOptionState::SafeDefault => {
                if mask_all.contains("...") {
                    mk(
                        ObligationState::Unknown,
                        None,
                        None,
                        "object spread (...opts) can override shell: false at runtime",
                        "Pass explicit options object { shell: false } without untrusted spread",
                    )
                } else {
                    mk(
                        ObligationState::Proven,
                        Some(call.span),
                        None,
                        "execFile/execFileSync default shell=false verified",
                        "",
                    )
                }
            }
            TsShellOptionState::NotAnObjectLiteral => mk(
                ObligationState::Unknown,
                None,
                None,
                "opaque options argument on execFile/execFileSync may enable shell: true",
                "Pass inline options object literal with explicit { shell: false }",
            ),
        };
    }

    if sink.callee == "authorizeCommand" {
        if mask_all.contains("...") {
            return mk(
                ObligationState::Unknown,
                None,
                None,
                "object spread (...opts) can override shell: false at runtime",
                "Pass explicit options object { shell: false } without untrusted spread",
            );
        }
        let mut saw_bad = false;
        let mut saw_unk = false;
        for (_, ra, _) in &call.arg_line_offsets {
            match parse_ts_options_object(ra) {
                TsShellOptionState::Violated => saw_bad = true,
                TsShellOptionState::Unknown => saw_unk = true,
                _ => {}
            }
        }
        if saw_bad {
            return mk(
                ObligationState::Violated,
                Some(call.span),
                None,
                "explicit shell: true or shell path in child_process options",
                "Pass { shell: false } and argv array",
            );
        }
        if !saw_unk && !has_ts_shell_prop(mask_all) {
            return mk(
                ObligationState::Proven,
                Some(call.span),
                None,
                "authorizeCommand verified without shell override",
                "",
            );
        }
        return mk(
            ObligationState::Unknown,
            None,
            None,
            "dynamic shell option in authorizeCommand options",
            "Pass literal { shell: false } explicitly",
        );
    }

    // spawn / spawnSync / runProcess / runCommand: inspect ONLY the exact options argument (2nd arg for 2-arg call, 3rd arg for >=3-arg call).
    let opt_raw_opt = match call.arg_line_offsets.len() {
        2 => Some(call.arg_line_offsets[1].1.as_str()),
        n if n >= 3 => Some(call.arg_line_offsets[2].1.as_str()),
        _ => None,
    };
    if let Some(opt_raw) = opt_raw_opt {
        return match parse_ts_options_object(opt_raw) {
            TsShellOptionState::Violated => mk(
                ObligationState::Violated,
                Some(call.span),
                None,
                "explicit shell: true or shell path in child_process options",
                "Pass { shell: false } and argv array",
            ),
            TsShellOptionState::SafeExplicitFalse => {
                if mask_all.contains("...") {
                    mk(
                        ObligationState::Unknown,
                        None,
                        None,
                        "object spread (...opts) can override shell: false at runtime",
                        "Pass explicit options object { shell: false } without untrusted spread",
                    )
                } else {
                    mk(
                        ObligationState::Proven,
                        Some(call.span),
                        None,
                        "explicit { shell: false } verified",
                        "",
                    )
                }
            }
            TsShellOptionState::Unknown => mk(
                ObligationState::Unknown,
                None,
                None,
                "dynamic, shorthand, getter, computed, or spread shell option in child_process options",
                "Pass literal { shell: false } explicitly",
            ),
            TsShellOptionState::SafeDefault | TsShellOptionState::NotAnObjectLiteral => mk(
                ObligationState::Unknown,
                None,
                None,
                "missing explicit shell: false in child_process options",
                "Pass { shell: false } explicitly",
            ),
        };
    }
    mk(
        ObligationState::Unknown,
        None,
        None,
        "missing explicit shell: false in child_process options",
        "Pass { shell: false } explicitly",
    )
}

fn is_single_balanced_delim(s: &str, open: u8, close: u8) -> bool {
    let b = s.as_bytes();
    if b.len() < 2 || b[0] != open || b[b.len() - 1] != close {
        return false;
    }
    let mut depth = 0usize;
    for (i, &ch) in b.iter().enumerate() {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 && i + 1 < b.len() {
                return false;
            }
        }
    }
    depth == 0
}

fn has_ts_shell_prop(mask: &str) -> bool {
    let mb = mask.as_bytes();
    let mut from = 0usize;
    while from < mask.len() {
        let Some(rel) = mask[from..].find("shell") else { break };
        let idx = from + rel;
        let left_ok = idx == 0 || !is_ident_byte(mb[idx - 1]);
        let after = idx + 5;
        let right_ok = after >= mb.len() || !is_ident_byte(mb[after]);
        if left_ok && right_ok && mask[after..].trim_start().starts_with(':') {
            return true;
        }
        from = after;
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsShellOptionState {
    NotAnObjectLiteral,
    SafeDefault,
    SafeExplicitFalse,
    Violated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsShellVal {
    False,
    Violated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsQuotedKey {
    Shell,
    Suspicious,
    OtherSafe,
}

fn skip_ts_ws_and_comments(s: &str, mut i: usize) -> Option<usize> {
    let b = s.as_bytes();
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
        } else if b[i..].starts_with(b"//") {
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            i += 2;
            let mut closed = false;
            while i + 1 < b.len() {
                if b[i] == b'*' && b[i + 1] == b'/' {
                    i += 2;
                    closed = true;
                    break;
                }
                i += 1;
            }
            if !closed {
                return None;
            }
        } else {
            break;
        }
    }
    Some(i)
}

fn advance_ts_string(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    let q = *b.get(start)?;
    if q != b'"' && q != b'\'' {
        return None;
    }
    let mut i = start + 1;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 1 >= b.len() {
                return None;
            }
            let step = s[i + 1..].chars().next().map_or(1, char::len_utf8);
            i += 1 + step;
            continue;
        }
        if b[i] == q {
            return Some(i + 1);
        }
        i += s[i..].chars().next().map_or(1, char::len_utf8);
    }
    None
}

fn advance_ts_template(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    if b.get(start) != Some(&b'`') {
        return None;
    }
    let mut i = start + 1;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 1 >= b.len() {
                return None;
            }
            let step = s[i + 1..].chars().next().map_or(1, char::len_utf8);
            i += 1 + step;
            continue;
        }
        if b[i] == b'`' {
            return Some(i + 1);
        }
        if b[i] == b'$' && b.get(i + 1) == Some(&b'{') {
            let close = scan_ts_balanced(s, i + 1, b'{', b'}')?;
            i = close + 1;
            continue;
        }
        i += s[i..].chars().next().map_or(1, char::len_utf8);
    }
    None
}

fn scan_ts_balanced(s: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let b = s.as_bytes();
    if b.get(start) != Some(&open) {
        return None;
    }
    let mut depth = 0usize;
    let mut i = start;
    while i < b.len() {
        let ch = b[i];
        if ch == b'"' || ch == b'\'' {
            i = advance_ts_string(s, i)?;
        } else if ch == b'`' {
            i = advance_ts_template(s, i)?;
        } else if b[i..].starts_with(b"//") || b[i..].starts_with(b"/*") {
            i = skip_ts_ws_and_comments(s, i)?;
        } else if ch == open {
            depth += 1;
            i += 1;
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(i);
            }
            i += 1;
        } else {
            i += s[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    None
}

fn trim_ts_ws_and_comments(s: &str) -> Option<&str> {
    let start = skip_ts_ws_and_comments(s, 0)?;
    if start >= s.len() {
        return Some("");
    }
    let b = s.as_bytes();
    let mut i = start;
    let mut last_end = start;
    while i < b.len() {
        if b[i].is_ascii_whitespace() || b[i..].starts_with(b"//") || b[i..].starts_with(b"/*") {
            i = skip_ts_ws_and_comments(s, i)?;
        } else if b[i] == b'"' || b[i] == b'\'' {
            i = advance_ts_string(s, i)?;
            last_end = i;
        } else if b[i] == b'`' {
            i = advance_ts_template(s, i)?;
            last_end = i;
        } else {
            i += s[i..].chars().next().map_or(1, char::len_utf8);
            last_end = i;
        }
    }
    Some(&s[start..last_end])
}

fn split_ts_top_level_entries(inner: &str) -> Option<Vec<&str>> {
    let b = inner.as_bytes();
    let mut out = Vec::new();
    let (mut p, mut br, mut c) = (0usize, 0usize, 0usize);
    let mut seg_start = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        let ch = b[i];
        if ch == b'"' || ch == b'\'' {
            i = advance_ts_string(inner, i)?;
        } else if ch == b'`' {
            i = advance_ts_template(inner, i)?;
        } else if b[i..].starts_with(b"//") || b[i..].starts_with(b"/*") {
            i = skip_ts_ws_and_comments(inner, i)?;
        } else {
            match ch {
                b'(' => p += 1,
                b')' => {
                    if p == 0 { return None; }
                    p -= 1;
                }
                b'[' => br += 1,
                b']' => {
                    if br == 0 { return None; }
                    br -= 1;
                }
                b'{' => c += 1,
                b'}' => {
                    if c == 0 { return None; }
                    c -= 1;
                }
                b',' if p == 0 && br == 0 && c == 0 => {
                    out.push(&inner[seg_start..i]);
                    seg_start = i + 1;
                }
                _ => {}
            }
            i += inner[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    if p != 0 || br != 0 || c != 0 {
        return None;
    }
    out.push(&inner[seg_start..]);
    Some(out)
}

fn classify_ts_quoted_key(lit: &str) -> TsQuotedKey {
    if lit.len() < 2 || lit.contains('\\') {
        return TsQuotedKey::Suspicious;
    }
    if lit.starts_with('`') && lit.contains("${") {
        return TsQuotedKey::Suspicious;
    }
    match &lit[1..lit.len() - 1] {
        "shell" => TsQuotedKey::Shell,
        "__proto__" => TsQuotedKey::Suspicious,
        _ => TsQuotedKey::OtherSafe,
    }
}

fn classify_ts_shell_value(raw_val: &str) -> TsShellVal {
    let Some(v) = trim_ts_ws_and_comments(raw_val) else {
        return TsShellVal::Unknown;
    };
    if v == "false" {
        TsShellVal::False
    } else if v == "true" {
        TsShellVal::Violated
    } else if v.starts_with('"') || v.starts_with('\'') {
        let Some(end) = advance_ts_string(v, 0) else {
            return TsShellVal::Unknown;
        };
        if end == v.len() || v[end..].trim_start().starts_with('+') {
            TsShellVal::Violated
        } else {
            TsShellVal::Unknown
        }
    } else if v.starts_with('`') {
        let Some(end) = advance_ts_template(v, 0) else {
            return TsShellVal::Unknown;
        };
        if end == v.len() || v[end..].trim_start().starts_with('+') {
            TsShellVal::Violated
        } else {
            TsShellVal::Unknown
        }
    } else {
        TsShellVal::Unknown
    }
}

fn parse_ts_options_object(raw_opt: &str) -> TsShellOptionState {
    let Some(start) = skip_ts_ws_and_comments(raw_opt, 0) else {
        return TsShellOptionState::Unknown;
    };
    if raw_opt.as_bytes().get(start) != Some(&b'{') {
        return TsShellOptionState::NotAnObjectLiteral;
    }
    let Some(close) = scan_ts_balanced(raw_opt, start, b'{', b'}') else {
        return TsShellOptionState::Unknown;
    };
    let Some(after) = skip_ts_ws_and_comments(raw_opt, close + 1) else {
        return TsShellOptionState::Unknown;
    };
    if after != raw_opt.len() {
        return TsShellOptionState::NotAnObjectLiteral;
    }
    let inner = &raw_opt[start + 1..close];
    let Some(entries) = split_ts_top_level_entries(inner) else {
        return TsShellOptionState::Unknown;
    };

    let mut saw_violated = false;
    let mut saw_unknown = false;
    let mut saw_explicit_false = false;

    for entry in entries {
        let Some(e_trimmed) = trim_ts_ws_and_comments(entry) else {
            saw_unknown = true;
            continue;
        };
        if e_trimmed.is_empty() {
            continue;
        }
        if e_trimmed.starts_with("...") {
            saw_unknown = true;
            continue;
        }
        if e_trimmed.starts_with('[') {
            let Some(close_br) = scan_ts_balanced(e_trimmed, 0, b'[', b']') else {
                saw_unknown = true;
                continue;
            };
            let Some(key_expr) = trim_ts_ws_and_comments(&e_trimmed[1..close_br]) else {
                saw_unknown = true;
                continue;
            };
            let Some(after_idx) = skip_ts_ws_and_comments(e_trimmed, close_br + 1) else {
                saw_unknown = true;
                continue;
            };
            let after_br = &e_trimmed[after_idx..];
            let is_single_quote_lit = (key_expr.starts_with('"') || key_expr.starts_with('\''))
                && advance_ts_string(key_expr, 0) == Some(key_expr.len());
            let is_single_tpl_lit = key_expr.starts_with('`')
                && advance_ts_template(key_expr, 0) == Some(key_expr.len());
            if is_single_quote_lit || is_single_tpl_lit {
                match classify_ts_quoted_key(key_expr) {
                    TsQuotedKey::Shell => {
                        if let Some(val_raw) = after_br.strip_prefix(':') {
                            match classify_ts_shell_value(val_raw) {
                                TsShellVal::Violated => saw_violated = true,
                                TsShellVal::False => saw_explicit_false = true,
                                TsShellVal::Unknown => saw_unknown = true,
                            }
                        } else {
                            saw_unknown = true;
                        }
                    }
                    TsQuotedKey::Suspicious => saw_unknown = true,
                    TsQuotedKey::OtherSafe => {}
                }
            } else {
                saw_unknown = true;
            }
            continue;
        }
        if e_trimmed.starts_with('"') || e_trimmed.starts_with('\'') {
            let Some(q_end) = advance_ts_string(e_trimmed, 0) else {
                saw_unknown = true;
                continue;
            };
            let key_lit = &e_trimmed[..q_end];
            let Some(after_idx) = skip_ts_ws_and_comments(e_trimmed, q_end) else {
                saw_unknown = true;
                continue;
            };
            let after_q = &e_trimmed[after_idx..];
            match classify_ts_quoted_key(key_lit) {
                TsQuotedKey::Shell => {
                    if let Some(val_raw) = after_q.strip_prefix(':') {
                        match classify_ts_shell_value(val_raw) {
                            TsShellVal::Violated => saw_violated = true,
                            TsShellVal::False => saw_explicit_false = true,
                            TsShellVal::Unknown => saw_unknown = true,
                        }
                    } else {
                        saw_unknown = true;
                    }
                }
                TsQuotedKey::Suspicious => saw_unknown = true,
                TsQuotedKey::OtherSafe => {}
            }
            continue;
        }
        // Generator method shorthand `*shell() {}` / `*"shell"() {}` / `*'shell'() {}` / `*[k]() {}` / `*__proto__() {}`
        if let Some(after_star_raw) = e_trimmed.strip_prefix('*') {
            let Some(ns) = skip_ts_ws_and_comments(after_star_raw, 0) else {
                saw_unknown = true;
                continue;
            };
            let after_star = &after_star_raw[ns..];
            if after_star.starts_with('[') {
                saw_unknown = true;
            } else if after_star.starts_with('"') || after_star.starts_with('\'') {
                let Some(q_end) = advance_ts_string(after_star, 0) else {
                    saw_unknown = true;
                    continue;
                };
                if !matches!(classify_ts_quoted_key(&after_star[..q_end]), TsQuotedKey::OtherSafe) {
                    saw_unknown = true;
                }
            } else {
                let ab = after_star.as_bytes();
                let mut ae = 0usize;
                while ae < ab.len() && is_ident_byte(ab[ae]) {
                    ae += 1;
                }
                let gname = &after_star[..ae];
                if gname == "shell" || gname == "__proto__" || gname.is_empty() {
                    saw_unknown = true;
                }
            }
            continue;
        }
        // Static identifier, shorthand property, getter/setter, or method
        let eb = e_trimmed.as_bytes();
        let mut id_end = 0usize;
        while id_end < eb.len() && is_ident_byte(eb[id_end]) {
            id_end += 1;
        }
        if id_end == 0 {
            saw_unknown = true;
            continue;
        }
        let first_id = &e_trimmed[..id_end];
        let Some(after_idx) = skip_ts_ws_and_comments(e_trimmed, id_end) else {
            saw_unknown = true;
            continue;
        };
        let rest = &e_trimmed[after_idx..];
        if let Some(val_raw) = rest.strip_prefix(':') {
            if first_id == "shell" {
                match classify_ts_shell_value(val_raw) {
                    TsShellVal::Violated => saw_violated = true,
                    TsShellVal::False => saw_explicit_false = true,
                    TsShellVal::Unknown => saw_unknown = true,
                }
            } else if first_id == "__proto__" {
                saw_unknown = true;
            }
        } else if rest.is_empty() {
            // Shorthand property: `{ shell }` or `{ cwd }`
            if first_id == "shell" || first_id == "__proto__" {
                saw_unknown = true;
            }
        } else if rest.starts_with('(') {
            // Method shorthand: `{ shell() {} }`
            if first_id == "shell" || first_id == "__proto__" {
                saw_unknown = true;
            }
        } else if matches!(first_id, "get" | "set" | "async") {
            let mut prop = rest;
            if first_id == "async" && prop.starts_with('*') {
                let Some(ns) = skip_ts_ws_and_comments(&prop[1..], 0) else {
                    saw_unknown = true;
                    continue;
                };
                prop = &prop[1 + ns..];
            }
            if prop.starts_with('[') {
                saw_unknown = true;
            } else if prop.starts_with('"') || prop.starts_with('\'') {
                let Some(q_end) = advance_ts_string(prop, 0) else {
                    saw_unknown = true;
                    continue;
                };
                if !matches!(classify_ts_quoted_key(&prop[..q_end]), TsQuotedKey::OtherSafe) {
                    saw_unknown = true;
                }
            } else {
                let pb = prop.as_bytes();
                let mut pe = 0usize;
                while pe < pb.len() && is_ident_byte(pb[pe]) {
                    pe += 1;
                }
                let pname = &prop[..pe];
                if pname == "shell" || pname == "__proto__" || pname.is_empty() {
                    saw_unknown = true;
                }
            }
        } else {
            saw_unknown = true;
        }
    }

    if saw_violated {
        TsShellOptionState::Violated
    } else if saw_unknown {
        TsShellOptionState::Unknown
    } else if saw_explicit_false {
        TsShellOptionState::SafeExplicitFalse
    } else {
        TsShellOptionState::SafeDefault
    }
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
    obligations.extend(crate::audit::prover_extensions::prove_extended_obligations(
        file,
        &raw_lines,
        masked_lines,
        &source_hash,
    ));
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

    #[test]
    fn ts_cmd_exec_trampoline_opaque_opts_and_utf8_sql_regression() {
        // PoC #13a: TS shell trampoline `spawnSync('/bin/sh', ['-c', userCmd], { shell: false })` -> VIOLATED
        let t1 = prove("tramp.ts", "import { spawnSync } from 'child_process';\nfunction run(userCmd: string) {\n  spawnSync('/bin/sh', ['-c', userCmd], { shell: false });\n}\n");
        assert_eq!((t1.len(), t1[0].rule, t1[0].state), (1, "CMD_EXEC", ObligationState::Violated));

        // PoC #13a2: Windows cmd /c and powershell -c trampoline -> VIOLATED
        let t1b = prove("tramp_win.ts", "import { execFileSync } from 'child_process';\nfunction run(u: string) {\n  execFileSync('cmd', ['/c', u]);\n}\n");
        assert_eq!(t1b[0].state, ObligationState::Violated);

        // PoC #13b: Opaque `opts` on `execFileSync('ls', [userArg], opts)` -> UNKNOWN (NEVER PROVEN!)
        let t2 = prove("opaque_opts.ts", "import { execFileSync } from 'child_process';\nfunction run(userArg: string) {\n  const opts = { shell: true };\n  execFileSync('ls', [userArg], opts);\n}\n");
        assert_eq!((t2.len(), t2[0].rule, t2[0].state), (1, "CMD_EXEC", ObligationState::Unknown));

        // Positive: `execFileSync` with <= 2 args OR inline `{ encoding: 'utf8' }` without spread/shell -> PROVEN
        let t3 = prove("safe_ef.ts", "import { execFileSync } from 'child_process';\nfunction run(userArg: string) {\n  execFileSync('ls', [userArg]);\n  execFileSync('ls', [userArg], { encoding: 'utf8' });\n}\n");
        assert_eq!(t3.len(), 2);
        assert!(t3.iter().all(|o| o.rule == "CMD_EXEC" && o.state == ObligationState::Proven));

        // PoC #2: Multi-byte UTF-8 (2-byte `café` and 4-byte `🚀`) in `extract_balanced_call` & `try_parse_assignment`
        let u1 = prove("utf8_sql.py", "def q(cur, uid):\n    cur.execute(\"SELECT 'café 🚀' FROM u WHERE id = ?\", (uid,))\n");
        assert_eq!((u1.len(), u1[0].rule, u1[0].state), (1, "SQL_EXEC", ObligationState::Proven));

        let u2 = prove("utf8_aug.ts", "function f(db: any, id: string) {\n  /* 🚀🚀🚀 */ let sql = \"SELECT 'café' FROM u WHERE id = ?\";\n  db.query(sql, [id]);\n}\n");
        assert_eq!((u2.len(), u2[0].rule, u2[0].state), (1, "SQL_EXEC", ObligationState::Proven));

        // PoC #13c (HIGH #3): 2-arg `execFileSync("printf", options)` MUST return UNKNOWN (never PROVEN!)
        let o2_unk = prove(
            "two_arg_opts.ts",
            "import { execFileSync } from 'child_process';\nfunction run(options: any) {\n  execFileSync(\"printf\", options);\n}\n",
        );
        assert_eq!((o2_unk.len(), o2_unk[0].rule, o2_unk[0].state), (1, "CMD_EXEC", ObligationState::Unknown));

        let o2_expr = prove(
            "two_arg_expr.ts",
            "import { execFileSync } from 'child_process';\nfunction run(argsOrOpts: any) {\n  execFileSync(\"printf\", argsOrOpts);\n  execFileSync(\"printf\", [\"a\"] || argsOrOpts);\n}\n",
        );
        assert_eq!(o2_expr.len(), 2);
        assert!(o2_expr.iter().all(|o| o.rule == "CMD_EXEC" && o.state == ObligationState::Unknown));

        let o2_bad = prove(
            "two_arg_shell_true.ts",
            "import { execFileSync } from 'child_process';\nfunction run() {\n  execFileSync(\"printf\", { shell: true });\n  execFileSync(\"printf\", { shell: \"/bin/sh\" });\n}\n",
        );
        assert_eq!(o2_bad.len(), 2);
        assert!(o2_bad.iter().all(|o| o.rule == "CMD_EXEC" && o.state == ObligationState::Violated));

        // Positive controls: 1-arg, 2-arg inline array, 2-arg inline safe options -> PROVEN
        let o2_ok = prove(
            "two_arg_safe.ts",
            "import { execFileSync } from 'child_process';\nfunction run() {\n  execFileSync(\"ls\");\n  execFileSync(\"printf\", [\"hello\"]);\n  execFileSync(\"printf\", { timeout: 5000 });\n  execFileSync(\"printf\", { timeout: 5000, shell: false });\n}\n",
        );
        assert_eq!(o2_ok.len(), 4);
        assert!(o2_ok.iter().all(|o| o.rule == "CMD_EXEC" && o.state == ObligationState::Proven));
    }

    #[test]
    fn ts_cmd_exec_round2_options_parser_bypasses_and_comments() {
        // Shorthand `{ shell }`, getter `get shell()`, dynamic computed `[keyVar]`, nested/callback/arg1 shell:false spoof -> UNKNOWN (NEVER PROVEN!)
        for (fname, src) in [
            (
                "shorthand2.ts",
                "import { execFileSync } from 'child_process';\nfunction run(shell: boolean) { execFileSync(\"printf\", { shell }); }\n",
            ),
            (
                "shorthand3.ts",
                "import { execFileSync } from 'child_process';\nfunction run(userArg: string, shell: boolean) { execFileSync(\"printf\", [userArg], { shell }); }\n",
            ),
            (
                "getter.ts",
                "import { execFileSync } from 'child_process';\nfunction run() { execFileSync(\"printf\", { get shell() { return true; } }); }\n",
            ),
            (
                "computed_dyn.ts",
                "import { execFileSync } from 'child_process';\nfunction run(userArg: string, keyVar: string) { execFileSync(\"printf\", [userArg], { [keyVar]: true }); }\n",
            ),
            (
                "nested_env_downgrade.ts",
                "import { execFileSync } from 'child_process';\nfunction run(x: string, dynamicFlag: any) { execFileSync(\"printf\", [x], { shell: dynamicFlag, env: { shell: false } }); }\n",
            ),
            (
                "arg1_spoof_spawn.ts",
                "import { spawnSync } from 'child_process';\nfunction run(opaqueOpts: any) { spawnSync(\"printf\", [helper({ shell: false })], opaqueOpts); }\n",
            ),
            (
                "callback_downgrade.ts",
                "import { execFile } from 'child_process';\nfunction run(x: string, dynamicFlag: any) { execFile(\"printf\", [x], { shell: dynamicFlag }, () => ({ shell: false })); }\n",
            ),
            (
                "quoted_gen_dq.ts",
                "import { execFileSync } from 'child_process';\nfunction run() { execFileSync(\"printf\", { *\"shell\"() {} }); }\n",
            ),
            (
                "quoted_gen_sq.ts",
                "import { execFileSync } from 'child_process';\nfunction run(userArg: string) { execFileSync(\"printf\", [userArg], { *'shell'() {} }); }\n",
            ),
            (
                "proto_gen.ts",
                "import { execFileSync } from 'child_process';\nfunction run() { execFileSync(\"printf\", { *__proto__() {} }); }\n",
            ),
        ] {
            let obs = prove(fname, src);
            assert_eq!(obs.len(), 1, "{fname}");
            assert_eq!(obs[0].rule, "CMD_EXEC", "{fname}");
            assert_eq!(obs[0].state, ObligationState::Unknown, "{fname}: must be Unknown, never Proven");
        }

        // Quoted `"shell"` / `'shell'`, static computed `["shell"]`, and block comment before string value -> VIOLATED!
        for (fname, src) in [
            (
                "quoted_dq.ts",
                "import { execFileSync } from 'child_process';\nfunction run() { execFileSync(\"printf\", { \"shell\": true }); }\n",
            ),
            (
                "quoted_sq.ts",
                "import { execFileSync } from 'child_process';\nfunction run(userArg: string) { execFileSync(\"printf\", [userArg], { 'shell': \"/bin/sh\" }); }\n",
            ),
            (
                "computed_lit.ts",
                "import { execFileSync } from 'child_process';\nfunction run(userArg: string) { execFileSync(\"printf\", [userArg], { [\"shell\"]: true }); }\n",
            ),
            (
                "comment_val.ts",
                "import { execFileSync } from 'child_process';\nfunction run() { execFileSync(\"printf\", { shell: /* comment */ \"/bin/sh\" }); }\n",
            ),
        ] {
            let obs = prove(fname, src);
            assert_eq!(obs.len(), 1, "{fname}");
            assert_eq!(obs[0].rule, "CMD_EXEC", "{fname}");
            assert_eq!(obs[0].state, ObligationState::Violated, "{fname}: must be Violated");
        }

        // Valid safe inline `{ shell: false, env: { FOO: "1" } }` -> PROVEN!
        let ok = prove(
            "safe_with_env.ts",
            "import { execFileSync } from 'child_process';\nfunction run(x: string) { execFileSync(\"printf\", [x], { shell: false, env: { FOO: \"1\" } }); }\n",
        );
        assert_eq!((ok.len(), ok[0].rule, ok[0].state), (1, "CMD_EXEC", ObligationState::Proven));
    }
}
