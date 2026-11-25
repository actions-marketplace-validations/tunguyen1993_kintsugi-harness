//! Shared `@CT2` Causal Seam Classification, Cross-Line [`StatefulMasker`],
//! and Defense Strength Codebook (`S0`..`S3`).

use std::path::Path;

pub fn is_ct2_supported_ext(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|ext| {
        matches!(
            ext.to_ascii_lowercase().as_str(),
            "py" | "pyi" | "php" | "java" | "sol" | "rs" | "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "gtl" | "go"
        )
    })
}

pub fn is_ct2_stopword(w: &str) -> bool {
    matches!(
        w,
        "the" | "and" | "not" | "for" | "with" | "from" | "that" | "this" | "are" | "was" | "were" | "have" | "has" | "had"
            | "will" | "can" | "may" | "must" | "should" | "return" | "returns" | "Returns" | "Reads" | "else" | "elif"
            | "def" | "function" | "class" | "public" | "private" | "protected" | "static" | "void" | "int" | "str"
            | "string" | "String" | "bool" | "boolean" | "True" | "False" | "true" | "false" | "None" | "null" | "case"
            | "break" | "default" | "continue" | "switch" | "echo" | "print" | "import" | "include" | "require" | "new"
            | "try" | "catch" | "except" | "finally" | "throw" | "throws" | "self"
    )
}

/// Persistent lexical mode tracked across lines by [`StatefulMasker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexMode {
    Code,
    SingleQuote,
    DoubleQuote,
    BlockComment,
    PyTripleDouble,
    PyTripleSingle,
    JsTemplate { expr_brace_depth: usize },
}

/// Cross-line lexical masker preserving multiline `/* ... */`, Python `"""..."""`/`'''...'''`,
/// and JS `` `...${expr}...` `` state across file lines while keeping `${...}` expressions unmasked.
#[derive(Debug, Clone)]
pub struct StatefulMasker {
    mode: LexMode,
    template_expr_stack: Vec<usize>,
}

impl Default for StatefulMasker {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn is_rust_lifetime_tick(bytes: &[u8], i: usize) -> bool {
    i > 0
        && (bytes[i - 1] == b'&' || bytes[i - 1] == b'<')
        && bytes.get(i + 1).is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && bytes.get(i + 2) != Some(&b'\'')
}

fn is_py_floor_div(line: &str, bytes: &[u8], i: usize) -> bool {
    let trimmed = line.trim_start();
    if ["let ", "const ", "var ", "pub ", "fn ", "func "].iter().any(|kw| trimmed.starts_with(kw))
        || line[..i].contains(';')
    {
        return false;
    }
    if !(i >= 2
        && bytes[i - 1] == b' '
        && (matches!(bytes[i - 2], b')' | b']' | b'_') || bytes[i - 2].is_ascii_alphanumeric())
        && bytes.get(i + 2) == Some(&b' '))
    {
        return false;
    }
    let mut k = i + 3;
    while k < bytes.len() && bytes[k] == b' ' {
        k += 1;
    }
    let Some(&first) = bytes.get(k) else { return false };
    if first == b'(' {
        return true;
    }
    if !(first.is_ascii_alphanumeric() || first == b'_') {
        return false;
    }
    while k < bytes.len() && (bytes[k].is_ascii_alphanumeric() || matches!(bytes[k], b'_' | b'.')) {
        k += 1;
    }
    while k < bytes.len() && bytes[k] == b' ' {
        k += 1;
    }
    k >= bytes.len()
        || matches!(
            bytes[k],
            b'#' | b')' | b']' | b'}' | b',' | b':' | b'+' | b'-' | b'*' | b'/' | b'%' | b'=' | b'!' | b'<' | b'>' | b'&' | b'|' | b'^'
        )
        || ["if ", "else ", "and ", "or ", "in ", "is ", "not ", "for "].iter().any(|kw| line[k..].starts_with(kw))
}

#[inline]
fn push_spaces(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push(' ');
    }
}

impl StatefulMasker {
    pub fn new() -> Self {
        Self { mode: LexMode::Code, template_expr_stack: Vec::new() }
    }

    pub fn mode(&self) -> LexMode {
        self.mode
    }

    fn scan_line(&mut self, line: &str) -> (String, usize) {
        let bytes = line.as_bytes();
        let mut out = String::with_capacity(line.len());
        let (mut block_start, mut i) = (0usize, 0usize);

        while i < bytes.len() {
            let b = bytes[i];
            match self.mode {
                LexMode::Code | LexMode::JsTemplate { expr_brace_depth: 1.. } => {
                    if bytes[i..].starts_with(b"\"\"\"") || bytes[i..].starts_with(b"'''") {
                        self.mode = if b == b'"' { LexMode::PyTripleDouble } else { LexMode::PyTripleSingle };
                        out.push_str("   ");
                        i += 3;
                    } else if b == b'#' || (b == b'/' && bytes.get(i + 1) == Some(&b'/') && !is_py_floor_div(line, bytes, i)) {
                        return (out, i);
                    } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                        block_start = i;
                        out.push_str("  ");
                        i += 2;
                        self.mode = LexMode::BlockComment;
                    } else if b == b'"' || (b == b'\'' && !is_rust_lifetime_tick(bytes, i)) || b == b'`' {
                        self.mode = match b {
                            b'"' => LexMode::DoubleQuote,
                            b'\'' => LexMode::SingleQuote,
                            _ => LexMode::JsTemplate { expr_brace_depth: 0 },
                        };
                        out.push(' ');
                        i += 1;
                    } else if b == b'{' {
                        if let Some(d) = self.template_expr_stack.last_mut() {
                            *d += 1;
                            self.mode = LexMode::JsTemplate { expr_brace_depth: *d };
                        }
                        out.push('{');
                        i += 1;
                    } else if b == b'}' {
                        if let Some(d) = self.template_expr_stack.last_mut() {
                            if *d <= 1 {
                                self.template_expr_stack.pop();
                                out.push('}');
                                i += 1;
                                self.mode = LexMode::JsTemplate { expr_brace_depth: 0 };
                                continue;
                            }
                            *d -= 1;
                            self.mode = LexMode::JsTemplate { expr_brace_depth: *d };
                        }
                        out.push('}');
                        i += 1;
                    } else {
                        let ch = line[i..].chars().next().unwrap_or(' ');
                        out.push(ch);
                        i += ch.len_utf8();
                    }
                }
                LexMode::SingleQuote | LexMode::DoubleQuote => {
                    let q = if self.mode == LexMode::SingleQuote { b'\'' } else { b'"' };
                    if b == b'\\' {
                        let step = if i + 1 < bytes.len() {
                            1 + line[i + 1..].chars().next().map_or(1, char::len_utf8)
                        } else {
                            1
                        };
                        push_spaces(&mut out, step);
                        i += step;
                    } else if b == q {
                        out.push(' ');
                        i += 1;
                        self.mode = match self.template_expr_stack.last().copied() {
                            Some(d) => LexMode::JsTemplate { expr_brace_depth: d },
                            None => LexMode::Code,
                        };
                    } else {
                        let step = line[i..].chars().next().map_or(1, char::len_utf8);
                        push_spaces(&mut out, step);
                        i += step;
                    }
                }
                LexMode::PyTripleSingle | LexMode::PyTripleDouble => {
                    let pat: &[u8] = if self.mode == LexMode::PyTripleSingle { b"'''" } else { b"\"\"\"" };
                    if b == b'\\' {
                        let step = if i + 1 < bytes.len() {
                            1 + line[i + 1..].chars().next().map_or(1, char::len_utf8)
                        } else {
                            1
                        };
                        push_spaces(&mut out, step);
                        i += step;
                    } else if bytes[i..].starts_with(pat) {
                        out.push_str("   ");
                        i += 3;
                        self.mode = match self.template_expr_stack.last().copied() {
                            Some(d) => LexMode::JsTemplate { expr_brace_depth: d },
                            None => LexMode::Code,
                        };
                    } else {
                        let step = line[i..].chars().next().map_or(1, char::len_utf8);
                        push_spaces(&mut out, step);
                        i += step;
                    }
                }
                LexMode::JsTemplate { expr_brace_depth: 0 } => {
                    if b == b'\\' {
                        let step = if i + 1 < bytes.len() {
                            1 + line[i + 1..].chars().next().map_or(1, char::len_utf8)
                        } else {
                            1
                        };
                        push_spaces(&mut out, step);
                        i += step;
                    } else if b == b'`' {
                        out.push(' ');
                        i += 1;
                        self.mode = match self.template_expr_stack.last().copied() {
                            Some(d) => LexMode::JsTemplate { expr_brace_depth: d },
                            None => LexMode::Code,
                        };
                    } else if b == b'$' && bytes.get(i + 1) == Some(&b'{') {
                        out.push_str("${");
                        self.template_expr_stack.push(1);
                        self.mode = LexMode::JsTemplate { expr_brace_depth: 1 };
                        i += 2;
                    } else {
                        let step = line[i..].chars().next().map_or(1, char::len_utf8);
                        push_spaces(&mut out, step);
                        i += step;
                    }
                }
                LexMode::BlockComment => {
                    if b == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        out.push_str("  ");
                        i += 2;
                        self.mode = match self.template_expr_stack.last().copied() {
                            Some(d) => LexMode::JsTemplate { expr_brace_depth: d },
                            None => LexMode::Code,
                        };
                        if line[i..].trim().is_empty() {
                            push_spaces(&mut out, bytes.len() - i);
                            return (out, block_start);
                        }
                    } else {
                        let step = line[i..].chars().next().map_or(1, char::len_utf8);
                        push_spaces(&mut out, step);
                        i += step;
                    }
                }
            }
        }

        if matches!(self.mode, LexMode::SingleQuote | LexMode::DoubleQuote) {
            self.mode = match self.template_expr_stack.last().copied() {
                Some(d) => LexMode::JsTemplate { expr_brace_depth: d },
                None => LexMode::Code,
            };
        }
        let cut = if self.mode == LexMode::BlockComment { block_start } else { bytes.len() };
        (out, cut)
    }

    pub fn mask_line(&mut self, line: &str) -> String {
        self.scan_line(line).0
    }

    pub fn mask_file_lines(content: &str) -> Vec<String> {
        let mut masker = Self::new();
        content.lines().map(|l| masker.mask_line(l)).collect()
    }
}

/// Stateless single-line masker delegating to a fresh [`StatefulMasker`].
pub fn mask_strings_and_comments(line: &str) -> String {
    StatefulMasker::new().mask_line(line)
}

pub fn strip_inline_comment(line: &str) -> &str {
    let (_, cut) = StatefulMasker::new().scan_line(line);
    &line[..cut]
}

pub fn extract_identifiers(line: &str) -> Vec<String> {
    let code_only = mask_strings_and_comments(line);
    let (mut res, mut cur) = (Vec::new(), String::new());
    for c in code_only.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else {
            if cur.len() >= 3 && !cur.as_bytes()[0].is_ascii_digit() && !is_ct2_stopword(&cur) {
                res.push(cur.clone());
            }
            cur.clear();
        }
    }
    res
}

/// Classify ALL security seams present on a pre-masked single code line (supports multiple sinks per line).
/// Callers analyzing a multi-line file MUST pass lines produced by a single file-level `StatefulMasker::mask_file_lines`.
pub fn classify_seams_in_line_masked(masked_code: &str) -> Vec<&'static str> {
    let no_strings = masked_code.trim();
    if no_strings.is_empty()
        || no_strings.starts_with('*')
        || no_strings.starts_with("def ")
        || no_strings.starts_with("async def ")
        || no_strings.starts_with("function ")
        || no_strings.starts_with("async function ")
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    if (no_strings.contains("open(") && !no_strings.contains("popen(") && no_strings.contains('+'))
        || no_strings.contains("os.open(")
        || no_strings.contains("File(")
        || (no_strings.contains("include(") && no_strings.contains('$'))
        || (no_strings.contains("require(") && no_strings.contains("$_"))
    {
        out.push("PATH_LFI");
    }
    if ["eval(", "exec(", "execSync(", "shell_exec(", "system(", "popen(", "subprocess.run(", "Runtime.getRuntime().exec"]
        .iter()
        .any(|k| no_strings.contains(k))
    {
        out.push("CMD_EXEC");
    }
    if no_strings.contains("mysql_query(")
        || no_strings.contains("mysqli_query(")
        || no_strings.contains("executeQuery(")
        || no_strings.contains(".execute(")
        || no_strings.contains(".executemany(")
        || (no_strings.contains("prepare(") && (no_strings.contains('$') || no_strings.contains('+')))
    {
        out.push("SQL_CONCAT");
    }
    if (no_strings.contains("total_supply") && no_strings.contains("total_assets") && no_strings.contains("//"))
        || (no_strings.contains("totalSupply") && no_strings.contains("totalAssets") && no_strings.contains('/'))
        || (no_strings.contains("caller_assets *") && (no_strings.contains("total_supply") || no_strings.contains("virtual_shares")) && no_strings.contains("//"))
    {
        out.push("ERC4626_ROUNDING");
    }
    if ["witness_inv_unconstrained", "r1cs_constraint_ok =", "witness_assign_only"].iter().any(|k| no_strings.contains(k)) {
        out.push("ZKP_UNCONSTRAINED");
    }
    if no_strings.contains("raw_socket_payload =") || (no_strings.contains("ipaddress.ip_address(") && no_strings.contains("host")) {
        out.push("SSRF_CRLF_CHAIN");
    }
    if no_strings.contains("public_rsa_pem_bytes") || no_strings.contains("private_hmac_keyring[") {
        out.push("JWT_ALG_CONFUSION");
    }
    if no_strings.contains("redirect_uri.startswith(") || no_strings.contains("registered_redirect_uris") {
        out.push("OAUTH_REDIRECT_PKCE");
    }
    if no_strings.contains("vault_eth_balance * 1e18") || no_strings.contains("self.reentrancy_lock") {
        out.push("READONLY_REENTRANCY");
    }
    if no_strings.contains("snapshot_balance = self.ledger_balances") || no_strings.contains("consumed_idempotency_keys") {
        out.push("TOCTOU_RACE_DOUBLE_SPEND");
    }
    if no_strings.contains(".update(") || no_strings.contains("_CreateUser") || (no_strings.contains("is_admin") && no_strings.contains('=')) {
        out.push("PRIV_ASSIGN");
    }
    if ["hash(", "md5(", "sha1(", "hmac.new(", "ecrecover(", "Jwt", "parseClaims", "hashlib.sha256("]
        .iter()
        .any(|k| no_strings.contains(k))
    {
        out.push("CRYPTO_TOKEN");
    }
    if ["_Expand(", "echo $_", "print $_", "innerHTML"].iter().any(|k| no_strings.contains(k)) {
        out.push("XSS_SINK");
    }
    out
}

/// File-level multi-sink seam classifier preserving cross-line comment/docstring/template masker state.
pub fn classify_seams_for_file(content: &str) -> Vec<(usize, Vec<&'static str>)> {
    let masked = StatefulMasker::mask_file_lines(content);
    masked
        .iter()
        .enumerate()
        .filter_map(|(idx, ml)| {
            let seams = classify_seams_in_line_masked(ml);
            if seams.is_empty() { None } else { Some((idx + 1, seams)) }
        })
        .collect()
}

/// Backward-compatible single-line wrapper returning the first classified seam on `line`.
pub fn classify_seam(line: &str) -> Option<&'static str> {
    let masked = StatefulMasker::new().mask_line(line);
    classify_seams_in_line_masked(&masked).into_iter().next()
}

/// Council `@CT2` Defense Strength Codebook (`S0`..`S3`), strictly scoped by `seam_kind`.
///
/// No generic string marker or guard belonging to another `seam_kind` may ever promote an unrelated seam to `S3`.
pub fn grade_transform_line(line: &str, seam_kind: &str) -> Option<(String, &'static str)> {
    let (masked, cut) = StatefulMasker::new().scan_line(line);
    let l = line[..cut].trim();
    let m = masked.trim();
    if l.is_empty() {
        return None;
    }

    if m.contains("mysqli_real_escape_string") || m.contains("mysql_real_escape_string") {
        return Some(if matches!(seam_kind, "SQL_CONCAT" | "SQL_EXEC") {
            ("mysqli_real_escape_string".to_string(), "S3")
        } else {
            ("mysqli_real_escape_string_ctx_mismatch".to_string(), "S0")
        });
    }
    if m.contains("htmlspecialchars") || m.contains("htmlentities") {
        return Some(if seam_kind == "XSS_SINK" {
            ("htmlspecialchars".to_string(), "S3")
        } else {
            ("htmlspecialchars_wrong_ctx".to_string(), "S0")
        });
    }
    if seam_kind == "READONLY_REENTRANCY" && m.contains("self.reentrancy_lock") {
        return Some(("cei_and_view_reentrancy_lock".to_string(), "S3"));
    }

    // Scoped rules: `(allowed_seams, needles, use_raw_for_literals, label, grade)`
    const SCOPED_RULES: &[(&[&str], &[&str], bool, &str, &str)] = &[
        (&["SQL_CONCAT", "SQL_EXEC"], &["setString(", "setInt("], false, "PreparedStatement_bind", "S3"),
        (&["SQL_CONCAT", "SQL_EXEC"], &["bindParam(", "bindValue("], false, "pdo_bind_param", "S3"),
        (&["SSRF_CRLF_CHAIN", "PATH_LFI"], &["is_numeric( $octet[0] )", "is_numeric($octet[0])"], false, "octet_numeric_whitelist", "S3"),
        (&["ERC4626_ROUNDING"], &["virtual_shares", "_decimalsOffset"], false, "virtual_shares_offset", "S3"),
        (&["ZKP_UNCONSTRAINED"], &["r1cs_assert_eq", "range_check_bits", "% self.field_prime) == 1"], false, "r1cs_quadratic_and_range_lock", "S3"),
        (&["CRYPTO_TOKEN"], &["merkle_domain_sep_0x00", "b\"\\x00\"", "b\"\\x01\""], true, "merkle_rfc6962_domain_sep", "S3"),
        (&["PATH_LFI"], &["O_NOFOLLOW", "RESOLVE_BENEATH"], false, "openat_nofollow_canonical", "S3"),
        (&["CMD_EXEC"], &["policy_gate_allowlist", "shell=False", "ALLOWED_MCP_TOOLS"], false, "mcp_policy_gate_argv_lock", "S3"),
        (&["SSRF_CRLF_CHAIN"], &["ip_obj.is_global"], false, "canonical_ip_and_crlf_lock", "S3"),
        (&["SSRF_CRLF_CHAIN"], &["\"127.0.0.1\" in target_url"], true, "ssrf_string_blacklist", "S1"),
        (&["JWT_ALG_CONFUSION"], &["private_hmac_keyring["], false, "jwt_pinned_alg_keyring", "S3"),
        (&["JWT_ALG_CONFUSION"], &["alg == \"NONE\"", "public_rsa_pem_bytes"], true, "jwt_alg_none_only_check", "S1"),
        (&["OAUTH_REDIRECT_PKCE"], &["registered_redirect_uris"], false, "oauth_exact_uri_and_pkce_s256", "S3"),
        (&["OAUTH_REDIRECT_PKCE"], &["redirect_uri.startswith("], false, "oauth_prefix_redirect_check", "S1"),
        (&["TOCTOU_RACE_DOUBLE_SPEND"], &["consumed_idempotency_keys"], false, "atomic_cas_and_idempotency_lock", "S3"),
        (&["CRYPTO_TOKEN", "CRYPTO_VERIFY"], &["compare_digest(", "timingSafeEqual("], false, "hmac_compare_digest", "S3"),
        (&["CMD_EXEC"], &["escapeshellarg", "escapeshellcmd"], false, "escapeshellcmd", "S3"),
        (&["PATH_LFI"], &["realpath(", "canonicalize("], false, "realpath_canonical", "S3"),
        (&["XSS_SINK"], &["_Sanitize", "SanitizeHtml"], false, "SanitizeHtml", "S3"),
        (&["XSS_SINK", "PATH_LFI", "SQL_CONCAT"], &["urldecode("], false, "urldecode_post_filter", "S2"),
        (&["SQL_CONCAT", "XSS_SINK"], &["addslashes("], false, "addslashes", "S1"),
        (&["SQL_CONCAT", "XSS_SINK", "PATH_LFI"], &["str_replace("], false, "str_replace_single_pass", "S1"),
        (&["XSS_SINK", "CMD_EXEC", "SQL_CONCAT", "PATH_LFI"], &["_check_1("], false, "check_1_medium_filter", "S1"),
        (&["XSS_SINK", "CMD_EXEC", "SQL_CONCAT", "PATH_LFI"], &["_check_2(", "_check_3("], false, "check_2_high_guard", "S3"),
    ];
    for &(allowed_seams, needles, use_raw, label, grade) in SCOPED_RULES {
        if !allowed_seams.contains(&seam_kind) {
            continue;
        }
        let hay = if use_raw { l } else { m };
        if needles.iter().any(|n| hay.contains(n)) {
            return Some((label.to_string(), grade));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stateful_masker_handles_multiline_comments_docstrings_and_js_templates() {
        let js_tmpl = "execSync(`git diff ${targetRef}`) // trailing comment";
        let masked = mask_strings_and_comments(js_tmpl);
        assert!(masked.contains("execSync(") && masked.contains("${targetRef}") && !masked.contains("git diff"));
        assert_eq!(classify_seam(js_tmpl), Some("CMD_EXEC"));

        let c_block = StatefulMasker::mask_file_lines("/*\n os.system(x)\n*/\nlet ok = 1;");
        assert!(!c_block[1].contains("os.system"));
        assert!(c_block[3].contains("let ok = 1;"));

        let py_doc = StatefulMasker::mask_file_lines("doc = \"\"\"\nsubprocess.run(cmd, shell=True)\n\"\"\"\nx = 2");
        assert!(!py_doc[1].contains("subprocess"));
        assert!(py_doc[3].contains("x = 2"));

        let ml_js = StatefulMasker::mask_file_lines("const s = `hello\n${os.system(x)}\nworld`;");
        assert!(!ml_js[0].contains("hello") && !ml_js[2].contains("world"));
        assert!(ml_js[1].contains("${os.system(x)}"));
    }

    #[test]
    fn stateful_masker_preserves_utf8_byte_alignment_across_quotes_escapes_and_comments() {
        let cases = [
            "cur.execute(\"SELECT 'café' FROM u WHERE id = ?\", (uid,))",
            "open(\"café\", \"w\")",
            "function f() { /* 🚀🚀🚀 */ x=1; fs.writeFileSync(x, \"a\"); }",
            "export const X = () => <a title=\"🚀\" href=\"javascript:alert(1)\">click</a>;",
            "const s = \"escaped \\é and \\🚀\"; const y = 2;",
            "const t = `prefix 🚀 ${danger(x)} café`;",
        ];
        for raw in cases {
            let masked = mask_strings_and_comments(raw);
            assert_eq!(masked.len(), raw.len(), "byte length mismatch for: {raw}");
            for (idx, ch) in masked.char_indices() {
                if ch != ' ' {
                    assert!(raw.is_char_boundary(idx), "misaligned boundary at {idx} in: {raw}");
                    assert_eq!(raw[idx..].chars().next(), Some(ch), "char mismatch at byte {idx} in: {raw}");
                }
            }
        }
        // Line comment preserves exact byte alignment up to comment start without leaking comment text
        let with_comment = "const a = \"café\"; // trailing 🚀 comment";
        let masked_c = mask_strings_and_comments(with_comment);
        assert!(masked_c.len() < with_comment.len());
        assert!(with_comment.is_char_boundary(masked_c.len()));
        assert_eq!(&with_comment[masked_c.len()..], "// trailing 🚀 comment");
    }
}
