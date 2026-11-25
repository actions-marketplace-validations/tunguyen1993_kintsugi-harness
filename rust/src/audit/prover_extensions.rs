//! Extended Typed Obligation Provers (`rust/src/audit/prover_extensions.rs`).
//!
//! Modular zero-dependency provers wired into `obligation_prover::prove_file_obligations`:
//! `TSX_XSS`, `PATH_CONFINE`, `CRYPTO_MAC_BIDI`, `SOL_REENTRANCY_CEI`, `SOL_SAFE_ERC20`.
//! Produces honest 4-way states (`PROVEN | VIOLATED | UNKNOWN | UNSUPPORTED`), 0 false `PROVEN`.

use std::collections::BTreeSet;
use std::path::Path;

use crate::audit::ct2_seams::strip_inline_comment;
use crate::audit::obligation_prover::{Obligation, ObligationState, Span};
use crate::rules::matcher::is_fixture_definition_line;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtLang { Python, JsTs, TsxJsx, Rust, Solidity, Other }

impl ExtLang {
    fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
            "py" | "pyi" => Self::Python, "ts" | "js" | "mjs" | "cjs" => Self::JsTs,
            "tsx" | "jsx" => Self::TsxJsx, "rs" => Self::Rust, "sol" => Self::Solidity, _ => Self::Other,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python", Self::JsTs => "typescript", Self::TsxJsx => "tsx",
            Self::Rust => "rust", Self::Solidity => "solidity", Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FnBlock { start: usize, body_start: usize, end: usize, balanced: bool }

#[inline] fn is_id(b: u8) -> bool { b.is_ascii_alphanumeric() || b == b'_' || b == b'$' }
#[inline] fn lspan(l0: usize, cols: usize) -> Span { Span { start_line: l0 + 1, start_col: 1, end_line: l0 + 1, end_col: cols.max(1) } }
#[inline] fn has_word(hay: &str, w: &str) -> bool { find_word_col(hay, w, 0).is_some() }

fn is_simple_ident(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && !t.as_bytes()[0].is_ascii_digit()
        && t.bytes().all(is_id)
        && !matches!(t, "true" | "false" | "True" | "False" | "null" | "undefined" | "None")
}

fn mk_ob(
    rule: &'static str, lang: ExtLang, sink: Span, witness: Option<Span>, binding: Option<String>,
    hash: &str, state: ObligationState, reason: &'static str, fix_hint: &'static str,
) -> Obligation {
    Obligation { rule, lang: lang.as_str(), sink_span: sink, witness_span: witness, binding, source_hash: hash.to_string(), state, reason, fix_hint }
}

fn skip_fixture(raw: &str) -> bool {
    let rt = raw.trim();
    rt.is_empty() || rt.contains(".contains(\"") || is_fixture_definition_line(rt)
        || ["*", "fix_hint:", "title:", "kmi_token:", "let bad_", "let ignored_", "poisoned."].iter().any(|p| rt.starts_with(p))
}

fn find_word_col(hay: &str, word: &str, mut from: usize) -> Option<usize> {
    let hb = hay.as_bytes();
    while from < hay.len() && !hay.is_char_boundary(from) {
        from += 1;
    }
    while from < hay.len() {
        let idx = from + hay[from..].find(word)?;
        if (idx == 0 || !is_id(hb[idx - 1])) && (idx + word.len() >= hb.len() || !is_id(hb[idx + word.len()])) {
            return Some(idx);
        }
        from = idx + word.len();
    }
    None
}

/// UTF-8-safe balanced delimiter extraction on byte-aligned `(raw, masked)` lines.
fn extract_balanced(
    raw: &[&str], masked: &[String], sl: usize, oc: usize, ob: u8, cb: u8, max_l: usize,
) -> Option<(String, String, usize)> {
    let (mut rb, mut mb, mut d) = (String::new(), String::new(), 0usize);
    for li in sl..(sl + max_l).min(raw.len()) {
        let (rl, ml) = (raw[li], masked[li].as_str());
        if li > sl { rb.push('\n'); mb.push('\n'); }
        let mut lim = rl.len().min(ml.len());
        while lim > 0 && (!rl.is_char_boundary(lim) || !ml.is_char_boundary(lim)) {
            lim -= 1;
        }
        let mut bi = if li == sl { oc } else { 0 };
        while bi < lim && (!rl.is_char_boundary(bi) || !ml.is_char_boundary(bi)) {
            bi += 1;
        }
        while bi < lim {
            let b = ml.as_bytes()[bi];
            if b == ob {
                d += 1;
                if d > 1 { rb.push(ob as char); mb.push(ob as char); }
                bi += 1;
            } else if b == cb {
                if d <= 1 { return Some((rb, mb, li)); }
                d -= 1;
                rb.push(cb as char);
                mb.push(cb as char);
                bi += 1;
            } else {
                let r_step = rl[bi..].chars().next().map_or(1, char::len_utf8);
                let next_bi = (bi + r_step).min(lim);
                if let (Some(rs), Some(ms)) = (rl.get(bi..next_bi), ml.get(bi..next_bi)) {
                    if d >= 1 { rb.push_str(rs); mb.push_str(ms); }
                    bi = next_bi;
                } else {
                    let mut sync = (bi + 1).min(lim);
                    while sync < lim && (!rl.is_char_boundary(sync) || !ml.is_char_boundary(sync)) {
                        sync += 1;
                    }
                    if let (Some(rs), Some(ms)) = (rl.get(bi..sync), ml.get(bi..sync)) {
                        if d >= 1 { rb.push_str(rs); mb.push_str(ms); }
                    }
                    bi = sync;
                }
            }
        }
    }
    None
}

fn count_top_commas(masked: &str) -> usize {
    let (mut p, mut b, mut c, mut n) = (0usize, 0usize, 0usize, 0usize);
    for x in masked.bytes() {
        match x {
            b'(' => p += 1, b')' => p = p.saturating_sub(1),
            b'[' => b += 1, b']' => b = b.saturating_sub(1),
            b'{' => c += 1, b'}' => c = c.saturating_sub(1),
            b',' if p == 0 && b == 0 && c == 0 => n += 1,
            _ => {}
        }
    }
    n
}

fn extract_first_top_arg(s: &str) -> &str {
    let (mut p, mut b, mut c) = (0usize, 0usize, 0usize);
    for (i, x) in s.bytes().enumerate() {
        match x {
            b'(' => p += 1, b')' => p = p.saturating_sub(1),
            b'[' => b += 1, b']' => b = b.saturating_sub(1),
            b'{' => c += 1, b'}' => c = c.saturating_sub(1),
            b',' if p == 0 && b == 0 && c == 0 => return &s[..i],
            _ => {}
        }
    }
    s
}

fn strip_outer_parens(mut s: &str) -> &str {
    loop {
        let t = s.trim();
        if !(t.starts_with('(') && t.ends_with(')')) { return t; }
        let (mut d, mut wraps_all) = (0usize, true);
        let bytes = t.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'(' { d += 1; } else if b == b')' {
                d = d.saturating_sub(1);
                if d == 0 && i + 1 < bytes.len() { wraps_all = false; break; }
            }
        }
        if wraps_all { s = &t[1..t.len() - 1]; } else { return t; }
    }
}

fn split_top_level_by<'a>(s: &'a str, sep: &str) -> Vec<&'a str> {
    let (mut out, mut p, mut b, mut c, mut start, mut i) = (Vec::new(), 0usize, 0usize, 0usize, 0usize, 0usize);
    let sb = s.as_bytes();
    let sep_b = sep.as_bytes();
    while i < sb.len() {
        if p == 0 && b == 0 && c == 0 && sb[i..].starts_with(sep_b) {
            out.push(&s[start..i]);
            i += sep_b.len();
            start = i;
            continue;
        }
        match sb[i] {
            b'(' => p += 1, b')' => p = p.saturating_sub(1),
            b'[' => b += 1, b']' => b = b.saturating_sub(1),
            b'{' => c += 1, b'}' => c = c.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    out.push(&s[start..]);
    out
}

/// Strip JS/TS `//` and `/* ... */` comments while preserving string/template literals verbatim.
fn strip_js_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && i + 1 < bytes.len() {
                let step = 1 + s[i + 1..].chars().next().map_or(1, char::len_utf8);
                if let Some(seg) = s.get(i..i + step) { out.push_str(seg); }
                i += step;
                continue;
            }
            if b == q { quote = None; }
            let ch = s[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        } else if matches!(b, b'"' | b'\'' | b'`') {
            quote = Some(b);
            out.push(b as char);
            i += 1;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' { i += 1; }
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' { out.push('\n'); }
                i += 1;
            }
            if i + 1 < bytes.len() { i += 2; } else { i = bytes.len(); }
            out.push(' ');
        } else {
            let ch = s[i..].chars().next().unwrap_or(' ');
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn extract_idents(s: &str) -> Vec<String> {
    let (mut out, mut cur) = (Vec::new(), String::new());
    for ch in s.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' { cur.push(ch); }
        else { if !cur.is_empty() && !cur.as_bytes()[0].is_ascii_digit() { out.push(cur.clone()); } cur.clear(); }
    }
    out
}

fn find_single_eq(ml: &str) -> Option<usize> {
    let mb = ml.as_bytes();
    for (i, &b) in mb.iter().enumerate() {
        if b == b'=' && i > 0
            && !matches!(mb[i - 1], b'!' | b'<' | b'>' | b'=')
            && !matches!(mb.get(i + 1).copied().unwrap_or(b' '), b'=' | b'>')
        {
            return Some(i);
        }
    }
    None
}

fn parse_simple_lhs(ml: &str) -> Option<(&str, usize)> {
    let eq = find_single_eq(ml)?;
    let lhs = ml[..eq]
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("mut ")
        .trim_start_matches("var ")
        .split(':')
        .next()
        .unwrap_or("")
        .trim();
    (!lhs.is_empty() && lhs.bytes().all(is_id)).then_some((lhs, eq))
}

fn parse_lhs_base_ident(ml: &str) -> Option<(&str, usize)> {
    if let Some(hit) = parse_simple_lhs(ml) { return Some(hit); }
    let eq = find_single_eq(ml)?;
    let raw_lhs = ml[..eq].trim().trim_start_matches("const ").trim_start_matches("let ").trim_start_matches("var ").trim();
    if raw_lhs.contains('(') { return None; }
    let base = raw_lhs.split(['[', '.']).next()?.trim();
    (!base.is_empty() && base.bytes().all(is_id) && raw_lhs.len() > base.len()).then_some((base, eq))
}

fn extract_functions(raw: &[&str], masked: &[String], lang: ExtLang) -> Vec<FnBlock> {
    let (mut blocks, n) = (Vec::new(), raw.len());
    if lang == ExtLang::Python {
        for i in 0..n {
            let mt = masked[i].trim();
            if !(mt.starts_with("def ") || mt.starts_with("async def ")) { continue; }
            let base = raw[i].bytes().take_while(|&b| b == b' ' || b == b'\t').count();
            let (mut he, mut pd) = (i, 0i32);
            for h in i..n.min(i + 16) {
                let hm = masked[h].trim();
                pd += hm.bytes().map(|b| if b == b'(' { 1 } else if b == b')' { -1 } else { 0 }).sum::<i32>();
                he = h;
                if pd <= 0 && hm.ends_with(':') { break; }
            }
            let mut end = he;
            for j in (he + 1)..n {
                if masked[j].trim().is_empty() { continue; }
                if raw[j].bytes().take_while(|&b| b == b' ' || b == b'\t').count() <= base { break; }
                end = j;
            }
            blocks.push(FnBlock { start: i, body_start: (he + 1).min(end), end, balanced: true });
        }
        return blocks;
    }
    for i in 0..n {
        let mt = masked[i].trim();
        let ok = match lang {
            ExtLang::Solidity => has_word(mt, "function") || mt.starts_with("receive(") || mt.starts_with("fallback("),
            ExtLang::Rust => has_word(mt, "fn") && !mt.starts_with("type ") && !mt.starts_with("use "),
            ExtLang::JsTs | ExtLang::TsxJsx => {
                ["function ", "async function ", "export function ", "export async function ", "export default function "]
                    .iter().any(|p| mt.starts_with(p))
                    || ((mt.contains("=> {") || mt.ends_with(") {"))
                        && !["if ", "for ", "while ", "switch ", "catch "].iter().any(|k| mt.starts_with(k)))
            }
            _ => false,
        };
        if !ok { continue; }
        let (mut open_pos, mut pd) = (None, 0usize);
        'hdr: for h in i..n.min(i + 20) {
            for (bi, &b) in masked[h].as_bytes().iter().enumerate() {
                if b == b'(' {
                    pd += 1;
                } else if b == b')' {
                    pd = pd.saturating_sub(1);
                } else if pd == 0 && b == b';' {
                    break 'hdr;
                } else if pd == 0 && b == b'{' {
                    open_pos = Some((h, bi));
                    break 'hdr;
                }
            }
        }
        let Some((bl, oc)) = open_pos else { continue };
        let (mut d, mut end, mut bal) = (0usize, bl, false);
        'scan: for j in bl..n {
            for &b in &masked[j].as_bytes()[if j == bl { oc } else { 0 }..] {
                if b == b'{' { d += 1; } else if b == b'}' {
                    d = d.saturating_sub(1);
                    if d == 0 { end = j; bal = true; break 'scan; }
                }
            }
            end = j;
        }
        blocks.push(FnBlock { start: i, body_start: bl, end, balanced: bal });
    }
    blocks
}

fn is_nested_py(blocks: &[FnBlock], lang: ExtLang, cur: FnBlock, l: usize) -> bool {
    lang == ExtLang::Python && blocks.iter().any(|b| b.start > cur.start && b.start <= cur.end && l >= b.start && l <= b.end)
}

// ============================================================================
// 1. TSX_XSS (.tsx / .jsx)
// ============================================================================

fn is_exact_call(expr: &str, prefix: &str) -> bool {
    let Some(rest) = expr.trim().strip_prefix(prefix) else { return false };
    let mut d = 1usize;
    for (i, &b) in rest.as_bytes().iter().enumerate() {
        if b == b'(' { d += 1; } else if b == b')' {
            d -= 1;
            if d == 0 { return rest[i + 1..].trim().is_empty(); }
        }
    }
    false
}

fn has_js_param_shadow(raw: &[&str], masked: &[String], target: &str) -> bool {
    for l in 0..masked.len() {
        let ml = masked[l].as_str();
        let mut from = 0usize;
        while let Some(rel) = ml[from..].find('(') {
            let lp = from + rel;
            if let Some((_, pm, end_l)) = extract_balanced(raw, masked, l, lp, b'(', b')', 16) {
                if has_word(&pm, target) {
                    let before = ml[..lp].trim();
                    let is_fn_hdr = has_word(before, "function");
                    let after_joined = masked[end_l..(end_l + 2).min(masked.len())].join(" ");
                    let after_rp = if end_l == l {
                        ml[lp..].rfind(')').map(|rp| &ml[lp + rp + 1..]).unwrap_or("")
                    } else {
                        masked[end_l].find(')').map(|rp| &masked[end_l][rp + 1..]).unwrap_or("")
                    };
                    let after_t = after_rp.trim_start();
                    let is_arrow_or_block = after_t.starts_with("=>")
                        || after_t.starts_with('{')
                        || after_t.contains("=>")
                        || (after_t.starts_with(':') && (after_joined.contains("=>") || after_joined.contains('{')));
                    if is_fn_hdr || is_arrow_or_block {
                        return true;
                    }
                }
            }
            from = lp + 1;
        }
    }
    false
}

fn is_canonical_dompurify_source(raw_nc: &str) -> bool {
    ["'dompurify'", "\"dompurify\"", "'isomorphic-dompurify'", "\"isomorphic-dompurify\""]
        .iter().any(|pkg| raw_nc.contains(pkg))
}

fn has_dompurify_import(raw: &[&str], masked: &[String]) -> bool {
    for l in 0..masked.len() {
        let mt = masked[l].trim();
        if !has_word(mt, "DOMPurify") { continue; }
        let rnc = strip_js_comments(raw[l]);
        if !is_canonical_dompurify_source(&rnc) { continue; }
        if mt.starts_with("import ") {
            // Reject `import { fake as DOMPurify } from 'dompurify'` (only allow default / `* as DOMPurify`)
            let bad_alias = find_word_col(mt, "DOMPurify", 0).is_some_and(|p| {
                let before = mt[..p].trim_end();
                before.ends_with(" as")
                    && !before.ends_with("default as")
                    && !before.ends_with("* as")
            });
            if !bad_alias { return true; }
        } else if mt.contains("require(") {
            return true;
        }
    }
    false
}

fn is_dompurify_shadowed(raw: &[&str], masked: &[String]) -> bool {
    if has_js_param_shadow(raw, masked, "DOMPurify") { return true; }
    for l in 0..masked.len() {
        let mt = masked[l].trim();
        if mt.starts_with("import ") || !has_word(mt, "DOMPurify") { continue; }
        let rnc = strip_js_comments(raw[l]);
        let canon_req = mt.contains("require(") && is_canonical_dompurify_source(&rnc);
        if canon_req { continue; }
        if parse_simple_lhs(mt).is_some_and(|(lhs, _)| lhs == "DOMPurify")
            || mt.contains("function DOMPurify")
            || mt.contains("class DOMPurify")
            || mt.contains("Object.assign(DOMPurify")
            || mt.contains("Object.defineProperty(DOMPurify")
        {
            return true;
        }
        // Dot/bracket mutation: `DOMPurify.sanitize = ...` or `DOMPurify["sanitize"] = ...`
        if let Some(eq) = find_single_eq(mt) {
            let lhs = mt[..eq].trim();
            if has_word(lhs, "DOMPurify")
                && (lhs.starts_with("DOMPurify.") || lhs.starts_with("DOMPurify[")
                    || (lhs.contains('{') && lhs.contains('}')))
            {
                return true;
            }
        }
    }
    false
}

fn is_url_guard_shadowed(raw: &[&str], masked: &[String], fns: &[FnBlock]) -> bool {
    if has_js_param_shadow(raw, masked, "isSafeHttpUrl") { return true; }
    for blk in fns {
        let hdr = masked[blk.start..=blk.body_start].join(" ");
        let defines_fn = find_word_col(&hdr, "isSafeHttpUrl", 0).is_some_and(|pos| {
            let before = hdr[..pos].trim_end();
            let after = hdr[pos + 13..].trim_start();
            before.ends_with("function") || after.starts_with('=') || after.starts_with(':')
        });
        if defines_fn {
            let body_m = masked[blk.start..=blk.end].join("\n");
            let body_r = strip_js_comments(&raw[blk.start..=blk.end].join("\n"));
            let has_real_proto = (body_r.contains("startsWith(\"https://\")")
                || body_r.contains("startsWith('https://')")
                || body_m.contains(".protocol"))
                && !body_m.contains("|| true");
            if !has_real_proto { return true; }
        }
    }
    for l in 0..masked.len() {
        let mt = masked[l].trim();
        if mt.starts_with("import ") || !has_word(mt, "isSafeHttpUrl") { continue; }
        if let Some(eq) = find_single_eq(mt) {
            let lhs = mt[..eq].trim();
            if has_word(lhs, "isSafeHttpUrl") && !lhs.contains('(') {
                let rhs_m = &mt[eq + 1..];
                let rnc = strip_js_comments(raw[l]);
                let has_real = rnc.contains("startsWith(\"https://\")")
                    || rnc.contains("startsWith('https://')")
                    || rhs_m.contains(".protocol");
                if !rhs_m.contains('{') && !has_real { return true; }
            }
        }
    }
    false
}

fn has_url_guard(raw: &str, mask: &str, v: &str) -> bool {
    let raw_nc = strip_js_comments(raw);
    // 1. `isSafeHttpUrl(v)` in masked code
    let mut from = 0usize;
    while let Some(pos) = find_word_col(mask, "isSafeHttpUrl", from) {
        let after = mask[pos + 13..].trim_start();
        if let Some(inner) = after.strip_prefix('(') {
            if let Some(rp) = inner.find(')') {
                if inner[..rp].trim() == v { return true; }
            }
        }
        from = pos + 13;
    }
    // 2. `v.startsWith("https://")` or `v.startsWith('https://')` in BOTH masked code and comment-stripped raw
    let mut mf = 0usize;
    let mask_has_sw = loop {
        let Some(p) = find_word_col(mask, v, mf) else { break false };
        if mask[p + v.len()..].starts_with(".startsWith(") { break true; }
        mf = p + v.len();
    };
    if !mask_has_sw { return false; }
    let mut rf = 0usize;
    while let Some(p) = find_word_col(&raw_nc, v, rf) {
        let tail = &raw_nc[p + v.len()..];
        if tail.starts_with(".startsWith(\"https://\")") || tail.starts_with(".startsWith('https://')") {
            return true;
        }
        rf = p + v.len();
    }
    false
}

fn has_positive_url_guard(cond_r: &str, cond_m: &str, v: &str) -> bool {
    let cm = strip_outer_parens(cond_m.trim());
    let cr_s = strip_js_comments(cond_r);
    let cr = strip_outer_parens(cr_s.trim());
    if cm.starts_with('!') || !split_top_level_by(cm, "||").len().eq(&1) { return false; }
    if ["=== false", "== false", "!== true", "!= true", "false ===", "false =="].iter().any(|k| cm.contains(k)) {
        return false;
    }
    let m_parts = split_top_level_by(cm, "&&");
    let r_parts = split_top_level_by(cr, "&&");
    for (idx, mp) in m_parts.iter().enumerate() {
        let mt = mp.trim();
        let inner_m = strip_outer_parens(mt);
        if mt.starts_with('!') || inner_m.starts_with('!') { continue; }
        let rp = r_parts.get(idx).copied().unwrap_or(cr);
        if has_url_guard(rp, inner_m, v) { return true; }
    }
    false
}

fn is_negated_url_guard(cond_r: &str, cond_m: &str, v: &str) -> bool {
    let cm = strip_outer_parens(cond_m.trim());
    let cr_s = strip_js_comments(cond_r);
    let cr = strip_outer_parens(cr_s.trim());
    // `if (!guard && extra)` does NOT dominate; `if (!guard || other)` DOES dominate.
    if split_top_level_by(cm, "&&").len() > 1 { return false; }
    let m_parts = split_top_level_by(cm, "||");
    let r_parts = split_top_level_by(cr, "||");
    for (idx, mp) in m_parts.iter().enumerate() {
        let mt = strip_outer_parens(mp.trim());
        let rp = r_parts.get(idx).copied().unwrap_or(cr);
        let rt = strip_outer_parens(rp.trim());
        if let Some(neg_m) = mt.strip_prefix('!') {
            let neg_r = rt.strip_prefix('!').unwrap_or(rt);
            if has_url_guard(strip_outer_parens(neg_r), strip_outer_parens(neg_m), v) { return true; }
        } else if ["=== false", "== false", "!== true", "!= true", "false ===", "false =="].iter().any(|k| mt.contains(k))
            && has_url_guard(rt, mt, v)
        {
            return true;
        }
    }
    false
}

fn split_top_level_ternary<'a>(re: &'a str, me: &'a str) -> Option<(&'a str, &'a str, &'a str, &'a str, &'a str, &'a str)> {
    let mb = me.as_bytes();
    let (mut p, mut b, mut c) = (0usize, 0usize, 0usize);
    let mut q_pos = None;
    for (i, &ch) in mb.iter().enumerate() {
        match ch {
            b'(' => p += 1, b')' => p = p.saturating_sub(1),
            b'[' => b += 1, b']' => b = b.saturating_sub(1),
            b'{' => c += 1, b'}' => c = c.saturating_sub(1),
            b'?' if p == 0 && b == 0 && c == 0 => {
                let prev = if i > 0 { mb[i - 1] } else { b' ' };
                let next = mb.get(i + 1).copied().unwrap_or(b' ');
                if prev != b'?' && next != b'?' && next != b'.' {
                    q_pos = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let qp = q_pos?;
    let (mut p2, mut b2, mut c2, mut qd) = (0usize, 0usize, 0usize, 0usize);
    let mut colon_pos = None;
    for i in (qp + 1)..mb.len() {
        match mb[i] {
            b'(' => p2 += 1, b')' => p2 = p2.saturating_sub(1),
            b'[' => b2 += 1, b']' => b2 = b2.saturating_sub(1),
            b'{' => c2 += 1, b'}' => c2 = c2.saturating_sub(1),
            b'?' if p2 == 0 && b2 == 0 && c2 == 0 => {
                let next = mb.get(i + 1).copied().unwrap_or(b' ');
                if next != b'?' && next != b'.' { qd += 1; }
            }
            b':' if p2 == 0 && b2 == 0 && c2 == 0 => {
                if qd == 0 { colon_pos = Some(i); break; }
                qd -= 1;
            }
            _ => {}
        }
    }
    let cp = colon_pos?;
    let (cr, tr, fr) = (re.get(..qp)?, re.get(qp + 1..cp)?, re.get(cp + 1..)?);
    Some((cr, &me[..qp], tr, &me[qp + 1..cp], fr, &me[cp + 1..]))
}

fn is_safe_static_href_literal(raw_b: &str, mask_b: &str) -> bool {
    let mb = strip_outer_parens(mask_b.trim());
    if matches!(mb, "undefined" | "null") { return true; }
    let rnc = strip_js_comments(raw_b);
    let rb = strip_outer_parens(rnc.trim());
    if !(mb.is_empty() && !rb.contains("${") && rb.len() >= 2) { return false; }
    let q = rb.as_bytes()[0];
    if !matches!(q, b'"' | b'\'' | b'`') || rb.as_bytes()[rb.len() - 1] != q { return false; }
    let lit = &rb[1..rb.len() - 1];
    let lo = lit.to_ascii_lowercase();
    lit.is_empty()
        || lit.starts_with('#')
        || (lit.starts_with('/') && !lit.starts_with("//"))
        || lo.starts_with("https://")
        || lo.starts_with("http://")
}

fn is_var_reassigned_in_range(masked: &[String], from: usize, to: usize, v: &str) -> bool {
    for l in from..to {
        let mt = masked[l].trim();
        if !has_word(mt, v) { continue; }
        if parse_simple_lhs(mt).is_some_and(|(lhs, _)| lhs == v) { return true; }
        let mut cur = 0usize;
        while let Some(pos) = find_word_col(mt, v, cur) {
            let after = mt[pos + v.len()..].trim_start();
            if ["+=", "-=", "??=", "||=", "&&="].iter().any(|op| after.starts_with(op)) {
                return true;
            }
            cur = pos + v.len();
        }
    }
    false
}

/// Check that a brace-scoped guard on line `guard_l` (ending its own block at `guard_end_l`) dominates `sink_l`
/// within `blk`: depth at start of `guard_l` must never drop lower between `guard_end_l + 1` and `sink_l`.
fn brace_guard_dominates(masked: &[String], blk: FnBlock, guard_l: usize, guard_end_l: usize, sink_l: usize) -> bool {
    let mut depth = 0usize;
    let mut guard_depth = 0usize;
    for l in blk.body_start..=sink_l {
        if l == guard_l {
            guard_depth = depth;
        }
        if l > guard_end_l && l <= sink_l && depth < guard_depth {
            return false;
        }
        for &b in masked[l].as_bytes() {
            if b == b'{' {
                depth += 1;
            } else if b == b'}' {
                depth = depth.saturating_sub(1);
                if l > guard_end_l && l < sink_l && depth < guard_depth {
                    return false;
                }
            }
        }
    }
    depth >= guard_depth
}

fn find_prior_dominating_url_guard(raw: &[&str], masked: &[String], fns: &[FnBlock], i: usize, v: &str) -> Option<usize> {
    let enclosing = *fns.iter().filter(|b| i >= b.start && i <= b.end).max_by_key(|b| b.start)?;
    for gl in (enclosing.body_start..i).rev() {
        let mt = masked[gl].trim();
        if !(mt.starts_with("if ") || mt.starts_with("if(")) { continue; }
        let Some(lp) = masked[gl].find('(') else { continue };
        let Some((cond_r, cond_m, cond_end_l)) = extract_balanced(raw, masked, gl, lp, b'(', b')', 4) else { continue };
        if !is_negated_url_guard(&cond_r, &cond_m, v) { continue; }

        // Verify unconditional early exit (`return` or `throw`) strictly before sink line `i`
        let after_rp = if cond_end_l == gl {
            masked[gl][lp..].find(')').map(|_| {
                let mut d = 0usize;
                let mut end_p = lp;
                for (k, &b) in masked[gl].as_bytes()[lp..].iter().enumerate() {
                    if b == b'(' { d += 1; } else if b == b')' { d -= 1; if d == 0 { end_p = lp + k + 1; break; } }
                }
                &masked[gl][end_p..]
            }).unwrap_or("")
        } else {
            masked[cond_end_l].find(')').map(|rp| &masked[cond_end_l][rp + 1..]).unwrap_or("")
        }.trim();

        let (exits_early, guard_end_l) = if after_rp.starts_with('{') {
            if let Some(ob) = masked[cond_end_l].find('{') {
                if let Some((_, bm, end_b)) = extract_balanced(raw, masked, cond_end_l, ob, b'{', b'}', 5) {
                    let uncond_exit = end_b < i && !has_word(&bm, "if") && (has_word(&bm, "return") || has_word(&bm, "throw"));
                    (uncond_exit, end_b)
                } else { (false, cond_end_l) }
            } else { (false, cond_end_l) }
        } else if !after_rp.is_empty() {
            let ok = !after_rp.starts_with("if ") && !after_rp.starts_with("if(")
                && (has_word(after_rp, "return") || has_word(after_rp, "throw"));
            (ok, cond_end_l)
        } else if cond_end_l + 1 < i {
            let nxt = masked[cond_end_l + 1].trim();
            let ok = !nxt.starts_with("if ") && !nxt.starts_with("if(")
                && (has_word(nxt, "return") || has_word(nxt, "throw"));
            (ok, cond_end_l + 1)
        } else {
            (false, cond_end_l)
        };

        if exits_early
            && brace_guard_dominates(masked, enclosing, gl, guard_end_l, i)
            && !is_var_reassigned_in_range(masked, guard_end_l + 1, i, v)
        {
            return Some(gl);
        }
    }
    None
}

fn prove_tsx_xss(raw: &[&str], masked: &[String], hash: &str) -> Vec<Obligation> {
    let mut out = Vec::new();
    let fns = extract_functions(raw, masked, ExtLang::TsxJsx);
    let dp_shadow = is_dompurify_shadowed(raw, masked);
    let dp_imported = has_dompurify_import(raw, masked);
    let url_shadow = is_url_guard_shadowed(raw, masked, &fns);

    for i in 0..raw.len() {
        let (rl, ml) = (raw[i], masked[i].as_str());
        if skip_fixture(rl) || ml.trim().is_empty() { continue; }

        if let Some((pos, (_, mo, el))) = find_word_col(ml, "dangerouslySetInnerHTML", 0).and_then(|p| {
            let eq = ml[p + 23..].find('=')?;
            let ob = ml[p + 24 + eq..].find('{')?;
            Some((p, extract_balanced(raw, masked, i, p + 24 + eq + ob, b'{', b'}', 10)?))
        }) {
            let (mt, sink) = (mo.trim(), Span { start_line: i + 1, start_col: pos + 1, end_line: el + 1, end_col: 1 });
            let (st, wit, bnd, rsn, hint) = if mt.starts_with('{') && mt.ends_with('}') {
                let inner = mt[1..mt.len() - 1].trim();
                if inner.contains("...") {
                    (ObligationState::Unknown, None, None, "spread inside dangerouslySetInnerHTML obscures __html", "Inline {{ __html: DOMPurify.sanitize(val) }}")
                } else if let Some(hp) = find_word_col(inner, "__html", 0) {
                    let val = inner[hp + 6..].trim_start().strip_prefix(':').unwrap_or("").trim().trim_end_matches(',').trim();
                    if find_word_col(val, "__html", 0).is_none() && is_exact_call(val, "DOMPurify.sanitize(") {
                        if dp_shadow {
                            (ObligationState::Violated, Some(sink), Some("DOMPurify".into()), "DOMPurify locally shadowed or mutated; sanitizer bypass detected", "Import canonical DOMPurify without shadowing")
                        } else if !dp_imported {
                            (ObligationState::Unknown, None, Some("DOMPurify".into()), "DOMPurify.sanitize() called without verified dompurify import", "Import DOMPurify from 'dompurify' or 'isomorphic-dompurify'")
                        } else {
                            (ObligationState::Proven, Some(sink), None, "dangerouslySetInnerHTML directly sanitized via imported DOMPurify.sanitize()", "")
                        }
                    } else {
                        (ObligationState::Violated, Some(sink), None, "dangerouslySetInnerHTML __html lacks direct DOMPurify.sanitize() call", "Wrap __html directly in DOMPurify.sanitize(...)")
                    }
                } else {
                    (ObligationState::Unknown, None, None, "dangerouslySetInnerHTML object missing __html key", "Pass {{ __html: DOMPurify.sanitize(val) }}")
                }
            } else {
                (ObligationState::Unknown, None, None, "dangerouslySetInnerHTML receives opaque variable or spread", "Inline {{ __html: DOMPurify.sanitize(val) }}")
            };
            out.push(mk_ob("TSX_XSS", ExtLang::TsxJsx, sink, wit, bnd, hash, st, rsn, hint));
        }

        if let Some((pos, ol)) = ml.find(".innerHTML").and_then(|p| {
            let t = ml[p + 10..].trim_start();
            if t.starts_with("+=") { Some((p, 2)) } else if t.starts_with('=') && !t.starts_with("==") { Some((p, 1)) } else { None }
        }) {
            let rhs_m = ml[pos + 10..].trim_start()[ol..].split(';').next().unwrap_or("").trim();
            let rhs_r = strip_inline_comment(rl).get(pos + 10..).and_then(|s| s.trim_start().get(ol..)).map(|r| r.split(';').next().unwrap_or("").trim()).unwrap_or("");
            if !matches!(rhs_r, "\"\"" | "''" | "``") {
                let s = lspan(i, rl.len());
                let (st, wit, rsn, hint) = if rhs_m.is_empty() && !rhs_r.contains("${") {
                    (ObligationState::Unknown, None, "static .innerHTML assignment bypasses React escaping", "Use React JSX or textContent")
                } else {
                    (ObligationState::Violated, Some(s), "dynamic .innerHTML assignment enables DOM XSS", "Use textContent or sanitized React JSX")
                };
                out.push(mk_ob("TSX_XSS", ExtLang::TsxJsx, s, wit, None, hash, st, rsn, hint));
            }
        }

        if let Some((hp, vcol)) = find_word_col(ml, "href", 0).and_then(|hp| {
            let eq = ml[hp + 4..].find('=')?;
            (ml[hp + 4..hp + 4 + eq].trim().is_empty() && !ml[hp + 5 + eq..].starts_with('=')).then_some((hp, hp + 5 + eq))
        }) {
            let ra = rl.get(vcol..).unwrap_or("").trim_start();
            if ra.starts_with('"') || ra.starts_with('\'') {
                let norm: String = ra[1..].split(ra.as_bytes()[0] as char).next().unwrap_or("")
                    .chars().filter(|c| !c.is_whitespace() && !c.is_control()).collect::<String>().to_ascii_lowercase();
                if ["javascript:", "vbscript:", "data:text/html"].iter().any(|p| norm.starts_with(p)) {
                    let s = lspan(i, rl.len());
                    out.push(mk_ob("TSX_XSS", ExtLang::TsxJsx, s, Some(s), None, hash, ObligationState::Violated, "dangerous javascript:/vbscript:/data:text/html protocol literal in href", "Use verified https:// URL"));
                }
            } else if let Some((re, me, el)) = ml.get(vcol..).and_then(|s| s.find('{'))
                .and_then(|ob| ml.get(vcol..vcol + ob).is_some_and(|w| w.trim().is_empty()).then_some(ob))
                .and_then(|ob| extract_balanced(raw, masked, i, vcol + ob, b'{', b'}', 6))
            {
                let sink = Span { start_line: i + 1, start_col: hp + 1, end_line: el + 1, end_col: 1 };
                let re_nc = strip_js_comments(&re);
                let compact: String = re_nc.chars().filter(|c| !c.is_whitespace() && !c.is_control()).collect::<String>().to_ascii_lowercase();
                if compact.contains("javascript:") || compact.contains("vbscript:") || compact.contains("data:text/html") {
                    out.push(mk_ob("TSX_XSS", ExtLang::TsxJsx, sink, Some(sink), None, hash, ObligationState::Violated, "dangerous javascript:/vbscript:/data:text/html literal inside JSX href expression", "Reject non-http(s) URLs with isSafeHttpUrl()"));
                } else if !(me.trim().is_empty() && !re_nc.contains("${") && !me.contains('+')) {
                    let ids = extract_idents(&me);
                    let mt = me.trim();
                    let (st, wit, rsn, hint) = if let Some((cr, cm, _tr, tm, fr, fm)) = split_top_level_ternary(&re, &me) {
                        let tv = strip_outer_parens(tm.trim());
                        if url_shadow && has_word(cm, "isSafeHttpUrl") {
                            (ObligationState::Violated, Some(sink), "isSafeHttpUrl locally shadowed; URL guard bypass detected", "Validate URL protocol via real startsWith(\"https://\") or URL.protocol check")
                        } else if !url_shadow && is_simple_ident(tv) && is_negated_url_guard(cr, cm, tv) {
                            (ObligationState::Violated, Some(sink), "inverted URL guard passes unverified href when check fails", "Return guarded URL in true branch and safe fallback '#' in false branch")
                        } else if !url_shadow && is_simple_ident(tv) && has_positive_url_guard(cr, cm, tv) {
                            let false_safe = is_safe_static_href_literal(fr, fm)
                                || (is_simple_ident(fm.trim()) && find_prior_dominating_url_guard(raw, masked, &fns, i, fm.trim()).is_some());
                            if false_safe {
                                (ObligationState::Proven, Some(sink), "dynamic href guarded inline by positive URL guard with safe fallback", "")
                            } else {
                                (ObligationState::Unknown, None, "inline href ternary false branch is not a safe static literal or guarded URL", "Use '#' or '' or a verified https:// literal for the fallback branch")
                            }
                        } else {
                            (ObligationState::Unknown, None, "dynamic href ternary lacks matching positive URL guard", "Validate URL via isSafeHttpUrl(url) ? url : '#'")
                        }
                    } else if is_simple_ident(mt) {
                        if !url_shadow {
                            if let Some(gl) = find_prior_dominating_url_guard(raw, masked, &fns, i, mt) {
                                (ObligationState::Proven, Some(lspan(gl, raw[gl].len())), "dynamic href guarded by prior dominating early-exit URL check", "")
                            } else {
                                (ObligationState::Unknown, None, "dynamic href lacks dominating early-exit URL guard", "Add if (!isSafeHttpUrl(url)) return null; before JSX")
                            }
                        } else {
                            (ObligationState::Violated, Some(sink), "isSafeHttpUrl locally shadowed; prior URL guard cannot be trusted", "Validate URL protocol via real startsWith(\"https://\") or URL.protocol check")
                        }
                    } else {
                        (ObligationState::Unknown, None, "compound dynamic href lacks verifiable URL confinement", "Pass a single guarded URL variable or inline isSafeHttpUrl(u) ? u : '#'")
                    };
                    out.push(mk_ob("TSX_XSS", ExtLang::TsxJsx, sink, wit, ids.first().cloned(), hash, st, rsn, hint));
                }
            }
        }
    }
    out
}

// ============================================================================
// 2. PATH_CONFINE (.py / .ts / .js / .rs)
// ============================================================================

fn extract_ident_before_dot(ml: &str, dot_pos: usize) -> Option<String> {
    let before = ml[..dot_pos].trim_end();
    let bytes = before.as_bytes();
    let mut start = bytes.len();
    while start > 0 && is_id(bytes[start - 1]) { start -= 1; }
    let cand = &before[start..];
    if is_simple_ident(cand) && (start == 0 || bytes[start - 1] != b'.') {
        Some(cand.to_string())
    } else {
        None
    }
}

fn split_py_top_args(ra: &str) -> Vec<&str> {
    let bytes = ra.as_bytes();
    let (mut p, mut b, mut c, mut i, mut start) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut quote: Option<u8> = None;
    let mut out = Vec::new();
    while i < bytes.len() {
        let ch = bytes[i];
        if let Some(q) = quote {
            if ch == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match ch {
            b'\'' | b'"' => quote = Some(ch),
            b'(' => p += 1,
            b')' => p = p.saturating_sub(1),
            b'[' => b += 1,
            b']' => b = b.saturating_sub(1),
            b'{' => c += 1,
            b'}' => c = c.saturating_sub(1),
            b',' if p == 0 && b == 0 && c == 0 => {
                out.push(&ra[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < ra.len() {
        out.push(&ra[start..]);
    }
    out
}

fn is_py_write_mode_literal(val: &str) -> bool {
    const WRITE_MODES: &[&str] = &[
        "'w'", "\"w\"", "'wb'", "\"wb\"", "'wt'", "\"wt\"", "'w+'", "\"w+\"",
        "'wb+'", "\"wb+\"", "'w+b'", "\"w+b\"", "'a'", "\"a\"", "'ab'", "\"ab\"",
        "'at'", "\"at\"", "'a+'", "\"a+\"", "'ab+'", "\"ab+\"", "'a+b'", "\"a+b\"",
        "'x'", "\"x\"", "'xb'", "\"xb\"", "'xt'", "\"xt\"", "'x+'", "\"x+\"",
        "'xb+'", "\"xb+\"", "'x+b'", "\"x+b\"", "'r+'", "\"r+\"", "'rb+'", "\"rb+\"",
        "'r+b'", "\"r+b\"",
    ];
    let t = val.trim();
    WRITE_MODES.contains(&t)
}

fn python_open_has_write_mode(ra: &str) -> bool {
    let args = split_py_top_args(ra);
    for (idx, arg) in args.iter().enumerate().skip(1) {
        let t = arg.trim();
        if let Some((k, v)) = t.split_once('=') {
            if k.trim() == "mode" && is_py_write_mode_literal(v) {
                return true;
            }
        } else if idx == 1 && is_py_write_mode_literal(t) {
            return true;
        }
    }
    false
}

fn extract_write_sinks(raw: &[&str], masked: &[String], i: usize, lang: ExtLang) -> Vec<(usize, Option<String>, String, String)> {
    let ml = masked[i].as_str();
    let mb = ml.as_bytes();
    let mut sinks = Vec::new();
    match lang {
        ExtLang::Python => {
            let mut from_os = 0usize;
            while from_os < ml.len() {
                let Some(rel) = ml[from_os..].find("os.open(") else { break };
                let c = from_os + rel;
                if c == 0 || !is_id(mb[c - 1]) {
                    if let Some((ra, ma, _)) = extract_balanced(raw, masked, i, c + 7, b'(', b')', 6) {
                        if ["O_WRONLY", "O_CREAT", "O_RDWR", "O_TRUNC", "O_APPEND"].iter().any(|f| ma.contains(f)) {
                            let a0 = strip_outer_parens(extract_first_top_arg(&ma).trim());
                            sinks.push((c, is_simple_ident(a0).then(|| a0.to_string()), ra, ma));
                        }
                    }
                }
                from_os = c + 8;
            }
            for pat in [".write_text(", ".write_bytes("] {
                let mut from_wt = 0usize;
                while from_wt < ml.len() {
                    let Some(rel) = ml[from_wt..].find(pat) else { break };
                    let c = from_wt + rel;
                    let tv = extract_ident_before_dot(ml, c);
                    sinks.push((c, tv, String::new(), String::new()));
                    from_wt = c + pat.len();
                }
            }
            let mut from_open = 0usize;
            while let Some(c) = find_word_col(ml, "open", from_open) {
                if !(c > 0 && mb[c - 1] == b'.') && ml[c + 4..].starts_with('(') {
                    if let Some((ra, ma, _)) = extract_balanced(raw, masked, i, c + 4, b'(', b')', 6) {
                        if python_open_has_write_mode(&ra) {
                            let a0 = strip_outer_parens(extract_first_top_arg(&ma).trim());
                            sinks.push((c, is_simple_ident(a0).then(|| a0.to_string()), ra, ma));
                        }
                    }
                }
                from_open = c + 4;
            }
        }
        ExtLang::JsTs => {
            let mut seen_parens = BTreeSet::new();
            for (pat, lp_off) in [("writeFileSync(", 13usize), ("fs.writeFile(", 12usize), ("promises.writeFile(", 18usize)] {
                let mut from = 0usize;
                while from < ml.len() {
                    let Some(rel) = ml[from..].find(pat) else { break };
                    let c = from + rel;
                    let left_ok = c == 0 || !is_id(mb[c - 1]);
                    if left_ok && seen_parens.insert(c + lp_off) {
                        let (ra, ma, _) = extract_balanced(raw, masked, i, c + lp_off, b'(', b')', 6).unwrap_or_default();
                        let a0 = strip_outer_parens(extract_first_top_arg(&ma).trim());
                        sinks.push((c, is_simple_ident(a0).then(|| a0.to_string()), ra, ma));
                    }
                    from = c + pat.len();
                }
            }
        }
        ExtLang::Rust => {
            let mut from = 0usize;
            while from < ml.len() {
                let Some(rel) = ml[from..].find("fs::write(") else { break };
                let c = from + rel;
                let (ra, ma, _) = extract_balanced(raw, masked, i, c + 9, b'(', b')', 6).unwrap_or_default();
                let a0 = strip_outer_parens(extract_first_top_arg(&ma).trim())
                    .trim_start_matches("&mut ")
                    .trim_start_matches('&')
                    .trim()
                    .trim_end_matches(".as_path()")
                    .trim();
                sinks.push((c, is_simple_ident(a0).then(|| a0.to_string()), ra, ma));
                from = c + 10;
            }
        }
        _ => {}
    }
    sinks.sort_by_key(|s| s.0);
    sinks
}

fn has_sep_suffix(raw: &str, mask: &str) -> bool {
    ["os.sep", "os.path.sep", "path.sep", "MAIN_SEPARATOR"].iter().any(|k| raw.contains(k))
        || ((mask.contains('+') || raw.contains("f\"") || raw.contains("f'") || raw.contains("${"))
            && ["\"/\"", "'/'", "\"\\\\\"", "}/\"", "}/'", "}/`"].iter().any(|p| raw.contains(p)))
        || (raw.contains("os.path.join(") && (raw.contains("\"\"") || raw.contains("''")))
}

fn has_py_path_div(rhs_m: &str) -> bool {
    let b = rhs_m.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'/' && (i == 0 || b[i - 1] != b'/') && b.get(i + 1) != Some(&b'/') {
            return true;
        }
    }
    false
}

fn strip_rust_unwrap_tail(mut s: &str) -> &str {
    loop {
        let t = s.trim().trim_end_matches(';').trim().trim_end_matches('?').trim();
        if let Some(base) = t.strip_suffix(".unwrap()") { s = base; continue; }
        if let Some(pos) = t.rfind(".expect(") {
            if t.ends_with(')') { s = &t[..pos]; continue; }
        }
        return t;
    }
}

fn is_real_canonicalizer_rhs(rhs_m: &str, lang: ExtLang) -> bool {
    let t = strip_rust_unwrap_tail(rhs_m).trim_start_matches("await ").trim();
    if t.contains("Promise.resolve(") { return false; }
    match lang {
        ExtLang::Python => {
            if is_exact_call(t, "os.path.realpath(") || is_exact_call(t, "realpath(") {
                return true;
            }
            // `(...).resolve()` or `Path(...).resolve()` — must end with `.resolve(...)` (no trailing `/ rel`!)
            if let Some(rpos) = t.rfind(".resolve(") {
                let before = t[..rpos].trim_end();
                if !before.ends_with("Promise") && !before.ends_with("path")
                    && is_exact_call(&t[rpos + 1..], "resolve(")
                {
                    return true;
                }
            }
            false
        }
        ExtLang::JsTs => {
            // Explicitly reject Node's lexical-only `path.resolve(...)` and `Promise.resolve(...)`!
            ["fs.realpathSync(", "realpathSync(", "fs.promises.realpath(", "promises.realpath(", "fsPromises.realpath("]
                .iter().any(|p| is_exact_call(t, p))
        }
        ExtLang::Rust => {
            ["std::fs::canonicalize(", "fs::canonicalize(", "canonicalize("]
                .iter().any(|p| is_exact_call(t, p))
        }
        _ => false,
    }
}

fn is_path_join_rhs(rhs_r: &str, rhs_m: &str, lang: ExtLang) -> bool {
    ["os.path.join(", "path.join(", ".joinpath("].iter().any(|k| rhs_m.contains(k))
        || (lang == ExtLang::JsTs && rhs_m.contains("path.resolve("))
        || (rhs_m.contains(".join(") && !["\"\".join(", "''.join(", "','.join("].iter().any(|k| rhs_r.contains(k)))
        || (lang == ExtLang::Python && has_py_path_div(rhs_m))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardForm { Assert, RejectIf }

fn classify_rejecting_guard(
    raw: &[&str], masked: &[String], blk: FnBlock, l: usize, sink_l: usize, lang: ExtLang,
) -> Option<GuardForm> {
    let mt = masked[l].trim();
    let py_dominates = |gl: usize| -> bool {
        let g_ind = raw[gl].bytes().take_while(|&b| b == b' ' || b == b'\t').count();
        let s_ind = raw[sink_l].bytes().take_while(|&b| b == b' ' || b == b'\t').count();
        if g_ind > s_ind { return false; }
        // Ensure no line between `gl` and `sink_l` dedented below `g_ind` (which would mean `gl` was in a closed branch)
        !(gl + 1..sink_l).any(|k| {
            !masked[k].trim().is_empty() && raw[k].bytes().take_while(|&b| b == b' ' || b == b'\t').count() < g_ind
        })
    };

    if mt.starts_with("assert ") || mt.starts_with("assert(") || mt.starts_with("assert!(")
        || mt.starts_with("assert.ok(") || mt.starts_with("ensure!(")
    {
        let dom = if lang == ExtLang::Python { py_dominates(l) } else { brace_guard_dominates(masked, blk, l, l, sink_l) };
        return dom.then_some(GuardForm::Assert);
    }
    if !(mt.starts_with("if ") || mt.starts_with("if(")) { return None; }
    let reject_kws: &[&str] = match lang {
        ExtLang::Python => &["raise", "return"],
        ExtLang::JsTs => &["throw", "return"],
        ExtLang::Rust => &["return", "panic", "bail", "Err"],
        _ => &["return"],
    };
    let has_rej = |s: &str| reject_kws.iter().any(|kw| has_word(s, kw));
    if lang == ExtLang::Python {
        if !py_dominates(l) { return None; }
        if let Some(col) = mt.rfind(':') {
            let tail = mt[col + 1..].trim();
            if !tail.starts_with("if ") && !tail.starts_with("if(") && has_rej(tail) {
                return Some(GuardForm::RejectIf);
            }
        }
        let base_ind = raw[l].bytes().take_while(|&b| b == b' ' || b == b'\t').count();
        for j in (l + 1)..sink_l.min(l + 4) {
            let jm = masked[j].trim();
            if jm.is_empty() { continue; }
            let ind = raw[j].bytes().take_while(|&b| b == b' ' || b == b'\t').count();
            if ind <= base_ind { break; }
            if jm.starts_with("if ") || jm.starts_with("if(") { return None; }
            if has_rej(jm) { return Some(GuardForm::RejectIf); }
        }
        None
    } else {
        let cond_end = masked[l].find('(').and_then(|lp| extract_balanced(raw, masked, l, lp, b'(', b')', 3)).map(|(_, _, el)| el).unwrap_or(l);
        if let Some(ob) = masked[cond_end].find('{') {
            if let Some((_, bm, eb)) = extract_balanced(raw, masked, cond_end, ob, b'{', b'}', 5) {
                if eb < sink_l && !has_word(&bm, "if") && has_rej(&bm) && brace_guard_dominates(masked, blk, l, eb, sink_l) {
                    return Some(GuardForm::RejectIf);
                }
            }
            return None;
        }
        // Single-line `if (...) throw ...;`
        if !brace_guard_dominates(masked, blk, l, cond_end, sink_l) { return None; }
        if has_rej(mt) { return Some(GuardForm::RejectIf); }
        if cond_end + 1 < sink_l {
            let nxt = masked[cond_end + 1].trim();
            if !nxt.starts_with("if ") && !nxt.starts_with("if(") && has_rej(nxt) {
                return Some(GuardForm::RejectIf);
            }
        }
        None
    }
}

fn is_expr_negated_in_clause(ml: &str, expr_pos: usize) -> bool {
    let before = &ml[..expr_pos];
    // Trim back to start of current logical sub-clause
    let start = [" or ", " and ", "||", "&&", "assert!(", "assert(", "assert ", "if(", "if "]
        .iter()
        .filter_map(|sep| before.rfind(sep).map(|p| p + sep.len()))
        .max()
        .unwrap_or(0);
    let prefix = before[start..].trim_start().trim_start_matches('(').trim_start();
    prefix.starts_with('!') || prefix.starts_with("not ") || prefix.starts_with("not(")
}

fn guard_condition_slice(ml: &str, form: GuardForm, lang: ExtLang) -> &str {
    let mt = ml.trim();
    match form {
        GuardForm::Assert => mt
            .trim_start_matches("assert!")
            .trim_start_matches("assert.ok")
            .trim_start_matches("assert")
            .trim_start_matches("ensure!")
            .trim(),
        GuardForm::RejectIf => {
            if lang == ExtLang::Python {
                mt.split(':').next().unwrap_or(mt).trim_start_matches("if").trim()
            } else {
                mt.split('{').next().unwrap_or(mt).trim_start_matches("if").trim()
            }
        }
    }
}

fn line_has_bound_symlink_check(ml: &str, tv: &str, lstat_vars: &BTreeSet<String>, form: GuardForm, lang: ExtLang) -> bool {
    let cond = guard_condition_slice(ml, form, lang);
    // Polarity & boolean-connective soundness:
    // - `assert`: symlink check MUST be negated (`not islink(t)` / `!is_symlink()`), and NOT weakened by `or`/`||`.
    // - `if ... raise/throw`: symlink check MUST be positive (`islink(t)` / `isSymbolicLink()`), and NOT weakened by `and`/`&&`.
    if form == GuardForm::Assert && (cond.contains(" or ") || cond.contains("||")) { return false; }
    if form == GuardForm::RejectIf && (cond.contains(" and ") || cond.contains("&&")) { return false; }

    let mut match_pos = None;
    // Direct patterns bound to `tv`
    for pat in ["islink(", "lstatSync(", "lstat(", "symlink_metadata("] {
        if let Some(p) = ml.find(pat) {
            let after = &ml[p + pat.len()..];
            if let Some(rp) = after.find(')') {
                let arg = after[..rp].trim().trim_start_matches('&').trim();
                let is_lstat_check = !pat.starts_with("lstat") || ml[p..].contains("isSymbolicLink(");
                let is_meta_check = pat != "symlink_metadata(" || ml[p..].contains("is_symlink(");
                if arg == tv && is_lstat_check && is_meta_check {
                    match_pos = Some(p);
                    break;
                }
            }
        }
    }
    if match_pos.is_none() {
        if let Some(p) = ml.find(".is_symlink(") {
            if extract_ident_before_dot(ml, p).as_deref() == Some(tv) {
                match_pos = Some(p.saturating_sub(tv.len()));
            }
        }
    }
    if match_pos.is_none() {
        for lv in lstat_vars {
            if let Some(p) = find_word_col(ml, lv, 0) {
                if ml[p..].contains("isSymbolicLink(") || ml[p..].contains("is_symlink(") {
                    match_pos = Some(p);
                    break;
                }
            }
        }
    }
    let Some(pos) = match_pos else { return false };
    let negated = is_expr_negated_in_clause(ml, pos);
    match form {
        GuardForm::Assert => negated,
        GuardForm::RejectIf => !negated,
    }
}

fn prove_path_confine(raw: &[&str], masked: &[String], lang: ExtLang, hash: &str) -> Vec<Obligation> {
    let blocks = extract_functions(raw, masked, lang);
    let mut out = Vec::new();
    for &blk in &blocks {
        let has_ops = (blk.start..=blk.end).any(|l| {
            !is_nested_py(&blocks, lang, blk, l)
                && ["realpath(", "realpathSync(", ".resolve(", "path.resolve(", "canonicalize(", ".startswith(", ".startsWith(", ".starts_with(", ".is_relative_to(", "os.path.join(", "path.join(", ".joinpath(", ".join("]
                    .iter().any(|k| masked[l].contains(k))
        });
        if !has_ops { continue; }
        for i in blk.body_start..=blk.end {
            if is_nested_py(&blocks, lang, blk, i) || skip_fixture(raw[i]) { continue; }
            for (sink_col, target_var, sink_ra, sink_ma) in extract_write_sinks(raw, masked, i, lang) {
                let (mut target_can, mut target_unclean_join, mut s_pref, mut b_pref, mut sym) = (None, None, None, None, None);
                let (mut sep_vars, mut lstat_vars, mut str_vars, mut target_str_aliases) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
                let mut target_str_converted = false;

                for l in blk.start..=i {
                    if is_nested_py(&blocks, lang, blk, l) { continue; }
                    let (rl, ml) = (raw[l], masked[l].as_str());

                    if let Some((lhs, eq)) = parse_simple_lhs(ml) {
                        let rhs_r = rl.get(eq + 1..).unwrap_or("");
                        let rhs_m = ml.get(eq + 1..).unwrap_or("");
                        if has_sep_suffix(rhs_r, rhs_m) { sep_vars.insert(lhs.to_string()); }
                        if lang == ExtLang::Rust
                            && ["to_str(", "to_string_lossy(", ".display(", "format!(", ".to_string("].iter().any(|k| rhs_m.contains(k))
                        {
                            str_vars.insert(lhs.to_string());
                            if target_var.as_deref().is_some_and(|tv| has_word(rhs_m, tv)) {
                                target_str_converted = true;
                                target_str_aliases.insert(lhs.to_string());
                            }
                        }
                        if let Some(tv) = target_var.as_deref() {
                            if ["lstatSync(", "lstat(", "symlink_metadata("].iter().any(|k| rhs_m.contains(k)) && has_word(rhs_m, tv) {
                                lstat_vars.insert(lhs.to_string());
                            }
                            if lhs == tv {
                                // Reassignment of `target_var`: reset prior guards and evaluate new RHS strictly!
                                s_pref = None;
                                sym = None;
                                if is_real_canonicalizer_rhs(rhs_m, lang) {
                                    target_can = Some(l);
                                    target_unclean_join = None;
                                } else {
                                    target_can = None;
                                    if is_path_join_rhs(rhs_r, rhs_m, lang) {
                                        target_unclean_join = Some(l);
                                    }
                                }
                            }
                        }
                    }
                    if lang == ExtLang::Rust {
                        if let Some(tv) = target_var.as_deref() {
                            if has_word(ml, tv) && ["to_str(", "to_string_lossy(", ".display("].iter().any(|k| ml.contains(k)) {
                                target_str_converted = true;
                            }
                        }
                    }

                    let Some(tv) = target_var.as_deref() else { continue };

                    // Check O_NOFOLLOW directly on sink line `i`
                    if l == i && ml.contains("O_NOFOLLOW") && has_word(ml, tv) {
                        sym = Some(i);
                    }

                    let guard_form = classify_rejecting_guard(raw, masked, blk, l, i, lang);

                    // Symlink check bound to `tv` inside a rejecting `if`/`assert`
                    if let Some(form) = guard_form {
                        if line_has_bound_symlink_check(ml, tv, &lstat_vars, form, lang) {
                            sym = Some(l);
                        }
                    }

                    // Prefix check `.is_relative_to(...)` bound to `tv`
                    if let Some(pos) = ml.find(".is_relative_to(") {
                        if extract_ident_before_dot(ml, pos).as_deref() == Some(tv) {
                            if let Some(form) = guard_form {
                                let cond = guard_condition_slice(ml, form, lang);
                                let neg = is_expr_negated_in_clause(ml, pos.saturating_sub(tv.len()));
                                let pol_ok = match form {
                                    GuardForm::Assert => !neg && !cond.contains(" or ") && !cond.contains("||"),
                                    GuardForm::RejectIf => neg && !cond.contains(" and ") && !cond.contains("&&"),
                                };
                                if pol_ok { s_pref = Some(l); }
                            }
                        }
                    }

                    // Prefix check `.startswith(` / `.startsWith(` / `.starts_with(`
                    for needle in [".startswith(", ".startsWith(", ".starts_with("] {
                        if let Some((pos, (ra, ma, _))) = ml.find(needle).and_then(|p| {
                            Some((p, extract_balanced(raw, masked, l, p + needle.len() - 1, b'(', b')', 3)?))
                        }) {
                            let mt = ma.trim();
                            if mt.is_empty() { continue; }
                            let recv = extract_ident_before_dot(ml, pos);
                            let is_target = recv.as_deref() == Some(tv);
                            let is_str_alias = recv.as_deref().is_some_and(|r| target_str_aliases.contains(r));
                            if !is_target && !is_str_alias { continue; }

                            let rust_path_safe = lang == ExtLang::Rust
                                && is_target
                                && target_can.is_some()
                                && !target_str_converted
                                && !str_vars.contains(tv)
                                && !["to_str", "to_string_lossy", "display"].iter().any(|k| ml[..pos].contains(k) || ma.contains(k))
                                && !extract_idents(&ma).iter().any(|id| str_vars.contains(id));
                            let ok = rust_path_safe || has_sep_suffix(&ra, &ma) || sep_vars.contains(mt);
                            if !ok {
                                b_pref = Some(l);
                            } else if is_target {
                                if let Some(form) = guard_form {
                                    let cond = guard_condition_slice(ml, form, lang);
                                    let neg = is_expr_negated_in_clause(ml, pos.saturating_sub(tv.len()));
                                    let pol_ok = match form {
                                        GuardForm::Assert => !neg && !cond.contains(" or ") && !cond.contains("||"),
                                        GuardForm::RejectIf => neg && !cond.contains(" and ") && !cond.contains("&&"),
                                    };
                                    if pol_ok { s_pref = Some(l); }
                                }
                            }
                        }
                    }
                }

                let sink_end_col = {
                    let rest = masked[i].get(sink_col..).unwrap_or("");
                    if let Some(lp) = rest.find('(') {
                        let mut d = 0usize;
                        let mut end_c = raw[i].len().max(sink_col + 1);
                        for (bi, &b) in rest.as_bytes()[lp..].iter().enumerate() {
                            if b == b'(' {
                                d += 1;
                            } else if b == b')' {
                                d = d.saturating_sub(1);
                                if d == 0 {
                                    end_c = sink_col + lp + bi + 1;
                                    break;
                                }
                            }
                        }
                        end_c
                    } else {
                        raw[i].len().max(sink_col + 1)
                    }
                };
                let sink = Span {
                    start_line: i + 1,
                    start_col: sink_col + 1,
                    end_line: i + 1,
                    end_col: sink_end_col.max(sink_col + 1),
                };
                let a0_ra = extract_first_top_arg(&sink_ra);
                let a0_ma = extract_first_top_arg(&sink_ma);
                let inline_unclean_join = target_var.is_none()
                    && !is_real_canonicalizer_rhs(a0_ma, lang)
                    && is_path_join_rhs(a0_ra, a0_ma, lang);

                let (st, wit, rsn, hint) = if let Some(bl) = b_pref {
                    (ObligationState::Violated, Some(lspan(bl, raw[bl].len())), "prefix check startswith(root) lacks trailing separator or converts Path to string (sibling bypass)", "Use canonicalize + startswith(root + sep)/is_relative_to + symlink check")
                } else if target_unclean_join.is_some() || inline_unclean_join {
                    (ObligationState::Violated, Some(sink), "joined target path written without post-join symlink-resolving canonicalize/realpath/resolve", "Canonicalize joined target via realpath/Path.resolve/realpathSync/canonicalize before write")
                } else if let (Some(cl), Some(pl), Some(_)) = (target_can, s_pref, sym) {
                    (ObligationState::Proven, Some(Span { start_line: cl + 1, start_col: 1, end_line: pl + 1, end_col: 1 }), "target canonicalized, rejecting sibling-safe prefix check, and symlink defense verified", "")
                } else {
                    (ObligationState::Unknown, target_can.or(s_pref).map(|l| lspan(l, 1)), "incomplete path confinement on target variable (requires real canonicalize + rejecting sibling-safe prefix + symlink defense)", "Canonicalize target variable, reject escaping prefixes with if/assert, and check symlink/O_NOFOLLOW on target")
                };
                out.push(mk_ob("PATH_CONFINE", lang, sink, wit, target_var, hash, st, rsn, hint));
            }
        }
    }
    out
}

// ============================================================================
// 3. CRYPTO_MAC_BIDI (.py / .ts / .js)
// ============================================================================

fn split_clause_ranges(line: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    let bytes = line.as_bytes();
    while i < bytes.len() {
        let sep_len = if bytes[i..].starts_with(b" and ") || bytes[i..].starts_with(b" else ") {
            if bytes[i..].starts_with(b" else ") { 6 } else { 5 }
        } else if bytes[i..].starts_with(b" or ") || bytes[i..].starts_with(b" if ") {
            4
        } else if bytes[i..].starts_with(b"&&") || bytes[i..].starts_with(b"||") {
            2
        } else if matches!(bytes[i], b';' | b'?' | b':' | b',') {
            1
        } else {
            0
        };
        if sep_len > 0 {
            if start < i { out.push((start, i)); }
            i += sep_len;
            start = i;
        } else {
            i += line[i..].chars().next().map_or(1, char::len_utf8);
        }
    }
    if start < bytes.len() { out.push((start, bytes.len())); }
    out
}

fn is_sig_tok(tok: &str, hv: &BTreeSet<String>) -> bool {
    hv.contains(tok)
        || ["sig", "signature", "mac", "hmac", "digest", "expected", "secret", "token"]
            .iter().any(|k| tok.to_ascii_lowercase().contains(k))
}

fn is_benign_side(s: &str) -> bool {
    let t = s.trim().trim_start_matches(['(', '!', ' ']);
    for lit in ["\"\"", "''", "``", "b\"\"", "b''", "None", "null", "undefined", "0"] {
        if let Some(r) = t.strip_prefix(lit).map(str::trim_start) {
            if r.is_empty() || r.starts_with(':') || r.starts_with(')') || r.starts_with("return") { return true; }
        }
    }
    let tok = t.split(|c: char| c.is_whitespace() || matches!(c, ')' | ':' | ',')).next().unwrap_or("");
    !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_digit())
}

fn find_all_eq_ops(s: &str) -> Vec<(usize, usize)> {
    let mut ops = Vec::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    while i + 1 < b.len() {
        if b[i..].starts_with(b"!==") || b[i..].starts_with(b"===") {
            ops.push((i, 3));
            i += 3;
        } else if (b[i..].starts_with(b"!=") || b[i..].starts_with(b"=="))
            && (i == 0 || !matches!(b[i - 1], b'!' | b'<' | b'>' | b'='))
            && b.get(i + 2) != Some(&b'=')
        {
            ops.push((i, 2));
            i += 2;
        } else {
            i += 1;
        }
    }
    ops
}

fn has_unsafe_sig_eq(raw_line: &str, masked_line: &str, hv: &BTreeSet<String>) -> bool {
    let raw_nc = strip_inline_comment(raw_line);
    let is_len = |s: &str| s.contains("len(") || s.contains(".length") || s.contains(".byteLength") || s.contains(".len(");
    for (cs, ce) in split_clause_ranges(masked_line) {
        let cm = &masked_line[cs..ce];
        let cr = raw_nc.get(cs..ce).unwrap_or("");
        if cm.contains(".equals(") && extract_idents(cm).iter().any(|t| is_sig_tok(t, hv)) {
            return true;
        }
        let ops = find_all_eq_ops(cm);
        if ops.is_empty() { continue; }
        for (oi, &(op_p, op_l)) in ops.iter().enumerate() {
            let l_start = if oi == 0 { 0 } else { ops[oi - 1].0 + ops[oi - 1].1 };
            let r_end = if oi + 1 < ops.len() { ops[oi + 1].0 } else { cm.len() };
            let lm = cm[l_start..op_p].trim();
            let rm = cm[op_p + op_l..r_end].trim();
            if !(extract_idents(lm).iter().any(|t| is_sig_tok(t, hv)) || extract_idents(rm).iter().any(|t| is_sig_tok(t, hv))) {
                continue;
            }
            if lm.contains("typeof ") || rm.contains("typeof ") { continue; }
            if (is_len(lm) && is_len(rm)) || ((is_len(lm) || is_len(rm)) && (is_benign_side(lm) || is_benign_side(rm))) {
                continue;
            }
            let lr = cr.get(l_start..op_p).unwrap_or("");
            let rr = cr.get(op_p + op_l..r_end).unwrap_or("");
            if is_benign_side(lr) || is_benign_side(rr) { continue; }
            return true;
        }
    }
    false
}

fn is_ct_shadowed(raw: &[&str], masked: &[String], blocks: &[FnBlock], lang: ExtLang) -> bool {
    for sym in ["compare_digest", "timingSafeEqual"] {
        // 1. Parameter list shadowing (single-line & multi-line across Python & JS/TS)
        if lang == ExtLang::JsTs && has_js_param_shadow(raw, masked, sym) { return true; }
        for blk in blocks {
            if let Some(lp) = masked[blk.start].find('(') {
                if let Some((_, pm, _)) = extract_balanced(raw, masked, blk.start, lp, b'(', b')', 16) {
                    if has_word(&pm, sym) { return true; }
                }
            }
        }
        // 2. Definitions, assignments (with/without spaces, `: Type`, `var`, dot-LHS), destructuring, `as <sym>`
        for l in 0..masked.len() {
            let mt = masked[l].trim();
            if !has_word(mt, sym) { continue; }
            let rnc = strip_inline_comment(raw[l]);
            let is_canon_crypto_src = ["'crypto'", "\"crypto\"", "'node:crypto'", "\"node:crypto\""]
                .iter().any(|p| rnc.contains(p));
            let is_canon_py_import = mt.starts_with("from hmac import ") || mt.starts_with("from secrets import ");

            // `def compare_digest` / `function timingSafeEqual` / `class ...`
            if let Some(p) = find_word_col(mt, sym, 0) {
                let before = mt[..p].trim_end();
                if before.ends_with("def") || before.ends_with("function") || before.ends_with("class") {
                    return true;
                }
            }
            // Non-canonical direct import: `from evil import compare_digest` or `import { timingSafeEqual } from './evil'`
            if sym == "compare_digest" && mt.starts_with("from ") && !is_canon_py_import {
                return true;
            }
            if sym == "timingSafeEqual" && mt.starts_with("import ") && !is_canon_crypto_src {
                return true;
            }
            // Aliasing `... as compare_digest` / `... as timingSafeEqual`
            let mut cur = 0usize;
            while let Some(p) = find_word_col(mt, sym, cur) {
                let before = mt[..p].trim_end();
                if before.ends_with(" as") || before == "as" {
                    let exact_self_import = (is_canon_py_import || (mt.starts_with("import ") && is_canon_crypto_src))
                        && before.trim_end_matches(" as").trim_end().ends_with(sym);
                    if !exact_self_import { return true; }
                }
                cur = p + sym.len();
            }
            // Assignment / declaration: `compare_digest=lambda`, `const timingSafeEqual: any = ...`, `var timingSafeEqual = ...`, `hmac.compare_digest = ...`
            if !mt.starts_with("import ") && !mt.starts_with("from ") {
                if let Some(eq) = find_single_eq(mt) {
                    let lhs = mt[..eq].trim();
                    let is_canon_req = mt[eq + 1..].contains("require(") && is_canon_crypto_src;
                    if !is_canon_req && has_word(lhs, sym) && !lhs.contains('(') {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn prove_crypto_mac_bidi(raw: &[&str], masked: &[String], lang: ExtLang, hash: &str) -> Vec<Obligation> {
    let blocks = extract_functions(raw, masked, lang);
    let ct_shadowed = is_ct_shadowed(raw, masked, &blocks, lang);
    let mut out = Vec::new();
    for &blk in &blocks {
        let (mut hl, mut ct, mut bad, mut help, mut hv) = (None, None, None, None, BTreeSet::new());
        let v_hdr = ["verify", "check", "valid", "auth", "sig", "mac", "digest", "expected"]
            .iter().any(|k| masked[blk.start].to_ascii_lowercase().contains(k));
        for l in blk.body_start..=blk.end {
            if is_nested_py(&blocks, lang, blk, l) || skip_fixture(raw[l]) { continue; }
            let (rl, ml) = (raw[l], masked[l].as_str());
            let is_h = ml.contains("hmac.new(") || ml.contains("hmac.digest(") || ml.contains("createHmac(");
            if is_h && hl.is_none() { hl = Some(l); }
            if let Some((lhs, eq)) = parse_lhs_base_ident(ml) {
                let rhs = &ml[eq + 1..];
                let rhs_is_len = rhs.trim().starts_with("len(") || rhs.trim().ends_with(".length");
                if is_h || (!rhs_is_len && extract_idents(rhs).iter().any(|t| is_sig_tok(t, &hv))) {
                    hv.insert(lhs.to_string());
                }
            }
            if ml.contains("compare_digest(") || ml.contains("timingSafeEqual(") {
                let mt = ml.trim();
                let consumed = mt.starts_with("return ") || mt.starts_with("if ") || mt.starts_with("assert ")
                    || mt.starts_with("elif ") || mt.contains('=') || mt.contains("&&")
                    || mt.contains("||") || mt.contains('?') || mt.contains(" and ") || mt.contains(" or ");
                if consumed {
                    ct = Some(l);
                } else if help.is_none() {
                    help = Some(l);
                }
            }
            if has_unsafe_sig_eq(rl, ml, &hv) && bad.is_none() { bad = Some(l); }
            if !is_h && ct.is_none() && ml.contains('(') && extract_idents(ml).iter().any(|t| is_sig_tok(t, &hv)) {
                let mt = ml.trim();
                let b = ["Buffer.from(", "len(", ".encode(", ".decode(", ".hexdigest(", ".digest(", ".update(", ".toString(", "bytes("]
                    .iter().any(|k| mt.contains(k)) && !mt.starts_with("return ");
                if !b && !mt.starts_with("if ") { help = Some(l); }
            }
        }
        let Some(h) = hl else { continue };
        if ct.is_none() && bad.is_none() && !(v_hdr && help.is_some()) { continue; }
        let (sl, st, rsn, hint) = if let Some(u) = bad {
            (u, ObligationState::Violated, "non-constant-time comparison (==/!=/equals) on HMAC signature/digest/secret", "Use hmac.compare_digest() or crypto.timingSafeEqual() exclusively")
        } else if let Some(c) = ct {
            if ct_shadowed {
                (c, ObligationState::Violated, "compare_digest/timingSafeEqual locally shadowed", "Call canonical hmac.compare_digest / crypto.timingSafeEqual")
            } else {
                (c, ObligationState::Proven, "constant-time HMAC verification verified without raw equality", "")
            }
        } else {
            (help.unwrap_or(h), ObligationState::Unknown, "HMAC verification delegated to unresolved helper", "Verify directly with hmac.compare_digest() or crypto.timingSafeEqual()")
        };
        out.push(mk_ob("CRYPTO_MAC_BIDI", lang, lspan(sl, raw[sl].len()), Some(lspan(h, raw[h].len())), None, hash, st, rsn, hint));
    }
    out
}

// ============================================================================
// 4 & 5. SOL_REENTRANCY_CEI & SOL_SAFE_ERC20 (.sol)
// ============================================================================

fn has_fake_nonreentrant_modifier(raw: &[&str], masked: &[String]) -> bool {
    for l in 0..masked.len() {
        let mt = masked[l].trim();
        if has_word(mt, "modifier") && has_word(mt, "nonReentrant") {
            let mut brace_pos = None;
            for h in l..masked.len().min(l + 8) {
                if let Some(ob) = masked[h].find('{') { brace_pos = Some((h, ob)); break; }
            }
            let Some((bl, ob)) = brace_pos else { return true };
            let Some((_, body, _)) = extract_balanced(raw, masked, bl, ob, b'{', b'}', 32) else { return true };
            let has_guard = body.contains("require(") || has_word(&body, "if") || has_word(&body, "revert");
            let has_lock_write = find_single_eq(&body).is_some()
                || body.contains("+=") || body.contains("-=")
                || has_word(&body, "delete") || has_word(&body, "tstore");
            let has_lock_helpers = body.contains("_nonReentrantBefore(") && body.contains("_nonReentrantAfter(");
            if !((has_guard && has_lock_write) || has_lock_helpers) {
                return true;
            }
        }
    }
    false
}

fn has_nonreentrant_in_header_tail(masked: &[String], blk: FnBlock) -> bool {
    let hdr = masked[blk.start..=blk.body_start].join(" ");
    let Some(lp) = hdr.find('(') else { return false };
    let mut d = 0usize;
    let mut rp_opt = None;
    for (i, &b) in hdr.as_bytes()[lp..].iter().enumerate() {
        if b == b'(' { d += 1; } else if b == b')' {
            d -= 1;
            if d == 0 { rp_opt = Some(lp + i); break; }
        }
    }
    let Some(rp) = rp_opt else { return false };
    let after_params = &hdr[rp + 1..];
    let tail_raw = after_params.split('{').next().unwrap_or(after_params);
    // Strip `returns (...)` so `returns (bool nonReentrant)` cannot spoof the modifier!
    let tail = if let Some(rpos) = find_word_col(tail_raw, "returns", 0) {
        let after_ret = &tail_raw[rpos + 7..];
        if let Some(rlp) = after_ret.find('(') {
            let mut rd = 0usize;
            let mut rrp = after_ret.len();
            for (k, &b) in after_ret.as_bytes()[rlp..].iter().enumerate() {
                if b == b'(' { rd += 1; } else if b == b')' { rd -= 1; if rd == 0 { rrp = rlp + k + 1; break; } }
            }
            format!("{} {}", &tail_raw[..rpos], &after_ret[rrp..])
        } else {
            tail_raw.to_string()
        }
    } else {
        tail_raw.to_string()
    };
    has_word(&tail, "nonReentrant")
}

fn strip_sol_prefixes(mut st: &str) -> &str {
    loop {
        let t = st.trim().trim_start_matches(['{', '}']).trim();
        if let Some(rest) = t.strip_prefix("else") {
            if rest.is_empty() || !is_id(rest.as_bytes()[0]) { st = rest; continue; }
        }
        if let Some(rest) = t.strip_prefix("unchecked") {
            if rest.is_empty() || !is_id(rest.as_bytes()[0]) { st = rest; continue; }
        }
        if let Some(rest) = t.strip_prefix("if") {
            if rest.starts_with(' ') || rest.starts_with('(') {
                let r = rest.trim_start();
                if r.starts_with('(') {
                    let mut d = 0usize;
                    let mut end_p = None;
                    for (i, &b) in r.as_bytes().iter().enumerate() {
                        if b == b'(' { d += 1; } else if b == b')' { d -= 1; if d == 0 { end_p = Some(i + 1); break; } }
                    }
                    if let Some(ep) = end_p { st = &r[ep..]; continue; }
                }
            }
        }
        return t;
    }
}

fn is_sol_local_decl(mt: &str) -> bool {
    if mt.starts_with("(bool") || mt.starts_with("mapping(") { return true; }
    let first = mt.split_whitespace().next().unwrap_or("");
    matches!(first, "bool" | "address" | "string" | "bytes" | "uint" | "int")
        || (first.starts_with("uint") && first.len() > 4 && first[4..].bytes().all(|b| b.is_ascii_digit()))
        || (first.starts_with("int") && first.len() > 3 && first[3..].bytes().all(|b| b.is_ascii_digit()))
        || (first.starts_with("bytes") && first.len() > 5 && first[5..].bytes().all(|b| b.is_ascii_digit()))
}

fn is_sol_state_mut(st: &str) -> bool {
    let mt = strip_sol_prefixes(st);
    if mt.is_empty() || ["revert", "emit ", "return "].iter().any(|k| mt.starts_with(k)) {
        return false;
    }
    if mt.starts_with("require(") || mt.starts_with("assert(") {
        return mt.contains("++") || mt.contains("--") || mt.contains("+=") || mt.contains("-=") || find_single_eq(mt).is_some();
    }
    if mt.contains("++") || mt.contains("--") || mt.contains("-=") || mt.contains("+=") || mt.contains("*=") || mt.contains("/=")
        || has_word(mt, "delete") || mt.contains(".push(") || mt.contains(".pop(")
    {
        return !is_sol_local_decl(mt);
    }
    if is_sol_local_decl(mt) { return false; }
    find_single_eq(mt).is_some()
}

fn has_sol_post_helper_call(st: &str) -> bool {
    let mt = st.trim();
    if mt.is_empty() || !mt.contains('(') { return false; }
    let is_emit_or_revert = mt.starts_with("emit ") || mt.starts_with("revert ");
    let mut skipped_top = false;
    let bytes = mt.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'(' { continue; }
        let mut s = i;
        while s > 0 && (is_id(bytes[s - 1]) || bytes[s - 1] == b'.') { s -= 1; }
        if s == i { continue; }
        let callee = &mt[s..i];
        if is_emit_or_revert && !skipped_top {
            skipped_top = true;
            continue;
        }
        let benign = matches!(
            callee,
            "require" | "assert" | "revert" | "if" | "while" | "for" | "keccak256" | "sha256" | "ecrecover"
                | "abi.decode" | "abi.encode" | "abi.encodePacked" | "abi.encodeWithSelector" | "abi.encodeWithSignature"
                | "bool" | "address" | "payable" | "string" | "bytes" | "uint" | "int" | "type"
        ) || (callee.starts_with("uint") && callee[4..].bytes().all(|c| c.is_ascii_digit()))
            || (callee.starts_with("int") && callee[3..].bytes().all(|c| c.is_ascii_digit()))
            || (callee.starts_with("bytes") && callee[5..].bytes().all(|c| c.is_ascii_digit()));
        if !benign { return true; }
    }
    false
}

fn find_sol_arity(raw: &[&str], masked: &[String], l: usize, needle: &str) -> Option<(usize, usize)> {
    let pos = masked[l].find(needle)?;
    Some((pos, count_top_commas(&extract_balanced(raw, masked, l, pos + needle.len() - 1, b'(', b')', 6)?.1) + 1))
}

fn extract_sol_call_tuple(ml: &str) -> Option<(String, String)> {
    let eq = find_single_eq(ml)?;
    let lhs = ml[..eq].trim();
    if !(lhs.starts_with('(') && lhs.ends_with(')')) { return None; }
    let inner = &lhs[1..lhs.len() - 1];
    let (p0, p1) = inner.split_once(',')?;
    let ok_var = p0.trim().strip_prefix("bool ")?.trim();
    let data_var = p1.trim().strip_prefix("bytes memory ")?.trim();
    if is_simple_ident(ok_var) && is_simple_ident(data_var) {
        Some((ok_var.to_string(), data_var.to_string()))
    } else {
        None
    }
}

fn matches_safe_erc20_require(raw: &[&str], masked: &[String], k: usize, ok_var: &str, data_var: &str) -> bool {
    let Some(req_p) = find_word_col(&masked[k], "require", 0) else { return false };
    let after_req = &masked[k][req_p + 7..];
    let Some(lp_rel) = after_req.find('(') else { return false };
    if !after_req[..lp_rel].trim().is_empty() { return false; }
    let Some((_, ma, _)) = extract_balanced(raw, masked, k, req_p + 7 + lp_rel, b'(', b')', 4) else { return false };
    let cond = strip_outer_parens(extract_first_top_arg(&ma).trim());
    // Must NOT have top-level `||` outside parens!
    if split_top_level_by(cond, "||").len() > 1 { return false; }
    let conj = split_top_level_by(cond, "&&");
    if conj.len() < 2 { return false; }

    let has_ok = conj.iter().any(|c| strip_outer_parens(c.trim()) == ok_var);
    if !has_ok { return false; }

    let expect_len_l = format!("{data_var}.length==0");
    let expect_len_r = format!("0=={data_var}.length");
    let expect_dec = format!("abi.decode({data_var},(bool))");

    conj.iter().any(|c| {
        let inner = strip_outer_parens(c.trim());
        if split_top_level_by(inner, "&&").len() > 1 { return false; }
        let disj = split_top_level_by(inner, "||");
        if disj.len() != 2 { return false; }
        let norm = |s: &str| strip_outer_parens(s.trim()).chars().filter(|ch| !ch.is_whitespace()).collect::<String>();
        let (d0, d1) = (norm(disj[0]), norm(disj[1]));
        let is_len = |d: &str| d == expect_len_l || d == expect_len_r;
        (is_len(&d0) && d1 == expect_dec) || (is_len(&d1) && d0 == expect_dec)
    })
}

fn has_safe_erc20_import(raw: &[&str]) -> bool {
    let cleaned = strip_js_comments(&raw.join("\n"));
    let bytes = cleaned.as_bytes();
    let mut i = 0usize;
    let mut seg_start = 0usize;
    let mut seg_start_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut stmts: Vec<&str> = Vec::new();

    while i < bytes.len() {
        let ch = bytes[i];
        if let Some(q) = quote {
            if ch == b'\\' && i + 1 < bytes.len() {
                let step = cleaned[i + 1..].chars().next().map_or(1, char::len_utf8);
                i += 1 + step;
                continue;
            }
            if ch == q {
                quote = None;
            }
            i += cleaned[i..].chars().next().map_or(1, char::len_utf8);
            continue;
        }
        match ch {
            b'"' | b'\'' => {
                quote = Some(ch);
                i += 1;
            }
            b'{' => {
                brace_depth += 1;
                i += 1;
            }
            b'}' => {
                brace_depth = brace_depth.saturating_sub(1);
                i += 1;
                // Only reset statement start when closing a contract/library block (not `import { ... } from "..."`)
                let prefix_t = cleaned[seg_start..i].trim_start();
                let is_import_prefix = prefix_t.starts_with("import")
                    && prefix_t.as_bytes().get(6).map_or(true, |&b| !is_id(b));
                if brace_depth == 0 && !is_import_prefix {
                    seg_start = i;
                    seg_start_depth = 0;
                }
            }
            b';' if brace_depth == 0 => {
                if seg_start_depth == 0 {
                    stmts.push(&cleaned[seg_start..i]);
                }
                i += 1;
                seg_start = i;
                seg_start_depth = brace_depth;
            }
            _ => {
                i += cleaned[i..].chars().next().map_or(1, char::len_utf8);
            }
        }
    }

    for stmt_raw in stmts {
        let stmt = stmt_raw.trim();
        let starts_import = stmt.starts_with("import")
            && stmt.as_bytes().get(6).map_or(false, |&b| !is_id(b));
        if !starts_import {
            continue;
        }
        let sb = stmt.as_bytes();
        let mut quoted: Vec<String> = Vec::new();
        let mut outside = String::with_capacity(stmt.len());
        let mut j = 0usize;
        let mut unclosed = false;
        while j < sb.len() {
            let b = sb[j];
            if b == b'"' || b == b'\'' {
                let q = b;
                j += 1;
                let q_start = j;
                let mut closed = false;
                while j < sb.len() {
                    if sb[j] == b'\\' && j + 1 < sb.len() {
                        let step = stmt[j + 1..].chars().next().map_or(1, char::len_utf8);
                        j += 1 + step;
                        continue;
                    }
                    if sb[j] == q {
                        quoted.push(stmt[q_start..j].to_string());
                        j += 1;
                        closed = true;
                        break;
                    }
                    j += stmt[j..].chars().next().map_or(1, char::len_utf8);
                }
                if !closed {
                    unclosed = true;
                    break;
                }
                outside.push(' ');
            } else {
                let ch = stmt[j..].chars().next().unwrap_or(' ');
                outside.push(ch);
                j += ch.len_utf8();
            }
        }
        if unclosed || quoted.len() != 1 {
            continue;
        }
        let path = &quoted[0];
        if !(path == "SafeERC20.sol" || path.ends_with("/SafeERC20.sol")) {
            continue;
        }
        // Reject any `as` alias/namespace clause outside quotes (`import "..." as Other`, `import { Evil as SafeERC20 }`, etc.)
        if has_word(&outside, "as") || outside.contains('*') {
            continue;
        }
        if outside.contains('{') || outside.contains('}') {
            let (Some(lb), Some(rb)) = (outside.find('{'), outside.rfind('}')) else {
                continue;
            };
            if rb <= lb {
                continue;
            }
            let inner = &outside[lb + 1..rb];
            if inner.contains('{') || inner.contains('}') {
                continue;
            }
            if outside[..lb].trim() != "import" || outside[rb + 1..].trim() != "from" {
                continue;
            }
            if inner.split(',').any(|item| item.trim() == "SafeERC20") {
                return true;
            }
        } else if outside.trim() == "import" {
            return true;
        }
    }
    false
}

fn has_local_safe_erc20_shadow(masked: &[String]) -> bool {
    let joined = masked.join("\n");
    let mut cur = 0usize;
    while let Some(p) = find_word_col(&joined, "SafeERC20", cur) {
        let before = joined[..p].trim_end();
        let after_raw = &joined[p + "SafeERC20".len()..];
        let after = after_raw.trim_start();
        let after_same_line = after_raw.split('\n').next().unwrap_or("").trim_start();
        let prev_word = before
            .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
            .next()
            .unwrap_or("");
        if matches!(
            prev_word,
            "library" | "contract" | "interface" | "struct" | "enum"
                | "function" | "modifier" | "event" | "error" | "type"
        ) {
            return true;
        }
        let followed_by_dot = after.starts_with('.');
        let followed_by_for = after.starts_with("for")
            && after.as_bytes().get(3).map_or(true, |&b| !is_id(b));
        if !followed_by_dot && !followed_by_for {
            if after.starts_with('=') && !after.starts_with("==") {
                return true;
            }
            let prev_byte = before.as_bytes().last().copied();
            let preceded_by_type_or_qual = prev_byte.is_some_and(|b| is_id(b) || b == b']' || b == b')')
                && !matches!(prev_word, "using" | "import" | "from" | "return");
            let followed_by_decl_delim = after.is_empty()
                || after_same_line.is_empty()
                || matches!(after.as_bytes()[0], b',' | b')' | b';' | b'=' | b'{' | b'}');
            if preceded_by_type_or_qual && followed_by_decl_delim {
                return true;
            }
        }
        cur = p + "SafeERC20".len();
    }
    false
}

fn is_valid_erc20_using_type(ty: &str) -> bool {
    if !is_simple_ident(ty) {
        return false;
    }
    if matches!(ty, "address" | "bool" | "string" | "bytes" | "uint" | "int" | "payable")
        || (ty.starts_with("uint") && ty.len() > 4 && ty[4..].bytes().all(|b| b.is_ascii_digit()))
        || (ty.starts_with("int") && ty.len() > 3 && ty[3..].bytes().all(|b| b.is_ascii_digit()))
        || (ty.starts_with("bytes") && ty.len() > 5 && ty[5..].bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    matches!(
        ty,
        "IERC20"
            | "IERC20Upgradeable"
            | "IERC20Metadata"
            | "IERC20MetadataUpgradeable"
            | "IERC20Permit"
            | "IERC20PermitUpgradeable"
            | "ERC20"
            | "ERC20Upgradeable"
            | "ERC20Permit"
            | "ERC20PermitUpgradeable"
    ) || ty.ends_with("ERC20")
        || ty.ends_with("ERC20Upgradeable")
}

fn parse_using_safe_erc20_type(stmt: &str, require_global: bool) -> Option<String> {
    let tokens: Vec<&str> = stmt.split_whitespace().collect();
    if tokens.len() < 4 || tokens[0] != "using" || tokens[1] != "SafeERC20" || tokens[2] != "for" {
        return None;
    }
    let ty = tokens[3];
    if require_global {
        if tokens.len() != 5 || tokens[4] != "global" {
            return None;
        }
    } else if tokens.len() != 4 {
        return None;
    }
    is_valid_erc20_using_type(ty).then(|| ty.to_string())
}

fn defines_local_safe_transfer_fn(s: &str) -> bool {
    let mut cur = 0usize;
    while let Some(fp) = find_word_col(s, "function", cur) {
        let after_fn = s[fp + 8..].trim_start();
        for name in ["safeTransferFrom", "safeTransfer"] {
            if let Some(tail) = after_fn.strip_prefix(name) {
                if tail.is_empty() || !is_id(tail.as_bytes()[0]) {
                    if tail.trim_start().starts_with('(') {
                        return true;
                    }
                }
            }
        }
        cur = fp + 8;
    }
    false
}

#[derive(Debug, Clone)]
struct SolContractScope {
    start: usize,
    end: usize,
    bound_types: BTreeSet<String>,
    defines_local_safe_transfer: bool,
    body_depth1_text: String,
}

fn extract_sol_scopes(masked: &[String]) -> (Vec<SolContractScope>, BTreeSet<String>, bool) {
    let mut contracts = Vec::new();
    let mut global_using = BTreeSet::new();
    let mut file_level_safe_transfer = false;
    let n = masked.len();

    let mut depth = 0usize;
    let mut file_stmt = String::new();
    let mut i = 0usize;
    while i < n {
        let mt = masked[i].trim();
        let is_contract_hdr = depth == 0
            && (has_word(mt, "contract") || has_word(mt, "library") || has_word(mt, "interface"))
            && !mt.starts_with("import")
            && !mt.starts_with("using")
            && !mt.starts_with("pragma");
        if is_contract_hdr {
            let (mut open_pos, mut pd) = (None, 0usize);
            'hdr: for h in i..n.min(i + 20) {
                for (bi, &b) in masked[h].as_bytes().iter().enumerate() {
                    if b == b'(' {
                        pd += 1;
                    } else if b == b')' {
                        pd = pd.saturating_sub(1);
                    } else if pd == 0 && b == b';' {
                        break 'hdr;
                    } else if pd == 0 && b == b'{' {
                        open_pos = Some((h, bi));
                        break 'hdr;
                    }
                }
            }
            if let Some((bl, oc)) = open_pos {
                let mut d = 0usize;
                let mut end = bl;
                let mut depth1_buf = String::new();
                'scan: for j in bl..n {
                    let bytes = masked[j].as_bytes();
                    let start_b = if j == bl { oc } else { 0 };
                    for &b in &bytes[start_b..] {
                        if b == b'{' {
                            d += 1;
                            if d == 2 {
                                depth1_buf.push(' ');
                            }
                        } else if b == b'}' {
                            d = d.saturating_sub(1);
                            if d == 0 {
                                end = j;
                                break 'scan;
                            }
                            if d == 1 {
                                depth1_buf.push(';');
                            }
                        } else if d == 1 {
                            depth1_buf.push(b as char);
                        }
                    }
                    if d == 1 {
                        depth1_buf.push('\n');
                    }
                    end = j;
                }
                let mut bound_types = BTreeSet::new();
                for stmt in depth1_buf.split(';') {
                    if let Some(ty) = parse_using_safe_erc20_type(stmt, false) {
                        bound_types.insert(ty);
                    }
                }
                let defines_local_safe_transfer = defines_local_safe_transfer_fn(&depth1_buf);
                contracts.push(SolContractScope {
                    start: i,
                    end,
                    bound_types,
                    defines_local_safe_transfer,
                    body_depth1_text: depth1_buf,
                });
                file_stmt.clear();
                i = end + 1;
                continue;
            }
        }
        // Track file-level statements (depth == 0)
        for &b in masked[i].as_bytes() {
            if b == b'{' {
                depth += 1;
                if depth == 1 && defines_local_safe_transfer_fn(&file_stmt) {
                    file_level_safe_transfer = true;
                }
                file_stmt.clear();
            } else if b == b'}' {
                depth = depth.saturating_sub(1);
            } else if depth == 0 {
                if b == b';' {
                    if let Some(ty) = parse_using_safe_erc20_type(&file_stmt, true) {
                        global_using.insert(ty);
                    }
                    if defines_local_safe_transfer_fn(&file_stmt) {
                        file_level_safe_transfer = true;
                    }
                    file_stmt.clear();
                } else {
                    file_stmt.push(b as char);
                }
            }
        }
        if depth == 0 {
            file_stmt.push(' ');
        }
        i += 1;
    }
    (contracts, global_using, file_level_safe_transfer)
}

fn is_this_or_super_recv(ml: &str, dot_pos: usize) -> bool {
    let mut trimmed = ml[..dot_pos].trim_end();
    while trimmed.ends_with(')') {
        let bytes = trimmed.as_bytes();
        let mut d = 0usize;
        let mut open = None;
        for i in (0..bytes.len()).rev() {
            if bytes[i] == b')' {
                d += 1;
            } else if bytes[i] == b'(' {
                d -= 1;
                if d == 0 {
                    open = Some(i);
                    break;
                }
            }
        }
        if let Some(op) = open {
            let before_op = trimmed[..op].trim_end();
            if before_op.as_bytes().last().is_some_and(|&b| is_id(b)) {
                break;
            }
            trimmed = trimmed[op + 1..trimmed.len() - 1].trim();
        } else {
            break;
        }
    }
    let bytes = trimmed.as_bytes();
    let mut start = bytes.len();
    while start > 0 && is_id(bytes[start - 1]) {
        start -= 1;
    }
    let ident = &trimmed[start..];
    matches!(ident, "this" | "super") && (start == 0 || bytes[start - 1] != b'.')
}

fn find_sol_var_declared_type(scope_text: &str, var: &str) -> Option<String> {
    let mut cur = 0usize;
    while let Some(p) = find_word_col(scope_text, var, cur) {
        let after = scope_text[p + var.len()..].trim_start();
        let is_decl_end = after.is_empty()
            || (matches!(after.as_bytes()[0], b',' | b')' | b';' | b'=') && !after.starts_with("=="));
        if is_decl_end {
            let before = scope_text[..p].trim_end();
            let seg_start = before
                .rfind(|c: char| matches!(c, '(' | ',' | ';' | '{' | '}' | '='))
                .map_or(0, |k| k + 1);
            let decl_prefix = before[seg_start..].trim();
            let parts: Vec<&str> = decl_prefix
                .split_whitespace()
                .filter(|tok| {
                    !matches!(
                        *tok,
                        "memory" | "calldata" | "storage" | "payable"
                            | "public" | "private" | "internal" | "immutable" | "constant"
                    )
                })
                .collect();
            if parts.len() == 1
                && is_simple_ident(parts[0])
                && !matches!(parts[0], "return" | "returns" | "delete" | "emit" | "using" | "for" | "is")
            {
                return Some(parts[0].to_string());
            }
        }
        cur = p + var.len();
    }
    None
}

fn extract_sol_cast_type_before_dot(ml: &str, dot_pos: usize) -> Option<String> {
    let mut trimmed = ml[..dot_pos].trim_end();
    loop {
        if !trimmed.ends_with(')') {
            return None;
        }
        let bytes = trimmed.as_bytes();
        let mut d = 0usize;
        let mut open = None;
        for i in (0..bytes.len()).rev() {
            if bytes[i] == b')' {
                d += 1;
            } else if bytes[i] == b'(' {
                d -= 1;
                if d == 0 {
                    open = Some(i);
                    break;
                }
            }
        }
        let op = open?;
        let before_op = trimmed[..op].trim_end();
        if before_op.as_bytes().last().is_some_and(|&b| is_id(b)) {
            let bb = before_op.as_bytes();
            let mut st = bb.len();
            while st > 0 && is_id(bb[st - 1]) {
                st -= 1;
            }
            if st > 0 && bb[st - 1] == b'.' {
                return None;
            }
            let ty = &before_op[st..];
            return is_simple_ident(ty).then(|| ty.to_string());
        }
        trimmed = trimmed[op + 1..trimmed.len() - 1].trim();
    }
}

fn find_safe_transfer_dot_cols(ml: &str) -> Vec<usize> {
    let mut dots = Vec::new();
    for needle in [".safeTransfer(", ".safeTransferFrom("] {
        let mut from = 0usize;
        while from < ml.len() {
            let Some(rel) = ml[from..].find(needle) else { break };
            let pos = from + rel;
            dots.push(pos);
            from = pos + needle.len();
        }
    }
    dots.sort_unstable();
    dots.dedup();
    dots
}

fn prove_solidity(raw: &[&str], masked: &[String], hash: &str) -> Vec<Obligation> {
    let mut out = Vec::new();
    let fake_nr = has_fake_nonreentrant_modifier(raw, masked);
    let safe_erc20_import = has_safe_erc20_import(raw);
    let safe_erc20_shadow = has_local_safe_erc20_shadow(masked);
    let (sol_contracts, global_using_types, file_level_safe_transfer) = extract_sol_scopes(masked);
    for blk in extract_functions(raw, masked, ExtLang::Solidity) {
        let enclosing_contract = sol_contracts
            .iter()
            .find(|c| blk.start >= c.start && blk.end <= c.end);
        let mut active_using_types: BTreeSet<&str> = global_using_types.iter().map(|s| s.as_str()).collect();
        if let Some(c) = enclosing_contract {
            for ty in &c.bound_types {
                active_using_types.insert(ty.as_str());
            }
        }
        let local_safe_transfer_defined = file_level_safe_transfer
            || enclosing_contract.is_some_and(|c| c.defines_local_safe_transfer);
        let fn_scope_text = masked[blk.start..=blk.end].join("\n");
        let has_nr = !fake_nr && has_nonreentrant_in_header_tail(masked, blk);
        let (mut has_low, mut has_eth, mut has_asm, mut in_loop, mut post_help) = (false, false, false, false, false);
        let (mut f_call, mut m_bef, mut m_aft, mut loop_d, mut rel_d) = (None, None, None, 0usize, 0usize);
        for l in blk.body_start..=blk.end {
            let ml = masked[l].as_str();
            let mt = ml.trim();
            if skip_fixture(raw[l]) || mt.is_empty() { continue; }
            if ml.contains("tx.origin") && (ml.contains("require(") || ml.contains("==") || ml.contains("!=") || mt.starts_with("if")) {
                let s = lspan(l, raw[l].len());
                out.push(mk_ob("SOL_REENTRANCY_CEI", ExtLang::Solidity, s, Some(s), Some("tx.origin".into()), hash, ObligationState::Violated, "tx.origin used for authorization (phishing/relay bypass)", "Replace tx.origin with msg.sender"));
            }
            if has_word(ml, "assembly") || ml.contains("delegatecall(") { has_asm = true; }
            let starts_loop = ["for ", "for(", "while ", "while(", "do ", "do{"].iter().any(|k| mt.starts_with(k)) || mt == "do";
            if starts_loop && loop_d == 0 { loop_d = rel_d + 1; }
            let eth_1 = find_sol_arity(raw, masked, l, ".transfer(").is_some_and(|(_, a)| a == 1);
            // Split top-level semicolons so `for (uint i = 0; i < n; i++)` isn't misread as top-level statements
            for stmt in split_top_level_by(ml, ";") {
                let st = stmt.trim();
                if st.is_empty() { continue; }
                let st_body = strip_sol_prefixes(st);
                if ["for ", "for(", "while ", "while(", "do ", "do{"].iter().any(|k| st_body.starts_with(k)) && loop_d == 0 {
                    loop_d = rel_d + 1;
                }
                let (low, eth) = (st.contains(".call{") || st.contains(".call("), st.contains(".send(") || (eth_1 && st.contains(".transfer(")));
                if low || eth {
                    if low { has_low = true; } else { has_eth = true; }
                    if f_call.is_none() { f_call = Some(l); }
                    if loop_d > 0 { in_loop = true; }
                } else if f_call.is_some() {
                    if is_sol_state_mut(st) && m_aft.is_none() { m_aft = Some(l); }
                    else if has_sol_post_helper_call(st) { post_help = true; }
                } else if is_sol_state_mut(st) && m_bef.is_none() {
                    m_bef = Some(l);
                }
            }
            for &b in ml.as_bytes() {
                if b == b'{' { rel_d += 1; } else if b == b'}' {
                    rel_d = rel_d.saturating_sub(1);
                    if loop_d > 0 && rel_d < loop_d { loop_d = 0; }
                }
            }
        }
        if let Some(fc) = f_call {
            let sink = lspan(fc, raw[fc].len());
            let (st, wit, bnd, rsn, hint) = if !blk.balanced || has_asm {
                (ObligationState::Unknown, None, None, "inline assembly, delegatecall, or unbalanced block prevents reentrancy proof", "Avoid assembly/delegatecall around value calls and use nonReentrant")
            } else if has_low && !has_nr && m_aft.is_some() {
                let m = m_aft.unwrap();
                (ObligationState::Violated, Some(lspan(m, raw[m].len())), None, "CEI violation: state mutated after external .call without nonReentrant guard", "Apply all state updates before .call or add nonReentrant modifier")
            } else if has_nr {
                (ObligationState::Proven, Some(lspan(blk.start, raw[blk.start].len())), Some("nonReentrant".into()), "explicit nonReentrant modifier verified on function header", "")
            } else if !in_loop && m_aft.is_none() && !post_help && (has_low || has_eth) {
                let w = m_bef.unwrap_or(fc);
                (ObligationState::Proven, Some(lspan(w, raw[w].len())), None, "strict checks-effects-interactions (CEI) order verified before external call", "")
            } else {
                (ObligationState::Unknown, None, None, "ambiguous loop or post-call helper prevents static CEI proof", "Add nonReentrant modifier and keep state mutations strictly before external calls")
            };
            out.push(mk_ob("SOL_REENTRANCY_CEI", ExtLang::Solidity, sink, wit, bnd, hash, st, rsn, hint));
        }

        for l in blk.body_start..=blk.end {
            let (ml, mt) = (masked[l].as_str(), masked[l].trim());
            if skip_fixture(raw[l]) || mt.is_empty() || mt.starts_with("emit ") || mt.starts_with("event ") { continue; }
            let sink = lspan(l, raw[l].len());
            let safe_dots = find_safe_transfer_dot_cols(ml);
            if !safe_dots.is_empty() {
                for dot_pos in safe_dots {
                    let recv = extract_ident_before_dot(ml, dot_pos);
                    let is_direct_lib = recv.as_deref() == Some("SafeERC20");
                    let is_self_member = is_this_or_super_recv(ml, dot_pos);
                    let recv_type_verified = if !is_direct_lib && !is_self_member {
                        let resolved_ty = if let Some(rv) = recv.as_deref() {
                            find_sol_var_declared_type(&fn_scope_text, rv).or_else(|| {
                                enclosing_contract
                                    .and_then(|c| find_sol_var_declared_type(&c.body_depth1_text, rv))
                            })
                        } else {
                            extract_sol_cast_type_before_dot(ml, dot_pos)
                        };
                        resolved_ty
                            .as_deref()
                            .is_some_and(|ty| active_using_types.contains(ty))
                    } else {
                        false
                    };
                    let (st, wit, bnd, rsn, hint) = if safe_erc20_shadow {
                        (
                            ObligationState::Unknown,
                            None,
                            None,
                            "SafeERC20 is locally defined/shadowed; cannot verify canonical SafeERC20",
                            "Import OpenZeppelin SafeERC20 instead of defining a local SafeERC20 shadow",
                        )
                    } else if is_direct_lib && safe_erc20_import {
                        (
                            ObligationState::Proven,
                            Some(sink),
                            Some("SafeERC20".into()),
                            "SafeERC20.safeTransfer/safeTransferFrom verified with SafeERC20 import",
                            "",
                        )
                    } else if !is_direct_lib
                        && safe_erc20_import
                        && !active_using_types.is_empty()
                        && !is_self_member
                        && !local_safe_transfer_defined
                        && recv_type_verified
                    {
                        (
                            ObligationState::Proven,
                            Some(sink),
                            Some("SafeERC20".into()),
                            "SafeERC20 safeTransfer/safeTransferFrom verified with import and contract-scoped ERC20 using-for binding",
                            "",
                        )
                    } else {
                        (
                            ObligationState::Unknown,
                            None,
                            None,
                            "safeTransfer/safeTransferFrom call lacks verified SafeERC20 import and contract-scoped ERC20 using-for binding",
                            "Import OpenZeppelin SafeERC20 and bind with 'using SafeERC20 for IERC20;' in the enclosing contract or call SafeERC20.safeTransfer/safeTransferFrom",
                        )
                    };
                    out.push(mk_ob("SOL_SAFE_ERC20", ExtLang::Solidity, sink, wit, bnd, hash, st, rsn, hint));
                }
            } else if ml.contains(".call(") && (ml.contains("abi.encodeWithSelector(") || ml.contains("abi.encodeWithSignature(")) {
                let req_ok = extract_sol_call_tuple(ml).is_some_and(|(ok_v, data_v)| {
                    (l..=blk.end).any(|k| {
                        let intervening_branch = ((l + 1)..k).any(|m| {
                            let tm = masked[m].trim();
                            tm.starts_with("if ") || tm.starts_with("if(") || tm.starts_with("else")
                                || tm.starts_with("return") || tm.contains('{') || tm.contains('}')
                        });
                        !intervening_branch
                            && matches_safe_erc20_require(raw, masked, k, &ok_v, &data_v)
                            && !is_var_reassigned_in_range(masked, l + 1, k, &ok_v)
                            && !is_var_reassigned_in_range(masked, l + 1, k, &data_v)
                    })
                });
                let (st, wit, rsn, hint) = if req_ok {
                    (ObligationState::Proven, Some(sink), "low-level ERC-20 call checks exact ok && (data.length == 0 || abi.decode(data, (bool)))", "")
                } else if !ml.contains('=') && !mt.starts_with("require(") {
                    (ObligationState::Violated, Some(sink), "low-level ERC-20 call ignores return tuple", "Verify (bool ok, bytes memory data) + require(ok && (data.length == 0 || abi.decode(data, (bool))))")
                } else {
                    (ObligationState::Unknown, None, "low-level ERC-20 call missing bound ok && (data.length == 0 || abi.decode) check", "Use SafeERC20 or check ok && (data.length == 0 || abi.decode(data, (bool)))")
                };
                out.push(mk_ob("SOL_SAFE_ERC20", ExtLang::Solidity, sink, wit, None, hash, st, rsn, hint));
            } else if let Some(pos) = find_sol_arity(raw, masked, l, ".transferFrom(").map(|(p, _)| p)
                .or_else(|| find_sol_arity(raw, masked, l, ".transfer(").and_then(|(p, a)| (a >= 2).then_some(p)))
            {
                let before = &ml[..pos];
                let pd: i32 = before.bytes().map(|b| if b == b'(' { 1 } else if b == b')' { -1 } else { 0 }).sum();
                let bare = !(before.contains('=') && !before.contains("==") && !before.contains("!="))
                    && pd <= 0
                    && !["return ", "require(", "assert(", "if"].iter().any(|k| mt.starts_with(k));
                let (st, wit, rsn) = if bare {
                    (ObligationState::Violated, Some(sink), "raw ERC-20 transfer/transferFrom ignores boolean return value")
                } else {
                    (ObligationState::Unknown, None, "raw ERC-20 transfer/transferFrom does not handle void-returning tokens")
                };
                out.push(mk_ob("SOL_SAFE_ERC20", ExtLang::Solidity, sink, wit, None, hash, st, rsn, "Use SafeERC20.safeTransfer / safeTransferFrom"));
            } else if l > blk.body_start && ml.contains('(') && !mt.starts_with("require(") && !mt.starts_with("function ") {
                let lo = mt.to_ascii_lowercase();
                if lo.contains("transfer") && !lo.contains(".transfer(") && !lo.contains("safetransfer") {
                    out.push(mk_ob("SOL_SAFE_ERC20", ExtLang::Solidity, sink, None, None, hash, ObligationState::Unknown, "ERC-20 transfer delegated to unresolved custom helper", "Use OpenZeppelin SafeERC20 directly"));
                }
            }
        }
    }
    out
}

/// Entry point wired into `obligation_prover::prove_file_obligations`.
pub fn prove_extended_obligations(file: &Path, raw: &[&str], masked: &[String], hash: &str) -> Vec<Obligation> {
    let lang = ExtLang::from_path(file);
    let mut out = Vec::new();
    match lang {
        ExtLang::TsxJsx => out.extend(prove_tsx_xss(raw, masked, hash)),
        ExtLang::Python | ExtLang::JsTs => {
            out.extend(prove_path_confine(raw, masked, lang, hash));
            out.extend(prove_crypto_mac_bidi(raw, masked, lang, hash));
        }
        ExtLang::Rust => out.extend(prove_path_confine(raw, masked, lang, hash)),
        ExtLang::Solidity => out.extend(prove_solidity(raw, masked, hash)),
        ExtLang::Other => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::ct2_seams::StatefulMasker;
    use crate::audit::obligation_prover::prove_file_obligations;

    fn run(name: &str, code: &str) -> Vec<Obligation> {
        prove_file_obligations(Path::new(name), code, &StatefulMasker::mask_file_lines(code))
    }

    #[test]
    fn extended_prover_matrix_positive_negative_bypasses_and_unknown() {
        let ok_tsx = run("Safe.tsx", "import DOMPurify from 'dompurify';\nexport function S({ h, url }: any) {\n  if (!url.startsWith(\"https://\")) return null;\n  return <a href={url} dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(h) }} />;\n}\n");
        assert!(ok_tsx.len() == 2 && ok_tsx.iter().all(|o| o.rule == "TSX_XSS" && o.state == ObligationState::Proven));
        let dom = run("Dom.jsx", "export function D(el, raw) { el.innerHTML = raw; el.innerHTML = \"\"; }\n");
        assert_eq!((dom.len(), dom[0].state), (1, ObligationState::Violated));
        let low = run("PayLow.sol", "contract P {\n  function pay(address t, address to, uint256 a) external {\n    (bool ok, bytes memory data) = t.call(abi.encodeWithSelector(0xa9059cbb, to, a));\n    require(ok && (data.length == 0 || abi.decode(data, (bool))));\n  }\n}\n");
        assert!(low.iter().any(|o| o.rule == "SOL_SAFE_ERC20" && o.state == ObligationState::Proven));

        for (f, rule, code, exp) in [
            ("Inl.tsx", "TSX_XSS", "export const L = ({ u }: any) => <a href={isSafeHttpUrl(u) ? u : '#'}>x</a>;\n", ObligationState::Proven),
            ("Bad.tsx", "TSX_XSS", "export const B = ({ r }: any) => <div dangerouslySetInnerHTML={{ __html: r }} />;\n", ObligationState::Violated),
            ("Cat.tsx", "TSX_XSS", "export const B = ({ r, x }: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) + x }} />;\n", ObligationState::Violated),
            ("Sh1.tsx", "TSX_XSS", "const DOMPurify = { sanitize: (x: string) => x };\nexport const B = ({ r }: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) }} />;\n", ObligationState::Violated),
            ("Sh2.tsx", "TSX_XSS", "export function B({ DOMPurify, r }: any) { return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) }} />; }\n", ObligationState::Violated),
            ("Sp.tsx", "TSX_XSS", "export const U = ({ obj }: any) => <div dangerouslySetInnerHTML={obj} />;\n", ObligationState::Unknown),
            ("HrefU.tsx", "TSX_XSS", "export const L = ({ userUrl }: any) => <a href={userUrl}>go</a>;\n", ObligationState::Unknown),
            ("HrefMis.tsx", "TSX_XSS", "export const L = ({ other, userUrl }: any) => <a href={isSafeHttpUrl(other) ? userUrl : '#'}>go</a>;\n", ObligationState::Unknown),
            ("Js.tsx", "TSX_XSS", "export const L = () => <a href=\"javascript:alert(1)\">x</a>;\n", ObligationState::Violated),
            ("safe.py", "PATH_CONFINE", "import os\ndef save(root, rel, d):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    if not t.startswith(r + os.sep) or os.path.islink(t): raise ValueError()\n    with open(t, 'w') as f: f.write(d)\n", ObligationState::Proven),
            ("pl.py", "PATH_CONFINE", "from pathlib import Path\ndef save(root, rel, d):\n    r = Path(root).resolve()\n    t = (r / rel).resolve()\n    assert t.is_relative_to(r) and not t.is_symlink()\n    t.write_text(d)\n", ObligationState::Proven),
            ("fd.py", "PATH_CONFINE", "import os\ndef save(root, rel):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    assert t.startswith(r + os.sep)\n    return os.open(t, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW)\n", ObligationState::Proven),
            ("sib.py", "PATH_CONFINE", "import os\ndef save(root, rel, d):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    if not t.startswith(r) or os.path.islink(t): raise ValueError()\n    open(t, 'w').write(d)\n", ObligationState::Violated),
            ("ronly.py", "PATH_CONFINE", "import os\ndef save(root, rel, d):\n    r = os.path.realpath(root)\n    t = os.path.join(r, rel)\n    if not t.startswith(r + os.sep) or os.path.islink(t): raise ValueError()\n    open(t, 'w').write(d)\n", ObligationState::Violated),
            ("noc.py", "PATH_CONFINE", "import os\ndef save(root, rel, d):\n    t = os.path.join(root, rel)\n    open(t, 'w').write(d)\n", ObligationState::Violated),
            ("nosym.ts", "PATH_CONFINE", "import fs from 'fs';\nimport path from 'path';\nfunction save(root: string, rel: string, data: string) {\n  const r = fs.realpathSync(root);\n  const t = fs.realpathSync(path.join(r, rel));\n  if (!t.startsWith(r + path.sep)) throw new Error('esc');\n  fs.writeFileSync(t, data);\n}\n", ObligationState::Unknown),
            ("safe.rs", "PATH_CONFINE", "use std::path::Path;\nfn save(root: &Path, rel: &Path, data: &[u8]) {\n    let r = std::fs::canonicalize(root).unwrap();\n    let t = std::fs::canonicalize(r.join(rel)).unwrap();\n    assert!(t.starts_with(&r));\n    assert!(!std::fs::symlink_metadata(&t).unwrap().file_type().is_symlink());\n    let _ = std::fs::write(&t, data);\n}\n", ObligationState::Proven),
            ("ok.py", "CRYPTO_MAC_BIDI", "import hmac, hashlib\ndef verify(k, m, sig):\n    if len(sig) == 0 or sig == b\"\" or sig == \"\": return False\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return hmac.compare_digest(sig, mac)\n", ObligationState::Proven),
            ("ok.ts", "CRYPTO_MAC_BIDI", "import crypto from 'crypto';\nfunction verify(k: string, m: string, sig: string) {\n  if (sig === '') return false;\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  const a = Buffer.from(sig); const b = Buffer.from(d);\n  if (a.length !== b.length) return false;\n  return crypto.timingSafeEqual(a, b);\n}\n", ObligationState::Proven),
            ("bad.py", "CRYPTO_MAC_BIDI", "import hmac, hashlib\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return sig == mac\n", ObligationState::Violated),
            ("dual.py", "CRYPTO_MAC_BIDI", "import hmac, hashlib\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return sig == mac and hmac.compare_digest(sig, mac)\n", ObligationState::Violated),
            ("sh.py", "CRYPTO_MAC_BIDI", "import hmac, hashlib\ncompare_digest = lambda a, b: a == b\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return compare_digest(sig, mac)\n", ObligationState::Violated),
            ("bad.ts", "CRYPTO_MAC_BIDI", "import crypto from 'crypto';\nfunction verify(k: string, m: string, sig: string) {\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  return sig !== d;\n}\n", ObligationState::Violated),
            ("unk.py", "CRYPTO_MAC_BIDI", "import hmac, hashlib\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return custom_verify(sig, mac)\n", ObligationState::Unknown),
            ("Bad.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function withdraw(uint256 a) external {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n    balances[msg.sender] -= a;\n  }\n}\n", ObligationState::Violated),
            ("One.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function withdraw(uint256 a) external {\n    (bool ok, ) = msg.sender.call{value: a}(\"\"); balances[msg.sender] = 0;\n  }\n}\n", ObligationState::Violated),
            ("Cei.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function withdraw(uint256 a) external {\n    balances[msg.sender] -= a;\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n  }\n}\n", ObligationState::Proven),
            ("Nr.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function withdraw(uint256 a) external nonReentrant {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n    balances[msg.sender] -= a;\n  }\n}\n", ObligationState::Proven),
            ("Asm.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function withdraw(uint256 a) external nonReentrant {\n    assembly { pop(0) }\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n  }\n}\n", ObligationState::Unknown),
            ("Del.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function run(address t) external nonReentrant {\n    (bool ok, ) = t.delegatecall(\"\");\n    (bool ok2, ) = msg.sender.call{value: 1}(\"\");\n    require(ok && ok2);\n  }\n}\n", ObligationState::Unknown),
            ("Post.sol", "SOL_REENTRANCY_CEI", "contract V {\n  function run(address to) external {\n    (bool ok, ) = to.call{value: 1}(\"\");\n    require(ok);\n    _settleAfter(msg.sender);\n  }\n}\n", ObligationState::Unknown),
            ("Txo.sol", "SOL_REENTRANCY_CEI", "contract A {\n  function sweep() external { require(tx.origin == owner); }\n}\n", ObligationState::Violated),
            ("Pay.sol", "SOL_SAFE_ERC20", "contract P {\n  function pay(address t, address to, uint256 a) external {\n    IERC20(t).transfer(to, a);\n  }\n}\n", ObligationState::Violated),
            ("PayReq.sol", "SOL_SAFE_ERC20", "contract P {\n  function pay(address t, address to, uint256 a) external {\n    require(IERC20(t).transfer(to, a));\n  }\n}\n", ObligationState::Unknown),
            ("PaySafe.sol", "SOL_SAFE_ERC20", "contract P {\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransferFrom(msg.sender, to, a);\n  }\n}\n", ObligationState::Unknown),
            ("PaySafeBound.sol", "SOL_SAFE_ERC20", "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransferFrom(msg.sender, to, a);\n  }\n}\n", ObligationState::Proven),
            ("PaySafeDirect.sol", "SOL_SAFE_ERC20", "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  function pay(IERC20 t, address to, uint256 a) external {\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n", ObligationState::Proven),
            ("PayHelp.sol", "SOL_SAFE_ERC20", "contract P {\n  function pay(address t, address to, uint256 a) external {\n    _customTransfer(t, to, a);\n  }\n}\n", ObligationState::Unknown),
        ] {
            let r = run(f, code);
            assert_eq!((r[0].rule, r[0].state), (rule, exp), "{f}");
        }
    }

    #[test]
    fn utf8_multibyte_pocs_never_panic_and_emit_exact_obligations() {
        // PoC #2.1: 2-byte UTF-8 inside SQL literal
        let r1 = run("utf8_sql.py", "def q(cur, uid):\n    cur.execute(\"SELECT 'café' FROM u WHERE id = ?\", (uid,))\n");
        assert_eq!((r1.len(), r1[0].rule, r1[0].state), (1, "SQL_EXEC", ObligationState::Proven));

        // PoC #2.2: 2-byte UTF-8 inside open() and dangerouslySetInnerHTML
        let _r2a = run("utf8_open.py", "import os\ndef f(r):\n    os.path.realpath(r)\n    open(\"café\", \"w\").write(\"x\")\n");
        let r2b = run("Utf8Dp.tsx", "import DOMPurify from 'dompurify';\nexport const C = () => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(\"café\") }} />;\n");
        assert_eq!((r2b.len(), r2b[0].state), (1, ObligationState::Proven));
        let r2c = run("Utf8EmojiDp.tsx", "import DOMPurify from 'dompurify';\nexport const C = () => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(\"🚀\") }} />;\n");
        assert_eq!((r2c.len(), r2c[0].state), (1, ObligationState::Proven));

        // PoC #2.3: 4-byte emoji block comment before assignment and writeFileSync
        let _r3 = run("utf8_cmt.ts", "import fs from 'fs';\nfunction f() { /* 🚀🚀🚀 */ x=1; fs.writeFileSync(x, \"a\"); }\n");

        // PoC #2.4: 4-byte emoji attribute before javascript: href MUST emit VIOLATED (NOT 0 obligations!)
        let r4 = run("Utf8Href.tsx", "export const X = () => <a title=\"🚀\" href=\"javascript:alert(1)\">click</a>;\n");
        assert_eq!(r4.len(), 1, "must emit VIOLATED obligation after emoji attribute");
        assert_eq!((r4[0].rule, r4[0].state), ("TSX_XSS", ObligationState::Violated));
    }

    #[test]
    fn tsx_xss_adversarial_bypasses_never_proven() {
        // Comment spoof `// u.startsWith("https://")`
        let c1 = run("CmtSpoof.tsx", "export function C({ u }: any) {\n  // u.startsWith(\"https://\")\n  return <a href={u}>go</a>;\n}\n");
        assert_ne!(c1[0].state, ObligationState::Proven);

        // Negated inline ternary `!isSafeHttpUrl(u) ? u : '#'`
        let c2 = run("NegTern.tsx", "export const C = ({ u }: any) => <a href={!isSafeHttpUrl(u) ? u : '#'}>go</a>;\n");
        assert_eq!(c2[0].state, ObligationState::Violated);

        // Unsafe false branch `isSafeHttpUrl(safe) ? safe : evil`
        let c3 = run("BadFalse.tsx", "export const C = ({ safe, evil }: any) => <a href={isSafeHttpUrl(safe) ? safe : evil}>go</a>;\n");
        assert_ne!(c3[0].state, ObligationState::Proven);

        // Compound expression `safe ? evil : "#"` with prior guard on `safe`
        let c4 = run("CompPrior.tsx", "export function C({ safe, evil }: any) {\n  if (!isSafeHttpUrl(safe)) return null;\n  return <a href={safe ? evil : \"#\"}>go</a>;\n}\n");
        assert_ne!(c4[0].state, ObligationState::Proven);

        // Non-early-exit prior check `const ok = isSafeHttpUrl(u)`
        let c5 = run("NoExit.tsx", "export function C({ u }: any) {\n  const ok = isSafeHttpUrl(u);\n  return <a href={u}>go</a>;\n}\n");
        assert_ne!(c5[0].state, ObligationState::Proven);

        // Reassigned variable after guard
        let c5b = run("Reassign.tsx", "export function C({ u, evil }: any) {\n  if (!isSafeHttpUrl(u)) return null;\n  u = evil;\n  return <a href={u}>go</a>;\n}\n");
        assert_ne!(c5b[0].state, ObligationState::Proven);

        // Non-dominating guard inside conditional branch & conditional inner exit
        let c5c = run("NonDom.tsx", "export function C({ u, flag }: any) {\n  if (flag) {\n    if (!isSafeHttpUrl(u)) return null;\n  }\n  return <a href={u}>go</a>;\n}\n");
        assert_ne!(c5c[0].state, ObligationState::Proven);
        let c5d = run("CondExit.tsx", "export function C({ u, debug }: any) {\n  if (!isSafeHttpUrl(u)) {\n    if (debug) return null;\n  }\n  return <a href={u}>go</a>;\n}\n");
        assert_ne!(c5d[0].state, ObligationState::Proven);

        // Cross-component bleed `Safe` -> `Evil`
        let c6 = run("Bleed.tsx", "export const Safe = ({ u }: any) => {\n  if (!isSafeHttpUrl(u)) return null;\n  return <a href={u}>ok</a>;\n};\nexport const Evil = ({ u }: any) => <a href={u}>evil</a>;\n");
        assert_eq!(c6.len(), 2);
        assert_eq!(c6[0].state, ObligationState::Proven);
        assert_ne!(c6[1].state, ObligationState::Proven);

        // Shadow PoC 1: `DOMPurify.sanitize = (x) => x` dot-LHS mutation (even with import!)
        let s1 = run("DotSh.tsx", "import DOMPurify from 'dompurify';\nDOMPurify.sanitize = (x: string) => x;\nexport const B = ({ r }: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) }} />;\n");
        assert_eq!(s1[0].state, ObligationState::Violated);

        // Shadow PoC 2: `const { DOMPurify } = fake` destructuring
        let s2 = run("DestrSh.tsx", "const { DOMPurify } = fake;\nexport const B = ({ r }: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) }} />;\n");
        assert_eq!(s2[0].state, ObligationState::Violated);

        // Shadow PoC 3: multi-line param `{ DOMPurify, r }`
        let s3 = run("MlParamSh.tsx", "import DOMPurify from 'dompurify';\nexport function B({\n  DOMPurify,\n  r,\n}: any) {\n  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) }} />;\n}\n");
        assert_eq!(s3[0].state, ObligationState::Violated);

        // Shadow PoC 4: multi-line `function isSafeHttpUrl(...) {\n return true;\n}`
        let s4 = run("MlUrlSh.tsx", "function isSafeHttpUrl(u: string) {\n  return true;\n}\nexport const L = ({ u }: any) => <a href={isSafeHttpUrl(u) ? u : '#'}>go</a>;\n");
        assert_ne!(s4[0].state, ObligationState::Proven);

        // Missing DOMPurify import
        let s5 = run("NoImp.tsx", "export const B = ({ r }: any) => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(r) }} />;\n");
        assert_ne!(s5[0].state, ObligationState::Proven);

        // `data:text/html` inside JSX `{...}` expression
        let d1 = run("DataHref.tsx", "export const L = () => <a href={\"data:text/html,<script>alert(1)</script>\"}>go</a>;\n");
        assert_eq!(d1[0].state, ObligationState::Violated);
    }

    #[test]
    fn path_confine_adversarial_bypasses_never_proven() {
        // PoC #4.1: Different variable checked (`safe`) vs written (`evil`)
        let p1 = run("diff_var.py", "import os\ndef save(root, rel, evil, d):\n    r = os.path.realpath(root)\n    safe = os.path.realpath(os.path.join(r, rel))\n    if not safe.startswith(r + os.sep) or os.path.islink(safe): raise ValueError()\n    open(evil, 'w').write(d)\n");
        assert_ne!(p1[0].state, ObligationState::Proven);

        // PoC #4.2: Python uncanonicalized `r / rel` with `.is_relative_to(r)`
        let p2 = run("py_div.py", "from pathlib import Path\ndef save(root, rel, d):\n    r = Path(root).resolve()\n    t = r / rel\n    assert t.is_relative_to(r) and not t.is_symlink()\n    t.write_text(d)\n");
        assert_eq!(p2[0].state, ObligationState::Violated);

        // PoC #4.3: JS/TS `Promise.resolve()` + lexical-only `path.resolve(...)`
        let p3 = run("promise_res.ts", "import fs from 'fs';\nimport path from 'path';\nasync function save(root: string, rel: string, data: string) {\n  await Promise.resolve();\n  const r = path.resolve(root);\n  const t = path.resolve(r, rel);\n  if (!t.startsWith(r + path.sep) || fs.lstatSync(t).isSymbolicLink()) throw new Error('esc');\n  fs.writeFileSync(t, data);\n}\n");
        assert_ne!(p3[0].state, ObligationState::Proven);

        // PoC #4.4: Non-rejecting prefix/symlink check
        let p4 = run("non_rej.py", "import os\ndef save(root, rel, d):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    ok = t.startswith(r + os.sep)\n    sym = os.path.islink(t)\n    open(t, 'w').write(d)\n");
        assert_ne!(p4[0].state, ObligationState::Proven);

        // PoC #4.4b: Non-dominating guard inside conditional branch
        let p4b = run("non_dom.py", "import os\ndef save(root, rel, flag, d):\n    r = os.path.realpath(root)\n    t = os.path.realpath(os.path.join(r, rel))\n    if flag:\n        assert t.startswith(r + os.sep) and not os.path.islink(t)\n    open(t, 'w').write(d)\n");
        assert_ne!(p4b[0].state, ObligationState::Proven);

        // PoC #4.5: Rust `Path` converted via `to_string_lossy` / `to_str` on a prior line
        let p5a = run("rust_lossy.rs", "use std::path::Path;\nfn save(root: &Path, rel: &Path, data: &[u8]) {\n    let r = std::fs::canonicalize(root).unwrap();\n    let t = std::fs::canonicalize(r.join(rel)).unwrap();\n    let ts = t.to_string_lossy();\n    let rs = r.to_string_lossy();\n    assert!(ts.starts_with(rs.as_ref()));\n    assert!(!std::fs::symlink_metadata(&t).unwrap().file_type().is_symlink());\n    let _ = std::fs::write(&t, data);\n}\n");
        assert_eq!(p5a[0].state, ObligationState::Violated);

        let p5b = run("rust_tostr.rs", "use std::path::Path;\nfn save(root: &Path, rel: &Path, data: &[u8]) {\n    let r = std::fs::canonicalize(root).unwrap();\n    let t = std::fs::canonicalize(r.join(rel)).unwrap();\n    let _s = t.to_str().unwrap();\n    assert!(t.starts_with(&r));\n    assert!(!std::fs::symlink_metadata(&t).unwrap().file_type().is_symlink());\n    let _ = std::fs::write(&t, data);\n}\n");
        assert_ne!(p5b[0].state, ObligationState::Proven);
    }

    #[test]
    fn solidity_cei_and_safe_erc20_adversarial_bypasses_never_proven() {
        // PoC #5.1: Parameter named `nonReentrant`
        let s1 = run("ParamNr.sol", "contract V {\n  function withdraw(uint256 a, bool nonReentrant) external {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n    balances[msg.sender] -= a;\n  }\n}\n");
        assert_eq!(s1[0].state, ObligationState::Violated);

        // PoC #5.2: Empty `modifier nonReentrant() { _; }` with no lock state
        let s2 = run("EmptyNr.sol", "contract V {\n  modifier nonReentrant() { _; }\n  function withdraw(uint256 a) external nonReentrant {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok);\n    balances[msg.sender] -= a;\n  }\n}\n");
        assert_eq!(s2[0].state, ObligationState::Violated);

        // PoC #5.3: `if (ok) balances[msg.sender] = 0;`, `unchecked { ... }`, `++`/`--`
        let s3a = run("IfMut.sol", "contract V {\n  function withdraw(uint256 a) external {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    if (ok) balances[msg.sender] = 0;\n  }\n}\n");
        assert_eq!(s3a[0].state, ObligationState::Violated);

        let s3b = run("UnchInc.sol", "contract V {\n  function claim() external {\n    (bool ok, ) = msg.sender.call{value: 1}(\"\");\n    require(ok);\n    unchecked { claimed[msg.sender]++; }\n  }\n}\n");
        assert_eq!(s3b[0].state, ObligationState::Violated);

        // PoC #5.4: Nested helper inside `require(ok && _deductBalance(...))`
        let s4 = run("ReqHelp.sol", "contract V {\n  function withdraw(uint256 a) external {\n    (bool ok, ) = msg.sender.call{value: a}(\"\");\n    require(ok && _deductBalance(msg.sender, a));\n  }\n}\n");
        assert_eq!(s4[0].state, ObligationState::Unknown);

        // PoC #5.5: `do { ... } while` loop around external call
        let s5 = run("DoLoop.sol", "contract V {\n  function drain(uint256 n) external {\n    do {\n      (bool ok, ) = msg.sender.call{value: 1}(\"\");\n      require(ok);\n    } while (n > 0);\n  }\n}\n");
        assert_eq!(s5[0].state, ObligationState::Unknown);

        // PoC #5.6: Cross-call `ok1`/`ok2` bleed in `SOL_SAFE_ERC20`
        let s6 = run("CrossOk.sol", "contract P {\n  function pay(address t1, address t2, address to, uint256 a) external {\n    (bool ok1, bytes memory data1) = t1.call(abi.encodeWithSelector(0xa9059cbb, to, a));\n    (bool ok2, bytes memory data2) = t2.call(abi.encodeWithSelector(0xa9059cbb, to, a));\n    require(ok2 && (data2.length == 0 || abi.decode(data2, (bool))));\n  }\n}\n");
        let erc20_obs: Vec<_> = s6.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
        assert_eq!(erc20_obs.len(), 2);
        assert_eq!(erc20_obs[0].state, ObligationState::Unknown, "unchecked ok1 must never be PROVEN");
        assert_eq!(erc20_obs[1].state, ObligationState::Proven, "checked ok2 stays PROVEN");

        // PoC #5.7: Inverted `require(ok || (data.length == 0 && abi.decode(...)))`
        let s7 = run("InvErc.sol", "contract P {\n  function pay(address t, address to, uint256 a) external {\n    (bool ok, bytes memory data) = t.call(abi.encodeWithSelector(0xa9059cbb, to, a));\n    require(ok || (data.length == 0 && abi.decode(data, (bool))));\n  }\n}\n");
        let erc7: Vec<_> = s7.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
        assert_eq!(erc7[0].state, ObligationState::Unknown);

        // PoC #5.8 (HIGH #2): Unbound / shadowed SafeERC20 calls MUST NEVER return PROVEN!
        for (fname, src) in [
            (
                "UnboundMember.sol",
                "contract P {\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransferFrom(msg.sender, to, a);\n  }\n}\n",
            ),
            (
                "ImportNoUsing.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "UsingNoImport.sol",
                "contract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "DirectNoImport.sol",
                "contract P {\n  function pay(IERC20 t, address to, uint256 a) external {\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n",
            ),
            (
                "LocalShadowLib.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\nlibrary SafeERC20 {\n  function safeTransferFrom(IERC20, address, address, uint256) internal {}\n}\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransferFrom(msg.sender, to, a);\n  }\n}\n",
            ),
            (
                "CommentSpoofSafe.sol",
                "// import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\n// using SafeERC20 for IERC20;\ncontract P {\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransferFrom(msg.sender, to, a);\n  }\n}\n",
            ),
        ] {
            let obs = run(fname, src);
            let erc: Vec<_> = obs.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
            assert!(!erc.is_empty(), "{fname}: expected SOL_SAFE_ERC20 obligation");
            assert_eq!(erc[0].state, ObligationState::Unknown, "{fname}: must be UNKNOWN, never PROVEN");
        }

        // Positive control: canonical OpenZeppelin import + using SafeERC20 for IERC20 -> PROVEN
        let s_pos = run(
            "OzSafe.sol",
            "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransferFrom(msg.sender, to, a);\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n",
        );
        let erc_pos: Vec<_> = s_pos.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
        assert_eq!(erc_pos.len(), 2);
        assert!(erc_pos.iter().all(|o| o.state == ObligationState::Proven));
    }

    #[test]
    fn crypto_mac_bidi_adversarial_bypasses_never_proven() {
        // PoC #6.1: Multi-comparison ternary + Buffer `.equals(`
        let m1a = run("tern_eq.ts", "import crypto from 'crypto';\nfunction verify(k: string, m: string, sig: string) {\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  const a = Buffer.from(sig); const b = Buffer.from(d);\n  return a.length === b.length ? sig === d : false;\n}\n");
        assert_eq!(m1a[0].state, ObligationState::Violated);

        let m1b = run("buf_eq.ts", "import crypto from 'crypto';\nfunction verify(k: string, m: string, sig: string) {\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  const a = Buffer.from(sig); const b = Buffer.from(d);\n  return a.length === b.length ? a.equals(b) : false;\n}\n");
        assert_eq!(m1b[0].state, ObligationState::Violated);

        // PoC #6.2: Shadow variants (`compare_digest=lambda`, `: Type`, `var`, `as compare_digest`, param shadowing)
        for (name, code) in [
            ("sh_nospace.py", "import hmac, hashlib\ncompare_digest=lambda a, b: a == b\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return compare_digest(sig, mac)\n"),
            ("sh_as.py", "import hmac, hashlib\nfrom fake import eq as compare_digest\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return compare_digest(sig, mac)\n"),
            ("sh_param.py", "import hmac, hashlib\ndef verify(k, m, sig, compare_digest=lambda a, b: a == b):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return compare_digest(sig, mac)\n"),
            ("sh_type.ts", "import crypto from 'crypto';\nconst timingSafeEqual: any = () => true;\nfunction verify(k: string, m: string, sig: string) {\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  return timingSafeEqual(Buffer.from(sig), Buffer.from(d));\n}\n"),
            ("sh_var.ts", "import crypto from 'crypto';\nvar timingSafeEqual = () => true;\nfunction verify(k: string, m: string, sig: string) {\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  return timingSafeEqual(Buffer.from(sig), Buffer.from(d));\n}\n"),
            ("sh_imp.py", "import hmac, hashlib\nfrom fake_hmac import compare_digest\ndef verify(k, m, sig):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return compare_digest(sig, mac)\n"),
            ("sh_imp.ts", "import crypto from 'crypto';\nimport { timingSafeEqual } from './fake-crypto';\nfunction verify(k: string, m: string, sig: string) {\n  const d = crypto.createHmac('sha256', k).update(m).digest('hex');\n  return timingSafeEqual(Buffer.from(sig), Buffer.from(d));\n}\n"),
        ] {
            let r = run(name, code);
            assert_eq!(r[0].state, ObligationState::Violated, "{name} must be VIOLATED");
        }

        // PoC #6.3: Subscript-assigned digest (`d["x"] = hmac.new(...)`) & `secret`/`token` comparison
        let m3a = run("sub_mac.py", "import hmac, hashlib\ndef verify(k, m, u):\n    d = {}\n    d[\"x\"] = hmac.new(k, m, hashlib.sha256).hexdigest()\n    return d[\"x\"] == u\n");
        assert_eq!(m3a[0].state, ObligationState::Violated);

        let m3b = run("tok_sec.py", "import hmac, hashlib\ndef verify(k, m, sig, caller_token, api_secret):\n    mac = hmac.new(k, m, hashlib.sha256).hexdigest()\n    if caller_token == api_secret:\n        return True\n    return hmac.compare_digest(sig, mac)\n");
        assert_eq!(m3b[0].state, ObligationState::Violated);
    }

    #[test]
    fn sol_safe_erc20_round2_four_bypass_classes_never_proven() {
        for (fname, src) in [
            // (a) Import path / namespace spoofs
            (
                "ImportDirSpoof.sol",
                "import { Evil } from \"./SafeERC20/Evil.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "ImportNsAlias.sol",
                "import \"./SafeERC20.sol\" as Other;\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "ImportEvilAlias.sol",
                "import { Evil as SafeERC20 } from \"./SafeERC20/fake.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n",
            ),
            // (b) Cross-contract `using` bleed
            (
                "CrossContractUsing.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract A {\n  using SafeERC20 for IERC20;\n}\ncontract B {\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            // (c) Wrong `using-for` type, `this`/`super`, and local `function safeTransfer(...)`
            (
                "UsingUint256.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for uint256;\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "ThisSafeTransfer.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(address to, uint256 a) external {\n    this.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "LocalFnSafeTransfer.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function safeTransfer(address to, uint256 a) public {}\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
            ),
            // (d) Typed variable / parameter / state variable shadow
            (
                "ParamShadow.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  function pay(IFake SafeERC20, IERC20 t, address to, uint256 a) external {\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n",
            ),
            (
                "StateVarShadow.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  IFake SafeERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n",
            ),
            (
                "PublicStateShadow.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  IFake public SafeERC20;\n  function pay(IERC20 t, address to, uint256 a) external {\n    SafeERC20.safeTransfer(t, to, a);\n  }\n}\n",
            ),
            // (e) Fail-closed receiver typing: cast/indexed/chained/inherited non-ERC20 receivers MUST be Unknown
            (
                "CastEvilRecv.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ninterface IEvil { function safeTransfer(address to, uint256 a) external; }\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(address evilAddr, address to, uint256 a) external {\n    IEvil(evilAddr).safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "MappedEvilRecv.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  mapping(uint256 => IEvil) public evilMap;\n  function pay(address to, uint256 a) external {\n    evilMap[0].safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "ChainedStructRecv.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  struct Cfg { IEvil tok; }\n  Cfg internal cfg;\n  function pay(address to, uint256 a) external {\n    cfg.tok.safeTransfer(to, a);\n  }\n}\n",
            ),
            (
                "InheritedEvilRecv.sol",
                "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract Base { IEvil internal inheritedEvil; }\ncontract P is Base {\n  using SafeERC20 for IERC20;\n  function pay(address to, uint256 a) external {\n    inheritedEvil.safeTransfer(to, a);\n  }\n}\n",
            ),
        ] {
            let obs = run(fname, src);
            let erc: Vec<_> = obs.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
            assert!(!erc.is_empty(), "{fname}: expected SOL_SAFE_ERC20 obligation");
            assert!(
                erc.iter().all(|o| o.state == ObligationState::Unknown),
                "{fname}: all obligations must be Unknown (never Proven): {:?}",
                erc
            );
        }

        // Positive controls: global `using SafeERC20 for IERC20 global;` + explicit `IERC20(addr).safeTransfer(...)` cast remain PROVEN!
        let pos_global = run(
            "GlobalUsing.sol",
            "import { SafeERC20 } from \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\nusing SafeERC20 for IERC20 global;\ncontract B {\n  function pay(IERC20 t, address to, uint256 a) external {\n    t.safeTransfer(to, a);\n  }\n}\n",
        );
        let erc_g: Vec<_> = pos_global.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
        assert_eq!((erc_g.len(), erc_g[0].state), (1, ObligationState::Proven));

        let pos_cast = run(
            "ExplicitCastUsing.sol",
            "import \"@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol\";\ncontract P {\n  using SafeERC20 for IERC20;\n  function pay(address tokenAddr, address to, uint256 a) external {\n    IERC20(tokenAddr).safeTransfer(to, a);\n  }\n}\n",
        );
        let erc_c: Vec<_> = pos_cast.iter().filter(|o| o.rule == "SOL_SAFE_ERC20").collect();
        assert_eq!((erc_c.len(), erc_c[0].state), (1, ObligationState::Proven));
    }

    #[test]
    fn path_confine_same_line_double_write_emits_both_obligations() {
        let code = "import os\ndef save(root, rel, u, d):\n    r = os.path.realpath(root)\n    safe_p = os.path.realpath(os.path.join(r, rel))\n    if not safe_p.startswith(r + os.sep) or os.path.islink(safe_p): raise ValueError()\n    open(safe_p, \"w\"); open(os.path.join(root, u), \"w\")\n";
        let obs = run("double_write.py", code);
        let pc: Vec<_> = obs.iter().filter(|o| o.rule == "PATH_CONFINE").collect();
        assert_eq!(pc.len(), 2, "must emit BOTH PATH_CONFINE obligations on same line: {:?}", pc);
        assert_eq!(pc[0].state, ObligationState::Proven);
        assert_eq!(pc[1].state, ObligationState::Violated);
    }
}
