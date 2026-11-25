// kintsugi: ignore-file
//! Arm C Shadow Rules (`KC-C01`..`KC-C05`) — Flow-Sensitive & Function-Scope Python Security Evaluators.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{Finding, NativeRule, Severity};
use crate::parsers::python_shadow::{
    collect_balanced_parens, extract_bracket_list_items, extract_def_func_name,
    extract_fstring_expr_idents, extract_git_guard_vars_on_line, extract_identifiers,
    extract_lstrip_dash_source, extract_method_receiver, find_dotted_call,
    find_standalone_ident_call, gap_between_spans_is_whitespace, has_fstring_interpolation,
    has_sensitive_file_token, is_safe_path_join_rhs, is_single_ident, is_trivial_cmp_operand,
    parse_python_file, slice_cmp_sides, split_top_level_args, tail_after_string_is_pct_or_format,
    unquote_simple_py_str, unwrap_git_var_expr, PyParsedFile,
};
use crate::rules::{line_ignores_rule, ARM_C_SHADOW_RULES};

pub fn is_safe_fstring_git_arg(raw: &str) -> Option<bool> {
    let t = raw.trim();
    let rest = t
        .strip_prefix("f")
        .or_else(|| t.strip_prefix("F"))
        .or_else(|| t.strip_prefix("rf"))
        .or_else(|| t.strip_prefix("fr"))?;
    let quote = rest.chars().next()?;
    if (quote != '"' && quote != '\'') || !rest.ends_with(quote) || rest.len() < 2 {
        return None;
    }
    let inner = &rest[1..rest.len() - 1];
    if let Some(brace_pos) = inner.find('{') {
        let prefix = &inner[..brace_pos];
        Some(
            !prefix.is_empty()
                && (!prefix.starts_with('-')
                    || matches!(
                        prefix,
                        "-n" | "--max-count=" | "--depth=" | "--format=" | "--pretty=" | "--skip="
                    )),
        )
    } else {
        Some(!inner.starts_with('-'))
    }
}

fn is_git_flag_with_value(flag: &str) -> bool {
    matches!(
        flag,
        "-C" | "-c" | "-m" | "-n" | "-F" | "-b" | "-B" | "-o" | "-U"
            | "--git-dir" | "--work-tree" | "--depth" | "--format" | "--pretty"
            | "--message" | "--file" | "--branch" | "--git-path" | "--exec-path"
    )
}

fn is_arg_guarded_by_vars(
    unwrapped: &str,
    item_masked: &str,
    guarded_vars: &BTreeSet<String>,
    safe_vars: &BTreeSet<String>,
) -> bool {
    if is_safe_path_join_rhs(unwrapped, item_masked) || extract_lstrip_dash_source(unwrapped).is_some() {
        return true;
    }
    if let Some(ident) = is_single_ident(unwrapped) {
        return guarded_vars.contains(ident) || safe_vars.contains(ident);
    }
    if unwrapped.contains('(') {
        return false;
    }
    let ids = extract_identifiers(unwrapped);
    !ids.is_empty() && ids.iter().all(|id| guarded_vars.contains(id) || safe_vars.contains(id))
}

fn is_git_argv_vulnerable(
    items: &[(String, String)],
    guarded_vars: &BTreeSet<String>,
    safe_vars: &BTreeSet<String>,
) -> bool {
    if items.len() <= 1 {
        return false;
    }
    let (mut seen_double_dash, mut skip_next) = (false, false);

    for (item_raw, item_masked) in &items[1..] {
        if skip_next {
            skip_next = false;
            continue;
        }
        if let Some(lit) = unquote_simple_py_str(item_raw) {
            if lit == "--" {
                seen_double_dash = true;
            } else if is_git_flag_with_value(&lit) {
                skip_next = true;
            }
            continue;
        }
        if let Some(is_safe_fstr) = is_safe_fstring_git_arg(item_raw) {
            if is_safe_fstr {
                continue;
            }
            let rt = item_raw.trim();
            let inner_starts_dash = rt.contains("f\"-") || rt.contains("f'-") || rt.contains("F\"-") || rt.contains("F'-");
            if !inner_starts_dash && !rt.contains('(') {
                let ids = extract_fstring_expr_idents(rt);
                if !ids.is_empty() && ids.iter().all(|id| guarded_vars.contains(id) || safe_vars.contains(id)) {
                    continue;
                }
            }
            if !seen_double_dash {
                return true;
            }
            continue;
        }
        let unwrapped = unwrap_git_var_expr(item_raw);
        if is_arg_guarded_by_vars(unwrapped, item_masked, guarded_vars, safe_vars) {
            continue;
        }
        if !seen_double_dash {
            return true;
        }
    }
    false
}

fn split_top_level_plus(raw: &str, masked: &str) -> Vec<(String, String)> {
    if raw.len() != masked.len() {
        return vec![(raw.trim().to_string(), masked.trim().to_string())];
    }
    let (mut out, mut depth, mut start) = (Vec::new(), 0usize, 0usize);
    for (idx, &b) in masked.as_bytes().iter().enumerate() {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'+' if depth == 0 => {
                let (r, m) = (raw[start..idx].trim(), masked[start..idx].trim());
                if !r.is_empty() { out.push((r.to_string(), m.to_string())); }
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start < raw.len() {
        let (r, m) = (raw[start..].trim(), masked[start..].trim());
        if !r.is_empty() { out.push((r.to_string(), m.to_string())); }
    }
    out
}

fn extract_sequence_or_expr_items(raw_expr: &str, masked_expr: &str) -> Vec<(String, String)> {
    let (rt, mt) = (raw_expr.trim(), masked_expr.trim());
    if rt.is_empty() { return Vec::new(); }
    if let Some(items) = extract_bracket_list_items(rt, mt) { return items; }
    if mt.starts_with('(') && mt.ends_with(')') && rt.len() >= 2 && rt.len() == mt.len() {
        return split_top_level_args(&rt[1..rt.len() - 1], &mt[1..mt.len() - 1]);
    }
    vec![(rt.to_string(), mt.to_string())]
}

fn resolve_git_plus_chain(
    parts: &[(String, String)],
    cmd_vars: &BTreeMap<String, Vec<(String, String)>>,
) -> Option<Vec<(String, String)>> {
    if parts.len() <= 1 { return None; }
    let (p0_r, p0_m) = &parts[0];
    let mut acc = extract_bracket_list_items(p0_r, p0_m)
        .filter(|it| it.first().and_then(|(r, _)| unquote_simple_py_str(r)).is_some_and(|s| s == "git"))
        .or_else(|| is_single_ident(p0_m).and_then(|v| cmd_vars.get(v).cloned()))?;
    for (pr, pm) in &parts[1..] {
        acc.extend(extract_sequence_or_expr_items(pr, pm));
    }
    Some(acc)
}

/// Flow-sensitive per-variable guard & kill-set evaluator for `KC-C01` Git option injection.
pub fn eval_kc_c01_git_injection(parsed: &PyParsedFile) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    let mut module_safe_vars: BTreeSet<String> = BTreeSet::new();
    if let Some(top_indices) = parsed.scope_lines.get(&0) {
        for &idx in top_indices {
            let line = &parsed.lines[idx];
            if !line.is_non_exec {
                if let Some(eq_pos) = line.masked.find('=') {
                    if let Some(ident) = is_single_ident(line.masked[..eq_pos].trim()) {
                        if is_safe_path_join_rhs(line.raw[eq_pos + 1..].trim(), line.masked[eq_pos + 1..].trim()) {
                            module_safe_vars.insert(ident.to_string());
                        }
                    }
                }
            }
        }
    }

    for indices in parsed.scope_lines.values() {
        let mut safe_vars = module_safe_vars.clone();
        let mut guarded_vars: BTreeSet<String> = BTreeSet::new();
        let mut cmd_vars: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();

        for &idx in indices {
            let line = &parsed.lines[idx];
            if line.is_non_exec { continue; }

            for gvar in extract_git_guard_vars_on_line(&line.raw, &line.masked) {
                guarded_vars.insert(gvar);
            }

            if let Some(eq_pos) = line.masked.find('=') {
                let is_cmp = line.masked.as_bytes().get(eq_pos + 1) == Some(&b'=')
                    || (eq_pos > 0 && matches!(line.masked.as_bytes()[eq_pos - 1], b'!' | b'<' | b'>' | b'='));
                if !is_cmp {
                    let is_plus_eq = eq_pos > 0 && line.masked.as_bytes()[eq_pos - 1] == b'+';
                    let lhs_slice = line.masked[..if is_plus_eq { eq_pos - 1 } else { eq_pos }].trim();
                    if let Some(var_name) = is_single_ident(lhs_slice.split(':').next().unwrap_or(lhs_slice).trim()) {
                        let (rhs_r, rhs_m) = (line.raw[eq_pos + 1..].trim(), line.masked[eq_pos + 1..].trim());
                        if is_plus_eq {
                            if cmd_vars.contains_key(var_name) {
                                let ext_items = if rhs_m.starts_with('[') || rhs_m.starts_with('(') {
                                    let rel = line.masked[eq_pos + 1..].find(['[', '(']).unwrap_or(0);
                                    collect_balanced_parens(&parsed.lines, idx, eq_pos + 1 + rel)
                                        .map(|(ir, im)| split_top_level_args(&ir, &im))
                                        .unwrap_or_default()
                                } else {
                                    extract_sequence_or_expr_items(rhs_r, rhs_m)
                                };
                                if let Some(vec) = cmd_vars.get_mut(var_name) { vec.extend(ext_items); }
                            } else {
                                guarded_vars.remove(var_name);
                                safe_vars.remove(var_name);
                            }
                        } else {
                            if extract_lstrip_dash_source(rhs_r).is_some()
                                || is_single_ident(rhs_m).is_some_and(|src| guarded_vars.contains(src))
                            {
                                guarded_vars.insert(var_name.to_string());
                            } else {
                                guarded_vars.remove(var_name);
                            }
                            if is_safe_path_join_rhs(rhs_r, rhs_m) {
                                safe_vars.insert(var_name.to_string());
                            } else {
                                safe_vars.remove(var_name);
                            }
                            let plus_parts = split_top_level_plus(rhs_r, rhs_m);
                            if let Some(acc) = resolve_git_plus_chain(&plus_parts, &cmd_vars) {
                                cmd_vars.insert(var_name.to_string(), acc);
                            } else if let Some(br_pos) = line.masked[eq_pos + 1..].find('[') {
                                if let Some((inner_r, inner_m)) = collect_balanced_parens(&parsed.lines, idx, eq_pos + 1 + br_pos) {
                                    let items = split_top_level_args(&inner_r, &inner_m);
                                    if items.first().and_then(|(r, _)| unquote_simple_py_str(r)).is_some_and(|s| s == "git") {
                                        cmd_vars.insert(var_name.to_string(), items);
                                    } else {
                                        cmd_vars.remove(var_name);
                                    }
                                }
                            } else {
                                cmd_vars.remove(var_name);
                            }
                        }
                    }
                }
            }

            for method in [".append(", ".extend("] {
                if let Some(m_pos) = line.masked.find(method) {
                    if let Some(var_name) = is_single_ident(line.masked[..m_pos].trim()) {
                        if cmd_vars.contains_key(var_name) {
                            if let Some((arg_r, arg_m)) = collect_balanced_parens(&parsed.lines, idx, m_pos + method.len() - 1) {
                                if let Some(vec) = cmd_vars.get_mut(var_name) {
                                    if method == ".append(" {
                                        vec.push((arg_r.trim().to_string(), arg_m.trim().to_string()));
                                    } else {
                                        vec.extend(extract_sequence_or_expr_items(&arg_r, &arg_m));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            for callee in ["subprocess.run(", "subprocess.Popen(", "subprocess.check_output(", "subprocess.check_call(", "subprocess.call("] {
                let mut search_from = 0usize;
                while let Some(c_pos) = find_dotted_call(&line.masked, callee, search_from) {
                    if let Some((call_r, call_m)) = collect_balanced_parens(&parsed.lines, idx, c_pos + callee.len() - 1) {
                        if let Some((arg0_r, arg0_m)) = split_top_level_args(&call_r, &call_m).first() {
                            let parts = split_top_level_plus(arg0_r, arg0_m);
                            let vuln = if let Some(items) = resolve_git_plus_chain(&parts, &cmd_vars) {
                                is_git_argv_vulnerable(&items, &guarded_vars, &safe_vars)
                            } else if let Some(inline_items) = extract_bracket_list_items(arg0_r, arg0_m) {
                                inline_items.first().and_then(|(r, _)| unquote_simple_py_str(r)).is_some_and(|s| s == "git")
                                    && is_git_argv_vulnerable(&inline_items, &guarded_vars, &safe_vars)
                            } else if let Some(var_name) = is_single_ident(arg0_m) {
                                cmd_vars.get(var_name).is_some_and(|it| is_git_argv_vulnerable(it, &guarded_vars, &safe_vars))
                            } else {
                                false
                            };
                            if vuln {
                                hits.push((line.lineno, line.trimmed.clone()));
                            }
                        }
                    }
                    search_from = c_pos + callee.len();
                }
            }
        }
    }
    hits
}

fn contains_sql_verb_clause(s: &str) -> bool {
    let upper = s.to_ascii_uppercase();
    (upper.contains("SELECT ") && upper.contains(" FROM "))
        || upper.contains("INSERT INTO ")
        || (upper.contains("UPDATE ") && upper.contains(" SET "))
        || upper.contains("DELETE FROM ")
}

pub fn eval_kc_c02_sql_interp(parsed: &PyParsedFile) -> Vec<(usize, String)> {
    let (mut hits, mut hit_lines, mut idx_span) = (Vec::new(), BTreeSet::new(), 0usize);

    while idx_span < parsed.string_spans.len() {
        let span = &parsed.string_spans[idx_span];
        if parsed.lines[span.start_line_idx].is_non_exec { idx_span += 1; continue; }
        if span.is_fstring {
            if contains_sql_verb_clause(&span.inner) && has_fstring_interpolation(&span.inner) && hit_lines.insert(span.start_line_idx + 1) {
                let ln = &parsed.lines[span.start_line_idx];
                hits.push((ln.lineno, ln.trimmed.clone()));
            }
            idx_span += 1;
            continue;
        }
        let (mut combined_inner, mut end_idx) = (span.inner.clone(), idx_span);
        while end_idx + 1 < parsed.string_spans.len()
            && !parsed.string_spans[end_idx + 1].is_fstring
            && !parsed.lines[parsed.string_spans[end_idx + 1].start_line_idx].is_non_exec
            && gap_between_spans_is_whitespace(&parsed.lines, &parsed.string_spans[end_idx], &parsed.string_spans[end_idx + 1])
        {
            end_idx += 1;
            combined_inner.push_str(&parsed.string_spans[end_idx].inner);
        }
        let last = &parsed.string_spans[end_idx];
        if contains_sql_verb_clause(&combined_inner)
            && tail_after_string_is_pct_or_format(&parsed.lines, last.end_line_idx, last.end_byte_after)
            && hit_lines.insert(span.start_line_idx + 1)
        {
            let ln = &parsed.lines[span.start_line_idx];
            hits.push((ln.lineno, ln.trimmed.clone()));
        }
        idx_span = end_idx + 1;
    }

    for indices in parsed.scope_lines.values() {
        let mut sql_vars: BTreeSet<String> = BTreeSet::new();
        for &idx in indices {
            let line = &parsed.lines[idx];
            if line.is_non_exec { continue; }
            if let Some(eq_pos) = line.masked.find('=') {
                let (lhs, rhs_r) = (line.masked[..eq_pos].trim(), line.raw[eq_pos + 1..].trim());
                if let Some(var_name) = is_single_ident(lhs) {
                    if contains_sql_verb_clause(rhs_r) && (rhs_r.contains('"') || rhs_r.contains('\''))
                        && !rhs_r.starts_with("f\"") && !rhs_r.starts_with("f'")
                    {
                        sql_vars.insert(var_name.to_string());
                    } else {
                        sql_vars.remove(var_name);
                    }
                }
            }
            for var_name in &sql_vars {
                let fmt_pat = format!("{var_name}.format(");
                let pct_pat1 = format!("{var_name} % ");
                let pct_pat2 = format!("{var_name}%");
                let has_fmt = find_standalone_ident_call(&line.masked, &fmt_pat, 0).is_some();
                let has_pct = line.masked.contains(&pct_pat1) || (line.masked.contains(&pct_pat2) && !line.masked.contains("%="));
                if (has_fmt || has_pct) && hit_lines.insert(line.lineno) {
                    hits.push((line.lineno, line.trimmed.clone()));
                }
            }
        }
    }
    hits
}

fn is_hmac_or_sig_ident(ident: &str) -> bool {
    let low = ident.to_ascii_lowercase();
    if ["sha256", "manifest_sha", "patch_sha", "payload_sha", "snapshot_sha", "signing_domain"]
        .iter()
        .any(|k| low.contains(k))
    {
        return false;
    }
    low.contains("hmac")
        || matches!(low.as_str(), "sig" | "mac")
        || low.ends_with("_sig")
        || low.starts_with("sig_")
        || low.contains("signature")
        || low.ends_with("_mac")
        || low.starts_with("mac_")
        || low.contains("digest")
        || low.ends_with("_tag")
}

fn calls_hmac_helper(expr_masked: &str, hmac_helpers: &BTreeSet<String>) -> bool {
    hmac_helpers.iter().any(|h| {
        let pat = format!("{h}(");
        let dpat = format!(".{h}(");
        find_standalone_ident_call(expr_masked, &pat, 0).is_some()
            || find_dotted_call(expr_masked, &dpat, 0).is_some()
    })
}

fn rhs_is_hmac_derived(
    rhs_masked: &str,
    hmac_vars: &BTreeSet<String>,
    hmac_helpers: &BTreeSet<String>,
) -> bool {
    let rt = rhs_masked.trim();
    if ["len(", "type(", "isinstance(", "bool(", "int(", "hmac.compare_digest("]
        .iter()
        .any(|p| rt.starts_with(p))
        || rt.contains("compare_digest(")
    {
        return false;
    }
    if rt.contains("hmac.new(") || rt.contains("hmac.digest(") || calls_hmac_helper(rt, hmac_helpers) {
        return true;
    }
    if is_single_ident(rt).is_some_and(|id| hmac_vars.contains(id)) {
        return true;
    }
    let propagates = [".hexdigest(", ".digest(", ".strip(", ".lower(", ".upper(", ".encode(", ".decode("]
        .iter()
        .any(|m| rt.contains(m))
        || rt.contains('+');
    propagates && extract_identifiers(rt).iter().any(|id| hmac_vars.contains(id))
}

fn extract_assignment_rhs(parsed: &PyParsedFile, idx: usize) -> Option<(&str, String)> {
    let line = &parsed.lines[idx];
    let eq_pos = line.masked.find('=')?;
    let mb = line.masked.as_bytes();
    if mb.get(eq_pos + 1) == Some(&b'=') || (eq_pos > 0 && matches!(mb[eq_pos - 1], b'!' | b'<' | b'>' | b'=' | b'+')) {
        return None;
    }
    let lhs_raw = line.masked[..eq_pos].trim();
    let var_name = is_single_ident(lhs_raw.split(':').next().unwrap_or(lhs_raw).trim())?;
    let mut rhs = line.masked[eq_pos + 1..].trim().to_string();
    if rhs == "(" {
        if let Some(open_p) = line.masked[eq_pos + 1..].find('(') {
            if let Some((_, inner_m)) = collect_balanced_parens(&parsed.lines, idx, eq_pos + 1 + open_p) {
                rhs = inner_m;
            }
        }
    }
    Some((var_name, rhs))
}

fn collect_module_hmac_helpers(parsed: &PyParsedFile) -> BTreeSet<String> {
    let mut helpers = BTreeSet::new();
    for _ in 0..2 {
        let mut changed = false;
        for (&fid, indices) in &parsed.scope_lines {
            if fid == 0 || indices.is_empty() { continue; }
            let Some(fname) = extract_def_func_name(parsed.lines[indices[0]].masked.trim()) else { continue };
            if helpers.contains(fname) { continue; }
            let mut fn_hmac_vars: BTreeSet<String> = BTreeSet::new();
            for &idx in &indices[1..] {
                let ln = &parsed.lines[idx];
                if ln.is_non_exec { continue; }
                if let Some((var_name, rhs)) = extract_assignment_rhs(parsed, idx) {
                    if rhs_is_hmac_derived(&rhs, &fn_hmac_vars, &helpers) {
                        fn_hmac_vars.insert(var_name.to_string());
                    } else {
                        fn_hmac_vars.remove(var_name);
                    }
                }
                if let Some(ret_expr) = ln.masked.trim().strip_prefix("return ") {
                    if rhs_is_hmac_derived(ret_expr, &fn_hmac_vars, &helpers) {
                        helpers.insert(fname.to_string());
                        changed = true;
                        break;
                    }
                }
            }
        }
        if !changed { break; }
    }
    helpers
}

/// Flow-sensitive `KC-C03` HMAC timing-leak evaluator with variable kill-sets and interprocedural helper propagation.
pub fn eval_kc_c03_hmac_timing(parsed: &PyParsedFile) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    if !parsed.lines.iter().any(|l| {
        !l.is_non_exec && (l.masked.contains("import hmac") || l.masked.contains("from hmac") || l.masked.contains("hmac."))
    }) {
        return hits;
    }

    let hmac_helpers = collect_module_hmac_helpers(parsed);

    for indices in parsed.scope_lines.values() {
        let scope_uses_compare_digest = indices.iter().any(|&idx| {
            let l = &parsed.lines[idx];
            !l.is_non_exec && l.masked.contains("compare_digest")
        });

        let mut hmac_vars: BTreeSet<String> = BTreeSet::new();
        let mut killed_vars: BTreeSet<String> = BTreeSet::new();

        for &idx in indices {
            let line = &parsed.lines[idx];
            if line.is_non_exec { continue; }

            if !line.masked.contains("compare_digest") {
                let mb = line.masked.as_bytes();
                let mut pos = 0usize;
                while pos + 1 < mb.len() {
                    let is_eq_op = (mb[pos] == b'=' && mb[pos + 1] == b'=') || (mb[pos] == b'!' && mb[pos + 1] == b'=');
                    if is_eq_op {
                        let prev_ok = pos == 0 || !matches!(mb[pos - 1], b'<' | b'>' | b'=' | b'!');
                        let next_ok = pos + 2 >= mb.len() || mb[pos + 2] != b'=';
                        if prev_ok && next_ok {
                            let (mut lhs_m, mut rhs_m) = slice_cmp_sides(&line.masked, pos);
                            let (mut lhs_r, mut rhs_r) = slice_cmp_sides(&line.raw, pos);
                            let (win_r, win_m): (String, String);
                            if (lhs_m.is_empty() || rhs_m.is_empty()) && parsed.lines.len() > 1 {
                                let (prev_idx, next_idx) = (idx.saturating_sub(1), (idx + 1).min(parsed.lines.len() - 1));
                                let (mut cur_off, mut wr, mut wm) = (0usize, String::new(), String::new());
                                for w_idx in prev_idx..=next_idx {
                                    if w_idx > prev_idx { wr.push(' '); wm.push(' '); }
                                    if w_idx == idx { cur_off = wm.len(); }
                                    wr.push_str(&parsed.lines[w_idx].raw);
                                    wm.push_str(&parsed.lines[w_idx].masked);
                                }
                                (win_r, win_m) = (wr, wm);
                                (lhs_m, rhs_m) = slice_cmp_sides(&win_m, cur_off + pos);
                                (lhs_r, rhs_r) = slice_cmp_sides(&win_r, cur_off + pos);
                            }
                            if !is_trivial_cmp_operand(lhs_r, lhs_m) && !is_trivial_cmp_operand(rhs_r, rhs_m) {
                                let direct_hmac = lhs_m.contains("hmac.new(") || rhs_m.contains("hmac.new(")
                                    || lhs_m.contains("hmac.digest(") || rhs_m.contains("hmac.digest(")
                                    || calls_hmac_helper(lhs_m, &hmac_helpers) || calls_hmac_helper(rhs_m, &hmac_helpers);
                                let (lhs_idents, rhs_idents) = (extract_identifiers(lhs_m), extract_identifiers(rhs_m));
                                let tainted_var = lhs_idents.iter().any(|id| hmac_vars.contains(id))
                                    || rhs_idents.iter().any(|id| hmac_vars.contains(id));
                                let sig_vs_sig = !scope_uses_compare_digest
                                    && lhs_idents.iter().any(|id| is_hmac_or_sig_ident(id) && !killed_vars.contains(id))
                                    && rhs_idents.iter().any(|id| is_hmac_or_sig_ident(id) && !killed_vars.contains(id));
                                if direct_hmac || tainted_var || sig_vs_sig {
                                    hits.push((line.lineno, line.trimmed.clone()));
                                    break;
                                }
                            }
                        }
                        pos += 2;
                        continue;
                    }
                    pos += 1;
                }
            }

            if let Some((var_name, rhs)) = extract_assignment_rhs(parsed, idx) {
                if rhs_is_hmac_derived(&rhs, &hmac_vars, &hmac_helpers) {
                    hmac_vars.insert(var_name.to_string());
                    killed_vars.remove(var_name);
                } else {
                    hmac_vars.remove(var_name);
                    killed_vars.insert(var_name.to_string());
                }
            }
        }
    }
    hits
}

#[inline]
pub fn eval_kc_c03_hmac_eq(parsed: &PyParsedFile) -> Vec<(usize, String)> {
    eval_kc_c03_hmac_timing(parsed)
}

pub fn eval_kc_c04_sensitive_open(parsed: &PyParsedFile) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    for indices in parsed.scope_lines.values() {
        let scope_has_nofollow = indices.iter().any(|&idx| {
            let l = &parsed.lines[idx];
            !l.is_non_exec
                && (l.raw.contains("O_NOFOLLOW")
                    || l.masked.contains("open_regular_nofollow")
                    || l.masked.contains("_read_and_hash_regular_nofollow")
                    || l.masked.contains("_read_regular_nofollow"))
        });
        let scope_is_non_security_catalog = indices.iter().any(|&idx| {
            let l = &parsed.lines[idx];
            !l.is_non_exec
                && (l.masked.contains("packs_dir.glob(")
                    || l.masked.contains("build_demo_flawed_openmontage_manifest")
                    || l.masked.contains("OpenMontagePackageManager")
                    || l.masked.contains("active_registry_path"))
        });
        if scope_has_nofollow || scope_is_non_security_catalog { continue; }

        for &idx in indices {
            let line = &parsed.lines[idx];
            if line.is_non_exec { continue; }
            let mut matched = false;
            let mut pos = 0usize;
            while let Some(c_pos) = find_dotted_call(&line.masked, "os.open(", pos) {
                if let Some((call_r, call_m)) = collect_balanced_parens(&parsed.lines, idx, c_pos + "os.open(".len() - 1) {
                    if !call_r.contains("O_NOFOLLOW")
                        && split_top_level_args(&call_r, &call_m).first().is_some_and(|(a0, _)| has_sensitive_file_token(a0))
                    {
                        matched = true;
                        break;
                    }
                }
                pos = c_pos + "os.open(".len();
            }

            if !matched {
                pos = 0;
                while let Some(c_pos) = find_standalone_ident_call(&line.masked, "open(", pos) {
                    if let Some((call_r, call_m)) = collect_balanced_parens(&parsed.lines, idx, c_pos + "open(".len() - 1) {
                        if !call_r.contains("O_NOFOLLOW")
                            && split_top_level_args(&call_r, &call_m).first().is_some_and(|(a0, _)| has_sensitive_file_token(a0))
                        {
                            matched = true;
                            break;
                        }
                    }
                    pos = c_pos + "open(".len();
                }
            }

            if !matched {
                for method in [".read_text(", ".read_bytes("] {
                    pos = 0;
                    while let Some(rel) = line.masked[pos..].find(method) {
                        let dot_pos = pos + rel;
                        if has_sensitive_file_token(&extract_method_receiver(&parsed.lines, idx, dot_pos)) {
                            matched = true;
                            break;
                        }
                        pos = dot_pos + method.len();
                    }
                    if matched { break; }
                }
            }

            if matched { hits.push((line.lineno, line.trimmed.clone())); }
        }
    }
    hits
}

fn match_ablation_bool_field(raw_inner: &str) -> Option<(&str, &str)> {
    let t = raw_inner.trim();
    for field in ["with_passed", "without_passed", "baseline_regression", "passed"] {
        let (dq_sub, sq_sub) = (format!("[\"{field}\"]"), format!("['{field}']"));
        if let Some(pos) = t.find(&dq_sub).or_else(|| t.find(&sq_sub)) {
            let var_part = t[..pos].trim();
            if is_single_ident(var_part).is_some() { return Some((var_part, field)); }
        }
        let (dq_get, sq_get) = (format!(".get(\"{field}\""), format!(".get('{field}'"));
        if let Some(pos) = t.find(&dq_get).or_else(|| t.find(&sq_get)) {
            let var_part = t[..pos].trim();
            if is_single_ident(var_part).is_some() { return Some((var_part, field)); }
        }
    }
    None
}

pub fn eval_kc_c05_ablation_bool(parsed: &PyParsedFile) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    for indices in parsed.scope_lines.values() {
        let is_oracle_ctx = indices.iter().any(|&idx| {
            let l = &parsed.lines[idx];
            !l.is_non_exec && (l.raw.contains("ORACLE_PASS") || l.raw.contains("ORACLE_FAILED"))
        });
        let is_ablation_ctx = indices.iter().any(|&idx| {
            let l = &parsed.lines[idx];
            !l.is_non_exec
                && ["with_passed", "without_passed", "baseline_regression", "MatchedTaskTrial", "ablation", "benchmark"]
                    .iter()
                    .any(|k| l.raw.contains(k))
        });

        for &idx in indices {
            let line = &parsed.lines[idx];
            if line.is_non_exec { continue; }
            let mut pos = 0usize;
            while let Some(c_pos) = find_standalone_ident_call(&line.masked, "bool(", pos) {
                if let Some((inner_r, _)) = collect_balanced_parens(&parsed.lines, idx, c_pos + "bool(".len() - 1) {
                    if let Some((var_name, field)) = match_ablation_bool_field(&inner_r) {
                        let is_flagged = field != "passed"
                            || (!is_oracle_ctx
                                && (is_ablation_ctx
                                    || matches!(
                                        var_name,
                                        "data" | "trial" | "row" | "record" | "entry" | "metrics"
                                            | "benchmark" | "ablation" | "strat_out" | "base_out"
                                    )));
                        if is_flagged {
                            hits.push((line.lineno, line.trimmed.clone()));
                            break;
                        }
                    }
                }
                pos = c_pos + "bool(".len();
            }
        }
    }
    hits
}

fn evaluate_arm_c_rule_parsed(
    rule: &NativeRule,
    parsed: &PyParsedFile,
    file_path: &str,
    allowed_lines: Option<&BTreeSet<usize>>,
    allow_inline_ignores: bool,
) -> Vec<Finding> {
    let raw_hits = match rule.id {
        "KC-C01" => eval_kc_c01_git_injection(parsed),
        "KC-C02" => eval_kc_c02_sql_interp(parsed),
        "KC-C03" => eval_kc_c03_hmac_timing(parsed),
        "KC-C04" => eval_kc_c04_sensitive_open(parsed),
        "KC-C05" => eval_kc_c05_ablation_bool(parsed),
        _ => Vec::new(),
    };
    let mut out = Vec::new();
    for (lineno, snippet) in raw_hits {
        if allowed_lines.is_some_and(|allowed| !allowed.contains(&lineno)) { continue; }
        if allow_inline_ignores
            && parsed.lines.get(lineno.saturating_sub(1)).is_some_and(|li| line_ignores_rule(&li.raw, rule.id))
        {
            continue;
        }
        out.push(Finding::from_rule(rule, file_path, lineno, 1, &snippet));
    }
    out
}

pub fn evaluate_arm_c_shadow_rule(rule_id: &str, content: &str, file_path: &str, lang: &str) -> Vec<Finding> {
    if lang != "python" { return Vec::new(); }
    let Some(rule) = ARM_C_SHADOW_RULES.iter().find(|r| r.id == rule_id) else { return Vec::new() };
    let parsed = parse_python_file(content);
    evaluate_arm_c_rule_parsed(rule, &parsed, file_path, None, true)
}

pub fn scan_arm_c_shadow_text(content: &str, file_path: &str, lang: &str) -> Vec<Finding> {
    scan_arm_c_shadow_text_with_options(content, file_path, lang, Severity::Low, None, true, false)
}

pub fn scan_arm_c_shadow_text_with_options(
    content: &str,
    file_path: &str,
    lang: &str,
    min_severity: Severity,
    allowed_lines: Option<&BTreeSet<usize>>,
    allow_inline_ignores: bool,
    allow_file_ignores: bool,
) -> Vec<Finding> {
    if lang != "python" { return Vec::new(); }
    if allow_file_ignores
        && content.lines().take(8).any(|hl| {
            (hl.contains("kintsugi:") || hl.contains("KINTSUGI:"))
                && hl.to_ascii_lowercase().contains("kintsugi: ignore-file")
        })
    {
        return Vec::new();
    }
    let parsed = parse_python_file(content);
    let mut findings = Vec::new();
    for rule in ARM_C_SHADOW_RULES {
        if rule.severity.ge(&min_severity) && rule.languages.contains(&lang) {
            findings.extend(evaluate_arm_c_rule_parsed(rule, &parsed, file_path, allowed_lines, allow_inline_ignores));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kc_c01_flow_sensitive_per_variable_guard_and_rebind_kill_set() {
        let wrong_var_guarded = "import subprocess\n\
            def f(a, b):\n\
            \x20   if a.startswith('-'):\n\
            \x20       return\n\
            \x20   subprocess.run(['git', 'show', b])\n";
        let hits_wrong = evaluate_arm_c_shadow_rule("KC-C01", wrong_var_guarded, "g.py", "python");
        assert_eq!(hits_wrong.len(), 1);
        assert_eq!(hits_wrong[0].line, 5);

        let right_var_guarded = "import subprocess\n\
            def f(a, b):\n\
            \x20   if b.startswith('-'):\n\
            \x20       raise ValueError()\n\
            \x20   subprocess.run(['git', 'show', b])\n";
        assert!(evaluate_arm_c_shadow_rule("KC-C01", right_var_guarded, "g.py", "python").is_empty());

        let killed_after_guard = "import subprocess\n\
            def f(b):\n\
            \x20   if b.startswith('-'):\n\
            \x20       raise ValueError()\n\
            \x20   b = untrusted()\n\
            \x20   subprocess.run(['git', 'show', b])\n";
        let hits_killed = evaluate_arm_c_shadow_rule("KC-C01", killed_after_guard, "g.py", "python");
        assert_eq!(hits_killed.len(), 1);
        assert_eq!(hits_killed[0].line, 6);
    }

    #[test]
    fn kc_c03_flow_sensitive_kill_set_and_interprocedural_hmac_helpers() {
        let killed_safe = "import hmac, hashlib\n\
            def process(secret, body, header_sig, expected_label):\n\
            \x20   sig = hmac.new(secret, body, hashlib.sha256).hexdigest()\n\
            \x20   if not hmac.compare_digest(sig, header_sig):\n\
            \x20       return False\n\
            \x20   sig = compute_label(body)\n\
            \x20   return sig == expected_label\n";
        assert!(evaluate_arm_c_shadow_rule("KC-C03", killed_safe, "w.py", "python").is_empty());

        let helper_vuln = "import hmac, hashlib\n\
            def compute_mac(key, msg):\n\
            \x20   return hmac.new(key, msg, hashlib.sha256).hexdigest()\n\
            def verify(key, msg, header):\n\
            \x20   out = compute_mac(key, msg)\n\
            \x20   if out == header:\n\
            \x20       return True\n\
            \x20   return False\n";
        let hits_helper = evaluate_arm_c_shadow_rule("KC-C03", helper_vuln, "w.py", "python");
        assert_eq!(hits_helper.len(), 1);
        assert_eq!(hits_helper[0].line, 6);
    }
}
