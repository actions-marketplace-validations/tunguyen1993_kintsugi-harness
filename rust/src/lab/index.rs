//! `@CT2` Repository Indexing, Gate Verification, and Cross-Function Inspection (`lab/index.rs`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use kintsugi_core::audit::ct2_seams::{
    classify_seam, extract_identifiers, grade_transform_line, is_ct2_supported_ext, strip_inline_comment,
};
use kintsugi_core::io_json::{fnv1a_64, JsonArr, JsonObj, FNV1A_64_INIT};
use kintsugi_core::scanner::should_skip_dir;

fn walk_ct2_targets(root: &Path, out: &mut Vec<PathBuf>) {
    if root.is_file() {
        if is_ct2_supported_ext(root) { out.push(root.to_path_buf()); }
        return;
    }
    let Ok(entries) = fs::read_dir(root) else { return };
    let mut sorted: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    sorted.sort();
    for p in sorted {
        if fs::symlink_metadata(&p).map(|m| m.file_type().is_symlink()).unwrap_or(false) { continue; }
        if p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.') || should_skip_dir(n) || n == "images" || n == "stylesheets") { continue; }
        if p.is_dir() { walk_ct2_targets(&p, out); } else if is_ct2_supported_ext(&p) { out.push(p); }
    }
}

#[derive(Clone)]
pub(crate) struct SeamRecord {
    pub(crate) seam_id: String,
    pub(crate) kind: &'static str,
    pub(crate) function: String,
    pub(crate) anchor: String,
    pub(crate) code: String,
    pub(crate) xform_code: String,
    pub(crate) hop_chain: String,
    pub(crate) ct2_prefix: String,
    pub(crate) symbols: Vec<String>,
}

pub(crate) struct RepoIndex {
    pub(crate) manifest_sha: String,
    pub(crate) files_count: usize,
    pub(crate) functions: BTreeMap<String, Vec<String>>,
    pub(crate) classes: BTreeMap<String, Vec<String>>,
    pub(crate) variables: BTreeSet<String>,
    pub(crate) file_lines: BTreeMap<String, Vec<String>>,
    pub(crate) seams: Vec<SeamRecord>,
}

fn load_bwapp_external_grades(root: &Path) -> BTreeMap<String, String> {
    let mut grades = BTreeMap::new();
    let Some(ext_p) = root.is_file().then(|| root.parent().map(|p| p.join("functions_external.php"))).flatten() else { return grades };
    if !ext_p.exists() || ext_p == root { return grades; }
    if let Ok(ext_txt) = fs::read_to_string(&ext_p) {
        let mut cur_fn = String::new();
        for line in ext_txt.lines() {
            let t = strip_inline_comment(line).trim();
            if t.starts_with("function ") {
                if let Some(first) = extract_identifiers(t).into_iter().next() { cur_fn = first; }
            } else if !cur_fn.is_empty() {
                if let Some((xf_name, tier)) = grade_transform_line(t, "XSS_SINK") { grades.insert(cur_fn.clone(), format!("{xf_name}:{tier}")); }
            }
        }
    }
    grades
}

fn push_unique_capped(dst: &mut Vec<String>, items: Vec<String>, cap: usize) {
    for id in items { if dst.len() >= cap { break; } if !dst.contains(&id) { dst.push(id); } }
}

pub(crate) fn build_repo_index(root: &Path) -> RepoIndex {
    let mut files = Vec::new();
    walk_ct2_targets(root, &mut files);
    let ext_fn_grades = load_bwapp_external_grades(root);

    let mut hash = FNV1A_64_INIT;
    let (mut functions, mut classes): (BTreeMap<String, Vec<String>>, BTreeMap<String, Vec<String>>) = (BTreeMap::new(), BTreeMap::new());
    let (mut variables, mut file_lines, mut seams) = (BTreeSet::new(), BTreeMap::new(), Vec::new());

    for f in &files {
        let rel = if root.is_dir() { f.strip_prefix(root).unwrap_or(f).to_string_lossy().to_string() }
            else { f.file_name().unwrap_or_default().to_string_lossy().to_string() };
        hash = fnv1a_64(rel.as_bytes(), hash);
        let Ok(bytes) = fs::read(f) else { continue };
        hash = fnv1a_64(&bytes, hash);
        let lines: Vec<String> = String::from_utf8_lossy(&bytes).lines().map(String::from).collect();

        let (mut local_fn_hops, mut scan_fn) = (BTreeMap::new(), String::new());
        for line in &lines {
            let t = strip_inline_comment(line).trim();
            let words: Vec<&str> = t.split(|c: char| !c.is_ascii_alphanumeric() && c != '_').filter(|s| !s.is_empty()).collect();
            if words.len() >= 2 && (words[0] == "def" || words[0] == "function") {
                scan_fn = words[1].to_string();
            } else if !scan_fn.is_empty() {
                if t.contains("no_check(") {
                    local_fn_hops.insert(scan_fn.clone(), "no_check:S0".to_string());
                } else if let Some((xf_n, tier)) = grade_transform_line(t, "CMD_EXEC") {
                    local_fn_hops.entry(scan_fn.clone()).or_insert_with(|| format!("{xf_n}:{tier}"));
                }
                for (ext_fn, ext_grade) in &ext_fn_grades {
                    if t.contains(ext_fn) { local_fn_hops.entry(scan_fn.clone()).or_insert_with(|| format!("{ext_fn}({ext_grade})")); }
                }
            }
        }

        let (mut current_fn, mut in_docstring, mut in_block_comment) = (String::from("module_scope"), false, false);
        for (i, line) in lines.iter().enumerate() {
            let (ln, trimmed) = (i + 1, line.trim());
            if (trimmed.matches("\"\"\"").count() + trimmed.matches("'''").count()) % 2 == 1 { in_docstring = !in_docstring; continue; }
            if in_docstring { continue; }
            if trimmed.contains("/*") && !trimmed.contains("*/") { in_block_comment = true; continue; }
            if in_block_comment { if trimmed.contains("*/") { in_block_comment = false; } continue; }

            let raw_words: Vec<&str> = strip_inline_comment(trimmed).split(|c: char| !c.is_ascii_alphanumeric() && c != '_').filter(|s| !s.is_empty()).collect();
            for w_idx in 0..raw_words.len() {
                let t = raw_words[w_idx];
                if (t == "def" || t == "function") && w_idx + 1 < raw_words.len() {
                    current_fn = raw_words[w_idx + 1].to_string();
                    functions.entry(current_fn.clone()).or_default().push(format!("{rel}:{ln}"));
                } else if (t == "class" || t == "contract" || t == "interface") && w_idx + 1 < raw_words.len() {
                    classes.entry(raw_words[w_idx + 1].to_string()).or_default().push(format!("{rel}:{ln}"));
                } else if matches!(t, "public" | "private" | "protected") && trimmed.contains('(') && trimmed.contains('{') {
                    if let Some(clean_fn) = trimmed.find('(').and_then(|p| trimmed[..p].split_whitespace().last()).map(|s| s.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')).filter(|s| s.len() >= 2) {
                        current_fn = clean_fn.to_string();
                        functions.entry(current_fn.clone()).or_default().push(format!("{rel}:{ln}"));
                    }
                }
            }

            for id in extract_identifiers(trimmed) { variables.insert(id); }
            let Some(seam_kind) = classify_seam(trimmed) else { continue };
            if (current_fn == "module_scope" || current_fn.starts_with("run_closed_loop_")) && rel.ends_with(".py") { continue; }

            let (mut start_g, mut end_g) = (i, i + 1);
            for back in 1..=14 {
                if i < back || lines[i - back].trim().starts_with("def ") || lines[i - back].trim().starts_with("function ") { break; }
                start_g = i - back;
            }
            for fwd in 1..=8 {
                if i + fwd >= lines.len() || lines[i + fwd].trim().starts_with("def ") || lines[i + fwd].trim().starts_with("function ") { break; }
                end_g = i + fwd + 1;
            }

            let (mut xform_code, mut local_syms) = (String::from("NONE:S0"), Vec::new());
            push_unique_capped(&mut local_syms, extract_identifiers(trimmed), 6);
            for line_g in &lines[start_g..end_g] {
                if let Some((xf_name, tier)) = grade_transform_line(line_g, seam_kind) { xform_code = format!("{xf_name}:{tier}"); }
                push_unique_capped(&mut local_syms, extract_identifiers(line_g), 6);
            }

            let mut hop_chain = format!("src->{seam_kind}");
            for sym in &local_syms {
                if let Some(fn_hop) = local_fn_hops.get(sym) {
                    hop_chain = format!("src->{sym}[{fn_hop}]->{seam_kind}");
                    if xform_code == "NONE:S0" { xform_code = fn_hop.clone(); }
                    break;
                }
            }

            let anchor = format!("{rel}:{ln}");
            let syms_short = local_syms.iter().take(3).cloned().collect::<Vec<_>>().join(",");
            let ct2_prefix = format!("<think>@CT2|L={anchor}|S={seam_kind}|sym={syms_short}|hop={hop_chain}|xf={xform_code}|");
            seams.push(SeamRecord {
                seam_id: format!("seam_{:04}", seams.len() + 1), kind: seam_kind, function: current_fn.clone(),
                anchor, code: strip_inline_comment(trimmed).trim().chars().take(140).collect(),
                xform_code, hop_chain, ct2_prefix, symbols: local_syms,
            });
        }
        file_lines.insert(rel, lines);
    }
    RepoIndex { manifest_sha: format!("{hash:016x}"), files_count: files.len(), functions, classes, variables, file_lines, seams }
}

pub(crate) fn render_index_json(target: &Path, max_seams: usize) -> String {
    let (t0, idx) = (Instant::now(), build_repo_index(target));
    let mut seams_arr = JsonArr::with_capacity(idx.seams.len().min(max_seams) * 240);
    for s in idx.seams.iter().take(max_seams) {
        let mut syms_arr = JsonArr::with_capacity(s.symbols.len() * 16);
        for sym in &s.symbols { syms_arr = syms_arr.str(sym); }
        seams_arr = seams_arr.obj(
            JsonObj::with_capacity(240).str("seam_id", &s.seam_id).str("kind", s.kind).str("function", &s.function)
                .str("anchor", &s.anchor).str("code", &s.code).str("guard", &s.xform_code)
                .str("hop_chain", &s.hop_chain).str("ct2_prefix", &s.ct2_prefix).arr("symbols", syms_arr),
        );
    }
    JsonObj::with_capacity(384)
        .bool("ok", true).str("engine", "rust_neuro_symbolic_core_v3_ct2").f64_3("elapsed_ms", t0.elapsed().as_secs_f64() * 1000.0)
        .str("manifest_sha", &idx.manifest_sha).usize("files_count", idx.files_count)
        .usize("functions_count", idx.functions.len()).usize("classes_count", idx.classes.len())
        .usize("variables_count", idx.variables.len()).usize("total_seams", idx.seams.len()).arr("seams", seams_arr).finish()
}

pub(crate) fn render_gate_json(target: &Path, fn_name: &str, anchor: &str, syms_csv: &str, guard_status: &str) -> String {
    let (t0, idx, mut reasons) = (Instant::now(), build_repo_index(target), Vec::new());
    let parts: Vec<&str> = anchor.split(':').collect();
    if parts.len() != 2 {
        reasons.push(format!("INVALID_ANCHOR:{anchor}"));
    } else if let Some(lines) = idx.file_lines.get(parts[0]) {
        let ln_ok = parts[1].parse::<usize>().unwrap_or(0);
        if ln_ok == 0 || ln_ok > lines.len() { reasons.push(format!("LINE_OUT_OF_RANGE:{}:{ln_ok}", parts[0])); }
    } else {
        reasons.push(format!("UNKNOWN_FILE:{}", parts[0]));
    }
    if !fn_name.is_empty() && fn_name != "module_scope" && !idx.functions.contains_key(fn_name) && !idx.classes.contains_key(fn_name) && !idx.variables.contains(fn_name) {
        reasons.push(format!("HALLUCINATED_FUNCTION:{fn_name}"));
    }
    for sym in syms_csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !idx.variables.contains(sym) && !idx.functions.contains_key(sym) && !idx.classes.contains_key(sym) { reasons.push(format!("HALLUCINATED_SYMBOL:{sym}")); }
    }
    if guard_status.to_ascii_uppercase().contains("REFUTED") || guard_status.ends_with(":S3") { reasons.push(String::from("S3_STRONG_LOCK_REFUTED")); }
    let state = if reasons.is_empty() { "VERIFIED" } else { "REFUTED" };
    let tabu_hash = format!("{:016x}", fnv1a_64(format!("{fn_name}|{anchor}|{syms_csv}").as_bytes(), FNV1A_64_INIT));
    let mut reasons_arr = JsonArr::with_capacity(reasons.len() * 32);
    for r in &reasons { reasons_arr = reasons_arr.str(r); }
    JsonObj::with_capacity(192).bool("ok", true).str("state", state).f64_3("elapsed_ms", t0.elapsed().as_secs_f64() * 1000.0).str("tabu_hash", &tabu_hash[..12]).arr("reasons", reasons_arr).finish()
}

pub(crate) fn render_inspect_fn_json(target: &Path, fn_name: &str) -> String {
    let (t0, idx) = (Instant::now(), build_repo_index(target));
    let (mut found_locs, mut snippet, mut detected_grade) = (Vec::new(), Vec::new(), String::from("NONE:S0"));
    if let Some(locs) = idx.functions.get(fn_name) {
        found_locs = locs.clone();
        if let Some(parts) = locs.first().map(|s| s.split(':').collect::<Vec<_>>()).filter(|p| p.len() == 2) {
            let ln = parts[1].parse::<usize>().unwrap_or(1);
            if let Some(lines) = idx.file_lines.get(parts[0]) {
                for (i, row) in lines.iter().enumerate().take(lines.len().min(ln + 15)).skip(ln.saturating_sub(1)) {
                    let clean = strip_inline_comment(row).trim();
                    if !clean.is_empty() {
                        snippet.push(format!("{}:{}: {clean}", parts[0], i + 1));
                        if let Some((xf_n, tier)) = grade_transform_line(clean, "XSS_SINK") { detected_grade = format!("{xf_n}:{tier}"); }
                    }
                }
            }
        }
    }
    let mut loc_arr = JsonArr::with_capacity(found_locs.len() * 24);
    for loc in &found_locs { loc_arr = loc_arr.str(loc); }
    JsonObj::with_capacity(256).bool("ok", !found_locs.is_empty()).str("tool", "rust_inspect_fn").str("fn_name", fn_name)
        .f64_3("elapsed_ms", t0.elapsed().as_secs_f64() * 1000.0).str("xform_grade", &detected_grade).arr("locations", loc_arr).str("body", &snippet.join("\n")).finish()
}
