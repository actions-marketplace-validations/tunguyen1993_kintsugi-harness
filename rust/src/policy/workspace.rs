// kintsugi: ignore-file
//! Filesystem symlink-confinement checks, dangerous `rm` target verifier,
//! repository root boundary discovery, and SHA-256-pinned trusted policy loader.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::kernels::sha256_hw::sha256_hex_fast;
use crate::policy::shell::{
    classify_non_ws_abs_path, collapse_slashes, extract_leading_shell_var, has_glob_meta,
    is_dangerous_home_subpath, is_protected_workspace_dir, is_safe_build_cache_dir,
    normalize_lexical_posix, parse_json_string_array_items,
};

/// Hardware-accelerated (when `FEAT_SHA256` available) FIPS 180-4 SHA-256 hex digest (`KH-R4-SEC-06`, zero external crates).
pub fn sha256_hex(data: &[u8]) -> String {
    sha256_hex_fast(data)
}

pub fn resolve_abs_uncollapsed(abs_raw: &str, real_ws: Option<&str>) -> Option<String> {
    let collapsed = collapse_slashes(abs_raw.trim());
    if !collapsed.starts_with('/') {
        return None;
    }
    let raw_segs: Vec<&str> = collapsed.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    let ws_trim = real_ws
        .map(|s| s.trim_end_matches('/'))
        .filter(|s| s.split('/').filter(|p| !p.is_empty()).count() >= 2)
        .unwrap_or("");
    let ws_prefix = if ws_trim.is_empty() { String::new() } else { format!("{ws_trim}/") };
    let mut entered_ws = false;
    let check_entered = |segs: &[String], entered: &mut bool| -> bool {
        if ws_trim.is_empty() {
            return true;
        }
        let cur_abs = format!("/{}", segs.join("/"));
        let ct = cur_abs.trim_end_matches('/');
        if ct == ws_trim || ct.starts_with(&ws_prefix) {
            *entered = true;
            return true;
        }
        !*entered
    };

    let mut canon_segs: Vec<String> = Vec::new();
    let mut unseen_tail = false;
    for (idx, seg) in raw_segs.iter().enumerate() {
        if has_glob_meta(seg) {
            if raw_segs[idx..].contains(&"..") {
                return None;
            }
            canon_segs.extend(raw_segs[idx..].iter().map(|s| (*s).to_string()));
            break;
        }
        if *seg == ".." {
            if canon_segs.is_empty() {
                return None;
            }
            canon_segs.pop();
            if !check_entered(&canon_segs, &mut entered_ws) {
                return None;
            }
            continue;
        }
        if unseen_tail {
            canon_segs.push((*seg).to_string());
            if !check_entered(&canon_segs, &mut entered_ws) {
                return None;
            }
            continue;
        }
        let mut cand = PathBuf::from("/");
        for part in &canon_segs {
            cand.push(part);
        }
        cand.push(seg);
        match fs::symlink_metadata(&cand) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let real_cand = fs::canonicalize(&cand).ok()?;
                let real_str = real_cand.to_string_lossy().replace('\\', "/");
                if idx == 0 && *seg == "home" && real_str == "/System/Volumes/Data/home" {
                    canon_segs = vec!["home".to_string()];
                } else {
                    canon_segs = real_str.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
                }
            }
            Ok(_) => canon_segs.push((*seg).to_string()),
            Err(_) => {
                canon_segs.push((*seg).to_string());
                unseen_tail = true;
            }
        }
        if !check_entered(&canon_segs, &mut entered_ws) {
            return None;
        }
    }
    Some(format!("/{}", canon_segs.join("/")))
}

pub fn classify_workspace_rel_path(rel_raw: &str, ws_root: &Path, cwd_untrusted: bool) -> bool {
    classify_workspace_rel_path_opt(rel_raw, Some(ws_root), cwd_untrusted)
}

pub fn classify_workspace_rel_path_opt(rel_raw: &str, ws_root: Option<&Path>, cwd_untrusted: bool) -> bool {
    if cwd_untrusted {
        return true;
    }
    let collapsed = collapse_slashes(rel_raw.trim());
    if matches!(collapsed.as_str(), "" | "." | ".." | "*") || collapsed.starts_with('/') {
        return true;
    }
    let raw_segs: Vec<&str> = collapsed.split('/').filter(|s| !s.is_empty() && *s != ".").collect();
    if raw_segs.is_empty() || raw_segs[0] == ".." {
        return true;
    }
    let real_ws_opt: Option<PathBuf> = match ws_root {
        Some(ws) => match fs::canonicalize(ws) {
            Ok(p) => Some(p),
            Err(_) => return true,
        },
        None => None,
    };
    let mut resolved_segs: Vec<String> = Vec::new();
    let mut glob_tail: Vec<String> = Vec::new();
    let mut unseen_tail = real_ws_opt.is_none();

    for (idx, seg) in raw_segs.iter().enumerate() {
        if has_glob_meta(seg) {
            if raw_segs[idx..].contains(&"..") {
                return true;
            }
            glob_tail = raw_segs[idx..].iter().map(|s| (*s).to_string()).collect();
            break;
        }
        if *seg == ".." {
            if resolved_segs.is_empty() {
                return true;
            }
            resolved_segs.pop();
            continue;
        }
        if is_protected_workspace_dir(seg) {
            return true;
        }
        resolved_segs.push((*seg).to_string());
        if unseen_tail {
            continue;
        }
        let Some(ref real_ws) = real_ws_opt else {
            unseen_tail = true;
            continue;
        };
        let mut probe = real_ws.clone();
        for s in &resolved_segs {
            probe.push(s);
        }
        match fs::symlink_metadata(&probe) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let Ok(real_cur) = fs::canonicalize(&probe) else { return true };
                if real_cur == *real_ws || !real_cur.starts_with(real_ws) {
                    return true;
                }
                let Ok(rel_resolved) = real_cur.strip_prefix(real_ws) else { return true };
                let new_segs: Vec<String> = rel_resolved
                    .to_string_lossy()
                    .replace('\\', "/")
                    .split('/')
                    .filter(|s| !s.is_empty() && *s != ".")
                    .map(|s| s.to_string())
                    .collect();
                if new_segs.iter().any(|p| is_protected_workspace_dir(p)) {
                    return true;
                }
                resolved_segs = new_segs;
            }
            Ok(_) => {}
            Err(_) => unseen_tail = true,
        }
    }

    resolved_segs.extend(glob_tail);
    if resolved_segs.is_empty()
        || resolved_segs.iter().any(|p| is_protected_workspace_dir(p))
        || has_glob_meta(&resolved_segs[0])
    {
        return true;
    }
    !is_safe_build_cache_dir(&resolved_segs[0])
}

pub fn is_dangerous_rm_target(tgt: &str) -> bool {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    is_dangerous_rm_target_with_ws(tgt, &cwd, false, true)
}

pub fn is_dangerous_rm_target_with_ws(tgt: &str, ws_root: &Path, cwd_untrusted: bool, check_symlink: bool) -> bool {
    is_dangerous_rm_target_with_ws_opt(tgt, Some(ws_root), cwd_untrusted, check_symlink)
}

pub fn is_dangerous_rm_target_with_ws_opt(
    tgt: &str,
    ws_root: Option<&Path>,
    cwd_untrusted: bool,
    check_symlink: bool,
) -> bool {
    let mut raw_owned = tgt.trim().to_string();
    if raw_owned.is_empty() {
        return false;
    }
    if raw_owned.contains('`') || raw_owned.contains("$(") {
        return true;
    }
    if raw_owned.contains('$') {
        let Some((var_name, after)) = extract_leading_shell_var(&raw_owned) else { return true };
        if after.contains('$') || after.is_empty() || after == "/" || after == "/*" || !after.starts_with('/') {
            return true;
        }
        match var_name.as_str() {
            "PWD" => return classify_workspace_rel_path_opt(after.trim_start_matches('/'), ws_root, cwd_untrusted),
            "HOME" => return is_dangerous_home_subpath(after.trim_start_matches('/')),
            "TMPDIR" | "TMP" | "TEMP" => raw_owned = format!("/tmp/{}", after.trim_start_matches('/')),
            _ => return true,
        }
    }

    let raw = raw_owned.as_str();
    if raw.starts_with('~') {
        let Some(after) = raw.strip_prefix("~/") else { return true };
        return is_dangerous_home_subpath(after);
    }

    let collapsed = collapse_slashes(raw);
    let lex_norm = normalize_lexical_posix(&collapsed);
    if matches!(lex_norm.as_str(), "." | ".." | "/" | "*" | "/*" | ".*" | "~")
        || matches!(raw.trim_end_matches('/'), "" | "." | ".." | "*")
        || lex_norm.starts_with("../")
        || (raw.ends_with("/*") && lex_norm.split('/').filter(|s| !s.is_empty()).count() <= 2)
    {
        return true;
    }

    if collapsed.starts_with('/') {
        let _ = check_symlink;
        let (norm, real_ws_str) = if let Some(ws) = ws_root {
            let mut ws_candidates: Vec<String> = Vec::new();
            let ws_raw = collapse_slashes(&ws.to_string_lossy().replace('\\', "/")).trim_end_matches('/').to_string();
            if ws_raw.split('/').filter(|s| !s.is_empty()).count() >= 2 {
                ws_candidates.push(ws_raw);
            }
            let real_ws_str = fs::canonicalize(ws)
                .map(|p| p.to_string_lossy().replace('\\', "/").trim_end_matches('/').to_string())
                .ok();
            if let Some(ref rw) = real_ws_str {
                if rw.split('/').filter(|s| !s.is_empty()).count() >= 2 && !ws_candidates.contains(rw) {
                    ws_candidates.push(rw.clone());
                }
            }
            for wp in &ws_candidates {
                if &collapsed == wp {
                    return true;
                }
                if let Some(rel_tail) = collapsed.strip_prefix(&format!("{wp}/")) {
                    return classify_workspace_rel_path_opt(rel_tail, ws_root, cwd_untrusted);
                }
            }
            let Some(norm) = resolve_abs_uncollapsed(&collapsed, real_ws_str.as_deref()) else { return true };
            (norm, real_ws_str)
        } else {
            if collapsed.split('/').any(|s| s == "..") {
                return true;
            }
            (lex_norm, None)
        };
        let parts: Vec<&str> = norm.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() <= 1 {
            return true;
        }
        if let Some(ref ws_s) = real_ws_str {
            if ws_s.split('/').filter(|s| !s.is_empty()).count() >= 2 && norm.starts_with(&format!("{ws_s}/")) {
                return classify_workspace_rel_path_opt(&norm[ws_s.len() + 1..], ws_root, cwd_untrusted);
            }
        }
        return classify_non_ws_abs_path(&norm, &parts);
    }

    classify_workspace_rel_path_opt(&collapsed, ws_root, cwd_untrusted)
}

pub fn is_ancestor_stop_boundary(cand: &Path, home_res: Option<&Path>) -> bool {
    let s = cand.to_string_lossy().replace('\\', "/");
    if matches!(
        s.as_str(),
        "/" | "/tmp" | "/private/tmp" | "/var" | "/private/var" | "/var/folders" | "/private/var/folders" | "/home" | "/Users"
    ) || home_res.is_some_and(|hr| cand == hr)
    {
        return true;
    }
    if cand.file_name().and_then(|n| n.to_str()) == Some("T")
        && (s.contains("/var/folders/") || s.contains("/private/var/folders/"))
    {
        return true;
    }
    if let Some(p1) = cand.parent() {
        let p1s = p1.to_string_lossy().replace('\\', "/");
        if matches!(p1s.as_str(), "/var/folders" | "/private/var/folders") {
            return true;
        }
        if let Some(p2) = p1.parent() {
            let p2s = p2.to_string_lossy().replace('\\', "/");
            if matches!(p2s.as_str(), "/var/folders" | "/private/var/folders") {
                return true;
            }
        }
    }
    false
}

pub fn find_enclosing_repo_root(target_abs: &Path) -> PathBuf {
    let start_dir = if target_abs.is_file() {
        target_abs.parent().unwrap_or(target_abs).to_path_buf()
    } else {
        target_abs.to_path_buf()
    };
    let home_res = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .and_then(|h| fs::canonicalize(Path::new(&h)).ok());

    let mut bounded = Vec::new();
    let mut cur = Some(start_dir.as_path());
    while let Some(c) = cur {
        if is_ancestor_stop_boundary(c, home_res.as_deref()) {
            break;
        }
        bounded.push(c.to_path_buf());
        if bounded.len() >= 12 {
            break;
        }
        cur = c.parent();
    }

    let mut vcs_root: Option<PathBuf> = None;
    let mut proj_root: Option<PathBuf> = None;
    let mut src_parent_root: Option<PathBuf> = None;
    for cand in &bounded {
        if [".git", ".hg", ".svn"].iter().any(|m| cand.join(m).exists()) {
            vcs_root = Some(cand.clone());
        } else if [".kintsugi", "pyproject.toml", "Cargo.toml", "package.json"].iter().any(|m| cand.join(m).exists()) {
            proj_root = Some(cand.clone());
        } else if *cand != start_dir && ["src", "tests", "app", "lib"].iter().any(|d| cand.join(d).is_dir()) {
            src_parent_root = Some(cand.clone());
        }
    }
    vcs_root.or(proj_root).or(src_parent_root).unwrap_or(start_dir)
}

pub fn load_trusted_policy_files_explicit_sha(
    target: &Path,
    explicit_policy: Option<&Path>,
    expected_sha256: Option<&str>,
) -> BTreeSet<PathBuf> {
    let mut trusted = BTreeSet::new();
    let env_val;
    let pol_path: &Path = match explicit_policy {
        Some(p) => p,
        None => {
            env_val = env::var_os("KINTSUGI_TRUSTED_POLICY").unwrap_or_default();
            if env_val.is_empty() {
                return trusted;
            }
            Path::new(&env_val)
        }
    };
    let Ok(meta) = fs::symlink_metadata(pol_path) else { return trusted };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return trusted;
    }
    let Ok(target_abs) = fs::canonicalize(target) else { return trusted };
    let target_root = if target_abs.is_file() {
        target_abs.parent().unwrap_or(&target_abs).to_path_buf()
    } else {
        target_abs.clone()
    };
    let repo_root = find_enclosing_repo_root(&target_abs);
    let Ok(pol_abs) = fs::canonicalize(pol_path) else { return trusted };
    let in_kintsugi_ancestor = pol_abs
        .parent()
        .filter(|p| p.file_name().and_then(|n| n.to_str()) == Some(".kintsugi"))
        .and_then(|p| p.parent())
        .map(|anc| target_abs == anc || target_abs.starts_with(anc))
        .unwrap_or(false);
    if pol_abs == target_root
        || pol_abs.starts_with(&target_root)
        || pol_abs == repo_root
        || pol_abs.starts_with(&repo_root)
        || in_kintsugi_ancestor
    {
        eprintln!(
            "KH-R3-SEC-01 FAIL-CLOSED: Refusing self-declared policy inside scanned target/repository ({}).",
            pol_abs.display()
        );
        return trusted;
    }
    let Ok(raw_bytes) = fs::read(&pol_abs) else { return trusted };
    let env_sha = env::var("KINTSUGI_TRUSTED_POLICY_SHA256").unwrap_or_default();
    let pin_sha = expected_sha256
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| env_sha.trim().to_ascii_lowercase());
    if !pin_sha.is_empty() {
        let valid_hex = pin_sha.len() == 64 && pin_sha.bytes().all(|b| b.is_ascii_hexdigit());
        if !valid_hex || sha256_hex(&raw_bytes) != pin_sha {
            eprintln!("KH-R3-SEC-01 FAIL-CLOSED: Trusted policy SHA-256 mismatch for {}.", pol_abs.display());
            return trusted;
        }
    }
    if let Ok(raw) = String::from_utf8(raw_bytes) {
        if let Some(idx) = raw.find("\"trusted_fixture_files\"") {
            let tail = &raw[idx..];
            if let (Some(lb), Some(rb)) = (tail.find('['), tail.find(']')) {
                for s in parse_json_string_array_items(&tail[lb..=rb]) {
                    for base in [&repo_root, &target_root] {
                        if let Ok(canon) = fs::canonicalize(base.join(&s)) {
                            if canon == *base || canon.starts_with(base) {
                                trusted.insert(canon);
                            }
                        }
                    }
                }
            }
        }
    }
    trusted
}
