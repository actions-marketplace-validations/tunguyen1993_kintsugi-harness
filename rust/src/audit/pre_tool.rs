//! Field-Aware Fail-Closed `PreToolUse` JIT Hook with Single-Language Semantic Dispatch
//! and Symlink-Verified Canonical Workspace Confinement (`audit/pre_tool.rs`).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::audit::pre_tool_fields::{extract_pre_tool_fields, is_shell_tool_name, looks_like_python_code, FieldRole};
use crate::io_json::JsonObj;
use crate::json_dom::{parse_json_value, JsonValue};
use crate::model::{Finding, Severity};
use crate::parsers::scan_arm_c_shadow_text_with_options;
use crate::policy::{
    audit_shell_command_argv_inner, audit_shell_command_argv_with_ws, collapse_slashes,
    has_glob_meta, is_protected_workspace_dir, resolve_abs_uncollapsed,
};
use crate::rules::detect_language;
use crate::scanner::scan_text_with_policy;
use crate::unicode_policy::contains_security_unicode_control;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEvaluation {
    pub allowed: bool,
    pub reason: Option<String>,
    pub json: String,
}

impl HookEvaluation {
    #[inline]
    fn allow() -> Self {
        let inner = JsonObj::with_capacity(80).str("hookEventName", "PreToolUse").str("permissionDecision", "allow").finish();
        Self { allowed: true, reason: None, json: JsonObj::with_capacity(112).raw("hookSpecificOutput", &inner).finish() }
    }

    #[inline]
    fn deny(reason: impl Into<String>) -> Self {
        let r = reason.into();
        let inner = JsonObj::with_capacity(128 + r.len())
            .str("hookEventName", "PreToolUse").str("permissionDecision", "deny").str("permissionDecisionReason", &r).finish();
        Self { allowed: false, json: JsonObj::with_capacity(160 + r.len()).raw("hookSpecificOutput", &inner).finish(), reason: Some(r) }
    }
}

/// Resolve a single primary language for a `FieldRole::SourceCode` `PreToolUse` payload.
///
/// Returns `"unknown"` when neither the path hint nor the content gives a clear signal. The scanner
/// still runs every language-agnostic `*` rule (Unicode Trojan/Bidi, secrets, prompt injection) for
/// `"unknown"`, but it skips Python-only rules, which avoids false positives on config/plain text.
pub fn infer_pretool_source_language(file_path_hint: &str, snippet: &str) -> &'static str {
    let hint = file_path_hint.trim();
    if !hint.is_empty() {
        if let Some(lang) = detect_language(Path::new(hint)).filter(|&l| l != "other") {
            return lang;
        }
    }
    if let Some(sb) = snippet.trim_start().strip_prefix("#!") {
        let hdr = sb.lines().next().unwrap_or("").to_ascii_lowercase();
        if hdr.contains("python") { return "python"; }
        if hdr.contains("node") || hdr.contains("deno") || hdr.contains("bun") { return "javascript"; }
        if hdr.contains("sh") { return "shell"; }
    }
    if looks_like_python_code(snippet) { return "python"; }
    let line_starts = |prefixes: &[&str]| snippet.lines().any(|ln| {
        let t = ln.trim_start();
        prefixes.iter().any(|p| t.starts_with(p))
    });
    // Rust is checked before JS so that `let mut ` / Rust `=>` match arms are never treated as JavaScript.
    if line_starts(&["fn ", "pub fn ", "pub(crate) fn ", "let mut ", "impl ", "impl<", "use std::", "pub struct ", "pub enum "]) {
        return "rust";
    }
    if line_starts(&["const ", "let ", "function ", "async function ", "import ", "export "])
        || ["require(", "console.", "document.", "process.env"].iter().any(|m| snippet.contains(m))
    {
        return "javascript";
    }
    if snippet.lines().any(|ln| {
        let u = ln.trim_start().to_ascii_uppercase();
        u.starts_with("CREATE ") || u.starts_with("ALTER ") || u.starts_with("DROP ")
    }) {
        return "sql";
    }
    "unknown"
}

/// Windows directory identity `(dwVolumeSerialNumber, nFileIndexHigh, nFileIndexLow)`, the
/// equivalent of Unix `(dev, ino)`, read without following reparse points.
#[cfg(windows)]
fn windows_dir_identity(path: &Path) -> Option<(u32, u32, u32)> {
    use std::ffi::c_void;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;

    type Handle = *mut c_void;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_SHARE_ALL: u32 = 0x0001 | 0x0002 | 0x0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(name: *const u16, access: u32, share: u32, sa: *mut c_void, disposition: u32, flags: u32, template: Handle) -> Handle;
        // `BY_HANDLE_FILE_INFORMATION` is 13 contiguous DWORDs (52 bytes, 4-byte aligned).
        fn GetFileInformationByHandle(handle: Handle, info: *mut [u32; 13]) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer that outlives the call; the null
    // security-attributes and template pointers are explicitly permitted by the Win32 contract.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(), FILE_READ_ATTRIBUTES, FILE_SHARE_ALL, std::ptr::null_mut(), OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle as isize == -1 {
        return None;
    }
    let mut info = [0u32; 13];
    // SAFETY: `handle` is a valid open handle (checked above) and `info` is a writable, properly
    // sized and aligned buffer matching `BY_HANDLE_FILE_INFORMATION`.
    let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
    // SAFETY: `handle` was returned by a successful `CreateFileW` and is closed exactly once here.
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    // Layout: [7]=dwVolumeSerialNumber, [11]=nFileIndexHigh, [12]=nFileIndexLow.
    Some((info[7], info[11], info[12]))
}

/// Verify that `dir` is a non-symlink, non-reparse-point directory, canonicalize it, and confirm that
/// the canonical path names the *same* directory object: `(dev, ino)` on Unix, and
/// `(dwVolumeSerialNumber, nFileIndexHigh, nFileIndexLow)` on Windows.
///
/// # TOCTOU caveat
/// This check is path-based and has an inherent race window. Between `fs::symlink_metadata(dir)`,
/// `fs::canonicalize(dir)` and the identity re-check, a process with write access to `dir`'s parent
/// can swap path components. The identity comparison catches a swap that happens *between* those
/// steps, but nothing here pins the directory for later use: callers receive a `PathBuf`, not a
/// handle, so the path can be replaced again after this function returns. This is defense in depth
/// against non-adversarial or slow attackers, not a race-free guarantee. Full confinement would need
/// handle-relative (`openat`/`O_NOFOLLOW`-style) access everywhere downstream.
pub fn resolve_trusted_workspace_dir(dir: &Path) -> Option<PathBuf> {
    let meta = fs::symlink_metadata(dir).ok()?;
    if meta.file_type().is_symlink() || !meta.is_dir() { return None; }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & 0x0400) != 0 { return None; }
    }
    let canon = fs::canonicalize(dir).ok()?;
    let canon_meta = fs::symlink_metadata(&canon).ok()?;
    if !canon_meta.is_dir() { return None; }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != canon_meta.dev() || meta.ino() != canon_meta.ino() { return None; }
    }
    #[cfg(windows)]
    {
        let original_id = windows_dir_identity(dir)?;
        if windows_dir_identity(&canon)? != original_id { return None; }
    }
    Some(canon)
}

fn push_unique_findings(dst: &mut Vec<Finding>, src: Vec<Finding>) {
    for f in src {
        if !dst.iter().any(|e| e.scar_id == f.scar_id) { dst.push(f); }
    }
}

pub fn evaluate_pre_tool_json(raw_json: &str, min_block: Severity) -> String {
    evaluate_pre_tool_detailed(raw_json, min_block, None).json
}

pub fn evaluate_pre_tool_json_with_workspace(raw_json: &str, min_block: Severity, trusted_ws: Option<&Path>) -> String {
    evaluate_pre_tool_detailed(raw_json, min_block, trusted_ws).json
}

/// Evaluate a `PreToolUse` JSON stdin payload with structured semantic field isolation and fail-closed bounds.
pub fn evaluate_pre_tool_detailed(raw_stdin: &str, min_block_severity: Severity, explicit_workspace: Option<&Path>) -> HookEvaluation {
    let trimmed = raw_stdin.trim();
    if trimmed.is_empty() || !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return HookEvaluation::deny("[@KML/1 S3 Fail-Closed] Malformed or non-JSON PreToolUse stdin payload");
    }
    let Ok(root_val) = parse_json_value(trimmed) else {
        return HookEvaluation::deny("[@KML/1 S3 Fail-Closed] Invalid JSON PreToolUse payload");
    };
    let Some(root) = root_val.as_object() else {
        return HookEvaluation::deny("[@KML/1 S3 Fail-Closed] PreToolUse root must be a JSON object");
    };
    let tool_input_val = root.get("tool_input").or_else(|| root.get("toolCall"));
    if matches!(tool_input_val, Some(ti) if !matches!(ti, JsonValue::Object(_) | JsonValue::Null)) {
        return HookEvaluation::deny("[@KML/1 S3 Fail-Closed] tool_input / toolCall must be a JSON object");
    }
    let ti_obj = tool_input_val.and_then(|v| v.as_object());
    let tool_name = root.get("tool_name").or_else(|| root.get("tool")).and_then(|v| v.as_str()).unwrap_or("");

    let fields = match extract_pre_tool_fields(root, ti_obj, tool_name) {
        Ok(f) => f,
        Err(err) if err.contains("TROJAN_UNICODE") => {
            return HookEvaluation::deny("[@KML/1 JIT Guard] Blocked KS-019 (CRITICAL): Trojan Source bidirectional or zero-width Unicode smuggling in PreToolUse key");
        }
        Err(err) => return HookEvaluation::deny(format!("[@KML/1 S3 Fail-Closed] {err}")),
    };

    for f in &fields {
        if contains_security_unicode_control(&f.text, f.bom_policy.allows_file_start_bom()) {
            return HookEvaluation::deny(format!(
                "[@KML/1 JIT Guard] Blocked KS-019 (CRITICAL): Trojan Source bidirectional or zero-width Unicode smuggling in '{}' | Fix: Strip hidden Bidi/ZWSP/BOM control characters",
                f.field_path
            ));
        }
        if !matches!(f.leaf_key.as_str(), "old_string" | "Target") && f.text.to_ascii_lowercase().contains("kintsugi: ignore-file") {
            return HookEvaluation::deny("[@KML/1 JIT Guard] Blocked KS-S3-IGNORE-BYPASS (HIGH): Untrusted inline kintsugi: ignore-file directive in agent payload");
        }
    }

    let env_ws = env::var_os("KINTSUGI_TRUSTED_WORKSPACE").unwrap_or_default();
    let trust_base: PathBuf = match explicit_workspace {
        Some(p) => p.to_path_buf(),
        None if !env_ws.is_empty() => PathBuf::from(env_ws),
        None => env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    let Some(real_trust) = resolve_trusted_workspace_dir(&trust_base) else {
        return HookEvaluation::deny("[@KML/1 S3 Fail-Closed] Unable to resolve non-symlink trusted workspace root");
    };

    let lookup_str = |keys: &[&str]| -> &str {
        keys.iter().find_map(|k| ti_obj.and_then(|o| o.get(*k)).or_else(|| root.get(*k))).and_then(|v| v.as_str()).map(str::trim).unwrap_or("")
    };
    let raw_agent_cwd = lookup_str(&["cwd", "Cwd", "workspace_root"]);
    let file_path = lookup_str(&["file_path", "path", "Path", "target_file"]);

    let (mut effective_ws, mut agent_cwd_untrusted) = (Some(real_trust.clone()), false);
    if !raw_agent_cwd.is_empty() {
        let trust_s = real_trust.to_string_lossy().replace('\\', "/");
        let agent_sym = fs::symlink_metadata(Path::new(raw_agent_cwd)).is_ok_and(|m| m.file_type().is_symlink());
        if agent_sym || has_glob_meta(raw_agent_cwd) || raw_agent_cwd.contains('`') || raw_agent_cwd.contains('$') || !raw_agent_cwd.starts_with('/') {
            (effective_ws, agent_cwd_untrusted) = (None, true);
        } else if let Some(resolved_agent) = resolve_abs_uncollapsed(&collapse_slashes(raw_agent_cwd), Some(&trust_s)) {
            let (trust_trim, agent_trim) = (trust_s.trim_end_matches('/'), resolved_agent.trim_end_matches('/'));
            if agent_trim == trust_trim {
                effective_ws = resolve_trusted_workspace_dir(Path::new(raw_agent_cwd)).filter(|c| *c == real_trust);
                agent_cwd_untrusted = effective_ws.is_none();
            } else if let Some(rel_sub) = agent_trim.strip_prefix(&format!("{trust_trim}/")) {
                if rel_sub.split('/').filter(|s| !s.is_empty() && *s != ".").any(is_protected_workspace_dir) {
                    (effective_ws, agent_cwd_untrusted) = (None, true);
                } else {
                    effective_ws = resolve_trusted_workspace_dir(Path::new(raw_agent_cwd)).filter(|c| c.starts_with(&real_trust));
                }
            } else {
                (effective_ws, agent_cwd_untrusted) = (None, true);
            }
        } else {
            (effective_ws, agent_cwd_untrusted) = (None, true);
        }
    }

    let shell_tool = is_shell_tool_name(tool_name);
    let mut all_findings = Vec::new();
    for f in &fields {
        if f.text.is_empty() { continue; }
        let disp = if file_path.is_empty() { f.field_path.as_str() } else { file_path };
        if f.role == FieldRole::ShellCommand || (shell_tool && f.role == FieldRole::SourceCode) {
            let shell_reason = match effective_ws.as_deref() {
                Some(ws) => audit_shell_command_argv_with_ws(&f.text, ws, agent_cwd_untrusted),
                None => audit_shell_command_argv_inner(&f.text, 0, None, agent_cwd_untrusted),
            };
            if let Some(reason) = shell_reason {
                return HookEvaluation::deny(format!("[@KML/1 JIT Guard] Blocked KS-014 (CRITICAL): {reason} | Fix: git stash push -u -m 'backup'"));
            }
            push_unique_findings(&mut all_findings, scan_text_with_policy(&f.text, disp, "shell", min_block_severity, None, false, false));
        } else if f.role == FieldRole::SourceCode {
            let lang = infer_pretool_source_language(file_path, &f.text);
            push_unique_findings(&mut all_findings, scan_text_with_policy(&f.text, disp, lang, min_block_severity, None, false, false));
            if lang == "python" {
                push_unique_findings(&mut all_findings, scan_arm_c_shadow_text_with_options(&f.text, disp, "python", min_block_severity, None, false, false));
            }
        }
    }

    let Some(first) = all_findings.first() else { return HookEvaluation::allow() };
    HookEvaluation::deny(format!("[@KML/1 JIT Guard] Blocked {} ({}): {} | Fix: {}", first.scar_id, first.severity.as_str(), first.title, first.fix_hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::kmi_benchmark::{compute_token_benchmark, render_kmi_compact_header};

    #[test]
    fn single_lang_dispatch_bom_policy_and_symlink_workspace_confinement() {
        let header = render_kmi_compact_header();
        assert!(header.contains("estimator=subword_heuristic_v2") && !header.to_ascii_uppercase().contains("BPE"));
        assert!(compute_token_benchmark().reduction_pct >= 88.0);
        assert_eq!(infer_pretool_source_language("app.ts", "x = 1"), "typescript");
        assert_eq!(infer_pretool_source_language("", "const fn = (x) => x + 1;"), "javascript");
        assert_eq!(infer_pretool_source_language("", "ALTER TABLE t ADD COLUMN c INT;"), "sql");
        assert_eq!(infer_pretool_source_language("", "pub fn f(x: Option<u8>) -> u8 {\n    match x { Some(v) => v, None => 0 }\n}"), "rust");
        assert_eq!(infer_pretool_source_language("", "let mut n = 0;\nn += 1;"), "rust");
        assert_eq!(infer_pretool_source_language("", "match x { Some(v) => v, None => 0 }"), "unknown");
        assert_eq!(infer_pretool_source_language("", "$arr = ['a' => 1, 'b' => 2];"), "unknown");
        assert_eq!(infer_pretool_source_language("", "console.log(x)"), "javascript");
        assert_eq!(infer_pretool_source_language("", "export default {};"), "javascript");
        assert_eq!(infer_pretool_source_language("", "listen_port: 8080\nlog_level: info\n"), "unknown");
        assert_eq!(infer_pretool_source_language("", "#!/bin/bash\necho hi"), "shell");
        let tmp = env::temp_dir();
        assert!(resolve_trusted_workspace_dir(&tmp).is_some_and(|c| c.is_dir()));
        assert!(resolve_trusted_workspace_dir(&tmp.join("kintsugi-definitely-missing-dir-w11")).is_none());
        assert!(evaluate_pre_tool_detailed(r#"{"tool_name":"Bash","tool_input":{"command":"echo 'el.innerHTML = msg'"}}"#, Severity::Low, None).allowed);
        assert!(!evaluate_pre_tool_detailed("{\"tool_name\":\"Edit\",\"tool_input\":{\"file_path\":\"a.py\",\"old_string\":\"x\",\"new_string\":\"\\ufeffy\"}}", Severity::High, None).allowed);
        assert!(evaluate_pre_tool_detailed("{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"a.py\",\"content\":\"\\ufeffx = 1\\n\"}}", Severity::High, None).allowed);
    }
}
