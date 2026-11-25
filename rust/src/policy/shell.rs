// kintsugi: ignore-file
//! Pure lexical/structural shell stage & pipeline parser and destructive command analyzer.

use std::env;
use std::path::{Path, PathBuf};

use super::workspace::is_dangerous_rm_target_with_ws_opt;

pub fn split_shell_stages_and_pipelines(cmd: &str) -> (Vec<Vec<String>>, Vec<String>) {
    let mut segments: Vec<String> = Vec::new();
    let mut cur = String::new();
    let bytes = cmd.as_bytes();
    let mut i = 0;
    let mut in_sq = false;
    let mut in_dq = false;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if ch == '\\' && !in_sq && i + 1 < bytes.len() {
            cur.push(ch);
            cur.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if ch == '\'' && !in_dq {
            in_sq = !in_sq;
            cur.push(ch);
            i += 1;
            continue;
        }
        if ch == '"' && !in_sq {
            in_dq = !in_dq;
            cur.push(ch);
            i += 1;
            continue;
        }
        if !in_sq && !in_dq {
            if i + 1 < bytes.len()
                && ((bytes[i] == b'&' && bytes[i + 1] == b'&')
                    || (bytes[i] == b'|' && bytes[i + 1] == b'|'))
            {
                segments.push(cur.clone());
                cur.clear();
                i += 2;
                continue;
            }
            if ch == ';' || ch == '\n' {
                segments.push(cur.clone());
                cur.clear();
                i += 1;
                continue;
            }
        }
        cur.push(ch);
        i += 1;
    }
    if !cur.trim().is_empty() {
        segments.push(cur);
    }

    let mut pipelines = Vec::new();
    let mut single_stages = Vec::new();
    for seg in segments {
        let mut stages = Vec::new();
        let mut buf = String::new();
        let sb = seg.as_bytes();
        let mut j = 0;
        let mut sq = false;
        let mut dq = false;
        while j < sb.len() {
            let c = sb[j] as char;
            if c == '\\' && !sq && j + 1 < sb.len() {
                buf.push(c);
                buf.push(sb[j + 1] as char);
                j += 2;
                continue;
            }
            if c == '\'' && !dq {
                sq = !sq;
                buf.push(c);
                j += 1;
                continue;
            }
            if c == '"' && !sq {
                dq = !dq;
                buf.push(c);
                j += 1;
                continue;
            }
            if c == '|' && !sq && !dq {
                if !buf.trim().is_empty() {
                    stages.push(buf.trim().to_string());
                }
                buf.clear();
                j += 1;
                continue;
            }
            buf.push(c);
            j += 1;
        }
        if !buf.trim().is_empty() {
            stages.push(buf.trim().to_string());
        }
        if stages.len() >= 2 {
            pipelines.push(stages.clone());
        }
        single_stages.extend(stages);
    }
    (pipelines, single_stages)
}

pub fn split_shell_words(stage: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_tok = false;
    let mut in_sq = false;
    let mut in_dq = false;
    let chars: Vec<char> = stage.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && !in_sq && i + 1 < chars.len() {
            cur.push(chars[i + 1]);
            in_tok = true;
            i += 2;
            continue;
        }
        if c == '\'' && !in_dq {
            in_sq = !in_sq;
            in_tok = true;
            i += 1;
            continue;
        }
        if c == '"' && !in_sq {
            in_dq = !in_dq;
            in_tok = true;
            i += 1;
            continue;
        }
        if c.is_whitespace() && !in_sq && !in_dq {
            if in_tok {
                words.push(cur.clone());
                cur.clear();
                in_tok = false;
            }
            i += 1;
            continue;
        }
        cur.push(c);
        in_tok = true;
        i += 1;
    }
    if in_tok {
        words.push(cur);
    }
    let mut idx = 0;
    while idx < words.len() {
        let w = &words[idx];
        if let Some(eq_pos) = w.find('=') {
            let lhs = &w[..eq_pos];
            if !lhs.is_empty() && lhs.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
                idx += 1;
                continue;
            }
        }
        let base = w.rsplit('/').next().unwrap_or(w.as_str()).trim_start_matches('\\');
        if matches!(
            base,
            "sudo" | "env" | "command" | "nohup" | "nice" | "timeout" | "xargs" | "exec" | "time" | "ionice" | "stdbuf" | "setsid" | "busybox"
        ) {
            idx += 1;
            while idx < words.len() && words[idx].starts_with('-') {
                let flag = words[idx].as_str();
                idx += 1;
                if flag == "--" {
                    break;
                }
                if matches!(
                    flag,
                    "-u" | "-g" | "-C" | "-n" | "-s" | "-k" | "--user" | "--group" | "--chdir" | "--adjustment" | "--signal" | "--kill-after" | "-P" | "-L"
                ) && idx < words.len()
                {
                    idx += 1;
                }
            }
            if base == "timeout"
                && idx < words.len()
                && words[idx].chars().all(|c| c.is_ascii_digit() || matches!(c, '.' | 's' | 'm' | 'h' | 'd'))
            {
                idx += 1;
            }
            continue;
        }
        break;
    }
    words[idx..].to_vec()
}

pub fn collapse_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push(ch);
                prev_slash = true;
            }
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    out
}

pub fn normalize_lexical_posix(path: &str) -> String {
    let is_abs = path.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if let Some(&top) = stack.last() {
                if top != ".." {
                    stack.pop();
                    continue;
                }
            }
            if !is_abs {
                stack.push("..");
            }
            continue;
        }
        stack.push(seg);
    }
    if is_abs {
        if stack.is_empty() { "/".to_string() } else { format!("/{}", stack.join("/")) }
    } else if stack.is_empty() {
        ".".to_string()
    } else {
        stack.join("/")
    }
}

pub fn is_safe_build_cache_dir(seg: &str) -> bool {
    matches!(
        seg.to_ascii_lowercase().as_str(),
        "build" | "dist" | "target" | "node_modules" | ".cache" | "tmp_cache" | "tmp_build"
            | "__pycache__" | ".pytest_cache" | ".ruff_cache" | ".mypy_cache" | ".next" | ".turbo"
            | "coverage" | ".parcel-cache" | ".tox" | ".nox" | ".venv" | "venv" | "out" | "tmp" | "temp"
    )
}

pub fn is_protected_workspace_dir(seg: &str) -> bool {
    matches!(
        seg.to_ascii_lowercase().as_str(),
        ".git" | ".hg" | ".svn" | "src" | "lib" | "app" | "cmd" | "pkg" | "internal" | "tests"
            | "test" | "docs" | "doc" | "config" | "configs" | "conf" | "data" | "db"
            | "migrations" | "scripts" | "bin" | "infra" | "deploy" | ".github" | ".kintsugi"
            | ".agent" | ".agents" | ".claude" | ".vscode" | ".env" | "secrets" | "credentials"
            | "keys" | "certs"
    )
}

pub fn has_glob_meta(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

pub fn extract_leading_shell_var(raw: &str) -> Option<(String, &str)> {
    if !raw.starts_with('$') {
        return None;
    }
    if let Some(after_open) = raw.strip_prefix("${") {
        let close = after_open.find('}')?;
        let name = &after_open[..close];
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Some((name.to_string(), &after_open[close + 1..]));
        }
        return None;
    }
    let rest = &raw[1..];
    let end = rest
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    Some((rest[..end].to_string(), &rest[end..]))
}

pub(crate) fn is_dangerous_home_subpath(sub: &str) -> bool {
    if sub.is_empty() || sub == "*" || sub.split('/').any(|s| s == "..") {
        return true;
    }
    let hnorm = normalize_lexical_posix(sub);
    let hparts: Vec<&str> = hnorm.split('/').filter(|s| !s.is_empty()).collect();
    if hparts.is_empty()
        || hparts[0] == ".."
        || hparts.iter().any(|p| has_glob_meta(p) || is_protected_workspace_dir(p))
    {
        return true;
    }
    !(hparts.len() >= 2 && hparts[1..].iter().any(|s| is_safe_build_cache_dir(s)))
}

pub(crate) fn classify_non_ws_abs_path(norm: &str, parts: &[&str]) -> bool {
    for safe_tmp in ["/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/private/var/folders/"] {
        if format!("{norm}/").starts_with(safe_tmp) {
            if norm.starts_with("/private/tmp/") || norm.starts_with("/private/var/folders/") {
                return (parts.last() == Some(&"*") && parts.len() <= 3) || parts.len() < 3;
            }
            return parts.len() < 2;
        }
    }
    if matches!(parts[0], "home" | "Users") {
        if parts[2..].iter().any(|p| is_protected_workspace_dir(p)) {
            return true;
        }
        return !(parts.len() >= 4 && parts[3..].iter().any(|s| is_safe_build_cache_dir(s)));
    }
    if parts[0] == "root" {
        if parts[1..].iter().any(|p| is_protected_workspace_dir(p)) {
            return true;
        }
        return !(parts.len() >= 3 && parts[2..].iter().any(|s| is_safe_build_cache_dir(s)));
    }
    true
}

pub(crate) fn parse_json_string_array_items(raw_json: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let chars: Vec<char> = raw_json.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '"' {
            i += 1;
            continue;
        }
        i += 1;
        let mut s = String::new();
        while i < chars.len() {
            let ch = chars[i];
            if ch == '"' {
                i += 1;
                break;
            }
            if ch == '\\' && i + 1 < chars.len() {
                match chars[i + 1] {
                    '"' | '\\' | '/' => s.push(chars[i + 1]),
                    'n' => s.push('\n'),
                    'r' => s.push('\r'),
                    't' => s.push('\t'),
                    'u' if i + 5 < chars.len() => {
                        let hex: String = chars[i + 2..i + 6].iter().collect();
                        if let Some(uc) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                            s.push(uc);
                        }
                        i += 6;
                        continue;
                    }
                    other => s.push(other),
                }
                i += 2;
            } else {
                s.push(ch);
                i += 1;
            }
        }
        strings.push(s);
    }
    strings
}

pub fn audit_shell_command_argv(cmd: &str) -> Option<&'static str> {
    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    audit_shell_command_argv_inner(cmd, 0, Some(&cwd), false)
}

pub fn audit_shell_command_argv_with_ws(cmd: &str, ws_root: &Path, cwd_untrusted: bool) -> Option<&'static str> {
    audit_shell_command_argv_inner(cmd, 0, Some(ws_root), cwd_untrusted)
}

pub fn audit_shell_command_argv_inner(
    cmd: &str,
    depth: usize,
    ws_root: Option<&Path>,
    initial_untrusted: bool,
) -> Option<&'static str> {
    let (pipelines, stages) = split_shell_stages_and_pipelines(cmd);
    let mut cwd_untrusted = initial_untrusted;
    for chain in pipelines {
        if chain.len() < 2 {
            continue;
        }
        let mut has_untrusted_feed = false;
        for st in &chain[..chain.len() - 1] {
            let tks = split_shell_words(st);
            if let Some(first) = tks.first() {
                let verb = first.rsplit('/').next().unwrap_or(first.as_str()).trim_start_matches('\\').to_ascii_lowercase();
                if matches!(verb.as_str(), "curl" | "wget" | "fetch") {
                    has_untrusted_feed = true;
                } else if verb == "base64" && tks[1..].iter().any(|a| matches!(a.as_str(), "-d" | "-D" | "--decode")) {
                    has_untrusted_feed = true;
                }
            }
        }
        if has_untrusted_feed {
            if let Some(last) = chain.last() {
                let tks = split_shell_words(last);
                if let Some(first) = tks.first() {
                    let dv = first.rsplit('/').next().unwrap_or(first.as_str()).trim_start_matches('\\').to_ascii_lowercase();
                    if matches!(
                        dv.as_str(),
                        "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "python" | "python3" | "perl" | "ruby" | "eval"
                    ) {
                        return Some("Piped remote or base64-decoded payload into shell interpreter");
                    }
                }
            }
        }
    }

    for st in stages {
        let tks = split_shell_words(&st);
        if tks.is_empty() {
            continue;
        }
        let verb = tks[0].rsplit('/').next().unwrap_or(tks[0].as_str()).trim_start_matches('\\').to_ascii_lowercase();
        let args = &tks[1..];
        if matches!(verb.as_str(), "cd" | "pushd") {
            let dest = args.iter().find(|a| a.as_str() != "--" && !a.starts_with('-')).map(|s| s.trim()).unwrap_or("~");
            let dest_norm = normalize_lexical_posix(dest);
            let safe_tmp = dest.starts_with('/')
                && ["/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/private/var/folders/"]
                    .iter()
                    .any(|p| format!("{dest_norm}/").starts_with(p))
                && dest_norm.split('/').filter(|s| !s.is_empty()).count() >= 2;
            if !safe_tmp
                && (matches!(dest, "/" | "~" | "$HOME" | "${HOME}" | "..")
                    || dest.starts_with('/')
                    || dest.starts_with('~')
                    || dest.starts_with('$')
                    || dest.starts_with('`')
                    || dest.starts_with("../")
                    || dest.contains("/../")
                    || dest_norm.split('/').filter(|s| !s.is_empty() && *s != ".").any(is_protected_workspace_dir))
            {
                cwd_untrusted = true;
            }
            continue;
        }
        if verb == "rm" {
            let mut has_r = false;
            let mut has_f = false;
            let mut no_preserve_root = false;
            let mut targets = Vec::new();
            let mut end_opts = false;
            for a in args {
                if !end_opts && a == "--" {
                    end_opts = true;
                } else if !end_opts && a.starts_with("--") {
                    if a == "--recursive" {
                        has_r = true;
                    } else if a == "--force" {
                        has_f = true;
                    } else if a == "--no-preserve-root" {
                        no_preserve_root = true;
                    }
                } else if !end_opts && a.starts_with('-') && a.len() > 1 {
                    if a[1..].contains('r') || a[1..].contains('R') {
                        has_r = true;
                    }
                    if a[1..].contains('f') {
                        has_f = true;
                    }
                } else {
                    targets.push(a.as_str());
                }
            }
            if (no_preserve_root || has_r)
                && targets.iter().any(|t| is_dangerous_rm_target_with_ws_opt(t, ws_root, cwd_untrusted, true))
            {
                return Some("Destructive recursive rm targeting protected or unverified path");
            }
            if !has_r && has_f && targets.iter().any(|t| is_dangerous_rm_target_with_ws_opt(t, ws_root, cwd_untrusted, true)) {
                return Some("Forced file removal targeting protected path");
            }
        } else if verb == "git" {
            let mut gi = 0;
            while gi < args.len() {
                let a = args[gi].as_str();
                if a.starts_with("-C=") || a.starts_with("-c=") || a.starts_with("--git-dir=")
                    || a.starts_with("--work-tree=") || a.starts_with("--namespace=") || a.starts_with("--exec-path=")
                {
                    gi += 1;
                } else if matches!(
                    a,
                    "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--config-env" | "--exec-path"
                ) {
                    gi += 2;
                } else if matches!(
                    a,
                    "--no-pager" | "--bare" | "-p" | "--paginate" | "--no-replace-objects" | "--literal-pathspecs" | "--no-optional-locks"
                ) || a.starts_with("-C") || a.starts_with("-c")
                {
                    gi += 1;
                } else {
                    break;
                }
            }
            if gi < args.len() {
                let sub = args[gi].to_ascii_lowercase();
                let subargs = &args[gi + 1..];
                if sub == "reset" && subargs.iter().any(|x| x == "--hard") {
                    return Some("Destructive `git reset --hard` (including via global `-C`)");
                }
                if sub == "push" {
                    let has_lease = subargs.iter().any(|x| x == "--force-with-lease" || x.starts_with("--force-with-lease="));
                    let has_force = subargs.iter().any(|x| {
                        x == "-f" || x == "--force"
                            || (x.starts_with('-') && !x.starts_with("--") && x[1..].contains('f'))
                            || (x.starts_with('+') && !x.starts_with("+-"))
                    });
                    if has_force && !has_lease {
                        return Some("Destructive `git push --force`/`-f` without `--force-with-lease`");
                    }
                }
                if sub == "clean" {
                    let has_f = subargs.iter().any(|x| x == "--force" || (x.starts_with('-') && !x.starts_with("--") && x[1..].contains('f')));
                    let has_d = subargs.iter().any(|x| x.starts_with('-') && !x.starts_with("--") && x[1..].contains('d'));
                    if has_f && has_d {
                        return Some("Destructive `git clean -fd`/`-fdx`");
                    }
                }
            }
        } else if verb.starts_with("mkfs") {
            return Some("Destructive block device filesystem format (`mkfs`)");
        } else if verb == "dd" && args.iter().any(|a| a.starts_with("of=/dev/")) {
            return Some("Destructive raw disk overwrite (`dd of=/dev/...`)");
        } else if verb == "chmod" {
            let world = args.iter().any(|a| matches!(a.as_str(), "777" | "0777" | "a+rwx" | "o+w" | "o+rwx"));
            let protected_t = args.iter().any(|a| {
                !matches!(a.as_str(), "777" | "0777" | "a+rwx" | "o+w" | "o+rwx")
                    && !a.starts_with('-')
                    && is_dangerous_rm_target_with_ws_opt(a, ws_root, cwd_untrusted, true)
            });
            if world && protected_t {
                return Some("Destructive world-writable `chmod 777` on protected OS/home path");
            }
        } else if verb == "find" && (args.iter().any(|a| a == "-delete") || args.iter().any(|a| a == "-exec")) {
            let root_arg = args.iter().find(|a| !a.starts_with('-') && a.as_str() != "!").map(|s| s.as_str()).unwrap_or(".");
            let has_del = args.iter().any(|a| a == "-delete");
            let has_exec_rm = args.windows(2).any(|w| {
                w[0] == "-exec" && w[1].rsplit('/').next().unwrap_or(&w[1]).eq_ignore_ascii_case("rm")
            });
            if (has_del || has_exec_rm) && is_dangerous_rm_target_with_ws_opt(root_arg, ws_root, cwd_untrusted, true) {
                return Some("Destructive `find ... -delete/-exec rm` targeting protected path");
            }
        } else if matches!(verb.as_str(), "shred" | "wipefs") {
            if args.iter().any(|a| !a.starts_with('-') && is_dangerous_rm_target_with_ws_opt(a, ws_root, cwd_untrusted, true)) {
                return Some("Destructive block/file wipe command targeting protected path");
            }
        } else if verb == "eval" && depth < 2 && !args.is_empty() {
            if let Some(sub) = audit_shell_command_argv_inner(&args.join(" "), depth + 1, ws_root, cwd_untrusted) {
                return Some(sub);
            }
        } else if matches!(verb.as_str(), "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash") && depth < 2 {
            for (ai, arg) in args.iter().enumerate() {
                if (arg == "-c" || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('c'))) && ai + 1 < args.len() {
                    if let Some(sub) = audit_shell_command_argv_inner(&args[ai + 1], depth + 1, ws_root, cwd_untrusted) {
                        return Some(sub);
                    }
                }
            }
        }
    }
    None
}
