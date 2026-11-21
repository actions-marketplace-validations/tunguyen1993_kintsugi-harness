"""Claude Code PreToolUse Hook handler and `.claude/settings.json` / git pre-commit installer."""

from __future__ import annotations

import json
import os
import posixpath
import re
import shlex
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from kintsugi.models import GoldenScar, ScanFinding, Severity
from kintsugi.scanner import IGNORE_FILE_RE, KintsugiScanner
from kintsugi.shield import assert_not_symlink, atomic_write_text, normalize_shell_command

HEX_OCTAL_MAPPED_IP_RE = re.compile(
    r"\b0x[0-9a-fA-F]{4,}\b|::ffff:|\b0\d{2,3}\.\d+",
    re.IGNORECASE,
)
NETWORK_VERB_RE = re.compile(
    r"\b(?:ssh|scp|sftp|sshpass|rsync|curl|wget)\b",
    re.IGNORECASE,
)

_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_WRAPPER_VERBS = {"sudo", "env", "command", "nohup", "nice", "timeout", "xargs", "exec", "time", "ionice", "stdbuf", "setsid", "busybox"}
_WRAPPER_VALUE_FLAGS = {"-u", "-g", "-C", "-n", "-s", "-k", "--user", "--group", "--chdir", "--adjustment", "--signal", "--kill-after", "-P", "-L"}
_GIT_GLOBAL_VALUE_FLAGS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--exec-path"}
_GIT_GLOBAL_BOOL_FLAGS = {"--no-pager", "--bare", "-p", "--paginate", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks"}
_SAFE_BUILD_CACHE_DIRS = {
    "build",
    "dist",
    "target",
    "node_modules",
    ".cache",
    "tmp_cache",
    "tmp_build",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".next",
    ".turbo",
    "coverage",
    ".parcel-cache",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "out",
    "tmp",
    "temp",
}
_PROTECTED_WORKSPACE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "src",
    "lib",
    "app",
    "cmd",
    "pkg",
    "internal",
    "tests",
    "test",
    "docs",
    "doc",
    "config",
    "configs",
    "conf",
    "data",
    "db",
    "migrations",
    "scripts",
    "bin",
    "infra",
    "deploy",
    ".github",
    ".kintsugi",
    ".agent",
    ".agents",
    ".claude",
    ".vscode",
    ".env",
    "secrets",
    "credentials",
    "keys",
    "certs",
}
_SHELL_VAR_RE = re.compile(r"\$\{([^}]*)\}|\$([A-Za-z_][A-Za-z0-9_]*|\d+|[@*?#$-])")
_SAFE_TMP_PREFIXES = ("/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/private/var/folders/")
_CRITICAL_ABS_PREFIXES = (
    "/etc",
    "/usr",
    "/var",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/run",
    "/srv",
    "/opt",
    "/home",
    "/root",
    "/Users",
    "/System",
    "/Library",
    "/Applications",
    "/private",
    "/mnt",
    "/media",
)
_PIPE_FETCH_VERBS = {"curl", "wget", "fetch"}
_SHELL_EXEC_VERBS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "python", "python3", "perl", "ruby", "eval"}


def _has_glob_meta(text: str) -> bool:
    return any(ch in text for ch in ("*", "?", "["))


def _resolve_abs_uncollapsed(abs_raw: str, *, real_ws: str = "") -> Optional[str]:
    """
    Resolve an absolute POSIX path component-by-component on disk BEFORE collapsing `..`,
    following symlinks at every existing segment so `link/../target` cannot escape confinement
    or mask external symlinks (`KH-R4-SEC-01`). If the path ever enters `real_ws`, it must NEVER
    step back out or follow a symlink leaving `real_ws`. Returns None on invalid escapes or broken links.
    """
    collapsed = re.sub(r"/+", "/", abs_raw.strip())
    if not collapsed.startswith("/"):
        return None
    raw_segs = [s for s in collapsed.split("/") if s and s != "."]
    canon_segs: List[str] = []
    unseen_tail = False
    ws_trim = real_ws.rstrip("/") if real_ws and len([p for p in real_ws.split("/") if p]) >= 2 else ""
    ws_prefix = (ws_trim + "/") if ws_trim else ""
    entered_ws = False

    def _check_entered(cur_abs: str) -> bool:
        nonlocal entered_ws
        if not ws_trim:
            return True
        cur_t = cur_abs.rstrip("/")
        if cur_t == ws_trim or cur_t.startswith(ws_prefix):
            entered_ws = True
            return True
        if entered_ws:
            return False
        return True

    for idx, seg in enumerate(raw_segs):
        if _has_glob_meta(seg):
            if ".." in raw_segs[idx:]:
                return None
            canon_segs.extend(raw_segs[idx:])
            break
        if seg == "..":
            if not canon_segs:
                return None
            canon_segs.pop()
            if not _check_entered("/" + "/".join(canon_segs)):
                return None
            continue
        if unseen_tail:
            canon_segs.append(seg)
            if not _check_entered("/" + "/".join(canon_segs)):
                return None
            continue
        cand = "/" + "/".join([*canon_segs, seg])
        try:
            if os.path.islink(cand):
                if not os.path.exists(cand):
                    return None
                real_cand = os.path.realpath(cand)
                if idx == 0 and seg == "home" and real_cand == "/System/Volumes/Data/home":
                    canon_segs = ["home"]
                else:
                    canon_segs = [p for p in real_cand.split("/") if p]
                if not _check_entered("/" + "/".join(canon_segs)):
                    return None
            elif os.path.exists(cand):
                canon_segs.append(seg)
                if not _check_entered(cand):
                    return None
            else:
                canon_segs.append(seg)
                if not _check_entered(cand):
                    return None
                unseen_tail = True
        except OSError:
            return None
    return "/" + "/".join(canon_segs)


def _classify_workspace_rel_path(
    rel_raw: str,
    ws_root: Path,
    *,
    cwd_untrusted: bool = False,
) -> bool:
    """
    Existence-independent workspace-relative target check (`KH-R3-SEC-02`, `KH-R3-FUNC-03`, `KH-R4-SEC-01`).
    Walks raw path components BEFORE collapsing `..` so escaping symlinks (`link/../build`) are caught
    before `..` normalization. Returns True if DANGEROUS (DENY), False only for safe build/cache dirs.
    """
    if cwd_untrusted:
        return True
    collapsed = re.sub(r"/+", "/", rel_raw.strip())
    if collapsed in ("", ".", "..", "*") or collapsed.startswith("/"):
        return True

    raw_segs = [s for s in collapsed.split("/") if s and s != "."]
    if not raw_segs or raw_segs[0] == "..":
        return True

    try:
        real_ws = os.path.realpath(str(ws_root))
    except OSError:
        return True
    ws_prefix = real_ws.rstrip("/") + "/"

    resolved_segs: List[str] = []
    glob_tail: List[str] = []
    unseen_tail = False
    for idx, seg in enumerate(raw_segs):
        if _has_glob_meta(seg):
            if ".." in raw_segs[idx:]:
                return True
            glob_tail = raw_segs[idx:]
            break
        if seg == "..":
            if not resolved_segs:
                return True
            resolved_segs.pop()
            continue
        if seg.lower() in _PROTECTED_WORKSPACE_DIRS:
            return True
        resolved_segs.append(seg)
        if unseen_tail:
            continue
        probe = os.path.join(real_ws, *resolved_segs)
        try:
            if os.path.islink(probe):
                if not os.path.exists(probe):
                    return True
                real_cur = os.path.realpath(probe)
                if real_cur == real_ws or not real_cur.startswith(ws_prefix):
                    return True
                resolved_rel = posixpath.relpath(real_cur, real_ws)
                new_segs = [p for p in resolved_rel.split("/") if p and p != "."]
                if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in new_segs):
                    return True
                resolved_segs = new_segs
            elif not os.path.exists(probe):
                unseen_tail = True
        except OSError:
            return True

    parts = resolved_segs + glob_tail
    if not parts:
        return True
    # Protect any critical workspace dir at any depth, case-insensitively (`docs`, `src`, `.git`, `config`, `data`, ...)
    if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in parts):
        return True
    # Glob inside a confirmed disposable cache/build prefix (e.g. ./build/*) is OK; bare globs are forbidden
    if _has_glob_meta(parts[0]):
        return True
    # Fail-closed: ONLY allow workspace-relative recursive deletion when scoped under known build/cache dirs
    # Only a top-level disposable cache/build root is authorized. A nested
    # `other/build` may hold irreplaceable project data.
    return parts[0].lower() not in _SAFE_BUILD_CACHE_DIRS


def _is_dangerous_rm_target(
    tgt: str,
    *,
    workspace_root: Optional[Path] = None,
    cwd_untrusted: bool = False,
    _resolve_symlink: bool = True,
) -> bool:
    """
    Existence-independent, workspace-aware path policy rejecting destructive removal on OS/home/sensitive roots,
    unknown shell variables (`$PROJECT_ROOT`), and critical or unverified workspace targets (`KH-R2-SEC-01`, `KH-R3-SEC-02`, `KH-R3-FUNC-03`).
    """
    raw = tgt.strip()
    if not raw:
        return False
    ws_root = workspace_root if workspace_root is not None else Path.cwd()

    # Fail-closed on command substitution or backticks
    if "`" in raw or "$(" in raw:
        return True

    # Inspect shell variable expansions explicitly before path normalization
    var_matches = list(_SHELL_VAR_RE.finditer(raw))
    if var_matches:
        if len(var_matches) != 1 or var_matches[0].start() != 0:
            return True
        m0 = var_matches[0]
        var_name = m0.group(1) if m0.group(1) is not None else (m0.group(2) or "")
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", var_name):
            return True
        after = raw[m0.end() :]
        if var_name == "PWD":
            if after in ("", "/", "/*") or not after.startswith("/"):
                return True
            return _classify_workspace_rel_path(after.lstrip("/"), ws_root, cwd_untrusted=cwd_untrusted)
        if var_name == "HOME":
            if after in ("", "/", "/*") or not after.startswith("/") or ".." in after.split("/"):
                return True
            home_norm = posixpath.normpath(re.sub(r"/+", "/", after.lstrip("/")))
            home_parts = [p for p in home_norm.split("/") if p]
            if not home_parts or home_parts[0] == ".." or any(_has_glob_meta(p) for p in home_parts):
                return True
            if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in home_parts):
                return True
            if len(home_parts) >= 2 and any(seg in _SAFE_BUILD_CACHE_DIRS for seg in home_parts[1:]):
                return False
            return True
        if var_name in ("TMPDIR", "TMP", "TEMP"):
            if after in ("", "/", "/*") or not after.startswith("/"):
                return True
            raw = f"/tmp/{after.lstrip('/')}"
        else:
            # Unknown or untrusted env var (`${PROJECT_ROOT}/src`, `$DIR`, `$ROOT`, etc.) -> fail-closed
            return True

    # Home `~` prefix handling
    if raw.startswith("~"):
        if raw in ("~", "~/", "~/*") or not raw.startswith("~/") or ".." in raw.split("/"):
            return True
        home_norm = posixpath.normpath(re.sub(r"/+", "/", raw[2:]))
        home_parts = [p for p in home_norm.split("/") if p]
        if not home_parts or home_parts[0] == ".." or any(_has_glob_meta(p) for p in home_parts):
            return True
        if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in home_parts):
            return True
        if len(home_parts) >= 2 and any(seg in _SAFE_BUILD_CACHE_DIRS for seg in home_parts[1:]):
            return False
        return True

    collapsed = re.sub(r"/+", "/", raw)
    norm = posixpath.normpath(collapsed)
    if norm in (".", "..", "/", "*", "/*", ".*") or collapsed.rstrip("/") in ("", ".", "..", "*"):
        return True
    if raw.endswith("/*") and len([p for p in norm.strip("/").split("/") if p]) <= 2:
        return True
    if norm == ".." or norm.startswith("../"):
        return True

    if collapsed.startswith("/"):
        ws_candidates: List[str] = []
        ws_raw = re.sub(r"/+", "/", str(ws_root)).rstrip("/")
        if ws_raw and len([p for p in ws_raw.split("/") if p]) >= 2:
            ws_candidates.append(ws_raw)
        try:
            real_ws = os.path.realpath(str(ws_root))
        except OSError as exc:
            _ = exc
            real_ws = ""
        if real_ws and len([p for p in real_ws.split("/") if p]) >= 2 and real_ws.rstrip("/") not in ws_candidates:
            ws_candidates.append(real_ws.rstrip("/"))
        for wp in ws_candidates:
            if collapsed == wp:
                return True
            if collapsed.startswith(wp + "/"):
                return _classify_workspace_rel_path(collapsed[len(wp) + 1 :], ws_root, cwd_untrusted=cwd_untrusted)

        resolved_abs = _resolve_abs_uncollapsed(collapsed, real_ws=real_ws)
        if resolved_abs is None:
            return True
        norm = resolved_abs
        parts = [p for p in norm.split("/") if p]
        if len(parts) <= 1:
            return True
        if any(f"{norm}/".startswith(pref) or norm == pref.rstrip("/") for pref in _SAFE_TMP_PREFIXES):
            if norm.startswith("/private/tmp/") or norm.startswith("/private/var/folders/"):
                if parts[-1] == "*" and len(parts) <= 3:
                    return True
                return len(parts) < 3
            return len(parts) < 2
        if real_ws:
            ws_parts = [p for p in real_ws.split("/") if p]
            ws_prefix = real_ws.rstrip("/") + "/"
            if len(ws_parts) >= 2 and norm.startswith(ws_prefix):
                rel_from_ws = posixpath.relpath(norm, real_ws)
                return _classify_workspace_rel_path(rel_from_ws, ws_root, cwd_untrusted=cwd_untrusted)
        if parts[0] in ("home", "Users"):
            if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in parts[2:]):
                return True
            if len(parts) >= 4 and any(seg in _SAFE_BUILD_CACHE_DIRS for seg in parts[3:]):
                return False
            return True
        if parts[0] == "root":
            if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in parts[1:]):
                return True
            if len(parts) >= 3 and any(seg in _SAFE_BUILD_CACHE_DIRS for seg in parts[2:]):
                return False
            return True
        for cp in _CRITICAL_ABS_PREFIXES:
            if norm == cp or norm.startswith(f"{cp}/"):
                return True
        return True

    return _classify_workspace_rel_path(collapsed, ws_root, cwd_untrusted=cwd_untrusted)


def _deny_payload(reason: str) -> Dict[str, Any]:
    return {
        "decision": "deny",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def _split_outside_quotes(text: str, seps: Sequence[str]) -> List[str]:
    """Split shell string on separator tokens only when outside single/double quotes and backslash escapes."""
    out: List[str] = []
    cur: List[str] = []
    in_sq = False
    in_dq = False
    i = 0
    n = len(text)
    sorted_seps = sorted(seps, key=len, reverse=True)
    while i < n:
        ch = text[i]
        if ch == "\\" and not in_sq and i + 1 < n:
            cur.append(ch)
            cur.append(text[i + 1])
            i += 2
            continue
        if ch == "'" and not in_dq:
            in_sq = not in_sq
            cur.append(ch)
            i += 1
            continue
        if ch == '"' and not in_sq:
            in_dq = not in_dq
            cur.append(ch)
            i += 1
            continue
        if not in_sq and not in_dq:
            matched_sep = next((sep for sep in sorted_seps if text.startswith(sep, i)), None)
            if matched_sep is not None:
                out.append("".join(cur))
                cur = []
                i += len(matched_sep)
                continue
        cur.append(ch)
        i += 1
    if cur:
        out.append("".join(cur))
    return out


def _split_shell_segments_and_pipelines(cmd: str) -> Tuple[List[List[str]], List[str]]:
    """Split shell command into semicolon/newline/boolean segments and `|` pipeline chains, respecting quotes."""
    segments = _split_outside_quotes(cmd, ("&&", "||", ";", "\n"))
    pipelines: List[List[str]] = []
    single_cmds: List[str] = []
    for seg in segments:
        cleaned_stages = [s.strip() for s in _split_outside_quotes(seg, ("|",)) if s.strip()]
        if len(cleaned_stages) >= 2:
            pipelines.append(cleaned_stages)
        single_cmds.extend(cleaned_stages)
    return pipelines, single_cmds


def _tokenize_shell_stage(stage: str) -> List[str]:
    try:
        tokens = shlex.split(stage, posix=True)
    except ValueError:
        tokens = stage.split()
    # Strip leading env var assignments and command wrappers (`sudo`, `env`, `command`, `nohup`, ...)
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if _ENV_ASSIGN_RE.match(tok):
            idx += 1
            continue
        base = os.path.basename(tok)
        if base in _WRAPPER_VERBS:
            idx += 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                flag = tokens[idx]
                idx += 1
                if flag == "--":
                    break
                if flag in _WRAPPER_VALUE_FLAGS and idx < len(tokens):
                    idx += 1
            if base == "timeout" and idx < len(tokens) and re.match(r"^\d+(?:\.\d+)?[smhd]?$", tokens[idx]):
                idx += 1
            continue
        break
    return tokens[idx:]


def _ks002_finding(snippet: str, rationale: str) -> ScanFinding:
    return ScanFinding(
        scar_id="KS-002",
        title="Destructive shell or irreversible git history wipe",
        severity=Severity.CRITICAL,
        category="safety",
        file_path="<bash>",
        line=1,
        column=1,
        snippet=snippet[:140],
        rationale=rationale,
        good_code_hint="git stash push -u -m 'pre-refactor-backup' && git status",
        engine="s3-shell-argv",
    )


def _audit_shell_command_argv(
    cmd: str,
    _depth: int = 0,
    *,
    workspace_root: Optional[Path] = None,
    _cwd_untrusted: bool = False,
) -> List[ScanFinding]:
    """Argv/AST analyzer detecting flag permutations, wrappers, subshells, git `-C`, `cd` taint, and pipe-to-shell bypasses (`KH-SEC-001`, `KH-R3-SEC-02`)."""
    findings: List[ScanFinding] = []
    pipelines, stages = _split_shell_segments_and_pipelines(cmd)
    ws_root = workspace_root if workspace_root is not None else Path.cwd()
    cwd_untrusted = _cwd_untrusted

    # 1. Pipeline-stage fetch/decode -> interpreter execution check
    for chain in pipelines:
        tokenized = [_tokenize_shell_stage(st) for st in chain]
        has_untrusted_feed = False
        for tks in tokenized[:-1]:
            if not tks:
                continue
            v = os.path.basename(tks[0]).lower()
            if v in _PIPE_FETCH_VERBS:
                has_untrusted_feed = True
            elif v == "base64" and any(a in ("-d", "-D", "--decode") for a in tks[1:]):
                has_untrusted_feed = True
        downstream_verb = os.path.basename(tokenized[-1][0]).lower() if tokenized and tokenized[-1] else ""
        if has_untrusted_feed and downstream_verb in _SHELL_EXEC_VERBS:
            findings.append(
                _ks002_finding(
                    cmd,
                    f"Piping remote/decoded payload directly into `{downstream_verb}` executes unverified commands.",
                )
            )

    # 2. Per-command argv inspection
    for st in stages:
        tokens = _tokenize_shell_stage(st)
        if not tokens:
            continue
        verb = os.path.basename(tokens[0].lstrip("\\")).lower()
        args = tokens[1:]

        if verb in ("cd", "pushd"):
            dest = next((a for a in args if a != "--" and not a.startswith("-")), "~")
            dest_s = dest.strip()
            dest_norm = posixpath.normpath(re.sub(r"/+", "/", dest_s))
            is_safe_tmp = (
                dest_s.startswith("/")
                and any(f"{dest_norm}/".startswith(p) for p in _SAFE_TMP_PREFIXES)
                and len([x for x in dest_norm.split("/") if x]) >= 2
            )
            if not is_safe_tmp:
                if (
                    dest_s in ("/", "~", "$HOME", "${HOME}", "..")
                    or dest_s.startswith(("/", "~", "$", "`", "../"))
                    or "/../" in f"/{dest_s}/"
                ):
                    cwd_untrusted = True
                else:
                    parts = [p for p in dest_norm.split("/") if p and p != "."]
                    if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in parts):
                        cwd_untrusted = True
            continue

        if verb == "rm":
            has_r = False
            has_f = False
            no_preserve_root = False
            targets: List[str] = []
            end_opts = False
            for a in args:
                if not end_opts and a == "--":
                    end_opts = True
                    continue
                if not end_opts and a.startswith("--"):
                    if a == "--recursive":
                        has_r = True
                    elif a == "--force":
                        has_f = True
                    elif a == "--no-preserve-root":
                        no_preserve_root = True
                elif not end_opts and a.startswith("-") and len(a) > 1:
                    if "r" in a[1:] or "R" in a[1:]:
                        has_r = True
                    if "f" in a[1:]:
                        has_f = True
                else:
                    targets.append(a)
            if no_preserve_root or has_r:
                for tgt in targets:
                    if _is_dangerous_rm_target(tgt, workspace_root=ws_root, cwd_untrusted=cwd_untrusted):
                        findings.append(
                            _ks002_finding(
                                st,
                                f"Destructive recursive removal (`rm`) targeting protected or unverified path `{tgt}`.",
                            )
                        )
                        break
            elif has_f:
                for tgt in targets:
                    if _is_dangerous_rm_target(tgt, workspace_root=ws_root, cwd_untrusted=cwd_untrusted):
                        findings.append(
                            _ks002_finding(
                                st,
                                f"Forced file removal (`rm -f`) targeting protected path `{tgt}`.",
                            )
                        )
                        break

        elif verb == "git":
            gi = 0
            while gi < len(args):
                a = args[gi]
                if any(a.startswith(f"{gf}=") for gf in _GIT_GLOBAL_VALUE_FLAGS):
                    gi += 1
                    continue
                if a in _GIT_GLOBAL_VALUE_FLAGS:
                    gi += 2
                    continue
                if a in _GIT_GLOBAL_BOOL_FLAGS or a.startswith("-C") or a.startswith("-c"):
                    if (a.startswith("-C") or a.startswith("-c")) and len(a) == 2:
                        gi += 2
                    else:
                        gi += 1
                    continue
                break
            if gi < len(args):
                subcmd = args[gi].lower()
                subargs = args[gi + 1 :]
                if subcmd == "reset" and "--hard" in subargs:
                    findings.append(
                        _ks002_finding(
                            st,
                            "Destructive hard reset (`reset --hard`, including via `git -C ...`) destroys uncommitted workspace changes.",
                        )
                    )
                elif subcmd == "push":
                    has_lease = any(x == "--force-with-lease" or x.startswith("--force-with-lease=") for x in subargs)
                    has_force = any(
                        x in ("-f", "--force")
                        or (x.startswith("-") and not x.startswith("--") and "f" in x[1:])
                        or (x.startswith("+") and not x.startswith("+-"))
                        for x in subargs
                    )
                    if has_force and not has_lease:
                        findings.append(
                            _ks002_finding(
                                st,
                                "Forced push (`--force` / `-f`) without `--force-with-lease` risks irreversible remote history loss.",
                            )
                        )
                elif subcmd == "clean":
                    clean_f = any(x == "--force" or (x.startswith("-") and not x.startswith("--") and "f" in x[1:]) for x in subargs)
                    clean_d = any(x.startswith("-") and not x.startswith("--") and "d" in x[1:] for x in subargs)
                    if clean_f and clean_d:
                        findings.append(
                            _ks002_finding(
                                st,
                                "`git clean -fd` / `-fdx` irreversibly deletes untracked files.",
                            )
                        )

        elif verb.startswith("mkfs"):
            findings.append(_ks002_finding(st, f"`{verb}` formats block devices destructively."))

        elif verb == "dd" and any(a.startswith("of=/dev/") for a in args):
            findings.append(_ks002_finding(st, "Raw block device write `dd ... of=/dev/...` blocked."))

        elif verb == "chmod":
            world = any(a in ("777", "0777", "a+rwx", "o+w", "o+rwx") for a in args)
            protected_tgt = any(
                _is_dangerous_rm_target(a, workspace_root=ws_root, cwd_untrusted=cwd_untrusted)
                for a in args
                if a not in ("777", "0777", "a+rwx", "o+w", "o+rwx") and not a.startswith("-")
            )
            if world and protected_tgt:
                findings.append(_ks002_finding(st, "World-writable `chmod 777` on protected OS/home path compromises system permissions."))

        elif verb == "find" and ("-delete" in args or "-exec" in args):
            root_arg = next((a for a in args if not a.startswith("-") and a != "!"), ".")
            has_rm_exec = False
            if "-exec" in args:
                ei = args.index("-exec")
                if ei + 1 < len(args) and os.path.basename(args[ei + 1]).lower() == "rm":
                    has_rm_exec = True
            if ("-delete" in args or has_rm_exec) and _is_dangerous_rm_target(
                root_arg, workspace_root=ws_root, cwd_untrusted=cwd_untrusted
            ):
                findings.append(_ks002_finding(st, f"Destructive `find {root_arg} -delete/-exec rm` targeting protected path."))

        elif verb in ("shred", "wipefs"):
            if any(_is_dangerous_rm_target(a, workspace_root=ws_root, cwd_untrusted=cwd_untrusted) for a in args if not a.startswith("-")):
                findings.append(_ks002_finding(st, f"Destructive `{verb}` targeting protected path or device."))

        elif verb == "eval" and _depth < 2 and args:
            findings.extend(
                _audit_shell_command_argv(
                    " ".join(args),
                    _depth=_depth + 1,
                    workspace_root=ws_root,
                    _cwd_untrusted=cwd_untrusted,
                )
            )

        elif verb in {"sh", "bash", "zsh", "dash", "ksh", "ash"} and _depth < 2:
            for ai, arg in enumerate(args):
                if (arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:])) and ai + 1 < len(args):
                    findings.extend(
                        _audit_shell_command_argv(
                            args[ai + 1],
                            _depth=_depth + 1,
                            workspace_root=ws_root,
                            _cwd_untrusted=cwd_untrusted,
                        )
                    )

    return findings


def evaluate_claude_pre_tool_payload(
    payload: Dict[str, Any],
    scars: Sequence[GoldenScar],
    *,
    block_threshold: Severity = Severity.HIGH,
    trusted_workspace_root: Optional[str | Path] = None,
) -> Dict[str, Any]:
    """
    Evaluate a Claude Code or Antigravity `PreToolUse` JSON event in-memory (< 15ms)
    with Grade S3 NFKC/Bidi/quote-splitting, argv shell AST analysis, non-suppressive scanning,
    trusted workspace root confinement (`KH-R4-SEC-04`), and Hex/Octal IP blocking.
    """
    if not isinstance(payload, dict):
        return _deny_payload("FAIL-CLOSED HOOK GUARD: Payload must be a JSON object.")

    raw_tool_call = payload.get("toolCall") if "toolCall" in payload else None
    if raw_tool_call is not None and not isinstance(raw_tool_call, dict):
        return _deny_payload("FAIL-CLOSED HOOK GUARD: toolCall must be a JSON object.")
    tool_call = raw_tool_call if isinstance(raw_tool_call, dict) else {}
    tool_name = str(payload.get("tool_name") or tool_call.get("name") or "")

    if "tool_input" in payload and payload["tool_input"] is not None:
        tool_input = payload["tool_input"]
    elif "args" in tool_call and tool_call["args"] is not None:
        tool_input = tool_call["args"]
    else:
        tool_input = {}

    if not isinstance(tool_input, dict):
        return _deny_payload("FAIL-CLOSED HOOK GUARD: tool_input must be a JSON object.")

    if not tool_name and ("CommandLine" in tool_input or "command" in tool_input):
        tool_name = "run_command"

    # Agents must NEVER self-suppress guardrails via inline ignore comments in tool payloads (KH-SEC-002)
    scanner = KintsugiScanner(scars, allow_inline_ignores=False)
    findings: List[ScanFinding] = []

    def _scan_agent_write(content_text: str, fpath: str) -> None:
        if IGNORE_FILE_RE.search(content_text):
            findings.append(
                ScanFinding(
                    scar_id="KS-S3-IGNORE-BYPASS",
                    title="Untrusted inline `kintsugi: ignore-file` directive in agent tool payload",
                    severity=Severity.HIGH,
                    category="security",
                    file_path=fpath,
                    line=1,
                    column=1,
                    snippet="kintsugi: ignore-file",
                    rationale="Agents may not disable security scanning by injecting `kintsugi: ignore-file` into generated code. Exceptions require external trusted policy.",
                    good_code_hint="# Fix the underlying vulnerability or configure trusted workspace policy.",
                    engine="s3-hook-guard",
                )
            )
        findings.extend(scanner.scan_text(content_text, file_path=fpath, allow_inline_ignores=False))

    if tool_name in {"Write", "CreateFile", "write_file"}:
        fpath = str(tool_input.get("file_path") or tool_input.get("path") or "<write>")
        content = str(tool_input.get("content") or "")
        _scan_agent_write(content, fpath)

    elif tool_name in {"Edit", "Replace", "edit_file"}:
        fpath = str(tool_input.get("file_path") or tool_input.get("path") or "<edit>")
        new_str = str(tool_input.get("new_string") or tool_input.get("replacement") or "")
        _scan_agent_write(new_str, fpath)

    elif tool_name == "MultiEdit":
        fpath = str(tool_input.get("file_path") or "<multiedit>")
        edits = tool_input.get("edits") or []
        if isinstance(edits, list):
            combined = "\n".join(
                str(ed.get("new_string") or "") for ed in edits if isinstance(ed, dict)
            )
            _scan_agent_write(combined, fpath)

    elif tool_name in {"Bash", "run_command"}:
        raw_cmd = str(tool_input.get("command") or tool_input.get("CommandLine") or "")
        cmd = normalize_shell_command(raw_cmd)
        if NETWORK_VERB_RE.search(cmd) and HEX_OCTAL_MAPPED_IP_RE.search(cmd):
            findings.append(
                ScanFinding(
                    scar_id="KS-S3-IP-OBFUSCATION",
                    title="Obfuscated Hex/Octal/IPv6-Mapped IP in Network Command",
                    severity=Severity.CRITICAL,
                    category="security",
                    file_path="<bash>",
                    line=1,
                    column=1,
                    snippet=cmd[:140],
                    rationale="Hex (0x...), octal (0177...), or IPv6-mapped (::ffff:) IP notation used to bypass host/SSRF allowlists. Use canonical dotted-decimal IPv4 or verified domain names only.",
                    good_code_hint="ssh user@192.0.2.10",
                    engine="s3-hook-guard",
                )
            )
        env_ws = os.environ.get("KINTSUGI_TRUSTED_WORKSPACE", "").strip()
        trust_base = Path(trusted_workspace_root) if trusted_workspace_root is not None else (Path(env_ws) if env_ws else Path.cwd())
        try:
            real_trust = Path(os.path.realpath(str(trust_base)))
        except OSError:
            return _deny_payload("FAIL-CLOSED HOOK GUARD: Unable to resolve trusted workspace root.")
        raw_agent_cwd = str(tool_input.get("cwd") or tool_input.get("workspace_root") or payload.get("cwd") or "").strip()
        effective_ws = real_trust
        agent_cwd_untrusted = False
        if raw_agent_cwd:
            if _has_glob_meta(raw_agent_cwd) or "`" in raw_agent_cwd or "$" in raw_agent_cwd or not raw_agent_cwd.startswith("/"):
                agent_cwd_untrusted = True
            else:
                resolved_agent = _resolve_abs_uncollapsed(re.sub(r"/+", "/", raw_agent_cwd), real_ws=str(real_trust))
                if not resolved_agent:
                    agent_cwd_untrusted = True
                else:
                    trust_s = str(real_trust).rstrip("/")
                    agent_s = resolved_agent.rstrip("/")
                    if agent_s == trust_s:
                        effective_ws = real_trust
                    elif agent_s.startswith(trust_s + "/"):
                        rel_cwd = posixpath.relpath(agent_s, trust_s)
                        rel_parts = [p for p in rel_cwd.split("/") if p and p != "."]
                        if any(p.lower() in _PROTECTED_WORKSPACE_DIRS for p in rel_parts):
                            agent_cwd_untrusted = True
                        else:
                            effective_ws = Path(agent_s)
                    else:
                        agent_cwd_untrusted = True
        findings.extend(
            _audit_shell_command_argv(
                cmd,
                workspace_root=effective_ws,
                _cwd_untrusted=agent_cwd_untrusted,
            )
        )
        findings.extend(scanner.scan_text(cmd, file_path="<bash>", language="shell", allow_inline_ignores=False))

    # Deduplicate findings by (scar_id, line)
    deduped: List[ScanFinding] = []
    seen_pairs = set()
    for f in findings:
        key = (f.scar_id, f.line)
        if key not in seen_pairs:
            seen_pairs.add(key)
            deduped.append(f)

    blocking = [f for f in deduped if f.severity.meets(block_threshold)]
    if not blocking:
        # Leave permissionDecision unset on clean calls so Claude Code's normal
        # user permission prompt remains intact (never auto-approve clean tool calls).
        return {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
            },
        }

    reason_lines = [
        f"Kintsugi PreToolUse Guard blocked {len(blocking)} violation(s):"
    ]
    for f in blocking[:3]:
        reason_lines.append(
            f"- [{f.scar_id} / {f.severity.value}] {f.title} (line {f.line}): `{f.snippet}`\n"
            f"  Why: {f.rationale}\n"
            f"  Verified Fix:\n  {f.good_code_hint}"
        )

    return _deny_payload("\n".join(reason_lines))


def install_claude_settings_hook(workspace_root: str | Path) -> Path:
    """Register `kintsugi hook claude-pre-tool` inside `.claude/settings.json` idempotently."""
    root = Path(workspace_root)
    settings_path = root / ".claude" / "settings.json"
    assert_not_symlink(settings_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    data: Dict[str, Any] = {}
    if settings_path.exists():
        raw_settings = settings_path.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw_settings)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Refusing to overwrite malformed .claude/settings.json ({settings_path}): {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ValueError(
                f"Refusing to overwrite non-object .claude/settings.json ({settings_path})"
            )
        # Write a .bak backup before modifying existing settings.json
        backup_path = settings_path.with_suffix(".json.bak")
        atomic_write_text(backup_path, raw_settings, mode=0o600)
        data = parsed

    hooks_obj = data.setdefault("hooks", {})
    pre_tool_list = hooks_obj.setdefault("PreToolUse", [])
    hook_cmd = "kintsugi hook claude-pre-tool"

    already_installed = any(
        isinstance(entry, dict)
        and any(
            isinstance(h, dict) and hook_cmd in str(h.get("command", ""))
            for h in (entry.get("hooks") or [])
        )
        for entry in pre_tool_list
    )
    if not already_installed:
        pre_tool_list.append(
            {
                "matcher": "Write|Edit|MultiEdit|Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": hook_cmd,
                    }
                ],
            }
        )

    atomic_write_text(settings_path, json.dumps(data, indent=2) + "\n", mode=0o600)
    return settings_path


def _resolve_git_hooks_dir(workspace_root: Path) -> Path:
    """Resolve Git's active hooks directory (honoring `core.hooksPath` and linked worktrees)."""
    import subprocess

    proc = subprocess.run(
        ["git", "-C", str(workspace_root), "rev-parse", "--git-path", "hooks"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        candidate = Path(proc.stdout.strip())
        if candidate.is_absolute():
            return candidate
        return (workspace_root / candidate).resolve()
    return workspace_root / ".git" / "hooks"


def install_git_pre_commit_hook(workspace_root: str | Path) -> Path:
    """
    Install a lightweight git pre-commit hook running index-safe
    `kintsugi scan . --ledger .kintsugi/scars.json --staged --fail-on HIGH`,
    honoring `git rev-parse --git-path hooks` and preserving/chaining any existing hook.
    """
    root = Path(workspace_root)
    hooks_dir = _resolve_git_hooks_dir(root)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    backup_hook = hooks_dir / "pre-commit.pre-kintsugi"

    if hook_path.exists():
        existing_text = hook_path.read_text(encoding="utf-8", errors="replace")
        if "# Managed by kintsugi-harness" not in existing_text:
            backup_hook.write_text(existing_text, encoding="utf-8")
            backup_mode = hook_path.stat().st_mode
            backup_hook.chmod(backup_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    script = (
        "#!/usr/bin/env sh\n"
        "# Managed by kintsugi-harness\n"
        "set -e\n"
        'HOOK_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\n'
        'if [ -x "$HOOK_DIR/pre-commit.pre-kintsugi" ]; then\n'
        '  "$HOOK_DIR/pre-commit.pre-kintsugi" "$@"\n'
        "fi\n"
        "kintsugi scan . --ledger .kintsugi/scars.json --staged --fail-on HIGH\n"
    )
    hook_path.write_text(script, encoding="utf-8")
    mode = hook_path.stat().st_mode
    hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path
