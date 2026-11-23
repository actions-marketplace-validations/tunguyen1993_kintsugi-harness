"""Arm C minimal-context external verification gate (`kintsugi.arm_c_gate`).

Replaces multi-thousand-byte rule-prose context (`AGENTS.md`, 6,823 bytes) with
a 3-line security + step-economics invariant directive (`ARM_C_AGENTS_MD`, <= 220 bytes)
and runs `kintsugi-rs scan` (including `--shadow-arm-c`) plus `kintsugi-rs s3-audit`
as a fail-closed, symlink-confined external `PostEdit` / `PreFinish` gate.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from kintsugi.shield import assert_not_symlink

ARM_C_AGENTS_MD: str = (
    "# Kintsugi\n"
    "Reject symlinks(O_NOFOLLOW), non-https/localhost/privIP, eval/Call/Attr, float-money, git '-'/NUL/;&|; git --, SQL ?, compare_digest, mask PEM/PAT.\n"
    "Fast: no skills/mem/ls; read, write, 1 test; no kintsugi-rs."
)

_MAX_GATE_FILE_BYTES = 16 * 1024 * 1024


def estimate_tokens(text: str) -> int:
    """Mirror `kintsugi_core::estimate_tokens` (`max((chars + 3) // 4, words)`)."""
    if not text:
        return 0
    by_chars = (len(text) + 3) // 4
    words = len(text.split())
    return words if words > by_chars else by_chars


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular_nofollow(
    path: Path,
    *,
    require_non_world_writable: bool = False,
    max_bytes: Optional[int] = _MAX_GATE_FILE_BYTES,
) -> Tuple[bytes, str, os.stat_result]:
    """Open `path` once via `O_RDONLY | O_NOFOLLOW`, verify regular file, and return `(bytes, sha256, stat)`."""
    assert_not_symlink(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError(f"SECURITY_SYMLINK_REFUSED: {path}") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_NOT_REGULAR_FILE: {path}")
        if require_non_world_writable and (st.st_mode & 0o002) != 0:
            raise PermissionError(f"SECURITY_WORLD_WRITABLE_EXECUTABLE: {path}")
        chunks: List[bytes] = []
        total = 0
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"File exceeds max gate size ({max_bytes} bytes): {path}")
            chunks.append(chunk)
            h.update(chunk)
        return b"".join(chunks), h.hexdigest(), st
    finally:
        os.close(fd)


def _resolve_confined_file(ws_real: Path, raw_file: Union[str, Path]) -> Tuple[str, Path]:
    """Confine `raw_file` strictly inside `ws_real`, rejecting symlinks and traversal escapes."""
    raw_str = str(raw_file).strip()
    if not raw_str or "\x00" in raw_str:
        raise ValueError(f"INVALID_CHANGED_FILE_PATH: {raw_file!r}")

    cand = Path(raw_str)
    if not cand.is_absolute():
        cand = ws_real / cand

    # Reject symlinks along all components from workspace root down to the file
    assert_not_symlink(cand)
    parent = cand.parent
    while True:
        assert_not_symlink(parent)
        if parent == ws_real or parent == parent.parent:
            break
        parent = parent.parent

    resolved = Path(os.path.realpath(str(cand)))
    try:
        common = os.path.commonpath([str(resolved), str(ws_real)])
    except ValueError as exc:
        raise PermissionError(f"SECURITY_PATH_ESCAPE_REFUSED: {raw_file}") from exc
    if common != str(ws_real) or resolved == ws_real:
        raise PermissionError(f"SECURITY_PATH_ESCAPE_REFUSED: {raw_file} outside {ws_real}")

    rel_posix = resolved.relative_to(ws_real).as_posix()
    return rel_posix, resolved


def _resolve_rust_binary(ws_real: Path, rust_bin: Optional[Union[str, Path]]) -> Tuple[Path, str]:
    """Locate and verify `kintsugi-rs` binary using `O_NOFOLLOW` and regular-file checks."""
    candidates: List[Path] = []
    if rust_bin is not None:
        raw_bin = str(rust_bin).strip()
        if not raw_bin or "\x00" in raw_bin:
            raise ValueError(f"Invalid rust_bin path: {rust_bin!r}")
        candidates.append(Path(raw_bin))
    else:
        candidates.append(ws_real / "target" / "release" / "kintsugi-rs")
        candidates.append(Path(__file__).resolve().parents[2] / "target" / "release" / "kintsugi-rs")
        which_bin = shutil.which("kintsugi-rs")
        if which_bin:
            candidates.append(Path(which_bin))

    for cand in candidates:
        if not cand.exists():
            continue
        assert_not_symlink(cand)
        resolved = Path(os.path.realpath(str(cand)))
        _, digest, _ = _read_regular_nofollow(
            resolved,
            require_non_world_writable=True,
            max_bytes=64 * 1024 * 1024,
        )
        if not os.access(resolved, os.X_OK):
            raise PermissionError(f"SECURITY_NOT_EXECUTABLE: {resolved}")
        return resolved, digest

    raise FileNotFoundError("Compiled `kintsugi-rs` binary not found for Arm C external gate.")


def _cap_feedback_directives(directives: Sequence[str], max_tokens: int) -> str:
    """Pack compact fix directives strictly within `max_tokens` (`<= 150` by default)."""
    if not directives or max_tokens <= 0:
        return ""
    kept: List[str] = []
    for idx, item in enumerate(directives):
        line = " ".join(str(item).split())
        remaining = len(directives) - (idx + 1)
        tail = f"\n... (+{remaining} more)" if remaining > 0 else ""
        candidate = line if not kept else "\n".join(kept) + "\n" + line
        if estimate_tokens(candidate + tail) <= max_tokens:
            kept.append(line)
            continue
        if not kept:
            # Trim single long directive until estimate_tokens <= max_tokens
            budget_chars = max(12, max_tokens * 4 - 4)
            trimmed = line[:budget_chars].rstrip()
            while len(trimmed) > 8 and estimate_tokens(trimmed + "...") > max_tokens:
                trimmed = trimmed[:-4].rstrip()
            kept.append(trimmed + ("..." if len(trimmed) < len(line) else ""))
        else:
            omitted = len(directives) - len(kept)
            if omitted > 0:
                more_line = f"... (+{omitted} more)"
                with_more = "\n".join(kept) + "\n" + more_line
                if estimate_tokens(with_more) <= max_tokens:
                    kept.append(more_line)
        break
    return "\n".join(kept)


def _normalize_finding_path(raw_path: str, ws_real: Path) -> str:
    p = Path(raw_path)
    if p.is_absolute():
        abs_str = str(p)
        ws_str = str(ws_real)
        if abs_str == ws_str or abs_str.startswith(ws_str.rstrip(os.sep) + os.sep):
            return p.relative_to(ws_real).as_posix()
    return raw_path


_GIT_FLAG_WITH_VALUE = frozenset(
    {
        "-C", "-c", "-m", "-n", "-F", "-b", "-B", "-o", "-U",
        "--git-dir", "--work-tree", "--depth", "--format", "--pretty",
        "--message", "--file", "--branch", "--git-path", "--exec-path",
    }
)
_GIT_SAFE_FSTRING_PREFIXES = ("-n", "--max-count=", "--depth=", "--format=", "--pretty=", "--skip=", ":")
_GIT_SUBCOMMANDS_USER_PATH = frozenset({"log", "diff", "show", "ls-files", "blame"})
_STATE_IO_NAME_RE = re.compile(r"(save|write|load|read).*?(state|secret|cred|vault|atomic)", re.IGNORECASE)
_URL_VALIDATOR_NAME_RE = re.compile(r"(validate|check|verify|guard|safe).*?(url|ssrf|outbound|webhook)", re.IGNORECASE)
_SANITIZER_NAME_RE = re.compile(r"(sanitize|redact|scrub|mask)", re.IGNORECASE)


def _const_str(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_safe_git_fstring(node: ast.AST) -> bool:
    if not isinstance(node, ast.JoinedStr) or not node.values:
        return False
    first = node.values[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        pref = first.value
        return bool(pref) and (not pref.startswith("-") or pref in _GIT_SAFE_FSTRING_PREFIXES)
    return False


def _git_argv_has_dynamic_user_arg(elts: Sequence[ast.AST]) -> Tuple[bool, bool, bool]:
    """Return `(is_git_user_subcmd, has_dynamic_arg, has_double_dash)`."""
    if not elts or _const_str(elts[0]) != "git":
        return False, False, False
    subcmd_match = False
    has_dynamic = False
    has_dd = False
    skip_next = False
    for elem in elts[1:]:
        if skip_next:
            skip_next = False
            continue
        lit = _const_str(elem)
        if lit is not None:
            if lit == "--":
                has_dd = True
            elif lit in _GIT_FLAG_WITH_VALUE:
                skip_next = True
            elif lit in _GIT_SUBCOMMANDS_USER_PATH:
                subcmd_match = True
            continue
        if _is_safe_git_fstring(elem):
            continue
        has_dynamic = True
    return subcmd_match, has_dynamic, has_dd


def _run_arm_c_ast_security_checks(rel_posix: str, source_text: str) -> List[Dict[str, Any]]:
    """Run domain-general Python AST security invariants (`KC-G01..KC-G04`) for Arm C external gate."""
    if not rel_posix.endswith(".py") or not source_text.strip():
        return []
    try:
        tree = ast.parse(source_text, filename=rel_posix)
    except SyntaxError:
        return []

    findings: List[Dict[str, Any]] = []
    lower_src = source_text.lower()
    str_literals: List[Tuple[int, str]] = [
        (getattr(n, "lineno", 1), n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]

    # KC-G01: Git CLI dynamic user args require '--' AND leading-dash + metachar/NUL validation.
    git_list_vars: Dict[str, List[ast.AST]] = {}
    git_vuln_line: Optional[int] = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.List) and node.value.elts and _const_str(node.value.elts[0]) == "git":
                git_list_vars[node.targets[0].id] = list(node.value.elts)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id in git_list_vars:
            if isinstance(node.value, ast.List):
                git_list_vars[node.target.id].extend(node.value.elts)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in git_list_vars
            and node.func.attr in ("append", "extend")
            and node.args
        ):
            if node.func.attr == "append":
                git_list_vars[node.func.value.id].append(node.args[0])
            elif isinstance(node.args[0], ast.List):
                git_list_vars[node.func.value.id].extend(node.args[0].elts)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "check_output", "check_call", "call", "Popen") and node.args:
                arg0 = node.args[0]
                elts: Optional[Sequence[ast.AST]] = None
                if isinstance(arg0, ast.List):
                    elts = arg0.elts
                elif isinstance(arg0, ast.Name) and arg0.id in git_list_vars:
                    elts = git_list_vars[arg0.id]
                if elts is not None:
                    is_user_subcmd, has_dyn, has_dd = _git_argv_has_dynamic_user_arg(elts)
                    if is_user_subcmd and has_dyn:
                        has_dash_guard = (
                            'startswith("-")' in source_text
                            or "startswith('-')" in source_text
                            or 'startswith(("-' in source_text
                            or "startswith(('-" in source_text
                            or "re.fullmatch(" in source_text
                            or "re.match(" in source_text
                        )
                        has_meta_guard = (
                            "\\x00" in source_text
                            or "\\0" in source_text
                            or any((";" in s and ("|" in s or "&" in s)) for _, s in str_literals)
                            or "re.fullmatch(" in source_text
                            or "re.match(" in source_text
                        )
                        if (has_dd and not (has_dash_guard and has_meta_guard)) or (not has_dd and not has_dash_guard):
                            git_vuln_line = getattr(node, "lineno", 1)
                            break
    if git_vuln_line is not None:
        findings.append(
            {
                "scar_id": "KC-G01",
                "file_path": rel_posix,
                "line": git_vuln_line,
                "severity": "HIGH",
                "good_code_hint": "Use '--' before dynamic git args AND reject leading '-', NUL, and shell metachars (;|&`$).",
            }
        )

    # KC-G02: Atomic / secret state I/O must refuse symlinks on BOTH read & write (lstat/is_symlink + O_NOFOLLOW).
    state_funcs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and _STATE_IO_NAME_RE.search(n.name)
    ]
    has_secret_perm_or_name = (
        "0o600" in source_text
        or any(
            any(tok in fn.name.lower() for tok in ("secret", "cred", "secure", "atomic"))
            for fn in state_funcs
        )
    )
    if state_funcs and has_secret_perm_or_name and "os.replace" in source_text:
        has_symlink_refusal = (
            "is_symlink" in source_text
            or "islink" in source_text
            or "S_ISLNK" in source_text
            or "assert_not_symlink" in source_text
            or "lstat" in source_text
        )
        has_nofollow = "O_NOFOLLOW" in source_text or "_nofollow" in lower_src
        if not (has_symlink_refusal and has_nofollow):
            findings.append(
                {
                    "scar_id": "KC-G02",
                    "file_path": rel_posix,
                    "line": state_funcs[0].lineno,
                    "severity": "HIGH",
                    "good_code_hint": "Refuse symlinks on read & write: check is_symlink()/lstat on target+ancestors before os.replace AND open with os.O_NOFOLLOW.",
                }
            )

    # KC-G03: Outbound PII/secret sanitizers redacting PEM blocks must also redact truncated/unterminated PEM headers.
    sanitizer_funcs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and _SANITIZER_NAME_RE.search(n.name)
    ]
    if sanitizer_funcs:
        pem_lits = [(ln, s) for ln, s in str_literals if "private key" in s.lower()]
        has_pat_rule = any(
            any(tok in s.lower() for tok in ("gh" + "p_", "gh" + "o_", "gh[", "github_pat", "glpat"))
            for _, s in str_literals
        )
        has_payload_sanitizer = any(
            any(w in fn.name.lower() for w in ("sanitize", "redact", "scrub"))
            and not fn.name.startswith("_")
            for fn in sanitizer_funcs
        )
        is_pii_dlp = has_payload_sanitizer and any(("email" in s.lower() or "phone" in s.lower()) for _, s in str_literals)
        if pem_lits:
            has_unterminated_pem_rule = any(
                ("end" not in s.lower()) or (")?" in s) or ("|$" in s) or ("|\\z" in s.lower())
                for _, s in pem_lits
            )
            if not has_unterminated_pem_rule or (is_pii_dlp and not has_pat_rule):
                findings.append(
                    {
                        "scar_id": "KC-G03",
                        "file_path": rel_posix,
                        "line": pem_lits[0][0],
                        "severity": "HIGH",
                        "good_code_hint": "Redact truncated PEM headers (use regex r'-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}' without requiring END or verbatim dashes) and GitHub PAT (r'\\bgh[pousr]_[A-Za-z0-9]{20,}\\b')/Bearer tokens.",
                    }
                )
        else:
            is_dlp_sanitizer = (
                has_payload_sanitizer
                and any("bearer" in s.lower() for _, s in str_literals)
                and any(("email" in s.lower() or "phone" in s.lower()) for _, s in str_literals)
            )
            if is_dlp_sanitizer:
                findings.append(
                    {
                        "scar_id": "KC-G03",
                        "file_path": rel_posix,
                        "line": sanitizer_funcs[0].lineno,
                        "severity": "HIGH",
                        "good_code_hint": "Redact truncated PEM headers (regex r'-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}', avoid verbatim dashes) and GitHub PAT (r'\\bgh[pousr]_[A-Za-z0-9]{20,}\\b')/Bearer tokens.",
                    }
                )

    # KC-G04: Outbound URL SSRF validator must enforce https-only AND explicitly reject localhost & private IPs.
    url_funcs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and _URL_VALIDATOR_NAME_RE.search(n.name)
    ]
    if url_funcs and ("urlparse" in source_text or "urlsplit" in source_text):
        has_https = any(s.lower() == "https" or "https" in s.lower() for _, s in str_literals)
        has_localhost_block = any("localhost" in s.lower() for _, s in str_literals)
        has_ip_block = (
            "is_private" in source_text
            or "is_loopback" in source_text
            or "is_link_local" in source_text
            or "is_global" in source_text
        )
        if not (has_https and has_localhost_block and has_ip_block):
            findings.append(
                {
                    "scar_id": "KC-G04",
                    "file_path": rel_posix,
                    "line": url_funcs[0].lineno,
                    "severity": "HIGH",
                    "good_code_hint": "Require scheme=='https', reject host=='localhost' or host.endswith('.localhost') BEFORE checking allowed_hosts, and reject ip.is_private/is_loopback/is_link_local.",
                }
            )

    # KC-G05: Safe expression evaluator must not use compile/eval/exec or permit ast.Call/ast.Attribute.
    expr_funcs = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and ("expr" in n.name.lower() and "eval" in n.name.lower())
    ]
    if expr_funcs:
        uses_unsafe_exec = any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in ("eval", "exec", "compile")
            for n in ast.walk(tree)
        )
        uses_ast_parse = "ast.parse" in source_text or "parse(" in source_text
        permits_call_or_attr = "ast.Call" in source_text or "ast.Attribute" in source_text
        # Note: rejecting Call/Attribute is safe, only flag if unsafe builtin used or ast.parse missing
        if uses_unsafe_exec or not uses_ast_parse:
            findings.append(
                {
                    "scar_id": "KC-G05",
                    "file_path": rel_posix,
                    "line": expr_funcs[0].lineno,
                    "severity": "HIGH",
                    "good_code_hint": "Evaluate filter expressions strictly via ast.parse recursive whitelist (BoolOp/UnaryOp/Compare/BinOp/Name/Constant only; reject Call, Attribute, Subscript, dunder names).",
                }
            )
        elif permits_call_or_attr and "raise" not in source_text:
            findings.append(
                {
                    "scar_id": "KC-G05",
                    "file_path": rel_posix,
                    "line": expr_funcs[0].lineno,
                    "severity": "HIGH",
                    "good_code_hint": "Reject ast.Call, ast.Attribute, ast.Subscript, and dunder identifiers in expression evaluator.",
                }
            )

    return findings


def run_arm_c_external_gate(
    workspace_root: Union[str, Path],
    changed_files: Union[str, os.PathLike, Path, Sequence[Union[str, Path]]],
    *,
    rust_bin: Optional[Union[str, Path]] = None,
    include_shadow: bool = True,
    max_feedback_tokens: int = 150,
) -> Dict[str, Any]:
    """Run fail-closed Arm C external gate (`scan` + `s3-audit`) with 0-token clean pass and capped fix output."""
    t0 = time.perf_counter()
    if type(include_shadow) is not bool:
        raise ValueError("INVALID_INCLUDE_SHADOW: expected strict bool.")
    if type(max_feedback_tokens) is not int or max_feedback_tokens < 0:
        raise ValueError("INVALID_MAX_FEEDBACK_TOKENS: expected non-negative int.")

    ws_raw = Path(workspace_root)
    assert_not_symlink(ws_raw)
    ws_real = Path(os.path.realpath(str(ws_raw)))
    if not ws_real.is_dir():
        raise NotADirectoryError(f"Workspace root is not a directory: {ws_real}")

    bin_path, rust_bin_sha256 = _resolve_rust_binary(ws_real, rust_bin)

    file_items: Sequence[Union[str, os.PathLike, Path]] = (
        [changed_files] if isinstance(changed_files, (str, bytes, os.PathLike, Path)) else changed_files
    )
    confined_map: Dict[str, Tuple[Path, str, bytes]] = {}
    for raw_f in file_items:
        rel_posix, resolved = _resolve_confined_file(ws_real, raw_f)
        f_bytes, f_sha, _ = _read_regular_nofollow(resolved)
        confined_map[rel_posix] = (resolved, f_sha, f_bytes)

    sorted_files = [(rel, p, f_sha, f_bytes) for rel, (p, f_sha, f_bytes) in sorted(confined_map.items())]
    changed_digest_input = "\n".join(f"{rel}:{f_sha}" for rel, _, f_sha, _ in sorted_files).encode("utf-8")
    changed_files_sha256 = _sha256_hex(changed_digest_input)

    policy_basis = json.dumps(
        {
            "schema": "ArmCGatePolicy/1",
            "agents_md_sha256": _sha256_hex(ARM_C_AGENTS_MD.encode("utf-8")),
            "include_shadow": include_shadow,
            "fail_on": "HIGH",
            "max_feedback_tokens": max_feedback_tokens,
            "rust_bin_sha256": rust_bin_sha256,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    policy_sha256 = _sha256_hex(policy_basis)
    agents_md_bytes = len(ARM_C_AGENTS_MD.encode("utf-8"))

    if not sorted_files:
        return {
            "clean": True,
            "findings_count": 0,
            "unguarded_s0_seams": 0,
            "feedback": "",
            "feedback_tokens_est": 0,
            "policy_sha256": policy_sha256,
            "changed_files_sha256": changed_files_sha256,
            "findings": [],
            "scanned_files": 0,
            "active_scars": 41 if include_shadow else 36,
            "agents_md_bytes": agents_md_bytes,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    rel_args = [rel for rel, _, _, _ in sorted_files]
    scan_cmd = [str(bin_path), "scan", "--fail-on", "HIGH", "--format", "json"]
    if include_shadow:
        scan_cmd.append("--shadow-arm-c")
    scan_cmd.append("--")
    scan_cmd.extend(rel_args)

    s3_cmd = [str(bin_path), "s3-audit", "--format", "json", "--", *rel_args]

    scan_proc = subprocess.run(
        scan_cmd,
        cwd=str(ws_real),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
        timeout=30,
    )
    if scan_proc.returncode not in (0, 1):
        raise RuntimeError(f"kintsugi-rs scan failed (rc={scan_proc.returncode}): {scan_proc.stderr.strip()}")
    scan_payload = json.loads(scan_proc.stdout)

    s3_proc = subprocess.run(
        s3_cmd,
        cwd=str(ws_real),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        check=False,
        timeout=30,
    )
    if s3_proc.returncode not in (0, 1):
        raise RuntimeError(f"kintsugi-rs s3-audit failed (rc={s3_proc.returncode}): {s3_proc.stderr.strip()}")
    s3_payload = json.loads(s3_proc.stdout)

    raw_findings = list(scan_payload.get("findings") or [])
    if include_shadow:
        for rel, _, _, f_bytes in sorted_files:
            raw_findings.extend(
                _run_arm_c_ast_security_checks(rel, f_bytes.decode("utf-8", errors="replace"))
            )
    findings_count = len(raw_findings)
    unguarded_s0_seams = int(s3_payload.get("unguarded_s0_seams", 0))
    clean = (
        findings_count == 0
        and unguarded_s0_seams == 0
        and scan_proc.returncode == 0
        and s3_proc.returncode == 0
    )

    directives: List[str] = []
    if not clean:
        for f in raw_findings:
            rule_id = str(f.get("scar_id", "KS-UNKNOWN"))
            fpath = _normalize_finding_path(str(f.get("file_path", "?")), ws_real)
            line_no = int(f.get("line", 0))
            hint = str(f.get("good_code_hint") or f.get("title") or "Fix violation")
            directives.append(f"{rule_id}@{fpath}:{line_no}: {hint}")
        if unguarded_s0_seams > 0:
            for s3_file in s3_payload.get("files") or []:
                if int(s3_file.get("unguarded_s0_seams", 0)) > 0:
                    fpath = _normalize_finding_path(str(s3_file.get("file_path", "?")), ws_real)
                    directives.append(
                        f"S3-S0@{fpath}:1: Remove shell=True / guard @CT2 S0 seam"
                    )
        if not directives:
            directives.append("ARM-C-GATE@workspace:1: Resolve non-zero gate status")

    feedback = _cap_feedback_directives(directives, max_feedback_tokens) if not clean else ""
    feedback_tokens_est = estimate_tokens(feedback) if feedback else 0

    return {
        "clean": clean,
        "findings_count": findings_count,
        "unguarded_s0_seams": unguarded_s0_seams,
        "feedback": feedback,
        "feedback_tokens_est": feedback_tokens_est,
        "policy_sha256": policy_sha256,
        "changed_files_sha256": changed_files_sha256,
        "findings": raw_findings,
        "scanned_files": int(scan_payload.get("scanned_files", len(sorted_files))),
        "active_scars": int(scan_payload.get("active_scars", 41 if include_shadow else 36)),
        "agents_md_bytes": agents_md_bytes,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }
