"""Dual-engine deterministic scanner (Python AST + Multi-Language Regex + Git-Diff Hunk Filter + SARIF 2.1.0)."""

from __future__ import annotations

import ast
import bisect
import difflib
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from kintsugi import __version__
from kintsugi.models import GoldenScar, ScanFinding, ScanReport, Severity

EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".md": "markdown",
    ".mdc": "markdown",
    ".txt": "decision",
    ".decision": "decision",
    ".contract": "contract",
    ".dockerfile": "dockerfile",
}

DEFAULT_EXCLUDED_DIRS: Set[str] = {
    ".git",
    ".hg",
    ".svn",
    ".kintsugi",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "target",
    "dist",
    "build",
}

IGNORE_FILE_RE = re.compile(r"kintsugi:\s*ignore-file\b", re.IGNORECASE)
IGNORE_PRAGMA_RE = re.compile(r"kintsugi:\s*ignore(?:\[([A-Za-z0-9_,\s-]+)\])?", re.IGNORECASE)
HUNK_HEADER_RE = re.compile(r"^@@\s+-\d+(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")
SECURITY_NAME_RE = re.compile(
    r"(?:token|secret|nonce|api_key|apikey|password|passwd|auth_code|otp|session_id|private_key|salt)",
    re.IGNORECASE,
)


def _extract_ignored_ids(line_text: str) -> Optional[Set[str]]:
    match = IGNORE_PRAGMA_RE.search(line_text)
    if not match:
        return None
    group = match.group(1)
    if not group:
        return {"*"}
    return {item.strip().upper() for item in group.split(",") if item.strip()}


def _dotted_call_name(node: ast.Call) -> str:
    parts: List[str] = []
    curr: ast.AST = node.func
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
    return ".".join(reversed(parts))


def _decode_git_diff_header_path(raw_line: str) -> Optional[str]:
    """Decode `+++ b/...` or Git C-quoted `+++ "b/..."` diff headers into a relative POSIX path."""
    if not raw_line.startswith("+++ ") or raw_line.startswith("+++ /dev/null"):
        return None
    tail = raw_line[4:].strip()
    if tail.startswith('"') and tail.endswith('"') and len(tail) >= 2:
        inner = tail[1:-1]
        out_bytes = bytearray()
        i = 0
        n = len(inner)
        while i < n:
            ch = inner[i]
            if ch == "\\" and i + 1 < n:
                nxt = inner[i + 1]
                if nxt in "01234567" and i + 3 < n and all(c in "01234567" for c in inner[i + 1 : i + 4]):
                    out_bytes.append(int(inner[i + 1 : i + 4], 8))
                    i += 4
                    continue
                esc_map = {
                    '"': ord('"'),
                    "\\": ord("\\"),
                    "n": ord("\n"),
                    "r": ord("\r"),
                    "t": ord("\t"),
                    "a": 7,
                    "b": 8,
                    "f": 12,
                    "v": 11,
                }
                if nxt in esc_map:
                    out_bytes.append(esc_map[nxt])
                    i += 2
                    continue
            out_bytes.extend(ch.encode("utf-8"))
            i += 1
        decoded = out_bytes.decode("utf-8", errors="replace")
        return decoded[2:] if decoded.startswith("b/") else decoded
    if tail.startswith("b/"):
        return tail[2:]
    return None


def _lexical_repo_path(repo_root: Path, rel_or_abs: str | Path) -> Path:
    """Resolve `repo_root / rel_or_abs` lexically without dereferencing working-tree symlinks."""
    root_real = Path(os.path.normpath(str(Path(repo_root).resolve())))
    candidate = Path(rel_or_abs)
    if candidate.is_absolute():
        return Path(os.path.normpath(str(candidate)))
    return Path(os.path.normpath(str(root_real / candidate)))


def parse_git_diff_text(diff_text: str, repo_root: Path, *, require_worktree_file: bool = True) -> Dict[Path, Set[int]]:
    """
    Parse unified `git diff -U0` output into `{lexical_file_path: {added_or_modified_line_numbers}}`.
    """
    changed: Dict[Path, Set[int]] = {}
    current_file: Optional[Path] = None
    saw_minus_header: bool = False
    hunk_minus_remaining: int = 0
    hunk_plus_remaining: int = 0
    root_real = Path(os.path.normpath(str(Path(repo_root).resolve())))

    for raw_line in (ln[:-1] if ln.endswith("\r") else ln for ln in diff_text.split("\n")):
        if hunk_minus_remaining > 0 or hunk_plus_remaining > 0:
            if raw_line.startswith("+") and hunk_plus_remaining > 0:
                hunk_plus_remaining -= 1
                continue
            if raw_line.startswith("-") and hunk_minus_remaining > 0:
                hunk_minus_remaining -= 1
                continue
            if raw_line.startswith(" "):
                if hunk_minus_remaining > 0:
                    hunk_minus_remaining -= 1
                if hunk_plus_remaining > 0:
                    hunk_plus_remaining -= 1
                continue
            if raw_line.startswith("\\"):
                continue
            hunk_minus_remaining = 0
            hunk_plus_remaining = 0

        if raw_line.startswith("diff --git "):
            saw_minus_header = False
            current_file = None
            continue
        if raw_line == "--- /dev/null" or raw_line.startswith("--- /dev/null\t") or raw_line.startswith("--- a/") or raw_line.startswith('--- "a/'):
            saw_minus_header = True
            continue
        if saw_minus_header and (raw_line == "+++ /dev/null" or raw_line.startswith("+++ /dev/null\t")):
            current_file = None
            saw_minus_header = False
            continue
        if saw_minus_header:
            rel_path = _decode_git_diff_header_path(raw_line)
            if rel_path is not None:
                current_file = _lexical_repo_path(root_real, rel_path)
                changed.setdefault(current_file, set())
                saw_minus_header = False
                continue
        if current_file is not None and raw_line.startswith("@@"):
            match = HUNK_HEADER_RE.match(raw_line)
            if match:
                old_count = int(match.group(1)) if match.group(1) is not None else 1
                start_line = int(match.group(2))
                new_count = int(match.group(3)) if match.group(3) is not None else 1
                hunk_minus_remaining = max(0, old_count)
                hunk_plus_remaining = max(0, new_count)
                if new_count > 0:
                    changed[current_file].update(range(start_line, start_line + new_count))
    return {
        p: lines
        for p, lines in changed.items()
        if lines and (not require_worktree_file or p.exists())
    }


def read_git_index_blob(repo_root: str | Path, file_path: str | Path) -> Optional[str]:
    """Read staged file content directly from the Git index (`:<relpath>`) without dereferencing worktree symlinks."""
    root = Path(os.path.normpath(str(Path(repo_root).resolve())))
    target = _lexical_repo_path(root, file_path)
    try:
        rel_posix = target.relative_to(root).as_posix()
    except ValueError:
        return None
    proc = subprocess.run(
        ["git", "-C", str(root), "show", f":{rel_posix}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def get_git_changed_lines(
    repo_root: str | Path = ".",
    *,
    staged: bool = False,
    diff_ref: Optional[str] = None,
) -> Dict[Path, Set[int]]:
    """Run `git -c core.quotePath=false diff --text --no-ext-diff --no-textconv -U0` and return touched line numbers per file."""
    root = Path(repo_root).resolve()
    cmd = ["git", "-C", str(root), "-c", "core.quotePath=false", "diff", "--text", "--no-ext-diff", "--no-textconv", "-U0", "--no-color"]
    if staged:
        cmd.append("--staged")
    elif diff_ref:
        if diff_ref.startswith("-"):
            raise ValueError(f"Invalid diff_ref starting with '-': {diff_ref}")
        cmd.append(diff_ref)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git diff failed: {proc.stderr.strip()}")
    return parse_git_diff_text(proc.stdout, root, require_worktree_file=not staged)


def render_patch_preview(finding: ScanFinding) -> str:
    """Generate a unified diff preview showing how to replace the offending snippet."""
    before_lines = [finding.snippet.rstrip() + "\n"]
    after_lines = [ln + "\n" for ln in finding.good_code_hint.strip().splitlines()]
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"a/{finding.file_path}:{finding.line}",
        tofile=f"b/{finding.file_path}:{finding.line} (verified {finding.scar_id} fix)",
        lineterm="\n",
    )
    return "".join(diff).rstrip()


class _PythonASTVisitor(ast.NodeVisitor):
    """Deterministic AST analyzer for Python anti-patterns."""

    def __init__(self, source_lines: Sequence[str], ast_scars: Dict[str, List[GoldenScar]]) -> None:
        self.source_lines = source_lines
        self.ast_scars = ast_scars
        self.matches: List[Tuple[GoldenScar, int, int, int, str]] = []
        self._current_target_names: List[str] = []

    def _record(self, rule_name: str, node: ast.AST) -> None:
        scars = self.ast_scars.get(rule_name, [])
        if not scars:
            return
        lineno = getattr(node, "lineno", 1)
        end_lineno = getattr(node, "end_lineno", lineno) or lineno
        col = getattr(node, "col_offset", 0) + 1
        snippet = (
            self.source_lines[lineno - 1].strip()
            if 1 <= lineno <= len(self.source_lines)
            else ""
        )
        for scar in scars:
            self.matches.append((scar, lineno, end_lineno, col, snippet))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_mutable_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_mutable_defaults(node)
        self.generic_visit(node)

    def _check_mutable_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        defaults = list(node.args.defaults) + [
            d for d in node.args.kw_defaults if d is not None
        ]
        for default_expr in defaults:
            if isinstance(default_expr, (ast.List, ast.Dict, ast.Set)):
                self._record("py_mutable_default_arg", default_expr)
            elif isinstance(default_expr, ast.Call) and _dotted_call_name(default_expr) in {
                "list",
                "dict",
                "set",
            }:
                self._record("py_mutable_default_arg", default_expr)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        is_bare = node.type is None
        is_pass_only = len(node.body) == 1 and (
            isinstance(node.body[0], ast.Pass)
            or (
                isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and node.body[0].value.value is Ellipsis
            )
        )
        if is_bare or is_pass_only:
            self._record("py_silent_except_swallow", node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        names: List[str] = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, ast.Attribute):
                names.append(target.attr)
        self._current_target_names.extend(names)
        try:
            self.generic_visit(node)
        finally:
            for _ in names:
                self._current_target_names.pop()

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        name = node.target.id if isinstance(node.target, ast.Name) else ""
        if name:
            self._current_target_names.append(name)
        try:
            self.generic_visit(node)
        finally:
            if name:
                self._current_target_names.pop()

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _dotted_call_name(node)
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg is not None}

        if call_name in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }:
            shell_val = kwargs.get("shell")
            if isinstance(shell_val, ast.Constant) and shell_val.value is True:
                self._record("py_subprocess_shell_true", node)
        elif call_name in {"os.system", "os.popen"}:
            self._record("py_os_system_cmd", node)

        if call_name in {"eval", "exec", "pickle.loads", "pickle.load", "marshal.loads"}:
            self._record("py_unsafe_dynamic_exec", node)
        elif call_name == "yaml.load" and "Loader" not in kwargs:
            self._record("py_unsafe_dynamic_exec", node)
        elif call_name == "torch.load":
            wo = kwargs.get("weights_only")
            if not (isinstance(wo, ast.Constant) and wo.value is True):
                self._record("py_torch_load_unsafe", node)
        elif call_name in {"jwt.decode", "pyjwt.decode"}:
            ver_kw = kwargs.get("verify")
            opts_kw = kwargs.get("options")
            unverified_jwt = isinstance(ver_kw, ast.Constant) and ver_kw.value is False
            if isinstance(opts_kw, ast.Dict):
                for k_node, v_node in zip(opts_kw.keys, opts_kw.values):
                    if (
                        isinstance(k_node, ast.Constant)
                        and k_node.value == "verify_signature"
                        and isinstance(v_node, ast.Constant)
                        and v_node.value is False
                    ):
                        unverified_jwt = True
            if unverified_jwt:
                self._record("py_jwt_unverified_decode", node)

        if call_name in {
            "urlopen",
            "request.urlopen",
            "urllib.request.urlopen",
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "requests.patch",
            "requests.head",
            "requests.request",
            "httpx.get",
            "httpx.post",
        }:
            has_star_kwargs = any(kw.arg is None for kw in node.keywords)
            if "timeout" not in kwargs and not has_star_kwargs:
                if call_name.endswith("urlopen") and len(node.args) >= 3:
                    pass
                else:
                    self._record("py_http_missing_timeout", node)

        if call_name.startswith("random.") and any(
            SECURITY_NAME_RE.search(t) for t in self._current_target_names
        ):
            self._record("py_insecure_random_for_secret", node)

        if "allow_origins" in kwargs and "allow_credentials" in kwargs:
            cred_node = kwargs["allow_credentials"]
            orig_node = kwargs["allow_origins"]
            is_cred_true = isinstance(cred_node, ast.Constant) and cred_node.value is True
            has_wildcard_origin = (
                isinstance(orig_node, ast.Constant) and orig_node.value == "*"
            ) or (
                isinstance(orig_node, (ast.List, ast.Tuple, ast.Set))
                and any(isinstance(elt, ast.Constant) and elt.value == "*" for elt in orig_node.elts)
            )
            if is_cred_true and has_wildcard_origin:
                self._record("py_cors_wildcard_credentials", node)

        for rule_key in self.ast_scars:
            if rule_key.startswith("call:"):
                target_fn = rule_key.split(":", 1)[1]
                if call_name == target_fn or call_name.endswith(f".{target_fn}"):
                    self._record(rule_key, node)
            elif rule_key.startswith("missing_kwarg:"):
                parts = rule_key.split(":")
                if len(parts) == 3:
                    _, target_fn, required_kw = parts
                    if (
                        call_name == target_fn or call_name.endswith(f".{target_fn}")
                    ) and required_kw not in kwargs:
                        self._record(rule_key, node)

        self.generic_visit(node)


_JS_GO_RUST_COMMENT_RE = re.compile(
    r"""(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:\\[\s\S]|[^`\\])*`)|(?P<bcomm>/\*[\s\S]*?\*/)|(?P<lcomm>//[^\r\n]*)""",
    re.VERBOSE,
)
_PY_SH_COMMENT_RE = re.compile(
    r'(?P<str>"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:[^"\\\r\n]|\\.)*"|\'(?:[^\'\\\r\n]|\\.)*\')|(?P<lcomm>#[^\r\n]*)'
)


def _mask_comments_preserve_newlines(content: str, lang: str) -> str:
    """
    Mask single-line and multi-line comments with spaces while preserving exact newlines and character offsets.
    Guarantees line numbers, character code-point offsets, and column positions are 100% identical to original content.
    """
    if not content:
        return content
    if lang in {"javascript", "typescript", "go", "rust"}:
        def repl_js(m: re.Match[str]) -> str:
            if m.group("bcomm") or m.group("lcomm"):
                chunk = m.group(0)
                return "".join(c if c in "\r\n" else " " for c in chunk)
            return m.group(0)
        return _JS_GO_RUST_COMMENT_RE.sub(repl_js, content)
    if lang in {"python", "shell"}:
        def repl_py(m: re.Match[str]) -> str:
            if m.group("lcomm"):
                chunk = m.group(0)
                return "".join(c if c in "\r\n" else " " for c in chunk)
            return m.group(0)
        return _PY_SH_COMMENT_RE.sub(repl_py, content)
    return content


class _StructuralScope:
    __slots__ = ("kind", "name", "start_char", "end_char", "start_line", "end_line", "col", "text")

    def __init__(
        self,
        kind: str,
        name: str,
        start_char: int,
        end_char: int,
        start_line: int,
        end_line: int,
        col: int,
        text: str,
    ) -> None:
        self.kind = kind
        self.name = name
        self.start_char = start_char
        self.end_char = end_char
        self.start_line = start_line
        self.end_line = end_line
        self.col = col
        self.text = text


class _StructuralCallExtractor:
    """
    Zero-dependency structural analyzer for JS/TS/Go/Rust (Structural AST-Lite).
    Extracts balanced paren and brace call/object scopes from comment-sanitized code
    to resolve KS-013, KS-014, KS-015, and KS-016 without comment false positives,
    cross-call false positives, or nested brace truncation.
    """

    _TOKEN_RE = re.compile(
        r"""(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:\\[\s\S]|[^`\\])*`)|(?P<punct>[(){}])|(?P<ident>[A-Za-z_$][A-Za-z0-9_$.]*)""",
        re.VERBOSE,
    )
    _KS015_ORIGIN_RE = re.compile(
        r"""["']?\borigin["']?\s*:\s*(?:["']\*["']|true\b|\[[^\]]*["']\*["'])""",
        re.IGNORECASE,
    )
    _KS015_CRED_RE = re.compile(
        r"""["']?\bcredentials["']?\s*:\s*true\b""",
        re.IGNORECASE,
    )
    _KS013_EXEC_NAMES = {
        "exec",
        "execSync",
        "child_process.exec",
        "child_process.execSync",
    }
    _KS016_GO_HTTP_NAMES = {
        "http.Get",
        "http.Post",
        "http.PostForm",
        "http.Head",
    }

    def __init__(
        self,
        source_lines: Sequence[str],
        masked_content: str,
        lang: str,
        scars_by_id: Dict[str, GoldenScar],
        newline_offsets: Sequence[int],
    ) -> None:
        self.source_lines = source_lines
        self.masked_content = masked_content
        self.lang = lang
        self.scars_by_id = scars_by_id
        self.newline_offsets = newline_offsets
        self.scopes: List[_StructuralScope] = []
        self._extract_scopes()

    def _get_loc(self, pos: int) -> Tuple[int, int]:
        l_idx = bisect.bisect_right(self.newline_offsets, pos - 1) if pos > 0 else 0
        lineno = l_idx + 1
        col = pos - (self.newline_offsets[l_idx - 1] + 1) + 1 if l_idx > 0 else pos + 1
        return lineno, col

    def _extract_scopes(self) -> None:
        paren_stack: List[Tuple[str, int]] = []
        brace_stack: List[Tuple[str, int]] = []
        last_ident = ""
        last_ident_pos = 0

        for m in self._TOKEN_RE.finditer(self.masked_content):
            if m.group("ident"):
                last_ident = m.group("ident")
                last_ident_pos = m.start()
            elif m.group("punct"):
                p = m.group("punct")
                if p == "(":
                    is_call = (not bool(self.masked_content[last_ident_pos + len(last_ident):m.start()].strip())) if last_ident else False
                    name = last_ident if is_call else ""
                    paren_stack.append((name, last_ident_pos if is_call else m.start()))
                    last_ident = ""
                elif p == ")":
                    if paren_stack:
                        name, start_pos = paren_stack.pop()
                        s_line, s_col = self._get_loc(start_pos)
                        e_line, _ = self._get_loc(m.end())
                        self.scopes.append(
                            _StructuralScope("call", name, start_pos, m.end(), s_line, e_line, s_col, self.masked_content[start_pos:m.end()])
                        )
                    last_ident = ""
                elif p == "{":
                    is_named = (not bool(self.masked_content[last_ident_pos + len(last_ident):m.start()].strip())) if last_ident else False
                    name = last_ident if is_named else ""
                    brace_stack.append((name, last_ident_pos if is_named else m.start()))
                    last_ident = ""
                elif p == "}":
                    if brace_stack:
                        name, start_pos = brace_stack.pop()
                        s_line, s_col = self._get_loc(start_pos)
                        e_line, _ = self._get_loc(m.end())
                        self.scopes.append(
                            _StructuralScope("object", name, start_pos, m.end(), s_line, e_line, s_col, self.masked_content[start_pos:m.end()])
                        )
                    last_ident = ""

    def find_findings(self) -> List[Tuple[GoldenScar, int, int, int, str, str]]:
        matches: List[Tuple[GoldenScar, int, int, int, str, str]] = []

        # 1. KS-015: Permissive CORS wildcard origin combined with allow_credentials=True in JS/TS
        scar_015 = self.scars_by_id.get("KS-015")
        if scar_015 and self.lang in {"javascript", "typescript"}:
            matched_scopes: List[_StructuralScope] = []
            for sc in self.scopes:
                if sc.kind in {"object", "call"}:
                    if self._KS015_ORIGIN_RE.search(sc.text) and self._KS015_CRED_RE.search(sc.text):
                        matched_scopes.append(sc)
            # Retain the most specific (innermost) scopes to avoid reporting outer wrapper callers
            for sc in matched_scopes:
                has_child = any(
                    other != sc
                    and other.start_char >= sc.start_char
                    and other.end_char <= sc.end_char
                    for other in matched_scopes
                )
                if not has_child:
                    snippet = self.source_lines[sc.start_line - 1].strip() if 1 <= sc.start_line <= len(self.source_lines) else ""
                    matches.append((scar_015, sc.start_line, sc.end_line, sc.col, snippet, "ast:js_cors_wildcard_credentials"))

        # 2. KS-013: Potential shell command injection through interpolated exec command in JS/TS
        scar_013 = self.scars_by_id.get("KS-013")
        if scar_013 and self.lang in {"javascript", "typescript"}:
            for sc in self.scopes:
                if sc.kind == "call" and (sc.name in self._KS013_EXEC_NAMES or any(sc.name.endswith(f".{x}") for x in self._KS013_EXEC_NAMES)):
                    if re.search(r"`[^`]*\$\{[^}]+\}", sc.text):
                        snippet = self.source_lines[sc.start_line - 1].strip() if 1 <= sc.start_line <= len(self.source_lines) else ""
                        matches.append((scar_013, sc.start_line, sc.end_line, sc.col, snippet, "ast:js_exec_template_literal"))

        # 3. KS-014: Global TLS certificate verification disabled in Node.js process (rejectUnauthorized: false)
        scar_014 = self.scars_by_id.get("KS-014")
        if scar_014 and self.lang in {"javascript", "typescript"}:
            for m in re.finditer(r"""(?:NODE_TLS_REJECT_UNAUTHORIZED\s*(?:=|:)\s*["']?0["']?|rejectUnauthorized\s*:\s*false\b)""", self.masked_content):
                lineno, col = self._get_loc(m.start())
                snippet = self.source_lines[lineno - 1].strip() if 1 <= lineno <= len(self.source_lines) else ""
                matches.append((scar_014, lineno, lineno, col, snippet, "ast:js_reject_unauthorized_false"))

        # 4. KS-016: Go net/http DefaultClient call without bounded timeout in Go
        scar_016 = self.scars_by_id.get("KS-016")
        if scar_016 and self.lang == "go":
            for sc in self.scopes:
                if sc.kind == "call" and sc.name in self._KS016_GO_HTTP_NAMES:
                    snippet = self.source_lines[sc.start_line - 1].strip() if 1 <= sc.start_line <= len(self.source_lines) else ""
                    matches.append((scar_016, sc.start_line, sc.end_line, sc.col, snippet, "ast:go_http_missing_timeout"))

        return matches


class KintsugiScanner:
    """Deterministic static, git-diff, and pre-tool code scanner backed by a GoldenScar list."""

    def __init__(
        self,
        scars: Sequence[GoldenScar],
        *,
        min_severity: Severity = Severity.LOW,
        excluded_dirs: Optional[Set[str]] = None,
    ) -> None:
        self.scars = [s for s in scars if s.severity.meets(min_severity)]
        self.excluded_dirs = excluded_dirs if excluded_dirs is not None else set(DEFAULT_EXCLUDED_DIRS)
        self._compiled_regex: List[Tuple[GoldenScar, re.Pattern[str]]] = []
        self._lang_regex_map: Dict[str, List[Tuple[GoldenScar, re.Pattern[str]]]] = {}
        self._lang_fast_gate: Dict[str, Optional[re.Pattern[str]]] = {}
        self._ast_scars: Dict[str, List[GoldenScar]] = {}
        self._scan_cache: Dict[Tuple[int, int, str, str], List[ScanFinding]] = {}
        self._scars_fingerprint = "|".join(f"{s.id}:{s.regex_pattern}:{s.ast_rule}" for s in self.scars)

        for scar in self.scars:
            if scar.regex_pattern:
                compiled = re.compile(scar.regex_pattern, re.MULTILINE)
                self._compiled_regex.append((scar, compiled))
                allowed_langs = [x.lower() for x in scar.languages] if scar.languages else ["*"]
                for lg in allowed_langs:
                    self._lang_regex_map.setdefault(lg, []).append((scar, compiled))
            if scar.ast_rule:
                self._ast_scars.setdefault(scar.ast_rule, []).append(scar)

        # Build single-pass fused union regex gate per language for O(1)-pass fast rejection on clean files
        all_langs = set(EXTENSION_LANGUAGE_MAP.values()) | set(self._lang_regex_map.keys())
        for lg in all_langs:
            applicable = list(self._lang_regex_map.get(lg, []))
            if lg != "*":
                applicable.extend(self._lang_regex_map.get("*", []))
            if applicable:
                try:
                    cleaned_branches: List[str] = []
                    for s, _ in applicable:
                        if s.regex_pattern:
                            scoped_pat = re.sub(
                                r"^\(\?([aiLmsux]+)\)(.*)",
                                r"(?\1:\2)",
                                s.regex_pattern.strip(),
                                flags=re.DOTALL,
                            )
                            cleaned_branches.append(f"(?:{scoped_pat})")
                    union_pat = "|".join(cleaned_branches)
                    self._lang_fast_gate[lg] = re.compile(union_pat, re.MULTILINE) if union_pat else None
                except re.error:
                    self._lang_fast_gate[lg] = None

    @staticmethod
    def infer_language(file_path: str | Path, fallback: str = "python") -> str:
        suffix = Path(file_path).suffix.lower()
        return EXTENSION_LANGUAGE_MAP.get(suffix, fallback)

    def scan_text(
        self,
        content: str,
        *,
        file_path: str = "<memory>",
        language: Optional[str] = None,
        allowed_lines: Optional[Set[int]] = None,
    ) -> List[ScanFinding]:
        lang = (language or self.infer_language(file_path)).lower()
        cache_key: Optional[Tuple[int, int, str, str]] = None
        if allowed_lines is None and len(content) <= 262144:
            cache_key = (len(content), hash(content), lang, file_path)
            cached = self._scan_cache.get(cache_key)
            if cached is not None:
                return list(cached)

        lines = [ln[:-1] if ln.endswith("\r") else ln for ln in content.split("\n")]
        if any(IGNORE_FILE_RE.search(ln) for ln in lines[:8]):
            return []
        findings: List[ScanFinding] = []
        seen_keys: Set[Tuple[str, int]] = set()
        newline_offsets: Optional[List[int]] = None

        def _is_ignored(line_no: int, scar_id: str, end_line_no: Optional[int] = None) -> bool:
            span_end = max(line_no, end_line_no or line_no)
            if allowed_lines is not None:
                if not any(ln in allowed_lines for ln in range(line_no, span_end + 1)):
                    return True
            if not (1 <= line_no <= len(lines)):
                return False
            ignored = _extract_ignored_ids(lines[line_no - 1])
            if ignored is None:
                return False
            return "*" in ignored or scar_id.upper() in ignored

        tree: Optional[ast.AST] = None
        if lang == "python" and self._ast_scars:
            try:
                tree = ast.parse(content, filename=file_path)
            except SyntaxError:
                tree = None
            if tree is not None:
                visitor = _PythonASTVisitor(lines, self._ast_scars)
                visitor.visit(tree)
                for scar, lineno, end_lineno, col, snippet in visitor.matches:
                    if _is_ignored(lineno, scar.id, end_lineno):
                        continue
                    dedup = (scar.id, lineno)
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)
                    findings.append(
                        ScanFinding(
                            scar_id=scar.id,
                            title=scar.title,
                            severity=scar.severity,
                            category=scar.category,
                            file_path=file_path,
                            line=lineno,
                            column=col,
                            engine=f"ast:{scar.ast_rule}",
                            snippet=snippet[:200],
                            rationale=scar.rationale,
                            good_code_hint=scar.good_code,
                        )
                    )

        # Prepare comment-masked content preserving exact newlines & column offsets
        masked_content = _mask_comments_preserve_newlines(content, lang)
        if newline_offsets is None:
            newline_offsets = [idx for idx, ch in enumerate(content) if ch == "\n"]

        # Run StructuralCallExtractor for JS/TS/Go/Rust (Structural AST-Lite)
        if lang in {"javascript", "typescript", "go", "rust"}:
            scars_by_id = {s.id: s for s in self.scars}
            extractor = _StructuralCallExtractor(lines, masked_content, lang, scars_by_id, newline_offsets)
            for scar, lineno, end_lineno, col, snippet, engine_name in extractor.find_findings():
                if _is_ignored(lineno, scar.id, end_lineno):
                    continue
                dedup = (scar.id, lineno)
                if dedup in seen_keys:
                    continue
                seen_keys.add(dedup)
                findings.append(
                    ScanFinding(
                        scar_id=scar.id,
                        title=scar.title,
                        severity=scar.severity,
                        category=scar.category,
                        file_path=file_path,
                        line=lineno,
                        column=col,
                        engine=engine_name,
                        snippet=snippet[:200],
                        rationale=scar.rationale,
                        good_code_hint=scar.good_code,
                    )
                )

        # Single-pass fused regex fast-gate skips per-rule scanning completely if 0 patterns match
        fast_gate = self._lang_fast_gate.get(lang)
        applicable_regex = list(self._lang_regex_map.get(lang, []))
        if lang != "*":
            applicable_regex.extend(self._lang_regex_map.get("*", []))
        if not applicable_regex and self._compiled_regex:
            applicable_regex = [
                (s, p)
                for s, p in self._compiled_regex
                if not s.languages or "*" in [x.lower() for x in s.languages] or lang in [x.lower() for x in s.languages]
            ]

        if applicable_regex and (fast_gate is None or fast_gate.search(content) is not None):
            for scar, pattern in applicable_regex:
                if lang == "python" and tree is not None and scar.ast_rule:
                    continue
                if lang in {"javascript", "typescript", "go", "rust"} and scar.id in {"KS-013", "KS-014", "KS-015", "KS-016"}:
                    continue
                for match in pattern.finditer(content):
                    start = match.start()
                    end = max(start, match.end() - 1)
                    line_idx = bisect.bisect_right(newline_offsets, start - 1) if start > 0 else 0
                    end_line_idx = bisect.bisect_right(newline_offsets, end - 1) if end > 0 else 0
                    lineno = line_idx + 1
                    end_lineno = max(lineno, end_line_idx + 1)
                    line_start = newline_offsets[line_idx - 1] if line_idx > 0 else -1
                    col = start - (0 if line_start == -1 else line_start + 1) + 1
                    if _is_ignored(lineno, scar.id, end_lineno):
                        continue
                    dedup = (scar.id, lineno)
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)
                    snippet = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else match.group(0)
                    findings.append(
                        ScanFinding(
                            scar_id=scar.id,
                            title=scar.title,
                            severity=scar.severity,
                            category=scar.category,
                            file_path=file_path,
                            line=lineno,
                            column=col,
                            engine="regex",
                            snippet=snippet[:200],
                            rationale=scar.rationale,
                            good_code_hint=scar.good_code,
                        )
                    )

        findings.sort(key=lambda f: (f.file_path, f.line, -f.severity.rank, f.scar_id))
        if cache_key is not None:
            if len(self._scan_cache) >= 2048:
                self._scan_cache.clear()
            self._scan_cache[cache_key] = list(findings)
        return findings

    def iter_target_files(self, target: Path) -> Iterable[Path]:
        if target.is_file():
            yield target
            return
        for root, dirs, files in os.walk(target):
            dirs[:] = sorted(d for d in dirs if d not in self.excluded_dirs)
            root_path = Path(root)
            for fname in sorted(files):
                fpath = root_path / fname
                if fpath.suffix.lower() in EXTENSION_LANGUAGE_MAP:
                    yield fpath

    def scan_path(self, target: str | Path) -> ScanReport:
        t0 = time.perf_counter()
        target_path = Path(target)
        findings: List[ScanFinding] = []
        file_count = 0

        for fpath in self.iter_target_files(target_path):
            try:
                text = fpath.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            file_count += 1
            findings.extend(self.scan_text(text, file_path=str(fpath)))

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return ScanReport(
            scanned_files=file_count,
            active_scars=len(self.scars),
            findings=findings,
            elapsed_ms=elapsed_ms,
        )

    def scan_git_changes(
        self,
        repo_root: str | Path = ".",
        *,
        staged: bool = False,
        diff_ref: Optional[str] = None,
    ) -> ScanReport:
        """Scan only git-modified files and touched line numbers (reads Git index blobs when staged=True)."""
        t0 = time.perf_counter()
        root_resolved = Path(repo_root).resolve()
        changed_map = get_git_changed_lines(root_resolved, staged=staged, diff_ref=diff_ref)
        findings: List[ScanFinding] = []
        file_count = 0

        for fpath, touched_lines in sorted(changed_map.items()):
            if fpath.suffix.lower() not in EXTENSION_LANGUAGE_MAP:
                continue
            try:
                rel_dir_parts = fpath.relative_to(root_resolved).parts[:-1]
            except ValueError:
                continue
            if any(part in self.excluded_dirs for part in rel_dir_parts):
                continue
            if staged:
                indexed_text = read_git_index_blob(root_resolved, fpath)
                if indexed_text is None:
                    continue
                text = indexed_text
            else:
                try:
                    text = fpath.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
            file_count += 1
            findings.extend(
                self.scan_text(
                    text,
                    file_path=str(fpath),
                    allowed_lines=touched_lines,
                )
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return ScanReport(
            scanned_files=file_count,
            active_scars=len(self.scars),
            findings=findings,
            elapsed_ms=elapsed_ms,
        )


def report_to_sarif(report: ScanReport, scars: Sequence[GoldenScar]) -> Dict[str, Any]:
    """Export ScanReport to OASIS SARIF 2.1.0 format for GitHub Code Scanning."""
    rules_payload = []
    for scar in scars:
        rules_payload.append(
            {
                "id": scar.id,
                "name": scar.title,
                "shortDescription": {"text": scar.title},
                "fullDescription": {"text": f"{scar.root_cause} {scar.rationale}".strip()},
                "help": {
                    "text": f"Recommended pattern:\n{scar.good_code}",
                    "markdown": f"**Why:** {scar.rationale}\n\n**Verified Fix:**\n```\n{scar.good_code}\n```",
                },
                "defaultConfiguration": {"level": scar.severity.sarif_level},
                "properties": {"tags": scar.tags, "category": scar.category},
            }
        )

    results_payload = []
    for f in report.findings:
        results_payload.append(
            {
                "ruleId": f.scar_id,
                "level": f.severity.sarif_level,
                "message": {"text": f"{f.title} — {f.rationale}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": f.line,
                                "startColumn": f.column,
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "kintsugi-harness",
                        "version": __version__,
                        "informationUri": "https://github.com/tunguyen1993/kintsugi-harness",
                        "rules": rules_payload,
                    }
                },
                "results": results_payload,
            }
        ],
    }
