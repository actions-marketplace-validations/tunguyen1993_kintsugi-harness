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
    ".claude",
    ".cursor",
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
HUNK_HEADER_RE = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")
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


def parse_git_diff_text(diff_text: str, repo_root: Path, *, require_worktree_file: bool = True) -> Dict[Path, Set[int]]:
    """
    Parse unified `git diff -U0` output into `{resolved_file_path: {added_or_modified_line_numbers}}`.
    """
    changed: Dict[Path, Set[int]] = {}
    current_file: Optional[Path] = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            rel_path = raw_line[6:].strip()
            current_file = (repo_root / rel_path).resolve()
            changed.setdefault(current_file, set())
        elif raw_line.startswith("+++ /dev/null"):
            current_file = None
        elif current_file is not None and raw_line.startswith("@@"):
            match = HUNK_HEADER_RE.match(raw_line)
            if match:
                start_line = int(match.group(1))
                count = int(match.group(2)) if match.group(2) is not None else 1
                if count > 0:
                    changed[current_file].update(range(start_line, start_line + count))
    return {
        p: lines
        for p, lines in changed.items()
        if lines and (not require_worktree_file or p.exists())
    }


def read_git_index_blob(repo_root: str | Path, file_path: str | Path) -> Optional[str]:
    """Read staged file content directly from the Git index (`:<relpath>`) for index-safe scanning."""
    root = Path(repo_root).resolve()
    target = Path(file_path).resolve()
    try:
        rel_posix = target.relative_to(root).as_posix()
    except ValueError:
        return None
    proc = subprocess.run(
        ["git", "-C", str(root), "show", f":{rel_posix}"],
        capture_output=True,
        text=True,
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
    """Run `git diff -U0` and return touched line numbers per file."""
    root = Path(repo_root).resolve()
    cmd = ["git", "-C", str(root), "diff", "-U0", "--no-color"]
    if staged:
        cmd.append("--staged")
    elif diff_ref:
        cmd.append(diff_ref)
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
        self.matches: List[Tuple[GoldenScar, int, int, str]] = []
        self._current_target_names: List[str] = []

    def _record(self, rule_name: str, node: ast.AST) -> None:
        scars = self.ast_scars.get(rule_name, [])
        if not scars:
            return
        lineno = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0) + 1
        snippet = (
            self.source_lines[lineno - 1].strip()
            if 1 <= lineno <= len(self.source_lines)
            else ""
        )
        for scar in scars:
            self.matches.append((scar, lineno, col, snippet))

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

        if call_name in {"eval", "exec", "pickle.loads", "pickle.load", "marshal.loads"}:
            self._record("py_unsafe_dynamic_exec", node)
        elif call_name == "yaml.load" and "Loader" not in kwargs:
            self._record("py_unsafe_dynamic_exec", node)

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

        lines = content.splitlines()
        if any(IGNORE_FILE_RE.search(ln) for ln in lines[:5]):
            return []
        findings: List[ScanFinding] = []
        seen_keys: Set[Tuple[str, int]] = set()
        newline_offsets: Optional[List[int]] = None

        def _is_ignored(line_no: int, scar_id: str) -> bool:
            if allowed_lines is not None and line_no not in allowed_lines:
                return True
            if not (1 <= line_no <= len(lines)):
                return False
            ignored = _extract_ignored_ids(lines[line_no - 1])
            if ignored is None:
                return False
            return "*" in ignored or scar_id.upper() in ignored

        if lang == "python" and self._ast_scars:
            try:
                tree = ast.parse(content, filename=file_path)
            except SyntaxError:
                tree = None
            if tree is not None:
                visitor = _PythonASTVisitor(lines, self._ast_scars)
                visitor.visit(tree)
                for scar, lineno, col, snippet in visitor.matches:
                    if _is_ignored(lineno, scar.id):
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
                for match in pattern.finditer(content):
                    start = match.start()
                    if newline_offsets is None:
                        newline_offsets = [idx for idx, ch in enumerate(content) if ch == "\n"]
                    line_idx = bisect.bisect_right(newline_offsets, start - 1) if start > 0 else 0
                    lineno = line_idx + 1
                    line_start = newline_offsets[line_idx - 1] if line_idx > 0 else -1
                    col = start - (0 if line_start == -1 else line_start + 1) + 1
                    if _is_ignored(lineno, scar.id):
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
            if any(part in self.excluded_dirs for part in fpath.parts):
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
