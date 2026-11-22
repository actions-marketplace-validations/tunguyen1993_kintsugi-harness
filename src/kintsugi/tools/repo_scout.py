"""
RepoScout (`kintsugi.tools.repo_scout`) — Symlink-Confined, Incremental Repository Intelligence
& Diff-to-Test Impact Slicer (`KINTSUGI-NEXTGEN/1` Section H1).

Capabilities:
  1. Symlink-confined deterministic file walker excluding build/VCS noise (`DEFAULT_EXCLUDED_DIRS`)
     and rejecting symlinks (`O_NOFOLLOW`, component `is_symlink()` checks, and `resolve()` bounds).
  2. Incremental atomic cache (`RepoIndex/1`) persisted via `shield.assert_not_symlink` and
     `shield.atomic_write_json`, tracking per-file SHA-256 + `mtime_ns` + `size` so rescans
     and `update_from_paths()` only re-parse new or modified files.
  3. Python AST + Rust symbol, dependency, and call-site extraction (compatible with
     `kintsugi.grounding.RepoAstGroundingEngine`).
  4. Reverse dependency graph traversal (`map_changed_files_to_tests`) returning minimal ranked
     test targets and matched symbol call-sites.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

from kintsugi.grounding import RepoAstGroundingEngine
from kintsugi.scanner import DEFAULT_EXCLUDED_DIRS
from kintsugi.shield import assert_not_symlink, atomic_write_json

REPO_INDEX_SCHEMA = "RepoIndex/1"
REPO_SCOUT_IMPACT_SCHEMA = "RepoScoutImpact/1"
DEFAULT_INDEX_REL_PATH = Path(".kintsugi") / "repo_scout_index.json"
DEFAULT_SOURCE_EXTENSIONS: FrozenSet[str] = frozenset({".py", ".rs"})

_MAX_TRAVERSAL_STEPS = 100_000
_MAX_INDEX_BYTES = 64 * 1024 * 1024

_RUST_KEYWORDS: FrozenSet[str] = frozenset({
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "sizeof",
})

_RUST_TOKEN_RE = re.compile(r'//|/\*|r#*"|"|\'')
_RUST_BLOCK_COMMENT_RE = re.compile(r"/\*|\*/")
_RUST_STR_INNER_RE = re.compile(r'\\.|"', re.DOTALL)
_RUST_CHAR_LIT_RE = re.compile(
    r"(?:[^\n\\']|\\(?:[^\n]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]+\}))'"
)
_RUST_MOD_DECL_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
_RUST_DECL_RE = re.compile(
    r"^\s*(?P<vis>pub(?:\s*\([^)]*\))?)?\s*"
    r"(?:(?:async|unsafe|const)\s+)*"
    r"(?P<kind>fn|struct|enum|trait|mod)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_RUST_IMPL_RE = re.compile(
    r"^\s*impl(?:<[^>]*>)?\s+(?:[A-Za-z0-9_:<>]+\s+for\s+)?([A-Za-z_][A-Za-z0-9_]*)\b"
)
_RUST_CALL_RE = re.compile(
    r"(?P<dot>\.)?(?P<target>[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)\s*(?:::<[^>]*>)?\s*\("
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_under_root(candidate_resolved: Path, root_resolved: Path) -> bool:
    return candidate_resolved == root_resolved or root_resolved in candidate_resolved.parents


def _mask_preserving_newlines(segment: str) -> str:
    if "\n" not in segment:
        return " " * len(segment)
    return "".join("\n" if ch == "\n" else " " for ch in segment)


def _dotted_from_call_expr(expr: ast.AST) -> Optional[str]:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        parent = _dotted_from_call_expr(expr.value)
        return f"{parent}.{expr.attr}" if parent else f"<expr>.{expr.attr}"
    return None


def _python_module_from_rel(rel_path: str) -> Tuple[str, bool]:
    """Derive canonical Python module name and `__init__` flag from a POSIX relative path."""
    parts = list(Path(rel_path).parts)
    if parts and parts[0] == "src" and len(parts) > 1:
        parts = parts[1:]
    if not parts:
        return "", False
    stem = Path(parts[-1]).stem
    is_init = stem == "__init__"
    mod_parts = parts[:-1] if is_init else parts[:-1] + [stem]
    return ".".join(mod_parts), is_init


def _resolve_relative_import(
    current_module: str, is_init: bool, raw_module: Optional[str], level: int
) -> str:
    """Resolve Python relative import level (`from ..x import y`) against `current_module`."""
    if level <= 0:
        return raw_module or ""
    mod_parts = current_module.split(".") if current_module else []
    pkg_parts = mod_parts if is_init else mod_parts[:-1]
    ascend = level - 1
    if ascend > len(pkg_parts):
        return raw_module or ""
    base_parts = pkg_parts[: len(pkg_parts) - ascend]
    return ".".join(base_parts + raw_module.split(".")) if raw_module else ".".join(base_parts)


def _is_python_test_path(rel_path: str) -> bool:
    name = Path(rel_path).name
    return name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py"))


def _is_rust_test_path(rel_path: str, has_inline_tests: bool) -> bool:
    p = Path(rel_path)
    if p.suffix.lower() != ".rs":
        return False
    return has_inline_tests or "tests" in p.parts[:-1] or p.name.endswith("_test.rs")


class _PythonModuleExtractor(ast.NodeVisitor):
    """AST visitor extracting imports, scoped symbol spans, and resolved call-sites."""

    def __init__(self, rel_path: str, module_name: str, is_init: bool, include_ast_hashes: bool = False) -> None:
        self.rel_path = rel_path
        self.module_name = module_name
        self.is_init = is_init
        self.include_ast_hashes = include_ast_hashes
        self._scope: List[str] = []
        self._local_aliases: Dict[str, str] = {}
        self._local_symbols: Set[str] = set()
        self.imports: List[Dict[str, Any]] = []
        self.import_modules: Set[str] = set()
        self.symbols: List[Dict[str, Any]] = []
        self.call_sites: List[Dict[str, Any]] = []

    def _current_caller(self) -> str:
        return ".".join(self._scope) if self._scope else "<module>"

    def _qualname(self, name: str) -> str:
        return ".".join(self._scope + [name]) if self._scope else name

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bind_name = alias.asname or alias.name.split(".", 1)[0]
            self._local_aliases[bind_name] = alias.name if alias.asname else bind_name
            self.import_modules.add(alias.name)
            self.imports.append({
                "kind": "import",
                "module": alias.name,
                "raw_module": alias.name,
                "names": [],
                "asname": alias.asname,
                "level": 0,
                "line": int(node.lineno),
            })

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        resolved_mod = _resolve_relative_import(
            self.module_name, self.is_init, node.module, int(node.level or 0)
        )
        names = sorted(alias.name for alias in node.names)
        if resolved_mod:
            self.import_modules.add(resolved_mod)
        for alias in node.names:
            if alias.name == "*":
                continue
            target_qual = f"{resolved_mod}.{alias.name}" if resolved_mod else alias.name
            self.import_modules.add(target_qual)
            self._local_aliases[alias.asname or alias.name] = target_qual
        self.imports.append({
            "kind": "from",
            "module": resolved_mod,
            "raw_module": node.module or "",
            "names": names,
            "asname": None,
            "level": int(node.level or 0),
            "line": int(node.lineno),
        })

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qual = self._qualname(node.name)
        self._local_symbols.add(node.name)
        bases = [b for b in (_dotted_from_call_expr(base) for base in node.bases) if b]
        end_line = int(getattr(node, "end_lineno", node.lineno) or node.lineno)
        self.symbols.append({
            "name": node.name,
            "qualname": qual,
            "kind": "class",
            "visibility": "private" if node.name.startswith("_") else "public",
            "start_line": int(node.lineno),
            "end_line": end_line,
            "anchor": f"{self.rel_path}:{node.lineno}",
            "bases": bases,
        })
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str) -> None:
        qual = self._qualname(node.name)
        self._local_symbols.add(node.name)
        end_line = int(getattr(node, "end_lineno", node.lineno) or node.lineno)
        decorators = [d for d in (_dotted_from_call_expr(dec) for dec in node.decorator_list) if d]
        sym_entry: Dict[str, Any] = {
            "name": node.name,
            "qualname": qual,
            "kind": kind,
            "visibility": "private" if node.name.startswith("_") else "public",
            "start_line": int(node.lineno),
            "end_line": end_line,
            "anchor": f"{self.rel_path}:{node.lineno}",
            "decorators": decorators,
        }
        if self.include_ast_hashes:
            sym_entry["ast_quotient_hash"] = RepoAstGroundingEngine.compute_alpha_normalized_ast_hash(node)
        self.symbols.append(sym_entry)
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, "async_function")

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_from_call_expr(node.func)
        if dotted:
            self.call_sites.append({
                "file": self.rel_path,
                "line": int(node.lineno),
                "end_line": int(getattr(node, "end_lineno", node.lineno) or node.lineno),
                "caller": self._current_caller(),
                "target": dotted,
                "callee": dotted.rsplit(".", 1)[-1],
                "resolved_target": dotted,
                "anchor": f"{self.rel_path}:{node.lineno}",
            })
        self.generic_visit(node)

    def finalize(self) -> None:
        for site in self.call_sites:
            target = site["target"]
            if target.startswith("<expr>."):
                continue
            head, *tail = target.split(".")
            if head in self._local_aliases:
                resolved_head = self._local_aliases[head]
                site["resolved_target"] = ".".join([resolved_head] + tail) if tail else resolved_head
            elif head in self._local_symbols and self.module_name:
                site["resolved_target"] = f"{self.module_name}.{target}"
        self.imports.sort(key=lambda item: (item["line"], item["kind"], item["module"], tuple(item["names"])))
        self.symbols.sort(key=lambda item: (item["start_line"], item["end_line"], item["kind"], item["qualname"]))
        self.call_sites.sort(key=lambda item: (item["line"], item["caller"], item["target"]))


def _strip_rust_comments_and_strings(text: str) -> str:
    """Replace Rust comments and literals with spaces while preserving line numbers."""
    n = len(text)
    out: List[str] = []
    pos = 0
    for _ in range(n + 1):
        if pos >= n:
            break
        m = _RUST_TOKEN_RE.search(text, pos)
        if m is None:
            out.append(text[pos:])
            break
        if m.start() > pos:
            out.append(text[pos : m.start()])
        tok = m.group(0)
        if tok == "//":
            nl = text.find("\n", m.end())
            end_pos = n if nl == -1 else nl
            out.append(" " * (end_pos - m.start()))
            pos = end_pos
        elif tok == "/*":
            depth = 1
            scan = m.end()
            for _ in range(n + 1):
                bm = _RUST_BLOCK_COMMENT_RE.search(text, scan)
                if bm is None:
                    scan = n
                    break
                depth += 1 if bm.group(0) == "/*" else -1
                scan = bm.end()
                if depth == 0:
                    break
            out.append(_mask_preserving_newlines(text[m.start() : scan]))
            pos = scan
        elif tok.startswith("r"):
            closing = '"' + ("#" * (len(tok) - 2))
            close_idx = text.find(closing, m.end())
            end_pos = n if close_idx == -1 else close_idx + len(closing)
            out.append(_mask_preserving_newlines(text[m.start() : end_pos]))
            pos = end_pos
        elif tok == '"':
            scan = m.end()
            for _ in range(n + 1):
                sm = _RUST_STR_INNER_RE.search(text, scan)
                if sm is None:
                    scan = n
                    break
                scan = sm.end()
                if sm.group(0) == '"':
                    break
            out.append(_mask_preserving_newlines(text[m.start() : scan]))
            pos = scan
        else:
            cm = _RUST_CHAR_LIT_RE.match(text, m.end())
            if cm is not None:
                out.append(" " * (cm.end() - m.start()))
                pos = cm.end()
            else:
                out.append("'")
                pos = m.end()
    return "".join(out)


def _expand_rust_use_statement(stmt: str) -> List[str]:
    """Expand a Rust `use ...;` statement into flattened path strings."""
    cleaned = re.sub(r"^pub(?:\s*\([^)]*\))?\s+", "", stmt.strip())
    if not cleaned.startswith("use "):
        return []
    body = cleaned[4:].rstrip(";").strip()

    def _expand_group(expr: str) -> List[str]:
        expr = expr.strip()
        if not expr:
            return []
        lbrace = expr.find("{")
        if lbrace == -1:
            base = re.sub(r"\s+as\s+[A-Za-z_][A-Za-z0-9_]*$", "", expr).strip()
            return [base] if base else []
        prefix = expr[:lbrace].strip()
        rbrace = expr.rfind("}")
        if rbrace == -1 or rbrace < lbrace:
            return [prefix.rstrip(":")] if prefix else []
        inner = expr[lbrace + 1 : rbrace]
        parts: List[str] = []
        depth = 0
        start = 0
        for idx, ch in enumerate(inner):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
            elif ch == "," and depth == 0:
                parts.append(inner[start:idx])
                start = idx + 1
        parts.append(inner[start:])
        results: List[str] = []
        for item in parts:
            for expanded in _expand_group(item):
                if expanded == "self":
                    joined = prefix.rstrip(":")
                elif expanded:
                    joined = (
                        f"{prefix}{expanded}"
                        if prefix.endswith("::")
                        else f"{prefix}::{expanded}"
                        if prefix
                        else expanded
                    )
                else:
                    joined = prefix.rstrip(":")
                if joined:
                    results.append(joined)
        return results

    return sorted(set(_expand_group(body))) if body else []


def _precompute_rust_brace_ends(lines: List[str]) -> Dict[int, int]:
    """Map each 0-based line index containing an opening `{` to its matching 1-based closing line."""
    stack: List[Tuple[int, bool]] = []
    first_brace_end: Dict[int, int] = {}
    for idx, line in enumerate(lines):
        seen_open_on_line = False
        for ch in line:
            if ch == "{":
                stack.append((idx, not seen_open_on_line))
                seen_open_on_line = True
            elif ch == "}" and stack:
                open_idx, is_first = stack.pop()
                if is_first:
                    first_brace_end[open_idx] = idx + 1
    return first_brace_end


def _rust_decl_end_line(lines: List[str], start_idx: int, brace_ends: Dict[int, int]) -> int:
    limit = min(len(lines), start_idx + 32)
    for idx in range(start_idx, limit):
        line = lines[idx]
        if "{" in line:
            return brace_ends.get(idx, idx + 1)
        if ";" in line:
            return idx + 1
    return start_idx + 1


def _extract_rust_file(rel_path: str, text: str) -> Dict[str, Any]:
    """Extract Rust `pub fn`, `pub struct`, `mod`, `use` imports, and call-sites."""
    stripped = _strip_rust_comments_and_strings(text)
    has_inline_tests = "#[test]" in stripped or bool(re.search(r"#\[cfg\s*\(\s*test\s*\)\]", stripped))
    lines = stripped.splitlines()
    brace_ends = _precompute_rust_brace_ends(lines)

    imports: List[Dict[str, Any]] = []
    import_modules: Set[str] = set()
    symbols: List[Dict[str, Any]] = []
    use_buffer: List[str] = []
    use_start_line = 0

    for idx, line in enumerate(lines):
        ln = idx + 1
        s_line = line.strip()
        if use_buffer or re.match(r"^(?:pub(?:\s*\([^)]*\))?\s+)?use\s+", s_line):
            if not use_buffer:
                use_start_line = ln
            use_buffer.append(s_line)
            if ";" in s_line:
                joined = " ".join(use_buffer)
                expanded = _expand_rust_use_statement(joined)
                import_modules.update(expanded)
                if expanded:
                    imports.append({
                        "kind": "use",
                        "module": expanded[0].split("::", 1)[0],
                        "raw_module": joined,
                        "names": expanded,
                        "asname": None,
                        "level": 0,
                        "line": use_start_line,
                    })
                use_buffer.clear()
            continue

        m_mod = _RUST_MOD_DECL_RE.match(line)
        if m_mod:
            mod_name = m_mod.group(1)
            vis = "public" if "pub" in line.split("mod", 1)[0] else "private"
            imports.append({
                "kind": "mod",
                "module": mod_name,
                "raw_module": mod_name,
                "names": [mod_name],
                "asname": None,
                "level": 0,
                "line": ln,
            })
            import_modules.add(f"mod::{mod_name}")
            symbols.append({
                "name": mod_name,
                "qualname": mod_name,
                "kind": "mod",
                "visibility": vis,
                "start_line": ln,
                "end_line": ln,
                "anchor": f"{rel_path}:{ln}",
            })
            continue

        m_decl = _RUST_DECL_RE.match(line)
        if m_decl:
            vis_raw = (m_decl.group("vis") or "").strip()
            vis = "public" if vis_raw == "pub" else (vis_raw or "private")
            kind_kw = m_decl.group("kind")
            sym_name = m_decl.group("name")
            symbols.append({
                "name": sym_name,
                "qualname": sym_name,
                "kind": "function" if kind_kw == "fn" else kind_kw,
                "visibility": vis,
                "start_line": ln,
                "end_line": _rust_decl_end_line(lines, idx, brace_ends),
                "anchor": f"{rel_path}:{ln}",
            })

    call_sites = _extract_rust_call_sites(rel_path, lines, symbols)
    imports.sort(key=lambda item: (item["line"], item["kind"], item["module"]))
    symbols.sort(key=lambda item: (item["start_line"], item["end_line"], item["kind"], item["qualname"]))
    call_sites.sort(key=lambda item: (item["line"], item["caller"], item["target"]))

    return {
        "language": "rust",
        "module": Path(rel_path).stem,
        "line_count": len(text.splitlines()),
        "is_test": _is_rust_test_path(rel_path, has_inline_tests),
        "has_tests": has_inline_tests,
        "syntax_error": False,
        "imports": imports,
        "import_modules": sorted(import_modules),
        "symbols": symbols,
        "call_sites": call_sites,
    }


def _extract_rust_call_sites(
    rel_path: str, lines: List[str], symbols: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    fn_spans = [(s["start_line"], s["end_line"], s["qualname"]) for s in symbols if s["kind"] == "function"]
    call_sites: List[Dict[str, Any]] = []
    span_idx = 0
    for idx, line in enumerate(lines):
        ln = idx + 1
        if _RUST_DECL_RE.match(line) or _RUST_IMPL_RE.match(line):
            continue
        if re.match(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?use\s+", line):
            continue
        while span_idx < len(fn_spans) and fn_spans[span_idx][1] < ln:
            span_idx += 1
        caller = "<module>"
        for probe in range(span_idx, len(fn_spans)):
            st_ln, en_ln, qname = fn_spans[probe]
            if st_ln > ln:
                break
            if st_ln <= ln <= en_ln:
                caller = qname
        for match in _RUST_CALL_RE.finditer(line):
            target = match.group("target")
            leaf = target.rsplit("::", 1)[-1]
            if leaf in _RUST_KEYWORDS:
                continue
            call_sites.append({
                "file": rel_path,
                "line": ln,
                "end_line": ln,
                "caller": caller,
                "target": target,
                "callee": leaf,
                "resolved_target": target,
                "anchor": f"{rel_path}:{ln}",
            })
    return call_sites


def _extract_python_file(rel_path: str, text: str, include_ast_hashes: bool = False) -> Dict[str, Any]:
    """Extract Python module, imports, scoped symbol spans, and call-sites."""
    module_name, is_init = _python_module_from_rel(rel_path)
    raw_lines = text.splitlines()
    try:
        tree = ast.parse(text, filename=rel_path)
    except SyntaxError:
        return {
            "language": "python",
            "module": module_name,
            "line_count": len(raw_lines),
            "is_test": _is_python_test_path(rel_path),
            "has_tests": False,
            "syntax_error": True,
            "imports": [],
            "import_modules": [],
            "symbols": [],
            "call_sites": [],
        }

    visitor = _PythonModuleExtractor(rel_path, module_name, is_init, include_ast_hashes=include_ast_hashes)
    visitor.visit(tree)
    visitor.finalize()
    has_test_defs = any(
        s["kind"] in ("function", "async_function") and s["name"].startswith("test_")
        for s in visitor.symbols
    )
    return {
        "language": "python",
        "module": module_name,
        "line_count": len(raw_lines),
        "is_test": _is_python_test_path(rel_path),
        "has_tests": has_test_defs,
        "syntax_error": False,
        "imports": visitor.imports,
        "import_modules": sorted(visitor.import_modules),
        "symbols": visitor.symbols,
        "call_sites": visitor.call_sites,
    }


def _find_rust_src_root(rel_path: str, files_map: Dict[str, Dict[str, Any]]) -> Path:
    cur = Path(rel_path).parent
    for _ in range(64):
        if (cur / "lib.rs").as_posix() in files_map or (cur / "main.rs").as_posix() in files_map:
            return cur
        if cur.name == "src" or str(cur) in ("", "."):
            return cur
        cur = cur.parent
    return Path("src")


def _matched_query_symbols(site: Dict[str, Any], queries: Set[str]) -> List[str]:
    candidates = {site.get("target", ""), site.get("callee", ""), site.get("resolved_target", "")}
    matched: Set[str] = set()
    for q in queries:
        if q in candidates:
            matched.add(q)
            continue
        q_leaf = q.rsplit(".", 1)[-1].rsplit("::", 1)[-1]
        if q_leaf and q_leaf == site.get("callee", ""):
            matched.add(q)
    return sorted(matched)


class RepoScout:
    """
    Fast symlink-confined, incremental diff-aware repository intelligence & test-impact slicer.

    Tracks per-file SHA-256 + `mtime_ns` + `size` under `RepoIndex/1` so incremental updates
    re-parse only added or modified files while guaranteeing canonical parity with cold builds.
    """

    def __init__(
        self,
        repo_root: str | Path,
        index_path: Optional[str | Path] = None,
        excluded_dirs: Optional[Iterable[str]] = None,
        extensions: Optional[Iterable[str]] = None,
        include_ast_hashes: bool = False,
    ) -> None:
        raw_root = Path(repo_root)
        assert_not_symlink(raw_root)
        if not raw_root.exists() or not raw_root.is_dir():
            raise NotADirectoryError(f"Repository root is not an existing directory: {raw_root}")

        self._raw_root_abs = Path(os.path.abspath(str(raw_root)))
        self.repo_root: Path = raw_root.resolve()
        self.excluded_dirs: FrozenSet[str] = (
            frozenset(excluded_dirs) if excluded_dirs is not None else frozenset(DEFAULT_EXCLUDED_DIRS)
        )
        self.extensions: FrozenSet[str] = (
            frozenset(ext.lower() for ext in extensions)
            if extensions is not None
            else DEFAULT_SOURCE_EXTENSIONS
        )
        self.include_ast_hashes = include_ast_hashes
        self.index_path: Path = self._resolve_index_path(index_path)
        self._index: Dict[str, Any] = {}
        self._last_stats: Dict[str, Any] = {}

    @property
    def index(self) -> Dict[str, Any]:
        return dict(self._index)

    @property
    def last_stats(self) -> Dict[str, Any]:
        return dict(self._last_stats)

    def _resolve_index_path(self, index_path: Optional[str | Path]) -> Path:
        candidate = Path(index_path) if index_path is not None else (self.repo_root / DEFAULT_INDEX_REL_PATH)
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        self._assert_index_path_safe(candidate)
        return candidate

    def _assert_index_path_safe(self, candidate: Path) -> None:
        assert_not_symlink(candidate.parent)
        assert_not_symlink(candidate)
        try:
            rel = candidate.relative_to(self.repo_root)
        except ValueError:
            rel = None
        if rel is not None:
            cur = self.repo_root
            for part in rel.parts:
                cur = cur / part
                assert_not_symlink(cur)

    def _confine_candidate(self, raw_path: str | Path, *, check_extension: bool = True) -> Optional[str]:
        """Validate that `raw_path` resolves strictly within `self.repo_root` without symlinks."""
        raw_str = str(raw_path).strip()
        if not raw_str or "\x00" in raw_str:
            return None

        p = Path(raw_str)
        if p.is_absolute():
            rel_candidate: Optional[Path] = None
            for root_base in (self.repo_root, self._raw_root_abs):
                try:
                    rel_candidate = p.relative_to(root_base)
                    break
                except ValueError:
                    continue
            if rel_candidate is None:
                return None
            parts = rel_candidate.parts
        else:
            parts = p.parts

        if not parts or any(part in ("..", "") for part in parts):
            return None
        clean_parts = [part for part in parts if part != "."]
        if not clean_parts or any(part in self.excluded_dirs for part in clean_parts):
            return None

        cur = self.repo_root
        for part in clean_parts:
            cur = cur / part
            if cur.is_symlink():
                return None

        try:
            resolved = cur.resolve()
        except OSError:
            return None
        if resolved == self.repo_root or not _is_under_root(resolved, self.repo_root):
            return None
        if check_extension and resolved.suffix.lower() not in self.extensions:
            return None
        return Path(*clean_parts).as_posix()

    @staticmethod
    def _open_confined_fd_with_stat(
        target: Path, max_bytes: Optional[int] = None
    ) -> Tuple[bytes, int, int]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(target), flags)
        opened_stream = False
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"Refusing non-regular file: {target}")
            if max_bytes is not None and st.st_size > max_bytes:
                raise ValueError(f"File exceeds max size guard ({st.st_size} bytes): {target}")
            with os.fdopen(fd, "rb") as handle:
                opened_stream = True
                return handle.read(), int(st.st_mtime_ns), int(st.st_size)
        finally:
            if not opened_stream:
                try:
                    os.close(fd)
                except OSError as _close_err:
                    _ = _close_err

    def _read_confined_bytes(self, rel_path: str) -> Optional[Tuple[bytes, int, int]]:
        """Read file bytes via `O_NOFOLLOW` after verifying non-symlink containment."""
        verified_rel = self._confine_candidate(rel_path, check_extension=True)
        if verified_rel is None:
            return None
        try:
            return self._open_confined_fd_with_stat(self.repo_root / verified_rel)
        except (OSError, PermissionError, ValueError):
            return None

    def _stat_confined_file(self, rel_path: str) -> Optional[Tuple[int, int]]:
        if self._confine_candidate(rel_path, check_extension=True) is None:
            return None
        try:
            st = os.lstat(str(self.repo_root / rel_path))
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            return None
        return int(st.st_mtime_ns), int(st.st_size)

    def walk_files(self) -> List[str]:
        """Walk workspace excluding `excluded_dirs` and all symlinks, returning sorted POSIX paths."""
        collected: List[str] = []
        for root, dirs, files in os.walk(self.repo_root, followlinks=False):
            root_path = Path(root)
            safe_dirs: List[str] = []
            for dname in sorted(dirs):
                dpath = root_path / dname
                if dname in self.excluded_dirs or dpath.is_symlink():
                    continue
                try:
                    if _is_under_root(dpath.resolve(), self.repo_root):
                        safe_dirs.append(dname)
                except OSError:
                    continue
            dirs[:] = safe_dirs

            for fname in sorted(files):
                fpath = root_path / fname
                if fpath.is_symlink() or fpath.suffix.lower() not in self.extensions:
                    continue
                try:
                    f_res = fpath.resolve()
                except OSError:
                    continue
                if f_res != self.repo_root and _is_under_root(f_res, self.repo_root):
                    collected.append(f_res.relative_to(self.repo_root).as_posix())
        return sorted(collected)

    def _parse_file_entry(
        self, rel_path: str, raw_bytes: bytes, mtime_ns: int, size: int
    ) -> Dict[str, Any]:
        text = raw_bytes.decode("utf-8", errors="replace")
        ext = Path(rel_path).suffix.lower()
        if ext == ".py":
            parsed = _extract_python_file(rel_path, text, include_ast_hashes=self.include_ast_hashes)
        elif ext == ".rs":
            parsed = _extract_rust_file(rel_path, text)
        else:
            parsed = {
                "language": ext.lstrip(".") or "unknown",
                "module": Path(rel_path).stem,
                "line_count": len(text.splitlines()),
                "is_test": False,
                "has_tests": False,
                "syntax_error": False,
                "imports": [],
                "import_modules": [],
                "symbols": [],
                "call_sites": [],
            }
        return {
            "path": rel_path,
            "sha256": _sha256_bytes(raw_bytes),
            "mtime_ns": mtime_ns,
            "size": size,
            **parsed,
        }

    @staticmethod
    def _build_dependency_graphs(
        files_map: Dict[str, Dict[str, Any]],
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]], Dict[str, List[Dict[str, Any]]]]:
        sorted_paths = sorted(files_map.keys())
        py_module_map: Dict[str, Set[str]] = {}
        has_src_init = "src/__init__.py" in files_map
        rust_pub_symbols: Dict[str, Set[str]] = {}
        rust_lib_files: List[str] = []

        for rel_path in sorted_paths:
            entry = files_map[rel_path]
            if entry["language"] == "python" and entry["module"]:
                mod = entry["module"]
                if rel_path.startswith("src/") and has_src_init:
                    py_module_map.setdefault(f"src.{mod}", set()).add(rel_path)
                else:
                    py_module_map.setdefault(mod, set()).add(rel_path)
                    if rel_path.startswith("src/"):
                        py_module_map.setdefault(f"src.{mod}", set()).add(rel_path)
            elif entry["language"] == "rust":
                if Path(rel_path).name == "lib.rs":
                    rust_lib_files.append(rel_path)
                rust_pub_symbols[rel_path] = {
                    s["name"]
                    for s in entry["symbols"]
                    if str(s.get("visibility", "")).startswith("pub")
                }

        deps_sets: Dict[str, Set[str]] = {p: set() for p in sorted_paths}
        rev_sets: Dict[str, Set[str]] = {p: set() for p in sorted_paths}

        def _add_edge(src_file: str, dst_file: str) -> None:
            if dst_file in files_map and dst_file != src_file:
                deps_sets[src_file].add(dst_file)
                rev_sets[dst_file].add(src_file)

        for rel_path in sorted_paths:
            entry = files_map[rel_path]
            if entry["language"] == "python":
                for imp_mod in entry["import_modules"]:
                    for target in py_module_map.get(imp_mod, ()):
                        _add_edge(rel_path, target)
            elif entry["language"] == "rust":
                RepoScout._link_rust_dependencies(
                    rel_path, entry, files_map, rust_lib_files, rust_pub_symbols, _add_edge
                )

        dependencies = {p: sorted(deps_sets[p]) for p in sorted_paths}
        reverse_dependencies = {p: sorted(rev_sets[p]) for p in sorted_paths}
        symbol_index = RepoScout._build_symbol_index(sorted_paths, files_map)
        return dependencies, reverse_dependencies, symbol_index

    @staticmethod
    def _link_rust_dependencies(
        rel_path: str,
        entry: Dict[str, Any],
        files_map: Dict[str, Dict[str, Any]],
        rust_lib_files: List[str],
        rust_pub_symbols: Dict[str, Set[str]],
        add_edge: Any,
    ) -> None:
        cur_dir = Path(rel_path).parent
        crate_src_root = _find_rust_src_root(rel_path, files_map)
        for imp in entry["imports"]:
            if imp["kind"] == "mod":
                m_name = imp["module"]
                add_edge(rel_path, (cur_dir / f"{m_name}.rs").as_posix())
                add_edge(rel_path, (cur_dir / m_name / "mod.rs").as_posix())
                continue
            for use_path in imp.get("names", ()):
                segs = [s for s in use_path.split("::") if s]
                if not segs:
                    continue
                if segs[0] in ("crate", "self", "super"):
                    base_dir = (
                        crate_src_root if segs[0] == "crate"
                        else cur_dir.parent if segs[0] == "super"
                        else cur_dir
                    )
                    rem = segs[1:]
                    for prefix_len in (len(rem), len(rem) - 1):
                        if prefix_len > 0:
                            sub = Path(*rem[:prefix_len])
                            add_edge(rel_path, (base_dir / f"{sub}.rs").as_posix())
                            add_edge(rel_path, (base_dir / sub / "mod.rs").as_posix())
                    if segs[0] == "crate":
                        add_edge(rel_path, (crate_src_root / "lib.rs").as_posix())
                elif segs[0] not in ("std", "core", "alloc"):
                    for lib_file in rust_lib_files:
                        pubs = rust_pub_symbols.get(lib_file, set())
                        if segs[-1] in pubs or (len(segs) >= 2 and segs[1] in pubs):
                            add_edge(rel_path, lib_file)

    @staticmethod
    def _build_symbol_index(
        sorted_paths: List[str], files_map: Dict[str, Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        symbol_index: Dict[str, List[Dict[str, Any]]] = {}
        for rel_path in sorted_paths:
            for sym in files_map[rel_path]["symbols"]:
                rec = {
                    "file": rel_path,
                    "name": sym["name"],
                    "qualname": sym["qualname"],
                    "kind": sym["kind"],
                    "visibility": sym.get("visibility", "public"),
                    "start_line": sym["start_line"],
                    "end_line": sym["end_line"],
                    "anchor": sym["anchor"],
                }
                symbol_index.setdefault(sym["name"], []).append(rec)
                if sym["qualname"] != sym["name"]:
                    symbol_index.setdefault(sym["qualname"], []).append(rec)
        return {
            name: sorted(items, key=lambda it: (it["file"], it["start_line"], it["qualname"]))
            for name, items in sorted(symbol_index.items())
        }

    @classmethod
    def _assemble_index(cls, files_map: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        sorted_files = {k: files_map[k] for k in sorted(files_map.keys())}
        dependencies, reverse_dependencies, symbol_index = cls._build_dependency_graphs(sorted_files)
        test_files = [k for k in sorted_files if sorted_files[k].get("is_test")]

        manifest_hasher = hashlib.sha256()
        canonical_files: Dict[str, Dict[str, Any]] = {}
        for rel_path, entry in sorted_files.items():
            manifest_hasher.update(f"{rel_path}:{entry['sha256']}\n".encode("utf-8"))
            canonical_files[rel_path] = {k: v for k, v in entry.items() if k != "mtime_ns"}
        manifest_sha = manifest_hasher.hexdigest()[:16]

        canonical_body = {
            "schema": REPO_INDEX_SCHEMA,
            "manifest_sha": manifest_sha,
            "file_count": len(sorted_files),
            "files": canonical_files,
            "dependencies": dependencies,
            "reverse_dependencies": reverse_dependencies,
            "test_files": test_files,
            "symbol_index": symbol_index,
        }
        canonical_bytes = json.dumps(
            canonical_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        index_digest = hashlib.sha256(canonical_bytes).hexdigest()

        return {
            "schema": REPO_INDEX_SCHEMA,
            "manifest_sha": manifest_sha,
            "index_digest": index_digest,
            "file_count": len(sorted_files),
            "files": sorted_files,
            "dependencies": dependencies,
            "reverse_dependencies": reverse_dependencies,
            "test_files": test_files,
            "symbol_index": symbol_index,
        }

    def _reconcile_file(
        self,
        rel_path: str,
        prev_entry: Optional[Dict[str, Any]],
        *,
        use_stat_fastpath: bool,
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """Reconcile one file against cached metadata; returns `(entry_or_none, status_tag)`."""
        if prev_entry is not None and use_stat_fastpath:
            st_info = self._stat_confined_file(rel_path)
            if st_info is not None and st_info == (prev_entry.get("mtime_ns"), prev_entry.get("size")):
                return prev_entry, "stat_hit"

        read_res = self._read_confined_bytes(rel_path)
        if read_res is None:
            return None, "missing"

        raw_bytes, mtime_ns, size = read_res
        digest = _sha256_bytes(raw_bytes)
        if prev_entry is not None and digest == prev_entry.get("sha256"):
            updated_entry = dict(prev_entry)
            updated_entry["mtime_ns"] = mtime_ns
            updated_entry["size"] = size
            return updated_entry, "hash_hit"

        status = "added" if prev_entry is None else "modified"
        return self._parse_file_entry(rel_path, raw_bytes, mtime_ns, size), status

    def _ensure_loaded_or_build(self) -> bool:
        if self._index:
            return True
        if self.index_path.exists() and not self.index_path.is_symlink():
            self.load()
            return True
        return False

    def build(self) -> Dict[str, Any]:
        """Perform a full symlink-confined cold scan and build `RepoIndex/1`."""
        t0 = time.perf_counter()
        files_map: Dict[str, Dict[str, Any]] = {}
        for rel_path in self.walk_files():
            entry, status = self._reconcile_file(rel_path, None, use_stat_fastpath=False)
            if entry is not None and status == "added":
                files_map[rel_path] = entry

        self._index = self._assemble_index(files_map)
        self._last_stats = {
            "mode": "build",
            "total_files": len(files_map),
            "parsed_files": len(files_map),
            "reused_files": 0,
            "added_files": len(files_map),
            "modified_files": 0,
            "deleted_files": 0,
            "skipped_stat_hits": 0,
            "skipped_hash_hits": 0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }
        return self.index

    def update(self, verify_hashes: bool = False) -> Dict[str, Any]:
        """Incrementally rescan the workspace, re-parsing only added or modified files."""
        if not self._ensure_loaded_or_build():
            return self.build()

        t0 = time.perf_counter()
        prev_files: Dict[str, Dict[str, Any]] = self._index.get("files", {})
        current_paths = self.walk_files()
        current_set = set(current_paths)

        next_files: Dict[str, Dict[str, Any]] = {}
        counts = {"added": 0, "modified": 0, "stat_hit": 0, "hash_hit": 0}
        deleted_count = sum(1 for old_path in prev_files if old_path not in current_set)

        for rel_path in current_paths:
            entry, status = self._reconcile_file(
                rel_path, prev_files.get(rel_path), use_stat_fastpath=not verify_hashes
            )
            if entry is not None:
                next_files[rel_path] = entry
                if status in counts:
                    counts[status] += 1

        parsed_count = counts["added"] + counts["modified"]
        reused_count = counts["stat_hit"] + counts["hash_hit"]
        self._index = self._assemble_index(next_files)
        self._last_stats = {
            "mode": "update",
            "total_files": len(next_files),
            "parsed_files": parsed_count,
            "reused_files": reused_count,
            "added_files": counts["added"],
            "modified_files": counts["modified"],
            "deleted_files": deleted_count,
            "skipped_stat_hits": counts["stat_hit"],
            "skipped_hash_hits": counts["hash_hit"],
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }
        return self.index

    def update_from_paths(self, changed_paths: Sequence[str | Path]) -> Dict[str, Any]:
        """Incrementally update the index solely for explicit `changed_paths` without full walk."""
        if not self._ensure_loaded_or_build():
            return self.build()

        t0 = time.perf_counter()
        next_files: Dict[str, Dict[str, Any]] = dict(self._index.get("files", {}))
        counts = {"added": 0, "modified": 0, "deleted": 0, "hash_hit": 0}
        seen_rel: Set[str] = set()

        for raw_path in changed_paths:
            rel_path = self._confine_candidate(raw_path, check_extension=True)
            if rel_path is None or rel_path in seen_rel:
                continue
            seen_rel.add(rel_path)
            entry, status = self._reconcile_file(
                rel_path, next_files.get(rel_path), use_stat_fastpath=False
            )
            if entry is None:
                if rel_path in next_files:
                    del next_files[rel_path]
                    counts["deleted"] += 1
            else:
                next_files[rel_path] = entry
                if status in counts:
                    counts[status] += 1

        parsed_count = counts["added"] + counts["modified"]
        self._index = self._assemble_index(next_files)
        self._last_stats = {
            "mode": "update_from_paths",
            "total_files": len(next_files),
            "parsed_files": parsed_count,
            "reused_files": max(0, len(next_files) - parsed_count),
            "added_files": counts["added"],
            "modified_files": counts["modified"],
            "deleted_files": counts["deleted"],
            "skipped_stat_hits": 0,
            "skipped_hash_hits": counts["hash_hit"],
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }
        return self.index

    def save(self, path: Optional[str | Path] = None) -> Path:
        """Persist `RepoIndex/1` atomically with `assert_not_symlink` and `0600` mode."""
        if not self._index:
            self.build()
        target = self._resolve_index_path(path)
        self._assert_index_path_safe(target)
        atomic_write_json(target, self._index, mode=0o600, indent=2)
        return target

    def load(self, path: Optional[str | Path] = None) -> Dict[str, Any]:
        """Load and validate `RepoIndex/1` from disk using `O_NOFOLLOW` symlink rejection."""
        target = self._resolve_index_path(path)
        self._assert_index_path_safe(target)
        if not target.exists():
            raise FileNotFoundError(f"RepoScout index not found: {target}")

        raw_bytes, _, _ = self._open_confined_fd_with_stat(target, max_bytes=_MAX_INDEX_BYTES)
        payload = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != REPO_INDEX_SCHEMA:
            raise ValueError(f"Invalid RepoScout index schema in {target}")
        raw_files = payload.get("files")
        if not isinstance(raw_files, dict):
            raise ValueError(f"Invalid files map in RepoScout index {target}")

        validated_files: Dict[str, Dict[str, Any]] = {}
        for rel_path, entry in raw_files.items():
            if not isinstance(rel_path, str) or not isinstance(entry, dict):
                raise ValueError("Malformed entry in RepoScout index")
            if not rel_path or "\x00" in rel_path or rel_path.startswith("/") or ".." in Path(rel_path).parts:
                raise ValueError(f"Confined path violation in RepoScout index: {rel_path}")
            if not any(part in self.excluded_dirs for part in Path(rel_path).parts):
                validated_files[rel_path] = entry

        self._index = self._assemble_index(validated_files)
        return self.index

    def load_or_update(self, path: Optional[str | Path] = None) -> Dict[str, Any]:
        """Load cached `RepoIndex/1` if present and incrementally update, else perform cold `build()`."""
        target = self._resolve_index_path(path)
        if target.exists():
            self.load(target)
            return self.update()
        return self.build()

    def find_symbol(self, symbol_name: str) -> List[Dict[str, Any]]:
        """Return matching symbol definition records (file, line span, anchor)."""
        if not self._index:
            self.load_or_update()
        return list(self._index.get("symbol_index", {}).get(symbol_name, []))

    def compute_symbol_ast_hash(self, rel_path: str, symbol_qualname: str) -> Optional[str]:
        """Compute `RepoAstGroundingEngine` alpha-normalized AST quotient hash for a Python symbol."""
        if not self._index:
            self.load_or_update()
        read_res = self._read_confined_bytes(rel_path)
        if read_res is None or Path(rel_path).suffix.lower() != ".py":
            return None
        try:
            tree = ast.parse(read_res[0].decode("utf-8", errors="replace"), filename=rel_path)
        except SyntaxError:
            return None
        target_leaf = symbol_qualname.rsplit(".", 1)[-1]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name == symbol_qualname or node.name == target_leaf:
                    return RepoAstGroundingEngine.compute_alpha_normalized_ast_hash(node)
        return None

    def find_call_sites(
        self,
        target_symbols: Sequence[str],
        *,
        file_filter: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Find call-sites targeting any symbol in `target_symbols`."""
        if not self._index:
            self.load_or_update()
        queries = {q.strip() for q in target_symbols if q and q.strip()}
        if not queries:
            return []

        files_map: Dict[str, Dict[str, Any]] = self._index.get("files", {})
        allowed_files = (
            sorted(f for f in set(file_filter) if f in files_map)
            if file_filter is not None
            else sorted(files_map.keys())
        )
        matches = [
            dict(site)
            for rel_path in allowed_files
            for site in files_map[rel_path].get("call_sites", [])
            if _matched_query_symbols(site, queries)
        ]
        matches.sort(key=lambda s: (s["file"], s["line"], s["caller"], s["target"]))
        return matches

    def map_changed_files_to_tests(
        self,
        changed_files: Sequence[str | Path],
        *,
        changed_symbols: Optional[Sequence[str]] = None,
        max_depth: int = 8,
        max_tests: int = 25,
    ) -> Dict[str, Any]:
        """
        Traverse the reverse dependency graph from `changed_files` to compute minimal ranked
        test targets and matched symbol call-sites.
        """
        if not self._index:
            self.load_or_update()

        files_map: Dict[str, Dict[str, Any]] = self._index.get("files", {})
        rev_deps: Dict[str, List[str]] = self._index.get("reverse_dependencies", {})
        normalized_changed, rejected_paths = self._confine_changed_list(changed_files)
        seed_symbols = self._collect_seed_symbols(normalized_changed, changed_symbols, files_map)
        distances, via_chains = self._traverse_reverse_deps(
            normalized_changed, files_map, rev_deps, max_depth=max_depth
        )

        impacted_ordered = sorted(distances.keys(), key=lambda p: (distances[p], p))
        all_call_sites = self.find_call_sites(sorted(seed_symbols), file_filter=impacted_ordered)
        calls_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for site in all_call_sites:
            calls_by_file.setdefault(site["file"], []).append(site)

        ranked_tests = self._rank_test_targets(
            normalized_changed, impacted_ordered, files_map, distances, via_chains, calls_by_file, seed_symbols
        )
        limited_tests = ranked_tests[: max(1, max_tests)] if max_tests > 0 else ranked_tests

        return {
            "schema": REPO_SCOUT_IMPACT_SCHEMA,
            "manifest_sha": self._index.get("manifest_sha", ""),
            "changed_files": normalized_changed,
            "rejected_paths": rejected_paths,
            "changed_symbols": sorted(seed_symbols),
            "impacted_files": [
                {"path": p, "distance": distances[p], "via": via_chains[p]}
                for p in impacted_ordered
            ],
            "test_targets": limited_tests,
            "recommended_tests": [t["path"] for t in limited_tests],
            "call_sites": all_call_sites,
        }

    def _confine_changed_list(self, changed_files: Sequence[str | Path]) -> Tuple[List[str], List[str]]:
        normalized: List[str] = []
        rejected: List[str] = []
        seen: Set[str] = set()
        for raw_p in changed_files:
            rel_p = self._confine_candidate(raw_p, check_extension=True)
            if rel_p is None:
                rejected.append(str(raw_p))
            elif rel_p not in seen:
                seen.add(rel_p)
                normalized.append(rel_p)
        normalized.sort()
        return normalized, rejected

    @staticmethod
    def _collect_seed_symbols(
        normalized_changed: List[str],
        changed_symbols: Optional[Sequence[str]],
        files_map: Dict[str, Dict[str, Any]],
    ) -> Set[str]:
        explicit = {s.strip() for s in (changed_symbols or ()) if s and s.strip()}
        if explicit:
            return explicit
        seeds: Set[str] = set()
        for ch_file in normalized_changed:
            entry = files_map.get(ch_file)
            if not entry:
                continue
            mod = entry.get("module", "")
            for sym in entry.get("symbols", []):
                s_name = sym["name"]
                if s_name.startswith("__") and s_name.endswith("__"):
                    continue
                seeds.add(s_name)
                if sym["qualname"] != s_name:
                    seeds.add(sym["qualname"])
                if mod:
                    seeds.add(f"{mod}.{sym['qualname']}")
        return seeds

    @staticmethod
    def _traverse_reverse_deps(
        seeds: List[str],
        files_map: Dict[str, Dict[str, Any]],
        rev_deps: Dict[str, List[str]],
        *,
        max_depth: int,
    ) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
        distances: Dict[str, int] = {}
        via_chains: Dict[str, List[str]] = {}
        queue: deque[str] = deque()
        for ch_file in seeds:
            if ch_file in files_map:
                distances[ch_file] = 0
                via_chains[ch_file] = [ch_file]
                queue.append(ch_file)

        steps = 0
        while queue and steps < _MAX_TRAVERSAL_STEPS:
            steps += 1
            current = queue.popleft()
            cur_dist = distances[current]
            if cur_dist >= max_depth:
                continue
            for dependent in rev_deps.get(current, ()):
                if dependent not in distances:
                    distances[dependent] = cur_dist + 1
                    via_chains[dependent] = via_chains[current] + [dependent]
                    queue.append(dependent)

        for impacted_path in list(distances.keys()):
            if Path(impacted_path).name == "conftest.py" and distances[impacted_path] < max_depth:
                conftest_dir = Path(impacted_path).parent
                conftest_dist = distances[impacted_path]
                for cand_path, cand_entry in files_map.items():
                    if cand_entry.get("is_test") and cand_path not in distances:
                        if _is_under_root(Path(cand_path).parent, conftest_dir):
                            distances[cand_path] = conftest_dist + 1
                            via_chains[cand_path] = via_chains[impacted_path] + [cand_path]
        return distances, via_chains

    @staticmethod
    def _rank_test_targets(
        normalized_changed: List[str],
        impacted_ordered: List[str],
        files_map: Dict[str, Dict[str, Any]],
        distances: Dict[str, int],
        via_chains: Dict[str, List[str]],
        calls_by_file: Dict[str, List[Dict[str, Any]]],
        seed_symbols: Set[str],
    ) -> List[Dict[str, Any]]:
        changed_stems = {
            Path(ch).stem.removeprefix("test_").removesuffix("_test")
            for ch in normalized_changed
        }
        ranked: List[Dict[str, Any]] = []
        for path in impacted_ordered:
            entry = files_map.get(path)
            if not entry or not entry.get("is_test"):
                continue
            dist = distances[path]
            file_calls = calls_by_file.get(path, [])
            matched_syms = sorted({
                s for site in file_calls for s in _matched_query_symbols(site, seed_symbols)
            })
            base_score = max(10, 200 - (dist * 45))
            call_bonus = min(80, len(file_calls) * 15) + min(60, len(matched_syms) * 20)
            test_stem = Path(path).stem.removeprefix("test_").removesuffix("_test")
            name_bonus = 25 if test_stem in changed_stems else 0
            reason = "changed_test_file" if dist == 0 else "direct_import" if dist == 1 else f"transitive_hop_{dist}"
            if file_calls:
                reason = f"{reason}+call_site"
            ranked.append({
                "path": path,
                "language": entry["language"],
                "distance": dist,
                "score": base_score + call_bonus + name_bonus,
                "reason": reason,
                "via": via_chains[path],
                "matched_symbols": matched_syms,
                "call_sites": file_calls,
            })
        ranked.sort(key=lambda item: (-item["score"], item["distance"], item["path"]))
        return ranked

    def to_grounding_summary(self) -> Dict[str, Any]:
        """Return a compact summary aligned with `RepoAstGroundingEngine.summary()`."""
        if not self._index:
            self.load_or_update()
        files_map: Dict[str, Dict[str, Any]] = self._index.get("files", {})
        fn_count = sum(
            1
            for entry in files_map.values()
            for sym in entry.get("symbols", [])
            if sym.get("kind") in ("function", "async_function")
        )
        cls_count = sum(
            1
            for entry in files_map.values()
            for sym in entry.get("symbols", [])
            if sym.get("kind") in ("class", "struct", "enum", "trait")
        )
        call_count = sum(len(entry.get("call_sites", [])) for entry in files_map.values())
        return {
            "schema": self._index.get("schema", REPO_INDEX_SCHEMA),
            "target": str(self.repo_root),
            "manifest_sha": self._index.get("manifest_sha", ""),
            "index_digest": self._index.get("index_digest", ""),
            "indexed_files": self._index.get("file_count", 0),
            "test_files_count": len(self._index.get("test_files", [])),
            "functions_count": fn_count,
            "classes_count": cls_count,
            "call_sites_count": call_count,
        }
