"""
Neuro-Symbolic AST Symbol Grounding Gate & Cross-Boundary Seam Detector (`kintsugi ground`).

Distilled from production multi-agent security & verification brains:
1. Computes a deterministic SHA-256 repository manifest (`manifest_sha`) to prevent commit-drift.
2. Extracts a multi-language Symbol Table (`functions`, `classes`, `variables`, excluding language keywords)
   and detects cross-layer trust-boundary seams (`FILE_PATH_CONCAT_SEAM`, `PRIVILEGE_DICT_MERGE_SEAM`,
   `TENANT_UNSCOPED_CACHE_SEAM`, `DYNAMIC_EXEC_OR_EVAL`, `RAW_TEMPLATE_OR_HTML_RENDER`).
3. Evaluates agent hypotheses through a <5ms 3-State Grounding Gate (`VERIFIED` / `REFUTED` / `UNKNOWN`),
   immediately refuting hallucinated file paths, line numbers, or non-existent symbols.
"""

from __future__ import annotations

import ast
import hashlib
import keyword
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

LANGUAGE_KEYWORDS: Set[str] = set(keyword.kwlist) | {
    "true", "false", "null", "none", "undefined", "var", "let", "const",
    "function", "return", "async", "await", "import", "from", "export",
    "default", "class", "interface", "type", "public", "private", "protected",
    "static", "struct", "impl", "fn", "mut", "pub", "use", "mod", "match",
}


class RepoAstGroundingEngine:
    """
    Deterministic AST & Seam Extractor + 3-State Grounding Gate (`VERIFIED`, `REFUTED`, `UNKNOWN`).
    Prevents Commit Drift via SHA-256 Manifest and blocks Symbol Hallucination in <5ms.
    """

    def __init__(self, target_path: str | Path) -> None:
        self.target_path = Path(target_path).resolve()
        self.files: List[Path] = self._collect_files()
        self.manifest_sha: str = self._compute_manifest_sha()
        self.symbol_table: Dict[str, Any] = {
            "manifest_sha": self.manifest_sha,
            "functions": {},
            "classes": {},
            "variables": set(),
            "file_lines": {},
            "seams": [],
            "guards": {},
        }
        self._build_index()

    def _collect_files(self) -> List[Path]:
        if self.target_path.is_file():
            return [self.target_path]
        exts = {".py", ".js", ".ts", ".sol", ".go", ".rs", ".java", ".php", ".gtl", ".html"}
        excluded = {".git", ".kintsugi", "__pycache__", "node_modules", "target", ".venv", "venv"}
        out: List[Path] = []
        for p in sorted(self.target_path.rglob("*")):
            if p.is_file() and p.suffix.lower() in exts and not ( excluded & set(p.parts) ):
                out.append(p)
        return out

    def _compute_manifest_sha(self) -> str:
        h = hashlib.sha256()
        for f in self.files:
            rel = self._rel(f)
            h.update(rel.encode("utf-8"))
            try:
                h.update(f.read_bytes())
            except OSError:
                continue
        return h.hexdigest()[:16]

    def _rel(self, f: Path) -> str:
        return str(f.relative_to(self.target_path)) if self.target_path.is_dir() else f.name

    def _build_index(self) -> None:
        seam_patterns = [
            ("FILE_PATH_CONCAT_SEAM", re.compile(r"\bopen\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*")),
            ("PRIVILEGE_DICT_MERGE_SEAM", re.compile(r"\b[A-Za-z0-9_]*(?:profile|user|account|record|data)[A-Za-z0-9_]*\.(?:update|setdefault)\s*\(")),
            ("TENANT_UNSCOPED_CACHE_SEAM", re.compile(r"\b(?:redis|cache)\.(?:get|set)\(\s*f?['\"](?!tenant:)[^'\"]*record:")),
            ("DYNAMIC_EXEC_OR_EVAL", re.compile(r"(?<!\.)\b(?:eval|exec|compile)\s*\(|\bos\.system\s*\(")),
            ("RAW_TEMPLATE_OR_HTML_RENDER", re.compile(r"(?:innerHTML|document\.write|dangerouslySetInnerHTML)")),
        ]
        guard_regex = re.compile(
            r"\b(?:if\s+not\s+|if\s+.*==|require\(|assert\s+|is_relative_to|compare_digest|SafeLoader|weights_only=True)\b"
        )

        for f in self.files:
            rel = self._rel(f)
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            self.symbol_table["file_lines"][rel] = lines

            current_func: Optional[str] = None
            for idx, line in enumerate(lines, start=1):
                m_def = re.match(r"^\s*(?:async\s+def|def|function|fn)\s+([A-Za-z_][A-Za-z0-9_]*)", line)
                if m_def:
                    current_func = m_def.group(1)
                anchor = f"{rel}:{idx}"
                if guard_regex.search(line):
                    self.symbol_table["guards"][anchor] = line.strip()[:140]
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//") or "re.compile(" in stripped:
                    continue
                if current_func is None and f.suffix.lower() in {".py", ".js", ".ts", ".go", ".rs"}:
                    continue
                for seam_kind, rgx in seam_patterns:
                    if rgx.search(line):
                        self.symbol_table["seams"].append(
                            {
                                "seam_id": f"seam_{len(self.symbol_table['seams']) + 1:03d}",
                                "kind": seam_kind,
                                "function": current_func or "module_scope",
                                "anchor": anchor,
                                "code": stripped[:140],
                            }
                        )

            for idx, line in enumerate(lines, start=1):
                for m_fn in re.finditer(r"\b(?:def|function|fn)\s+([A-Za-z_][A-Za-z0-9_]*)", line):
                    self.symbol_table["functions"].setdefault(m_fn.group(1), []).append(f"{rel}:{idx}")
                for m_cls in re.finditer(r"\b(?:class|contract|interface|struct)\s+([A-Za-z_][A-Za-z0-9_]*)", line):
                    self.symbol_table["classes"].setdefault(m_cls.group(1), []).append(f"{rel}:{idx}")

            for tok in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b", text):
                if tok not in LANGUAGE_KEYWORDS and tok.lower() not in LANGUAGE_KEYWORDS:
                    self.symbol_table["variables"].add(tok)

            if f.suffix.lower() == ".py":
                try:
                    tree = ast.parse(text)
                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            loc = f"{rel}:{node.lineno}"
                            lst = self.symbol_table["functions"].setdefault(node.name, [])
                            if loc not in lst:
                                lst.append(loc)
                        elif isinstance(node, ast.ClassDef):
                            loc = f"{rel}:{node.lineno}"
                            lst = self.symbol_table["classes"].setdefault(node.name, [])
                            if loc not in lst:
                                lst.append(loc)
                        elif isinstance(node, ast.Name) and node.id not in LANGUAGE_KEYWORDS:
                            self.symbol_table["variables"].add(node.id)
                        elif isinstance(node, ast.Attribute) and node.attr not in LANGUAGE_KEYWORDS:
                            self.symbol_table["variables"].add(node.attr)
                except SyntaxError:
                    continue

    def get_code_window(self, rel_file: str, line_no: int, radius: int = 8) -> str:
        lines = self.symbol_table["file_lines"].get(rel_file, [])
        if not lines:
            return ""
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        return "\n".join(f"{rel_file}:{ln}: {lines[ln - 1]}" for ln in range(start, end + 1))

    def verify_hypothesis(
        self,
        hyp: Dict[str, Any],
        expected_manifest_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Deterministic 3-State Grounding Gate (`VERIFIED`, `REFUTED`, `UNKNOWN`).
        1. Checks manifest SHA consistency (blocks Commit Drift).
        2. Checks that cited `anchor` (`file:line`) and `symbols` exist in `SYMBOL_TABLE` (excluding keywords).
        3. Evaluates code window around anchor to verify symbol presence.
        """
        t0 = time.perf_counter()
        if expected_manifest_sha and expected_manifest_sha != self.manifest_sha:
            return {
                "status": "REFUTED",
                "reason": f"COMMIT_DRIFT_MISMATCH: expected={expected_manifest_sha} actual={self.manifest_sha}",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        anchor = str(hyp.get("anchor") or "").strip()
        if ":" not in anchor:
            return {
                "status": "REFUTED",
                "reason": f"INVALID_ANCHOR_FORMAT: '{anchor}' (must be file:line)",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        rel_file, line_str = anchor.rsplit(":", 1)
        try:
            line_no = int(line_str)
        except ValueError:
            return {
                "status": "REFUTED",
                "reason": f"NON_INTEGER_LINE: '{anchor}'",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        file_lines = self.symbol_table["file_lines"].get(rel_file)
        if not file_lines or line_no < 1 or line_no > len(file_lines):
            return {
                "status": "REFUTED",
                "reason": f"HALLUCINATED_FILE_OR_LINE: '{anchor}' does not exist in repo index",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        known_all: Set[str] = (
            set(self.symbol_table["functions"].keys())
            | set(self.symbol_table["classes"].keys())
            | set(self.symbol_table["variables"])
        )
        cited_symbols = [
            str(s).strip()
            for s in (hyp.get("symbols") or [])
            if str(s).strip() and str(s).strip().lower() not in LANGUAGE_KEYWORDS
        ]
        if not cited_symbols:
            return {
                "status": "REFUTED",
                "reason": "EMPTY_OR_KEYWORD_ONLY_SYMBOLS: Hypothesis must pin >=1 real non-keyword symbol",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        missing_syms = [s for s in cited_symbols if s not in known_all]
        if missing_syms:
            return {
                "status": "REFUTED",
                "reason": f"HALLUCINATED_SYMBOL: {missing_syms} not found in AST SYMBOL_TABLE",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        window_text = self.get_code_window(rel_file, line_no, radius=10)
        if not any(sym in window_text for sym in cited_symbols):
            return {
                "status": "UNKNOWN",
                "reason": f"SYMBOL_NOT_IN_LOCAL_WINDOW: {cited_symbols} exist in repo but not within +/-10 lines of {anchor}",
                "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            }

        return {
            "status": "VERIFIED",
            "reason": f"GROUNDED_IN_AST_AND_WINDOW ({anchor}, symbols={cited_symbols})",
            "manifest_sha": self.manifest_sha,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
            "evidence_window": window_text,
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "target": str(self.target_path),
            "manifest_sha": self.manifest_sha,
            "indexed_files": len(self.files),
            "functions_count": len(self.symbol_table["functions"]),
            "classes_count": len(self.symbol_table["classes"]),
            "variables_count": len(self.symbol_table["variables"]),
            "seams_detected": len(self.symbol_table["seams"]),
            "seams": self.symbol_table["seams"][:25],
            "guards_detected": len(self.symbol_table["guards"]),
        }
