#!/usr/bin/env python3
"""Universal Truth Gate for Kintsugi Harness — Cloud Sandbox Edition (v3.1.1).

Fail-closed runtime verification gates using Python 3.9+ stdlib ONLY:
  1. `run_builtin_truth_gate(contract_name="all")` — verifies 4 built-in falsifiable contracts
     (`idempotency`, `decimal_fx`, `erc4626`, `ledger`) from `kintsugi.evolution.contract_ledger`.
  2. `run_custom_truth_gate(broken_file, fixed_file, test_file, *, runner="auto", timeout_s=15)` —
     isolated, resource-capped, anti-reward-hacking verifier for Python (`.py`), Node.js
     (`.js`/`.mjs`/`.cjs`), and SQLite in-memory SQL (`.sql` + Python oracle).

Security invariants:
  - POSIX `dir_fd` + `O_NOFOLLOW` containment (hardened against parent-swap TOCTOU, FIFO-safe,
    1 MiB cap) via `security_io.read_regular_bytes_secure`, plus explicit NUL-byte rejection.
  - Rejects byte-identical broken/fixed files, suffix/runner mismatches, and vacuous oracles.
  - Private inherited pipe FD (`KINTSUGI_VERDICT_FD` popped & marked non-inheritable before oracle
    runs; no nonce in `argv`) delivers the authoritative runner verdict; stdout `KINTSUGI_VERDICT:`
    may only attach optional `property_id` metadata when already matching the private-FD verdict.
  - True 2-process OS-level IPC separation for Python candidates: untrusted candidate code executes
    in a separate isolated worker subprocess (`close_fds=True`, `start_new_session=True`, clean
    minimal env, POSIX `rlimit`, zero access to `KINTSUGI_VERDICT_FD` or oracle `__main__`) behind
    a trusted `candidate.py` JSON-RPC proxy (tagged JSON codec, no `pickle`).
  - Candidate-origin `AssertionError`, `SystemExit` (incl. `sys.exit(0)` / `os._exit(0)`),
    unexpected `SystemExit`, `MemoryError`, and signal kills (`rc < 0`) map to `INFRA_ERROR`,
    blocking reward hacking.
  - Minimal allowlist `env`, `0o700` temp workspace, `start_new_session=True`, POSIX `setrlimit`
    (`CPU`/`FSIZE`/`NOFILE`/`DATA` + Linux `AS` skipped for Node.js which uses
    `--max-old-space-size=256`), bounded `<= 64 KiB` stdout/stderr & `<= 16 KiB` verdict pipe,
    `SIGKILL` process group on timeout, and fail-closed DLP redaction on output tails.
"""

from __future__ import annotations

import ast
import contextlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    import resource
except ImportError:  # pragma: no cover - non-POSIX fallback
    resource = None  # type: ignore[assignment]

BUNDLE_ROOT = Path(__file__).resolve().parent
_SRC_DIR = (
    BUNDLE_ROOT / "src"
    if (BUNDLE_ROOT / "src" / "kintsugi").is_dir()
    else (BUNDLE_ROOT.parent / "src" if (BUNDLE_ROOT.parent / "src" / "kintsugi").is_dir() else BUNDLE_ROOT / "src")
)
for _p in (BUNDLE_ROOT, _SRC_DIR):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
os.environ.setdefault("KINTSUGI_DISABLE_NATIVE", "1")

from security_io import (  # noqa: E402
    MAX_DEFAULT_FILE_BYTES,
    dlp_redact_output,
    read_regular_bytes_secure,
    sha256_bytes,
    strict_json_loads,
)

MAX_TRUTH_GATE_BYTES = min(1024 * 1024, MAX_DEFAULT_FILE_BYTES)
MAX_OUTPUT_BYTES = 64 * 1024
MAX_OUTPUT_HEAD_BYTES = 48 * 1024
MAX_OUTPUT_TAIL_BYTES = 16 * 1024
MAX_VERDICT_PIPE_BYTES = 16 * 1024
MAX_RETURNED_TAIL_CHARS = 400
MAX_SQL_ENV_BYTES = 64 * 1024
MAX_MEM_LIMIT_BYTES = 512 * 1024 * 1024
NODE_RSS_LIMIT_KIB = 384 * 1024
MIN_TIMEOUT_S = 1
MAX_TIMEOUT_S = 60

ISOLATION_LEVEL = "OS_SUBPROCESS_IPC_SAME_UID"
ISOLATION_NOTE = (
    "Candidate runs in separate OS subprocess (close_fds=True, minimal env, rlimits) "
    "under current UID; untrusted code requires an OS container/sandbox"
)

SUPPORTED_RUNNERS = ("auto", "python", "node", "sqlite")
SUFFIX_TO_RUNNER: Dict[str, str] = {".py": "python", ".js": "node", ".mjs": "node", ".cjs": "node", ".sql": "sqlite"}
RUNNER_TO_LANGUAGE: Dict[str, str] = {"python": "python", "node": "javascript", "sqlite": "sql"}
NODE_EXTS = frozenset({".js", ".mjs", ".cjs"})
ORACLE_VERDICT_PREFIX = "KINTSUGI_VERDICT:"
ALLOWED_ORACLE_VERDICTS = frozenset({"EXPECTED_PROPERTY_FAIL", "PROPERTY_PASSED"})
SAFE_MINIMAL_PATH = "/usr/bin:/bin:/usr/local/bin"

_VM_RSS_RE = re.compile(r"^VmRSS:\s*(\d+)\s*kB", re.MULTILINE)
_PEM_BLOCK_RE = re.compile(
    "-----BEG" + r"IN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----E" + r"ND [A-Z0-9 ]*PRIVATE KEY-----|\Z)"
)
_JS_RESERVED_EXPORTS = frozenset(
    {"default", "function", "class", "const", "let", "var", "async", "from", "as", "return", "export", "import"}
)
_JS_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def _redact_and_tail(full_text: str) -> str:
    """DLP-redact FULL output (including multiline PEM blocks) BEFORE truncating to tail chars."""
    if not isinstance(full_text, str) or not full_text:
        return ""
    cleaned = _PEM_BLOCK_RE.sub("[REDACTED_DLP]", full_text)
    redacted = dlp_redact_output(cleaned)
    if len(redacted) <= MAX_RETURNED_TAIL_CHARS:
        return redacted
    return redacted[-MAX_RETURNED_TAIL_CHARS:]


def _reject(status: str, error: str, **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ok": False,
        "status": status,
        "verdict": status,
        "error": error,
        "isolation_level": ISOLATION_LEVEL,
        "isolation_note": ISOLATION_NOTE,
    }
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# Built-in 4 Domain Contracts Truth Gate
# ---------------------------------------------------------------------------


def run_builtin_truth_gate(contract_name: str = "all") -> Dict[str, Any]:
    """Verify live BROKEN (fail on property) vs FIXED (pass all controls) across 4 domain contracts."""
    from kintsugi.evolution.contract_ledger import (
        verify_contract_cm_decimal_fx,
        verify_contract_cm_idempotency,
        verify_contract_mm_erc4626_bounded,
        verify_contract_mm_ledger_conservation,
    )
    from kintsugi.evolution.fast_learner import RuntimeOutcome

    def _summarize(name: str, b_res: Dict[str, Any], f_res: Dict[str, Any]) -> Dict[str, Any]:
        ok = b_res["outcome"] == RuntimeOutcome.EXPECTED_PROPERTY_FAIL and f_res["outcome"] == RuntimeOutcome.PASSED
        return {"contract": name, "truth_gate_passed": ok, "broken": b_res["outcome"].value, "fixed": f_res["outcome"].value}

    def _run_idempotency() -> Dict[str, Any]:
        class BrokenFulfill:
            def __init__(self) -> None:
                self.stock, self.movs = {"SKU-TEE-01": 100}, 0
            def stock_of(self, sku: str) -> int: return self.stock[sku]
            def movements_count(self) -> int: return self.movs
            def fulfill_order(self, key: str, sku: str, qty: int) -> Dict[str, Any]:
                self.stock[sku] -= qty; self.movs += 1
                return {"key": key, "sku": sku, "qty": qty}

        class FixedFulfill:
            def __init__(self) -> None:
                self.stock, self.movs = {"SKU-TEE-01": 100}, 0
                self.seen: Dict[str, Tuple[Tuple[str, int], Dict[str, Any]]] = {}
            def stock_of(self, sku: str) -> int: return self.stock[sku]
            def movements_count(self) -> int: return self.movs
            def fulfill_order(self, key: str, sku: str, qty: int) -> Dict[str, Any]:
                sig = (sku, qty)
                if key in self.seen:
                    prev_sig, receipt = self.seen[key]
                    if prev_sig != sig:
                        raise ValueError("idempotency conflict")
                    return receipt
                self.stock[sku] -= qty; self.movs += 1
                receipt = {"key": key, "sku": sku, "qty": qty, "movement": self.movs}
                self.seen[key] = (sig, receipt)
                return receipt

        return _summarize("CONTRACT-CM-IDEMPOTENCY", verify_contract_cm_idempotency(BrokenFulfill), verify_contract_cm_idempotency(FixedFulfill))

    def _run_decimal_fx() -> Dict[str, Any]:
        def broken_fx(raw_lines: List[str], fx: str) -> Tuple[List[Any], Any]:
            lines = [round(float(r) * float(fx), 2) for r in raw_lines]
            return lines, sum(lines)

        def fixed_fx(raw_lines: List[str], fx: str) -> Tuple[List[Decimal], Decimal]:
            rate = Decimal(str(fx))
            lines = [(Decimal(str(r)) * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) for r in raw_lines]
            return lines, sum(lines, Decimal("0.00"))

        return _summarize("CONTRACT-CM-DECIMAL-FX", verify_contract_cm_decimal_fx(broken_fx), verify_contract_cm_decimal_fx(fixed_fx))

    def _run_erc4626() -> Dict[str, Any]:
        def broken_mint(assets: int, total_shares: int, total_assets: int) -> int:
            return (assets * (total_shares + 10**6)) // (total_assets + 1)

        def fixed_mint(assets: int, total_shares: int, total_assets: int) -> int:
            shares = (assets * (total_shares + 10**6)) // (total_assets + 1)
            if assets > 0 and shares <= 0:
                raise ValueError("zero shares outside precondition")
            return shares

        return _summarize("CONTRACT-MM-ERC4626-BOUNDED", verify_contract_mm_erc4626_bounded(broken_mint), verify_contract_mm_erc4626_bounded(fixed_mint))

    def _run_ledger() -> Dict[str, Any]:
        class BrokenLedger:
            def __init__(self, initial: Dict[str, int]) -> None:
                self._bal = dict(initial)
            def balances(self) -> Dict[str, int]: return dict(self._bal)
            def transfer(self, src: str, dst: str, amount: int) -> None:
                if amount <= 0 or self._bal[src] < amount:
                    raise ValueError("invalid")
                self._bal[src] -= amount
                if src != dst:
                    self._bal[dst] += amount

        class FixedLedger:
            def __init__(self, initial: Dict[str, int]) -> None:
                self._bal = dict(initial)
                self._locks = {k: threading.Lock() for k in initial}
            def balances(self) -> Dict[str, int]: return dict(self._bal)
            def transfer(self, src: str, dst: str, amount: int) -> None:
                if amount <= 0:
                    raise ValueError("amount must be positive")
                if src == dst:
                    with self._locks[src]:
                        if self._bal[src] < amount:
                            raise ValueError("insufficient")
                        return
                first, second = sorted((src, dst))
                with self._locks[first], self._locks[second]:
                    if self._bal[src] < amount:
                        raise ValueError("insufficient")
                    self._bal[src] -= amount; self._bal[dst] += amount

        return _summarize("CONTRACT-MM-LEDGER-CONSERVATION", verify_contract_mm_ledger_conservation(BrokenLedger), verify_contract_mm_ledger_conservation(FixedLedger))

    runners = {"idempotency": _run_idempotency, "decimal_fx": _run_decimal_fx, "erc4626": _run_erc4626, "ledger": _run_ledger}
    if contract_name != "all" and contract_name not in runners:
        return {"ok": False, "status": "UNSUPPORTED_CONTRACT", "error": f"Unknown contract: {contract_name!r}", "contracts": []}
    selected = list(runners.values()) if contract_name == "all" else [runners[contract_name]]
    results = [fn() for fn in selected]
    all_ok = all(r["truth_gate_passed"] for r in results)
    return {"ok": all_ok, "status": "PASS_TRUTH_GATE" if all_ok else "FAILED_TRUTH_GATE", "contracts": results}


# ---------------------------------------------------------------------------
# Anti-Vacuous Oracle Static Inspection Helpers
# ---------------------------------------------------------------------------


def _const_eval_literal(node: ast.AST) -> Tuple[bool, Any]:
    """Return (is_constant, value) for simple constant AST expressions without side effects."""
    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        ok, val = _const_eval_literal(node.operand)
        if ok:
            return True, not bool(val)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        vals = []
        for elt in node.elts:
            ok, v = _const_eval_literal(elt)
            if not ok:
                return False, None
            vals.append(v)
        return True, vals
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        ok_l, vl = _const_eval_literal(node.left)
        ok_r, vr = _const_eval_literal(node.comparators[0])
        if ok_l and ok_r:
            op = node.ops[0]
            if isinstance(op, ast.Eq): return True, vl == vr
            if isinstance(op, ast.NotEq): return True, vl != vr
            if isinstance(op, ast.Is): return True, vl is vr
            if isinstance(op, ast.IsNot): return True, vl is not vr
    return False, None


def _is_trivial_constant_true(expr: ast.AST) -> bool:
    has_dyn = any(
        (isinstance(s, ast.Name) and s.id not in ("True", "False", "None"))
        or isinstance(s, (ast.Call, ast.Attribute, ast.Subscript))
        for s in ast.walk(expr)
    )
    if not has_dyn:
        return True
    ok, val = _const_eval_literal(expr)
    return ok and bool(val)


def _is_assertion_error_raise(node: ast.Raise) -> bool:
    exc = node.exc
    return (isinstance(exc, ast.Name) and exc.id == "AssertionError") or (
        isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id == "AssertionError"
    )


def _inspect_python_oracle_ast(tree: ast.AST, test_text: str, *, is_sqlite: bool) -> Tuple[bool, int, str]:
    """Ensure Python oracle references candidate and contains >= 1 non-vacuous assertion."""
    markers = ("KINTSUGI_CANDIDATE_SQL", "KINTSUGI_CANDIDATE_FILE", "candidate.sql", "sys.argv") if is_sqlite else ("KINTSUGI_CANDIDATE_FILE", "sys.argv")
    refs_candidate = any(m in test_text for m in markers)
    non_trivial_checks = 0

    def _walk(node: ast.AST, in_cond: bool) -> None:
        nonlocal refs_candidate, non_trivial_checks
        if isinstance(node, ast.Import):
            refs_candidate |= any(a.name == "candidate" or a.name.startswith("candidate.") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            refs_candidate |= bool(node.module and (node.module == "candidate" or node.module.startswith("candidate.")))
        elif isinstance(node, ast.Name) and node.id == "candidate":
            refs_candidate = True
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "candidate":
            refs_candidate = True
        elif isinstance(node, ast.Assert):
            if not _is_trivial_constant_true(node.test) or (in_cond and _const_eval_literal(node.test) == (True, False)):
                non_trivial_checks += 1
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr.startswith("assert") and len(attr) > 6:
                if attr == "assertTrue" and node.args and _is_trivial_constant_true(node.args[0]):
                    pass
                elif attr == "assertEqual" and len(node.args) >= 2:
                    ok_a, va = _const_eval_literal(node.args[0])
                    ok_b, vb = _const_eval_literal(node.args[1])
                    if not (ok_a and ok_b and va == vb):
                        non_trivial_checks += 1
                else:
                    non_trivial_checks += 1
        elif isinstance(node, ast.Raise) and in_cond and _is_assertion_error_raise(node):
            non_trivial_checks += 1

        next_cond = in_cond or isinstance(node, (ast.If, ast.Try, ast.ExceptHandler))
        for child in ast.iter_child_nodes(node):
            _walk(child, next_cond)

    _walk(tree, False)
    if not refs_candidate:
        return False, 0, "Oracle test never references candidate module or candidate file"
    if non_trivial_checks < 1:
        return False, 0, "Oracle test contains no non-trivial assertions"
    return True, non_trivial_checks, ""


def _strip_js_comments(source: str) -> str:
    """Remove // and /* ... */ comments while leaving string literals intact."""
    out: List[str] = []
    i, n, in_str = 0, len(source), None
    while i < n:
        ch, nxt = source[i], (source[i + 1] if i + 1 < n else "")
        if in_str is not None:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(nxt); i += 2; continue
            if ch == in_str:
                in_str = None
            i += 1; continue
        if ch in ("'", '"', "`"):
            in_str = ch; out.append(ch); i += 1; continue
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < n and not (source[i] == "*" and source[i + 1] == "/"):
                if source[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2; continue
        out.append(ch); i += 1
    return "".join(out)


_NODE_ASSERT_RE = re.compile(
    r"\b(?:assert(?:\.[A-Za-z0-9_]+)?\s*\(|strictEqual\s*\(|deepStrictEqual\s*\(|"
    r"notStrictEqual\s*\(|throws\s*\(|rejects\s*\(|expect\s*\(|AssertionError\b)"
)
_NODE_TRIVIAL_ASSERT_RE = re.compile(r"^\s*assert(?:\.ok)?\s*\(\s*(?:true|1|'[^']+'|\"[^\"]+\")\s*\)\s*;?\s*$")


def _inspect_node_oracle(test_text: str) -> Tuple[bool, int, str]:
    stripped = _strip_js_comments(test_text)
    if not any(m in stripped for m in ("candidate", "KINTSUGI_CANDIDATE_FILE", "process.argv")):
        return False, 0, "Node oracle never references candidate module or candidate file"
    real_checks = sum(
        1 for ln in stripped.splitlines() if not _NODE_TRIVIAL_ASSERT_RE.match(ln) and _NODE_ASSERT_RE.search(ln)
    )
    if real_checks < 1:
        return False, 0, "Node oracle contains no non-trivial assertions"
    return True, real_checks, ""


# ---------------------------------------------------------------------------
# Trusted Isolated Runner Scripts (Private Verdict FD + Origin Attribution)
# ---------------------------------------------------------------------------


_PY_RUNNER_SOURCE = """import ast, contextlib, importlib.machinery, importlib.util, json, os, sys, traceback, unittest

def _make_verdict_writer():
    raw_fd = os.environ.pop("KINTSUGI_VERDICT_FD", "")
    nonce = os.environ.pop("KINTSUGI_VERDICT_NONCE", "")
    vfd = int(raw_fd) if raw_fd.isdigit() else -1
    if vfd >= 3:
        with contextlib.suppress(OSError):
            os.set_inheritable(vfd, False)
    emitted = [False]
    def _emit(payload, code):
        if emitted[0]:
            raise SystemExit(code)
        emitted[0] = True
        if vfd >= 3:
            out_obj = dict(payload)
            if nonce:
                out_obj["_nonce"] = nonce
            data = (json.dumps(out_obj, separators=(",", ":")) + "\\n").encode("utf-8")
            try:
                view = memoryview(data)
                written = 0
                while written < len(view):
                    n = os.write(vfd, view[written:])
                    if n <= 0:
                        break
                    written += n
            finally:
                with contextlib.suppress(OSError):
                    os.close(vfd)
        raise SystemExit(code)
    return _emit

_EMIT = _make_verdict_writer()
_K_RUNTIME_ASSERTS = [0]

def _hit_assert():
    _K_RUNTIME_ASSERTS[0] += 1

def _same_file(filename, target_real):
    if not filename or not target_real:
        return False
    if filename == target_real:
        return True
    try: return os.path.realpath(filename) == target_real
    except OSError: return False

def _deepest_origin(frames, oracle_real, cand_real):
    for fr in reversed(frames):
        if _same_file(fr.filename, cand_real):
            return "candidate"
        if _same_file(fr.filename, oracle_real):
            return "oracle"
    return "unknown"

def _is_trivial_const_true_ast(expr):
    has_dyn = any(
        (isinstance(s, ast.Name) and s.id not in ("True", "False", "None"))
        or isinstance(s, (ast.Call, ast.Attribute, ast.Subscript))
        for s in ast.walk(expr)
    )
    if has_dyn:
        return False
    if isinstance(expr, ast.Constant):
        return bool(expr.value)
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not) and isinstance(expr.operand, ast.Constant):
        return not bool(expr.operand.value)
    return True

class _AssertInstrumenter(ast.NodeTransformer):
    def visit_Assert(self, node):
        self.generic_visit(node)
        if _is_trivial_const_true_ast(node.test):
            return node
        hit = ast.Expr(value=ast.Call(func=ast.Name(id="__kintsugi_hit_assert__", ctx=ast.Load()), args=[], keywords=[]))
        ast.copy_location(hit, node)
        return [hit, node]

class _InstrumentedOracleLoader(importlib.machinery.SourceFileLoader):
    def source_to_code(self, data, path, *, _optimize=-1):
        tree = ast.parse(data, filename=path)
        tree = _AssertInstrumenter().visit(tree)
        ast.fix_missing_locations(tree)
        return compile(tree, path, "exec", dont_inherit=True, optimize=_optimize)

def _oracle_imports_unittest(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name == "unittest" or a.name.startswith("unittest.") for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module and (node.module == "unittest" or node.module.startswith("unittest.")):
            return True
    return False

def _oracle_uses_sys_argv(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "sys" and node.attr == "argv":
            return True
    return False

def _patch_unittest_runtime(oracle_path):
    for attr in dir(unittest.TestCase):
        if attr.startswith("assert") and len(attr) > 6 and attr != "assert_":
            orig_fn = getattr(unittest.TestCase, attr, None)
            if callable(orig_fn):
                def _make_wrap(fn):
                    def _wrapped(self, *args, **kwargs):
                        _hit_assert()
                        return fn(self, *args, **kwargs)
                    return _wrapped
                setattr(unittest.TestCase, attr, _make_wrap(orig_fn))

    _orig_unittest_main = unittest.main
    def _kintsugi_unittest_main(*args, **kwargs):
        if "argv" not in kwargs and len(args) < 3:
            kwargs["argv"] = [oracle_path]
        kwargs["exit"] = False
        prog = _orig_unittest_main(*args, **kwargs)
        res = getattr(prog, "result", None)
        if res is None:
            _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": "UnittestNoResult", "detail": "unittest.main returned no result", "assertions_run": 0}, 20)
        if res.errors:
            first_tb = str(res.errors[0][1])[:200]
            _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": "UnittestError", "detail": first_tb, "assertions_run": 0}, 20)
        if res.failures:
            first_tb = str(res.failures[0][1])[:200]
            if any(tok in first_tb for tok in ("CandidateAssertionError", "CandidateSystemExit", "_CandidateProcessError")):
                _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": "CandidateErrorInUnittest", "detail": first_tb, "assertions_run": 0}, 20)
            _EMIT({"property_id": "ASSERTION", "verdict": "EXPECTED_PROPERTY_FAIL", "assertions_run": max(1, int(res.testsRun)), "detail": first_tb}, 10)
        if res.wasSuccessful() and int(res.testsRun) >= 1:
            return prog
        _EMIT({"property_id": "NO_ASSERTIONS_EXECUTED", "verdict": "NO_ASSERTIONS_EXECUTED", "assertions_run": 0, "detail": f"unittest ran {getattr(res, 'testsRun', 0)} tests"}, 21)

    unittest.main = _kintsugi_unittest_main

def _main():
    oracle_path, cand_path = sys.argv[1], sys.argv[2]
    oracle_real, cand_real = os.path.realpath(oracle_path), os.path.realpath(cand_path)
    oracle_dir = os.path.dirname(oracle_real)
    if oracle_dir and (not sys.path or sys.path[0] != oracle_dir):
        sys.path.insert(0, oracle_dir)
    with open(oracle_path, "rb") as _fh:
        _raw_oracle = _fh.read()
    _oracle_tree = ast.parse(_raw_oracle, filename=oracle_path)
    if _oracle_imports_unittest(_oracle_tree) and not _oracle_uses_sys_argv(_oracle_tree):
        sys.argv = [oracle_path]
    else:
        sys.argv = [oracle_path, cand_path]
    _patch_unittest_runtime(oracle_path)
    try:
        loader = _InstrumentedOracleLoader("__main__", oracle_path)
        spec = importlib.util.spec_from_loader("__main__", loader, origin=oracle_path)
        mod = importlib.util.module_from_spec(spec)
        mod.__dict__["__kintsugi_hit_assert__"] = _hit_assert
        sys.modules["__main__"] = mod
        loader.exec_module(mod)
    except AssertionError as exc:
        frames = traceback.extract_tb(exc.__traceback__)
        if _deepest_origin(frames, oracle_real, cand_real) != "oracle":
            _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": "CandidateAssertionError", "detail": str(exc)[:200], "assertions_run": 0}, 20)
        _EMIT({"property_id": "ASSERTION", "verdict": "EXPECTED_PROPERTY_FAIL", "assertions_run": max(1, _K_RUNTIME_ASSERTS[0]), "detail": str(exc)[:200]}, 10)
    except SystemExit as exc:
        frames, code = traceback.extract_tb(exc.__traceback__), exc.code
        if any(_same_file(fr.filename, cand_real) for fr in frames):
            _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": "CandidateSystemExit", "detail": repr(code)[:200], "assertions_run": 0}, 20)
        _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": "UnexpectedSystemExit", "detail": repr(code)[:200], "assertions_run": 0}, 20)
    except BaseException as exc:
        _EMIT({"property_id": "INFRA", "verdict": "INFRA_ERROR", "exc_type": type(exc).__name__, "detail": str(exc)[:200], "assertions_run": 0}, 20)
    if _K_RUNTIME_ASSERTS[0] < 1:
        _EMIT({"property_id": "NO_ASSERTIONS_EXECUTED", "verdict": "NO_ASSERTIONS_EXECUTED", "assertions_run": 0, "detail": "Oracle completed with 0 runtime assertions executed"}, 21)
    _EMIT({"property_id": "ASSERTION", "verdict": "PROPERTY_PASSED", "assertions_run": _K_RUNTIME_ASSERTS[0]}, 0)

if __name__ == "__main__":
    _main()
"""

_PY_IPC_CODEC_SNIPPET = """def _make_ipc_codec(b64enc, b64dec, dec_cls, isnan, isinf, on_unknown_encode, on_handle_decode, max_depth=64):
    _isinstance, _type, _str, _bytes, _bytearray = isinstance, type, str, bytes, bytearray
    _bool, _int, _float, _list, _tuple, _set, _frozenset, _dict = bool, int, float, list, tuple, set, frozenset, dict
    _ValueError = ValueError

    def _encode(val, depth=0):
        if depth > max_depth:
            raise _ValueError("IPC_MAX_DEPTH_EXCEEDED")
        if val is None or _isinstance(val, _bool):
            return val
        t = _type(val)
        if t is _int or t is _str:
            return val
        if t is _float:
            if isnan(val):
                return {"__k_t__": "float", "v": "nan"}
            if isinf(val):
                return {"__k_t__": "float", "v": "inf" if val > 0 else "-inf"}
            return val
        if t is _bytes:
            return {"__k_t__": "bytes", "v": b64enc(val).decode("ascii")}
        if t is _bytearray:
            return {"__k_t__": "bytearray", "v": b64enc(_bytes(val)).decode("ascii")}
        if _isinstance(val, dec_cls):
            return {"__k_t__": "decimal", "v": _str(val)}
        if t is _list:
            return [_encode(x, depth + 1) for x in val]
        if t is _tuple:
            return {"__k_t__": "tuple", "v": [_encode(x, depth + 1) for x in val]}
        if t is _set:
            return {"__k_t__": "set", "v": [_encode(x, depth + 1) for x in val]}
        if t is _frozenset:
            return {"__k_t__": "frozenset", "v": [_encode(x, depth + 1) for x in val]}
        if t is _dict:
            if all(_type(k) is _str and not k.startswith("__k_") for k in val):
                return {k: _encode(v, depth + 1) for k, v in val.items()}
            return {"__k_t__": "dict", "v": [[_encode(k, depth + 1), _encode(v, depth + 1)] for k, v in val.items()]}
        return on_unknown_encode(val)

    def _decode(val, depth=0):
        if depth > max_depth:
            raise _ValueError("IPC_MAX_DEPTH_EXCEEDED")
        if _isinstance(val, _list):
            return [_decode(x, depth + 1) for x in val]
        if _isinstance(val, _dict):
            handled = on_handle_decode(val)
            if handled is not None:
                return handled[0]
            tag = val.get("__k_t__")
            if tag == "bytes":
                return b64dec(val["v"].encode("ascii"))
            if tag == "bytearray":
                return _bytearray(b64dec(val["v"].encode("ascii")))
            if tag == "decimal":
                return dec_cls(val["v"])
            if tag == "float":
                return _float(val["v"])
            if tag == "tuple":
                return _tuple(_decode(x, depth + 1) for x in val["v"])
            if tag == "set":
                return {_decode(x, depth + 1) for x in val["v"]}
            if tag == "frozenset":
                return _frozenset(_decode(x, depth + 1) for x in val["v"])
            if tag == "dict":
                return {_decode(k, depth + 1): _decode(v, depth + 1) for k, v in val["v"]}
            return {k: _decode(v, depth + 1) for k, v in val.items()}
        return val

    return _encode, _decode
"""

_PY_CAND_WORKER_TEMPLATE = """import base64, contextlib, decimal, importlib.util, io, json, math, os, queue, signal, sys, threading

_K_MAIN_SENTINEL = object()
__IPC_CODEC__

def _run_worker():
    _os_read, _os_write, _os_exit = os.read, os.write, os._exit
    _os_killpg, _os_getpgrp, _sigkill = getattr(os, "killpg", None), getattr(os, "getpgrp", None), getattr(signal, "SIGKILL", 9)
    _json_dumps, _json_loads = json.dumps, json.loads
    _main_mod, _sentinel, _sys_modules = sys.modules.get("__main__"), _K_MAIN_SENTINEL, sys.modules
    _spec_from_file, _mod_from_spec = importlib.util.spec_from_file_location, importlib.util.module_from_spec
    _AssertionError, _SystemExit, _Exception, _BaseException = AssertionError, SystemExit, Exception, BaseException
    _RuntimeError, _ValueError = RuntimeError, ValueError
    _type, _isinstance, _callable, _getattr, _setattr = type, isinstance, callable, getattr, setattr
    _str, _repr, _len, _bool, _list, _dir, _id, _memoryview = str, repr, len, bool, list, dir, id, memoryview
    _max_ipc, _max_out, _max_handles = 4 * 1024 * 1024, 65536, 4096

    impl_path, timeout_s = sys.argv[1], int(sys.argv[2])
    sys.argv = ["candidate.py"]
    _keep_streams = (sys.stdin, sys.stdout)
    with contextlib.suppress(OSError, ValueError):
        sys.stdout.flush()

    class _OutCap:
        encoding = "utf-8"
        def __init__(self):
            self._parts, self._size = [], 0
        def write(self, s):
            if not _isinstance(s, _str): s = _str(s)
            rem = _max_out - self._size
            if rem > 0 and s:
                chunk = s[:rem]; self._parts.append(chunk); self._size += _len(chunk)
            return _len(s)
        def writelines(self, lines):
            for ln in lines: self.write(ln)
        def flush(self):
            return None
        def isatty(self):
            return False
        def drain(self):
            out = "".join(self._parts); self._parts.clear(); self._size = 0; return out

    _cap = _OutCap()
    sys.stdout = sys.__stdout__ = _cap
    sys.stdin = sys.__stdin__ = io.StringIO("")

    def _kill_self_group():
        if _os_killpg is not None and _os_getpgrp is not None:
            with contextlib.suppress(OSError):
                _os_killpg(_os_getpgrp(), _sigkill)
        _os_exit(137)

    watchdog = threading.Timer(float(timeout_s) + 2.0, _kill_self_group)
    watchdog.daemon = True
    watchdog.start()

    req_q = queue.Queue()
    def _stdin_loop():
        buf = bytearray()
        while True:
            try: chunk = _os_read(0, 4096)
            except OSError: _kill_self_group()
            if not chunk: _kill_self_group()
            buf.extend(chunk)
            if _len(buf) > _max_ipc: _kill_self_group()
            while True:
                nl = buf.find(b"\\n")
                if nl < 0: break
                line = bytes(buf[:nl]); del buf[: nl + 1]; req_q.put(line)

    threading.Thread(target=_stdin_loop, daemon=True).start()

    handles, id_to_hid, next_hid = {}, {}, [1]
    def _reg_handle(obj):
        oid = _id(obj)
        existing = id_to_hid.get(oid)
        if existing is not None and handles.get(existing) is obj:
            return existing
        if _len(handles) >= _max_handles:
            raise _RuntimeError("IPC_HANDLE_LIMIT_EXCEEDED")
        hid = next_hid[0]; next_hid[0] = hid + 1
        handles[hid] = obj; id_to_hid[oid] = hid
        return hid

    def _enc_handle(val):
        return {"__k_handle__": _reg_handle(val), "__k_callable__": _callable(val)}

    def _dec_handle(val):
        if "__k_handle__" not in val:
            return None
        hid = val["__k_handle__"]
        if hid not in handles:
            raise _ValueError(f"UNKNOWN_IPC_HANDLE:{hid}")
        return (handles[hid],)

    _encode, _decode = _make_ipc_codec(
        base64.b64encode, base64.b64decode, decimal.Decimal, math.isnan, math.isinf, _enc_handle, _dec_handle
    )

    def _send(payload):
        raw = (_json_dumps(payload, allow_nan=False, separators=(",", ":")) + "\\n").encode("utf-8")
        if _len(raw) > _max_ipc:
            fb = {"rpc": payload.get("rpc", ""), "id": payload.get("id", 0), "ok": False, "exc_type": "_CandidateProcessError", "exc_msg": "IPC_RESPONSE_TOO_LARGE", "out": ""}
            raw = (_json_dumps(fb, separators=(",", ":")) + "\\n").encode("utf-8")
        view, off = _memoryview(raw), 0
        while off < _len(view):
            try: n = _os_write(1, view[off:])
            except OSError: _kill_self_group()
            if n <= 0: _kill_self_group()
            off += n

    tok, cand_mod = "", None
    while True:
        raw_line = req_q.get()
        try: req = _json_loads(raw_line.decode("utf-8"))
        except _Exception: _kill_self_group()
        req_id, op = req.get("id", 0), req.get("op", "")
        if op == "init" and cand_mod is None:
            tok = _str(req.get("tok", ""))
        elif not tok or req.get("tok") != tok:
            _kill_self_group()

        try:
            if op == "init":
                spec = _spec_from_file("candidate", impl_path)
                if spec is None or spec.loader is None:
                    raise _RuntimeError("CANDIDATE_SPEC_LOAD_FAILED")
                mod = _mod_from_spec(spec)
                _sys_modules["candidate"] = mod
                spec.loader.exec_module(mod)
                cand_mod, res = mod, None
            elif op == "dir":
                res = _list(_dir(cand_mod))
            elif op == "getattr":
                name = req["name"]
                val = _getattr(cand_mod, name)
                res = {"__k_mod_call__": name} if (_callable(val) and not _isinstance(val, _type)) else _encode(val)
            elif op == "call":
                fn = _getattr(cand_mod, req["name"])
                res = _encode(fn(*[_decode(a) for a in req.get("args", [])], **{k: _decode(v) for k, v in req.get("kwargs", {}).items()}))
            elif op == "mod_subgetattr":
                res = _encode(_getattr(_getattr(cand_mod, req["name"]), req["attr"]))
            elif op == "obj_getattr":
                hid, attr = req["hid"], req["attr"]
                val = _getattr(handles[hid], attr)
                res = {"__k_bound__": [hid, attr]} if (_callable(val) and not _isinstance(val, _type)) else _encode(val)
            elif op == "obj_setattr":
                _setattr(handles[req["hid"]], req["attr"], _decode(req["val"])); res = None
            elif op == "obj_call":
                obj, method = handles[req["hid"]], req.get("method")
                target = obj if method is None else _getattr(obj, method)
                res = _encode(target(*[_decode(a) for a in req.get("args", [])], **{k: _decode(v) for k, v in req.get("kwargs", {}).items()}))
            elif op == "obj_len": res = _len(handles[req["hid"]])
            elif op == "obj_repr": res = _repr(handles[req["hid"]])
            elif op == "obj_str": res = _str(handles[req["hid"]])
            elif op == "obj_bool": res = _bool(handles[req["hid"]])
            elif op == "obj_eq": res = _bool(handles[req["hid"]] == _decode(req["other"]))
            elif op == "obj_getitem": res = _encode(handles[req["hid"]][_decode(req["key"])])
            elif op == "obj_contains": res = _bool(_decode(req["item"]) in handles[req["hid"]])
            else:
                raise _RuntimeError(f"UNKNOWN_IPC_OP:{op}")
        except _AssertionError as exc:
            _send({"rpc": tok, "id": req_id, "ok": False, "exc_type": "CandidateAssertionError", "exc_msg": _str(exc)[:200], "out": _cap.drain()})
            continue
        except _SystemExit as exc:
            _send({"rpc": tok, "id": req_id, "ok": False, "exc_type": "CandidateSystemExit", "exc_msg": _repr(exc.code)[:200], "out": _cap.drain()})
            _os_exit(0)
        except _BaseException as exc:
            exc_type = _type(exc).__name__ if _isinstance(exc, _Exception) else "_CandidateProcessError"
            _send({"rpc": tok, "id": req_id, "ok": False, "exc_type": exc_type, "exc_msg": _str(exc)[:200], "out": _cap.drain()})
            continue

        if _main_mod is not None and _main_mod.__dict__.get("_K_MAIN_SENTINEL") is not _sentinel:
            _send({"rpc": tok, "id": req_id, "ok": False, "exc_type": "_CandidateProcessError", "exc_msg": "CandidateMainTamper", "out": _cap.drain()})
            _os_exit(0)

        _send({"rpc": tok, "id": req_id, "ok": True, "val": res, "out": _cap.drain()})
    return _keep_streams

if __name__ == "__main__":
    _run_worker()
"""

_PY_CAND_WORKER_SOURCE = _PY_CAND_WORKER_TEMPLATE.replace("__IPC_CODEC__", _PY_IPC_CODEC_SNIPPET)

_PY_CAND_PROXY_TEMPLATE = """# Trusted Kintsugi IPC proxy module (2-process candidate isolation)

class CandidateAssertionError(BaseException):
    pass

class _CandidateProcessError(BaseException):
    pass

class CandidateSystemExit(_CandidateProcessError):
    pass

def _kintsugi_build_client():
    import atexit, base64, contextlib, decimal, json, math, os, secrets, signal, subprocess, sys, threading
    try:
        import resource
    except ImportError:
        resource = None
__IPC_CODEC_INDENTED__
    _worker_script, _impl_path, _cand_dir = __WORKER_SCRIPT__, __IMPL_PATH__, __CAND_DIR__
    _cand_stdout_log, _timeout_s, _mem_limit = __CAND_STDOUT_LOG__, __TIMEOUT_S__, __MEM_LIMIT__
    _max_ipc, _max_diag_out = 4 * 1024 * 1024, 65536
    _exc_map = {
        "ValueError": ValueError, "TypeError": TypeError, "KeyError": KeyError, "IndexError": IndexError,
        "ZeroDivisionError": ZeroDivisionError, "OverflowError": OverflowError, "RuntimeError": RuntimeError,
        "AttributeError": AttributeError, "StopIteration": StopIteration, "NotImplementedError": NotImplementedError,
        "LookupError": LookupError, "ArithmeticError": ArithmeticError, "InvalidOperation": decimal.InvalidOperation,
        "RecursionError": RecursionError, "MemoryError": MemoryError,
    }

    def _set_clamped(limit_const, soft, hard):
        if resource is None: return
        with contextlib.suppress(ValueError, OSError):
            cur_s, cur_h = resource.getrlimit(limit_const)
            if cur_h != resource.RLIM_INFINITY:
                hard = min(hard, cur_h); soft = min(soft, hard)
            elif cur_s != resource.RLIM_INFINITY:
                soft = min(soft, hard)
            resource.setrlimit(limit_const, (soft, hard))

    def _preexec():
        if resource is None: return
        _set_clamped(resource.RLIMIT_CPU, _timeout_s, _timeout_s + 1)
        _set_clamped(resource.RLIMIT_FSIZE, 8 * 1024 * 1024, 8 * 1024 * 1024)
        _set_clamped(resource.RLIMIT_NOFILE, 64, 64)
        if hasattr(resource, "RLIMIT_DATA"):
            _set_clamped(resource.RLIMIT_DATA, _mem_limit, _mem_limit)
        if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
            _set_clamped(resource.RLIMIT_AS, _mem_limit, _mem_limit)

    class _RemoteObject:
        __slots__ = ("_c", "_hid")
        def __init__(self, client, hid):
            object.__setattr__(self, "_c", client); object.__setattr__(self, "_hid", hid)
        def __getattr__(self, attr):
            if attr.startswith("__") and attr.endswith("__"): raise AttributeError(attr)
            return object.__getattribute__(self, "_c").rpc("obj_getattr", hid=object.__getattribute__(self, "_hid"), attr=attr)
        def __setattr__(self, attr, val):
            c = object.__getattribute__(self, "_c")
            c.rpc("obj_setattr", hid=object.__getattribute__(self, "_hid"), attr=attr, val=c.encode(val))
        def __len__(self): return object.__getattribute__(self, "_c").rpc("obj_len", hid=object.__getattribute__(self, "_hid"))
        def __repr__(self): return object.__getattribute__(self, "_c").rpc("obj_repr", hid=object.__getattribute__(self, "_hid"))
        def __str__(self): return object.__getattribute__(self, "_c").rpc("obj_str", hid=object.__getattribute__(self, "_hid"))
        def __bool__(self): return bool(object.__getattribute__(self, "_c").rpc("obj_bool", hid=object.__getattribute__(self, "_hid")))
        def __eq__(self, other):
            c = object.__getattribute__(self, "_c")
            return bool(c.rpc("obj_eq", hid=object.__getattribute__(self, "_hid"), other=c.encode(other)))
        def __getitem__(self, key):
            c = object.__getattribute__(self, "_c")
            return c.rpc("obj_getitem", hid=object.__getattribute__(self, "_hid"), key=c.encode(key))
        def __contains__(self, item):
            c = object.__getattribute__(self, "_c")
            return bool(c.rpc("obj_contains", hid=object.__getattribute__(self, "_hid"), item=c.encode(item)))

    class _RemoteCallable(_RemoteObject):
        __slots__ = ()
        def __call__(self, *args, **kwargs):
            c = object.__getattribute__(self, "_c")
            return c.rpc("obj_call", hid=object.__getattribute__(self, "_hid"), method=None, args=[c.encode(a) for a in args], kwargs={k: c.encode(v) for k, v in kwargs.items()})

    class _RemoteBoundMethod:
        __slots__ = ("_c", "_hid", "_attr")
        def __init__(self, client, hid, attr): self._c, self._hid, self._attr = client, hid, attr
        def __call__(self, *args, **kwargs):
            return self._c.rpc("obj_call", hid=self._hid, method=self._attr, args=[self._c.encode(a) for a in args], kwargs={k: self._c.encode(v) for k, v in kwargs.items()})

    class _RemoteModuleCallable:
        __slots__ = ("_c", "_name")
        def __init__(self, client, name): self._c, self._name = client, name
        def __call__(self, *args, **kwargs):
            return self._c.rpc("call", name=self._name, args=[self._c.encode(a) for a in args], kwargs={k: self._c.encode(v) for k, v in kwargs.items()})
        def __getattr__(self, attr):
            if attr.startswith("__") and attr.endswith("__"): raise AttributeError(attr)
            return self._c.rpc("mod_subgetattr", name=self._name, attr=attr)

    class _Client:
        def __init__(self):
            self._lock, self._proc, self._tok, self._seq, self._dead, self._diag_written = threading.Lock(), None, secrets.token_hex(16), 0, False, 0
            def _enc_unknown(val):
                if isinstance(val, _RemoteObject):
                    return {"__k_handle__": object.__getattribute__(val, "_hid")}
                raise TypeError(f"UNSUPPORTED_IPC_ARGUMENT_TYPE:{type(val).__name__}")
            def _dec_handle(val):
                if "__k_mod_call__" in val:
                    return (_RemoteModuleCallable(self, val["__k_mod_call__"]),)
                if "__k_bound__" in val:
                    hid, attr = val["__k_bound__"]
                    return (_RemoteBoundMethod(self, hid, attr),)
                if "__k_handle__" in val:
                    hid = val["__k_handle__"]
                    return (_RemoteCallable(self, hid) if val.get("__k_callable__") else _RemoteObject(self, hid),)
                return None
            self.encode, self.decode = _make_ipc_codec(
                base64.b64encode, base64.b64decode, decimal.Decimal, math.isnan, math.isinf, _enc_unknown, _dec_handle
            )
            atexit.register(self.cleanup)

        def cleanup(self):
            proc = self._proc
            if proc is None: return
            self._proc = None
            for st in (proc.stdin, proc.stdout):
                if st is not None:
                    with contextlib.suppress(OSError): st.close()
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                if os.name == "posix": os.killpg(proc.pid, signal.SIGKILL)
                else: proc.kill()
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                proc.wait(timeout=1.0)

        def _ensure_started_locked(self):
            if self._proc is not None: return
            if self._dead: raise _CandidateProcessError("CandidateWorkerTerminated")
            env = {
                "PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": _cand_dir, "TMPDIR": _cand_dir,
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "LC_ALL": "C.UTF-8",
            }
            kwargs = {
                "cwd": _cand_dir, "env": env, "stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
                "stderr": None, "shell": False, "close_fds": True, "start_new_session": True,
            }
            if os.name == "posix" and resource is not None:
                kwargs["preexec_fn"] = _preexec
            self._proc = subprocess.Popen(
                [sys.executable, "-B", _worker_script, _impl_path, str(_timeout_s)], **kwargs
            )
            self._exchange_locked("init", {})

        def _exchange_locked(self, op, fields):
            proc = self._proc
            if proc is None or proc.stdin is None or proc.stdout is None:
                self._dead = True; raise _CandidateProcessError("CandidateWorkerNotRunning")
            self._seq += 1; req_id = self._seq
            msg = {"id": req_id, "tok": self._tok, "op": op}; msg.update(fields)
            raw = (json.dumps(msg, allow_nan=False, separators=(",", ":")) + "\\n").encode("utf-8")
            try:
                proc.stdin.write(raw); proc.stdin.flush()
                line = proc.stdout.readline(_max_ipc + 1)
            except OSError:
                line = b""
            if not line or len(line) > _max_ipc:
                rc = proc.poll()
                if rc is None:
                    with contextlib.suppress(subprocess.TimeoutExpired, OSError): rc = proc.wait(timeout=0.5)
                self._dead = True; self.cleanup()
                if len(line) > _max_ipc: raise _CandidateProcessError("IPC_RESPONSE_TOO_LARGE")
                raise _CandidateProcessError(f"CandidateSystemExit: worker exited (rc={rc})")
            try: resp = json.loads(line.decode("utf-8"))
            except Exception:
                self._dead = True; self.cleanup(); raise _CandidateProcessError("CORRUPT_WORKER_RPC")
            if not isinstance(resp, dict) or resp.get("rpc") != self._tok or resp.get("id") != req_id:
                self._dead = True; self.cleanup(); raise _CandidateProcessError("FORGED_OR_MISMATCHED_WORKER_RPC")
            out_chunk = resp.get("out")
            if isinstance(out_chunk, str) and out_chunk and self._diag_written < _max_diag_out:
                chunk_bytes = out_chunk.encode("utf-8", errors="replace")[: _max_diag_out - self._diag_written]
                if chunk_bytes:
                    self._diag_written += len(chunk_bytes)
                    with contextlib.suppress(OSError):
                        with open(_cand_stdout_log, "ab") as _dfh:
                            _dfh.write(chunk_bytes)
            if not resp.get("ok"):
                et, em = str(resp.get("exc_type") or "_CandidateProcessError"), str(resp.get("exc_msg") or "")
                if et in ("CandidateAssertionError", "AssertionError"): raise CandidateAssertionError(em)
                if et in ("CandidateSystemExit", "SystemExit"):
                    self._dead = True; self.cleanup(); raise CandidateSystemExit(em)
                if et == "_CandidateProcessError":
                    self._dead = True; self.cleanup(); raise _CandidateProcessError(em)
                exc_cls = _exc_map.get(et)
                if exc_cls is not None: raise exc_cls(em)
                raise RuntimeError(f"{et}: {em}")
            try:
                return self.decode(resp.get("val"))
            except Exception as exc:
                self._dead = True; self.cleanup()
                raise _CandidateProcessError(f"IPC_DECODE_ERROR:{type(exc).__name__}")

        def rpc(self, op, **fields):
            with self._lock:
                self._ensure_started_locked()
                return self._exchange_locked(op, fields)

    return _Client()

_kintsugi_ipc = _kintsugi_build_client()
del _kintsugi_build_client
_KINTSUGI_SKIP_DUNDERS = frozenset({"__path__", "__wrapped__", "__pytest_wrapped__", "__orig_bases__", "__mro_entries__", "__test__"})

def __getattr__(name):
    if name in _KINTSUGI_SKIP_DUNDERS:
        raise AttributeError(name)
    return _kintsugi_ipc.rpc("getattr", name=name)

def __dir__():
    return _kintsugi_ipc.rpc("dir")
"""


def _render_py_cand_proxy(
    *,
    worker_script: Path,
    impl_path: Path,
    cand_dir: Path,
    cand_stdout_log: Path,
    timeout_s: int,
) -> str:
    indented_codec = "\n".join(("    " + ln if ln else "") for ln in _PY_IPC_CODEC_SNIPPET.splitlines())
    src = _PY_CAND_PROXY_TEMPLATE.replace("__IPC_CODEC_INDENTED__", indented_codec)
    replacements = {
        "__WORKER_SCRIPT__": repr(str(worker_script)),
        "__IMPL_PATH__": repr(str(impl_path)),
        "__CAND_DIR__": repr(str(cand_dir)),
        "__CAND_STDOUT_LOG__": repr(str(cand_stdout_log)),
        "__TIMEOUT_S__": repr(int(timeout_s)),
        "__MEM_LIMIT__": repr(int(MAX_MEM_LIMIT_BYTES)),
    }
    for key, val in replacements.items():
        src = src.replace(key, val)
    return src


def _parse_js_exports(cand_text: str, ext: str) -> Tuple[bool, List[str], bool]:
    """Statically extract JS/ESM exported names and default-export flag from comment-stripped source."""
    stripped = _strip_js_comments(cand_text)
    if ext == ".mjs":
        is_esm = True
    elif ext == ".cjs":
        is_esm = False
    else:
        is_esm = bool(re.search(r"(?:^|[;\n])\s*export\b", stripped))
    if not is_esm:
        return False, [], False

    named: List[str] = []
    seen = set()
    has_default = bool(re.search(r"\bexport\s+default\b", stripped))

    def _add(name: str) -> None:
        clean = name.strip()
        if clean == "default":
            return
        if clean and clean not in seen and clean not in _JS_RESERVED_EXPORTS and _JS_IDENT_RE.fullmatch(clean):
            seen.add(clean)
            named.append(clean)

    for m in re.finditer(r"\bexport\s+(?:async\s+)?function\s*\*?\s+([A-Za-z_$][A-Za-z0-9_$]*)", stripped):
        _add(m.group(1))
    for m in re.finditer(r"\bexport\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)", stripped):
        _add(m.group(1))
    for m in re.finditer(r"\bexport\s+(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)", stripped):
        _add(m.group(1))
    for m in re.finditer(r"\bexport\s*\{([^}]+)\}", stripped):
        for item in m.group(1).split(","):
            seg = item.strip()
            if not seg:
                continue
            as_m = re.match(r"^[A-Za-z_$][A-Za-z0-9_$]*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)$", seg)
            if as_m:
                alias = as_m.group(1)
                if alias == "default":
                    has_default = True
                else:
                    _add(alias)
            else:
                _add(seg)
    return True, named, has_default


def _rewrite_node_oracle_assert_imports(test_text: str) -> str:
    """Rewrite node:assert / assert imports/requires to our runtime-counting shims preserving line numbers."""
    out = re.sub(
        r"""(\bfrom\s+)(['"])(?:node:)?assert/strict\2""",
        r"\1'./_kintsugi_assert_strict.mjs'",
        test_text,
    )
    out = re.sub(
        r"""(\bfrom\s+)(['"])(?:node:)?assert\2""",
        r"\1'./_kintsugi_assert.mjs'",
        out,
    )
    out = re.sub(
        r"""(\bimport\s*\(\s*)(['"])(?:node:)?assert/strict\2(\s*\))""",
        r"\1'./_kintsugi_assert_strict.mjs'\3",
        out,
    )
    out = re.sub(
        r"""(\bimport\s*\(\s*)(['"])(?:node:)?assert\2(\s*\))""",
        r"\1'./_kintsugi_assert.mjs'\3",
        out,
    )
    out = re.sub(
        r"""(\brequire\s*\(\s*)(['"])(?:node:)?assert/strict\2(\s*\))""",
        r"\1'./_kintsugi_assert_strict.cjs'\3",
        out,
    )
    out = re.sub(
        r"""(\brequire\s*\(\s*)(['"])(?:node:)?assert\2(\s*\))""",
        r"\1'./_kintsugi_assert.cjs'\3",
        out,
    )
    return out


def _make_node_assert_shim_esm(strict_mode: bool) -> str:
    mod_spec = "node:assert/strict" if strict_mode else "node:assert"
    return f"""import realAssert from '{mod_spec}';
const _SYM = Symbol.for('__kintsugi_node_runtime_asserts__');
function _bump() {{
  const box = globalThis[_SYM];
  if (box && typeof box.count === 'number') box.count += 1;
}}
function _wrap(fn) {{
  return function kintsugiAssertWrap(...args) {{
    _bump();
    return fn.apply(this, args);
  }};
}}
const wrapped = _wrap(realAssert);
export const ok = _wrap(realAssert.ok.bind(realAssert));
export const equal = _wrap(realAssert.equal.bind(realAssert));
export const notEqual = _wrap(realAssert.notEqual.bind(realAssert));
export const strictEqual = _wrap(realAssert.strictEqual.bind(realAssert));
export const notStrictEqual = _wrap(realAssert.notStrictEqual.bind(realAssert));
export const deepEqual = _wrap(realAssert.deepEqual.bind(realAssert));
export const notDeepEqual = _wrap(realAssert.notDeepEqual.bind(realAssert));
export const deepStrictEqual = _wrap(realAssert.deepStrictEqual.bind(realAssert));
export const notDeepStrictEqual = _wrap(realAssert.notDeepStrictEqual.bind(realAssert));
export const throws = _wrap(realAssert.throws.bind(realAssert));
export const doesNotThrow = _wrap(realAssert.doesNotThrow.bind(realAssert));
export const rejects = _wrap(realAssert.rejects.bind(realAssert));
export const doesNotReject = _wrap(realAssert.doesNotReject.bind(realAssert));
export const match = _wrap(realAssert.match.bind(realAssert));
export const doesNotMatch = _wrap(realAssert.doesNotMatch.bind(realAssert));
export const ifError = _wrap(realAssert.ifError.bind(realAssert));
export const fail = _wrap(realAssert.fail.bind(realAssert));
export const AssertionError = realAssert.AssertionError;
Object.assign(wrapped, {{
  ok, equal, notEqual, strictEqual, notStrictEqual, deepEqual, notDeepEqual,
  deepStrictEqual, notDeepStrictEqual, throws, doesNotThrow, rejects, doesNotReject,
  match, doesNotMatch, ifError, fail, AssertionError, strict: wrapped,
}});
export const strict = wrapped;
export default wrapped;
"""


def _make_node_assert_shim_cjs(strict_mode: bool) -> str:
    mod_spec = "node:assert/strict" if strict_mode else "node:assert"
    return f"""const realAssert = require('{mod_spec}');
const _SYM = Symbol.for('__kintsugi_node_runtime_asserts__');
function _bump() {{
  const box = globalThis[_SYM];
  if (box && typeof box.count === 'number') box.count += 1;
}}
function _wrap(fn) {{
  return function kintsugiAssertWrap(...args) {{
    _bump();
    return fn.apply(this, args);
  }};
}}
const wrapped = _wrap(realAssert);
for (const k of [
  'ok', 'equal', 'notEqual', 'strictEqual', 'notStrictEqual', 'deepEqual', 'notDeepEqual',
  'deepStrictEqual', 'notDeepStrictEqual', 'throws', 'doesNotThrow', 'rejects', 'doesNotReject',
  'match', 'doesNotMatch', 'ifError', 'fail',
]) {{
  if (typeof realAssert[k] === 'function') wrapped[k] = _wrap(realAssert[k].bind(realAssert));
}}
wrapped.AssertionError = realAssert.AssertionError;
wrapped.strict = wrapped;
module.exports = wrapped;
"""


_NODE_IPC_CODEC_JS = """function _kEncode(v, depth = 0) {
  if (depth > 48) throw new Error('IPC_MAX_DEPTH_EXCEEDED');
  if (v === undefined) return { __k_t__: 'undef' };
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return v;
  if (typeof v === 'number') {
    if (Number.isNaN(v)) return { __k_t__: 'num', v: 'NaN' };
    if (v === Infinity) return { __k_t__: 'num', v: 'Infinity' };
    if (v === -Infinity) return { __k_t__: 'num', v: '-Infinity' };
    if (Object.is(v, -0)) return { __k_t__: 'num', v: '-0' };
    return v;
  }
  if (typeof v === 'bigint') return { __k_t__: 'bigint', v: v.toString() };
  if (Buffer.isBuffer(v)) return { __k_t__: 'buf', v: v.toString('base64') };
  if (v instanceof Uint8Array) return { __k_t__: 'u8', v: Buffer.from(v).toString('base64') };
  if (v instanceof Date) return { __k_t__: 'date', v: v.toISOString() };
  if (v instanceof RegExp) return { __k_t__: 're', s: v.source, f: v.flags };
  if (v instanceof Map) return { __k_t__: 'map', v: Array.from(v.entries(), ([mk, mv]) => [_kEncode(mk, depth + 1), _kEncode(mv, depth + 1)]) };
  if (v instanceof Set) return { __k_t__: 'set', v: Array.from(v.values(), (sv) => _kEncode(sv, depth + 1)) };
  if (Array.isArray(v)) return v.map((x) => _kEncode(x, depth + 1));
  if (typeof v === 'object') {
    const out = {};
    for (const [ok, ov] of Object.entries(v)) out[ok] = _kEncode(ov, depth + 1);
    return out;
  }
  return { __k_t__: 'unencodable', v: String(v) };
}
function _kDecode(v, depth = 0) {
  if (depth > 48) throw new Error('IPC_MAX_DEPTH_EXCEEDED');
  if (v === null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map((x) => _kDecode(x, depth + 1));
  const t = v.__k_t__;
  if (t === 'undef') return undefined;
  if (t === 'num') {
    if (v.v === 'NaN') return Number.NaN;
    if (v.v === 'Infinity') return Infinity;
    if (v.v === '-Infinity') return -Infinity;
    if (v.v === '-0') return -0;
    return Number(v.v);
  }
  if (t === 'bigint') return BigInt(v.v);
  if (t === 'buf') return Buffer.from(v.v, 'base64');
  if (t === 'u8') return new Uint8Array(Buffer.from(v.v, 'base64'));
  if (t === 'date') return new Date(v.v);
  if (t === 're') return new RegExp(v.s, v.f);
  if (t === 'map') return new Map(v.v.map(([mk, mv]) => [_kDecode(mk, depth + 1), _kDecode(mv, depth + 1)]));
  if (t === 'set') return new Set(v.v.map((sv) => _kDecode(sv, depth + 1)));
  const out = {};
  for (const [ok, ov] of Object.entries(v)) out[ok] = _kDecode(ov, depth + 1);
  return out;
}
"""


_NODE_CAND_WORKER_SOURCE = (
    """import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
"""
    + _NODE_IPC_CODEC_JS
    + """
const _writeSync = fs.writeSync.bind(fs);
const _rawIn = fs.readFileSync(0, 'utf8');
const _req = JSON.parse(_rawIn);
const _tok = String(_req.tok || '');
const _implPath = String(_req.implPath || '');
const _ext = String(_req.ext || '.mjs');
const _isCjs = Boolean(_req.isCjs);
process.argv = [process.execPath, 'candidate' + _ext];

let _capOut = '';
const _MAX_OUT = 65536;
const _origStdoutWrite = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk, encoding, cb) => {
  const s = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk);
  if (_capOut.length < _MAX_OUT) _capOut += s.slice(0, _MAX_OUT - _capOut.length);
  if (typeof encoding === 'function') encoding();
  else if (typeof cb === 'function') cb();
  return true;
};

function _send(obj) {
  const payload = Object.assign({ rpc: _tok, out: _capOut }, obj);
  const line = '\\n__K_NODE_RPC__:' + _tok + ':' + JSON.stringify(payload) + '\\n';
  _writeSync(1, line);
}

function _describeExport(val) {
  if (typeof val === 'function') return { kind: 'function' };
  if (val && typeof val === 'object' && !Array.isArray(val) && !Buffer.isBuffer(val) && !(val instanceof Date) && !(val instanceof RegExp) && !(val instanceof Map) && !(val instanceof Set)) {
    const props = {};
    let hasFn = false;
    for (const [k, v] of Object.entries(val)) {
      if (typeof v === 'function') {
        props[k] = { kind: 'function' };
        hasFn = true;
      } else {
        props[k] = { kind: 'value', val: _kEncode(v) };
      }
    }
    if (hasFn) return { kind: 'object', props };
  }
  return { kind: 'value', val: _kEncode(val) };
}

(async () => {
  try {
    const mod = await import(pathToFileURL(_implPath).href);
    const op = _req.op;
    if (op === 'introspect') {
      if (_isCjs) {
        _send({ ok: true, cjs: _describeExport(mod.default) });
        return;
      }
      const exportsDesc = {};
      for (const k of Object.keys(mod)) {
        exportsDesc[k] = _describeExport(mod[k]);
      }
      _send({ ok: true, exports: exportsDesc });
      return;
    }
    const args = Array.isArray(_req.args) ? _req.args.map((a) => _kDecode(a)) : [];
    let ret;
    if (op === 'call') {
      const target = _isCjs
        ? (_req.name === '__cjs_root__' ? mod.default : mod.default[_req.name])
        : mod[_req.name];
      if (typeof target !== 'function') throw new TypeError('EXPORT_NOT_CALLABLE: ' + String(_req.name));
      ret = target(...args);
    } else if (op === 'call_prop') {
      const owner = _isCjs ? mod.default : mod[_req.name];
      if (!owner || typeof owner[_req.prop] !== 'function') throw new TypeError('PROP_NOT_CALLABLE: ' + String(_req.prop));
      ret = owner[_req.prop](...args);
    } else {
      throw new Error('UNKNOWN_NODE_IPC_OP: ' + String(op));
    }
    if (ret && typeof ret.then === 'function') {
      try {
        const awaited = await ret;
        _send({ ok: true, isPromise: true, val: _kEncode(awaited) });
      } catch (asyncErr) {
        const isAssert = Boolean(asyncErr && (asyncErr.code === 'ERR_ASSERTION' || asyncErr.name === 'AssertionError'));
        _send({
          ok: false,
          isPromise: true,
          exc_type: isAssert ? 'CandidateAssertionError' : String((asyncErr && asyncErr.name) || 'Error'),
          exc_msg: String((asyncErr && asyncErr.message) || asyncErr || '').slice(0, 200),
        });
      }
      return;
    }
    _send({ ok: true, isPromise: false, val: _kEncode(ret) });
  } catch (err) {
    const isAssert = Boolean(err && (err.code === 'ERR_ASSERTION' || err.name === 'AssertionError'));
    _send({
      ok: false,
      isPromise: false,
      exc_type: isAssert ? 'CandidateAssertionError' : String((err && err.name) || 'Error'),
      exc_msg: String((err && err.message) || err || '').slice(0, 200),
    });
  }
})();
"""
)


def _render_node_cand_proxy(
    *,
    worker_script: Path,
    impl_path: Path,
    cand_dir: Path,
    cand_stdout_log: Path,
    ext: str,
    is_esm: bool,
    named_exports: Sequence[str],
    has_default: bool,
    timeout_s: int,
) -> str:
    """Render an isolated Node.js candidate proxy forwarding calls over spawnSync JSON-RPC."""
    header = (
        "import crypto from 'node:crypto';\nimport fs from 'node:fs';\nimport { spawnSync } from 'node:child_process';\n"
        if is_esm
        else "const crypto = require('node:crypto');\nconst fs = require('node:fs');\nconst { spawnSync } = require('node:child_process');\n"
    )
    core = (
        header
        + _NODE_IPC_CODEC_JS
        + f"""
const _WORKER = {json.dumps(str(worker_script))};
const _IMPL = {json.dumps(str(impl_path))};
const _CAND_DIR = {json.dumps(str(cand_dir))};
const _CAND_STDOUT_LOG = {json.dumps(str(cand_stdout_log))};
const _EXT = {json.dumps(ext)};
const _IS_CJS = {'false' if is_esm else 'true'};
const _TIMEOUT_MS = {max(1000, int(timeout_s) * 1000)};
const _CLEAN_ENV = {{ PATH: {json.dumps(SAFE_MINIMAL_PATH)}, HOME: _CAND_DIR, TMPDIR: _CAND_DIR, LC_ALL: 'C.UTF-8' }};
let _diagWritten = 0;
const _MAX_DIAG = 65536;

function _appendCandStdout(text) {{
  if (!text || _diagWritten >= _MAX_DIAG) return;
  const buf = Buffer.from(String(text), 'utf8').subarray(0, _MAX_DIAG - _diagWritten);
  if (buf.length > 0) {{
    _diagWritten += buf.length;
    try {{ fs.appendFileSync(_CAND_STDOUT_LOG, buf); }} catch {{}}
  }}
}}

function _makeCandidateErr(name, msg) {{
  const e = new Error(String(msg || name));
  e.name = name;
  e._kintsugiCandidateError = true;
  return e;
}}

function _makeJsErr(name, msg) {{
  const map = {{ TypeError, RangeError, SyntaxError, ReferenceError, URIError, Error }};
  const Ctor = map[name] || Error;
  const e = new Ctor(String(msg || ''));
  e.name = name || 'Error';
  return e;
}}

function _rpc(op, extra) {{
  const tok = crypto.randomBytes(16).toString('hex');
  const req = Object.assign({{ tok, op, implPath: _IMPL, ext: _EXT, isCjs: _IS_CJS }}, extra || {{}});
  const res = spawnSync(process.execPath, ['--max-old-space-size=256', _WORKER], {{
    cwd: _CAND_DIR,
    env: _CLEAN_ENV,
    stdio: ['pipe', 'pipe', 'pipe'],
    input: JSON.stringify(req),
    encoding: 'utf8',
    timeout: _TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
    killSignal: 'SIGKILL',
  }});
  if (res.stderr) {{
    try {{ process.stderr.write(res.stderr); }} catch {{}}
  }}
  if (res.error && res.error.code === 'ETIMEDOUT') {{
    throw _makeCandidateErr('_CandidateProcessError', 'CandidateWorkerTimeout');
  }}
  const marker = '__K_NODE_RPC__:' + tok + ':';
  const rawOut = String(res.stdout || '');
  let resp = null;
  let extraOut = '';
  for (const line of rawOut.split('\\n')) {{
    const idx = line.indexOf(marker);
    if (idx >= 0) {{
      if (idx > 0) extraOut += line.slice(0, idx) + '\\n';
      try {{ resp = JSON.parse(line.slice(idx + marker.length)); }} catch {{ resp = null; }}
    }} else if (line) {{
      extraOut += line + '\\n';
    }}
  }}
  if (extraOut) _appendCandStdout(extraOut);
  if (!resp || resp.rpc !== tok) {{
    throw _makeCandidateErr('CandidateSystemExit', 'worker exited without valid RPC (status=' + res.status + ', signal=' + res.signal + ')');
  }}
  if (resp.out) _appendCandStdout(resp.out);
  if (!resp.ok) {{
    const et = String(resp.exc_type || '_CandidateProcessError');
    const em = String(resp.exc_msg || '');
    if (et === 'CandidateAssertionError' || et === 'CandidateSystemExit' || et === '_CandidateProcessError') {{
      const ce = _makeCandidateErr(et, em);
      if (resp.isPromise) return Promise.reject(ce);
      throw ce;
    }}
    const je = _makeJsErr(et, em);
    if (resp.isPromise) return Promise.reject(je);
    throw je;
  }}
  if (op === 'introspect') return resp;
  const decoded = _kDecode(resp.val);
  return resp.isPromise ? Promise.resolve(decoded) : decoded;
}}

function _bindDescriptor(exportName, desc) {{
  if (!desc) return undefined;
  if (desc.kind === 'function') {{
    return (...args) => _rpc('call', {{ name: exportName, args: args.map((a) => _kEncode(a)) }});
  }}
  if (desc.kind === 'object' && desc.props) {{
    const obj = {{}};
    for (const [pk, pd] of Object.entries(desc.props)) {{
      if (pd.kind === 'function') {{
        obj[pk] = (...args) => _rpc('call_prop', {{ name: exportName, prop: pk, args: args.map((a) => _kEncode(a)) }});
      }} else {{
        obj[pk] = _kDecode(pd.val);
      }}
    }}
    return obj;
  }}
  return _kDecode(desc.val);
}}

const _meta = _rpc('introspect', {{}});
"""
    )
    if not is_esm:
        return core + "module.exports = _bindDescriptor('__cjs_root__', _meta.cjs);\n"

    lines = [core]
    for name in named_exports:
        lines.append(f"export const {name} = _bindDescriptor({json.dumps(name)}, (_meta.exports || {{}})[{json.dumps(name)}]);\n")
    if has_default:
        lines.append("const __k_default_export = _bindDescriptor('default', (_meta.exports || {})['default']);\n")
        lines.append("export default __k_default_export;\n")
    return "".join(lines)


_NODE_RUNNER_SOURCE = """import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const _ASSERT_SYM = Symbol.for('__kintsugi_node_runtime_asserts__');
globalThis[_ASSERT_SYM] = { count: 0 };

const emit = (() => {
  const rawFd = process.env.KINTSUGI_VERDICT_FD || '';
  delete process.env.KINTSUGI_VERDICT_FD;
  const nonce = process.env.KINTSUGI_VERDICT_NONCE || '';
  delete process.env.KINTSUGI_VERDICT_NONCE;
  let vfd = /^\\d+$/.test(rawFd) ? Number.parseInt(rawFd, 10) : -1;
  // Swap verdict FD to an O_CLOEXEC FD so spawned candidate workers NEVER inherit it!
  if (Number.isInteger(vfd) && vfd >= 3) {
    for (const fdPath of [`/dev/fd/${vfd}`, `/proc/self/fd/${vfd}`]) {
      try {
        const cloexecFd = fs.openSync(fdPath, 'w');
        fs.closeSync(vfd);
        vfd = cloexecFd;
        break;
      } catch {}
    }
  }
  let settled = false;
  return function emitVerdict(payload, code) {
    if (settled) return;
    settled = true;
    if (Number.isInteger(vfd) && vfd >= 3) {
      const outObj = nonce ? Object.assign({}, payload, { _nonce: nonce }) : payload;
      const buf = Buffer.from(JSON.stringify(outObj) + '\\n', 'utf8');
      try {
        let off = 0;
        while (off < buf.length) {
          const n = fs.writeSync(vfd, buf, off, buf.length - off);
          if (n <= 0) break;
          off += n;
        }
      } finally {
        try { fs.closeSync(vfd); } catch {}
      }
    }
    process.exit(code);
  };
})();

const oraclePath = process.argv[2];
const candPath = process.argv[3];
const oracleReal = fs.realpathSync(oraclePath);
const candReal = fs.realpathSync(candPath);
const oracleRefs = [oracleReal, oraclePath, pathToFileURL(oracleReal).href, pathToFileURL(oraclePath).href, path.basename(oraclePath)];
const candRefs = [candReal, candPath, pathToFileURL(candReal).href, pathToFileURL(candPath).href, path.basename(candPath)];
process.argv = [process.execPath, oraclePath, candPath];

function getRuntimeAsserts() {
  const box = globalThis[_ASSERT_SYM];
  return box && typeof box.count === 'number' ? box.count : 0;
}

function originFromStack(err) {
  const raw = String((err && err.stack) || '');
  const msg = String((err && err.message) || '');
  const idx = msg ? raw.indexOf(msg) : -1;
  const body = idx >= 0 ? raw.slice(idx + msg.length) : raw;
  for (const line of body.split('\\n')) {
    const t = line.trim();
    if (
      !t.startsWith('at ')
      || t.includes('(node:')
      || t.includes(' node:')
      || t.includes('_kintsugi_node_runner.mjs')
      || t.includes('_kintsugi_assert')
    ) continue;
    if (candRefs.some((r) => r && t.includes(r))) return 'candidate';
    if (oracleRefs.some((r) => r && t.includes(r))) return 'oracle';
  }
  return 'unknown';
}

function classifyError(err) {
  const detail = String((err && err.message) || err || '').slice(0, 200);
  if (err && err._kintsugiCandidateError) {
    emit({ property_id: 'INFRA', verdict: 'INFRA_ERROR', exc_type: String(err.name || '_CandidateProcessError'), detail, assertions_run: 0 }, 20);
  }
  if (err && (err.code === 'ERR_ASSERTION' || err.name === 'AssertionError')) {
    if (originFromStack(err) !== 'oracle') {
      emit({ property_id: 'INFRA', verdict: 'INFRA_ERROR', exc_type: 'CandidateAssertionError', detail, assertions_run: 0 }, 20);
    }
    emit({ property_id: 'ASSERTION', verdict: 'EXPECTED_PROPERTY_FAIL', assertions_run: Math.max(1, getRuntimeAsserts()), detail }, 10);
  }
  emit({ property_id: 'INFRA', verdict: 'INFRA_ERROR', exc_type: String((err && err.name) || 'Error'), detail, assertions_run: 0 }, 20);
}

let oracleLoaded = false;
let unhandledCount = 0;

process.on('uncaughtException', classifyError);
process.on('unhandledRejection', (reason) => {
  unhandledCount += 1;
  classifyError(reason instanceof Error ? reason : new Error(String(reason)));
});

process.on('beforeExit', () => {
  if (!oracleLoaded) return;
  if (unhandledCount > 0) {
    emit({ property_id: 'INFRA', verdict: 'INFRA_ERROR', exc_type: 'UnhandledRejection', detail: 'Unhandled promise rejection during oracle run', assertions_run: 0 }, 20);
  }
  if (process.exitCode && process.exitCode !== 0) {
    emit({ property_id: 'INFRA', verdict: 'INFRA_ERROR', exc_type: `ExitCode(${process.exitCode})`, assertions_run: 0 }, 20);
  }
  const ran = getRuntimeAsserts();
  if (ran < 1) {
    emit({ property_id: 'NO_ASSERTIONS_EXECUTED', verdict: 'NO_ASSERTIONS_EXECUTED', assertions_run: 0, detail: 'Oracle completed with 0 runtime assertions executed' }, 21);
  }
  emit({ property_id: 'ASSERTION', verdict: 'PROPERTY_PASSED', assertions_run: ran }, 0);
});

try {
  await import(pathToFileURL(oraclePath).href);
  oracleLoaded = true;
} catch (err) {
  classifyError(err);
}
"""


def _set_rlimit_clamped(limit_const: int, soft: int, hard: int) -> None:
    if resource is None:
        return
    with contextlib.suppress(ValueError, OSError):
        cur_soft, cur_hard = resource.getrlimit(limit_const)
        if cur_hard != resource.RLIM_INFINITY:
            hard = min(hard, cur_hard)
            soft = min(soft, hard)
        elif cur_soft != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(limit_const, (soft, hard))


def _make_preexec_rlimits(timeout_s: int, nofile_limit: int, *, apply_rlimit_as: bool = True) -> Any:
    def _apply() -> None:
        if resource is None:
            return
        _set_rlimit_clamped(resource.RLIMIT_CPU, timeout_s, timeout_s + 1)
        _set_rlimit_clamped(resource.RLIMIT_FSIZE, 8 * 1024 * 1024, 8 * 1024 * 1024)
        _set_rlimit_clamped(resource.RLIMIT_NOFILE, nofile_limit, nofile_limit)
        if apply_rlimit_as:
            if hasattr(resource, "RLIMIT_DATA"):
                _set_rlimit_clamped(resource.RLIMIT_DATA, MAX_MEM_LIMIT_BYTES, MAX_MEM_LIMIT_BYTES)
            if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
                _set_rlimit_clamped(resource.RLIMIT_AS, MAX_MEM_LIMIT_BYTES, MAX_MEM_LIMIT_BYTES)

    return _apply


def _bounded_pipe_reader(stream: Any, result_box: Dict[str, Any]) -> None:
    """Drain stream into <= 64 KiB RAM (48 KiB head + 16 KiB rolling tail if truncated)."""
    head, tail, truncated = bytearray(), bytearray(), False
    try:
        with contextlib.suppress(OSError):
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                if not truncated and len(head) + len(chunk) <= MAX_OUTPUT_BYTES:
                    head.extend(chunk)
                else:
                    if not truncated:
                        truncated = True
                        tail.extend(bytes(head[MAX_OUTPUT_HEAD_BYTES:]))
                        del head[MAX_OUTPUT_HEAD_BYTES:]
                    tail.extend(chunk)
                    if len(tail) > MAX_OUTPUT_TAIL_BYTES:
                        del tail[: len(tail) - MAX_OUTPUT_TAIL_BYTES]
    finally:
        with contextlib.suppress(OSError):
            stream.close()
    result_box["data"] = (bytes(head) + b"\n...[TRUNCATED]...\n" + bytes(tail)) if truncated else bytes(head)
    result_box["truncated"] = truncated


def _bounded_verdict_reader(stream: Any, result_box: Dict[str, Any]) -> None:
    """Read bounded private verdict pipe (<= 16 KiB); flag overflow fail-closed."""
    buf, overflow = bytearray(), False
    try:
        with contextlib.suppress(OSError):
            while True:
                chunk = stream.read(4096)
                if not chunk:
                    break
                if len(buf) + len(chunk) > MAX_VERDICT_PIPE_BYTES:
                    overflow = True
                    break
                buf.extend(chunk)
    finally:
        with contextlib.suppress(OSError):
            stream.close()
    result_box["data"] = bytes(buf)
    result_box["overflow"] = overflow


def _read_proc_rss_kib(pid: int) -> int:
    """Read total VmRSS (KiB) for `pid` and its direct children on Linux `/proc`."""
    pids = [pid]
    task_dir = Path(f"/proc/{pid}/task")
    with contextlib.suppress(OSError):
        for t_entry in os.scandir(str(task_dir)):
            with contextlib.suppress(OSError):
                raw_ch = Path(t_entry.path, "children").read_text(encoding="ascii", errors="ignore")
                for tok in raw_ch.split():
                    if tok.isdigit():
                        pids.append(int(tok))
    total_kib = 0
    for p in set(pids):
        with contextlib.suppress(OSError):
            txt = Path(f"/proc/{p}/status").read_text(encoding="ascii", errors="ignore")
            m = _VM_RSS_RE.search(txt)
            if m:
                total_kib += int(m.group(1))
    return total_kib


def _run_bounded_subprocess(
    cmd: Sequence[str],
    *,
    cwd: str,
    env: Dict[str, str],
    timeout_s: int,
    nofile_limit: int = 64,
    apply_rlimit_as: bool = True,
) -> Tuple[int, str, str, str, bool, bool, bool, str]:
    """Run subprocess with private verdict pipe FD, nonce, POSIX rlimits, Linux RSS watchdog, and SIGKILL group."""
    r_fd, w_fd = os.pipe()
    w_closed = False
    r_stream: Optional[Any] = None
    verdict_nonce = secrets.token_hex(16)
    try:
        child_env = dict(env)
        child_env["KINTSUGI_VERDICT_FD"] = str(w_fd)
        child_env["KINTSUGI_VERDICT_NONCE"] = verdict_nonce
        popen_kwargs: Dict[str, Any] = {
            "cwd": cwd, "env": child_env, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
            "stdin": subprocess.DEVNULL, "shell": False, "start_new_session": True, "pass_fds": (w_fd,),
        }
        if os.name == "posix" and resource is not None:
            popen_kwargs["preexec_fn"] = _make_preexec_rlimits(
                timeout_s, max(nofile_limit, w_fd + 32), apply_rlimit_as=apply_rlimit_as
            )
        proc = subprocess.Popen(list(cmd), **popen_kwargs)
        os.close(w_fd)
        w_closed = True
        r_stream = os.fdopen(r_fd, "rb")
    except BaseException:
        if not w_closed:
            with contextlib.suppress(OSError): os.close(w_fd)
        if r_stream is not None:
            with contextlib.suppress(OSError): r_stream.close()
        else:
            with contextlib.suppress(OSError): os.close(r_fd)
        raise

    out_box: Dict[str, Any] = {"data": b"", "truncated": False}
    err_box: Dict[str, Any] = {"data": b"", "truncated": False}
    ver_box: Dict[str, Any] = {"data": b"", "overflow": False}
    threads = [
        threading.Thread(target=_bounded_pipe_reader, args=(proc.stdout, out_box), daemon=True),
        threading.Thread(target=_bounded_pipe_reader, args=(proc.stderr, err_box), daemon=True),
        threading.Thread(target=_bounded_verdict_reader, args=(r_stream, ver_box), daemon=True),
    ]
    for t in threads:
        t.start()

    rss_exceeded = [False]
    rss_stop = threading.Event()
    rss_thread: Optional[threading.Thread] = None
    if (not apply_rlimit_as) and sys.platform.startswith("linux"):
        def _rss_watchdog() -> None:
            while not rss_stop.wait(0.05):
                if proc.poll() is not None:
                    return
                if _read_proc_rss_kib(proc.pid) > NODE_RSS_LIMIT_KIB:
                    rss_exceeded[0] = True
                    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    return

        rss_thread = threading.Thread(target=_rss_watchdog, daemon=True)
        rss_thread.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            proc.wait(timeout=2)
    finally:
        rss_stop.set()
        if rss_thread is not None:
            rss_thread.join(timeout=1.0)
        for t in threads:
            t.join(timeout=1.5)

    rc = 124 if timed_out else (proc.returncode if proc.returncode is not None else 1)
    out_text = out_box["data"].decode("utf-8", errors="replace")
    err_text = err_box["data"].decode("utf-8", errors="replace") or ("TRUTH_GATE_TIMEOUT" if timed_out else "")
    if rss_exceeded[0] and "RSS_LIMIT_EXCEEDED" not in err_text:
        err_text = (err_text + "\nRSS_LIMIT_EXCEEDED").strip()
    ver_text = ver_box["data"].decode("utf-8", errors="replace")
    return rc, out_text, err_text, ver_text, bool(ver_box["overflow"]), timed_out, bool(rss_exceeded[0]), verdict_nonce


def _parse_verdict_json(raw_json: str, *, allow_infra: bool) -> Optional[Dict[str, Any]]:
    try:
        obj = strict_json_loads(raw_json)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    prop_id, verdict, asserts = obj.get("property_id"), obj.get("verdict"), obj.get("assertions_run")
    if not isinstance(prop_id, str) or not (1 <= len(prop_id.strip()) <= 128):
        return None
    allowed = ALLOWED_ORACLE_VERDICTS | ({"INFRA_ERROR", "NO_ASSERTIONS_EXECUTED"} if allow_infra else set())
    if not isinstance(verdict, str) or verdict not in allowed:
        return None
    if not isinstance(asserts, int) or isinstance(asserts, bool):
        return None
    if (verdict in ALLOWED_ORACLE_VERDICTS and asserts < 1) or (verdict in ("INFRA_ERROR", "NO_ASSERTIONS_EXECUTED") and asserts < 0):
        return None
    return {
        "property_id": prop_id.strip(), "verdict": verdict, "assertions_run": asserts,
        "exc_type": str(obj.get("exc_type") or ""), "detail": str(obj.get("detail") or ""),
        "_nonce": str(obj.get("_nonce") or ""),
    }


def _extract_run_verdict(
    verdict_pipe_text: str,
    verdict_overflow: bool,
    stdout_text: str,
    rc: int,
    timed_out: bool,
    oracle_declares_verdict_tag: bool,
    *,
    rss_exceeded: bool = False,
    expected_nonce: str = "",
) -> Tuple[str, str, int, bool, bool]:
    """Extract authoritative private-FD runner verdict; stdout may only attach matching `property_id`."""
    if rss_exceeded:
        return "INFRA_ERROR", "RSS_LIMIT_EXCEEDED", 0, True, False
    if timed_out:
        return "TIMEOUT", "TIMEOUT", 0, True, False
    if rc < 0:
        return "INFRA_ERROR", f"SIGNAL_{-rc}", 0, True, False
    if verdict_overflow:
        return "INFRA_ERROR", "VERDICT_PIPE_OVERFLOW", 0, True, False

    pipe_lines = [ln.strip() for ln in verdict_pipe_text.splitlines() if ln.strip()]
    if len(pipe_lines) != 1:
        return "INFRA_ERROR", "MISSING_RUNNER_VERDICT", 0, True, False
    runner_verdict = _parse_verdict_json(pipe_lines[0], allow_infra=True)
    if runner_verdict is None:
        return "INFRA_ERROR", "INVALID_RUNNER_VERDICT", 0, True, False
    if expected_nonce and runner_verdict.get("_nonce") != expected_nonce:
        return "INFRA_ERROR", "FORGED_VERDICT_NONCE", 0, True, False

    r_ver = runner_verdict["verdict"]
    if r_ver == "NO_ASSERTIONS_EXECUTED":
        return "NO_ASSERTIONS_EXECUTED", "NO_ASSERTIONS_EXECUTED", 0, True, False
    if r_ver == "INFRA_ERROR":
        return "INFRA_ERROR", runner_verdict["property_id"], 0, True, False
    if (r_ver == "PROPERTY_PASSED" and rc != 0) or (r_ver == "EXPECTED_PROPERTY_FAIL" and rc == 0):
        return "INFRA_ERROR", "EXIT_CODE_MISMATCH", 0, True, False

    prop_id, attached_explicit = runner_verdict["property_id"], False
    if oracle_declares_verdict_tag and r_ver in ALLOWED_ORACLE_VERDICTS:
        for raw_line in stdout_text.splitlines():
            line = raw_line.strip()
            if line.startswith(ORACLE_VERDICT_PREFIX):
                parsed = _parse_verdict_json(line[len(ORACLE_VERDICT_PREFIX) :].strip(), allow_infra=False)
                if parsed is not None and parsed["verdict"] == r_ver:
                    prop_id, attached_explicit = parsed["property_id"], True
    return r_ver, prop_id, runner_verdict["assertions_run"], False, attached_explicit


# ---------------------------------------------------------------------------
# Custom Hardened Multi-Language Truth Gate
# ---------------------------------------------------------------------------


def run_custom_truth_gate(
    broken_file: Path,
    fixed_file: Path,
    test_file: Path,
    *,
    runner: str = "auto",
    timeout_s: int = 15,
) -> Dict[str, Any]:
    """Run an isolated oracle test against broken_file (must fail on property) and fixed_file (must pass)."""
    runner_norm = (runner or "auto").strip().lower()
    if runner_norm not in SUPPORTED_RUNNERS:
        return _reject("UNSUPPORTED_RUNNER", f"UNSUPPORTED_RUNNER: {runner!r} (expected one of {SUPPORTED_RUNNERS})")
    if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or not (MIN_TIMEOUT_S <= timeout_s <= MAX_TIMEOUT_S):
        return _reject("REJECTED_TRUTH_GATE", f"INVALID_TIMEOUT: timeout_s must be int in {MIN_TIMEOUT_S}..{MAX_TIMEOUT_S}")

    b_path, f_path, t_path = Path(broken_file), Path(fixed_file), Path(test_file)
    b_ext, f_ext, t_ext = b_path.suffix.lower(), f_path.suffix.lower(), t_path.suffix.lower()
    if b_ext != f_ext:
        return _reject("UNSUPPORTED_RUNNER", f"SUFFIX_MISMATCH: broken ({b_ext!r}) != fixed ({f_ext!r})")

    inferred = SUFFIX_TO_RUNNER.get(b_ext)
    if runner_norm == "auto":
        if inferred is None:
            return _reject("UNSUPPORTED_RUNNER", f"UNSUPPORTED_FILE_SUFFIX: {b_ext!r} (supported: .py, .js, .mjs, .cjs, .sql)")
        resolved_runner = inferred
    else:
        if inferred != runner_norm:
            return _reject("UNSUPPORTED_RUNNER", f"RUNNER_SUFFIX_MISMATCH: runner={runner_norm!r} incompatible with suffix {b_ext!r}")
        resolved_runner = runner_norm

    if resolved_runner in ("python", "sqlite") and t_ext != ".py":
        return _reject("UNSUPPORTED_RUNNER", f"ORACLE_SUFFIX_MISMATCH: runner={resolved_runner!r} requires .py oracle, got {t_ext!r}", runner=resolved_runner)
    if resolved_runner == "node" and t_ext not in NODE_EXTS:
        return _reject("UNSUPPORTED_RUNNER", f"ORACLE_SUFFIX_MISMATCH: runner='node' requires .js/.mjs/.cjs oracle, got {t_ext!r}", runner=resolved_runner)

    node_bin: Optional[str] = None
    if resolved_runner == "node":
        node_bin = shutil.which("node")
        if not node_bin:
            return _reject("UNSUPPORTED_RUNNER", "NODE_RUNTIME_NOT_AVAILABLE: 'node' binary not found on PATH", runner="node")

    verified_language = RUNNER_TO_LANGUAGE[resolved_runner]

    try:
        broken_bytes = read_regular_bytes_secure(b_path, max_bytes=MAX_TRUTH_GATE_BYTES)
        fixed_bytes = read_regular_bytes_secure(f_path, max_bytes=MAX_TRUTH_GATE_BYTES)
        test_bytes = read_regular_bytes_secure(t_path, max_bytes=MAX_TRUTH_GATE_BYTES)
    except (OSError, PermissionError, ValueError) as exc:
        return _reject("REJECTED_TRUTH_GATE", dlp_redact_output(str(exc)), runner=resolved_runner, verified_language=verified_language)

    broken_sha, fixed_sha, test_sha = sha256_bytes(broken_bytes), sha256_bytes(fixed_bytes), sha256_bytes(test_bytes)
    base_hashes = {
        "runner": resolved_runner, "verified_language": verified_language,
        "broken_sha256": broken_sha, "fixed_sha256": fixed_sha, "test_sha256": test_sha,
    }

    for label, raw_b in (("broken", broken_bytes), ("fixed", fixed_bytes), ("test", test_bytes)):
        if b"\x00" in raw_b:
            return _reject("REJECTED_TRUTH_GATE", "NUL_BYTE_IN_INPUT", broken_setup_error=True, detail=f"NUL byte in {label}", **base_hashes)
    if broken_sha == fixed_sha:
        return _reject("REJECTED_TRUTH_GATE", "IDENTICAL_BROKEN_AND_FIXED", **base_hashes)

    try:
        broken_text, fixed_text, test_text = broken_bytes.decode("utf-8"), fixed_bytes.decode("utf-8"), test_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return _reject("REJECTED_TRUTH_GATE", f"UTF8_DECODE_ERROR: {exc}", broken_setup_error=True, **base_hashes)
    if not broken_text.strip() or not fixed_text.strip() or not test_text.strip():
        return _reject("REJECTED_TRUTH_GATE", "EMPTY_TRUTH_GATE_INPUT", broken_setup_error=True, **base_hashes)

    for label, text in (("broken", broken_text), ("fixed", fixed_text)):
        if (
            ORACLE_VERDICT_PREFIX in text
            or "KINTSUGI_RUNNER_VERDICT_" in text
            or "KINTSUGI_VERDICT_FD" in text
            or "KINTSUGI_VERDICT_NONCE" in text
        ):
            return _reject("REJECTED_TRUTH_GATE", f"CANDIDATE_SPOOFED_VERDICT_MARKER_IN_{label.upper()}", broken_setup_error=True, **base_hashes)

    oracle_declares_verdict_tag = ORACLE_VERDICT_PREFIX in test_text
    if resolved_runner == "python":
        parsed_trees: Dict[str, ast.AST] = {}
        for label, src in (("broken", broken_text), ("fixed", fixed_text), ("test", test_text)):
            try:
                parsed_trees[label] = ast.parse(src, filename=f"{label}.py")
            except (SyntaxError, IndentationError, TabError) as exc:
                return _reject("REJECTED_TRUTH_GATE", f"PARSE_ERROR_IN_{label.upper()}: {exc}", broken_setup_error=True, **base_hashes)
        oracle_ok, _static_checks, oracle_err = _inspect_python_oracle_ast(parsed_trees["test"], test_text, is_sqlite=False)
    elif resolved_runner == "sqlite":
        try:
            test_tree = ast.parse(test_text, filename="test.py")
        except (SyntaxError, IndentationError, TabError) as exc:
            return _reject("REJECTED_TRUTH_GATE", f"PARSE_ERROR_IN_TEST: {exc}", broken_setup_error=True, **base_hashes)
        oracle_ok, _static_checks, oracle_err = _inspect_python_oracle_ast(test_tree, test_text, is_sqlite=True)
    else:
        oracle_ok, _static_checks, oracle_err = _inspect_node_oracle(test_text)

    if not oracle_ok:
        return _reject("VACUOUS_ORACLE_REJECTED", f"VACUOUS_ORACLE_REJECTED: {oracle_err}", **base_hashes)

    def _exec_candidate(cand_bytes: bytes, cand_text: str) -> Dict[str, Any]:
        run_dir = tempfile.mkdtemp(prefix="kintsugi_tg_")
        try:
            os.chmod(run_dir, 0o700)
            run_path = Path(run_dir)
            oracle_copy = run_path / f"_oracle_test{t_ext}"
            cand_stdout_log = run_path / "_cand_stdout.log"

            if resolved_runner == "node":
                oracle_copy.write_text(_rewrite_node_oracle_assert_imports(test_text), encoding="utf-8")
                for fname, body in (
                    ("_kintsugi_assert_strict.mjs", _make_node_assert_shim_esm(True)),
                    ("_kintsugi_assert.mjs", _make_node_assert_shim_esm(False)),
                    ("_kintsugi_assert_strict.cjs", _make_node_assert_shim_cjs(True)),
                    ("_kintsugi_assert.cjs", _make_node_assert_shim_cjs(False)),
                ):
                    sp = run_path / fname
                    sp.write_text(body, encoding="utf-8")
                    os.chmod(str(sp), 0o600)
            else:
                oracle_copy.write_bytes(test_bytes)
            os.chmod(str(oracle_copy), 0o600)

            if resolved_runner == "python":
                cand_dir = run_path / "_cand_proc"
                cand_dir.mkdir(mode=0o700)
                os.chmod(str(cand_dir), 0o700)
                cand_impl = cand_dir / "_candidate_impl.py"
                cand_worker = cand_dir / "_candidate_worker.py"
                cand_copy = run_path / "candidate.py"
                cand_impl.write_bytes(cand_bytes)
                cand_worker.write_text(_PY_CAND_WORKER_SOURCE, encoding="utf-8")
                cand_copy.write_text(
                    _render_py_cand_proxy(
                        worker_script=cand_worker,
                        impl_path=cand_impl,
                        cand_dir=cand_dir,
                        cand_stdout_log=cand_stdout_log,
                        timeout_s=timeout_s,
                    ),
                    encoding="utf-8",
                )
                os.chmod(str(cand_impl), 0o600)
                os.chmod(str(cand_worker), 0o600)
                os.chmod(str(cand_copy), 0o600)
            elif resolved_runner == "node":
                cand_dir = run_path / "_cand_proc"
                cand_dir.mkdir(mode=0o700)
                os.chmod(str(cand_dir), 0o700)
                cand_impl = cand_dir / f"_candidate_impl{b_ext}"
                cand_worker = cand_dir / "_node_cand_worker.mjs"
                cand_copy = run_path / f"candidate{b_ext}"
                cand_impl.write_bytes(cand_bytes)
                cand_worker.write_text(_NODE_CAND_WORKER_SOURCE, encoding="utf-8")
                is_esm, named_exports, has_default = _parse_js_exports(cand_text, b_ext)
                cand_copy.write_text(
                    _render_node_cand_proxy(
                        worker_script=cand_worker,
                        impl_path=cand_impl,
                        cand_dir=cand_dir,
                        cand_stdout_log=cand_stdout_log,
                        ext=b_ext,
                        is_esm=is_esm,
                        named_exports=named_exports,
                        has_default=has_default,
                        timeout_s=timeout_s,
                    ),
                    encoding="utf-8",
                )
                os.chmod(str(cand_impl), 0o600)
                os.chmod(str(cand_worker), 0o600)
                os.chmod(str(cand_copy), 0o600)
            else:
                cand_copy = run_path / f"candidate{b_ext}"
                cand_copy.write_bytes(cand_bytes)
                os.chmod(str(cand_copy), 0o600)

            env: Dict[str, str] = {
                "PATH": SAFE_MINIMAL_PATH, "HOME": run_dir, "TMPDIR": run_dir, "PYTHONPATH": run_dir,
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                "KINTSUGI_CANDIDATE_FILE": str(cand_copy), "LC_ALL": "C.UTF-8",
            }
            if resolved_runner == "sqlite" and len(cand_bytes) <= MAX_SQL_ENV_BYTES:
                env["KINTSUGI_CANDIDATE_SQL"] = cand_text

            if resolved_runner in ("python", "sqlite"):
                runner_script = run_path / "_kintsugi_py_runner.py"
                runner_script.write_text(_PY_RUNNER_SOURCE, encoding="utf-8")
                os.chmod(str(runner_script), 0o600)
                cmd = [sys.executable, "-B", str(runner_script), str(oracle_copy), str(cand_copy)]
            else:
                assert node_bin is not None
                runner_script = run_path / "_kintsugi_node_runner.mjs"
                runner_script.write_text(_NODE_RUNNER_SOURCE, encoding="utf-8")
                os.chmod(str(runner_script), 0o600)
                cmd = [
                    node_bin, "--max-old-space-size=256",
                    str(runner_script), str(oracle_copy), str(cand_copy),
                ]

            rc, out_full, err_full, ver_full, ver_overflow, timed_out, rss_exceeded, verdict_nonce = _run_bounded_subprocess(
                cmd, cwd=run_dir, env=env, timeout_s=timeout_s, nofile_limit=64,
                apply_rlimit_as=(resolved_runner != "node"),
            )
            # Candidate stdout is kept strictly isolated from oracle stdout scanned for KINTSUGI_VERDICT metadata.
            cand_out = ""
            if cand_stdout_log.is_file() and not cand_stdout_log.is_symlink():
                with contextlib.suppress(OSError):
                    cand_out = cand_stdout_log.read_bytes()[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
            verdict, prop_id, asserts_run, is_setup_err, explicit = _extract_run_verdict(
                ver_full,
                ver_overflow,
                out_full,
                rc,
                timed_out,
                oracle_declares_verdict_tag,
                rss_exceeded=rss_exceeded,
                expected_nonce=verdict_nonce,
            )
            diag_stdout = (out_full + ("\n" + cand_out if (out_full and cand_out) else cand_out))
            return {
                "rc": rc, "verdict": verdict, "property_id": prop_id, "assertions_run": asserts_run,
                "setup_error": is_setup_err, "explicit": explicit, "timed_out": timed_out,
                "stdout": diag_stdout, "stderr": err_full,
            }
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    b_run = _exec_candidate(broken_bytes, broken_text)
    f_run = _exec_candidate(fixed_bytes, fixed_text)

    prop_match = bool(b_run["property_id"]) and (b_run["property_id"] == f_run["property_id"])
    broken_ok = (
        b_run["verdict"] == "EXPECTED_PROPERTY_FAIL"
        and b_run["assertions_run"] >= 1
        and b_run["rc"] > 0
        and not b_run["setup_error"]
        and not b_run["timed_out"]
    )
    fixed_ok = (
        f_run["verdict"] == "PROPERTY_PASSED"
        and f_run["assertions_run"] >= 1
        and f_run["rc"] == 0
        and not f_run["setup_error"]
        and not f_run["timed_out"]
    )
    verified = broken_ok and fixed_ok and prop_match

    error_reason = ""
    if not verified:
        if b_run["timed_out"] or f_run["timed_out"]:
            error_reason = "TRUTH_GATE_TIMEOUT"
        elif b_run["setup_error"]:
            error_reason = f"BROKEN_INFRA_ERROR: {b_run['verdict']} ({b_run['property_id']})"
        elif not broken_ok:
            error_reason = f"BROKEN_DID_NOT_FAIL_PROPERTY: got {b_run['verdict']}"
        elif not fixed_ok:
            error_reason = f"FIXED_DID_NOT_PASS_PROPERTY: got {f_run['verdict']} ({f_run['property_id']}, rc={f_run['rc']})"
        elif not prop_match:
            error_reason = f"PROPERTY_ID_MISMATCH: broken={b_run['property_id']!r} vs fixed={f_run['property_id']!r}"

    final_verdict = "PROMOTE_ELIGIBLE" if verified else "REJECTED_TRUTH_GATE"
    result: Dict[str, Any] = {
        "ok": verified, "status": final_verdict, "verdict": final_verdict, **base_hashes,
        "isolation_level": ISOLATION_LEVEL, "isolation_note": ISOLATION_NOTE,
        "broken_rc": b_run["rc"], "broken_verdict": b_run["verdict"], "broken_property_id": b_run["property_id"],
        "broken_assertions_run": b_run["assertions_run"], "broken_setup_error": b_run["setup_error"],
        "fixed_rc": f_run["rc"], "fixed_verdict": f_run["verdict"], "fixed_property_id": f_run["property_id"],
        "fixed_assertions_run": f_run["assertions_run"],
        "broken_stderr": _redact_and_tail(b_run["stderr"]),
        "fixed_stdout": _redact_and_tail(f_run["stdout"]),
        "fixed_stderr": _redact_and_tail(f_run["stderr"]),
    }
    if error_reason:
        result["error"] = dlp_redact_output(error_reason)
    return result
