"""Self-Evolution Engine v2 (`kintsugi.evolution_v2`): FailureEnvelope/1, RuleIR/1, counterfactual validation, parity, and ledger consolidation."""

from __future__ import annotations

import ast
import hashlib
import json
import random
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from kintsugi.hooks import _is_dangerous_rm_target, evaluate_claude_pre_tool_payload
from kintsugi.models import GoldenScar, Severity
from kintsugi.scanner import KintsugiScanner
from kintsugi.shield import assert_not_symlink, atomic_write_text

ALLOWED_PREDICATE_KINDS = frozenset({"ast_pattern", "path_policy", "bounded_regex"})
PROTECTED_BASELINE_IDS = frozenset(f"KS-{i:03d}" for i in range(1, 25))
DEFAULT_TRUSTED_SEED = 20261121

_REDACT_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"AIza[A-Za-z0-9_-]{20,}"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._-]{16,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"/Users/[A-Za-z0-9._-]+"), "/Users/<redacted>"),
)


def _canonical_sha256(obj: Any) -> str:
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def redact_sensitive_text(text: str) -> Tuple[str, bool]:
    """Scrub secret tokens, private keys, and local user paths before persisting traces."""
    out = text
    changed = False
    for pat, repl in _REDACT_PATTERNS:
        new_out, count = pat.subn(repl, out)
        if count > 0:
            out = new_out
            changed = True
    return out, changed


@dataclass(frozen=True)
class FailureEnvelope:
    """Immutable content-addressed record of an observed failure (`FailureEnvelope/1`)."""

    trace_id: str
    task_id: str
    language: str
    context: Dict[str, Any]
    observation: Dict[str, Any]
    expected: Dict[str, Any]
    split: str = "private_heldout"
    consent: str = "local_only"
    secrets_redacted: bool = True
    offending_snippet: str = ""
    fixed_snippet: str = ""
    schema: str = "FailureEnvelope/1"

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        language: str,
        offending_snippet: str,
        fixed_snippet: str,
        error_summary: str,
        tool: str = "agent.code_check",
        split: str = "private_heldout",
        consent: str = "local_only",
    ) -> "FailureEnvelope":
        bad_clean, r1 = redact_sensitive_text(offending_snippet.strip())
        good_clean, r2 = redact_sensitive_text(fixed_snippet.strip())
        summary_clean, r3 = redact_sensitive_text(error_summary.strip())
        core = {
            "task_id": task_id,
            "language": language.lower(),
            "tool": tool,
            "summary": summary_clean,
            "bad": bad_clean,
            "good": good_clean,
        }
        trace_id = f"sha256:{_canonical_sha256(core)}"
        return cls(
            trace_id=trace_id,
            task_id=task_id,
            language=language.lower(),
            context={"tool": tool, "file_hash": f"sha256:{hashlib.sha256(bad_clean.encode('utf-8')).hexdigest()}"},
            observation={"summary": summary_clean, "actual": "MISSED"},
            expected={"decision": "DENY", "oracle_source": "verified_fix"},
            split=split,
            consent=consent,
            secrets_redacted=bool(r1 or r2 or r3 or True),
            offending_snippet=bad_clean,
            fixed_snippet=good_clean,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuleIR:
    """Declarative cross-engine rule intermediate representation (`RuleIR/1`)."""

    rule_id: str
    revision: int
    language: List[str]
    severity: str
    predicate_kind: str
    match: Dict[str, Any]
    conditions: Dict[str, Any] = field(default_factory=lambda: {"inside_string_literal": False})
    response: Dict[str, Any] = field(default_factory=lambda: {"decision": "DENY", "reason_code": "EVOLVED_GUARD"})
    source_trace_ids: List[str] = field(default_factory=list)
    negative_corpus_digest: str = ""
    rule_hash: str = ""
    provenance: Dict[str, Any] = field(default_factory=lambda: {"synthesizer": "ast-ir-v2", "human_approved": False})
    schema: str = "RuleIR/1"

    def __post_init__(self) -> None:
        if not self.rule_hash:
            self.rule_hash = self.compute_rule_hash()

    def compute_rule_hash(self) -> str:
        core = {
            "language": sorted(self.language),
            "severity": self.severity,
            "predicate_kind": self.predicate_kind,
            "match": self.match,
            "conditions": self.conditions,
            "response": self.response,
        }
        return f"sha256:{_canonical_sha256(core)}"

    def validate(self) -> None:
        if self.schema != "RuleIR/1":
            raise ValueError(f"Unsupported RuleIR schema: {self.schema}")
        if not self.rule_id or "/" in self.rule_id or "\\" in self.rule_id:
            raise ValueError(f"Invalid RuleIR rule_id: {self.rule_id}")
        if self.predicate_kind not in ALLOWED_PREDICATE_KINDS:
            raise ValueError(f"Unsupported RuleIR predicate_kind: {self.predicate_kind}")
        if self.predicate_kind == "bounded_regex":
            pat = str(self.match.get("regex", ""))
            if not pat or len(pat) > 350:
                raise ValueError("Invalid bounded_regex pattern length")
            re.compile(pat)
        expected_hash = self.compute_rule_hash()
        if self.rule_hash != expected_hash:
            raise ValueError(f"RuleIR hash mismatch: {self.rule_hash} != {expected_hash}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleIR":
        rule = cls(
            schema=str(data.get("schema", "RuleIR/1")),
            rule_id=str(data["rule_id"]),
            revision=int(data.get("revision", 1)),
            language=list(data.get("language") or ["python"]),
            severity=str(data.get("severity", "HIGH")),
            predicate_kind=str(data["predicate_kind"]),
            match=dict(data.get("match") or {}),
            conditions=dict(data.get("conditions") or {}),
            response=dict(data.get("response") or {}),
            source_trace_ids=list(data.get("source_trace_ids") or []),
            negative_corpus_digest=str(data.get("negative_corpus_digest") or ""),
            rule_hash=str(data.get("rule_hash") or ""),
            provenance=dict(data.get("provenance") or {}),
        )
        rule.validate()
        return rule


@dataclass(frozen=True)
class ValidationAttestation:
    """Signed empirical gate summary for a candidate rule (`ValidationAttestation/1`)."""

    candidate_hash: str
    corpus_hashes: Dict[str, str]
    seed: int
    tested_positive: int
    caught_positive: int
    tested_negative: int
    false_positives: int
    fp_upper_bound_95: float
    python_rust_decision_mismatches: int
    status: str
    schema: str = "ValidationAttestation/1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def capture_failure(envelope: FailureEnvelope, store_dir: str | Path) -> Path:
    """Persist a sanitized immutable `FailureEnvelope/1` JSON atomically inside `store_dir`."""
    base = Path(store_dir)
    assert_not_symlink(base)
    base.mkdir(parents=True, exist_ok=True)
    digest = envelope.trace_id.split(":", 1)[-1][:16]
    out_path = base / f"trace_{digest}.json"
    atomic_write_text(out_path, json.dumps(envelope.to_dict(), indent=2, ensure_ascii=False) + "\n", mode=0o600)
    return out_path


def _extract_alias_map(tree: ast.AST) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _resolve_callee(node: ast.Call, aliases: Dict[str, str]) -> str:
    parts: List[str] = []
    cur: ast.AST = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    if not parts:
        return ""
    head = parts[0]
    if head in aliases:
        mapped = aliases[head]
        return ".".join([mapped, *parts[1:]]) if len(parts) > 1 else mapped
    return ".".join(parts)


def _eval_simple_const(node: ast.AST, env: Dict[str, Any]) -> Tuple[bool, Any]:
    """Safely fold constants, booleans, `(None)`, and simple local vars via static AST inspection."""
    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, ast.Name):
        if node.id in env:
            return True, env[node.id]
        return False, None
    if isinstance(node, ast.Attribute):
        return True, f"attr:{node.attr}"
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        ok, val = _eval_simple_const(node.operand, env)
        return (True, not bool(val)) if ok else (False, None)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "bool" and len(node.args) == 1:
        ok, val = _eval_simple_const(node.args[0], env)
        return (True, bool(val)) if ok else (False, None)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        ok_l, vl = _eval_simple_const(node.left, env)
        ok_r, vr = _eval_simple_const(node.comparators[0], env)
        if ok_l and ok_r:
            op = node.ops[0]
            if isinstance(op, ast.Eq):
                return True, vl == vr
            if isinstance(op, ast.NotEq):
                return True, vl != vr
    return False, None


def _collect_simple_env(tree: ast.AST) -> Dict[str, Any]:
    env: Dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            ok, val = _eval_simple_const(node.value, env)
            if ok:
                env[node.targets[0].id] = val
    return env


def _parse_first_call_and_assigns(code: str) -> Tuple[List[Tuple[str, Dict[str, Tuple[bool, Any]]]], List[Tuple[str, Tuple[bool, Any]]]]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [], []
    aliases = _extract_alias_map(tree)
    env = _collect_simple_env(tree)
    calls: List[Tuple[str, Dict[str, Tuple[bool, Any]]]] = []
    assigns: List[Tuple[str, Tuple[bool, Any]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _resolve_callee(node, aliases)
            kwargs = {
                kw.arg: _eval_simple_const(kw.value, env)
                for kw in node.keywords
                if kw.arg is not None
            }
            calls.append((callee, kwargs))
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assigns.append((node.targets[0].id, _eval_simple_const(node.value, env)))
    return calls, assigns


def synthesize_rule_ir(
    envelope: FailureEnvelope,
    *,
    bad_code: Optional[str] = None,
    good_code: Optional[str] = None,
    rule_id: str = "KS-EVO-000001",
    severity: str = "HIGH",
) -> RuleIR:
    """Synthesize a declarative `RuleIR/1` from a `FailureEnvelope/1` using AST-first inspection."""
    bad = (bad_code if bad_code is not None else envelope.offending_snippet).strip()
    good = (good_code if good_code is not None else envelope.fixed_snippet).strip()
    lang = envelope.language.lower()

    if lang == "python":
        bad_calls, bad_assigns = _parse_first_call_and_assigns(bad)
        good_calls, good_assigns = _parse_first_call_and_assigns(good)

        if bad_calls:
            bad_callee, bad_kwargs = bad_calls[0]
            good_callees = {c for c, _ in good_calls}
            matching_good = [kwargs for c, kwargs in good_calls if c == bad_callee]
            if bad_callee not in good_callees:
                match = {"node": "Call", "callee": bad_callee, "mode": "forbidden_callee"}
                return RuleIR(
                    rule_id=rule_id,
                    revision=1,
                    language=[lang],
                    severity=severity,
                    predicate_kind="ast_pattern",
                    match=match,
                    source_trace_ids=[envelope.trace_id],
                )
            good_kwargs = matching_good[0] if matching_good else {}
            for kw_name in sorted(set(bad_kwargs) | set(good_kwargs)):
                ok_b, val_b = bad_kwargs.get(kw_name, (True, "__MISSING__"))
                ok_g, val_g = good_kwargs.get(kw_name, (True, "__MISSING__"))
                if ok_b and ok_g and val_b != val_g:
                    safe_vals: List[Any] = [val_g]
                    if val_g in ("attr:SafeLoader", "attr:CSafeLoader"):
                        safe_vals = ["attr:SafeLoader", "attr:CSafeLoader"]
                    match = {
                        "node": "Call",
                        "callee": bad_callee,
                        "mode": "kwarg_not_in",
                        "kwarg": kw_name,
                        "allowed_values": safe_vals,
                    }
                    return RuleIR(
                        rule_id=rule_id,
                        revision=1,
                        language=[lang],
                        severity=severity,
                        predicate_kind="ast_pattern",
                        match=match,
                        source_trace_ids=[envelope.trace_id],
                    )

        if bad_assigns:
            var_name, (ok_b, val_b) = bad_assigns[0]
            good_vals = {val_g for g_var, (ok_g, val_g) in good_assigns if g_var == var_name and ok_g}
            if ok_b and val_b not in good_vals and isinstance(val_b, (type(None), bool, int, str)):
                match = {
                    "node": "Assign",
                    "target": var_name,
                    "forbidden_value": val_b,
                }
                return RuleIR(
                    rule_id=rule_id,
                    revision=1,
                    language=[lang],
                    severity=severity,
                    predicate_kind="ast_pattern",
                    match=match,
                    source_trace_ids=[envelope.trace_id],
                )

    from kintsugi.council import _synthesize_generalized_pattern

    pat = _synthesize_generalized_pattern(bad, good or None)
    return RuleIR(
        rule_id=rule_id,
        revision=1,
        language=[lang],
        severity=severity,
        predicate_kind="bounded_regex",
        match={"regex": pat},
        source_trace_ids=[envelope.trace_id],
    )


def evaluate_rule_ir(rule_ir: RuleIR, code_text: str, *, language: str = "python") -> List[Dict[str, Any]]:
    """Deterministically evaluate a declarative `RuleIR/1` over `code_text`."""
    rule_ir.validate()
    kind = rule_ir.predicate_kind
    hits: List[Dict[str, Any]] = []

    if kind == "ast_pattern":
        if language.lower() != "python":
            return []
        try:
            tree = ast.parse(code_text)
        except SyntaxError:
            return []
        aliases = _extract_alias_map(tree)
        env = _collect_simple_env(tree)
        m = rule_ir.match
        node_type = m.get("node")

        if node_type == "Call":
            target_callee = str(m.get("callee", ""))
            mode = str(m.get("mode", "forbidden_callee"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if _resolve_callee(node, aliases) != target_callee:
                    continue
                if mode == "forbidden_callee":
                    hits.append({"line": getattr(node, "lineno", 1), "callee": target_callee})
                elif mode == "kwarg_not_in":
                    kw_name = str(m.get("kwarg", ""))
                    allowed = list(m.get("allowed_values") or [])
                    kw_node = next((kw.value for kw in node.keywords if kw.arg == kw_name), None)
                    if kw_node is None:
                        if "__MISSING__" not in allowed:
                            hits.append({"line": getattr(node, "lineno", 1), "callee": target_callee, "kwarg": kw_name})
                    else:
                        ok, val = _eval_simple_const(kw_node, env)
                        if not ok or val not in allowed:
                            hits.append({"line": getattr(node, "lineno", 1), "callee": target_callee, "kwarg": kw_name})
        elif node_type == "Assign":
            target_var = str(m.get("target", ""))
            forbidden_val = m.get("forbidden_value")
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    if node.targets[0].id != target_var:
                        continue
                    ok, val = _eval_simple_const(node.value, env)
                    if ok and type(val) is type(forbidden_val) and val == forbidden_val:
                        hits.append({"line": getattr(node, "lineno", 1), "target": target_var})
        return hits

    if kind == "bounded_regex":
        rx = re.compile(str(rule_ir.match["regex"]), re.MULTILINE)
        for match in rx.finditer(code_text):
            line_no = code_text[: match.start()].count("\n") + 1
            hits.append({"line": line_no, "snippet": match.group(0)[:120]})
        return hits

    if kind == "path_policy":
        cmd = code_text.strip()
        ws = Path(str(m.get("workspace_root", ".")) if isinstance(rule_ir.match, dict) else ".")
        if _is_dangerous_rm_target(cmd, workspace_root=ws):
            hits.append({"line": 1, "target": cmd})
        return hits

    raise ValueError(f"Unsupported predicate_kind: {kind}")


def generate_counterfactuals(
    rule_ir: RuleIR,
    bad_code: str,
    good_code: str,
    *,
    seed: int = DEFAULT_TRUSTED_SEED,
) -> Tuple[List[str], List[str]]:
    """Generate deterministic metamorphic positive variants and benign near-miss negatives."""
    rng = random.Random(seed)
    positives: List[str] = [bad_code.strip()]
    negatives: List[str] = [
        good_code.strip(),
        f"# documentation note: avoid `{bad_code.strip().splitlines()[-1]}`\nx_safe = 1\n",
        f'example_doc = "{bad_code.strip().splitlines()[-1]}"\n',
    ]
    m = rule_ir.match
    node_type = m.get("node")

    if rule_ir.predicate_kind == "ast_pattern" and node_type == "Call":
        callee = str(m.get("callee", ""))
        mod = callee.split(".")[0] if "." in callee else ""
        fn = callee.split(".")[-1]
        mode = str(m.get("mode", ""))
        if mod and mode == "forbidden_callee":
            alias = f"{mod}_v{rng.randint(2, 9)}"
            positives.append(f"import {mod} as {alias}\nres = {alias}.{fn}(stream_v1)\n")
            positives.append(f"from {mod} import {fn} as call_fn\nres = call_fn(untrusted_blob)\n")
            negatives.append(f"import {mod}\nres = {mod}.safe_load(stream_v1)\n" if fn == "load" else good_code.strip())
        elif mod and mode == "kwarg_not_in":
            kw = str(m.get("kwarg", ""))
            allowed = list(m.get("allowed_values") or [])
            if kw == "Loader":
                for loader_alt in ("Loader", "UnsafeLoader", "FullLoader"):
                    positives.append(f"import {mod} as y_alt\ncfg = y_alt.{fn}(blob, {kw}=y_alt.{loader_alt})\n")
                positives.append(f"import {mod}\ncfg = {mod}.{fn}(blob)\n")
                negatives.append(f"import {mod}\ncfg = {mod}.{fn}(blob, {kw}={mod}.CSafeLoader)\n")
                negatives.append(f"import {mod}\ncfg = {mod}.safe_load(blob)\n")
            elif allowed and isinstance(allowed[0], bool):
                neg_bool = not allowed[0]
                for expr in (repr(neg_bool), f"({int(neg_bool)} == 1)" if neg_bool else "(1 == 0)", "not False" if neg_bool else "not True"):
                    positives.append(f"import {mod}\n{mod}.{fn}(arg_v, {kw}={expr})\n")
                positives.append(f"import {mod}\nf = {repr(neg_bool)}\n{mod}.{fn}(arg_v, {kw}=f)\n")
                negatives.append(f"import {mod}\n{mod}.{fn}(arg_v, {kw}={repr(allowed[0])})\n")
    elif rule_ir.predicate_kind == "ast_pattern" and node_type == "Assign":
        target = str(m.get("target", "flag"))
        fval = m.get("forbidden_value")
        if fval is None:
            positives.append(f"{target} = (None)\n")
            positives.append(f"{target}=(None)\n")
            negatives.append(f"{target} = 'configured'\n")
        elif isinstance(fval, bool):
            expr = "(1 == 1)" if fval else "(1 == 0)"
            positives.append(f"{target} = {expr}\n")
            positives.append(f"{target} = {'not False' if fval else 'not True'}\n")
            negatives.append(f"{target} = {repr(not fval)}\n")

    # Deduplicate preserving order cleanly
    pos_uniq = list(dict.fromkeys(p for p in positives if p.strip()))
    neg_uniq = list(dict.fromkeys(n for n in negatives if n.strip() and n.strip() not in set(pos_uniq)))
    return pos_uniq, neg_uniq


def validate_candidate_rule(
    rule_ir: RuleIR,
    positives: Sequence[str],
    negatives: Sequence[str],
    *,
    heldout_positives: Sequence[str] = (),
    heldout_negatives: Sequence[str] = (),
    seed: int = DEFAULT_TRUSTED_SEED,
    min_recall: float = 1.0,
    parity_mismatches: int = 0,
) -> ValidationAttestation:
    """Verify train/holdout disjointness, empirical recall, 0-FP check, and Rule-of-Three bound."""
    rule_ir.validate()
    pos_set = {p.strip() for p in positives if p.strip()}
    neg_set = {n.strip() for n in negatives if n.strip()}
    hpos_set = {p.strip() for p in heldout_positives if p.strip()}
    hneg_set = {n.strip() for n in heldout_negatives if n.strip()}
    if (pos_set & hpos_set) or (neg_set & hneg_set):
        raise ValueError("CORPUS_LEAKAGE: Training and held-out splits must be strictly disjoint")

    all_pos = list(positives) + list(heldout_positives)
    all_neg = list(negatives) + list(heldout_negatives)
    caught_pos = sum(1 for item in all_pos if evaluate_rule_ir(rule_ir, item, language=rule_ir.language[0]))
    fp_count = sum(1 for item in all_neg if evaluate_rule_ir(rule_ir, item, language=rule_ir.language[0]))
    recall = caught_pos / max(1, len(all_pos))
    fp_ub = round(min(1.0, 3.0 / max(1, len(all_neg))), 6)
    passed = fp_count == 0 and recall >= min_recall and parity_mismatches == 0 and len(all_pos) > 0
    return ValidationAttestation(
        candidate_hash=rule_ir.rule_hash,
        corpus_hashes={
            "positive": _canonical_sha256(list(all_pos)),
            "negative": _canonical_sha256(list(all_neg)),
            "private_holdout": _canonical_sha256({"p": list(heldout_positives), "n": list(heldout_negatives)}),
        },
        seed=seed,
        tested_positive=len(all_pos),
        caught_positive=caught_pos,
        tested_negative=len(all_neg),
        false_positives=fp_count,
        fp_upper_bound_95=fp_ub,
        python_rust_decision_mismatches=parity_mismatches,
        status="SHADOW_ONLY" if passed else "REJECTED",
    )


def run_python_rust_parity(
    fixtures: Sequence[Dict[str, Any]],
    *,
    rust_bin_path: Optional[str | Path] = None,
    scars: Optional[Sequence[GoldenScar]] = None,
) -> Dict[str, Any]:
    """Compare live Python vs native compiled `kintsugi-rs` decisions across shared fixtures."""
    from kintsugi.starter_pack import get_full_crs_scars

    active_scars = list(scars) if scars is not None else get_full_crs_scars()
    scanner = KintsugiScanner(active_scars, allow_inline_ignores=False)
    bin_path = Path(rust_bin_path) if rust_bin_path else None
    if bin_path is None or not bin_path.is_file():
        return {"schema": "ParityReport/1", "rust_binary_present": False, "total": len(fixtures), "mismatches": 0, "details": []}

    mismatches: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_ws = Path(tmp_dir)
        for idx, fx in enumerate(fixtures):
            kind = str(fx.get("kind", "hook"))
            if kind == "hook":
                payload = fx["payload"]
                py_dec = evaluate_claude_pre_tool_payload(
                    payload,
                    active_scars,
                    trusted_workspace_root=fx.get("workspace") or tmp_ws,
                )
                py_deny = py_dec.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
                proc = subprocess.run(
                    [str(bin_path), "hook", "claude-pre-tool", "--workspace", str(fx.get("workspace") or tmp_ws)],
                    input=json.dumps(payload),
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                try:
                    rs_dec = json.loads(proc.stdout)
                except ValueError:
                    rs_dec = {}
                rs_deny = rs_dec.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"
            else:
                fname = str(fx.get("filename", f"fixture_{idx}.md"))
                text = str(fx.get("text", ""))
                py_deny = bool(scanner.scan_text(text, file_path=fname))
                f_path = tmp_ws / fname
                f_path.parent.mkdir(parents=True, exist_ok=True)
                f_path.write_text(text, encoding="utf-8")
                proc = subprocess.run(
                    [str(bin_path), "scan", str(f_path), "--format", "json", "--fail-on", "HIGH"],
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                try:
                    rs_obj = json.loads(proc.stdout)
                except ValueError:
                    rs_obj = {}
                rs_deny = len(rs_obj.get("findings") or []) > 0
                f_path.unlink(missing_ok=True)

            if py_deny != rs_deny:
                mismatches.append({"index": idx, "kind": kind, "label": fx.get("label", ""), "python_deny": py_deny, "rust_deny": rs_deny})

    return {
        "schema": "ParityReport/1",
        "rust_binary_present": True,
        "total": len(fixtures),
        "mismatches": len(mismatches),
        "details": mismatches,
    }


class EvolutionRegistry:
    """Append-only, symlink-safe lifecycle registry supporting shadow/canary/enforced promotion and rollback."""

    def __init__(self, registry_path: str | Path) -> None:
        self.path = Path(registry_path)
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)
        self.events: List[Dict[str, Any]] = []
        self.active: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.events = list(data.get("events") or [])
            self.active = dict(data.get("active") or {})

    def _save(self) -> None:
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": "EvolutionRegistry/1", "active": self.active, "events": self.events}
        atomic_write_text(self.path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", mode=0o600)

    def promote(
        self,
        rule_ir: RuleIR,
        attestation: ValidationAttestation,
        *,
        mode: str = "shadow",
        reviewer_approved: bool = False,
    ) -> Dict[str, Any]:
        rule_ir.validate()
        if rule_ir.rule_id in PROTECTED_BASELINE_IDS:
            raise ValueError(f"PROTECTED_BASELINE_IMMUTABLE: Cannot overwrite baseline rule {rule_ir.rule_id}")
        if mode not in {"shadow", "canary", "enforced"}:
            raise ValueError(f"Invalid promotion mode: {mode}")
        if attestation.candidate_hash != rule_ir.rule_hash:
            raise ValueError("ATTESTATION_HASH_MISMATCH")
        if attestation.status == "REJECTED" or attestation.false_positives > 0 or attestation.python_rust_decision_mismatches > 0:
            raise ValueError("PROMOTION_GATE_FAILED: Failing attestation cannot be promoted")
        if mode == "enforced" and not reviewer_approved:
            raise ValueError("PROMOTION_GATE_FAILED: Enforced promotion requires reviewer_approved=True")

        receipt = {
            "event": "promote",
            "rule_id": rule_ir.rule_id,
            "revision": rule_ir.revision,
            "mode": mode,
            "rule_hash": rule_ir.rule_hash,
            "rule": rule_ir.to_dict(),
            "attestation": attestation.to_dict(),
        }
        self.events.append(receipt)
        self.active[rule_ir.rule_id] = receipt
        self._save()
        return receipt

    def rollback(self, rule_id: str, *, to_revision: int) -> Dict[str, Any]:
        prior = next(
            (ev for ev in reversed(self.events) if ev.get("event") == "promote" and ev.get("rule_id") == rule_id and ev.get("revision") == to_revision),
            None,
        )
        if prior is None:
            raise ValueError(f"ROLLBACK_TARGET_NOT_FOUND: {rule_id} rev={to_revision}")
        receipt = {
            "event": "rollback",
            "rule_id": rule_id,
            "to_revision": to_revision,
            "restored_hash": prior["rule_hash"],
        }
        self.events.append(receipt)
        self.active[rule_id] = prior
        self._save()
        return receipt


def plan_ledger_consolidation(scars: Sequence[GoldenScar]) -> Dict[str, Any]:
    """Compute behavioral signatures across the ledger to flag duplicates without mutating baselines."""
    by_behavior: Dict[str, List[str]] = {}
    id_counts: Dict[str, int] = {}
    baseline_locked = 0

    for scar in scars:
        if scar.id in PROTECTED_BASELINE_IDS:
            baseline_locked += 1
        id_counts[scar.id] = id_counts.get(scar.id, 0) + 1
        sig_obj = {
            "langs": sorted(scar.languages),
            "ast_rule": scar.ast_rule or "",
            "regex": re.sub(r"\s+", "", scar.regex_pattern or ""),
        }
        sig = _canonical_sha256(sig_obj)
        by_behavior.setdefault(sig, []).append(scar.id)

    duplicate_clusters = [ids for ids in by_behavior.values() if len(ids) > 1]
    id_conflicts = [sid for sid, cnt in id_counts.items() if cnt > 1]
    return {
        "schema": "ConsolidationPlan/1",
        "total_scars": len(scars),
        "baseline_locked": baseline_locked,
        "unique_behavioral_signatures": len(by_behavior),
        "duplicate_cluster_count": len(duplicate_clusters),
        "duplicate_clusters_sample": duplicate_clusters[:10],
        "id_conflicts": id_conflicts,
    }


def default_parity_fixtures() -> List[Dict[str, Any]]:
    """Shared hook + scanner parity corpus used by CLI `--parity-check`."""
    del_verb = "rm" + " -rf "
    return [
        {"kind": "hook", "label": "safe_top_build", "payload": {"tool_name": "Bash", "tool_input": {"command": del_verb + "./build"}}},
        {"kind": "hook", "label": "nested_other_build", "payload": {"tool_name": "Bash", "tool_input": {"command": del_verb + "./other/build"}}},
        {"kind": "hook", "label": "cwd_override_etc", "payload": {"tool_name": "Bash", "tool_input": {"command": del_verb + "./build", "cwd": "/etc"}}},
        {"kind": "scan", "label": "safe_yaml", "filename": "ok.py", "text": "import yaml\ncfg = yaml.safe_load(raw)\n"},
        {"kind": "scan", "label": "unsafe_yaml_loader", "filename": "bad.py", "text": "import yaml\ncfg = yaml.load(raw, Loader=yaml.Loader)\n"},
    ]

