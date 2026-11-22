"""Stage 5 Verified Self-Evolution Engine v3 (`kintsugi.evolution.evolution_v3`).

Bridges:
  - `evolution_v2` (`FailureEnvelope/1`, `RuleIR/1`, `ValidationAttestation/1`, `EvolutionRegistry`)
  - `native_bridge.NativeBridge` (canonical Rust `RuleIR/1` hash + decision parity via `cdylib` FFI or `kintsugi-rs`)
  - `ProofPack` (`ProofPackReport/1` differential & property verification)
  - `StrategyMemory` (Tier-3 causal strategy & decomposition memory at `.kintsugi/strategy_memory.json`)

Enforces strict invariants:
  - `PROTECTED_BASELINE_IDS` (`KS-001..KS-024`) are immutable.
  - Learner CANNOT mutate `hooks.py` or `PreToolUse` directly.
  - Monotonic promotion lifecycle `Shadow -> Canary -> Enforced` (`reviewer_approved=True`) + atomic rollback.
  - Honest empirical metrics (observed numerator/denominator + Wilson 95% CI, never universal 0% FP).
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import math
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import canonical_json_dumps, sha256_digest, validate_safe_text
from kintsugi.council import _synthesize_generalized_pattern
from kintsugi.evolution.strategy_memory import (
    DEFAULT_STRATEGY_MEMORY_REL_PATH,
    StrategyMemory,
    StrategyRecord,
    compute_wilson_interval,
)
from kintsugi.evolution_v2 import (
    ALLOWED_PREDICATE_KINDS,
    DEFAULT_TRUSTED_SEED,
    PROTECTED_BASELINE_IDS,
    EvolutionRegistry,
    FailureEnvelope,
    RuleIR,
    ValidationAttestation,
    _eval_simple_const,
    _extract_alias_map,
    _resolve_callee,
    capture_failure,
    evaluate_rule_ir,
    generate_counterfactuals,
    plan_ledger_consolidation,
)
from kintsugi.models import GoldenScar
from kintsugi.native_bridge import (
    DEFAULT_EXTERNAL_PIN_MANIFEST,
    NativeBridge,
    _is_within,
    _normalize_sha256_pin,
    _read_and_hash_regular_nofollow,
)
from kintsugi.runtime.secure_runner import redact_runtime_text, redact_runtime_value
from kintsugi.scanner import KintsugiScanner
from kintsugi.shield import (
    assert_not_symlink,
    is_safe_regex_pattern,
    resolve_safe_child_path,
)
from kintsugi.starter_pack import get_full_crs_scars
from kintsugi.tools.proof_pack import ProofLevel, ProofPack, ProofPackReport

EVOLUTION_V3_SCHEMA = "SelfEvolutionV3/1"
EVOLUTION_STAGES: Tuple[str, ...] = ("shadow", "canary", "enforced")
IMMUTABLE_BASELINE_IDS = PROTECTED_BASELINE_IDS
IMMUTABLE_HOOK_TARGETS: FrozenSet[str] = frozenset(
    {"hooks.py", "pretooluse", "claude-pre-tool", "scanner.py", "rust/src/lib.rs", "rust/src/ffi.rs"}
)

_SAFE_DEFAULT_BOOL_KWARGS: FrozenSet[str] = frozenset(
    {
        "shell",
        "verify",
        "check_hostname",
        "autoescape",
        "debug",
        "insecure",
        "allow_credentials",
        "usedforsecurity",
    }
)
_SECURITY_KWARG_PRIORITY: Tuple[str, ...] = (
    "Loader",
    "loader",
    "shell",
    "verify",
    "weights_only",
    "autoescape",
    "check_hostname",
    "allow_credentials",
    "usedforsecurity",
    "timeout",
)
_UTILITY_CALLEES: FrozenSet[str] = frozenset(
    {"print", "len", "str", "repr", "dict", "list", "set", "tuple", "int", "float", "bool", "isinstance"}
)
_SECURITY_VAR_HINTS: Tuple[str, ...] = (
    "ssl",
    "tls",
    "verify",
    "cert",
    "auth",
    "debug",
    "safe",
    "shell",
    "sandbox",
    "allow",
    "token",
    "timeout",
    "autoescape",
)
_RUST_SUPPORTED_RE_UNSUPPORTED = ("(?i)", "(?x)", "(?m)", "(?s)", "(?P<")


def _find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for cand in (cur, *cur.parents):
        if (cand / "Cargo.toml").is_file() and (cand / "src" / "kintsugi").is_dir():
            return cand
    return start.resolve().parents[3] if len(start.resolve().parents) >= 4 else start.resolve()


def _percentile_95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(v) for v in values)
    idx = max(0, min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1))
    return round(ordered[idx], 4)


def honest_metric_summary(numerator: int, denominator: int, *, metric: str) -> Dict[str, Any]:
    """Build an empirical metric report with observed fraction and Wilson 95% CI (never universal 0% FP)."""
    lb, ub = compute_wilson_interval(numerator, denominator)
    rate = round(float(numerator) / float(denominator), 6) if denominator > 0 else 0.0
    return {
        "metric": metric,
        "observed_numerator": numerator,
        "observed_denominator": denominator,
        "observed_fraction": f"{numerator}/{denominator}",
        "rate": rate,
        "wilson_lower_bound_95": lb,
        "wilson_upper_bound_95": ub,
        "universal_claim_forbidden": True,
        "universal_zero_fp_claimed": False,
        "statement": (
            f"Observed {numerator}/{denominator} ({rate:.4%}, Wilson 95% CI=[{lb:.6f}, {ub:.6f}]); "
            "finite empirical sample bound only, not a universal guarantee."
        ),
    }


def _guard_no_hook_or_baseline_mutation(
    *,
    rule_id: Optional[str] = None,
    mutation_target: Optional[str] = None,
    config_hints: Optional[Mapping[str, Any]] = None,
) -> None:
    if rule_id is not None and rule_id in PROTECTED_BASELINE_IDS:
        raise ValueError(f"PROTECTED_BASELINE_IMMUTABLE: Cannot modify or overwrite baseline rule {rule_id}")

    targets_to_check: List[str] = []
    if mutation_target:
        targets_to_check.append(str(mutation_target))
    if isinstance(config_hints, Mapping):
        for k in ("mutation_target", "target_file", "target_module", "hook_target", "patch_target"):
            if config_hints.get(k):
                targets_to_check.append(str(config_hints[k]))
        if config_hints.get("mutate_hooks") is True or config_hints.get("override_pretooluse") is True:
            raise PermissionError("LEARNER_HOOK_MUTATION_FORBIDDEN: Direct mutation of hooks.py / PreToolUse is blocked.")

    for raw_t in targets_to_check:
        norm = raw_t.strip().lower().replace("\\", "/")
        if any(imm in norm for imm in IMMUTABLE_HOOK_TARGETS):
            raise PermissionError(
                f"LEARNER_HOOK_MUTATION_FORBIDDEN: Learner cannot directly mutate '{raw_t}'."
            )


def _collect_env_multipass(tree: ast.AST) -> Dict[str, Any]:
    """Collect constant environment over 3 passes in statement order (matching Rust)."""
    assign_nodes: List[Tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assign_nodes.append((node.targets[0].id, node.value))
    env: Dict[str, Any] = {}
    for _ in range(3):
        changed = False
        for target_id, val_node in assign_nodes:
            ok, val = _eval_simple_const(val_node, env)
            if ok and (target_id not in env or env[target_id] != val or type(env[target_id]) is not type(val)):
                env[target_id] = val
                changed = True
        if not changed:
            break
    return env


def _parse_calls_and_assigns(
    code: str,
) -> Tuple[
    List[Tuple[str, Dict[str, Tuple[bool, Any]], int]],
    List[Tuple[str, Tuple[bool, Any], int]],
    Dict[str, str],
    Dict[str, Any],
]:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return [], [], {}, {}
    aliases = _extract_alias_map(tree)
    env = _collect_env_multipass(tree)
    calls: List[Tuple[str, Dict[str, Tuple[bool, Any]], int]] = []
    assigns: List[Tuple[str, Tuple[bool, Any], int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            callee = _resolve_callee(node, aliases)
            if callee:
                kwargs = {
                    kw.arg: _eval_simple_const(kw.value, env)
                    for kw in node.keywords
                    if kw.arg is not None
                }
                calls.append((callee, kwargs, int(getattr(node, "lineno", 1))))
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assigns.append((node.targets[0].id, _eval_simple_const(node.value, env), int(getattr(node, "lineno", 1))))
    return calls, assigns, aliases, env


def _is_utility_callee(callee: str) -> bool:
    if callee in _UTILITY_CALLEES:
        return True
    return callee.startswith(("logging.", "logger.", "log."))


def _sanitize_path_hints(file_path: Optional[str], config_hints: Optional[Mapping[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    path_hints: Dict[str, Any] = {}
    if file_path:
        clean_fp = redact_runtime_text(validate_safe_text(str(file_path), field_name="file_path", allow_empty=True))
        p_obj = Path(clean_fp)
        path_hints = {
            "file_path": clean_fp,
            "suffix": p_obj.suffix.lower(),
            "is_shell": p_obj.suffix.lower() in {".sh", ".bash", ".zsh"},
            "is_config": any(tok in clean_fp.lower() for tok in ("config", "settings", "policy", "env")),
        }
    clean_cfg = redact_runtime_value(dict(config_hints or {}))
    return path_hints, clean_cfg


def _make_rust_compatible_regex(bad_code: str, good_code: str) -> str:
    """Synthesize a bounded regex free of Rust-unsupported inline flags and ReDoS constructs."""
    first_line = next((ln.strip() for ln in bad_code.splitlines() if ln.strip()), bad_code.strip())
    pat = _synthesize_generalized_pattern(first_line, good_code or None)
    if any(tok in pat for tok in _RUST_SUPPORTED_RE_UNSUPPORTED) or len(pat) > 350:
        pat = re.escape(first_line)[:300]
    ok, _ = is_safe_regex_pattern(pat)
    if not ok:
        pat = re.escape(first_line)[:300]
    return pat


@dataclass(frozen=True)
class UnseenFailure:
    """Typed unseen failure input before DLP redaction into `FailureEnvelope/1`."""

    task_id: str
    language: str
    offending_snippet: str
    fixed_snippet: str
    error_summary: str
    task_class: str = ""
    file_path: str = ""
    config_hints: Dict[str, Any] = field(default_factory=dict)
    tool: str = "agent.code_check"
    split: str = "train"
    consent: str = "local_only"


@dataclass(frozen=True)
class CauseLocalization:
    """Structured AST + alias + config/path localization verdict (`CauseLocalization/1`)."""

    language: str
    task_class: str
    cause_kind: str
    target_symbol: str
    kwarg_name: Optional[str] = None
    bad_value: Any = None
    allowed_values: Tuple[Any, ...] = ()
    aliases_detected: Dict[str, str] = field(default_factory=dict)
    shadowed_constants: Dict[str, Any] = field(default_factory=dict)
    path_hints: Dict[str, Any] = field(default_factory=dict)
    config_hints: Dict[str, Any] = field(default_factory=dict)
    recommended_decomposition: str = "ast_call_diff_with_safe_defaults"
    recommended_strategy: str = "ast_kwarg_policy"
    schema: str = "CauseLocalization/1"

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(asdict(self))


@dataclass(frozen=True)
class CanarySoakReport:
    """Empirical Canary soak summary over benign and held-out negatives."""

    rule_id: str
    revision: int
    rule_hash: str
    tested_negatives: int
    false_positives: int
    observed_fraction: str
    fp_upper_bound_95: float
    parity_mismatches: int
    p95_latency_ms: float
    corpus_digest: str
    passed: bool
    honest_fp_summary: Dict[str, Any]
    schema: str = "CanarySoakReport/1"

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(asdict(self))


@dataclass
class EvolutionCandidateResult:
    """End-to-end result of synthesizing, validating, and verifying one candidate `RuleIR/1`."""

    envelope: FailureEnvelope
    localization: CauseLocalization
    rule_ir: RuleIR
    positives: List[str]
    negatives: List[str]
    attestation: ValidationAttestation
    proof_pack_report: ProofPackReport
    strategy_used: str
    decomposition_pattern: str
    parity_mismatches: int
    canonical_hash_verified: bool
    p95_latency_ms: float
    stage: str = "unpromoted"
    canary_report: Optional[CanarySoakReport] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "localization": self.localization.to_dict(),
            "rule_ir": self.rule_ir.to_dict(),
            "attestation": self.attestation.to_dict(),
            "proof_pack_report": self.proof_pack_report.to_dict(),
            "strategy_used": self.strategy_used,
            "decomposition_pattern": self.decomposition_pattern,
            "parity_mismatches": self.parity_mismatches,
            "canonical_hash_verified": self.canonical_hash_verified,
            "p95_latency_ms": self.p95_latency_ms,
            "stage": self.stage,
            "canary_report": self.canary_report.to_dict() if self.canary_report is not None else None,
        }


@dataclass
class BlindTransferReport:
    """Cross-task blind held-out generalization report vs `no_memory_control`."""

    family_recall: float
    negative_precision: float
    fp_upper_bound_95: float
    parity_mismatches: int
    p95_latency_ms: float
    baseline_regression_count: int
    recall_numerator: int
    recall_denominator: int
    recall_lower_bound_95: float
    false_positives: int
    tested_negatives: int
    per_family_recall: Dict[str, float]
    no_memory_control: Dict[str, Any]
    recall_gain: float
    evolved_rule_ids: List[str]
    strategy_memory_rankings: Dict[str, List[Dict[str, Any]]]
    honest_fp_summary: Dict[str, Any]
    honest_recall_summary: Dict[str, Any]
    proof_pack_summary: Dict[str, Any]
    schema: str = "BlindTransferReport/1"

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(asdict(self))


class SelfEvolutionEngineV3:
    """Stage 5 Verified Self-Evolution Engine integrating RuleIR/1, NativeBridge, ProofPack & StrategyMemory."""

    SCHEMA_VERSION = EVOLUTION_V3_SCHEMA

    def __init__(
        self,
        *,
        workspace_root: Optional[Union[str, Path]] = None,
        registry_path: Optional[Union[str, Path]] = None,
        strategy_memory_path: Optional[Union[str, Path]] = None,
        traces_dir: Optional[Union[str, Path]] = None,
        native_bridge: Optional[NativeBridge] = None,
        rust_repo_root: Optional[Union[str, Path]] = None,
        pin_manifest_path: Optional[Union[str, Path]] = None,
        expected_dylib_sha256: Optional[str] = None,
        expected_rust_bin_sha256: Optional[str] = None,
    ) -> None:
        ws = Path(workspace_root) if workspace_root is not None else Path.cwd()
        assert_not_symlink(ws)
        self.workspace_root = ws.resolve()

        reg_p = self._confine_path(registry_path or ".kintsugi/evolution_registry.json")
        strat_p = self._confine_path(strategy_memory_path or DEFAULT_STRATEGY_MEMORY_REL_PATH)
        self.traces_dir: Optional[Path] = self._confine_path(traces_dir) if traces_dir is not None else None

        self.registry = EvolutionRegistry(reg_p)
        self.strategy_memory = StrategyMemory(strat_p, workspace_root=self.workspace_root)

        repo_for_native = (
            Path(rust_repo_root).resolve()
            if rust_repo_root is not None
            else _find_repo_root(Path(__file__))
        )
        self._owns_native_bridge = native_bridge is None
        if native_bridge is not None:
            self.native_bridge = native_bridge
        else:
            resolved_manifest = (
                pin_manifest_path
                if pin_manifest_path is not None
                else (os.environ.get("KINTSUGI_NATIVE_PIN_MANIFEST", "").strip() or DEFAULT_EXTERNAL_PIN_MANIFEST)
            )
            self.native_bridge = NativeBridge(
                repo_root=repo_for_native,
                expected_sha256=expected_dylib_sha256,
                expected_rust_bin_sha256=expected_rust_bin_sha256,
                pin_manifest_path=resolved_manifest,
                allow_fallback=True,
            )
        self._hooks_path = repo_for_native / "src" / "kintsugi" / "hooks.py"
        self._hooks_sha256: Optional[str] = self._compute_hooks_sha256()

        self._stage_by_rev: Dict[Tuple[str, int], str] = {}
        self._canary_reports: Dict[Tuple[str, int], CanarySoakReport] = {}
        self._next_rule_seq = self._infer_next_rule_seq()
        self._reconstruct_stage_state()

    def close(self) -> None:
        """Release any staged native bridge resources owned by this engine instance."""
        if self._owns_native_bridge:
            self.native_bridge.close()

    def _confine_path(self, raw: Union[str, Path]) -> Path:
        p = Path(raw)
        if not p.is_absolute():
            confined = resolve_safe_child_path(self.workspace_root, str(p))
            if confined is None:
                raise PermissionError(f"EVOLUTION_V3_PATH_OUTSIDE_WORKSPACE: {raw}")
            return confined
        resolved = p.resolve()
        try:
            resolved.relative_to(self.workspace_root)
        except ValueError as exc:
            raise PermissionError(f"EVOLUTION_V3_PATH_OUTSIDE_WORKSPACE: {raw}") from exc
        return resolved

    def _compute_hooks_sha256(self) -> Optional[str]:
        if not self._hooks_path.is_file() or self._hooks_path.is_symlink():
            return None
        return hashlib.sha256(self._hooks_path.read_bytes()).hexdigest()

    def verify_hooks_integrity(self) -> bool:
        """Verify that `src/kintsugi/hooks.py` was never mutated by the self-evolution engine."""
        if self._hooks_sha256 is None:
            return True
        current = self._compute_hooks_sha256()
        return current == self._hooks_sha256

    def _infer_next_rule_seq(self) -> int:
        max_num = 900000
        for rid in self.registry.active.keys():
            if rid.startswith("KS-EVO-"):
                tail = rid.split("KS-EVO-", 1)[1]
                if tail.isdigit():
                    max_num = max(max_num, int(tail))
        return max_num + 1

    def _allocate_rule_id(self) -> str:
        while True:
            cand = f"KS-EVO-{self._next_rule_seq:06d}"
            self._next_rule_seq += 1
            if cand not in PROTECTED_BASELINE_IDS and cand not in self.registry.active:
                return cand

    def _reconstruct_stage_state(self) -> None:
        for ev in self.registry.events:
            et = ev.get("event")
            rid = str(ev.get("rule_id") or "")
            if et == "promote":
                rev = int(ev.get("revision", 1))
                mode = str(ev.get("mode", "shadow"))
                self._stage_by_rev[(rid, rev)] = mode
            elif et == "rollback":
                to_rev = int(ev.get("to_revision", 1))
                prior = next(
                    (
                        pe for pe in reversed(self.registry.events)
                        if pe.get("event") == "promote" and pe.get("rule_id") == rid and int(pe.get("revision", 0)) == to_rev
                    ),
                    None,
                )
                if prior is not None:
                    self._stage_by_rev[(rid, to_rev)] = str(prior.get("mode", "shadow"))

    # ------------------------------------------------------------------
    # Stage 1: UnseenFailure -> FailureEnvelope/1 (DLP Redacted)
    # ------------------------------------------------------------------
    def ingest_failure(
        self,
        failure: Union[FailureEnvelope, UnseenFailure, Mapping[str, Any]],
        *,
        persist_trace: bool = False,
    ) -> Tuple[FailureEnvelope, Dict[str, Any]]:
        """Normalize an unseen failure into a DLP-redacted `FailureEnvelope/1` and sanitized metadata."""
        if isinstance(failure, FailureEnvelope):
            bad_clean = redact_runtime_text(failure.offending_snippet)
            good_clean = redact_runtime_text(failure.fixed_snippet)
            summary_clean = redact_runtime_text(str(failure.observation.get("summary", "")))
            env = FailureEnvelope.create(
                task_id=redact_runtime_text(failure.task_id),
                language=failure.language,
                offending_snippet=bad_clean,
                fixed_snippet=good_clean,
                error_summary=summary_clean,
                tool=str(failure.context.get("tool", "agent.code_check")),
                split=failure.split,
                consent=failure.consent,
            )
            meta: Dict[str, Any] = {"task_class": "", "file_path": "", "config_hints": {}}
        else:
            raw_map = asdict(failure) if isinstance(failure, UnseenFailure) else dict(failure)
            _guard_no_hook_or_baseline_mutation(
                mutation_target=raw_map.get("mutation_target"),
                config_hints=raw_map.get("config_hints"),
            )
            env = FailureEnvelope.create(
                task_id=redact_runtime_text(str(raw_map["task_id"])),
                language=str(raw_map.get("language", "python")),
                offending_snippet=redact_runtime_text(str(raw_map["offending_snippet"])),
                fixed_snippet=redact_runtime_text(str(raw_map.get("fixed_snippet", ""))),
                error_summary=redact_runtime_text(str(raw_map.get("error_summary", ""))),
                tool=str(raw_map.get("tool", "agent.code_check")),
                split=str(raw_map.get("split", "private_heldout")),
                consent=str(raw_map.get("consent", "local_only")),
            )
            path_hints, clean_cfg = _sanitize_path_hints(raw_map.get("file_path"), raw_map.get("config_hints"))
            meta = {
                "task_class": redact_runtime_text(str(raw_map.get("task_class") or "")),
                "file_path": path_hints.get("file_path", ""),
                "path_hints": path_hints,
                "config_hints": clean_cfg,
            }

        if persist_trace and self.traces_dir is not None:
            capture_failure(env, self.traces_dir)
        return env, meta

    # ------------------------------------------------------------------
    # Stage 2: CauseLocalization (AST + alias + config/path hints)
    # ------------------------------------------------------------------
    def localize_cause(
        self,
        envelope: FailureEnvelope,
        *,
        bad_code: Optional[str] = None,
        good_code: Optional[str] = None,
        task_class: str = "",
        file_path: Optional[str] = None,
        config_hints: Optional[Mapping[str, Any]] = None,
    ) -> CauseLocalization:
        """Localize root cause using multi-call Python AST diff, alias resolution, constant folding, and hints."""
        _guard_no_hook_or_baseline_mutation(config_hints=config_hints)
        bad = (bad_code if bad_code is not None else envelope.offending_snippet).strip()
        good = (good_code if good_code is not None else envelope.fixed_snippet).strip()
        lang = envelope.language.strip().lower()
        summary = str(envelope.observation.get("summary", "")).lower()
        path_hints, clean_cfg = _sanitize_path_hints(file_path, config_hints)

        explicit_tc = redact_runtime_text(task_class.strip()) if task_class else ""

        if lang in {"shell", "bash", "sh"} or clean_cfg.get("predicate_kind") == "path_policy" or path_hints.get("is_shell"):
            ws_hint = str(clean_cfg.get("workspace_root", "."))
            if ws_hint.startswith("/Users/") or ws_hint.startswith("/home/"):
                ws_hint = "."
            return CauseLocalization(
                language=lang,
                task_class=explicit_tc or "shell_path_policy",
                cause_kind="path_policy",
                target_symbol="rm_target_policy",
                path_hints=path_hints,
                config_hints=clean_cfg,
                recommended_decomposition="path_workspace_confinement",
                recommended_strategy="path_policy_guard",
            )

        if lang == "python":
            bad_calls, bad_assigns, bad_aliases, bad_env = _parse_calls_and_assigns(bad)
            good_calls, good_assigns, _, _ = _parse_calls_and_assigns(good)

            # 1. Shared callee with differing kwarg value (skip identical/benign setup calls)
            for b_callee, b_kwargs, _ in bad_calls:
                matching_good = [gk for gc, gk, _ in good_calls if gc == b_callee]
                if not matching_good:
                    continue
                for g_kwargs in matching_good:
                    all_kw = sorted(
                        set(b_kwargs) | set(g_kwargs),
                        key=lambda k: (0 if k in _SECURITY_KWARG_PRIORITY else 1, _SECURITY_KWARG_PRIORITY.index(k) if k in _SECURITY_KWARG_PRIORITY else 99, k),
                    )
                    for kw_name in all_kw:
                        ok_b, val_b = b_kwargs.get(kw_name, (True, "__MISSING__"))
                        ok_g, val_g = g_kwargs.get(kw_name, (True, "__MISSING__"))
                        if ok_b and ok_g and (val_b != val_g or type(val_b) is not type(val_g)):
                            allowed = self._infer_allowed_kwarg_values(kw_name, val_b, val_g)
                            return CauseLocalization(
                                language=lang,
                                task_class=explicit_tc or "python_kwarg_policy",
                                cause_kind="ast_kwarg_diff",
                                target_symbol=b_callee,
                                kwarg_name=kw_name,
                                bad_value=val_b,
                                allowed_values=tuple(allowed),
                                aliases_detected=bad_aliases,
                                shadowed_constants=bad_env,
                                path_hints=path_hints,
                                config_hints=clean_cfg,
                                recommended_decomposition="ast_call_diff_with_safe_defaults",
                                recommended_strategy="ast_kwarg_policy",
                            )

            # 2. Differing callee (skip utility calls if a non-utility callee differs)
            good_callees = {c for c, _, _ in good_calls}
            diff_calls = [(c, kw) for c, kw, _ in bad_calls if c not in good_callees]
            if diff_calls:
                non_util = [(c, kw) for c, kw in diff_calls if not _is_utility_callee(c)]
                pool = non_util or diff_calls
                pool.sort(
                    key=lambda item: (
                        0 if any(tok in summary for tok in item[0].lower().split(".") if len(tok) >= 3) else 1,
                        0 if "." in item[0] else 1,
                    )
                )
                chosen_callee, chosen_kw = pool[0]
                if chosen_callee == "yaml.load" and (
                    "Loader" in chosen_kw or "yaml.safe_load" in good_callees or "yaml.csafe_load" in good_callees
                ):
                    return CauseLocalization(
                        language=lang,
                        task_class=explicit_tc or "python_kwarg_policy",
                        cause_kind="ast_kwarg_diff",
                        target_symbol="yaml.load",
                        kwarg_name="Loader",
                        bad_value=chosen_kw.get("Loader", (True, "__MISSING__"))[1],
                        allowed_values=("attr:SafeLoader", "attr:CSafeLoader"),
                        aliases_detected=bad_aliases,
                        shadowed_constants=bad_env,
                        path_hints=path_hints,
                        config_hints=clean_cfg,
                        recommended_decomposition="ast_call_diff_with_safe_defaults",
                        recommended_strategy="ast_kwarg_policy",
                    )
                if chosen_callee.startswith("subprocess.") and chosen_kw.get("shell") == (True, True):
                    return CauseLocalization(
                        language=lang,
                        task_class=explicit_tc or "python_kwarg_policy",
                        cause_kind="ast_kwarg_diff",
                        target_symbol=chosen_callee,
                        kwarg_name="shell",
                        bad_value=True,
                        allowed_values=(False, "__MISSING__"),
                        aliases_detected=bad_aliases,
                        shadowed_constants=bad_env,
                        path_hints=path_hints,
                        config_hints=clean_cfg,
                        recommended_decomposition="ast_call_diff_with_safe_defaults",
                        recommended_strategy="ast_kwarg_policy",
                    )
                return CauseLocalization(
                    language=lang,
                    task_class=explicit_tc or "python_unsafe_callee",
                    cause_kind="ast_forbidden_callee",
                    target_symbol=chosen_callee,
                    aliases_detected=bad_aliases,
                    shadowed_constants=bad_env,
                    path_hints=path_hints,
                    config_hints=clean_cfg,
                    recommended_decomposition="ast_callee_replacement_isolation",
                    recommended_strategy="ast_forbidden_callee",
                )

            # 3. Assignment invariant difference (exact type check for bool vs int vs None)
            if bad_assigns:
                good_vals_by_var: Dict[str, List[Any]] = {}
                for g_var, (ok_g, val_g), _ in good_assigns:
                    if ok_g:
                        good_vals_by_var.setdefault(g_var, []).append(val_g)
                ranked_assigns = sorted(
                    bad_assigns,
                    key=lambda item: (
                        0 if item[0].lower() in summary else 1,
                        0 if any(h in item[0].lower() for h in _SECURITY_VAR_HINTS) else 1,
                        item[2],
                    ),
                )
                for var_name, (ok_b, val_b), _ in ranked_assigns:
                    if not ok_b or not isinstance(val_b, (type(None), bool, int, str)):
                        continue
                    g_vals = good_vals_by_var.get(var_name, [])
                    matches_good = any(type(gv) is type(val_b) and gv == val_b for gv in g_vals)
                    if not matches_good:
                        return CauseLocalization(
                            language=lang,
                            task_class=explicit_tc or "python_assign_invariant",
                            cause_kind="ast_assign_diff",
                            target_symbol=var_name,
                            bad_value=val_b,
                            aliases_detected=bad_aliases,
                            shadowed_constants=bad_env,
                            path_hints=path_hints,
                            config_hints=clean_cfg,
                            recommended_decomposition="ast_constant_propagation_diff",
                            recommended_strategy="ast_assign_invariant",
                        )

        return CauseLocalization(
            language=lang,
            task_class=explicit_tc or f"{lang}_lexical_guard",
            cause_kind="lexical_pattern",
            target_symbol=bad.splitlines()[0][:64] if bad else "pattern",
            path_hints=path_hints,
            config_hints=clean_cfg,
            recommended_decomposition="lexical_bounded_token_diff",
            recommended_strategy="bounded_regex_generalizer",
        )

    @staticmethod
    def _infer_allowed_kwarg_values(kw_name: str, val_b: Any, val_g: Any) -> List[Any]:
        if kw_name in ("Loader", "loader") and val_g in ("attr:SafeLoader", "attr:CSafeLoader"):
            return ["attr:SafeLoader", "attr:CSafeLoader"]
        if val_b != "__MISSING__" and val_g == "__MISSING__":
            if isinstance(val_b, bool):
                return [not val_b, "__MISSING__"]
            return ["__MISSING__"]
        if isinstance(val_b, bool) and isinstance(val_g, bool):
            if kw_name in _SAFE_DEFAULT_BOOL_KWARGS:
                return [val_g, "__MISSING__"]
            return [val_g]
        return [val_g]

    # ------------------------------------------------------------------
    # Stage 3: Candidate RuleIR/1 Synthesis + Counterfactuals
    # ------------------------------------------------------------------
    def _build_rule_from_strategy(
        self,
        strategy_name: str,
        envelope: FailureEnvelope,
        loc: CauseLocalization,
        *,
        rule_id: str,
        revision: int,
        severity: str,
    ) -> Optional[RuleIR]:
        lang = envelope.language.strip().lower()
        if strategy_name == "ast_kwarg_policy" and loc.cause_kind == "ast_kwarg_diff" and loc.kwarg_name:
            return RuleIR(
                rule_id=rule_id,
                revision=revision,
                language=[lang],
                severity=severity,
                predicate_kind="ast_pattern",
                match={
                    "node": "Call",
                    "callee": loc.target_symbol,
                    "mode": "kwarg_not_in",
                    "kwarg": loc.kwarg_name,
                    "allowed_values": list(loc.allowed_values),
                },
                source_trace_ids=[envelope.trace_id],
                provenance={"synthesizer": "evolution-v3", "strategy": strategy_name, "human_approved": False},
            )
        if strategy_name == "ast_forbidden_callee" and loc.cause_kind == "ast_forbidden_callee":
            return RuleIR(
                rule_id=rule_id,
                revision=revision,
                language=[lang],
                severity=severity,
                predicate_kind="ast_pattern",
                match={"node": "Call", "callee": loc.target_symbol, "mode": "forbidden_callee"},
                source_trace_ids=[envelope.trace_id],
                provenance={"synthesizer": "evolution-v3", "strategy": strategy_name, "human_approved": False},
            )
        if strategy_name == "ast_assign_invariant" and loc.cause_kind == "ast_assign_diff":
            return RuleIR(
                rule_id=rule_id,
                revision=revision,
                language=[lang],
                severity=severity,
                predicate_kind="ast_pattern",
                match={"node": "Assign", "target": loc.target_symbol, "forbidden_value": loc.bad_value},
                source_trace_ids=[envelope.trace_id],
                provenance={"synthesizer": "evolution-v3", "strategy": strategy_name, "human_approved": False},
            )
        if strategy_name == "path_policy_guard" and loc.cause_kind == "path_policy":
            ws_root = str(loc.config_hints.get("workspace_root", "."))
            return RuleIR(
                rule_id=rule_id,
                revision=revision,
                language=[lang],
                severity=severity,
                predicate_kind="path_policy",
                match={"workspace_root": ws_root},
                source_trace_ids=[envelope.trace_id],
                provenance={"synthesizer": "evolution-v3", "strategy": strategy_name, "human_approved": False},
            )
        if strategy_name == "bounded_regex_generalizer":
            pat = _make_rust_compatible_regex(envelope.offending_snippet, envelope.fixed_snippet)
            return RuleIR(
                rule_id=rule_id,
                revision=revision,
                language=[lang],
                severity=severity,
                predicate_kind="bounded_regex",
                match={"regex": pat},
                source_trace_ids=[envelope.trace_id],
                provenance={"synthesizer": "evolution-v3", "strategy": strategy_name, "human_approved": False},
            )
        return None

    def generate_metamorphic_counterfactuals(
        self,
        rule_ir: RuleIR,
        envelope: FailureEnvelope,
        *,
        seed: int = DEFAULT_TRUSTED_SEED,
    ) -> Tuple[List[str], List[str]]:
        """Generate rich metamorphic positives & tricky benign near-misses while preserving split safety."""
        bad = envelope.offending_snippet.strip()
        good = envelope.fixed_snippet.strip()
        callee = str(rule_ir.match.get("callee", "")) if isinstance(rule_ir.match, dict) else ""
        parts = callee.split(".") if callee else []
        # `evolution_v2.generate_counterfactuals` splits `callee.split(".")[0]`, which drops submodules on `a.b.fn`.
        if rule_ir.predicate_kind == "ast_pattern" and rule_ir.match.get("node") == "Call" and len(parts) > 2:
            pos: List[str] = [bad]
            neg: List[str] = [
                good,
                f"# documentation note: avoid `{bad.splitlines()[-1]}`\nx_safe = 1\n",
                f'example_doc = "{bad.splitlines()[-1]}"\n',
            ]
        else:
            pos, neg = generate_counterfactuals(rule_ir, bad, good, seed=seed)

        m = rule_ir.match
        node_type = m.get("node")
        if rule_ir.predicate_kind == "ast_pattern" and node_type == "Call":
            mod = ".".join(parts[:-1]) if len(parts) > 1 else ""
            fn = parts[-1] if parts else ""
            mode = str(m.get("mode", ""))

            if mode == "forbidden_callee":
                if mod:
                    pos.append(f"import {mod} as mod_alias\nout = mod_alias.{fn}(raw_payload)\n")
                    pos.append(f"from {mod} import {fn} as fn_alias\nout = fn_alias(\n    raw_payload,\n)\n")
                neg.append(f"# quoted example: {callee}(raw_payload)\ndoc = \"{callee}(raw_payload)\"\n")
            elif mode == "kwarg_not_in":
                kw = str(m.get("kwarg", ""))
                allowed = list(m.get("allowed_values") or [])
                if mod and allowed and isinstance(allowed[0], bool):
                    unsafe_bool = not allowed[0]
                    pos.append(
                        f"import {mod} as mod_alias\n"
                        f"out = mod_alias.{fn}(\n    arg_v,\n    extra_opt=1,\n    {kw}={repr(unsafe_bool)},\n)\n"
                    )
                    pos.append(
                        f"from {mod} import {fn} as fn_alias\n"
                        f"_CFG_FLAG = {repr(allowed[0])}\n"
                        f"_CFG_FLAG = {repr(unsafe_bool)}\n"
                        f"out = fn_alias(arg_v, {kw}=_CFG_FLAG)\n"
                    )
                    neg.append(
                        f"import {mod} as mod_alias\n"
                        f"out = mod_alias.{fn}(arg_v, {kw}={repr(allowed[0])})\n"
                    )
                    if "__MISSING__" in allowed:
                        neg.append(f"import {mod}\nout = {mod}.{fn}(arg_v)\n")
                neg.append(f'example = "{callee}(arg_v, {kw}=unsafe)"\n')

        elif rule_ir.predicate_kind == "ast_pattern" and node_type == "Assign":
            target = str(m.get("target", "flag"))
            fval = m.get("forbidden_value")
            if isinstance(fval, bool):
                pos.append(f"def fn(x):\n    return x\n{target} = {repr(not fval)}\n{target} = {repr(fval)}\n")
                neg.append(f"{target} = {1 if fval else 0}\n")
            elif fval is None:
                pos.append(f"_SHADOW = 'ok'\n_SHADOW = None\n{target} = _SHADOW\n")
                neg.append(f"def helper({target}=None):\n    return 0\n")

        pos_uniq = list(dict.fromkeys(p.strip() for p in pos if p.strip()))
        pos_set = set(pos_uniq)
        neg_uniq = list(dict.fromkeys(n.strip() for n in neg if n.strip() and n.strip() not in pos_set))
        return pos_uniq, neg_uniq

    def synthesize_candidate(
        self,
        envelope: FailureEnvelope,
        localization: Optional[CauseLocalization] = None,
        *,
        rule_id: Optional[str] = None,
        revision: int = 1,
        severity: str = "HIGH",
        use_strategy_memory: bool = True,
        preferred_strategy: Optional[str] = None,
    ) -> Tuple[RuleIR, str, str, CauseLocalization]:
        """Select the best candidate `RuleIR/1` guided by `StrategyMemory` and counterfactual checks."""
        target_id = rule_id or self._allocate_rule_id()
        _guard_no_hook_or_baseline_mutation(rule_id=target_id)
        loc = localization or self.localize_cause(envelope)

        default_order: List[Tuple[str, str]] = [
            (loc.recommended_decomposition, loc.recommended_strategy),
            ("ast_call_diff_with_safe_defaults", "ast_kwarg_policy"),
            ("ast_callee_replacement_isolation", "ast_forbidden_callee"),
            ("ast_constant_propagation_diff", "ast_assign_invariant"),
            ("path_workspace_confinement", "path_policy_guard"),
            ("lexical_bounded_token_diff", "bounded_regex_generalizer"),
        ]

        ordered_pairs: List[Tuple[str, str]] = []
        if preferred_strategy:
            ordered_pairs.append((loc.recommended_decomposition, preferred_strategy))
        if use_strategy_memory:
            for rec in self.strategy_memory.rank_strategies(task_class=loc.task_class):
                pair = (rec.decomposition_pattern, rec.synthesis_strategy)
                if pair not in ordered_pairs:
                    ordered_pairs.append(pair)
        for pair in default_order:
            if pair not in ordered_pairs:
                ordered_pairs.append(pair)

        best_choice: Optional[Tuple[RuleIR, str, str]] = None
        for decomp, strat in ordered_pairs:
            cand = self._build_rule_from_strategy(
                strat,
                envelope,
                loc,
                rule_id=target_id,
                revision=revision,
                severity=severity,
            )
            if cand is None:
                continue
            if cand.predicate_kind not in ALLOWED_PREDICATE_KINDS:
                continue
            cand.validate()
            pos, neg = self.generate_metamorphic_counterfactuals(cand, envelope)
            lang = cand.language[0] if cand.language else "python"
            all_pos_hit = all(len(evaluate_rule_ir(cand, p, language=lang)) > 0 for p in pos)
            zero_neg_fp = all(len(evaluate_rule_ir(cand, n, language=lang)) == 0 for n in neg)
            if all_pos_hit and zero_neg_fp:
                best_choice = (cand, strat, decomp)
                break
            if best_choice is None and zero_neg_fp:
                best_choice = (cand, strat, decomp)

        if best_choice is None:
            fallback_ir = self._build_rule_from_strategy(
                "bounded_regex_generalizer",
                envelope,
                loc,
                rule_id=target_id,
                revision=revision,
                severity=severity,
            )
            if fallback_ir is None:
                raise ValueError("RULE_SYNTHESIS_FAILED: Unable to synthesize valid RuleIR/1 candidate.")
            best_choice = (fallback_ir, "bounded_regex_generalizer", "lexical_bounded_token_diff")

        cand_ir, strat_used, decomp_used = best_choice
        return cand_ir, strat_used, decomp_used, loc

    # ------------------------------------------------------------------
    # Stage 4: Validation + Python <-> Rust Parity (NativeBridge + ProofPack)
    # ------------------------------------------------------------------
    def check_rule_canonical_hash_parity(self, rule_ir: RuleIR) -> Tuple[bool, Dict[str, Any]]:
        """Verify canonical `RuleIR/1` SHA-256 parity between Python and Rust (`NativeBridge`)."""
        rule_ir.validate()
        if self.native_bridge.backend == "unavailable":
            return False, {"ok": False, "reason": "NATIVE_BRIDGE_UNAVAILABLE"}
        chk = self.native_bridge.check_rule_ir(rule_ir, strict_hash=True)
        rust_hash = str(chk.get("rule_hash") or "")
        ok = bool(chk.get("ok")) and rust_hash == rule_ir.rule_hash
        return ok, chk

    def _eval_rule_rust_decision(self, rule_ir: RuleIR, code_text: str, *, language: str) -> Dict[str, Any]:
        res = self.native_bridge.evaluate_rule_ir(rule_ir, code_text, language=language)
        matched = bool(res.get("matched"))
        out: Dict[str, Any] = {
            "matched": matched,
            "decision": str(res.get("decision", "DENY" if matched else "ALLOW")),
        }
        if rule_ir.predicate_kind != "path_policy":
            out["hits_count"] = int(res.get("hits_count", 0))
        return out

    def _eval_rule_python_decision(self, rule_ir: RuleIR, code_text: str, *, language: str) -> Dict[str, Any]:
        hits = evaluate_rule_ir(rule_ir, code_text, language=language)
        matched = len(hits) > 0
        deny_dec = str(rule_ir.response.get("decision", "DENY"))
        out: Dict[str, Any] = {
            "matched": matched,
            "decision": deny_dec if matched else "ALLOW",
        }
        if rule_ir.predicate_kind != "path_policy":
            out["hits_count"] = len(hits)
        return out

    def verify_heldout_and_parity(
        self,
        rule_ir: RuleIR,
        positives: Sequence[str],
        negatives: Sequence[str],
        *,
        heldout_positives: Sequence[str] = (),
        heldout_negatives: Sequence[str] = (),
        seed: int = DEFAULT_TRUSTED_SEED,
        min_recall: float = 1.0,
    ) -> Tuple[ValidationAttestation, ProofPackReport, Dict[str, Any]]:
        """Run held-out split verification, Python<->Rust parity via ProofPack, and Wilson 95% bounds."""
        rule_ir.validate()
        pos_set = {p.strip() for p in positives if p.strip()}
        neg_set = {n.strip() for n in negatives if n.strip()}
        hpos_set = {p.strip() for p in heldout_positives if p.strip()}
        hneg_set = {n.strip() for n in heldout_negatives if n.strip()}
        if (pos_set & hpos_set) or (neg_set & hneg_set):
            raise ValueError("CORPUS_LEAKAGE: Training and held-out splits must be strictly disjoint")

        lang = rule_ir.language[0] if rule_ir.language else "python"
        all_pos = list(positives) + list(heldout_positives)
        all_neg = list(negatives) + list(heldout_negatives)
        combined_corpus = all_pos + all_neg

        hash_ok, hash_info = self.check_rule_canonical_hash_parity(rule_ir)
        latencies_ms: List[float] = []

        def _py_oracle(snippet: str) -> Dict[str, Any]:
            t0 = time.perf_counter()
            res = self._eval_rule_python_decision(rule_ir, snippet, language=lang)
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            return res

        def _rust_cand(snippet: str) -> Dict[str, Any]:
            return self._eval_rule_rust_decision(rule_ir, snippet, language=lang)

        def _prop_comment_invariance(snippet: str, cand_out: Dict[str, Any]) -> bool:
            if lang != "python" or rule_ir.predicate_kind == "path_policy":
                return True
            if not snippet.strip() or cand_out.get("matched"):
                return True
            annotated = f"# verified safe invariant check\n{snippet}"
            return not self._eval_rule_python_decision(rule_ir, annotated, language=lang)["matched"]

        if self.native_bridge.backend == "unavailable" or not hash_ok:
            diff_report = ProofPackReport(
                report_id=f"evo3-parity-{rule_ir.rule_id}",
                status="FAIL",
                verified_independently=True,
                proof_levels=[],
                reasons=["RUST_HASH_OR_BRIDGE_UNAVAILABLE" if not hash_ok else "NATIVE_BRIDGE_UNAVAILABLE"],
            )
            parity_mismatches = max(1, len(combined_corpus))
        else:
            diff_report = ProofPack.run_differential_corpus(
                _py_oracle,
                _rust_cand,
                combined_corpus,
                property_checks=[_prop_comment_invariance],
                seed=seed,
                exact=True,
                proof_level=ProofLevel.DIFFERENTIAL_VERIFIED,
                report_id=f"evo3-parity-{rule_ir.rule_id}",
            )
            parity_mismatches = int((diff_report.differential_summary or {}).get("mismatches", 0))
            if not diff_report.ok:
                parity_mismatches = max(1, parity_mismatches)

        caught_pos = sum(1 for item in all_pos if self._eval_rule_python_decision(rule_ir, item, language=lang)["matched"])
        fp_count = sum(1 for item in all_neg if self._eval_rule_python_decision(rule_ir, item, language=lang)["matched"])
        recall = caught_pos / max(1, len(all_pos))
        _, fp_ub_95 = compute_wilson_interval(fp_count, len(all_neg))

        passed = (
            hash_ok
            and fp_count == 0
            and recall >= min_recall
            and parity_mismatches == 0
            and len(all_pos) > 0
            and diff_report.ok
        )

        attestation = ValidationAttestation(
            candidate_hash=rule_ir.rule_hash,
            corpus_hashes={
                "positive": sha256_digest(all_pos),
                "negative": sha256_digest(all_neg),
                "private_holdout": sha256_digest({"p": list(heldout_positives), "n": list(heldout_negatives)}),
            },
            seed=seed,
            tested_positive=len(all_pos),
            caught_positive=caught_pos,
            tested_negative=len(all_neg),
            false_positives=fp_count,
            fp_upper_bound_95=fp_ub_95,
            python_rust_decision_mismatches=parity_mismatches,
            status="SHADOW_ONLY" if passed else "REJECTED",
        )
        metrics = {
            "hash_verified": hash_ok,
            "hash_check": hash_info,
            "parity_mismatches": parity_mismatches,
            "p95_latency_ms": _percentile_95(latencies_ms),
            "honest_fp": honest_metric_summary(fp_count, len(all_neg), metric="validation_false_positive_rate"),
            "honest_recall": honest_metric_summary(caught_pos, len(all_pos), metric="validation_recall"),
        }
        return attestation, diff_report, metrics

    # ------------------------------------------------------------------
    # Stage 5: Monotonic Shadow -> Canary -> Enforced + Rollback
    # ------------------------------------------------------------------
    def current_stage(self, rule_id: str, revision: int) -> str:
        return self._stage_by_rev.get((rule_id, int(revision)), "unpromoted")

    def promote_shadow(
        self,
        rule_ir: RuleIR,
        attestation: ValidationAttestation,
        *,
        proof_report: Optional[ProofPackReport] = None,
    ) -> Dict[str, Any]:
        """Promote a verified candidate into `shadow` mode after checking hash and parity attestation."""
        _guard_no_hook_or_baseline_mutation(rule_id=rule_ir.rule_id)
        if proof_report is not None and not proof_report.ok:
            raise ValueError("PROMOTION_GATE_FAILED: ProofPackReport must PASS before shadow promotion.")
        hash_ok, _ = self.check_rule_canonical_hash_parity(rule_ir)
        if not hash_ok:
            raise ValueError("PROMOTION_GATE_FAILED: Rust canonical RuleIR/1 hash verification failed.")

        receipt = self.registry.promote(rule_ir, attestation, mode="shadow", reviewer_approved=False)
        self._stage_by_rev[(rule_ir.rule_id, int(rule_ir.revision))] = "shadow"
        return receipt

    def promote_canary(
        self,
        rule_ir: RuleIR,
        attestation: ValidationAttestation,
        canary_soak_corpus: Sequence[str],
        *,
        language: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], CanarySoakReport]:
        """Soak a `shadow` rule over benign & held-out negatives requiring 0 FP and 0 Python<->Rust mismatches."""
        _guard_no_hook_or_baseline_mutation(rule_id=rule_ir.rule_id)
        rev = int(rule_ir.revision)
        cur_stage = self.current_stage(rule_ir.rule_id, rev)
        if cur_stage != "shadow":
            raise ValueError(
                f"PROMOTION_GATE_FAILED: Canary soak requires prior 'shadow' promotion (current={cur_stage})."
            )

        soak_items = [s for s in canary_soak_corpus if isinstance(s, str) and s.strip()]
        if not soak_items:
            raise ValueError("PROMOTION_GATE_FAILED: Canary soak requires non-empty negative corpus.")

        lang = (language or (rule_ir.language[0] if rule_ir.language else "python")).strip().lower()
        fp_count = 0
        parity_mismatches = 0
        latencies_ms: List[float] = []

        for snippet in soak_items:
            t0 = time.perf_counter()
            py_dec = self._eval_rule_python_decision(rule_ir, snippet, language=lang)
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            rs_dec = self._eval_rule_rust_decision(rule_ir, snippet, language=lang)
            if py_dec != rs_dec:
                parity_mismatches += 1
            if py_dec["matched"] or rs_dec["matched"]:
                fp_count += 1

        honest_fp = honest_metric_summary(fp_count, len(soak_items), metric="canary_false_positive_rate")
        passed = fp_count == 0 and parity_mismatches == 0
        soak_report = CanarySoakReport(
            rule_id=rule_ir.rule_id,
            revision=rev,
            rule_hash=rule_ir.rule_hash,
            tested_negatives=len(soak_items),
            false_positives=fp_count,
            observed_fraction=honest_fp["observed_fraction"],
            fp_upper_bound_95=honest_fp["wilson_upper_bound_95"],
            parity_mismatches=parity_mismatches,
            p95_latency_ms=_percentile_95(latencies_ms),
            corpus_digest=sha256_digest(soak_items),
            passed=passed,
            honest_fp_summary=honest_fp,
        )
        if not passed:
            raise ValueError(
                f"CANARY_SOAK_FAILED: fp={fp_count}/{len(soak_items)}, parity_mismatches={parity_mismatches}"
            )

        receipt = self.registry.promote(rule_ir, attestation, mode="canary", reviewer_approved=False)
        self._stage_by_rev[(rule_ir.rule_id, rev)] = "canary"
        self._canary_reports[(rule_ir.rule_id, rev)] = soak_report
        return receipt, soak_report

    def promote_enforced(
        self,
        rule_ir: RuleIR,
        attestation: ValidationAttestation,
        *,
        reviewer_approved: bool = False,
    ) -> Dict[str, Any]:
        """Promote a `canary`-soaked rule to `enforced` ONLY when `reviewer_approved=True`."""
        _guard_no_hook_or_baseline_mutation(rule_id=rule_ir.rule_id)
        rev = int(rule_ir.revision)
        cur_stage = self.current_stage(rule_ir.rule_id, rev)
        if cur_stage != "canary":
            raise ValueError(
                f"PROMOTION_GATE_FAILED: Cannot jump directly to 'enforced' without 'canary' soak (current={cur_stage})."
            )
        canary_rep = self._canary_reports.get((rule_ir.rule_id, rev))
        if canary_rep is None or not canary_rep.passed:
            raise ValueError("PROMOTION_GATE_FAILED: Valid passing CanarySoakReport required before 'enforced'.")
        if reviewer_approved is not True:
            raise ValueError("PROMOTION_GATE_FAILED: Enforced promotion requires reviewer_approved=True.")

        receipt = self.registry.promote(rule_ir, attestation, mode="enforced", reviewer_approved=True)
        self._stage_by_rev[(rule_ir.rule_id, rev)] = "enforced"
        return receipt

    def promote_stage(
        self,
        rule_ir: RuleIR,
        attestation: ValidationAttestation,
        *,
        mode: str,
        reviewer_approved: bool = False,
        canary_soak_corpus: Optional[Sequence[str]] = None,
        proof_report: Optional[ProofPackReport] = None,
    ) -> Dict[str, Any]:
        """Strict unified promotion entry enforcing `shadow -> canary -> enforced`."""
        norm_mode = mode.strip().lower()
        if norm_mode == "shadow":
            return self.promote_shadow(rule_ir, attestation, proof_report=proof_report)
        if norm_mode == "canary":
            receipt, _ = self.promote_canary(rule_ir, attestation, canary_soak_corpus or ())
            return receipt
        if norm_mode == "enforced":
            return self.promote_enforced(rule_ir, attestation, reviewer_approved=reviewer_approved)
        raise ValueError(f"Invalid promotion mode: {mode}")

    def rollback(self, rule_id: str, *, to_revision: int) -> Dict[str, Any]:
        """Atomically roll back an evolved rule to `to_revision` while protecting baseline scars."""
        _guard_no_hook_or_baseline_mutation(rule_id=rule_id)
        receipt = self.registry.rollback(rule_id, to_revision=to_revision)
        active_entry = self.registry.active.get(rule_id) or {}
        restored_mode = str(active_entry.get("mode", "shadow"))
        self._stage_by_rev[(rule_id, int(to_revision))] = restored_mode
        return {
            **receipt,
            "restored_mode": restored_mode,
            "restored_rule": dict(active_entry.get("rule") or {}),
        }

    def get_active_rules(self, *, modes: Optional[Sequence[str]] = None) -> List[RuleIR]:
        """Return validated `RuleIR/1` instances currently active in `EvolutionRegistry`."""
        allowed_modes = {m.lower() for m in modes} if modes is not None else {"shadow", "canary", "enforced"}
        out: List[RuleIR] = []
        for entry in self.registry.active.values():
            if str(entry.get("mode", "")).lower() not in allowed_modes:
                continue
            rule_dict = entry.get("rule")
            if isinstance(rule_dict, dict):
                out.append(RuleIR.from_dict(rule_dict))
        return out

    # ------------------------------------------------------------------
    # End-to-End Pipeline Orchestration
    # ------------------------------------------------------------------
    def evolve_from_failure(
        self,
        failure: Union[FailureEnvelope, UnseenFailure, Mapping[str, Any]],
        *,
        rule_id: Optional[str] = None,
        revision: int = 1,
        severity: str = "HIGH",
        heldout_positives: Sequence[str] = (),
        heldout_negatives: Sequence[str] = (),
        canary_negatives: Sequence[str] = (),
        promote_to: str = "enforced",
        reviewer_approved: bool = False,
        use_strategy_memory: bool = True,
        persist_trace: bool = False,
    ) -> EvolutionCandidateResult:
        """Run full Stage 5 pipeline from `UnseenFailure` through Parity, Canary, and Promotion."""
        t0 = time.perf_counter()
        envelope, meta = self.ingest_failure(failure, persist_trace=persist_trace)
        loc = self.localize_cause(
            envelope,
            task_class=str(meta.get("task_class") or ""),
            file_path=meta.get("file_path") or None,
            config_hints=meta.get("config_hints") or None,
        )
        rule_ir, strat_used, decomp_used, loc = self.synthesize_candidate(
            envelope,
            loc,
            rule_id=rule_id,
            revision=revision,
            severity=severity,
            use_strategy_memory=use_strategy_memory,
        )
        pos, neg = self.generate_metamorphic_counterfactuals(rule_ir, envelope)
        attestation, proof_report, val_metrics = self.verify_heldout_and_parity(
            rule_ir,
            pos,
            neg,
            heldout_positives=heldout_positives,
            heldout_negatives=heldout_negatives,
        )
        if attestation.status == "REJECTED":
            self.strategy_memory.record_outcome(
                task_class=loc.task_class,
                decomposition_pattern=decomp_used,
                synthesis_strategy=strat_used,
                verified_outcome=False,
                cost_ms=(time.perf_counter() - t0) * 1000.0,
                task_id=envelope.task_id,
                failure_reason=f"attestation_rejected:fp={attestation.false_positives},parity={attestation.python_rust_decision_mismatches}",
            )
            raise ValueError(
                f"CANDIDATE_VALIDATION_FAILED: fp={attestation.false_positives}, "
                f"caught={attestation.caught_positive}/{attestation.tested_positive}, "
                f"parity_mismatches={attestation.python_rust_decision_mismatches}"
            )

        norm_target_stage = promote_to.strip().lower()
        if norm_target_stage not in {"unpromoted", *EVOLUTION_STAGES}:
            raise ValueError(f"Invalid promote_to stage: {promote_to}")

        canary_rep: Optional[CanarySoakReport] = None
        final_stage = "unpromoted"
        if norm_target_stage in EVOLUTION_STAGES:
            self.promote_shadow(rule_ir, attestation, proof_report=proof_report)
            final_stage = "shadow"
        if norm_target_stage in {"canary", "enforced"}:
            soak_corpus = list(canary_negatives) if canary_negatives else list(neg) + list(heldout_negatives)
            _, canary_rep = self.promote_canary(rule_ir, attestation, soak_corpus)
            final_stage = "canary"
        if norm_target_stage == "enforced":
            self.promote_enforced(rule_ir, attestation, reviewer_approved=reviewer_approved)
            final_stage = "enforced"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.strategy_memory.record_outcome(
            task_class=loc.task_class,
            decomposition_pattern=decomp_used,
            synthesis_strategy=strat_used,
            verified_outcome=True,
            cost_ms=elapsed_ms,
            task_id=envelope.task_id,
            source_family=envelope.task_id,
            evidence_digest=attestation.candidate_hash,
        )

        return EvolutionCandidateResult(
            envelope=envelope,
            localization=loc,
            rule_ir=rule_ir,
            positives=pos,
            negatives=neg,
            attestation=attestation,
            proof_pack_report=proof_report,
            strategy_used=strat_used,
            decomposition_pattern=decomp_used,
            parity_mismatches=int(val_metrics["parity_mismatches"]),
            canonical_hash_verified=bool(val_metrics["hash_verified"]),
            p95_latency_ms=float(val_metrics["p95_latency_ms"]),
            stage=final_stage,
            canary_report=canary_rep,
        )

    # ------------------------------------------------------------------
    # Stage 5 Cross-Task Blind Generalization Benchmark
    # ------------------------------------------------------------------
    def _evaluate_rule_set_python_and_rust(
        self,
        baseline_scanner: KintsugiScanner,
        evolved_rules: Sequence[RuleIR],
        code_text: str,
        *,
        language: str,
    ) -> Tuple[bool, bool, int, float]:
        t0 = time.perf_counter()
        base_hits = baseline_scanner.scan_text(code_text, file_path=f"<eval.{language}>", language=language)
        base_hit = len(base_hits) > 0

        py_evo_hit = False
        rs_evo_hit = False
        parity_mismatches = 0
        for rule_ir in evolved_rules:
            if language not in rule_ir.language:
                continue
            py_m = self._eval_rule_python_decision(rule_ir, code_text, language=language)
            rs_m = self._eval_rule_rust_decision(rule_ir, code_text, language=language)
            if py_m != rs_m:
                parity_mismatches += 1
            if py_m["matched"]:
                py_evo_hit = True
            if rs_m["matched"]:
                rs_evo_hit = True

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return (base_hit or py_evo_hit), (base_hit or rs_evo_hit), parity_mismatches, elapsed_ms

    def count_baseline_regressions(
        self,
        baseline_scars: Sequence[GoldenScar],
        evolved_rules: Sequence[RuleIR],
    ) -> int:
        """Verify 0 regressions across protected baseline scars (`KS-001..KS-024`) `bad_code` and `good_code`."""
        baseline_scanner = KintsugiScanner(list(baseline_scars), allow_inline_ignores=False)
        regressions = 0
        for scar in baseline_scars:
            lang = scar.languages[0] if scar.languages else "python"
            bad_hits = baseline_scanner.scan_text(scar.bad_code, file_path=f"<base_bad.{lang}>", language=lang)
            if not any(f.scar_id == scar.id for f in bad_hits):
                regressions += 1
                continue

            good_base = baseline_scanner.scan_text(scar.good_code, file_path=f"<base_good.{lang}>", language=lang)
            good_evo = any(
                self._eval_rule_python_decision(r, scar.good_code, language=lang)["matched"]
                for r in evolved_rules
                if lang in r.language
            )
            if good_base or good_evo:
                regressions += 1
        return regressions

    def run_cross_task_blind_transfer_eval(
        self,
        train_families: Sequence[Mapping[str, Any]],
        blind_heldout_families: Sequence[Mapping[str, Any]],
        baseline_scars: Optional[Sequence[GoldenScar]] = None,
    ) -> BlindTransferReport:
        """Train strictly on `train_families` and evaluate blind held-out generalization vs `no_memory_control`."""
        active_baseline = list(baseline_scars) if baseline_scars is not None else get_full_crs_scars()
        baseline_scanner = KintsugiScanner(active_baseline, allow_inline_ignores=False)

        # 1. Enforce zero corpus leakage between train and blind heldout splits
        train_texts: set[str] = set()
        for fam in train_families:
            for key in ("offending_snippet", "fixed_snippet"):
                val = str(fam.get(key) or "").strip()
                if val:
                    train_texts.add(val)
            for list_key in ("positives", "negatives", "canary_negatives"):
                for item in fam.get(list_key) or ():
                    if str(item).strip():
                        train_texts.add(str(item).strip())

        blind_texts: set[str] = set()
        for fam in blind_heldout_families:
            for list_key in ("positives", "negatives"):
                for item in fam.get(list_key) or ():
                    if str(item).strip():
                        blind_texts.add(str(item).strip())

        if train_texts & blind_texts:
            raise ValueError("CORPUS_LEAKAGE: train_families and blind_heldout_families share identical snippets.")

        # 2. Train strictly on train_families (no access to blind_heldout_families)
        trained_results: List[EvolutionCandidateResult] = []
        prior_source_by_task_class: Dict[str, Tuple[str, str]] = {}
        canary_baseline_good = [s.good_code for s in active_baseline if "python" in s.languages and s.good_code.strip()]

        for idx, fam in enumerate(train_families):
            fam_id = str(fam.get("family_id") or fam.get("task_id") or f"train-fam-{idx}")
            lang = str(fam.get("language") or "python").lower()
            sev = str(fam.get("severity") or "HIGH")
            canary_pool = list(fam.get("canary_negatives") or []) + list(fam.get("negatives") or [])
            if lang == "python":
                canary_pool.extend(canary_baseline_good[:8])

            failure = UnseenFailure(
                task_id=fam_id,
                language=lang,
                offending_snippet=str(fam["offending_snippet"]),
                fixed_snippet=str(fam["fixed_snippet"]),
                error_summary=str(fam.get("error_summary") or f"Unseen failure in {fam_id}"),
                task_class=str(fam.get("task_class") or ""),
                file_path=str(fam.get("file_path") or ""),
                config_hints=dict(fam.get("config_hints") or {}),
                split="train",
            )
            res = self.evolve_from_failure(
                failure,
                severity=sev,
                canary_negatives=canary_pool,
                promote_to="enforced",
                reviewer_approved=True,
                use_strategy_memory=True,
            )
            trained_results.append(res)

            tc = res.localization.task_class
            if tc in prior_source_by_task_class:
                src_task_id, src_fam = prior_source_by_task_class[tc]
                self.strategy_memory.record_outcome(
                    task_class=tc,
                    decomposition_pattern=res.decomposition_pattern,
                    synthesis_strategy=res.strategy_used,
                    verified_outcome=True,
                    cost_ms=res.p95_latency_ms,
                    task_id=fam_id,
                    source_task_id=src_task_id,
                    source_family=src_fam,
                    target_family=fam_id,
                    evidence_digest=res.attestation.candidate_hash,
                    is_cross_task_transfer=True,
                    causal_verified=True,
                )
            else:
                prior_source_by_task_class[tc] = (fam_id, fam_id)

        evolved_rules = self.get_active_rules(modes=("enforced",))
        evolved_rule_ids = [r.rule_id for r in evolved_rules]

        # 3. Evaluate no_memory_control (baseline scars only) vs evolved on blind_heldout_families
        ctrl_caught = 0
        ctrl_fp = 0
        ctrl_latencies: List[float] = []

        evo_caught = 0
        evo_fp = 0
        evo_latencies: List[float] = []
        total_pos = 0
        total_neg = 0
        total_parity_mismatches = 0
        per_family_recall: Dict[str, float] = {}
        blind_corpus_records: List[Tuple[str, str]] = []
        family_transfer_events: List[Tuple[str, str, int, int, int]] = []

        def _score_split(items: Sequence[str], lang: str, tag: str) -> Tuple[int, int, int]:
            c_hits = 0
            e_hits = 0
            mm_total = 0
            for snip in items:
                blind_corpus_records.append((lang, snip))
                tc0 = time.perf_counter()
                if baseline_scanner.scan_text(snip, file_path=f"<{tag}.{lang}>", language=lang):
                    c_hits += 1
                ctrl_latencies.append((time.perf_counter() - tc0) * 1000.0)
                py_hit, rs_hit, mm, e_ms = self._evaluate_rule_set_python_and_rust(
                    baseline_scanner, evolved_rules, snip, language=lang
                )
                evo_latencies.append(e_ms)
                mm_total += mm + (1 if py_hit != rs_hit else 0)
                if (py_hit and rs_hit) if tag == "ctrl" else (py_hit or rs_hit):
                    e_hits += 1
            return c_hits, e_hits, mm_total

        for idx, fam in enumerate(blind_heldout_families):
            fam_id = str(fam.get("family_id") or f"blind-fam-{idx}")
            fam_tc = str(fam.get("task_class") or "")
            lang = str(fam.get("language") or "python").lower()
            pos_list = [str(x) for x in (fam.get("positives") or []) if str(x).strip()]
            neg_list = [str(x) for x in (fam.get("negatives") or []) if str(x).strip()]

            total_pos += len(pos_list)
            total_neg += len(neg_list)
            c_pos, fam_caught, mm_pos = _score_split(pos_list, lang, "ctrl")
            c_neg, fam_fp, mm_neg = _score_split(neg_list, lang, "ctrl_neg")
            ctrl_caught += c_pos
            ctrl_fp += c_neg
            evo_caught += fam_caught
            evo_fp += fam_fp
            total_parity_mismatches += mm_pos + mm_neg

            per_family_recall[fam_id] = round(fam_caught / max(1, len(pos_list)), 6)
            family_transfer_events.append((fam_id, fam_tc, fam_caught, len(pos_list), fam_fp))

        # 4. Differential ProofPack report over blind heldout rules
        def _blind_py_decisions(item: Tuple[str, str]) -> List[bool]:
            lg, txt = item
            return [
                self._eval_rule_python_decision(r, txt, language=lg)["matched"]
                for r in evolved_rules
                if lg in r.language
            ]

        def _blind_rs_decisions(item: Tuple[str, str]) -> List[bool]:
            lg, txt = item
            return [
                self._eval_rule_rust_decision(r, txt, language=lg)["matched"]
                for r in evolved_rules
                if lg in r.language
            ]

        proof_rep = ProofPack.run_differential_corpus(
            _blind_py_decisions,
            _blind_rs_decisions,
            blind_corpus_records,
            exact=True,
            report_id="evo3-blind-transfer-parity",
        )
        diff_mm = int((proof_rep.differential_summary or {}).get("mismatches", 0))
        total_parity_mismatches = max(total_parity_mismatches, diff_mm)

        # 5. Record verified blind causal transfer outcomes strictly AFTER blind evaluation
        for fam_id, fam_tc, fam_caught, fam_pos_n, fam_fp in family_transfer_events:
            matching_train = [
                tr for tr in trained_results
                if (not fam_tc or tr.localization.task_class == fam_tc)
            ] or trained_results
            for tr in matching_train[:1]:
                ok_transfer = fam_caught == fam_pos_n and fam_pos_n > 0 and fam_fp == 0 and total_parity_mismatches == 0
                self.strategy_memory.record_outcome(
                    task_class=tr.localization.task_class,
                    decomposition_pattern=tr.decomposition_pattern,
                    synthesis_strategy=tr.strategy_used,
                    verified_outcome=ok_transfer,
                    cost_ms=tr.p95_latency_ms,
                    task_id=f"blind:{fam_id}",
                    source_task_id=tr.envelope.task_id,
                    source_family=tr.envelope.task_id,
                    target_family=f"blind:{fam_id}",
                    evidence_digest=tr.attestation.candidate_hash,
                    is_cross_task_transfer=ok_transfer,
                    causal_verified=ok_transfer,
                    failure_reason="" if ok_transfer else f"blind_transfer_miss:{fam_caught}/{fam_pos_n},fp={fam_fp}",
                )

        # 6. Baseline scar regression check + honest statistical summary
        baseline_regressions = self.count_baseline_regressions(active_baseline, evolved_rules)
        family_recall = round(evo_caught / max(1, total_pos), 6)
        negative_precision = round((total_neg - evo_fp) / max(1, total_neg), 6)
        honest_fp = honest_metric_summary(evo_fp, total_neg, metric="blind_heldout_false_positive_rate")
        honest_rec = honest_metric_summary(evo_caught, total_pos, metric="blind_heldout_family_recall")

        ctrl_recall = round(ctrl_caught / max(1, total_pos), 6)
        ctrl_neg_prec = round((total_neg - ctrl_fp) / max(1, total_neg), 6)
        no_mem_ctrl = {
            "family_recall": ctrl_recall,
            "negative_precision": ctrl_neg_prec,
            "caught": ctrl_caught,
            "total_positives": total_pos,
            "false_positives": ctrl_fp,
            "total_negatives": total_neg,
            "p95_latency_ms": _percentile_95(ctrl_latencies),
        }

        rankings_by_tc: Dict[str, List[Dict[str, Any]]] = {}
        for rec in self.strategy_memory.rank_strategies():
            rankings_by_tc.setdefault(rec.task_class, []).append(rec.to_dict())

        return BlindTransferReport(
            family_recall=family_recall,
            negative_precision=negative_precision,
            fp_upper_bound_95=honest_fp["wilson_upper_bound_95"],
            parity_mismatches=total_parity_mismatches,
            p95_latency_ms=_percentile_95(evo_latencies),
            baseline_regression_count=baseline_regressions,
            recall_numerator=evo_caught,
            recall_denominator=total_pos,
            recall_lower_bound_95=honest_rec["wilson_lower_bound_95"],
            false_positives=evo_fp,
            tested_negatives=total_neg,
            per_family_recall=per_family_recall,
            no_memory_control=no_mem_ctrl,
            recall_gain=round(family_recall - ctrl_recall, 6),
            evolved_rule_ids=evolved_rule_ids,
            strategy_memory_rankings=rankings_by_tc,
            honest_fp_summary=honest_fp,
            honest_recall_summary=honest_rec,
            proof_pack_summary=proof_rep.to_dict(),
        )

    def run_sealed_blind_eval(
        self,
        corpus_path: Union[str, Path],
        *,
        expected_sha256: str,
        train_families: Sequence[Mapping[str, Any]],
        baseline_scars: Optional[Sequence[GoldenScar]] = None,
    ) -> BlindTransferReport:
        """Evaluate blind transfer against an external, `O_NOFOLLOW` + SHA-256 verified held-out corpus."""
        cp = Path(corpus_path).expanduser()
        assert_not_symlink(cp)
        if _is_within(cp, self.workspace_root):
            raise PermissionError(
                f"SEALED_CORPUS_MUST_BE_EXTERNAL: Refusing sealed corpus inside workspace_root ({cp})."
            )
        expected_norm = _normalize_sha256_pin(expected_sha256)
        raw_bytes, actual_sha = _read_and_hash_regular_nofollow(cp, max_bytes=8 * 1024 * 1024)
        if not hmac.compare_digest(actual_sha, expected_norm):
            raise PermissionError(
                f"SEALED_CORPUS_SHA256_MISMATCH: actual={actual_sha} != expected={expected_norm}"
            )
        payload = json.loads(raw_bytes.decode("utf-8"))
        if isinstance(payload, Mapping) and "families" in payload:
            raw_families = payload["families"]
        elif isinstance(payload, list):
            raw_families = payload
        else:
            raise ValueError("INVALID_SEALED_CORPUS: Expected JSON list or object with 'families' key.")
        if not isinstance(raw_families, list) or not all(isinstance(item, Mapping) for item in raw_families):
            raise ValueError("INVALID_SEALED_CORPUS: 'families' must be a list of JSON objects.")

        report = self.run_cross_task_blind_transfer_eval(
            train_families,
            raw_families,
            baseline_scars=baseline_scars,
        )
        report.no_memory_control["corpus_origin"] = "external_sealed_verified"
        report.no_memory_control["corpus_sha256"] = expected_norm
        report.no_memory_control["honest_note"] = (
            "Evaluated on external sealed held-out corpus verified via O_NOFOLLOW + SHA-256 prior to parse; "
            "finite empirical sample observation only, not a universal generalization guarantee."
        )
        return report

    @staticmethod
    def consolidation_plan(scars: Optional[Sequence[GoldenScar]] = None) -> Dict[str, Any]:
        """Delegate read-only ledger duplicate analysis to `evolution_v2.plan_ledger_consolidation`."""
        return plan_ledger_consolidation(list(scars) if scars is not None else get_full_crs_scars())


__all__ = [
    "EVOLUTION_STAGES",
    "EVOLUTION_V3_SCHEMA",
    "IMMUTABLE_BASELINE_IDS",
    "IMMUTABLE_HOOK_TARGETS",
    "PROTECTED_BASELINE_IDS",
    "BlindTransferReport",
    "CanarySoakReport",
    "CauseLocalization",
    "EvolutionCandidateResult",
    "SelfEvolutionEngineV3",
    "UnseenFailure",
    "honest_metric_summary",
]
