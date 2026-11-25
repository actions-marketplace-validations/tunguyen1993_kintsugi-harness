"""Stage 5 Causal Counterfactual & Adaptive Token Economics Self-Evolution Engine v4 (`kintsugi.evolution.evolution_v4`).

Implements Build #3's verified causal self-evolution architecture alongside `evolution_v3`:
  - `CausalAblationResult`: counterfactual matched-pair ablation (`with_strategy` vs
    `without_strategy`) across strictly disjoint `train_families` and `heldout_families`,
    ranked via exact Wilson score lower bound (`z=1.96`) and Newcombe uplift lower bound
    so tiny-N noisy wins (e.g. 2/2) cannot outrank proven transfer strategies (e.g. 19/20).
  - `AdaptiveBudgetController`: isolates `ExecutionMode.LOCAL_RESEARCH` (high-throughput
    multi-round hypothesis exploration + dynamic variance-driven scaling) from
    `ExecutionMode.GITHUB_PUBLIC` (strict fail-closed token/step/latency budgets via exact
    `Decimal` and `int` arithmetic).
  - `MonotonicPromotionLedger` & `EvolutionEngineV4`: enforces the monotonic lifecycle
    `CANDIDATE -> SHADOW -> CANARY -> ENFORCED` + automatic fail-fast `ROLLED_BACK`
    whenever a canary or enforced verification slice regresses below pinned baseline,
    restoring the previous active pointer atomically (`0o600`, `O_NOFOLLOW`, symlink-guarded).
  - Immutable security protection invariant: strictly refuses any strategy or mutation
    attempting to weaken `KS-001..KS-036`, `KS-S3-01..KS-S3-04`, `hooks.py`,
    `PreToolUse`, `secure_runner`, or `attestation_authority`.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
import os
import re
import stat
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.schemas import (
    assert_no_raw_secrets,
    canonical_json_dumps,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.config import KintsugiConfig, OperatingProfile, SECURITY_BASELINE_VALUES
from kintsugi.evolution.evolution_v3 import IMMUTABLE_HOOK_TARGETS
from kintsugi.evolution.strategy_memory import (
    DEFAULT_STRATEGY_MEMORY_REL_PATH,
    StrategyMemory,
    compute_wilson_interval,
)
from kintsugi.evolution_v2 import PROTECTED_BASELINE_IDS
from kintsugi.runtime.secure_runner import redact_runtime_text, redact_runtime_value
from kintsugi.runtime.token_economics import BudgetExceededError, TokenEconomicsTracker
from kintsugi.shield import (
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    _S3_EXTERNAL_INJECTION_RE,
    assert_not_symlink,
    atomic_write_json,
    resolve_safe_child_path,
    scan_artifact_egress,
)

EVOLUTION_V4_SCHEMA = "SelfEvolutionV4/1"
CAUSAL_ABLATION_SCHEMA = "CausalAblationResult/1"
PROMOTION_LEDGER_SCHEMA = "MonotonicPromotionLedger/1"
BUDGET_CONTROLLER_SCHEMA = "AdaptiveBudgetController/1"
DEFAULT_PROMOTION_LEDGER_REL_PATH = ".kintsugi/evolution_v4_ledger.json"
DEFAULT_WILSON_Z = 1.96

_DECIMAL_QUANT = Decimal("0.000001")
_ZERO_DEC = Decimal("0")
_ONE_DEC = Decimal("1")

IMMUTABLE_GUARDRAIL_IDS: FrozenSet[str] = frozenset(
    {
        *(f"KS-{i:03d}" for i in range(1, 37)),
        *(f"KS-S3-{i:02d}" for i in range(1, 5)),
        *PROTECTED_BASELINE_IDS,
    }
)

IMMUTABLE_SECURITY_MODULES: FrozenSet[str] = frozenset(
    {
        *IMMUTABLE_HOOK_TARGETS,
        "secure_runner",
        "secure_runner.py",
        "runtime/secure_runner.py",
        "attestation_authority",
        "attestationauthority",
        "tool_registry.py",
        "capability/tool_registry.py",
        "shield.py",
        "config.py",
        "security_baseline",
    }
)

FORBIDDEN_MUTATION_KEYS: FrozenSet[str] = frozenset(
    {
        "disable_guardrails",
        "skip_verification",
        "bypass_scars",
        "mutate_hooks",
        "hooks_override",
        "override_pretooluse",
        "disable_pretooluse",
        "bypass_security",
        "skip_security",
        "weaken_security",
        "disable_attestation",
        "bypass_attestation",
        "disable_scanner",
        "disable_baseline",
        "suppress_ks_rules",
        "weaken_baseline",
        "allow_untrusted_native",
        "policy_override",
        *SECURITY_BASELINE_VALUES.keys(),
    }
)

_TARGET_INSPECTION_KEYS: FrozenSet[str] = frozenset(
    {
        "rule_id",
        "target_rule_id",
        "replaces_rule_id",
        "disabled_rules",
        "disable_rules",
        "weaken_rules",
        "mutation_target",
        "target_file",
        "target_module",
        "hook_target",
        "patch_target",
        "target_component",
        "affected_components",
        "touched_paths",
        "target",
    }
)

_GUARDRAIL_ID_RE = re.compile(r"\bKS-(?:0(?:0[1-9]|[12]\d|3[0-6])|S3-0[1-4])\b", re.IGNORECASE)
_GUARDRAIL_TARGET_RE = re.compile(
    r"(?:hooks\.py|pretooluse|claude-pre-tool|secure_runner|attestation_authority|attestationauthority|"
    r"security_baseline|tool_registry\.py|shield\.py|scanner\.py|rust/src/lib\.rs|rust/src/ffi\.rs)",
    re.IGNORECASE,
)
_WEAKEN_VERB_RE = re.compile(
    r"\b(?:disable|bypass|weaken|remove|delete|drop|override|skip|relax|mutate|modify|replace|"
    r"patch|tamper|circumvent|suppress|turn_off|off)\b",
    re.IGNORECASE,
)
_VALID_STRATEGY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ExecutionMode(str, Enum):
    """Execution governance modes aligned 1:1 with `OperatingProfile`."""

    LOCAL_RESEARCH = OperatingProfile.LOCAL_RESEARCH.value
    GITHUB_PUBLIC = OperatingProfile.GITHUB_PUBLIC.value


class StrategyStage(str, Enum):
    """Monotonic causal promotion lifecycle stages (`CANDIDATE -> SHADOW -> CANARY -> ENFORCED` + `ROLLED_BACK`)."""

    CANDIDATE = "CANDIDATE"
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    ENFORCED = "ENFORCED"
    ROLLED_BACK = "ROLLED_BACK"


MONOTONIC_STAGE_TRANSITIONS: Mapping[Optional[StrategyStage], FrozenSet[StrategyStage]] = {
    None: frozenset({StrategyStage.CANDIDATE}),
    StrategyStage.CANDIDATE: frozenset({StrategyStage.SHADOW}),
    StrategyStage.SHADOW: frozenset({StrategyStage.CANARY, StrategyStage.ROLLED_BACK}),
    StrategyStage.CANARY: frozenset({StrategyStage.ENFORCED, StrategyStage.ROLLED_BACK}),
    StrategyStage.ENFORCED: frozenset({StrategyStage.ROLLED_BACK}),
    StrategyStage.ROLLED_BACK: frozenset(),
}


class CorpusLeakageError(ValueError):
    """Raised when `train_families` and `heldout_families` overlap or share leaked artifacts."""


class ImmutableGuardrailError(PermissionError, ValueError):
    """Raised when a strategy attempts to weaken protected security guardrails or core trust modules."""


class PromotionGateError(ValueError):
    """Raised when a candidate fails monotonic promotion gates or attempts an invalid stage jump."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strict_bool(value: Any, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"INVALID_STRICT_BOOL ({field_name}): expected exact bool, got {type(value).__name__}")
    return value


def _strict_nonneg_int(value: Any, *, field_name: str) -> int:
    if type(value) is not int:
        raise ValueError(f"INVALID_INT ({field_name}): expected strict int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"NEGATIVE_INT ({field_name}): must be >= 0, got {value}")
    return value


def _strict_pos_int(value: Any, *, field_name: str) -> int:
    parsed = _strict_nonneg_int(value, field_name=field_name)
    if parsed < 1:
        raise ValueError(f"INVALID_POSITIVE_INT ({field_name}): must be >= 1, got {parsed}")
    return parsed


def _to_exact_decimal(
    value: Any,
    *,
    field_name: str,
    allow_zero: bool = True,
) -> Decimal:
    """Parse strict finite non-negative `Decimal` (rejecting booleans, NaN, Infinity, and negatives)."""
    if isinstance(value, bool) or value is None:
        raise ValueError(f"INVALID_DECIMAL ({field_name}): cannot parse {value!r}")
    if isinstance(value, Decimal):
        dec = value
    elif isinstance(value, (int, float, str)):
        text = str(value).strip()
        if not text:
            raise ValueError(f"EMPTY_DECIMAL ({field_name})")
        try:
            dec = Decimal(text)
        except InvalidOperation as exc:
            raise ValueError(f"INVALID_DECIMAL ({field_name}): {value!r}") from exc
    else:
        raise ValueError(f"INVALID_DECIMAL_TYPE ({field_name}): {type(value).__name__}")

    if not dec.is_finite():
        raise ValueError(f"NON_FINITE_DECIMAL ({field_name}): {value!r}")
    if allow_zero:
        if dec < _ZERO_DEC:
            raise ValueError(f"NEGATIVE_DECIMAL ({field_name}): {dec}")
    else:
        if dec <= _ZERO_DEC:
            raise ValueError(f"NON_POSITIVE_DECIMAL ({field_name}): {dec}")
    return dec


def _normalize_execution_mode(mode: Union[ExecutionMode, OperatingProfile, str]) -> ExecutionMode:
    if isinstance(mode, ExecutionMode):
        return mode
    if isinstance(mode, OperatingProfile):
        return ExecutionMode(mode.value)
    if not isinstance(mode, str) or not mode.strip():
        raise ValueError(f"INVALID_EXECUTION_MODE: {mode!r}")
    token = mode.strip().upper()
    try:
        return ExecutionMode(token)
    except ValueError as exc:
        raise ValueError(
            f"UNSUPPORTED_EXECUTION_MODE: {mode!r}; expected LOCAL_RESEARCH or GITHUB_PUBLIC"
        ) from exc


def _validate_strategy_id(strategy_id: Any) -> str:
    cleaned = validate_safe_text(str(strategy_id if strategy_id is not None else ""), field_name="strategy_id")
    if not _VALID_STRATEGY_ID_RE.fullmatch(cleaned):
        raise ValueError(f"INVALID_STRATEGY_ID: '{cleaned}' contains disallowed path or control characters.")
    assert_strategy_respects_guardrails(cleaned, context="strategy_id", strict_target_value=True)
    return cleaned


def _string_targets_immutable_guardrail(text: str, *, strict_target_value: bool) -> Optional[str]:
    norm = text.strip()
    if not norm:
        return None
    upper = norm.upper()
    if upper in IMMUTABLE_GUARDRAIL_IDS:
        return f"PROTECTED_BASELINE_GUARDRAIL: '{upper}' is immutable."
    low = norm.lower().replace("\\", "/")
    if strict_target_value:
        for mod in IMMUTABLE_SECURITY_MODULES:
            if mod in low:
                return f"PROTECTED_SECURITY_MODULE: target '{norm}' references immutable module '{mod}'."
        m_id = _GUARDRAIL_ID_RE.search(norm)
        if m_id:
            return f"PROTECTED_BASELINE_GUARDRAIL: target '{norm}' references immutable rule '{m_id.group(0).upper()}'."
    else:
        has_guardrail_ref = (_GUARDRAIL_ID_RE.search(norm) is not None) or (_GUARDRAIL_TARGET_RE.search(low) is not None)
        if has_guardrail_ref and _WEAKEN_VERB_RE.search(norm):
            return f"GUARDRAIL_WEAKENING_FORBIDDEN: directive '{norm[:120]}' attempts to weaken immutable security."
    return None


def assert_strategy_respects_guardrails(
    payload: Any,
    *,
    context: str = "strategy",
    strict_target_value: bool = False,
) -> None:
    """Fail closed if any strategy field, target, or metadata attempts to weaken immutable security guardrails."""
    if payload is None:
        return
    if isinstance(payload, str):
        if "\x00" in payload or TROJAN_UNICODE_RE.search(payload):
            raise ImmutableGuardrailError(f"TROJAN_UNICODE_BLOCKED at {context}")
        if PROMPT_INJECTION_RE.search(payload) or _S3_EXTERNAL_INJECTION_RE.search(payload):
            raise ImmutableGuardrailError(f"PROMPT_INJECTION_BLOCKED at {context}")
        err = _string_targets_immutable_guardrail(payload, strict_target_value=strict_target_value)
        if err is not None:
            raise ImmutableGuardrailError(f"{err} ({context})")
        return

    if isinstance(payload, Mapping):
        for raw_k, raw_v in payload.items():
            key_str = str(raw_k).strip()
            key_norm = key_str.lower()
            if key_norm in FORBIDDEN_MUTATION_KEYS:
                if key_norm in SECURITY_BASELINE_VALUES:
                    expected = SECURITY_BASELINE_VALUES[key_norm]
                    if raw_v is not expected:
                        raise ImmutableGuardrailError(
                            f"IMMUTABLE_BASELINE_MUTATION: '{key_norm}' cannot be altered from {expected!r} ({context})"
                        )
                elif raw_v is not False and raw_v is not None and raw_v != "":
                    raise ImmutableGuardrailError(
                        f"GUARDRAIL_OVERRIDE_FORBIDDEN: directive key '{key_norm}' is blocked ({context})"
                    )
            is_target_field = strict_target_value or key_norm in _TARGET_INSPECTION_KEYS
            assert_strategy_respects_guardrails(key_str, context=f"{context}.key({key_norm})", strict_target_value=False)
            assert_strategy_respects_guardrails(
                raw_v,
                context=f"{context}.{key_norm}",
                strict_target_value=is_target_field,
            )
        return

    if isinstance(payload, (list, tuple, set, frozenset)):
        for idx, item in enumerate(payload):
            assert_strategy_respects_guardrails(
                item,
                context=f"{context}[{idx}]",
                strict_target_value=strict_target_value,
            )
        return

    if hasattr(payload, "to_dict") and callable(payload.to_dict):
        assert_strategy_respects_guardrails(
            payload.to_dict(),
            context=context,
            strict_target_value=strict_target_value,
        )


_ALPHA_NODE_THRESHOLD = 10
_SHINGLE_TOKEN_MIN = 8
_SHINGLE_N = 3
_WORD_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
_WHITESPACE_COLLAPSE_RE = re.compile(r"\s+")


def _strip_ast_docstrings(tree: ast.AST) -> None:
    """Strip module, function, and class docstrings in-place from a parsed AST."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body = node.body[1:]


class _AlphaNormalizer:
    """Alpha-rename bound variable/arg/target Name ids to v0, v1, ... keeping calls/attrs/imports/constants intact."""

    @staticmethod
    def _bind(scope: Dict[str, str], local_names: Set[str], ident: str, *, force_new: bool = False) -> str:
        if not force_new and ident in local_names:
            return scope[ident]
        canon = f"v{len(scope)}"
        scope[ident] = canon
        local_names.add(ident)
        return canon

    def _bind_target(self, target: ast.AST, scope: Dict[str, str], local_names: Set[str]) -> None:
        if isinstance(target, ast.Name):
            target.id = self._bind(scope, local_names, target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind_target(elt, scope, local_names)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, scope, local_names)
        elif isinstance(target, ast.Attribute):
            self.visit(target.value, scope, local_names)
        elif isinstance(target, ast.Subscript):
            self.visit(target.value, scope, local_names)
            self.visit(target.slice, scope, local_names)

    def _bind_arguments(
        self,
        args_node: ast.arguments,
        outer_scope: Dict[str, str],
        outer_locals: Set[str],
        inner_scope: Dict[str, str],
        inner_locals: Set[str],
    ) -> None:
        for default in args_node.defaults:
            if default is not None:
                self.visit(default, outer_scope, outer_locals)
        for default in args_node.kw_defaults:
            if default is not None:
                self.visit(default, outer_scope, outer_locals)
        for arg in (*args_node.posonlyargs, *args_node.args, *args_node.kwonlyargs):
            arg.arg = self._bind(inner_scope, inner_locals, arg.arg, force_new=True)
            if arg.annotation is not None:
                self.visit(arg.annotation, outer_scope, outer_locals)
        if args_node.vararg is not None:
            args_node.vararg.arg = self._bind(inner_scope, inner_locals, args_node.vararg.arg, force_new=True)
            if args_node.vararg.annotation is not None:
                self.visit(args_node.vararg.annotation, outer_scope, outer_locals)
        if args_node.kwarg is not None:
            args_node.kwarg.arg = self._bind(inner_scope, inner_locals, args_node.kwarg.arg, force_new=True)
            if args_node.kwarg.annotation is not None:
                self.visit(args_node.kwarg.annotation, outer_scope, outer_locals)

    def _visit_stmt_list(self, stmts: Sequence[ast.AST], scope: Dict[str, str], local_names: Set[str]) -> None:
        for stmt in stmts:
            self.visit(stmt, scope, local_names)

    def visit(self, node: ast.AST, scope: Dict[str, str], local_names: Set[str]) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_stmt_list(node.decorator_list, scope, local_names)
            if node.returns is not None:
                self.visit(node.returns, scope, local_names)
            inner_scope = dict(scope)
            inner_locals: Set[str] = set()
            self._bind_arguments(node.args, scope, local_names, inner_scope, inner_locals)
            self._visit_stmt_list(node.body, inner_scope, inner_locals)
            return
        if isinstance(node, ast.Lambda):
            inner_scope = dict(scope)
            inner_locals = set()
            self._bind_arguments(node.args, scope, local_names, inner_scope, inner_locals)
            self.visit(node.body, inner_scope, inner_locals)
            return
        if isinstance(node, ast.ClassDef):
            self._visit_stmt_list(node.bases, scope, local_names)
            self._visit_stmt_list(node.keywords, scope, local_names)
            self._visit_stmt_list(node.decorator_list, scope, local_names)
            self._visit_stmt_list(node.body, dict(scope), set())
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            comp_scope = dict(scope)
            comp_locals: Set[str] = set()
            for idx, comp in enumerate(node.generators):
                if idx == 0:
                    self.visit(comp.iter, scope, local_names)
                else:
                    self.visit(comp.iter, comp_scope, comp_locals)
                self._bind_target(comp.target, comp_scope, comp_locals)
                self._visit_stmt_list(comp.ifs, comp_scope, comp_locals)
            if isinstance(node, ast.DictComp):
                self.visit(node.key, comp_scope, comp_locals)
                self.visit(node.value, comp_scope, comp_locals)
            else:
                self.visit(node.elt, comp_scope, comp_locals)
            return
        if isinstance(node, ast.Assign):
            self.visit(node.value, scope, local_names)
            for tgt in node.targets:
                self._bind_target(tgt, scope, local_names)
            return
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.visit(node.value, scope, local_names)
            self.visit(node.annotation, scope, local_names)
            self._bind_target(node.target, scope, local_names)
            return
        if isinstance(node, ast.AugAssign):
            self.visit(node.value, scope, local_names)
            if isinstance(node.target, ast.Name):
                if node.target.id in scope:
                    node.target.id = scope[node.target.id]
            else:
                self.visit(node.target, scope, local_names)
            return
        if isinstance(node, ast.NamedExpr):
            self.visit(node.value, scope, local_names)
            self._bind_target(node.target, scope, local_names)
            return
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self.visit(node.iter, scope, local_names)
            self._bind_target(node.target, scope, local_names)
            self._visit_stmt_list(node.body, scope, local_names)
            self._visit_stmt_list(node.orelse, scope, local_names)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.visit(item.context_expr, scope, local_names)
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars, scope, local_names)
            self._visit_stmt_list(node.body, scope, local_names)
            return
        if isinstance(node, ast.ExceptHandler):
            if node.type is not None:
                self.visit(node.type, scope, local_names)
            if node.name is not None:
                node.name = self._bind(scope, local_names, node.name)
            self._visit_stmt_list(node.body, scope, local_names)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            return
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, (ast.Load, ast.Del)) and node.id in scope:
                node.id = scope[node.id]
            elif isinstance(node.ctx, ast.Store):
                node.id = self._bind(scope, local_names, node.id)
            return
        match_as_cls = getattr(ast, "MatchAs", None)
        if match_as_cls is not None and isinstance(node, match_as_cls):
            if node.pattern is not None:
                self.visit(node.pattern, scope, local_names)
            if node.name is not None:
                node.name = self._bind(scope, local_names, node.name)
            return
        for child in ast.iter_child_nodes(node):
            self.visit(child, scope, local_names)


@dataclass(frozen=True)
class _SnippetFingerprints:
    ws_sha256: str
    ast_sha256: Optional[str]
    alpha_sha256: Optional[str]
    shingles: Optional[FrozenSet[Tuple[str, str, str]]]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parse_snippet_ast(snippet: str) -> Optional[ast.Module]:
    dedented = textwrap.dedent(snippet).strip()
    if not dedented:
        return None
    try:
        return ast.parse(dedented)
    except SyntaxError:
        return None


def _build_snippet_fingerprints(snippet: str) -> _SnippetFingerprints:
    ws_norm = _WHITESPACE_COLLAPSE_RE.sub(" ", snippet.strip())
    ws_sha = _sha256_text(ws_norm)

    ast_sha: Optional[str] = None
    alpha_sha: Optional[str] = None
    tree = _parse_snippet_ast(snippet)
    if tree is not None:
        _strip_ast_docstrings(tree)
        ast_sha = _sha256_text(ast.dump(tree, include_attributes=False))
        node_count = sum(1 for _ in ast.walk(tree))
        if node_count >= _ALPHA_NODE_THRESHOLD or len(tree.body) >= 2:
            _AlphaNormalizer().visit(tree, {}, set())
            alpha_sha = _sha256_text(ast.dump(tree, include_attributes=False))

    tokens = _WORD_TOKEN_RE.findall(snippet)
    shingles: Optional[FrozenSet[Tuple[str, str, str]]] = None
    if len(tokens) >= _SHINGLE_TOKEN_MIN:
        shingles = frozenset(
            (tokens[i], tokens[i + 1], tokens[i + 2]) for i in range(len(tokens) - _SHINGLE_N + 1)
        )

    return _SnippetFingerprints(
        ws_sha256=ws_sha,
        ast_sha256=ast_sha,
        alpha_sha256=alpha_sha,
        shingles=shingles,
    )


def _extract_family_records(
    families: Sequence[Any],
    *,
    split_name: str,
) -> Tuple[Tuple[str, ...], Set[str], Set[str]]:
    if not families:
        raise ValueError(f"EMPTY_TASK_FAMILIES: '{split_name}' must contain at least one task family.")
    ordered_ids: List[str] = []
    seen_norm: Set[str] = set()
    task_ids: Set[str] = set()
    snippets: Set[str] = set()

    for idx, fam in enumerate(families):
        if isinstance(fam, str):
            raw_id = fam
            fam_map: Optional[Mapping[str, Any]] = None
        elif isinstance(fam, Mapping):
            raw_id = str(fam.get("family_id") or fam.get("id") or fam.get("task_class") or "")
            fam_map = fam
        else:
            raise ValueError(f"INVALID_FAMILY_ITEM ({split_name}[{idx}]): expected str or mapping.")

        clean_id = validate_safe_text(raw_id, field_name=f"{split_name}[{idx}].family_id")
        norm_id = clean_id.lower()
        if norm_id not in seen_norm:
            seen_norm.add(norm_id)
            ordered_ids.append(clean_id)

        if fam_map is not None:
            for tk_key in ("task_id", "id"):
                val = fam_map.get(tk_key)
                if isinstance(val, str) and val.strip():
                    task_ids.add(val.strip().lower())
            for snip_key in ("offending_snippet", "fixed_snippet", "snippet", "code"):
                sval = fam_map.get(snip_key)
                if isinstance(sval, str) and sval.strip():
                    snippets.add(sval.strip())
            for list_key in ("positives", "negatives", "tasks", "snippets"):
                sub = fam_map.get(list_key)
                if isinstance(sub, (list, tuple)):
                    for item in sub:
                        if isinstance(item, str) and item.strip():
                            snippets.add(item.strip())
                        elif isinstance(item, Mapping):
                            sub_tid = item.get("task_id")
                            if isinstance(sub_tid, str) and sub_tid.strip():
                                task_ids.add(sub_tid.strip().lower())
                            for sk in ("code", "snippet", "offending_snippet", "fixed_snippet"):
                                sv = item.get(sk)
                                if isinstance(sv, str) and sv.strip():
                                    snippets.add(sv.strip())

    return tuple(ordered_ids), task_ids, snippets


def verify_disjoint_families(
    train_families: Sequence[Any],
    heldout_families: Sequence[Any],
    *,
    train_snippets: Sequence[str] = (),
    heldout_snippets: Sequence[str] = (),
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """Verify strict disjointness between `train_families` and `heldout_families`; raises `CorpusLeakageError`."""
    train_ids, train_tasks, train_snips = _extract_family_records(train_families, split_name="train_families")
    held_ids, held_tasks, held_snips = _extract_family_records(heldout_families, split_name="heldout_families")

    for s in train_snippets:
        if isinstance(s, str) and s.strip():
            train_snips.add(s.strip())
    for s in heldout_snippets:
        if isinstance(s, str) and s.strip():
            held_snips.add(s.strip())

    fam_overlap = sorted({f.lower() for f in train_ids} & {f.lower() for f in held_ids})
    if fam_overlap:
        raise CorpusLeakageError(
            f"CORPUS_LEAKAGE: train_families and heldout_families overlap on families={fam_overlap}"
        )

    task_overlap = sorted(train_tasks & held_tasks)
    if task_overlap:
        raise CorpusLeakageError(
            f"CORPUS_LEAKAGE: train_families and heldout_families share task_ids={task_overlap}"
        )

    snip_overlap = train_snips & held_snips
    if snip_overlap:
        raise CorpusLeakageError(
            f"CORPUS_LEAKAGE: train_families and heldout_families share {len(snip_overlap)} identical snippet(s)."
        )

    if train_snips and held_snips:
        train_fps = [_build_snippet_fingerprints(s) for s in train_snips]
        held_fps = [_build_snippet_fingerprints(s) for s in held_snips]

        train_ws = {fp.ws_sha256 for fp in train_fps}
        held_ws = {fp.ws_sha256 for fp in held_fps}
        if train_ws & held_ws:
            raise CorpusLeakageError(
                "CORPUS_LEAKAGE: train_families and heldout_families share whitespace-normalized duplicate snippet(s)."
            )

        train_ast = {fp.ast_sha256 for fp in train_fps if fp.ast_sha256 is not None}
        held_ast = {fp.ast_sha256 for fp in held_fps if fp.ast_sha256 is not None}
        if train_ast & held_ast:
            raise CorpusLeakageError(
                "CORPUS_LEAKAGE: train_families and heldout_families share AST-structural duplicate snippet(s)."
            )

        train_alpha = {fp.alpha_sha256 for fp in train_fps if fp.alpha_sha256 is not None}
        held_alpha = {fp.alpha_sha256 for fp in held_fps if fp.alpha_sha256 is not None}
        if train_alpha & held_alpha:
            raise CorpusLeakageError(
                "CORPUS_LEAKAGE: train_families and heldout_families share alpha-normalized AST duplicate snippet(s)."
            )

        train_shingles = [fp.shingles for fp in train_fps if fp.shingles is not None]
        held_shingles = [fp.shingles for fp in held_fps if fp.shingles is not None]
        for tr_sh in train_shingles:
            tr_len = len(tr_sh)
            for he_sh in held_shingles:
                he_len = len(he_sh)
                min_len = tr_len if tr_len < he_len else he_len
                max_len = he_len if tr_len < he_len else tr_len
                if max_len == 0 or min_len * 10 < max_len * 9:
                    continue
                inter = len(tr_sh & he_sh)
                union = tr_len + he_len - inter
                if union > 0 and inter * 10 >= union * 9:
                    raise CorpusLeakageError(
                        "CORPUS_LEAKAGE: train_families and heldout_families share near-duplicate snippet(s) "
                        f"(token 3-gram Jaccard >= 0.90: {inter}/{union})."
                    )

    return train_ids, held_ids


def _compute_newcombe_uplift_lb(
    with_rate: float,
    with_lb: float,
    without_rate: float,
    without_ub: float,
) -> float:
    """Newcombe Method-10 Wilson score lower bound on `p_with - p_without`."""
    delta = with_rate - without_rate
    margin = math.sqrt((with_rate - with_lb) ** 2 + (without_ub - without_rate) ** 2)
    return round(delta - margin, 6)


@dataclass(frozen=True)
class MatchedTaskTrial:
    """Single matched counterfactual ablation observation (`with_strategy` vs `without_strategy`)."""

    family_id: str
    task_id: str
    with_passed: bool
    without_passed: bool
    with_fp: int = 0
    without_fp: int = 0
    baseline_regression: bool = False
    tokens_used: int = 0
    latency_ms: Decimal = _ZERO_DEC

    def __post_init__(self) -> None:
        clean_fam = validate_safe_text(self.family_id, field_name="family_id")
        clean_tid = validate_safe_text(self.task_id, field_name="task_id")
        object.__setattr__(self, "family_id", clean_fam)
        object.__setattr__(self, "task_id", clean_tid)
        _strict_bool(self.with_passed, field_name="with_passed")
        _strict_bool(self.without_passed, field_name="without_passed")
        _strict_bool(self.baseline_regression, field_name="baseline_regression")
        object.__setattr__(self, "with_fp", _strict_nonneg_int(self.with_fp, field_name="with_fp"))
        object.__setattr__(self, "without_fp", _strict_nonneg_int(self.without_fp, field_name="without_fp"))
        object.__setattr__(self, "tokens_used", _strict_nonneg_int(self.tokens_used, field_name="tokens_used"))
        object.__setattr__(
            self,
            "latency_ms",
            _to_exact_decimal(self.latency_ms, field_name="latency_ms", allow_zero=True),
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MatchedTaskTrial":
        if isinstance(data, MatchedTaskTrial):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_MATCHED_TRIAL: expected mapping.")
        if "with_passed" not in data or "without_passed" not in data:
            raise ValueError("MISSING_REQUIRED_TRIAL_FIELD: with_passed and without_passed are required.")
        raw_family_id = data.get("family_id")
        raw_task_id = data.get("task_id")
        if type(raw_family_id) is not str or type(raw_task_id) is not str:
            raise ValueError("INVALID_TRIAL_ID_TYPE: family_id and task_id must be exact str.")
        return cls(
            family_id=raw_family_id,
            task_id=raw_task_id,
            with_passed=_strict_bool(data["with_passed"], field_name="with_passed"),
            without_passed=_strict_bool(data["without_passed"], field_name="without_passed"),
            with_fp=_strict_nonneg_int(data.get("with_fp", 0), field_name="with_fp"),
            without_fp=_strict_nonneg_int(data.get("without_fp", 0), field_name="without_fp"),
            baseline_regression=_strict_bool(data.get("baseline_regression", False), field_name="baseline_regression"),
            tokens_used=_strict_nonneg_int(data.get("tokens_used", 0), field_name="tokens_used"),
            latency_ms=data.get("latency_ms", _ZERO_DEC),
        )


@dataclass(frozen=True)
class CausalAblationResult:
    """Counterfactual uplift & exact Wilson score interval report across disjoint task families."""

    strategy_id: str
    revision: int
    train_families: Tuple[str, ...]
    heldout_families: Tuple[str, ...]
    disjoint_verified: bool
    heldout_verified: bool
    total_matched: int
    with_successes: int
    without_successes: int
    with_success_rate: Decimal
    without_success_rate: Decimal
    raw_uplift: Decimal
    with_wilson_lb: float
    with_wilson_ub: float
    without_wilson_lb: float
    without_wilson_ub: float
    wilson_lb_delta: float
    uplift_wilson_lb: float
    improved_count: int
    regressed_count: int
    false_positives_with: int
    false_positives_without: int
    false_positive_delta: int
    baseline_regressions: int
    z_score: float = DEFAULT_WILSON_Z
    min_sample_size: int = 5
    min_wilson_lb: float = 0.5
    passed: bool = False
    rejection_reasons: Tuple[str, ...] = ()
    evidence_digest: str = ""
    schema: str = CAUSAL_ABLATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CAUSAL_ABLATION_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {CAUSAL_ABLATION_SCHEMA}, got {self.schema!r}")
        _validate_strategy_id(self.strategy_id)
        _strict_pos_int(self.revision, field_name="revision")
        if self.disjoint_verified is not True:
            raise CorpusLeakageError("CORPUS_LEAKAGE: disjoint_verified must be True.")
        verify_disjoint_families(self.train_families, self.heldout_families)
        _strict_nonneg_int(self.total_matched, field_name="total_matched")
        _strict_nonneg_int(self.with_successes, field_name="with_successes")
        _strict_nonneg_int(self.without_successes, field_name="without_successes")
        if self.with_successes > self.total_matched or self.without_successes > self.total_matched:
            raise ValueError("INVALID_ABLATION_COUNTS: successes cannot exceed total_matched.")
        if not math.isfinite(float(self.z_score)) or float(self.z_score) <= 0.0:
            raise ValueError(f"INVALID_Z_SCORE: {self.z_score!r}")
        _strict_pos_int(self.min_sample_size, field_name="min_sample_size")

    @property
    def eligible_for_promotion(self) -> bool:
        return self.passed is True and self.disjoint_verified is True and self.heldout_verified is True

    def ranking_key(self) -> Tuple[int, float, float, float, int, int, int, str]:
        """Deterministic sort key prioritizing verified eligibility & exact Wilson lower bounds over tiny-N noise."""
        return (
            0 if self.eligible_for_promotion else 1,
            -self.uplift_wilson_lb,
            -self.with_wilson_lb,
            -self.wilson_lb_delta,
            -self.total_matched,
            self.baseline_regressions,
            self.false_positive_delta,
            self.strategy_id,
        )

    @classmethod
    def from_trials(
        cls,
        *,
        strategy_id: str,
        revision: int = 1,
        train_families: Sequence[Any],
        heldout_families: Sequence[Any],
        trials: Sequence[Union[MatchedTaskTrial, Mapping[str, Any]]],
        z_score: float = DEFAULT_WILSON_Z,
        min_sample_size: int = 5,
        min_wilson_lb: float = 0.5,
        extra_baseline_regressions: int = 0,
    ) -> "CausalAblationResult":
        """Compute exact counterfactual ablation metrics and Wilson bounds from matched heldout trials."""
        clean_sid = _validate_strategy_id(strategy_id)
        rev = _strict_pos_int(revision, field_name="revision")
        min_n = _strict_pos_int(min_sample_size, field_name="min_sample_size")
        extra_reg = _strict_nonneg_int(extra_baseline_regressions, field_name="extra_baseline_regressions")

        norm_train, norm_heldout = verify_disjoint_families(train_families, heldout_families)
        train_set = {f.lower() for f in norm_train}
        held_set = {f.lower() for f in norm_heldout}

        normalized_trials = [MatchedTaskTrial.from_mapping(t) for t in trials]
        seen_pairs: Set[Tuple[str, str]] = set()
        for t in normalized_trials:
            fam_low = t.family_id.lower()
            if fam_low in train_set:
                raise CorpusLeakageError(
                    f"CORPUS_LEAKAGE: heldout trial '{t.task_id}' belongs to train family '{t.family_id}'."
                )
            if fam_low not in held_set:
                raise ValueError(
                    f"UNDECLARED_HELDOUT_FAMILY: trial family '{t.family_id}' not present in heldout_families."
                )
            pair = (fam_low, t.task_id.lower())
            if pair in seen_pairs:
                raise ValueError(f"DUPLICATE_MATCHED_TRIAL: ({t.family_id}, {t.task_id}) repeated.")
            seen_pairs.add(pair)

        total = len(normalized_trials)
        with_succ = sum(1 for t in normalized_trials if t.with_passed)
        without_succ = sum(1 for t in normalized_trials if t.without_passed)
        improved = sum(1 for t in normalized_trials if t.with_passed and not t.without_passed)
        regressed = sum(1 for t in normalized_trials if (not t.with_passed and t.without_passed) or t.baseline_regression)
        fp_with = sum(t.with_fp for t in normalized_trials)
        fp_without = sum(t.without_fp for t in normalized_trials)
        fp_delta = fp_with - fp_without
        total_regressions = extra_reg + regressed

        if total > 0:
            total_dec = Decimal(total)
            with_rate_dec = (Decimal(with_succ) / total_dec).quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)
            without_rate_dec = (Decimal(without_succ) / total_dec).quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)
        else:
            with_rate_dec = _ZERO_DEC
            without_rate_dec = _ZERO_DEC
        raw_uplift_dec = (with_rate_dec - without_rate_dec).quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)

        with_lb, with_ub = compute_wilson_interval(with_succ, total, z=float(z_score))
        without_lb, without_ub = compute_wilson_interval(without_succ, total, z=float(z_score))
        lb_delta = round(with_lb - without_lb, 6)
        uplift_lb = (
            _compute_newcombe_uplift_lb(
                float(with_succ) / float(total),
                with_lb,
                float(without_succ) / float(total),
                without_ub,
            )
            if total > 0
            else -1.0
        )

        heldout_ok = total > 0
        reasons: List[str] = []
        if not heldout_ok:
            reasons.append("HELDOUT_NOT_VERIFIED")
        if total < min_n:
            reasons.append(f"INSUFFICIENT_SAMPLE_SIZE:{total}<{min_n}")
        if with_lb < float(min_wilson_lb):
            reasons.append(f"LOW_WILSON_LOWER_BOUND:{with_lb:.6f}<{float(min_wilson_lb):.6f}")
        if lb_delta <= 0.0:
            reasons.append(f"NON_POSITIVE_WILSON_LB_DELTA:{lb_delta:.6f}<=0")
        if total_regressions > 0:
            reasons.append(f"BASELINE_REGRESSIONS:{total_regressions}>0")
        if fp_delta > 0:
            reasons.append(f"FALSE_POSITIVE_INCREASE:{fp_delta}>0")

        digest = sha256_digest(
            {
                "strategy_id": clean_sid,
                "revision": rev,
                "train_families": list(norm_train),
                "heldout_families": list(norm_heldout),
                "total": total,
                "with": with_succ,
                "without": without_succ,
                "with_wilson_lb": with_lb,
                "without_wilson_lb": without_lb,
                "wilson_lb_delta": lb_delta,
                "uplift_wilson_lb": uplift_lb,
                "regressions": total_regressions,
                "fp_delta": fp_delta,
            }
        )

        return cls(
            strategy_id=clean_sid,
            revision=rev,
            train_families=norm_train,
            heldout_families=norm_heldout,
            disjoint_verified=True,
            heldout_verified=heldout_ok,
            total_matched=total,
            with_successes=with_succ,
            without_successes=without_succ,
            with_success_rate=with_rate_dec,
            without_success_rate=without_rate_dec,
            raw_uplift=raw_uplift_dec,
            with_wilson_lb=with_lb,
            with_wilson_ub=with_ub,
            without_wilson_lb=without_lb,
            without_wilson_ub=without_ub,
            wilson_lb_delta=lb_delta,
            uplift_wilson_lb=uplift_lb,
            improved_count=improved,
            regressed_count=regressed,
            false_positives_with=fp_with,
            false_positives_without=fp_without,
            false_positive_delta=fp_delta,
            baseline_regressions=total_regressions,
            z_score=float(z_score),
            min_sample_size=min_n,
            min_wilson_lb=float(min_wilson_lb),
            passed=len(reasons) == 0,
            rejection_reasons=tuple(reasons),
            evidence_digest=digest,
        )

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(
            {
                "schema": self.schema,
                "strategy_id": self.strategy_id,
                "revision": self.revision,
                "train_families": list(self.train_families),
                "heldout_families": list(self.heldout_families),
                "disjoint_verified": self.disjoint_verified,
                "heldout_verified": self.heldout_verified,
                "total_matched": self.total_matched,
                "with_successes": self.with_successes,
                "without_successes": self.without_successes,
                "with_success_rate": str(self.with_success_rate),
                "without_success_rate": str(self.without_success_rate),
                "raw_uplift": str(self.raw_uplift),
                "with_wilson_lb": self.with_wilson_lb,
                "with_wilson_ub": self.with_wilson_ub,
                "without_wilson_lb": self.without_wilson_lb,
                "without_wilson_ub": self.without_wilson_ub,
                "wilson_lb_delta": self.wilson_lb_delta,
                "uplift_wilson_lb": self.uplift_wilson_lb,
                "improved_count": self.improved_count,
                "regressed_count": self.regressed_count,
                "false_positives_with": self.false_positives_with,
                "false_positives_without": self.false_positives_without,
                "false_positive_delta": self.false_positive_delta,
                "baseline_regressions": self.baseline_regressions,
                "z_score": self.z_score,
                "min_sample_size": self.min_sample_size,
                "min_wilson_lb": self.min_wilson_lb,
                "passed": self.passed,
                "rejection_reasons": list(self.rejection_reasons),
                "evidence_digest": self.evidence_digest,
            }
        )


@dataclass(frozen=True)
class ExplorationPlan:
    """Mode-aware exploration depth plan computed via exact `Decimal` / `int` arithmetic."""

    mode: ExecutionMode
    residual_variance: Decimal
    scale_factor: Decimal
    exploration_rounds: int
    hypotheses_per_round: int
    max_parallel_workers: int
    scaled_for_variance: bool
    hard_capped: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "residual_variance": str(self.residual_variance),
            "scale_factor": str(self.scale_factor),
            "exploration_rounds": self.exploration_rounds,
            "hypotheses_per_round": self.hypotheses_per_round,
            "max_parallel_workers": self.max_parallel_workers,
            "scaled_for_variance": self.scaled_for_variance,
            "hard_capped": self.hard_capped,
        }


class AdaptiveBudgetController:
    """
    Exact `Decimal`/`int` token, step, latency, and hypothesis exploration budget controller.

    - `ExecutionMode.LOCAL_RESEARCH`: permits high-throughput multi-round hypothesis exploration
      and dynamically scales exploration depth when residual variance exceeds `variance_threshold`.
    - `ExecutionMode.GITHUB_PUBLIC`: enforces strict hard `token_budget`, `max_steps`, and
      `max_latency_ms` fail-closed before execution, disabling unbounded variance scaling.
    """

    SCHEMA_VERSION = BUDGET_CONTROLLER_SCHEMA

    def __init__(
        self,
        mode: Union[ExecutionMode, OperatingProfile, str] = ExecutionMode.GITHUB_PUBLIC,
        *,
        token_budget: Optional[int] = None,
        max_steps: Optional[int] = None,
        max_latency_ms: Optional[Union[Decimal, int, str]] = None,
        base_exploration_rounds: int = 3,
        max_exploration_rounds: int = 12,
        base_hypotheses_per_round: int = 4,
        max_hypotheses_per_round: int = 16,
        public_max_rounds: int = 1,
        public_max_hypotheses: int = 2,
        variance_threshold: Union[Decimal, int, str] = Decimal("0.15"),
        config: Optional[KintsugiConfig] = None,
        tracker: Optional[TokenEconomicsTracker] = None,
    ) -> None:
        self.mode = _normalize_execution_mode(mode)
        self.config = config if config is not None else KintsugiConfig.for_profile(self.mode.value)
        self.tracker = tracker

        self.base_exploration_rounds = _strict_pos_int(base_exploration_rounds, field_name="base_exploration_rounds")
        self.max_exploration_rounds = _strict_pos_int(max_exploration_rounds, field_name="max_exploration_rounds")
        if self.max_exploration_rounds < self.base_exploration_rounds:
            raise ValueError("max_exploration_rounds must be >= base_exploration_rounds.")

        self.base_hypotheses_per_round = _strict_pos_int(
            base_hypotheses_per_round, field_name="base_hypotheses_per_round"
        )
        self.max_hypotheses_per_round = _strict_pos_int(
            max_hypotheses_per_round, field_name="max_hypotheses_per_round"
        )
        if self.max_hypotheses_per_round < self.base_hypotheses_per_round:
            raise ValueError("max_hypotheses_per_round must be >= base_hypotheses_per_round.")

        self.public_max_rounds = _strict_pos_int(public_max_rounds, field_name="public_max_rounds")
        self.public_max_hypotheses = _strict_pos_int(public_max_hypotheses, field_name="public_max_hypotheses")
        self.variance_threshold = _to_exact_decimal(
            variance_threshold, field_name="variance_threshold", allow_zero=False
        )

        if self.mode == ExecutionMode.GITHUB_PUBLIC:
            gp = self.config.github_public
            self.token_budget: Optional[int] = (
                _strict_pos_int(token_budget, field_name="token_budget")
                if token_budget is not None
                else int(gp.token_budget)
            )
            self.max_steps: Optional[int] = (
                _strict_pos_int(max_steps, field_name="max_steps")
                if max_steps is not None
                else max(1, int(gp.max_tool_probes) * 4)
            )
            self.max_latency_ms: Optional[Decimal] = (
                _to_exact_decimal(max_latency_ms, field_name="max_latency_ms", allow_zero=False)
                if max_latency_ms is not None
                else Decimal(gp.max_runtime_seconds) * Decimal("1000")
            )
        else:
            self.token_budget = _strict_pos_int(token_budget, field_name="token_budget") if token_budget is not None else None
            self.max_steps = _strict_pos_int(max_steps, field_name="max_steps") if max_steps is not None else None
            self.max_latency_ms = (
                _to_exact_decimal(max_latency_ms, field_name="max_latency_ms", allow_zero=False)
                if max_latency_ms is not None
                else None
            )

        self.tokens_used: int = 0
        self.steps_used: int = 0
        self.rounds_completed: int = 0
        self.latency_ms_used: Decimal = _ZERO_DEC
        self.halted: bool = False
        self.halt_reason: str = ""

    @property
    def remaining_tokens(self) -> Optional[int]:
        if self.token_budget is None:
            return None
        return max(0, self.token_budget - self.tokens_used)

    @property
    def remaining_steps(self) -> Optional[int]:
        if self.max_steps is None:
            return None
        return max(0, self.max_steps - self.steps_used)

    @property
    def remaining_latency_ms(self) -> Optional[Decimal]:
        if self.max_latency_ms is None:
            return None
        rem = self.max_latency_ms - self.latency_ms_used
        return rem if rem > _ZERO_DEC else _ZERO_DEC

    @property
    def token_utilization_ratio(self) -> Decimal:
        if self.token_budget is None or self.token_budget <= 0:
            return _ZERO_DEC
        return (Decimal(self.tokens_used) / Decimal(self.token_budget)).quantize(
            _DECIMAL_QUANT, rounding=ROUND_HALF_UP
        )

    def _halt_if_exceeded(
        self,
        *,
        metric: str,
        label: str,
        projected: Union[int, Decimal],
        limit: Optional[Union[int, Decimal]],
    ) -> None:
        if limit is not None and projected > limit:
            reason = f"{self.mode.value}_{label}_BUDGET_EXCEEDED: projected={projected} > limit={limit}"
            self.halted = True
            self.halt_reason = reason
            raise BudgetExceededError(reason, metric=metric, limit=float(limit), observed=float(projected))

    def check_limits(
        self,
        *,
        additional_tokens: int = 0,
        additional_steps: int = 0,
        additional_latency_ms: Union[Decimal, int, str] = _ZERO_DEC,
    ) -> None:
        """Fail-closed exact `int`/`Decimal` budget gate enforcing `GITHUB_PUBLIC` hard caps."""
        add_tok = _strict_nonneg_int(additional_tokens, field_name="additional_tokens")
        add_steps = _strict_nonneg_int(additional_steps, field_name="additional_steps")
        add_lat = _to_exact_decimal(additional_latency_ms, field_name="additional_latency_ms", allow_zero=True)

        if self.halted:
            raise BudgetExceededError(
                self.halt_reason or "BUDGET_ALREADY_HALTED",
                metric="halted",
                limit=0.0,
                observed=1.0,
            )

        self._halt_if_exceeded(
            metric="token_budget",
            label="TOKEN",
            projected=self.tokens_used + add_tok,
            limit=self.token_budget,
        )
        self._halt_if_exceeded(
            metric="max_steps",
            label="STEP",
            projected=self.steps_used + add_steps,
            limit=self.max_steps,
        )
        self._halt_if_exceeded(
            metric="max_latency_ms",
            label="LATENCY",
            projected=self.latency_ms_used + add_lat,
            limit=self.max_latency_ms,
        )

    def consume(
        self,
        *,
        tokens: int = 0,
        steps: int = 1,
        latency_ms: Union[Decimal, int, str] = _ZERO_DEC,
    ) -> Dict[str, Any]:
        """Atomically verify and consume token/step/latency budgets via exact `int`/`Decimal` arithmetic."""
        tok_delta = _strict_nonneg_int(tokens, field_name="tokens")
        step_delta = _strict_nonneg_int(steps, field_name="steps")
        lat_delta = _to_exact_decimal(latency_ms, field_name="latency_ms", allow_zero=True)

        self.check_limits(
            additional_tokens=tok_delta,
            additional_steps=step_delta,
            additional_latency_ms=lat_delta,
        )

        self.tokens_used += tok_delta
        self.steps_used += step_delta
        self.latency_ms_used = (self.latency_ms_used + lat_delta).quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)

        if self.tracker is not None:
            if tok_delta > 0:
                self.tracker.record_llm_call(input_tokens=tok_delta, output_tokens=0, calls=max(1, step_delta), enforce=False)
            if step_delta > 0:
                self.tracker.record_search_node(step_delta)
            if lat_delta > _ZERO_DEC:
                self.tracker.record_timing(wall_time_ms=float(lat_delta), enforce=False)

        return self.snapshot()

    def plan_exploration(self, residual_variance: Union[Decimal, int, str, float]) -> ExplorationPlan:
        """
        Compute exploration rounds and hypothesis breadth for the active `ExecutionMode`.

        Under `LOCAL_RESEARCH`, high residual variance dynamically scales rounds and hypotheses
        upward (bounded by `max_exploration_rounds` / `max_hypotheses_per_round`).
        Under `GITHUB_PUBLIC`, refuses dynamic upward scaling and stays strictly within public caps.
        """
        var_dec = _to_exact_decimal(residual_variance, field_name="residual_variance", allow_zero=True)

        if self.mode == ExecutionMode.GITHUB_PUBLIC:
            self.check_limits(additional_tokens=0, additional_steps=1, additional_latency_ms=_ZERO_DEC)
            rem_steps = self.remaining_steps if self.remaining_steps is not None else self.public_max_rounds
            rounds = min(self.public_max_rounds, max(1, rem_steps))
            hyps = min(self.public_max_hypotheses, max(1, rem_steps))
            workers = max(1, min(int(self.config.github_public.max_parallel_agents), hyps))
            return ExplorationPlan(
                mode=self.mode,
                residual_variance=var_dec,
                scale_factor=_ONE_DEC,
                exploration_rounds=rounds,
                hypotheses_per_round=hyps,
                max_parallel_workers=workers,
                scaled_for_variance=False,
                hard_capped=True,
            )

        # LOCAL_RESEARCH: dynamically scale exploration depth when residual variance is high
        scaled = var_dec > self.variance_threshold
        if scaled:
            excess_ratio = (var_dec - self.variance_threshold) / self.variance_threshold
            raw_scale = (_ONE_DEC + excess_ratio).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            scale_factor = min(Decimal("4.00"), max(_ONE_DEC, raw_scale))
        else:
            scale_factor = _ONE_DEC

        raw_rounds = int((Decimal(self.base_exploration_rounds) * scale_factor).to_integral_value(rounding=ROUND_HALF_UP))
        raw_hyps = int(
            (Decimal(self.base_hypotheses_per_round) * scale_factor).to_integral_value(rounding=ROUND_HALF_UP)
        )
        rounds = min(self.max_exploration_rounds, max(self.base_exploration_rounds, raw_rounds))
        hyps = min(self.max_hypotheses_per_round, max(self.base_hypotheses_per_round, raw_hyps))
        cpu_cap = max(1, os.cpu_count() or 2)
        workers = min(cpu_cap, hyps)

        return ExplorationPlan(
            mode=self.mode,
            residual_variance=var_dec,
            scale_factor=scale_factor,
            exploration_rounds=rounds,
            hypotheses_per_round=hyps,
            max_parallel_workers=workers,
            scaled_for_variance=scaled,
            hard_capped=False,
        )

    def record_round(self) -> int:
        self.rounds_completed += 1
        return self.rounds_completed

    def snapshot(self) -> Dict[str, Any]:
        return {
            "schema": self.SCHEMA_VERSION,
            "mode": self.mode.value,
            "tokens_used": self.tokens_used,
            "token_budget": self.token_budget,
            "remaining_tokens": self.remaining_tokens,
            "steps_used": self.steps_used,
            "max_steps": self.max_steps,
            "remaining_steps": self.remaining_steps,
            "rounds_completed": self.rounds_completed,
            "latency_ms_used": str(self.latency_ms_used),
            "max_latency_ms": str(self.max_latency_ms) if self.max_latency_ms is not None else None,
            "remaining_latency_ms": str(self.remaining_latency_ms) if self.remaining_latency_ms is not None else None,
            "token_utilization_ratio": str(self.token_utilization_ratio),
            "halted": self.halted,
            "halt_reason": self.halt_reason,
        }


@dataclass(frozen=True)
class VerificationSlice:
    """Canary or Enforced verification batch checked against the strategy's pinned baseline."""

    passed_count: int
    total_count: int
    false_positives: int = 0
    baseline_regressions: int = 0
    slice_id: str = "slice-0"

    def __post_init__(self) -> None:
        _strict_nonneg_int(self.passed_count, field_name="passed_count")
        _strict_pos_int(self.total_count, field_name="total_count")
        if self.passed_count > self.total_count:
            raise ValueError(f"INVALID_SLICE_COUNTS: {self.passed_count}/{self.total_count}")
        _strict_nonneg_int(self.false_positives, field_name="false_positives")
        _strict_nonneg_int(self.baseline_regressions, field_name="baseline_regressions")
        validate_safe_text(self.slice_id, field_name="slice_id")

    @property
    def pass_rate(self) -> Decimal:
        return (Decimal(self.passed_count) / Decimal(self.total_count)).quantize(
            _DECIMAL_QUANT, rounding=ROUND_HALF_UP
        )

    @property
    def fp_rate(self) -> Decimal:
        return (Decimal(self.false_positives) / Decimal(self.total_count)).quantize(
            _DECIMAL_QUANT, rounding=ROUND_HALF_UP
        )

    @classmethod
    def coerce(cls, raw: Union["VerificationSlice", Mapping[str, Any]]) -> "VerificationSlice":
        if isinstance(raw, VerificationSlice):
            return raw
        if not isinstance(raw, Mapping):
            raise ValueError("INVALID_VERIFICATION_SLICE: expected VerificationSlice or mapping.")
        return cls(
            passed_count=int(raw["passed_count"]),
            total_count=int(raw["total_count"]),
            false_positives=int(raw.get("false_positives", 0)),
            baseline_regressions=int(raw.get("baseline_regressions", 0)),
            slice_id=str(raw.get("slice_id") or "slice-0"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slice_id": self.slice_id,
            "passed_count": self.passed_count,
            "total_count": self.total_count,
            "pass_rate": str(self.pass_rate),
            "false_positives": self.false_positives,
            "fp_rate": str(self.fp_rate),
            "baseline_regressions": self.baseline_regressions,
        }


class MonotonicPromotionLedger:
    """
    Append-only monotonic strategy promotion & fail-fast rollback ledger (`MonotonicPromotionLedger/1`).

    Enforces:
      - Lifecycle `CANDIDATE -> SHADOW -> CANARY -> ENFORCED` + `ROLLED_BACK`.
      - Monotonic promotion gate (minimum sample size, positive Wilson lower bound delta,
        zero baseline regressions, zero FP increase, verified disjoint holdout generalization).
      - Atomic `0o600` persistence (`assert_not_symlink`, workspace traversal jail, `O_NOFOLLOW`)
        restoring the previous active pointer whenever canary/enforced verification regresses.
      - Immutable protection invariant blocking any guardrail-weakening mutation.
    """

    SCHEMA_VERSION = PROMOTION_LEDGER_SCHEMA

    def __init__(
        self,
        ledger_path: Optional[Union[str, Path]] = None,
        *,
        workspace_root: Optional[Union[str, Path]] = None,
        min_sample_size: int = 5,
        min_wilson_lb: float = 0.5,
    ) -> None:
        self.min_sample_size = _strict_pos_int(min_sample_size, field_name="min_sample_size")
        self.min_wilson_lb = float(min_wilson_lb)
        self._ws_resolved: Optional[Path] = None
        self.path: Optional[Path] = None

        if workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            self._ws_resolved = ws.resolve()
            raw_target = Path(ledger_path) if ledger_path is not None else Path(DEFAULT_PROMOTION_LEDGER_REL_PATH)
            self.path = self._confine_path(raw_target)
        elif ledger_path is not None:
            self.path = Path(ledger_path)

        self._entries: Dict[str, Dict[str, Any]] = {}
        self.events: List[Dict[str, Any]] = []
        self.active_pointer: Optional[Dict[str, Any]] = None
        self.previous_active_pointer: Optional[Dict[str, Any]] = None
        self._active_stack: List[Dict[str, Any]] = []

        if self.path is not None:
            self._assert_paths_not_symlink()
            if self.path.exists():
                self.load()

    def _confine_path(self, raw_path: Path) -> Path:
        assert self._ws_resolved is not None
        if not raw_path.is_absolute():
            confined = resolve_safe_child_path(self._ws_resolved, str(raw_path))
            if confined is None:
                raise PermissionError(f"PROMOTION_LEDGER_PATH_OUTSIDE_WORKSPACE: {raw_path}")
            return confined
        resolved = raw_path.resolve()
        try:
            resolved.relative_to(self._ws_resolved)
        except ValueError as exc:
            raise PermissionError(f"PROMOTION_LEDGER_PATH_OUTSIDE_WORKSPACE: {raw_path}") from exc
        return resolved

    def _assert_paths_not_symlink(self) -> None:
        if self.path is None:
            return
        if self._ws_resolved is not None:
            try:
                rel = self.path.relative_to(self._ws_resolved)
            except ValueError:
                rel = None
            if rel is not None:
                cur = self._ws_resolved
                for part in rel.parts:
                    cur = cur / part
                    if cur.exists() or cur.is_symlink():
                        assert_not_symlink(cur)
                return
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)

    @staticmethod
    def _entry_key(strategy_id: str, revision: int) -> str:
        return f"{strategy_id}@v{revision}"

    def _validate_persisted_payload(self, payload: Mapping[str, Any]) -> None:
        if payload.get("schema") != self.SCHEMA_VERSION:
            raise ValueError(f"INVALID_LEDGER_SCHEMA: expected {self.SCHEMA_VERSION}, got {payload.get('schema')!r}")
        serialized = canonical_json_dumps(payload)
        assert_no_raw_secrets(serialized, context="MonotonicPromotionLedger")
        egress = scan_artifact_egress(serialized, context="promotion_ledger")
        if not egress.get("ok"):
            raise ValueError("PROMOTION_LEDGER_SECRET_LEAK_BLOCKED")
        assert_strategy_respects_guardrails(payload.get("entries"), context="ledger.entries")
        assert_strategy_respects_guardrails(payload.get("active_pointer"), context="ledger.active_pointer")

    def load(self) -> None:
        """Load persisted ledger securely using `assert_not_symlink`, `O_NOFOLLOW`, and `S_ISREG` checks."""
        if self.path is None:
            return
        self._assert_paths_not_symlink()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise PermissionError(f"PROMOTION_LEDGER_OPEN_REFUSED: {exc}") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError("PROMOTION_LEDGER_NOT_REGULAR_FILE")
            raw = json.load(handle)

        if not isinstance(raw, Mapping):
            raise ValueError("PROMOTION_LEDGER_CORRUPT_ROOT")
        self._validate_persisted_payload(raw)

        self._entries = {str(k): dict(v) for k, v in (raw.get("entries") or {}).items()}
        self.events = [dict(ev) for ev in (raw.get("events") or [])]
        self.active_pointer = dict(raw["active_pointer"]) if isinstance(raw.get("active_pointer"), Mapping) else None
        self.previous_active_pointer = (
            dict(raw["previous_active_pointer"])
            if isinstance(raw.get("previous_active_pointer"), Mapping)
            else None
        )
        self._active_stack = [dict(p) for p in (raw.get("active_stack") or []) if isinstance(p, Mapping)]

    def _save(self) -> None:
        if self.path is None:
            return
        self._assert_paths_not_symlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = redact_runtime_value(
            {
                "schema": self.SCHEMA_VERSION,
                "active_pointer": self.active_pointer,
                "previous_active_pointer": self.previous_active_pointer,
                "active_stack": self._active_stack,
                "entries": self._entries,
                "events": self.events,
            }
        )
        self._validate_persisted_payload(payload)
        atomic_write_json(self.path, payload, mode=0o600, indent=2)

    def _require_transition(self, current: Optional[StrategyStage], target: StrategyStage, key: str) -> None:
        allowed = MONOTONIC_STAGE_TRANSITIONS.get(current, frozenset())
        if target not in allowed:
            cur_label = current.value if current is not None else "UNREGISTERED"
            raise PromotionGateError(
                f"INVALID_STAGE_TRANSITION ({key}): {cur_label} -> {target.value} is forbidden."
            )

    def _append_event(self, event_type: str, details: Mapping[str, Any]) -> Dict[str, Any]:
        prev_hash = self.events[-1]["event_hash"] if self.events else "sha256:" + ("0" * 64)
        body = {
            "seq": len(self.events) + 1,
            "event": event_type,
            "timestamp": _utc_now_iso(),
            "prev_hash": prev_hash,
            **dict(details),
        }
        event_hash = sha256_digest(body)
        record = redact_runtime_value({**body, "event_hash": event_hash})
        self.events.append(record)
        return record

    def _require_entry(self, strategy_id: str, revision: int) -> Tuple[str, int, str, Dict[str, Any]]:
        clean_sid = _validate_strategy_id(strategy_id)
        rev = _strict_pos_int(revision, field_name="revision")
        key = self._entry_key(clean_sid, rev)
        entry = self._entries.get(key)
        if entry is None:
            raise PromotionGateError(f"UNKNOWN_STRATEGY: {key}")
        return clean_sid, rev, key, entry

    def get_stage(self, strategy_id: str, revision: int = 1) -> Optional[StrategyStage]:
        key = self._entry_key(_validate_strategy_id(strategy_id), _strict_pos_int(revision, field_name="revision"))
        entry = self._entries.get(key)
        if entry is None:
            return None
        return StrategyStage(str(entry["stage"]))

    def get_entry(self, strategy_id: str, revision: int = 1) -> Optional[Dict[str, Any]]:
        key = self._entry_key(_validate_strategy_id(strategy_id), _strict_pos_int(revision, field_name="revision"))
        entry = self._entries.get(key)
        return copy.deepcopy(entry) if entry is not None else None

    def register_candidate(
        self,
        strategy_id: str,
        revision: int = 1,
        *,
        spec: Optional[Mapping[str, Any]] = None,
        pinned_baseline_rate: Union[Decimal, int, str, float] = _ZERO_DEC,
        pinned_max_fp_rate: Union[Decimal, int, str, float] = _ZERO_DEC,
    ) -> Dict[str, Any]:
        """Register a new candidate strategy revision at `CANDIDATE` after guardrail validation."""
        clean_sid = _validate_strategy_id(strategy_id)
        rev = _strict_pos_int(revision, field_name="revision")
        assert_strategy_respects_guardrails(spec, context="register_candidate.spec")

        baseline_rate_dec = _to_exact_decimal(
            pinned_baseline_rate, field_name="pinned_baseline_rate", allow_zero=True
        )
        max_fp_dec = _to_exact_decimal(pinned_max_fp_rate, field_name="pinned_max_fp_rate", allow_zero=True)
        if baseline_rate_dec > _ONE_DEC or max_fp_dec > _ONE_DEC:
            raise ValueError("PINNED_RATE_OUT_OF_RANGE: baseline rates must be within [0, 1].")

        key = self._entry_key(clean_sid, rev)
        if key in self._entries:
            raise PromotionGateError(f"DUPLICATE_CANDIDATE_REVISION: {key} already registered.")
        self._require_transition(None, StrategyStage.CANDIDATE, key)

        sanitized_spec = redact_runtime_value(
            {
                k: (v.to_dict() if hasattr(v, "to_dict") and callable(v.to_dict) else v)
                for k, v in dict(spec or {}).items()
            }
        )
        entry = {
            "strategy_id": clean_sid,
            "revision": rev,
            "stage": StrategyStage.CANDIDATE.value,
            "spec": sanitized_spec,
            "pinned_baseline": {
                "baseline_pass_rate": str(baseline_rate_dec.quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)),
                "max_fp_rate": str(max_fp_dec.quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)),
            },
            "ablation": None,
            "canary_slices": [],
            "enforced_slices": [],
            "reviewer_approved": False,
            "rollback_reason": "",
            "updated_at": _utc_now_iso(),
        }
        self._entries[key] = entry
        self._append_event(
            "register_candidate",
            {"strategy_id": clean_sid, "revision": rev, "stage": StrategyStage.CANDIDATE.value},
        )
        self._save()
        return copy.deepcopy(entry)

    def _assert_ablation_satisfies_gate(self, ablation: CausalAblationResult, clean_sid: str, rev: int) -> None:
        if ablation.strategy_id != clean_sid or ablation.revision != rev:
            raise PromotionGateError(
                f"ABLATION_IDENTITY_MISMATCH: expected ({clean_sid}, v{rev}), "
                f"got ({ablation.strategy_id}, v{ablation.revision})"
            )
        if not ablation.disjoint_verified or not ablation.heldout_verified:
            raise PromotionGateError("PROMOTION_GATE_FAILED: verified disjoint holdout generalization required.")
        if ablation.total_matched < self.min_sample_size:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED: sample_size={ablation.total_matched} < min_sample_size={self.min_sample_size}"
            )
        if ablation.with_wilson_lb < self.min_wilson_lb:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED: with_wilson_lb={ablation.with_wilson_lb:.6f} < {self.min_wilson_lb:.6f}"
            )
        if ablation.wilson_lb_delta <= 0.0:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED: non-positive wilson_lb_delta={ablation.wilson_lb_delta:.6f}"
            )
        if ablation.baseline_regressions > 0:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED: baseline_regressions={ablation.baseline_regressions} > 0"
            )
        if ablation.false_positive_delta > 0:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED: false_positive_delta={ablation.false_positive_delta} > 0"
            )
        if not ablation.passed:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED: ablation rejected ({', '.join(ablation.rejection_reasons)})"
            )

    def promote_shadow(
        self,
        strategy_id: str,
        revision: int,
        ablation: CausalAblationResult,
    ) -> Dict[str, Any]:
        """Promote `CANDIDATE -> SHADOW` strictly after verifying causal ablation gate invariants."""
        clean_sid, rev, key, entry = self._require_entry(strategy_id, revision)

        assert_strategy_respects_guardrails(entry.get("spec"), context="promote_shadow.spec")
        self._require_transition(StrategyStage(entry["stage"]), StrategyStage.SHADOW, key)
        self._assert_ablation_satisfies_gate(ablation, clean_sid, rev)

        # Anchor pinned baseline to observed counterfactual control unless caller pinned a stricter baseline
        pinned_dec = _to_exact_decimal(
            entry["pinned_baseline"]["baseline_pass_rate"], field_name="baseline_pass_rate", allow_zero=True
        )
        effective_baseline = max(pinned_dec, ablation.without_success_rate)
        entry["pinned_baseline"]["baseline_pass_rate"] = str(
            effective_baseline.quantize(_DECIMAL_QUANT, rounding=ROUND_HALF_UP)
        )
        entry["ablation"] = ablation.to_dict()
        entry["stage"] = StrategyStage.SHADOW.value
        entry["updated_at"] = _utc_now_iso()

        self._append_event(
            "promote_shadow",
            {
                "strategy_id": clean_sid,
                "revision": rev,
                "stage": StrategyStage.SHADOW.value,
                "evidence_digest": ablation.evidence_digest,
                "wilson_lb_delta": ablation.wilson_lb_delta,
            },
        )
        self._save()
        return copy.deepcopy(entry)

    def _slice_regresses_against_pin(self, entry: Mapping[str, Any], vslice: VerificationSlice) -> Optional[str]:
        pinned_pass = _to_exact_decimal(
            entry["pinned_baseline"]["baseline_pass_rate"], field_name="pinned_baseline_pass_rate", allow_zero=True
        )
        pinned_max_fp = _to_exact_decimal(
            entry["pinned_baseline"]["max_fp_rate"], field_name="pinned_max_fp_rate", allow_zero=True
        )
        if vslice.baseline_regressions > 0:
            return f"BASELINE_SCAR_REGRESSION: count={vslice.baseline_regressions}"
        if vslice.fp_rate > pinned_max_fp:
            return f"FALSE_POSITIVE_REGRESSION: fp_rate={vslice.fp_rate} > pinned_max_fp={pinned_max_fp}"
        if vslice.pass_rate < pinned_pass:
            return f"SLICE_PASS_RATE_REGRESSION: pass_rate={vslice.pass_rate} < pinned_baseline={pinned_pass}"
        return None

    def _activate_pointer(self, entry: Mapping[str, Any], stage: StrategyStage) -> None:
        new_ptr = {
            "strategy_id": entry["strategy_id"],
            "revision": entry["revision"],
            "stage": stage.value,
            "evidence_digest": (entry.get("ablation") or {}).get("evidence_digest", ""),
            "updated_at": _utc_now_iso(),
        }
        cur = self.active_pointer
        if cur is not None and not (
            cur.get("strategy_id") == new_ptr["strategy_id"] and cur.get("revision") == new_ptr["revision"]
        ):
            self._active_stack.append(dict(cur))
            self.previous_active_pointer = dict(cur)
        elif cur is None:
            self.previous_active_pointer = None
        self.active_pointer = new_ptr

    def rollback(
        self,
        strategy_id: str,
        revision: int,
        *,
        reason: str,
        slice_report: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Fail-fast `ROLLED_BACK` transition atomically restoring the previous active pointer (`0o600`)."""
        clean_sid, rev, key, entry = self._require_entry(strategy_id, revision)

        cur_stage = StrategyStage(entry["stage"])
        self._require_transition(cur_stage, StrategyStage.ROLLED_BACK, key)
        clean_reason = redact_runtime_text(validate_safe_text(reason, field_name="rollback_reason"))

        entry["stage"] = StrategyStage.ROLLED_BACK.value
        entry["rollback_reason"] = clean_reason
        entry["updated_at"] = _utc_now_iso()

        self._active_stack = [
            p
            for p in self._active_stack
            if not (p.get("strategy_id") == clean_sid and int(p.get("revision", 0)) == rev)
        ]

        restored: Optional[Dict[str, Any]] = None
        if (
            self.active_pointer is not None
            and self.active_pointer.get("strategy_id") == clean_sid
            and int(self.active_pointer.get("revision", 0)) == rev
        ):
            restored = self._active_stack.pop() if self._active_stack else None
            self.active_pointer = restored
            self.previous_active_pointer = dict(self._active_stack[-1]) if self._active_stack else None
        else:
            restored = dict(self.active_pointer) if self.active_pointer is not None else None
            self.previous_active_pointer = dict(self._active_stack[-1]) if self._active_stack else None

        self._append_event(
            "rollback",
            {
                "strategy_id": clean_sid,
                "revision": rev,
                "from_stage": cur_stage.value,
                "stage": StrategyStage.ROLLED_BACK.value,
                "reason": clean_reason,
                "restored_pointer": restored,
                "slice": dict(slice_report) if slice_report is not None else None,
            },
        )
        self._save()
        return {
            "strategy_id": clean_sid,
            "revision": rev,
            "stage": StrategyStage.ROLLED_BACK.value,
            "rolled_back": True,
            "reason": clean_reason,
            "active_pointer": copy.deepcopy(self.active_pointer),
            "restored_pointer": copy.deepcopy(restored),
        }

    def promote_canary(
        self,
        strategy_id: str,
        revision: int,
        *,
        verification_slice: Optional[Union[VerificationSlice, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Promote `SHADOW -> CANARY` (or fail-fast `ROLLED_BACK` if initial canary slice regresses)."""
        clean_sid, rev, key, entry = self._require_entry(strategy_id, revision)

        assert_strategy_respects_guardrails(entry.get("spec"), context="promote_canary.spec")
        self._require_transition(StrategyStage(entry["stage"]), StrategyStage.CANARY, key)

        if entry.get("ablation") is None:
            raise PromotionGateError(f"PROMOTION_GATE_FAILED: {key} lacks verified CausalAblationResult.")

        entry["stage"] = StrategyStage.CANARY.value
        entry["updated_at"] = _utc_now_iso()
        self._activate_pointer(entry, StrategyStage.CANARY)

        if verification_slice is not None:
            vslice = VerificationSlice.coerce(verification_slice)
            entry["canary_slices"].append(vslice.to_dict())
            reg_reason = self._slice_regresses_against_pin(entry, vslice)
            if reg_reason is not None:
                self._append_event(
                    "promote_canary_provisional",
                    {"strategy_id": clean_sid, "revision": rev, "slice": vslice.to_dict()},
                )
                return self.rollback(clean_sid, rev, reason=reg_reason, slice_report=vslice.to_dict())

        self._append_event(
            "promote_canary",
            {
                "strategy_id": clean_sid,
                "revision": rev,
                "stage": StrategyStage.CANARY.value,
                "active_pointer": self.active_pointer,
            },
        )
        self._save()
        return {
            **copy.deepcopy(entry),
            "rolled_back": False,
            "active_pointer": copy.deepcopy(self.active_pointer),
        }

    def verify_slice(
        self,
        strategy_id: str,
        revision: int,
        verification_slice: Union[VerificationSlice, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Verify a live `CANARY` or `ENFORCED` verification batch against pinned baseline.

        Automatically executes fail-fast rollback (`ROLLED_BACK`) and atomically restores the
        previous active pointer if any regression is detected.
        """
        clean_sid, rev, key, entry = self._require_entry(strategy_id, revision)

        cur_stage = StrategyStage(entry["stage"])
        if cur_stage not in {StrategyStage.CANARY, StrategyStage.ENFORCED}:
            raise PromotionGateError(
                f"INVALID_SLICE_STAGE ({key}): verification slices apply to CANARY/ENFORCED, got {cur_stage.value}"
            )

        vslice = VerificationSlice.coerce(verification_slice)
        bucket = "canary_slices" if cur_stage == StrategyStage.CANARY else "enforced_slices"
        entry[bucket].append(vslice.to_dict())

        reg_reason = self._slice_regresses_against_pin(entry, vslice)
        if reg_reason is not None:
            return self.rollback(clean_sid, rev, reason=reg_reason, slice_report=vslice.to_dict())

        entry["updated_at"] = _utc_now_iso()
        self._append_event(
            "verify_slice",
            {
                "strategy_id": clean_sid,
                "revision": rev,
                "stage": cur_stage.value,
                "slice": vslice.to_dict(),
            },
        )
        self._save()
        return {
            "strategy_id": clean_sid,
            "revision": rev,
            "stage": cur_stage.value,
            "passed": True,
            "rolled_back": False,
            "slice": vslice.to_dict(),
            "active_pointer": copy.deepcopy(self.active_pointer),
        }

    def promote_enforced(
        self,
        strategy_id: str,
        revision: int,
        *,
        reviewer_approved: bool = False,
        verification_slice: Optional[Union[VerificationSlice, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Promote `CANARY -> ENFORCED` requiring `reviewer_approved=True` (or fail-fast rollback on slice regression)."""
        clean_sid, rev, key, entry = self._require_entry(strategy_id, revision)

        assert_strategy_respects_guardrails(entry.get("spec"), context="promote_enforced.spec")
        self._require_transition(StrategyStage(entry["stage"]), StrategyStage.ENFORCED, key)
        if reviewer_approved is not True:
            raise PromotionGateError(
                f"PROMOTION_GATE_FAILED ({key}): Enforced promotion requires reviewer_approved=True."
            )

        if verification_slice is not None:
            vslice = VerificationSlice.coerce(verification_slice)
            entry["canary_slices"].append(vslice.to_dict())
            reg_reason = self._slice_regresses_against_pin(entry, vslice)
            if reg_reason is not None:
                return self.rollback(clean_sid, rev, reason=reg_reason, slice_report=vslice.to_dict())

        entry["reviewer_approved"] = True
        entry["stage"] = StrategyStage.ENFORCED.value
        entry["updated_at"] = _utc_now_iso()
        self._activate_pointer(entry, StrategyStage.ENFORCED)

        self._append_event(
            "promote_enforced",
            {
                "strategy_id": clean_sid,
                "revision": rev,
                "stage": StrategyStage.ENFORCED.value,
                "active_pointer": self.active_pointer,
            },
        )
        self._save()
        return {
            **copy.deepcopy(entry),
            "rolled_back": False,
            "active_pointer": copy.deepcopy(self.active_pointer),
        }


class EvolutionEngineV4:
    """
    Stage 5 Causal Counterfactual & Adaptive Token Economics Self-Evolution Engine v4 (`SelfEvolutionV4/1`).

    Coordinates counterfactual ablation across disjoint task families, exact Wilson lower-bound
    ranking, `ExecutionMode`-isolated `AdaptiveBudgetController`, immutable guardrail refusal, and
    `MonotonicPromotionLedger` lifecycle governance (`CANDIDATE -> SHADOW -> CANARY -> ENFORCED` / `ROLLED_BACK`).
    """

    SCHEMA_VERSION = EVOLUTION_V4_SCHEMA

    def __init__(
        self,
        *,
        mode: Union[ExecutionMode, OperatingProfile, str] = ExecutionMode.GITHUB_PUBLIC,
        workspace_root: Optional[Union[str, Path]] = None,
        ledger_path: Optional[Union[str, Path]] = None,
        strategy_memory_path: Optional[Union[str, Path]] = None,
        budget_controller: Optional[AdaptiveBudgetController] = None,
        min_sample_size: int = 5,
        min_wilson_lb: float = 0.5,
        z_score: float = DEFAULT_WILSON_Z,
    ) -> None:
        self.mode = _normalize_execution_mode(mode)
        self.min_sample_size = _strict_pos_int(min_sample_size, field_name="min_sample_size")
        self.min_wilson_lb = float(min_wilson_lb)
        self.z_score = float(z_score)

        self.workspace_root: Optional[Path] = None
        if workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            self.workspace_root = ws.resolve()

        self.budget_controller = (
            budget_controller
            if budget_controller is not None
            else AdaptiveBudgetController(mode=self.mode)
        )
        self.ledger = MonotonicPromotionLedger(
            ledger_path=ledger_path,
            workspace_root=self.workspace_root,
            min_sample_size=self.min_sample_size,
            min_wilson_lb=self.min_wilson_lb,
        )
        self.strategy_memory: Optional[StrategyMemory] = None
        if self.workspace_root is not None or strategy_memory_path is not None:
            mem_target = strategy_memory_path or DEFAULT_STRATEGY_MEMORY_REL_PATH
            self.strategy_memory = StrategyMemory(mem_target, workspace_root=self.workspace_root)

    def validate_strategy_mutation(self, strategy_id: str, spec: Optional[Mapping[str, Any]] = None) -> str:
        """Validate `strategy_id` and `spec` against immutable security guardrails."""
        clean_sid = _validate_strategy_id(strategy_id)
        assert_strategy_respects_guardrails(spec, context="EvolutionEngineV4.validate_strategy_mutation")
        return clean_sid

    def evaluate_ablation_trials(
        self,
        *,
        strategy_id: str,
        revision: int = 1,
        train_families: Sequence[Any],
        heldout_families: Sequence[Any],
        trials: Sequence[Union[MatchedTaskTrial, Mapping[str, Any]]],
        spec: Optional[Mapping[str, Any]] = None,
        extra_baseline_regressions: int = 0,
    ) -> CausalAblationResult:
        """Score pre-collected matched counterfactual trials with strict leakage, guardrail, and budget checks."""
        clean_sid = self.validate_strategy_mutation(strategy_id, spec)
        verify_disjoint_families(train_families, heldout_families)
        for item in trials:
            trial = MatchedTaskTrial.from_mapping(item)
            self.budget_controller.consume(
                tokens=trial.tokens_used,
                steps=1,
                latency_ms=trial.latency_ms,
            )
        return CausalAblationResult.from_trials(
            strategy_id=clean_sid,
            revision=revision,
            train_families=train_families,
            heldout_families=heldout_families,
            trials=trials,
            z_score=self.z_score,
            min_sample_size=self.min_sample_size,
            min_wilson_lb=self.min_wilson_lb,
            extra_baseline_regressions=extra_baseline_regressions,
        )

    def evaluate_causal_ablation(
        self,
        *,
        strategy_id: str,
        revision: int = 1,
        train_families: Sequence[Any],
        heldout_families: Sequence[Any],
        heldout_tasks: Sequence[Mapping[str, Any]],
        with_strategy_fn: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        without_strategy_fn: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        spec: Optional[Mapping[str, Any]] = None,
        residual_variance: Union[Decimal, int, str, float] = Decimal("0.10"),
    ) -> Tuple[CausalAblationResult, ExplorationPlan]:
        """
        Execute live matched counterfactual ablation across `heldout_tasks` under `AdaptiveBudgetController`.

        Raises `CorpusLeakageError` (`ValueError`) on train/heldout overlap, `ImmutableGuardrailError`
        on security mutation attempts, and `BudgetExceededError` under `GITHUB_PUBLIC` overruns.
        """
        clean_sid = self.validate_strategy_mutation(strategy_id, spec)
        verify_disjoint_families(train_families, heldout_families)
        plan = self.budget_controller.plan_exploration(residual_variance)

        matched_trials: List[MatchedTaskTrial] = []
        for idx, task in enumerate(heldout_tasks):
            fam_id = str(task.get("family_id") or "")
            task_id = str(task.get("task_id") or f"task-{idx}")
            est_tokens = _strict_nonneg_int(task.get("estimated_tokens", 0), field_name="estimated_tokens")
            est_lat = _to_exact_decimal(task.get("estimated_latency_ms", _ZERO_DEC), field_name="estimated_latency_ms")
            self.budget_controller.check_limits(
                additional_tokens=est_tokens,
                additional_steps=1,
                additional_latency_ms=est_lat,
            )

            base_out = dict(without_strategy_fn(task) or {})
            strat_out = dict(with_strategy_fn(task) or {})

            tokens_used = _strict_nonneg_int(strat_out.get("tokens_used", est_tokens), field_name="tokens_used")
            lat_ms = _to_exact_decimal(strat_out.get("latency_ms", est_lat), field_name="latency_ms")
            self.budget_controller.consume(tokens=tokens_used, steps=1, latency_ms=lat_ms)

            matched_trials.append(
                MatchedTaskTrial(
                    family_id=fam_id,
                    task_id=task_id,
                    with_passed=_strict_bool(strat_out.get("passed", False), field_name="with_passed"),
                    without_passed=_strict_bool(base_out.get("passed", False), field_name="without_passed"),
                    with_fp=_strict_nonneg_int(strat_out.get("false_positives", 0), field_name="with_fp"),
                    without_fp=_strict_nonneg_int(base_out.get("false_positives", 0), field_name="without_fp"),
                    baseline_regression=_strict_bool(
                        strat_out.get("baseline_regression", False),
                        field_name="baseline_regression",
                    ),
                    tokens_used=tokens_used,
                    latency_ms=lat_ms,
                )
            )

        self.budget_controller.record_round()
        result = CausalAblationResult.from_trials(
            strategy_id=clean_sid,
            revision=revision,
            train_families=train_families,
            heldout_families=heldout_families,
            trials=matched_trials,
            z_score=self.z_score,
            min_sample_size=self.min_sample_size,
            min_wilson_lb=self.min_wilson_lb,
        )
        return result, plan

    @staticmethod
    def rank_ablations(results: Sequence[CausalAblationResult]) -> List[CausalAblationResult]:
        """Sort `CausalAblationResult` items placing verified high-Wilson-LB strategies ahead of noisy tiny-N wins."""
        return sorted(results, key=lambda r: r.ranking_key())

    @staticmethod
    def select_best_ablation(results: Sequence[CausalAblationResult]) -> Optional[CausalAblationResult]:
        """Return the highest-ranked eligible `CausalAblationResult`, or `None` if none pass the gate."""
        ranked = EvolutionEngineV4.rank_ablations(results)
        for cand in ranked:
            if cand.eligible_for_promotion:
                return cand
        return None

    def register_and_promote(
        self,
        *,
        ablation: CausalAblationResult,
        spec: Optional[Mapping[str, Any]] = None,
        target_stage: Union[StrategyStage, str] = StrategyStage.ENFORCED,
        canary_slice: Optional[Union[VerificationSlice, Mapping[str, Any]]] = None,
        pinned_baseline_rate: Optional[Union[Decimal, int, str, float]] = None,
        reviewer_approved: bool = False,
    ) -> Dict[str, Any]:
        """Drive a candidate cleanly through `CANDIDATE -> SHADOW -> CANARY -> ENFORCED` (or auto `ROLLED_BACK`)."""
        self.validate_strategy_mutation(ablation.strategy_id, spec)
        stage_target = (
            target_stage
            if isinstance(target_stage, StrategyStage)
            else StrategyStage(str(target_stage).strip().upper())
        )
        if stage_target == StrategyStage.ROLLED_BACK:
            raise PromotionGateError("Cannot directly target ROLLED_BACK during promotion.")

        pinned_base = (
            pinned_baseline_rate if pinned_baseline_rate is not None else ablation.without_success_rate
        )
        entry = self.ledger.register_candidate(
            ablation.strategy_id,
            ablation.revision,
            spec=spec,
            pinned_baseline_rate=pinned_base,
        )
        if stage_target == StrategyStage.CANDIDATE:
            return entry

        entry = self.ledger.promote_shadow(ablation.strategy_id, ablation.revision, ablation)
        if stage_target == StrategyStage.SHADOW:
            return entry

        canary_res = self.ledger.promote_canary(
            ablation.strategy_id,
            ablation.revision,
            verification_slice=canary_slice,
        )
        if canary_res.get("rolled_back") or stage_target == StrategyStage.CANARY:
            return canary_res

        enforced_res = self.ledger.promote_enforced(
            ablation.strategy_id,
            ablation.revision,
            reviewer_approved=reviewer_approved,
        )
        if self.strategy_memory is not None and not enforced_res.get("rolled_back"):
            spec_map = spec or {}
            self.strategy_memory.record_outcome(
                task_class=str(spec_map.get("task_class") or "causal_evolution_v4"),
                decomposition_pattern=str(spec_map.get("decomposition_pattern") or "counterfactual_ablation"),
                synthesis_strategy=ablation.strategy_id,
                verified_outcome=True,
                task_id=ablation.heldout_families[-1],
                source_task_id=ablation.train_families[0],
                source_family=ablation.train_families[0],
                target_family=ablation.heldout_families[-1],
                evidence_digest=ablation.evidence_digest,
                is_cross_task_transfer=True,
                causal_verified=True,
            )
        return enforced_res


__all__ = [
    "BUDGET_CONTROLLER_SCHEMA",
    "CAUSAL_ABLATION_SCHEMA",
    "DEFAULT_PROMOTION_LEDGER_REL_PATH",
    "DEFAULT_WILSON_Z",
    "EVOLUTION_V4_SCHEMA",
    "FORBIDDEN_MUTATION_KEYS",
    "IMMUTABLE_GUARDRAIL_IDS",
    "IMMUTABLE_SECURITY_MODULES",
    "MONOTONIC_STAGE_TRANSITIONS",
    "PROMOTION_LEDGER_SCHEMA",
    "AdaptiveBudgetController",
    "CausalAblationResult",
    "CorpusLeakageError",
    "EvolutionEngineV4",
    "ExecutionMode",
    "ExplorationPlan",
    "ImmutableGuardrailError",
    "MatchedTaskTrial",
    "MonotonicPromotionLedger",
    "PromotionGateError",
    "StrategyStage",
    "VerificationSlice",
    "assert_strategy_respects_guardrails",
    "verify_disjoint_families",
]
