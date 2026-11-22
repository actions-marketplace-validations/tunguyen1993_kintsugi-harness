"""Stage 2 LEGO Tool Composer (`kintsugi.composition.tool_composer`).

Implements deterministic (`llm_calls=0`) backward-chaining DAG planning with strict
`PortContract/1` + `EffectContract/1` verification, `AdapterSpec/1` bridging, profile-aware
search bounds (`LOCAL_RESEARCH` vs `GITHUB_PUBLIC`), and checkpointed `SecureRunner` execution
backed by an append-only hash-chained `RunEvent/1` log.
"""

from __future__ import annotations

import heapq
import hmac
import json
import os
import re
import secrets
import stat
import time
from collections import deque
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.capability_graph import tool_violates_security_context
from kintsugi.capability.contracts_v2 import (
    GENESIS_EVENT_HASH,
    AbstainError,
    AdapterSpec,
    CompositionPlan,
    CompositionReceipt,
    EffectContract,
    PortCompatibilityResult,
    PortContract,
    RunEvent,
    compute_dag_effects,
    ports_compatible,
    verify_event_chain,
)
from kintsugi.capability.schemas import (
    VALID_RUN_ID_RE,
    CapabilityGap,
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    compute_tool_spec_security_digest,
    has_valid_verification_attestation,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.config import GithubPublicConfig, KintsugiConfig, OperatingProfile
from kintsugi.runtime.secure_runner import (
    SecureRunner,
    compute_callable_sha256,
    redact_runtime_text,
    redact_runtime_value,
)
from kintsugi.shield import (
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    resolve_safe_child_path,
)

_DEFAULT_MAX_BEAM_WIDTH = 64
_DEFAULT_MAX_SEARCH_NODES = 4096
_DEFAULT_MAX_SEARCH_SECONDS = 10.0

_NETWORK_TOKENS: FrozenSet[str] = frozenset(
    {"network", "network.outbound", "network.inbound", "net", "http", "https", "socket", "web"}
)
_NATIVE_PERMISSIONS: FrozenSet[str] = frozenset(
    {"native", "native.exec", "native.untrusted", "untrusted_native"}
)
_MAPPING_META_KEYS: FrozenSet[str] = frozenset(
    {
        "source",
        "target",
        "src",
        "dst",
        "from",
        "to",
        "source_field",
        "target_field",
        "transform",
        "op",
        "mode",
        "strategy",
        "description",
        "notes",
        "type",
        "unit",
        "kind",
        "format",
        "confidence",
        "status",
        "ambiguous",
        "strict_projection",
        "fields",
        "field_map",
    }
)
_DECLASSIFICATION_HINTS: Tuple[str, ...] = (
    "redact",
    "mask",
    "hash",
    "tokenize",
    "anonymize",
    "declassify",
    "sanitize",
)
_SAFE_ID_CLEAN_RE = re.compile(r"[^A-Za-z0-9._:-]+")


@dataclass
class MissingAdapterGap:
    """Diagnostic record describing an unbridgeable port compatibility gap."""

    producer_id: str
    consumer_id: str
    reasons: List[str] = field(default_factory=list)
    source_port: Optional[Dict[str, Any]] = None
    target_port: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "producer_id": self.producer_id,
            "consumer_id": self.consumer_id,
            "reasons": list(self.reasons),
            "source_port": dict(self.source_port) if self.source_port is not None else None,
            "target_port": dict(self.target_port) if self.target_port is not None else None,
        }


@dataclass
class CompositionPlanResult:
    """Result returned by `ToolComposer.plan` (`CompositionPlanResult/1`, `llm_calls=0`)."""

    goal_id: str
    status: ExecutionStatus
    plan: Optional[CompositionPlan] = None
    executable: bool = False
    reasons: List[str] = field(default_factory=list)
    missing_capabilities: List[str] = field(default_factory=list)
    missing_adapters: List[Dict[str, Any]] = field(default_factory=list)
    diagnostics: Dict[str, Any] = field(default_factory=dict)
    llm_calls: int = 0
    schema: str = "CompositionPlanResult/1"

    @property
    def ok(self) -> bool:
        """Return True only when planning produced a verified executable `CompositionPlan`."""
        return self.plan is not None and self.status == ExecutionStatus.PASS and self.executable

    def __bool__(self) -> bool:
        return self.ok

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "goal_id": self.goal_id,
            "status": self.status.value,
            "executable": self.executable,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "reasons": list(self.reasons),
            "missing_capabilities": list(self.missing_capabilities),
            "missing_adapters": list(self.missing_adapters),
            "diagnostics": dict(self.diagnostics),
            "llm_calls": self.llm_calls,
        }


@dataclass(frozen=True)
class _NamedPort:
    name: str
    port: Optional[PortContract]


@dataclass
class _VerifiedToolEntry:
    spec: ToolSpec
    input_ports: Tuple[_NamedPort, ...]
    output_ports: Tuple[_NamedPort, ...]
    effect_contract: EffectContract
    capabilities: FrozenSet[str]
    memory_bonus: int = 0


@dataclass
class _VerifiedAdapterEntry:
    spec: AdapterSpec


@dataclass(frozen=True)
class _GoalPortSpec:
    name: str
    port: Optional[PortContract]
    capability: Optional[str] = None


@dataclass
class _GoalSpec:
    goal_id: str
    required_capabilities: Tuple[str, ...]
    input_ports: Tuple[_GoalPortSpec, ...]
    output_ports: Tuple[_GoalPortSpec, ...]
    input_bindings: Dict[str, Any]
    expected_outputs_raw: Union[List[Dict[str, Any]], Dict[str, Any]]
    oracle_ref: str
    verification_plan: Dict[str, Any]
    budget: Dict[str, Any]
    max_depth_override: Optional[int]
    goal_contract_hash: str


@dataclass(frozen=True)
class _OpenReq:
    consumer_key: str  # "goal" or internal node key
    consumer_port_name: str
    required_port: Optional[PortContract]
    required_capability: Optional[str]
    depth: int
    ancestor_tool_ids: FrozenSet[str]


@dataclass(frozen=True)
class _PlannedEdge:
    from_key: str  # internal node key (or "goal")
    to_key: str  # internal node key (or "goal")
    from_port: str
    to_port: str
    adapter_id: Optional[str] = None
    adapter_hash: Optional[str] = None


@dataclass
class _SearchState:
    node_tools: Dict[str, str]  # node_key -> tool_id
    node_caps: Dict[str, Tuple[str, ...]]  # node_key -> matched capabilities
    node_depths: Dict[str, int]  # node_key -> distance from goal
    edges: Tuple[_PlannedEdge, ...]
    goal_input_bindings: Tuple[Tuple[str, str, Optional[str], Optional[str]], ...]
    goal_output_bindings: Tuple[Tuple[str, str, Optional[str], Optional[str]], ...]
    open_reqs: Tuple[_OpenReq, ...]
    remaining_caps: FrozenSet[str]
    used_adapters: FrozenSet[str]
    next_node_idx: int
    cost_tuple: Tuple[float, ...]


def _sanitize_plan_id(raw_id: str) -> str:
    cleaned = _SAFE_ID_CLEAN_RE.sub("-", str(raw_id or "").strip()).strip(".-_:")
    if not cleaned or not cleaned[0].isalnum():
        cleaned = f"plan-{cleaned or '0'}"
    cleaned = cleaned[:128]
    if not VALID_RUN_ID_RE.fullmatch(cleaned):
        return f"plan-{sha256_digest(raw_id).split(':', 1)[1][:12]}"
    return cleaned


def _expected_context_policy_hash(security_context: SecurityContext) -> str:
    profile_val = getattr(security_context, "profile", SecurityProfile.LOCAL_RESEARCH)
    profile_str = profile_val.value if hasattr(profile_val, "value") else str(profile_val).strip().upper()
    return sha256_digest(
        {
            "schema": getattr(security_context, "schema", "SecurityContext/1"),
            "profile": profile_str,
            "workspace_root": str(getattr(security_context, "workspace_root", "")),
            "allowed_permissions": sorted(str(p) for p in getattr(security_context, "allowed_permissions", ())),
            "network_allowed": bool(getattr(security_context, "network_allowed", False)),
            "allow_untrusted_native": bool(getattr(security_context, "allow_untrusted_native", False)),
        }
    )


def _verify_security_context_integrity(security_context: SecurityContext) -> Optional[str]:
    """Return an error code if `security_context` fails workspace or policy-hash checks."""
    if not isinstance(security_context, SecurityContext):
        raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext instance.")
    ws_path = Path(security_context.workspace_root)
    try:
        assert_not_symlink(ws_path)
    except PermissionError as exc:
        return str(exc)
    if not ws_path.is_dir():
        return "WORKSPACE_ROOT_NOT_A_DIRECTORY"
    expected_hash = _expected_context_policy_hash(security_context)
    declared_hash = str(getattr(security_context, "policy_hash", "") or "").strip().lower()
    if not declared_hash or not is_valid_sha256(declared_hash):
        return "SECURITY_POLICY_HASH_MISSING_OR_INVALID"
    if not hmac.compare_digest(declared_hash, expected_hash):
        return "SECURITY_POLICY_HASH_TAMPERED"
    return None


def _derive_schema_ref(raw: Mapping[str, Any], semantic: Mapping[str, Any]) -> str:
    if raw.get("schema_ref"):
        return str(raw["schema_ref"]).strip()
    base_type = str(raw.get("type") or "").strip().lower()
    fmt = str(raw.get("format") or raw.get("schema") or semantic.get("schema") or "").strip().lower()
    if fmt and fmt != "portcontract/1":
        return f"{base_type}:{fmt}" if base_type else fmt
    if base_type:
        return f"{base_type}:object" if base_type == "json" else base_type
    return "json:object"


def _direction_semantic_value(semantic: Mapping[str, Any], direction: str, key: str) -> Any:
    dir_key = f"{direction}_{key}"
    if dir_key in semantic and semantic[dir_key] is not None:
        return semantic[dir_key]
    return semantic.get(key)


def _derive_semantic_type(
    raw: Mapping[str, Any],
    semantic: Mapping[str, Any],
    direction: str,
) -> str:
    explicit = raw.get("semantic_type") or _direction_semantic_value(semantic, direction, "semantic_type")
    if explicit:
        return str(explicit).strip()
    kind = _direction_semantic_value(semantic, direction, "kind")
    domain = _direction_semantic_value(semantic, direction, "domain")
    concept = _direction_semantic_value(semantic, direction, "concept")
    contract = _direction_semantic_value(semantic, direction, "contract")
    if domain and kind:
        return f"{str(domain).strip()}:{str(kind).strip()}"
    for val in (kind, concept, contract, domain, raw.get("semantic_contract")):
        if val:
            return str(val).strip()
    if raw.get("type"):
        return str(raw["type"]).strip()
    return "generic"


def _coerce_port_contract(
    raw: Any,
    *,
    semantic_contract: Optional[Mapping[str, Any]] = None,
    direction: str = "input",
) -> Optional[PortContract]:
    """Normalize a `PortContract/1`, dict, or legacy schema mapping into `PortContract`."""
    if raw is None:
        return None
    if isinstance(raw, PortContract):
        return raw
    if not isinstance(raw, Mapping):
        raise ValueError(f"INVALID_PORT_SPEC ({direction}): expected PortContract or mapping.")
    if "port_contract" in raw and isinstance(raw["port_contract"], Mapping):
        return _coerce_port_contract(raw["port_contract"], semantic_contract=semantic_contract, direction=direction)
    if "port" in raw and isinstance(raw["port"], Mapping):
        return _coerce_port_contract(raw["port"], semantic_contract=semantic_contract, direction=direction)

    sem = dict(semantic_contract or {})
    if not raw:
        has_dir_sem = any(
            k.startswith(f"{direction}_") for k in sem
        ) or (direction == "output" and any(k in sem for k in ("semantic_type", "kind", "concept")))
        if not has_dir_sem:
            return None

    if raw.get("schema") == "PortContract/1" or ("schema_ref" in raw and "semantic_type" in raw):
        return PortContract.from_dict(raw)

    inner_schema = raw.get("schema") if isinstance(raw.get("schema"), Mapping) else raw
    inner_sem = raw.get("semantic_contract") if isinstance(raw.get("semantic_contract"), Mapping) else sem

    unit_val = (
        inner_schema.get("unit")
        or inner_schema.get("units")
        or _direction_semantic_value(inner_sem, direction, "unit")
        or _direction_semantic_value(inner_sem, direction, "units")
        or "none"
    )
    return PortContract(
        schema_ref=_derive_schema_ref(inner_schema, inner_sem),
        semantic_type=_derive_semantic_type(inner_schema, inner_sem, direction),
        encoding=str(inner_schema.get("encoding") or _direction_semantic_value(inner_sem, direction, "encoding") or "utf-8"),
        unit=str(unit_val),
        cardinality=str(
            inner_schema.get("cardinality") or _direction_semantic_value(inner_sem, direction, "cardinality") or "one"
        ),
        ordering=str(
            inner_schema.get("ordering") or _direction_semantic_value(inner_sem, direction, "ordering") or "unordered"
        ),
        sensitivity=str(
            inner_schema.get("sensitivity") or _direction_semantic_value(inner_sem, direction, "sensitivity") or "public"
        ),
        trust_label=str(
            inner_schema.get("trust_label") or _direction_semantic_value(inner_sem, direction, "trust_label") or "trusted"
        ),
        streaming=inner_schema.get("streaming", _direction_semantic_value(inner_sem, direction, "streaming")),
        precision=inner_schema.get("precision") or _direction_semantic_value(inner_sem, direction, "precision"),
        nullable=bool(inner_schema.get("nullable", _direction_semantic_value(inner_sem, direction, "nullable") or False)),
    )


def _extract_named_ports(
    spec: ToolSpec,
    direction: str,
) -> Tuple[_NamedPort, ...]:
    """Extract typed input or output ports from a `ToolSpec` without mutating it."""
    sem = dict(spec.semantic_contract or {})
    req = dict(spec.runtime_requirements or {})
    raw_schema = dict(spec.input_schema if direction == "input" else spec.output_schema)
    default_name = "in" if direction == "input" else "out"

    multi_raw = (
        getattr(spec, f"{direction}_ports", None)
        or sem.get(f"{direction}_ports")
        or req.get(f"{direction}_ports")
        or raw_schema.get("ports")
    )
    if isinstance(multi_raw, Mapping) and multi_raw:
        ports: List[_NamedPort] = []
        for pname in sorted(multi_raw.keys()):
            coerced = _coerce_port_contract(multi_raw[pname], semantic_contract=sem, direction=direction)
            if coerced is not None:
                ports.append(_NamedPort(name=str(pname), port=coerced))
        if ports:
            return tuple(ports)

    explicit_single = (
        getattr(spec, f"{direction}_port", None)
        or sem.get(f"{direction}_port")
        or req.get(f"{direction}_port")
    )
    if explicit_single is not None:
        coerced = _coerce_port_contract(explicit_single, semantic_contract=sem, direction=direction)
        return (_NamedPort(name=default_name, port=coerced),) if coerced is not None else ()

    coerced_schema = _coerce_port_contract(raw_schema, semantic_contract=sem, direction=direction)
    if coerced_schema is not None:
        return (_NamedPort(name=default_name, port=coerced_schema),)
    return ()


def extract_tool_effect_contract(spec: ToolSpec) -> EffectContract:
    """Extract and merge a tool's `EffectContract/1` with `ToolSpec` permission & resource fields."""
    sem = dict(spec.semantic_contract or {})
    req = dict(spec.runtime_requirements or {})
    raw_eff = getattr(spec, "effect_contract", None) or req.get("effect_contract") or sem.get("effect_contract")

    base_eff = EffectContract.from_dict(raw_eff) if raw_eff is not None else EffectContract()
    side_effs = {str(s).strip().lower() for s in (spec.side_effects or ()) if str(s).strip()}

    read_scopes = list(base_eff.read_scopes)
    write_scopes = list(base_eff.write_scopes)
    network_scopes = list(base_eff.network_scopes)
    exec_permissions = sorted(set(base_eff.exec_permissions) | set(spec.required_permissions or ()))

    if "read_only" in side_effs and not read_scopes:
        read_scopes.append("workspace:read")
    if "workspace_write" in side_effs and not write_scopes:
        write_scopes.append("workspace:write")
    for tok in sorted(side_effs):
        if tok in _NETWORK_TOKENS or tok.startswith("network."):
            network_scopes.append(tok)
    if req.get("network") is True and not network_scopes:
        network_scopes.append("network:outbound")

    irreversible = bool(base_eff.irreversible or req.get("irreversible") or ("irreversible" in side_effs))
    idempotent = bool(
        base_eff.idempotent
        and not (req.get("idempotent") is False or "non_idempotent" in side_effs or irreversible)
    )

    resources = dict(base_eff.resource_requirements)
    if spec.latency_estimate_ms > 0 and "wall_time_ms" not in resources:
        resources["wall_time_ms"] = float(spec.latency_estimate_ms)
    if spec.memory_estimate_mb > 0 and "max_memory_mb" not in resources:
        resources["max_memory_mb"] = float(spec.memory_estimate_mb)
    if spec.api_token_estimate > 0 and "api_tokens" not in resources:
        resources["api_tokens"] = int(spec.api_token_estimate)

    return EffectContract(
        read_scopes=read_scopes,
        write_scopes=write_scopes,
        network_scopes=network_scopes,
        exec_permissions=exec_permissions,
        irreversible=irreversible,
        idempotent=idempotent,
        resource_requirements=resources,
    )


def _check_tool_budget(spec: ToolSpec, eff: EffectContract, budget: Mapping[str, Any]) -> List[str]:
    if not budget:
        return []
    reasons: List[str] = []
    res = eff.resource_requirements
    lat = max(float(spec.latency_estimate_ms), float(res.get("wall_time_ms", 0.0) or 0.0))
    mem = max(float(spec.memory_estimate_mb), float(res.get("max_memory_mb", res.get("memory_mb", 0.0)) or 0.0))
    tok = max(int(spec.api_token_estimate), int(res.get("api_tokens", res.get("tokens", 0)) or 0))
    if budget.get("max_latency_ms") is not None and lat > float(budget["max_latency_ms"]):
        reasons.append(f"BUDGET_LATENCY_EXCEEDED:{lat}>{float(budget['max_latency_ms'])}")
    if budget.get("max_memory_mb") is not None and mem > float(budget["max_memory_mb"]):
        reasons.append(f"BUDGET_MEMORY_EXCEEDED:{mem}>{float(budget['max_memory_mb'])}")
    if budget.get("max_api_tokens") is not None and tok > int(budget["max_api_tokens"]):
        reasons.append(f"BUDGET_TOKENS_EXCEEDED:{tok}>{int(budget['max_api_tokens'])}")
    return reasons


def _validate_tool_candidate(
    spec: ToolSpec,
    security_context: SecurityContext,
    config: KintsugiConfig,
    budget: Mapping[str, Any],
) -> Tuple[bool, Optional[EffectContract], List[str], ExecutionStatus]:
    """Validate trust lifecycle, independent attestation, `EffectContract`, and policy bounds."""
    try:
        validate_tool_id(spec.tool_id)
        if not is_valid_sha256(spec.binary_hash):
            return False, None, ["INVALID_BINARY_HASH"], ExecutionStatus.PERMISSION_DENIED
        serialized = spec.to_canonical_json()
        if TROJAN_UNICODE_RE.search(serialized) or PROMPT_INJECTION_RE.search(serialized):
            return False, None, ["UNSAFE_TOOL_METADATA"], ExecutionStatus.PERMISSION_DENIED
    except (ValueError, TypeError) as exc:
        return False, None, [f"INVALID_TOOL_SPEC:{exc}"], ExecutionStatus.PERMISSION_DENIED

    if spec.trust_status == TrustStatus.DISCOVERED:
        return False, None, ["UNVERIFIED_DISCOVERED_TOOL"], ExecutionStatus.NO_VERIFIED_TOOL
    if spec.trust_status in (TrustStatus.QUARANTINED, TrustStatus.RETIRED):
        return False, None, [f"TOOL_TRUST_STATUS_{spec.trust_status.value}"], ExecutionStatus.PERMISSION_DENIED
    if spec.trust_status != TrustStatus.VERIFIED:
        return False, None, [f"TOOL_TRUST_STATUS_{spec.trust_status}"], ExecutionStatus.PERMISSION_DENIED

    if not has_valid_verification_attestation(spec.verification_attestation, spec.binary_hash, spec.tool_id):
        return False, None, ["SPOOFED_OR_INVALID_VERIFICATION_ATTESTATION"], ExecutionStatus.PERMISSION_DENIED

    eff = extract_tool_effect_contract(spec)
    policy_reasons = list(tool_violates_security_context(spec, security_context))

    allowed_perms = set(security_context.allowed_permissions)
    extra_eff_perms = sorted(set(eff.exec_permissions) - allowed_perms)
    if extra_eff_perms:
        policy_reasons.append(f"OVER_PRIVILEGED_EFFECT_PERMISSIONS:{','.join(extra_eff_perms)}")

    network_allowed = bool(security_context.network_allowed)
    if config.profile == OperatingProfile.GITHUB_PUBLIC:
        network_allowed = network_allowed and bool(config.github_public.network_access)
    if not network_allowed and (
        eff.network_scopes
        or any(
            p.strip().lower() in _NETWORK_TOKENS or p.strip().lower().startswith("network.")
            for p in eff.exec_permissions
        )
    ):
        policy_reasons.append("NETWORK_DISALLOWED_BY_POLICY")

    if not security_context.allow_untrusted_native:
        req = dict(spec.runtime_requirements or {})
        if (
            spec.source.lower() in {"untrusted_native", "native_untrusted"}
            or bool(req.get("native"))
            or bool(req.get("untrusted_native"))
            or bool(set(p.lower() for p in eff.exec_permissions) & _NATIVE_PERMISSIONS)
        ):
            policy_reasons.append("UNTRUSTED_NATIVE_DISALLOWED_BY_CONTEXT")

    if policy_reasons:
        return False, eff, sorted(set(policy_reasons)), ExecutionStatus.PERMISSION_DENIED

    budget_reasons = _check_tool_budget(spec, eff, budget)
    if budget_reasons:
        return False, eff, budget_reasons, ExecutionStatus.INSUFFICIENT_EVIDENCE

    return True, eff, [], ExecutionStatus.PASS


def _validate_adapter_candidate(
    raw_adapter: Union[AdapterSpec, Mapping[str, Any]],
    *,
    authority: Optional[AttestationAuthority] = None,
) -> Tuple[Optional[AdapterSpec], List[str], ExecutionStatus]:
    """Re-verify `AdapterSpec` hash integrity, `VERIFIED` status, corpus hash, and HMAC authority."""
    try:
        adapter = AdapterSpec.from_dict(raw_adapter.to_dict() if isinstance(raw_adapter, AdapterSpec) else raw_adapter)
        if isinstance(raw_adapter, AdapterSpec):
            recomputed = AdapterSpec(
                adapter_id=raw_adapter.adapter_id,
                version=raw_adapter.version,
                source_port=raw_adapter.source_port,
                target_port=raw_adapter.target_port,
                mapping=dict(raw_adapter.mapping),
                unit_conversion=dict(raw_adapter.unit_conversion) if raw_adapter.unit_conversion is not None else None,
                lossless=raw_adapter.lossless,
                preconditions=list(raw_adapter.preconditions),
                verification_corpus_hash=raw_adapter.verification_corpus_hash,
                trust_status=raw_adapter.trust_status,
                verification_attestation=(
                    dict(raw_adapter.verification_attestation)
                    if raw_adapter.verification_attestation is not None
                    else None
                ),
            )
            if not hmac.compare_digest(recomputed.adapter_hash, raw_adapter.adapter_hash):
                return None, ["ADAPTER_HASH_TAMPERED"], ExecutionStatus.PERMISSION_DENIED
            adapter = recomputed
    except (AbstainError, ValueError, KeyError, TypeError) as exc:
        return None, [f"INVALID_ADAPTER_SPEC:{exc}"], ExecutionStatus.PERMISSION_DENIED

    if adapter.trust_status == TrustStatus.DISCOVERED:
        return None, [f"UNVERIFIED_DISCOVERED_ADAPTER:{adapter.adapter_id}"], ExecutionStatus.NO_VERIFIED_TOOL
    if adapter.trust_status != TrustStatus.VERIFIED:
        return None, [f"ADAPTER_TRUST_STATUS_{adapter.trust_status.value}:{adapter.adapter_id}"], ExecutionStatus.PERMISSION_DENIED
    if not is_valid_sha256(adapter.verification_corpus_hash):
        return None, [f"ADAPTER_MISSING_CORPUS_HASH:{adapter.adapter_id}"], ExecutionStatus.PERMISSION_DENIED
    if authority is None or not authority.has_registered_verifiers:
        return None, [f"ADAPTER_ATTESTATION_AUTHORITY_REQUIRED:{adapter.adapter_id}"], ExecutionStatus.PERMISSION_DENIED
    if not authority.verify_adapter_attestation(
        adapter.verification_attestation or {},
        expected_adapter_id=adapter.adapter_id,
        expected_adapter_hash=adapter.adapter_hash,
        expected_corpus_hash=adapter.verification_corpus_hash,
    ):
        return None, [f"SPOOFED_VERIFIED_ADAPTER_ATTESTATION:{adapter.adapter_id}"], ExecutionStatus.PERMISSION_DENIED
    return adapter, [], ExecutionStatus.PASS


def _extract_goal_spec(
    goal_contract: Union[CapabilityGap, Mapping[str, Any]],
) -> _GoalSpec:
    """Normalize a `CapabilityGap` or mapping goal contract into typed composition targets."""
    if isinstance(goal_contract, CapabilityGap):
        raw: Dict[str, Any] = {
            "goal_id": goal_contract.goal_id,
            "required_capabilities": list(goal_contract.required_capabilities),
            "input_artifacts": list(goal_contract.input_artifacts),
            "expected_outputs": list(goal_contract.expected_outputs),
            "acceptance_tests": list(goal_contract.acceptance_tests),
            "budget": dict(goal_contract.budget),
        }
    elif isinstance(goal_contract, Mapping):
        raw = dict(goal_contract)
    else:
        raise ValueError("INVALID_GOAL_CONTRACT: expected CapabilityGap or mapping.")

    raw_json = canonical_json_dumps(redact_secrets_in_value(raw))
    if "\x00" in raw_json or TROJAN_UNICODE_RE.search(raw_json):
        raise ValueError("REJECTED_TROJAN_UNICODE (goal_contract): control or bidi character detected.")
    if PROMPT_INJECTION_RE.search(raw_json):
        raise PermissionError("REJECTED_PROMPT_INJECTION (goal_contract)")

    raw_goal_id = str(raw.get("goal_id") or raw.get("task_id") or raw.get("id") or "").strip()
    if not raw_goal_id:
        raw_goal_id = f"goal-{sha256_digest(raw_json).split(':', 1)[1][:10]}"
    goal_id = validate_safe_text(raw_goal_id, field_name="goal_id")

    req_caps_raw = raw.get("required_capabilities") or ()
    req_caps = tuple(
        dict.fromkeys(validate_safe_text(str(c), field_name="required_capability") for c in req_caps_raw)
    )

    input_ports: List[_GoalPortSpec] = []
    if raw.get("input_port") is not None or raw.get("source_port") is not None:
        in_p = _coerce_port_contract(raw.get("input_port") or raw.get("source_port"), direction="input")
        if in_p is not None:
            input_ports.append(_GoalPortSpec(name="goal.in", port=in_p))
    for idx, item in enumerate(raw.get("input_artifacts") or ()):
        if isinstance(item, PortContract):
            input_ports.append(_GoalPortSpec(name=f"goal.in.{idx}", port=item))
        elif isinstance(item, Mapping):
            p = _coerce_port_contract(item, semantic_contract=item.get("semantic_contract"), direction="input")
            if p is not None:
                cap_hint = str(item.get("capability")).strip() if item.get("capability") else None
                input_ports.append(_GoalPortSpec(name=str(item.get("name") or f"goal.in.{idx}"), port=p, capability=cap_hint))

    output_ports: List[_GoalPortSpec] = []
    raw_expected = raw.get("expected_outputs")
    if raw.get("target_port") is not None or raw.get("output_port") is not None:
        out_p = _coerce_port_contract(raw.get("target_port") or raw.get("output_port"), direction="output")
        if out_p is not None:
            output_ports.append(_GoalPortSpec(name="goal.out", port=out_p))
    if isinstance(raw_expected, Mapping):
        p = _coerce_port_contract(raw_expected, semantic_contract=raw_expected.get("semantic_contract"), direction="output")
        if p is not None:
            cap_hint = str(raw_expected.get("capability")).strip() if raw_expected.get("capability") else None
            output_ports.append(_GoalPortSpec(name="goal.out", port=p, capability=cap_hint))
    elif isinstance(raw_expected, (list, tuple)):
        for idx, item in enumerate(raw_expected):
            if isinstance(item, PortContract):
                output_ports.append(_GoalPortSpec(name=f"goal.out.{idx}", port=item))
            elif isinstance(item, Mapping):
                p = _coerce_port_contract(item, semantic_contract=item.get("semantic_contract"), direction="output")
                cap_hint = str(item.get("capability")).strip() if item.get("capability") else None
                if p is not None or cap_hint is not None:
                    output_ports.append(_GoalPortSpec(name=str(item.get("name") or f"goal.out.{idx}"), port=p, capability=cap_hint))

    if isinstance(raw_expected, Mapping):
        expected_outputs_raw: Union[List[Dict[str, Any]], Dict[str, Any]] = redact_secrets_in_value(dict(raw_expected))
    elif isinstance(raw_expected, (list, tuple)):
        expected_outputs_raw = redact_secrets_in_value(
            [x.to_dict() if hasattr(x, "to_dict") else dict(x) for x in raw_expected if isinstance(x, (Mapping, PortContract))]
        )
    elif output_ports:
        expected_outputs_raw = [op.port.to_dict() for op in output_ports if op.port is not None]
    else:
        expected_outputs_raw = []

    oracle_ref = validate_safe_text(str(raw.get("oracle_ref") or f"oracle:{goal_id}"), field_name="oracle_ref")
    input_bindings = redact_secrets_in_value(dict(raw.get("input_bindings") or {}))
    verification_plan = redact_secrets_in_value(dict(raw.get("verification_plan") or {}))
    if raw.get("acceptance_tests") and "acceptance_tests" not in verification_plan:
        verification_plan["acceptance_tests"] = redact_secrets_in_value(list(raw.get("acceptance_tests") or []))
    budget = redact_secrets_in_value(dict(raw.get("budget") or {}))
    max_depth_raw = raw.get("max_depth")
    max_depth_override = int(max_depth_raw) if max_depth_raw is not None else None
    if max_depth_override is not None and max_depth_override < 1:
        raise ValueError("INVALID_MAX_DEPTH: max_depth must be >= 1.")

    goal_contract_hash = sha256_digest(
        {
            "goal_id": goal_id,
            "required_capabilities": list(req_caps),
            "input_ports": [ip.port.to_dict() for ip in input_ports if ip.port is not None],
            "output_ports": [op.port.to_dict() for op in output_ports if op.port is not None],
            "expected_outputs": expected_outputs_raw,
            "oracle_ref": oracle_ref,
            "budget": budget,
        }
    )

    return _GoalSpec(
        goal_id=goal_id,
        required_capabilities=req_caps,
        input_ports=tuple(input_ports),
        output_ports=tuple(output_ports),
        input_bindings=input_bindings,
        expected_outputs_raw=expected_outputs_raw,
        oracle_ref=oracle_ref,
        verification_plan=verification_plan,
        budget=budget,
        max_depth_override=max_depth_override,
        goal_contract_hash=goal_contract_hash,
    )


def _find_bridge_for_ports(
    src_port: PortContract,
    dst_port: PortContract,
    adapters: Sequence[_VerifiedAdapterEntry],
) -> Tuple[bool, Optional[AdapterSpec], List[str]]:
    """Return `(True, adapter_or_None, [])` if `src_port -> dst_port` is directly compatible or adapter-bridged."""
    direct: PortCompatibilityResult = ports_compatible(src_port, dst_port)
    if direct.compatible:
        return True, None, []

    for entry in sorted(adapters, key=lambda a: (0 if a.spec.lossless else 1, a.spec.adapter_id)):
        ad = entry.spec
        c_in = ports_compatible(src_port, ad.source_port)
        if not c_in.compatible:
            continue
        c_out = ports_compatible(ad.target_port, dst_port)
        if c_out.compatible:
            return True, ad, []

    return False, None, list(direct.reasons)


def _memory_bonus_map(
    composition_memory: Any,
    goal: _GoalSpec,
    security_context: SecurityContext,
    raw_goal_contract: Any = None,
    registry: Optional[ToolRegistry] = None,
) -> Dict[str, int]:
    """Read optional composition memory strictly as a ranking hint (never skips verification)."""
    if composition_memory is None:
        return {}
    bonuses: Dict[str, int] = {}
    items: List[Any] = []
    try:
        if hasattr(composition_memory, "retrieve") and callable(composition_memory.retrieve):
            lookup = composition_memory.retrieve(
                goal_contract=raw_goal_contract if isinstance(raw_goal_contract, (CapabilityGap, Mapping)) else None,
                current_policy_hash=security_context.policy_hash,
                current_oracle_ref=goal.oracle_ref,
                registry=registry,
                security_context=security_context,
                require_full_provenance=False,
            )
            if getattr(lookup, "hit", False) and getattr(lookup, "plan", None) is not None:
                reuse = int(getattr(getattr(lookup, "entry", None), "reuse_count", 0) or 0)
                for node in getattr(lookup.plan, "nodes", ()) or ():
                    tid = node.get("tool_id") if isinstance(node, Mapping) else None
                    if isinstance(tid, str) and tid:
                        bonuses[tid] = max(bonuses.get(tid, 0), 2 + max(0, reuse))
        if hasattr(composition_memory, "list_entries") and callable(composition_memory.list_entries):
            for entry in composition_memory.list_entries() or ():
                if getattr(entry, "attestation_revoked", False):
                    continue
                prov = getattr(entry, "provenance", None)
                if prov is not None and getattr(prov, "policy_hash", "") not in ("", security_context.policy_hash):
                    continue
                plan_obj = getattr(entry, "plan", None)
                reuse = int(getattr(entry, "reuse_count", 0) or 0)
                for node in getattr(plan_obj, "nodes", ()) or ():
                    tid = node.get("tool_id") if isinstance(node, Mapping) else None
                    if isinstance(tid, str) and tid:
                        bonuses[tid] = max(bonuses.get(tid, 0), 1 + max(0, reuse))
        elif hasattr(composition_memory, "retrieve_similar") and callable(composition_memory.retrieve_similar):
            for cap in goal.required_capabilities or ("",):
                hits = composition_memory.retrieve_similar(
                    capability=cap or None,
                    security_profile=security_context.profile,
                    verified_only=True,
                )
                items.extend(hits or ())
        elif hasattr(composition_memory, "list_experiences") and callable(composition_memory.list_experiences):
            items.extend(composition_memory.list_experiences() or ())
        elif isinstance(composition_memory, (list, tuple)):
            items.extend(composition_memory)
    except (ValueError, TypeError, AttributeError) as exc:
        _ = exc
        return bonuses

    for item in items:
        if hasattr(item, "is_positive_verified") and not item.is_positive_verified:
            continue
        tid = getattr(item, "tool_or_plan_id", None) or (item.get("tool_or_plan_id") if isinstance(item, Mapping) else None)
        if isinstance(tid, str) and tid:
            reuse = int(getattr(item, "reuse_count", 0) if not isinstance(item, Mapping) else item.get("reuse_count", 0) or 0)
            bonuses[tid] = max(bonuses.get(tid, 0), 1 + max(0, reuse))
        node_ids = item.get("tool_ids") if isinstance(item, Mapping) else getattr(item, "tool_ids", None)
        if isinstance(node_ids, (list, tuple)):
            for n_tid in node_ids:
                if isinstance(n_tid, str) and n_tid:
                    bonuses[n_tid] = max(bonuses.get(n_tid, 0), 1)
    return bonuses


def _would_create_cycle(
    src_key: str,
    dst_key: str,
    edges: Sequence[_PlannedEdge],
) -> bool:
    """Return True if adding `src_key -> dst_key` would introduce a cycle in the DAG."""
    if src_key == dst_key:
        return True
    adj: Dict[str, List[str]] = {}
    for edge in edges:
        adj.setdefault(edge.from_key, []).append(edge.to_key)
    visited: Set[str] = {dst_key}
    queue: deque[str] = deque([dst_key])
    while queue:
        cur = queue.popleft()
        if cur == src_key:
            return True
        for nxt in adj.get(cur, ()):
            if nxt not in visited:
                visited.add(nxt)
                queue.append(nxt)
    return False


def _compute_state_dag_depth(
    node_keys: Sequence[str],
    edges: Sequence[Union[_PlannedEdge, Tuple[str, str]]],
) -> int:
    """Return the longest node-path length across `edges` (>= 1 when `node_keys` is non-empty)."""
    if not node_keys:
        return 0
    adj: Dict[str, List[str]] = {k: [] for k in node_keys}
    indeg: Dict[str, int] = {k: 0 for k in node_keys}
    for edge in edges:
        src, dst = edge if isinstance(edge, tuple) else (edge.from_key, edge.to_key)
        if src in adj and dst in adj:
            adj[src].append(dst)
            indeg[dst] += 1
    depth_of: Dict[str, int] = {k: 1 for k in node_keys}
    queue = deque(k for k in node_keys if indeg[k] == 0)
    while queue:
        cur = queue.popleft()
        for nxt in adj[cur]:
            if depth_of[cur] + 1 > depth_of[nxt]:
                depth_of[nxt] = depth_of[cur] + 1
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                queue.append(nxt)
    return max(depth_of.values())


class _BackwardChainPlanner:
    """Bounded A* / beam backward-chaining search from goal outputs & capabilities."""

    def __init__(
        self,
        *,
        goal: _GoalSpec,
        tools_by_id: Mapping[str, _VerifiedToolEntry],
        adapters: Sequence[_VerifiedAdapterEntry],
        security_context: SecurityContext,
        config: KintsugiConfig,
        max_beam_width: int,
        max_search_nodes: int,
        max_search_seconds: float,
    ) -> None:
        self.goal = goal
        self.tools_by_id = tools_by_id
        self.adapters = tuple(adapters)
        self.security_context = security_context
        self.config = config
        self.max_beam_width = max(4, int(max_beam_width))
        self.max_search_nodes = max(1, int(max_search_nodes))
        self.max_search_seconds = max(0.05, float(max_search_seconds))

        if config.profile == OperatingProfile.GITHUB_PUBLIC:
            cfg_depth = int(config.github_public.max_composition_depth)
            self.max_depth: Optional[int] = (
                min(cfg_depth, goal.max_depth_override) if goal.max_depth_override is not None else cfg_depth
            )
            self.max_search_seconds = min(self.max_search_seconds, float(config.github_public.max_runtime_seconds))
        else:
            lr_depth = config.local_research.hard_composition_depth_limit
            if lr_depth is not None and goal.max_depth_override is not None:
                self.max_depth = min(int(lr_depth), goal.max_depth_override)
            elif lr_depth is not None:
                self.max_depth = int(lr_depth)
            else:
                self.max_depth = goal.max_depth_override

        self.nodes_expanded = 0
        self.states_deduped = 0
        self.depth_limit_hit = False
        self.cycle_rejected = False
        self.watchdog_triggered = False
        self.termination_reason = "NOT_STARTED"
        self.missing_gaps: List[MissingAdapterGap] = []
        self.sensitivity_or_trust_violations: List[str] = []
        self.budget_violations: List[str] = []

    def _record_port_mismatch(
        self,
        producer_id: str,
        consumer_id: str,
        src_port: PortContract,
        dst_port: PortContract,
        reasons: Sequence[str],
    ) -> None:
        for reason in reasons:
            if reason.startswith(("SENSITIVITY_FLOW_VIOLATION", "TRUST_LABEL_VIOLATION")):
                if reason not in self.sensitivity_or_trust_violations:
                    self.sensitivity_or_trust_violations.append(reason)
        if len(self.missing_gaps) < 25:
            gap = MissingAdapterGap(
                producer_id=producer_id,
                consumer_id=consumer_id,
                reasons=list(reasons),
                source_port=src_port.to_dict(),
                target_port=dst_port.to_dict(),
            )
            sig = canonical_json_dumps(gap.to_dict())
            if all(canonical_json_dumps(existing.to_dict()) != sig for existing in self.missing_gaps):
                self.missing_gaps.append(gap)

    def _can_ground_at_goal(
        self,
        required_port: Optional[PortContract],
        consumer_tool_id: str,
    ) -> Tuple[bool, Optional[str], Optional[AdapterSpec]]:
        """Check whether `required_port` can be supplied directly from `goal.input_ports`."""
        if required_port is None:
            return True, None, None
        if not self.goal.input_ports:
            return False, None, None
        for g_in in self.goal.input_ports:
            if g_in.port is None:
                continue
            ok, adapter, reasons = _find_bridge_for_ports(g_in.port, required_port, self.adapters)
            if ok:
                return True, g_in.name, adapter
            self._record_port_mismatch(g_in.name, consumer_tool_id, g_in.port, required_port, reasons)
        return False, None, None

    def _state_dedup_key(self, state: _SearchState) -> Tuple[Any, ...]:
        tools_sig = tuple(sorted((k, tid) for k, tid in state.node_tools.items()))
        edges_sig = tuple(sorted((e.from_key, e.to_key, e.from_port, e.to_port, e.adapter_id or "") for e in state.edges))
        reqs_sig = tuple(
            (
                r.consumer_key,
                r.consumer_port_name,
                r.required_capability or "",
                r.required_port.content_hash() if r.required_port is not None else "",
                r.depth,
            )
            for r in state.open_reqs
        )
        return (tools_sig, edges_sig, reqs_sig, tuple(sorted(state.remaining_caps)))

    def _score_state(self, state: _SearchState) -> Tuple[float, float, int, int, int, float, Tuple[str, ...]]:
        entries = [self.tools_by_id[tid] for tid in state.node_tools.values()]
        effects = compute_dag_effects([e.effect_contract for e in entries]) if entries else {"permission_union": [], "irreversible_any": False}
        perm_count = len(effects["permission_union"])
        irrev = 1 if effects.get("irreversible_any") else 0
        mem_bonus = sum(e.memory_bonus for e in entries)
        tokens = sum(e.spec.api_token_estimate for e in entries)
        latency = sum(e.spec.latency_estimate_ms for e in entries)
        h_rem = float(len(state.open_reqs) + len(state.remaining_caps))
        g_steps = float(len(state.node_tools) + (0.5 * len(state.used_adapters)))
        return (
            g_steps + h_rem - min(0.4, 0.05 * mem_bonus),
            float(len(state.used_adapters)),
            perm_count,
            irrev,
            tokens,
            latency,
            tuple(sorted(state.node_tools.values())),
        )

    def _next_requirement(
        self,
        state: _SearchState,
    ) -> Tuple[Optional[_OpenReq], Tuple[_OpenReq, ...], FrozenSet[str], bool]:
        """Select next port requirement first, then remaining capability requirements."""
        if state.open_reqs:
            return state.open_reqs[0], state.open_reqs[1:], state.remaining_caps, False
        if state.remaining_caps:
            next_cap = sorted(state.remaining_caps)[0]
            synth_req = _OpenReq(
                consumer_key="goal",
                consumer_port_name="capability",
                required_port=None,
                required_capability=next_cap,
                depth=1,
                ancestor_tool_ids=frozenset(),
            )
            return synth_req, (), state.remaining_caps - {next_cap}, True
        return None, (), state.remaining_caps, False

    def _check_state_dag_limits(
        self,
        node_tools: Mapping[str, str],
        edges: Sequence[_PlannedEdge],
    ) -> Tuple[bool, str]:
        depth = _compute_state_dag_depth(list(node_tools.keys()), edges)
        if self.max_depth is not None and depth > self.max_depth:
            self.depth_limit_hit = True
            return False, "MAX_COMPOSITION_DEPTH_EXCEEDED"
        entries = [self.tools_by_id[tid] for tid in node_tools.values()]
        effects = compute_dag_effects([e.effect_contract for e in entries])
        if not set(effects["permission_union"]).issubset(set(self.security_context.allowed_permissions)):
            return False, "OVER_PRIVILEGED_DAG_UNION"
        res = effects["effects_union"].get("resource_requirements", {})
        if self.goal.budget:
            if self.goal.budget.get("max_latency_ms") is not None:
                lat = float(res.get("wall_time_ms", 0.0) or 0.0)
                if lat > float(self.goal.budget["max_latency_ms"]):
                    self.budget_violations.append(f"DAG_BUDGET_LATENCY_EXCEEDED:{lat}")
                    return False, "DAG_BUDGET_LATENCY_EXCEEDED"
            if self.goal.budget.get("max_memory_mb") is not None:
                mem = float(res.get("max_memory_mb", 0.0) or 0.0)
                if mem > float(self.goal.budget["max_memory_mb"]):
                    self.budget_violations.append(f"DAG_BUDGET_MEMORY_EXCEEDED:{mem}")
                    return False, "DAG_BUDGET_MEMORY_EXCEEDED"
            if self.goal.budget.get("max_api_tokens") is not None:
                tok = int(res.get("api_tokens", 0) or 0)
                if tok > int(self.goal.budget["max_api_tokens"]):
                    self.budget_violations.append(f"DAG_BUDGET_TOKENS_EXCEEDED:{tok}")
                    return False, "DAG_BUDGET_TOKENS_EXCEEDED"
        return True, ""

    def _match_tool_outputs(
        self,
        entry: _VerifiedToolEntry,
        req: _OpenReq,
    ) -> List[Tuple[str, Optional[AdapterSpec]]]:
        if req.required_capability and req.required_capability not in entry.capabilities:
            return []
        if req.required_port is None:
            out_name = entry.output_ports[0].name if entry.output_ports else "out"
            return [(out_name, None)]
        matches: List[Tuple[str, Optional[AdapterSpec]]] = []
        for out_p in entry.output_ports:
            if out_p.port is None:
                continue
            ok, adapter, reasons = _find_bridge_for_ports(out_p.port, req.required_port, self.adapters)
            if ok:
                matches.append((out_p.name, adapter))
            else:
                self._record_port_mismatch(entry.spec.tool_id, req.consumer_key, out_p.port, req.required_port, reasons)
        return matches

    def _resolve_tool_inputs(
        self,
        node_key: str,
        entry: _VerifiedToolEntry,
        req_depth: int,
        child_ancestors: FrozenSet[str],
    ) -> Tuple[bool, List[_OpenReq], List[Tuple[str, str, Optional[str], Optional[str]]]]:
        """Ground input ports at `goal.input_ports` when compatible or push upstream `_OpenReq`s."""
        new_reqs: List[_OpenReq] = []
        goal_in_binds: List[Tuple[str, str, Optional[str], Optional[str]]] = []
        next_depth = req_depth + 1
        for in_p in entry.input_ports:
            if in_p.port is None:
                continue
            grounded, goal_in_name, goal_in_adapter = self._can_ground_at_goal(in_p.port, entry.spec.tool_id)
            if grounded and goal_in_name is not None:
                goal_in_binds.append(
                    (
                        f"{node_key}.{in_p.name}",
                        goal_in_name,
                        goal_in_adapter.adapter_id if goal_in_adapter else None,
                        goal_in_adapter.adapter_hash if goal_in_adapter else None,
                    )
                )
            else:
                if self.max_depth is not None and next_depth > self.max_depth:
                    self.depth_limit_hit = True
                    return False, [], []
                new_reqs.append(
                    _OpenReq(
                        consumer_key=node_key,
                        consumer_port_name=in_p.name,
                        required_port=in_p.port,
                        required_capability=None,
                        depth=next_depth,
                        ancestor_tool_ids=child_ancestors,
                    )
                )
        return True, new_reqs, goal_in_binds

    def _bind_edge_or_goal_output(
        self,
        *,
        state: _SearchState,
        producer_key: str,
        out_port_name: str,
        req: _OpenReq,
        adapter: Optional[AdapterSpec],
        from_cap_pool: bool,
        extra_adapters: Sequence[str] = (),
    ) -> Tuple[List[_PlannedEdge], List[Tuple[str, str, Optional[str], Optional[str]]], Set[str]]:
        new_edges = list(state.edges)
        new_goal_out = list(state.goal_output_bindings)
        new_adapters = set(state.used_adapters) | {ad for ad in extra_adapters if ad}
        if adapter is not None:
            new_adapters.add(adapter.adapter_id)
        if req.consumer_key == "goal":
            if not from_cap_pool:
                new_goal_out.append(
                    (
                        req.consumer_port_name,
                        f"{producer_key}.{out_port_name}",
                        adapter.adapter_id if adapter else None,
                        adapter.adapter_hash if adapter else None,
                    )
                )
        else:
            new_edges.append(
                _PlannedEdge(
                    from_key=producer_key,
                    to_key=req.consumer_key,
                    from_port=out_port_name,
                    to_port=req.consumer_port_name,
                    adapter_id=adapter.adapter_id if adapter else None,
                    adapter_hash=adapter.adapter_hash if adapter else None,
                )
            )
        return new_edges, new_goal_out, new_adapters

    def _expand_state(self, state: _SearchState, req: _OpenReq, rest_reqs: Tuple[_OpenReq, ...], rem_caps: FrozenSet[str], from_cap_pool: bool) -> List[_SearchState]:
        successors: List[_SearchState] = []

        # Option A: Reuse an already placed node in the DAG (supports diamond fan-out & capability-only ordering)
        for existing_key in sorted(state.node_tools.keys()):
            existing_tid = state.node_tools[existing_key]
            existing_entry = self.tools_by_id[existing_tid]
            if req.consumer_key != "goal" and (
                _would_create_cycle(existing_key, req.consumer_key, state.edges)
                or existing_tid in req.ancestor_tool_ids
            ):
                self.cycle_rejected = True
                continue
            for out_port_name, adapter in self._match_tool_outputs(existing_entry, req):
                new_edges, new_goal_out, new_adapters = self._bind_edge_or_goal_output(
                    state=state,
                    producer_key=existing_key,
                    out_port_name=out_port_name,
                    req=req,
                    adapter=adapter,
                    from_cap_pool=from_cap_pool,
                )
                ok_limits, _ = self._check_state_dag_limits(state.node_tools, new_edges)
                if not ok_limits:
                    continue
                cand = _SearchState(
                    node_tools=dict(state.node_tools),
                    node_caps=dict(state.node_caps),
                    node_depths=dict(state.node_depths),
                    edges=tuple(new_edges),
                    goal_input_bindings=state.goal_input_bindings,
                    goal_output_bindings=tuple(new_goal_out),
                    open_reqs=rest_reqs,
                    remaining_caps=rem_caps - existing_entry.capabilities,
                    used_adapters=frozenset(new_adapters),
                    next_node_idx=state.next_node_idx,
                    cost_tuple=(),
                )
                cand.cost_tuple = self._score_state(cand)
                successors.append(cand)

        # Option B: Place a fresh verified tool node
        if self.max_depth is not None and req.depth > self.max_depth:
            self.depth_limit_hit = True
            return successors

        for tid in sorted(self.tools_by_id.keys()):
            entry = self.tools_by_id[tid]
            if tid in req.ancestor_tool_ids:
                self.cycle_rejected = True
                continue
            out_matches = self._match_tool_outputs(entry, req)
            if not out_matches:
                continue

            node_key = f"k{state.next_node_idx}"
            child_ancestors = req.ancestor_tool_ids | {tid}
            ok_in, added_reqs, added_goal_in = self._resolve_tool_inputs(node_key, entry, req.depth, child_ancestors)
            if not ok_in:
                continue

            extra_goal_adapters = [g_ad_id for _, _, g_ad_id, _ in added_goal_in if g_ad_id]
            for out_port_name, adapter in out_matches:
                new_node_tools = dict(state.node_tools)
                new_node_tools[node_key] = tid
                new_node_caps = dict(state.node_caps)
                matched_caps = tuple(sorted(entry.capabilities & (self.goal.required_capabilities and set(self.goal.required_capabilities) or entry.capabilities)))
                new_node_caps[node_key] = matched_caps or tuple(sorted(entry.capabilities))
                new_node_depths = dict(state.node_depths)
                new_node_depths[node_key] = req.depth

                new_edges, new_goal_out, new_adapters = self._bind_edge_or_goal_output(
                    state=state,
                    producer_key=node_key,
                    out_port_name=out_port_name,
                    req=req,
                    adapter=adapter,
                    from_cap_pool=from_cap_pool,
                    extra_adapters=extra_goal_adapters,
                )
                ok_limits, _ = self._check_state_dag_limits(new_node_tools, new_edges)
                if not ok_limits:
                    continue

                # Depth-first LIFO preference for open subgoals keeps chains tightly resolved
                cand = _SearchState(
                    node_tools=new_node_tools,
                    node_caps=new_node_caps,
                    node_depths=new_node_depths,
                    edges=tuple(new_edges),
                    goal_input_bindings=state.goal_input_bindings + tuple(added_goal_in),
                    goal_output_bindings=tuple(new_goal_out),
                    open_reqs=tuple(added_reqs) + rest_reqs,
                    remaining_caps=rem_caps - entry.capabilities,
                    used_adapters=frozenset(new_adapters),
                    next_node_idx=state.next_node_idx + 1,
                    cost_tuple=(),
                )
                cand.cost_tuple = self._score_state(cand)
                successors.append(cand)

        return successors

    def search(self) -> Optional[_SearchState]:
        """Run bounded A* / beam backward-chaining search returning best satisfied state."""
        t0 = time.monotonic()
        init_reqs: List[_OpenReq] = []
        for g_out in self.goal.output_ports:
            init_reqs.append(
                _OpenReq(
                    consumer_key="goal",
                    consumer_port_name=g_out.name,
                    required_port=g_out.port,
                    required_capability=g_out.capability,
                    depth=1,
                    ancestor_tool_ids=frozenset(),
                )
            )
        rem_caps = frozenset(self.goal.required_capabilities)
        if not init_reqs and not rem_caps:
            self.termination_reason = "EMPTY_GOAL_SPECIFICATION"
            return None

        init_state = _SearchState(
            node_tools={},
            node_caps={},
            node_depths={},
            edges=(),
            goal_input_bindings=(),
            goal_output_bindings=(),
            open_reqs=tuple(init_reqs),
            remaining_caps=rem_caps,
            used_adapters=frozenset(),
            next_node_idx=1,
            cost_tuple=(),
        )
        init_state.cost_tuple = self._score_state(init_state)

        tie_seq = 0
        pq: List[Tuple[Tuple[Any, ...], int, _SearchState]] = [(init_state.cost_tuple, tie_seq, init_state)]
        best_cost_seen: Dict[Tuple[Any, ...], Tuple[Any, ...]] = {self._state_dedup_key(init_state): init_state.cost_tuple}

        while pq:
            if self.nodes_expanded >= self.max_search_nodes:
                self.watchdog_triggered = True
                self.termination_reason = "SEARCH_NODE_WATCHDOG_EXCEEDED"
                return None
            if (time.monotonic() - t0) > self.max_search_seconds:
                self.watchdog_triggered = True
                self.termination_reason = "SEARCH_TIME_WATCHDOG_EXCEEDED"
                return None

            _, _, state = heapq.heappop(pq)
            self.nodes_expanded += 1

            req, rest_reqs, next_rem_caps, from_cap_pool = self._next_requirement(state)
            if req is None:
                self.termination_reason = "SATISFIED"
                return state

            for nxt in self._expand_state(state, req, rest_reqs, next_rem_caps, from_cap_pool):
                dkey = self._state_dedup_key(nxt)
                prev_best = best_cost_seen.get(dkey)
                if prev_best is not None and prev_best <= nxt.cost_tuple:
                    self.states_deduped += 1
                    continue
                best_cost_seen[dkey] = nxt.cost_tuple
                tie_seq += 1
                heapq.heappush(pq, (nxt.cost_tuple, tie_seq, nxt))

            if len(pq) > self.max_beam_width * 4:
                pq = heapq.nsmallest(self.max_beam_width, pq)
                heapq.heapify(pq)

        self.termination_reason = "NO_SATISFYING_COMPOSITION"
        return None


def _topological_sort_keys(
    node_keys: Sequence[str],
    edges: Sequence[Tuple[str, str]],
    tie_key_fn: Callable[[str], Tuple[Any, ...]],
) -> List[str]:
    """Deterministically topologically sort DAG node keys using Kahn's algorithm + min-heap."""
    adj: Dict[str, List[str]] = {k: [] for k in node_keys}
    indeg: Dict[str, int] = {k: 0 for k in node_keys}
    for src, dst in edges:
        if src in adj and dst in adj:
            adj[src].append(dst)
            indeg[dst] += 1

    heap: List[Tuple[Tuple[Any, ...], str]] = [
        (tie_key_fn(k), k) for k in node_keys if indeg[k] == 0
    ]
    heapq.heapify(heap)
    ordered: List[str] = []
    while heap:
        _, cur = heapq.heappop(heap)
        ordered.append(cur)
        for nxt in adj[cur]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                heapq.heappush(heap, (tie_key_fn(nxt), nxt))

    if len(ordered) != len(node_keys):
        raise ValueError("INVALID_COMPOSITION_DAG: cycle detected during topological sort.")
    return ordered


def _decimal_mul(value: Any, factor: Any) -> Any:
    """Apply exact Decimal scaling when multiplying numeric port payloads."""
    try:
        res = Decimal(str(value)) * Decimal(str(factor))
    except (InvalidOperation, ValueError, TypeError):
        return float(value) * float(factor)
    if res == res.to_integral_value() and not isinstance(value, float):
        return int(res)
    return float(res)


def _apply_adapter_spec(adapter: AdapterSpec, payload: Any) -> Any:
    """Deterministically execute a verified `AdapterSpec` mapping and unit conversion (`llm_calls=0`)."""
    mapping = dict(adapter.mapping or {})
    unit_conv = dict(adapter.unit_conversion or {}) if adapter.unit_conversion is not None else None
    scale_factor = None
    if unit_conv is not None:
        scale_factor = unit_conv.get("factor", unit_conv.get("scale"))

    field_map_raw = mapping.get("fields") or mapping.get("field_map")
    if isinstance(field_map_raw, Mapping):
        field_map: Dict[str, str] = {}
        for k, v in field_map_raw.items():
            if isinstance(v, Mapping):
                tgt = str(v.get("target") or v.get("to") or k)
            elif isinstance(v, (list, tuple)):
                tgt = str(v[0])
            else:
                tgt = str(v)
            field_map[str(k)] = tgt
    else:
        field_map = {
            str(k): str(v)
            for k, v in mapping.items()
            if str(k).lower() not in _MAPPING_META_KEYS and isinstance(v, str)
        }

    if isinstance(payload, Mapping):
        out: Dict[str, Any] = {}
        mapped_sources = set(field_map.keys())
        strict_proj = bool(mapping.get("strict_projection", False))
        is_declass = adapter.source_port.sensitivity != adapter.target_port.sensitivity
        if not strict_proj and not is_declass:
            for k, v in payload.items():
                if str(k) not in mapped_sources:
                    out[str(k)] = v
        for src_key, dst_key in field_map.items():
            if src_key not in payload:
                continue
            val = payload[src_key]
            if scale_factor is not None and isinstance(val, (int, float)) and not isinstance(val, bool):
                val = _decimal_mul(val, scale_factor)
            out[dst_key] = val
        if not field_map and scale_factor is not None:
            for k, v in payload.items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    out[str(k)] = _decimal_mul(v, scale_factor)
                else:
                    out[str(k)] = v
        if is_declass or any(tok in canonical_json_dumps(mapping).lower() for tok in _DECLASSIFICATION_HINTS):
            out = redact_secrets_in_value(out)
        return out

    if scale_factor is not None and isinstance(payload, (int, float)) and not isinstance(payload, bool):
        return _decimal_mul(payload, scale_factor)
    return redact_secrets_in_value(payload) if adapter.source_port.sensitivity != adapter.target_port.sensitivity else payload


def _invoke_dag_oracle(
    oracle: Callable[..., Any],
    dag_summary: Dict[str, Any],
    plan: CompositionPlan,
    security_context: SecurityContext,
) -> Tuple[bool, str]:
    """Execute optional DAG-level verification oracle cleanly with fail-closed error handling."""
    import inspect

    try:
        sig = inspect.signature(oracle)
        pos = [
            p
            for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        has_var = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
        if has_var or len(pos) >= 3:
            res = oracle(dag_summary, plan, security_context)
        elif len(pos) == 2:
            res = oracle(dag_summary, plan)
        elif len(pos) == 1:
            res = oracle(dag_summary)
        else:
            res = oracle()
    except Exception as exc:
        return False, f"ORACLE_EXCEPTION: {redact_runtime_text(exc)}"

    if isinstance(res, bool):
        return res, "ORACLE_PASS" if res else "ORACLE_FAILED"
    if isinstance(res, tuple) and res:
        passed = bool(res[0])
        reason = str(res[1]) if len(res) > 1 else ("ORACLE_PASS" if passed else "ORACLE_FAILED")
        return passed, reason
    if isinstance(res, Mapping):
        if "passed" in res:
            passed = bool(res["passed"])
        elif "verified" in res:
            passed = bool(res["verified"])
        elif "ok" in res:
            passed = bool(res["ok"])
        else:
            passed = str(res.get("status", "")).upper() == "PASS"
        reason = str(res.get("reason") or ("ORACLE_PASS" if passed else "ORACLE_FAILED"))
        return passed, reason
    return False, "ORACLE_INVALID_RETURN"


@dataclass(frozen=True)
class _ConfinedCheckpointRef:
    """Descriptor-validated checkpoint location bound strictly to an authorized root."""

    path: Path
    authorized_root: Path
    rel_path: Path


def _make_adapter_step_id(prefix: str, *parts: Any) -> str:
    """Construct a deterministic `VALID_RUN_ID_RE`-compliant adapter WAL step identifier."""
    raw = ":".join([prefix, *(str(p) for p in parts)])
    cleaned = re.sub(r"[^A-Za-z0-9._:-]+", "_", raw)
    if len(cleaned) > 120:
        tail = sha256_digest(raw).split(":", 1)[1][:12]
        cleaned = f"{cleaned[:107]}:{tail}"
    return cleaned


def _confine_path_under_authorized_root(candidate: Path, authorized_root: Path) -> Optional[Path]:
    """Confine `candidate` under `authorized_root` without traversing symlinks; return None if outside."""
    assert_not_symlink(authorized_root)
    root_resolved = authorized_root.resolve()
    assert_not_symlink(candidate)
    try:
        rel = candidate.resolve().relative_to(root_resolved)
    except ValueError:
        return None
    rel_str = str(rel) if str(rel) != "." else "."
    if rel_str == ".":
        return root_resolved
    cur = root_resolved
    for part in Path(rel_str).parts:
        if part in ("", "."):
            continue
        if part == "..":
            raise PermissionError("SECURITY_CHECKPOINT_PATH_TRAVERSAL")
        cur = cur / part
        assert_not_symlink(cur)
    safe = resolve_safe_child_path(root_resolved, rel_str)
    if safe is None:
        return None
    assert_not_symlink(safe)
    return safe


def _assert_owned_dir_fd(dir_fd: int) -> None:
    st = os.fstat(dir_fd)
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError("CHECKPOINT_PARENT_NOT_DIRECTORY")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PermissionError("CHECKPOINT_UNTRUSTED_DIR_OWNER")


def _open_confined_dir_fd(
    authorized_root: Path,
    rel_parts: Sequence[str],
    *,
    create_missing: bool,
) -> int:
    """Walk `rel_parts` under `authorized_root` using `dir_fd + O_NOFOLLOW` to prevent symlink/race swaps."""
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        cur_fd = os.open(str(authorized_root), dir_flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PermissionError(f"CHECKPOINT_DIR_OPEN_REFUSED: {exc}") from exc
    try:
        _assert_owned_dir_fd(cur_fd)
        for seg in rel_parts:
            if not seg or seg == ".":
                continue
            if seg == ".." or "/" in seg or "\\" in seg or "\x00" in seg:
                raise PermissionError("SECURITY_CHECKPOINT_PATH_TRAVERSAL")
            try:
                nxt_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
            except FileNotFoundError:
                if not create_missing:
                    raise
                try:
                    os.mkdir(seg, 0o700, dir_fd=cur_fd)
                except FileExistsError as _exists_err:
                    _ = _exists_err
                try:
                    nxt_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
                except OSError as exc:
                    raise PermissionError(f"CHECKPOINT_DIR_OPEN_REFUSED: {exc}") from exc
            except OSError as exc:
                raise PermissionError(f"CHECKPOINT_DIR_OPEN_REFUSED: {exc}") from exc
            os.close(cur_fd)
            cur_fd = nxt_fd
            _assert_owned_dir_fd(cur_fd)
        return cur_fd
    except Exception:
        os.close(cur_fd)
        raise


def _open_confined_checkpoint_fd(ref: _ConfinedCheckpointRef, *, write: bool) -> Tuple[int, int]:
    """Open checkpoint descriptor relative to confined directory FD, rejecting symlinks and hardlinks."""
    parts = [p for p in ref.rel_path.parts if p not in ("", ".")]
    if not parts or any(p == ".." or "\x00" in p for p in parts):
        raise PermissionError("SECURITY_CHECKPOINT_PATH_TRAVERSAL")
    parent_parts = parts[:-1]
    leaf = parts[-1]
    parent_fd = _open_confined_dir_fd(ref.authorized_root, parent_parts, create_missing=write)
    file_fd: Optional[int] = None
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        if not write:
            try:
                file_fd = os.open(leaf, os.O_RDONLY | nofollow, dir_fd=parent_fd)
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise PermissionError(f"CHECKPOINT_OPEN_REFUSED: {exc}") from exc
        else:
            try:
                file_fd = os.open(
                    leaf,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | nofollow,
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                try:
                    file_fd = os.open(
                        leaf,
                        os.O_WRONLY | os.O_APPEND | nofollow,
                        0o600,
                        dir_fd=parent_fd,
                    )
                except OSError as exc:
                    raise PermissionError(f"CHECKPOINT_OPEN_REFUSED: {exc}") from exc
            except OSError as exc:
                raise PermissionError(f"CHECKPOINT_OPEN_REFUSED: {exc}") from exc

        st = os.fstat(file_fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("CHECKPOINT_NOT_REGULAR_FILE")
        if st.st_nlink > 1:
            raise PermissionError("CHECKPOINT_HARDLINK_FORBIDDEN")
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise PermissionError("CHECKPOINT_UNTRUSTED_OWNER")

        try:
            lstat_entry = os.lstat(leaf, dir_fd=parent_fd)
        except OSError as exc:
            raise PermissionError(f"CHECKPOINT_STAT_REFUSED: {exc}") from exc
        if stat.S_ISLNK(lstat_entry.st_mode):
            raise PermissionError("SECURITY_SYMLINK_REFUSED: checkpoint leaf is symlink")
        if (lstat_entry.st_dev, lstat_entry.st_ino) != (st.st_dev, st.st_ino) or lstat_entry.st_nlink > 1:
            raise PermissionError("CHECKPOINT_HARDLINK_OR_RACE_DETECTED")

        if write:
            os.fchmod(file_fd, 0o600)
        return parent_fd, file_fd
    except Exception:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError as _close_err:
                _ = _close_err
        os.close(parent_fd)
        raise


def _resolve_checkpoint_file(
    checkpoint_store_path: Optional[Union[str, Path]],
    run_id: str,
    security_context: SecurityContext,
    *,
    allowed_checkpoint_roots: Sequence[Path] = (),
) -> Optional[_ConfinedCheckpointRef]:
    """Validate and bind checkpoint path strictly under workspace or owner-configured roots."""
    if checkpoint_store_path is None:
        return None
    safe_run = validate_safe_text(run_id, field_name="run_id")
    if "/" in safe_run or "\\" in safe_run or ".." in safe_run or not VALID_RUN_ID_RE.fullmatch(safe_run):
        raise PermissionError("SECURITY_INVALID_CHECKPOINT_RUN_ID")

    raw_str = str(checkpoint_store_path).strip()
    if not raw_str or "\x00" in raw_str or TROJAN_UNICODE_RE.search(raw_str):
        raise PermissionError("SECURITY_INVALID_CHECKPOINT_PATH")
    candidate = Path(raw_str)
    if ".." in candidate.parts:
        raise PermissionError("SECURITY_CHECKPOINT_PATH_TRAVERSAL")
    assert_not_symlink(candidate)

    ws_root = Path(security_context.workspace_root)
    assert_not_symlink(ws_root)
    ws_resolved = ws_root.resolve()

    if not candidate.is_absolute():
        confined = security_context.validate_path(candidate)
        matched_root = ws_resolved
    else:
        authorized_roots: List[Path] = [ws_resolved]
        for extra_root in allowed_checkpoint_roots:
            extra_path = Path(extra_root)
            assert_not_symlink(extra_path)
            authorized_roots.append(extra_path.resolve())
        confined = None
        matched_root = ws_resolved
        for root_cand in authorized_roots:
            res = _confine_path_under_authorized_root(candidate, root_cand)
            if res is not None:
                confined = res
                matched_root = root_cand
                break
        if confined is None:
            raise PermissionError(
                f"SECURITY_CHECKPOINT_OUTSIDE_AUTHORIZED_ROOT: '{checkpoint_store_path}' is outside workspace '{ws_resolved}'."
            )

    if (confined.exists() and confined.is_dir()) or raw_str.endswith(("/", os.sep)):
        target = confined / f"{safe_run}.events.jsonl"
        assert_not_symlink(confined)
        assert_not_symlink(target)
        rechecked = _confine_path_under_authorized_root(target, matched_root)
        if rechecked is None:
            raise PermissionError("SECURITY_CHECKPOINT_OUTSIDE_AUTHORIZED_ROOT")
        rel_path = rechecked.relative_to(matched_root)
        return _ConfinedCheckpointRef(path=rechecked, authorized_root=matched_root, rel_path=rel_path)

    rel_path = confined.relative_to(matched_root)
    if rel_path == Path("."):
        raise PermissionError("SECURITY_INVALID_CHECKPOINT_PATH")
    return _ConfinedCheckpointRef(path=confined, authorized_root=matched_root, rel_path=rel_path)


def _load_checkpoint_events(ckpt_ref: _ConfinedCheckpointRef, *, missing_ok: bool = True) -> List[RunEvent]:
    """Load existing `RunEvent/1` records using `dir_fd + O_NOFOLLOW` and hardlink rejection."""
    try:
        parent_fd, file_fd = _open_confined_checkpoint_fd(ckpt_ref, write=False)
    except FileNotFoundError:
        if missing_ok:
            return []
        raise
    try:
        with os.fdopen(file_fd, "r", encoding="utf-8") as handle:
            raw_text = handle.read()
    finally:
        os.close(parent_fd)

    events: List[RunEvent] = []
    for idx, line in enumerate(raw_text.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        parsed = json.loads(stripped)
        if not isinstance(parsed, Mapping):
            raise ValueError(f"CHECKPOINT_INVALID_EVENT_LINE:idx={idx}")
        events.append(RunEvent.from_dict(parsed))
    return events


def _append_checkpoint_event(ckpt_ref: Optional[_ConfinedCheckpointRef], event: RunEvent) -> None:
    """Append a single verified `RunEvent/1` JSON line via `dir_fd + O_NOFOLLOW` + `fchmod(0o600)` + fsync."""
    if ckpt_ref is None:
        return
    line = event.to_canonical_json() + "\n"
    parent_fd, file_fd = _open_confined_checkpoint_fd(ckpt_ref, write=True)
    try:
        with os.fdopen(file_fd, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        # Persist the directory entry metadata via the already-verified parent_fd.
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _unresolved_checkpoint_nodes(events: Sequence[RunEvent]) -> List[str]:
    """Find nodes and adapters with durable IN_FLIGHT evidence but no trusted resolution."""
    inflight: Set[str] = set()
    for event in events:
        if event.state in {"NODE_IN_FLIGHT", "ADAPTER_IN_FLIGHT"}:
            inflight.add(event.step_id)
        elif event.state in {
            "NODE_COMPLETED",
            "ADAPTER_APPLIED",
            "NODE_RECONCILED_COMMITTED",
            "NODE_RECONCILED_NOT_EXECUTED",
            "ADAPTER_RECONCILED_COMMITTED",
            "ADAPTER_RECONCILED_NOT_EXECUTED",
        }:
            inflight.discard(event.step_id)
    return sorted(inflight)


class ToolComposer:
    """Zero-LLM (`llm_calls=0`) backward-chaining LEGO tool DAG composer & checkpointed executor."""

    def __init__(
        self,
        *,
        max_beam_width: int = _DEFAULT_MAX_BEAM_WIDTH,
        max_search_nodes: int = _DEFAULT_MAX_SEARCH_NODES,
        max_search_seconds: float = _DEFAULT_MAX_SEARCH_SECONDS,
        allowed_checkpoint_roots: Sequence[Union[str, Path]] = (),
    ) -> None:
        self.max_beam_width = max(4, int(max_beam_width))
        self.max_search_nodes = max(1, int(max_search_nodes))
        self.max_search_seconds = max(0.05, float(max_search_seconds))
        validated_roots: List[Path] = []
        for raw_root in allowed_checkpoint_roots:
            root_str = validate_safe_text(str(raw_root), field_name="allowed_checkpoint_root")
            cand = Path(root_str)
            if ".." in cand.parts:
                raise ValueError(f"INVALID_CHECKPOINT_ROOT: traversal segment in '{raw_root}'.")
            assert_not_symlink(cand)
            validated_roots.append(cand.resolve())
        self._allowed_checkpoint_roots: Tuple[Path, ...] = tuple(validated_roots)

    def plan(
        self,
        goal_contract: Union[CapabilityGap, Mapping[str, Any]],
        registry: ToolRegistry,
        security_context: SecurityContext,
        *,
        adapters: Sequence[Union[AdapterSpec, Mapping[str, Any]]] = (),
        config: Optional[KintsugiConfig] = None,
        composition_memory: Optional[Any] = None,
    ) -> CompositionPlanResult:
        """
        Plan a deterministic verified `CompositionPlan/1` DAG via backward chaining.

        Enforces `PortContract/1` compatibility, `EffectContract/1` permission/scope unions,
        `TrustStatus.VERIFIED` attestation checks, and profile-specific depth/watchdog limits.
        """
        if not isinstance(registry, ToolRegistry):
            raise ValueError("INVALID_REGISTRY: expected ToolRegistry instance.")
        ctx_err = _verify_security_context_integrity(security_context)
        if ctx_err is not None:
            goal_id_fallback = str(getattr(goal_contract, "goal_id", None) or (goal_contract.get("goal_id") if isinstance(goal_contract, Mapping) else "unknown") or "unknown")
            return CompositionPlanResult(
                goal_id=goal_id_fallback,
                status=ExecutionStatus.PERMISSION_DENIED,
                executable=False,
                reasons=[ctx_err],
                diagnostics={"llm_calls": 0},
                llm_calls=0,
            )

        effective_config = config if config is not None else KintsugiConfig.for_profile(security_context.profile.value)
        goal = _extract_goal_spec(goal_contract)
        memory_bonuses = _memory_bonus_map(
            composition_memory,
            goal,
            security_context,
            raw_goal_contract=goal_contract,
            registry=registry,
        )

        eligible_tools: Dict[str, _VerifiedToolEntry] = {}
        rejected_tools: List[Dict[str, Any]] = []
        permission_denials: List[str] = []
        unverified_only_reasons: List[str] = []
        budget_denials: List[str] = []

        for spec in registry.list_tools():
            ok, eff, reasons, st_hint = _validate_tool_candidate(spec, security_context, effective_config, goal.budget)
            if not ok or eff is None:
                rejected_tools.append(
                    {
                        "tool_id": spec.tool_id,
                        "capabilities": list(spec.capabilities),
                        "trust_status": spec.trust_status.value,
                        "status": st_hint.value,
                        "reasons": list(reasons),
                    }
                )
                if st_hint == ExecutionStatus.PERMISSION_DENIED:
                    permission_denials.extend(reasons)
                elif st_hint == ExecutionStatus.INSUFFICIENT_EVIDENCE:
                    budget_denials.extend(reasons)
                else:
                    unverified_only_reasons.extend(reasons)
                continue

            eligible_tools[spec.tool_id] = _VerifiedToolEntry(
                spec=spec,
                input_ports=_extract_named_ports(spec, "input"),
                output_ports=_extract_named_ports(spec, "output"),
                effect_contract=eff,
                capabilities=frozenset(spec.capabilities),
                memory_bonus=memory_bonuses.get(spec.tool_id, 0),
            )

        eligible_adapters: List[_VerifiedAdapterEntry] = []
        rejected_adapters: List[Dict[str, Any]] = []
        for raw_ad in adapters or ():
            ad_obj, ad_reasons, ad_status = _validate_adapter_candidate(raw_ad, authority=registry.authority)
            if ad_obj is None:
                rejected_adapters.append({"reasons": ad_reasons, "status": ad_status.value})
                if ad_status == ExecutionStatus.PERMISSION_DENIED:
                    permission_denials.extend(ad_reasons)
                else:
                    unverified_only_reasons.extend(ad_reasons)
            else:
                eligible_adapters.append(_VerifiedAdapterEntry(spec=ad_obj))

        planner = _BackwardChainPlanner(
            goal=goal,
            tools_by_id=eligible_tools,
            adapters=eligible_adapters,
            security_context=security_context,
            config=effective_config,
            max_beam_width=self.max_beam_width,
            max_search_nodes=self.max_search_nodes,
            max_search_seconds=self.max_search_seconds,
        )
        solved = planner.search()

        diagnostics: Dict[str, Any] = {
            "profile": effective_config.profile.value,
            "max_depth_limit": planner.max_depth,
            "nodes_expanded": planner.nodes_expanded,
            "states_deduped": planner.states_deduped,
            "termination_reason": planner.termination_reason,
            "depth_limit_hit": planner.depth_limit_hit,
            "cycle_rejected": planner.cycle_rejected,
            "watchdog_triggered": planner.watchdog_triggered,
            "eligible_tool_count": len(eligible_tools),
            "eligible_adapter_count": len(eligible_adapters),
            "rejected_tools": rejected_tools,
            "rejected_adapters": rejected_adapters,
            "memory_bonus_tools": sorted(memory_bonuses.keys()),
        }

        if solved is None:
            missing_caps = self._diagnose_missing_capabilities(goal, eligible_tools)
            fail_status, fail_reasons = self._classify_failure(
                goal=goal,
                planner=planner,
                missing_caps=missing_caps,
                eligible_tools=eligible_tools,
                rejected_tools=rejected_tools,
                permission_denials=permission_denials,
                budget_denials=budget_denials,
            )
            return CompositionPlanResult(
                goal_id=goal.goal_id,
                status=fail_status,
                plan=None,
                executable=False,
                reasons=fail_reasons,
                missing_capabilities=missing_caps,
                missing_adapters=[g.to_dict() for g in planner.missing_gaps],
                diagnostics=diagnostics,
                llm_calls=0,
            )

        plan = self._materialize_plan(
            goal=goal,
            solved=solved,
            eligible_tools=eligible_tools,
            eligible_adapters=eligible_adapters,
            config=effective_config,
            security_context=security_context,
        )
        return CompositionPlanResult(
            goal_id=goal.goal_id,
            status=ExecutionStatus.PASS,
            plan=plan,
            executable=True,
            reasons=[],
            missing_capabilities=[],
            missing_adapters=[],
            diagnostics=diagnostics,
            llm_calls=0,
        )

    def _diagnose_missing_capabilities(
        self,
        goal: _GoalSpec,
        eligible_tools: Mapping[str, _VerifiedToolEntry],
    ) -> List[str]:
        covered = {cap for entry in eligible_tools.values() for cap in entry.capabilities}
        return [cap for cap in goal.required_capabilities if cap not in covered]

    def _classify_failure(
        self,
        *,
        goal: _GoalSpec,
        planner: _BackwardChainPlanner,
        missing_caps: Sequence[str],
        eligible_tools: Mapping[str, _VerifiedToolEntry],
        rejected_tools: Sequence[Mapping[str, Any]],
        permission_denials: Sequence[str],
        budget_denials: Sequence[str],
    ) -> Tuple[ExecutionStatus, List[str]]:
        reasons: List[str] = []
        if planner.termination_reason == "EMPTY_GOAL_SPECIFICATION":
            return ExecutionStatus.INSUFFICIENT_EVIDENCE, ["EMPTY_GOAL_SPECIFICATION"]
        if planner.watchdog_triggered:
            reasons.append(planner.termination_reason)
            return ExecutionStatus.INSUFFICIENT_EVIDENCE, reasons
        if planner.depth_limit_hit:
            reasons.append(f"MAX_COMPOSITION_DEPTH_EXCEEDED:limit={planner.max_depth}")
            return ExecutionStatus.INSUFFICIENT_EVIDENCE, reasons
        if planner.sensitivity_or_trust_violations:
            reasons.extend(planner.sensitivity_or_trust_violations)
            return ExecutionStatus.PERMISSION_DENIED, list(dict.fromkeys(reasons))

        if missing_caps:
            missing_set = set(missing_caps)
            relevant = [
                rej for rej in rejected_tools if set(rej.get("capabilities") or ()) & missing_set
            ]
            rel_perm_reasons = [
                r
                for rej in relevant
                if rej.get("status") == ExecutionStatus.PERMISSION_DENIED.value
                for r in (rej.get("reasons") or ())
            ]
            has_perm_blocker = bool(rel_perm_reasons)
            has_unverified_only = any(
                rej.get("status") == ExecutionStatus.NO_VERIFIED_TOOL.value for rej in relevant
            )
            if has_perm_blocker and not has_unverified_only:
                reasons.extend(sorted(set(rel_perm_reasons)))
                return ExecutionStatus.PERMISSION_DENIED, reasons
            reasons.append(f"MISSING_VERIFIED_CAPABILITIES:{','.join(missing_caps)}")
            if has_perm_blocker:
                reasons.extend(sorted(set(rel_perm_reasons)))
            return ExecutionStatus.NO_VERIFIED_TOOL, list(dict.fromkeys(reasons))

        if planner.budget_violations or budget_denials:
            reasons.extend(planner.budget_violations or budget_denials)
            return ExecutionStatus.INSUFFICIENT_EVIDENCE, list(dict.fromkeys(reasons))

        if planner.cycle_rejected and not planner.missing_gaps:
            reasons.append("CIRCULAR_DEPENDENCY_DETECTED")
            return ExecutionStatus.NO_VERIFIED_TOOL, reasons

        if planner.missing_gaps:
            for gap in planner.missing_gaps:
                reasons.extend(gap.reasons)
            return ExecutionStatus.NO_VERIFIED_TOOL, list(dict.fromkeys(reasons))

        if permission_denials and not eligible_tools:
            return ExecutionStatus.PERMISSION_DENIED, sorted(set(permission_denials))

        return ExecutionStatus.NO_VERIFIED_TOOL, [planner.termination_reason]

    def _materialize_plan(
        self,
        *,
        goal: _GoalSpec,
        solved: _SearchState,
        eligible_tools: Mapping[str, _VerifiedToolEntry],
        eligible_adapters: Sequence[_VerifiedAdapterEntry],
        config: KintsugiConfig,
        security_context: SecurityContext,
    ) -> CompositionPlan:
        """Convert a satisfied search state into a deterministic canonical `CompositionPlan/1`."""
        raw_edges = [(e.from_key, e.to_key) for e in solved.edges]
        ordered_keys = _topological_sort_keys(
            list(solved.node_tools.keys()),
            raw_edges,
            tie_key_fn=lambda k: (-solved.node_depths.get(k, 0), solved.node_tools[k], k),
        )
        key_to_nid = {k: f"n{idx + 1}" for idx, k in enumerate(ordered_keys)}
        adapter_lookup = {a.spec.adapter_id: a.spec for a in eligible_adapters}

        inputs_by_node: Dict[str, Dict[str, Any]] = {nid: {} for nid in key_to_nid.values()}
        edges_out: List[Dict[str, Any]] = []
        used_adapter_hashes: Dict[str, str] = {}
        used_adapter_specs: Dict[str, Dict[str, Any]] = {}

        for edge in sorted(solved.edges, key=lambda e: (key_to_nid[e.from_key], key_to_nid[e.to_key], e.from_port, e.to_port)):
            src_nid = key_to_nid[edge.from_key]
            dst_nid = key_to_nid[edge.to_key]
            edge_dict: Dict[str, Any] = {
                "from_node": src_nid,
                "to_node": dst_nid,
                "output_port": edge.from_port,
                "input_port": edge.to_port,
            }
            binding: Dict[str, Any] = {"from_node": src_nid, "output_port": edge.from_port}
            if edge.adapter_id and edge.adapter_hash:
                edge_dict["adapter_id"] = edge.adapter_id
                edge_dict["adapter_hash"] = edge.adapter_hash
                binding["adapter_id"] = edge.adapter_id
                binding["adapter_hash"] = edge.adapter_hash
                used_adapter_hashes[edge.adapter_id] = edge.adapter_hash
                if edge.adapter_id in adapter_lookup:
                    used_adapter_specs[edge.adapter_id] = adapter_lookup[edge.adapter_id].to_dict()
            edges_out.append(edge_dict)
            inputs_by_node[dst_nid][edge.to_port] = binding

        input_bindings = dict(goal.input_bindings)
        goal_input_adapters: List[Dict[str, Any]] = []
        for target_ref, g_in_name, ad_id, ad_hash in sorted(solved.goal_input_bindings):
            raw_key, port_name = target_ref.split(".", 1)
            dst_nid = key_to_nid[raw_key]
            bind_entry: Dict[str, Any] = {"source": g_in_name}
            if ad_id and ad_hash:
                bind_entry["adapter_id"] = ad_id
                bind_entry["adapter_hash"] = ad_hash
                used_adapter_hashes[ad_id] = ad_hash
                if ad_id in adapter_lookup:
                    used_adapter_specs[ad_id] = adapter_lookup[ad_id].to_dict()
                goal_input_adapters.append(
                    {"node_id": dst_nid, "input_port": port_name, "adapter_id": ad_id, "adapter_hash": ad_hash}
                )
            inputs_by_node[dst_nid][port_name] = bind_entry
            input_bindings[f"{dst_nid}.{port_name}"] = bind_entry
        if goal_input_adapters:
            input_bindings["goal_input_adapters"] = goal_input_adapters

        goal_output_adapters: List[Dict[str, Any]] = []
        for g_out_name, src_ref, ad_id, ad_hash in sorted(solved.goal_output_bindings):
            raw_key, port_name = src_ref.split(".", 1)
            src_nid = key_to_nid[raw_key]
            if ad_id and ad_hash:
                used_adapter_hashes[ad_id] = ad_hash
                if ad_id in adapter_lookup:
                    used_adapter_specs[ad_id] = adapter_lookup[ad_id].to_dict()
                goal_output_adapters.append(
                    {"goal_port": g_out_name, "node_id": src_nid, "output_port": port_name, "adapter_id": ad_id, "adapter_hash": ad_hash}
                )

        nodes_out: List[Dict[str, Any]] = []
        tool_artifact_hashes: Dict[str, str] = {}
        eff_list: List[EffectContract] = []
        for k in ordered_keys:
            nid = key_to_nid[k]
            entry = eligible_tools[solved.node_tools[k]]
            spec = entry.spec
            tool_artifact_hashes[spec.tool_id] = spec.binary_hash
            eff_list.append(entry.effect_contract)
            node_kind = spec.source.lower() if spec.source.lower() in {"synthesized", "builtin"} else "tool"
            node_dict: Dict[str, Any] = {
                "node_id": nid,
                "tool_id": spec.tool_id,
                "tool_version": spec.version,
                "kind": node_kind,
                "binary_hash": spec.binary_hash,
                "capabilities": sorted(spec.capabilities),
                "inputs_from": inputs_by_node[nid],
                "requires_sandbox": bool(config.security.require_sandbox_for_untrusted_code),
            }
            timeout_val = spec.runtime_requirements.get("timeout_ms")
            if isinstance(timeout_val, int) and timeout_val >= 1:
                node_dict["timeout_ms"] = timeout_val
            nodes_out.append(node_dict)

        dag_effects = compute_dag_effects(eff_list)
        permission_union = list(dag_effects["permission_union"])
        effects_union = dict(dag_effects["effects_union"])
        if not set(permission_union).issubset(set(security_context.allowed_permissions)):
            raise PermissionError("OVER_PRIVILEGED_PERMISSION_UNION")

        dag_depth = max(1, _compute_state_dag_depth(ordered_keys, raw_edges))
        est_res = dict(effects_union.get("resource_requirements", {}))
        est_res["nodes_count"] = len(nodes_out)
        est_res["edges_count"] = len(edges_out)
        est_res["dag_depth"] = dag_depth
        est_res["llm_calls"] = 0

        ver_plan = dict(goal.verification_plan)
        ver_plan.setdefault("mode", "dag_oracle")
        ver_plan["goal_id"] = goal.goal_id
        if used_adapter_specs:
            ver_plan["adapters"] = used_adapter_specs
        if goal_output_adapters:
            ver_plan["goal_output_adapters"] = goal_output_adapters

        plan_basis_digest = sha256_digest(
            {"goal": goal.goal_contract_hash, "nodes": nodes_out, "edges": edges_out}
        ).split(":", 1)[1][:10]
        plan_id = _sanitize_plan_id(f"plan-{goal.goal_id}-{plan_basis_digest}")

        return CompositionPlan(
            plan_id=plan_id,
            goal_contract_hash=goal.goal_contract_hash,
            nodes=nodes_out,
            edges=edges_out,
            input_bindings=input_bindings,
            tool_artifact_hashes=tool_artifact_hashes,
            adapter_hashes=used_adapter_hashes,
            permission_union=permission_union,
            effects_union=effects_union,
            expected_outputs=goal.expected_outputs_raw,
            oracle_ref=goal.oracle_ref,
            verification_plan=ver_plan,
            estimated_resources=est_res,
            gap_id=goal.goal_id,
            profile=config.profile.value,
            max_depth=dag_depth,
            security_checks={
                "all_tools_verified": True,
                "no_untrusted_native_on_host": True,
                "within_profile_limits": True,
            },
        )

    def execute_plan(
        self,
        plan: Union[CompositionPlan, Mapping[str, Any]],
        registry: ToolRegistry,
        security_context: SecurityContext,
        *,
        runner: Optional[SecureRunner] = None,
        adapters_callables: Optional[Mapping[str, Callable[..., Any]]] = None,
        oracle: Optional[Callable[..., Any]] = None,
        checkpoint_store_path: Optional[Union[str, Path]] = None,
        resume_run_id: Optional[str] = None,
        adapters: Sequence[Union[AdapterSpec, Mapping[str, Any]]] = (),
        initial_inputs: Optional[Mapping[str, Any]] = None,
        node_oracles: Optional[Mapping[str, Callable[..., Any]]] = None,
    ) -> Tuple[CompositionReceipt, List[RunEvent]]:
        """
        Execute a `CompositionPlan/1` DAG in deterministic topological order via `SecureRunner`.

        Re-verifies `plan_hash`, `policy_hash`, and every tool/adapter artifact hash before running,
        aborts cleanly on mid-DAG node failures, and supports crash/resume via `RunEvent/1` chains.
        """
        if not isinstance(registry, ToolRegistry):
            raise ValueError("INVALID_REGISTRY: expected ToolRegistry instance.")

        plan_obj = CompositionPlan.from_dict(plan.to_dict() if isinstance(plan, CompositionPlan) else plan)
        run_id = validate_safe_text(resume_run_id, field_name="resume_run_id") if resume_run_id else f"run_{secrets.token_hex(8)}"
        if not VALID_RUN_ID_RE.fullmatch(run_id):
            raise ValueError(f"INVALID_RUN_ID: {run_id!r}")

        active_runner = (
            runner
            if runner is not None
            else SecureRunner(attestation_authority=registry.authority)
        )
        env_hash = sha256_digest({"workspace": sha256_digest(str(security_context.workspace_root)), "llm_calls": 0})
        input_digest = sha256_digest({"input_bindings": plan_obj.input_bindings, "initial_inputs": redact_runtime_value(dict(initial_inputs or {}))})

        ctx_err = _verify_security_context_integrity(security_context)
        if ctx_err is not None:
            return self._abort_pre_exec(
                run_id=run_id,
                plan=plan_obj,
                policy_hash=str(getattr(security_context, "policy_hash", "") or GENESIS_EVENT_HASH),
                env_hash=env_hash,
                input_digest=input_digest,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=ctx_err,
                security_context=security_context,
            )

        policy_hash = security_context.policy_hash
        ordered_nodes, adj_in, pre_err, pre_status, verified_specs, verified_adapters = self._reverify_plan_for_execution(
            plan_obj,
            registry,
            security_context,
            runner=active_runner,
            adapters=adapters,
            adapters_callables=adapters_callables,
        )
        if pre_err is not None:
            return self._abort_pre_exec(
                run_id=run_id,
                plan=plan_obj,
                policy_hash=policy_hash,
                env_hash=env_hash,
                input_digest=input_digest,
                status=pre_status,
                reason=pre_err,
                security_context=security_context,
            )

        try:
            ckpt_file = _resolve_checkpoint_file(
                checkpoint_store_path,
                run_id,
                security_context,
                allowed_checkpoint_roots=self._allowed_checkpoint_roots,
            )
            events, completed_outputs, completed_receipts, completed_adapter_outputs, ckpt_err = (
                self._load_and_verify_checkpoint(ckpt_file, run_id, plan_obj, policy_hash)
            )
        except (PermissionError, ValueError, json.JSONDecodeError) as exc:
            return self._abort_pre_exec(
                run_id=run_id,
                plan=plan_obj,
                policy_hash=policy_hash,
                env_hash=env_hash,
                input_digest=input_digest,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=f"CHECKPOINT_ERROR:{exc}",
                security_context=security_context,
            )

        if ckpt_err is not None:
            return self._abort_pre_exec(
                run_id=run_id,
                plan=plan_obj,
                policy_hash=policy_hash,
                env_hash=env_hash,
                input_digest=input_digest,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=ckpt_err,
                security_context=security_context,
            )

        def _append_event(
            *,
            step_id: str,
            state: str,
            tool_id: str = "",
            in_dig: str = "",
            out_dig: str = "",
            elapsed_ms: float = 0.0,
            tokens_used: int = 0,
            resource_usage: Optional[Dict[str, Any]] = None,
            reason: str = "",
            severity: str = "INFO",
        ) -> RunEvent:
            prev_hash = events[-1].event_hash if events else GENESIS_EVENT_HASH
            ev = RunEvent(
                run_id=run_id,
                step_id=step_id,
                state=state,
                tool_id=tool_id,
                input_digest=in_dig or sha256_digest(""),
                output_digest=out_dig or sha256_digest(""),
                elapsed_ms=max(0.0, float(elapsed_ms)),
                tokens_used=max(0, int(tokens_used)),
                resource_usage=redact_runtime_value(dict(resource_usage or {})),
                decision_reason=redact_runtime_text(reason, max_len=1024),
                prev_event_hash=prev_hash,
                seq=len(events),
                profile=security_context.profile.value,
                component="tool_composer",
                severity=severity,
                correlation={
                    "gap_id": plan_obj.gap_id,
                    "plan_id": plan_obj.plan_id,
                    "receipt_id": run_id,
                    "tool_id": tool_id or None,
                },
            )
            events.append(ev)
            _append_checkpoint_event(ckpt_file, ev)
            return ev

        unresolved = _unresolved_checkpoint_nodes(events)
        if unresolved:
            _append_event(
                step_id="plan", state="PLAN_RECONCILIATION_REQUIRED",
                in_dig=input_digest, out_dig=plan_obj.plan_hash,
                resource_usage={"unresolved_nodes": unresolved},
                reason="unresolved_in_flight_nodes", severity="HIGH",
            )
            receipt = CompositionReceipt(
                run_id=run_id,
                plan_hash=plan_obj.plan_hash,
                policy_hash=policy_hash,
                sandbox_environment_hash=env_hash,
                node_receipts=list(completed_receipts.values()),
                unresolved_nodes=unresolved,
                input_digest=input_digest,
                output_digest=sha256_digest(""),
                oracle_result={"passed": False, "unresolved_nodes": unresolved},
                verification_status="FAIL",
                status=ExecutionStatus.RECONCILIATION_REQUIRED,
            )
            return receipt, events

        if not events:
            _append_event(
                step_id="plan",
                state="PLAN_STARTED",
                in_dig=input_digest,
                out_dig=plan_obj.plan_hash,
                resource_usage={"policy_hash": policy_hash, "plan_hash": plan_obj.plan_hash, "node_count": len(ordered_nodes)},
                reason="composition_plan_verified",
            )
        else:
            _append_event(
                step_id="plan",
                state="PLAN_RESUMED",
                in_dig=input_digest,
                out_dig=plan_obj.plan_hash,
                resource_usage={"policy_hash": policy_hash, "plan_hash": plan_obj.plan_hash, "completed_nodes": sorted(completed_outputs.keys())},
                reason=f"resumed_with_{len(completed_outputs)}_completed_nodes",
            )

        node_outputs: Dict[str, Any] = dict(completed_outputs)
        node_receipts: List[Dict[str, Any]] = []
        failed_status: Optional[ExecutionStatus] = None
        failed_reason = ""
        failed_node_id = ""
        last_output: Any = None

        for node in ordered_nodes:
            nid = str(node["node_id"])
            tid = str(node["tool_id"])
            node_kind = str(node.get("kind", "tool")).lower()

            if nid in completed_outputs:
                last_output = completed_outputs[nid]
                restored_rec = dict(completed_receipts.get(nid) or {"node_id": nid, "tool_id": tid, "status": "PASS"})
                restored_rec["resumed_from_checkpoint"] = True
                node_receipts.append(restored_rec)
                _append_event(
                    step_id=nid,
                    state="NODE_SKIPPED_CHECKPOINT",
                    tool_id=tid if node_kind != "adapter" else "",
                    in_dig=sha256_digest({"node_id": nid}),
                    out_dig=sha256_digest(last_output),
                    resource_usage={"node_id": nid, "resumed": True},
                    reason="already_completed_in_verified_checkpoint",
                )
                continue

            node_args, edge_err = self._assemble_node_inputs(
                node=node,
                incoming_edges=adj_in.get(nid, ()),
                node_outputs=node_outputs,
                plan=plan_obj,
                initial_inputs=initial_inputs,
                verified_adapters=verified_adapters,
                adapters_callables=adapters_callables,
                runner=active_runner,
                security_context=security_context,
                append_event_fn=_append_event,
                completed_adapter_outputs=completed_adapter_outputs,
                checkpoint_enabled=(ckpt_file is not None),
            )
            if edge_err is not None:
                failed_status = ExecutionStatus.FAIL
                failed_reason = edge_err
                failed_node_id = nid
                _append_event(
                    step_id=nid,
                    state="NODE_FAILED",
                    tool_id=tid if node_kind != "adapter" else "",
                    in_dig=sha256_digest(node_args),
                    out_dig=sha256_digest(""),
                    reason=edge_err,
                    severity="HIGH",
                )
                break

            if node_kind == "adapter":
                if ckpt_file is not None:
                    _append_event(
                        step_id=nid, state="NODE_IN_FLIGHT", in_dig=sha256_digest(node_args),
                        resource_usage={"node_id": nid, "kind": "adapter", "idempotent": False},
                        reason="durable_adapter_execution_intent", severity="HIGH",
                    )
                t0 = time.monotonic()
                try:
                    raw_out = self._run_adapter_transform(
                        adapter_id=tid,
                        payload=node_args,
                        verified_adapters=verified_adapters,
                        adapters_callables=adapters_callables,
                        runner=active_runner,
                        security_context=security_context,
                    )
                except Exception as exc:
                    failed_status = ExecutionStatus.FAIL
                    failed_reason = f"ADAPTER_EXECUTION_FAILED:{tid}:{exc}"
                    failed_node_id = nid
                    _append_event(step_id=nid, state="NODE_FAILED", reason=failed_reason, severity="HIGH")
                    break
                elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)
                node_outputs[nid] = raw_out
                last_output = raw_out
                rec_dict = {"node_id": nid, "tool_id": tid, "kind": "adapter", "status": "PASS", "llm_calls": 0}
                node_receipts.append(rec_dict)
                ad_hash = verified_adapters[tid].adapter_hash if tid in verified_adapters else ""
                _append_event(
                    step_id=nid,
                    state="NODE_COMPLETED",
                    tool_id=tid,
                    in_dig=sha256_digest(node_args),
                    out_dig=sha256_digest(raw_out),
                    elapsed_ms=elapsed_ms,
                    resource_usage={"node_id": nid, "adapter_hash": ad_hash, "output": raw_out, "node_receipt": rec_dict},
                    reason="adapter_node_completed",
                )
                continue

            spec = verified_specs[tid]
            expected_bin_hash = plan_obj.tool_artifact_hashes[tid]
            step_oracle = (node_oracles or {}).get(nid) or (node_oracles or {}).get(tid) or (lambda r: r.get("exit_code") == 0)
            step_cap = (node.get("capabilities") or spec.capabilities or [""])[0]

            if ckpt_file is not None:
                _append_event(
                    step_id=nid, state="NODE_IN_FLIGHT", tool_id=tid,
                    in_dig=sha256_digest(node_args),
                    resource_usage={
                        "node_id": nid,
                        "irreversible": bool(node.get("irreversible")),
                        "idempotent": bool(node.get("idempotent", False)),
                        "side_effects": list(spec.side_effects),
                        "tool_hash": spec.binary_hash,
                    },
                    reason="durable_node_execution_intent", severity="HIGH",
                )

            try:
                step_receipt: ExecutionReceipt = active_runner.run(
                    spec,
                    args=node_args,
                    security_context=security_context,
                    oracle=step_oracle,
                    task_id=f"{plan_obj.plan_id}:{nid}",
                    capability=str(step_cap),
                    plan_hash=plan_obj.plan_hash,
                    expected_tool_hash=expected_bin_hash,
                    expected_policy_hash=policy_hash,
                )
            except Exception as exc:
                failed_status = ExecutionStatus.FAIL
                failed_reason = f"RUNNER_EXCEPTION:{tid}:{redact_runtime_text(exc)}"
                failed_node_id = nid
                _append_event(
                    step_id=nid,
                    state="NODE_FAILED",
                    tool_id=tid,
                    in_dig=sha256_digest(node_args),
                    out_dig=sha256_digest(""),
                    reason=failed_reason,
                    severity="HIGH",
                )
                break

            node_rec_dict = {
                "node_id": nid,
                "tool_id": tid,
                "run_id": step_receipt.run_id,
                "status": step_receipt.status.value,
                "verification_status": step_receipt.verification_status,
                "tool_hash": step_receipt.tool_hash,
                "exit_status": step_receipt.exit_status,
                "trace_digest": step_receipt.trace_digest,
                "llm_calls": step_receipt.llm_calls,
            }
            node_receipts.append(node_rec_dict)
            step_wall_ms = float(step_receipt.resource_metrics.get("wall_time_ms", 0.0) or 0.0)

            if step_receipt.status != ExecutionStatus.PASS:
                failed_status = step_receipt.status
                failed_reason = str(
                    step_receipt.stderr_excerpt
                    or step_receipt.resource_metrics.get("error")
                    or step_receipt.resource_metrics.get("oracle_reason")
                    or f"NODE_STATUS_{step_receipt.status.value}"
                )
                failed_node_id = nid
                _append_event(
                    step_id=nid,
                    state="NODE_FAILED",
                    tool_id=tid,
                    in_dig=sha256_digest(node_args),
                    out_dig=sha256_digest(step_receipt.resource_metrics.get("output")),
                    elapsed_ms=step_wall_ms,
                    tokens_used=int(spec.api_token_estimate),
                    resource_usage={"node_id": nid, "node_receipt": node_rec_dict},
                    reason=failed_reason,
                    severity="HIGH",
                )
                break

            step_output = step_receipt.resource_metrics.get("output")
            node_outputs[nid] = step_output
            last_output = step_output
            _append_event(
                step_id=nid,
                state="NODE_COMPLETED",
                tool_id=tid,
                in_dig=sha256_digest(node_args),
                out_dig=sha256_digest(step_output),
                elapsed_ms=step_wall_ms,
                tokens_used=int(spec.api_token_estimate),
                resource_usage={
                    "node_id": nid,
                    "binary_hash": spec.binary_hash,
                    "output": step_output,
                    "node_receipt": node_rec_dict,
                },
                reason="node_executed_ok",
            )

        if failed_status is not None:
            _append_event(
                step_id="plan",
                state="PLAN_FAILED",
                in_dig=input_digest,
                out_dig=sha256_digest(last_output),
                reason=f"aborted_at_node:{failed_node_id}:{failed_reason}",
                severity="HIGH",
            )
            receipt = CompositionReceipt(
                run_id=run_id,
                plan_hash=plan_obj.plan_hash,
                policy_hash=policy_hash,
                sandbox_environment_hash=env_hash,
                node_receipts=node_receipts,
                input_digest=input_digest,
                output_digest=sha256_digest(last_output),
                oracle_result={"passed": False, "failed_node": failed_node_id, "reason": failed_reason},
                verification_status="FAIL",
                status=failed_status,
            )
            return receipt, events

        # Apply optional goal-boundary output adapters via durable pre-WAL wrapper
        goal_out_adapters = plan_obj.verification_plan.get("goal_output_adapters") or ()
        goal_out_failed = False
        goal_out_err = ""
        goal_out_nid = ""
        for g_idx, g_ad in enumerate(goal_out_adapters):
            if not isinstance(g_ad, Mapping):
                continue
            src_nid = str(g_ad.get("node_id") or "")
            ad_id = str(g_ad.get("adapter_id") or "")
            if src_nid in node_outputs and ad_id:
                step_key = _make_adapter_step_id("goal_out", src_nid, g_idx, ad_id)
                try:
                    last_output = self._execute_checkpointed_adapter(
                        adapter_step_id=step_key,
                        adapter_id=ad_id,
                        adapter_kind="goal_output",
                        payload=node_outputs[src_nid],
                        verified_adapters=verified_adapters,
                        adapters_callables=adapters_callables,
                        runner=active_runner,
                        security_context=security_context,
                        append_event_fn=_append_event,
                        completed_adapter_outputs=completed_adapter_outputs,
                        checkpoint_enabled=(ckpt_file is not None),
                        extra_meta={"node_id": src_nid, "goal_out_idx": g_idx},
                    )
                    node_outputs[f"{src_nid}__goal_adapted"] = last_output
                except Exception as exc:
                    goal_out_failed = True
                    goal_out_err = f"GOAL_OUTPUT_ADAPTER_FAILED:{ad_id}:{exc}"
                    goal_out_nid = src_nid
                    _append_event(
                        step_id=step_key,
                        state="ADAPTER_FAILED",
                        tool_id=ad_id,
                        in_dig=sha256_digest(node_outputs[src_nid]),
                        out_dig=sha256_digest(""),
                        reason=goal_out_err,
                        severity="HIGH",
                    )
                    break

        if goal_out_failed:
            _append_event(
                step_id="plan",
                state="PLAN_FAILED",
                in_dig=input_digest,
                out_dig=sha256_digest(last_output),
                reason=f"aborted_at_node:{goal_out_nid}:{goal_out_err}",
                severity="HIGH",
            )
            return (
                CompositionReceipt(
                    run_id=run_id,
                    plan_hash=plan_obj.plan_hash,
                    policy_hash=policy_hash,
                    sandbox_environment_hash=env_hash,
                    node_receipts=node_receipts,
                    input_digest=input_digest,
                    output_digest=sha256_digest(last_output),
                    oracle_result={"passed": False, "failed_node": goal_out_nid, "reason": goal_out_err},
                    verification_status="FAIL",
                    status=ExecutionStatus.FAIL,
                ),
                events,
            )

        final_output_digest = sha256_digest(last_output)
        if oracle is None:
            _append_event(
                step_id="plan",
                state="PLAN_COMPLETED",
                in_dig=input_digest,
                out_dig=final_output_digest,
                reason="completed_without_oracle",
            )
            return (
                CompositionReceipt(
                    run_id=run_id,
                    plan_hash=plan_obj.plan_hash,
                    policy_hash=policy_hash,
                    sandbox_environment_hash=env_hash,
                    node_receipts=node_receipts,
                    input_digest=input_digest,
                    output_digest=final_output_digest,
                    oracle_result={"passed": None, "reason": "NO_ORACLE_PROVIDED"},
                    verification_status="NOT_VERIFIED",
                    status=ExecutionStatus.NOT_VERIFIED,
                ),
                events,
            )

        dag_summary = {
            "status": "SUCCEEDED",
            "run_id": run_id,
            "plan_hash": plan_obj.plan_hash,
            "output": last_output,
            "outputs_by_node": node_outputs,
            "node_receipts": node_receipts,
            "workspace_root": security_context.workspace_root,
        }
        passed, oracle_reason = _invoke_dag_oracle(oracle, dag_summary, plan_obj, security_context)
        final_status = ExecutionStatus.PASS if passed else ExecutionStatus.FAIL
        final_ver_status = "PASS" if passed else "FAIL"
        _append_event(
            step_id="plan",
            state="PLAN_COMPLETED" if passed else "PLAN_FAILED",
            in_dig=input_digest,
            out_dig=final_output_digest,
            reason=oracle_reason,
            severity="INFO" if passed else "HIGH",
        )
        return (
            CompositionReceipt(
                run_id=run_id,
                plan_hash=plan_obj.plan_hash,
                policy_hash=policy_hash,
                sandbox_environment_hash=env_hash,
                node_receipts=node_receipts,
                input_digest=input_digest,
                output_digest=final_output_digest,
                oracle_result={"passed": passed, "reason": oracle_reason},
                verification_status=final_ver_status,
                status=final_status,
            ),
            events,
        )

    def _abort_pre_exec(
        self,
        *,
        run_id: str,
        plan: CompositionPlan,
        policy_hash: str,
        env_hash: str,
        input_digest: str,
        status: ExecutionStatus,
        reason: str,
        security_context: SecurityContext,
    ) -> Tuple[CompositionReceipt, List[RunEvent]]:
        safe_pol = policy_hash if is_valid_sha256(policy_hash) else GENESIS_EVENT_HASH
        ev = RunEvent(
            run_id=run_id,
            step_id="plan",
            state="PLAN_DENIED",
            tool_id="",
            input_digest=input_digest,
            output_digest=sha256_digest(""),
            elapsed_ms=0.0,
            tokens_used=0,
            resource_usage={"plan_hash": plan.plan_hash},
            decision_reason=redact_runtime_text(reason, max_len=1024),
            prev_event_hash=GENESIS_EVENT_HASH,
            seq=0,
            profile=security_context.profile.value,
            component="tool_composer",
            severity="HIGH",
            correlation={"gap_id": plan.gap_id, "plan_id": plan.plan_id, "receipt_id": run_id, "tool_id": None},
        )
        rec = CompositionReceipt(
            run_id=run_id,
            plan_hash=plan.plan_hash,
            policy_hash=safe_pol,
            sandbox_environment_hash=env_hash,
            node_receipts=[],
            input_digest=input_digest,
            output_digest=sha256_digest(""),
            oracle_result={"passed": False, "reason": redact_runtime_text(reason)},
            verification_status="FAIL",
            status=status,
        )
        return rec, [ev]

    def _reverify_plan_for_execution(
        self,
        plan: CompositionPlan,
        registry: ToolRegistry,
        security_context: SecurityContext,
        *,
        runner: SecureRunner,
        adapters: Sequence[Union[AdapterSpec, Mapping[str, Any]]],
        adapters_callables: Optional[Mapping[str, Callable[..., Any]]],
    ) -> Tuple[
        List[Dict[str, Any]],
        Dict[str, List[Dict[str, Any]]],
        Optional[str],
        ExecutionStatus,
        Dict[str, ToolSpec],
        Dict[str, AdapterSpec],
    ]:
        # Enforce profile limits
        if security_context.profile == SecurityProfile.GITHUB_PUBLIC:
            depth = _compute_state_dag_depth(
                [str(n["node_id"]) for n in plan.nodes],
                [(str(e["from_node"]), str(e["to_node"])) for e in plan.edges],
            )
            if depth > GithubPublicConfig().max_composition_depth:
                return [], {}, "MAX_COMPOSITION_DEPTH_EXCEEDED", ExecutionStatus.PERMISSION_DENIED, {}, {}

        # Verify declared permission_union against SecurityContext
        allowed_perms = set(security_context.allowed_permissions)
        extra_plan_perms = sorted(set(plan.permission_union) - allowed_perms)
        if extra_plan_perms:
            return [], {}, f"OVER_PRIVILEGED_PLAN_PERMISSIONS:{','.join(extra_plan_perms)}", ExecutionStatus.PERMISSION_DENIED, {}, {}

        # Verify every node tool against live registry and artifact hashes
        verified_specs: Dict[str, ToolSpec] = {}
        eff_list: List[EffectContract] = []
        node_map: Dict[str, Dict[str, Any]] = {}
        for node in plan.nodes:
            nid = str(node["node_id"])
            tid = str(node["tool_id"])
            node_map[nid] = node
            kind = str(node.get("kind", "tool")).lower()
            if kind == "adapter":
                if tid not in plan.adapter_hashes:
                    return [], {}, f"MISSING_ADAPTER_HASH:{tid}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                if node.get("adapter_hash") and not hmac.compare_digest(str(node["adapter_hash"]).lower(), plan.adapter_hashes[tid]):
                    return [], {}, f"ADAPTER_HASH_MISMATCH:{tid}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                continue

            spec = registry.get(tid)
            if spec is None:
                return [], {}, f"TOOL_NOT_IN_REGISTRY:{tid}", ExecutionStatus.NO_VERIFIED_TOOL, {}, {}
            if spec.trust_status == TrustStatus.DISCOVERED:
                return [], {}, f"TOOL_UNVERIFIED_DISCOVERED:{tid}", ExecutionStatus.NO_VERIFIED_TOOL, {}, {}
            if spec.trust_status != TrustStatus.VERIFIED:
                return [], {}, f"TOOL_NOT_VERIFIED:{tid}:{spec.trust_status.value}", ExecutionStatus.PERMISSION_DENIED, {}, {}
            if not registry.authority.verify_attestation(
                spec.verification_attestation or {},
                expected_tool_id=spec.tool_id,
                expected_binary_hash=spec.binary_hash,
                expected_spec_digest=compute_tool_spec_security_digest(spec),
            ):
                return [], {}, f"SPOOFED_VERIFIED_ATTESTATION:{tid}", ExecutionStatus.PERMISSION_DENIED, {}, {}
            expected_hash = plan.tool_artifact_hashes.get(tid)
            if not expected_hash or not hmac.compare_digest(expected_hash, spec.binary_hash.lower()):
                return [], {}, f"TOOL_ARTIFACT_HASH_MISMATCH:{tid}", ExecutionStatus.PERMISSION_DENIED, {}, {}
            if node.get("binary_hash") and not hmac.compare_digest(str(node["binary_hash"]).lower(), spec.binary_hash.lower()):
                return [], {}, f"NODE_BINARY_HASH_MISMATCH:{tid}", ExecutionStatus.PERMISSION_DENIED, {}, {}
            viol = tool_violates_security_context(spec, security_context)
            if viol:
                return [], {}, f"SECURITY_CONTEXT_VIOLATION:{tid}:{','.join(viol)}", ExecutionStatus.PERMISSION_DENIED, {}, {}

            eff = extract_tool_effect_contract(spec)
            eff_list.append(eff)
            verified_specs[tid] = spec

        dag_eff = compute_dag_effects(eff_list)
        if not set(dag_eff["permission_union"]).issubset(allowed_perms):
            return [], {}, "DAG_EFFECT_PERMISSION_UNION_EXCEEDED", ExecutionStatus.PERMISSION_DENIED, {}, {}

        # Load & re-verify adapters from explicit `adapters` arg and embedded `verification_plan.adapters`
        verified_adapters: Dict[str, AdapterSpec] = {}
        raw_adapter_sources: List[Union[AdapterSpec, Mapping[str, Any]]] = list(adapters or ())
        embedded_adapters = plan.verification_plan.get("adapters")
        if isinstance(embedded_adapters, Mapping):
            for ad_dict in embedded_adapters.values():
                if isinstance(ad_dict, Mapping):
                    raw_adapter_sources.append(ad_dict)
        for raw_ad in raw_adapter_sources:
            ad_obj, ad_reasons, _ = _validate_adapter_candidate(raw_ad, authority=registry.authority)
            if ad_obj is None:
                return [], {}, f"INVALID_ADAPTER_AT_EXECUTION:{','.join(ad_reasons)}", ExecutionStatus.PERMISSION_DENIED, {}, {}
            if ad_obj.adapter_id in plan.adapter_hashes:
                if not hmac.compare_digest(ad_obj.adapter_hash, plan.adapter_hashes[ad_obj.adapter_id]):
                    return [], {}, f"ADAPTER_HASH_MISMATCH:{ad_obj.adapter_id}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                verified_adapters[ad_obj.adapter_id] = ad_obj

        if adapters_callables:
            runner_auth = getattr(runner, "_attestation_authority", None)
            runner_allows = bool(getattr(runner, "_allow_trusted_host_callables", False))
            for raw_ad_id, fn in adapters_callables.items():
                ad_id = str(raw_ad_id)
                ad_spec = verified_adapters.get(ad_id)
                if ad_spec is None or not callable(fn):
                    return [], {}, f"UNTRUSTED_OR_UNBOUND_ADAPTER_CALLABLE:{ad_id}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                if not runner_allows or not runner.has_trusted_host_adapter(ad_id, fn):
                    return [], {}, f"UNREGISTERED_TRUSTED_HOST_ADAPTER:{ad_id}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                fn_hash = compute_callable_sha256(fn)
                if not registry.authority.verify_adapter_attestation(
                    ad_spec.verification_attestation or {},
                    expected_adapter_id=ad_spec.adapter_id,
                    expected_adapter_hash=ad_spec.adapter_hash,
                    expected_corpus_hash=ad_spec.verification_corpus_hash,
                    expected_callable_hash=fn_hash,
                ) or runner_auth is None or not runner_auth.verify_adapter_attestation(
                    ad_spec.verification_attestation or {},
                    expected_adapter_id=ad_spec.adapter_id,
                    expected_adapter_hash=ad_spec.adapter_hash,
                    expected_corpus_hash=ad_spec.verification_corpus_hash,
                    expected_callable_hash=fn_hash,
                ):
                    return [], {}, f"UNTRUSTED_OR_UNBOUND_ADAPTER_CALLABLE:{ad_id}", ExecutionStatus.PERMISSION_DENIED, {}, {}

        adj_in: Dict[str, List[Dict[str, Any]]] = {nid: [] for nid in node_map}
        raw_edges: List[Tuple[str, str]] = []
        for edge in plan.edges:
            src_nid = str(edge["from_node"])
            dst_nid = str(edge["to_node"])
            raw_edges.append((src_nid, dst_nid))
            adj_in[dst_nid].append(edge)
            ad_id = edge.get("adapter_id")
            ad_hash = edge.get("adapter_hash")
            if ad_id:
                expected_ad_hash = plan.adapter_hashes.get(str(ad_id))
                if not expected_ad_hash:
                    return [], {}, f"MISSING_EDGE_ADAPTER_HASH:{ad_id}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                if ad_hash and not hmac.compare_digest(str(ad_hash).lower(), expected_ad_hash):
                    return [], {}, f"EDGE_ADAPTER_HASH_MISMATCH:{ad_id}", ExecutionStatus.PERMISSION_DENIED, {}, {}
                if str(ad_id) not in verified_adapters:
                    return [], {}, f"MISSING_ADAPTER_IMPL:{ad_id}", ExecutionStatus.NO_VERIFIED_TOOL, {}, {}

        for node in plan.nodes:
            if str(node.get("kind", "tool")).lower() == "adapter":
                tid = str(node["tool_id"])
                if tid not in verified_adapters:
                    return [], {}, f"MISSING_ADAPTER_IMPL:{tid}", ExecutionStatus.NO_VERIFIED_TOOL, {}, {}

        for g_ad in list(plan.input_bindings.get("goal_input_adapters") or ()) + list(
            plan.verification_plan.get("goal_output_adapters") or ()
        ):
            if isinstance(g_ad, Mapping) and g_ad.get("adapter_id"):
                ad_id = str(g_ad.get("adapter_id") or "")
                if ad_id and ad_id not in verified_adapters:
                    return [], {}, f"MISSING_ADAPTER_IMPL:{ad_id}", ExecutionStatus.NO_VERIFIED_TOOL, {}, {}

        ordered_nids = _topological_sort_keys(list(node_map.keys()), raw_edges, tie_key_fn=lambda nid: (nid,))
        ordered_nodes = [node_map[nid] for nid in ordered_nids]
        return ordered_nodes, adj_in, None, ExecutionStatus.PASS, verified_specs, verified_adapters

    def reconcile_checkpoint_node(
        self,
        *,
        checkpoint_store_path: Union[str, Path],
        run_id: str,
        node_id: str,
        outcome: str,
        security_context: SecurityContext,
        verified_output: Any = None,
        verified_receipt: Optional[Mapping[str, Any]] = None,
        operator_confirmed: bool = False,
    ) -> RunEvent:
        """Explicit operator reconciliation for an ambiguous completed side effect.

        For COMMITTED, caller supplies a trusted execution receipt and output;
        no oracle result is fabricated by this method. NOT_EXECUTED permits a
        later retry only after an operator positively confirms non-execution.
        """
        if not operator_confirmed:
            raise PermissionError("OPERATOR_RECONCILIATION_APPROVAL_REQUIRED")
        if outcome not in {"COMMITTED", "NOT_EXECUTED"}:
            raise ValueError("INVALID_RECONCILIATION_OUTCOME")
        safe_run = validate_safe_text(run_id, field_name="run_id")
        safe_node = validate_safe_text(node_id, field_name="node_id")
        if not VALID_RUN_ID_RE.fullmatch(safe_run):
            raise ValueError("INVALID_RUN_ID")
        ckpt = _resolve_checkpoint_file(
            checkpoint_store_path,
            safe_run,
            security_context,
            allowed_checkpoint_roots=self._allowed_checkpoint_roots,
        )
        if ckpt is None:
            raise ValueError("CHECKPOINT_NOT_FOUND")
        try:
            events = _load_checkpoint_events(ckpt, missing_ok=False)
        except FileNotFoundError as exc:
            raise ValueError("CHECKPOINT_NOT_FOUND") from exc
        if not events or not verify_event_chain(events).valid or events[0].run_id != safe_run:
            raise ValueError("CHECKPOINT_EVENT_CHAIN_INVALID")
        if safe_node not in _unresolved_checkpoint_nodes(events):
            raise ValueError("NODE_NOT_AWAITING_RECONCILIATION")
        is_adapter_step = safe_node.startswith(("edge:", "goal_in:", "goal_out:"))
        if outcome == "COMMITTED":
            if not isinstance(verified_receipt, Mapping) or verified_receipt.get("verification_status") != "PASS":
                raise PermissionError("VERIFIED_EXECUTION_RECEIPT_REQUIRED")
            node_result = {"node_id": safe_node, "output": verified_output, "node_receipt": dict(verified_receipt)}
            state = "ADAPTER_RECONCILED_COMMITTED" if is_adapter_step else "NODE_RECONCILED_COMMITTED"
        else:
            node_result = {"node_id": safe_node, "confirmed_not_executed": True}
            state = "ADAPTER_RECONCILED_NOT_EXECUTED" if is_adapter_step else "NODE_RECONCILED_NOT_EXECUTED"
        ev = RunEvent(
            run_id=safe_run,
            step_id=safe_node,
            state=state,
            input_digest=sha256_digest({"operator_confirmed": True, "outcome": outcome}),
            output_digest=sha256_digest(verified_output) if outcome == "COMMITTED" else sha256_digest(""),
            resource_usage=redact_runtime_value(node_result),
            decision_reason="explicit_operator_reconciliation",
            prev_event_hash=events[-1].event_hash,
            seq=len(events),
            profile=security_context.profile.value,
            component="tool_composer",
            severity="HIGH",
        )
        _append_checkpoint_event(ckpt, ev)
        return ev

    def _load_and_verify_checkpoint(
        self,
        ckpt_file: Optional[_ConfinedCheckpointRef],
        run_id: str,
        plan: CompositionPlan,
        policy_hash: str,
    ) -> Tuple[List[RunEvent], Dict[str, Any], Dict[str, Dict[str, Any]], Dict[str, Any], Optional[str]]:
        if ckpt_file is None:
            return [], {}, {}, {}, None

        prior_events = _load_checkpoint_events(ckpt_file, missing_ok=True)
        if not prior_events:
            return [], {}, {}, {}, None

        chain_verdict = verify_event_chain(prior_events)
        if not chain_verdict.valid:
            return [], {}, {}, {}, f"CHECKPOINT_EVENT_CHAIN_INVALID:{','.join(chain_verdict.reasons)}"

        if prior_events[0].run_id != run_id:
            return [], {}, {}, {}, f"CHECKPOINT_RUN_ID_MISMATCH:{prior_events[0].run_id}!={run_id}"

        start_ev = prior_events[0]
        if start_ev.state == "PLAN_STARTED":
            if not hmac.compare_digest(start_ev.output_digest, plan.plan_hash):
                return [], {}, {}, {}, "CHECKPOINT_PLAN_HASH_MISMATCH"
            rec_pol = str(start_ev.resource_usage.get("policy_hash", "")).strip().lower()
            if rec_pol and not hmac.compare_digest(rec_pol, policy_hash.lower()):
                return [], {}, {}, {}, "CHECKPOINT_POLICY_HASH_MISMATCH"

        completed_outputs: Dict[str, Any] = {}
        completed_receipts: Dict[str, Dict[str, Any]] = {}
        completed_adapter_outputs: Dict[str, Any] = {}
        for ev in prior_events:
            if ev.state in {"NODE_RECONCILED_NOT_EXECUTED", "ADAPTER_RECONCILED_NOT_EXECUTED"}:
                completed_outputs.pop(ev.step_id, None)
                completed_receipts.pop(ev.step_id, None)
                completed_adapter_outputs.pop(ev.step_id, None)
                continue
            if ev.state in {"ADAPTER_APPLIED", "ADAPTER_RECONCILED_COMMITTED"}:
                rec_ad_hash = str(ev.resource_usage.get("adapter_hash") or "").strip().lower()
                ad_id = str(ev.tool_id or ev.resource_usage.get("adapter_id") or "").strip()
                if ad_id and ad_id in plan.adapter_hashes and rec_ad_hash:
                    if not hmac.compare_digest(rec_ad_hash, plan.adapter_hashes[ad_id]):
                        return [], {}, {}, {}, f"CHECKPOINT_ADAPTER_HASH_CHANGED:{ad_id}"
                completed_adapter_outputs[ev.step_id] = ev.resource_usage.get("output")
                continue
            if ev.state not in {"NODE_COMPLETED", "NODE_RECONCILED_COMMITTED"}:
                continue
            nid = str(ev.resource_usage.get("node_id") or ev.step_id)
            rec_bin = str(ev.resource_usage.get("binary_hash") or "").strip().lower()
            if ev.tool_id and ev.tool_id in plan.tool_artifact_hashes and rec_bin:
                if not hmac.compare_digest(rec_bin, plan.tool_artifact_hashes[ev.tool_id]):
                    return [], {}, {}, {}, f"CHECKPOINT_TOOL_HASH_CHANGED:{ev.tool_id}"
            rec_ad = str(ev.resource_usage.get("adapter_hash") or "").strip().lower()
            if ev.tool_id and ev.tool_id in plan.adapter_hashes and rec_ad:
                if not hmac.compare_digest(rec_ad, plan.adapter_hashes[ev.tool_id]):
                    return [], {}, {}, {}, f"CHECKPOINT_ADAPTER_HASH_CHANGED:{ev.tool_id}"
            if ev.step_id.startswith(("edge:", "goal_in:", "goal_out:")):
                completed_adapter_outputs[ev.step_id] = ev.resource_usage.get("output")
                continue
            completed_outputs[nid] = ev.resource_usage.get("output")
            if isinstance(ev.resource_usage.get("node_receipt"), Mapping):
                completed_receipts[nid] = dict(ev.resource_usage["node_receipt"])

        return prior_events, completed_outputs, completed_receipts, completed_adapter_outputs, None

    def _run_adapter_transform(
        self,
        *,
        adapter_id: str,
        payload: Any,
        verified_adapters: Mapping[str, AdapterSpec],
        adapters_callables: Optional[Mapping[str, Callable[..., Any]]],
        runner: SecureRunner,
        security_context: SecurityContext,
    ) -> Any:
        ad_spec = verified_adapters.get(adapter_id)
        if ad_spec is None:
            raise PermissionError(f"MISSING_VERIFIED_ADAPTER:{adapter_id}")
        signed_callable_hash = str((ad_spec.verification_attestation or {}).get("callable_hash") or "").strip().lower()
        if adapters_callables and adapter_id in adapters_callables:
            if not signed_callable_hash:
                raise PermissionError(f"ADAPTER_CALLABLE_OVERRIDE_FORBIDDEN:{adapter_id}")
            return runner.execute_trusted_host_adapter(
                ad_spec,
                payload,
                security_context=security_context,
                expected_callable=adapters_callables[adapter_id],
            )
        if signed_callable_hash:
            return runner.execute_trusted_host_adapter(
                ad_spec,
                payload,
                security_context=security_context,
            )
        return _apply_adapter_spec(ad_spec, payload)

    def _execute_checkpointed_adapter(
        self,
        *,
        adapter_step_id: str,
        adapter_id: str,
        adapter_kind: str,
        payload: Any,
        verified_adapters: Mapping[str, AdapterSpec],
        adapters_callables: Optional[Mapping[str, Callable[..., Any]]],
        runner: SecureRunner,
        security_context: SecurityContext,
        append_event_fn: Callable[..., RunEvent],
        completed_adapter_outputs: Dict[str, Any],
        checkpoint_enabled: bool,
        extra_meta: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        """Execute an edge or goal adapter with pre-WAL intent and crash-resume replay protection."""
        if adapter_step_id in completed_adapter_outputs:
            restored = completed_adapter_outputs[adapter_step_id]
            append_event_fn(
                step_id=adapter_step_id,
                state="ADAPTER_SKIPPED_CHECKPOINT",
                tool_id=adapter_id,
                in_dig=sha256_digest(payload),
                out_dig=sha256_digest(restored),
                resource_usage={
                    "step_id": adapter_step_id,
                    "adapter_id": adapter_id,
                    "kind": adapter_kind,
                    "resumed": True,
                    **dict(extra_meta or {}),
                },
                reason="already_completed_in_verified_checkpoint",
            )
            return restored

        ad_spec = verified_adapters.get(adapter_id)
        if ad_spec is None:
            raise PermissionError(f"MISSING_VERIFIED_ADAPTER:{adapter_id}")

        if checkpoint_enabled:
            append_event_fn(
                step_id=adapter_step_id,
                state="ADAPTER_IN_FLIGHT",
                tool_id=adapter_id,
                in_dig=sha256_digest(payload),
                resource_usage={
                    "step_id": adapter_step_id,
                    "adapter_id": adapter_id,
                    "adapter_hash": ad_spec.adapter_hash,
                    "kind": adapter_kind,
                    "idempotent": False,
                    **dict(extra_meta or {}),
                },
                reason="durable_adapter_execution_intent",
                severity="HIGH",
            )

        t0 = time.monotonic()
        adapted_val = self._run_adapter_transform(
            adapter_id=adapter_id,
            payload=payload,
            verified_adapters=verified_adapters,
            adapters_callables=adapters_callables,
            runner=runner,
            security_context=security_context,
        )
        elapsed_ms = round((time.monotonic() - t0) * 1000.0, 3)
        append_event_fn(
            step_id=adapter_step_id,
            state="ADAPTER_APPLIED",
            tool_id=adapter_id,
            in_dig=sha256_digest(payload),
            out_dig=sha256_digest(adapted_val),
            elapsed_ms=elapsed_ms,
            resource_usage={
                "step_id": adapter_step_id,
                "adapter_id": adapter_id,
                "adapter_hash": ad_spec.adapter_hash,
                "kind": adapter_kind,
                "output": adapted_val,
                **dict(extra_meta or {}),
            },
            reason="adapter_transform_applied",
        )
        completed_adapter_outputs[adapter_step_id] = adapted_val
        return adapted_val

    def _assemble_node_inputs(
        self,
        *,
        node: Mapping[str, Any],
        incoming_edges: Sequence[Mapping[str, Any]],
        node_outputs: Mapping[str, Any],
        plan: CompositionPlan,
        initial_inputs: Optional[Mapping[str, Any]],
        verified_adapters: Mapping[str, AdapterSpec],
        adapters_callables: Optional[Mapping[str, Callable[..., Any]]],
        runner: SecureRunner,
        security_context: SecurityContext,
        append_event_fn: Callable[..., RunEvent],
        completed_adapter_outputs: Optional[Dict[str, Any]] = None,
        checkpoint_enabled: bool = False,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        nid = str(node["node_id"])
        node_args: Dict[str, Any] = {}
        adapter_cache: Dict[str, Any] = completed_adapter_outputs if completed_adapter_outputs is not None else {}

        if isinstance(initial_inputs, Mapping):
            if nid in initial_inputs and isinstance(initial_inputs[nid], Mapping):
                node_args.update(dict(initial_inputs[nid]))
            elif not incoming_edges:
                for k, v in initial_inputs.items():
                    if not isinstance(v, Mapping) or k not in {str(n["node_id"]) for n in plan.nodes}:
                        node_args[str(k)] = v

        node_id_set = {str(n["node_id"]) for n in plan.nodes}
        for k, v in plan.input_bindings.items():
            if k == "goal_input_adapters":
                continue
            if "." in k and k.split(".", 1)[0] in node_id_set:
                prefix, sub_key = k.split(".", 1)
                if prefix == nid and not isinstance(v, Mapping):
                    node_args.setdefault(sub_key, v)
            elif not incoming_edges:
                node_args.setdefault(k, v)

        # Apply goal-boundary input adapters with pre-WAL durable intent
        for g_idx, g_ad in enumerate(plan.input_bindings.get("goal_input_adapters") or ()):
            if isinstance(g_ad, Mapping) and str(g_ad.get("node_id")) == nid:
                ad_id = str(g_ad.get("adapter_id") or "")
                if ad_id:
                    step_key = _make_adapter_step_id("goal_in", nid, g_idx, ad_id)
                    try:
                        transformed = self._execute_checkpointed_adapter(
                            adapter_step_id=step_key,
                            adapter_id=ad_id,
                            adapter_kind="goal_input",
                            payload=dict(node_args),
                            verified_adapters=verified_adapters,
                            adapters_callables=adapters_callables,
                            runner=runner,
                            security_context=security_context,
                            append_event_fn=append_event_fn,
                            completed_adapter_outputs=adapter_cache,
                            checkpoint_enabled=checkpoint_enabled,
                            extra_meta={"to_node": nid, "goal_in_idx": g_idx},
                        )
                    except Exception as exc:
                        append_event_fn(
                            step_id=step_key,
                            state="ADAPTER_FAILED",
                            tool_id=ad_id,
                            in_dig=sha256_digest(node_args),
                            out_dig=sha256_digest(""),
                            reason=f"GOAL_INPUT_ADAPTER_FAILED:{ad_id}:{exc}",
                            severity="HIGH",
                        )
                        return node_args, f"GOAL_INPUT_ADAPTER_FAILED:{ad_id}:{exc}"
                    if isinstance(transformed, Mapping):
                        node_args = dict(transformed)
                    else:
                        node_args = {"payload": transformed}

        for edge_idx, edge in enumerate(incoming_edges):
            src_nid = str(edge["from_node"])
            if src_nid not in node_outputs:
                return node_args, f"MISSING_UPSTREAM_OUTPUT:{src_nid}"
            val = node_outputs[src_nid]
            ad_id = edge.get("adapter_id")
            if ad_id:
                ad_id_s = str(ad_id)
                step_key = _make_adapter_step_id("edge", f"{src_nid}__to__{nid}", edge_idx, ad_id_s)
                try:
                    val = self._execute_checkpointed_adapter(
                        adapter_step_id=step_key,
                        adapter_id=ad_id_s,
                        adapter_kind="edge",
                        payload=val,
                        verified_adapters=verified_adapters,
                        adapters_callables=adapters_callables,
                        runner=runner,
                        security_context=security_context,
                        append_event_fn=append_event_fn,
                        completed_adapter_outputs=adapter_cache,
                        checkpoint_enabled=checkpoint_enabled,
                        extra_meta={"from_node": src_nid, "to_node": nid, "edge_idx": edge_idx},
                    )
                except Exception as exc:
                    append_event_fn(
                        step_id=step_key,
                        state="ADAPTER_FAILED",
                        tool_id=ad_id_s,
                        in_dig=sha256_digest(val),
                        out_dig=sha256_digest(""),
                        reason=f"EDGE_ADAPTER_FAILED:{ad_id_s}:{exc}",
                        severity="HIGH",
                    )
                    return node_args, f"EDGE_ADAPTER_FAILED:{ad_id_s}:{exc}"

            in_port = str(edge.get("input_port") or edge.get("to_port") or "").strip()
            if isinstance(val, Mapping):
                node_args.update({str(k): v for k, v in val.items()})
                if in_port and in_port not in {"in", "default", "input", "output"}:
                    node_args.setdefault(in_port, dict(val))
            else:
                target_key = in_port if (in_port and in_port not in {"in", "default", "input", "output"}) else "payload"
                node_args[target_key] = val

        return node_args, None


def unverified_tools_present(rejected_tools: Sequence[Mapping[str, Any]]) -> bool:
    return any(r.get("status") == ExecutionStatus.NO_VERIFIED_TOOL.value for r in rejected_tools)


__all__ = [
    "CompositionPlanResult",
    "MissingAdapterGap",
    "ToolComposer",
    "extract_tool_effect_contract",
]
