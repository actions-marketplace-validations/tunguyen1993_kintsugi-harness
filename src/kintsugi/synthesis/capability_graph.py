"""Build #3 Demand-Driven Typed Capability Graph, Gap Discovery & Pareto Synthesis Ranking.

Implements deterministic (`llm_calls=0`) multi-hop typed capability routing over
`VERIFIED` tools (`ToolSpec/1`), enforcing sensitivity lattice non-leakage,
least-privilege permission subsetting, and `EffectContract/1` idempotency rules.
Discovers single-hop and multi-hop bottlenecks to emit canonical
`SynthesisBlueprint/1` specifications and ranks synthesis candidates on exact
integer / `Decimal` Pareto frontiers (`RankedSynthesisPlan/1`).
"""

from __future__ import annotations

import heapq
import hmac
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.capability_graph import tool_violates_security_context
from kintsugi.capability.contracts_v2 import EffectContract, PortContract, compute_dag_effects
from kintsugi.capability.schemas import (
    CapabilityGap,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    has_valid_verification_attestation,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.shield import TROJAN_UNICODE_RE
from kintsugi.tools.tool_wire import DeclassificationGrant

TYPED_PORT_SCHEMA = "TypedPort/1"
SYNTHESIS_BLUEPRINT_SCHEMA = "SynthesisBlueprint/1"
RANKED_SYNTHESIS_PLAN_SCHEMA = "RankedSynthesisPlan/1"

SENSITIVITY_LEVELS: Dict[str, int] = {
    "public": 0,
    "internal": 1,
    "secret": 2,
}
_RANK_TO_SENSITIVITY: Dict[int, str] = {v: k for k, v in SENSITIVITY_LEVELS.items()}

DECLASSIFY_TRANSFORMS: FrozenSet[str] = frozenset(
    {"redact", "mask", "hash", "tokenize", "anonymize", "sanitize", "declassify"}
)
_WILDCARD_TOKENS: FrozenSet[str] = frozenset({"", "any", "*"})
_NETWORK_TOKENS: FrozenSet[str] = frozenset(
    {"network", "network.outbound", "network.inbound", "net", "http", "https", "socket", "web"}
)

CANONICAL_UNIT_ALIASES: Dict[str, str] = {
    "": "none",
    "none": "none",
    "unitless": "none",
    "ns": "ns",
    "nanosecond": "ns",
    "nanoseconds": "ns",
    "us": "us",
    "microsecond": "us",
    "microseconds": "us",
    "µs": "us",
    "ms": "ms",
    "millisecond": "ms",
    "milliseconds": "ms",
    "s": "s",
    "sec": "s",
    "second": "s",
    "seconds": "s",
    "b": "bytes",
    "byte": "bytes",
    "bytes": "bytes",
    "kb": "kb",
    "kilobyte": "kb",
    "kilobytes": "kb",
    "mb": "mb",
    "megabyte": "mb",
    "megabytes": "mb",
    "gb": "gb",
    "gigabyte": "gb",
    "gigabytes": "gb",
    "bps": "bps",
    "basis_points": "bps",
    "pct": "pct",
    "percent": "pct",
    "micro_usd": "micro_usd",
    "usd": "usd",
    "count": "count",
}

_FORMAT_ALIASES: Dict[str, str] = {
    "raw_bytes": "bytes",
    "application/octet-stream": "bytes",
    "ndjson": "jsonl",
    "application/jsonl": "jsonl",
    "application/x-ndjson": "jsonl",
    "text/csv": "csv",
    "application/json": "json",
    "typed_events": "typed_event_stream",
    "typed_event": "typed_event_stream",
    "event_stream": "typed_event_stream",
    "events": "typed_event_stream",
}

_WIRE_LIKE_FORMATS: FrozenSet[str] = frozenset(
    {"bytes", "jsonl", "csv", "json", "typed_event_stream", "sarif", "text"}
)

_MAX_ACCURACY_BPS = Decimal("10000")
_DECIMAL_ZERO = Decimal("0")
_DECIMAL_THOUSAND = Decimal("1000")


class GapKind(str, Enum):
    """Canonical bottleneck categories emitted by `TypedCapabilityGraph.detect_capability_gaps`."""

    MISSING_FORMAT_BRIDGE = "MISSING_FORMAT_BRIDGE"
    MISSING_UNIT_CONVERTER = "MISSING_UNIT_CONVERTER"
    MISSING_DECLASSIFICATION_GATE = "MISSING_DECLASSIFICATION_GATE"
    PERMISSION_BLOCKED_EDGE = "PERMISSION_BLOCKED_EDGE"
    EFFECT_CONSTRAINT_BLOCKED = "EFFECT_CONSTRAINT_BLOCKED"
    MISSING_PRIMITIVE_KERNEL = "MISSING_PRIMITIVE_KERNEL"


def _validate_structure_hygiene(value: Any, *, field_name: str) -> None:
    if isinstance(value, str):
        if "\x00" in value or TROJAN_UNICODE_RE.search(value):
            raise ValueError(f"REJECTED_TROJAN_UNICODE ({field_name}): control or bidi character detected.")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _validate_structure_hygiene(str(k), field_name=field_name)
            _validate_structure_hygiene(v, field_name=field_name)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            _validate_structure_hygiene(item, field_name=field_name)


def _sanitize_dict(value: Any, *, field_name: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"INVALID_{field_name.upper()}: expected mapping.")
    cleaned = redact_secrets_in_value(dict(value))
    _validate_structure_hygiene(cleaned, field_name=field_name)
    return cleaned


def _normalize_format(value: Any) -> str:
    if value is None:
        return "any"
    token = validate_safe_text(str(value), field_name="format", allow_empty=True).lower()
    if token in _WILDCARD_TOKENS:
        return "any"
    return _FORMAT_ALIASES.get(token, token)


def _normalize_unit(value: Any) -> str:
    if value is None:
        return "none"
    token = validate_safe_text(str(value), field_name="unit", allow_empty=True).lower()
    if token in {"any", "*"}:
        return "any"
    return CANONICAL_UNIT_ALIASES.get(token, token)


def _normalize_sensitivity(value: Any, *, default: str = "public", allow_any: bool = False) -> str:
    if value is None:
        return default
    token = validate_safe_text(str(value), field_name="sensitivity", allow_empty=True).lower()
    if not token:
        return default
    if allow_any and token in {"any", "*"}:
        return "any"
    if token not in SENSITIVITY_LEVELS:
        raise ValueError(
            f"INVALID_SENSITIVITY: '{value}' not in {sorted(SENSITIVITY_LEVELS.keys())}."
        )
    return token


def _normalize_ordering(value: Any) -> str:
    if value is None:
        return "unordered"
    token = validate_safe_text(str(value), field_name="ordering", allow_empty=True).lower()
    if not token or token in {"any", "*"}:
        return "unordered"
    if token not in {"ordered", "unordered"}:
        raise ValueError(f"INVALID_ORDERING: '{value}' must be 'ordered' or 'unordered'.")
    return token


def _normalize_semantic_type(value: Any) -> str:
    if value is None:
        return "any"
    token = validate_safe_text(str(value), field_name="semantic_type", allow_empty=True).lower()
    return "any" if token in _WILDCARD_TOKENS else token


def _extract_schema_fields(raw: Mapping[str, Any]) -> Tuple[str, ...]:
    candidates: List[str] = []
    for key in ("schema_fields", "fields", "required"):
        val = raw.get(key)
        if isinstance(val, (list, tuple, set, frozenset)):
            candidates.extend(validate_safe_text(str(x), field_name="schema_fields") for x in val)
    props = raw.get("properties")
    if isinstance(props, Mapping):
        candidates.extend(validate_safe_text(str(k), field_name="schema_fields") for k in props.keys())
    return tuple(sorted(set(candidates)))


def _to_finite_decimal(
    value: Any,
    *,
    field_name: str,
    min_value: Optional[Decimal] = None,
    max_value: Optional[Decimal] = None,
) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"INVALID_METRIC ({field_name}): boolean value not allowed.")
    try:
        dec = value if isinstance(value, Decimal) else Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"INVALID_METRIC ({field_name}): expected finite numeric/Decimal, got {value!r}.") from exc
    if not dec.is_finite():
        raise ValueError(f"INVALID_METRIC ({field_name}): non-finite Decimal not allowed.")
    if min_value is not None and dec < min_value:
        raise ValueError(f"INVALID_METRIC ({field_name}): {dec} < minimum {min_value}.")
    if max_value is not None and dec > max_value:
        raise ValueError(f"INVALID_METRIC ({field_name}): {dec} > maximum {max_value}.")
    return dec


def _decimal_to_json_number(dec: Decimal) -> Union[int, str]:
    normalized = dec.normalize()
    if normalized == normalized.to_integral_value():
        return int(normalized)
    return format(normalized, "f")


def _sanitize_blueprint_id(raw_id: str) -> str:
    cleaned = validate_safe_text(raw_id, field_name="blueprint_id")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise ValueError(f"INVALID_BLUEPRINT_ID: '{cleaned}' contains forbidden path characters.")
    return cleaned


@dataclass(frozen=True)
class TypedPort:
    """Canonical typed port descriptor (`TypedPort/1`) for graph routing and synthesis."""

    format: str = "any"
    unit: str = "none"
    schema_fields: Tuple[str, ...] = ()
    sensitivity: str = "public"
    semantic_type: str = "any"
    ordering: str = "unordered"
    cardinality: str = "one"
    precision: Optional[str] = None
    trust_label: str = "trusted"
    preserves_fields: Optional[bool] = None
    preserves_semantic_type: bool = False
    sensitivity_polymorphic: bool = False
    schema: str = TYPED_PORT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TYPED_PORT_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {TYPED_PORT_SCHEMA}, got '{self.schema}'.")
        object.__setattr__(self, "format", _normalize_format(self.format))
        object.__setattr__(self, "unit", _normalize_unit(self.unit))
        fields = tuple(sorted({validate_safe_text(str(f), field_name="schema_fields") for f in self.schema_fields}))
        object.__setattr__(self, "schema_fields", fields)
        object.__setattr__(
            self,
            "sensitivity",
            _normalize_sensitivity(self.sensitivity, default="public", allow_any=True),
        )
        object.__setattr__(self, "semantic_type", _normalize_semantic_type(self.semantic_type))
        object.__setattr__(self, "ordering", _normalize_ordering(self.ordering))
        card = validate_safe_text(self.cardinality, field_name="cardinality").lower()
        if card not in {"one", "many", "stream"}:
            raise ValueError(f"INVALID_CARDINALITY: '{self.cardinality}' must be one, many, or stream.")
        object.__setattr__(self, "cardinality", card)
        if self.precision is not None:
            object.__setattr__(self, "precision", validate_safe_text(str(self.precision), field_name="precision"))
        trust_lbl = validate_safe_text(self.trust_label, field_name="trust_label").lower()
        if trust_lbl not in {"trusted", "untrusted", "derived"}:
            raise ValueError(f"INVALID_TRUST_LABEL: '{self.trust_label}'.")
        object.__setattr__(self, "trust_label", trust_lbl)
        if self.preserves_fields is not None:
            object.__setattr__(self, "preserves_fields", bool(self.preserves_fields))
        object.__setattr__(self, "preserves_semantic_type", bool(self.preserves_semantic_type))
        object.__setattr__(self, "sensitivity_polymorphic", bool(self.sensitivity_polymorphic))

    def effective_sensitivity(self) -> str:
        return "public" if self.sensitivity == "any" else self.sensitivity

    def state_key(self) -> Tuple[str, str, Tuple[str, ...], str, str, str]:
        return (
            self.format,
            self.unit,
            self.schema_fields,
            self.effective_sensitivity(),
            self.semantic_type,
            self.ordering,
        )

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema": self.schema,
            "format": self.format,
            "unit": self.unit,
            "schema_fields": list(self.schema_fields),
            "sensitivity": self.sensitivity,
            "semantic_type": self.semantic_type,
            "ordering": self.ordering,
            "cardinality": self.cardinality,
            "trust_label": self.trust_label,
        }
        if self.precision is not None:
            payload["precision"] = self.precision
        if self.preserves_fields is not None:
            payload["preserves_fields"] = self.preserves_fields
        if self.preserves_semantic_type:
            payload["preserves_semantic_type"] = True
        if self.sensitivity_polymorphic:
            payload["sensitivity_polymorphic"] = True
        return redact_secrets_in_value(payload)

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_port_contract(cls, port: PortContract) -> "TypedPort":
        fmt = port.encoding if port.encoding.lower() not in {"utf-8", "utf8", "ascii"} else port.schema_ref
        return cls(
            format=fmt,
            unit=port.unit,
            schema_fields=(),
            sensitivity=port.sensitivity,
            semantic_type=port.semantic_type,
            ordering=port.ordering,
            cardinality=port.cardinality,
            precision=port.precision,
            trust_label=port.trust_label,
        )

    @classmethod
    def coerce(
        cls,
        raw: Union["TypedPort", PortContract, Mapping[str, Any], str],
        *,
        semantic_hints: Optional[Mapping[str, Any]] = None,
        direction: str = "input",
    ) -> "TypedPort":
        if isinstance(raw, TypedPort):
            return raw
        if isinstance(raw, PortContract):
            return cls.from_port_contract(raw)
        if isinstance(raw, str):
            return cls(format=raw)
        if not isinstance(raw, Mapping):
            raise ValueError(f"INVALID_TYPED_PORT: expected TypedPort, PortContract, mapping, or str; got {type(raw).__name__}.")

        hints = dict(semantic_hints or {})
        dir_prefix = "input_" if direction == "input" else "output_"

        nested_schema = raw.get("schema") if isinstance(raw.get("schema"), Mapping) else {}
        merged: Dict[str, Any] = {}
        merged.update(nested_schema)
        merged.update(raw)

        raw_fmt = (
            merged.get("format")
            or merged.get("encoding")
            or merged.get("type")
            or hints.get(f"{dir_prefix}format")
            or hints.get("format")
            or merged.get("schema_ref")
        )
        if str(raw_fmt or "").strip().lower() in {"utf-8", "utf8", "ascii"} and merged.get("schema_ref"):
            raw_fmt = merged.get("schema_ref")

        raw_unit = (
            merged.get("unit")
            or merged.get("units")
            or hints.get(f"{dir_prefix}unit")
            or hints.get(f"{dir_prefix}units")
            or hints.get("unit")
            or hints.get("units")
            or "none"
        )
        raw_sens = (
            merged.get("sensitivity")
            or hints.get(f"{dir_prefix}sensitivity")
            or hints.get("sensitivity")
            or "public"
        )
        raw_sem = (
            merged.get("semantic_type")
            or merged.get("kind")
            or merged.get("concept")
            or hints.get(f"{dir_prefix}semantic_type")
            or hints.get("semantic_type")
            or hints.get("kind")
            or "any"
        )
        raw_ord = (
            merged.get("ordering")
            or hints.get(f"{dir_prefix}ordering")
            or hints.get("ordering")
            or "unordered"
        )
        fields = _extract_schema_fields(merged)
        if not fields and isinstance(hints.get(f"{dir_prefix}schema_fields"), (list, tuple, set)):
            fields = tuple(str(x) for x in hints[f"{dir_prefix}schema_fields"])

        preserves_fields = merged.get("preserves_fields")
        if preserves_fields is None:
            preserves_fields = hints.get("preserves_fields")

        return cls(
            format=raw_fmt or "any",
            unit=raw_unit,
            schema_fields=fields,
            sensitivity=raw_sens,
            semantic_type=raw_sem,
            ordering=raw_ord,
            cardinality=str(merged.get("cardinality") or hints.get("cardinality") or "one"),
            precision=merged.get("precision") or hints.get("precision"),
            trust_label=str(merged.get("trust_label") or hints.get("trust_label") or "trusted"),
            preserves_fields=preserves_fields,
            preserves_semantic_type=bool(
                merged.get("preserves_semantic_type") or hints.get("preserves_semantic_type") or False
            ),
            sensitivity_polymorphic=bool(
                merged.get("sensitivity_polymorphic")
                or hints.get("sensitivity_polymorphic")
                or str(raw_sens).strip().lower() in {"any", "*"}
            ),
        )


@dataclass(frozen=True)
class ExclusionRecord:
    """Explicit audit trail recording why an indexed tool cannot serve execution routes."""

    tool_id: str
    trust_status: str
    reasons: Tuple[str, ...]
    capabilities: Tuple[str, ...]
    required_permissions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "trust_status": self.trust_status,
            "reasons": list(self.reasons),
            "capabilities": list(self.capabilities),
            "required_permissions": list(self.required_permissions),
        }


@dataclass(frozen=True)
class _DeclassifierSpec:
    is_declassifier: bool
    transform: str
    source_sensitivity: Optional[str]
    target_sensitivity: Optional[str]
    grant_required: bool = False


@dataclass(frozen=True)
class _IndexedTool:
    spec: ToolSpec
    input_port: TypedPort
    output_port: TypedPort
    effect_contract: EffectContract
    declassifier: _DeclassifierSpec
    latency_us: Decimal
    cost_micro_usd: Decimal
    risk_score: Decimal


@dataclass(frozen=True)
class SynthesisGoal:
    """Demand-driven goal specification for gap detection and blueprint generation."""

    goal_id: str
    source_req: Union[TypedPort, PortContract, Mapping[str, Any], str]
    target_req: Union[TypedPort, PortContract, Mapping[str, Any], str]
    sensitivity_ceiling: Optional[str] = None
    require_idempotent: bool = False
    allow_irreversible: bool = True
    allowed_effects: Dict[str, Any] = field(default_factory=dict)
    permission_budget: Optional[List[str]] = None
    declassification_grants: Optional[Sequence[DeclassificationGrant]] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "goal_id", validate_safe_text(self.goal_id, field_name="goal_id"))
        if self.sensitivity_ceiling is not None:
            object.__setattr__(
                self,
                "sensitivity_ceiling",
                _normalize_sensitivity(self.sensitivity_ceiling),
            )
        object.__setattr__(self, "require_idempotent", bool(self.require_idempotent))
        object.__setattr__(self, "allow_irreversible", bool(self.allow_irreversible))
        object.__setattr__(self, "allowed_effects", _sanitize_dict(self.allowed_effects, field_name="allowed_effects"))
        if self.permission_budget is not None:
            cleaned = sorted({validate_safe_text(str(p), field_name="permission_budget") for p in self.permission_budget})
            object.__setattr__(self, "permission_budget", cleaned)

    @classmethod
    def coerce(cls, raw: Union["SynthesisGoal", CapabilityGap, Mapping[str, Any]], index: int = 0) -> "SynthesisGoal":
        if isinstance(raw, SynthesisGoal):
            return raw
        if isinstance(raw, CapabilityGap):
            src = raw.input_artifacts[0] if raw.input_artifacts else {"format": "any"}
            dst = raw.expected_outputs[0] if raw.expected_outputs else {"format": "any"}
            return cls(
                goal_id=raw.goal_id,
                source_req=src,
                target_req=dst,
                require_idempotent=bool(raw.budget.get("require_idempotent", False)),
                allowed_effects=dict(raw.budget.get("allowed_effects", {})),
            )
        if not isinstance(raw, Mapping):
            raise ValueError(f"INVALID_GOAL: expected SynthesisGoal, CapabilityGap, or mapping; got {type(raw).__name__}.")

        gid = str(raw.get("goal_id") or f"goal-{index:03d}")
        src = raw.get("source_req") or raw.get("source") or raw.get("input")
        if src is None:
            artifacts = raw.get("input_artifacts")
            if isinstance(artifacts, Sequence) and not isinstance(artifacts, (str, bytes)) and artifacts:
                src = artifacts[0]
            else:
                src = {"format": "any"}
        dst = raw.get("target_req") or raw.get("target") or raw.get("output")
        if dst is None:
            outputs = raw.get("expected_outputs")
            if isinstance(outputs, Sequence) and not isinstance(outputs, (str, bytes)) and outputs:
                dst = outputs[0]
            else:
                dst = {"format": "any"}

        allowed_eff = dict(raw.get("allowed_effects") or {})
        req_idemp = bool(
            raw.get("require_idempotent")
            or raw.get("idempotent")
            or allowed_eff.get("idempotent") is True
            or allowed_eff.get("idempotent_required") is True
        )
        allow_irrev = bool(
            raw.get("allow_irreversible", allowed_eff.get("irreversible_allowed", not allowed_eff.get("irreversible") is False))
        )
        if allowed_eff.get("irreversible") is False:
            allow_irrev = False

        raw_perm_budget = raw.get("permission_budget")
        if isinstance(raw_perm_budget, Mapping):
            raw_perm_budget = raw_perm_budget.get("allowed_permissions")

        return cls(
            goal_id=gid,
            source_req=src,
            target_req=dst,
            sensitivity_ceiling=raw.get("sensitivity_ceiling"),
            require_idempotent=req_idemp,
            allow_irreversible=allow_irrev,
            allowed_effects=allowed_eff,
            permission_budget=list(raw_perm_budget) if raw_perm_budget is not None else None,
            declassification_grants=raw.get("declassification_grants"),
        )


@dataclass
class SynthesisBlueprint:
    """Actionable deterministic synthesis specification (`SynthesisBlueprint/1`)."""

    blueprint_id: str
    source_type: Union[Dict[str, Any], str]
    target_type: Union[Dict[str, Any], str]
    required_units: List[str] = field(default_factory=list)
    sensitivity_ceiling: str = "public"
    allowed_effects: Dict[str, Any] = field(default_factory=dict)
    permission_budget: Dict[str, Any] = field(default_factory=dict)
    missing_hop_description: str = ""
    candidate_templates: List[Dict[str, Any]] = field(default_factory=list)
    provenance_sha256: str = ""
    gap_kind: str = GapKind.MISSING_PRIMITIVE_KERNEL.value
    goal_id: Optional[str] = None
    declassification_required: bool = False
    blocked_tool_reasons: Dict[str, List[str]] = field(default_factory=dict)
    schema: str = SYNTHESIS_BLUEPRINT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SYNTHESIS_BLUEPRINT_SCHEMA:
            raise ValueError(
                f"INVALID_SCHEMA: expected {SYNTHESIS_BLUEPRINT_SCHEMA}, got '{self.schema}'."
            )
        self.blueprint_id = _sanitize_blueprint_id(self.blueprint_id)

        if isinstance(self.source_type, TypedPort):
            self.source_type = self.source_type.to_dict()
        elif isinstance(self.source_type, PortContract):
            self.source_type = TypedPort.from_port_contract(self.source_type).to_dict()
        elif isinstance(self.source_type, Mapping):
            self.source_type = _sanitize_dict(self.source_type, field_name="source_type")
        else:
            self.source_type = validate_safe_text(str(self.source_type), field_name="source_type")

        if isinstance(self.target_type, TypedPort):
            self.target_type = self.target_type.to_dict()
        elif isinstance(self.target_type, PortContract):
            self.target_type = TypedPort.from_port_contract(self.target_type).to_dict()
        elif isinstance(self.target_type, Mapping):
            self.target_type = _sanitize_dict(self.target_type, field_name="target_type")
        else:
            self.target_type = validate_safe_text(str(self.target_type), field_name="target_type")

        if isinstance(self.required_units, str):
            raw_units = [self.required_units] if self.required_units.strip() else []
        elif isinstance(self.required_units, (list, tuple, set)):
            raw_units = [str(u) for u in self.required_units]
        else:
            raise ValueError("INVALID_REQUIRED_UNITS: expected string or sequence of unit strings.")
        self.required_units = list(
            dict.fromkeys(_normalize_unit(u) for u in raw_units if _normalize_unit(u) != "none")
        )

        self.sensitivity_ceiling = _normalize_sensitivity(self.sensitivity_ceiling, default="public")

        if isinstance(self.allowed_effects, EffectContract):
            eff_d = self.allowed_effects.to_dict()
            eff_d.pop("schema", None)
            self.allowed_effects = eff_d
        elif isinstance(self.allowed_effects, Mapping):
            self.allowed_effects = _sanitize_dict(self.allowed_effects, field_name="allowed_effects")
        elif isinstance(self.allowed_effects, (list, tuple, set)):
            self.allowed_effects = {
                "allowed_side_effects": sorted(
                    validate_safe_text(str(s), field_name="allowed_effects") for s in self.allowed_effects
                )
            }
        else:
            raise ValueError("INVALID_ALLOWED_EFFECTS: expected EffectContract, mapping, or sequence.")

        if isinstance(self.permission_budget, SecurityContext):
            self.permission_budget = {
                "allowed_permissions": list(self.permission_budget.allowed_permissions),
                "network_allowed": self.permission_budget.network_allowed,
                "allow_untrusted_native": self.permission_budget.allow_untrusted_native,
                "profile": self.permission_budget.profile.value,
                "policy_hash": self.permission_budget.policy_hash,
            }
        elif isinstance(self.permission_budget, Mapping):
            self.permission_budget = _sanitize_dict(self.permission_budget, field_name="permission_budget")
        elif isinstance(self.permission_budget, (list, tuple, set)):
            self.permission_budget = {
                "allowed_permissions": sorted(
                    validate_safe_text(str(p), field_name="permission_budget") for p in self.permission_budget
                ),
                "network_allowed": False,
                "allow_untrusted_native": False,
            }
        else:
            raise ValueError("INVALID_PERMISSION_BUDGET: expected SecurityContext, mapping, or sequence.")

        self.missing_hop_description = redact_secrets_in_text(
            validate_safe_text(self.missing_hop_description, field_name="missing_hop_description")
        )
        _validate_structure_hygiene(self.missing_hop_description, field_name="missing_hop_description")

        cleaned_templates: List[Dict[str, Any]] = []
        for idx, tmpl in enumerate(self.candidate_templates or ()):
            cleaned_tmpl = _sanitize_dict(tmpl, field_name=f"candidate_templates[{idx}]")
            if "template_id" in cleaned_tmpl:
                cleaned_tmpl["template_id"] = validate_tool_id(str(cleaned_tmpl["template_id"]))
            if not cleaned_tmpl.get("provenance_sha256"):
                basis_copy = dict(cleaned_tmpl)
                basis_copy.pop("provenance_sha256", None)
                cleaned_tmpl["provenance_sha256"] = sha256_digest(basis_copy)
            else:
                cleaned_tmpl["provenance_sha256"] = normalize_sha256(
                    cleaned_tmpl["provenance_sha256"], field_name="template.provenance_sha256"
                )
            cleaned_templates.append(cleaned_tmpl)
        self.candidate_templates = cleaned_templates

        self.gap_kind = GapKind(validate_safe_text(self.gap_kind, field_name="gap_kind").upper()).value
        if self.goal_id is not None:
            self.goal_id = validate_safe_text(self.goal_id, field_name="goal_id")
        self.declassification_required = bool(self.declassification_required)

        norm_blocked: Dict[str, List[str]] = {}
        for tid, reasons in sorted((self.blocked_tool_reasons or {}).items()):
            safe_tid = validate_tool_id(str(tid))
            norm_blocked[safe_tid] = [
                redact_secrets_in_text(validate_safe_text(str(r), field_name="blocked_reason"))
                for r in reasons
            ]
        self.blocked_tool_reasons = norm_blocked

        computed = self.compute_provenance_sha256()
        if self.provenance_sha256:
            provided = normalize_sha256(self.provenance_sha256, field_name="provenance_sha256")
            if not hmac.compare_digest(provided, computed):
                raise ValueError(
                    "BLUEPRINT_PROVENANCE_MISMATCH: provenance_sha256 does not match canonical SynthesisBlueprint."
                )
            self.provenance_sha256 = provided
        else:
            self.provenance_sha256 = computed

    def _canonical_hash_basis(self) -> Dict[str, Any]:
        basis: Dict[str, Any] = {
            "schema": self.schema,
            "blueprint_id": self.blueprint_id,
            "gap_kind": self.gap_kind,
            "source_type": self.source_type,
            "target_type": self.target_type,
            "required_units": list(self.required_units),
            "sensitivity_ceiling": self.sensitivity_ceiling,
            "allowed_effects": dict(self.allowed_effects),
            "permission_budget": dict(self.permission_budget),
            "missing_hop_description": self.missing_hop_description,
            "candidate_templates": list(self.candidate_templates),
            "declassification_required": self.declassification_required,
            "blocked_tool_reasons": dict(self.blocked_tool_reasons),
        }
        if self.goal_id is not None:
            basis["goal_id"] = self.goal_id
        return basis

    def compute_provenance_sha256(self) -> str:
        return sha256_digest(self._canonical_hash_basis())

    def to_dict(self) -> Dict[str, Any]:
        payload = self._canonical_hash_basis()
        payload["provenance_sha256"] = self.provenance_sha256
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"SynthesisBlueprint:{self.blueprint_id}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SynthesisBlueprint":
        if isinstance(data, SynthesisBlueprint):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_SYNTHESIS_BLUEPRINT: expected mapping.")
        return cls(
            blueprint_id=data["blueprint_id"],
            source_type=data["source_type"],
            target_type=data["target_type"],
            required_units=list(data.get("required_units", [])),
            sensitivity_ceiling=data.get("sensitivity_ceiling", "public"),
            allowed_effects=dict(data.get("allowed_effects", {})),
            permission_budget=dict(data.get("permission_budget", {})),
            missing_hop_description=data["missing_hop_description"],
            candidate_templates=list(data.get("candidate_templates", [])),
            provenance_sha256=data.get("provenance_sha256", ""),
            gap_kind=data.get("gap_kind", GapKind.MISSING_PRIMITIVE_KERNEL.value),
            goal_id=data.get("goal_id"),
            declassification_required=bool(data.get("declassification_required", False)),
            blocked_tool_reasons=dict(data.get("blocked_tool_reasons", {})),
            schema=data.get("schema", SYNTHESIS_BLUEPRINT_SCHEMA),
        )


@dataclass(frozen=True)
class ParetoCandidate:
    """Exact integer / `Decimal` multi-objective synthesis candidate."""

    candidate_id: str
    latency_us: Decimal
    accuracy_bps: Decimal
    risk_score: Decimal
    cost_micro_usd: Decimal
    provenance_sha256: str = ""
    blueprint_id: Optional[str] = None
    kind: str = "adapter"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", validate_tool_id(self.candidate_id))
        object.__setattr__(
            self,
            "latency_us",
            _to_finite_decimal(self.latency_us, field_name="latency_us", min_value=_DECIMAL_ZERO),
        )
        object.__setattr__(
            self,
            "accuracy_bps",
            _to_finite_decimal(
                self.accuracy_bps,
                field_name="accuracy_bps",
                min_value=_DECIMAL_ZERO,
                max_value=_MAX_ACCURACY_BPS,
            ),
        )
        object.__setattr__(
            self,
            "risk_score",
            _to_finite_decimal(self.risk_score, field_name="risk_score", min_value=_DECIMAL_ZERO),
        )
        object.__setattr__(
            self,
            "cost_micro_usd",
            _to_finite_decimal(self.cost_micro_usd, field_name="cost_micro_usd", min_value=_DECIMAL_ZERO),
        )
        object.__setattr__(self, "kind", validate_safe_text(self.kind, field_name="kind"))
        if self.blueprint_id is not None:
            object.__setattr__(self, "blueprint_id", _sanitize_blueprint_id(self.blueprint_id))
        cleaned_meta = _sanitize_dict(self.metadata, field_name="metadata")
        object.__setattr__(self, "metadata", cleaned_meta)

        if self.provenance_sha256:
            object.__setattr__(
                self,
                "provenance_sha256",
                normalize_sha256(self.provenance_sha256, field_name="provenance_sha256"),
            )
        else:
            basis = {
                "candidate_id": self.candidate_id,
                "latency_us": _decimal_to_json_number(self.latency_us),
                "accuracy_bps": _decimal_to_json_number(self.accuracy_bps),
                "risk_score": _decimal_to_json_number(self.risk_score),
                "cost_micro_usd": _decimal_to_json_number(self.cost_micro_usd),
                "kind": self.kind,
                "blueprint_id": self.blueprint_id,
                "metadata": cleaned_meta,
            }
            object.__setattr__(self, "provenance_sha256", sha256_digest(basis))

    def objective_vector(self) -> Tuple[Decimal, Decimal, Decimal, Decimal]:
        """Return exact minimization vector `(latency_us, -accuracy_bps, risk_score, cost_micro_usd)`."""
        return (self.latency_us, -self.accuracy_bps, self.risk_score, self.cost_micro_usd)

    def dominates(self, other: "ParetoCandidate") -> bool:
        """Return True iff `self` is <= `other` on all objectives and < on at least one."""
        a = self.objective_vector()
        b = other.objective_vector()
        no_worse = all(x <= y for x, y in zip(a, b))
        strictly_better = any(x < y for x, y in zip(a, b))
        return no_worse and strictly_better

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "candidate_id": self.candidate_id,
            "latency_us": _decimal_to_json_number(self.latency_us),
            "accuracy_bps": _decimal_to_json_number(self.accuracy_bps),
            "risk_score": _decimal_to_json_number(self.risk_score),
            "cost_micro_usd": _decimal_to_json_number(self.cost_micro_usd),
            "provenance_sha256": self.provenance_sha256,
            "kind": self.kind,
            "metadata": dict(self.metadata),
        }
        if self.blueprint_id is not None:
            payload["blueprint_id"] = self.blueprint_id
        return redact_secrets_in_value(payload)

    @classmethod
    def coerce(
        cls,
        raw: Union["ParetoCandidate", Mapping[str, Any]],
        *,
        blueprint_id: Optional[str] = None,
    ) -> "ParetoCandidate":
        if isinstance(raw, ParetoCandidate):
            return raw
        if not isinstance(raw, Mapping):
            raise ValueError(f"INVALID_PARETO_CANDIDATE: expected ParetoCandidate or mapping, got {type(raw).__name__}.")
        metrics = raw.get("metrics") if isinstance(raw.get("metrics"), Mapping) else {}
        cid = raw.get("candidate_id") or raw.get("template_id") or raw.get("tool_id")
        if not cid:
            raise ValueError("INVALID_PARETO_CANDIDATE: missing candidate_id/template_id.")

        def _pick(key: str) -> Any:
            if key in raw:
                return raw[key]
            if key in metrics:
                return metrics[key]
            raise ValueError(f"INVALID_PARETO_CANDIDATE: missing required metric '{key}' on '{cid}'.")

        known_keys = {
            "candidate_id",
            "template_id",
            "tool_id",
            "latency_us",
            "accuracy_bps",
            "risk_score",
            "cost_micro_usd",
            "provenance_sha256",
            "blueprint_id",
            "kind",
            "metadata",
            "metrics",
        }
        extra_meta = {str(k): v for k, v in raw.items() if k not in known_keys}
        meta = dict(raw.get("metadata") or {})
        meta.update(extra_meta)

        return cls(
            candidate_id=str(cid),
            latency_us=_pick("latency_us"),
            accuracy_bps=_pick("accuracy_bps"),
            risk_score=_pick("risk_score"),
            cost_micro_usd=_pick("cost_micro_usd"),
            provenance_sha256=str(raw.get("provenance_sha256") or ""),
            blueprint_id=raw.get("blueprint_id") or blueprint_id,
            kind=str(raw.get("kind") or "adapter"),
            metadata=meta,
        )


@dataclass(frozen=True)
class RankedCandidateEntry:
    """Single candidate annotated with exact Pareto front rank and dominance provenance."""

    candidate: ParetoCandidate
    pareto_rank: int
    is_pareto_optimal: bool
    dominated_by: Tuple[str, ...] = ()
    dominates: Tuple[str, ...] = ()
    exact_weighted_score: Optional[Decimal] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "candidate": self.candidate.to_dict(),
            "pareto_rank": self.pareto_rank,
            "is_pareto_optimal": self.is_pareto_optimal,
            "dominated_by": list(self.dominated_by),
            "dominates": list(self.dominates),
        }
        if self.exact_weighted_score is not None:
            payload["exact_weighted_score"] = _decimal_to_json_number(self.exact_weighted_score)
        return payload


@dataclass(frozen=True)
class RankedSynthesisPlan:
    """Deterministic Pareto-ranked synthesis candidate plan (`RankedSynthesisPlan/1`)."""

    plan_id: str
    ranked_candidates: Tuple[RankedCandidateEntry, ...]
    pareto_frontier: Tuple[RankedCandidateEntry, ...]
    dominated_candidates: Tuple[RankedCandidateEntry, ...]
    fronts: Tuple[Tuple[RankedCandidateEntry, ...], ...]
    selected_candidate: Optional[RankedCandidateEntry] = None
    blueprint_id: Optional[str] = None
    provenance_sha256: str = ""
    schema: str = RANKED_SYNTHESIS_PLAN_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != RANKED_SYNTHESIS_PLAN_SCHEMA:
            raise ValueError(
                f"INVALID_SCHEMA: expected {RANKED_SYNTHESIS_PLAN_SCHEMA}, got '{self.schema}'."
            )
        object.__setattr__(self, "plan_id", _sanitize_blueprint_id(self.plan_id))
        if self.blueprint_id is not None:
            object.__setattr__(self, "blueprint_id", _sanitize_blueprint_id(self.blueprint_id))
        computed = self.compute_provenance_sha256()
        if self.provenance_sha256:
            provided = normalize_sha256(self.provenance_sha256, field_name="provenance_sha256")
            if not hmac.compare_digest(provided, computed):
                raise ValueError("PLAN_PROVENANCE_MISMATCH: provenance_sha256 mismatch.")
            object.__setattr__(self, "provenance_sha256", provided)
        else:
            object.__setattr__(self, "provenance_sha256", computed)

    def _canonical_hash_basis(self) -> Dict[str, Any]:
        basis: Dict[str, Any] = {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "ranked_candidates": [entry.to_dict() for entry in self.ranked_candidates],
            "pareto_frontier": [entry.candidate.candidate_id for entry in self.pareto_frontier],
            "dominated_candidates": [entry.candidate.candidate_id for entry in self.dominated_candidates],
            "selected_candidate_id": (
                self.selected_candidate.candidate.candidate_id if self.selected_candidate else None
            ),
        }
        if self.blueprint_id is not None:
            basis["blueprint_id"] = self.blueprint_id
        return basis

    def compute_provenance_sha256(self) -> str:
        return sha256_digest(self._canonical_hash_basis())

    def to_dict(self) -> Dict[str, Any]:
        payload = self._canonical_hash_basis()
        payload["fronts"] = [[entry.candidate.candidate_id for entry in front] for front in self.fronts]
        payload["provenance_sha256"] = self.provenance_sha256
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"RankedSynthesisPlan:{self.plan_id}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RankedSynthesisPlan":
        if isinstance(data, RankedSynthesisPlan):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_RANKED_SYNTHESIS_PLAN: expected mapping.")
        entries: List[RankedCandidateEntry] = []
        for raw_entry in data.get("ranked_candidates", ()):
            if not isinstance(raw_entry, Mapping):
                raise ValueError("INVALID_RANKED_ENTRY: expected mapping.")
            cand = ParetoCandidate.coerce(raw_entry["candidate"])
            raw_score = raw_entry.get("exact_weighted_score")
            w_score = (
                _to_finite_decimal(raw_score, field_name="exact_weighted_score")
                if raw_score is not None
                else None
            )
            entries.append(
                RankedCandidateEntry(
                    candidate=cand,
                    pareto_rank=int(raw_entry["pareto_rank"]),
                    is_pareto_optimal=bool(raw_entry["is_pareto_optimal"]),
                    dominated_by=tuple(str(x) for x in raw_entry.get("dominated_by", ())),
                    dominates=tuple(str(x) for x in raw_entry.get("dominates", ())),
                    exact_weighted_score=w_score,
                )
            )
        by_id = {e.candidate.candidate_id: e for e in entries}
        frontier = tuple(by_id[cid] for cid in data.get("pareto_frontier", ()) if cid in by_id)
        dominated = tuple(by_id[cid] for cid in data.get("dominated_candidates", ()) if cid in by_id)
        fronts = tuple(
            tuple(by_id[cid] for cid in grp if cid in by_id)
            for grp in data.get("fronts", ())
        )
        sel_id = data.get("selected_candidate_id")
        selected = by_id.get(sel_id) if sel_id else (frontier[0] if frontier else None)
        return cls(
            plan_id=str(data["plan_id"]),
            ranked_candidates=tuple(entries),
            pareto_frontier=frontier,
            dominated_candidates=dominated,
            fronts=fronts,
            selected_candidate=selected,
            blueprint_id=data.get("blueprint_id"),
            provenance_sha256=str(data.get("provenance_sha256", "")),
            schema=str(data.get("schema", RANKED_SYNTHESIS_PLAN_SCHEMA)),
        )


def _compute_weighted_score(
    cand: ParetoCandidate,
    objective_weights: Optional[Mapping[str, Union[int, str, Decimal]]],
) -> Optional[Decimal]:
    if not objective_weights:
        return None
    w_lat = _to_finite_decimal(objective_weights.get("latency_us", 0), field_name="w_latency_us", min_value=_DECIMAL_ZERO)
    w_acc = _to_finite_decimal(objective_weights.get("accuracy_bps", 0), field_name="w_accuracy_bps", min_value=_DECIMAL_ZERO)
    w_risk = _to_finite_decimal(objective_weights.get("risk_score", 0), field_name="w_risk_score", min_value=_DECIMAL_ZERO)
    w_cost = _to_finite_decimal(objective_weights.get("cost_micro_usd", 0), field_name="w_cost_micro_usd", min_value=_DECIMAL_ZERO)
    return (
        w_lat * cand.latency_us
        - w_acc * cand.accuracy_bps
        + w_risk * cand.risk_score
        + w_cost * cand.cost_micro_usd
    )


def rank_pareto_candidates(
    candidates: Sequence[Union[ParetoCandidate, Mapping[str, Any]]],
    *,
    plan_id: str = "pareto-plan",
    blueprint_id: Optional[str] = None,
    objective_weights: Optional[Mapping[str, Union[int, str, Decimal]]] = None,
) -> RankedSynthesisPlan:
    """Perform exact non-dominated Pareto front sorting with deterministic `provenance_sha256` tie-breaking."""
    coerced = [ParetoCandidate.coerce(item, blueprint_id=blueprint_id) for item in (candidates or ())]
    if not coerced:
        return RankedSynthesisPlan(
            plan_id=plan_id,
            ranked_candidates=(),
            pareto_frontier=(),
            dominated_candidates=(),
            fronts=(),
            selected_candidate=None,
            blueprint_id=blueprint_id,
        )

    seen_ids: Set[str] = set()
    for cand in coerced:
        if cand.candidate_id in seen_ids:
            raise ValueError(f"DUPLICATE_CANDIDATE_ID: '{cand.candidate_id}' appears multiple times.")
        seen_ids.add(cand.candidate_id)

    n = len(coerced)
    dominates_map: Dict[str, List[str]] = {c.candidate_id: [] for c in coerced}
    dominated_by_map: Dict[str, List[str]] = {c.candidate_id: [] for c in coerced}
    dom_counts: Dict[str, int] = {c.candidate_id: 0 for c in coerced}
    by_id: Dict[str, ParetoCandidate] = {c.candidate_id: c for c in coerced}

    for i in range(n):
        ci = coerced[i]
        for j in range(n):
            if i == j:
                continue
            cj = coerced[j]
            if ci.dominates(cj):
                dominates_map[ci.candidate_id].append(cj.candidate_id)
                dominated_by_map[cj.candidate_id].append(ci.candidate_id)
                dom_counts[cj.candidate_id] += 1

    def _sort_key(cid: str) -> Tuple[Any, ...]:
        cand = by_id[cid]
        w_score = _compute_weighted_score(cand, objective_weights)
        if w_score is not None:
            return (w_score, cand.provenance_sha256, cand.candidate_id)
        return (
            cand.latency_us,
            -cand.accuracy_bps,
            cand.risk_score,
            cand.cost_micro_usd,
            cand.provenance_sha256,
            cand.candidate_id,
        )

    remaining_counts = dict(dom_counts)
    current_front_ids = sorted([cid for cid, cnt in remaining_counts.items() if cnt == 0], key=_sort_key)
    fronts: List[Tuple[RankedCandidateEntry, ...]] = []
    all_entries: List[RankedCandidateEntry] = []
    rank = 0

    while current_front_ids:
        front_entries: List[RankedCandidateEntry] = []
        next_candidates: List[str] = []
        for cid in current_front_ids:
            cand = by_id[cid]
            entry = RankedCandidateEntry(
                candidate=cand,
                pareto_rank=rank,
                is_pareto_optimal=(rank == 0),
                dominated_by=tuple(sorted(dominated_by_map[cid])),
                dominates=tuple(sorted(dominates_map[cid])),
                exact_weighted_score=_compute_weighted_score(cand, objective_weights),
            )
            front_entries.append(entry)
            all_entries.append(entry)
            for dep_id in dominates_map[cid]:
                remaining_counts[dep_id] -= 1
                if remaining_counts[dep_id] == 0:
                    next_candidates.append(dep_id)
        fronts.append(tuple(front_entries))
        current_front_ids = sorted(next_candidates, key=_sort_key)
        rank += 1

    frontier = fronts[0] if fronts else ()
    dominated = tuple(e for e in all_entries if e.pareto_rank > 0)
    selected = frontier[0] if frontier else None
    return RankedSynthesisPlan(
        plan_id=plan_id,
        ranked_candidates=tuple(all_entries),
        pareto_frontier=frontier,
        dominated_candidates=dominated,
        fronts=tuple(fronts),
        selected_candidate=selected,
        blueprint_id=blueprint_id,
    )


@dataclass(frozen=True)
class SafePathResult:
    """Deterministic multi-hop typed execution path verdict from `TypedCapabilityGraph`."""

    found: bool
    tools: Tuple[ToolSpec, ...] = ()
    tool_ids: Tuple[str, ...] = ()
    hop_count: int = 0
    source_port: Optional[TypedPort] = None
    target_port: Optional[TypedPort] = None
    final_port: Optional[TypedPort] = None
    effective_sensitivity: str = "public"
    declassified_by: Tuple[str, ...] = ()
    permission_union: Tuple[str, ...] = ()
    effects_summary: Dict[str, Any] = field(default_factory=dict)
    total_latency_us: Decimal = _DECIMAL_ZERO
    total_cost_micro_usd: Decimal = _DECIMAL_ZERO
    blocked_reasons: Tuple[str, ...] = ()
    rejected_tools: Dict[str, List[str]] = field(default_factory=dict)
    path_digest: str = ""

    def __post_init__(self) -> None:
        if not self.path_digest:
            object.__setattr__(self, "path_digest", sha256_digest(self._canonical_basis()))

    def _canonical_basis(self) -> Dict[str, Any]:
        return {
            "found": self.found,
            "tool_ids": list(self.tool_ids),
            "hop_count": self.hop_count,
            "source_port": self.source_port.to_dict() if self.source_port else None,
            "target_port": self.target_port.to_dict() if self.target_port else None,
            "final_port": self.final_port.to_dict() if self.final_port else None,
            "effective_sensitivity": self.effective_sensitivity,
            "declassified_by": list(self.declassified_by),
            "permission_union": list(self.permission_union),
            "effects_summary": dict(self.effects_summary),
            "total_latency_us": _decimal_to_json_number(self.total_latency_us),
            "total_cost_micro_usd": _decimal_to_json_number(self.total_cost_micro_usd),
            "blocked_reasons": list(self.blocked_reasons),
            "rejected_tools": {k: list(v) for k, v in sorted(self.rejected_tools.items())},
        }

    def to_dict(self) -> Dict[str, Any]:
        payload = self._canonical_basis()
        payload["path_digest"] = self.path_digest
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context="SafePathResult")
        return serialized


def _extract_tool_effect(spec: ToolSpec) -> EffectContract:
    sem = dict(spec.semantic_contract or {})
    req = dict(spec.runtime_requirements or {})
    raw_eff = req.get("effect_contract") or sem.get("effect_contract")
    base = EffectContract.from_dict(raw_eff) if raw_eff is not None else EffectContract()
    side_effs = {str(s).strip().lower() for s in (spec.side_effects or ()) if str(s).strip()}

    read_scopes = list(base.read_scopes)
    write_scopes = list(base.write_scopes)
    network_scopes = list(base.network_scopes)
    exec_perms = sorted(set(base.exec_permissions) | set(spec.required_permissions or ()))
    for tok in sorted(side_effs):
        if tok in _NETWORK_TOKENS or tok.startswith("network."):
            network_scopes.append(tok)
    if req.get("network") is True and not network_scopes:
        network_scopes.append("network:outbound")

    irreversible = bool(
        base.irreversible
        or req.get("irreversible") is True
        or sem.get("irreversible") is True
        or ("irreversible" in side_effs)
    )
    idempotent = bool(
        base.idempotent
        and req.get("idempotent") is not False
        and sem.get("idempotent") is not False
        and ("non_idempotent" not in side_effs)
        and not irreversible
    )
    return EffectContract(
        read_scopes=read_scopes,
        write_scopes=write_scopes,
        network_scopes=network_scopes,
        exec_permissions=exec_perms,
        irreversible=irreversible,
        idempotent=idempotent,
        resource_requirements=dict(base.resource_requirements),
    )


def _extract_declassifier_info(spec: ToolSpec, in_port: TypedPort, out_port: TypedPort) -> _DeclassifierSpec:
    sem = dict(spec.semantic_contract or {})
    raw_decl = sem.get("declassifies") if isinstance(sem.get("declassifies"), Mapping) else {}
    is_decl = bool(sem.get("declassifier") is True or raw_decl)
    xform = str(
        sem.get("declassify_transform")
        or raw_decl.get("transform")
        or sem.get("transform")
        or ""
    ).strip().lower()
    src_s = raw_decl.get("from") or raw_decl.get("source_sensitivity") or in_port.sensitivity
    dst_s = raw_decl.get("to") or raw_decl.get("target_sensitivity") or out_port.sensitivity
    norm_src = _normalize_sensitivity(src_s, allow_any=True) if src_s else None
    norm_dst = _normalize_sensitivity(dst_s, allow_any=True) if dst_s else None
    grant_req = bool(sem.get("requires_declassification_grant") is True or raw_decl.get("requires_grant") is True)
    return _DeclassifierSpec(
        is_declassifier=(is_decl and xform in DECLASSIFY_TRANSFORMS),
        transform=xform,
        source_sensitivity=norm_src,
        target_sensitivity=norm_dst,
        grant_required=grant_req,
    )


def _extract_tool_metrics(spec: ToolSpec) -> Tuple[Decimal, Decimal, Decimal]:
    req = dict(spec.runtime_requirements or {})
    sem = dict(spec.semantic_contract or {})
    raw_lat_us = req.get("latency_us") or sem.get("latency_us")
    if raw_lat_us is not None:
        latency_us = _to_finite_decimal(raw_lat_us, field_name="latency_us", min_value=_DECIMAL_ZERO)
    else:
        latency_us = _to_finite_decimal(spec.latency_estimate_ms, field_name="latency_estimate_ms", min_value=_DECIMAL_ZERO) * _DECIMAL_THOUSAND

    raw_cost = req.get("cost_micro_usd") or sem.get("cost_micro_usd")
    if raw_cost is not None:
        cost_micro_usd = _to_finite_decimal(raw_cost, field_name="cost_micro_usd", min_value=_DECIMAL_ZERO)
    else:
        cost_micro_usd = Decimal(int(spec.api_token_estimate)) * Decimal("10")

    raw_risk = req.get("risk_score") or sem.get("risk_score")
    if raw_risk is not None:
        risk_score = _to_finite_decimal(raw_risk, field_name="risk_score", min_value=_DECIMAL_ZERO)
    else:
        risk_score = Decimal(len(spec.required_permissions)) + Decimal(len([s for s in spec.side_effects if s != "none"]))
    return latency_us, cost_micro_usd, risk_score


def _index_tool_ports(spec: ToolSpec) -> Tuple[TypedPort, TypedPort]:
    sem = dict(spec.semantic_contract or {})
    req = dict(spec.runtime_requirements or {})
    raw_in = sem.get("input_port") or req.get("input_port") or spec.input_schema
    raw_out = sem.get("output_port") or req.get("output_port") or spec.output_schema
    in_port = TypedPort.coerce(raw_in, semantic_hints=sem, direction="input")
    out_port = TypedPort.coerce(raw_out, semantic_hints=sem, direction="output")
    return in_port, out_port


def _check_policy_and_effects(
    node: _IndexedTool,
    security_context: SecurityContext,
    *,
    require_idempotent: bool,
    allow_irreversible: bool,
    permission_budget: Optional[Sequence[str]] = None,
    allowed_effects: Optional[Mapping[str, Any]] = None,
) -> List[str]:
    reasons = list(tool_violates_security_context(node.spec, security_context))

    allowed_perms = set(security_context.allowed_permissions)
    if permission_budget is not None:
        allowed_perms = allowed_perms & set(permission_budget)

    missing_perms = sorted((set(node.spec.required_permissions) | set(node.effect_contract.exec_permissions)) - allowed_perms)
    if missing_perms:
        code = f"OVER_PRIVILEGED_PERMISSIONS:{','.join(missing_perms)}"
        if code not in reasons:
            reasons.append(code)

    if not security_context.network_allowed and node.effect_contract.network_scopes:
        if "NETWORK_DISALLOWED_BY_POLICY" not in reasons:
            reasons.append("NETWORK_DISALLOWED_BY_POLICY")

    if require_idempotent and not node.effect_contract.idempotent:
        reasons.append("NON_IDEMPOTENT_EFFECT_BLOCKED")
    if not allow_irreversible and node.effect_contract.irreversible:
        reasons.append("IRREVERSIBLE_EFFECT_BLOCKED")

    if allowed_effects:
        if allowed_effects.get("idempotent") is True and not node.effect_contract.idempotent:
            if "NON_IDEMPOTENT_EFFECT_BLOCKED" not in reasons:
                reasons.append("NON_IDEMPOTENT_EFFECT_BLOCKED")
        if allowed_effects.get("irreversible") is False and node.effect_contract.irreversible:
            if "IRREVERSIBLE_EFFECT_BLOCKED" not in reasons:
                reasons.append("IRREVERSIBLE_EFFECT_BLOCKED")
        allowed_se = allowed_effects.get("allowed_side_effects")
        if isinstance(allowed_se, (list, tuple, set)):
            allowed_se_set = {str(s).strip().lower() for s in allowed_se}
            bad_se = sorted(
                s for s in node.spec.side_effects
                if s.strip().lower() not in {"", "none"} and s.strip().lower() not in allowed_se_set
            )
            if bad_se:
                reasons.append(f"DISALLOWED_SIDE_EFFECTS:{','.join(bad_se)}")

    return reasons


def _check_port_transition(
    state: TypedPort,
    dst: TypedPort,
    *,
    is_target_sink: bool = False,
) -> List[str]:
    reasons: List[str] = []
    if dst.format != "any" and state.format != dst.format:
        reasons.append(f"FORMAT_MISMATCH:{state.format}->{dst.format}")
    if dst.semantic_type != "any" and state.semantic_type != dst.semantic_type:
        reasons.append(f"SEMANTIC_TYPE_MISMATCH:{state.semantic_type}->{dst.semantic_type}")
    if dst.unit != "any" and state.unit != dst.unit:
        reasons.append(f"UNIT_MISMATCH:{state.unit}->{dst.unit}")
    if dst.ordering == "ordered" and state.ordering == "unordered":
        reasons.append("ORDERING_MISMATCH:unordered->ordered")
    missing_fields = sorted(set(dst.schema_fields) - set(state.schema_fields))
    if missing_fields:
        reasons.append(f"SCHEMA_FIELDS_MISSING:{','.join(missing_fields)}")

    src_rank = SENSITIVITY_LEVELS[state.effective_sensitivity()]
    dst_rank = SENSITIVITY_LEVELS[dst.effective_sensitivity()] if dst.sensitivity != "any" else 2
    if is_target_sink or dst.sensitivity != "any":
        if src_rank > dst_rank:
            reasons.append(
                f"SENSITIVITY_FLOW_VIOLATION:{state.effective_sensitivity()}->{dst.effective_sensitivity()}"
            )
    return reasons


def _advance_port_with_tool(
    state: TypedPort,
    node: _IndexedTool,
    *,
    declassification_grants: Optional[Sequence[DeclassificationGrant]] = None,
) -> Tuple[Optional[TypedPort], List[str], bool]:
    """Validate entering `node` from `state` and compute output `TypedPort`."""
    in_reasons = _check_port_transition(state, node.input_port, is_target_sink=False)
    if in_reasons:
        return None, in_reasons, False

    cur_sens = state.effective_sensitivity()
    cur_rank = SENSITIVITY_LEVELS[cur_sens]
    declared_out_sens = node.output_port.effective_sensitivity()
    out_rank = SENSITIVITY_LEVELS[declared_out_sens]

    used_declassifier = False
    if node.declassifier.is_declassifier and out_rank < cur_rank:
        decl = node.declassifier
        if decl.source_sensitivity and decl.source_sensitivity != "any":
            if cur_rank > SENSITIVITY_LEVELS[decl.source_sensitivity]:
                return None, ["DECLASSIFIER_SOURCE_CEILING_EXCEEDED"], False
        if decl.target_sensitivity and decl.target_sensitivity != "any":
            if out_rank < SENSITIVITY_LEVELS[decl.target_sensitivity]:
                return None, ["DECLASSIFIER_TARGET_FLOOR_VIOLATED"], False
        if declassification_grants is not None or decl.grant_required:
            grants = list(declassification_grants or ())
            if not any(
                g.covers(cur_sens, declared_out_sens) and g.transform == decl.transform
                for g in grants
            ):
                return None, ["MISSING_AUTHORIZED_DECLASSIFICATION_GRANT"], False
        new_sens = declared_out_sens
        used_declassifier = True
    elif node.output_port.sensitivity == "any" or node.output_port.sensitivity_polymorphic:
        new_sens = cur_sens
    elif out_rank < cur_rank:
        return (
            None,
            [f"UNATTESTED_SENSITIVITY_DOWNGRADE:{cur_sens}->{declared_out_sens}"],
            False,
        )
    else:
        new_sens = _RANK_TO_SENSITIVITY[max(cur_rank, out_rank)]

    new_fmt = state.format if node.output_port.format == "any" else node.output_port.format
    new_unit = state.unit if node.output_port.unit == "any" else node.output_port.unit

    if node.output_port.semantic_type == "any" or node.output_port.preserves_semantic_type:
        new_sem = state.semantic_type
    else:
        new_sem = node.output_port.semantic_type

    if node.output_port.schema_fields:
        if node.output_port.preserves_fields:
            new_fields = tuple(sorted(set(state.schema_fields) | set(node.output_port.schema_fields)))
        else:
            new_fields = node.output_port.schema_fields
    elif node.output_port.preserves_fields is False:
        new_fields = ()
    else:
        new_fields = state.schema_fields

    new_ord = node.output_port.ordering if node.output_port.ordering == "ordered" else state.ordering
    next_port = TypedPort(
        format=new_fmt,
        unit=new_unit,
        schema_fields=new_fields,
        sensitivity=new_sens,
        semantic_type=new_sem,
        ordering=new_ord,
        cardinality=node.output_port.cardinality,
        precision=node.output_port.precision or state.precision,
        trust_label=node.output_port.trust_label,
    )
    return next_port, [], used_declassifier


def _default_candidate_templates(
    gap_kind: str,
    src_port: TypedPort,
    dst_port: TypedPort,
    declass_req: bool,
) -> List[Dict[str, Any]]:
    """Build deterministic Pareto-tradeoff candidate templates for a `SynthesisBlueprint/1`."""
    tag = f"{src_port.format}-{dst_port.format}-{src_port.unit}-{dst_port.unit}".replace("_", "-")
    if gap_kind == GapKind.MISSING_DECLASSIFICATION_GATE.value or declass_req:
        return [
            {
                "template_id": f"py-declass-{tag}"[:64],
                "kind": "python_adapter",
                "language": "python",
                "description": f"Deterministic field redaction/masking declassifier ({src_port.sensitivity}->{dst_port.sensitivity})",
                "requires_sandbox": True,
                "metrics": {
                    "latency_us": 180,
                    "accuracy_bps": 10000,
                    "risk_score": 5,
                    "cost_micro_usd": 40,
                },
            },
            {
                "template_id": f"c99-declass-{tag}"[:64],
                "kind": "native_c99_asm_kernel",
                "language": "c99",
                "description": f"Streaming C99 zero-allocation declassifier ({src_port.sensitivity}->{dst_port.sensitivity})",
                "requires_sandbox": True,
                "metrics": {
                    "latency_us": 22,
                    "accuracy_bps": 10000,
                    "risk_score": 18,
                    "cost_micro_usd": 320,
                },
            },
            {
                "template_id": f"ext-declass-{tag}"[:64],
                "kind": "external_verified_tool",
                "language": "external_tool",
                "description": f"Attested external declassification gate ({src_port.sensitivity}->{dst_port.sensitivity})",
                "requires_sandbox": True,
                "metrics": {
                    "latency_us": 650,
                    "accuracy_bps": 9950,
                    "risk_score": 12,
                    "cost_micro_usd": 15,
                },
            },
        ]

    if gap_kind in (GapKind.MISSING_UNIT_CONVERTER.value, GapKind.MISSING_FORMAT_BRIDGE.value):
        return [
            {
                "template_id": f"c99-bridge-{tag}"[:64],
                "kind": "native_c99_asm_kernel",
                "language": "c99_asm",
                "description": f"Native C99/SIMD deterministic transform ({src_port.format}/{src_port.unit} -> {dst_port.format}/{dst_port.unit})",
                "requires_sandbox": True,
                "metrics": {
                    "latency_us": 15,
                    "accuracy_bps": 10000,
                    "risk_score": 20,
                    "cost_micro_usd": 300,
                },
            },
            {
                "template_id": f"py-bridge-{tag}"[:64],
                "kind": "python_adapter",
                "language": "python",
                "description": f"Exact-Decimal pure-Python bridge ({src_port.format}/{src_port.unit} -> {dst_port.format}/{dst_port.unit})",
                "requires_sandbox": True,
                "metrics": {
                    "latency_us": 240,
                    "accuracy_bps": 10000,
                    "risk_score": 4,
                    "cost_micro_usd": 50,
                },
            },
            {
                "template_id": f"ext-bridge-{tag}"[:64],
                "kind": "external_verified_tool",
                "language": "external_tool",
                "description": f"Verified external adapter candidate ({src_port.format} -> {dst_port.format})",
                "requires_sandbox": True,
                "metrics": {
                    "latency_us": 900,
                    "accuracy_bps": 9900,
                    "risk_score": 10,
                    "cost_micro_usd": 10,
                },
            },
        ]

    return [
        {
            "template_id": f"c99-kernel-{tag}"[:64],
            "kind": "native_c99_asm_kernel",
            "language": "c99_asm",
            "description": f"Synthesized native C99/ASM kernel ({src_port.semantic_type} -> {dst_port.semantic_type})",
            "requires_sandbox": True,
            "metrics": {
                "latency_us": 25,
                "accuracy_bps": 10000,
                "risk_score": 25,
                "cost_micro_usd": 450,
            },
        },
        {
            "template_id": f"py-ref-{tag}"[:64],
            "kind": "python_adapter",
            "language": "python",
            "description": f"Synthesized pure-Python reference kernel ({src_port.semantic_type} -> {dst_port.semantic_type})",
            "requires_sandbox": True,
            "metrics": {
                "latency_us": 420,
                "accuracy_bps": 10000,
                "risk_score": 6,
                "cost_micro_usd": 80,
            },
        },
        {
            "template_id": f"ext-tool-{tag}"[:64],
            "kind": "external_verified_tool",
            "language": "external_tool",
            "description": f"Attested external verified tool lookup ({dst_port.semantic_type})",
            "requires_sandbox": True,
            "metrics": {
                "latency_us": 1200,
                "accuracy_bps": 9850,
                "risk_score": 14,
                "cost_micro_usd": 20,
            },
        },
    ]


@dataclass(frozen=True)
class _SyntheticEdge:
    gap_kind: GapKind
    cost: int
    next_port: TypedPort
    description: str
    blocked_tools: Dict[str, List[str]] = field(default_factory=dict)


class TypedCapabilityGraph:
    """Demand-driven typed capability graph for safe multi-hop routing and synthesis gap discovery."""

    def __init__(self, tools: Optional[Sequence[ToolSpec]] = None) -> None:
        self._verified: Dict[str, _IndexedTool] = {}
        self._excluded: Dict[str, ExclusionRecord] = {}
        self._all_specs: Dict[str, ToolSpec] = {}
        for spec in sorted(tools or (), key=lambda s: s.tool_id):
            self.add_tool(spec)

    @classmethod
    def from_registry(cls, registry: ToolRegistry) -> "TypedCapabilityGraph":
        if not isinstance(registry, ToolRegistry):
            raise ValueError("INVALID_REGISTRY: expected ToolRegistry instance.")
        return cls(registry.list_tools(trust_statuses=None))

    def add_tool(self, spec: ToolSpec) -> bool:
        """Index a `ToolSpec`; admit ONLY `VERIFIED` attested tools to executable routes."""
        if not isinstance(spec, ToolSpec):
            raise ValueError("INVALID_TOOL_SPEC: expected ToolSpec instance.")
        validate_tool_id(spec.tool_id)
        if not is_valid_sha256(spec.binary_hash):
            raise ValueError(f"INVALID_BINARY_HASH: '{spec.tool_id}' has invalid binary_hash.")

        self._all_specs[spec.tool_id] = spec

        exclusion_reasons: List[str] = []
        if spec.trust_status != TrustStatus.VERIFIED:
            exclusion_reasons.append(f"TRUST_STATUS_{spec.trust_status.value}_EXCLUDED")
        elif not has_valid_verification_attestation(
            spec.verification_attestation, spec.binary_hash, spec.tool_id
        ):
            exclusion_reasons.append("INVALID_VERIFICATION_ATTESTATION")

        if exclusion_reasons:
            self._verified.pop(spec.tool_id, None)
            self._excluded[spec.tool_id] = ExclusionRecord(
                tool_id=spec.tool_id,
                trust_status=spec.trust_status.value,
                reasons=tuple(exclusion_reasons),
                capabilities=tuple(spec.capabilities),
                required_permissions=tuple(spec.required_permissions),
            )
            return False

        in_port, out_port = _index_tool_ports(spec)
        effect_contract = _extract_tool_effect(spec)
        declassifier = _extract_declassifier_info(spec, in_port, out_port)
        latency_us, cost_micro_usd, risk_score = _extract_tool_metrics(spec)

        self._excluded.pop(spec.tool_id, None)
        self._verified[spec.tool_id] = _IndexedTool(
            spec=spec,
            input_port=in_port,
            output_port=out_port,
            effect_contract=effect_contract,
            declassifier=declassifier,
            latency_us=latency_us,
            cost_micro_usd=cost_micro_usd,
            risk_score=risk_score,
        )
        return True

    @property
    def verified_tool_ids(self) -> List[str]:
        return sorted(self._verified.keys())

    @property
    def excluded_tools(self) -> Dict[str, ExclusionRecord]:
        return dict(self._excluded)

    def get_excluded_tools(self) -> Dict[str, ExclusionRecord]:
        return dict(self._excluded)

    def rank_pareto_candidates(
        self,
        candidates: Sequence[Union[ParetoCandidate, Mapping[str, Any]]],
        *,
        plan_id: str = "pareto-plan",
        blueprint_id: Optional[str] = None,
        objective_weights: Optional[Mapping[str, Union[int, str, Decimal]]] = None,
    ) -> RankedSynthesisPlan:
        return rank_pareto_candidates(
            candidates,
            plan_id=plan_id,
            blueprint_id=blueprint_id,
            objective_weights=objective_weights,
        )

    def find_shortest_safe_path(
        self,
        source_req: Union[TypedPort, PortContract, Mapping[str, Any], str],
        target_req: Union[TypedPort, PortContract, Mapping[str, Any], str],
        security_context: SecurityContext,
        *,
        require_idempotent: Optional[bool] = None,
        allow_irreversible: Optional[bool] = None,
        sensitivity_ceiling: Optional[str] = None,
        declassification_grants: Optional[Sequence[DeclassificationGrant]] = None,
        permission_budget: Optional[Sequence[str]] = None,
        allowed_effects: Optional[Mapping[str, Any]] = None,
        max_hops: int = 16,
    ) -> SafePathResult:
        """Find minimum-hop verified safe path enforcing sensitivity, permission, and effect rules."""
        if not isinstance(security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext instance.")
        if max_hops < 1:
            raise ValueError("INVALID_MAX_HOPS: max_hops must be >= 1.")

        src_port = TypedPort.coerce(source_req, direction="input")
        dst_port = TypedPort.coerce(target_req, direction="output")

        req_idemp = bool(
            require_idempotent
            if require_idempotent is not None
            else (
                isinstance(target_req, Mapping)
                and (
                    target_req.get("require_idempotent") is True
                    or target_req.get("idempotent") is True
                )
            )
            or (isinstance(allowed_effects, Mapping) and allowed_effects.get("idempotent") is True)
        )
        allow_irrev = bool(
            allow_irreversible
            if allow_irreversible is not None
            else not (isinstance(allowed_effects, Mapping) and allowed_effects.get("irreversible") is False)
        )

        ceiling = (
            _normalize_sensitivity(sensitivity_ceiling)
            if sensitivity_ceiling is not None
            else dst_port.effective_sensitivity()
        )
        effective_dst = TypedPort(
            format=dst_port.format,
            unit=dst_port.unit,
            schema_fields=dst_port.schema_fields,
            sensitivity=(
                ceiling
                if SENSITIVITY_LEVELS[ceiling] < SENSITIVITY_LEVELS[dst_port.effective_sensitivity()]
                else dst_port.sensitivity
            ),
            semantic_type=dst_port.semantic_type,
            ordering=dst_port.ordering,
            cardinality=dst_port.cardinality,
            precision=dst_port.precision,
            trust_label=dst_port.trust_label,
        )

        rejected: Dict[str, List[str]] = {
            tid: list(rec.reasons) for tid, rec in sorted(self._excluded.items())
        }

        direct_reasons = _check_port_transition(src_port, effective_dst, is_target_sink=True)
        if not direct_reasons:
            return SafePathResult(
                found=True,
                tools=(),
                tool_ids=(),
                hop_count=0,
                source_port=src_port,
                target_port=effective_dst,
                final_port=src_port,
                effective_sensitivity=src_port.effective_sensitivity(),
                rejected_tools=rejected,
            )

        eligible: List[_IndexedTool] = []
        for tid in sorted(self._verified.keys()):
            node = self._verified[tid]
            p_reasons = _check_policy_and_effects(
                node,
                security_context,
                require_idempotent=req_idemp,
                allow_irreversible=allow_irrev,
                permission_budget=permission_budget,
                allowed_effects=allowed_effects,
            )
            if p_reasons:
                rejected[tid] = p_reasons
                continue
            eligible.append(node)

        best_cost: Dict[Tuple[Any, ...], Tuple[int, Decimal, Decimal, Tuple[str, ...]]] = {}
        start_key = src_port.state_key()
        best_cost[start_key] = (0, _DECIMAL_ZERO, _DECIMAL_ZERO, ())

        # Priority queue: (hop_count, latency_us, cost_micro_usd, tool_ids, current_port, nodes_tuple, declassifiers)
        heap: List[
            Tuple[
                int,
                Decimal,
                Decimal,
                Tuple[str, ...],
                TypedPort,
                Tuple[_IndexedTool, ...],
                Tuple[str, ...],
            ]
        ] = [(0, _DECIMAL_ZERO, _DECIMAL_ZERO, (), src_port, (), ())]

        blocked_reasons: List[str] = list(direct_reasons)

        while heap:
            hops, lat_us, cost_us, tids, cur_port, nodes_path, decls = heapq.heappop(heap)
            if not _check_port_transition(cur_port, effective_dst, is_target_sink=True):
                eff_summary = (
                    compute_dag_effects([n.effect_contract for n in nodes_path])
                    if nodes_path
                    else {
                        "permission_union": [],
                        "effects_union": EffectContract().to_dict(),
                        "irreversible_any": False,
                        "idempotent_all": True,
                    }
                )
                return SafePathResult(
                    found=True,
                    tools=tuple(n.spec for n in nodes_path),
                    tool_ids=tids,
                    hop_count=hops,
                    source_port=src_port,
                    target_port=effective_dst,
                    final_port=cur_port,
                    effective_sensitivity=cur_port.effective_sensitivity(),
                    declassified_by=decls,
                    permission_union=tuple(eff_summary["permission_union"]),
                    effects_summary=eff_summary["effects_union"],
                    total_latency_us=lat_us,
                    total_cost_micro_usd=cost_us,
                    rejected_tools=rejected,
                )

            if hops >= max_hops:
                continue

            for node in eligible:
                if node.spec.tool_id in tids:
                    continue
                next_port, step_reasons, used_decl = _advance_port_with_tool(
                    cur_port,
                    node,
                    declassification_grants=declassification_grants,
                )
                if next_port is None:
                    if any(
                        r.startswith(("UNATTESTED_SENSITIVITY_DOWNGRADE", "MISSING_AUTHORIZED_DECLASSIFICATION_GRANT", "DECLASSIFIER_"))
                        for r in step_reasons
                    ):
                        existing = rejected.setdefault(node.spec.tool_id, [])
                        for r in step_reasons:
                            if r not in existing:
                                existing.append(r)
                    continue

                nxt_key = next_port.state_key()
                nxt_tids = tids + (node.spec.tool_id,)
                nxt_rank = (hops + 1, lat_us + node.latency_us, cost_us + node.cost_micro_usd, nxt_tids)
                prev_rank = best_cost.get(nxt_key)
                if prev_rank is not None and prev_rank <= nxt_rank:
                    continue
                best_cost[nxt_key] = nxt_rank
                nxt_decls = decls + ((node.spec.tool_id,) if used_decl else ())
                heapq.heappush(
                    heap,
                    (
                        hops + 1,
                        nxt_rank[1],
                        nxt_rank[2],
                        nxt_tids,
                        next_port,
                        nodes_path + (node,),
                        nxt_decls,
                    ),
                )

        # Enrich failure reasons with policy/excluded diagnostics
        for tid in sorted(rejected.keys()):
            for r in rejected[tid]:
                tag = f"{tid}:{r}"
                if tag not in blocked_reasons:
                    blocked_reasons.append(tag)

        return SafePathResult(
            found=False,
            source_port=src_port,
            target_port=effective_dst,
            effective_sensitivity=src_port.effective_sensitivity(),
            blocked_reasons=tuple(blocked_reasons),
            rejected_tools=rejected,
        )

    def _enumerate_synthetic_edges(
        self,
        cur_port: TypedPort,
        demand_ports: Sequence[TypedPort],
        security_context: SecurityContext,
        *,
        require_idempotent: bool,
        allow_irreversible: bool,
        permission_budget: Optional[Sequence[str]],
        allowed_effects: Optional[Mapping[str, Any]],
        declassification_grants: Optional[Sequence[DeclassificationGrant]] = None,
    ) -> List[_SyntheticEdge]:
        edges: List[_SyntheticEdge] = []
        seen_signatures: Set[Tuple[str, Tuple[Any, ...]]] = set()

        # 1. Existing verified tools blocked by permissions or effects
        for tid in sorted(self._verified.keys()):
            node = self._verified[tid]
            p_reasons = _check_policy_and_effects(
                node,
                security_context,
                require_idempotent=require_idempotent,
                allow_irreversible=allow_irreversible,
                permission_budget=permission_budget,
                allowed_effects=allowed_effects,
            )
            if not p_reasons:
                continue
            next_port, step_reasons, _ = _advance_port_with_tool(
                cur_port, node, declassification_grants=declassification_grants
            )
            if next_port is None or step_reasons:
                continue
            is_effect_only = all(
                r in {"NON_IDEMPOTENT_EFFECT_BLOCKED", "IRREVERSIBLE_EFFECT_BLOCKED"}
                or r.startswith("DISALLOWED_SIDE_EFFECTS:")
                for r in p_reasons
            )
            gkind = GapKind.EFFECT_CONSTRAINT_BLOCKED if is_effect_only else GapKind.PERMISSION_BLOCKED_EDGE
            cost = 950 if is_effect_only else 900
            sig = (gkind.value, next_port.state_key())
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                edges.append(
                    _SyntheticEdge(
                        gap_kind=gkind,
                        cost=cost,
                        next_port=next_port,
                        description=(
                            f"Verified tool '{tid}' matches typed transform ({cur_port.format}/{cur_port.unit} -> "
                            f"{next_port.format}/{next_port.unit}) but is blocked by policy/effect constraints: "
                            f"{', '.join(p_reasons)}."
                        ),
                        blocked_tools={tid: p_reasons},
                    )
                )

        # 2. Synthetic typed gaps toward downstream demand ports (`target_req` & verified tool inputs)
        cur_sens = cur_port.effective_sensitivity()
        cur_rank = SENSITIVITY_LEVELS[cur_sens]

        for dport in demand_ports:
            d_sens = dport.effective_sensitivity() if dport.sensitivity != "any" else cur_sens
            d_rank = SENSITIVITY_LEVELS[d_sens]

            # Match excluded tools (DISCOVERED/QUARANTINED/RETIRED) on this transition for clear provenance
            matching_excluded: Dict[str, List[str]] = {}
            for tid, rec in sorted(self._excluded.items()):
                spec = self._all_specs[tid]
                t_in, t_out = _index_tool_ports(spec)
                if not _check_port_transition(cur_port, t_in, is_target_sink=False) and not _check_port_transition(t_out, dport, is_target_sink=False):
                    matching_excluded[tid] = list(rec.reasons)

            # Declassification gate if sensitivity exceeds destination
            if cur_rank > d_rank:
                declass_port = TypedPort(
                    format=cur_port.format,
                    unit=cur_port.unit,
                    schema_fields=cur_port.schema_fields,
                    sensitivity=d_sens,
                    semantic_type=cur_port.semantic_type,
                    ordering=cur_port.ordering,
                    cardinality=cur_port.cardinality,
                    precision=cur_port.precision,
                )
                sig = (GapKind.MISSING_DECLASSIFICATION_GATE.value, declass_port.state_key())
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    edges.append(
                        _SyntheticEdge(
                            gap_kind=GapKind.MISSING_DECLASSIFICATION_GATE,
                            cost=1500,
                            next_port=declass_port,
                            description=(
                                f"Missing verified declassification gate: '{cur_sens}' data cannot flow to "
                                f"'{d_sens}' consumer without explicit redaction/masking/tokenization."
                            ),
                            blocked_tools=matching_excluded,
                        )
                    )
                continue

            fmt_match = dport.format == "any" or cur_port.format == dport.format
            sem_match = dport.semantic_type == "any" or cur_port.semantic_type == dport.semantic_type
            unit_match = dport.unit == "any" or cur_port.unit == dport.unit
            ord_match = dport.ordering != "ordered" or cur_port.ordering == "ordered"
            fields_match = set(dport.schema_fields).issubset(set(cur_port.schema_fields))

            if fmt_match and sem_match and ord_match and fields_match and not unit_match:
                if cur_port.unit != "none" and dport.unit != "none":
                    unit_port = TypedPort(
                        format=cur_port.format,
                        unit=dport.unit,
                        schema_fields=cur_port.schema_fields,
                        sensitivity=cur_sens,
                        semantic_type=cur_port.semantic_type,
                        ordering=cur_port.ordering,
                        cardinality=cur_port.cardinality,
                        precision=cur_port.precision,
                    )
                    sig = (GapKind.MISSING_UNIT_CONVERTER.value, unit_port.state_key())
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        edges.append(
                            _SyntheticEdge(
                                gap_kind=GapKind.MISSING_UNIT_CONVERTER,
                                cost=1000,
                                next_port=unit_port,
                                description=(
                                    f"Missing verified unit converter from '{cur_port.unit}' to '{dport.unit}' "
                                    f"on {cur_port.format} ({cur_port.semantic_type})."
                                ),
                                blocked_tools=matching_excluded,
                            )
                        )
                    continue

            wire_compat = (cur_port.format in _WIRE_LIKE_FORMATS and dport.format in _WIRE_LIKE_FORMATS)
            if sem_match and (not fmt_match or not ord_match or (wire_compat and not unit_match)):
                bridge_port = TypedPort(
                    format=cur_port.format if dport.format == "any" else dport.format,
                    unit=cur_port.unit if dport.unit == "any" else dport.unit,
                    schema_fields=tuple(sorted(set(cur_port.schema_fields) | set(dport.schema_fields))),
                    sensitivity=cur_sens,
                    semantic_type=cur_port.semantic_type if dport.semantic_type == "any" else dport.semantic_type,
                    ordering=dport.ordering if dport.ordering == "ordered" else cur_port.ordering,
                    cardinality=dport.cardinality,
                    precision=dport.precision or cur_port.precision,
                )
                sig = (GapKind.MISSING_FORMAT_BRIDGE.value, bridge_port.state_key())
                if sig not in seen_signatures:
                    seen_signatures.add(sig)
                    edges.append(
                        _SyntheticEdge(
                            gap_kind=GapKind.MISSING_FORMAT_BRIDGE,
                            cost=1200,
                            next_port=bridge_port,
                            description=(
                                f"Missing verified format/schema bridge from {cur_port.format}({cur_port.unit}) "
                                f"to {bridge_port.format}({bridge_port.unit}) for '{bridge_port.semantic_type}'."
                            ),
                            blocked_tools=matching_excluded,
                        )
                    )
                continue

            # Fallback: absent primitive kernel connecting current state to demand port
            kernel_port = TypedPort(
                format=cur_port.format if dport.format == "any" else dport.format,
                unit=cur_port.unit if dport.unit == "any" else dport.unit,
                schema_fields=dport.schema_fields or cur_port.schema_fields,
                sensitivity=cur_sens,
                semantic_type=cur_port.semantic_type if dport.semantic_type == "any" else dport.semantic_type,
                ordering=dport.ordering if dport.ordering == "ordered" else cur_port.ordering,
                cardinality=dport.cardinality,
                precision=dport.precision or cur_port.precision,
            )
            sig = (GapKind.MISSING_PRIMITIVE_KERNEL.value, kernel_port.state_key())
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                edges.append(
                    _SyntheticEdge(
                        gap_kind=GapKind.MISSING_PRIMITIVE_KERNEL,
                        cost=5000,
                        next_port=kernel_port,
                        description=(
                            f"Absent primitive verified kernel transforming ({cur_port.format}, "
                            f"{cur_port.semantic_type}, unit={cur_port.unit}) -> ({kernel_port.format}, "
                            f"{kernel_port.semantic_type}, unit={kernel_port.unit})."
                        ),
                        blocked_tools=matching_excluded,
                    )
                )

        return edges

    def _analyze_single_goal_gaps(
        self,
        goal: SynthesisGoal,
        security_context: SecurityContext,
        *,
        default_grants: Optional[Sequence[DeclassificationGrant]],
        max_hops: int,
    ) -> List[SynthesisBlueprint]:
        grants = goal.declassification_grants if goal.declassification_grants is not None else default_grants
        safe = self.find_shortest_safe_path(
            goal.source_req,
            goal.target_req,
            security_context,
            require_idempotent=goal.require_idempotent,
            allow_irreversible=goal.allow_irreversible,
            sensitivity_ceiling=goal.sensitivity_ceiling,
            declassification_grants=grants,
            permission_budget=goal.permission_budget,
            allowed_effects=goal.allowed_effects,
            max_hops=max_hops,
        )
        if safe.found:
            return []

        src_port = safe.source_port or TypedPort.coerce(goal.source_req, direction="input")
        dst_port = safe.target_port or TypedPort.coerce(goal.target_req, direction="output")
        ceiling = goal.sensitivity_ceiling or dst_port.effective_sensitivity()

        eligible: List[_IndexedTool] = []
        for tid in sorted(self._verified.keys()):
            node = self._verified[tid]
            if _check_policy_and_effects(
                node,
                security_context,
                require_idempotent=goal.require_idempotent,
                allow_irreversible=goal.allow_irreversible,
                permission_budget=goal.permission_budget,
                allowed_effects=goal.allowed_effects,
            ):
                continue
            eligible.append(node)

        demand_ports: List[TypedPort] = [dst_port]
        seen_demands: Set[Tuple[Any, ...]] = {dst_port.state_key()}
        for node in eligible:
            dk = node.input_port.state_key()
            if dk not in seen_demands:
                seen_demands.add(dk)
                demand_ports.append(node.input_port)

        # Weighted Dijkstra over (synthetic_penalty, real_hops) to isolate exact bottleneck(s)
        best: Dict[Tuple[Any, ...], Tuple[int, int]] = {src_port.state_key(): (0, 0)}
        # Heap entry: (penalty, real_hops, seq_idx, cur_port, used_tids, gap_steps)
        seq_counter = 0
        heap: List[
            Tuple[
                int,
                int,
                int,
                TypedPort,
                Tuple[str, ...],
                Tuple[Tuple[TypedPort, _SyntheticEdge], ...],
            ]
        ] = [(0, 0, seq_counter, src_port, (), ())]

        winning_steps: Optional[Tuple[Tuple[TypedPort, _SyntheticEdge], ...]] = None
        expansions = 0
        max_expansions = 4096

        while heap and expansions < max_expansions:
            expansions += 1
            pen, hops, _seq, cur_port, used_tids, gap_steps = heapq.heappop(heap)
            if not _check_port_transition(cur_port, dst_port, is_target_sink=True):
                winning_steps = gap_steps
                break
            if hops + len(gap_steps) >= max_hops:
                continue

            for node in eligible:
                if node.spec.tool_id in used_tids:
                    continue
                next_port, _reasons, _used_decl = _advance_port_with_tool(
                    cur_port, node, declassification_grants=grants
                )
                if next_port is None:
                    continue
                nkey = next_port.state_key()
                ncost = (pen, hops + 1)
                if best.get(nkey) is not None and best[nkey] <= ncost:
                    continue
                best[nkey] = ncost
                seq_counter += 1
                heapq.heappush(
                    heap,
                    (pen, hops + 1, seq_counter, next_port, used_tids + (node.spec.tool_id,), gap_steps),
                )

            if len(gap_steps) < min(max_hops, 6):
                for syn in self._enumerate_synthetic_edges(
                    cur_port,
                    demand_ports,
                    security_context,
                    require_idempotent=goal.require_idempotent,
                    allow_irreversible=goal.allow_irreversible,
                    permission_budget=goal.permission_budget,
                    allowed_effects=goal.allowed_effects,
                    declassification_grants=grants,
                ):
                    nkey = syn.next_port.state_key()
                    ncost = (pen + syn.cost, hops)
                    if best.get(nkey) is not None and best[nkey] <= ncost:
                        continue
                    best[nkey] = ncost
                    seq_counter += 1
                    heapq.heappush(
                        heap,
                        (
                            pen + syn.cost,
                            hops,
                            seq_counter,
                            syn.next_port,
                            used_tids,
                            gap_steps + ((cur_port, syn),),
                        ),
                    )

        if not winning_steps:
            fallback_edge = _SyntheticEdge(
                gap_kind=GapKind.MISSING_PRIMITIVE_KERNEL,
                cost=5000,
                next_port=dst_port,
                description=(
                    f"Absent end-to-end verified capability chain for goal '{goal.goal_id}': "
                    f"({src_port.format}, {src_port.semantic_type}, unit={src_port.unit}, sens={src_port.effective_sensitivity()}) "
                    f"-> ({dst_port.format}, {dst_port.semantic_type}, unit={dst_port.unit}, sens={dst_port.effective_sensitivity()})."
                ),
                blocked_tools=safe.rejected_tools,
            )
            winning_steps = ((src_port, fallback_edge),)

        allowed_perms = list(security_context.allowed_permissions)
        if goal.permission_budget is not None:
            allowed_perms = sorted(set(allowed_perms) & set(goal.permission_budget))
        perm_budget = {
            "allowed_permissions": allowed_perms,
            "network_allowed": security_context.network_allowed,
            "allow_untrusted_native": security_context.allow_untrusted_native,
            "profile": security_context.profile.value,
            "policy_hash": security_context.policy_hash,
        }
        effects_budget = dict(goal.allowed_effects)
        effects_budget.setdefault("idempotent", goal.require_idempotent)
        effects_budget.setdefault("irreversible_allowed", goal.allow_irreversible)
        effects_budget.setdefault("network_allowed", security_context.network_allowed)

        blueprints: List[SynthesisBlueprint] = []
        for idx, (step_src, syn_edge) in enumerate(winning_steps):
            step_dst = syn_edge.next_port
            req_units = [
                u for u in dict.fromkeys((step_src.unit, step_dst.unit))
                if u not in {"none", "any"}
            ]
            declass_req = (
                syn_edge.gap_kind == GapKind.MISSING_DECLASSIFICATION_GATE
                or SENSITIVITY_LEVELS[step_src.effective_sensitivity()]
                > SENSITIVITY_LEVELS[step_dst.effective_sensitivity()]
            )
            step_ceiling = (
                ceiling
                if SENSITIVITY_LEVELS[ceiling] < SENSITIVITY_LEVELS[step_dst.effective_sensitivity()]
                else step_dst.effective_sensitivity()
            )
            blocked_info = dict(syn_edge.blocked_tools)
            for ex_id, ex_rec in sorted(self._excluded.items()):
                blocked_info.setdefault(ex_id, list(ex_rec.reasons))

            bp_seed = sha256_digest(
                {
                    "goal_id": goal.goal_id,
                    "step_index": idx,
                    "gap_kind": syn_edge.gap_kind.value,
                    "src": step_src.to_dict(),
                    "dst": step_dst.to_dict(),
                }
            ).split(":", 1)[1][:12]
            bp_id = f"bp-{goal.goal_id}-{idx}-{bp_seed}"
            blueprints.append(
                SynthesisBlueprint(
                    blueprint_id=bp_id,
                    goal_id=goal.goal_id,
                    gap_kind=syn_edge.gap_kind.value,
                    source_type=step_src.to_dict(),
                    target_type=step_dst.to_dict(),
                    required_units=req_units,
                    sensitivity_ceiling=step_ceiling,
                    allowed_effects=effects_budget,
                    permission_budget=perm_budget,
                    missing_hop_description=syn_edge.description,
                    candidate_templates=_default_candidate_templates(
                        syn_edge.gap_kind.value, step_src, step_dst, declass_req
                    ),
                    declassification_required=declass_req,
                    blocked_tool_reasons=blocked_info,
                )
            )
        return blueprints

    def detect_capability_gaps(
        self,
        goals: Union[
            SynthesisGoal,
            CapabilityGap,
            Mapping[str, Any],
            Sequence[Union[SynthesisGoal, CapabilityGap, Mapping[str, Any]]],
        ],
        security_context: SecurityContext,
        *,
        declassification_grants: Optional[Sequence[DeclassificationGrant]] = None,
        max_hops: int = 16,
    ) -> List[SynthesisBlueprint]:
        """Identify single-hop & multi-hop typed bottlenecks and emit deterministic `SynthesisBlueprint/1` specs."""
        if not isinstance(security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext instance.")

        if isinstance(goals, (SynthesisGoal, CapabilityGap, Mapping)):
            raw_goals: Sequence[Any] = (goals,)
        elif isinstance(goals, Sequence) and not isinstance(goals, (str, bytes)):
            raw_goals = goals
        else:
            raise ValueError("INVALID_GOALS: expected goal or sequence of goals.")

        normalized_goals = [SynthesisGoal.coerce(g, index=i) for i, g in enumerate(raw_goals)]
        blueprints: List[SynthesisBlueprint] = []
        for goal in sorted(normalized_goals, key=lambda g: g.goal_id):
            blueprints.extend(
                self._analyze_single_goal_gaps(
                    goal,
                    security_context,
                    default_grants=declassification_grants,
                    max_hops=max_hops,
                )
            )
        return blueprints

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "TypedCapabilityGraph/1",
            "verified_tools": {
                tid: {
                    "input_port": self._verified[tid].input_port.to_dict(),
                    "output_port": self._verified[tid].output_port.to_dict(),
                    "effect_contract": self._verified[tid].effect_contract.to_dict(),
                    "required_permissions": list(self._verified[tid].spec.required_permissions),
                    "binary_hash": self._verified[tid].spec.binary_hash,
                }
                for tid in sorted(self._verified.keys())
            },
            "excluded_tools": {
                tid: rec.to_dict() for tid, rec in sorted(self._excluded.items())
            },
        }

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())


__all__ = [
    "CANONICAL_UNIT_ALIASES",
    "DECLASSIFY_TRANSFORMS",
    "RANKED_SYNTHESIS_PLAN_SCHEMA",
    "SENSITIVITY_LEVELS",
    "SYNTHESIS_BLUEPRINT_SCHEMA",
    "TYPED_PORT_SCHEMA",
    "ExclusionRecord",
    "GapKind",
    "ParetoCandidate",
    "RankedCandidateEntry",
    "RankedSynthesisPlan",
    "SafePathResult",
    "SynthesisBlueprint",
    "SynthesisGoal",
    "TypedCapabilityGraph",
    "TypedPort",
    "rank_pareto_candidates",
]
