"""Build #2 frozen typed contracts (`Build2Contracts/1`) for capability composition and forge."""

from __future__ import annotations

import hmac
import re
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import (
    VALID_EXECUTION_STATUSES,
    VALID_RUN_ID_RE,
    ExecutionStatus,
    TrustStatus,
    assert_dataclass_type_unmodified,
    assert_no_raw_secrets,
    canonical_json_dumps,
    extract_exact_str_list,
    has_valid_verification_attestation,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    safe_exact_str_dict_view,
    sanitize_exact_json_value,
    sha256_digest,
    snapshot_class_lifecycle,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.shield import TROJAN_UNICODE_RE

GENESIS_EVENT_HASH = "sha256:" + ("0" * 64)

VALID_CARDINALITIES = frozenset({"one", "many", "stream"})
VALID_ORDERINGS = frozenset({"ordered", "unordered"})
VALID_SENSITIVITIES = frozenset({"public", "internal", "secret"})
VALID_TRUST_LABELS = frozenset({"trusted", "untrusted", "derived"})

_SENSITIVITY_RANK: Dict[str, int] = {"public": 0, "internal": 1, "secret": 2}
_TRUST_RANK: Dict[str, int] = {"untrusted": 0, "derived": 1, "trusted": 2}

_AMBIGUOUS_MAP_TOKENS = frozenset({"?", "tbd", "unknown", "ambiguous", "multiple", "any"})
_MAPPING_META_KEYS = frozenset(
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
    }
)
_DECLASSIFICATION_HINTS = ("redact", "mask", "hash", "tokenize", "anonymize", "declassify", "sanitize")
_ADDITIVE_RESOURCE_KEYS = frozenset(
    {
        "tokens",
        "api_tokens",
        "api_token_estimate",
        "runtime_seconds",
        "wall_time_ms",
        "duration_ms",
        "latency_ms",
        "cpu_ms",
        "disk_write_mb",
        "estimated_cost",
    }
)
_PEAK_RESOURCE_KEYS = frozenset(
    {
        "memory_mb",
        "max_memory_mb",
        "max_runtime_seconds",
        "timeout_seconds",
        "timeout_ms",
        "cpu_cores",
        "max_cpu_cores",
        "parallelism",
    }
)

_NUMERIC_PREC_RE = re.compile(
    r"\b(decimal128|decimal64|decimal|numeric|exact_decimal|float64|double|fp64|f64|"
    r"float32|fp32|f32|float16|fp16|f16|float|int64|i64|int32|i32|int16|i16|int8|i8|int|"
    r"uint64|u64|uint32|u32|uint16|u16|uint8|u8)\b"
)
_TIME_PREC_RE = re.compile(
    r"\b(nanosecond|nanoseconds|ns|microsecond|microseconds|us|"
    r"millisecond|milliseconds|ms|second|seconds|datetime|timestamp|date)\b"
)
_BIT_PREC_RE = re.compile(r"^(\d+)(?:\s*(?:bit|bits|b|dp))?$")
_QUALITATIVE_PREC_RANK: Dict[str, int] = {
    "lossy": 1,
    "approx": 1,
    "approximate": 1,
    "low": 1,
    "medium": 2,
    "high": 3,
    "exact": 4,
    "lossless": 4,
}
_TIME_PREC_RANK: Dict[str, int] = {
    "date": 1,
    "second": 2,
    "seconds": 2,
    "millisecond": 3,
    "milliseconds": 3,
    "ms": 3,
    "microsecond": 4,
    "microseconds": 4,
    "us": 4,
    "nanosecond": 5,
    "nanoseconds": 5,
    "ns": 5,
}
_FLOAT_BITS: Dict[str, int] = {
    "float16": 16,
    "fp16": 16,
    "f16": 16,
    "float32": 32,
    "fp32": 32,
    "f32": 32,
    "float": 32,
    "float64": 64,
    "double": 64,
    "fp64": 64,
    "f64": 64,
    "decimal64": 64,
    "decimal128": 128,
    "decimal": 128,
    "numeric": 128,
    "exact_decimal": 128,
}
_INT_BITS: Dict[str, Tuple[bool, int]] = {
    "int8": (True, 8),
    "i8": (True, 8),
    "int16": (True, 16),
    "i16": (True, 16),
    "int32": (True, 32),
    "i32": (True, 32),
    "int": (True, 32),
    "int64": (True, 64),
    "i64": (True, 64),
    "uint8": (False, 8),
    "u8": (False, 8),
    "uint16": (False, 16),
    "u16": (False, 16),
    "uint32": (False, 32),
    "u32": (False, 32),
    "uint64": (False, 64),
    "u64": (False, 64),
}


class AbstainError(ValueError):
    """Raised when an adapter or semantic mapping is missing, ambiguous, or unsafe (`ABSTAIN`)."""


class ForgeState(str, Enum):
    """Strict monotonic Build #2 forge lifecycle state machine."""

    PROPOSED = "PROPOSED"
    SPECIFIED = "SPECIFIED"
    REFERENCE_VERIFIED = "REFERENCE_VERIFIED"
    GENERATED = "GENERATED"
    COMPILED = "COMPILED"
    SANDBOX_TESTED = "SANDBOX_TESTED"
    DIFFERENTIAL_VERIFIED = "DIFFERENTIAL_VERIFIED"
    BENCHMARKED = "BENCHMARKED"
    SHADOW = "SHADOW"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"


FORGE_STAGE_ORDER: Tuple[ForgeState, ...] = (
    ForgeState.PROPOSED,
    ForgeState.SPECIFIED,
    ForgeState.REFERENCE_VERIFIED,
    ForgeState.GENERATED,
    ForgeState.COMPILED,
    ForgeState.SANDBOX_TESTED,
    ForgeState.DIFFERENTIAL_VERIFIED,
    ForgeState.BENCHMARKED,
    ForgeState.SHADOW,
    ForgeState.VERIFIED,
)
_FORGE_STAGE_INDEX: Dict[ForgeState, int] = {
    stage: idx for idx, stage in enumerate(FORGE_STAGE_ORDER)
}


def _coerce_forge_state(value: Union[ForgeState, str]) -> ForgeState:
    if isinstance(value, ForgeState):
        return value
    if isinstance(value, str):
        return ForgeState(value.strip().upper())
    raise ValueError(f"INVALID_FORGE_STATE: {value!r}")


def validate_forge_transition(
    prev_state: Union[ForgeState, str],
    next_state: Union[ForgeState, str],
) -> ForgeState:
    """Enforce strict single-step monotonic forge progression and terminal rollback/reject rules."""
    prev = _coerce_forge_state(prev_state)
    nxt = _coerce_forge_state(next_state)

    if prev in (ForgeState.REJECTED, ForgeState.ROLLED_BACK):
        raise ValueError(
            f"INVALID_FORGE_TRANSITION: cannot transition out of terminal state {prev.value} -> {nxt.value}."
        )
    if prev == nxt:
        raise ValueError(f"INVALID_FORGE_TRANSITION: self-transition {prev.value} -> {nxt.value} forbidden.")

    if nxt == ForgeState.ROLLED_BACK:
        return nxt
    if nxt == ForgeState.REJECTED:
        if prev == ForgeState.VERIFIED:
            raise ValueError("INVALID_FORGE_TRANSITION: VERIFIED builds must transition to ROLLED_BACK, not REJECTED.")
        return nxt

    prev_idx = _FORGE_STAGE_INDEX.get(prev)
    nxt_idx = _FORGE_STAGE_INDEX.get(nxt)
    if prev_idx is None or nxt_idx is None:
        raise ValueError(f"INVALID_FORGE_TRANSITION: {prev.value} -> {nxt.value}.")
    if nxt_idx != prev_idx + 1:
        raise ValueError(
            f"INVALID_FORGE_TRANSITION: {prev.value} -> {nxt.value} skips or reverses required monotonic stages."
        )
    return nxt


def _validate_structure_hygiene(value: Any, *, field_name: str) -> None:
    """Reject NUL bytes and Trojan/Bidi Unicode control characters recursively."""
    if isinstance(value, str):
        if "\x00" in value or TROJAN_UNICODE_RE.search(value):
            raise ValueError(f"REJECTED_TROJAN_UNICODE ({field_name}): control or bidi character detected.")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _validate_structure_hygiene(str(k), field_name=field_name)
            _validate_structure_hygiene(v, field_name=field_name)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _validate_structure_hygiene(item, field_name=field_name)


def _sanitize_mapping(value: Any, *, field_name: str, allow_empty: bool = True) -> Dict[str, Any]:
    """Validate mapping type, redact secrets, and check Unicode hygiene."""
    if value is None:
        data: Dict[str, Any] = {}
    elif isinstance(value, Mapping):
        data = dict(value)
    else:
        raise ValueError(f"INVALID_{field_name.upper()}: expected mapping.")
    if not allow_empty and not data:
        raise ValueError(f"INVALID_{field_name.upper()}: must be non-empty.")
    cleaned = redact_secrets_in_value(data)
    _validate_structure_hygiene(cleaned, field_name=field_name)
    return cleaned


def _validate_safe_id(value: Any, *, field_name: str) -> str:
    """Validate safe identifier (`plan_id`, `run_id`, `build_id`) with no traversal or Trojan chars."""
    cleaned = validate_safe_text(value, field_name=field_name)
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned or not VALID_RUN_ID_RE.fullmatch(cleaned):
        raise ValueError(f"INVALID_{field_name.upper()}: '{cleaned}' violates safe identifier syntax.")
    return cleaned


def _validate_str_list(
    values: Any,
    *,
    field_name: str,
    allow_empty: bool = True,
    sort_items: bool = False,
) -> List[str]:
    if values is None:
        items: List[str] = []
    elif isinstance(values, (list, tuple, set)):
        items = [redact_secrets_in_text(validate_safe_text(str(v), field_name=field_name)) for v in values]
    else:
        raise ValueError(f"INVALID_{field_name.upper()}: expected sequence of strings.")
    deduped = sorted(set(items)) if sort_items else list(dict.fromkeys(items))
    if not allow_empty and not deduped:
        raise ValueError(f"INVALID_{field_name.upper()}: must contain at least one item.")
    return deduped


def _validate_enum_token(value: Any, valid_values: frozenset[str], *, field_name: str) -> str:
    cleaned = validate_safe_text(value, field_name=field_name).lower()
    if cleaned not in valid_values:
        raise ValueError(f"INVALID_{field_name.upper()}: '{value}' not in {sorted(valid_values)}.")
    return cleaned


class _CanonicalContractMixin:
    """Shared canonical JSON serialization, secret verification, and SHA-256 hashing."""

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=type(self).__name__)
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())


@dataclass
class PortContract(_CanonicalContractMixin):
    """Typed port contract (`PortContract/1`) with semantic, unit, ordering, sensitivity, and trust labels."""

    schema_ref: str
    semantic_type: str
    encoding: str = "utf-8"
    unit: str = "none"
    cardinality: str = "one"
    ordering: str = "unordered"
    sensitivity: str = "public"
    trust_label: str = "trusted"
    streaming: Optional[bool] = None
    precision: Optional[str] = None
    nullable: bool = False
    schema: str = "PortContract/1"

    def __post_init__(self) -> None:
        if self.schema != "PortContract/1":
            raise ValueError(f"INVALID_SCHEMA: expected PortContract/1, got '{self.schema}'.")
        self.schema_ref = validate_safe_text(self.schema_ref, field_name="schema_ref")
        self.semantic_type = validate_safe_text(self.semantic_type, field_name="semantic_type")
        self.encoding = validate_safe_text(self.encoding, field_name="encoding")
        self.unit = validate_safe_text(self.unit, field_name="unit")
        self.cardinality = _validate_enum_token(self.cardinality, VALID_CARDINALITIES, field_name="cardinality")
        self.ordering = _validate_enum_token(self.ordering, VALID_ORDERINGS, field_name="ordering")
        self.sensitivity = _validate_enum_token(self.sensitivity, VALID_SENSITIVITIES, field_name="sensitivity")
        self.trust_label = _validate_enum_token(self.trust_label, VALID_TRUST_LABELS, field_name="trust_label")

        if self.streaming is None:
            self.streaming = self.cardinality == "stream"
        elif not isinstance(self.streaming, bool):
            raise ValueError("INVALID_STREAMING: expected bool.")

        if self.cardinality == "stream" and not self.streaming:
            raise ValueError("INVALID_STREAMING_CONTRACT: cardinality='stream' requires streaming=True.")
        if self.cardinality == "one" and self.streaming:
            raise ValueError("INVALID_STREAMING_CONTRACT: cardinality='one' cannot have streaming=True.")

        if self.precision is not None:
            self.precision = validate_safe_text(str(self.precision), field_name="precision")
        self.nullable = bool(self.nullable)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema": self.schema,
            "schema_ref": self.schema_ref,
            "semantic_type": self.semantic_type,
            "encoding": self.encoding,
            "unit": self.unit,
            "cardinality": self.cardinality,
            "ordering": self.ordering,
            "sensitivity": self.sensitivity,
            "trust_label": self.trust_label,
            "streaming": bool(self.streaming),
        }
        if self.precision is not None:
            payload["precision"] = self.precision
        if self.nullable:
            payload["nullable"] = True
        return redact_secrets_in_value(payload)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PortContract":
        if isinstance(data, PortContract):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_PORT_CONTRACT: expected mapping.")
        return cls(
            schema_ref=data["schema_ref"],
            semantic_type=data["semantic_type"],
            encoding=data.get("encoding", "utf-8"),
            unit=data.get("unit", "none"),
            cardinality=data.get("cardinality", "one"),
            ordering=data.get("ordering", "unordered"),
            sensitivity=data.get("sensitivity", "public"),
            trust_label=data.get("trust_label", "trusted"),
            streaming=data.get("streaming"),
            precision=data.get("precision"),
            nullable=bool(data.get("nullable", False)),
            schema=data.get("schema", "PortContract/1"),
        )


@dataclass
class PortCompatibilityResult:
    """Structured compatibility verdict for `ports_compatible(src_port, dst_port)`."""

    compatible: bool
    reasons: List[str] = field(default_factory=list)
    checked_dimensions: Tuple[str, ...] = (
        "schema_ref",
        "semantic_type",
        "encoding",
        "unit",
        "cardinality",
        "streaming",
        "ordering",
        "precision",
        "sensitivity",
        "trust_label",
        "nullable",
    )
    adapter_required: bool = False
    score: float = 1.0

    def __bool__(self) -> bool:
        return self.compatible

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compatible": self.compatible,
            "reasons": list(self.reasons),
            "checked_dimensions": list(self.checked_dimensions),
            "adapter_required": self.adapter_required,
            "score": round(self.score, 6),
        }


def _extract_precision_tokens(port: PortContract) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    combined = " ".join(
        part.lower()
        for part in (port.precision or "", port.semantic_type, port.schema_ref, port.encoding)
        if part
    )
    num_match = _NUMERIC_PREC_RE.search(combined)
    time_match = _TIME_PREC_RE.search(combined)
    explicit = port.precision.strip().lower() if port.precision else None
    return (explicit, num_match.group(1) if num_match else None, time_match.group(1) if time_match else None)


def _check_precision_loss(src: PortContract, dst: PortContract) -> Optional[str]:
    src_exp, src_num, src_time = _extract_precision_tokens(src)
    dst_exp, dst_num, dst_time = _extract_precision_tokens(dst)

    if src_exp and dst_exp and src_exp != dst_exp:
        if src_exp in _QUALITATIVE_PREC_RANK and dst_exp in _QUALITATIVE_PREC_RANK:
            if _QUALITATIVE_PREC_RANK[src_exp] > _QUALITATIVE_PREC_RANK[dst_exp]:
                return f"PRECISION_LOSS:{src_exp}->{dst_exp}"
        m_src = _BIT_PREC_RE.fullmatch(src_exp)
        m_dst = _BIT_PREC_RE.fullmatch(dst_exp)
        if m_src and m_dst and int(m_src.group(1)) > int(m_dst.group(1)):
            return f"PRECISION_LOSS:{src_exp}->{dst_exp}"
        try:
            s_tol = float(src_exp)
            d_tol = float(dst_exp)
            if 0.0 < s_tol < d_tol < 1.0:
                return f"PRECISION_LOSS:{src_exp}->{dst_exp}"
        except ValueError as _tol_err:
            _ = _tol_err

    if src_num and dst_num and src_num != dst_num:
        if src_num in ("decimal", "decimal128", "decimal64", "numeric", "exact_decimal"):
            if dst_num in _FLOAT_BITS and dst_num not in ("decimal128", "decimal", "numeric", "exact_decimal"):
                return f"PRECISION_LOSS:{src_num}->{dst_num}"
            if dst_num in _INT_BITS:
                return f"PRECISION_LOSS:{src_num}->{dst_num}"
        if src_num in _FLOAT_BITS and dst_num in _FLOAT_BITS:
            if _FLOAT_BITS[src_num] > _FLOAT_BITS[dst_num]:
                return f"PRECISION_LOSS:{src_num}->{dst_num}"
        if src_num in _FLOAT_BITS and dst_num in _INT_BITS:
            return f"PRECISION_LOSS:{src_num}->{dst_num}"
        if src_num in _INT_BITS and dst_num in _INT_BITS:
            s_signed, s_bits = _INT_BITS[src_num]
            d_signed, d_bits = _INT_BITS[dst_num]
            if s_bits > d_bits or (s_signed != d_signed and s_bits >= d_bits):
                return f"PRECISION_LOSS:{src_num}->{dst_num}"
        if src_num in _INT_BITS and dst_num in _FLOAT_BITS:
            _, s_bits = _INT_BITS[src_num]
            d_bits = _FLOAT_BITS[dst_num]
            if (s_bits >= 64 and d_bits <= 64) or (s_bits >= 32 and d_bits <= 32):
                return f"PRECISION_LOSS:{src_num}->{dst_num}"

    if src_time and dst_time and src_time != dst_time:
        if src_time in _TIME_PREC_RANK and dst_time in _TIME_PREC_RANK:
            if _TIME_PREC_RANK[src_time] > _TIME_PREC_RANK[dst_time]:
                return f"PRECISION_LOSS:{src_time}->{dst_time}"
        if src_time in ("datetime", "timestamp") and dst_time == "date":
            return f"PRECISION_LOSS:{src_time}->{dst_time}"

    return None


def ports_compatible(
    src_port: Union[PortContract, Mapping[str, Any]],
    dst_port: Union[PortContract, Mapping[str, Any]],
) -> PortCompatibilityResult:
    """Verify strict multi-dimensional compatibility between producer `src_port` and consumer `dst_port`."""
    src = PortContract.from_dict(src_port)
    dst = PortContract.from_dict(dst_port)
    reasons: List[str] = []

    if src.schema_ref.lower() != dst.schema_ref.lower():
        reasons.append(f"SCHEMA_REF_MISMATCH:{src.schema_ref}!={dst.schema_ref}")
    if src.semantic_type.lower() != dst.semantic_type.lower():
        reasons.append(f"SEMANTIC_TYPE_MISMATCH:{src.semantic_type}!={dst.semantic_type}")
    if src.encoding.lower() != dst.encoding.lower():
        reasons.append(f"ENCODING_MISMATCH:{src.encoding}!={dst.encoding}")
    if src.unit.lower() != dst.unit.lower():
        reasons.append(f"UNIT_MISMATCH:{src.unit}!={dst.unit}")
    if src.cardinality != dst.cardinality:
        reasons.append(f"CARDINALITY_MISMATCH:{src.cardinality}->{dst.cardinality}")
    if bool(src.streaming) != bool(dst.streaming):
        reasons.append(f"STREAMING_MISMATCH:{src.streaming}->{dst.streaming}")
    if src.ordering == "unordered" and dst.ordering == "ordered":
        reasons.append("ORDERING_VIOLATION:unordered->ordered")

    prec_err = _check_precision_loss(src, dst)
    if prec_err is not None:
        reasons.append(prec_err)

    if _SENSITIVITY_RANK[src.sensitivity] > _SENSITIVITY_RANK[dst.sensitivity]:
        reasons.append(f"SENSITIVITY_FLOW_VIOLATION:{src.sensitivity}->{dst.sensitivity}")
    if _TRUST_RANK[src.trust_label] < _TRUST_RANK[dst.trust_label]:
        reasons.append(f"TRUST_LABEL_VIOLATION:{src.trust_label}->{dst.trust_label}")
    if src.nullable and not dst.nullable:
        reasons.append("NULLABILITY_VIOLATION:nullable->non_nullable")

    compatible = len(reasons) == 0
    return PortCompatibilityResult(
        compatible=compatible,
        reasons=reasons,
        adapter_required=not compatible,
        score=1.0 if compatible else 0.0,
    )


@dataclass
class EffectContract(_CanonicalContractMixin):
    """Typed side-effect, scope, reversibility, and resource contract (`EffectContract/1`)."""

    read_scopes: List[str] = field(default_factory=list)
    write_scopes: List[str] = field(default_factory=list)
    network_scopes: List[str] = field(default_factory=list)
    exec_permissions: List[str] = field(default_factory=list)
    irreversible: bool = False
    idempotent: bool = True
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    schema: str = "EffectContract/1"

    def __post_init__(self) -> None:
        if self.schema != "EffectContract/1":
            raise ValueError(f"INVALID_SCHEMA: expected EffectContract/1, got '{self.schema}'.")
        self.read_scopes = _validate_str_list(self.read_scopes, field_name="read_scopes", sort_items=True)
        self.write_scopes = _validate_str_list(self.write_scopes, field_name="write_scopes", sort_items=True)
        self.network_scopes = _validate_str_list(self.network_scopes, field_name="network_scopes", sort_items=True)
        self.exec_permissions = _validate_str_list(self.exec_permissions, field_name="exec_permissions", sort_items=True)
        self.irreversible = bool(self.irreversible)
        self.idempotent = bool(self.idempotent)
        self.resource_requirements = _sanitize_mapping(self.resource_requirements, field_name="resource_requirements")

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "read_scopes": list(self.read_scopes),
                "write_scopes": list(self.write_scopes),
                "network_scopes": list(self.network_scopes),
                "exec_permissions": list(self.exec_permissions),
                "irreversible": self.irreversible,
                "idempotent": self.idempotent,
                "resource_requirements": dict(self.resource_requirements),
            }
        )

    @classmethod
    def from_dict(cls, data: Union["EffectContract", Mapping[str, Any]]) -> "EffectContract":
        if isinstance(data, EffectContract):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_EFFECT_CONTRACT: expected mapping.")
        return cls(
            read_scopes=list(data.get("read_scopes", [])),
            write_scopes=list(data.get("write_scopes", [])),
            network_scopes=list(data.get("network_scopes", [])),
            exec_permissions=list(data.get("exec_permissions", [])),
            irreversible=bool(data.get("irreversible", False)),
            idempotent=bool(data.get("idempotent", True)),
            resource_requirements=dict(data.get("resource_requirements", {})),
            schema=data.get("schema", "EffectContract/1"),
        )


def _merge_resource_requirements(effects: Sequence[EffectContract]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for eff in effects:
        for key, raw_val in eff.resource_requirements.items():
            if isinstance(raw_val, bool):
                merged[key] = bool(merged.get(key, False)) or raw_val
            elif isinstance(raw_val, (int, float)):
                if key in _ADDITIVE_RESOURCE_KEYS:
                    merged[key] = merged.get(key, 0) + raw_val
                elif key in _PEAK_RESOURCE_KEYS or key not in merged:
                    merged[key] = max(merged.get(key, raw_val), raw_val)
                else:
                    merged[key] = max(merged[key], raw_val)
            elif key not in merged:
                merged[key] = raw_val
    return merged


def compute_dag_effects(
    effects_list: Sequence[Union[EffectContract, Mapping[str, Any]]],
) -> Dict[str, Any]:
    """Aggregate permissions, effect scopes, reversibility, and idempotency across DAG nodes."""
    normalized = [EffectContract.from_dict(item) for item in effects_list]
    read_union = sorted({scope for eff in normalized for scope in eff.read_scopes})
    write_union = sorted({scope for eff in normalized for scope in eff.write_scopes})
    network_union = sorted({scope for eff in normalized for scope in eff.network_scopes})
    permission_union = sorted({perm for eff in normalized for perm in eff.exec_permissions})
    irreversible_any = any(eff.irreversible for eff in normalized)
    idempotent_all = all(eff.idempotent for eff in normalized)
    merged_resources = _merge_resource_requirements(normalized)

    effects_union = {
        "read_scopes": read_union,
        "write_scopes": write_union,
        "network_scopes": network_union,
        "exec_permissions": permission_union,
        "irreversible": irreversible_any,
        "idempotent": idempotent_all,
        "resource_requirements": merged_resources,
    }
    return {
        "permission_union": permission_union,
        "effects_union": effects_union,
        "irreversible_any": irreversible_any,
        "idempotent_all": idempotent_all,
    }


def _validate_adapter_mapping(
    mapping: Any,
    source_port: PortContract,
    target_port: PortContract,
    unit_conversion: Optional[Dict[str, Any]],
    lossless: bool,
    preconditions: Sequence[str],
) -> Dict[str, Any]:
    if not isinstance(mapping, Mapping) or not mapping:
        raise AbstainError("ABSTAIN: AdapterSpec requires non-empty semantic mapping.")
    cleaned = _sanitize_mapping(mapping, field_name="mapping", allow_empty=False)

    if cleaned.get("ambiguous") is True or str(cleaned.get("status", "")).strip().upper() == "AMBIGUOUS":
        raise AbstainError("ABSTAIN: AdapterSpec mapping explicitly marked ambiguous.")
    if "confidence" in cleaned:
        try:
            conf = float(cleaned["confidence"])
        except (TypeError, ValueError) as exc:
            raise AbstainError("ABSTAIN: invalid adapter mapping confidence.") from exc
        if conf < 1.0:
            raise AbstainError(f"ABSTAIN: ambiguous adapter mapping confidence={conf} < 1.0.")

    def _check_map_entries(entries: Mapping[str, Any], *, is_field_map: bool = False) -> None:
        seen_targets: Dict[str, str] = {}
        for k, v in entries.items():
            key_s = str(k).strip()
            if not key_s:
                raise AbstainError("ABSTAIN: empty mapping key.")
            if v is None:
                raise AbstainError(f"ABSTAIN: missing target mapping for '{key_s}'.")
            if isinstance(v, (list, tuple, set)):
                if len(v) != 1:
                    raise AbstainError(f"ABSTAIN: ambiguous multi-target mapping for '{key_s}'.")
            elif isinstance(v, Mapping):
                if v.get("ambiguous") is True or (
                    isinstance(v.get("candidates"), (list, tuple)) and len(v["candidates"]) > 1
                ):
                    raise AbstainError(f"ABSTAIN: ambiguous candidate mapping for '{key_s}'.")
                target_val = v.get("target") or v.get("to") or v.get("expr") or v.get("transform")
                if target_val is not None and str(target_val).strip().lower() in _AMBIGUOUS_MAP_TOKENS | {""}:
                    raise AbstainError(f"ABSTAIN: unresolved target mapping for '{key_s}'.")
            elif isinstance(v, str):
                v_low = v.strip().lower()
                if not v_low or v_low in _AMBIGUOUS_MAP_TOKENS or " | " in v or " or " in v_low:
                    raise AbstainError(f"ABSTAIN: ambiguous or unresolved mapping value '{v}' for '{key_s}'.")
                if is_field_map or key_s.lower() not in _MAPPING_META_KEYS:
                    if v_low in seen_targets and seen_targets[v_low] != key_s:
                        raise AbstainError(
                            f"ABSTAIN: conflicting sources '{seen_targets[v_low]}' and '{key_s}' -> '{v}'."
                        )
                    seen_targets[v_low] = key_s

    nested_fields = cleaned.get("fields") or cleaned.get("field_map")
    if isinstance(nested_fields, Mapping):
        if not nested_fields:
            raise AbstainError("ABSTAIN: empty field_map in AdapterSpec.")
        _check_map_entries(nested_fields, is_field_map=True)
    else:
        _check_map_entries(cleaned, is_field_map=False)

    src_unit = source_port.unit.lower()
    dst_unit = target_port.unit.lower()
    if src_unit != dst_unit and "none" not in (src_unit, dst_unit):
        if not unit_conversion or not any(
            k in unit_conversion for k in ("factor", "scale", "formula", "expression", "fn")
        ):
            raise AbstainError(
                f"ABSTAIN: unit mismatch ({source_port.unit} -> {target_port.unit}) requires explicit unit_conversion."
            )
        if "from_unit" in unit_conversion and str(unit_conversion["from_unit"]).strip().lower() != src_unit:
            raise AbstainError("ABSTAIN: unit_conversion.from_unit contradicts source_port.unit.")
        if "to_unit" in unit_conversion and str(unit_conversion["to_unit"]).strip().lower() != dst_unit:
            raise AbstainError("ABSTAIN: unit_conversion.to_unit contradicts target_port.unit.")

    if _SENSITIVITY_RANK[source_port.sensitivity] > _SENSITIVITY_RANK[target_port.sensitivity]:
        map_text = canonical_json_dumps({"mapping": cleaned, "preconditions": list(preconditions)}).lower()
        has_declass = any(tok in map_text for tok in _DECLASSIFICATION_HINTS)
        if lossless or not has_declass:
            raise AbstainError(
                f"ABSTAIN: sensitivity downgrade ({source_port.sensitivity} -> {target_port.sensitivity}) "
                "requires lossless=False and explicit redaction/declassification transform."
            )

    return cleaned


def _has_valid_adapter_attestation(attestation: Any, adapter_hash: str, adapter_id: str) -> bool:
    if type(attestation) is not dict or type(adapter_hash) is not str or type(adapter_id) is not str:
        return False
    att_view = safe_exact_str_dict_view(attestation)
    if not att_view:
        return False
    normalized = dict(att_view)
    if "binary_hash" not in normalized and "adapter_hash" in normalized:
        normalized["binary_hash"] = normalized["adapter_hash"]
    if "tool_id" not in normalized and "adapter_id" in normalized:
        normalized["tool_id"] = normalized["adapter_id"]
    raw_callable = normalized.get("callable_hash")
    if raw_callable is not None and raw_callable != "":
        if type(raw_callable) is not str or not is_valid_sha256(raw_callable):
            return False
    raw_sig = normalized.get("signature")
    if raw_sig is not None and type(raw_sig) is not str:
        return False
    return has_valid_verification_attestation(normalized, adapter_hash, adapter_id)


@dataclass
class AdapterSpec(_CanonicalContractMixin):
    """Verified typed port adapter contract (`AdapterSpec/1`)."""

    adapter_id: str
    version: str
    source_port: Union[PortContract, Mapping[str, Any]]
    target_port: Union[PortContract, Mapping[str, Any]]
    mapping: Dict[str, Any]
    unit_conversion: Optional[Dict[str, Any]] = None
    lossless: bool = True
    preconditions: List[str] = field(default_factory=list)
    verification_corpus_hash: str = ""
    adapter_hash: str = ""
    trust_status: Union[TrustStatus, str] = TrustStatus.DISCOVERED
    verification_attestation: Optional[Dict[str, Any]] = None
    schema: str = "AdapterSpec/1"

    def __post_init__(self) -> None:
        if self.schema != "AdapterSpec/1":
            raise ValueError(f"INVALID_SCHEMA: expected AdapterSpec/1, got '{self.schema}'.")
        self.adapter_id = validate_tool_id(self.adapter_id)
        self.version = validate_safe_text(self.version, field_name="version")
        self.source_port = PortContract.from_dict(self.source_port)
        self.target_port = PortContract.from_dict(self.target_port)
        self.lossless = bool(self.lossless)
        self.preconditions = _validate_str_list(self.preconditions, field_name="preconditions")

        if self.unit_conversion is not None:
            self.unit_conversion = _sanitize_mapping(self.unit_conversion, field_name="unit_conversion")
        self.mapping = _validate_adapter_mapping(
            self.mapping,
            self.source_port,
            self.target_port,
            self.unit_conversion,
            self.lossless,
            self.preconditions,
        )

        if self.verification_corpus_hash:
            self.verification_corpus_hash = normalize_sha256(
                self.verification_corpus_hash, field_name="verification_corpus_hash"
            )

        if isinstance(self.trust_status, str):
            self.trust_status = TrustStatus(self.trust_status.strip().upper())
        elif not isinstance(self.trust_status, TrustStatus):
            raise ValueError(f"INVALID_TRUST_STATUS: {self.trust_status!r}")

        if self.verification_attestation is not None:
            self.verification_attestation = _sanitize_mapping(
                self.verification_attestation, field_name="verification_attestation"
            )

        computed_hash = sha256_digest(
            {
                "schema": self.schema,
                "adapter_id": self.adapter_id,
                "version": self.version,
                "source_port": self.source_port.to_dict(),
                "target_port": self.target_port.to_dict(),
                "mapping": self.mapping,
                "unit_conversion": self.unit_conversion,
                "lossless": self.lossless,
                "preconditions": self.preconditions,
                "verification_corpus_hash": self.verification_corpus_hash,
            }
        )
        if self.adapter_hash:
            provided = normalize_sha256(self.adapter_hash, field_name="adapter_hash")
            if not hmac.compare_digest(provided, computed_hash):
                raise ValueError("ADAPTER_HASH_MISMATCH: adapter_hash does not match canonical AdapterSpec.")
            self.adapter_hash = provided
        else:
            self.adapter_hash = computed_hash

        if self.trust_status == TrustStatus.VERIFIED:
            if not self.verification_corpus_hash:
                raise ValueError("REJECTED_UNVERIFIED_ADAPTER: VERIFIED AdapterSpec requires verification_corpus_hash.")
            if not _has_valid_adapter_attestation(
                self.verification_attestation, self.adapter_hash, self.adapter_id
            ):
                raise ValueError("REJECTED_UNVERIFIED_TRUST_ESCALATION: VERIFIED AdapterSpec lacks valid attestation.")

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "adapter_id": self.adapter_id,
                "version": self.version,
                "source_port": self.source_port.to_dict(),
                "target_port": self.target_port.to_dict(),
                "mapping": dict(self.mapping),
                "unit_conversion": dict(self.unit_conversion) if self.unit_conversion is not None else None,
                "lossless": self.lossless,
                "preconditions": list(self.preconditions),
                "verification_corpus_hash": self.verification_corpus_hash,
                "adapter_hash": self.adapter_hash,
                "trust_status": self.trust_status.value,
                "verification_attestation": (
                    dict(self.verification_attestation) if self.verification_attestation is not None else None
                ),
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AdapterSpec":
        if isinstance(data, AdapterSpec):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_ADAPTER_SPEC: expected mapping.")
        return cls(
            adapter_id=data["adapter_id"],
            version=data.get("version", "1.0.0"),
            source_port=data["source_port"],
            target_port=data["target_port"],
            mapping=data["mapping"],
            unit_conversion=data.get("unit_conversion"),
            lossless=bool(data.get("lossless", True)),
            preconditions=list(data.get("preconditions", [])),
            verification_corpus_hash=data.get("verification_corpus_hash", ""),
            adapter_hash=data.get("adapter_hash", ""),
            trust_status=data.get("trust_status", TrustStatus.DISCOVERED),
            verification_attestation=data.get("verification_attestation"),
            schema=data.get("schema", "AdapterSpec/1"),
        )


_CONTRACTS_TYPE_DICT_DESCR = type.__dict__["__dict__"]
_CONTRACTS_OBJECT_GETATTR = object.__getattribute__
_ORIG_CANONICAL_MIXIN_DICT_DESCR = _CONTRACTS_TYPE_DICT_DESCR.__get__(_CanonicalContractMixin, type).get("__dict__")
_ORIG_PORT_CONTRACT_DICT_DESCR = _CONTRACTS_TYPE_DICT_DESCR.__get__(PortContract, type).get("__dict__")
_ORIG_ADAPTER_SPEC_DICT_DESCR = _CONTRACTS_TYPE_DICT_DESCR.__get__(AdapterSpec, type).get("__dict__")
_ORIG_CANONICAL_MIXIN_LIFECYCLE = snapshot_class_lifecycle(_CanonicalContractMixin)
_ORIG_PORT_CONTRACT_LIFECYCLE = snapshot_class_lifecycle(PortContract)
_ORIG_ADAPTER_SPEC_LIFECYCLE = snapshot_class_lifecycle(AdapterSpec)
_ADAPTER_TRUST_IDENTITY_PAIRS: Tuple[Tuple[TrustStatus, str], ...] = tuple(
    (member, member.value) for member in TrustStatus
)
_EXACT_PORT_CONTRACT_FIELDS: Tuple[str, ...] = (
    "schema_ref",
    "semantic_type",
    "encoding",
    "unit",
    "cardinality",
    "ordering",
    "sensitivity",
    "trust_label",
    "streaming",
    "precision",
    "nullable",
    "schema",
)
_EXACT_ADAPTER_SPEC_FIELDS: Tuple[str, ...] = (
    "adapter_id",
    "version",
    "source_port",
    "target_port",
    "mapping",
    "unit_conversion",
    "lossless",
    "preconditions",
    "verification_corpus_hash",
    "adapter_hash",
    "trust_status",
    "verification_attestation",
    "schema",
)


def extract_exact_port_contract_dict(port: Any) -> Dict[str, Any]:
    """Extract clean built-in fields from an exact `PortContract` without running any hooks."""
    if type(port) is not PortContract:
        raise TypeError("UNTRUSTED_PORT_CONTRACT_SUBCLASS_FORBIDDEN")
    assert_dataclass_type_unmodified(
        PortContract,
        _EXACT_PORT_CONTRACT_FIELDS,
        _ORIG_PORT_CONTRACT_DICT_DESCR,
        allowed_base_dict_descrs=(_ORIG_CANONICAL_MIXIN_DICT_DESCR,),
        expected_mro=(PortContract, _CanonicalContractMixin, object),
        orig_lifecycle_methods=_ORIG_PORT_CONTRACT_LIFECYCLE,
        allowed_base_lifecycle_methods=((_CanonicalContractMixin, _ORIG_CANONICAL_MIXIN_LIFECYCLE),),
    )
    view = safe_exact_str_dict_view(_CONTRACTS_OBJECT_GETATTR(port, "__dict__"))
    if view is None:
        raise ValueError("UNTRUSTED_PORT_CONTRACT_STORAGE")
    for k in view:
        if k not in _EXACT_PORT_CONTRACT_FIELDS:
            raise ValueError("UNTRUSTED_PORT_CONTRACT_EXTRA_FIELD")
    for sfield in ("schema_ref", "semantic_type", "encoding", "unit", "cardinality", "ordering", "sensitivity", "trust_label", "schema"):
        if sfield not in view or type(view[sfield]) is not str:
            raise TypeError(f"UNTRUSTED_PORT_CONTRACT_{sfield.upper()}")
    precision = view.get("precision")
    if precision is not None and type(precision) is not str:
        raise TypeError("UNTRUSTED_PORT_CONTRACT_PRECISION")
    streaming = view.get("streaming")
    if streaming is not None and type(streaming) is not bool:
        raise TypeError("UNTRUSTED_PORT_CONTRACT_STREAMING")
    nullable = view.get("nullable")
    if type(nullable) is not bool:
        raise TypeError("UNTRUSTED_PORT_CONTRACT_NULLABLE")
    out: Dict[str, Any] = {
        "schema": view["schema"],
        "schema_ref": view["schema_ref"],
        "semantic_type": view["semantic_type"],
        "encoding": view["encoding"],
        "unit": view["unit"],
        "cardinality": view["cardinality"],
        "ordering": view["ordering"],
        "sensitivity": view["sensitivity"],
        "trust_label": view["trust_label"],
        "streaming": bool(streaming),
    }
    if precision is not None:
        out["precision"] = precision
    if nullable:
        out["nullable"] = True
    return redact_secrets_in_value(out)


def extract_exact_adapter_spec_dict(spec: Any) -> Dict[str, Any]:
    """Extract clean canonical fields from an exact `AdapterSpec` without running any descriptors."""
    if type(spec) is not AdapterSpec:
        raise TypeError("UNTRUSTED_ADAPTER_SPEC_SUBCLASS_FORBIDDEN")
    assert_dataclass_type_unmodified(
        AdapterSpec,
        _EXACT_ADAPTER_SPEC_FIELDS,
        _ORIG_ADAPTER_SPEC_DICT_DESCR,
        allowed_base_dict_descrs=(_ORIG_CANONICAL_MIXIN_DICT_DESCR,),
        expected_mro=(AdapterSpec, _CanonicalContractMixin, object),
        orig_lifecycle_methods=_ORIG_ADAPTER_SPEC_LIFECYCLE,
        allowed_base_lifecycle_methods=((_CanonicalContractMixin, _ORIG_CANONICAL_MIXIN_LIFECYCLE),),
    )
    view = safe_exact_str_dict_view(_CONTRACTS_OBJECT_GETATTR(spec, "__dict__"))
    if view is None:
        raise ValueError("UNTRUSTED_ADAPTER_SPEC_STORAGE")
    for k in view:
        if k not in _EXACT_ADAPTER_SPEC_FIELDS:
            raise ValueError("UNTRUSTED_ADAPTER_SPEC_EXTRA_FIELD")
    for sfield in ("adapter_id", "version", "verification_corpus_hash", "adapter_hash", "schema"):
        if sfield not in view or type(view[sfield]) is not str:
            raise TypeError(f"UNTRUSTED_ADAPTER_SPEC_{sfield.upper()}")
    if type(view.get("lossless")) is not bool:
        raise TypeError("UNTRUSTED_ADAPTER_SPEC_LOSSLESS")
    source_port = extract_exact_port_contract_dict(view.get("source_port"))
    target_port = extract_exact_port_contract_dict(view.get("target_port"))
    mapping_clean = sanitize_exact_json_value(view.get("mapping"), allow_bytes=False)
    if type(mapping_clean) is not dict:
        raise TypeError("UNTRUSTED_ADAPTER_SPEC_MAPPING")
    unit_raw = view.get("unit_conversion")
    unit_clean = None if unit_raw is None else sanitize_exact_json_value(unit_raw, allow_bytes=False)
    if unit_clean is not None and type(unit_clean) is not dict:
        raise TypeError("UNTRUSTED_ADAPTER_SPEC_UNIT_CONVERSION")
    preconditions = extract_exact_str_list(view.get("preconditions"), field_name="preconditions")
    raw_trust = view.get("trust_status")
    trust_str: Optional[str] = None
    for member, member_val in _ADAPTER_TRUST_IDENTITY_PAIRS:
        if raw_trust is member:
            trust_str = member_val
            break
    if trust_str is None:
        if type(raw_trust) is str:
            trust_str = raw_trust
        else:
            raise TypeError("UNTRUSTED_ADAPTER_SPEC_TRUST_STATUS")
    att_raw = view.get("verification_attestation")
    att_clean = None if att_raw is None else sanitize_exact_json_value(att_raw, allow_bytes=False)
    if att_clean is not None and type(att_clean) is not dict:
        raise TypeError("UNTRUSTED_ADAPTER_SPEC_VERIFICATION_ATTESTATION")
    return redact_secrets_in_value(
        {
            "schema": view["schema"],
            "adapter_id": view["adapter_id"],
            "version": view["version"],
            "source_port": source_port,
            "target_port": target_port,
            "mapping": mapping_clean,
            "unit_conversion": unit_clean,
            "lossless": view["lossless"],
            "preconditions": preconditions,
            "verification_corpus_hash": view["verification_corpus_hash"],
            "adapter_hash": view["adapter_hash"],
            "trust_status": trust_str,
            "verification_attestation": att_clean,
        }
    )


def _validate_dag_structure(nodes: Sequence[Dict[str, Any]], edges: Sequence[Dict[str, Any]]) -> None:
    node_ids: List[str] = []
    seen: set[str] = set()
    for node in nodes:
        nid = validate_safe_text(node.get("node_id"), field_name="node_id")
        if nid in seen:
            raise ValueError(f"INVALID_COMPOSITION_DAG: duplicate node_id '{nid}'.")
        seen.add(nid)
        node_ids.append(nid)
        validate_safe_text(node.get("tool_id"), field_name="tool_id")

    adj: Dict[str, List[str]] = {nid: [] for nid in node_ids}
    indegree: Dict[str, int] = {nid: 0 for nid in node_ids}
    for edge in edges:
        src = validate_safe_text(edge.get("from_node"), field_name="from_node")
        dst = validate_safe_text(edge.get("to_node"), field_name="to_node")
        if src not in seen or dst not in seen:
            raise ValueError(f"INVALID_COMPOSITION_DAG: edge ({src} -> {dst}) references unknown node.")
        if src == dst:
            raise ValueError(f"INVALID_COMPOSITION_DAG: self-loop on '{src}' forbidden.")
        adj[src].append(dst)
        indegree[dst] += 1

    queue = deque(nid for nid in node_ids if indegree[nid] == 0)
    visited = 0
    for _ in range(len(node_ids) + 1):
        if not queue:
            break
        cur = queue.popleft()
        visited += 1
        for nxt in adj[cur]:
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)
    if visited != len(node_ids):
        raise ValueError("INVALID_COMPOSITION_DAG: cycle detected in plan edges.")


@dataclass
class CompositionPlan(_CanonicalContractMixin):
    """Content-addressed bounded DAG composition plan (`CompositionPlan/1`)."""

    plan_id: str
    goal_contract_hash: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]] = field(default_factory=list)
    input_bindings: Dict[str, Any] = field(default_factory=dict)
    tool_artifact_hashes: Dict[str, str] = field(default_factory=dict)
    adapter_hashes: Dict[str, str] = field(default_factory=dict)
    permission_union: List[str] = field(default_factory=list)
    effects_union: Dict[str, Any] = field(default_factory=dict)
    expected_outputs: Union[List[Dict[str, Any]], Dict[str, Any]] = field(default_factory=list)
    oracle_ref: str = ""
    verification_plan: Dict[str, Any] = field(default_factory=dict)
    estimated_resources: Dict[str, Any] = field(default_factory=dict)
    plan_hash: str = ""
    gap_id: Optional[str] = None
    profile: Optional[str] = None
    max_depth: Optional[int] = None
    security_checks: Optional[Dict[str, Any]] = None
    created_at: Optional[str] = None
    schema: str = "CompositionPlan/1"

    def __post_init__(self) -> None:
        if self.schema != "CompositionPlan/1":
            raise ValueError(f"INVALID_SCHEMA: expected CompositionPlan/1, got '{self.schema}'.")
        self.plan_id = _validate_safe_id(self.plan_id, field_name="plan_id")
        self.goal_contract_hash = normalize_sha256(self.goal_contract_hash, field_name="goal_contract_hash")
        self.oracle_ref = validate_safe_text(self.oracle_ref, field_name="oracle_ref")

        if not isinstance(self.nodes, (list, tuple)) or not self.nodes:
            raise ValueError("INVALID_NODES: CompositionPlan requires at least one node.")
        self.nodes = [_sanitize_mapping(node, field_name="nodes", allow_empty=False) for node in self.nodes]
        if not isinstance(self.edges, (list, tuple)):
            raise ValueError("INVALID_EDGES: expected sequence of edge mappings.")
        self.edges = [_sanitize_mapping(edge, field_name="edges", allow_empty=False) for edge in self.edges]
        _validate_dag_structure(self.nodes, self.edges)

        self.input_bindings = _sanitize_mapping(self.input_bindings, field_name="input_bindings")
        self.tool_artifact_hashes = {
            validate_tool_id(k): normalize_sha256(v, field_name="tool_artifact_hash")
            for k, v in dict(self.tool_artifact_hashes or {}).items()
        }
        self.adapter_hashes = {
            validate_tool_id(k): normalize_sha256(v, field_name="adapter_hash")
            for k, v in dict(self.adapter_hashes or {}).items()
        }
        self.permission_union = _validate_str_list(
            self.permission_union, field_name="permission_union", sort_items=True
        )
        if isinstance(self.effects_union, EffectContract):
            eff_dict = self.effects_union.to_dict()
            eff_dict.pop("schema", None)
            self.effects_union = eff_dict
        else:
            self.effects_union = _sanitize_mapping(self.effects_union, field_name="effects_union")

        if isinstance(self.expected_outputs, Mapping):
            self.expected_outputs = _sanitize_mapping(self.expected_outputs, field_name="expected_outputs")
        elif isinstance(self.expected_outputs, (list, tuple)):
            clean_outputs = redact_secrets_in_value(list(self.expected_outputs))
            _validate_structure_hygiene(clean_outputs, field_name="expected_outputs")
            self.expected_outputs = clean_outputs
        else:
            raise ValueError("INVALID_EXPECTED_OUTPUTS: expected list or dict.")

        self.verification_plan = _sanitize_mapping(self.verification_plan, field_name="verification_plan")
        self.estimated_resources = _sanitize_mapping(self.estimated_resources, field_name="estimated_resources")
        if self.security_checks is not None:
            self.security_checks = _sanitize_mapping(self.security_checks, field_name="security_checks")
        if self.gap_id is not None:
            self.gap_id = _validate_safe_id(self.gap_id, field_name="gap_id")
        if self.profile is not None:
            self.profile = validate_safe_text(self.profile, field_name="profile").upper()
        if self.created_at is not None:
            self.created_at = validate_safe_text(self.created_at, field_name="created_at")

        computed_hash = sha256_digest(self._canonical_hash_basis())
        if self.plan_hash:
            provided = normalize_sha256(self.plan_hash, field_name="plan_hash")
            if not hmac.compare_digest(provided, computed_hash):
                raise ValueError("PLAN_HASH_MISMATCH: plan_hash does not match deterministic CompositionPlan digest.")
            self.plan_hash = provided
        else:
            self.plan_hash = computed_hash

    def _canonical_hash_basis(self) -> Dict[str, Any]:
        basis: Dict[str, Any] = {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "goal_contract_hash": self.goal_contract_hash,
            "nodes": list(self.nodes),
            "edges": list(self.edges),
            "input_bindings": dict(self.input_bindings),
            "tool_artifact_hashes": dict(self.tool_artifact_hashes),
            "adapter_hashes": dict(self.adapter_hashes),
            "permission_union": list(self.permission_union),
            "effects_union": dict(self.effects_union),
            "expected_outputs": (
                dict(self.expected_outputs)
                if isinstance(self.expected_outputs, Mapping)
                else list(self.expected_outputs)
            ),
            "oracle_ref": self.oracle_ref,
            "verification_plan": dict(self.verification_plan),
            "estimated_resources": dict(self.estimated_resources),
        }
        for opt_key in ("gap_id", "profile", "max_depth", "security_checks", "created_at"):
            val = getattr(self, opt_key)
            if val is not None:
                basis[opt_key] = val
        return basis

    def to_dict(self) -> Dict[str, Any]:
        payload = self._canonical_hash_basis()
        payload["plan_hash"] = self.plan_hash
        return redact_secrets_in_value(payload)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompositionPlan":
        if isinstance(data, CompositionPlan):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_COMPOSITION_PLAN: expected mapping.")
        return cls(
            plan_id=data["plan_id"],
            goal_contract_hash=data["goal_contract_hash"],
            nodes=list(data["nodes"]),
            edges=list(data.get("edges", [])),
            input_bindings=dict(data.get("input_bindings", {})),
            tool_artifact_hashes=dict(data.get("tool_artifact_hashes", {})),
            adapter_hashes=dict(data.get("adapter_hashes", {})),
            permission_union=list(data.get("permission_union", [])),
            effects_union=dict(data.get("effects_union", {})),
            expected_outputs=data.get("expected_outputs", []),
            oracle_ref=data["oracle_ref"],
            verification_plan=dict(data.get("verification_plan", {})),
            estimated_resources=dict(data.get("estimated_resources", {})),
            plan_hash=data.get("plan_hash", ""),
            gap_id=data.get("gap_id"),
            profile=data.get("profile"),
            max_depth=data.get("max_depth"),
            security_checks=data.get("security_checks"),
            created_at=data.get("created_at"),
            schema=data.get("schema", "CompositionPlan/1"),
        )


@dataclass
class CompositionReceipt(_CanonicalContractMixin):
    """Cryptographically bound composition DAG receipt (`CompositionReceipt/1`)."""

    run_id: str
    plan_hash: str
    policy_hash: str
    sandbox_environment_hash: str
    node_receipts: List[Dict[str, Any]] = field(default_factory=list)
    unresolved_nodes: List[str] = field(default_factory=list)
    input_digest: str = ""
    output_digest: str = ""
    oracle_result: Dict[str, Any] = field(default_factory=dict)
    verification_status: str = "NOT_VERIFIED"
    trace_digest: str = ""
    status: Union[ExecutionStatus, str] = ExecutionStatus.NOT_VERIFIED
    schema: str = "CompositionReceipt/1"

    def __post_init__(self) -> None:
        if self.schema != "CompositionReceipt/1":
            raise ValueError(f"INVALID_SCHEMA: expected CompositionReceipt/1, got '{self.schema}'.")
        self.run_id = _validate_safe_id(self.run_id, field_name="run_id")
        self.plan_hash = normalize_sha256(self.plan_hash, field_name="plan_hash")
        self.policy_hash = normalize_sha256(self.policy_hash, field_name="policy_hash")
        self.sandbox_environment_hash = normalize_sha256(
            self.sandbox_environment_hash, field_name="sandbox_environment_hash"
        )
        self.input_digest = (
            normalize_sha256(self.input_digest, field_name="input_digest")
            if self.input_digest
            else sha256_digest("")
        )
        self.output_digest = (
            normalize_sha256(self.output_digest, field_name="output_digest")
            if self.output_digest
            else sha256_digest("")
        )

        if isinstance(self.status, str):
            norm_status = self.status.strip().upper()
            if norm_status not in VALID_EXECUTION_STATUSES:
                raise ValueError(f"INVALID_EXECUTION_STATUS: {self.status!r}")
            self.status = ExecutionStatus(norm_status)
        elif not isinstance(self.status, ExecutionStatus):
            raise ValueError(f"INVALID_EXECUTION_STATUS: {self.status!r}")

        self.verification_status = validate_safe_text(self.verification_status, field_name="verification_status")
        self.oracle_result = _sanitize_mapping(self.oracle_result, field_name="oracle_result")

        if self.status == ExecutionStatus.PASS:
            if self.verification_status.upper() in {"FAIL", "FAILED", "NOT_VERIFIED", "INSUFFICIENT_EVIDENCE"}:
                raise ValueError(
                    f"INVALID_PASS_RECEIPT: PASS cannot have verification_status '{self.verification_status}'."
                )
            if self.oracle_result.get("passed") is False:
                raise ValueError("INVALID_PASS_RECEIPT: PASS cannot have oracle_result.passed=False.")

        clean_nodes: List[Dict[str, Any]] = []
        for item in self.node_receipts or ():
            raw_item = item.to_dict() if hasattr(item, "to_dict") and callable(item.to_dict) else item
            clean_nodes.append(_sanitize_mapping(raw_item, field_name="node_receipts", allow_empty=False))
        self.node_receipts = clean_nodes
        self.unresolved_nodes = [
            _validate_safe_id(str(node_id), field_name="unresolved_node_id")
            for node_id in self.unresolved_nodes
        ]
        if len(set(self.unresolved_nodes)) != len(self.unresolved_nodes):
            raise ValueError("DUPLICATE_UNRESOLVED_NODE_ID")

        if self.trace_digest:
            self.trace_digest = normalize_sha256(self.trace_digest, field_name="trace_digest")
        else:
            trace_payload = {
                "schema": self.schema,
                "run_id": self.run_id,
                "plan_hash": self.plan_hash,
                "policy_hash": self.policy_hash,
                "sandbox_environment_hash": self.sandbox_environment_hash,
                "input_digest": self.input_digest,
                "output_digest": self.output_digest,
                "node_receipts": self.node_receipts,
                "oracle_result": self.oracle_result,
                "verification_status": self.verification_status,
                "status": self.status.value,
            }
            # Preserve existing receipt hashes when there is no unresolved step.
            if self.unresolved_nodes:
                trace_payload["unresolved_nodes"] = self.unresolved_nodes
            self.trace_digest = sha256_digest(trace_payload)

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "run_id": self.run_id,
                "plan_hash": self.plan_hash,
                "policy_hash": self.policy_hash,
                "sandbox_environment_hash": self.sandbox_environment_hash,
                "node_receipts": list(self.node_receipts),
                "unresolved_nodes": list(self.unresolved_nodes),
                "input_digest": self.input_digest,
                "output_digest": self.output_digest,
                "oracle_result": dict(self.oracle_result),
                "verification_status": self.verification_status,
                "trace_digest": self.trace_digest,
                "status": self.status.value,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompositionReceipt":
        if isinstance(data, CompositionReceipt):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_COMPOSITION_RECEIPT: expected mapping.")
        return cls(
            run_id=data["run_id"],
            plan_hash=data["plan_hash"],
            policy_hash=data["policy_hash"],
            sandbox_environment_hash=data["sandbox_environment_hash"],
            node_receipts=list(data.get("node_receipts", [])),
            unresolved_nodes=list(data.get("unresolved_nodes", [])),
            input_digest=data.get("input_digest", ""),
            output_digest=data.get("output_digest", ""),
            oracle_result=dict(data.get("oracle_result", {})),
            verification_status=data.get("verification_status", "NOT_VERIFIED"),
            trace_digest=data.get("trace_digest", ""),
            status=data.get("status", ExecutionStatus.NOT_VERIFIED),
            schema=data.get("schema", "CompositionReceipt/1"),
        )


@dataclass
class ToolBuild(_CanonicalContractMixin):
    """Monotonic forge provenance and verification record (`ToolBuild/1`)."""

    build_id: str
    tool_id: str
    tool_version: str = "1.0.0"
    state: Union[ForgeState, str] = ForgeState.PROPOSED
    source_hash: str = ""
    oracle_hash: str = ""
    unit_test_digest: str = ""
    differential_digest: str = ""
    fuzz_digest: str = ""
    boundary_digest: str = ""
    compiler: str = ""
    compiler_version: str = ""
    flags: List[str] = field(default_factory=list)
    artifact_hash: str = ""
    sandbox_receipt: Dict[str, Any] = field(default_factory=dict)
    benchmark_vs_baseline: Dict[str, Any] = field(default_factory=dict)
    rollback_metadata: Dict[str, Any] = field(default_factory=dict)
    gap_id: Optional[str] = None
    profile: Optional[str] = None
    language: Optional[str] = None
    built_at: Optional[str] = None
    build_hash: Optional[str] = None
    schema: str = "ToolBuild/1"

    def __post_init__(self) -> None:
        if self.schema != "ToolBuild/1":
            raise ValueError(f"INVALID_SCHEMA: expected ToolBuild/1, got '{self.schema}'.")
        self.build_id = _validate_safe_id(self.build_id, field_name="build_id")
        self.tool_id = validate_tool_id(self.tool_id)
        self.tool_version = validate_safe_text(self.tool_version, field_name="tool_version")
        self.state = _coerce_forge_state(self.state)

        for hash_field in (
            "source_hash",
            "oracle_hash",
            "unit_test_digest",
            "differential_digest",
            "fuzz_digest",
            "boundary_digest",
            "artifact_hash",
        ):
            val = getattr(self, hash_field)
            if val:
                setattr(self, hash_field, normalize_sha256(val, field_name=hash_field))
            else:
                setattr(self, hash_field, "")

        self.compiler = validate_safe_text(self.compiler, field_name="compiler", allow_empty=True)
        self.compiler_version = validate_safe_text(
            self.compiler_version, field_name="compiler_version", allow_empty=True
        )
        self.flags = _validate_str_list(self.flags, field_name="flags")
        self.sandbox_receipt = _sanitize_mapping(self.sandbox_receipt, field_name="sandbox_receipt")
        self.benchmark_vs_baseline = _sanitize_mapping(
            self.benchmark_vs_baseline, field_name="benchmark_vs_baseline"
        )
        self.rollback_metadata = _sanitize_mapping(self.rollback_metadata, field_name="rollback_metadata")

        if self.gap_id is not None:
            self.gap_id = _validate_safe_id(self.gap_id, field_name="gap_id")
        if self.profile is not None:
            self.profile = validate_safe_text(self.profile, field_name="profile").upper()
        if self.language is not None:
            self.language = validate_safe_text(self.language, field_name="language").lower()
        if self.built_at is not None:
            self.built_at = validate_safe_text(self.built_at, field_name="built_at")
        if self.build_hash is not None:
            self.build_hash = normalize_sha256(self.build_hash, field_name="build_hash")

        self._enforce_stage_provenance()

    def _enforce_stage_provenance(self) -> None:
        stage_idx = _FORGE_STAGE_INDEX.get(self.state)
        if stage_idx is None:
            return
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.REFERENCE_VERIFIED] and not self.oracle_hash:
            raise ValueError("MISSING_PROVENANCE: oracle_hash required at REFERENCE_VERIFIED+.")
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.GENERATED] and not self.source_hash:
            raise ValueError("MISSING_PROVENANCE: source_hash required at GENERATED+.")
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.COMPILED]:
            if not self.compiler or not self.compiler_version or not self.artifact_hash:
                raise ValueError("MISSING_PROVENANCE: compiler, compiler_version, and artifact_hash required at COMPILED+.")
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.SANDBOX_TESTED]:
            if not self.unit_test_digest or not self.sandbox_receipt:
                raise ValueError("MISSING_PROVENANCE: unit_test_digest and sandbox_receipt required at SANDBOX_TESTED+.")
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.DIFFERENTIAL_VERIFIED]:
            if not self.differential_digest or not self.fuzz_digest or not self.boundary_digest:
                raise ValueError(
                    "MISSING_PROVENANCE: differential_digest, fuzz_digest, and boundary_digest required at DIFFERENTIAL_VERIFIED+."
                )
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.BENCHMARKED] and not self.benchmark_vs_baseline:
            raise ValueError("MISSING_PROVENANCE: benchmark_vs_baseline required at BENCHMARKED+.")
        if stage_idx >= _FORGE_STAGE_INDEX[ForgeState.SHADOW] and not self.rollback_metadata:
            raise ValueError("MISSING_PROVENANCE: rollback_metadata required at SHADOW/VERIFIED.")
        if self.state == ForgeState.VERIFIED:
            sb_status = str(self.sandbox_receipt.get("status", "")).strip().upper()
            if sb_status == "FAIL" or self.sandbox_receipt.get("passed") is False:
                raise ValueError("INVALID_VERIFIED_BUILD: sandbox_receipt indicates failure.")
            if self.benchmark_vs_baseline.get("passed") is False or self.benchmark_vs_baseline.get("regressed") is True:
                raise ValueError("INVALID_VERIFIED_BUILD: benchmark_vs_baseline indicates regression.")

    def transition_to(self, next_state: Union[ForgeState, str], **updates: Any) -> "ToolBuild":
        """Transition strictly by one valid monotonic step (or REJECTED/ROLLED_BACK) with updated provenance."""
        validated_next = validate_forge_transition(self.state, next_state)
        payload = self.to_dict()
        payload.update(updates)
        payload["state"] = validated_next.value
        return ToolBuild.from_dict(payload)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema": self.schema,
            "build_id": self.build_id,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "state": self.state.value,
            "source_hash": self.source_hash,
            "oracle_hash": self.oracle_hash,
            "unit_test_digest": self.unit_test_digest,
            "differential_digest": self.differential_digest,
            "fuzz_digest": self.fuzz_digest,
            "boundary_digest": self.boundary_digest,
            "compiler": self.compiler,
            "compiler_version": self.compiler_version,
            "flags": list(self.flags),
            "artifact_hash": self.artifact_hash,
            "sandbox_receipt": dict(self.sandbox_receipt),
            "benchmark_vs_baseline": dict(self.benchmark_vs_baseline),
            "rollback_metadata": dict(self.rollback_metadata),
        }
        for opt_key in ("gap_id", "profile", "language", "built_at", "build_hash"):
            val = getattr(self, opt_key)
            if val is not None:
                payload[opt_key] = val
        return redact_secrets_in_value(payload)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ToolBuild":
        if isinstance(data, ToolBuild):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_TOOL_BUILD: expected mapping.")
        return cls(
            build_id=data["build_id"],
            tool_id=data["tool_id"],
            tool_version=data.get("tool_version", "1.0.0"),
            state=data.get("state", ForgeState.PROPOSED),
            source_hash=data.get("source_hash", ""),
            oracle_hash=data.get("oracle_hash", ""),
            unit_test_digest=data.get("unit_test_digest", ""),
            differential_digest=data.get("differential_digest", ""),
            fuzz_digest=data.get("fuzz_digest", ""),
            boundary_digest=data.get("boundary_digest", ""),
            compiler=data.get("compiler", ""),
            compiler_version=data.get("compiler_version", ""),
            flags=list(data.get("flags", [])),
            artifact_hash=data.get("artifact_hash", ""),
            sandbox_receipt=dict(data.get("sandbox_receipt", {})),
            benchmark_vs_baseline=dict(data.get("benchmark_vs_baseline", {})),
            rollback_metadata=dict(data.get("rollback_metadata", {})),
            gap_id=data.get("gap_id"),
            profile=data.get("profile"),
            language=data.get("language"),
            built_at=data.get("built_at"),
            build_hash=data.get("build_hash"),
            schema=data.get("schema", "ToolBuild/1"),
        )


@dataclass
class RunEvent(_CanonicalContractMixin):
    """Append-only hash-chained execution telemetry event (`RunEvent/1`)."""

    run_id: str
    step_id: str
    state: str
    tool_id: str = ""
    input_digest: str = ""
    output_digest: str = ""
    elapsed_ms: float = 0.0
    tokens_used: int = 0
    resource_usage: Dict[str, Any] = field(default_factory=dict)
    decision_reason: str = ""
    prev_event_hash: str = GENESIS_EVENT_HASH
    event_hash: str = ""
    event_id: Optional[str] = None
    seq: Optional[int] = None
    timestamp: Optional[str] = None
    profile: Optional[str] = None
    component: Optional[str] = None
    severity: Optional[str] = None
    correlation: Optional[Dict[str, Any]] = None
    schema: str = "RunEvent/1"

    def __post_init__(self) -> None:
        if self.schema != "RunEvent/1":
            raise ValueError(f"INVALID_SCHEMA: expected RunEvent/1, got '{self.schema}'.")
        self.run_id = _validate_safe_id(self.run_id, field_name="run_id")
        self.step_id = validate_safe_text(str(self.step_id), field_name="step_id")
        self.state = validate_safe_text(self.state, field_name="state")
        self.tool_id = validate_tool_id(self.tool_id) if self.tool_id else ""
        self.input_digest = (
            normalize_sha256(self.input_digest, field_name="input_digest")
            if self.input_digest
            else sha256_digest("")
        )
        self.output_digest = (
            normalize_sha256(self.output_digest, field_name="output_digest")
            if self.output_digest
            else sha256_digest("")
        )
        self.elapsed_ms = float(self.elapsed_ms)
        self.tokens_used = int(self.tokens_used)
        if self.elapsed_ms < 0 or self.tokens_used < 0:
            raise ValueError("INVALID_TELEMETRY_METRICS: elapsed_ms and tokens_used must be >= 0.")
        self.resource_usage = _sanitize_mapping(self.resource_usage, field_name="resource_usage")
        self.decision_reason = redact_secrets_in_text(
            validate_safe_text(self.decision_reason, field_name="decision_reason", allow_empty=True)
        )
        self.prev_event_hash = (
            normalize_sha256(self.prev_event_hash, field_name="prev_event_hash")
            if self.prev_event_hash
            else GENESIS_EVENT_HASH
        )

        if self.event_id is not None:
            self.event_id = _validate_safe_id(self.event_id, field_name="event_id")
        if self.timestamp is not None:
            self.timestamp = validate_safe_text(self.timestamp, field_name="timestamp")
        if self.profile is not None:
            self.profile = validate_safe_text(self.profile, field_name="profile").upper()
        if self.component is not None:
            self.component = validate_safe_text(self.component, field_name="component")
        if self.severity is not None:
            self.severity = validate_safe_text(self.severity, field_name="severity").upper()
        if self.correlation is not None:
            self.correlation = _sanitize_mapping(self.correlation, field_name="correlation")

        computed = self.compute_event_hash()
        if self.event_hash:
            provided = normalize_sha256(self.event_hash, field_name="event_hash")
            if not hmac.compare_digest(provided, computed):
                raise ValueError("EVENT_HASH_MISMATCH: RunEvent event_hash does not match canonical digest.")
            self.event_hash = provided
        else:
            self.event_hash = computed

    def _canonical_event_basis(self) -> Dict[str, Any]:
        basis: Dict[str, Any] = {
            "schema": self.schema,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "state": self.state,
            "tool_id": self.tool_id,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "elapsed_ms": self.elapsed_ms,
            "tokens_used": self.tokens_used,
            "resource_usage": dict(self.resource_usage),
            "decision_reason": self.decision_reason,
            "prev_event_hash": self.prev_event_hash,
        }
        for opt_key in ("event_id", "seq", "timestamp", "profile", "component", "severity", "correlation"):
            val = getattr(self, opt_key)
            if val is not None:
                basis[opt_key] = val
        return redact_secrets_in_value(basis)

    def compute_event_hash(self) -> str:
        return sha256_digest(self._canonical_event_basis())

    def to_dict(self) -> Dict[str, Any]:
        payload = self._canonical_event_basis()
        payload["event_hash"] = self.event_hash
        return redact_secrets_in_value(payload)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RunEvent":
        if isinstance(data, RunEvent):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_RUN_EVENT: expected mapping.")
        return cls(
            run_id=data["run_id"],
            step_id=data["step_id"],
            state=data["state"],
            tool_id=data.get("tool_id", ""),
            input_digest=data.get("input_digest", ""),
            output_digest=data.get("output_digest", ""),
            elapsed_ms=data.get("elapsed_ms", 0.0),
            tokens_used=data.get("tokens_used", 0),
            resource_usage=dict(data.get("resource_usage", {})),
            decision_reason=data.get("decision_reason", ""),
            prev_event_hash=data.get("prev_event_hash", GENESIS_EVENT_HASH),
            event_hash=data.get("event_hash", ""),
            event_id=data.get("event_id"),
            seq=data.get("seq"),
            timestamp=data.get("timestamp"),
            profile=data.get("profile"),
            component=data.get("component"),
            severity=data.get("severity"),
            correlation=data.get("correlation"),
            schema=data.get("schema", "RunEvent/1"),
        )


@dataclass
class EventChainVerificationResult:
    """Verification verdict for `verify_event_chain(events)`."""

    valid: bool
    checked_count: int = 0
    reasons: List[str] = field(default_factory=list)
    head_hash: str = ""

    @property
    def ok(self) -> bool:
        return self.valid

    def __bool__(self) -> bool:
        return self.valid

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "ok": self.ok,
            "checked_count": self.checked_count,
            "reasons": list(self.reasons),
            "head_hash": self.head_hash,
        }


def verify_event_chain(
    events: Sequence[Union[RunEvent, Mapping[str, Any]]],
) -> EventChainVerificationResult:
    """Verify append-only `RunEvent/1` hash chain integrity, linkage, and secret hygiene."""
    reasons: List[str] = []
    expected_prev = GENESIS_EVENT_HASH
    expected_run_id: Optional[str] = None
    checked = 0
    head_hash = ""

    for idx, raw_ev in enumerate(events):
        try:
            if isinstance(raw_ev, RunEvent):
                ev_dict = raw_ev.to_dict()
                reconstructed = RunEvent.from_dict(ev_dict)
            elif isinstance(raw_ev, Mapping):
                ev_dict = dict(raw_ev)
                reconstructed = RunEvent.from_dict(ev_dict)
            else:
                reasons.append(f"INVALID_EVENT_TYPE:idx={idx}")
                break
        except (ValueError, KeyError, TypeError) as exc:
            reasons.append(f"EVENT_VALIDATION_FAILED:idx={idx}:{exc}")
            break

        raw_hash = str(ev_dict.get("event_hash", "")).strip().lower()
        if not is_valid_sha256(raw_hash) or not hmac.compare_digest(raw_hash, reconstructed.compute_event_hash()):
            reasons.append(f"EVENT_HASH_MISMATCH:idx={idx}")
            break

        if expected_run_id is None:
            expected_run_id = reconstructed.run_id
        elif reconstructed.run_id != expected_run_id:
            reasons.append(f"RUN_ID_MISMATCH:idx={idx}")
            break

        if not hmac.compare_digest(reconstructed.prev_event_hash, expected_prev):
            reasons.append(f"PREV_EVENT_HASH_MISMATCH:idx={idx}")
            break

        try:
            assert_no_raw_secrets(canonical_json_dumps(ev_dict), context=f"RunEvent[{idx}]")
        except ValueError as exc:
            reasons.append(f"EVENT_SECRET_LEAK:idx={idx}:{exc}")
            break

        expected_prev = reconstructed.event_hash
        head_hash = reconstructed.event_hash
        checked += 1

    return EventChainVerificationResult(
        valid=len(reasons) == 0,
        checked_count=checked,
        reasons=reasons,
        head_hash=head_hash,
    )


__all__ = [
    "GENESIS_EVENT_HASH",
    "VALID_CARDINALITIES",
    "VALID_ORDERINGS",
    "VALID_SENSITIVITIES",
    "VALID_TRUST_LABELS",
    "AbstainError",
    "ForgeState",
    "FORGE_STAGE_ORDER",
    "validate_forge_transition",
    "PortContract",
    "PortCompatibilityResult",
    "ports_compatible",
    "EffectContract",
    "compute_dag_effects",
    "AdapterSpec",
    "CompositionPlan",
    "CompositionReceipt",
    "ToolBuild",
    "RunEvent",
    "EventChainVerificationResult",
    "verify_event_chain",
]
