"""AdapterSynthesizer (`kintsugi.composition.adapter_synthesizer`): Tiered deterministic port adapter synthesizer.

Implements Build #2 tiered adapter resolution and synthesis:
  Tier 1: Lookup and re-verify a stored `AdapterSpec/1` from trusted `AdapterCatalog`.
  Tier 2: Deterministically synthesize `AdapterSpec/1` + pure-Python executable
          callable across format bridges (`bytes -> jsonl <-> typed_event_stream <-> csv`),
          exact unit scaling (`ns <-> us <-> ms <-> s`), field renames, and nested
          projections, then build and run an independent positive + negative fixture
          suite through `AdapterOracleVerifier`.
  Tier 3: Explicitly abstain (`AdapterProposalStatus.ABSTAIN` / `AbstainError`) when
          semantic types are ambiguous, target fields are unknown, lossless mapping
          cannot be proven, or the sensitivity/trust lattice would be violated.
"""

from __future__ import annotations

import copy
import csv
import hmac
import io
import json
from collections.abc import Iterator as IteratorABC
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass, field
from decimal import Decimal, localcontext
from enum import Enum
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.contracts_v2 import (
    AbstainError,
    AdapterSpec,
    PortCompatibilityResult,
    PortContract,
    ports_compatible,
)
from kintsugi.capability.schemas import (
    TrustStatus,
    canonical_json_dumps,
    has_valid_verification_attestation,
    is_valid_sha256,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.capability.tool_registry import AttestationAuthority
from kintsugi.runtime.secure_runner import compute_callable_sha256
from kintsugi.shield import assert_not_symlink, atomic_write_json
from kintsugi.tools.tool_wire import (
    CANONICAL_TIME_UNITS,
    TIME_UNIT_NS_FACTORS,
    DeclassificationGrant,
    LossyConversionError,
    ToolWire,
    ToolWireError,
    WireFormat,
    decode_json_exact,
    encode_json_exact,
    extract_nested_path,
    set_nested_path,
)

ADAPTER_SYNTHESIZER_VERSION = "1.0.0"
DEFAULT_ORACLE_VERIFIER_ID = "kintsugi.composition_oracle"

_AMBIGUOUS_SEMANTIC_TOKENS = frozenset(
    {"?", "tbd", "unknown", "ambiguous", "multiple", "any", "mixed", "unspecified", "misc", "other"}
)
_SENSITIVITY_RANK: Dict[str, int] = {"public": 0, "internal": 1, "secret": 2}
_TRUST_RANK: Dict[str, int] = {"untrusted": 0, "derived": 1, "trusted": 2}
_DECIMAL_PRECISION_TOKENS = frozenset({"decimal", "decimal64", "decimal128", "numeric", "exact_decimal", "exact"})
_INT_PRECISION_TOKENS = frozenset(
    {"int", "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64"}
)
_VALID_WIRE_ENCODINGS = frozenset({"utf-8", "utf8", "ascii", "jsonl", "csv", "bytes", "typed_event_stream"})
_WIRE_FORMAT_ALIASES: Dict[str, str] = {
    "bytes": "bytes", "raw_bytes": "bytes", "application/octet-stream": "bytes",
    "jsonl": "jsonl", "ndjson": "jsonl", "application/jsonl": "jsonl", "application/x-ndjson": "jsonl",
    "typed_event_stream": "typed_event_stream", "typed_events": "typed_event_stream",
    "typed_event": "typed_event_stream", "event_stream": "typed_event_stream", "events": "typed_event_stream",
    "csv": "csv", "text/csv": "csv",
}
_STRUCTURAL_SEMANTIC_FAMILIES: Dict[str, str] = {
    tok: "wire_record_stream"
    for tok in (
        "raw_bytes", "bytes", "jsonl", "jsonl_events", "typed_event",
        "typed_events", "typed_event_stream", "csv", "csv_records", "structured_records",
    )
}


class AdapterProposalStatus(str, Enum):
    """Explicit tiered outcome status for `AdapterSynthesizer`."""

    DIRECT_COMPATIBLE = "DIRECT_COMPATIBLE"
    VERIFIED_CATALOG = "VERIFIED_CATALOG"
    SYNTHESIZED_VERIFIED = "SYNTHESIZED_VERIFIED"
    SYNTHESIZED_CANDIDATE = "SYNTHESIZED_CANDIDATE"
    ABSTAIN = "ABSTAIN"


@dataclass(frozen=True)
class AdapterOracleReport:
    """Independent positive/negative fixture oracle verification report."""

    passed: bool
    positive_total: int
    positive_passed: int
    negative_total: int
    negative_passed: int
    verification_corpus_hash: str
    failure_reasons: Tuple[str, ...] = ()
    fixture_results: Tuple[Dict[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed, "positive_total": self.positive_total, "positive_passed": self.positive_passed,
            "negative_total": self.negative_total, "negative_passed": self.negative_passed,
            "verification_corpus_hash": self.verification_corpus_hash,
            "failure_reasons": list(self.failure_reasons), "fixture_results": [dict(i) for i in self.fixture_results],
        }


@dataclass
class AdapterProposalResult:
    """Tiered result returned by `AdapterSynthesizer.propose(...)`."""

    status: AdapterProposalStatus
    tier: int
    source_port: PortContract
    target_port: PortContract
    compatibility_before: PortCompatibilityResult
    adapter_spec: Optional[AdapterSpec] = None
    callable_adapter: Optional[Callable[[Any], Any]] = None
    callable_hash: str = ""
    oracle_report: Optional[AdapterOracleReport] = None
    compatibility_after: Optional[PortCompatibilityResult] = None
    abstain_reason: Optional[str] = None
    llm_calls: int = 0
    provenance: Dict[str, Any] = field(default_factory=dict)

    @property
    def abstained(self) -> bool:
        return self.status == AdapterProposalStatus.ABSTAIN

    @property
    def accepted(self) -> bool:
        return self.status != AdapterProposalStatus.ABSTAIN

    def require_accepted(self) -> "AdapterProposalResult":
        """Raise `AbstainError` if this proposal abstained."""
        if self.abstained:
            raise AbstainError(self.abstain_reason or "ABSTAIN: adapter synthesis abstained.")
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "AdapterProposalResult/1", "status": self.status.value, "tier": self.tier,
            "accepted": self.accepted, "abstained": self.abstained, "abstain_reason": self.abstain_reason,
            "source_port": self.source_port.to_dict(), "target_port": self.target_port.to_dict(),
            "compatibility_before": self.compatibility_before.to_dict(),
            "compatibility_after": self.compatibility_after.to_dict() if self.compatibility_after else None,
            "adapter_spec": self.adapter_spec.to_dict() if self.adapter_spec else None,
            "callable_hash": self.callable_hash,
            "oracle_report": self.oracle_report.to_dict() if self.oracle_report else None,
            "llm_calls": self.llm_calls, "provenance": dict(self.provenance),
        }


def _reverify_catalog_adapter(
    spec: AdapterSpec,
    *,
    authority: Optional[AttestationAuthority] = None,
) -> Optional[str]:
    if spec.trust_status != TrustStatus.VERIFIED:
        return f"UNVERIFIED_STATUS:{spec.trust_status.value}"
    if not is_valid_sha256(spec.verification_corpus_hash):
        return "MISSING_VERIFICATION_CORPUS_HASH"
    expected_hash = sha256_digest({
        "schema": spec.schema, "adapter_id": spec.adapter_id, "version": spec.version,
        "source_port": spec.source_port.to_dict(), "target_port": spec.target_port.to_dict(),
        "mapping": spec.mapping, "unit_conversion": spec.unit_conversion, "lossless": spec.lossless,
        "preconditions": spec.preconditions, "verification_corpus_hash": spec.verification_corpus_hash,
    })
    if not is_valid_sha256(spec.adapter_hash) or not hmac.compare_digest(spec.adapter_hash, expected_hash):
        return "ADAPTER_HASH_MISMATCH"
    if authority is None or not authority.has_registered_verifiers:
        return "ADAPTER_ATTESTATION_AUTHORITY_REQUIRED"
    att = dict(spec.verification_attestation or {})
    att.setdefault("binary_hash", att.get("adapter_hash"))
    att.setdefault("tool_id", att.get("adapter_id"))
    if not has_valid_verification_attestation(att, spec.adapter_hash, spec.adapter_id):
        return "INVALID_VERIFICATION_ATTESTATION"
    if not authority.verify_adapter_attestation(
        att,
        expected_adapter_id=spec.adapter_id,
        expected_adapter_hash=spec.adapter_hash,
        expected_corpus_hash=spec.verification_corpus_hash,
    ):
        return "UNTRUSTED_OR_INVALID_ATTESTATION_SIGNATURE"
    return None


class AdapterCatalog:
    """Zero-trust catalog storing verified `AdapterSpec/1` contracts and optional callables."""

    SCHEMA_VERSION = "AdapterCatalog/1"

    def __init__(
        self,
        storage_path: Optional[Union[str, Path]] = None,
        *,
        auto_load: bool = True,
        authority: Optional[AttestationAuthority] = None,
    ) -> None:
        self.storage_path: Optional[Path] = Path(storage_path) if storage_path is not None else None
        self.authority: Optional[AttestationAuthority] = authority
        self._entries: Dict[str, Tuple[AdapterSpec, Optional[Callable[[Any], Any]]]] = {}
        if auto_load and self.storage_path is not None and self.storage_path.exists():
            self.load(self.storage_path)

    def register(
        self, spec: Union[AdapterSpec, Mapping[str, Any]], callable_adapter: Optional[Callable[[Any], Any]] = None
    ) -> str:
        """Validate and store a verified `AdapterSpec/1`, rejecting unverified or tampered specs."""
        parsed = AdapterSpec.from_dict(spec)
        err = _reverify_catalog_adapter(parsed, authority=self.authority)
        if err is not None:
            raise AbstainError(f"CATALOG_REJECTED_ADAPTER ({parsed.adapter_id}): {err}")
        if callable_adapter is not None and not callable(callable_adapter):
            raise TypeError("callable_adapter must be callable when provided.")
        self._entries[parsed.adapter_id] = (parsed, callable_adapter)
        return parsed.adapter_hash

    def get(self, adapter_id: str) -> Optional[Tuple[AdapterSpec, Optional[Callable[[Any], Any]]]]:
        entry = self._entries.get(validate_tool_id(adapter_id))
        if entry is None or _reverify_catalog_adapter(entry[0], authority=self.authority) is not None:
            return None
        return entry

    def list_verified(self) -> List[AdapterSpec]:
        return [
            self._entries[aid][0]
            for aid in sorted(self._entries)
            if _reverify_catalog_adapter(self._entries[aid][0], authority=self.authority) is None
        ]

    def lookup(
        self, source_port: PortContract, target_port: PortContract, *, declassification_grant: Optional[DeclassificationGrant] = None
    ) -> List[Tuple[AdapterSpec, Optional[Callable[[Any], Any]]]]:
        """Find deterministically sorted verified adapters matching `(source_port -> target_port)`."""
        matches: List[Tuple[Tuple[Any, ...], AdapterSpec, Optional[Callable[[Any], Any]]]] = []
        for aid in sorted(self._entries):
            spec, fn = self._entries[aid]
            if _reverify_catalog_adapter(spec, authority=self.authority) is not None:
                continue
            if not (ports_compatible(source_port, spec.source_port).compatible and ports_compatible(spec.target_port, target_port).compatible):
                continue
            if _SENSITIVITY_RANK[source_port.sensitivity] > _SENSITIVITY_RANK[target_port.sensitivity]:
                if declassification_grant is None or not declassification_grant.covers(source_port.sensitivity, target_port.sensitivity) or spec.lossless:
                    continue
            exact = 0 if (spec.source_port.to_dict() == source_port.to_dict() and spec.target_port.to_dict() == target_port.to_dict()) else 1
            matches.append(((0 if spec.lossless else 1, exact, spec.adapter_id, spec.version, spec.adapter_hash), spec, fn))
        matches.sort(key=lambda item: item[0])
        return [(spec, fn) for _, spec, fn in matches]

    def save(self, path: Optional[Union[str, Path]] = None) -> Path:
        """Persist verified catalog entries atomically (`0o600`, symlink-safe)."""
        target = Path(path) if path is not None else self.storage_path
        if target is None:
            raise ValueError("CATALOG_SAVE_NO_PATH: specify storage_path.")
        assert_not_symlink(target.parent)
        assert_not_symlink(target)
        atomic_write_json(target, {"schema": self.SCHEMA_VERSION, "adapters": [s.to_dict() for s in self.list_verified()]})
        return target

    def load(self, path: Optional[Union[str, Path]] = None) -> int:
        """Load and re-verify persisted `AdapterSpec/1` records without trusting raw JSON blindly."""
        target = Path(path) if path is not None else self.storage_path
        if target is None or not target.exists():
            return 0
        assert_not_symlink(target.parent)
        assert_not_symlink(target)
        raw = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("schema") != self.SCHEMA_VERSION:
            raise ValueError("INVALID_ADAPTER_CATALOG_SCHEMA")
        loaded = 0
        for item in raw.get("adapters", []):
            spec = AdapterSpec.from_dict(item)
            if _reverify_catalog_adapter(spec, authority=self.authority) is None:
                self._entries[spec.adapter_id] = (spec, None)
                loaded += 1
        return loaded


def _detect_port_wire_format(port: PortContract) -> Optional[WireFormat]:
    for cand in (port.schema_ref, port.encoding, port.semantic_type):
        low = cand.strip().lower()
        if low in _WIRE_FORMAT_ALIASES:
            return WireFormat(_WIRE_FORMAT_ALIASES[low])
        for sep in (":", ";", "/"):
            if sep in low:
                head, tail = (p.strip() for p in low.split(sep, 1))
                for tok in (head, tail):
                    if tok in _WIRE_FORMAT_ALIASES:
                        return WireFormat(_WIRE_FORMAT_ALIASES[tok])
    return None


def _is_ambiguous_semantic(semantic_type: str) -> bool:
    low = semantic_type.strip().lower()
    return (not low) or low in _AMBIGUOUS_SEMANTIC_TOKENS or " | " in low or " or " in low or "?" in low


def _semantics_compatible(
    src: PortContract, dst: PortContract, *, semantic_equivalence: Optional[Mapping[str, str]] = None, has_explicit_field_map: bool = False
) -> Tuple[bool, Optional[str]]:
    if _is_ambiguous_semantic(src.semantic_type) or _is_ambiguous_semantic(dst.semantic_type):
        return False, f"AMBIGUOUS_SEMANTIC_TYPE:'{src.semantic_type}'->'{dst.semantic_type}'"
    s_low, d_low = src.semantic_type.strip().lower(), dst.semantic_type.strip().lower()
    if s_low == d_low:
        return True, None
    s_fam, d_fam = _STRUCTURAL_SEMANTIC_FAMILIES.get(s_low), _STRUCTURAL_SEMANTIC_FAMILIES.get(d_low)
    if s_fam is not None and s_fam == d_fam:
        return True, None
    if semantic_equivalence:
        mapped = semantic_equivalence.get(src.semantic_type) or semantic_equivalence.get(s_low)
        if mapped and mapped.strip().lower() == d_low:
            return True, None
    if has_explicit_field_map:
        return True, None
    return False, f"INCOMPATIBLE_SEMANTIC_TYPES:'{src.semantic_type}'!='{dst.semantic_type}'"


def _extract_schema_fields(schema: Optional[Mapping[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    if not schema:
        return {}, []
    props = schema.get("properties")
    prop_map = {str(k): (dict(v) if isinstance(v, MappingABC) else {}) for k, v in props.items()} if isinstance(props, MappingABC) else {}
    req = [str(x) for x in (schema.get("required") or [])]
    for r in req:
        prop_map.setdefault(r, {})
    return prop_map, req


def _resolve_deterministic_field_mapping(
    source_port: PortContract,
    target_port: PortContract,
    source_schema: Optional[Mapping[str, Any]],
    target_schema: Optional[Mapping[str, Any]],
    field_map: Optional[Mapping[str, str]],
    projections: Optional[Mapping[str, str]],
    unit_fields: Optional[Union[Sequence[str], Mapping[str, str]]],
) -> Tuple[Dict[str, str], Dict[str, str], Optional[str]]:
    src_props, src_req = _extract_schema_fields(source_schema)
    dst_props, dst_req = _extract_schema_fields(target_schema)
    resolved: Dict[str, str] = {}
    for k, v in (field_map or {}).items():
        if v is None or str(v).strip().lower() in _AMBIGUOUS_SEMANTIC_TOKENS | {""}:
            return {}, {}, f"AMBIGUOUS_FIELD_MAP_VALUE:{k}->{v!r}"
        resolved[str(k)] = str(v)
    for k, v in (projections or {}).items():
        ks, vs = str(k), str(v)
        resolved[vs if (vs in src_props or "." in vs) else ks] = ks if (vs in src_props or "." in vs) else vs

    src_u = CANONICAL_TIME_UNITS.get(source_port.unit.strip().lower())
    dst_u = CANONICAL_TIME_UNITS.get(target_port.unit.strip().lower())
    mapped_targets = set(resolved.values())
    for dst_f in dict.fromkeys(list(dst_req) + list(dst_props.keys())):
        if dst_f in mapped_targets:
            continue
        if dst_f in src_props or dst_f in src_req:
            resolved[dst_f] = dst_f
            mapped_targets.add(dst_f)
            continue
        if src_u and dst_u and src_u != dst_u and dst_f.endswith(f"_{dst_u}"):
            cand = f"{dst_f[: -(len(dst_u) + 1)]}_{src_u}"
            if cand in src_props or cand in src_req:
                resolved[cand] = dst_f
                mapped_targets.add(dst_f)
                continue
        if dst_f in dst_req or target_schema is not None:
            return {}, {}, f"UNKNOWN_OR_UNMAPPED_TARGET_FIELD:'{dst_f}'"

    if len(set(resolved.values())) != len(resolved.values()):
        return {}, {}, "AMBIGUOUS_CONFLICTING_TARGET_MAPPING"

    resolved_uf: Dict[str, str] = {}
    if src_u != dst_u and "none" not in (source_port.unit.lower(), target_port.unit.lower()):
        if isinstance(unit_fields, MappingABC):
            resolved_uf = {str(k): str(v) for k, v in unit_fields.items()}
        elif isinstance(unit_fields, (list, tuple, set)):
            resolved_uf = {str(u): resolved.get(str(u), str(u)) for u in unit_fields}
        else:
            cands = [
                (sf, df)
                for sf, df in resolved.items()
                if (CANONICAL_TIME_UNITS.get(str(src_props.get(sf, {}).get("unit", "")).lower()) == src_u or sf.endswith(f"_{src_u}"))
                and (CANONICAL_TIME_UNITS.get(str(dst_props.get(df, {}).get("unit", "")).lower()) == dst_u or df.endswith(f"_{dst_u}") or sf == df)
            ]
            if not cands and len(resolved) == 1:
                cands = [next(iter(resolved.items()))]
            if not cands and not src_props and not dst_props and not resolved:
                cands = [("value", "value")]
                resolved["value"] = "value"
            if len(cands) != 1:
                return {}, {}, f"AMBIGUOUS_OR_MISSING_UNIT_FIELD: found {len(cands)} candidates for {src_u}->{dst_u}."
            resolved_uf[cands[0][0]] = cands[0][1]
        for sf, df in resolved_uf.items():
            resolved.setdefault(sf, df)
    return resolved, resolved_uf, None


def _analyze_unit_synthesis(
    source_port: PortContract,
    target_port: PortContract,
    *,
    unit_representation: Optional[str],
    require_divisible: bool,
    allow_lossy: bool,
) -> Tuple[Optional[Dict[str, Any]], str, bool, List[str], Optional[str]]:
    src_raw, dst_raw = source_port.unit.strip().lower(), target_port.unit.strip().lower()
    if src_raw == dst_raw or "none" in (src_raw, dst_raw):
        return None, "auto", True, [], None
    src_u, dst_u = CANONICAL_TIME_UNITS.get(src_raw), CANONICAL_TIME_UNITS.get(dst_raw)
    if src_u is None or dst_u is None:
        return None, "auto", False, [], f"UNSUPPORTED_UNIT_PAIR:'{source_port.unit}'->'{target_port.unit}'"

    src_ns, dst_ns = TIME_UNIT_NS_FACTORS[src_u], TIME_UNIT_NS_FACTORS[dst_u]
    with localcontext() as ctx:
        ctx.prec = 80
        factor_str = str((Decimal(src_ns) / Decimal(dst_ns)).normalize())
    rep = (unit_representation or "auto").strip().lower()
    dst_prec = (target_port.precision or "").strip().lower()

    if src_ns >= dst_ns:
        mult = src_ns // dst_ns
        uc = {"from_unit": src_u, "to_unit": dst_u, "factor": factor_str, "scale": {"numerator": mult, "denominator": 1}, "formula": f"value * {mult}", "exact": True}
        return uc, ("decimal_string" if rep == "decimal_string" else "auto"), True, [], None

    div = dst_ns // src_ns
    uc = {"from_unit": src_u, "to_unit": dst_u, "factor": factor_str, "scale": {"numerator": 1, "denominator": div}, "formula": f"value / {div}", "exact": True}
    if rep in {"decimal", "decimal_string", "structured"} or (rep == "auto" and dst_prec in _DECIMAL_PRECISION_TOKENS):
        mode = rep if rep in {"decimal", "decimal_string", "structured"} else "decimal"
        return uc, mode, True, [], None
    if require_divisible:
        uc["exact_divisible_only"] = True
        return uc, "int", True, [f"divisible_by:{div}"], None
    if allow_lossy:
        return uc, "int", False, ["explicit_lossy_truncation_opt_in"], None
    return None, "auto", False, [], f"UNPROVABLE_LOSSLESS_UNIT_CONVERSION:'{src_u}'->'{dst_u}' requires decimal/structured, require_divisible=True, or allow_lossy=True"


def _compute_independent_expected_record(
    record: Mapping[str, Any],
    *,
    field_map: Mapping[str, str],
    unit_fields: Mapping[str, str],
    src_unit: str,
    dst_unit: str,
    unit_mode: str,
    allow_lossy: bool,
    grant: Optional[DeclassificationGrant],
) -> Dict[str, Any]:
    """Independent reference oracle implementation using `fractions.Fraction`."""
    working = grant.apply_to_record(record) if grant is not None else dict(record)
    if field_map:
        out: Dict[str, Any] = {}
        for src_p, dst_p in field_map.items():
            found, val = extract_nested_path(working, src_p)
            if not found:
                raise KeyError(src_p)
            set_nested_path(out, dst_p, val)
    else:
        out = dict(working)

    s_c, d_c = CANONICAL_TIME_UNITS.get(src_unit.lower()), CANONICAL_TIME_UNITS.get(dst_unit.lower())
    if unit_fields and s_c and d_c and s_c != d_c:
        ratio = Fraction(TIME_UNIT_NS_FACTORS[s_c], TIME_UNIT_NS_FACTORS[d_c])
        for s_f, d_f in unit_fields.items():
            found, raw_val = extract_nested_path(out, d_f)
            if not found:
                found, raw_val = extract_nested_path(working, s_f)
            if isinstance(raw_val, bool) or not isinstance(raw_val, (int, Decimal, str)):
                raise TypeError(f"Unsupported oracle value: {raw_val!r}")
            scaled = Fraction(raw_val) * ratio
            if unit_mode == "structured":
                q_abs, r_abs = divmod(abs(scaled.numerator), scaled.denominator)
                sign = -1 if scaled.numerator < 0 else 1
                res_val: Any = {"value": sign * q_abs, "remainder": sign * r_abs, "unit": d_c, "remainder_unit": s_c}
            elif unit_mode in {"decimal", "decimal_string"}:
                with localcontext() as ctx:
                    ctx.prec = 120
                    dec = (Decimal(scaled.numerator) / Decimal(scaled.denominator)).normalize()
                if unit_mode == "decimal_string":
                    if dec == dec.to_integral_value():
                        res_val = str(int(dec))
                    else:
                        s_dec = format(dec, "f")
                        res_val = s_dec.rstrip("0").rstrip(".") if "." in s_dec else s_dec
                else:
                    res_val = dec
            else:
                if scaled.denominator != 1 and not allow_lossy:
                    raise LossyConversionError("Oracle non-divisible lossy value")
                q_abs = abs(scaled.numerator) // scaled.denominator
                res_val = -q_abs if scaled.numerator < 0 else q_abs
            set_nested_path(out, d_f, res_val)
    return out


class AdapterOracleVerifier:
    """Builds independent positive + negative fixture suites and verifies adapter callables."""

    def build_fixture_suite(
        self,
        *,
        source_port: PortContract,
        target_port: PortContract,
        src_format: Optional[WireFormat],
        dst_format: Optional[WireFormat],
        field_map: Mapping[str, str],
        unit_fields: Mapping[str, str],
        unit_mode: str,
        exact_divisible_only: bool,
        allow_lossy: bool,
        source_schema: Optional[Mapping[str, Any]],
        grant: Optional[DeclassificationGrant],
        sample_fixtures: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Deterministically construct independent positive and negative test fixtures."""
        src_props, _ = _extract_schema_fields(source_schema)
        s_u = CANONICAL_TIME_UNITS.get(source_port.unit.lower())
        d_u = CANONICAL_TIME_UNITS.get(target_port.unit.lower())
        div = (TIME_UNIT_NS_FACTORS[d_u] // TIME_UNIT_NS_FACTORS[s_u]) if (s_u and d_u and TIME_UNIT_NS_FACTORS[s_u] < TIME_UNIT_NS_FACTORS[d_u]) else 1
        rec_1 = self._sample_record(
            field_map, unit_fields, src_props, 1_700_000_000_000_000_000 if s_u == "ns" else (2 * div if div > 1 else 42), 0, "alpha-utf8-café", grant is not None
        )
        non_div = 1_700_000_000_123_456_789 if div >= 1_000 else (div * 3 + 1 if div > 1 else 9_007_199_254_740_993)
        rec_2 = self._sample_record(
            field_map, unit_fields, src_props, 1_700_000_005_000_000_000 if (exact_divisible_only and s_u == "ns") else non_div, 1, "beta-big-int", grant is not None
        )
        raw_records = [rec_1, rec_2] + ([dict(x) for x in sample_fixtures] if sample_fixtures else [])
        is_single = source_port.cardinality == "one"
        pos = [
            {
                "name": f"pos_record_{i}",
                "input": self._format_payload(rec, src_format, is_single=is_single),
                "expected_record": _compute_independent_expected_record(
                    rec, field_map=field_map, unit_fields=unit_fields, src_unit=source_port.unit,
                    dst_unit=target_port.unit, unit_mode=unit_mode, allow_lossy=allow_lossy, grant=grant,
                ),
            }
            for i, rec in enumerate(raw_records)
        ]
        neg = self._build_negative_fixtures(
            rec_1, src_format=src_format, is_single=is_single, field_map=field_map,
            unit_fields=unit_fields, div=div, exact_divisible_only=exact_divisible_only, nullable=target_port.nullable,
        )
        return pos, neg

    def _build_negative_fixtures(
        self, base_rec: Mapping[str, Any], *, src_format: Optional[WireFormat], is_single: bool,
        field_map: Mapping[str, str], unit_fields: Mapping[str, str], div: int, exact_divisible_only: bool, nullable: bool,
    ) -> List[Dict[str, Any]]:
        neg: List[Dict[str, Any]] = []
        if src_format == WireFormat.BYTES:
            neg.append({"name": "neg_invalid_utf8", "input": b"\xff\xfe\xfd\n"})
        if src_format in (WireFormat.BYTES, WireFormat.JSONL):
            neg.append({"name": "neg_malformed_jsonl", "input": b'{"broken": \n' if src_format == WireFormat.BYTES else '{"broken": \n'})
        if src_format == WireFormat.CSV:
            cols = list(base_rec.keys())
            neg.append({"name": "neg_csv_col_mismatch", "input": f"{','.join(cols)}\n{','.join(['1'] * (len(cols) + 1))}\n"})
        if unit_fields:
            uf = next(iter(unit_fields))
            float_rec = copy.deepcopy(dict(base_rec))
            set_nested_path(float_rec, uf, 1.5)
            neg.append({"name": "neg_float_precision", "input": self._format_payload(float_rec, src_format, is_single=is_single)})
            if div > 1 and exact_divisible_only:
                nd_rec = copy.deepcopy(dict(base_rec))
                set_nested_path(nd_rec, uf, div + 1)
                neg.append({"name": "neg_non_divisible", "input": self._format_payload(nd_rec, src_format, is_single=is_single)})
        if field_map and not nullable:
            missing = copy.deepcopy(dict(base_rec))
            missing.pop(next(iter(field_map)).split(".", 1)[0], None)
            neg.append({"name": "neg_missing_field", "input": self._format_payload(missing, src_format, is_single=is_single)})
        return neg or [{"name": "neg_wrong_type", "input": 123456789}]

    def _sample_record(
        self, field_map: Mapping[str, str], unit_fields: Mapping[str, str], src_props: Mapping[str, Mapping[str, Any]],
        unit_val: int, seq_idx: int, text_val: str, secret_mode: bool,
    ) -> Dict[str, Any]:
        rec: Dict[str, Any] = {}
        keys = list(dict.fromkeys(list(field_map.keys()) + list(unit_fields.keys()) + list(src_props.keys()))) or ["seq", "message"]
        for k in keys:
            if k in unit_fields:
                set_nested_path(rec, k, unit_val)
            else:
                mtype = str(src_props.get(k, {}).get("type", "")).lower()
                if k in {"seq", "id", "index", "count"} or mtype in {"integer", "int"}:
                    val: Any = 9_007_199_254_740_993 + seq_idx
                elif mtype == "boolean":
                    val = seq_idx % 2 == 0
                elif secret_mode and any(tok in k.lower() for tok in ("secret", "token", "key")):
                    val = f"SUPER_SECRET_RAW_VAL_{seq_idx}"
                else:
                    val = f"{text_val}-{seq_idx}"
                set_nested_path(rec, k, val)
        return rec

    def _format_payload(self, record: Mapping[str, Any], src_format: Optional[WireFormat], *, is_single: bool) -> Any:
        if src_format == WireFormat.BYTES:
            return (encode_json_exact(record) + "\n").encode("utf-8")
        if src_format == WireFormat.JSONL:
            return encode_json_exact(record) + "\n"
        if src_format == WireFormat.CSV:
            cols = list(record.keys())
            buf = io.StringIO()
            csv.writer(buf, lineterminator="\n", strict=True).writerows([
                cols, ["" if record[c] is None else (encode_json_exact(record[c]) if isinstance(record[c], (dict, list)) else str(record[c])) for c in cols],
            ])
            return buf.getvalue()
        return copy.deepcopy(dict(record)) if is_single else [copy.deepcopy(dict(record))]

    def verify(self, callable_adapter: Callable[[Any], Any], **kwargs: Any) -> AdapterOracleReport:
        """Run independent positive + negative fixture suite against `callable_adapter`."""
        pos_fixtures, neg_fixtures = self.build_fixture_suite(**kwargs)
        dst_format: Optional[WireFormat] = kwargs.get("dst_format")
        grant: Optional[DeclassificationGrant] = kwargs.get("grant")
        results: List[Dict[str, Any]] = []
        failures: List[str] = []
        pos_ok, neg_ok = 0, 0

        for fix in pos_fixtures:
            try:
                raw = callable_adapter(fix["input"])
                items = list(raw) if isinstance(raw, IteratorABC) else raw
                actual = self._extract_first_record(items, dst_format)
                ok, reason = self._compare_records_exact(actual, fix["expected_record"], dst_format=dst_format, grant=grant)
                if ok:
                    pos_ok += 1
                    results.append({"name": fix["name"], "kind": "positive", "passed": True})
                else:
                    failures.append(f"{fix['name']}:{reason}")
                    results.append({"name": fix["name"], "kind": "positive", "passed": False, "reason": reason})
            except Exception as exc:
                failures.append(f"{fix['name']}:EXCEPTION:{type(exc).__name__}:{exc}")
                results.append({"name": fix["name"], "kind": "positive", "passed": False, "reason": str(exc)})

        for fix in neg_fixtures:
            try:
                out = callable_adapter(fix["input"])
                if isinstance(out, IteratorABC):
                    list(out)
                failures.append(f"{fix['name']}:NEGATIVE_INPUT_ACCEPTED")
                results.append({"name": fix["name"], "kind": "negative", "passed": False})
            except (AbstainError, ToolWireError, ValueError, TypeError, KeyError, UnicodeError) as exc:
                neg_ok += 1
                results.append({"name": fix["name"], "kind": "negative", "passed": True, "rejected_with": type(exc).__name__})

        corpus_hash = sha256_digest({
            "positive": canonical_json_dumps([{"name": f["name"], "expected": _json_safe(f["expected_record"])} for f in pos_fixtures]),
            "negative": [f["name"] for f in neg_fixtures], "results": results,
        })
        passed = pos_ok == len(pos_fixtures) and neg_ok == len(neg_fixtures) and not failures and bool(pos_fixtures) and bool(neg_fixtures)
        return AdapterOracleReport(
            passed=passed, positive_total=len(pos_fixtures), positive_passed=pos_ok,
            negative_total=len(neg_fixtures), negative_passed=neg_ok,
            verification_corpus_hash=corpus_hash, failure_reasons=tuple(failures), fixture_results=tuple(results),
        )

    def _extract_first_record(self, actual: Any, dst_format: Optional[WireFormat]) -> Dict[str, Any]:
        if isinstance(actual, bytes):
            actual = actual.decode("utf-8", errors="strict")
        if dst_format == WireFormat.JSONL and isinstance(actual, (str, list)):
            lines = [ln for ln in (actual.splitlines() if isinstance(actual, str) else actual) if str(ln).strip()]
            if len(lines) != 1:
                raise ValueError(f"Expected 1 JSONL line, got {len(lines)}")
            return decode_json_exact(str(lines[0]).rstrip("\r\n"))
        if dst_format == WireFormat.CSV and isinstance(actual, (str, list)):
            rows = list(csv.reader(io.StringIO("".join(actual) if isinstance(actual, list) else actual), strict=True))
            if len(rows) != 2:
                raise ValueError(f"Expected CSV header + 1 row, got {len(rows)} rows")
            return dict(zip(rows[0], rows[1]))
        if isinstance(actual, MappingABC):
            return dict(actual)
        if isinstance(actual, list) and len(actual) == 1 and isinstance(actual[0], MappingABC):
            return dict(actual[0])
        raise ValueError(f"Unexpected adapter output shape: {type(actual).__name__}")

    def _compare_records_exact(
        self, actual: Mapping[str, Any], expected: Mapping[str, Any], *, dst_format: Optional[WireFormat], grant: Optional[DeclassificationGrant]
    ) -> Tuple[bool, str]:
        if grant is not None and "SUPER_SECRET_RAW_VAL" in encode_json_exact(actual, decimal_as_string=True):
            return False, "SECRET_LEAKED_AFTER_DECLASSIFICATION"
        if set(actual.keys()) != set(expected.keys()):
            return False, f"KEYS_MISMATCH:{sorted(actual.keys())}!={sorted(expected.keys())}"
        for k, exp_v in expected.items():
            act_v = actual[k]
            if dst_format == WireFormat.CSV:
                exp_s = "" if exp_v is None else ("true" if exp_v is True else ("false" if exp_v is False else (encode_json_exact(exp_v) if isinstance(exp_v, (dict, list)) else str(exp_v))))
                if str(act_v) != exp_s:
                    return False, f"CSV_VALUE_MISMATCH:{k}:{act_v!r}!={exp_s!r}"
            elif type(exp_v) is int and (type(act_v) is not int or act_v != exp_v):
                return False, f"INT_EXACT_MISMATCH:{k}:{act_v!r}!={exp_v!r}"
            elif isinstance(exp_v, Decimal) and (not isinstance(act_v, Decimal) or act_v != exp_v):
                return False, f"DECIMAL_EXACT_MISMATCH:{k}:{act_v!r}!={exp_v!r}"
            elif isinstance(exp_v, MappingABC):
                if not isinstance(act_v, MappingABC):
                    return False, f"NESTED_TYPE_MISMATCH:{k}"
                ok, reason = self._compare_records_exact(act_v, exp_v, dst_format=None, grant=grant)
                if not ok:
                    return False, reason
            elif act_v != exp_v:
                return False, f"VALUE_MISMATCH:{k}:{act_v!r}!={exp_v!r}"
        return True, ""


def _json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, MappingABC):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


class AdapterSynthesizer:
    """Deterministic 3-tier `PortContract/1` adapter resolver, synthesizer, and oracle verifier."""

    VERSION = ADAPTER_SYNTHESIZER_VERSION

    def __init__(
        self,
        catalog: Optional[AdapterCatalog] = None,
        *,
        wire: Optional[ToolWire] = None,
        oracle: Optional[AdapterOracleVerifier] = None,
        verifier_id: str = DEFAULT_ORACLE_VERIFIER_ID,
        authority: Optional[AttestationAuthority] = None,
    ) -> None:
        effective_auth = authority if authority is not None else (catalog.authority if catalog is not None else None)
        self.catalog = catalog if catalog is not None else AdapterCatalog(authority=effective_auth)
        self.wire = wire if wire is not None else ToolWire()
        self.oracle = oracle if oracle is not None else AdapterOracleVerifier()
        self.verifier_id = validate_safe_text(verifier_id, field_name="verifier_id")
        self.authority: Optional[AttestationAuthority] = effective_auth

    def propose(
        self,
        source_port: Union[PortContract, Mapping[str, Any]],
        target_port: Union[PortContract, Mapping[str, Any]],
        *,
        source_schema: Optional[Mapping[str, Any]] = None,
        target_schema: Optional[Mapping[str, Any]] = None,
        field_map: Optional[Mapping[str, str]] = None,
        projections: Optional[Mapping[str, str]] = None,
        unit_fields: Optional[Union[Sequence[str], Mapping[str, str]]] = None,
        unit_representation: Optional[str] = None,
        require_divisible: bool = False,
        allow_lossy: bool = False,
        declassification_grant: Optional[DeclassificationGrant] = None,
        semantic_equivalence: Optional[Mapping[str, str]] = None,
        sort_key: Optional[str] = None,
        sample_fixtures: Optional[Sequence[Mapping[str, Any]]] = None,
        promote_verified: bool = True,
        authority: Optional[AttestationAuthority] = None,
        raise_on_abstain: bool = False,
    ) -> AdapterProposalResult:
        """Select or synthesize a verified port adapter across Tier 1 -> Tier 2 -> Tier 3 (`ABSTAIN`)."""
        src, dst = PortContract.from_dict(source_port), PortContract.from_dict(target_port)
        compat = ports_compatible(src, dst)

        def _abstain(reason: str) -> AdapterProposalResult:
            res = AdapterProposalResult(
                status=AdapterProposalStatus.ABSTAIN, tier=3, source_port=src, target_port=dst,
                compatibility_before=compat, abstain_reason=reason, llm_calls=0,
                provenance={"synthesizer_version": self.VERSION, "tier_selected": 3},
            )
            if raise_on_abstain:
                raise AbstainError(reason)
            return res

        lattice_err = _check_lattice_gates(src, dst, declassification_grant=declassification_grant)
        if lattice_err is not None:
            return _abstain(lattice_err)

        effective_authority = (
            authority
            if authority is not None
            else (self.authority if self.authority is not None else self.catalog.authority)
        )
        has_custom = bool(field_map or projections or unit_fields or unit_representation or allow_lossy)
        if not has_custom:
            hits = self.catalog.lookup(src, dst, declassification_grant=declassification_grant)
            for spec, fn in hits:
                if (
                    effective_authority is None
                    or not effective_authority.has_registered_verifiers
                    or _reverify_catalog_adapter(spec, authority=effective_authority) is not None
                ):
                    continue
                compiled = fn or self.compile_adapter_callable(spec, declassification_grant=declassification_grant)
                return AdapterProposalResult(
                    status=AdapterProposalStatus.VERIFIED_CATALOG, tier=1, source_port=src, target_port=dst,
                    compatibility_before=compat, compatibility_after=ports_compatible(spec.target_port, dst),
                    adapter_spec=spec, callable_adapter=compiled, callable_hash=compute_callable_sha256(compiled),
                    llm_calls=0, provenance={"synthesizer_version": self.VERSION, "tier_selected": 1, "catalog_adapter_id": spec.adapter_id, "adapter_hash": spec.adapter_hash},
                )

        if compat.compatible and not has_custom and source_schema is None and target_schema is None:
            ident_fn = _build_identity_callable()
            return AdapterProposalResult(
                status=AdapterProposalStatus.DIRECT_COMPATIBLE, tier=0, source_port=src, target_port=dst,
                compatibility_before=compat, compatibility_after=compat, callable_adapter=ident_fn,
                callable_hash=compute_callable_sha256(ident_fn), llm_calls=0,
                provenance={"synthesizer_version": self.VERSION, "tier_selected": 0, "direct": True},
            )

        pre_err = _check_tier2_preconditions(
            src, dst, compat, has_custom=has_custom, allow_lossy=allow_lossy, sort_key=sort_key,
            semantic_equivalence=semantic_equivalence, has_explicit_field_map=bool(field_map or projections),
        )
        if pre_err is not None:
            return _abstain(pre_err)

        return self._synthesize_tier2(
            src, dst, compat, source_schema=source_schema, target_schema=target_schema,
            field_map=field_map, projections=projections, unit_fields=unit_fields,
            unit_representation=unit_representation, require_divisible=require_divisible,
            allow_lossy=allow_lossy, declassification_grant=declassification_grant,
            sample_fixtures=sample_fixtures, promote_verified=promote_verified,
            authority=(authority if authority is not None else self.authority),
            abstain_fn=_abstain,
        )

    def _synthesize_tier2(
        self,
        src: PortContract,
        dst: PortContract,
        compat: PortCompatibilityResult,
        *,
        source_schema: Optional[Mapping[str, Any]],
        target_schema: Optional[Mapping[str, Any]],
        field_map: Optional[Mapping[str, str]],
        projections: Optional[Mapping[str, str]],
        unit_fields: Optional[Union[Sequence[str], Mapping[str, str]]],
        unit_representation: Optional[str],
        require_divisible: bool,
        allow_lossy: bool,
        declassification_grant: Optional[DeclassificationGrant],
        sample_fixtures: Optional[Sequence[Mapping[str, Any]]],
        promote_verified: bool,
        authority: Optional[AttestationAuthority],
        abstain_fn: Callable[[str], AdapterProposalResult],
    ) -> AdapterProposalResult:
        resolved_map, resolved_uf, map_err = _resolve_deterministic_field_mapping(
            src, dst, source_schema, target_schema, field_map, projections, unit_fields
        )
        if map_err is not None:
            return abstain_fn(f"ABSTAIN_{map_err}")

        unit_conv, unit_mode, unit_lossless, preconds, unit_err = _analyze_unit_synthesis(
            src, dst, unit_representation=unit_representation, require_divisible=require_divisible, allow_lossy=allow_lossy
        )
        if unit_err is not None:
            return abstain_fn(f"ABSTAIN_{unit_err}")

        eff_src_fmt = _detect_port_wire_format(src) or WireFormat.TYPED_EVENT_STREAM
        eff_dst_fmt = _detect_port_wire_format(dst) or WireFormat.TYPED_EVENT_STREAM
        lossless = unit_lossless and (not allow_lossy) and (declassification_grant is None)
        mapping_doc: Dict[str, Any] = {
            "op": "wire_adapter", "source_format": eff_src_fmt.value, "target_format": eff_dst_fmt.value, "unit_mode": unit_mode
        }
        if resolved_map:
            mapping_doc["fields"] = dict(resolved_map)
        if resolved_uf:
            mapping_doc["unit_fields"] = dict(resolved_uf)
        if declassification_grant is not None:
            mapping_doc.update({"transform": declassification_grant.transform, "grant_id": declassification_grant.grant_id})
            preconds.append(f"declassification_grant:{declassification_grant.grant_id}:{declassification_grant.transform}")

        adapter_id = _deterministic_adapter_id(src, dst, mapping_doc, unit_conv, lossless)
        csv_types = _infer_csv_field_types(source_schema, resolved_uf)
        try:
            draft = AdapterSpec(
                adapter_id=adapter_id, version="1.0.0", source_port=src, target_port=dst,
                mapping=mapping_doc, unit_conversion=unit_conv, lossless=lossless,
                preconditions=preconds, trust_status=TrustStatus.DISCOVERED,
            )
            fn = self.compile_adapter_callable(
                draft, source_format=eff_src_fmt, target_format=eff_dst_fmt,
                unit_mode=unit_mode, declassification_grant=declassification_grant, field_types=csv_types,
            )
        except (AbstainError, ToolWireError, ValueError) as exc:
            return abstain_fn(f"ABSTAIN_SPEC_REJECTED:{exc}")

        report = self.oracle.verify(
            fn, source_port=src, target_port=dst, src_format=eff_src_fmt, dst_format=eff_dst_fmt,
            field_map=resolved_map, unit_fields=resolved_uf, unit_mode=unit_mode,
            exact_divisible_only=require_divisible, allow_lossy=allow_lossy,
            source_schema=source_schema, grant=declassification_grant, sample_fixtures=sample_fixtures,
        )
        if not report.passed:
            return abstain_fn(f"ABSTAIN_ORACLE_VERIFICATION_FAILED:{';'.join(report.failure_reasons)}")

        final_spec = self._finalize_attested_spec(
            adapter_id,
            src,
            dst,
            mapping_doc,
            unit_conv,
            lossless,
            preconds,
            report,
            promote_verified,
            authority=authority,
        )
        final_fn = self.compile_adapter_callable(
            final_spec, source_format=eff_src_fmt, target_format=eff_dst_fmt,
            unit_mode=unit_mode, declassification_grant=declassification_grant, field_types=csv_types,
        )
        proposal_status = (
            AdapterProposalStatus.SYNTHESIZED_VERIFIED
            if final_spec.trust_status == TrustStatus.VERIFIED
            else AdapterProposalStatus.SYNTHESIZED_CANDIDATE
        )
        return AdapterProposalResult(
            status=proposal_status, tier=2, source_port=src, target_port=dst,
            compatibility_before=compat, compatibility_after=ports_compatible(final_spec.target_port, dst),
            adapter_spec=final_spec, callable_adapter=final_fn, callable_hash=compute_callable_sha256(final_fn),
            oracle_report=report, llm_calls=0,
            provenance={"synthesizer_version": self.VERSION, "tier_selected": 2, "verification_corpus_hash": report.verification_corpus_hash, "adapter_hash": final_spec.adapter_hash},
        )

    def _finalize_attested_spec(
        self, adapter_id: str, src: PortContract, dst: PortContract, mapping_doc: Dict[str, Any],
        unit_conv: Optional[Dict[str, Any]], lossless: bool, preconds: List[str],
        report: AdapterOracleReport, promote_verified: bool,
        *, authority: Optional[AttestationAuthority] = None,
    ) -> AdapterSpec:
        draft = AdapterSpec(
            adapter_id=adapter_id, version="1.0.0", source_port=src, target_port=dst,
            mapping=mapping_doc, unit_conversion=unit_conv, lossless=lossless, preconditions=preconds,
            verification_corpus_hash=report.verification_corpus_hash, trust_status=TrustStatus.DISCOVERED,
        )
        if not promote_verified or authority is None or not authority.has_verifier(self.verifier_id):
            return draft
        verification_digest = sha256_digest({
            "adapter_id": adapter_id,
            "adapter_hash": draft.adapter_hash,
            "verification_corpus_hash": report.verification_corpus_hash,
            "positive_passed": report.positive_passed,
            "negative_passed": report.negative_passed,
        })
        attestation = authority.issue_adapter_attestation(
            adapter_id,
            draft.adapter_hash,
            report.verification_corpus_hash,
            verification_digest,
            self.verifier_id,
        )
        return AdapterSpec(
            adapter_id=adapter_id, version="1.0.0", source_port=src, target_port=dst,
            mapping=mapping_doc, unit_conversion=unit_conv, lossless=lossless, preconditions=preconds,
            verification_corpus_hash=report.verification_corpus_hash, adapter_hash=draft.adapter_hash,
            trust_status=TrustStatus.VERIFIED, verification_attestation=attestation,
        )

    def synthesize(
        self, source_port: Union[PortContract, Mapping[str, Any]], target_port: Union[PortContract, Mapping[str, Any]], *, raise_on_abstain: bool = False, **kwargs: Any
    ) -> AdapterProposalResult:
        """Alias for `propose(...)` supporting deterministic synthesis and optional `AbstainError`."""
        return self.propose(source_port, target_port, raise_on_abstain=raise_on_abstain, **kwargs)

    def compile_adapter_callable(
        self,
        spec: AdapterSpec,
        *,
        source_format: Optional[WireFormat] = None,
        target_format: Optional[WireFormat] = None,
        unit_mode: Optional[str] = None,
        declassification_grant: Optional[DeclassificationGrant] = None,
        field_types: Optional[Mapping[str, str]] = None,
    ) -> Callable[[Any], Any]:
        """Compile an `AdapterSpec/1` into a pure-Python deterministic callable (zero `eval`/`exec`)."""
        eff_src = source_format or _detect_port_wire_format(spec.source_port) or WireFormat.TYPED_EVENT_STREAM
        eff_dst = target_format or _detect_port_wire_format(spec.target_port) or WireFormat.TYPED_EVENT_STREAM
        eff_mode = unit_mode or str(spec.mapping.get("unit_mode", "auto"))
        exact_div = bool((spec.unit_conversion or {}).get("exact_divisible_only", False))
        raw_uf = spec.mapping.get("unit_fields")
        resolved_uf = dict(raw_uf) if isinstance(raw_uf, MappingABC) else None
        wire = self.wire

        def _adapter_callable(payload: Any) -> Any:
            single = isinstance(payload, MappingABC)
            kwargs = {
                "source_port": spec.source_port, "target_port": spec.target_port,
                "source_format": eff_src, "target_format": eff_dst, "adapter_spec": spec,
                "unit_fields": resolved_uf, "unit_output_mode": eff_mode, "exact_divisible_only": exact_div,
                "lossless": spec.lossless, "declassification_grant": declassification_grant, "field_types": field_types,
            }
            if single and eff_src == WireFormat.TYPED_EVENT_STREAM and eff_dst == WireFormat.TYPED_EVENT_STREAM:
                return wire.convert([payload], **kwargs).output[0]
            if spec.target_port.streaming and isinstance(payload, IteratorABC):
                return wire.stream(payload, **kwargs)
            res = wire.convert([payload] if single else payload, **kwargs)
            if spec.target_port.cardinality == "one" and eff_dst == WireFormat.TYPED_EVENT_STREAM:
                if len(res.output) != 1:
                    raise AbstainError(f"CARDINALITY_VIOLATION: expected 1 record, got {len(res.output)}.")
                return res.output[0]
            return res.output

        return _adapter_callable


def _check_lattice_gates(
    src: PortContract, dst: PortContract, *, declassification_grant: Optional[DeclassificationGrant]
) -> Optional[str]:
    if _SENSITIVITY_RANK[src.sensitivity] > _SENSITIVITY_RANK[dst.sensitivity]:
        if declassification_grant is None or not declassification_grant.covers(src.sensitivity, dst.sensitivity):
            return f"ABSTAIN_SENSITIVITY_LATTICE: '{src.sensitivity}' -> '{dst.sensitivity}' blocked without authorized DeclassificationGrant."
    if _TRUST_RANK[src.trust_label] < _TRUST_RANK[dst.trust_label]:
        return f"ABSTAIN_TRUST_LATTICE: cannot silently escalate '{src.trust_label}' -> '{dst.trust_label}'."
    return None


def _check_tier2_preconditions(
    src: PortContract,
    dst: PortContract,
    compat: PortCompatibilityResult,
    *,
    has_custom: bool,
    allow_lossy: bool,
    sort_key: Optional[str],
    semantic_equivalence: Optional[Mapping[str, str]],
    has_explicit_field_map: bool,
) -> Optional[str]:
    if src.ordering == "unordered" and dst.ordering == "ordered" and (src.streaming or not sort_key):
        return "ABSTAIN_ORDERING_VIOLATION: cannot deterministically synthesize unordered->ordered stream."
    if src.cardinality == "stream" and dst.cardinality == "one" and not has_custom:
        return "ABSTAIN_CARDINALITY_LOSS: unreduced stream -> one mapping cannot be proven lossless."
    if src.nullable and not dst.nullable and not allow_lossy:
        return "ABSTAIN_NULLABILITY_VIOLATION: nullable source cannot safely feed non-nullable target."
    for reason in compat.reasons:
        if reason.startswith("PRECISION_LOSS:") and not allow_lossy and not _is_pure_time_precision_reason(reason):
            return f"ABSTAIN_{reason}"
    sem_ok, sem_err = _semantics_compatible(src, dst, semantic_equivalence=semantic_equivalence, has_explicit_field_map=has_explicit_field_map)
    if not sem_ok:
        return f"ABSTAIN_{sem_err}"
    src_fmt, dst_fmt = _detect_port_wire_format(src), _detect_port_wire_format(dst)
    if src_fmt == WireFormat.BYTES and dst_fmt not in (WireFormat.JSONL, WireFormat.TYPED_EVENT_STREAM, WireFormat.CSV):
        return f"ABSTAIN_UNSUPPORTED_FORMAT_BRIDGE:{src.schema_ref}->{dst.schema_ref}"
    if src.encoding.strip().lower() not in _VALID_WIRE_ENCODINGS:
        return f"ABSTAIN_UNSUPPORTED_ENCODING:{src.encoding}"
    if dst.encoding.strip().lower() not in _VALID_WIRE_ENCODINGS:
        return f"ABSTAIN_UNSUPPORTED_ENCODING:{dst.encoding}"
    return None


def _build_identity_callable() -> Callable[[Any], Any]:
    def _identity_adapter(payload: Any) -> Any:
        return dict(payload) if isinstance(payload, MappingABC) else payload
    return _identity_adapter


def _is_pure_time_precision_reason(reason: str) -> bool:
    if not reason.startswith("PRECISION_LOSS:") or "->" not in reason:
        return False
    left, right = reason.split(":", 1)[1].split("->", 1)
    return left.strip().lower() in TIME_UNIT_NS_FACTORS and right.strip().lower() in TIME_UNIT_NS_FACTORS


def _deterministic_adapter_id(
    src: PortContract, dst: PortContract, mapping_doc: Mapping[str, Any], unit_conv: Optional[Mapping[str, Any]], lossless: bool
) -> str:
    digest = sha256_digest({
        "src": src.to_dict(), "dst": dst.to_dict(), "mapping": dict(mapping_doc),
        "unit_conversion": dict(unit_conv) if unit_conv else None, "lossless": lossless,
    }).split(":", 1)[1][:12]
    return f"adapter.{src.unit.lower()}_to_{dst.unit.lower()}.{digest}"


def _infer_csv_field_types(source_schema: Optional[Mapping[str, Any]], unit_fields: Mapping[str, str]) -> Dict[str, str]:
    types: Dict[str, str] = {}
    props, _ = _extract_schema_fields(source_schema)
    for k, meta in props.items():
        t = str(meta.get("type", "")).strip().lower()
        if t in {"integer", "int"}:
            types[k] = "int"
        elif t in {"decimal", "numeric"}:
            types[k] = "decimal"
        elif t in {"boolean", "bool"}:
            types[k] = "bool"
    for uf in unit_fields:
        types.setdefault(uf, "int")
    return types


__all__ = [
    "ADAPTER_SYNTHESIZER_VERSION", "AdapterCatalog", "AdapterOracleReport",
    "AdapterOracleVerifier", "AdapterProposalResult", "AdapterProposalStatus", "AdapterSynthesizer",
]
