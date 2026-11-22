"""ToolWire (`kintsugi.tools.tool_wire`): Working Tool #3 for typed streaming wire conversion.

Deterministic, zero-float-loss streaming converter across
`JSONL <-> typed_event_stream <-> CSV` (plus strict UTF-8 `bytes` lines) enforcing
`PortContract/1`, exact `int`/`Decimal` unit scaling (`ns <-> us <-> ms <-> s`),
ordering preservation, sensitivity lattice rules, strict malformed-record
diagnostics, and O(1)-RAM incremental provenance digests.
"""

from __future__ import annotations

import codecs
import csv
import hashlib
import hmac
import io
import json
from collections.abc import Iterable as IterableABC
from collections.abc import Iterator as IteratorABC
from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, localcontext
from enum import Enum
from fractions import Fraction
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.contracts_v2 import AbstainError, AdapterSpec, PortContract, ports_compatible
from kintsugi.capability.schemas import (
    ToolSpec,
    TrustStatus,
    canonical_json_dumps,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.shield import TROJAN_UNICODE_RE

TOOLWIRE_VERSION = "1.0.0"
DEFAULT_MAX_LINE_BYTES = 16 * 1024 * 1024

_UNIT_DEFS: Tuple[Tuple[str, int, Tuple[str, ...]], ...] = (
    ("ns", 1, ("ns", "nanosecond", "nanoseconds")),
    ("us", 1_000, ("us", "microsecond", "microseconds")),
    ("ms", 1_000_000, ("ms", "millisecond", "milliseconds")),
    ("s", 1_000_000_000, ("s", "sec", "second", "seconds")),
)
CANONICAL_TIME_UNITS: Dict[str, str] = {alias: canon for canon, _, aliases in _UNIT_DEFS for alias in aliases}
TIME_UNIT_NS_FACTORS: Dict[str, int] = {alias: ns for _, ns, aliases in _UNIT_DEFS for alias in aliases}

_INT_LIMITS: Dict[str, Tuple[int, int]] = {
    "int8": (-(1 << 7), (1 << 7) - 1), "i8": (-(1 << 7), (1 << 7) - 1),
    "uint8": (0, (1 << 8) - 1), "u8": (0, (1 << 8) - 1),
    "int16": (-(1 << 15), (1 << 15) - 1), "i16": (-(1 << 15), (1 << 15) - 1),
    "uint16": (0, (1 << 16) - 1), "u16": (0, (1 << 16) - 1),
    "int32": (-(1 << 31), (1 << 31) - 1), "i32": (-(1 << 31), (1 << 31) - 1), "int": (-(1 << 31), (1 << 31) - 1),
    "uint32": (0, (1 << 32) - 1), "u32": (0, (1 << 32) - 1),
    "int64": (-(1 << 63), (1 << 63) - 1), "i64": (-(1 << 63), (1 << 63) - 1),
    "uint64": (0, (1 << 64) - 1), "u64": (0, (1 << 64) - 1),
}
_FLOAT_EXACT_INT_LIMITS: Dict[str, int] = {
    "float16": 1 << 11, "fp16": 1 << 11, "f16": 1 << 11,
    "float32": 1 << 24, "fp32": 1 << 24, "f32": 1 << 24, "float": 1 << 24,
    "float64": 1 << 53, "fp64": 1 << 53, "f64": 1 << 53, "double": 1 << 53,
}
_DECIMAL_PRECISIONS = frozenset({"decimal", "decimal64", "decimal128", "numeric", "exact_decimal", "exact"})
_SENSITIVITY_RANK: Dict[str, int] = {"public": 0, "internal": 1, "secret": 2}
_TRUST_RANK: Dict[str, int] = {"untrusted": 0, "derived": 1, "trusted": 2}
_DECLASSIFY_TRANSFORMS = frozenset({"redact", "mask", "hash", "tokenize", "anonymize", "sanitize"})
_DISALLOWED_AUTHORIZERS = frozenset({"", "self", "auto", "none", "unverified", "unknown"})
_UTF8_CHARSETS = frozenset({"utf-8", "utf8", "ascii"})
_WIRE_FORMAT_ALIASES: Dict[str, str] = {
    "jsonl": "jsonl", "ndjson": "jsonl", "application/jsonl": "jsonl", "application/x-ndjson": "jsonl",
    "csv": "csv", "text/csv": "csv",
    "typed_event_stream": "typed_event_stream", "typed_events": "typed_event_stream",
    "typed_event": "typed_event_stream", "event_stream": "typed_event_stream", "events": "typed_event_stream",
    "bytes": "bytes", "raw_bytes": "bytes", "application/octet-stream": "bytes",
}
_WIRE_SEMANTIC_TYPES = frozenset({
    "raw_bytes", "bytes", "jsonl", "jsonl_events", "typed_event",
    "typed_events", "typed_event_stream", "csv", "csv_records", "structured_records",
})


class WireFormat(str, Enum):
    """Canonical streaming formats supported by `ToolWire`."""

    JSONL = "jsonl"
    TYPED_EVENT_STREAM = "typed_event_stream"
    CSV = "csv"
    BYTES = "bytes"


class ToolWireError(ValueError):
    """Base error raised on invalid wire contracts, encoding, units, or malformed records."""


class ToolWireFormatError(ToolWireError):
    """Raised when JSONL, CSV, or typed event input is malformed."""

    def __init__(self, message: str, *, record_index: int = -1, line_number: int = -1) -> None:
        self.record_index = record_index
        self.line_number = line_number
        super().__init__(message)


class ToolWireEncodingError(ToolWireError):
    """Raised when UTF-8 validation or encoding compatibility fails."""


class ToolWireContractError(ToolWireError):
    """Raised when `PortContract/1` boundary invariants are violated."""


class ToolWireSensitivityError(AbstainError):
    """Raised when a sensitivity flow violates the lattice without an authorized grant."""


class LossyConversionError(AbstainError):
    """Raised when unit or numeric conversion would silently lose or truncate precision."""


@dataclass(frozen=True)
class DeclassificationGrant:
    """Explicitly authorized grant allowing sensitivity downgrade via mandatory transformation."""

    grant_id: str
    source_sensitivity: str
    target_sensitivity: str
    authorized_by: str
    transform: str = "redact"
    redacted_fields: Tuple[str, ...] = ()
    grant_digest: str = ""
    schema: str = "DeclassificationGrant/1"

    def __post_init__(self) -> None:
        if self.schema != "DeclassificationGrant/1":
            raise ToolWireSensitivityError(f"INVALID_GRANT_SCHEMA: expected DeclassificationGrant/1, got {self.schema!r}")
        gid = validate_safe_text(self.grant_id, field_name="grant_id")
        src_s = validate_safe_text(self.source_sensitivity, field_name="source_sensitivity").lower()
        dst_s = validate_safe_text(self.target_sensitivity, field_name="target_sensitivity").lower()
        auth = validate_safe_text(self.authorized_by, field_name="authorized_by")
        xform = validate_safe_text(self.transform, field_name="transform").lower()
        if src_s not in _SENSITIVITY_RANK or dst_s not in _SENSITIVITY_RANK:
            raise ToolWireSensitivityError("INVALID_GRANT_SENSITIVITY: unknown sensitivity level.")
        if auth.strip().lower() in _DISALLOWED_AUTHORIZERS:
            raise ToolWireSensitivityError(f"INVALID_GRANT_AUTHORIZER: self-asserted authorizer '{auth}' rejected.")
        if xform not in _DECLASSIFY_TRANSFORMS:
            raise ToolWireSensitivityError(f"INVALID_GRANT_TRANSFORM: unsupported transform '{xform}'.")
        clean_fields = tuple(validate_safe_text(str(f), field_name="redacted_fields") for f in self.redacted_fields)
        for k, v in (
            ("grant_id", gid), ("source_sensitivity", src_s), ("target_sensitivity", dst_s),
            ("authorized_by", auth), ("transform", xform), ("redacted_fields", clean_fields),
        ):
            object.__setattr__(self, k, v)
        expected = self.compute_digest()
        if self.grant_digest:
            norm = normalize_sha256(self.grant_digest, field_name="grant_digest")
            if not hmac.compare_digest(norm, expected):
                raise ToolWireSensitivityError("DECLASSIFICATION_GRANT_DIGEST_MISMATCH")
            object.__setattr__(self, "grant_digest", norm)
        else:
            object.__setattr__(self, "grant_digest", expected)

    def compute_digest(self) -> str:
        """Compute canonical SHA-256 digest binding grant metadata and transform."""
        return sha256_digest({
            "schema": self.schema, "grant_id": self.grant_id,
            "source_sensitivity": self.source_sensitivity, "target_sensitivity": self.target_sensitivity,
            "authorized_by": self.authorized_by, "transform": self.transform,
            "redacted_fields": list(self.redacted_fields),
        })

    def covers(self, src_sensitivity: str, dst_sensitivity: str) -> bool:
        """Return True if this grant authorizes flow from `src_sensitivity` to `dst_sensitivity`."""
        s_rank = _SENSITIVITY_RANK.get(src_sensitivity.lower(), -1)
        d_rank = _SENSITIVITY_RANK.get(dst_sensitivity.lower(), -1)
        return (
            s_rank <= _SENSITIVITY_RANK[self.source_sensitivity]
            and d_rank >= _SENSITIVITY_RANK[self.target_sensitivity]
            and self.authorized_by.strip().lower() not in _DISALLOWED_AUTHORIZERS
            and is_valid_sha256(self.grant_digest)
            and hmac.compare_digest(self.grant_digest, self.compute_digest())
        )

    def apply_to_record(self, record: Mapping[str, Any]) -> Dict[str, Any]:
        """Apply mandatory declassification transform without mutating `record`."""
        base = redact_secrets_in_value(dict(record))
        targets = set(self.redacted_fields)
        return {
            k: (_apply_declassify_value(v, self.transform) if ((not targets and _looks_secret_key(k)) or k in targets) else v)
            for k, v in base.items()
        }


@dataclass(frozen=True)
class WireDiagnostic:
    """Structured diagnostic emitted when `strict=False` captures a malformed record."""

    record_index: int
    line_number: int
    code: str
    message: str
    raw_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_index": self.record_index, "line_number": self.line_number,
            "code": self.code, "message": self.message, "raw_digest": self.raw_digest,
        }


@dataclass(frozen=True)
class WiredRecord:
    """Single converted record paired with exact input/transform provenance digests."""

    record_index: int
    data: Any
    source_digest: str
    transform_digest: str
    lossless: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_index": self.record_index, "data": self.data,
            "source_digest": self.source_digest, "transform_digest": self.transform_digest,
            "lossless": self.lossless,
        }


@dataclass(frozen=True)
class WireProvenanceSummary:
    """Incremental O(1)-memory provenance summary across a `ToolWire` stream."""

    source_format: str
    target_format: str
    record_count: int
    rejected_count: int
    source_digest: str
    transform_digest: str
    output_digest: str
    lossless: bool
    diagnostics: Tuple[WireDiagnostic, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_format": self.source_format, "target_format": self.target_format,
            "record_count": self.record_count, "rejected_count": self.rejected_count,
            "source_digest": self.source_digest, "transform_digest": self.transform_digest,
            "output_digest": self.output_digest, "lossless": self.lossless,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
        }


@dataclass(frozen=True)
class WireResult:
    """Materialized result of `ToolWire.convert(...)` preserving provenance and diagnostics."""

    output: Any
    records: Tuple[Any, ...]
    provenance: WireProvenanceSummary

    @property
    def source_digest(self) -> str:
        return self.provenance.source_digest

    @property
    def transform_digest(self) -> str:
        return self.provenance.transform_digest

    @property
    def output_digest(self) -> str:
        return self.provenance.output_digest

    @property
    def record_count(self) -> int:
        return self.provenance.record_count

    @property
    def rejected_count(self) -> int:
        return self.provenance.rejected_count

    @property
    def lossless(self) -> bool:
        return self.provenance.lossless

    @property
    def diagnostics(self) -> Tuple[WireDiagnostic, ...]:
        return self.provenance.diagnostics

    def to_dict(self) -> Dict[str, Any]:
        return {"output": self.output, "record_count": self.record_count, "provenance": self.provenance.to_dict()}


def _looks_secret_key(key: str) -> bool:
    low = key.lower()
    return any(tok in low for tok in ("secret", "token", "key", "password", "passwd", "auth", "credential", "cookie"))


def _apply_declassify_value(value: Any, transform: str) -> Any:
    if value is None:
        return None
    if transform == "hash":
        return sha256_digest(value if isinstance(value, (bytes, str)) else canonical_json_dumps(value))
    if transform == "tokenize":
        return f"[TOKEN:{sha256_digest(str(value)).split(':', 1)[1][:16]}]"
    if transform in {"mask", "anonymize"}:
        text = str(value)
        return "****" if len(text) <= 4 else f"{text[:2]}***{text[-2:]}"
    return "[REDACTED]"


def _reject_json_constant(token: str) -> Any:
    raise ToolWireFormatError(f"INVALID_JSON_CONSTANT: non-standard constant {token!r} forbidden.")


def validate_utf8_text(text: str, *, strict_unicode: bool = True, context: str = "wire") -> str:
    """Verify `text` is surrogate-free valid UTF-8 without NUL or Trojan Bidi control chars."""
    if not isinstance(text, str):
        raise ToolWireEncodingError(f"INVALID_TEXT_TYPE ({context}): expected str, got {type(text).__name__}.")
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ToolWireEncodingError(f"INVALID_UTF8_SURROGATE ({context}): {exc}") from exc
    if "\x00" in text:
        raise ToolWireEncodingError(f"REJECTED_NUL_BYTE ({context}): NUL byte forbidden.")
    if strict_unicode and TROJAN_UNICODE_RE.search(text):
        raise ToolWireEncodingError(f"REJECTED_TROJAN_UNICODE ({context}): invisible or bidi control char detected.")
    return text


def decode_json_exact(line: str, *, line_number: int = -1, strict_unicode: bool = True) -> Dict[str, Any]:
    """Parse one JSONL line using `Decimal` for non-integers and reject non-object JSON or constants."""
    validate_utf8_text(line, strict_unicode=strict_unicode, context="jsonl_line")
    try:
        parsed = json.loads(line, parse_float=Decimal, parse_constant=_reject_json_constant)
    except ToolWireFormatError:
        raise
    except (ValueError, InvalidOperation) as exc:
        raise ToolWireFormatError(f"MALFORMED_JSONL_LINE (line={line_number}): {exc}", line_number=line_number) from exc
    if not isinstance(parsed, dict):
        raise ToolWireFormatError(
            f"MALFORMED_JSONL_RECORD_TYPE (line={line_number}): expected JSON object, got {type(parsed).__name__}.",
            line_number=line_number,
        )
    return parsed


def encode_json_exact(value: Any, *, decimal_as_string: bool = False) -> str:
    """Deterministically serialize Python values to compact JSON preserving exact `int` and `Decimal`."""
    if value is None or isinstance(value, (bool, int, str)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ToolWireFormatError(f"INVALID_DECIMAL_VALUE: non-finite Decimal {value!r} cannot be serialized.")
        return json.dumps(str(value), ensure_ascii=False) if decimal_as_string else str(value)
    if isinstance(value, float):
        raise LossyConversionError(f"FLOAT_FORBIDDEN_IN_EXACT_JSON: float value {value!r} rejected.")
    if isinstance(value, MappingABC):
        parts = [
            f"{json.dumps(str(k), ensure_ascii=False)}:{encode_json_exact(v, decimal_as_string=decimal_as_string)}"
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        ]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(encode_json_exact(item, decimal_as_string=decimal_as_string) for item in value) + "]"
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return encode_json_exact(value.to_dict(), decimal_as_string=decimal_as_string)
    raise ToolWireFormatError(f"UNSERIALIZABLE_VALUE: unsupported type {type(value).__name__}.")


def extract_nested_path(mapping: Mapping[str, Any], path: str) -> Tuple[bool, Any]:
    """Read a dotted field path safely without mutating `mapping`, returning `(found, value)`."""
    if path in mapping:
        return True, mapping[path]
    cur: Any = mapping
    for seg in path.split("."):
        if isinstance(cur, MappingABC) and seg in cur:
            cur = cur[seg]
        else:
            return False, None
    return True, cur


def set_nested_path(target: Dict[str, Any], path: str, value: Any) -> None:
    """Assign `value` at dotted `path` without mutating any pre-existing shared nested dicts."""
    parts = path.split(".")
    cur = target
    for seg in parts[:-1]:
        nxt = cur.get(seg)
        cur[seg] = dict(nxt) if isinstance(nxt, MappingABC) else {}
        cur = cur[seg]
    cur[parts[-1]] = value


def _to_exact_int_or_decimal(value: Any, *, allow_float_input: bool = False) -> Union[int, Decimal]:
    if isinstance(value, bool):
        raise LossyConversionError("INVALID_NUMERIC_BOOL: boolean cannot be used in exact unit scaling.")
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise LossyConversionError(f"INVALID_DECIMAL: non-finite {value!r}")
        return value
    if isinstance(value, float):
        if not allow_float_input:
            raise LossyConversionError(
                f"FLOAT_INPUT_REJECTED: IEEE-754 float {value!r} risks silent precision loss; use int, Decimal, or str."
            )
        return Decimal(str(value))
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise LossyConversionError("EMPTY_NUMERIC_STRING")
        if "." not in cleaned and "e" not in cleaned.lower():
            try:
                return int(cleaned)
            except ValueError as exc:
                raise LossyConversionError(f"INVALID_INTEGER_STRING: {value!r}") from exc
        try:
            dec = Decimal(cleaned)
        except InvalidOperation as exc:
            raise LossyConversionError(f"INVALID_DECIMAL_STRING: {value!r}") from exc
        if not dec.is_finite():
            raise LossyConversionError(f"INVALID_DECIMAL_STRING: non-finite {value!r}")
        return dec
    raise LossyConversionError(f"UNSUPPORTED_NUMERIC_TYPE: {type(value).__name__}")


def _check_target_precision_bounds(val: Union[int, Decimal], target_precision: Optional[str], *, lossless: bool) -> None:
    if not target_precision:
        return
    p_low = target_precision.strip().lower()
    if p_low in _INT_LIMITS:
        if isinstance(val, Decimal) and val != val.to_integral_value():
            if lossless:
                raise LossyConversionError(f"LOSSY_FRACTION_TO_INT ({p_low}): value {val} has non-zero fractional part.")
            return
        lo, hi = _INT_LIMITS[p_low]
        int_val = int(val)
        if int_val < lo or int_val > hi:
            raise LossyConversionError(f"INTEGER_OVERFLOW ({p_low}): {int_val} outside [{lo}, {hi}].")
    elif p_low in _FLOAT_EXACT_INT_LIMITS and isinstance(val, int) and lossless:
        ceiling = _FLOAT_EXACT_INT_LIMITS[p_low]
        if abs(val) > ceiling:
            raise LossyConversionError(f"FLOAT_PRECISION_OVERFLOW ({p_low}): |{val}| exceeds exact integer ceiling {ceiling}.")


def _verify_explicit_unit_conversion(
    unit_conversion: Mapping[str, Any], src_c: str, dst_c: str, src_ns: int, dst_ns: int
) -> None:
    decl_from, decl_to = unit_conversion.get("from_unit"), unit_conversion.get("to_unit")
    if decl_from is not None and CANONICAL_TIME_UNITS.get(str(decl_from).strip().lower()) != src_c:
        raise ToolWireContractError(f"UNIT_CONVERSION_FROM_MISMATCH: {decl_from!r} != {src_c!r}")
    if decl_to is not None and CANONICAL_TIME_UNITS.get(str(decl_to).strip().lower()) != dst_c:
        raise ToolWireContractError(f"UNIT_CONVERSION_TO_MISMATCH: {decl_to!r} != {dst_c!r}")
    scale = unit_conversion.get("scale")
    if isinstance(scale, MappingABC) and "numerator" in scale and "denominator" in scale:
        num, den = int(scale["numerator"]), int(scale["denominator"])
        if den <= 0 or num * dst_ns != den * src_ns:
            raise ToolWireContractError(f"UNIT_SCALE_MISMATCH: ({num}/{den}) != ({src_ns}/{dst_ns}).")
    if unit_conversion.get("factor") is not None:
        raw_factor = unit_conversion["factor"]
        try:
            dec_factor = raw_factor if isinstance(raw_factor, Decimal) else Decimal(str(raw_factor))
        except (InvalidOperation, ValueError) as exc:
            raise ToolWireContractError(f"INVALID_UNIT_FACTOR: {raw_factor!r}") from exc
        with localcontext() as ctx:
            ctx.prec = 80
            if dec_factor != Decimal(src_ns) / Decimal(dst_ns):
                raise ToolWireContractError(f"UNIT_FACTOR_MISMATCH: {dec_factor} != exact {src_c}->{dst_c} factor.")


def _decimal_to_plain_str(val: Decimal) -> str:
    """Format a normalized Decimal cleanly without scientific notation."""
    norm = val.normalize()
    if norm == norm.to_integral_value():
        return str(int(norm))
    s = format(norm, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def convert_exact_unit_value(
    value: Any,
    from_unit: str,
    to_unit: str,
    *,
    lossless: bool = True,
    output_mode: str = "auto",
    allow_lossy: bool = False,
    exact_divisible_only: bool = False,
    allow_float_input: bool = False,
    target_precision: Optional[str] = None,
    unit_conversion: Optional[Mapping[str, Any]] = None,
) -> Tuple[Any, bool, Optional[str]]:
    """Convert `value` across exact time units (`ns`, `us`, `ms`, `s`) without float rounding."""
    src_c = CANONICAL_TIME_UNITS.get(from_unit.strip().lower())
    dst_c = CANONICAL_TIME_UNITS.get(to_unit.strip().lower())
    if src_c is None or dst_c is None:
        raise ToolWireContractError(f"UNSUPPORTED_UNIT_CONVERSION: '{from_unit}' -> '{to_unit}'.")
    src_ns, dst_ns = TIME_UNIT_NS_FACTORS[src_c], TIME_UNIT_NS_FACTORS[dst_c]
    if unit_conversion is not None:
        _verify_explicit_unit_conversion(unit_conversion, src_c, dst_c, src_ns, dst_ns)

    parsed = _to_exact_int_or_decimal(value, allow_float_input=allow_float_input)
    strict_lossless = lossless and not allow_lossy
    if src_ns == dst_ns:
        _check_target_precision_bounds(parsed, target_precision, lossless=strict_lossless)
        return parsed, True, None

    mode = output_mode.strip().lower()
    if mode == "auto" and target_precision and target_precision.strip().lower() in _DECIMAL_PRECISIONS:
        mode = "decimal"

    ratio = Fraction(src_ns, dst_ns)
    num, den = ratio.numerator, ratio.denominator
    if isinstance(parsed, int) and den > 1 and mode == "structured":
        sign = -1 if parsed < 0 else 1
        q_abs, rem_abs = divmod(abs(parsed) * num, den)
        return {"value": sign * q_abs, "remainder": sign * rem_abs, "unit": dst_c, "remainder_unit": src_c}, True, None

    if isinstance(parsed, int) and (den == 1 or mode not in {"decimal", "decimal_string"}):
        scaled_num = parsed * num
        sign = -1 if scaled_num < 0 else 1
        q_abs, rem_abs = divmod(abs(scaled_num), den)
        q = sign * q_abs
        if rem_abs == 0:
            _check_target_precision_bounds(q, target_precision, lossless=strict_lossless)
            if mode == "decimal_string":
                return str(q), True, None
            if mode == "decimal":
                return Decimal(q), True, None
            return q, True, None
        if exact_divisible_only or strict_lossless:
            raise LossyConversionError(
                f"LOSSY_UNIT_CONVERSION ({src_c}->{dst_c}): {parsed} {src_c} not divisible by {den} (rem={sign * rem_abs})."
            )
        _check_target_precision_bounds(q, target_precision, lossless=False)
        return q, False, f"truncated_remainder_{src_c}:{sign * rem_abs}"

    with localcontext() as ctx:
        ctx.prec = max(80, len(str(parsed)) + 32)
        dec_val = (Decimal(parsed) * Decimal(num) / Decimal(den)).normalize()
    if mode in {"decimal", "decimal_string"} and not exact_divisible_only:
        return (_decimal_to_plain_str(dec_val) if mode == "decimal_string" else dec_val), True, None
    if dec_val == dec_val.to_integral_value():
        out_i = int(dec_val)
        _check_target_precision_bounds(out_i, target_precision, lossless=strict_lossless)
        return out_i, True, None
    if exact_divisible_only or strict_lossless:
        raise LossyConversionError(f"LOSSY_UNIT_CONVERSION ({src_c}->{dst_c}): {parsed} yields non-integer {dec_val}.")
    trunc_i = int(dec_val)
    _check_target_precision_bounds(trunc_i, target_precision, lossless=False)
    return trunc_i, False, f"truncated_fraction_from:{dec_val}"


def _try_infer_from_port(port: PortContract) -> Optional[str]:
    for raw in (port.schema_ref.strip().lower(), port.encoding.strip().lower(), port.semantic_type.strip().lower()):
        if raw in _WIRE_FORMAT_ALIASES:
            return _WIRE_FORMAT_ALIASES[raw]
        for sep in (":", ";", "/"):
            if sep in raw:
                head, tail = (p.strip() for p in raw.split(sep, 1))
                if head in _WIRE_FORMAT_ALIASES:
                    return _WIRE_FORMAT_ALIASES[head]
                if tail in _WIRE_FORMAT_ALIASES:
                    return _WIRE_FORMAT_ALIASES[tail]
    return None


def _infer_wire_format(port: PortContract, explicit: Optional[Union[str, WireFormat]] = None) -> WireFormat:
    inferred = _try_infer_from_port(port)
    if explicit is None:
        if inferred is None:
            raise ToolWireContractError(f"UNSPECIFIED_WIRE_FORMAT: schema_ref={port.schema_ref!r}, encoding={port.encoding!r}.")
        return WireFormat(inferred)
    tok = explicit.value if isinstance(explicit, WireFormat) else str(explicit).strip().lower()
    canon = _WIRE_FORMAT_ALIASES.get(tok)
    if canon is None:
        raise ToolWireContractError(f"UNSUPPORTED_WIRE_FORMAT: {explicit!r}")
    if inferred is not None and inferred != canon and not (canon == "bytes" and inferred == "jsonl"):
        raise ToolWireContractError(f"PORT_FORMAT_CONFLICT: explicit '{canon}' contradicts PortContract '{inferred}'.")
    return WireFormat(canon)


def _validate_port_encoding(port: PortContract, role: str) -> None:
    enc = port.encoding.strip().lower()
    if enc in _UTF8_CHARSETS or enc in _WIRE_FORMAT_ALIASES or any(t in _UTF8_CHARSETS for t in enc.replace(";", ":").split(":")):
        return
    raise ToolWireEncodingError(f"UNSUPPORTED_PORT_ENCODING ({role}): '{port.encoding}' (strict UTF-8 required).")


def _iter_utf8_lines_from_bytes(
    chunks: Iterable[Union[bytes, bytearray, memoryview]], *, max_line_bytes: int, strict_unicode: bool
) -> Iterator[str]:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    pending = ""
    for raw_chunk in chunks:
        if not isinstance(raw_chunk, (bytes, bytearray, memoryview)):
            raise ToolWireEncodingError(f"EXPECTED_BYTES_CHUNK: got {type(raw_chunk).__name__}.")
        try:
            pending += decoder.decode(bytes(raw_chunk), final=False)
        except UnicodeDecodeError as exc:
            raise ToolWireEncodingError(f"INVALID_UTF8_BYTE_SEQUENCE: {exc}") from exc
        if len(pending.encode("utf-8")) > max_line_bytes and "\n" not in pending:
            raise ToolWireFormatError("WIRE_LINE_EXCEEDS_MAX_BYTES")
        while "\n" in pending:
            line, pending = pending.split("\n", 1)
            yield validate_utf8_text(line[:-1] if line.endswith("\r") else line, strict_unicode=strict_unicode, context="byte_line")
    try:
        pending += decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise ToolWireEncodingError(f"TRUNCATED_UTF8_AT_EOF: {exc}") from exc
    if pending:
        yield validate_utf8_text(pending[:-1] if pending.endswith("\r") else pending, strict_unicode=strict_unicode, context="byte_line_eof")


def _iter_text_lines(data: Any, *, max_line_bytes: int, strict_unicode: bool) -> Iterator[str]:
    if isinstance(data, (bytes, bytearray, memoryview)):
        yield from _iter_utf8_lines_from_bytes((data,), max_line_bytes=max_line_bytes, strict_unicode=strict_unicode)
        return
    if isinstance(data, str):
        validate_utf8_text(data, strict_unicode=strict_unicode, context="text_input")
        start, n = 0, len(data)
        while start < n:
            nl = data.find("\n", start)
            seg = data[start:] if nl < 0 else data[start:nl]
            yield seg[:-1] if seg.endswith("\r") else seg
            if nl < 0:
                break
            start = nl + 1
        return
    if isinstance(data, IterableABC) and not isinstance(data, MappingABC):
        it = iter(data)
        try:
            first = next(it)
        except StopIteration:
            return
        if isinstance(first, (bytes, bytearray, memoryview)):
            yield from _iter_utf8_lines_from_bytes(
                itertools_chain_one(first, it), max_line_bytes=max_line_bytes, strict_unicode=strict_unicode
            )
            return
        pending = ""
        for item in itertools_chain_one(first, it):
            if not isinstance(item, str):
                raise ToolWireEncodingError(f"EXPECTED_STR_OR_BYTES_LINE: got {type(item).__name__}.")
            validate_utf8_text(item, strict_unicode=strict_unicode, context="stream_str")
            if "\n" not in item and not pending:
                yield item[:-1] if item.endswith("\r") else item
                continue
            pending += item
            if len(pending.encode("utf-8")) > max_line_bytes and "\n" not in pending:
                raise ToolWireFormatError("WIRE_LINE_EXCEEDS_MAX_BYTES")
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                yield line[:-1] if line.endswith("\r") else line
        if pending:
            yield pending[:-1] if pending.endswith("\r") else pending
        return
    raise ToolWireFormatError(f"UNSUPPORTED_TEXT_INPUT_TYPE: {type(data).__name__}")


def itertools_chain_one(first: Any, rest: Iterator[Any]) -> Iterator[Any]:
    yield first
    yield from rest


def _emit_or_raise_diag(
    strict: bool,
    diagnostics: List[WireDiagnostic],
    *,
    rec_idx: int,
    line_num: int,
    code: str,
    exc: Exception,
    raw_digest: str,
) -> Tuple[int, str, None]:
    diag = WireDiagnostic(record_index=rec_idx, line_number=line_num, code=code, message=str(exc), raw_digest=raw_digest)
    if strict:
        if isinstance(exc, ToolWireError):
            raise exc
        raise ToolWireFormatError(diag.message, record_index=rec_idx, line_number=line_num) from exc
    diagnostics.append(diag)
    return rec_idx, raw_digest, None


def _iter_csv_records_streaming(
    data: Any,
    *,
    max_line_bytes: int,
    strict_unicode: bool,
    field_types: Optional[Mapping[str, str]],
    strict: bool,
    diagnostics: List[WireDiagnostic],
) -> Iterator[Tuple[int, str, Optional[Dict[str, Any]]]]:
    quote_state = {"in_quotes": False}

    def _checked_lines() -> Iterator[str]:
        for raw_line in _iter_text_lines(data, max_line_bytes=max_line_bytes, strict_unicode=strict_unicode):
            i, n, in_q = 0, len(raw_line), quote_state["in_quotes"]
            while i < n:
                if raw_line[i] == '"':
                    if in_q and i + 1 < n and raw_line[i + 1] == '"':
                        i += 2
                        continue
                    in_q = not in_q
                i += 1
            quote_state["in_quotes"] = in_q
            yield raw_line + "\n"
        if quote_state["in_quotes"]:
            raise ToolWireFormatError("MALFORMED_CSV_UNCLOSED_QUOTE: EOF reached inside quoted field.")

    reader = csv.reader(_checked_lines(), strict=True)
    try:
        headers = next(reader)
    except StopIteration as exc:
        raise ToolWireFormatError("MALFORMED_CSV_EMPTY: missing CSV header row.", line_number=1) from exc
    except csv.Error as exc:
        raise ToolWireFormatError(f"MALFORMED_CSV_HEADER: {exc}", line_number=1) from exc

    if not headers or any(not str(h).strip() for h in headers):
        raise ToolWireFormatError("MALFORMED_CSV_EMPTY_HEADER: blank column name forbidden.", line_number=1)
    if len(set(headers)) != len(headers):
        raise ToolWireFormatError("MALFORMED_CSV_DUPLICATE_HEADER: duplicate column names forbidden.", line_number=1)

    rec_idx = 0
    while True:
        line_num = rec_idx + 2
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=rec_idx, line_num=line_num,
                code="MALFORMED_CSV_SYNTAX", exc=exc, raw_digest=sha256_digest(f"csv_err:{line_num}:{exc}"),
            )
            rec_idx += 1
            continue

        raw_digest = sha256_digest(row)
        if len(row) != len(headers):
            err = ToolWireFormatError(f"Expected {len(headers)} columns, got {len(row)} at CSV row {line_num}.")
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=rec_idx, line_num=line_num,
                code="MALFORMED_CSV_COLUMN_COUNT", exc=err, raw_digest=raw_digest,
            )
            rec_idx += 1
            continue

        try:
            yield rec_idx, raw_digest, _coerce_csv_row(headers, row, field_types=field_types)
        except (ValueError, InvalidOperation) as exc:
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=rec_idx, line_num=line_num,
                code="MALFORMED_CSV_FIELD_TYPE", exc=exc, raw_digest=raw_digest,
            )
        rec_idx += 1


def _coerce_csv_row(headers: Sequence[str], row: Sequence[str], *, field_types: Optional[Mapping[str, str]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    types = field_types or {}
    for col, cell in zip(headers, row):
        t_hint = str(types.get(col, "str")).strip().lower()
        if t_hint in {"int", "integer", "int64", "int32", "uint64"}:
            out[col] = int(cell.strip())
        elif t_hint in _DECIMAL_PRECISIONS:
            d = Decimal(cell.strip())
            if not d.is_finite():
                raise ValueError(f"Non-finite decimal in CSV column '{col}': {cell!r}")
            out[col] = d
        elif t_hint in {"bool", "boolean"}:
            low = cell.strip().lower()
            if low not in {"true", "false"}:
                raise ValueError(f"Invalid boolean in CSV column '{col}': {cell!r}")
            out[col] = low == "true"
        elif t_hint == "nullable_int":
            out[col] = None if cell == "" else int(cell.strip())
        else:
            out[col] = cell
    return out


def _iter_jsonl_records_streaming(
    data: Any, *, max_line_bytes: int, strict_unicode: bool, strict: bool, diagnostics: List[WireDiagnostic]
) -> Iterator[Tuple[int, str, Optional[Dict[str, Any]]]]:
    for idx, line in enumerate(_iter_text_lines(data, max_line_bytes=max_line_bytes, strict_unicode=strict_unicode)):
        raw_digest = sha256_digest(line)
        if not line.strip():
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=idx, line_num=idx + 1,
                code="MALFORMED_JSONL_EMPTY_LINE",
                exc=ToolWireFormatError(f"Blank JSONL line at line {idx + 1}.", record_index=idx, line_number=idx + 1),
                raw_digest=raw_digest,
            )
            continue
        try:
            yield idx, raw_digest, decode_json_exact(line, line_number=idx + 1, strict_unicode=strict_unicode)
        except ToolWireError as exc:
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=idx, line_num=idx + 1,
                code="MALFORMED_JSONL", exc=exc, raw_digest=raw_digest,
            )


def _iter_typed_records_streaming(
    data: Any, *, strict_unicode: bool, strict: bool, diagnostics: List[WireDiagnostic]
) -> Iterator[Tuple[int, str, Optional[Dict[str, Any]]]]:
    if isinstance(data, (str, bytes, bytearray, memoryview)):
        raise ToolWireFormatError("EXPECTED_TYPED_EVENT_STREAM: got raw str/bytes instead of event iterable.")
    if isinstance(data, MappingABC):
        items: Iterable[Any] = (data,)
    elif isinstance(data, IterableABC):
        items = data
    else:
        raise ToolWireFormatError(f"EXPECTED_TYPED_EVENT_STREAM: unsupported type {type(data).__name__}.")

    for idx, item in enumerate(items):
        if hasattr(item, "to_dict") and callable(item.to_dict):
            raw_obj = item.to_dict()
        elif isinstance(item, MappingABC):
            raw_obj = dict(item)
        else:
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=idx, line_num=idx + 1, code="MALFORMED_TYPED_EVENT",
                exc=ToolWireFormatError(f"Expected mapping/to_dict event at index {idx}, got {type(item).__name__}."),
                raw_digest=sha256_digest(repr(item)),
            )
            continue
        try:
            _validate_mapping_strings(raw_obj, strict_unicode=strict_unicode)
            rec_digest = sha256_digest(encode_json_exact(raw_obj, decimal_as_string=True))
        except ToolWireError as exc:
            yield _emit_or_raise_diag(
                strict, diagnostics, rec_idx=idx, line_num=idx + 1, code="INVALID_TYPED_EVENT_ENCODING",
                exc=exc, raw_digest=sha256_digest(repr(raw_obj)),
            )
            continue
        yield idx, rec_digest, raw_obj


def _validate_mapping_strings(value: Any, *, strict_unicode: bool) -> None:
    if isinstance(value, str):
        validate_utf8_text(value, strict_unicode=strict_unicode, context="typed_event")
    elif isinstance(value, MappingABC):
        for k, v in value.items():
            validate_utf8_text(str(k), strict_unicode=strict_unicode, context="typed_event_key")
            _validate_mapping_strings(v, strict_unicode=strict_unicode)
    elif isinstance(value, (list, tuple)):
        for elem in value:
            _validate_mapping_strings(elem, strict_unicode=strict_unicode)


def _format_csv_row(values: Sequence[Any]) -> str:
    buf = io.StringIO()
    rendered: List[str] = []
    for val in values:
        if val is None:
            rendered.append("")
        elif isinstance(val, bool):
            rendered.append("true" if val else "false")
        elif isinstance(val, (int, Decimal)):
            rendered.append(str(val))
        elif isinstance(val, float):
            raise LossyConversionError(f"FLOAT_FORBIDDEN_IN_CSV: float {val!r} rejected.")
        elif isinstance(val, (dict, list)):
            rendered.append(encode_json_exact(val))
        else:
            rendered.append(str(val))
    csv.writer(buf, lineterminator="\n", strict=True).writerow(rendered)
    return buf.getvalue()


class WireStream(IteratorABC):
    """O(1)-memory lazy streaming iterator tracking exact provenance digests and diagnostics."""

    def __init__(
        self,
        generator: Iterator[Tuple[int, str, str, Any, bool]],
        *,
        source_format: WireFormat,
        target_format: WireFormat,
        source_port: PortContract,
        target_port: PortContract,
        transform_config_digest: str,
        emit_formatter: Callable[[Any], Any],
        csv_header_fn: Optional[Callable[[Any], Optional[str]]] = None,
        diagnostics_ref: Optional[List[WireDiagnostic]] = None,
        initial_lossless: bool = True,
    ) -> None:
        self._gen = generator
        self.source_format = source_format
        self.target_format = target_format
        self.source_port = source_port
        self.target_port = target_port
        self._transform_config_digest = transform_config_digest
        self._emit_formatter = emit_formatter
        self._csv_header_fn = csv_header_fn
        self._diagnostics = diagnostics_ref if diagnostics_ref is not None else []
        self._src_hasher = hashlib.sha256()
        self._out_hasher = hashlib.sha256()
        self._record_count = 0
        self._lossless = initial_lossless
        self._last_record_provenance: Optional[Dict[str, Any]] = None
        self._pending_row: Any = None
        self._has_pending_row = False
        self._header_emitted = csv_header_fn is None
        self._exhausted = False

    def __iter__(self) -> "WireStream":
        return self

    def __next__(self) -> Any:
        if self._has_pending_row:
            self._has_pending_row = False
            row_out, self._pending_row = self._pending_row, None
            return row_out
        if self._exhausted:
            raise StopIteration
        try:
            rec_idx, rec_src_d, rec_xf_d, rec_data, rec_lossless = next(self._gen)
        except StopIteration:
            self._exhausted = True
            raise

        self._record_count += 1
        self._lossless = self._lossless and rec_lossless
        self._src_hasher.update(rec_src_d.encode("utf-8"))
        emitted = self._emit_formatter(rec_data)
        emitted_s = emitted if isinstance(emitted, (bytes, str)) else encode_json_exact(emitted, decimal_as_string=True)
        self._out_hasher.update(sha256_digest(emitted_s).encode("utf-8"))
        self._last_record_provenance = {
            "record_index": rec_idx, "source_digest": rec_src_d,
            "transform_digest": rec_xf_d, "lossless": rec_lossless,
        }
        if not self._header_emitted and self._csv_header_fn is not None:
            self._header_emitted = True
            header_line = self._csv_header_fn(rec_data)
            if header_line is not None:
                self._pending_row, self._has_pending_row = emitted, True
                return header_line
        return emitted

    @property
    def record_count(self) -> int:
        return self._record_count

    @property
    def rejected_count(self) -> int:
        return len(self._diagnostics)

    @property
    def diagnostics(self) -> Tuple[WireDiagnostic, ...]:
        return tuple(self._diagnostics)

    @property
    def lossless(self) -> bool:
        return self._lossless

    @property
    def last_record_provenance(self) -> Optional[Dict[str, Any]]:
        return dict(self._last_record_provenance) if self._last_record_provenance is not None else None

    @property
    def source_digest(self) -> str:
        return f"sha256:{self._src_hasher.hexdigest()}"

    @property
    def output_digest(self) -> str:
        return f"sha256:{self._out_hasher.hexdigest()}"

    @property
    def transform_digest(self) -> str:
        return sha256_digest({
            "config_digest": self._transform_config_digest, "source_digest": self.source_digest,
            "output_digest": self.output_digest, "record_count": self._record_count, "lossless": self._lossless,
        })

    def summary(self) -> WireProvenanceSummary:
        """Return an immutable snapshot of incremental stream provenance and diagnostics."""
        return WireProvenanceSummary(
            source_format=self.source_format.value, target_format=self.target_format.value,
            record_count=self._record_count, rejected_count=len(self._diagnostics),
            source_digest=self.source_digest, transform_digest=self.transform_digest,
            output_digest=self.output_digest, lossless=self._lossless, diagnostics=tuple(self._diagnostics),
        )


def _normalize_unit_field_spec(
    unit_fields: Optional[Union[Sequence[str], Mapping[str, str]]], field_map: Optional[Mapping[str, str]]
) -> Dict[str, str]:
    if unit_fields is None:
        return {}
    if isinstance(unit_fields, MappingABC):
        return {str(k): str(v) for k, v in unit_fields.items()}
    if isinstance(unit_fields, (list, tuple, set)):
        mapping = field_map or {}
        return {str(f): str(mapping.get(str(f), f)) for f in unit_fields}
    raise ToolWireContractError(f"INVALID_UNIT_FIELDS: expected sequence or mapping, got {type(unit_fields).__name__}.")


def _resolve_order_and_provenance(
    record: Dict[str, Any],
    *,
    rec_idx: int,
    expected_seq: int,
    ordering: str,
    sequence_field: Optional[str],
    preserve_upstream_provenance: bool,
    raw_digest: str,
    transform_config_digest: str,
) -> Tuple[int, str, str]:
    if ordering == "ordered" and sequence_field:
        found, seq_val = extract_nested_path(record, sequence_field)
        if found:
            if isinstance(seq_val, bool) or not isinstance(seq_val, int):
                raise ToolWireContractError(f"ORDERING_SEQUENCE_INVALID: '{sequence_field}' must be int, got {seq_val!r}.")
            if seq_val < expected_seq:
                raise ToolWireContractError(f"ORDERING_VIOLATION: index {rec_idx} ({sequence_field}={seq_val} < {expected_seq}).")
            expected_seq = seq_val + 1
        else:
            expected_seq = rec_idx + 1
    else:
        expected_seq = rec_idx + 1

    upstream_src = record.get("source_digest") if preserve_upstream_provenance else None
    src_digest = (
        normalize_sha256(upstream_src, field_name="source_digest")
        if isinstance(upstream_src, str) and is_valid_sha256(upstream_src)
        else raw_digest
    )
    xform_digest = sha256_digest({
        "config": transform_config_digest, "record_index": rec_idx, "source_digest": src_digest,
        "upstream_transform": record.get("transform_digest") if preserve_upstream_provenance else None,
    })
    return expected_seq, src_digest, xform_digest


class ToolWire:
    """Typed streaming converter across `JSONL <-> typed_event_stream <-> CSV` enforcing `PortContract/1`."""

    VERSION = TOOLWIRE_VERSION

    def __init__(self, *, max_line_bytes: int = DEFAULT_MAX_LINE_BYTES, strict_unicode: bool = True) -> None:
        self.max_line_bytes = max(1024, int(max_line_bytes))
        self.strict_unicode = bool(strict_unicode)

    @staticmethod
    def build_tool_spec(binary_hash: Optional[str] = None, *, trust_status: TrustStatus = TrustStatus.DISCOVERED) -> ToolSpec:
        """Build a canonical `ToolSpec/1` descriptor for `ToolWire`."""
        digest = binary_hash or sha256_digest({"tool": "tool_wire", "version": TOOLWIRE_VERSION})
        return ToolSpec(
            tool_id="kintsugi.tool_wire", version=TOOLWIRE_VERSION, source="builtin", binary_hash=digest,
            capabilities=[
                "wire.convert", "wire.jsonl_to_csv", "wire.csv_to_jsonl",
                "wire.jsonl_to_typed_event_stream", "wire.typed_event_stream_to_csv", "wire.stream_adapt",
            ],
            input_schema={"type": "stream", "formats": ["bytes", "jsonl", "typed_event_stream", "csv"]},
            output_schema={"type": "stream", "formats": ["jsonl", "typed_event_stream", "csv", "bytes"]},
            semantic_contract={"contract": "PortContract/1", "exact_math": "decimal_and_int", "streaming": True},
            required_permissions=[], side_effects=["none"], trust_status=trust_status,
        )

    def validate_boundary(
        self,
        source_port: Union[PortContract, Mapping[str, Any]],
        target_port: Union[PortContract, Mapping[str, Any]],
        *,
        source_format: Optional[Union[str, WireFormat]] = None,
        target_format: Optional[Union[str, WireFormat]] = None,
        adapter_spec: Optional[AdapterSpec] = None,
        field_map: Optional[Mapping[str, str]] = None,
        unit_conversion: Optional[Mapping[str, Any]] = None,
        unit_fields: Optional[Union[Sequence[str], Mapping[str, str]]] = None,
        declassification_grant: Optional[DeclassificationGrant] = None,
        allow_lossy: bool = False,
        lossless: Optional[bool] = None,
        sort_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate `PortContract/1` source & target boundaries and resolve conversion policy."""
        src, dst = PortContract.from_dict(source_port), PortContract.from_dict(target_port)
        _validate_port_encoding(src, "source_port")
        _validate_port_encoding(dst, "target_port")
        src_fmt, dst_fmt = _infer_wire_format(src, source_format), _infer_wire_format(dst, target_format)

        if src.semantic_type.lower() != dst.semantic_type.lower() and adapter_spec is None and not field_map:
            if not (src.semantic_type.lower() in _WIRE_SEMANTIC_TYPES and dst.semantic_type.lower() in _WIRE_SEMANTIC_TYPES and src_fmt != dst_fmt):
                raise ToolWireContractError(
                    f"SEMANTIC_TYPE_MISMATCH: '{src.semantic_type}' -> '{dst.semantic_type}' requires AdapterSpec or field_map."
                )
        if src.ordering == "unordered" and dst.ordering == "ordered" and not sort_key:
            raise ToolWireContractError("ORDERING_VIOLATION: unordered -> ordered requires explicit sort_key.")
        if _TRUST_RANK[src.trust_label] < _TRUST_RANK[dst.trust_label]:
            raise ToolWireContractError(f"TRUST_LABEL_VIOLATION: cannot elevate '{src.trust_label}' -> '{dst.trust_label}'.")

        effective_lossless = (not allow_lossy) if lossless is None else bool(lossless)
        if effective_lossless and allow_lossy:
            raise ToolWireContractError("CONTRADICTORY_LOSSLESS_FLAGS: lossless=True with allow_lossy=True.")
        if adapter_spec is not None and not adapter_spec.lossless and effective_lossless:
            effective_lossless = False

        if _SENSITIVITY_RANK[src.sensitivity] > _SENSITIVITY_RANK[dst.sensitivity]:
            if declassification_grant is None or not declassification_grant.covers(src.sensitivity, dst.sensitivity):
                raise ToolWireSensitivityError(
                    f"SENSITIVITY_FLOW_BLOCKED: '{src.sensitivity}' -> '{dst.sensitivity}' requires authorized DeclassificationGrant."
                )
            if effective_lossless:
                raise ToolWireSensitivityError("SENSITIVITY_DECLASSIFICATION_REQUIRES_LOSSLESS_FALSE: set lossless=False.")

        for reason in ports_compatible(src, dst).reasons:
            if reason.startswith("PRECISION_LOSS:") and effective_lossless:
                raise LossyConversionError(f"{reason} (requires allow_lossy=True and lossless=False)")

        resolved_unit_conv = dict(unit_conversion) if unit_conversion is not None else (
            dict(adapter_spec.unit_conversion) if adapter_spec and adapter_spec.unit_conversion else None
        )
        resolved_unit_fields = _normalize_unit_field_spec(unit_fields, field_map)
        src_u, dst_u = src.unit.strip().lower(), dst.unit.strip().lower()
        if src_u != dst_u and "none" not in (src_u, dst_u):
            if resolved_unit_conv is None:
                raise LossyConversionError(f"UNIT_CONVERSION_REQUIRED: '{src.unit}' -> '{dst.unit}' requires unit_conversion.")
            src_c, dst_c = CANONICAL_TIME_UNITS.get(src_u), CANONICAL_TIME_UNITS.get(dst_u)
            if src_c is None or dst_c is None:
                raise ToolWireContractError(f"UNSUPPORTED_UNITS: '{src.unit}' -> '{dst.unit}'.")
            _verify_explicit_unit_conversion(resolved_unit_conv, src_c, dst_c, TIME_UNIT_NS_FACTORS[src_c], TIME_UNIT_NS_FACTORS[dst_c])
            if not resolved_unit_fields and resolved_unit_conv.get("fields") is not None:
                resolved_unit_fields = _normalize_unit_field_spec(resolved_unit_conv.get("fields"), field_map)
            if not resolved_unit_fields and isinstance(resolved_unit_conv.get("field"), str):
                f_in = resolved_unit_conv["field"]
                resolved_unit_fields = {f_in: str(resolved_unit_conv.get("target_field") or (field_map or {}).get(f_in) or f_in)}
            if not resolved_unit_fields:
                raise ToolWireContractError("AMBIGUOUS_UNIT_FIELDS: specify unit_fields or unit_conversion['field'].")

        return {
            "source_port": src, "target_port": dst, "source_format": src_fmt, "target_format": dst_fmt,
            "lossless": effective_lossless, "unit_conversion": resolved_unit_conv,
            "unit_fields": resolved_unit_fields, "declassification_grant": declassification_grant,
        }

    def stream_records(self, data: Any, *, source_port: Union[PortContract, Mapping[str, Any]], target_port: Union[PortContract, Mapping[str, Any]], **opts: Any) -> Iterator[WiredRecord]:
        """Yield `WiredRecord` entries lazily in O(1) RAM with per-record provenance digests."""
        boundary, cfg_digest, diag_sink, gen = self._prepare_generator(data, source_port, target_port, include_provenance=False, **opts)
        _ = (boundary, cfg_digest, diag_sink)
        for rec_idx, src_d, xform_d, rec_data, rec_lossless in gen:
            yield WiredRecord(record_index=rec_idx, data=rec_data, source_digest=src_d, transform_digest=xform_d, lossless=rec_lossless)

    def stream(
        self,
        data: Any,
        *,
        source_port: Union[PortContract, Mapping[str, Any]],
        target_port: Union[PortContract, Mapping[str, Any]],
        csv_fields: Optional[Sequence[str]] = None,
        decimal_as_string: bool = False,
        include_provenance: bool = False,
        **opts: Any,
    ) -> WireStream:
        """Return a lazy O(1)-memory `WireStream` converting input into the target wire representation."""
        boundary, cfg_digest, diag_sink, gen = self._prepare_generator(
            data, source_port, target_port, include_provenance=include_provenance, **opts
        )
        dst_fmt: WireFormat = boundary["target_format"]
        ordered_csv_cols = list(csv_fields) if csv_fields is not None else None

        def _csv_header(first_rec: Dict[str, Any]) -> str:
            nonlocal ordered_csv_cols
            if ordered_csv_cols is None:
                ordered_csv_cols = list(first_rec.keys())
            if not ordered_csv_cols:
                raise ToolWireFormatError("EMPTY_CSV_RECORD: cannot emit CSV header for empty record.")
            return _format_csv_row(ordered_csv_cols)

        def _emit_item(rec: Dict[str, Any]) -> Any:
            if dst_fmt == WireFormat.TYPED_EVENT_STREAM:
                return rec
            if dst_fmt == WireFormat.JSONL:
                return encode_json_exact(rec, decimal_as_string=decimal_as_string) + "\n"
            if dst_fmt == WireFormat.BYTES:
                return (encode_json_exact(rec, decimal_as_string=decimal_as_string) + "\n").encode("utf-8")
            cols = ordered_csv_cols if ordered_csv_cols is not None else list(rec.keys())
            return _format_csv_row([rec.get(c) for c in cols])

        return WireStream(
            gen, source_format=boundary["source_format"], target_format=dst_fmt,
            source_port=boundary["source_port"], target_port=boundary["target_port"],
            transform_config_digest=cfg_digest, emit_formatter=_emit_item,
            csv_header_fn=_csv_header if dst_fmt == WireFormat.CSV else None,
            diagnostics_ref=diag_sink, initial_lossless=boundary["lossless"],
        )

    def convert(self, data: Any, *, source_port: Union[PortContract, Mapping[str, Any]], target_port: Union[PortContract, Mapping[str, Any]], **opts: Any) -> WireResult:
        """Execute bounded conversion and return `WireResult` with materialized output & provenance."""
        ws = self.stream(data, source_port=source_port, target_port=target_port, **opts)
        items = tuple(ws)
        if ws.target_format in (WireFormat.JSONL, WireFormat.CSV):
            output: Any = "".join(items)
        elif ws.target_format == WireFormat.BYTES:
            output = b"".join(items)
        else:
            output = list(items)
        return WireResult(output=output, records=items, provenance=ws.summary())

    def _prepare_generator(
        self,
        data: Any,
        source_port: Union[PortContract, Mapping[str, Any]],
        target_port: Union[PortContract, Mapping[str, Any]],
        *,
        source_format: Optional[Union[str, WireFormat]] = None,
        target_format: Optional[Union[str, WireFormat]] = None,
        adapter_spec: Optional[AdapterSpec] = None,
        field_map: Optional[Mapping[str, str]] = None,
        unit_conversion: Optional[Mapping[str, Any]] = None,
        unit_fields: Optional[Union[Sequence[str], Mapping[str, str]]] = None,
        unit_output_mode: str = "auto",
        exact_divisible_only: bool = False,
        allow_float_input: bool = False,
        allow_lossy: bool = False,
        lossless: Optional[bool] = None,
        declassification_grant: Optional[DeclassificationGrant] = None,
        field_types: Optional[Mapping[str, str]] = None,
        required_fields: Optional[Sequence[str]] = None,
        sequence_field: Optional[str] = None,
        preserve_upstream_provenance: bool = True,
        include_provenance: bool = False,
        strict: bool = True,
        diagnostics: Optional[List[WireDiagnostic]] = None,
        sort_key: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str, List[WireDiagnostic], Iterator[Tuple[int, str, str, Dict[str, Any], bool]]]:
        boundary = self.validate_boundary(
            source_port, target_port, source_format=source_format, target_format=target_format,
            adapter_spec=adapter_spec, field_map=field_map, unit_conversion=unit_conversion,
            unit_fields=unit_fields, declassification_grant=declassification_grant,
            allow_lossy=allow_lossy, lossless=lossless, sort_key=sort_key,
        )
        diag_sink = diagnostics if diagnostics is not None else []
        src_port, dst_port = boundary["source_port"], boundary["target_port"]
        src_fmt = boundary["source_format"]
        cfg_digest = sha256_digest({
            "source_port": src_port.to_dict(), "target_port": dst_port.to_dict(),
            "source_format": src_fmt.value, "target_format": boundary["target_format"].value,
            "field_map": dict(field_map or {}), "unit_conversion": boundary["unit_conversion"],
            "unit_fields": boundary["unit_fields"], "lossless": boundary["lossless"],
            "adapter_hash": adapter_spec.adapter_hash if adapter_spec else "",
        })

        if src_fmt in (WireFormat.JSONL, WireFormat.BYTES):
            raw_iter = _iter_jsonl_records_streaming(
                data, max_line_bytes=self.max_line_bytes, strict_unicode=self.strict_unicode, strict=strict, diagnostics=diag_sink
            )
        elif src_fmt == WireFormat.CSV:
            raw_iter = _iter_csv_records_streaming(
                data, max_line_bytes=self.max_line_bytes, strict_unicode=self.strict_unicode,
                field_types=field_types, strict=strict, diagnostics=diag_sink,
            )
        else:
            raw_iter = _iter_typed_records_streaming(data, strict_unicode=self.strict_unicode, strict=strict, diagnostics=diag_sink)

        effective_map = _resolve_effective_field_map(field_map, adapter_spec)
        req_list = list(required_fields or ())

        def _gen() -> Iterator[Tuple[int, str, str, Dict[str, Any], bool]]:
            expected_seq, valid_emitted = 0, 0
            for rec_idx, raw_digest, record in raw_iter:
                if record is None:
                    continue
                if src_port.cardinality == "one" and valid_emitted >= 1:
                    raise ToolWireContractError("CARDINALITY_VIOLATION: source cardinality='one' received >1 records.")
                if dst_port.cardinality == "one" and valid_emitted >= 1:
                    raise ToolWireContractError("CARDINALITY_VIOLATION: target cardinality='one' cannot emit >1 records.")
                expected_seq, src_d, xf_d = _resolve_order_and_provenance(
                    record, rec_idx=rec_idx, expected_seq=expected_seq,
                    ordering=dst_port.ordering if dst_port.ordering == "ordered" else src_port.ordering,
                    sequence_field=sequence_field, preserve_upstream_provenance=preserve_upstream_provenance,
                    raw_digest=raw_digest, transform_config_digest=cfg_digest,
                )
                transformed, rec_lossless = _transform_single_record(
                    record, src_port=src_port, dst_port=dst_port, effective_map=effective_map,
                    unit_fields=boundary["unit_fields"], unit_conv=boundary["unit_conversion"],
                    unit_output_mode=unit_output_mode, exact_divisible_only=exact_divisible_only,
                    allow_float_input=allow_float_input, lossless=boundary["lossless"],
                    grant=boundary["declassification_grant"], required_fields=req_list,
                    include_provenance=include_provenance, src_digest=src_d, xform_digest=xf_d,
                )
                valid_emitted += 1
                yield rec_idx, src_d, xf_d, transformed, rec_lossless

        return boundary, cfg_digest, diag_sink, _gen()


def _resolve_effective_field_map(field_map: Optional[Mapping[str, str]], adapter_spec: Optional[AdapterSpec]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    if adapter_spec is not None:
        spec_fields = adapter_spec.mapping.get("fields") or adapter_spec.mapping.get("field_map")
        if isinstance(spec_fields, MappingABC):
            for k, v in spec_fields.items():
                tgt = (v.get("target") or v.get("to")) if isinstance(v, MappingABC) else (v if isinstance(v, str) else None)
                if tgt:
                    merged[str(k)] = str(tgt)
    if field_map:
        merged.update({str(k): str(v) for k, v in field_map.items()})
    return merged


def _transform_single_record(
    record: Dict[str, Any],
    *,
    src_port: PortContract,
    dst_port: PortContract,
    effective_map: Dict[str, str],
    unit_fields: Dict[str, str],
    unit_conv: Optional[Dict[str, Any]],
    unit_output_mode: str,
    exact_divisible_only: bool,
    allow_float_input: bool,
    lossless: bool,
    grant: Optional[DeclassificationGrant],
    required_fields: Sequence[str],
    include_provenance: bool,
    src_digest: str,
    xform_digest: str,
) -> Tuple[Dict[str, Any], bool]:
    working = grant.apply_to_record(record) if grant is not None else dict(record)
    rec_lossless = lossless and (grant is None)

    if effective_map:
        out: Dict[str, Any] = {}
        for src_path, dst_path in effective_map.items():
            found, val = extract_nested_path(working, src_path)
            if not found:
                if not dst_port.nullable:
                    raise ToolWireFormatError(f"MISSING_REQUIRED_SOURCE_FIELD: '{src_path}' not found in record.")
                val = None
            set_nested_path(out, dst_path, val)
    else:
        out = dict(working)

    if unit_fields and src_port.unit.lower() != dst_port.unit.lower() and "none" not in (src_port.unit.lower(), dst_port.unit.lower()):
        for src_f, dst_f in unit_fields.items():
            found, raw_val = extract_nested_path(out, dst_f)
            if not found:
                found, raw_val = extract_nested_path(working, src_f)
            if not found:
                raise ToolWireFormatError(f"MISSING_UNIT_FIELD: '{src_f}' / '{dst_f}' missing in record.")
            if raw_val is None:
                if not dst_port.nullable:
                    raise ToolWireContractError(f"NULLABILITY_VIOLATION: unit field '{dst_f}' is None.")
                continue
            scaled_val, step_lossless, _ = convert_exact_unit_value(
                raw_val, src_port.unit, dst_port.unit, lossless=lossless, output_mode=unit_output_mode,
                allow_lossy=not lossless, exact_divisible_only=exact_divisible_only,
                allow_float_input=allow_float_input, target_precision=dst_port.precision, unit_conversion=unit_conv,
            )
            rec_lossless = rec_lossless and step_lossless
            set_nested_path(out, dst_f, scaled_val)

    for req in required_fields:
        found, rval = extract_nested_path(out, req)
        if not found:
            raise ToolWireFormatError(f"MISSING_REQUIRED_TARGET_FIELD: '{req}'.")
        if rval is None and not dst_port.nullable:
            raise ToolWireContractError(f"NULLABILITY_VIOLATION: required field '{req}' cannot be None.")

    if not dst_port.nullable and any(v is None for v in out.values()):
        raise ToolWireContractError("NULLABILITY_VIOLATION: None value emitted for nullable=False target.")

    if dst_port.precision and dst_port.precision.strip().lower() in (set(_INT_LIMITS) | set(_FLOAT_EXACT_INT_LIMITS) | _DECIMAL_PRECISIONS):
        _validate_record_numeric_precision(out, dst_port.precision, lossless=rec_lossless)

    if include_provenance:
        out["source_digest"] = src_digest
        out["transform_digest"] = xform_digest
    return out, rec_lossless


def _validate_record_numeric_precision(obj: Any, target_precision: str, *, lossless: bool) -> None:
    if isinstance(obj, float) and lossless:
        raise LossyConversionError(f"FLOAT_FORBIDDEN_FOR_PRECISION ({target_precision}): float {obj!r} violates exact precision.")
    if isinstance(obj, int) and not isinstance(obj, bool):
        _check_target_precision_bounds(obj, target_precision, lossless=lossless)
    elif isinstance(obj, MappingABC):
        for v in obj.values():
            _validate_record_numeric_precision(v, target_precision, lossless=lossless)
    elif isinstance(obj, (list, tuple)):
        for elem in obj:
            _validate_record_numeric_precision(elem, target_precision, lossless=lossless)


__all__ = [
    "CANONICAL_TIME_UNITS", "TIME_UNIT_NS_FACTORS", "TOOLWIRE_VERSION", "DeclassificationGrant",
    "LossyConversionError", "ToolWire", "ToolWireContractError", "ToolWireEncodingError",
    "ToolWireError", "ToolWireFormatError", "ToolWireSensitivityError", "WireDiagnostic",
    "WireFormat", "WireProvenanceSummary", "WireResult", "WireStream", "WiredRecord",
    "convert_exact_unit_value", "decode_json_exact", "encode_json_exact",
    "extract_nested_path", "set_nested_path", "validate_utf8_text",
]
