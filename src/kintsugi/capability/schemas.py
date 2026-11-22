"""Typed schemas, canonical hashing, validation, and secret redaction for Capability Fabric."""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from kintsugi.shield import (
    OUTBOUND_DLP_SECRET_RE,
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    redact_high_entropy_secrets,
    resolve_safe_child_path,
    scan_high_entropy_secrets,
)

VALID_TOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
VALID_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
VALID_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN\s+[A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END\s+[A-Z0-9 ]*PRIVATE KEY-----"
)
_BEARER_TOKEN_RE = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*(?:bearer|basic)\s+|bearer\s+)([A-Za-z0-9._~+/=-]{8,})"
)
_URL_USERINFO_RE = re.compile(r"(https?://)([^:@/\s]+):([^@/\s]+)@")
_CLI_SECRET_FLAG_RE = re.compile(
    r"(?i)(--?(?:api[-_]?key|token|secret|password|passwd|auth[-_]?token|private[-_]?key)(?:=|\s+))(['\"]?)([^\s'\"]{8,})\2"
)
_KNOWN_TOKEN_PREFIX_RE = re.compile(
    r"\b(?:sk-(?!proj-EXAMPLE_PLACEHOLDER)[A-Za-z0-9_-]{12,}|"
    r"tj_[A-Za-z0-9_-]{16,}|"
    r"gsk_(?!your_free_key)[A-Za-z0-9_-]{16,}|"
    r"xai-[A-Za-z0-9_-]{16,}|"
    r"hf_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"AIza[0-9A-Za-z_-]{30,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}|"
    r"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,})\b"
)

_SENSITIVE_KEY_EXACT = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "access_token",
        "auth_token",
        "bearer_token",
        "private_key",
        "client_secret",
        "api_token",
        "password",
        "passwd",
        "token",
        "authorization",
        "auth_header",
        "credential",
        "credentials",
        "cookie",
        "cookies",
        "session_token",
        "signing_key",
    }
)
_SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?i)(?:key|secret|token|pass|pwd|auth|cred|cookie|bearer|private)"
)
_SAFE_REDACTED_MARKERS = (
    "[REDACTED",
    "[HIGH_ENTROPY_REDACTED",
    "EXAMPLE_PLACEHOLDER",
    "YOUR_API_KEY",
    "YOUR_FREE_KEY",
)


class TrustStatus(str, Enum):
    """Trust lifecycle states for capability tools."""

    DISCOVERED = "DISCOVERED"
    QUARANTINED = "QUARANTINED"
    VERIFIED = "VERIFIED"
    RETIRED = "RETIRED"


class ExecutionStatus(str, Enum):
    """Strict execution receipt outcomes (`ExecutionReceipt/1`)."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_VERIFIED = "NOT_VERIFIED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NO_VERIFIED_TOOL = "NO_VERIFIED_TOOL"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    ROLLED_BACK = "ROLLED_BACK"


VALID_EXECUTION_STATUSES = frozenset(item.value for item in ExecutionStatus)


class SecurityProfile(str, Enum):
    """Execution security boundary profiles."""

    LOCAL_RESEARCH = "LOCAL_RESEARCH"
    GITHUB_PUBLIC = "GITHUB_PUBLIC"


def _to_json_native(value: Any) -> Any:
    """Recursively normalize enums, paths, sets, and schema objects for canonical JSON."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return value.to_dict()
    if isinstance(value, dict):
        return {str(k): _to_json_native(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_json_native(v) for v in value]
    if isinstance(value, set):
        return sorted(_to_json_native(v) for v in value)
    return value


def canonical_json_dumps(obj: Any) -> str:
    """Serialize `obj` deterministically using sorted keys and compact separators."""
    normalized = _to_json_native(obj)
    return json.dumps(normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def sha256_digest(data: Any) -> str:
    """Compute a `sha256:` content digest from bytes, string, or JSON-serializable object."""
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = canonical_json_dumps(data).encode("utf-8")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


# Stable, security-relevant ToolSpec/1 fields. Neither caller-supplied attestation
# nor mutable resource estimates/provenance may influence the signed contract.
_TOOL_SPEC_SECURITY_FIELDS = (
    "tool_id", "version", "source", "binary_hash", "capabilities",
    "input_schema", "output_schema", "semantic_contract", "preconditions",
    "postconditions", "side_effects", "required_permissions",
    "runtime_requirements", "entrypoint", "command",
)

_EXACT_TOOL_SPEC_FIELDS: Tuple[str, ...] = (
    "tool_id",
    "version",
    "source",
    "binary_hash",
    "capabilities",
    "input_schema",
    "output_schema",
    "semantic_contract",
    "preconditions",
    "postconditions",
    "side_effects",
    "required_permissions",
    "runtime_requirements",
    "trust_status",
    "latency_estimate_ms",
    "memory_estimate_mb",
    "api_token_estimate",
    "verification_attestation",
    "provenance",
    "entrypoint",
    "command",
    "schema",
)

_EXACT_SECURITY_CONTEXT_FIELDS: Tuple[str, ...] = (
    "workspace_root",
    "profile",
    "allowed_permissions",
    "network_allowed",
    "allow_untrusted_native",
    "policy_hash",
    "schema",
)

_SCHEMA_TYPE_DICT_DESCR = type.__dict__["__dict__"]
_SCHEMA_TYPE_MRO_DESCR = type.__dict__["__mro__"]
_SCHEMA_OBJECT_GETATTR = object.__getattribute__
_EXACT_PATH_TYPES: Tuple[type, ...] = tuple(
    dict.fromkeys(
        t
        for t in (
            Path,
            getattr(pathlib, "PosixPath", None),
            getattr(pathlib, "WindowsPath", None),
            getattr(pathlib, "PurePosixPath", None),
            getattr(pathlib, "PureWindowsPath", None),
        )
        if t is not None
    )
)
_TRUST_STATUS_IDENTITY_PAIRS: Tuple[Tuple[TrustStatus, str], ...] = tuple(
    (member, member.value) for member in TrustStatus
)
_SECURITY_PROFILE_IDENTITY_PAIRS: Tuple[Tuple[SecurityProfile, str], ...] = tuple(
    (member, member.value) for member in SecurityProfile
)


def is_exact_path_type(tp: type) -> bool:
    """Return True iff `tp` is pointer-identical to an immutable stdlib `Path` concrete type."""
    for candidate in _EXACT_PATH_TYPES:
        if tp is candidate:
            return True
    return False


def safe_exact_str_dict_view(mapping: Any, *, max_entries: int = 4096) -> Optional[Dict[str, Any]]:
    """Copy a raw `dict` linearly rejecting non-`str` keys without triggering `__hash__`/`__eq__`."""
    if type(mapping) is not dict:
        return None
    out: Dict[str, Any] = {}
    count = 0
    for k, v in dict.items(mapping):
        count += 1
        if count > max_entries or type(k) is not str:
            return None
        out[k] = v
    return out


def safe_type_has_descriptor(val: Any) -> bool:
    """Return True iff `type(val)` implements the descriptor protocol (`__get__`/`__set__`/`__delete__`)."""
    vt = type(val)
    mro = _SCHEMA_TYPE_MRO_DESCR.__get__(vt, type)
    if type(mro) is not tuple:
        return True
    for base_cls in mro:
        if base_cls is object:
            continue
        raw_base = _SCHEMA_TYPE_DICT_DESCR.__get__(base_cls, type)
        base_view: Dict[str, Any] = {}
        for k, v in raw_base.items():
            if type(k) is not str:
                return True
            base_view[k] = v
        if "__get__" in base_view or "__set__" in base_view or "__delete__" in base_view:
            return True
    return False


_FORBIDDEN_CONTRACT_HOOKS: Tuple[str, ...] = (
    "__new__",
    "__setattr__",
    "__delattr__",
    "__getattribute__",
    "__getattr__",
    "__bool__",
    "__ne__",
    "__str__",
    "__fspath__",
)
_PINNED_LIFECYCLE_ATTRS: Tuple[str, ...] = (
    "__init__",
    "__post_init__",
    "__repr__",
    "__eq__",
    "__hash__",
    "validate_path",
    "to_dict",
    "to_canonical_json",
    "content_hash",
    "from_dict",
    "_clean_excerpt",
)


def snapshot_class_lifecycle(cls: type) -> Callable[[Dict[str, Any]], None]:
    """Capture import-time raw `tp_dict` lifecycle method identities inside a callable guard."""
    raw_dict = _SCHEMA_TYPE_DICT_DESCR.__get__(cls, type)
    pinned: Tuple[Tuple[str, Any], ...] = tuple(
        (attr, raw_dict[attr]) for attr in _PINNED_LIFECYCLE_ATTRS if attr in raw_dict
    )

    def _verify_lifecycle(base_view: Dict[str, Any]) -> None:
        for method_name, orig_fn in pinned:
            if method_name not in base_view or base_view[method_name] is not orig_fn:
                raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")

    return _verify_lifecycle


def assert_dataclass_type_unmodified(
    cls: type,
    field_names: Tuple[str, ...],
    orig_dict_descr: Any,
    *,
    allowed_base_dict_descrs: Tuple[Any, ...] = (),
    expected_mro: Optional[Tuple[type, ...]] = None,
    orig_lifecycle_methods: Optional[Callable[[Dict[str, Any]], None]] = None,
    allowed_base_lifecycle_methods: Optional[Tuple[Tuple[type, Callable[[Dict[str, Any]], None]], ...]] = None,
) -> None:
    """Verify via raw C type dicts that no descriptor or lifecycle hook was injected or replaced."""
    mro = _SCHEMA_TYPE_MRO_DESCR.__get__(cls, type)
    if type(mro) is not tuple or len(mro) < 2:
        raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
    if expected_mro is not None:
        if len(mro) != len(expected_mro) or not all(a is b for a, b in zip(mro, expected_mro)):
            raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
    for idx, base_cls in enumerate(mro):
        if base_cls is object:
            continue
        raw_base = _SCHEMA_TYPE_DICT_DESCR.__get__(base_cls, type)
        base_view: Dict[str, Any] = {}
        for k, v in raw_base.items():
            if type(k) is not str:
                raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
            base_view[k] = v
        for hook_name in _FORBIDDEN_CONTRACT_HOOKS:
            if hook_name in base_view:
                raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
        if idx == 0:
            if orig_dict_descr is None:
                if "__dict__" in base_view:
                    raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
            elif "__dict__" not in base_view or base_view["__dict__"] is not orig_dict_descr:
                raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
            if orig_lifecycle_methods is not None:
                orig_lifecycle_methods(base_view)
        else:
            if "__dict__" in base_view:
                if not any(
                    base_view["__dict__"] is allowed and allowed is not None for allowed in allowed_base_dict_descrs
                ):
                    raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")
            if allowed_base_lifecycle_methods is not None:
                for target_base, verify_fn in allowed_base_lifecycle_methods:
                    if base_cls is target_base:
                        verify_fn(base_view)
        for fname in field_names:
            if fname in base_view and safe_type_has_descriptor(base_view[fname]):
                raise TypeError("UNTRUSTED_CONTRACT_CLASS_TAMPERED")


def sanitize_exact_json_value(
    value: Any,
    *,
    allow_bytes: bool = False,
    max_depth: int = 32,
    max_nodes: int = 4096,
) -> Any:
    """Recursively copy exact built-in JSON/bytes primitives without accepting `Path` or user hooks."""
    nodes = 0
    active_ids: set[int] = set()

    def _walk(item: Any, depth: int) -> Any:
        nonlocal nodes
        if depth > max_depth:
            raise ValueError("UNTRUSTED_VALUE_MAX_DEPTH_EXCEEDED")
        nodes += 1
        if nodes > max_nodes:
            raise ValueError("UNTRUSTED_VALUE_MAX_NODES_EXCEEDED")
        if item is None:
            return None
        vt = type(item)
        if vt is bool or vt is int or vt is float or vt is str:
            return item
        if allow_bytes and vt is bytes:
            return item
        if vt is list:
            oid = id(item)
            if oid in active_ids:
                raise ValueError("UNTRUSTED_CYCLIC_VALUE_FORBIDDEN")
            active_ids.add(oid)
            try:
                return [_walk(sub, depth + 1) for sub in list.__iter__(item)]
            finally:
                active_ids.discard(oid)
        if vt is tuple:
            oid = id(item)
            if oid in active_ids:
                raise ValueError("UNTRUSTED_CYCLIC_VALUE_FORBIDDEN")
            active_ids.add(oid)
            try:
                return tuple(_walk(sub, depth + 1) for sub in tuple.__iter__(item))
            finally:
                active_ids.discard(oid)
        if vt is dict:
            oid = id(item)
            if oid in active_ids:
                raise ValueError("UNTRUSTED_CYCLIC_VALUE_FORBIDDEN")
            view = safe_exact_str_dict_view(item, max_entries=max_nodes)
            if view is None:
                raise ValueError("UNTRUSTED_NON_STRING_DICT_KEY")
            active_ids.add(oid)
            try:
                return {k: _walk(v, depth + 1) for k, v in dict.items(view)}
            finally:
                active_ids.discard(oid)
        raise TypeError("UNTRUSTED_NON_EXACT_DATA_TYPE")

    return _walk(value, 0)


def extract_exact_str_list(value: Any, *, field_name: str, allow_none: bool = False) -> Optional[List[str]]:
    """Extract a `list`/`tuple` of exact `str` items without invoking coercion or iteration hooks."""
    if value is None:
        if allow_none:
            return None
        raise TypeError(f"UNTRUSTED_{field_name.upper()}_TYPE")
    vt = type(value)
    if vt is list:
        seq_iter = list.__iter__(value)
    elif vt is tuple:
        seq_iter = tuple.__iter__(value)
    else:
        raise TypeError(f"UNTRUSTED_{field_name.upper()}_TYPE")
    out: List[str] = []
    for elem in seq_iter:
        if type(elem) is not str:
            raise TypeError(f"UNTRUSTED_{field_name.upper()}_ELEMENT_TYPE")
        out.append(elem)
    return out


def compute_tool_spec_security_digest(spec_or_dict: Any) -> str:
    """Canonical SHA-256 over *all* execution- and permission-relevant ToolSpec fields.

    Excludes the attestation itself to avoid recursive signatures. Uses hook-free
    exact-type field extraction so untrusted subclasses or descriptors never run.
    """
    st = type(spec_or_dict)
    if st is dict:
        clean_dict = sanitize_exact_json_value(spec_or_dict, allow_bytes=False)
        required = {"tool_id", "version", "source", "binary_hash", "capabilities"}
        if not required.issubset(clean_dict):
            raise ValueError("TOOL_SPEC_SECURITY_FIELDS_MISSING")
        fields = {key: clean_dict.get(key) for key in _TOOL_SPEC_SECURITY_FIELDS}
        fields.update({key: clean_dict.get(key, []) for key in (
            "preconditions", "postconditions", "side_effects", "required_permissions")})
        fields.update({key: clean_dict.get(key, {}) for key in (
            "input_schema", "output_schema", "semantic_contract", "runtime_requirements")})
    elif st is ToolSpec:
        data = extract_exact_tool_spec_dict(spec_or_dict)
        fields = {key: data.get(key) for key in _TOOL_SPEC_SECURITY_FIELDS}
    else:
        raise TypeError("TOOL_SPEC_SECURITY_DIGEST_REQUIRES_EXACT_TOOL_SPEC_OR_DICT")
    return sha256_digest({"domain": "ToolSpecSecurity/1", "fields": fields})


def is_valid_sha256(digest: Any) -> bool:
    """Return True if `digest` is an exact `str` matching `sha256:<64-hex>`."""
    if type(digest) is not str:
        return False
    return bool(VALID_SHA256_RE.fullmatch(digest.strip().lower()))


def normalize_sha256(digest: Any, *, field_name: str = "digest") -> str:
    """Validate and normalize an exact `str` `sha256:` hex digest."""
    if type(digest) is not str:
        raise ValueError(f"INVALID_{field_name.upper()}: expected exact sha256:<64hex> string.")
    cleaned = digest.strip().lower()
    if not VALID_SHA256_RE.fullmatch(cleaned):
        raise ValueError(f"INVALID_{field_name.upper()}: '{digest}' is not a valid sha256:<64hex> digest.")
    return cleaned


def _short_sha8(secret_value: str) -> str:
    return hashlib.sha256(secret_value.encode("utf-8")).hexdigest()[:8]


def _is_already_redacted_or_digest(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if any(stripped.startswith(marker) for marker in _SAFE_REDACTED_MARKERS):
        return True
    if VALID_SHA256_RE.fullmatch(stripped.lower()):
        return True
    return False


def redact_secrets_in_text(text: str, *, redact_paths: bool = False) -> str:
    """Scrub private keys, tokens, high-entropy assignments, and credential patterns from text."""
    if not text:
        return ""
    out = _PEM_PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    out = _URL_USERINFO_RE.sub(r"\1[REDACTED_USER]:[REDACTED_PASS]@", out)
    out = _BEARER_TOKEN_RE.sub(r"\1[REDACTED_TOKEN]", out)
    out = _CLI_SECRET_FLAG_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED_SECRET:{_short_sha8(m.group(3))}]{m.group(2)}",
        out,
    )
    out = _KNOWN_TOKEN_PREFIX_RE.sub(lambda m: f"[REDACTED_SECRET:{_short_sha8(m.group(0))}]", out)
    out = redact_high_entropy_secrets(out)
    if redact_paths:
        out = OUTBOUND_DLP_SECRET_RE.sub(
            lambda m: f"[REDACTED_DLP:{_short_sha8(m.group(0))}]",
            out,
        )
    return out


def redact_secrets_in_value(
    value: Any,
    *,
    key_hint: str = "",
    in_env_mapping: bool = False,
) -> Any:
    """Recursively redact secrets inside strings, dicts, and lists before persistence."""
    if isinstance(value, str):
        norm_key = key_hint.lower().replace("-", "_")
        is_sensitive_key = norm_key in _SENSITIVE_KEY_EXACT or (
            in_env_mapping and bool(_SENSITIVE_ENV_KEY_RE.search(norm_key))
        )
        if is_sensitive_key and not _is_already_redacted_or_digest(value):
            return f"[REDACTED_SECRET:{_short_sha8(value)}]"
        return redact_secrets_in_text(value)
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for k, v in value.items():
            key_str = str(k)
            child_env = in_env_mapping or key_str.lower() in {"env", "environment", "headers", "secrets"}
            result[key_str] = redact_secrets_in_value(
                v,
                key_hint=key_str,
                in_env_mapping=child_env,
            )
        return result
    if isinstance(value, (list, tuple)):
        return [
            redact_secrets_in_value(item, key_hint=key_hint, in_env_mapping=in_env_mapping)
            for item in value
        ]
    return value


def assert_no_raw_secrets(serialized_json: str, *, context: str = "schema") -> None:
    """Verify no high-entropy contextual secrets remain in canonical serialized JSON."""
    hits = scan_high_entropy_secrets(serialized_json)
    if hits:
        first = hits[0]
        raise ValueError(
            f"SECRET_LEAK_BLOCKED ({context}): high-entropy secret detected (sha8={first['candidate_sha8']})."
        )


def validate_safe_text(value: Any, *, field_name: str, allow_empty: bool = False) -> str:
    """Ensure text fields contain exact `str` without NUL bytes or Trojan/Bidi Unicode characters."""
    if type(value) is not str:
        raise ValueError(f"INVALID_{field_name.upper()}: expected exact string.")
    if "\x00" in value:
        raise ValueError(f"INVALID_{field_name.upper()}: NUL byte forbidden.")
    if TROJAN_UNICODE_RE.search(value):
        raise ValueError(f"REJECTED_TROJAN_UNICODE ({field_name}): invisible/bidi character detected.")
    cleaned = value.strip()
    if not allow_empty and not cleaned:
        raise ValueError(f"INVALID_{field_name.upper()}: must be non-empty.")
    return cleaned


def validate_tool_id(tool_id: Any) -> str:
    """Reject empty, path-traversal, slash-containing, or Trojan-Unicode `tool_id` values."""
    cleaned = validate_safe_text(tool_id, field_name="tool_id")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise ValueError(f"REJECTED_TRAVERSAL_TOOL_ID: invalid tool_id '{cleaned}'.")
    if not VALID_TOOL_ID_RE.fullmatch(cleaned):
        raise ValueError(f"REJECTED_INVALID_TOOL_ID: '{cleaned}' violates strict identifier syntax.")
    return cleaned


def _validate_string_list(values: Any, *, field_name: str, allow_empty: bool = True) -> List[str]:
    if values is None:
        items: List[str] = []
    elif isinstance(values, (list, tuple, set)):
        items = [validate_safe_text(str(item), field_name=field_name) for item in values]
    else:
        raise ValueError(f"INVALID_{field_name.upper()}: expected sequence of strings.")
    deduped = list(dict.fromkeys(items))
    if not allow_empty and not deduped:
        raise ValueError(f"INVALID_{field_name.upper()}: must contain at least one entry.")
    return deduped


def _validate_no_trojan_in_structure(value: Any, *, field_name: str) -> None:
    if isinstance(value, str):
        if "\x00" in value or TROJAN_UNICODE_RE.search(value):
            raise ValueError(f"REJECTED_TROJAN_UNICODE ({field_name}): control character detected.")
    elif isinstance(value, dict):
        for k, v in value.items():
            _validate_no_trojan_in_structure(str(k), field_name=field_name)
            _validate_no_trojan_in_structure(v, field_name=field_name)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_no_trojan_in_structure(item, field_name=field_name)


def has_valid_verification_attestation(
    attestation: Any,
    binary_hash: str,
    tool_id: str,
) -> bool:
    """Validate via exact built-in types that `verification_attestation` binds verifier and `binary_hash`."""
    if type(attestation) is not dict or type(binary_hash) is not str or type(tool_id) is not str:
        return False
    att_view = safe_exact_str_dict_view(attestation)
    if not att_view:
        return False
    self_asserted = att_view.get("self_asserted")
    if self_asserted is True:
        return False
    if self_asserted is not None and type(self_asserted) is not bool:
        return False
    raw_source = att_view.get("source", "")
    if raw_source is None:
        raw_source = ""
    elif type(raw_source) is not str:
        return False
    source = raw_source.strip().lower()
    if source in {"discovery", "local_discovery", "mcp_discovery", "untrusted"}:
        return False
    verifier_id = att_view.get("verifier_id")
    if type(verifier_id) is not str:
        return False
    cleaned_verifier = verifier_id.strip()
    if not cleaned_verifier or cleaned_verifier.lower() in {
        "self",
        "auto",
        "discovery",
        "none",
        "unverified",
        tool_id.lower(),
    }:
        return False
    if TROJAN_UNICODE_RE.search(cleaned_verifier):
        return False
    if not is_valid_sha256(att_view.get("verification_digest")):
        return False
    attested_bin = att_view.get("binary_hash")
    if attested_bin is not None:
        if type(attested_bin) is not str or attested_bin.strip().lower() != binary_hash.lower():
            return False
    attested_tool_id = att_view.get("tool_id")
    if attested_tool_id is not None:
        if type(attested_tool_id) is not str or attested_tool_id.strip() != tool_id:
            return False
    return True


def has_suspicious_metadata(raw_payload: Dict[str, Any]) -> Optional[str]:
    """Return a quarantine reason if raw discovery metadata exhibits injection or unsafe assertions."""
    serialized = canonical_json_dumps(raw_payload)
    if TROJAN_UNICODE_RE.search(serialized):
        return "TROJAN_UNICODE_IN_METADATA"
    if PROMPT_INJECTION_RE.search(serialized):
        return "PROMPT_INJECTION_IN_METADATA"
    raw_trust = str(raw_payload.get("trust_status", "")).strip().upper()
    if raw_trust == TrustStatus.VERIFIED.value:
        return "SELF_ASSERTED_TRUST_ESCALATION"
    entrypoint = raw_payload.get("entrypoint")
    if isinstance(entrypoint, str) and (".." in Path(entrypoint).parts or "\x00" in entrypoint):
        return "SUSPICIOUS_ENTRYPOINT_TRAVERSAL"
    return None


@dataclass
class SecurityContext:
    """Execution security boundary (`SecurityContext/1`) enforcing workspace & symlink isolation."""

    workspace_root: str
    profile: Union[SecurityProfile, str] = SecurityProfile.LOCAL_RESEARCH
    allowed_permissions: List[str] = field(default_factory=list)
    network_allowed: bool = False
    allow_untrusted_native: bool = False
    policy_hash: str = ""
    schema: str = "SecurityContext/1"

    def __post_init__(self) -> None:
        if self.schema != "SecurityContext/1":
            raise ValueError(f"INVALID_SCHEMA: expected SecurityContext/1, got '{self.schema}'.")
        raw_root = validate_safe_text(self.workspace_root, field_name="workspace_root")
        root_path = Path(raw_root)
        assert_not_symlink(root_path)
        if not root_path.is_absolute():
            root_path = Path.cwd() / root_path
            assert_not_symlink(root_path)
        self.workspace_root = str(root_path.resolve())

        if isinstance(self.profile, str):
            self.profile = SecurityProfile(self.profile.strip().upper())
        elif not isinstance(self.profile, SecurityProfile):
            raise ValueError(f"INVALID_SECURITY_PROFILE: {self.profile!r}")

        self.allowed_permissions = sorted(
            _validate_string_list(self.allowed_permissions, field_name="allowed_permissions", allow_empty=True)
        )
        self.network_allowed = bool(self.network_allowed)
        self.allow_untrusted_native = bool(self.allow_untrusted_native)

        if not self.policy_hash:
            self.policy_hash = sha256_digest(
                {
                    "schema": self.schema,
                    "profile": self.profile.value,
                    "workspace_root": self.workspace_root,
                    "allowed_permissions": self.allowed_permissions,
                    "network_allowed": self.network_allowed,
                    "allow_untrusted_native": self.allow_untrusted_native,
                }
            )
        else:
            self.policy_hash = normalize_sha256(self.policy_hash, field_name="policy_hash")

    def validate_path(self, target_path: Union[str, Path]) -> Path:
        """Verify `target_path` contains no symlinks and resolves inside `workspace_root`."""
        raw = str(target_path)
        if not raw or "\x00" in raw or TROJAN_UNICODE_RE.search(raw):
            raise PermissionError("SECURITY_INVALID_PATH: empty, NUL, or control characters in path.")
        ws_path = Path(self.workspace_root)
        assert_not_symlink(ws_path)

        candidate_in = Path(raw)
        if candidate_in.is_absolute():
            assert_not_symlink(candidate_in)
            try:
                rel = candidate_in.relative_to(ws_path)
            except ValueError:
                resolved = candidate_in.resolve()
                try:
                    rel = resolved.relative_to(ws_path.resolve())
                except ValueError as exc:
                    raise PermissionError(
                        f"SECURITY_WORKSPACE_ESCAPE: '{target_path}' is outside workspace '{self.workspace_root}'."
                    ) from exc
            rel_str = str(rel) if str(rel) != "." else "."
        else:
            rel_str = raw

        if rel_str == ".":
            return ws_path.resolve()

        cur = ws_path
        for part in Path(rel_str).parts:
            if part in ("", "."):
                continue
            if part == "..":
                raise PermissionError(f"SECURITY_PATH_TRAVERSAL: '..' segment rejected in '{target_path}'.")
            cur = cur / part
            assert_not_symlink(cur)

        resolved_child = resolve_safe_child_path(ws_path, rel_str)
        if resolved_child is None:
            raise PermissionError(
                f"SECURITY_WORKSPACE_ESCAPE: '{target_path}' escapes '{self.workspace_root}'."
            )
        assert_not_symlink(resolved_child)
        return resolved_child

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "workspace_root": self.workspace_root,
            "profile": self.profile.value,
            "allowed_permissions": list(self.allowed_permissions),
            "network_allowed": self.network_allowed,
            "allow_untrusted_native": self.allow_untrusted_native,
            "policy_hash": self.policy_hash,
        }

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context="SecurityContext")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityContext":
        if not isinstance(data, dict):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected dict.")
        return cls(
            workspace_root=data["workspace_root"],
            profile=data.get("profile", SecurityProfile.LOCAL_RESEARCH),
            allowed_permissions=list(data.get("allowed_permissions", [])),
            network_allowed=bool(data.get("network_allowed", False)),
            allow_untrusted_native=bool(data.get("allow_untrusted_native", False)),
            policy_hash=data.get("policy_hash", ""),
            schema=data.get("schema", "SecurityContext/1"),
        )


@dataclass
class ToolSpec:
    """Typed capability tool contract (`ToolSpec/1`) with strict trust and secret hygiene."""

    tool_id: str
    version: str
    source: str
    binary_hash: str
    capabilities: List[str]
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    semantic_contract: Dict[str, Any] = field(default_factory=dict)
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    required_permissions: List[str] = field(default_factory=list)
    runtime_requirements: Dict[str, Any] = field(default_factory=dict)
    trust_status: Union[TrustStatus, str] = TrustStatus.DISCOVERED
    latency_estimate_ms: float = 0.0
    memory_estimate_mb: float = 0.0
    api_token_estimate: int = 0
    verification_attestation: Optional[Dict[str, Any]] = None
    provenance: Dict[str, Any] = field(default_factory=dict)
    entrypoint: Optional[str] = None
    command: Optional[List[str]] = None
    schema: str = "ToolSpec/1"

    def __post_init__(self) -> None:
        if self.schema != "ToolSpec/1":
            raise ValueError(f"INVALID_SCHEMA: expected ToolSpec/1, got '{self.schema}'.")
        self.tool_id = validate_tool_id(self.tool_id)
        self.version = validate_safe_text(self.version, field_name="version")
        self.source = validate_safe_text(self.source, field_name="source")
        self.binary_hash = normalize_sha256(self.binary_hash, field_name="binary_hash")
        self.capabilities = _validate_string_list(self.capabilities, field_name="capabilities", allow_empty=False)

        self.input_schema = dict(self.input_schema or {})
        self.output_schema = dict(self.output_schema or {})
        if isinstance(self.semantic_contract, str):
            self.semantic_contract = {"contract": self.semantic_contract}
        else:
            self.semantic_contract = dict(self.semantic_contract or {})

        self.preconditions = _validate_string_list(self.preconditions, field_name="preconditions")
        self.postconditions = _validate_string_list(self.postconditions, field_name="postconditions")
        self.side_effects = _validate_string_list(self.side_effects, field_name="side_effects")
        self.required_permissions = sorted(
            _validate_string_list(self.required_permissions, field_name="required_permissions")
        )
        self.runtime_requirements = dict(self.runtime_requirements or {})

        if isinstance(self.trust_status, str):
            self.trust_status = TrustStatus(self.trust_status.strip().upper())
        elif not isinstance(self.trust_status, TrustStatus):
            raise ValueError(f"INVALID_TRUST_STATUS: {self.trust_status!r}")

        self.latency_estimate_ms = float(self.latency_estimate_ms)
        self.memory_estimate_mb = float(self.memory_estimate_mb)
        self.api_token_estimate = int(self.api_token_estimate)
        if self.latency_estimate_ms < 0 or self.memory_estimate_mb < 0 or self.api_token_estimate < 0:
            raise ValueError("INVALID_RESOURCE_ESTIMATE: latency, memory, and token estimates must be >= 0.")

        if self.entrypoint is not None:
            cleaned_entry = validate_safe_text(self.entrypoint, field_name="entrypoint")
            if ".." in Path(cleaned_entry).parts:
                raise ValueError(f"REJECTED_ENTRYPOINT_TRAVERSAL: '{cleaned_entry}' contains '..'.")
            self.entrypoint = redact_secrets_in_text(cleaned_entry)

        if self.command is not None:
            if isinstance(self.command, str):
                raw_cmd = [self.command]
            elif isinstance(self.command, (list, tuple)):
                raw_cmd = [str(part) for part in self.command]
            else:
                raise ValueError("INVALID_COMMAND: expected list of strings.")
            self.command = [
                redact_secrets_in_text(validate_safe_text(part, field_name="command"))
                for part in raw_cmd
            ]

        self.input_schema = redact_secrets_in_value(self.input_schema)
        self.output_schema = redact_secrets_in_value(self.output_schema)
        self.semantic_contract = redact_secrets_in_value(self.semantic_contract)
        self.runtime_requirements = redact_secrets_in_value(self.runtime_requirements)
        self.provenance = redact_secrets_in_value(dict(self.provenance or {}))
        if self.verification_attestation is not None:
            if not isinstance(self.verification_attestation, dict):
                raise ValueError("INVALID_VERIFICATION_ATTESTATION: expected attestation dict.")
            self.verification_attestation = redact_secrets_in_value(dict(self.verification_attestation))

        for struct_name, struct_val in (
            ("input_schema", self.input_schema),
            ("output_schema", self.output_schema),
            ("semantic_contract", self.semantic_contract),
            ("runtime_requirements", self.runtime_requirements),
            ("provenance", self.provenance),
            ("verification_attestation", self.verification_attestation),
        ):
            _validate_no_trojan_in_structure(struct_val, field_name=struct_name)

        if self.trust_status == TrustStatus.VERIFIED:
            if not has_valid_verification_attestation(
                self.verification_attestation, self.binary_hash, self.tool_id
            ):
                raise ValueError(
                    "REJECTED_UNVERIFIED_TRUST_ESCALATION: VERIFIED status requires valid verification_attestation."
                )

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["trust_status"] = self.trust_status.value
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"ToolSpec:{self.tool_id}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any], *, from_discovery: bool = False) -> "ToolSpec":
        """Deserialize a `ToolSpec`, downgrading self-asserted `VERIFIED` discovery payloads."""
        if not isinstance(data, dict):
            raise ValueError("INVALID_TOOL_SPEC: expected dict.")
        payload = dict(data)
        raw_source = str(payload.get("source", "")).strip().lower()
        raw_trust = str(payload.get("trust_status", TrustStatus.DISCOVERED.value)).strip().upper()
        provenance = dict(payload.get("provenance") or {})
        attestation = payload.get("verification_attestation")

        has_attestation = has_valid_verification_attestation(
            attestation,
            str(payload.get("binary_hash", "")).strip().lower(),
            str(payload.get("tool_id", "")).strip(),
        )
        if from_discovery or (
            raw_source in {"discovery", "local_discovery", "mcp_discovery"} and not has_attestation
        ):
            suspicious_reason = has_suspicious_metadata(payload)
            if raw_trust == TrustStatus.VERIFIED.value:
                payload["trust_status"] = TrustStatus.QUARANTINED.value
                payload["verification_attestation"] = None
                provenance["quarantine_reason"] = suspicious_reason or "SELF_ASSERTED_TRUST_ESCALATION"
            elif suspicious_reason:
                payload["trust_status"] = TrustStatus.QUARANTINED.value
                payload["verification_attestation"] = None
                provenance["quarantine_reason"] = suspicious_reason
            elif raw_trust not in {
                TrustStatus.DISCOVERED.value,
                TrustStatus.QUARANTINED.value,
                TrustStatus.RETIRED.value,
            }:
                payload["trust_status"] = TrustStatus.QUARANTINED.value
                provenance["quarantine_reason"] = "INVALID_DISCOVERY_TRUST_STATUS"
            payload["provenance"] = provenance
        elif raw_trust == TrustStatus.VERIFIED.value and not has_attestation:
            raise ValueError(
                "REJECTED_UNVERIFIED_TRUST_ESCALATION: VERIFIED ToolSpec lacks valid verification_attestation."
            )

        return cls(
            tool_id=payload["tool_id"],
            version=payload.get("version", "0.0.0"),
            source=payload.get("source", "unknown"),
            binary_hash=payload["binary_hash"],
            capabilities=payload["capabilities"],
            input_schema=payload.get("input_schema", {}),
            output_schema=payload.get("output_schema", {}),
            semantic_contract=payload.get("semantic_contract", {}),
            preconditions=payload.get("preconditions", []),
            postconditions=payload.get("postconditions", []),
            side_effects=payload.get("side_effects", []),
            required_permissions=payload.get("required_permissions", []),
            runtime_requirements=payload.get("runtime_requirements", {}),
            trust_status=payload.get("trust_status", TrustStatus.DISCOVERED),
            latency_estimate_ms=payload.get("latency_estimate_ms", 0.0),
            memory_estimate_mb=payload.get("memory_estimate_mb", 0.0),
            api_token_estimate=payload.get("api_token_estimate", 0),
            verification_attestation=payload.get("verification_attestation"),
            provenance=payload.get("provenance", {}),
            entrypoint=payload.get("entrypoint"),
            command=payload.get("command"),
            schema=payload.get("schema", "ToolSpec/1"),
        )


_ORIG_SECURITY_CONTEXT_DICT_DESCR = _SCHEMA_TYPE_DICT_DESCR.__get__(SecurityContext, type).get("__dict__")
_ORIG_TOOL_SPEC_DICT_DESCR = _SCHEMA_TYPE_DICT_DESCR.__get__(ToolSpec, type).get("__dict__")
_ORIG_SECURITY_CONTEXT_LIFECYCLE = snapshot_class_lifecycle(SecurityContext)
_ORIG_TOOL_SPEC_LIFECYCLE = snapshot_class_lifecycle(ToolSpec)


def extract_exact_security_context_dict(ctx: Any) -> Dict[str, Any]:
    """Extract clean built-in fields from an exact `SecurityContext` without running any hooks."""
    if type(ctx) is not SecurityContext:
        raise TypeError("UNTRUSTED_SECURITY_CONTEXT_SUBCLASS_FORBIDDEN")
    assert_dataclass_type_unmodified(
        SecurityContext,
        _EXACT_SECURITY_CONTEXT_FIELDS,
        _ORIG_SECURITY_CONTEXT_DICT_DESCR,
        expected_mro=(SecurityContext, object),
        orig_lifecycle_methods=_ORIG_SECURITY_CONTEXT_LIFECYCLE,
    )
    raw_d = _SCHEMA_OBJECT_GETATTR(ctx, "__dict__")
    view = safe_exact_str_dict_view(raw_d)
    if view is None:
        raise ValueError("UNTRUSTED_SECURITY_CONTEXT_STORAGE")
    for k in view:
        if k not in _EXACT_SECURITY_CONTEXT_FIELDS:
            raise ValueError("UNTRUSTED_SECURITY_CONTEXT_EXTRA_FIELD")
    for req_field in ("workspace_root", "policy_hash", "schema"):
        if req_field not in view or type(view[req_field]) is not str:
            raise TypeError(f"UNTRUSTED_SECURITY_CONTEXT_{req_field.upper()}")
    raw_profile = view.get("profile")
    profile_str: Optional[str] = None
    for member, member_val in _SECURITY_PROFILE_IDENTITY_PAIRS:
        if raw_profile is member:
            profile_str = member_val
            break
    if profile_str is None:
        if type(raw_profile) is str:
            profile_str = raw_profile
        else:
            raise TypeError("UNTRUSTED_SECURITY_CONTEXT_PROFILE")
    allowed_perms = extract_exact_str_list(
        view.get("allowed_permissions"), field_name="allowed_permissions"
    )
    assert allowed_perms is not None
    net_allowed = view.get("network_allowed")
    untrusted_native = view.get("allow_untrusted_native")
    if type(net_allowed) is not bool or type(untrusted_native) is not bool:
        raise TypeError("UNTRUSTED_SECURITY_CONTEXT_FLAGS")
    return {
        "schema": view["schema"],
        "workspace_root": view["workspace_root"],
        "profile": profile_str,
        "allowed_permissions": allowed_perms,
        "network_allowed": net_allowed,
        "allow_untrusted_native": untrusted_native,
        "policy_hash": view["policy_hash"],
    }


def extract_exact_tool_spec_dict(spec: Any) -> Dict[str, Any]:
    """Extract clean canonical fields from an exact `ToolSpec` without running descriptors or `to_dict()`."""
    if type(spec) is not ToolSpec:
        raise TypeError("UNTRUSTED_TOOL_SPEC_SUBCLASS_FORBIDDEN")
    assert_dataclass_type_unmodified(
        ToolSpec,
        _EXACT_TOOL_SPEC_FIELDS,
        _ORIG_TOOL_SPEC_DICT_DESCR,
        expected_mro=(ToolSpec, object),
        orig_lifecycle_methods=_ORIG_TOOL_SPEC_LIFECYCLE,
    )
    raw_d = _SCHEMA_OBJECT_GETATTR(spec, "__dict__")
    view = safe_exact_str_dict_view(raw_d)
    if view is None:
        raise ValueError("UNTRUSTED_TOOL_SPEC_STORAGE")
    for k in view:
        if k not in _EXACT_TOOL_SPEC_FIELDS:
            raise ValueError("UNTRUSTED_TOOL_SPEC_EXTRA_FIELD")
    for str_field in ("tool_id", "version", "source", "binary_hash", "schema"):
        if str_field not in view or type(view[str_field]) is not str:
            raise TypeError(f"UNTRUSTED_TOOL_SPEC_{str_field.upper()}")
    entrypoint = view.get("entrypoint")
    if entrypoint is not None and type(entrypoint) is not str:
        raise TypeError("UNTRUSTED_TOOL_SPEC_ENTRYPOINT")
    raw_trust = view.get("trust_status")
    trust_str: Optional[str] = None
    for member, member_val in _TRUST_STATUS_IDENTITY_PAIRS:
        if raw_trust is member:
            trust_str = member_val
            break
    if trust_str is None:
        if type(raw_trust) is str:
            trust_str = raw_trust
        else:
            raise TypeError("UNTRUSTED_TOOL_SPEC_TRUST_STATUS")
    capabilities = extract_exact_str_list(view.get("capabilities"), field_name="capabilities")
    preconditions = extract_exact_str_list(view.get("preconditions"), field_name="preconditions")
    postconditions = extract_exact_str_list(view.get("postconditions"), field_name="postconditions")
    side_effects = extract_exact_str_list(view.get("side_effects"), field_name="side_effects")
    required_permissions = extract_exact_str_list(
        view.get("required_permissions"), field_name="required_permissions"
    )
    command = extract_exact_str_list(view.get("command"), field_name="command", allow_none=True)
    lat_val = view.get("latency_estimate_ms")
    mem_val = view.get("memory_estimate_mb")
    tok_val = view.get("api_token_estimate")
    vt_lat = type(lat_val)
    vt_mem = type(mem_val)
    if (
        (vt_lat is not int and vt_lat is not float)
        or (vt_mem is not int and vt_mem is not float)
        or type(tok_val) is not int
    ):
        raise TypeError("UNTRUSTED_TOOL_SPEC_RESOURCE_ESTIMATES")
    clean_payload: Dict[str, Any] = {
        "tool_id": view["tool_id"],
        "version": view["version"],
        "source": view["source"],
        "binary_hash": view["binary_hash"],
        "capabilities": capabilities,
        "input_schema": sanitize_exact_json_value(view.get("input_schema"), allow_bytes=False),
        "output_schema": sanitize_exact_json_value(view.get("output_schema"), allow_bytes=False),
        "semantic_contract": sanitize_exact_json_value(view.get("semantic_contract"), allow_bytes=False),
        "preconditions": preconditions,
        "postconditions": postconditions,
        "side_effects": side_effects,
        "required_permissions": required_permissions,
        "runtime_requirements": sanitize_exact_json_value(view.get("runtime_requirements"), allow_bytes=False),
        "trust_status": trust_str,
        "latency_estimate_ms": float(lat_val),
        "memory_estimate_mb": float(mem_val),
        "api_token_estimate": tok_val,
        "verification_attestation": (
            sanitize_exact_json_value(view["verification_attestation"], allow_bytes=False)
            if view.get("verification_attestation") is not None
            else None
        ),
        "provenance": sanitize_exact_json_value(view.get("provenance"), allow_bytes=False),
        "entrypoint": entrypoint,
        "command": command,
        "schema": view["schema"],
    }
    for dict_key in ("input_schema", "output_schema", "semantic_contract", "runtime_requirements", "provenance"):
        if type(clean_payload[dict_key]) is not dict:
            raise TypeError(f"UNTRUSTED_TOOL_SPEC_{dict_key.upper()}")
    if clean_payload["verification_attestation"] is not None and type(clean_payload["verification_attestation"]) is not dict:
        raise TypeError("UNTRUSTED_TOOL_SPEC_VERIFICATION_ATTESTATION")
    return redact_secrets_in_value(clean_payload)


@dataclass
class CapabilityGap:
    """Gap analysis report (`CapabilityGap/1`) distinguishing verified, discovered, and missing caps."""

    goal_id: str
    required_capabilities: List[str]
    available_capabilities: List[str] = field(default_factory=list)
    missing_capabilities: List[str] = field(default_factory=list)
    input_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    expected_outputs: List[Dict[str, Any]] = field(default_factory=list)
    acceptance_tests: List[Dict[str, Any]] = field(default_factory=list)
    security_context: Optional[SecurityContext] = None
    budget: Dict[str, Any] = field(default_factory=dict)
    discovered_unverified_capabilities: List[str] = field(default_factory=list)
    quarantined_capabilities: List[str] = field(default_factory=list)
    blocked_by_policy_capabilities: List[str] = field(default_factory=list)
    schema: str = "CapabilityGap/1"

    def __post_init__(self) -> None:
        if self.schema != "CapabilityGap/1":
            raise ValueError(f"INVALID_SCHEMA: expected CapabilityGap/1, got '{self.schema}'.")
        self.goal_id = validate_safe_text(self.goal_id, field_name="goal_id")
        self.required_capabilities = _validate_string_list(
            self.required_capabilities, field_name="required_capabilities", allow_empty=False
        )
        self.available_capabilities = _validate_string_list(
            self.available_capabilities, field_name="available_capabilities"
        )
        self.missing_capabilities = _validate_string_list(
            self.missing_capabilities, field_name="missing_capabilities"
        )
        self.discovered_unverified_capabilities = _validate_string_list(
            self.discovered_unverified_capabilities, field_name="discovered_unverified_capabilities"
        )
        self.quarantined_capabilities = _validate_string_list(
            self.quarantined_capabilities, field_name="quarantined_capabilities"
        )
        self.blocked_by_policy_capabilities = _validate_string_list(
            self.blocked_by_policy_capabilities, field_name="blocked_by_policy_capabilities"
        )
        self.input_artifacts = redact_secrets_in_value(list(self.input_artifacts or []))
        self.expected_outputs = redact_secrets_in_value(list(self.expected_outputs or []))
        self.acceptance_tests = redact_secrets_in_value(list(self.acceptance_tests or []))
        self.budget = redact_secrets_in_value(dict(self.budget or {}))

        if isinstance(self.security_context, dict):
            self.security_context = SecurityContext.from_dict(self.security_context)
        elif not isinstance(self.security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: CapabilityGap requires a SecurityContext.")

    @property
    def is_satisfied(self) -> bool:
        """Return True only if every required capability is covered by a verified policy-compliant tool."""
        return set(self.required_capabilities).issubset(set(self.available_capabilities))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "goal_id": self.goal_id,
            "required_capabilities": list(self.required_capabilities),
            "available_capabilities": list(self.available_capabilities),
            "missing_capabilities": list(self.missing_capabilities),
            "discovered_unverified_capabilities": list(self.discovered_unverified_capabilities),
            "quarantined_capabilities": list(self.quarantined_capabilities),
            "blocked_by_policy_capabilities": list(self.blocked_by_policy_capabilities),
            "input_artifacts": list(self.input_artifacts),
            "expected_outputs": list(self.expected_outputs),
            "acceptance_tests": list(self.acceptance_tests),
            "security_context": self.security_context.to_dict() if self.security_context else None,
            "budget": dict(self.budget),
        }

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"CapabilityGap:{self.goal_id}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CapabilityGap":
        if not isinstance(data, dict):
            raise ValueError("INVALID_CAPABILITY_GAP: expected dict.")
        sec = data.get("security_context")
        sec_obj = SecurityContext.from_dict(sec) if isinstance(sec, dict) else sec
        return cls(
            goal_id=data["goal_id"],
            required_capabilities=data["required_capabilities"],
            available_capabilities=data.get("available_capabilities", []),
            missing_capabilities=data.get("missing_capabilities", []),
            input_artifacts=data.get("input_artifacts", []),
            expected_outputs=data.get("expected_outputs", []),
            acceptance_tests=data.get("acceptance_tests", []),
            security_context=sec_obj,
            budget=data.get("budget", {}),
            discovered_unverified_capabilities=data.get("discovered_unverified_capabilities", []),
            quarantined_capabilities=data.get("quarantined_capabilities", []),
            blocked_by_policy_capabilities=data.get("blocked_by_policy_capabilities", []),
            schema=data.get("schema", "CapabilityGap/1"),
        )


@dataclass
class ExecutionReceipt:
    """Cryptographically bound execution record (`ExecutionReceipt/1`) with redacted excerpts."""

    run_id: str
    status: Union[ExecutionStatus, str]
    plan_hash: str
    tool_hash: str
    policy_hash: str
    environment_hash: str
    exit_status: int = 0
    verification_status: str = "NOT_VERIFIED"
    artifact_digests: Dict[str, str] = field(default_factory=dict)
    resource_metrics: Dict[str, Any] = field(default_factory=dict)
    trace_digest: str = ""
    llm_calls: int = 0
    stderr_excerpt: str = ""
    stdout_excerpt: str = ""
    schema: str = "ExecutionReceipt/1"

    def __post_init__(self) -> None:
        if self.schema != "ExecutionReceipt/1":
            raise ValueError(f"INVALID_SCHEMA: expected ExecutionReceipt/1, got '{self.schema}'.")
        self.run_id = validate_safe_text(self.run_id, field_name="run_id")
        if "/" in self.run_id or "\\" in self.run_id or ".." in self.run_id or not VALID_RUN_ID_RE.fullmatch(self.run_id):
            raise ValueError(f"INVALID_RUN_ID: '{self.run_id}' violates safe identifier format.")

        if isinstance(self.status, str):
            self.status = ExecutionStatus(self.status.strip().upper())
        elif not isinstance(self.status, ExecutionStatus):
            raise ValueError(f"INVALID_EXECUTION_STATUS: {self.status!r}")

        self.plan_hash = normalize_sha256(self.plan_hash, field_name="plan_hash")
        self.tool_hash = normalize_sha256(self.tool_hash, field_name="tool_hash")
        self.policy_hash = normalize_sha256(self.policy_hash, field_name="policy_hash")
        self.environment_hash = normalize_sha256(self.environment_hash, field_name="environment_hash")
        self.exit_status = int(self.exit_status)
        self.verification_status = validate_safe_text(self.verification_status, field_name="verification_status")
        self.llm_calls = int(self.llm_calls)
        if self.llm_calls < 0:
            raise ValueError("INVALID_LLM_CALLS: llm_calls must be >= 0.")

        if self.status == ExecutionStatus.PASS:
            if self.exit_status != 0:
                raise ValueError("INVALID_PASS_RECEIPT: PASS status requires exit_status == 0.")
            if self.verification_status.upper() in {"FAIL", "FAILED", "NOT_VERIFIED", "INSUFFICIENT_EVIDENCE"}:
                raise ValueError(
                    f"INVALID_PASS_RECEIPT: PASS cannot have verification_status '{self.verification_status}'."
                )

        normalized_artifacts: Dict[str, str] = {}
        for name, digest in dict(self.artifact_digests or {}).items():
            safe_name = validate_safe_text(str(name), field_name="artifact_name")
            normalized_artifacts[safe_name] = normalize_sha256(digest, field_name="artifact_digest")
        self.artifact_digests = normalized_artifacts

        self.resource_metrics = redact_secrets_in_value(dict(self.resource_metrics or {}))
        _validate_no_trojan_in_structure(self.resource_metrics, field_name="resource_metrics")

        self.stderr_excerpt = self._clean_excerpt(self.stderr_excerpt)
        self.stdout_excerpt = self._clean_excerpt(self.stdout_excerpt)

        if self.trace_digest:
            self.trace_digest = normalize_sha256(self.trace_digest, field_name="trace_digest")
        else:
            self.trace_digest = sha256_digest(
                {
                    "run_id": self.run_id,
                    "status": self.status.value,
                    "plan_hash": self.plan_hash,
                    "tool_hash": self.tool_hash,
                    "policy_hash": self.policy_hash,
                    "environment_hash": self.environment_hash,
                    "exit_status": self.exit_status,
                }
            )

    @staticmethod
    def _clean_excerpt(raw: Any, max_len: int = 4096) -> str:
        text = str(raw or "")
        text = TROJAN_UNICODE_RE.sub("", text).replace("\x00", "")
        text = redact_secrets_in_text(text)
        return text[:max_len]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"ExecutionReceipt:{self.run_id}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionReceipt":
        if not isinstance(data, dict):
            raise ValueError("INVALID_EXECUTION_RECEIPT: expected dict.")
        return cls(
            run_id=data["run_id"],
            status=data["status"],
            plan_hash=data["plan_hash"],
            tool_hash=data["tool_hash"],
            policy_hash=data["policy_hash"],
            environment_hash=data["environment_hash"],
            exit_status=data.get("exit_status", 0),
            verification_status=data.get("verification_status", "NOT_VERIFIED"),
            artifact_digests=data.get("artifact_digests", {}),
            resource_metrics=data.get("resource_metrics", {}),
            trace_digest=data.get("trace_digest", ""),
            llm_calls=data.get("llm_calls", 0),
            stderr_excerpt=data.get("stderr_excerpt", ""),
            stdout_excerpt=data.get("stdout_excerpt", ""),
            schema=data.get("schema", "ExecutionReceipt/1"),
        )


_EXACT_EXECUTION_RECEIPT_FIELDS: Tuple[str, ...] = (
    "run_id",
    "status",
    "plan_hash",
    "tool_hash",
    "policy_hash",
    "environment_hash",
    "exit_status",
    "verification_status",
    "artifact_digests",
    "resource_metrics",
    "trace_digest",
    "llm_calls",
    "stderr_excerpt",
    "stdout_excerpt",
    "schema",
)
_ORIG_EXECUTION_RECEIPT_DICT_DESCR = _SCHEMA_TYPE_DICT_DESCR.__get__(ExecutionReceipt, type).get("__dict__")
_ORIG_EXECUTION_RECEIPT_LIFECYCLE = snapshot_class_lifecycle(ExecutionReceipt)


def assert_execution_receipt_type_unmodified() -> None:
    """Verify `ExecutionReceipt` has not had lifecycle hooks or descriptors tampered with."""
    assert_dataclass_type_unmodified(
        ExecutionReceipt,
        _EXACT_EXECUTION_RECEIPT_FIELDS,
        _ORIG_EXECUTION_RECEIPT_DICT_DESCR,
        expected_mro=(ExecutionReceipt, object),
        orig_lifecycle_methods=_ORIG_EXECUTION_RECEIPT_LIFECYCLE,
    )


@dataclass
class Experience:
    """Verified cross-task tool/plan experience record (`Experience/1`)."""

    task_fingerprint: str
    failure_class: str
    tool_or_plan_id: str
    input_characteristics: Dict[str, Any] = field(default_factory=dict)
    verified_outcome: Union[bool, str] = False
    cost: Union[Dict[str, Any], float, int] = field(default_factory=dict)
    failure_reasons: List[str] = field(default_factory=list)
    reuse_count: int = 0
    cross_task_transfer_evidence: List[Dict[str, Any]] = field(default_factory=list)
    trace_hash: str = ""
    tool_hash: str = ""
    security_profile: Union[SecurityProfile, str] = SecurityProfile.LOCAL_RESEARCH
    schema: str = "Experience/1"

    def __post_init__(self) -> None:
        if self.schema != "Experience/1":
            raise ValueError(f"INVALID_SCHEMA: expected Experience/1, got '{self.schema}'.")
        self.task_fingerprint = validate_safe_text(self.task_fingerprint, field_name="task_fingerprint")
        self.failure_class = validate_safe_text(self.failure_class, field_name="failure_class")
        self.tool_or_plan_id = validate_safe_text(self.tool_or_plan_id, field_name="tool_or_plan_id")

        self.input_characteristics = redact_secrets_in_value(dict(self.input_characteristics or {}))
        _validate_no_trojan_in_structure(self.input_characteristics, field_name="input_characteristics")

        if isinstance(self.cost, dict):
            self.cost = redact_secrets_in_value(dict(self.cost))
        else:
            self.cost = float(self.cost)
            if self.cost < 0:
                raise ValueError("INVALID_COST: numeric cost must be >= 0.")

        self.failure_reasons = [
            redact_secrets_in_text(validate_safe_text(str(reason), field_name="failure_reasons"))
            for reason in (self.failure_reasons or [])
        ]
        self.reuse_count = int(self.reuse_count)
        if self.reuse_count < 0:
            raise ValueError("INVALID_REUSE_COUNT: reuse_count must be >= 0.")

        normalized_evidence: List[Dict[str, Any]] = []
        for item in self.cross_task_transfer_evidence or []:
            if isinstance(item, dict):
                cleaned = redact_secrets_in_value(dict(item))
            else:
                cleaned = {"evidence": redact_secrets_in_text(validate_safe_text(str(item), field_name="evidence"))}
            _validate_no_trojan_in_structure(cleaned, field_name="cross_task_transfer_evidence")
            normalized_evidence.append(cleaned)
        self.cross_task_transfer_evidence = normalized_evidence

        if self.trace_hash:
            self.trace_hash = normalize_sha256(self.trace_hash, field_name="trace_hash")
        if self.tool_hash:
            self.tool_hash = normalize_sha256(self.tool_hash, field_name="tool_hash")

        if isinstance(self.security_profile, str):
            self.security_profile = SecurityProfile(self.security_profile.strip().upper())
        elif not isinstance(self.security_profile, SecurityProfile):
            raise ValueError(f"INVALID_SECURITY_PROFILE: {self.security_profile!r}")

    @property
    def is_positive_verified(self) -> bool:
        """Return True if this experience records a verified passing outcome."""
        if isinstance(self.verified_outcome, bool):
            return self.verified_outcome
        return str(self.verified_outcome).strip().upper() in {"PASS", "VERIFIED", "SUCCESS", "TRUE"}

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["security_profile"] = self.security_profile.value
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"Experience:{self.task_fingerprint}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Experience":
        if not isinstance(data, dict):
            raise ValueError("INVALID_EXPERIENCE: expected dict.")
        return cls(
            task_fingerprint=data["task_fingerprint"],
            failure_class=data["failure_class"],
            tool_or_plan_id=data["tool_or_plan_id"],
            input_characteristics=data.get("input_characteristics", {}),
            verified_outcome=data.get("verified_outcome", False),
            cost=data.get("cost", {}),
            failure_reasons=data.get("failure_reasons", []),
            reuse_count=data.get("reuse_count", 0),
            cross_task_transfer_evidence=data.get("cross_task_transfer_evidence", []),
            trace_hash=data.get("trace_hash", ""),
            tool_hash=data.get("tool_hash", ""),
            security_profile=data.get("security_profile", SecurityProfile.LOCAL_RESEARCH),
            schema=data.get("schema", "Experience/1"),
        )
