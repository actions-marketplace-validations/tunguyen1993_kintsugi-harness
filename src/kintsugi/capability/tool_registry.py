"""Zero-trust local tool registry, static discovery, attestation, and quarantine."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import (
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    compute_tool_spec_security_digest,
    has_suspicious_metadata,
    has_valid_verification_attestation,
    normalize_sha256,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.shield import (
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    atomic_write_json,
    resolve_safe_child_path,
)

MAX_DISCOVERY_BINARY_BYTES = 64 * 1024 * 1024
MAX_DISCOVERY_JSON_BYTES = 1 * 1024 * 1024
_READ_CHUNK_BYTES = 65536
_SHELL_METACHAR_RE = re.compile(r"[;&|`$<>]")
_TRUST_SORT_RANK = {
    TrustStatus.VERIFIED: 0,
    TrustStatus.DISCOVERED: 1,
    TrustStatus.QUARANTINED: 2,
    TrustStatus.RETIRED: 3,
}


def _safe_read_regular_no_follow(file_path: Path, *, max_bytes: int) -> Tuple[bytes, str]:
    """Read up to `max_bytes` from a regular non-symlink file using `O_NOFOLLOW` and return `(prefix, sha256:...)`."""
    assert_not_symlink(file_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(file_path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_NON_REGULAR_FILE: '{file_path}' is not a regular file.")
        if st.st_size > max_bytes:
            raise ValueError(f"DISCOVERY_FILE_TOO_LARGE: '{file_path}' exceeds {max_bytes} bytes.")
        hasher = hashlib.sha256()
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"DISCOVERY_FILE_TOO_LARGE: '{file_path}' exceeded {max_bytes} bytes during read.")
            hasher.update(chunk)
            if total <= MAX_DISCOVERY_JSON_BYTES:
                chunks.append(chunk)
        return b"".join(chunks), f"sha256:{hasher.hexdigest()}"
    finally:
        os.close(fd)


def _sanitize_discovered_tool_id(raw_name: str, prefix: str = "") -> str:
    stem = re.sub(r"[^A-Za-z0-9._:-]+", "-", raw_name).strip(".-_:")
    if not stem:
        stem = f"tool-{hashlib.sha256(raw_name.encode('utf-8')).hexdigest()[:8]}"
    combined = f"{prefix}{stem}" if prefix else stem
    if not combined[0].isalnum():
        combined = f"t-{combined}"
    return validate_tool_id(combined[:128])


def _is_manifest_file(path: Path) -> bool:
    name = path.name.lower()
    return name == "tool.json" or name.endswith(".tool.json") or name.endswith(".manifest.json")


def _is_candidate_executable_or_script(path: Path, st_mode: int) -> bool:
    name = path.name
    if name.startswith(".") or name == "__init__.py" or name.endswith((".pyc", ".pyo", ".json", ".md", ".txt")):
        return False
    if path.suffix.lower() in {".py", ".sh"}:
        return True
    return bool(st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _is_within(candidate: Path, base: Path) -> bool:
    """Return True if `candidate` falls inside `base` lexically or after resolution."""
    abs_cand = Path(os.path.abspath(str(candidate)))
    abs_base = Path(os.path.abspath(str(base)))
    try:
        abs_cand.relative_to(abs_base)
        return True
    except ValueError as lexical_err:
        _ = lexical_err
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


_MIN_VERIFIER_KEY_BYTES = 16
_HMAC_SIG_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_RESERVED_UNTRUSTED_VERIFIERS = frozenset({"self", "auto", "discovery", "none", "unverified", "self-verifier"})


class AttestationAuthority:
    """Independent cryptographic HMAC-SHA256 attestation authority (`KH-B2-SEC-001`).

    Verifier signing keys exist ONLY in memory or in an explicit owner-controlled
    `0o600` regular file strictly outside `workspace_root` (read via `O_NOFOLLOW`),
    and are never persisted inside workspace `.kintsugi/tool_registry.json`.
    """

    def __init__(
        self,
        verifier_keys: Optional[Mapping[str, Union[str, bytes]]] = None,
        *,
        key_file: Optional[Union[str, Path]] = None,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> None:
        self._keys: Dict[str, bytes] = {}
        if verifier_keys is not None:
            if not isinstance(verifier_keys, Mapping):
                raise ValueError("INVALID_VERIFIER_KEYS: expected mapping of verifier_id -> secret_key.")
            for vid, secret in verifier_keys.items():
                self.register_verifier(vid, secret)
        if key_file is not None:
            self.load_key_file(key_file, workspace_root=workspace_root)

    def __repr__(self) -> str:
        return f"AttestationAuthority(verifiers={sorted(self._keys.keys())!r})"

    @classmethod
    def from_key_file(
        cls,
        key_file: Union[str, Path],
        *,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> "AttestationAuthority":
        """Load an `AttestationAuthority` from an owner-controlled external `0o600` key file."""
        return cls(key_file=key_file, workspace_root=workspace_root)

    def register_verifier(self, verifier_id: str, secret_key: Union[str, bytes]) -> None:
        """Register an authorized verifier's HMAC-SHA256 secret key in memory."""
        cleaned_verifier = validate_safe_text(verifier_id, field_name="verifier_id")
        if cleaned_verifier.lower() in _RESERVED_UNTRUSTED_VERIFIERS:
            raise ValueError(f"REJECTED_RESERVED_VERIFIER_ID: '{cleaned_verifier}' cannot be a trusted verifier.")
        if isinstance(secret_key, bytes):
            raw_key = secret_key
        elif isinstance(secret_key, str):
            if "\x00" in secret_key or TROJAN_UNICODE_RE.search(secret_key):
                raise ValueError("INVALID_VERIFIER_SECRET: NUL or control characters forbidden.")
            if not secret_key.strip():
                raise ValueError("WEAK_VERIFIER_SECRET: secret_key must be non-empty.")
            raw_key = secret_key.encode("utf-8")
        else:
            raise ValueError("INVALID_VERIFIER_SECRET: expected str or bytes.")
        if len(raw_key) < _MIN_VERIFIER_KEY_BYTES:
            raise ValueError(
                f"WEAK_VERIFIER_SECRET: verifier key for '{cleaned_verifier}' must be >= {_MIN_VERIFIER_KEY_BYTES} bytes."
            )
        self._keys[cleaned_verifier] = raw_key

    def has_verifier(self, verifier_id: str) -> bool:
        """Return True if `verifier_id` has an active signing key registered."""
        if not isinstance(verifier_id, str):
            return False
        cleaned = verifier_id.strip()
        return bool(cleaned and cleaned in self._keys)

    @property
    def has_registered_verifiers(self) -> bool:
        """Return True if at least one trusted verifier key is registered."""
        return bool(self._keys)

    def load_key_file(
        self,
        key_file: Union[str, Path],
        *,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> None:
        """Load `{verifier_id: secret}` keys from an external `0o600` regular file via `O_NOFOLLOW`."""
        raw_str = validate_safe_text(str(key_file), field_name="key_file")
        key_path = Path(raw_str)
        assert_not_symlink(key_path.parent)
        assert_not_symlink(key_path)
        if key_path.name == "tool_registry.json":
            raise PermissionError(
                "ATTESTATION_KEY_FILE_FORBIDDEN_REGISTRY_PATH: verifier signing keys must never live in tool_registry.json."
            )
        if workspace_root is not None:
            ws_path = Path(validate_safe_text(str(workspace_root), field_name="workspace_root"))
            assert_not_symlink(ws_path)
            if _is_within(key_path, ws_path):
                raise PermissionError(
                    f"ATTESTATION_KEY_FILE_INSIDE_WORKSPACE: '{key_path}' must be outside workspace '{ws_path}'."
                )

        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(key_path), flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"SECURITY_NON_REGULAR_FILE: '{key_path}' is not a regular file.")
            if stat.S_IMODE(st.st_mode) not in (0o400, 0o600):
                raise PermissionError(
                    f"ATTESTATION_KEY_FILE_INSECURE_PERMISSIONS: '{key_path}' mode {oct(stat.S_IMODE(st.st_mode))} must be 0o600."
                )
            if st.st_size > MAX_DISCOVERY_JSON_BYTES:
                raise ValueError(f"ATTESTATION_KEY_FILE_TOO_LARGE: '{key_path}' exceeds {MAX_DISCOVERY_JSON_BYTES} bytes.")
            chunks: List[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, _READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DISCOVERY_JSON_BYTES:
                    raise ValueError(f"ATTESTATION_KEY_FILE_TOO_LARGE: '{key_path}' exceeded {MAX_DISCOVERY_JSON_BYTES} bytes.")
                chunks.append(chunk)
        finally:
            os.close(fd)

        payload = json.loads(b"".join(chunks).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("INVALID_ATTESTATION_KEY_FILE: expected JSON object.")
        entries = payload.get("verifiers") if isinstance(payload.get("verifiers"), dict) else payload
        for vid, secret in entries.items():
            if vid == "schema":
                continue
            self.register_verifier(str(vid), secret)

    @staticmethod
    def _canonical_attestation_bytes(
        tool_id: str,
        binary_hash: str,
        verification_digest: str,
        verifier_id: str,
        spec_digest: str,
    ) -> bytes:
        canonical_payload = {
            "domain": "KintsugiToolAttestation/2",
            "tool_id": tool_id,
            "binary_hash": binary_hash,
            "verification_digest": verification_digest,
            "verifier_id": verifier_id,
            "spec_digest": spec_digest,
        }
        return canonical_json_dumps(canonical_payload).encode("utf-8")

    def issue_attestation(
        self,
        tool_id: str,
        binary_hash: str,
        verification_digest: str,
        verifier_id: str,
        *,
        spec_digest: str,
    ) -> Dict[str, Any]:
        """Sign the complete immutable ToolSpec security contract, not only the binary."""
        if (
            type(tool_id) is not str
            or type(binary_hash) is not str
            or type(verification_digest) is not str
            or type(verifier_id) is not str
            or type(spec_digest) is not str
        ):
            raise ValueError("INVALID_ATTESTATION_ARGUMENT_TYPE: exact strings required.")
        cleaned_tool_id = validate_tool_id(tool_id)
        norm_bin_hash = normalize_sha256(binary_hash, field_name="binary_hash")
        norm_ver_digest = normalize_sha256(verification_digest, field_name="verification_digest")
        norm_spec_digest = normalize_sha256(spec_digest, field_name="spec_digest")
        cleaned_verifier = validate_safe_text(verifier_id, field_name="verifier_id")
        secret = self._keys.get(cleaned_verifier)
        if secret is None:
            raise PermissionError(
                f"UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: verifier '{cleaned_verifier}' is not registered."
            )
        canonical_bytes = self._canonical_attestation_bytes(
            cleaned_tool_id, norm_bin_hash, norm_ver_digest, cleaned_verifier, norm_spec_digest
        )
        sig_hex = hmac.new(secret, canonical_bytes, hashlib.sha256).hexdigest()
        attestation: Dict[str, Any] = {
            "verifier_id": cleaned_verifier,
            "verification_digest": norm_ver_digest,
            "binary_hash": norm_bin_hash,
            "tool_id": cleaned_tool_id,
            "spec_digest": norm_spec_digest,
            "signature": f"hmac-sha256:{sig_hex}",
            "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if not has_valid_verification_attestation(attestation, norm_bin_hash, cleaned_tool_id):
            raise ValueError("INVALID_ATTESTATION_BINDING: attestation failed structural binding validation.")
        return attestation

    def verify_attestation(
        self,
        attestation: Mapping[str, Any],
        *,
        expected_tool_id: str,
        expected_binary_hash: str,
        expected_spec_digest: str,
    ) -> bool:
        """Cryptographically verify `attestation` using constant-time HMAC comparison; fail closed on any error."""
        if (
            type(attestation) is not dict
            or type(expected_tool_id) is not str
            or type(expected_binary_hash) is not str
            or type(expected_spec_digest) is not str
        ):
            return False
        from kintsugi.capability.schemas import sanitize_exact_json_value

        try:
            att_dict = sanitize_exact_json_value(attestation, allow_bytes=False)
        except (TypeError, ValueError):
            return False
        if type(att_dict) is not dict:
            return False
        try:
            cleaned_tool_id = validate_tool_id(expected_tool_id)
            norm_bin_hash = normalize_sha256(expected_binary_hash, field_name="binary_hash")
            norm_spec_digest = normalize_sha256(expected_spec_digest, field_name="spec_digest")
        except ValueError:
            return False

        if not has_valid_verification_attestation(att_dict, norm_bin_hash, cleaned_tool_id):
            return False
        raw_spec_digest_val = att_dict.get("spec_digest")
        if type(raw_spec_digest_val) is not str:
            return False
        raw_spec_digest = raw_spec_digest_val.strip().lower()
        if not hmac.compare_digest(raw_spec_digest, norm_spec_digest):
            return False

        raw_verifier_val = att_dict.get("verifier_id")
        if type(raw_verifier_val) is not str:
            return False
        cleaned_verifier = raw_verifier_val.strip()
        secret = self._keys.get(cleaned_verifier)
        if secret is None:
            return False

        raw_sig = att_dict.get("signature")
        if type(raw_sig) is not str:
            return False
        cleaned_sig = raw_sig.strip().lower()
        if not _HMAC_SIG_RE.fullmatch(cleaned_sig):
            return False

        try:
            norm_ver_digest = normalize_sha256(att_dict.get("verification_digest"), field_name="verification_digest")
        except ValueError:
            return False

        canonical_bytes = self._canonical_attestation_bytes(
            cleaned_tool_id, norm_bin_hash, norm_ver_digest, cleaned_verifier, norm_spec_digest
        )
        expected_sig = "hmac-sha256:" + hmac.new(secret, canonical_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(cleaned_sig, expected_sig)

    @staticmethod
    def _canonical_adapter_attestation_bytes(
        adapter_id: str,
        adapter_hash: str,
        verification_corpus_hash: str,
        verification_digest: str,
        verifier_id: str,
        callable_hash: str = "",
    ) -> bytes:
        canonical_payload = {
            "domain": "KintsugiAdapterAttestation/1",
            "adapter_id": adapter_id,
            "adapter_hash": adapter_hash,
            "verification_corpus_hash": verification_corpus_hash,
            "verification_digest": verification_digest,
            "verifier_id": verifier_id,
            "callable_hash": callable_hash,
        }
        return canonical_json_dumps(canonical_payload).encode("utf-8")

    def issue_adapter_attestation(
        self,
        adapter_id: str,
        adapter_hash: str,
        verification_corpus_hash: str,
        verification_digest: str,
        verifier_id: str,
        *,
        callable_hash: str = "",
    ) -> Dict[str, Any]:
        """Sign an `AdapterSpec/1` attestation with optional bound host callable SHA-256."""
        if (
            type(adapter_id) is not str
            or type(adapter_hash) is not str
            or type(verification_corpus_hash) is not str
            or type(verification_digest) is not str
            or type(verifier_id) is not str
            or type(callable_hash) is not str
        ):
            raise ValueError("INVALID_ADAPTER_ATTESTATION_ARGUMENT_TYPE: exact strings required.")
        cleaned_adapter_id = validate_tool_id(adapter_id)
        norm_adapter_hash = normalize_sha256(adapter_hash, field_name="adapter_hash")
        norm_corpus_hash = normalize_sha256(verification_corpus_hash, field_name="verification_corpus_hash")
        norm_ver_digest = normalize_sha256(verification_digest, field_name="verification_digest")
        cleaned_verifier = validate_safe_text(verifier_id, field_name="verifier_id")
        norm_callable_hash = (
            normalize_sha256(callable_hash, field_name="callable_hash") if callable_hash else ""
        )
        secret = self._keys.get(cleaned_verifier)
        if secret is None:
            raise PermissionError(
                f"UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: verifier '{cleaned_verifier}' is not registered."
            )
        canonical_bytes = self._canonical_adapter_attestation_bytes(
            cleaned_adapter_id,
            norm_adapter_hash,
            norm_corpus_hash,
            norm_ver_digest,
            cleaned_verifier,
            norm_callable_hash,
        )
        sig_hex = hmac.new(secret, canonical_bytes, hashlib.sha256).hexdigest()
        attestation: Dict[str, Any] = {
            "verifier_id": cleaned_verifier,
            "verification_digest": norm_ver_digest,
            "adapter_id": cleaned_adapter_id,
            "adapter_hash": norm_adapter_hash,
            "verification_corpus_hash": norm_corpus_hash,
            "callable_hash": norm_callable_hash,
            "signature": f"hmac-sha256:{sig_hex}",
            "verified_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        structural_view = dict(attestation)
        structural_view["binary_hash"] = norm_adapter_hash
        structural_view["tool_id"] = cleaned_adapter_id
        if not has_valid_verification_attestation(structural_view, norm_adapter_hash, cleaned_adapter_id):
            raise ValueError("INVALID_ADAPTER_ATTESTATION_BINDING: attestation failed structural validation.")
        return attestation

    def verify_adapter_attestation(
        self,
        attestation: Mapping[str, Any],
        *,
        expected_adapter_id: str,
        expected_adapter_hash: str,
        expected_corpus_hash: str,
        expected_callable_hash: Optional[str] = None,
    ) -> bool:
        """Cryptographically verify an `AdapterSpec/1` HMAC-SHA256 attestation; fail closed."""
        if (
            type(attestation) is not dict
            or type(expected_adapter_id) is not str
            or type(expected_adapter_hash) is not str
            or type(expected_corpus_hash) is not str
            or (expected_callable_hash is not None and type(expected_callable_hash) is not str)
        ):
            return False
        from kintsugi.capability.schemas import sanitize_exact_json_value

        try:
            att_dict = sanitize_exact_json_value(attestation, allow_bytes=False)
        except (TypeError, ValueError):
            return False
        if type(att_dict) is not dict:
            return False
        try:
            cleaned_adapter_id = validate_tool_id(expected_adapter_id)
            norm_adapter_hash = normalize_sha256(expected_adapter_hash, field_name="adapter_hash")
            norm_corpus_hash = normalize_sha256(expected_corpus_hash, field_name="verification_corpus_hash")
            norm_ver_digest = normalize_sha256(
                att_dict.get("verification_digest"), field_name="verification_digest"
            )
            att_corpus = normalize_sha256(
                att_dict.get("verification_corpus_hash"), field_name="verification_corpus_hash"
            )
            att_adapter_hash = normalize_sha256(
                att_dict.get("adapter_hash"), field_name="adapter_hash"
            )
            raw_callable = att_dict.get("callable_hash", "")
            if raw_callable is None:
                att_callable_hash = ""
            elif type(raw_callable) is not str:
                return False
            else:
                stripped_callable = raw_callable.strip().lower()
                att_callable_hash = (
                    normalize_sha256(stripped_callable, field_name="callable_hash")
                    if stripped_callable
                    else ""
                )
        except ValueError:
            return False

        structural_view = dict(att_dict)
        structural_view.setdefault("binary_hash", att_adapter_hash)
        structural_view.setdefault("tool_id", att_dict.get("adapter_id"))
        if not has_valid_verification_attestation(structural_view, norm_adapter_hash, cleaned_adapter_id):
            return False

        att_adapter_id_val = att_dict.get("adapter_id")
        if type(att_adapter_id_val) is not str or att_adapter_id_val.strip() != cleaned_adapter_id:
            return False
        if not hmac.compare_digest(att_adapter_hash, norm_adapter_hash):
            return False
        if not hmac.compare_digest(att_corpus, norm_corpus_hash):
            return False

        if expected_callable_hash is not None:
            try:
                norm_exp_callable = normalize_sha256(expected_callable_hash, field_name="callable_hash")
            except ValueError:
                return False
            if not att_callable_hash or not hmac.compare_digest(att_callable_hash, norm_exp_callable):
                return False

        att_verifier_val = att_dict.get("verifier_id")
        if type(att_verifier_val) is not str:
            return False
        cleaned_verifier = att_verifier_val.strip()
        secret = self._keys.get(cleaned_verifier)
        if secret is None:
            return False

        raw_sig = att_dict.get("signature")
        if type(raw_sig) is not str:
            return False
        cleaned_sig = raw_sig.strip().lower()
        if not _HMAC_SIG_RE.fullmatch(cleaned_sig):
            return False

        canonical_bytes = self._canonical_adapter_attestation_bytes(
            cleaned_adapter_id,
            norm_adapter_hash,
            norm_corpus_hash,
            norm_ver_digest,
            cleaned_verifier,
            att_callable_hash,
        )
        expected_sig = "hmac-sha256:" + hmac.new(secret, canonical_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(cleaned_sig, expected_sig)


class ToolRegistry:
    """Deterministic, zero-trust registry for discovered, quarantined, and verified tools."""

    SCHEMA_VERSION = "ToolRegistry/1"

    def __init__(
        self,
        storage_path: Optional[Union[str, Path]] = None,
        *,
        auto_load: bool = True,
        authority: Optional[AttestationAuthority] = None,
    ) -> None:
        self.storage_path: Optional[Path] = Path(storage_path) if storage_path is not None else None
        if authority is None:
            self.authority: AttestationAuthority = AttestationAuthority()
        elif isinstance(authority, AttestationAuthority):
            self.authority = authority
        else:
            raise ValueError("INVALID_ATTESTATION_AUTHORITY: expected AttestationAuthority instance.")
        self._tools: Dict[str, ToolSpec] = {}
        self.discovery_rejections: List[Dict[str, str]] = []
        if auto_load and self.storage_path is not None and self.storage_path.exists():
            self.load(self.storage_path)

    def register_trusted_verifier(self, verifier_id: str, secret_key: Union[str, bytes]) -> None:
        """Register an authorized verifier HMAC secret key in memory on this registry's authority."""
        self.authority.register_verifier(verifier_id, secret_key)

    def get(self, tool_id: str) -> Optional[ToolSpec]:
        """Return registered `ToolSpec` by `tool_id`, or `None` if not found."""
        cleaned = validate_tool_id(tool_id)
        return self._tools.get(cleaned)

    def list_tools(
        self,
        *,
        trust_statuses: Optional[Sequence[TrustStatus]] = None,
    ) -> List[ToolSpec]:
        """Return deterministically sorted tools, optionally filtered by `TrustStatus`."""
        allowed = set(trust_statuses) if trust_statuses is not None else None
        tools = [
            spec for spec in self._tools.values()
            if allowed is None or spec.trust_status in allowed
        ]
        return sorted(tools, key=lambda s: (_TRUST_SORT_RANK.get(s.trust_status, 99), s.tool_id))

    def search_capability(
        self,
        capability: str,
        *,
        include_unverified: bool = True,
        trust_statuses: Optional[Sequence[TrustStatus]] = None,
    ) -> List[ToolSpec]:
        """Search registered tools providing `capability`, sorted deterministically by trust then ID."""
        cleaned_cap = validate_safe_text(capability, field_name="capability")
        allowed: Optional[set] = set(trust_statuses) if trust_statuses is not None else None
        if not include_unverified:
            allowed = {TrustStatus.VERIFIED} if allowed is None else (allowed & {TrustStatus.VERIFIED})
        matched = [
            spec
            for spec in self._tools.values()
            if cleaned_cap in spec.capabilities and (allowed is None or spec.trust_status in allowed)
        ]
        return sorted(matched, key=lambda s: (_TRUST_SORT_RANK.get(s.trust_status, 99), s.tool_id))

    def register(self, spec: ToolSpec, trusted_attestor: bool = False) -> str:
        """
        Register a `ToolSpec`.

        Unless `trusted_attestor=True` with valid attestation, `VERIFIED` claims are downgraded
        to `QUARANTINED`, and existing `VERIFIED` tools cannot be overwritten or downgraded.
        """
        if not isinstance(spec, ToolSpec):
            raise ValueError("INVALID_TOOL_SPEC: expected ToolSpec instance.")

        stored_spec = spec
        if spec.trust_status == TrustStatus.VERIFIED:
            if not trusted_attestor:
                provenance = dict(spec.provenance)
                provenance["quarantine_reason"] = "UNTRUSTED_ATTESTOR_VERIFIED_CLAIM"
                stored_spec = ToolSpec(
                    tool_id=spec.tool_id,
                    version=spec.version,
                    source=spec.source,
                    binary_hash=spec.binary_hash,
                    capabilities=list(spec.capabilities),
                    input_schema=dict(spec.input_schema),
                    output_schema=dict(spec.output_schema),
                    semantic_contract=dict(spec.semantic_contract),
                    preconditions=list(spec.preconditions),
                    postconditions=list(spec.postconditions),
                    side_effects=list(spec.side_effects),
                    required_permissions=list(spec.required_permissions),
                    runtime_requirements=dict(spec.runtime_requirements),
                    trust_status=TrustStatus.QUARANTINED,
                    latency_estimate_ms=spec.latency_estimate_ms,
                    memory_estimate_mb=spec.memory_estimate_mb,
                    api_token_estimate=spec.api_token_estimate,
                    verification_attestation=None,
                    provenance=provenance,
                    entrypoint=spec.entrypoint,
                    command=list(spec.command) if spec.command is not None else None,
                )
            else:
                att = dict(spec.verification_attestation or {})
                att_verifier = str(att.get("verifier_id", "")).strip()
                if not self.authority.has_registered_verifiers or not self.authority.verify_attestation(
                    att,
                    expected_tool_id=spec.tool_id,
                    expected_binary_hash=spec.binary_hash,
                    expected_spec_digest=compute_tool_spec_security_digest(spec),
                ):
                    raise PermissionError(
                        f"UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: signed ToolSpec required for '{spec.tool_id}'."
                    )

        existing = self._tools.get(stored_spec.tool_id)
        if existing is not None and existing.trust_status == TrustStatus.VERIFIED and not trusted_attestor:
            if existing.binary_hash != stored_spec.binary_hash:
                raise PermissionError(
                    f"REFUSED_OVERWRITE_VERIFIED_TOOL: '{stored_spec.tool_id}' already verified with different hash."
                )
            if stored_spec.trust_status != TrustStatus.VERIFIED:
                raise PermissionError(
                    f"REFUSED_DOWNGRADE_VERIFIED_TOOL: use quarantine() to revoke '{stored_spec.tool_id}'."
                )

        canonical_copy = ToolSpec.from_dict(stored_spec.to_dict(), from_discovery=False)
        canonical_copy.to_canonical_json()
        self._tools[canonical_copy.tool_id] = canonical_copy
        return canonical_copy.tool_id

    def verify_tool(
        self,
        tool_id: str,
        verification_digest: str,
        verifier_id: str,
        *,
        expected_binary_hash: Optional[str] = None,
        attestation_signature: Optional[str] = None,
        attestation: Optional[Mapping[str, Any]] = None,
    ) -> ToolSpec:
        """Promote a `DISCOVERED` tool to `VERIFIED` after cryptographic `AttestationAuthority` verification."""
        cleaned_id = validate_tool_id(tool_id)
        existing = self._tools.get(cleaned_id)
        if existing is None:
            raise KeyError(f"TOOL_NOT_FOUND: '{cleaned_id}' is not registered.")
        if existing.trust_status in {TrustStatus.QUARANTINED, TrustStatus.RETIRED}:
            raise ValueError(
                f"CANNOT_VERIFY_{existing.trust_status.value}_TOOL: '{cleaned_id}' must be remediated before verification."
            )
        if expected_binary_hash is not None and expected_binary_hash.strip().lower() != existing.binary_hash.lower():
            self.quarantine(cleaned_id, "BINARY_HASH_MISMATCH_ON_VERIFY")
            raise ValueError(f"BINARY_HASH_MISMATCH: expected {expected_binary_hash}, found {existing.binary_hash}.")

        cleaned_verifier = validate_safe_text(verifier_id, field_name="verifier_id")
        if not self.authority.has_verifier(cleaned_verifier):
            raise PermissionError(
                f"UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: '{cleaned_verifier}' is not a registered trusted verifier."
            )

        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if attestation is not None:
            if not isinstance(attestation, Mapping):
                raise PermissionError("UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: invalid attestation payload.")
            candidate_attestation = dict(attestation)
            if (
                "verifier_id" in candidate_attestation
                and str(candidate_attestation["verifier_id"]).strip() != cleaned_verifier
            ):
                raise PermissionError(
                    "UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: attestation verifier_id mismatch."
                )
            if (
                "verification_digest" in candidate_attestation
                and str(candidate_attestation["verification_digest"]).strip().lower()
                != str(verification_digest).strip().lower()
            ):
                raise PermissionError(
                    "UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: attestation verification_digest mismatch."
                )
            candidate_attestation.setdefault("verifier_id", cleaned_verifier)
            candidate_attestation.setdefault("verification_digest", verification_digest)
            candidate_attestation.setdefault("binary_hash", existing.binary_hash)
            candidate_attestation.setdefault("tool_id", existing.tool_id)
            candidate_attestation.setdefault("spec_digest", compute_tool_spec_security_digest(existing))
            candidate_attestation.setdefault("verified_at", now_iso)
            if attestation_signature is not None:
                existing_sig = candidate_attestation.get("signature")
                if (
                    existing_sig is not None
                    and str(existing_sig).strip().lower() != attestation_signature.strip().lower()
                ):
                    raise PermissionError(
                        "UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: attestation_signature mismatch."
                    )
                candidate_attestation["signature"] = attestation_signature
        else:
            candidate_attestation = {
                "verifier_id": cleaned_verifier,
                "verification_digest": verification_digest,
                "binary_hash": existing.binary_hash,
                "tool_id": existing.tool_id,
                "spec_digest": compute_tool_spec_security_digest(existing),
                "verified_at": now_iso,
            }
            if attestation_signature is not None:
                candidate_attestation["signature"] = attestation_signature

        if not self.authority.verify_attestation(
            candidate_attestation,
            expected_tool_id=existing.tool_id,
            expected_binary_hash=existing.binary_hash,
            expected_spec_digest=compute_tool_spec_security_digest(existing),
        ):
            raise PermissionError(
                f"UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY: invalid signature for '{cleaned_id}'."
            )

        verified = ToolSpec(
            tool_id=existing.tool_id,
            version=existing.version,
            source=existing.source,
            binary_hash=existing.binary_hash,
            capabilities=list(existing.capabilities),
            input_schema=dict(existing.input_schema),
            output_schema=dict(existing.output_schema),
            semantic_contract=dict(existing.semantic_contract),
            preconditions=list(existing.preconditions),
            postconditions=list(existing.postconditions),
            side_effects=list(existing.side_effects),
            required_permissions=list(existing.required_permissions),
            runtime_requirements=dict(existing.runtime_requirements),
            trust_status=TrustStatus.VERIFIED,
            latency_estimate_ms=existing.latency_estimate_ms,
            memory_estimate_mb=existing.memory_estimate_mb,
            api_token_estimate=existing.api_token_estimate,
            verification_attestation=candidate_attestation,
            provenance=dict(existing.provenance),
            entrypoint=existing.entrypoint,
            command=list(existing.command) if existing.command is not None else None,
        )
        self._tools[cleaned_id] = verified
        return verified

    def quarantine(self, tool_id: str, reason: str) -> ToolSpec:
        """Transition `tool_id` to `QUARANTINED`, stripping verification attestation and recording reason."""
        cleaned_id = validate_tool_id(tool_id)
        existing = self._tools.get(cleaned_id)
        if existing is None:
            raise KeyError(f"TOOL_NOT_FOUND: '{cleaned_id}' is not registered.")
        cleaned_reason = validate_safe_text(reason, field_name="reason")
        provenance = dict(existing.provenance)
        provenance["quarantine_reason"] = cleaned_reason
        provenance["quarantined_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        quarantined = ToolSpec(
            tool_id=existing.tool_id,
            version=existing.version,
            source=existing.source,
            binary_hash=existing.binary_hash,
            capabilities=list(existing.capabilities),
            input_schema=dict(existing.input_schema),
            output_schema=dict(existing.output_schema),
            semantic_contract=dict(existing.semantic_contract),
            preconditions=list(existing.preconditions),
            postconditions=list(existing.postconditions),
            side_effects=list(existing.side_effects),
            required_permissions=list(existing.required_permissions),
            runtime_requirements=dict(existing.runtime_requirements),
            trust_status=TrustStatus.QUARANTINED,
            latency_estimate_ms=existing.latency_estimate_ms,
            memory_estimate_mb=existing.memory_estimate_mb,
            api_token_estimate=existing.api_token_estimate,
            verification_attestation=None,
            provenance=provenance,
            entrypoint=existing.entrypoint,
            command=list(existing.command) if existing.command is not None else None,
        )
        self._tools[cleaned_id] = quarantined
        return quarantined

    def retire(self, tool_id: str, reason: str = "retired") -> ToolSpec:
        """Mark `tool_id` as `RETIRED` so it is excluded from new resolutions."""
        cleaned_id = validate_tool_id(tool_id)
        existing = self._tools.get(cleaned_id)
        if existing is None:
            raise KeyError(f"TOOL_NOT_FOUND: '{cleaned_id}' is not registered.")
        provenance = dict(existing.provenance)
        provenance["retire_reason"] = validate_safe_text(reason, field_name="reason")
        retired = ToolSpec(
            tool_id=existing.tool_id,
            version=existing.version,
            source=existing.source,
            binary_hash=existing.binary_hash,
            capabilities=list(existing.capabilities),
            input_schema=dict(existing.input_schema),
            output_schema=dict(existing.output_schema),
            semantic_contract=dict(existing.semantic_contract),
            preconditions=list(existing.preconditions),
            postconditions=list(existing.postconditions),
            side_effects=list(existing.side_effects),
            required_permissions=list(existing.required_permissions),
            runtime_requirements=dict(existing.runtime_requirements),
            trust_status=TrustStatus.RETIRED,
            latency_estimate_ms=existing.latency_estimate_ms,
            memory_estimate_mb=existing.memory_estimate_mb,
            api_token_estimate=existing.api_token_estimate,
            verification_attestation=None,
            provenance=provenance,
            entrypoint=existing.entrypoint,
            command=list(existing.command) if existing.command is not None else None,
        )
        self._tools[cleaned_id] = retired
        return retired

    def _resolve_allowlisted_scan_target(
        self,
        raw_target: Union[str, Path],
        security_context: SecurityContext,
    ) -> Path:
        raw_str = str(raw_target)
        if not raw_str or "\x00" in raw_str or TROJAN_UNICODE_RE.search(raw_str):
            raise PermissionError("SECURITY_INVALID_ALLOWLIST_PATH: empty, NUL, or control chars.")
        path_obj = Path(raw_str)
        if ".." in path_obj.parts:
            raise PermissionError(f"SECURITY_PATH_TRAVERSAL: '..' forbidden in allowlisted path '{raw_str}'.")
        assert_not_symlink(path_obj)
        ws_resolved = Path(security_context.workspace_root).resolve()
        is_inside_ws = False
        if path_obj.is_absolute():
            try:
                path_obj.resolve().relative_to(ws_resolved)
                is_inside_ws = True
            except ValueError:
                is_inside_ws = False
        if not path_obj.is_absolute() or is_inside_ws or security_context.profile == SecurityProfile.GITHUB_PUBLIC:
            return security_context.validate_path(path_obj)
        return path_obj.resolve()

    def _store_discovered_spec(self, spec: ToolSpec) -> ToolSpec:
        """Register a discovered tool safely without ever overwriting an existing `VERIFIED` tool."""
        existing = self._tools.get(spec.tool_id)
        if existing is not None and existing.trust_status == TrustStatus.VERIFIED:
            if existing.binary_hash == spec.binary_hash:
                return existing
            quarantined_id = _sanitize_discovered_tool_id(
                f"{spec.tool_id}.conflict.{spec.binary_hash[7:15]}"
            )
            provenance = dict(spec.provenance)
            provenance["quarantine_reason"] = f"VERIFIED_TOOL_ID_COLLISION:{spec.tool_id}"
            spec = ToolSpec(
                tool_id=quarantined_id,
                version=spec.version,
                source=spec.source,
                binary_hash=spec.binary_hash,
                capabilities=list(spec.capabilities),
                input_schema=dict(spec.input_schema),
                output_schema=dict(spec.output_schema),
                semantic_contract=dict(spec.semantic_contract),
                preconditions=list(spec.preconditions),
                postconditions=list(spec.postconditions),
                side_effects=list(spec.side_effects),
                required_permissions=list(spec.required_permissions),
                runtime_requirements=dict(spec.runtime_requirements),
                trust_status=TrustStatus.QUARANTINED,
                latency_estimate_ms=spec.latency_estimate_ms,
                memory_estimate_mb=spec.memory_estimate_mb,
                api_token_estimate=spec.api_token_estimate,
                verification_attestation=None,
                provenance=provenance,
                entrypoint=spec.entrypoint,
                command=list(spec.command) if spec.command is not None else None,
            )
        canonical_copy = ToolSpec.from_dict(spec.to_dict(), from_discovery=True)
        canonical_copy.to_canonical_json()
        self._tools[canonical_copy.tool_id] = canonical_copy
        return canonical_copy

    def _discover_manifest_file(
        self,
        manifest_path: Path,
        scan_root: Path,
        claimed_entrypoints: set,
    ) -> Optional[ToolSpec]:
        raw_bytes, manifest_sha = _safe_read_regular_no_follow(
            manifest_path, max_bytes=MAX_DISCOVERY_JSON_BYTES
        )
        raw_payload = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(raw_payload, dict):
            self.discovery_rejections.append({"path": str(manifest_path), "reason": "MANIFEST_NOT_OBJECT"})
            return None

        suspicious_reason = has_suspicious_metadata(raw_payload)
        payload = dict(raw_payload)
        payload.setdefault("version", "0.1.0")
        payload["source"] = "local_discovery"
        provenance = dict(payload.get("provenance") or {})
        provenance["manifest_path"] = manifest_path.name
        provenance["manifest_sha256"] = manifest_sha

        raw_entry = payload.get("entrypoint")
        computed_hash = manifest_sha
        if isinstance(raw_entry, str) and raw_entry.strip():
            safe_entry = resolve_safe_child_path(scan_root, raw_entry.strip())
            if safe_entry is None or safe_entry.is_symlink():
                suspicious_reason = suspicious_reason or "ENTRYPOINT_TRAVERSAL_OR_SYMLINK"
            elif safe_entry.exists():
                _, computed_hash = _safe_read_regular_no_follow(
                    safe_entry, max_bytes=MAX_DISCOVERY_BINARY_BYTES
                )
                claimed_entrypoints.add(safe_entry.resolve())
                declared_hash = str(payload.get("binary_hash", "")).strip().lower()
                if declared_hash and declared_hash != computed_hash:
                    suspicious_reason = suspicious_reason or "BINARY_HASH_MISMATCH"
        payload["binary_hash"] = computed_hash

        if "tool_id" not in payload:
            payload["tool_id"] = _sanitize_discovered_tool_id(manifest_path.stem.replace(".tool", ""))
        else:
            try:
                payload["tool_id"] = validate_tool_id(payload["tool_id"])
            except ValueError as exc:
                self.discovery_rejections.append({"path": str(manifest_path), "reason": str(exc)})
                return None

        if not payload.get("capabilities"):
            payload["capabilities"] = [f"tool.{payload['tool_id']}"]

        if suspicious_reason:
            payload["trust_status"] = TrustStatus.QUARANTINED.value
            payload["verification_attestation"] = None
            provenance["quarantine_reason"] = suspicious_reason
        else:
            payload["trust_status"] = TrustStatus.DISCOVERED.value
            payload["verification_attestation"] = None
        payload["provenance"] = redact_secrets_in_value(provenance)
        spec = ToolSpec.from_dict(payload, from_discovery=True)
        return self._store_discovered_spec(spec)

    def _discover_binary_file(self, bin_path: Path) -> Optional[ToolSpec]:
        raw_prefix, bin_sha = _safe_read_regular_no_follow(bin_path, max_bytes=MAX_DISCOVERY_BINARY_BYTES)
        suspicious_reason: Optional[str] = None
        try:
            text_sample = raw_prefix.decode("utf-8")
        except UnicodeDecodeError:
            text_sample = ""
        if text_sample:
            if TROJAN_UNICODE_RE.search(text_sample):
                suspicious_reason = "TROJAN_UNICODE_IN_BINARY"
            elif PROMPT_INJECTION_RE.search(text_sample):
                suspicious_reason = "PROMPT_INJECTION_IN_SCRIPT"

        tool_id = _sanitize_discovered_tool_id(bin_path.stem if bin_path.suffix in {".py", ".sh"} else bin_path.name)
        provenance: Dict[str, Any] = {"discovered_file": bin_path.name, "discovery_mode": "static_no_exec"}
        status = TrustStatus.DISCOVERED
        if suspicious_reason:
            status = TrustStatus.QUARANTINED
            provenance["quarantine_reason"] = suspicious_reason

        spec = ToolSpec(
            tool_id=tool_id,
            version="0.0.0-discovered",
            source="local_discovery",
            binary_hash=bin_sha,
            capabilities=[f"local.{tool_id}"],
            side_effects=["unknown"],
            required_permissions=["process.exec"],
            runtime_requirements={"static_inspected": True, "executed": False},
            trust_status=status,
            provenance=provenance,
            entrypoint=bin_path.name,
        )
        return self._store_discovered_spec(spec)

    def _discover_mcp_config(
        self,
        cfg_source: Union[str, Path, Dict[str, Any]],
        security_context: SecurityContext,
    ) -> List[ToolSpec]:
        discovered: List[ToolSpec] = []
        source_label = "inline_mcp_config"
        if isinstance(cfg_source, dict):
            raw_cfg = dict(cfg_source)
        else:
            cfg_path = self._resolve_allowlisted_scan_target(cfg_source, security_context)
            source_label = cfg_path.name
            raw_bytes, _ = _safe_read_regular_no_follow(cfg_path, max_bytes=MAX_DISCOVERY_JSON_BYTES)
            raw_cfg = json.loads(raw_bytes.decode("utf-8"))
            if not isinstance(raw_cfg, dict):
                self.discovery_rejections.append({"path": str(cfg_path), "reason": "MCP_CONFIG_NOT_OBJECT"})
                return discovered

        servers = raw_cfg.get("mcpServers") or raw_cfg.get("servers") or {}
        if not isinstance(servers, dict):
            return discovered

        for server_name in sorted(servers.keys()):
            srv_cfg = servers[server_name]
            if not isinstance(srv_cfg, dict):
                continue
            suspicious_reason = has_suspicious_metadata(srv_cfg)
            cmd = str(srv_cfg.get("command", "") or "").strip()
            args = [str(a) for a in (srv_cfg.get("args") or [])]
            if cmd and (_SHELL_METACHAR_RE.search(cmd) or ".." in Path(cmd).parts):
                suspicious_reason = suspicious_reason or "UNSAFE_MCP_COMMAND"

            redacted_srv = redact_secrets_in_value(srv_cfg)
            bin_hash = sha256_digest({"server": server_name, "config": redacted_srv})
            if cmd and not Path(cmd).is_symlink():
                cmd_path = Path(cmd)
                if not cmd_path.is_absolute():
                    safe_cmd = resolve_safe_child_path(Path(security_context.workspace_root), cmd)
                    cmd_path = safe_cmd if safe_cmd is not None else cmd_path
                if cmd_path.exists() and not cmd_path.is_symlink() and cmd_path.is_file():
                    try:
                        _, bin_hash = _safe_read_regular_no_follow(
                            cmd_path, max_bytes=MAX_DISCOVERY_BINARY_BYTES
                        )
                    except (OSError, ValueError) as exc:
                        suspicious_reason = suspicious_reason or f"MCP_COMMAND_UNREADABLE:{type(exc).__name__}"
                        self.discovery_rejections.append({"path": str(cmd_path), "reason": str(exc)})

            tool_id = _sanitize_discovered_tool_id(str(server_name), prefix="mcp.")
            caps = srv_cfg.get("capabilities")
            if not isinstance(caps, list) or not caps:
                caps = [f"mcp.{tool_id}"]
            perms = srv_cfg.get("required_permissions")
            if not isinstance(perms, list):
                perms = ["mcp.invoke"]
                if srv_cfg.get("url"):
                    perms.append("network.outbound")

            provenance: Dict[str, Any] = {
                "mcp_server": str(server_name),
                "mcp_config_source": source_label,
                "redacted_env_keys": sorted(str(k) for k in (srv_cfg.get("env") or {}).keys()),
            }
            status = TrustStatus.DISCOVERED
            if suspicious_reason:
                status = TrustStatus.QUARANTINED
                provenance["quarantine_reason"] = suspicious_reason

            spec = ToolSpec(
                tool_id=tool_id,
                version=str(srv_cfg.get("version", "0.0.0-mcp")),
                source="mcp_discovery",
                binary_hash=bin_hash,
                capabilities=[str(c) for c in caps],
                input_schema=dict(srv_cfg.get("input_schema") or {}),
                output_schema=dict(srv_cfg.get("output_schema") or {}),
                semantic_contract=dict(srv_cfg.get("semantic_contract") or {}),
                side_effects=[str(s) for s in (srv_cfg.get("side_effects") or ["mcp.external"])],
                required_permissions=[str(p) for p in perms],
                runtime_requirements={"mcp_config": redacted_srv, "executed": False},
                trust_status=status,
                provenance=provenance,
                command=[cmd, *args] if cmd else None,
            )
            discovered.append(self._store_discovered_spec(spec))
        return discovered

    def discover_local(
        self,
        security_context: SecurityContext,
        allowlisted_paths: Optional[Sequence[Union[str, Path]]] = None,
        mcp_configs: Optional[Sequence[Union[str, Path, Dict[str, Any]]]] = None,
    ) -> List[ToolSpec]:
        """
        Statically discover local tools and MCP configs without executing any untrusted binaries.

        Uses `O_NOFOLLOW` and symlink guards; discovered tools are strictly marked `DISCOVERED`
        or `QUARANTINED`, never `VERIFIED`.
        """
        if not isinstance(security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext.")

        discovered: List[ToolSpec] = []
        claimed_entrypoints: set = set()

        if allowlisted_paths is None:
            ws_root = Path(security_context.workspace_root)
            candidates = [ws_root / rel for rel in ("tools", "bin", ".kintsugi/tools")]
            scan_targets = [p for p in candidates if p.exists() and not p.is_symlink()]
        else:
            scan_targets = [
                self._resolve_allowlisted_scan_target(raw_p, security_context)
                for raw_p in allowlisted_paths
            ]

        for target in scan_targets:
            assert_not_symlink(target)
            if not target.exists():
                continue
            if target.is_file():
                if _is_manifest_file(target):
                    spec = self._discover_manifest_file(target, target.parent, claimed_entrypoints)
                    if spec is not None:
                        discovered.append(spec)
                else:
                    st = os.lstat(str(target))
                    if stat.S_ISREG(st.st_mode) and _is_candidate_executable_or_script(target, st.st_mode):
                        spec = self._discover_binary_file(target)
                        if spec is not None:
                            discovered.append(spec)
                continue

            if not target.is_dir():
                continue

            entries = sorted(os.scandir(str(target)), key=lambda e: e.name)
            manifest_entries = [e for e in entries if _is_manifest_file(Path(e.name))]
            other_entries = [e for e in entries if not _is_manifest_file(Path(e.name))]

            for entry in manifest_entries:
                entry_path = Path(entry.path)
                if entry.is_symlink():
                    self.discovery_rejections.append({"path": str(entry_path), "reason": "SYMLINK_REFUSED"})
                    continue
                if entry.is_file(follow_symlinks=False):
                    spec = self._discover_manifest_file(entry_path, target, claimed_entrypoints)
                    if spec is not None:
                        discovered.append(spec)

            for entry in other_entries:
                entry_path = Path(entry.path)
                if entry.is_symlink():
                    self.discovery_rejections.append({"path": str(entry_path), "reason": "SYMLINK_REFUSED"})
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if entry_path.resolve() in claimed_entrypoints:
                    continue
                st = entry.stat(follow_symlinks=False)
                if stat.S_ISREG(st.st_mode) and _is_candidate_executable_or_script(entry_path, st.st_mode):
                    spec = self._discover_binary_file(entry_path)
                    if spec is not None:
                        discovered.append(spec)

        for cfg in mcp_configs or ():
            discovered.extend(self._discover_mcp_config(cfg, security_context))

        return discovered

    def save(self, path: Optional[Union[str, Path]] = None) -> Path:
        """Atomically persist the registry to disk after symlink and secret checks."""
        target = Path(path) if path is not None else self.storage_path
        if target is None:
            raise ValueError("MISSING_STORAGE_PATH: specify path to save ToolRegistry.")
        assert_not_symlink(target.parent)
        assert_not_symlink(target)
        ordered = [self._tools[tid].to_dict() for tid in sorted(self._tools.keys())]
        payload = {
            "schema": self.SCHEMA_VERSION,
            "total_tools": len(ordered),
            "tools": ordered,
        }
        assert_no_raw_secrets(canonical_json_dumps(payload), context="ToolRegistry.save")
        atomic_write_json(target, payload, mode=0o600, indent=2)
        return target

    def load(self, path: Optional[Union[str, Path]] = None) -> None:
        """Safely load registry JSON using `O_NOFOLLOW` while enforcing trust attestation invariants."""
        target = Path(path) if path is not None else self.storage_path
        if target is None:
            raise ValueError("MISSING_STORAGE_PATH: specify path to load ToolRegistry.")
        assert_not_symlink(target.parent)
        assert_not_symlink(target)
        raw_bytes, _ = _safe_read_regular_no_follow(target, max_bytes=16 * 1024 * 1024)
        payload = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != self.SCHEMA_VERSION:
            raise ValueError(f"INVALID_REGISTRY_SCHEMA: expected '{self.SCHEMA_VERSION}'.")
        loaded: Dict[str, ToolSpec] = {}
        for item in payload.get("tools", []):
            if not isinstance(item, dict):
                continue
            raw_trust = str(item.get("trust_status", TrustStatus.DISCOVERED.value)).strip().upper()
            if raw_trust == TrustStatus.VERIFIED.value:
                bin_hash = str(item.get("binary_hash", "")).strip().lower()
                tid = str(item.get("tool_id", "")).strip()
                att = item.get("verification_attestation")
                valid_structural = has_valid_verification_attestation(att, bin_hash, tid)
                valid_crypto = False
                if valid_structural and isinstance(att, dict) and self.authority.has_registered_verifiers:
                    try:
                        valid_crypto = self.authority.verify_attestation(
                            att,
                            expected_tool_id=tid,
                            expected_binary_hash=bin_hash,
                            expected_spec_digest=compute_tool_spec_security_digest(item),
                        )
                    except (TypeError, ValueError, KeyError):
                        valid_crypto = False
                if not valid_structural or not valid_crypto:
                    tampered = dict(item)
                    tampered["trust_status"] = TrustStatus.QUARANTINED.value
                    tampered["verification_attestation"] = None
                    prov = dict(tampered.get("provenance") or {})
                    prov["quarantine_reason"] = (
                        "TAMPERED_OR_UNTRUSTED_ATTESTATION"
                        if not valid_structural
                        else "TAMPERED_OR_UNTRUSTED_ATTESTATION"
                    )
                    tampered["provenance"] = prov
                    spec = ToolSpec.from_dict(tampered, from_discovery=True)
                else:
                    spec = ToolSpec.from_dict(item, from_discovery=False)
            else:
                spec = ToolSpec.from_dict(item, from_discovery=False)
            loaded[spec.tool_id] = spec
        self._tools = loaded
