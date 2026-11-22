"""ProofPack (`kintsugi.tools.proof_pack`): Independent verification, differential parity, and proof-tier engine.

Enforces strict separation between the three verification tiers (`ProofLevel`):
  - `DIFFERENTIAL_VERIFIED`: Reference vs. candidate outputs matched across a tested corpus
    (reporting case count, seed, inputs digest, and exact vs. tolerant comparison).
  - `PROPERTY_TESTED`: Metamorphic / boundary invariants checked and passed on tested inputs.
  - `FORMALLY_PROVEN`: Permitted ONLY when an explicit, validated formal solver proof artifact
    (`solver_name`, `solver_version`, `assumptions`, `proof_scope`, `proof_digest`, `verified=True`)
    is supplied. Any attempt to promote differential or fuzz testing to `FORMALLY_PROVEN`
    raises `ValueError`.

Emits `ProofPackReport/1` (`PASS | FAIL | NOT_VERIFIED`) and never claims `PASS` without
independent verification.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import math
import os
import platform
import random
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import (
    assert_no_raw_secrets,
    canonical_json_dumps,
    normalize_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.shield import TROJAN_UNICODE_RE, assert_not_symlink, resolve_safe_child_path
from kintsugi.tools.log_forge import (
    LogForgeNativeBridge,
    normalize_log_records_python,
    scan_delimiters_python,
)

PROOF_PACK_REPORT_SCHEMA = "ProofPackReport/1"
ARTIFACT_MANIFEST_SCHEMA = "ArtifactManifest/1"
FORMAL_PROOF_ARTIFACT_SCHEMA = "FormalProofArtifact/1"
VALID_PROOF_STATUSES = frozenset({"PASS", "FAIL", "NOT_VERIFIED"})

_READ_CHUNK_BYTES = 65536
_MAX_MANIFEST_FILE_BYTES = 256 * 1024 * 1024
_FORBIDDEN_SOLVER_TOKENS = frozenset(
    {
        "fuzz",
        "fuzzer",
        "fuzzing",
        "differential",
        "diff",
        "property",
        "property_test",
        "random",
        "corpus",
        "empirical",
        "heuristic",
        "mock",
        "self",
        "llm",
        "none",
        "unknown",
        "hypothesis",
        "unittest",
        "pytest",
    }
)
_EPHEMERAL_REPRO_KEYS = frozenset(
    {
        "run_id",
        "timestamp",
        "created_at",
        "built_at",
        "verified_at",
        "elapsed_ms",
        "elapsed_us",
        "wall_time_ms",
        "duration_ms",
        "trace_digest",
        "report_id",
        "report_digest",
    }
)


class ProofLevel(str, Enum):
    """Strict non-interchangeable verification proof tiers."""

    DIFFERENTIAL_VERIFIED = "DIFFERENTIAL_VERIFIED"
    PROPERTY_TESTED = "PROPERTY_TESTED"
    FORMALLY_PROVEN = "FORMALLY_PROVEN"


def _coerce_proof_level(value: Union[ProofLevel, str]) -> ProofLevel:
    if isinstance(value, ProofLevel):
        return value
    if isinstance(value, str):
        return ProofLevel(value.strip().upper())
    raise ValueError(f"INVALID_PROOF_LEVEL: {value!r}")


def _validate_structure_no_trojan(value: Any, *, field_name: str) -> None:
    if isinstance(value, str):
        if "\x00" in value or TROJAN_UNICODE_RE.search(value):
            raise ValueError(f"REJECTED_TROJAN_UNICODE ({field_name}): invisible or bidi control character detected.")
    elif isinstance(value, Mapping):
        for k, v in value.items():
            _validate_structure_no_trojan(str(k), field_name=field_name)
            _validate_structure_no_trojan(v, field_name=field_name)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            _validate_structure_no_trojan(item, field_name=field_name)


def _sanitize_summary(value: Optional[Mapping[str, Any]], *, field_name: str) -> Optional[Dict[str, Any]]:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError(f"INVALID_{field_name.upper()}: expected mapping.")
    cleaned = redact_secrets_in_value(dict(value))
    _validate_structure_no_trojan(cleaned, field_name=field_name)
    return cleaned


def _normalize_for_digest(value: Any) -> Any:
    """Encode arbitrary Python values (including bytes/tuples/sets) unambiguously for SHA-256 digests."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"__bytes_sha256__": hashlib.sha256(raw).hexdigest(), "__len__": len(raw)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _normalize_for_digest(value.to_dict())
    if isinstance(value, Mapping):
        return {str(k): _normalize_for_digest(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, tuple):
        return {"__tuple__": [_normalize_for_digest(v) for v in value]}
    if isinstance(value, list):
        return [_normalize_for_digest(v) for v in value]
    if isinstance(value, (set, frozenset)):
        norm_items = [_normalize_for_digest(v) for v in value]
        return sorted(norm_items, key=canonical_json_dumps)
    return repr(value)


def _is_forbidden_solver_label(text: str) -> bool:
    low = text.strip().lower()
    if low in _FORBIDDEN_SOLVER_TOKENS:
        return True
    tokens = {tok for tok in low.replace("-", "_").split("_") if tok}
    return bool(tokens & {"fuzz", "fuzzer", "fuzzing", "differential", "property", "random", "heuristic", "empirical"})


@dataclass
class FormalProofArtifact:
    """Explicit solver-backed formal proof certificate (`FormalProofArtifact/1`)."""

    solver_name: str
    solver_version: str
    assumptions: List[str]
    proof_scope: str
    proof_digest: str
    verified: bool
    evidence_kind: str = "formal_solver"
    schema: str = FORMAL_PROOF_ARTIFACT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != FORMAL_PROOF_ARTIFACT_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {FORMAL_PROOF_ARTIFACT_SCHEMA}, got '{self.schema}'.")
        self.solver_name = validate_safe_text(self.solver_name, field_name="solver_name")
        if _is_forbidden_solver_label(self.solver_name):
            raise ValueError(
                f"FORMAL_PROOF_ESCALATION_REJECTED: solver_name '{self.solver_name}' is not a valid formal solver."
            )
        self.solver_version = validate_safe_text(self.solver_version, field_name="solver_version")
        if not isinstance(self.assumptions, (list, tuple)):
            raise ValueError("INVALID_ASSUMPTIONS: FormalProofArtifact requires explicit sequence of assumptions.")
        cleaned_assumptions: List[str] = []
        for item in self.assumptions:
            cleaned_assumptions.append(redact_secrets_in_text(validate_safe_text(item, field_name="assumptions")))
        self.assumptions = cleaned_assumptions
        self.proof_scope = redact_secrets_in_text(validate_safe_text(self.proof_scope, field_name="proof_scope"))
        self.proof_digest = normalize_sha256(self.proof_digest, field_name="proof_digest")
        if not isinstance(self.verified, bool):
            raise ValueError("INVALID_VERIFIED_FLAG: FormalProofArtifact.verified must be a strict boolean.")
        self.evidence_kind = validate_safe_text(self.evidence_kind, field_name="evidence_kind")
        if _is_forbidden_solver_label(self.evidence_kind):
            raise ValueError(
                f"FORMAL_PROOF_ESCALATION_REJECTED: evidence_kind '{self.evidence_kind}' cannot represent a formal proof."
            )

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "solver_name": self.solver_name,
                "solver_version": self.solver_version,
                "assumptions": list(self.assumptions),
                "proof_scope": self.proof_scope,
                "proof_digest": self.proof_digest,
                "verified": self.verified,
                "evidence_kind": self.evidence_kind,
            }
        )

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Union["FormalProofArtifact", Mapping[str, Any]]) -> "FormalProofArtifact":
        if isinstance(data, FormalProofArtifact):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_FORMAL_PROOF_ARTIFACT: expected mapping.")
        if data.get("self_asserted") is True:
            raise ValueError("FORMAL_PROOF_ESCALATION_REJECTED: self_asserted formal proofs are forbidden.")
        required = ("solver_name", "solver_version", "assumptions", "proof_scope", "proof_digest", "verified")
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(f"MISSING_FORMAL_PROOF_FIELDS: {','.join(missing)}")
        return cls(
            solver_name=data["solver_name"],
            solver_version=data["solver_version"],
            assumptions=list(data["assumptions"]) if isinstance(data["assumptions"], (list, tuple)) else data["assumptions"],  # type: ignore[arg-type]
            proof_scope=data["proof_scope"],
            proof_digest=data["proof_digest"],
            verified=data["verified"],
            evidence_kind=data.get("evidence_kind", "formal_solver"),
            schema=data.get("schema", FORMAL_PROOF_ARTIFACT_SCHEMA),
        )


def validate_formal_proof_artifact(
    artifact: Union[FormalProofArtifact, Mapping[str, Any]],
) -> FormalProofArtifact:
    """Validate an explicit formal solver proof artifact and require `verified is True`."""
    if artifact is None:
        raise ValueError("FORMAL_PROOF_REQUIRED: FormalProofArtifact cannot be None.")
    parsed = FormalProofArtifact.from_dict(artifact)
    if parsed.verified is not True:
        raise ValueError("FORMAL_PROOF_NOT_VERIFIED: FormalProofArtifact requires verified=True.")
    return parsed


@dataclass
class ProofPackReport:
    """Independent verification verdict (`ProofPackReport/1`) with strict proof-tier guarantees."""

    status: str
    verified_independently: bool = False
    proof_levels: List[ProofLevel] = field(default_factory=list)
    differential_summary: Optional[Dict[str, Any]] = None
    property_summary: Optional[Dict[str, Any]] = None
    formal_proof: Optional[FormalProofArtifact] = None
    reproducibility_summary: Optional[Dict[str, Any]] = None
    manifest: Optional[Dict[str, Any]] = None
    parity_summary: Optional[Dict[str, Any]] = None
    reasons: List[str] = field(default_factory=list)
    report_id: str = "proof-report"
    report_digest: str = ""
    schema: str = PROOF_PACK_REPORT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != PROOF_PACK_REPORT_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {PROOF_PACK_REPORT_SCHEMA}, got '{self.schema}'.")
        self.report_id = validate_safe_text(self.report_id, field_name="report_id")

        norm_status = validate_safe_text(self.status, field_name="status").upper()
        if norm_status not in VALID_PROOF_STATUSES:
            raise ValueError(f"INVALID_PROOF_STATUS: '{self.status}' not in {sorted(VALID_PROOF_STATUSES)}.")
        self.status = norm_status

        if not isinstance(self.verified_independently, bool):
            raise ValueError("INVALID_VERIFIED_INDEPENDENTLY: expected bool.")

        coerced_levels: List[ProofLevel] = []
        for lvl in self.proof_levels or ():
            coerced = _coerce_proof_level(lvl)
            if coerced not in coerced_levels:
                coerced_levels.append(coerced)
        self.proof_levels = coerced_levels

        self.differential_summary = _sanitize_summary(self.differential_summary, field_name="differential_summary")
        self.property_summary = _sanitize_summary(self.property_summary, field_name="property_summary")
        self.reproducibility_summary = _sanitize_summary(
            self.reproducibility_summary, field_name="reproducibility_summary"
        )
        self.manifest = _sanitize_summary(self.manifest, field_name="manifest")
        self.parity_summary = _sanitize_summary(self.parity_summary, field_name="parity_summary")

        if self.formal_proof is not None:
            self.formal_proof = validate_formal_proof_artifact(self.formal_proof)

        clean_reasons: List[str] = []
        for reason in self.reasons or ():
            clean_reasons.append(redact_secrets_in_text(validate_safe_text(str(reason), field_name="reasons")))
        self.reasons = clean_reasons

        # Strictly forbid escalating differential/property/fuzz testing to FORMALLY_PROVEN
        if ProofLevel.FORMALLY_PROVEN in self.proof_levels:
            if self.formal_proof is None:
                raise ValueError(
                    "FORMAL_PROOF_ESCALATION_REJECTED: FORMALLY_PROVEN requires an explicit validated "
                    "FormalProofArtifact; differential/fuzz testing cannot claim FORMALLY_PROVEN."
                )
            validate_formal_proof_artifact(self.formal_proof)

        # Never claim PASS without independent verification and consistent positive evidence
        if self.status == "PASS":
            self._enforce_pass_evidence()

        computed_digest = sha256_digest(self._digest_basis())
        if self.report_digest:
            provided = normalize_sha256(self.report_digest, field_name="report_digest")
            if not hmac.compare_digest(provided, computed_digest):
                raise ValueError("REPORT_DIGEST_MISMATCH: report_digest does not match canonical ProofPackReport.")
            self.report_digest = provided
        else:
            self.report_digest = computed_digest

    def _enforce_pass_evidence(self) -> None:
        if not self.verified_independently:
            raise ValueError(
                "UNVERIFIED_PASS_REJECTED: ProofPackReport cannot claim PASS without independent verification."
            )
        has_verified_evidence = False

        if ProofLevel.DIFFERENTIAL_VERIFIED in self.proof_levels:
            if not self.differential_summary:
                raise ValueError("UNVERIFIED_PASS_REJECTED: DIFFERENTIAL_VERIFIED requires differential_summary.")
            if int(self.differential_summary.get("total_cases", 0)) <= 0:
                raise ValueError("UNVERIFIED_PASS_REJECTED: differential_summary requires total_cases > 0.")
            if int(self.differential_summary.get("mismatches", 0)) != 0:
                raise ValueError("UNVERIFIED_PASS_REJECTED: differential_summary contains mismatches.")
            has_verified_evidence = True

        if ProofLevel.PROPERTY_TESTED in self.proof_levels:
            if not self.property_summary:
                raise ValueError("UNVERIFIED_PASS_REJECTED: PROPERTY_TESTED requires property_summary.")
            if int(self.property_summary.get("total_checks", 0)) <= 0:
                raise ValueError("UNVERIFIED_PASS_REJECTED: property_summary requires total_checks > 0.")
            if int(self.property_summary.get("failed_checks", 0)) != 0:
                raise ValueError("UNVERIFIED_PASS_REJECTED: property_summary contains failed_checks.")
            has_verified_evidence = True

        if ProofLevel.FORMALLY_PROVEN in self.proof_levels:
            if self.formal_proof is None or self.formal_proof.verified is not True:
                raise ValueError("UNVERIFIED_PASS_REJECTED: FORMALLY_PROVEN requires verified FormalProofArtifact.")
            has_verified_evidence = True

        if self.reproducibility_summary is not None:
            if self.reproducibility_summary.get("reproducible") is not True:
                raise ValueError("UNVERIFIED_PASS_REJECTED: reproducibility_summary is not reproducible.")
            if int(self.reproducibility_summary.get("checked_count", 0)) < 2:
                raise ValueError("UNVERIFIED_PASS_REJECTED: reproducibility requires >= 2 independent runs/manifests.")
            has_verified_evidence = True

        if self.parity_summary is not None:
            if self.parity_summary.get("parity_ok") is not True:
                raise ValueError("UNVERIFIED_PASS_REJECTED: parity_summary indicates parity failure.")
            if int(self.parity_summary.get("checked_cases", 0)) <= 0:
                raise ValueError("UNVERIFIED_PASS_REJECTED: parity_summary requires checked_cases > 0.")
            has_verified_evidence = True

        if not has_verified_evidence:
            raise ValueError("UNVERIFIED_PASS_REJECTED: PASS requires at least one independently verified evidence record.")

    def _digest_basis(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "report_id": self.report_id,
            "status": self.status,
            "verified_independently": self.verified_independently,
            "proof_levels": [lvl.value for lvl in self.proof_levels],
            "differential_summary": self.differential_summary,
            "property_summary": self.property_summary,
            "formal_proof": self.formal_proof.to_dict() if self.formal_proof is not None else None,
            "reproducibility_summary": self.reproducibility_summary,
            "manifest": self.manifest,
            "parity_summary": self.parity_summary,
            "reasons": list(self.reasons),
        }

    @property
    def ok(self) -> bool:
        return self.status == "PASS"

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    @property
    def reproducible(self) -> bool:
        return bool((self.reproducibility_summary or {}).get("reproducible", False))

    def __bool__(self) -> bool:
        return self.status == "PASS"

    def to_dict(self) -> Dict[str, Any]:
        payload = self._digest_basis()
        payload["report_digest"] = self.report_digest
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"ProofPackReport:{self.report_id}")
        return serialized

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())

    @classmethod
    def from_dict(cls, data: Union["ProofPackReport", Mapping[str, Any]]) -> "ProofPackReport":
        if isinstance(data, ProofPackReport):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_PROOF_PACK_REPORT: expected mapping.")
        raw_fp = data.get("formal_proof")
        fp_obj = FormalProofArtifact.from_dict(raw_fp) if raw_fp is not None else None
        return cls(
            status=data["status"],
            verified_independently=bool(data.get("verified_independently", False)),
            proof_levels=list(data.get("proof_levels", [])),
            differential_summary=data.get("differential_summary"),
            property_summary=data.get("property_summary"),
            formal_proof=fp_obj,
            reproducibility_summary=data.get("reproducibility_summary"),
            manifest=data.get("manifest"),
            parity_summary=data.get("parity_summary"),
            reasons=list(data.get("reasons", [])),
            report_id=data.get("report_id", "proof-report"),
            report_digest=data.get("report_digest", ""),
            schema=data.get("schema", PROOF_PACK_REPORT_SCHEMA),
        )


def _confine_and_hash_regular_file(
    raw_file: Union[str, Path],
    ws_path: Path,
    ws_resolved: Path,
) -> Tuple[str, Dict[str, Any]]:
    """Confine `raw_file` inside `ws_resolved`, reject any symlink component, and hash via `O_NOFOLLOW`."""
    raw_str = validate_safe_text(str(raw_file), field_name="file_path")
    if ".." in Path(raw_str).parts:
        raise PermissionError(f"SECURITY_PATH_TRAVERSAL: '..' forbidden in '{raw_str}'.")

    candidate = Path(raw_str)
    assert_not_symlink(candidate)
    if candidate.is_absolute():
        rel_str: Optional[str] = None
        for base in (ws_path, ws_resolved):
            try:
                rel_obj = candidate.relative_to(base)
                rel_str = rel_obj.as_posix()
                break
            except ValueError:
                continue
        if rel_str is None:
            try:
                rel_str = candidate.resolve().relative_to(ws_resolved).as_posix()
            except ValueError as exc:
                raise PermissionError(
                    f"SECURITY_WORKSPACE_ESCAPE: '{raw_str}' lies outside workspace root."
                ) from exc
    else:
        rel_str = candidate.as_posix()

    if not rel_str or rel_str == ".":
        raise ValueError(f"INVALID_MANIFEST_FILE: '{raw_str}' does not name a file.")

    cur = ws_resolved
    for seg in Path(rel_str).parts:
        if seg in ("", "."):
            continue
        if seg == "..":
            raise PermissionError(f"SECURITY_PATH_TRAVERSAL: '..' forbidden in '{raw_str}'.")
        cur = cur / seg
        assert_not_symlink(cur)

    safe_target = resolve_safe_child_path(ws_resolved, rel_str)
    if safe_target is None:
        raise PermissionError(f"SECURITY_WORKSPACE_ESCAPE: '{raw_str}' escapes workspace root.")
    assert_not_symlink(safe_target)

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(safe_target), flags)
    except OSError as exc:
        raise PermissionError(f"SECURITY_NOFOLLOW_OPEN_FAILED: '{rel_str}' ({exc})") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_NON_REGULAR_FILE: '{rel_str}' is not a regular file.")
        if st.st_size > _MAX_MANIFEST_FILE_BYTES:
            raise ValueError(f"MANIFEST_FILE_TOO_LARGE: '{rel_str}' exceeds {_MAX_MANIFEST_FILE_BYTES} bytes.")
        hasher = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_MANIFEST_FILE_BYTES:
                raise ValueError(f"MANIFEST_FILE_TOO_LARGE: '{rel_str}' exceeded size limit during read.")
            hasher.update(chunk)
    finally:
        os.close(fd)

    entry = {
        "sha256": f"sha256:{hasher.hexdigest()}",
        "size_bytes": int(total),
        "mode": oct(stat.S_IMODE(st.st_mode)),
    }
    return rel_str, entry


def build_artifact_manifest(
    files: Iterable[Union[str, Path]],
    workspace_root: Union[str, Path],
    extra_metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a deterministic, symlink-safe (`O_NOFOLLOW`) SHA-256 `ArtifactManifest/1`
    with OS, architecture, Python, and toolchain metadata.
    """
    raw_ws = validate_safe_text(str(workspace_root), field_name="workspace_root")
    ws_path = Path(raw_ws)
    assert_not_symlink(ws_path)
    if not ws_path.exists() or not ws_path.is_dir():
        raise FileNotFoundError(f"INVALID_WORKSPACE_ROOT: directory does not exist: '{raw_ws}'.")
    ws_resolved = ws_path.resolve()

    if isinstance(files, (str, Path)):
        file_list = [files]
    else:
        file_list = list(files)
    if not file_list:
        raise ValueError("EMPTY_MANIFEST_FILES: at least one artifact file is required.")

    file_entries: Dict[str, Dict[str, Any]] = {}
    for item in file_list:
        rel_posix, entry = _confine_and_hash_regular_file(item, ws_path, ws_resolved)
        file_entries[rel_posix] = entry

    ordered_files = {k: file_entries[k] for k in sorted(file_entries.keys())}
    cleaned_extra = _sanitize_summary(extra_metadata, field_name="extra_metadata") if extra_metadata is not None else {}

    env_meta: Dict[str, Any] = {
        "os": platform.system(),
        "os_release": platform.release(),
        "arch": platform.machine(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }
    toolchain_meta: Dict[str, Any] = {"python": platform.python_version()}
    if isinstance(cleaned_extra.get("toolchain"), Mapping):
        toolchain_meta.update(cleaned_extra["toolchain"])

    basis: Dict[str, Any] = {
        "schema": ARTIFACT_MANIFEST_SCHEMA,
        "workspace_name": ws_resolved.name,
        "workspace_root_digest": sha256_digest(str(ws_resolved)),
        "files": ordered_files,
        "environment": env_meta,
        "toolchain": toolchain_meta,
        "extra_metadata": cleaned_extra,
    }
    manifest_digest = sha256_digest(basis)
    basis["manifest_digest"] = manifest_digest
    serialized = canonical_json_dumps(basis)
    assert_no_raw_secrets(serialized, context="ArtifactManifest")
    return basis


def _values_match(
    ref_val: Any,
    cand_val: Any,
    *,
    tolerance: Optional[float] = None,
    comparator: Optional[Callable[[Any, Any], bool]] = None,
) -> bool:
    if comparator is not None:
        return bool(comparator(ref_val, cand_val))

    if isinstance(ref_val, bool) or isinstance(cand_val, bool):
        return ref_val is cand_val

    if tolerance is not None:
        if isinstance(ref_val, (int, float)) and isinstance(cand_val, (int, float)):
            return math.isclose(float(ref_val), float(cand_val), rel_tol=0.0, abs_tol=tolerance)
        if isinstance(ref_val, Mapping) and isinstance(cand_val, Mapping):
            if set(ref_val.keys()) != set(cand_val.keys()):
                return False
            return all(_values_match(ref_val[k], cand_val[k], tolerance=tolerance) for k in ref_val.keys())
        if isinstance(ref_val, (list, tuple)) and isinstance(cand_val, (list, tuple)):
            if type(ref_val) is not type(cand_val) or len(ref_val) != len(cand_val):
                return False
            return all(_values_match(a, b, tolerance=tolerance) for a, b in zip(ref_val, cand_val))

    if type(ref_val) is not type(cand_val):
        return False
    if isinstance(ref_val, Mapping):
        if set(ref_val.keys()) != set(cand_val.keys()):
            return False
        return all(_values_match(ref_val[k], cand_val[k]) for k in ref_val.keys())
    if isinstance(ref_val, (list, tuple)):
        return len(ref_val) == len(cand_val) and all(_values_match(a, b) for a, b in zip(ref_val, cand_val))
    return bool(ref_val == cand_val)


def _invoke_with_signature(fn: Callable[..., Any], *available_args: Any) -> Any:
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
    positional = [
        p
        for p in params
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if has_varargs:
        return fn(*available_args)
    count = min(len(positional), len(available_args))
    return fn(*available_args[:count])


def run_differential_corpus(
    reference_fn: Callable[..., Any],
    candidate_fn: Callable[..., Any],
    corpus: Iterable[Any],
    *,
    property_checks: Optional[Sequence[Callable[..., Any]]] = None,
    seed: Union[int, str] = 0,
    tolerance: Optional[float] = None,
    exact: Optional[bool] = None,
    proof_level: Union[ProofLevel, str] = ProofLevel.DIFFERENTIAL_VERIFIED,
    comparator: Optional[Callable[[Any, Any], bool]] = None,
    unpack_args: bool = False,
    allow_matching_exceptions: bool = False,
    report_id: str = "proof-differential",
) -> ProofPackReport:
    """
    Independently execute `reference_fn` and `candidate_fn` across `corpus` (plus optional
    `property_checks`), emitting a `ProofPackReport/1`.

    Strictly rejects attempts to claim `ProofLevel.FORMALLY_PROVEN` from differential or fuzz testing.
    """
    if not callable(reference_fn) or not callable(candidate_fn):
        raise ValueError("INVALID_CALLABLE: reference_fn and candidate_fn must be callable.")

    requested_level = _coerce_proof_level(proof_level)
    if requested_level == ProofLevel.FORMALLY_PROVEN:
        raise ValueError(
            "FORMAL_PROOF_ESCALATION_REJECTED: differential/fuzz corpus verification cannot be "
            "labeled FORMALLY_PROVEN; an explicit validated formal solver proof artifact is required."
        )

    tol_val: Optional[float] = None
    if tolerance is not None:
        tol_val = float(tolerance)
        if not math.isfinite(tol_val) or tol_val < 0.0:
            raise ValueError(f"INVALID_TOLERANCE: tolerance must be finite and >= 0, got {tolerance!r}.")
    if exact is True and tol_val is not None and tol_val > 0.0:
        raise ValueError("INVALID_COMPARISON_MODE: exact=True cannot be combined with tolerance > 0.")

    cases = list(corpus)
    inputs_digest = sha256_digest([_normalize_for_digest(item) for item in cases])
    comparison_mode = "exact" if (tol_val is None and comparator is None) else "tolerant"

    if not cases:
        return ProofPackReport(
            report_id=report_id,
            status="NOT_VERIFIED",
            verified_independently=False,
            proof_levels=[],
            differential_summary={
                "total_cases": 0,
                "passed_cases": 0,
                "mismatches": 0,
                "seed": seed,
                "inputs_digest": inputs_digest,
                "comparison_mode": comparison_mode,
                "tolerance": tol_val,
                "mismatch_samples": [],
            },
            reasons=["EMPTY_DIFFERENTIAL_CORPUS"],
        )

    prop_fns = list(property_checks or ())
    for pfn in prop_fns:
        if not callable(pfn):
            raise ValueError("INVALID_PROPERTY_CHECK: every property check must be callable.")

    passed_cases = 0
    mismatches: List[Dict[str, Any]] = []
    prop_total = 0
    prop_passed = 0
    prop_failures: List[Dict[str, Any]] = []

    for idx, case in enumerate(cases):
        ref_exc: Optional[Exception] = None
        cand_exc: Optional[Exception] = None
        ref_out: Any = None
        cand_out: Any = None

        try:
            if unpack_args and isinstance(case, tuple):
                ref_out = reference_fn(*case)
            elif unpack_args and isinstance(case, Mapping):
                ref_out = reference_fn(**case)
            else:
                ref_out = reference_fn(case)
        except Exception as exc:
            ref_exc = exc

        try:
            if unpack_args and isinstance(case, tuple):
                cand_out = candidate_fn(*case)
            elif unpack_args and isinstance(case, Mapping):
                cand_out = candidate_fn(**case)
            else:
                cand_out = candidate_fn(case)
        except Exception as exc:
            cand_exc = exc

        case_matched = False
        if ref_exc is not None or cand_exc is not None:
            if allow_matching_exceptions and ref_exc is not None and cand_exc is not None and type(ref_exc) is type(cand_exc):
                case_matched = True
            else:
                mismatches.append(
                    {
                        "case_index": idx,
                        "input_digest": sha256_digest(_normalize_for_digest(case)),
                        "reference_error": f"{type(ref_exc).__name__}: {ref_exc}" if ref_exc else None,
                        "candidate_error": f"{type(cand_exc).__name__}: {cand_exc}" if cand_exc else None,
                    }
                )
        elif _values_match(ref_out, cand_out, tolerance=tol_val, comparator=comparator):
            case_matched = True
        else:
            mismatches.append(
                {
                    "case_index": idx,
                    "input_digest": sha256_digest(_normalize_for_digest(case)),
                    "reference_digest": sha256_digest(_normalize_for_digest(ref_out)),
                    "candidate_digest": sha256_digest(_normalize_for_digest(cand_out)),
                }
            )

        if case_matched:
            passed_cases += 1

        if cand_exc is None:
            for p_idx, pfn in enumerate(prop_fns):
                prop_total += 1
                prop_name = getattr(pfn, "__name__", f"property_{p_idx}")
                try:
                    ok = bool(_invoke_with_signature(pfn, case, cand_out, ref_out))
                except Exception as exc:
                    ok = False
                    prop_failures.append(
                        {"case_index": idx, "property": prop_name, "error": f"{type(exc).__name__}: {exc}"}
                    )
                else:
                    if ok:
                        prop_passed += 1
                    else:
                        prop_failures.append({"case_index": idx, "property": prop_name, "error": "PROPERTY_RETURNED_FALSE"})
        elif prop_fns:
            for p_idx, pfn in enumerate(prop_fns):
                prop_total += 1
                prop_name = getattr(pfn, "__name__", f"property_{p_idx}")
                prop_failures.append(
                    {"case_index": idx, "property": prop_name, "error": "CANDIDATE_RAISED_EXCEPTION"}
                )

    diff_ok = len(mismatches) == 0
    prop_ok = len(prop_failures) == 0
    achieved_levels: List[ProofLevel] = []
    if diff_ok:
        achieved_levels.append(ProofLevel.DIFFERENTIAL_VERIFIED)
    if prop_fns and prop_ok and prop_total > 0:
        achieved_levels.append(ProofLevel.PROPERTY_TESTED)

    reasons: List[str] = []
    if not diff_ok:
        reasons.append(f"DIFFERENTIAL_MISMATCH:{len(mismatches)}/{len(cases)}")
    if prop_fns and not prop_ok:
        reasons.append(f"PROPERTY_CHECK_FAILED:{len(prop_failures)}/{prop_total}")

    diff_summary: Dict[str, Any] = {
        "total_cases": len(cases),
        "passed_cases": passed_cases,
        "mismatches": len(mismatches),
        "seed": seed,
        "inputs_digest": inputs_digest,
        "comparison_mode": comparison_mode,
        "tolerance": tol_val,
        "mismatch_samples": mismatches[:10],
    }
    prop_summary: Optional[Dict[str, Any]] = None
    if prop_fns:
        prop_summary = {
            "total_checks": prop_total,
            "passed_checks": prop_passed,
            "failed_checks": len(prop_failures),
            "property_names": [getattr(fn, "__name__", f"property_{i}") for i, fn in enumerate(prop_fns)],
            "inputs_digest": inputs_digest,
            "failures": prop_failures[:10],
        }

    overall_status = "PASS" if (diff_ok and prop_ok) else "FAIL"
    return ProofPackReport(
        report_id=report_id,
        status=overall_status,
        verified_independently=True,
        proof_levels=achieved_levels,
        differential_summary=diff_summary,
        property_summary=prop_summary,
        reasons=reasons,
    )


def run_property_tests(
    target_fn: Callable[..., Any],
    corpus: Iterable[Any],
    property_checks: Sequence[Callable[..., Any]],
    *,
    seed: Union[int, str] = 0,
    proof_level: Union[ProofLevel, str] = ProofLevel.PROPERTY_TESTED,
    report_id: str = "proof-property",
) -> ProofPackReport:
    """Run metamorphic/boundary `property_checks` on `target_fn` over `corpus` (never claims FORMALLY_PROVEN)."""
    if not callable(target_fn):
        raise ValueError("INVALID_CALLABLE: target_fn must be callable.")
    requested = _coerce_proof_level(proof_level)
    if requested == ProofLevel.FORMALLY_PROVEN:
        raise ValueError(
            "FORMAL_PROOF_ESCALATION_REJECTED: property/fuzz testing cannot be labeled FORMALLY_PROVEN."
        )
    if requested == ProofLevel.DIFFERENTIAL_VERIFIED:
        raise ValueError(
            "INVALID_PROOF_LEVEL: run_property_tests cannot emit DIFFERENTIAL_VERIFIED without a reference oracle."
        )

    cases = list(corpus)
    prop_fns = list(property_checks or ())
    inputs_digest = sha256_digest([_normalize_for_digest(item) for item in cases])
    if not cases or not prop_fns:
        return ProofPackReport(
            report_id=report_id,
            status="NOT_VERIFIED",
            verified_independently=False,
            proof_levels=[],
            property_summary={
                "total_checks": 0,
                "passed_checks": 0,
                "failed_checks": 0,
                "seed": seed,
                "inputs_digest": inputs_digest,
                "property_names": [getattr(fn, "__name__", f"property_{i}") for i, fn in enumerate(prop_fns)],
                "failures": [],
            },
            reasons=["EMPTY_CORPUS_OR_PROPERTY_CHECKS"],
        )

    total_checks = 0
    passed_checks = 0
    failures: List[Dict[str, Any]] = []
    for idx, case in enumerate(cases):
        try:
            out = target_fn(case)
        except Exception as exc:
            for p_idx, pfn in enumerate(prop_fns):
                total_checks += 1
                failures.append(
                    {
                        "case_index": idx,
                        "property": getattr(pfn, "__name__", f"property_{p_idx}"),
                        "error": f"TARGET_EXCEPTION:{type(exc).__name__}:{exc}",
                    }
                )
            continue

        for p_idx, pfn in enumerate(prop_fns):
            total_checks += 1
            prop_name = getattr(pfn, "__name__", f"property_{p_idx}")
            try:
                ok = bool(_invoke_with_signature(pfn, case, out))
            except Exception as exc:
                failures.append(
                    {"case_index": idx, "property": prop_name, "error": f"{type(exc).__name__}: {exc}"}
                )
            else:
                if ok:
                    passed_checks += 1
                else:
                    failures.append({"case_index": idx, "property": prop_name, "error": "PROPERTY_RETURNED_FALSE"})

    prop_ok = len(failures) == 0
    return ProofPackReport(
        report_id=report_id,
        status="PASS" if prop_ok else "FAIL",
        verified_independently=True,
        proof_levels=[ProofLevel.PROPERTY_TESTED] if prop_ok else [],
        property_summary={
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": len(failures),
            "seed": seed,
            "inputs_digest": inputs_digest,
            "property_names": [getattr(fn, "__name__", f"property_{i}") for i, fn in enumerate(prop_fns)],
            "failures": failures[:10],
        },
        reasons=[] if prop_ok else [f"PROPERTY_CHECK_FAILED:{len(failures)}/{total_checks}"],
    )


def verify_formal_proof(
    formal_proof: Union[FormalProofArtifact, Mapping[str, Any]],
    *,
    report_id: str = "proof-formal",
) -> ProofPackReport:
    """Validate an explicit formal solver proof artifact and emit a `FORMALLY_PROVEN` report."""
    validated = validate_formal_proof_artifact(formal_proof)
    return ProofPackReport(
        report_id=report_id,
        status="PASS",
        verified_independently=True,
        proof_levels=[ProofLevel.FORMALLY_PROVEN],
        formal_proof=validated,
    )


def _canonicalize_repro_item(item: Any) -> Tuple[str, Dict[str, Any], Optional[str]]:
    raw = item.to_dict() if hasattr(item, "to_dict") and callable(item.to_dict) else dict(item)
    schema = str(raw.get("schema") or "GenericArtifact")

    if schema == ARTIFACT_MANIFEST_SCHEMA:
        declared = raw.get("manifest_digest")
        basis = {
            "schema": raw.get("schema"),
            "workspace_name": raw.get("workspace_name"),
            "workspace_root_digest": raw.get("workspace_root_digest"),
            "files": raw.get("files"),
            "environment": raw.get("environment"),
            "toolchain": raw.get("toolchain"),
            "extra_metadata": raw.get("extra_metadata", {}),
        }
        expected = sha256_digest(basis)
        if declared and not hmac.compare_digest(str(declared).lower(), expected.lower()):
            return schema, {}, "MANIFEST_DIGEST_TAMPERED"
        return schema, {"files": raw.get("files"), "manifest_digest": expected}, None

    if schema == "ExecutionReceipt/1":
        if str(raw.get("status", "")).upper() == "NOT_VERIFIED":
            return schema, {}, "UNVERIFIED_EXECUTION_RECEIPT"
        return (
            schema,
            {
                "plan_hash": raw.get("plan_hash"),
                "tool_hash": raw.get("tool_hash"),
                "policy_hash": raw.get("policy_hash"),
                "environment_hash": raw.get("environment_hash"),
                "exit_status": raw.get("exit_status"),
                "status": raw.get("status"),
                "artifact_digests": raw.get("artifact_digests"),
            },
            None,
        )

    if schema == "CompositionReceipt/1":
        if str(raw.get("status", "")).upper() == "NOT_VERIFIED":
            return schema, {}, "UNVERIFIED_COMPOSITION_RECEIPT"
        return (
            schema,
            {
                "plan_hash": raw.get("plan_hash"),
                "policy_hash": raw.get("policy_hash"),
                "sandbox_environment_hash": raw.get("sandbox_environment_hash"),
                "input_digest": raw.get("input_digest"),
                "output_digest": raw.get("output_digest"),
                "status": raw.get("status"),
                "verification_status": raw.get("verification_status"),
            },
            None,
        )

    if schema == "ToolBuild/1":
        return (
            schema,
            {
                "tool_id": raw.get("tool_id"),
                "tool_version": raw.get("tool_version"),
                "source_hash": raw.get("source_hash"),
                "oracle_hash": raw.get("oracle_hash"),
                "artifact_hash": raw.get("artifact_hash"),
                "compiler": raw.get("compiler"),
                "compiler_version": raw.get("compiler_version"),
                "flags": raw.get("flags"),
                "state": raw.get("state"),
            },
            None,
        )

    filtered = {k: v for k, v in raw.items() if k not in _EPHEMERAL_REPRO_KEYS}
    return schema, filtered, None


def verify_reproducibility(
    receipts_or_manifests: Sequence[Any],
    *,
    report_id: str = "proof-reproducibility",
) -> ProofPackReport:
    """
    Verify deterministic build/execution reproducibility across >= 2 independent manifests
    or execution receipts (comparing artifact hashes and content digests while ignoring ephemeral IDs/timings).
    """
    items = list(receipts_or_manifests or ())
    if len(items) < 2:
        return ProofPackReport(
            report_id=report_id,
            status="NOT_VERIFIED",
            verified_independently=False,
            proof_levels=[],
            reproducibility_summary={
                "reproducible": False,
                "checked_count": len(items),
                "fingerprint_digests": [],
            },
            reasons=["REPRODUCIBILITY_REQUIRES_AT_LEAST_2_ARTIFACTS"],
        )

    schemas: List[str] = []
    fingerprints: List[str] = []
    norm_records: List[Dict[str, Any]] = []
    reasons: List[str] = []

    for idx, item in enumerate(items):
        if not isinstance(item, Mapping) and not (hasattr(item, "to_dict") and callable(item.to_dict)):
            reasons.append(f"INVALID_REPRODUCIBILITY_ITEM:idx={idx}")
            continue
        schema_name, canonical_payload, err = _canonicalize_repro_item(item)
        if err is not None:
            reasons.append(f"{err}:idx={idx}")
            continue
        schemas.append(schema_name)
        norm_records.append(canonical_payload)
        fingerprints.append(sha256_digest(_normalize_for_digest(canonical_payload)))

    if not reasons and len(set(schemas)) > 1:
        reasons.append(f"REPRODUCIBILITY_SCHEMA_MISMATCH:{','.join(sorted(set(schemas)))}")

    if not reasons and len(set(fingerprints)) > 1:
        baseline = norm_records[0]
        diff_keys: List[str] = []
        for idx, rec in enumerate(norm_records[1:], start=1):
            all_keys = sorted(set(baseline.keys()) | set(rec.keys()))
            for k in all_keys:
                if baseline.get(k) != rec.get(k):
                    diff_keys.append(f"run[{idx}].{k}")
        reasons.append(f"REPRODUCIBILITY_DIGEST_MISMATCH:{','.join(diff_keys[:10])}")

    reproducible = len(reasons) == 0 and len(fingerprints) >= 2 and len(set(fingerprints)) == 1
    return ProofPackReport(
        report_id=report_id,
        status="PASS" if reproducible else "FAIL",
        verified_independently=True,
        proof_levels=[],
        reproducibility_summary={
            "reproducible": reproducible,
            "checked_count": len(items),
            "schema": schemas[0] if len(set(schemas)) == 1 and schemas else "mixed",
            "fingerprint_digests": fingerprints,
            "canonical_digest": fingerprints[0] if reproducible else "",
        },
        reasons=reasons,
    )


def _generate_default_logforge_corpus(seed: int, num_cases: int) -> List[Tuple[bytes, int]]:
    rng = random.Random(seed)
    cases: List[Tuple[bytes, int]] = [
        (b"", ord("\n")),
        (b"\n", ord("\n")),
        (b"a" * 15 + b"\n" + b"b" * 16 + b"\n" + b"c" * 33, ord("\n")),
        (b"\x00\xff" * 32 + b"\n" + "Tiếng Việt 🚀\n".encode("utf-8"), ord("\n")),
        (b"k=1|k=2||k=3|", ord("|")),
    ]
    for idx in range(max(0, num_cases - len(cases))):
        length = rng.randint(0, 260) if idx % 2 == 0 else rng.randint(261, 1024)
        delim = rng.choice([0x0A, 0x00, 0x7C, 0xFF, rng.randint(0, 255)])
        buf = bytes(rng.getrandbits(8) for _ in range(length))
        cases.append((buf, delim))
    return cases


def check_python_rust_parity(
    python_fn: Optional[Callable[..., Any]] = None,
    rust_fn: Optional[Callable[..., Any]] = None,
    corpus: Optional[Iterable[Any]] = None,
    *,
    rust_bin: Optional[Union[str, Path]] = None,
    seed: int = 20261121,
    num_cases: int = 32,
    disable_simd_check: bool = True,
    normalize: bool = False,
    tolerance: Optional[float] = None,
    exact: Optional[bool] = None,
    report_id: str = "proof-python-rust-parity",
) -> ProofPackReport:
    """
    Verify exact parity between Python reference logic and Rust implementation.

    Supports either:
      1. Custom `(python_fn, rust_fn, corpus)` callables; or
      2. Default LogForge parity against the compiled `kintsugi-rs` binary (`scan-bytes` SIMD & scalar).
    """
    if (python_fn is None) != (rust_fn is None):
        raise ValueError("INVALID_PARITY_ARGS: supply both python_fn and rust_fn, or neither for built-in kintsugi-rs parity.")

    if python_fn is not None and rust_fn is not None:
        if corpus is None:
            raise ValueError("MISSING_CORPUS: corpus is required when python_fn and rust_fn are supplied.")
        diff_report = run_differential_corpus(
            python_fn,
            rust_fn,
            corpus,
            seed=seed,
            tolerance=tolerance,
            exact=exact,
            report_id=report_id,
        )
        summary = dict(diff_report.differential_summary or {})
        parity_summary = {
            "mode": "custom_callables",
            "parity_ok": diff_report.status == "PASS",
            "checked_cases": summary.get("total_cases", 0),
            "mismatches": summary.get("mismatches", 0),
            "inputs_digest": summary.get("inputs_digest", ""),
            "seed": seed,
        }
        return ProofPackReport(
            report_id=report_id,
            status=diff_report.status,
            verified_independently=diff_report.verified_independently,
            proof_levels=list(diff_report.proof_levels),
            differential_summary=diff_report.differential_summary,
            parity_summary=parity_summary,
            reasons=list(diff_report.reasons),
        )

    bridge = LogForgeNativeBridge(rust_bin=rust_bin)
    if not bridge.available() or bridge.rust_bin is None:
        return ProofPackReport(
            report_id=report_id,
            status="NOT_VERIFIED",
            verified_independently=False,
            proof_levels=[],
            parity_summary={"mode": "kintsugi_rs_scan_bytes", "parity_ok": False, "checked_cases": 0},
            reasons=["RUST_BINARY_UNAVAILABLE"],
        )

    assert_not_symlink(bridge.rust_bin)
    _, bin_entry = _confine_and_hash_regular_file(
        bridge.rust_bin,
        bridge.rust_bin.parent,
        bridge.rust_bin.parent.resolve(),
    )

    raw_corpus = list(corpus) if corpus is not None else _generate_default_logforge_corpus(seed, num_cases)
    norm_cases: List[Tuple[bytes, int]] = []
    for item in raw_corpus:
        if isinstance(item, tuple) and len(item) == 2:
            norm_cases.append((bytes(item[0]), int(item[1])))
        elif isinstance(item, (bytes, bytearray, memoryview)):
            norm_cases.append((bytes(item), 0x0A))
        else:
            raise ValueError(f"INVALID_PARITY_CORPUS_ITEM: expected bytes or (bytes, delim), got {type(item).__name__}.")

    def _py_oracle(case: Tuple[bytes, int]) -> Dict[str, Any]:
        buf, delim = case
        out: Dict[str, Any] = {"offsets": scan_delimiters_python(buf, delim)}
        if normalize:
            out["events"] = [ev.to_dict() for ev in normalize_log_records_python(buf, delim)]
        return out

    def _rust_candidate(case: Tuple[bytes, int]) -> Dict[str, Any]:
        buf, delim = case
        res_simd = bridge.scan_bytes(buf, delim=delim, disable_simd=False, normalize=normalize)
        if disable_simd_check:
            res_scalar = bridge.scan_bytes(buf, delim=delim, disable_simd=True, normalize=normalize)
            if res_simd.offsets != res_scalar.offsets:
                raise RuntimeError("RUST_SIMD_VS_SCALAR_DIVERGENCE")
            if normalize and (
                [e.to_dict() for e in (res_simd.events or [])]
                != [e.to_dict() for e in (res_scalar.events or [])]
            ):
                raise RuntimeError("RUST_SIMD_VS_SCALAR_EVENT_DIVERGENCE")
        out: Dict[str, Any] = {"offsets": res_simd.offsets}
        if normalize:
            out["events"] = [e.to_dict() for e in (res_simd.events or [])]
        return out

    diff_report = run_differential_corpus(
        _py_oracle,
        _rust_candidate,
        norm_cases,
        seed=seed,
        exact=True,
        report_id=report_id,
    )
    summary = dict(diff_report.differential_summary or {})
    parity_summary = {
        "mode": "kintsugi_rs_scan_bytes",
        "rust_bin_sha256": bin_entry["sha256"],
        "backends_checked": ["rust_simd", "rust_scalar_fallback"] if disable_simd_check else ["rust_simd"],
        "normalize": normalize,
        "parity_ok": diff_report.status == "PASS",
        "checked_cases": summary.get("total_cases", 0),
        "mismatches": summary.get("mismatches", 0),
        "inputs_digest": summary.get("inputs_digest", ""),
        "seed": seed,
    }
    return ProofPackReport(
        report_id=report_id,
        status=diff_report.status,
        verified_independently=diff_report.verified_independently,
        proof_levels=list(diff_report.proof_levels),
        differential_summary=diff_report.differential_summary,
        parity_summary=parity_summary,
        reasons=list(diff_report.reasons),
    )


class ProofPack:
    """Working Tool #5: Independent verification & evidence packager (`ProofPackReport/1`)."""

    @staticmethod
    def build_artifact_manifest(
        files: Iterable[Union[str, Path]],
        workspace_root: Union[str, Path],
        extra_metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return build_artifact_manifest(files, workspace_root, extra_metadata=extra_metadata)

    @staticmethod
    def run_differential_corpus(
        reference_fn: Callable[..., Any],
        candidate_fn: Callable[..., Any],
        corpus: Iterable[Any],
        *,
        property_checks: Optional[Sequence[Callable[..., Any]]] = None,
        seed: Union[int, str] = 0,
        tolerance: Optional[float] = None,
        exact: Optional[bool] = None,
        proof_level: Union[ProofLevel, str] = ProofLevel.DIFFERENTIAL_VERIFIED,
        comparator: Optional[Callable[[Any, Any], bool]] = None,
        unpack_args: bool = False,
        allow_matching_exceptions: bool = False,
        report_id: str = "proof-differential",
    ) -> ProofPackReport:
        return run_differential_corpus(
            reference_fn,
            candidate_fn,
            corpus,
            property_checks=property_checks,
            seed=seed,
            tolerance=tolerance,
            exact=exact,
            proof_level=proof_level,
            comparator=comparator,
            unpack_args=unpack_args,
            allow_matching_exceptions=allow_matching_exceptions,
            report_id=report_id,
        )

    @staticmethod
    def run_property_tests(
        target_fn: Callable[..., Any],
        corpus: Iterable[Any],
        property_checks: Sequence[Callable[..., Any]],
        *,
        seed: Union[int, str] = 0,
        proof_level: Union[ProofLevel, str] = ProofLevel.PROPERTY_TESTED,
        report_id: str = "proof-property",
    ) -> ProofPackReport:
        return run_property_tests(
            target_fn,
            corpus,
            property_checks,
            seed=seed,
            proof_level=proof_level,
            report_id=report_id,
        )

    @staticmethod
    def verify_formal_proof(
        formal_proof: Union[FormalProofArtifact, Mapping[str, Any]],
        *,
        report_id: str = "proof-formal",
    ) -> ProofPackReport:
        return verify_formal_proof(formal_proof, report_id=report_id)

    @staticmethod
    def verify_reproducibility(
        receipts_or_manifests: Sequence[Any],
        *,
        report_id: str = "proof-reproducibility",
    ) -> ProofPackReport:
        return verify_reproducibility(receipts_or_manifests, report_id=report_id)

    @staticmethod
    def check_python_rust_parity(
        python_fn: Optional[Callable[..., Any]] = None,
        rust_fn: Optional[Callable[..., Any]] = None,
        corpus: Optional[Iterable[Any]] = None,
        *,
        rust_bin: Optional[Union[str, Path]] = None,
        seed: int = 20261121,
        num_cases: int = 32,
        disable_simd_check: bool = True,
        normalize: bool = False,
        tolerance: Optional[float] = None,
        exact: Optional[bool] = None,
        report_id: str = "proof-python-rust-parity",
    ) -> ProofPackReport:
        return check_python_rust_parity(
            python_fn=python_fn,
            rust_fn=rust_fn,
            corpus=corpus,
            rust_bin=rust_bin,
            seed=seed,
            num_cases=num_cases,
            disable_simd_check=disable_simd_check,
            normalize=normalize,
            tolerance=tolerance,
            exact=exact,
            report_id=report_id,
        )


__all__ = [
    "ARTIFACT_MANIFEST_SCHEMA",
    "FORMAL_PROOF_ARTIFACT_SCHEMA",
    "PROOF_PACK_REPORT_SCHEMA",
    "VALID_PROOF_STATUSES",
    "FormalProofArtifact",
    "ProofLevel",
    "ProofPack",
    "ProofPackReport",
    "build_artifact_manifest",
    "check_python_rust_parity",
    "run_differential_corpus",
    "run_property_tests",
    "validate_formal_proof_artifact",
    "verify_formal_proof",
    "verify_reproducibility",
]
