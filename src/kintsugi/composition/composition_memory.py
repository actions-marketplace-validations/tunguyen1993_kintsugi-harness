"""Gate G4 Provenance-Bound Composition Memory (`kintsugi.composition.composition_memory`).

Persists verified `CompositionPlan/1` DAG plans to `.kintsugi/composition_memory.json`
using symlink rejection (`assert_not_symlink`), atomic `0o600` writes (`atomic_write_json`),
and fail-closed secret/injection scanning (`assert_no_raw_secrets`, `scan_artifact_egress`).

Strict Gate G4 Cache Invalidation:
  NEVER returns a cached `PASS` plan solely on matching `tool_id` or `task_signature`.
  Every `retrieve(...)` verifies the full provenance fingerprint across:
    1. `tool_artifact_hashes` (all plan tools)
    2. `adapter_hashes` (all plan adapters)
    3. `schema_hashes` (all bound port/IO schemas)
    4. `policy_hash` (`SecurityContext.policy_hash`)
    5. `oracle_ref` (and optional `oracle_hash`)
    6. `runtime_version` (runtime semantics version)
    7. Active non-retired status (`retired_tool_ids`) & non-revoked attestations
"""

from __future__ import annotations

import copy
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union

from kintsugi.capability.contracts_v2 import CompositionPlan, CompositionReceipt
from kintsugi.capability.schemas import (
    CapabilityGap,
    ExecutionStatus,
    SecurityContext,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    has_valid_verification_attestation,
    normalize_sha256,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.config import SECURITY_BASELINE_VALUES
from kintsugi.runtime.secure_runner import redact_runtime_text, redact_runtime_value
from kintsugi.shield import (
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    atomic_write_json,
    resolve_safe_child_path,
    scan_artifact_egress,
)

DEFAULT_COMPOSITION_MEMORY_REL_PATH = ".kintsugi/composition_memory.json"
COMPOSITION_MEMORY_SCHEMA = "CompositionMemory/1"
CACHE_STATUS_HIT = "CACHE_HIT"
CACHE_STATUS_INVALIDATED = "CACHE_INVALIDATED"
CACHE_STATUS_MISS = "CACHE_MISS"

_FORBIDDEN_METADATA_KEYS: FrozenSet[str] = frozenset(
    {
        "security_context",
        "allowed_permissions",
        "network_allowed",
        "allow_untrusted_native",
        "policy_override",
        "disable_guardrails",
        "skip_verification",
        "bypass_scars",
        "env_override",
        "elevate_privileges",
        *SECURITY_BASELINE_VALUES.keys(),
    }
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_hygiene(obj: Any, *, path: str = "root") -> None:
    if isinstance(obj, str):
        if "\x00" in obj or TROJAN_UNICODE_RE.search(obj):
            raise ValueError(f"COMPOSITION_MEMORY_TROJAN_UNICODE_BLOCKED at {path}")
        if PROMPT_INJECTION_RE.search(obj):
            raise ValueError(f"COMPOSITION_MEMORY_PROMPT_INJECTION_BLOCKED at {path}")
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            key_norm = str(k).strip().lower()
            if key_norm in _FORBIDDEN_METADATA_KEYS:
                raise ValueError(f"COMPOSITION_MEMORY_POLICY_MUTATION_BLOCKED: '{key_norm}' at {path}")
            _check_hygiene(str(k), path=f"{path}.{key_norm}")
            _check_hygiene(v, path=f"{path}.{key_norm}")
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            _check_hygiene(item, path=f"{path}[{idx}]")


def _normalize_hash_map(
    raw: Optional[Mapping[str, str]],
    *,
    field_name: str,
    validate_ids_as_tools: bool = True,
) -> Dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ValueError(f"INVALID_{field_name.upper()}: expected mapping.")
    normalized: Dict[str, str] = {}
    for k, v in sorted(raw.items(), key=lambda kv: str(kv[0])):
        clean_k = validate_tool_id(str(k)) if validate_ids_as_tools else validate_safe_text(str(k), field_name=field_name)
        normalized[clean_k] = normalize_sha256(str(v), field_name=field_name)
    return normalized


def derive_task_signature(
    goal_contract: Union[CapabilityGap, Mapping[str, Any], str],
) -> str:
    """Derive a deterministic `task_signature` from a `CapabilityGap` or goal mapping."""
    if isinstance(goal_contract, str):
        return validate_safe_text(goal_contract, field_name="task_signature")
    if isinstance(goal_contract, CapabilityGap):
        basis = {
            "required_capabilities": sorted(goal_contract.required_capabilities),
            "input_artifacts": goal_contract.input_artifacts,
            "expected_outputs": goal_contract.expected_outputs,
            "budget": goal_contract.budget,
        }
        return sha256_digest(basis)
    if isinstance(goal_contract, Mapping):
        if "task_signature" in goal_contract and str(goal_contract["task_signature"]).strip():
            return validate_safe_text(str(goal_contract["task_signature"]), field_name="task_signature")
        basis = {
            "required_capabilities": sorted(str(c) for c in (goal_contract.get("required_capabilities") or [])),
            "input_artifacts": list(goal_contract.get("input_artifacts") or []),
            "expected_outputs": list(goal_contract.get("expected_outputs") or []),
            "budget": dict(goal_contract.get("budget") or {}),
        }
        if not basis["required_capabilities"] and goal_contract.get("goal_id"):
            basis["goal_id"] = str(goal_contract["goal_id"])
        return sha256_digest(basis)
    raise ValueError("INVALID_GOAL_CONTRACT: expected CapabilityGap, mapping, or str.")


@dataclass
class CompositionProvenance:
    """Full cryptographic provenance fingerprint for Gate G4 cache safety."""

    tool_artifact_hashes: Dict[str, str]
    adapter_hashes: Dict[str, str]
    schema_hashes: Dict[str, str]
    policy_hash: str
    oracle_ref: str
    runtime_version: str
    plan_hash: str
    oracle_hash: Optional[str] = None
    tool_attestation_digests: Dict[str, str] = field(default_factory=dict)
    adapter_attestation_digests: Dict[str, str] = field(default_factory=dict)
    provenance_fingerprint: str = ""

    def __post_init__(self) -> None:
        self.tool_artifact_hashes = _normalize_hash_map(
            self.tool_artifact_hashes, field_name="tool_artifact_hashes", validate_ids_as_tools=True
        )
        self.adapter_hashes = _normalize_hash_map(
            self.adapter_hashes, field_name="adapter_hashes", validate_ids_as_tools=True
        )
        self.schema_hashes = _normalize_hash_map(
            self.schema_hashes, field_name="schema_hashes", validate_ids_as_tools=False
        )
        self.policy_hash = normalize_sha256(self.policy_hash, field_name="policy_hash")
        self.oracle_ref = redact_runtime_text(validate_safe_text(self.oracle_ref, field_name="oracle_ref"))
        self.runtime_version = redact_runtime_text(
            validate_safe_text(self.runtime_version, field_name="runtime_version")
        )
        self.plan_hash = normalize_sha256(self.plan_hash, field_name="plan_hash")
        if self.oracle_hash:
            self.oracle_hash = normalize_sha256(self.oracle_hash, field_name="oracle_hash")
        else:
            self.oracle_hash = None
        self.tool_attestation_digests = _normalize_hash_map(
            self.tool_attestation_digests, field_name="tool_attestation_digests", validate_ids_as_tools=True
        )
        self.adapter_attestation_digests = _normalize_hash_map(
            self.adapter_attestation_digests, field_name="adapter_attestation_digests", validate_ids_as_tools=True
        )

        computed = self.compute_fingerprint()
        if self.provenance_fingerprint:
            provided = normalize_sha256(self.provenance_fingerprint, field_name="provenance_fingerprint")
            if not hmac.compare_digest(provided, computed):
                raise ValueError("PROVENANCE_FINGERPRINT_MISMATCH: fingerprint does not match provenance fields.")
            self.provenance_fingerprint = provided
        else:
            self.provenance_fingerprint = computed

    def compute_fingerprint(self) -> str:
        basis: Dict[str, Any] = {
            "tool_artifact_hashes": dict(self.tool_artifact_hashes),
            "adapter_hashes": dict(self.adapter_hashes),
            "schema_hashes": dict(self.schema_hashes),
            "policy_hash": self.policy_hash,
            "oracle_ref": self.oracle_ref,
            "runtime_version": self.runtime_version,
            "plan_hash": self.plan_hash,
        }
        if self.oracle_hash is not None:
            basis["oracle_hash"] = self.oracle_hash
        if self.tool_attestation_digests:
            basis["tool_attestation_digests"] = dict(self.tool_attestation_digests)
        if self.adapter_attestation_digests:
            basis["adapter_attestation_digests"] = dict(self.adapter_attestation_digests)
        return sha256_digest(basis)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "tool_artifact_hashes": dict(self.tool_artifact_hashes),
            "adapter_hashes": dict(self.adapter_hashes),
            "schema_hashes": dict(self.schema_hashes),
            "policy_hash": self.policy_hash,
            "oracle_ref": self.oracle_ref,
            "runtime_version": self.runtime_version,
            "plan_hash": self.plan_hash,
            "provenance_fingerprint": self.provenance_fingerprint,
        }
        if self.oracle_hash is not None:
            payload["oracle_hash"] = self.oracle_hash
        if self.tool_attestation_digests:
            payload["tool_attestation_digests"] = dict(self.tool_attestation_digests)
        if self.adapter_attestation_digests:
            payload["adapter_attestation_digests"] = dict(self.adapter_attestation_digests)
        return redact_runtime_value(payload)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompositionProvenance":
        if isinstance(data, CompositionProvenance):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_COMPOSITION_PROVENANCE: expected mapping.")
        return cls(
            tool_artifact_hashes=dict(data.get("tool_artifact_hashes") or {}),
            adapter_hashes=dict(data.get("adapter_hashes") or {}),
            schema_hashes=dict(data.get("schema_hashes") or {}),
            policy_hash=data["policy_hash"],
            oracle_ref=data["oracle_ref"],
            runtime_version=data["runtime_version"],
            plan_hash=data["plan_hash"],
            oracle_hash=data.get("oracle_hash"),
            tool_attestation_digests=dict(data.get("tool_attestation_digests") or {}),
            adapter_attestation_digests=dict(data.get("adapter_attestation_digests") or {}),
            provenance_fingerprint=data.get("provenance_fingerprint", ""),
        )


@dataclass
class CompositionMemoryEntry:
    """Persisted verified composite plan paired with its provenance fingerprint."""

    task_signature: str
    goal_contract_hash: str
    plan: CompositionPlan
    provenance: CompositionProvenance
    verification_status: str = "PASS"
    receipt_digest: str = ""
    attestation_revoked: bool = False
    revocation_reason: str = ""
    reuse_count: int = 0
    created_at: str = field(default_factory=_utc_now_iso)
    last_verified_at: str = field(default_factory=_utc_now_iso)

    def __post_init__(self) -> None:
        self.task_signature = redact_runtime_text(validate_safe_text(self.task_signature, field_name="task_signature"))
        self.goal_contract_hash = normalize_sha256(self.goal_contract_hash, field_name="goal_contract_hash")
        self.plan = CompositionPlan.from_dict(self.plan)
        self.provenance = CompositionProvenance.from_dict(self.provenance)
        self.verification_status = validate_safe_text(self.verification_status, field_name="verification_status").upper()
        if self.verification_status not in {"PASS", "VERIFIED"}:
            raise ValueError(
                f"UNVERIFIED_COMPOSITION_ENTRY: only PASS/VERIFIED compositions may be cached (got {self.verification_status})."
            )
        if not hmac.compare_digest(self.plan.plan_hash, self.provenance.plan_hash):
            raise ValueError("PLAN_PROVENANCE_HASH_MISMATCH: plan.plan_hash != provenance.plan_hash.")
        if self.receipt_digest:
            self.receipt_digest = normalize_sha256(self.receipt_digest, field_name="receipt_digest")
        self.attestation_revoked = bool(self.attestation_revoked)
        self.revocation_reason = redact_runtime_text(self.revocation_reason)
        self.reuse_count = max(0, int(self.reuse_count))
        self.created_at = validate_safe_text(self.created_at, field_name="created_at")
        self.last_verified_at = validate_safe_text(self.last_verified_at, field_name="last_verified_at")

    @property
    def entry_key(self) -> str:
        return sha256_digest(
            {
                "task_signature": self.task_signature,
                "goal_contract_hash": self.goal_contract_hash,
                "provenance_fingerprint": self.provenance.provenance_fingerprint,
            }
        ).split(":", 1)[1]

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(
            {
                "task_signature": self.task_signature,
                "goal_contract_hash": self.goal_contract_hash,
                "plan": self.plan.to_dict(),
                "provenance": self.provenance.to_dict(),
                "verification_status": self.verification_status,
                "receipt_digest": self.receipt_digest,
                "attestation_revoked": self.attestation_revoked,
                "revocation_reason": self.revocation_reason,
                "reuse_count": self.reuse_count,
                "created_at": self.created_at,
                "last_verified_at": self.last_verified_at,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CompositionMemoryEntry":
        if isinstance(data, CompositionMemoryEntry):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_MEMORY_ENTRY: expected mapping.")
        return cls(
            task_signature=data["task_signature"],
            goal_contract_hash=data["goal_contract_hash"],
            plan=data["plan"],
            provenance=data["provenance"],
            verification_status=data.get("verification_status", "PASS"),
            receipt_digest=data.get("receipt_digest", ""),
            attestation_revoked=bool(data.get("attestation_revoked", False)),
            revocation_reason=str(data.get("revocation_reason", "")),
            reuse_count=int(data.get("reuse_count", 0)),
            created_at=data.get("created_at") or _utc_now_iso(),
            last_verified_at=data.get("last_verified_at") or _utc_now_iso(),
        )


@dataclass
class CompositionCacheLookup:
    """Structured Gate G4 cache retrieval verdict (`CACHE_HIT` | `CACHE_INVALIDATED` | `CACHE_MISS`)."""

    status: str
    hit: bool
    plan: Optional[CompositionPlan] = None
    entry: Optional[CompositionMemoryEntry] = None
    reasons: List[str] = field(default_factory=list)
    task_signature: str = ""
    provenance_fingerprint: str = ""
    checked_entries: int = 0
    llm_calls: int = 0

    def __bool__(self) -> bool:
        return self.hit

    @property
    def invalidation_reasons(self) -> List[str]:
        return list(self.reasons)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "hit": self.hit,
            "plan": self.plan.to_dict() if self.plan is not None else None,
            "provenance_fingerprint": self.provenance_fingerprint,
            "reasons": list(self.reasons),
            "task_signature": self.task_signature,
            "checked_entries": self.checked_entries,
            "llm_calls": self.llm_calls,
        }


def _check_dict_hashes(
    expected_map: Mapping[str, str],
    current_map: Optional[Mapping[str, str]],
    *,
    missing_prov_code: str,
    missing_item_prefix: str,
    changed_prefix: str,
    require_present: bool,
) -> List[str]:
    reasons: List[str] = []
    if not expected_map:
        return reasons
    if current_map is None:
        if require_present:
            reasons.append(missing_prov_code)
        return reasons
    norm_current: Dict[str, str] = {}
    for k, v in current_map.items():
        try:
            norm_current[str(k).strip()] = normalize_sha256(str(v), field_name=missing_prov_code)
        except ValueError:
            norm_current[str(k).strip()] = ""
    for item_id, expected_h in expected_map.items():
        cur_h = norm_current.get(item_id, "")
        if not cur_h:
            reasons.append(f"{missing_item_prefix}:{item_id}")
        elif not hmac.compare_digest(cur_h, expected_h):
            reasons.append(f"{changed_prefix}:{item_id}")
    return reasons


class CompositionMemory:
    """Symlink-safe, redacted, Gate G4 provenance-checked cache at `.kintsugi/composition_memory.json`."""

    SCHEMA_VERSION = COMPOSITION_MEMORY_SCHEMA

    def __init__(
        self,
        path: Union[Path, str] = DEFAULT_COMPOSITION_MEMORY_REL_PATH,
        *,
        workspace_root: Optional[Union[Path, str]] = None,
    ) -> None:
        raw_path = Path(path)
        if workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            ws_resolved = ws.resolve()
            if not raw_path.is_absolute():
                confined = resolve_safe_child_path(ws_resolved, str(raw_path))
                if confined is None:
                    raise PermissionError("COMPOSITION_MEMORY_PATH_OUTSIDE_WORKSPACE")
                self.path = confined
            else:
                try:
                    raw_path.resolve().relative_to(ws_resolved)
                except ValueError as exc:
                    raise PermissionError("COMPOSITION_MEMORY_PATH_OUTSIDE_WORKSPACE") from exc
                self.path = raw_path
        else:
            self.path = raw_path

        self._entries: Dict[str, CompositionMemoryEntry] = {}
        self.quarantined: List[Tuple[str, str]] = []
        self.last_invalidation_reasons: List[str] = []
        self._assert_store_paths_not_symlink()
        if self.path.exists():
            self.load()

    def _assert_store_paths_not_symlink(self) -> None:
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)

    def load(self) -> None:
        """Load persisted composite plans safely with `assert_not_symlink` and `O_NOFOLLOW`."""
        self._assert_store_paths_not_symlink()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise PermissionError(f"COMPOSITION_MEMORY_OPEN_REFUSED: {exc}") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError("COMPOSITION_MEMORY_NOT_REGULAR_FILE")
            raw = json.load(handle)

        if not isinstance(raw, Mapping):
            raise ValueError("COMPOSITION_MEMORY_CORRUPT_ROOT")
        raw_entries = raw.get("entries", [])
        if not isinstance(raw_entries, list):
            raise ValueError("COMPOSITION_MEMORY_CORRUPT_ENTRIES")

        self._entries.clear()
        self.quarantined.clear()
        for idx, item in enumerate(raw_entries):
            try:
                _check_hygiene(item, path=f"entries[{idx}]")
                serialized_item = canonical_json_dumps(item)
                assert_no_raw_secrets(serialized_item, context=f"CompositionMemory.load[{idx}]")
                egress = scan_artifact_egress(serialized_item, context="composition_memory_load")
                if not egress.get("ok"):
                    raise ValueError("COMPOSITION_MEMORY_SECRET_LEAK_BLOCKED")
                entry = CompositionMemoryEntry.from_dict(item)
                self._entries[entry.entry_key] = entry
            except (ValueError, KeyError, TypeError) as exc:
                label = (
                    str(item.get("task_signature", f"idx_{idx}"))
                    if isinstance(item, Mapping)
                    else f"idx_{idx}"
                )
                self.quarantined.append((label, str(exc)))

    def save(self) -> None:
        """Persist composition memory atomically with mode `0o600` after secret checks."""
        self._assert_store_paths_not_symlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(
            self._entries.values(),
            key=lambda e: (e.task_signature, e.plan.plan_id, e.provenance.provenance_fingerprint),
        )
        payload = {
            "schema": self.SCHEMA_VERSION,
            "total_entries": len(ordered),
            "entries": [e.to_dict() for e in ordered],
        }
        serialized = canonical_json_dumps(payload)
        assert_no_raw_secrets(serialized, context="CompositionMemory.save")
        egress = scan_artifact_egress(serialized, context="composition_memory_save")
        if not egress.get("ok"):
            raise ValueError("COMPOSITION_MEMORY_RESIDUAL_SECRET_BLOCKED")
        atomic_write_json(self.path, payload, mode=0o600, indent=2)

    def store(
        self,
        plan: Union[CompositionPlan, Mapping[str, Any]],
        *,
        task_signature: Optional[str] = None,
        goal_contract: Optional[Union[CapabilityGap, Mapping[str, Any]]] = None,
        receipt: Optional[Union[CompositionReceipt, Mapping[str, Any]]] = None,
        tool_artifact_hashes: Optional[Mapping[str, str]] = None,
        adapter_hashes: Optional[Mapping[str, str]] = None,
        schema_hashes: Optional[Mapping[str, str]] = None,
        schema_hash: Optional[str] = None,
        policy_hash: Optional[str] = None,
        oracle_ref: Optional[str] = None,
        oracle_hash: Optional[str] = None,
        runtime_version: str = "",
        tool_attestation_digests: Optional[Mapping[str, str]] = None,
        adapter_attestation_digests: Optional[Mapping[str, str]] = None,
        verification_status: str = "PASS",
    ) -> CompositionMemoryEntry:
        """Validate verification outcome & full provenance fingerprint, then store atomically."""
        _check_hygiene(plan if isinstance(plan, Mapping) else plan.to_dict(), path="plan")
        plan_obj = CompositionPlan.from_dict(plan)

        ver_norm = validate_safe_text(verification_status, field_name="verification_status").upper()
        if ver_norm not in {"PASS", "VERIFIED"}:
            raise ValueError(f"REFUSED_UNVERIFIED_PLAN: cannot store verification_status='{ver_norm}'.")

        receipt_digest = ""
        receipt_policy_hash: Optional[str] = None
        if receipt is not None:
            rec_obj = CompositionReceipt.from_dict(receipt)
            if rec_obj.status != ExecutionStatus.PASS:
                raise ValueError(f"REFUSED_FAILED_RECEIPT: cannot cache receipt with status={rec_obj.status.value}.")
            if rec_obj.oracle_result.get("passed") is False:
                raise ValueError("REFUSED_FAILED_ORACLE: cannot cache composition with oracle_result.passed=False.")
            if rec_obj.verification_status.upper() in {"FAIL", "FAILED", "NOT_VERIFIED", "INSUFFICIENT_EVIDENCE"}:
                raise ValueError(f"REFUSED_UNVERIFIED_RECEIPT: verification_status={rec_obj.verification_status}.")
            if not hmac.compare_digest(rec_obj.plan_hash, plan_obj.plan_hash):
                raise ValueError("RECEIPT_PLAN_HASH_MISMATCH: receipt.plan_hash does not match plan.plan_hash.")
            receipt_digest = rec_obj.trace_digest
            receipt_policy_hash = rec_obj.policy_hash

        eff_policy_hash = policy_hash or receipt_policy_hash
        if not eff_policy_hash:
            raise ValueError("MISSING_PROVENANCE: policy_hash is required to store in CompositionMemory.")
        eff_policy_hash = normalize_sha256(eff_policy_hash, field_name="policy_hash")
        if receipt_policy_hash and not hmac.compare_digest(eff_policy_hash, receipt_policy_hash):
            raise ValueError("POLICY_HASH_MISMATCH: explicit policy_hash contradicts receipt.policy_hash.")

        eff_oracle_ref = oracle_ref or plan_obj.oracle_ref
        if oracle_ref and oracle_ref.strip() != plan_obj.oracle_ref:
            raise ValueError("ORACLE_REF_MISMATCH: explicit oracle_ref contradicts plan.oracle_ref.")

        eff_tool_hashes = dict(
            tool_artifact_hashes if tool_artifact_hashes is not None else plan_obj.tool_artifact_hashes
        )
        if plan_obj.tool_artifact_hashes and tool_artifact_hashes is not None:
            norm_explicit = _normalize_hash_map(eff_tool_hashes, field_name="tool_artifact_hashes")
            if norm_explicit != plan_obj.tool_artifact_hashes:
                raise ValueError("TOOL_HASH_MISMATCH: explicit tool_artifact_hashes contradicts plan.tool_artifact_hashes.")

        eff_adapter_hashes = dict(adapter_hashes if adapter_hashes is not None else plan_obj.adapter_hashes)
        if plan_obj.adapter_hashes and adapter_hashes is not None:
            norm_adapters = _normalize_hash_map(eff_adapter_hashes, field_name="adapter_hashes")
            if norm_adapters != plan_obj.adapter_hashes:
                raise ValueError("ADAPTER_HASH_MISMATCH: explicit adapter_hashes contradicts plan.adapter_hashes.")

        for node in plan_obj.nodes:
            tid = str(node.get("tool_id") or "").strip()
            kind = str(node.get("kind") or "tool").strip().lower()
            if kind == "adapter":
                if tid not in eff_adapter_hashes and tid not in eff_tool_hashes:
                    raise ValueError(f"MISSING_ADAPTER_PROVENANCE: adapter node '{tid}' lacks hash.")
            elif tid not in eff_tool_hashes:
                raise ValueError(f"MISSING_TOOL_PROVENANCE: plan node tool '{tid}' lacks tool_artifact_hash.")

        eff_schema_hashes: Dict[str, str] = {}
        if schema_hashes is not None:
            eff_schema_hashes.update(
                _normalize_hash_map(schema_hashes, field_name="schema_hashes", validate_ids_as_tools=False)
            )
        if schema_hash is not None:
            eff_schema_hashes["__schema__"] = normalize_sha256(schema_hash, field_name="schema_hash")

        eff_task_sig = task_signature
        if not eff_task_sig:
            if goal_contract is not None:
                eff_task_sig = derive_task_signature(goal_contract)
            else:
                eff_task_sig = plan_obj.goal_contract_hash

        prov = CompositionProvenance(
            tool_artifact_hashes=eff_tool_hashes,
            adapter_hashes=eff_adapter_hashes,
            schema_hashes=eff_schema_hashes,
            policy_hash=eff_policy_hash,
            oracle_ref=eff_oracle_ref,
            runtime_version=runtime_version,
            plan_hash=plan_obj.plan_hash,
            oracle_hash=oracle_hash,
            tool_attestation_digests=dict(tool_attestation_digests or {}),
            adapter_attestation_digests=dict(adapter_attestation_digests or {}),
        )
        entry = CompositionMemoryEntry(
            task_signature=eff_task_sig,
            goal_contract_hash=plan_obj.goal_contract_hash,
            plan=plan_obj,
            provenance=prov,
            verification_status=ver_norm,
            receipt_digest=receipt_digest,
            attestation_revoked=False,
        )

        existing = self._entries.get(entry.entry_key)
        if existing is not None:
            entry.reuse_count = existing.reuse_count + 1
            entry.created_at = existing.created_at
            entry.last_verified_at = _utc_now_iso()

        self._entries[entry.entry_key] = entry
        self.save()
        return copy.deepcopy(entry)

    record = store

    def _evaluate_entry_provenance(
        self,
        entry: CompositionMemoryEntry,
        *,
        current_tool_hashes: Optional[Mapping[str, str]] = None,
        current_adapter_hashes: Optional[Mapping[str, str]] = None,
        current_schema_hashes: Optional[Mapping[str, str]] = None,
        current_schema_hash: Optional[str] = None,
        current_policy_hash: Optional[str] = None,
        current_oracle_ref: Optional[str] = None,
        current_oracle_hash: Optional[str] = None,
        current_runtime_version: Optional[str] = None,
        retired_tool_ids: Optional[Iterable[str]] = None,
        revoked_tool_ids: Optional[Iterable[str]] = None,
        revoked_attestation_digests: Optional[Iterable[str]] = None,
        current_tool_attestations: Optional[Mapping[str, Any]] = None,
        registry: Optional[ToolRegistry] = None,
        security_context: Optional[SecurityContext] = None,
        require_full_provenance: bool = True,
    ) -> List[str]:
        reasons: List[str] = []
        prov = entry.provenance

        if entry.attestation_revoked:
            reasons.append(f"ATTESTATION_REVOKED:{entry.revocation_reason or 'entry_revoked'}")

        try:
            rechecked = CompositionPlan.from_dict(entry.plan.to_dict())
            if not hmac.compare_digest(rechecked.plan_hash, prov.plan_hash):
                reasons.append("PLAN_HASH_MISMATCH")
        except (ValueError, KeyError, TypeError):
            reasons.append("PLAN_INTEGRITY_INVALID")

        plan_tool_ids = {str(n.get("tool_id") or "").strip() for n in entry.plan.nodes if n.get("tool_id")}
        all_bound_ids = set(prov.tool_artifact_hashes.keys()) | set(prov.adapter_hashes.keys()) | plan_tool_ids

        if retired_tool_ids is not None:
            retired_set = {str(t).strip() for t in retired_tool_ids if str(t).strip()}
            for tid in sorted(all_bound_ids & retired_set):
                reasons.append(f"TOOL_RETIRED:{tid}")

        if revoked_tool_ids is not None:
            revoked_set = {str(t).strip() for t in revoked_tool_ids if str(t).strip()}
            for tid in sorted(all_bound_ids & revoked_set):
                reasons.append(f"ATTESTATION_REVOKED:{tid}")

        if revoked_attestation_digests is not None and prov.tool_attestation_digests:
            rev_digests = {str(d).strip().lower() for d in revoked_attestation_digests if str(d).strip()}
            for tid, dig in prov.tool_attestation_digests.items():
                if dig.lower() in rev_digests:
                    reasons.append(f"ATTESTATION_REVOKED:{tid}")

        registry_tool_hashes: Optional[Dict[str, str]] = None
        if registry is not None:
            registry_tool_hashes = {}
            for tid in sorted(prov.tool_artifact_hashes.keys()):
                spec = registry.get(tid)
                if spec is None:
                    reasons.append(f"TOOL_MISSING_FROM_REGISTRY:{tid}")
                    continue
                if spec.trust_status == TrustStatus.RETIRED:
                    reasons.append(f"TOOL_RETIRED:{tid}")
                elif spec.trust_status != TrustStatus.VERIFIED or not has_valid_verification_attestation(
                    spec.verification_attestation, spec.binary_hash, spec.tool_id
                ):
                    reasons.append(f"ATTESTATION_REVOKED:{tid}")
                registry_tool_hashes[tid] = spec.binary_hash

        if current_tool_attestations is not None:
            for tid in sorted(prov.tool_artifact_hashes.keys()):
                att_val = current_tool_attestations.get(tid)
                if att_val is False or att_val is None:
                    reasons.append(f"ATTESTATION_REVOKED:{tid}")
                elif isinstance(att_val, Mapping):
                    expected_bin = prov.tool_artifact_hashes[tid]
                    if not has_valid_verification_attestation(dict(att_val), expected_bin, tid):
                        reasons.append(f"ATTESTATION_REVOKED:{tid}")
                elif isinstance(att_val, TrustStatus) and att_val != TrustStatus.VERIFIED:
                    reasons.append(f"ATTESTATION_REVOKED:{tid}")

        eff_cur_tools = current_tool_hashes if current_tool_hashes is not None else registry_tool_hashes
        reasons.extend(
            _check_dict_hashes(
                prov.tool_artifact_hashes,
                eff_cur_tools,
                missing_prov_code="MISSING_PROVENANCE:tool_artifact_hashes",
                missing_item_prefix="TOOL_ARTIFACT_MISSING",
                changed_prefix="TOOL_ARTIFACT_HASH_CHANGED",
                require_present=require_full_provenance,
            )
        )

        reasons.extend(
            _check_dict_hashes(
                prov.adapter_hashes,
                current_adapter_hashes,
                missing_prov_code="MISSING_PROVENANCE:adapter_hashes",
                missing_item_prefix="ADAPTER_HASH_MISSING",
                changed_prefix="ADAPTER_HASH_CHANGED",
                require_present=require_full_provenance,
            )
        )

        eff_cur_schemas: Optional[Dict[str, str]] = None
        if current_schema_hashes is not None or current_schema_hash is not None:
            eff_cur_schemas = dict(current_schema_hashes or {})
            if current_schema_hash is not None:
                eff_cur_schemas["__schema__"] = current_schema_hash
        if prov.schema_hashes:
            reasons.extend(
                _check_dict_hashes(
                    prov.schema_hashes,
                    eff_cur_schemas,
                    missing_prov_code="MISSING_PROVENANCE:schema_hashes",
                    missing_item_prefix="SCHEMA_HASH_MISSING",
                    changed_prefix="SCHEMA_HASH_CHANGED",
                    require_present=require_full_provenance,
                )
            )
        elif eff_cur_schemas:
            reasons.append("SCHEMA_HASH_UNBOUND_IN_ENTRY")

        eff_cur_policy = current_policy_hash
        if security_context is not None:
            expected_ctx_pol = sha256_digest(
                {
                    "schema": security_context.schema,
                    "profile": security_context.profile.value,
                    "workspace_root": security_context.workspace_root,
                    "allowed_permissions": sorted(security_context.allowed_permissions),
                    "network_allowed": bool(security_context.network_allowed),
                    "allow_untrusted_native": bool(security_context.allow_untrusted_native),
                }
            )
            if not hmac.compare_digest(expected_ctx_pol, security_context.policy_hash):
                reasons.append("SECURITY_CONTEXT_POLICY_TAMPERED")
            if eff_cur_policy is None:
                eff_cur_policy = security_context.policy_hash

        if eff_cur_policy is None:
            if require_full_provenance:
                reasons.append("MISSING_PROVENANCE:policy_hash")
        else:
            try:
                norm_pol = normalize_sha256(eff_cur_policy, field_name="policy_hash")
                if not hmac.compare_digest(norm_pol, prov.policy_hash):
                    reasons.append("POLICY_HASH_CHANGED")
            except ValueError:
                reasons.append("POLICY_HASH_CHANGED")

        if current_oracle_ref is None:
            if require_full_provenance:
                reasons.append("MISSING_PROVENANCE:oracle_ref")
        elif current_oracle_ref.strip() != prov.oracle_ref:
            reasons.append("ORACLE_REF_CHANGED")

        if prov.oracle_hash is not None or current_oracle_hash is not None:
            if current_oracle_hash is None:
                if require_full_provenance:
                    reasons.append("MISSING_PROVENANCE:oracle_hash")
            elif prov.oracle_hash is None:
                reasons.append("ORACLE_HASH_CHANGED")
            else:
                try:
                    norm_oh = normalize_sha256(current_oracle_hash, field_name="oracle_hash")
                    if not hmac.compare_digest(norm_oh, prov.oracle_hash):
                        reasons.append("ORACLE_HASH_CHANGED")
                except ValueError:
                    reasons.append("ORACLE_HASH_CHANGED")

        if current_runtime_version is None:
            if require_full_provenance:
                reasons.append("MISSING_PROVENANCE:runtime_version")
        elif current_runtime_version.strip() != prov.runtime_version:
            reasons.append("RUNTIME_VERSION_CHANGED")

        return list(dict.fromkeys(reasons))

    def retrieve(
        self,
        *,
        task_signature: Optional[str] = None,
        goal_contract: Optional[Union[CapabilityGap, Mapping[str, Any]]] = None,
        goal_contract_hash: Optional[str] = None,
        current_tool_hashes: Optional[Mapping[str, str]] = None,
        current_adapter_hashes: Optional[Mapping[str, str]] = None,
        current_schema_hashes: Optional[Mapping[str, str]] = None,
        current_schema_hash: Optional[str] = None,
        current_policy_hash: Optional[str] = None,
        current_oracle_ref: Optional[str] = None,
        current_oracle_hash: Optional[str] = None,
        current_runtime_version: Optional[str] = None,
        retired_tool_ids: Optional[Iterable[str]] = None,
        revoked_tool_ids: Optional[Iterable[str]] = None,
        revoked_attestation_digests: Optional[Iterable[str]] = None,
        current_tool_attestations: Optional[Mapping[str, Any]] = None,
        registry: Optional[ToolRegistry] = None,
        security_context: Optional[SecurityContext] = None,
        require_full_provenance: bool = True,
    ) -> CompositionCacheLookup:
        """
        Gate G4 strict cache retrieval.

        Returns `CACHE_HIT` with the verified `CompositionPlan` ONLY when task signature / goal
        AND every provenance axis match without retirement or revocation. Otherwise returns
        `CACHE_INVALIDATED` (with `plan=None` and explicit reasons) or `CACHE_MISS`.
        """
        self.last_invalidation_reasons.clear()
        eff_sig = task_signature
        if not eff_sig and goal_contract is not None:
            eff_sig = derive_task_signature(goal_contract)
        eff_goal_hash = goal_contract_hash
        if not eff_goal_hash and isinstance(goal_contract, CapabilityGap):
            eff_goal_hash = goal_contract.content_hash()
        elif not eff_goal_hash and isinstance(goal_contract, Mapping) and goal_contract.get("goal_contract_hash"):
            eff_goal_hash = str(goal_contract["goal_contract_hash"])

        candidates: List[CompositionMemoryEntry] = []
        for entry in self._entries.values():
            if eff_sig and entry.task_signature != eff_sig:
                continue
            if eff_goal_hash and not hmac.compare_digest(entry.goal_contract_hash, eff_goal_hash.strip().lower()):
                continue
            if not eff_sig and not eff_goal_hash:
                continue
            candidates.append(entry)

        if not candidates:
            return CompositionCacheLookup(
                status=CACHE_STATUS_MISS,
                hit=False,
                plan=None,
                entry=None,
                reasons=["NO_MATCHING_COMPOSITION_ENTRY"],
                task_signature=eff_sig or "",
                checked_entries=0,
            )

        candidates.sort(key=lambda e: (-e.reuse_count, e.provenance.provenance_fingerprint))
        all_reasons: List[str] = []
        for entry in candidates:
            reasons = self._evaluate_entry_provenance(
                entry,
                current_tool_hashes=current_tool_hashes,
                current_adapter_hashes=current_adapter_hashes,
                current_schema_hashes=current_schema_hashes,
                current_schema_hash=current_schema_hash,
                current_policy_hash=current_policy_hash,
                current_oracle_ref=current_oracle_ref,
                current_oracle_hash=current_oracle_hash,
                current_runtime_version=current_runtime_version,
                retired_tool_ids=retired_tool_ids,
                revoked_tool_ids=revoked_tool_ids,
                revoked_attestation_digests=revoked_attestation_digests,
                current_tool_attestations=current_tool_attestations,
                registry=registry,
                security_context=security_context,
                require_full_provenance=require_full_provenance,
            )
            if not reasons:
                return CompositionCacheLookup(
                    status=CACHE_STATUS_HIT,
                    hit=True,
                    plan=copy.deepcopy(entry.plan),
                    entry=copy.deepcopy(entry),
                    reasons=[],
                    task_signature=entry.task_signature,
                    provenance_fingerprint=entry.provenance.provenance_fingerprint,
                    checked_entries=len(candidates),
                )
            for r in reasons:
                if r not in all_reasons:
                    all_reasons.append(r)

        self.last_invalidation_reasons = list(all_reasons)
        return CompositionCacheLookup(
            status=CACHE_STATUS_INVALIDATED,
            hit=False,
            plan=None,
            entry=None,
            reasons=all_reasons,
            task_signature=eff_sig or "",
            checked_entries=len(candidates),
        )

    def retrieve_plan(self, **kwargs: Any) -> Optional[CompositionPlan]:
        """Convenience wrapper returning `CompositionPlan` on `CACHE_HIT` or `None` otherwise."""
        return self.retrieve(**kwargs).plan

    def revoke_attestation(
        self,
        *,
        plan_hash: Optional[str] = None,
        tool_id: Optional[str] = None,
        reason: str = "ATTESTATION_REVOKED",
    ) -> int:
        """Mark cached plans matching `plan_hash` or `tool_id` as attestation-revoked and persist."""
        updated = 0
        norm_plan_h = normalize_sha256(plan_hash, field_name="plan_hash") if plan_hash else None
        clean_reason = redact_runtime_text(validate_safe_text(reason, field_name="reason"))
        for entry in self._entries.values():
            matches_plan = norm_plan_h is not None and hmac.compare_digest(entry.plan.plan_hash, norm_plan_h)
            matches_tool = tool_id is not None and (
                tool_id in entry.provenance.tool_artifact_hashes
                or tool_id in entry.provenance.adapter_hashes
                or any(n.get("tool_id") == tool_id for n in entry.plan.nodes)
            )
            if matches_plan or matches_tool:
                entry.attestation_revoked = True
                entry.revocation_reason = clean_reason
                updated += 1
        if updated > 0:
            self.save()
        return updated

    def invalidate_stale(self, **kwargs: Any) -> int:
        """Remove entries invalidated under current provenance kwargs and persist."""
        removed = 0
        for key in list(self._entries.keys()):
            entry = self._entries[key]
            reasons = self._evaluate_entry_provenance(entry, **kwargs)
            if reasons:
                self._entries.pop(key, None)
                removed += 1
        if removed > 0:
            self.save()
        return removed

    def list_entries(self) -> List[CompositionMemoryEntry]:
        return [copy.deepcopy(e) for e in self._entries.values()]


__all__ = [
    "DEFAULT_COMPOSITION_MEMORY_REL_PATH",
    "COMPOSITION_MEMORY_SCHEMA",
    "CACHE_STATUS_HIT",
    "CACHE_STATUS_INVALIDATED",
    "CACHE_STATUS_MISS",
    "derive_task_signature",
    "CompositionProvenance",
    "CompositionMemoryEntry",
    "CompositionCacheLookup",
    "CompositionMemory",
]
