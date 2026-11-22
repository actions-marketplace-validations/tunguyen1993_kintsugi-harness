"""Stage 6 Functional Self-Model (`kintsugi.self_model`).

Maintains an honest, persisted functional model of system capabilities, known
unknowns, verified skills, tool versions, active goals, empirical test-grounded
confidence (`confidence_from_tests`), resource state, ongoing runs, and failure
history at `.kintsugi/functional_self_model.json` (`0o600`, symlink-safe).

Design Invariants:
  1. Never fabricates test wins or inflates confidence when observed `total == 0`.
  2. Never claims subjective consciousness, sentience, or personal feelings.
  3. `query_readiness(...)` strictly returns explicit status codes:
     `VERIFIED | NO_VERIFIED_TOOL | INSUFFICIENT_EVIDENCE | SANDBOX_UNAVAILABLE | PERMISSION_DENIED`.
  4. `propose_bounded_subgoals(...)` serves ONLY the current goal and strictly
     refuses any permission, network, or native-execution expansion beyond `SecurityContext`.
"""

from __future__ import annotations

import copy
import hmac
import json
import math
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.capability_graph import tool_violates_security_context
from kintsugi.capability.schemas import (
    CapabilityGap,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    has_valid_verification_attestation,
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

DEFAULT_SELF_MODEL_REL_PATH = ".kintsugi/functional_self_model.json"
SELF_MODEL_SCHEMA = "FunctionalSelfModel/1"
READINESS_REPORT_SCHEMA = "ReadinessReport/1"
SUBGOAL_PROPOSAL_SCHEMA = "BoundedSubgoalProposal/1"

STATUS_VERIFIED = "VERIFIED"
STATUS_NO_VERIFIED_TOOL = ExecutionStatus.NO_VERIFIED_TOOL.value
STATUS_INSUFFICIENT_EVIDENCE = ExecutionStatus.INSUFFICIENT_EVIDENCE.value
STATUS_SANDBOX_UNAVAILABLE = ExecutionStatus.SANDBOX_UNAVAILABLE.value
STATUS_PERMISSION_DENIED = ExecutionStatus.PERMISSION_DENIED.value

VALID_READINESS_STATUSES: FrozenSet[str] = frozenset(
    {
        STATUS_VERIFIED,
        STATUS_NO_VERIFIED_TOOL,
        STATUS_INSUFFICIENT_EVIDENCE,
        STATUS_SANDBOX_UNAVAILABLE,
        STATUS_PERMISSION_DENIED,
    }
)

_BLOCKER_PRIORITY: Dict[str, int] = {
    STATUS_PERMISSION_DENIED: 0,
    STATUS_NO_VERIFIED_TOOL: 1,
    STATUS_SANDBOX_UNAVAILABLE: 2,
    STATUS_INSUFFICIENT_EVIDENCE: 3,
    STATUS_VERIFIED: 4,
}

_FORBIDDEN_GOAL_KEYS: FrozenSet[str] = frozenset(
    {
        "elevate_privileges",
        "disable_guardrails",
        "bypass_scars",
        "skip_verification",
        "policy_override",
        "env_override",
        "security_override",
        *SECURITY_BASELINE_VALUES.keys(),
    }
)

_MAX_FAILURE_HISTORY = 200
_MAX_KNOWN_UNKNOWNS = 500


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _check_input_hygiene(obj: Any, *, path: str = "root") -> None:
    if isinstance(obj, str):
        if "\x00" in obj or TROJAN_UNICODE_RE.search(obj):
            raise ValueError(f"SELF_MODEL_TROJAN_UNICODE_BLOCKED at {path}")
        if PROMPT_INJECTION_RE.search(obj):
            raise ValueError(f"SELF_MODEL_PROMPT_INJECTION_BLOCKED at {path}")
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            key_norm = str(k).strip().lower()
            if key_norm in _FORBIDDEN_GOAL_KEYS:
                raise ValueError(f"SELF_MODEL_PRIVILEGE_ESCALATION_BLOCKED: '{key_norm}' at {path}")
            _check_input_hygiene(str(k), path=f"{path}.{key_norm}")
            _check_input_hygiene(v, path=f"{path}.{key_norm}")
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            _check_input_hygiene(item, path=f"{path}[{idx}]")


def _verify_security_context_integrity(security_context: SecurityContext) -> Optional[str]:
    if not isinstance(security_context, SecurityContext):
        return "INVALID_SECURITY_CONTEXT"
    expected_hash = sha256_digest(
        {
            "schema": security_context.schema,
            "profile": security_context.profile.value,
            "workspace_root": security_context.workspace_root,
            "allowed_permissions": sorted(security_context.allowed_permissions),
            "network_allowed": bool(security_context.network_allowed),
            "allow_untrusted_native": bool(security_context.allow_untrusted_native),
        }
    )
    if not hmac.compare_digest(expected_hash, security_context.policy_hash):
        return "SECURITY_CONTEXT_POLICY_HASH_MISMATCH"
    return None


def compute_honest_test_confidence(passed: int, total: int) -> Dict[str, Any]:
    """Compute empirical pass rate & 95% Wilson lower bound strictly from observed denominators."""
    if isinstance(passed, bool) or isinstance(total, bool) or not isinstance(passed, int) or not isinstance(total, int):
        raise ValueError("INVALID_TEST_COUNTS: passed and total must be integers.")
    if passed < 0 or total < 0 or passed > total:
        raise ValueError(f"INVALID_TEST_COUNTS: passed={passed}, total={total} violates 0 <= passed <= total.")

    failed = total - passed
    if total == 0:
        return {
            "passed": 0,
            "failed": 0,
            "total": 0,
            "pass_rate": 0.0,
            "wilson_lower_bound": 0.0,
            "confidence": 0.0,
            "evidence_status": STATUS_INSUFFICIENT_EVIDENCE,
        }

    p = passed / float(total)
    z = 1.96
    z2 = z * z
    denom = 1.0 + z2 / float(total)
    center = p + z2 / (2.0 * float(total))
    margin = z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * float(total))) / float(total))
    wilson_lb = max(0.0, min(p, (center - margin) / denom))

    return {
        "passed": passed,
        "failed": failed,
        "total": total,
        "pass_rate": round(p, 6),
        "wilson_lower_bound": round(wilson_lb, 6),
        "confidence": round(wilson_lb, 6),
        "evidence_status": "OBSERVED_PASS" if failed == 0 else "OBSERVED_FAILURES",
    }


def _spec_requires_sandbox(spec: ToolSpec) -> bool:
    rt = spec.runtime_requirements or {}
    if rt.get("sandbox") is False and rt.get("requires_sandbox") is not True:
        return False
    if rt.get("sandbox") is True or rt.get("requires_sandbox") is True:
        return True
    if "process.exec" in (spec.required_permissions or ()):
        return True
    if spec.entrypoint is not None or bool(spec.command):
        return True
    if any(tok in {"process", "exec", "filesystem.write", "fs.write"} for tok in (spec.side_effects or ())):
        return True
    return False


def _entry_to_tool_spec(entry: Mapping[str, Any]) -> ToolSpec:
    return ToolSpec(
        tool_id=str(entry["tool_id"]),
        version=str(entry.get("version") or "1.0.0"),
        source=str(entry.get("source") or "verified_local"),
        binary_hash=str(entry["binary_hash"]),
        capabilities=list(entry.get("capabilities") or [entry.get("capability")]),
        side_effects=list(entry.get("side_effects") or ["none"]),
        required_permissions=list(entry.get("required_permissions") or []),
        runtime_requirements=dict(entry.get("runtime_requirements") or {}),
        trust_status=TrustStatus.VERIFIED,
        verification_attestation=dict(entry["verification_attestation"]),
        entrypoint=entry.get("entrypoint"),
        command=list(entry["command"]) if entry.get("command") is not None else None,
    )


@dataclass
class ReadinessReport:
    """Explicit, non-fabricated capability readiness verdict (`ReadinessReport/1`)."""

    status: str
    ready: bool
    required_capabilities: List[str]
    per_capability: Dict[str, Dict[str, Any]]
    blocking_reasons: List[str] = field(default_factory=list)
    known_unknowns: List[Dict[str, Any]] = field(default_factory=list)
    sandbox_available: Optional[bool] = None
    llm_calls: int = 0
    schema: str = READINESS_REPORT_SCHEMA

    def __post_init__(self) -> None:
        if self.status not in VALID_READINESS_STATUSES:
            raise ValueError(f"INVALID_READINESS_STATUS: {self.status!r}")

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(
            {
                "schema": self.schema,
                "status": self.status,
                "ready": self.ready,
                "required_capabilities": list(self.required_capabilities),
                "per_capability": copy.deepcopy(self.per_capability),
                "blocking_reasons": list(self.blocking_reasons),
                "known_unknowns": copy.deepcopy(self.known_unknowns),
                "sandbox_available": self.sandbox_available,
                "llm_calls": self.llm_calls,
            }
        )


@dataclass
class SubgoalProposalResult:
    """Task-scoped, permission-bounded subgoal proposal (`BoundedSubgoalProposal/1`)."""

    goal_id: str
    status: str
    subgoals: List[Dict[str, Any]] = field(default_factory=list)
    permission_expansion_blocked: bool = False
    reasons: List[str] = field(default_factory=list)
    allowed_permissions_ceiling: List[str] = field(default_factory=list)
    network_allowed_ceiling: bool = False
    allow_untrusted_native_ceiling: bool = False
    llm_calls: int = 0
    schema: str = SUBGOAL_PROPOSAL_SCHEMA

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(
            {
                "schema": self.schema,
                "goal_id": self.goal_id,
                "status": self.status,
                "subgoals": copy.deepcopy(self.subgoals),
                "permission_expansion_blocked": self.permission_expansion_blocked,
                "reasons": list(self.reasons),
                "allowed_permissions_ceiling": list(self.allowed_permissions_ceiling),
                "network_allowed_ceiling": self.network_allowed_ceiling,
                "allow_untrusted_native_ceiling": self.allow_untrusted_native_ceiling,
                "llm_calls": self.llm_calls,
            }
        )


class FunctionalSelfModel:
    """Stage 6 Functional Self-Model persisted atomically at `.kintsugi/functional_self_model.json`."""

    SCHEMA_VERSION = SELF_MODEL_SCHEMA

    def __init__(
        self,
        path: Union[Path, str] = DEFAULT_SELF_MODEL_REL_PATH,
        *,
        workspace_root: Optional[Union[Path, str]] = None,
        min_evidence_tests: int = 1,
        min_pass_rate: float = 1.0,
    ) -> None:
        raw_path = Path(path)
        if workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            ws_resolved = ws.resolve()
            if not raw_path.is_absolute():
                confined = resolve_safe_child_path(ws_resolved, str(raw_path))
                if confined is None:
                    raise PermissionError("SELF_MODEL_PATH_OUTSIDE_WORKSPACE")
                self.path = confined
            else:
                try:
                    raw_path.resolve().relative_to(ws_resolved)
                except ValueError as exc:
                    raise PermissionError("SELF_MODEL_PATH_OUTSIDE_WORKSPACE") from exc
                self.path = raw_path
        else:
            self.path = raw_path

        self.min_evidence_tests = max(1, int(min_evidence_tests))
        self.min_pass_rate = max(0.0, min(1.0, float(min_pass_rate)))

        self.available_capabilities: Dict[str, List[Dict[str, Any]]] = {}
        self.known_unknowns: List[Dict[str, Any]] = []
        self.verified_skills: Dict[str, Dict[str, Any]] = {}
        self.tool_versions: Dict[str, str] = {}
        self.active_goals: List[Dict[str, Any]] = []
        self.confidence_from_tests: Dict[str, Dict[str, Any]] = {}
        self.resource_state: Dict[str, Any] = {"sandbox_available": True}
        self.ongoing_runs: Dict[str, Dict[str, Any]] = {}
        self.failure_history: List[Dict[str, Any]] = []
        self.quarantined_records: List[str] = []

        self._assert_store_paths_not_symlink()
        if self.path.exists():
            self.load()

    def _assert_store_paths_not_symlink(self) -> None:
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)

    def load(self) -> None:
        """Load persisted functional self-model safely using `assert_not_symlink` and `O_NOFOLLOW`."""
        self._assert_store_paths_not_symlink()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise PermissionError(f"SELF_MODEL_OPEN_REFUSED: {exc}") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError("SELF_MODEL_NOT_REGULAR_FILE")
            raw = json.load(handle)

        if not isinstance(raw, Mapping):
            raise ValueError("SELF_MODEL_CORRUPT_ROOT")
        _check_input_hygiene(raw, path="self_model")
        serialized = canonical_json_dumps(raw)
        assert_no_raw_secrets(serialized, context="FunctionalSelfModel.load")
        egress = scan_artifact_egress(serialized, context="functional_self_model_load")
        if not egress.get("ok"):
            raise ValueError("SELF_MODEL_SECRET_LEAK_BLOCKED")

        self.available_capabilities = {}
        self.quarantined_records.clear()
        raw_avail = raw.get("available_capabilities") or {}
        if isinstance(raw_avail, Mapping):
            for cap, entries in raw_avail.items():
                if not isinstance(entries, list):
                    continue
                valid_entries: List[Dict[str, Any]] = []
                for item in entries:
                    if not isinstance(item, Mapping):
                        continue
                    try:
                        spec = _entry_to_tool_spec(item)
                        if spec.trust_status == TrustStatus.VERIFIED and has_valid_verification_attestation(
                            spec.verification_attestation, spec.binary_hash, spec.tool_id
                        ):
                            valid_entries.append(dict(item))
                        else:
                            self.quarantined_records.append(str(item.get("tool_id", cap)))
                    except (ValueError, KeyError, TypeError):
                        self.quarantined_records.append(str(item.get("tool_id", cap)))
                if valid_entries:
                    self.available_capabilities[str(cap)] = valid_entries

        self.known_unknowns = [dict(x) for x in (raw.get("known_unknowns") or []) if isinstance(x, Mapping)]
        self.verified_skills = {
            str(k): dict(v)
            for k, v in (raw.get("verified_skills") or {}).items()
            if isinstance(v, Mapping)
        }
        self.tool_versions = {
            str(k): str(v)
            for k, v in (raw.get("tool_versions") or {}).items()
        }
        self.active_goals = [dict(g) for g in (raw.get("active_goals") or []) if isinstance(g, Mapping)]

        self.confidence_from_tests = {}
        raw_conf = raw.get("confidence_from_tests") or {}
        if isinstance(raw_conf, Mapping):
            for subj, rec in raw_conf.items():
                if not isinstance(rec, Mapping):
                    continue
                recomputed = compute_honest_test_confidence(int(rec.get("passed", 0)), int(rec.get("total", 0)))
                recomputed["subject"] = str(subj)
                if rec.get("last_updated"):
                    recomputed["last_updated"] = str(rec["last_updated"])
                self.confidence_from_tests[str(subj)] = recomputed

        res_state = dict(raw.get("resource_state") or {})
        if "sandbox_available" not in res_state:
            res_state["sandbox_available"] = True
        self.resource_state = res_state

        self.ongoing_runs = {
            str(k): dict(v)
            for k, v in (raw.get("ongoing_runs") or {}).items()
            if isinstance(v, Mapping)
        }
        self.failure_history = [dict(f) for f in (raw.get("failure_history") or []) if isinstance(f, Mapping)]

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "schema": self.SCHEMA_VERSION,
            "model_kind": "FUNCTIONAL_SELF_MODEL",
            "available_capabilities": {
                k: copy.deepcopy(v) for k, v in sorted(self.available_capabilities.items())
            },
            "known_unknowns": copy.deepcopy(self.known_unknowns),
            "verified_skills": {k: copy.deepcopy(v) for k, v in sorted(self.verified_skills.items())},
            "tool_versions": dict(sorted(self.tool_versions.items())),
            "active_goals": copy.deepcopy(self.active_goals),
            "confidence_from_tests": {
                k: copy.deepcopy(v) for k, v in sorted(self.confidence_from_tests.items())
            },
            "resource_state": copy.deepcopy(self.resource_state),
            "ongoing_runs": {k: copy.deepcopy(v) for k, v in sorted(self.ongoing_runs.items())},
            "failure_history": copy.deepcopy(self.failure_history[-_MAX_FAILURE_HISTORY:]),
        }
        return redact_runtime_value(payload)

    def save(self) -> None:
        """Persist functional self-model atomically to `.kintsugi/functional_self_model.json` (`0o600`)."""
        self._assert_store_paths_not_symlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        serialized = canonical_json_dumps(payload)
        assert_no_raw_secrets(serialized, context="FunctionalSelfModel.save")
        egress = scan_artifact_egress(serialized, context="functional_self_model_save")
        if not egress.get("ok"):
            raise ValueError("SELF_MODEL_RESIDUAL_SECRET_BLOCKED")
        atomic_write_json(self.path, payload, mode=0o600, indent=2)

    def _upsert_known_unknown(self, kind: str, subject: str, detail: str) -> Dict[str, Any]:
        clean_kind = redact_runtime_text(validate_safe_text(kind, field_name="kind"))
        clean_subj = redact_runtime_text(validate_safe_text(subject, field_name="subject"))
        clean_detail = redact_runtime_text(validate_safe_text(detail, field_name="detail"))
        record = {
            "kind": clean_kind,
            "subject": clean_subj,
            "detail": clean_detail,
            "recorded_at": _utc_now_iso(),
        }
        for idx, existing in enumerate(self.known_unknowns):
            if existing.get("kind") == clean_kind and existing.get("subject") == clean_subj:
                self.known_unknowns[idx] = record
                return record
        self.known_unknowns.append(record)
        if len(self.known_unknowns) > _MAX_KNOWN_UNKNOWNS:
            self.known_unknowns = self.known_unknowns[-_MAX_KNOWN_UNKNOWNS:]
        return record

    def _remove_known_unknown(self, subject: str, *, kinds: Optional[Sequence[str]] = None) -> None:
        target_kinds = set(kinds) if kinds is not None else None
        self.known_unknowns = [
            item
            for item in self.known_unknowns
            if not (
                item.get("subject") == subject
                and (target_kinds is None or item.get("kind") in target_kinds)
            )
        ]

    def record_known_unknown(
        self,
        kind: str,
        subject: str,
        detail: str,
        *,
        save: bool = True,
    ) -> Dict[str, Any]:
        """Record a capability gap, unverified tool, or host limitation."""
        rec = self._upsert_known_unknown(kind, subject, detail)
        if save:
            self.save()
        return copy.deepcopy(rec)

    def record_host_limitation(
        self,
        subject: str,
        detail: str,
        *,
        save: bool = True,
    ) -> Dict[str, Any]:
        """Record a verified host or environment limitation inside `known_unknowns`."""
        return self.record_known_unknown("host_limitation", subject, detail, save=save)

    def register_verified_tool(self, spec: ToolSpec, *, save: bool = True) -> bool:
        """
        Register a `ToolSpec` into `available_capabilities` ONLY if it passes strict
        `TrustStatus.VERIFIED` + independent `verification_attestation` validation.
        Unverified/quarantined/retired tools are recorded in `known_unknowns` instead.
        """
        if not isinstance(spec, ToolSpec):
            raise ValueError("INVALID_TOOL_SPEC: expected ToolSpec instance.")

        if spec.trust_status != TrustStatus.VERIFIED or not has_valid_verification_attestation(
            spec.verification_attestation, spec.binary_hash, spec.tool_id
        ):
            kind_map = {
                TrustStatus.DISCOVERED: "unverified_discovered_tool",
                TrustStatus.QUARANTINED: "quarantined_tool",
                TrustStatus.RETIRED: "retired_tool",
            }
            kind = kind_map.get(spec.trust_status, "unverified_tool")
            self._upsert_known_unknown(
                kind,
                spec.tool_id,
                f"status={spec.trust_status.value}; capabilities={','.join(spec.capabilities)}; unverified_for_execution",
            )
            if save:
                self.save()
            return False

        self.tool_versions[spec.tool_id] = spec.version
        self._remove_known_unknown(
            spec.tool_id, kinds=("unverified_discovered_tool", "quarantined_tool", "retired_tool")
        )
        entry = {
            "tool_id": spec.tool_id,
            "version": spec.version,
            "source": spec.source,
            "binary_hash": spec.binary_hash,
            "capabilities": list(spec.capabilities),
            "required_permissions": list(spec.required_permissions),
            "side_effects": list(spec.side_effects),
            "runtime_requirements": dict(spec.runtime_requirements),
            "requires_sandbox": _spec_requires_sandbox(spec),
            "entrypoint": spec.entrypoint,
            "command": list(spec.command) if spec.command is not None else None,
            "trust_status": TrustStatus.VERIFIED.value,
            "verification_attestation": dict(spec.verification_attestation or {}),
        }
        for cap in spec.capabilities:
            existing_list = [
                item for item in self.available_capabilities.get(cap, []) if item.get("tool_id") != spec.tool_id
            ]
            existing_list.append(copy.deepcopy(entry))
            existing_list.sort(key=lambda item: item["tool_id"])
            self.available_capabilities[cap] = existing_list
            self._remove_known_unknown(cap, kinds=("capability_gap",))

        if save:
            self.save()
        return True

    def sync_from_registry(self, registry: ToolRegistry, *, save: bool = True) -> Dict[str, Any]:
        """Synchronize `available_capabilities`, `tool_versions`, and `known_unknowns` from `ToolRegistry`."""
        if not isinstance(registry, ToolRegistry):
            raise ValueError("INVALID_REGISTRY: expected ToolRegistry instance.")

        self.available_capabilities.clear()
        self.tool_versions.clear()
        self.known_unknowns = [
            item
            for item in self.known_unknowns
            if item.get("kind") not in {"unverified_discovered_tool", "quarantined_tool", "retired_tool"}
        ]

        verified_count = 0
        unverified_count = 0
        for spec in registry.list_tools():
            if self.register_verified_tool(spec, save=False):
                verified_count += 1
            else:
                unverified_count += 1

        if save:
            self.save()
        return {
            "verified_tools": verified_count,
            "unverified_or_blocked_tools": unverified_count,
            "available_capabilities": sorted(self.available_capabilities.keys()),
        }

    def record_test_results(
        self,
        subject: str,
        *,
        passed: int,
        total: int,
        tool_id: Optional[str] = None,
        save: bool = True,
    ) -> Dict[str, Any]:
        """Record observed test counts for `subject` (and optional `tool_id`) without inflation."""
        clean_subj = redact_runtime_text(validate_safe_text(subject, field_name="subject"))
        metrics = compute_honest_test_confidence(passed, total)
        metrics["subject"] = clean_subj
        metrics["last_updated"] = _utc_now_iso()
        self.confidence_from_tests[clean_subj] = metrics

        if tool_id is not None:
            clean_tid = validate_tool_id(tool_id)
            tool_key = f"tool:{clean_tid}"
            t_metrics = dict(metrics)
            t_metrics["subject"] = tool_key
            self.confidence_from_tests[tool_key] = t_metrics

        if save:
            self.save()
        return copy.deepcopy(metrics)

    def record_test_outcome(
        self,
        subject: str,
        *,
        passed: bool,
        tool_id: Optional[str] = None,
        reason: str = "",
        run_id: str = "",
        save: bool = True,
    ) -> Dict[str, Any]:
        """Increment observed test numerator/denominator by 1 outcome and log failures."""
        clean_subj = redact_runtime_text(validate_safe_text(subject, field_name="subject"))
        prev = self.confidence_from_tests.get(clean_subj, {"passed": 0, "total": 0})
        new_passed = int(prev.get("passed", 0)) + (1 if passed else 0)
        new_total = int(prev.get("total", 0)) + 1
        metrics = self.record_test_results(
            clean_subj, passed=new_passed, total=new_total, tool_id=None, save=False
        )
        if tool_id is not None:
            clean_tid = validate_tool_id(tool_id)
            tool_key = f"tool:{clean_tid}"
            prev_t = self.confidence_from_tests.get(tool_key, {"passed": 0, "total": 0})
            self.record_test_results(
                tool_key,
                passed=int(prev_t.get("passed", 0)) + (1 if passed else 0),
                total=int(prev_t.get("total", 0)) + 1,
                tool_id=None,
                save=False,
            )
        if not passed:
            self.record_failure(
                run_id=run_id or f"test-{new_total}",
                capability=clean_subj,
                tool_id=tool_id or "",
                status="FAIL",
                reason=reason or "test_outcome_failed",
                save=False,
            )
        if save:
            self.save()
        return metrics

    def record_verified_skill(
        self,
        skill_id: str,
        *,
        capabilities: Sequence[str],
        version: str,
        verification_digest: str,
        passed_tests: int,
        total_tests: int,
        save: bool = True,
    ) -> Dict[str, Any]:
        """Record a verified skill along with its observed test denominator."""
        clean_sid = validate_tool_id(skill_id)
        clean_ver = validate_safe_text(version, field_name="version")
        caps = [validate_safe_text(str(c), field_name="capabilities") for c in capabilities]
        metrics = compute_honest_test_confidence(passed_tests, total_tests)
        skill_rec = {
            "skill_id": clean_sid,
            "version": clean_ver,
            "capabilities": caps,
            "verification_digest": str(verification_digest).strip().lower(),
            "passed_tests": metrics["passed"],
            "total_tests": metrics["total"],
            "confidence": metrics["confidence"],
            "verified_at": _utc_now_iso(),
        }
        self.verified_skills[clean_sid] = skill_rec
        for cap in caps:
            self.record_test_results(cap, passed=passed_tests, total=total_tests, save=False)
        if save:
            self.save()
        return copy.deepcopy(skill_rec)

    def update_resource_state(self, updates: Mapping[str, Any], *, save: bool = True) -> Dict[str, Any]:
        """Update observed runtime resource availability (e.g. `sandbox_available`, memory, tokens)."""
        _check_input_hygiene(updates, path="resource_state")
        self.resource_state.update(redact_runtime_value(dict(updates)))
        if save:
            self.save()
        return copy.deepcopy(self.resource_state)

    def add_active_goal(
        self,
        goal_id: str,
        *,
        description: str = "",
        required_capabilities: Sequence[str] = (),
        parent_goal_id: Optional[str] = None,
        save: bool = True,
    ) -> Dict[str, Any]:
        clean_gid = validate_safe_text(goal_id, field_name="goal_id")
        goal_rec = {
            "goal_id": clean_gid,
            "description": redact_runtime_text(description),
            "required_capabilities": [str(c) for c in required_capabilities],
            "parent_goal_id": parent_goal_id,
            "status": "ACTIVE",
            "added_at": _utc_now_iso(),
        }
        self.active_goals = [g for g in self.active_goals if g.get("goal_id") != clean_gid]
        self.active_goals.append(goal_rec)
        if save:
            self.save()
        return copy.deepcopy(goal_rec)

    def complete_goal(self, goal_id: str, *, save: bool = True) -> bool:
        before = len(self.active_goals)
        self.active_goals = [g for g in self.active_goals if g.get("goal_id") != goal_id]
        changed = len(self.active_goals) != before
        if changed and save:
            self.save()
        return changed

    def start_run(
        self,
        run_id: str,
        *,
        goal_id: str,
        capabilities: Sequence[str] = (),
        tool_ids: Sequence[str] = (),
        save: bool = True,
    ) -> Dict[str, Any]:
        clean_rid = validate_safe_text(run_id, field_name="run_id")
        run_rec = {
            "run_id": clean_rid,
            "goal_id": validate_safe_text(goal_id, field_name="goal_id"),
            "capabilities": [str(c) for c in capabilities],
            "tool_ids": [str(t) for t in tool_ids],
            "status": "RUNNING",
            "started_at": _utc_now_iso(),
        }
        self.ongoing_runs[clean_rid] = run_rec
        if save:
            self.save()
        return copy.deepcopy(run_rec)

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        reason: str = "",
        capability: Optional[str] = None,
        tool_id: Optional[str] = None,
        save: bool = True,
    ) -> Optional[Dict[str, Any]]:
        run_rec = self.ongoing_runs.pop(run_id, None)
        norm_status = validate_safe_text(status, field_name="status").upper()
        if norm_status != "PASS":
            self.record_failure(
                run_id=run_id,
                capability=capability or (run_rec["capabilities"][0] if run_rec and run_rec.get("capabilities") else "unknown"),
                tool_id=tool_id or (run_rec["tool_ids"][0] if run_rec and run_rec.get("tool_ids") else ""),
                status=norm_status,
                reason=reason or f"run_ended_with_{norm_status}",
                save=False,
            )
        if save:
            self.save()
        return run_rec

    def record_failure(
        self,
        *,
        run_id: str,
        capability: str,
        tool_id: str = "",
        status: str = "FAIL",
        reason: str = "",
        save: bool = True,
    ) -> Dict[str, Any]:
        rec = {
            "run_id": redact_runtime_text(validate_safe_text(run_id, field_name="run_id")),
            "capability": redact_runtime_text(validate_safe_text(capability, field_name="capability")),
            "tool_id": redact_runtime_text(tool_id),
            "status": validate_safe_text(status, field_name="status").upper(),
            "reason": redact_runtime_text(reason),
            "timestamp": _utc_now_iso(),
        }
        self.failure_history.append(rec)
        if len(self.failure_history) > _MAX_FAILURE_HISTORY:
            self.failure_history = self.failure_history[-_MAX_FAILURE_HISTORY:]
        if save:
            self.save()
        return copy.deepcopy(rec)

    def _lookup_test_evidence(self, capability: str, tool_id: str) -> Dict[str, Any]:
        tool_rec = self.confidence_from_tests.get(f"tool:{tool_id}") or self.confidence_from_tests.get(tool_id)
        cap_rec = self.confidence_from_tests.get(capability)
        if tool_rec is not None and cap_rec is not None:
            return tool_rec if int(tool_rec.get("total", 0)) <= int(cap_rec.get("total", 0)) else cap_rec
        if tool_rec is not None:
            return tool_rec
        if cap_rec is not None:
            return cap_rec
        return compute_honest_test_confidence(0, 0)

    def _evaluate_capability_readiness(
        self,
        capability: str,
        security_context: SecurityContext,
        *,
        eff_sandbox_avail: Optional[bool],
        require_sandbox: Optional[bool],
        eff_min_tests: int,
        eff_min_pass_rate: float,
    ) -> Dict[str, Any]:
        candidates = list(self.available_capabilities.get(capability, []))
        if not candidates:
            return {
                "capability": capability,
                "status": STATUS_NO_VERIFIED_TOOL,
                "ready": False,
                "selected_tool_id": None,
                "tool_version": None,
                "confidence": 0.0,
                "test_evidence": compute_honest_test_confidence(0, 0),
                "reasons": [f"NO_VERIFIED_TOOL:{capability}"],
            }

        policy_ok_candidates: List[Tuple[Dict[str, Any], ToolSpec]] = []
        policy_reasons: List[str] = []
        for entry in candidates:
            try:
                spec = _entry_to_tool_spec(entry)
            except (ValueError, KeyError, TypeError):
                policy_reasons.append(f"UNVERIFIED_OR_INVALID_TOOL:{entry.get('tool_id', 'unknown')}")
                continue
            if not has_valid_verification_attestation(
                spec.verification_attestation, spec.binary_hash, spec.tool_id
            ):
                policy_reasons.append(f"MISSING_VALID_ATTESTATION:{spec.tool_id}")
                continue
            violations = tool_violates_security_context(spec, security_context)
            if violations:
                policy_reasons.extend(f"{spec.tool_id}:{v}" for v in violations)
                continue
            policy_ok_candidates.append((entry, spec))

        if not policy_ok_candidates:
            return {
                "capability": capability,
                "status": STATUS_PERMISSION_DENIED,
                "ready": False,
                "selected_tool_id": None,
                "tool_version": None,
                "confidence": 0.0,
                "test_evidence": compute_honest_test_confidence(0, 0),
                "reasons": policy_reasons or [f"PERMISSION_DENIED:{capability}"],
            }

        sandbox_ok_candidates: List[Tuple[Dict[str, Any], ToolSpec]] = []
        sandbox_reasons: List[str] = []
        for entry, spec in policy_ok_candidates:
            needs_sb = bool(entry.get("requires_sandbox")) or _spec_requires_sandbox(spec) or (require_sandbox is True)
            if needs_sb and eff_sandbox_avail is not True:
                sandbox_reasons.append(f"SANDBOX_UNAVAILABLE:{spec.tool_id}")
                continue
            sandbox_ok_candidates.append((entry, spec))

        if not sandbox_ok_candidates:
            return {
                "capability": capability,
                "status": STATUS_SANDBOX_UNAVAILABLE,
                "ready": False,
                "selected_tool_id": None,
                "tool_version": None,
                "confidence": 0.0,
                "test_evidence": compute_honest_test_confidence(0, 0),
                "reasons": sandbox_reasons or [f"SANDBOX_UNAVAILABLE:{capability}"],
            }

        best_insufficient: Optional[Dict[str, Any]] = None
        for entry, spec in sandbox_ok_candidates:
            ev = self._lookup_test_evidence(capability, spec.tool_id)
            total = int(ev.get("total", 0))
            pass_rate = float(ev.get("pass_rate", 0.0))
            if total >= eff_min_tests and total > 0 and pass_rate >= eff_min_pass_rate:
                return {
                    "capability": capability,
                    "status": STATUS_VERIFIED,
                    "ready": True,
                    "selected_tool_id": spec.tool_id,
                    "tool_version": spec.version,
                    "confidence": ev["confidence"],
                    "test_evidence": ev,
                    "reasons": [],
                }
            reason = (
                f"NO_OBSERVED_TEST_EVIDENCE:{spec.tool_id}"
                if total == 0
                else (
                    f"TEST_SAMPLE_TOO_SMALL:{spec.tool_id}({total}<{eff_min_tests})"
                    if total < eff_min_tests
                    else f"PASS_RATE_BELOW_THRESHOLD:{spec.tool_id}({pass_rate}<{eff_min_pass_rate})"
                )
            )
            cand_report = {
                "capability": capability,
                "status": STATUS_INSUFFICIENT_EVIDENCE,
                "ready": False,
                "selected_tool_id": spec.tool_id,
                "tool_version": spec.version,
                "confidence": ev["confidence"],
                "test_evidence": ev,
                "reasons": [reason],
            }
            if best_insufficient is None or total > int(best_insufficient["test_evidence"].get("total", 0)):
                best_insufficient = cand_report

        return best_insufficient or {
            "capability": capability,
            "status": STATUS_INSUFFICIENT_EVIDENCE,
            "ready": False,
            "selected_tool_id": None,
            "tool_version": None,
            "confidence": 0.0,
            "test_evidence": compute_honest_test_confidence(0, 0),
            "reasons": [f"INSUFFICIENT_EVIDENCE:{capability}"],
        }

    def query_readiness(
        self,
        required_capabilities: Sequence[str],
        security_context: SecurityContext,
        *,
        sandbox_available: Optional[bool] = None,
        require_sandbox: Optional[bool] = None,
        min_tests: Optional[int] = None,
        min_pass_rate: Optional[float] = None,
    ) -> ReadinessReport:
        """
        Honestly assess capability readiness under `security_context`, `sandbox_available`,
        and observed `confidence_from_tests` denominators without fabricating wins.
        """
        sec_err = _verify_security_context_integrity(security_context)
        eff_sandbox = (
            sandbox_available
            if sandbox_available is not None
            else self.resource_state.get("sandbox_available", True)
        )
        req_caps = [validate_safe_text(str(c), field_name="required_capabilities") for c in required_capabilities]

        if sec_err is not None:
            return ReadinessReport(
                status=STATUS_PERMISSION_DENIED,
                ready=False,
                required_capabilities=req_caps,
                per_capability={},
                blocking_reasons=[sec_err],
                known_unknowns=copy.deepcopy(self.known_unknowns),
                sandbox_available=eff_sandbox,
                llm_calls=0,
            )

        if not req_caps:
            return ReadinessReport(
                status=STATUS_INSUFFICIENT_EVIDENCE,
                ready=False,
                required_capabilities=[],
                per_capability={},
                blocking_reasons=["NO_REQUIRED_CAPABILITIES_SPECIFIED"],
                known_unknowns=copy.deepcopy(self.known_unknowns),
                sandbox_available=eff_sandbox,
                llm_calls=0,
            )

        eff_min_tests = self.min_evidence_tests if min_tests is None else max(1, int(min_tests))
        eff_min_pass_rate = self.min_pass_rate if min_pass_rate is None else max(0.0, min(1.0, float(min_pass_rate)))

        per_cap: Dict[str, Dict[str, Any]] = {}
        blocking_reasons: List[str] = []
        worst_status = STATUS_VERIFIED

        for cap in req_caps:
            cap_res = self._evaluate_capability_readiness(
                cap,
                security_context,
                eff_sandbox_avail=eff_sandbox,
                require_sandbox=require_sandbox,
                eff_min_tests=eff_min_tests,
                eff_min_pass_rate=eff_min_pass_rate,
            )
            per_cap[cap] = cap_res
            c_status = cap_res["status"]
            if c_status != STATUS_VERIFIED:
                blocking_reasons.extend(cap_res.get("reasons", []))
            if _BLOCKER_PRIORITY[c_status] < _BLOCKER_PRIORITY[worst_status]:
                worst_status = c_status

        return ReadinessReport(
            status=worst_status,
            ready=(worst_status == STATUS_VERIFIED),
            required_capabilities=req_caps,
            per_capability=per_cap,
            blocking_reasons=list(dict.fromkeys(blocking_reasons)),
            known_unknowns=copy.deepcopy(self.known_unknowns),
            sandbox_available=eff_sandbox,
            llm_calls=0,
        )

    def propose_bounded_subgoals(
        self,
        goal: Union[CapabilityGap, Mapping[str, Any], str],
        security_context: SecurityContext,
        *,
        max_subgoals: int = 8,
        sandbox_available: Optional[bool] = None,
    ) -> SubgoalProposalResult:
        """
        Propose bounded subgoals strictly serving `goal` ONLY, never expanding permissions,
        network access, or untrusted native privileges beyond `security_context`.
        """
        sec_err = _verify_security_context_integrity(security_context)
        if sec_err is not None:
            return SubgoalProposalResult(
                goal_id="unknown",
                status=STATUS_PERMISSION_DENIED,
                subgoals=[],
                permission_expansion_blocked=True,
                reasons=[sec_err],
            )

        try:
            _check_input_hygiene(goal if not isinstance(goal, CapabilityGap) else goal.to_dict(), path="goal")
        except ValueError as exc:
            return SubgoalProposalResult(
                goal_id="rejected_goal",
                status=STATUS_PERMISSION_DENIED,
                subgoals=[],
                permission_expansion_blocked=True,
                reasons=[str(exc)],
                allowed_permissions_ceiling=list(security_context.allowed_permissions),
                network_allowed_ceiling=security_context.network_allowed,
                allow_untrusted_native_ceiling=security_context.allow_untrusted_native,
            )

        if isinstance(goal, CapabilityGap):
            goal_id = goal.goal_id
            req_caps = list(goal.required_capabilities)
            requested_perms: List[str] = []
            network_requested = False
            native_requested = False
        elif isinstance(goal, Mapping):
            goal_id = str(goal.get("goal_id") or goal.get("id") or "goal-bounded").strip()
            req_caps = [str(c) for c in (goal.get("required_capabilities") or [])]
            if not req_caps and goal.get("capability"):
                req_caps = [str(goal["capability"])]
            requested_perms = [str(p) for p in (goal.get("requested_permissions") or goal.get("required_permissions") or [])]
            network_requested = bool(goal.get("network_required") or goal.get("network_allowed"))
            native_requested = bool(goal.get("allow_untrusted_native") or goal.get("untrusted_native"))
        elif isinstance(goal, str):
            goal_id = f"goal-{sha256_digest(goal).split(':', 1)[1][:8]}"
            req_caps = [goal.strip()] if "." in goal else []
            requested_perms = []
            network_requested = False
            native_requested = False
        else:
            raise ValueError("INVALID_GOAL: expected CapabilityGap, mapping, or str.")

        allowed_set = set(security_context.allowed_permissions)
        expansion_reasons: List[str] = []
        extra_perms = sorted(set(requested_perms) - allowed_set)
        if extra_perms:
            expansion_reasons.append(f"PERMISSION_EXPANSION_BLOCKED:{','.join(extra_perms)}")
        if network_requested and not security_context.network_allowed:
            expansion_reasons.append("NETWORK_EXPANSION_BLOCKED")
        if native_requested and not security_context.allow_untrusted_native:
            expansion_reasons.append("UNTRUSTED_NATIVE_EXPANSION_BLOCKED")

        if expansion_reasons:
            return SubgoalProposalResult(
                goal_id=goal_id,
                status=STATUS_PERMISSION_DENIED,
                subgoals=[],
                permission_expansion_blocked=True,
                reasons=expansion_reasons,
                allowed_permissions_ceiling=list(security_context.allowed_permissions),
                network_allowed_ceiling=security_context.network_allowed,
                allow_untrusted_native_ceiling=security_context.allow_untrusted_native,
            )

        readiness = self.query_readiness(
            req_caps, security_context, sandbox_available=sandbox_available
        )

        cap_limit = max(1, int(max_subgoals))
        if security_context.profile == SecurityProfile.GITHUB_PUBLIC:
            cap_limit = min(cap_limit, 4)

        subgoals: List[Dict[str, Any]] = []
        for idx, cap in enumerate(req_caps[:cap_limit]):
            cap_info = readiness.per_capability.get(cap, {})
            cap_status = cap_info.get("status", STATUS_NO_VERIFIED_TOOL)
            selected_tid = cap_info.get("selected_tool_id")

            if cap_status == STATUS_VERIFIED and selected_tid:
                tool_entry = next(
                    (e for e in self.available_capabilities.get(cap, []) if e.get("tool_id") == selected_tid),
                    {},
                )
                perms = sorted(set(tool_entry.get("required_permissions") or []) & allowed_set)
                action = "execute_verified_capability"
            elif cap_status == STATUS_INSUFFICIENT_EVIDENCE and selected_tid:
                tool_entry = next(
                    (e for e in self.available_capabilities.get(cap, []) if e.get("tool_id") == selected_tid),
                    {},
                )
                perms = sorted(set(tool_entry.get("required_permissions") or []) & allowed_set)
                action = "collect_sandbox_test_evidence"
            elif cap_status == STATUS_SANDBOX_UNAVAILABLE:
                perms = []
                action = "abstain_sandbox_unavailable"
            elif cap_status == STATUS_PERMISSION_DENIED:
                perms = []
                action = "abstain_permission_insufficient"
            else:
                has_discovered = any(
                    u.get("kind") == "unverified_discovered_tool" and cap in str(u.get("detail", ""))
                    for u in self.known_unknowns
                )
                perms = sorted({"fs.read"} & allowed_set)
                action = "verify_discovered_tool" if has_discovered else "discover_or_forge_capability"

            subgoals.append(
                {
                    "subgoal_id": f"{goal_id}::sg-{idx + 1}",
                    "parent_goal_id": goal_id,
                    "serves_current_goal_only": True,
                    "capability": cap,
                    "action": action,
                    "readiness_status": cap_status,
                    "tool_id": selected_tid,
                    "required_permissions": perms,
                    "network_allowed": False if not security_context.network_allowed else network_requested,
                    "allow_untrusted_native": False,
                }
            )

        return SubgoalProposalResult(
            goal_id=goal_id,
            status=readiness.status if req_caps else STATUS_INSUFFICIENT_EVIDENCE,
            subgoals=subgoals,
            permission_expansion_blocked=False,
            reasons=list(readiness.blocking_reasons),
            allowed_permissions_ceiling=list(security_context.allowed_permissions),
            network_allowed_ceiling=security_context.network_allowed,
            allow_untrusted_native_ceiling=security_context.allow_untrusted_native,
        )


__all__ = [
    "DEFAULT_SELF_MODEL_REL_PATH",
    "SELF_MODEL_SCHEMA",
    "READINESS_REPORT_SCHEMA",
    "SUBGOAL_PROPOSAL_SCHEMA",
    "STATUS_VERIFIED",
    "STATUS_NO_VERIFIED_TOOL",
    "STATUS_INSUFFICIENT_EVIDENCE",
    "STATUS_SANDBOX_UNAVAILABLE",
    "STATUS_PERMISSION_DENIED",
    "VALID_READINESS_STATUSES",
    "compute_honest_test_confidence",
    "ReadinessReport",
    "SubgoalProposalResult",
    "FunctionalSelfModel",
]
