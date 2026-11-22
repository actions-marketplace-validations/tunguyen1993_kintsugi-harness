"""Persistent, redacted, policy-isolated Tool Experience Memory (`kintsugi.runtime.experience_store`)."""

from __future__ import annotations

import copy
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple, Union

from kintsugi.capability.schemas import (
    Experience,
    SecurityProfile,
    assert_no_raw_secrets,
    canonical_json_dumps,
    normalize_sha256,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
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

DEFAULT_EXPERIENCE_STORE_REL_PATH = ".kintsugi/experience_store.json"

_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_PROVENANCE_FIELDS: FrozenSet[str] = frozenset(
    {
        "policy_hash",
        "oracle_hash",
        "oracle_ref",
        "schema_hash",
        "runtime_version",
        "tool_hashes",
    }
)
_FORBIDDEN_POLICY_KEYS: FrozenSet[str] = frozenset(
    {
        "security_context",
        "allowed_permissions",
        "network_allowed",
        "allow_untrusted_native",
        "trusted_tool_roots",
        "policy_hash",
        "policy_override",
        "disable_guardrails",
        "skip_verification",
        "bypass_scars",
        "block_threshold",
        "trusted_workspace_root",
        "env_override",
        "elevate_privileges",
        "operating_profile",
        "security",
        "limits",
        "policy",
        *SECURITY_BASELINE_VALUES.keys(),
    }
)


def _normalize_security_profile(val: Any) -> SecurityProfile:
    if isinstance(val, SecurityProfile):
        return val
    raw = str(val or SecurityProfile.LOCAL_RESEARCH.value).strip().upper()
    return SecurityProfile(raw)


def _check_no_policy_mutation_keys(obj: Any, path: str = "root") -> None:
    """Reject any attempt by experience entries to embed or override SecurityContext policies."""
    if isinstance(obj, Mapping):
        for k, v in obj.items():
            key_norm = str(k).strip().lower()
            if key_norm in _FORBIDDEN_POLICY_KEYS:
                raise ValueError(
                    f"EXPERIENCE_POLICY_MUTATION_BLOCKED: forbidden key '{key_norm}' at {path}"
                )
            _check_no_policy_mutation_keys(v, f"{path}.{key_norm}")
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            _check_no_policy_mutation_keys(item, f"{path}[{idx}]")


def _check_no_injection_or_trojan(obj: Any) -> None:
    if isinstance(obj, str):
        if TROJAN_UNICODE_RE.search(obj):
            raise ValueError("EXPERIENCE_TROJAN_UNICODE_BLOCKED")
        if PROMPT_INJECTION_RE.search(obj):
            raise ValueError("EXPERIENCE_PROMPT_INJECTION_BLOCKED")
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            _check_no_injection_or_trojan(str(k))
            _check_no_injection_or_trojan(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _check_no_injection_or_trojan(item)


def _sanitize_provenance_record(
    raw_provenance: Optional[Mapping[str, Any]] = None,
    *,
    policy_hash: Optional[str] = None,
    oracle_hash: Optional[str] = None,
    oracle_ref: Optional[str] = None,
    schema_hash: Optional[str] = None,
    runtime_version: Optional[str] = None,
    tool_hashes: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Validate and normalize read-only cache-key provenance without permitting policy mutations."""
    src = dict(raw_provenance or {})
    _check_no_injection_or_trojan(src)

    clean: Dict[str, Any] = {}
    for hash_key, explicit_val in (
        ("policy_hash", policy_hash),
        ("oracle_hash", oracle_hash),
        ("schema_hash", schema_hash),
    ):
        raw_val = explicit_val if explicit_val is not None else src.get(hash_key)
        if raw_val is not None and str(raw_val).strip():
            clean[hash_key] = normalize_sha256(str(raw_val), field_name=hash_key)

    for text_key, explicit_val in (
        ("oracle_ref", oracle_ref),
        ("runtime_version", runtime_version),
    ):
        raw_val = explicit_val if explicit_val is not None else src.get(text_key)
        if raw_val is not None and str(raw_val).strip():
            clean[text_key] = redact_runtime_text(
                validate_safe_text(str(raw_val), field_name=text_key)
            )

    raw_th = tool_hashes if tool_hashes is not None else src.get("tool_hashes")
    if raw_th is not None:
        if not isinstance(raw_th, Mapping):
            raise ValueError("EXPERIENCE_INVALID_PROVENANCE_TOOL_HASHES")
        normalized_th: Dict[str, str] = {}
        for tid, th in raw_th.items():
            safe_tid = validate_tool_id(str(tid))
            normalized_th[safe_tid] = normalize_sha256(str(th), field_name="tool_hash")
        if normalized_th:
            clean["tool_hashes"] = normalized_th

    return clean


def _dedup_key_for_experience(
    exp: Experience,
    provenance: Optional[Mapping[str, Any]] = None,
) -> str:
    cap = str(exp.input_characteristics.get("capability") or exp.failure_class)
    core: Dict[str, Any] = {
        "task_fingerprint": exp.task_fingerprint,
        "capability": cap,
        "security_profile": exp.security_profile.value,
        "tool_or_plan_id": exp.tool_or_plan_id,
        "tool_hash": exp.tool_hash,
    }
    if provenance:
        core["provenance"] = dict(provenance)
    return sha256_digest(core).split(":", 1)[1]


def _extract_wall_time_ms(cost: Any) -> float:
    if isinstance(cost, Mapping):
        return float(cost.get("wall_time_ms", 0.0) or 0.0)
    if isinstance(cost, (int, float)):
        return float(cost)
    return 0.0


class ExperienceStore:
    """Symlink-safe, redacted, provenance-checked experience store at `.kintsugi/experience_store.json`."""

    SCHEMA_VERSION = "1.0"

    def __init__(
        self,
        path: Path | str = DEFAULT_EXPERIENCE_STORE_REL_PATH,
        *,
        workspace_root: Optional[Path | str] = None,
    ) -> None:
        raw_path = Path(path)
        if workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            ws_resolved = ws.resolve()
            if not raw_path.is_absolute():
                confined = resolve_safe_child_path(ws_resolved, str(raw_path))
                if confined is None:
                    raise PermissionError("EXPERIENCE_STORE_PATH_OUTSIDE_WORKSPACE")
                self.path = confined
            else:
                try:
                    raw_path.resolve().relative_to(ws_resolved)
                except ValueError as exc:
                    raise PermissionError("EXPERIENCE_STORE_PATH_OUTSIDE_WORKSPACE") from exc
                self.path = raw_path
        else:
            self.path = raw_path

        self._entries: Dict[str, Experience] = {}
        self._provenance: Dict[str, Dict[str, Any]] = {}
        self.quarantined: List[Tuple[str, str]] = []
        self.last_invalidation_reasons: Dict[str, str] = {}
        self._assert_store_paths_not_symlink()
        if self.path.exists():
            self.load()

    def _assert_store_paths_not_symlink(self) -> None:
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)

    def _sanitize_and_validate(
        self,
        raw_entry: Any,
        *,
        policy_hash: Optional[str] = None,
        oracle_hash: Optional[str] = None,
        oracle_ref: Optional[str] = None,
        schema_hash: Optional[str] = None,
        runtime_version: Optional[str] = None,
        tool_hashes: Optional[Mapping[str, str]] = None,
        stored_provenance: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[Experience, Dict[str, Any]]:
        if isinstance(raw_entry, Experience):
            raw_map = raw_entry.to_dict()
        elif isinstance(raw_entry, Mapping):
            raw_map = dict(raw_entry)
        elif hasattr(raw_entry, "to_dict"):
            raw_map = dict(raw_entry.to_dict())
        else:
            raise ValueError("INVALID_EXPERIENCE_ENTRY: expected Experience or mapping")

        # Extract top-level / explicit cache-key provenance before policy-mutation scanning.
        # Embedded policy keys inside `input_characteristics` or `cost` remain strictly blocked.
        top_provenance: Dict[str, Any] = {}
        if isinstance(stored_provenance, Mapping):
            top_provenance.update(stored_provenance)
        raw_nested_prov = raw_map.pop("provenance", None)
        if isinstance(raw_nested_prov, Mapping):
            for k in _PROVENANCE_FIELDS:
                if k in raw_nested_prov:
                    top_provenance[k] = raw_nested_prov[k]
            extra_nested = {k: v for k, v in raw_nested_prov.items() if k not in _PROVENANCE_FIELDS}
            _check_no_policy_mutation_keys(extra_nested, path="root.provenance")
        elif raw_nested_prov is not None:
            raise ValueError("INVALID_EXPERIENCE_PROVENANCE: expected mapping")

        for k in _PROVENANCE_FIELDS:
            if k in raw_map:
                top_provenance[k] = raw_map.pop(k)

        raw_ic = raw_map.get("input_characteristics")
        if isinstance(raw_ic, Mapping):
            for non_policy_key in ("oracle_hash", "oracle_ref", "schema_hash", "runtime_version", "tool_hashes"):
                if non_policy_key in raw_ic and non_policy_key not in top_provenance:
                    top_provenance[non_policy_key] = raw_ic[non_policy_key]

        _check_no_policy_mutation_keys(raw_map)
        _check_no_injection_or_trojan(raw_map)

        clean_prov = _sanitize_provenance_record(
            top_provenance,
            policy_hash=policy_hash,
            oracle_hash=oracle_hash,
            oracle_ref=oracle_ref,
            schema_hash=schema_hash,
            runtime_version=runtime_version,
            tool_hashes=tool_hashes,
        )

        schema = str(raw_map.get("schema") or "Experience/1")
        if schema != "Experience/1":
            raise ValueError(f"UNSUPPORTED_EXPERIENCE_SCHEMA: {schema}")

        task_fingerprint = redact_runtime_text(str(raw_map.get("task_fingerprint") or "").strip())
        failure_class = redact_runtime_text(
            str(raw_map.get("failure_class") or raw_map.get("capability") or "").strip()
        )
        tool_or_plan_id = str(
            raw_map.get("tool_or_plan_id") or raw_map.get("tool_id") or ""
        ).strip()
        if not task_fingerprint or not failure_class or not tool_or_plan_id:
            raise ValueError("EXPERIENCE_MISSING_REQUIRED_FIELDS")
        if not _SAFE_IDENTIFIER_RE.fullmatch(tool_or_plan_id):
            raise ValueError(f"EXPERIENCE_INVALID_TOOL_ID: {tool_or_plan_id!r}")

        raw_tool_hash = str(raw_map.get("tool_hash") or "").strip()
        tool_hash = normalize_sha256(raw_tool_hash, field_name="tool_hash") if raw_tool_hash else ""
        raw_trace_hash = str(raw_map.get("trace_hash") or raw_map.get("receipt_digest") or "").strip()
        trace_hash = normalize_sha256(raw_trace_hash, field_name="trace_hash") if raw_trace_hash else ""

        sec_profile = _normalize_security_profile(
            raw_map.get("security_profile") or SecurityProfile.LOCAL_RESEARCH
        )

        if "verified_outcome" in raw_map:
            verified_outcome = raw_map["verified_outcome"]
        elif "verification_status" in raw_map:
            verified_outcome = str(raw_map["verification_status"]).strip().upper()
        else:
            verified_outcome = False

        input_chars = redact_runtime_value(dict(raw_map.get("input_characteristics") or {}))
        if raw_map.get("capability") and "capability" not in input_chars:
            input_chars["capability"] = redact_runtime_text(str(raw_map["capability"]))

        raw_cost = raw_map.get("cost")
        if raw_cost is None:
            cost: Union[Dict[str, Any], float, int] = {}
        elif isinstance(raw_cost, Mapping):
            cost = redact_runtime_value(dict(raw_cost))
        else:
            cost = float(raw_cost)

        failure_reasons = [
            redact_runtime_text(str(r))
            for r in (raw_map.get("failure_reasons") or [])
            if str(r).strip()
        ]
        transfer_evidence = redact_runtime_value(
            list(raw_map.get("cross_task_transfer_evidence") or [])
        )
        reuse_count = max(0, int(raw_map.get("reuse_count", 0)))

        exp = Experience(
            task_fingerprint=task_fingerprint,
            failure_class=failure_class,
            tool_or_plan_id=tool_or_plan_id,
            input_characteristics=input_chars,
            verified_outcome=verified_outcome,
            cost=cost,
            failure_reasons=failure_reasons,
            reuse_count=reuse_count,
            cross_task_transfer_evidence=transfer_evidence,
            trace_hash=trace_hash,
            tool_hash=tool_hash,
            security_profile=sec_profile,
            schema="Experience/1",
        )

        serialized = exp.to_canonical_json()
        assert_no_raw_secrets(serialized, context="ExperienceStore")
        egress = scan_artifact_egress(serialized, context="experience_store")
        if not egress.get("ok"):
            raise ValueError("EXPERIENCE_RESIDUAL_SECRET_BLOCKED")
        if clean_prov:
            assert_no_raw_secrets(canonical_json_dumps(clean_prov), context="ExperienceStore.provenance")
        return exp, clean_prov

    def load(self) -> None:
        """Load persisted experiences safely using `assert_not_symlink` and `O_NOFOLLOW`."""
        self._assert_store_paths_not_symlink()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise PermissionError(f"EXPERIENCE_STORE_OPEN_REFUSED: {exc}") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError("EXPERIENCE_STORE_NOT_REGULAR_FILE")
            raw = json.load(handle)

        if not isinstance(raw, Mapping):
            raise ValueError("EXPERIENCE_STORE_CORRUPT_ROOT")
        entries = raw.get("experiences", [])
        if not isinstance(entries, list):
            raise ValueError("EXPERIENCE_STORE_CORRUPT_ENTRIES")
        prov_index = raw.get("provenance_index") or {}
        if not isinstance(prov_index, Mapping):
            raise ValueError("EXPERIENCE_STORE_CORRUPT_PROVENANCE")

        self._entries.clear()
        self._provenance.clear()
        self.quarantined.clear()
        claimed_prov_keys: set[str] = set()
        for idx, item in enumerate(entries):
            try:
                raw_item_prov: Optional[Mapping[str, Any]] = None
                matched_p_key: Optional[str] = None
                if isinstance(item, Mapping):
                    prelim_exp, prelim_prov = self._sanitize_and_validate(item)
                    legacy_key = _dedup_key_for_experience(prelim_exp, None)
                    full_key = _dedup_key_for_experience(prelim_exp, prelim_prov or None)
                    for k_cand in (full_key, legacy_key):
                        if (
                            k_cand not in claimed_prov_keys
                            and k_cand in prov_index
                            and isinstance(prov_index[k_cand], Mapping)
                        ):
                            raw_item_prov = prov_index[k_cand]
                            matched_p_key = k_cand
                            break
                    if raw_item_prov is None:
                        for p_key, p_val in sorted(prov_index.items()):
                            if p_key in claimed_prov_keys or not isinstance(p_val, Mapping):
                                continue
                            if _dedup_key_for_experience(prelim_exp, p_val) == p_key:
                                raw_item_prov = p_val
                                matched_p_key = p_key
                                break
                exp, prov = self._sanitize_and_validate(item, stored_provenance=raw_item_prov)
            except (ValueError, KeyError, TypeError) as exc:
                entry_id = (
                    str(item.get("task_fingerprint", f"idx_{idx}"))
                    if isinstance(item, Mapping)
                    else f"idx_{idx}"
                )
                self.quarantined.append((entry_id, str(exc)))
                continue
            dedup_key = _dedup_key_for_experience(exp, prov or None)
            if matched_p_key is not None:
                claimed_prov_keys.add(matched_p_key)
            elif prov:
                claimed_prov_keys.add(dedup_key)
            self._entries[dedup_key] = exp
            if prov:
                self._provenance[dedup_key] = prov

    def save(self) -> None:
        """Persist experience store atomically to disk with mode `0o600`."""
        self._assert_store_paths_not_symlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(
            self._entries.values(),
            key=lambda e: (e.failure_class, e.tool_or_plan_id, e.task_fingerprint),
        )
        payload: Dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "total_experiences": len(ordered),
            "experiences": [e.to_dict() for e in ordered],
        }
        if self._provenance:
            payload["provenance_index"] = {
                k: copy.deepcopy(v) for k, v in sorted(self._provenance.items()) if k in self._entries and v
            }
        assert_no_raw_secrets(canonical_json_dumps(payload), context="ExperienceStore.save")
        atomic_write_json(self.path, payload, mode=0o600, indent=2)

    def record(
        self,
        experience: Union[Experience, Mapping[str, Any]],
        *,
        policy_hash: Optional[str] = None,
        oracle_hash: Optional[str] = None,
        oracle_ref: Optional[str] = None,
        schema_hash: Optional[str] = None,
        runtime_version: Optional[str] = None,
        tool_hashes: Optional[Mapping[str, str]] = None,
    ) -> Experience:
        """Validate, redact, deduplicate/increment `reuse_count`, bind provenance, and persist atomically."""
        clean_exp, clean_prov = self._sanitize_and_validate(
            experience,
            policy_hash=policy_hash,
            oracle_hash=oracle_hash,
            oracle_ref=oracle_ref,
            schema_hash=schema_hash,
            runtime_version=runtime_version,
            tool_hashes=tool_hashes,
        )
        key = _dedup_key_for_experience(clean_exp, clean_prov or None)

        if key in self._entries:
            existing = self._entries[key]
            existing.reuse_count += 1
            if clean_exp.trace_hash:
                existing.trace_hash = clean_exp.trace_hash
            new_ms = _extract_wall_time_ms(clean_exp.cost)
            if isinstance(existing.cost, dict) and new_ms > 0:
                prev_ms = float(existing.cost.get("wall_time_ms", 0.0) or 0.0)
                existing.cost["wall_time_ms"] = min(prev_ms, new_ms) if prev_ms > 0 else new_ms
            for ev in clean_exp.cross_task_transfer_evidence:
                if ev not in existing.cross_task_transfer_evidence and len(existing.cross_task_transfer_evidence) < 50:
                    existing.cross_task_transfer_evidence.append(copy.deepcopy(ev))
            if clean_prov:
                self._provenance[key] = clean_prov
            self.save()
            return copy.deepcopy(existing)

        self._entries[key] = clean_exp
        if clean_prov:
            self._provenance[key] = clean_prov
        self.save()
        return copy.deepcopy(clean_exp)

    def _invalidation_reason(
        self,
        key: str,
        exp: Experience,
        *,
        current_tool_hashes: Optional[Mapping[str, str]] = None,
        current_policy_hash: Optional[str] = None,
        current_oracle_hash: Optional[str] = None,
        current_oracle_ref: Optional[str] = None,
        current_schema_hash: Optional[str] = None,
        retired_tool_ids: Optional[Iterable[str]] = None,
        runtime_version: Optional[str] = None,
    ) -> Optional[str]:
        prov = self._provenance.get(key, {})

        if retired_tool_ids is not None:
            retired_set = {str(tid).strip() for tid in retired_tool_ids if str(tid).strip()}
            if exp.tool_or_plan_id in retired_set:
                return "RETIRED_TOOL"
            for tid in (prov.get("tool_hashes") or {}):
                if tid in retired_set:
                    return "RETIRED_TOOL"

        if current_tool_hashes is not None:
            cur_map = {str(k).strip(): str(v).strip().lower() for k, v in current_tool_hashes.items()}
            rec_plan_hashes = prov.get("tool_hashes")
            if isinstance(rec_plan_hashes, Mapping) and rec_plan_hashes:
                for tid, rec_h in rec_plan_hashes.items():
                    cur_h = cur_map.get(str(tid).strip(), "")
                    if not cur_h or not hmac.compare_digest(str(rec_h).strip().lower(), cur_h):
                        return f"TOOL_HASH_CHANGED:{tid}"
            else:
                cur_h = cur_map.get(exp.tool_or_plan_id, "")
                rec_h = (exp.tool_hash or "").strip().lower()
                if not cur_h or not rec_h or not hmac.compare_digest(rec_h, cur_h):
                    return f"TOOL_HASH_CHANGED:{exp.tool_or_plan_id}"

        if current_policy_hash is not None:
            rec_pol = str(prov.get("policy_hash") or "").strip().lower()
            cur_pol = str(current_policy_hash).strip().lower()
            if not rec_pol or not cur_pol or not hmac.compare_digest(rec_pol, cur_pol):
                return "POLICY_HASH_CHANGED"

        if current_oracle_hash is not None:
            rec_ora = str(prov.get("oracle_hash") or "").strip().lower()
            cur_ora = str(current_oracle_hash).strip().lower()
            if not rec_ora or not cur_ora or not hmac.compare_digest(rec_ora, cur_ora):
                return "ORACLE_HASH_CHANGED"

        if current_oracle_ref is not None:
            rec_ref = str(prov.get("oracle_ref") or "").strip()
            cur_ref = str(current_oracle_ref).strip()
            if not rec_ref or not cur_ref or rec_ref != cur_ref:
                return "ORACLE_REF_CHANGED"

        if current_schema_hash is not None:
            rec_sch = str(prov.get("schema_hash") or "").strip().lower()
            cur_sch = str(current_schema_hash).strip().lower()
            if not rec_sch or not cur_sch or not hmac.compare_digest(rec_sch, cur_sch):
                return "SCHEMA_HASH_CHANGED"

        if runtime_version is not None:
            rec_rt = str(prov.get("runtime_version") or "").strip()
            cur_rt = str(runtime_version).strip()
            if not rec_rt or not cur_rt or rec_rt != cur_rt:
                return "RUNTIME_VERSION_CHANGED"

        return None

    def invalidate_stale(
        self,
        *,
        current_tool_hashes: Optional[Mapping[str, str]] = None,
        current_policy_hash: Optional[str] = None,
        current_oracle_hash: Optional[str] = None,
        current_oracle_ref: Optional[str] = None,
        current_schema_hash: Optional[str] = None,
        retired_tool_ids: Optional[Iterable[str]] = None,
        runtime_version: Optional[str] = None,
    ) -> int:
        """Purge stale entries whose tool, policy, oracle, schema, runtime, or retired state changed."""
        removed = 0
        for key in list(self._entries.keys()):
            exp = self._entries[key]
            reason = self._invalidation_reason(
                key,
                exp,
                current_tool_hashes=current_tool_hashes,
                current_policy_hash=current_policy_hash,
                current_oracle_hash=current_oracle_hash,
                current_oracle_ref=current_oracle_ref,
                current_schema_hash=current_schema_hash,
                retired_tool_ids=retired_tool_ids,
                runtime_version=runtime_version,
            )
            if reason is not None:
                self._entries.pop(key, None)
                self._provenance.pop(key, None)
                self.last_invalidation_reasons[key] = reason
                removed += 1
        if removed > 0:
            self.save()
        return removed

    def retrieve_similar(
        self,
        *,
        task_fingerprint: Optional[str] = None,
        capability: Optional[str] = None,
        security_profile: Optional[Union[SecurityProfile, str]] = None,
        limit: int = 5,
        verified_only: bool = True,
        current_tool_hashes: Optional[Mapping[str, str]] = None,
        current_policy_hash: Optional[str] = None,
        current_oracle_hash: Optional[str] = None,
        current_oracle_ref: Optional[str] = None,
        current_schema_hash: Optional[str] = None,
        retired_tool_ids: Optional[Iterable[str]] = None,
        runtime_version: Optional[str] = None,
    ) -> List[Experience]:
        """Return ranked verified prior experiences matching fingerprint, profile, and live provenance."""
        norm_fp = str(task_fingerprint or "").strip()
        norm_cap = str(capability or "").strip()
        cap_domain = norm_cap.split(".", 1)[0] if norm_cap else ""
        target_profile = _normalize_security_profile(security_profile) if security_profile is not None else None
        self.last_invalidation_reasons.clear()

        scored: List[Tuple[Tuple[int, int, int, int, int, float], Experience]] = []
        for key, exp in self._entries.items():
            if verified_only and not exp.is_positive_verified:
                continue
            if target_profile is not None and exp.security_profile != target_profile:
                continue

            invalid_reason = self._invalidation_reason(
                key,
                exp,
                current_tool_hashes=current_tool_hashes,
                current_policy_hash=current_policy_hash,
                current_oracle_hash=current_oracle_hash,
                current_oracle_ref=current_oracle_ref,
                current_schema_hash=current_schema_hash,
                retired_tool_ids=retired_tool_ids,
                runtime_version=runtime_version,
            )
            if invalid_reason is not None:
                self.last_invalidation_reasons[key] = invalid_reason
                continue

            exp_cap = str(exp.input_characteristics.get("capability") or exp.failure_class)
            exact_fp = 1 if (norm_fp and exp.task_fingerprint == norm_fp) else 0
            exact_cap = 1 if (norm_cap and exp_cap == norm_cap) else 0
            prefix_cap = 1 if (cap_domain and not exact_cap and exp_cap.split(".", 1)[0] == cap_domain) else 0

            if (norm_fp or norm_cap) and (exact_fp == 0 and exact_cap == 0 and prefix_cap == 0):
                continue

            wall_ms = _extract_wall_time_ms(exp.cost)
            rank_key = (
                exact_fp,
                exact_cap,
                prefix_cap,
                int(exp.reuse_count),
                len(exp.cross_task_transfer_evidence),
                -wall_ms,
            )
            scored.append((rank_key, exp))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [copy.deepcopy(exp) for _, exp in scored[: max(0, int(limit))]]

    def list_experiences(self) -> List[Experience]:
        """Return deep copies of all stored experiences (compatible with `ToolResolver`)."""
        return [copy.deepcopy(exp) for exp in self._entries.values()]

    def all(self) -> List[Experience]:
        """Return deep copies of all stored experiences."""
        return self.list_experiences()

    @property
    def experiences(self) -> List[Experience]:
        return self.list_experiences()
