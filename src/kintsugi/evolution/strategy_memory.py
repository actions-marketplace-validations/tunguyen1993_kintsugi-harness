"""Stage 5 Tier-3 Causal Strategy Memory (`kintsugi.evolution.strategy_memory`).

Third memory tier alongside `ExperienceStore` (ToolMemory) and `CompositionMemory`.
Persists `.kintsugi/strategy_memory.json` with strict security invariants:
  - `assert_not_symlink` on directory and store file
  - `O_NOFOLLOW` + regular-file verification on load
  - Atomic `0o600` writes with secret, high-entropy, and user-path redaction
  - Policy-mutation & Trojan/Prompt-Injection quarantine
  - Causal cross-task transfer ranking immune to raw-volume replay inflation
"""

from __future__ import annotations

import copy
import math
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import (
    assert_no_raw_secrets,
    canonical_json_dumps,
    normalize_sha256,
    sha256_digest,
    validate_safe_text,
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

DEFAULT_STRATEGY_MEMORY_REL_PATH = ".kintsugi/strategy_memory.json"
STRATEGY_MEMORY_SCHEMA = "StrategyMemory/1"
STRATEGY_RECORD_SCHEMA = "StrategyRecord/1"

_MAX_TRACKED_KEYS = 500
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
        "env_override",
        "elevate_privileges",
        "mutate_hooks",
        "hooks_override",
        *SECURITY_BASELINE_VALUES.keys(),
    }
)
_FORBIDDEN_POLICY_STR_RE = re.compile(
    r"""["']?(?:""" + "|".join(re.escape(k) for k in sorted(_FORBIDDEN_POLICY_KEYS)) + r""")["']?\s*[:=]""",
    re.IGNORECASE,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_wilson_interval(successes: int, total: int, z: float = 1.96) -> Tuple[float, float]:
    """Compute honest 95% Wilson score confidence interval `(lower, upper)`."""
    if isinstance(successes, bool) or isinstance(total, bool) or not isinstance(successes, int) or not isinstance(total, int):
        raise ValueError("INVALID_WILSON_COUNTS: successes and total must be strict integers.")
    if successes < 0 or total < 0 or successes > total:
        raise ValueError(f"INVALID_WILSON_COUNTS: {successes}/{total} violates 0 <= successes <= total.")
    if total == 0:
        return 0.0, 1.0

    n = float(total)
    p = float(successes) / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = p + z2 / (2.0 * n)
    margin = z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)
    lb = max(0.0, min(1.0, (center - margin) / denom))
    ub = max(0.0, min(1.0, (center + margin) / denom))
    return round(lb, 6), round(ub, 6)


def _check_hygiene(obj: Any, *, path: str = "root") -> None:
    if isinstance(obj, str):
        if "\x00" in obj or TROJAN_UNICODE_RE.search(obj):
            raise ValueError(f"STRATEGY_MEMORY_TROJAN_UNICODE_BLOCKED at {path}")
        if PROMPT_INJECTION_RE.search(obj):
            raise ValueError(f"STRATEGY_MEMORY_PROMPT_INJECTION_BLOCKED at {path}")
        if _FORBIDDEN_POLICY_STR_RE.search(obj):
            raise ValueError(f"STRATEGY_MEMORY_POLICY_MUTATION_BLOCKED: embedded directive at {path}")
    elif isinstance(obj, Mapping):
        for k, v in obj.items():
            key_norm = str(k).strip().lower()
            if key_norm in _FORBIDDEN_POLICY_KEYS:
                raise ValueError(f"STRATEGY_MEMORY_POLICY_MUTATION_BLOCKED: '{key_norm}' at {path}")
            _check_hygiene(str(k), path=f"{path}.{key_norm}")
            _check_hygiene(v, path=f"{path}.{key_norm}")
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            _check_hygiene(item, path=f"{path}[{idx}]")


def _sanitize_text(value: Any, *, field_name: str, allow_empty: bool = False) -> str:
    cleaned = validate_safe_text(str(value if value is not None else ""), field_name=field_name, allow_empty=allow_empty)
    if PROMPT_INJECTION_RE.search(cleaned):
        raise ValueError(f"STRATEGY_MEMORY_PROMPT_INJECTION_BLOCKED ({field_name})")
    return redact_runtime_text(cleaned)


def _sanitize_key_list(items: Optional[Sequence[str]], *, field_name: str) -> List[str]:
    if not items:
        return []
    out: List[str] = []
    seen: set[str] = set()
    for raw in items:
        clean = _sanitize_text(raw, field_name=field_name, allow_empty=True)
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
            if len(out) >= _MAX_TRACKED_KEYS:
                break
    return out


def _derive_strategy_id(task_class: str, decomposition_pattern: str, synthesis_strategy: str) -> str:
    digest = sha256_digest(
        {
            "task_class": task_class,
            "decomposition_pattern": decomposition_pattern,
            "synthesis_strategy": synthesis_strategy,
        }
    ).split(":", 1)[1][:16]
    return f"strat:{digest}"


@dataclass
class StrategyRecord:
    """Persisted strategy performance and causal cross-task transfer record (`StrategyRecord/1`)."""

    task_class: str
    decomposition_pattern: str
    synthesis_strategy: str
    verified_passes: int = 0
    failures: int = 0
    mean_cost_ms: float = 0.0
    cross_task_transfer_successes: int = 0
    raw_observations: int = 0
    verified_task_keys: List[str] = field(default_factory=list)
    transfer_target_keys: List[str] = field(default_factory=list)
    failure_keys: List[str] = field(default_factory=list)
    last_verified_digest: str = ""
    updated_at: str = field(default_factory=_utc_now_iso)
    strategy_id: str = ""
    schema: str = STRATEGY_RECORD_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != STRATEGY_RECORD_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {STRATEGY_RECORD_SCHEMA}, got '{self.schema}'.")
        self.task_class = _sanitize_text(self.task_class, field_name="task_class")
        self.decomposition_pattern = _sanitize_text(self.decomposition_pattern, field_name="decomposition_pattern")
        self.synthesis_strategy = _sanitize_text(self.synthesis_strategy, field_name="synthesis_strategy")

        self.verified_task_keys = _sanitize_key_list(self.verified_task_keys, field_name="verified_task_keys")
        self.transfer_target_keys = _sanitize_key_list(self.transfer_target_keys, field_name="transfer_target_keys")
        self.failure_keys = _sanitize_key_list(self.failure_keys, field_name="failure_keys")

        self.verified_passes = max(0, int(self.verified_passes))
        self.failures = max(0, int(self.failures))
        self.cross_task_transfer_successes = max(0, int(self.cross_task_transfer_successes))
        self.raw_observations = max(0, int(self.raw_observations))

        # Bind counters to deduplicated evidence keys when keys are present so loaded records cannot inflate counts
        if self.verified_task_keys and self.verified_passes > len(self.verified_task_keys):
            self.verified_passes = len(self.verified_task_keys)
        if self.transfer_target_keys and self.cross_task_transfer_successes > len(self.transfer_target_keys):
            self.cross_task_transfer_successes = len(self.transfer_target_keys)
        if self.cross_task_transfer_successes > 0 and not self.transfer_target_keys:
            raise ValueError("INVALID_STRATEGY_RECORD: cross_task_transfer_successes requires transfer_target_keys evidence.")
        if self.verified_passes > 0 and not self.verified_task_keys:
            raise ValueError("INVALID_STRATEGY_RECORD: verified_passes requires verified_task_keys evidence.")

        cost = float(self.mean_cost_ms)
        if not math.isfinite(cost) or cost < 0.0:
            raise ValueError(f"INVALID_MEAN_COST_MS: {self.mean_cost_ms!r}")
        self.mean_cost_ms = round(cost, 4)

        if self.last_verified_digest:
            self.last_verified_digest = normalize_sha256(self.last_verified_digest, field_name="last_verified_digest")
        self.updated_at = _sanitize_text(self.updated_at or _utc_now_iso(), field_name="updated_at")
        expected_id = _derive_strategy_id(self.task_class, self.decomposition_pattern, self.synthesis_strategy)
        if self.strategy_id:
            clean_id = _sanitize_text(self.strategy_id, field_name="strategy_id")
            if clean_id != expected_id:
                raise ValueError(f"STRATEGY_ID_MISMATCH: {clean_id} != {expected_id}")
        self.strategy_id = expected_id

    @property
    def causal_transfer_score(self) -> float:
        """Causal-transfer-first score (`transfer_wilson_lb + 0.25 * pass_wilson_lb`) immune to raw volume."""
        transfer_trials = self.cross_task_transfer_successes + self.failures
        transfer_lb = (
            compute_wilson_interval(self.cross_task_transfer_successes, transfer_trials)[0]
            if self.cross_task_transfer_successes > 0 and transfer_trials > 0
            else 0.0
        )
        pass_trials = self.verified_passes + self.failures
        pass_lb = (
            compute_wilson_interval(self.verified_passes, pass_trials)[0]
            if self.verified_passes > 0 and pass_trials > 0
            else 0.0
        )
        return round(transfer_lb + 0.25 * pass_lb, 6)

    def ranking_key(self) -> Tuple[float, int, int, int, float, str]:
        """Deterministic descending-friendly key (sort with `reverse=False` via negated score/counts)."""
        return (
            -self.causal_transfer_score,
            -self.cross_task_transfer_successes,
            -self.verified_passes,
            self.failures,
            self.mean_cost_ms,
            self.strategy_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return redact_runtime_value(
            {
                "schema": self.schema,
                "strategy_id": self.strategy_id,
                "task_class": self.task_class,
                "decomposition_pattern": self.decomposition_pattern,
                "synthesis_strategy": self.synthesis_strategy,
                "verified_passes": self.verified_passes,
                "failures": self.failures,
                "mean_cost_ms": self.mean_cost_ms,
                "cross_task_transfer_successes": self.cross_task_transfer_successes,
                "causal_transfer_score": self.causal_transfer_score,
                "raw_observations": self.raw_observations,
                "verified_task_keys": list(self.verified_task_keys),
                "transfer_target_keys": list(self.transfer_target_keys),
                "failure_keys": list(self.failure_keys),
                "last_verified_digest": self.last_verified_digest,
                "updated_at": self.updated_at,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "StrategyRecord":
        if isinstance(data, StrategyRecord):
            return data
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_STRATEGY_RECORD: expected mapping.")
        return cls(
            task_class=data["task_class"],
            decomposition_pattern=data["decomposition_pattern"],
            synthesis_strategy=data["synthesis_strategy"],
            verified_passes=int(data.get("verified_passes", 0)),
            failures=int(data.get("failures", 0)),
            mean_cost_ms=float(data.get("mean_cost_ms", 0.0)),
            cross_task_transfer_successes=int(data.get("cross_task_transfer_successes", 0)),
            raw_observations=int(data.get("raw_observations", 0)),
            verified_task_keys=list(data.get("verified_task_keys") or []),
            transfer_target_keys=list(data.get("transfer_target_keys") or []),
            failure_keys=list(data.get("failure_keys") or []),
            last_verified_digest=str(data.get("last_verified_digest") or ""),
            updated_at=str(data.get("updated_at") or _utc_now_iso()),
            strategy_id=str(data.get("strategy_id") or ""),
            schema=str(data.get("schema") or STRATEGY_RECORD_SCHEMA),
        )


class StrategyMemory:
    """Symlink-safe, DLP-redacted causal strategy memory persisted at `.kintsugi/strategy_memory.json`."""

    SCHEMA_VERSION = STRATEGY_MEMORY_SCHEMA

    def __init__(
        self,
        path: Union[Path, str] = DEFAULT_STRATEGY_MEMORY_REL_PATH,
        *,
        workspace_root: Optional[Union[Path, str]] = None,
    ) -> None:
        raw_path = Path(path)
        self._ws_resolved: Optional[Path] = None
        if workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            ws_resolved = ws.resolve()
            self._ws_resolved = ws_resolved
            if not raw_path.is_absolute():
                confined = resolve_safe_child_path(ws_resolved, str(raw_path))
                if confined is None:
                    raise PermissionError("STRATEGY_MEMORY_PATH_OUTSIDE_WORKSPACE")
                self.path = confined
            else:
                try:
                    raw_path.resolve().relative_to(ws_resolved)
                except ValueError as exc:
                    raise PermissionError("STRATEGY_MEMORY_PATH_OUTSIDE_WORKSPACE") from exc
                self.path = raw_path
        else:
            self.path = raw_path

        self._records: Dict[str, StrategyRecord] = {}
        self.quarantined: List[Tuple[str, str]] = []
        self._assert_store_paths_not_symlink()
        if self.path.exists():
            self.load()

    def _assert_store_paths_not_symlink(self) -> None:
        if self._ws_resolved is not None:
            try:
                rel = self.path.relative_to(self._ws_resolved)
            except ValueError:
                rel = None
            if rel is not None:
                cur = self._ws_resolved
                for part in rel.parts:
                    cur = cur / part
                    if cur.exists() or cur.is_symlink():
                        assert_not_symlink(cur)
                return
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)

    def load(self) -> None:
        """Load strategy records safely with `assert_not_symlink`, `O_NOFOLLOW`, and quarantine."""
        self._assert_store_paths_not_symlink()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise PermissionError(f"STRATEGY_MEMORY_OPEN_REFUSED: {exc}") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError("STRATEGY_MEMORY_NOT_REGULAR_FILE")
            raw = json_load_handle(handle)

        if not isinstance(raw, Mapping):
            raise ValueError("STRATEGY_MEMORY_CORRUPT_ROOT")
        raw_records = raw.get("strategies", [])
        if not isinstance(raw_records, list):
            raise ValueError("STRATEGY_MEMORY_CORRUPT_STRATEGIES")

        self._records.clear()
        self.quarantined.clear()
        for idx, item in enumerate(raw_records):
            try:
                _check_hygiene(item, path=f"strategies[{idx}]")
                serialized = canonical_json_dumps(item)
                assert_no_raw_secrets(serialized, context=f"StrategyMemory.load[{idx}]")
                egress = scan_artifact_egress(serialized, context="strategy_memory_load")
                if not egress.get("ok"):
                    raise ValueError("STRATEGY_MEMORY_SECRET_LEAK_BLOCKED")
                rec = StrategyRecord.from_dict(item)
                self._records[rec.strategy_id] = rec
            except (ValueError, KeyError, TypeError) as exc:
                label = (
                    str(item.get("strategy_id") or item.get("task_class") or f"idx_{idx}")
                    if isinstance(item, Mapping)
                    else f"idx_{idx}"
                )
                self.quarantined.append((label, str(exc)))

    def save(self) -> None:
        """Persist strategy memory atomically to `.kintsugi/strategy_memory.json` with mode `0o600`."""
        self._assert_store_paths_not_symlink()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(self._records.values(), key=lambda r: r.ranking_key())
        payload = {
            "schema": self.SCHEMA_VERSION,
            "total_strategies": len(ordered),
            "strategies": [r.to_dict() for r in ordered],
        }
        serialized = canonical_json_dumps(payload)
        assert_no_raw_secrets(serialized, context="StrategyMemory.save")
        egress = scan_artifact_egress(serialized, context="strategy_memory_save")
        if not egress.get("ok"):
            raise ValueError("STRATEGY_MEMORY_RESIDUAL_SECRET_BLOCKED")
        atomic_write_json(self.path, payload, mode=0o600, indent=2)

    def record_outcome(
        self,
        *,
        task_class: str,
        decomposition_pattern: str,
        synthesis_strategy: str,
        verified_outcome: Optional[Union[bool, str]],
        cost_ms: float = 0.0,
        task_id: str = "",
        source_task_id: str = "",
        source_family: str = "",
        target_family: str = "",
        evidence_digest: str = "",
        is_cross_task_transfer: bool = False,
        causal_verified: bool = False,
        failure_reason: str = "",
    ) -> StrategyRecord:
        """Record a strategy observation, deduplicating by task/evidence so raw volume cannot inflate rank."""
        _check_hygiene(
            {
                "task_class": task_class,
                "decomposition_pattern": decomposition_pattern,
                "synthesis_strategy": synthesis_strategy,
                "task_id": task_id,
                "source_task_id": source_task_id,
                "source_family": source_family,
                "target_family": target_family,
                "failure_reason": failure_reason,
            },
            path="record_outcome",
        )
        clean_task_class = _sanitize_text(task_class, field_name="task_class")
        clean_decomp = _sanitize_text(decomposition_pattern, field_name="decomposition_pattern")
        clean_synth = _sanitize_text(synthesis_strategy, field_name="synthesis_strategy")
        sid = _derive_strategy_id(clean_task_class, clean_decomp, clean_synth)

        existing = self._records.get(sid)
        if existing is None:
            existing = StrategyRecord(
                task_class=clean_task_class,
                decomposition_pattern=clean_decomp,
                synthesis_strategy=clean_synth,
                strategy_id=sid,
            )

        obs_cost = float(cost_ms)
        if not math.isfinite(obs_cost) or obs_cost < 0.0:
            raise ValueError(f"INVALID_COST_MS: {cost_ms!r}")

        prev_n = existing.raw_observations
        new_n = prev_n + 1
        existing.mean_cost_ms = round(((existing.mean_cost_ms * prev_n) + obs_cost) / float(new_n), 4)
        existing.raw_observations = new_n
        existing.updated_at = _utc_now_iso()

        clean_task = _sanitize_text(task_id, field_name="task_id", allow_empty=True)
        clean_src_task = _sanitize_text(source_task_id, field_name="source_task_id", allow_empty=True)
        clean_src_fam = _sanitize_text(source_family, field_name="source_family", allow_empty=True)
        clean_tgt_fam = _sanitize_text(target_family, field_name="target_family", allow_empty=True)
        clean_ev_digest = (
            normalize_sha256(evidence_digest, field_name="evidence_digest")
            if evidence_digest
            else ""
        )
        clean_fail = _sanitize_text(failure_reason, field_name="failure_reason", allow_empty=True)

        outcome_norm: Optional[bool]
        if isinstance(verified_outcome, bool):
            outcome_norm = verified_outcome
        elif isinstance(verified_outcome, str):
            up = verified_outcome.strip().upper()
            outcome_norm = True if up in {"PASS", "VERIFIED", "TRUE"} else (False if up in {"FAIL", "FAILED", "FALSE"} else None)
        else:
            outcome_norm = None

        dedup_subject = clean_task or clean_tgt_fam or (clean_ev_digest[:24] if clean_ev_digest else "") or f"default:{sid}"

        if outcome_norm is True:
            pass_key = f"{dedup_subject}:{clean_tgt_fam}" if clean_tgt_fam else dedup_subject
            if pass_key not in existing.verified_task_keys and len(existing.verified_task_keys) < _MAX_TRACKED_KEYS:
                existing.verified_task_keys.append(pass_key)
                existing.verified_passes = len(existing.verified_task_keys)
            if clean_ev_digest:
                existing.last_verified_digest = clean_ev_digest

            # Causal cross-task transfer requires explicit causal verification AND distinct target vs source
            distinct_from_source = (
                (bool(clean_src_task) and bool(clean_task) and clean_src_task != clean_task)
                or (bool(clean_src_fam) and bool(clean_tgt_fam) and clean_src_fam != clean_tgt_fam)
                or (not clean_src_task and not clean_src_fam and bool(clean_task or clean_tgt_fam))
            )
            if is_cross_task_transfer and causal_verified and distinct_from_source:
                transfer_key = f"{clean_src_fam or clean_src_task}->{dedup_subject}:{clean_tgt_fam}"
                if transfer_key not in existing.transfer_target_keys and len(existing.transfer_target_keys) < _MAX_TRACKED_KEYS:
                    existing.transfer_target_keys.append(transfer_key)
                    existing.cross_task_transfer_successes = len(existing.transfer_target_keys)

        elif outcome_norm is False:
            fail_sig = clean_fail or (clean_ev_digest[:24] if clean_ev_digest else "failed")
            fail_key = f"{dedup_subject}:{fail_sig}"
            if fail_key not in existing.failure_keys and len(existing.failure_keys) < _MAX_TRACKED_KEYS:
                existing.failure_keys.append(fail_key)
                existing.failures = len(existing.failure_keys)

        # Unverified outcomes (`outcome_norm is None`) never increment passes or transfers
        self._records[sid] = existing
        self.save()
        return copy.deepcopy(existing)

    def rank_strategies(
        self,
        task_class: Optional[str] = None,
        *,
        decomposition_pattern: Optional[str] = None,
        require_verified_transfer: bool = False,
    ) -> List[StrategyRecord]:
        """Return persisted strategies ordered by verified causal transfer outcome."""
        norm_tc = task_class.strip() if task_class else None
        norm_dec = decomposition_pattern.strip() if decomposition_pattern else None
        candidates: List[StrategyRecord] = []
        for rec in self._records.values():
            if norm_tc is not None and rec.task_class != norm_tc:
                continue
            if norm_dec is not None and rec.decomposition_pattern != norm_dec:
                continue
            if require_verified_transfer and rec.cross_task_transfer_successes <= 0:
                continue
            candidates.append(copy.deepcopy(rec))
        candidates.sort(key=lambda r: r.ranking_key())
        return candidates

    def best_strategy(
        self,
        task_class: Optional[str] = None,
        *,
        require_verified_transfer: bool = False,
    ) -> Optional[StrategyRecord]:
        ranked = self.rank_strategies(task_class=task_class, require_verified_transfer=require_verified_transfer)
        return ranked[0] if ranked else None

    def get(self, strategy_id: str) -> Optional[StrategyRecord]:
        rec = self._records.get(strategy_id)
        return copy.deepcopy(rec) if rec is not None else None

    def list_records(self) -> List[StrategyRecord]:
        return self.rank_strategies()


def json_load_handle(handle: Any) -> Any:
    import json

    return json.load(handle)


__all__ = [
    "DEFAULT_STRATEGY_MEMORY_REL_PATH",
    "STRATEGY_MEMORY_SCHEMA",
    "STRATEGY_RECORD_SCHEMA",
    "StrategyMemory",
    "StrategyRecord",
    "compute_wilson_interval",
]
