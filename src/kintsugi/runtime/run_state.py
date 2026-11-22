"""Stage 4 Durable Run State Machine & Atomic Idempotent Checkpointing (`kintsugi.runtime.run_state`)."""

from __future__ import annotations

import copy
import errno
import hmac
import json
import os
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple, Union

from kintsugi.capability.schemas import (
    assert_no_raw_secrets,
    canonical_json_dumps,
    normalize_sha256,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.runtime.trace_store import (
    TraceStore,
    assert_no_symlink_components,
    read_regular_text_nofollow,
    redact_trace_text,
    redact_trace_value,
    resolve_confined_dir,
    run_flock,
    utc_now_iso,
    validate_safe_run_id,
)
from kintsugi.shield import assert_not_symlink, atomic_write_json, resolve_safe_child_path, scan_artifact_egress

DEFAULT_RUN_CHECKPOINTS_REL_PATH = ".kintsugi/run_checkpoints"
CHECKPOINT_SCHEMA_VERSION = "RunCheckpoint/1"


class RunStatus(str, Enum):
    """Strict durable execution lifecycle states."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    PAUSED = "PAUSED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


ALLOWED_TRANSITIONS: Dict[RunStatus, FrozenSet[RunStatus]] = {
    RunStatus.PENDING: frozenset(
        {
            RunStatus.RUNNING,
            RunStatus.WAITING_APPROVAL,
            RunStatus.PAUSED,
            RunStatus.FAILED,
        }
    ),
    RunStatus.RUNNING: frozenset(
        {
            RunStatus.WAITING_APPROVAL,
            RunStatus.PAUSED,
            RunStatus.RECONCILIATION_REQUIRED,
            RunStatus.COMPLETED,
            RunStatus.FAILED,
        }
    ),
    RunStatus.WAITING_APPROVAL: frozenset(
        {
            RunStatus.RUNNING,
            RunStatus.PAUSED,
            RunStatus.FAILED,
        }
    ),
    RunStatus.PAUSED: frozenset(
        {
            RunStatus.RUNNING,
            RunStatus.WAITING_APPROVAL,
            RunStatus.FAILED,
        }
    ),
    RunStatus.RECONCILIATION_REQUIRED: frozenset(
        {
            RunStatus.RUNNING,
            RunStatus.FAILED,
        }
    ),
    RunStatus.FAILED: frozenset(),
    RunStatus.COMPLETED: frozenset(),
}

TERMINAL_RUN_STATUSES: FrozenSet[RunStatus] = frozenset({RunStatus.FAILED, RunStatus.COMPLETED})


class InvalidStateTransitionError(ValueError):
    """Raised when a run attempts a disallowed `RunStatus` state transition."""


class ReconciliationRequiredError(RuntimeError):
    """Raised when an interrupted in-flight side-effect step requires explicit reconciliation."""

    def __init__(
        self,
        message: str = "",
        *,
        run_id: str = "",
        step_id: str = "",
        idempotency_key: str = "",
        in_flight_record: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self.run_id = run_id
        self.step_id = step_id
        self.idempotency_key = idempotency_key
        self.in_flight_record: Optional[Dict[str, Any]] = (
            copy.deepcopy(dict(in_flight_record)) if isinstance(in_flight_record, Mapping) else None
        )
        if not message:
            message = (
                f"RECONCILIATION_REQUIRED: run_id={run_id!r}, step_id={step_id!r}, "
                f"idempotency_key={idempotency_key!r}"
            )
        super().__init__(message)


def coerce_run_status(value: Union[RunStatus, str]) -> RunStatus:
    """Parse and validate a `RunStatus` enum or case-insensitive status string."""
    if isinstance(value, RunStatus):
        return value
    if isinstance(value, str):
        token = value.strip().upper()
        try:
            return RunStatus(token)
        except ValueError as exc:
            raise ValueError(f"INVALID_RUN_STATUS: {value!r}") from exc
    raise ValueError(f"INVALID_RUN_STATUS: {value!r}")


class RunStateMachine:
    """Enforces strict `RunStatus` transitions (`ALLOWED_TRANSITIONS`) with audit history."""

    ALLOWED_TRANSITIONS: Dict[RunStatus, FrozenSet[RunStatus]] = ALLOWED_TRANSITIONS

    def __init__(
        self,
        run_id: Union[str, RunStatus, None] = None,
        initial_status: Union[RunStatus, str] = RunStatus.PENDING,
        *,
        status: Optional[Union[RunStatus, str]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
        trace_store: Optional[TraceStore] = None,
    ) -> None:
        if isinstance(run_id, RunStatus):
            initial_status = run_id
            resolved_run_id = "run-default"
        elif run_id is None:
            resolved_run_id = "run-default"
        else:
            resolved_run_id = validate_safe_run_id(run_id, field_name="run_id")

        effective_status = status if status is not None else initial_status
        self.run_id = resolved_run_id
        self._status: RunStatus = coerce_run_status(effective_status)
        self._history: List[Dict[str, Any]] = [
            dict(item) for item in (history or []) if isinstance(item, Mapping)
        ]
        self._trace_store = trace_store

    @property
    def status(self) -> RunStatus:
        return self._status

    @property
    def state(self) -> RunStatus:
        return self._status

    @property
    def is_terminal(self) -> bool:
        return self._status in TERMINAL_RUN_STATUSES

    @property
    def history(self) -> List[Dict[str, Any]]:
        return [dict(item) for item in self._history]

    @staticmethod
    def validate_transition(
        prev_status: Union[RunStatus, str],
        next_status: Union[RunStatus, str],
    ) -> RunStatus:
        """Validate `prev_status -> next_status` against `ALLOWED_TRANSITIONS`, returning `RunStatus`."""
        prev = coerce_run_status(prev_status)
        nxt = coerce_run_status(next_status)
        if prev == nxt:
            raise InvalidStateTransitionError(
                f"INVALID_RUN_TRANSITION: self-transition {prev.value} -> {nxt.value} forbidden."
            )
        allowed = ALLOWED_TRANSITIONS.get(prev, frozenset())
        if nxt not in allowed:
            raise InvalidStateTransitionError(
                f"INVALID_RUN_TRANSITION: {prev.value} -> {nxt.value} not permitted "
                f"(allowed={sorted(s.value for s in allowed)})."
            )
        return nxt

    def can_transition(self, next_status: Union[RunStatus, str]) -> bool:
        """Return True iff `self.status -> next_status` is permitted."""
        try:
            self.validate_transition(self._status, next_status)
            return True
        except (InvalidStateTransitionError, ValueError):
            return False

    def transition(
        self,
        next_status: Union[RunStatus, str],
        *,
        reason: str = "",
        step_id: str = "lifecycle",
    ) -> RunStatus:
        """Atomically validate and apply `next_status`, recording history and optional trace event."""
        prev = self._status
        nxt = self.validate_transition(prev, next_status)
        clean_reason = redact_trace_text(reason, max_len=512)
        entry = {
            "from_status": prev.value,
            "to_status": nxt.value,
            "reason": clean_reason,
            "timestamp": utc_now_iso(),
        }
        self._status = nxt
        self._history.append(entry)
        if self._trace_store is not None:
            self._trace_store.append_event(
                self.run_id,
                step_id=step_id,
                state=nxt.value,
                decision_reason=clean_reason or f"transition:{prev.value}->{nxt.value}",
                resource_usage={"from_status": prev.value, "to_status": nxt.value},
                component="run_state",
                severity="HIGH" if nxt in (RunStatus.FAILED, RunStatus.RECONCILIATION_REQUIRED) else "INFO",
            )
        return nxt

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self._status.value,
            "history": self.history,
        }

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        trace_store: Optional[TraceStore] = None,
    ) -> "RunStateMachine":
        if not isinstance(data, Mapping):
            raise ValueError("INVALID_RUN_STATE_MACHINE: expected mapping.")
        return cls(
            run_id=data.get("run_id", "run-default"),
            initial_status=data.get("status", RunStatus.PENDING),
            history=list(data.get("history", [])),
            trace_store=trace_store,
        )


def _compute_checkpoint_digest(payload_without_digest: Mapping[str, Any]) -> str:
    basis = {k: v for k, v in payload_without_digest.items() if k != "checkpoint_digest"}
    return sha256_digest(basis)


def _fsync_directory(dir_path: Path) -> None:
    """Flush parent directory metadata changes to disk safely (`O_RDONLY | O_NOFOLLOW`)."""
    assert_not_symlink(dir_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    dir_fd = os.open(str(dir_path), flags)
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EBADF):
            raise
    finally:
        os.close(dir_fd)


class CheckpointManager:
    """
    Atomic, symlink-safe, idempotent run checkpoint manager (`.kintsugi/run_checkpoints/<run_id>.json`).

    Guarantees at-most-once execution for committed `step_id` and `idempotency_key` pairs across
    crashes, restarts, and duplicate replays.
    """

    def __init__(
        self,
        base_dir: Optional[Union[Path, str]] = None,
        *,
        workspace_root: Optional[Union[Path, str]] = None,
        trace_store: Optional[TraceStore] = None,
    ) -> None:
        self.base_dir = resolve_confined_dir(
            base_dir, DEFAULT_RUN_CHECKPOINTS_REL_PATH, workspace_root=workspace_root
        )
        self._lock_dir = self.base_dir / ".locks"
        self.trace_store = trace_store

    def checkpoint_path(self, run_id: str) -> Path:
        """Return validated, symlink-free path `.kintsugi/run_checkpoints/<run_id>.json`."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        assert_not_symlink(self.base_dir)
        base_resolved = self.base_dir.resolve() if self.base_dir.exists() else self.base_dir
        target = resolve_safe_child_path(base_resolved, f"{safe_id}.json")
        if target is None:
            raise PermissionError(f"CHECKPOINT_PATH_ESCAPE_REFUSED: {safe_id}")
        raw_target = self.base_dir / f"{safe_id}.json"
        assert_no_symlink_components(self.base_dir, raw_target)
        return raw_target

    def _empty_checkpoint(
        self,
        safe_id: str,
        *,
        status: RunStatus = RunStatus.PENDING,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_meta = redact_trace_value(dict(metadata or {}))
        payload: Dict[str, Any] = {
            "schema": CHECKPOINT_SCHEMA_VERSION,
            "run_id": safe_id,
            "status": status.value,
            "completed_step_ids": [],
            "idempotency_keys": {},
            "completed_outputs": {},
            "idempotency_outputs": {},
            "side_effects_committed": {},
            "in_flight_steps": {},
            "transition_history": [],
            "metadata": clean_meta if isinstance(clean_meta, dict) else {},
            "updated_at": utc_now_iso(),
        }
        payload["checkpoint_digest"] = _compute_checkpoint_digest(payload)
        return payload

    def _normalize_and_verify_loaded(self, safe_id: str, raw: Mapping[str, Any]) -> Dict[str, Any]:
        if raw.get("schema") != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(f"INVALID_CHECKPOINT_SCHEMA: {raw.get('schema')!r}")
        if str(raw.get("run_id", "")) != safe_id:
            raise ValueError(f"CHECKPOINT_RUN_ID_MISMATCH: expected '{safe_id}', got '{raw.get('run_id')}'")
        coerce_run_status(str(raw.get("status", "")))

        stored_digest = str(raw.get("checkpoint_digest") or "").strip().lower()
        if not stored_digest:
            raise ValueError("CHECKPOINT_MISSING_INTEGRITY_DIGEST")
        normalized_stored = normalize_sha256(stored_digest, field_name="checkpoint_digest")
        expected_digest = _compute_checkpoint_digest(raw)
        if not hmac.compare_digest(normalized_stored, expected_digest):
            raise ValueError("CHECKPOINT_INTEGRITY_MISMATCH: checkpoint digest verification failed.")

        serialized = canonical_json_dumps(dict(raw))
        assert_no_raw_secrets(serialized, context=f"Checkpoint:{safe_id}")
        loaded = copy.deepcopy(dict(raw))
        if "in_flight_steps" not in loaded:
            loaded["in_flight_steps"] = {}
        elif not isinstance(loaded["in_flight_steps"], dict):
            raise ValueError(f"INVALID_CHECKPOINT_IN_FLIGHT_STEPS ({safe_id}): expected JSON object.")
        return loaded

    def _read_checkpoint_unlocked(self, safe_id: str) -> Optional[Dict[str, Any]]:
        ckpt_path = self.checkpoint_path(safe_id)
        if not ckpt_path.exists():
            return None
        raw_text = read_regular_text_nofollow(ckpt_path)
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"CORRUPT_CHECKPOINT_JSON ({safe_id}): {exc}") from exc
        if not isinstance(parsed, Mapping):
            raise ValueError(f"INVALID_CHECKPOINT_ROOT ({safe_id}): expected JSON object.")
        return self._normalize_and_verify_loaded(safe_id, parsed)

    def _write_checkpoint_unlocked(self, safe_id: str, state: Mapping[str, Any]) -> Dict[str, Any]:
        ckpt_path = self.checkpoint_path(safe_id)
        assert_not_symlink(self.base_dir)
        assert_not_symlink(ckpt_path)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        status_obj = coerce_run_status(state.get("status", RunStatus.PENDING))
        completed_ids = list(
            dict.fromkeys(
                validate_safe_text(str(s), field_name="step_id")
                for s in (state.get("completed_step_ids") or [])
            )
        )
        clean_outputs = redact_trace_value(dict(state.get("completed_outputs") or {}))
        clean_idem_keys = {
            validate_safe_text(str(k), field_name="idempotency_key"): validate_safe_text(
                str(v), field_name="step_id"
            )
            for k, v in dict(state.get("idempotency_keys") or {}).items()
        }
        clean_idem_outputs = redact_trace_value(dict(state.get("idempotency_outputs") or {}))
        clean_side_effects = redact_trace_value(dict(state.get("side_effects_committed") or {}))
        raw_in_flight = state.get("in_flight_steps") or {}
        if not isinstance(raw_in_flight, Mapping):
            raise ValueError(f"INVALID_CHECKPOINT_IN_FLIGHT_STEPS ({safe_id}): expected mapping.")
        clean_in_flight: Dict[str, Any] = {}
        for k, v in raw_in_flight.items():
            clean_key = validate_safe_text(str(k), field_name="idempotency_key")
            if not isinstance(v, Mapping):
                raise ValueError(f"INVALID_IN_FLIGHT_RECORD ({safe_id}): expected mapping for '{clean_key}'.")
            clean_rec = redact_trace_value(dict(v))
            clean_in_flight[clean_key] = clean_rec if isinstance(clean_rec, dict) else {}
        clean_history = redact_trace_value(list(state.get("transition_history") or []))
        clean_meta = redact_trace_value(dict(state.get("metadata") or {}))

        payload: Dict[str, Any] = {
            "schema": CHECKPOINT_SCHEMA_VERSION,
            "run_id": safe_id,
            "status": status_obj.value,
            "completed_step_ids": completed_ids,
            "idempotency_keys": clean_idem_keys,
            "completed_outputs": clean_outputs if isinstance(clean_outputs, dict) else {},
            "idempotency_outputs": clean_idem_outputs if isinstance(clean_idem_outputs, dict) else {},
            "side_effects_committed": clean_side_effects if isinstance(clean_side_effects, dict) else {},
            "in_flight_steps": clean_in_flight,
            "transition_history": clean_history if isinstance(clean_history, list) else [],
            "metadata": clean_meta if isinstance(clean_meta, dict) else {},
            "updated_at": utc_now_iso(),
        }
        payload["checkpoint_digest"] = _compute_checkpoint_digest(payload)

        serialized = canonical_json_dumps(payload)
        assert_no_raw_secrets(serialized, context=f"Checkpoint:{safe_id}")
        egress = scan_artifact_egress(serialized, context=f"checkpoint:{safe_id}")
        if not egress.get("ok"):
            raise ValueError(f"CHECKPOINT_SECRET_LEAK_BLOCKED:{egress.get('findings', [])[:1]}")

        atomic_write_json(ckpt_path, payload, mode=0o600, indent=2)
        _fsync_directory(ckpt_path.parent)
        return copy.deepcopy(payload)

    def create_run(
        self,
        run_id: str,
        *,
        initial_status: Union[RunStatus, str] = RunStatus.PENDING,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Initialize and atomically persist a new run checkpoint (`0o600`)."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        status_obj = coerce_run_status(initial_status)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        with run_flock(self._lock_dir, safe_id):
            existing = self._read_checkpoint_unlocked(safe_id)
            if existing is not None:
                return existing
            empty = self._empty_checkpoint(safe_id, status=status_obj, metadata=metadata)
            saved = self._write_checkpoint_unlocked(safe_id, empty)
            if self.trace_store is not None:
                self.trace_store.append_event(
                    safe_id,
                    step_id="lifecycle",
                    state=status_obj.value,
                    decision_reason="run_initialized",
                    resource_usage={"status": status_obj.value},
                    component="checkpoint_manager",
                    severity="INFO",
                )
            return saved

    def load_checkpoint(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Safely load and integrity-verify `.kintsugi/run_checkpoints/<run_id>.json` (`O_NOFOLLOW`)."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        return self._read_checkpoint_unlocked(safe_id)

    def save_checkpoint(self, run_id: str, state: Mapping[str, Any]) -> Dict[str, Any]:
        """Atomically persist checkpoint payload with `0o600`, symlink checks, and integrity digest."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        with run_flock(self._lock_dir, safe_id):
            return self._write_checkpoint_unlocked(safe_id, state)

    def get_status(self, run_id: str) -> RunStatus:
        """Return persisted `RunStatus` for `run_id` (default `PENDING` if uninitialized)."""
        ckpt = self.load_checkpoint(run_id)
        if ckpt is None:
            return RunStatus.PENDING
        return coerce_run_status(ckpt["status"])

    def transition_run(
        self,
        run_id: str,
        next_status: Union[RunStatus, str],
        *,
        reason: str = "",
    ) -> RunStatus:
        """Transition persisted run status strictly according to `ALLOWED_TRANSITIONS`."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        with run_flock(self._lock_dir, safe_id):
            ckpt = self._read_checkpoint_unlocked(safe_id)
            if ckpt is None:
                ckpt = self._empty_checkpoint(safe_id, status=RunStatus.PENDING)
            sm = RunStateMachine(
                safe_id,
                initial_status=ckpt["status"],
                history=ckpt.get("transition_history"),
                trace_store=self.trace_store,
            )
            nxt = sm.transition(next_status, reason=reason, step_id="lifecycle")
            ckpt["status"] = nxt.value
            ckpt["transition_history"] = sm.history
            self._write_checkpoint_unlocked(safe_id, ckpt)
            return nxt

    def is_step_committed(
        self,
        run_id: str,
        *,
        step_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> bool:
        """Return True if `step_id` or `idempotency_key` is already committed in checkpoint."""
        ckpt = self.load_checkpoint(run_id)
        if ckpt is None:
            return False
        if idempotency_key:
            clean_key = validate_safe_text(str(idempotency_key), field_name="idempotency_key")
            if clean_key in ckpt.get("idempotency_outputs", {}) or clean_key in ckpt.get(
                "side_effects_committed", {}
            ):
                return True
        if step_id:
            clean_step = validate_safe_text(str(step_id), field_name="step_id")
            if clean_step in ckpt.get("completed_step_ids", []) or clean_step in ckpt.get(
                "completed_outputs", {}
            ):
                return True
        return False

    def get_completed_steps(self, run_id: str) -> List[str]:
        """Return ordered list of committed `step_id`s for `run_id`."""
        ckpt = self.load_checkpoint(run_id)
        return list(ckpt.get("completed_step_ids", [])) if ckpt else []

    def get_committed_side_effects(self, run_id: str) -> Dict[str, Any]:
        """Return deep copy of committed side-effect ledger for `run_id`."""
        ckpt = self.load_checkpoint(run_id)
        return copy.deepcopy(ckpt.get("side_effects_committed", {})) if ckpt else {}

    def get_in_flight_steps(self, run_id: str) -> Dict[str, Any]:
        """Return deep copy of unresolved in-flight steps for `run_id`."""
        ckpt = self.load_checkpoint(run_id)
        return copy.deepcopy(ckpt.get("in_flight_steps", {})) if ckpt else {}

    def _find_in_flight_record(
        self,
        ckpt: Mapping[str, Any],
        clean_step: str,
        clean_idem: str,
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        in_flight = ckpt.get("in_flight_steps") or {}
        if not isinstance(in_flight, Mapping):
            return None, None
        if clean_idem and clean_idem in in_flight:
            rec = in_flight[clean_idem]
            return clean_idem, copy.deepcopy(dict(rec)) if isinstance(rec, Mapping) else {}
        for key, rec in in_flight.items():
            if isinstance(rec, Mapping) and str(rec.get("step_id", "")) == clean_step:
                return str(key), copy.deepcopy(dict(rec))
        return None, None

    def _transition_checkpoint_status(
        self,
        safe_id: str,
        ckpt: Dict[str, Any],
        next_status: RunStatus,
        *,
        reason: str,
        step_id: str,
    ) -> RunStatus:
        sm = RunStateMachine(
            safe_id,
            initial_status=ckpt["status"],
            history=ckpt.get("transition_history"),
            trace_store=self.trace_store,
        )
        nxt = sm.transition(next_status, reason=reason, step_id=step_id)
        ckpt["status"] = nxt.value
        ckpt["transition_history"] = sm.history
        return nxt

    def _record_committed_step(
        self,
        ckpt: Dict[str, Any],
        *,
        clean_step: str,
        clean_idem: str,
        clean_output: Any,
        out_digest: str,
        is_side_effect: bool,
        clean_meta: Any,
        extra_idem_key: Optional[str] = None,
        reconciliation_reason: Optional[str] = None,
    ) -> None:
        if clean_step not in ckpt["completed_step_ids"]:
            ckpt["completed_step_ids"].append(clean_step)
        ckpt["completed_outputs"][clean_step] = clean_output
        ckpt["idempotency_keys"][clean_idem] = clean_step
        ckpt["idempotency_outputs"][clean_idem] = clean_output
        if extra_idem_key and extra_idem_key != clean_idem:
            ckpt["idempotency_keys"][extra_idem_key] = clean_step
            ckpt["idempotency_outputs"][extra_idem_key] = clean_output
        if is_side_effect:
            meta_dict = clean_meta if isinstance(clean_meta, dict) else {}
            entry: Dict[str, Any] = {
                "step_id": clean_step,
                "idempotency_key": clean_idem,
                "output_digest": out_digest,
                "committed_at": utc_now_iso(),
                "metadata": meta_dict,
            }
            if reconciliation_reason is not None:
                entry["reconciled"] = True
                entry["reconciliation_reason"] = reconciliation_reason
            ckpt["side_effects_committed"][clean_idem] = entry

    def _emit_trace(
        self,
        safe_id: str,
        *,
        step_id: str,
        state: str,
        decision_reason: str,
        resource_usage: Mapping[str, Any],
        output_data: Any = None,
        output_digest: str = "",
        severity: str = "INFO",
    ) -> None:
        if self.trace_store is None:
            return
        self.trace_store.append_event(
            safe_id,
            step_id=step_id,
            state=state,
            output_data=output_data,
            output_digest=output_digest,
            decision_reason=decision_reason,
            resource_usage=dict(resource_usage),
            component="checkpoint_manager",
            severity=severity,
        )

    @staticmethod
    def _build_in_flight_entry(
        clean_step: str,
        clean_idem: str,
        clean_meta: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "step_id": clean_step,
            "idempotency_key": clean_idem,
            "state": "IN_FLIGHT",
            "is_side_effect": True,
            "prepared_at": utc_now_iso(),
            "pid": os.getpid(),
            "metadata": clean_meta,
        }

    def _raise_if_reconciliation_required(
        self,
        safe_id: str,
        ckpt: Dict[str, Any],
        *,
        clean_step: str,
        clean_idem: str,
        cur_status: RunStatus,
    ) -> None:
        _, in_flight_rec = self._find_in_flight_record(ckpt, clean_step, clean_idem)
        if in_flight_rec is None and cur_status != RunStatus.RECONCILIATION_REQUIRED:
            return
        if cur_status in (RunStatus.PENDING, RunStatus.PAUSED):
            cur_status = self._transition_checkpoint_status(
                safe_id,
                ckpt,
                RunStatus.RUNNING,
                reason=f"prepare_reconcile:{clean_step}",
                step_id=clean_step,
            )
        if cur_status == RunStatus.RUNNING:
            self._transition_checkpoint_status(
                safe_id,
                ckpt,
                RunStatus.RECONCILIATION_REQUIRED,
                reason=f"in_flight_interrupted:{clean_step}",
                step_id=clean_step,
            )
            self._write_checkpoint_unlocked(safe_id, ckpt)

        self._emit_trace(
            safe_id,
            step_id=clean_step,
            state="STEP_RECONCILIATION_REQUIRED",
            decision_reason=(
                "in_flight_step_interrupted"
                if in_flight_rec is not None
                else "run_requires_reconciliation"
            ),
            resource_usage={
                "idempotency_key": clean_idem,
                "in_flight_present": in_flight_rec is not None,
            },
            severity="HIGH",
        )
        raise ReconciliationRequiredError(
            f"RECONCILIATION_REQUIRED: step '{clean_step}' (idempotency_key='{clean_idem}') "
            "has an unresolved in-flight execution or run is awaiting reconciliation.",
            run_id=safe_id,
            step_id=clean_step,
            idempotency_key=clean_idem,
            in_flight_record=in_flight_rec,
        )

    def _record_side_effect_interruption(
        self,
        safe_id: str,
        ckpt: Dict[str, Any],
        *,
        clean_step: str,
        clean_idem: str,
        clean_meta: Dict[str, Any],
        exc: Exception,
    ) -> None:
        in_flight = ckpt.setdefault("in_flight_steps", {})
        entry = in_flight.get(clean_idem)
        if not isinstance(entry, dict):
            entry = self._build_in_flight_entry(clean_step, clean_idem, clean_meta)
            in_flight[clean_idem] = entry
        err_text = redact_trace_text(str(exc), max_len=512)
        entry["last_error"] = err_text
        entry["interrupted_at"] = utc_now_iso()
        if coerce_run_status(ckpt["status"]) == RunStatus.RUNNING:
            self._transition_checkpoint_status(
                safe_id,
                ckpt,
                RunStatus.RECONCILIATION_REQUIRED,
                reason=f"step_interrupted:{clean_step}",
                step_id=clean_step,
            )
        self._write_checkpoint_unlocked(safe_id, ckpt)
        self._emit_trace(
            safe_id,
            step_id=clean_step,
            state="STEP_IN_FLIGHT_INTERRUPTED",
            decision_reason=err_text or "side_effect_interrupted",
            resource_usage={
                "idempotency_key": clean_idem,
                "error_type": type(exc).__name__,
            },
            severity="HIGH",
        )

    def _lookup_committed_output(
        self,
        ckpt: Mapping[str, Any],
        clean_step: str,
        clean_idem: str,
    ) -> Tuple[bool, Any, str]:
        idem_outputs = ckpt.get("idempotency_outputs", {})
        if clean_idem and clean_idem in idem_outputs:
            return True, copy.deepcopy(idem_outputs[clean_idem]), "idempotency_key"
        idem_keys = ckpt.get("idempotency_keys", {})
        completed_outputs = ckpt.get("completed_outputs", {})
        if clean_idem and clean_idem in idem_keys:
            linked_step = idem_keys[clean_idem]
            if linked_step in completed_outputs:
                return True, copy.deepcopy(completed_outputs[linked_step]), "idempotency_key"
        if clean_step in ckpt.get("completed_step_ids", []) and clean_step in completed_outputs:
            return True, copy.deepcopy(completed_outputs[clean_step]), "step_id"
        if clean_step in completed_outputs:
            return True, copy.deepcopy(completed_outputs[clean_step]), "step_id"
        return False, None, ""

    def resume_step(
        self,
        run_id: str,
        step_id: str,
        idempotency_key: str,
        runner_fn: Callable[[], Any],
        *,
        is_side_effect: bool = True,
        side_effect_metadata: Optional[Mapping[str, Any]] = None,
        verify_fn: Optional[Callable[[Any], bool]] = None,
    ) -> Any:
        """
        Execute `runner_fn` at most once for `(run_id, step_id, idempotency_key)` with a two-phase WAL.

        If committed output exists, returns cached value without re-executing.
        If an interrupted in-flight side-effect step or `RECONCILIATION_REQUIRED` state is present,
        transitions to `RECONCILIATION_REQUIRED` (if running) and raises `ReconciliationRequiredError`
        instead of auto-re-executing.
        """
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        clean_step = validate_safe_text(str(step_id), field_name="step_id")
        clean_idem = validate_safe_text(str(idempotency_key), field_name="idempotency_key")
        if not callable(runner_fn):
            raise TypeError("runner_fn must be callable")

        self.base_dir.mkdir(parents=True, exist_ok=True)
        with run_flock(self._lock_dir, safe_id):
            ckpt = self._read_checkpoint_unlocked(safe_id)
            if ckpt is None:
                ckpt = self._empty_checkpoint(safe_id, status=RunStatus.PENDING)

            hit, cached_val, match_via = self._lookup_committed_output(ckpt, clean_step, clean_idem)
            if hit:
                self._emit_trace(
                    safe_id,
                    step_id=clean_step,
                    state="STEP_REPLAY_CACHED",
                    output_data=cached_val,
                    decision_reason=f"cached_via_{match_via}",
                    resource_usage={"idempotency_key": clean_idem, "cache_hit": True},
                )
                return cached_val

            cur_status = coerce_run_status(ckpt["status"])
            if cur_status == RunStatus.WAITING_APPROVAL:
                raise PermissionError(
                    f"RUN_WAITING_APPROVAL: cannot execute step '{clean_step}' before approval."
                )
            if cur_status in TERMINAL_RUN_STATUSES:
                raise InvalidStateTransitionError(
                    f"RUN_TERMINAL_STATE: cannot execute new step '{clean_step}' in state {cur_status.value}."
                )

            self._raise_if_reconciliation_required(
                safe_id, ckpt, clean_step=clean_step, clean_idem=clean_idem, cur_status=cur_status
            )

            if cur_status in (RunStatus.PENDING, RunStatus.PAUSED):
                self._transition_checkpoint_status(
                    safe_id,
                    ckpt,
                    RunStatus.RUNNING,
                    reason=f"execute_step:{clean_step}",
                    step_id=clean_step,
                )
                ckpt = self._write_checkpoint_unlocked(safe_id, ckpt)

            raw_meta = redact_trace_value(dict(side_effect_metadata or {}))
            clean_meta = raw_meta if isinstance(raw_meta, dict) else {}

            if is_side_effect:
                ckpt.setdefault("in_flight_steps", {})[clean_idem] = self._build_in_flight_entry(
                    clean_step, clean_idem, clean_meta
                )
                ckpt = self._write_checkpoint_unlocked(safe_id, ckpt)
                self._emit_trace(
                    safe_id,
                    step_id=clean_step,
                    state="STEP_PREPARED_IN_FLIGHT",
                    decision_reason="wal_phase1_prepared",
                    resource_usage={
                        "idempotency_key": clean_idem,
                        "is_side_effect": True,
                        "pid": os.getpid(),
                    },
                )

            try:
                raw_output = runner_fn()
                if verify_fn is not None and not bool(verify_fn(raw_output)):
                    raise ValueError(f"STEP_VERIFICATION_FAILED: '{clean_step}' failed verification check.")
                clean_output = redact_trace_value(raw_output)
                out_digest = sha256_digest(clean_output)
            except Exception as exc:
                if is_side_effect:
                    self._record_side_effect_interruption(
                        safe_id,
                        ckpt,
                        clean_step=clean_step,
                        clean_idem=clean_idem,
                        clean_meta=clean_meta,
                        exc=exc,
                    )
                raise

            ckpt.setdefault("in_flight_steps", {}).pop(clean_idem, None)
            self._record_committed_step(
                ckpt,
                clean_step=clean_step,
                clean_idem=clean_idem,
                clean_output=clean_output,
                out_digest=out_digest,
                is_side_effect=is_side_effect,
                clean_meta=clean_meta,
            )
            self._write_checkpoint_unlocked(safe_id, ckpt)

            self._emit_trace(
                safe_id,
                step_id=clean_step,
                state="STEP_COMPLETED",
                output_digest=out_digest,
                decision_reason="step_committed",
                resource_usage={
                    "idempotency_key": clean_idem,
                    "side_effect_committed": bool(is_side_effect),
                },
            )
            return copy.deepcopy(clean_output)

    def reconcile_step(
        self,
        run_id: str,
        step_id: str,
        idempotency_key: str,
        *,
        outcome: str,
        reconciled_output: Any = None,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Explicitly resolve an interrupted in-flight step after external inspection.

        `outcome` must be `"COMMITTED"` (commit `reconciled_output` without re-running) or
        `"NOT_EXECUTED"` (clear the in-flight WAL lock so `resume_step` may execute safely).
        """
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        clean_step = validate_safe_text(str(step_id), field_name="step_id")
        clean_idem = validate_safe_text(str(idempotency_key), field_name="idempotency_key")
        if not isinstance(outcome, str):
            raise ValueError(f"INVALID_RECONCILIATION_OUTCOME: {outcome!r}")
        norm_outcome = outcome.strip().upper()
        if norm_outcome not in ("COMMITTED", "NOT_EXECUTED"):
            raise ValueError(
                f"INVALID_RECONCILIATION_OUTCOME: expected 'COMMITTED' or 'NOT_EXECUTED', got {outcome!r}"
            )
        clean_reason = redact_trace_text(reason, max_len=512)

        self.base_dir.mkdir(parents=True, exist_ok=True)
        with run_flock(self._lock_dir, safe_id):
            ckpt = self._read_checkpoint_unlocked(safe_id)
            if ckpt is None:
                raise ValueError(f"CHECKPOINT_NOT_FOUND: run_id={safe_id!r}")
            cur_status = coerce_run_status(ckpt["status"])
            if cur_status in TERMINAL_RUN_STATUSES:
                raise InvalidStateTransitionError(
                    f"RUN_TERMINAL_STATE: cannot reconcile step '{clean_step}' in state {cur_status.value}."
                )

            matched_key, in_flight_rec = self._find_in_flight_record(ckpt, clean_step, clean_idem)
            if matched_key is None or in_flight_rec is None:
                raise ValueError(
                    f"IN_FLIGHT_STEP_NOT_FOUND: step_id={clean_step!r}, idempotency_key={clean_idem!r}"
                )

            ckpt.setdefault("in_flight_steps", {}).pop(matched_key, None)

            out_digest = ""
            if norm_outcome == "COMMITTED":
                clean_output = redact_trace_value(reconciled_output)
                out_digest = sha256_digest(clean_output)
                orig_idem = str(in_flight_rec.get("idempotency_key") or matched_key)
                self._record_committed_step(
                    ckpt,
                    clean_step=clean_step,
                    clean_idem=clean_idem,
                    clean_output=clean_output,
                    out_digest=out_digest,
                    is_side_effect=bool(in_flight_rec.get("is_side_effect", True)),
                    clean_meta=in_flight_rec.get("metadata"),
                    extra_idem_key=orig_idem,
                    reconciliation_reason=clean_reason,
                )

            if not ckpt["in_flight_steps"] and cur_status == RunStatus.RECONCILIATION_REQUIRED:
                self._transition_checkpoint_status(
                    safe_id,
                    ckpt,
                    RunStatus.RUNNING,
                    reason=clean_reason or f"reconciled_{norm_outcome.lower()}:{clean_step}",
                    step_id=clean_step,
                )

            saved = self._write_checkpoint_unlocked(safe_id, ckpt)

            event_state = (
                "STEP_RECONCILED_COMMITTED"
                if norm_outcome == "COMMITTED"
                else "STEP_RECONCILED_NOT_EXECUTED"
            )
            self._emit_trace(
                safe_id,
                step_id=clean_step,
                state=event_state,
                output_digest=out_digest,
                decision_reason=clean_reason or f"reconciled_{norm_outcome.lower()}",
                resource_usage={
                    "idempotency_key": clean_idem,
                    "outcome": norm_outcome,
                    "remaining_in_flight": len(saved.get("in_flight_steps", {})),
                },
            )
            return saved


__all__ = [
    "ALLOWED_TRANSITIONS",
    "CHECKPOINT_SCHEMA_VERSION",
    "CheckpointManager",
    "DEFAULT_RUN_CHECKPOINTS_REL_PATH",
    "InvalidStateTransitionError",
    "ReconciliationRequiredError",
    "RunStateMachine",
    "RunStatus",
    "TERMINAL_RUN_STATUSES",
    "coerce_run_status",
]
