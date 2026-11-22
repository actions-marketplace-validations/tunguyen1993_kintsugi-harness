"""Append-only hash-chained `RunEvent/1` persistence (`kintsugi.runtime.trace_store`)."""

from __future__ import annotations

import fcntl
import hmac
import json
import os
import re
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.contracts_v2 import (
    GENESIS_EVENT_HASH,
    EventChainVerificationResult,
    RunEvent,
    verify_event_chain,
)
from kintsugi.capability.schemas import (
    VALID_RUN_ID_RE,
    assert_no_raw_secrets,
    canonical_json_dumps,
    is_valid_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.shield import (
    OUTBOUND_DLP_SECRET_RE,
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    atomic_write_text,
    redact_high_entropy_secrets,
    resolve_safe_child_path,
    scan_artifact_egress,
)

DEFAULT_RUN_TRACES_REL_PATH = ".kintsugi/run_traces"

_USER_PATH_REDACT_RE = re.compile(r"(?:/Users/|/home/|C:\\\\Users\\\\|C:\\Users\\)[A-Za-z0-9._-]+")
_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE " + r"KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE " + r"KEY-----"
)
_SENSITIVE_VALUE_KEY_RE = re.compile(
    r"(?i)^(?:.*[_-])?(?:api_?key|secret|secret_?key|access_?token|auth_?token|bearer_?token|"
    r"private_?key|client_?secret|password|passwd|authorization|auth_?header|cookie|cookies|"
    r"session_?token|signing_?key)$"
)
_SAFE_TELEMETRY_KEYS = frozenset(
    {
        "idempotency_key",
        "token_budget",
        "tokens_used",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "tokens_saved_estimate",
    }
)


def utc_now_iso() -> str:
    """Return current UTC timestamp formatted as RFC 3339 / ISO-8601 `Z` string."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_safe_run_id(run_id: Any, *, field_name: str = "run_id") -> str:
    """Validate `run_id` / `step_id` style safe identifiers with zero traversal or Trojan Unicode."""
    cleaned = validate_safe_text(run_id, field_name=field_name)
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned or not VALID_RUN_ID_RE.fullmatch(cleaned):
        raise ValueError(f"INVALID_{field_name.upper()}: '{cleaned}' violates safe identifier syntax.")
    return cleaned


def assert_no_symlink_components(base_dir: Path, target: Path) -> None:
    """Verify `base_dir`, every intermediate segment down to `target`, and `target` are non-symlinks."""
    assert_not_symlink(base_dir)
    try:
        rel = target.relative_to(base_dir)
    except ValueError:
        assert_not_symlink(target.parent)
        assert_not_symlink(target)
        return
    cur = base_dir
    for part in rel.parts:
        cur = cur / part
        assert_not_symlink(cur)


def resolve_confined_dir(
    base_dir: Optional[Union[Path, str]],
    default_rel_path: str,
    *,
    workspace_root: Optional[Union[Path, str]] = None,
) -> Path:
    """Resolve and confine a runtime storage directory under `workspace_root` when provided."""
    raw_path = Path(base_dir) if base_dir is not None else Path(default_rel_path)
    if workspace_root is None:
        assert_not_symlink(raw_path.parent)
        assert_not_symlink(raw_path)
        return raw_path

    ws = Path(workspace_root)
    assert_not_symlink(ws)
    ws_resolved = ws.resolve()
    if not raw_path.is_absolute():
        confined = resolve_safe_child_path(ws_resolved, str(raw_path))
        if confined is None:
            raise PermissionError(f"RUNTIME_PATH_OUTSIDE_WORKSPACE: {raw_path}")
        assert_no_symlink_components(ws_resolved, confined)
        return confined

    assert_not_symlink(raw_path)
    try:
        raw_path.resolve().relative_to(ws_resolved)
    except ValueError as exc:
        raise PermissionError(f"RUNTIME_PATH_OUTSIDE_WORKSPACE: {raw_path}") from exc
    assert_no_symlink_components(ws_resolved, raw_path)
    return raw_path


def _is_preserved_marker_or_digest(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped.startswith(("[REDACTED", "[HIGH_ENTROPY_REDACTED", "EXAMPLE_PLACEHOLDER")):
        return True
    return is_valid_sha256(stripped)


def redact_trace_text(text: Any, *, max_len: int = 0) -> str:
    """Redact credentials, private keys, high-entropy literals, Bidi chars, and user paths."""
    cleaned = str(text or "")
    if not cleaned:
        return ""
    cleaned = TROJAN_UNICODE_RE.sub("", cleaned).replace("\x00", "")
    if _is_preserved_marker_or_digest(cleaned):
        return cleaned[:max_len] if (max_len > 0 and len(cleaned) > max_len) else cleaned
    cleaned = _PEM_PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", cleaned)
    cleaned = redact_secrets_in_text(cleaned, redact_paths=False)
    cleaned = redact_high_entropy_secrets(cleaned)
    cleaned = _USER_PATH_REDACT_RE.sub("/Users/<redacted>", cleaned)
    cleaned = OUTBOUND_DLP_SECRET_RE.sub("[REDACTED_SECRET]", cleaned)
    return cleaned[:max_len] if (max_len > 0 and len(cleaned) > max_len) else cleaned


def redact_trace_value(value: Any, *, key_hint: str = "") -> Any:
    """Recursively normalize and redact sensitive strings in JSON-serializable structures."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Enum):
        return redact_trace_value(value.value, key_hint=key_hint)
    if isinstance(value, Path):
        return redact_trace_text(str(value))
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return redact_trace_value(value.to_dict(), key_hint=key_hint)
    if isinstance(value, str):
        norm_key = key_hint.strip().lower().replace("-", "_")
        if (
            norm_key
            and norm_key not in _SAFE_TELEMETRY_KEYS
            and _SENSITIVE_VALUE_KEY_RE.fullmatch(norm_key)
            and not _is_preserved_marker_or_digest(value)
        ):
            digest8 = sha256_digest(value).split(":", 1)[1][:8]
            return f"[REDACTED_SECRET:{digest8}]"
        base = redact_secrets_in_value(value, key_hint=key_hint)
        if isinstance(base, str):
            return redact_trace_text(base)
        return base
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            safe_k = redact_trace_text(str(k))
            out[safe_k] = redact_trace_value(v, key_hint=safe_k)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_trace_value(item, key_hint=key_hint) for item in value]
    if isinstance(value, set):
        return sorted(redact_trace_value(item, key_hint=key_hint) for item in value)
    return redact_trace_text(str(value))


def read_regular_text_nofollow(path: Path) -> str:
    """Open `path` with `O_RDONLY | O_NOFOLLOW`, verify regular file, and return UTF-8 text."""
    assert_not_symlink(path.parent)
    assert_not_symlink(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise PermissionError(f"SECURITY_OPEN_REFUSED_NOFOLLOW ({path.name}): {exc}") from exc
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_NON_REGULAR_FILE_REFUSED: {path}")
        return handle.read()


@contextmanager
def run_flock(lock_dir: Path, safe_run_id: str) -> Iterator[None]:
    """Acquire an exclusive `fcntl.flock(LOCK_EX)` lock per `run_id` with `0o600` + `O_NOFOLLOW`."""
    assert_not_symlink(lock_dir.parent)
    assert_not_symlink(lock_dir)
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{safe_run_id}.lock"
    assert_not_symlink(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(lock_path), flags, 0o600)
    with os.fdopen(fd, "a+", encoding="utf-8") as lock_file:
        st = os.fstat(lock_file.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_LOCK_NOT_REGULAR_FILE: {lock_path}")
        try:
            os.chmod(lock_path, 0o600)
        except OSError as _chmod_err:
            _ = _chmod_err
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _assert_egress_clean(serialized_json: str, *, context: str) -> None:
    assert_no_raw_secrets(serialized_json, context=context)
    egress = scan_artifact_egress(serialized_json, context=context)
    if not egress.get("ok"):
        raise ValueError(f"SECRET_LEAK_BLOCKED ({context}): {egress.get('findings', [])[:1]}")


class TraceStore:
    """Symlink-safe, redacted, append-only hash-chained `RunEvent/1` store under `.kintsugi/run_traces/`."""

    def __init__(
        self,
        base_dir: Optional[Union[Path, str]] = None,
        *,
        workspace_root: Optional[Union[Path, str]] = None,
    ) -> None:
        self.base_dir = resolve_confined_dir(
            base_dir, DEFAULT_RUN_TRACES_REL_PATH, workspace_root=workspace_root
        )
        self._lock_dir = self.base_dir / ".locks"

    def trace_path_for(self, run_id: str) -> Path:
        """Return validated, symlink-free trace path `.kintsugi/run_traces/<run_id>.jsonl`."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        assert_not_symlink(self.base_dir)
        base_resolved = self.base_dir.resolve() if self.base_dir.exists() else self.base_dir
        target = resolve_safe_child_path(base_resolved, f"{safe_id}.jsonl")
        if target is None:
            raise PermissionError(f"TRACE_PATH_ESCAPE_REFUSED: {safe_id}")
        raw_target = self.base_dir / f"{safe_id}.jsonl"
        assert_no_symlink_components(self.base_dir, raw_target)
        return raw_target

    def _read_raw_lines(self, trace_path: Path) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        raw_text = read_regular_text_nofollow(trace_path)
        records: List[Dict[str, Any]] = []
        for idx, raw_line in enumerate(raw_text.splitlines()):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return records, f"CORRUPT_TRACE_LINE:idx={idx}:{exc}"
            if not isinstance(parsed, Mapping):
                return records, f"INVALID_TRACE_LINE_TYPE:idx={idx}"
            records.append(dict(parsed))
        return records, None

    @staticmethod
    def _validate_records(safe_id: str, records: Sequence[Dict[str, Any]]) -> EventChainVerificationResult:
        if not records:
            return EventChainVerificationResult(
                valid=False,
                checked_count=0,
                reasons=[f"EMPTY_TRACE_FILE:{safe_id}"],
                head_hash="",
            )
        chain_res = verify_event_chain(records)
        if not chain_res.valid:
            return chain_res
        reasons: List[str] = []
        prev_seq: Optional[int] = None
        for idx, rec in enumerate(records):
            if str(rec.get("run_id", "")) != safe_id:
                reasons.append(f"TRACE_FILE_RUN_ID_MISMATCH:idx={idx}:expected={safe_id}")
                break
            seq_val = rec.get("seq")
            if seq_val is not None:
                if isinstance(seq_val, bool) or not isinstance(seq_val, int) or seq_val < 0:
                    reasons.append(f"INVALID_EVENT_SEQ:idx={idx}:{seq_val!r}")
                    break
                if prev_seq is not None and seq_val < prev_seq:
                    reasons.append(f"EVENT_SEQ_REGRESSION:idx={idx}:{seq_val}<{prev_seq}")
                    break
                prev_seq = seq_val
        if reasons:
            return EventChainVerificationResult(
                valid=False,
                checked_count=chain_res.checked_count,
                reasons=reasons,
                head_hash=chain_res.head_hash,
            )
        return chain_res

    def _build_redacted_event(
        self,
        safe_id: str,
        prev_hash: str,
        seq: int,
        *,
        step_id: Optional[Union[str, RunEvent, Mapping[str, Any]]] = None,
        state: Optional[str] = None,
        event: Optional[Union[RunEvent, Mapping[str, Any]]] = None,
        tool_id: str = "",
        input_data: Any = None,
        output_data: Any = None,
        input_digest: str = "",
        output_digest: str = "",
        elapsed_ms: float = 0.0,
        tokens_used: int = 0,
        resource_usage: Optional[Mapping[str, Any]] = None,
        decision_reason: str = "",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        profile: Optional[str] = None,
        component: Optional[str] = None,
        severity: Optional[str] = None,
        correlation: Optional[Mapping[str, Any]] = None,
    ) -> RunEvent:
        source_ev = event if event is not None else (step_id if isinstance(step_id, (RunEvent, Mapping)) else None)
        if source_ev is not None:
            raw_map = source_ev.to_dict() if isinstance(source_ev, RunEvent) else dict(source_ev)
            ev_run_id = raw_map.get("run_id")
            if ev_run_id is not None and str(ev_run_id).strip() != safe_id:
                raise ValueError(f"RUN_ID_MISMATCH: expected '{safe_id}', got '{ev_run_id}'.")
            if isinstance(source_ev, RunEvent):
                explicit_prev = raw_map.get("prev_event_hash", GENESIS_EVENT_HASH)
                if explicit_prev != GENESIS_EVENT_HASH and not hmac.compare_digest(explicit_prev, prev_hash):
                    raise ValueError("PREV_EVENT_HASH_MISMATCH: RunEvent does not link to trace head.")
            elif "prev_event_hash" in raw_map and raw_map["prev_event_hash"]:
                if not hmac.compare_digest(str(raw_map["prev_event_hash"]).lower(), prev_hash.lower()):
                    raise ValueError("PREV_EVENT_HASH_MISMATCH: event dict does not link to trace head.")
            step_val = raw_map.get("step_id")
            state_val = raw_map.get("state")
            tool_val = raw_map.get("tool_id", "")
            in_dig = raw_map.get("input_digest", "")
            out_dig = raw_map.get("output_digest", "")
            elapsed_val = raw_map.get("elapsed_ms", 0.0)
            tokens_val = raw_map.get("tokens_used", 0)
            ru_val = raw_map.get("resource_usage") or {}
            reason_val = raw_map.get("decision_reason", "")
            ev_id_val = raw_map.get("event_id") or f"ev-{seq:06d}"
            ts_val = raw_map.get("timestamp") or utc_now_iso()
            prof_val = raw_map.get("profile")
            comp_val = raw_map.get("component")
            sev_val = raw_map.get("severity")
            corr_val = raw_map.get("correlation")
        else:
            step_val = step_id
            state_val = state
            tool_val = tool_id
            in_dig = input_digest or (sha256_digest(redact_trace_value(input_data)) if input_data is not None else "")
            out_dig = output_digest or (sha256_digest(redact_trace_value(output_data)) if output_data is not None else "")
            elapsed_val = elapsed_ms
            tokens_val = tokens_used
            ru_val = dict(resource_usage or {})
            reason_val = decision_reason
            ev_id_val = event_id or f"ev-{seq:06d}"
            ts_val = timestamp or utc_now_iso()
            prof_val = profile
            comp_val = component
            sev_val = severity
            corr_val = dict(correlation) if correlation is not None else None

        if not step_val or not state_val:
            raise ValueError("INVALID_RUN_EVENT: step_id and state are required.")

        clean_ru = redact_trace_value(dict(ru_val))
        clean_reason = redact_trace_text(reason_val, max_len=4096)
        clean_corr = redact_trace_value(dict(corr_val)) if corr_val is not None else None
        clean_comp = redact_trace_text(comp_val, max_len=128) if comp_val is not None else None

        return RunEvent(
            run_id=safe_id,
            step_id=redact_trace_text(str(step_val), max_len=128),
            state=redact_trace_text(str(state_val), max_len=128),
            tool_id=redact_trace_text(str(tool_val), max_len=128) if tool_val else "",
            input_digest=in_dig,
            output_digest=out_dig,
            elapsed_ms=max(0.0, float(elapsed_val)),
            tokens_used=max(0, int(tokens_val)),
            resource_usage=clean_ru if isinstance(clean_ru, dict) else {},
            decision_reason=clean_reason,
            prev_event_hash=prev_hash,
            event_id=str(ev_id_val),
            seq=seq,
            timestamp=str(ts_val),
            profile=str(prof_val).strip().upper() if prof_val else None,
            component=clean_comp,
            severity=str(sev_val).strip().upper() if sev_val else None,
            correlation=clean_corr if isinstance(clean_corr, dict) else None,
        )

    def _write_trace_atomic_append(self, trace_path: Path, existing_records: Sequence[Dict[str, Any]], new_ev: RunEvent) -> None:
        """Persist `existing_records + [new_ev]` atomically with `0o600`, `fsync`, and symlink checks."""
        assert_not_symlink(self.base_dir)
        assert_not_symlink(trace_path)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        line = new_ev.to_canonical_json() + "\n"
        _assert_egress_clean(line, context=f"TraceStore:{new_ev.run_id}")

        if not existing_records and not trace_path.exists():
            atomic_write_text(trace_path, line, mode=0o600)
            return

        # Append atomically via O_APPEND + O_NOFOLLOW when extending existing log, and enforce 0o600 + fsync.
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(trace_path), flags, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            st = os.fstat(handle.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"TRACE_NOT_REGULAR_FILE: {trace_path}")
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(trace_path, 0o600)

    def append_event(
        self,
        run_id: str,
        step_id: Optional[Union[str, RunEvent, Mapping[str, Any]]] = None,
        state: Optional[str] = None,
        *,
        event: Optional[Union[RunEvent, Mapping[str, Any]]] = None,
        tool_id: str = "",
        input_data: Any = None,
        output_data: Any = None,
        input_digest: str = "",
        output_digest: str = "",
        elapsed_ms: float = 0.0,
        tokens_used: int = 0,
        resource_usage: Optional[Mapping[str, Any]] = None,
        decision_reason: str = "",
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        profile: Optional[str] = None,
        component: Optional[str] = None,
        severity: Optional[str] = None,
        correlation: Optional[Mapping[str, Any]] = None,
    ) -> RunEvent:
        """Redact, hash-chain, verify, and append a `RunEvent/1` record for `run_id`."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        trace_path = self.trace_path_for(safe_id)
        self.base_dir.mkdir(parents=True, exist_ok=True)

        with run_flock(self._lock_dir, safe_id):
            trace_path = self.trace_path_for(safe_id)
            existing_records: List[Dict[str, Any]] = []
            if trace_path.exists():
                existing_records, parse_err = self._read_raw_lines(trace_path)
                if parse_err is not None:
                    raise ValueError(f"TAMPERED_RUN_TRACE:{parse_err}")
                if existing_records:
                    verdict = self._validate_records(safe_id, existing_records)
                    if not verdict.valid:
                        raise ValueError(f"TAMPERED_RUN_TRACE:{';'.join(verdict.reasons)}")

            prev_hash = str(existing_records[-1]["event_hash"]) if existing_records else GENESIS_EVENT_HASH
            seq = len(existing_records)
            new_ev = self._build_redacted_event(
                safe_id,
                prev_hash,
                seq,
                step_id=step_id,
                state=state,
                event=event,
                tool_id=tool_id,
                input_data=input_data,
                output_data=output_data,
                input_digest=input_digest,
                output_digest=output_digest,
                elapsed_ms=elapsed_ms,
                tokens_used=tokens_used,
                resource_usage=resource_usage,
                decision_reason=decision_reason,
                event_id=event_id,
                timestamp=timestamp,
                profile=profile,
                component=component,
                severity=severity,
                correlation=correlation,
            )
            self._write_trace_atomic_append(trace_path, existing_records, new_ev)
            return new_ev

    def verify_run_chain(self, run_id: str) -> EventChainVerificationResult:
        """Verify on-disk `RunEvent/1` hash chain integrity, linkage, `run_id`, and secret hygiene."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        trace_path = self.trace_path_for(safe_id)
        if not trace_path.exists():
            return EventChainVerificationResult(
                valid=False,
                checked_count=0,
                reasons=[f"TRACE_NOT_FOUND:{safe_id}"],
                head_hash="",
            )
        records, parse_err = self._read_raw_lines(trace_path)
        if parse_err is not None:
            return EventChainVerificationResult(
                valid=False,
                checked_count=len(records),
                reasons=[parse_err],
                head_hash="",
            )
        return self._validate_records(safe_id, records)

    def load_events(self, run_id: str, *, verify: bool = True) -> List[RunEvent]:
        """Load `RunEvent/1` chain for `run_id` safely via `O_NOFOLLOW`, failing closed if tampered."""
        safe_id = validate_safe_run_id(run_id, field_name="run_id")
        trace_path = self.trace_path_for(safe_id)
        if not trace_path.exists():
            return []
        records, parse_err = self._read_raw_lines(trace_path)
        if parse_err is not None:
            raise ValueError(f"TAMPERED_RUN_TRACE:{parse_err}")
        if verify:
            verdict = self._validate_records(safe_id, records)
            if not verdict.valid:
                raise ValueError(f"TAMPERED_RUN_TRACE:{';'.join(verdict.reasons)}")
        return [RunEvent.from_dict(rec) for rec in records]

    def list_runs(self) -> List[str]:
        """Return sorted list of valid `run_id` traces stored in `.kintsugi/run_traces/`."""
        assert_not_symlink(self.base_dir)
        if not self.base_dir.exists():
            return []
        run_ids: List[str] = []
        for entry in self.base_dir.iterdir():
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            if not entry.name.endswith(".jsonl") or not entry.is_file():
                continue
            candidate_id = entry.name[:-6]
            if VALID_RUN_ID_RE.fullmatch(candidate_id):
                run_ids.append(candidate_id)
        return sorted(run_ids)


__all__ = [
    "DEFAULT_RUN_TRACES_REL_PATH",
    "TraceStore",
    "assert_no_symlink_components",
    "read_regular_text_nofollow",
    "redact_trace_text",
    "redact_trace_value",
    "resolve_confined_dir",
    "run_flock",
    "utc_now_iso",
    "validate_safe_run_id",
]
