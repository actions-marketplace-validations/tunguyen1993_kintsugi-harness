#!/usr/bin/env python3
"""Delivery Gate Telemetry & Live 2-Strike / Dead-Scar Auto-Freeze Tracker (`DeliveryTelemetry/1`).

Pure Python stdlib parity module for `rust/src/audit/delivery_telemetry.rs`.
Tracks honest 3-stage receipts (`issued -> included_in_input -> patch_bound`) across
`claude_code`, `antigravity`, `local_cli`, and `cloud_sandbox` with `O_NOFOLLOW` + atomic `0o600`
persistence, ancestor symlink rejection, cross-process `<store>.lock` serialization,
and 2-strike / dead-scar auto-freeze parity with `capsules.rs`.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import time
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from kintsugi import __version__

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix fallback
    fcntl = None  # type: ignore[assignment]

DELIVERY_TELEMETRY_SCHEMA = "DeliveryTelemetry/1"
SCHEMA_VERSION = __version__
SUPPORTED_CLIENTS: Tuple[str, ...] = ("claude_code", "antigravity", "local_cli", "cloud_sandbox")
SUPPORTED_STAGES: Tuple[str, ...] = ("issued", "included_in_input", "patch_bound")
MAX_TELEMETRY_FILE_BYTES = 8 * 1024 * 1024
GATE_3_MIN_SESSIONS = 10
TWO_STRIKE_LOSS_LIMIT = 2
DEAD_SCAR_MIN_TRIALS = 30
DEAD_SCAR_MIN_WIN_PCT = 15
_MAX_ID_LEN = 256
_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1


def is_supported_client(client: str) -> bool:
    return isinstance(client, str) and client in SUPPORTED_CLIENTS


def _is_nonneg_int(val: Any) -> bool:
    return not isinstance(val, bool) and isinstance(val, int) and val >= 0


def _validate_id_token(field: str, raw: str, *, required: bool) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"INVALID_{field.upper()}: expected string")
    trimmed = raw.strip()
    if not trimmed:
        if required:
            raise ValueError(f"MISSING_{field.upper()}")
        return ""
    if len(trimmed) > _MAX_ID_LEN or any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "|" for ch in trimmed):
        raise ValueError(f"INVALID_{field.upper()}: control chars, '|', or length > {_MAX_ID_LEN}")
    return trimmed


def _dedupe_ids(ids: Sequence[str]) -> List[str]:
    if isinstance(ids, (str, bytes, bytearray)) or not isinstance(ids, Sequence):
        raise ValueError("INVALID_IDS: expected sequence of strings, not bare str/bytes")
    seen, out = set(), []
    for raw in ids:
        clean = _validate_id_token("item_id", raw, required=False)
        if clean and clean not in seen:
            seen.add(clean)
            out.append(clean)
    return out


def _is_macos_system_root_symlink(path: Path) -> bool:
    if sys.platform != "darwin":
        return False
    s = str(path)
    if s not in ("/var", "/tmp", "/etc"):
        return False
    try:
        return os.readlink(s) == f"private{s}"
    except OSError:
        return False


def _reject_symlink_if_present(path: Path) -> None:
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"REFUSING_SYMLINK: {path}")


def _reject_symlink_ancestors(directory: Path) -> None:
    parts = directory.parts
    if not parts:
        return
    cur = Path(parts[0])
    for idx, part in enumerate(parts):
        if idx > 0:
            cur = cur / part
        if str(cur) in ("", "."):
            continue
        try:
            st = os.lstat(str(cur))
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            if not _is_macos_system_root_symlink(cur):
                raise PermissionError(f"REFUSING_SYMLINK_ANCESTOR: {cur}")
        elif not stat.S_ISDIR(st.st_mode):
            raise PermissionError(f"ANCESTOR_NOT_DIR: {cur}")


def _ensure_safe_parent_dir(path: Path) -> Path:
    _reject_symlink_if_present(path)
    parent = path.parent if str(path.parent) else Path(".")
    _reject_symlink_ancestors(parent)
    parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_ancestors(parent)
    allow_mac_root = _is_macos_system_root_symlink(parent)
    p_st = os.stat(str(parent)) if allow_mac_root else os.lstat(str(parent))
    if (not allow_mac_root and stat.S_ISLNK(p_st.st_mode)) or not stat.S_ISDIR(p_st.st_mode):
        raise PermissionError(f"REFUSING_SYMLINK_PARENT: {parent}")
    return parent


@contextmanager
def _telemetry_file_lock(store_path: Path) -> Iterator[None]:
    _ensure_safe_parent_dir(store_path)
    lock_path = Path(f"{store_path}.lock")
    _reject_symlink_if_present(lock_path)
    if fcntl is not None:
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(str(lock_path), flags, 0o600)
        except OSError as exc:
            raise PermissionError(f"LOCK_OPEN_FAILED: {lock_path}: {exc}") from exc
        try:
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"REFUSING_NON_REGULAR_LOCK: {lock_path}")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
        return
    # Non-Unix fallback: bounded atomic O_CREAT|O_EXCL lockfile (fail-closed; never unlink by mtime)
    acquired = False
    for _ in range(200):
        try:
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            acquired = True
            break
        except FileExistsError:
            try:
                st = os.lstat(str(lock_path))
                if stat.S_ISLNK(st.st_mode):
                    raise PermissionError(f"REFUSING_SYMLINK: {lock_path}")
            except FileNotFoundError:
                continue
            time.sleep(0.01)
    if not acquired:
        raise TimeoutError(f"TELEMETRY_LOCK_TIMEOUT: {lock_path}")
    try:
        yield
    finally:
        lock_path.unlink(missing_ok=True)


def _strict_json_loads(raw: str) -> Any:
    def _no_dups(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        obj: Dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"DUPLICATE_JSON_KEY: '{k}'")
            obj[k] = v
        return obj
    return json.loads(raw, object_pairs_hook=_no_dups)


def read_regular_text_secure(path: Path, max_bytes: int = MAX_TELEMETRY_FILE_BYTES) -> Optional[str]:
    """Read UTF-8 text via `O_NOFOLLOW` + `(dev, ino)` TOCTOU verification; returns None if absent."""
    parent = path.parent if str(path.parent) else Path(".")
    _reject_symlink_ancestors(parent)
    try:
        pre_st = os.lstat(str(path))
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(pre_st.st_mode):
        raise PermissionError(f"REFUSING_SYMLINK: {path}")
    if not stat.S_ISREG(pre_st.st_mode):
        raise PermissionError(f"NOT_REGULAR_FILE: {path}")
    if pre_st.st_size > max_bytes:
        raise ValueError(f"FILE_TOO_LARGE:{pre_st.st_size}:{path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise PermissionError(f"OPEN_NOFOLLOW_FAILED: {path}: {exc}") from exc
    with os.fdopen(fd, "rb") as fh:
        fd_st = os.fstat(fh.fileno())
        if not stat.S_ISREG(fd_st.st_mode):
            raise PermissionError(f"NOT_REGULAR_FILE_FD: {path}")
        if (fd_st.st_dev, fd_st.st_ino) != (pre_st.st_dev, pre_st.st_ino):
            raise PermissionError(f"IDENTITY_MISMATCH_TOCTOU: {path}")
        if fd_st.st_size > max_bytes:
            raise ValueError(f"FILE_TOO_LARGE_FD:{fd_st.st_size}:{path}")
        raw = fh.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"FILE_TOO_LARGE_READ:{len(raw)}:{path}")
    return raw.decode("utf-8")


def atomic_write_text_secure(path: Path, content: str, mode: int = 0o600) -> None:
    """Atomically write UTF-8 text via `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW`, `0o600`, `fsync`, and `os.replace`."""
    parent = _ensure_safe_parent_dir(path)
    tmp_path = parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(tmp_path), flags, mode)
    fd_wrapped = False
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_TELEMETRY_FILE_BYTES:
            raise ValueError(f"TELEMETRY_SIZE_CAP_EXCEEDED: {len(encoded)} > {MAX_TELEMETRY_FILE_BYTES}")
        with os.fdopen(fd, "wb") as fh:
            fd_wrapped = True
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        _reject_symlink_if_present(path)
        os.replace(str(tmp_path), str(path))
    except BaseException:
        if not fd_wrapped:
            os.close(fd)
        if tmp_path.exists() or tmp_path.is_symlink():
            try:
                tmp_path.unlink()
            except OSError as cleanup_err:
                _ = cleanup_err
        raise


def _dead_scar_triggered(rec: Dict[str, Any]) -> bool:
    wins, trials = int(rec.get("wins", 0)), int(rec.get("trials", 0))
    return trials >= DEAD_SCAR_MIN_TRIALS and (wins * 100) < (trials * DEAD_SCAR_MIN_WIN_PCT)


def _is_efficacy_frozen(rec: Dict[str, Any]) -> bool:
    return bool(rec.get("frozen", False)) or int(rec.get("consecutive_losses", 0)) >= TWO_STRIKE_LOSS_LIMIT or _dead_scar_triggered(rec)


def _effective_freeze_reason(rec: Dict[str, Any]) -> Optional[str]:
    if rec.get("freeze_reason"):
        return str(rec["freeze_reason"])
    if int(rec.get("consecutive_losses", 0)) >= TWO_STRIKE_LOSS_LIMIT:
        return "two_strike_consecutive_losses"
    if _dead_scar_triggered(rec):
        return "dead_scar_low_efficacy"
    return "manual_or_persisted_freeze" if bool(rec.get("frozen", False)) else None


def _apply_efficacy_outcome(rec: Dict[str, Any], passed: bool) -> bool:
    was_frozen = _is_efficacy_frozen(rec)
    if was_frozen:
        if not rec.get("freeze_reason"):
            rec["freeze_reason"] = _effective_freeze_reason(rec)
        rec["frozen"] = True
    rec["trials"] = min(_U32_MAX, int(rec.get("trials", 0)) + 1)
    if passed:
        rec["wins"], rec["consecutive_losses"] = min(_U32_MAX, int(rec.get("wins", 0)) + 1), 0
    else:
        rec["losses"], rec["consecutive_losses"] = min(_U32_MAX, int(rec.get("losses", 0)) + 1), min(_U32_MAX, int(rec.get("consecutive_losses", 0)) + 1)
    if not bool(rec.get("frozen", False)):
        if int(rec["consecutive_losses"]) >= TWO_STRIKE_LOSS_LIMIT:
            rec["frozen"], rec["freeze_reason"] = True, "two_strike_consecutive_losses"
        elif _dead_scar_triggered(rec):
            rec["frozen"], rec["freeze_reason"] = True, "dead_scar_low_efficacy"
    return (not was_frozen) and _is_efficacy_frozen(rec)


def _load_store(store_path: Path) -> Dict[str, Any]:
    raw = read_regular_text_secure(store_path, MAX_TELEMETRY_FILE_BYTES)
    if raw is None or len(raw) == 0:
        return {
            "schema": DELIVERY_TELEMETRY_SCHEMA, "schema_version": SCHEMA_VERSION,
            "updated_at_utc": 0, "envelopes": {}, "efficacy": {}, "applied_outcomes": set(),
        }
    doc = _strict_json_loads(raw.strip())
    if not isinstance(doc, dict):
        raise ValueError("UNRECOGNIZED_TELEMETRY_STORE: root must be object")
    if "schema" not in doc or not isinstance(doc["schema"], str):
        raise ValueError("UNRECOGNIZED_TELEMETRY_STORE: missing or invalid schema")
    if doc["schema"] != DELIVERY_TELEMETRY_SCHEMA:
        raise ValueError(f"UNRECOGNIZED_TELEMETRY_STORE: UNSUPPORTED_SCHEMA: expected {DELIVERY_TELEMETRY_SCHEMA}, got {doc['schema']!r}")
    raw_updated = doc.get("updated_at_utc")
    if raw_updated is None:
        updated_at_utc = 0
    elif not _is_nonneg_int(raw_updated):
        raise ValueError(f"CORRUPT_STORE_UPDATED_AT: expected non-negative int or null, got {raw_updated!r}")
    elif raw_updated > _U64_MAX:
        raise ValueError(f"INT_OVERFLOW: 'updated_at_utc'={raw_updated} exceeds u64::MAX")
    else:
        updated_at_utc = raw_updated
    if "envelopes" not in doc or not isinstance(doc["envelopes"], dict):
        raise ValueError("UNRECOGNIZED_TELEMETRY_STORE: missing or invalid 'envelopes' object")
    if "efficacy" not in doc or not isinstance(doc["efficacy"], dict):
        raise ValueError("UNRECOGNIZED_TELEMETRY_STORE: missing or invalid 'efficacy' object")
    envelopes, efficacy = doc["envelopes"], doc["efficacy"]
    needs_backfill = "applied_outcomes" not in doc
    if needs_backfill:
        applied_outcomes: Set[str] = set()
    elif isinstance(doc["applied_outcomes"], list) and all(isinstance(x, str) for x in doc["applied_outcomes"]):
        applied_outcomes = set(doc["applied_outcomes"])
    else:
        raise ValueError("INVALID_TELEMETRY_STORE: CORRUPT_STORE_APPLIED_OUTCOMES")

    def _chk_int(val: Any, cap: int, label: str, key: str) -> None:
        if not _is_nonneg_int(val) or val > cap:
            tag = "INT_OVERFLOW" if _is_nonneg_int(val) else label
            raise ValueError(f"INVALID_TELEMETRY_STORE: {tag}: {key}")

    for k, env in envelopes.items():
        if not isinstance(env, dict):
            raise ValueError(f"INVALID_TELEMETRY_STORE: ENVELOPE_NOT_OBJECT: {k}")
        for req_fld in ("session_id", "stage", "client", "envelope_id"):
            val = env.get(req_fld)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_ENVELOPE_{req_fld.upper()}: {k}")
        if not is_supported_client(env["client"]) or env["stage"] not in SUPPORTED_STAGES:
            raise ValueError(f"INVALID_TELEMETRY_STORE: UNSUPPORTED_CLIENT_OR_STAGE: {k}")
        if "source_digest" in env and not isinstance(env["source_digest"], str):
            raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_ENVELOPE_SOURCE_DIGEST: {k}")
        if env.get("patch_digest") is not None and not isinstance(env["patch_digest"], str):
            raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_ENVELOPE_PATCH_DIGEST: {k}")
        for arr_fld in ("capsule_ids", "pitfall_ids"):
            if arr_fld in env and (not isinstance(env[arr_fld], list) or not all(isinstance(x, str) for x in env[arr_fld])):
                raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_ENVELOPE_{arr_fld.upper()}: {k}")
        for req_u64 in ("estimated_tokens", "timestamp_utc"):
            if req_u64 in env:
                _chk_int(env[req_u64], _U64_MAX, f"CORRUPT_ENVELOPE_{req_u64.upper()}", k)
        for opt_u64 in ("included_at_utc", "patch_bound_at_utc"):
            if env.get(opt_u64) is not None:
                _chk_int(env[opt_u64], _U64_MAX, f"CORRUPT_ENVELOPE_{opt_u64.upper()}", k)
        for b_fld in ("included_in_input", "included_before_first_patch", "patch_bound", "first_patch"):
            if b_fld in env and not isinstance(env[b_fld], bool):
                raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_ENVELOPE_{b_fld.upper()}: {k}")
        for opt_b in ("passed", "patch_passed"):
            if env.get(opt_b) is not None and not isinstance(env[opt_b], bool):
                raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_ENVELOPE_{opt_b.upper()}: {k}")
    for k, rec in efficacy.items():
        if not isinstance(rec, dict):
            raise ValueError(f"INVALID_TELEMETRY_STORE: EFFICACY_NOT_OBJECT: {k}")
        for opt_s in ("id", "freeze_reason"):
            if rec.get(opt_s) is not None and not isinstance(rec[opt_s], str):
                raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_EFFICACY_{opt_s.upper()}: {k}")
        for cnt_fld in ("wins", "losses", "trials", "consecutive_losses"):
            _chk_int(rec.get(cnt_fld, 0), _U32_MAX, f"CORRUPT_EFFICACY_{cnt_fld.upper()}", k)
        if "frozen" in rec and not isinstance(rec["frozen"], bool):
            raise ValueError(f"INVALID_TELEMETRY_STORE: CORRUPT_EFFICACY_FROZEN: {k}")
        if "last_updated_utc" in rec:
            _chk_int(rec["last_updated_utc"], _U64_MAX, "CORRUPT_EFFICACY_LAST_UPDATED_UTC", k)
    if needs_backfill:
        for env in envelopes.values():
            p_dig = env.get("patch_digest") or ""
            if env.get("patch_bound") is True and env.get("included_before_first_patch") is True and p_dig:
                for item_id in (*env.get("capsule_ids", ()), *env.get("pitfall_ids", ())):
                    applied_outcomes.add(f"{env['client']}|{env['session_id']}|{p_dig}|{item_id}")
    return {
        "schema": DELIVERY_TELEMETRY_SCHEMA, "schema_version": SCHEMA_VERSION,
        "updated_at_utc": updated_at_utc, "envelopes": envelopes, "efficacy": efficacy,
        "applied_outcomes": applied_outcomes,
    }


def _save_store(store_path: Path, store: Dict[str, Any]) -> None:
    ordered_envs = {k: store["envelopes"][k] for k in sorted(store["envelopes"].keys())}
    ordered_eff: Dict[str, Any] = {}
    for k in sorted(store["efficacy"].keys()):
        rec = dict(store["efficacy"][k])
        rec["id"], rec["frozen"], rec["freeze_reason"] = str(rec.get("id") or k), _is_efficacy_frozen(rec), _effective_freeze_reason(rec)
        ordered_eff[k] = rec
    payload = {
        "schema": DELIVERY_TELEMETRY_SCHEMA, "schema_version": SCHEMA_VERSION,
        "updated_at_utc": int(store.get("updated_at_utc", 0)),
        "envelopes": ordered_envs, "efficacy": ordered_eff,
        "applied_outcomes": sorted(store.get("applied_outcomes", ())),
    }
    atomic_write_text_secure(store_path, json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", mode=0o600)


def _validate_existing_envelope(envelopes: Dict[str, Dict[str, Any]], env_id: str, client: str, sess_in: str, src_dig: str) -> Dict[str, Any]:
    env = envelopes.get(env_id)
    if env is None:
        raise ValueError(f"UNKNOWN_ENVELOPE_ID: '{env_id}'")
    if env["client"] != client:
        raise ValueError(f"CLIENT_MISMATCH: expected '{env['client']}', got '{client}'")
    if sess_in and env["session_id"] != sess_in:
        raise ValueError(f"SESSION_MISMATCH: expected '{env['session_id']}', got '{sess_in}'")
    if src_dig and env.get("source_digest") and env["source_digest"] != src_dig:
        raise ValueError("SOURCE_DIGEST_MISMATCH")
    return env


def record_telemetry_event(
    store_path: Path, *, client: str, stage: str, session_id: str = "", envelope_id: str = "",
    source_digest: str = "", patch_digest: str = "", capsule_ids: Sequence[str] = (),
    pitfall_ids: Sequence[str] = (), estimated_tokens: int = 0, passed: Optional[bool] = None,
    first_patch: Optional[bool] = None, timestamp_utc: Optional[int] = None,
) -> Dict[str, Any]:
    """Record a single receipt transition (`issued`, `included_in_input`, or `patch_bound`) atomically under `<store>.lock`."""
    store_path = Path(store_path)
    if not is_supported_client(client):
        raise ValueError(f"UNSUPPORTED_CLIENT: '{client}' not in {SUPPORTED_CLIENTS}")
    if stage not in SUPPORTED_STAGES:
        raise ValueError(f"UNSUPPORTED_STAGE: '{stage}' not in {SUPPORTED_STAGES}")
    if not _is_nonneg_int(estimated_tokens):
        raise ValueError("INVALID_ESTIMATED_TOKENS: expected non-negative int")
    if estimated_tokens > _U64_MAX:
        raise ValueError(f"INT_OVERFLOW: estimated_tokens={estimated_tokens} exceeds u64::MAX")
    if timestamp_utc is None:
        now = int(time.time())
    else:
        if not _is_nonneg_int(timestamp_utc):
            raise ValueError("INVALID_TIMESTAMP_UTC: expected non-negative int")
        if timestamp_utc > _U64_MAX:
            raise ValueError(f"INT_OVERFLOW: timestamp_utc={timestamp_utc} exceeds u64::MAX")
        now = timestamp_utc
    env_id = _validate_id_token("envelope_id", envelope_id, required=True)
    sess_in = _validate_id_token("session_id", session_id, required=(stage == "issued"))
    src_dig = _validate_id_token("source_digest", source_digest, required=False)
    clean_caps = _dedupe_ids(capsule_ids) if stage == "issued" else []
    clean_pits = _dedupe_ids(pitfall_ids) if stage == "issued" else []
    p_dig = _validate_id_token("patch_digest", patch_digest, required=True) if stage == "patch_bound" else ""
    if stage == "patch_bound" and not isinstance(passed, bool):
        raise ValueError("MISSING_PASSED_FLAG: patch_bound requires bool passed")

    with _telemetry_file_lock(store_path):
        store = _load_store(store_path)
        envelopes, efficacy = store["envelopes"], store["efficacy"]
        newly_frozen: List[str] = []
        efficacy_updated = False

        if stage == "issued":
            if env_id in envelopes:
                raise ValueError(f"DUPLICATE_ENVELOPE_ID: '{env_id}' already issued")
            env: Dict[str, Any] = {
                "envelope_id": env_id, "session_id": sess_in, "client": client, "source_digest": src_dig,
                "capsule_ids": clean_caps, "pitfall_ids": clean_pits,
                "estimated_tokens": estimated_tokens, "stage": "issued", "timestamp_utc": now,
                "included_in_input": False, "included_before_first_patch": False, "included_at_utc": None,
                "patch_bound": False, "patch_digest": "", "passed": None, "first_patch": False, "patch_bound_at_utc": None,
            }
            envelopes[env_id] = env
        elif stage == "included_in_input":
            env = _validate_existing_envelope(envelopes, env_id, client, sess_in, src_dig)
            session_has_patch = any(e["client"] == client and e["session_id"] == env["session_id"] and bool(e.get("patch_bound")) for e in envelopes.values())
            if not bool(env.get("included_in_input")):
                env["included_in_input"], env["included_at_utc"] = True, now
                if env.get("stage") == "issued":
                    env["stage"] = "included_in_input"
                if not bool(env.get("patch_bound")) and not session_has_patch:
                    env["included_before_first_patch"] = True
        else:
            env = _validate_existing_envelope(envelopes, env_id, client, sess_in, src_dig)
            if bool(env.get("patch_bound")):
                raise ValueError(f"ENVELOPE_ALREADY_PATCH_BOUND: '{env_id}'")
            prior_patch = any(e["client"] == client and e["session_id"] == env["session_id"] and bool(e.get("patch_bound")) for e in envelopes.values())
            if first_patch is None:
                is_first = not prior_patch
            else:
                if not isinstance(first_patch, bool):
                    raise ValueError("INVALID_FIRST_PATCH_FLAG: expected bool")
                if first_patch and prior_patch:
                    raise ValueError("FIRST_PATCH_ALREADY_BOUND_IN_SESSION")
                is_first = first_patch
            env["patch_bound"], env["patch_digest"], env["passed"] = True, p_dig, passed
            env["first_patch"], env["patch_bound_at_utc"], env["stage"] = is_first, now, "patch_bound"
            tracked_ids = sorted(set(env.get("capsule_ids", [])) | set(env.get("pitfall_ids", [])))
            if bool(env["included_before_first_patch"]) and tracked_ids:
                applied_outcomes: Set[str] = store["applied_outcomes"]
                for item_id in tracked_ids:
                    dedup_key = f"{client}|{env['session_id']}|{p_dig}|{item_id}"
                    if dedup_key in applied_outcomes:
                        continue
                    applied_outcomes.add(dedup_key)
                    efficacy_updated = True
                    rec = efficacy.setdefault(item_id, {"id": item_id, "wins": 0, "losses": 0, "trials": 0, "consecutive_losses": 0, "frozen": False, "freeze_reason": None})
                    if _apply_efficacy_outcome(rec, bool(passed)):
                        newly_frozen.append(item_id)

        store["updated_at_utc"] = now
        _save_store(store_path, store)
        frozen_ids = sorted(k for k, v in efficacy.items() if _is_efficacy_frozen(v))
    return {
        "ok": True, "schema": DELIVERY_TELEMETRY_SCHEMA, "schema_version": SCHEMA_VERSION,
        "stage": stage, "client": client, "session_id": env["session_id"], "envelope_id": env_id,
        "included_before_first_patch": bool(env["included_before_first_patch"]),
        "first_patch": bool(env["first_patch"]), "passed": env["passed"],
        "efficacy_updated": efficacy_updated,
        "newly_frozen_ids": newly_frozen, "frozen_ids": frozen_ids,
    }


def build_telemetry_report(store_path: Path) -> Dict[str, Any]:
    """Compute honest Delivery Gate #3 report across all 4 clients without dropping failed/unincluded sessions."""
    store = _load_store(Path(store_path))
    envelopes, efficacy = store["envelopes"], store["efficacy"]
    clients_report: Dict[str, Dict[str, Any]] = {}
    total_sessions_all = 0
    for client in sorted(SUPPORTED_CLIENTS):
        all_sessions, included_sessions = set(), set()
        issued_count = patch_bound_count = patch_passed_count = 0
        for env in envelopes.values():
            if env["client"] != client:
                continue
            issued_count += 1
            all_sessions.add(str(env["session_id"]))
            if bool(env.get("included_before_first_patch")):
                included_sessions.add(str(env["session_id"]))
            if bool(env.get("patch_bound")):
                patch_bound_count += 1
                if env.get("passed") is True:
                    patch_passed_count += 1
        tot_s, inc_s = len(all_sessions), len(included_sessions)
        total_sessions_all += tot_s
        clients_report[client] = {
            "client": client, "total_sessions": tot_s, "issued_count": issued_count,
            "included_before_first_patch_count": inc_s,
            "included_before_first_patch_rate": round(inc_s / tot_s, 4) if tot_s > 0 else 0.0,
            "patch_bound_count": patch_bound_count, "patch_passed_count": patch_passed_count,
            "patch_pass_rate": round(patch_passed_count / patch_bound_count, 4) if patch_bound_count > 0 else 0.0,
            "gate_3_min_10_sessions_met": tot_s >= GATE_3_MIN_SESSIONS,
        }
    frozen_ids = sorted(k for k, v in efficacy.items() if _is_efficacy_frozen(v))
    efficacy_table = [
        {
            "id": item_id, "wins": int(r.get("wins", 0)), "losses": int(r.get("losses", 0)),
            "trials": int(r.get("trials", 0)), "consecutive_losses": int(r.get("consecutive_losses", 0)),
            "efficacy_pct": round((int(r.get("wins", 0)) * 100.0) / int(r.get("trials", 0)), 2) if int(r.get("trials", 0)) > 0 else 0.0,
            "frozen": _is_efficacy_frozen(r), "freeze_reason": _effective_freeze_reason(r),
        }
        for item_id, r in sorted(efficacy.items())
    ]
    return {
        "ok": True, "schema": DELIVERY_TELEMETRY_SCHEMA, "schema_version": SCHEMA_VERSION,
        "total_envelopes": len(envelopes), "total_sessions": total_sessions_all,
        "clients": clients_report, "frozen_ids": frozen_ids,
        "frozen_count": len(frozen_ids), "efficacy_table": efficacy_table,
    }


def render_telemetry_report_json(store_path: Path) -> str:
    return json.dumps(build_telemetry_report(store_path), ensure_ascii=False, separators=(",", ":"))


def try_load_frozen_ids(store_path: Path) -> Set[str]:
    """Fail-closed loader for auto-frozen capsule/pitfall IDs (raises on corrupt/unreadable store)."""
    store = _load_store(Path(store_path))
    return {k for k, v in store["efficacy"].items() if _is_efficacy_frozen(v)}


def load_frozen_ids(store_path: Path) -> Set[str]:
    try:
        return try_load_frozen_ids(store_path)
    except (OSError, ValueError, PermissionError):
        return set()


@dataclass
class DeliveryTelemetryTracker:
    """Stateful convenience wrapper bound to a single `store_path`."""
    store_path: Path

    def record_issued(self, **kw: Any) -> Dict[str, Any]:
        return record_telemetry_event(self.store_path, stage="issued", **kw)
    def record_included_in_input(self, **kw: Any) -> Dict[str, Any]:
        return record_telemetry_event(self.store_path, stage="included_in_input", **kw)
    def record_patch_bound(self, **kw: Any) -> Dict[str, Any]:
        return record_telemetry_event(self.store_path, stage="patch_bound", **kw)
    def report(self) -> Dict[str, Any]:
        return build_telemetry_report(self.store_path)
    def render_report_json(self) -> str:
        return render_telemetry_report_json(self.store_path)
    def load_frozen_ids(self) -> Set[str]:
        return load_frozen_ids(self.store_path)
