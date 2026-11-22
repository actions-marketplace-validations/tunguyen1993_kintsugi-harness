"""Symlink-Safe Atomic Build Manifest Store & Rollback Ledger (`kintsugi.forge.build_manifest`).

Persists `ToolBuild/1` records and optional `ToolSpec/1` snapshots to
`.kintsugi/build_manifests.json` with `0o600` permissions, `assert_not_symlink`,
`O_NOFOLLOW` reads, `fcntl.flock` concurrency locking, secret-egress validation,
and atomic rollback to prior verified artifact hashes.
"""

from __future__ import annotations

import fcntl
import hmac
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from kintsugi.capability.contracts_v2 import ForgeState, ToolBuild
from kintsugi.capability.schemas import (
    ToolSpec,
    assert_no_raw_secrets,
    canonical_json_dumps,
    normalize_sha256,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.shield import assert_not_symlink, atomic_write_json

DEFAULT_BUILD_MANIFEST_REL_PATH = ".kintsugi/build_manifests.json"
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024


def compute_tool_build_hash(build: ToolBuild) -> str:
    """Compute canonical `sha256:<hex>` integrity digest over a `ToolBuild` excluding `build_hash`."""
    payload = build.to_dict()
    payload.pop("build_hash", None)
    return sha256_digest(payload)


def _read_regular_nofollow(target: Path, *, max_bytes: int = _MAX_MANIFEST_BYTES) -> bytes:
    assert_not_symlink(target.parent)
    assert_not_symlink(target)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target), flags)
    except OSError as exc:
        if target.is_symlink():
            raise PermissionError(f"SECURITY_SYMLINK_REFUSED: {target}") from exc
        raise
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_NON_REGULAR_FILE_REFUSED: {target}")
        raw = handle.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError(f"MANIFEST_TOO_LARGE: exceeds {max_bytes} bytes.")
    return raw


@dataclass(frozen=True)
class RollbackResult:
    """Structured result of an atomic rollback operation."""

    tool_id: str
    rolled_back_build: ToolBuild
    restored_build: Optional[ToolBuild]
    restored_spec: Optional[ToolSpec]
    restored_artifact_hash: Optional[str]
    manifest_path: Path

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "tool_id": self.tool_id,
                "rolled_back_build_id": self.rolled_back_build.build_id,
                "rolled_back_state": self.rolled_back_build.state.value,
                "restored_build_id": self.restored_build.build_id if self.restored_build else None,
                "restored_artifact_hash": self.restored_artifact_hash,
                "manifest_path": str(self.manifest_path),
            }
        )


class BuildManifestStore:
    """Atomic, symlink-safe store for `ToolBuild/1` provenance and verified rollback."""

    SCHEMA_VERSION = "BuildManifestStore/1"

    def __init__(
        self,
        storage_path: Optional[Union[str, Path]] = None,
        *,
        workspace_root: Optional[Union[str, Path]] = None,
        auto_load: bool = True,
    ) -> None:
        if storage_path is not None:
            resolved = Path(storage_path)
        elif workspace_root is not None:
            ws = Path(workspace_root)
            assert_not_symlink(ws)
            resolved = ws / DEFAULT_BUILD_MANIFEST_REL_PATH
        else:
            resolved = Path.cwd() / DEFAULT_BUILD_MANIFEST_REL_PATH

        assert_not_symlink(resolved.parent)
        assert_not_symlink(resolved)
        self.storage_path: Path = resolved
        self._builds: Dict[str, ToolBuild] = {}
        self._active_builds: Dict[str, str] = {}
        self._verified_history: Dict[str, List[str]] = {}
        self._spec_snapshots: Dict[str, Dict[str, Any]] = {}

        if auto_load and self.storage_path.exists():
            self.load()

    def _lock_path(self) -> Path:
        return self.storage_path.parent / f".{self.storage_path.name}.lock"

    def _ensure_parent_dir(self) -> None:
        assert_not_symlink(self.storage_path.parent)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.storage_path.parent, 0o700)
        assert_not_symlink(self.storage_path)

    def _serialize_state(self) -> Dict[str, Any]:
        ordered_builds = {bid: self._builds[bid].to_dict() for bid in sorted(self._builds.keys())}
        ordered_specs = {bid: dict(self._spec_snapshots[bid]) for bid in sorted(self._spec_snapshots.keys())}
        payload = {
            "schema": self.SCHEMA_VERSION,
            "total_builds": len(ordered_builds),
            "active_builds": {tid: self._active_builds[tid] for tid in sorted(self._active_builds.keys())},
            "verified_history": {
                tid: list(self._verified_history[tid]) for tid in sorted(self._verified_history.keys())
            },
            "builds": ordered_builds,
            "spec_snapshots": ordered_specs,
        }
        assert_no_raw_secrets(canonical_json_dumps(payload), context="BuildManifestStore")
        return payload

    def _load_unlocked(self) -> None:
        assert_not_symlink(self.storage_path.parent)
        assert_not_symlink(self.storage_path)
        if not self.storage_path.exists():
            self._builds = {}
            self._active_builds = {}
            self._verified_history = {}
            self._spec_snapshots = {}
            return
        raw_bytes = _read_regular_nofollow(self.storage_path)
        data = json.loads(raw_bytes.decode("utf-8"))
        if not isinstance(data, dict) or data.get("schema") != self.SCHEMA_VERSION:
            raise ValueError(f"INVALID_MANIFEST_SCHEMA: expected {self.SCHEMA_VERSION!r}.")

        builds: Dict[str, ToolBuild] = {}
        for bid, raw_build in dict(data.get("builds") or {}).items():
            build = ToolBuild.from_dict(raw_build)
            if build.build_id != bid:
                raise ValueError(f"MANIFEST_BUILD_ID_MISMATCH: key={bid!r} != {build.build_id!r}.")
            if build.build_hash:
                expected_hash = compute_tool_build_hash(build)
                if not hmac.compare_digest(build.build_hash, expected_hash):
                    raise ValueError(f"MANIFEST_TAMPERED_BUILD_HASH: {build.build_id}.")
            builds[bid] = build

        active: Dict[str, str] = {}
        for tid, bid in dict(data.get("active_builds") or {}).items():
            safe_tid = validate_tool_id(tid)
            if bid not in builds:
                raise ValueError(f"MANIFEST_UNKNOWN_ACTIVE_BUILD: {bid!r} for {safe_tid}.")
            active[safe_tid] = str(bid)

        history: Dict[str, List[str]] = {}
        for tid, bid_list in dict(data.get("verified_history") or {}).items():
            safe_tid = validate_tool_id(tid)
            history[safe_tid] = [str(x) for x in bid_list if str(x) in builds]

        specs: Dict[str, Dict[str, Any]] = {}
        for bid, raw_spec in dict(data.get("spec_snapshots") or {}).items():
            if bid in builds and isinstance(raw_spec, dict):
                specs[bid] = ToolSpec.from_dict(raw_spec, from_discovery=False).to_dict()

        self._builds = builds
        self._active_builds = active
        self._verified_history = history
        self._spec_snapshots = specs

    def load(self) -> None:
        """Safely load manifest file under `O_NOFOLLOW` and verify `build_hash` integrity."""
        self._ensure_parent_dir()
        lock_path = self._lock_path()
        assert_not_symlink(lock_path)
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_SH)
            try:
                self._load_unlocked()
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def save(self) -> Path:
        """Atomically persist manifest state to `self.storage_path` with `0o600` permissions."""
        self._ensure_parent_dir()
        lock_path = self._lock_path()
        assert_not_symlink(lock_path)
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                payload = self._serialize_state()
                atomic_write_json(self.storage_path, payload, mode=0o600, indent=2)
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return self.storage_path

    def _with_exclusive_transaction(self, mutator) -> Any:
        self._ensure_parent_dir()
        lock_path = self._lock_path()
        assert_not_symlink(lock_path)
        with lock_path.open("a+", encoding="utf-8") as lock_file:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                if self.storage_path.exists():
                    self._load_unlocked()
                result = mutator()
                payload = self._serialize_state()
                atomic_write_json(self.storage_path, payload, mode=0o600, indent=2)
                return result
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def record_build(
        self,
        build: ToolBuild,
        *,
        tool_spec: Optional[ToolSpec] = None,
        set_active: bool = True,
    ) -> ToolBuild:
        """Atomically record a `ToolBuild` (and optional verified `ToolSpec` snapshot)."""
        if not isinstance(build, ToolBuild):
            raise ValueError("INVALID_TOOL_BUILD: expected ToolBuild instance.")
        if tool_spec is not None and not isinstance(tool_spec, ToolSpec):
            raise ValueError("INVALID_TOOL_SPEC: expected ToolSpec instance.")

        sealed_dict = build.to_dict()
        if not sealed_dict.get("built_at"):
            sealed_dict["built_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tmp_build = ToolBuild.from_dict(sealed_dict)
        sealed_dict["build_hash"] = compute_tool_build_hash(tmp_build)
        sealed_build = ToolBuild.from_dict(sealed_dict)

        def _mutate() -> ToolBuild:
            self._builds[sealed_build.build_id] = sealed_build
            if tool_spec is not None:
                self._spec_snapshots[sealed_build.build_id] = ToolSpec.from_dict(
                    tool_spec.to_dict(), from_discovery=False
                ).to_dict()
            if sealed_build.state == ForgeState.VERIFIED:
                hist = self._verified_history.setdefault(sealed_build.tool_id, [])
                if sealed_build.build_id not in hist:
                    hist.append(sealed_build.build_id)
                if set_active:
                    self._active_builds[sealed_build.tool_id] = sealed_build.build_id
            return sealed_build

        return self._with_exclusive_transaction(_mutate)

    def get_build(self, build_id: str) -> Optional[ToolBuild]:
        return self._builds.get(validate_safe_text(build_id, field_name="build_id"))

    def get_active_build(self, tool_id: str) -> Optional[ToolBuild]:
        safe_tid = validate_tool_id(tool_id)
        bid = self._active_builds.get(safe_tid)
        if not bid:
            return None
        return self._builds.get(bid)

    def get_active_spec(self, tool_id: str) -> Optional[ToolSpec]:
        active = self.get_active_build(tool_id)
        if active is None:
            return None
        raw_spec = self._spec_snapshots.get(active.build_id)
        if not raw_spec:
            return None
        return ToolSpec.from_dict(raw_spec, from_discovery=False)

    def list_builds(self, tool_id: Optional[str] = None) -> List[ToolBuild]:
        if tool_id is None:
            return [self._builds[bid] for bid in sorted(self._builds.keys())]
        safe_tid = validate_tool_id(tool_id)
        return [self._builds[bid] for bid in sorted(self._builds.keys()) if self._builds[bid].tool_id == safe_tid]

    def rollback(
        self,
        tool_id: str,
        *,
        target_build_id: Optional[str] = None,
        target_artifact_hash: Optional[str] = None,
        reason: str = "manual_rollback",
    ) -> RollbackResult:
        """Atomically roll back active verified build for `tool_id` to a prior verified artifact hash."""
        safe_tid = validate_tool_id(tool_id)
        safe_reason = validate_safe_text(reason, field_name="reason")
        norm_target_hash = (
            normalize_sha256(target_artifact_hash, field_name="target_artifact_hash")
            if target_artifact_hash
            else None
        )

        def _mutate() -> RollbackResult:
            active_bid = self._active_builds.get(safe_tid)
            if not active_bid or active_bid not in self._builds:
                raise KeyError(f"NO_ACTIVE_VERIFIED_BUILD: '{safe_tid}' has no active verified build.")
            current_build = self._builds[active_bid]
            if current_build.state != ForgeState.VERIFIED:
                raise ValueError(
                    f"INVALID_ROLLBACK_STATE: active build '{active_bid}' is in state {current_build.state.value}."
                )

            history_ids = [
                bid
                for bid in self._verified_history.get(safe_tid, [])
                if bid != active_bid
                and bid in self._builds
                and self._builds[bid].state == ForgeState.VERIFIED
            ]

            restored_build: Optional[ToolBuild] = None
            if target_build_id is not None:
                safe_tbid = validate_safe_text(target_build_id, field_name="target_build_id")
                for bid in reversed(history_ids):
                    if bid == safe_tbid:
                        restored_build = self._builds[bid]
                        break
                if restored_build is None:
                    raise KeyError(f"ROLLBACK_TARGET_BUILD_NOT_FOUND: '{safe_tbid}' for '{safe_tid}'.")
            elif norm_target_hash is not None:
                for bid in reversed(history_ids):
                    if hmac.compare_digest(self._builds[bid].artifact_hash, norm_target_hash):
                        restored_build = self._builds[bid]
                        break
                if restored_build is None:
                    raise KeyError(
                        f"ROLLBACK_TARGET_HASH_NOT_FOUND: '{norm_target_hash}' for '{safe_tid}'."
                    )
            else:
                if history_ids:
                    restored_build = self._builds[history_ids[-1]]

            rb_meta = dict(current_build.rollback_metadata)
            rb_meta.update(
                {
                    "reason": safe_reason,
                    "rolled_back_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "rolled_back_artifact_hash": current_build.artifact_hash,
                    "restored_build_id": restored_build.build_id if restored_build else "none",
                    "restored_artifact_hash": restored_build.artifact_hash if restored_build else "none",
                }
            )
            rolled = current_build.transition_to(ForgeState.ROLLED_BACK, rollback_metadata=rb_meta)
            rolled_dict = rolled.to_dict()
            rolled_dict["build_hash"] = compute_tool_build_hash(rolled)
            rolled_sealed = ToolBuild.from_dict(rolled_dict)
            self._builds[active_bid] = rolled_sealed

            restored_spec: Optional[ToolSpec] = None
            if restored_build is not None:
                self._active_builds[safe_tid] = restored_build.build_id
                raw_spec = self._spec_snapshots.get(restored_build.build_id)
                if raw_spec:
                    restored_spec = ToolSpec.from_dict(raw_spec, from_discovery=False)
            else:
                self._active_builds.pop(safe_tid, None)

            return RollbackResult(
                tool_id=safe_tid,
                rolled_back_build=rolled_sealed,
                restored_build=restored_build,
                restored_spec=restored_spec,
                restored_artifact_hash=restored_build.artifact_hash if restored_build else None,
                manifest_path=self.storage_path,
            )

        return self._with_exclusive_transaction(_mutate)


__all__ = [
    "DEFAULT_BUILD_MANIFEST_REL_PATH",
    "RollbackResult",
    "BuildManifestStore",
    "compute_tool_build_hash",
]
