"""Hermetic Spawn/Exec Execution Worker (`kintsugi.runtime.hermetic_worker`).

Eliminates `os.fork()` parent memory sharing and host Python object-graph
crawling / preflight side-effect risk for Build #3 by executing pinned
module:callable entrypoints inside a freshly spawned `subprocess.Popen`
isolated interpreter (`-I -S`, `shell=False`, `close_fds=True`,
`start_new_session=True`) with:

- Pre-spawn and in-worker `O_NOFOLLOW` + `(st_dev, st_ino)` + `st_nlink == 1`
  + constant-time `hmac.compare_digest` module-file pinning.
- Strict allowlist environment scrubbing (zero host secrets, `PYTHONPATH`,
  `PYTHONHOME`, `PYTHONINSPECT`, `PYTHONSTARTUP`, `LD_*`, `DYLD_*`, or proxies).
- Length-prefixed JSON framing over dedicated pipe descriptors (`req_r`,
  `resp_w`) and bounded streaming stdout/stderr capture.
- Worker FD sanitization (`0/1/2` confined, `>= 3` closed except IPC pipe,
  response FD relocated with `FD_CLOEXEC`).
- Real OS confinement inside the spawned worker: macOS Seatbelt (`sandbox_init`)
  or Linux Landlock + seccomp-BPF network/exec deny (fail-closed with
  `SANDBOX_LINUX_LANDLOCK_FAILED:errno=...` when unavailable), plus an
  irremovable `sys.addaudithook` and `sys.meta_path` import prefix guard.
- Full process-tree timeout cleanup via `terminate_execution_tree()` so
  detached `setsid()` grandchildren never survive deadline expiration.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import hmac
import importlib.abc
import importlib.machinery
import importlib.util
import inspect
import json
import keyword
import math
import os
import platform
import posixpath
import re
import resource
import secrets
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import types
from dataclasses import dataclass, field
from pathlib import Path, PosixPath, PurePosixPath
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple, Union

_IS_WORKER_MAIN = __name__ == "__main__" and "--worker-mode" in sys.argv[1:]

_FALLBACK_TROJAN_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
)

if not _IS_WORKER_MAIN:
    from kintsugi.capability.schemas import (
        ExecutionReceipt,
        ExecutionStatus,
        SecurityContext,
        SecurityProfile,
        assert_dataclass_type_unmodified,
        assert_execution_receipt_type_unmodified,
        canonical_json_dumps,
        extract_exact_security_context_dict,
        is_valid_sha256,
        normalize_sha256,
        redact_secrets_in_text,
        redact_secrets_in_value,
        safe_exact_str_dict_view,
        sha256_digest,
        snapshot_class_lifecycle,
        validate_safe_text,
        validate_tool_id,
    )
    from kintsugi.process_tree import EXEC_TOKEN_NAME, new_execution_token, terminate_execution_tree
    from kintsugi.shield import TROJAN_UNICODE_RE, resolve_safe_child_path

    _VALID_SECURITY_PROFILES: FrozenSet[str] = frozenset(p.value for p in SecurityProfile)
    _HW_TYPE_DICT_DESCR = type.__dict__["__dict__"]
    _HW_OBJECT_GETATTR = object.__getattribute__
else:  # pragma: no cover - invoked directly in `-I -S --worker-mode`
    EXEC_TOKEN_NAME = "_KINTSUGI_EXEC_TOKEN"
    TROJAN_UNICODE_RE = _FALLBACK_TROJAN_UNICODE_RE

    def safe_exact_str_dict_view(mapping: Any, *, max_entries: int = 4096) -> Optional[Dict[str, Any]]:
        if type(mapping) is not dict or dict.__len__(mapping) > max_entries:
            return None
        out: Dict[str, Any] = {}
        for k in dict.__iter__(mapping):
            if type(k) is not str:
                return None
            out[k] = dict.__getitem__(mapping, k)
        return out

DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_OUTPUT_BYTES = 262144
MAX_IPC_REQUEST_BYTES = 16 * 1024 * 1024
MAX_IPC_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_MODULE_FILE_BYTES = 16 * 1024 * 1024
_MAX_PAYLOAD_DEPTH = 32

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_TOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HOME_ENV_VAR_RE = re.compile(r"\$(?:\{?\s*(?:HOME|USER|LOGNAME|PWD|SSH_AUTH_SOCK)\s*\}?)")
_SENSITIVE_PATH_FRAGMENTS: Tuple[str, ...] = (
    "/.ssh",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "/.aws",
    ".aws/",
    "/.gnupg",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/master.passwd",
)
_AUDIT_EXEC_PERMISSIONS: FrozenSet[str] = frozenset(
    {"process.exec", "subprocess", "subprocess.run", "exec"}
)
_SCRUB_ENV_PREFIXES: Tuple[str, ...] = ("PYTHON", "LD_", "DYLD_")
_SCRUB_ENV_EXACT: FrozenSet[str] = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONEXECUTABLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "FTP_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "ftp_proxy",
        "no_proxy",
    }
)
_FORBIDDEN_BROAD_ROOTS: FrozenSet[str] = frozenset(
    {
        "/",
        "/Users",
        "/home",
        "/etc",
        "/var",
        "/tmp",
        "/private",
        "/private/tmp",
        "/private/var",
    }
)


def _normalize_sha256_local(digest: Any, *, field_name: str = "digest") -> str:
    if type(digest) is not str:
        raise ValueError(f"INVALID_{field_name.upper()}: expected sha256:<64hex> string.")
    cleaned = digest.strip().lower()
    if not _SHA256_RE.fullmatch(cleaned):
        raise ValueError(f"INVALID_{field_name.upper()}: '{digest}' is not a valid sha256:<64hex> digest.")
    return cleaned


def _assert_no_symlink_local(path_obj: Path) -> None:
    if path_obj.is_symlink():
        raise PermissionError(f"SECURITY_SYMLINK_REFUSED: {path_obj}")


def _resolve_safe_child_local(base_dir: Path, relative_path: str) -> Optional[Path]:
    if not relative_path or "\x00" in relative_path or TROJAN_UNICODE_RE.search(relative_path):
        return None
    if os.path.isabs(relative_path) or relative_path.startswith(("/", "\\")):
        return None
    parts = [seg for seg in relative_path.replace("\\", "/").split("/") if seg not in ("", ".")]
    if any(seg == ".." for seg in parts):
        return None
    base_resolved = base_dir.resolve()
    candidate = (base_resolved / "/".join(parts)).resolve() if parts else base_resolved
    try:
        candidate.relative_to(base_resolved)
    except ValueError:
        return None
    return candidate


def _check_no_symlink_components(root_resolved: Path, rel_path: str) -> None:
    """Verify every existing segment from `root_resolved` down to `rel_path` is not a symlink."""
    _assert_no_symlink_local(root_resolved)
    clean_rel = rel_path.replace("\\", "/").strip("/")
    if not clean_rel or clean_rel == ".":
        return
    cur = root_resolved
    for seg in clean_rel.split("/"):
        if not seg or seg == ".":
            continue
        if seg == "..":
            raise PermissionError("SECURITY_PATH_TRAVERSAL_REFUSED: '..' segment forbidden")
        cur = cur / seg
        _assert_no_symlink_local(cur)


def _match_root_relative(raw_path: str, root: Path) -> Optional[str]:
    """Return relative sub-path when `raw_path` lexically sits inside `root` or `root.resolve()`."""
    norm_raw = posixpath.normpath(raw_path.replace("\\", "/"))
    for base_str in (str(root).rstrip("/"), str(root.resolve()).rstrip("/")):
        if not base_str:
            continue
        if norm_raw == base_str:
            return "."
        if norm_raw.startswith(base_str + "/"):
            return norm_raw[len(base_str) + 1 :]
    return None


def _confine_path_under_roots(raw_path: str, roots: Sequence[Path]) -> Tuple[Path, Path]:
    """Confine `raw_path` strictly under one of `roots`, returning `(safe_path, matched_root)`."""
    cleaned = str(raw_path or "").strip()
    if not cleaned or "\x00" in cleaned:
        raise PermissionError("SECURITY_PATH_EMPTY_OR_NULL")
    if TROJAN_UNICODE_RE.search(cleaned):
        raise PermissionError("SECURITY_PATH_TROJAN_UNICODE")
    if cleaned == "~" or cleaned.startswith("~/") or _HOME_ENV_VAR_RE.search(cleaned):
        raise PermissionError("SECURITY_PATH_HOME_EXPANSION_FORBIDDEN")
    lowered = cleaned.lower()
    if any(frag in lowered for frag in _SENSITIVE_PATH_FRAGMENTS):
        raise PermissionError("SECURITY_SENSITIVE_PATH_FORBIDDEN")
    if ".." in [seg for seg in cleaned.replace("\\", "/").split("/") if seg]:
        raise PermissionError("SECURITY_PATH_TRAVERSAL_REFUSED")

    is_abs = os.path.isabs(cleaned) or cleaned.startswith("/")
    for root in roots:
        _assert_no_symlink_local(root)
        root_resolved = root.resolve()
        rel = _match_root_relative(cleaned, root) if is_abs else cleaned
        if rel is None and is_abs:
            cand_path = Path(cleaned)
            _assert_no_symlink_local(cand_path)
            try:
                rel_obj = cand_path.resolve().relative_to(root_resolved)
                rel = str(rel_obj) if str(rel_obj) != "." else "."
            except ValueError:
                rel = None
        if rel is None:
            continue
        _check_no_symlink_components(root_resolved, rel)
        resolver = _resolve_safe_child_local if _IS_WORKER_MAIN else resolve_safe_child_path
        safe = root_resolved if rel == "." else resolver(root_resolved, rel)
        if safe is None:
            continue
        _assert_no_symlink_local(safe)
        return safe, root_resolved
    raise PermissionError("SECURITY_PATH_OUTSIDE_CONFINEMENT")


def _validate_safe_dotted_name(value: Any, *, field_name: str, allow_dots: bool) -> str:
    """Validate a safe Python module or attribute identifier without dunder or traversal risk."""
    if type(value) is not str:
        raise ValueError(f"INVALID_{field_name.upper()}: expected str.")
    if "\x00" in value or TROJAN_UNICODE_RE.search(value):
        raise ValueError(f"INVALID_{field_name.upper()}: forbidden control characters.")
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 256:
        raise ValueError(f"INVALID_{field_name.upper()}: empty or exceeds max length.")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned:
        raise ValueError(f"INVALID_{field_name.upper()}: path separators or '..' forbidden.")
    if not allow_dots and "." in cleaned:
        raise ValueError(f"INVALID_{field_name.upper()}: dotted access forbidden.")
    segments = cleaned.split(".") if allow_dots else [cleaned]
    for seg in segments:
        if not seg or not _IDENT_RE.fullmatch(seg) or keyword.iskeyword(seg):
            raise ValueError(f"INVALID_{field_name.upper()}: invalid identifier segment '{seg}'.")
        if seg.startswith("__") and seg.endswith("__"):
            raise ValueError(f"INVALID_{field_name.upper()}: dunder segment '{seg}' forbidden.")
    return cleaned


def validate_safe_module_path(module_path: Any) -> str:
    """Validate `module_path` as a safe dotted Python module identifier."""
    return _validate_safe_dotted_name(module_path, field_name="module_path", allow_dots=True)


def validate_safe_callable_attr(callable_attr: Any) -> str:
    """Validate `callable_attr` as a safe single-segment Python attribute identifier."""
    return _validate_safe_dotted_name(callable_attr, field_name="callable_attr", allow_dots=False)


def validate_allowed_import_prefixes(prefixes: Any) -> Tuple[str, ...]:
    """Validate and normalize `allowed_import_prefixes` into a deduplicated tuple of dotted names."""
    if prefixes is None:
        return ()
    if type(prefixes) not in (tuple, list, set, frozenset):
        raise ValueError("INVALID_ALLOWED_IMPORT_PREFIXES: expected sequence of module prefix strings.")
    deduped: List[str] = []
    seen: Set[str] = set()
    for item in prefixes:
        norm = validate_safe_module_path(item)
        if norm not in seen:
            seen.add(norm)
            deduped.append(norm)
    return tuple(deduped)


def _validate_spec_tool_id(tool_id: Any) -> str:
    """Validate `tool_id` using strict `type(tool_id) is str` check before schema rules."""
    if type(tool_id) is not str:
        raise ValueError("INVALID_TOOL_ID: expected str.")
    if not _IS_WORKER_MAIN:
        return validate_tool_id(tool_id)
    cleaned = tool_id.strip()
    if not cleaned or "\x00" in cleaned or TROJAN_UNICODE_RE.search(cleaned):
        raise ValueError("INVALID_TOOL_ID")
    if "/" in cleaned or "\\" in cleaned or ".." in cleaned or not _SAFE_TOOL_ID_RE.fullmatch(cleaned):
        raise ValueError("INVALID_TOOL_ID")
    return cleaned


_MAX_PAYLOAD_NODES = 4096


def _validate_strict_json_value(value: Any, *, depth: int = 0) -> Any:
    """Validate `value` using exact built-in type identity ONLY so no host dunder hooks or cycles execute."""
    nodes = 0
    active_ids: Set[int] = set()

    def _walk(item: Any, cur_depth: int) -> Any:
        nonlocal nodes
        if cur_depth > _MAX_PAYLOAD_DEPTH:
            raise ValueError("PAYLOAD_DEPTH_EXCEEDED")
        nodes += 1
        if nodes > _MAX_PAYLOAD_NODES:
            raise ValueError("PAYLOAD_MAX_NODES_EXCEEDED")
        if item is None:
            return None
        vt = type(item)
        if vt is bool or vt is int:
            return item
        if vt is float:
            if not math.isfinite(item):
                raise ValueError("PAYLOAD_NON_FINITE_FLOAT")
            return item
        if vt is str:
            if "\x00" in item or TROJAN_UNICODE_RE.search(item):
                raise ValueError("PAYLOAD_TROJAN_OR_NULL_STRING")
            return item
        if vt is list:
            oid = id(item)
            if oid in active_ids:
                raise ValueError("PAYLOAD_CYCLIC_REFERENCE_FORBIDDEN")
            active_ids.add(oid)
            try:
                return [_walk(sub, cur_depth + 1) for sub in list.__iter__(item)]
            finally:
                active_ids.discard(oid)
        if vt is tuple:
            oid = id(item)
            if oid in active_ids:
                raise ValueError("PAYLOAD_CYCLIC_REFERENCE_FORBIDDEN")
            active_ids.add(oid)
            try:
                return [_walk(sub, cur_depth + 1) for sub in tuple.__iter__(item)]
            finally:
                active_ids.discard(oid)
        if vt is dict:
            oid = id(item)
            if oid in active_ids:
                raise ValueError("PAYLOAD_CYCLIC_REFERENCE_FORBIDDEN")
            view = safe_exact_str_dict_view(item, max_entries=_MAX_PAYLOAD_NODES)
            if view is None:
                raise TypeError("UNSUPPORTED_PAYLOAD_DICT_OR_KEY_TYPE")
            active_ids.add(oid)
            try:
                out: Dict[str, Any] = {}
                for k, v in dict.items(view):
                    if "\x00" in k or TROJAN_UNICODE_RE.search(k):
                        raise ValueError("PAYLOAD_TROJAN_OR_NULL_KEY")
                    out[k] = _walk(v, cur_depth + 1)
                return out
            finally:
                active_ids.discard(oid)
        raise TypeError(f"UNSUPPORTED_PAYLOAD_TYPE:{vt.__name__}")

    return _walk(value, depth)


@dataclass(frozen=True)
class PinnedModuleFile:
    """Cryptographically and inode-pinned module file metadata (`O_NOFOLLOW` + `st_nlink == 1`)."""

    resolved_path: Path
    matched_root: Path
    sha256: str
    st_dev: int
    st_ino: int
    st_size: int
    st_nlink: int


def _read_pinned_regular_file_nofollow(
    target_path: Path,
    *,
    expected_sha256: Optional[str] = None,
    expected_dev_ino: Optional[Tuple[int, int]] = None,
    capture_bytes: bool = False,
) -> Tuple[str, Tuple[int, int, int, int], Optional[bytes]]:
    """Open `target_path` via `O_RDONLY|O_NOFOLLOW`, enforce `S_ISREG` and `st_nlink == 1`, and verify hash."""
    _assert_no_symlink_local(target_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target_path), flags)
    except OSError as exc:
        raise PermissionError(f"SECURITY_OPEN_FAILED_NOFOLLOW:{exc.errno}") from exc

    chunks: List[bytes] = []
    total_read = 0
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("SECURITY_NON_REGULAR_FILE_FORBIDDEN")
        if int(st.st_nlink) != 1:
            raise PermissionError(f"SECURITY_HARDLINK_FORBIDDEN:st_nlink={int(st.st_nlink)}")
        dev_ino = (int(st.st_dev), int(st.st_ino))
        if expected_dev_ino is not None and dev_ino != expected_dev_ino:
            raise PermissionError("TOCTOU_MODULE_INODE_CHANGED")
        hasher = hashlib.sha256()
        for _ in range(100000):
            chunk = handle.read(65536)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > _MAX_MODULE_FILE_BYTES:
                raise PermissionError("MODULE_FILE_EXCEEDS_MAX_BYTES")
            hasher.update(chunk)
            if capture_bytes:
                chunks.append(chunk)

    actual_sha = f"sha256:{hasher.hexdigest()}"
    if expected_sha256 is not None:
        norm_expected = _normalize_sha256_local(expected_sha256, field_name="expected_module_file_sha256")
        if not hmac.compare_digest(actual_sha, norm_expected):
            raise PermissionError("MODULE_FILE_SHA256_MISMATCH")

    stat_tuple = (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_nlink))
    return actual_sha, stat_tuple, (b"".join(chunks) if capture_bytes else None)


def pin_module_file(
    module_path: str,
    expected_module_file_sha256: str,
    *,
    workspace_root: Path,
    allowed_roots: Sequence[Path] = (),
    module_file_path: Optional[Union[str, Path]] = None,
) -> PinnedModuleFile:
    """Confine and pin the target module file under allowed roots before worker spawn."""
    safe_mod = validate_safe_module_path(module_path)
    expected_norm = _normalize_sha256_local(
        expected_module_file_sha256, field_name="expected_module_file_sha256"
    )
    roots: List[Path] = [workspace_root, *allowed_roots]

    if module_file_path is not None:
        mft = type(module_file_path)
        if mft is not str and mft is not Path and mft is not PosixPath and mft is not PurePosixPath:
            raise PermissionError("INVALID_MODULE_FILE_PATH_TYPE")
        raw_mod_file = str(module_file_path)
        confined, matched_root = _confine_path_under_roots(raw_mod_file, roots)
        actual_sha, stat_tuple, _ = _read_pinned_regular_file_nofollow(
            confined, expected_sha256=expected_norm, capture_bytes=False
        )
        return PinnedModuleFile(
            resolved_path=confined,
            matched_root=matched_root,
            sha256=actual_sha,
            st_dev=stat_tuple[0],
            st_ino=stat_tuple[1],
            st_size=stat_tuple[2],
            st_nlink=stat_tuple[3],
        )

    rel_parts = safe_mod.split(".")
    rel_candidates = (
        "/".join(rel_parts) + ".py",
        "/".join(rel_parts) + "/__init__.py",
    )
    for root in roots:
        _assert_no_symlink_local(root)
        root_resolved = root.resolve()
        for rel_cand in rel_candidates:
            try:
                confined, matched_root = _confine_path_under_roots(rel_cand, (root_resolved,))
            except PermissionError as exc:
                _ = exc
                continue
            if not confined.exists():
                continue
            actual_sha, stat_tuple, _ = _read_pinned_regular_file_nofollow(
                confined, expected_sha256=expected_norm, capture_bytes=False
            )
            return PinnedModuleFile(
                resolved_path=confined,
                matched_root=matched_root,
                sha256=actual_sha,
                st_dev=stat_tuple[0],
                st_ino=stat_tuple[1],
                st_size=stat_tuple[2],
                st_nlink=stat_tuple[3],
            )
    raise PermissionError("MODULE_FILE_NOT_FOUND_IN_ALLOWED_ROOTS")


@dataclass
class HermeticEntrypointSpec:
    """Pinned module:callable contract executed inside an isolated spawned worker."""

    tool_id: str
    module_path: str
    callable_attr: str
    expected_module_file_sha256: str
    module_file_path: Optional[Union[str, Path]] = None
    allowed_import_prefixes: Tuple[str, ...] = ()
    timeout_s: float = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        self.tool_id = _validate_spec_tool_id(self.tool_id)
        self.module_path = validate_safe_module_path(self.module_path)
        self.callable_attr = validate_safe_callable_attr(self.callable_attr)
        self.expected_module_file_sha256 = _normalize_sha256_local(
            self.expected_module_file_sha256, field_name="expected_module_file_sha256"
        )
        if self.module_file_path is not None:
            mft = type(self.module_file_path)
            if mft is not str and mft is not Path and mft is not PosixPath and mft is not PurePosixPath:
                raise ValueError("INVALID_MODULE_FILE_PATH: expected str or Path.")
            raw_path = str(self.module_file_path).strip()
            if not raw_path or "\x00" in raw_path or TROJAN_UNICODE_RE.search(raw_path):
                raise ValueError("INVALID_MODULE_FILE_PATH: empty, NUL, or control character.")
            if ".." in [seg for seg in raw_path.replace("\\", "/").split("/") if seg]:
                raise ValueError("REJECTED_MODULE_FILE_TRAVERSAL: '..' forbidden.")
            self.module_file_path = raw_path
        self.allowed_import_prefixes = validate_allowed_import_prefixes(self.allowed_import_prefixes)

        tst = type(self.timeout_s)
        if tst is not int and tst is not float:
            raise ValueError("INVALID_TIMEOUT_S: expected finite positive number.")
        eff_timeout = float(self.timeout_s)
        if not math.isfinite(eff_timeout) or eff_timeout <= 0.0:
            raise ValueError("INVALID_TIMEOUT_S: timeout_s must be > 0.")
        self.timeout_s = eff_timeout

        if type(self.max_output_bytes) is not int:
            raise ValueError("INVALID_MAX_OUTPUT_BYTES: expected int >= 1024.")
        if self.max_output_bytes < 1024:
            raise ValueError("INVALID_MAX_OUTPUT_BYTES: max_output_bytes must be >= 1024.")


_EXACT_HERMETIC_SPEC_FIELDS: Tuple[str, ...] = (
    "tool_id",
    "module_path",
    "callable_attr",
    "expected_module_file_sha256",
    "module_file_path",
    "allowed_import_prefixes",
    "timeout_s",
    "max_output_bytes",
)
if not _IS_WORKER_MAIN:
    _ORIG_HERMETIC_SPEC_DICT_DESCR = _HW_TYPE_DICT_DESCR.__get__(HermeticEntrypointSpec, type).get("__dict__")
    _ORIG_HERMETIC_SPEC_LIFECYCLE = snapshot_class_lifecycle(HermeticEntrypointSpec)


def extract_exact_hermetic_spec_dict(spec: Any) -> Dict[str, Any]:
    """Extract clean primitives from an exact `HermeticEntrypointSpec` with zero hooks or `Path` objects."""
    if type(spec) is not HermeticEntrypointSpec:
        raise TypeError("UNTRUSTED_HERMETIC_SPEC_SUBCLASS_FORBIDDEN")
    assert_dataclass_type_unmodified(
        HermeticEntrypointSpec,
        _EXACT_HERMETIC_SPEC_FIELDS,
        _ORIG_HERMETIC_SPEC_DICT_DESCR,
        expected_mro=(HermeticEntrypointSpec, object),
        orig_lifecycle_methods=_ORIG_HERMETIC_SPEC_LIFECYCLE,
    )
    raw_d = _HW_OBJECT_GETATTR(spec, "__dict__")
    view = safe_exact_str_dict_view(raw_d)
    if view is None:
        raise ValueError("UNTRUSTED_HERMETIC_SPEC_STORAGE")
    for k in view:
        if k not in _EXACT_HERMETIC_SPEC_FIELDS:
            raise ValueError("UNTRUSTED_HERMETIC_SPEC_EXTRA_FIELD")
    for sfield in ("tool_id", "module_path", "callable_attr", "expected_module_file_sha256"):
        if sfield not in view or type(view[sfield]) is not str:
            raise TypeError(f"UNTRUSTED_HERMETIC_SPEC_{sfield.upper()}")
    mod_file = view.get("module_file_path")
    if mod_file is not None and type(mod_file) is not str:
        raise TypeError("UNTRUSTED_HERMETIC_SPEC_MODULE_FILE_PATH")
    raw_prefixes = view.get("allowed_import_prefixes")
    if type(raw_prefixes) is not tuple:
        raise TypeError("UNTRUSTED_HERMETIC_SPEC_ALLOWED_IMPORT_PREFIXES")
    clean_prefixes = []
    for item in tuple.__iter__(raw_prefixes):
        if type(item) is not str:
            raise TypeError("UNTRUSTED_HERMETIC_SPEC_PREFIX_TYPE")
        clean_prefixes.append(item)
    t_val = view.get("timeout_s")
    vt_t = type(t_val)
    if (vt_t is not int and vt_t is not float) or not math.isfinite(float(t_val)) or float(t_val) <= 0.0:
        raise ValueError("INVALID_TIMEOUT_S: timeout_s must be finite > 0.")
    mob_val = view.get("max_output_bytes")
    if type(mob_val) is not int or mob_val < 1024:
        raise ValueError("INVALID_MAX_OUTPUT_BYTES: max_output_bytes must be int >= 1024.")
    return {
        "tool_id": _validate_spec_tool_id(view["tool_id"]),
        "module_path": validate_safe_module_path(view["module_path"]),
        "callable_attr": validate_safe_callable_attr(view["callable_attr"]),
        "expected_module_file_sha256": _normalize_sha256_local(
            view["expected_module_file_sha256"], field_name="expected_module_file_sha256"
        ),
        "module_file_path": mod_file,
        "allowed_import_prefixes": validate_allowed_import_prefixes(tuple(clean_prefixes)),
        "timeout_s": float(t_val),
        "max_output_bytes": mob_val,
    }


@dataclass
class HermeticExecutionResult:
    """Outcome and cryptographic receipt returned by `HermeticSpawnRunner.run`."""

    execution_status: ExecutionStatus
    receipt: ExecutionReceipt
    output: Any = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    wall_time_ms: float = 0.0
    isolated: bool = False
    backend: str = "none"
    worker_spawned: bool = False
    pinned_module_path: str = ""
    pinned_module_sha256: str = ""
    pinned_inode: Optional[Tuple[int, int]] = None
    error: str = ""

    @property
    def status(self) -> ExecutionStatus:
        return self.execution_status

    @property
    def passed(self) -> bool:
        return self.execution_status == ExecutionStatus.PASS and self.isolated

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_status": self.execution_status.value,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "wall_time_ms": round(self.wall_time_ms, 3),
            "isolated": self.isolated,
            "backend": self.backend,
            "worker_spawned": self.worker_spawned,
            "pinned_module_sha256": self.pinned_module_sha256,
            "pinned_inode": list(self.pinned_inode) if self.pinned_inode is not None else None,
            "error": redact_secrets_in_text(self.error),
            "receipt": self.receipt.to_dict(),
        }


_EXACT_HERMETIC_RESULT_FIELDS: Tuple[str, ...] = (
    "execution_status",
    "receipt",
    "output",
    "stdout",
    "stderr",
    "exit_code",
    "timed_out",
    "wall_time_ms",
    "isolated",
    "backend",
    "worker_spawned",
    "pinned_module_path",
    "pinned_module_sha256",
    "pinned_inode",
    "error",
)
if not _IS_WORKER_MAIN:
    _ORIG_HERMETIC_RESULT_DICT_DESCR = _HW_TYPE_DICT_DESCR.__get__(HermeticExecutionResult, type).get("__dict__")
    _ORIG_HERMETIC_RESULT_LIFECYCLE = snapshot_class_lifecycle(HermeticExecutionResult)


def assert_hermetic_result_type_unmodified() -> None:
    """Verify `HermeticExecutionResult` has not had lifecycle hooks or descriptors tampered with."""
    assert_dataclass_type_unmodified(
        HermeticExecutionResult,
        _EXACT_HERMETIC_RESULT_FIELDS,
        _ORIG_HERMETIC_RESULT_DICT_DESCR,
        expected_mro=(HermeticExecutionResult, object),
        orig_lifecycle_methods=_ORIG_HERMETIC_RESULT_LIFECYCLE,
    )


# ---------------------------------------------------------------------------
# Length-Prefixed JSON IPC Framing
# ---------------------------------------------------------------------------


def _encode_framed_json(obj: Mapping[str, Any], *, max_bytes: int) -> bytes:
    body = json.dumps(dict(obj), ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(body) > max_bytes:
        raise ValueError(f"IPC_FRAME_TOO_LARGE:{len(body)}>{max_bytes}")
    return struct.pack(">I", len(body)) + body


def _decode_framed_json(raw: bytes, *, max_bytes: int) -> Dict[str, Any]:
    if len(raw) < 4:
        raise ValueError("WORKER_EMPTY_OR_TRUNCATED_FRAME_HEADER")
    (frame_len,) = struct.unpack(">I", raw[:4])
    if frame_len == 0 or frame_len > max_bytes:
        raise ValueError(f"WORKER_INVALID_FRAME_LENGTH:{frame_len}")
    if len(raw) != 4 + frame_len:
        raise ValueError(f"WORKER_FRAME_LENGTH_MISMATCH:{len(raw) - 4}!={frame_len}")
    parsed = json.loads(raw[4:].decode("utf-8"))
    if type(parsed) is not dict:
        raise ValueError("WORKER_FRAME_PAYLOAD_NOT_OBJECT")
    return parsed


def _read_exact_fd(fd: int, length: int) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = os.read(fd, length - len(buf))
        if not chunk:
            raise ValueError("IPC_UNEXPECTED_EOF")
        buf.extend(chunk)
    return bytes(buf)


def _read_framed_fd(fd: int, *, max_bytes: int) -> Dict[str, Any]:
    header = _read_exact_fd(fd, 4)
    (frame_len,) = struct.unpack(">I", header)
    if frame_len == 0 or frame_len > max_bytes:
        raise ValueError(f"IPC_INVALID_FRAME_LENGTH:{frame_len}")
    body = _read_exact_fd(fd, frame_len)
    return _decode_framed_json(header + body, max_bytes=max_bytes)


def _write_all_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    sent = 0
    while sent < len(data):
        written = os.write(fd, view[sent:])
        if written <= 0:
            raise OSError("IPC_SHORT_WRITE")
        sent += written


# ---------------------------------------------------------------------------
# Strict Environment Scrub & Worker FD Sanitization
# ---------------------------------------------------------------------------


def _build_hermetic_env(ws_resolved: Path, execution_token: str) -> Dict[str, str]:
    """Construct a minimal allowlist-only environment for the spawned hermetic worker."""
    return {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(ws_resolved),
        "TMPDIR": str(ws_resolved),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        EXEC_TOKEN_NAME: execution_token,
        "KINTSUGI_EXEC_TOKEN": execution_token,
    }


def _scrub_worker_env_inplace() -> None:
    """Defense-in-depth scrub inside worker in case `--worker-mode` is invoked directly."""
    keep = {EXEC_TOKEN_NAME, "KINTSUGI_EXEC_TOKEN", "PATH", "LANG", "LC_ALL", "HOME", "TMPDIR"}
    for key in list(os.environ.keys()):
        if key in keep:
            continue
        if key in ("PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE"):
            continue
        if key in _SCRUB_ENV_EXACT or key.startswith(_SCRUB_ENV_PREFIXES):
            os.environ.pop(key, None)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTHONNOUSERSITE"] = "1"


def _is_safe_stdio_fd(fd: int, *, allow_pipe: bool) -> bool:
    try:
        st = os.fstat(fd)
    except OSError:
        return False
    if allow_pipe and stat.S_ISFIFO(st.st_mode):
        return True
    if stat.S_ISCHR(st.st_mode):
        try:
            null_st = os.stat("/dev/null")
            return (st.st_rdev, st.st_mode & stat.S_IFMT(st.st_mode)) == (
                null_st.st_rdev,
                null_st.st_mode & stat.S_IFMT(null_st.st_mode),
            )
        except OSError:
            return False
    return False


def _sanitize_worker_fds(keep_fds: Sequence[int]) -> None:
    """Confine FDs 0/1/2 and close every FD >= 3 outside `keep_fds`."""
    keep_set = {int(fd) for fd in keep_fds if int(fd) >= 3}
    devnull_fd = os.open("/dev/null", os.O_RDWR)
    try:
        if not _is_safe_stdio_fd(0, allow_pipe=False):
            os.dup2(devnull_fd, 0)
        for fd in (1, 2):
            if not _is_safe_stdio_fd(fd, allow_pipe=True):
                os.dup2(devnull_fd, fd)
    finally:
        if devnull_fd > 2 and devnull_fd not in keep_set:
            try:
                os.close(devnull_fd)
            except OSError as exc:
                _ = exc

    for fd_dir in ("/proc/self/fd", "/dev/fd"):
        if not os.path.isdir(fd_dir):
            continue
        try:
            open_fds = [int(name) for name in os.listdir(fd_dir) if name.isdigit()]
        except OSError as exc:
            _ = exc
            continue
        for fd in open_fds:
            if fd >= 3 and fd not in keep_set:
                try:
                    os.close(fd)
                except OSError as exc:
                    _ = exc
        break

    try:
        soft_nofile, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    except (OSError, ValueError) as exc:
        _ = exc
        soft_nofile = 4096
    upper = min(max(int(soft_nofile), 4096), 65536)
    sorted_keeps = sorted(fd for fd in keep_set if 3 <= fd < upper)
    cursor = 3
    for keep_fd in sorted_keeps:
        if keep_fd > cursor:
            os.closerange(cursor, keep_fd)
        cursor = keep_fd + 1
    if upper > cursor:
        os.closerange(cursor, upper)
    for keep_fd in keep_set:
        os.set_inheritable(keep_fd, False)


def _relocate_resp_fd(resp_fd: int) -> int:
    """Move response pipe FD to a high CLOEXEC slot and close the original argv descriptor."""
    min_target = 64
    try:
        soft_nofile, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if 0 < int(soft_nofile) <= 128:
            min_target = max(16, int(soft_nofile) // 2)
    except (OSError, ValueError) as exc:
        _ = exc
        min_target = 64
    dup_cmd = getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD)
    new_fd = int(fcntl.fcntl(resp_fd, dup_cmd, min_target))
    os.set_inheritable(new_fd, False)
    if new_fd != resp_fd:
        os.close(resp_fd)
    return new_fd


# ---------------------------------------------------------------------------
# OS Confinement (macOS Seatbelt + Linux Landlock/Seccomp + Audit Hook)
# ---------------------------------------------------------------------------


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _LandlockRulesetAttrV4(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def _configure_linux_libc_syscalls(libc: ctypes.CDLL) -> None:
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    libc.syscall.argtypes = [
        ctypes.c_long,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.syscall.restype = ctypes.c_long


def probe_linux_landlock_available() -> Tuple[bool, int]:
    """Return `(available, errno)` by probing `landlock_create_ruleset(NULL, 0, VERSION)` on Linux."""
    if not sys.platform.startswith("linux"):
        return False, 0
    if platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        return False, 0
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _configure_linux_libc_syscalls(libc)
        ctypes.set_errno(0)
        abi_ver = int(libc.syscall(444, 0, 0, 1, 0, 0))
        if abi_ver >= 1:
            return True, 0
        return False, int(ctypes.get_errno())
    except (OSError, AttributeError) as exc:
        return False, int(getattr(exc, "errno", 0) or 0)


def _validate_sbpl_safe_path(path_obj: Path) -> str:
    raw = str(path_obj)
    if not raw or "\x00" in raw or TROJAN_UNICODE_RE.search(raw):
        raise PermissionError("SECURITY_INVALID_SANDBOX_PATH")
    for bad in ('"', "(", ")", ";", "\n", "\r", "\\"):
        if bad in raw:
            raise PermissionError(f"SECURITY_INVALID_SANDBOX_PATH:{bad!r}")
    return raw


def build_hermetic_seatbelt_profile(
    ws_resolved: Path,
    *,
    ro_roots: Sequence[Path] = (),
    network_allowed: bool = False,
    allow_exec: bool = False,
) -> str:
    """Build strict macOS Seatbelt SBPL profile confined to `ws_resolved` and optional read-only roots."""
    _assert_no_symlink_local(ws_resolved)
    ws_str = _validate_sbpl_safe_path(ws_resolved.resolve())
    lines: List[str] = [
        "(version 1)",
        "(deny default)",
        '(import "system.sb")',
    ]
    if allow_exec:
        lines.append("(allow process-exec* process-fork)")
    lines.append("(allow file-read-metadata)")
    lines.append(f'(allow file-read* file-write* (subpath "{ws_str}"))')
    lines.extend(
        [
            "(allow file-read*",
            '    (subpath "/Library/Developer/CommandLineTools")',
            '    (subpath "/opt/homebrew")',
            '    (subpath "/usr")',
            '    (subpath "/System")',
            '    (subpath "/Library/Frameworks")',
            '    (subpath "/Library/Apple")',
            '    (subpath "/bin")',
            '    (subpath "/dev"))',
        ]
    )
    seen_ro: Set[str] = {ws_str}
    for ro_root in ro_roots:
        _assert_no_symlink_local(ro_root)
        ro_str = _validate_sbpl_safe_path(ro_root.resolve())
        if ro_str in seen_ro:
            continue
        seen_ro.add(ro_str)
        lines.append(f'(allow file-read* (subpath "{ro_str}"))')
    lines.append(
        "(deny file-read* "
        '(literal "/etc/passwd") (literal "/private/etc/passwd") '
        '(literal "/etc/master.passwd") (literal "/private/etc/master.passwd"))'
    )
    lines.append("(allow network*)" if network_allowed else "(deny network*)")
    return "\n".join(lines) + "\n"


def _apply_macos_seatbelt(
    ws_resolved: Path,
    *,
    ro_roots: Sequence[Path] = (),
    network_allowed: bool = False,
    allow_exec: bool = False,
) -> None:
    profile = build_hermetic_seatbelt_profile(
        ws_resolved, ro_roots=ro_roots, network_allowed=network_allowed, allow_exec=allow_exec
    )
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.sandbox_init.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char_p)]
    lib.sandbox_init.restype = ctypes.c_int
    err_ptr = ctypes.c_char_p()
    rc = int(lib.sandbox_init(profile.encode("utf-8"), 0, ctypes.byref(err_ptr)))
    if rc != 0:
        detail = err_ptr.value.decode("utf-8", errors="replace") if err_ptr.value else f"rc={rc}"
        free_fn = getattr(lib, "sandbox_free_error", None)
        if free_fn is not None and err_ptr.value:
            free_fn(err_ptr)
        raise PermissionError(f"SEATBELT_CHILD_INIT_FAILED:{detail}")


def _apply_linux_landlock(
    ws_resolved: Path,
    *,
    ro_roots: Sequence[Path] = (),
    network_allowed: bool = False,
) -> bool:
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64", "aarch64", "arm64"}:
        return False
    nr_create_ruleset = 444
    nr_add_rule = 445
    nr_restrict_self = 446
    pr_set_no_new_privs = 38
    landlock_rule_path_beneath = 1
    fs_read_exec = 0x1 | 0x4 | 0x8
    fs_rw_all = 0x1FFF
    net_bind_connect = 0x1 | 0x2

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _configure_linux_libc_syscalls(libc)
        if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
            return False
        abi_ver = int(libc.syscall(nr_create_ruleset, 0, 0, 1, 0, 0))
        ruleset_fd = -1
        if (not network_allowed) and abi_ver >= 4:
            attr_v4 = _LandlockRulesetAttrV4(handled_access_fs=fs_rw_all, handled_access_net=net_bind_connect)
            ruleset_fd = int(
                libc.syscall(nr_create_ruleset, ctypes.addressof(attr_v4), ctypes.sizeof(attr_v4), 0, 0, 0)
            )
        if ruleset_fd < 0:
            attr_v1 = _LandlockRulesetAttr(handled_access_fs=fs_rw_all)
            ruleset_fd = int(
                libc.syscall(nr_create_ruleset, ctypes.addressof(attr_v1), ctypes.sizeof(attr_v1), 0, 0, 0)
            )
        if ruleset_fd < 0:
            return False
    except OSError:
        return False

    try:
        o_path = getattr(os, "O_PATH", os.O_RDONLY)

        def _allow_tree(path_obj: Path, access_mask: int) -> bool:
            if not path_obj.exists():
                return True
            try:
                pfd = os.open(str(path_obj), o_path)
            except OSError:
                return False
            try:
                rule = _LandlockPathBeneathAttr(allowed_access=access_mask, parent_fd=pfd)
                rc = int(libc.syscall(nr_add_rule, ruleset_fd, landlock_rule_path_beneath, ctypes.addressof(rule), 0, 0))
                return rc == 0
            finally:
                os.close(pfd)

        if not _allow_tree(ws_resolved, fs_rw_all):
            return False
        all_ro_roots: List[Path] = [
            Path("/usr"),
            Path("/lib"),
            Path("/lib64"),
            Path("/bin"),
            Path("/sbin"),
            Path("/etc"),
            Path("/dev"),
            Path("/proc"),
            Path("/sys"),
            Path(sys.prefix).resolve(),
            Path(sys.base_prefix).resolve(),
            *ro_roots,
        ]
        seen_ro: Set[str] = {str(ws_resolved)}
        for root_p in all_ro_roots:
            key = str(root_p)
            if key in seen_ro or not root_p.exists():
                continue
            seen_ro.add(key)
            if not _allow_tree(root_p, fs_read_exec):
                return False
        return int(libc.syscall(nr_restrict_self, ruleset_fd, 0, 0, 0, 0)) == 0
    except OSError:
        return False
    finally:
        try:
            os.close(ruleset_fd)
        except OSError as exc:
            _ = exc


def _apply_linux_seccomp(*, deny_network: bool, allow_exec: bool) -> bool:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        expected_arch = 0xC000003E
        sys_seccomp = 317
        net_nrs = [41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 288, 299, 307, 425]
        exec_nrs = [59, 322]
    elif machine in {"aarch64", "arm64"}:
        expected_arch = 0xC00000B7
        sys_seccomp = 277
        net_nrs = [198, 199, 200, 201, 202, 203, 206, 207, 211, 212, 242, 243, 269, 425]
        exec_nrs = [221, 281]
    else:
        return False

    denied_nrs: List[int] = []
    if deny_network:
        denied_nrs.extend(net_nrs)
    if not allow_exec:
        denied_nrs.extend(exec_nrs)
    if not denied_nrs:
        return True

    bpf_ld_w_abs = 0x20
    bpf_jmp_jeq_k = 0x15
    bpf_ret_k = 0x06
    seccomp_ret_allow = 0x7FFF0000
    seccomp_ret_errno_eperm = 0x00050001
    pr_set_seccomp = 22
    seccomp_mode_filter = 2
    pr_set_no_new_privs = 38
    seccomp_set_mode_filter = 1

    n = len(denied_nrs)
    insns: List[bytes] = [
        struct.pack("=HBBI", bpf_ld_w_abs, 0, 0, 4),
        struct.pack("=HBBI", bpf_jmp_jeq_k, 0, n + 2, expected_arch),
        struct.pack("=HBBI", bpf_ld_w_abs, 0, 0, 0),
    ]
    for j, nr in enumerate(denied_nrs):
        insns.append(struct.pack("=HBBI", bpf_jmp_jeq_k, n - j, 0, nr))
    insns.append(struct.pack("=HBBI", bpf_ret_k, 0, 0, seccomp_ret_allow))
    insns.append(struct.pack("=HBBI", bpf_ret_k, 0, 0, seccomp_ret_errno_eperm))

    raw_bpf = b"".join(insns)
    bpf_buf = ctypes.create_string_buffer(raw_bpf, len(raw_bpf))
    fprog = _SockFprog(len=len(insns), filter=ctypes.addressof(bpf_buf))
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        _configure_linux_libc_syscalls(libc)
        if libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
            return False
        if libc.prctl(pr_set_seccomp, seccomp_mode_filter, ctypes.addressof(fprog), 0, 0) == 0:
            return True
        return int(libc.syscall(sys_seccomp, seccomp_set_mode_filter, 0, ctypes.addressof(fprog), 0, 0)) == 0
    except OSError:
        return False


def _apply_linux_netns() -> bool:
    clone_newuser = 0x10000000
    clone_newnet = 0x40000000
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        unshare_fn = getattr(libc, "unshare", None)
        if unshare_fn is None:
            return False
        unshare_fn.argtypes = [ctypes.c_int]
        unshare_fn.restype = ctypes.c_int
        return int(unshare_fn(clone_newuser | clone_newnet)) == 0
    except OSError:
        return False


def _discover_stdlib_top_names() -> FrozenSet[str]:
    names: Set[str] = set(sys.builtin_module_names)
    stdlib_names = getattr(sys, "stdlib_module_names", None)
    if stdlib_names is not None:
        names.update(stdlib_names)
    else:
        stdlib_dir = Path(os.__file__).resolve().parent
        try:
            for entry in stdlib_dir.iterdir():
                if entry.suffix == ".py":
                    names.add(entry.stem)
                elif entry.is_dir() and (entry / "__init__.py").exists():
                    names.add(entry.name)
            dynload_dir = stdlib_dir / "lib-dynload"
            if dynload_dir.is_dir():
                for entry in dynload_dir.iterdir():
                    if ".cpython-" in entry.name:
                        names.add(entry.name.split(".", 1)[0])
        except OSError as exc:
            _ = exc
    names.discard("ctypes")
    names.discard("_ctypes")
    return frozenset(names)


class _PinnedInMemorySourceLoader(importlib.machinery.SourceFileLoader):
    """Load pre-verified module bytes from memory so disk TOCTOU cannot occur at import time."""

    def __init__(self, fullname: str, path: str, verified_bytes: bytes) -> None:
        super().__init__(fullname, path)
        self._pinned_path = path
        self._verified_bytes = verified_bytes

    def get_data(self, path: str) -> bytes:
        if path == self._pinned_path:
            return self._verified_bytes
        raise PermissionError(f"UNPINNED_MODULE_DATA_ACCESS:{path}")


class _HermeticImportGuard(importlib.abc.MetaPathFinder):
    """Restrict non-stdlib imports strictly to `allowed_import_prefixes` and pinned `target_module`."""

    def __init__(
        self,
        *,
        target_module: str,
        allowed_prefixes: Tuple[str, ...],
        stdlib_top_names: FrozenSet[str],
        allowed_roots: Tuple[Path, ...],
    ) -> None:
        self._target_module = target_module
        self._allowed_prefixes = allowed_prefixes
        self._stdlib_top_names = stdlib_top_names
        self._allowed_roots = allowed_roots

    def is_name_allowed(self, fullname: str) -> bool:
        if fullname == self._target_module:
            return True
        if self._target_module.startswith(fullname + "."):
            return True
        for prefix in self._allowed_prefixes:
            if fullname == prefix or fullname.startswith(prefix + ".") or prefix.startswith(fullname + "."):
                return True
        top = fullname.split(".", 1)[0]
        if top in self._stdlib_top_names:
            return True
        return False

    def find_spec(
        self,
        fullname: str,
        path: Optional[Sequence[str]] = None,
        target: Any = None,
    ) -> Any:
        _ = path
        _ = target
        if not self.is_name_allowed(fullname):
            raise ImportError(f"HERMETIC_IMPORT_BLOCKED:{fullname}")
        return None


def _install_worker_audit_hook(
    ws_resolved: Path,
    *,
    network_allowed: bool,
    allow_exec: bool,
    protected_fds: FrozenSet[int],
    import_guard: _HermeticImportGuard,
    allowed_sys_path: Tuple[str, ...],
) -> None:
    """Install irremovable CPython audit hook inside worker process."""

    def _confine_hook_path(raw_path: Any, *, allow_dev_null: bool = False) -> Path:
        if raw_path is None:
            raise PermissionError("SANDBOX_EMPTY_PATH_FORBIDDEN")
        raw_str = os.fsdecode(os.fspath(raw_path))
        if not raw_str or "\x00" in raw_str or TROJAN_UNICODE_RE.search(raw_str):
            raise PermissionError("SANDBOX_INVALID_PATH_FORBIDDEN")
        if allow_dev_null and raw_str == "/dev/null":
            return Path("/dev/null")
        try:
            cand = Path(raw_str)
            resolved = cand.resolve()
            rel = resolved.relative_to(ws_resolved)
        except (OSError, ValueError) as exc:
            raise PermissionError(f"SANDBOX_OUTSIDE_WORKSPACE_FORBIDDEN:{raw_str}") from exc
        cur = ws_resolved
        for part in rel.parts:
            if part in ("", "."):
                continue
            cur = cur / part
            _assert_no_symlink_local(cur)
        return resolved

    def _reject_rel_dir_fd(path_arg: Any, dir_fd: Any) -> None:
        if dir_fd is not None:
            raw_str = os.fsdecode(os.fspath(path_arg)) if isinstance(path_arg, (str, bytes, os.PathLike)) else ""
            if not os.path.isabs(raw_str):
                raise PermissionError("SANDBOX_DIR_FD_ESCAPE_FORBIDDEN")

    def _hook(event: str, args: Tuple[Any, ...]) -> None:
        if event in {"ctypes.dlopen", "ctypes.dlsym"}:
            raise PermissionError("SANDBOX_CTYPES_FORBIDDEN")

        if event == "import":
            if not sys.meta_path or sys.meta_path[0] is not import_guard:
                raise PermissionError("SANDBOX_IMPORT_GUARD_TAMPERED")
            if tuple(sys.path) != allowed_sys_path:
                raise PermissionError("SANDBOX_SYS_PATH_TAMPERED")
            if args and isinstance(args[0], str):
                mod_name = args[0]
                if mod_name and not import_guard.is_name_allowed(mod_name):
                    # Allow bare relative import inside an already-allowed package (`args[1]` holds parent path)
                    if "." not in mod_name and len(args) > 1 and args[1] is not None:
                        return
                    raise ImportError(f"HERMETIC_IMPORT_BLOCKED:{mod_name}")
            return

        if event in {"socket.connect", "socket.bind", "socket.sendto", "socket.sendmsg", "urllib.Request", "http.client.connect"}:
            if not network_allowed:
                raise PermissionError(f"SANDBOX_NETWORK_FORBIDDEN:{event}")
            return

        if event in {"subprocess.Popen", "os.posix_spawn", "os.posix_spawnp", "os.system", "os.exec", "os.fork", "os.forkpty"}:
            if not allow_exec:
                raise PermissionError(f"SANDBOX_EXEC_PERMISSION_REQUIRED:{event}")
            return

        if event == "open":
            if not args:
                return
            path_or_fd = args[0]
            if isinstance(path_or_fd, int):
                if path_or_fd < 0 or path_or_fd in protected_fds:
                    raise PermissionError("SANDBOX_IPC_FD_ACCESS_FORBIDDEN")
                return
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else -1
            mutating = (
                (isinstance(mode, str) and any(ch in mode for ch in ("w", "a", "x", "+")))
                or (
                    isinstance(flags, int)
                    and flags >= 0
                    and bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
                )
            )
            if mutating:
                _confine_hook_path(path_or_fd, allow_dev_null=True)
            else:
                raw_low = os.fsdecode(os.fspath(path_or_fd)).lower()
                if any(frag in raw_low for frag in _SENSITIVE_PATH_FRAGMENTS):
                    _confine_hook_path(path_or_fd)
            return

        if event == "os.chdir":
            if args:
                _confine_hook_path(args[0])
            return

        if event in {"os.remove", "os.unlink", "os.rmdir"}:
            if args:
                _reject_rel_dir_fd(args[0], args[1] if len(args) > 1 else None)
                _confine_hook_path(args[0])
            return

        if event in {"os.mkdir", "os.chmod"}:
            if args:
                _reject_rel_dir_fd(args[0], args[2] if len(args) > 2 else None)
                _confine_hook_path(args[0])
            return

        if event == "os.chown":
            if args:
                _reject_rel_dir_fd(args[0], args[3] if len(args) > 3 else None)
                _confine_hook_path(args[0])
            return

        if event in {"os.truncate", "os.utime", "os.chflags", "shutil.rmtree"}:
            if args:
                _confine_hook_path(args[0])
            return

        if event in {"os.rename", "os.replace", "os.link"}:
            if len(args) >= 2:
                _reject_rel_dir_fd(args[0], args[2] if len(args) > 2 else None)
                _reject_rel_dir_fd(args[1], args[3] if len(args) > 3 else None)
                _confine_hook_path(args[0])
                _confine_hook_path(args[1])
            return

        if event == "os.symlink":
            if len(args) >= 2:
                _reject_rel_dir_fd(args[1], args[2] if len(args) > 2 else None)
                link_dst = _confine_hook_path(args[1])
                raw_src = os.fsdecode(os.fspath(args[0]))
                target_cand = Path(raw_src) if os.path.isabs(raw_src) else (link_dst.parent / raw_src)
                _confine_hook_path(target_cand)
            return

        if event in {"shutil.move", "shutil.copyfile", "shutil.copymode", "shutil.chown"}:
            if args:
                _confine_hook_path(args[0])
            if len(args) >= 2 and isinstance(args[1], (str, bytes, os.PathLike)):
                _confine_hook_path(args[1])
            return

    sys.addaudithook(_hook)


# ---------------------------------------------------------------------------
# Worker Main (`--worker-mode`)
# ---------------------------------------------------------------------------


def _load_and_invoke_pinned_module(
    *,
    module_path: str,
    callable_attr: str,
    pinned_path: Path,
    expected_sha256: str,
    expected_dev_ino: Tuple[int, int],
    allowed_roots: Tuple[Path, ...],
    ws_resolved: Path,
    allowed_prefixes: Tuple[str, ...],
    payload: Any,
) -> Any:
    confined_path, _ = _confine_path_under_roots(str(pinned_path), allowed_roots)
    _, _, verified_bytes = _read_pinned_regular_file_nofollow(
        confined_path,
        expected_sha256=expected_sha256,
        expected_dev_ino=expected_dev_ino,
        capture_bytes=True,
    )
    if verified_bytes is None:
        raise PermissionError("MODULE_BYTES_CAPTURE_FAILED")

    # Register namespace-only parent package stubs so dotted module paths never import
    # unpinned `__init__.py` code behind our back unless explicitly allowed.
    if "." in module_path:
        parts = module_path.split(".")
        for i in range(1, len(parts)):
            parent_name = ".".join(parts[:i])
            if parent_name not in sys.modules and not any(
                parent_name == p or parent_name.startswith(p + ".") for p in allowed_prefixes
            ):
                pkg_stub = types.ModuleType(parent_name)
                pkg_stub.__path__ = []  # type: ignore[attr-defined]
                sys.modules[parent_name] = pkg_stub

    loader = _PinnedInMemorySourceLoader(module_path, str(confined_path), verified_bytes)
    spec = importlib.util.spec_from_file_location(module_path, str(confined_path), loader=loader)
    if spec is None or spec.loader is None:
        raise ImportError(f"FAILED_CREATE_SPEC:{module_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_path] = mod
    spec.loader.exec_module(mod)

    target_fn = getattr(mod, callable_attr, None)
    if target_fn is None or not callable(target_fn):
        raise AttributeError(f"CALLABLE_NOT_FOUND_OR_NOT_CALLABLE:{module_path}:{callable_attr}")

    sig = inspect.signature(target_fn)
    params = sig.parameters
    positional = [
        p
        for p in params.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if "workspace_root" in params:
        if not positional:
            return target_fn(workspace_root=ws_resolved)
        return target_fn(payload, workspace_root=ws_resolved)
    if not params:
        return target_fn()
    return target_fn(payload)


def _parse_worker_cli_args(argv: Sequence[str]) -> Tuple[int, int]:
    req_fd = -1
    resp_fd = -1
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--worker-mode":
            i += 1
            continue
        if tok == "--req-fd" and i + 1 < len(argv):
            req_fd = int(argv[i + 1])
            i += 2
            continue
        if tok == "--resp-fd" and i + 1 < len(argv):
            resp_fd = int(argv[i + 1])
            i += 2
            continue
        raise ValueError(f"INVALID_WORKER_ARG:{tok}")
    if req_fd < 3 or resp_fd < 3 or req_fd == resp_fd:
        raise ValueError("INVALID_WORKER_IPC_FDS")
    return req_fd, resp_fd


def _worker_main(argv: Sequence[str]) -> int:
    _scrub_worker_env_inplace()
    req_fd, resp_fd = _parse_worker_cli_args(argv)
    _sanitize_worker_fds((req_fd, resp_fd))
    resp_fd = _relocate_resp_fd(resp_fd)
    sys.argv = [sys.argv[0]]

    kernel_sandbox_active = False
    backend = "none"
    eff_max_output = DEFAULT_MAX_OUTPUT_BYTES

    try:
        try:
            request = _read_framed_fd(req_fd, max_bytes=MAX_IPC_REQUEST_BYTES)
        finally:
            try:
                os.close(req_fd)
            except OSError as exc:
                _ = exc

        module_path = validate_safe_module_path(request.get("module_path"))
        callable_attr = validate_safe_callable_attr(request.get("callable_attr"))
        expected_sha = _normalize_sha256_local(
            request.get("expected_module_file_sha256"), field_name="expected_module_file_sha256"
        )
        ws_raw = Path(str(request.get("workspace_root") or ""))
        _assert_no_symlink_local(ws_raw)
        ws_resolved = ws_raw.resolve()
        if not ws_resolved.is_dir():
            raise PermissionError("WORKSPACE_ROOT_NOT_A_DIRECTORY")

        ro_roots: List[Path] = []
        for raw_root in request.get("allowed_roots") or []:
            rp = Path(str(raw_root))
            _assert_no_symlink_local(rp)
            rp_resolved = rp.resolve()
            if str(rp_resolved) in _FORBIDDEN_BROAD_ROOTS:
                raise PermissionError(f"FORBIDDEN_BROAD_ALLOWED_ROOT:{rp_resolved}")
            if rp_resolved.is_dir() and rp_resolved != ws_resolved:
                ro_roots.append(rp_resolved)

        pinned_path = Path(str(request.get("pinned_module_file_path") or ""))
        pinned_dev = int(request["pinned_dev"])
        pinned_ino = int(request["pinned_ino"])
        allowed_prefixes = validate_allowed_import_prefixes(request.get("allowed_import_prefixes") or ())
        allowed_perms = frozenset(
            str(p).strip().lower() for p in (request.get("allowed_permissions") or []) if str(p).strip()
        )
        network_allowed = bool(request.get("network_allowed", False))
        allow_exec = bool(allowed_perms & _AUDIT_EXEC_PERMISSIONS)
        eff_max_output = max(1024, min(MAX_IPC_RESPONSE_BYTES, int(request.get("max_output_bytes", DEFAULT_MAX_OUTPUT_BYTES))))
        payload = request.get("payload")

        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (OSError, ValueError) as exc:
            _ = exc
        os.chdir(str(ws_resolved))

        if sys.platform == "darwin":
            _apply_macos_seatbelt(
                ws_resolved,
                ro_roots=ro_roots,
                network_allowed=network_allowed,
                allow_exec=allow_exec,
            )
            backend = "seatbelt"
            kernel_sandbox_active = True
        elif sys.platform.startswith("linux"):
            if not _apply_linux_landlock(ws_resolved, ro_roots=ro_roots, network_allowed=network_allowed):
                _ll_ok, ll_errno = probe_linux_landlock_available()
                raise PermissionError(f"SANDBOX_LINUX_LANDLOCK_FAILED:errno={ll_errno}")
            if (not network_allowed) or (not allow_exec):
                sec_ok = _apply_linux_seccomp(deny_network=not network_allowed, allow_exec=allow_exec)
                if (not sec_ok) and (not network_allowed):
                    if not _apply_linux_netns():
                        raise PermissionError("SANDBOX_LINUX_NETWORK_ISOLATION_FAILED")
            backend = "linux_landlock_seccomp"
            kernel_sandbox_active = True
        else:
            raise PermissionError(f"SANDBOX_UNSUPPORTED_OS_PLATFORM:{sys.platform}")

        # Keep stdlib ahead of workspace/ro_roots so workspace files can never shadow stdlib.
        stdlib_paths = [p for p in sys.path if p]
        extra_import_paths = [str(ws_resolved)] + [str(r) for r in ro_roots]
        new_sys_path: List[str] = []
        for entry in [*stdlib_paths, *extra_import_paths]:
            if entry not in new_sys_path:
                new_sys_path.append(entry)
        sys.path[:] = new_sys_path
        allowed_sys_path = tuple(sys.path)

        stdlib_top = _discover_stdlib_top_names()
        import_guard = _HermeticImportGuard(
            target_module=module_path,
            allowed_prefixes=allowed_prefixes,
            stdlib_top_names=stdlib_top,
            allowed_roots=(ws_resolved, *ro_roots),
        )
        sys.meta_path.insert(0, import_guard)

        _install_worker_audit_hook(
            ws_resolved,
            network_allowed=network_allowed,
            allow_exec=allow_exec,
            protected_fds=frozenset({resp_fd}),
            import_guard=import_guard,
            allowed_sys_path=allowed_sys_path,
        )

        # Evict cached ctypes modules after kernel sandbox init so target code cannot
        # bypass `_HermeticImportGuard` via `sys.modules['ctypes']`.
        if not any(p == "ctypes" or p.startswith("ctypes.") for p in allowed_prefixes):
            for mod_key in list(sys.modules.keys()):
                if mod_key == "ctypes" or mod_key.startswith("ctypes.") or mod_key == "_ctypes":
                    sys.modules.pop(mod_key, None)

        result_val = _load_and_invoke_pinned_module(
            module_path=module_path,
            callable_attr=callable_attr,
            pinned_path=pinned_path,
            expected_sha256=expected_sha,
            expected_dev_ino=(pinned_dev, pinned_ino),
            allowed_roots=(ws_resolved, *ro_roots),
            ws_resolved=ws_resolved,
            allowed_prefixes=allowed_prefixes,
            payload=payload,
        )

        # Validate JSON serializability before writing response frame.
        envelope: Dict[str, Any] = {
            "ok": True,
            "backend": backend,
            "isolated": True,
            "result": result_val,
        }
        try:
            frame = _encode_framed_json(envelope, max_bytes=eff_max_output)
        except (TypeError, ValueError) as ser_exc:
            err_env = {
                "ok": False,
                "backend": backend,
                "isolated": kernel_sandbox_active,
                "sandbox_init_error": False,
                "err": f"WORKER_OUTPUT_SERIALIZATION_FAILED:{type(ser_exc).__name__}: {ser_exc}",
            }
            frame = _encode_framed_json(err_env, max_bytes=max(4096, eff_max_output))
        _write_all_fd(resp_fd, frame)
        return 0
    except Exception as exc:
        err_msg = f"{type(exc).__name__}: {exc}"
        is_sb_err = (not kernel_sandbox_active) or str(exc).startswith(
            ("SANDBOX_LINUX_", "SEATBELT_CHILD_INIT_FAILED", "SANDBOX_UNSUPPORTED_OS_PLATFORM")
        )
        err_env = {
            "ok": False,
            "backend": backend,
            "isolated": kernel_sandbox_active,
            "sandbox_init_error": is_sb_err,
            "err": err_msg[:4096],
        }
        try:
            frame = _encode_framed_json(err_env, max_bytes=max(8192, eff_max_output))
            _write_all_fd(resp_fd, frame)
        except OSError as write_exc:
            _ = write_exc
        return 1
    finally:
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except OSError as flush_exc:
            _ = flush_exc
        try:
            os.close(resp_fd)
        except OSError as close_exc:
            _ = close_exc


# ---------------------------------------------------------------------------
# Host Orchestrator (`HermeticSpawnRunner`)
# ---------------------------------------------------------------------------


def _decode_capped_utf8(raw: bytes, max_bytes: int) -> str:
    cap = max(0, int(max_bytes))
    if cap == 0 or not raw:
        return ""
    trimmed = raw[:cap]
    decoded = trimmed.decode("utf-8", errors="replace")
    encoded = decoded.encode("utf-8", errors="replace")
    if len(encoded) > cap:
        decoded = encoded[:cap].decode("utf-8", errors="ignore")
    return decoded


def _close_fd_quietly(fd: Optional[int]) -> None:
    if fd is None or fd < 0:
        return
    try:
        os.close(fd)
    except OSError as exc:
        _ = exc


def _close_stream_quietly(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError as exc:
        _ = exc


def _invoke_oracle(
    oracle: Callable[..., Any],
    execution_result: Dict[str, Any],
    spec: Any,
    payload: Any,
    security_context: Any,
) -> Tuple[bool, str]:
    try:
        sig = inspect.signature(oracle)
        positional = [
            p
            for p in sig.parameters.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in sig.parameters.values())
        if has_varargs or len(positional) >= 4:
            outcome = oracle(execution_result, spec, payload, security_context)
        elif len(positional) == 3:
            outcome = oracle(execution_result, spec, payload)
        elif len(positional) == 2:
            outcome = oracle(execution_result, payload)
        elif len(positional) == 1:
            outcome = oracle(execution_result)
        else:
            outcome = oracle()
    except Exception as exc:
        return False, f"ORACLE_EXCEPTION: {redact_secrets_in_text(str(exc))}"

    if isinstance(outcome, bool):
        return outcome, "ORACLE_PASS" if outcome else "ORACLE_FAILED"
    if isinstance(outcome, tuple) and outcome:
        passed = bool(outcome[0])
        reason = str(outcome[1]) if len(outcome) > 1 else ("ORACLE_PASS" if passed else "ORACLE_FAILED")
        return passed, reason
    if isinstance(outcome, Mapping):
        if "passed" in outcome:
            passed = bool(outcome["passed"])
        elif "verified" in outcome:
            passed = bool(outcome["verified"])
        elif "ok" in outcome:
            passed = bool(outcome["ok"])
        else:
            passed = str(outcome.get("status", "")).upper() == "PASS"
        reason = str(outcome.get("reason") or ("ORACLE_PASS" if passed else "ORACLE_FAILED"))
        return passed, reason
    return False, "ORACLE_INVALID_RETURN"


class HermeticSpawnRunner:
    """Pure `spawn`/`exec` zero-trust runner avoiding `os.fork()` and host object-graph crawling."""

    def __init__(
        self,
        *,
        allowed_roots: Sequence[Union[str, Path]] = (),
        default_timeout_s: float = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        python_executable: Optional[str] = None,
    ) -> None:
        self._allowed_roots: Tuple[Path, ...] = tuple(self._validate_root(r) for r in allowed_roots)
        self._default_timeout_s = max(0.05, float(default_timeout_s))
        self._max_output_bytes = max(1024, int(max_output_bytes))
        py_bin = str(python_executable or sys.executable)
        if not py_bin or "\x00" in py_bin or TROJAN_UNICODE_RE.search(py_bin):
            raise ValueError("INVALID_PYTHON_EXECUTABLE")
        self._python_executable = py_bin

        worker_script = Path(__file__)
        _assert_no_symlink_local(worker_script)
        self._worker_script_path = worker_script.resolve()
        if not self._worker_script_path.is_file():
            raise RuntimeError("HERMETIC_WORKER_SCRIPT_NOT_FOUND")

    @staticmethod
    def _validate_root(raw_root: Union[str, Path]) -> Path:
        rt = type(raw_root)
        if rt is not str and rt is not Path and rt is not PosixPath and rt is not PurePosixPath:
            raise ValueError("INVALID_ALLOWED_ROOT_TYPE")
        raw_str = str(raw_root).strip()
        if not raw_str or "\x00" in raw_str or TROJAN_UNICODE_RE.search(raw_str):
            raise ValueError("INVALID_ALLOWED_ROOT_TEXT")
        rp = Path(raw_str)
        _assert_no_symlink_local(rp)
        resolved = rp.resolve()
        if str(resolved) in _FORBIDDEN_BROAD_ROOTS:
            raise PermissionError(f"FORBIDDEN_BROAD_ALLOWED_ROOT:{resolved}")
        return resolved

    @staticmethod
    def _normalize_hermetic_context(security_context: Any) -> Tuple[Dict[str, Any], str]:
        """Extract and validate an exact `SecurityContext` hook-free into built-in primitives."""
        try:
            clean_dict = extract_exact_security_context_dict(security_context)
            if clean_dict["schema"] != "SecurityContext/1":
                raise ValueError(f"INVALID_SCHEMA: expected SecurityContext/1, got '{clean_dict['schema']}'.")
            raw_root = validate_safe_text(clean_dict["workspace_root"], field_name="workspace_root")
            profile_str = clean_dict["profile"].strip().upper()
            if profile_str not in _VALID_SECURITY_PROFILES:
                raise ValueError(f"INVALID_SECURITY_PROFILE: {clean_dict['profile']!r}")
            cleaned_perms = sorted(
                validate_safe_text(perm, field_name="allowed_permissions")
                for perm in clean_dict["allowed_permissions"]
            )
        except (TypeError, ValueError) as exc:
            raise PermissionError(str(exc)) from exc

        expected = sha256_digest(
            {
                "schema": "SecurityContext/1",
                "profile": profile_str,
                "workspace_root": raw_root,
                "allowed_permissions": cleaned_perms,
                "network_allowed": bool(clean_dict["network_allowed"]),
                "allow_untrusted_native": bool(clean_dict["allow_untrusted_native"]),
            }
        )
        declared_raw = clean_dict["policy_hash"]
        declared = declared_raw.strip().lower() if type(declared_raw) is str else ""
        if not declared or not is_valid_sha256(declared):
            raise PermissionError("SECURITY_POLICY_HASH_MISSING_OR_INVALID")
        if not hmac.compare_digest(declared, expected):
            raise PermissionError("SECURITY_POLICY_HASH_TAMPERED")
        ws_raw = Path(raw_root)
        _assert_no_symlink_local(ws_raw)
        ws_resolved = ws_raw.resolve()
        if not ws_resolved.is_dir():
            raise PermissionError("WORKSPACE_ROOT_NOT_A_DIRECTORY")
        clean_ctx: Dict[str, Any] = {
            "schema": "SecurityContext/1",
            "workspace_root": raw_root,
            "workspace_resolved": str(ws_resolved),
            "profile": profile_str,
            "allowed_permissions": cleaned_perms,
            "network_allowed": bool(clean_dict["network_allowed"]),
            "allow_untrusted_native": bool(clean_dict["allow_untrusted_native"]),
            "policy_hash": declared,
        }
        return clean_ctx, declared

    @staticmethod
    def _verify_context_integrity(security_context: Any) -> str:
        _, declared = HermeticSpawnRunner._normalize_hermetic_context(security_context)
        return declared

    def _make_failure_result(
        self,
        *,
        run_id: str,
        status: ExecutionStatus,
        reason: str,
        plan_hash: str,
        tool_hash: str,
        policy_hash: str,
        environment_hash: str,
        t0: float,
        exit_code: int = -1,
        timed_out: bool = False,
        isolated: bool = False,
        backend: str = "none",
        worker_spawned: bool = False,
        pinned_module_path: str = "",
        pinned_module_sha256: str = "",
        pinned_inode: Optional[Tuple[int, int]] = None,
        stdout_str: str = "",
        stderr_str: str = "",
    ) -> HermeticExecutionResult:
        wall_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        safe_reason = redact_secrets_in_text(reason)
        metrics: Dict[str, Any] = {
            "wall_time_ms": wall_ms,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "isolated": isolated,
            "backend": backend,
            "worker_spawned": worker_spawned,
            "error": safe_reason,
        }
        if pinned_inode is not None:
            metrics["pinned_inode"] = list(pinned_inode)
        try:
            assert_execution_receipt_type_unmodified()
            assert_hermetic_result_type_unmodified()
        except TypeError as exc:
            raise PermissionError(str(exc)) from exc
        receipt = ExecutionReceipt(
            run_id=run_id,
            status=status,
            plan_hash=plan_hash,
            tool_hash=tool_hash,
            policy_hash=policy_hash,
            environment_hash=environment_hash,
            exit_status=exit_code,
            verification_status="FAIL",
            artifact_digests={
                "stdout": sha256_digest(stdout_str),
                "stderr": sha256_digest(stderr_str or safe_reason),
            },
            resource_metrics=metrics,
            llm_calls=0,
            stdout_excerpt=stdout_str,
            stderr_excerpt=safe_reason or stderr_str,
        )
        return HermeticExecutionResult(
            execution_status=status,
            receipt=receipt,
            output=None,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            timed_out=timed_out,
            wall_time_ms=wall_ms,
            isolated=isolated,
            backend=backend,
            worker_spawned=worker_spawned,
            pinned_module_path=pinned_module_path,
            pinned_module_sha256=pinned_module_sha256,
            pinned_inode=pinned_inode,
            error=safe_reason,
        )

    def _spawn_and_communicate(
        self,
        *,
        ws_resolved: Path,
        framed_request: bytes,
        execution_token: str,
        timeout_s: float,
        max_output_bytes: int,
    ) -> Tuple[int, bytes, bytes, bytes, bool, bool, int]:
        req_r, req_w = os.pipe()
        resp_r, resp_w = os.pipe()
        os.set_inheritable(req_r, True)
        os.set_inheritable(resp_w, True)
        os.set_inheritable(req_w, False)
        os.set_inheritable(resp_r, False)

        clean_env = _build_hermetic_env(ws_resolved, execution_token)
        argv = [
            self._python_executable,
            "-I",
            "-S",
            str(self._worker_script_path),
            "--worker-mode",
            "--req-fd",
            str(req_r),
            "--resp-fd",
            str(resp_w),
        ]

        proc: Optional[subprocess.Popen[bytes]] = None
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(ws_resolved),
                env=clean_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                pass_fds=(req_r, resp_w),
                start_new_session=True,
            )
        finally:
            _close_fd_quietly(req_r)
            _close_fd_quietly(resp_w)
            if proc is None:
                _close_fd_quietly(req_w)
                _close_fd_quietly(resp_r)

        assert proc is not None
        req_view = memoryview(framed_request)
        req_offset = 0
        resp_buf = bytearray()
        out_buf = bytearray()
        err_buf = bytearray()
        timed_out = False
        truncated = False
        req_open = True
        resp_open = True
        resp_cap = max(8192, max_output_bytes + 4096)

        os.set_blocking(req_w, False)
        os.set_blocking(resp_r, False)
        if proc.stdout is not None:
            os.set_blocking(proc.stdout.fileno(), False)
        if proc.stderr is not None:
            os.set_blocking(proc.stderr.fileno(), False)

        selector = selectors.DefaultSelector()
        try:
            selector.register(req_w, selectors.EVENT_WRITE, data="req")
            selector.register(resp_r, selectors.EVENT_READ, data="resp")
            if proc.stdout is not None:
                selector.register(proc.stdout, selectors.EVENT_READ, data="out")
            if proc.stderr is not None:
                selector.register(proc.stderr, selectors.EVENT_READ, data="err")

            deadline = time.monotonic() + timeout_s
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                events = selector.select(timeout=remaining)
                if not events:
                    if time.monotonic() >= deadline:
                        timed_out = True
                        break
                    continue
                for key, _mask in events:
                    kind = key.data
                    if kind == "req":
                        if req_offset >= len(req_view):
                            selector.unregister(key.fileobj)
                            _close_fd_quietly(req_w)
                            req_open = False
                            continue
                        try:
                            written = os.write(key.fd, req_view[req_offset : req_offset + 65536])
                            if written > 0:
                                req_offset += written
                            if req_offset >= len(req_view):
                                selector.unregister(key.fileobj)
                                _close_fd_quietly(req_w)
                                req_open = False
                        except BlockingIOError as exc:
                            _ = exc
                        except (BrokenPipeError, OSError) as exc:
                            _ = exc
                            selector.unregister(key.fileobj)
                            _close_fd_quietly(req_w)
                            req_open = False
                    elif kind == "resp":
                        try:
                            chunk = os.read(key.fd, 8192)
                        except BlockingIOError as exc:
                            _ = exc
                            continue
                        except OSError as exc:
                            _ = exc
                            selector.unregister(key.fileobj)
                            _close_fd_quietly(resp_r)
                            resp_open = False
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            _close_fd_quietly(resp_r)
                            resp_open = False
                            continue
                        if len(resp_buf) + len(chunk) <= resp_cap:
                            resp_buf.extend(chunk)
                        else:
                            take = max(0, resp_cap - len(resp_buf))
                            if take:
                                resp_buf.extend(chunk[:take])
                            truncated = True
                    else:
                        target_buf = out_buf if kind == "out" else err_buf
                        try:
                            chunk = os.read(key.fd, 8192)
                        except BlockingIOError as exc:
                            _ = exc
                            continue
                        except OSError as exc:
                            _ = exc
                            selector.unregister(key.fileobj)
                            _close_stream_quietly(key.fileobj)
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            _close_stream_quietly(key.fileobj)
                            continue
                        if len(target_buf) < max_output_bytes:
                            take = min(len(chunk), max_output_bytes - len(target_buf))
                            target_buf.extend(chunk[:take])
                            if take < len(chunk):
                                truncated = True
                        else:
                            truncated = True

            if timed_out:
                terminate_execution_tree(proc.pid, execution_token)
                proc.wait()
                return -1, bytes(resp_buf), bytes(out_buf), bytes(err_buf), True, truncated, proc.pid

            rem_wait = max(0.01, deadline - time.monotonic())
            try:
                exit_code = int(proc.wait(timeout=rem_wait))
            except subprocess.TimeoutExpired:
                terminate_execution_tree(proc.pid, execution_token)
                proc.wait()
                return -1, bytes(resp_buf), bytes(out_buf), bytes(err_buf), True, truncated, proc.pid
            return exit_code, bytes(resp_buf), bytes(out_buf), bytes(err_buf), False, truncated, proc.pid
        finally:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except (KeyError, ValueError) as exc:
                    _ = exc
            try:
                selector.close()
            except OSError as exc:
                _ = exc
            if req_open:
                _close_fd_quietly(req_w)
            if resp_open:
                _close_fd_quietly(resp_r)
            _close_stream_quietly(proc.stdout)
            _close_stream_quietly(proc.stderr)
            if proc.poll() is None:
                terminate_execution_tree(proc.pid, execution_token)
                try:
                    proc.wait(timeout=1.0)
                except (OSError, subprocess.SubprocessError) as exc:
                    _ = exc

    def run(
        self,
        spec: HermeticEntrypointSpec,
        payload: Any = None,
        *,
        security_context: SecurityContext,
        oracle: Optional[Callable[..., Any]] = None,
        task_id: str = "",
        capability: str = "",
        plan_hash: Optional[str] = None,
        timeout_s: Optional[float] = None,
        max_output_bytes: Optional[int] = None,
    ) -> HermeticExecutionResult:
        """Pin target module file without host import, spawn isolated worker, and return sealed receipt."""
        if security_context is None:
            raise ValueError("SecurityContext is required for HermeticSpawnRunner.run()")

        t0 = time.perf_counter()
        run_id = f"hrun_{secrets.token_hex(8)}"
        empty_tool_hash = sha256_digest("unpinned_hermetic_tool")
        safe_task_id = task_id if type(task_id) is str else ""
        safe_capability = capability if type(capability) is str else ""
        fallback_policy = sha256_digest("unverified_hermetic_context")
        fallback_env = sha256_digest({"python": sys.version.split()[0], "platform": sys.platform, "mode": "hermetic_spawn"})
        fallback_plan = sha256_digest({"task_id": safe_task_id, "capability": safe_capability})

        try:
            clean_ctx, policy_hash = self._normalize_hermetic_context(security_context)
            clean_spec = extract_exact_hermetic_spec_dict(spec)
        except (PermissionError, ValueError, TypeError) as exc:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=str(exc),
                plan_hash=fallback_plan,
                tool_hash=empty_tool_hash,
                policy_hash=fallback_policy,
                environment_hash=fallback_env,
                t0=t0,
            )

        ws_resolved = Path(clean_ctx["workspace_resolved"])
        tool_id = clean_spec["tool_id"]
        module_path = clean_spec["module_path"]
        callable_attr = clean_spec["callable_attr"]
        expected_sha = clean_spec["expected_module_file_sha256"]
        allowed_prefixes = clean_spec["allowed_import_prefixes"]
        spec_timeout_s = clean_spec["timeout_s"]
        spec_max_out = clean_spec["max_output_bytes"]

        try:
            clean_payload = _validate_strict_json_value(payload)
        except (TypeError, ValueError) as exc:
            err_plan = sha256_digest({"task_id": safe_task_id, "tool_id": tool_id, "err": str(exc)})
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=f"INVALID_HERMETIC_PAYLOAD:{exc}",
                plan_hash=err_plan,
                tool_hash=empty_tool_hash,
                policy_hash=policy_hash,
                environment_hash=fallback_env,
                t0=t0,
            )

        safe_plan = (
            plan_hash.strip().lower()
            if (plan_hash is not None and type(plan_hash) is str and is_valid_sha256(plan_hash))
            else None
        )
        computed_plan_hash = safe_plan or sha256_digest(
            {
                "task_id": safe_task_id,
                "capability": safe_capability,
                "tool_id": tool_id,
                "module_path": module_path,
                "callable_attr": callable_attr,
                "payload": redact_secrets_in_value(clean_payload),
            }
        )

        try:
            dedup_roots: List[Path] = []
            seen_roots: Set[Path] = {ws_resolved}
            for r in self._allowed_roots:
                if r not in seen_roots:
                    seen_roots.add(r)
                    dedup_roots.append(r)

            pinned = pin_module_file(
                module_path,
                expected_sha,
                workspace_root=ws_resolved,
                allowed_roots=dedup_roots,
                module_file_path=clean_spec.get("module_file_path"),
            )
        except (PermissionError, ValueError, TypeError, OSError) as exc:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=str(exc),
                plan_hash=computed_plan_hash,
                tool_hash=empty_tool_hash,
                policy_hash=policy_hash,
                environment_hash=fallback_env,
                t0=t0,
            )

        pinned_inode = (pinned.st_dev, pinned.st_ino)
        req_timeout_val = timeout_s if timeout_s is not None else min(spec_timeout_s, self._default_timeout_s)
        vt_rt = type(req_timeout_val)
        if (vt_rt is not int and vt_rt is not float) or not math.isfinite(float(req_timeout_val)) or float(req_timeout_val) <= 0.0:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason="INVALID_TIMEOUT_S",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=fallback_env,
                t0=t0,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
            )
        eff_timeout = max(0.05, float(req_timeout_val))
        req_max_out = max_output_bytes if max_output_bytes is not None else min(spec_max_out, self._max_output_bytes)
        if type(req_max_out) is not int or req_max_out < 1024:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason="INVALID_MAX_OUTPUT_BYTES",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=fallback_env,
                t0=t0,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
            )
        eff_max_out = max(1024, int(req_max_out))
        env_hash = sha256_digest(
            {
                "python": sys.version.split()[0],
                "platform": sys.platform,
                "mode": "hermetic_spawn_isolated",
                "ws_hash": sha256_digest(str(ws_resolved)),
                "module_sha": pinned.sha256,
            }
        )

        request_obj: Dict[str, Any] = {
            "tool_id": tool_id,
            "module_path": module_path,
            "callable_attr": callable_attr,
            "expected_module_file_sha256": expected_sha,
            "pinned_module_file_path": str(pinned.resolved_path),
            "pinned_dev": pinned.st_dev,
            "pinned_ino": pinned.st_ino,
            "workspace_root": str(ws_resolved),
            "allowed_roots": [str(r) for r in dedup_roots],
            "allowed_import_prefixes": list(allowed_prefixes),
            "allowed_permissions": list(clean_ctx["allowed_permissions"]),
            "network_allowed": bool(clean_ctx["network_allowed"]),
            "max_output_bytes": eff_max_out,
            "payload": clean_payload,
        }
        try:
            framed_req = _encode_framed_json(request_obj, max_bytes=MAX_IPC_REQUEST_BYTES)
        except (TypeError, ValueError) as exc:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=f"REQUEST_ENCODE_FAILED:{exc}",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
            )

        execution_token = new_execution_token()
        exit_code, raw_resp, raw_out, raw_err, timed_out, truncated, worker_pid = self._spawn_and_communicate(
            ws_resolved=ws_resolved,
            framed_request=framed_req,
            execution_token=execution_token,
            timeout_s=eff_timeout,
            max_output_bytes=eff_max_out,
        )
        stdout_str = _decode_capped_utf8(raw_out, eff_max_out)
        stderr_str = _decode_capped_utf8(raw_err, eff_max_out)

        if timed_out:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.FAIL,
                reason="HERMETIC_WORKER_EXECUTION_TIMED_OUT",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=-1,
                timed_out=True,
                isolated=True,
                backend="seatbelt" if sys.platform == "darwin" else "linux_landlock_seccomp",
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        if truncated and not raw_resp:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.FAIL,
                reason="HERMETIC_WORKER_OUTPUT_TRUNCATED",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=exit_code,
                isolated=True,
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        if not raw_resp:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.FAIL,
                reason=stderr_str.strip() or f"HERMETIC_WORKER_EMPTY_RESPONSE:exit={exit_code}",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=exit_code,
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        try:
            resp_obj = _decode_framed_json(raw_resp, max_bytes=max(8192, eff_max_out + 4096))
        except (ValueError, UnicodeDecodeError) as exc:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.FAIL,
                reason=f"HERMETIC_WORKER_INVALID_FRAME:{exc}",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=exit_code,
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        backend = str(resp_obj.get("backend") or "none")
        isolated = bool(resp_obj.get("isolated", False))

        if not resp_obj.get("ok"):
            err_txt = str(resp_obj.get("err") or stderr_str or "HERMETIC_WORKER_ERROR")
            is_sb_unavail = bool(resp_obj.get("sandbox_init_error")) or "SANDBOX_LINUX_LANDLOCK_FAILED" in err_txt
            fail_status = ExecutionStatus.SANDBOX_UNAVAILABLE if is_sb_unavail else ExecutionStatus.FAIL
            return self._make_failure_result(
                run_id=run_id,
                status=fail_status,
                reason=err_txt,
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=exit_code if exit_code != 0 else 1,
                isolated=isolated,
                backend=backend,
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        # Post-exec TOCTOU check: verify pinned file was not swapped or modified during run.
        try:
            _read_pinned_regular_file_nofollow(
                pinned.resolved_path,
                expected_sha256=expected_sha,
                expected_dev_ino=pinned_inode,
                capture_bytes=False,
            )
        except PermissionError as exc:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.PERMISSION_DENIED,
                reason=f"TOCTOU_POST_EXEC_{exc}",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=exit_code,
                isolated=isolated,
                backend=backend,
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        if exit_code != 0 or not isolated:
            return self._make_failure_result(
                run_id=run_id,
                status=ExecutionStatus.FAIL if isolated else ExecutionStatus.SANDBOX_UNAVAILABLE,
                reason=stderr_str.strip() or f"HERMETIC_WORKER_EXIT:{exit_code}",
                plan_hash=computed_plan_hash,
                tool_hash=pinned.sha256,
                policy_hash=policy_hash,
                environment_hash=env_hash,
                t0=t0,
                exit_code=exit_code,
                isolated=isolated,
                backend=backend,
                worker_spawned=True,
                pinned_module_path=str(pinned.resolved_path),
                pinned_module_sha256=pinned.sha256,
                pinned_inode=pinned_inode,
                stdout_str=stdout_str,
                stderr_str=stderr_str,
            )

        result_val = resp_obj.get("result")
        oracle_reason = "VERIFIED_HERMETIC_SPAWN"
        final_status = ExecutionStatus.PASS
        verification_status = "PASS"
        if oracle is not None:
            exec_summary = {
                "status": "SUCCEEDED",
                "exit_code": exit_code,
                "output": result_val,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "workspace_root": str(ws_resolved),
                "backend": backend,
                "isolated": isolated,
            }
            passed, oracle_reason = _invoke_oracle(oracle, exec_summary, clean_spec, clean_payload, clean_ctx)
            if not passed:
                final_status = ExecutionStatus.FAIL
                verification_status = "FAIL"

        wall_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        safe_out_digest = sha256_digest(canonical_json_dumps(result_val) if result_val is not None else "null")
        metrics = {
            "wall_time_ms": wall_ms,
            "exit_code": exit_code,
            "timed_out": False,
            "isolated": isolated,
            "backend": backend,
            "worker_spawned": True,
            "worker_pid": worker_pid,
            "pinned_inode": list(pinned_inode),
            "task_id": safe_task_id,
            "tool_id": tool_id,
            "capability": safe_capability,
            "oracle_reason": oracle_reason,
            "output": redact_secrets_in_value(result_val),
        }
        try:
            assert_execution_receipt_type_unmodified()
            assert_hermetic_result_type_unmodified()
        except TypeError as exc:
            raise PermissionError(str(exc)) from exc
        receipt = ExecutionReceipt(
            run_id=run_id,
            status=final_status,
            plan_hash=computed_plan_hash,
            tool_hash=pinned.sha256,
            policy_hash=policy_hash,
            environment_hash=env_hash,
            exit_status=exit_code,
            verification_status=verification_status,
            artifact_digests={
                "stdout": sha256_digest(stdout_str),
                "stderr": sha256_digest(stderr_str),
                "output": safe_out_digest,
            },
            resource_metrics=metrics,
            llm_calls=0,
            stdout_excerpt=stdout_str,
            stderr_excerpt=stderr_str if final_status == ExecutionStatus.PASS else oracle_reason,
        )
        return HermeticExecutionResult(
            execution_status=final_status,
            receipt=receipt,
            output=result_val,
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
            timed_out=False,
            wall_time_ms=wall_ms,
            isolated=isolated,
            backend=backend,
            worker_spawned=True,
            pinned_module_path=str(pinned.resolved_path),
            pinned_module_sha256=pinned.sha256,
            pinned_inode=pinned_inode,
            error="" if final_status == ExecutionStatus.PASS else oracle_reason,
        )

    def execute(
        self,
        spec: HermeticEntrypointSpec,
        payload: Any = None,
        *,
        security_context: SecurityContext,
        oracle: Optional[Callable[..., Any]] = None,
        task_id: str = "",
        capability: str = "",
        plan_hash: Optional[str] = None,
        timeout_s: Optional[float] = None,
        max_output_bytes: Optional[int] = None,
    ) -> HermeticExecutionResult:
        """Alias for `run(...)` matching sandbox runner ergonomics."""
        return self.run(
            spec,
            payload,
            security_context=security_context,
            oracle=oracle,
            task_id=task_id,
            capability=capability,
            plan_hash=plan_hash,
            timeout_s=timeout_s,
            max_output_bytes=max_output_bytes,
        )


__all__ = [
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "HermeticEntrypointSpec",
    "HermeticExecutionResult",
    "HermeticSpawnRunner",
    "PinnedModuleFile",
    "build_hermetic_seatbelt_profile",
    "pin_module_file",
    "probe_linux_landlock_available",
    "validate_allowed_import_prefixes",
    "validate_safe_callable_attr",
    "validate_safe_module_path",
]

if _IS_WORKER_MAIN:  # pragma: no cover - executed in isolated child process
    raise SystemExit(_worker_main(sys.argv[1:]))
