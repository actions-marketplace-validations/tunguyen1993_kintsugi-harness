#!/usr/bin/env python3
"""Fail-Closed Security I/O & Unified DLP Primitives for Kintsugi Harness — Cloud Sandbox Edition.

100% pure Python 3.9+ standard library, zero external dependencies, zero dynamic code evaluation,
and zero shell invocations. Provides:
  - Symlink-ancestor and POSIX `dir_fd` + `O_NOFOLLOW` containment (hardened against parent-swap
    TOCTOU; macOS `/tmp`, `/var`, `/etc` system-root aware).
  - Non-blocking, non-following regular-file reading and streaming SHA-256 hashing via pinned
    parent `dir_fd` with post-read `(st_dev, st_ino)` identity checks.
  - Cross-process advisory file locking (`fcntl.flock` with `dir_fd` + `O_NOFOLLOW` + non-Unix
    `O_EXCL` fallback).
  - Crash-safe atomic writes via pinned `dir_fd` (`O_CREAT|O_EXCL|O_NOFOLLOW`, `fsync`,
    `os.replace(src_dir_fd=..., dst_dir_fd=...)`, `os.fsync(parent_fd)`, and `BaseException`-safe
    temp cleanup).
  - Strict JSON parsing (rejects duplicate object keys and `NaN`/`Infinity`/`-Infinity`).
  - Unified NFKC-normalized DLP scanner and fail-closed output redactor (never echoes secrets).
  - Bounded, symlink-safe iterative directory traversal (`iter_safe_files`).
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix fallback
    fcntl = None  # type: ignore[assignment]

MAX_DEFAULT_FILE_BYTES = 2 * 1024 * 1024
MAX_STORE_BYTES = 4 * 1024 * 1024
MAX_SCAN_FILES = 500
MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SCAN_DEPTH = 12

_READ_CHUNK_BYTES = 65536
_LOCK_RETRY_COUNT = 200
_LOCK_RETRY_SLEEP_SECONDS = 0.01
_MAX_OBJECT_WALK_NODES = 200000

# Construct sensitive token prefixes dynamically so static secret scanners do not false-positive
# on this module's own pattern definitions.
_PEM_RE = re.compile(
    "-----BEG"
    + r"IN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----EN"
    + r"D [A-Z0-9 ]*PRIVATE KEY-----|$)"
)
_API_TOKEN_RE = re.compile(
    r"\b(?:"
    + "sk" + r"-(?:live|proj|ant)-[A-Za-z0-9_-]{12,}|"
    + "sk" + r"-[A-Za-z0-9_-]{20,}|"
    + "gh" + r"[pousr]_[A-Za-z0-9]{20,}|"
    + "github_" + r"pat_[A-Za-z0-9_]{20,}|"
    + "AK" + r"IA[0-9A-Z]{16}|"
    + "AS" + r"IA[0-9A-Z]{16}|"
    + "AI" + r"za[0-9A-Za-z_-]{35}|"
    + "xo" + r"x[baprs]-[A-Za-z0-9-]{10,}"
    + r")\b"
)
_JWT_RE = re.compile(
    r"\b" + "ey" + r"J[A-Za-z0-9_-]{10,}\." + "ey" + r"J[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)
_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(?:private_key|mnemonic|seed_phrase)\s*[:=]\s*['\"]?[A-Za-z0-9_/+\s-]{12,}"
)
_RFC1918_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
_PRIVATE_IP_RE = re.compile(
    r"\b(?:"
    + "192" + r"\.168\." + _RFC1918_OCTET + r"\." + _RFC1918_OCTET + r"|"
    + "10" + r"\." + _RFC1918_OCTET + r"\." + _RFC1918_OCTET + r"\." + _RFC1918_OCTET + r"|"
    + "172" + r"\.(?:1[6-9]|2\d|3[01])\." + _RFC1918_OCTET + r"\." + _RFC1918_OCTET
    + r")\b"
)
_HOST_PATH_RE = re.compile(
    r"(?:/Us" + r"ers/[A-Za-z0-9._-]+/|"
    + r"/ho" + r"me/[A-Za-z0-9._-]+/|"
    + r"(?i:[a-z]:[/\\]Us" + r"ers[/\\][a-z0-9._-]+[/\\]))"
)
_HEX_KEY_WALLET_RE = re.compile(r"\b0x[0-9a-fA-F]{40,64}\b")
_BIDI_NUL_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069\u061c\x00]")

_DLP_RULES: Tuple[Tuple[str, str, re.Pattern[str]], ...] = (
    ("DLP-PEM-PRIVATE-KEY", "PEM private key block", _PEM_RE),
    ("DLP-API-TOKEN", "API token or cloud credential", _API_TOKEN_RE),
    ("DLP-JWT", "JSON Web Token (JWT)", _JWT_RE),
    ("DLP-SECRET-ASSIGNMENT", "Private key, mnemonic, or seed phrase assignment", _SECRET_ASSIGN_RE),
    ("DLP-RFC1918-IP", "Private RFC1918 LAN IP address", _PRIVATE_IP_RE),
    ("DLP-HOST-USER-PATH", "Host user directory path", _HOST_PATH_RE),
    ("DLP-HEX-KEY-OR-WALLET", "40-to-64 hex wallet address or raw key", _HEX_KEY_WALLET_RE),
    ("DLP-BIDI-OR-NUL", "Trojan Source Bidi control character or NUL byte", _BIDI_NUL_RE),
)


def is_macos_system_root_symlink(path: Path) -> bool:
    """Return True iff `path` is one of macOS's standard root symlinks (`/tmp`, `/var`, `/etc`)."""
    if sys.platform != "darwin":
        return False
    s = str(path)
    if s not in ("/var", "/tmp", "/etc"):
        return False
    try:
        return os.readlink(s) == f"private{s}"
    except OSError:
        return False


def reject_symlink(path: Path) -> None:
    """Raise PermissionError if `path` exists as a symlink (`os.lstat` fail-closed)."""
    try:
        st = os.lstat(str(path))
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"REFUSING_SYMLINK: {path}")


def reject_symlink_ancestors(directory: Path) -> None:
    """Walk every ancestor of `directory`, rejecting symlinks (except macOS system roots) and non-dirs."""
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
            if not is_macos_system_root_symlink(cur):
                raise PermissionError(f"REFUSING_SYMLINK_ANCESTOR: {cur}")
        elif not stat.S_ISDIR(st.st_mode):
            raise PermissionError(f"ANCESTOR_NOT_DIR: {cur}")


def ensure_safe_parent_dir(path: Path) -> Path:
    """Ensure `path` is not a symlink and its parent directory exists with no symlink ancestors."""
    reject_symlink(path)
    parent = path.parent if str(path.parent) else Path(".")
    reject_symlink_ancestors(parent)
    parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_ancestors(parent)
    allow_mac_root = is_macos_system_root_symlink(parent)
    p_st = os.stat(str(parent)) if allow_mac_root else os.lstat(str(parent))
    if (not allow_mac_root and stat.S_ISLNK(p_st.st_mode)) or not stat.S_ISDIR(p_st.st_mode):
        raise PermissionError(f"REFUSING_SYMLINK_PARENT: {parent}")
    return parent


def ensure_contained_path(root_dir: Path, rel_key: str) -> Path:
    """Verify every segment of `rel_key` under `root_dir` is non-symlink and stays contained in `root_dir`."""
    if (
        not isinstance(rel_key, str)
        or not rel_key
        or rel_key.startswith("/")
        or "\\" in rel_key
        or "\x00" in rel_key
    ):
        raise ValueError(f"UNSAFE_RELATIVE_PATH: {rel_key!r}")
    segments = rel_key.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise ValueError(f"UNSAFE_RELATIVE_PATH: {rel_key!r}")

    reject_symlink_ancestors(root_dir)
    root_real = os.path.realpath(str(root_dir))
    root_prefix = root_real.rstrip(os.sep) + os.sep

    cur = root_dir
    last_idx = len(segments) - 1
    for idx, part in enumerate(segments):
        cur = cur / part
        try:
            st = os.lstat(str(cur))
        except FileNotFoundError:
            raise FileNotFoundError(f"MISSING:{rel_key}") from None
        if stat.S_ISLNK(st.st_mode):
            raise PermissionError(f"SYMLINK_SEGMENT_REJECTED:{rel_key}")
        if idx < last_idx and not stat.S_ISDIR(st.st_mode):
            raise PermissionError(f"NON_DIR_SEGMENT_REJECTED:{rel_key}")

    target_real = os.path.realpath(str(cur))
    if target_real != root_real and not target_real.startswith(root_prefix):
        raise PermissionError(f"PATH_ESCAPE_REJECTED:{rel_key}")
    return cur


_DIR_FD_SUPPORT = getattr(os, "supports_dir_fd", set())
_SUPPORTS_OPEN_DIR_FD = os.open in _DIR_FD_SUPPORT
_SUPPORTS_STAT_DIR_FD = os.stat in _DIR_FD_SUPPORT
_SUPPORTS_UNLINK_DIR_FD = os.unlink in _DIR_FD_SUPPORT
_SUPPORTS_REPLACE_DIR_FD = os.replace in _DIR_FD_SUPPORT
_SUPPORTS_RENAME_DIR_FD = os.rename in _DIR_FD_SUPPORT
_SUPPORTS_DIR_FD = (
    _SUPPORTS_OPEN_DIR_FD
    and _SUPPORTS_STAT_DIR_FD
    and _SUPPORTS_UNLINK_DIR_FD
    and (_SUPPORTS_REPLACE_DIR_FD or _SUPPORTS_RENAME_DIR_FD)
)


def _open_parent_dir_fd_nofollow(directory: Path) -> int:
    """Open `directory` by walking each segment with `O_DIRECTORY|O_NOFOLLOW` via `dir_fd`.

    POSIX `dir_fd` + `O_NOFOLLOW` containment (hardened against parent-swap TOCTOU).
    Resolves macOS `/tmp`, `/var`, and `/etc` root symlinks to `/private/...` before walking.
    Caller owns and must close the returned file descriptor.
    """
    dir_path = Path(directory) if str(directory) else Path(".")
    parts = dir_path.parts
    if (
        sys.platform == "darwin"
        and len(parts) >= 2
        and parts[0] == "/"
        and parts[1] in ("tmp", "var", "etc")
        and is_macos_system_root_symlink(Path("/" + parts[1]))
    ):
        parts = ("/", "private", parts[1], *parts[2:])

    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if parts and parts[0] == "/":
        cur_fd = os.open("/", dir_flags)
        walk_segs = parts[1:]
        cur_path = Path("/")
    else:
        cur_fd = os.open(".", dir_flags)
        walk_segs = parts
        cur_path = Path(".")

    try:
        for seg in walk_segs:
            if seg in ("", "."):
                continue
            cur_path = cur_path / seg
            try:
                next_fd = os.open(seg, dir_flags, dir_fd=cur_fd)
            except OSError as exc:
                if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                    raise PermissionError(f"REFUSING_SYMLINK_ANCESTOR: {cur_path}") from exc
                if exc.errno == getattr(errno, "ENOTDIR", -1):
                    is_sym = False
                    if _SUPPORTS_STAT_DIR_FD:
                        with contextlib.suppress(OSError):
                            is_sym = stat.S_ISLNK(os.lstat(seg, dir_fd=cur_fd).st_mode)
                    if is_sym:
                        raise PermissionError(f"REFUSING_SYMLINK_ANCESTOR: {cur_path}") from exc
                    raise PermissionError(f"ANCESTOR_NOT_DIR: {cur_path}") from exc
                raise
            try:
                st = os.fstat(next_fd)
                if not stat.S_ISDIR(st.st_mode):
                    raise PermissionError(f"ANCESTOR_NOT_DIR: {cur_path}")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(cur_fd)
            cur_fd = next_fd
        return cur_fd
    except BaseException:
        os.close(cur_fd)
        raise


def _open_regular_nofollow_nonblock(path: Path, max_bytes: int) -> Tuple[int, os.stat_result]:
    """Open regular file via POSIX `dir_fd` + `O_NOFOLLOW|O_NONBLOCK` (hardened against parent-swap TOCTOU)."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError(f"INVALID_MAX_BYTES: {max_bytes!r}")
    leaf = path.name
    if not leaf or leaf in (".", ".."):
        raise PermissionError(f"REFUSING_NON_REGULAR_FILE: {path}")
    parent = path.parent if str(path.parent) else Path(".")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if _SUPPORTS_DIR_FD:
        parent_fd = _open_parent_dir_fd_nofollow(parent)
        try:
            fd = os.open(leaf, flags, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                raise PermissionError(f"REFUSING_SYMLINK: {path}") from exc
            raise
        finally:
            os.close(parent_fd)
    else:  # pragma: no cover - non-POSIX fallback
        reject_symlink_ancestors(parent)
        reject_symlink(path)
        try:
            fd = os.open(str(path), flags)
        except OSError as exc:
            if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                raise PermissionError(f"REFUSING_SYMLINK: {path}") from exc
            raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"REFUSING_NON_REGULAR_FILE: {path}")
        if st.st_size > max_bytes:
            raise ValueError(f"FILE_TOO_LARGE: {path} ({st.st_size} > {max_bytes})")
        return fd, st
    except BaseException:
        os.close(fd)
        raise


def _verify_post_read_identity(path: Path, open_st: os.stat_result) -> None:
    try:
        if _SUPPORTS_DIR_FD and _SUPPORTS_STAT_DIR_FD and path.name and path.name not in (".", ".."):
            parent = path.parent if str(path.parent) else Path(".")
            parent_fd = _open_parent_dir_fd_nofollow(parent)
            try:
                post_st = os.lstat(path.name, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        else:
            post_st = os.lstat(str(path))
    except (OSError, PermissionError) as exc:
        raise PermissionError(f"FILE_CHANGED_DURING_READ: {path}") from exc
    if stat.S_ISLNK(post_st.st_mode) or (post_st.st_dev, post_st.st_ino) != (open_st.st_dev, open_st.st_ino):
        raise PermissionError(f"FILE_CHANGED_DURING_READ: {path}")


def read_regular_bytes_secure(path: Path, max_bytes: int = MAX_DEFAULT_FILE_BYTES) -> bytes:
    """Securely read a regular file with POSIX `dir_fd` + `O_NOFOLLOW|O_NONBLOCK` containment."""
    fd, open_st = _open_regular_nofollow_nonblock(path, max_bytes)
    try:
        chunks: List[bytes] = []
        total = 0
        while True:
            blk = os.read(fd, _READ_CHUNK_BYTES)
            if not blk:
                break
            total += len(blk)
            if total > max_bytes:
                raise ValueError(f"FILE_TOO_LARGE: {path} (> {max_bytes})")
            chunks.append(blk)
        _verify_post_read_identity(path, open_st)
        return b"".join(chunks)
    finally:
        os.close(fd)


def sha256_bytes(data: bytes) -> str:
    """Return lowercase hexadecimal SHA-256 digest of `data`."""
    return hashlib.sha256(data).hexdigest()


def sha256_file_secure(path: Path, max_bytes: int = MAX_DEFAULT_FILE_BYTES) -> str:
    """Stream-compute SHA-256 of a regular file with POSIX `dir_fd` + `O_NOFOLLOW|O_NONBLOCK` containment."""
    fd, open_st = _open_regular_nofollow_nonblock(path, max_bytes)
    try:
        digest = hashlib.sha256()
        total = 0
        while True:
            blk = os.read(fd, _READ_CHUNK_BYTES)
            if not blk:
                break
            total += len(blk)
            if total > max_bytes:
                raise ValueError(f"FILE_TOO_LARGE: {path} (> {max_bytes})")
            digest.update(blk)
        _verify_post_read_identity(path, open_st)
        return digest.hexdigest()
    finally:
        os.close(fd)


def fsync_dir(directory: Path) -> None:
    """Flush directory metadata to disk where supported, suppressing unsupported-fs `OSError` cleanly."""
    if _SUPPORTS_DIR_FD:
        try:
            fd = _open_parent_dir_fd_nofollow(directory)
        except (OSError, PermissionError):
            return
    else:  # pragma: no cover - non-POSIX fallback
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            fd = os.open(str(directory), flags)
        except OSError:
            return
    try:
        with contextlib.suppress(OSError):
            os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def file_lock(target_path: Path) -> Iterator[None]:
    """Acquire an exclusive lock on `<target_path>.lock` using POSIX `dir_fd` + `fcntl.flock` or `O_EXCL`."""
    parent = ensure_safe_parent_dir(target_path)
    lock_path = Path(f"{target_path}.lock")
    lock_name = f"{target_path.name}.lock"
    reject_symlink(lock_path)
    if fcntl is not None:
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        if _SUPPORTS_DIR_FD:
            parent_fd = _open_parent_dir_fd_nofollow(parent)
            try:
                fd = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                    raise PermissionError(f"REFUSING_SYMLINK: {lock_path}") from exc
                raise
            finally:
                os.close(parent_fd)
        else:  # pragma: no cover - non-POSIX fallback
            try:
                fd = os.open(str(lock_path), flags, 0o600)
            except OSError as exc:
                if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                    raise PermissionError(f"REFUSING_SYMLINK: {lock_path}") from exc
                raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"REFUSING_NON_REGULAR_LOCK: {lock_path}")
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return

    acquired = False
    for _ in range(_LOCK_RETRY_COUNT):
        try:
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            acquired = True
            break
        except FileExistsError:
            reject_symlink(lock_path)
            time.sleep(_LOCK_RETRY_SLEEP_SECONDS)
    if not acquired:
        raise TimeoutError(f"FILE_LOCK_TIMEOUT: {lock_path}")
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            os.unlink(str(lock_path))


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise OSError("SHORT_WRITE_ZERO_BYTES")
        written += n


def atomic_write_bytes_secure(
    path: Path,
    data: bytes,
    *,
    mode: int = 0o600,
    max_bytes: int = MAX_STORE_BYTES,
) -> None:
    """Crash-safe atomic file write via POSIX `dir_fd` + `O_NOFOLLOW` containment (hardened against parent-swap TOCTOU)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("ATOMIC_WRITE_REQUIRES_BYTES")
    raw = bytes(data)
    if len(raw) > max_bytes:
        raise ValueError(f"WRITE_PAYLOAD_TOO_LARGE: {len(raw)} > {max_bytes}")
    leaf = path.name
    if not leaf or leaf in (".", ".."):
        raise PermissionError(f"REFUSING_NON_REGULAR_FILE: {path}")
    parent = ensure_safe_parent_dir(path)
    tmp_name = f".{leaf}.tmp.{os.getpid()}.{secrets.token_hex(6)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    if _SUPPORTS_DIR_FD:
        parent_fd = _open_parent_dir_fd_nofollow(parent)
        try:
            if _SUPPORTS_STAT_DIR_FD:
                with contextlib.suppress(FileNotFoundError):
                    if stat.S_ISLNK(os.lstat(leaf, dir_fd=parent_fd).st_mode):
                        raise PermissionError(f"REFUSING_SYMLINK: {path}")
            fd = os.open(tmp_name, flags, mode, dir_fd=parent_fd)
            fd_closed = False
            replaced = False
            try:
                if hasattr(os, "fchmod"):
                    with contextlib.suppress(OSError):
                        os.fchmod(fd, mode)
                _write_all(fd, raw)
                os.fsync(fd)
                os.close(fd)
                fd_closed = True
                if _SUPPORTS_STAT_DIR_FD:
                    with contextlib.suppress(FileNotFoundError):
                        if stat.S_ISLNK(os.lstat(leaf, dir_fd=parent_fd).st_mode):
                            raise PermissionError(f"REFUSING_SYMLINK: {path}")
                if _SUPPORTS_REPLACE_DIR_FD:
                    os.replace(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                elif _SUPPORTS_RENAME_DIR_FD:
                    os.rename(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                else:  # pragma: no cover - defensive guard
                    raise OSError("DIR_FD_REPLACE_UNSUPPORTED")
                replaced = True
                with contextlib.suppress(OSError):
                    os.fsync(parent_fd)
            except BaseException:
                if not fd_closed:
                    with contextlib.suppress(OSError):
                        os.close(fd)
                    fd_closed = True
                if not replaced:
                    with contextlib.suppress(OSError):
                        os.unlink(tmp_name, dir_fd=parent_fd)
                raise
        finally:
            os.close(parent_fd)
        return

    # Non-POSIX fallback
    tmp = parent / tmp_name
    reject_symlink(tmp)
    fd = os.open(str(tmp), flags, mode)
    fd_closed = False
    replaced = False
    try:
        if hasattr(os, "fchmod"):
            with contextlib.suppress(OSError):
                os.fchmod(fd, mode)
        _write_all(fd, raw)
        os.fsync(fd)
        os.close(fd)
        fd_closed = True
        reject_symlink(path)
        os.replace(str(tmp), str(path))
        replaced = True
        fsync_dir(parent)
    except BaseException:
        if not fd_closed:
            with contextlib.suppress(OSError):
                os.close(fd)
            fd_closed = True
        if not replaced:
            with contextlib.suppress(OSError):
                os.unlink(str(tmp))
        raise


def atomic_write_json_secure(
    path: Path,
    doc: Dict[str, Any],
    *,
    mode: int = 0o600,
    max_bytes: int = MAX_STORE_BYTES,
) -> None:
    """Serialize `doc` as strict UTF-8 JSON (`allow_nan=False`) and persist via `atomic_write_bytes_secure`."""
    raw = (json.dumps(doc, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    atomic_write_bytes_secure(path, raw, mode=mode, max_bytes=max_bytes)


def strict_json_loads(
    raw_text: str,
    *,
    parse_float: Optional[Callable[[str], Any]] = None,
) -> Any:
    """Parse JSON strictly, rejecting duplicate object keys and `NaN`/`Infinity`/`-Infinity`."""

    def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"DUPLICATE_JSON_KEY: {key!r}")
            out[key] = value
        return out

    def _reject_non_finite(token: str) -> Any:
        raise ValueError(f"NON_FINITE_JSON_TOKEN: {token!r}")

    if parse_float is not None:
        return json.loads(
            raw_text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
            parse_float=parse_float,
        )
    return json.loads(
        raw_text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


def dlp_scan_text(text: str) -> List[Dict[str, str]]:
    """Scan both raw and NFKC-normalized text for DLP violations without echoing secret values."""
    if not isinstance(text, str) or not text:
        return []
    normalized = unicodedata.normalize("NFKC", text)
    findings: List[Dict[str, str]] = []
    seen_rules: Set[str] = set()
    for rule_id, label, pattern in _DLP_RULES:
        if pattern.search(text) or (normalized != text and pattern.search(normalized)):
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                findings.append({"rule": rule_id, "label": label})
    return findings


_SENSITIVE_KV_KEYS = frozenset(
    {
        "privatekey",
        "privkey",
        "secretkey",
        "apikey",
        "accesstoken",
        "authtoken",
        "mnemonic",
        "seedphrase",
        "password",
        "passwd",
        "clientsecret",
        "bearertoken",
    }
)
_CLEAN_REDACTED_MARKER_RE = re.compile(
    r"^(?:\[REDACTED(?:_[A-Z0-9]+)?\]|REDACTED|\*{3,}|<\.{3}>|<REDACTED(?:_[A-Z0-9]+)?>|<PLACEHOLDER>)$",
    re.IGNORECASE,
)


def _is_sensitive_kv_pair(key: str, value: Any) -> bool:
    if not isinstance(key, str) or not isinstance(value, str):
        return False
    norm_key = re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", key).lower())
    if norm_key not in _SENSITIVE_KV_KEYS:
        return False
    stripped = unicodedata.normalize("NFKC", value).strip()
    if len(stripped) < 8:
        return False
    if _CLEAN_REDACTED_MARKER_RE.fullmatch(stripped):
        return False
    return True


def dlp_scan_object(obj: Any) -> List[Dict[str, str]]:
    """Iteratively walk an arbitrary JSON-like object (keys, values, and KV pairs) and aggregate DLP findings."""
    findings: List[Dict[str, str]] = []
    seen_rules: Set[str] = set()
    stack: List[Any] = [obj]
    visited_nodes = 0
    while stack:
        visited_nodes += 1
        if visited_nodes > _MAX_OBJECT_WALK_NODES:
            raise ValueError("DLP_OBJECT_NODE_LIMIT_EXCEEDED")
        cur = stack.pop()
        if isinstance(cur, str):
            for hit in dlp_scan_text(cur):
                if hit["rule"] not in seen_rules:
                    seen_rules.add(hit["rule"])
                    findings.append(hit)
        elif isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str) and _is_sensitive_kv_pair(k, v):
                    if "DLP-SECRET-KV-PAIR" not in seen_rules:
                        seen_rules.add("DLP-SECRET-KV-PAIR")
                        findings.append({"rule": "DLP-SECRET-KV-PAIR", "label": "sensitive_key_value_pair"})
                stack.append(v)
                if isinstance(k, str):
                    stack.append(k)
        elif isinstance(cur, (list, tuple, set, frozenset)):
            for item in cur:
                stack.append(item)
    return findings


def dlp_redact_output(text: str) -> str:
    """Replace sensitive DLP matches with `[REDACTED_DLP]` fail-closed without NFKC-mutating safe prose."""
    if not isinstance(text, str) or not text:
        return ""
    out = text
    for _rule_id, _label, pattern in _DLP_RULES:
        out = pattern.sub("[REDACTED_DLP]", out)
    if dlp_scan_text(out):
        return "[REDACTED_DLP]"
    return out


def iter_safe_files(
    root: Path,
    *,
    skip_dirs: Sequence[str] = (".git", "__pycache__", "node_modules", ".venv", "venv", ".pytest_cache"),
    max_files: int = MAX_SCAN_FILES,
    max_file_bytes: int = MAX_DEFAULT_FILE_BYTES,
    max_total_bytes: int = MAX_SCAN_TOTAL_BYTES,
    max_depth: int = MAX_SCAN_DEPTH,
) -> Dict[str, Any]:
    """Safely enumerate regular files under `root` without following symlinks or exceeding budgets."""
    files: List[Path] = []
    symlink_rejections: List[str] = []
    skipped_oversized: List[str] = []
    skipped_dirs: List[str] = []
    stat_errors: List[str] = []
    special_inodes: List[str] = []
    truncated = False
    bytes_budget_used = 0

    def _result() -> Dict[str, Any]:
        return {
            "files": files,
            "symlink_rejections": symlink_rejections,
            "skipped_oversized": skipped_oversized,
            "skipped_dirs": skipped_dirs,
            "stat_errors": stat_errors,
            "special_inodes": special_inodes,
            "truncated": truncated,
            "bytes_budget_used": bytes_budget_used,
        }

    root_st = os.lstat(str(root))
    if stat.S_ISLNK(root_st.st_mode):
        symlink_rejections.append(str(root))
        return _result()

    if stat.S_ISREG(root_st.st_mode):
        if root_st.st_size > max_file_bytes or root_st.st_size > max_total_bytes:
            skipped_oversized.append(str(root))
        elif max_files <= 0:
            truncated = True
        else:
            files.append(root)
            bytes_budget_used = root_st.st_size
        return _result()

    if not stat.S_ISDIR(root_st.st_mode):
        special_inodes.append(str(root))
        return _result()

    skip_set = set(skip_dirs)
    root_real = os.path.realpath(str(root))
    root_prefix = root_real.rstrip(os.sep) + os.sep
    max_entries = max(max(max_files, 0) * 8, 2000)
    scanned_entries = 0
    stack: List[Tuple[Path, int]] = [(root, 0)]

    while stack:
        if scanned_entries >= max_entries or (max_files > 0 and len(files) >= max_files):
            truncated = True
            break

        cur_dir, depth = stack.pop()
        cur_real = os.path.realpath(str(cur_dir))
        if cur_real != root_real and not cur_real.startswith(root_prefix):
            symlink_rejections.append(str(cur_dir))
            continue

        child_dirs: List[Tuple[Path, int]] = []
        hit_entry_cap = False
        try:
            with os.scandir(str(cur_dir)) as it:
                for entry in it:
                    if scanned_entries >= max_entries or (max_files > 0 and len(files) >= max_files):
                        truncated = True
                        hit_entry_cap = True
                        break
                    scanned_entries += 1
                    entry_path = Path(entry.path)
                    try:
                        est = entry.stat(follow_symlinks=False)
                    except OSError:
                        stat_errors.append(str(entry_path))
                        continue

                    if stat.S_ISLNK(est.st_mode):
                        symlink_rejections.append(str(entry_path))
                        continue

                    if stat.S_ISDIR(est.st_mode):
                        if entry.name in skip_set:
                            skipped_dirs.append(str(entry_path))
                            continue
                        if depth + 1 > max_depth:
                            skipped_dirs.append(str(entry_path))
                            truncated = True
                            continue
                        dir_real = os.path.realpath(str(entry_path))
                        if dir_real != root_real and not dir_real.startswith(root_prefix):
                            symlink_rejections.append(str(entry_path))
                            continue
                        child_dirs.append((entry_path, depth + 1))
                        continue

                    if not stat.S_ISREG(est.st_mode):
                        special_inodes.append(str(entry_path))
                        continue

                    file_real = os.path.realpath(str(entry_path))
                    if file_real != root_real and not file_real.startswith(root_prefix):
                        symlink_rejections.append(str(entry_path))
                        continue

                    if est.st_size > max_file_bytes:
                        skipped_oversized.append(str(entry_path))
                        continue

                    if len(files) >= max_files:
                        truncated = True
                        hit_entry_cap = True
                        break

                    if bytes_budget_used + est.st_size > max_total_bytes:
                        truncated = True
                        continue

                    files.append(entry_path)
                    bytes_budget_used += est.st_size
        except OSError:
            skipped_dirs.append(str(cur_dir))
            continue

        if hit_entry_cap:
            break

        child_dirs.sort(key=lambda item: item[0].name, reverse=True)
        for subdir in child_dirs:
            stack.append(subdir)

    files.sort(key=lambda p: str(p))
    return _result()


__all__ = [
    "MAX_DEFAULT_FILE_BYTES",
    "MAX_STORE_BYTES",
    "MAX_SCAN_FILES",
    "MAX_SCAN_TOTAL_BYTES",
    "MAX_SCAN_DEPTH",
    "is_macos_system_root_symlink",
    "reject_symlink",
    "reject_symlink_ancestors",
    "ensure_safe_parent_dir",
    "ensure_contained_path",
    "read_regular_bytes_secure",
    "sha256_bytes",
    "sha256_file_secure",
    "fsync_dir",
    "file_lock",
    "atomic_write_bytes_secure",
    "atomic_write_json_secure",
    "strict_json_loads",
    "dlp_scan_text",
    "dlp_scan_object",
    "dlp_redact_output",
    "iter_safe_files",
]
