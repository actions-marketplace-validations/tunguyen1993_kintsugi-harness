#!/usr/bin/env python3
"""Fail-Closed GitHub Bootstrap & Self-Updater for Kintsugi Harness — Cloud Sandbox Edition.

100% standalone pure Python 3.9+ standard library, zero external dependencies, zero dynamic code
evaluation, and zero shell invocations. Pulls `cloud-sandbox/` + `src/kintsugi/*.py` directly from the
official public GitHub repository (`https://github.com/tunguyen1993/kintsugi-harness`) or a local
`.tar.gz`/`.zip` archive, enforces bounded streaming decompression, rejects Tar-Slip/Zip-Slip,
symlinks/special files inside bundle scope, Unicode NFC+casefold collisions, and unmanifested
inodes, verifies EVERY file's SHA-256 and data counts against `cloud-sandbox/manifest.json`
(`KintsugiCloudSandboxManifest/1`), optionally runs a clean-env post-stage smoke test, and atomically
swaps + post-verifies the bundle into `--dest` under a cross-process install lock.

Usage:
    curl -fsSL https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/main/cloud-sandbox/bootstrap.py -o /tmp/k_boot.py
    python3 -B /tmp/k_boot.py --ref main --dest /tmp/kintsugi_sandbox
    python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py boot && python3 -B /tmp/kintsugi_sandbox/kintsugi_sandbox.py self-test
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import secrets
import shlex
import shutil
import ssl
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
import tarfile
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Unix fallback
    fcntl = None  # type: ignore[assignment]

REPO_OWNER = "tunguyen1993"
REPO_NAME = "kintsugi-harness"
REPO_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}"
ALLOWED_HTTPS_HOSTS = frozenset({"github.com", "codeload.github.com", "raw.githubusercontent.com"})
MANIFEST_SCHEMA = "KintsugiCloudSandboxManifest/1"
INSTALL_MARKER_FILE = ".kintsugi_sandbox_install.json"

MAX_ARCHIVE_BYTES = 15 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 32 * 1024 * 1024
MAX_EXTRACTED_FILES = 600
MAX_TAR_MEMBERS = 4000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_REDIRECT_HOPS = 5
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 300
SMOKE_TEST_TIMEOUT_SECONDS = 15
_READ_CHUNK_BYTES = 65536

REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,79}$")
FULL_SHA40_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
HEX_SHA_SHORT_OR_FULL_PATTERN = re.compile(r"^[0-9a-fA-F]{7,40}$")
HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
DRIVE_PREFIX_PATTERN = re.compile(r"^[A-Za-z]:")
SENSITIVE_HEADERS = frozenset({"authorization", "cookie", "x-api-key", "proxy-authorization"})
ZIP_MAGIC_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

REQUIRED_CORE_FILES = frozenset(
    {
        "kintsugi_sandbox.py",
        "bootstrap.py",
        "security_io.py",
        "evolution_loop.py",
        "truth_gate.py",
        "scanner_sandbox.py",
        "data/invariant_capsules_v3.json",
        "data/low_tier_pitfall_lexicon_v3.json",
        "data/canary_corpus_v3.json",
        "src/kintsugi/__init__.py",
    }
)


def _is_full_40hex(ref: str) -> bool:
    """Return True iff `ref` is an exact 40-hex commit SHA."""
    return bool(FULL_SHA40_PATTERN.fullmatch((ref or "").strip()))


def validate_git_ref(ref: str, *, require_full_sha: bool = False) -> str:
    """Fail-closed git ref validator (branch, tag, or full 40-hex commit SHA)."""
    clean = (ref or "").strip()
    if not clean or not REF_PATTERN.fullmatch(clean):
        raise ValueError(f"INVALID_REF: {ref!r}")
    if ".." in clean or "//" in clean or clean.endswith("/") or clean.endswith(".lock"):
        raise ValueError(f"INVALID_REF_PATH: {ref!r}")
    if require_full_sha and not FULL_SHA40_PATTERN.fullmatch(clean):
        raise ValueError(f"FULL_COMMIT_SHA_REQUIRED: {ref!r} (expected 40-hex commit SHA)")
    return clean


def validate_allowed_https_url(url: str) -> str:
    """Enforce HTTPS-only GitHub origin allowlist without userinfo, non-443 ports, traversal, or CRLF."""
    raw = str(url or "")
    if not raw or any(ord(ch) < 32 or ch in "\r\n\x7f" for ch in raw):
        raise ValueError("INVALID_URL_CONTROL_CHARS")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme != "https":
        raise ValueError(f"REFUSING_NON_HTTPS_SCHEME: {parsed.scheme!r}")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ValueError("REFUSING_URL_USERINFO")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("INVALID_URL_PORT") from exc
    if port not in (None, 443):
        raise ValueError(f"REFUSING_NON_443_PORT: {port!r}")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HTTPS_HOSTS:
        raise ValueError(f"REFUSING_UNTRUSTED_HOST: {host!r}")
    raw_path = parsed.path or ""
    lower_raw = raw_path.lower()
    unquoted = urllib.parse.unquote(raw_path)
    if (
        "\\" in raw_path
        or "\\" in unquoted
        or ".." in raw_path.split("/")
        or ".." in unquoted.split("/")
        or "%2e" in lower_raw
        or "%2f" in lower_raw
        or "%5c" in lower_raw
    ):
        raise ValueError(f"REFUSING_URL_PATH_TRAVERSAL: {raw_path!r}")
    expected_prefix = f"/{REPO_OWNER}/{REPO_NAME}/"
    norm_path = posixpath.normpath(unquoted)
    if not raw_path.startswith(expected_prefix) or not norm_path.startswith(expected_prefix):
        raise ValueError(f"REFUSING_UNTRUSTED_REPO_PATH: {raw_path!r}")
    return raw


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler enforcing strict GitHub HTTPS allowlist and credential stripping."""

    def __init__(self) -> None:
        super().__init__()
        self._hops = 0

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        self._hops += 1
        if self._hops > MAX_REDIRECT_HOPS:
            raise ValueError(f"TOO_MANY_REDIRECTS: > {MAX_REDIRECT_HOPS}")
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        validate_allowed_https_url(resolved)
        new_req = super().redirect_request(req, fp, code, msg, headers, resolved)
        if new_req is not None:
            for hdr_map in (new_req.headers, new_req.unredirected_hdrs):
                for hname in list(hdr_map.keys()):
                    if hname.lower() in SENSITIVE_HEADERS:
                        del hdr_map[hname]
        return new_req


def _validate_timeout(timeout: int) -> int:
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not (MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
        raise ValueError(
            f"INVALID_TIMEOUT: {timeout!r} (expected integer {MIN_TIMEOUT_SECONDS}..{MAX_TIMEOUT_SECONDS})"
        )
    return timeout


def _set_response_socket_timeout(resp: Any, remaining: float) -> None:
    """Best-effort tightening of the underlying socket timeout to respect total wall-clock deadline."""
    with contextlib.suppress(AttributeError, OSError):
        raw = getattr(getattr(resp, "fp", None), "raw", None)
        sock = getattr(raw, "_sock", None)
        if sock is not None and hasattr(sock, "settimeout"):
            sock.settimeout(max(0.1, remaining))


def _download_bounded_bytes(url: str, timeout: int = 30) -> bytes:
    """Download an archive over HTTPS with wall-clock deadline, redirect allowlist, and size/encoding guards."""
    safe_timeout = _validate_timeout(timeout)
    validate_allowed_https_url(url)
    deadline = time.monotonic() + float(safe_timeout)
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _AllowlistedRedirectHandler(),
    )
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "kintsugi-cloud-sandbox-bootstrap/3.1.1",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "identity",
            "Accept": "application/gzip, application/zip, application/octet-stream, */*",
        },
        method="GET",
    )
    with opener.open(req, timeout=safe_timeout) as resp:
        validate_allowed_https_url(resp.geturl())
        content_encoding = (resp.headers.get("Content-Encoding") or "").strip().lower()
        if content_encoding not in ("", "identity"):
            raise ValueError(f"UNEXPECTED_CONTENT_ENCODING: {content_encoding!r}")
        buf = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"DOWNLOAD_DEADLINE_EXCEEDED: > {safe_timeout}s")
            _set_response_socket_timeout(resp, remaining)
            chunk = resp.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > MAX_ARCHIVE_BYTES:
                raise ValueError(f"ARCHIVE_TOO_LARGE: exceeds {MAX_ARCHIVE_BYTES} bytes")
        return bytes(buf)


def candidate_archive_urls(ref: str, *, require_full_sha: bool = False) -> List[str]:
    """Build allowlisted GitHub tar.gz archive URLs for branch, tag, or commit SHA."""
    safe_ref = validate_git_ref(ref, require_full_sha=require_full_sha)
    if HEX_SHA_SHORT_OR_FULL_PATTERN.fullmatch(safe_ref):
        return [f"{REPO_URL}/archive/{safe_ref}.tar.gz"]
    if safe_ref.startswith("v") and "." in safe_ref:
        return [
            f"{REPO_URL}/archive/refs/tags/{safe_ref}.tar.gz",
            f"{REPO_URL}/archive/refs/heads/{safe_ref}.tar.gz",
        ]
    return [
        f"{REPO_URL}/archive/refs/heads/{safe_ref}.tar.gz",
        f"{REPO_URL}/archive/refs/tags/{safe_ref}.tar.gz",
    ]


def _strict_json_loads(raw_text: str) -> Any:
    def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ValueError(f"DUPLICATE_JSON_KEY: {key!r}")
            out[key] = value
        return out

    def _reject_non_finite(token: str) -> Any:
        raise ValueError(f"NON_FINITE_JSON_TOKEN: {token!r}")

    return json.loads(
        raw_text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_non_finite,
    )


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


def _reject_symlink(path: Path) -> None:
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


_SUPPORTS_DIR_FD = (
    os.open in getattr(os, "supports_dir_fd", set())
    and os.rename in getattr(os, "supports_dir_fd", set())
    and os.unlink in getattr(os, "supports_dir_fd", set())
    and os.rmdir in getattr(os, "supports_dir_fd", set())
)
_SUPPORTS_STAT_DIR_FD = os.stat in getattr(os, "supports_dir_fd", set())
_SUPPORTS_LISTDIR_FD = os.listdir in getattr(os, "supports_fd", set())


def _normalize_macos_root_path(path: Path) -> Path:
    """Rewrite macOS `/tmp`, `/var`, `/etc` root symlinks to `/private/...` without following user symlinks."""
    parts = path.parts
    if (
        sys.platform == "darwin"
        and len(parts) >= 2
        and parts[0] == "/"
        and parts[1] in ("tmp", "var", "etc")
        and _is_macos_system_root_symlink(Path("/" + parts[1]))
    ):
        return Path("/", "private", parts[1], *parts[2:])
    return path


def _open_parent_dir_fd_nofollow(directory: Path) -> int:
    """Open `directory` by walking each segment with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC` via `dir_fd`.

    Standalone POSIX `dir_fd` + `O_NOFOLLOW` containment (hardened against parent-swap TOCTOU).
    Resolves macOS `/tmp`, `/var`, and `/etc` root symlinks to `/private/...` before walking.
    Caller owns and must close the returned file descriptor.
    """
    dir_path = Path(directory) if str(directory) else Path(".")
    parts = _normalize_macos_root_path(dir_path).parts
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
            if seg == "..":
                raise PermissionError(f"REFUSING_PARENT_TRAVERSAL: {directory}")
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


def _open_relative_dir_fd_nofollow(
    base_fd: int,
    segments: Tuple[str, ...],
    base_label: Path = Path("."),
) -> int:
    """Walk relative directory `segments` from `base_fd` using `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`.

    Never closes `base_fd`. Caller owns and must close the returned file descriptor.
    """
    if not segments:
        raise ValueError("EMPTY_RELATIVE_SEGMENTS")
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    cur_fd = base_fd
    cur_owned = False
    cur_path = base_label
    try:
        for seg in segments:
            if not seg or seg in (".", "..") or "/" in seg or "\\" in seg or "\x00" in seg:
                raise PermissionError(f"REFUSING_INVALID_STAGE_SEGMENT: {seg!r}")
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
            if cur_owned:
                os.close(cur_fd)
            cur_fd = next_fd
            cur_owned = True
        return cur_fd
    except BaseException:
        if cur_owned:
            os.close(cur_fd)
        raise


def _open_rel_file_under_dir_fd(root_fd: int, rel_key: str) -> int:
    """Open regular file `rel_key` strictly relative to pinned `root_fd` via `dir_fd` + `O_NOFOLLOW`.

    Rejects empty, `.`, `..`, backslash, and NUL segments; walks intermediate directories step-by-step
    with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`; opens the leaf with
    `O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` using `dir_fd=parent_fd`; closes any intermediate
    parent fd cleanly in `finally:`; and returns the opened regular-file descriptor.
    """
    if (
        not isinstance(rel_key, str)
        or not rel_key
        or rel_key.startswith("/")
        or "\\" in rel_key
        or "\x00" in rel_key
    ):
        raise ValueError(f"UNSAFE_MANIFEST_PATH: {rel_key!r}")
    segments = rel_key.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise ValueError(f"UNSAFE_MANIFEST_PATH: {rel_key!r}")
    *parent_parts, leaf = segments

    parent_fd = root_fd
    owns_parent_fd = False
    try:
        if parent_parts:
            try:
                parent_fd = _open_relative_dir_fd_nofollow(root_fd, tuple(parent_parts))
            except FileNotFoundError:
                raise FileNotFoundError(f"MISSING:{rel_key}") from None
            owns_parent_fd = True
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(leaf, flags, dir_fd=parent_fd)
        except OSError as exc:
            if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                raise PermissionError(f"REFUSING_SYMLINK: {rel_key}") from exc
            if exc.errno == getattr(errno, "ENOENT", -1):
                raise FileNotFoundError(f"MISSING:{rel_key}") from None
            raise
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"REFUSING_NON_REGULAR_FILE: {rel_key}")
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        if owns_parent_fd:
            os.close(parent_fd)


def _read_rel_bytes_under_dir_fd(root_fd: int, rel_key: str, max_bytes: int) -> bytes:
    """Read bounded regular-file bytes strictly under pinned `root_fd` via `dir_fd` + `O_NOFOLLOW`."""
    fd = _open_rel_file_under_dir_fd(root_fd, rel_key)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"REFUSING_NON_REGULAR_FILE: {rel_key}")
        if st.st_size > max_bytes:
            raise ValueError(f"FILE_TOO_LARGE: {rel_key} ({st.st_size} > {max_bytes})")
        chunks: List[bytes] = []
        total = 0
        while True:
            blk = os.read(fd, _READ_CHUNK_BYTES)
            if not blk:
                break
            total += len(blk)
            if total > max_bytes:
                raise ValueError(f"FILE_TOO_LARGE: {rel_key} (> {max_bytes})")
            chunks.append(blk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _sha256_rel_under_dir_fd(root_fd: int, rel_key: str, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
    """Compute SHA-256 hex digest of regular file `rel_key` strictly under pinned `root_fd`."""
    fd = _open_rel_file_under_dir_fd(root_fd, rel_key)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"REFUSING_NON_REGULAR_FILE: {rel_key}")
        if st.st_size > max_bytes:
            raise ValueError(f"FILE_TOO_LARGE: {rel_key} ({st.st_size} > {max_bytes})")
        digest = hashlib.sha256()
        total = 0
        while True:
            blk = os.read(fd, _READ_CHUNK_BYTES)
            if not blk:
                break
            total += len(blk)
            if total > max_bytes:
                raise ValueError(f"FILE_TOO_LARGE: {rel_key}")
            digest.update(blk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def _is_regular_file_under_dir_fd(dir_fd: int, name: str) -> bool:
    try:
        st = os.lstat(name, dir_fd=dir_fd)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def _rmtree_under_dir_fd(parent_fd: int, name: str) -> None:
    """Iteratively remove a non-symlink directory `name` inside `parent_fd` using `dir_fd` ops only."""
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        root_fd = os.open(name, dir_flags, dir_fd=parent_fd)
    except OSError:
        return
    stack: List[Tuple[int, int, str, Optional[List[str]]]] = [(root_fd, parent_fd, name, None)]
    try:
        while stack:
            cur_fd, cur_parent_fd, cur_name, pending_dirs = stack[-1]
            if pending_dirs is None:
                pending_dirs = []
                try:
                    entries = os.listdir(cur_fd)
                except OSError:
                    entries = []
                for child in entries:
                    try:
                        cst = os.lstat(child, dir_fd=cur_fd)
                    except OSError:
                        continue
                    if stat.S_ISDIR(cst.st_mode) and not stat.S_ISLNK(cst.st_mode):
                        pending_dirs.append(child)
                    else:
                        with contextlib.suppress(OSError):
                            os.unlink(child, dir_fd=cur_fd)
                stack[-1] = (cur_fd, cur_parent_fd, cur_name, pending_dirs)
            if pending_dirs:
                child = pending_dirs.pop()
                try:
                    child_fd = os.open(child, dir_flags, dir_fd=cur_fd)
                except OSError:
                    continue
                stack.append((child_fd, cur_fd, child, None))
            else:
                stack.pop()
                os.close(cur_fd)
                with contextlib.suppress(OSError):
                    os.rmdir(cur_name, dir_fd=cur_parent_fd)
    finally:
        for fd_val, _pfd, _nm, _pending in stack:
            with contextlib.suppress(OSError):
                os.close(fd_val)


def _fsync_dir(directory: Path) -> None:
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


def _is_regular_file_nofollow(path: Path) -> bool:
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode)


def _ensure_no_symlink_segment_under(root_dir: Path, rel_key: str) -> Path:
    """Verify every path segment from `root_dir` down to `rel_key` is non-symlink & stays inside `root_dir`."""
    if (
        not isinstance(rel_key, str)
        or not rel_key
        or rel_key.startswith("/")
        or "\\" in rel_key
        or "\x00" in rel_key
    ):
        raise ValueError(f"UNSAFE_MANIFEST_PATH: {rel_key!r}")
    segments = rel_key.split("/")
    if any(seg in ("", ".", "..") for seg in segments):
        raise ValueError(f"UNSAFE_MANIFEST_PATH: {rel_key!r}")
    _reject_symlink_ancestors(root_dir)
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


def _open_regular_nofollow_nonblock(path: Path, max_bytes: int) -> Tuple[int, os.stat_result]:
    _reject_symlink(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
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
        post_st = os.lstat(str(path))
    except OSError as exc:
        raise PermissionError(f"FILE_CHANGED_DURING_READ: {path}") from exc
    if stat.S_ISLNK(post_st.st_mode) or (post_st.st_dev, post_st.st_ino) != (open_st.st_dev, open_st.st_ino):
        raise PermissionError(f"FILE_CHANGED_DURING_READ: {path}")


def _read_regular_bytes_nofollow(path: Path, max_bytes: int) -> bytes:
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


def _sha256_file_nofollow(path: Path, max_bytes: int = MAX_ARCHIVE_BYTES) -> str:
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
                raise ValueError(f"FILE_TOO_LARGE: {path}")
            digest.update(blk)
        _verify_post_read_identity(path, open_st)
        return digest.hexdigest()
    finally:
        os.close(fd)


def verify_self_sha256(expected_hex: str) -> str:
    """Hash `Path(__file__)` via `O_NOFOLLOW` and fail closed if it mismatches `expected_hex`."""
    exp = (expected_hex or "").strip().lower()
    if not HEX64_PATTERN.fullmatch(exp):
        raise ValueError("INVALID_EXPECTED_BOOTSTRAP_SHA256")
    self_path = Path(os.path.abspath(__file__))
    if _SUPPORTS_DIR_FD:
        parent_fd = _open_parent_dir_fd_nofollow(self_path.parent)
        try:
            actual = _sha256_rel_under_dir_fd(parent_fd, self_path.name, max_bytes=MAX_MANIFEST_BYTES)
        finally:
            os.close(parent_fd)
    else:  # pragma: no cover - non-POSIX fallback
        _reject_symlink_ancestors(self_path.parent)
        actual = _sha256_file_nofollow(self_path, max_bytes=MAX_MANIFEST_BYTES)
    if actual != exp:
        raise ValueError(f"BOOTSTRAP_SELF_SHA256_MISMATCH: expected={exp} actual={actual}")
    return actual


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    written = 0
    while written < len(view):
        n = os.write(fd, view[written:])
        if n <= 0:
            raise OSError("SHORT_WRITE_ZERO_BYTES")
        written += n


def _write_new_regular_file(dest_path: Path, data: bytes, *, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(dest_path), flags, mode)
    fd_closed = False
    try:
        _write_all(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd_closed = True
    except BaseException:
        if not fd_closed:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(str(dest_path))
        raise


@contextmanager
def _install_file_lock(dest_abs: Path) -> Iterator[Optional[int]]:
    """Cross-process advisory lock `<dest_abs>.install.lock` via POSIX `dir_fd` + `O_NOFOLLOW`.

    Yields the pinned parent directory fd on POSIX (`None` on non-POSIX) and closes it cleanly in `finally:`.
    """
    dest_name = dest_abs.name
    if not dest_name or dest_name in (".", "..") or dest_abs == dest_abs.parent:
        raise ValueError(f"INVALID_DEST_DIR: {dest_abs!r}")
    lock_name = f"{dest_name}.install.lock"
    lock_path = dest_abs.parent / lock_name

    if _SUPPORTS_DIR_FD:
        parent_fd = _open_parent_dir_fd_nofollow(dest_abs.parent)
        try:
            if fcntl is not None:
                flags = (
                    os.O_CREAT
                    | os.O_RDWR
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_NONBLOCK", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    fd = os.open(lock_name, flags, 0o600, dir_fd=parent_fd)
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
                        yield parent_fd
                    finally:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
                return

            excl_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            acquired = False
            for _ in range(200):
                try:
                    fd = os.open(lock_name, excl_flags, 0o600, dir_fd=parent_fd)
                    os.close(fd)
                    acquired = True
                    break
                except FileExistsError:
                    if _SUPPORTS_STAT_DIR_FD:
                        with contextlib.suppress(FileNotFoundError):
                            if stat.S_ISLNK(os.lstat(lock_name, dir_fd=parent_fd).st_mode):
                                raise PermissionError(f"REFUSING_SYMLINK: {lock_path}")
                    time.sleep(0.01)
            if not acquired:
                raise TimeoutError(f"INSTALL_LOCK_TIMEOUT: {lock_path}")
            try:
                yield parent_fd
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(lock_name, dir_fd=parent_fd)
            return
        finally:
            os.close(parent_fd)

    # Non-POSIX fallback (no dir_fd support)
    _reject_symlink_ancestors(dest_abs.parent)
    _reject_symlink(lock_path)
    if fcntl is not None:
        flags = (
            os.O_CREAT
            | os.O_RDWR
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
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
                yield None
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return

    acquired = False
    for _ in range(200):
        try:
            fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            acquired = True
            break
        except FileExistsError:
            _reject_symlink(lock_path)
            time.sleep(0.01)
    if not acquired:
        raise TimeoutError(f"INSTALL_LOCK_TIMEOUT: {lock_path}")
    try:
        yield None
    finally:
        with contextlib.suppress(OSError):
            os.unlink(str(lock_path))


class _BoundedStreamReader:
    """Wraps a GzipFile stream to enforce a hard decompressed byte ceiling during streaming tar reads."""

    def __init__(self, stream: Any, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self.total_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._max_bytes - self.total_read
        if remaining < 0:
            raise ValueError(f"TAR_DECOMPRESSED_LIMIT_EXCEEDED: > {self._max_bytes}")
        req = remaining + 1 if (size is None or size < 0) else min(size, remaining + 1)
        data = self._stream.read(req)
        self.total_read += len(data)
        if self.total_read > self._max_bytes:
            raise ValueError(f"TAR_DECOMPRESSED_LIMIT_EXCEEDED: > {self._max_bytes}")
        return data


def _parse_archive_member_path(raw_name: str, *, kind: str) -> Tuple[str, Optional[Tuple[str, ...]]]:
    """Validate an archive member path and split off its mandatory single top-level root prefix."""
    tag = "TAR" if kind == "tar" else "ZIP"
    if not raw_name or "\x00" in raw_name or "\\" in raw_name:
        raise ValueError(f"{tag}_INVALID_PATH: {raw_name!r}")
    if raw_name.startswith("/") or DRIVE_PREFIX_PATTERN.match(raw_name):
        raise ValueError(f"{tag}_ABSOLUTE_PATH: {raw_name!r}")
    raw_segments = raw_name.split("/")
    if any(seg == ".." for seg in raw_segments):
        raise ValueError(f"{tag}_SLIP_TRAVERSAL: {raw_name!r}")
    parts = [p for p in raw_segments if p and p != "."]
    if not parts:
        raise ValueError(f"{tag}_INVALID_PATH: {raw_name!r}")
    top_root = parts[0]
    rel = tuple(parts[1:]) if len(parts) > 1 else None
    if rel is not None and any(p in ("..", "") for p in rel):
        raise ValueError(f"{tag}_SLIP_TRAVERSAL: {raw_name!r}")
    return top_root, rel


def _is_in_bundle_scope(rel: Optional[Tuple[str, ...]], *, layout: str = "repo") -> bool:
    if not rel:
        return False
    if layout == "standalone":
        return True
    if rel[0] == "cloud-sandbox":
        return True
    if len(rel) >= 2 and rel[0] == "src" and rel[1] == "kintsugi":
        return True
    return False


def _is_wanted_bundle_rel(
    rel: Optional[Tuple[str, ...]],
    *,
    layout: str = "repo",
) -> Optional[Tuple[str, ...]]:
    """Map archive relative path (`repo` or `standalone` layout) into standalone bundle layout."""
    if not rel:
        return None
    if "__pycache__" in rel or rel[-1].endswith((".pyc", ".pyo")) or rel[-1] == ".DS_Store":
        return None
    if layout == "standalone":
        if rel[0] == "src":
            if len(rel) >= 3 and rel[1] == "kintsugi" and rel[-1].endswith(".py"):
                return rel
            return None
        return rel
    if rel[0] == "cloud-sandbox" and len(rel) >= 2:
        return rel[1:]
    if len(rel) >= 3 and rel[0] == "src" and rel[1] == "kintsugi" and rel[-1].endswith(".py"):
        return rel
    return None


def _ensure_stage_parent_contained(stage_dir: Path, root_real: str, dest_path: Path, member_name: str, tag: str) -> None:
    root_prefix = root_real.rstrip(os.sep) + os.sep
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    parent_real = os.path.realpath(str(dest_path.parent))
    if parent_real != root_real and not parent_real.startswith(root_prefix):
        raise PermissionError(f"{tag}_ESCAPE_DETECTED: {member_name!r}")


def _read_bounded_member_bytes(
    src_fh: Any,
    *,
    member_name: str,
    tag: str,
    per_file_limit: int,
    remaining_decompressed: int,
) -> bytes:
    chunks: List[bytes] = []
    total = 0
    while True:
        blk = src_fh.read(_READ_CHUNK_BYTES)
        if not blk:
            break
        total += len(blk)
        if total > per_file_limit:
            raise ValueError(f"{tag}_MEMBER_SIZE_MISMATCH: {member_name!r}")
        if total > remaining_decompressed:
            raise ValueError(f"{tag}_DECOMPRESSED_LIMIT_EXCEEDED: > {MAX_DECOMPRESSED_BYTES}")
        chunks.append(blk)
    return b"".join(chunks)


def _safe_extract_tar_gz(archive_bytes: bytes, stage_dir: Path) -> int:
    """Stream-extract only `cloud-sandbox/` and `src/kintsugi/*.py` regular files from `.tar.gz` safely."""
    os.chmod(str(stage_dir), 0o700)
    root_real = os.path.realpath(str(stage_dir))
    total_bytes = 0
    total_files = 0
    scanned_members = 0
    expected_top_root: Optional[str] = None
    seen_mapped_ci: Set[str] = set()

    with gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb") as gz:
        bounded = _BoundedStreamReader(gz, MAX_DECOMPRESSED_BYTES)
        with tarfile.open(fileobj=bounded, mode="r|") as tf:  # type: ignore[arg-type]
            for member in tf:
                scanned_members += 1
                if scanned_members > MAX_TAR_MEMBERS:
                    raise ValueError(f"TAR_TOO_MANY_MEMBERS: > {MAX_TAR_MEMBERS}")
                top_root, rel = _parse_archive_member_path(member.name, kind="tar")
                if expected_top_root is None:
                    expected_top_root = top_root
                elif top_root != expected_top_root:
                    raise ValueError(
                        f"TAR_INCONSISTENT_ROOT_PREFIX: expected={expected_top_root!r} got={top_root!r}"
                    )
                in_scope = _is_in_bundle_scope(rel)
                mapped = _is_wanted_bundle_rel(rel)
                if member.issym() or member.islnk():
                    if in_scope or mapped is not None:
                        raise PermissionError(f"TAR_SYMLINK_REJECTED: {member.name!r}")
                    continue
                if not (member.isfile() or member.isdir()):
                    if in_scope or mapped is not None:
                        raise PermissionError(f"TAR_SPECIAL_FILE_REJECTED: {member.name!r}")
                    continue
                if mapped is None or member.isdir():
                    continue

                norm_key = unicodedata.normalize("NFC", "/".join(mapped)).casefold()
                if norm_key in seen_mapped_ci:
                    raise ValueError(f"TAR_DUPLICATE_MEMBER: {'/'.join(mapped)!r}")
                seen_mapped_ci.add(norm_key)

                if member.size < 0 or member.size > MAX_ARCHIVE_BYTES:
                    raise ValueError(f"TAR_MEMBER_TOO_LARGE: {member.name!r}")
                total_files += 1
                if total_files > MAX_EXTRACTED_FILES:
                    raise ValueError(f"TAR_TOO_MANY_FILES: > {MAX_EXTRACTED_FILES}")

                dest_path = stage_dir.joinpath(*mapped)
                _ensure_stage_parent_contained(stage_dir, root_real, dest_path, member.name, "TAR")
                src_fh = tf.extractfile(member)
                if src_fh is None:
                    continue
                with src_fh:
                    data = _read_bounded_member_bytes(
                        src_fh,
                        member_name=member.name,
                        tag="TAR",
                        per_file_limit=MAX_ARCHIVE_BYTES,
                        remaining_decompressed=MAX_DECOMPRESSED_BYTES,
                    )
                total_bytes += len(data)
                if total_bytes > MAX_EXTRACTED_BYTES:
                    raise ValueError(f"TAR_EXTRACTED_LIMIT_EXCEEDED: > {MAX_EXTRACTED_BYTES}")
                _write_new_regular_file(dest_path, data, mode=0o644)
    return total_files


def _safe_extract_zip(archive_bytes: bytes, stage_dir: Path) -> int:
    """Safely extract GitHub repo (`cloud-sandbox/` + `src/kintsugi/*.py`) OR flat standalone bundle `.zip` with bomb/slip guards."""
    os.chmod(str(stage_dir), 0o700)
    root_real = os.path.realpath(str(stage_dir))
    total_bytes = 0
    total_decompressed = 0
    total_declared_bytes = 0
    total_files = 0
    expected_top_root: Optional[str] = None
    seen_mapped_ci: Set[str] = set()

    with zipfile.ZipFile(io.BytesIO(archive_bytes), mode="r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_TAR_MEMBERS:
            raise ValueError(f"ZIP_TOO_MANY_MEMBERS: > {MAX_TAR_MEMBERS}")
        parsed_entries: List[Tuple[zipfile.ZipInfo, Optional[Tuple[str, ...]]]] = []
        has_cloud_sandbox = False
        has_root_kintsugi = False
        has_root_manifest = False
        for info in infos:
            top_root, rel = _parse_archive_member_path(info.filename, kind="zip")
            if expected_top_root is None:
                expected_top_root = top_root
            elif top_root != expected_top_root:
                raise ValueError(
                    f"ZIP_INCONSISTENT_ROOT_PREFIX: expected={expected_top_root!r} got={top_root!r}"
                )
            parsed_entries.append((info, rel))
            if rel:
                if rel[0] == "cloud-sandbox":
                    has_cloud_sandbox = True
                elif not info.is_dir():
                    if rel == ("kintsugi_sandbox.py",):
                        has_root_kintsugi = True
                    elif rel == ("manifest.json",):
                        has_root_manifest = True

        layout = "repo" if has_cloud_sandbox else ("standalone" if (has_root_kintsugi and has_root_manifest) else "repo")

        for info, rel in parsed_entries:
            if info.file_size < 0:
                raise ValueError(f"ZIP_MEMBER_TOO_LARGE: {info.filename!r}")
            total_declared_bytes += info.file_size
            if total_declared_bytes > MAX_DECOMPRESSED_BYTES:
                raise ValueError(f"ZIP_DECOMPRESSED_LIMIT_EXCEEDED: > {MAX_DECOMPRESSED_BYTES}")

            in_scope = _is_in_bundle_scope(rel, layout=layout)
            mapped = _is_wanted_bundle_rel(rel, layout=layout)
            unix_mode = (info.external_attr >> 16) & 0o170000
            if unix_mode == 0o120000:
                if in_scope or mapped is not None:
                    raise PermissionError(f"ZIP_SYMLINK_REJECTED: {info.filename!r}")
                continue
            if unix_mode not in (0, 0o100000, 0o040000):
                if in_scope or mapped is not None:
                    raise PermissionError(f"ZIP_SPECIAL_FILE_REJECTED: {info.filename!r}")
                continue
            if mapped is None or info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise PermissionError(f"ZIP_ENCRYPTED_ENTRY_REJECTED: {info.filename!r}")

            norm_key = unicodedata.normalize("NFC", "/".join(mapped)).casefold()
            if norm_key in seen_mapped_ci:
                raise ValueError(f"ZIP_DUPLICATE_MEMBER: {'/'.join(mapped)!r}")
            seen_mapped_ci.add(norm_key)

            if info.file_size > MAX_ARCHIVE_BYTES:
                raise ValueError(f"ZIP_MEMBER_TOO_LARGE: {info.filename!r}")
            total_files += 1
            if total_files > MAX_EXTRACTED_FILES:
                raise ValueError(f"ZIP_TOO_MANY_FILES: > {MAX_EXTRACTED_FILES}")

            dest_path = stage_dir.joinpath(*mapped)
            _ensure_stage_parent_contained(stage_dir, root_real, dest_path, info.filename, "ZIP")
            with zf.open(info, mode="r") as src_fh:
                data = _read_bounded_member_bytes(
                    src_fh,
                    member_name=info.filename,
                    tag="ZIP",
                    per_file_limit=MAX_ARCHIVE_BYTES,
                    remaining_decompressed=MAX_DECOMPRESSED_BYTES - total_decompressed,
                )
            total_decompressed += len(data)
            if total_decompressed > MAX_DECOMPRESSED_BYTES:
                raise ValueError(f"ZIP_DECOMPRESSED_LIMIT_EXCEEDED: > {MAX_DECOMPRESSED_BYTES}")
            total_bytes += len(data)
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError(f"ZIP_EXTRACTED_LIMIT_EXCEEDED: > {MAX_EXTRACTED_BYTES}")
            _write_new_regular_file(dest_path, data, mode=0o644)
    return total_files


def _safe_extract_archive(archive_bytes: bytes, stage_dir: Path) -> int:
    """Auto-detect gzip `.tar.gz` vs `.zip` archive bytes and extract safely into `stage_dir`."""
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"ARCHIVE_TOO_LARGE: exceeds {MAX_ARCHIVE_BYTES} bytes")
    if archive_bytes[:2] == b"\x1f\x8b":
        return _safe_extract_tar_gz(archive_bytes, stage_dir)
    if archive_bytes[:4] in ZIP_MAGIC_PREFIXES:
        return _safe_extract_zip(archive_bytes, stage_dir)
    raise ValueError("UNSUPPORTED_ARCHIVE_FORMAT: expected .tar.gz or .zip")


def _verify_data_counts(
    bundle_dir: Path,
    doc: Dict[str, Any],
    *,
    bundle_fd: Optional[int] = None,
) -> Tuple[int, int]:
    """Verify actual JSON capsule and pitfall entry counts match `manifest.json` metadata."""
    exp_capsules = doc.get("capsules_count")
    exp_pitfalls = doc.get("pitfalls_count")
    if not isinstance(exp_capsules, int) or isinstance(exp_capsules, bool) or exp_capsules < 0:
        raise ValueError(f"INVALID_MANIFEST_CAPSULES_COUNT: {exp_capsules!r}")
    if not isinstance(exp_pitfalls, int) or isinstance(exp_pitfalls, bool) or exp_pitfalls < 0:
        raise ValueError(f"INVALID_MANIFEST_PITFALLS_COUNT: {exp_pitfalls!r}")

    if bundle_fd is not None:
        cap_raw = _read_rel_bytes_under_dir_fd(bundle_fd, "data/invariant_capsules_v3.json", MAX_MANIFEST_BYTES)
    else:
        cap_path = _ensure_no_symlink_segment_under(bundle_dir, "data/invariant_capsules_v3.json")
        cap_raw = _read_regular_bytes_nofollow(cap_path, MAX_MANIFEST_BYTES)
    cap_doc = _strict_json_loads(cap_raw.decode("utf-8"))
    if not isinstance(cap_doc, dict) or not isinstance(cap_doc.get("capsules"), list):
        raise ValueError("INVALID_CAPSULES_DATA_SCHEMA")
    actual_capsules = len(cap_doc["capsules"])
    if actual_capsules != exp_capsules:
        raise ValueError(
            f"MANIFEST_CAPSULES_COUNT_MISMATCH: manifest={exp_capsules} actual={actual_capsules}"
        )

    if bundle_fd is not None:
        pit_raw = _read_rel_bytes_under_dir_fd(bundle_fd, "data/low_tier_pitfall_lexicon_v3.json", MAX_MANIFEST_BYTES)
    else:
        pit_path = _ensure_no_symlink_segment_under(bundle_dir, "data/low_tier_pitfall_lexicon_v3.json")
        pit_raw = _read_regular_bytes_nofollow(pit_path, MAX_MANIFEST_BYTES)
    pit_doc = _strict_json_loads(pit_raw.decode("utf-8"))
    if not isinstance(pit_doc, dict) or not isinstance(pit_doc.get("entries"), list):
        raise ValueError("INVALID_PITFALLS_DATA_SCHEMA")
    actual_pitfalls = len(pit_doc["entries"])
    if actual_pitfalls != exp_pitfalls:
        raise ValueError(
            f"MANIFEST_PITFALLS_COUNT_MISMATCH: manifest={exp_pitfalls} actual={actual_pitfalls}"
        )

    return actual_capsules, actual_pitfalls


def _build_allowed_tree_sets(allowed_files: Set[str]) -> Tuple[Set[str], Set[str]]:
    allowed_dirs: Set[str] = set()
    known_code_dirs: Set[str] = set()
    for rel in allowed_files:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            allowed_dirs.add("/".join(parts[:i]))
        if rel.endswith(".py"):
            known_code_dirs.add("/".join(parts[:-1]))
    return allowed_dirs, known_code_dirs


def _scan_unexpected_inodes_under_dir_fd(
    bundle_fd: int,
    files_map: Dict[str, str],
    *,
    allow_install_marker: bool = True,
    include_src_prefix: bool = True,
    allowed_files: Optional[Set[str]] = None,
    allow_pycache: bool = False,
) -> List[str]:
    """Walk EVERY inode under pinned `bundle_fd` using `dir_fd` + `O_NOFOLLOW` only (zero path walk)."""
    if allowed_files is None:
        if include_src_prefix:
            eff_allowed: Set[str] = set(files_map.keys()) | {"manifest.json"}
        else:
            eff_allowed = {k for k in files_map.keys() if not k.startswith("src/kintsugi/")} | {"manifest.json"}
        if allow_install_marker:
            eff_allowed.add(INSTALL_MARKER_FILE)
    else:
        eff_allowed = set(allowed_files)

    allowed_dirs, known_code_dirs = _build_allowed_tree_sets(eff_allowed)
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )

    extras: List[str] = []
    stack: List[Tuple[int, str, bool]] = [(bundle_fd, "", False)]
    try:
        while stack:
            cur_fd, cur_rel, owns_cur = stack.pop()
            try:
                for name in sorted(os.listdir(cur_fd)):
                    entry_rel = f"{cur_rel}/{name}" if cur_rel else name
                    est = os.lstat(name, dir_fd=cur_fd)
                    if stat.S_ISLNK(est.st_mode):
                        extras.append(f"SYMLINK:{entry_rel}")
                        continue
                    if stat.S_ISDIR(est.st_mode):
                        if name == "__pycache__":
                            if not allow_pycache:
                                extras.append(f"UNVERIFIED_BYTECODE_REJECTED:{entry_rel}")
                                continue
                            if cur_rel in known_code_dirs:
                                try:
                                    pyc_dir_fd = os.open(name, dir_flags, dir_fd=cur_fd)
                                except OSError as exc:
                                    if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                                        extras.append(f"SYMLINK:{entry_rel}")
                                        continue
                                    if exc.errno == getattr(errno, "ENOTDIR", -1):
                                        is_sym = False
                                        with contextlib.suppress(OSError):
                                            is_sym = stat.S_ISLNK(os.lstat(name, dir_fd=cur_fd).st_mode)
                                        extras.append(f"SYMLINK:{entry_rel}" if is_sym else f"SPECIAL:{entry_rel}")
                                        continue
                                    raise
                                try:
                                    for pyc_name in sorted(os.listdir(pyc_dir_fd)):
                                        pyc_rel = f"{entry_rel}/{pyc_name}"
                                        pst = os.lstat(pyc_name, dir_fd=pyc_dir_fd)
                                        if stat.S_ISLNK(pst.st_mode):
                                            extras.append(f"SYMLINK:{pyc_rel}")
                                        elif not stat.S_ISREG(pst.st_mode) or not pyc_name.endswith(".pyc"):
                                            extras.append(pyc_rel)
                                        else:
                                            stem = pyc_name.split(".", 1)[0]
                                            expected_py = f"{cur_rel}/{stem}.py" if cur_rel else f"{stem}.py"
                                            if not stem or expected_py not in eff_allowed:
                                                extras.append(f"ORPHAN_PYC:{pyc_rel}")
                                finally:
                                    os.close(pyc_dir_fd)
                                continue
                        if entry_rel not in allowed_dirs:
                            extras.append(f"UNEXPECTED_DIR:{entry_rel}")
                            continue
                        try:
                            child_fd = os.open(name, dir_flags, dir_fd=cur_fd)
                        except OSError as exc:
                            if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                                extras.append(f"SYMLINK:{entry_rel}")
                                continue
                            if exc.errno == getattr(errno, "ENOTDIR", -1):
                                is_sym = False
                                with contextlib.suppress(OSError):
                                    is_sym = stat.S_ISLNK(os.lstat(name, dir_fd=cur_fd).st_mode)
                                extras.append(f"SYMLINK:{entry_rel}" if is_sym else f"SPECIAL:{entry_rel}")
                                continue
                            raise
                        try:
                            cst = os.fstat(child_fd)
                            if not stat.S_ISDIR(cst.st_mode):
                                extras.append(f"SPECIAL:{entry_rel}")
                                os.close(child_fd)
                                continue
                        except BaseException:
                            os.close(child_fd)
                            raise
                        stack.append((child_fd, entry_rel, True))
                        continue
                    if stat.S_ISREG(est.st_mode):
                        if entry_rel not in eff_allowed:
                            if not allow_pycache and name.endswith((".pyc", ".pyo")):
                                extras.append(f"UNVERIFIED_BYTECODE_REJECTED:{entry_rel}")
                            else:
                                extras.append(entry_rel)
                        continue
                    extras.append(f"SPECIAL:{entry_rel}")
            finally:
                if owns_cur:
                    os.close(cur_fd)
    finally:
        for rem_fd, _rem_rel, rem_owns in stack:
            if rem_owns:
                with contextlib.suppress(OSError):
                    os.close(rem_fd)
    return sorted(extras)


def _scan_unexpected_inodes(
    bundle_dir: Path,
    *,
    allowed_files: Set[str],
    allow_pycache: bool = False,
) -> List[str]:
    """Non-POSIX fallback: walk EVERY inode under `bundle_dir` without following symlinks."""
    allowed_dirs, known_code_dirs = _build_allowed_tree_sets(allowed_files)

    extras: List[str] = []
    stack: List[Tuple[Path, str]] = [(bundle_dir, "")]
    while stack:
        cur_dir, cur_rel = stack.pop()
        with os.scandir(str(cur_dir)) as it:
            entries = sorted(list(it), key=lambda e: e.name)
        for entry in entries:
            entry_rel = f"{cur_rel}/{entry.name}" if cur_rel else entry.name
            est = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(est.st_mode):
                extras.append(f"SYMLINK:{entry_rel}")
                continue
            if stat.S_ISDIR(est.st_mode):
                if entry.name == "__pycache__":
                    if not allow_pycache:
                        extras.append(f"UNVERIFIED_BYTECODE_REJECTED:{entry_rel}")
                        continue
                    if cur_rel in known_code_dirs:
                        with os.scandir(entry.path) as pyc_it:
                            for pyc_entry in sorted(list(pyc_it), key=lambda e: e.name):
                                pyc_rel = f"{entry_rel}/{pyc_entry.name}"
                                pst = pyc_entry.stat(follow_symlinks=False)
                                if stat.S_ISLNK(pst.st_mode):
                                    extras.append(f"SYMLINK:{pyc_rel}")
                                elif not stat.S_ISREG(pst.st_mode) or not pyc_entry.name.endswith(".pyc"):
                                    extras.append(pyc_rel)
                                else:
                                    stem = pyc_entry.name.split(".", 1)[0]
                                    expected_py = f"{cur_rel}/{stem}.py" if cur_rel else f"{stem}.py"
                                    if not stem or expected_py not in allowed_files:
                                        extras.append(f"ORPHAN_PYC:{pyc_rel}")
                        continue
                if entry_rel not in allowed_dirs:
                    extras.append(f"UNEXPECTED_DIR:{entry_rel}")
                    continue
                stack.append((Path(entry.path), entry_rel))
                continue
            if stat.S_ISREG(est.st_mode):
                if entry_rel not in allowed_files:
                    if not allow_pycache and entry.name.endswith((".pyc", ".pyo")):
                        extras.append(f"UNVERIFIED_BYTECODE_REJECTED:{entry_rel}")
                    else:
                        extras.append(entry_rel)
                continue
            extras.append(f"SPECIAL:{entry_rel}")
    return sorted(extras)


def _parse_and_validate_manifest_bytes(
    raw_manifest: bytes,
    *,
    expected_manifest_sha256: str = "",
) -> Tuple[str, Dict[str, Any], Dict[str, str]]:
    actual_manifest_sha = hashlib.sha256(raw_manifest).hexdigest()
    if expected_manifest_sha256:
        exp = expected_manifest_sha256.strip().lower()
        if not HEX64_PATTERN.fullmatch(exp):
            raise ValueError("INVALID_EXPECTED_MANIFEST_SHA256")
        if actual_manifest_sha != exp:
            raise ValueError(
                f"MANIFEST_SHA256_MISMATCH: expected={exp} actual={actual_manifest_sha}"
            )
    doc = _strict_json_loads(raw_manifest.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(
            f"INVALID_MANIFEST_SCHEMA: {doc.get('schema') if isinstance(doc, dict) else type(doc).__name__}"
        )
    files_map = doc.get("files")
    if not isinstance(files_map, dict) or len(files_map) < len(REQUIRED_CORE_FILES):
        raise ValueError("INVALID_MANIFEST_FILES_MAP")
    if "total_files" in doc and doc.get("total_files") != len(files_map):
        raise ValueError(
            f"MANIFEST_TOTAL_FILES_MISMATCH: manifest={doc.get('total_files')!r} actual={len(files_map)}"
        )
    missing_core = sorted(REQUIRED_CORE_FILES - set(files_map.keys()))
    if missing_core:
        raise ValueError(f"MANIFEST_MISSING_CORE_FILES: {', '.join(missing_core)}")
    return actual_manifest_sha, doc, files_map


def verify_manifest_tree(
    bundle_dir: Path,
    *,
    src_root: Optional[Path] = None,
    expected_manifest_sha256: str = "",
    reject_extra_files: bool = False,
    allow_install_marker: bool = True,
    allow_pycache: bool = False,
    bundle_fd: Optional[int] = None,
) -> Dict[str, Any]:
    """Fail-closed SHA-256 and data-count verification of EVERY file recorded in `manifest.json`."""
    if _SUPPORTS_DIR_FD and _SUPPORTS_STAT_DIR_FD and _SUPPORTS_LISTDIR_FD:
        b_fd = bundle_fd
        owns_b_fd = False
        s_fd: Optional[int] = None
        owns_s_fd = False
        try:
            if b_fd is None:
                b_fd = _open_parent_dir_fd_nofollow(bundle_dir)
                owns_b_fd = True
            else:
                bst_chk = os.fstat(b_fd)
                if not stat.S_ISDIR(bst_chk.st_mode):
                    raise PermissionError(f"ANCESTOR_NOT_DIR: {bundle_dir}")

            raw_manifest = _read_rel_bytes_under_dir_fd(b_fd, "manifest.json", MAX_MANIFEST_BYTES)
            actual_manifest_sha, doc, files_map = _parse_and_validate_manifest_bytes(
                raw_manifest, expected_manifest_sha256=expected_manifest_sha256
            )

            resolved_src_root = src_root
            if resolved_src_root is None:
                has_local_src = False
                try:
                    probe_fd = _open_relative_dir_fd_nofollow(b_fd, ("src", "kintsugi"))
                    os.close(probe_fd)
                    has_local_src = True
                except (FileNotFoundError, PermissionError, OSError):
                    has_local_src = False
                if has_local_src:
                    resolved_src_root = bundle_dir
                    s_fd = b_fd
                else:
                    parent_cand = Path(os.path.abspath(str(bundle_dir))).parent
                    try:
                        parent_fd = _open_parent_dir_fd_nofollow(parent_cand)
                    except (FileNotFoundError, PermissionError, OSError):
                        raise FileNotFoundError("KINTSUGI_SRC_DIR_NOT_FOUND") from None
                    try:
                        probe_fd = _open_relative_dir_fd_nofollow(parent_fd, ("src", "kintsugi"))
                        os.close(probe_fd)
                    except (FileNotFoundError, PermissionError, OSError):
                        os.close(parent_fd)
                        raise FileNotFoundError("KINTSUGI_SRC_DIR_NOT_FOUND") from None
                    resolved_src_root = parent_cand
                    s_fd = parent_fd
                    owns_s_fd = True
            else:
                norm_bundle = _normalize_macos_root_path(Path(os.path.abspath(str(bundle_dir))))
                norm_src = _normalize_macos_root_path(Path(os.path.abspath(str(resolved_src_root))))
                if resolved_src_root == bundle_dir or norm_src == norm_bundle:
                    s_fd = b_fd
                else:
                    s_fd = _open_parent_dir_fd_nofollow(resolved_src_root)
                    owns_s_fd = True

            verified = 0
            mismatches: List[str] = []
            for rel_key, expected_hex in sorted(files_map.items()):
                if not isinstance(rel_key, str) or not isinstance(expected_hex, str) or not HEX64_PATTERN.fullmatch(expected_hex):
                    raise ValueError(f"INVALID_MANIFEST_ENTRY: {rel_key!r}")
                if rel_key.startswith("/") or ".." in rel_key.split("/") or "\\" in rel_key or "\x00" in rel_key:
                    raise ValueError(f"UNSAFE_MANIFEST_PATH: {rel_key!r}")
                target_root_fd = s_fd if rel_key.startswith("src/kintsugi/") else b_fd
                try:
                    actual_hex = _sha256_rel_under_dir_fd(target_root_fd, rel_key)
                except PermissionError:
                    raise
                except (FileNotFoundError, OSError, ValueError) as exc:
                    mismatches.append(f"INVALID:{rel_key}({exc})")
                    continue
                if actual_hex != expected_hex:
                    mismatches.append(f"HASH_MISMATCH:{rel_key}")
                else:
                    verified += 1

            if mismatches:
                raise ValueError(f"MANIFEST_HASH_MISMATCH: {'; '.join(mismatches[:8])}")

            actual_capsules, actual_pitfalls = _verify_data_counts(bundle_dir, doc, bundle_fd=b_fd)

            if reject_extra_files:
                b_st = os.fstat(b_fd)
                s_st = b_st if s_fd == b_fd else os.fstat(s_fd)
                same_root = (b_st.st_dev, b_st.st_ino) == (s_st.st_dev, s_st.st_ino)
                extras = _scan_unexpected_inodes_under_dir_fd(
                    b_fd,
                    files_map,
                    allow_install_marker=allow_install_marker,
                    include_src_prefix=same_root,
                    allow_pycache=allow_pycache,
                )
                if extras:
                    raise ValueError(f"MANIFEST_UNEXPECTED_EXTRA_FILES: {', '.join(extras[:8])}")

            return {
                "ok": True,
                "status": "PASS_MANIFEST_VERIFIED",
                "schema": MANIFEST_SCHEMA,
                "version": str(doc.get("version", "")),
                "cloud_sandbox_edition_version": str(doc.get("cloud_sandbox_edition_version") or doc.get("version", "")),
                "manifest_sha256": actual_manifest_sha,
                "files_verified": verified,
                "capsules_count": actual_capsules,
                "pitfalls_count": actual_pitfalls,
            }
        finally:
            if owns_s_fd and s_fd is not None:
                os.close(s_fd)
            if owns_b_fd and b_fd is not None:
                os.close(b_fd)

    # Non-POSIX fallback (no dir_fd support)
    manifest_path = _ensure_no_symlink_segment_under(bundle_dir, "manifest.json")
    raw_manifest = _read_regular_bytes_nofollow(manifest_path, MAX_MANIFEST_BYTES)
    actual_manifest_sha, doc, files_map = _parse_and_validate_manifest_bytes(
        raw_manifest, expected_manifest_sha256=expected_manifest_sha256
    )

    resolved_src_root = src_root
    if resolved_src_root is None:
        if (bundle_dir / "src" / "kintsugi").is_dir() and not (bundle_dir / "src").is_symlink():
            resolved_src_root = bundle_dir
        elif (bundle_dir.parent / "src" / "kintsugi").is_dir() and not (bundle_dir.parent / "src").is_symlink():
            resolved_src_root = bundle_dir.parent
        else:
            raise FileNotFoundError("KINTSUGI_SRC_DIR_NOT_FOUND")

    verified = 0
    mismatches = []
    for rel_key, expected_hex in sorted(files_map.items()):
        if not isinstance(rel_key, str) or not isinstance(expected_hex, str) or not HEX64_PATTERN.fullmatch(expected_hex):
            raise ValueError(f"INVALID_MANIFEST_ENTRY: {rel_key!r}")
        if rel_key.startswith("/") or ".." in rel_key.split("/") or "\\" in rel_key or "\x00" in rel_key:
            raise ValueError(f"UNSAFE_MANIFEST_PATH: {rel_key!r}")
        base_root = resolved_src_root if rel_key.startswith("src/kintsugi/") else bundle_dir
        try:
            target = _ensure_no_symlink_segment_under(base_root, rel_key)
            actual_hex = _sha256_file_nofollow(target)
        except PermissionError:
            raise
        except (FileNotFoundError, OSError, ValueError) as exc:
            mismatches.append(f"INVALID:{rel_key}({exc})")
            continue
        if actual_hex != expected_hex:
            mismatches.append(f"HASH_MISMATCH:{rel_key}")
        else:
            verified += 1

    if mismatches:
        raise ValueError(f"MANIFEST_HASH_MISMATCH: {'; '.join(mismatches[:8])}")

    actual_capsules, actual_pitfalls = _verify_data_counts(bundle_dir, doc)

    if reject_extra_files:
        same_root = os.path.realpath(str(resolved_src_root)) == os.path.realpath(str(bundle_dir))
        if same_root:
            allowed_files = set(files_map.keys()) | {"manifest.json"}
        else:
            allowed_files = {k for k in files_map.keys() if not k.startswith("src/kintsugi/")} | {"manifest.json"}
        if allow_install_marker:
            allowed_files.add(INSTALL_MARKER_FILE)
        extras = _scan_unexpected_inodes(
            bundle_dir,
            allowed_files=allowed_files,
            allow_pycache=allow_pycache,
        )
        if extras:
            raise ValueError(f"MANIFEST_UNEXPECTED_EXTRA_FILES: {', '.join(extras[:8])}")

    return {
        "ok": True,
        "status": "PASS_MANIFEST_VERIFIED",
        "schema": MANIFEST_SCHEMA,
        "version": str(doc.get("version", "")),
        "cloud_sandbox_edition_version": str(doc.get("cloud_sandbox_edition_version") or doc.get("version", "")),
        "manifest_sha256": actual_manifest_sha,
        "files_verified": verified,
        "capsules_count": actual_capsules,
        "pitfalls_count": actual_pitfalls,
    }


def _parse_install_marker_doc(raw_bytes: bytes, dest_abs: Path) -> Dict[str, Any]:
    try:
        doc = _strict_json_loads(raw_bytes.decode("utf-8"))
    except Exception as exc:
        raise PermissionError(
            f"REFUSING_NON_KINTSUGI_NONEMPTY_DEST: {dest_abs} "
            f"(invalid {INSTALL_MARKER_FILE}: {exc})"
        ) from exc
    if not isinstance(doc, dict) or doc.get("schema") != "KintsugiSandboxInstallMarker/1":
        raise PermissionError(
            f"REFUSING_NON_KINTSUGI_NONEMPTY_DEST: {dest_abs} "
            f"(destination is non-empty and lacks valid {INSTALL_MARKER_FILE} schema KintsugiSandboxInstallMarker/1)"
        )
    return doc


def _enforce_pin_continuity(
    marker_doc: Dict[str, Any],
    *,
    expected_manifest_sha256: str,
    allow_downgrade_to_tofu: bool,
) -> None:
    if (
        marker_doc.get("trust_mode") == "PINNED_MANIFEST_SHA256"
        and not (expected_manifest_sha256 or "").strip()
        and not allow_downgrade_to_tofu
    ):
        raise PermissionError(
            "REFUSING_PIN_DOWNGRADE_TO_TOFU: existing install is pinned; "
            "supply --expected-manifest-sha256 or --allow-unpinned-downgrade"
        )


def _validate_safe_dest_dir(
    dest: Path,
    *,
    check_nonempty: bool = True,
    create_parent: bool = False,
    parent_fd: Optional[int] = None,
    expected_manifest_sha256: str = "",
    allow_downgrade_to_tofu: bool = False,
) -> Path:
    """Validate `--dest` is not root/git checkout, has no symlink ancestors/target, and never clobbers user files."""
    dest_abs = Path(os.path.abspath(str(dest)))
    dest_name = dest_abs.name
    if not dest_name or dest_name in (".", "..") or dest_abs == dest_abs.parent:
        raise ValueError(f"INVALID_DEST_DIR: {dest!r}")
    if parent_fd is None:
        _reject_symlink_ancestors(dest_abs.parent)
        if create_parent:
            dest_abs.parent.mkdir(parents=True, exist_ok=True)
            _reject_symlink_ancestors(dest_abs.parent)

    if _SUPPORTS_DIR_FD and _SUPPORTS_STAT_DIR_FD and _SUPPORTS_LISTDIR_FD:
        owns_pfd = False
        pfd = parent_fd
        if pfd is None:
            try:
                pfd = _open_parent_dir_fd_nofollow(dest_abs.parent)
                owns_pfd = True
            except FileNotFoundError:
                return dest_abs
        try:
            git_in_parent = False
            try:
                os.lstat(".git", dir_fd=pfd)
                git_in_parent = True
            except FileNotFoundError:
                git_in_parent = False
            if git_in_parent:
                raise PermissionError(
                    f"REFUSING_GIT_CHECKOUT_DEST: refusing to overwrite git repository checkout ({dest_abs})"
                )
            try:
                st = os.lstat(dest_name, dir_fd=pfd)
            except FileNotFoundError:
                return dest_abs
            if stat.S_ISLNK(st.st_mode):
                raise PermissionError(f"REFUSING_SYMLINK_DEST: {dest_abs}")
            if not stat.S_ISDIR(st.st_mode):
                raise PermissionError(f"REFUSING_NON_DIR_DEST: {dest_abs}")
            dir_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                dest_fd = os.open(dest_name, dir_flags, dir_fd=pfd)
            except OSError as exc:
                if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                    raise PermissionError(f"REFUSING_SYMLINK_DEST: {dest_abs}") from exc
                if exc.errno == getattr(errno, "ENOTDIR", -1):
                    raise PermissionError(f"REFUSING_NON_DIR_DEST: {dest_abs}") from exc
                raise
            try:
                git_in_dest = False
                try:
                    os.lstat(".git", dir_fd=dest_fd)
                    git_in_dest = True
                except FileNotFoundError:
                    git_in_dest = False
                if git_in_dest:
                    raise PermissionError(
                        f"REFUSING_GIT_CHECKOUT_DEST: refusing to overwrite git repository checkout ({dest_abs})"
                    )
                if check_nonempty:
                    has_entries = bool(os.listdir(dest_fd))
                    if has_entries:
                        if not _is_regular_file_under_dir_fd(dest_fd, INSTALL_MARKER_FILE):
                            raise PermissionError(
                                f"REFUSING_NON_KINTSUGI_NONEMPTY_DEST: {dest_abs} "
                                f"(destination is non-empty and lacks {INSTALL_MARKER_FILE})"
                            )
                        try:
                            raw_marker = _read_rel_bytes_under_dir_fd(
                                dest_fd, INSTALL_MARKER_FILE, MAX_MANIFEST_BYTES
                            )
                        except (OSError, ValueError) as exc:
                            raise PermissionError(
                                f"REFUSING_NON_KINTSUGI_NONEMPTY_DEST: {dest_abs} ({exc})"
                            ) from exc
                        marker_doc = _parse_install_marker_doc(raw_marker, dest_abs)
                        _enforce_pin_continuity(
                            marker_doc,
                            expected_manifest_sha256=expected_manifest_sha256,
                            allow_downgrade_to_tofu=allow_downgrade_to_tofu,
                        )
                        existing_files_map: Optional[Dict[str, str]] = None
                        try:
                            raw_existing_manifest = _read_rel_bytes_under_dir_fd(
                                dest_fd, "manifest.json", MAX_MANIFEST_BYTES
                            )
                            _m_sha, _m_doc, parsed_files_map = _parse_and_validate_manifest_bytes(
                                raw_existing_manifest
                            )
                            existing_files_map = parsed_files_map
                        except (FileNotFoundError, OSError, PermissionError, ValueError):
                            existing_files_map = None
                        if existing_files_map is not None:
                            unexpected = _scan_unexpected_inodes_under_dir_fd(
                                dest_fd,
                                existing_files_map,
                                allow_install_marker=True,
                                include_src_prefix=True,
                                allow_pycache=True,
                            )
                        else:
                            unexpected = _scan_unexpected_inodes_under_dir_fd(
                                dest_fd,
                                {},
                                allow_install_marker=True,
                                include_src_prefix=True,
                                allowed_files={INSTALL_MARKER_FILE},
                                allow_pycache=True,
                            )
                        if unexpected:
                            raise PermissionError(
                                f"REFUSING_DEST_WITH_USER_FILES: {dest_abs} contains unexpected entries "
                                f"outside installed manifest ({', '.join(unexpected[:8])})"
                            )
            finally:
                os.close(dest_fd)
            return dest_abs
        finally:
            if owns_pfd and pfd is not None:
                os.close(pfd)

    # Non-POSIX fallback
    git_in_parent = False
    try:
        os.lstat(str(dest_abs.parent / ".git"))
        git_in_parent = True
    except FileNotFoundError:
        git_in_parent = False
    if git_in_parent:
        raise PermissionError(
            f"REFUSING_GIT_CHECKOUT_DEST: refusing to overwrite git repository checkout ({dest_abs})"
        )
    try:
        st = os.lstat(str(dest_abs))
    except FileNotFoundError:
        return dest_abs
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"REFUSING_SYMLINK_DEST: {dest_abs}")
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"REFUSING_NON_DIR_DEST: {dest_abs}")
    git_in_dest = False
    try:
        os.lstat(str(dest_abs / ".git"))
        git_in_dest = True
    except FileNotFoundError:
        git_in_dest = False
    if git_in_dest:
        raise PermissionError(
            f"REFUSING_GIT_CHECKOUT_DEST: refusing to overwrite git repository checkout ({dest_abs})"
        )
    if check_nonempty:
        with os.scandir(str(dest_abs)) as it:
            has_entries = next(it, None) is not None
        if has_entries:
            marker_path = dest_abs / INSTALL_MARKER_FILE
            if not _is_regular_file_nofollow(marker_path):
                raise PermissionError(
                    f"REFUSING_NON_KINTSUGI_NONEMPTY_DEST: {dest_abs} "
                    f"(destination is non-empty and lacks {INSTALL_MARKER_FILE})"
                )
            try:
                raw_marker = _read_regular_bytes_nofollow(marker_path, MAX_MANIFEST_BYTES)
            except (OSError, ValueError) as exc:
                raise PermissionError(
                    f"REFUSING_NON_KINTSUGI_NONEMPTY_DEST: {dest_abs} ({exc})"
                ) from exc
            marker_doc = _parse_install_marker_doc(raw_marker, dest_abs)
            _enforce_pin_continuity(
                marker_doc,
                expected_manifest_sha256=expected_manifest_sha256,
                allow_downgrade_to_tofu=allow_downgrade_to_tofu,
            )
            allowed_existing: Set[str]
            try:
                manifest_path = _ensure_no_symlink_segment_under(dest_abs, "manifest.json")
                raw_existing_manifest = _read_regular_bytes_nofollow(manifest_path, MAX_MANIFEST_BYTES)
                _m_sha, _m_doc, parsed_files_map = _parse_and_validate_manifest_bytes(raw_existing_manifest)
                allowed_existing = set(parsed_files_map.keys()) | {"manifest.json", INSTALL_MARKER_FILE}
            except (FileNotFoundError, OSError, PermissionError, ValueError):
                allowed_existing = {INSTALL_MARKER_FILE}
            unexpected = _scan_unexpected_inodes(
                dest_abs,
                allowed_files=allowed_existing,
                allow_pycache=True,
            )
            if unexpected:
                raise PermissionError(
                    f"REFUSING_DEST_WITH_USER_FILES: {dest_abs} contains unexpected entries "
                    f"outside installed manifest ({', '.join(unexpected[:8])})"
                )
    return dest_abs


def _write_install_marker(
    stage_dir: Path,
    *,
    version: str,
    ref: str,
    manifest_sha256: str,
    trust_mode: str,
    source_archive: Optional[Path] = None,
) -> None:
    verified_commit_sha = ref if (_is_full_40hex(ref) and source_archive is None) else ""
    marker_doc = {
        "schema": "KintsugiSandboxInstallMarker/1",
        "version": version,
        "ref": ref,
        "requested_ref": ref,
        "verified_commit_sha": verified_commit_sha,
        "manifest_sha256": manifest_sha256,
        "trust_mode": trust_mode,
        "installed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    raw = (json.dumps(marker_doc, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    marker_path = stage_dir / INSTALL_MARKER_FILE
    _write_new_regular_file(marker_path, raw, mode=0o600)
    _fsync_dir(stage_dir)


def _run_post_stage_smoke_test(stage_dir: Path) -> Dict[str, Any]:
    """Run `kintsugi_sandbox.py boot` in a clean minimal environment before swapping into `--dest`."""
    clean_env: Dict[str, str] = {
        "PATH": "/usr/bin:/bin:/usr/local/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "KINTSUGI_DISABLE_NATIVE": "1",
    }
    if "SYSTEMROOT" in os.environ:
        clean_env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    try:
        proc = subprocess.run(
            [sys.executable, str(stage_dir / "kintsugi_sandbox.py"), "boot"],
            cwd=str(stage_dir),
            env=clean_env,
            capture_output=True,
            text=True,
            timeout=SMOKE_TEST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"POST_STAGE_SMOKE_TIMEOUT: > {SMOKE_TEST_TIMEOUT_SECONDS}s") from exc
    if proc.returncode != 0:
        err_snippet = (proc.stderr or proc.stdout or "").strip()[:300]
        raise RuntimeError(f"POST_STAGE_SMOKE_FAILED: exit={proc.returncode} detail={err_snippet}")
    stdout_clean = (proc.stdout or "").strip()
    if not stdout_clean:
        raise RuntimeError("POST_STAGE_SMOKE_FAILED: empty boot output")
    try:
        boot_doc = _strict_json_loads(stdout_clean)
    except Exception as exc:
        raise RuntimeError(f"POST_STAGE_SMOKE_INVALID_JSON: {exc}") from exc
    if not isinstance(boot_doc, dict) or boot_doc.get("ok") is not True:
        raise RuntimeError("POST_STAGE_SMOKE_FAILED: boot reported ok != True")
    return boot_doc


def _atomic_swap_and_verify(
    stage_bundle_dir: Path,
    dest_dir: Path,
    *,
    expected_manifest_sha256: str = "",
    parent_fd: Optional[int] = None,
) -> Dict[str, Any]:
    """Atomically swap `stage_bundle_dir` into `dest_dir` via POSIX `dir_fd`, post-verify, and rollback on failure."""
    dest_abs = Path(os.path.abspath(str(dest_dir)))
    dest_name = dest_abs.name
    if not dest_name or dest_name in (".", "..") or dest_abs == dest_abs.parent:
        raise ValueError(f"INVALID_DEST_DIR: {dest_dir!r}")

    nonce = f"{os.getpid()}.{secrets.token_hex(6)}"
    old_name = f".{dest_name}.old.{nonce}"
    failed_name = f".{dest_name}.failed.{nonce}"

    if _SUPPORTS_DIR_FD and _SUPPORTS_STAT_DIR_FD and _SUPPORTS_LISTDIR_FD:
        owns_parent_fd = False
        pinned_parent_fd = parent_fd
        if pinned_parent_fd is None:
            pinned_parent_fd = _open_parent_dir_fd_nofollow(dest_abs.parent)
            owns_parent_fd = True

        stage_parent_fd: Optional[int] = None
        owns_stage_parent_fd = False
        try:
            stage_abs = _normalize_macos_root_path(Path(os.path.abspath(str(stage_bundle_dir))))
            parent_abs = _normalize_macos_root_path(dest_abs.parent)
            stage_rel = os.path.relpath(str(stage_abs), str(parent_abs))
            rel_parts = [p for p in stage_rel.split(os.sep) if p and p != "."]
            if rel_parts and ".." not in rel_parts and not os.path.isabs(stage_rel):
                stage_name = rel_parts[-1]
                inter_segs = tuple(rel_parts[:-1])
                if not inter_segs:
                    stage_parent_fd = pinned_parent_fd
                else:
                    stage_parent_fd = _open_relative_dir_fd_nofollow(pinned_parent_fd, inter_segs, dest_abs.parent)
                    owns_stage_parent_fd = True
            else:
                stage_name = stage_abs.name
                if not stage_name or stage_name in (".", ".."):
                    raise ValueError(f"INVALID_STAGE_DIR: {stage_bundle_dir!r}")
                stage_parent_fd = _open_parent_dir_fd_nofollow(stage_abs.parent)
                owns_stage_parent_fd = True

            stage_st = os.lstat(stage_name, dir_fd=stage_parent_fd)
            if stat.S_ISLNK(stage_st.st_mode):
                raise PermissionError(f"REFUSING_SYMLINK_STAGE: {stage_bundle_dir}")
            if not stat.S_ISDIR(stage_st.st_mode):
                raise PermissionError(f"REFUSING_NON_DIR_STAGE: {stage_bundle_dir}")

            for cand_name in (old_name, failed_name):
                try:
                    os.lstat(cand_name, dir_fd=pinned_parent_fd)
                except FileNotFoundError:
                    continue
                raise PermissionError(f"STAGING_COLLISION_OR_SYMLINK: {dest_abs.parent / cand_name}")

            dest_exists = False
            try:
                dest_st = os.lstat(dest_name, dir_fd=pinned_parent_fd)
            except FileNotFoundError:
                dest_st = None
            if dest_st is not None:
                if stat.S_ISLNK(dest_st.st_mode):
                    raise PermissionError(f"REFUSING_SYMLINK_DEST: {dest_abs}")
                if not stat.S_ISDIR(dest_st.st_mode):
                    raise PermissionError(f"REFUSING_NON_DIR_DEST: {dest_abs}")
                dest_exists = True

            dir_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            verified_ok = False
            moved_old = False
            moved_new = False
            try:
                if dest_exists:
                    os.rename(dest_name, old_name, src_dir_fd=pinned_parent_fd, dst_dir_fd=pinned_parent_fd)
                    moved_old = True
                os.rename(stage_name, dest_name, src_dir_fd=stage_parent_fd, dst_dir_fd=pinned_parent_fd)
                moved_new = True
                with contextlib.suppress(OSError):
                    os.fsync(pinned_parent_fd)

                try:
                    post_dest_fd = os.open(dest_name, dir_flags, dir_fd=pinned_parent_fd)
                except OSError as exc:
                    if exc.errno in (getattr(errno, "ELOOP", -1), getattr(errno, "EMLINK", -1)):
                        raise PermissionError(f"REFUSING_SYMLINK_DEST: {dest_abs}") from exc
                    if exc.errno == getattr(errno, "ENOTDIR", -1):
                        raise PermissionError(f"REFUSING_NON_DIR_DEST: {dest_abs}") from exc
                    raise
                try:
                    post_dest_st = os.fstat(post_dest_fd)
                    if not stat.S_ISDIR(post_dest_st.st_mode):
                        raise PermissionError(f"REFUSING_NON_DIR_DEST: {dest_abs}")
                    if (post_dest_st.st_dev, post_dest_st.st_ino) != (stage_st.st_dev, stage_st.st_ino):
                        raise PermissionError(f"DEST_CHANGED_DURING_VERIFY: {dest_abs}")
                    post_manifest = verify_manifest_tree(
                        dest_abs,
                        src_root=dest_abs,
                        expected_manifest_sha256=expected_manifest_sha256,
                        reject_extra_files=True,
                        allow_install_marker=True,
                        bundle_fd=post_dest_fd,
                    )
                    try:
                        after_st = os.lstat(dest_name, dir_fd=pinned_parent_fd)
                    except OSError as exc:
                        raise PermissionError(f"DEST_CHANGED_DURING_VERIFY: {dest_abs}") from exc
                    if stat.S_ISLNK(after_st.st_mode) or (after_st.st_dev, after_st.st_ino) != (
                        post_dest_st.st_dev,
                        post_dest_st.st_ino,
                    ):
                        raise PermissionError(f"DEST_CHANGED_DURING_VERIFY: {dest_abs}")
                finally:
                    os.close(post_dest_fd)

                verified_ok = True
                return post_manifest
            except BaseException:
                if moved_new:
                    cur_dest_st: Optional[os.stat_result] = None
                    with contextlib.suppress(FileNotFoundError, OSError):
                        cur_dest_st = os.lstat(dest_name, dir_fd=pinned_parent_fd)
                    if cur_dest_st is not None and not stat.S_ISLNK(cur_dest_st.st_mode):
                        with contextlib.suppress(OSError):
                            os.rename(dest_name, failed_name, src_dir_fd=pinned_parent_fd, dst_dir_fd=pinned_parent_fd)
                if moved_old:
                    old_st: Optional[os.stat_result] = None
                    with contextlib.suppress(FileNotFoundError, OSError):
                        old_st = os.lstat(old_name, dir_fd=pinned_parent_fd)
                    dest_still_present = False
                    with contextlib.suppress(FileNotFoundError, OSError):
                        os.lstat(dest_name, dir_fd=pinned_parent_fd)
                        dest_still_present = True
                    if old_st is not None and not stat.S_ISLNK(old_st.st_mode) and not dest_still_present:
                        os.rename(old_name, dest_name, src_dir_fd=pinned_parent_fd, dst_dir_fd=pinned_parent_fd)
                        with contextlib.suppress(OSError):
                            os.fsync(pinned_parent_fd)
                with contextlib.suppress(OSError):
                    failed_st = os.lstat(failed_name, dir_fd=pinned_parent_fd)
                    if stat.S_ISDIR(failed_st.st_mode) and not stat.S_ISLNK(failed_st.st_mode):
                        _rmtree_under_dir_fd(pinned_parent_fd, failed_name)
                        with contextlib.suppress(OSError):
                            os.fsync(pinned_parent_fd)
                raise
            finally:
                if verified_ok:
                    with contextlib.suppress(OSError):
                        old_st = os.lstat(old_name, dir_fd=pinned_parent_fd)
                        if stat.S_ISDIR(old_st.st_mode) and not stat.S_ISLNK(old_st.st_mode):
                            _rmtree_under_dir_fd(pinned_parent_fd, old_name)
                            with contextlib.suppress(OSError):
                                os.fsync(pinned_parent_fd)
        finally:
            if owns_stage_parent_fd and stage_parent_fd is not None:
                os.close(stage_parent_fd)
            if owns_parent_fd and pinned_parent_fd is not None:
                os.close(pinned_parent_fd)

    # Non-POSIX fallback (no dir_fd support)
    sibling_old = dest_abs.parent / old_name
    sibling_bad = dest_abs.parent / failed_name
    for cand in (sibling_old, sibling_bad):
        if cand.is_symlink() or cand.exists():
            raise PermissionError(f"STAGING_COLLISION_OR_SYMLINK: {cand}")
    verified_ok = False
    moved_old = False
    moved_new = False
    try:
        if dest_abs.exists():
            os.rename(str(dest_abs), str(sibling_old))
            moved_old = True
        os.rename(str(stage_bundle_dir), str(dest_abs))
        moved_new = True
        _fsync_dir(dest_abs.parent)
        post_manifest = verify_manifest_tree(
            dest_abs,
            src_root=dest_abs,
            expected_manifest_sha256=expected_manifest_sha256,
            reject_extra_files=True,
            allow_install_marker=True,
        )
        verified_ok = True
        return post_manifest
    except BaseException:
        if moved_new and dest_abs.exists() and not dest_abs.is_symlink():
            with contextlib.suppress(OSError):
                os.rename(str(dest_abs), str(sibling_bad))
        if moved_old and sibling_old.exists() and not dest_abs.exists():
            os.rename(str(sibling_old), str(dest_abs))
            _fsync_dir(dest_abs.parent)
        with contextlib.suppress(OSError):
            if sibling_bad.exists() and not sibling_bad.is_symlink():
                shutil.rmtree(sibling_bad, ignore_errors=True)
        raise
    finally:
        if verified_ok and sibling_old.exists() and not sibling_old.is_symlink():
            shutil.rmtree(sibling_old, ignore_errors=True)
            _fsync_dir(dest_abs.parent)


def _build_cloud_browser_fallback(
    *,
    safe_ref: str,
    dest_abs: Path,
    expected_manifest_sha256: str,
    require_pin: bool,
    require_full_sha: bool,
    allow_downgrade_to_tofu: bool = False,
    primary_tar: str,
) -> Dict[str, Any]:
    primary_zip = primary_tar[:-7] + ".zip" if primary_tar.endswith(".tar.gz") else primary_tar
    extra_flags: List[str] = [
        f"--ref {shlex.quote(safe_ref)}",
        f"--dest {shlex.quote(str(dest_abs))}",
    ]
    clean_pin = (expected_manifest_sha256 or "").strip().lower()
    if clean_pin:
        extra_flags.append(f"--expected-manifest-sha256 {shlex.quote(clean_pin)}")
    if require_pin:
        extra_flags.append("--require-pin")
    if require_full_sha:
        extra_flags.append("--require-full-sha")
    if allow_downgrade_to_tofu:
        extra_flags.append("--allow-unpinned-downgrade")
    flag_str = " ".join(extra_flags)
    tar_local = f"/mnt/data/{REPO_NAME}-{safe_ref}.tar.gz"
    zip_local = f"/mnt/data/{REPO_NAME}-{safe_ref}.zip"
    return {
        "archive_zip_url": primary_zip,
        "archive_tar_url": primary_tar,
        "instructions_url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{safe_ref}/cloud-sandbox/AGENT_INSTRUCTIONS.md",
        "tasks_url": f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{safe_ref}/cloud-sandbox/TASKS.md",
        "install_downloaded_archive_cmd": f"python3 -B /tmp/k_boot.py --source-archive {shlex.quote(tar_local)} {flag_str}",
        "install_downloaded_zip_cmd": f"python3 -B /tmp/k_boot.py --source-archive {shlex.quote(zip_local)} {flag_str}",
    }


def install_or_update(
    *,
    ref: str = "main",
    dest: Path = Path("/tmp/kintsugi_sandbox"),
    source_archive: Optional[Path] = None,
    expected_manifest_sha256: str = "",
    expected_bootstrap_sha256: str = "",
    require_pin: bool = False,
    require_full_sha: bool = False,
    allow_downgrade_to_tofu: bool = False,
    run_post_stage_smoke: bool = True,
    timeout: int = 30,
) -> Dict[str, Any]:
    """Download (or load local `.tar.gz`/`.zip`), verify manifest fail-closed, and atomically install."""
    if (expected_bootstrap_sha256 or "").strip():
        verify_self_sha256(expected_bootstrap_sha256)
    safe_ref = validate_git_ref(ref, require_full_sha=require_full_sha)
    clean_pin = (expected_manifest_sha256 or "").strip().lower()
    if require_pin and not clean_pin:
        raise ValueError("UNTRUSTED_UPDATE_MANIFEST_PIN_REQUIRED")
    if clean_pin and not HEX64_PATTERN.fullmatch(clean_pin):
        raise ValueError("INVALID_EXPECTED_MANIFEST_SHA256")
    trust_mode = (
        "PINNED_MANIFEST_SHA256"
        if clean_pin
        else ("TOFU_UNPINNED_LOCAL_ARCHIVE" if source_archive is not None else "TOFU_UNPINNED_GITHUB_HTTPS")
    )
    verified_commit_sha = safe_ref if (_is_full_40hex(safe_ref) and source_archive is None) else ""

    # For network installs, refuse unsafe non-empty non-Kintsugi dest or pin downgrade before any network request.
    # For local archives, validate dest structure & git checkout protection immediately and enforce non-empty,
    # pin-continuity, and user-file protection under the install lock right before smoke test & swap so bad
    # archives fail with archive errors first.
    dest_abs = _validate_safe_dest_dir(
        dest,
        check_nonempty=(source_archive is None),
        create_parent=False,
        expected_manifest_sha256=clean_pin,
        allow_downgrade_to_tofu=allow_downgrade_to_tofu,
    )

    source_used = ""
    if source_archive is not None:
        _reject_symlink_ancestors(source_archive.parent)
        archive_bytes = _read_regular_bytes_nofollow(source_archive, MAX_ARCHIVE_BYTES)
        source_used = f"local:{source_archive}"
    else:
        safe_timeout = _validate_timeout(timeout)
        archive_bytes = b""
        last_err: Optional[Exception] = None
        failure_status = "NETWORK_BLOCKED_USE_CLOUD_BROWSER"
        urls = candidate_archive_urls(safe_ref, require_full_sha=require_full_sha)
        all_404 = True
        for url in urls:
            try:
                archive_bytes = _download_bounded_bytes(url, timeout=safe_timeout)
                source_used = url
                all_404 = False
                break
            except urllib.error.HTTPError as exc:
                last_err = exc
                if exc.code == 404:
                    continue
                all_404 = False
                if exc.code == 403:
                    failure_status = "ACCESS_DENIED_USE_CLOUD_BROWSER"
                else:
                    failure_status = "NETWORK_BLOCKED_USE_CLOUD_BROWSER"
                break
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_err = exc
                all_404 = False
                failure_status = "NETWORK_BLOCKED_USE_CLOUD_BROWSER"
                break
        if not archive_bytes:
            if all_404:
                failure_status = "REF_NOT_FOUND"
            return {
                "ok": False,
                "status": failure_status,
                "ref": safe_ref,
                "requested_ref": safe_ref,
                "verified_commit_sha": verified_commit_sha,
                "trust_mode": trust_mode,
                "error": str(last_err or "download failed"),
                "cloud_browser_fallback": _build_cloud_browser_fallback(
                    safe_ref=safe_ref,
                    dest_abs=dest_abs,
                    expected_manifest_sha256=clean_pin,
                    require_pin=require_pin,
                    require_full_sha=require_full_sha,
                    allow_downgrade_to_tofu=allow_downgrade_to_tofu,
                    primary_tar=urls[0],
                ),
            }

    dest_abs.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_ancestors(dest_abs.parent)

    # Stage directly under dest_abs.parent so os.rename() is guaranteed same-filesystem & atomic.
    with tempfile.TemporaryDirectory(prefix=f".{dest_abs.name}.stage.", dir=str(dest_abs.parent)) as td:
        os.chmod(td, 0o700)
        stage_dir = Path(td) / "bundle"
        stage_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(str(stage_dir), 0o700)

        extracted_count = _safe_extract_archive(archive_bytes, stage_dir)
        pre_manifest = verify_manifest_tree(
            stage_dir,
            src_root=stage_dir,
            expected_manifest_sha256=clean_pin,
            reject_extra_files=True,
            allow_install_marker=False,
        )

        with _install_file_lock(dest_abs) as parent_fd:
            # Re-validate destination under the cross-process lock using the pinned parent dir_fd.
            _validate_safe_dest_dir(
                dest_abs,
                check_nonempty=True,
                create_parent=False,
                parent_fd=parent_fd,
                expected_manifest_sha256=clean_pin,
                allow_downgrade_to_tofu=allow_downgrade_to_tofu,
            )

            _write_install_marker(
                stage_dir,
                version=str(pre_manifest.get("cloud_sandbox_edition_version") or pre_manifest.get("version", "")),
                ref=safe_ref,
                manifest_sha256=str(pre_manifest["manifest_sha256"]),
                trust_mode=trust_mode,
                source_archive=source_archive,
            )

            smoke_passed: Optional[bool] = None
            if run_post_stage_smoke:
                _run_post_stage_smoke_test(stage_dir)
                smoke_passed = True

            post_manifest = _atomic_swap_and_verify(
                stage_dir,
                dest_abs,
                expected_manifest_sha256=clean_pin,
                parent_fd=parent_fd,
            )

    return {
        "ok": True,
        "status": "UPDATED_AND_VERIFIED",
        "ref": safe_ref,
        "requested_ref": safe_ref,
        "verified_commit_sha": verified_commit_sha,
        "trust_mode": trust_mode,
        "source": source_used,
        "dest": str(dest_abs),
        "extracted_files": extracted_count,
        "smoke_test_passed": smoke_passed,
        "manifest": post_manifest,
    }


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Fail-Closed GitHub Self-Updater for Kintsugi Harness Cloud Sandbox")
    parser.add_argument("--ref", default="main", help="Git branch, tag, or commit SHA (default: main)")
    parser.add_argument("--dest", default="/tmp/kintsugi_sandbox", help="Target install directory")
    parser.add_argument("--source-archive", default="", help="Optional local .tar.gz or .zip archive (offline fallback)")
    parser.add_argument("--expected-manifest-sha256", default="", help="Optional pinned 64-hex manifest SHA-256")
    parser.add_argument(
        "--expected-bootstrap-sha256",
        default="",
        help="Optional pinned 64-hex SHA-256 of bootstrap.py itself (fail-closed self-digest verification)",
    )
    parser.add_argument("--require-pin", action="store_true", help="Fail closed unless --expected-manifest-sha256 is given")
    parser.add_argument("--require-full-sha", action="store_true", help="Fail closed unless --ref is a full 40-hex commit SHA")
    parser.add_argument(
        "--allow-unpinned-downgrade",
        action="store_true",
        help="Explicitly allow downgrading an existing pinned installation to unpinned TOFU mode",
    )
    parser.add_argument("--timeout", type=int, default=30, help="HTTPS timeout in seconds (1..300)")
    args = parser.parse_args(argv)
    try:
        res = install_or_update(
            ref=args.ref,
            dest=Path(args.dest),
            source_archive=Path(args.source_archive) if args.source_archive else None,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_bootstrap_sha256=args.expected_bootstrap_sha256,
            require_pin=args.require_pin,
            require_full_sha=args.require_full_sha,
            allow_downgrade_to_tofu=args.allow_unpinned_downgrade,
            timeout=args.timeout,
        )
    except Exception as exc:
        print(json.dumps({"ok": False, "status": "BOOTSTRAP_FAILED_CLOSED", "error": str(exc)}, indent=2))
        return 1
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0 if res.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
