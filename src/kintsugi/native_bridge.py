"""Verified `cdylib` FFI bridge (`kintsugi.native_bridge`) with external SHA-256 pinning, atomic staging, and `kintsugi-rs` fallback.

Security model (`KH-B2-FFI-004` hardened):
  1. Discovers/builds ONLY `<repo_root>/target/release/libkintsugi_core.dylib`.
  2. Enforces `assert_not_symlink` on `repo_root`, `target/`, `target/release/`, binaries, and pin manifests.
  3. Rejects ANY co-located `.sha256` pin inside `repo_root`, `target/`, or sharing a parent directory with
     the `.dylib` / `kintsugi-rs` binary (`SECURITY_COLOCATED_PIN_REFUSED`). Trusted pins come ONLY from
     explicit constructor args, environment variables, or an external `pin_manifest_path` /
     `DEFAULT_EXTERNAL_PIN_MANIFEST`.
  4. Reads the binary ONCE via `O_RDONLY | O_NOFOLLOW`, verifies regular non-world-writable file, computes
     SHA-256 in memory over those exact bytes, verifies via `hmac.compare_digest`, and stages the verified
     bytes into a private `0o700` temp directory with mode `0o500` BEFORE `ctypes.CDLL` or `subprocess.run`
     (eliminating TOCTOU swaps on `target/release/`).
  5. Verifies `kintsugi_abi_version() == 1` before exposing any FFI function, and refuses unpinned `kintsugi-rs`
     fallback execution (`backend == "unavailable"`).
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import hmac
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import weakref
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from kintsugi.shield import assert_not_symlink, atomic_write_text

EXPECTED_ABI_VERSION = 1
DEFAULT_EXTERNAL_PIN_MANIFEST = Path.home() / ".config" / "kintsugi" / "native_pins.json"
PIN_MANIFEST_SCHEMA = "KintsugiNativePins/1"
_MAX_MANIFEST_BYTES = 1_048_576


def _cdylib_filename() -> str:
    """Return platform-native Cargo cdylib filename (`.dylib` on macOS, `.so` on Linux, `.dll` on Windows)."""
    if sys.platform == "darwin":
        return "libkintsugi_core.dylib"
    if sys.platform == "win32":
        return "kintsugi_core.dll"
    return "libkintsugi_core.so"

KINTSUGI_FFI_OK = 0
KINTSUGI_FFI_ERR_NULL_PTR = -1
KINTSUGI_FFI_ERR_INVALID_UTF8 = -2
KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL = -3
KINTSUGI_FFI_ERR_INVALID_ARG = -4
KINTSUGI_FFI_ERR_RULE_INVALID = -5
KINTSUGI_FFI_ERR_OVERFLOW = -6
KINTSUGI_FFI_ERR_PANIC = -99

ByteLike = Union[bytes, bytearray, memoryview]

_LANG_TO_EXT: Dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "rust": ".rs",
    "shell": ".sh",
    "markdown": ".md",
    "dockerfile": ".dockerfile",
}


def _as_bytes(data: Union[str, ByteLike]) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    view = memoryview(data)
    if view.format != "B":
        view = view.cast("B")
    return bytes(view)


def _normalize_sha256_pin(raw_pin: str) -> str:
    clean = str(raw_pin).strip().split()[0].lower()
    if clean.startswith("sha256:"):
        clean = clean[len("sha256:") :]
    if len(clean) != 64 or any(ch not in "0123456789abcdef" for ch in clean):
        raise ValueError(f"Invalid SHA-256 digest format: {raw_pin!r}")
    return clean


def _commonpath_within(child_str: str, parent_str: str) -> bool:
    try:
        return os.path.commonpath([child_str, parent_str]) == parent_str
    except ValueError:
        return False
    except OSError:
        return True


def _is_within(child: Path, parent: Path) -> bool:
    """Return True if `child` is inside or equal to `parent` (lexical or resolved), fail-closed on OSError."""
    try:
        c_abs = os.path.abspath(str(child))
        p_abs = os.path.abspath(str(parent))
        if _commonpath_within(c_abs, p_abs):
            return True
        c_real = os.path.realpath(str(child))
        p_real = os.path.realpath(str(parent))
        return _commonpath_within(c_real, p_real)
    except OSError:
        return True


def _same_parent_dir(a: Path, b: Path) -> bool:
    try:
        if os.path.abspath(str(a.parent)) == os.path.abspath(str(b.parent)):
            return True
        return os.path.realpath(str(a.parent)) == os.path.realpath(str(b.parent))
    except OSError:
        return True


def _validate_external_pin_path(
    pin_path: Union[str, Path],
    *,
    repo_root: Optional[Path] = None,
    binary_paths: Sequence[Optional[Path]] = (),
) -> Path:
    """Reject symlinks and ANY co-located pin inside `repo_root`, `target/`, or sharing a binary parent dir."""
    pin_p = Path(pin_path).expanduser()
    assert_not_symlink(pin_p)
    if pin_p.parent.exists() and pin_p.parent.is_symlink():
        raise PermissionError(f"SECURITY_SYMLINK_REFUSED: Pin parent directory is a symlink: {pin_p.parent}")
    if repo_root is not None:
        if _is_within(pin_p, repo_root) or _is_within(pin_p, repo_root / "target"):
            raise PermissionError(
                f"SECURITY_COLOCATED_PIN_REFUSED: Refusing pin inside repo_root or target/: {pin_p}"
            )
    for bin_p in binary_paths:
        if bin_p is not None and _same_parent_dir(pin_p, bin_p):
            raise PermissionError(
                f"SECURITY_COLOCATED_PIN_REFUSED: Refusing pin sharing parent directory with binary: {pin_p}"
            )
    parent_real = os.path.realpath(str(pin_p.parent)) if pin_p.parent.exists() else os.path.abspath(str(pin_p.parent))
    return Path(parent_real) / pin_p.name


def _read_and_hash_regular_nofollow(path: Path, *, max_bytes: Optional[int] = None) -> Tuple[bytes, str]:
    """Open `path` ONCE with `O_RDONLY | O_NOFOLLOW`, verify non-world-writable regular file, read & SHA-256."""
    assert_not_symlink(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise PermissionError(f"SECURITY_SYMLINK_REFUSED: {path}") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"SECURITY_NOT_REGULAR_FILE: {path}")
        if (st.st_mode & 0o002) != 0:
            raise PermissionError(f"SECURITY_WORLD_WRITABLE_BINARY: {path}")
        chunks: List[bytes] = []
        total = 0
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"File exceeds maximum allowed bytes ({max_bytes}): {path}")
            chunks.append(chunk)
            h.update(chunk)
        return b"".join(chunks), h.hexdigest()
    finally:
        os.close(fd)


def _read_regular_nofollow_sha256(path: Path) -> str:
    """Open `path` with `O_NOFOLLOW`, verify non-world-writable regular file, and return SHA-256 hex digest."""
    _, digest = _read_and_hash_regular_nofollow(path)
    return digest


def _stage_verified_binary_bytes(
    raw_bytes: bytes,
    *,
    filename: str,
    mode: int = 0o500,
) -> Tuple[tempfile.TemporaryDirectory[str], Path]:
    """Stage verified in-memory binary bytes into an owner-only `0o700` dir with immutable `0o500` permissions."""
    if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
        raise ValueError(f"Invalid staged binary filename: {filename!r}")
    stage_dir = tempfile.TemporaryDirectory(prefix="kintsugi_ffi_stage_")
    try:
        os.chmod(stage_dir.name, 0o700)
        staged_path = Path(stage_dir.name) / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(staged_path), flags, mode)
        try:
            view = memoryview(raw_bytes)
            written = 0
            while written < len(view):
                n = os.write(fd, view[written:])
                if n <= 0:
                    raise OSError(f"Short write staging verified binary: {staged_path}")
                written += n
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        return stage_dir, staged_path
    except Exception:
        stage_dir.cleanup()
        raise


def _cleanup_stage_dirs(stage_dirs: List[tempfile.TemporaryDirectory[str]]) -> None:
    while stage_dirs:
        td = stage_dirs.pop()
        try:
            td.cleanup()
        except OSError as cleanup_err:
            _ = cleanup_err


def _resolve_manifest_path(
    pin_manifest_path: Optional[Union[str, Path]] = None,
    *,
    repo_root: Optional[Path] = None,
    binary_paths: Sequence[Optional[Path]] = (),
) -> Path:
    raw: Union[str, Path]
    if pin_manifest_path is not None:
        raw = pin_manifest_path
    else:
        env_manifest = os.environ.get("KINTSUGI_NATIVE_PIN_MANIFEST", "").strip()
        raw = env_manifest if env_manifest else DEFAULT_EXTERNAL_PIN_MANIFEST
    return _validate_external_pin_path(raw, repo_root=repo_root, binary_paths=binary_paths)


def read_external_native_pins(
    pin_manifest_path: Optional[Union[str, Path]] = None,
    *,
    repo_root: Optional[Union[str, Path]] = None,
    binary_paths: Sequence[Optional[Path]] = (),
) -> Dict[str, Dict[str, Any]]:
    """Read verified native binary pins from an external JSON manifest (`O_NOFOLLOW`, non-world-writable)."""
    root_p = Path(repo_root).resolve() if repo_root is not None else None
    manifest_p = _resolve_manifest_path(pin_manifest_path, repo_root=root_p, binary_paths=binary_paths)
    if not manifest_p.exists():
        return {}
    raw_bytes, _ = _read_and_hash_regular_nofollow(manifest_p, max_bytes=_MAX_MANIFEST_BYTES)
    parsed = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"Invalid external pin manifest format (expected JSON object): {manifest_p}")
    out: Dict[str, Dict[str, Any]] = {}
    nested = parsed.get("repos")
    if isinstance(nested, dict):
        for k, v in nested.items():
            if isinstance(v, dict):
                out[str(k)] = dict(v)
    for k, v in parsed.items():
        if k not in ("schema", "repos") and isinstance(v, dict):
            out[str(k)] = dict(v)
    return out


def write_external_native_pins(
    repo_root: Union[str, Path],
    *,
    dylib_sha256: Optional[str] = None,
    rust_bin_sha256: Optional[str] = None,
    dylib_path: Optional[Union[str, Path]] = None,
    rust_bin_path: Optional[Union[str, Path]] = None,
    pin_manifest_path: Optional[Union[str, Path]] = None,
) -> Path:
    """Atomically store native binary SHA-256 pins (`0o600`) in an external manifest outside `repo_root`."""
    root_p = Path(repo_root).resolve()
    bin_paths: List[Optional[Path]] = [
        root_p / "target" / "release" / _cdylib_filename(),
        root_p / "target" / "release" / "kintsugi-rs",
        Path(dylib_path) if dylib_path is not None else None,
        Path(rust_bin_path) if rust_bin_path is not None else None,
    ]
    manifest_p = _resolve_manifest_path(pin_manifest_path, repo_root=root_p, binary_paths=bin_paths)
    existing = read_external_native_pins(manifest_p, repo_root=root_p, binary_paths=bin_paths)

    repo_key = str(root_p)
    entry: Dict[str, Any] = dict(existing.get(repo_key) or {})
    if dylib_sha256 is not None:
        entry["dylib_sha256"] = _normalize_sha256_pin(dylib_sha256)
    if rust_bin_sha256 is not None:
        entry["rust_bin_sha256"] = _normalize_sha256_pin(rust_bin_sha256)
    if dylib_path is not None:
        entry["dylib_path"] = str(Path(dylib_path).resolve())
    if rust_bin_path is not None:
        entry["rust_bin_path"] = str(Path(rust_bin_path).resolve())
    existing[repo_key] = entry

    if manifest_p.parent == DEFAULT_EXTERNAL_PIN_MANIFEST.parent and not manifest_p.parent.exists():
        manifest_p.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(manifest_p.parent, 0o700)
    serialized = json.dumps(existing, ensure_ascii=False, indent=2) + "\n"
    atomic_write_text(manifest_p, serialized, mode=0o600)
    return manifest_p


def _find_cargo_bin() -> Optional[str]:
    found = shutil.which("cargo")
    if found:
        return found
    cand = Path.home() / ".cargo" / "bin" / "cargo"
    if cand.is_file():
        return str(cand)
    return None


def build_verified_cdylib(
    repo_root: Optional[Union[str, Path]] = None,
    *,
    pin_manifest_path: Optional[Union[str, Path]] = None,
    timeout_sec: float = 120.0,
) -> Tuple[Path, str]:
    """Build `target/release/libkintsugi_core.dylib` + bins via Cargo and store verified SHA-256 pins externally."""
    root = (Path(repo_root) if repo_root is not None else Path(__file__).resolve().parents[2]).resolve()
    cargo_toml = root / "Cargo.toml"
    ffi_rs = root / "rust" / "src" / "ffi.rs"
    assert_not_symlink(cargo_toml)
    assert_not_symlink(ffi_rs)
    if not cargo_toml.is_file() or not ffi_rs.is_file():
        raise FileNotFoundError(f"Missing Cargo.toml or rust/src/ffi.rs under {root}")

    target_dir = root / "target"
    release_dir = target_dir / "release"
    dylib_name = _cdylib_filename()
    dylib_path = release_dir / dylib_name
    rust_bin_path = release_dir / "kintsugi-rs"
    # Validate external pin path BEFORE building so co-located paths fail closed immediately
    resolved_manifest = _resolve_manifest_path(
        pin_manifest_path,
        repo_root=root,
        binary_paths=(dylib_path, rust_bin_path),
    )

    cargo = _find_cargo_bin()
    if not cargo:
        raise FileNotFoundError("`cargo` toolchain executable not found")

    proc = subprocess.run(
        [cargo, "build", "--release", "--lib", "--bins"],
        cwd=str(root),
        capture_output=True,
        text=True,
        shell=False,
        check=False,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cargo build --release --lib --bins failed (rc={proc.returncode}): {proc.stderr.strip()}")

    assert_not_symlink(target_dir)
    assert_not_symlink(release_dir)
    assert_not_symlink(dylib_path)
    assert_not_symlink(rust_bin_path)
    if not dylib_path.is_file():
        raise FileNotFoundError(f"Expected built cdylib missing: {dylib_path}")
    if not rust_bin_path.is_file():
        raise FileNotFoundError(f"Expected built binary missing: {rust_bin_path}")

    _, dylib_digest = _read_and_hash_regular_nofollow(dylib_path)
    _, rust_bin_digest = _read_and_hash_regular_nofollow(rust_bin_path)
    write_external_native_pins(
        root,
        dylib_sha256=dylib_digest,
        rust_bin_sha256=rust_bin_digest,
        dylib_path=dylib_path,
        rust_bin_path=rust_bin_path,
        pin_manifest_path=resolved_manifest,
    )
    stale_colocated = release_dir / f"{dylib_name}.sha256"
    if not stale_colocated.is_symlink() and stale_colocated.is_file():
        stale_colocated.unlink()
    return dylib_path, dylib_digest


class NativeBridge:
    """Verified FFI bridge to `target/release/libkintsugi_core.{dylib,so,dll}` with pinned `kintsugi-rs` fallback."""

    def __init__(
        self,
        *,
        repo_root: Optional[Union[str, Path]] = None,
        dylib_path: Optional[Union[str, Path]] = None,
        rust_bin: Optional[Union[str, Path]] = None,
        expected_sha256: Optional[str] = None,
        expected_rust_bin_sha256: Optional[str] = None,
        pin_manifest_path: Optional[Union[str, Path]] = None,
        auto_build: bool = False,
        allow_fallback: bool = True,
    ) -> None:
        self.repo_root = (
            Path(repo_root).resolve() if repo_root is not None else Path(__file__).resolve().parents[2]
        )
        self.expected_dylib_path = self.repo_root / "target" / "release" / _cdylib_filename()
        self.allow_fallback = allow_fallback
        self._explicit_pin_manifest_path = pin_manifest_path
        self._raw_rust_bin_candidate = self._resolve_rust_bin(rust_bin)
        self._stage_dirs: List[tempfile.TemporaryDirectory[str]] = []
        self._finalizer = weakref.finalize(self, _cleanup_stage_dirs, self._stage_dirs)

        self._lib: Optional[ctypes.CDLL] = None
        self._staged_dylib_path: Optional[Path] = None
        self.cdylib_loaded: bool = False
        self.abi_version: Optional[int] = None
        self.dylib_sha256: Optional[str] = None
        self.rust_bin: Optional[Path] = None
        self.rust_bin_sha256: Optional[str] = None
        self.fallback_reason: Optional[str] = None

        self._load_verified_cdylib(
            requested_dylib=dylib_path,
            expected_sha256=expected_sha256,
            auto_build=auto_build,
        )
        if not self.cdylib_loaded and self.allow_fallback:
            self._load_verified_rust_bin(expected_rust_bin_sha256=expected_rust_bin_sha256)

    def close(self) -> None:
        """Clean up private `0o700` staged binary directories and clear loaded native handles."""
        self._lib = None
        self._staged_dylib_path = None
        self.cdylib_loaded = False
        self.abi_version = None
        self.rust_bin = None
        if self._finalizer.alive:
            self._finalizer()
        else:
            _cleanup_stage_dirs(self._stage_dirs)

    def __enter__(self) -> "NativeBridge":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _resolve_rust_bin(self, explicit: Optional[Union[str, Path]]) -> Optional[Path]:
        if explicit is not None:
            p = Path(explicit)
            if p.is_symlink() or not p.is_file():
                return None
            return p
        target_dir = self.repo_root / "target"
        if target_dir.is_symlink():
            return None
        for rel in ("target/release/kintsugi-rs", "target/debug/kintsugi-rs"):
            cand = self.repo_root / rel
            if cand.parent.is_symlink() or cand.is_symlink() or not cand.is_file():
                continue
            return cand
        return None

    @property
    def backend(self) -> str:
        if self.cdylib_loaded:
            return "cdylib_ffi_v1"
        if self.rust_bin is not None and self.rust_bin.is_file():
            return "subprocess_kintsugi_rs"
        return "unavailable"

    def _reject_or_fallback(self, reason: str, exc: Optional[Exception] = None) -> None:
        self._lib = None
        self._staged_dylib_path = None
        self.cdylib_loaded = False
        self.abi_version = None
        self.fallback_reason = reason
        if not self.allow_fallback:
            self.close()
            if exc is not None:
                raise exc
            raise PermissionError(f"CDYLIB_VERIFICATION_FAILED: {reason}")

    def _validated_binary_paths_for_pin_check(self, requested_dylib: Optional[Union[str, Path]] = None) -> Tuple[Optional[Path], ...]:
        return (
            self.expected_dylib_path,
            self._raw_rust_bin_candidate,
            Path(requested_dylib) if requested_dylib is not None else None,
        )

    def _has_colocated_sha256_pin(self, binary_path: Optional[Path]) -> bool:
        if binary_path is None:
            return False
        candidates = (
            binary_path.parent / f"{binary_path.name}.sha256",
            binary_path.with_suffix(".sha256"),
        )
        return any(c.exists() or c.is_symlink() for c in candidates)

    def _resolve_trusted_pin(
        self,
        *,
        explicit_pin: Optional[str],
        env_var: str,
        manifest_field: str,
        binary_path: Optional[Path],
        requested_dylib: Optional[Union[str, Path]] = None,
        check_colocated_pin: bool = True,
    ) -> Optional[str]:
        bin_paths = self._validated_binary_paths_for_pin_check(requested_dylib)
        if self._explicit_pin_manifest_path is not None or os.environ.get("KINTSUGI_NATIVE_PIN_MANIFEST", "").strip():
            # Always reject co-located manifest paths even if explicit/env pin was also passed
            _resolve_manifest_path(
                self._explicit_pin_manifest_path,
                repo_root=self.repo_root,
                binary_paths=bin_paths,
            )

        if explicit_pin is not None:
            return _normalize_sha256_pin(explicit_pin)

        env_pin = os.environ.get(env_var, "").strip()
        if env_pin:
            return _normalize_sha256_pin(env_pin)

        manifest_p = _resolve_manifest_path(
            self._explicit_pin_manifest_path,
            repo_root=self.repo_root,
            binary_paths=bin_paths,
        )
        pins_map = read_external_native_pins(manifest_p, repo_root=self.repo_root, binary_paths=bin_paths)
        entry = pins_map.get(str(self.repo_root.resolve()))
        if isinstance(entry, dict) and entry.get(manifest_field):
            return _normalize_sha256_pin(str(entry[manifest_field]))

        if check_colocated_pin and self._has_colocated_sha256_pin(binary_path):
            raise PermissionError(
                f"SECURITY_COLOCATED_PIN_REFUSED: Co-located .sha256 pin near {binary_path} is untrusted"
            )
        return None

    def _load_verified_cdylib(
        self,
        *,
        requested_dylib: Optional[Union[str, Path]],
        expected_sha256: Optional[str],
        auto_build: bool,
    ) -> None:
        try:
            # 1. Strictly enforce ONLY `<repo_root>/target/release/libkintsugi_core.dylib`
            if requested_dylib is not None:
                req_p = Path(requested_dylib)
                if req_p.is_symlink():
                    raise PermissionError(f"SECURITY_SYMLINK_REFUSED: {req_p}")
                if req_p.resolve() != self.expected_dylib_path.resolve():
                    raise PermissionError(
                        f"SECURITY_UNTRUSTED_DYLIB_PATH: Refusing path outside target/release/{self.expected_dylib_path.name}: {req_p}"
                    )

            target_dir = self.repo_root / "target"
            release_dir = target_dir / "release"
            assert_not_symlink(self.repo_root)
            if target_dir.exists() or target_dir.is_symlink():
                assert_not_symlink(target_dir)
            if release_dir.exists() or release_dir.is_symlink():
                assert_not_symlink(release_dir)
            if self.expected_dylib_path.exists() or self.expected_dylib_path.is_symlink():
                assert_not_symlink(self.expected_dylib_path)

            # 2. Optionally build & externally pin if missing/unpinned when `auto_build=True`
            if auto_build:
                existing_pin = self._resolve_trusted_pin(
                    explicit_pin=expected_sha256,
                    env_var="KINTSUGI_NATIVE_DYLIB_SHA256",
                    manifest_field="dylib_sha256",
                    binary_path=self.expected_dylib_path,
                    requested_dylib=requested_dylib,
                    check_colocated_pin=False,
                )
                if not self.expected_dylib_path.is_file() or existing_pin is None:
                    if self.expected_dylib_path.is_file() and existing_pin is None:
                        self.expected_dylib_path.unlink()
                    build_verified_cdylib(
                        self.repo_root,
                        pin_manifest_path=self._explicit_pin_manifest_path,
                    )

            if not self.expected_dylib_path.is_file():
                self._reject_or_fallback("cdylib_absent")
                return

            # 3. Resolve trusted SHA-256 pin STRICTLY from explicit/env/external manifest BEFORE read+stage
            trusted_sha = self._resolve_trusted_pin(
                explicit_pin=expected_sha256,
                env_var="KINTSUGI_NATIVE_DYLIB_SHA256",
                manifest_field="dylib_sha256",
                binary_path=self.expected_dylib_path,
                requested_dylib=requested_dylib,
            )
            if trusted_sha is None:
                self._reject_or_fallback("missing_verified_sha256_pin")
                return

            # 4. Read ONCE via `O_RDONLY | O_NOFOLLOW`, verify SHA-256 in memory, then stage immutable `0o500` copy
            raw_bytes, actual_sha = _read_and_hash_regular_nofollow(self.expected_dylib_path)
            if not hmac.compare_digest(actual_sha, trusted_sha):
                raise PermissionError(
                    f"SECURITY_DYLIB_SHA256_MISMATCH: actual={actual_sha} != expected={trusted_sha}"
                )

            stage_dir, staged_dylib_path = _stage_verified_binary_bytes(
                raw_bytes,
                filename=self.expected_dylib_path.name,
                mode=0o500,
            )
            try:
                # 5. Load ONLY the private `0o500` staged path via `ctypes.CDLL` (eliminating TOCTOU)
                lib = ctypes.CDLL(str(staged_dylib_path))
                abi_fn = lib.kintsugi_abi_version
                abi_fn.argtypes = []
                abi_fn.restype = ctypes.c_uint32
                abi = int(abi_fn())
                if abi != EXPECTED_ABI_VERSION:
                    raise RuntimeError(f"INCOMPATIBLE_CDYLIB_ABI: got={abi}, expected={EXPECTED_ABI_VERSION}")
            except Exception:
                stage_dir.cleanup()
                raise

            self._stage_dirs.append(stage_dir)
            self._staged_dylib_path = staged_dylib_path
            self._configure_signatures(lib)
            self._lib = lib
            self.cdylib_loaded = True
            self.abi_version = abi
            self.dylib_sha256 = actual_sha
            self.fallback_reason = None
        except Exception as exc:
            self._reject_or_fallback(str(exc), exc=exc)

    def _load_verified_rust_bin(self, *, expected_rust_bin_sha256: Optional[str]) -> None:
        """Verify `kintsugi-rs` against an external SHA-256 pin and stage immutable `0o500` copy for fallback."""
        self.rust_bin = None
        self.rust_bin_sha256 = None
        cand = self._raw_rust_bin_candidate
        if cand is None or not cand.is_file():
            return
        try:
            trusted_sha = self._resolve_trusted_pin(
                explicit_pin=expected_rust_bin_sha256,
                env_var="KINTSUGI_RUST_BIN_SHA256",
                manifest_field="rust_bin_sha256",
                binary_path=cand,
            )
            if trusted_sha is None:
                self.fallback_reason = (
                    f"{self.fallback_reason}; rust_bin_unpinned" if self.fallback_reason else "rust_bin_unpinned"
                )
                return

            raw_bytes, actual_sha = _read_and_hash_regular_nofollow(cand)
            if not hmac.compare_digest(actual_sha, trusted_sha):
                raise PermissionError(
                    f"SECURITY_RUST_BIN_SHA256_MISMATCH: actual={actual_sha} != expected={trusted_sha}"
                )

            stage_dir, staged_rust_path = _stage_verified_binary_bytes(
                raw_bytes,
                filename="kintsugi-rs",
                mode=0o500,
            )
            self._stage_dirs.append(stage_dir)
            self.rust_bin = staged_rust_path
            self.rust_bin_sha256 = actual_sha
        except Exception as exc:
            self.rust_bin = None
            self.rust_bin_sha256 = None
            self.fallback_reason = f"{self.fallback_reason}; {exc}" if self.fallback_reason else str(exc)

    @staticmethod
    def _configure_signatures(lib: ctypes.CDLL) -> None:
        lib.kintsugi_sha256_v1.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
        ]
        lib.kintsugi_sha256_v1.restype = ctypes.c_int32

        lib.kintsugi_scan_buffer_v1.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.kintsugi_scan_buffer_v1.restype = ctypes.c_int32

        lib.kintsugi_rule_ir_eval_v1.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.kintsugi_rule_ir_eval_v1.restype = ctypes.c_int32

    @staticmethod
    def _c_u8_buf(raw: bytes) -> Tuple[Any, int]:
        if not raw:
            return None, 0
        arr = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
        return ctypes.cast(arr, ctypes.POINTER(ctypes.c_uint8)), len(raw)

    def sha256_hex(self, data: Union[str, ByteLike]) -> str:
        raw = _as_bytes(data)
        if self.cdylib_loaded and self._lib is not None:
            # Keep backing array alive across C call
            if raw:
                in_arr = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
                in_ptr = ctypes.cast(in_arr, ctypes.POINTER(ctypes.c_uint8))
            else:
                in_arr = None
                in_ptr = None
            out_arr = (ctypes.c_uint8 * 65)()
            rc = int(self._lib.kintsugi_sha256_v1(in_ptr, len(raw), out_arr, 65))
            _ = in_arr
            if rc != KINTSUGI_FFI_OK:
                raise RuntimeError(f"kintsugi_sha256_v1 failed with rc={rc}")
            return bytes(out_arr[:64]).decode("ascii")
        return hashlib.sha256(raw).hexdigest()

    def _require_staged_rust_bin(self) -> Path:
        if self.rust_bin is None or not self.rust_bin.is_file():
            raise FileNotFoundError("Neither verified cdylib nor verified pinned kintsugi-rs binary is available")
        assert_not_symlink(self.rust_bin)
        return self.rust_bin

    @staticmethod
    def _serialize_rule_ir(rule_ir: Any) -> str:
        if isinstance(rule_ir, str):
            return rule_ir
        if hasattr(rule_ir, "to_dict"):
            return json.dumps(rule_ir.to_dict(), ensure_ascii=False)
        return json.dumps(rule_ir, ensure_ascii=False)

    def scan_buffer(self, code: Union[str, ByteLike], *, language: str = "python") -> Dict[str, Any]:
        raw = _as_bytes(code)
        lang_b = language.strip().encode("utf-8") or b"python"

        if self.cdylib_loaded and self._lib is not None:
            in_arr = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw) if raw else None
            in_ptr = ctypes.cast(in_arr, ctypes.POINTER(ctypes.c_uint8)) if in_arr is not None else None
            lang_arr = (ctypes.c_uint8 * len(lang_b)).from_buffer_copy(lang_b)
            lang_ptr = ctypes.cast(lang_arr, ctypes.POINTER(ctypes.c_uint8))

            cap = max(8192, len(raw) // 2 + 4096)
            out_len = ctypes.c_size_t(0)
            for _attempt in range(3):
                out_arr = (ctypes.c_uint8 * cap)()
                rc = int(
                    self._lib.kintsugi_scan_buffer_v1(
                        in_ptr,
                        len(raw),
                        lang_ptr,
                        len(lang_b),
                        out_arr,
                        cap,
                        ctypes.byref(out_len),
                    )
                )
                if rc == KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL:
                    cap = max(cap * 2, int(out_len.value) + 64)
                    continue
                if rc != KINTSUGI_FFI_OK:
                    raise RuntimeError(f"kintsugi_scan_buffer_v1 failed with rc={rc}")
                _ = (in_arr, lang_arr)
                return json.loads(bytes(out_arr[: int(out_len.value)]).decode("utf-8"))
            raise RuntimeError("kintsugi_scan_buffer_v1 exceeded buffer growth attempts")

        rust_bin = self._require_staged_rust_bin()
        ext = _LANG_TO_EXT.get(language.strip().lower(), ".py")
        with tempfile.TemporaryDirectory(prefix="kintsugi_bridge_") as tmpdir:
            fname = "Dockerfile" if ext == ".dockerfile" else f"buffer{ext}"
            fpath = Path(tmpdir) / fname
            fpath.write_bytes(raw)
            proc = subprocess.run(
                [
                    str(rust_bin),
                    "scan",
                    str(fpath),
                    "--format",
                    "json",
                    "--min-severity",
                    "LOW",
                    "--fail-on",
                    "NONE",
                ],
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                timeout=15.0,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"kintsugi-rs scan fallback failed (rc={proc.returncode}): {proc.stderr.strip()}")
            res = json.loads(proc.stdout)
            res["bridge_backend"] = "subprocess_kintsugi_rs"
            return res

    def check_rule_ir(self, rule_ir: Any, *, strict_hash: bool = True) -> Dict[str, Any]:
        rule_json = self._serialize_rule_ir(rule_ir)

        if self.cdylib_loaded and self._lib is not None:
            return self.evaluate_rule_ir(rule_json, "", language="python")

        rust_bin = self._require_staged_rust_bin()
        argv = [str(rust_bin), "rule-ir-check", "-"]
        if strict_hash:
            argv.append("--strict-hash")
        proc = subprocess.run(
            argv,
            input=rule_json,
            capture_output=True,
            text=True,
            shell=False,
            check=False,
            timeout=10.0,
        )
        if proc.returncode != 0:
            raise ValueError(f"kintsugi-rs rule-ir-check failed: {proc.stderr.strip()}")
        return json.loads(proc.stdout)

    def evaluate_rule_ir(self, rule_ir: Any, code_text: str, *, language: str = "python") -> Dict[str, Any]:
        rule_json = self._serialize_rule_ir(rule_ir)

        rule_b = rule_json.encode("utf-8")
        code_b = code_text.encode("utf-8")
        lang_b = (language.strip() or "python").encode("utf-8")

        if self.cdylib_loaded and self._lib is not None:
            rule_arr = (ctypes.c_uint8 * len(rule_b)).from_buffer_copy(rule_b) if rule_b else None
            rule_ptr = ctypes.cast(rule_arr, ctypes.POINTER(ctypes.c_uint8)) if rule_arr is not None else None
            code_arr = (ctypes.c_uint8 * len(code_b)).from_buffer_copy(code_b) if code_b else None
            code_ptr = ctypes.cast(code_arr, ctypes.POINTER(ctypes.c_uint8)) if code_arr is not None else None
            lang_arr = (ctypes.c_uint8 * len(lang_b)).from_buffer_copy(lang_b)
            lang_ptr = ctypes.cast(lang_arr, ctypes.POINTER(ctypes.c_uint8))

            cap = 8192
            out_len = ctypes.c_size_t(0)
            for _attempt in range(3):
                out_arr = (ctypes.c_uint8 * cap)()
                rc = int(
                    self._lib.kintsugi_rule_ir_eval_v1(
                        rule_ptr,
                        len(rule_b),
                        code_ptr,
                        len(code_b),
                        lang_ptr,
                        len(lang_b),
                        out_arr,
                        cap,
                        ctypes.byref(out_len),
                    )
                )
                if rc == KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL:
                    cap = max(cap * 2, int(out_len.value) + 64)
                    continue
                if rc == KINTSUGI_FFI_ERR_RULE_INVALID:
                    raise ValueError("Invalid RuleIR/1 payload rejected by kintsugi_rule_ir_eval_v1")
                if rc != KINTSUGI_FFI_OK:
                    raise RuntimeError(f"kintsugi_rule_ir_eval_v1 failed with rc={rc}")
                _ = (rule_arr, code_arr, lang_arr)
                return json.loads(bytes(out_arr[: int(out_len.value)]).decode("utf-8"))
            raise RuntimeError("kintsugi_rule_ir_eval_v1 exceeded buffer growth attempts")

        rust_bin = self._require_staged_rust_bin()
        with tempfile.TemporaryDirectory(prefix="kintsugi_ir_") as tmpdir:
            rule_file = Path(tmpdir) / "rule.json"
            code_file = Path(tmpdir) / "code.txt"
            rule_file.write_text(rule_json, encoding="utf-8")
            code_file.write_text(code_text, encoding="utf-8")
            proc = subprocess.run(
                [
                    str(rust_bin),
                    "rule-ir-eval",
                    "--rule",
                    str(rule_file),
                    "--lang",
                    language,
                    str(code_file),
                ],
                capture_output=True,
                text=True,
                shell=False,
                check=False,
                timeout=10.0,
            )
            if proc.returncode != 0:
                raise ValueError(f"kintsugi-rs rule-ir-eval failed: {proc.stderr.strip()}")
            return json.loads(proc.stdout)
