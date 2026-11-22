"""Empirically Probed OS Sandbox (`kintsugi.forge.tool_sandbox`).

Enforces real OS-level confinement (macOS Seatbelt `sandbox-exec` or locked-down
Docker containers) and verifies confinement before every execution via 4 live
adversarial self-probes (`confined_rw_inside`, `deny_read_outside`,
`deny_write_outside`, and `deny_network_egress`).

Never treats Python `cwd`, `timeout`, `ulimit`, or hook filters as an OS sandbox.
When no OS-level isolation backend passes all 4 adversarial probes, `execute(...)`
fails closed with `ExecutionStatus.SANDBOX_UNAVAILABLE` and records
`SandboxReceipt(isolated=False, status="SANDBOX_UNAVAILABLE")`.
"""

from __future__ import annotations

import os
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import (
    ExecutionStatus,
    canonical_json_dumps,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.shield import TROJAN_UNICODE_RE, assert_not_symlink, resolve_safe_child_path
from kintsugi.process_tree import EXEC_TOKEN_NAME, new_execution_token, terminate_execution_tree

_DEFAULT_TIMEOUT_S = 15.0
_DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
_PROBE_EXIT_BLOCKED = 42

_C_PROBE_SOURCE = r"""
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int is_sandbox_denied(int err) {
    return err == EPERM || err == EACCES;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return 2;
    }
    const char *mode = argv[1];
    if (strcmp(mode, "rw_inside") == 0) {
        if (argc < 3) return 2;
        FILE *f = fopen(argv[2], "w");
        if (!f) return 10;
        if (fputs("kintsugi_probe_ok\n", f) < 0) {
            fclose(f);
            return 11;
        }
        fclose(f);
        f = fopen(argv[2], "r");
        if (!f) return 12;
        char buf[64];
        memset(buf, 0, sizeof(buf));
        if (!fgets(buf, sizeof(buf), f)) {
            fclose(f);
            return 13;
        }
        fclose(f);
        return strcmp(buf, "kintsugi_probe_ok\n") == 0 ? 0 : 14;
    }
    if (strcmp(mode, "read_outside") == 0) {
        if (argc < 3) return 2;
        FILE *f = fopen(argv[2], "r");
        if (f) {
            char buf[64];
            if (fgets(buf, sizeof(buf), f)) {
                fputs(buf, stdout);
            }
            fclose(f);
            return 0;
        }
        return is_sandbox_denied(errno) ? 42 : 43;
    }
    if (strcmp(mode, "write_outside") == 0) {
        if (argc < 3) return 2;
        FILE *f = fopen(argv[2], "w");
        if (f) {
            fputs("escaped\n", f);
            fclose(f);
            return 0;
        }
        return is_sandbox_denied(errno) ? 42 : 43;
    }
    if (strcmp(mode, "net_connect") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return is_sandbox_denied(errno) ? 42 : 44;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        if (inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr) != 1) {
            close(fd);
            return 45;
        }
        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        int err = errno;
        close(fd);
        if (rc == 0) {
            return 0;
        }
        return is_sandbox_denied(err) ? 42 : 46;
    }
    return 3;
}
"""

_PY_PROBE_SCRIPT = """
import errno, os, socket, sys
mode = sys.argv[1]
target = sys.argv[2] if len(sys.argv) > 2 else ""
if mode == "rw_inside":
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("kintsugi_probe_ok\\n")
    with open(target, "r", encoding="utf-8") as handle:
        data = handle.read()
    sys.exit(0 if data == "kintsugi_probe_ok\\n" else 14)
elif mode == "read_outside":
    try:
        with open(target, "r", encoding="utf-8") as handle:
            sys.stdout.write(handle.read())
        sys.exit(0)
    except PermissionError:
        sys.exit(42)
    except OSError as exc:
        sys.exit(42 if exc.errno in (errno.EPERM, errno.EACCES) else 43)
elif mode == "write_outside":
    try:
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("escaped\\n")
        sys.exit(0)
    except PermissionError:
        sys.exit(42)
    except OSError as exc:
        sys.exit(42 if exc.errno in (errno.EPERM, errno.EACCES) else 43)
elif mode == "net_connect":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    try:
        sock.connect(("1.1.1.1", 80))
        sys.exit(0)
    except PermissionError:
        sys.exit(42)
    except OSError as exc:
        sys.exit(42 if exc.errno in (errno.EPERM, errno.EACCES) else 46)
    finally:
        sock.close()
sys.exit(3)
"""


def _validate_sbpl_safe_path(path_obj: Path) -> str:
    """Validate resolved path contains no SBPL delimiter, NUL, or Trojan Unicode characters."""
    raw = str(path_obj)
    if not raw or "\x00" in raw or TROJAN_UNICODE_RE.search(raw):
        raise PermissionError("SECURITY_INVALID_SANDBOX_PATH: NUL or Trojan Unicode detected.")
    for bad in ('"', "(", ")", ";", "\n", "\r", "\\"):
        if bad in raw:
            raise PermissionError(f"SECURITY_INVALID_SANDBOX_PATH: forbidden SBPL character {bad!r} in path.")
    return raw


def _is_path_within(candidate: Path, base: Path) -> bool:
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _decode_capped_utf8(raw: bytes, max_bytes: int) -> str:
    """Decode up to `max_bytes` of UTF-8 bytes without expanding trailing replacement chars past the cap."""
    cap = max(0, int(max_bytes))
    if cap == 0 or not raw:
        return ""
    trimmed = raw[:cap]
    decoded = trimmed.decode("utf-8", errors="replace")
    encoded = decoded.encode("utf-8", errors="replace")
    if len(encoded) > cap:
        decoded = encoded[:cap].decode("utf-8", errors="ignore")
    return decoded


def _close_stream_quietly(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except OSError as _close_err:
        _ = _close_err


def _kill_process_group(proc: subprocess.Popen[bytes], execution_token: str = "") -> None:
    if execution_token:
        terminate_execution_tree(proc.pid, execution_token)
        return
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError) as _killpg_err:
        _ = _killpg_err
        if proc.poll() is None:
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError, OSError) as _kill_err:
                _ = _kill_err


def run_subprocess_streaming_bounded(
    argv: Sequence[str],
    *,
    cwd: Union[str, Path],
    env: Optional[Mapping[str, str]] = None,
    stdin_bytes: Optional[bytes] = None,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
) -> Tuple[int, bytes, bytes, bool, bool]:
    """Execute a subprocess (`shell=False`) with non-blocking streaming bounded pipes and SIGKILL process-group timeout."""
    cleaned_argv = _validate_argv(argv)
    eff_timeout = max(0.01, float(timeout_s))
    cap = max(0, int(max_output_bytes))
    stdin_mode = subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL
    env_dict = dict(env) if env is not None else dict(os.environ)
    execution_token = new_execution_token()
    env_dict[EXEC_TOKEN_NAME] = execution_token

    proc = subprocess.Popen(
        list(cleaned_argv),
        cwd=str(cwd),
        env=env_dict,
        stdin=stdin_mode,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )

    out_buf = bytearray()
    err_buf = bytearray()
    timed_out = False
    truncated = False
    stdin_view = memoryview(stdin_bytes) if stdin_bytes is not None else None
    stdin_offset = 0
    selector = selectors.DefaultSelector()

    try:
        if proc.stdin is not None:
            if stdin_bytes is None or len(stdin_bytes) == 0:
                _close_stream_quietly(proc.stdin)
            else:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, data=("in", None))

        if proc.stdout is not None:
            os.set_blocking(proc.stdout.fileno(), False)
            selector.register(proc.stdout, selectors.EVENT_READ, data=("out", out_buf))

        if proc.stderr is not None:
            os.set_blocking(proc.stderr.fileno(), False)
            selector.register(proc.stderr, selectors.EVENT_READ, data=("err", err_buf))

        deadline = time.monotonic() + eff_timeout
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
                kind, target_buf = key.data
                if kind == "in":
                    if stdin_view is None or stdin_offset >= len(stdin_view):
                        try:
                            selector.unregister(key.fileobj)
                        except (KeyError, ValueError) as _unreg_err:
                            _ = _unreg_err
                        _close_stream_quietly(key.fileobj)
                        continue
                    try:
                        written = os.write(key.fd, stdin_view[stdin_offset : stdin_offset + 65536])
                        if written > 0:
                            stdin_offset += written
                        if stdin_offset >= len(stdin_view):
                            selector.unregister(key.fileobj)
                            _close_stream_quietly(key.fileobj)
                    except BlockingIOError as _bio_err:
                        _ = _bio_err
                    except (BrokenPipeError, OSError) as _in_err:
                        _ = _in_err
                        try:
                            selector.unregister(key.fileobj)
                        except (KeyError, ValueError) as _unreg_err:
                            _ = _unreg_err
                        _close_stream_quietly(key.fileobj)
                else:
                    try:
                        chunk = os.read(key.fd, 8192)
                    except BlockingIOError as _bio_err:
                        _ = _bio_err
                        continue
                    except OSError as _read_err:
                        _ = _read_err
                        try:
                            selector.unregister(key.fileobj)
                        except (KeyError, ValueError) as _unreg_err:
                            _ = _unreg_err
                        _close_stream_quietly(key.fileobj)
                        continue
                    if not chunk:
                        try:
                            selector.unregister(key.fileobj)
                        except (KeyError, ValueError) as _unreg_err:
                            _ = _unreg_err
                        _close_stream_quietly(key.fileobj)
                        continue
                    assert isinstance(target_buf, bytearray)
                    if len(target_buf) < cap:
                        take = min(len(chunk), cap - len(target_buf))
                        target_buf.extend(chunk[:take])
                        if take < len(chunk):
                            truncated = True
                    else:
                        truncated = True

        if timed_out:
            _kill_process_group(proc, execution_token)
            proc.wait()
            return -1, bytes(out_buf), bytes(err_buf), True, truncated

        remaining_wait = max(0.01, deadline - time.monotonic())
        try:
            exit_code = int(proc.wait(timeout=remaining_wait))
        except subprocess.TimeoutExpired:
            _kill_process_group(proc, execution_token)
            proc.wait()
            return -1, bytes(out_buf), bytes(err_buf), True, truncated
        return exit_code, bytes(out_buf), bytes(err_buf), False, truncated
    finally:
        for key in list(selector.get_map().values()):
            try:
                selector.unregister(key.fileobj)
            except (KeyError, ValueError) as _unreg_err:
                _ = _unreg_err
            _close_stream_quietly(key.fileobj)
        try:
            selector.close()
        except OSError as _sel_err:
            _ = _sel_err
        _close_stream_quietly(proc.stdin)
        _close_stream_quietly(proc.stdout)
        _close_stream_quietly(proc.stderr)
        if proc.poll() is None:
            _kill_process_group(proc, execution_token)
            try:
                proc.wait(timeout=1.0)
            except (OSError, subprocess.SubprocessError) as _wait_err:
                _ = _wait_err


def _validate_argv(argv: Sequence[str]) -> List[str]:
    if not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("INVALID_ARGV: expected non-empty command sequence.")
    cleaned: List[str] = []
    for token in argv:
        if not isinstance(token, str) or not token or "\x00" in token or TROJAN_UNICODE_RE.search(token):
            raise ValueError("INVALID_ARGV_TOKEN: empty, NUL, non-string, or Trojan Unicode token.")
        cleaned.append(token)
    return cleaned


def _resolve_clang_toolchain() -> Tuple[Optional[str], Optional[str], str]:
    """Locate CLT or system clang, optional macOS SDK root, and version string."""
    clang_bin: Optional[str] = None
    sdk_path: Optional[str] = None
    xcrun = shutil.which("xcrun")
    if sys.platform == "darwin" and xcrun:
        try:
            res_cc = subprocess.run(
                [xcrun, "--find", "clang"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res_cc.returncode == 0 and res_cc.stdout.strip():
                cand = res_cc.stdout.strip()
                if Path(cand).exists():
                    clang_bin = cand
            res_sdk = subprocess.run(
                [xcrun, "--show-sdk-path"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if res_sdk.returncode == 0 and res_sdk.stdout.strip():
                sdk_cand = res_sdk.stdout.strip()
                if Path(sdk_cand).exists():
                    sdk_path = sdk_cand
        except (OSError, subprocess.SubprocessError):
            clang_bin = None

    if clang_bin is None:
        clt_clang = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        if clt_clang.exists():
            clang_bin = str(clt_clang)
        else:
            clang_bin = shutil.which("clang")

    version_str = "unknown"
    if clang_bin:
        try:
            ver_res = subprocess.run(
                [clang_bin, "--version"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            first_line = (ver_res.stdout or "").splitlines()[0].strip() if ver_res.stdout else ""
            if first_line:
                version_str = first_line[:120]
        except (OSError, subprocess.SubprocessError):
            version_str = "unknown"

    return clang_bin, sdk_path, version_str


def build_seatbelt_profile(sandbox_ws: Path) -> str:
    """Build the strict macOS Seatbelt SBPL profile confined exclusively to `sandbox_ws`."""
    assert_not_symlink(sandbox_ws)
    resolved_ws = sandbox_ws.resolve()
    ws_str = _validate_sbpl_safe_path(resolved_ws)
    return (
        "(version 1)\n"
        "(deny default)\n"
        '(import "system.sb")\n'
        "(allow process-exec* process-fork)\n"
        "(allow file-read-metadata)\n"
        f'(allow file-read* file-write* (subpath "{ws_str}"))\n'
        "(allow file-read*\n"
        '    (subpath "/Library/Developer/CommandLineTools")\n'
        '    (subpath "/opt/homebrew")\n'
        '    (subpath "/usr")\n'
        '    (subpath "/System")\n'
        '    (subpath "/Library/Frameworks")\n'
        '    (subpath "/Library/Apple")\n'
        '    (subpath "/bin")\n'
        '    (subpath "/dev"))\n'
        "(deny network*)\n"
    )


@dataclass(frozen=True)
class SandboxProbeCheck:
    """Outcome of a single live adversarial sandbox probe."""

    name: str
    passed: bool
    exit_code: int
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "detail": redact_secrets_in_text(self.detail),
        }


@dataclass(frozen=True)
class SandboxProbeReport:
    """Aggregated verdict across all 4 mandatory adversarial isolation probes."""

    all_passed: bool
    backend: str
    profile_hash: str
    checks: Dict[str, SandboxProbeCheck] = field(default_factory=dict)
    reason: str = ""
    probed_at_monotonic_ms: float = 0.0
    schema: str = "SandboxProbeReport/1"

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "all_passed": self.all_passed,
                "backend": self.backend,
                "profile_hash": self.profile_hash,
                "reason": self.reason,
                "checks": {k: v.to_dict() for k, v in sorted(self.checks.items())},
            }
        )


@dataclass
class SandboxReceipt:
    """Cryptographically bound receipt of real OS isolation enforcement (`SandboxReceipt/1`)."""

    isolated: bool
    status: str
    passed: bool = False
    backend: str = "none"
    sandbox_workspace_hash: str = ""
    profile_hash: str = ""
    environment_hash: str = ""
    exit_code: int = -1
    timed_out: bool = False
    wall_time_ms: float = 0.0
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    probe_summary: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    schema: str = "SandboxReceipt/1"

    def __post_init__(self) -> None:
        self.isolated = bool(self.isolated)
        self.status = validate_safe_text(self.status, field_name="status").upper()
        self.passed = bool(self.passed)
        if not self.isolated and self.status != ExecutionStatus.SANDBOX_UNAVAILABLE.value:
            raise ValueError("INVALID_SANDBOX_RECEIPT: non-isolated receipt must report SANDBOX_UNAVAILABLE.")
        if not self.isolated and self.passed:
            raise ValueError("INVALID_SANDBOX_RECEIPT: non-isolated receipt cannot have passed=True.")

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "isolated": self.isolated,
                "status": self.status,
                "passed": self.passed,
                "backend": self.backend,
                "sandbox_workspace_hash": self.sandbox_workspace_hash,
                "profile_hash": self.profile_hash,
                "environment_hash": self.environment_hash,
                "exit_code": self.exit_code,
                "timed_out": self.timed_out,
                "wall_time_ms": round(self.wall_time_ms, 3),
                "stdout_excerpt": redact_secrets_in_text(self.stdout_excerpt, redact_paths=True)[:1024],
                "stderr_excerpt": redact_secrets_in_text(self.stderr_excerpt, redact_paths=True)[:1024],
                "probe_summary": dict(self.probe_summary),
                "reason": redact_secrets_in_text(self.reason),
            }
        )


@dataclass
class SandboxExecutionResult:
    """Result returned by `ToolSandbox.execute` carrying full output and `SandboxReceipt`."""

    execution_status: ExecutionStatus
    receipt: SandboxReceipt
    exit_code: int
    stdout: str
    stderr: str
    wall_time_ms: float
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return self.execution_status == ExecutionStatus.PASS and self.receipt.isolated

    @property
    def status(self) -> ExecutionStatus:
        return self.execution_status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_status": self.execution_status.value,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "wall_time_ms": round(self.wall_time_ms, 3),
            "receipt": self.receipt.to_dict(),
        }


class ToolSandbox:
    """Empirically verified OS-level sandbox (`sandbox-exec` on macOS or Docker).

    All 4 live adversarial probes MUST pass before any command or compiled binary
    is permitted to execute inside the sandbox.
    """

    def __init__(
        self,
        workspace_dir: Union[str, Path],
        *,
        backend: str = "auto",
        docker_image: Optional[str] = None,
        force_unavailable: bool = False,
        default_timeout_s: float = _DEFAULT_TIMEOUT_S,
        max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    ) -> None:
        raw_ws = Path(str(workspace_dir))
        assert_not_symlink(raw_ws)
        raw_ws.mkdir(parents=True, exist_ok=True)
        os.chmod(raw_ws, 0o700)
        assert_not_symlink(raw_ws)
        self.workspace_root: Path = raw_ws.resolve()
        _validate_sbpl_safe_path(self.workspace_root)
        self._tmp_dir: Path = self.workspace_root / ".sandbox_tmp"
        assert_not_symlink(self._tmp_dir)
        self._tmp_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self._tmp_dir, 0o700)

        norm_backend = str(backend or "auto").strip().lower()
        if norm_backend not in {"auto", "seatbelt", "docker"}:
            raise ValueError(f"UNSUPPORTED_SANDBOX_BACKEND: {backend!r}")
        self._requested_backend = norm_backend
        self._docker_image = str(docker_image).strip() if docker_image else None
        self._force_unavailable = bool(force_unavailable)
        self._default_timeout_s = max(0.1, float(default_timeout_s))
        self._max_output_bytes = max(1024, int(max_output_bytes))
        self._probe_report: Optional[SandboxProbeReport] = None
        self._verified_backend: Optional[str] = None

    @property
    def is_ready(self) -> bool:
        """Return True only when all 4 adversarial OS isolation probes have passed."""
        return bool(self._probe_report is not None and self._probe_report.all_passed)

    @property
    def last_probe_report(self) -> Optional[SandboxProbeReport]:
        return self._probe_report

    def seatbelt_profile(self) -> str:
        """Return the exact macOS Seatbelt SBPL profile confined to `self.workspace_root`."""
        return build_seatbelt_profile(self.workspace_root)

    def _select_candidate_backend(self) -> Tuple[str, str]:
        if self._force_unavailable:
            return "none", "SANDBOX_FORCE_UNAVAILABLE"

        seatbelt_bin = Path("/usr/bin/sandbox-exec")
        if self._requested_backend == "seatbelt":
            if sys.platform == "darwin" and seatbelt_bin.exists():
                return "seatbelt", ""
            return "none", "SEATBELT_UNAVAILABLE_ON_HOST"

        if self._requested_backend == "docker":
            return self._check_docker_available()

        # Auto selection: prefer native macOS Seatbelt on darwin, then Docker if configured.
        if sys.platform == "darwin" and seatbelt_bin.exists():
            return "seatbelt", ""
        return self._check_docker_available()

    def _check_docker_available(self) -> Tuple[str, str]:
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return "none", "DOCKER_CLI_NOT_FOUND"
        if not self._docker_image:
            return "none", "DOCKER_IMAGE_NOT_CONFIGURED"
        try:
            info = subprocess.run(
                [docker_bin, "info"],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if info.returncode != 0:
                return "none", "DOCKER_DAEMON_UNAVAILABLE"
            inspect = subprocess.run(
                [docker_bin, "image", "inspect", self._docker_image],
                shell=False,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            if inspect.returncode != 0:
                return "none", f"DOCKER_IMAGE_MISSING:{self._docker_image}"
            return "docker", ""
        except (OSError, subprocess.SubprocessError) as exc:
            return "none", f"DOCKER_PROBE_ERROR:{exc}"

    def _policy_profile_hash(self, backend: str) -> str:
        if backend == "seatbelt":
            return sha256_digest({"backend": "seatbelt", "profile": self.seatbelt_profile()})
        if backend == "docker":
            return sha256_digest(
                {
                    "backend": "docker",
                    "image": self._docker_image or "",
                    "network": "none",
                    "read_only": True,
                    "cap_drop": "ALL",
                    "workspace": str(self.workspace_root),
                }
            )
        return sha256_digest({"backend": "none", "workspace": str(self.workspace_root)})

    def _environment_hash(self, backend: str) -> str:
        return sha256_digest(
            {
                "platform": sys.platform,
                "arch": platform.machine(),
                "backend": backend,
                "profile_hash": self._policy_profile_hash(backend),
                "workspace_hash": sha256_digest(str(self.workspace_root)),
            }
        )

    def _build_clean_env(self, env_overrides: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
        env: Dict[str, str] = {
            "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/Library/Developer/CommandLineTools/usr/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": str(self._tmp_dir),
            "HOME": str(self.workspace_root),
        }
        if env_overrides:
            for k, v in env_overrides.items():
                key_s = validate_safe_text(str(k), field_name="env_key")
                val_s = str(v)
                if "\x00" in val_s or TROJAN_UNICODE_RE.search(val_s):
                    raise ValueError(f"INVALID_ENV_VALUE: unsafe characters in '{key_s}'.")
                env[key_s] = val_s
        return env

    def _wrap_command_for_backend(
        self,
        backend: str,
        argv: Sequence[str],
        cwd: Path,
    ) -> List[str]:
        if backend == "seatbelt":
            return ["/usr/bin/sandbox-exec", "-p", self.seatbelt_profile(), *argv]
        if backend == "docker":
            docker_bin = shutil.which("docker") or "docker"
            if not self._docker_image:
                raise RuntimeError("DOCKER_IMAGE_NOT_CONFIGURED")
            return [
                docker_bin,
                "run",
                "--rm",
                "--init",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--pids-limit=64",
                "--memory=256m",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m",
                "-v",
                f"{self.workspace_root}:{self.workspace_root}:rw",
                "-w",
                str(cwd),
                self._docker_image,
                *argv,
            ]
        raise RuntimeError(f"NO_ACTIVE_SANDBOX_BACKEND:{backend}")

    def _run_raw_confined(
        self,
        backend: str,
        argv: Sequence[str],
        *,
        cwd: Path,
        stdin_bytes: Optional[bytes] = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        env_overrides: Optional[Mapping[str, str]] = None,
        max_output_bytes: Optional[int] = None,
    ) -> Tuple[int, str, str, bool, float]:
        wrapped = self._wrap_command_for_backend(backend, argv, cwd)
        clean_env = self._build_clean_env(env_overrides)
        eff_max_output = max(1, int(max_output_bytes if max_output_bytes is not None else self._max_output_bytes))
        t0 = time.perf_counter()
        exit_code, raw_out, raw_err, timed_out, _truncated = run_subprocess_streaming_bounded(
            wrapped,
            cwd=cwd,
            env=clean_env,
            stdin_bytes=stdin_bytes,
            timeout_s=timeout_s,
            max_output_bytes=eff_max_output,
        )
        wall_ms = (time.perf_counter() - t0) * 1000.0
        if timed_out and not raw_err:
            raw_err = b"SANDBOX_EXECUTION_TIMED_OUT"
        out_str = _decode_capped_utf8(raw_out, eff_max_output)
        err_str = _decode_capped_utf8(raw_err, eff_max_output)
        return exit_code, out_str, err_str, timed_out, wall_ms

    def _create_disjoint_outside_dir(self) -> Path:
        outside = Path(tempfile.mkdtemp(prefix="kintsugi_sb_outside_")).resolve()
        if _is_path_within(outside, self.workspace_root) or _is_path_within(self.workspace_root, outside):
            shutil.rmtree(outside, ignore_errors=True)
            alt_base = Path("/private/tmp") if Path("/private/tmp").exists() else None
            outside = Path(tempfile.mkdtemp(prefix="kintsugi_sb_outside_", dir=str(alt_base) if alt_base else None)).resolve()
            if _is_path_within(outside, self.workspace_root) or _is_path_within(self.workspace_root, outside):
                shutil.rmtree(outside, ignore_errors=True)
                raise RuntimeError("CANNOT_CREATE_DISJOINT_OUTSIDE_PROBE_DIR")
        return outside

    def _prepare_probe_command(self, backend: str, probe_dir: Path) -> Tuple[List[str], str]:
        if backend == "seatbelt":
            clang_bin, sdk_path, _ = _resolve_clang_toolchain()
            if clang_bin:
                c_src = probe_dir / "probe.c"
                c_bin = probe_dir / "probe_bin"
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(str(c_src), flags, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(_C_PROBE_SOURCE)
                cmd = [clang_bin, "-O2", "-std=c99"]
                if sdk_path:
                    cmd.extend(["-isysroot", sdk_path])
                cmd.extend(["-o", str(c_bin), str(c_src)])
                comp_res = subprocess.run(
                    cmd,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                    env=self._build_clean_env(),
                )
                if comp_res.returncode == 0 and c_bin.exists():
                    os.chmod(c_bin, 0o700)
                    return [str(c_bin)], "c_binary"

            probe_py = probe_dir / "probe.py"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(str(probe_py), flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(_PY_PROBE_SCRIPT)
            return [sys.executable, "-I", str(probe_py)], "python_isolated"

        # Docker probes use python3 inside container (if available) or fail cleanly.
        probe_py = probe_dir / "probe.py"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(probe_py), flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_PY_PROBE_SCRIPT)
        return ["python3", "-I", str(probe_py)], "docker_python"

    def probe_isolation(self, *, force_reprobe: bool = False) -> SandboxProbeReport:
        """Execute 4 live adversarial isolation probes before marking the sandbox ready.

        Checks:
          1. `confined_rw_inside`: reading & writing inside `workspace_root` succeeds.
          2. `deny_read_outside`: reading an outside secret file fails (`EPERM`/`EACCES`).
          3. `deny_write_outside`: writing outside `workspace_root` fails (`EPERM`/`EACCES`).
          4. `deny_network_egress`: outbound TCP `connect(('1.1.1.1', 80))` fails (`EPERM`/`EACCES`).
        """
        if not force_reprobe and self._probe_report is not None and not self._force_unavailable:
            return self._probe_report

        backend, init_reason = self._select_candidate_backend()
        profile_hash = self._policy_profile_hash(backend)
        if backend == "none":
            report = SandboxProbeReport(
                all_passed=False,
                backend="none",
                profile_hash=profile_hash,
                checks={},
                reason=init_reason or "SANDBOX_UNAVAILABLE",
                probed_at_monotonic_ms=round(time.monotonic() * 1000.0, 3),
            )
            self._probe_report = report
            self._verified_backend = None
            return report

        probe_dir = Path(tempfile.mkdtemp(prefix=".probe_", dir=str(self.workspace_root))).resolve()
        outside_dir: Optional[Path] = None
        checks: Dict[str, SandboxProbeCheck] = {}
        try:
            os.chmod(probe_dir, 0o700)
            outside_dir = self._create_disjoint_outside_dir()
            secret_file = outside_dir / "outside_secret.txt"
            canary = "KINTSUGI_OUTSIDE_SECRET_CANARY_9821"
            secret_file.write_text(canary, encoding="utf-8")
            os.chmod(secret_file, 0o644)
            outside_write_target = outside_dir / "outside_escape.txt"
            inside_rw_target = probe_dir / "inside_rw.txt"

            base_cmd, probe_kind = self._prepare_probe_command(backend, probe_dir)

            # 1. Confined read/write inside sandbox succeeds
            rc1, out1, err1, to1, _ = self._run_raw_confined(
                backend, [*base_cmd, "rw_inside", str(inside_rw_target)], cwd=probe_dir, timeout_s=8.0
            )
            checks["confined_rw_inside"] = SandboxProbeCheck(
                name="confined_rw_inside",
                passed=(rc1 == 0 and not to1 and inside_rw_target.exists()),
                exit_code=rc1,
                detail=f"kind={probe_kind} rc={rc1} err={err1.strip()[:120]}",
            )

            # 2. Reading outside-sandbox secret file MUST fail with EPERM/EACCES
            rc2, out2, err2, to2, _ = self._run_raw_confined(
                backend, [*base_cmd, "read_outside", str(secret_file)], cwd=probe_dir, timeout_s=8.0
            )
            checks["deny_read_outside"] = SandboxProbeCheck(
                name="deny_read_outside",
                passed=(rc2 == _PROBE_EXIT_BLOCKED and not to2 and canary not in out2 and canary not in err2),
                exit_code=rc2,
                detail=f"kind={probe_kind} rc={rc2} blocked={rc2 == _PROBE_EXIT_BLOCKED}",
            )

            # 3. Writing outside-sandbox path MUST fail with EPERM/EACCES and create nothing
            rc3, _out3, _err3, to3, _ = self._run_raw_confined(
                backend, [*base_cmd, "write_outside", str(outside_write_target)], cwd=probe_dir, timeout_s=8.0
            )
            checks["deny_write_outside"] = SandboxProbeCheck(
                name="deny_write_outside",
                passed=(rc3 == _PROBE_EXIT_BLOCKED and not to3 and not outside_write_target.exists()),
                exit_code=rc3,
                detail=f"kind={probe_kind} rc={rc3} blocked={rc3 == _PROBE_EXIT_BLOCKED}",
            )

            # 4. Outbound socket connect(('1.1.1.1', 80)) MUST fail with EPERM/EACCES
            rc4, _out4, _err4, to4, _ = self._run_raw_confined(
                backend, [*base_cmd, "net_connect", "1.1.1.1:80"], cwd=probe_dir, timeout_s=8.0
            )
            checks["deny_network_egress"] = SandboxProbeCheck(
                name="deny_network_egress",
                passed=(rc4 == _PROBE_EXIT_BLOCKED and not to4),
                exit_code=rc4,
                detail=f"kind={probe_kind} rc={rc4} blocked={rc4 == _PROBE_EXIT_BLOCKED}",
            )

            all_ok = len(checks) == 4 and all(c.passed for c in checks.values())
            failed_names = [k for k, c in checks.items() if not c.passed]
            report = SandboxProbeReport(
                all_passed=all_ok,
                backend=backend if all_ok else "none",
                profile_hash=profile_hash,
                checks=checks,
                reason="ISOLATION_VERIFIED" if all_ok else f"PROBE_FAILED:{','.join(failed_names)}",
                probed_at_monotonic_ms=round(time.monotonic() * 1000.0, 3),
            )
            self._probe_report = report
            self._verified_backend = backend if all_ok else None
            return report
        finally:
            shutil.rmtree(probe_dir, ignore_errors=True)
            if outside_dir is not None:
                shutil.rmtree(outside_dir, ignore_errors=True)

    def _confine_cwd(self, cwd: Optional[Union[str, Path]]) -> Path:
        if cwd is None:
            return self.workspace_root
        raw = str(cwd)
        if not raw or "\x00" in raw or TROJAN_UNICODE_RE.search(raw):
            raise PermissionError("SECURITY_INVALID_CWD")
        cand = Path(raw)
        assert_not_symlink(cand)
        if cand.is_absolute():
            resolved = cand.resolve()
            if not _is_path_within(resolved, self.workspace_root):
                raise PermissionError(f"SECURITY_CWD_OUTSIDE_SANDBOX: {cand}")
            return resolved
        safe = resolve_safe_child_path(self.workspace_root, raw)
        if safe is None:
            raise PermissionError(f"SECURITY_CWD_ESCAPE: {raw}")
        assert_not_symlink(safe)
        return safe

    def execute(
        self,
        argv: Sequence[str],
        *,
        stdin_data: Optional[Union[str, bytes]] = None,
        timeout_s: Optional[float] = None,
        env_overrides: Optional[Mapping[str, str]] = None,
        cwd: Optional[Union[str, Path]] = None,
        max_output_bytes: Optional[int] = None,
    ) -> SandboxExecutionResult:
        """Execute `argv` strictly inside the verified OS sandbox (`shell=False`).

        Returns `ExecutionStatus.SANDBOX_UNAVAILABLE` and records
        `SandboxReceipt(isolated=False, status="SANDBOX_UNAVAILABLE")` whenever
        live OS isolation fails or is unavailable.
        """
        cleaned_argv = _validate_argv(argv)
        probe = self.probe_isolation()
        ws_hash = sha256_digest(str(self.workspace_root))
        probe_summary = {k: v.passed for k, v in sorted(probe.checks.items())}

        if not probe.all_passed or not self._verified_backend:
            receipt = SandboxReceipt(
                isolated=False,
                status=ExecutionStatus.SANDBOX_UNAVAILABLE.value,
                passed=False,
                backend="none",
                sandbox_workspace_hash=ws_hash,
                profile_hash=probe.profile_hash,
                environment_hash=self._environment_hash("none"),
                exit_code=-1,
                timed_out=False,
                wall_time_ms=0.0,
                stdout_excerpt="",
                stderr_excerpt="",
                probe_summary=probe_summary,
                reason=probe.reason or "SANDBOX_UNAVAILABLE",
            )
            return SandboxExecutionResult(
                execution_status=ExecutionStatus.SANDBOX_UNAVAILABLE,
                receipt=receipt,
                exit_code=-1,
                stdout="",
                stderr="",
                wall_time_ms=0.0,
                timed_out=False,
            )

        effective_cwd = self._confine_cwd(cwd)
        stdin_bytes: Optional[bytes]
        if stdin_data is None:
            stdin_bytes = None
        elif isinstance(stdin_data, bytes):
            stdin_bytes = stdin_data
        else:
            stdin_bytes = str(stdin_data).encode("utf-8")

        eff_timeout = max(0.05, float(timeout_s if timeout_s is not None else self._default_timeout_s))
        eff_max_output = max(1, int(max_output_bytes if max_output_bytes is not None else self._max_output_bytes))
        backend = self._verified_backend
        exit_code, out_str, err_str, timed_out, wall_ms = self._run_raw_confined(
            backend,
            cleaned_argv,
            cwd=effective_cwd,
            stdin_bytes=stdin_bytes,
            timeout_s=eff_timeout,
            env_overrides=env_overrides,
            max_output_bytes=eff_max_output,
        )

        passed = (not timed_out) and (exit_code == 0)
        exec_status = ExecutionStatus.PASS if passed else ExecutionStatus.FAIL
        receipt = SandboxReceipt(
            isolated=True,
            status=exec_status.value,
            passed=passed,
            backend=backend,
            sandbox_workspace_hash=ws_hash,
            profile_hash=probe.profile_hash,
            environment_hash=self._environment_hash(backend),
            exit_code=exit_code,
            timed_out=timed_out,
            wall_time_ms=wall_ms,
            stdout_excerpt=out_str[:1024],
            stderr_excerpt=err_str[:1024],
            probe_summary=probe_summary,
            reason="PASS" if passed else ("EXECUTION_TIMED_OUT" if timed_out else f"EXIT_CODE:{exit_code}"),
        )
        return SandboxExecutionResult(
            execution_status=exec_status,
            receipt=receipt,
            exit_code=exit_code,
            stdout=out_str,
            stderr=err_str,
            wall_time_ms=wall_ms,
            timed_out=timed_out,
        )

    def compile_c(
        self,
        source_path: Union[str, Path],
        output_path: Union[str, Path],
        *,
        flags: Sequence[str] = ("-O2", "-std=c99", "-Wall", "-Wextra", "-Werror"),
        timeout_s: float = 20.0,
    ) -> Tuple[SandboxExecutionResult, str, str, List[str]]:
        """Compile a confined C99 source file strictly inside the verified OS sandbox."""
        src = self._confine_cwd(Path(source_path).parent) / Path(source_path).name
        out = self._confine_cwd(Path(output_path).parent) / Path(output_path).name
        assert_not_symlink(src)
        assert_not_symlink(out)
        if not src.exists():
            raise FileNotFoundError(f"SOURCE_NOT_FOUND: {src}")

        clang_bin, sdk_path, clang_version = _resolve_clang_toolchain()
        if not clang_bin:
            probe = self.probe_isolation()
            receipt = SandboxReceipt(
                isolated=False,
                status=ExecutionStatus.SANDBOX_UNAVAILABLE.value,
                passed=False,
                backend="none",
                sandbox_workspace_hash=sha256_digest(str(self.workspace_root)),
                profile_hash=probe.profile_hash,
                environment_hash=self._environment_hash("none"),
                exit_code=-1,
                reason="CLANG_COMPILER_NOT_FOUND",
            )
            return (
                SandboxExecutionResult(
                    execution_status=ExecutionStatus.SANDBOX_UNAVAILABLE,
                    receipt=receipt,
                    exit_code=-1,
                    stdout="",
                    stderr="CLANG_COMPILER_NOT_FOUND",
                    wall_time_ms=0.0,
                ),
                "clang",
                "unavailable",
                list(flags),
            )

        effective_flags = [validate_safe_text(str(f), field_name="compiler_flag") for f in flags]
        argv: List[str] = [clang_bin, *effective_flags]
        if sdk_path and sys.platform == "darwin":
            argv.extend(["-isysroot", sdk_path])
        argv.extend(["-o", str(out), str(src)])

        res = self.execute(argv, timeout_s=timeout_s, cwd=src.parent)
        if res.passed and out.exists():
            assert_not_symlink(out)
            os.chmod(out, 0o500)
        return res, "clang", clang_version, effective_flags

    def receipt_canonical_json(self, receipt: SandboxReceipt) -> str:
        """Serialize `receipt` deterministically using canonical JSON."""
        return canonical_json_dumps(receipt.to_dict())


__all__ = [
    "SandboxProbeCheck",
    "SandboxProbeReport",
    "SandboxReceipt",
    "SandboxExecutionResult",
    "ToolSandbox",
    "build_seatbelt_profile",
    "run_subprocess_streaming_bounded",
]
