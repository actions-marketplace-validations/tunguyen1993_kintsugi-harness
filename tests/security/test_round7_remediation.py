"""Independent regression probes for Build #2 Round-7 security & liveness fixes (R6 audit closure)."""

from __future__ import annotations

import builtins
import json
import math
import mmap
import os
import posixpath
import signal
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from typing import Any, Dict

from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    compute_tool_spec_security_digest,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.runtime import (
    SecureRunner,
    compute_callable_sha256,
    probe_linux_landlock_available,
    validate_trusted_host_callable_hygiene,
)
from kintsugi.runtime.secure_runner import _sanitize_child_fds
from kintsugi.tools.log_forge import LogForge

try:
    from fixture_attestation import sign_fixture_tool
except ImportError:  # pragma: no cover
    from tests.fixture_attestation import sign_fixture_tool


def _signed_callable_tool(
    registry: ToolRegistry,
    runner: SecureRunner,
    *,
    tool_id: str,
    cap: str,
    fn: Any,
    permissions: list[str] | None = None,
) -> ToolSpec:
    perms = permissions if permissions is not None else ["fs.read"]
    digest = runner.register_trusted_host_callable(tool_id, fn, required_permissions=perms)
    spec = ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="host_trusted",
        binary_hash=digest,
        capabilities=[cap],
        required_permissions=perms,
        side_effects=[],
        runtime_requirements={"callable_name": tool_id},
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={
            "verifier_id": "round7-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class TestRound7Remediation(unittest.TestCase):
    """Verify KH-B2-R6-RUNTIME-003, KH-B2-R6-SEC-001, and KH-B2-R6-SEC-002 fixes."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_r7_")
        self.root = Path(self._tmp.name)
        self.ws = self.root / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile="LOCAL_RESEARCH",
            allowed_permissions=["fs.read", "fs.write"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_kh_b2_r6_runtime_003_sanitize_child_fds_does_not_hang_when_stdio_closed(self) -> None:
        outside_file = self.root / "outside_r7_closed_stdio_wd.txt"
        outside_file.write_text("", encoding="utf-8")
        # Child opens a fresh Unix socketpair AFTER closing 0/1/2 or inherits parent pipe >= 3:
        # We want child to close 0/1/2 BEFORE calling os.pipe(), then verify _sanitize_child_fds returns >=3 fast
        # and communicates result over sanitized_fd? Wait: parent doesn't know child's internal pipe, so child opens a
        # temp IPC socket/pipe inside ws or uses a pre-closed low-fd pipe + second pipe? No: if parent gives a
        # single high FD >= 10 via dup2, _sanitize_child_fds closes it UNLESS sanitized_fd writes to a workspace file!
        result_file = self.ws / "r7_closed_stdio_result.json"
        pid = os.fork()
        if pid == 0:
            try:
                ext_fd = os.open(str(outside_file), os.O_WRONLY | os.O_APPEND)
                for sfd in (0, 1, 2):
                    try:
                        os.close(sfd)
                    except OSError as _c_err:
                        _ = _c_err
                ipc_r, ipc_w = os.pipe()
                orig_write_fd = ipc_w
                sanitized_fd = _sanitize_child_fds(orig_write_fd, ws_resolved=self.ws.resolve())
                ext_blocked = False
                try:
                    os.write(ext_fd, b"ESCAPE\n")
                except OSError:
                    ext_blocked = True
                st_null = os.stat("/dev/null")
                stdio_devnull = all(
                    (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (st_null.st_dev, st_null.st_ino)
                    for fd in (0, 1, 2)
                )
                # orig ipc_r was either rebound to /dev/null (if <=2) or closed (if >=3).
                if ipc_r <= 2:
                    ipc_read_sanitized = (
                        os.fstat(ipc_r).st_dev,
                        os.fstat(ipc_r).st_ino,
                    ) == (st_null.st_dev, st_null.st_ino)
                else:
                    try:
                        os.fstat(ipc_r)
                        ipc_read_sanitized = False
                    except OSError:
                        ipc_read_sanitized = True
                sanitized_is_fifo = stat.S_ISFIFO(os.fstat(sanitized_fd).st_mode)
                os.close(sanitized_fd)
                result_file.write_text(
                    json.dumps(
                        {
                            "ok": True,
                            "orig_write_fd": orig_write_fd,
                            "sanitized_fd": sanitized_fd,
                            "ext_blocked": ext_blocked,
                            "ipc_read_closed": ipc_read_sanitized,
                            "sanitized_is_fifo": sanitized_is_fifo,
                            "stdio_devnull": stdio_devnull,
                        }
                    ),
                    encoding="utf-8",
                )
            except Exception as exc:
                result_file.write_text(json.dumps({"ok": False, "err": str(exc)}), encoding="utf-8")
            os._exit(0)

        deadline = time.monotonic() + 3.0
        reaped = False
        while time.monotonic() < deadline:
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                reaped = True
                break
            time.sleep(0.01)
        if not reaped:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            self.fail("_sanitize_child_fds hung when FDs 0/1/2 were closed prior to os.pipe()")

        self.assertTrue(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)
        payload = json.loads(result_file.read_text(encoding="utf-8"))
        self.assertTrue(payload["ok"], payload)
        self.assertLessEqual(payload["orig_write_fd"], 2)
        self.assertGreaterEqual(payload["sanitized_fd"], 3)
        self.assertTrue(payload["ext_blocked"])
        self.assertTrue(payload["ipc_read_closed"])
        self.assertTrue(payload["sanitized_is_fifo"])
        self.assertTrue(payload["stdio_devnull"])
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "")

    def test_kh_b2_r6_sec_001_stdlib_monkeypatch_and_depth_budget_caps_fail_closed(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        # 1. Monkeypatching math.sqrt after signing MUST alter compute_callable_sha256 and deny run().
        def sqrt_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"val": math.sqrt(144)}

        spec_sqrt = _signed_callable_tool(
            registry, runner, tool_id="r7.math_sqrt", cap="cap.math", fn=sqrt_fn
        )
        d_sqrt_before = compute_callable_sha256(sqrt_fn)
        orig_sqrt = math.sqrt
        try:
            math.sqrt = lambda _x: 777  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(sqrt_fn), d_sqrt_before)
            rec_patch_fn = runner.run(spec_sqrt, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_patch_fn.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("CALLABLE_HASH", rec_patch_fn.stderr_excerpt)

            # Swapping to another C builtin (math.sin) also changes digest!
            math.sqrt = math.sin  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(sqrt_fn), d_sqrt_before)
        finally:
            math.sqrt = orig_sqrt

        # 2. Monkeypatching posixpath.join (os.path.join) and builtins.abs also alters digest.
        def join_abs_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"p": os.path.join("a", "b"), "n": abs(-5)}

        d_ja_before = compute_callable_sha256(join_abs_fn)
        orig_join = posixpath.join
        orig_abs = builtins.abs
        try:
            posixpath.join = lambda *parts: "/tampered/" + "/".join(parts)  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(join_abs_fn), d_ja_before)
            posixpath.join = orig_join

            builtins.abs = lambda _x: 999  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(join_abs_fn), d_ja_before)
        finally:
            posixpath.join = orig_join
            builtins.abs = orig_abs

        # 2b. Bound builtin method tracks mutated self container; in-function import, non-function stdlib patch, and per-function __builtins__ are hashed.
        box: list[int] = [1]
        append_ref = box.append

        def append_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            append_ref(2)
            return {"n": len(box)}

        d_app_before = compute_callable_sha256(append_fn)
        box.append(99)
        self.assertNotEqual(compute_callable_sha256(append_fn), d_app_before)

        def inline_import_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            import math as _m
            return {"val": _m.sqrt(9)}

        class _EvilCallable:
            def __call__(self, _x: Any) -> float:
                return 888.0

        d_imp_before = compute_callable_sha256(inline_import_fn)
        orig_math_sqrt = math.sqrt
        try:
            math.sqrt = lambda _x: 555.0  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(inline_import_fn), d_imp_before)
            math.sqrt = _EvilCallable()  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(inline_import_fn), d_imp_before)
        finally:
            math.sqrt = orig_math_sqrt

        def _abs_tmpl(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"val": abs(-7)}

        clean_b = dict(builtins.__dict__)
        custom_globs: Dict[str, Any] = {"__builtins__": clean_b}
        fn_custom_b = types.FunctionType(_abs_tmpl.__code__, custom_globs, "fn_custom_b")
        d_cb_before = compute_callable_sha256(fn_custom_b)
        clean_b["abs"] = lambda _x: 888
        self.assertNotEqual(compute_callable_sha256(fn_custom_b), d_cb_before)

        # 3. Depth-15 nested mutable structure is accurately tracked (leaf mutation changes digest & denies).
        deep15: list[Any] = ["leaf_original"]
        for _ in range(15):
            deep15 = [deep15]

        def read_deep15(_args: Dict[str, Any]) -> Dict[str, Any]:
            cur = deep15
            for _ in range(15):
                cur = cur[0]
            return {"v": cur[0]}

        spec_d15 = _signed_callable_tool(
            registry, runner, tool_id="r7.deep15", cap="cap.d15", fn=read_deep15
        )
        d15_before = compute_callable_sha256(read_deep15)
        leaf_box = deep15
        for _ in range(15):
            leaf_box = leaf_box[0]
        leaf_box[0] = "leaf_mutated"
        self.assertNotEqual(compute_callable_sha256(read_deep15), d15_before)
        rec_d15 = runner.run(spec_d15, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec_d15.status, ExecutionStatus.PERMISSION_DENIED)

        # 4. Exceeding depth (>64) or budget (>16384) FAILS CLOSED (never emits valid hash or hygiene=None).
        deep80: list[Any] = ["leaf_80"]
        for _ in range(80):
            deep80 = [deep80]

        def read_deep80(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"d": bool(deep80)}

        with self.assertRaises(ValueError) as depth_exc:
            compute_callable_sha256(read_deep80)
        self.assertIn("CALLABLE_STATE_CANONICALIZATION_LIMIT_EXCEEDED", str(depth_exc.exception))
        self.assertEqual(
            validate_trusted_host_callable_hygiene(read_deep80),
            "CALLABLE_HYGIENE_DEPTH_OR_BUDGET_EXCEEDED",
        )

        # Also verify direct SecureRunner rejection if a pre-signed spec wraps an over-budget structure.
        huge_list = list(range(17000))

        def read_huge(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"n": len(huge_list)}

        with self.assertRaises(ValueError):
            compute_callable_sha256(read_huge)
        self.assertEqual(
            validate_trusted_host_callable_hygiene(read_huge),
            "CALLABLE_HYGIENE_DEPTH_OR_BUDGET_EXCEEDED",
        )

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_kh_b2_r6_sec_002_inherited_shared_mmap_blocked_by_hygiene_and_child_revocation(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        outside_canary = self.root / "outside_mmap_canary.bin"
        outside_canary.write_bytes(b"ORIG_MMAP_CANARY" + b"\x00" * 4080)
        fd = os.open(str(outside_canary), os.O_RDWR)
        mm = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        os.close(fd)
        try:
            def mmap_escape_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                mm[0:4] = b"PWN!"
                return {"written": True}

            # 1. Hygiene validator & SecureRunner reject callable holding shared mmap.mmap handle.
            self.assertEqual(
                validate_trusted_host_callable_hygiene(mmap_escape_fn),
                "CALLABLE_SHARED_MMAP_FORBIDDEN",
            )
            spec_mm = _signed_callable_tool(
                registry, runner, tool_id="r7.mmap_escape", cap="cap.mm", fn=mmap_escape_fn
            )
            rec_mm = runner.run(spec_mm, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_mm.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("CALLABLE_SHARED_MMAP_FORBIDDEN", rec_mm.stderr_excerpt)
            self.assertEqual(outside_canary.read_bytes()[:16], b"ORIG_MMAP_CANARY")

            # 1b. memoryview(mm) and bound mm.write are also rejected before execution.
            mv = memoryview(mm)
            try:
                def mv_escape_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                    mv[0:4] = b"MVWN"
                    return {"written": True}

                self.assertEqual(
                    validate_trusted_host_callable_hygiene(mv_escape_fn),
                    "CALLABLE_SHARED_MMAP_FORBIDDEN",
                )
                spec_mv = _signed_callable_tool(
                    registry, runner, tool_id="r7.mv_escape", cap="cap.mv", fn=mv_escape_fn
                )
                rec_mv = runner.run(spec_mv, {}, self.ctx, oracle=lambda _: True)
                self.assertEqual(rec_mv.status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("CALLABLE_SHARED_MMAP_FORBIDDEN", rec_mv.stderr_excerpt)
            finally:
                mv.release()

            mm_write = mm.write

            def bound_mm_escape_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                mm_write(b"BMM!")
                return {"written": True}

            self.assertEqual(
                validate_trusted_host_callable_hygiene(bound_mm_escape_fn),
                "CALLABLE_SHARED_MMAP_FORBIDDEN",
            )
            spec_bmm = _signed_callable_tool(
                registry, runner, tool_id="r7.bmm_escape", cap="cap.bmm", fn=bound_mm_escape_fn
            )
            rec_bmm = runner.run(spec_bmm, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_bmm.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("CALLABLE_SHARED_MMAP_FORBIDDEN", rec_bmm.stderr_excerpt)

            # 2. On Linux, direct fork + _sanitize_child_fds() MUST revoke external writable AND read-only MAP_SHARED mappings (SIGSEGV).
            if sys.platform.startswith("linux"):
                r_fd, w_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(r_fd)
                    w_fd = _sanitize_child_fds(w_fd, ws_resolved=self.ws.resolve())
                    mm[0:4] = b"EDIT"
                    os.write(w_fd, b"SURVIVED")
                    os.close(w_fd)
                    os._exit(0)
                os.close(w_fd)
                out = os.read(r_fd, 64)
                os.close(r_fd)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(out, b"")
                self.assertTrue(os.WIFSIGNALED(status) or os.WEXITSTATUS(status) != 0)
                self.assertEqual(outside_canary.read_bytes()[:16], b"ORIG_MMAP_CANARY")

                ro_fd = os.open(str(outside_canary), os.O_RDONLY)
                mm_ro = mmap.mmap(ro_fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ)
                os.close(ro_fd)
                try:
                    r_ro, w_ro = os.pipe()
                    pid_ro = os.fork()
                    if pid_ro == 0:
                        os.close(r_ro)
                        w_ro = _sanitize_child_fds(w_ro, ws_resolved=self.ws.resolve())
                        _ = mm_ro[0:4]
                        os.write(w_ro, b"SURVIVED_RO")
                        os.close(w_ro)
                        os._exit(0)
                    os.close(w_ro)
                    out_ro = os.read(r_ro, 64)
                    os.close(r_ro)
                    _, status_ro = os.waitpid(pid_ro, 0)
                    self.assertEqual(out_ro, b"")
                    self.assertTrue(os.WIFSIGNALED(status_ro) or os.WEXITSTATUS(status_ro) != 0)
                finally:
                    mm_ro.close()
        finally:
            mm.close()

    def test_clean_stdlib_callable_and_logforge_positive_regression(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        logforge = LogForge()

        def clean_fn(task_args: Dict[str, Any]) -> Dict[str, Any]:
            root_val = int(math.sqrt(144))
            offsets = logforge.scan_delimiters(
                str(task_args.get("data", "")).encode("utf-8"),
                delim=10,
                tier="python_oracle",
            ).offsets
            return {"root": root_val, "offsets": offsets}

        self.assertIsNone(validate_trusted_host_callable_hygiene(clean_fn))
        spec = _signed_callable_tool(registry, runner, tool_id="r7.clean_ok", cap="cap.ok", fn=clean_fn)
        rec = runner.run(
            spec,
            {"data": "x\ny"},
            self.ctx,
            oracle=lambda d: d["output"] == {"root": 12, "offsets": [1]},
        )
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec.stderr_excerpt)
        else:
            self.assertEqual(rec.status, ExecutionStatus.PASS, rec.stderr_excerpt)


if __name__ == "__main__":
    unittest.main()
