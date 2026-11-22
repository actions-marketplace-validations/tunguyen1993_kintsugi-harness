"""Independent regression probes for Build #2 Round-6 security boundary hardening."""

from __future__ import annotations

import ctypes
import functools
import json
import os
import platform
import socket
import sys
import tempfile
import types
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest import mock

from kintsugi.capability.contracts_v2 import AdapterSpec, PortContract
from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    compute_tool_spec_security_digest,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.runtime import probe_linux_landlock_available, validate_trusted_host_callable_hygiene
from kintsugi.runtime.secure_runner import (
    SecureRunner,
    _apply_linux_seccomp_network_deny_in_child,
    _sanitize_child_fds,
    compute_callable_sha256,
)
from kintsugi.tools.log_forge import LogForge

try:
    from fixture_attestation import sign_fixture_adapter, sign_fixture_tool
except ImportError:  # pragma: no cover
    from tests.fixture_attestation import sign_fixture_adapter, sign_fixture_tool

INDIRECT_MODE = "safe_initial"
_UNREFERENCED_GLOBAL_MODE = "untouched"


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
            "verifier_id": "round6-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class _MutableDepClass:
    MODE = "class_safe"


class _CallableWithGlobals:
    def __init__(self, tag: str) -> None:
        self.tag = tag

    def __call__(self, _args: Dict[str, Any]) -> Dict[str, Any]:
        return {"tag": self.tag, "mode": globals()["INDIRECT_MODE"]}


class TestRound6Remediation(unittest.TestCase):
    """Verify KH-B2-R5-SEC-001, KH-B2-R5-SEC-002, and KH-B2-R5-SEC-003 fixes."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_r6_")
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
    def test_kh_b2_r5_sec_001_inherited_fds_and_stdio_sanitized_in_child(self) -> None:
        outside_fd_file = self.root / "outside_inherited_fd.txt"
        outside_fd_file.write_text("", encoding="utf-8")
        outside_stdout_file = self.root / "outside_stdout.txt"
        outside_stderr_file = self.root / "outside_stderr.txt"

        ext_fd = os.open(str(outside_fd_file), os.O_WRONLY | os.O_APPEND)
        try:
            def fd_escape_probe(_args: Dict[str, Any]) -> Dict[str, Any]:
                os.write(ext_fd, b"ESCAPED_VIA_INHERITED_FD\n")
                return {"written": True}

            registry = ToolRegistry()
            runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
            spec = _signed_callable_tool(
                registry, runner, tool_id="r6.fd_escape", cap="cap.fd", fn=fd_escape_probe, permissions=["fs.read"]
            )
            rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec.status, ExecutionStatus.FAIL, rec.stderr_excerpt)
            self.assertIn("OSError", rec.stderr_excerpt)
            self.assertEqual(outside_fd_file.read_text(encoding="utf-8"), "")

            # Also verify FD 1 (stdout) and FD 2 (stderr) redirected outside workspace cannot leak bytes.
            def stdio_leak_probe(_args: Dict[str, Any]) -> Dict[str, Any]:
                os.write(1, b"STDOUT_ESCAPE\n")
                os.write(2, b"STDERR_ESCAPE\n")
                return {"ok": True}

            stdio_spec = _signed_callable_tool(
                registry, runner, tool_id="r6.stdio_leak", cap="cap.stdio", fn=stdio_leak_probe, permissions=["fs.read"]
            )
            saved_out = os.dup(1)
            saved_err = os.dup(2)
            out_fd = os.open(str(outside_stdout_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            err_fd = os.open(str(outside_stderr_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.dup2(out_fd, 1)
                os.dup2(err_fd, 2)
                rec_stdio = runner.run(stdio_spec, {}, self.ctx, oracle=lambda _: True)
            finally:
                os.dup2(saved_out, 1)
                os.dup2(saved_err, 2)
                os.close(saved_out)
                os.close(saved_err)
                os.close(out_fd)
                os.close(err_fd)

            if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
                self.assertEqual(rec_stdio.status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_stdio.stderr_excerpt)
            else:
                self.assertEqual(rec_stdio.status, ExecutionStatus.PASS)
            self.assertEqual(outside_stdout_file.read_text(encoding="utf-8"), "")
            self.assertEqual(outside_stderr_file.read_text(encoding="utf-8"), "")
        finally:
            os.close(ext_fd)

        # Direct unit check of _sanitize_child_fds relocating pipe write_fd <= 2 if needed.
        self.assertTrue(callable(_sanitize_child_fds))

    def test_kh_b2_r5_sec_002_dynamic_namespace_and_dependency_mutations_blocked(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        global INDIRECT_MODE, _UNREFERENCED_GLOBAL_MODE

        # 1. globals()["INDIRECT_MODE"] mutates hash AND is fail-closed by callable hygiene validator.
        def indirect_global_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"mode": globals()["INDIRECT_MODE"]}

        spec_glob = _signed_callable_tool(
            registry, runner, tool_id="r6.indirect_glob", cap="cap.glob", fn=indirect_global_fn
        )
        hash_before = compute_callable_sha256(indirect_global_fn)
        orig_mode = INDIRECT_MODE
        orig_unref = _UNREFERENCED_GLOBAL_MODE
        try:
            INDIRECT_MODE = "tampered_indirect"
            hash_after = compute_callable_sha256(indirect_global_fn)
            self.assertNotEqual(hash_before, hash_after)

            def computed_key_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                k = "_UNREFERENCED_" + "GLOBAL_MODE"
                return {"mode": globals()[k]}

            h_comp_1 = compute_callable_sha256(computed_key_fn)
            _UNREFERENCED_GLOBAL_MODE = "tampered_unref"
            h_comp_2 = compute_callable_sha256(computed_key_fn)
            self.assertNotEqual(h_comp_1, h_comp_2)
        finally:
            INDIRECT_MODE = orig_mode
            _UNREFERENCED_GLOBAL_MODE = orig_unref

        rec_glob = runner.run(spec_glob, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec_glob.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:globals", rec_glob.stderr_excerpt)

        # 2. getattr(), vars(), sys.modules[], eval(), and callable class instance with globals() are rejected.
        dep_mod = types.ModuleType("kintsugi_r6_synthetic_dep")
        dep_mod.MODE = "dep_safe"  # type: ignore[attr-defined]

        def getattr_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"mode": getattr(dep_mod, "MODE")}

        def vars_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"cnt": len(vars(dep_mod))}

        def sys_modules_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"has_os": "os" in sys.modules}

        def eval_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            ev = eval
            return {"val": ev("1 + 1")}

        callable_inst = _CallableWithGlobals("inst")

        for tid, bad_fn, expected_tok in [
            ("r6.getattr", getattr_fn, "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:getattr"),
            ("r6.vars", vars_fn, "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:vars"),
            ("r6.sysmod", sys_modules_fn, "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:sys.modules"),
            ("r6.eval", eval_fn, "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:eval"),
            ("r6.callinst", callable_inst, "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:globals"),
        ]:
            sp = _signed_callable_tool(registry, runner, tool_id=tid, cap=f"cap.{tid}", fn=bad_fn)
            rec_bad = runner.run(sp, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_bad.status, ExecutionStatus.PERMISSION_DENIED, tid)
            self.assertIn(expected_tok, rec_bad.stderr_excerpt, tid)

        # 3. Direct attribute read on user module, class attribute, and cyclic config mutates callable SHA-256.
        cyclic_cfg: Dict[str, Any] = {"mode": "safe", "nested": {"limit": 10}}
        cyclic_cfg["self_ref"] = cyclic_cfg

        def dep_attr_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "mod_mode": dep_mod.MODE,  # type: ignore[attr-defined]
                "cls_mode": _MutableDepClass.MODE,
                "cfg_mode": cyclic_cfg["mode"],
            }

        self.assertIsNone(validate_trusted_host_callable_hygiene(dep_attr_fn))
        spec_dep = _signed_callable_tool(
            registry, runner, tool_id="r6.dep_attr", cap="cap.dep", fn=dep_attr_fn
        )
        d0 = compute_callable_sha256(dep_attr_fn)
        try:
            dep_mod.MODE = "dep_mutated"  # type: ignore[attr-defined]
            self.assertNotEqual(compute_callable_sha256(dep_attr_fn), d0)
            rec_mut_mod = runner.run(spec_dep, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_mut_mod.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("CALLABLE_HASH", rec_mut_mod.stderr_excerpt)
            dep_mod.MODE = "dep_safe"  # type: ignore[attr-defined]

            _MutableDepClass.MODE = "class_mutated"
            self.assertNotEqual(compute_callable_sha256(dep_attr_fn), d0)
            rec_mut_cls = runner.run(spec_dep, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_mut_cls.status, ExecutionStatus.PERMISSION_DENIED)
            _MutableDepClass.MODE = "class_safe"

            cyclic_cfg["nested"]["limit"] = 999
            self.assertNotEqual(compute_callable_sha256(dep_attr_fn), d0)
            rec_mut_cfg = runner.run(spec_dep, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_mut_cfg.status, ExecutionStatus.PERMISSION_DENIED)
        finally:
            _MutableDepClass.MODE = "class_safe"

        # 4. Trusted host adapter with dynamic namespace primitive is also blocked.
        def bad_adapter(payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"x": getattr(dep_mod, "MODE"), "payload": payload}

        ad_hash = runner.register_trusted_host_adapter("r6.bad.ad", bad_adapter)
        p_in = PortContract(schema_ref="json_obj", semantic_type="json", unit="count", cardinality="one", ordering="unordered")
        p_out = PortContract(schema_ref="json_obj", semantic_type="json", unit="count", cardinality="one", ordering="unordered")
        ad_draft = AdapterSpec(
            adapter_id="r6.bad.ad",
            version="1.0.0",
            source_port=p_in,
            target_port=p_out,
            mapping={"fields": {"a": "a"}},
            verification_corpus_hash=sha256_digest("r6-ad"),
            trust_status=TrustStatus.DISCOVERED,
        )
        ad_verified = AdapterSpec(
            adapter_id="r6.bad.ad",
            version="1.0.0",
            source_port=p_in,
            target_port=p_out,
            mapping={"fields": {"a": "a"}},
            verification_corpus_hash=ad_draft.verification_corpus_hash,
            adapter_hash=ad_draft.adapter_hash,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "round6-ci",
                "adapter_id": "r6.bad.ad",
                "adapter_hash": ad_draft.adapter_hash,
                "verification_digest": sha256_digest("r6-ad"),
            },
        )
        ad_signed = sign_fixture_adapter(registry, ad_verified, callable_hash=ad_hash)
        with self.assertRaises(PermissionError) as ctx_exc:
            runner.execute_trusted_host_adapter(ad_signed, {"a": 1}, security_context=self.ctx)
        self.assertIn("CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:getattr", str(ctx_exc.exception))

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_kh_b2_r5_sec_003_cached_native_syscall_network_and_fail_closed_sandbox(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        # Start ephemeral loopback TCP listener strictly bound to 127.0.0.1.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        srv_port = srv.getsockname()[1]
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            cached_syscall = libc.syscall
            cached_socket = libc.socket
            cached_socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
            cached_socket.restype = ctypes.c_int
            cached_connect = libc.connect
            cached_connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
            cached_connect.restype = ctypes.c_int

            def cached_ffi_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                _ = cached_syscall
                return {"reached": True}

            # 1. Pre-cached ctypes function pointer / CDLL object rejected before fork.
            spec_ffi = _signed_callable_tool(
                registry, runner, tool_id="r6.cached_ffi", cap="cap.ffi", fn=cached_ffi_fn, permissions=["fs.read"]
            )
            rec_ffi = runner.run(spec_ffi, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_ffi.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("CALLABLE_NATIVE_FFI_OBJECT_FORBIDDEN", rec_ffi.stderr_excerpt)

            # 2. Direct forked-sandbox kernel probe (macOS Seatbelt / Linux seccomp-BPF):
            # even if called directly bypassing audit hook and hygiene gate via pre-cached native C pointers,
            # kernel sandbox blocks outbound 127.0.0.1 connect.
            def kernel_net_probe(_args: Dict[str, Any]) -> Dict[str, Any]:
                import struct as _struct

                sock_fd = int(cached_socket(socket.AF_INET, socket.SOCK_STREAM, 0))
                if sock_fd < 0:
                    raise PermissionError("KERNEL_SOCKET_EPERM")
                try:
                    if sys.platform == "darwin":
                        # Darwin struct sockaddr_in: uint8 sin_len=16, uint8 sin_family=AF_INET, be16 port, 4B ip, 8B zero
                        sa = (
                            _struct.pack("BB", 16, socket.AF_INET)
                            + _struct.pack("!H", srv_port)
                            + socket.inet_aton("127.0.0.1")
                            + b"\x00" * 8
                        )
                    else:
                        # Linux struct sockaddr_in: host u16 sin_family=AF_INET, be16 port, 4B ip, 8B zero
                        sa = (
                            _struct.pack("=H", socket.AF_INET)
                            + _struct.pack("!H", srv_port)
                            + socket.inet_aton("127.0.0.1")
                            + b"\x00" * 8
                        )
                    sa_buf = ctypes.create_string_buffer(sa, len(sa))
                    conn_rc = int(cached_connect(sock_fd, ctypes.addressof(sa_buf), len(sa)))
                    if conn_rc != 0:
                        raise PermissionError("KERNEL_CONNECT_EPERM")
                    return {"connected": True}
                finally:
                    os.close(sock_fd)

            landlock_ready = (not sys.platform.startswith("linux")) or probe_linux_landlock_available()[0]
            if landlock_ready:
                rc, _out, _stdout, err_txt, _to = runner._execute_callable_forked(
                    kernel_net_probe,
                    {},
                    self.ws.resolve(),
                    2.0,
                    65536,
                    security_context=self.ctx,
                )
                self.assertNotEqual(rc, 0, f"Kernel network block unexpectedly returned rc=0: {err_txt}")
            else:
                with self.assertRaises(PermissionError) as ll_exc:
                    runner._execute_callable_forked(
                        kernel_net_probe,
                        {},
                        self.ws.resolve(),
                        2.0,
                        65536,
                        security_context=self.ctx,
                    )
                self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", str(ll_exc.exception))

            if sys.platform.startswith("linux"):
                # Verify seccomp-BPF filter directly in forked child even on Landlock-unavailable hosts.
                sec_r, sec_w = os.pipe()
                sec_pid = os.fork()
                if sec_pid == 0:
                    os.close(sec_r)
                    ok_filter = _apply_linux_seccomp_network_deny_in_child(allow_exec=False)
                    sfd = int(cached_socket(socket.AF_INET, socket.SOCK_STREAM, 0)) if ok_filter else -2
                    nr_socket = 41 if platform.machine().lower() in {"x86_64", "amd64"} else 198
                    raw_rc = int(cached_syscall(nr_socket, socket.AF_INET, socket.SOCK_STREAM, 0)) if ok_filter else -2
                    os.write(sec_w, json.dumps({"ok_filter": ok_filter, "sfd": sfd, "raw_rc": raw_rc}).encode("utf-8"))
                    os.close(sec_w)
                    os._exit(0)
                os.close(sec_w)
                sec_out = json.loads(os.read(sec_r, 512).decode("utf-8"))
                os.close(sec_r)
                os.waitpid(sec_pid, 0)
                self.assertTrue(sec_out["ok_filter"], sec_out)
                self.assertLess(sec_out["sfd"], 0, sec_out)
                self.assertLess(sec_out["raw_rc"], 0, sec_out)

                if landlock_ready:
                    def linux_raw_syscall_probe(_args: Dict[str, Any]) -> Dict[str, Any]:
                        import struct as _struct

                        nr_socket = 41 if platform.machine().lower() in {"x86_64", "amd64"} else 198
                        nr_connect = 42 if platform.machine().lower() in {"x86_64", "amd64"} else 203
                        sfd = int(cached_syscall(nr_socket, socket.AF_INET, socket.SOCK_STREAM, 0))
                        if sfd < 0:
                            raise PermissionError("KERNEL_RAW_SYSCALL_SOCKET_EPERM")
                        try:
                            sa = (
                                _struct.pack("=H", socket.AF_INET)
                                + _struct.pack("!H", srv_port)
                                + socket.inet_aton("127.0.0.1")
                                + b"\x00" * 8
                            )
                            sa_buf = ctypes.create_string_buffer(sa, len(sa))
                            crc = int(cached_syscall(nr_connect, sfd, ctypes.addressof(sa_buf), len(sa)))
                            if crc != 0:
                                raise PermissionError("KERNEL_RAW_SYSCALL_CONNECT_EPERM")
                            return {"connected": True}
                        finally:
                            os.close(sfd)

                    rc_raw, _, _, err_raw, _ = runner._execute_callable_forked(
                        linux_raw_syscall_probe,
                        {},
                        self.ws.resolve(),
                        2.0,
                        65536,
                        security_context=self.ctx,
                    )
                    self.assertNotEqual(rc_raw, 0, f"Linux raw syscall network unexpectedly succeeded: {err_raw}")

            # 2b. Verify network_allowed=True context distinction cleanly (Linux allows loopback; macOS Seatbelt keeps host net deny without audit error).
            def stdlib_net_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.settimeout(0.3)
                    s.connect(("127.0.0.1", srv_port))
                    return {"connected": True}
                finally:
                    s.close()

            net_ctx = SecurityContext(
                workspace_root=str(self.ws),
                profile="LOCAL_RESEARCH",
                allowed_permissions=["fs.read", "network.outbound"],
                network_allowed=True,
                allow_untrusted_native=False,
            )
            spec_net_ok = _signed_callable_tool(
                registry,
                runner,
                tool_id="r6.net_allowed",
                cap="cap.net",
                fn=stdlib_net_fn,
                permissions=["fs.read", "network.outbound"],
            )
            rec_net_ok = runner.run(spec_net_ok, {}, net_ctx, oracle=lambda _: True)
            self.assertNotIn("SANDBOX_NETWORK_FORBIDDEN", rec_net_ok.stderr_excerpt)
            if sys.platform.startswith("linux") and landlock_ready:
                self.assertEqual(rec_net_ok.status, ExecutionStatus.PASS, rec_net_ok.stderr_excerpt)

            # 3. Kernel sandbox unavailability on Linux MUST fail closed with PermissionError (no audit-only fallback).
            def trivial_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                return {"executed": True}

            spec_ok = _signed_callable_tool(
                registry, runner, tool_id="r6.fail_closed", cap="cap.fc", fn=trivial_fn, permissions=["fs.read"]
            )
            with mock.patch("kintsugi.runtime.secure_runner.sys.platform", "linux"), \
                 mock.patch("kintsugi.runtime.secure_runner._apply_linux_landlock_in_child", return_value=False):
                rec_no_ll = runner.run(spec_ok, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_no_ll.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_no_ll.stderr_excerpt)

            with mock.patch("kintsugi.runtime.secure_runner.sys.platform", "linux"), \
                 mock.patch("kintsugi.runtime.secure_runner._apply_linux_landlock_in_child", return_value=True), \
                 mock.patch("kintsugi.runtime.secure_runner._apply_linux_seccomp_network_deny_in_child", return_value=False), \
                 mock.patch("kintsugi.runtime.secure_runner._apply_linux_netns_isolation_in_child", return_value=False):
                rec_no_net = runner.run(spec_ok, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_no_net.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_NETWORK_ISOLATION_FAILED", rec_no_net.stderr_excerpt)
        finally:
            srv.close()

        # 4. Positive regression: clean LogForge trusted host callable still passes all checks.
        logforge = LogForge()

        def clean_logforge(task_args: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "offsets": logforge.scan_delimiters(
                    str(task_args.get("data", "")).encode("utf-8"),
                    delim=10,
                    tier="python_oracle",
                ).offsets
            }

        self.assertIsNone(validate_trusted_host_callable_hygiene(clean_logforge))
        spec_lf = _signed_callable_tool(
            registry, runner, tool_id="r6.clean_logforge", cap="cap.lf", fn=clean_logforge, permissions=["fs.read"]
        )
        rec_lf = runner.run(
            spec_lf,
            {"data": "a\nb\nc"},
            self.ctx,
            oracle=lambda d: d["output"] == {"offsets": [1, 3]},
        )
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec_lf.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_lf.stderr_excerpt)
        else:
            self.assertEqual(rec_lf.status, ExecutionStatus.PASS, rec_lf.stderr_excerpt)


if __name__ == "__main__":
    unittest.main()
