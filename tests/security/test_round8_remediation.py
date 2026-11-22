"""Independent regression probes for Build #2 Round-8 preflight isolation, MRO/dunder hashing, and hardlinked MAP_SHARED revocation (R7 audit closure)."""

from __future__ import annotations

import mmap
import os
import re
import sys
import tempfile
import types
import unittest
from decimal import Decimal
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
from kintsugi.tools.log_forge import LogForge, LogScanResult
from kintsugi.tools.tool_wire import ToolWire

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
    permissions: Any = ("fs.read", "fs.write"),
) -> ToolSpec:
    perms = list(permissions)
    digest = runner.register_trusted_host_callable(tool_id, fn, required_permissions=perms)
    spec = ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="host_trusted",
        binary_hash=digest,
        capabilities=[cap],
        input_schema={"type": "object", "required": []},
        output_schema={"type": "object", "required": []},
        semantic_contract={"domain": "security"},
        side_effects=["read"],
        required_permissions=perms,
        runtime_requirements={"callable_name": tool_id},
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={
            "verifier_id": "round8-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class TestRound8Remediation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "ws"
        self.ws.mkdir()
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            allowed_permissions=["fs.read", "fs.write"],
            network_allowed=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kh_b2_r7_sec_001_preflight_blocks_side_effects_without_executing_user_hooks(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        outside_canary = self.root / "r8_preflight_canary.txt"

        def _pwn(tag: str) -> None:
            outside_canary.write_text(tag, encoding="utf-8")

        class EvilGetAttribute:
            def __getattribute__(self, name: str) -> Any:
                _pwn(f"__getattribute__:{name}")
                return object.__getattribute__(self, name)

        class EvilGetattr:
            def __getattr__(self, name: str) -> Any:
                _pwn(f"__getattr__:{name}")
                return None

        class EvilPropDict:
            @property
            def __dict__(self) -> dict:  # type: ignore[override]
                _pwn("property___dict__")
                return {}

        class EvilDesc:
            def __get__(self, inst: Any, owner: Any) -> Any:
                _pwn("descriptor___get__")
                return 1

        class EvilWithDesc:
            trap = EvilDesc()

        class EvilMeta(type):
            def __getattribute__(cls, name: str) -> Any:
                _pwn(f"metaclass:{name}")
                return type.__getattribute__(cls, name)

        class EvilMetaObj(metaclass=EvilMeta):
            x = 1

        class EvilDict(dict):
            def items(self) -> Any:  # type: ignore[override]
                _pwn("dict_items")
                return []

        class EvilModule(types.ModuleType):
            def __getattribute__(self, name: str) -> Any:
                _pwn(f"module:{name}")
                return types.ModuleType.__getattribute__(self, name)

        traps = [
            ("CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__getattribute__", EvilGetAttribute()),
            ("CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__getattr__", EvilGetattr()),
            ("CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__dict__", EvilPropDict()),
            ("CALLABLE_CUSTOM_DESCRIPTOR_FORBIDDEN:trap", EvilWithDesc()),
            ("CALLABLE_CUSTOM_METACLASS_FORBIDDEN", EvilMetaObj()),
            ("CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__getattribute__", EvilModule("evil_mod")),
        ]

        holder: list[Any] = []

        def read_holder(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"count": len(holder)}

        signed_spec = _signed_callable_tool(
            registry, runner, tool_id="r8.preflight", cap="cap.preflight", fn=read_holder
        )

        for expected_err, trap_obj in traps:
            holder[:] = [trap_obj]
            err = validate_trusted_host_callable_hygiene(read_holder)
            self.assertIsNotNone(err)
            self.assertIn(expected_err, str(err))
            with self.assertRaises(ValueError):
                compute_callable_sha256(read_holder)
            rec = runner.run(signed_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertFalse(outside_canary.exists(), f"Host preflight executed hook for {expected_err}")

        # Direct closure reference (without holder list) MUST also fail with zero hook execution.
        direct_trap = EvilGetAttribute()

        def direct_closure_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"seen": direct_trap is not None}

        direct_err = validate_trusted_host_callable_hygiene(direct_closure_fn)
        self.assertIsNotNone(direct_err)
        self.assertIn("CALLABLE_CUSTOM_ATTRIBUTE_HOOK_FORBIDDEN:__getattribute__", str(direct_err))
        with self.assertRaises(ValueError):
            compute_callable_sha256(direct_closure_fn)
        with self.assertRaises(ValueError):
            runner.register_trusted_host_callable("r8.direct_trap", direct_closure_fn)
        self.assertFalse(outside_canary.exists(), "Direct closure reference executed __getattribute__!")

        # Builtin dict subclass with side-effectful .items() override MUST NOT execute .items() during hygiene or hashing.
        ed = EvilDict({"k": "v"})
        holder[:] = [ed]
        self.assertIsNone(validate_trusted_host_callable_hygiene(read_holder))
        d_ed = compute_callable_sha256(read_holder)
        self.assertTrue(d_ed.startswith("sha256:"))
        self.assertFalse(outside_canary.exists(), "EvilDict.items() executed during preflight!")

    def test_kh_b2_r7_sec_002_signed_special_methods_mro_and_properties_bound_in_digest(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        class BaseBox:
            base_bonus = 0

        class Box(BaseBox):
            factor = 7

            def __int__(self) -> int:
                return int(self.factor + self.base_bonus)

            @property
            def scaled(self) -> int:
                return int(self.factor) * 2

        inst = Box()

        def read_box(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": int(inst)}

        signed_spec = _signed_callable_tool(
            registry, runner, tool_id="r8.special", cap="cap.special", fn=read_box
        )
        d0 = compute_callable_sha256(read_box)

        # Positive unmutated baseline (Darwin runs PASS; Linux container w/o Landlock fails closed).
        rec_ok = runner.run(signed_spec, {}, self.ctx, oracle=lambda d: d["output"] == {"v": 7})
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec_ok.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_ok.stderr_excerpt)
        else:
            self.assertEqual(rec_ok.status, ExecutionStatus.PASS, rec_ok.stderr_excerpt)

        # 1. Mutating class attribute Box.factor alters signed digest & denies run().
        Box.factor = 777
        try:
            self.assertNotEqual(compute_callable_sha256(read_box), d0)
            rec_factor = runner.run(signed_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_factor.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("TOOL_CALLABLE_HASH_MISMATCH", rec_factor.stderr_excerpt)
        finally:
            Box.factor = 7

        # 2. Replacing special method Box.__int__ alters signed digest & denies run().
        orig_int = Box.__int__
        try:
            Box.__int__ = lambda _self: 999  # type: ignore[method-assign,assignment]
            self.assertNotEqual(compute_callable_sha256(read_box), d0)
            rec_int = runner.run(signed_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_int.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("TOOL_CALLABLE_HASH_MISMATCH", rec_int.stderr_excerpt)
        finally:
            Box.__int__ = orig_int

        # 3. Mutating base class attribute in MRO (BaseBox.base_bonus) alters signed digest & denies run().
        BaseBox.base_bonus = 100
        try:
            self.assertNotEqual(compute_callable_sha256(read_box), d0)
            rec_mro = runner.run(signed_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_mro.status, ExecutionStatus.PERMISSION_DENIED)
        finally:
            BaseBox.base_bonus = 0

        # 4. Mutating @property getter fget alters signed digest & denies run().
        orig_prop = Box.scaled
        try:
            Box.scaled = property(lambda s: int(s.factor) * 99)  # type: ignore[assignment]
            self.assertNotEqual(compute_callable_sha256(read_box), d0)
            rec_prop = runner.run(signed_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_prop.status, ExecutionStatus.PERMISSION_DENIED)
        finally:
            Box.scaled = orig_prop

        # 5. Builtin subclass special method (SubInt.__int__) mutation alters signed digest.
        class SubInt(int):
            mul = 1

            def __int__(self) -> int:
                return int.__int__(self) * self.mul

        si = SubInt(5)

        def read_subint(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": int(si)}

        si_spec = _signed_callable_tool(
            registry, runner, tool_id="r8.subint", cap="cap.subint", fn=read_subint
        )
        d_si = compute_callable_sha256(read_subint)
        SubInt.mul = 50
        try:
            self.assertNotEqual(compute_callable_sha256(read_subint), d_si)
            rec_si = runner.run(si_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_si.status, ExecutionStatus.PERMISSION_DENIED)
        finally:
            SubInt.mul = 1

        # 6. Dynamic reflection/eval inside a special method (__int__) is caught by hygiene!
        class DynamicDunder:
            def __int__(self) -> int:
                return int(len(globals()))

        dyn = DynamicDunder()

        def read_dyn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": int(dyn)}

        hyg = validate_trusted_host_callable_hygiene(read_dyn)
        self.assertIsNotNone(hyg)
        self.assertIn("CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:globals", str(hyg))

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_kh_b2_r7_sec_003_workspace_hardlink_shared_mmap_revoked_in_child(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        outside_canary = self.root / "outside_r8_hardlink_canary.bin"
        outside_canary.write_bytes(b"R8_OUTSIDE_SECRET" + b"\x00" * 4079)
        ws_hardlink = self.ws / "alias_inside_ws.bin"
        os.link(outside_canary, ws_hardlink)

        fd = os.open(str(ws_hardlink), os.O_RDWR)
        mm = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        os.close(fd)
        try:
            def hl_escape_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
                mm[0:4] = b"PWN!"
                return {"written": True}

            self.assertEqual(
                validate_trusted_host_callable_hygiene(hl_escape_fn),
                "CALLABLE_SHARED_MMAP_FORBIDDEN",
            )
            spec = _signed_callable_tool(
                registry, runner, tool_id="r8.hl_mmap", cap="cap.hl", fn=hl_escape_fn
            )
            rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertEqual(outside_canary.read_bytes()[:17], b"R8_OUTSIDE_SECRET")

            if sys.platform.startswith("linux"):
                r_fd, w_fd = os.pipe()
                pid = os.fork()
                if pid == 0:
                    os.close(r_fd)
                    w_fd = _sanitize_child_fds(w_fd, ws_resolved=self.ws.resolve())
                    mm[0:4] = b"PWN!"
                    os.write(w_fd, b"SURVIVED")
                    os.close(w_fd)
                    os._exit(0)
                os.close(w_fd)
                out = os.read(r_fd, 64)
                os.close(r_fd)
                _, status = os.waitpid(pid, 0)
                self.assertEqual(out, b"")
                self.assertTrue(os.WIFSIGNALED(status) or os.WEXITSTATUS(status) != 0)
                self.assertEqual(outside_canary.read_bytes()[:17], b"R8_OUTSIDE_SECRET")
        finally:
            mm.close()

    def test_clean_dataclasses_enums_and_logforge_positive_regression(self) -> None:
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        logforge = LogForge()
        wire = ToolWire()
        sample_result = LogScanResult(
            backend="python_oracle",
            disable_simd=False,
            input_bytes=4,
            delim=10,
            offsets=[1],
        )
        const_dec = Decimal("12.345")
        const_pat = re.compile(r"^x")
        const_path = self.ws / "sample.log"

        def clean_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            res = logforge.scan_delimiters(b"a\nb", delim=10, tier="python_oracle")
            _ = (wire.VERSION, len(sample_result.offsets), ExecutionStatus.PASS, const_dec, const_pat.pattern, const_path.name)
            return {
                "offsets": res.offsets,
                "status": str(ExecutionStatus.PASS.value),
                "dec": str(const_dec),
            }

        self.assertIsNone(validate_trusted_host_callable_hygiene(clean_fn))
        digest = compute_callable_sha256(clean_fn)
        self.assertTrue(digest.startswith("sha256:"))
        spec = _signed_callable_tool(
            registry, runner, tool_id="r8.clean_pos", cap="cap.clean", fn=clean_fn
        )
        rec = runner.run(
            spec,
            {},
            self.ctx,
            oracle=lambda d: d["output"] == {"offsets": [1], "status": "PASS", "dec": "12.345"},
        )
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec.stderr_excerpt)
        else:
            self.assertEqual(rec.status, ExecutionStatus.PASS, rec.stderr_excerpt)


if __name__ == "__main__":
    unittest.main()
