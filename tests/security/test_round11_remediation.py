"""Independent regression probes for Build #2 Round-11 zero-metaclass-hook identity checks and zero-repr bytecode scanning (R10 KH-B2-R10-SEC-001 closure)."""

from __future__ import annotations

import math  # noqa: F401
import sys
import tempfile
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
            "verifier_id": "round11-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class TestRound11Remediation(unittest.TestCase):
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

    def test_kh_b2_r10_sec_001_metaclass_eq_hash_ne_zero_side_effects_hmac_signed(self) -> None:
        outside_canary = self.root / "r11_metaclass_eq_canary.txt"
        armed = [False]

        def _trip(tag: str) -> None:
            if armed[0]:
                outside_canary.write_text(f"PWNED:{tag}", encoding="utf-8")

        class EvilMeta(type):
            def __eq__(cls, other: Any) -> bool:
                _trip("meta_eq")
                return False

            def __ne__(cls, other: Any) -> bool:
                _trip("meta_ne")
                return True

            def __hash__(cls) -> int:
                _trip("meta_hash")
                return 42

        class EvilCls(metaclass=EvilMeta):
            tag = "evil"

        holder: Dict[str, Any] = {"obj": "clean"}

        def post_mut_fn(_args: Dict[str, Any], default_box: Dict[str, Any] = holder) -> Dict[str, Any]:
            return {"v": str(type(default_box["obj"]))}

        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r11.hmac_meta_eq", cap="cap.sec", fn=post_mut_fn
        )

        # Mutate default holder post-registration to EvilCls() instance and also arm direct probes.
        holder["obj"] = EvilCls()
        evil_inst = EvilCls()

        def direct_inst_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"t": evil_inst.tag}

        def direct_cls_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"t": EvilCls.tag}

        def closure_eq_fn(_args: Dict[str, Any], target: Any = evil_inst) -> Dict[str, Any]:
            return {"t": str(type(target))}

        armed[0] = True
        self.assertFalse(outside_canary.exists())

        for label, probe in (
            ("post_mut_fn", post_mut_fn),
            ("direct_inst_fn", direct_inst_fn),
            ("direct_cls_fn", direct_cls_fn),
            ("closure_eq_fn", closure_eq_fn),
        ):
            self.assertEqual(
                validate_trusted_host_callable_hygiene(probe),
                "CALLABLE_CUSTOM_METACLASS_FORBIDDEN",
                label,
            )
            self.assertFalse(outside_canary.exists(), f"hygiene invoked metaclass hook on {label}")
            with self.assertRaisesRegex(ValueError, "CALLABLE_CUSTOM_METACLASS_FORBIDDEN", msg=label):
                compute_callable_sha256(probe)
            self.assertFalse(outside_canary.exists(), f"digest invoked metaclass hook on {label}")

        rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("CALLABLE_CUSTOM_METACLASS_FORBIDDEN", rec.stderr_excerpt)
        self.assertFalse(outside_canary.exists(), "HMAC-signed runner invoked metaclass __eq__/__hash__")

    def test_metaclass_mro_dict_module_property_zero_side_effects_hmac_signed(self) -> None:
        outside_canary = self.root / "r11_metaclass_prop_canary.txt"
        armed = [False]

        def _trip(tag: str) -> None:
            if armed[0]:
                outside_canary.write_text(f"PWNED:{tag}", encoding="utf-8")

        class EvilPropMeta(type):
            @property
            def __mro__(cls) -> Any:
                _trip("meta_mro_prop")
                return (cls, object)

            @property
            def __dict__(cls) -> Any:
                _trip("meta_dict_prop")
                return types.MappingProxyType({})

            @property
            def __module__(cls) -> Any:
                _trip("meta_module_prop")
                return "builtins"

        class EvilPropCls(metaclass=EvilPropMeta):
            val = 7

        holder: Dict[str, Any] = {"item": 1}

        def use_holder(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": str(type(holder["item"]))}

        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r11.hmac_meta_prop", cap="cap.sec", fn=use_holder
        )

        holder["item"] = EvilPropCls()
        evil_cls_ref = EvilPropCls

        def direct_prop_cls(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"n": str(type(evil_cls_ref))}

        armed[0] = True
        self.assertFalse(outside_canary.exists())

        for label, fn_target in (("use_holder", use_holder), ("direct_prop_cls", direct_prop_cls)):
            self.assertEqual(
                validate_trusted_host_callable_hygiene(fn_target),
                "CALLABLE_CUSTOM_METACLASS_FORBIDDEN",
                label,
            )
            self.assertFalse(outside_canary.exists(), f"hygiene triggered metaclass property on {label}")
            with self.assertRaisesRegex(ValueError, "CALLABLE_CUSTOM_METACLASS_FORBIDDEN", msg=label):
                compute_callable_sha256(fn_target)
            self.assertFalse(outside_canary.exists(), f"digest triggered metaclass property on {label}")

        rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("CALLABLE_CUSTOM_METACLASS_FORBIDDEN", rec.stderr_excerpt)
        self.assertFalse(outside_canary.exists(), "HMAC-signed runner triggered metaclass property")

    def test_code_co_consts_evil_repr_and_class_prop_zero_side_effects(self) -> None:
        outside_canary = self.root / "r11_co_consts_canary.txt"
        armed = [False]

        class EvilReprConst:
            def __repr__(self) -> str:
                if armed[0]:
                    outside_canary.write_text("PWNED:co_const_repr", encoding="utf-8")
                return "EVIL"

        class EvilClassProp:
            @property
            def __class__(self) -> type:
                if armed[0]:
                    outside_canary.write_text("PWNED:class_prop", encoding="utf-8")
                return int

        def template_with_import(_args: Dict[str, Any]) -> Dict[str, Any]:
            import math as local_math
            sentinel = 987654321
            return {"s": round(local_math.sqrt(16)), "tag": sentinel}

        bad_consts = tuple(
            EvilReprConst() if c == 987654321 else c for c in template_with_import.__code__.co_consts
        )
        forged_code = template_with_import.__code__.replace(co_consts=bad_consts)
        fn_bad_const = types.FunctionType(forged_code, template_with_import.__globals__, "fn_bad_const")

        class EvilClassDesc:
            def __get__(self, obj: Any, owner: Any = None) -> type:
                if armed[0]:
                    outside_canary.write_text("PWNED:class_desc", encoding="utf-8")
                return int

        class EvilClassCustomDesc:
            __class__ = EvilClassDesc()  # type: ignore[assignment]

        evil_cprop_obj = EvilClassProp()
        evil_cdesc_obj = EvilClassCustomDesc()

        def fn_evil_cprop(_args: Dict[str, Any], target: Any = evil_cprop_obj) -> Dict[str, Any]:
            return {"n": str(type(target))}

        def fn_evil_cdesc(_args: Dict[str, Any], target: Any = evil_cdesc_obj) -> Dict[str, Any]:
            return {"n": str(type(target))}

        armed[0] = True
        self.assertFalse(outside_canary.exists())

        # Zero-repr import extraction must inspect fn_bad_const without firing EvilReprConst.__repr__.
        err_c = validate_trusted_host_callable_hygiene(fn_bad_const)
        self.assertFalse(outside_canary.exists(), "dis/hygiene called EvilReprConst.__repr__")
        self.assertIsNone(err_c)
        self.assertTrue(compute_callable_sha256(fn_bad_const).startswith("sha256:"))
        self.assertFalse(outside_canary.exists(), "canonicalizer called EvilReprConst.__repr__")

        # EvilClassProp must never invoke __class__ property during hygiene or hashing (type(obj) only).
        self.assertIsNone(validate_trusted_host_callable_hygiene(fn_evil_cprop))
        self.assertFalse(outside_canary.exists(), "hygiene invoked EvilClassProp.__class__")
        self.assertTrue(compute_callable_sha256(fn_evil_cprop).startswith("sha256:"))
        self.assertFalse(outside_canary.exists(), "digest invoked EvilClassProp.__class__")

        # Custom descriptor on __class__ must fail preflight without invoking __get__.
        err_d = validate_trusted_host_callable_hygiene(fn_evil_cdesc)
        self.assertEqual(err_d, "CALLABLE_CUSTOM_DESCRIPTOR_FORBIDDEN:__class__")
        self.assertFalse(outside_canary.exists(), "hygiene invoked EvilClassDesc.__get__")
        with self.assertRaisesRegex(ValueError, "CALLABLE_CUSTOM_DESCRIPTOR_FORBIDDEN:__class__"):
            compute_callable_sha256(fn_evil_cdesc)
        self.assertFalse(outside_canary.exists(), "digest invoked EvilClassDesc.__get__")

    def test_clean_regression_imports_enums_dataclasses_logforge_and_toolwire(self) -> None:
        from kintsugi.runtime import secure_runner as sr

        def import_sample(_args: Dict[str, Any]) -> Dict[str, Any]:
            import collections.abc
            from os import path
            import math
            return {"m": int(math.sqrt(9)), "b": bool(collections.abc.Mapping), "p": bool(path)}

        self.assertEqual(
            sr._collect_code_import_names(import_sample.__code__),
            {"collections.abc", "os", "math"},
        )

        def forbidden_mmap_imp(_args: Dict[str, Any]) -> Dict[str, Any]:
            import mmap
            return {"p": mmap.PAGESIZE}

        def forbidden_importlib_imp(_args: Dict[str, Any]) -> Dict[str, Any]:
            import importlib
            return {"m": bool(importlib)}

        self.assertEqual(validate_trusted_host_callable_hygiene(forbidden_mmap_imp), "CALLABLE_SHARED_MMAP_FORBIDDEN")
        self.assertEqual(
            validate_trusted_host_callable_hygiene(forbidden_importlib_imp),
            "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:importlib",
        )

        wire = ToolWire()
        logforge = LogForge()
        sr_sample = LogScanResult(backend="python_oracle", disable_simd=False, input_bytes=4, delim=10, offsets=[1])

        def clean_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            scan = logforge.scan_delimiters(b"a\nb", delim=10, tier="python_oracle")
            return {
                "wire": wire.VERSION,
                "status": ExecutionStatus.PASS.value,
                "sample": len(sr_sample.offsets),
                "scan": scan.offsets,
            }

        self.assertIsNone(validate_trusted_host_callable_hygiene(clean_fn))
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r11.clean_pos", cap="cap.pos", fn=clean_fn
        )
        rec = runner.run(spec, {}, self.ctx, oracle=lambda d: d["output"]["scan"] == [1])
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec.stderr_excerpt)
        else:
            self.assertEqual(rec.status, ExecutionStatus.PASS, rec.stderr_excerpt)


if __name__ == "__main__":
    unittest.main()
