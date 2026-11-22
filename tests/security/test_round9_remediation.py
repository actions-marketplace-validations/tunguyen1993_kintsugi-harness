"""Independent regression probes for Build #2 Round-9 zero-hook Enum preflight, Python 3.13 dataclass helper compatibility, and stdlib repr safety (R8 audit closure)."""

from __future__ import annotations

import collections
import dataclasses
import datetime
import enum
import fractions
import functools
import sys
import tempfile
import types
import unittest
import uuid
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
            "verifier_id": "round9-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class TestRound9Remediation(unittest.TestCase):
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

    def test_kh_b2_r8_sec_001_enum_property_and_host_hook_preflight_zero_side_effects(self) -> None:
        outside_canary = self.root / "r9_host_preflight_canary.txt"
        armed = [False]

        def _trip_canary(tag: str) -> None:
            if armed[0]:
                outside_canary.write_text(f"PWNED:{tag}", encoding="utf-8")

        class EvilMixin:
            def _get_val(self) -> str:
                _trip_canary("enum_mixin_property")
                return "pwn"

            def _set_val(self, val: Any) -> None:
                self.__dict__["_value_"] = val

            _value_ = property(_get_val, _set_val)

        class MixinEvilEnum(EvilMixin, enum.Enum):
            ALPHA = "ok"

        class PostPropEnum(enum.Enum):
            BETA = "ok"

        def _post_val_getter(self_obj: Any) -> str:
            _trip_canary("enum_post_property")
            return "pwn"

        PostPropEnum._value_ = property(_post_val_getter)  # type: ignore[assignment]

        class NamePropEnum(enum.Enum):
            GAMMA = 1

        def _name_getter(self_obj: Any) -> str:
            _trip_canary("enum_name_property")
            return "GAMMA"

        NamePropEnum._name_ = property(_name_getter)  # type: ignore[assignment]

        class DynamicAttrEnum(enum.Enum):
            DELTA = 2

        DynamicAttrEnum._value_ = types.DynamicClassAttribute(_post_val_getter)  # type: ignore[assignment]

        class EvilStr:
            def __str__(self) -> str:
                _trip_canary("evil_str")
                return "dataclasses"

            def __bool__(self) -> bool:
                _trip_canary("evil_bool")
                return True

        class EvilRepr:
            def __repr__(self) -> str:
                _trip_canary("evil_repr")
                return "PWN_REPR"

        def mod_spoof_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"ok": True}

        mod_spoof_fn.__module__ = EvilStr()  # type: ignore[assignment]

        class KeyContainer:
            pass

        bad_key_obj = KeyContainer()
        bad_key_obj.__dict__[EvilStr()] = 123

        evil_deque = collections.deque([EvilRepr()])
        evil_proxy = types.MappingProxyType({"k": EvilRepr()})

        armed[0] = True
        self.assertFalse(outside_canary.exists())

        for label, bad_obj in (
            ("mixin_enum", MixinEvilEnum.ALPHA),
            ("post_prop_enum", PostPropEnum.BETA),
            ("name_prop_enum", NamePropEnum.GAMMA),
            ("dynamic_attr_enum", DynamicAttrEnum.DELTA),
            ("bad_key_obj", bad_key_obj),
        ):
            def _probe(_args: Dict[str, Any], target: Any = bad_obj) -> Dict[str, Any]:
                return {"v": str(type(target))}

            err = validate_trusted_host_callable_hygiene(_probe)
            self.assertIsNotNone(err, label)
            self.assertFalse(outside_canary.exists(), f"side effect on {label}")
            with self.assertRaises(ValueError):
                compute_callable_sha256(_probe)
            self.assertFalse(outside_canary.exists(), f"side effect in digest on {label}")

        self.assertIsNotNone(validate_trusted_host_callable_hygiene(mod_spoof_fn))
        self.assertFalse(outside_canary.exists())
        with self.assertRaises(ValueError):
            compute_callable_sha256(mod_spoof_fn)
        self.assertFalse(outside_canary.exists())

        def _deque_and_proxy_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"n": len(evil_deque), "k": "k" in evil_proxy}

        self.assertIsNone(validate_trusted_host_callable_hygiene(_deque_and_proxy_fn))
        self.assertFalse(outside_canary.exists())
        self.assertTrue(compute_callable_sha256(_deque_and_proxy_fn).startswith("sha256:"))
        self.assertFalse(outside_canary.exists())

        # Valid HMAC-signed ToolSpec case where Enum `_value_` property is attached post-registration:
        class MutableHostEnum(enum.Enum):
            ITEM = "clean"

        holder: Dict[str, Any] = {"item": MutableHostEnum.ITEM}
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        def signed_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"name": str(holder["item"])}

        spec = _signed_callable_tool(
            registry, runner, tool_id="r9.hmac_enum_prop", cap="cap.sec", fn=signed_fn
        )
        MutableHostEnum._value_ = property(_post_val_getter)  # type: ignore[assignment]
        rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(outside_canary.exists(), "signed HMAC runner must not invoke property on Enum")

    def test_kh_b2_r8_compat_002_python313_dataclass_replace_allowed_and_forged_rejected(self) -> None:
        logforge = LogForge()
        sample_result = LogScanResult(
            backend="python_oracle",
            disable_simd=False,
            input_bytes=4,
            delim=10,
            offsets=[1],
        )

        def clean_logforge(_args: Dict[str, Any]) -> Dict[str, Any]:
            res = logforge.scan_delimiters(b"a\nb", delim=10, tier="python_oracle")
            return {"offsets": res.offsets, "sample_offsets": len(sample_result.offsets)}

        self.assertIsNone(validate_trusted_host_callable_hygiene(clean_logforge))

        @dataclasses.dataclass(frozen=True)
        class Point:
            x: int
            y: int

        # Ensure Python < 3.13 also exercises authentic stdlib helper with `getattr` (`dataclasses.replace`):
        if "__replace__" not in Point.__dict__:
            Point.__replace__ = dataclasses.replace  # type: ignore[method-assign]

        def use_point(_args: Dict[str, Any]) -> Dict[str, Any]:
            p = Point(1, 2)
            p2 = dataclasses.replace(p, x=9)
            return {"x": p2.x, "y": p2.y}

        self.assertIsNone(validate_trusted_host_callable_hygiene(use_point))
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r9.dc_replace", cap="cap.dc", fn=use_point
        )
        rec = runner.run(spec, {}, self.ctx, oracle=lambda d: d["output"] == {"x": 9, "y": 2})
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec.stderr_excerpt)
        else:
            self.assertEqual(rec.status, ExecutionStatus.PASS, rec.stderr_excerpt)

        # Post-attestation mutation of `__replace__` must invalidate callable digest and fail closed:
        def alt_replace(obj: Any, **changes: Any) -> Any:
            return Point(obj.x + 1, obj.y)

        Point.__replace__ = alt_replace  # type: ignore[method-assign]
        rec_tampered = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec_tampered.status, ExecutionStatus.PERMISSION_DENIED)

        # Spoofed `__module__ = "dataclasses"` with `getattr` must still be rejected:
        @dataclasses.dataclass
        class SpoofDC:
            v: int

        def spoof_mod_replace(obj: Any, name: str) -> Any:
            return getattr(obj, name)

        spoof_mod_replace.__module__ = "dataclasses"
        SpoofDC.__replace__ = spoof_mod_replace  # type: ignore[method-assign]

        def use_spoof(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": SpoofDC(1).v}

        self.assertEqual(
            validate_trusted_host_callable_hygiene(use_spoof),
            "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:getattr",
        )

        # Forged function reusing `dataclasses.__dict__` & `co_filename == dataclasses.__file__` with `getattr` must be rejected:
        def raw_getattr_helper(obj: Any, name: str) -> Any:
            return getattr(obj, name)

        forged_code = raw_getattr_helper.__code__.replace(co_filename=dataclasses.__file__)
        forged_fn = types.FunctionType(forged_code, dataclasses.__dict__, "_replace")

        @dataclasses.dataclass
        class ForgedGlobalsDC:
            v: int

        ForgedGlobalsDC.__replace__ = forged_fn  # type: ignore[method-assign]

        def use_forged(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": ForgedGlobalsDC(2).v}

        self.assertEqual(
            validate_trusted_host_callable_hygiene(use_forged),
            "CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN:getattr",
        )

    def test_cached_property_and_dynamic_class_attribute_bound_in_hygiene_and_digest(self) -> None:
        class BadCached:
            @functools.cached_property
            def leak(self) -> Any:
                return getattr(self, "__class__")

        class BadDyn:
            @types.DynamicClassAttribute
            def leak(self) -> Any:
                return globals()

        for bad_cls in (BadCached, BadDyn):
            def _probe(_args: Dict[str, Any], target: type = bad_cls) -> Dict[str, Any]:
                return {"name": target.__name__}

            err = validate_trusted_host_callable_hygiene(_probe)
            self.assertIsNotNone(err)
            self.assertIn("CALLABLE_DYNAMIC_NAMESPACE_FORBIDDEN", str(err))

        class CleanBox:
            def __init__(self, base: int) -> None:
                self.base = base

            @functools.cached_property
            def doubled(self) -> int:
                return self.base * 2

            @types.DynamicClassAttribute
            def label(self) -> str:
                return f"B:{self.base}"

        def read_box(_args: Dict[str, Any]) -> Dict[str, Any]:
            b = CleanBox(5)
            return {"d": b.doubled, "l": b.label}

        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r9.desc_bind", cap="cap.desc", fn=read_box
        )
        d0 = compute_callable_sha256(read_box)

        CleanBox.doubled = functools.cached_property(lambda self: self.base * 99)  # type: ignore[method-assign]
        CleanBox.doubled.__set_name__(CleanBox, "doubled")
        self.assertNotEqual(compute_callable_sha256(read_box), d0)
        self.assertEqual(runner.run(spec, {}, self.ctx, oracle=lambda _: True).status, ExecutionStatus.PERMISSION_DENIED)

    def test_enum_extra_instance_state_and_safe_stdlib_types_regression(self) -> None:
        class StatefulEnum(enum.Enum):
            ONE = 10

        StatefulEnum.ONE.extra_tag = "v1"  # type: ignore[attr-defined]
        now_utc = datetime.datetime(2026, 11, 22, 5, 0, tzinfo=datetime.timezone.utc)
        uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        frac = fractions.Fraction(3, 7)
        sl = slice(1, 5, 2)
        dq = collections.deque([1, 2, 3], maxlen=4)
        mp = types.MappingProxyType({"a": 1})
        wire = ToolWire()
        logforge = LogForge()
        sr = LogScanResult(backend="python_oracle", disable_simd=False, input_bytes=4, delim=10, offsets=[1])

        def stdlib_heavy(_args: Dict[str, Any]) -> Dict[str, Any]:
            scan = logforge.scan_delimiters(b"x\ny", delim=10, tier="python_oracle")
            return {
                "enum_val": int(StatefulEnum.ONE.value),
                "extra": StatefulEnum.ONE.extra_tag,
                "status": ExecutionStatus.PASS.value,
                "year": now_utc.year,
                "uid": str(uid),
                "frac": str(frac),
                "sl": sl.stop,
                "dq": len(dq),
                "mp": mp["a"],
                "wire": wire.VERSION,
                "sr": len(sr.offsets),
                "scan": scan.offsets,
                "dec": str(Decimal("2.5")),
            }

        self.assertIsNone(validate_trusted_host_callable_hygiene(stdlib_heavy))
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r9.stdlib_enum", cap="cap.pos", fn=stdlib_heavy
        )
        d_before = compute_callable_sha256(stdlib_heavy)

        rec = runner.run(spec, {}, self.ctx, oracle=lambda d: d["output"]["extra"] == "v1")
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec.stderr_excerpt)
        else:
            self.assertEqual(rec.status, ExecutionStatus.PASS, rec.stderr_excerpt)

        StatefulEnum.ONE.extra_tag = "mutated"  # type: ignore[attr-defined]
        self.assertNotEqual(compute_callable_sha256(stdlib_heavy), d_before)
        rec_mut = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec_mut.status, ExecutionStatus.PERMISSION_DENIED)


if __name__ == "__main__":
    unittest.main()
