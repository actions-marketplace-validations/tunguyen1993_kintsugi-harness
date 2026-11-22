"""Independent regression probes for Build #2 Round-10 zero-truthiness and pre-key-validation host-preflight hardening (R9 KH-B2-R9-SEC-001 closure)."""

from __future__ import annotations

import enum
import functools
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
            "verifier_id": "round10-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class TestRound10Remediation(unittest.TestCase):
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

    def test_kh_b2_r9_sec_001_path1_module_bool_truthiness_zero_side_effects_hmac_signed(self) -> None:
        outside_canary = self.root / "r10_module_bool_canary.txt"
        armed = [False]

        def _trip(tag: str) -> None:
            if armed[0]:
                outside_canary.write_text(f"PWNED:{tag}", encoding="utf-8")

        class EvilBoolModule(types.ModuleType):
            def __bool__(self) -> bool:
                _trip("module_bool")
                return True

        mod_exact = EvilBoolModule("evil_r10_bool_exact")
        mod_pkg = EvilBoolModule("evil_r10_bool_pkg")

        class ForeignCls:
            pass

        ForeignCls.__module__ = "evil_r10_bool_pkg.sub"

        def inline_imp_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            import evil_r10_bool_exact  # noqa: F401
            return {"ok": True}

        def use_foreign_cls(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"name": ForeignCls.__name__}

        class CleanBoolCallable:
            def __call__(self, _args: Dict[str, Any]) -> Dict[str, Any]:
                return {"ok": True}

            def __bool__(self) -> bool:
                outside_canary.write_text("PWNED:clean_callable_bool", encoding="utf-8")
                return False

        class EvilBoolCallable:
            def __call__(self, _args: Dict[str, Any]) -> Dict[str, Any]:
                return {"leak": getattr(self, "__class__")}

            def __bool__(self) -> bool:
                outside_canary.write_text("PWNED:evil_callable_bool", encoding="utf-8")
                return False

        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec_cls = _signed_callable_tool(
            registry, runner, tool_id="r10.mod_bool_cls", cap="cap.sec", fn=use_foreign_cls
        )
        clean_bool_callable = CleanBoolCallable()
        spec_clean_bool = _signed_callable_tool(
            registry,
            runner,
            tool_id="r10.clean_bool_callable",
            cap="cap.sec",
            fn=clean_bool_callable,
            permissions=("fs.read",),
        )
        evil_bool_callable = EvilBoolCallable()
        eb_digest = compute_callable_sha256(evil_bool_callable)
        runner.register_trusted_host_callable(
            "r10.evil_bool_callable", evil_bool_callable, required_permissions=["fs.read"]
        )
        spec_evil_bool = ToolSpec(
            tool_id="r10.evil_bool_callable",
            version="1.0.0",
            source="host_trusted",
            binary_hash=eb_digest,
            capabilities=["cap.sec"],
            input_schema={"type": "object", "required": []},
            output_schema={"type": "object", "required": []},
            semantic_contract={"domain": "security"},
            side_effects=["read"],
            required_permissions=["fs.read"],
            runtime_requirements={"callable_name": "r10.evil_bool_callable"},
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "round10-ci",
                "tool_id": "r10.evil_bool_callable",
                "binary_hash": eb_digest,
                "verification_digest": sha256_digest("r10.evil_bool_callable"),
            },
        )
        sign_fixture_tool(registry, spec_evil_bool)
        runner.bind_trusted_host_callable_spec(
            "r10.evil_bool_callable", compute_tool_spec_security_digest(spec_evil_bool)
        )

        spec_imp = _signed_callable_tool(
            registry, runner, tool_id="r10.inline_mod_bool", cap="cap.sec", fn=inline_imp_fn
        )

        sys.modules["evil_r10_bool_exact"] = mod_exact
        sys.modules["evil_r10_bool_pkg"] = mod_pkg
        try:
            armed[0] = True
            self.assertFalse(outside_canary.exists())

            # Subpath A1: class __module__ lookup in _is_stdlib_module_name -> _safe_sys_module_get top package fallback
            self.assertIsNone(validate_trusted_host_callable_hygiene(use_foreign_cls))
            self.assertFalse(outside_canary.exists(), "hygiene invoked ModuleType.__bool__")
            self.assertTrue(compute_callable_sha256(use_foreign_cls).startswith("sha256:"))
            self.assertFalse(outside_canary.exists(), "canonicalizer invoked ModuleType.__bool__")
            rec_cls = runner.run(spec_cls, {}, self.ctx, oracle=lambda d: d["output"]["name"] == "ForeignCls")
            self.assertFalse(outside_canary.exists(), "signed runner invoked ModuleType.__bool__")
            if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
                self.assertEqual(rec_cls.status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_cls.stderr_excerpt)
            else:
                self.assertEqual(rec_cls.status, ExecutionStatus.PASS, rec_cls.stderr_excerpt)

            # Subpath A2: inline import of custom ModuleType subclass in sys.modules
            self.assertIsNone(validate_trusted_host_callable_hygiene(inline_imp_fn))
            self.assertFalse(outside_canary.exists(), "inline import hygiene invoked ModuleType.__bool__")
            self.assertTrue(compute_callable_sha256(inline_imp_fn).startswith("sha256:"))
            self.assertFalse(outside_canary.exists(), "inline import canonicalizer invoked ModuleType.__bool__")
            rec_imp = runner.run(spec_imp, {}, self.ctx, oracle=lambda d: d["output"] == {"ok": True})
            self.assertFalse(outside_canary.exists(), "signed runner inline import invoked ModuleType.__bool__")
            # Hash must differ now that evil_r10_bool_exact is loaded vs registration time -> PERMISSION_DENIED
            self.assertEqual(rec_imp.status, ExecutionStatus.PERMISSION_DENIED)

            # Subpath B: callable instance __bool__ during _verify_trust_and_identity
            rec_clean_bool = runner.run(spec_clean_bool, {}, self.ctx, oracle=lambda d: d["output"] == {"ok": True})
            self.assertFalse(outside_canary.exists(), "clean callable instance __bool__ invoked in host preflight")
            if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
                self.assertEqual(rec_clean_bool.status, ExecutionStatus.PERMISSION_DENIED)
            else:
                self.assertEqual(rec_clean_bool.status, ExecutionStatus.PASS, rec_clean_bool.stderr_excerpt)

            rec_evil_bool = runner.run(spec_evil_bool, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_evil_bool.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertFalse(outside_canary.exists(), "evil callable instance __bool__ invoked in host preflight")
        finally:
            sys.modules.pop("evil_r10_bool_exact", None)
            sys.modules.pop("evil_r10_bool_pkg", None)

    def test_kh_b2_r9_sec_001_path2_enum_hash_colliding_key_eq_zero_side_effects_hmac_signed(self) -> None:
        outside_canary = self.root / "r10_enum_eq_canary.txt"
        armed = [False]

        class CollidingKey:
            def __init__(self, target_name: str) -> None:
                self._target = target_name

            def __hash__(self) -> int:
                return hash(self._target)

            def __eq__(self, other: Any) -> bool:
                if armed[0]:
                    outside_canary.write_text(f"PWNED:{self._target}:{other!r}", encoding="utf-8")
                return False

        class BadKeyEnum(enum.Enum):
            ALPHA = 1

        object.__getattribute__(BadKeyEnum.ALPHA, "__dict__")[CollidingKey("_name_")] = "FORGED"
        object.__getattribute__(BadKeyEnum.ALPHA, "__dict__")[CollidingKey("_value_")] = 999

        def read_bad_enum(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"v": str(BadKeyEnum.ALPHA)}

        class PostMutatedEnum(enum.Enum):
            BETA = "safe"

        holder: Dict[str, Any] = {"member": PostMutatedEnum.BETA}

        def read_signed_enum(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"m": str(holder["member"])}

        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r10.hmac_enum_eq", cap="cap.sec", fn=read_signed_enum
        )

        # Inject hash-colliding key after valid HMAC registration, then arm canary.
        object.__getattribute__(PostMutatedEnum.BETA, "__dict__")[CollidingKey("_name_")] = "EVIL"
        armed[0] = True
        self.assertFalse(outside_canary.exists())

        self.assertEqual(
            validate_trusted_host_callable_hygiene(read_bad_enum),
            "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN",
        )
        self.assertFalse(outside_canary.exists(), "hygiene triggered CollidingKey.__eq__")
        with self.assertRaisesRegex(ValueError, "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN"):
            compute_callable_sha256(read_bad_enum)
        self.assertFalse(outside_canary.exists(), "canonicalizer triggered CollidingKey.__eq__")

        rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN", rec.stderr_excerpt)
        self.assertFalse(outside_canary.exists(), "HMAC-signed runner triggered CollidingKey.__eq__")

    def test_adjacent_colliding_keys_and_custom_mappingproxy_zero_side_effects(self) -> None:
        outside_canary = self.root / "r10_adjacent_canary.txt"
        armed = [False]

        class CollidingKey:
            def __init__(self, target_name: str) -> None:
                self._target = target_name

            def __hash__(self) -> int:
                return hash(self._target)

            def __eq__(self, other: Any) -> bool:
                if armed[0]:
                    outside_canary.write_text(f"PWNED:{self._target}:{other!r}", encoding="utf-8")
                return False

            def __str__(self) -> str:
                if armed[0]:
                    outside_canary.write_text(f"PWNED_STR:{self._target}", encoding="utf-8")
                return self._target

        # (a) Class mappingproxy containing hash-colliding key for __module__
        bad_cls = type("BadCls", (), {CollidingKey("__module__"): "evil", "x": 1})

        def probe_cls(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"n": bad_cls.__name__}

        # (b) cached_property and DynamicClassAttribute instance dicts with colliding keys
        cp = functools.cached_property(lambda self: 1)
        object.__getattribute__(cp, "__dict__")[CollidingKey("func")] = lambda self: 2

        class BadCP:
            attr = cp

        dca = types.DynamicClassAttribute(lambda self: 1)
        object.__getattribute__(dca, "__dict__")[CollidingKey("fget")] = lambda self: 2

        class BadDCA:
            attr = dca

        def probe_cp(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"n": BadCP.__name__}

        def probe_dca(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"n": BadDCA.__name__}

        # (c) ModuleType.__dict__ containing colliding key for __name__
        evil_mod = types.ModuleType("evil_key_mod")
        object.__getattribute__(evil_mod, "__dict__")[CollidingKey("__name__")] = "sys"

        def probe_mod(_args: Dict[str, Any]) -> Dict[str, Any]:
            _ = "modules"
            return {"m": str(type(evil_mod))}

        # (d) Function __globals__ and custom __builtins__ dicts with colliding keys
        def template_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"x": len("abc")}

        bad_globals = {"__builtins__": __builtins__, CollidingKey("__builtins__"): 1}
        fn_bad_globals = types.FunctionType(template_fn.__code__, bad_globals, "fn_bad_globals")

        bad_builtins_dict = {"len": len, CollidingKey("len"): 1}
        fn_bad_builtins = types.FunctionType(
            template_fn.__code__, {"__builtins__": bad_builtins_dict}, "fn_bad_builtins"
        )

        # (e) dict subclass containing CollidingKey (must not call dict(sub_items))
        class SubDict(dict):
            pass

        sub_holder = SubDict({CollidingKey("k"): 1})

        def probe_subdict(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"t": type(sub_holder).__name__}

        # (f) Custom MappingProxyType wrapping EvilMap (must not invoke items() or __getitem__)
        class EvilMap:
            def __getitem__(self, k: Any) -> Any:
                if armed[0]:
                    outside_canary.write_text(f"PWNED_GETITEM:{k!r}", encoding="utf-8")
                return 1

            def items(self) -> Any:
                if armed[0]:
                    outside_canary.write_text("PWNED_ITEMS", encoding="utf-8")
                return [("a", 1)]

        backing_clean: Dict[str, Any] = {"a": 1}
        mutable_holder: Dict[str, Any] = {"proxy": types.MappingProxyType(backing_clean)}

        def probe_proxy(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"len": len(mutable_holder["proxy"])}

        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec_proxy = _signed_callable_tool(
            registry, runner, tool_id="r10.evil_proxy", cap="cap.sec", fn=probe_proxy
        )
        mutable_holder["proxy"] = types.MappingProxyType(EvilMap())

        armed[0] = True
        self.assertFalse(outside_canary.exists())

        for label, fn_target in (
            ("cls_key", probe_cls),
            ("cached_property_key", probe_cp),
            ("dynamic_attr_key", probe_dca),
            ("module_dict_key", probe_mod),
            ("fn_globals_key", fn_bad_globals),
            ("fn_builtins_key", fn_bad_builtins),
        ):
            self.assertEqual(
                validate_trusted_host_callable_hygiene(fn_target),
                "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN",
                label,
            )
            self.assertFalse(outside_canary.exists(), f"hygiene side effect on {label}")
            with self.assertRaisesRegex(ValueError, "CALLABLE_NON_STRING_NAMESPACE_KEY_FORBIDDEN", msg=label):
                compute_callable_sha256(fn_target)
            self.assertFalse(outside_canary.exists(), f"digest side effect on {label}")

        # dict subclass with CollidingKey must fail closed cleanly in hygiene & digest with zero __eq__ calls
        self.assertIsNone(validate_trusted_host_callable_hygiene(probe_subdict))
        self.assertTrue(compute_callable_sha256(probe_subdict).startswith("sha256:"))
        self.assertFalse(outside_canary.exists(), "SubDict triggered CollidingKey.__eq__/__str__")

        self.assertEqual(
            validate_trusted_host_callable_hygiene(probe_proxy),
            "CALLABLE_CUSTOM_MAPPING_PROXY_FORBIDDEN",
        )
        self.assertFalse(outside_canary.exists(), "hygiene invoked EvilMap")
        with self.assertRaisesRegex(ValueError, "CALLABLE_CUSTOM_MAPPING_PROXY_FORBIDDEN"):
            compute_callable_sha256(probe_proxy)
        self.assertFalse(outside_canary.exists(), "canonicalizer invoked EvilMap")
        rec_proxy = runner.run(spec_proxy, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(rec_proxy.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("CALLABLE_CUSTOM_MAPPING_PROXY_FORBIDDEN", rec_proxy.stderr_excerpt)
        self.assertFalse(outside_canary.exists(), "HMAC-signed runner invoked EvilMap")

    def test_clean_regression_logforge_enum_toolwire_mappingproxy_and_dict_subclass(self) -> None:
        class CleanDict(dict):
            def label(self) -> str:
                return "clean"

        backing = {"k": 1, "n": 2}
        proxy = types.MappingProxyType(backing)
        cd = CleanDict({"a": 10})
        wire = ToolWire()
        logforge = LogForge()
        sample = LogScanResult(
            backend="python_oracle",
            disable_simd=False,
            input_bytes=4,
            delim=10,
            offsets=[1],
        )

        def clean_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            res = logforge.scan_delimiters(b"p\nq", delim=10, tier="python_oracle")
            return {
                "proxy": proxy["k"] + proxy["n"],
                "cd": cd["a"],
                "cd_lbl": cd.label(),
                "wire": wire.VERSION,
                "status": ExecutionStatus.PASS.value,
                "sample": len(sample.offsets),
                "scan": res.offsets,
            }

        self.assertIsNone(validate_trusted_host_callable_hygiene(clean_fn))
        registry = ToolRegistry()
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        spec = _signed_callable_tool(
            registry, runner, tool_id="r10.clean_pos", cap="cap.pos", fn=clean_fn
        )
        d0 = compute_callable_sha256(clean_fn)
        rec = runner.run(spec, {}, self.ctx, oracle=lambda d: d["output"]["proxy"] == 3 and d["output"]["cd"] == 10)
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec.stderr_excerpt)
        else:
            self.assertEqual(rec.status, ExecutionStatus.PASS, rec.stderr_excerpt)

        # Mutate CleanDict and MappingProxy backing; both must alter digest & fail closed
        cd["a"] = 99
        d1 = compute_callable_sha256(clean_fn)
        self.assertNotEqual(d1, d0)
        self.assertEqual(runner.run(spec, {}, self.ctx, oracle=lambda _: True).status, ExecutionStatus.PERMISSION_DENIED)

        cd["a"] = 10
        backing["n"] = 999
        d2 = compute_callable_sha256(clean_fn)
        self.assertNotEqual(d2, d0)
        self.assertEqual(runner.run(spec, {}, self.ctx, oracle=lambda _: True).status, ExecutionStatus.PERMISSION_DENIED)


if __name__ == "__main__":
    unittest.main()
