"""Round-12 remediation tests for Build #2 findings KH-B2-R11-COMPAT-001 and KH-B2-R11-SEC-002.

Verifies cross-version Python 3.9–3.13+ bytecode scanning immune to runtime
`dis` monkeypatching, and verifies zero-hook exact contract normalization across
`ToolSpec`, `SecurityContext`, `AdapterSpec`, `AttestationAuthority`, and
`SecureRunner` entrypoints with `outside_canary.exists() == False`.
"""

from __future__ import annotations

import dis
import hashlib
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from kintsugi.capability.contracts_v2 import AdapterSpec, PortContract
from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    compute_tool_spec_security_digest,
    has_valid_verification_attestation,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority
from kintsugi.runtime.secure_runner import (
    SecureRunner,
    _IMPORT_NAME_OP,
    _build_inline_cache_table,
    _iter_bytecode_opargs,
    compute_callable_sha256,
    probe_linux_landlock_available,
    validate_trusted_host_callable_hygiene,
)
from kintsugi.tools.log_forge import scan_delimiters_python


_VERIFIER_ID = "ci-round12-verifier"
_VERIFIER_SECRET = "kintsugi-round12-audit-signing-secret-material-64bytes-0123456789"


def _make_authority() -> AttestationAuthority:
    return AttestationAuthority(verifier_keys={_VERIFIER_ID: _VERIFIER_SECRET})


def _ver_digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode('utf-8')).hexdigest()}"


def _sign_tool_spec(authority: AttestationAuthority, spec: ToolSpec) -> ToolSpec:
    att = authority.issue_attestation(
        spec.tool_id,
        spec.binary_hash,
        _ver_digest(f"verify:{spec.tool_id}:{spec.binary_hash}"),
        _VERIFIER_ID,
        spec_digest=compute_tool_spec_security_digest(spec),
    )
    spec.verification_attestation = att
    return spec


def _register_and_sign_callable(
    runner: SecureRunner,
    authority: AttestationAuthority,
    tool_id: str,
    fn: object,
) -> ToolSpec:
    callable_hash = runner.register_trusted_host_callable(
        tool_id, fn, required_permissions=["fs.read"]  # type: ignore[arg-type]
    )
    spec = ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="builtin",
        binary_hash=callable_hash,
        capabilities=["security.round12"],
        required_permissions=["fs.read"],
        runtime_requirements={"callable_name": tool_id},
        trust_status=TrustStatus.DISCOVERED,
    )
    spec = _sign_tool_spec(authority, spec)
    spec.trust_status = TrustStatus.VERIFIED
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


class TestRound12Remediation(unittest.TestCase):
    """Independent regression tests for Round-12 Build #2 security and compatibility closures."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.outside_canary = self.root / "outside_canary.txt"
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kh_b2_r11_compat_001_bytecode_decoder_py313_and_dis_monkeypatch(self) -> None:
        canary = self.outside_canary
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _clean_fn(args: dict) -> dict:
            return {"value": int(args.get("x", 0)) + 1}

        def _evil_inline_mmap(_args: dict) -> dict:
            import mmap  # noqa: F401

            return {"bad": True}

        def _evil_extended_import(_args: dict) -> dict:
            v000 = 0
            v001 = 1
            v002 = 2
            v003 = 3
            v004 = 4
            v005 = 5
            items = [f"k{i}" for i in range(4)]
            # Pad co_names beyond 256 entries so CPython emits EXTENDED_ARG before IMPORT_NAME.
            d = {}
            d.a00 = d.a01 = d.a02 = d.a03 = d.a04 = d.a05 = d.a06 = d.a07 = 1  # type: ignore[attr-defined]
            d.a08 = d.a09 = d.a10 = d.a11 = d.a12 = d.a13 = d.a14 = d.a15 = 1  # type: ignore[attr-defined]
            d.a16 = d.a17 = d.a18 = d.a19 = d.a20 = d.a21 = d.a22 = d.a23 = 1  # type: ignore[attr-defined]
            d.a24 = d.a25 = d.a26 = d.a27 = d.a28 = d.a29 = d.a30 = d.a31 = 1  # type: ignore[attr-defined]
            d.a32 = d.a33 = d.a34 = d.a35 = d.a36 = d.a37 = d.a38 = d.a39 = 1  # type: ignore[attr-defined]
            d.a40 = d.a41 = d.a42 = d.a43 = d.a44 = d.a45 = d.a46 = d.a47 = 1  # type: ignore[attr-defined]
            d.a48 = d.a49 = d.a50 = d.a51 = d.a52 = d.a53 = d.a54 = d.a55 = 1  # type: ignore[attr-defined]
            d.a56 = d.a57 = d.a58 = d.a59 = d.a60 = d.a61 = d.a62 = d.a63 = 1  # type: ignore[attr-defined]
            d.a64 = d.a65 = d.a66 = d.a67 = d.a68 = d.a69 = d.a70 = d.a71 = 1  # type: ignore[attr-defined]
            d.a72 = d.a73 = d.a74 = d.a75 = d.a76 = d.a77 = d.a78 = d.a79 = 1  # type: ignore[attr-defined]
            d.a80 = d.a81 = d.a82 = d.a83 = d.a84 = d.a85 = d.a86 = d.a87 = 1  # type: ignore[attr-defined]
            d.a88 = d.a89 = d.a90 = d.a91 = d.a92 = d.a93 = d.a94 = d.a95 = 1  # type: ignore[attr-defined]
            d.a96 = d.a97 = d.a98 = d.a99 = d.b00 = d.b01 = d.b02 = d.b03 = 1  # type: ignore[attr-defined]
            d.b04 = d.b05 = d.b06 = d.b07 = d.b08 = d.b09 = d.b10 = d.b11 = 1  # type: ignore[attr-defined]
            d.b12 = d.b13 = d.b14 = d.b15 = d.b16 = d.b17 = d.b18 = d.b19 = 1  # type: ignore[attr-defined]
            d.b20 = d.b21 = d.b22 = d.b23 = d.b24 = d.b25 = d.b26 = d.b27 = 1  # type: ignore[attr-defined]
            d.b28 = d.b29 = d.b30 = d.b31 = d.b32 = d.b33 = d.b34 = d.b35 = 1  # type: ignore[attr-defined]
            d.b36 = d.b37 = d.b38 = d.b39 = d.b40 = d.b41 = d.b42 = d.b43 = 1  # type: ignore[attr-defined]
            d.b44 = d.b45 = d.b46 = d.b47 = d.b48 = d.b49 = d.b50 = d.b51 = 1  # type: ignore[attr-defined]
            d.b52 = d.b53 = d.b54 = d.b55 = d.b56 = d.b57 = d.b58 = d.b59 = 1  # type: ignore[attr-defined]
            d.b60 = d.b61 = d.b62 = d.b63 = d.b64 = d.b65 = d.b66 = d.b67 = 1  # type: ignore[attr-defined]
            d.b68 = d.b69 = d.b70 = d.b71 = d.b72 = d.b73 = d.b74 = d.b75 = 1  # type: ignore[attr-defined]
            d.b76 = d.b77 = d.b78 = d.b79 = d.b80 = d.b81 = d.b82 = d.b83 = 1  # type: ignore[attr-defined]
            d.b84 = d.b85 = d.b86 = d.b87 = d.b88 = d.b89 = d.b90 = d.b91 = 1  # type: ignore[attr-defined]
            d.b92 = d.b93 = d.b94 = d.b95 = d.b96 = d.b97 = d.b98 = d.b99 = 1  # type: ignore[attr-defined]
            d.c00 = d.c01 = d.c02 = d.c03 = d.c04 = d.c05 = d.c06 = d.c07 = 1  # type: ignore[attr-defined]
            d.c08 = d.c09 = d.c10 = d.c11 = d.c12 = d.c13 = d.c14 = d.c15 = 1  # type: ignore[attr-defined]
            d.c16 = d.c17 = d.c18 = d.c19 = d.c20 = d.c21 = d.c22 = d.c23 = 1  # type: ignore[attr-defined]
            d.c24 = d.c25 = d.c26 = d.c27 = d.c28 = d.c29 = d.c30 = d.c31 = 1  # type: ignore[attr-defined]
            d.c32 = d.c33 = d.c34 = d.c35 = d.c36 = d.c37 = d.c38 = d.c39 = 1  # type: ignore[attr-defined]
            d.c40 = d.c41 = d.c42 = d.c43 = d.c44 = d.c45 = d.c46 = d.c47 = 1  # type: ignore[attr-defined]
            d.c48 = d.c49 = d.c50 = d.c51 = d.c52 = d.c53 = d.c54 = d.c55 = 1  # type: ignore[attr-defined]
            d.c56 = d.c57 = d.c58 = d.c59 = d.c60 = d.c61 = d.c62 = d.c63 = 1  # type: ignore[attr-defined]
            import importlib  # noqa: F401

            return {"items": items, "sum": v000 + v001 + v002 + v003 + v004 + v005}

        def _fake_py313_4tuple_unpack(_raw_code: bytes):
            canary.write_text("DIS_HOOK_FIRED", encoding="utf-8")
            yield (0, 0, None, None)

        spec_clean = _register_and_sign_callable(runner, authority, "r12.clean_fn", _clean_fn)
        self.assertIsNone(validate_trusted_host_callable_hygiene(_clean_fn))
        self.assertIn("mmap", _evil_inline_mmap.__code__.co_names)
        self.assertGreater(len(_evil_extended_import.__code__.co_names), 256)

        with mock.patch.object(dis, "_unpack_opargs", side_effect=_fake_py313_4tuple_unpack):
            h_clean = compute_callable_sha256(_clean_fn)
            self.assertEqual(h_clean, spec_clean.binary_hash)
            self.assertIsNone(validate_trusted_host_callable_hygiene(_clean_fn))
            rec_ok = runner.run(
                spec_clean,
                {"x": 41},
                self.ctx,
                oracle=lambda r: r.get("output") == {"value": 42},
            )
            if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
                self.assertEqual(rec_ok.status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_ok.stderr_excerpt)
            else:
                self.assertEqual(rec_ok.status, ExecutionStatus.PASS)
            mmap_err = validate_trusted_host_callable_hygiene(_evil_inline_mmap)
            ext_err = validate_trusted_host_callable_hygiene(_evil_extended_import)
            self.assertIsNotNone(mmap_err)
            self.assertIsNotNone(ext_err)
            self.assertIn("MMAP", str(mmap_err).upper())
            self.assertIn("importlib", str(ext_err))
        self.assertFalse(canary.exists())

        # Verify Python 3.13 dict-style _inline_cache_entries builder and inline-cache skipping.
        load_global_op = int(dis.opmap["LOAD_GLOBAL"])
        cache_tbl = _build_inline_cache_table(
            {"LOAD_GLOBAL": 4, "IMPORT_NAME": 0}, dis.opmap
        )
        self.assertEqual(cache_tbl[load_global_op], 4)
        fake_bytecode = bytes([
            load_global_op, 1,
            _IMPORT_NAME_OP, 2,
            0, 0,
            0, 0,
            0, 0,
        ])
        with mock.patch("kintsugi.runtime.secure_runner._INLINE_CACHE_ENTRIES", cache_tbl):
            with mock.patch("kintsugi.runtime.secure_runner._DEOP_MAP", tuple(range(256))):
                ops_seen = list(_iter_bytecode_opargs(fake_bytecode))
        self.assertEqual(len(ops_seen), 1)
        self.assertEqual(ops_seen[0][1], load_global_op)
        self.assertFalse(canary.exists())

    def test_kh_b2_r11_sec_002_evil_tool_spec_subclass_signed_hmac_blocked_zero_side_effects(self) -> None:
        canary = self.outside_canary
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _benign(_args: dict) -> dict:
            return {"ok": True}

        callable_hash = runner.register_trusted_host_callable(
            "r12.signed_sub_base", _benign, required_permissions=["fs.read"]
        )

        class EvilToolSpec(ToolSpec):
            @property
            def tool_id(self) -> str:  # type: ignore[override]
                canary.write_text("EVIL_TOOLSPEC_TOOL_ID", encoding="utf-8")
                return "r12.signed_sub_base"

            @property
            def runtime_requirements(self) -> dict:  # type: ignore[override]
                canary.write_text("EVIL_TOOLSPEC_REQS", encoding="utf-8")
                return {"callable_name": "r12.signed_sub_base"}

            @property
            def verification_attestation(self):  # type: ignore[override]
                canary.write_text("EVIL_TOOLSPEC_ATT", encoding="utf-8")
                return self._signed_att

            def to_dict(self) -> dict:
                canary.write_text("EVIL_TOOLSPEC_TO_DICT", encoding="utf-8")
                return {}

        base_spec = ToolSpec(
            tool_id="r12.signed_sub_base",
            version="1.0.0",
            source="builtin",
            binary_hash=callable_hash,
            capabilities=["security.round12"],
            required_permissions=["fs.read"],
            runtime_requirements={"callable_name": "r12.signed_sub_base"},
            trust_status=TrustStatus.DISCOVERED,
        )
        base_digest = compute_tool_spec_security_digest(base_spec)
        att = authority.issue_attestation(
            base_spec.tool_id,
            base_spec.binary_hash,
            _ver_digest("evil-sub-verify"),
            _VERIFIER_ID,
            spec_digest=base_digest,
        )
        evil_spec = ToolSpec.__new__(EvilToolSpec)
        object.__setattr__(evil_spec, "__dict__", {
            "tool_id": "r12.signed_sub_base",
            "version": "1.0.0",
            "source": "builtin",
            "binary_hash": callable_hash,
            "capabilities": ["security.round12"],
            "input_schema": {},
            "output_schema": {},
            "semantic_contract": {},
            "preconditions": [],
            "postconditions": [],
            "side_effects": [],
            "required_permissions": ["fs.read"],
            "runtime_requirements": {"callable_name": "r12.signed_sub_base"},
            "trust_status": TrustStatus.VERIFIED,
            "latency_estimate_ms": 0.0,
            "memory_estimate_mb": 0.0,
            "api_token_estimate": 0,
            "verification_attestation": att,
            "provenance": {},
            "entrypoint": None,
            "command": None,
            "schema": "ToolSpec/1",
            "_signed_att": att,
        })
        runner.bind_trusted_host_callable_spec("r12.signed_sub_base", base_digest)

        with self.assertRaises(TypeError):
            compute_tool_spec_security_digest(evil_spec)
        self.assertFalse(canary.exists())

        status, tid, reason = runner._verify_trust_and_identity(evil_spec)
        self.assertEqual(status, ExecutionStatus.PERMISSION_DENIED)
        self.assertEqual(tid, "")
        self.assertIn("UNTRUSTED_TOOL_SPEC_SUBCLASS_FORBIDDEN", reason)
        self.assertFalse(canary.exists())

        rec = runner.run(evil_spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

    def test_kh_b2_r11_sec_002_class_tamper_and_non_exact_fields_blocked(self) -> None:
        canary = self.outside_canary
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _benign(_args: dict) -> dict:
            return {"ok": True}

        spec = _register_and_sign_callable(runner, authority, "r12.class_tamper", _benign)

        # 1. Class-level descriptor replacement on ToolSpec must fail closed without firing.
        @property
        def _evil_class_prop(self) -> str:
            canary.write_text("CLASS_PROP_FIRED", encoding="utf-8")
            return "r12.class_tamper"

        try:
            setattr(ToolSpec, "tool_id", _evil_class_prop)
            with self.assertRaises(TypeError):
                compute_tool_spec_security_digest(spec)
            rec_cls = runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
            self.assertEqual(rec_cls.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", rec_cls.stderr_excerpt)
            self.assertFalse(canary.exists())
        finally:
            delattr(ToolSpec, "tool_id")

        # 2. Subclassed builtin fields & colliding dict keys inside genuinely signed ToolSpec must fail closed.
        class EvilStr(str):
            def strip(self, *args, **kwargs):
                canary.write_text("EVIL_STR_STRIP", encoding="utf-8")
                return super().strip(*args, **kwargs)

            def lower(self):
                canary.write_text("EVIL_STR_LOWER", encoding="utf-8")
                return super().lower()

        class EvilDict(dict):
            def items(self):
                canary.write_text("EVIL_DICT_ITEMS", encoding="utf-8")
                return super().items()

        class CollidingKey(str):
            def __hash__(self) -> int:
                return hash("verifier_id")

            def __eq__(self, other: object) -> bool:
                canary.write_text("COLLIDING_KEY_EQ", encoding="utf-8")
                return False

        orig_att = dict(spec.verification_attestation or {})
        orig_digest = compute_tool_spec_security_digest(spec)
        spec.verification_attestation = EvilDict(orig_att)  # type: ignore[assignment]
        rec_ed = runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_ed.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

        att_colliding = {k: v for k, v in orig_att.items() if k != "verifier_id"}
        att_colliding[CollidingKey("not_verifier")] = "x"  # type: ignore[index]
        spec.verification_attestation = att_colliding
        self.assertFalse(has_valid_verification_attestation(spec.verification_attestation, spec.binary_hash, spec.tool_id))
        self.assertFalse(authority.verify_attestation(spec.verification_attestation, expected_tool_id=spec.tool_id, expected_binary_hash=spec.binary_hash, expected_spec_digest=orig_digest))
        rec_ck = runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_ck.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

        spec.verification_attestation = orig_att
        spec.tool_id = EvilStr(spec.tool_id)  # type: ignore[assignment]
        rec_es = runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_es.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

    def test_kh_b2_r11_sec_002_evil_security_context_adapter_spec_and_args_blocked(self) -> None:
        canary = self.outside_canary
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _benign(args: dict) -> dict:
            return {"ok": args.get("n", 0)}

        spec = _register_and_sign_callable(runner, authority, "r12.input_barrier", _benign)

        class EvilSecurityContext(SecurityContext):
            @property
            def workspace_root(self) -> str:  # type: ignore[override]
                canary.write_text("EVIL_CTX_WS", encoding="utf-8")
                return self._real_ws

            @property
            def policy_hash(self) -> str:  # type: ignore[override]
                canary.write_text("EVIL_CTX_POL", encoding="utf-8")
                return self._real_pol

        evil_ctx = SecurityContext.__new__(EvilSecurityContext)
        object.__setattr__(evil_ctx, "__dict__", {
            "workspace_root": str(self.ws),
            "profile": SecurityProfile.LOCAL_RESEARCH,
            "allowed_permissions": ["fs.read"],
            "network_allowed": False,
            "allow_untrusted_native": False,
            "policy_hash": self.ctx.policy_hash,
            "schema": "SecurityContext/1",
            "_real_ws": str(self.ws),
            "_real_pol": self.ctx.policy_hash,
        })
        rec_ctx = runner.run(spec, {}, evil_ctx, oracle=lambda _r: True)
        self.assertEqual(rec_ctx.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

        class EvilDict(dict):
            def __bool__(self) -> bool:
                canary.write_text("EVIL_ARGS_BOOL", encoding="utf-8")
                return True

            def items(self):
                canary.write_text("EVIL_ARGS_ITEMS", encoding="utf-8")
                return super().items()

        class EvilStr(str):
            def strip(self, *args, **kwargs):
                canary.write_text("EVIL_ARG_STR", encoding="utf-8")
                return super().strip(*args, **kwargs)

        for call_kwargs in (
            {"args": EvilDict({"n": 1})},
            {"args": {"nested": EvilStr("abc")}},
            {"task_id": EvilStr("task-1")},
            {"plan_hash": EvilStr(spec.binary_hash)},
            {"argv": [EvilStr("echo")]},
            {"timeout_seconds": True},
        ):
            rec_in = runner.run(
                spec,
                call_kwargs.get("args", {}),  # type: ignore[arg-type]
                self.ctx,
                task_id=call_kwargs.get("task_id", ""),  # type: ignore[arg-type]
                plan_hash=call_kwargs.get("plan_hash"),  # type: ignore[arg-type]
                argv=call_kwargs.get("argv"),  # type: ignore[arg-type]
                timeout_seconds=call_kwargs.get("timeout_seconds"),  # type: ignore[arg-type]
                oracle=lambda _r: True,
            )
            self.assertEqual(rec_in.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertFalse(canary.exists())

        # EvilAdapterSpec subclass + EvilDict payload must be rejected before descriptor reads.
        def _benign_adapter(payload: dict) -> dict:
            return {"out": payload.get("k")}

        ad_callable_hash = runner.register_trusted_host_adapter("r12.adapter", _benign_adapter)
        src_p = PortContract(schema_ref="in/v1", semantic_type="json", unit="ms")
        dst_p = PortContract(schema_ref="out/v1", semantic_type="json", unit="s")
        good_ad = AdapterSpec(
            adapter_id="r12.adapter",
            version="1.0.0",
            source_port=src_p,
            target_port=dst_p,
            mapping={"fields": {"x": "y"}},
            unit_conversion={"factor": 0.001, "from_unit": "ms", "to_unit": "s"},
            verification_corpus_hash=_ver_digest("r12-corpus"),
            trust_status=TrustStatus.DISCOVERED,
        )
        ad_att = authority.issue_adapter_attestation(
            good_ad.adapter_id,
            good_ad.adapter_hash,
            good_ad.verification_corpus_hash,
            _ver_digest("r12-adapter-ver"),
            _VERIFIER_ID,
            callable_hash=ad_callable_hash,
        )

        class EvilAdapterSpec(AdapterSpec):
            @property
            def adapter_id(self) -> str:  # type: ignore[override]
                canary.write_text("EVIL_ADAPTER_ID", encoding="utf-8")
                return "r12.adapter"

        evil_ad = AdapterSpec.__new__(EvilAdapterSpec)
        object.__setattr__(evil_ad, "__dict__", {
            **object.__getattribute__(good_ad, "__dict__"),
            "trust_status": TrustStatus.VERIFIED,
            "verification_attestation": ad_att,
        })
        with self.assertRaises(PermissionError):
            runner.execute_trusted_host_adapter(evil_ad, {"k": 1}, security_context=self.ctx)
        self.assertFalse(canary.exists())

        good_ad.verification_attestation = ad_att
        good_ad.trust_status = TrustStatus.VERIFIED
        with self.assertRaises(PermissionError):
            runner.execute_trusted_host_adapter(good_ad, EvilDict({"k": 1}), security_context=self.ctx)
        self.assertFalse(canary.exists())

    def test_round12_clean_positive_regression_and_toctou_preserved(self) -> None:
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _log_tool(args: dict) -> dict:
            return scan_delimiters_python(bytes(str(args.get("payload", "")), "utf-8"))

        spec = _register_and_sign_callable(runner, authority, "r12.log_scan", _log_tool)
        # Digest via exact ToolSpec equals digest via plain dict.
        self.assertEqual(
            compute_tool_spec_security_digest(spec),
            compute_tool_spec_security_digest(spec.to_dict()),
        )

        rec_ok = runner.run(
            spec,
            {"payload": "a\nb\nc\n"},
            self.ctx,
            oracle=lambda r: r["output"] == [1, 3, 5],
        )
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            self.assertEqual(rec_ok.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_ok.stderr_excerpt)
        else:
            self.assertEqual(rec_ok.status, ExecutionStatus.PASS)

        # Clean AdapterSpec regression works end-to-end inside child isolation.
        def _ms_to_s(payload: dict) -> dict:
            return {"seconds": payload["ms"] / 1000.0}

        ad_ch = runner.register_trusted_host_adapter("r12.ms_to_s", _ms_to_s)
        ad = AdapterSpec(
            adapter_id="r12.ms_to_s",
            version="1.0.0",
            source_port=PortContract(schema_ref="in/v1", semantic_type="duration", unit="ms"),
            target_port=PortContract(schema_ref="out/v1", semantic_type="duration", unit="s"),
            mapping={"fields": {"ms": "seconds"}},
            unit_conversion={"factor": 0.001, "from_unit": "ms", "to_unit": "s"},
            verification_corpus_hash=_ver_digest("ms-to-s-corpus"),
            trust_status=TrustStatus.DISCOVERED,
        )
        ad.verification_attestation = authority.issue_adapter_attestation(
            ad.adapter_id,
            ad.adapter_hash,
            ad.verification_corpus_hash,
            _ver_digest("ms-to-s-ver"),
            _VERIFIER_ID,
            callable_hash=ad_ch,
        )
        ad.trust_status = TrustStatus.VERIFIED
        if sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]:
            with self.assertRaises((RuntimeError, PermissionError)) as ad_exc:
                runner.execute_trusted_host_adapter(ad, {"ms": 2500}, security_context=self.ctx)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", str(ad_exc.exception))
        else:
            out_ad = runner.execute_trusted_host_adapter(ad, {"ms": 2500}, security_context=self.ctx)
            self.assertEqual(out_ad, {"seconds": 2.5})

        # Mid-flight ToolSpec trust mutation still caught by POST_EXEC TOCTOU verification.
        inproc = SecureRunner(
            allow_in_process_callable=True,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _pure(_args: dict) -> dict:
            return {"ok": True}

        mut_spec = _register_and_sign_callable(inproc, authority, "r12.toctou_mut", _pure)

        def _mutate_mid_flight(*_a: object, **_kw: object):
            mut_spec.trust_status = TrustStatus.QUARANTINED
            return 0, {"ok": True}, '{"ok": true}', "", False

        with mock.patch.object(inproc, "_execute_callable_bounded", side_effect=_mutate_mid_flight):
            rec_mut = inproc.run(mut_spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_mut.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TOCTOU_POST_EXEC_", rec_mut.stderr_excerpt)

        # Clean subprocess file hash check preserved.
        script_path = self.ws / "echo_ok.py"
        script_path.write_text("import json\nprint(json.dumps({'ok': True}))\n", encoding="utf-8")
        os.chmod(script_path, 0o600)
        sub_spec = ToolSpec(
            tool_id="r12.sub_ok",
            version="1.0.0",
            source="local_script",
            binary_hash=sha256_digest(script_path.read_bytes()),
            capabilities=["demo.sub"],
            required_permissions=["fs.read"],
            entrypoint=str(script_path),
            trust_status=TrustStatus.DISCOVERED,
        )
        sub_spec = _sign_tool_spec(authority, sub_spec)
        sub_spec.trust_status = TrustStatus.VERIFIED
        sub_runner = SecureRunner(require_os_sandbox=True, attestation_authority=authority)
        rec_sub = sub_runner.run(sub_spec, {}, self.ctx, oracle=lambda r: r["output"] == {"ok": True})
        if sys.platform == "darwin":
            self.assertEqual(rec_sub.status, ExecutionStatus.PASS)
        else:
            self.assertEqual(rec_sub.status, ExecutionStatus.SANDBOX_UNAVAILABLE)


if __name__ == "__main__":
    unittest.main()
