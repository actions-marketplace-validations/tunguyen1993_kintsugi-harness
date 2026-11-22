"""Round-14 remediation tests for Build #2 finding KH-B2-R13-SEC-001 and Linux Landlock parity.

Verifies zero-constructor, zero-method, lifecycle-pinned contract handling across
`SecureRunner.run()`, `execute_trusted_host_adapter()`, and `ExecutionReceipt`
creation so that monkeypatching any lifecycle hook on `SecurityContext`, `ToolSpec`,
`PortContract`, `AdapterSpec`, `_CanonicalContractMixin`, or `ExecutionReceipt`
fails closed with `outside_canary.exists() == False`.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

from kintsugi.capability.contracts_v2 import AdapterSpec, PortContract, _CanonicalContractMixin
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    compute_tool_spec_security_digest,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority
from kintsugi.runtime.secure_runner import (
    SecureRunner,
    probe_linux_landlock_available,
)


_VERIFIER_ID = "ci-round14-verifier"
_VERIFIER_SECRET = "kintsugi-round14-audit-signing-secret-material-64bytes-0123456789"
_SRC_ROOT = str(Path(__file__).resolve().parents[2] / "src")


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


def _sign_adapter(authority: AttestationAuthority, ad: AdapterSpec, callable_hash: str) -> AdapterSpec:
    att = authority.issue_adapter_attestation(
        ad.adapter_id,
        ad.adapter_hash,
        ad.verification_corpus_hash,
        _ver_digest(f"adapter:{ad.adapter_id}:{ad.adapter_hash}"),
        _VERIFIER_ID,
        callable_hash=callable_hash,
    )
    ad.verification_attestation = att
    ad.trust_status = TrustStatus.VERIFIED
    return ad


@contextlib.contextmanager
def _patch_cls_attr(cls: type, attr_name: str, replacement: Any) -> Iterator[None]:
    """Patch `cls.<attr_name>` safely using raw `tp_dict` (never used on C `tp_new` slot)."""
    type_dict_descr = type.__dict__["__dict__"]
    raw_dict = type_dict_descr.__get__(cls, type)
    existed = attr_name in raw_dict
    original = raw_dict.get(attr_name)
    setattr(cls, attr_name, replacement)
    try:
        yield
    finally:
        if existed:
            setattr(cls, attr_name, original)
        elif attr_name in type_dict_descr.__get__(cls, type):
            delattr(cls, attr_name)


def _double_ms(payload: dict) -> dict:
    return {"seconds": float(payload["ms"]) / 1000.0}


def _run_isolated_new_hook_probe(ws: Path, canary: Path) -> subprocess.CompletedProcess:
    """Test `__new__` monkeypatching in an isolated Python process (avoids CPython `tp_new` slot corruption)."""
    probe_code = """
import hashlib
import sys
from pathlib import Path

from kintsugi.capability.contracts_v2 import AdapterSpec, PortContract
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    compute_tool_spec_security_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority
from kintsugi.runtime.secure_runner import SecureRunner


def _tag(args: dict) -> dict:
    return {"ok": True}


def _ad_fn(payload: dict) -> dict:
    return {"seconds": float(payload["ms"]) / 1000.0}


def main() -> None:
    ws = Path(sys.argv[1])
    canary = Path(sys.argv[2])
    vid = "ci-r14-new-probe"
    vsec = "kintsugi-round14-audit-signing-secret-material-64bytes-0123456789"
    auth = AttestationAuthority(verifier_keys={vid: vsec})
    ctx = SecurityContext(
        workspace_root=str(ws),
        profile=SecurityProfile.LOCAL_RESEARCH,
        allowed_permissions=["fs.read", "fs.write"],
        network_allowed=False,
        allow_untrusted_native=False,
    )

    runner = SecureRunner(allow_in_process_callable=False, allow_trusted_host_callables=True, require_os_sandbox=True, attestation_authority=auth)
    ch = runner.register_trusted_host_callable("r14.tag_new", _tag, required_permissions=["fs.read"])
    spec = ToolSpec(
        tool_id="r14.tag_new",
        version="1.0.0",
        source="builtin",
        binary_hash=ch,
        capabilities=["security.round14"],
        required_permissions=["fs.read"],
        runtime_requirements={"callable_name": "r14.tag_new"},
        trust_status=TrustStatus.DISCOVERED,
    )
    vd = f"sha256:{hashlib.sha256(b'verify:tag_new').hexdigest()}"
    spec.verification_attestation = auth.issue_attestation(spec.tool_id, spec.binary_hash, vd, vid, spec_digest=compute_tool_spec_security_digest(spec))
    spec.trust_status = TrustStatus.VERIFIED
    runner.bind_trusted_host_callable_spec("r14.tag_new", compute_tool_spec_security_digest(spec))

    ad_runner = SecureRunner(allow_in_process_callable=False, allow_trusted_host_callables=True, require_os_sandbox=True, attestation_authority=auth)
    ad_ch = ad_runner.register_trusted_host_adapter("r14.ms_new", _ad_fn)
    ad = AdapterSpec(
        adapter_id="r14.ms_new",
        version="1.0.0",
        source_port=PortContract(schema_ref="in/v1", semantic_type="duration", unit="ms"),
        target_port=PortContract(schema_ref="out/v1", semantic_type="duration", unit="s"),
        mapping={"fields": {"ms": "seconds"}},
        unit_conversion={"factor": 0.001, "from_unit": "ms", "to_unit": "s"},
        verification_corpus_hash=f"sha256:{hashlib.sha256(b'corpus').hexdigest()}",
        trust_status=TrustStatus.DISCOVERED,
    )
    ad.verification_attestation = auth.issue_adapter_attestation(
        ad.adapter_id, ad.adapter_hash, ad.verification_corpus_hash,
        f"sha256:{hashlib.sha256(b'adver').hexdigest()}", vid, callable_hash=ad_ch,
    )
    ad.trust_status = TrustStatus.VERIFIED

    def _mk_new(label: str):
        def _new_fn(cls, *a, **kw):
            canary.write_text(f"FIRED:{label}", encoding="utf-8")
            return object.__new__(cls)
        return _new_fn

    # 1. SecurityContext.__new__
    SecurityContext.__new__ = _mk_new("SecurityContext.__new__")
    rec = runner.run(spec, {"input_path": "ok.txt"}, ctx, oracle=lambda _r: True)
    assert rec.status == ExecutionStatus.PERMISSION_DENIED, rec
    assert "UNTRUSTED_CONTRACT_CLASS_TAMPERED" in rec.stderr_excerpt, rec.stderr_excerpt
    assert not canary.exists()
    try:
        ad_runner.execute_trusted_host_adapter(ad, {"ms": 100}, security_context=ctx)
        raise AssertionError("adapter unexpectedly succeeded after SecurityContext.__new__ patch")
    except PermissionError as exc:
        assert "UNTRUSTED_CONTRACT_CLASS_TAMPERED" in str(exc), exc
    assert not canary.exists()

    # 2. ToolSpec.__new__
    ToolSpec.__new__ = _mk_new("ToolSpec.__new__")
    assert runner._verify_trust_and_identity(spec)[0] == ExecutionStatus.PERMISSION_DENIED
    assert not canary.exists()

    # 3. AdapterSpec.__new__
    AdapterSpec.__new__ = _mk_new("AdapterSpec.__new__")
    try:
        ad_runner.execute_trusted_host_adapter(ad, {"ms": 100}, security_context=ctx)
        raise AssertionError("adapter unexpectedly succeeded after AdapterSpec.__new__ patch")
    except PermissionError as exc:
        assert "UNTRUSTED_CONTRACT_CLASS_TAMPERED" in str(exc), exc
    assert not canary.exists()

    # 4. ExecutionReceipt.__new__
    ExecutionReceipt.__new__ = _mk_new("ExecutionReceipt.__new__")
    try:
        runner.run(spec, {}, ctx, oracle=lambda _r: True)
        raise AssertionError("runner.run unexpectedly succeeded after ExecutionReceipt.__new__ patch")
    except PermissionError as exc:
        assert "UNTRUSTED_CONTRACT_CLASS_TAMPERED" in str(exc), exc
    assert not canary.exists()
    print("ALL_NEW_HOOK_PROBES_PASSED")


main()
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC_ROOT
    return subprocess.run(
        [sys.executable, "-c", probe_code, str(ws), str(canary)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=False,
    )


class TestRound14Remediation(unittest.TestCase):
    """Independent tests closing KH-B2-R13-SEC-001 across Python 3.9–3.13+."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.outside_canary = self.root / "outside_canary.txt"
        self.safe_file = self.ws / "ok.txt"
        self.safe_file.write_text("ok\n", encoding="utf-8")
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_signed_callable_runner(self) -> tuple[AttestationAuthority, SecureRunner, ToolSpec]:
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            require_os_sandbox=True,
            attestation_authority=authority,
        )

        def _read_tag(args: dict) -> dict:
            return {"ok": True, "input_path": str(args.get("input_path") or "")}

        ch = runner.register_trusted_host_callable(
            "r14.read_tag",
            _read_tag,
            required_permissions=["fs.read"],
        )
        spec = ToolSpec(
            tool_id="r14.read_tag",
            version="1.0.0",
            source="builtin",
            binary_hash=ch,
            capabilities=["security.round14"],
            required_permissions=["fs.read"],
            runtime_requirements={"callable_name": "r14.read_tag"},
            trust_status=TrustStatus.DISCOVERED,
        )
        spec = _sign_tool_spec(authority, spec)
        spec.trust_status = TrustStatus.VERIFIED
        runner.bind_trusted_host_callable_spec("r14.read_tag", compute_tool_spec_security_digest(spec))
        return authority, runner, spec

    def _build_signed_adapter_runner(self) -> tuple[AttestationAuthority, SecureRunner, AdapterSpec]:
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            require_os_sandbox=True,
            attestation_authority=authority,
        )
        ad_ch = runner.register_trusted_host_adapter("r14.ms_to_s", _double_ms)
        ad = AdapterSpec(
            adapter_id="r14.ms_to_s",
            version="1.0.0",
            source_port=PortContract(schema_ref="in/v1", semantic_type="duration", unit="ms"),
            target_port=PortContract(schema_ref="out/v1", semantic_type="duration", unit="s"),
            mapping={"fields": {"ms": "seconds"}},
            unit_conversion={"factor": 0.001, "from_unit": "ms", "to_unit": "s"},
            verification_corpus_hash=_ver_digest("r14-ms-to-s-corpus"),
            trust_status=TrustStatus.DISCOVERED,
        )
        ad = _sign_adapter(authority, ad, ad_ch)
        return authority, runner, ad

    def test_kh_b2_r13_sec_001_security_context_lifecycle_hooks_blocked_zero_canary(self) -> None:
        """Verify all 4 ChatGPT Round-13 PoCs + `validate_path` + `to_dict` cannot fire in host preflight."""
        canary = self.outside_canary
        _, runner, spec = self._build_signed_callable_runner()
        _, ad_runner, ad = self._build_signed_adapter_runner()

        def _bomb_method(label: str):
            def _fn(self_obj: Any, *_a: Any, **_kw: Any) -> Any:
                canary.write_text(f"FIRED:{label}", encoding="utf-8")
                return Path(self.ws)

            return _fn

        def _bomb_setattr(label: str):
            def _set_fn(self_obj: Any, name: str, val: Any) -> None:
                canary.write_text(f"FIRED:{label}", encoding="utf-8")
                object.__setattr__(self_obj, name, val)

            return _set_fn

        hooks = [
            ("__post_init__", _bomb_method("SecurityContext.__post_init__")),
            ("__init__", _bomb_method("SecurityContext.__init__")),
            ("__setattr__", _bomb_setattr("SecurityContext.__setattr__")),
            ("validate_path", _bomb_method("SecurityContext.validate_path")),
            ("to_dict", _bomb_method("SecurityContext.to_dict")),
        ]
        for attr_name, hook_fn in hooks:
            with self.subTest(hook=attr_name):
                with _patch_cls_attr(SecurityContext, attr_name, hook_fn):
                    rec = runner.run(spec, {"input_path": "ok.txt"}, self.ctx, oracle=lambda _r: True)
                    self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
                    self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", rec.stderr_excerpt)
                    self.assertFalse(canary.exists(), f"Canary written on runner.run for {attr_name}")

                    with self.assertRaises(PermissionError) as ad_exc:
                        ad_runner.execute_trusted_host_adapter(ad, {"ms": 1500}, security_context=self.ctx)
                    self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", str(ad_exc.exception))
                    self.assertFalse(canary.exists(), f"Canary written on adapter for {attr_name}")

        # Test all `__new__` hooks in isolated child interpreter (avoids CPython tp_new state lock-in).
        proc = _run_isolated_new_hook_probe(self.ws, canary)
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("ALL_NEW_HOOK_PROBES_PASSED", proc.stdout)
        self.assertFalse(canary.exists())

    def test_kh_b2_r13_sec_001_tool_adapter_receipt_lifecycle_and_no_normalized_class(self) -> None:
        """Verify `_NormalizedToolSpec` is removed and ToolSpec/AdapterSpec/PortContract/Receipt hooks fail closed."""
        import kintsugi.runtime.secure_runner as secure_runner_mod

        self.assertFalse(hasattr(secure_runner_mod, "_NormalizedToolSpec"))
        canary = self.outside_canary
        _, runner, spec = self._build_signed_callable_runner()
        _, ad_runner, ad = self._build_signed_adapter_runner()

        def _bomb_method(label: str):
            def _fn(self_obj: Any, *_a: Any, **_kw: Any) -> Any:
                canary.write_text(f"FIRED:{label}", encoding="utf-8")
                return {}

            return _fn

        def _bomb_setattr(label: str):
            def _set_fn(self_obj: Any, name: str, val: Any) -> None:
                canary.write_text(f"FIRED:{label}", encoding="utf-8")
                object.__setattr__(self_obj, name, val)

            return _set_fn

        for attr_name, fn in [
            ("__post_init__", _bomb_method("ToolSpec.__post_init__")),
            ("__init__", _bomb_method("ToolSpec.__init__")),
            ("__setattr__", _bomb_setattr("ToolSpec.__setattr__")),
            ("to_dict", _bomb_method("ToolSpec.to_dict")),
        ]:
            with _patch_cls_attr(ToolSpec, attr_name, fn):
                rec = runner.run(spec, {"input_path": "ok.txt"}, self.ctx, oracle=lambda _r: True)
                self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", rec.stderr_excerpt)
                self.assertFalse(canary.exists(), f"Canary written for ToolSpec.{attr_name}")

        adapter_targets = [
            (AdapterSpec, "__init__", _bomb_method("AdapterSpec.__init__")),
            (AdapterSpec, "__setattr__", _bomb_setattr("AdapterSpec.__setattr__")),
            (PortContract, "__init__", _bomb_method("PortContract.__init__")),
            (_CanonicalContractMixin, "to_dict", _bomb_method("_CanonicalContractMixin.to_dict")),
        ]
        for cls, attr_name, fn in adapter_targets:
            with _patch_cls_attr(cls, attr_name, fn):
                with self.assertRaises(PermissionError) as exc_ctx:
                    ad_runner.execute_trusted_host_adapter(ad, {"ms": 1500}, security_context=self.ctx)
                self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", str(exc_ctx.exception))
                self.assertFalse(canary.exists(), f"Canary written for {cls.__name__}.{attr_name}")

        for attr_name, fn in [
            ("__post_init__", _bomb_method("ExecutionReceipt.__post_init__")),
            ("__init__", _bomb_method("ExecutionReceipt.__init__")),
            ("__setattr__", _bomb_setattr("ExecutionReceipt.__setattr__")),
        ]:
            with _patch_cls_attr(ExecutionReceipt, attr_name, fn):
                with self.assertRaises(PermissionError) as rec_exc:
                    runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
                self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", str(rec_exc.exception))
                self.assertFalse(canary.exists(), f"Canary written for ExecutionReceipt.{attr_name}")

    def test_round14_mid_preflight_mutation_never_invokes_contract_constructors_or_methods(self) -> None:
        """Even if SecurityContext is mutated AFTER initial extraction, preflight never invokes constructors/methods."""
        import kintsugi.runtime.secure_runner as secure_runner_mod

        canary = self.outside_canary
        _, runner, spec = self._build_signed_callable_runner()
        _, ad_runner, ad = self._build_signed_adapter_runner()

        def _bomb_method(label: str):
            def _fn(self_obj: Any, *_a: Any, **_kw: Any) -> Any:
                canary.write_text(f"MID_FLIGHT:{label}", encoding="utf-8")
                return Path(self.ws)

            return _fn

        def _bomb_setattr(self_obj: Any, name: str, val: Any) -> None:
            canary.write_text("MID_FLIGHT:SecurityContext.__setattr__", encoding="utf-8")
            object.__setattr__(self_obj, name, val)

        orig_load_scars = runner._load_scars
        orig_extract_adapter = secure_runner_mod.extract_exact_adapter_spec_dict

        with contextlib.ExitStack() as stack:
            injected = False

            def _inject_bombs() -> None:
                stack.enter_context(_patch_cls_attr(SecurityContext, "__post_init__", _bomb_method("__post_init__")))
                stack.enter_context(_patch_cls_attr(SecurityContext, "__init__", _bomb_method("__init__")))
                stack.enter_context(_patch_cls_attr(SecurityContext, "__setattr__", _bomb_setattr))
                stack.enter_context(_patch_cls_attr(SecurityContext, "validate_path", _bomb_method("validate_path")))

            def _load_and_mutate(ws_resolved: Path, ctx_obj: Any):
                nonlocal injected
                res = orig_load_scars(ws_resolved, ctx_obj)
                if not injected:
                    injected = True
                    _inject_bombs()
                return res

            with mock.patch.object(runner, "_load_scars", side_effect=_load_and_mutate):
                rec = runner.run(
                    spec,
                    {"input_path": "ok.txt", "nested": {"file": str(self.safe_file)}},
                    self.ctx,
                    oracle=lambda _r: True,
                )
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertFalse(canary.exists())

        canary.unlink(missing_ok=True)
        with contextlib.ExitStack() as stack2:
            def _extract_and_mutate(ad_obj: Any):
                out = orig_extract_adapter(ad_obj)
                stack2.enter_context(_patch_cls_attr(SecurityContext, "__post_init__", _bomb_method("ad.__post_init__")))
                stack2.enter_context(_patch_cls_attr(SecurityContext, "__init__", _bomb_method("ad.__init__")))
                stack2.enter_context(_patch_cls_attr(SecurityContext, "__setattr__", _bomb_setattr))
                stack2.enter_context(_patch_cls_attr(SecurityContext, "validate_path", _bomb_method("ad.validate_path")))
                return out

            with mock.patch.object(secure_runner_mod, "extract_exact_adapter_spec_dict", side_effect=_extract_and_mutate):
                if sys.platform == "darwin" or (
                    sys.platform.startswith("linux") and probe_linux_landlock_available()[0]
                ):
                    out_ad = ad_runner.execute_trusted_host_adapter(ad, {"ms": 2500}, security_context=self.ctx)
                    self.assertEqual(out_ad, {"seconds": 2.5})
                else:
                    with self.assertRaises((RuntimeError, PermissionError)) as ad_exc:
                        ad_runner.execute_trusted_host_adapter(ad, {"ms": 2500}, security_context=self.ctx)
                    self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", str(ad_exc.exception))
            self.assertFalse(canary.exists())

    def test_round14_clean_positive_regression_and_post_exec_toctou_preserved(self) -> None:
        """Clean callable, subprocess, adapter, workspace escape rejection, and POST_EXEC TOCTOU remain intact."""
        authority, runner, spec = self._build_signed_callable_runner()
        _, ad_runner, ad = self._build_signed_adapter_runner()

        # 1. Clean callable execution (or fail-closed ENOSYS=38 when Landlock unavailable on Linux).
        rec_call = runner.run(
            spec,
            {"input_path": "ok.txt"},
            self.ctx,
            oracle=lambda d: d.get("output") == {"ok": True, "input_path": "ok.txt"},
        )
        if sys.platform == "darwin" or (
            sys.platform.startswith("linux") and probe_linux_landlock_available()[0]
        ):
            self.assertEqual(rec_call.status, ExecutionStatus.PASS)
        else:
            self.assertEqual(rec_call.status, ExecutionStatus.PERMISSION_DENIED)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", rec_call.stderr_excerpt)

        # 2. Clean subprocess execution.
        script = self.ws / "echo_ok.py"
        script.write_text("import json\nprint(json.dumps({'r14': 'ok'}))\n", encoding="utf-8")
        os.chmod(script, 0o600)
        sub_spec = ToolSpec(
            tool_id="r14.echo_sub",
            version="1.0.0",
            source="local_script",
            binary_hash=sha256_digest(script.read_bytes()),
            capabilities=["security.round14"],
            required_permissions=["fs.read"],
            entrypoint=str(script),
            trust_status=TrustStatus.DISCOVERED,
        )
        sub_spec = _sign_tool_spec(authority, sub_spec)
        sub_spec.trust_status = TrustStatus.VERIFIED
        rec_sub = runner.run(
            sub_spec,
            {"input_path": str(self.safe_file)},
            self.ctx,
            argv=[sys.executable, str(script)],
            oracle=lambda d: d.get("output") == {"r14": "ok"},
        )
        if sys.platform == "darwin" or (
            sys.platform.startswith("linux") and probe_linux_landlock_available()[0]
        ):
            self.assertEqual(rec_sub.status, ExecutionStatus.PASS)
        else:
            self.assertEqual(rec_sub.status, ExecutionStatus.SANDBOX_UNAVAILABLE)

        # 3. Clean adapter execution + Linux Landlock exception parity.
        if sys.platform == "darwin" or (
            sys.platform.startswith("linux") and probe_linux_landlock_available()[0]
        ):
            self.assertEqual(
                ad_runner.execute_trusted_host_adapter(ad, {"ms": 2500}, security_context=self.ctx),
                {"seconds": 2.5},
            )
        else:
            with self.assertRaises((RuntimeError, PermissionError)) as ad_exc:
                ad_runner.execute_trusted_host_adapter(ad, {"ms": 2500}, security_context=self.ctx)
            self.assertIn("SANDBOX_LINUX_LANDLOCK_FAILED", str(ad_exc.exception))

        # 4. Workspace escape path blocked via pure standalone `_validate_workspace_path_str`.
        rec_esc = runner.run(spec, {"input_path": "../outside_secret.txt"}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_esc.status, ExecutionStatus.PERMISSION_DENIED)

        # 5. Mid-flight TOCTOU still caught at POST_EXEC.
        inproc = SecureRunner(
            allow_in_process_callable=True,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _pure(_args: dict) -> dict:
            return {"ok": True}

        mut_ch = inproc.register_trusted_host_callable("r14.toctou_mut", _pure, required_permissions=["fs.read"])
        mut_spec = ToolSpec(
            tool_id="r14.toctou_mut",
            version="1.0.0",
            source="builtin",
            binary_hash=mut_ch,
            capabilities=["security.round14"],
            required_permissions=["fs.read"],
            runtime_requirements={"callable_name": "r14.toctou_mut"},
            trust_status=TrustStatus.DISCOVERED,
        )
        mut_spec = _sign_tool_spec(authority, mut_spec)
        mut_spec.trust_status = TrustStatus.VERIFIED
        inproc.bind_trusted_host_callable_spec("r14.toctou_mut", compute_tool_spec_security_digest(mut_spec))

        def _mutate_mid_flight(*_a: Any, **_kw: Any):
            mut_spec.trust_status = TrustStatus.QUARANTINED
            return 0, {"ok": True}, '{"ok": true}', "", False

        with mock.patch.object(inproc, "_execute_callable_bounded", side_effect=_mutate_mid_flight):
            rec_mut = inproc.run(mut_spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_mut.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TOCTOU_POST_EXEC_", rec_mut.stderr_excerpt)


if __name__ == "__main__":
    unittest.main()
