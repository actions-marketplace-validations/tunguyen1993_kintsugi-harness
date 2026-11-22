"""Round-13 remediation tests for Build #2 finding KH-B2-R12-SEC-001.

Verifies primitive-only trust boundary enforcement across `SecureRunner.run()`,
`execute_trusted_host_adapter()`, and exact contract schema extractors so that
caller-supplied `pathlib.Path` / `PurePath` instances (including internally
mutated `Path._raw_paths` / `_parts` / `_str` with custom `__fspath__` hooks)
never execute host side effects (`outside_canary.exists() == False`).
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

from kintsugi.capability.contracts_v2 import AdapterSpec, PortContract
from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    compute_tool_spec_security_digest,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority
from kintsugi.runtime.secure_runner import SecureRunner, probe_linux_landlock_available


_VERIFIER_ID = "ci-round13-verifier"
_VERIFIER_SECRET = "kintsugi-round13-audit-signing-secret-material-64bytes-0123456789"


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


def _make_mutated_posix_path(base: Path, canary: Path) -> Path:
    """Create a genuine `type(p) is Path` instance whose internal state runs `canary` write on `__fspath__`/`__str__`."""

    class _EvilFspath:
        def __fspath__(self) -> str:
            canary.write_text("PATH_FSPATH_FIRED", encoding="utf-8")
            return str(base)

        def __str__(self) -> str:
            canary.write_text("PATH_STR_FIRED", encoding="utf-8")
            return str(base)

    class _EvilStr(str):
        def __fspath__(self) -> str:
            canary.write_text("EVILSTR_FSPATH_FIRED", encoding="utf-8")
            return str(base)

        def __str__(self) -> str:
            canary.write_text("EVILSTR_STR_FIRED", encoding="utf-8")
            return str(base)

        def __add__(self, other: object) -> str:
            canary.write_text("EVILSTR_ADD_FIRED", encoding="utf-8")
            return str(base) + str(other)

    mutated = Path(base)
    evil_obj = _EvilFspath()
    evil_s = _EvilStr(str(base))
    # Python 3.12-3.13+ uses _raw_paths; Python 3.9-3.11 uses _parts / _drv / _root (+ optional _str cache).
    if hasattr(mutated, "_raw_paths"):
        object.__setattr__(mutated, "_raw_paths", [evil_obj])
    if hasattr(mutated, "_parts"):
        object.__setattr__(mutated, "_parts", ["/", evil_obj])
    if hasattr(mutated, "_drv"):
        object.__setattr__(mutated, "_drv", "")
    if hasattr(mutated, "_root"):
        object.__setattr__(mutated, "_root", "/")
    if hasattr(mutated, "_str"):
        object.__setattr__(mutated, "_str", evil_s)
    if hasattr(mutated, "_str"):
        object.__delattr__(mutated, "_str")
    return mutated


class TestRound13Remediation(unittest.TestCase):
    """Independent tests closing KH-B2-R12-SEC-001 across Python 3.9–3.13+."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.outside_canary = self.root / "outside_canary.txt"
        self.safe_file = self.ws / "safe_input.txt"
        self.safe_file.write_text("ok\n", encoding="utf-8")
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kh_b2_r12_sec_001_mutated_posixpath_fspath_blocked_in_argv_and_args_hmac_signed(self) -> None:
        canary = self.outside_canary
        authority = _make_authority()
        runner = SecureRunner(require_os_sandbox=True, attestation_authority=authority)

        script = self.ws / "echo_argv.py"
        script.write_text("import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n", encoding="utf-8")
        os.chmod(script, 0o600)
        spec = ToolSpec(
            tool_id="r13.echo_argv",
            version="1.0.0",
            source="local_script",
            binary_hash=sha256_digest(script.read_bytes()),
            capabilities=["security.round13"],
            required_permissions=["fs.read"],
            entrypoint=str(script),
            trust_status=TrustStatus.DISCOVERED,
        )
        spec = _sign_tool_spec(authority, spec)
        spec.trust_status = TrustStatus.VERIFIED

        evil_path = _make_mutated_posix_path(self.safe_file, canary)

        # 1. Mutated Path in argv=[evil_path]
        rec_argv = runner.run(spec, {}, self.ctx, argv=[evil_path], oracle=lambda _r: True)  # type: ignore[list-item]
        self.assertEqual(rec_argv.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_ARGV_ELEMENT_TYPE", rec_argv.stderr_excerpt)
        self.assertFalse(canary.exists())

        # 2. Mutated Path at top level args={"input_path": evil_path}
        rec_top = runner.run(spec, {"input_path": evil_path}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_top.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_NON_EXACT_DATA_TYPE", rec_top.stderr_excerpt)
        self.assertFalse(canary.exists())

        # 3. Mutated Path nested inside dict args={"nested": {"path": evil_path}}
        rec_nested = runner.run(spec, {"nested": {"path": evil_path}}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_nested.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_NON_EXACT_DATA_TYPE", rec_nested.stderr_excerpt)
        self.assertFalse(canary.exists())

        # 4. Mutated Path nested inside list args={"items": [evil_path]}
        rec_list = runner.run(spec, {"items": [evil_path]}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_list.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_NON_EXACT_DATA_TYPE", rec_list.stderr_excerpt)
        self.assertFalse(canary.exists())

        # 5. Mutated Path inside args["argv"] list
        rec_args_argv = runner.run(spec, {"argv": [evil_path]}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_args_argv.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_NON_EXACT_DATA_TYPE", rec_args_argv.stderr_excerpt)
        self.assertFalse(canary.exists())

    def test_kh_b2_r12_sec_001_mutated_path_blocked_in_adapter_payload_and_contract_fields(self) -> None:
        canary = self.outside_canary
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _benign_ad(payload: dict) -> dict:
            return {"ok": True, "k": payload.get("k")}

        ad_ch = runner.register_trusted_host_adapter("r13.adapter", _benign_ad)
        ad = AdapterSpec(
            adapter_id="r13.adapter",
            version="1.0.0",
            source_port=PortContract(schema_ref="in/v1", semantic_type="text", unit="none"),
            target_port=PortContract(schema_ref="out/v1", semantic_type="text", unit="none"),
            mapping={"fields": {"k": "k"}},
            verification_corpus_hash=_ver_digest("r13-corpus"),
            trust_status=TrustStatus.DISCOVERED,
        )
        ad.verification_attestation = authority.issue_adapter_attestation(
            ad.adapter_id,
            ad.adapter_hash,
            ad.verification_corpus_hash,
            _ver_digest("r13-ver"),
            _VERIFIER_ID,
            callable_hash=ad_ch,
        )
        ad.trust_status = TrustStatus.VERIFIED

        evil_path = _make_mutated_posix_path(self.safe_file, canary)
        with self.assertRaises(PermissionError):
            runner.execute_trusted_host_adapter(ad, {"p": evil_path}, security_context=self.ctx)
        self.assertFalse(canary.exists())

        # Contract fields mutated to contain mutated Path must fail closed without touching Path.
        def _benign(_args: dict) -> dict:
            return {"ok": True}

        ch = runner.register_trusted_host_callable("r13.callable", _benign, required_permissions=["fs.read"])
        spec = ToolSpec(
            tool_id="r13.callable",
            version="1.0.0",
            source="builtin",
            binary_hash=ch,
            capabilities=["security.round13"],
            required_permissions=["fs.read"],
            runtime_requirements={"callable_name": "r13.callable"},
            trust_status=TrustStatus.DISCOVERED,
        )
        spec = _sign_tool_spec(authority, spec)
        spec.trust_status = TrustStatus.VERIFIED

        orig_in = dict(spec.input_schema)
        spec.input_schema = {"p": evil_path}  # type: ignore[dict-item]
        rec_spec_mut = runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_spec_mut.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())
        spec.input_schema = orig_in

        orig_ctx_ws = self.ctx.workspace_root
        self.ctx.workspace_root = evil_path  # type: ignore[assignment]
        rec_ctx_mut = runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(rec_ctx_mut.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())
        self.ctx.workspace_root = orig_ctx_ws

        # Altered MRO check via _SCHEMA_TYPE_MRO_DESCR mock raises TypeError without hooks.
        class _FakeMixin:
            pass

        with mock.patch(
            "kintsugi.capability.schemas._SCHEMA_TYPE_MRO_DESCR",
            new=type("MockDescr", (), {"__get__": staticmethod(lambda _cls, _tp=None: (ToolSpec, _FakeMixin, object))})(),
        ):
            with self.assertRaises(TypeError):
                compute_tool_spec_security_digest(spec)
        self.assertFalse(canary.exists())

    def test_kh_b2_r12_sec_001_even_unmutated_path_objects_rejected_at_trust_boundary(self) -> None:
        authority = _make_authority()
        runner = SecureRunner(
            allow_in_process_callable=False,
            allow_trusted_host_callables=True,
            attestation_authority=authority,
        )

        def _benign(args: dict) -> dict:
            return {"ok": True, "p": args.get("p")}

        ch = runner.register_trusted_host_callable("r13.no_path", _benign, required_permissions=["fs.read"])
        spec = ToolSpec(
            tool_id="r13.no_path",
            version="1.0.0",
            source="builtin",
            binary_hash=ch,
            capabilities=["security.round13"],
            required_permissions=["fs.read"],
            runtime_requirements={"callable_name": "r13.no_path"},
            trust_status=TrustStatus.DISCOVERED,
        )
        spec = _sign_tool_spec(authority, spec)
        spec.trust_status = TrustStatus.VERIFIED
        runner.bind_trusted_host_callable_spec("r13.no_path", compute_tool_spec_security_digest(spec))

        clean_path = Path(self.safe_file)
        pure_path = PurePosixPath("safe_input.txt")

        for p_obj in (clean_path, pure_path):
            r_argv = runner.run(spec, {}, self.ctx, argv=[p_obj], oracle=lambda _r: True)  # type: ignore[list-item]
            self.assertEqual(r_argv.status, ExecutionStatus.PERMISSION_DENIED)
            r_args = runner.run(spec, {"input_path": p_obj}, self.ctx, oracle=lambda _r: True)
            self.assertEqual(r_args.status, ExecutionStatus.PERMISSION_DENIED)
            r_nested = runner.run(spec, {"nested": {"path": p_obj}}, self.ctx, oracle=lambda _r: True)
            self.assertEqual(r_nested.status, ExecutionStatus.PERMISSION_DENIED)

    def test_round13_clean_str_paths_and_regression_preserved(self) -> None:
        authority = _make_authority()
        runner = SecureRunner(require_os_sandbox=True, attestation_authority=authority)

        script = self.ws / "read_str_arg.py"
        script.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "print(json.dumps({'content': Path(sys.argv[1]).read_text(encoding='utf-8').strip()}))\n",
            encoding="utf-8",
        )
        os.chmod(script, 0o600)
        spec = ToolSpec(
            tool_id="r13.read_str",
            version="1.0.0",
            source="local_script",
            binary_hash=sha256_digest(script.read_bytes()),
            capabilities=["security.round13"],
            required_permissions=["fs.read"],
            entrypoint=str(script),
            trust_status=TrustStatus.DISCOVERED,
        )
        spec = _sign_tool_spec(authority, spec)
        spec.trust_status = TrustStatus.VERIFIED

        # Exact str inside workspace passes on Darwin or Landlock-enabled Linux (fails closed ENOSYS otherwise).
        rec_ok = runner.run(
            spec,
            {"input_path": str(self.safe_file)},
            self.ctx,
            argv=[sys.executable, str(script), str(self.safe_file)],
            oracle=lambda r: r.get("output") == {"content": "ok"},
        )
        if sys.platform == "darwin" or (
            sys.platform.startswith("linux") and probe_linux_landlock_available()[0]
        ):
            self.assertEqual(rec_ok.status, ExecutionStatus.PASS)
        else:
            self.assertEqual(rec_ok.status, ExecutionStatus.SANDBOX_UNAVAILABLE)

        # Outside workspace str path still denied fail-closed.
        outside_file = self.root / "outside_secret.txt"
        outside_file.write_text("secret", encoding="utf-8")
        rec_out = runner.run(
            spec,
            {"input_path": str(outside_file)},
            self.ctx,
            argv=[sys.executable, str(script), str(outside_file)],
            oracle=lambda _r: True,
        )
        self.assertEqual(rec_out.status, ExecutionStatus.PERMISSION_DENIED)


if __name__ == "__main__":
    unittest.main()
