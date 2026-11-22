"""Independent regression probes for Build #2 Round-4 API & execution boundary gates."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

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
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.composition.adapter_synthesizer import AdapterProposalStatus, AdapterSynthesizer
from kintsugi.composition.composition_verifier import CompositionVerifier
from kintsugi.composition.tool_composer import ToolComposer, _validate_adapter_candidate
from kintsugi.runtime.secure_runner import SecureRunner

try:
    from fixture_attestation import sign_fixture_adapter, sign_fixture_tool
except ImportError:  # pragma: no cover
    from tests.fixture_attestation import sign_fixture_adapter, sign_fixture_tool

_R4_KEY = b"kintsugi-round4-independent-fixture-hmac-key"


def _authority() -> AttestationAuthority:
    return AttestationAuthority(
        {
            "round4-ci": _R4_KEY,
            "kintsugi.composition_oracle": _R4_KEY,
        }
    )


def _signed_adapter(
    registry: ToolRegistry,
    adapter_id: str,
    src: PortContract,
    dst: PortContract,
    *,
    callable_hash: str = "",
) -> AdapterSpec:
    draft = AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=src,
        target_port=dst,
        mapping={"fields": {"ns": "ms"}},
        unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
        verification_corpus_hash=sha256_digest("corpus:" + adapter_id),
        trust_status=TrustStatus.DISCOVERED,
    )
    verified = AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=src,
        target_port=dst,
        mapping={"fields": {"ns": "ms"}},
        unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
        verification_corpus_hash=draft.verification_corpus_hash,
        adapter_hash=draft.adapter_hash,
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={
            "verifier_id": "round4-ci",
            "adapter_id": adapter_id,
            "adapter_hash": draft.adapter_hash,
            "verification_digest": sha256_digest({"adapter_id": adapter_id, "adapter_hash": draft.adapter_hash}),
        },
    )
    return sign_fixture_adapter(registry, verified, callable_hash=callable_hash)


def _register_signed_callable_tool(
    registry: ToolRegistry,
    runner: SecureRunner,
    *,
    tool_id: str,
    cap: str,
    fn,
    in_port: PortContract | None = None,
    out_port: PortContract | None = None,
    permissions: list[str] | None = None,
) -> ToolSpec:
    digest = runner.register_trusted_host_callable(tool_id, fn, required_permissions=permissions or ["fs.read"])
    sem = {}
    if in_port is not None:
        sem["input_port"] = in_port.to_dict()
    if out_port is not None:
        sem["output_port"] = out_port.to_dict()
    spec = ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="host_trusted",
        binary_hash=digest,
        capabilities=[cap],
        required_permissions=permissions or ["fs.read"],
        runtime_requirements={"callable_name": tool_id},
        semantic_contract=sem,
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={
            "verifier_id": "round4-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    return sign_fixture_tool(registry, spec)


class TestRound4Remediation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "process.exec"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kh_b2_r3_sec_001_unsigned_verified_adapter_rejected_everywhere(self) -> None:
        p_ns = PortContract(schema_ref="json:obj", semantic_type="latency", unit="ns")
        p_ms = PortContract(schema_ref="json:obj", semantic_type="latency", unit="ms")
        corpus_hash = sha256_digest("corpus:fake")
        base = AdapterSpec(
            adapter_id="fake.adapter",
            version="1.0.0",
            source_port=p_ns,
            target_port=p_ms,
            mapping={"fields": {"a": "b"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            verification_corpus_hash=corpus_hash,
            trust_status=TrustStatus.DISCOVERED,
        )
        fake = AdapterSpec(
            adapter_id="fake.adapter",
            version="1.0.0",
            source_port=p_ns,
            target_port=p_ms,
            mapping={"fields": {"a": "b"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            verification_corpus_hash=corpus_hash,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "attacker-asserted",
                "verification_digest": sha256_digest("fake"),
                "adapter_id": "fake.adapter",
                "adapter_hash": base.adapter_hash,
            },
        )
        # Missing authority or unsigned attestation fails closed.
        res_no_auth, reasons_no_auth, st_no_auth = _validate_adapter_candidate(fake)
        self.assertIsNone(res_no_auth)
        self.assertEqual(st_no_auth, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("ADAPTER_ATTESTATION_AUTHORITY_REQUIRED", ",".join(reasons_no_auth))

        auth = _authority()
        res_auth, reasons_auth, st_auth = _validate_adapter_candidate(fake, authority=auth)
        self.assertIsNone(res_auth)
        self.assertEqual(st_auth, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("SPOOFED_VERIFIED_ADAPTER_ATTESTATION", ",".join(reasons_auth))

        # Synthesizer without authority never self-escalates to VERIFIED.
        p_bytes = PortContract(schema_ref="bytes", semantic_type="raw_bytes", encoding="utf-8", cardinality="many")
        p_jsonl = PortContract(schema_ref="jsonl", semantic_type="jsonl_events", encoding="utf-8", cardinality="many")
        unauth_prop = AdapterSynthesizer().propose(p_bytes, p_jsonl, promote_verified=True)
        self.assertEqual(unauth_prop.status, AdapterProposalStatus.SYNTHESIZED_CANDIDATE)
        assert unauth_prop.adapter_spec is not None
        self.assertEqual(unauth_prop.adapter_spec.trust_status, TrustStatus.DISCOVERED)

        auth_prop = AdapterSynthesizer(authority=auth).propose(p_bytes, p_jsonl, promote_verified=True)
        self.assertEqual(auth_prop.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)
        assert auth_prop.adapter_spec is not None
        self.assertEqual(auth_prop.adapter_spec.trust_status, TrustStatus.VERIFIED)
        valid_obj, _, valid_st = _validate_adapter_candidate(auth_prop.adapter_spec, authority=auth)
        self.assertIsNotNone(valid_obj)
        self.assertEqual(valid_st, ExecutionStatus.PASS)

    def test_kh_b2_r3_sec_001_untrusted_adapter_callable_blocked_and_signed_isolated(self) -> None:
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        p_ns = PortContract(schema_ref="json:obj", semantic_type="value", unit="ns")
        p_ms = PortContract(schema_ref="json:obj", semantic_type="value", unit="ms")
        p_done = PortContract(schema_ref="json:res", semantic_type="done", unit="none")

        in_marker = self.ws / "in_tool_ran.txt"

        def fn_in(_args):
            in_marker.write_text("RAN", encoding="utf-8")
            return {"ns": 2000000}

        def fn_out(args):
            return {"value": args.get("ms")}

        _register_signed_callable_tool(registry, runner, tool_id="test.in", cap="cap.in", fn=fn_in, out_port=p_ns)
        _register_signed_callable_tool(
            registry, runner, tool_id="test.out", cap="cap.out", fn=fn_out, in_port=p_ms, out_port=p_done
        )

        # Signed declarative adapter -> passing untrusted adapters_callables override MUST fail closed before any node runs.
        decl_ad = _signed_adapter(registry, "test.decl.ns.ms", p_ns, p_ms)
        composer = ToolComposer()
        plan_res = composer.plan(
            {"goal_id": "r4-ad-sec", "required_capabilities": ["cap.in", "cap.out"], "expected_outputs": [p_done]},
            registry,
            self.ctx,
            adapters=[decl_ad],
        )
        self.assertTrue(plan_res.ok and plan_res.plan is not None, plan_res.reasons)

        outside_canary = self.root / "outside_adapter_canary"

        def evil_adapter(_payload):
            outside_canary.write_text("EVIL_HOST_CALL", encoding="utf-8")
            return {"ms": 2}

        rec_evil, _ = composer.execute_plan(
            plan_res.plan,
            registry,
            self.ctx,
            runner=runner,
            adapters=[decl_ad],
            adapters_callables={decl_ad.adapter_id: evil_adapter},
            oracle=lambda d: d["output"] == {"value": 2},
        )
        self.assertEqual(rec_evil.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(outside_canary.exists())
        self.assertFalse(in_marker.exists())

        # CompositionVerifier rejects forged/unsigned adapter on a valid plan structure too.
        unsigned_ad = AdapterSpec(
            adapter_id=decl_ad.adapter_id,
            version="1.0.0",
            source_port=p_ns,
            target_port=p_ms,
            mapping={"fields": {"ns": "ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            verification_corpus_hash=decl_ad.verification_corpus_hash,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "forged-verifier",
                "adapter_id": decl_ad.adapter_id,
                "adapter_hash": decl_ad.adapter_hash,
                "verification_digest": sha256_digest("forged"),
            },
        )
        ver_forged = CompositionVerifier().verify(plan_res.plan, registry, self.ctx, adapters=[unsigned_ad])
        self.assertFalse(ver_forged.valid)
        self.assertTrue(any("INVALID_ADAPTER_ATTESTATION" in r for r in ver_forged.reasons), ver_forged.reasons)

        # Registered + HMAC-bound trusted host adapter runs strictly in isolated forked child, and swapped callable fails.
        child_pid_log = self.ws / "adapter_child_pid.txt"

        def trusted_host_adapter(payload):
            child_pid_log.write_text(str(os.getpid()), encoding="utf-8")
            return {"ms": int(payload["ns"]) // 1_000_000}

        ad_hash = runner.register_trusted_host_adapter("test.host.ns.ms", trusted_host_adapter)
        bound_ad = _signed_adapter(registry, "test.host.ns.ms", p_ns, p_ms, callable_hash=ad_hash)
        plan_bound = composer.plan(
            {"goal_id": "r4-ad-bound", "required_capabilities": ["cap.in", "cap.out"], "expected_outputs": [p_done]},
            registry,
            self.ctx,
            adapters=[bound_ad],
        )
        self.assertTrue(plan_bound.ok and plan_bound.plan is not None, plan_bound.reasons)

        # Swap callable with different function while keeping registered ID -> denied.
        rec_swap, _ = composer.execute_plan(
            plan_bound.plan,
            registry,
            self.ctx,
            runner=runner,
            adapters=[bound_ad],
            adapters_callables={bound_ad.adapter_id: evil_adapter},
            oracle=lambda d: d["output"] == {"value": 2},
        )
        self.assertEqual(rec_swap.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(outside_canary.exists())

        rec_ok, _ = composer.execute_plan(
            plan_bound.plan,
            registry,
            self.ctx,
            runner=runner,
            adapters=[bound_ad],
            oracle=lambda d: d["output"] == {"value": 2},
        )
        self.assertEqual(rec_ok.status, ExecutionStatus.PASS, rec_ok.oracle_result)
        self.assertTrue(child_pid_log.exists())
        if hasattr(os, "fork"):
            self.assertNotEqual(int(child_pid_log.read_text(encoding="utf-8")), os.getpid())

    def test_kh_b2_r3_sec_002_direct_runner_enforces_hmac_and_immutable_binding(self) -> None:
        outside_write = self.root / "outside_direct_write"
        inside_write = self.ws / "inside_direct_write"

        def host_sensitive(args):
            target_p = Path(str(args.get("target") or outside_write))
            target_p.write_text("HOST_CALLED", encoding="utf-8")
            return {"ok": True}

        # 1. Runner without attestation_authority rejects direct run() even with allow_trusted_host_callables=True.
        no_auth_runner = SecureRunner(allow_trusted_host_callables=True)
        digest = no_auth_runner.register_trusted_host_callable(
            "host.sensitive", host_sensitive, required_permissions=["fs.write"]
        )
        unsigned_spec = ToolSpec(
            tool_id="host.sensitive",
            version="1.0.0",
            source="host_trusted",
            binary_hash=digest,
            capabilities=["host.sensitive"],
            required_permissions=[],
            runtime_requirements={"callable_name": "host.sensitive"},
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "tool_id": "host.sensitive",
                "binary_hash": digest,
                "verification_digest": sha256_digest("fake"),
                "verifier_id": "untrusted-claimed-verifier",
            },
        )
        r_no_auth = no_auth_runner.run(unsigned_spec, {"target": str(outside_write)}, self.ctx, oracle=lambda _: True)
        self.assertEqual(r_no_auth.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("MISSING_ATTESTATION_AUTHORITY", r_no_auth.stderr_excerpt)
        self.assertFalse(outside_write.exists())

        # 2. Runner WITH authority rejects unsigned ToolSpec.
        auth = _authority()
        auth_runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=auth)
        auth_runner.register_trusted_host_callable(
            "host.sensitive", host_sensitive, required_permissions=["fs.write"]
        )
        r_unsigned = auth_runner.run(unsigned_spec, {"target": str(outside_write)}, self.ctx, oracle=lambda _: True)
        self.assertEqual(r_unsigned.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_OR_INVALID_ATTESTATION_SIGNATURE", r_unsigned.stderr_excerpt)
        self.assertFalse(outside_write.exists())

        # 3. Signed spec with downgraded/tampered permissions fails spec_digest verification.
        low_spec = ToolSpec(
            tool_id="host.sensitive",
            version="1.0.0",
            source="host_trusted",
            binary_hash=digest,
            capabilities=["host.sensitive"],
            required_permissions=[],
            runtime_requirements={"callable_name": "host.sensitive"},
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={"verifier_id": "round4-ci", "verification_digest": sha256_digest("ok")},
        )
        low_spec.verification_attestation = auth.issue_attestation(
            low_spec.tool_id, low_spec.binary_hash, sha256_digest("ok"), "round4-ci",
            spec_digest=compute_tool_spec_security_digest(low_spec),
        )
        # Even though low_spec is signed, its empty permissions cannot satisfy the host callable's immutable fs.write contract!
        r_perm_mismatch = auth_runner.run(low_spec, {"target": str(inside_write)}, self.ctx, oracle=lambda _: True)
        self.assertEqual(r_perm_mismatch.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TRUSTED_HOST_CALLABLE_PERMISSION_MISMATCH", r_perm_mismatch.stderr_excerpt)
        self.assertFalse(outside_write.exists())
        self.assertFalse(inside_write.exists())

        # Mutating an adequately signed spec in memory fails spec_digest HMAC check.
        signed_spec = ToolSpec(
            tool_id="host.sensitive",
            version="1.0.0",
            source="host_trusted",
            binary_hash=digest,
            capabilities=["host.sensitive"],
            required_permissions=["fs.write"],
            runtime_requirements={"callable_name": "host.sensitive"},
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={"verifier_id": "round4-ci", "verification_digest": sha256_digest("ok")},
        )
        signed_spec.verification_attestation = auth.issue_attestation(
            signed_spec.tool_id, signed_spec.binary_hash, sha256_digest("ok"), "round4-ci",
            spec_digest=compute_tool_spec_security_digest(signed_spec),
        )
        signed_spec.required_permissions = []
        r_tamper = auth_runner.run(signed_spec, {"target": str(inside_write)}, self.ctx, oracle=lambda _: True)
        self.assertEqual(r_tamper.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("UNTRUSTED_OR_INVALID_ATTESTATION_SIGNATURE", r_tamper.stderr_excerpt)
        self.assertFalse(outside_write.exists())
        self.assertFalse(inside_write.exists())

        # Restore matching contract: confined inside workspace passes, external path blocked!
        signed_spec.required_permissions = ["fs.write"]
        r_ok = auth_runner.run(signed_spec, {"target": str(inside_write)}, self.ctx, oracle=lambda _: True)
        self.assertEqual(r_ok.status, ExecutionStatus.PASS)
        self.assertTrue(inside_write.exists())
        self.assertFalse(outside_write.exists())

    def test_kh_b2_r3_api_003_checkpoint_path_confined_to_workspace_or_explicit_roots(self) -> None:
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        p_out = PortContract(schema_ref="json:obj", semantic_type="ckpt_res", unit="none")
        _register_signed_callable_tool(
            registry, runner, tool_id="test.ckpt.ok", cap="cap.ckpt", fn=lambda _a: {"ok": True}, out_port=p_out
        )
        composer = ToolComposer()
        plan_res = composer.plan(
            {"goal_id": "r4-ckpt", "required_capabilities": ["cap.ckpt"], "expected_outputs": [p_out]},
            registry,
            self.ctx,
        )
        self.assertTrue(plan_res.ok and plan_res.plan is not None, plan_res.reasons)

        # 1. External absolute path rejected by default.
        ext_journal = self.root / "outside_checkpoint.jsonl"
        rec_ext, _ = composer.execute_plan(
            plan_res.plan,
            registry,
            self.ctx,
            runner=runner,
            checkpoint_store_path=ext_journal,
            resume_run_id="r4_ext_run",
            oracle=lambda d: d["output"] == {"ok": True},
        )
        self.assertEqual(rec_ext.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(ext_journal.exists())

        with self.assertRaises(PermissionError):
            composer.reconcile_checkpoint_node(
                checkpoint_store_path=ext_journal,
                run_id="r4_ext_run",
                node_id="n1",
                outcome="NOT_EXECUTED",
                security_context=self.ctx,
                operator_confirmed=True,
            )

        # 2. Symlink escape inside workspace also rejected.
        ext_dir = self.root / "outside_dir"
        ext_dir.mkdir()
        sym_dir = self.ws / "escape_dir"
        sym_dir.symlink_to(ext_dir)
        rec_sym, _ = composer.execute_plan(
            plan_res.plan,
            registry,
            self.ctx,
            runner=runner,
            checkpoint_store_path=sym_dir / "sym.jsonl",
            resume_run_id="r4_sym_run",
            oracle=lambda d: d["output"] == {"ok": True},
        )
        self.assertEqual(rec_sym.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse((ext_dir / "sym.jsonl").exists())

        # 3. Owner-configured allowed_checkpoint_roots permits external root ONLY within configured dir.
        ext_composer = ToolComposer(allowed_checkpoint_roots=[ext_dir])
        ext_allowed_journal = ext_dir / "authorized.jsonl"
        rec_allowed, _ = ext_composer.execute_plan(
            plan_res.plan,
            registry,
            self.ctx,
            runner=runner,
            checkpoint_store_path=ext_allowed_journal,
            resume_run_id="r4_allowed_run",
            oracle=lambda d: d["output"] == {"ok": True},
        )
        self.assertEqual(rec_allowed.status, ExecutionStatus.PASS)
        self.assertTrue(ext_allowed_journal.exists())

        # Any other outside path still denied even when ext_dir is allowed.
        other_outside = self.root / "unauthorized.jsonl"
        rec_other, _ = ext_composer.execute_plan(
            plan_res.plan,
            registry,
            self.ctx,
            runner=runner,
            checkpoint_store_path=other_outside,
            resume_run_id="r4_other_run",
            oracle=lambda d: d["output"] == {"ok": True},
        )
        self.assertEqual(rec_other.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(other_outside.exists())


if __name__ == "__main__":
    unittest.main()
