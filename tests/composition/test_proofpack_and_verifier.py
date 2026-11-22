"""Comprehensive tests for Working Tool #5 `ProofPack` and 6-dimension `CompositionVerifier`."""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_adapter, sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_adapter, sign_fixture_tool

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict

from kintsugi.capability.contracts_v2 import (
    AdapterSpec,
    CompositionPlan,
    CompositionReceipt,
    EffectContract,
    PortContract,
    compute_dag_effects,
)
from kintsugi.capability.schemas import (
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.composition.composition_verifier import (
    CompositionVerifier,
    parallel_execution_groups,
)
from kintsugi.tools.proof_pack import (
    FormalProofArtifact,
    ProofLevel,
    ProofPack,
    ProofPackReport,
    build_artifact_manifest,
    check_python_rust_parity,
    run_differential_corpus,
    verify_formal_proof,
    verify_reproducibility,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HASH_1 = "sha256:" + "1" * 64
HASH_2 = "sha256:" + "2" * 64
HASH_3 = "sha256:" + "3" * 64
HASH_4 = "sha256:" + "4" * 64
HASH_5 = "sha256:" + "5" * 64


def _attest(tool_id: str, binary_hash: str) -> Dict[str, Any]:
    return {
        "verifier_id": "ci-verifier",
        "verification_digest": sha256_digest({"tool_id": tool_id, "binary_hash": binary_hash}),
        "binary_hash": binary_hash,
        "tool_id": tool_id,
        "source": "ci_attestation",
    }


def _verified_tool(
    tool_id: str,
    *,
    binary_hash: str,
    permissions: list,
    input_port: PortContract,
    output_port: PortContract,
    effect: EffectContract,
    preconditions: list = None,
    postconditions: list = None,
    trust_status: TrustStatus = TrustStatus.VERIFIED,
) -> ToolSpec:
    attestation = _attest(tool_id, binary_hash) if trust_status == TrustStatus.VERIFIED else None
    return ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="verified_local",
        binary_hash=binary_hash,
        capabilities=[f"cap.{tool_id}"],
        input_schema={"type": "object", "encoding": input_port.encoding},
        output_schema={"type": "object", "encoding": output_port.encoding},
        semantic_contract={
            "input_port": input_port.to_dict(),
            "output_port": output_port.to_dict(),
            "effect_contract": effect.to_dict(),
        },
        preconditions=list(preconditions or []),
        postconditions=list(postconditions or []),
        side_effects=list(effect.write_scopes or ["none"]),
        required_permissions=list(permissions),
        trust_status=trust_status,
        verification_attestation=attestation,
    )


def _verified_adapter(
    adapter_id: str,
    src_port: PortContract,
    dst_port: PortContract,
    *,
    mapping: Dict[str, Any],
    unit_conversion: Dict[str, Any] = None,
    lossless: bool = True,
    preconditions: list = None,
    trust_status: TrustStatus = TrustStatus.VERIFIED,
) -> AdapterSpec:
    att = (
        {
            "verifier_id": "ci-verifier",
            "verification_digest": HASH_5,
            "adapter_id": adapter_id,
        }
        if trust_status == TrustStatus.VERIFIED
        else None
    )
    return AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=src_port,
        target_port=dst_port,
        mapping=mapping,
        unit_conversion=unit_conversion,
        lossless=lossless,
        preconditions=list(preconditions or []),
        verification_corpus_hash=HASH_4,
        trust_status=trust_status,
        verification_attestation=att,
    )


class TestProofPack(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.pack = ProofPack()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_differential_pass_mismatch_and_tolerant_mode(self) -> None:
        corpus = [0, 1, 5, -3, 42]
        ok_rep = run_differential_corpus(
            lambda x: x * 2 + 1,
            lambda x: (x << 1) + 1,
            corpus,
            property_checks=[lambda x, out: (out % 2) == 1],
            seed=1337,
        )
        self.assertEqual(ok_rep.schema, "ProofPackReport/1")
        self.assertEqual(ok_rep.status, "PASS")
        self.assertTrue(ok_rep.ok)
        self.assertTrue(ok_rep.verified_independently)
        self.assertIn(ProofLevel.DIFFERENTIAL_VERIFIED, ok_rep.proof_levels)
        self.assertIn(ProofLevel.PROPERTY_TESTED, ok_rep.proof_levels)
        self.assertNotIn(ProofLevel.FORMALLY_PROVEN, ok_rep.proof_levels)
        assert ok_rep.differential_summary is not None
        self.assertEqual(ok_rep.differential_summary["total_cases"], 5)
        self.assertEqual(ok_rep.differential_summary["seed"], 1337)
        self.assertEqual(ok_rep.differential_summary["comparison_mode"], "exact")
        self.assertTrue(ok_rep.differential_summary["inputs_digest"].startswith("sha256:"))

        # Mismatch detection
        bad_rep = self.pack.run_differential_corpus(
            lambda x: x * 2,
            lambda x: x * 2 if x != 5 else 999,
            corpus,
            seed=99,
        )
        self.assertEqual(bad_rep.status, "FAIL")
        self.assertFalse(bad_rep.ok)
        assert bad_rep.differential_summary is not None
        self.assertEqual(bad_rep.differential_summary["mismatches"], 1)

        # Tolerant float comparison
        tol_pass = run_differential_corpus(
            lambda x: x / 3.0,
            lambda x: (x / 3.0) + 1e-6,
            [1.0, 2.0, 3.0],
            tolerance=1e-4,
        )
        self.assertEqual(tol_pass.status, "PASS")
        assert tol_pass.differential_summary is not None
        self.assertEqual(tol_pass.differential_summary["comparison_mode"], "tolerant")

        tol_fail = run_differential_corpus(
            lambda x: x / 3.0,
            lambda x: (x / 3.0) + 0.01,
            [1.0, 2.0],
            tolerance=1e-4,
        )
        self.assertEqual(tol_fail.status, "FAIL")

        # Empty corpus cannot claim PASS
        empty_rep = run_differential_corpus(lambda x: x, lambda x: x, [])
        self.assertEqual(empty_rep.status, "NOT_VERIFIED")
        self.assertFalse(empty_rep.ok)

    def test_formally_proven_escalation_rejection_and_valid_formal_artifact(self) -> None:
        # 1. Trying to label differential/fuzz testing as FORMALLY_PROVEN MUST raise ValueError
        with self.assertRaises(ValueError):
            run_differential_corpus(
                lambda x: x + 1,
                lambda x: x + 1,
                [1, 2, 3],
                proof_level=ProofLevel.FORMALLY_PROVEN,
            )

        with self.assertRaises(ValueError):
            self.pack.run_property_tests(
                lambda x: x + 1,
                [1, 2, 3],
                [lambda x, y: y > x],
                proof_level="FORMALLY_PROVEN",
            )

        # 2. ProofPackReport cannot claim FORMALLY_PROVEN without FormalProofArtifact
        with self.assertRaises(ValueError):
            ProofPackReport(
                status="PASS",
                verified_independently=True,
                proof_levels=[ProofLevel.FORMALLY_PROVEN],
                differential_summary={"total_cases": 100, "mismatches": 0},
            )

        # 3. Pseudo-solver names (fuzz / differential / random) rejected inside FormalProofArtifact
        with self.assertRaises(ValueError):
            FormalProofArtifact(
                solver_name="differential_fuzz_runner",
                solver_version="1.0.0",
                assumptions=["bounded"],
                proof_scope="fn(x) == ref(x)",
                proof_digest=HASH_1,
                verified=True,
            )

        # 4. Unverified formal artifact (verified=False) rejected
        unverified_fp = FormalProofArtifact(
            solver_name="z3",
            solver_version="5.3.3",
            assumptions=["32-bit unsigned"],
            proof_scope="no_overflow",
            proof_digest=HASH_1,
            verified=False,
        )
        with self.assertRaises(ValueError):
            verify_formal_proof(unverified_fp)

        # 5. Claiming PASS without independent verification rejected
        with self.assertRaises(ValueError):
            ProofPackReport(
                status="PASS",
                verified_independently=False,
                proof_levels=[ProofLevel.DIFFERENTIAL_VERIFIED],
                differential_summary={"total_cases": 10, "mismatches": 0},
            )

        # 6. Explicit validated formal solver proof artifact succeeds cleanly
        valid_fp = FormalProofArtifact(
            solver_name="z3",
            solver_version="5.3.3",
            assumptions=["64-bit two's complement bitvector", "count >= 1"],
            proof_scope="allocation_overflow_safety",
            proof_digest=HASH_2,
            verified=True,
        )
        formal_rep = verify_formal_proof(valid_fp)
        self.assertEqual(formal_rep.status, "PASS")
        self.assertEqual(formal_rep.proof_levels, [ProofLevel.FORMALLY_PROVEN])
        self.assertTrue(formal_rep.verified_independently)

    def test_symlink_safe_manifest_hashing_and_reproducibility(self) -> None:
        sub = self.ws / "artifacts"
        sub.mkdir()
        f1 = sub / "tool.py"
        f2 = sub / "schema.json"
        f1.write_text("print('ok')\n", encoding="utf-8")
        f2.write_text('{"v":1}\n', encoding="utf-8")

        m1 = build_artifact_manifest(
            ["artifacts/tool.py", str(f2)],
            self.ws,
            extra_metadata={"toolchain": {"rustc": "1.99.1"}},
        )
        m2 = self.pack.build_artifact_manifest(
            [str(f2), "artifacts/tool.py"],
            self.ws,
            extra_metadata={"toolchain": {"rustc": "1.99.1"}},
        )
        self.assertEqual(m1["schema"], "ArtifactManifest/1")
        self.assertEqual(m1["manifest_digest"], m2["manifest_digest"])
        self.assertIn("os", m1["environment"])
        self.assertIn("arch", m1["environment"])
        self.assertIn("artifacts/tool.py", m1["files"])

        repro_ok = verify_reproducibility([m1, m2])
        self.assertEqual(repro_ok.status, "PASS")
        self.assertTrue(repro_ok.reproducible)

        # Mutate file content -> manifest differs -> reproducibility FAIL
        f1.write_text("print('tampered')\n", encoding="utf-8")
        m3 = build_artifact_manifest(["artifacts/tool.py", str(f2)], self.ws, extra_metadata={"toolchain": {"rustc": "1.99.1"}})
        repro_fail = verify_reproducibility([m1, m3])
        self.assertEqual(repro_fail.status, "FAIL")
        self.assertFalse(repro_fail.reproducible)

        # Insufficient (<2) artifacts -> NOT_VERIFIED
        self.assertEqual(verify_reproducibility([m1]).status, "NOT_VERIFIED")

        # Symlink file, broken symlink, symlinked parent dir, and path traversal rejected
        outside = Path(self._tmp.name) / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        sym_file = self.ws / "sym.py"
        os.symlink(outside, sym_file)
        with self.assertRaises(PermissionError):
            build_artifact_manifest([sym_file], self.ws)

        broken_sym = self.ws / "broken_sym.py"
        os.symlink(self.ws / "does_not_exist.py", broken_sym)
        with self.assertRaises(PermissionError):
            build_artifact_manifest([broken_sym], self.ws)

        sym_dir = self.ws / "sym_dir"
        os.symlink(Path(self._tmp.name), sym_dir)
        with self.assertRaises(PermissionError):
            build_artifact_manifest(["sym_dir/outside.txt"], self.ws)

        with self.assertRaises(PermissionError):
            build_artifact_manifest(["../outside.txt"], self.ws)

    def test_python_rust_parity_builtin_and_custom(self) -> None:
        # Custom parity pass & fail
        custom_ok = check_python_rust_parity(
            python_fn=lambda b: b.count(b"\n"),
            rust_fn=lambda b: len([x for x in b if x == 10]),
            corpus=[b"", b"a\nb\n", b"xyz"],
        )
        self.assertEqual(custom_ok.status, "PASS")
        assert custom_ok.parity_summary is not None
        self.assertTrue(custom_ok.parity_summary["parity_ok"])

        custom_fail = check_python_rust_parity(
            python_fn=lambda b: len(b),
            rust_fn=lambda b: len(b) + 1,
            corpus=[b"abc"],
        )
        self.assertEqual(custom_fail.status, "FAIL")

        # Missing rust binary -> NOT_VERIFIED (never PASS)
        missing_rust = check_python_rust_parity(rust_bin=self.ws / "missing-kintsugi-rs")
        self.assertEqual(missing_rust.status, "NOT_VERIFIED")

        # Built-in kintsugi-rs scan-bytes parity check (when compiled binary exists)
        rust_bin = REPO_ROOT / "target" / "release" / "kintsugi-rs"
        if rust_bin.is_file():
            builtin_rep = check_python_rust_parity(rust_bin=rust_bin, num_cases=16, disable_simd_check=True)
            self.assertEqual(builtin_rep.status, "PASS")
            assert builtin_rep.parity_summary is not None
            self.assertEqual(builtin_rep.parity_summary["checked_cases"], 16)
            self.assertTrue(builtin_rep.parity_summary["parity_ok"])


class TestCompositionVerifier(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "ast.scan"],
            network_allowed=False,
            allow_untrusted_native=False,
        )
        self.verifier = CompositionVerifier()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _build_valid_fixture(self):
        p_ns = PortContract(schema_ref="json:metrics", semantic_type="latency", encoding="utf-8", unit="ns")
        p_ms = PortContract(schema_ref="json:metrics", semantic_type="latency", encoding="utf-8", unit="ms")
        p_rep = PortContract(schema_ref="json:report", semantic_type="summary", encoding="utf-8", unit="none")

        e1 = EffectContract(read_scopes=["ws:in/raw.log"], exec_permissions=["fs.read"], idempotent=True)
        e2 = EffectContract(write_scopes=["ws:out/summary.json"], exec_permissions=["fs.write"], idempotent=True)

        t1 = _verified_tool(
            "tool.collect",
            binary_hash=HASH_1,
            permissions=["fs.read"],
            input_port=p_ns,
            output_port=p_ns,
            effect=e1,
            postconditions=["metrics_collected"],
        )
        t2 = _verified_tool(
            "tool.summarize",
            binary_hash=HASH_2,
            permissions=["fs.write"],
            input_port=p_ms,
            output_port=p_rep,
            effect=e2,
            preconditions=["metrics_collected"],
            postconditions=["summary_written"],
        )
        adapter = _verified_adapter(
            "adapter.ns_to_ms",
            p_ns,
            p_ms,
            mapping={"fields": {"latency_ns": "latency_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": 1e-6},
        )

        reg = ToolRegistry()
        sign_fixture_tool(reg, t1)
        sign_fixture_tool(reg, t2)
        adapter = sign_fixture_adapter(reg, adapter)

        dag_eff = compute_dag_effects([e1, e2])
        plan = CompositionPlan(
            plan_id="plan-valid-01",
            goal_contract_hash=HASH_3,
            nodes=[
                {"node_id": "n1", "tool_id": "tool.collect", "retryable": True},
                {"node_id": "n2", "tool_id": "tool.summarize", "retryable": True},
            ],
            edges=[{"from_node": "n1", "to_node": "n2", "adapter_id": "adapter.ns_to_ms", "adapter_hash": adapter.adapter_hash}],
            input_bindings={"n1.in": "goal.raw_log"},
            tool_artifact_hashes={"tool.collect": HASH_1, "tool.summarize": HASH_2},
            adapter_hashes={"adapter.ns_to_ms": adapter.adapter_hash},
            permission_union=dag_eff["permission_union"],
            effects_union=dag_eff["effects_union"],
            expected_outputs=[{"semantic_type": "summary", "postconditions": ["summary_written"]}],
            oracle_ref="oracle:summary_v1",
            verification_plan={"mode": "replay"},
            estimated_resources={"memory_mb": 64},
        )
        return plan, reg, [adapter]

    def test_valid_plan_static_and_oracle_verification(self) -> None:
        plan, reg, adapters = self._build_valid_fixture()

        # Without receipts/replay -> static_valid=True, status=NOT_VERIFIED (never PASS without independent oracle)
        res_unverified = self.verifier.verify(plan, reg, self.ctx, adapters=adapters)
        self.assertTrue(res_unverified.valid)
        self.assertTrue(res_unverified.static_valid)
        self.assertFalse(res_unverified.verified)
        self.assertEqual(res_unverified.status, "NOT_VERIFIED")
        self.assertEqual(res_unverified.oracle_status, "NOT_VERIFIED")
        self.assertEqual(res_unverified.execution_order, ["n1", "n2"])
        self.assertEqual(res_unverified.parallel_groups, [["n1"], ["n2"]])

        # With valid CompositionReceipt + passing oracle -> PASS
        receipt = CompositionReceipt(
            run_id="run-1",
            plan_hash=plan.plan_hash,
            policy_hash=self.ctx.policy_hash,
            sandbox_environment_hash=HASH_4,
            node_receipts=[{"node_id": "n1", "status": "PASS"}, {"node_id": "n2", "status": "PASS"}],
            input_digest=HASH_1,
            output_digest=HASH_2,
            oracle_result={"passed": True},
            verification_status="PASS",
            status=ExecutionStatus.PASS,
        )
        res_pass = self.verifier.verify(
            plan,
            reg,
            self.ctx,
            adapters=adapters,
            receipts=receipt,
            oracle=lambda r: r.status == ExecutionStatus.PASS,
        )
        self.assertTrue(res_pass.valid)
        self.assertTrue(res_pass.verified)
        self.assertEqual(res_pass.status, "PASS")
        self.assertEqual(res_pass.oracle_status, "PASS")

        # With replay_corpus + oracle -> PASS; mismatched replay_corpus -> FAIL
        res_replay = self.verifier.verify(
            plan,
            reg,
            self.ctx,
            adapters=adapters,
            replay_corpus=[{"input": {"ns": 2_000_000}, "output": {"ms": 2.0}, "expected": {"ms": 2.0}}],
            oracle=lambda out: out["ms"] == 2.0,
        )
        self.assertEqual(res_replay.status, "PASS")

        res_replay_fail = self.verifier.verify(
            plan,
            reg,
            self.ctx,
            adapters=adapters,
            replay_corpus=[{"input": {"ns": 2_000_000}, "output": {"ms": 999.0}, "expected": {"ms": 2.0}}],
        )
        self.assertEqual(res_replay_fail.status, "FAIL")
        self.assertFalse(res_replay_fail.valid)

    def test_rejects_unit_mismatch_without_adapter(self) -> None:
        plan, reg, _ = self._build_valid_fixture()
        raw = plan.to_dict()
        raw["edges"] = [{"from_node": "n1", "to_node": "n2"}]
        raw["adapter_hashes"] = {}
        raw.pop("plan_hash", None)
        no_adapter_plan = CompositionPlan.from_dict(raw)

        res = self.verifier.verify(no_adapter_plan, reg, self.ctx)
        self.assertFalse(res.valid)
        self.assertEqual(res.status, "FAIL")
        self.assertTrue(any("UNIT_MISMATCH" in r for r in res.reasons))

    def test_rejects_secret_leak_port_and_embedded_secret(self) -> None:
        p_secret = PortContract(schema_ref="json:token", semantic_type="auth_payload", sensitivity="secret")
        p_public = PortContract(schema_ref="json:token", semantic_type="auth_payload", sensitivity="public")
        eff = EffectContract(exec_permissions=["fs.read"])

        t_sec = _verified_tool("tool.secret_src", binary_hash=HASH_1, permissions=["fs.read"], input_port=p_secret, output_port=p_secret, effect=eff)
        t_pub = _verified_tool("tool.public_dst", binary_hash=HASH_2, permissions=["fs.read"], input_port=p_public, output_port=p_public, effect=eff)
        reg = ToolRegistry()
        sign_fixture_tool(reg, t_sec)
        sign_fixture_tool(reg, t_pub)

        dag_eff = compute_dag_effects([eff, eff])
        leak_plan = CompositionPlan(
            plan_id="plan-secret-leak",
            goal_contract_hash=HASH_3,
            nodes=[{"node_id": "n1", "tool_id": "tool.secret_src"}, {"node_id": "n2", "tool_id": "tool.public_dst"}],
            edges=[{"from_node": "n1", "to_node": "n2"}],
            tool_artifact_hashes={"tool.secret_src": HASH_1, "tool.public_dst": HASH_2},
            permission_union=dag_eff["permission_union"],
            effects_union=dag_eff["effects_union"],
            oracle_ref="oracle:sec",
        )
        res = self.verifier.verify(leak_plan, reg, self.ctx)
        self.assertFalse(res.valid)
        self.assertEqual(res.status, "FAIL")
        self.assertTrue(any("SENSITIVITY_FLOW_VIOLATION" in r for r in res.reasons))

        # Embedded high-entropy credential in raw plan dict must also fail Dimension 1
        dynamic_secret = "".join(chr(ord("A") + (i * 7) % 26) + str((i * 3) % 10) for i in range(10))
        plan_ok, reg_ok, adapters_ok = self._build_valid_fixture()
        raw_secret_plan = plan_ok.to_dict()
        raw_secret_plan["input_bindings"]["api_key"] = dynamic_secret
        res_secret = self.verifier.verify(raw_secret_plan, reg_ok, self.ctx, adapters=adapters_ok)
        self.assertFalse(res_secret.valid)
        self.assertTrue(any("SECRET_LEAK_BLOCKED" in r for r in res_secret.reasons))

    def test_rejects_hash_tampers_across_plan_tool_adapter_and_receipt(self) -> None:
        plan, reg, adapters = self._build_valid_fixture()

        # 1. Tampered plan_hash
        bad_plan_dict = plan.to_dict()
        bad_plan_dict["plan_hash"] = HASH_5
        res_ph = self.verifier.verify(bad_plan_dict, reg, self.ctx, adapters=adapters)
        self.assertFalse(res_ph.valid)
        self.assertTrue(any("PLAN_HASH_MISMATCH" in r for r in res_ph.reasons))

        # 2. Tampered tool_artifact_hashes
        raw_th = plan.to_dict()
        raw_th["tool_artifact_hashes"]["tool.collect"] = HASH_5
        raw_th.pop("plan_hash", None)
        res_th = self.verifier.verify(CompositionPlan.from_dict(raw_th), reg, self.ctx, adapters=adapters)
        self.assertFalse(res_th.valid)
        self.assertTrue(any("TOOL_BINARY_HASH_MISMATCH" in r for r in res_th.reasons))

        # 3. Tampered adapter_hashes
        raw_ah = plan.to_dict()
        raw_ah["adapter_hashes"]["adapter.ns_to_ms"] = HASH_5
        raw_ah.pop("plan_hash", None)
        res_ah = self.verifier.verify(CompositionPlan.from_dict(raw_ah), reg, self.ctx, adapters=adapters)
        self.assertFalse(res_ah.valid)
        self.assertTrue(any("ADAPTER_HASH_MISMATCH" in r for r in res_ah.reasons))

        # 4. Tampered receipt trace_digest
        good_rec = CompositionReceipt(
            run_id="run-tamper",
            plan_hash=plan.plan_hash,
            policy_hash=self.ctx.policy_hash,
            sandbox_environment_hash=HASH_4,
            node_receipts=[{"node_id": "n1", "status": "PASS"}, {"node_id": "n2", "status": "PASS"}],
            oracle_result={"passed": True},
            verification_status="PASS",
            status=ExecutionStatus.PASS,
        ).to_dict()
        good_rec["trace_digest"] = HASH_5
        res_rec = self.verifier.verify(plan, reg, self.ctx, adapters=adapters, receipts=good_rec)
        self.assertFalse(res_rec.valid)
        self.assertEqual(res_rec.status, "FAIL")
        self.assertTrue(any("RECEIPT_TRACE_DIGEST_TAMPERED" in r for r in res_rec.reasons))

    def test_rejects_circular_dag(self) -> None:
        plan, reg, adapters = self._build_valid_fixture()
        cyc_dict = plan.to_dict()
        cyc_dict["edges"] = [
            {"from_node": "n1", "to_node": "n2", "adapter_id": "adapter.ns_to_ms", "adapter_hash": adapters[0].adapter_hash},
            {"from_node": "n2", "to_node": "n1"},
        ]
        res = self.verifier.verify(cyc_dict, reg, self.ctx, adapters=adapters)
        self.assertFalse(res.valid)
        self.assertEqual(res.status, "FAIL")
        self.assertTrue(any("CYCLE_DETECTED" in r for r in res.reasons))

        with self.assertRaises(ValueError):
            parallel_execution_groups(cyc_dict, registry=reg)

    def test_rejects_over_privilege_and_retired_quarantined_discovered_tools(self) -> None:
        plan, reg, adapters = self._build_valid_fixture()

        # Over-privileged: SecurityContext only allows fs.read, plan needs fs.write too
        narrow_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read"],
        )
        res_priv = self.verifier.verify(plan, reg, narrow_ctx, adapters=adapters)
        self.assertFalse(res_priv.valid)
        self.assertTrue(any("OVER_PRIVILEGED_PERMISSIONS" in r for r in res_priv.reasons))

        # Retired tool rejected
        reg.retire("tool.summarize", reason="deprecated")
        res_ret = self.verifier.verify(plan, reg, self.ctx, adapters=adapters)
        self.assertFalse(res_ret.valid)
        self.assertTrue(any("UNTRUSTED_TOOL:tool.summarize:RETIRED" in r for r in res_ret.reasons))

        # Quarantined tool rejected
        reg.quarantine("tool.collect", reason="cve_found")
        res_quar = self.verifier.verify(plan, reg, self.ctx, adapters=adapters)
        self.assertFalse(res_quar.valid)
        self.assertTrue(any("UNTRUSTED_TOOL:tool.collect:QUARANTINED" in r for r in res_quar.reasons))

        # Discovered (unverified) tool rejected
        p_ok = PortContract(schema_ref="json:metrics", semantic_type="latency", unit="ns")
        e_ok = EffectContract(exec_permissions=["fs.read"])
        t_disc = _verified_tool(
            "tool.discovered_only",
            binary_hash=HASH_1,
            permissions=["fs.read"],
            input_port=p_ok,
            output_port=p_ok,
            effect=e_ok,
            trust_status=TrustStatus.DISCOVERED,
        )
        reg_disc = ToolRegistry()
        reg_disc.register(t_disc)
        plan_disc = CompositionPlan(
            plan_id="plan-disc",
            goal_contract_hash=HASH_3,
            nodes=[{"node_id": "n1", "tool_id": "tool.discovered_only"}],
            tool_artifact_hashes={"tool.discovered_only": HASH_1},
            permission_union=["fs.read"],
            effects_union=compute_dag_effects([e_ok])["effects_union"],
            oracle_ref="oracle:disc",
        )
        res_disc = self.verifier.verify(plan_disc, reg_disc, self.ctx)
        self.assertFalse(res_disc.valid)
        self.assertTrue(any("UNTRUSTED_TOOL:tool.discovered_only:DISCOVERED" in r for r in res_disc.reasons))

    def test_parallel_execution_groups_and_conflicting_write_scopes(self) -> None:
        p = PortContract(schema_ref="json:doc", semantic_type="report", unit="none")
        eff_w_a = EffectContract(write_scopes=["ws:out/a.json"], exec_permissions=["fs.write"])
        eff_w_b = EffectContract(write_scopes=["ws:out/b.json"], exec_permissions=["fs.write"])
        eff_w_glob = EffectContract(write_scopes=["ws:out/*.json"], exec_permissions=["fs.write"])
        eff_r_all = EffectContract(read_scopes=["ws:out/**"], exec_permissions=["fs.read"])

        t_a = _verified_tool("tool.wa", binary_hash=HASH_1, permissions=["fs.write"], input_port=p, output_port=p, effect=eff_w_a)
        t_b = _verified_tool("tool.wb", binary_hash=HASH_2, permissions=["fs.write"], input_port=p, output_port=p, effect=eff_w_b)
        t_g = _verified_tool("tool.wg", binary_hash=HASH_3, permissions=["fs.write"], input_port=p, output_port=p, effect=eff_w_glob)
        t_r = _verified_tool("tool.ra", binary_hash=HASH_4, permissions=["fs.read"], input_port=p, output_port=p, effect=eff_r_all)

        reg = ToolRegistry()
        for t in (t_a, t_b, t_g, t_r):
            sign_fixture_tool(reg, t)

        # 1. Disjoint writes (a.json vs b.json) CAN run in parallel; downstream reader waits
        dag_disjoint = compute_dag_effects([eff_w_a, eff_w_b, eff_r_all])
        plan_disjoint = CompositionPlan(
            plan_id="plan-par-ok",
            goal_contract_hash=HASH_1,
            nodes=[
                {"node_id": "a", "tool_id": "tool.wa"},
                {"node_id": "b", "tool_id": "tool.wb"},
                {"node_id": "c", "tool_id": "tool.ra"},
            ],
            edges=[{"from_node": "a", "to_node": "c"}, {"from_node": "b", "to_node": "c"}],
            tool_artifact_hashes={"tool.wa": HASH_1, "tool.wb": HASH_2, "tool.ra": HASH_4},
            permission_union=dag_disjoint["permission_union"],
            effects_union=dag_disjoint["effects_union"],
            oracle_ref="oracle:par",
        )
        groups_ok = parallel_execution_groups(plan_disjoint, registry=reg)
        self.assertEqual(groups_ok, [["a", "b"], ["c"]])

        # 2. Overlapping write scopes (a.json vs *.json) CANNOT be grouped together
        dag_conflict = compute_dag_effects([eff_w_a, eff_w_glob])
        plan_conflict = CompositionPlan(
            plan_id="plan-par-conflict",
            goal_contract_hash=HASH_1,
            nodes=[
                {"node_id": "a", "tool_id": "tool.wa"},
                {"node_id": "g", "tool_id": "tool.wg"},
            ],
            edges=[],
            tool_artifact_hashes={"tool.wa": HASH_1, "tool.wg": HASH_3},
            permission_union=dag_conflict["permission_union"],
            effects_union=dag_conflict["effects_union"],
            oracle_ref="oracle:conflict",
            verification_plan={"parallel_groups": [["a", "g"]]},
        )
        safe_groups = parallel_execution_groups(plan_conflict, registry=reg)
        self.assertEqual(safe_groups, [["a"], ["g"]])

        # Verifier explicitly rejects plan asserting conflicting parallel_groups
        res_conflict = self.verifier.verify(plan_conflict, reg, self.ctx)
        self.assertFalse(res_conflict.valid)
        self.assertEqual(res_conflict.status, "FAIL")
        self.assertTrue(any("PARALLEL_SIDE_EFFECT_CONFLICT" in r for r in res_conflict.reasons))

    def test_rejects_precondition_gap_and_non_idempotent_retry(self) -> None:
        p = PortContract(schema_ref="json:doc", semantic_type="text", unit="none")
        eff_non_idem = EffectContract(write_scopes=["ws:out/log.txt"], exec_permissions=["fs.write"], idempotent=False, irreversible=True)
        t1 = _verified_tool(
            "tool.writer",
            binary_hash=HASH_1,
            permissions=["fs.write"],
            input_port=p,
            output_port=p,
            effect=eff_non_idem,
            preconditions=["auth_ready"],
        )
        reg = ToolRegistry()
        sign_fixture_tool(reg, t1)

        dag_eff = compute_dag_effects([eff_non_idem])
        bad_plan = CompositionPlan(
            plan_id="plan-pre-retry",
            goal_contract_hash=HASH_2,
            nodes=[{"node_id": "n1", "tool_id": "tool.writer", "max_retries": 2}],
            tool_artifact_hashes={"tool.writer": HASH_1},
            permission_union=dag_eff["permission_union"],
            effects_union=dag_eff["effects_union"],
            oracle_ref="oracle:retry",
        )
        res = self.verifier.verify(bad_plan, reg, self.ctx)
        self.assertFalse(res.valid)
        self.assertTrue(any("UNSATISFIED_PRECONDITION" in r for r in res.reasons))
        self.assertTrue(any("NON_IDEMPOTENT_RETRYABLE_STEP" in r for r in res.reasons))

    def test_rejects_untrusted_or_retired_adapter(self) -> None:
        plan, reg, adapters = self._build_valid_fixture()
        p_ns = adapters[0].source_port
        p_ms = adapters[0].target_port
        retired_adapter = _verified_adapter(
            "adapter.ns_to_ms",
            p_ns,
            p_ms,
            mapping={"fields": {"latency_ns": "latency_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": 1e-6},
            trust_status=TrustStatus.RETIRED,
        )
        res = self.verifier.verify(plan, reg, self.ctx, adapters=[retired_adapter])
        self.assertFalse(res.valid)
        self.assertEqual(res.status, "FAIL")
        self.assertTrue(any("UNTRUSTED_ADAPTER:adapter.ns_to_ms:RETIRED" in r for r in res.reasons))


if __name__ == "__main__":
    unittest.main()
