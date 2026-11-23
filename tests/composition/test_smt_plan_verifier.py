"""Tests for Build #3 SMT Neuro-Symbolic Formal Plan Verifier (`smt_plan_verifier`)."""

from __future__ import annotations

try:
    from fixture_attestation import TEST_VERIFIER_ID, make_fixture_authority, sign_fixture_adapter, sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import TEST_VERIFIER_ID, make_fixture_authority, sign_fixture_adapter, sign_fixture_tool

import builtins
import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

from kintsugi.capability.contracts_v2 import (
    AdapterSpec,
    CompositionPlan,
    EffectContract,
    PortContract,
    compute_dag_effects,
)
from kintsugi.capability.schemas import (
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.composition.smt_plan_verifier import (
    BACKEND_PYTHON,
    BACKEND_Z3,
    STATUS_COUNTEREXAMPLE,
    STATUS_ERROR,
    STATUS_PROVEN,
    FormalVerificationBundle,
    SMTProofCertificate,
    compute_declassifier_node_spec_digest,
    is_z3_available,
    prove_acyclic_and_total_order,
    prove_effect_idempotency,
    prove_no_secret_escalation,
    prove_permission_monotonicity,
    verify_bundle_digest,
    verify_certificate_digest,
    verify_plan_formal,
)

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
    permissions: List[str],
    input_port: PortContract,
    output_port: PortContract,
    effect: EffectContract,
    trust_status: TrustStatus = TrustStatus.VERIFIED,
) -> ToolSpec:
    att = _attest(tool_id, binary_hash) if trust_status == TrustStatus.VERIFIED else None
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
        side_effects=list(effect.write_scopes or ["none"]),
        required_permissions=list(permissions),
        trust_status=trust_status,
        verification_attestation=att,
    )


def _verified_adapter(
    adapter_id: str,
    src_port: PortContract,
    dst_port: PortContract,
    *,
    mapping: Dict[str, Any],
    lossless: bool = True,
    preconditions: List[str] = None,
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
        lossless=lossless,
        preconditions=list(preconditions or []),
        verification_corpus_hash=HASH_4,
        trust_status=trust_status,
        verification_attestation=att,
    )


class TestSMTPlanVerifier(unittest.TestCase):
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

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _active_backends(self) -> List[str]:
        backends = [BACKEND_PYTHON]
        if is_z3_available():
            backends.insert(0, BACKEND_Z3)
        return backends

    def _build_compliant_plan(self):
        p_secret = PortContract(schema_ref="json:secret", semantic_type="secret_doc", sensitivity="secret")
        p_pub = PortContract(schema_ref="json:public", semantic_type="summary", sensitivity="public")

        e1 = EffectContract(read_scopes=["ws:in/secret.json"], exec_permissions=["fs.read"], idempotent=True)
        e2 = EffectContract(read_scopes=["ws:in/secret.json"], exec_permissions=["ast.scan"], idempotent=True)
        e3 = EffectContract(
            write_scopes=["ws:out/report.json"],
            exec_permissions=["fs.write"],
            irreversible=False,
            idempotent=False,
        )

        t1 = _verified_tool("tool.fetch_secret", binary_hash=HASH_1, permissions=["fs.read"], input_port=p_pub, output_port=p_secret, effect=e1)
        t2 = _verified_tool("tool.analyze", binary_hash=HASH_2, permissions=["ast.scan"], input_port=p_secret, output_port=p_secret, effect=e2)
        t3 = _verified_tool("tool.publish", binary_hash=HASH_3, permissions=["fs.write"], input_port=p_pub, output_port=p_pub, effect=e3)

        declass_adapter = _verified_adapter(
            "adapter.redact_secret",
            p_secret,
            p_pub,
            mapping={"fields": {"token": "redacted_token"}, "transform": "redact_secrets"},
            lossless=False,
            preconditions=["redact_secrets"],
        )

        reg = ToolRegistry()
        sign_fixture_tool(reg, t1)
        sign_fixture_tool(reg, t2)
        sign_fixture_tool(reg, t3)
        declass_adapter = sign_fixture_adapter(reg, declass_adapter)

        dag_eff = compute_dag_effects([e1, e2, e3])
        plan = CompositionPlan(
            plan_id="plan-smt-compliant-01",
            goal_contract_hash=HASH_4,
            nodes=[
                {"node_id": "n1", "tool_id": "tool.fetch_secret", "retryable": True},
                {"node_id": "n2", "tool_id": "tool.analyze", "retryable": True},
                {
                    "node_id": "n3",
                    "tool_id": "tool.publish",
                    "retryable": True,
                    "wal_protected": True,
                    "idempotency_key": "-".join(["publish", "report", "01"]),
                },
            ],
            edges=[
                {"from_node": "n1", "to_node": "n2"},
                {
                    "from_node": "n2",
                    "to_node": "n3",
                    "adapter_id": "adapter.redact_secret",
                    "adapter_hash": declass_adapter.adapter_hash,
                },
            ],
            input_bindings={"n1.in": "goal.input"},
            tool_artifact_hashes={
                "tool.fetch_secret": HASH_1,
                "tool.analyze": HASH_2,
                "tool.publish": HASH_3,
            },
            adapter_hashes={"adapter.redact_secret": declass_adapter.adapter_hash},
            permission_union=dag_eff["permission_union"],
            effects_union=dag_eff["effects_union"],
            expected_outputs=[{"semantic_type": "summary", "sensitivity": "public"}],
            oracle_ref="oracle:smt_compliant",
            verification_plan={"mode": "replay", "adapters": {"adapter.redact_secret": declass_adapter.to_dict()}},
        )
        return plan, reg, [declass_adapter]

    def test_compliant_plan_proven_z3_and_python_parity(self) -> None:
        plan, reg, adapters = self._build_compliant_plan()
        bundles: Dict[str, FormalVerificationBundle] = {}

        for backend in self._active_backends():
            bundle = verify_plan_formal(plan, self.ctx, registry=reg, adapters=adapters, backend=backend)
            bundles[backend] = bundle

            self.assertTrue(bundle.all_proven, f"Expected all_proven=True on {backend}: {bundle.to_dict()}")
            self.assertEqual(bundle.backend, backend)
            self.assertTrue(bundle.verify_integrity())
            self.assertTrue(verify_bundle_digest(bundle.to_dict()))
            self.assertEqual(
                sorted(bundle.certificates.keys()),
                ["acyclic_and_total_order", "effect_idempotency", "no_secret_escalation", "permission_monotonicity"],
            )

            for prop_name, cert in bundle.certificates.items():
                self.assertEqual(cert.status, STATUS_PROVEN, f"{prop_name} failed on {backend}: {cert.unsat_core_or_witness}")
                self.assertEqual(cert.backend, backend)
                self.assertGreaterEqual(cert.elapsed_ms, 0.0)
                self.assertTrue(cert.verify_integrity())
                self.assertTrue(verify_certificate_digest(cert.to_dict()))
                artifact = cert.to_formal_proof_artifact()
                self.assertTrue(artifact.verified)

            order_cert = bundle.certificates["acyclic_and_total_order"]
            self.assertEqual(order_cert.unsat_core_or_witness["total_order"], ["n1", "n2", "n3"])
            if backend == BACKEND_Z3:
                self.assertTrue(order_cert.smtlib2_sha256.startswith("sha256:"))
                self.assertIn("unsat_core", bundle.certificates["no_secret_escalation"].unsat_core_or_witness)
                self.assertIn("unsat_core", bundle.certificates["permission_monotonicity"].unsat_core_or_witness)
                self.assertIn("unsat_core", bundle.certificates["effect_idempotency"].unsat_core_or_witness)

        if BACKEND_Z3 in bundles:
            for prop in bundles[BACKEND_Z3].certificates:
                self.assertEqual(
                    bundles[BACKEND_Z3].certificates[prop].status,
                    bundles[BACKEND_PYTHON].certificates[prop].status,
                )

    def test_dynamic_z3_missing_import_falls_back_cleanly(self) -> None:
        plan, reg, adapters = self._build_compliant_plan()
        real_import = builtins.__import__

        def _import_without_z3(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "z3" or name.startswith("z3."):
                raise ImportError("simulated missing z3-solver")
            return real_import(name, globals, locals, fromlist, level)

        with mock.patch("builtins.__import__", side_effect=_import_without_z3):
            self.assertFalse(is_z3_available())
            bundle = verify_plan_formal(plan, self.ctx, registry=reg, adapters=adapters)
            self.assertEqual(bundle.backend, BACKEND_PYTHON)
            self.assertTrue(bundle.all_proven)
            for cert in bundle.certificates.values():
                self.assertEqual(cert.backend, BACKEND_PYTHON)
                self.assertEqual(cert.status, STATUS_PROVEN)

            with self.assertRaises(RuntimeError):
                prove_acyclic_and_total_order(plan, backend=BACKEND_Z3)

    def test_secret_taint_leak_without_declassifier_yields_counterexample(self) -> None:
        # SECRET source -> adapter without declassifier -> PUBLIC sink
        leak_plan = {
            "schema": "CompositionPlan/1",
            "plan_id": "plan-secret-leak",
            "goal_contract_hash": HASH_1,
            "nodes": [
                {"node_id": "src_secret", "tool_id": "tool.read_vault", "output_sensitivity": "secret"},
                {"node_id": "mid_adapter", "tool_id": "adapter.passthrough", "kind": "adapter"},
                {"node_id": "dst_public", "tool_id": "tool.post_public", "sensitivity": "public"},
            ],
            "edges": [
                {"from_node": "src_secret", "to_node": "mid_adapter"},
                {"from_node": "mid_adapter", "to_node": "dst_public"},
            ],
            "expected_outputs": [{"sensitivity": "public"}],
            "oracle_ref": "oracle:leak",
        }

        for backend in self._active_backends():
            cert = prove_no_secret_escalation(leak_plan, self.ctx, backend=backend)
            self.assertEqual(cert.status, STATUS_COUNTEREXAMPLE, f"Expected leak on {backend}")
            self.assertEqual(cert.backend, backend)
            self.assertTrue(cert.verify_integrity())
            witness = cert.unsat_core_or_witness
            self.assertTrue(witness["leak_detected"])
            self.assertEqual(witness["violating_path"], ["src_secret", "mid_adapter", "dst_public"])
            self.assertEqual(witness["source_sensitivity"], "secret")
            self.assertEqual(witness["sink_ceiling"], "public")

        # Edge-level AdapterSpec without declassification transform between SECRET -> PUBLIC
        p_sec = PortContract(schema_ref="json:doc", semantic_type="doc", sensitivity="secret")
        p_sec_norm = PortContract(schema_ref="json:doc_v2", semantic_type="doc", sensitivity="secret")
        p_pub = PortContract(schema_ref="json:doc_v2", semantic_type="doc", sensitivity="public")
        lossless_ad = _verified_adapter(
            "adapter.schema_only",
            p_sec,
            p_sec_norm,
            mapping={"fields": {"body": "text"}},
            lossless=True,
        )
        reg = ToolRegistry()
        lossless_ad = sign_fixture_adapter(reg, lossless_ad)
        edge_leak_plan = CompositionPlan(
            plan_id="plan-edge-adapter-leak",
            goal_contract_hash=HASH_3,
            nodes=[
                {"node_id": "src", "tool_id": "tool.secret_src", "output_port": p_sec.to_dict()},
                {"node_id": "sink", "tool_id": "tool.pub_sink", "input_port": p_pub.to_dict()},
            ],
            edges=[
                {
                    "from_node": "src",
                    "to_node": "sink",
                    "adapter_id": "adapter.schema_only",
                    "adapter_hash": lossless_ad.adapter_hash,
                }
            ],
            adapter_hashes={"adapter.schema_only": lossless_ad.adapter_hash},
            oracle_ref="oracle:edge_leak",
        )
        for backend in self._active_backends():
            cert_edge = prove_no_secret_escalation(
                edge_leak_plan, self.ctx, registry=reg, adapters=[lossless_ad], backend=backend
            )
            self.assertEqual(cert_edge.status, STATUS_COUNTEREXAMPLE)
            self.assertEqual(cert_edge.unsat_core_or_witness["violating_path"], ["src", "sink"])
            self.assertEqual(cert_edge.unsat_core_or_witness["adapters_on_path"], ["adapter.schema_only"])

    def test_restricted_binding_and_unattested_declassifier_rejected(self) -> None:
        # Unattested declassifier (no verification_attestation) must NOT strip RESTRICTED taint
        restricted_plan = {
            "schema": "CompositionPlan/1",
            "plan_id": "plan-restricted-unattested",
            "goal_contract_hash": HASH_2,
            "nodes": [
                {"node_id": "n1", "tool_id": "tool.transform"},
                {"node_id": "n2", "tool_id": "tool.fake_redact", "declassifier": True, "target_sensitivity": "public"},
                {"node_id": "n3", "tool_id": "tool.internal_log", "input_sensitivity": "internal"},
            ],
            "edges": [
                {"from_node": "n1", "to_node": "n2"},
                {"from_node": "n2", "to_node": "n3"},
            ],
            "input_bindings": {
                "goal_sensitivities": {"goal.master_key": "restricted"},
                "n1.key": "goal.master_key",
            },
            "oracle_ref": "oracle:restricted",
        }

        for backend in self._active_backends():
            cert = prove_no_secret_escalation(restricted_plan, self.ctx, backend=backend)
            self.assertEqual(cert.status, STATUS_COUNTEREXAMPLE)
            self.assertEqual(cert.unsat_core_or_witness["source_sensitivity"], "restricted")
            self.assertEqual(cert.unsat_core_or_witness["sink_node"], "n3")
            self.assertIn("n1", cert.unsat_core_or_witness["violating_path"])
            self.assertIn("n3", cert.unsat_core_or_witness["violating_path"])

        # Self-attested / unsigned _attest(...) without authority or valid HMAC must ALSO be rejected
        forged_self_attested_plan = copy.deepcopy(restricted_plan)
        forged_self_attested_plan["nodes"][1]["binary_hash"] = HASH_3
        forged_self_attested_plan["nodes"][1]["verification_attestation"] = _attest("tool.fake_redact", HASH_3)
        auth = make_fixture_authority()
        for backend in self._active_backends():
            cert_no_auth = prove_no_secret_escalation(forged_self_attested_plan, self.ctx, backend=backend)
            self.assertEqual(cert_no_auth.status, STATUS_COUNTEREXAMPLE)
            cert_forged_hmac = prove_no_secret_escalation(
                forged_self_attested_plan, self.ctx, authority=auth, backend=backend
            )
            self.assertEqual(cert_forged_hmac.status, STATUS_COUNTEREXAMPLE)

        # Signing the declassifier node with an AttestationAuthority resolves the leak ONLY when authority is provided
        attested_plan = copy.deepcopy(restricted_plan)
        attested_plan["nodes"][1]["binary_hash"] = HASH_3
        attested_plan["nodes"][1]["verification_attestation"] = auth.issue_attestation(
            "tool.fake_redact",
            HASH_3,
            sha256_digest({"node_id": "n2", "tool_id": "tool.fake_redact", "binary_hash": HASH_3}),
            TEST_VERIFIER_ID,
            spec_digest=compute_declassifier_node_spec_digest(attested_plan["nodes"][1]),
        )
        tampered_target_plan = copy.deepcopy(attested_plan)
        tampered_target_plan["nodes"][1]["target_sensitivity"] = "internal"
        tampered_target_plan["nodes"][1]["output_port"] = {"sensitivity": "public"}
        tampered_missing_bin = copy.deepcopy(attested_plan)
        tampered_missing_bin["nodes"][1]["verification_attestation"].pop("binary_hash", None)

        for backend in self._active_backends():
            cert_missing_auth = prove_no_secret_escalation(attested_plan, self.ctx, backend=backend)
            self.assertEqual(cert_missing_auth.status, STATUS_COUNTEREXAMPLE)

            cert_tampered = prove_no_secret_escalation(tampered_target_plan, self.ctx, authority=auth, backend=backend)
            self.assertEqual(cert_tampered.status, STATUS_COUNTEREXAMPLE)

            cert_no_bin = prove_no_secret_escalation(tampered_missing_bin, self.ctx, authority=auth, backend=backend)
            self.assertEqual(cert_no_bin.status, STATUS_COUNTEREXAMPLE)

            cert_ok = prove_no_secret_escalation(attested_plan, self.ctx, authority=auth, backend=backend)
            self.assertEqual(cert_ok.status, STATUS_PROVEN)
            self.assertIn("n2", cert_ok.unsat_core_or_witness["attested_declassifiers"])

        # Adapter declassifier without authority must also fail closed
        plan_ok, reg_ok, adapters_ok = self._build_compliant_plan()
        tool_dict_reg = {tid: reg_ok.get(tid) for tid in ("tool.fetch_secret", "tool.analyze", "tool.publish")}
        for backend in self._active_backends():
            cert_adapter_no_auth = prove_no_secret_escalation(
                plan_ok, self.ctx, registry=tool_dict_reg, adapters=adapters_ok, backend=backend
            )
            self.assertEqual(cert_adapter_no_auth.status, STATUS_COUNTEREXAMPLE)

        # Registry-backed declassifier tool inherits registry.authority; forged node att still rejected
        p_sec = PortContract(schema_ref="json:sec", semantic_type="sec", sensitivity="secret")
        p_pub = PortContract(schema_ref="json:pub", semantic_type="pub", sensitivity="public")
        e_idemp = EffectContract(read_scopes=["ws:in"], exec_permissions=["fs.read"], idempotent=True)
        t_decl = _verified_tool(
            "tool.verified_redact",
            binary_hash=HASH_3,
            permissions=["fs.read"],
            input_port=p_sec,
            output_port=p_pub,
            effect=e_idemp,
        )
        decl_reg = ToolRegistry()
        sign_fixture_tool(decl_reg, t_decl)
        reg_decl_plan = copy.deepcopy(restricted_plan)
        reg_decl_plan["input_bindings"]["goal_sensitivities"] = {"goal.master_key": "secret"}
        reg_decl_plan["nodes"][1]["tool_id"] = "tool.verified_redact"
        for backend in self._active_backends():
            cert_reg_ok = prove_no_secret_escalation(reg_decl_plan, self.ctx, registry=decl_reg, backend=backend)
            self.assertEqual(cert_reg_ok.status, STATUS_PROVEN)
            self.assertIn("n2", cert_reg_ok.unsat_core_or_witness["attested_declassifiers"])

            forged_node_att_plan = copy.deepcopy(reg_decl_plan)
            forged_node_att_plan["nodes"][1]["verification_attestation"] = _attest("tool.verified_redact", HASH_3)
            cert_reg_forged_node = prove_no_secret_escalation(
                forged_node_att_plan, self.ctx, registry=decl_reg, backend=backend
            )
            self.assertEqual(cert_reg_forged_node.status, STATUS_COUNTEREXAMPLE)

            signed_node_att_plan = copy.deepcopy(reg_decl_plan)
            signed_node_att_plan["nodes"][1]["declassifier_attestation"] = decl_reg.authority.issue_attestation(
                "tool.verified_redact",
                HASH_3,
                sha256_digest({"node_id": "n2", "tool_id": "tool.verified_redact", "binary_hash": HASH_3}),
                TEST_VERIFIER_ID,
                spec_digest=compute_declassifier_node_spec_digest(signed_node_att_plan["nodes"][1]),
            )
            cert_reg_signed_node = prove_no_secret_escalation(
                signed_node_att_plan, self.ctx, registry=decl_reg, backend=backend
            )
            self.assertEqual(cert_reg_signed_node.status, STATUS_PROVEN)

    def test_transitive_permission_escalation_yields_counterexample(self) -> None:
        esc_plan = CompositionPlan(
            plan_id="plan-perm-escalation",
            goal_contract_hash=HASH_1,
            nodes=[
                {"node_id": "n1", "tool_id": "tool.read", "required_permissions": ["fs.read"]},
                {"node_id": "n2", "tool_id": "tool.scan", "required_permissions": ["ast.scan"]},
                {"node_id": "n3", "tool_id": "tool.exfil", "required_permissions": ["fs.read", "shell.exec", "net.egress"]},
            ],
            edges=[
                {"from_node": "n1", "to_node": "n2"},
                {"from_node": "n2", "to_node": "n3"},
            ],
            permission_union=["fs.read", "ast.scan"],
            oracle_ref="oracle:perm",
        )

        for backend in self._active_backends():
            cert = prove_permission_monotonicity(esc_plan, self.ctx, backend=backend)
            self.assertEqual(cert.status, STATUS_COUNTEREXAMPLE)
            self.assertTrue(cert.verify_integrity())
            w = cert.unsat_core_or_witness
            self.assertFalse(w["monotonic"])
            self.assertEqual(w["offending_node"], "n3")
            self.assertEqual(w["offending_chain"], ["n1", "n2", "n3"])
            self.assertEqual(w["missing_permissions"], ["net.egress", "shell.exec"])
            self.assertEqual(w["undeclared_in_plan_permissions"], ["net.egress", "shell.exec"])

    def test_unguarded_non_idempotent_retry_and_fanin_counterexamples(self) -> None:
        # Case A: direct retryable non-idempotent node without WAL checkpoint
        retry_plan = CompositionPlan(
            plan_id="plan-retry-unsafe",
            goal_contract_hash=HASH_1,
            nodes=[
                {"node_id": "n1", "tool_id": "tool.read", "idempotent": True},
                {"node_id": "n2", "tool_id": "tool.charge_card", "idempotent": False, "retryable": True, "max_retries": 3},
            ],
            edges=[{"from_node": "n1", "to_node": "n2"}],
            oracle_ref="oracle:retry",
        )

        # Case B: unguarded fan-in amplification into non-idempotent sink
        fanin_plan = CompositionPlan(
            plan_id="plan-fanin-unsafe",
            goal_contract_hash=HASH_2,
            nodes=[
                {"node_id": "a1", "tool_id": "tool.branch1", "idempotent": True},
                {"node_id": "a2", "tool_id": "tool.branch2", "idempotent": True},
                {"node_id": "sink", "tool_id": "tool.append_ledger", "irreversible": True, "idempotent": False},
            ],
            edges=[
                {"from_node": "a1", "to_node": "sink"},
                {"from_node": "a2", "to_node": "sink"},
            ],
            oracle_ref="oracle:fanin",
        )

        # Case C: upstream unguarded retry amplifying downstream non-idempotent node
        upstream_retry_plan = CompositionPlan(
            plan_id="plan-upstream-retry-unsafe",
            goal_contract_hash=HASH_3,
            nodes=[
                {"node_id": "u1", "tool_id": "tool.fetch", "idempotent": True, "retryable": True},
                {"node_id": "d2", "tool_id": "tool.send_webhook", "idempotent": False},
            ],
            edges=[{"from_node": "u1", "to_node": "d2"}],
            oracle_ref="oracle:upstream_retry",
        )

        for backend in self._active_backends():
            cert_a = prove_effect_idempotency(retry_plan, backend=backend)
            self.assertEqual(cert_a.status, STATUS_COUNTEREXAMPLE)
            self.assertEqual(cert_a.unsat_core_or_witness["offending_node"], "n2")
            self.assertGreaterEqual(cert_a.unsat_core_or_witness["effective_multiplicity"], 4)
            self.assertTrue(any("self_retry" in c for c in cert_a.unsat_core_or_witness["amplification_causes"]))

            cert_b = prove_effect_idempotency(fanin_plan, backend=backend)
            self.assertEqual(cert_b.status, STATUS_COUNTEREXAMPLE)
            self.assertEqual(cert_b.unsat_core_or_witness["offending_node"], "sink")
            self.assertTrue(any("fan_in_amplification" in c for c in cert_b.unsat_core_or_witness["amplification_causes"]))

            cert_c = prove_effect_idempotency(upstream_retry_plan, backend=backend)
            self.assertEqual(cert_c.status, STATUS_COUNTEREXAMPLE)
            self.assertEqual(cert_c.unsat_core_or_witness["offending_node"], "d2")
            self.assertEqual(cert_c.unsat_core_or_witness["execution_trace"], ["u1", "d2"])
            self.assertIn("upstream_unguarded_retry:u1", cert_c.unsat_core_or_witness["amplification_causes"])

            # Guarding with WAL checkpoint / idempotency_key makes it PROVEN
            protected_dict = retry_plan.to_dict()
            protected_dict["nodes"][1]["idempotency_key"] = "charge-tx-001"
            protected_dict["nodes"][1]["wal_protected"] = True
            cert_ok = prove_effect_idempotency(protected_dict, backend=backend)
            self.assertEqual(cert_ok.status, STATUS_PROVEN)
            self.assertIn("n2", cert_ok.unsat_core_or_witness["wal_protected_nodes"])

    def test_cycle_injection_and_certificate_tamper_detection(self) -> None:
        cyclic_plan = {
            "schema": "CompositionPlan/1",
            "plan_id": "plan-cyclic",
            "goal_contract_hash": HASH_1,
            "nodes": [
                {"node_id": "n1", "tool_id": "tool.a"},
                {"node_id": "n2", "tool_id": "tool.b"},
                {"node_id": "n3", "tool_id": "tool.c"},
            ],
            "edges": [
                {"from_node": "n1", "to_node": "n2"},
                {"from_node": "n2", "to_node": "n3"},
                {"from_node": "n3", "to_node": "n1"},
            ],
            "oracle_ref": "oracle:cycle",
        }

        for backend in self._active_backends():
            cyc_cert = prove_acyclic_and_total_order(cyclic_plan, backend=backend)
            self.assertEqual(cyc_cert.status, STATUS_COUNTEREXAMPLE)
            cycle = cyc_cert.unsat_core_or_witness["cycle"]
            self.assertEqual(cycle[0], cycle[-1])
            self.assertEqual(set(cycle[:-1]), {"n1", "n2", "n3"})

            bundle = verify_plan_formal(cyclic_plan, self.ctx, backend=backend)
            self.assertFalse(bundle.all_proven)
            self.assertEqual(bundle.certificates["acyclic_and_total_order"].status, STATUS_COUNTEREXAMPLE)

        # Self-loop cycle
        self_loop_plan = {
            "plan_id": "plan-self-loop",
            "nodes": [{"node_id": "solo", "tool_id": "tool.solo"}],
            "edges": [{"from_node": "solo", "to_node": "solo"}],
        }
        for backend in self._active_backends():
            self_cert = prove_acyclic_and_total_order(self_loop_plan, backend=backend)
            self.assertEqual(self_cert.status, STATUS_COUNTEREXAMPLE)
            self.assertEqual(self_cert.unsat_core_or_witness["cycle"], ["solo", "solo"])

        # Tampered certificate digest & bundle digest detection
        plan, reg, adapters = self._build_compliant_plan()
        bundle = verify_plan_formal(plan, self.ctx, registry=reg, adapters=adapters)
        cert = bundle.certificates["acyclic_and_total_order"]

        # 1. Tamper serialized certificate payload
        tampered_cert_dict = cert.to_dict()
        tampered_cert_dict["unsat_core_or_witness"]["total_order"] = ["n3", "n2", "n1"]
        self.assertFalse(verify_certificate_digest(tampered_cert_dict))
        with self.assertRaises(ValueError):
            SMTProofCertificate.from_dict(tampered_cert_dict)

        # 2. Tamper serialized proof_sha256 directly
        tampered_digest_dict = cert.to_dict()
        tampered_digest_dict["proof_sha256"] = HASH_1
        self.assertFalse(verify_certificate_digest(tampered_digest_dict))
        with self.assertRaises(ValueError):
            SMTProofCertificate.from_dict(tampered_digest_dict)

        # 3. In-place mutation of certificate instance
        mutated_cert = SMTProofCertificate.from_dict(cert.to_dict())
        mutated_cert.status = STATUS_ERROR
        self.assertFalse(mutated_cert.verify_integrity())
        self.assertFalse(verify_certificate_digest(mutated_cert))

        # 4. Tampered aggregate FormalVerificationBundle
        tampered_bundle_dict = bundle.to_dict()
        tampered_bundle_dict["certificate_sha256"] = HASH_2
        self.assertFalse(verify_bundle_digest(tampered_bundle_dict))
        with self.assertRaises(ValueError):
            FormalVerificationBundle.from_dict(tampered_bundle_dict)

        # 5. Tampered SecurityContext policy_hash rejected fail-closed
        tampered_ctx = SecurityContext(
            workspace_root=str(self.ws),
            allowed_permissions=["fs.read"],
            policy_hash=HASH_1,
        )
        err_cert = prove_permission_monotonicity(plan, tampered_ctx)
        self.assertEqual(err_cert.status, STATUS_ERROR)
        self.assertIn("SECURITY_POLICY_HASH", err_cert.unsat_core_or_witness["error"])


if __name__ == "__main__":
    unittest.main()
