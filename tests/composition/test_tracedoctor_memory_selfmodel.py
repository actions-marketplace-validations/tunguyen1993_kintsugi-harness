"""Tests for TraceDoctor (`tools/trace_doctor.py`), CompositionMemory (`composition/composition_memory.py`),
and Stage 6 FunctionalSelfModel (`self_model.py`).
"""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_tool

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from kintsugi.capability.contracts_v2 import (
    GENESIS_EVENT_HASH,
    CompositionPlan,
    CompositionReceipt,
    RunEvent,
)
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.composition.composition_memory import (
    CACHE_STATUS_HIT,
    CACHE_STATUS_INVALIDATED,
    CACHE_STATUS_MISS,
    CompositionMemory,
    derive_task_signature,
)
from kintsugi.self_model import (
    STATUS_INSUFFICIENT_EVIDENCE,
    STATUS_NO_VERIFIED_TOOL,
    STATUS_PERMISSION_DENIED,
    STATUS_SANDBOX_UNAVAILABLE,
    STATUS_VERIFIED,
    FunctionalSelfModel,
    compute_honest_test_confidence,
)
from kintsugi.shield import scan_high_entropy_secrets
from kintsugi.tools.trace_doctor import (
    MECHANISM_INTEGRITY_FAILURE,
    MECHANISM_TEMPORAL_CORRELATION,
    MECHANISM_VERIFIED_CAUSAL,
    TraceDoctor,
)

HASH_1 = "sha256:" + "1" * 64
HASH_2 = "sha256:" + "2" * 64
HASH_3 = "sha256:" + "3" * 64
HASH_4 = "sha256:" + "4" * 64
HASH_5 = "sha256:" + "5" * 64
HASH_6 = "sha256:" + "6" * 64
HASH_7 = "sha256:" + "7" * 64
HASH_8 = "sha256:" + "8" * 64
HASH_9 = "sha256:" + "9" * 64


def _make_attestation(tool_id: str, binary_hash: str, verifier_id: str = "ci-verifier-1") -> Dict[str, Any]:
    return {
        "verifier_id": verifier_id,
        "verification_digest": sha256_digest({"tool_id": tool_id, "binary_hash": binary_hash}),
        "binary_hash": binary_hash,
        "tool_id": tool_id,
        "source": "ci_attestation",
    }


def _make_verified_tool(
    tool_id: str,
    capabilities: List[str],
    *,
    version: str = "1.2.0",
    binary_hash: str = HASH_1,
    permissions: Optional[List[str]] = None,
    runtime_requirements: Optional[Dict[str, Any]] = None,
    entrypoint: Optional[str] = "tools/worker.py",
) -> ToolSpec:
    return ToolSpec(
        tool_id=tool_id,
        version=version,
        source="verified_local",
        binary_hash=binary_hash,
        capabilities=capabilities,
        required_permissions=permissions if permissions is not None else ["fs.read", "process.exec"],
        runtime_requirements=runtime_requirements if runtime_requirements is not None else {"sandbox": True},
        side_effects=["none"],
        trust_status=TrustStatus.VERIFIED,
        verification_attestation=_make_attestation(tool_id, binary_hash),
        entrypoint=entrypoint,
    )


def _append_event(
    chain: List[RunEvent],
    *,
    run_id: str,
    step_id: str,
    state: str,
    tool_id: str,
    input_digest: str = "",
    output_digest: str = "",
    elapsed_ms: float = 5.0,
    tokens_used: int = 0,
    decision_reason: str = "ok",
    resource_usage: Optional[Dict[str, Any]] = None,
    severity: Optional[str] = "INFO",
) -> RunEvent:
    prev_h = chain[-1].event_hash if chain else GENESIS_EVENT_HASH
    ev = RunEvent(
        run_id=run_id,
        step_id=step_id,
        state=state,
        tool_id=tool_id,
        input_digest=input_digest,
        output_digest=output_digest,
        elapsed_ms=elapsed_ms,
        tokens_used=tokens_used,
        decision_reason=decision_reason,
        resource_usage=resource_usage or {},
        prev_event_hash=prev_h,
        seq=len(chain),
        severity=severity,
    )
    chain.append(ev)
    return ev


class TestTraceDoctor(unittest.TestCase):
    def test_zero_failure_run_handled_cleanly(self) -> None:
        plan = CompositionPlan(
            plan_id="plan-healthy",
            goal_contract_hash=HASH_1,
            nodes=[{"node_id": "n1", "tool_id": "tool.read"}, {"node_id": "n2", "tool_id": "tool.parse"}],
            edges=[{"from_node": "n1", "to_node": "n2"}],
            tool_artifact_hashes={"tool.read": HASH_2, "tool.parse": HASH_3},
            oracle_ref="oracle:parse_v1",
        )
        events: List[RunEvent] = []
        _append_event(
            events,
            run_id="run-ok-1",
            step_id="n1",
            state="TOOL_COMPLETED",
            tool_id="tool.read",
            input_digest=HASH_1,
            output_digest=HASH_4,
        )
        _append_event(
            events,
            run_id="run-ok-1",
            step_id="n2",
            state="TOOL_COMPLETED",
            tool_id="tool.parse",
            input_digest=HASH_4,
            output_digest=HASH_5,
        )
        receipt = CompositionReceipt(
            run_id="run-ok-1",
            plan_hash=plan.plan_hash,
            policy_hash=HASH_6,
            sandbox_environment_hash=HASH_7,
            node_receipts=[
                {"node_id": "n1", "status": "PASS", "verification_status": "PASS"},
                {"node_id": "n2", "status": "PASS", "verification_status": "PASS"},
            ],
            input_digest=HASH_1,
            output_digest=HASH_5,
            oracle_result={"passed": True},
            verification_status="PASS",
            trace_digest=events[-1].event_hash,
            status=ExecutionStatus.PASS,
        )

        doctor = TraceDoctor()
        diag = doctor.diagnose(events, receipt=receipt, plan=plan)
        self.assertTrue(diag.ok)
        self.assertTrue(diag.chain_valid)
        self.assertFalse(diag.tampered)
        self.assertTrue(diag.zero_failure)
        self.assertEqual(diag.status, "NO_FAILURES_DETECTED")
        self.assertIsNone(diag.first_observable_failure)
        self.assertEqual(diag.dependency_chain, [])
        self.assertEqual(diag.candidate_root_causes, [])
        self.assertEqual(len(diag.dag_edges), 1)
        self.assertTrue(diag.receipt_summary["receipts"][0]["trace_digest_bound_to_chain"])

    def test_dag_reconstruction_first_failure_isolation_and_causal_vs_temporal(self) -> None:
        # Graph:
        #   n0 (root) -> n1 (OK) -> n3 (downstream cascade FAIL)
        #   n0 (root) -> n2 (FIRST FAILURE via node_receipt + digest link) -> n3
        #   sibling_slow (disjoint branch, ran right before n2 with WARNING + high latency)
        plan = CompositionPlan(
            plan_id="plan-dag-diag",
            goal_contract_hash=HASH_1,
            nodes=[
                {"node_id": "n0", "tool_id": "tool.ingest"},
                {"node_id": "n1", "tool_id": "tool.meta"},
                {"node_id": "sibling_slow", "tool_id": "tool.telemetry"},
                {"node_id": "n2", "tool_id": "tool.transform"},
                {"node_id": "n3", "tool_id": "tool.aggregate"},
            ],
            edges=[
                {"from_node": "n0", "to_node": "n1"},
                {"from_node": "n0", "to_node": "n2"},
                {"from_node": "n1", "to_node": "n3"},
                {"from_node": "n2", "to_node": "n3"},
            ],
            tool_artifact_hashes={
                "tool.ingest": HASH_2,
                "tool.meta": HASH_3,
                "tool.telemetry": HASH_4,
                "tool.transform": HASH_5,
                "tool.aggregate": HASH_6,
            },
            oracle_ref="oracle:agg_v1",
        )

        events: List[RunEvent] = []
        _append_event(
            events,
            run_id="run-diag-1",
            step_id="n0",
            state="TOOL_COMPLETED",
            tool_id="tool.ingest",
            input_digest=HASH_1,
            output_digest=HASH_2,
            elapsed_ms=10.0,
        )
        _append_event(
            events,
            run_id="run-diag-1",
            step_id="n1",
            state="TOOL_COMPLETED",
            tool_id="tool.meta",
            input_digest=HASH_2,
            output_digest=HASH_3,
            elapsed_ms=12.0,
        )
        # Disjoint sibling ran immediately before n2 with warning & high latency
        _append_event(
            events,
            run_id="run-diag-1",
            step_id="sibling_slow",
            state="WARN",
            tool_id="tool.telemetry",
            input_digest=HASH_8,
            output_digest=HASH_9,
            elapsed_ms=900.0,
            decision_reason="slow_telemetry_flush",
            severity="HIGH",
        )
        # n2 is the first failing node in topological order (fails with exit_code=2 in receipt)
        _append_event(
            events,
            run_id="run-diag-1",
            step_id="n2",
            state="TOOL_COMPLETED",
            tool_id="tool.transform",
            input_digest=HASH_2,
            output_digest=HASH_4,
            elapsed_ms=15.0,
            decision_reason="emitted_truncated_record",
        )
        # n3 fails downstream because n2's bad output flowed into n3
        _append_event(
            events,
            run_id="run-diag-1",
            step_id="n3",
            state="FAILED",
            tool_id="tool.aggregate",
            input_digest=HASH_4,
            output_digest="",
            elapsed_ms=3.0,
            decision_reason="upstream_schema_violation",
            resource_usage={"exit_code": 1, "error": "missing field"},
            severity="HIGH",
        )

        receipt = CompositionReceipt(
            run_id="run-diag-1",
            plan_hash=plan.plan_hash,
            policy_hash=HASH_7,
            sandbox_environment_hash=HASH_8,
            node_receipts=[
                {"node_id": "n0", "status": "PASS", "verification_status": "PASS"},
                {"node_id": "n1", "status": "PASS", "verification_status": "PASS"},
                {"node_id": "sibling_slow", "status": "PASS", "verification_status": "PASS"},
                {
                    "node_id": "n2",
                    "status": "FAIL",
                    "verification_status": "FAIL",
                    "exit_status": 2,
                    "stderr_excerpt": "Bearer SecretValueShouldRedact99",
                },
                {"node_id": "n3", "status": "FAIL", "verification_status": "FAIL", "exit_status": 1},
            ],
            oracle_result={"passed": False, "reason": "aggregate_failed"},
            verification_status="FAIL",
            status=ExecutionStatus.FAIL,
        )

        diag = TraceDoctor().diagnose(events, receipt=receipt, plan=plan)
        self.assertFalse(diag.ok)
        self.assertTrue(diag.chain_valid)
        self.assertFalse(diag.tampered)
        self.assertFalse(diag.zero_failure)
        self.assertEqual(diag.status, "FAILURE_DIAGNOSED")

        # Isolated n2 (not downstream n3, not sibling_slow)
        self.assertIsNotNone(diag.first_observable_failure)
        self.assertEqual(diag.first_observable_failure["step_id"], "n2")
        self.assertTrue(diag.first_observable_failure["receipt_failed"])

        # Dependency chain contains ONLY causal ancestors of n2: [n0, n2]
        dep_steps = [item["step_id"] for item in diag.dependency_chain]
        self.assertEqual(dep_steps, ["n0", "n2"])
        self.assertNotIn("sibling_slow", dep_steps)
        self.assertNotIn("n1", dep_steps)
        self.assertNotIn("n3", dep_steps)

        # Verify causal vs correlation distinction + evidence + distinguishing tests
        verified_causes = [c for c in diag.candidate_root_causes if c["causal_verified"]]
        correlated_causes = [
            c for c in diag.candidate_root_causes if c["mechanism_type"] == MECHANISM_TEMPORAL_CORRELATION
        ]
        self.assertTrue(any(c["step_id"] == "n2" and c["mechanism_type"] == MECHANISM_VERIFIED_CAUSAL for c in verified_causes))
        self.assertTrue(any(c["step_id"] == "sibling_slow" and not c["causal_verified"] for c in correlated_causes))
        for cause in diag.candidate_root_causes:
            self.assertTrue(len(cause["supporting_evidence"]) >= 1)
            self.assertTrue(len(cause["distinguishing_tests"]) >= 1)

        # Secret redaction in serialized diagnosis
        canon = diag.to_canonical_json()
        self.assertNotIn("SecretValueShouldRedact99", canon)
        self.assertEqual(scan_high_entropy_secrets(canon), [])

    def test_tampered_and_broken_event_chain_rejected(self) -> None:
        events: List[RunEvent] = []
        _append_event(
            events,
            run_id="run-tamper",
            step_id="s1",
            state="STARTED",
            tool_id="tool.a",
            input_digest=HASH_1,
            output_digest=HASH_2,
        )
        _append_event(
            events,
            run_id="run-tamper",
            step_id="s2",
            state="FAILED",
            tool_id="tool.b",
            input_digest=HASH_2,
            output_digest=HASH_3,
            decision_reason="real_error",
        )

        # 1. Tamper payload field in s1
        tampered_payload = [events[0].to_dict(), events[1].to_dict()]
        tampered_payload[0]["decision_reason"] = "forged_ok"
        diag_tampered = TraceDoctor().diagnose(tampered_payload)
        self.assertTrue(diag_tampered.tampered)
        self.assertFalse(diag_tampered.chain_valid)
        self.assertFalse(diag_tampered.ok)
        self.assertEqual(diag_tampered.status, "TAMPERED_EVENT_CHAIN")
        self.assertIsNone(diag_tampered.first_observable_failure)
        self.assertEqual(diag_tampered.candidate_root_causes[0]["mechanism_type"], MECHANISM_INTEGRITY_FAILURE)

        # 2. Mutating prev_event_hash without re-hashing triggers EVENT_HASH_MISMATCH
        mutated_prev = [events[0].to_dict(), events[1].to_dict()]
        mutated_prev[1]["prev_event_hash"] = HASH_9
        diag_mut_prev = TraceDoctor().diagnose(mutated_prev)
        self.assertTrue(diag_mut_prev.tampered)
        self.assertFalse(diag_mut_prev.chain_valid)
        self.assertTrue(any("EVENT_HASH_MISMATCH" in e for e in diag_mut_prev.chain_errors))

        # 3. Re-hashed event with wrong prev_event_hash triggers PREV_EVENT_HASH_MISMATCH
        rehashed_broken = RunEvent(
            run_id="run-tamper",
            step_id="s2",
            state="FAILED",
            tool_id="tool.b",
            input_digest=HASH_2,
            output_digest=HASH_3,
            decision_reason="forged_link",
            prev_event_hash=HASH_9,
            seq=1,
        )
        diag_broken = TraceDoctor().diagnose([events[0].to_dict(), rehashed_broken.to_dict()])
        self.assertTrue(diag_broken.tampered)
        self.assertFalse(diag_broken.chain_valid)
        self.assertTrue(any("PREV_EVENT_HASH_MISMATCH" in e for e in diag_broken.chain_errors))

        # 4. raise_on_tamper=True raises ValueError
        with self.assertRaises(ValueError):
            TraceDoctor().diagnose([events[0].to_dict(), rehashed_broken.to_dict()], raise_on_tamper=True)

        # 5. Receipt run_id mismatch flagged as tampered
        bad_rec = ExecutionReceipt(
            run_id="run-other",
            status=ExecutionStatus.PASS,
            plan_hash=HASH_1,
            tool_hash=HASH_2,
            policy_hash=HASH_3,
            environment_hash=HASH_4,
            verification_status="PASS",
        )
        diag_mismatch = TraceDoctor().diagnose(events, receipt=bad_rec)
        self.assertTrue(diag_mismatch.tampered)
        self.assertTrue(any("RECEIPT_RUN_ID_MISMATCH" in e for e in diag_mismatch.chain_errors))

    def test_empty_events_with_failing_receipt_and_oracle_boundary(self) -> None:
        # Empty events + healthy -> NO_FAILURES_DETECTED
        ok_diag = TraceDoctor().diagnose([])
        self.assertTrue(ok_diag.zero_failure)
        self.assertEqual(ok_diag.status, "NO_FAILURES_DETECTED")

        # Empty events + PERMISSION_DENIED ExecutionReceipt -> FAILURE_DIAGNOSED at boundary
        denied_rec = ExecutionReceipt(
            run_id="run-precheck-deny",
            status=ExecutionStatus.PERMISSION_DENIED,
            plan_hash=HASH_1,
            tool_hash=HASH_2,
            policy_hash=HASH_3,
            environment_hash=HASH_4,
            exit_status=126,
            verification_status="FAIL",
            stderr_excerpt="OVER_PRIVILEGED_PERMISSIONS:process.exec",
        )
        deny_diag = TraceDoctor().diagnose([], receipt=denied_rec)
        self.assertFalse(deny_diag.ok)
        self.assertFalse(deny_diag.zero_failure)
        self.assertEqual(deny_diag.status, "FAILURE_DIAGNOSED")
        self.assertIsNotNone(deny_diag.first_observable_failure)
        self.assertEqual(deny_diag.candidate_root_causes[0]["category"], "POLICY_OR_PERMISSION_DENIAL")

        # Completed event + CompositionReceipt failing oracle_result
        events: List[RunEvent] = []
        _append_event(
            events,
            run_id="run-oracle-fail",
            step_id="n1",
            state="TOOL_COMPLETED",
            tool_id="tool.calc",
            input_digest=HASH_1,
            output_digest=HASH_2,
        )
        comp_fail = CompositionReceipt(
            run_id="run-oracle-fail",
            plan_hash=HASH_3,
            policy_hash=HASH_4,
            sandbox_environment_hash=HASH_5,
            oracle_result={"passed": False, "reason": "oracle_mismatch"},
            verification_status="FAIL",
            status=ExecutionStatus.FAIL,
        )
        ora_diag = TraceDoctor().diagnose(events, receipt=comp_fail)
        self.assertFalse(ora_diag.ok)
        self.assertEqual(ora_diag.candidate_root_causes[0]["category"], "ORACLE_VERIFICATION_FAILURE")


class TestCompositionMemory(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.mem_path = self.ws / ".kintsugi" / "composition_memory.json"
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "process.exec"],
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_full_provenance_cache_hit_and_all_invalidation_axes(self) -> None:
        goal_contract = {
            "goal_id": "goal-compose-1",
            "required_capabilities": ["log.scan", "sarif.emit"],
            "expected_outputs": [{"semantic_type": "sarif"}],
        }
        task_sig = derive_task_signature(goal_contract)
        plan = CompositionPlan(
            plan_id="plan-comp-1",
            goal_contract_hash=sha256_digest(goal_contract),
            nodes=[
                {"node_id": "n1", "tool_id": "tool.scan"},
                {"node_id": "n2", "tool_id": "adapter.to_sarif", "kind": "adapter"},
                {"node_id": "n3", "tool_id": "tool.emit"},
            ],
            edges=[
                {"from_node": "n1", "to_node": "n2"},
                {"from_node": "n2", "to_node": "n3"},
            ],
            tool_artifact_hashes={"tool.scan": HASH_1, "tool.emit": HASH_2},
            adapter_hashes={"adapter.to_sarif": HASH_3},
            oracle_ref="oracle:sarif_v1",
        )
        receipt = CompositionReceipt(
            run_id="run-comp-1",
            plan_hash=plan.plan_hash,
            policy_hash=self.ctx.policy_hash,
            sandbox_environment_hash=HASH_4,
            node_receipts=[{"node_id": "n1", "status": "PASS"}],
            oracle_result={"passed": True},
            verification_status="PASS",
            status=ExecutionStatus.PASS,
        )

        mem = CompositionMemory(self.mem_path, workspace_root=self.ws)
        mem.store(
            plan,
            task_signature=task_sig,
            receipt=receipt,
            schema_hashes={"n1.out": HASH_5, "n3.out": HASH_6},
            oracle_hash=HASH_7,
            runtime_version="kintsugi-2.5.0",
            tool_attestation_digests={"tool.scan": HASH_8, "tool.emit": HASH_9},
        )
        self.assertEqual(stat.S_IMODE(self.mem_path.stat().st_mode), 0o600)

        # Reload from disk and verify exact full-provenance CACHE_HIT
        reloaded = CompositionMemory(self.mem_path, workspace_root=self.ws)
        base_query = {
            "task_signature": task_sig,
            "current_tool_hashes": {"tool.scan": HASH_1, "tool.emit": HASH_2},
            "current_adapter_hashes": {"adapter.to_sarif": HASH_3},
            "current_schema_hashes": {"n1.out": HASH_5, "n3.out": HASH_6},
            "current_policy_hash": self.ctx.policy_hash,
            "current_oracle_ref": "oracle:sarif_v1",
            "current_oracle_hash": HASH_7,
            "current_runtime_version": "kintsugi-2.5.0",
        }
        hit_res = reloaded.retrieve(**base_query)
        self.assertEqual(hit_res.status, CACHE_STATUS_HIT)
        self.assertTrue(hit_res.hit)
        self.assertTrue(bool(hit_res))
        self.assertIsNotNone(hit_res.plan)
        self.assertEqual(hit_res.plan.plan_hash, plan.plan_hash)

        # Different task signature -> CACHE_MISS
        miss_res = reloaded.retrieve(**{**base_query, "task_signature": "unrelated-task"})
        self.assertEqual(miss_res.status, CACHE_STATUS_MISS)
        self.assertFalse(miss_res.hit)
        self.assertIsNone(miss_res.plan)

        # Gate G4: Every single mutation axis MUST return CACHE_INVALIDATED with plan=None
        mutations = [
            ("binary_swap", {"current_tool_hashes": {"tool.scan": HASH_9, "tool.emit": HASH_2}}, "TOOL_ARTIFACT_HASH_CHANGED"),
            ("adapter_swap", {"current_adapter_hashes": {"adapter.to_sarif": HASH_9}}, "ADAPTER_HASH_CHANGED"),
            ("schema_change", {"current_schema_hashes": {"n1.out": HASH_9, "n3.out": HASH_6}}, "SCHEMA_HASH_CHANGED"),
            ("policy_change", {"current_policy_hash": HASH_9}, "POLICY_HASH_CHANGED"),
            ("oracle_ref_change", {"current_oracle_ref": "oracle:sarif_v2"}, "ORACLE_REF_CHANGED"),
            ("oracle_hash_change", {"current_oracle_hash": HASH_9}, "ORACLE_HASH_CHANGED"),
            ("runtime_version_change", {"current_runtime_version": "kintsugi-2.6.0"}, "RUNTIME_VERSION_CHANGED"),
            ("retired_tool", {"retired_tool_ids": ["tool.emit"]}, "TOOL_RETIRED"),
            ("revoked_attestation_digest", {"revoked_attestation_digests": [HASH_8]}, "ATTESTATION_REVOKED"),
            ("missing_provenance", {"current_policy_hash": None}, "MISSING_PROVENANCE"),
        ]
        for label, overrides, expected_prefix in mutations:
            query = {**base_query, **overrides}
            inv_res = reloaded.retrieve(**query)
            self.assertEqual(inv_res.status, CACHE_STATUS_INVALIDATED, f"{label} did not invalidate")
            self.assertFalse(inv_res.hit)
            self.assertFalse(bool(inv_res))
            self.assertIsNone(inv_res.plan)
            self.assertTrue(
                any(r.startswith(expected_prefix) for r in inv_res.reasons),
                f"{label} expected reason starting with {expected_prefix}, got {inv_res.reasons}",
            )

        # Revocation via ToolRegistry quarantine -> CACHE_INVALIDATED
        reg = ToolRegistry()
        sign_fixture_tool(reg, _make_verified_tool("tool.scan", ["log.scan"], binary_hash=HASH_1))
        sign_fixture_tool(reg, _make_verified_tool("tool.emit", ["sarif.emit"], binary_hash=HASH_2))
        self.assertEqual(reloaded.retrieve(**{**base_query, "registry": reg}).status, CACHE_STATUS_HIT)
        reg.quarantine("tool.scan", "cve_detected")
        reg_inv = reloaded.retrieve(**{**base_query, "registry": reg})
        self.assertEqual(reg_inv.status, CACHE_STATUS_INVALIDATED)
        self.assertTrue(any("ATTESTATION_REVOKED:tool.scan" in r for r in reg_inv.reasons))

        # Persistent attestation revocation
        revoked_count = reloaded.revoke_attestation(tool_id="tool.emit", reason="manual_revoke")
        self.assertEqual(revoked_count, 1)
        reloaded_after_revoke = CompositionMemory(self.mem_path, workspace_root=self.ws)
        perm_inv = reloaded_after_revoke.retrieve(**base_query)
        self.assertEqual(perm_inv.status, CACHE_STATUS_INVALIDATED)
        self.assertIsNone(perm_inv.plan)

    def test_symlink_rejection_and_refuse_failed_receipt(self) -> None:
        ext_target = Path(self._tmp.name) / "outside.json"
        ext_target.write_text("{}", encoding="utf-8")
        (self.ws / ".kintsugi").mkdir(parents=True, exist_ok=True)
        self.mem_path.symlink_to(ext_target)
        with self.assertRaises(PermissionError):
            CompositionMemory(self.mem_path, workspace_root=self.ws)

        clean_mem = CompositionMemory(self.ws / ".kintsugi" / "clean_mem.json", workspace_root=self.ws)
        plan = CompositionPlan(
            plan_id="plan-fail",
            goal_contract_hash=HASH_1,
            nodes=[{"node_id": "n1", "tool_id": "tool.a"}],
            tool_artifact_hashes={"tool.a": HASH_2},
            oracle_ref="oracle:v1",
        )
        fail_rec = CompositionReceipt(
            run_id="run-fail",
            plan_hash=plan.plan_hash,
            policy_hash=self.ctx.policy_hash,
            sandbox_environment_hash=HASH_3,
            oracle_result={"passed": False},
            verification_status="FAIL",
            status=ExecutionStatus.FAIL,
        )
        with self.assertRaises(ValueError):
            clean_mem.store(plan, receipt=fail_rec, runtime_version="kintsugi-2.5.0")

    def test_tampered_persisted_entry_quarantined_on_load(self) -> None:
        plan = CompositionPlan(
            plan_id="plan-tamper-disk",
            goal_contract_hash=HASH_1,
            nodes=[{"node_id": "n1", "tool_id": "tool.a"}],
            tool_artifact_hashes={"tool.a": HASH_2},
            oracle_ref="oracle:v1",
        )
        mem = CompositionMemory(self.mem_path, workspace_root=self.ws)
        mem.store(
            plan,
            task_signature="sig-disk",
            policy_hash=self.ctx.policy_hash,
            schema_hash=HASH_3,
            runtime_version="kintsugi-2.5.0",
        )
        # Tamper persisted JSON on disk by flipping verification_status and plan_hash
        raw = json.loads(self.mem_path.read_text(encoding="utf-8"))
        raw["entries"][0]["verification_status"] = "FAIL"
        self.mem_path.write_text(json.dumps(raw), encoding="utf-8")

        reloaded = CompositionMemory(self.mem_path, workspace_root=self.ws)
        self.assertEqual(len(reloaded.quarantined), 1)
        res = reloaded.retrieve(
            task_signature="sig-disk",
            current_tool_hashes={"tool.a": HASH_2},
            current_schema_hash=HASH_3,
            current_policy_hash=self.ctx.policy_hash,
            current_oracle_ref="oracle:v1",
            current_runtime_version="kintsugi-2.5.0",
        )
        self.assertEqual(res.status, CACHE_STATUS_MISS)
        self.assertIsNone(res.plan)


class TestFunctionalSelfModel(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.model_path = self.ws / ".kintsugi" / "functional_self_model.json"
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "process.exec"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_honest_confidence_persistence_and_readiness_verdicts(self) -> None:
        # 0/0 observed tests MUST yield 0.0 confidence (no prior inflation!)
        zero_conf = compute_honest_test_confidence(0, 0)
        self.assertEqual(zero_conf["confidence"], 0.0)
        self.assertEqual(zero_conf["pass_rate"], 0.0)
        self.assertEqual(zero_conf["evidence_status"], STATUS_INSUFFICIENT_EVIDENCE)

        # Small sample n=1 has conservative lower bound < 1.0
        one_conf = compute_honest_test_confidence(1, 1)
        self.assertEqual(one_conf["pass_rate"], 1.0)
        self.assertLess(one_conf["confidence"], 0.30)

        reg = ToolRegistry()
        verified_scanner = _make_verified_tool(
            "tool.scanner", ["code.scan"], version="2.1.0", binary_hash=HASH_1
        )
        discovered_parser = ToolSpec(
            tool_id="tool.unverified_parser",
            version="0.1.0",
            source="local_discovery",
            binary_hash=HASH_2,
            capabilities=["doc.parse"],
            required_permissions=["fs.read"],
            trust_status=TrustStatus.DISCOVERED,
        )
        net_tool = _make_verified_tool(
            "tool.net_fetch",
            ["web.fetch"],
            version="1.0.0",
            binary_hash=HASH_3,
            permissions=["fs.read", "network.outbound"],
            runtime_requirements={"network": True, "sandbox": True},
        )
        sign_fixture_tool(reg, verified_scanner)
        reg.register(discovered_parser, trusted_attestor=False)
        sign_fixture_tool(reg, net_tool)

        model = FunctionalSelfModel(self.model_path, workspace_root=self.ws)
        model.sync_from_registry(reg)
        model.record_host_limitation("gpu_cuda", "No CUDA GPU present on Apple M2 host")
        model.record_verified_skill(
            "skill.sarif_lint",
            capabilities=["sarif.lint"],
            version="1.0.0",
            verification_digest=HASH_4,
            passed_tests=8,
            total_tests=8,
        )
        model.add_active_goal("goal-1", description="Audit repo", required_capabilities=["code.scan"])
        model.start_run("run-active-1", goal_id="goal-1", capabilities=["code.scan"], tool_ids=["tool.scanner"])
        model.record_failure(
            run_id="run-past-0",
            capability="doc.parse",
            tool_id="tool.unverified_parser",
            status="NO_VERIFIED_TOOL",
            reason="discovered tool unverified",
        )

        self.assertEqual(stat.S_IMODE(self.model_path.stat().st_mode), 0o600)
        self.assertEqual(model.tool_versions["tool.scanner"], "2.1.0")
        self.assertNotIn("doc.parse", model.available_capabilities)
        self.assertTrue(
            any(u["kind"] == "unverified_discovered_tool" and u["subject"] == "tool.unverified_parser" for u in model.known_unknowns)
        )

        # 1. Missing or unverified capability -> NO_VERIFIED_TOOL
        r_missing = model.query_readiness(["quantum.compile"], self.ctx)
        self.assertEqual(r_missing.status, STATUS_NO_VERIFIED_TOOL)
        self.assertFalse(r_missing.ready)

        r_disc = model.query_readiness(["doc.parse"], self.ctx)
        self.assertEqual(r_disc.status, STATUS_NO_VERIFIED_TOOL)

        # 2. Verified tool with 0 observed tests -> INSUFFICIENT_EVIDENCE (never fabricated!)
        r_no_tests = model.query_readiness(["code.scan"], self.ctx, sandbox_available=True)
        self.assertEqual(r_no_tests.status, STATUS_INSUFFICIENT_EVIDENCE)
        self.assertFalse(r_no_tests.ready)
        self.assertEqual(r_no_tests.per_capability["code.scan"]["confidence"], 0.0)

        # 3. Network tool disallowed by policy -> PERMISSION_DENIED
        r_perm = model.query_readiness(["web.fetch"], self.ctx, sandbox_available=True)
        self.assertEqual(r_perm.status, STATUS_PERMISSION_DENIED)

        # 4. Sandbox unavailable when tool requires sandbox -> SANDBOX_UNAVAILABLE
        model.record_test_results("code.scan", passed=10, total=10, tool_id="tool.scanner")
        r_nosb = model.query_readiness(["code.scan"], self.ctx, sandbox_available=False)
        self.assertEqual(r_nosb.status, STATUS_SANDBOX_UNAVAILABLE)
        self.assertFalse(r_nosb.ready)

        # 5. Sandbox available + verified tool + observed passing tests -> VERIFIED
        r_ok = model.query_readiness(["code.scan"], self.ctx, sandbox_available=True)
        self.assertEqual(r_ok.status, STATUS_VERIFIED)
        self.assertTrue(r_ok.ready)
        self.assertGreater(r_ok.per_capability["code.scan"]["confidence"], 0.70)

        # 6. Reload from disk and verify full persistence
        reloaded = FunctionalSelfModel(self.model_path, workspace_root=self.ws)
        self.assertEqual(reloaded.tool_versions, model.tool_versions)
        self.assertEqual(reloaded.confidence_from_tests["code.scan"]["passed"], 10)
        self.assertEqual(reloaded.confidence_from_tests["code.scan"]["total"], 10)
        self.assertIn("skill.sarif_lint", reloaded.verified_skills)
        self.assertIn("run-active-1", reloaded.ongoing_runs)
        self.assertEqual(len(reloaded.failure_history), 1)
        self.assertEqual(len(reloaded.active_goals), 1)
        self.assertEqual(reloaded.query_readiness(["code.scan"], self.ctx, sandbox_available=True).status, STATUS_VERIFIED)

        # Confirm zero consciousness/sentience claims in persisted JSON
        persisted_text = self.model_path.read_text(encoding="utf-8").lower()
        for forbidden_term in ("conscious", "sentient", "i feel", "qualia"):
            self.assertNotIn(forbidden_term, persisted_text)

    def test_propose_bounded_subgoals_never_expands_permissions(self) -> None:
        reg = ToolRegistry()
        sign_fixture_tool(reg, _make_verified_tool("tool.scanner", ["code.scan"], permissions=["fs.read", "process.exec"]))
        model = FunctionalSelfModel(self.model_path, workspace_root=self.ws)
        model.sync_from_registry(reg)
        model.record_test_results("code.scan", passed=5, total=5, tool_id="tool.scanner")

        restricted_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.GITHUB_PUBLIC,
            allowed_permissions=["fs.read"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

        # Attempted permission / network expansion MUST be blocked
        for bad_goal in (
            {"goal_id": "g-write", "required_capabilities": ["code.scan"], "requested_permissions": ["fs.write"]},
            {"goal_id": "g-net", "required_capabilities": ["code.scan"], "network_required": True},
            {"goal_id": "g-native", "required_capabilities": ["code.scan"], "allow_untrusted_native": True},
        ):
            res_bad = model.propose_bounded_subgoals(bad_goal, restricted_ctx)
            self.assertEqual(res_bad.status, STATUS_PERMISSION_DENIED)
            self.assertTrue(res_bad.permission_expansion_blocked)
            self.assertEqual(res_bad.subgoals, [])

        # Valid bounded goal under LOCAL_RESEARCH proposes scoped subgoals within allowed permissions
        valid_goal = {
            "goal_id": "g-audit",
            "required_capabilities": ["code.scan", "missing.cap", "c3", "c4", "c5"],
        }
        proposal = model.propose_bounded_subgoals(valid_goal, restricted_ctx, max_subgoals=8)
        # GITHUB_PUBLIC bounds max subgoals to 4
        self.assertLessEqual(len(proposal.subgoals), 4)
        self.assertFalse(proposal.permission_expansion_blocked)
        for sg in proposal.subgoals:
            self.assertEqual(sg["parent_goal_id"], "g-audit")
            self.assertTrue(sg["serves_current_goal_only"])
            self.assertTrue(set(sg["required_permissions"]).issubset(set(restricted_ctx.allowed_permissions)))
            self.assertFalse(sg["network_allowed"])
            self.assertFalse(sg["allow_untrusted_native"])

        # In-memory tampered SecurityContext MUST yield PERMISSION_DENIED in both methods
        tampered_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.GITHUB_PUBLIC,
            allowed_permissions=["fs.read"],
        )
        tampered_ctx.allowed_permissions.append("process.exec")
        self.assertEqual(model.query_readiness(["code.scan"], tampered_ctx).status, STATUS_PERMISSION_DENIED)
        self.assertEqual(model.propose_bounded_subgoals(valid_goal, tampered_ctx).status, STATUS_PERMISSION_DENIED)

        # Partial failing tests MUST return INSUFFICIENT_EVIDENCE (never VERIFIED)
        model.record_test_results("code.scan", passed=3, total=5, tool_id="tool.scanner")
        self.assertEqual(
            model.query_readiness(["code.scan"], self.ctx, sandbox_available=True).status,
            STATUS_INSUFFICIENT_EVIDENCE,
        )

        # Symlink target for self-model path MUST fail closed
        ext = Path(self._tmp.name) / "ext_self_model.json"
        ext.write_text("{}", encoding="utf-8")
        sym_path = self.ws / ".kintsugi" / "sym_self_model.json"
        sym_path.symlink_to(ext)
        with self.assertRaises(PermissionError):
            FunctionalSelfModel(sym_path, workspace_root=self.ws)


if __name__ == "__main__":
    unittest.main()
