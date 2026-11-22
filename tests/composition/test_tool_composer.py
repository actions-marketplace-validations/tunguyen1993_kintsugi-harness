"""Comprehensive unit, security, and checkpoint/resume tests for Stage 2 ToolComposer."""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_adapter, sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_adapter, sign_fixture_tool

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List

from kintsugi.capability.contracts_v2 import (
    AdapterSpec,
    CompositionPlan,
    EffectContract,
    PortContract,
    RunEvent,
    verify_event_chain,
)
from kintsugi.capability.schemas import (
    ExecutionStatus,
    Experience,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.composition import (
    CompositionPlanResult,
    MissingAdapterGap,
    ToolComposer,
    extract_tool_effect_contract,
)
from kintsugi.config import KintsugiConfig
from kintsugi.runtime.experience_store import ExperienceStore
from kintsugi.runtime.secure_runner import SecureRunner, compute_file_sha256_confined

HASH_1 = "sha256:" + "1" * 64
HASH_2 = "sha256:" + "2" * 64
HASH_3 = "sha256:" + "3" * 64


def _attest_tool(tool_id: str, binary_hash: str, verifier_id: str = "ci-verifier") -> Dict[str, Any]:
    return {
        "verifier_id": verifier_id,
        "verification_digest": sha256_digest({"tool_id": tool_id, "binary_hash": binary_hash}),
        "binary_hash": binary_hash,
        "tool_id": tool_id,
        "source": "ci_attestation",
    }


def _make_verified_callable_tool(
    runner: SecureRunner,
    registry: ToolRegistry,
    *,
    tool_id: str,
    capabilities: List[str],
    fn: Callable[[Dict[str, Any]], Any],
    input_port: PortContract | None = None,
    input_ports: Dict[str, PortContract] | None = None,
    output_port: PortContract | None = None,
    permissions: List[str] | None = None,
    side_effects: List[str] | None = None,
    effect_contract: EffectContract | None = None,
    latency_ms: float = 5.0,
    memory_mb: float = 32.0,
    api_tokens: int = 0,
) -> ToolSpec:
    bin_hash = runner.register_trusted_host_callable(tool_id, fn)
    req: Dict[str, Any] = {"callable_name": tool_id}
    if effect_contract is not None:
        req["effect_contract"] = effect_contract.to_dict()
    sem: Dict[str, Any] = {}
    if input_port is not None:
        sem["input_port"] = input_port.to_dict()
    if input_ports is not None:
        sem["input_ports"] = {k: v.to_dict() for k, v in input_ports.items()}
    if output_port is not None:
        sem["output_port"] = output_port.to_dict()

    spec = ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="builtin",
        binary_hash=bin_hash,
        capabilities=capabilities,
        input_schema=input_port.to_dict() if input_port is not None else {},
        output_schema=output_port.to_dict() if output_port is not None else {},
        semantic_contract=sem,
        side_effects=side_effects if side_effects is not None else ["none"],
        required_permissions=permissions if permissions is not None else ["fs.read"],
        runtime_requirements=req,
        trust_status=TrustStatus.VERIFIED,
        latency_estimate_ms=latency_ms,
        memory_estimate_mb=memory_mb,
        api_token_estimate=api_tokens,
        verification_attestation=_attest_tool(tool_id, bin_hash),
    )
    sign_fixture_tool(registry, spec)
    return spec


def _make_verified_adapter(
    adapter_id: str,
    source_port: PortContract,
    target_port: PortContract,
    mapping: Dict[str, Any],
    *,
    unit_conversion: Dict[str, Any] | None = None,
    lossless: bool = True,
    preconditions: List[str] | None = None,
    trust_status: TrustStatus = TrustStatus.VERIFIED,
    registry: ToolRegistry | None = None,
    callable_hash: str = "",
) -> AdapterSpec:
    base = AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=source_port,
        target_port=target_port,
        mapping=mapping,
        unit_conversion=unit_conversion,
        lossless=lossless,
        preconditions=preconditions or [],
        verification_corpus_hash=HASH_1,
        trust_status=TrustStatus.DISCOVERED,
    )
    if trust_status != TrustStatus.VERIFIED:
        return AdapterSpec(
            adapter_id=adapter_id,
            version="1.0.0",
            source_port=source_port,
            target_port=target_port,
            mapping=mapping,
            unit_conversion=unit_conversion,
            lossless=lossless,
            preconditions=preconditions or [],
            verification_corpus_hash=HASH_1,
            trust_status=trust_status,
        )
    spec = AdapterSpec(
        adapter_id=adapter_id,
        version="1.0.0",
        source_port=source_port,
        target_port=target_port,
        mapping=mapping,
        unit_conversion=unit_conversion,
        lossless=lossless,
        preconditions=preconditions or [],
        verification_corpus_hash=HASH_1,
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={
            "verifier_id": "ci-adapter-verifier",
            "verification_digest": HASH_2,
            "adapter_id": adapter_id,
            "adapter_hash": base.adapter_hash,
        },
    )
    if registry is not None:
        return sign_fixture_adapter(registry, spec, callable_hash=callable_hash)
    return spec


class TestToolComposer(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "process.exec"],
            network_allowed=False,
            allow_untrusted_native=False,
        )
        self.registry = ToolRegistry()
        self.runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=self.registry.authority)
        self.composer = ToolComposer()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_three_tool_plus_adapter_dag_plan_and_execute(self) -> None:
        p_raw = PortContract(schema_ref="json:object", semantic_type="raw_trace", unit="none")
        p_dur_ns = PortContract(schema_ref="json:metrics", semantic_type="request_duration", unit="ns", precision="float64")
        p_dur_ms = PortContract(schema_ref="json:metrics", semantic_type="request_duration", unit="ms", precision="float64")
        p_stats = PortContract(schema_ref="json:summary", semantic_type="latency_stats", unit="ms", precision="float64")
        p_report = PortContract(schema_ref="json:report", semantic_type="slo_report", unit="none")

        call_order_log = self.ws / ".test_call_order.log"

        def fn_collect(args: Dict[str, Any]) -> Dict[str, Any]:
            with call_order_log.open("a", encoding="utf-8") as cf:
                cf.write("collect\n")
            samples = args.get("samples_ns") or [1_500_000, 2_500_000]
            return {"dur_ns": sum(samples), "count": len(samples)}

        def fn_aggregate(args: Dict[str, Any]) -> Dict[str, Any]:
            with call_order_log.open("a", encoding="utf-8") as cf:
                cf.write("aggregate\n")
            total_ms = float(args["dur_ms"])
            count = int(args["count"])
            return {"avg_ms": total_ms / count, "count": count}

        def fn_report(args: Dict[str, Any]) -> Dict[str, Any]:
            with call_order_log.open("a", encoding="utf-8") as cf:
                cf.write("report\n")
            return {"slo_ok": args["avg_ms"] <= 5.0, "avg_ms": args["avg_ms"], "count": args["count"]}

        t1 = _make_verified_callable_tool(
            self.runner,
            self.registry,
            tool_id="tool.collect",
            capabilities=["trace.collect"],
            fn=fn_collect,
            input_port=p_raw,
            output_port=p_dur_ns,
            permissions=["fs.read"],
        )
        t2 = _make_verified_callable_tool(
            self.runner,
            self.registry,
            tool_id="tool.aggregate",
            capabilities=["trace.aggregate"],
            fn=fn_aggregate,
            input_port=p_dur_ms,
            output_port=p_stats,
            permissions=["fs.read"],
        )
        t3 = _make_verified_callable_tool(
            self.runner,
            self.registry,
            tool_id="tool.report",
            capabilities=["report.slo"],
            fn=fn_report,
            input_port=p_stats,
            output_port=p_report,
            permissions=["fs.write"],
        )
        adapter = _make_verified_adapter(
            "adapter.ns_to_ms",
            p_dur_ns,
            p_dur_ms,
            {"fields": {"dur_ns": "dur_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            registry=self.registry,
        )

        goal = {
            "goal_id": "slo-pipeline",
            "required_capabilities": ["trace.collect", "trace.aggregate", "report.slo"],
            "input_port": p_raw,
            "expected_outputs": [p_report],
            "oracle_ref": "oracle:slo_v1",
        }
        plan_res = self.composer.plan(goal, self.registry, self.ctx, adapters=[adapter])
        self.assertIsInstance(plan_res, CompositionPlanResult)
        self.assertTrue(plan_res.ok, msg=plan_res.reasons)
        self.assertEqual(plan_res.status, ExecutionStatus.PASS)
        self.assertEqual(plan_res.llm_calls, 0)
        self.assertIsNotNone(plan_res.plan)
        plan = plan_res.plan
        assert plan is not None

        self.assertEqual(len(plan.nodes), 3)
        self.assertEqual([n["tool_id"] for n in plan.nodes], ["tool.collect", "tool.aggregate", "tool.report"])
        self.assertEqual(
            plan.tool_artifact_hashes,
            {
                "tool.collect": t1.binary_hash,
                "tool.aggregate": t2.binary_hash,
                "tool.report": t3.binary_hash,
            },
        )
        self.assertEqual(plan.adapter_hashes, {"adapter.ns_to_ms": adapter.adapter_hash})
        self.assertEqual(plan.permission_union, ["fs.read", "fs.write"])
        self.assertEqual(plan.effects_union["exec_permissions"], ["fs.read", "fs.write"])
        self.assertTrue(any(e.get("adapter_id") == "adapter.ns_to_ms" for e in plan.edges))
        # Canonical roundtrip validation
        reloaded_plan = CompositionPlan.from_dict(json.loads(plan.to_canonical_json()))
        self.assertEqual(reloaded_plan.plan_hash, plan.plan_hash)

        receipt, events = self.composer.execute_plan(
            plan,
            self.registry,
            self.ctx,
            runner=self.runner,
            initial_inputs={"samples_ns": [1_500_000, 2_500_000]},
            oracle=lambda d: d["output"] == {"slo_ok": True, "avg_ms": 2.0, "count": 2},
        )
        self.assertEqual(receipt.status, ExecutionStatus.PASS)
        self.assertEqual(receipt.verification_status, "PASS")
        self.assertTrue(receipt.oracle_result["passed"])
        call_order = call_order_log.read_text(encoding="utf-8").splitlines() if call_order_log.exists() else []
        self.assertEqual(call_order, ["collect", "aggregate", "report"])
        self.assertEqual(len(receipt.node_receipts), 3)
        self.assertTrue(all(nr["llm_calls"] == 0 for nr in receipt.node_receipts))
        chain_check = verify_event_chain(events)
        self.assertTrue(chain_check.valid, msg=chain_check.reasons)
        self.assertTrue(any(ev.state == "ADAPTER_APPLIED" and ev.tool_id == "adapter.ns_to_ms" for ev in events))

    def test_workspace_script_tools_and_custom_adapter_callable_execution(self) -> None:
        s1_path = self.ws / "tools" / "step1.py"
        s2_path = self.ws / "tools" / "step2.py"
        s3_path = self.ws / "tools" / "step3.py"
        s1_path.parent.mkdir(parents=True, exist_ok=True)
        s1_path.write_text("import json\nprint(json.dumps({'raw_ns': 3000000}))\n", encoding="utf-8")
        s2_path.write_text("import json, sys\nprint(json.dumps({'ms_val': 3.0, 'doubled': 6.0}))\n", encoding="utf-8")
        s3_path.write_text("import json\nprint(json.dumps({'final_ok': True}))\n", encoding="utf-8")

        p1 = PortContract(schema_ref="json:obj", semantic_type="latency", unit="ns")
        p2 = PortContract(schema_ref="json:obj", semantic_type="latency", unit="ms")
        p3 = PortContract(schema_ref="json:obj", semantic_type="scaled_latency", unit="ms")
        p4 = PortContract(schema_ref="json:obj", semantic_type="verdict", unit="none")

        for tid, rel, cap, in_p, out_p in (
            ("script.one", "tools/step1.py", "s.one", None, p1),
            ("script.two", "tools/step2.py", "s.two", p2, p3),
            ("script.three", "tools/step3.py", "s.three", p3, p4),
        ):
            _, dig = compute_file_sha256_confined(self.ws / rel, (self.ws,))
            spec = ToolSpec(
                tool_id=tid,
                version="1.0.0",
                source="verified_local",
                binary_hash=dig,
                capabilities=[cap],
                input_schema=in_p.to_dict() if in_p else {},
                output_schema=out_p.to_dict(),
                required_permissions=["fs.read", "process.exec"],
                trust_status=TrustStatus.VERIFIED,
                verification_attestation=_attest_tool(tid, dig),
                entrypoint=rel,
            )
            sign_fixture_tool(self.registry, spec)

        adapter_log = self.ws / "adapter_invocations.jsonl"

        def custom_adapter_fn(payload: Any) -> Dict[str, Any]:
            with adapter_log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")
            return {"ms_val": payload["raw_ns"] / 1_000_000.0}

        custom_runner = SecureRunner(
            require_os_sandbox=False,
            allow_trusted_host_callables=True,
            attestation_authority=self.registry.authority,
        )
        ad_callable_hash = custom_runner.register_trusted_host_adapter(
            "adapter.custom_ns_ms", custom_adapter_fn
        )
        ad = _make_verified_adapter(
            "adapter.custom_ns_ms",
            p1,
            p2,
            {"fields": {"raw_ns": "ms_val"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            registry=self.registry,
            callable_hash=ad_callable_hash,
        )
        res = self.composer.plan(
            {"goal_id": "script-dag", "required_capabilities": ["s.one", "s.two", "s.three"], "expected_outputs": [p4]},
            self.registry,
            self.ctx,
            adapters=[ad],
        )
        self.assertTrue(res.ok, msg=res.reasons)
        assert res.plan is not None

        receipt, events = self.composer.execute_plan(
            res.plan,
            self.registry,
            self.ctx,
            adapters=[ad],
            adapters_callables={"adapter.custom_ns_ms": custom_adapter_fn},
            runner=custom_runner,
            oracle=lambda d: d["output"] == {"final_ok": True},
        )
        self.assertEqual(receipt.status, ExecutionStatus.PASS)
        recorded_invocations = [json.loads(line) for line in adapter_log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(recorded_invocations, [{"raw_ns": 3000000}])
        self.assertTrue(verify_event_chain(events).valid)

    def test_circular_dependency_rejected(self) -> None:
        p_x = PortContract(schema_ref="json:obj", semantic_type="type_x", unit="none")
        p_y = PortContract(schema_ref="json:obj", semantic_type="type_y", unit="none")
        p_goal = PortContract(schema_ref="json:obj", semantic_type="type_goal", unit="none")

        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.cyc_a", capabilities=["cyc.a"],
            fn=lambda a: a, input_port=p_x, output_port=p_y,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.cyc_b", capabilities=["cyc.b"],
            fn=lambda a: a, input_port=p_y, output_port=p_x,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.sink", capabilities=["cyc.sink"],
            fn=lambda a: a, input_port=p_y, output_port=p_goal,
        )

        res = self.composer.plan(
            {"goal_id": "cycle-goal", "expected_outputs": [p_goal]},
            self.registry,
            self.ctx,
        )
        self.assertFalse(res.ok)
        self.assertIsNone(res.plan)
        self.assertEqual(res.status, ExecutionStatus.NO_VERIFIED_TOOL)
        self.assertTrue(res.diagnostics["cycle_rejected"])

        # Direct cyclic CompositionPlan dict rejected cleanly
        with self.assertRaises(ValueError):
            self.composer.execute_plan(
                {
                    "plan_id": "plan-bad-cycle",
                    "goal_contract_hash": HASH_1,
                    "nodes": [{"node_id": "n1", "tool_id": "tool.cyc_a"}, {"node_id": "n2", "tool_id": "tool.cyc_b"}],
                    "edges": [{"from_node": "n1", "to_node": "n2"}, {"from_node": "n2", "to_node": "n1"}],
                    "oracle_ref": "oracle:none",
                },
                self.registry,
                self.ctx,
            )

    def test_json_unit_and_semantic_mismatches_rejected(self) -> None:
        # 1. Unit mismatch (ns vs ms) even with matching schema_ref="json:object" and semantic_type
        p_ns = PortContract(schema_ref="json:object", semantic_type="request_duration", unit="ns")
        p_ms = PortContract(schema_ref="json:object", semantic_type="request_duration", unit="ms")
        p_done = PortContract(schema_ref="json:object", semantic_type="summary", unit="none")

        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.ns_prod", capabilities=["dur.prod"],
            fn=lambda _a: {"dur": 1000}, input_port=None, output_port=p_ns,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.ms_cons", capabilities=["dur.cons"],
            fn=lambda a: a, input_port=p_ms, output_port=p_done,
        )

        res_unit = self.composer.plan(
            {"goal_id": "unit-gap", "required_capabilities": ["dur.prod", "dur.cons"], "expected_outputs": [p_done]},
            self.registry,
            self.ctx,
        )
        self.assertFalse(res_unit.ok)
        self.assertEqual(res_unit.status, ExecutionStatus.NO_VERIFIED_TOOL)
        self.assertTrue(any("UNIT_MISMATCH:ns!=ms" in r for r in res_unit.reasons), msg=res_unit.reasons)
        self.assertTrue(len(res_unit.missing_adapters) >= 1)

        # 2. Semantic mismatch even when BOTH are JSON ("json:object") and unit="none"
        reg_sem = ToolRegistry()
        p_user = PortContract(schema_ref="json:object", semantic_type="user_account_id", unit="none")
        p_inv = PortContract(schema_ref="json:object", semantic_type="invoice_amount", unit="none")
        _make_verified_callable_tool(
            self.runner, reg_sem, tool_id="tool.user_json", capabilities=["user.emit"],
            fn=lambda _a: {"id": "u1"}, input_port=None, output_port=p_user,
        )
        _make_verified_callable_tool(
            self.runner, reg_sem, tool_id="tool.inv_json", capabilities=["inv.consume"],
            fn=lambda a: a, input_port=p_inv, output_port=p_done,
        )
        res_sem = self.composer.plan(
            {"goal_id": "sem-gap", "required_capabilities": ["user.emit", "inv.consume"], "expected_outputs": [p_done]},
            reg_sem,
            self.ctx,
        )
        self.assertFalse(res_sem.ok)
        self.assertEqual(res_sem.status, ExecutionStatus.NO_VERIFIED_TOOL)
        self.assertTrue(any("SEMANTIC_TYPE_MISMATCH" in r for r in res_sem.reasons), msg=res_sem.reasons)

    def test_secret_to_public_and_untrusted_to_trusted_leak_rejected(self) -> None:
        p_secret = PortContract(schema_ref="json:obj", semantic_type="audit_record", sensitivity="secret")
        p_public = PortContract(schema_ref="json:obj", semantic_type="audit_record", sensitivity="public")
        p_out = PortContract(schema_ref="json:obj", semantic_type="published_log", sensitivity="public")

        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.secret_src", capabilities=["sec.read"],
            fn=lambda _a: {"secret_field": "val"}, input_port=None, output_port=p_secret,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.pub_sink", capabilities=["pub.write"],
            fn=lambda a: a, input_port=p_public, output_port=p_out,
        )

        res = self.composer.plan(
            {"goal_id": "leak-check", "required_capabilities": ["sec.read", "pub.write"], "expected_outputs": [p_out]},
            self.registry,
            self.ctx,
        )
        self.assertFalse(res.ok)
        self.assertIsNone(res.plan)
        self.assertEqual(res.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertTrue(any("SENSITIVITY_FLOW_VIOLATION:secret->public" in r for r in res.reasons), msg=res.reasons)

        # Untrusted -> Trusted escalation also rejected
        reg_trust = ToolRegistry()
        p_untrusted = PortContract(schema_ref="json:obj", semantic_type="payload", trust_label="untrusted")
        p_trusted = PortContract(schema_ref="json:obj", semantic_type="payload", trust_label="trusted")
        _make_verified_callable_tool(
            self.runner, reg_trust, tool_id="tool.ext_in", capabilities=["ext.fetch"],
            fn=lambda _a: {"v": 1}, input_port=None, output_port=p_untrusted,
        )
        _make_verified_callable_tool(
            self.runner, reg_trust, tool_id="tool.core_op", capabilities=["core.run"],
            fn=lambda a: a, input_port=p_trusted, output_port=p_out,
        )
        res_trust = self.composer.plan(
            {"goal_id": "trust-check", "required_capabilities": ["ext.fetch", "core.run"], "expected_outputs": [p_out]},
            reg_trust,
            self.ctx,
        )
        self.assertFalse(res_trust.ok)
        self.assertEqual(res_trust.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertTrue(any("TRUST_LABEL_VIOLATION:untrusted->trusted" in r for r in res_trust.reasons))

    def test_over_privileged_union_and_spoofed_unverified_tools_blocked(self) -> None:
        p_out = PortContract(schema_ref="json:obj", semantic_type="result", unit="none")

        # 1. EffectContract permission exceeds SecurityContext.allowed_permissions
        eff_sudo = EffectContract(exec_permissions=["fs.read", "process.sudo"])
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.overpriv_eff", capabilities=["cap.admin"],
            fn=lambda _a: {"ok": True}, output_port=p_out, permissions=["fs.read"], effect_contract=eff_sudo,
        )
        res_over = self.composer.plan(
            {"goal_id": "overpriv", "required_capabilities": ["cap.admin"], "expected_outputs": [p_out]},
            self.registry,
            self.ctx,
        )
        self.assertFalse(res_over.ok)
        self.assertEqual(res_over.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertTrue(any("OVER_PRIVILEGED" in r for r in res_over.reasons), msg=res_over.reasons)

        # 2. Spoofed VERIFIED tool injected directly into registry._tools
        spoof_hash = sha256_digest("spoof")
        spoof_spec = ToolSpec(
            tool_id="tool.spoofed",
            version="1.0.0",
            source="local_discovery",
            binary_hash=spoof_hash,
            capabilities=["cap.spoof"],
            output_schema=p_out.to_dict(),
            required_permissions=["fs.read"],
            trust_status=TrustStatus.DISCOVERED,
        )
        spoof_spec.trust_status = TrustStatus.VERIFIED
        spoof_spec.verification_attestation = {"verifier_id": "self", "verification_digest": HASH_1}
        self.registry._tools["tool.spoofed"] = spoof_spec

        res_spoof = self.composer.plan(
            {"goal_id": "spoof-check", "required_capabilities": ["cap.spoof"], "expected_outputs": [p_out]},
            self.registry,
            self.ctx,
        )
        self.assertFalse(res_spoof.ok)
        self.assertEqual(res_spoof.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertTrue(any("SPOOFED" in r for r in res_spoof.reasons), msg=res_spoof.reasons)

        # 3. DISCOVERED, QUARANTINED, and RETIRED tools all blocked
        for status, cap, tid, expected_status in (
            (TrustStatus.DISCOVERED, "cap.disc", "tool.disc", ExecutionStatus.NO_VERIFIED_TOOL),
            (TrustStatus.QUARANTINED, "cap.quar", "tool.quar", ExecutionStatus.PERMISSION_DENIED),
            (TrustStatus.RETIRED, "cap.ret", "tool.ret", ExecutionStatus.PERMISSION_DENIED),
        ):
            spec = ToolSpec(
                tool_id=tid,
                version="1.0.0",
                source="local_discovery",
                binary_hash=HASH_1,
                capabilities=[cap],
                output_schema=p_out.to_dict(),
                required_permissions=["fs.read"],
                trust_status=status,
            )
            self.registry.register(spec)
            res_st = self.composer.plan(
                {"goal_id": f"st-{tid}", "required_capabilities": [cap], "expected_outputs": [p_out]},
                self.registry,
                self.ctx,
            )
            self.assertFalse(res_st.ok)
            self.assertEqual(res_st.status, expected_status)

    def test_profile_depth_bounds_and_search_watchdog(self) -> None:
        # 5-node chain: exceeds GITHUB_PUBLIC max_composition_depth=4, passes LOCAL_RESEARCH
        ports = [PortContract(schema_ref="json:step", semantic_type=f"stage_{i}", unit="none") for i in range(6)]
        for i in range(5):
            _make_verified_callable_tool(
                self.runner,
                self.registry,
                tool_id=f"tool.step{i + 1}",
                capabilities=[f"step.{i + 1}"],
                fn=lambda a, idx=i: {"step": idx + 1, "prev": a},
                input_port=ports[i] if i > 0 else None,
                output_port=ports[i + 1],
                permissions=["fs.read"],
            )

        goal = {"goal_id": "deep-chain", "expected_outputs": [ports[5]]}
        cfg_local = KintsugiConfig.for_profile("LOCAL_RESEARCH")
        res_local = self.composer.plan(goal, self.registry, self.ctx, config=cfg_local)
        self.assertTrue(res_local.ok, msg=res_local.reasons)
        assert res_local.plan is not None
        self.assertEqual(len(res_local.plan.nodes), 5)

        cfg_gh = KintsugiConfig.for_profile("GITHUB_PUBLIC")
        ctx_gh = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.GITHUB_PUBLIC,
            allowed_permissions=["fs.read"],
        )
        res_gh = self.composer.plan(goal, self.registry, ctx_gh, config=cfg_gh)
        self.assertFalse(res_gh.ok)
        self.assertEqual(res_gh.status, ExecutionStatus.INSUFFICIENT_EVIDENCE)
        self.assertTrue(any("MAX_COMPOSITION_DEPTH_EXCEEDED" in r for r in res_gh.reasons), msg=res_gh.reasons)

        # Bounded search watchdog triggers cleanly on tight node budget
        tight_composer = ToolComposer(max_search_nodes=3)
        res_wd = tight_composer.plan(goal, self.registry, self.ctx, config=cfg_local)
        self.assertFalse(res_wd.ok)
        self.assertEqual(res_wd.status, ExecutionStatus.INSUFFICIENT_EVIDENCE)
        self.assertTrue(res_wd.diagnostics["watchdog_triggered"])
        self.assertEqual(res_wd.diagnostics["termination_reason"], "SEARCH_NODE_WATCHDOG_EXCEEDED")

    def test_mid_dag_failure_aborts_without_downstream_and_toctou_blocks(self) -> None:
        p1 = PortContract(schema_ref="json:obj", semantic_type="s1", unit="none")
        p2 = PortContract(schema_ref="json:obj", semantic_type="s2", unit="none")
        p3 = PortContract(schema_ref="json:obj", semantic_type="s3", unit="none")

        executed_log = self.ws / ".test_mid_exec.log"

        def _read_executed() -> List[str]:
            return executed_log.read_text(encoding="utf-8").splitlines() if executed_log.exists() else []

        def fn1(_a: Dict[str, Any]) -> Dict[str, Any]:
            with executed_log.open("a", encoding="utf-8") as ef:
                ef.write("n1\n")
            return {"v": 1}

        def fn2(_a: Dict[str, Any]) -> Dict[str, Any]:
            with executed_log.open("a", encoding="utf-8") as ef:
                ef.write("n2\n")
            raise RuntimeError("MID_DAG_BOOM")

        def fn3(_a: Dict[str, Any]) -> Dict[str, Any]:
            with executed_log.open("a", encoding="utf-8") as ef:
                ef.write("n3\n")
            return {"v": 3}

        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.m1", capabilities=["m.1"],
            fn=fn1, input_port=None, output_port=p1,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.m2", capabilities=["m.2"],
            fn=fn2, input_port=p1, output_port=p2,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.m3", capabilities=["m.3"],
            fn=fn3, input_port=p2, output_port=p3,
        )

        plan_res = self.composer.plan(
            {"goal_id": "mid-fail", "required_capabilities": ["m.1", "m.2", "m.3"], "expected_outputs": [p3]},
            self.registry,
            self.ctx,
        )
        self.assertTrue(plan_res.ok)
        assert plan_res.plan is not None

        receipt, events = self.composer.execute_plan(
            plan_res.plan,
            self.registry,
            self.ctx,
            runner=self.runner,
            oracle=lambda _d: True,
        )
        self.assertEqual(receipt.status, ExecutionStatus.FAIL)
        self.assertEqual(receipt.oracle_result["failed_node"], "n2")
        self.assertEqual(_read_executed(), ["n1", "n2"], "Downstream n3 MUST NOT execute after n2 failure!")
        self.assertTrue(verify_event_chain(events).valid)
        self.assertTrue(any(ev.state == "NODE_FAILED" and ev.step_id == "n2" for ev in events))

        # Pre-execution TOCTOU: policy_hash tampering aborts before any node runs
        if executed_log.exists():
            executed_log.unlink()
        bad_ctx = SecurityContext(workspace_root=str(self.ws), allowed_permissions=["fs.read"])
        bad_ctx.allowed_permissions.append("fs.write")
        rec_pol, ev_pol = self.composer.execute_plan(plan_res.plan, self.registry, bad_ctx, runner=self.runner)
        self.assertEqual(rec_pol.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertEqual(_read_executed(), [])
        self.assertTrue(verify_event_chain(ev_pol).valid)

        # Pre-execution TOCTOU: quarantining tool in registry after planning blocks execution
        self.registry.quarantine("tool.m2", "post_plan_compromise")
        rec_q, _ = self.composer.execute_plan(plan_res.plan, self.registry, self.ctx, runner=self.runner)
        self.assertEqual(rec_q.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertEqual(_read_executed(), [])

    def test_checkpoint_and_crash_resume_skips_completed_side_effect_node(self) -> None:
        side_effect_log = self.ws / "side_effect_ledger.txt"
        ckpt_path = self.ws / ".kintsugi" / "run_checkpoint.jsonl"
        p_ns = PortContract(schema_ref="json:obj", semantic_type="metric", unit="ns")
        p_ms = PortContract(schema_ref="json:obj", semantic_type="metric", unit="ms")
        p_final = PortContract(schema_ref="json:obj", semantic_type="final", unit="none")

        exec_log = self.ws / ".test_exec_counts.log"
        fail_n2_flag = self.ws / ".fail_n2.flag"
        fail_n2_flag.write_text("1", encoding="utf-8")

        def _read_counts() -> Dict[str, int]:
            lines = exec_log.read_text(encoding="utf-8").splitlines() if exec_log.exists() else []
            return {"n1": lines.count("n1"), "n2": lines.count("n2"), "n3": lines.count("n3")}

        def fn_side_effect(_args: Dict[str, Any]) -> Dict[str, Any]:
            with exec_log.open("a", encoding="utf-8") as cf:
                cf.write("n1\n")
            n1_idx = _read_counts()["n1"]
            with side_effect_log.open("a", encoding="utf-8") as f:
                f.write(f"effect_{n1_idx}\n")
            return {"dur_ns": 2_500_000}

        def fn_middle(args: Dict[str, Any]) -> Dict[str, Any]:
            with exec_log.open("a", encoding="utf-8") as cf:
                cf.write("n2\n")
            if fail_n2_flag.exists():
                raise RuntimeError("TRANSIENT_CRASH_ON_N2")
            return {"scaled_ms": float(args["dur_ms"]) * 2.0}

        def fn_tail(args: Dict[str, Any]) -> Dict[str, Any]:
            with exec_log.open("a", encoding="utf-8") as cf:
                cf.write("n3\n")
            return {"result_ms": args["scaled_ms"]}

        _make_verified_callable_tool(
            self.runner,
            self.registry,
            tool_id="tool.side_effect_1",
            capabilities=["step.one"],
            fn=fn_side_effect,
            input_port=None,
            output_port=p_ns,
            permissions=["fs.write"],
            side_effects=["workspace_write", "irreversible"],
            effect_contract=EffectContract(
                write_scopes=["ws:side_effect_ledger.txt"],
                exec_permissions=["fs.write"],
                irreversible=True,
                idempotent=False,
            ),
        )
        _make_verified_callable_tool(
            self.runner,
            self.registry,
            tool_id="tool.mid_2",
            capabilities=["step.two"],
            fn=fn_middle,
            input_port=p_ms,
            output_port=p_ms,
            permissions=["fs.read"],
        )
        _make_verified_callable_tool(
            self.runner,
            self.registry,
            tool_id="tool.tail_3",
            capabilities=["step.three"],
            fn=fn_tail,
            input_port=p_ms,
            output_port=p_final,
            permissions=["fs.read"],
        )
        ad = _make_verified_adapter(
            "adapter.ns_ms_ckpt",
            p_ns,
            p_ms,
            {"fields": {"dur_ns": "dur_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            registry=self.registry,
        )

        plan_res = self.composer.plan(
            {
                "goal_id": "ckpt-resume",
                "required_capabilities": ["step.one", "step.two", "step.three"],
                "expected_outputs": [p_final],
            },
            self.registry,
            self.ctx,
            adapters=[ad],
        )
        self.assertTrue(plan_res.ok, msg=plan_res.reasons)
        assert plan_res.plan is not None
        self.assertTrue(plan_res.plan.effects_union["irreversible"])
        self.assertFalse(plan_res.plan.effects_union["idempotent"])

        run_id = "run-ckpt-001"
        rec1, ev1 = self.composer.execute_plan(
            plan_res.plan,
            self.registry,
            self.ctx,
            runner=self.runner,
            checkpoint_store_path=ckpt_path,
            resume_run_id=run_id,
            oracle=lambda d: d["output"] == {"result_ms": 5.0},
        )
        self.assertEqual(rec1.status, ExecutionStatus.FAIL)
        self.assertEqual(_read_counts(), {"n1": 1, "n2": 1, "n3": 0})
        self.assertEqual(side_effect_log.read_text(encoding="utf-8").splitlines(), ["effect_1"])
        self.assertEqual(stat.S_IMODE(ckpt_path.stat().st_mode), 0o600)
        self.assertTrue(verify_event_chain(ev1).valid)

        # Resume after fixing transient failure on n2: durable IN_FLIGHT is
        # ambiguous until explicitly reconciled by an operator.
        fail_n2_flag.unlink()
        self.composer.reconcile_checkpoint_node(
            checkpoint_store_path=ckpt_path, run_id=run_id, node_id="n2",
            outcome="NOT_EXECUTED", security_context=self.ctx, operator_confirmed=True,
        )
        rec2, ev2 = self.composer.execute_plan(
            plan_res.plan,
            self.registry,
            self.ctx,
            runner=self.runner,
            checkpoint_store_path=ckpt_path,
            resume_run_id=run_id,
            oracle=lambda d: d["output"] == {"result_ms": 5.0},
        )
        self.assertEqual(rec2.status, ExecutionStatus.PASS)
        self.assertTrue(rec2.oracle_result["passed"])
        self.assertEqual(_read_counts(), {"n1": 1, "n2": 2, "n3": 1}, "Completed side-effect n1 MUST NOT re-execute!")
        self.assertEqual(side_effect_log.read_text(encoding="utf-8").splitlines(), ["effect_1"])
        self.assertTrue(any(ev.state == "NODE_SKIPPED_CHECKPOINT" and ev.step_id == "n1" for ev in ev2))
        self.assertTrue(verify_event_chain(ev2).valid)

        # On-disk append-only RunEvent/1 log must validate cleanly from line 0 to end
        persisted = [json.loads(line) for line in ckpt_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        disk_chain = verify_event_chain(persisted)
        self.assertTrue(disk_chain.valid, msg=disk_chain.reasons)
        self.assertEqual(len(persisted), len(ev2))

        # Tampering with persisted RunEvent log must fail closed on resume
        tampered_lines = ckpt_path.read_text(encoding="utf-8").splitlines()
        first_ev = json.loads(tampered_lines[0])
        first_ev["decision_reason"] = "tampered"
        tampered_lines[0] = json.dumps(first_ev)
        ckpt_path.write_text("\n".join(tampered_lines) + "\n", encoding="utf-8")

        rec_tampered, _ = self.composer.execute_plan(
            plan_res.plan,
            self.registry,
            self.ctx,
            runner=self.runner,
            checkpoint_store_path=ckpt_path,
            resume_run_id=run_id,
        )
        self.assertEqual(rec_tampered.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertEqual(_read_counts()["n1"], 1)

    def test_memory_preference_steers_selection_without_bypassing_verification(self) -> None:
        p_out = PortContract(schema_ref="json:obj", semantic_type="scan_result", unit="none")
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.alpha", capabilities=["scan.code"],
            fn=lambda _a: {"tool": "alpha"}, output_port=p_out, latency_ms=10.0,
        )
        t_beta = _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.beta", capabilities=["scan.code"],
            fn=lambda _a: {"tool": "beta"}, output_port=p_out, latency_ms=10.0,
        )

        exp_store = ExperienceStore(self.ws / ".kintsugi" / "exp.json", workspace_root=self.ws)
        exp_store.record(
            Experience(
                task_fingerprint="fp_scan",
                failure_class="scan.code",
                tool_or_plan_id="tool.beta",
                input_characteristics={"capability": "scan.code"},
                verified_outcome="PASS",
                reuse_count=5,
                tool_hash=t_beta.binary_hash,
                security_profile=SecurityProfile.LOCAL_RESEARCH,
            )
        )

        res = self.composer.plan(
            {"goal_id": "mem-hint", "required_capabilities": ["scan.code"], "expected_outputs": [p_out]},
            self.registry,
            self.ctx,
            composition_memory=exp_store,
        )
        self.assertTrue(res.ok)
        assert res.plan is not None
        self.assertEqual(res.plan.nodes[0]["tool_id"], "tool.beta")

        eff = extract_tool_effect_contract(t_beta)
        self.assertEqual(eff.exec_permissions, ["fs.read"])
        self.assertIsInstance(MissingAdapterGap(producer_id="a", consumer_id="b").to_dict(), dict)

    def test_diamond_dag_fan_out_fan_in_and_schema_parity(self) -> None:
        p_seed = PortContract(schema_ref="json:obj", semantic_type="raw_seed", unit="ns")
        p_seed_ms = PortContract(schema_ref="json:obj", semantic_type="raw_seed", unit="ms")
        p_left = PortContract(schema_ref="json:obj", semantic_type="left_branch", unit="ms")
        p_right = PortContract(schema_ref="json:obj", semantic_type="right_branch", unit="ns")
        p_merged = PortContract(schema_ref="json:obj", semantic_type="merged_report", unit="none")

        root_log = self.ws / ".test_diamond_root.log"

        def fn_root(_a: Dict[str, Any]) -> Dict[str, Any]:
            with root_log.open("a", encoding="utf-8") as rf:
                rf.write("root\n")
            return {"dur_ns": 4_000_000}

        def fn_left(args: Dict[str, Any]) -> Dict[str, Any]:
            return {"left_ms": float(args["dur_ms"]) + 1.0}

        def fn_right(args: Dict[str, Any]) -> Dict[str, Any]:
            return {"right_ns": int(args["dur_ns"]) // 1000}

        def fn_merge(args: Dict[str, Any]) -> Dict[str, Any]:
            return {"left": args["left"]["left_ms"], "right": args["right"]["right_ns"]}

        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.d_root", capabilities=["d.root"],
            fn=fn_root, input_port=None, output_port=p_seed,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.d_left", capabilities=["d.left"],
            fn=fn_left, input_port=p_seed_ms, output_port=p_left,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.d_right", capabilities=["d.right"],
            fn=fn_right, input_port=p_seed, output_port=p_right,
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.d_merge", capabilities=["d.merge"],
            fn=fn_merge, input_ports={"left": p_left, "right": p_right}, output_port=p_merged,
        )

        ad_ns_ms = _make_verified_adapter(
            "adapter.diamond_ns_ms",
            p_seed,
            p_seed_ms,
            {"fields": {"dur_ns": "dur_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            registry=self.registry,
        )
        plan_res = self.composer.plan(
            {
                "goal_id": "diamond-dag",
                "required_capabilities": ["d.root", "d.left", "d.right", "d.merge"],
                "expected_outputs": [p_merged],
            },
            self.registry,
            self.ctx,
            adapters=[ad_ns_ms],
        )
        self.assertTrue(plan_res.ok, msg=plan_res.reasons)
        assert plan_res.plan is not None
        self.assertEqual(len(plan_res.plan.nodes), 4, "Diamond root MUST be reused without duplicate node!")
        self.assertEqual(len(plan_res.plan.edges), 4)

        receipt, events = self.composer.execute_plan(
            plan_res.plan,
            self.registry,
            self.ctx,
            runner=self.runner,
            oracle=lambda d: d["output"] == {"left": 5.0, "right": 4000},
        )
        self.assertEqual(receipt.status, ExecutionStatus.PASS)
        root_count = len(root_log.read_text(encoding="utf-8").splitlines()) if root_log.exists() else 0
        self.assertEqual(root_count, 1, "Shared diamond root MUST execute exactly once!")
        self.assertTrue(verify_event_chain(events).valid)

        # Schema parity against JSON schemas in schemas/
        schemas_dir = Path(__file__).resolve().parents[2] / "schemas"
        plan_schema = json.loads((schemas_dir / "composition_plan.v1.schema.json").read_text(encoding="utf-8"))
        rec_schema = json.loads((schemas_dir / "composition_receipt.v1.schema.json").read_text(encoding="utf-8"))
        ev_schema = json.loads((schemas_dir / "run_event.v1.schema.json").read_text(encoding="utf-8"))

        plan_dict = plan_res.plan.to_dict()
        self.assertTrue(set(plan_schema["required"]).issubset(plan_dict.keys()))
        self.assertTrue(set(plan_dict.keys()).issubset(plan_schema["properties"].keys()))
        for edge in plan_dict["edges"]:
            self.assertTrue(set(edge.keys()).issubset(plan_schema["$defs"] if "$defs" in plan_schema else plan_schema["properties"]["edges"]["items"]["properties"].keys()))

        rec_dict = receipt.to_dict()
        self.assertTrue(set(rec_schema["required"]).issubset(rec_dict.keys()))
        self.assertTrue(set(rec_dict.keys()).issubset(rec_schema["properties"].keys()))

        for ev in events:
            ev_dict = ev.to_dict()
            self.assertTrue(set(ev_schema["required"]).issubset(ev_dict.keys()))
            self.assertTrue(set(ev_dict.keys()).issubset(ev_schema["properties"].keys()))

    def test_unverified_adapter_rejected_and_narrowed_context_blocked_at_exec(self) -> None:
        p_ns = PortContract(schema_ref="json:obj", semantic_type="lat", unit="ns")
        p_ms = PortContract(schema_ref="json:obj", semantic_type="lat", unit="ms")
        p_done = PortContract(schema_ref="json:obj", semantic_type="out", unit="none")

        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.a_ns", capabilities=["a.ns"],
            fn=lambda _a: {"dur_ns": 1000}, input_port=None, output_port=p_ns, permissions=["fs.read"],
        )
        _make_verified_callable_tool(
            self.runner, self.registry, tool_id="tool.b_ms", capabilities=["b.ms"],
            fn=lambda a: a, input_port=p_ms, output_port=p_done, permissions=["fs.write"],
        )
        unverified_ad = _make_verified_adapter(
            "adapter.unverified_ns_ms",
            p_ns,
            p_ms,
            {"fields": {"dur_ns": "dur_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            trust_status=TrustStatus.DISCOVERED,
        )
        res_bad_ad = self.composer.plan(
            {"goal_id": "bad-adapter", "required_capabilities": ["a.ns", "b.ms"], "expected_outputs": [p_done]},
            self.registry,
            self.ctx,
            adapters=[unverified_ad],
        )
        self.assertFalse(res_bad_ad.ok)
        self.assertEqual(res_bad_ad.status, ExecutionStatus.NO_VERIFIED_TOOL)

        verified_ad = _make_verified_adapter(
            "adapter.verified_ns_ms",
            p_ns,
            p_ms,
            {"fields": {"dur_ns": "dur_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            registry=self.registry,
        )
        res_ok = self.composer.plan(
            {"goal_id": "ok-plan", "required_capabilities": ["a.ns", "b.ms"], "expected_outputs": [p_done]},
            self.registry,
            self.ctx,
            adapters=[verified_ad],
        )
        self.assertTrue(res_ok.ok)
        assert res_ok.plan is not None

        # Narrowed SecurityContext without fs.write must fail closed at execute_plan time
        narrow_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read"],
        )
        rec_narrow, ev_narrow = self.composer.execute_plan(res_ok.plan, self.registry, narrow_ctx, runner=self.runner)
        self.assertEqual(rec_narrow.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertTrue(verify_event_chain(ev_narrow).valid)


if __name__ == "__main__":
    unittest.main()
