"""End-to-End Integration Suite for Demos 2, 3, 4 and Build #2 CLI + MCP."""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_adapter, sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_adapter, sign_fixture_tool
from kintsugi.capability.schemas import compute_tool_spec_security_digest

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from kintsugi.capability import (
    AdapterSpec,
    AttestationAuthority,
    EffectContract,
    ExecutionStatus,
    PortContract,
    SecurityContext,
    SecurityProfile,
    ToolRegistry,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.cli import main as cli_main
from kintsugi.composition import (
    AdapterSynthesizer,
    CompositionMemory,
    CompositionVerifier,
    ToolComposer,
)
from kintsugi.forge import (
    NativeToolForge,
    ToolSandbox,
    build_kvpipe_v1_task_spec,
    parse_kvpipe_v1_python,
)
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.runtime import SecureRunner
from kintsugi.runtime.secure_runner import compute_file_sha256_confined
from kintsugi.tools import LogForge, ProofPack, ToolWire, TraceDoctor


def _make_callable_tool_spec(
    *,
    tool_id: str,
    capability: str,
    binary_hash: str,
    input_port: PortContract,
    output_port: PortContract,
    callable_name: str,
) -> ToolSpec:
    att_digest = sha256_digest({"tool_id": tool_id, "binary_hash": binary_hash})
    return ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="host_trusted",
        binary_hash=binary_hash,
        capabilities=[capability],
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        semantic_contract={
            "input_port": input_port.to_dict(),
            "output_port": output_port.to_dict(),
        },
        preconditions=[],
        postconditions=[capability],
        side_effects=[],
        required_permissions=[],
        runtime_requirements={
            "callable_name": callable_name,
            "network": False,
            "effect_contract": EffectContract(
                read_scopes=[],
                write_scopes=[],
                network_scopes=[],
                exec_permissions=[],
                irreversible=False,
                idempotent=True,
                resource_requirements={"max_memory_mb": 128, "timeout_seconds": 10},
            ).to_dict(),
        },
        trust_status=TrustStatus.VERIFIED,
        latency_estimate_ms=5.0,
        memory_estimate_mb=32.0,
        api_token_estimate=0,
        verification_attestation={
            "verifier_id": "test.integration.verifier",
            "verification_digest": att_digest,
            "binary_hash": binary_hash,
            "tool_id": tool_id,
        },
        provenance={"origin": "integration_test"},
    )


def _run_cli_json(argv: List[str]) -> tuple[int, Any]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli_main(argv)
    text = buf.getvalue().strip()
    return rc, json.loads(text) if text else {}


class TestNextGenDemos234AndCliMcp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_demos234_")
        self.ws = Path(self._tmp.name).resolve() / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=[],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_demo2_lego_pipeline_logreader_toolwire_logforge_anomaly_proofpack(self) -> None:
        """Demo 2: LogReader -> ToolWire Adapter -> LogForge Parser -> AnomalyDetector + ProofPack + TraceDoctor + Replay."""
        registry = ToolRegistry()
        registry.authority.register_verifier(
            "kintsugi.composition_oracle", b"kintsugi-round4-oracle-verifier-key-32b"
        )
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        # Ports: LogReader outputs latency (ns int64); LogForgeParser expects ms (decimal128)
        reader_in = PortContract("raw.log_path", "log_path", encoding="utf-8", unit="none")
        reader_out = PortContract(
            "typed_event_stream",
            "log_records",
            encoding="utf-8",
            unit="ns",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
            precision="int64",
        )
        parser_in = PortContract(
            "typed_event_stream",
            "log_records",
            encoding="utf-8",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
            precision="decimal128",
        )
        parser_out = PortContract(
            "typed_event_stream",
            "parsed_events",
            encoding="utf-8",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
        )
        anomaly_out = PortContract(
            "typed_event_stream",
            "anomaly_report",
            encoding="utf-8",
            unit="none",
            cardinality="one",
            ordering="unordered",
            sensitivity="internal",
            trust_label="derived",
        )

        # Tool 1: LogReader
        def _log_reader(args: Dict[str, Any]) -> Dict[str, Any]:
            raw = str(args.get("raw_logs") or "")
            lf_scan = LogForge().scan_delimiters(
                raw.encode("utf-8"), delim=10, tier="python_oracle", normalize=True
            )
            rows = []
            for idx, line in enumerate(raw.splitlines(), start=1):
                if not line.strip():
                    continue
                obj = json.loads(line)
                rows.append({"line": idx, "service": obj["svc"], "latency": int(obj["latency_ns"])})
            return {"records": rows, "line_delims": len(lf_scan.offsets)}

        # Adapter via AdapterSynthesizer (ns -> ms with lossless exact Decimal arithmetic)
        synth = AdapterSynthesizer(authority=registry.authority)
        proposal = synth.propose(
            reader_out,
            parser_in,
            source_schema={
                "properties": {
                    "line": {"type": "integer"},
                    "service": {"type": "string"},
                    "latency": {"type": "integer"},
                },
                "required": ["line", "service", "latency"],
            },
            target_schema={
                "properties": {
                    "line": {"type": "integer"},
                    "service": {"type": "string"},
                    "latency": {"type": "string"},
                },
                "required": ["line", "service", "latency"],
            },
            field_map={"line": "line", "service": "service"},
            unit_fields={"latency": "latency"},
            unit_representation="decimal_string",
            sample_fixtures=[{"line": 1, "service": "api", "latency": 150000000}],
        )
        self.assertTrue(proposal.accepted, msg=str(proposal.abstain_reason))
        adapter_spec = proposal.adapter_spec
        adapter_fn = proposal.callable_adapter
        self.assertIsNotNone(adapter_spec)
        self.assertIsNotNone(adapter_fn)

        def _bridge_records(payload: Any) -> Dict[str, Any]:
            src_rows = list((payload or {}).get("records") or []) if isinstance(payload, dict) else []
            return {"records": adapter_fn(src_rows)}

        bridge_hash = runner.register_trusted_host_adapter(adapter_spec.adapter_id, _bridge_records)
        adapter_spec = sign_fixture_adapter(registry, adapter_spec, callable_hash=bridge_hash)

        # Tool 2: LogForgeParser
        def _logforge_parser(args: Dict[str, Any]) -> Dict[str, Any]:
            upstream = args.get("payload") if isinstance(args.get("payload"), dict) else args
            recs = list(upstream.get("records") or [])
            return {"events": recs, "count": len(recs)}

        # Tool 3: AnomalyDetector + ProofPack check
        def _anomaly_detector(args: Dict[str, Any]) -> Dict[str, Any]:
            upstream = args.get("payload") if isinstance(args.get("payload"), dict) else args
            events = list(upstream.get("events") or [])
            flagged = [ev for ev in events if float(ev.get("latency", 0)) >= 120.0]
            return {
                "total_events": len(events),
                "anomalies_count": len(flagged),
                "anomalous_services": [str(ev["service"]) for ev in flagged],
            }

        specs = [
            ("tool.log_reader", "log.ingest", reader_in, reader_out, _log_reader),
            ("tool.logforge_parser", "log.parse", parser_in, parser_out, _logforge_parser),
            ("tool.anomaly_detector", "log.anomaly_detect", parser_out, anomaly_out, _anomaly_detector),
        ]
        for tid, cap, pin, pout, fn in specs:
            h = runner.register_trusted_host_callable(tid, fn)
            sign_fixture_tool(registry, _make_callable_tool_spec(
                    tool_id=tid,
                    capability=cap,
                    binary_hash=h,
                    input_port=pin,
                    output_port=pout,
                    callable_name=tid,
                ))

        composer = ToolComposer()
        goal = {
            "goal_id": "demo2-log-anomaly-pipeline",
            "required_capabilities": ["log.ingest", "log.parse", "log.anomaly_detect"],
            "input_port": reader_in.to_dict(),
            "expected_outputs": [anomaly_out.to_dict()],
            "oracle_ref": "anomaly.count == 1",
        }
        plan_res = composer.plan(
            goal,
            registry,
            self.sec_ctx,
            adapters=[adapter_spec],
        )
        self.assertTrue(plan_res.executable, msg=f"Plan failed: {plan_res.reasons}")
        self.assertEqual(plan_res.llm_calls, 0)
        plan = plan_res.plan
        self.assertIsNotNone(plan)
        self.assertGreaterEqual(len(plan.nodes), 3)
        self.assertGreaterEqual(len(plan.adapter_hashes), 1)

        ver = CompositionVerifier().verify(plan, registry, self.sec_ctx, adapters=[adapter_spec])
        self.assertTrue(ver.ok, msg=str(ver.reasons))

        raw_logs = (
            '{"svc":"auth","latency_ns":25000000}\n'
            '{"svc":"checkout","latency_ns":250000000}\n'
            '{"svc":"search","latency_ns":10000000}\n'
        )
        init_inputs = {"raw_logs": raw_logs}

        def _oracle(dag_res: Dict[str, Any]) -> bool:
            out = dag_res.get("output") or {}
            return out.get("anomalies_count") == 1 and out.get("anomalous_services") == ["checkout"]

        rec1, ev1 = composer.execute_plan(
            plan,
            registry,
            self.sec_ctx,
            runner=runner,
            adapters=[adapter_spec],
            adapters_callables={adapter_spec.adapter_id: _bridge_records},
            oracle=_oracle,
            initial_inputs=init_inputs,
        )
        self.assertEqual(rec1.status.value, "PASS", msg=str(rec1.oracle_result))
        diag = TraceDoctor().diagnose(ev1, receipt=rec1, plan=plan)
        self.assertTrue(diag.ok)
        self.assertTrue(diag.chain_valid)
        self.assertTrue(diag.zero_failure)

        # Differential replay parity & ProofPack reproducibility verification
        rec2, _ = composer.execute_plan(
            plan,
            registry,
            self.sec_ctx,
            runner=runner,
            adapters=[adapter_spec],
            adapters_callables={adapter_spec.adapter_id: _bridge_records},
            oracle=_oracle,
            initial_inputs=init_inputs,
        )
        self.assertEqual(rec1.output_digest, rec2.output_digest)

        pp = ProofPack()
        repro = pp.verify_reproducibility([rec1, rec2])
        self.assertTrue(repro.verified_independently)
        diff = pp.run_differential_corpus(
            lambda x: {"total_events": len(x), "anomalies_count": sum(1 for v in x if v >= 120_000_000)},
            lambda x: {"total_events": len(x), "anomalies_count": sum(1 for v in x if (v / 1_000_000) >= 120.0)},
            [[25_000_000, 250_000_000, 10_000_000], [10_000_000, 120_000_000]],
        )
        self.assertTrue(diff.verified_independently)

    @unittest.skipUnless(sys.platform == "darwin", "End-to-End Demo 3 OS sandbox requires Darwin Seatbelt host")
    def test_demo3_forged_kvpipe_c99_composed_in_lego_dag(self) -> None:
        """Demo 3: Forge C99 kvpipe.v1 in Seatbelt sandbox and execute directly inside a multi-tool LEGO DAG."""
        registry = ToolRegistry()
        forge = NativeToolForge(self.ws, profile=SecurityProfile.LOCAL_RESEARCH)
        task_spec = build_kvpipe_v1_task_spec(
            tool_id="forge.kvpipe_v1_parser",
            version="1.0.0",
            fuzz_count=120,
            benchmark_lines=20000,
        )
        res = forge.forge_tool(
            task_spec,
            registry=registry,
            security_context=self.sec_ctx,
            force_forge=True,
        )
        self.assertTrue(res.verified, msg=res.reason)
        self.assertIsNotNone(res.tool_spec)

        # Register downstream consumer accepting forged output_port
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        summary_in = PortContract(
            schema_ref="kvpipe.v1.parsed_records",
            semantic_type="parsed_log_records",
            encoding="json",
            unit="records",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
        )
        summary_out = PortContract(
            schema_ref="kvpipe.v1.summary",
            semantic_type="log_summary",
            encoding="json",
            unit="none",
            cardinality="one",
            ordering="unordered",
            sensitivity="internal",
            trust_label="derived",
        )

        def _summarize_kv(args: Dict[str, Any]) -> Dict[str, Any]:
            upstream = args.get("payload") if isinstance(args.get("payload"), dict) else args
            recs = list(upstream.get("records") or [])
            err_count = sum(1 for r in recs if r.get("fields", {}).get("LEVEL") == "ERROR")
            return {
                "parsed": int(upstream.get("parsed", len(recs))),
                "malformed": int(upstream.get("malformed", 0)),
                "error_count": err_count,
            }

        sum_hash = runner.register_trusted_host_callable("tool.kv_summary", _summarize_kv)
        sign_fixture_tool(registry, _make_callable_tool_spec(
                tool_id="tool.kv_summary",
                capability="kv.summarize",
                binary_hash=sum_hash,
                input_port=summary_in,
                output_port=summary_out,
                callable_name="tool.kv_summary",
            ))

        composer = ToolComposer()
        goal = {
            "goal_id": "demo3-forged-kvpipe-composed-dag",
            "required_capabilities": ["log.parse.kvpipe.v1", "kv.summarize"],
            "input_port": res.tool_spec.semantic_contract["input_port"],
            "expected_outputs": [summary_out.to_dict()],
            "oracle_ref": "kv.summarize matches python oracle",
        }
        plan_res = composer.plan(goal, registry, self.sec_ctx)
        self.assertTrue(plan_res.executable, msg=str(plan_res.reasons))
        assert plan_res.plan is not None
        self.assertEqual(len(plan_res.plan.nodes), 2)

        sample_bytes = b"TS=2026-11-22T00:00:00Z|LEVEL=INFO|MSG=boot\nTS=2026-11-22T00:00:01Z|LEVEL=ERROR|MSG=timeout\nBROKEN_ROW\n"
        expected_py = parse_kvpipe_v1_python(sample_bytes)
        (self.ws / "demo3_input.kv").write_bytes(sample_bytes)

        rec, events = composer.execute_plan(
            plan_res.plan,
            registry,
            self.sec_ctx,
            runner=runner,
            initial_inputs={"stdin": sample_bytes.decode("utf-8")},
            oracle=lambda dag: (
                (dag.get("output") or {}).get("parsed") == expected_py["parsed"]
                and (dag.get("output") or {}).get("malformed") == expected_py["malformed"]
                and (dag.get("output") or {}).get("error_count") == 1
            ),
        )
        self.assertEqual(rec.status.value, "PASS", msg=str(rec.oracle_result))
        self.assertTrue(TraceDoctor().diagnose(events, receipt=rec, plan=plan_res.plan).ok)

    def test_demo4_cross_task_transfer_with_swapped_adapter_and_drift_invalidation(self) -> None:
        """Demo 4: Learn Alpha composition memory, transfer to unseen Beta with swapped adapter, reject on drift."""
        registry = ToolRegistry()
        registry.authority.register_verifier(
            "kintsugi.composition_oracle", b"kintsugi-round4-oracle-verifier-key-32b"
        )
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        in_ns = PortContract(
            "typed_event_stream",
            "latency_events",
            encoding="utf-8",
            unit="ns",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )
        core_in = PortContract(
            "typed_event_stream",
            "latency_events",
            encoding="utf-8",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            precision="decimal128",
        )
        core_out = PortContract(
            "typed_event_stream",
            "latency_report",
            encoding="utf-8",
            unit="ms",
            cardinality="one",
            ordering="unordered",
        )
        in_sec = PortContract(
            "typed_event_stream",
            "latency_events",
            encoding="utf-8",
            unit="s",
            cardinality="many",
            ordering="ordered",
            precision="int64",
        )

        def _core_scorer(args: Dict[str, Any]) -> Dict[str, Any]:
            upstream = args.get("payload") if isinstance(args.get("payload"), dict) else args
            recs = list(upstream.get("records") or [])
            return {"count": len(recs), "max_ms": max((float(r["latency"]) for r in recs), default=0.0)}

        core_hash = runner.register_trusted_host_callable("tool.latency_scorer", _core_scorer)
        core_spec = _make_callable_tool_spec(
            tool_id="tool.latency_scorer",
            capability="telemetry.score_latency",
            binary_hash=core_hash,
            input_port=core_in,
            output_port=core_out,
            callable_name="tool.latency_scorer",
        )
        sign_fixture_tool(registry, core_spec)

        synth = AdapterSynthesizer(authority=registry.authority)
        ad_ns_to_ms = synth.propose(
            in_ns,
            core_in,
            unit_fields=["latency"],
            unit_representation="decimal_string",
            sample_fixtures=[{"latency": 5000000}],
        )
        ad_s_to_ms = synth.propose(
            in_sec,
            core_in,
            unit_fields=["latency"],
            unit_representation="decimal_string",
            sample_fixtures=[{"latency": 1}],
        )
        self.assertTrue(ad_ns_to_ms.accepted and ad_s_to_ms.accepted)
        assert ad_ns_to_ms.adapter_spec is not None and ad_s_to_ms.adapter_spec is not None

        mem = CompositionMemory(self.ws / ".kintsugi" / "composition_memory.json", workspace_root=self.ws)
        composer = ToolComposer()

        # Train task: alpha_app (ns)
        alpha_goal = {
            "goal_id": "goal-alpha",
            "required_capabilities": ["telemetry.score_latency"],
            "input_port": in_ns.to_dict(),
            "expected_outputs": [core_out.to_dict()],
            "oracle_ref": "oracle.latency.v1",
        }
        alpha_res = composer.plan(
            alpha_goal,
            registry,
            self.sec_ctx,
            adapters=[ad_ns_to_ms.adapter_spec],
            composition_memory=mem,
        )
        self.assertTrue(alpha_res.executable and alpha_res.plan is not None)
        mem.record(
            alpha_res.plan,
            task_signature="telemetry.latency.pipeline",
            goal_contract=alpha_goal,
            policy_hash="sha256:" + "1" * 64,
            schema_hash="sha256:" + "2" * 64,
            oracle_ref="oracle.latency.v1",
            oracle_hash="sha256:" + "3" * 64,
            runtime_version="3.0.1",
            tool_attestation_digests={
                core_spec.tool_id: core_spec.verification_attestation["verification_digest"]
            },
        )

        # Warm lookup passes under matching provenance
        hit = mem.retrieve(
            task_signature="telemetry.latency.pipeline",
            current_tool_hashes={core_spec.tool_id: core_spec.binary_hash},
            current_adapter_hashes={ad_ns_to_ms.adapter_spec.adapter_id: ad_ns_to_ms.adapter_spec.adapter_hash},
            current_policy_hash="sha256:" + "1" * 64,
            current_schema_hash="sha256:" + "2" * 64,
            current_oracle_ref="oracle.latency.v1",
            current_oracle_hash="sha256:" + "3" * 64,
            current_runtime_version="3.0.1",
            current_tool_attestations={core_spec.tool_id: core_spec.verification_attestation},
        )
        self.assertTrue(hit.hit)

        # Unseen Beta (beta_sensor in seconds): swap AdapterSpec (s -> ms), compose and run cleanly
        beta_goal = {
            "goal_id": "goal-beta",
            "required_capabilities": ["telemetry.score_latency"],
            "input_port": in_sec.to_dict(),
            "expected_outputs": [core_out.to_dict()],
            "oracle_ref": "oracle.latency.v1",
        }
        beta_res = composer.plan(beta_goal, registry, self.sec_ctx, adapters=[ad_s_to_ms.adapter_spec])
        self.assertTrue(beta_res.executable and beta_res.plan is not None)
        self.assertNotEqual(beta_res.plan.adapter_hashes, alpha_res.plan.adapter_hashes)

        # Drift check: mutated policy_hash MUST fail closed (cache miss!)
        miss_drift = mem.retrieve(
            task_signature="telemetry.latency.pipeline",
            current_tool_hashes={core_spec.tool_id: core_spec.binary_hash},
            current_adapter_hashes={ad_ns_to_ms.adapter_spec.adapter_id: ad_ns_to_ms.adapter_spec.adapter_hash},
            current_policy_hash="sha256:" + "9" * 64,
            current_schema_hash="sha256:" + "2" * 64,
            current_oracle_ref="oracle.latency.v1",
            current_oracle_hash="sha256:" + "3" * 64,
            current_runtime_version="3.0.1",
            current_tool_attestations={core_spec.tool_id: core_spec.verification_attestation},
        )
        self.assertFalse(miss_drift.hit)

    def test_nextgen_cli_and_mcp_19_tools(self) -> None:
        import shutil
        if not (shutil.which("kintsugi-rs") or (Path(__file__).resolve().parents[2] / "target" / "release" / "kintsugi-rs").exists()):
            self.skipTest("Rust binary required for native CLI parity")
        """Verify Build #2 CLI subcommands and MCP Build #2 tools (while default stays 9)."""
        # Write a small toolwire input & failure trace inside workspace
        tw_in = self.ws / "wire.jsonl"
        tw_in.write_text('{"ts": 1000000}\n{"ts": 2000000}\n', encoding="utf-8")

        rc_tw, out_tw = _run_cli_json(
            [
                "toolwire",
                "--workspace",
                str(self.ws),
                "--input",
                "wire.jsonl",
                "--source-format",
                "jsonl",
                "--target-format",
                "typed_event_stream",
                "--unit-from",
                "ns",
                "--unit-to",
                "ms",
                "--field",
                "ts",
            ]
        )
        self.assertEqual(rc_tw, 0, msg=str(out_tw))
        self.assertTrue(out_tw["ok"])
        self.assertEqual(out_tw["records_count"], 2)

        rc_sm, out_sm = _run_cli_json(
            [
                "self-model",
                "inspect",
                "--workspace",
                str(self.ws),
                "--required",
                "missing.cap",
                "--save",
            ]
        )
        self.assertEqual(rc_sm, 0, msg=str(out_sm))
        self.assertFalse(out_sm["readiness"]["ready"])

        rc_pp, out_pp = _run_cli_json(["proofpack", "--workspace", str(self.ws), "--parity", "--num-cases", "8"])
        self.assertEqual(rc_pp, 0, msg=str(out_pp))
        self.assertTrue(out_pp["verified_independently"])

        rc_fp, out_fp = _run_cli_json(
            ["forge", "propose", "--workspace", str(self.ws), "--required", "unknown.cap"]
        )
        self.assertEqual(rc_fp, 0)
        self.assertEqual(out_fp["selected_tier"], "rust_c")

        # Stage 5 evolve CLI flags
        rc_ev, out_ev = _run_cli_json(
            [
                "evolve",
                "--workspace",
                str(self.ws),
                "--promote",
                "--mode",
                "shadow",
                "--rule-id",
                "KS-CLI-901",
                "--summary",
                "Eval forbidden",
                "--bad-code",
                "eval(user_data)",
                "--good-code",
                "ast.literal_eval(user_data)",
            ]
        )
        self.assertEqual(rc_ev, 0, msg=str(out_ev))
        self.assertEqual(out_ev["stage"], "shadow")

        rc_reg, out_reg = _run_cli_json(["evolve", "--workspace", str(self.ws), "--registry-status"])
        self.assertEqual(rc_reg, 0)
        self.assertTrue(out_reg["hooks_intact"])

        # Seed a real durable TraceStore + CheckpointManager run and verify `runs`, `tracedoctor`, `compose`, `forge` CLIs
        from kintsugi.runtime import CheckpointManager, RunStatus, TraceStore

        tstore = TraceStore(workspace_root=self.ws)
        ckpt = CheckpointManager(workspace_root=self.ws, trace_store=tstore)
        run_id = "run_cli_e2e_001"
        ckpt.create_run(run_id)
        ckpt.transition_run(run_id, RunStatus.RUNNING, reason="cli_test")
        ckpt.resume_step(run_id, "step_1", "k1", lambda: {"parsed": 2})
        ckpt.transition_run(run_id, RunStatus.COMPLETED, reason="done")

        # Write a plan + verify via CLI compose
        sample_plan_path = self.ws / "sample_plan.json"
        sample_plan_path.write_text(
            json.dumps(
                {
                    "schema": "CompositionPlan/1",
                    "plan_id": "plan-cli-001",
                    "goal_contract_hash": sha256_digest("goal-cli"),
                    "nodes": [],
                    "edges": [],
                    "input_bindings": {},
                    "tool_artifact_hashes": {},
                    "adapter_hashes": {},
                    "permission_union": [],
                    "effects_union": {"read_scopes": [], "write_scopes": [], "network_scopes": [], "exec_permissions": [], "irreversible": False, "idempotent": True, "resource_requirements": {"max_memory_mb": 64, "timeout_seconds": 5}},
                    "expected_outputs": [],
                    "oracle_ref": "ok",
                    "verification_plan": {"mode": "dag_oracle", "goal_id": "goal-cli"},
                    "estimated_resources": {"nodes_count": 0, "edges_count": 0, "dag_depth": 1, "llm_calls": 0},
                }
            ),
            encoding="utf-8",
        )
        rc_cv, out_cv = _run_cli_json(
            ["compose", "plan", "--workspace", str(self.ws), "--required", "missing.cap"]
        )
        self.assertEqual(rc_cv, 1)
        self.assertEqual(out_cv["missing_capabilities"], ["missing.cap"])

        # Runs status & TraceDoctor
        rc_runs, out_runs = _run_cli_json(["runs", "status", "--workspace", str(self.ws)])
        self.assertEqual(rc_runs, 0)
        self.assertGreaterEqual(out_runs["runs_count"], 1)
        first_run = run_id

        rc_rep, out_rep = _run_cli_json(["runs", "replay", "--workspace", str(self.ws), "--run-id", first_run])
        self.assertEqual(rc_rep, 0)
        self.assertTrue(out_rep["chain_verification"]["valid"])

        rc_td, out_td = _run_cli_json(["tracedoctor", "--workspace", str(self.ws), "--run-id", first_run])
        self.assertEqual(rc_td, 0)
        self.assertTrue(out_td["ok"])

        # MCP compatibility & Next-Gen tools
        ledger_path = self.ws / ".kintsugi" / "scars.json"
        default_srv = KintsugiMCPServer(ledger_path)
        self.assertEqual(len(default_srv.active_tools()), 9)

        ng_srv = KintsugiMCPServer(ledger_path, profile="nextgen")
        self.assertEqual(len(ng_srv.active_tools()), 19)
        for tool_name, arguments in (
            ("kintsugi_composition_plan", {"workspace_root": str(self.ws), "required_capabilities": ["missing.cap"]}),
            ("kintsugi_run_status", {"workspace_root": str(self.ws), "run_id": first_run}),
            ("kintsugi_self_model_inspect", {"workspace_root": str(self.ws), "required_capabilities": ["missing.cap"]}),
            ("kintsugi_tracedoctor_analyze", {"workspace_root": str(self.ws), "run_id": first_run}),
            ("kintsugi_proofpack_verify", {"workspace_root": str(self.ws), "mode": "parity", "num_cases": 8}),
        ):
            resp = ng_srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": arguments},
                }
            )
            self.assertIsNotNone(resp)
            self.assertFalse(resp["result"]["isError"], msg=str(resp))

    @unittest.skipUnless(sys.platform == "darwin", "macOS Seatbelt test requires Darwin host")
    def test_kh_b2_sec_003_forged_c_binary_blocked_by_seatbelt_inside_tool_composer(self) -> None:
        canary = "SECRET_KH_B2_SEC_003_COMPOSER_E2E_7719"
        with tempfile.TemporaryDirectory() as ext_tmp:
            outside_secret = Path(ext_tmp).resolve() / "outside_secret.txt"
            outside_secret.write_text(canary, encoding="utf-8")
            os.chmod(outside_secret, 0o644)

            c_src = self.ws / "forged_composer_probe.c"
            c_bin = self.ws / "forged_composer_probe"
            c_escaped = str(outside_secret).replace("\\", "\\\\").replace('"', '\\"')
            c_src.write_text(
                "#include <errno.h>\n"
                "#include <stdio.h>\n"
                "int main(void) {\n"
                f'    FILE *f = fopen("{c_escaped}", "r");\n'
                "    if (f) {\n"
                "        char buf[128];\n"
                "        if (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);\n"
                "        fclose(f);\n"
                "        return 0;\n"
                "    }\n"
                "    return (errno == EPERM || errno == EACCES) ? 42 : 43;\n"
                "}\n",
                encoding="utf-8",
            )
            sb = ToolSandbox(self.ws)
            comp_res, _, _, _ = sb.compile_c(c_src, c_bin, flags=("-O2", "-std=c99"))
            self.assertTrue(comp_res.passed, msg=comp_res.stderr)

            _, bin_digest = compute_file_sha256_confined(c_bin, (self.ws,))
            auth = AttestationAuthority({"ops-ci": "composer-sec003-hmac-secret-material"})
            att = {
                "verifier_id": "ops-ci", "verification_digest": sha256_digest("kh-b2-sec-003-verify"),
                "binary_hash": bin_digest, "tool_id": "forge.composer_probe",
            }
            p_in = PortContract(schema_ref="json:object", semantic_type="exfil_probe_in", unit="none")
            p_probe = PortContract(schema_ref="json:object", semantic_type="exfil_probe_out", unit="none")
            forged_spec = ToolSpec(
                tool_id="forge.composer_probe",
                version="1.0.0",
                source="forge_native",
                binary_hash=bin_digest,
                capabilities=["forge.exfil_probe"],
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                semantic_contract={
                    "input_port": p_in.to_dict(),
                    "output_port": p_probe.to_dict(),
                },
                required_permissions=[],
                runtime_requirements={
                    "sandbox_required": True,
                    "sandbox_backend": "seatbelt",
                    "untrusted_native": False,
                },
                trust_status=TrustStatus.VERIFIED,
                verification_attestation=att,
                entrypoint="forged_composer_probe",
            )
            registry = ToolRegistry(authority=auth)
            forged_spec.verification_attestation = auth.issue_attestation(
                forged_spec.tool_id, forged_spec.binary_hash, sha256_digest("kh-b2-sec-003-verify"),
                "ops-ci", spec_digest=compute_tool_spec_security_digest(forged_spec),
            )
            sign_fixture_tool(registry, forged_spec)

            composer = ToolComposer()
            goal = {
                "goal_id": "goal-kh-b2-sec-003-e2e",
                "required_capabilities": ["forge.exfil_probe"],
                "input_port": p_in.to_dict(),
                "expected_outputs": [p_probe.to_dict()],
                "oracle_ref": "oracle.exfil.v1",
            }
            ctx = SecurityContext(
                workspace_root=str(self.ws),
                profile=SecurityProfile.LOCAL_RESEARCH,
                allowed_permissions=["fs.read"],
                network_allowed=False,
                allow_untrusted_native=False,
            )
            plan_res = composer.plan(goal, registry, ctx)
            self.assertTrue(plan_res.ok and plan_res.plan is not None, msg=plan_res.reasons)

            receipt, _events = composer.execute_plan(
                plan_res.plan,
                registry,
                ctx,
                runner=SecureRunner(attestation_authority=auth),
                oracle=lambda _d: True,
            )
            self.assertNotIn(canary, json.dumps(receipt.to_dict()))
            if sb.probe_isolation().all_passed:
                self.assertEqual(receipt.status, ExecutionStatus.FAIL)
                self.assertEqual(receipt.node_receipts[0]["exit_status"], 42)
            else:
                self.assertEqual(receipt.status, ExecutionStatus.SANDBOX_UNAVAILABLE)

            unavail_runner = SecureRunner(
                sandbox=ToolSandbox(self.ws, force_unavailable=True),
                require_os_sandbox=False,
                attestation_authority=auth,
            )
            receipt_unavail, _ = composer.execute_plan(
                plan_res.plan,
                registry,
                ctx,
                runner=unavail_runner,
                oracle=lambda _d: True,
            )
            self.assertEqual(receipt_unavail.status, ExecutionStatus.SANDBOX_UNAVAILABLE)
            self.assertEqual(receipt_unavail.verification_status, "FAIL")

    def test_cli_tools_verify_external_key_and_evolve_sealed_blind_corpus(self) -> None:
        reg_path = self.ws / ".kintsugi" / "tool_registry.json"
        probe_script = self.ws / "tools" / "cli_probe.py"
        probe_script.parent.mkdir(parents=True, exist_ok=True)
        probe_script.write_text("print('ok')\n", encoding="utf-8")
        _, script_hash = compute_file_sha256_confined(probe_script, (self.ws,))

        reg = ToolRegistry()
        reg.register(
            ToolSpec(
                tool_id="cli.probe_tool",
                version="1.0.0",
                source="local",
                binary_hash=script_hash,
                capabilities=["cli.probe"],
                trust_status=TrustStatus.DISCOVERED,
                entrypoint="tools/cli_probe.py",
            )
        )
        reg.save(reg_path)

        ver_digest = sha256_digest({"tool_id": "cli.probe_tool", "binary_hash": script_hash})
        rc_nokey, out_nokey = _run_cli_json(
            [
                "tools",
                "verify",
                "cli.probe_tool",
                "--workspace",
                str(self.ws),
                "--registry",
                str(reg_path),
                "--verify-digest",
                ver_digest,
                "--verifier-id",
                "ops-ci",
            ]
        )
        self.assertEqual(rc_nokey, 1)
        self.assertFalse(out_nokey["ok"])
        self.assertIn("VERIFIER_KEY_FILE_REQUIRED", out_nokey["error"])

        with tempfile.TemporaryDirectory() as ext_tmp:
            ext_dir = Path(ext_tmp).resolve()
            ext_key_file = ext_dir / "verifiers.json"
            ext_key_file.write_text(
                json.dumps({"verifiers": {"ops-ci": "owner-external-hmac-secret-material-2026"}}),
                encoding="utf-8",
            )
            os.chmod(ext_key_file, 0o600)

            ext_auth = AttestationAuthority.from_key_file(ext_key_file, workspace_root=self.ws)
            att = ext_auth.issue_attestation("cli.probe_tool", script_hash, ver_digest, "ops-ci", spec_digest=compute_tool_spec_security_digest(json.loads(reg_path.read_text(encoding="utf-8"))["tools"][0]))
            rc_ok, out_ok = _run_cli_json(
                [
                    "tools",
                    "verify",
                    "cli.probe_tool",
                    "--workspace",
                    str(self.ws),
                    "--registry",
                    str(reg_path),
                    "--verify-digest",
                    ver_digest,
                    "--verifier-id",
                    "ops-ci",
                    "--verifier-key-file",
                    str(ext_key_file),
                    "--attestation-signature",
                    str(att["signature"]),
                    "--save",
                ]
            )
            self.assertEqual(rc_ok, 0, msg=str(out_ok))
            self.assertTrue(out_ok["ok"])
            self.assertEqual(out_ok["tool"]["trust_status"], "VERIFIED")
            self.assertEqual(out_ok["tool"]["verification_attestation"]["signature"], att["signature"])

            sealed_corpus = ext_dir / "sealed_blind.json"
            corpus_payload = {
                "families": [
                    {
                        "family_id": "cli-sealed-fam-1",
                        "task_class": "dangerous_exec",
                        "language": "python",
                        "positives": ["import pickle\npickle.loads(raw)\n"],
                        "negatives": ["import json\njson.loads(raw)\n"],
                    }
                ]
            }
            corpus_bytes = json.dumps(corpus_payload).encode("utf-8")
            sealed_corpus.write_bytes(corpus_bytes)
            _, corpus_sha = compute_file_sha256_confined(sealed_corpus, (ext_dir,))

            rc_nopin, _ = _run_cli_json(
                ["evolve", "--workspace", str(self.ws), "--sealed-blind-corpus", str(sealed_corpus)]
            )
            self.assertEqual(rc_nopin, 2)

            rc_badpin, out_badpin = _run_cli_json(
                [
                    "evolve",
                    "--workspace",
                    str(self.ws),
                    "--sealed-blind-corpus",
                    str(sealed_corpus),
                    "--sealed-sha256",
                    "sha256:" + ("0" * 64),
                ]
            )
            self.assertEqual(rc_badpin, 1)
            self.assertIn("SEALED_CORPUS_SHA256_MISMATCH", out_badpin["error"])

            inside_corpus = self.ws / "inside_sealed.json"
            inside_corpus.write_bytes(corpus_bytes)
            rc_inside, out_inside = _run_cli_json(
                [
                    "evolve",
                    "--workspace",
                    str(self.ws),
                    "--sealed-blind-corpus",
                    str(inside_corpus),
                    "--sealed-sha256",
                    corpus_sha,
                ]
            )
            self.assertEqual(rc_inside, 1)
            self.assertIn("SEALED_CORPUS_MUST_BE_EXTERNAL", out_inside["error"])

            rc_sealed, out_sealed = _run_cli_json(
                [
                    "evolve",
                    "--workspace",
                    str(self.ws),
                    "--sealed-blind-corpus",
                    str(sealed_corpus),
                    "--sealed-sha256",
                    corpus_sha,
                ]
            )
            self.assertEqual(rc_sealed, 0, msg=str(out_sealed))
            self.assertTrue(out_sealed["ok"])
            self.assertEqual(
                out_sealed["report"]["no_memory_control"]["corpus_origin"],
                "external_sealed_verified",
            )


if __name__ == "__main__":
    unittest.main()
