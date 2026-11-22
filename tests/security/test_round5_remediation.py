"""Independent regression probes for Build #2 Round-5 security & durable-runtime gates."""

from __future__ import annotations

import json
import os
import signal
import socket
import stat
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict

from kintsugi.capability.contracts_v2 import AdapterSpec, CompositionPlan, PortContract
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
from kintsugi.composition.adapter_synthesizer import (
    AdapterCatalog,
    AdapterProposalStatus,
    AdapterSynthesizer,
)
from kintsugi.composition.tool_composer import ToolComposer
from kintsugi.runtime.secure_runner import SecureRunner, compute_callable_sha256

try:
    from fixture_attestation import sign_fixture_adapter, sign_fixture_tool
except ImportError:  # pragma: no cover
    from tests.fixture_attestation import sign_fixture_adapter, sign_fixture_tool

_R5_KEY = b"kintsugi-round5-independent-fixture-hmac-key"
_R5_MUTABLE_GLOBAL: Dict[str, str] = {"mode": "safe_initial"}


def _authority() -> AttestationAuthority:
    return AttestationAuthority(
        {
            "round5-ci": _R5_KEY,
            "kintsugi.composition_oracle": _R5_KEY,
        }
    )


def _signed_callable_tool(
    registry: ToolRegistry,
    runner: SecureRunner,
    *,
    tool_id: str,
    cap: str,
    fn,
    in_port: PortContract | None = None,
    out_port: PortContract | None = None,
    permissions: list[str] | None = None,
    side_effects: list[str] | None = None,
) -> ToolSpec:
    perms = permissions if permissions is not None else ["fs.read", "fs.write"]
    digest = runner.register_trusted_host_callable(tool_id, fn, required_permissions=perms)
    sem: Dict[str, Any] = {}
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
        required_permissions=perms,
        side_effects=side_effects or [],
        runtime_requirements={"callable_name": tool_id},
        semantic_contract=sem,
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={
            "verifier_id": "round5-ci",
            "tool_id": tool_id,
            "binary_hash": digest,
            "verification_digest": sha256_digest(tool_id),
        },
    )
    sign_fixture_tool(registry, spec)
    runner.bind_trusted_host_callable_spec(tool_id, compute_tool_spec_security_digest(spec))
    return spec


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
            "verifier_id": "round5-ci",
            "adapter_id": adapter_id,
            "adapter_hash": draft.adapter_hash,
            "verification_digest": sha256_digest({"adapter_id": adapter_id, "adapter_hash": draft.adapter_hash}),
        },
    )
    return sign_fixture_adapter(registry, verified, callable_hash=callable_hash)


def _inc_counter(path: Path) -> int:
    val = int(path.read_text(encoding="utf-8")) + 1 if path.exists() else 1
    path.write_text(str(val), encoding="utf-8")
    return val


class TestRound5Remediation(unittest.TestCase):
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
        _R5_MUTABLE_GLOBAL["mode"] = "safe_initial"
        self._tmp.cleanup()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_kh_b2_r4_runtime_001_edge_and_goal_adapter_wal_blocks_sigkill_replay(self) -> None:
        # 1. Crash during edge adapter execution -> ADAPTER_IN_FLIGHT triggers RECONCILIATION_REQUIRED & zero replay.
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        p_ns = PortContract(schema_ref="json:obj", semantic_type="r5_dur", unit="ns")
        p_ms = PortContract(schema_ref="json:obj", semantic_type="r5_dur", unit="ms")
        p_done = PortContract(schema_ref="json:obj", semantic_type="r5_done", unit="none")

        edge_counter = self.ws / "edge_counter.txt"
        edge_ready = self.ws / "edge_ready.flag"
        journal = self.ws / "edge_kill_journal.jsonl"

        def n1_fn(_args: Dict[str, Any]) -> Dict[str, Any]:
            return {"ns": 3_000_000}

        def edge_kill_adapter(payload: Dict[str, Any]) -> Dict[str, Any]:
            _inc_counter(edge_counter)
            edge_ready.write_text("EDGE_COMMITTED", encoding="utf-8")
            if os.environ.get("KINTSUGI_WAIT_KILL") == "1":
                time.sleep(5.0)
            return {"ms": int(payload["ns"]) // 1_000_000}

        def n2_fn(args: Dict[str, Any]) -> Dict[str, Any]:
            return {"final_ms": int(args["ms"])}

        _signed_callable_tool(registry, runner, tool_id="r5.n1", cap="cap.n1", fn=n1_fn, out_port=p_ns)
        _signed_callable_tool(registry, runner, tool_id="r5.n2", cap="cap.n2", fn=n2_fn, in_port=p_ms, out_port=p_done)
        edge_hash = runner.register_trusted_host_adapter("r5.edge.ns_ms", edge_kill_adapter)
        edge_ad = _signed_adapter(registry, "r5.edge.ns_ms", p_ns, p_ms, callable_hash=edge_hash)

        composer = ToolComposer()
        pres = composer.plan(
            {"goal_id": "r5-edge-kill", "required_capabilities": ["cap.n1", "cap.n2"], "expected_outputs": [p_done]},
            registry,
            self.ctx,
            adapters=[edge_ad],
        )
        self.assertTrue(pres.ok and pres.plan is not None, pres.reasons)
        plan = pres.plan

        pid = os.fork()
        if pid == 0:
            os.environ["KINTSUGI_WAIT_KILL"] = "1"
            composer.execute_plan(
                plan,
                registry,
                self.ctx,
                runner=runner,
                adapters=[edge_ad],
                checkpoint_store_path=journal,
                resume_run_id="r5_edge_run1",
                oracle=lambda d: d["output"] == {"final_ms": 3},
            )
            os._exit(2)

        deadline = time.monotonic() + 10.0
        while not edge_ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(edge_ready.exists(), "edge adapter did not signal side-effect commit")
        os.kill(pid, signal.SIGKILL)
        _, wait_st = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(wait_st))
        self.assertEqual(int(edge_counter.read_text(encoding="utf-8")), 1)

        # Resume MUST fail closed with RECONCILIATION_REQUIRED and MUST NOT re-run edge adapter.
        rec_wait, ev_wait = composer.execute_plan(
            plan,
            registry,
            self.ctx,
            runner=runner,
            adapters=[edge_ad],
            checkpoint_store_path=journal,
            resume_run_id="r5_edge_run1",
            oracle=lambda d: d["output"] == {"final_ms": 3},
        )
        self.assertEqual(rec_wait.status, ExecutionStatus.RECONCILIATION_REQUIRED)
        self.assertEqual(len(rec_wait.unresolved_nodes), 1)
        edge_step_id = rec_wait.unresolved_nodes[0]
        self.assertTrue(edge_step_id.startswith("edge:"), edge_step_id)
        self.assertEqual(int(edge_counter.read_text(encoding="utf-8")), 1)
        self.assertIn("ADAPTER_IN_FLIGHT", [e.state for e in ev_wait])

        # Reconcile edge adapter COMMITTED and finish resume without re-invoking adapter.
        composer.reconcile_checkpoint_node(
            checkpoint_store_path=journal,
            run_id="r5_edge_run1",
            node_id=edge_step_id,
            outcome="COMMITTED",
            security_context=self.ctx,
            verified_output={"ms": 3},
            verified_receipt={"verification_status": "PASS", "node_id": edge_step_id, "status": "PASS"},
            operator_confirmed=True,
        )
        rec_done, ev_done = composer.execute_plan(
            plan,
            registry,
            self.ctx,
            runner=runner,
            adapters=[edge_ad],
            checkpoint_store_path=journal,
            resume_run_id="r5_edge_run1",
            oracle=lambda d: d["output"] == {"final_ms": 3},
        )
        self.assertEqual(rec_done.status, ExecutionStatus.PASS, rec_done.oracle_result)
        self.assertEqual(int(edge_counter.read_text(encoding="utf-8")), 1)
        self.assertIn("ADAPTER_SKIPPED_CHECKPOINT", [e.state for e in ev_done])

        # 2. Crash INSIDE n2 AFTER edge adapter already completed -> ADAPTER_APPLIED cached, no edge replay on resume.
        edge_counter_b = self.ws / "edge_counter_b.txt"
        n2_ready = self.ws / "n2_ready.flag"
        journal_b = self.ws / "after_edge_journal.jsonl"

        def edge_b_fn(payload: Dict[str, Any]) -> Dict[str, Any]:
            _inc_counter(edge_counter_b)
            return {"ms": int(payload["ns"]) // 1_000_000}

        def n2_kill_fn(args: Dict[str, Any]) -> Dict[str, Any]:
            if os.environ.get("KINTSUGI_KILL_N2") == "1":
                n2_ready.write_text("N2_STARTED", encoding="utf-8")
                time.sleep(5.0)
            return {"final_ms": int(args["ms"])}

        reg_b = ToolRegistry(authority=_authority())
        run_b = SecureRunner(allow_trusted_host_callables=True, attestation_authority=reg_b.authority)
        _signed_callable_tool(reg_b, run_b, tool_id="r5.b.n1", cap="cap.b1", fn=n1_fn, out_port=p_ns)
        _signed_callable_tool(reg_b, run_b, tool_id="r5.b.n2", cap="cap.b2", fn=n2_kill_fn, in_port=p_ms, out_port=p_done)
        edge_b_hash = run_b.register_trusted_host_adapter("r5.b.edge", edge_b_fn)
        edge_b_ad = _signed_adapter(reg_b, "r5.b.edge", p_ns, p_ms, callable_hash=edge_b_hash)
        plan_b = composer.plan(
            {"goal_id": "r5-after-edge-kill", "required_capabilities": ["cap.b1", "cap.b2"], "expected_outputs": [p_done]},
            reg_b,
            self.ctx,
            adapters=[edge_b_ad],
        ).plan
        assert plan_b is not None

        pid_b = os.fork()
        if pid_b == 0:
            os.environ["KINTSUGI_KILL_N2"] = "1"
            composer.execute_plan(
                plan_b,
                reg_b,
                self.ctx,
                runner=run_b,
                adapters=[edge_b_ad],
                checkpoint_store_path=journal_b,
                resume_run_id="r5_edge_run2",
                oracle=lambda d: d["output"] == {"final_ms": 3},
            )
            os._exit(2)

        deadline_b = time.monotonic() + 10.0
        while not n2_ready.exists() and time.monotonic() < deadline_b:
            time.sleep(0.01)
        self.assertTrue(n2_ready.exists())
        os.kill(pid_b, signal.SIGKILL)
        os.waitpid(pid_b, 0)
        self.assertEqual(int(edge_counter_b.read_text(encoding="utf-8")), 1)

        rec_b_wait, _ = composer.execute_plan(
            plan_b,
            reg_b,
            self.ctx,
            runner=run_b,
            adapters=[edge_b_ad],
            checkpoint_store_path=journal_b,
            resume_run_id="r5_edge_run2",
            oracle=lambda d: d["output"] == {"final_ms": 3},
        )
        self.assertEqual(rec_b_wait.status, ExecutionStatus.RECONCILIATION_REQUIRED)
        self.assertEqual(int(edge_counter_b.read_text(encoding="utf-8")), 1)
        n2_step_id = rec_b_wait.unresolved_nodes[0]
        composer.reconcile_checkpoint_node(
            checkpoint_store_path=journal_b,
            run_id="r5_edge_run2",
            node_id=n2_step_id,
            outcome="NOT_EXECUTED",
            security_context=self.ctx,
            operator_confirmed=True,
        )
        rec_b_done, ev_b_done = composer.execute_plan(
            plan_b,
            reg_b,
            self.ctx,
            runner=run_b,
            adapters=[edge_b_ad],
            checkpoint_store_path=journal_b,
            resume_run_id="r5_edge_run2",
            oracle=lambda d: d["output"] == {"final_ms": 3},
        )
        self.assertEqual(rec_b_done.status, ExecutionStatus.PASS, rec_b_done.oracle_result)
        self.assertEqual(int(edge_counter_b.read_text(encoding="utf-8")), 1)
        self.assertIn("ADAPTER_SKIPPED_CHECKPOINT", [e.state for e in ev_b_done])

        # 3. Goal-input & goal-output adapters both journaled with ADAPTER_IN_FLIGHT before execution.
        gin_counter = self.ws / "gin_counter.txt"
        gout_counter = self.ws / "gout_counter.txt"
        gout_ready = self.ws / "gout_ready.flag"
        goal_journal = self.ws / "goal_adapters.jsonl"

        def gin_fn(payload: Dict[str, Any]) -> Dict[str, Any]:
            _inc_counter(gin_counter)
            return {"ns": int(payload.get("ns", 5_000_000))}

        def passthrough_ms(args: Dict[str, Any]) -> Dict[str, Any]:
            return {"ms": int(args["ns"]) // 1_000_000}

        def gout_fn(payload: Dict[str, Any]) -> Dict[str, Any]:
            _inc_counter(gout_counter)
            gout_ready.write_text("GOUT", encoding="utf-8")
            if os.environ.get("KINTSUGI_WAIT_GOUT") == "1":
                time.sleep(5.0)
            return {"ms": int(payload["ms"]) * 2}

        reg_g = ToolRegistry(authority=_authority())
        run_g = SecureRunner(allow_trusted_host_callables=True, attestation_authority=reg_g.authority)
        t_spec = _signed_callable_tool(
            reg_g, run_g, tool_id="r5.g.core", cap="cap.g", fn=passthrough_ms, in_port=p_ns, out_port=p_ms
        )
        gin_hash = run_g.register_trusted_host_adapter("r5.g.in", gin_fn)
        gout_hash = run_g.register_trusted_host_adapter("r5.g.out", gout_fn)
        gin_ad = _signed_adapter(reg_g, "r5.g.in", p_ns, p_ns, callable_hash=gin_hash)
        gout_ad = _signed_adapter(reg_g, "r5.g.out", p_ms, p_ms, callable_hash=gout_hash)
        goal_plan = CompositionPlan(
            plan_id="plan-r5-goal-adapters",
            goal_contract_hash=sha256_digest("goal-r5"),
            nodes=[
                {
                    "node_id": "n1",
                    "tool_id": t_spec.tool_id,
                    "tool_version": t_spec.version,
                    "kind": "host_trusted",
                    "binary_hash": t_spec.binary_hash,
                    "capabilities": ["cap.g"],
                }
            ],
            edges=[],
            input_bindings={"goal_input_adapters": [{"node_id": "n1", "adapter_id": gin_ad.adapter_id}], "n1.ns": 4_000_000},
            tool_artifact_hashes={t_spec.tool_id: t_spec.binary_hash},
            adapter_hashes={gin_ad.adapter_id: gin_ad.adapter_hash, gout_ad.adapter_id: gout_ad.adapter_hash},
            permission_union=["fs.read", "fs.write"],
            expected_outputs=[p_ms.to_dict()],
            oracle_ref="oracle:r5",
            verification_plan={"goal_output_adapters": [{"node_id": "n1", "adapter_id": gout_ad.adapter_id}]},
        )

        pid_g = os.fork()
        if pid_g == 0:
            os.environ["KINTSUGI_WAIT_GOUT"] = "1"
            composer.execute_plan(
                goal_plan,
                reg_g,
                self.ctx,
                runner=run_g,
                adapters=[gin_ad, gout_ad],
                checkpoint_store_path=goal_journal,
                resume_run_id="r5_goal_run",
                oracle=lambda d: d["output"] == {"ms": 8},
            )
            os._exit(2)

        deadline_g = time.monotonic() + 10.0
        while not gout_ready.exists() and time.monotonic() < deadline_g:
            time.sleep(0.01)
        self.assertTrue(gout_ready.exists())
        os.kill(pid_g, signal.SIGKILL)
        os.waitpid(pid_g, 0)
        self.assertEqual(int(gin_counter.read_text(encoding="utf-8")), 1)
        self.assertEqual(int(gout_counter.read_text(encoding="utf-8")), 1)

        rec_g_wait, _ = composer.execute_plan(
            goal_plan,
            reg_g,
            self.ctx,
            runner=run_g,
            adapters=[gin_ad, gout_ad],
            checkpoint_store_path=goal_journal,
            resume_run_id="r5_goal_run",
            oracle=lambda d: d["output"] == {"ms": 8},
        )
        self.assertEqual(rec_g_wait.status, ExecutionStatus.RECONCILIATION_REQUIRED)
        self.assertTrue(rec_g_wait.unresolved_nodes and rec_g_wait.unresolved_nodes[0].startswith("goal_out:"))
        self.assertEqual(int(gin_counter.read_text(encoding="utf-8")), 1)
        self.assertEqual(int(gout_counter.read_text(encoding="utf-8")), 1)

        composer.reconcile_checkpoint_node(
            checkpoint_store_path=goal_journal,
            run_id="r5_goal_run",
            node_id=rec_g_wait.unresolved_nodes[0],
            outcome="COMMITTED",
            security_context=self.ctx,
            verified_output={"ms": 8},
            verified_receipt={"verification_status": "PASS", "node_id": rec_g_wait.unresolved_nodes[0], "status": "PASS"},
            operator_confirmed=True,
        )
        rec_g_done, _ = composer.execute_plan(
            goal_plan,
            reg_g,
            self.ctx,
            runner=run_g,
            adapters=[gin_ad, gout_ad],
            checkpoint_store_path=goal_journal,
            resume_run_id="r5_goal_run",
            oracle=lambda d: d["output"] == {"ms": 8},
        )
        self.assertEqual(rec_g_done.status, ExecutionStatus.PASS, rec_g_done.oracle_result)
        self.assertEqual(int(gin_counter.read_text(encoding="utf-8")), 1)
        self.assertEqual(int(gout_counter.read_text(encoding="utf-8")), 1)

    def test_kh_b2_r4_sec_001_mutable_callable_state_and_workspace_sandbox(self) -> None:
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)

        # 1. Mutable closure dict, default list, and module global all change compute_callable_sha256 & get blocked.
        closure_cfg: Dict[str, Any] = {"target": str(self.ws / "safe_closure.txt")}
        side_marker = self.ws / "mutated_marker.txt"

        def fn_closure(_args: Dict[str, Any]) -> Dict[str, Any]:
            side_marker.write_text("SHOULD_NOT_RUN", encoding="utf-8")
            return {"target": closure_cfg["target"]}

        default_targets = [str(self.ws / "safe_default.txt")]

        def fn_default(_args: Dict[str, Any], cfg: list[str] = default_targets) -> Dict[str, Any]:
            side_marker.write_text("SHOULD_NOT_RUN", encoding="utf-8")
            return {"target": cfg[-1]}

        def fn_global(_args: Dict[str, Any]) -> Dict[str, Any]:
            side_marker.write_text("SHOULD_NOT_RUN", encoding="utf-8")
            return {"mode": _R5_MUTABLE_GLOBAL["mode"]}

        spec_c = _signed_callable_tool(registry, runner, tool_id="r5.mut.closure", cap="cap.mc", fn=fn_closure)
        spec_d = _signed_callable_tool(registry, runner, tool_id="r5.mut.default", cap="cap.md", fn=fn_default)
        spec_g = _signed_callable_tool(registry, runner, tool_id="r5.mut.global", cap="cap.mg", fn=fn_global)

        h_c_before = compute_callable_sha256(fn_closure)
        closure_cfg["target"] = str(self.root / "outside_tampered")
        self.assertNotEqual(compute_callable_sha256(fn_closure), h_c_before)

        h_d_before = compute_callable_sha256(fn_default)
        default_targets.append(str(self.root / "outside_default_tampered"))
        self.assertNotEqual(compute_callable_sha256(fn_default), h_d_before)

        h_g_before = compute_callable_sha256(fn_global)
        _R5_MUTABLE_GLOBAL["mode"] = "tampered_global"
        self.assertNotEqual(compute_callable_sha256(fn_global), h_g_before)

        for spec in (spec_c, spec_d, spec_g):
            rec = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED, spec.tool_id)
            self.assertIn("TOOL_CALLABLE_HASH_MISMATCH", rec.stderr_excerpt)
            self.assertFalse(side_marker.exists())

        # 2. Even an unmutated signed host callable & signed adapter are OS/audit-sandboxed to workspace_root.
        outside_target = self.root / "outside_callable_canary.txt"
        inside_target = self.ws / "inside_callable_ok.txt"

        def host_writer(args: Dict[str, Any]) -> Dict[str, Any]:
            Path(str(args["dest"])).write_text("ESCAPED", encoding="utf-8")
            return {"written": True}

        writer_spec = _signed_callable_tool(
            registry, runner, tool_id="r5.writer", cap="cap.w", fn=host_writer, permissions=["fs.read", "fs.write"]
        )
        rec_out = runner.run(writer_spec, {"dest": str(outside_target)}, self.ctx, oracle=lambda _: True)
        self.assertNotEqual(rec_out.status, ExecutionStatus.PASS)
        self.assertFalse(outside_target.exists())

        rec_in = runner.run(writer_spec, {"dest": str(inside_target)}, self.ctx, oracle=lambda r: r["output"] == {"written": True})
        self.assertEqual(rec_in.status, ExecutionStatus.PASS)
        self.assertTrue(inside_target.exists())

        # 3. Signed trusted host adapter trying to write outside workspace is also blocked.
        outside_ad_canary = self.root / "outside_adapter_canary.txt"
        p_in = PortContract(schema_ref="json:obj", semantic_type="ad_in", unit="ns")
        p_out = PortContract(schema_ref="json:obj", semantic_type="ad_out", unit="ms")
        p_final = PortContract(schema_ref="json:obj", semantic_type="ad_fin", unit="none")

        _signed_callable_tool(registry, runner, tool_id="r5.src", cap="cap.asrc", fn=lambda _a: {"ns": 1_000_000}, out_port=p_in)
        _signed_callable_tool(registry, runner, tool_id="r5.dst", cap="cap.adst", fn=lambda a: {"ms": a["ms"]}, in_port=p_out, out_port=p_final)

        def evil_signed_adapter(payload: Dict[str, Any]) -> Dict[str, Any]:
            outside_ad_canary.write_text("ADAPTER_ESCAPE", encoding="utf-8")
            return {"ms": int(payload["ns"]) // 1_000_000}

        ad_hash = runner.register_trusted_host_adapter("r5.evil_signed.ad", evil_signed_adapter)
        evil_ad = _signed_adapter(registry, "r5.evil_signed.ad", p_in, p_out, callable_hash=ad_hash)
        composer = ToolComposer()
        ad_plan = composer.plan(
            {"goal_id": "r5-ad-sandbox", "required_capabilities": ["cap.asrc", "cap.adst"], "expected_outputs": [p_final]},
            registry,
            self.ctx,
            adapters=[evil_ad],
        )
        self.assertTrue(ad_plan.ok and ad_plan.plan is not None, ad_plan.reasons)
        rec_ad, _ = composer.execute_plan(ad_plan.plan, registry, self.ctx, runner=runner, adapters=[evil_ad], oracle=lambda _: True)
        self.assertNotEqual(rec_ad.status, ExecutionStatus.PASS)
        self.assertFalse(outside_ad_canary.exists())

        # 4. Forked child blocks ctypes.CDLL and socket.connect when network_allowed=False.
        if hasattr(os, "fork"):
            def ctypes_probe(_args: Dict[str, Any]) -> Dict[str, Any]:
                import ctypes
                ctypes.CDLL(None)
                return {"bypassed": True}

            def net_probe(_args: Dict[str, Any]) -> Dict[str, Any]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.settimeout(0.2)
                    s.connect(("127.0.0.1", 1))
                finally:
                    s.close()
                return {"connected": True}

            ct_spec = _signed_callable_tool(registry, runner, tool_id="r5.ct", cap="cap.ct", fn=ctypes_probe)
            nt_spec = _signed_callable_tool(registry, runner, tool_id="r5.nt", cap="cap.nt", fn=net_probe)
            rec_ct = runner.run(ct_spec, {}, self.ctx, oracle=lambda _: True)
            rec_nt = runner.run(nt_spec, {}, self.ctx, oracle=lambda _: True)
            self.assertEqual(rec_ct.status, ExecutionStatus.FAIL)
            self.assertIn("SANDBOX_CTYPES_FORBIDDEN", rec_ct.stderr_excerpt)
            self.assertEqual(rec_nt.status, ExecutionStatus.FAIL)
            self.assertTrue(
                "SANDBOX_NETWORK_FORBIDDEN" in rec_nt.stderr_excerpt
                or "Operation not permitted" in rec_nt.stderr_excerpt
                or "PermissionError" in rec_nt.stderr_excerpt,
                rec_nt.stderr_excerpt,
            )

    def test_kh_b2_r4_sec_002_adapter_catalog_and_synthesizer_require_authority(self) -> None:
        p_ns = PortContract(schema_ref="typed_event_stream", semantic_type="duration", unit="ns", cardinality="many", ordering="ordered", precision="decimal128")
        p_ms = PortContract(schema_ref="typed_event_stream", semantic_type="duration", unit="ms", cardinality="many", ordering="ordered", precision="decimal128")
        corpus_hash = sha256_digest("r5-catalog-corpus")
        draft = AdapterSpec(
            adapter_id="forged.catalog.ns_ms",
            version="1.0.0",
            source_port=p_ns,
            target_port=p_ms,
            mapping={"fields": {"dur_ns": "dur_ms"}, "unit_fields": {"dur_ns": "dur_ms"}, "unit_mode": "decimal"},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": "0.000001"},
            lossless=True,
            verification_corpus_hash=corpus_hash,
            trust_status=TrustStatus.DISCOVERED,
        )
        forged_verified = AdapterSpec(
            adapter_id="forged.catalog.ns_ms",
            version="1.0.0",
            source_port=p_ns,
            target_port=p_ms,
            mapping=draft.mapping,
            unit_conversion=draft.unit_conversion,
            lossless=True,
            verification_corpus_hash=corpus_hash,
            adapter_hash=draft.adapter_hash,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "self-asserted-attacker",
                "adapter_id": "forged.catalog.ns_ms",
                "adapter_hash": draft.adapter_hash,
                "verification_digest": sha256_digest({"forged": True}),
            },
        )

        unauth_catalog = AdapterCatalog()
        with self.assertRaises(Exception):
            unauth_catalog.register(forged_verified)

        # Even if forged entry is injected into JSON or internal map without authority, lookup/get/load reject it.
        cat_file = self.ws / "forged_catalog.json"
        cat_file.write_text(
            json.dumps({"schema": AdapterCatalog.SCHEMA_VERSION, "adapters": [forged_verified.to_dict()]}),
            encoding="utf-8",
        )
        loaded_no_auth = AdapterCatalog(cat_file)
        self.assertEqual(loaded_no_auth.list_verified(), [])
        self.assertIsNone(loaded_no_auth.get("forged.catalog.ns_ms"))
        self.assertEqual(loaded_no_auth.lookup(p_ns, p_ms), [])

        unauth_catalog._entries["forged.catalog.ns_ms"] = (forged_verified, None)
        self.assertIsNone(unauth_catalog.get("forged.catalog.ns_ms"))
        self.assertEqual(unauth_catalog.list_verified(), [])
        self.assertEqual(unauth_catalog.lookup(p_ns, p_ms), [])

        synth_no_auth = AdapterSynthesizer(catalog=unauth_catalog)
        prop_no_auth = synth_no_auth.propose(p_ns, p_ms)
        self.assertNotEqual(prop_no_auth.status, AdapterProposalStatus.VERIFIED_CATALOG)
        self.assertNotEqual(prop_no_auth.status, AdapterProposalStatus.SYNTHESIZED_VERIFIED)

        # With real authority + HMAC signature, catalog & Tier-1 VERIFIED_CATALOG succeed cleanly.
        auth = _authority()
        signed_ad = sign_fixture_adapter(auth, forged_verified)
        auth_catalog = AdapterCatalog(cat_file, authority=auth)
        auth_catalog.register(signed_ad)
        auth_catalog.save()
        reloaded_auth = AdapterCatalog(cat_file, authority=auth)
        self.assertIsNotNone(reloaded_auth.get("forged.catalog.ns_ms"))
        synth_auth = AdapterSynthesizer(catalog=reloaded_auth)
        prop_auth = synth_auth.propose(p_ns, p_ms)
        self.assertEqual(prop_auth.status, AdapterProposalStatus.VERIFIED_CATALOG)

    def test_kh_b2_r4_api_003_hardlink_checkpoint_escape_blocked(self) -> None:
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        p_out = PortContract(schema_ref="json:obj", semantic_type="hl_out", unit="none")
        exec_marker = self.ws / "node_should_not_run.flag"

        def safe_tool(_args: Dict[str, Any]) -> Dict[str, Any]:
            exec_marker.write_text("RAN", encoding="utf-8")
            return {"ok": True}

        _signed_callable_tool(registry, runner, tool_id="r5.hl.tool", cap="cap.hl", fn=safe_tool, out_port=p_out)
        composer = ToolComposer()
        pres = composer.plan(
            {"goal_id": "r5-hl", "required_capabilities": ["cap.hl"], "expected_outputs": [p_out]},
            registry,
            self.ctx,
        )
        self.assertTrue(pres.ok and pres.plan is not None, pres.reasons)
        plan = pres.plan

        # Test both 0-byte empty AND non-empty hard-linked external files.
        for label, init_bytes in (("empty", b""), ("seeded", b"EXTERNAL_OWNER_DATA\n")):
            with self.subTest(label=label):
                ext_target = self.root / f"external_target_{label}.txt"
                ext_target.write_bytes(init_bytes)
                hl_path = self.ws / f"hardlink_ckpt_{label}.jsonl"
                os.link(ext_target, hl_path)

                rec, evs = composer.execute_plan(
                    plan,
                    registry,
                    self.ctx,
                    runner=runner,
                    checkpoint_store_path=hl_path,
                    resume_run_id=f"r5_hl_{label}",
                    oracle=lambda d: d["output"] == {"ok": True},
                )
                self.assertEqual(rec.status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("CHECKPOINT_HARDLINK_FORBIDDEN", rec.oracle_result.get("reason", "") + evs[0].decision_reason)
                self.assertEqual(ext_target.read_bytes(), init_bytes)
                self.assertFalse(exec_marker.exists())

                with self.assertRaises(PermissionError):
                    composer.reconcile_checkpoint_node(
                        checkpoint_store_path=hl_path,
                        run_id=f"r5_hl_{label}",
                        node_id="n1",
                        outcome="NOT_EXECUTED",
                        security_context=self.ctx,
                        operator_confirmed=True,
                    )

        # Normal confined checkpoint file succeeds with mode 0o600 and st_nlink == 1.
        normal_ckpt = self.ws / "sub" / "normal_ckpt.jsonl"
        rec_ok, _ = composer.execute_plan(
            plan,
            registry,
            self.ctx,
            runner=runner,
            checkpoint_store_path=normal_ckpt,
            resume_run_id="r5_hl_normal",
            oracle=lambda d: d["output"] == {"ok": True},
        )
        self.assertEqual(rec_ok.status, ExecutionStatus.PASS)
        st = normal_ckpt.stat()
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertEqual(st.st_nlink, 1)


if __name__ == "__main__":
    unittest.main()
