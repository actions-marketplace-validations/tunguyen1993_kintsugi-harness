"""Stage 4 tests for TraceStore, RunStateMachine, CheckpointManager, TokenEconomicsTracker & AdaptiveResourceScheduler."""

from __future__ import annotations

import json
import os
import random
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Set

from kintsugi.capability.contracts_v2 import RunEvent, verify_event_chain
from kintsugi.capability.schemas import sha256_digest
from kintsugi.config import GithubPublicConfig, KintsugiConfig, OperatingProfile
from kintsugi.runtime import ReconciliationRequiredError as RuntimeReconciliationRequiredError
from kintsugi.runtime.run_state import (
    ALLOWED_TRANSITIONS,
    CHECKPOINT_SCHEMA_VERSION,
    CheckpointManager,
    InvalidStateTransitionError,
    ReconciliationRequiredError,
    RunStateMachine,
    RunStatus,
    _compute_checkpoint_digest,
)
from kintsugi.runtime.token_economics import (
    REQUIRED_STAGE4_METRICS,
    AdaptiveResourceScheduler,
    BudgetExceededError,
    CancellationError,
    CancellationToken,
    RunTelemetry,
    TokenEconomicsTracker,
    WatchdogTimeoutError,
)
from kintsugi.runtime.trace_store import TraceStore


class _SimulatedProcessKill(RuntimeError):
    """Simulated SIGKILL / abrupt crash injected during durable DAG tests."""


class TestDurableRuntimeAndEconomics(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.external = self.root / "external"
        self.external.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # 1. RunStatus & RunStateMachine strict transition checks
    # ------------------------------------------------------------------
    def test_run_status_exact_states_and_strict_transitions(self) -> None:
        self.assertIs(RuntimeReconciliationRequiredError, ReconciliationRequiredError)
        self.assertEqual(
            {s.value for s in RunStatus},
            {
                "PENDING",
                "RUNNING",
                "WAITING_APPROVAL",
                "PAUSED",
                "RECONCILIATION_REQUIRED",
                "FAILED",
                "COMPLETED",
            },
        )

        sm = RunStateMachine("run-state-001")
        self.assertEqual(sm.status, RunStatus.PENDING)
        self.assertFalse(sm.is_terminal)

        # Valid lifecycle: PENDING -> WAITING_APPROVAL -> RUNNING -> PAUSED -> RUNNING -> RECONCILIATION_REQUIRED -> RUNNING -> COMPLETED
        self.assertEqual(sm.transition(RunStatus.WAITING_APPROVAL, reason="needs_gate"), RunStatus.WAITING_APPROVAL)
        self.assertEqual(sm.transition(RunStatus.RUNNING, reason="approved"), RunStatus.RUNNING)
        self.assertEqual(sm.transition(RunStatus.PAUSED, reason="checkpoint_pause"), RunStatus.PAUSED)
        self.assertEqual(sm.transition(RunStatus.RUNNING, reason="resumed"), RunStatus.RUNNING)
        self.assertEqual(
            sm.transition(RunStatus.RECONCILIATION_REQUIRED, reason="sigkill_in_flight"),
            RunStatus.RECONCILIATION_REQUIRED,
        )
        self.assertFalse(sm.is_terminal)
        self.assertEqual(sm.transition(RunStatus.RUNNING, reason="reconciled"), RunStatus.RUNNING)
        self.assertEqual(sm.transition(RunStatus.COMPLETED, reason="all_steps_verified"), RunStatus.COMPLETED)
        self.assertTrue(sm.is_terminal)
        self.assertEqual(len(sm.history), 7)

        # Valid recovery-failure lifecycle: RUNNING -> RECONCILIATION_REQUIRED -> FAILED (terminal)
        sm_fail = RunStateMachine("run-state-002", initial_status=RunStatus.RUNNING)
        self.assertEqual(
            sm_fail.transition(RunStatus.RECONCILIATION_REQUIRED, reason="ambiguous_side_effect"),
            RunStatus.RECONCILIATION_REQUIRED,
        )
        self.assertEqual(sm_fail.transition(RunStatus.FAILED, reason="operator_aborted"), RunStatus.FAILED)
        self.assertTrue(sm_fail.is_terminal)

        # Exhaustively verify ALLOWED_TRANSITIONS against all pairs (prev, nxt)
        all_states = list(RunStatus)
        for prev in all_states:
            allowed = ALLOWED_TRANSITIONS[prev]
            for nxt in all_states:
                probe = RunStateMachine("run-probe", initial_status=prev)
                if nxt in allowed:
                    self.assertTrue(probe.can_transition(nxt))
                    self.assertEqual(probe.transition(nxt), nxt)
                else:
                    self.assertFalse(probe.can_transition(nxt))
                    with self.assertRaises(InvalidStateTransitionError):
                        probe.transition(nxt)

        # CheckpointManager enforces RunStateMachine transitions and approval/terminal gates
        ckpt_mgr = CheckpointManager(workspace_root=self.ws)
        ckpt_mgr.create_run("run-gated")
        ckpt_mgr.transition_run("run-gated", RunStatus.WAITING_APPROVAL, reason="manual_review")
        with self.assertRaises(PermissionError):
            ckpt_mgr.resume_step("run-gated", "step-1", "idem-1", lambda: {"ok": True})

        ckpt_mgr.transition_run("run-gated", RunStatus.RUNNING, reason="approved")
        out = ckpt_mgr.resume_step("run-gated", "step-1", "idem-1", lambda: {"ok": True})
        self.assertEqual(out, {"ok": True})
        ckpt_mgr.transition_run("run-gated", RunStatus.COMPLETED, reason="done")

        # Replaying already-committed step on COMPLETED run still returns cached output
        replayed = ckpt_mgr.resume_step("run-gated", "step-1", "idem-1", lambda: self.fail("must not re-run"))
        self.assertEqual(replayed, {"ok": True})

        # Executing an uncommitted step on terminal COMPLETED run is forbidden
        with self.assertRaises(InvalidStateTransitionError):
            ckpt_mgr.resume_step("run-gated", "step-2", "idem-2", lambda: {"should": "fail"})

    # ------------------------------------------------------------------
    # 2. TraceStore: append-only chain, secret redaction, tamper & symlink refusal
    # ------------------------------------------------------------------
    def test_trace_store_chain_redaction_tamper_and_symlink_guards(self) -> None:
        store = TraceStore(workspace_root=self.ws)
        run_id = "run-trace-sec-01"

        sample_a = "".join(("sk", "-", "testSecret", "9876543210abcd"))
        sample_b = "".join(("ghp", "_", "AbCdEf0123456789", "GhIjKlMnOpQr"))
        sample_c = "".join(("a9Z$kL8!", "mP2qR7xT9vB4"))

        ev0 = store.append_event(
            run_id,
            step_id="step-init",
            state="RUNNING",
            tool_id="tool.init",
            input_data={"query": "inspect"},
            output_data={"status": "started"},
            tokens_used=120,
            decision_reason=f"bearer_used={sample_a} from /{'Users'}/alice_dev/repo",
            resource_usage={"api_key": sample_b, "password": sample_c, "tokens_used": 120},
            profile="LOCAL_RESEARCH",
            severity="INFO",
        )
        ev1 = store.append_event(
            run_id,
            step_id="step-verify",
            state="COMPLETED",
            tool_id="tool.verify",
            output_data={"passed": True},
            elapsed_ms=12.5,
            tokens_used=0,
            decision_reason="verified_ok",
            profile="LOCAL_RESEARCH",
            severity="INFO",
        )

        self.assertEqual(ev1.prev_event_hash, ev0.event_hash)
        self.assertEqual(store.list_runs(), [run_id])

        trace_path = store.trace_path_for(run_id)
        self.assertTrue(trace_path.exists())
        self.assertEqual(stat.S_IMODE(trace_path.stat().st_mode), 0o600)

        raw_disk_text = trace_path.read_text(encoding="utf-8")
        self.assertNotIn(sample_a, raw_disk_text)
        self.assertNotIn(sample_b, raw_disk_text)
        self.assertNotIn(sample_c, raw_disk_text)
        self.assertNotIn("alice_dev", raw_disk_text)

        verdict = store.verify_run_chain(run_id)
        self.assertTrue(verdict.valid)
        self.assertEqual(verdict.checked_count, 2)
        self.assertEqual(verdict.head_hash, ev1.event_hash)
        loaded = store.load_events(run_id)
        self.assertEqual(len(loaded), 2)
        self.assertTrue(verify_event_chain(loaded).valid)

        # Tampering 1: Mutate payload field on disk -> detected fail-closed
        lines = raw_disk_text.splitlines()
        row0 = json.loads(lines[0])
        row0["tokens_used"] = 99999
        trace_path.write_text("\n".join([json.dumps(row0), lines[1]]) + "\n", encoding="utf-8")
        bad_verdict = store.verify_run_chain(run_id)
        self.assertFalse(bad_verdict.valid)
        with self.assertRaises(ValueError):
            store.load_events(run_id)
        with self.assertRaises(ValueError):
            store.append_event(run_id, step_id="step-after", state="FAILED")

        # Tampering 2: Recompute forged ev0.event_hash without linking ev1.prev_event_hash
        row0_rehashed = RunEvent(
            run_id=row0["run_id"],
            step_id=row0["step_id"],
            state=row0["state"],
            tool_id=row0["tool_id"],
            input_digest=row0["input_digest"],
            output_digest=row0["output_digest"],
            elapsed_ms=row0["elapsed_ms"],
            tokens_used=99999,
            resource_usage=row0["resource_usage"],
            decision_reason=row0["decision_reason"],
            prev_event_hash=row0["prev_event_hash"],
            event_id=row0["event_id"],
            seq=row0["seq"],
            timestamp=row0["timestamp"],
            profile=row0["profile"],
            severity=row0["severity"],
        )
        trace_path.write_text(
            "\n".join([row0_rehashed.to_canonical_json(), lines[1]]) + "\n", encoding="utf-8"
        )
        broken_link = store.verify_run_chain(run_id)
        self.assertFalse(broken_link.valid)
        self.assertTrue(any("PREV_EVENT_HASH_MISMATCH" in r for r in broken_link.reasons))

        # Tampering 3: Cross-run file substitution detected
        store.append_event("run-legit-a", step_id="s0", state="RUNNING")
        sub_path = store.trace_path_for("run-legit-b")
        sub_path.write_text(store.trace_path_for("run-legit-a").read_text(encoding="utf-8"), encoding="utf-8")
        sub_verdict = store.verify_run_chain("run-legit-b")
        self.assertFalse(sub_verdict.valid)
        self.assertTrue(any("RUN_ID_MISMATCH" in r for r in sub_verdict.reasons))

        # Symlink attack refused on both TraceStore and CheckpointManager
        evil_ext = self.external / "evil_trace.jsonl"
        evil_ext.write_text("", encoding="utf-8")
        sym_trace = store.base_dir / "sym-run.jsonl"
        os.symlink(str(evil_ext), str(sym_trace))
        with self.assertRaises(PermissionError):
            store.verify_run_chain("sym-run")
        with self.assertRaises(PermissionError):
            store.append_event("sym-run", step_id="s1", state="RUNNING")

        ckpt_mgr = CheckpointManager(workspace_root=self.ws)
        ckpt_mgr.base_dir.mkdir(parents=True, exist_ok=True)
        sym_ckpt = ckpt_mgr.base_dir / "sym-ckpt.json"
        os.symlink(str(self.external / "evil_ckpt.json"), str(sym_ckpt))
        with self.assertRaises(PermissionError):
            ckpt_mgr.load_checkpoint("sym-ckpt")

    # ------------------------------------------------------------------
    # 3. 120+ Simulated Kill/Restart Tests across Multi-Step DAGs
    # ------------------------------------------------------------------
    def test_120_simulated_kill_restart_cycles_at_most_once_side_effects_and_clean_parity(self) -> None:
        """
        Run 120 simulated crash/kill & restart cycles across a 6-step multi-branch DAG
        with non-idempotent side-effect steps. Assert every side-effect executes
        AT MOST ONCE across crashes, re-runs, and idempotency-key replays, and that
        final outputs match clean execution 100%.
        """
        dag_order = ["extract", "enrich_a", "enrich_b", "merge", "side_effect_charge", "side_effect_emit"]
        side_effect_steps = {"enrich_b", "side_effect_charge", "side_effect_emit"}

        def execute_dag_cycle(
            run_id: str,
            *,
            ckpt_dir: Path,
            traces_dir: Path,
            counters: Dict[str, int],
            side_effect_journal: List[str],
            crash_plan: Dict[str, str],
            pending_reconciliations: Set[str],
            reconciliation_stats: Dict[str, int],
        ) -> Dict[str, Any]:
            trace_store = TraceStore(traces_dir)
            ckpt_mgr = CheckpointManager(ckpt_dir, trace_store=trace_store)
            if ckpt_mgr.load_checkpoint(run_id) is None:
                ckpt_mgr.create_run(run_id)
            elif ckpt_mgr.get_status(run_id) == RunStatus.PAUSED:
                ckpt_mgr.transition_run(run_id, RunStatus.RUNNING, reason="restart")

            outputs: Dict[str, Any] = {}

            def run_step_with_crash(step_id: str, idem_key: str, fn: Any) -> Any:
                crash_mode = crash_plan.pop(step_id, "")
                if crash_mode == "before_step":
                    raise _SimulatedProcessKill(f"killed_before:{step_id}")

                def _wrapped() -> Any:
                    if crash_mode == "inside_before_effect":
                        if step_id in side_effect_steps:
                            pending_reconciliations.add(step_id)
                        raise _SimulatedProcessKill(f"killed_inside_before_effect:{step_id}")
                    return fn()

                is_se = step_id in side_effect_steps
                try:
                    val = ckpt_mgr.resume_step(
                        run_id,
                        step_id,
                        idem_key,
                        _wrapped,
                        is_side_effect=is_se,
                        side_effect_metadata={"dag_step": step_id},
                    )
                except ReconciliationRequiredError as rec_err:
                    self.assertIn(
                        step_id,
                        pending_reconciliations,
                        f"Unexpected ReconciliationRequiredError on {step_id}",
                    )
                    self.assertEqual(rec_err.run_id, run_id)
                    self.assertEqual(rec_err.step_id, step_id)
                    self.assertEqual(rec_err.idempotency_key, idem_key)
                    self.assertIsNotNone(rec_err.in_flight_record)
                    self.assertEqual(ckpt_mgr.get_status(run_id), RunStatus.RECONCILIATION_REQUIRED)

                    ckpt_mgr.reconcile_step(
                        run_id,
                        step_id,
                        idem_key,
                        outcome="NOT_EXECUTED",
                        reason="verified_before_effect",
                    )
                    self.assertEqual(ckpt_mgr.get_status(run_id), RunStatus.RUNNING)
                    pending_reconciliations.remove(step_id)
                    reconciliation_stats["count"] += 1

                    val = ckpt_mgr.resume_step(
                        run_id,
                        step_id,
                        idem_key,
                        _wrapped,
                        is_side_effect=is_se,
                        side_effect_metadata={"dag_step": step_id},
                    )

                self.assertNotIn(
                    step_id,
                    pending_reconciliations,
                    f"Step {step_id} did not raise ReconciliationRequiredError before retry",
                )
                if crash_mode == "after_commit":
                    raise _SimulatedProcessKill(f"killed_after_commit:{step_id}")
                return val

            outputs["extract"] = run_step_with_crash(
                "extract",
                f"{run_id}:idem:extract",
                lambda: {"items": [3, 1, 4, 1, 5], "source": "local_seed"},
            )
            outputs["enrich_a"] = run_step_with_crash(
                "enrich_a",
                f"{run_id}:idem:enrich_a",
                lambda: {"sum": sum(outputs["extract"]["items"]), "count": len(outputs["extract"]["items"])},
            )

            def _side_effect_enrich_b() -> Dict[str, Any]:
                counters["enrich_b"] += 1
                side_effect_journal.append(f"{run_id}:enrich_b")
                return {"max_item": max(outputs["extract"]["items"]), "tag": "verified_b"}

            outputs["enrich_b"] = run_step_with_crash(
                "enrich_b", f"{run_id}:idem:enrich_b", _side_effect_enrich_b
            )
            outputs["merge"] = run_step_with_crash(
                "merge",
                f"{run_id}:idem:merge",
                lambda: {
                    "total": outputs["enrich_a"]["sum"],
                    "count": outputs["enrich_a"]["count"],
                    "peak": outputs["enrich_b"]["max_item"],
                    "digest": sha256_digest({"a": outputs["enrich_a"], "b": outputs["enrich_b"]}),
                },
            )

            def _side_effect_charge() -> Dict[str, Any]:
                counters["side_effect_charge"] += 1
                side_effect_journal.append(f"{run_id}:charge")
                return {
                    "tx_ref": f"tx-{outputs['merge']['digest'].split(':', 1)[1][:12]}",
                    "amount_units": outputs["merge"]["total"] * 10,
                }

            outputs["side_effect_charge"] = run_step_with_crash(
                "side_effect_charge", f"{run_id}:idem:charge", _side_effect_charge
            )

            def _side_effect_emit() -> Dict[str, Any]:
                counters["side_effect_emit"] += 1
                side_effect_journal.append(f"{run_id}:emit")
                return {
                    "receipt_hash": sha256_digest(outputs["side_effect_charge"]),
                    "final_score": outputs["merge"]["total"] + outputs["merge"]["peak"],
                }

            outputs["side_effect_emit"] = run_step_with_crash(
                "side_effect_emit", f"{run_id}:idem:emit", _side_effect_emit
            )

            # Verify matching idempotency_key under a different step_id ALSO skips re-execution
            replay_same_key = ckpt_mgr.resume_step(
                run_id,
                "side_effect_charge_alias",
                f"{run_id}:idem:charge",
                lambda: (_ for _ in ()).throw(AssertionError("idempotency_key replay re-executed runner_fn!")),
            )
            self.assertEqual(replay_same_key, outputs["side_effect_charge"])

            ckpt_mgr.transition_run(run_id, RunStatus.COMPLETED, reason="dag_verified")
            return outputs

        # Clean baseline execution
        clean_counters = {s: 0 for s in side_effect_steps}
        clean_journal: List[str] = []
        clean_ckpt_dir = self.ws / "clean_checkpoints"
        clean_trace_dir = self.ws / "clean_traces"
        clean_outputs = execute_dag_cycle(
            "run-clean-ref",
            ckpt_dir=clean_ckpt_dir,
            traces_dir=clean_trace_dir,
            counters=clean_counters,
            side_effect_journal=clean_journal,
            crash_plan={},
            pending_reconciliations=set(),
            reconciliation_stats={"count": 0},
        )
        self.assertTrue(all(v == 1 for v in clean_counters.values()))

        # 120 simulated crash/restart runs with random multi-point kills
        rng = random.Random(20261121)
        crash_modes = ("before_step", "inside_before_effect", "after_commit")
        total_cycles = 120
        ckpt_dir = self.ws / ".kintsugi" / "run_checkpoints"
        trace_dir = self.ws / ".kintsugi" / "run_traces"
        reconciliation_stats = {"count": 0}

        for trial in range(total_cycles):
            run_id = f"run-crash-{trial:03d}"
            counters = {s: 0 for s in side_effect_steps}
            journal: List[str] = []
            pending_reconciliations: Set[str] = set()

            # Pick 1 to 3 random crash points across the 6 DAG steps for this run
            num_crashes = rng.randint(1, 3)
            chosen_steps = rng.sample(dag_order, k=num_crashes)
            crash_plan = {step: rng.choice(crash_modes) for step in chosen_steps}

            crashes_observed = 0
            final_outputs = None
            for _attempt in range(len(dag_order) * 2 + 4):
                try:
                    final_outputs = execute_dag_cycle(
                        run_id,
                        ckpt_dir=ckpt_dir,
                        traces_dir=trace_dir,
                        counters=counters,
                        side_effect_journal=journal,
                        crash_plan=crash_plan,
                        pending_reconciliations=pending_reconciliations,
                        reconciliation_stats=reconciliation_stats,
                    )
                    break
                except _SimulatedProcessKill:
                    crashes_observed += 1
                    # At every intermediate crash point, no side effect may have executed > 1 time
                    for s_name, count in counters.items():
                        self.assertLessEqual(
                            count,
                            1,
                            f"Side effect {s_name} ran {count} times during trial {trial}",
                        )

            self.assertGreaterEqual(crashes_observed, 1)
            self.assertEqual(len(pending_reconciliations), 0)
            self.assertIsNotNone(final_outputs, f"Trial {trial} did not finish after resume")
            self.assertEqual(final_outputs, clean_outputs, f"Trial {trial} diverged from clean replay")
            for s_name in side_effect_steps:
                self.assertEqual(counters[s_name], 1, f"Trial {trial} step {s_name} count={counters[s_name]}")
            self.assertEqual(len(journal), len(side_effect_steps))

            # Verify persisted checkpoint & trace chain integrity + 0o600 permissions
            restarted_ckpt_mgr = CheckpointManager(ckpt_dir)
            persisted = restarted_ckpt_mgr.load_checkpoint(run_id)
            self.assertIsNotNone(persisted)
            assert persisted is not None
            self.assertEqual(persisted["status"], RunStatus.COMPLETED.value)
            self.assertEqual(persisted["completed_step_ids"], dag_order)
            self.assertEqual(persisted["in_flight_steps"], {})
            self.assertEqual(len(persisted["side_effects_committed"]), len(side_effect_steps))
            self.assertEqual(stat.S_IMODE(restarted_ckpt_mgr.checkpoint_path(run_id).stat().st_mode), 0o600)

            restarted_traces = TraceStore(trace_dir)
            chain_res = restarted_traces.verify_run_chain(run_id)
            self.assertTrue(chain_res.valid, f"Trial {trial} invalid trace chain: {chain_res.reasons}")

        self.assertGreater(reconciliation_stats["count"], 0)

        # Verify CheckpointManager fails closed if checkpoint JSON on disk is tampered
        sample_ckpt_path = CheckpointManager(ckpt_dir).checkpoint_path("run-crash-000")
        tampered = json.loads(sample_ckpt_path.read_text(encoding="utf-8"))
        tampered["completed_outputs"]["merge"]["total"] = 999999
        sample_ckpt_path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(ValueError):
            CheckpointManager(ckpt_dir).load_checkpoint("run-crash-000")

    # ------------------------------------------------------------------
    # 3b. Real SIGKILL (-9) between side effect and commit + backward compat
    # ------------------------------------------------------------------
    def test_real_sigkill_between_side_effect_and_commit_prevents_double_execution(self) -> None:
        run_id = "run-sigkill-poc-01"
        counter_path = self.ws / "external_counter.txt"
        counter_path.write_text("0", encoding="utf-8")

        child_script = "\n".join(
            [
                "import os, sys, time",
                "from pathlib import Path",
                "from kintsugi.runtime.run_state import CheckpointManager",
                "from kintsugi.runtime.trace_store import TraceStore",
                "ws = Path(sys.argv[1])",
                "counter_file = Path(sys.argv[2])",
                "run_id = sys.argv[3]",
                "trace_store = TraceStore(workspace_root=ws)",
                "ckpt_mgr = CheckpointManager(workspace_root=ws, trace_store=trace_store)",
                "ckpt_mgr.create_run(run_id)",
                "def _side_effect():",
                "    cur = int(counter_file.read_text(encoding='utf-8').strip())",
                "    nxt = cur + 1",
                "    tmp = counter_file.with_suffix('.tmp')",
                "    tmp.write_text(str(nxt), encoding='utf-8')",
                "    os.replace(str(tmp), str(counter_file))",
                "    print('EFFECT_COMMITTED_EXTERNALLY', flush=True)",
                "    time.sleep(30)",
                "    return {'counter': nxt}",
                "ckpt_mgr.resume_step(run_id, 'charge', 'idem-sigkill-1', _side_effect, is_side_effect=True)",
            ]
        )

        src_dir = str(Path(__file__).resolve().parents[2] / "src")
        env = os.environ.copy()
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{src_dir}{os.pathsep}{existing_pp}" if existing_pp else src_dir

        proc = subprocess.Popen(
            [sys.executable, "-c", child_script, str(self.ws), str(counter_path), run_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            assert proc.stdout is not None
            line = proc.stdout.readline().strip()
            self.assertEqual(line, "EFFECT_COMMITTED_EXTERNALLY")
            os.kill(proc.pid, signal.SIGKILL)
            exit_code = proc.wait(timeout=5)
            self.assertEqual(exit_code, -signal.SIGKILL)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()

        self.assertEqual(counter_path.read_text(encoding="utf-8").strip(), "1")

        # Fresh CheckpointManager sees in-flight WAL and MUST refuse auto-re-execution
        fresh_traces = TraceStore(workspace_root=self.ws)
        fresh_ckpt = CheckpointManager(workspace_root=self.ws, trace_store=fresh_traces)

        def _must_not_run() -> Dict[str, Any]:
            cur = int(counter_path.read_text(encoding="utf-8").strip())
            counter_path.write_text(str(cur + 1), encoding="utf-8")
            return {"counter": cur + 1}

        with self.assertRaises(ReconciliationRequiredError) as err_ctx:
            fresh_ckpt.resume_step(
                run_id,
                "charge",
                "idem-sigkill-1",
                _must_not_run,
                is_side_effect=True,
            )

        self.assertEqual(err_ctx.exception.run_id, run_id)
        self.assertEqual(err_ctx.exception.step_id, "charge")
        self.assertEqual(err_ctx.exception.idempotency_key, "idem-sigkill-1")
        self.assertIsNotNone(err_ctx.exception.in_flight_record)
        self.assertEqual(fresh_ckpt.get_status(run_id), RunStatus.RECONCILIATION_REQUIRED)
        self.assertEqual(counter_path.read_text(encoding="utf-8").strip(), "1")

        # Unrelated new steps are also blocked while run awaits reconciliation
        with self.assertRaises(ReconciliationRequiredError):
            fresh_ckpt.resume_step(run_id, "other-step", "idem-other", lambda: {"x": 1}, is_side_effect=False)

        # Operator inspects external counter == 1 and reconciles as COMMITTED
        external_count = int(counter_path.read_text(encoding="utf-8").strip())
        self.assertEqual(external_count, 1)
        reconciled_ckpt = fresh_ckpt.reconcile_step(
            run_id,
            "charge",
            "idem-sigkill-1",
            outcome="COMMITTED",
            reconciled_output={"counter": external_count},
            reason="external_counter_confirmed",
        )
        self.assertEqual(reconciled_ckpt["in_flight_steps"], {})
        self.assertEqual(fresh_ckpt.get_status(run_id), RunStatus.RUNNING)

        # Replaying resume_step returns cached reconciled output without double execution
        replayed = fresh_ckpt.resume_step(
            run_id,
            "charge",
            "idem-sigkill-1",
            _must_not_run,
            is_side_effect=True,
        )
        self.assertEqual(replayed, {"counter": 1})
        self.assertEqual(counter_path.read_text(encoding="utf-8").strip(), "1")
        self.assertEqual(stat.S_IMODE(fresh_ckpt.checkpoint_path(run_id).stat().st_mode), 0o600)

        chain_res = fresh_traces.verify_run_chain(run_id)
        self.assertTrue(chain_res.valid, f"Invalid trace chain after SIGKILL recovery: {chain_res.reasons}")

    def test_backward_compatible_checkpoint_loading_and_reconcile_validation(self) -> None:
        ckpt_mgr = CheckpointManager(workspace_root=self.ws)
        legacy_run_id = "run-legacy-no-inflight"
        legacy_payload: Dict[str, Any] = {
            "schema": CHECKPOINT_SCHEMA_VERSION,
            "run_id": legacy_run_id,
            "status": RunStatus.RUNNING.value,
            "completed_step_ids": ["s0"],
            "idempotency_keys": {"k0": "s0"},
            "completed_outputs": {"s0": {"ok": True}},
            "idempotency_outputs": {"k0": {"ok": True}},
            "side_effects_committed": {},
            "transition_history": [],
            "metadata": {},
            "updated_at": "2026-11-21T00:00:00Z",
        }
        legacy_payload["checkpoint_digest"] = _compute_checkpoint_digest(legacy_payload)
        ckpt_mgr.base_dir.mkdir(parents=True, exist_ok=True)
        ckpt_mgr.checkpoint_path(legacy_run_id).write_text(json.dumps(legacy_payload), encoding="utf-8")

        loaded = ckpt_mgr.load_checkpoint(legacy_run_id)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded["in_flight_steps"], {})
        self.assertEqual(
            ckpt_mgr.resume_step(legacy_run_id, "s0", "k0", lambda: self.fail("must use cached legacy output")),
            {"ok": True},
        )

        # Validation errors on reconcile_step
        with self.assertRaises(ValueError):
            ckpt_mgr.reconcile_step(legacy_run_id, "s1", "k1", outcome="INVALID_CHOICE")
        with self.assertRaises(ValueError):
            ckpt_mgr.reconcile_step(legacy_run_id, "s1", "k1", outcome="NOT_EXECUTED")
        with self.assertRaises(ValueError):
            ckpt_mgr.reconcile_step("run-does-not-exist", "s1", "k1", outcome="NOT_EXECUTED")

    # ------------------------------------------------------------------
    # 4. TokenEconomicsTracker: 9 metrics, GITHUB_PUBLIC caps vs LOCAL_RESEARCH
    # ------------------------------------------------------------------
    def test_token_economics_9_metrics_and_profile_policies(self) -> None:
        # GITHUB_PUBLIC enforces token_budget, max_tool_probes, max_runtime_seconds
        gh_cfg = KintsugiConfig(
            profile=OperatingProfile.GITHUB_PUBLIC,
            github_public=GithubPublicConfig(
                token_budget=1000,
                max_tool_probes=3,
                max_runtime_seconds=2,
                max_parallel_agents=2,
            ),
        )
        t_tok = TokenEconomicsTracker(gh_cfg, run_id="run-gh-tokens")
        t_tok.record_llm_call(input_tokens=400, output_tokens=300)
        t_tok.record_search_node(4)
        snap = t_tok.snapshot()
        snap_dict = snap.to_dict()
        for metric_name in REQUIRED_STAGE4_METRICS:
            self.assertIn(metric_name, snap_dict)
        self.assertEqual(snap.llm_calls, 1)
        self.assertEqual(snap.input_tokens, 400)
        self.assertEqual(snap.output_tokens, 300)
        self.assertEqual(snap.search_nodes, 4)
        self.assertGreaterEqual(snap.wall_time_ms, 0.0)
        self.assertGreaterEqual(snap.cpu_time_ms, 0.0)
        self.assertGreater(snap.peak_memory_mb, 0.0)

        with self.assertRaises(BudgetExceededError) as ctx_tok:
            t_tok.record_llm_call(input_tokens=200, output_tokens=200)  # 700 + 400 = 1100 > 1000
        self.assertEqual(ctx_tok.exception.metric, "token_budget")
        self.assertTrue(t_tok.snapshot().halted_by_policy)

        # max_tool_probes enforcement
        t_probe = TokenEconomicsTracker(gh_cfg, run_id="run-gh-probes")
        for _ in range(3):
            t_probe.record_tool_probe(1)
        with self.assertRaises(BudgetExceededError) as ctx_probe:
            t_probe.record_tool_probe(1)
        self.assertEqual(ctx_probe.exception.metric, "max_tool_probes")
        ok, reason = t_probe.try_check_limits(additional_probes=1)
        self.assertFalse(ok)
        self.assertIn("MAX_TOOL_PROBES", reason)

        # max_runtime_seconds enforcement
        t_time = TokenEconomicsTracker(gh_cfg, run_id="run-gh-time")
        with self.assertRaises(BudgetExceededError) as ctx_time:
            t_time.record_timing(wall_time_ms=2500.0)
        self.assertEqual(ctx_time.exception.metric, "max_runtime_seconds")

        # LOCAL_RESEARCH NEVER imposes artificial token/iteration/probe caps
        lr_cfg = KintsugiConfig.for_profile(OperatingProfile.LOCAL_RESEARCH)
        t_lr = TokenEconomicsTracker(lr_cfg, run_id="run-local-unconstrained")
        t_lr.record_llm_call(input_tokens=2_000_000, output_tokens=1_000_000, calls=50)
        t_lr.record_tool_probe(1000)
        t_lr.record_search_node(25000)
        t_lr.record_timing(wall_time_ms=10_000_000.0)
        lr_snap = t_lr.snapshot()
        self.assertFalse(lr_snap.halted_by_policy)
        self.assertEqual(lr_snap.total_tokens, 3_000_000)
        self.assertEqual(lr_snap.tool_probes, 1000)
        self.assertEqual(lr_snap.search_nodes, 25000)

        # Deterministic-first / memory-first savings & early_stop_on_verified_pass
        t_save = TokenEconomicsTracker(lr_cfg, run_id="run-det-first", early_stop_on_verified_pass=True)
        t_save.record_deterministic_solve(3, tokens_saved_estimate=4500)
        t_save.record_memory_hit(1, tokens_saved_estimate=1500)
        stopped = t_save.record_verified_outcome("PASS", deterministic=True)
        self.assertTrue(stopped)
        self.assertTrue(t_save.should_stop_early)
        save_snap = t_save.snapshot()
        self.assertEqual(save_snap.local_solve_rate, 1.0)
        self.assertEqual(save_snap.tokens_saved_estimate, 6000)
        self.assertTrue(save_snap.early_stopped)
        self.assertTrue(save_snap.is_verified_pass)

        # Mixed run (4 local + 1 LLM = 0.80 local_solve_rate)
        t_save.record_llm_call(input_tokens=100, output_tokens=50, calls=1)
        self.assertAlmostEqual(t_save.local_solve_rate, 0.8, places=4)

    # ------------------------------------------------------------------
    # 5. AdaptiveResourceScheduler: CPU/mem scaling, watchdog, cancellation, early stop
    # ------------------------------------------------------------------
    def test_adaptive_scheduler_concurrency_watchdog_cancellation_and_early_stop(self) -> None:
        lr_cfg = KintsugiConfig.for_profile(OperatingProfile.LOCAL_RESEARCH)
        gh_cfg = KintsugiConfig(
            profile=OperatingProfile.GITHUB_PUBLIC,
            github_public=GithubPublicConfig(max_parallel_agents=2, max_runtime_seconds=5),
        )

        # Calibrated to os.cpu_count() and memory pressure
        sched_low_mem = AdaptiveResourceScheduler(
            lr_cfg,
            cpu_count_fn=lambda: 8,
            memory_probe_fn=lambda: 0.25,
        )
        self.assertEqual(sched_low_mem.recommended_workers(), 8)

        sched_high_mem = AdaptiveResourceScheduler(
            lr_cfg,
            cpu_count_fn=lambda: 8,
            memory_probe_fn=lambda: 0.80,
        )
        self.assertEqual(sched_high_mem.recommended_workers(), 4)

        sched_crit_mem = AdaptiveResourceScheduler(
            lr_cfg,
            cpu_count_fn=lambda: 8,
            memory_probe_fn=lambda: 0.95,
        )
        self.assertEqual(sched_crit_mem.recommended_workers(), 1)

        sched_gh = AdaptiveResourceScheduler(
            gh_cfg,
            cpu_count_fn=lambda: 16,
            memory_probe_fn=lambda: 0.10,
        )
        self.assertEqual(sched_gh.recommended_workers(), 2)

        # Watchdog timeout cancels cooperative CancellationToken and raises WatchdogTimeoutError
        with self.assertRaises(WatchdogTimeoutError):
            sched_low_mem.run_with_watchdog(
                lambda tok: (tok.wait(1.0), tok.raise_if_cancelled()),
                timeout_seconds=0.03,
            )

        # Explicit cooperative cancellation stops pending queued tasks cleanly
        manual_token = CancellationToken()
        executed: List[int] = []

        def _cancelling_task(idx: int, tok: CancellationToken) -> int:
            if idx == 0:
                executed.append(idx)
                manual_token.cancel("owner_abort")
                return idx
            tok.wait(0.2)
            tok.raise_if_cancelled()
            executed.append(idx)
            return idx

        sched_seq = AdaptiveResourceScheduler(lr_cfg, max_workers=1)
        cancel_res = sched_seq.run_tasks(
            [lambda tok, i=i: _cancelling_task(i, tok) for i in range(6)],
            token=manual_token,
        )
        self.assertTrue(cancel_res["cancelled"])
        self.assertEqual(cancel_res["halt_reason"], "owner_abort")
        self.assertEqual(executed, [0])

        # Early stop when deterministic PASS verified prevents downstream LLM fallback tasks
        tracker = TokenEconomicsTracker(lr_cfg, run_id="run-early-exit", early_stop_on_verified_pass=True)
        llm_executed = 0

        def _det_task() -> Dict[str, Any]:
            tracker.record_deterministic_solve(1, tokens_saved_estimate=2000)
            return {"verified_outcome": "PASS", "deterministic": True}

        def _expensive_llm_fallback() -> Dict[str, Any]:
            nonlocal llm_executed
            llm_executed += 1
            tracker.record_llm_call(500, 500)
            return {"verified_outcome": "PASS"}

        early_res = sched_seq.run_tasks(
            [_det_task, _expensive_llm_fallback, _expensive_llm_fallback],
            tracker=tracker,
            early_stop_on_verified_pass=True,
        )
        self.assertTrue(early_res["stopped_early"])
        self.assertEqual(llm_executed, 0)
        self.assertEqual(tracker.snapshot().llm_calls, 0)
        self.assertTrue(tracker.snapshot().is_verified_pass)
        self.assertEqual(tracker.snapshot().local_solve_rate, 1.0)


if __name__ == "__main__":
    unittest.main()
