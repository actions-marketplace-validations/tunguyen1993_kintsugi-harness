"""Stage 5 Verification Suite for Causal Counterfactual & Adaptive Token Economics Engine v4."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List

from kintsugi.evolution.evolution_v4 import (
    AdaptiveBudgetController,
    CausalAblationResult,
    CorpusLeakageError,
    EvolutionEngineV4,
    ExecutionMode,
    ImmutableGuardrailError,
    MatchedTaskTrial,
    MonotonicPromotionLedger,
    PromotionGateError,
    StrategyStage,
    VerificationSlice,
    verify_disjoint_families,
)
from kintsugi.runtime.token_economics import BudgetExceededError


def _make_trials(
    families: List[str],
    count: int,
    *,
    with_passes: int,
    without_passes: int = 0,
    with_fp: int = 0,
) -> List[MatchedTaskTrial]:
    """Build `count` matched counterfactual trials across `families` with deterministic outcomes."""
    trials: List[MatchedTaskTrial] = []
    for idx in range(count):
        fam = families[idx % len(families)]
        w_pass = idx < with_passes
        wo_pass = idx < without_passes
        # Avoid creating artificial baseline regressions when testing pure recall gains
        if wo_pass and not w_pass:
            w_pass = True
        fp_val = 1 if idx < with_fp else 0
        trials.append(
            MatchedTaskTrial(
                family_id=fam,
                task_id=f"{fam}-task-{idx}",
                with_passed=w_pass,
                without_passed=wo_pass,
                with_fp=fp_val,
                without_fp=0,
                tokens_used=50,
                latency_ms=Decimal("2.5"),
            )
        )
    return trials


class TestEvolutionV4(unittest.TestCase):
    """Verify CausalAblationResult, AdaptiveBudgetController, MonotonicPromotionLedger & Guardrails."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_evo4_")
        self.root = Path(self._tmp.name)
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.train_families = ["train_yaml_loader", "train_subprocess_shell"]
        self.heldout_families = ["heldout_tls_verify", "heldout_jwt_sig", "heldout_tar_extract", "heldout_xml_xxe"]

    def tearDown(self) -> None:
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # 1. Causal Counterfactual Ablation & Exact Wilson Ranking (2/2 vs 19/20)
    # ------------------------------------------------------------------
    def test_causal_ablation_rejects_noisy_2_of_2_in_favor_of_19_of_20(self) -> None:
        spurious_trials = _make_trials(self.heldout_families[:2], 2, with_passes=2, without_passes=0)
        proven_trials = _make_trials(self.heldout_families, 20, with_passes=19, without_passes=0)

        spurious = CausalAblationResult.from_trials(
            strategy_id="strat_spurious_2_of_2",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=spurious_trials,
            z_score=1.96,
            min_sample_size=5,
            min_wilson_lb=0.50,
        )
        proven = CausalAblationResult.from_trials(
            strategy_id="strat_proven_19_of_20",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=proven_trials,
            z_score=1.96,
            min_sample_size=5,
            min_wilson_lb=0.50,
        )

        # Raw empirical rate looks higher on 2/2 (1.00) than 19/20 (0.95),
        # but exact Wilson lower bound (z=1.96) strictly exposes tiny-N variance.
        self.assertEqual(spurious.raw_uplift, Decimal("1.000000"))
        self.assertEqual(proven.raw_uplift, Decimal("0.950000"))
        self.assertTrue(spurious.disjoint_verified)
        self.assertTrue(proven.disjoint_verified)

        self.assertLess(spurious.with_wilson_lb, 0.35)
        self.assertGreater(proven.with_wilson_lb, 0.76)
        self.assertGreater(proven.uplift_wilson_lb, spurious.uplift_wilson_lb)

        self.assertFalse(spurious.passed)
        self.assertTrue(any("LOW_WILSON_LOWER_BOUND" in r for r in spurious.rejection_reasons))
        self.assertTrue(any("INSUFFICIENT_SAMPLE_SIZE" in r for r in spurious.rejection_reasons))
        self.assertTrue(proven.passed)
        self.assertEqual(proven.rejection_reasons, ())

        # Even if min_sample_size=1 and min_wilson_lb=0.0, ranking strictly prefers 19/20
        spurious_relaxed = CausalAblationResult.from_trials(
            strategy_id="strat_spurious_2_of_2_relaxed",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=spurious_trials,
            min_sample_size=1,
            min_wilson_lb=0.0,
        )
        ranked = EvolutionEngineV4.rank_ablations([spurious, spurious_relaxed, proven])
        self.assertEqual(ranked[0].strategy_id, "strat_proven_19_of_20")
        best = EvolutionEngineV4.select_best_ablation([spurious, proven])
        self.assertIsNotNone(best)
        assert best is not None
        self.assertEqual(best.strategy_id, "strat_proven_19_of_20")

    # ------------------------------------------------------------------
    # 2. Leakage Guard: Train / Heldout Disjointness Enforcement
    # ------------------------------------------------------------------
    def test_leakage_guard_rejects_overlapping_train_and_heldout_families(self) -> None:
        with self.assertRaises(ValueError) as ctx1:
            verify_disjoint_families(
                ["fam_a", "fam_b"],
                ["fam_b", "fam_c"],
            )
        self.assertIsInstance(ctx1.exception, CorpusLeakageError)

        # Case-insensitive family collision
        with self.assertRaises(ValueError):
            verify_disjoint_families(["Fam_Alpha"], ["fam_alpha"])

        # Snippet / task_id overlap across distinct family IDs
        with self.assertRaises(ValueError):
            verify_disjoint_families(
                [{"family_id": "train_1", "task_id": "shared_task_id", "code": "x = 1"}],
                [{"family_id": "held_1", "task_id": "shared_task_id", "code": "y = 2"}],
            )
        with self.assertRaises(ValueError):
            verify_disjoint_families(
                [{"family_id": "train_1", "positives": ["cfg = yaml.load(raw, Loader=yaml.Loader)"]}],
                [{"family_id": "held_1", "positives": ["cfg = yaml.load(raw, Loader=yaml.Loader)"]}],
            )

        # Trial leaking a training family into heldout ablation
        leaked_trial = MatchedTaskTrial(
            family_id="train_yaml_loader",
            task_id="leak-1",
            with_passed=True,
            without_passed=False,
        )
        with self.assertRaises(ValueError):
            CausalAblationResult.from_trials(
                strategy_id="strat_leaky",
                train_families=self.train_families,
                heldout_families=self.heldout_families,
                trials=[leaked_trial],
            )

        # Direct instantiation with disjoint_verified=False fails closed
        with self.assertRaises(ValueError):
            CausalAblationResult(
                strategy_id="strat_unverified_split",
                revision=1,
                train_families=("train_a",),
                heldout_families=("held_b",),
                disjoint_verified=False,
                heldout_verified=True,
                total_matched=10,
                with_successes=10,
                without_successes=0,
                with_success_rate=Decimal("1"),
                without_success_rate=Decimal("0"),
                raw_uplift=Decimal("1"),
                with_wilson_lb=0.72246,
                with_wilson_ub=1.0,
                without_wilson_lb=0.0,
                without_wilson_ub=0.27754,
                wilson_lb_delta=0.72246,
                uplift_wilson_lb=0.44492,
                improved_count=10,
                regressed_count=0,
                false_positives_with=0,
                false_positives_without=0,
                false_positive_delta=0,
                baseline_regressions=0,
            )

    # ------------------------------------------------------------------
    # 3. AdaptiveBudgetController: LOCAL_RESEARCH vs GITHUB_PUBLIC Fail-Closed
    # ------------------------------------------------------------------
    def test_adaptive_budget_controller_local_research_vs_github_public_fail_closed(self) -> None:
        local_ctrl = AdaptiveBudgetController(
            ExecutionMode.LOCAL_RESEARCH,
            base_exploration_rounds=3,
            max_exploration_rounds=12,
            base_hypotheses_per_round=4,
            max_hypotheses_per_round=16,
            variance_threshold=Decimal("0.15"),
        )
        low_plan = local_ctrl.plan_exploration(Decimal("0.05"))
        high_plan = local_ctrl.plan_exploration(Decimal("0.45"))

        self.assertEqual(low_plan.mode, ExecutionMode.LOCAL_RESEARCH)
        self.assertFalse(low_plan.scaled_for_variance)
        self.assertFalse(low_plan.hard_capped)
        self.assertEqual(low_plan.exploration_rounds, 3)
        self.assertEqual(low_plan.hypotheses_per_round, 4)

        self.assertTrue(high_plan.scaled_for_variance)
        self.assertFalse(high_plan.hard_capped)
        self.assertEqual(high_plan.scale_factor, Decimal("3.00"))
        self.assertEqual(high_plan.exploration_rounds, 9)
        self.assertEqual(high_plan.hypotheses_per_round, 12)

        # LOCAL_RESEARCH allows high-throughput exploration consumption without artificial public cap
        for _ in range(10):
            local_ctrl.consume(tokens=5000, steps=1, latency_ms=Decimal("12.5"))
        self.assertEqual(local_ctrl.tokens_used, 50000)
        self.assertEqual(local_ctrl.steps_used, 10)
        self.assertFalse(local_ctrl.halted)

        # GITHUB_PUBLIC refuses variance-based upward scaling & enforces strict caps fail-closed
        pub_tok_ctrl = AdaptiveBudgetController(
            ExecutionMode.GITHUB_PUBLIC,
            token_budget=1000,
            max_steps=10,
            max_latency_ms=Decimal("500"),
        )
        pub_plan = pub_tok_ctrl.plan_exploration(Decimal("0.45"))
        self.assertEqual(pub_plan.mode, ExecutionMode.GITHUB_PUBLIC)
        self.assertFalse(pub_plan.scaled_for_variance)
        self.assertTrue(pub_plan.hard_capped)
        self.assertEqual(pub_plan.scale_factor, Decimal("1"))
        self.assertEqual(pub_plan.exploration_rounds, 1)
        self.assertEqual(pub_plan.hypotheses_per_round, 2)

        pub_tok_ctrl.consume(tokens=600, steps=1, latency_ms=Decimal("10.25"))
        with self.assertRaises(BudgetExceededError) as tok_err:
            pub_tok_ctrl.consume(tokens=401, steps=1, latency_ms=Decimal("5.00"))
        self.assertEqual(tok_err.exception.metric, "token_budget")
        self.assertEqual(pub_tok_ctrl.tokens_used, 600)
        self.assertTrue(pub_tok_ctrl.halted)

        # Strict step budget fail-closed enforcement
        pub_step_ctrl = AdaptiveBudgetController(
            ExecutionMode.GITHUB_PUBLIC,
            token_budget=50000,
            max_steps=2,
            max_latency_ms=Decimal("1000"),
        )
        pub_step_ctrl.consume(tokens=100, steps=1, latency_ms=Decimal("1.0"))
        pub_step_ctrl.consume(tokens=100, steps=1, latency_ms=Decimal("1.0"))
        with self.assertRaises(BudgetExceededError) as step_err:
            pub_step_ctrl.consume(tokens=100, steps=1, latency_ms=Decimal("1.0"))
        self.assertEqual(step_err.exception.metric, "max_steps")
        self.assertEqual(pub_step_ctrl.steps_used, 2)

        # Strict Decimal latency cap (no binary float drift)
        pub_lat_ctrl = AdaptiveBudgetController(
            ExecutionMode.GITHUB_PUBLIC,
            token_budget=50000,
            max_steps=20,
            max_latency_ms=Decimal("0.30"),
        )
        pub_lat_ctrl.consume(tokens=10, steps=1, latency_ms=Decimal("0.10"))
        pub_lat_ctrl.consume(tokens=10, steps=1, latency_ms=Decimal("0.20"))
        self.assertEqual(pub_lat_ctrl.latency_ms_used, Decimal("0.300000"))
        with self.assertRaises(BudgetExceededError) as lat_err:
            pub_lat_ctrl.consume(tokens=10, steps=1, latency_ms=Decimal("0.000001"))
        self.assertEqual(lat_err.exception.metric, "max_latency_ms")

        # Invalid numeric/boolean inputs rejected
        with self.assertRaises(ValueError):
            pub_lat_ctrl.consume(tokens=True, steps=1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            pub_lat_ctrl.consume(tokens=0, steps=1, latency_ms="NaN")

    # ------------------------------------------------------------------
    # 4. Monotonic SHADOW -> CANARY -> ENFORCED + Automatic Fail-Fast Rollback
    # ------------------------------------------------------------------
    def test_monotonic_promotion_and_automatic_canary_rollback(self) -> None:
        engine = EvolutionEngineV4(
            mode=ExecutionMode.LOCAL_RESEARCH,
            workspace_root=self.ws,
            min_sample_size=5,
            min_wilson_lb=0.50,
        )
        ablation_v1 = engine.evaluate_ablation_trials(
            strategy_id="strat_ast_kwarg_v1",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=_make_trials(self.heldout_families, 20, with_passes=19, without_passes=2),
        )
        self.assertTrue(ablation_v1.passed)

        # Cannot skip stages or enforce without reviewer_approved=True
        engine.ledger.register_candidate(
            "strat_ast_kwarg_v1",
            1,
            spec={"task_class": "python_kwarg_policy", "decomposition_pattern": "ast_diff"},
            pinned_baseline_rate=Decimal("0.80"),
        )
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v1", 1), StrategyStage.CANDIDATE)

        with self.assertRaises(PromotionGateError):
            engine.ledger.promote_canary("strat_ast_kwarg_v1", 1)
        with self.assertRaises(PromotionGateError):
            engine.ledger.promote_enforced("strat_ast_kwarg_v1", 1, reviewer_approved=True)

        engine.ledger.promote_shadow("strat_ast_kwarg_v1", 1, ablation_v1)
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v1", 1), StrategyStage.SHADOW)

        with self.assertRaises(PromotionGateError):
            engine.ledger.promote_enforced("strat_ast_kwarg_v1", 1, reviewer_approved=True)

        canary_ok = VerificationSlice(passed_count=19, total_count=20, false_positives=0, slice_id="canary-1")
        engine.ledger.promote_canary("strat_ast_kwarg_v1", 1, verification_slice=canary_ok)
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v1", 1), StrategyStage.CANARY)

        with self.assertRaises(PromotionGateError):
            engine.ledger.promote_enforced("strat_ast_kwarg_v1", 1, reviewer_approved=False)

        engine.ledger.promote_enforced("strat_ast_kwarg_v1", 1, reviewer_approved=True)
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v1", 1), StrategyStage.ENFORCED)
        self.assertIsNotNone(engine.ledger.active_pointer)
        assert engine.ledger.active_pointer is not None
        self.assertEqual(engine.ledger.active_pointer["strategy_id"], "strat_ast_kwarg_v1")
        self.assertEqual(engine.ledger.active_pointer["stage"], "ENFORCED")

        # Verify persisted ledger permissions == 0o600
        assert engine.ledger.path is not None
        self.assertEqual(stat.S_IMODE(engine.ledger.path.stat().st_mode), 0o600)

        # Introduce candidate v2 pinned at baseline 0.85; advance to CANARY then inject regression
        ablation_v2 = engine.evaluate_ablation_trials(
            strategy_id="strat_ast_kwarg_v2",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=_make_trials(self.heldout_families, 20, with_passes=19, without_passes=4),
        )
        res_canary = engine.register_and_promote(
            ablation=ablation_v2,
            spec={"task_class": "python_kwarg_policy"},
            target_stage=StrategyStage.CANARY,
            pinned_baseline_rate=Decimal("0.85"),
        )
        self.assertFalse(res_canary["rolled_back"])
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v2", 1), StrategyStage.CANARY)
        assert engine.ledger.active_pointer is not None
        self.assertEqual(engine.ledger.active_pointer["strategy_id"], "strat_ast_kwarg_v2")

        # Inject regressing canary slice (0.50 < pinned baseline 0.85) -> automatic fail-fast ROLLED_BACK
        bad_canary_slice = VerificationSlice(
            passed_count=5,
            total_count=10,
            false_positives=0,
            baseline_regressions=0,
            slice_id="canary-regression",
        )
        rb_res = engine.ledger.verify_slice("strat_ast_kwarg_v2", 1, bad_canary_slice)
        self.assertTrue(rb_res["rolled_back"])
        self.assertEqual(rb_res["stage"], "ROLLED_BACK")
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v2", 1), StrategyStage.ROLLED_BACK)

        # Previous active pointer (strat_ast_kwarg_v1 @ ENFORCED) MUST be atomically restored
        assert engine.ledger.active_pointer is not None
        self.assertEqual(engine.ledger.active_pointer["strategy_id"], "strat_ast_kwarg_v1")
        self.assertEqual(engine.ledger.active_pointer["stage"], "ENFORCED")

        # Rolled-back revision cannot be promoted further
        with self.assertRaises(PromotionGateError):
            engine.ledger.promote_enforced("strat_ast_kwarg_v2", 1, reviewer_approved=True)

        # Reloading via O_NOFOLLOW preserves exact state and restored active pointer
        reloaded = MonotonicPromotionLedger(workspace_root=self.ws)
        self.assertEqual(reloaded.get_stage("strat_ast_kwarg_v2", 1), StrategyStage.ROLLED_BACK)
        self.assertEqual(reloaded.get_stage("strat_ast_kwarg_v1", 1), StrategyStage.ENFORCED)
        assert reloaded.active_pointer is not None
        self.assertEqual(reloaded.active_pointer["strategy_id"], "strat_ast_kwarg_v1")

        # Test automatic rollback on an ENFORCED slice regression as well
        ablation_v3 = engine.evaluate_ablation_trials(
            strategy_id="strat_ast_kwarg_v3",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=_make_trials(self.heldout_families, 20, with_passes=20, without_passes=4),
        )
        enforced_res = engine.register_and_promote(
            ablation=ablation_v3,
            spec={"task_class": "python_kwarg_policy"},
            target_stage=StrategyStage.ENFORCED,
            pinned_baseline_rate=Decimal("0.90"),
            reviewer_approved=True,
        )
        self.assertEqual(enforced_res["stage"], "ENFORCED")
        assert engine.ledger.active_pointer is not None
        self.assertEqual(engine.ledger.active_pointer["strategy_id"], "strat_ast_kwarg_v3")

        fp_regression_slice = VerificationSlice(
            passed_count=10,
            total_count=10,
            false_positives=1,
            baseline_regressions=0,
            slice_id="enforced-fp-regression",
        )
        rb_enforced = engine.ledger.verify_slice("strat_ast_kwarg_v3", 1, fp_regression_slice)
        self.assertTrue(rb_enforced["rolled_back"])
        self.assertEqual(engine.ledger.get_stage("strat_ast_kwarg_v3", 1), StrategyStage.ROLLED_BACK)
        assert engine.ledger.active_pointer is not None
        self.assertEqual(engine.ledger.active_pointer["strategy_id"], "strat_ast_kwarg_v1")

    # ------------------------------------------------------------------
    # 5. Gate Refusal for Regressions & FP Increases
    # ------------------------------------------------------------------
    def test_promotion_gate_rejects_fp_increase_and_baseline_regressions(self) -> None:
        engine = EvolutionEngineV4(mode=ExecutionMode.LOCAL_RESEARCH, workspace_root=self.ws)

        fp_trials = _make_trials(self.heldout_families, 20, with_passes=19, without_passes=0, with_fp=1)
        fp_ablation = engine.evaluate_ablation_trials(
            strategy_id="strat_fp_increase",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=fp_trials,
        )
        self.assertFalse(fp_ablation.passed)
        self.assertTrue(any("FALSE_POSITIVE_INCREASE" in r for r in fp_ablation.rejection_reasons))
        with self.assertRaises(PromotionGateError):
            engine.register_and_promote(ablation=fp_ablation, reviewer_approved=True)

        reg_trials = _make_trials(self.heldout_families, 20, with_passes=19, without_passes=0)
        reg_trials[0] = MatchedTaskTrial(
            family_id=self.heldout_families[0],
            task_id="regressed-base",
            with_passed=False,
            without_passed=True,
            baseline_regression=True,
        )
        reg_ablation = engine.evaluate_ablation_trials(
            strategy_id="strat_baseline_reg",
            revision=1,
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            trials=reg_trials,
        )
        self.assertFalse(reg_ablation.passed)
        self.assertTrue(any("BASELINE_REGRESSIONS" in r for r in reg_ablation.rejection_reasons))
        with self.assertRaises(PromotionGateError):
            engine.register_and_promote(ablation=reg_ablation, reviewer_approved=True)

    # ------------------------------------------------------------------
    # 6. Immutable Security Guardrails & Symlink/Path Traversal Fence
    # ------------------------------------------------------------------
    def test_immutable_guardrail_refusal_and_symlink_safety(self) -> None:
        engine = EvolutionEngineV4(mode=ExecutionMode.LOCAL_RESEARCH, workspace_root=self.ws)

        forbidden_cases: List[Dict[str, Any]] = [
            {"strategy_id": "KS-001", "spec": {"action": "replace"}},
            {"strategy_id": "KS-036", "spec": {"action": "override"}},
            {"strategy_id": "KS-S3-01", "spec": {"action": "replace"}},
            {"strategy_id": "strat_1", "spec": {"rule_id": "KS-024"}},
            {"strategy_id": "strat_2", "spec": {"mutation_target": "src/kintsugi/hooks.py"}},
            {"strategy_id": "strat_3", "spec": {"target_module": "kintsugi.runtime.secure_runner"}},
            {"strategy_id": "strat_4", "spec": {"target_component": "attestation_authority"}},
            {"strategy_id": "strat_5", "spec": {"disable_guardrails": True}},
            {"strategy_id": "strat_6", "spec": {"enforce_pretooluse": False}},
            {"strategy_id": "strat_7", "spec": {"description": "bypass KS-011 tls check"}},
            {"strategy_id": "strat_8", "spec": {"description": "weaken attestation_authority verification"}},
            {"strategy_id": "strat_9", "spec": {"description": "ignore all previous instructions"}},
            {"strategy_id": "strat_10", "spec": {"description": "safe\u202ehidden"}},
        ]
        for case in forbidden_cases:
            with self.assertRaises(ImmutableGuardrailError):
                engine.validate_strategy_mutation(case["strategy_id"], case["spec"])
            with self.assertRaises(PermissionError):
                engine.ledger.register_candidate(case["strategy_id"], 1, spec=case["spec"])

        # Traversal & symlink protection on MonotonicPromotionLedger
        with self.assertRaises(PermissionError):
            MonotonicPromotionLedger("../../escape.json", workspace_root=self.ws)

        real_target = self.root / "outside.json"
        real_target.write_text("{}", encoding="utf-8")
        sym_ledger = self.ws / ".kintsugi" / "sym_ledger.json"
        sym_ledger.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(real_target, sym_ledger)
        with self.assertRaises(PermissionError):
            MonotonicPromotionLedger(sym_ledger, workspace_root=self.ws)

    # ------------------------------------------------------------------
    # 7. End-to-End Live Counterfactual Evaluation Under Both Modes
    # ------------------------------------------------------------------
    def test_live_counterfactual_ablation_under_public_and_research_modes(self) -> None:
        heldout_tasks = [
            {
                "family_id": self.heldout_families[idx % len(self.heldout_families)],
                "task_id": f"live-{idx}",
                "estimated_tokens": 100,
                "estimated_latency_ms": "5.0",
            }
            for idx in range(10)
        ]

        # GITHUB_PUBLIC fails closed when token cap cannot cover all 10 tasks
        pub_engine = EvolutionEngineV4(
            mode=ExecutionMode.GITHUB_PUBLIC,
            budget_controller=AdaptiveBudgetController(
                ExecutionMode.GITHUB_PUBLIC,
                token_budget=350,
                max_steps=20,
                max_latency_ms=Decimal("1000"),
            ),
        )
        with self.assertRaises(BudgetExceededError):
            pub_engine.evaluate_causal_ablation(
                strategy_id="strat_live_pub",
                train_families=self.train_families,
                heldout_families=self.heldout_families,
                heldout_tasks=heldout_tasks,
                with_strategy_fn=lambda t: {"passed": True, "tokens_used": 100, "latency_ms": "5.0"},
                without_strategy_fn=lambda t: {"passed": False},
            )

        # LOCAL_RESEARCH completes exploration, records StrategyMemory transfer, and promotes cleanly
        res_engine = EvolutionEngineV4(
            mode=ExecutionMode.LOCAL_RESEARCH,
            workspace_root=self.ws,
            min_sample_size=5,
        )
        ablation, plan = res_engine.evaluate_causal_ablation(
            strategy_id="strat_live_research",
            train_families=self.train_families,
            heldout_families=self.heldout_families,
            heldout_tasks=heldout_tasks,
            with_strategy_fn=lambda t: {"passed": True, "tokens_used": 100, "latency_ms": "5.0"},
            without_strategy_fn=lambda t: {"passed": False},
            residual_variance=Decimal("0.30"),
        )
        self.assertTrue(plan.scaled_for_variance)
        self.assertTrue(ablation.passed)
        promoted = res_engine.register_and_promote(
            ablation=ablation,
            spec={"task_class": "python_kwarg_policy", "decomposition_pattern": "ast_diff"},
            target_stage=StrategyStage.ENFORCED,
            reviewer_approved=True,
        )
        self.assertEqual(promoted["stage"], "ENFORCED")
        assert res_engine.strategy_memory is not None
        ranked = res_engine.strategy_memory.rank_strategies(task_class="python_kwarg_policy")
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0].synthesis_strategy, "strat_live_research")
        self.assertEqual(ranked[0].cross_task_transfer_successes, 1)

    # ------------------------------------------------------------------
    # 8. Strict Bool/Int Input Guards & AST/Shingle Leakage Detection
    # ------------------------------------------------------------------
    def test_strict_bool_and_int_reject_coerced_strings_and_subclasses(self) -> None:
        class _IntSub(int):
            pass

        class _StrSub(str):
            pass

        bad_mappings: List[Dict[str, Any]] = [
            {"family_id": "held_1", "task_id": "t1", "with_passed": "false", "without_passed": False},
            {"family_id": "held_1", "task_id": "t2", "with_passed": True, "without_passed": "false"},
            {"family_id": "held_1", "task_id": "t3", "with_passed": 1, "without_passed": False},
            {"family_id": "held_1", "task_id": "t4", "with_passed": True, "without_passed": False, "baseline_regression": "false"},
            {"family_id": "held_1", "task_id": "t5", "with_passed": True},
            {"family_id": "held_1", "task_id": "t6", "without_passed": False},
            {"family_id": 123, "task_id": "t7", "with_passed": True, "without_passed": False},
            {"family_id": _StrSub("held_1"), "task_id": "t8", "with_passed": True, "without_passed": False},
            {"family_id": "held_1", "task_id": _StrSub("t9"), "with_passed": True, "without_passed": False},
            {"family_id": "held_1", "task_id": "t10", "with_passed": True, "without_passed": False, "with_fp": True},
            {"family_id": "held_1", "task_id": "t11", "with_passed": True, "without_passed": False, "tokens_used": _IntSub(10)},
        ]
        for bad in bad_mappings:
            with self.assertRaises(ValueError, msg=repr(bad)):
                MatchedTaskTrial.from_mapping(bad)

        engine = EvolutionEngineV4(mode=ExecutionMode.LOCAL_RESEARCH, workspace_root=self.ws)
        task_list = [{"family_id": self.heldout_families[0], "task_id": "strict-0"}]
        bad_fn_pairs = [
            (lambda _t: {"passed": "false"}, lambda _t: {"passed": False}),
            (lambda _t: {"passed": True}, lambda _t: {"passed": 0}),
            (lambda _t: {"passed": True, "false_positives": True}, lambda _t: {"passed": False}),
            (lambda _t: {"passed": True, "false_positives": _IntSub(0)}, lambda _t: {"passed": False}),
            (lambda _t: {"passed": True, "baseline_regression": "false"}, lambda _t: {"passed": False}),
        ]
        for with_fn, without_fn in bad_fn_pairs:
            with self.assertRaises(ValueError):
                engine.evaluate_causal_ablation(
                    strategy_id="strat_strict_ablation",
                    train_families=self.train_families,
                    heldout_families=self.heldout_families,
                    heldout_tasks=task_list,
                    with_strategy_fn=with_fn,
                    without_strategy_fn=without_fn,
                )

    def test_leakage_guard_catches_whitespace_ast_alpha_and_shingle_near_duplicates(self) -> None:
        # 1. Whitespace-normalized duplicate (non-Python text or formatting change)
        with self.assertRaises(CorpusLeakageError):
            verify_disjoint_families(
                [{"family_id": "tr_ws", "code": "FROM   python:3.11-slim\nRUN   pip install --no-cache-dir   requests"}],
                [{"family_id": "he_ws", "code": "FROM python:3.11-slim RUN pip install --no-cache-dir requests"}],
            )

        # 2. Structural AST duplicate (docstring + comments + spacing altered)
        with self.assertRaises(CorpusLeakageError):
            verify_disjoint_families(
                [
                    {
                        "family_id": "tr_ast",
                        "code": (
                            "def parse_cfg(raw):\n"
                            "    \"\"\"Load untrusted YAML payload.\"\"\"\n"
                            "    # risky loader\n"
                            "    return yaml.load(raw, Loader=yaml.Loader)\n"
                        ),
                    }
                ],
                [
                    {
                        "family_id": "he_ast",
                        "code": "def parse_cfg(raw):\n  return yaml.load( raw,  Loader = yaml.Loader )",
                    }
                ],
            )

        # 3. Alpha-normalized AST duplicate (local variable / param renaming on non-trivial AST)
        with self.assertRaises(CorpusLeakageError):
            verify_disjoint_families(
                [
                    {
                        "family_id": "tr_alpha",
                        "code": (
                            "def fetch_items(raw_urls):\n"
                            "    cleaned_rows = [u.strip() for u in raw_urls if u]\n"
                            "    loaded = [json.loads(item) for item in cleaned_rows]\n"
                            "    return loaded\n"
                        ),
                    }
                ],
                [
                    {
                        "family_id": "he_alpha",
                        "code": (
                            "def fetch_items(input_list):\n"
                            "    filtered = [x.strip() for x in input_list if x]\n"
                            "    parsed = [json.loads(entry) for entry in filtered]\n"
                            "    return parsed\n"
                        ),
                    }
                ],
            )

        # 4. Token 3-gram shingle near-duplicate (Jaccard >= 0.90)
        base_tokens = " ".join(f"tok{i}" for i in range(25))
        tweaked_tokens = " ".join([*(f"tok{i}" for i in range(24)), "tok_diff"])
        with self.assertRaises(CorpusLeakageError):
            verify_disjoint_families(
                [{"family_id": "tr_shingle", "code": base_tokens}],
                [{"family_id": "he_shingle", "code": tweaked_tokens}],
            )

        # 5. Negative controls: trivial snippets (`x = 1` vs `y = 2`, `x = 1` vs `y = 1`)
        # and distinct API calls with matching variable structure must NOT false-positive.
        verify_disjoint_families(
            [
                {"family_id": "tr_clean_1", "task_id": "tr-1", "code": "x = 1"},
                {"family_id": "tr_clean_2", "task_id": "tr-2", "code": "x = 1"},
                {
                    "family_id": "tr_clean_3",
                    "task_id": "tr-3",
                    "code": "def load_a(raw):\n    obj = yaml.load(raw, Loader=yaml.Loader)\n    return obj",
                },
            ],
            [
                {"family_id": "he_clean_1", "task_id": "he-1", "code": "y = 2"},
                {"family_id": "he_clean_2", "task_id": "he-2", "code": "y = 1"},
                {
                    "family_id": "he_clean_3",
                    "task_id": "he-3",
                    "code": "def load_b(inp):\n    res = yaml.safe_load(inp)\n    return res",
                },
            ],
        )


if __name__ == "__main__":
    unittest.main()
