"""Deterministic Warmup + Measured Benchmarking & Economic Selection (`kintsugi.forge.tool_benchmark`).

Evaluates candidate native/adapted tools against baseline Python references across
warmup and measured iterations, recording dataset provenance, input distribution,
seed, compiler/flags, CPU architecture, median & p95 latencies, and exact-Decimal
economic viability without artificially prohibiting exploration in `LOCAL_RESEARCH`.
"""

from __future__ import annotations

import math
import platform
import statistics
import time
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from kintsugi.capability.schemas import (
    SecurityProfile,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)


def _to_finite_decimal(value: Union[int, float, str, Decimal], *, field_name: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"INVALID_ECONOMIC_VALUE ({field_name}): boolean not allowed.")
    try:
        dec = value if isinstance(value, Decimal) else Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError(f"INVALID_ECONOMIC_VALUE ({field_name}): {value!r}") from exc
    if not dec.is_finite():
        raise ValueError(f"INVALID_ECONOMIC_VALUE ({field_name}): non-finite value.")
    return dec


def _percentile(sorted_values: Sequence[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return float(sorted_values[lo])
    frac = rank - lo
    return float(sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * frac)


def _summarize_latencies(samples_ms: Sequence[float]) -> Dict[str, float]:
    ordered = sorted(float(x) for x in samples_ms)
    median_v = float(statistics.median(ordered))
    p95_v = _percentile(ordered, 95.0)
    mean_v = float(statistics.fmean(ordered))
    return {
        "count": float(len(ordered)),
        "min_ms": round(ordered[0], 4),
        "median_ms": round(median_v, 4),
        "p95_ms": round(p95_v, 4),
        "mean_ms": round(mean_v, 4),
        "max_ms": round(ordered[-1], 4),
    }


def _normalize_profile(profile: Union[SecurityProfile, str]) -> SecurityProfile:
    if isinstance(profile, SecurityProfile):
        return profile
    return SecurityProfile(str(profile).strip().upper())


@dataclass(frozen=True)
class EconomicAssessment:
    """Exact-Decimal economic evaluation for build-vs-reuse decisions (`EconomicAssessment/1`)."""

    expected_reuses: Decimal
    old_cost: Decimal
    new_cost: Decimal
    build_cost: Decimal
    verify_cost: Decimal
    maintenance_reserve: Decimal
    expected_savings: Decimal
    total_investment: Decimal
    net_value: Decimal
    economically_justified: bool
    profile: SecurityProfile
    default_selection: bool
    research_mode_permitted: bool
    selected: bool
    decision_reason: str
    schema: str = "EconomicAssessment/1"

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "expected_reuses": str(self.expected_reuses),
                "old_cost": str(self.old_cost),
                "new_cost": str(self.new_cost),
                "build_cost": str(self.build_cost),
                "verify_cost": str(self.verify_cost),
                "maintenance_reserve": str(self.maintenance_reserve),
                "expected_savings": str(self.expected_savings),
                "total_investment": str(self.total_investment),
                "net_value": str(self.net_value),
                "economically_justified": self.economically_justified,
                "profile": self.profile.value,
                "default_selection": self.default_selection,
                "research_mode_permitted": self.research_mode_permitted,
                "selected": self.selected,
                "decision_reason": self.decision_reason,
            }
        )


def evaluate_economic_criterion(
    *,
    expected_reuses: Union[int, float, str, Decimal],
    old_cost: Union[int, float, str, Decimal],
    new_cost: Union[int, float, str, Decimal],
    build_cost: Union[int, float, str, Decimal],
    verify_cost: Union[int, float, str, Decimal],
    maintenance_reserve: Union[int, float, str, Decimal],
    profile: Union[SecurityProfile, str] = SecurityProfile.LOCAL_RESEARCH,
    allow_exploratory_research: bool = True,
) -> EconomicAssessment:
    """Evaluate `expected_reuses * (old_cost - new_cost) > build_cost + verify_cost + maintenance_reserve`.

    Economics acts as the default selection rule. In `LOCAL_RESEARCH` mode,
    exploratory research builds are recorded transparently without artificial
    prohibition even when short-run economic payback is negative.
    """
    reuses = _to_finite_decimal(expected_reuses, field_name="expected_reuses")
    old_c = _to_finite_decimal(old_cost, field_name="old_cost")
    new_c = _to_finite_decimal(new_cost, field_name="new_cost")
    bld_c = _to_finite_decimal(build_cost, field_name="build_cost")
    ver_c = _to_finite_decimal(verify_cost, field_name="verify_cost")
    mnt_c = _to_finite_decimal(maintenance_reserve, field_name="maintenance_reserve")

    for name, val in (
        ("expected_reuses", reuses),
        ("old_cost", old_c),
        ("new_cost", new_c),
        ("build_cost", bld_c),
        ("verify_cost", ver_c),
        ("maintenance_reserve", mnt_c),
    ):
        if val < Decimal("0"):
            raise ValueError(f"INVALID_ECONOMIC_VALUE ({name}): must be >= 0, got {val}.")

    norm_profile = _normalize_profile(profile)
    expected_savings = reuses * (old_c - new_c)
    total_investment = bld_c + ver_c + mnt_c
    net_value = expected_savings - total_investment
    justified = expected_savings > total_investment

    research_permitted = (norm_profile == SecurityProfile.LOCAL_RESEARCH) and bool(allow_exploratory_research)
    if justified:
        selected = True
        reason = "ECONOMIC_CRITERION_MET"
    elif research_permitted:
        selected = True
        reason = "LOCAL_RESEARCH_EXPLORATORY_PERMITTED_DESPITE_NEGATIVE_ROI"
    else:
        selected = False
        reason = "ECONOMIC_CRITERION_NOT_MET"

    return EconomicAssessment(
        expected_reuses=reuses,
        old_cost=old_c,
        new_cost=new_c,
        build_cost=bld_c,
        verify_cost=ver_c,
        maintenance_reserve=mnt_c,
        expected_savings=expected_savings,
        total_investment=total_investment,
        net_value=net_value,
        economically_justified=justified,
        profile=norm_profile,
        default_selection=justified,
        research_mode_permitted=research_permitted,
        selected=selected,
        decision_reason=reason,
    )


@dataclass
class BenchmarkReport:
    """Complete warmup+measured benchmark & economic report (`BenchmarkReport/1`)."""

    dataset: Dict[str, Any]
    input_distribution: str
    seed: int
    compiler: str
    compiler_version: str
    flags: List[str]
    cpu_arch: str
    warmup_iterations: int
    measured_iterations: int
    candidate_samples_ms: List[float]
    baseline_samples_ms: List[float]
    candidate_median_ms: float
    candidate_p95_ms: float
    baseline_median_ms: float
    baseline_p95_ms: float
    speedup_median: float
    speedup_p95: float
    baseline_comparison: Dict[str, Any]
    economics: EconomicAssessment
    regressed: bool
    passed: bool
    reason: str = ""
    schema: str = "BenchmarkReport/1"

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "schema": self.schema,
                "dataset": dict(self.dataset),
                "input_distribution": self.input_distribution,
                "seed": self.seed,
                "compiler": self.compiler,
                "compiler_version": self.compiler_version,
                "flags": list(self.flags),
                "cpu_arch": self.cpu_arch,
                "warmup_iterations": self.warmup_iterations,
                "measured_iterations": self.measured_iterations,
                "median_ms": round(self.candidate_median_ms, 4),
                "p95_ms": round(self.candidate_p95_ms, 4),
                "candidate_median_ms": round(self.candidate_median_ms, 4),
                "candidate_p95_ms": round(self.candidate_p95_ms, 4),
                "baseline_median_ms": round(self.baseline_median_ms, 4),
                "baseline_p95_ms": round(self.baseline_p95_ms, 4),
                "speedup_median": round(self.speedup_median, 4),
                "speedup_p95": round(self.speedup_p95, 4),
                "baseline_comparison": dict(self.baseline_comparison),
                "economics": self.economics.to_dict(),
                "regressed": self.regressed,
                "passed": self.passed,
                "reason": redact_secrets_in_text(self.reason),
            }
        )


class ToolBenchmark:
    """Warmup + measured benchmark runner with baseline comparison and economic gating."""

    def __init__(
        self,
        *,
        warmup_iterations: int = 2,
        measured_iterations: int = 9,
        max_regression_ratio: float = 1.05,
        profile: Union[SecurityProfile, str] = SecurityProfile.LOCAL_RESEARCH,
    ) -> None:
        if isinstance(warmup_iterations, bool) or warmup_iterations < 0:
            raise ValueError("INVALID_WARMUP_ITERATIONS: must be >= 0.")
        if isinstance(measured_iterations, bool) or measured_iterations < 1:
            raise ValueError("INVALID_MEASURED_ITERATIONS: must be >= 1.")
        if float(max_regression_ratio) <= 0.0:
            raise ValueError("INVALID_MAX_REGRESSION_RATIO: must be > 0.")
        self.warmup_iterations = int(warmup_iterations)
        self.measured_iterations = int(measured_iterations)
        self.max_regression_ratio = float(max_regression_ratio)
        self.profile = _normalize_profile(profile)

    def run(
        self,
        *,
        candidate_fn: Callable[[Any], Any],
        baseline_fn: Callable[[Any], Any],
        payload: Any,
        dataset_name: str = "synthetic_corpus",
        input_distribution: str = "uniform_seeded",
        seed: int = 42,
        compiler: str = "python",
        compiler_version: str = "",
        flags: Sequence[str] = (),
        profile: Optional[Union[SecurityProfile, str]] = None,
        expected_reuses: Union[int, float, str, Decimal] = 500,
        old_cost: Optional[Union[int, float, str, Decimal]] = None,
        new_cost: Optional[Union[int, float, str, Decimal]] = None,
        build_cost: Union[int, float, str, Decimal] = "1.0",
        verify_cost: Union[int, float, str, Decimal] = "0.5",
        maintenance_reserve: Union[int, float, str, Decimal] = "0.5",
        allow_exploratory_research: bool = True,
        verify_output_match: bool = True,
    ) -> BenchmarkReport:
        """Execute warmup + measured benchmark runs comparing `candidate_fn` vs `baseline_fn`."""
        eff_profile = _normalize_profile(profile) if profile is not None else self.profile
        safe_dataset_name = validate_safe_text(dataset_name, field_name="dataset_name")
        safe_dist = validate_safe_text(input_distribution, field_name="input_distribution")
        safe_compiler = validate_safe_text(compiler, field_name="compiler")
        safe_comp_ver = validate_safe_text(
            compiler_version or platform.python_version(), field_name="compiler_version"
        )
        safe_flags = [validate_safe_text(str(f), field_name="flag") for f in flags]

        payload_digest = sha256_digest(payload if isinstance(payload, (bytes, str)) else repr(payload))
        payload_bytes = (
            len(payload)
            if isinstance(payload, (bytes, bytearray))
            else len(str(payload).encode("utf-8", errors="replace"))
        )

        # Warmup iterations
        for _ in range(self.warmup_iterations):
            base_warm = baseline_fn(payload)
            cand_warm = candidate_fn(payload)
            if verify_output_match and base_warm != cand_warm:
                raise AssertionError("BENCHMARK_OUTPUT_MISMATCH_DURING_WARMUP")

        baseline_samples: List[float] = []
        candidate_samples: List[float] = []

        for _ in range(self.measured_iterations):
            t0 = time.perf_counter()
            base_out = baseline_fn(payload)
            t1 = time.perf_counter()
            baseline_samples.append((t1 - t0) * 1000.0)

            t2 = time.perf_counter()
            cand_out = candidate_fn(payload)
            t3 = time.perf_counter()
            candidate_samples.append((t3 - t2) * 1000.0)

            if verify_output_match and base_out != cand_out:
                raise AssertionError("BENCHMARK_OUTPUT_MISMATCH_DURING_MEASUREMENT")

        cand_stats = _summarize_latencies(candidate_samples)
        base_stats = _summarize_latencies(baseline_samples)
        cand_med = cand_stats["median_ms"]
        cand_p95 = cand_stats["p95_ms"]
        base_med = base_stats["median_ms"]
        base_p95 = base_stats["p95_ms"]

        eps = 1e-6
        speedup_med = base_med / max(cand_med, eps)
        speedup_p95 = base_p95 / max(cand_p95, eps)
        regressed = cand_med > (base_med * self.max_regression_ratio)

        # Derive latency-proportional default costs when caller does not supply explicit monetary units.
        eff_old_cost = old_cost if old_cost is not None else Decimal(f"{max(base_med, 0.001):.6f}")
        eff_new_cost = new_cost if new_cost is not None else Decimal(f"{max(cand_med, 0.001):.6f}")

        economics = evaluate_economic_criterion(
            expected_reuses=expected_reuses,
            old_cost=eff_old_cost,
            new_cost=eff_new_cost,
            build_cost=build_cost,
            verify_cost=verify_cost,
            maintenance_reserve=maintenance_reserve,
            profile=eff_profile,
            allow_exploratory_research=allow_exploratory_research,
        )

        if regressed:
            passed = False
            reason = f"LATENCY_REGRESSION:candidate_median_ms={cand_med:.4f}>baseline*{self.max_regression_ratio}"
        elif not economics.selected:
            passed = False
            reason = economics.decision_reason
        else:
            passed = True
            reason = "BENCHMARK_PASS_ECONOMIC" if economics.economically_justified else economics.decision_reason

        dataset_meta = {
            "name": safe_dataset_name,
            "digest": payload_digest,
            "payload_bytes": payload_bytes,
        }
        baseline_comp = {
            "baseline": base_stats,
            "candidate": cand_stats,
            "speedup_median": round(speedup_med, 4),
            "speedup_p95": round(speedup_p95, 4),
            "regression_tolerance": self.max_regression_ratio,
        }

        return BenchmarkReport(
            dataset=dataset_meta,
            input_distribution=safe_dist,
            seed=int(seed),
            compiler=safe_compiler,
            compiler_version=safe_comp_ver,
            flags=safe_flags,
            cpu_arch=platform.machine() or "unknown",
            warmup_iterations=self.warmup_iterations,
            measured_iterations=self.measured_iterations,
            candidate_samples_ms=[round(x, 4) for x in candidate_samples],
            baseline_samples_ms=[round(x, 4) for x in baseline_samples],
            candidate_median_ms=cand_med,
            candidate_p95_ms=cand_p95,
            baseline_median_ms=base_med,
            baseline_p95_ms=base_p95,
            speedup_median=speedup_med,
            speedup_p95=speedup_p95,
            baseline_comparison=baseline_comp,
            economics=economics,
            regressed=regressed,
            passed=passed,
            reason=reason,
        )


__all__ = [
    "EconomicAssessment",
    "BenchmarkReport",
    "ToolBenchmark",
    "evaluate_economic_criterion",
]
