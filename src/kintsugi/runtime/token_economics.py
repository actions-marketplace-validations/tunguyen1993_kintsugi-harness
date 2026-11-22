"""Stage 4 Token Economics, 9-Metric Telemetry & Adaptive Resource Scheduler (`kintsugi.runtime.token_economics`)."""

from __future__ import annotations

import inspect
import os
import resource
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait as futures_wait, FIRST_COMPLETED
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.config import KintsugiConfig, OperatingProfile
from kintsugi.runtime.trace_store import TraceStore, redact_trace_text

REQUIRED_STAGE4_METRICS: Tuple[str, ...] = (
    "llm_calls",
    "input_tokens",
    "output_tokens",
    "wall_time_ms",
    "cpu_time_ms",
    "peak_memory_mb",
    "tool_probes",
    "search_nodes",
    "verified_outcome",
)

_POSITIVE_OUTCOME_TOKENS = frozenset({"PASS", "VERIFIED", "SUCCESS", "TRUE"})


class BudgetExceededError(RuntimeError):
    """Raised under `GITHUB_PUBLIC` when token, tool-probe, memory, or runtime limits are exceeded."""

    def __init__(self, message: str, *, metric: str, limit: float, observed: float) -> None:
        super().__init__(message)
        self.metric = metric
        self.limit = limit
        self.observed = observed


class CancellationError(RuntimeError):
    """Raised when a cooperative `CancellationToken` has been triggered."""


class WatchdogTimeoutError(TimeoutError):
    """Raised when `AdaptiveResourceScheduler` watchdog timeout expires."""


def _is_positive_outcome(outcome: Union[bool, str]) -> bool:
    if isinstance(outcome, bool):
        return outcome
    return str(outcome or "").strip().upper() in _POSITIVE_OUTCOME_TOKENS


def _process_peak_rss_mb() -> float:
    """Return process peak RSS in MiB across macOS (`ru_maxrss` bytes) and Linux (`ru_maxrss` KiB)."""
    try:
        rss = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (OSError, ValueError):
        return 0.0
    if sys.platform == "darwin":
        return round(rss / (1024.0 * 1024.0), 4)
    return round(rss / 1024.0, 4)


def _total_system_memory_mb() -> float:
    """Best-effort cross-platform physical RAM size in MiB via POSIX `os.sysconf`."""
    if not hasattr(os, "sysconf"):
        return 0.0
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        phys_pages = os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError):
        return 0.0
    if page_size > 0 and phys_pages > 0:
        return round((float(page_size) * float(phys_pages)) / (1024.0 * 1024.0), 4)
    return 0.0


def _accepts_argument(fn: Callable[..., Any]) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for param in sig.parameters.values():
        if param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.VAR_POSITIONAL,
        ):
            return True
    return False


@dataclass
class RunTelemetry:
    """Stage-4 execution & economics telemetry containing all 9 required metrics plus savings."""

    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    wall_time_ms: float = 0.0
    cpu_time_ms: float = 0.0
    peak_memory_mb: float = 0.0
    tool_probes: int = 0
    search_nodes: int = 0
    verified_outcome: Union[bool, str] = False
    run_id: str = ""
    profile: str = OperatingProfile.GITHUB_PUBLIC.value
    deterministic_steps: int = 0
    memory_hits: int = 0
    llm_steps: int = 0
    local_solve_rate: float = 0.0
    early_stop_on_verified_pass: bool = True
    early_stopped: bool = False
    early_stop_reason: str = ""
    halted_by_policy: bool = False
    halt_reason: str = ""
    tokens_saved_estimate: int = 0

    @property
    def total_tokens(self) -> int:
        return int(self.input_tokens) + int(self.output_tokens)

    @property
    def is_verified_pass(self) -> bool:
        return _is_positive_outcome(self.verified_outcome)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "profile": self.profile,
            "llm_calls": int(self.llm_calls),
            "input_tokens": int(self.input_tokens),
            "output_tokens": int(self.output_tokens),
            "total_tokens": self.total_tokens,
            "wall_time_ms": round(float(self.wall_time_ms), 4),
            "cpu_time_ms": round(float(self.cpu_time_ms), 4),
            "peak_memory_mb": round(float(self.peak_memory_mb), 4),
            "tool_probes": int(self.tool_probes),
            "search_nodes": int(self.search_nodes),
            "verified_outcome": self.verified_outcome,
            "deterministic_steps": int(self.deterministic_steps),
            "memory_hits": int(self.memory_hits),
            "llm_steps": int(self.llm_steps),
            "local_solve_rate": round(float(self.local_solve_rate), 6),
            "early_stop_on_verified_pass": bool(self.early_stop_on_verified_pass),
            "early_stopped": bool(self.early_stopped),
            "early_stop_reason": self.early_stop_reason,
            "halted_by_policy": bool(self.halted_by_policy),
            "halt_reason": self.halt_reason,
            "tokens_saved_estimate": int(self.tokens_saved_estimate),
        }


class TokenEconomicsTracker:
    """
    Thread-safe Stage-4 telemetry collector and profile-aware resource/budget policy enforcer.

    - Under `GITHUB_PUBLIC`: enforces `token_budget`, `max_tool_probes`, `max_runtime_seconds`,
      and `max_memory_mb` fail-closed.
    - Under `LOCAL_RESEARCH`: NEVER imposes artificial token, iteration, search, or tool-probe caps,
      and tracks deterministic-first / memory-first savings (`local_solve_rate`,
      `early_stop_on_verified_pass`).
    """

    def __init__(
        self,
        config: Optional[KintsugiConfig] = None,
        *,
        profile: Optional[Union[OperatingProfile, str]] = None,
        run_id: str = "",
        early_stop_on_verified_pass: Optional[bool] = None,
        trace_store: Optional[TraceStore] = None,
    ) -> None:
        if config is None:
            resolved_cfg = KintsugiConfig.for_profile(profile or OperatingProfile.GITHUB_PUBLIC)
        elif profile is not None:
            target_prof = profile if isinstance(profile, OperatingProfile) else OperatingProfile(str(profile).strip().upper())
            resolved_cfg = KintsugiConfig(
                profile=target_prof,
                local_research=config.local_research,
                github_public=config.github_public,
                security=config.security,
            )
        else:
            resolved_cfg = config

        self.config = resolved_cfg
        self.profile = resolved_cfg.profile
        self.run_id = str(run_id or "").strip()
        self.trace_store = trace_store

        if early_stop_on_verified_pass is None:
            self.early_stop_on_verified_pass = bool(resolved_cfg.local_research.deterministic_first)
        else:
            self.early_stop_on_verified_pass = bool(early_stop_on_verified_pass)

        self._lock = threading.RLock()
        self._t0_wall = time.perf_counter()
        self._t0_cpu = time.process_time()
        self._wall_offset_ms = 0.0
        self._cpu_offset_ms = 0.0
        self._peak_memory_mb = _process_peak_rss_mb()

        self._llm_calls = 0
        self._input_tokens = 0
        self._output_tokens = 0
        self._tool_probes = 0
        self._search_nodes = 0
        self._verified_outcome: Union[bool, str] = False
        self._deterministic_steps = 0
        self._memory_hits = 0
        self._llm_steps = 0
        self._tokens_saved_estimate = 0
        self._early_stopped = False
        self._early_stop_reason = ""
        self._halted_by_policy = False
        self._halt_reason = ""

    def __enter__(self) -> "TokenEconomicsTracker":
        with self._lock:
            self._t0_wall = time.perf_counter()
            self._t0_cpu = time.process_time()
            self._peak_memory_mb = max(self._peak_memory_mb, _process_peak_rss_mb())
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.snapshot()

    def _measure_wall_ms_unlocked(self) -> float:
        elapsed = (time.perf_counter() - self._t0_wall) * 1000.0
        return max(0.0, elapsed + self._wall_offset_ms)

    def _measure_cpu_ms_unlocked(self) -> float:
        elapsed = (time.process_time() - self._t0_cpu) * 1000.0
        return max(0.0, elapsed + self._cpu_offset_ms)

    def _measure_peak_memory_mb_unlocked(self) -> float:
        self._peak_memory_mb = max(self._peak_memory_mb, _process_peak_rss_mb())
        return self._peak_memory_mb

    def _compute_local_solve_rate_unlocked(self) -> float:
        total = self._deterministic_steps + self._memory_hits + self._llm_steps
        if total > 0:
            return (self._deterministic_steps + self._memory_hits) / float(total)
        if _is_positive_outcome(self._verified_outcome) and self._llm_calls == 0:
            return 1.0
        return 0.0

    def _emit_policy_halt_event(self, reason: str) -> None:
        if self.trace_store is None or not self.run_id:
            return
        try:
            self.trace_store.append_event(
                self.run_id,
                step_id="token_economics",
                state="POLICY_HALTED",
                tokens_used=self._input_tokens + self._output_tokens,
                elapsed_ms=self._measure_wall_ms_unlocked(),
                decision_reason=reason,
                resource_usage=self._build_telemetry_unlocked().to_dict(),
                profile=self.profile.value,
                component="token_economics",
                severity="HIGH",
            )
        except Exception as _trace_err:
            _ = _trace_err

    def _check_github_public_limits_unlocked(
        self,
        *,
        additional_tokens: int = 0,
        additional_probes: int = 0,
        wall_time_ms_override: Optional[float] = None,
    ) -> Optional[Tuple[str, float, float, str]]:
        """Return `(metric, limit, observed, reason)` if `GITHUB_PUBLIC` cap exceeded, else `None`."""
        if self.profile != OperatingProfile.GITHUB_PUBLIC:
            return None

        gp = self.config.github_public
        projected_tokens = self._input_tokens + self._output_tokens + max(0, int(additional_tokens))
        if projected_tokens > gp.token_budget:
            reason = (
                f"GITHUB_PUBLIC_TOKEN_BUDGET_EXCEEDED: projected_tokens={projected_tokens} "
                f"> token_budget={gp.token_budget}"
            )
            return ("token_budget", float(gp.token_budget), float(projected_tokens), reason)

        projected_probes = self._tool_probes + max(0, int(additional_probes))
        if projected_probes > gp.max_tool_probes:
            reason = (
                f"GITHUB_PUBLIC_MAX_TOOL_PROBES_EXCEEDED: projected_probes={projected_probes} "
                f"> max_tool_probes={gp.max_tool_probes}"
            )
            return ("max_tool_probes", float(gp.max_tool_probes), float(projected_probes), reason)

        wall_ms = (
            float(wall_time_ms_override)
            if wall_time_ms_override is not None
            else self._measure_wall_ms_unlocked()
        )
        runtime_sec = wall_ms / 1000.0
        if runtime_sec > float(gp.max_runtime_seconds):
            reason = (
                f"GITHUB_PUBLIC_MAX_RUNTIME_EXCEEDED: runtime_seconds={runtime_sec:.4f} "
                f"> max_runtime_seconds={gp.max_runtime_seconds}"
            )
            return ("max_runtime_seconds", float(gp.max_runtime_seconds), runtime_sec, reason)

        peak_mb = self._measure_peak_memory_mb_unlocked()
        if peak_mb > float(gp.max_memory_mb):
            reason = (
                f"GITHUB_PUBLIC_MAX_MEMORY_EXCEEDED: peak_memory_mb={peak_mb:.2f} "
                f"> max_memory_mb={gp.max_memory_mb}"
            )
            return ("max_memory_mb", float(gp.max_memory_mb), peak_mb, reason)

        return None

    def check_limits(
        self,
        *,
        additional_tokens: int = 0,
        additional_probes: int = 0,
        wall_time_ms_override: Optional[float] = None,
    ) -> None:
        """Enforce active profile limits; raises `BudgetExceededError` under `GITHUB_PUBLIC` if exceeded."""
        with self._lock:
            violation = self._check_github_public_limits_unlocked(
                additional_tokens=additional_tokens,
                additional_probes=additional_probes,
                wall_time_ms_override=wall_time_ms_override,
            )
            if violation is not None:
                metric, limit, observed, reason = violation
                self._halted_by_policy = True
                self._halt_reason = reason
                self._emit_policy_halt_event(reason)
                raise BudgetExceededError(reason, metric=metric, limit=limit, observed=observed)

    def try_check_limits(
        self,
        *,
        additional_tokens: int = 0,
        additional_probes: int = 0,
        wall_time_ms_override: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Non-raising policy check returning `(allowed, reason)`."""
        with self._lock:
            violation = self._check_github_public_limits_unlocked(
                additional_tokens=additional_tokens,
                additional_probes=additional_probes,
                wall_time_ms_override=wall_time_ms_override,
            )
            if violation is not None:
                _, _, _, reason = violation
                self._halted_by_policy = True
                self._halt_reason = reason
                return False, reason
            return True, "OK"

    def record_llm_call(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        *,
        calls: int = 1,
        enforce: bool = True,
    ) -> RunTelemetry:
        """Record LLM invocation & tokens, enforcing `GITHUB_PUBLIC.token_budget` when active."""
        in_tok = max(0, int(input_tokens))
        out_tok = max(0, int(output_tokens))
        n_calls = max(0, int(calls))
        with self._lock:
            if enforce:
                self.check_limits(additional_tokens=in_tok + out_tok)
            self._llm_calls += n_calls
            self._llm_steps += n_calls
            self._input_tokens += in_tok
            self._output_tokens += out_tok
            return self._build_telemetry_unlocked()

    def record_tool_probe(self, count: int = 1, *, enforce: bool = True) -> RunTelemetry:
        """Record candidate tool probes, enforcing `GITHUB_PUBLIC.max_tool_probes` when active."""
        delta = max(0, int(count))
        with self._lock:
            if enforce:
                self.check_limits(additional_probes=delta)
            self._tool_probes += delta
            return self._build_telemetry_unlocked()

    def record_search_node(self, count: int = 1) -> RunTelemetry:
        """Record expanded planning/search nodes (never artificially capped under `LOCAL_RESEARCH`)."""
        delta = max(0, int(count))
        with self._lock:
            self._search_nodes += delta
            return self._build_telemetry_unlocked()

    def record_deterministic_solve(
        self, count: int = 1, *, tokens_saved_estimate: int = 0
    ) -> RunTelemetry:
        """Record zero-LLM deterministic step completion for `local_solve_rate` tracking."""
        with self._lock:
            self._deterministic_steps += max(0, int(count))
            self._tokens_saved_estimate += max(0, int(tokens_saved_estimate))
            return self._build_telemetry_unlocked()

    def record_memory_hit(
        self, count: int = 1, *, tokens_saved_estimate: int = 0
    ) -> RunTelemetry:
        """Record ExperienceStore / memory-first reuse hit for `local_solve_rate` tracking."""
        with self._lock:
            self._memory_hits += max(0, int(count))
            self._tokens_saved_estimate += max(0, int(tokens_saved_estimate))
            return self._build_telemetry_unlocked()

    def record_timing(
        self,
        *,
        wall_time_ms: Optional[float] = None,
        cpu_time_ms: Optional[float] = None,
        enforce: bool = True,
    ) -> RunTelemetry:
        """Add explicit wall/CPU milliseconds (useful for subprocess accumulation or testing)."""
        with self._lock:
            if wall_time_ms is not None:
                self._wall_offset_ms += max(0.0, float(wall_time_ms))
            if cpu_time_ms is not None:
                self._cpu_offset_ms += max(0.0, float(cpu_time_ms))
            if enforce:
                self.check_limits()
            return self._build_telemetry_unlocked()

    def record_memory(self, peak_memory_mb: float, *, enforce: bool = True) -> RunTelemetry:
        """Update peak memory high-water mark in MiB."""
        with self._lock:
            self._peak_memory_mb = max(self._peak_memory_mb, max(0.0, float(peak_memory_mb)))
            if enforce:
                self.check_limits()
            return self._build_telemetry_unlocked()

    def record_verified_outcome(
        self,
        outcome: Union[bool, str],
        *,
        deterministic: bool = False,
        from_memory: bool = False,
        tokens_saved_estimate: int = 0,
    ) -> bool:
        """
        Record final/milestone `verified_outcome` and trigger `early_stop_on_verified_pass`
        if enabled and outcome is a verified PASS. Returns `should_stop_early`.
        """
        with self._lock:
            self._verified_outcome = outcome
            passed = _is_positive_outcome(outcome)
            if passed:
                if deterministic and self._deterministic_steps == 0:
                    self._deterministic_steps += 1
                if from_memory and self._memory_hits == 0:
                    self._memory_hits += 1
                if tokens_saved_estimate > 0:
                    self._tokens_saved_estimate += int(tokens_saved_estimate)
                if self.early_stop_on_verified_pass:
                    self._early_stopped = True
                    self._early_stop_reason = (
                        "EARLY_STOP_ON_VERIFIED_DETERMINISTIC_PASS"
                        if (deterministic or from_memory or self._llm_calls == 0)
                        else "EARLY_STOP_ON_VERIFIED_PASS"
                    )
            return self._early_stopped

    @property
    def should_stop_early(self) -> bool:
        with self._lock:
            return self.early_stop_on_verified_pass and self._early_stopped

    @property
    def local_solve_rate(self) -> float:
        with self._lock:
            return self._compute_local_solve_rate_unlocked()

    def _build_telemetry_unlocked(self) -> RunTelemetry:
        return RunTelemetry(
            llm_calls=self._llm_calls,
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            wall_time_ms=self._measure_wall_ms_unlocked(),
            cpu_time_ms=self._measure_cpu_ms_unlocked(),
            peak_memory_mb=self._measure_peak_memory_mb_unlocked(),
            tool_probes=self._tool_probes,
            search_nodes=self._search_nodes,
            verified_outcome=self._verified_outcome,
            run_id=self.run_id,
            profile=self.profile.value,
            deterministic_steps=self._deterministic_steps,
            memory_hits=self._memory_hits,
            llm_steps=self._llm_steps,
            local_solve_rate=self._compute_local_solve_rate_unlocked(),
            early_stop_on_verified_pass=self.early_stop_on_verified_pass,
            early_stopped=self._early_stopped,
            early_stop_reason=self._early_stop_reason,
            halted_by_policy=self._halted_by_policy,
            halt_reason=self._halt_reason,
            tokens_saved_estimate=self._tokens_saved_estimate,
        )

    def snapshot(self) -> RunTelemetry:
        """Return thread-safe `RunTelemetry` snapshot containing all 9 Stage-4 metrics."""
        with self._lock:
            return self._build_telemetry_unlocked()

    @property
    def telemetry(self) -> RunTelemetry:
        return self.snapshot()

    def to_dict(self) -> Dict[str, Any]:
        return self.snapshot().to_dict()


class CancellationToken:
    """Thread-safe cooperative cancellation token shared across workers and watchdog timers."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.RLock()
        self._reason: Optional[str] = None
        self._timed_out = False
        self._callbacks: List[Callable[[str], None]] = []

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def timed_out(self) -> bool:
        with self._lock:
            return self._timed_out

    @property
    def reason(self) -> Optional[str]:
        with self._lock:
            return self._reason

    def cancel(self, reason: str = "CANCELLED", *, timed_out: bool = False) -> None:
        """Signal cooperative cancellation once and notify registered callbacks."""
        callbacks: List[Callable[[str], None]] = []
        clean_reason = redact_trace_text(reason or "CANCELLED", max_len=256)
        with self._lock:
            if not self._event.is_set():
                self._reason = clean_reason
                self._timed_out = bool(timed_out)
                self._event.set()
                callbacks = list(self._callbacks)
        for cb in callbacks:
            try:
                cb(clean_reason)
            except Exception as _cb_err:
                _ = _cb_err

    def on_cancel(self, callback: Callable[[str], None]) -> None:
        """Register a callback executed immediately if already cancelled or upon cancellation."""
        already_reason: Optional[str] = None
        with self._lock:
            if self._event.is_set():
                already_reason = self._reason or "CANCELLED"
            else:
                self._callbacks.append(callback)
        if already_reason is not None:
            callback(already_reason)

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._event.wait(timeout=timeout)

    def raise_if_cancelled(self) -> None:
        """Raise `WatchdogTimeoutError` or `CancellationError` if this token is cancelled."""
        if not self._event.is_set():
            return
        with self._lock:
            reason = self._reason or "CANCELLED"
            is_timeout = self._timed_out
        if is_timeout:
            raise WatchdogTimeoutError(reason)
        raise CancellationError(reason)


class AdaptiveResourceScheduler:
    """
    Bounded adaptive worker scheduler calibrated to `os.cpu_count()`, memory pressure,
    watchdog timeout, and cooperative `CancellationToken`.
    """

    def __init__(
        self,
        config: Optional[KintsugiConfig] = None,
        *,
        max_workers: Optional[int] = None,
        watchdog_timeout_seconds: Optional[float] = None,
        memory_pressure_high_ratio: float = 0.75,
        memory_pressure_critical_ratio: float = 0.90,
        cpu_count_fn: Optional[Callable[[], Optional[int]]] = None,
        memory_probe_fn: Optional[Callable[[], Union[float, Tuple[float, float]]]] = None,
    ) -> None:
        self.config = config if config is not None else KintsugiConfig.for_profile(OperatingProfile.LOCAL_RESEARCH)
        self._max_workers = max(1, int(max_workers)) if max_workers is not None else None
        self.watchdog_timeout_seconds = (
            max(0.001, float(watchdog_timeout_seconds))
            if watchdog_timeout_seconds is not None
            else None
        )
        self.memory_pressure_high_ratio = min(0.99, max(0.1, float(memory_pressure_high_ratio)))
        self.memory_pressure_critical_ratio = min(
            0.999, max(self.memory_pressure_high_ratio, float(memory_pressure_critical_ratio))
        )
        self._cpu_count_fn = cpu_count_fn or os.cpu_count
        self._memory_probe_fn = memory_probe_fn

    def create_cancellation_token(self) -> CancellationToken:
        return CancellationToken()

    def measure_memory_pressure(self) -> Dict[str, Any]:
        """Compute current RSS / memory pressure ratio and throttle level (`LOW`..`CRITICAL`)."""
        rss_mb = _process_peak_rss_mb()
        total_mb = _total_system_memory_mb()
        ratio = 0.0

        if self._memory_probe_fn is not None:
            probed = self._memory_probe_fn()
            if isinstance(probed, tuple) and len(probed) == 2:
                used_mb, cap_mb = float(probed[0]), float(probed[1])
                rss_mb = max(0.0, used_mb)
                total_mb = max(0.0, cap_mb)
                ratio = (used_mb / cap_mb) if cap_mb > 0 else 0.0
            else:
                ratio = float(probed)
        elif self.config.profile == OperatingProfile.GITHUB_PUBLIC:
            cap_mb = float(self.config.github_public.max_memory_mb)
            ratio = (rss_mb / cap_mb) if cap_mb > 0 else 0.0
        elif total_mb > 0:
            ratio = rss_mb / total_mb

        ratio = min(1.0, max(0.0, ratio))
        if ratio >= self.memory_pressure_critical_ratio:
            level = "CRITICAL"
        elif ratio >= self.memory_pressure_high_ratio:
            level = "HIGH"
        elif ratio >= 0.5:
            level = "ELEVATED"
        else:
            level = "LOW"

        return {
            "rss_mb": round(rss_mb, 4),
            "total_mb": round(total_mb, 4),
            "pressure_ratio": round(ratio, 4),
            "level": level,
        }

    def recommended_workers(self) -> int:
        """Return bounded concurrency calibrated to `os.cpu_count()`, profile, and memory pressure."""
        raw_cpus = self._cpu_count_fn()
        cpus = max(1, int(raw_cpus if raw_cpus is not None and raw_cpus >= 1 else 1))
        base = min(cpus, self._max_workers) if self._max_workers is not None else cpus

        if self.config.profile == OperatingProfile.GITHUB_PUBLIC:
            base = min(base, self.config.github_public.max_parallel_agents)

        pressure = self.measure_memory_pressure()
        ratio = float(pressure["pressure_ratio"])
        if ratio >= self.memory_pressure_critical_ratio:
            return 1
        if ratio >= self.memory_pressure_high_ratio:
            return max(1, base // 2)
        return max(1, base)

    def _resolve_watchdog_timeout(self, timeout_seconds: Optional[float]) -> Optional[float]:
        candidate = timeout_seconds if timeout_seconds is not None else self.watchdog_timeout_seconds
        if self.config.profile == OperatingProfile.GITHUB_PUBLIC:
            cap = float(self.config.github_public.max_runtime_seconds)
            return min(float(candidate), cap) if candidate is not None else cap
        if not self.config.local_research.watchdog_enabled:
            return None
        return float(candidate) if candidate is not None else None

    @contextmanager
    def watchdog(
        self,
        timeout_seconds: Optional[float] = None,
        *,
        token: Optional[CancellationToken] = None,
    ) -> Iterator[CancellationToken]:
        """Run scope under a bounded watchdog timer that triggers cooperative `CancellationToken`."""
        active_token = token if token is not None else CancellationToken()
        effective_timeout = self._resolve_watchdog_timeout(timeout_seconds)
        timer: Optional[threading.Timer] = None
        if effective_timeout is not None and effective_timeout > 0:
            timer = threading.Timer(
                effective_timeout,
                lambda: active_token.cancel(
                    reason=f"WATCHDOG_TIMEOUT: exceeded {effective_timeout:.3f}s",
                    timed_out=True,
                ),
            )
            timer.daemon = True
            timer.start()
        try:
            yield active_token
        finally:
            if timer is not None:
                timer.cancel()

    def run_with_watchdog(
        self,
        fn: Callable[..., Any],
        *,
        timeout_seconds: Optional[float] = None,
        token: Optional[CancellationToken] = None,
    ) -> Any:
        """Execute `fn` under watchdog supervision and fail closed if timed out or cancelled."""
        with self.watchdog(timeout_seconds, token=token) as active_token:
            active_token.raise_if_cancelled()
            result = fn(active_token) if _accepts_argument(fn) else fn()
            active_token.raise_if_cancelled()
            return result

    def run_tasks(
        self,
        tasks: Sequence[Callable[..., Any]],
        *,
        tracker: Optional[TokenEconomicsTracker] = None,
        token: Optional[CancellationToken] = None,
        timeout_seconds: Optional[float] = None,
        early_stop_on_verified_pass: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Execute `tasks` concurrently within bounded worker concurrency, watchdog timeout,
        cooperative cancellation, policy caps, and deterministic-first early stop.
        """
        if early_stop_on_verified_pass is None:
            early_stop = (
                tracker.early_stop_on_verified_pass
                if tracker is not None
                else bool(self.config.local_research.deterministic_first)
            )
        else:
            early_stop = bool(early_stop_on_verified_pass)

        workers = self.recommended_workers()
        results: List[Any] = []
        errors: List[str] = []
        stopped_early = False
        halted_reason = ""
        completed_count = 0

        with self.watchdog(timeout_seconds, token=token) as active_token:
            if not tasks:
                return {
                    "workers_used": workers,
                    "submitted": 0,
                    "completed": 0,
                    "results": [],
                    "errors": [],
                    "cancelled": active_token.is_cancelled,
                    "timed_out": active_token.timed_out,
                    "stopped_early": False,
                    "halt_reason": "",
                }

            task_iter = enumerate(tasks)
            pending: Dict[Future[Any], int] = {}
            with ThreadPoolExecutor(max_workers=workers) as pool:
                def _submit_next() -> bool:
                    if active_token.is_cancelled or stopped_early:
                        return False
                    if tracker is not None:
                        if early_stop and tracker.should_stop_early:
                            return False
                        ok_lim, lim_reason = tracker.try_check_limits()
                        if not ok_lim:
                            active_token.cancel(reason=lim_reason)
                            return False
                    try:
                        idx, fn = next(task_iter)
                    except StopIteration:
                        return False
                    call_fn = (lambda f=fn: f(active_token)) if _accepts_argument(fn) else fn
                    pending[pool.submit(call_fn)] = idx
                    return True

                for _ in range(workers):
                    if not _submit_next():
                        break

                while pending:
                    done, _ = futures_wait(pending.keys(), timeout=0.02, return_when=FIRST_COMPLETED)
                    if active_token.is_cancelled and not done:
                        for fut in list(pending.keys()):
                            fut.cancel()
                        break

                    for fut in done:
                        pending.pop(fut, None)
                        try:
                            res = fut.result()
                            results.append(res)
                            completed_count += 1
                            if tracker is not None:
                                tracker.record_search_node(1)
                            if early_stop and isinstance(res, Mapping) and _is_positive_outcome(
                                res.get("verified_outcome", False)
                            ):
                                stopped_early = True
                                if tracker is not None:
                                    tracker.record_verified_outcome(
                                        res.get("verified_outcome", True),
                                        deterministic=bool(res.get("deterministic", False)),
                                        from_memory=bool(res.get("from_memory", False)),
                                    )
                                active_token.cancel(reason="EARLY_STOP_ON_VERIFIED_PASS")
                        except (BudgetExceededError, CancellationError, WatchdogTimeoutError) as exc:
                            errors.append(str(exc))
                            halted_reason = str(exc)
                            active_token.cancel(
                                reason=str(exc),
                                timed_out=isinstance(exc, WatchdogTimeoutError),
                            )
                        except Exception as exc:
                            errors.append(str(exc))

                    if active_token.is_cancelled or stopped_early:
                        for fut in list(pending.keys()):
                            fut.cancel()
                        if not pending:
                            break
                        continue

                    while len(pending) < workers:
                        if not _submit_next():
                            break

        if not halted_reason and active_token.is_cancelled:
            halted_reason = active_token.reason or ""

        return {
            "workers_used": workers,
            "submitted": len(tasks),
            "completed": completed_count,
            "results": results,
            "errors": errors,
            "cancelled": active_token.is_cancelled,
            "timed_out": active_token.timed_out,
            "stopped_early": stopped_early or (tracker.should_stop_early if tracker else False),
            "halt_reason": halted_reason,
        }


__all__ = [
    "AdaptiveResourceScheduler",
    "BudgetExceededError",
    "CancellationError",
    "CancellationToken",
    "REQUIRED_STAGE4_METRICS",
    "RunTelemetry",
    "TokenEconomicsTracker",
    "WatchdogTimeoutError",
]
