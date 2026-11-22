"""Stage 1 Vertical-Slice Task Orchestrator (`kintsugi.runtime.orchestrator`).

Implements the zero-LLM deterministic capability pipeline:
`Task -> CapabilityGap -> ToolRegistry -> ToolResolver -> SecureRunner -> OracleVerification -> ExperienceStore`
with verifiable reuse telemetry on repeated or similar tasks.
"""

from __future__ import annotations

import hmac
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from kintsugi.capability.capability_gap import CapabilityGapDetector
from kintsugi.capability.capability_graph import tool_violates_security_context
from kintsugi.capability.schemas import (
    CapabilityGap,
    ExecutionReceipt,
    ExecutionStatus,
    Experience,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry
from kintsugi.capability.tool_resolver import ResolutionResult, ToolResolver
from kintsugi.config import KintsugiConfig
from kintsugi.runtime.experience_store import ExperienceStore
from kintsugi.runtime.secure_runner import SecureRunner, trust_status_value

_WORD_SPLIT_RE = re.compile(r"[a-z0-9_.-]+")


def _infer_capability_from_intent(intent: str) -> str:
    low = intent.lower()
    if "sha256" in low or "hash" in low:
        return "file.sha256"
    if "json" in low:
        return "json.validate"
    if "lint" in low or "scan" in low:
        return "code.scan"
    return "general.execute"


def _normalize_task_input(task: Any) -> Dict[str, Any]:
    if isinstance(task, str):
        intent = task.strip()
        capability = _infer_capability_from_intent(intent)
        task_id = f"task_{sha256_digest(intent).split(':', 1)[1][:10]}"
        args: Dict[str, Any] = {}
        explicit_fp = ""
        input_artifacts: List[Dict[str, Any]] = []
        expected_outputs: List[Dict[str, Any]] = []
        budget: Dict[str, Any] = {}
    elif isinstance(task, Mapping):
        intent = str(task.get("intent") or task.get("description") or "").strip()
        req_caps = task.get("required_capabilities")
        raw_cap = task.get("capability") or task.get("required_capability")
        if not raw_cap and isinstance(req_caps, (list, tuple)) and req_caps:
            raw_cap = req_caps[0]
        capability = str(raw_cap or "").strip() or _infer_capability_from_intent(intent)
        args = dict(task.get("args") or task.get("inputs") or {})
        task_id = str(task.get("task_id") or task.get("goal_id") or task.get("id") or "").strip()
        if not task_id:
            task_id = f"task_{sha256_digest({'cap': capability, 'intent': intent}).split(':', 1)[1][:10]}"
        explicit_fp = str(task.get("task_fingerprint") or "").strip()
        input_artifacts = list(task.get("input_artifacts") or [])
        expected_outputs = list(task.get("expected_outputs") or [])
        budget = dict(task.get("budget") or {})
    else:
        intent = str(getattr(task, "intent", None) or getattr(task, "description", "") or "").strip()
        req_caps = getattr(task, "required_capabilities", None)
        raw_cap = getattr(task, "capability", None) or getattr(task, "required_capability", None)
        if not raw_cap and isinstance(req_caps, (list, tuple)) and req_caps:
            raw_cap = req_caps[0]
        capability = str(raw_cap or "").strip() or _infer_capability_from_intent(intent)
        args = dict(getattr(task, "args", None) or getattr(task, "inputs", None) or {})
        task_id = str(
            getattr(task, "task_id", None)
            or getattr(task, "goal_id", None)
            or getattr(task, "id", "")
            or ""
        ).strip()
        if not task_id:
            task_id = f"task_{sha256_digest({'cap': capability, 'intent': intent}).split(':', 1)[1][:10]}"
        explicit_fp = str(getattr(task, "task_fingerprint", "") or "").strip()
        input_artifacts = list(getattr(task, "input_artifacts", None) or [])
        expected_outputs = list(getattr(task, "expected_outputs", None) or [])
        budget = dict(getattr(task, "budget", None) or {})

    if explicit_fp:
        task_fingerprint = explicit_fp
    else:
        intent_tokens = [
            tok for tok in _WORD_SPLIT_RE.findall(intent.lower()) if "." not in tok and "/" not in tok
        ]
        task_fingerprint = sha256_digest(
            {
                "capability": capability,
                "intent_tokens": intent_tokens[:12],
                "arg_keys": sorted(str(k) for k in args.keys()),
            }
        )

    return {
        "task_id": task_id,
        "intent": intent,
        "capability": capability,
        "args": args,
        "task_fingerprint": task_fingerprint,
        "input_artifacts": input_artifacts,
        "expected_outputs": expected_outputs,
        "budget": budget,
    }


@dataclass
class Stage1ExecutionResult:
    """End-to-end result and verifiable telemetry for a Stage 1 vertical slice."""

    task_id: str
    capability: str
    task_fingerprint: str
    status: str
    verification_status: str
    receipt: ExecutionReceipt
    capability_gap: Dict[str, Any]
    resolved_tool_id: Optional[str]
    experience: Optional[Experience]
    reuse_hit: bool
    reuse_count: int
    llm_calls: int = 0
    resolution: Optional[Dict[str, Any]] = None
    telemetry: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "capability": self.capability,
            "task_fingerprint": self.task_fingerprint,
            "status": self.status,
            "verification_status": self.verification_status,
            "receipt": self.receipt.to_dict(),
            "capability_gap": dict(self.capability_gap),
            "resolution": dict(self.resolution) if self.resolution is not None else None,
            "resolved_tool_id": self.resolved_tool_id,
            "experience": self.experience.to_dict() if self.experience is not None else None,
            "reuse_hit": self.reuse_hit,
            "reuse_count": self.reuse_count,
            "llm_calls": self.llm_calls,
            "telemetry": dict(self.telemetry),
        }


def run_stage1_vertical_slice(
    task: Any,
    *,
    security_context: SecurityContext,
    registry: Optional[ToolRegistry] = None,
    resolver: Optional[ToolResolver] = None,
    runner: Optional[SecureRunner] = None,
    experience_store: Optional[ExperienceStore] = None,
    oracle: Optional[Callable[..., Any]] = None,
    gap_detector: Optional[CapabilityGapDetector] = None,
    config: Optional[KintsugiConfig] = None,
) -> Stage1ExecutionResult:
    """Execute the deterministic Stage 1 vertical slice with zero LLM calls."""
    slice_t0 = time.perf_counter()
    norm = _normalize_task_input(task)
    task_id = norm["task_id"]
    capability = norm["capability"]
    args = norm["args"]
    task_fingerprint = norm["task_fingerprint"]

    active_registry = registry if registry is not None else ToolRegistry()
    active_gap_detector = gap_detector if gap_detector is not None else CapabilityGapDetector()
    active_resolver = resolver if resolver is not None else ToolResolver(gap_detector=active_gap_detector)
    active_runner = (
        runner
        if runner is not None
        else SecureRunner(config=config, attestation_authority=active_registry.authority)
    )
    active_profile = security_context.profile

    # Stage A: Fast-path ExperienceStore lookup (never skips SecureRunner re-verification)
    discovery_t0 = time.perf_counter()
    reuse_hit = False
    matched_experience: Optional[Experience] = None
    resolved_tool: Optional[ToolSpec] = None
    resolution_obj: Optional[ResolutionResult] = None
    candidates_evaluated = 0
    discovery_steps = 0
    skipped_gap_discovery = False
    gap_obj: Optional[CapabilityGap] = None
    plan_source = "CAPABILITY_DISCOVERY"

    if experience_store is not None:
        prior_hits = experience_store.retrieve_similar(
            task_fingerprint=task_fingerprint,
            capability=capability,
            security_profile=active_profile,
            limit=1,
            verified_only=True,
        )
        if prior_hits:
            candidate_exp = prior_hits[0]
            candidate_tool = active_registry.get(candidate_exp.tool_or_plan_id)
            if (
                candidate_tool is not None
                and trust_status_value(candidate_tool.trust_status) == TrustStatus.VERIFIED.value
                and not tool_violates_security_context(candidate_tool, security_context)
            ):
                spec_hash = candidate_tool.binary_hash.strip().lower()
                exp_hash = candidate_exp.tool_hash.strip().lower()
                if spec_hash and exp_hash and hmac.compare_digest(spec_hash, exp_hash):
                    reuse_hit = True
                    matched_experience = candidate_exp
                    resolved_tool = candidate_tool
                    candidates_evaluated = 1
                    discovery_steps = 1
                    skipped_gap_discovery = True
                    plan_source = "EXPERIENCE_STORE_REUSE"
                    gap_obj = CapabilityGap(
                        goal_id=task_id,
                        required_capabilities=[capability],
                        available_capabilities=[capability],
                        input_artifacts=norm["input_artifacts"],
                        expected_outputs=norm["expected_outputs"],
                        security_context=security_context,
                        budget=norm["budget"],
                    )

    # Stage B: Cold CapabilityGap -> ToolRegistry -> ToolResolver path
    if not reuse_hit:
        goal_contract: Dict[str, Any] = {
            "goal_id": task_id,
            "required_capabilities": [capability],
            "input_artifacts": norm["input_artifacts"],
            "expected_outputs": norm["expected_outputs"],
            "budget": norm["budget"],
        }
        gap_obj = active_gap_detector.analyze(goal_contract, active_registry, security_context)
        resolution_obj = active_resolver.resolve(
            gap_obj,
            active_registry,
            security_context,
            experience_store=experience_store,
        )
        total_tools = len(active_registry.list_tools())
        candidates_evaluated = max(1, total_tools)
        discovery_steps = 2 + total_tools
        if resolution_obj.executable:
            resolved_tool = resolution_obj.selected_tools.get(capability)
        else:
            resolved_tool = None
            plan_source = "UNRESOLVED_GAP"

    discovery_ms = round((time.perf_counter() - discovery_t0) * 1000.0, 3)

    # Stage C: SecureRunner + OracleVerification (always re-verifies all 6 security checks)
    exec_t0 = time.perf_counter()
    resolved_tool_id = resolved_tool.tool_id if resolved_tool is not None else None
    plan_hash = sha256_digest(
        {
            "task_id": task_id,
            "capability": capability,
            "task_fingerprint": task_fingerprint,
            "plan_source": plan_source,
            "tool_id": resolved_tool_id,
        }
    )
    receipt = active_runner.run(
        resolved_tool,
        args=args,
        security_context=security_context,
        oracle=oracle,
        task_id=task_id,
        capability=capability,
        plan_hash=plan_hash,
    )
    execution_ms = round((time.perf_counter() - exec_t0) * 1000.0, 3)

    # Stage D: ExperienceStore persistence ONLY for verified PASS outcomes
    exp_t0 = time.perf_counter()
    recorded_experience: Optional[Experience] = None
    reuse_count = int(matched_experience.reuse_count) if matched_experience is not None else 0

    if (
        experience_store is not None
        and receipt.status == ExecutionStatus.PASS
        and receipt.verification_status == "PASS"
        and resolved_tool_id
    ):
        exp_payload = Experience(
            task_fingerprint=task_fingerprint,
            failure_class=capability,
            tool_or_plan_id=resolved_tool_id,
            input_characteristics={
                "capability": capability,
                "arg_keys": sorted(str(k) for k in args.keys()),
            },
            verified_outcome="PASS",
            cost={
                "wall_time_ms": float(receipt.resource_metrics.get("wall_time_ms", execution_ms)),
                "llm_calls": 0,
            },
            reuse_count=0,
            cross_task_transfer_evidence=[
                {
                    "task_id": task_id,
                    "plan_source": plan_source,
                }
            ],
            trace_hash=receipt.trace_digest,
            tool_hash=receipt.tool_hash,
            security_profile=active_profile,
        )
        recorded_experience = experience_store.record(exp_payload)
        reuse_count = int(recorded_experience.reuse_count)

    experience_ms = round((time.perf_counter() - exp_t0) * 1000.0, 3)
    total_ms = round((time.perf_counter() - slice_t0) * 1000.0, 3)

    telemetry: Dict[str, Any] = {
        "total_ms": total_ms,
        "discovery_ms": discovery_ms,
        "execution_ms": execution_ms,
        "experience_ms": experience_ms,
        "discovery_steps": discovery_steps,
        "candidates_evaluated": candidates_evaluated,
        "skipped_gap_discovery": skipped_gap_discovery,
        "plan_source": plan_source,
        "reuse_hit": reuse_hit,
        "reuse_count": reuse_count,
        "llm_calls": 0,
    }

    return Stage1ExecutionResult(
        task_id=task_id,
        capability=capability,
        task_fingerprint=task_fingerprint,
        status=receipt.status.value,
        verification_status=receipt.verification_status,
        receipt=receipt,
        capability_gap=gap_obj.to_dict() if gap_obj is not None else {},
        resolved_tool_id=resolved_tool_id,
        experience=recorded_experience,
        reuse_hit=reuse_hit,
        reuse_count=reuse_count,
        llm_calls=int(receipt.llm_calls),
        resolution=resolution_obj.to_dict() if resolution_obj is not None else None,
        telemetry=telemetry,
    )
