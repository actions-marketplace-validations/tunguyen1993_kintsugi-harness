"""Deterministic-first tool resolver enforcing verification, least privilege, and experience ranking."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from kintsugi.capability.capability_gap import (
    CapabilityGapDetector,
    evaluate_tool_for_capability,
)
from kintsugi.capability.capability_graph import CapabilityGraph
from kintsugi.capability.schemas import (
    CapabilityGap,
    Experience,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry


class ResolutionStatus(str, Enum):
    """Explicit outcome states preventing unverified or quarantined execution."""

    VERIFIED = "VERIFIED"
    QUARANTINED = "QUARANTINED"
    NO_VERIFIED_TOOL = "NO_VERIFIED_TOOL"


@dataclass
class RankedCandidate:
    """Deterministic ranking metadata for an eligible `VERIFIED` tool candidate."""

    tool_id: str
    capability: str
    trust_status: TrustStatus
    experience_score: int
    schema_fit_score: float
    permission_count: int
    side_effect_count: int
    api_token_estimate: int
    latency_estimate_ms: float
    memory_estimate_mb: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "capability": self.capability,
            "trust_status": self.trust_status.value,
            "experience_score": self.experience_score,
            "schema_fit_score": round(self.schema_fit_score, 6),
            "permission_count": self.permission_count,
            "side_effect_count": self.side_effect_count,
            "api_token_estimate": self.api_token_estimate,
            "latency_estimate_ms": self.latency_estimate_ms,
            "memory_estimate_mb": self.memory_estimate_mb,
        }


@dataclass
class CapabilityResolution:
    """Per-capability resolution status, selected verified tool, and rejection diagnostics."""

    capability: str
    status: ResolutionStatus
    selected_tool: Optional[ToolSpec] = None
    ranked_candidates: List[RankedCandidate] = field(default_factory=list)
    rejected_candidates: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability,
            "status": self.status.value,
            "selected_tool_id": self.selected_tool.tool_id if self.selected_tool else None,
            "ranked_candidates": [c.to_dict() for c in self.ranked_candidates],
            "rejected_candidates": list(self.rejected_candidates),
        }


@dataclass
class ResolutionResult:
    """Deterministic resolution report (`ResolutionResult/1`) with `llm_calls=0`."""

    goal_id: str
    status: ResolutionStatus
    executable: bool
    selected_tools: Dict[str, ToolSpec] = field(default_factory=dict)
    per_capability: Dict[str, CapabilityResolution] = field(default_factory=dict)
    capability_gap: Optional[CapabilityGap] = None
    llm_calls: int = 0
    resolution_digest: str = ""
    schema: str = "ResolutionResult/1"

    def __post_init__(self) -> None:
        if not self.resolution_digest:
            self.resolution_digest = sha256_digest(self.to_dict(include_digest=False))

    def to_dict(self, *, include_digest: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema": self.schema,
            "goal_id": self.goal_id,
            "status": self.status.value,
            "executable": self.executable,
            "selected_tool_ids": {cap: spec.tool_id for cap, spec in sorted(self.selected_tools.items())},
            "per_capability": {cap: res.to_dict() for cap, res in sorted(self.per_capability.items())},
            "capability_gap": self.capability_gap.to_dict() if self.capability_gap else None,
            "llm_calls": self.llm_calls,
        }
        if include_digest:
            payload["resolution_digest"] = self.resolution_digest
        return payload


def _normalize_experiences(experience_store: Any) -> List[Experience]:
    if experience_store is None:
        return []
    raw_items: Any = experience_store
    if hasattr(experience_store, "list_experiences") and callable(experience_store.list_experiences):
        raw_items = experience_store.list_experiences()
    elif hasattr(experience_store, "all") and callable(experience_store.all):
        raw_items = experience_store.all()
    elif hasattr(experience_store, "experiences"):
        raw_items = experience_store.experiences

    normalized: List[Experience] = []
    for item in raw_items or ():
        if isinstance(item, Experience):
            normalized.append(item)
        elif isinstance(item, dict):
            normalized.append(Experience.from_dict(item))
    return normalized


def _compute_experience_score(
    spec: ToolSpec,
    experiences: Sequence[Experience],
    security_context: SecurityContext,
) -> int:
    score = 0
    for exp in experiences:
        if exp.tool_or_plan_id != spec.tool_id:
            continue
        if exp.tool_hash and exp.tool_hash != spec.binary_hash:
            continue
        profile_weight = 2 if exp.security_profile == security_context.profile else 1
        if exp.is_positive_verified:
            evidence_bonus = 1 + exp.reuse_count + len(exp.cross_task_transfer_evidence)
            score += evidence_bonus * profile_weight
        else:
            penalty = 1 + len(exp.failure_reasons)
            score -= penalty * profile_weight
    return score


class ToolResolver:
    """
    Deterministic-first (`llm_calls=0`) resolver ranking verified tools by:
    `verified > reuse/experience > schema+semantic fit > permissions least-privilege > lower cost/latency`.
    """

    def __init__(self, gap_detector: Optional[CapabilityGapDetector] = None) -> None:
        self._gap_detector = gap_detector or CapabilityGapDetector()

    def resolve(
        self,
        capability_gap_or_goal: Union[CapabilityGap, Dict[str, Any]],
        registry: ToolRegistry,
        security_context: SecurityContext,
        experience_store: Optional[Any] = None,
    ) -> ResolutionResult:
        """
        Resolve required capabilities to `VERIFIED`, policy-compliant tools deterministically.

        Quarantined, unverified (`DISCOVERED`/`RETIRED`), and over-privileged tools are never
        selected for execution.
        """
        if not isinstance(registry, ToolRegistry):
            raise ValueError("INVALID_REGISTRY: expected ToolRegistry instance.")
        if not isinstance(security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext instance.")

        if isinstance(capability_gap_or_goal, CapabilityGap):
            gap = capability_gap_or_goal
        else:
            gap = self._gap_detector.analyze(capability_gap_or_goal, registry, security_context)

        experiences = _normalize_experiences(experience_store)
        graph = CapabilityGraph.from_registry(registry)
        total_caps = len(gap.required_capabilities)

        selected_tools: Dict[str, ToolSpec] = {}
        per_capability: Dict[str, CapabilityResolution] = {}

        for cap in gap.required_capabilities:
            candidates = registry.search_capability(cap, include_unverified=True)
            eligible_pairs: List[Tuple[Tuple[Any, ...], RankedCandidate, ToolSpec]] = []
            rejected: List[Dict[str, Any]] = []
            saw_quarantined = False
            saw_discovered = False

            for spec in candidates:
                if spec.trust_status == TrustStatus.QUARANTINED:
                    saw_quarantined = True
                    rejected.append(
                        {
                            "tool_id": spec.tool_id,
                            "trust_status": spec.trust_status.value,
                            "reasons": [str(spec.provenance.get("quarantine_reason", "QUARANTINED_TOOL"))],
                        }
                    )
                    continue
                if spec.trust_status == TrustStatus.DISCOVERED:
                    saw_discovered = True
                    rejected.append(
                        {
                            "tool_id": spec.tool_id,
                            "trust_status": spec.trust_status.value,
                            "reasons": ["UNVERIFIED_DISCOVERED_TOOL"],
                        }
                    )
                    continue
                if spec.trust_status == TrustStatus.RETIRED:
                    rejected.append(
                        {
                            "tool_id": spec.tool_id,
                            "trust_status": spec.trust_status.value,
                            "reasons": ["RETIRED_TOOL"],
                        }
                    )
                    continue

                ok, schema_fit, reasons = evaluate_tool_for_capability(
                    spec,
                    cap,
                    total_capabilities=total_caps,
                    input_artifacts=gap.input_artifacts,
                    expected_outputs=gap.expected_outputs,
                    security_context=security_context,
                    budget=gap.budget,
                    graph=graph,
                )
                if not ok:
                    rejected.append(
                        {
                            "tool_id": spec.tool_id,
                            "trust_status": spec.trust_status.value,
                            "reasons": reasons,
                        }
                    )
                    continue

                exp_score = _compute_experience_score(spec, experiences, security_context)
                perm_count = len(set(spec.required_permissions))
                side_effect_count = len(
                    [se for se in spec.side_effects if str(se).strip().lower() not in {"", "none"}]
                )
                sort_key = (
                    0,
                    -exp_score,
                    -round(schema_fit, 6),
                    perm_count,
                    side_effect_count,
                    spec.api_token_estimate,
                    spec.latency_estimate_ms,
                    spec.memory_estimate_mb,
                    spec.tool_id,
                )
                ranked = RankedCandidate(
                    tool_id=spec.tool_id,
                    capability=cap,
                    trust_status=spec.trust_status,
                    experience_score=exp_score,
                    schema_fit_score=schema_fit,
                    permission_count=perm_count,
                    side_effect_count=side_effect_count,
                    api_token_estimate=spec.api_token_estimate,
                    latency_estimate_ms=spec.latency_estimate_ms,
                    memory_estimate_mb=spec.memory_estimate_mb,
                )
                eligible_pairs.append((sort_key, ranked, spec))

            if eligible_pairs:
                eligible_pairs.sort(key=lambda item: item[0])
                top_spec = eligible_pairs[0][2]
                selected_tools[cap] = top_spec
                per_capability[cap] = CapabilityResolution(
                    capability=cap,
                    status=ResolutionStatus.VERIFIED,
                    selected_tool=top_spec,
                    ranked_candidates=[item[1] for item in eligible_pairs],
                    rejected_candidates=rejected,
                )
            else:
                cap_status = (
                    ResolutionStatus.QUARANTINED
                    if (saw_quarantined and not saw_discovered)
                    else ResolutionStatus.NO_VERIFIED_TOOL
                )
                per_capability[cap] = CapabilityResolution(
                    capability=cap,
                    status=cap_status,
                    selected_tool=None,
                    ranked_candidates=[],
                    rejected_candidates=rejected,
                )

        cap_statuses = [res.status for res in per_capability.values()]
        if cap_statuses and all(st == ResolutionStatus.VERIFIED for st in cap_statuses):
            overall_status = ResolutionStatus.VERIFIED
            executable = True
        elif any(st == ResolutionStatus.QUARANTINED for st in cap_statuses) and not any(
            st == ResolutionStatus.NO_VERIFIED_TOOL for st in cap_statuses
        ):
            overall_status = ResolutionStatus.QUARANTINED
            executable = False
        else:
            overall_status = ResolutionStatus.NO_VERIFIED_TOOL
            executable = False

        return ResolutionResult(
            goal_id=gap.goal_id,
            status=overall_status,
            executable=executable,
            selected_tools=selected_tools,
            per_capability=per_capability,
            capability_gap=gap,
            llm_calls=0,
        )
