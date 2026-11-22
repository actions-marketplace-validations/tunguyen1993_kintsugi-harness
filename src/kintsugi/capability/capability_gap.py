"""Capability gap detector distinguishing verified, discovered-unverified, quarantined, and missing tools."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from kintsugi.capability.capability_graph import (
    CapabilityGraph,
    CompatibilityResult,
    tool_violates_security_context,
)
from kintsugi.capability.schemas import (
    CapabilityGap,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    has_valid_verification_attestation,
)
from kintsugi.capability.tool_registry import ToolRegistry


def check_tool_budget(spec: ToolSpec, budget: Dict[str, Any]) -> List[str]:
    """Check whether `spec` resource estimates satisfy optional `budget` ceilings."""
    if not budget:
        return []
    reasons: List[str] = []
    max_lat = budget.get("max_latency_ms")
    if max_lat is not None and spec.latency_estimate_ms > float(max_lat):
        reasons.append(f"BUDGET_LATENCY_EXCEEDED:{spec.latency_estimate_ms}>{float(max_lat)}")
    max_mem = budget.get("max_memory_mb")
    if max_mem is not None and spec.memory_estimate_mb > float(max_mem):
        reasons.append(f"BUDGET_MEMORY_EXCEEDED:{spec.memory_estimate_mb}>{float(max_mem)}")
    max_tok = budget.get("max_api_tokens")
    if max_tok is not None and spec.api_token_estimate > int(max_tok):
        reasons.append(f"BUDGET_TOKENS_EXCEEDED:{spec.api_token_estimate}>{int(max_tok)}")
    return reasons


def _filter_artifacts_for_capability(
    items: Sequence[Dict[str, Any]],
    capability: str,
    total_capabilities: int,
) -> List[Dict[str, Any]]:
    filtered: List[Dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        explicit_cap = item.get("capability")
        if explicit_cap is not None:
            if str(explicit_cap) == capability:
                filtered.append(item)
        elif total_capabilities <= 1:
            filtered.append(item)
    return filtered


def evaluate_tool_for_capability(
    spec: ToolSpec,
    capability: str,
    *,
    total_capabilities: int,
    input_artifacts: Sequence[Dict[str, Any]],
    expected_outputs: Sequence[Dict[str, Any]],
    security_context: SecurityContext,
    budget: Dict[str, Any],
    graph: CapabilityGraph,
) -> Tuple[bool, float, List[str]]:
    """
    Evaluate whether `spec` is policy-compliant, budget-compliant, and I/O-compatible
    for `capability`, returning `(policy_and_schema_ok, schema_fit_score, rejection_reasons)`.
    """
    reasons: List[str] = []
    reasons.extend(tool_violates_security_context(spec, security_context))
    reasons.extend(check_tool_budget(spec, budget))

    scoped_inputs = _filter_artifacts_for_capability(input_artifacts, capability, total_capabilities)
    scoped_outputs = _filter_artifacts_for_capability(expected_outputs, capability, total_capabilities)
    io_compat: CompatibilityResult = graph.check_goal_io_compatibility(
        spec,
        input_artifacts=scoped_inputs,
        expected_outputs=scoped_outputs,
        security_context=None,
    )
    if not io_compat.compatible:
        reasons.extend(io_compat.reasons)

    if spec.trust_status == TrustStatus.VERIFIED and not has_valid_verification_attestation(
        spec.verification_attestation, spec.binary_hash, spec.tool_id
    ):
        reasons.append("MISSING_VALID_VERIFICATION_ATTESTATION")

    return (len(reasons) == 0), io_compat.score, reasons


def extract_goal_fields(goal_contract: Union[CapabilityGap, Dict[str, Any]]) -> Dict[str, Any]:
    """Normalize a `CapabilityGap` or `goal_contract` mapping into standard analysis fields."""
    if isinstance(goal_contract, CapabilityGap):
        return {
            "goal_id": goal_contract.goal_id,
            "required_capabilities": list(goal_contract.required_capabilities),
            "input_artifacts": list(goal_contract.input_artifacts),
            "expected_outputs": list(goal_contract.expected_outputs),
            "acceptance_tests": list(goal_contract.acceptance_tests),
            "budget": dict(goal_contract.budget),
        }
    if not isinstance(goal_contract, dict):
        raise ValueError("INVALID_GOAL_CONTRACT: expected CapabilityGap or dict.")
    return {
        "goal_id": str(goal_contract.get("goal_id", "")),
        "required_capabilities": list(goal_contract.get("required_capabilities", [])),
        "input_artifacts": list(goal_contract.get("input_artifacts", [])),
        "expected_outputs": list(goal_contract.get("expected_outputs", [])),
        "acceptance_tests": list(goal_contract.get("acceptance_tests", [])),
        "budget": dict(goal_contract.get("budget", {})),
    }


class CapabilityGapDetector:
    """Deterministic analyzer classifying required capabilities by verification & policy readiness."""

    def analyze(
        self,
        goal_contract: Union[CapabilityGap, Dict[str, Any]],
        registry: ToolRegistry,
        security_context: SecurityContext,
    ) -> CapabilityGap:
        """
        Analyze `goal_contract` against `registry` and `security_context` without executing tools
        or invoking LLMs (`llm_calls=0`).
        """
        if not isinstance(registry, ToolRegistry):
            raise ValueError("INVALID_REGISTRY: expected ToolRegistry instance.")
        if not isinstance(security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext instance.")

        fields = extract_goal_fields(goal_contract)
        req_caps = [str(c) for c in fields["required_capabilities"]]
        input_artifacts = fields["input_artifacts"]
        expected_outputs = fields["expected_outputs"]
        acceptance_tests = fields["acceptance_tests"]
        budget = fields["budget"]

        graph = CapabilityGraph.from_registry(registry)

        available: List[str] = []
        discovered_unverified: List[str] = []
        quarantined: List[str] = []
        blocked_by_policy: List[str] = []
        missing: List[str] = []

        total_caps = len(req_caps)
        for cap in req_caps:
            candidates = registry.search_capability(cap, include_unverified=True)
            active = [c for c in candidates if c.trust_status != TrustStatus.RETIRED]
            if not active:
                missing.append(cap)
                continue

            has_verified_ok = False
            has_discovered_ok = False
            has_quarantined = False
            has_blocked_active = False

            for spec in active:
                if spec.trust_status == TrustStatus.QUARANTINED:
                    has_quarantined = True
                    continue
                ok, _score, _reasons = evaluate_tool_for_capability(
                    spec,
                    cap,
                    total_capabilities=total_caps,
                    input_artifacts=input_artifacts,
                    expected_outputs=expected_outputs,
                    security_context=security_context,
                    budget=budget,
                    graph=graph,
                )
                if spec.trust_status == TrustStatus.VERIFIED:
                    if ok:
                        has_verified_ok = True
                        break
                    has_blocked_active = True
                elif spec.trust_status == TrustStatus.DISCOVERED:
                    if ok:
                        has_discovered_ok = True
                    else:
                        has_blocked_active = True

            if has_verified_ok:
                available.append(cap)
            elif has_discovered_ok:
                discovered_unverified.append(cap)
            elif has_quarantined:
                quarantined.append(cap)
            elif has_blocked_active:
                blocked_by_policy.append(cap)
            else:
                missing.append(cap)

        return CapabilityGap(
            goal_id=fields["goal_id"],
            required_capabilities=req_caps,
            available_capabilities=available,
            missing_capabilities=missing,
            input_artifacts=input_artifacts,
            expected_outputs=expected_outputs,
            acceptance_tests=acceptance_tests,
            security_context=security_context,
            budget=budget,
            discovered_unverified_capabilities=discovered_unverified,
            quarantined_capabilities=quarantined,
            blocked_by_policy_capabilities=blocked_by_policy,
        )
