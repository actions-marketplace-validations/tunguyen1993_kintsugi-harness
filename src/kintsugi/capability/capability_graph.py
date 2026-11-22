"""Deterministic capability index and 6-dimension edge/schema compatibility checker."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from kintsugi.capability.schemas import (
    SecurityContext,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import ToolRegistry

COMPATIBILITY_DIMENSIONS: Tuple[str, ...] = (
    "type",
    "semantic_contract",
    "encoding",
    "units",
    "ordering",
    "permissions",
)
_WILDCARD_VALUES = frozenset({"", "any", "*"})
_NETWORK_TOKENS = frozenset({"network", "network.outbound", "network.inbound", "http", "https", "socket"})


def _norm_token(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _extract_dimension(schema_dict: Dict[str, Any], semantic_dict: Dict[str, Any], key: str) -> str:
    if key in schema_dict and schema_dict.get(key) is not None:
        return _norm_token(schema_dict.get(key))
    if key in semantic_dict and semantic_dict.get(key) is not None:
        return _norm_token(semantic_dict.get(key))
    return ""


def tool_violates_security_context(
    spec: ToolSpec,
    security_context: SecurityContext,
) -> List[str]:
    """Return list of policy denial reasons if `spec` exceeds `security_context` boundaries."""
    reasons: List[str] = []
    allowed = set(security_context.allowed_permissions)
    missing_perms = sorted(set(spec.required_permissions) - allowed)
    if missing_perms:
        reasons.append(f"OVER_PRIVILEGED_PERMISSIONS:{','.join(missing_perms)}")

    if not security_context.network_allowed:
        net_reqs = [
            tok
            for tok in list(spec.required_permissions) + list(spec.side_effects)
            if _norm_token(tok) in _NETWORK_TOKENS or _norm_token(tok).startswith("network.")
        ]
        if net_reqs or spec.runtime_requirements.get("network") is True:
            reasons.append("NETWORK_DISALLOWED_BY_POLICY")

    if not security_context.allow_untrusted_native:
        is_untrusted_native = (
            spec.source.lower() in {"untrusted_native", "native_untrusted"}
            or bool(spec.runtime_requirements.get("untrusted_native"))
        )
        if is_untrusted_native:
            reasons.append("UNTRUSTED_NATIVE_DISALLOWED_BY_POLICY")

    return reasons


@dataclass
class CompatibilityResult:
    """Result of 6-dimension compatibility verification between producer and consumer."""

    compatible: bool
    reasons: List[str] = field(default_factory=list)
    score: float = 1.0
    checked_dimensions: Tuple[str, ...] = COMPATIBILITY_DIMENSIONS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compatible": self.compatible,
            "reasons": list(self.reasons),
            "score": round(self.score, 6),
            "checked_dimensions": list(self.checked_dimensions),
        }


def check_contract_compatibility(
    producer_output: Dict[str, Any],
    producer_semantic: Dict[str, Any],
    consumer_input: Dict[str, Any],
    consumer_semantic: Dict[str, Any],
    *,
    producer_postconditions: Sequence[str] = (),
    producer_side_effects: Sequence[str] = (),
    producer_permissions: Sequence[str] = (),
    consumer_permissions: Sequence[str] = (),
    security_context: Optional[SecurityContext] = None,
) -> CompatibilityResult:
    """
    Verify compatibility across `type`, `semantic_contract`, `encoding`, `units`, `ordering`,
    and `permissions`.
    """
    reasons: List[str] = []
    fit_points = 0.0
    max_points = 6.0

    # 1. Type & required field structural check
    out_type = _norm_token(producer_output.get("type"))
    in_type = _norm_token(consumer_input.get("type"))
    if out_type in _WILDCARD_VALUES or in_type in _WILDCARD_VALUES:
        fit_points += 0.7
    elif out_type == in_type or (out_type == "integer" and in_type == "number"):
        fit_points += 1.0
    else:
        reasons.append(f"TYPE_MISMATCH:{out_type or 'unspecified'}!={in_type or 'unspecified'}")

    req_fields = [str(x) for x in (consumer_input.get("required") or [])]
    out_props = producer_output.get("properties")
    if req_fields and isinstance(out_props, dict):
        missing_fields = [f for f in req_fields if f not in out_props]
        if missing_fields:
            reasons.append(f"TYPE_MISSING_REQUIRED_FIELDS:{','.join(sorted(missing_fields))}")

    # 2. Semantic contract compatibility
    semantic_keys = ("domain", "kind", "concept", "format", "schema", "contract", "profile")
    sem_mismatch = False
    sem_matches = 0
    for skey in semantic_keys:
        pv = _norm_token(producer_semantic.get(skey))
        cv = _norm_token(consumer_semantic.get(skey))
        if pv not in _WILDCARD_VALUES and cv not in _WILDCARD_VALUES:
            if pv != cv:
                reasons.append(f"SEMANTIC_CONTRACT_MISMATCH:{skey}:{pv}!={cv}")
                sem_mismatch = True
            else:
                sem_matches += 1
        elif cv not in _WILDCARD_VALUES and pv in _WILDCARD_VALUES:
            reasons.append(f"SEMANTIC_CONTRACT_UNSPECIFIED:{skey}:{cv}")
            sem_mismatch = True

    req_invariants = {str(x) for x in (consumer_semantic.get("invariants") or [])}
    if req_invariants:
        avail_invariants = {str(x) for x in (producer_semantic.get("invariants") or [])} | {
            str(x) for x in producer_postconditions
        }
        missing_inv = sorted(req_invariants - avail_invariants)
        if missing_inv:
            reasons.append(f"SEMANTIC_INVARIANT_MISMATCH:{','.join(missing_inv)}")
            sem_mismatch = True
    if not sem_mismatch:
        fit_points += 1.0 if sem_matches > 0 else 0.7

    # 3. Encoding compatibility
    out_enc = _extract_dimension(producer_output, producer_semantic, "encoding")
    in_enc = _extract_dimension(consumer_input, consumer_semantic, "encoding")
    if in_enc in _WILDCARD_VALUES:
        fit_points += 0.8 if out_enc else 0.7
    elif out_enc == in_enc:
        fit_points += 1.0
    else:
        reasons.append(f"ENCODING_MISMATCH:{out_enc or 'unspecified'}!={in_enc}")

    # 4. Units compatibility (dimensional homogeneity)
    out_units = _extract_dimension(producer_output, producer_semantic, "units") or _extract_dimension(
        producer_output, producer_semantic, "unit"
    )
    in_units = _extract_dimension(consumer_input, consumer_semantic, "units") or _extract_dimension(
        consumer_input, consumer_semantic, "unit"
    )
    if in_units in _WILDCARD_VALUES:
        fit_points += 0.8 if out_units else 0.7
    elif out_units == in_units:
        fit_points += 1.0
    else:
        reasons.append(f"UNITS_MISMATCH:{out_units or 'unspecified'}!={in_units}")

    # 5. Ordering compatibility
    out_ord = _extract_dimension(producer_output, producer_semantic, "ordering")
    in_ord = _extract_dimension(consumer_input, consumer_semantic, "ordering")
    if in_ord in _WILDCARD_VALUES or in_ord == "unordered":
        fit_points += 0.8 if out_ord else 0.7
    elif out_ord == in_ord:
        fit_points += 1.0
    else:
        reasons.append(f"ORDERING_MISMATCH:{out_ord or 'unspecified'}!={in_ord}")

    # 6. Permissions & side-effect boundary compatibility
    perm_ok = True
    allowed_side_effects = consumer_semantic.get("allowed_producer_side_effects")
    if allowed_side_effects is not None:
        allowed_se_set = {_norm_token(x) for x in allowed_side_effects}
        bad_se = sorted(
            str(se)
            for se in producer_side_effects
            if _norm_token(se) not in {"", "none"} and _norm_token(se) not in allowed_se_set
        )
        if bad_se:
            reasons.append(f"SIDE_EFFECT_PERMISSION_MISMATCH:{','.join(bad_se)}")
            perm_ok = False

    if security_context is not None:
        allowed_perms = set(security_context.allowed_permissions)
        all_req = set(producer_permissions) | set(consumer_permissions)
        missing_p = sorted(all_req - allowed_perms)
        if missing_p:
            reasons.append(f"PERMISSIONS_EXCEED_CONTEXT:{','.join(missing_p)}")
            perm_ok = False
        if not security_context.network_allowed:
            net_hits = [
                p
                for p in list(all_req) + list(producer_side_effects)
                if _norm_token(p) in _NETWORK_TOKENS or _norm_token(p).startswith("network.")
            ]
            if net_hits:
                reasons.append("PERMISSIONS_NETWORK_DISALLOWED")
                perm_ok = False

    if perm_ok:
        fit_points += 1.0

    score = max(0.0, min(1.0, fit_points / max_points))
    return CompatibilityResult(
        compatible=(len(reasons) == 0),
        reasons=reasons,
        score=score if not reasons else 0.0,
    )


class CapabilityGraph:
    """Deterministic index of capabilities, I/O types, side-effects, permissions, and composition edges."""

    def __init__(self, tools: Optional[Sequence[ToolSpec]] = None) -> None:
        self._tools: Dict[str, ToolSpec] = {}
        self.capability_to_tools: Dict[str, List[str]] = {}
        self.tool_io_index: Dict[str, Dict[str, Any]] = {}
        self.side_effect_index: Dict[str, List[str]] = {}
        self.permission_index: Dict[str, List[str]] = {}
        for spec in tools or ():
            self._tools[spec.tool_id] = spec
        self._rebuild_indexes()

    @classmethod
    def from_registry(cls, registry: ToolRegistry, *, verified_only: bool = False) -> "CapabilityGraph":
        """Build a deterministic `CapabilityGraph` snapshot from a `ToolRegistry`."""
        statuses = (TrustStatus.VERIFIED,) if verified_only else None
        return cls(registry.list_tools(trust_statuses=statuses))

    def add_tool(self, spec: ToolSpec) -> None:
        """Add or update a tool node and deterministically rebuild graph indexes."""
        self._tools[spec.tool_id] = spec
        self._rebuild_indexes()

    def _rebuild_indexes(self) -> None:
        cap_map: Dict[str, Set[str]] = {}
        se_map: Dict[str, Set[str]] = {}
        perm_map: Dict[str, Set[str]] = {}
        io_map: Dict[str, Dict[str, Any]] = {}

        for tool_id in sorted(self._tools.keys()):
            spec = self._tools[tool_id]
            for cap in spec.capabilities:
                cap_map.setdefault(cap, set()).add(tool_id)
            for se in spec.side_effects or ["none"]:
                se_map.setdefault(se, set()).add(tool_id)
            for perm in spec.required_permissions:
                perm_map.setdefault(perm, set()).add(tool_id)
            io_map[tool_id] = {
                "tool_id": tool_id,
                "trust_status": spec.trust_status.value,
                "capabilities": sorted(spec.capabilities),
                "input_schema": dict(spec.input_schema),
                "output_schema": dict(spec.output_schema),
                "semantic_contract": dict(spec.semantic_contract),
                "side_effects": list(spec.side_effects),
                "required_permissions": list(spec.required_permissions),
            }

        self.capability_to_tools = {k: sorted(v) for k, v in sorted(cap_map.items())}
        self.side_effect_index = {k: sorted(v) for k, v in sorted(se_map.items())}
        self.permission_index = {k: sorted(v) for k, v in sorted(perm_map.items())}
        self.tool_io_index = io_map

    def get_tools_for_capability(self, capability: str) -> List[str]:
        """Return deterministically sorted `tool_id`s indexed for `capability`."""
        return list(self.capability_to_tools.get(capability, []))

    def check_edge_compatibility(
        self,
        producer: ToolSpec,
        consumer: ToolSpec,
        security_context: Optional[SecurityContext] = None,
    ) -> CompatibilityResult:
        """Check whether `producer` output satisfies `consumer` input across all 6 contract dimensions."""
        return check_contract_compatibility(
            producer_output=producer.output_schema,
            producer_semantic=producer.semantic_contract,
            consumer_input=consumer.input_schema,
            consumer_semantic=consumer.semantic_contract,
            producer_postconditions=producer.postconditions,
            producer_side_effects=producer.side_effects,
            producer_permissions=producer.required_permissions,
            consumer_permissions=consumer.required_permissions,
            security_context=security_context,
        )

    def can_compose(
        self,
        producer_id: str,
        consumer_id: str,
        security_context: Optional[SecurityContext] = None,
    ) -> CompatibilityResult:
        """Check compatibility between two indexed tools by `tool_id`."""
        producer = self._tools.get(producer_id)
        consumer = self._tools.get(consumer_id)
        if producer is None or consumer is None:
            missing = [tid for tid, obj in ((producer_id, producer), (consumer_id, consumer)) if obj is None]
            return CompatibilityResult(compatible=False, reasons=[f"UNKNOWN_TOOL:{','.join(missing)}"], score=0.0)
        return self.check_edge_compatibility(producer, consumer, security_context=security_context)

    def check_goal_io_compatibility(
        self,
        tool: ToolSpec,
        input_artifacts: Sequence[Dict[str, Any]] = (),
        expected_outputs: Sequence[Dict[str, Any]] = (),
        security_context: Optional[SecurityContext] = None,
    ) -> CompatibilityResult:
        """Check `tool` I/O schemas and semantic contract against goal input/output specifications."""
        reasons: List[str] = []
        scores: List[float] = []

        if security_context is not None:
            reasons.extend(tool_violates_security_context(tool, security_context))

        for artifact in input_artifacts:
            if not isinstance(artifact, dict):
                continue
            target_cap = artifact.get("capability")
            if target_cap and str(target_cap) not in tool.capabilities:
                continue
            art_schema = dict(artifact.get("schema") or artifact)
            art_sem = dict(artifact.get("semantic_contract") or {})
            if tool.input_schema or tool.semantic_contract:
                res = check_contract_compatibility(
                    producer_output=art_schema,
                    producer_semantic=art_sem,
                    consumer_input=tool.input_schema,
                    consumer_semantic=tool.semantic_contract,
                )
                if not res.compatible:
                    reasons.extend(f"INPUT:{r}" for r in res.reasons)
                else:
                    scores.append(res.score)

        for expected in expected_outputs:
            if not isinstance(expected, dict):
                continue
            target_cap = expected.get("capability")
            if target_cap and str(target_cap) not in tool.capabilities:
                continue
            exp_schema = dict(expected.get("schema") or expected)
            exp_sem = dict(expected.get("semantic_contract") or {})
            res = check_contract_compatibility(
                producer_output=tool.output_schema,
                producer_semantic=tool.semantic_contract,
                consumer_input=exp_schema,
                consumer_semantic=exp_sem,
                producer_postconditions=tool.postconditions,
                producer_side_effects=tool.side_effects,
                producer_permissions=tool.required_permissions,
                security_context=security_context,
            )
            if not res.compatible:
                reasons.extend(f"OUTPUT:{r}" for r in res.reasons)
            else:
                scores.append(res.score)

        if reasons:
            return CompatibilityResult(compatible=False, reasons=reasons, score=0.0)
        avg_score = sum(scores) / len(scores) if scores else 0.75
        return CompatibilityResult(compatible=True, reasons=[], score=avg_score)

    def compute_compatible_edges(
        self,
        *,
        verified_only: bool = False,
        security_context: Optional[SecurityContext] = None,
    ) -> Dict[str, List[str]]:
        """Build deterministic adjacency list of compatible `(producer -> consumer)` tool compositions."""
        tool_ids = sorted(self._tools.keys())
        if verified_only:
            tool_ids = [tid for tid in tool_ids if self._tools[tid].trust_status == TrustStatus.VERIFIED]
        edges: Dict[str, List[str]] = {tid: [] for tid in tool_ids}
        for src_id in tool_ids:
            src_tool = self._tools[src_id]
            for dst_id in tool_ids:
                if src_id == dst_id:
                    continue
                dst_tool = self._tools[dst_id]
                if self.check_edge_compatibility(src_tool, dst_tool, security_context=security_context).compatible:
                    edges[src_id].append(dst_id)
        return edges

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": "CapabilityGraph/1",
            "capability_to_tools": dict(self.capability_to_tools),
            "side_effect_index": dict(self.side_effect_index),
            "permission_index": dict(self.permission_index),
            "tool_io_index": dict(self.tool_io_index),
        }

    def content_hash(self) -> str:
        return sha256_digest(self.to_dict())
