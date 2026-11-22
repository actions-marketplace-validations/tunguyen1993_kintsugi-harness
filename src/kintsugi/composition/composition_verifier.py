"""Six-dimension zero-trust verifier for DAG `CompositionPlan/1` artifacts (`CompositionVerifier`).

Verifies:
  1. Schema & canonical `plan_hash` integrity (`CompositionPlan/1`) + secret/Trojan hygiene.
  2. Semantic & `PortContract/1` compatibility across every edge (including `AdapterSpec/1`
     coverage without silent `secret -> public` declassification or unit mismatch).
  3. Preconditions / postconditions alignment along the DAG.
  4. Permission union (`<= security_context.allowed_permissions`), `EffectContract/1` union,
     and `TrustStatus.VERIFIED` + matching on-record `tool_artifact_hashes` / `adapter_hashes`
     (strictly rejecting `DISCOVERED`, `QUARANTINED`, `RETIRED`, or hash mismatches).
  5. Acyclicity, canonical deterministic execution order, idempotency on retryable steps,
     and `parallel_execution_groups(plan)` proving parallel groups have disjoint data
     dependencies and non-conflicting side effects / exclusive resources.
  6. Independent replay / oracle output verification (`PASS | FAIL | NOT_VERIFIED`).
"""

from __future__ import annotations

import fnmatch
import heapq
import hmac
import inspect
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.capability_graph import (
    check_contract_compatibility,
    tool_violates_security_context,
)
from kintsugi.capability.contracts_v2 import (
    AdapterSpec,
    CompositionPlan,
    CompositionReceipt,
    EffectContract,
    PortContract,
    compute_dag_effects,
    ports_compatible,
)
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    ToolSpec,
    TrustStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    compute_tool_spec_security_digest,
    has_valid_verification_attestation,
    is_valid_sha256,
    normalize_sha256,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.runtime.secure_runner import _verify_context_policy_integrity
from kintsugi.shield import TROJAN_UNICODE_RE
from kintsugi.tools.proof_pack import ProofPackReport

COMPOSITION_VERIFICATION_SCHEMA = "CompositionVerificationResult/1"
VALID_VERIFICATION_STATUSES = frozenset({"PASS", "FAIL", "NOT_VERIFIED"})

_SENSITIVITY_RANK: Dict[str, int] = {"public": 0, "internal": 1, "secret": 2}
_WILDCARD_SCOPES = frozenset({"*", "**", "all", "workspace", "workspace_write", "fs.write", "unknown"})
_REQUIRED_PLAN_KEYS: Tuple[str, ...] = (
    "schema",
    "plan_id",
    "goal_contract_hash",
    "nodes",
    "edges",
    "input_bindings",
    "tool_artifact_hashes",
    "adapter_hashes",
    "permission_union",
    "effects_union",
    "expected_outputs",
    "oracle_ref",
    "verification_plan",
    "estimated_resources",
    "plan_hash",
)
_PORT_SIGNAL_KEYS = frozenset(
    {
        "schema_ref",
        "semantic_type",
        "unit",
        "units",
        "cardinality",
        "ordering",
        "sensitivity",
        "trust_label",
        "streaming",
        "precision",
        "nullable",
        "port_contract",
    }
)


@dataclass
class CompositionVerificationResult:
    """Structured 6-dimension verification verdict (`CompositionVerificationResult/1`)."""

    valid: bool
    static_valid: bool
    verified: bool
    status: str
    oracle_status: str
    plan_id: str
    plan_hash: str
    execution_order: List[str] = field(default_factory=list)
    parallel_groups: List[List[str]] = field(default_factory=list)
    permission_union: List[str] = field(default_factory=list)
    effects_union: Dict[str, Any] = field(default_factory=dict)
    dimension_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    verification_digest: str = ""
    schema: str = COMPOSITION_VERIFICATION_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != COMPOSITION_VERIFICATION_SCHEMA:
            raise ValueError(f"INVALID_SCHEMA: expected {COMPOSITION_VERIFICATION_SCHEMA}, got '{self.schema}'.")
        norm_status = str(self.status or "").strip().upper()
        if norm_status not in VALID_VERIFICATION_STATUSES:
            raise ValueError(f"INVALID_VERIFICATION_STATUS: {self.status!r}")
        self.status = norm_status
        norm_oracle = str(self.oracle_status or "").strip().upper()
        if norm_oracle not in VALID_VERIFICATION_STATUSES:
            raise ValueError(f"INVALID_ORACLE_STATUS: {self.oracle_status!r}")
        self.oracle_status = norm_oracle
        self.reasons = [redact_secrets_in_text(str(r)) for r in self.reasons]
        if not self.verification_digest:
            self.verification_digest = sha256_digest(self._digest_basis())

    def _digest_basis(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "valid": self.valid,
            "static_valid": self.static_valid,
            "verified": self.verified,
            "status": self.status,
            "oracle_status": self.oracle_status,
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "execution_order": list(self.execution_order),
            "parallel_groups": [list(g) for g in self.parallel_groups],
            "permission_union": list(self.permission_union),
            "effects_union": dict(self.effects_union),
            "dimension_results": dict(self.dimension_results),
            "reasons": list(self.reasons),
        }

    @property
    def ok(self) -> bool:
        return self.valid

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def __bool__(self) -> bool:
        return self.valid

    def to_dict(self) -> Dict[str, Any]:
        payload = self._digest_basis()
        payload["verification_digest"] = self.verification_digest
        return redact_secrets_in_value(payload)

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context=f"CompositionVerificationResult:{self.plan_id}")
        return serialized


def _has_trojan_unicode(value: Any) -> bool:
    if isinstance(value, str):
        return "\x00" in value or bool(TROJAN_UNICODE_RE.search(value))
    if isinstance(value, Mapping):
        return any(_has_trojan_unicode(str(k)) or _has_trojan_unicode(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return any(_has_trojan_unicode(item) for item in value)
    return False


def _plan_to_raw_dict(plan: Union[CompositionPlan, Mapping[str, Any]]) -> Dict[str, Any]:
    if isinstance(plan, CompositionPlan):
        payload: Dict[str, Any] = {
            "schema": plan.schema,
            "plan_id": plan.plan_id,
            "goal_contract_hash": plan.goal_contract_hash,
            "nodes": [dict(n) if isinstance(n, Mapping) else n for n in (plan.nodes or ())],
            "edges": [dict(e) if isinstance(e, Mapping) else e for e in (plan.edges or ())],
            "input_bindings": dict(plan.input_bindings or {}),
            "tool_artifact_hashes": dict(plan.tool_artifact_hashes or {}),
            "adapter_hashes": dict(plan.adapter_hashes or {}),
            "permission_union": list(plan.permission_union or ()),
            "effects_union": dict(plan.effects_union or {}),
            "expected_outputs": (
                dict(plan.expected_outputs)
                if isinstance(plan.expected_outputs, Mapping)
                else list(plan.expected_outputs or ())
            ),
            "oracle_ref": plan.oracle_ref,
            "verification_plan": dict(plan.verification_plan or {}),
            "estimated_resources": dict(plan.estimated_resources or {}),
            "plan_hash": plan.plan_hash,
        }
        for opt_key in ("gap_id", "profile", "max_depth", "security_checks", "created_at"):
            val = getattr(plan, opt_key, None)
            if val is not None:
                payload[opt_key] = val
        return payload
    if isinstance(plan, Mapping):
        return dict(plan)
    raise ValueError("INVALID_PLAN: expected CompositionPlan or mapping.")


def _recompute_plan_hash(plan_dict: Mapping[str, Any]) -> str:
    basis: Dict[str, Any] = {
        "schema": plan_dict.get("schema"),
        "plan_id": plan_dict.get("plan_id"),
        "goal_contract_hash": plan_dict.get("goal_contract_hash"),
        "nodes": list(plan_dict.get("nodes") or ()),
        "edges": list(plan_dict.get("edges") or ()),
        "input_bindings": dict(plan_dict.get("input_bindings") or {}),
        "tool_artifact_hashes": dict(plan_dict.get("tool_artifact_hashes") or {}),
        "adapter_hashes": dict(plan_dict.get("adapter_hashes") or {}),
        "permission_union": sorted(set(str(x) for x in (plan_dict.get("permission_union") or ()))),
        "effects_union": dict(plan_dict.get("effects_union") or {}),
        "expected_outputs": plan_dict.get("expected_outputs", []),
        "oracle_ref": plan_dict.get("oracle_ref"),
        "verification_plan": dict(plan_dict.get("verification_plan") or {}),
        "estimated_resources": dict(plan_dict.get("estimated_resources") or {}),
    }
    for opt_key in ("gap_id", "profile", "max_depth", "security_checks", "created_at"):
        if opt_key in plan_dict and plan_dict[opt_key] is not None:
            basis[opt_key] = plan_dict[opt_key]
    return sha256_digest(basis)


def _lookup_tool(
    registry: Union[ToolRegistry, Mapping[str, ToolSpec]],
    tool_id: str,
) -> Optional[ToolSpec]:
    if isinstance(registry, ToolRegistry):
        try:
            return registry.get(tool_id)
        except ValueError:
            return None
    if isinstance(registry, Mapping):
        spec = registry.get(tool_id)
        if spec is None or isinstance(spec, ToolSpec):
            return spec
        if isinstance(spec, Mapping):
            return ToolSpec.from_dict(dict(spec), from_discovery=False)
    raise ValueError("INVALID_REGISTRY: expected ToolRegistry or mapping of ToolSpec.")


def _normalize_adapters(
    adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None],
) -> Tuple[Dict[str, AdapterSpec], List[str]]:
    parsed: Dict[str, AdapterSpec] = {}
    errors: List[str] = []
    if not adapters:
        return parsed, errors

    items: Iterable[Any]
    if isinstance(adapters, Mapping):
        items = adapters.values()
    else:
        items = adapters

    for idx, raw_item in enumerate(items):
        try:
            spec = AdapterSpec.from_dict(raw_item)
        except Exception as exc:
            aid = raw_item.get("adapter_id", f"idx={idx}") if isinstance(raw_item, Mapping) else getattr(raw_item, "adapter_id", f"idx={idx}")
            errors.append(f"INVALID_ADAPTER:{aid}:{exc}")
            continue
        parsed[spec.adapter_id] = spec
    return parsed, errors


def _has_valid_adapter_attestation_strict(
    adapter: AdapterSpec,
    *,
    authority: Optional[AttestationAuthority] = None,
) -> bool:
    if adapter.trust_status != TrustStatus.VERIFIED:
        return False
    if not adapter.verification_corpus_hash or not is_valid_sha256(adapter.verification_corpus_hash):
        return False
    att = adapter.verification_attestation
    if not isinstance(att, Mapping) or not att:
        return False
    if authority is None or not authority.has_registered_verifiers:
        return False
    return authority.verify_adapter_attestation(
        att,
        expected_adapter_id=adapter.adapter_id,
        expected_adapter_hash=adapter.adapter_hash,
        expected_corpus_hash=adapter.verification_corpus_hash,
    )


def _node_effect_contract(node: Mapping[str, Any], tool: Optional[ToolSpec]) -> EffectContract:
    node_eff = node.get("effect_contract")
    if isinstance(node_eff, (EffectContract, Mapping)) and node_eff:
        return EffectContract.from_dict(node_eff)

    if tool is not None:
        tool_eff = getattr(tool, "effect_contract", None)
        if isinstance(tool_eff, (EffectContract, Mapping)) and tool_eff:
            return EffectContract.from_dict(tool_eff)
        sem_eff = tool.semantic_contract.get("effect_contract")
        if isinstance(sem_eff, Mapping) and sem_eff:
            return EffectContract.from_dict(sem_eff)
        rt_eff = tool.runtime_requirements.get("effect_contract")
        if isinstance(rt_eff, Mapping) and rt_eff:
            return EffectContract.from_dict(rt_eff)

    read_scopes: List[str] = list(node.get("read_scopes") or ())
    write_scopes: List[str] = list(node.get("write_scopes") or ())
    network_scopes: List[str] = list(node.get("network_scopes") or ())
    exec_perms: List[str] = list(tool.required_permissions) if tool is not None else []
    irreversible = bool(node.get("irreversible", False))
    idempotent = bool(node.get("idempotent", True))
    resources: Dict[str, Any] = dict(node.get("resource_requirements") or node.get("resources") or {})

    if tool is not None:
        for se in tool.side_effects:
            se_str = str(se).strip()
            se_low = se_str.lower()
            if not se_low or se_low in {"none", "read_only"}:
                continue
            if se_low.startswith(("read:", "fs.read:")):
                read_scopes.append(se_str.split(":", 1)[1])
            elif se_low.startswith(("write:", "fs.write:")):
                write_scopes.append(se_str.split(":", 1)[1])
            elif se_low in {"workspace_write", "fs.write", "unknown"}:
                write_scopes.append(se_low)
            elif se_low.startswith(("network", "http://", "https://")):
                network_scopes.append(se_str)
            elif se_low == "irreversible":
                irreversible = True
            elif se_low in {"non_idempotent", "not_idempotent"}:
                idempotent = False
        if tool.memory_estimate_mb > 0 and "memory_mb" not in resources:
            resources["memory_mb"] = tool.memory_estimate_mb
        if tool.api_token_estimate > 0 and "api_tokens" not in resources:
            resources["api_tokens"] = tool.api_token_estimate
        for rk in ("exclusive_resources", "locks", "resource_locks", "device", "port"):
            if rk in tool.runtime_requirements and rk not in resources:
                resources[rk] = tool.runtime_requirements[rk]

    if irreversible and "idempotent" not in node and (
        tool is None or "idempotent" not in tool.semantic_contract
    ):
        idempotent = False

    return EffectContract(
        read_scopes=read_scopes,
        write_scopes=write_scopes,
        network_scopes=network_scopes,
        exec_permissions=exec_perms,
        irreversible=irreversible,
        idempotent=idempotent,
        resource_requirements=resources,
    )


def _normalize_scope_token(scope: str) -> str:
    cleaned = scope.strip()
    if cleaned.startswith("ws:"):
        cleaned = cleaned[3:]
    cleaned = cleaned.replace("\\", "/").lstrip("./")
    while "//" in cleaned:
        cleaned = cleaned.replace("//", "/")
    return cleaned.lower()


def _scopes_overlap(scope_a: str, scope_b: str) -> bool:
    a = _normalize_scope_token(scope_a)
    b = _normalize_scope_token(scope_b)
    if not a or not b:
        return False
    if a in _WILDCARD_SCOPES or b in _WILDCARD_SCOPES:
        return True
    if a == b:
        return True
    if fnmatch.fnmatchcase(a, b) or fnmatch.fnmatchcase(b, a):
        return True

    prefix_a = a.rstrip("*").rstrip("/")
    prefix_b = b.rstrip("*").rstrip("/")
    if a.endswith(("*", "/**")) and prefix_a and (b == prefix_a or b.startswith(prefix_a + "/")):
        return True
    if b.endswith(("*", "/**")) and prefix_b and (a == prefix_b or a.startswith(prefix_b + "/")):
        return True
    if (a.endswith("/") and b.startswith(a)) or (b.endswith("/") and a.startswith(b)):
        return True
    if b.startswith(a.rstrip("/") + "/") or a.startswith(b.rstrip("/") + "/"):
        return True
    return False


def _extract_exclusive_resources(eff: EffectContract, node: Mapping[str, Any]) -> Set[str]:
    locks: Set[str] = set()
    for src in (eff.resource_requirements, node.get("resources") or {}, node):
        if not isinstance(src, Mapping):
            continue
        for key in ("exclusive_resources", "locks", "resource_locks"):
            vals = src.get(key)
            if isinstance(vals, (list, tuple, set)):
                locks.update(str(v).strip().lower() for v in vals if str(v).strip())
        for key in ("device", "port", "gpu_id"):
            val = src.get(key)
            if val is not None and str(val).strip():
                locks.add(f"{key}:{str(val).strip().lower()}")
    return locks


def _nodes_conflict_for_parallel(
    node_a: Mapping[str, Any],
    eff_a: EffectContract,
    node_b: Mapping[str, Any],
    eff_b: EffectContract,
) -> Optional[str]:
    # Write-Write conflict
    for wa in eff_a.write_scopes:
        for wb in eff_b.write_scopes:
            if _scopes_overlap(wa, wb):
                return f"WRITE_WRITE_CONFLICT:{wa}<->{wb}"
    # Write-Read conflict
    for wa in eff_a.write_scopes:
        for rb in eff_b.read_scopes:
            if _scopes_overlap(wa, rb):
                return f"WRITE_READ_CONFLICT:{wa}<->{rb}"
    # Read-Write conflict
    for ra in eff_a.read_scopes:
        for wb in eff_b.write_scopes:
            if _scopes_overlap(ra, wb):
                return f"READ_WRITE_CONFLICT:{ra}<->{wb}"
    # Exclusive resource lock conflict
    locks_a = _extract_exclusive_resources(eff_a, node_a)
    locks_b = _extract_exclusive_resources(eff_b, node_b)
    shared_locks = sorted(locks_a & locks_b)
    if shared_locks:
        return f"EXCLUSIVE_RESOURCE_CONFLICT:{','.join(shared_locks)}"
    # Shared irreversible network mutation scopes
    if (eff_a.irreversible or eff_b.irreversible) and eff_a.network_scopes and eff_b.network_scopes:
        shared_net = sorted(set(eff_a.network_scopes) & set(eff_b.network_scopes))
        if shared_net:
            return f"IRREVERSIBLE_NETWORK_CONFLICT:{','.join(shared_net)}"
    return None


def _extract_node_dependencies(
    nodes: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
    input_bindings: Mapping[str, Any],
) -> Tuple[List[str], Dict[str, Set[str]], Dict[str, Set[str]], List[str]]:
    """Build full DAG adjacency (`adj` & `preds`) from edges, `inputs_from`, and `input_bindings`."""
    node_ids: List[str] = []
    seen: Set[str] = set()
    errors: List[str] = []

    for idx, node in enumerate(nodes):
        raw_nid = node.get("node_id")
        if not isinstance(raw_nid, str) or not raw_nid.strip():
            errors.append(f"INVALID_NODE_ID:idx={idx}")
            continue
        nid = raw_nid.strip()
        if nid in seen:
            errors.append(f"DUPLICATE_NODE_ID:{nid}")
            continue
        seen.add(nid)
        node_ids.append(nid)

    adj: Dict[str, Set[str]] = {nid: set() for nid in node_ids}
    preds: Dict[str, Set[str]] = {nid: set() for nid in node_ids}

    def _add_dep(src: str, dst: str, origin: str) -> None:
        if src not in seen or dst not in seen:
            errors.append(f"UNKNOWN_DEPENDENCY_NODE:{origin}:{src}->{dst}")
            return
        if src == dst:
            errors.append(f"SELF_LOOP_DETECTED:{src}")
            return
        adj[src].add(dst)
        preds[dst].add(src)

    for edge in edges:
        src = str(edge.get("from_node") or "").strip()
        dst = str(edge.get("to_node") or "").strip()
        _add_dep(src, dst, "edge")

    for node in nodes:
        nid = str(node.get("node_id") or "").strip()
        if nid not in seen:
            continue
        inputs_from = node.get("inputs_from")
        if isinstance(inputs_from, Mapping):
            for val in inputs_from.values():
                ref_node = _extract_binding_source_node(val)
                if ref_node is not None and ref_node != "goal" and ref_node in seen:
                    _add_dep(ref_node, nid, "inputs_from")

    for dst_key, src_val in (input_bindings or {}).items():
        key_str = str(dst_key).strip()
        if "." not in key_str:
            continue
        dst_node = key_str.split(".", 1)[0].strip()
        if dst_node not in seen:
            continue
        src_node = _extract_binding_source_node(src_val)
        if src_node is not None and src_node != "goal" and src_node in seen:
            _add_dep(src_node, dst_node, "input_bindings")

    return node_ids, adj, preds, errors


def _extract_binding_source_node(val: Any) -> Optional[str]:
    if isinstance(val, str):
        cleaned = val.strip()
        if "." in cleaned:
            return cleaned.split(".", 1)[0].strip()
        return cleaned or None
    if isinstance(val, Mapping):
        if "node_id" in val:
            return str(val["node_id"]).strip()
        if "node" in val:
            return str(val["node"]).strip()
        if "from_node" in val:
            return str(val["from_node"]).strip()
    return None


def _compute_ancestors(node_ids: Sequence[str], preds: Mapping[str, Set[str]]) -> Dict[str, Set[str]]:
    ancestors: Dict[str, Set[str]] = {}
    for nid in node_ids:
        seen: Set[str] = set()
        queue = deque(preds.get(nid, set()))
        while queue:
            cur = queue.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            for p in preds.get(cur, set()):
                if p not in seen:
                    queue.append(p)
        ancestors[nid] = seen
    return ancestors


def _canonical_topological_order(
    node_ids: Sequence[str],
    adj: Mapping[str, Set[str]],
    preds: Mapping[str, Set[str]],
) -> Tuple[List[str], bool]:
    indegree = {nid: len(preds[nid]) for nid in node_ids}
    heap = [nid for nid in node_ids if indegree[nid] == 0]
    heapq.heapify(heap)
    order: List[str] = []
    while heap:
        cur = heapq.heappop(heap)
        order.append(cur)
        for nxt in sorted(adj[cur]):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                heapq.heappush(heap, nxt)
    return order, len(order) == len(node_ids)


def parallel_execution_groups(
    plan: Union[CompositionPlan, Mapping[str, Any]],
    registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
) -> List[List[str]]:
    """
    Compute deterministic parallel execution groups (`List[List[str]]`) from `plan`.

    Proves by construction that two nodes are grouped together ONLY if:
      1. They have disjoint data dependencies (neither is an ancestor of the other).
      2. Their side effects (write-write, write-read, read-write, irreversible network scopes)
         and exclusive resources do not conflict.
    Raises `ValueError` if `plan` contains a cycle or invalid DAG dependencies.
    """
    plan_dict = _plan_to_raw_dict(plan)
    nodes = [dict(n) for n in (plan_dict.get("nodes") or ()) if isinstance(n, Mapping)]
    edges = [dict(e) for e in (plan_dict.get("edges") or ()) if isinstance(e, Mapping)]
    input_bindings = dict(plan_dict.get("input_bindings") or {})

    node_ids, adj, preds, errors = _extract_node_dependencies(nodes, edges, input_bindings)
    if errors:
        raise ValueError(f"INVALID_COMPOSITION_DAG: {'; '.join(errors)}")
    order, is_acyclic = _canonical_topological_order(node_ids, adj, preds)
    if not is_acyclic:
        raise ValueError("INVALID_COMPOSITION_DAG: cycle detected in composition plan.")

    node_map: Dict[str, Dict[str, Any]] = {str(n["node_id"]).strip(): n for n in nodes}
    eff_map: Dict[str, EffectContract] = {}
    for nid in node_ids:
        n = node_map[nid]
        tool = _lookup_tool(registry, str(n.get("tool_id", ""))) if registry is not None else None
        eff_map[nid] = _node_effect_contract(n, tool)

    ancestors = _compute_ancestors(node_ids, preds)
    est_res = dict(plan_dict.get("estimated_resources") or {})
    ver_plan = dict(plan_dict.get("verification_plan") or {})
    max_par = ver_plan.get("max_parallelism") or est_res.get("parallelism")
    max_group_size = max(1, int(max_par)) if max_par is not None else len(node_ids)

    indegree = {nid: len(preds[nid]) for nid in node_ids}
    ready = sorted(nid for nid in node_ids if indegree[nid] == 0)
    completed: Set[str] = set()
    groups: List[List[str]] = []

    while ready:
        current_group: List[str] = []
        deferred: List[str] = []
        for candidate in ready:
            if len(current_group) >= max_group_size:
                deferred.append(candidate)
                continue
            conflicts = False
            for member in current_group:
                if member in ancestors[candidate] or candidate in ancestors[member]:
                    conflicts = True
                    break
                if _nodes_conflict_for_parallel(node_map[member], eff_map[member], node_map[candidate], eff_map[candidate]):
                    conflicts = True
                    break
            if conflicts:
                deferred.append(candidate)
            else:
                current_group.append(candidate)

        if not current_group:
            # Should never happen on an acyclic graph, fail closed safely
            raise ValueError("PARALLEL_SCHEDULING_STALLED")

        groups.append(current_group)
        newly_ready: List[str] = list(deferred)
        for finished in current_group:
            completed.add(finished)
            for nxt in adj[finished]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    newly_ready.append(nxt)
        ready = sorted(newly_ready)

    if len(completed) != len(order):
        raise ValueError("INVALID_COMPOSITION_DAG: cycle detected during parallel grouping.")
    return groups


def _extract_port_from_container(
    container: Mapping[str, Any],
    direction: str,
    port_name: str,
) -> Optional[PortContract]:
    if not isinstance(container, Mapping):
        return None
    plural_key = f"{direction}_ports"
    single_key = f"{direction}_port"
    ports_map = container.get(plural_key)
    if isinstance(ports_map, Mapping):
        cand = ports_map.get(port_name) or ports_map.get("default")
        if isinstance(cand, (PortContract, Mapping)):
            return PortContract.from_dict(cand)
    raw_port = container.get(single_key)
    if isinstance(raw_port, (PortContract, Mapping)):
        return PortContract.from_dict(raw_port)
    return None


def _derive_port_contract(
    node: Mapping[str, Any],
    tool: ToolSpec,
    direction: str,
    port_name: str,
) -> Tuple[Optional[PortContract], bool]:
    """Return `(PortContract, is_explicit)` for a producer `output` or consumer `input` port."""
    explicit_node_port = _extract_port_from_container(node, direction, port_name)
    if explicit_node_port is not None:
        return explicit_node_port, True

    attr_port = getattr(tool, f"{direction}_port", None)
    if isinstance(attr_port, (PortContract, Mapping)):
        return PortContract.from_dict(attr_port), True

    sem_port = _extract_port_from_container(tool.semantic_contract, direction, port_name)
    if sem_port is not None:
        return sem_port, True

    io_schema = tool.output_schema if direction == "output" else tool.input_schema
    if isinstance(io_schema, Mapping):
        if io_schema.get("schema") == "PortContract/1":
            return PortContract.from_dict(io_schema), True
        nested_pc = io_schema.get("port_contract")
        if isinstance(nested_pc, (PortContract, Mapping)):
            return PortContract.from_dict(nested_pc), True

    has_dir_prefixed = isinstance(tool.semantic_contract, Mapping) and any(
        k.startswith(f"{direction}_") for k in tool.semantic_contract
    )
    has_port_signals = bool(
        (isinstance(io_schema, Mapping) and (_PORT_SIGNAL_KEYS & set(io_schema.keys())))
        or (isinstance(tool.semantic_contract, Mapping) and (_PORT_SIGNAL_KEYS & set(tool.semantic_contract.keys())))
        or has_dir_prefixed
    )
    if not has_port_signals:
        return None, False

    sem = tool.semantic_contract if isinstance(tool.semantic_contract, Mapping) else {}
    sch = io_schema if isinstance(io_schema, Mapping) else {}

    def _pick(key: str, default: Any = None) -> Any:
        if key in sch and sch.get(key) is not None:
            return sch.get(key)
        dir_key = f"{direction}_{key}"
        if dir_key in sem and sem.get(dir_key) is not None:
            return sem.get(dir_key)
        if key in sem and sem.get(key) is not None:
            return sem.get(key)
        return default

    schema_ref = str(
        _pick("schema_ref")
        or (f"json:{sch.get('type')}" if sch.get("type") else "json:object")
    )
    semantic_type = str(
        _pick("semantic_type")
        or _pick("kind")
        or _pick("concept")
        or "generic"
    )
    encoding = str(_pick("encoding", "utf-8"))
    unit = str(_pick("unit") or _pick("units") or "none")
    cardinality = str(_pick("cardinality", "one"))
    ordering = str(_pick("ordering", "unordered"))
    sensitivity = str(_pick("sensitivity", "public"))
    trust_label = str(_pick("trust_label", "trusted"))
    streaming = _pick("streaming", None)
    precision = _pick("precision", None)
    nullable = bool(_pick("nullable", False))

    port = PortContract(
        schema_ref=schema_ref,
        semantic_type=semantic_type,
        encoding=encoding,
        unit=unit,
        cardinality=cardinality,
        ordering=ordering,
        sensitivity=sensitivity,
        trust_label=trust_label,
        streaming=streaming,
        precision=precision,
        nullable=nullable,
    )
    return port, True


def _normalize_conditions(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, str):
        return [values.strip()] if values.strip() else []
    if isinstance(values, (list, tuple, set)):
        return [str(v).strip() for v in values if str(v).strip()]
    return []


def _contradictory_pair(cond: str) -> Optional[str]:
    c = cond.strip().lower()
    if c.startswith("not:"):
        return c[4:].strip()
    if c.startswith("!"):
        return c[1:].strip()
    return f"not:{c}"


class CompositionVerifier:
    """Zero-trust 6-dimension verifier for `CompositionPlan/1` DAG compositions."""

    def verify(
        self,
        plan: Union[CompositionPlan, Mapping[str, Any]],
        registry: Union[ToolRegistry, Mapping[str, ToolSpec]],
        security_context: SecurityContext,
        *,
        adapters: Union[Sequence[Union[AdapterSpec, Mapping[str, Any]]], Mapping[str, Union[AdapterSpec, Mapping[str, Any]]], None] = (),
        authority: Optional[AttestationAuthority] = None,
        receipts: Optional[Union[CompositionReceipt, ExecutionReceipt, Mapping[str, Any], Sequence[Any]]] = None,
        oracle: Optional[Union[Callable[..., Any], ProofPackReport, Mapping[str, Any]]] = None,
        replay_corpus: Optional[Union[Sequence[Any], Mapping[str, Any], ProofPackReport]] = None,
        runner: Optional[Callable[..., Any]] = None,
    ) -> CompositionVerificationResult:
        """Execute all 6 verification dimensions against `plan`, returning `CompositionVerificationResult`."""
        if not isinstance(security_context, SecurityContext):
            raise ValueError("INVALID_SECURITY_CONTEXT: expected SecurityContext instance.")
        eff_authority: Optional[AttestationAuthority] = (
            authority if authority is not None else (registry.authority if isinstance(registry, ToolRegistry) else None)
        )

        dim_results: Dict[str, Dict[str, Any]] = {}
        all_reasons: List[str] = []

        # --- Dimension 1: Schema & canonical plan_hash integrity ---
        dim1_reasons, plan_dict = self._check_dimension1_schema_and_hash(plan, security_context)
        dim_results["schema_and_hash_integrity"] = {"ok": len(dim1_reasons) == 0, "reasons": list(dim1_reasons)}
        all_reasons.extend(dim1_reasons)

        plan_id = str(plan_dict.get("plan_id") or "unknown-plan")
        plan_hash = str(plan_dict.get("plan_hash") or "")
        nodes = [dict(n) for n in (plan_dict.get("nodes") or ()) if isinstance(n, Mapping)]
        edges = [dict(e) for e in (plan_dict.get("edges") or ()) if isinstance(e, Mapping)]
        input_bindings = dict(plan_dict.get("input_bindings") or {}) if isinstance(plan_dict.get("input_bindings"), Mapping) else {}

        raw_adapters_source = adapters
        if not raw_adapters_source and isinstance(plan_dict.get("verification_plan"), Mapping):
            embedded_adapters = plan_dict["verification_plan"].get("adapters")
            if isinstance(embedded_adapters, Mapping):
                raw_adapters_source = embedded_adapters
        adapter_map, adapter_parse_errors = _normalize_adapters(raw_adapters_source)
        tool_map: Dict[str, ToolSpec] = {}
        node_map: Dict[str, Dict[str, Any]] = {}
        for n in nodes:
            nid = str(n.get("node_id") or "").strip()
            if nid and nid not in node_map:
                node_map[nid] = n
            tid = str(n.get("tool_id") or "").strip()
            if tid and n.get("kind") != "adapter" and tid not in tool_map:
                found_tool = _lookup_tool(registry, tid)
                if found_tool is not None:
                    tool_map[tid] = found_tool

        # --- Dimension 4 (Trust, Hashes, Permissions & Effects) ---
        dim4_reasons, computed_perms, computed_effects = self._check_dimension4_permissions_effects_trust(
            plan_dict=plan_dict,
            nodes=nodes,
            edges=edges,
            tool_map=tool_map,
            adapter_map=adapter_map,
            adapter_parse_errors=adapter_parse_errors,
            registry=registry,
            security_context=security_context,
            authority=eff_authority,
        )
        dim_results["permissions_effects_and_trust"] = {
            "ok": len(dim4_reasons) == 0,
            "reasons": list(dim4_reasons),
            "permission_union": computed_perms,
            "effects_union": computed_effects,
        }
        all_reasons.extend(dim4_reasons)

        # --- Dimension 5 (Acyclicity, Order, Idempotency & Parallel Groups) ---
        dim5_reasons, exec_order, parallel_groups = self._check_dimension5_dag_order_and_parallelism(
            plan_dict=plan_dict,
            nodes=nodes,
            edges=edges,
            input_bindings=input_bindings,
            tool_map=tool_map,
            registry=registry,
        )
        dim_results["dag_acyclicity_order_idempotency_and_parallelism"] = {
            "ok": len(dim5_reasons) == 0,
            "reasons": list(dim5_reasons),
            "execution_order": exec_order,
            "parallel_groups": parallel_groups,
        }
        all_reasons.extend(dim5_reasons)

        # --- Dimension 2 (Semantic & Port Compatibility across every edge) ---
        dim2_reasons = self._check_dimension2_ports_and_semantics(
            plan_dict=plan_dict,
            nodes=nodes,
            edges=edges,
            node_map=node_map,
            tool_map=tool_map,
            adapter_map=adapter_map,
            security_context=security_context,
        )
        dim_results["port_and_semantic_compatibility"] = {"ok": len(dim2_reasons) == 0, "reasons": list(dim2_reasons)}
        all_reasons.extend(dim2_reasons)

        # --- Dimension 3 (Preconditions & Postconditions Alignment) ---
        dim3_reasons = self._check_dimension3_pre_postconditions(
            plan_dict=plan_dict,
            exec_order=exec_order if exec_order else [str(n.get("node_id", "")) for n in nodes],
            node_map=node_map,
            edges=edges,
            tool_map=tool_map,
            adapter_map=adapter_map,
        )
        dim_results["preconditions_and_postconditions"] = {"ok": len(dim3_reasons) == 0, "reasons": list(dim3_reasons)}
        all_reasons.extend(dim3_reasons)

        static_valid = all(
            dim_results[k]["ok"]
            for k in (
                "schema_and_hash_integrity",
                "port_and_semantic_compatibility",
                "preconditions_and_postconditions",
                "permissions_effects_and_trust",
                "dag_acyclicity_order_idempotency_and_parallelism",
            )
        )

        # --- Dimension 6 (Independent Replay / Oracle Output Verification) ---
        oracle_status, dim6_reasons, dim6_details = self._check_dimension6_replay_and_oracle(
            plan_dict=plan_dict,
            node_ids=list(node_map.keys()),
            security_context=security_context,
            receipts=receipts,
            oracle=oracle,
            replay_corpus=replay_corpus,
            runner=runner,
        )
        dim_results["replay_and_oracle_verification"] = {
            "ok": oracle_status == "PASS",
            "status": oracle_status,
            "reasons": list(dim6_reasons),
            **dim6_details,
        }
        all_reasons.extend(dim6_reasons)

        if not static_valid or oracle_status == "FAIL":
            overall_status = "FAIL"
        elif oracle_status == "PASS":
            overall_status = "PASS"
        else:
            overall_status = "NOT_VERIFIED"

        valid = static_valid and oracle_status != "FAIL"
        verified = overall_status == "PASS"

        return CompositionVerificationResult(
            valid=valid,
            static_valid=static_valid,
            verified=verified,
            status=overall_status,
            oracle_status=oracle_status,
            plan_id=plan_id,
            plan_hash=plan_hash,
            execution_order=exec_order,
            parallel_groups=parallel_groups,
            permission_union=computed_perms,
            effects_union=computed_effects,
            dimension_results=dim_results,
            reasons=all_reasons,
        )

    @staticmethod
    def parallel_execution_groups(
        plan: Union[CompositionPlan, Mapping[str, Any]],
        registry: Optional[Union[ToolRegistry, Mapping[str, ToolSpec]]] = None,
    ) -> List[List[str]]:
        return parallel_execution_groups(plan, registry=registry)

    def _check_dimension1_schema_and_hash(
        self,
        plan: Union[CompositionPlan, Mapping[str, Any]],
        security_context: SecurityContext,
    ) -> Tuple[List[str], Dict[str, Any]]:
        reasons: List[str] = []
        try:
            _verify_context_policy_integrity(security_context)
        except PermissionError as exc:
            reasons.append(str(exc))

        try:
            plan_dict = _plan_to_raw_dict(plan)
        except ValueError as exc:
            return [str(exc)], {}

        if _has_trojan_unicode(plan_dict):
            reasons.append("REJECTED_TROJAN_UNICODE_IN_PLAN")

        try:
            assert_no_raw_secrets(canonical_json_dumps(plan_dict), context="CompositionPlan")
        except ValueError as exc:
            reasons.append(str(exc))

        if plan_dict.get("schema") != "CompositionPlan/1":
            reasons.append(f"INVALID_SCHEMA:expected=CompositionPlan/1:got={plan_dict.get('schema')!r}")

        missing_keys = [k for k in _REQUIRED_PLAN_KEYS if k not in plan_dict]
        if missing_keys:
            reasons.append(f"MISSING_PLAN_FIELDS:{','.join(missing_keys)}")

        raw_nodes = plan_dict.get("nodes")
        if not isinstance(raw_nodes, (list, tuple)) or not raw_nodes:
            reasons.append("INVALID_NODES:must_be_non_empty_list")
        raw_edges = plan_dict.get("edges")
        if not isinstance(raw_edges, (list, tuple)):
            reasons.append("INVALID_EDGES:must_be_list")

        goal_hash = str(plan_dict.get("goal_contract_hash") or "")
        if not is_valid_sha256(goal_hash):
            reasons.append("INVALID_GOAL_CONTRACT_HASH")

        try:
            validate_safe_text(plan_dict.get("plan_id"), field_name="plan_id")
            validate_safe_text(plan_dict.get("oracle_ref"), field_name="oracle_ref")
        except ValueError as exc:
            reasons.append(str(exc))

        provided_hash = str(plan_dict.get("plan_hash") or "").strip().lower()
        if not is_valid_sha256(provided_hash):
            reasons.append("MISSING_OR_INVALID_PLAN_HASH")
        elif not missing_keys:
            expected_hash = _recompute_plan_hash(plan_dict)
            if not hmac.compare_digest(provided_hash, expected_hash.lower()):
                reasons.append("PLAN_HASH_MISMATCH")

        return reasons, plan_dict

    def _check_dimension2_ports_and_semantics(
        self,
        *,
        plan_dict: Mapping[str, Any],
        nodes: Sequence[Mapping[str, Any]],
        edges: Sequence[Mapping[str, Any]],
        node_map: Mapping[str, Mapping[str, Any]],
        tool_map: Mapping[str, ToolSpec],
        adapter_map: Mapping[str, AdapterSpec],
        security_context: SecurityContext,
    ) -> List[str]:
        reasons: List[str] = []
        edge_lookup: Dict[Tuple[str, str], List[Mapping[str, Any]]] = {}
        for edge in edges:
            src_id = str(edge.get("from_node") or "").strip()
            dst_id = str(edge.get("to_node") or "").strip()
            edge_lookup.setdefault((src_id, dst_id), []).append(edge)

        # Check adapter nodes (kind == "adapter")
        for n in nodes:
            if n.get("kind") != "adapter":
                continue
            nid = str(n.get("node_id") or "").strip()
            aid = str(n.get("adapter_id") or n.get("tool_id") or "").strip()
            adapter = adapter_map.get(aid)
            if adapter is None:
                reasons.append(f"MISSING_ADAPTER_NODE:{nid}:{aid}")
                continue
            incoming = [e for e in edges if str(e.get("to_node") or "").strip() == nid]
            outgoing = [e for e in edges if str(e.get("from_node") or "").strip() == nid]
            for e in incoming:
                u_id = str(e.get("from_node") or "").strip()
                u_node = node_map.get(u_id)
                u_tool = tool_map.get(str(u_node.get("tool_id", ""))) if u_node else None
                if u_node is not None and u_tool is not None:
                    src_port, _ = _derive_port_contract(
                        u_node, u_tool, "output", str(e.get("output_port") or e.get("from_port") or "default")
                    )
                    if src_port is not None:
                        res_in = ports_compatible(src_port, adapter.source_port)
                        if not res_in.compatible:
                            reasons.extend(f"EDGE_ADAPTER_IN:{u_id}->{nid}:{r}" for r in res_in.reasons)
            for e in outgoing:
                v_id = str(e.get("to_node") or "").strip()
                v_node = node_map.get(v_id)
                v_tool = tool_map.get(str(v_node.get("tool_id", ""))) if v_node else None
                if v_node is not None and v_tool is not None:
                    dst_port, _ = _derive_port_contract(
                        v_node, v_tool, "input", str(e.get("input_port") or e.get("to_port") or "default")
                    )
                    if dst_port is not None:
                        res_out = ports_compatible(adapter.target_port, dst_port)
                        if not res_out.compatible:
                            reasons.extend(f"EDGE_ADAPTER_OUT:{nid}->{v_id}:{r}" for r in res_out.reasons)

        # Check all tool -> tool edges (direct or edge-level adapter)
        for edge in edges:
            src_id = str(edge.get("from_node") or "").strip()
            dst_id = str(edge.get("to_node") or "").strip()
            src_node = node_map.get(src_id)
            dst_node = node_map.get(dst_id)
            if src_node is None or dst_node is None:
                reasons.append(f"UNKNOWN_EDGE_ENDPOINT:{src_id}->{dst_id}")
                continue
            if src_node.get("kind") == "adapter" or dst_node.get("kind") == "adapter":
                continue

            src_tool = tool_map.get(str(src_node.get("tool_id") or "").strip())
            dst_tool = tool_map.get(str(dst_node.get("tool_id") or "").strip())
            if src_tool is None or dst_tool is None:
                continue

            out_port_name = str(edge.get("output_port") or edge.get("from_port") or "default")
            in_port_name = str(edge.get("input_port") or edge.get("to_port") or "default")
            src_port, src_explicit = _derive_port_contract(src_node, src_tool, "output", out_port_name)
            dst_port, dst_explicit = _derive_port_contract(dst_node, dst_tool, "input", in_port_name)

            raw_adapter_id = edge.get("adapter_id")
            if raw_adapter_id:
                aid = str(raw_adapter_id).strip()
                adapter = adapter_map.get(aid)
                if adapter is None:
                    reasons.append(f"MISSING_EDGE_ADAPTER:{src_id}->{dst_id}:{aid}")
                    continue
                if src_port is not None:
                    res_src = ports_compatible(src_port, adapter.source_port)
                    if not res_src.compatible:
                        reasons.extend(f"ADAPTER_SRC_INCOMPATIBLE:{src_id}->{dst_id}:{r}" for r in res_src.reasons)
                if dst_port is not None:
                    res_dst = ports_compatible(adapter.target_port, dst_port)
                    if not res_dst.compatible:
                        reasons.extend(f"ADAPTER_DST_INCOMPATIBLE:{src_id}->{dst_id}:{r}" for r in res_dst.reasons)
                if src_port is None and dst_port is None:
                    reasons.extend(
                        f"ADAPTER_BOUNDARY_CHECK:{src_id}->{dst_id}:{r}"
                        for r in ports_compatible(adapter.source_port, adapter.source_port).reasons
                    )
            else:
                if src_port is not None and dst_port is not None:
                    port_res = ports_compatible(src_port, dst_port)
                    if not port_res.compatible:
                        reasons.extend(f"PORT_INCOMPATIBLE:{src_id}->{dst_id}:{r}" for r in port_res.reasons)
                elif src_explicit or dst_explicit:
                    # One side declared explicit sensitivity/unit/port contract; construct default peer to enforce boundaries
                    eff_src = src_port or PortContract(schema_ref="json:object", semantic_type="generic")
                    eff_dst = dst_port or PortContract(schema_ref="json:object", semantic_type="generic")
                    if _SENSITIVITY_RANK[eff_src.sensitivity] > _SENSITIVITY_RANK[eff_dst.sensitivity]:
                        reasons.append(
                            f"PORT_INCOMPATIBLE:{src_id}->{dst_id}:SENSITIVITY_FLOW_VIOLATION:{eff_src.sensitivity}->{eff_dst.sensitivity}"
                        )
                    if eff_src.unit.lower() != eff_dst.unit.lower() and "none" not in (
                        eff_src.unit.lower(),
                        eff_dst.unit.lower(),
                    ):
                        reasons.append(
                            f"PORT_INCOMPATIBLE:{src_id}->{dst_id}:UNIT_MISMATCH:{eff_src.unit}!={eff_dst.unit}"
                        )

                if src_tool.output_schema or dst_tool.input_schema or (
                    src_tool.semantic_contract and dst_tool.semantic_contract
                ):
                    compat = check_contract_compatibility(
                        producer_output=src_tool.output_schema,
                        producer_semantic=src_tool.semantic_contract,
                        consumer_input=dst_tool.input_schema,
                        consumer_semantic=dst_tool.semantic_contract,
                        producer_postconditions=src_tool.postconditions,
                        producer_side_effects=src_tool.side_effects,
                        producer_permissions=src_tool.required_permissions,
                        consumer_permissions=dst_tool.required_permissions,
                        security_context=security_context,
                    )
                    if not compat.compatible:
                        reasons.extend(f"CONTRACT_INCOMPATIBLE:{src_id}->{dst_id}:{r}" for r in compat.reasons)

        # Check input_bindings for secret->public leakage or dangling bindings
        bindings = plan_dict.get("input_bindings") or {}
        if isinstance(bindings, Mapping):
            goal_sens = {}
            if isinstance(bindings.get("goal_sensitivities"), Mapping):
                goal_sens = {str(k): str(v).lower() for k, v in bindings["goal_sensitivities"].items()}
            for dst_key, src_val in bindings.items():
                key_s = str(dst_key).strip()
                if "." not in key_s or key_s in {"goal_sensitivities", "preconditions", "satisfied_preconditions"}:
                    continue
                dst_nid, dst_port_name = key_s.split(".", 1)
                if dst_nid not in node_map:
                    reasons.append(f"DANGLING_INPUT_BINDING:{key_s}")
                    continue
                src_ref = _extract_binding_source_node(src_val)
                if src_ref == "goal" and isinstance(src_val, str) and src_val in goal_sens:
                    dst_node = node_map[dst_nid]
                    dst_tool = tool_map.get(str(dst_node.get("tool_id") or ""))
                    if dst_tool is not None:
                        dst_port, _ = _derive_port_contract(dst_node, dst_tool, "input", dst_port_name)
                        src_s = goal_sens[src_val]
                        dst_s = dst_port.sensitivity if dst_port else "public"
                        if _SENSITIVITY_RANK.get(src_s, 2) > _SENSITIVITY_RANK.get(dst_s, 0):
                            reasons.append(f"BINDING_SENSITIVITY_VIOLATION:{src_val}({src_s})->{key_s}({dst_s})")

        # Check expected_outputs compatibility against sink nodes if ports/units/sensitivity specified
        expected_outputs = plan_dict.get("expected_outputs")
        if isinstance(expected_outputs, list) and expected_outputs:
            out_sources = {str(e.get("from_node") or "").strip() for e in edges}
            sink_ids = [nid for nid in node_map.keys() if nid not in out_sources] or list(node_map.keys())
            for exp_item in expected_outputs:
                if not isinstance(exp_item, Mapping):
                    continue
                exp_unit = str(exp_item.get("unit") or exp_item.get("units") or "").strip().lower()
                exp_sem = str(exp_item.get("semantic_type") or "").strip().lower()
                exp_sens = str(exp_item.get("sensitivity") or "").strip().lower()
                if not (exp_unit or exp_sem or exp_sens):
                    continue
                matched_sink = False
                for sid in sink_ids:
                    snode = node_map[sid]
                    stool = tool_map.get(str(snode.get("tool_id") or ""))
                    if stool is None:
                        continue
                    sport, has_sp = _derive_port_contract(snode, stool, "output", "default")
                    if not has_sp or sport is None:
                        matched_sink = True
                        continue
                    unit_ok = not exp_unit or exp_unit == "none" or sport.unit.lower() == exp_unit
                    sem_ok = not exp_sem or sport.semantic_type.lower() == exp_sem
                    sens_ok = not exp_sens or _SENSITIVITY_RANK.get(sport.sensitivity, 0) <= _SENSITIVITY_RANK.get(exp_sens, 2)
                    if unit_ok and sem_ok and sens_ok:
                        matched_sink = True
                        break
                if not matched_sink:
                    reasons.append(
                        f"EXPECTED_OUTPUT_MISMATCH:sem={exp_sem or '*'},unit={exp_unit or '*'},sens={exp_sens or '*'}"
                    )

        return reasons

    def _check_dimension3_pre_postconditions(
        self,
        *,
        plan_dict: Mapping[str, Any],
        exec_order: Sequence[str],
        node_map: Mapping[str, Mapping[str, Any]],
        edges: Sequence[Mapping[str, Any]],
        tool_map: Mapping[str, ToolSpec],
        adapter_map: Mapping[str, AdapterSpec],
    ) -> List[str]:
        reasons: List[str] = []
        ver_plan = plan_dict.get("verification_plan") if isinstance(plan_dict.get("verification_plan"), Mapping) else {}
        bindings = plan_dict.get("input_bindings") if isinstance(plan_dict.get("input_bindings"), Mapping) else {}

        initial_conds: Set[str] = set()
        for src_seq in (
            ver_plan.get("initial_preconditions"),
            ver_plan.get("satisfied_preconditions"),
            bindings.get("preconditions"),
            bindings.get("satisfied_preconditions"),
        ):
            initial_conds.update(_normalize_conditions(src_seq))

        incoming_edges: Dict[str, List[Mapping[str, Any]]] = {}
        for edge in edges:
            incoming_edges.setdefault(str(edge.get("to_node") or "").strip(), []).append(edge)

        node_post_conds: Dict[str, Set[str]] = {}
        for nid in exec_order:
            node = node_map.get(nid)
            if node is None:
                continue
            tool = tool_map.get(str(node.get("tool_id") or "").strip())

            available: Set[str] = set(initial_conds)
            for edge in incoming_edges.get(nid, []):
                from_nid = str(edge.get("from_node") or "").strip()
                upstream = set(initial_conds) | set(node_post_conds.get(from_nid, set()))
                available.update(upstream)

                aid = edge.get("adapter_id")
                if aid and str(aid).strip() in adapter_map:
                    adapter = adapter_map[str(aid).strip()]
                    for ap in adapter.preconditions:
                        if ap.startswith(("exact_rational_representation:", "target_range:")):
                            continue
                        if ap not in upstream:
                            reasons.append(f"UNSATISFIED_ADAPTER_PRECONDITION:{aid}:{ap}")
                    available.update(adapter.preconditions)

            req_pre = _normalize_conditions(node.get("preconditions"))
            if tool is not None:
                req_pre.extend(_normalize_conditions(tool.preconditions))
            for cond in dict.fromkeys(req_pre):
                if cond not in available:
                    reasons.append(f"UNSATISFIED_PRECONDITION:{nid}:{cond}")

            produced: Set[str] = set(_normalize_conditions(node.get("postconditions")))
            if tool is not None:
                produced.update(_normalize_conditions(tool.postconditions))
                produced.update(_normalize_conditions(tool.semantic_contract.get("invariants")))

            for cond in produced:
                contra = _contradictory_pair(cond.lower())
                if contra and contra in {c.lower() for c in produced}:
                    reasons.append(f"CONTRADICTORY_POSTCONDITIONS:{nid}:{cond}")
            node_post_conds[nid] = available | produced

        # Check expected_outputs required postconditions/invariants if provided
        expected_outputs = plan_dict.get("expected_outputs")
        if isinstance(expected_outputs, list) and expected_outputs:
            all_produced = set().union(*node_post_conds.values()) if node_post_conds else set(initial_conds)
            for exp_item in expected_outputs:
                if not isinstance(exp_item, Mapping):
                    continue
                req_post = _normalize_conditions(exp_item.get("postconditions")) + _normalize_conditions(
                    exp_item.get("invariants")
                )
                for cond in req_post:
                    if cond not in all_produced:
                        reasons.append(f"MISSING_EXPECTED_POSTCONDITION:{cond}")

        return reasons

    def _check_dimension4_permissions_effects_trust(
        self,
        *,
        plan_dict: Mapping[str, Any],
        nodes: Sequence[Mapping[str, Any]],
        edges: Sequence[Mapping[str, Any]],
        tool_map: Mapping[str, ToolSpec],
        adapter_map: Mapping[str, AdapterSpec],
        adapter_parse_errors: Sequence[str],
        registry: Union[ToolRegistry, Mapping[str, ToolSpec]],
        security_context: SecurityContext,
        authority: Optional[AttestationAuthority] = None,
    ) -> Tuple[List[str], List[str], Dict[str, Any]]:
        reasons: List[str] = list(adapter_parse_errors)
        tool_hashes = plan_dict.get("tool_artifact_hashes") if isinstance(plan_dict.get("tool_artifact_hashes"), Mapping) else {}
        adapter_hashes = plan_dict.get("adapter_hashes") if isinstance(plan_dict.get("adapter_hashes"), Mapping) else {}

        referenced_effects: List[EffectContract] = []
        referenced_tools: List[ToolSpec] = []
        referenced_adapter_ids: Set[str] = set(str(k) for k in adapter_hashes.keys())

        for edge in edges:
            if edge.get("adapter_id"):
                aid = str(edge["adapter_id"]).strip()
                referenced_adapter_ids.add(aid)
                if edge.get("adapter_hash") and aid in adapter_map:
                    e_hash = str(edge["adapter_hash"]).strip().lower()
                    if not hmac.compare_digest(e_hash, adapter_map[aid].adapter_hash.lower()):
                        reasons.append(f"EDGE_ADAPTER_HASH_MISMATCH:{aid}")

        for n in nodes:
            nid = str(n.get("node_id") or "").strip()
            if n.get("kind") == "adapter":
                aid = str(n.get("adapter_id") or n.get("tool_id") or "").strip()
                referenced_adapter_ids.add(aid)
                if n.get("adapter_hash") and aid in adapter_map:
                    if not hmac.compare_digest(str(n["adapter_hash"]).lower(), adapter_map[aid].adapter_hash.lower()):
                        reasons.append(f"NODE_ADAPTER_HASH_MISMATCH:{nid}:{aid}")
                continue

            tid = str(n.get("tool_id") or "").strip()
            spec = tool_map.get(tid) or _lookup_tool(registry, tid)
            if spec is None:
                reasons.append(f"UNKNOWN_TOOL:{tid}")
                continue
            referenced_tools.append(spec)
            referenced_effects.append(_node_effect_contract(n, spec))

            if spec.trust_status != TrustStatus.VERIFIED:
                reasons.append(f"UNTRUSTED_TOOL:{tid}:{spec.trust_status.value}")
            elif not has_valid_verification_attestation(spec.verification_attestation, spec.binary_hash, spec.tool_id):
                reasons.append(f"INVALID_TOOL_ATTESTATION:{tid}")
            elif (
                authority is None
                or not authority.has_registered_verifiers
                or not authority.verify_attestation(
                    spec.verification_attestation or {},
                    expected_tool_id=spec.tool_id,
                    expected_binary_hash=spec.binary_hash,
                    expected_spec_digest=compute_tool_spec_security_digest(spec),
                )
            ):
                reasons.append(f"INVALID_TOOL_ATTESTATION:{tid}")

            declared_hash = tool_hashes.get(tid)
            if not declared_hash:
                reasons.append(f"MISSING_TOOL_ARTIFACT_HASH:{tid}")
            elif not hmac.compare_digest(str(declared_hash).strip().lower(), spec.binary_hash.lower()):
                reasons.append(f"TOOL_BINARY_HASH_MISMATCH:{tid}")

            if n.get("binary_hash"):
                if not hmac.compare_digest(str(n["binary_hash"]).strip().lower(), spec.binary_hash.lower()):
                    reasons.append(f"NODE_BINARY_HASH_MISMATCH:{nid}:{tid}")
            if n.get("tool_version") and str(n["tool_version"]).strip() != spec.version:
                reasons.append(f"TOOL_VERSION_MISMATCH:{nid}:{tid}")

            reasons.extend(f"POLICY_VIOLATION:{tid}:{r}" for r in tool_violates_security_context(spec, security_context))

        for aid in sorted(referenced_adapter_ids):
            adapter = adapter_map.get(aid)
            if adapter is None:
                reasons.append(f"UNREGISTERED_OR_MISSING_ADAPTER:{aid}")
                continue
            if adapter.trust_status != TrustStatus.VERIFIED:
                reasons.append(f"UNTRUSTED_ADAPTER:{aid}:{adapter.trust_status.value}")
            elif not _has_valid_adapter_attestation_strict(adapter, authority=authority):
                reasons.append(f"INVALID_ADAPTER_ATTESTATION:{aid}")

            declared_ah = adapter_hashes.get(aid)
            if not declared_ah:
                reasons.append(f"MISSING_ADAPTER_HASH:{aid}")
            elif not hmac.compare_digest(str(declared_ah).strip().lower(), adapter.adapter_hash.lower()):
                reasons.append(f"ADAPTER_HASH_MISMATCH:{aid}")

        dag_summary = compute_dag_effects(referenced_effects)
        computed_perms = list(dag_summary["permission_union"])
        computed_effects = dict(dag_summary["effects_union"])

        declared_perms = [str(p) for p in (plan_dict.get("permission_union") or ())]
        missing_in_plan_perms = sorted(set(computed_perms) - set(declared_perms))
        if missing_in_plan_perms:
            reasons.append(f"PLAN_UNDERSTATES_PERMISSIONS:{','.join(missing_in_plan_perms)}")

        allowed_perms = set(security_context.allowed_permissions)
        excess_perms = sorted((set(declared_perms) | set(computed_perms)) - allowed_perms)
        if excess_perms:
            reasons.append(f"OVER_PRIVILEGED_PERMISSIONS:{','.join(excess_perms)}")

        declared_effects = plan_dict.get("effects_union") if isinstance(plan_dict.get("effects_union"), Mapping) else {}
        for scope_key in ("read_scopes", "write_scopes", "network_scopes", "exec_permissions"):
            comp_set = set(str(x) for x in computed_effects.get(scope_key, []))
            decl_set = set(str(x) for x in (declared_effects.get(scope_key) or []))
            understated = sorted(comp_set - decl_set)
            if understated:
                reasons.append(f"EFFECTS_UNION_UNDERSTATED:{scope_key}:{','.join(understated)}")

        if computed_effects.get("irreversible") is True and declared_effects.get("irreversible") is False:
            reasons.append("EFFECTS_UNION_UNDERSTATED:irreversible")
        if computed_effects.get("idempotent") is False and declared_effects.get("idempotent") is True:
            reasons.append("EFFECTS_UNION_OVERSTATED_IDEMPOTENT")

        if not security_context.network_allowed:
            net_scopes = set(str(x) for x in computed_effects.get("network_scopes", [])) | set(
                str(x) for x in (declared_effects.get("network_scopes") or [])
            )
            if net_scopes:
                reasons.append("NETWORK_SCOPES_DISALLOWED_BY_POLICY")

        # Validate workspace confinement of declared read/write scopes if they look like file paths
        for scope in set(computed_effects.get("read_scopes", [])) | set(computed_effects.get("write_scopes", [])):
            raw_s = scope[3:] if scope.startswith("ws:") else scope
            if ".." in Path(raw_s).parts:
                reasons.append(f"PATH_TRAVERSAL_IN_EFFECT_SCOPE:{scope}")
            elif raw_s.startswith("/"):
                try:
                    Path(raw_s).resolve().relative_to(Path(security_context.workspace_root).resolve())
                except ValueError:
                    reasons.append(f"WORKSPACE_ESCAPE_IN_EFFECT_SCOPE:{scope}")

        plan_profile = plan_dict.get("profile")
        if plan_profile and str(plan_profile).strip().upper() != security_context.profile.value:
            reasons.append(f"PROFILE_MISMATCH:{plan_profile}!={security_context.profile.value}")

        sec_checks = plan_dict.get("security_checks")
        if isinstance(sec_checks, Mapping):
            if sec_checks.get("all_tools_verified") is False:
                reasons.append("SECURITY_CHECKS_ALL_TOOLS_VERIFIED_FALSE")
            if "no_untrusted_native_on_host" in sec_checks and sec_checks.get("no_untrusted_native_on_host") is not True:
                reasons.append("SECURITY_CHECKS_UNTRUSTED_NATIVE_FLAG_INVALID")

        return reasons, computed_perms, computed_effects

    def _check_dimension5_dag_order_and_parallelism(
        self,
        *,
        plan_dict: Mapping[str, Any],
        nodes: Sequence[Mapping[str, Any]],
        edges: Sequence[Mapping[str, Any]],
        input_bindings: Mapping[str, Any],
        tool_map: Mapping[str, ToolSpec],
        registry: Union[ToolRegistry, Mapping[str, ToolSpec]],
    ) -> Tuple[List[str], List[str], List[List[str]]]:
        reasons: List[str] = []
        node_ids, adj, preds, dep_errors = _extract_node_dependencies(nodes, edges, input_bindings)
        reasons.extend(dep_errors)

        exec_order: List[str] = []
        parallel_groups: List[List[str]] = []

        if not node_ids:
            reasons.append("EMPTY_DAG_NODES")
            return reasons, exec_order, parallel_groups

        exec_order, is_acyclic = _canonical_topological_order(node_ids, adj, preds)
        if not is_acyclic:
            reasons.append("CYCLE_DETECTED_IN_COMPOSITION_DAG")
            return reasons, [], []

        node_map: Dict[str, Mapping[str, Any]] = {str(n["node_id"]).strip(): n for n in nodes if n.get("node_id")}
        eff_map: Dict[str, EffectContract] = {}
        ver_plan = plan_dict.get("verification_plan") if isinstance(plan_dict.get("verification_plan"), Mapping) else {}
        retryable_nodes = set(str(x) for x in (ver_plan.get("retryable_nodes") or ()))
        retry_policies = ver_plan.get("retry_policies") if isinstance(ver_plan.get("retry_policies"), Mapping) else {}

        for nid in node_ids:
            n = node_map[nid]
            tid = str(n.get("tool_id") or "").strip()
            tool = tool_map.get(tid) or _lookup_tool(registry, tid)
            eff = _node_effect_contract(n, tool)
            eff_map[nid] = eff

            is_retryable = (
                bool(n.get("retryable"))
                or int(n.get("max_retries", 0) or 0) > 0
                or int(n.get("retries", 0) or 0) > 0
                or bool(n.get("retry_policy"))
                or nid in retryable_nodes
                or nid in retry_policies
            )
            if is_retryable and (not eff.idempotent or eff.irreversible):
                reasons.append(f"NON_IDEMPOTENT_RETRYABLE_STEP:{nid}")

        max_depth = plan_dict.get("max_depth")
        if max_depth is not None and len(node_ids) > 0:
            depth_map: Dict[str, int] = {nid: 1 for nid in node_ids}
            for nid in exec_order:
                for nxt in adj[nid]:
                    depth_map[nxt] = max(depth_map[nxt], depth_map[nid] + 1)
            longest = max(depth_map.values())
            if longest > int(max_depth):
                reasons.append(f"MAX_DEPTH_EXCEEDED:{longest}>{int(max_depth)}")

        try:
            parallel_groups = parallel_execution_groups(plan_dict, registry=registry)
        except ValueError as exc:
            reasons.append(str(exc))
            return reasons, exec_order, []

        # Validate any explicitly declared parallel_groups in verification_plan or node tags
        ancestors = _compute_ancestors(node_ids, preds)
        declared_groups: List[List[str]] = []
        raw_pg = ver_plan.get("parallel_groups")
        if isinstance(raw_pg, (list, tuple)):
            for grp in raw_pg:
                if isinstance(grp, (list, tuple)):
                    declared_groups.append([str(x).strip() for x in grp])
        group_by_tag: Dict[str, List[str]] = {}
        for nid in node_ids:
            tag = node_map[nid].get("parallel_group")
            if tag is not None and str(tag).strip():
                group_by_tag.setdefault(str(tag).strip(), []).append(nid)
        declared_groups.extend(group_by_tag.values())

        for grp in declared_groups:
            for i in range(len(grp)):
                for j in range(i + 1, len(grp)):
                    a, b = grp[i], grp[j]
                    if a not in node_map or b not in node_map:
                        reasons.append(f"UNKNOWN_NODE_IN_PARALLEL_GROUP:{a},{b}")
                        continue
                    if a in ancestors[b] or b in ancestors[a]:
                        reasons.append(f"PARALLEL_DATA_DEPENDENCY_CONFLICT:{a}<->{b}")
                        continue
                    conflict = _nodes_conflict_for_parallel(node_map[a], eff_map[a], node_map[b], eff_map[b])
                    if conflict:
                        reasons.append(f"PARALLEL_SIDE_EFFECT_CONFLICT:{a}<->{b}:{conflict}")

        return reasons, exec_order, parallel_groups

    def _check_dimension6_replay_and_oracle(
        self,
        *,
        plan_dict: Mapping[str, Any],
        node_ids: Sequence[str],
        security_context: SecurityContext,
        receipts: Any,
        oracle: Any,
        replay_corpus: Any,
        runner: Optional[Callable[..., Any]],
    ) -> Tuple[str, List[str], Dict[str, Any]]:
        reasons: List[str] = []
        details: Dict[str, Any] = {}
        expected_plan_hash = str(plan_dict.get("plan_hash") or "").strip().lower()
        expected_policy_hash = security_context.policy_hash.strip().lower()

        # 1. Pre-computed ProofPackReport passed directly
        if isinstance(oracle, ProofPackReport):
            details["proof_pack_report_digest"] = oracle.report_digest
            return oracle.status, list(oracle.reasons), details
        if isinstance(replay_corpus, ProofPackReport):
            details["proof_pack_report_digest"] = replay_corpus.report_digest
            return replay_corpus.status, list(replay_corpus.reasons), details

        has_verified_receipts = False
        has_unverified_receipt = False
        receipt_list: List[Any] = []
        if receipts is not None:
            if isinstance(receipts, (list, tuple)):
                receipt_list = list(receipts)
            else:
                receipt_list = [receipts]

        for idx, rec in enumerate(receipt_list):
            rec_dict = rec.to_dict() if hasattr(rec, "to_dict") and callable(rec.to_dict) else (
                dict(rec) if isinstance(rec, Mapping) else None
            )
            if rec_dict is None:
                reasons.append(f"INVALID_RECEIPT_TYPE:idx={idx}")
                continue
            r_schema = str(rec_dict.get("schema") or "")
            if r_schema == "CompositionReceipt/1":
                try:
                    parsed = CompositionReceipt.from_dict(rec_dict)
                except ValueError as exc:
                    reasons.append(f"INVALID_COMPOSITION_RECEIPT:idx={idx}:{exc}")
                    continue
                trace_payload = {
                    "schema": parsed.schema,
                    "run_id": parsed.run_id,
                    "plan_hash": parsed.plan_hash,
                    "policy_hash": parsed.policy_hash,
                    "sandbox_environment_hash": parsed.sandbox_environment_hash,
                    "input_digest": parsed.input_digest,
                    "output_digest": parsed.output_digest,
                    "node_receipts": parsed.node_receipts,
                    "oracle_result": parsed.oracle_result,
                    "verification_status": parsed.verification_status,
                    "status": parsed.status.value,
                }
                if parsed.unresolved_nodes:
                    trace_payload["unresolved_nodes"] = parsed.unresolved_nodes
                expected_trace = sha256_digest(trace_payload)
                if not hmac.compare_digest(parsed.trace_digest.lower(), expected_trace.lower()):
                    reasons.append(f"RECEIPT_TRACE_DIGEST_TAMPERED:idx={idx}")
                    continue
                if not hmac.compare_digest(parsed.plan_hash.lower(), expected_plan_hash):
                    reasons.append(f"RECEIPT_PLAN_HASH_MISMATCH:idx={idx}")
                    continue
                if not hmac.compare_digest(parsed.policy_hash.lower(), expected_policy_hash):
                    reasons.append(f"RECEIPT_POLICY_HASH_MISMATCH:idx={idx}")
                    continue
                if parsed.status in {ExecutionStatus.FAIL, ExecutionStatus.PERMISSION_DENIED, ExecutionStatus.ROLLED_BACK}:
                    reasons.append(f"RECEIPT_FAILED_STATUS:idx={idx}:{parsed.status.value}")
                    continue
                if parsed.oracle_result.get("passed") is False:
                    reasons.append(f"RECEIPT_ORACLE_FAILED:idx={idx}")
                    continue
                covered_nodes = {str(nr.get("node_id") or "") for nr in parsed.node_receipts if isinstance(nr, Mapping)}
                missing_nodes = sorted(set(node_ids) - covered_nodes)
                if parsed.node_receipts and missing_nodes:
                    reasons.append(f"RECEIPT_MISSING_NODE_EXECUTIONS:idx={idx}:{','.join(missing_nodes)}")
                    continue
                if parsed.status == ExecutionStatus.PASS and parsed.oracle_result.get("passed") is True:
                    has_verified_receipts = True
                elif parsed.status == ExecutionStatus.PASS and oracle is not None:
                    has_verified_receipts = True
                else:
                    has_unverified_receipt = True
            elif r_schema == "ExecutionReceipt/1":
                try:
                    parsed_er = ExecutionReceipt.from_dict(rec_dict)
                except ValueError as exc:
                    reasons.append(f"INVALID_EXECUTION_RECEIPT:idx={idx}:{exc}")
                    continue
                if not hmac.compare_digest(parsed_er.plan_hash.lower(), expected_plan_hash):
                    reasons.append(f"RECEIPT_PLAN_HASH_MISMATCH:idx={idx}")
                    continue
                if not hmac.compare_digest(parsed_er.policy_hash.lower(), expected_policy_hash):
                    reasons.append(f"RECEIPT_POLICY_HASH_MISMATCH:idx={idx}")
                    continue
                if parsed_er.status in {ExecutionStatus.FAIL, ExecutionStatus.PERMISSION_DENIED, ExecutionStatus.ROLLED_BACK}:
                    reasons.append(f"RECEIPT_FAILED_STATUS:idx={idx}:{parsed_er.status.value}")
                    continue
                if parsed_er.status == ExecutionStatus.PASS and parsed_er.verification_status.upper() not in {
                    "NOT_VERIFIED",
                    "FAIL",
                    "FAILED",
                }:
                    has_verified_receipts = True
                else:
                    has_unverified_receipt = True
            else:
                reasons.append(f"UNSUPPORTED_RECEIPT_SCHEMA:idx={idx}:{r_schema}")

        if reasons:
            return "FAIL", reasons, details

        # 2. Evaluate replay_corpus if provided
        has_verified_replay = False
        if replay_corpus is not None:
            replay_cases: List[Any] = []
            replay_runner = runner
            if isinstance(replay_corpus, Mapping):
                replay_cases = list(replay_corpus.get("cases") or ())
                replay_runner = replay_runner or replay_corpus.get("candidate_fn") or replay_corpus.get("runner")
            elif isinstance(replay_corpus, (list, tuple)):
                replay_cases = list(replay_corpus)
            else:
                return "FAIL", ["INVALID_REPLAY_CORPUS_TYPE"], details

            details["replay_cases"] = len(replay_cases)
            if not replay_cases:
                return "NOT_VERIFIED", ["EMPTY_REPLAY_CORPUS"], details

            for c_idx, case in enumerate(replay_cases):
                if replay_runner is not None and callable(replay_runner):
                    case_in = case.get("input", case.get("inputs", case)) if isinstance(case, Mapping) else (
                        case[0] if isinstance(case, tuple) and len(case) == 2 else case
                    )
                    try:
                        actual = replay_runner(case_in)
                    except Exception as exc:
                        return "FAIL", [f"REPLAY_RUNNER_EXCEPTION:idx={c_idx}:{exc}"], details
                elif isinstance(case, Mapping):
                    actual = case.get("output", case.get("actual"))
                else:
                    actual = case

                if isinstance(case, Mapping) and ("expected" in case or "expected_output" in case):
                    expected = case.get("expected", case.get("expected_output"))
                    if actual != expected:
                        return "FAIL", [f"REPLAY_OUTPUT_MISMATCH:idx={c_idx}"], details
                elif isinstance(case, tuple) and len(case) == 2 and replay_runner is not None:
                    if actual != case[1]:
                        return "FAIL", [f"REPLAY_OUTPUT_MISMATCH:idx={c_idx}"], details

                if callable(oracle):
                    case_in = case.get("input", case.get("inputs", case)) if isinstance(case, Mapping) else case
                    ok, msg = _invoke_oracle_callable(oracle, actual, case_in, plan_dict)
                    if not ok:
                        return "FAIL", [f"REPLAY_ORACLE_FAILED:idx={c_idx}:{msg}"], details
                elif not isinstance(case, Mapping) or ("expected" not in case and "expected_output" not in case):
                    return "NOT_VERIFIED", ["REPLAY_CASE_LACKS_ORACLE_OR_EXPECTED"], details

            has_verified_replay = True

        # 3. Evaluate standalone oracle against receipts (or fail-closed check when no outputs exist)
        if oracle is not None:
            if callable(oracle):
                if receipt_list:
                    target = receipt_list[0] if len(receipt_list) == 1 else receipt_list
                    ok, msg = _invoke_oracle_callable(oracle, target, plan_dict, security_context)
                    if not ok:
                        return "FAIL", [f"ORACLE_VERIFICATION_FAILED:{msg}"], details
                    if not has_unverified_receipt:
                        has_verified_receipts = True
                elif not has_verified_replay:
                    ok, msg = _invoke_oracle_callable(oracle, None, plan_dict, security_context)
                    if not ok:
                        return "FAIL", [f"ORACLE_VERIFICATION_FAILED:{msg}"], details
                    return "NOT_VERIFIED", ["NO_RECEIPTS_OR_REPLAY_OUTPUT_FOR_ORACLE"], details
            elif isinstance(oracle, Mapping):
                if oracle.get("passed") is False or str(oracle.get("status", "")).upper() == "FAIL":
                    return "FAIL", ["ORACLE_MAPPING_FAILED"], details
                if oracle.get("passed") is True and (has_verified_receipts or has_verified_replay):
                    pass
                elif not (has_verified_receipts or has_verified_replay):
                    return "NOT_VERIFIED", ["NO_RECEIPTS_OR_REPLAY_OUTPUT_FOR_ORACLE"], details

        if has_verified_replay or (has_verified_receipts and not has_unverified_receipt):
            return "PASS", [], details
        return "NOT_VERIFIED", [], details


def _invoke_oracle_callable(oracle: Callable[..., Any], *available_args: Any) -> Tuple[bool, str]:
    try:
        sig = inspect.signature(oracle)
        params = list(sig.parameters.values())
        has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
        positional = [
            p
            for p in params
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        if has_varargs:
            outcome = oracle(*available_args)
        else:
            count = min(len(positional), len(available_args))
            outcome = oracle(*available_args[:count])
    except Exception as exc:
        return False, f"ORACLE_EXCEPTION:{type(exc).__name__}:{exc}"

    if isinstance(outcome, bool):
        return outcome, "ORACLE_PASS" if outcome else "ORACLE_FALSE"
    if isinstance(outcome, tuple) and outcome:
        passed = bool(outcome[0])
        msg = str(outcome[1]) if len(outcome) > 1 else ("ORACLE_PASS" if passed else "ORACLE_FALSE")
        return passed, msg
    if isinstance(outcome, Mapping):
        if "passed" in outcome:
            passed = bool(outcome["passed"])
        elif "ok" in outcome:
            passed = bool(outcome["ok"])
        else:
            passed = str(outcome.get("status", "")).upper() == "PASS"
        return passed, str(outcome.get("reason") or ("ORACLE_PASS" if passed else "ORACLE_FALSE"))
    return False, "ORACLE_INVALID_RETURN"


__all__ = [
    "COMPOSITION_VERIFICATION_SCHEMA",
    "VALID_VERIFICATION_STATUSES",
    "CompositionVerificationResult",
    "CompositionVerifier",
    "parallel_execution_groups",
]
