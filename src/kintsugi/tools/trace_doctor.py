"""TraceDoctor (`kintsugi.tools.trace_doctor`): Working Tool #4 for hash-chained execution trace diagnosis.

Consumes append-only `RunEvent/1` hash chains together with `ExecutionReceipt/1`,
`CompositionReceipt/1`, and optional `CompositionPlan/1` contracts to:
  1. Verify event chain integrity (`verify_event_chain`) and flag tampered/broken chains.
  2. Reconstruct the causal directed Event DAG (from plan edges, explicit dependencies,
     cryptographic `output_digest -> input_digest` dataflow, and step lifecycle edges).
  3. Isolate `first_observable_failure` in deterministic topological order across both
     event telemetry and receipt/oracle verification outcomes.
  4. Trace the upstream causal `dependency_chain` reaching the failure.
  5. Emit `candidate_root_causes` with explicit `supporting_evidence` and falsifiable
     `distinguishing_tests`, strictly separating verified causal mechanisms from
     statistical/temporal correlation.
"""

from __future__ import annotations

import hmac
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, Union

from kintsugi.capability.contracts_v2 import (
    CompositionPlan,
    CompositionReceipt,
    EventChainVerificationResult,
    RunEvent,
    verify_event_chain,
)
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    assert_no_raw_secrets,
    canonical_json_dumps,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
)
from kintsugi.shield import TROJAN_UNICODE_RE

TRACE_DOCTOR_SCHEMA = "TraceDiagnosis/1"
MECHANISM_VERIFIED_CAUSAL = "VERIFIED_CAUSAL_MECHANISM"
MECHANISM_TEMPORAL_CORRELATION = "STATISTICAL_TEMPORAL_CORRELATION"
MECHANISM_INTEGRITY_FAILURE = "VERIFIED_INTEGRITY_VIOLATION"

_EMPTY_SHA256 = sha256_digest("")
_FAILING_EVENT_STATES = frozenset(
    {
        "FAIL",
        "FAILED",
        "ERROR",
        "PERMISSION_DENIED",
        "NO_VERIFIED_TOOL",
        "SANDBOX_UNAVAILABLE",
        "ROLLED_BACK",
        "ABORTED",
        "TIMEOUT",
        "TIMED_OUT",
        "ORACLE_FAILED",
        "TOCTOU_VIOLATION",
        "REJECTED",
        "CRASHED",
        "NOT_VERIFIED",
        "INSUFFICIENT_EVIDENCE",
    }
)
_FAILING_STATE_SUBSTRINGS = ("FAIL", "ERROR", "DENIED", "REJECT", "TIMEOUT", "VIOLATION", "CRASH", "ABORT")
_FAILING_RECEIPT_STATUSES = frozenset(
    {
        ExecutionStatus.FAIL.value,
        ExecutionStatus.NOT_VERIFIED.value,
        ExecutionStatus.INSUFFICIENT_EVIDENCE.value,
        ExecutionStatus.NO_VERIFIED_TOOL.value,
        ExecutionStatus.PERMISSION_DENIED.value,
        ExecutionStatus.SANDBOX_UNAVAILABLE.value,
        ExecutionStatus.ROLLED_BACK.value,
    }
)
_WARNING_STATES = frozenset({"WARN", "WARNING", "DEGRADED", "RETRY", "FALLBACK", "ANOMALY"})


@dataclass
class TraceDagNode:
    """Single verified telemetry event node inside a reconstructed Event DAG."""

    node_id: str
    event_index: int
    step_id: str
    plan_node_id: str
    state: str
    tool_id: str
    input_digest: str
    output_digest: str
    elapsed_ms: float
    tokens_used: int
    decision_reason: str
    event_hash: str
    seq: Optional[int] = None
    severity: Optional[str] = None
    resource_usage: Dict[str, Any] = field(default_factory=dict)
    correlation: Dict[str, Any] = field(default_factory=dict)
    event_failed: bool = False
    event_failure_reasons: List[str] = field(default_factory=list)
    receipt_failed: bool = False
    receipt_failure_reasons: List[str] = field(default_factory=list)
    receipt_status: Optional[str] = None

    @property
    def failed(self) -> bool:
        return self.event_failed or self.receipt_failed

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "node_id": self.node_id,
                "event_index": self.event_index,
                "step_id": self.step_id,
                "plan_node_id": self.plan_node_id,
                "state": self.state,
                "tool_id": self.tool_id,
                "input_digest": self.input_digest,
                "output_digest": self.output_digest,
                "elapsed_ms": self.elapsed_ms,
                "tokens_used": self.tokens_used,
                "decision_reason": self.decision_reason,
                "event_hash": self.event_hash,
                "seq": self.seq,
                "severity": self.severity,
                "event_failed": self.event_failed,
                "event_failure_reasons": list(self.event_failure_reasons),
                "receipt_failed": self.receipt_failed,
                "receipt_failure_reasons": list(self.receipt_failure_reasons),
                "receipt_status": self.receipt_status,
            }
        )


@dataclass
class TraceDagEdge:
    """Directed causal dependency edge in the reconstructed Event DAG."""

    from_node: str
    to_node: str
    edge_type: str
    evidence: str = ""
    mechanisms: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.mechanisms:
            self.mechanisms = [self.edge_type]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_node": self.from_node,
            "to_node": self.to_node,
            "edge_type": self.edge_type,
            "mechanisms": list(self.mechanisms),
            "evidence": redact_secrets_in_text(self.evidence),
        }


@dataclass
class CandidateRootCause:
    """Structured root-cause hypothesis separating verified causal mechanisms from correlation."""

    cause_id: str
    category: str
    mechanism_type: str
    causal_verified: bool
    confidence: float
    suspect_node_id: Optional[str]
    step_id: Optional[str]
    tool_id: Optional[str]
    summary: str
    supporting_evidence: List[str] = field(default_factory=list)
    distinguishing_tests: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "cause_id": self.cause_id,
                "category": self.category,
                "mechanism_type": self.mechanism_type,
                "causal_verified": self.causal_verified,
                "confidence": round(float(self.confidence), 4),
                "suspect_node_id": self.suspect_node_id,
                "step_id": self.step_id,
                "tool_id": self.tool_id,
                "summary": self.summary,
                "supporting_evidence": list(self.supporting_evidence),
                "distinguishing_tests": list(self.distinguishing_tests),
            }
        )


@dataclass
class TraceDiagnosis:
    """Deterministic `TraceDiagnosis/1` output produced by `TraceDoctor.diagnose(...)`."""

    status: str
    ok: bool
    chain_valid: bool
    tampered: bool
    zero_failure: bool
    run_id: str = ""
    chain_verification: Dict[str, Any] = field(default_factory=dict)
    chain_errors: List[str] = field(default_factory=list)
    dag_nodes: List[Dict[str, Any]] = field(default_factory=list)
    dag_edges: List[Dict[str, Any]] = field(default_factory=list)
    topological_order: List[str] = field(default_factory=list)
    first_observable_failure: Optional[Dict[str, Any]] = None
    dependency_chain: List[Dict[str, Any]] = field(default_factory=list)
    candidate_root_causes: List[Dict[str, Any]] = field(default_factory=list)
    receipt_summary: Dict[str, Any] = field(default_factory=dict)
    llm_calls: int = 0
    diagnosis_digest: str = ""
    schema: str = TRACE_DOCTOR_SCHEMA

    def __post_init__(self) -> None:
        if not self.diagnosis_digest:
            payload = self.to_dict(include_digest=False)
            self.diagnosis_digest = sha256_digest(payload)

    def to_dict(self, *, include_digest: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "schema": self.schema,
            "status": self.status,
            "ok": self.ok,
            "chain_valid": self.chain_valid,
            "tampered": self.tampered,
            "zero_failure": self.zero_failure,
            "run_id": self.run_id,
            "chain_verification": dict(self.chain_verification),
            "chain_errors": list(self.chain_errors),
            "dag_nodes": list(self.dag_nodes),
            "dag_edges": list(self.dag_edges),
            "topological_order": list(self.topological_order),
            "first_observable_failure": (
                dict(self.first_observable_failure) if self.first_observable_failure is not None else None
            ),
            "dependency_chain": list(self.dependency_chain),
            "candidate_root_causes": list(self.candidate_root_causes),
            "receipt_summary": dict(self.receipt_summary),
            "llm_calls": self.llm_calls,
        }
        if include_digest:
            payload["diagnosis_digest"] = self.diagnosis_digest
        cleaned = redact_secrets_in_value(payload)
        assert_no_raw_secrets(canonical_json_dumps(cleaned), context="TraceDiagnosis")
        return cleaned

    def to_canonical_json(self) -> str:
        serialized = canonical_json_dumps(self.to_dict())
        assert_no_raw_secrets(serialized, context="TraceDiagnosis.canonical")
        return serialized


def _sanitize_text(value: Any) -> str:
    raw = str(value or "")
    raw = TROJAN_UNICODE_RE.sub("", raw).replace("\x00", "")
    return redact_secrets_in_text(raw.strip())


def _normalize_plan(
    plan: Optional[Union[CompositionPlan, Mapping[str, Any]]],
) -> Tuple[Optional[CompositionPlan], Optional[str]]:
    if plan is None:
        return None, None
    try:
        return CompositionPlan.from_dict(plan), None
    except (ValueError, KeyError, TypeError) as exc:
        return None, f"INVALID_COMPOSITION_PLAN:{_sanitize_text(exc)}"


def _normalize_single_receipt(
    raw: Union[ExecutionReceipt, CompositionReceipt, Mapping[str, Any]],
) -> Tuple[Optional[Union[ExecutionReceipt, CompositionReceipt]], Optional[str]]:
    if isinstance(raw, (ExecutionReceipt, CompositionReceipt)):
        return raw, None
    if not isinstance(raw, Mapping):
        return None, "INVALID_RECEIPT_TYPE: expected ExecutionReceipt, CompositionReceipt, or mapping"
    schema = str(raw.get("schema") or "").strip()
    try:
        if schema == "CompositionReceipt/1" or "node_receipts" in raw or "sandbox_environment_hash" in raw:
            return CompositionReceipt.from_dict(raw), None
        return ExecutionReceipt.from_dict(dict(raw)), None
    except (ValueError, KeyError, TypeError) as exc:
        return None, f"INVALID_RECEIPT:{_sanitize_text(exc)}"


def _collect_receipts(
    receipt: Optional[Union[ExecutionReceipt, CompositionReceipt, Mapping[str, Any]]],
    receipts: Optional[Sequence[Union[ExecutionReceipt, CompositionReceipt, Mapping[str, Any]]]],
) -> Tuple[List[Union[ExecutionReceipt, CompositionReceipt]], List[str]]:
    items: List[Union[ExecutionReceipt, CompositionReceipt, Mapping[str, Any]]] = []
    if receipt is not None:
        items.append(receipt)
    if receipts:
        items.extend(receipts)
    parsed: List[Union[ExecutionReceipt, CompositionReceipt]] = []
    errors: List[str] = []
    for item in items:
        obj, err = _normalize_single_receipt(item)
        if err is not None:
            errors.append(err)
        elif obj is not None:
            parsed.append(obj)
    return parsed, errors


def _receipt_failed(rec: Union[ExecutionReceipt, CompositionReceipt]) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    status_val = rec.status.value
    if status_val in _FAILING_RECEIPT_STATUSES:
        reasons.append(f"receipt_status={status_val}")
    ver_val = str(rec.verification_status or "").strip().upper()
    if ver_val in {"FAIL", "FAILED", "NOT_VERIFIED", "INSUFFICIENT_EVIDENCE"}:
        reasons.append(f"verification_status={ver_val}")
    if isinstance(rec, ExecutionReceipt):
        if rec.exit_status != 0:
            reasons.append(f"exit_status={rec.exit_status}")
        if rec.stderr_excerpt:
            reasons.append(f"stderr={_sanitize_text(rec.stderr_excerpt[:240])}")
    else:
        if rec.oracle_result.get("passed") is False:
            reasons.append(
                f"oracle_failed:{_sanitize_text(rec.oracle_result.get('reason') or 'passed=False')}"
            )
    return (len(reasons) > 0), reasons


def _node_receipt_failed(nr: Mapping[str, Any]) -> Tuple[bool, Optional[str], List[str]]:
    reasons: List[str] = []
    raw_status = str(nr.get("status") or "").strip().upper()
    if raw_status in _FAILING_RECEIPT_STATUSES or any(tok in raw_status for tok in _FAILING_STATE_SUBSTRINGS):
        reasons.append(f"node_receipt_status={raw_status}")
    ver = str(nr.get("verification_status") or "").strip().upper()
    if ver in {"FAIL", "FAILED", "NOT_VERIFIED", "INSUFFICIENT_EVIDENCE"}:
        reasons.append(f"node_verification_status={ver}")
    exit_code = nr.get("exit_status", nr.get("exit_code"))
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        reasons.append(f"node_exit_status={exit_code}")
    if nr.get("passed") is False:
        reasons.append("node_passed=False")
    oracle_res = nr.get("oracle_result")
    if isinstance(oracle_res, Mapping) and oracle_res.get("passed") is False:
        reasons.append("node_oracle_passed=False")
    err_msg = nr.get("error") or nr.get("reason") or nr.get("stderr_excerpt")
    if err_msg and reasons:
        reasons.append(f"detail={_sanitize_text(str(err_msg)[:200])}")
    return (len(reasons) > 0), (raw_status or None), reasons


def _event_failed(ev: RunEvent) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    state_up = ev.state.strip().upper()
    if state_up in _FAILING_EVENT_STATES or any(sub in state_up for sub in _FAILING_STATE_SUBSTRINGS):
        reasons.append(f"event_state={ev.state}")
    ru = ev.resource_usage or {}
    ru_status = str(ru.get("status") or "").strip().upper()
    if ru_status in _FAILING_RECEIPT_STATUSES or any(sub in ru_status for sub in _FAILING_STATE_SUBSTRINGS):
        reasons.append(f"resource_status={ru_status}")
    exit_code = ru.get("exit_code", ru.get("exit_status"))
    if isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0:
        reasons.append(f"event_exit_code={exit_code}")
    if ru.get("passed") is False:
        reasons.append("event_passed=False")
    if ru.get("error"):
        reasons.append(f"event_error={_sanitize_text(str(ru['error'])[:200])}")
    if reasons and ev.decision_reason:
        reasons.append(f"decision_reason={_sanitize_text(ev.decision_reason[:200])}")
    return (len(reasons) > 0), reasons


def _extract_plan_node_id(ev: RunEvent) -> str:
    ru = ev.resource_usage or {}
    corr = ev.correlation or {}
    for cand in (ru.get("node_id"), corr.get("node_id")):
        if isinstance(cand, str) and cand.strip():
            return cand.strip()
    step = ev.step_id.strip()
    for sep in (":", "#"):
        if sep in step:
            return step.split(sep, 1)[0]
    return step


def _extract_explicit_parents(ev: RunEvent) -> List[str]:
    ru = ev.resource_usage or {}
    parents: List[str] = []
    for key in ("depends_on", "parent_step_ids", "upstream_step_ids", "upstream_nodes"):
        val = ru.get(key)
        if isinstance(val, (list, tuple, set)):
            for item in val:
                s = str(item or "").strip()
                if s:
                    parents.append(s)
        elif isinstance(val, str) and val.strip():
            parents.append(val.strip())
    for key in ("parent_step_id", "parent_node_id"):
        val = ru.get(key)
        if isinstance(val, str) and val.strip():
            parents.append(val.strip())
    return list(dict.fromkeys(parents))


def _binding_node_name(expr: Any) -> Optional[str]:
    if not isinstance(expr, str):
        return None
    cleaned = expr.strip()
    if "." not in cleaned:
        return None
    prefix = cleaned.split(".", 1)[0].strip()
    if not prefix or prefix.lower() in {"goal", "input", "inputs", "env", "context"}:
        return None
    return prefix


def _categorize_failure(text_blob: str, state: str = "", receipt_status: Optional[str] = None) -> str:
    combined = f"{state} {receipt_status or ''} {text_blob}".upper()
    if "TOCTOU" in combined or "INODE_CHANGED" in combined or "BINARY_HASH_CHANGED" in combined:
        return "TOCTOU_INTEGRITY_VIOLATION"
    if "PERMISSION_DENIED" in combined or "OVER_PRIVILEGED" in combined or "DISALLOWED_BY_POLICY" in combined:
        return "POLICY_OR_PERMISSION_DENIAL"
    if "NO_VERIFIED_TOOL" in combined or "QUARANTIN" in combined or "RETIRED_TOOL" in combined:
        return "MISSING_OR_UNVERIFIED_TOOL"
    if "SANDBOX_UNAVAILABLE" in combined:
        return "SANDBOX_UNAVAILABLE"
    if "ORACLE" in combined or "POSTCONDITION" in combined or "MISMATCH" in combined:
        return "ORACLE_VERIFICATION_FAILURE"
    if "TIMEOUT" in combined or "TIMED_OUT" in combined:
        return "EXECUTION_TIMEOUT"
    return "TOOL_EXECUTION_FAILURE"


class TraceDoctor:
    """Deterministic execution trace diagnostician (`Working Tool #4`, `llm_calls=0`)."""

    SCHEMA_VERSION = TRACE_DOCTOR_SCHEMA

    @staticmethod
    def verify_chain(
        events: Sequence[Union[RunEvent, Mapping[str, Any]]],
    ) -> EventChainVerificationResult:
        """Verify append-only `RunEvent/1` cryptographic hash chain."""
        return verify_event_chain(events)

    def diagnose(
        self,
        events: Sequence[Union[RunEvent, Mapping[str, Any]]],
        receipt: Optional[Union[ExecutionReceipt, CompositionReceipt, Mapping[str, Any]]] = None,
        *,
        receipts: Optional[Sequence[Union[ExecutionReceipt, CompositionReceipt, Mapping[str, Any]]]] = None,
        plan: Optional[Union[CompositionPlan, Mapping[str, Any]]] = None,
        raise_on_tamper: bool = False,
    ) -> TraceDiagnosis:
        """
        Verify event chain, build Event DAG, isolate `first_observable_failure`, trace upstream
        `dependency_chain`, and emit falsifiable `candidate_root_causes`.
        """
        parsed_plan, plan_err = _normalize_plan(plan)
        parsed_receipts, receipt_parse_errors = _collect_receipts(receipt, receipts)
        chain_res = verify_event_chain(events)
        parsed_events: List[RunEvent] = []

        if chain_res.valid:
            for raw_ev in events:
                parsed_events.append(raw_ev if isinstance(raw_ev, RunEvent) else RunEvent.from_dict(raw_ev))

        event_run_id = parsed_events[0].run_id if parsed_events else ""
        integrity_errors: List[str] = list(chain_res.reasons)

        if plan_err is not None:
            integrity_errors.append(plan_err)
        integrity_errors.extend(receipt_parse_errors)

        for rec in parsed_receipts:
            if event_run_id and rec.run_id != event_run_id:
                integrity_errors.append(
                    f"RECEIPT_RUN_ID_MISMATCH:event_run_id={event_run_id}:receipt_run_id={rec.run_id}"
                )
            if parsed_plan is not None and not hmac.compare_digest(rec.plan_hash, parsed_plan.plan_hash):
                integrity_errors.append(
                    f"RECEIPT_PLAN_HASH_MISMATCH:receipt={rec.plan_hash}:plan={parsed_plan.plan_hash}"
                )

        if parsed_events:
            prev_seq: Optional[int] = None
            for idx, ev in enumerate(parsed_events):
                if ev.seq is not None:
                    if prev_seq is not None and ev.seq < prev_seq:
                        integrity_errors.append(f"EVENT_SEQ_REGRESSION:idx={idx}:seq={ev.seq}<{prev_seq}")
                    prev_seq = ev.seq

        tampered = not chain_res.valid or any(
            err.startswith(
                (
                    "INVALID_RECEIPT",
                    "INVALID_COMPOSITION_PLAN",
                    "RECEIPT_RUN_ID_MISMATCH",
                    "RECEIPT_PLAN_HASH_MISMATCH",
                    "EVENT_SEQ_REGRESSION",
                )
            )
            for err in integrity_errors
        )

        receipt_summary = self._summarize_receipts(parsed_receipts, chain_res.head_hash)

        if tampered:
            if raise_on_tamper:
                raise ValueError(f"TAMPERED_EVENT_CHAIN: {'; '.join(integrity_errors)}")
            tamper_cause = CandidateRootCause(
                cause_id="cause-integrity-0",
                category="EVENT_CHAIN_INTEGRITY_VIOLATION",
                mechanism_type=MECHANISM_INTEGRITY_FAILURE,
                causal_verified=True,
                confidence=0.99,
                suspect_node_id=None,
                step_id=None,
                tool_id=None,
                summary="Execution trace failed cryptographic hash-chain or receipt integrity verification.",
                supporting_evidence=list(integrity_errors),
                distinguishing_tests=[
                    "Recompute canonical RunEvent/1 SHA-256 digests from genesis and compare against stored event_hash/prev_event_hash.",
                    "Compare receipt plan_hash and run_id against immutable CompositionPlan/1 and RunEvent log.",
                ],
            )
            return TraceDiagnosis(
                status="TAMPERED_EVENT_CHAIN",
                ok=False,
                chain_valid=chain_res.valid,
                tampered=True,
                zero_failure=False,
                run_id=event_run_id or (parsed_receipts[0].run_id if parsed_receipts else ""),
                chain_verification=chain_res.to_dict(),
                chain_errors=integrity_errors,
                dag_nodes=[],
                dag_edges=[],
                topological_order=[],
                first_observable_failure=None,
                dependency_chain=[],
                candidate_root_causes=[tamper_cause.to_dict()],
                receipt_summary=receipt_summary,
                llm_calls=0,
            )

        dag_nodes, dag_edges, topo_order, cycle_detected = self._build_event_dag(
            parsed_events, parsed_receipts, parsed_plan
        )
        if cycle_detected:
            cycle_cause = CandidateRootCause(
                cause_id="cause-dag-cycle",
                category="EVENT_DAG_CYCLE_DETECTED",
                mechanism_type=MECHANISM_INTEGRITY_FAILURE,
                causal_verified=True,
                confidence=0.95,
                suspect_node_id=None,
                step_id=None,
                tool_id=None,
                summary="Explicit event or plan metadata introduces a dependency cycle in the Event DAG.",
                supporting_evidence=["Kahn topological sort could not visit all DAG nodes."],
                distinguishing_tests=[
                    "Inspect explicit depends_on / CompositionPlan.edges for cyclic back-edges."
                ],
            )
            return TraceDiagnosis(
                status="INVALID_EVENT_DAG_CYCLE",
                ok=False,
                chain_valid=True,
                tampered=False,
                zero_failure=False,
                run_id=event_run_id or (parsed_receipts[0].run_id if parsed_receipts else ""),
                chain_verification=chain_res.to_dict(),
                chain_errors=[],
                dag_nodes=[n.to_dict() for n in dag_nodes.values()],
                dag_edges=[e.to_dict() for e in dag_edges],
                topological_order=topo_order,
                first_observable_failure=None,
                dependency_chain=[],
                candidate_root_causes=[cycle_cause.to_dict()],
                receipt_summary=receipt_summary,
                llm_calls=0,
            )

        first_fail_node = self._isolate_first_observable_failure(dag_nodes, topo_order)
        if first_fail_node is not None:
            dep_chain = self._trace_dependency_chain(first_fail_node.node_id, dag_nodes, dag_edges, topo_order)
            causes = self._emit_causal_and_correlated_candidates(
                first_fail_node, dep_chain, dag_nodes, dag_edges, parsed_receipts
            )
            return TraceDiagnosis(
                status="FAILURE_DIAGNOSED",
                ok=False,
                chain_valid=True,
                tampered=False,
                zero_failure=False,
                run_id=event_run_id or (parsed_receipts[0].run_id if parsed_receipts else ""),
                chain_verification=chain_res.to_dict(),
                chain_errors=[],
                dag_nodes=[dag_nodes[nid].to_dict() for nid in topo_order],
                dag_edges=[e.to_dict() for e in dag_edges],
                topological_order=topo_order,
                first_observable_failure=first_fail_node.to_dict(),
                dependency_chain=dep_chain,
                candidate_root_causes=[c.to_dict() for c in causes],
                receipt_summary=receipt_summary,
                llm_calls=0,
            )

        # Check top-level failing receipt when no node-level failure event/node_receipt fired
        failing_top_receipts = []
        for rec in parsed_receipts:
            r_fail, r_reasons = _receipt_failed(rec)
            if r_fail:
                failing_top_receipts.append((rec, r_reasons))

        if failing_top_receipts:
            rec, r_reasons = failing_top_receipts[0]
            boundary_failure, dep_chain, causes = self._diagnose_receipt_boundary_failure(
                rec, r_reasons, dag_nodes, dag_edges, topo_order
            )
            return TraceDiagnosis(
                status="FAILURE_DIAGNOSED",
                ok=False,
                chain_valid=True,
                tampered=False,
                zero_failure=False,
                run_id=event_run_id or rec.run_id,
                chain_verification=chain_res.to_dict(),
                chain_errors=[],
                dag_nodes=[dag_nodes[nid].to_dict() for nid in topo_order],
                dag_edges=[e.to_dict() for e in dag_edges],
                topological_order=topo_order,
                first_observable_failure=boundary_failure,
                dependency_chain=dep_chain,
                candidate_root_causes=[c.to_dict() for c in causes],
                receipt_summary=receipt_summary,
                llm_calls=0,
            )

        # Zero-failure run handled cleanly
        return TraceDiagnosis(
            status="NO_FAILURES_DETECTED",
            ok=True,
            chain_valid=True,
            tampered=False,
            zero_failure=True,
            run_id=event_run_id or (parsed_receipts[0].run_id if parsed_receipts else ""),
            chain_verification=chain_res.to_dict(),
            chain_errors=[],
            dag_nodes=[dag_nodes[nid].to_dict() for nid in topo_order],
            dag_edges=[e.to_dict() for e in dag_edges],
            topological_order=topo_order,
            first_observable_failure=None,
            dependency_chain=[],
            candidate_root_causes=[],
            receipt_summary=receipt_summary,
            llm_calls=0,
        )

    @staticmethod
    def _summarize_receipts(
        receipts: Sequence[Union[ExecutionReceipt, CompositionReceipt]],
        chain_head_hash: str,
    ) -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []
        all_passed = True
        for rec in receipts:
            failed, reasons = _receipt_failed(rec)
            if failed:
                all_passed = False
            items.append(
                {
                    "schema": rec.schema,
                    "run_id": rec.run_id,
                    "status": rec.status.value,
                    "verification_status": rec.verification_status,
                    "plan_hash": rec.plan_hash,
                    "trace_digest": rec.trace_digest,
                    "trace_digest_bound_to_chain": bool(
                        chain_head_hash and hmac.compare_digest(rec.trace_digest, chain_head_hash)
                    ),
                    "failed": failed,
                    "failure_reasons": reasons,
                }
            )
        return {
            "count": len(items),
            "all_passed": all_passed if items else None,
            "receipts": items,
        }

    def _build_event_dag(
        self,
        events: Sequence[RunEvent],
        receipts: Sequence[Union[ExecutionReceipt, CompositionReceipt]],
        plan: Optional[CompositionPlan],
    ) -> Tuple[Dict[str, TraceDagNode], List[TraceDagEdge], List[str], bool]:
        nodes: Dict[str, TraceDagNode] = {}
        by_step: Dict[str, List[str]] = {}
        by_plan_node: Dict[str, List[str]] = {}
        by_output_digest: Dict[str, List[str]] = {}

        # Index node-level receipts by (node_id/step_id, tool_id)
        node_receipt_by_id: Dict[str, Mapping[str, Any]] = {}
        single_exec_receipts: List[ExecutionReceipt] = []
        for rec in receipts:
            if isinstance(rec, CompositionReceipt):
                for nr in rec.node_receipts:
                    for key_name in ("node_id", "step_id"):
                        val = nr.get(key_name)
                        if isinstance(val, str) and val.strip():
                            node_receipt_by_id[val.strip()] = nr
            elif isinstance(rec, ExecutionReceipt):
                single_exec_receipts.append(rec)

        for idx, ev in enumerate(events):
            base_id = ev.event_id if ev.event_id and ev.event_id not in nodes else f"{ev.step_id}#{idx}"
            if base_id in nodes:
                base_id = f"ev#{idx}:{ev.step_id}"
            plan_nid = _extract_plan_node_id(ev)
            ev_failed, ev_reasons = _event_failed(ev)

            matched_nr = node_receipt_by_id.get(ev.step_id) or node_receipt_by_id.get(plan_nid)
            rec_failed = False
            rec_status: Optional[str] = None
            rec_reasons: List[str] = []
            if matched_nr is not None:
                rec_failed, rec_status, rec_reasons = _node_receipt_failed(matched_nr)
            elif len(single_exec_receipts) == 1 and len(events) == 1:
                rec_failed, rec_reasons = _receipt_failed(single_exec_receipts[0])
                rec_status = single_exec_receipts[0].status.value

            dag_node = TraceDagNode(
                node_id=base_id,
                event_index=idx,
                step_id=ev.step_id,
                plan_node_id=plan_nid,
                state=ev.state,
                tool_id=ev.tool_id,
                input_digest=ev.input_digest,
                output_digest=ev.output_digest,
                elapsed_ms=ev.elapsed_ms,
                tokens_used=ev.tokens_used,
                decision_reason=ev.decision_reason,
                event_hash=ev.event_hash,
                seq=ev.seq,
                severity=ev.severity,
                resource_usage=dict(ev.resource_usage),
                correlation=dict(ev.correlation or {}),
                event_failed=ev_failed,
                event_failure_reasons=ev_reasons,
                receipt_failed=rec_failed,
                receipt_failure_reasons=rec_reasons,
                receipt_status=rec_status,
            )
            nodes[base_id] = dag_node
            by_step.setdefault(ev.step_id, []).append(base_id)
            by_plan_node.setdefault(plan_nid, []).append(base_id)
            if ev.output_digest and ev.output_digest != _EMPTY_SHA256:
                by_output_digest.setdefault(ev.output_digest, []).append(base_id)

        edge_map: Dict[Tuple[str, str], TraceDagEdge] = {}

        def _add_edge(src_id: str, dst_id: str, edge_type: str, evidence: str) -> None:
            if src_id == dst_id or src_id not in nodes or dst_id not in nodes:
                return
            key = (src_id, dst_id)
            existing = edge_map.get(key)
            if existing is None:
                edge_map[key] = TraceDagEdge(
                    from_node=src_id,
                    to_node=dst_id,
                    edge_type=edge_type,
                    evidence=evidence,
                    mechanisms=[edge_type],
                )
            else:
                if edge_type not in existing.mechanisms:
                    existing.mechanisms.append(edge_type)
                if evidence and evidence not in existing.evidence:
                    existing.evidence = f"{existing.evidence}; {evidence}" if existing.evidence else evidence

        # 1. Same-step lifecycle transitions (STARTED -> COMPLETED/FAILED)
        for step_id, nids in by_step.items():
            for pos in range(len(nids) - 1):
                _add_edge(nids[pos], nids[pos + 1], "STEP_LIFECYCLE_EDGE", f"step_id={step_id}")

        # 2. CompositionPlan explicit edges & input_bindings
        if plan is not None:
            for edge in plan.edges:
                src_p = str(edge.get("from_node") or "").strip()
                dst_p = str(edge.get("to_node") or "").strip()
                src_events = by_plan_node.get(src_p) or by_step.get(src_p) or []
                dst_events = by_plan_node.get(dst_p) or by_step.get(dst_p) or []
                if src_events and dst_events:
                    _add_edge(
                        src_events[-1],
                        dst_events[0],
                        "PLAN_DATAFLOW_EDGE",
                        f"plan_edge:{src_p}->{dst_p}",
                    )
            for target_bind, source_bind in plan.input_bindings.items():
                dst_p = _binding_node_name(target_bind)
                src_p = _binding_node_name(source_bind)
                if src_p and dst_p and src_p != dst_p:
                    src_events = by_plan_node.get(src_p) or by_step.get(src_p) or []
                    dst_events = by_plan_node.get(dst_p) or by_step.get(dst_p) or []
                    if src_events and dst_events:
                        _add_edge(
                            src_events[-1],
                            dst_events[0],
                            "PLAN_DATAFLOW_EDGE",
                            f"input_binding:{source_bind}->{target_bind}",
                        )

        # 3. Explicit depends_on / parent_step_id metadata
        for idx, ev in enumerate(events):
            cur_id = list(nodes.keys())[idx]
            for parent_ref in _extract_explicit_parents(ev):
                cand_ids = by_step.get(parent_ref) or by_plan_node.get(parent_ref) or []
                prior_cands = [cid for cid in cand_ids if nodes[cid].event_index < idx]
                chosen = prior_cands[-1] if prior_cands else (cand_ids[-1] if cand_ids else None)
                if chosen:
                    _add_edge(chosen, cur_id, "EXPLICIT_DEPENDENCY_EDGE", f"depends_on={parent_ref}")

        # 4. Cryptographic output_digest -> input_digest dataflow links (preceding events only)
        for idx, ev in enumerate(events):
            cur_id = list(nodes.keys())[idx]
            if not ev.input_digest or ev.input_digest == _EMPTY_SHA256:
                continue
            producers = [
                pid
                for pid in by_output_digest.get(ev.input_digest, ())
                if nodes[pid].event_index < idx and nodes[pid].step_id != ev.step_id
            ]
            if producers:
                latest_producer = producers[-1]
                _add_edge(
                    latest_producer,
                    cur_id,
                    "DIGEST_DATAFLOW_EDGE",
                    f"digest={ev.input_digest}",
                )

        edges = sorted(
            edge_map.values(),
            key=lambda e: (nodes[e.from_node].event_index, nodes[e.to_node].event_index, e.edge_type),
        )

        # Deterministic Kahn topological sort
        adj: Dict[str, List[str]] = {nid: [] for nid in nodes}
        indegree: Dict[str, int] = {nid: 0 for nid in nodes}
        seen_pair: Set[Tuple[str, str]] = set()
        for edge in edges:
            pair = (edge.from_node, edge.to_node)
            if pair not in seen_pair:
                seen_pair.add(pair)
                adj[edge.from_node].append(edge.to_node)
                indegree[edge.to_node] += 1

        ready = sorted((nid for nid, deg in indegree.items() if deg == 0), key=lambda nid: nodes[nid].event_index)
        queue: deque[str] = deque(ready)
        topo_order: List[str] = []
        while queue:
            cur = queue.popleft()
            topo_order.append(cur)
            newly_ready: List[str] = []
            for nxt in adj[cur]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    newly_ready.append(nxt)
            if newly_ready:
                merged = sorted(list(queue) + newly_ready, key=lambda nid: nodes[nid].event_index)
                queue = deque(merged)

        cycle_detected = len(topo_order) != len(nodes)
        return nodes, edges, topo_order, cycle_detected

    @staticmethod
    def _isolate_first_observable_failure(
        nodes: Mapping[str, TraceDagNode],
        topo_order: Sequence[str],
    ) -> Optional[TraceDagNode]:
        for nid in topo_order:
            node = nodes[nid]
            if node.failed:
                return node
        return None

    @staticmethod
    def _trace_dependency_chain(
        fail_node_id: str,
        nodes: Mapping[str, TraceDagNode],
        edges: Sequence[TraceDagEdge],
        topo_order: Sequence[str],
    ) -> List[Dict[str, Any]]:
        reverse_adj: Dict[str, List[TraceDagEdge]] = {}
        forward_to_chain: Dict[str, List[TraceDagEdge]] = {}
        for edge in edges:
            reverse_adj.setdefault(edge.to_node, []).append(edge)
            forward_to_chain.setdefault(edge.from_node, []).append(edge)

        ancestors: Set[str] = {fail_node_id}
        stack: List[str] = [fail_node_id]
        while stack:
            cur = stack.pop()
            for edge in reverse_adj.get(cur, ()):
                if edge.from_node not in ancestors:
                    ancestors.add(edge.from_node)
                    stack.append(edge.from_node)

        chain: List[Dict[str, Any]] = []
        for nid in topo_order:
            if nid not in ancestors:
                continue
            node = nodes[nid]
            outgoing_in_chain = [
                {"to_node": e.to_node, "edge_type": e.edge_type, "evidence": e.evidence}
                for e in forward_to_chain.get(nid, ())
                if e.to_node in ancestors
            ]
            chain.append(
                {
                    "node_id": node.node_id,
                    "step_id": node.step_id,
                    "plan_node_id": node.plan_node_id,
                    "tool_id": node.tool_id,
                    "state": node.state,
                    "event_index": node.event_index,
                    "input_digest": node.input_digest,
                    "output_digest": node.output_digest,
                    "failed": node.failed,
                    "receipt_status": node.receipt_status,
                    "outgoing_causal_edges": outgoing_in_chain,
                }
            )
        return chain

    def _emit_causal_and_correlated_candidates(
        self,
        fail_node: TraceDagNode,
        dep_chain: Sequence[Mapping[str, Any]],
        nodes: Mapping[str, TraceDagNode],
        edges: Sequence[TraceDagEdge],
        receipts: Sequence[Union[ExecutionReceipt, CompositionReceipt]],
    ) -> List[CandidateRootCause]:
        candidates: List[CandidateRootCause] = []
        evidence: List[str] = [
            f"first_observable_failure node_id={fail_node.node_id} step_id={fail_node.step_id} (event_index={fail_node.event_index})",
            f"event_hash={fail_node.event_hash}",
        ]
        evidence.extend(fail_node.event_failure_reasons)
        evidence.extend(fail_node.receipt_failure_reasons)
        if fail_node.tool_id:
            evidence.append(f"tool_id={fail_node.tool_id}")

        all_err_text = " ".join(fail_node.event_failure_reasons + fail_node.receipt_failure_reasons + [fail_node.decision_reason])
        category = _categorize_failure(all_err_text, fail_node.state, fail_node.receipt_status)

        direct_tests = [
            f"Replay step '{fail_node.step_id}' (tool='{fail_node.tool_id or 'unknown'}') in isolation with input_digest={fail_node.input_digest}.",
            f"Verify tool binary integrity, permissions, and contract postconditions for '{fail_node.tool_id or fail_node.step_id}'.",
        ]
        if category == "TOCTOU_INTEGRITY_VIOLATION":
            direct_tests.insert(0, "Recompute SHA-256 and inode metadata of tool artifact against verified ToolSpec.binary_hash.")
        elif category == "POLICY_OR_PERMISSION_DENIAL":
            direct_tests.insert(0, "Diff ToolSpec.required_permissions and runtime_requirements against SecurityContext.allowed_permissions.")
        elif category == "ORACLE_VERIFICATION_FAILURE":
            direct_tests.insert(0, "Run target oracle assertion directly on step output artifact to confirm contract mismatch.")

        candidates.append(
            CandidateRootCause(
                cause_id=f"cause-direct-{fail_node.step_id}",
                category=category,
                mechanism_type=MECHANISM_VERIFIED_CAUSAL,
                causal_verified=True,
                confidence=0.92 if fail_node.receipt_failed else 0.85,
                suspect_node_id=fail_node.node_id,
                step_id=fail_node.step_id,
                tool_id=fail_node.tool_id or None,
                summary=f"First observable failure occurred at step '{fail_node.step_id}' ({category}).",
                supporting_evidence=evidence,
                distinguishing_tests=direct_tests,
            )
        )

        # Check causal upstream nodes for verified dataflow or anomaly propagation
        incoming_to_fail = [e for e in edges if e.to_node == fail_node.node_id]
        ancestor_ids = {item["node_id"] for item in dep_chain}
        for edge in incoming_to_fail:
            up_node = nodes.get(edge.from_node)
            if up_node is None or up_node.node_id == fail_node.node_id:
                continue
            up_state_up = up_node.state.strip().upper()
            is_warning = up_state_up in _WARNING_STATES or bool(up_node.resource_usage.get("warning"))
            if edge.edge_type in ("DIGEST_DATAFLOW_EDGE", "PLAN_DATAFLOW_EDGE"):
                up_evidence = [
                    f"Causal {edge.edge_type} ({edge.evidence}) links upstream step '{up_node.step_id}' -> '{fail_node.step_id}'.",
                    f"upstream output_digest={up_node.output_digest} -> failing input_digest={fail_node.input_digest}",
                ]
                if is_warning:
                    up_evidence.append(f"Upstream step emitted warning/degraded state '{up_node.state}'.")
                candidates.append(
                    CandidateRootCause(
                        cause_id=f"cause-upstream-{up_node.step_id}",
                        category="UPSTREAM_DATA_CONTRACT_DRIFT" if not is_warning else "UPSTREAM_DEGRADED_OUTPUT",
                        mechanism_type=MECHANISM_VERIFIED_CAUSAL,
                        causal_verified=True,
                        confidence=0.68 if is_warning else 0.55,
                        suspect_node_id=up_node.node_id,
                        step_id=up_node.step_id,
                        tool_id=up_node.tool_id or None,
                        summary=(
                            f"Upstream node '{up_node.step_id}' fed data into failing step '{fail_node.step_id}' "
                            f"via {edge.edge_type}."
                        ),
                        supporting_evidence=up_evidence,
                        distinguishing_tests=[
                            f"Substitute golden expected input fixture for '{fail_node.step_id}' bypassing '{up_node.step_id}'; "
                            "if failure disappears, upstream output semantics caused the failure."
                        ],
                    )
                )

        # Explicitly distinguish non-causal temporally preceding events (correlation != causation)
        non_ancestors_prior = [
            n
            for n in nodes.values()
            if n.event_index < fail_node.event_index and n.node_id not in ancestor_ids
        ]
        for sibling in non_ancestors_prior:
            sib_state_up = sibling.state.strip().upper()
            has_anomaly = (
                sib_state_up in _WARNING_STATES
                or sibling.elapsed_ms >= 500.0
                or sibling.severity in {"HIGH", "CRITICAL"}
            )
            if has_anomaly or sibling.event_index == fail_node.event_index - 1:
                corr_evidence = [
                    f"Temporal proximity only: '{sibling.step_id}' (event_index={sibling.event_index}) preceded '{fail_node.step_id}' (event_index={fail_node.event_index}).",
                    "NO Plan edge, NO explicit dependency, and NO digest dataflow edge connects this node to the failure.",
                ]
                if has_anomaly:
                    corr_evidence.append(
                        f"Coincident sibling signal: state={sibling.state}, elapsed_ms={sibling.elapsed_ms}."
                    )
                candidates.append(
                    CandidateRootCause(
                        cause_id=f"corr-temporal-{sibling.step_id}",
                        category="TEMPORAL_CORRELATION_NON_CAUSAL",
                        mechanism_type=MECHANISM_TEMPORAL_CORRELATION,
                        causal_verified=False,
                        confidence=0.18 if has_anomaly else 0.10,
                        suspect_node_id=sibling.node_id,
                        step_id=sibling.step_id,
                        tool_id=sibling.tool_id or None,
                        summary=(
                            f"Non-causal temporal correlation: sibling step '{sibling.step_id}' ran before "
                            f"'{fail_node.step_id}' without any causal DAG path."
                        ),
                        supporting_evidence=corr_evidence,
                        distinguishing_tests=[
                            f"Replay '{fail_node.step_id}' with sibling branch '{sibling.step_id}' disabled or stubbed; "
                            "if failure persists, temporal precedence is strictly non-causal."
                        ],
                    )
                )

        # Include overall composition receipt context if it adds extra failure details
        for rec in receipts:
            r_fail, r_reasons = _receipt_failed(rec)
            if r_fail and isinstance(rec, CompositionReceipt) and rec.oracle_result.get("passed") is False:
                candidates[0].supporting_evidence.extend(
                    f"composition_receipt:{r}" for r in r_reasons if f"composition_receipt:{r}" not in candidates[0].supporting_evidence
                )

        candidates.sort(key=lambda c: (0 if c.causal_verified else 1, -c.confidence, c.cause_id))
        return candidates

    def _diagnose_receipt_boundary_failure(
        self,
        rec: Union[ExecutionReceipt, CompositionReceipt],
        reasons: List[str],
        nodes: Mapping[str, TraceDagNode],
        edges: Sequence[TraceDagEdge],
        topo_order: Sequence[str],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[CandidateRootCause]]:
        sink_ids = set(topo_order) - {e.from_node for e in edges}
        last_node = nodes[topo_order[-1]] if topo_order else None
        boundary_info = {
            "node_id": "receipt_verification_boundary",
            "step_id": last_node.step_id if last_node else "run_boundary",
            "plan_node_id": last_node.plan_node_id if last_node else "run_boundary",
            "tool_id": last_node.tool_id if last_node else "",
            "state": rec.status.value,
            "receipt_schema": rec.schema,
            "receipt_status": rec.status.value,
            "verification_status": rec.verification_status,
            "receipt_failure_reasons": list(reasons),
            "sink_nodes": sorted(sink_ids),
        }
        dep_chain: List[Dict[str, Any]] = []
        if topo_order:
            dep_chain = [
                {
                    "node_id": nodes[nid].node_id,
                    "step_id": nodes[nid].step_id,
                    "tool_id": nodes[nid].tool_id,
                    "state": nodes[nid].state,
                    "event_index": nodes[nid].event_index,
                    "input_digest": nodes[nid].input_digest,
                    "output_digest": nodes[nid].output_digest,
                    "failed": False,
                }
                for nid in topo_order
            ]
        category = _categorize_failure(" ".join(reasons), rec.status.value, rec.status.value)
        cause = CandidateRootCause(
            cause_id="cause-receipt-boundary",
            category=category,
            mechanism_type=MECHANISM_VERIFIED_CAUSAL,
            causal_verified=True,
            confidence=0.90,
            suspect_node_id=last_node.node_id if last_node else None,
            step_id=last_node.step_id if last_node else None,
            tool_id=last_node.tool_id if last_node else None,
            summary=f"Run failed at receipt/oracle verification boundary ({rec.status.value}).",
            supporting_evidence=list(reasons),
            distinguishing_tests=[
                "Compare final output_digest against expected oracle contract and re-verify pre/post execution checks."
            ],
        )
        return boundary_info, dep_chain, [cause]


__all__ = [
    "TRACE_DOCTOR_SCHEMA",
    "MECHANISM_VERIFIED_CAUSAL",
    "MECHANISM_TEMPORAL_CORRELATION",
    "MECHANISM_INTEGRITY_FAILURE",
    "TraceDagNode",
    "TraceDagEdge",
    "CandidateRootCause",
    "TraceDiagnosis",
    "TraceDoctor",
]
