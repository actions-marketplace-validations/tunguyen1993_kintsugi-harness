"""Unit, security, and determinism tests for Build #3 Typed Capability Graph & Synthesis."""

from __future__ import annotations

import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fixture_attestation import make_fixture_authority, sign_fixture_spec, sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import make_fixture_authority, sign_fixture_spec, sign_fixture_tool

from kintsugi.capability.contracts_v2 import PortContract
from kintsugi.capability.schemas import (
    CapabilityGap,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.synthesis import (
    GapKind,
    ParetoCandidate,
    RankedSynthesisPlan,
    SynthesisBlueprint,
    SynthesisGoal,
    TypedCapabilityGraph,
    TypedPort,
    rank_pareto_candidates,
)
from kintsugi.tools.tool_wire import DeclassificationGrant

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64


def _make_tool(
    tool_id: str,
    *,
    capabilities: Optional[List[str]] = None,
    input_port: Optional[Dict[str, Any]] = None,
    output_port: Optional[Dict[str, Any]] = None,
    semantic_contract: Optional[Dict[str, Any]] = None,
    permissions: Optional[List[str]] = None,
    side_effects: Optional[List[str]] = None,
    runtime_requirements: Optional[Dict[str, Any]] = None,
    trust_status: TrustStatus = TrustStatus.VERIFIED,
    latency_ms: float = 5.0,
    api_tokens: int = 0,
    binary_hash: str = HASH_A,
    include_attestation: bool = True,
) -> ToolSpec:
    sem = dict(semantic_contract or {})
    if input_port is not None:
        sem["input_port"] = dict(input_port)
    if output_port is not None:
        sem["output_port"] = dict(output_port)

    attestation = None
    if include_attestation and trust_status == TrustStatus.VERIFIED:
        attestation = {
            "verifier_id": "ci-attestor",
            "verification_digest": HASH_B,
            "binary_hash": binary_hash,
            "tool_id": tool_id,
        }

    return ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="internal_verified" if trust_status == TrustStatus.VERIFIED else "discovery",
        binary_hash=binary_hash,
        capabilities=capabilities or [f"cap.{tool_id}"],
        input_schema=dict(input_port or {}),
        output_schema=dict(output_port or {}),
        semantic_contract=sem,
        side_effects=side_effects if side_effects is not None else ["none"],
        required_permissions=permissions if permissions is not None else ["fs.read"],
        runtime_requirements=dict(runtime_requirements or {}),
        trust_status=trust_status,
        latency_estimate_ms=latency_ms,
        api_token_estimate=api_tokens,
        verification_attestation=attestation,
    )


class TestTypedCapabilityGraphSynthesis(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "compute.parse", "compute.agg", "privacy.redact"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_multihop_typed_path_and_untrusted_exclusion(self) -> None:
        """Route 4-hop pipeline while excluding DISCOVERED, QUARANTINED, and RETIRED tools."""
        ingest = _make_tool(
            "log.ingest",
            input_port={
                "format": "bytes",
                "semantic_type": "raw_logs",
                "unit": "none",
                "schema_fields": ["raw_line"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "jsonl",
                "semantic_type": "ingested_logs",
                "unit": "none",
                "schema_fields": ["raw_line", "host"],
                "sensitivity": "internal",
            },
            permissions=["fs.read"],
            latency_ms=2.0,
        )
        parser = _make_tool(
            "log.parse",
            input_port={
                "format": "jsonl",
                "semantic_type": "ingested_logs",
                "unit": "none",
                "schema_fields": ["raw_line"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "typed_event_stream",
                "semantic_type": "parsed_events",
                "unit": "us",
                "schema_fields": ["ts", "level", "duration"],
                "sensitivity": "internal",
            },
            permissions=["compute.parse"],
            latency_ms=3.0,
        )
        normalizer = _make_tool(
            "unit.us_to_ms",
            input_port={
                "format": "typed_event_stream",
                "semantic_type": "parsed_events",
                "unit": "us",
                "schema_fields": ["ts", "duration"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "typed_event_stream",
                "semantic_type": "normalized_events",
                "unit": "ms",
                "schema_fields": ["ts", "duration"],
                "sensitivity": "internal",
                "preserves_fields": True,
            },
            permissions=["compute.parse"],
            latency_ms=1.0,
        )
        aggregator = _make_tool(
            "metrics.aggregate",
            input_port={
                "format": "typed_event_stream",
                "semantic_type": "normalized_events",
                "unit": "ms",
                "schema_fields": ["duration", "level"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "json",
                "semantic_type": "aggregated_metrics",
                "unit": "ms",
                "schema_fields": ["p50_ms", "p95_ms", "count"],
                "sensitivity": "internal",
            },
            permissions=["compute.agg"],
            latency_ms=4.0,
        )

        # Shorter shortcut tools that MUST be excluded because they are DISCOVERED / QUARANTINED / RETIRED
        shortcut_discovered = _make_tool(
            "fast.discovered_shortcut",
            input_port={
                "format": "bytes",
                "semantic_type": "raw_logs",
                "unit": "none",
                "schema_fields": ["raw_line"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "json",
                "semantic_type": "aggregated_metrics",
                "unit": "ms",
                "schema_fields": ["p50_ms", "p95_ms", "count"],
                "sensitivity": "internal",
            },
            trust_status=TrustStatus.DISCOVERED,
            latency_ms=0.5,
        )
        shortcut_quarantined = _make_tool(
            "fast.quarantined_shortcut",
            input_port={
                "format": "bytes",
                "semantic_type": "raw_logs",
                "unit": "none",
                "schema_fields": ["raw_line"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "json",
                "semantic_type": "aggregated_metrics",
                "unit": "ms",
                "schema_fields": ["p50_ms", "p95_ms", "count"],
                "sensitivity": "internal",
            },
            trust_status=TrustStatus.QUARANTINED,
            latency_ms=0.2,
        )
        shortcut_retired = _make_tool(
            "fast.retired_shortcut",
            input_port={
                "format": "bytes",
                "semantic_type": "raw_logs",
                "unit": "none",
                "schema_fields": ["raw_line"],
                "sensitivity": "internal",
            },
            output_port={
                "format": "json",
                "semantic_type": "aggregated_metrics",
                "unit": "ms",
                "schema_fields": ["p50_ms", "p95_ms", "count"],
                "sensitivity": "internal",
            },
            trust_status=TrustStatus.RETIRED,
            latency_ms=0.1,
        )

        registry = ToolRegistry(self.ws / ".kintsugi" / "tool_registry.json")
        for spec in (
            ingest,
            parser,
            normalizer,
            aggregator,
            shortcut_discovered,
            shortcut_quarantined,
            shortcut_retired,
        ):
            if spec.trust_status == TrustStatus.VERIFIED:
                sign_fixture_tool(registry, spec)
            else:
                registry.register(spec)

        graph = TypedCapabilityGraph.from_registry(registry)
        self.assertEqual(
            graph.verified_tool_ids,
            ["log.ingest", "log.parse", "metrics.aggregate", "unit.us_to_ms"],
        )
        excluded = graph.get_excluded_tools()
        self.assertIn("fast.discovered_shortcut", excluded)
        self.assertIn("TRUST_STATUS_DISCOVERED_EXCLUDED", excluded["fast.discovered_shortcut"].reasons)
        self.assertIn("fast.quarantined_shortcut", excluded)
        self.assertIn("TRUST_STATUS_QUARANTINED_EXCLUDED", excluded["fast.quarantined_shortcut"].reasons)
        self.assertIn("fast.retired_shortcut", excluded)
        self.assertIn("TRUST_STATUS_RETIRED_EXCLUDED", excluded["fast.retired_shortcut"].reasons)

        src_req = {
            "format": "bytes",
            "semantic_type": "raw_logs",
            "unit": "none",
            "schema_fields": ["raw_line"],
            "sensitivity": "internal",
        }
        dst_req = {
            "format": "json",
            "semantic_type": "aggregated_metrics",
            "unit": "ms",
            "schema_fields": ["p95_ms", "count"],
            "sensitivity": "internal",
        }
        res = graph.find_shortest_safe_path(src_req, dst_req, self.sec_ctx)
        self.assertTrue(res.found)
        self.assertEqual(res.hop_count, 4)
        self.assertEqual(
            res.tool_ids,
            ("log.ingest", "log.parse", "unit.us_to_ms", "metrics.aggregate"),
        )
        self.assertEqual(res.effective_sensitivity, "internal")
        self.assertEqual(res.total_latency_us, Decimal("10000"))
        self.assertEqual(
            res.permission_union,
            ("compute.agg", "compute.parse", "fs.read"),
        )
        self.assertIn("fast.discovered_shortcut", res.rejected_tools)
        self.assertIn("fast.quarantined_shortcut", res.rejected_tools)

        # Satisfied goal emits zero gaps
        gaps = graph.detect_capability_gaps(
            {"goal_id": "g-satisfied", "source": src_req, "target": dst_req},
            self.sec_ctx,
        )
        self.assertEqual(gaps, [])

    def test_gap_detection_emits_blueprints_for_bridge_unit_and_sensitivity(self) -> None:
        """Detect missing intermediate format bridge, unit converter, and declassification gate."""
        ingest = _make_tool(
            "log.ingest",
            input_port={"format": "bytes", "semantic_type": "raw_logs", "unit": "none", "sensitivity": "internal"},
            output_port={"format": "jsonl", "semantic_type": "log_records", "unit": "us", "sensitivity": "internal"},
            permissions=["fs.read"],
        )
        # Expects typed_event_stream in ms (missing format bridge jsonl->typed_event_stream OR unit us->ms)
        agg_ms = _make_tool(
            "metrics.agg_ms",
            input_port={"format": "jsonl", "semantic_type": "log_records", "unit": "ms", "sensitivity": "internal"},
            output_port={"format": "json", "semantic_type": "aggregated_metrics", "unit": "ms", "sensitivity": "internal"},
            permissions=["compute.agg"],
        )
        # Expects typed_event_stream in us (format bridge missing between jsonl and typed_event_stream)
        agg_stream = _make_tool(
            "metrics.agg_stream",
            input_port={
                "format": "typed_event_stream",
                "semantic_type": "stream_records",
                "unit": "us",
                "sensitivity": "public",
            },
            output_port={
                "format": "json",
                "semantic_type": "stream_summary",
                "unit": "us",
                "sensitivity": "public",
            },
            permissions=["compute.agg"],
        )
        bridge_head = _make_tool(
            "stream.head",
            input_port={"format": "bytes", "semantic_type": "raw_stream", "unit": "none", "sensitivity": "public"},
            output_port={"format": "jsonl", "semantic_type": "stream_records", "unit": "us", "sensitivity": "public"},
            permissions=["fs.read"],
        )

        auth = make_fixture_authority()
        for spec in (ingest, agg_ms, bridge_head, agg_stream):
            sign_fixture_spec(auth, spec)
        graph = TypedCapabilityGraph([ingest, agg_ms, bridge_head, agg_stream], authority=auth)

        # Goal 1: Multi-hop unit mismatch (log.ingest outputs us -> missing us->ms -> metrics.agg_ms)
        g_unit = SynthesisGoal(
            goal_id="g1-unit-gap",
            source_req={"format": "bytes", "semantic_type": "raw_logs", "unit": "none", "sensitivity": "internal"},
            target_req={"format": "json", "semantic_type": "aggregated_metrics", "unit": "ms", "sensitivity": "internal"},
            require_idempotent=True,
        )
        # Goal 2: Multi-hop missing format bridge (stream.head outputs jsonl -> missing typed_event_stream -> agg_stream)
        g_fmt = SynthesisGoal(
            goal_id="g2-format-gap",
            source_req={"format": "bytes", "semantic_type": "raw_stream", "unit": "none", "sensitivity": "public"},
            target_req={"format": "json", "semantic_type": "stream_summary", "unit": "us", "sensitivity": "public"},
        )
        # Goal 3: Sensitivity escalation/leakage block (SECRET -> PUBLIC without declassifier)
        g_sens = SynthesisGoal(
            goal_id="g3-sensitivity-gap",
            source_req={"format": "jsonl", "semantic_type": "audit_events", "unit": "ms", "sensitivity": "secret"},
            target_req={"format": "jsonl", "semantic_type": "audit_events", "unit": "ms", "sensitivity": "public"},
            sensitivity_ceiling="public",
        )
        # Goal 4: Absent primitive kernel
        g_kernel = SynthesisGoal(
            goal_id="g4-kernel-gap",
            source_req={"format": "jsonl", "semantic_type": "parsed_events", "unit": "ms", "sensitivity": "public"},
            target_req={"format": "json", "semantic_type": "fft_spectrum", "unit": "hz", "sensitivity": "public"},
        )

        blueprints = graph.detect_capability_gaps([g_kernel, g_sens, g_fmt, g_unit], self.sec_ctx)
        by_goal = {bp.goal_id: bp for bp in blueprints}

        self.assertEqual(set(by_goal.keys()), {"g1-unit-gap", "g2-format-gap", "g3-sensitivity-gap", "g4-kernel-gap"})

        bp_unit = by_goal["g1-unit-gap"]
        self.assertEqual(bp_unit.schema, "SynthesisBlueprint/1")
        self.assertEqual(bp_unit.gap_kind, GapKind.MISSING_UNIT_CONVERTER.value)
        self.assertEqual(bp_unit.required_units, ["us", "ms"])
        self.assertEqual(bp_unit.source_type["format"], "jsonl")
        self.assertEqual(bp_unit.target_type["unit"], "ms")
        self.assertTrue(bp_unit.allowed_effects["idempotent"])
        self.assertIn("compute.agg", bp_unit.permission_budget["allowed_permissions"])
        self.assertTrue(bp_unit.provenance_sha256.startswith("sha256:"))
        kinds_unit = {t["kind"] for t in bp_unit.candidate_templates}
        self.assertEqual(kinds_unit, {"native_c99_asm_kernel", "python_adapter", "external_verified_tool"})

        bp_fmt = by_goal["g2-format-gap"]
        self.assertEqual(bp_fmt.gap_kind, GapKind.MISSING_FORMAT_BRIDGE.value)
        self.assertEqual(bp_fmt.source_type["format"], "jsonl")
        self.assertEqual(bp_fmt.target_type["format"], "typed_event_stream")

        bp_sens = by_goal["g3-sensitivity-gap"]
        self.assertEqual(bp_sens.gap_kind, GapKind.MISSING_DECLASSIFICATION_GATE.value)
        self.assertEqual(bp_sens.sensitivity_ceiling, "public")
        self.assertTrue(bp_sens.declassification_required)
        self.assertIn("declassification", bp_sens.missing_hop_description.lower())

        bp_kern = by_goal["g4-kernel-gap"]
        self.assertEqual(bp_kern.gap_kind, GapKind.MISSING_PRIMITIVE_KERNEL.value)

        # Canonical serialization & tamper rejection check
        for bp in blueprints:
            reloaded = SynthesisBlueprint.from_dict(json.loads(bp.to_canonical_json()))
            self.assertEqual(reloaded.provenance_sha256, bp.provenance_sha256)
            self.assertEqual(reloaded.content_hash(), bp.content_hash())

        tampered = bp_unit.to_dict()
        tampered["sensitivity_ceiling"] = "secret"
        with self.assertRaises(ValueError):
            SynthesisBlueprint.from_dict(tampered)

    def test_sensitivity_declassification_over_privilege_and_idempotency(self) -> None:
        """Enforce explicit declassifier, grant matching, over-privilege block, and idempotency."""
        # Tool claiming secret->public without explicit declassifier MUST be rejected
        sneaky_launderer = _make_tool(
            "sneaky.launderer",
            input_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "secret"},
            output_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "public"},
            permissions=["fs.read"],
            latency_ms=1.0,
        )
        # Explicit verified declassifier requiring privacy.redact
        verified_redactor = _make_tool(
            "privacy.redactor",
            input_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "secret"},
            output_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "public"},
            semantic_contract={
                "declassifier": True,
                "declassify_transform": "redact",
                "declassifies": {"from": "secret", "to": "public", "transform": "redact", "requires_grant": True},
            },
            permissions=["privacy.redact"],
            latency_ms=4.0,
        )
        # Over-privileged verified sink (requires network.outbound not in sec_ctx)
        overpriv_sink = _make_tool(
            "sink.remote_upload",
            input_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "report", "unit": "ms", "sensitivity": "public"},
            permissions=["network.outbound"],
            side_effects=["network.outbound"],
            latency_ms=1.0,
        )
        # Non-idempotent local sink
        non_idemp_sink = _make_tool(
            "sink.append_non_idempotent",
            input_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "report", "unit": "ms", "sensitivity": "public"},
            permissions=["compute.agg"],
            side_effects=["non_idempotent"],
            latency_ms=2.0,
        )
        # Idempotent least-privilege verified sink
        safe_sink = _make_tool(
            "sink.safe_idempotent",
            input_port={"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "report", "unit": "ms", "sensitivity": "public"},
            permissions=["compute.agg"],
            side_effects=["none"],
            latency_ms=5.0,
        )

        src = {"format": "jsonl", "semantic_type": "user_events", "unit": "ms", "sensitivity": "secret"}
        dst = {"format": "json", "semantic_type": "report", "unit": "ms", "sensitivity": "public"}

        auth = make_fixture_authority()
        for spec in (sneaky_launderer, verified_redactor, overpriv_sink, non_idemp_sink, safe_sink):
            sign_fixture_spec(auth, spec)

        # 1. Without explicit declassifier in graph, sneaky_launderer is rejected
        graph_no_decl = TypedCapabilityGraph([sneaky_launderer, safe_sink], authority=auth)
        res_blocked = graph_no_decl.find_shortest_safe_path(src, dst, self.sec_ctx)
        self.assertFalse(res_blocked.found)
        self.assertIn("sneaky.launderer", res_blocked.rejected_tools)
        self.assertTrue(
            any("UNATTESTED_SENSITIVITY_DOWNGRADE" in r for r in res_blocked.rejected_tools["sneaky.launderer"])
        )

        # 2. With verified_redactor + grant, requires matching DeclassificationGrant and respects over-privilege + idempotency
        graph_full = TypedCapabilityGraph(
            [sneaky_launderer, verified_redactor, overpriv_sink, non_idemp_sink, safe_sink],
            authority=auth,
        )

        # Missing grant -> blocked
        res_no_grant = graph_full.find_shortest_safe_path(src, dst, self.sec_ctx, require_idempotent=True)
        self.assertFalse(res_no_grant.found)
        self.assertIn("MISSING_AUTHORIZED_DECLASSIFICATION_GRANT", res_no_grant.rejected_tools["privacy.redactor"])

        grant = DeclassificationGrant(
            grant_id="grant-pii-001",
            source_sensitivity="secret",
            target_sensitivity="public",
            authorized_by="security-officer",
            transform="redact",
            redacted_fields=("email", "token"),
        )

        # Insufficient permissions (no privacy.redact) -> blocked
        unprivileged_ctx = SecurityContext(
            workspace_root=str(self.ws),
            allowed_permissions=["fs.read", "compute.agg"],
            network_allowed=False,
        )
        res_unpriv = graph_full.find_shortest_safe_path(
            src, dst, unprivileged_ctx, require_idempotent=True, declassification_grants=[grant]
        )
        self.assertFalse(res_unpriv.found)
        self.assertIn("privacy.redactor", res_unpriv.rejected_tools)

        # Valid permissions + grant + require_idempotent=True -> skips overpriv_sink and non_idemp_sink, picks safe_sink!
        res_ok = graph_full.find_shortest_safe_path(
            src, dst, self.sec_ctx, require_idempotent=True, declassification_grants=[grant]
        )
        self.assertTrue(res_ok.found)
        self.assertEqual(res_ok.tool_ids, ("privacy.redactor", "sink.safe_idempotent"))
        self.assertEqual(res_ok.declassified_by, ("privacy.redactor",))
        self.assertEqual(res_ok.effective_sensitivity, "public")
        self.assertTrue(res_ok.effects_summary["idempotent"])
        self.assertIn("sink.remote_upload", res_ok.rejected_tools)
        self.assertIn("sink.append_non_idempotent", res_ok.rejected_tools)

        # Also verify gap detection flags PERMISSION_BLOCKED_EDGE when ONLY overpriv_sink exists downstream
        graph_perm_gap = TypedCapabilityGraph([verified_redactor, overpriv_sink], authority=auth)
        perm_gaps = graph_perm_gap.detect_capability_gaps(
            {
                "goal_id": "g-perm-block",
                "source": src,
                "target": dst,
                "declassification_grants": [grant],
            },
            self.sec_ctx,
        )
        self.assertEqual(len(perm_gaps), 1)
        self.assertEqual(perm_gaps[0].gap_kind, GapKind.PERMISSION_BLOCKED_EDGE.value)
        self.assertIn("sink.remote_upload", perm_gaps[0].blocked_tool_reasons)

    def test_exact_decimal_pareto_ranking_and_determinism(self) -> None:
        """Verify exact Decimal/int Pareto front sorting, dominance tracking, and provenance tie-breaking."""
        # Non-dominated Front 0 candidates + dominated Front 1 & Front 2 candidates
        # Notice exact Decimal test: Decimal("0.1") + Decimal("0.2") == Decimal("0.3") < Decimal("0.30000000000000004")
        exact_cost = Decimal("0.1") + Decimal("0.2")
        float_drift_cost = Decimal("0.30000000000000004")

        c_fast_c99 = ParetoCandidate(
            candidate_id="c99.fast",
            latency_us=15,
            accuracy_bps=10000,
            risk_score=20,
            cost_micro_usd=300,
            kind="native_c99_asm_kernel",
        )
        c_low_risk_py = ParetoCandidate(
            candidate_id="py.safe",
            latency_us=240,
            accuracy_bps=10000,
            risk_score=4,
            cost_micro_usd=exact_cost,
            kind="python_adapter",
        )
        # Dominated by c_low_risk_py ONLY because float_drift_cost > exact_cost (0.30000000000000004 > 0.3)!
        c_drift_dominated = ParetoCandidate(
            candidate_id="py.drift_dominated",
            latency_us=240,
            accuracy_bps=10000,
            risk_score=4,
            cost_micro_usd=float_drift_cost,
            kind="python_adapter",
        )
        # Dominated by c_fast_c99 (15,10000,20,300) and ties (100,9950,10,100), NOT by py.safe (240>220) -> Front 1
        c_slow_expensive = ParetoCandidate(
            candidate_id="ext.dominated_f1",
            latency_us=220,
            accuracy_bps=9900,
            risk_score=25,
            cost_micro_usd=400,
            kind="external_verified_tool",
        )
        # Dominated by BOTH c_fast_c99 and c_slow_expensive -> Front 2
        c_worst = ParetoCandidate(
            candidate_id="ext.dominated_f2",
            latency_us=900,
            accuracy_bps=9500,
            risk_score=30,
            cost_micro_usd=800,
            kind="external_verified_tool",
        )
        # Exact metric tie broken deterministically by provenance_sha256 ascending
        tie_high_hash = ParetoCandidate(
            candidate_id="tie.z_high_hash",
            latency_us=100,
            accuracy_bps=9950,
            risk_score=10,
            cost_micro_usd=100,
            provenance_sha256="sha256:" + "f" * 64,
        )
        tie_low_hash = ParetoCandidate(
            candidate_id="tie.a_low_hash",
            latency_us=100,
            accuracy_bps=9950,
            risk_score=10,
            cost_micro_usd=100,
            provenance_sha256="sha256:" + "1" * 64,
        )

        order_a = [c_worst, tie_high_hash, c_drift_dominated, c_low_risk_py, c_slow_expensive, c_fast_c99, tie_low_hash]
        order_b = list(reversed(order_a))

        plan_a = rank_pareto_candidates(order_a, plan_id="plan-alpha", blueprint_id="bp-unit-0")
        plan_b = rank_pareto_candidates(order_b, plan_id="plan-alpha", blueprint_id="bp-unit-0")

        self.assertEqual(plan_a.provenance_sha256, plan_b.provenance_sha256)
        self.assertEqual(plan_a.to_canonical_json(), plan_b.to_canonical_json())

        frontier_ids = [e.candidate.candidate_id for e in plan_a.pareto_frontier]
        self.assertEqual(frontier_ids, ["c99.fast", "tie.a_low_hash", "tie.z_high_hash", "py.safe"])

        entry_map = {e.candidate.candidate_id: e for e in plan_a.ranked_candidates}
        self.assertEqual(entry_map["py.safe"].pareto_rank, 0)
        self.assertTrue(entry_map["py.safe"].is_pareto_optimal)
        self.assertEqual(entry_map["py.drift_dominated"].pareto_rank, 1)
        self.assertFalse(entry_map["py.drift_dominated"].is_pareto_optimal)
        self.assertEqual(entry_map["py.drift_dominated"].dominated_by, ("py.safe",))
        self.assertEqual(entry_map["ext.dominated_f1"].pareto_rank, 1)
        self.assertEqual(entry_map["ext.dominated_f2"].pareto_rank, 2)
        self.assertIn("ext.dominated_f1", entry_map["ext.dominated_f2"].dominated_by)

        # Verify tie-break order strictly places lower provenance_sha256 first
        self.assertLess(
            frontier_ids.index("tie.a_low_hash"),
            frontier_ids.index("tie.z_high_hash"),
        )

        # Roundtrip canonical JSON -> RankedSynthesisPlan.from_dict
        reloaded = RankedSynthesisPlan.from_dict(json.loads(plan_a.to_canonical_json()))
        self.assertEqual(reloaded.provenance_sha256, plan_a.provenance_sha256)
        self.assertEqual(reloaded.content_hash(), plan_a.content_hash())

        # Integration: rank blueprint candidate_templates directly
        bp = SynthesisBlueprint(
            blueprint_id="bp-direct-test",
            source_type={"format": "jsonl", "unit": "us", "sensitivity": "public"},
            target_type={"format": "jsonl", "unit": "ms", "sensitivity": "public"},
            required_units=["us", "ms"],
            sensitivity_ceiling="public",
            allowed_effects={"idempotent": True},
            permission_budget=["fs.read"],
            missing_hop_description="Convert us to ms",
            candidate_templates=[
                {
                    "template_id": "c99-us-ms",
                    "kind": "native_c99_asm_kernel",
                    "metrics": {"latency_us": 12, "accuracy_bps": 10000, "risk_score": 18, "cost_micro_usd": 300},
                },
                {
                    "template_id": "py-us-ms",
                    "kind": "python_adapter",
                    "metrics": {"latency_us": 200, "accuracy_bps": 10000, "risk_score": 4, "cost_micro_usd": 40},
                },
                {
                    "template_id": "py-us-ms-dominated",
                    "kind": "python_adapter",
                    "metrics": {"latency_us": 250, "accuracy_bps": 10000, "risk_score": 8, "cost_micro_usd": 60},
                },
            ],
        )
        bp_plan = TypedCapabilityGraph().rank_pareto_candidates(bp.candidate_templates, blueprint_id=bp.blueprint_id)
        self.assertEqual([e.candidate.candidate_id for e in bp_plan.pareto_frontier], ["c99-us-ms", "py-us-ms"])
        self.assertEqual([e.candidate.candidate_id for e in bp_plan.dominated_candidates], ["py-us-ms-dominated"])

        # Weighted exact-Decimal tie breaking by provenance_sha256
        w_plan = rank_pareto_candidates(
            [
                ParetoCandidate("w.high", 10, 10000, 0, 20, provenance_sha256="sha256:" + "e" * 64),
                ParetoCandidate("w.low", 20, 10000, 0, 10, provenance_sha256="sha256:" + "2" * 64),
            ],
            objective_weights={"latency_us": Decimal("1"), "cost_micro_usd": Decimal("1")},
        )
        self.assertEqual([e.candidate.candidate_id for e in w_plan.pareto_frontier], ["w.low", "w.high"])
        self.assertEqual(w_plan.selected_candidate.exact_weighted_score, Decimal("30"))

    def test_multihop_double_gap_taint_propagation_and_effect_block(self) -> None:
        """Detect multiple gaps across island tools, sensitivity taint propagation, and non-idempotent block."""
        # Island tools: mid_parse (jsonl/raw_telemetry/us -> typed_event_stream/parsed_telemetry/us),
        # end_agg (typed_event_stream/parsed_telemetry/ms -> json/telemetry_summary/ms)
        mid_parse = _make_tool(
            "island.mid_parse",
            input_port={"format": "jsonl", "semantic_type": "raw_telemetry", "unit": "us", "sensitivity": "public"},
            output_port={"format": "typed_event_stream", "semantic_type": "parsed_telemetry", "unit": "us", "sensitivity": "public"},
        )
        end_agg = _make_tool(
            "island.end_agg",
            input_port={"format": "typed_event_stream", "semantic_type": "parsed_telemetry", "unit": "ms", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "telemetry_summary", "unit": "ms", "sensitivity": "public"},
        )
        # Sensitivity escalation + polymorphic passthrough (must NOT launder secret back to public)
        secret_enricher = _make_tool(
            "enrich.secret",
            input_port={"format": "json", "semantic_type": "telemetry_summary", "unit": "ms", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "enriched_summary", "unit": "ms", "sensitivity": "secret"},
        )
        poly_passthrough = _make_tool(
            "poly.passthrough",
            input_port={"format": "json", "semantic_type": "enriched_summary", "unit": "ms", "sensitivity": "any"},
            output_port={"format": "json", "semantic_type": "enriched_summary", "unit": "ms", "sensitivity": "any"},
        )
        # Only verified sink for report is non-idempotent
        non_idemp_report = _make_tool(
            "report.non_idemp",
            input_port={"format": "json", "semantic_type": "telemetry_summary", "unit": "ms", "sensitivity": "public"},
            output_port={"format": "text", "semantic_type": "final_report", "unit": "ms", "sensitivity": "public"},
            side_effects=["non_idempotent"],
        )

        auth = make_fixture_authority()
        for spec in (mid_parse, end_agg, secret_enricher, poly_passthrough, non_idemp_report):
            sign_fixture_spec(auth, spec)
        graph = TypedCapabilityGraph(
            [mid_parse, end_agg, secret_enricher, poly_passthrough, non_idemp_report],
            authority=auth,
        )

        # 1. Double-gap multi-hop goal: missing format bridge (bytes->jsonl) AND unit converter (us->ms)
        double_gap = graph.detect_capability_gaps(
            {
                "goal_id": "g-double-island",
                "source": {"format": "bytes", "semantic_type": "raw_telemetry", "unit": "us", "sensitivity": "public"},
                "target": {"format": "json", "semantic_type": "telemetry_summary", "unit": "ms", "sensitivity": "public"},
            },
            self.sec_ctx,
        )
        self.assertEqual(
            [bp.gap_kind for bp in double_gap],
            [GapKind.MISSING_FORMAT_BRIDGE.value, GapKind.MISSING_UNIT_CONVERTER.value],
        )

        # 2. Taint propagation: public -> enrich.secret (secret) -> poly.passthrough (stays secret) -> public target BLOCKED
        taint_res = graph.find_shortest_safe_path(
            PortContract(schema_ref="json", semantic_type="telemetry_summary", unit="ms", sensitivity="public"),
            PortContract(schema_ref="json", semantic_type="enriched_summary", unit="ms", sensitivity="public"),
            self.sec_ctx,
        )
        self.assertFalse(taint_res.found)

        # 3. Effect constraint block: only report tool is non_idempotent while require_idempotent=True
        eff_gaps = graph.detect_capability_gaps(
            {
                "goal_id": "g-effect-block",
                "source": {"format": "json", "semantic_type": "telemetry_summary", "unit": "ms", "sensitivity": "public"},
                "target": {"format": "text", "semantic_type": "final_report", "unit": "ms", "sensitivity": "public"},
                "require_idempotent": True,
            },
            self.sec_ctx,
        )
        self.assertEqual(len(eff_gaps), 1)
        self.assertEqual(eff_gaps[0].gap_kind, GapKind.EFFECT_CONSTRAINT_BLOCKED.value)
        self.assertIn("report.non_idemp", eff_gaps[0].blocked_tool_reasons)

        # 4. CapabilityGap compatibility + invalid metric / Trojan hygiene rejections
        cap_gap = CapabilityGap(
            goal_id="g-capgap-input",
            required_capabilities=["cap.missing"],
            input_artifacts=[{"format": "jsonl", "semantic_type": "telemetry", "unit": "us", "sensitivity": "secret"}],
            expected_outputs=[{"format": "jsonl", "semantic_type": "telemetry", "unit": "us", "sensitivity": "public"}],
            security_context=self.sec_ctx,
        )
        cg_blueprints = graph.detect_capability_gaps(cap_gap, self.sec_ctx)
        self.assertEqual(cg_blueprints[0].gap_kind, GapKind.MISSING_DECLASSIFICATION_GATE.value)

        with self.assertRaises(ValueError):
            ParetoCandidate("bad.bool", True, 9000, 1, 10)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ParetoCandidate("bad.nan", Decimal("NaN"), 9000, 1, 10)
        with self.assertRaises(ValueError):
            TypedPort(format="json\u202e")

    def test_fail_closed_hmac_attestation_authority_enforcement(self) -> None:
        """Self-attested or forged ToolSpecs without verified HMAC authority MUST be excluded."""
        self_attested = _make_tool(
            "self.attested_tool",
            input_port={"format": "bytes", "semantic_type": "raw", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "out", "sensitivity": "public"},
            include_attestation=True,
        )
        # 1. Passing self-attested ToolSpecs WITHOUT authority -> MISSING_ATTESTATION_AUTHORITY
        graph_no_auth = TypedCapabilityGraph([self_attested])
        self.assertEqual(graph_no_auth.verified_tool_ids, [])
        self.assertEqual(
            graph_no_auth.get_excluded_tools()["self.attested_tool"].reasons,
            ("MISSING_ATTESTATION_AUTHORITY",),
        )

        # 2. Authority with zero registered verifiers also excludes signed ToolSpecs -> MISSING_ATTESTATION_AUTHORITY
        auth = make_fixture_authority()
        signed_tool = sign_fixture_spec(
            auth,
            _make_tool(
                "signed.tool",
                input_port={"format": "bytes", "semantic_type": "raw", "sensitivity": "public"},
                output_port={"format": "json", "semantic_type": "out", "sensitivity": "public"},
            ),
        )
        graph_empty_auth = TypedCapabilityGraph([signed_tool], authority=AttestationAuthority())
        self.assertEqual(graph_empty_auth.verified_tool_ids, [])
        self.assertEqual(
            graph_empty_auth.get_excluded_tools()["signed.tool"].reasons,
            ("MISSING_ATTESTATION_AUTHORITY",),
        )

        # 3. Forged non-HMAC self-attested tool WITH valid authority -> INVALID_ATTESTATION_HMAC
        graph_with_auth = TypedCapabilityGraph([self_attested, signed_tool], authority=auth)
        self.assertEqual(graph_with_auth.verified_tool_ids, ["signed.tool"])
        self.assertEqual(
            graph_with_auth.get_excluded_tools()["self.attested_tool"].reasons,
            ("INVALID_ATTESTATION_HMAC",),
        )

        # 4. Mutating ToolSpec permissions after signing invalidates spec_digest -> INVALID_ATTESTATION_HMAC
        tampered_tool = _make_tool(
            "tampered.tool",
            input_port={"format": "bytes", "semantic_type": "raw", "sensitivity": "public"},
            output_port={"format": "json", "semantic_type": "out", "sensitivity": "public"},
            permissions=["fs.read"],
        )
        sign_fixture_spec(auth, tampered_tool)
        tampered_tool.required_permissions.append("shell.exec")
        graph_tampered = TypedCapabilityGraph([tampered_tool], authority=auth)
        self.assertEqual(graph_tampered.verified_tool_ids, [])
        self.assertEqual(
            graph_tampered.get_excluded_tools()["tampered.tool"].reasons,
            ("INVALID_ATTESTATION_HMAC",),
        )

        # 5. Invalid authority type fails fast
        with self.assertRaises(ValueError):
            TypedCapabilityGraph([signed_tool], authority="not-an-authority")  # type: ignore[arg-type]

        # 6. from_registry respects explicit authority override
        reg = ToolRegistry(self.ws / ".kintsugi" / "sec_registry.json")
        sign_fixture_tool(reg, signed_tool)
        other_auth = AttestationAuthority({"other": b"other-key-with-at-least-32-bytes-long!"})
        graph_wrong_auth = TypedCapabilityGraph.from_registry(reg, authority=other_auth)
        self.assertEqual(graph_wrong_auth.verified_tool_ids, [])
        self.assertEqual(
            graph_wrong_auth.get_excluded_tools()["signed.tool"].reasons,
            ("INVALID_ATTESTATION_HMAC",),
        )


if __name__ == "__main__":
    unittest.main()
