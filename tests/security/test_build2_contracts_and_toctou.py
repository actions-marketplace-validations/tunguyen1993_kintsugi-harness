"""Security, contract, TOCTOU, and cache-provenance tests for Build #2 (`Build2Contracts/1`)."""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

try:
    from fixture_attestation import make_fixture_authority, sign_fixture_spec
except ImportError:  # pragma: no cover
    from tests.fixture_attestation import make_fixture_authority, sign_fixture_spec

from kintsugi.capability.contracts_v2 import (
    FORGE_STAGE_ORDER,
    GENESIS_EVENT_HASH,
    AbstainError,
    AdapterSpec,
    CompositionPlan,
    CompositionReceipt,
    EffectContract,
    ForgeState,
    PortContract,
    RunEvent,
    ToolBuild,
    compute_dag_effects,
    ports_compatible,
    validate_forge_transition,
    verify_event_chain,
)
from kintsugi.capability.schemas import (
    ExecutionStatus,
    Experience,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.forge.tool_sandbox import ToolSandbox
from kintsugi.runtime.experience_store import ExperienceStore
from kintsugi.runtime.secure_runner import SecureRunner, compute_file_sha256_confined

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "schemas"

HASH_1 = "sha256:" + "1" * 64
HASH_2 = "sha256:" + "2" * 64
HASH_3 = "sha256:" + "3" * 64
HASH_4 = "sha256:" + "4" * 64
HASH_5 = "sha256:" + "5" * 64
HASH_6 = "sha256:" + "6" * 64
HASH_7 = "sha256:" + "7" * 64


def _make_attestation(tool_id: str, binary_hash: str, verifier_id: str = "ci-verifier") -> dict:
    return {
        "verifier_id": verifier_id,
        "verification_digest": sha256_digest({"tool_id": tool_id, "binary_hash": binary_hash}),
        "binary_hash": binary_hash,
        "tool_id": tool_id,
        "source": "ci_attestation",
    }


def _full_verified_build_kwargs() -> dict:
    return {
        "build_id": "build-001",
        "tool_id": "forge.fast_scan",
        "tool_version": "1.0.0",
        "source_hash": HASH_1,
        "oracle_hash": HASH_2,
        "unit_test_digest": HASH_3,
        "differential_digest": HASH_4,
        "fuzz_digest": HASH_5,
        "boundary_digest": HASH_6,
        "compiler": "rustc",
        "compiler_version": "1.83.0",
        "flags": ["-O", "-Ctarget-cpu=native"],
        "artifact_hash": HASH_7,
        "sandbox_receipt": {"status": "PASS", "passed": True, "exit_code": 0},
        "benchmark_vs_baseline": {"passed": True, "regressed": False, "speedup": 3.4},
        "rollback_metadata": {"previous_tool_hash": HASH_1, "reason": "none"},
    }


class TestBuild2ContractsAndSchemas(unittest.TestCase):
    def test_build2_json_schemas_valid_and_parity(self) -> None:
        owned_schemas = (
            "port_contract.v1.schema.json",
            "effect_contract.v1.schema.json",
            "adapter_spec.v1.schema.json",
            "composition_plan.v1.schema.json",
            "composition_receipt.v1.schema.json",
            "tool_build.v1.schema.json",
            "run_event.v1.schema.json",
            "tool_spec.v1.schema.json",
        )
        loaded = {}
        for fname in owned_schemas:
            doc = json.loads((SCHEMAS_DIR / fname).read_text(encoding="utf-8"))
            self.assertEqual(doc["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(doc["type"], "object")
            self.assertIs(doc["additionalProperties"], False)
            self.assertIn("required", doc)
            self.assertIn("properties", doc)
            loaded[fname] = doc

        # Backward compatibility of tool_spec.v1.schema.json
        ts_schema = loaded["tool_spec.v1.schema.json"]
        for legacy_req in ("schema", "tool_id", "name", "version", "kind", "trust_tier", "capabilities", "input_schema", "output_schema"):
            self.assertIn(legacy_req, ts_schema["required"])
        for opt_port in ("input_port", "output_port", "effect_contract"):
            self.assertIn(opt_port, ts_schema["properties"])
            self.assertNotIn(opt_port, ts_schema["required"])

        # Parity check between Python contracts and JSON schema required fields
        port = PortContract(schema_ref="json:metrics", semantic_type="latency", encoding="utf-8", unit="ms")
        for k in loaded["port_contract.v1.schema.json"]["required"]:
            self.assertIn(k, port.to_dict())

        eff = EffectContract(read_scopes=["ws:data/*"], exec_permissions=["fs.read"])
        for k in loaded["effect_contract.v1.schema.json"]["required"]:
            self.assertIn(k, eff.to_dict())

        dst_port = PortContract(schema_ref="json:metrics", semantic_type="latency", encoding="utf-8", unit="s")
        adapter = AdapterSpec(
            adapter_id="adapter.ms_to_s",
            version="1.0.0",
            source_port=port,
            target_port=dst_port,
            mapping={"fields": {"latency_ms": "latency_s"}},
            unit_conversion={"from_unit": "ms", "to_unit": "s", "factor": 0.001},
            verification_corpus_hash=HASH_1,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "ci-verifier",
                "verification_digest": HASH_2,
                "adapter_id": "adapter.ms_to_s",
            },
        )
        for k in loaded["adapter_spec.v1.schema.json"]["required"]:
            self.assertIn(k, adapter.to_dict())

        plan = CompositionPlan(
            plan_id="plan-001",
            goal_contract_hash=HASH_1,
            nodes=[{"node_id": "n1", "tool_id": "tool.a"}],
            edges=[],
            input_bindings={"n1.in": "goal.input"},
            tool_artifact_hashes={"tool.a": HASH_2},
            adapter_hashes={"adapter.ms_to_s": adapter.adapter_hash},
            permission_union=["fs.read"],
            effects_union=compute_dag_effects([eff])["effects_union"],
            expected_outputs=[{"semantic_type": "latency"}],
            oracle_ref="oracle:latency_v1",
            verification_plan={"mode": "differential"},
            estimated_resources={"memory_mb": 128},
        )
        for k in loaded["composition_plan.v1.schema.json"]["required"]:
            self.assertIn(k, plan.to_dict())

        receipt = CompositionReceipt(
            run_id="run-001",
            plan_hash=plan.plan_hash,
            policy_hash=HASH_3,
            sandbox_environment_hash=HASH_4,
            node_receipts=[{"node_id": "n1", "status": "PASS"}],
            input_digest=HASH_1,
            output_digest=HASH_2,
            oracle_result={"passed": True, "reason": "exact_match"},
            verification_status="PASS",
            status=ExecutionStatus.PASS,
        )
        for k in loaded["composition_receipt.v1.schema.json"]["required"]:
            self.assertIn(k, receipt.to_dict())

        build = ToolBuild(state=ForgeState.VERIFIED, **_full_verified_build_kwargs())
        for k in loaded["tool_build.v1.schema.json"]["required"]:
            self.assertIn(k, build.to_dict())

        ev = RunEvent(
            run_id="run-001",
            step_id="step-1",
            state="TOOL_COMPLETED",
            tool_id="tool.a",
            input_digest=HASH_1,
            output_digest=HASH_2,
            elapsed_ms=12.5,
            tokens_used=0,
            resource_usage={"memory_mb": 32},
            decision_reason="verified_ok",
        )
        for k in loaded["run_event.v1.schema.json"]["required"]:
            self.assertIn(k, ev.to_dict())

    def test_port_contract_compatibility_rejects_semantic_unit_ordering_precision_and_sensitivity(self) -> None:
        base_out = PortContract(
            schema_ref="json:object",
            semantic_type="request_duration",
            encoding="utf-8",
            unit="ns",
            cardinality="many",
            ordering="ordered",
            sensitivity="public",
            trust_label="trusted",
            precision="float64",
        )
        exact_in = PortContract.from_dict(base_out.to_dict())
        self.assertTrue(ports_compatible(base_out, exact_in).compatible)

        # Ordered -> unordered allowed
        unordered_in = PortContract(
            schema_ref="json:object",
            semantic_type="request_duration",
            encoding="utf-8",
            unit="ns",
            cardinality="many",
            ordering="unordered",
            sensitivity="internal",
            trust_label="derived",
            precision="float64",
        )
        self.assertTrue(ports_compatible(base_out, unordered_in).compatible)

        # 1. JSON-only matching with mismatched semantic_type MUST fail
        bad_sem = PortContract(
            schema_ref="json:object",
            semantic_type="user_account_id",
            encoding="utf-8",
            unit="ns",
            cardinality="many",
            ordering="ordered",
            precision="float64",
        )
        res_sem = ports_compatible(base_out, bad_sem)
        self.assertFalse(res_sem.compatible)
        self.assertTrue(any("SEMANTIC_TYPE_MISMATCH" in r for r in res_sem.reasons))

        # 2. Unit mismatch (ns vs ms) MUST fail
        bad_unit = PortContract(
            schema_ref="json:object",
            semantic_type="request_duration",
            encoding="utf-8",
            unit="ms",
            cardinality="many",
            ordering="ordered",
            precision="float64",
        )
        res_unit = ports_compatible(base_out, bad_unit)
        self.assertFalse(res_unit.compatible)
        self.assertTrue(any("UNIT_MISMATCH" in r for r in res_unit.reasons))

        # 3. Ordering violation (unordered -> ordered) MUST fail
        src_unordered = PortContract(
            schema_ref="json:object",
            semantic_type="request_duration",
            unit="ns",
            cardinality="many",
            ordering="unordered",
            precision="float64",
        )
        res_ord = ports_compatible(src_unordered, base_out)
        self.assertFalse(res_ord.compatible)
        self.assertTrue(any("ORDERING_VIOLATION" in r for r in res_ord.reasons))

        # 4. Precision loss (float64 -> float32, decimal128 -> float64, int64 -> int32) MUST fail
        for src_p, dst_p in (
            ("float64", "float32"),
            ("decimal128", "float64"),
            ("int64", "int32"),
            ("64bit", "32bit"),
            ("exact", "approx"),
        ):
            p_src = PortContract(schema_ref="json:object", semantic_type="metric", unit="ms", precision=src_p)
            p_dst = PortContract(schema_ref="json:object", semantic_type="metric", unit="ms", precision=dst_p)
            res_prec = ports_compatible(p_src, p_dst)
            self.assertFalse(res_prec.compatible, f"Failed to reject precision loss {src_p} -> {dst_p}")
            self.assertTrue(any("PRECISION_LOSS" in r for r in res_prec.reasons))

        # 5. Sensitivity secret -> public MUST fail (while public -> secret allowed)
        src_secret = PortContract(schema_ref="json:object", semantic_type="token_count", sensitivity="secret")
        dst_public = PortContract(schema_ref="json:object", semantic_type="token_count", sensitivity="public")
        res_sens = ports_compatible(src_secret, dst_public)
        self.assertFalse(res_sens.compatible)
        self.assertTrue(any("SENSITIVITY_FLOW_VIOLATION" in r for r in res_sens.reasons))
        self.assertTrue(ports_compatible(dst_public, src_secret).compatible)

        # 6. Trust label untrusted -> trusted MUST fail
        src_untrusted = PortContract(schema_ref="json:object", semantic_type="payload", trust_label="untrusted")
        dst_trusted = PortContract(schema_ref="json:object", semantic_type="payload", trust_label="trusted")
        res_trust = ports_compatible(src_untrusted, dst_trusted)
        self.assertFalse(res_trust.compatible)
        self.assertTrue(any("TRUST_LABEL_VIOLATION" in r for r in res_trust.reasons))

    def test_effect_contract_dag_union_and_adapter_abstain(self) -> None:
        e1 = EffectContract(
            read_scopes=["ws:src/**"],
            write_scopes=[],
            exec_permissions=["fs.read"],
            irreversible=False,
            idempotent=True,
            resource_requirements={"tokens": 100, "max_memory_mb": 128},
        )
        e2 = EffectContract(
            read_scopes=["ws:src/**", "ws:cfg/*"],
            write_scopes=["ws:out/**"],
            network_scopes=["https://api.example.com"],
            exec_permissions=["fs.write", "network.outbound"],
            irreversible=True,
            idempotent=False,
            resource_requirements={"tokens": 250, "max_memory_mb": 512},
        )
        dag_eff = compute_dag_effects([e1, e2])
        self.assertEqual(dag_eff["permission_union"], ["fs.read", "fs.write", "network.outbound"])
        self.assertTrue(dag_eff["irreversible_any"])
        self.assertFalse(dag_eff["idempotent_all"])
        self.assertEqual(dag_eff["effects_union"]["resource_requirements"]["tokens"], 350)
        self.assertEqual(dag_eff["effects_union"]["resource_requirements"]["max_memory_mb"], 512)
        self.assertFalse(compute_dag_effects([])["irreversible_any"])
        self.assertTrue(compute_dag_effects([])["idempotent_all"])

        p_ns = PortContract(schema_ref="json:obj", semantic_type="duration", unit="ns")
        p_ms = PortContract(schema_ref="json:obj", semantic_type="duration", unit="ms")

        # Missing or ambiguous mappings raise AbstainError (ValueError)
        for bad_map in (
            {},
            {"ambiguous": True, "a": "b"},
            {"a": "b | c"},
            {"a": ["b", "c"]},
            {"fields": {"a": "target", "b": "target"}},
            {"a": "unknown"},
            {"a": "b", "confidence": 0.75},
        ):
            with self.assertRaises(AbstainError):
                AdapterSpec(
                    adapter_id="adapter.bad",
                    version="1.0.0",
                    source_port=p_ns,
                    target_port=p_ms,
                    mapping=bad_map,
                    unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": 1e-6},
                )

        # Unit mismatch without conversion abstains
        with self.assertRaises(AbstainError):
            AdapterSpec(
                adapter_id="adapter.no_unit_conv",
                version="1.0.0",
                source_port=p_ns,
                target_port=p_ms,
                mapping={"fields": {"dur_ns": "dur_ms"}},
                unit_conversion=None,
            )

        # Lossless secret -> public declassification abstains
        p_secret = PortContract(schema_ref="json:obj", semantic_type="log", sensitivity="secret")
        p_public = PortContract(schema_ref="json:obj", semantic_type="log", sensitivity="public")
        with self.assertRaises(AbstainError):
            AdapterSpec(
                adapter_id="adapter.leak",
                version="1.0.0",
                source_port=p_secret,
                target_port=p_public,
                mapping={"fields": {"raw": "out"}},
                lossless=True,
            )

        # Valid AdapterSpec roundtrip, tampered adapter_hash rejection, and self-asserted VERIFIED rejection
        valid_adapter = AdapterSpec(
            adapter_id="adapter.ns_to_ms",
            version="1.0.0",
            source_port=p_ns,
            target_port=p_ms,
            mapping={"fields": {"dur_ns": "dur_ms"}},
            unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": 1e-6},
            verification_corpus_hash=HASH_1,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "ci-verifier",
                "verification_digest": HASH_2,
                "adapter_id": "adapter.ns_to_ms",
            },
        )
        reloaded_adapter = AdapterSpec.from_dict(json.loads(valid_adapter.to_canonical_json()))
        self.assertEqual(reloaded_adapter.adapter_hash, valid_adapter.adapter_hash)
        bad_adapter_dict = valid_adapter.to_dict()
        bad_adapter_dict["adapter_hash"] = HASH_7
        with self.assertRaises(ValueError):
            AdapterSpec.from_dict(bad_adapter_dict)
        with self.assertRaises(ValueError):
            AdapterSpec(
                adapter_id="adapter.self_verified",
                version="1.0.0",
                source_port=p_ns,
                target_port=p_ms,
                mapping={"fields": {"dur_ns": "dur_ms"}},
                unit_conversion={"from_unit": "ns", "to_unit": "ms", "factor": 1e-6},
                verification_corpus_hash=HASH_1,
                trust_status=TrustStatus.VERIFIED,
                verification_attestation={"verifier_id": "self", "verification_digest": HASH_2},
            )

    def test_composition_plan_hashing_dag_and_receipt_guards(self) -> None:
        kwargs_a = {
            "plan_id": "plan-det",
            "goal_contract_hash": HASH_1,
            "nodes": [{"node_id": "a", "tool_id": "t.a"}, {"node_id": "b", "tool_id": "t.b"}],
            "edges": [{"from_node": "a", "to_node": "b"}],
            "input_bindings": {"b.x": "a.y", "a.in": "goal.x"},
            "tool_artifact_hashes": {"t.b": HASH_3, "t.a": HASH_2},
            "adapter_hashes": {},
            "permission_union": ["fs.write", "fs.read"],
            "effects_union": {"irreversible": False},
            "expected_outputs": [{"semantic_type": "sarif"}],
            "oracle_ref": "oracle:sarif",
            "verification_plan": {"b": 2, "a": 1},
            "estimated_resources": {"tokens": 0, "memory_mb": 64},
        }
        kwargs_b = {
            **kwargs_a,
            "input_bindings": {"a.in": "goal.x", "b.x": "a.y"},
            "tool_artifact_hashes": {"t.a": HASH_2, "t.b": HASH_3},
            "permission_union": ["fs.read", "fs.write"],
            "verification_plan": {"a": 1, "b": 2},
        }
        p1 = CompositionPlan(**kwargs_a)
        p2 = CompositionPlan(**kwargs_b)
        self.assertEqual(p1.plan_hash, p2.plan_hash)
        self.assertEqual(CompositionPlan.from_dict(json.loads(p1.to_canonical_json())).plan_hash, p1.plan_hash)

        # Tampered plan_hash rejected
        tampered = p1.to_dict()
        tampered["plan_hash"] = HASH_7
        with self.assertRaises(ValueError):
            CompositionPlan.from_dict(tampered)

        # Cycle rejected
        with self.assertRaises(ValueError):
            CompositionPlan(
                plan_id="plan-cycle",
                goal_contract_hash=HASH_1,
                nodes=[{"node_id": "a", "tool_id": "t.a"}, {"node_id": "b", "tool_id": "t.b"}],
                edges=[{"from_node": "a", "to_node": "b"}, {"from_node": "b", "to_node": "a"}],
                oracle_ref="oracle:check",
            )

        # Invalid PASS CompositionReceipt rejected
        with self.assertRaises(ValueError):
            CompositionReceipt(
                run_id="run-bad",
                plan_hash=p1.plan_hash,
                policy_hash=HASH_2,
                sandbox_environment_hash=HASH_3,
                oracle_result={"passed": False},
                verification_status="PASS",
                status=ExecutionStatus.PASS,
            )

    def test_forge_state_monotonic_transitions_and_run_event_chain(self) -> None:
        # Skipping states MUST be rejected
        for prev_s, next_s in (
            (ForgeState.GENERATED, ForgeState.VERIFIED),
            (ForgeState.PROPOSED, ForgeState.GENERATED),
            (ForgeState.COMPILED, ForgeState.DIFFERENTIAL_VERIFIED),
            (ForgeState.COMPILED, ForgeState.GENERATED),
            (ForgeState.VERIFIED, ForgeState.VERIFIED),
            (ForgeState.REJECTED, ForgeState.VERIFIED),
            (ForgeState.ROLLED_BACK, ForgeState.VERIFIED),
            (ForgeState.VERIFIED, ForgeState.REJECTED),
        ):
            with self.assertRaises(ValueError, msg=f"Allowed invalid transition {prev_s} -> {next_s}"):
                validate_forge_transition(prev_s, next_s)

        # Full monotonic chain succeeds step by step
        build = ToolBuild(build_id="bld-1", tool_id="forge.kernel", state=ForgeState.PROPOSED)
        step_updates = {
            ForgeState.SPECIFIED: {},
            ForgeState.REFERENCE_VERIFIED: {"oracle_hash": HASH_2},
            ForgeState.GENERATED: {"source_hash": HASH_1},
            ForgeState.COMPILED: {
                "compiler": "rustc",
                "compiler_version": "1.83.0",
                "flags": ["-O"],
                "artifact_hash": HASH_7,
            },
            ForgeState.SANDBOX_TESTED: {
                "unit_test_digest": HASH_3,
                "sandbox_receipt": {"status": "PASS", "passed": True},
            },
            ForgeState.DIFFERENTIAL_VERIFIED: {
                "differential_digest": HASH_4,
                "fuzz_digest": HASH_5,
                "boundary_digest": HASH_6,
            },
            ForgeState.BENCHMARKED: {
                "benchmark_vs_baseline": {"passed": True, "regressed": False, "speedup": 2.5},
            },
            ForgeState.SHADOW: {
                "rollback_metadata": {"previous_tool_hash": HASH_1, "reason": "none"},
            },
            ForgeState.VERIFIED: {},
        }
        for target_state in FORGE_STAGE_ORDER[1:]:
            build = build.transition_to(target_state, **step_updates[target_state])
        self.assertEqual(build.state, ForgeState.VERIFIED)
        rolled = build.transition_to(ForgeState.ROLLED_BACK, rollback_metadata={"reason": "manual_test"})
        self.assertEqual(rolled.state, ForgeState.ROLLED_BACK)

        # Verified ToolBuild missing required provenance MUST fail
        bad_kwargs = _full_verified_build_kwargs()
        bad_kwargs["differential_digest"] = ""
        with self.assertRaises(ValueError):
            ToolBuild(state=ForgeState.VERIFIED, **bad_kwargs)

        # RunEvent append-only hash chain verification + tamper detection
        e1 = RunEvent(
            run_id="run-chain",
            step_id="s1",
            state="STARTED",
            tool_id="tool.a",
            input_digest=HASH_1,
            output_digest=HASH_2,
            elapsed_ms=1.0,
            tokens_used=0,
            decision_reason="init",
            prev_event_hash=GENESIS_EVENT_HASH,
        )
        e2 = RunEvent(
            run_id="run-chain",
            step_id="s2",
            state="COMPLETED",
            tool_id="tool.a",
            input_digest=HASH_2,
            output_digest=HASH_3,
            elapsed_ms=4.0,
            tokens_used=12,
            decision_reason="oracle_ok",
            prev_event_hash=e1.event_hash,
        )
        ok_res = verify_event_chain([e1, e2])
        self.assertTrue(ok_res)
        self.assertTrue(ok_res.valid)
        self.assertEqual(ok_res.checked_count, 2)
        self.assertEqual(ok_res.head_hash, e2.event_hash)

        # Tamper e1 payload
        tampered_d1 = e1.to_dict()
        tampered_d1["decision_reason"] = "bypassed"
        bad_res = verify_event_chain([tampered_d1, e2.to_dict()])
        self.assertFalse(bad_res)
        self.assertFalse(bad_res.valid)

        # Break chain link
        broken_d2 = e2.to_dict()
        broken_d2["prev_event_hash"] = HASH_7
        self.assertFalse(verify_event_chain([e1.to_dict(), broken_d2]))


class TestBuild2ToctouAndProvenance(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.ws = self.root / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "process.exec"],
            network_allowed=False,
            allow_untrusted_native=False,
        )
        self.authority = make_fixture_authority()
        self.runner = SecureRunner(require_os_sandbox=False, attestation_authority=self.authority)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_script_tool(self, rel_path: str, source: str, tool_id: str = "tool.toctou") -> tuple[ToolSpec, Path]:
        target = self.ws / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
        _, digest = compute_file_sha256_confined(target, (self.ws,))
        spec = sign_fixture_spec(
            self.authority,
            ToolSpec(
                tool_id=tool_id,
                version="1.0.0",
                source="verified_local",
                binary_hash=digest,
                capabilities=["demo.toctou"],
                required_permissions=["fs.read", "process.exec"],
                trust_status=TrustStatus.VERIFIED,
                verification_attestation=_make_attestation(tool_id, digest),
                entrypoint=rel_path,
            ),
        )
        return spec, target

    def test_pre_and_post_exec_binary_toctou_fails_closed(self) -> None:
        marker = self.ws / "pwned_pre.txt"
        spec, script_path = self._make_script_tool(
            "tools/probe.py",
            "import json; print(json.dumps({'ok': True}))\n",
            tool_id="tool.pre_toctou",
        )

        # 1. Pre-exec race: file modified AFTER initial hash check, BEFORE execution
        orig_hooks = self.runner._run_pre_tool_hooks

        def _swap_before_exec(*args, **kwargs):
            orig_hooks(*args, **kwargs)
            script_path.write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('RAN')\n",
                encoding="utf-8",
            )

        with unittest.mock.patch.object(self.runner, "_run_pre_tool_hooks", side_effect=_swap_before_exec):
            res_pre = self.runner.run(spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(res_pre.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TOCTOU_PRE_EXEC_BINARY_HASH_CHANGED", res_pre.stderr_excerpt)
        self.assertFalse(marker.exists(), "Tampered pre-exec script must NEVER execute!")

        # 2. Pre-exec atomic inode replacement (same content or different content via os.replace)
        spec2, script2 = self._make_script_tool(
            "tools/atomic.py",
            "import json; print(json.dumps({'ok': True}))\n",
            tool_id="tool.inode_toctou",
        )

        def _atomic_swap_before_exec(*args, **kwargs):
            orig_hooks(*args, **kwargs)
            tmp_new = self.ws / "tools" / "atomic.tmp"
            tmp_new.write_text("import json; print(json.dumps({'ok': True}))\n", encoding="utf-8")
            os.replace(tmp_new, script2)

        with unittest.mock.patch.object(self.runner, "_run_pre_tool_hooks", side_effect=_atomic_swap_before_exec):
            res_inode = self.runner.run(spec2, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(res_inode.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TOCTOU_PRE_EXEC_BINARY_INODE_CHANGED", res_inode.stderr_excerpt)

        # 3. Post-exec tamper: script mutates itself during execution -> staging isolates execution & post-exec denies PASS!
        self_mod_src = (
            "import json\n"
            "from pathlib import Path\n"
            "Path('tools/selfmod.py').write_text('print(\"mutated\")\\n', encoding='utf-8')\n"
            "print(json.dumps({'ok': True}))\n"
        )
        spec3, _ = self._make_script_tool("tools/selfmod.py", self_mod_src, tool_id="tool.post_toctou")
        res_post = self.runner.run(spec3, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(res_post.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TOCTOU_POST_EXEC_BINARY_HASH_CHANGED", res_post.stderr_excerpt)

    def test_policy_hash_swap_and_expected_hash_mismatches_denied(self) -> None:
        spec, _ = self._make_script_tool(
            "tools/echo.py",
            "import json; print(json.dumps({'ok': True}))\n",
            tool_id="tool.policy_check",
        )
        plan_h = sha256_digest({"plan": "fixed"})

        # Baseline valid run with matching expected hashes passes
        ok = self.runner.run(
            spec,
            {},
            self.ctx,
            plan_hash=plan_h,
            expected_tool_hash=spec.binary_hash,
            expected_policy_hash=self.ctx.policy_hash,
            expected_plan_hash=plan_h,
            oracle=lambda r: r.get("output") == {"ok": True},
        )
        self.assertEqual(ok.status, ExecutionStatus.PASS)

        # Expected hash mismatches fail closed cleanly
        self.assertEqual(
            self.runner.run(spec, {}, self.ctx, expected_tool_hash=HASH_1).status,
            ExecutionStatus.PERMISSION_DENIED,
        )
        self.assertEqual(
            self.runner.run(spec, {}, self.ctx, expected_policy_hash=HASH_1).status,
            ExecutionStatus.PERMISSION_DENIED,
        )
        self.assertEqual(
            self.runner.run(spec, {}, self.ctx, plan_hash=plan_h, expected_plan_hash=HASH_1).status,
            ExecutionStatus.PERMISSION_DENIED,
        )
        self.assertEqual(
            self.runner.run(spec, {}, self.ctx, plan_hash="not-a-sha256").status,
            ExecutionStatus.PERMISSION_DENIED,
        )

        # In-memory SecurityContext mutation after creation (policy-hash mismatch) -> PERMISSION_DENIED
        tampered_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.GITHUB_PUBLIC,
            allowed_permissions=["fs.read"],
            network_allowed=False,
        )
        tampered_ctx.allowed_permissions.append("process.exec")
        tampered_ctx.network_allowed = True
        self.assertEqual(
            self.runner.run(spec, {}, tampered_ctx).status,
            ExecutionStatus.PERMISSION_DENIED,
        )

        # Policy swap during execution window (between pre-check and exec) -> PERMISSION_DENIED
        orig_hooks = self.runner._run_pre_tool_hooks
        swap_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "process.exec"],
            network_allowed=False,
        )

        def _swap_policy_mid_flight(*args, **kwargs):
            orig_hooks(*args, **kwargs)
            swap_ctx.network_allowed = True

        with unittest.mock.patch.object(self.runner, "_run_pre_tool_hooks", side_effect=_swap_policy_mid_flight):
            res_swap = self.runner.run(spec, {}, swap_ctx, oracle=lambda _r: True)
        self.assertEqual(res_swap.status, ExecutionStatus.PERMISSION_DENIED)

        # Mid-flight callable trust/hash swap -> PERMISSION_DENIED (explicit in-process callable mock)
        inproc_runner = SecureRunner(
            allow_in_process_callable=True,
            allow_trusted_host_callables=True,
            attestation_authority=self.authority,
        )

        def _pure_callable(_args: dict) -> dict:
            return {"ok": True}

        mut_hash = inproc_runner.register_trusted_host_callable("callable.toctou_mut", _pure_callable)
        call_spec = sign_fixture_spec(
            self.authority,
            ToolSpec(
                tool_id="callable.toctou_mut",
                version="1.0.0",
                source="builtin",
                binary_hash=mut_hash,
                capabilities=["demo.call"],
                required_permissions=["fs.read"],
                runtime_requirements={"callable_name": "callable.toctou_mut"},
                trust_status=TrustStatus.VERIFIED,
                verification_attestation=_make_attestation("callable.toctou_mut", mut_hash),
            ),
        )

        def _mutate_mid_flight(*_a: object, **_kw: object):
            call_spec.trust_status = TrustStatus.QUARANTINED
            return 0, {"ok": True}, '{"ok": true}', "", False

        with unittest.mock.patch.object(inproc_runner, "_execute_callable_bounded", side_effect=_mutate_mid_flight):
            res_call_mut = inproc_runner.run(call_spec, {}, self.ctx, oracle=lambda _r: True)
        self.assertEqual(res_call_mut.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertIn("TOCTOU_POST_EXEC_TRUST_CHANGED", res_call_mut.stderr_excerpt)

    @unittest.skipUnless(sys.platform == "darwin", "macOS Seatbelt test requires Darwin host")
    def test_kh_b2_sec_003_forged_native_binary_sandbox_mandatory_and_enforced(self) -> None:
        outside_dir = (self.root / "outside_secret_dir").resolve()
        outside_dir.mkdir(parents=True, exist_ok=True)
        outside_secret = outside_dir / "secret_b2_003.txt"
        canary = "FORGE_NATIVE_SECRET_CANARY_9931"
        outside_secret.write_text(canary, encoding="utf-8")
        os.chmod(outside_secret, 0o644)

        c_src = self.ws / "forged_exfil.c"
        c_bin = self.ws / "forged_exfil"
        c_escaped_path = str(outside_secret).replace("\\", "\\\\").replace('"', '\\"')
        c_src.write_text(
            "#include <errno.h>\n"
            "#include <stdio.h>\n"
            "int main(void) {\n"
            f'    FILE *f = fopen("{c_escaped_path}", "r");\n'
            "    if (f) {\n"
            "        char buf[128];\n"
            "        if (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);\n"
            "        fclose(f);\n"
            "        return 0;\n"
            "    }\n"
            "    return (errno == EPERM || errno == EACCES) ? 42 : 43;\n"
            "}\n",
            encoding="utf-8",
        )
        sb = ToolSandbox(self.ws)
        comp_res, _, _, _ = sb.compile_c(c_src, c_bin, flags=("-O2", "-std=c99"))
        self.assertTrue(comp_res.passed, msg=comp_res.stderr)

        _, bin_digest = compute_file_sha256_confined(c_bin, (self.ws,))
        forged_spec = sign_fixture_spec(
            self.authority,
            ToolSpec(
                tool_id="forge.exfil_probe",
                version="1.0.0",
                source="forge_native",
                binary_hash=bin_digest,
                capabilities=["forge.probe"],
                required_permissions=[],
                runtime_requirements={
                    "sandbox_required": True,
                    "sandbox_backend": "seatbelt",
                    "untrusted_native": False,
                },
                trust_status=TrustStatus.VERIFIED,
                verification_attestation=_make_attestation("forge.exfil_probe", bin_digest),
                entrypoint="forged_exfil",
            ),
        )

        # Note: allow_untrusted_native=False still permits verified forge_native ONLY under mandatory OS sandbox
        res_sb = self.runner.run(
            forged_spec,
            {},
            self.ctx,
            oracle=lambda _r: True,
        )
        self.assertNotIn(canary, res_sb.stdout_excerpt)
        self.assertNotIn(canary, res_sb.stderr_excerpt)
        self.assertNotIn(canary, json.dumps(res_sb.resource_metrics))
        if sb.probe_isolation().all_passed:
            self.assertEqual(res_sb.status, ExecutionStatus.FAIL)
            self.assertEqual(res_sb.exit_status, 42)
            self.assertTrue(res_sb.resource_metrics["sandbox_receipt"]["isolated"])
        else:
            self.assertEqual(res_sb.status, ExecutionStatus.SANDBOX_UNAVAILABLE)
            self.assertEqual(res_sb.verification_status, "FAIL")

        # Even with require_os_sandbox=False, forge_native MUST NOT bypass OS sandbox!
        non_overridable_runner = SecureRunner(
            sandbox=ToolSandbox(self.ws, force_unavailable=True),
            require_os_sandbox=False,
            attestation_authority=self.authority,
        )
        res_unavail = non_overridable_runner.run(
            forged_spec,
            {},
            self.ctx,
            oracle=lambda _r: True,
        )
        self.assertEqual(res_unavail.status, ExecutionStatus.SANDBOX_UNAVAILABLE)
        self.assertEqual(res_unavail.verification_status, "FAIL")

    def test_experience_store_provenance_invalidation_across_all_dimensions(self) -> None:
        store_path = self.ws / ".kintsugi" / "experience_store.json"
        store = ExperienceStore(store_path, workspace_root=self.ws)

        exp = Experience(
            task_fingerprint="fp_build2_scan",
            failure_class="code.scan",
            tool_or_plan_id="tool.scanner_v2",
            input_characteristics={"capability": "code.scan"},
            verified_outcome="PASS",
            cost={"wall_time_ms": 14.0},
            trace_hash=HASH_1,
            tool_hash=HASH_2,
            security_profile=SecurityProfile.LOCAL_RESEARCH,
        )
        store.record(
            exp,
            policy_hash=HASH_3,
            oracle_hash=HASH_4,
            oracle_ref="oracle:code_scan_v1",
            schema_hash=HASH_5,
            runtime_version="kintsugi-2.5.0",
            tool_hashes={"tool.scanner_v2": HASH_2, "adapter.norm": HASH_6},
        )
        self.assertEqual(stat.S_IMODE(store_path.stat().st_mode), 0o600)

        reloaded = ExperienceStore(store_path, workspace_root=self.ws)
        valid_kwargs = {
            "task_fingerprint": "fp_build2_scan",
            "capability": "code.scan",
            "security_profile": SecurityProfile.LOCAL_RESEARCH,
            "current_tool_hashes": {"tool.scanner_v2": HASH_2, "adapter.norm": HASH_6},
            "current_policy_hash": HASH_3,
            "current_oracle_hash": HASH_4,
            "current_oracle_ref": "oracle:code_scan_v1",
            "current_schema_hash": HASH_5,
            "runtime_version": "kintsugi-2.5.0",
        }
        hits = reloaded.retrieve_similar(**valid_kwargs)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].tool_or_plan_id, "tool.scanner_v2")

        # Every single provenance drift MUST invalidate stale hit cleanly
        invalidation_cases = [
            ("tool_hash_changed", {"current_tool_hashes": {"tool.scanner_v2": HASH_7, "adapter.norm": HASH_6}}),
            ("adapter_hash_changed", {"current_tool_hashes": {"tool.scanner_v2": HASH_2, "adapter.norm": HASH_7}}),
            ("policy_hash_changed", {"current_policy_hash": HASH_7}),
            ("oracle_hash_changed", {"current_oracle_hash": HASH_7}),
            ("oracle_ref_changed", {"current_oracle_ref": "oracle:code_scan_v2"}),
            ("schema_hash_changed", {"current_schema_hash": HASH_7}),
            ("runtime_version_changed", {"runtime_version": "kintsugi-2.6.0"}),
            ("tool_retired", {"retired_tool_ids": ["tool.scanner_v2"]}),
            ("dependency_retired", {"retired_tool_ids": ["adapter.norm"]}),
        ]
        for label, override in invalidation_cases:
            query = {**valid_kwargs, **override}
            stale_hits = reloaded.retrieve_similar(**query)
            self.assertEqual(stale_hits, [], f"Expected invalidation for {label}, got {stale_hits}")

        # Policy mutation inside input_characteristics remains strictly forbidden
        with self.assertRaises(ValueError):
            reloaded.record(
                {
                    "task_fingerprint": "fp_evil",
                    "failure_class": "code.scan",
                    "tool_or_plan_id": "tool.evil",
                    "verified_outcome": "PASS",
                    "input_characteristics": {"policy_hash": HASH_3},
                }
            )

        # Explicit purge removes stale record on disk
        removed = reloaded.invalidate_stale(current_policy_hash=HASH_7)
        self.assertEqual(removed, 1)
        self.assertEqual(reloaded.all(), [])


if __name__ == "__main__":
    unittest.main()
