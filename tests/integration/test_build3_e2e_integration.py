"""End-to-end cohesive Build #3 Cognitive Forge integration & zero-hook boundary tests."""

from __future__ import annotations

try:
    from fixture_attestation import (
        make_fixture_authority,
        sign_fixture_adapter,
        sign_fixture_spec,
        sign_fixture_tool,
    )
except ImportError:
    from tests.fixture_attestation import (
        make_fixture_authority,
        sign_fixture_adapter,
        sign_fixture_spec,
        sign_fixture_tool,
    )

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Iterator, List
from unittest import mock

from kintsugi.capability.contracts_v2 import (
    AdapterSpec,
    CompositionPlan,
    EffectContract,
    PortContract,
    compute_dag_effects,
)
from kintsugi.capability.schemas import (
    ExecutionReceipt,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.cli import main as cli_main
from kintsugi.composition import (
    verify_bundle_digest,
    verify_plan_formal,
)
from kintsugi.evolution import (
    EvolutionEngineV4,
    ExecutionMode,
    verify_disjoint_families,
)
from kintsugi.forge import (
    AsmNativeForge,
    build_delim_scan_kernel_spec,
    detect_host_arch,
    resolve_asm_backend,
)
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.runtime import (
    HermeticEntrypointSpec,
    HermeticExecutionResult,
    HermeticSpawnRunner,
    probe_linux_landlock_available,
)
from kintsugi.synthesis.capability_graph import SynthesisGoal, TypedCapabilityGraph


_SRC_ROOT = str(Path(__file__).resolve().parents[2] / "src")


@contextlib.contextmanager
def _patch_cls_attr(cls: type, attr_name: str, replacement: Any) -> Iterator[None]:
    type_dict_descr = type.__dict__["__dict__"]
    raw_dict = type_dict_descr.__get__(cls, type)
    existed = attr_name in raw_dict
    original = raw_dict.get(attr_name)
    setattr(cls, attr_name, replacement)
    try:
        yield
    finally:
        if existed:
            setattr(cls, attr_name, original)
        elif attr_name in type_dict_descr.__get__(cls, type):
            delattr(cls, attr_name)


def _sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _run_cli_json(argv: List[str]) -> tuple[int, Dict[str, Any]]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli_main(argv)
    return rc, json.loads(buf.getvalue())


def _run_isolated_hw_new_hook_probe(ws: Path, canary: Path) -> subprocess.CompletedProcess:
    code = """
import hashlib
import sys
from pathlib import Path

from kintsugi.capability.schemas import ExecutionStatus, SecurityContext, SecurityProfile
from kintsugi.runtime.hermetic_worker import HermeticEntrypointSpec, HermeticSpawnRunner

ws = Path(sys.argv[1])
canary = Path(sys.argv[2])
tool_file = ws / "hw_tool.py"
tool_file.write_text("def run(p): return {'ok': True}\\n", encoding="utf-8")
sha = f"sha256:{hashlib.sha256(tool_file.read_bytes()).hexdigest()}"

ctx = SecurityContext(
    workspace_root=str(ws),
    profile=SecurityProfile.LOCAL_RESEARCH,
    allowed_permissions=["fs.read"],
    network_allowed=False,
    allow_untrusted_native=False,
)
spec = HermeticEntrypointSpec(
    tool_id="b3.new_probe",
    module_path="hw_tool",
    callable_attr="run",
    expected_module_file_sha256=sha,
    module_file_path=str(tool_file),
)
runner = HermeticSpawnRunner()

def _bomb_new(cls, *a, **kw):
    canary.write_text(f"FIRED:{cls.__name__}.__new__", encoding="utf-8")
    return object.__new__(cls)

SecurityContext.__new__ = _bomb_new
res = runner.run(spec, {"k": "v"}, security_context=ctx)
assert res.execution_status == ExecutionStatus.PERMISSION_DENIED, res
assert "UNTRUSTED_CONTRACT_CLASS_TAMPERED" in res.error, res.error
assert not canary.exists()

HermeticEntrypointSpec.__new__ = _bomb_new
res2 = runner.run(spec, {"k": "v"}, security_context=ctx)
assert res2.execution_status == ExecutionStatus.PERMISSION_DENIED, res2
assert "UNTRUSTED_CONTRACT_CLASS_TAMPERED" in res2.error, res2.error
assert not canary.exists()
print("HW_NEW_HOOK_PROBE_PASSED")
"""
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC_ROOT
    return subprocess.run(
        [sys.executable, "-c", code, str(ws), str(canary)],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        check=False,
    )


class TestBuild3E2EIntegration(unittest.TestCase):
    """Verify Build #3 cohesive cross-module flow, CLI/MCP integration, and zero-hook IPC."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.outside_canary = self.root / "outside_canary.txt"
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "ast.scan"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _expect_linux_landlock_unavailable(self) -> bool:
        return sys.platform.startswith("linux") and not probe_linux_landlock_available()[0]

    def _make_verified_ports_and_plan(self):
        p_raw = PortContract(schema_ref="bytes:raw", semantic_type="raw_logs", sensitivity="secret")
        p_pub = PortContract(schema_ref="json:summary", semantic_type="summary", sensitivity="public")
        e1 = EffectContract(read_scopes=["ws:in.log"], exec_permissions=["fs.read"], idempotent=True)
        e2 = EffectContract(
            write_scopes=["ws:out.json"],
            exec_permissions=["fs.write"],
            irreversible=False,
            idempotent=False,
        )

        h1 = "sha256:" + "1" * 64
        h2 = "sha256:" + "2" * 64
        t1 = ToolSpec(
            tool_id="b3.log_extract",
            version="1.0.0",
            source="verified_local",
            binary_hash=h1,
            capabilities=["b3.extract"],
            input_schema={"type": "object", "encoding": p_raw.encoding},
            output_schema={"type": "object", "encoding": p_raw.encoding},
            semantic_contract={
                "input_port": {
                    "format": "bytes",
                    "semantic_type": "raw_bytes",
                    "unit": "none",
                    "sensitivity": "public",
                },
                "output_port": {
                    "format": "jsonl",
                    "semantic_type": "raw_logs",
                    "unit": "none",
                    "sensitivity": "public",
                },
                "effect_contract": e1.to_dict(),
            },
            side_effects=["none"],
            required_permissions=["fs.read"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "fixture-test-attestor",
                "verification_digest": sha256_digest({"tool_id": "b3.log_extract", "binary_hash": h1}),
                "binary_hash": h1,
                "tool_id": "b3.log_extract",
            },
        )
        t2 = ToolSpec(
            tool_id="b3.log_summarize",
            version="1.0.0",
            source="verified_local",
            binary_hash=h2,
            capabilities=["b3.summarize"],
            input_schema={"type": "object", "encoding": p_pub.encoding},
            output_schema={"type": "object", "encoding": p_pub.encoding},
            semantic_contract={
                "input_port": {
                    "format": "jsonl",
                    "semantic_type": "raw_logs",
                    "unit": "none",
                    "sensitivity": "public",
                },
                "output_port": {
                    "format": "json",
                    "semantic_type": "summary",
                    "unit": "none",
                    "sensitivity": "public",
                },
                "effect_contract": e2.to_dict(),
            },
            side_effects=["ws:out.json"],
            required_permissions=["fs.write"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "fixture-test-attestor",
                "verification_digest": sha256_digest({"tool_id": "b3.log_summarize", "binary_hash": h2}),
                "binary_hash": h2,
                "tool_id": "b3.log_summarize",
            },
        )
        ad = AdapterSpec(
            adapter_id="b3.redact_declassify",
            version="1.0.0",
            source_port=p_raw,
            target_port=p_pub,
            mapping={"fields": {"token": "redacted"}, "transform": "redact_secrets"},
            lossless=False,
            preconditions=["redact_secrets"],
            verification_corpus_hash=sha256_digest("b3-corpus"),
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "fixture-test-attestor",
                "verification_digest": sha256_digest({"adapter_id": "b3.redact_declassify"}),
                "adapter_id": "b3.redact_declassify",
            },
        )
        reg = ToolRegistry(authority=make_fixture_authority())
        sign_fixture_tool(reg, t1)
        sign_fixture_tool(reg, t2)
        ad = sign_fixture_adapter(reg, ad)

        # Build SMT-clean plan referencing p_raw -> ad -> p_pub
        t1_smt = ToolSpec(
            tool_id="b3.log_extract",
            version="1.0.0",
            source="verified_local",
            binary_hash=h1,
            capabilities=["b3.extract"],
            semantic_contract={
                "input_port": p_pub.to_dict(),
                "output_port": p_raw.to_dict(),
                "effect_contract": e1.to_dict(),
            },
            required_permissions=["fs.read"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation=dict(t1.verification_attestation),
        )
        t2_smt = ToolSpec(
            tool_id="b3.log_summarize",
            version="1.0.0",
            source="verified_local",
            binary_hash=h2,
            capabilities=["b3.summarize"],
            semantic_contract={
                "input_port": p_pub.to_dict(),
                "output_port": p_pub.to_dict(),
                "effect_contract": e2.to_dict(),
            },
            required_permissions=["fs.write"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation=dict(t2.verification_attestation),
        )
        sign_fixture_spec(reg.authority, t1_smt)
        sign_fixture_spec(reg.authority, t2_smt)
        dag_eff = compute_dag_effects([e1, e2])
        plan = CompositionPlan(
            plan_id="b3-e2e-smt-plan-01",
            goal_contract_hash=sha256_digest("b3-goal"),
            nodes=[
                {"node_id": "n1", "tool_id": "b3.log_extract", "retryable": True},
                {
                    "node_id": "n2",
                    "tool_id": "b3.log_summarize",
                    "retryable": True,
                    "wal_protected": True,
                    "idempotency_key": "b3-pub-01",
                },
            ],
            edges=[
                {
                    "from_node": "n1",
                    "to_node": "n2",
                    "adapter_id": "b3.redact_declassify",
                    "adapter_hash": ad.adapter_hash,
                }
            ],
            input_bindings={"n1.in": "goal.input"},
            tool_artifact_hashes={"b3.log_extract": h1, "b3.log_summarize": h2},
            adapter_hashes={"b3.redact_declassify": ad.adapter_hash},
            permission_union=dag_eff["permission_union"],
            effects_union=dag_eff["effects_union"],
            expected_outputs=[{"semantic_type": "summary", "sensitivity": "public"}],
            oracle_ref="oracle:b3_e2e",
            verification_plan={"mode": "replay"},
        )
        return [t1, t2], [t1_smt, t2_smt], [ad], plan, reg

    def test_build3_full_pipeline_graph_smt_hermetic_asm_evolution_v4(self) -> None:
        """Chain Agent B synthesis -> Agent D SMT proof -> Agent A hermetic worker -> Agent C asm -> Agent E v4."""
        graph_tools, smt_tools, adapters, plan, reg = self._make_verified_ports_and_plan()

        # 1. Agent B: Typed Capability Graph Synthesis
        graph = TypedCapabilityGraph(graph_tools)
        path_res = graph.find_shortest_safe_path(
            {"format": "bytes", "semantic_type": "raw_bytes", "unit": "none", "sensitivity": "public"},
            {"format": "json", "semantic_type": "summary", "unit": "none", "sensitivity": "public"},
            self.ctx,
        )
        self.assertTrue(path_res.found, msg=str(path_res.blocked_reasons))
        self.assertEqual(list(path_res.tool_ids), ["b3.log_extract", "b3.log_summarize"])

        # 2. Agent D: Formal SMT Plan Verifier
        bundle = verify_plan_formal(
            plan,
            self.ctx,
            registry={t.tool_id: t for t in smt_tools},
            adapters=adapters,
        )
        self.assertTrue(bundle.all_proven, msg=json.dumps(bundle.to_dict()))
        self.assertTrue(verify_bundle_digest(bundle))

        # 3. Agent A: Hermetic Spawn Worker executing a pinned tool in OS sandbox
        worker_file = self.ws / "b3_worker_tool.py"
        worker_file.write_text(
            "def summarize_counts(payload):\n"
            "    items = payload.get('lines', [])\n"
            "    return {'count': len(items), 'first': items[0] if items else ''}\n",
            encoding="utf-8",
        )
        spec = HermeticEntrypointSpec(
            tool_id="b3.worker_summarize",
            module_path="b3_worker_tool",
            callable_attr="summarize_counts",
            expected_module_file_sha256=_sha256_file(worker_file),
            module_file_path=str(worker_file),
        )
        h_runner = HermeticSpawnRunner()
        h_res = h_runner.run(
            spec,
            {"lines": ["alpha", "beta"]},
            security_context=self.ctx,
            oracle=lambda s: s["output"] == {"count": 2, "first": "alpha"},
        )
        if self._expect_linux_landlock_unavailable():
            self.assertIn(
                h_res.execution_status,
                (ExecutionStatus.SANDBOX_UNAVAILABLE, ExecutionStatus.PERMISSION_DENIED),
            )
        else:
            self.assertTrue(h_res.passed, msg=h_res.error or h_res.stderr)
            self.assertEqual(h_res.output, {"count": 2, "first": "alpha"})

        # 4. Agent C: ASM Native Forge (if clang available)
        arch = detect_host_arch()
        self.assertIn(
            resolve_asm_backend(target_arch=arch),
            ("aarch64_neon_inline_asm", "aarch64_crc32_inline_asm", "portable_c99_scalar"),
        )
        if shutil.which("clang"):
            asm_res = AsmNativeForge(self.ws).forge_kernel(build_delim_scan_kernel_spec())
            self.assertTrue(asm_res.verified, msg=asm_res.reason)
            self.assertTrue(asm_res.differential_report.passed)

        # 5. Agent E: Evolution v4 matched causal ablation + family disjointness
        trials = [
            {
                "family_id": f"heldout_{i // 3}",
                "task_id": f"task_{i}",
                "with_passed": True,
                "without_passed": (i % 4 == 0),
                "tokens_used": 100,
                "latency_ms": 5.0,
            }
            for i in range(12)
        ]
        self.assertTrue(verify_disjoint_families(["train_a", "train_b"], ["heldout_0", "heldout_1", "heldout_2", "heldout_3"]))
        ev4 = EvolutionEngineV4(mode=ExecutionMode.LOCAL_RESEARCH, workspace_root=self.ws)
        ablation = ev4.evaluate_ablation_trials(
            strategy_id="strat.b3.e2e",
            revision=1,
            train_families=["train_a", "train_b"],
            heldout_families=["heldout_0", "heldout_1", "heldout_2", "heldout_3"],
            trials=trials,
        )
        self.assertTrue(ablation.passed, msg=str(ablation.rejection_reasons))

    def test_build3_cli_subcommands_and_mcp_profile_parity(self) -> None:
        """Preserve default=9 and nextgen=19 MCP profiles while enabling build3=23 tools and Build #3 CLI."""
        ledger_path = self.ws / ".kintsugi" / "scars.json"
        s_def = KintsugiMCPServer(ledger_path, profile="default")
        self.assertEqual(len(s_def.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]), 9)

        s_ng = KintsugiMCPServer(ledger_path, profile="nextgen")
        self.assertEqual(len(s_ng.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]), 19)

        s_b3 = KintsugiMCPServer(ledger_path, profile="build3")
        b3_tools = s_b3.handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})["result"]["tools"]
        self.assertEqual(len(b3_tools), 23)
        b3_names = {t["name"] for t in b3_tools}
        expected_b3 = {
            "kintsugi_build3_synthesize_plan",
            "kintsugi_build3_smt_verify_plan",
            "kintsugi_build3_asm_arch_status",
            "kintsugi_build3_evolution_v4_ablate",
        }
        self.assertTrue(expected_b3.issubset(b3_names))
        for tool in b3_tools:
            if tool["name"] in expected_b3:
                self.assertIs(tool["annotations"]["readOnlyHint"], True)

        graph_tools, smt_tools, adapters, plan, _ = self._make_verified_ports_and_plan()
        tools_json = [t.to_dict() for t in graph_tools]
        smt_tools_json = [t.to_dict() for t in smt_tools]
        adapters_json = [a.to_dict() for a in adapters]
        goal_json = {
            "goal_id": "b3-goal-01",
            "source_req": {"format": "bytes", "semantic_type": "raw_bytes", "unit": "none", "sensitivity": "public"},
            "target_req": {"format": "json", "semantic_type": "summary", "unit": "none", "sensitivity": "public"},
        }
        trials_payload = {
            "strategy_id": "strat.mcp.01",
            "revision": 1,
            "train_families": ["train_x"],
            "heldout_families": ["held_0", "held_1"],
            "trials": [
                {
                    "family_id": f"held_{i % 2}",
                    "task_id": f"mcp_t_{i}",
                    "with_passed": True,
                    "without_passed": False,
                    "tokens_used": 50,
                    "latency_ms": 2.0,
                }
                for i in range(10)
            ],
        }

        # Dispatch all 4 Build #3 MCP tools
        mcp_cases = [
            ("kintsugi_build3_asm_arch_status", {"workspace_root": str(self.ws)}),
            (
                "kintsugi_build3_synthesize_plan",
                {
                    "workspace_root": str(self.ws),
                    "goal": goal_json,
                    "tools": tools_json,
                    "security_context": self.ctx.to_dict(),
                },
            ),
            (
                "kintsugi_build3_smt_verify_plan",
                {
                    "workspace_root": str(self.ws),
                    "plan": plan.to_dict(),
                    "tools": smt_tools_json,
                    "adapters": adapters_json,
                    "security_context": self.ctx.to_dict(),
                },
            ),
            ("kintsugi_build3_evolution_v4_ablate", {"workspace_root": str(self.ws), **trials_payload}),
        ]
        for idx, (tname, targs) in enumerate(mcp_cases, 10):
            resp = s_b3.handle_request(
                {"jsonrpc": "2.0", "id": idx, "method": "tools/call", "params": {"name": tname, "arguments": targs}}
            )
            body = json.loads(resp["result"]["content"][0]["text"])
            self.assertTrue(body.get("ok"), msg=f"{tname} -> {body}")

        # Exercise Build #3 CLI subcommands directly
        (self.ws / "b3_goal.json").write_text(json.dumps(goal_json), encoding="utf-8")
        (self.ws / "b3_tools.json").write_text(json.dumps(tools_json), encoding="utf-8")
        (self.ws / "b3_smt_tools.json").write_text(json.dumps(smt_tools_json), encoding="utf-8")
        (self.ws / "b3_adapters.json").write_text(json.dumps(adapters_json), encoding="utf-8")
        (self.ws / "b3_plan.json").write_text(json.dumps(plan.to_dict()), encoding="utf-8")
        (self.ws / "b3_ctx.json").write_text(json.dumps(self.ctx.to_dict()), encoding="utf-8")
        (self.ws / "b3_trials.json").write_text(json.dumps(trials_payload), encoding="utf-8")

        rc_asm, out_asm = _run_cli_json(["asm-forge", "info", "--workspace", str(self.ws)])
        self.assertEqual(rc_asm, 0)
        self.assertTrue(out_asm["ok"])

        rc_syn, out_syn = _run_cli_json(
            [
                "synthesize",
                "--workspace",
                str(self.ws),
                "--goal-file",
                "b3_goal.json",
                "--tools-file",
                "b3_tools.json",
                "--context-file",
                "b3_ctx.json",
            ]
        )
        self.assertEqual(rc_syn, 0)
        self.assertTrue(out_syn["ok"])

        rc_smt, out_smt = _run_cli_json(
            [
                "smt-verify",
                "--workspace",
                str(self.ws),
                "--plan-file",
                "b3_plan.json",
                "--tools-file",
                "b3_smt_tools.json",
                "--adapters-file",
                "b3_adapters.json",
                "--context-file",
                "b3_ctx.json",
            ]
        )
        self.assertEqual(rc_smt, 0, msg=str(out_smt))
        self.assertTrue(out_smt["ok"])
        self.assertTrue(out_smt["all_proven"])
        self.assertIn("certificate_sha256", out_smt)

        rc_ev4, out_ev4 = _run_cli_json(["evolve-v4", "--workspace", str(self.ws), "--trials-file", "b3_trials.json"])
        self.assertEqual(rc_ev4, 0)
        self.assertTrue(out_ev4["ok"])

    def test_build3_hermetic_worker_zero_hook_primitive_boundary_r10_to_r14(self) -> None:
        """Enforce full R10-R14 zero-hook & primitive-only contract discipline in `HermeticSpawnRunner`."""
        canary = self.outside_canary
        worker_file = self.ws / "mod_tool.py"
        worker_file.write_text("def run(_p): return {'ok': True}\n", encoding="utf-8")
        sha = _sha256_file(worker_file)
        runner = HermeticSpawnRunner()
        spec = HermeticEntrypointSpec(
            tool_id="b3.r14_guard",
            module_path="mod_tool",
            callable_attr="run",
            expected_module_file_sha256=sha,
            module_file_path=str(worker_file),
        )

        # 1. Subclass SecurityContext + property hook -> PERMISSION_DENIED, 0 canary
        class EvilSecCtx(SecurityContext):
            @property
            def workspace_root(self) -> str:  # type: ignore[override]
                canary.write_text("EVIL_SEC_CTX_PROP", encoding="utf-8")
                return str(self.ws)

        evil_ctx = object.__new__(EvilSecCtx)
        res_sub_ctx = runner.run(spec, {}, security_context=evil_ctx)
        self.assertEqual(res_sub_ctx.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

        # 2. Mutated SecurityContext class lifecycle hooks
        def _bomb_method(label: str):
            def _fn(*_a: Any, **_kw: Any) -> Any:
                canary.write_text(f"FIRED:{label}", encoding="utf-8")
                return str(self.ws)

            return _fn

        def _bomb_setattr(self_obj: Any, k: str, v: Any) -> None:
            canary.write_text("FIRED:setattr", encoding="utf-8")
            object.__setattr__(self_obj, k, v)

        for cls, attr in [
            (SecurityContext, "__post_init__"),
            (SecurityContext, "__init__"),
            (SecurityContext, "__setattr__"),
            (SecurityContext, "validate_path"),
            (SecurityContext, "to_dict"),
            (HermeticEntrypointSpec, "__post_init__"),
            (HermeticEntrypointSpec, "__init__"),
            (HermeticEntrypointSpec, "__setattr__"),
        ]:
            fn = _bomb_setattr if attr == "__setattr__" else _bomb_method(f"{cls.__name__}.{attr}")
            with _patch_cls_attr(cls, attr, fn):
                res = runner.run(spec, {"k": "v"}, security_context=self.ctx)
                self.assertEqual(res.execution_status, ExecutionStatus.PERMISSION_DENIED)
                self.assertIn("UNTRUSTED_CONTRACT_CLASS_TAMPERED", res.error)
                self.assertFalse(canary.exists(), f"Canary triggered on {cls.__name__}.{attr}")

        # 3. Receipt & HermeticExecutionResult lifecycle hooks fail closed
        for cls in (ExecutionReceipt, HermeticExecutionResult):
            with _patch_cls_attr(cls, "__post_init__", _bomb_method(f"{cls.__name__}.__post_init__")):
                with self.assertRaises(PermissionError):
                    runner.run(spec, {"k": "v"}, security_context=self.ctx)
                self.assertFalse(canary.exists())

        # 4. Isolated subprocess __new__ hook test
        proc = _run_isolated_hw_new_hook_probe(self.ws, canary)
        self.assertEqual(proc.returncode, 0, msg=f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("HW_NEW_HOOK_PROBE_PASSED", proc.stdout)
        self.assertFalse(canary.exists())

        # 5. Subclass HermeticEntrypointSpec + post-init PosixPath injection
        class EvilSpec(HermeticEntrypointSpec):
            @property
            def module_file_path(self) -> Any:  # type: ignore[override]
                canary.write_text("EVIL_SPEC_PROP", encoding="utf-8")
                return str(worker_file)

        evil_spec = object.__new__(EvilSpec)
        res_evil_spec = runner.run(evil_spec, {}, security_context=self.ctx)
        self.assertEqual(res_evil_spec.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

        mutated_spec = HermeticEntrypointSpec(
            tool_id="b3.path_mut",
            module_path="mod_tool",
            callable_attr="run",
            expected_module_file_sha256=sha,
            module_file_path=str(worker_file),
        )
        object.__setattr__(mutated_spec, "module_file_path", Path(worker_file))
        res_path_mut = runner.run(mutated_spec, {}, security_context=self.ctx)
        self.assertEqual(res_path_mut.execution_status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(canary.exists())

        # 6. Adversarial payloads: metaclass __eq__, CollidingKey, EvilDict, Path, cyclic dict
        class _EvilMeta(type):
            def __eq__(cls, other: object) -> bool:
                canary.write_text("META_EQ", encoding="utf-8")
                return False

        class _EvilVal(metaclass=_EvilMeta):
            pass

        class _CollidingKey(str):
            def __hash__(self) -> int:
                return hash("k")

            def __eq__(self, other: object) -> bool:
                canary.write_text("COLLIDING_EQ", encoding="utf-8")
                return True

        class _EvilDict(dict):
            def items(self):  # type: ignore[override]
                canary.write_text("EVILDICT_ITEMS", encoding="utf-8")
                return []

        cyc: Dict[str, Any] = {}
        cyc["self"] = cyc
        for bad_payload in (
            {"x": _EvilVal},
            {_CollidingKey("x"): 2},
            _EvilDict({"a": 1}),
            {"path": worker_file},
            cyc,
        ):
            res_bad = runner.run(spec, bad_payload, security_context=self.ctx)
            self.assertEqual(res_bad.execution_status, ExecutionStatus.PERMISSION_DENIED)
            self.assertFalse(canary.exists())


if __name__ == "__main__":
    unittest.main()
