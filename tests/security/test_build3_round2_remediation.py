"""Round-2 remediation regression suite for all Build #3 Cognitive Forge findings.

Covers all 7 ChatGPT Round-1 findings + positive verified paths + Arm C gate checks:
  - KH-B3-R1-SEC-001: Fail-closed `smt_plan_verifier` declassifier attestation & MCP gate
  - KH-B3-R1-SEC-002: Fail-closed `TypedCapabilityGraph` HMAC authority & MCP gate
  - KH-B3-R1-SEC-003: `asm_native_forge` macro/constructor static safety rejection
  - KH-B3-R1-SEC-005: `asm_native_forge` TOCTOU swap defense via private staged dlopen
  - KH-B3-R1-SEC-004: `evolution_v4` strict bool & strict int checks (direct + MCP)
  - P2 cond: `hermetic_worker` poisoned `PosixPath._raw_paths`/`_parts` zero-canary rejection
  - KH-B3-R1-SEC-007: `evolution_v4` AST alpha-renamed & whitespace-reformatted leakage
  - Arm C gate: `kintsugi.arm_c_gate` micro `AGENTS.md` size + compact feedback gate
"""

from __future__ import annotations

try:
    from fixture_attestation import (
        TEST_VERIFIER_ID,
        TEST_VERIFIER_KEY,
        make_fixture_authority,
        sign_fixture_spec,
    )
except ImportError:
    from tests.fixture_attestation import (
        TEST_VERIFIER_ID,
        TEST_VERIFIER_KEY,
        make_fixture_authority,
        sign_fixture_spec,
    )

import contextlib
import ctypes
import hashlib
import inspect
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path, PosixPath
from typing import Any, Dict, List
from unittest import mock

from kintsugi.capability.schemas import (
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.cli import main as cli_main
from kintsugi.composition.smt_plan_verifier import (
    STATUS_COUNTEREXAMPLE,
    STATUS_PROVEN,
    compute_declassifier_node_spec_digest,
    verify_plan_formal,
)
from kintsugi.evolution.evolution_v4 import (
    CorpusLeakageError,
    EvolutionEngineV4,
    ExecutionMode,
    verify_disjoint_families,
)
from kintsugi.forge.asm_native_forge import (
    KINTSUGI_ASM_ABI_VERSION,
    AsmKernelSpec,
    AsmNativeForge,
    build_delim_scan_kernel_spec,
    delim_scan_python,
    scan_asm_source_safety,
)
from kintsugi.mcp_nextgen import dispatch_nextgen_build3_mcp_tool
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.runtime.hermetic_worker import HermeticEntrypointSpec, HermeticSpawnRunner
from kintsugi.synthesis.capability_graph import TypedCapabilityGraph


_REPO_ROOT = Path(__file__).resolve().parents[2]
_HASH_SRC = "sha256:" + "1" * 64
_HASH_DECL = "sha256:" + "2" * 64
_HASH_SINK = "sha256:" + "3" * 64


def _sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _make_heldout_trials(*, count: int = 20, with_passed: Any = True, without_passed: Any = False) -> List[Dict[str, Any]]:
    return [
        {
            "family_id": f"heldout_fam_{i % 4}",
            "task_id": f"task_{i:02d}",
            "with_passed": with_passed,
            "without_passed": without_passed,
            "tokens_used": 40,
            "latency_ms": 2.0,
        }
        for i in range(count)
    ]


def _extract_arm_c_feedback(result: Any) -> tuple[str, int]:
    """Normalize Arm C gate output into `(feedback_text, token_estimate)`."""
    if isinstance(result, str):
        text = result.strip()
        return text, (len(text.split()) if text else 0)
    if isinstance(result, tuple) and len(result) >= 2:
        text = str(result[1] or "").strip()
        return text, (len(text.split()) if text else 0)
    if isinstance(result, dict):
        text = str(result.get("feedback") or result.get("feedback_text") or result.get("message") or "").strip()
        tok = (
            result.get("tokens")
            or result.get("token_count")
            or result.get("feedback_tokens")
            or result.get("token_estimate")
            or result.get("estimated_tokens")
        )
        est = int(tok) if isinstance(tok, int) and not isinstance(tok, bool) else (len(text.split()) if text else 0)
        return text, est
    text = str(
        getattr(result, "feedback", None)
        or getattr(result, "feedback_text", None)
        or getattr(result, "message", None)
        or ""
    ).strip()
    tok = (
        getattr(result, "tokens", None)
        or getattr(result, "token_count", None)
        or getattr(result, "feedback_tokens", None)
        or getattr(result, "token_estimate", None)
        or getattr(result, "estimated_tokens", None)
    )
    est = int(tok) if isinstance(tok, int) and not isinstance(tok, bool) else (len(text.split()) if text else 0)
    return text, est


class TestBuild3Round2Remediation(unittest.TestCase):
    """Regression PoC & positive verification suite for Build #3 Round-1 security findings."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_b3_r2_")
        self.root = Path(self._tmp.name).resolve()
        self.ws = self.root / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.canary = self.root / "pwn_canary.txt"
        self.ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "ast.scan"],
            network_allowed=False,
            allow_untrusted_native=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_kh_b3_r1_sec_001_smt_declassifier_fail_closed_and_mcp_gate(self) -> None:
        """KH-B3-R1-SEC-001: Forged or unauthenticated declassifier fails closed; HMAC authority proves."""
        auth = make_fixture_authority()
        forged_att = {
            "verifier_id": TEST_VERIFIER_ID,
            "verification_digest": sha256_digest("forged-declassifier"),
            "binary_hash": _HASH_DECL,
            "tool_id": "b3.node_declassifier",
            "spec_digest": sha256_digest("forged-spec"),
            "signature": "hmac-sha256:" + ("f" * 64),
        }

        def _make_plan(decl_att: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "plan_id": "plan-sec001-dag",
                "goal_contract_hash": sha256_digest("goal-sec001"),
                "nodes": [
                    {
                        "node_id": "n1",
                        "tool_id": "b3.secret_source",
                        "output_sensitivity": "secret",
                        "retryable": True,
                    },
                    {
                        "node_id": "n2",
                        "tool_id": "b3.node_declassifier",
                        "declassifier": True,
                        "target_sensitivity": "public",
                        "binary_hash": _HASH_DECL,
                        "retryable": True,
                        "declassifier_attestation": decl_att,
                    },
                    {
                        "node_id": "n3",
                        "tool_id": "b3.public_sink",
                        "input_sensitivity": "public",
                        "output_sensitivity": "public",
                        "retryable": True,
                        "wal_protected": True,
                        "idempotency_key": "sec001-sink",
                    },
                ],
                "edges": [
                    {"from_node": "n1", "to_node": "n2"},
                    {"from_node": "n2", "to_node": "n3"},
                ],
                "input_bindings": {"n1.in": "goal.input"},
                "tool_artifact_hashes": {
                    "b3.secret_source": _HASH_SRC,
                    "b3.node_declassifier": _HASH_DECL,
                    "b3.public_sink": _HASH_SINK,
                },
                "adapter_hashes": {},
                "permission_union": ["fs.read"],
                "effects_union": {"read_scopes": ["ws:in"], "write_scopes": []},
                "expected_outputs": [{"sensitivity": "public"}],
                "oracle_ref": "oracle:sec001",
                "verification_plan": {"mode": "replay"},
            }

        forged_plan = _make_plan(forged_att)

        # 1. Direct verifier rejects forged attestation with and without authority
        b_no_auth = verify_plan_formal(forged_plan, self.ctx)
        self.assertFalse(b_no_auth.all_proven)
        self.assertEqual(b_no_auth.certificates["no_secret_escalation"].status, STATUS_COUNTEREXAMPLE)

        b_forged_hmac = verify_plan_formal(forged_plan, self.ctx, authority=auth)
        self.assertFalse(b_forged_hmac.all_proven)
        self.assertEqual(b_forged_hmac.certificates["no_secret_escalation"].status, STATUS_COUNTEREXAMPLE)

        # 2. MCP dispatch rejects forged attestation (default authority=None and even with authority)
        mcp_forged = dispatch_nextgen_build3_mcp_tool(
            "kintsugi_build3_smt_verify_plan",
            {
                "workspace_root": str(self.ws),
                "plan": forged_plan,
                "security_context": self.ctx.to_dict(),
            },
        )
        self.assertFalse(mcp_forged["ok"])
        self.assertFalse(mcp_forged["all_proven"])
        self.assertEqual(mcp_forged["certificates"]["no_secret_escalation"]["status"], STATUS_COUNTEREXAMPLE)

        # 3. Signed declassifier via compute_declassifier_node_spec_digest + AttestationAuthority
        signed_plan = _make_plan({})
        decl_node = signed_plan["nodes"][1]
        decl_node["declassifier_attestation"] = auth.issue_attestation(
            "b3.node_declassifier",
            _HASH_DECL,
            sha256_digest({"node_id": "n2", "binary_hash": _HASH_DECL}),
            TEST_VERIFIER_ID,
            spec_digest=compute_declassifier_node_spec_digest(decl_node),
        )

        # Still fails closed when authority is omitted (zero-trust default)
        b_signed_no_auth = verify_plan_formal(signed_plan, self.ctx)
        self.assertFalse(b_signed_no_auth.all_proven)
        self.assertEqual(b_signed_no_auth.certificates["no_secret_escalation"].status, STATUS_COUNTEREXAMPLE)

        mcp_signed_no_auth = dispatch_nextgen_build3_mcp_tool(
            "kintsugi_build3_smt_verify_plan",
            {
                "workspace_root": str(self.ws),
                "plan": signed_plan,
                "security_context": self.ctx.to_dict(),
            },
        )
        self.assertFalse(mcp_signed_no_auth["ok"])
        self.assertFalse(mcp_signed_no_auth["all_proven"])
        self.assertEqual(mcp_signed_no_auth["certificates"]["no_secret_escalation"]["status"], STATUS_COUNTEREXAMPLE)

        # Succeeds ONLY with trusted AttestationAuthority
        b_ok = verify_plan_formal(signed_plan, self.ctx, authority=auth)
        self.assertTrue(b_ok.all_proven, msg=json.dumps(b_ok.to_dict()))
        self.assertEqual(b_ok.certificates["no_secret_escalation"].status, STATUS_PROVEN)

        mcp_ok = dispatch_nextgen_build3_mcp_tool(
            "kintsugi_build3_smt_verify_plan",
            {
                "workspace_root": str(self.ws),
                "plan": signed_plan,
                "security_context": self.ctx.to_dict(),
            },
            authority=auth,
        )
        self.assertTrue(mcp_ok["ok"])
        self.assertTrue(mcp_ok["all_proven"])
        self.assertEqual(mcp_ok["certificates"]["no_secret_escalation"]["status"], STATUS_PROVEN)

    def test_kh_b3_r1_sec_002_capability_graph_self_attested_fail_closed_and_mcp_gate(self) -> None:
        """KH-B3-R1-SEC-002: Self-attested VERIFIED ToolSpec rejected directly & via MCP without HMAC authority."""
        self_attested = ToolSpec(
            tool_id="b3.self_claimed",
            version="1.0.0",
            source="untrusted_inline",
            binary_hash=_HASH_SRC,
            capabilities=["b3.parse"],
            semantic_contract={
                "input_port": {"format": "bytes", "semantic_type": "raw_bytes", "unit": "none", "sensitivity": "public"},
                "output_port": {"format": "json", "semantic_type": "summary", "unit": "none", "sensitivity": "public"},
                "effect_contract": {"read_scopes": ["ws:in"], "exec_permissions": ["fs.read"], "idempotent": True},
            },
            required_permissions=["fs.read"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "self-claimed-verifier",
                "verification_digest": sha256_digest({"tool_id": "b3.self_claimed", "binary_hash": _HASH_SRC}),
                "binary_hash": _HASH_SRC,
                "tool_id": "b3.self_claimed",
            },
        )
        goal = {
            "goal_id": "sec002-goal",
            "source_req": {"format": "bytes", "semantic_type": "raw_bytes", "unit": "none", "sensitivity": "public"},
            "target_req": {"format": "json", "semantic_type": "summary", "unit": "none", "sensitivity": "public"},
        }

        # 1. Direct TypedCapabilityGraph without authority excludes self-attested tool
        g_no_auth = TypedCapabilityGraph([self_attested])
        self.assertEqual(g_no_auth.verified_tool_ids, [])
        self.assertEqual(
            g_no_auth.get_excluded_tools()["b3.self_claimed"].reasons,
            ("MISSING_ATTESTATION_AUTHORITY",),
        )

        # 2. MCP dispatch without authority excludes self-attested tool
        mcp_no_auth = dispatch_nextgen_build3_mcp_tool(
            "kintsugi_build3_synthesize_plan",
            {
                "workspace_root": str(self.ws),
                "goal": goal,
                "tools": [self_attested.to_dict()],
                "security_context": self.ctx.to_dict(),
            },
        )
        self.assertFalse(mcp_no_auth["ok"])
        self.assertIn("b3.self_claimed", mcp_no_auth["excluded_tools"])
        self.assertEqual(
            mcp_no_auth["excluded_tools"]["b3.self_claimed"]["reasons"],
            ["MISSING_ATTESTATION_AUTHORITY"],
        )

        # 3. Signed ToolSpec with AttestationAuthority is admitted directly and via MCP
        auth = make_fixture_authority()
        signed_tool = ToolSpec(
            tool_id="b3.signed_worker",
            version="1.0.0",
            source="verified_local",
            binary_hash=_HASH_SINK,
            capabilities=["b3.parse"],
            semantic_contract=dict(self_attested.semantic_contract),
            required_permissions=["fs.read"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": TEST_VERIFIER_ID,
                "verification_digest": sha256_digest({"tool_id": "b3.signed_worker", "binary_hash": _HASH_SINK}),
                "binary_hash": _HASH_SINK,
                "tool_id": "b3.signed_worker",
            },
        )
        sign_fixture_spec(auth, signed_tool)

        g_signed_no_auth = TypedCapabilityGraph([signed_tool])
        self.assertEqual(g_signed_no_auth.verified_tool_ids, [])
        self.assertEqual(
            g_signed_no_auth.get_excluded_tools()["b3.signed_worker"].reasons,
            ("MISSING_ATTESTATION_AUTHORITY",),
        )

        g_auth = TypedCapabilityGraph([self_attested, signed_tool], authority=auth)
        self.assertEqual(g_auth.verified_tool_ids, ["b3.signed_worker"])
        self.assertEqual(
            g_auth.get_excluded_tools()["b3.self_claimed"].reasons,
            ("INVALID_ATTESTATION_HMAC",),
        )
        path_res = g_auth.find_shortest_safe_path(goal["source_req"], goal["target_req"], self.ctx)
        self.assertTrue(path_res.found)
        self.assertEqual(list(path_res.tool_ids), ["b3.signed_worker"])

        srv_auth = KintsugiMCPServer(self.ws / ".kintsugi" / "scars.json", profile="build3", attestation_authority=auth)
        resp = srv_auth.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {
                    "name": "kintsugi_build3_synthesize_plan",
                    "arguments": {
                        "workspace_root": str(self.ws),
                        "goal": goal,
                        "tools": [signed_tool.to_dict()],
                        "security_context": self.ctx.to_dict(),
                    },
                },
            }
        )
        assert resp is not None
        body = json.loads(resp["result"]["content"][0]["text"])
        self.assertTrue(body["ok"])
        self.assertTrue(body["safe_path"]["found"])
        self.assertEqual(body["safe_path"]["tool_ids"], ["b3.signed_worker"])

    def test_kh_b3_r1_sec_003_asm_macro_constructor_smuggling_rejected(self) -> None:
        """KH-B3-R1-SEC-003: `#define` hiding `fopen` + `__attribute__((constructor))` blocked before clang."""
        smuggled_macro_src = (
            "#include <stdint.h>\n"
            "#include <stdio.h>\n"
            f'#define KINTSUGI_CANARY_PATH "{self.canary}"\n'
            "#define HIDDEN_OPEN fopen\n"
            'const char *kintsugi_asm_abi_version(void) { return "KINTSUGI_ASM_ABI_V1"; }\n'
            "__attribute__((constructor)) static void pwn_ctor(void) {\n"
            '    FILE *fp = HIDDEN_OPEN(KINTSUGI_CANARY_PATH, "w");\n'
            '    if (fp) { fputs("PWN", fp); fclose(fp); }\n'
            "}\n"
        )
        prefixed_macro_src = smuggled_macro_src.replace("HIDDEN_OPEN", "KINTSUGI_OPEN")

        forge = AsmNativeForge(self.ws)
        for label, src, expect_macro_rule in (
            ("non_allowlist_macro", smuggled_macro_src, True),
            ("kintsugi_prefixed_macro", prefixed_macro_src, False),
        ):
            safe_ok, reasons = scan_asm_source_safety(src, allow_asm=True, abi_version=KINTSUGI_ASM_ABI_VERSION)
            self.assertFalse(safe_ok, msg=f"{label} unexpectedly passed static scan")
            self.assertIn("FORBIDDEN_CONSTRUCTOR_OR_ATTRIBUTE", reasons)
            if expect_macro_rule:
                self.assertIn("FORBIDDEN_NON_ALLOWLIST_MACRO_DEFINE", reasons)

            bad_spec = AsmKernelSpec(
                kernel_id=f"asm.evil.{label}",
                version="1.0.0",
                abi_version=KINTSUGI_ASM_ABI_VERSION,
                description="Macro/constructor smuggling PoC",
                source_code=src,
                oracle_fn=delim_scan_python,
                exported_symbols=("kintsugi_asm_abi_version",),
                boundary_and_fuzz_cases=(),
                benchmark_payload=b"x",
            )
            with self.assertRaises(ValueError) as ctx_err:
                forge.compile_kernel(bad_spec)
            self.assertIn("STATIC_SAFETY_REJECTED", str(ctx_err.exception))
            self.assertFalse(self.canary.exists())

            f_res = forge.forge_kernel(bad_spec)
            self.assertFalse(f_res.verified)
            self.assertFalse(f_res.safety_ok)
            self.assertFalse(self.canary.exists())

    def test_kh_b3_r1_sec_005_asm_toctou_swap_isolated_dlopen_staging(self) -> None:
        """KH-B3-R1-SEC-005: Binary swap between SHA-256 verify and ctypes.CDLL loads staged A, never B."""
        if not shutil.which("clang"):
            self.skipTest("clang toolchain unavailable")

        forge = AsmNativeForge(self.ws)
        spec_a = build_delim_scan_kernel_spec(fuzz_count=200, benchmark_size_bytes=4096)
        bin_a, man_a, _ = forge.compile_kernel(spec_a)

        # Build a separate rogue dylib B whose constructor writes self.canary
        rogue_dir = self.root / "rogue_dylib"
        rogue_dir.mkdir(parents=True, exist_ok=True)
        rogue_c = rogue_dir / "rogue.c"
        rogue_bin = rogue_dir / ("rogue.dylib" if os.uname().sysname == "Darwin" else "rogue.so")
        rogue_c.write_text(
            "#include <stdio.h>\n"
            "#include <stdint.h>\n"
            f'__attribute__((constructor)) static void rogue_init(void) {{ FILE *f = fopen("{self.canary}", "w"); if (f) {{ fputs("B_LOADED", f); fclose(f); }} }}\n'
            'const char *kintsugi_asm_abi_version(void) { return "KINTSUGI_ASM_ABI_V1"; }\n'
            "uint32_t kintsugi_asm_abi_magic(void) { return 0x4B415331u; }\n"
            'const char *kintsugi_asm_kernel_id(void) { return "asm.delim_scan.v1"; }\n'
            'const char *kintsugi_asm_backend_name(void) { return "rogue_b"; }\n',
            encoding="utf-8",
        )
        comp = subprocess.run(
            ["clang", "-shared", "-fPIC", str(rogue_c), "-o", str(rogue_bin)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(comp.returncode, 0, msg=comp.stderr)
        rogue_bytes = rogue_bin.read_bytes()

        real_cdll = ctypes.CDLL
        observed_cdll_paths: List[Path] = []

        def _toctou_swapping_cdll(path: str, *args: Any, **kwargs: Any) -> Any:
            observed_cdll_paths.append(Path(path).resolve())
            # Simulate attacker overwriting workspace bin_a right before dlopen fires
            os.chmod(bin_a, 0o600)
            bin_a.write_bytes(rogue_bytes)
            os.chmod(bin_a, 0o500)
            return real_cdll(path, *args, **kwargs)

        with mock.patch("kintsugi.forge.asm_native_forge.ctypes.CDLL", side_effect=_toctou_swapping_cdll):
            loaded = forge.load_verified_kernel(
                bin_a,
                expected_sha256=man_a.binary_sha256,
                expected_kernel_id=spec_a.kernel_id,
                expected_abi_version=KINTSUGI_ASM_ABI_VERSION,
            )

        self.assertEqual(len(observed_cdll_paths), 1)
        staged_loaded_path = observed_cdll_paths[0]
        self.assertNotEqual(staged_loaded_path, bin_a.resolve())
        self.assertTrue(staged_loaded_path.is_relative_to(forge._runtime_load_root.resolve()))
        self.assertFalse(self.canary.exists(), msg="TOCTOU swap executed swapped binary B constructor!")
        self.assertEqual(loaded.delim_scan(b"alpha\nbeta\n", 10), [5, 10])

        # Subsequent load against tampered bin_a fails SHA-256 verification before staging
        with self.assertRaises(PermissionError) as err:
            forge.load_verified_kernel(
                bin_a,
                expected_sha256=man_a.binary_sha256,
                expected_kernel_id=spec_a.kernel_id,
                expected_abi_version=KINTSUGI_ASM_ABI_VERSION,
            )
        self.assertIn("ASM_BINARY_SHA256_MISMATCH", str(err.exception))
        self.assertFalse(self.canary.exists())

    def test_kh_b3_r1_sec_004_evolution_v4_strict_bool_and_int_coercion(self) -> None:
        """KH-B3-R1-SEC-004: Reject string/non-bool trial outcomes and non-int counts directly & via MCP."""
        bad_trials = _make_heldout_trials(count=20, with_passed="false", without_passed=False)
        ev4 = EvolutionEngineV4(mode=ExecutionMode.LOCAL_RESEARCH, workspace_root=self.ws)

        with self.assertRaises(ValueError) as direct_err:
            ev4.evaluate_ablation_trials(
                strategy_id="strat.sec004",
                revision=1,
                train_families=["train_0"],
                heldout_families=["heldout_fam_0", "heldout_fam_1", "heldout_fam_2", "heldout_fam_3"],
                trials=bad_trials,
            )
        self.assertIn("INVALID_STRICT_BOOL", str(direct_err.exception))

        base_mcp_args = {
            "workspace_root": str(self.ws),
            "strategy_id": "strat.sec004",
            "revision": 1,
            "train_families": ["train_0"],
            "heldout_families": ["heldout_fam_0", "heldout_fam_1", "heldout_fam_2", "heldout_fam_3"],
            "trials": bad_trials,
        }
        with self.assertRaises(ValueError) as mcp_err:
            dispatch_nextgen_build3_mcp_tool("kintsugi_build3_evolution_v4_ablate", base_mcp_args)
        self.assertIn("INVALID_STRICT_BOOL", str(mcp_err.exception))

        good_trials = _make_heldout_trials(count=20, with_passed=True, without_passed=False)
        for bad_field, bad_val in (
            ("revision", True),
            ("revision", "1"),
            ("extra_baseline_regressions", False),
            ("extra_baseline_regressions", "0"),
        ):
            bad_payload = {
                **base_mcp_args,
                "trials": good_trials,
                bad_field: bad_val,
            }
            with self.assertRaises(ValueError) as int_err:
                dispatch_nextgen_build3_mcp_tool("kintsugi_build3_evolution_v4_ablate", bad_payload)
            self.assertIn("INVALID_STRICT_INT", str(int_err.exception))

        # Positive strict bool/int path passes cleanly
        ok_res = dispatch_nextgen_build3_mcp_tool(
            "kintsugi_build3_evolution_v4_ablate",
            {**base_mcp_args, "trials": good_trials},
        )
        self.assertTrue(ok_res["ok"])
        self.assertEqual(ok_res["total_matched"], 20)

    def test_p2_hermetic_worker_poisoned_posixpath_zero_canary(self) -> None:
        """P2 cond: PosixPath with poisoned `_raw_paths` / `_parts` fails closed with ValueError & 0 canary."""
        worker_file = self.ws / "p2_tool.py"
        worker_file.write_text("def run(_payload): return {'ok': True}\n", encoding="utf-8")
        canary = self.canary

        class _CanaryFspath:
            def __fspath__(self) -> str:
                canary.write_text("POISONED_FSPATH_TRIGGERED", encoding="utf-8")
                return str(worker_file)

            def __str__(self) -> str:
                canary.write_text("POISONED_STR_TRIGGERED", encoding="utf-8")
                return str(worker_file)

        poisoned_path = PosixPath(str(worker_file))
        if hasattr(poisoned_path, "_raw_paths"):
            object.__setattr__(poisoned_path, "_raw_paths", [_CanaryFspath()])
        if hasattr(poisoned_path, "_parts"):
            object.__setattr__(poisoned_path, "_parts", [_CanaryFspath()])

        with self.assertRaises(ValueError):
            HermeticSpawnRunner(allowed_roots=[poisoned_path])
        self.assertFalse(canary.exists(), msg="Poisoned PosixPath triggered canary in HermeticSpawnRunner")

        with self.assertRaises(ValueError):
            HermeticEntrypointSpec(
                tool_id="b3.p2_poisoned",
                module_path="p2_tool",
                callable_attr="run",
                expected_module_file_sha256=_sha256_file(worker_file),
                module_file_path=poisoned_path,
            )
        self.assertFalse(canary.exists(), msg="Poisoned PosixPath triggered canary in HermeticEntrypointSpec")

        # Clean PosixPath continues to work
        clean_path = PosixPath(str(worker_file))
        clean_runner = HermeticSpawnRunner(allowed_roots=[PosixPath(str(self.ws))])
        clean_spec = HermeticEntrypointSpec(
            tool_id="b3.p2_clean",
            module_path="p2_tool",
            callable_attr="run",
            expected_module_file_sha256=_sha256_file(worker_file),
            module_file_path=clean_path,
        )
        self.assertIsNotNone(clean_runner)
        self.assertEqual(clean_spec.module_file_path, str(worker_file))

    def test_kh_b3_r1_sec_007_evolution_v4_semantic_ast_leakage(self) -> None:
        """KH-B3-R1-SEC-007: Whitespace-reformatted & variable-renamed Python snippets raise CorpusLeakageError."""
        train_snippet = (
            "def sanitize_cmd(user_input):\n"
            '    """Train docstring."""\n'
            "    clean_val = user_input.strip()\n"
            "    return os.system(clean_val)\n"
        )
        heldout_equivalent = (
            "def sanitize_cmd(  payload_text  ):\n\n"
            "  raw_arg   =   payload_text.strip()\n"
            "  return   os.system( raw_arg )\n"
        )
        train_fam = {"family_id": "train_alpha", "offending_snippet": train_snippet}
        heldout_fam = {"family_id": "heldout_beta", "offending_snippet": heldout_equivalent}

        with self.assertRaises(CorpusLeakageError):
            verify_disjoint_families([train_fam], [heldout_fam])

        with self.assertRaises(CorpusLeakageError):
            verify_disjoint_families(
                ["train_alpha"],
                ["heldout_beta"],
                train_snippets=[train_snippet],
                heldout_snippets=[heldout_equivalent],
            )

        ev4 = EvolutionEngineV4(mode=ExecutionMode.LOCAL_RESEARCH, workspace_root=self.ws)
        with self.assertRaises(CorpusLeakageError):
            ev4.evaluate_ablation_trials(
                strategy_id="strat.sec007",
                revision=1,
                train_families=[train_fam],
                heldout_families=[heldout_fam],
                trials=[
                    {
                        "family_id": "heldout_beta",
                        "task_id": f"t_{i}",
                        "with_passed": True,
                        "without_passed": False,
                        "tokens_used": 20,
                        "latency_ms": 1.0,
                    }
                    for i in range(6)
                ],
            )

        # Genuinely disjoint semantic snippets pass
        distinct_heldout = {
            "family_id": "heldout_gamma",
            "offending_snippet": (
                "def compute_checksum(items):\n"
                "    acc = 0\n"
                "    for entry in items:\n"
                "        acc ^= len(entry)\n"
                "    return acc\n"
            ),
        }
        tr_ids, ho_ids = verify_disjoint_families([train_fam], [distinct_heldout])
        self.assertEqual(tr_ids, ("train_alpha",))
        self.assertEqual(ho_ids, ("heldout_gamma",))

    def test_arm_c_gate_micro_agents_contract_and_external_gate(self) -> None:
        """Arm C gate: micro AGENTS.md <= 220B & 3 lines; compact <=150-tok feedback via kintsugi-rs."""
        from kintsugi.arm_c_gate import ARM_C_AGENTS_MD, run_arm_c_external_gate

        self.assertEqual(len(ARM_C_AGENTS_MD.splitlines()), 3)
        self.assertLessEqual(len(ARM_C_AGENTS_MD.encode("utf-8")), 220)

        rs_candidates = [
            shutil.which("kintsugi-rs"),
            str(_REPO_ROOT / "target" / "release" / "kintsugi-rs"),
            str(Path.home() / ".local" / "bin" / "kintsugi-rs"),
        ]
        rs_bin = next((c for c in rs_candidates if c and Path(c).is_file()), None)
        if not rs_bin:
            self.skipTest("kintsugi-rs binary unavailable")

        clean_file = self.ws / "clean_module.py"
        clean_file.write_text(
            "def add_numbers(left: int, right: int) -> int:\n"
            "    return left + right\n",
            encoding="utf-8",
        )
        vuln_file = self.ws / "vuln_module.py"
        vuln_file.write_text(
            "import os\n"
            "def run_user_cmd(user_cmd: str) -> int:\n"
            "    return os.system(user_cmd)\n",
            encoding="utf-8",
        )

        sig = inspect.signature(run_arm_c_external_gate)
        params = list(sig.parameters.values())

        def _invoke_gate(target: Path) -> Any:
            kwargs: Dict[str, Any] = {}
            if "rust_bin" in sig.parameters:
                kwargs["rust_bin"] = rs_bin
            elif "kintsugi_rs_bin" in sig.parameters:
                kwargs["kintsugi_rs_bin"] = rs_bin
            elif "binary_path" in sig.parameters:
                kwargs["binary_path"] = rs_bin
            if "workspace_root" in sig.parameters and params and params[0].name != "workspace_root":
                kwargs["workspace_root"] = self.ws
            if params and params[0].name == "workspace_root":
                return run_arm_c_external_gate(self.ws, target, **kwargs)
            return run_arm_c_external_gate(target, **kwargs)

        clean_out = _invoke_gate(clean_file)
        clean_feedback, clean_tokens = _extract_arm_c_feedback(clean_out)
        self.assertEqual(clean_feedback, "")
        self.assertEqual(clean_tokens, 0)

        vuln_out = _invoke_gate(vuln_file)
        vuln_feedback, vuln_tokens = _extract_arm_c_feedback(vuln_out)
        self.assertTrue(vuln_feedback, msg=f"Expected non-empty feedback on vulnerable snippet, got: {vuln_out!r}")
        self.assertLessEqual(vuln_tokens, 150, msg=f"Feedback exceeded 150 tokens ({vuln_tokens}): {vuln_feedback!r}")

    def test_cli_and_mcp_external_authority_key_file_confinement(self) -> None:
        """CLI `--authority-key-file` and MCP `authority_key_file` enforce outside-workspace 0o600 loading."""
        ledger_path = self.ws / ".kintsugi" / "scars.json"
        key_payload = json.dumps({"verifiers": {TEST_VERIFIER_ID: TEST_VERIFIER_KEY.decode("utf-8")}})

        inside_key = self.ws / "inside_keys.json"
        inside_key.write_text(key_payload, encoding="utf-8")
        os.chmod(inside_key, 0o600)

        outside_bad_perm = self.root / "bad_perm_keys.json"
        outside_bad_perm.write_text(key_payload, encoding="utf-8")
        os.chmod(outside_bad_perm, 0o644)

        outside_good = self.root / "good_keys.json"
        outside_good.write_text(key_payload, encoding="utf-8")
        os.chmod(outside_good, 0o600)

        with self.assertRaises(PermissionError):
            KintsugiMCPServer(ledger_path, profile="build3", authority_key_file=inside_key, workspace_root=self.ws)
        with self.assertRaises(PermissionError):
            KintsugiMCPServer(ledger_path, profile="build3", authority_key_file=outside_bad_perm, workspace_root=self.ws)
        with self.assertRaises(ValueError):
            KintsugiMCPServer(
                ledger_path,
                profile="build3",
                attestation_authority=make_fixture_authority(),
                authority_key_file=outside_good,
                workspace_root=self.ws,
            )

        (self.ws / "goal.json").write_text(
            json.dumps(
                {
                    "goal_id": "g-kf",
                    "source_req": {"format": "bytes", "semantic_type": "raw", "unit": "none", "sensitivity": "public"},
                    "target_req": {"format": "json", "semantic_type": "out", "unit": "none", "sensitivity": "public"},
                }
            ),
            encoding="utf-8",
        )
        (self.ws / "plan.json").write_text(
            json.dumps(
                {
                    "plan_id": "p-kf",
                    "goal_contract_hash": sha256_digest("g-kf"),
                    "nodes": [{"node_id": "n1", "tool_id": "t1", "retryable": True}],
                    "edges": [],
                    "input_bindings": {},
                    "tool_artifact_hashes": {},
                    "adapter_hashes": {},
                    "permission_union": [],
                    "effects_union": {},
                    "expected_outputs": [],
                    "oracle_ref": "oracle:kf",
                    "verification_plan": {"mode": "replay"},
                }
            ),
            encoding="utf-8",
        )

        for cmd_args in (
            ["synthesize", "--workspace", str(self.ws), "--goal-file", "goal.json", "--authority-key-file", str(inside_key)],
            ["smt-verify", "--workspace", str(self.ws), "--plan-file", "plan.json", "--authority-key-file", str(outside_bad_perm)],
        ):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(cmd_args)
            self.assertEqual(rc, 1)
            out = json.loads(buf.getvalue())
            self.assertFalse(out["ok"])
            self.assertIn("ATTESTATION_KEY_FILE_", out["error"])


if __name__ == "__main__":
    unittest.main()
