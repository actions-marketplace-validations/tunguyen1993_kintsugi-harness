"""Integration tests for Build #1 CLI, profile-gated MCP, and Demo 1 (Existing Tool Reuse)."""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_tool

import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from kintsugi.capability import SecurityContext, ToolRegistry, ToolSpec, TrustStatus, sha256_digest
from kintsugi.cli import main as cli_main
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.runtime import ExperienceStore, SecureRunner, run_stage1_vertical_slice


class TestBuild1CliAndMcpIntegration(unittest.TestCase):
    def test_cli_config_and_working_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "tests").mkdir()
            (ws / "src" / "helper.py").write_text("def greet(name):\n    return f'hi {name}'\n", encoding="utf-8")
            (ws / "tests" / "test_helper.py").write_text(
                "import unittest\nfrom src.helper import greet\n\nclass T(unittest.TestCase):\n    def test_g(self):\n        self.assertEqual(greet('x'), 'hi x')\n",
                encoding="utf-8",
            )
            (ws / "app.log").write_text("ts=2026-11-22T00:00:00Z level=INFO msg=ok\n", encoding="utf-8")

            buf = io.StringIO()
            old_stdout = __import__("sys").stdout
            try:
                __import__("sys").stdout = buf
                rc = cli_main(["--profile", "LOCAL_RESEARCH", "config", "show", "--workspace", str(ws)])
                self.assertEqual(rc, 0)
                cfg_out = json.loads(buf.getvalue())
                self.assertEqual(cfg_out["profile"], "LOCAL_RESEARCH")
                self.assertIn("config_hash", cfg_out)

                buf.seek(0)
                buf.truncate(0)
                rc_lfg = cli_main(["logforge", "--workspace", str(ws), "--input", "app.log", "--normalize"])
                self.assertEqual(rc_lfg, 0)
                lfg_out = json.loads(buf.getvalue())
                self.assertEqual(lfg_out["offsets"], [len("ts=2026-11-22T00:00:00Z level=INFO msg=ok")])

                buf.seek(0)
                buf.truncate(0)
                rc_rsc = cli_main(
                    [
                        "reposcout",
                        "--workspace",
                        str(ws),
                        "--changed",
                        "src/helper.py",
                        "--symbol",
                        "greet",
                        "--save",
                    ]
                )
                self.assertEqual(rc_rsc, 0)
                rsc_out = json.loads(buf.getvalue())
                self.assertIn("tests/test_helper.py", rsc_out["impact"]["recommended_tests"])
                self.assertGreaterEqual(len(rsc_out["symbols"]), 1)

                buf.seek(0)
                buf.truncate(0)
                rc_slice = cli_main(["tools", "vertical-slice", "--workspace", str(ws)])
                self.assertEqual(rc_slice, 0)
                slice_out = json.loads(buf.getvalue())
                self.assertEqual(slice_out["status"], "PASS")
                self.assertEqual(slice_out["llm_calls"], 0)
            finally:
                __import__("sys").stdout = old_stdout

    def test_mcp_default_9_tools_vs_nextgen_19_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ledger_path = ws / ".kintsugi" / "scars.json"

            default_srv = KintsugiMCPServer(ledger_path)
            r_def = default_srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            self.assertEqual(len(r_def["result"]["tools"]), 9)

            ng_srv = KintsugiMCPServer(ledger_path, profile="nextgen")
            r_ng = ng_srv.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            tools_ng = r_ng["result"]["tools"]
            self.assertEqual(len(tools_ng), 19)
            tool_names = {t["name"] for t in tools_ng}
            self.assertTrue(
                {
                    "kintsugi_tools_discover",
                    "kintsugi_capability_analyze",
                    "kintsugi_reposcout_impact",
                    "kintsugi_logforge_scan",
                    "kintsugi_composition_plan",
                    "kintsugi_composition_verify",
                    "kintsugi_run_status",
                    "kintsugi_self_model_inspect",
                    "kintsugi_tracedoctor_analyze",
                    "kintsugi_proofpack_verify",
                }.issubset(tool_names)
            )
            for t in tools_ng:
                self.assertTrue(isinstance(t["annotations"]["readOnlyHint"], bool))

            call_lfg = ng_srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "kintsugi_logforge_scan",
                        "arguments": {"text": "a\nb\n", "delim": 10},
                    },
                }
            )
            payload = json.loads(call_lfg["result"]["content"][0]["text"])
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["result"]["offsets"], [1, 3])

            call_cap = ng_srv.handle_request(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "kintsugi_capability_analyze",
                        "arguments": {"workspace_root": str(ws), "required_capabilities": ["missing.cap"]},
                    },
                }
            )
            cap_payload = json.loads(call_cap["result"]["content"][0]["text"])
            self.assertFalse(cap_payload["ok"])
            self.assertEqual(cap_payload["capability_gap"]["missing_capabilities"], ["missing.cap"])

    def test_demo1_existing_tool_reuse_clang_asan_and_experience_reuse(self) -> None:
        clang_path = shutil.which("clang")
        if not clang_path:
            self.skipTest("clang not available on host")
        clang_real = Path(clang_path).resolve()
        clang_digest = f"sha256:{hashlib.sha256(clang_real.read_bytes()).hexdigest()}"

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            buggy_c = ws / "bug.c"
            buggy_c.write_text(
                "#include <stdlib.h>\n"
                "int main(int argc, char **argv) {\n"
                "    char *p = (char *)malloc(4);\n"
                "    int idx = argc + 3;\n"
                "    p[idx] = 'x';\n"
                "    char v = p[idx];\n"
                "    free(p);\n"
                "    return (int)v;\n"
                "}\n",
                encoding="utf-8",
            )
            buggy2_c = ws / "bug2.c"
            buggy2_c.write_text(
                "#include <stdlib.h>\n"
                "int main(int argc, char **argv) {\n"
                "    int *a = (int *)malloc(2 * sizeof(int));\n"
                "    int v = a[argc + 2];\n"
                "    free(a);\n"
                "    return v;\n"
                "}\n",
                encoding="utf-8",
            )

            sec_ctx = SecurityContext(
                workspace_root=str(ws),
                profile="LOCAL_RESEARCH",
                allowed_permissions=["compile_c", "run_asan"],
                network_allowed=False,
                allow_untrusted_native=False,
            )
            registry = ToolRegistry()
            runner = SecureRunner(
                trusted_tool_roots=(clang_real.parent,),
                allow_trusted_host_callables=True,
                attestation_authority=registry.authority,
            )

            def _run_asan_probe(task_args: dict) -> dict:
                return _run_asan_compile_and_probe(clang_real, ws, str(task_args["source_file"]))

            callable_hash = runner.register_trusted_host_callable("local.clang-asan", _run_asan_probe)
            tool_spec = ToolSpec(
                tool_id="local.clang-asan",
                version="1.0.0",
                source="host_trusted",
                binary_hash=callable_hash,
                capabilities=["c.memory_error_check"],
                input_schema={"type": "object", "required": ["source_file"]},
                output_schema={"type": "object", "required": ["asan_detected"]},
                semantic_contract={"output_semantics": "memory_error_verdict"},
                preconditions=["c_source_in_workspace"],
                postconditions=["asan_artifact_or_verdict"],
                side_effects=[],
                required_permissions=["compile_c", "run_asan"],
                runtime_requirements={"platform": ["darwin-arm64", "linux-x86_64"], "network": False},
                trust_status=TrustStatus.VERIFIED,
                latency_estimate_ms=250.0,
                memory_estimate_mb=128.0,
                api_token_estimate=0,
                verification_attestation={
                    "verifier_id": "demo1_harness",
                    "verification_digest": sha256_digest({"tool_id": "local.clang-asan", "binary_hash": callable_hash}),
                    "binary_hash": callable_hash,
                    "tool_id": "local.clang-asan",
                    "source": "demo1_trusted_verifier",
                },
                provenance={"origin": "local_toolchain", "verified_by": "demo1_harness"},
            )
            sign_fixture_tool(registry, tool_spec)
            exp_store = ExperienceStore(ws / ".kintsugi" / "experience_store.json")

            def asan_oracle(exec_summary: object, _tool: object, _args: dict) -> bool:
                payload = exec_summary.get("output") if isinstance(exec_summary, dict) else None
                return isinstance(payload, dict) and bool(payload.get("asan_detected"))

            # First task: cold discovery + resolve + ASan verification + store experience
            r1 = run_stage1_vertical_slice(
                {
                    "task_id": "demo1-asan-a",
                    "intent": "Detect heap buffer overflow in C fixture",
                    "capability": "c.memory_error_check",
                    "task_fingerprint": sha256_digest("c.memory_error_check:heap_oob"),
                    "args": {"source_file": "bug.c"},
                },
                security_context=sec_ctx,
                registry=registry,
                runner=runner,
                experience_store=exp_store,
                oracle=asan_oracle,
            )
            self.assertEqual(r1.status, "PASS")
            self.assertEqual(r1.llm_calls, 0)
            self.assertFalse(r1.reuse_hit)

            # Second task: different C source, same capability -> hits ExperienceStore & skips cold gap discovery
            r2 = run_stage1_vertical_slice(
                {
                    "task_id": "demo1-asan-b",
                    "intent": "Detect heap buffer overflow in C fixture 2",
                    "capability": "c.memory_error_check",
                    "task_fingerprint": sha256_digest("c.memory_error_check:heap_oob"),
                    "args": {"source_file": "bug2.c"},
                },
                security_context=sec_ctx,
                registry=registry,
                runner=runner,
                experience_store=exp_store,
                oracle=asan_oracle,
            )
            self.assertEqual(r2.status, "PASS")
            self.assertEqual(r2.llm_calls, 0)
            self.assertTrue(r2.reuse_hit)
            self.assertTrue(r2.telemetry["skipped_gap_discovery"])
            self.assertGreaterEqual(r2.reuse_count, 1)
            self.assertLess(r1.reuse_count, r2.reuse_count)


def _run_asan_compile_and_probe(clang_bin: Path, ws: Path, rel_src: str) -> dict:
    src = (ws / rel_src).resolve()
    out_bin = (ws / "asan_probe_bin").resolve()
    subprocess.run(
        [str(clang_bin), "-fsanitize=address", "-g", "-O0", str(src), "-o", str(out_bin)],
        cwd=str(ws),
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TMPDIR": str(ws)},
    )
    proc = subprocess.run(
        [str(out_bin)],
        cwd=str(ws),
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ASAN_OPTIONS": "detect_leaks=0"},
        timeout=10,
    )
    combined = proc.stdout + "\n" + proc.stderr
    return {
        "exit_code": proc.returncode,
        "asan_detected": proc.returncode != 0 and "AddressSanitizer" in combined,
        "summary": combined.splitlines()[:6],
    }


if __name__ == "__main__":
    unittest.main()
