"""Zero-dependency unit & integration test suite compatible with both `unittest` and `pytest`."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path

from kintsugi.cli import main as cli_main
from kintsugi.compiler import BOUNDARY_END, BOUNDARY_START, SkillCompiler
from kintsugi.council import AgentEndpoint, EvolutionCouncil, verify_candidate_scar
from kintsugi.hooks import evaluate_claude_pre_tool_payload, install_claude_settings_hook
from kintsugi.ledger import ScarLedger
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.models import FailureTrace, GoldenScar, Severity
from kintsugi.scanner import KintsugiScanner, report_to_sarif
from kintsugi.starter_pack import get_starter_scars


class TestStarterPackSelfVerification(unittest.TestCase):
    """Every built-in scar MUST catch its bad_code and return 0 findings on its good_code."""

    def test_all_starter_scars_pass_deterministic_self_check(self) -> None:
        scars = get_starter_scars()
        self.assertGreaterEqual(len(scars), 12)
        for scar in scars:
            with self.subTest(scar_id=scar.id):
                ok, message = verify_candidate_scar(scar)
                self.assertTrue(ok, f"{scar.id} failed self-check: {message}")


class TestASTAndRegexScanner(unittest.TestCase):
    def test_python_ast_catches_mutable_default_and_respects_pragma(self) -> None:
        scanner = KintsugiScanner(get_starter_scars())
        bad_src = "def collect(x, acc=[]):\n    acc.append(x)\n    return acc\n"
        findings = scanner.scan_text(bad_src, file_path="mod.py")
        self.assertTrue(any(f.scar_id == "KS-004" for f in findings))

        suppressed_src = "def collect(x, acc=[]):  # kintsugi: ignore[KS-004]\n    return acc\n"
        self.assertEqual(scanner.scan_text(suppressed_src, file_path="mod.py"), [])

    def test_python_ast_catches_missing_http_timeout(self) -> None:
        scanner = KintsugiScanner(get_starter_scars())
        bad = 'import requests\nresp = requests.get("https://api.example.com/v1")\n'
        good = 'import requests\nresp = requests.get("https://api.example.com/v1", timeout=5)\n'
        self.assertTrue(any(f.scar_id == "KS-008" for f in scanner.scan_text(bad, file_path="client.py")))
        self.assertEqual(scanner.scan_text(good, file_path="client.py"), [])

    def test_extensible_council_ast_rules(self) -> None:
        custom = GoldenScar(
            id="KS-801",
            title="Require encoding keyword on Path.read_text",
            severity=Severity.MEDIUM,
            category="portability",
            languages=["python"],
            tags=["encoding", "windows"],
            root_cause="Omitting encoding='utf-8' defaults to locale cp1252 on Windows.",
            bad_code='data = Path("README.md").read_text()',
            good_code='data = Path("README.md").read_text(encoding="utf-8")',
            rationale="Guarantees deterministic UTF-8 file decoding across OSes.",
            ast_rule="missing_kwarg:read_text:encoding",
        )
        ok, msg = verify_candidate_scar(custom)
        self.assertTrue(ok, msg)

    def test_sarif_export_valid_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.py"
            sample.write_text("import pickle\npickle.loads(buf)\n", encoding="utf-8")
            scars = get_starter_scars()
            scanner = KintsugiScanner(scars)
            report = scanner.scan_path(sample)
            sarif = report_to_sarif(report, scars)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "KS-006")


class TestScarLedgerAndSkillCompiler(unittest.TestCase):
    def test_ledger_deduplicates_identical_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = ScarLedger(Path(tmp) / ".kintsugi" / "scars.json")
            added = ledger.bootstrap_starter_pack()
            self.assertEqual(added, 12)
            self.assertEqual(ledger.bootstrap_starter_pack(), 0)
            self.assertEqual(len(ledger.all()), 12)

    def test_compiler_preserves_human_sections_in_claude_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            claude_md = tmp_path / "CLAUDE.md"
            claude_md.write_text("# Project Guide\n\nHuman architecture notes.\n", encoding="utf-8")

            compiler = SkillCompiler(get_starter_scars())
            written = compiler.compile_all(tmp_path)
            self.assertIn(claude_md, written)

            compiled_text = claude_md.read_text(encoding="utf-8")
            self.assertIn("Human architecture notes.", compiled_text)
            self.assertEqual(compiled_text.count(BOUNDARY_START), 1)
            self.assertEqual(compiled_text.count(BOUNDARY_END), 1)

            compiler.compile_all(tmp_path)
            recompiled_text = claude_md.read_text(encoding="utf-8")
            self.assertEqual(recompiled_text.count(BOUNDARY_START), 1)
            self.assertTrue((tmp_path / ".claude" / "skills" / "kintsugi-guardrails" / "SKILL.md").exists())
            self.assertTrue((tmp_path / ".cursor" / "rules" / "kintsugi-guardrails.mdc").exists())


class TestClaudeCodePreToolHooks(unittest.TestCase):
    def test_blocks_destructive_bash_command(self) -> None:
        payload = {
            "tool_name": "Bash",
            "tool_input": {"command": "git reset --hard HEAD~2"},
        }
        res = evaluate_claude_pre_tool_payload(payload, get_starter_scars())
        out = res["hookSpecificOutput"]
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("KS-002", out["permissionDecisionReason"])

    def test_allows_safe_file_write(self) -> None:
        payload = {
            "tool_name": "Write",
            "tool_input": {
                "file_path": "service.py",
                "content": "def add(a: int, b: int) -> int:\n    return a + b\n",
            },
        }
        res = evaluate_claude_pre_tool_payload(payload, get_starter_scars())
        self.assertEqual(res["hookSpecificOutput"]["permissionDecision"], "allow")

    def test_settings_installer_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            p1 = install_claude_settings_hook(tmp_path)
            p2 = install_claude_settings_hook(tmp_path)
            self.assertEqual(p1, p2)
            cfg = json.loads(p1.read_text(encoding="utf-8"))
            self.assertEqual(len(cfg["hooks"]["PreToolUse"]), 1)


class TestThreeAgentCouncilAndMCP(unittest.TestCase):
    def test_council_self_heals_when_first_regex_has_false_positive(self) -> None:
        endpoints = [
            AgentEndpoint("architect", "gemini-pro", "https://example.invalid/v1", "k1"),
            AgentEndpoint("synthesizer", "deepseek-r1", "https://example.invalid/v1", "k2"),
            AgentEndpoint("critic", "muse-critic", "https://example.invalid/v1", "k3"),
        ]
        call_counter = {"critic": 0}

        def fake_complete(ep: AgentEndpoint, sys_p: str, usr_p: str) -> str:
            if ep.role == "architect":
                return "Avoid console.log debugging in TypeScript handlers; use structured logger."
            if ep.role == "synthesizer":
                return "{}"
            call_counter["critic"] += 1
            if call_counter["critic"] == 1:
                return json.dumps(
                    {
                        "title": "Avoid raw console.log",
                        "severity": "MEDIUM",
                        "category": "observability",
                        "languages": ["typescript"],
                        "tags": ["logging"],
                        "root_cause": "Unstructured stdout logging",
                        "bad_code": "console.log(req.body);",
                        "good_code": "logger.info({ body: req.body }); // replaces console.log",
                        "rationale": "Use structured JSON logger",
                        "regex_pattern": r"console\.log",
                        "ast_rule": None,
                    }
                )
            return json.dumps(
                {
                    "title": "Avoid raw console.log call",
                    "severity": "MEDIUM",
                    "category": "observability",
                    "languages": ["typescript"],
                    "tags": ["logging"],
                    "root_cause": "Unstructured stdout logging",
                    "bad_code": "console.log(req.body);",
                    "good_code": "logger.info({ body: req.body });",
                    "rationale": "Use structured JSON logger",
                    "regex_pattern": r"\bconsole\.log\s*\(",
                    "ast_rule": None,
                }
            )

        council = EvolutionCouncil(endpoints=endpoints, completion_fn=fake_complete)
        trace = FailureTrace(
            source="ci",
            error_summary="Raw console.log leaked PII in TypeScript handler",
            raw_trace="console.log(req.body)",
            language="typescript",
        )
        scar, msg = council.evolve(trace, scar_id="KS-050")
        self.assertEqual(call_counter["critic"], 2)
        self.assertEqual(scar.id, "KS-050")
        self.assertIn("PASS", msg)

    def test_offline_evolve_yaml_load(self) -> None:
        council = EvolutionCouncil(endpoints=[])
        trace = FailureTrace(
            source="pytest",
            error_summary="Unsafe yaml.load detected",
            raw_trace="cfg = yaml.load(stream)",
            language="python",
        )
        scar, msg = council.evolve(trace, scar_id="KS-099")
        self.assertEqual(scar.id, "KS-099")
        self.assertIn("PASS", msg)

    def test_mcp_stdio_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger_file = Path(tmp) / ".kintsugi" / "scars.json"
            server = KintsugiMCPServer(ledger_file)
            requests_stream = "\n".join(
                [
                    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 3,
                            "method": "tools/call",
                            "params": {
                                "name": "kintsugi_scan_code",
                                "arguments": {
                                    "code": "eval(user_input)",
                                    "file_path": "handler.py",
                                },
                            },
                        }
                    ),
                ]
            )
            out_buf = io.StringIO()
            server.serve_stdio(stdin=io.StringIO(requests_stream + "\n"), stdout=out_buf)
            responses = [json.loads(line) for line in out_buf.getvalue().splitlines()]
            self.assertEqual(len(responses), 3)
            self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "kintsugi-harness")
            self.assertEqual(len(responses[1]["result"]["tools"]), 4)
            scan_payload = json.loads(responses[2]["result"]["content"][0]["text"])
            self.assertFalse(scan_payload["passed"])
            self.assertEqual(scan_payload["findings"][0]["scar_id"], "KS-006")


class TestCLIDogfooding(unittest.TestCase):
    def test_kintsugi_scans_its_own_source_code_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_src = Path(__file__).resolve().parent.parent / "src"
            ledger_path = tmp_path / "scars.json"
            self.assertEqual(
                cli_main(["init", "--workspace", str(tmp_path), "--ledger", str(ledger_path)]),
                0,
            )
            self.assertEqual(cli_main(["verify-ledger", "--ledger", str(ledger_path)]), 0)
            self.assertEqual(
                cli_main(
                    [
                        "scan",
                        str(repo_src),
                        "--ledger",
                        str(ledger_path),
                        "--fail-on",
                        "LOW",
                    ]
                ),
                0,
            )


if __name__ == "__main__":
    unittest.main()
