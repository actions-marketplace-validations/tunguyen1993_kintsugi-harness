# kintsugi: ignore-file
"""Zero-dependency unit & integration test suite compatible with both `unittest` and `pytest`."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from kintsugi.auditor import run_posture_audit
from kintsugi.autofix import run_autofix
from kintsugi.cli import main as cli_main
from kintsugi.cognition import (
    CognitiveLesson,
    CognitiveMemoryManager,
    ModelTier,
    SyncMode,
    get_seed_frontier_lessons,
    verify_frontier_sync_gate,
)
from kintsugi.compiler import BOUNDARY_END, BOUNDARY_START, SkillCompiler
from kintsugi.compressor import compute_token_savings_report, render_kmi_index
from kintsugi.council import AgentEndpoint, EvolutionCouncil, _extract_json_object, verify_candidate_scar
from kintsugi.hooks import evaluate_claude_pre_tool_payload, install_claude_settings_hook
from kintsugi.ledger import ScarLedger
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.models import FailureTrace, GoldenScar, Severity
from kintsugi.packs import install_skill_pack, list_installed_packs
from kintsugi.scanner import (
    KintsugiScanner,
    parse_git_diff_text,
    render_patch_preview,
    report_to_sarif,
)
from kintsugi.starter_pack import get_starter_scars


class TestStarterPackSelfVerification(unittest.TestCase):
    """Every built-in scar MUST catch its bad_code and return 0 findings on its good_code."""

    def test_all_starter_scars_pass_deterministic_self_check(self) -> None:
        scars = get_starter_scars()
        self.assertGreaterEqual(len(scars), 16)
        for scar in scars:
            with self.subTest(scar_id=scar.id):
                ok, message = verify_candidate_scar(scar)
                self.assertTrue(ok, f"{scar.id} failed self-check: {message}")


class TestASTRegexAndDiffScanner(unittest.TestCase):
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

    def test_git_diff_hunk_filtering_and_patch_preview(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "service.py"
            target.write_text(
                "def old_fn(a=[]):\n    return a\n\nimport pickle\npickle.loads(raw)\n",
                encoding="utf-8",
            )
            diff_sample = (
                "--- a/service.py\n"
                "+++ b/service.py\n"
                "@@ -4,0 +4,2 @@\n"
                "+import pickle\n"
                "+pickle.loads(raw)\n"
            )
            changed_map = parse_git_diff_text(diff_sample, root)
            self.assertIn(target.resolve(), changed_map)
            self.assertEqual(changed_map[target.resolve()], {4, 5})

            scanner = KintsugiScanner(get_starter_scars())
            findings = scanner.scan_text(
                target.read_text(encoding="utf-8"),
                file_path=str(target),
                allowed_lines=changed_map[target.resolve()],
            )
            # Line 1 mutable default is outside the diff hunk and MUST be ignored; Line 5 KS-006 is caught!
            self.assertEqual([f.scar_id for f in findings], ["KS-006"])
            preview = render_patch_preview(findings[0])
            self.assertIn("--- a/", preview)
            self.assertIn("+++ b/", preview)
            self.assertIn("-pickle.loads(raw)", preview)

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


class TestScarLedgerCompilerAndPackager(unittest.TestCase):
    def test_ledger_deduplicates_identical_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = ScarLedger(Path(tmp) / ".kintsugi" / "scars.json")
            added = ledger.bootstrap_starter_pack()
            self.assertEqual(added, 16)
            self.assertEqual(ledger.bootstrap_starter_pack(), 0)
            self.assertEqual(len(ledger.all()), 16)

    def test_compiler_supports_all_six_agent_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            claude_md = tmp_path / "CLAUDE.md"
            claude_md.write_text("# Project Guide\n\nHuman architecture notes.\n", encoding="utf-8")

            compiler = SkillCompiler(get_starter_scars())
            written = compiler.compile_all(tmp_path, targets=["all"])
            self.assertIn(claude_md, written)

            compiled_text = claude_md.read_text(encoding="utf-8")
            self.assertIn("Human architecture notes.", compiled_text)
            self.assertEqual(compiled_text.count(BOUNDARY_START), 1)
            self.assertEqual(compiled_text.count(BOUNDARY_END), 1)

            self.assertTrue((tmp_path / ".claude" / "skills" / "kintsugi-guardrails" / "SKILL.md").exists())
            self.assertTrue((tmp_path / ".cursor" / "rules" / "kintsugi-guardrails.mdc").exists())
            self.assertTrue(
                (tmp_path / ".github" / "instructions" / "kintsugi-guardrails.instructions.md").exists()
            )
            self.assertTrue((tmp_path / ".windsurfrules").exists())

    def test_kmi_token_compression_and_pack_installer_autofix(self) -> None:
        scars = get_starter_scars()
        compiler = SkillCompiler(scars)
        verbose_md = compiler.render_skill_markdown("kintsugi-guardrails", "desc", scars)
        stats = compute_token_savings_report(scars, verbose_md, turns_per_session=50)
        self.assertGreaterEqual(stats["reduction_percent"], 90.0)
        self.assertIn("KMI/1;pack=core@", render_kmi_index(scars))

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ledger_file = ws / ".kintsugi" / "scars.json"
            pack_json = ws / "sample-pro-pack.json"
            pack_json.write_text(
                json.dumps(
                    {
                        "name": "sample-pro-pack",
                        "title": "Sample Pro Pack",
                        "version": "0.3.0",
                        "tier": "premium",
                        "scars": [],
                        "autofix_playbooks": [
                            {
                                "scar_id": "KS-003",
                                "description": "Disable shell=True in subprocess calls",
                                "search_regex": r"shell\s*=\s*True",
                                "replace_expr": "shell=False",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            info = install_skill_pack(pack_json, workspace_root=ws, ledger_path=ledger_file)
            self.assertEqual(info["pack_id"], "sample-pro-pack")
            self.assertEqual(len(list_installed_packs(ws)), 1)

            bad_file = ws / "runner.py"
            bad_file.write_text('import subprocess\nsubprocess.run(["ls"], shell=True, check=True)\n', encoding="utf-8")
            fix_res = run_autofix(bad_file, scars, workspace_root=ws, apply_changes=True)
            self.assertEqual(fix_res["applied_fixes"], 1)
            self.assertIn("shell=False", bad_file.read_text(encoding="utf-8"))

            compiler.compile_all(ws, targets=["all"])
            audit = run_posture_audit(ws, scars)
            self.assertEqual(audit["grade"], "A+")
            self.assertEqual(audit["score"], 100)


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
    def test_extract_json_handles_template_literal_braces_in_prose(self) -> None:
        prose = 'Analysis of `exec(`convert ${userFile} out.png`)`:\n{"title": "Test", "bad_code": "x"}'
        obj = _extract_json_object(prose)
        self.assertEqual(obj["title"], "Test")

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
                        },
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
            self.assertEqual(cli_main(["explain", "KS-003", "--ledger", str(ledger_path)]), 0)
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


class TestFederatedCognitiveLearning(unittest.TestCase):
    def test_frontier_gate_blocks_low_tier_models_and_deduplicates_frontier_lessons(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            mgr = CognitiveMemoryManager(ws)

            # 1. Default mode is local-only: lesson stays strictly in lessons_local.json
            frontier_lesson = get_seed_frontier_lessons()[0]
            r_local = mgr.record_lesson(frontier_lesson)
            self.assertEqual(r_local["pool_sync_status"], "SKIPPED_LOCAL_ONLY_MODE")
            self.assertEqual(len(mgr.load_pool_lessons()), 0)
            self.assertEqual(len(mgr.load_local_lessons()), 1)

            # 2. Switch to federated-sync mode
            mgr.save_config(sync_mode=SyncMode.FEDERATED_SYNC.value)

            # 3. Low-tier model (e.g. gpt-4o-mini / flash-lite / haiku) MUST be rejected by Frontier Gate
            low_tier_lesson = CognitiveLesson(
                id="KL-LOW-001",
                title="Avoid yaml.load without SafeLoader",
                domain="security-zerotrust",
                severity=Severity.CRITICAL,
                languages=["python"],
                tags=["yaml", "security"],
                cognitive_trap="Used yaml.load on untrusted input.",
                mental_model="Always use yaml.safe_load.",
                bad_code="import yaml\nyaml.load(raw)",
                good_code="import yaml\nyaml.safe_load(raw)",
                regex_pattern=r"\byaml\.load\s*\(",
                synthesized_by_model="gpt-4o-mini",
            )
            self.assertEqual(low_tier_lesson.model_tier, ModelTier.TIER_3_LOW)
            r_low = mgr.record_lesson(low_tier_lesson)
            self.assertEqual(r_low["pool_sync_status"], "BLOCKED_BY_FRONTIER_GATE")
            self.assertIn("REJECTED_LOW_TIER_MODEL", r_low["reason"])
            self.assertEqual(len(mgr.load_pool_lessons()), 0)

            # 4. Tier-1 Frontier model (deepseek-r1-0528) passes 4-Stage Gate and publishes to pool
            r_pub = mgr.record_lesson(frontier_lesson)
            self.assertEqual(r_pub["pool_sync_status"], "PUBLISHED_TO_COLLECTIVE_POOL")
            self.assertEqual(len(mgr.load_pool_lessons()), 1)

            # 5. Another Frontier model (claude-opus-4) submits duplicate lesson -> reinforces existing instead of duplicating
            dup_lesson = CognitiveLesson(
                id="KL-MCP-999",
                title=frontier_lesson.title,
                domain=frontier_lesson.domain,
                severity=frontier_lesson.severity,
                languages=frontier_lesson.languages,
                tags=frontier_lesson.tags,
                cognitive_trap=frontier_lesson.cognitive_trap,
                mental_model=frontier_lesson.mental_model,
                bad_code=frontier_lesson.bad_code,
                good_code=frontier_lesson.good_code,
                regex_pattern=frontier_lesson.regex_pattern,
                synthesized_by_model="claude-opus-4",
            )
            r_dup = mgr.record_lesson(dup_lesson)
            self.assertEqual(r_dup["pool_sync_status"], "BLOCKED_BY_FRONTIER_GATE")
            self.assertIn("DUPLICATE_", r_dup["reason"])
            pool_after = mgr.load_pool_lessons()
            self.assertEqual(len(pool_after), 1)
            self.assertIn("claude-opus-4", pool_after[0].endorsed_by_models)

            # 6. Test selective domain pull into a clean local-only workspace
            with tempfile.TemporaryDirectory() as tmp2:
                ws2 = Path(tmp2)
                mgr2 = CognitiveMemoryManager(ws2, pool_root=mgr.pool_root)
                pull_res = mgr2.pull_lessons_by_domain(["ai-agents-mcp"])
                self.assertEqual(pull_res["newly_merged_to_local"], 1)
                self.assertEqual(len(mgr2.load_local_lessons()), 1)

    def test_real_life_domains_and_35_seed_frontier_lessons_pass_verification(self) -> None:
        seeds = get_seed_frontier_lessons()
        self.assertEqual(len(seeds), 35)
        pillars = {s.domain_pillar for s in seeds}
        self.assertEqual(pillars, {"engineering", "life-and-business"})
        for lesson in seeds:
            ok, msg, _ = verify_frontier_sync_gate(lesson, ())
            self.assertTrue(ok, f"{lesson.id} failed gate: {msg}")

    def test_ast_symbol_grounding_gate_verifies_real_and_refutes_hallucinated_symbols(self) -> None:
        from kintsugi.grounding import RepoAstGroundingEngine

        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "vault.py"
            sample.write_text(
                "def withdraw_assets(user_record, request_json):\n"
                "    user_record.update(request_json)\n"
                "    return user_record\n",
                encoding="utf-8",
            )
            engine = RepoAstGroundingEngine(tmp)
            self.assertGreaterEqual(engine.summary()["seams_detected"], 1)

            v_ok = engine.verify_hypothesis({"anchor": "vault.py:2", "symbols": ["withdraw_assets", "user_record"]})
            self.assertEqual(v_ok["status"], "VERIFIED")

            v_kw = engine.verify_hypothesis({"anchor": "vault.py:2", "symbols": ["def", "return"]})
            self.assertEqual(v_kw["status"], "REFUTED")

            v_hallucinated = engine.verify_hypothesis({"anchor": "vault.py:2", "symbols": ["non_existent_fn"]})
            self.assertEqual(v_hallucinated["status"], "REFUTED")

    def test_zero_github_account_relay_and_github_skill_harvester(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            mgr = CognitiveMemoryManager(ws)

            # 1. Agent without GitHub account pushes a real-life finance-capital lesson to Zero-Auth Relay
            life_lesson = [l for l in get_seed_frontier_lessons() if l.id == "KL-CAP-001"][0]
            relay_res = mgr.push_to_zero_auth_relay(life_lesson, network_send=False)
            self.assertTrue(relay_res["relay_pushed"])
            self.assertEqual(relay_res["protocol"], "KINTSUGI-RELAY/1")

            # 2. Sync from relay ingests and verifies the lesson into collective-pool/
            sync_res = mgr.sync_from_zero_auth_relay(fetch_network=False)
            self.assertEqual(sync_res["newly_accepted_to_pool"], 1)
            self.assertEqual(len(mgr.load_pool_lessons(domains=["finance-capital"])), 1)

            # 3. Autonomous GitHub Skill Harvester scans and adds the 8 GitHub-sourced skills
            harv_res = mgr.harvest_github_skill_repos(fetch_live_github=False)
            self.assertEqual(harv_res["sources_scanned"], 8)
            self.assertEqual(harv_res["newly_added_to_pool"], 8)
            self.assertEqual(harv_res["collective_pool_total"], 9)

    def test_autopoietic_metacognition_and_3_horizon_causal_foresight(self) -> None:
        from kintsugi.foresight import (
            AutopoieticSynthesizer,
            CausalForesightEngine,
            MetacognitiveSelfModel,
        )

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            app_file = ws / "service.py"
            app_file.write_text(
                "def update_account(user_record, payload):\n"
                "    user_record.update(payload)\n"
                "    return user_record\n\n"
                "def handle_request(user_record, payload):\n"
                "    return update_account(user_record, payload)\n",
                encoding="utf-8",
            )

            # 1. Metacognitive Self-Awareness
            meta = MetacognitiveSelfModel(ws)
            st = meta.record_outcome("security-zerotrust", succeeded=True, predicted_prob=0.9)
            self.assertGreater(st.competence, 0.65)
            meta_rep = meta.build_self_awareness_report()
            self.assertIn("@META/1|", meta_rep["kmi_metacognitive_wire"])

            # 2. Autopoietic Self-Generation
            synth = AutopoieticSynthesizer(ws)
            gen_res = synth.synthesize_from_target(ws)
            self.assertEqual(gen_res["newly_synthesized_count"], 1)
            self.assertEqual(gen_res["synthesized_lessons"][0]["seam_kind"], "PRIVILEGE_DICT_MERGE_SEAM")

            # 3. 3-Horizon Causal Foresight (T+1, T+2, T+3) + Proactive Action Queue
            forecaster = CausalForesightEngine(ws)
            f_rep = forecaster.forecast(ws)
            self.assertGreaterEqual(f_rep["horizons_summary"]["T+1_immediate_count"], 1)
            self.assertGreaterEqual(f_rep["horizons_summary"]["T+2_cascade_count"], 1)
            self.assertGreaterEqual(f_rep["horizons_summary"]["T+3_tail_risk_count"], 1)
            self.assertIn("@FORESIGHT/1|", f_rep["kmi_foresight_wire"])
            self.assertGreaterEqual(len(f_rep["proactive_action_queue"]), 2)
            top_act = f_rep["proactive_action_queue"][0]
            self.assertIn("what_will_happen", top_act)
            self.assertIn("what_to_do_now", top_act)


if __name__ == "__main__":
    unittest.main()
