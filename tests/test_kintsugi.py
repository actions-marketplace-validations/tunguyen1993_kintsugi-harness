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

    def test_real_life_domains_and_38_seed_frontier_lessons_pass_verification(self) -> None:
        seeds = get_seed_frontier_lessons()
        self.assertEqual(len(seeds), 41)
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

    def test_scientific_laws_grounding_autopoiesis_and_foresight(self) -> None:
        from kintsugi.foresight import AutopoieticSynthesizer, CausalForesightEngine
        from kintsugi.grounding import RepoAstGroundingEngine

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            sim_file = ws / "sim.py"
            sim_file.write_text(
                '"""Docstring mentioning math.sin(tilt_deg) and Thermodynamics that must be ignored."""\n'
                "import math\n\n"
                "def step_euler(x_pos, v_vel, accel, dt_sec):\n"
                "    x_next = x_pos + v_vel * dt_sec + 0.0 * accel  # NON_SYMPLECTIC_EULER_DRIFT\n"
                "    return x_next\n\n"
                "def add_incompatible_units(pressure_pa, velocity_ms, tilt_deg):\n"
                "    raw = pressure_pa + velocity_ms  # DIMENSIONAL_UNIT_MISMATCH\n"
                "    return raw * math.sin(tilt_deg)\n",
                encoding="utf-8",
            )
            eng = RepoAstGroundingEngine(ws)
            # Docstring word 'Thermodynamics' must NOT pollute AST variables
            self.assertEqual(
                eng.verify_hypothesis({"anchor": "sim.py:5", "symbols": ["Thermodynamics"]})["status"],
                "REFUTED",
            )
            self.assertEqual(
                eng.verify_hypothesis({"anchor": "sim.py:5", "symbols": ["step_euler", "x_next"]})["status"],
                "VERIFIED",
            )
            synth = AutopoieticSynthesizer(ws)
            gen = synth.synthesize_from_target(ws)
            self.assertEqual(gen["newly_synthesized_count"], 2)
            f_rep = CausalForesightEngine(ws).forecast(ws)
            self.assertGreaterEqual(f_rep["horizons_summary"]["T+1_immediate_count"], 2)

            # 4. Pillar 4: Analogical Transfer & Counterfactual Sandbox Dreamer
            from kintsugi.foresight import AnalogicalTransferEngine, CounterfactualDreamSimulator

            tr = AnalogicalTransferEngine().transfer_from_target(ws)
            self.assertEqual(tr["analogical_transfers_count"], 2)
            dream = CounterfactualDreamSimulator(ws).simulate_dream(ws)
            self.assertTrue(dream["no_disk_mutation"])
            self.assertTrue(dream["counterfactual_verified"])
            self.assertLess(dream["causal_deltas"]["delta_seams"], 0)
            self.assertIn("@DREAM/1|", dream["kmi_dream_wire"])

    def test_shadow_clone_swarm_parallel_learning_and_bft_merge(self) -> None:
        from kintsugi.swarm import ShadowCloneSwarmOrchestrator

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            target_file = ws / "unfamiliar_module.py"
            target_file.write_text(
                "import math\n\n"
                "def mutate_profile(user_record, untrusted_payload):\n"
                "    user_record.update(untrusted_payload)\n"
                "    return user_record\n\n"
                "def integrate_motion(x_pos, v_vel, accel, dt_sec):\n"
                "    x_next = x_pos + v_vel * dt_sec + 0.0 * accel  # NON_SYMPLECTIC_EULER_DRIFT\n"
                "    return x_next\n",
                encoding="utf-8",
            )

            orchestrator = ShadowCloneSwarmOrchestrator(ws)
            # 1. Normal 4-clone parallel exploration + BFT merge
            rep = orchestrator.run_swarm(ws, num_clones=4, consolidate_to_memory=True)
            self.assertEqual(rep["clones_spawned"], 4)
            self.assertEqual(rep["bft_consensus_status"], "PASS")
            self.assertEqual(rep["playbook_status"], "VERIFIED")
            self.assertGreaterEqual(rep["consolidated_truths_count"], 2)
            self.assertGreaterEqual(rep["negative_tabu_quarantined_count"], 1)
            self.assertGreaterEqual(rep["right_playbook_steps_count"], 2)
            self.assertIn("@SWARM/1|", rep["kmi_swarm_wire"])
            self.assertGreaterEqual(len(rep["distilled_lesson_ids"]), 2)

            # Verify each clone produced an independent signed episodic report
            tracks = {c["track"] for c in rep["clone_episodic_reports"]}
            self.assertEqual(len(tracks), 4)
            for c_rep in rep["clone_episodic_reports"]:
                self.assertEqual(len(c_rep["report_signature"]), 16)
                self.assertIn("VERIFIED", c_rep["independent_conclusion"])

            # 2. Byzantine Fault Injection test (1 clone corrupted, 3 honest clones still reach 3/4 BFT quorum!)
            bft_rep = orchestrator.run_swarm(
                ws,
                num_clones=4,
                consolidate_to_memory=False,
                inject_byzantine_fault=True,
            )
            self.assertTrue(bft_rep["byzantine_fault_injected"])
            self.assertEqual(bft_rep["bft_consensus_status"], "PASS")
            self.assertEqual(bft_rep["playbook_status"], "VERIFIED")
            self.assertGreaterEqual(bft_rep["consolidated_truths_count"], 2)
            for truth in bft_rep["consolidated_truths"]:
                self.assertEqual(truth["support_votes_s_p"], 3)
                self.assertEqual(truth["refute_votes_r_p"], 1)

    def test_consent_gated_free_agent_pool_and_condorcet_accuracy(self) -> None:
        from kintsugi.swarm import ConsentGatedFreePoolManager, ShadowCloneSwarmOrchestrator

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            pool_mgr = ConsentGatedFreePoolManager(ws)

            # 1. Default state: AWAITING_USER_CONSENT (Silence is NEVER consent)
            st0 = pool_mgr.get_pool_status(target_clones=4)
            self.assertEqual(st0["state"], "AWAITING_USER_CONSENT")
            self.assertFalse(st0["auto_provision_authorized"])
            self.assertIn("user_consent_request", st0)

            # 2. Attempting auto-provision without user confirmation MUST be blocked
            blocked = pool_mgr.authorize_auto_provision(confirmed_by_user=False)
            self.assertFalse(blocked["ok"])
            self.assertTrue(blocked["auto_provision_blocked_until_user_consent"])

            # 3. User supplies 1 free key -> state becomes USER_PROVIDED_KEY, secret is masked
            st1 = pool_mgr.add_user_provided_key("groq_free", "gsk_live_user_supplied_987654")
            self.assertEqual(st1["state"], "USER_PROVIDED_KEY")
            self.assertEqual(st1["distinct_model_families_count"], 1)
            self.assertNotIn("gsk_live_user_supplied_987654", st1["active_providers"][0]["masked_key"])

            # 4. User explicitly grants auto-provision consent -> VERIFIED_ACTIVE_POOL (12.5x error reduction)
            st_auth = pool_mgr.authorize_auto_provision(confirmed_by_user=True)
            self.assertEqual(st_auth["state"], "VERIFIED_ACTIVE_POOL")
            self.assertTrue(st_auth["auto_provision_authorized"])
            self.assertGreaterEqual(st_auth["distinct_model_families_count"], 4)
            self.assertEqual(
                st_auth["condorcet_bft_accuracy_metrics"]["current_error_reduction_multiplier"],
                "12.5x",
            )
            self.assertIn("@POOL/1|state=VERIFIED_ACTIVE_POOL|", st_auth["kmi_pool_wire"])

            # Verify Shadow Clones bind to the 4 distinct verified model families
            sample = ws / "demo.py"
            sample.write_text(
                "def update_profile(user_record, payload):\n"
                "    user_record.update(payload)\n"
                "    return user_record\n",
                encoding="utf-8",
            )
            swarm_rep = ShadowCloneSwarmOrchestrator(ws).run_swarm(ws, num_clones=4)
            routed_models = {c["routed_model"] for c in swarm_rep["clone_episodic_reports"]}
            self.assertEqual(len(routed_models), 4)

            # 5. Instant revocation -> state becomes REVOKED and all keys are purged
            st_rev = pool_mgr.revoke_consent()
            self.assertEqual(st_rev["state"], "REVOKED")
            self.assertFalse(st_rev["auto_provision_authorized"])
            self.assertEqual(st_rev["active_providers_count"], 0)

    def test_v1_2_0_covariance_bft_disjoint_scar_and_ast_quotient(self) -> None:
        from kintsugi.foresight import DisjointScarHoldoutVerifier
        from kintsugi.grounding import RepoAstGroundingEngine
        from kintsugi.models import GoldenScar, Severity
        from kintsugi.swarm import ShadowCloneSwarmOrchestrator

        # 1. Alpha-Normalized AST Quotient Hash & Semantic Equivalence
        code_v1 = (
            "def compute_kinetic(mass_kg, vel_ms):\n"
            "    energy_j = 0.5 * mass_kg * (vel_ms ** 2)\n"
            "    return energy_j\n"
        )
        code_v2_renamed = (
            "def calc_e(m_val, v_val):\n"
            "    res = 0.5 * m_val * (v_val ** 2)\n"
            "    return res\n"
        )
        code_v3_mutated = (
            "def calc_e(m_val, v_val):\n"
            "    res = 0.5 * m_val + (v_val ** 2)\n"
            "    return res\n"
        )
        eq_rep = RepoAstGroundingEngine.verify_semantic_equivalence(code_v1, code_v2_renamed)
        self.assertTrue(eq_rep["alpha_equivalent"])
        self.assertEqual(eq_rep["hash_a"], eq_rep["hash_b"])
        self.assertEqual(len(eq_rep["hash_a"]), 16)
        self.assertTrue(str(eq_rep["semantic_diff_certificate"]).startswith("ASTQ/1|"))

        diff_rep = RepoAstGroundingEngine.verify_semantic_equivalence(code_v1, code_v3_mutated)
        self.assertFalse(diff_rep["alpha_equivalent"])

        # 2. DisjointScarHoldoutVerifier (T_gen != T_ver, precision >= 0.95, 0 paraphrase FPs)
        valid_scar = GoldenScar(
            id="KS-V120-TEST",
            title="Symplectic Euler Guard",
            severity=Severity.CRITICAL,
            category="research-epistemology",
            languages=["python"],
            tags=["physics"],
            root_cause="Explicit Euler drift",
            bad_code="x_next = x_pos + v_vel * dt_sec + 0.0 * accel  # NON_SYMPLECTIC_EULER_DRIFT",
            good_code="v_half = v_vel + 0.5 * accel_0 * dt_sec\nx_next = x_pos + v_half * dt_sec",
            rationale="Use Velocity-Verlet",
            regex_pattern=r"NON_SYMPLECTIC_EULER_DRIFT",
        )
        holdout_ok = DisjointScarHoldoutVerifier.verify_disjoint_holdout(valid_scar)
        self.assertTrue(holdout_ok["passed"])
        self.assertGreaterEqual(holdout_ok["holdout_precision"], 0.95)
        self.assertEqual(holdout_ok["paraphrase_negative_fp_count"], 0)
        self.assertTrue(holdout_ok["disjoint_tiers"])

        overbroad_scar = GoldenScar(
            id="KS-OVERBROAD",
            title="Bad Regex",
            severity=Severity.HIGH,
            category="backend-api",
            languages=["python"],
            tags=["regex"],
            root_cause="Overbroad",
            bad_code="x = 1",
            good_code="x = 2",
            rationale="Reject trivial regex",
            regex_pattern=r".*",
        )
        holdout_bad = DisjointScarHoldoutVerifier.verify_disjoint_holdout(overbroad_scar)
        self.assertFalse(holdout_bad["passed"])

        # 3. Covariance-Aware BFT (N_eff), Anti-Sycophancy Probe, Call-Graph & Taint Flows
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            app = ws / "pipeline.py"
            app.write_text(
                "def apply_patch(user_record, untrusted_payload):\n"
                "    user_record.update(untrusted_payload)\n"
                "    return user_record\n\n"
                "def route_req(user_record, untrusted_payload):\n"
                "    return apply_patch(user_record, untrusted_payload)\n",
                encoding="utf-8",
            )
            eng = RepoAstGroundingEngine(ws)
            self.assertIn("route_req", eng.symbol_table["call_graph"])
            self.assertIn("apply_patch", eng.symbol_table["call_graph"]["route_req"])
            self.assertGreaterEqual(len(eng.symbol_table["taint_flows"]), 1)

            swarm = ShadowCloneSwarmOrchestrator(ws)
            s_rep = swarm.run_swarm(ws, num_clones=4)
            self.assertIn("covariance_bft_summary", s_rep)
            self.assertGreater(s_rep["covariance_bft_summary"]["n_eff"], 1.0)
            self.assertTrue(s_rep["anti_sycophancy_probe"]["sycophancy_rejected"])
            self.assertEqual(s_rep["anti_sycophancy_probe"]["sycophancy_rate"], 0.0)

    def test_hard_scientific_literature_verification_suite(self) -> None:
        from kintsugi.foresight import ScientificLiteratureVerifier

        with tempfile.TemporaryDirectory() as tmp:
            verifier = ScientificLiteratureVerifier(tmp)
            rep = verifier.verify_scientific_corpus()
            self.assertEqual(rep["papers_audited"], 5)
            self.assertTrue(rep["all_numerical_invariants_proven"])
            self.assertGreaterEqual(rep["baseline_scientific_seams_detected"], 6)
            self.assertEqual(rep["post_s3_counterfactual_seams"], 0)
            self.assertEqual(rep["q_risk_reduction_pct"], 100.0)

    def test_encrypted_pro_kpack_requires_customer_license_key(self) -> None:
        import io
        import zipfile
        from kintsugi.packs import encrypt_pro_kpack_bytes, install_skill_pack

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ledger_file = ws / ".kintsugi" / "scars.json"

            # Build an in-memory Pro Skill Pack .zip
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(
                    "agensi-manifest.json",
                    json.dumps(
                        {
                            "name": "kintsugi-pro-test-pack",
                            "title": "Kintsugi Pro Test Pack",
                            "version": "1.2.0",
                            "tier": "pro-encrypted",
                        }
                    ),
                )
                zf.writestr(
                    "scars.json",
                    json.dumps(
                        {
                            "scars": [
                                {
                                    "id": "KS-PRO-099",
                                    "title": "Pro Enterprise Guard",
                                    "severity": "CRITICAL",
                                    "category": "security",
                                    "languages": ["python"],
                                    "tags": ["pro"],
                                    "root_cause": "Pro check",
                                    "bad_code": "DANGEROUS_PRO_CALL()",
                                    "good_code": "SAFE_PRO_CALL()",
                                    "rationale": "Enforce Pro guard",
                                    "regex_pattern": r"DANGEROUS_PRO_CALL\s*\(",
                                }
                            ]
                        }
                    ),
                )
                zf.writestr(".claude/commands/kintsugi-audit.md", "# Pro Audit Command\n")

            secret_license = "KPRO-TEST-9988-7766-ABCD"
            kpack_bytes = encrypt_pro_kpack_bytes(
                buf.getvalue(),
                secret_license,
                pack_id="kintsugi-pro-test-pack",
                tier="pro-encrypted",
            )
            kpack_file = ws / "kintsugi-pro-test-pack.kpack"
            kpack_file.write_bytes(kpack_bytes)

            # 1. Plaintext secret must NOT appear inside encrypted .kpack file
            self.assertNotIn(b"DANGEROUS_PRO_CALL", kpack_bytes)
            self.assertNotIn(b"kintsugi-audit.md", kpack_bytes)

            # 2. Missing license key -> PermissionError
            with self.assertRaises(PermissionError):
                install_skill_pack(kpack_file, workspace_root=ws, ledger_path=ledger_file)

            # 3. Wrong license key -> PermissionError (constant-time HMAC rejection)
            with self.assertRaises(PermissionError):
                install_skill_pack(
                    kpack_file,
                    workspace_root=ws,
                    ledger_path=ledger_file,
                    license_key="WRONG-KEY-0000-1111-2222",
                )

            # 4. Valid customer license key -> Decrypts in memory and installs cleanly!
            info = install_skill_pack(
                kpack_file,
                workspace_root=ws,
                ledger_path=ledger_file,
                license_key=secret_license,
            )
            self.assertEqual(info["pack_id"], "kintsugi-pro-test-pack")
            self.assertEqual(info["newly_unlocked_scars"], 1)
            self.assertIn("/kintsugi-audit", info["slash_commands"])

    def test_v1_3_0_high_reasoning_and_red_blue_adversarial_arena(self) -> None:
        from kintsugi.foresight import CausalDoCalculusVerifier, LakatosCEGISVerifier
        from kintsugi.grounding import SoundSymbolicPathSolver
        from kintsugi.swarm import (
            BrierMomentShrinkagePool,
            RedBlueAdversarialArena,
            enforce_kl_high_001_promotion_guard,
        )

        # 1. Lakatos CEGIS Verifier: Monster-barring domain cut MUST return CONDITIONAL, never PROVED
        cegis = LakatosCEGISVerifier(c_min=0.80)
        res_monster = cegis.evaluate_conjecture(
            claim_id="CLM-TEST-1",
            conjecture_fn=lambda x: x >= 0,
            initial_domain=[-2, -1, 0, 1, 2, 3, 4, 5, 6, 7],
            domain_cuts=[-2, -1],
            lemma_dag={"lemma_nonneg": True},
            refuter_complete=True,
        )
        self.assertEqual(res_monster["status"], "CONDITIONAL")
        self.assertEqual(len(res_monster["preserved_original_refutations"]), 2)

        # 2. Sound Symbolic Path Solver: Correlated x - x -> 0 HOLDS; vacuous -> UNREACHABLE; nonlinear -> UNKNOWN
        solver = SoundSymbolicPathSolver(max_splits=8)
        res_corr = solver.discharge_assertion(
            path_bounds=[(0.0, 1.0)],
            assertion_le_zero_expr="x - x",
        )
        self.assertEqual(res_corr["status"], "HOLDS")
        self.assertTrue(res_corr["taint_clearance_allowed"])

        res_vac = solver.discharge_assertion(
            path_bounds=[(5.0, 10.0), (-3.0, 1.0)],
            assertion_le_zero_expr="x - 100.0",
        )
        self.assertEqual(res_vac["status"], "UNREACHABLE")
        self.assertFalse(res_vac["taint_clearance_allowed"])

        res_nonlin = solver.discharge_assertion(
            path_bounds=[(0.0, 10.0)],
            assertion_le_zero_expr="x * x - 5.0",
        )
        self.assertEqual(res_nonlin["status"], "UNKNOWN")
        self.assertFalse(res_nonlin["taint_clearance_allowed"])

        # 3. Causal Do-Calculus Verifier: Confounded collider -> NONIDENTIFIABLE with 2-SCM witness
        res_conf = CausalDoCalculusVerifier.verify_interventional_identification(
            directed_edges=[("U", "X"), ("U", "Y"), ("X", "Y"), ("X", "C"), ("Y", "C")],
            treatment="X",
            outcome="Y",
            observed_adjustment_set=set(),
            unobserved_nodes={"U"},
        )
        self.assertEqual(res_conf["status"], "NONIDENTIFIABLE")
        self.assertIsNotNone(res_conf["nonidentifiability_witness"])

        # 4. Brier Moment Shrinkage Pool: Uncentered second-moment shrinkage + abstention penalty 0.25
        brier_pool = BrierMomentShrinkagePool(bs0=0.25, shrinkage_gamma=0.15)
        roster = ["clone_honest", "clone_bias", "clone_abstain"]
        for t_idx in range(1, 9):
            y_true = t_idx % 2
            brier_pool.record_outcome(
                tick=t_idx,
                item_id=f"item_{t_idx}",
                forecasts_by_specialist={
                    "clone_honest": 0.92 if y_true == 1 else 0.08,
                    "clone_bias": 0.99,
                    "clone_abstain": None,
                },
                all_specialists=roster,
                outcome=y_true,
            )
        w_rep = brier_pool.compute_weights_and_pool(
            specialists=roster,
            current_forecasts={"clone_honest": 0.90, "clone_bias": 0.10, "clone_abstain": None},
            before_tick=9,
        )
        self.assertGreater(w_rep["weights"]["clone_honest"], w_rep["weights"]["clone_bias"])

        # 5. KL-HIGH-001 Supreme Invariant Guard
        promo = enforce_kl_high_001_promotion_guard(
            claim_id="CLM-99",
            source_scope="RESTRICTED_D_THETA",
            target_scope="FULL_DOMAIN_D0",
            assumptions=["x > 0"],
            evidence_lineage="lakatos_cegis",
            current_status="CONDITIONAL",
            requested_status="PROVED",
        )
        self.assertFalse(promo["promotion_allowed"])
        self.assertEqual(promo["emitted_status"], "CONDITIONAL")

        # 6. Full 2-Team Red vs Blue Adversarial Arena (5/5 campaigns neutralized)
        arena_rep = RedBlueAdversarialArena().run_arena()
        self.assertEqual(arena_rep["campaigns_total"], 5)
        self.assertEqual(arena_rep["campaigns_neutralized"], 5)
        self.assertTrue(arena_rep["all_attacks_neutralized"])
        self.assertEqual(arena_rep["defense_containment_rate_pct"], 100.0)
        self.assertIn("@ARENA/1|ver=1.3.0|campaigns=5/5|containment=100.0%", arena_rep["kmi_arena_wire"])


if __name__ == "__main__":
    unittest.main()
