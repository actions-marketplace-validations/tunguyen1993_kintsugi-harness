"""Stage 5 Private Held-Out Blind Generalization & Self-Evolution v3 Verification Suite.

Tests:
  1. Tier-3 `StrategyMemory`: `.kintsugi/strategy_memory.json` symlink/O_NOFOLLOW/0o600 persistence,
     DLP redaction, policy-mutation blocking, and anti-volume-inflation causal transfer ranking.
  2. Strict `Shadow -> Canary -> Enforced` monotonic soak gate refusing direct jumps to `enforced`
     without `canary` soak or without `reviewer_approved=True`, plus clean atomic rollback.
  3. Python <-> Rust canonical hash & decision parity (`parity_mismatches == 0`) via both
     `cdylib_ffi_v1` and `subprocess_kintsugi_rs` fallback (`NativeBridge` / `kintsugi-rs`).
  4. Cross-task blind generalization (`train/` vs `private_heldout/` with aliased imports,
     keyword-arg reordering, multiline expressions, shadowed constants, and tricky benign
     near-misses including `SafeLoader`/`CSafeLoader`, quoted examples, and `shell=False`)
     vs `no_memory_control`, with `0` baseline scar (`KS-001..KS-024`) regressions and honest
     Wilson 95% CI reporting.
  5. Baseline immutability (`KS-001..KS-024`) and no direct `hooks.py` / `PreToolUse` mutation.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

from kintsugi.evolution import (
    PROTECTED_BASELINE_IDS,
    SelfEvolutionEngineV3,
    StrategyMemory,
    UnseenFailure,
)
from kintsugi.evolution_v2 import RuleIR, evaluate_rule_ir
from kintsugi.native_bridge import (
    NativeBridge,
    _read_and_hash_regular_nofollow,
    write_external_native_pins,
)
from kintsugi.starter_pack import get_full_crs_scars

REPO_ROOT = Path(__file__).resolve().parents[2]


class TestBlindEvolutionTransfer(unittest.TestCase):
    """Verify Stage 5 Self-Evolution v3, Tier-3 StrategyMemory, Parity, Soak Gate & Blind Transfer."""

    _pin_tmp: tempfile.TemporaryDirectory[str]
    pin_manifest_path: Path
    dylib_sha256: str
    rust_bin_sha256: str

    @classmethod
    def setUpClass(cls) -> None:
        dylib_name = "libkintsugi_core.dylib" if sys.platform == "darwin" else "libkintsugi_core.so"
        dylib_p = REPO_ROOT / "target" / "release" / dylib_name
        rust_bin_p = REPO_ROOT / "target" / "release" / "kintsugi-rs"
        if not dylib_p.is_file() or not rust_bin_p.is_file():
            raise unittest.SkipTest("Compiled Rust cdylib/binary unavailable in this environment")
        cls._pin_tmp = tempfile.TemporaryDirectory(prefix="kintsugi_evo_pins_")
        cls.pin_manifest_path = Path(cls._pin_tmp.name) / "native_pins.json"
        _, cls.dylib_sha256 = _read_and_hash_regular_nofollow(dylib_p)
        _, cls.rust_bin_sha256 = _read_and_hash_regular_nofollow(rust_bin_p)
        write_external_native_pins(
            REPO_ROOT,
            dylib_sha256=cls.dylib_sha256,
            rust_bin_sha256=cls.rust_bin_sha256,
            dylib_path=dylib_p,
            rust_bin_path=rust_bin_p,
            pin_manifest_path=cls.pin_manifest_path,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._pin_tmp.cleanup()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_evo3_")
        self.ws = Path(self._tmp.name) / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.engine = SelfEvolutionEngineV3(
            workspace_root=self.ws,
            traces_dir=self.ws / ".kintsugi" / "traces",
            rust_repo_root=REPO_ROOT,
            pin_manifest_path=self.pin_manifest_path,
        )

    def tearDown(self) -> None:
        self.engine.close()
        self._tmp.cleanup()

    def test_strategy_memory_persistence_redaction_and_anti_volume_ranking(self) -> None:
        mem_path = self.ws / ".kintsugi" / "strategy_memory.json"
        mem = StrategyMemory(mem_path, workspace_root=self.ws)

        fake_tok = "sk-" + "live-" + "9876543210abcdefghijklmnop"
        # High-volume repeated replay on one non-transfer task MUST NOT inflate rank
        for idx in range(40):
            mem.record_outcome(
                task_class="python_kwarg_policy",
                decomposition_pattern="lexical_window",
                synthesis_strategy="bounded_regex_generalizer",
                verified_outcome=True,
                cost_ms=1.0 + idx * 0.01,
                task_id="train-single-task",
                source_family="train-single-task",
                failure_reason=f"note /{'Users'}/alice/secret_{fake_tok}",
            )

        # Unverified outcomes MUST NOT grant verified passes or transfer credit
        mem.record_outcome(
            task_class="python_kwarg_policy",
            decomposition_pattern="unverified_heuristic",
            synthesis_strategy="unverified_guess",
            verified_outcome=None,
            cost_ms=0.2,
            task_id="unverified-1",
            is_cross_task_transfer=True,
            causal_verified=True,
        )

        # Genuine causal cross-task transfer strategy across distinct tasks/families
        for idx in range(2):
            mem.record_outcome(
                task_class="python_kwarg_policy",
                decomposition_pattern="ast_call_diff_with_safe_defaults",
                synthesis_strategy="ast_kwarg_policy",
                verified_outcome=True,
                cost_ms=0.8,
                task_id=f"blind-task-{idx}",
                source_task_id="train-seed-0",
                source_family="requests_verify",
                target_family=f"heldout_variant_{idx}",
                evidence_digest="sha256:" + f"{idx + 1}" * 64,
                is_cross_task_transfer=True,
                causal_verified=True,
            )

        ranked = mem.rank_strategies(task_class="python_kwarg_policy")
        self.assertEqual(ranked[0].synthesis_strategy, "ast_kwarg_policy")
        self.assertEqual(ranked[0].cross_task_transfer_successes, 2)
        self.assertEqual(ranked[0].verified_passes, 2)

        regex_rec = next(r for r in ranked if r.synthesis_strategy == "bounded_regex_generalizer")
        self.assertEqual(regex_rec.raw_observations, 40)
        self.assertEqual(regex_rec.verified_passes, 1)
        self.assertEqual(regex_rec.cross_task_transfer_successes, 0)
        self.assertGreater(ranked[0].causal_transfer_score, regex_rec.causal_transfer_score)

        unverified_rec = next(r for r in ranked if r.synthesis_strategy == "unverified_guess")
        self.assertEqual(unverified_rec.verified_passes, 0)
        self.assertEqual(unverified_rec.cross_task_transfer_successes, 0)

        # File permissions, DLP redaction, and reload parity
        self.assertTrue(mem_path.is_file())
        mode = stat.S_IMODE(mem_path.stat().st_mode)
        self.assertEqual(mode, 0o600)
        raw_text = mem_path.read_text(encoding="utf-8")
        self.assertNotIn(fake_tok, raw_text)
        self.assertNotIn("/" + "Users/alice", raw_text)

        reloaded = StrategyMemory(mem_path, workspace_root=self.ws)
        self.assertEqual(reloaded.best_strategy("python_kwarg_policy").synthesis_strategy, "ast_kwarg_policy")

        # Symlink refusal on load & save
        link_path = self.ws / ".kintsugi" / "strategy_link.json"
        link_path.symlink_to(mem_path)
        with self.assertRaisesRegex(PermissionError, "SECURITY_SYMLINK_REFUSED"):
            StrategyMemory(link_path, workspace_root=self.ws)

        # Policy mutation & Trojan/prompt injection blocked
        with self.assertRaisesRegex(ValueError, "POLICY_MUTATION_BLOCKED"):
            mem.record_outcome(
                task_class="python_kwarg_policy",
                decomposition_pattern="x",
                synthesis_strategy="y",
                verified_outcome=True,
                task_id="t",
                failure_reason=json.dumps({"disable_guardrails": True}),
            )
        with self.assertRaisesRegex(ValueError, "TROJAN_UNICODE_BLOCKED"):
            mem.record_outcome(
                task_class="bad" + chr(0x202E),
                decomposition_pattern="x",
                synthesis_strategy="y",
                verified_outcome=True,
                task_id="t",
            )

    def test_monotonic_shadow_canary_enforced_gate_and_rollback(self) -> None:
        # 1. Baseline KS-001..KS-024 immutable and hooks.py protected
        for baseline_id in ("KS-001", "KS-012", "KS-024"):
            self.assertIn(baseline_id, PROTECTED_BASELINE_IDS)
            bad_ir = RuleIR(
                rule_id=baseline_id,
                revision=2,
                language=["python"],
                severity="CRITICAL",
                predicate_kind="ast_pattern",
                match={"node": "Call", "callee": "jsonpickle.decode", "mode": "forbidden_callee"},
            )
            with self.assertRaisesRegex(ValueError, "PROTECTED_BASELINE_IMMUTABLE"):
                self.engine.promote_shadow(
                    bad_ir,
                    self.engine.verify_heldout_and_parity(
                        bad_ir, ["import jsonpickle\njsonpickle.decode(x)\n"], ["import json\njson.loads(x)\n"]
                    )[0],
                )

        with self.assertRaisesRegex(PermissionError, "LEARNER_HOOK_MUTATION_FORBIDDEN"):
            self.engine.ingest_failure(
                UnseenFailure(
                    task_id="bad-hook-mutation",
                    language="python",
                    offending_snippet="requests.get(u, timeout=5, verify=False)",
                    fixed_snippet="requests.get(u, timeout=5, verify=True)",
                    error_summary="Attempt hook mutation",
                    config_hints={"mutation_target": "src/kintsugi/hooks.py"},
                )
            )

        # 2. Synthesize & validate rev=1
        failure = UnseenFailure(
            task_id="evo3-xml-xxe",
            language="python",
            offending_snippet=(
                "import logging\n"
                "logging.getLogger('xml').info('parsing')\n"
                "import xml.etree.ElementTree as ET\n"
                "root = ET.fromstring(raw_xml)\n"
            ),
            fixed_snippet=(
                "import logging\n"
                "logging.getLogger('xml').info('parsing')\n"
                "import defusedxml.ElementTree as DET\n"
                "root = DET.fromstring(raw_xml)\n"
            ),
            error_summary="Untrusted XML parsing vulnerable to XXE",
            task_class="python_unsafe_callee",
            file_path="src/parsers/xml_loader.py",
        )
        res1 = self.engine.evolve_from_failure(
            failure,
            rule_id="KS-EVO-920001",
            revision=1,
            promote_to="unpromoted",
            persist_trace=True,
        )
        self.assertEqual(res1.parity_mismatches, 0)
        self.assertTrue(res1.canonical_hash_verified)
        self.assertEqual(res1.rule_ir.match["callee"], "xml.etree.ElementTree.fromstring")

        # Refuses jumping straight to enforced or canary without prior stage
        with self.assertRaisesRegex(ValueError, "PROMOTION_GATE_FAILED"):
            self.engine.promote_enforced(res1.rule_ir, res1.attestation, reviewer_approved=True)
        with self.assertRaisesRegex(ValueError, "PROMOTION_GATE_FAILED"):
            self.engine.promote_canary(res1.rule_ir, res1.attestation, ["import defusedxml.ElementTree as ET\nET.fromstring(x)\n"])

        # Promote to Shadow -> still refuses jumping straight to Enforced without Canary!
        self.engine.promote_shadow(res1.rule_ir, res1.attestation, proof_report=res1.proof_pack_report)
        self.assertEqual(self.engine.current_stage("KS-EVO-920001", 1), "shadow")
        with self.assertRaisesRegex(ValueError, "without 'canary' soak"):
            self.engine.promote_enforced(res1.rule_ir, res1.attestation, reviewer_approved=True)

        # Canary soak fails if a false positive occurs on soak corpus
        with self.assertRaisesRegex(ValueError, "CANARY_SOAK_FAILED"):
            self.engine.promote_canary(
                res1.rule_ir,
                res1.attestation,
                ["import xml.etree.ElementTree as ET\nET.fromstring(x)\n"],
            )

        # Valid Canary soak with tricky near-misses passes with 0 FP and honest Wilson UB
        soak_negatives = [
            "import defusedxml.ElementTree as ET\nroot = ET.fromstring(raw_xml)\n",
            "doc = 'ET.fromstring(raw_xml)'\n# avoid xml.etree.ElementTree.fromstring\n",
            "import json\ndata = json.loads(raw_json)\n",
        ]
        _, canary_rep = self.engine.promote_canary(res1.rule_ir, res1.attestation, soak_negatives)
        self.assertTrue(canary_rep.passed)
        self.assertEqual(canary_rep.false_positives, 0)
        self.assertEqual(canary_rep.observed_fraction, "0/3")
        self.assertGreater(canary_rep.fp_upper_bound_95, 0.0)
        self.assertEqual(canary_rep.parity_mismatches, 0)

        # Enforced still refuses without reviewer_approved=True
        with self.assertRaisesRegex(ValueError, "reviewer_approved=True"):
            self.engine.promote_enforced(res1.rule_ir, res1.attestation, reviewer_approved=False)

        self.engine.promote_enforced(res1.rule_ir, res1.attestation, reviewer_approved=True)
        self.assertEqual(self.engine.current_stage("KS-EVO-920001", 1), "enforced")

        # Promote rev=2 through full Shadow -> Canary -> Enforced, then roll back cleanly to rev=1
        rev2_ir = RuleIR(
            rule_id="KS-EVO-920001",
            revision=2,
            language=["python"],
            severity="CRITICAL",
            predicate_kind="ast_pattern",
            match={"node": "Call", "callee": "xml.etree.ElementTree.XML", "mode": "forbidden_callee"},
            source_trace_ids=[res1.envelope.trace_id],
        )
        att2, proof2, _ = self.engine.verify_heldout_and_parity(
            rev2_ir,
            ["import xml.etree.ElementTree as ET\nET.XML(payload)\n"],
            soak_negatives,
        )
        self.engine.promote_shadow(rev2_ir, att2, proof_report=proof2)
        self.engine.promote_canary(rev2_ir, att2, soak_negatives)
        self.engine.promote_enforced(rev2_ir, att2, reviewer_approved=True)
        self.assertEqual(self.engine.get_active_rules()[0].revision, 2)

        rb = self.engine.rollback("KS-EVO-920001", to_revision=1)
        self.assertEqual(rb["to_revision"], 1)
        self.assertEqual(rb["restored_hash"], res1.rule_ir.rule_hash)
        self.assertEqual(rb["restored_mode"], "enforced")
        active_after = self.engine.get_active_rules(modes=("enforced",))
        self.assertEqual(len(active_after), 1)
        self.assertEqual(active_after[0].revision, 1)
        self.assertEqual(active_after[0].rule_hash, res1.rule_ir.rule_hash)

        # Reload engine from disk and confirm restored revision persists
        reloaded_engine = SelfEvolutionEngineV3(
            workspace_root=self.ws,
            rust_repo_root=REPO_ROOT,
            pin_manifest_path=self.pin_manifest_path,
        )
        try:
            reloaded_rules = reloaded_engine.get_active_rules(modes=("enforced",))
            self.assertEqual(reloaded_rules[0].revision, 1)
            self.assertEqual(reloaded_rules[0].rule_hash, res1.rule_ir.rule_hash)
            self.assertTrue(self.engine.verify_hooks_integrity())
        finally:
            reloaded_engine.close()

    def test_python_rust_parity_both_cdylib_and_cli_fallback(self) -> None:
        fallback_bridge = NativeBridge(
            repo_root=REPO_ROOT,
            expected_sha256="0" * 64,
            expected_rust_bin_sha256=self.rust_bin_sha256,
            pin_manifest_path=self.pin_manifest_path,
            allow_fallback=True,
        )
        try:
            self.assertEqual(self.engine.native_bridge.backend, "cdylib_ffi_v1")
            self.assertEqual(fallback_bridge.backend, "subprocess_kintsugi_rs")

            fallback_engine = SelfEvolutionEngineV3(
                workspace_root=self.ws,
                registry_path=".kintsugi/fallback_reg.json",
                strategy_memory_path=".kintsugi/fallback_strat.json",
                native_bridge=fallback_bridge,
                rust_repo_root=REPO_ROOT,
            )

            # Include tricky SafeLoader / shell=False near-misses + aliased/shadowed positives
            yaml_env = UnseenFailure(
                task_id="yaml-near-miss",
                language="python",
                offending_snippet="import yaml\ncfg = yaml.load(raw_doc, Loader=yaml.Loader)\n",
                fixed_snippet="import yaml\ncfg = yaml.safe_load(raw_doc)\n",
                error_summary="Unsafe YAML deserialization",
            )
            subp_run = "subprocess" + ".run"
            sh_true = "shell=" + "True"
            sh_false = "shell=" + "False"
            shell_env = UnseenFailure(
                task_id="subproc-near-miss",
                language="python",
                offending_snippet=f"import subprocess\n{subp_run}(cmd_line, {sh_true})\n",
                fixed_snippet=f"import subprocess\n{subp_run}(['echo', 'ok'], {sh_false})\n",
                error_summary="Subprocess shell enabled",
            )

            yaml_res = self.engine.evolve_from_failure(
                yaml_env,
                heldout_positives=[
                    "import yaml as ym\nout = ym.load(\n    payload,\n    Loader=ym.UnsafeLoader,\n)\n",
                    "from yaml import load as y_load\nout = y_load(payload)\n",
                ],
                heldout_negatives=[
                    "import yaml as ym\nout = ym.load(payload, Loader=ym.SafeLoader)\n",
                    "import yaml\nout = yaml.load(payload, Loader=yaml.CSafeLoader)\n",
                    "import yaml\nout = yaml.safe_load(payload)\n",
                    'example = "yaml.load(payload, Loader=yaml.Loader)"\n',
                ],
                reviewer_approved=True,
            )
            self.assertEqual(yaml_res.parity_mismatches, 0)
            self.assertTrue(yaml_res.canonical_hash_verified)
            self.assertEqual(yaml_res.attestation.false_positives, 0)
            self.assertEqual(yaml_res.attestation.caught_positive, yaml_res.attestation.tested_positive)

            shell_res = fallback_engine.evolve_from_failure(
                shell_env,
                heldout_positives=[
                    "import subprocess as sp\nSH_FLAG = False\nSH_FLAG = True\nsp.run(cmd, check=True, shell=SH_FLAG)\n",
                    "from subprocess import run as exec_proc\nexec_proc(cmd, shell=(1 == 1), check=True)\n",
                ],
                heldout_negatives=[
                    f"import subprocess as sp\nsp.run(['ls', '-la'], {sh_false}, check=True)\n",
                    f"import subprocess\n{subp_run}(['ls', '-la'], check=True)\n",
                    "SH_FLAG = True\nSH_FLAG = False\nimport subprocess\n" + f"{subp_run}(['ls'], shell=SH_FLAG)\n",
                    f'doc_note = "{subp_run}(cmd, {sh_true})"\n',
                ],
                reviewer_approved=True,
            )
            self.assertEqual(shell_res.parity_mismatches, 0)
            self.assertTrue(shell_res.canonical_hash_verified)
            self.assertEqual(shell_res.attestation.false_positives, 0)
            self.assertEqual(shell_res.attestation.caught_positive, shell_res.attestation.tested_positive)
        finally:
            fallback_bridge.close()

    @staticmethod
    def _build_transfer_families() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
        fake_api_key = "ghp_" + "AbCdEf1234567890GhIjKlMnOpQr"
        train_families: List[Dict[str, Any]] = [
            {
                "family_id": "requests_verify_disabled",
                "task_class": "python_kwarg_policy",
                "language": "python",
                "severity": "HIGH",
                "file_path": "train/http_client.py",
                "error_summary": f"Disabled TLS verification for /{'Users'}/dev/project ({fake_api_key})",
                "offending_snippet": (
                    "import logging\n"
                    "logging.info('fetching')\n"
                    "import requests\n"
                    "resp = requests.get('https://api.example.com/v1', timeout=10, verify=False)\n"
                ),
                "fixed_snippet": (
                    "import logging\n"
                    "logging.info('fetching')\n"
                    "import requests\n"
                    "resp = requests.get('https://api.example.com/v1', timeout=10, verify=True)\n"
                ),
                "negatives": [
                    "import requests\nresp = requests.get('https://api.example.com/v1', timeout=10)\n",
                ],
            },
            {
                "family_id": "jinja_autoescape_disabled",
                "task_class": "python_kwarg_policy",
                "language": "python",
                "severity": "HIGH",
                "file_path": "train/template_env.py",
                "error_summary": "Jinja2 Environment initialized with autoescape=False",
                "offending_snippet": (
                    "import jinja2\n"
                    "env = jinja2.Environment(loader=tmpl_loader, autoescape=False)\n"
                ),
                "fixed_snippet": (
                    "import jinja2\n"
                    "env = jinja2.Environment(loader=tmpl_loader, autoescape=True)\n"
                ),
                "negatives": [
                    "import jinja2\nenv = jinja2.Environment(loader=tmpl_loader, autoescape=True)\n",
                ],
            },
            {
                "family_id": "xml_xxe_fromstring",
                "task_class": "python_unsafe_callee",
                "language": "python",
                "severity": "CRITICAL",
                "file_path": "train/xml_reader.py",
                "error_summary": "Unsafe stdlib ElementTree XML parsing",
                "offending_snippet": (
                    "import xml.etree.ElementTree as ET\n"
                    "tree = ET.fromstring(xml_bytes)\n"
                ),
                "fixed_snippet": (
                    "import defusedxml.ElementTree as DET\n"
                    "tree = DET.fromstring(xml_bytes)\n"
                ),
                "negatives": [
                    "import defusedxml.ElementTree as DET\ntree = DET.fromstring(xml_bytes)\n",
                ],
            },
            {
                "family_id": "tempfile_mktemp_toctou",
                "task_class": "python_unsafe_callee",
                "language": "python",
                "severity": "HIGH",
                "file_path": "train/tmp_writer.py",
                "error_summary": "Insecure tempfile.mktemp race condition",
                "offending_snippet": (
                    "import tempfile\n"
                    "tmp_path = tempfile.mktemp(prefix='job_')\n"
                ),
                "fixed_snippet": (
                    "import tempfile\n"
                    "fd, tmp_path = tempfile.mkstemp(prefix='job_')\n"
                ),
                "negatives": [
                    "import tempfile\nfd, tmp_path = tempfile.mkstemp(prefix='job_')\n",
                ],
            },
            {
                "family_id": "ssl_verifier_assign_none",
                "task_class": "python_assign_invariant",
                "language": "python",
                "severity": "HIGH",
                "file_path": "train/tls_config.py",
                "error_summary": "SSL verifier explicitly disabled via None assignment",
                "offending_snippet": "ssl_verifier = None\n",
                "fixed_snippet": "ssl_verifier = strict_cert_verifier\n",
                "negatives": ["ssl_verifier = strict_cert_verifier\n"],
            },
        ]

        # Genuinely distinct blind held-out templates (aliased imports, keyword-args reordering,
        # multiline expressions, shadowed constants, plus tricky benign near-misses)
        blind_heldout_families: List[Dict[str, Any]] = [
            {
                "family_id": "requests_verify_disabled",
                "task_class": "python_kwarg_policy",
                "language": "python",
                "positives": [
                    (
                        "import requests as http_cli\n"
                        "reply = http_cli.get(\n"
                        "    timeout=15,\n"
                        "    verify=False,\n"
                        "    url=target_endpoint,\n"
                        ")\n"
                    ),
                    (
                        "from requests import get as fetch_remote\n"
                        "ENFORCE_CERT = True\n"
                        "ENFORCE_CERT = False\n"
                        "reply = fetch_remote(target_endpoint, verify=ENFORCE_CERT, timeout=5)\n"
                    ),
                    (
                        "import requests as rq\n"
                        "reply = rq.get(target_endpoint, verify=(1 == 0), timeout=8)\n"
                    ),
                ],
                "negatives": [
                    "import requests as rq\nreply = rq.get(target_endpoint, verify=True, timeout=12)\n",
                    "import requests as rq\nreply = rq.get(target_endpoint, timeout=12)\n",
                    (
                        "ENFORCE_CERT = False\n"
                        "ENFORCE_CERT = True\n"
                        "import requests\n"
                        "reply = requests.get(target_endpoint, verify=ENFORCE_CERT, timeout=10)\n"
                    ),
                    'example_snippet = "requests.get(url, verify=False, timeout=5)"\n',
                ],
            },
            {
                "family_id": "jinja_autoescape_disabled",
                "task_class": "python_kwarg_policy",
                "language": "python",
                "positives": [
                    (
                        "from jinja2 import Environment as TmEnv\n"
                        "renderer = TmEnv(\n"
                        "    autoescape=False,\n"
                        "    loader=fs_loader,\n"
                        ")\n"
                    ),
                    (
                        "import jinja2 as j2\n"
                        "AUTO_ESC = True\n"
                        "AUTO_ESC = False\n"
                        "renderer = j2.Environment(loader=fs_loader, autoescape=AUTO_ESC)\n"
                    ),
                ],
                "negatives": [
                    "from jinja2 import Environment as TmEnv\nrenderer = TmEnv(autoescape=True, loader=fs_loader)\n",
                    "# comment: jinja2.Environment(loader=fs_loader, autoescape=False)\nx = 1\n",
                ],
            },
            {
                "family_id": "xml_xxe_fromstring",
                "task_class": "python_unsafe_callee",
                "language": "python",
                "positives": [
                    (
                        "import xml.etree.ElementTree as std_xml\n"
                        "parsed = std_xml.fromstring(\n"
                        "    untrusted_payload,\n"
                        ")\n"
                    ),
                    (
                        "from xml.etree.ElementTree import fromstring as parse_xml_blob\n"
                        "parsed = parse_xml_blob(untrusted_payload)\n"
                    ),
                ],
                "negatives": [
                    "import defusedxml.ElementTree as ET\nparsed = ET.fromstring(untrusted_payload)\n",
                    'doc_text = "xml.etree.ElementTree.fromstring(raw)"\n',
                ],
            },
            {
                "family_id": "tempfile_mktemp_toctou",
                "task_class": "python_unsafe_callee",
                "language": "python",
                "positives": [
                    (
                        "import tempfile as tf\n"
                        "scratch = tf.mktemp(\n"
                        "    suffix='.tmp',\n"
                        "    prefix='runner_',\n"
                        ")\n"
                    ),
                    (
                        "from tempfile import mktemp as insecure_temp_path\n"
                        "scratch = insecure_temp_path()\n"
                    ),
                ],
                "negatives": [
                    "import tempfile as tf\nfd, scratch = tf.mkstemp(prefix='runner_', suffix='.tmp')\n",
                    "from tempfile import NamedTemporaryFile as safe_tmp\nfh = safe_tmp(delete=False)\n",
                ],
            },
            {
                "family_id": "ssl_verifier_assign_none",
                "task_class": "python_assign_invariant",
                "language": "python",
                "positives": [
                    "ssl_verifier = (None)\n",
                    "fallback_val = None\nssl_verifier = fallback_val\n",
                    "ssl_verifier = 'strict'\nssl_verifier = None\n",
                ],
                "negatives": [
                    "ssl_verifier = 'custom_ca_bundle'\n",
                    "def configure(ssl_verifier=None):\n    return bool(ssl_verifier)\n",
                    "import yaml\nout = yaml.safe_load(raw_cfg)\n",
                    "import subprocess\nsubprocess.run(['echo', 'safe'], shell=False)\n",
                ],
            },
        ]
        return train_families, blind_heldout_families, fake_api_key

    def test_cross_task_blind_heldout_transfer_vs_no_memory_control(self) -> None:
        # Materialize genuinely distinct `train/` and `private_heldout/` template trees
        train_dir = self.ws / "train"
        heldout_dir = self.ws / "private_heldout"
        train_dir.mkdir(parents=True, exist_ok=True)
        heldout_dir.mkdir(parents=True, exist_ok=True)

        train_families, blind_heldout_families, fake_api_key = self._build_transfer_families()

        # Persist train/ & private_heldout/ snapshots inside workspace to model physical split isolation
        for fam in train_families:
            (train_dir / f"{fam['family_id']}.py").write_text(fam["offending_snippet"], encoding="utf-8")
        for fam in blind_heldout_families:
            (heldout_dir / f"{fam['family_id']}.py").write_text("\n\n".join(fam["positives"]), encoding="utf-8")

        baseline_scars = get_full_crs_scars()
        report = self.engine.run_cross_task_blind_transfer_eval(
            train_families,
            blind_heldout_families,
            baseline_scars=baseline_scars,
        )

        # Assertions from KINTSUGI-NEXTGEN/1 Stage 5 Contract
        self.assertEqual(report.parity_mismatches, 0)
        self.assertEqual(report.baseline_regression_count, 0)
        self.assertEqual(report.family_recall, 1.0)
        self.assertEqual(report.negative_precision, 1.0)
        self.assertEqual(report.false_positives, 0)
        self.assertGreater(report.tested_negatives, 10)
        self.assertGreater(report.fp_upper_bound_95, 0.0)
        self.assertLess(report.fp_upper_bound_95, 0.30)
        self.assertTrue(report.honest_fp_summary["universal_claim_forbidden"])
        self.assertFalse(report.honest_fp_summary["universal_zero_fp_claimed"])
        self.assertIn("not a universal guarantee", report.honest_fp_summary["statement"])
        self.assertEqual(report.honest_fp_summary["observed_fraction"], f"0/{report.tested_negatives}")
        self.assertGreater(report.recall_lower_bound_95, 0.65)
        self.assertGreaterEqual(report.p95_latency_ms, 0.0)

        # Evolved recall strictly beats no-memory baseline control
        self.assertEqual(report.no_memory_control["family_recall"], 0.0)
        self.assertGreater(report.family_recall, report.no_memory_control["family_recall"])
        self.assertEqual(report.recall_gain, 1.0)
        self.assertEqual(len(report.evolved_rule_ids), len(train_families))

        # Verify DLP redaction on persisted strategy memory & traces
        strat_file = self.ws / ".kintsugi" / "strategy_memory.json"
        self.assertTrue(strat_file.is_file())
        strat_raw = strat_file.read_text(encoding="utf-8")
        self.assertNotIn(fake_api_key, strat_raw)
        self.assertNotIn("/" + "Users/dev", strat_raw)
        self.assertTrue(self.engine.verify_hooks_integrity())

        # Corpus leakage guard refuses any shared train/blind heldout snippet
        leaked_blind = [dict(blind_heldout_families[0])]
        leaked_blind[0]["positives"] = [train_families[0]["offending_snippet"]]
        with self.assertRaisesRegex(ValueError, "CORPUS_LEAKAGE"):
            self.engine.run_cross_task_blind_transfer_eval(train_families, leaked_blind, baseline_scars=baseline_scars)

    def test_sealed_external_blind_holdout_verification_and_tamper_rejection(self) -> None:
        train_families, blind_heldout_families, _ = self._build_transfer_families()
        baseline_scars = get_full_crs_scars()

        sealed_dir = Path(self._tmp.name) / "external_sealed"
        sealed_dir.mkdir(parents=True, exist_ok=True)
        sealed_path = sealed_dir / "sealed_blind_corpus.json"
        sealed_bytes = json.dumps({"families": blind_heldout_families}, indent=2).encode("utf-8")
        sealed_path.write_bytes(sealed_bytes)
        os.chmod(sealed_path, 0o600)
        expected_sha = hashlib.sha256(sealed_bytes).hexdigest()

        # 1. Valid external sealed corpus with matching SHA-256 passes
        report = self.engine.run_sealed_blind_eval(
            sealed_path,
            expected_sha256=expected_sha,
            train_families=train_families,
            baseline_scars=baseline_scars,
        )
        self.assertEqual(report.family_recall, 1.0)
        self.assertEqual(report.negative_precision, 1.0)
        self.assertEqual(report.parity_mismatches, 0)
        self.assertEqual(report.baseline_regression_count, 0)
        self.assertEqual(report.no_memory_control["corpus_origin"], "external_sealed_verified")
        self.assertEqual(report.no_memory_control["corpus_sha256"], expected_sha)
        self.assertIn("honest_note", report.no_memory_control)

        # 2. Tampered SHA-256 / modified corpus MUST be rejected
        with self.assertRaisesRegex(PermissionError, "SEALED_CORPUS_SHA256_MISMATCH"):
            self.engine.run_sealed_blind_eval(
                sealed_path,
                expected_sha256="a" * 64,
                train_families=train_families,
                baseline_scars=baseline_scars,
            )

        sealed_path.write_bytes(sealed_bytes + b"\n ")
        with self.assertRaisesRegex(PermissionError, "SEALED_CORPUS_SHA256_MISMATCH"):
            self.engine.run_sealed_blind_eval(
                sealed_path,
                expected_sha256=expected_sha,
                train_families=train_families,
                baseline_scars=baseline_scars,
            )

        # 3. Symlinked corpus MUST be rejected
        symlink_corpus = sealed_dir / "symlink_corpus.json"
        symlink_corpus.symlink_to(sealed_path)
        with self.assertRaisesRegex(PermissionError, "SECURITY_SYMLINK_REFUSED"):
            self.engine.run_sealed_blind_eval(
                symlink_corpus,
                expected_sha256=expected_sha,
                train_families=train_families,
                baseline_scars=baseline_scars,
            )

        # 4. Corpus placed inside workspace_root MUST be rejected
        inside_corpus = self.ws / "inside_heldout.json"
        inside_corpus.write_bytes(sealed_bytes)
        with self.assertRaisesRegex(PermissionError, "SEALED_CORPUS_MUST_BE_EXTERNAL"):
            self.engine.run_sealed_blind_eval(
                inside_corpus,
                expected_sha256=expected_sha,
                train_families=train_families,
                baseline_scars=baseline_scars,
            )


if __name__ == "__main__":
    unittest.main()
