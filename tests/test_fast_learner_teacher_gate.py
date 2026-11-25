#!/usr/bin/env python3
"""Unit tests for KintsugiFastLearner v3.0 Hardened Promotion Boundary, Universal Truth Gate & 2-Strike Auto-Freeze."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from kintsugi.evolution.fast_learner import (
    KintsugiFastLearner,
    RuntimeOutcome,
    validate_teacher_provenance,
    verify_runtime_broken_to_fixed,
)


def _find_kintsugi_bin() -> Path:
    env_bin = os.environ.get("KINTSUGI_RS_BIN", "").strip()
    which_bin = shutil.which("kintsugi-rs")
    for cand in (
        *( [Path(env_bin)] if env_bin else [] ),
        REPO_ROOT / "target/release/kintsugi-rs",
        REPO_ROOT / "target/debug/kintsugi-rs",
        *( [Path(which_bin)] if which_bin else [] ),
    ):
        if cand.is_file():
            return cand
    return REPO_ROOT / "target/release/kintsugi-rs"


KBIN = _find_kintsugi_bin()

BROKEN_MERKLE = """
import hashlib
def build_root(items):
    nodes = [hashlib.sha256(x.encode()).digest() for x in items]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(nodes[i] + nodes[i+1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0].hex()
"""

FIXED_MERKLE = """
import hashlib
def build_root(items):
    nodes = [hashlib.sha256(b"\\x00" + x.encode()).digest() for x in items]
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                nxt.append(hashlib.sha256(b"\\x01" + nodes[i] + nodes[i+1]).digest())
            else:
                nxt.append(nodes[i])
        nodes = nxt
    return nodes[0].hex()
"""

SAMPLE_CAPSULE_JSON = json.dumps({
    "kind": "capsule",
    "capsule": {
        "id": "CAP-AUTO-MERKLE-ODD",
        "domain": "crypto-merkle",
        "trigger_groups": [["build_root", "merkle"], ["sha256", "nodes"]],
        "when_clause": "Odd-length hash tree level reduction",
        "invariant": "Promote odd trailing node without duplication; for `-> bool` verifiers return False on invalid direction.",
        "pos_ast": "len(nodes) % 2 == 1 -> promote without append(nodes[-1])",
    },
})


def _real_runtime_merkle_check(code_src: str):
    """Real Python runtime test returning typed RuntimeOutcome."""
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as tf:
        tf.write(code_src)
        mod_path = Path(tf.name)
    try:
        spec = importlib.util.spec_from_file_location("merkle_runtime_probe", mod_path)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        r3 = mod.build_root(["a", "b", "c"])
        r4 = mod.build_root(["a", "b", "c", "c"])
        if r3 != r4:
            return RuntimeOutcome.PASSED, "distinct odd vs duplicated roots"
        return RuntimeOutcome.EXPECTED_PROPERTY_FAIL, "odd trailing leaf duplicated"
    finally:
        mod_path.unlink(missing_ok=True)


class TestFastLearnerTeacherGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="kintsugi_teacher_gate_"))
        self.clean_py = self.tmp / "clean_baseline.py"
        self.clean_py.write_text("def greet(name: str) -> str:\n    return f'hello {name}'\n", encoding="utf-8")
        self.learner = KintsugiFastLearner(
            kintsugi_bin=KBIN,
            active_rules_dir=self.tmp / "active_rules",
            quarantine_dir=self.tmp / "quarantine",
            capsules_json_path=self.tmp / "capsules.json",
            clean_corpus_paths=[self.clean_py],
        )

    def test_01_relay_spoofed_opus55_and_empty_host_and_null_sig_are_blocked(self) -> None:
        prov_relay = validate_teacher_provenance(
            teacher_model="claude-opus-4-5",
            teacher_origin="anthropic_official",
            endpoint_url="https://relay.unverified-proxy.example/v1/messages",
            thinking_signature_verified=False,
        )
        self.assertFalse(prov_relay["is_genuine_frontier"])

        # GPT-5.4 catch #2: empty endpoint_url + thinking_signature_verified=None MUST NOT pass!
        prov_empty = validate_teacher_provenance(
            teacher_model="claude-opus-4-6-thinking",
            teacher_origin="anthropic_official",
            endpoint_url="",
            thinking_signature_verified=None,
        )
        self.assertFalse(prov_empty["is_genuine_frontier"])
        self.assertTrue(any("missing_endpoint_host" in r for r in prov_empty["reasons"]))
        self.assertTrue(any("thinking_signature_unverified" in r for r in prov_empty["reasons"]))

        # Genuine Codex GPT-5.4 on chatgpt.com PASSES provenance
        prov_astra = validate_teacher_provenance(
            teacher_model="GPT-5.4",
            teacher_origin="openai_codex_official",
            endpoint_url="https://chatgpt.com/backend-api/codex/responses",
        )
        self.assertTrue(prov_astra["is_genuine_frontier"])

    def test_02_setup_error_timeout_and_no_tests_rejected_as_invalid_runtime_proof(self) -> None:
        for bad_outcome in (
            RuntimeOutcome.SETUP_ERROR,
            RuntimeOutcome.IMPORT_ERROR,
            RuntimeOutcome.TIMEOUT,
            RuntimeOutcome.NO_TESTS,
        ):
            res = verify_runtime_broken_to_fixed(
                BROKEN_MERKLE,
                FIXED_MERKLE,
                lambda src, bo=bad_outcome: (bo, "env broke") if "append(nodes[-1])" in src else (RuntimeOutcome.PASSED, "ok"),
            )
            self.assertFalse(res["verified"], f"{bad_outcome} must never count as broken-code proof")
            self.assertEqual(res["broken_outcome"], bad_outcome.value)

        # Legacy bool=False with ImportError detail is also caught fail-closed!
        legacy_err = verify_runtime_broken_to_fixed(
            BROKEN_MERKLE,
            FIXED_MERKLE,
            lambda src: (False, "ModuleNotFoundError: No module named 'foo'") if "append" in src else (True, "ok"),
        )
        self.assertFalse(legacy_err["verified"])
        self.assertEqual(legacy_err["broken_outcome"], RuntimeOutcome.IMPORT_ERROR.value)

    def test_03_low_tier_model_promoted_only_with_runtime_and_zero_regression_canary(self) -> None:
        res_no_rt = self.learner.learn_from_diff_generalized(
            bug_id="LOW-01",
            broken_code=BROKEN_MERKLE,
            fixed_code=FIXED_MERKLE,
            failure_summary="Odd leaf forgery",
            llm_proposer=lambda _p: SAMPLE_CAPSULE_JSON,
            teacher_model="gemini-4-hydrogen-low",
            teacher_origin="antigravity_native",
        )
        self.assertEqual(res_no_rt["status"], "QUARANTINED_UNTRUSTED_TEACHER_REQUIRES_RUNTIME_PROOF")

        res_ok = self.learner.learn_from_diff_generalized(
            bug_id="LOW-PASS-01",
            broken_code=BROKEN_MERKLE,
            fixed_code=FIXED_MERKLE,
            failure_summary="Odd leaf forgery",
            llm_proposer=lambda _p: SAMPLE_CAPSULE_JSON,
            teacher_model="gemini-4-hydrogen-low",
            teacher_origin="antigravity_native",
            runtime_test_fn=_real_runtime_merkle_check,
            canary_eval_fn=lambda _cap: {"score_raw": 17, "score_with_capsule": 20, "regressions": 0},
        )
        self.assertEqual(res_ok["status"], "PROMOTED_ACTIVE")
        self.assertTrue(res_ok["runtime_proof"]["verified"])

        # 2-Strike consecutive regression auto-freeze!
        u1 = self.learner.record_capsule_bandit_outcome("CAP-AUTO-MERKLE-ODD", success=False)
        self.assertFalse(u1["frozen"])
        u2 = self.learner.record_capsule_bandit_outcome("CAP-AUTO-MERKLE-ODD", success=False)
        self.assertTrue(u2["frozen"])
        self.assertEqual(u2["consecutive_losses"], 2)

    def test_04_universal_truth_gate_blocks_even_frontier_without_runtime_proof(self) -> None:
        # Kintsugi v3.0 core law: EVEN Frontier cannot self-certify without independent Truth Proof!
        res_blocked = self.learner.learn_from_diff_generalized(
            bug_id="FRONTIER-NO-PROOF",
            broken_code=BROKEN_MERKLE,
            fixed_code=FIXED_MERKLE,
            failure_summary="Unverified Frontier claim",
            llm_proposer=lambda _p: SAMPLE_CAPSULE_JSON,
            teacher_model="claude-opus-4-6-thinking",
            teacher_origin="antigravity_native",
            thinking_signature_verified=True,
        )
        self.assertEqual(res_blocked["status"], "QUARANTINED_TRUTH_GATE_REQUIRED")

        # Frontier WITH real runtime truth proof promotes cleanly!
        res_ok = self.learner.learn_from_diff_generalized(
            bug_id="FRONTIER-VERIFIED",
            broken_code=BROKEN_MERKLE,
            fixed_code=FIXED_MERKLE,
            failure_summary="Verified Frontier Opus 4.6 capsule",
            llm_proposer=lambda _p: SAMPLE_CAPSULE_JSON,
            teacher_model="claude-opus-4-6-thinking",
            teacher_origin="antigravity_native",
            thinking_signature_verified=True,
            runtime_test_fn=_real_runtime_merkle_check,
        )
        self.assertEqual(res_ok["status"], "PROMOTED_ACTIVE")
        self.assertEqual(res_ok["teacher_provenance"]["tier"], "FRONTIER_GENUINE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
