#!/usr/bin/env python3
"""End-to-end verification suite for Kintsugi v3.0:
  - Mũi A: Typed Obligation Prover (live Rust CLI confusion matrix + DeepSeek SQL_EXEC:403 + multiline subprocess)
  - Mũi B: ContextEnvelope + PostToolUse(Read) + task-pack --low-tier + MCP v3 (preserving build3 == 23!)
  - Mũi C: Verified Patch Transaction Controller (no-op blocked, stale CAS rollback, oracle tamper, allowlist, signed receipt)
  - Mũi D: 4 Falsifiable Domain Contracts + Universal Truth Gate + Held-Out Utility Gate + Low-Tier Lexicon (LT-001..LT-018)
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Dict, List, Tuple

OSS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(OSS / "src"))

from kintsugi.evolution.contract_ledger import (
    CLIENT_SUPPORT_MATRIX,
    ContractCandidate,
    ContractLedger,
    verify_contract_cm_decimal_fx,
    verify_contract_cm_idempotency,
    verify_contract_mm_erc4626_bounded,
    verify_contract_mm_ledger_conservation,
)
from kintsugi.evolution.fast_learner import RuntimeOutcome
from kintsugi.evolution.patch_transaction import (
    OracleRunResult,
    PatchTransactionSpec,
    VerifiedPatchTransactionController,
    compute_tree_digest,
)
from kintsugi.mcp_server import KintsugiMCPServer


def _find_kintsugi_bin() -> Path:
    env_bin = os.environ.get("KINTSUGI_RS_BIN", "").strip()
    which_bin = shutil.which("kintsugi-rs")
    for cand in (
        *( [Path(env_bin)] if env_bin else [] ),
        OSS / "target/release/kintsugi-rs",
        OSS / "target/debug/kintsugi-rs",
        *( [Path(which_bin)] if which_bin else [] ),
    ):
        if cand.is_file():
            return cand
    return OSS / "target/release/kintsugi-rs"


KBIN = _find_kintsugi_bin()


class TestKintsugiV3BreakthroughSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="kintsugi_v3_suite_"))

    # -----------------------------------------------------------------------
    # Mũi C: Verified Patch Transaction Controller
    # -----------------------------------------------------------------------
    def _make_tx_workspace(self) -> Tuple[Path, Path, Path]:
        ws = self.tmp / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "service.py").write_text(
            "def add_order(cursor, oid):\n"
            "    sql = f'SELECT * FROM orders WHERE id = {oid}'\n"
            "    cursor.execute(sql)\n"
            "    return True\n\n"
            "def untouched_helper(x):\n"
            "    return x + 1\n",
            encoding="utf-8",
        )
        oracle_dir = self.tmp / "oracle"
        oracle_dir.mkdir(parents=True, exist_ok=True)
        oracle_file = oracle_dir / "oracle_spec.py"
        oracle_file.write_text("# pinned oracle spec v3\n", encoding="utf-8")
        receipts = self.tmp / "receipts"
        return ws, oracle_file, receipts

    def test_01_patch_tx_rejects_noop_stale_cas_tamper_scope_and_promotes_cleanly(self) -> None:
        ws, oracle_file, receipts = self._make_tx_workspace()
        base_digest = compute_tree_digest(ws)

        def good_oracle(checkout: Path) -> OracleRunResult:
            src = (checkout / "service.py").read_text(encoding="utf-8")
            if "f'SELECT" in src:
                return OracleRunResult(
                    outcome=RuntimeOutcome.EXPECTED_PROPERTY_FAIL,
                    observed_test_ids=("t_pos", "t_neg", "t_cons"),
                    passed_test_ids=("t_pos",),
                    failed_test_ids=("t_neg",),
                    positive_control_passed=True,
                    negative_control_passed=False,
                    conservation_passed=True,
                    detail="SQL injection present",
                )
            if "return False" in src:  # No-op shortcut fails positive control!
                return OracleRunResult(
                    outcome=RuntimeOutcome.PASSED,
                    observed_test_ids=("t_pos", "t_neg", "t_cons"),
                    passed_test_ids=("t_pos", "t_neg", "t_cons"),
                    failed_test_ids=(),
                    positive_control_passed=False,
                    negative_control_passed=True,
                    conservation_passed=True,
                    detail="no-op shortcut",
                )
            return OracleRunResult(
                outcome=RuntimeOutcome.PASSED,
                observed_test_ids=("t_pos", "t_neg", "t_cons"),
                passed_test_ids=("t_pos", "t_neg", "t_cons"),
                failed_test_ids=(),
                positive_control_passed=True,
                negative_control_passed=True,
                conservation_passed=True,
                detail="all controls passed",
            )

        # (a) Receipt dir inside workspace MUST raise PermissionError
        with self.assertRaises(PermissionError):
            VerifiedPatchTransactionController(
                PatchTransactionSpec(
                    tx_id="bad_rcpt",
                    workspace_root=ws,
                    allowed_files=("service.py",),
                    oracle_manifest_files=(oracle_file,),
                    expected_test_ids=("t_pos", "t_neg", "t_cons"),
                    external_receipt_dir=ws / "receipts",
                )
            )

        # (b) No-op patch blocked by positive control; outside-allowlist & outside-symbol blocked!
        ctrl_noop = VerifiedPatchTransactionController(
            PatchTransactionSpec(
                tx_id="tx_noop",
                workspace_root=ws,
                allowed_files=("service.py",),
                allowed_symbols=("add_order",),
                oracle_manifest_files=(oracle_file,),
                expected_test_ids=("t_pos", "t_neg", "t_cons"),
                external_receipt_dir=receipts,
                kintsugi_bin=KBIN,
            )
        )
        res_noop = ctrl_noop.execute_transaction(
            proposer_fn=lambda attempt, _fb: (
                {"tests/evil.py": "pass"}
                if attempt == 1
                else {
                    "service.py": (
                        "def add_order(cursor, oid):\n"
                        "    sql = 'SELECT * FROM orders WHERE id = ?'\n"
                        "    cursor.execute(sql, (oid,))\n"
                        "    return False\n\n"
                        "def untouched_helper(x):\n"
                        "    return x + 1\n"
                    )
                }
            ),
            oracle_runner_fn=good_oracle,
        )
        self.assertEqual(res_noop["status"], "NO_PROMOTION")
        self.assertEqual(res_noop["attempts"][0]["status"], "REJECTED_SCOPE")
        self.assertEqual(res_noop["attempts"][1]["reason"], "POSITIVE_CONTROL_FAILED_NOOP_OR_SHORTCUT")
        self.assertEqual(compute_tree_digest(ws), base_digest)

        # (c) SETUP_ERROR baseline aborts cleanly
        res_setup = ctrl_noop.execute_transaction(
            proposer_fn=lambda _a, _fb: {},
            oracle_runner_fn=lambda _c: OracleRunResult(
                RuntimeOutcome.SETUP_ERROR, (), (), (), False, False, False, "ImportError"
            ),
        )
        self.assertEqual(res_setup["status"], "NO_PROMOTION")
        self.assertIn("SETUP_ERROR", res_setup["reason"])

        # (d) Stale-base CAS race blocks promote cleanly!
        ctrl_race = VerifiedPatchTransactionController(
            PatchTransactionSpec(
                tx_id="tx_race",
                workspace_root=ws,
                allowed_files=("service.py",),
                allowed_symbols=("add_order",),
                oracle_manifest_files=(oracle_file,),
                expected_test_ids=("t_pos", "t_neg", "t_cons"),
                external_receipt_dir=receipts,
                kintsugi_bin=KBIN,
            )
        )

        def racy_proposer(_attempt: int, _fb: str | None) -> Dict[str, str]:
            # Mutate live workspace behind controller's back -> triggers CAS mismatch!
            (ws / "concurrent_edit.txt").write_text("concurrent commit\n", encoding="utf-8")
            return {
                "service.py": (
                    "def add_order(cursor, oid):\n"
                    "    sql = 'SELECT * FROM orders WHERE id = ?'\n"
                    "    cursor.execute(sql, (oid,))\n"
                    "    return True\n\n"
                    "def untouched_helper(x):\n"
                    "    return x + 1\n"
                )
            }

        res_race = ctrl_race.execute_transaction(proposer_fn=racy_proposer, oracle_runner_fn=good_oracle)
        self.assertEqual(res_race["status"], "NO_PROMOTION")
        self.assertIn("STALE_BASE_CAS_MISMATCH", res_race["reason"])
        (ws / "concurrent_edit.txt").unlink()

        # (e) Clean happy path promotes atomically & writes external HMAC-signed receipt!
        ctrl_ok = VerifiedPatchTransactionController(
            PatchTransactionSpec(
                tx_id="tx_happy",
                workspace_root=ws,
                allowed_files=("service.py",),
                allowed_symbols=("add_order",),
                oracle_manifest_files=(oracle_file,),
                expected_test_ids=("t_pos", "t_neg", "t_cons"),
                external_receipt_dir=receipts,
                kintsugi_bin=KBIN,
                receipt_hmac_key=b"kintsugi-test-key",
            )
        )
        res_ok = ctrl_ok.execute_transaction(
            proposer_fn=lambda _a, _fb: {
                "service.py": (
                    "def add_order(cursor, oid):\n"
                    "    sql = 'SELECT * FROM orders WHERE id = ?'\n"
                    "    cursor.execute(sql, (oid,))\n"
                    "    return True\n\n"
                    "def untouched_helper(x):\n"
                    "    return x + 1\n"
                )
            },
            oracle_runner_fn=good_oracle,
        )
        self.assertEqual(res_ok["status"], "PROMOTED")
        self.assertEqual(res_ok["receipt_stage"], "patch_bound")
        self.assertEqual(res_ok["s3_audit"]["verdict"], "PASS_S3_LOCKED")
        rcpt = json.loads(Path(res_ok["receipt_path"]).read_text(encoding="utf-8"))
        self.assertIn("receipt_hmac_sha256", rcpt)

    # -----------------------------------------------------------------------
    # Mũi D: 4 Falsifiable Domain Contracts + Truth Gate + Utility Gate
    # -----------------------------------------------------------------------
    def test_02_four_domain_contracts_catch_bugs_and_pass_verified_implementations(self) -> None:
        # 1. CONTRACT-CM-IDEMPOTENCY (Broken: replays debit twice vs Fixed: payload-hash bound)
        class BrokenOrderSvc:
            def __init__(self) -> None:
                self.stock = {"SKU-TEE-01": 100}
                self.moves = 0

            def fulfill_order(self, key: str, sku: str, qty: int) -> dict:
                self.stock[sku] -= qty
                self.moves += 1
                return {"key": key, "sku": sku, "qty": qty}

            def stock_of(self, sku: str) -> int:
                return self.stock[sku]

            def movements_count(self) -> int:
                return self.moves

        class FixedOrderSvc:
            def __init__(self) -> None:
                self.stock = {"SKU-TEE-01": 100}
                self.moves = 0
                self.seen: Dict[str, Tuple[str, dict]] = {}

            def fulfill_order(self, key: str, sku: str, qty: int) -> dict:
                ph = hashlib.sha256(f"{sku}:{qty}".encode()).hexdigest()
                if key in self.seen:
                    prev_ph, prev_rcpt = self.seen[key]
                    if prev_ph != ph:
                        raise ValueError("idempotency payload conflict")
                    return prev_rcpt
                self.stock[sku] -= qty
                self.moves += 1
                rcpt = {"key": key, "sku": sku, "qty": qty, "move": self.moves}
                self.seen[key] = (ph, rcpt)
                return rcpt

            def stock_of(self, sku: str) -> int:
                return self.stock[sku]

            def movements_count(self) -> int:
                return self.moves

        self.assertEqual(verify_contract_cm_idempotency(BrokenOrderSvc)["outcome"], RuntimeOutcome.EXPECTED_PROPERTY_FAIL)
        cm_idem_ok = verify_contract_cm_idempotency(FixedOrderSvc)
        self.assertEqual(cm_idem_ok["outcome"], RuntimeOutcome.PASSED)

        # 2. CONTRACT-CM-DECIMAL-FX (Broken: binary float vs Fixed: exact Decimal ROUND_HALF_UP)
        def broken_fx(raws: List[str], fx: str):
            ls = [round(float(r) * float(fx), 2) for r in raws]
            return ls, sum(ls)

        def fixed_fx(raws: List[str], fx: str):
            rate = Decimal(str(fx))
            ls = [(Decimal(str(r)) * rate).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) for r in raws]
            return ls, sum(ls, Decimal("0.00"))

        self.assertEqual(verify_contract_cm_decimal_fx(broken_fx)["outcome"], RuntimeOutcome.EXPECTED_PROPERTY_FAIL)
        self.assertEqual(verify_contract_cm_decimal_fx(fixed_fx)["outcome"], RuntimeOutcome.PASSED)

        # 3. CONTRACT-MM-ERC4626-BOUNDED (Catches old flawed CAP-FIN-ERC4626 that returns 0 silently!)
        def old_flawed_erc4626(assets: int, total_shares: int, total_assets: int) -> int:
            return (assets * (total_shares + 10**6)) // (total_assets + 1)

        def fixed_bounded_erc4626(assets: int, total_shares: int, total_assets: int) -> int:
            shares = (assets * (total_shares + 10**6)) // (total_assets + 1)
            if shares <= 0:
                raise ValueError("zero shares outside mathematical precondition")
            return shares

        self.assertEqual(verify_contract_mm_erc4626_bounded(old_flawed_erc4626)["outcome"], RuntimeOutcome.EXPECTED_PROPERTY_FAIL)
        mm_erc_ok = verify_contract_mm_erc4626_bounded(fixed_bounded_erc4626)
        self.assertEqual(mm_erc_ok["outcome"], RuntimeOutcome.PASSED)

        # 4. CONTRACT-MM-LEDGER-CONSERVATION (Broken: ignores overdraw on self-transfer vs Fixed: sorted locks + single-lock self-transfer)
        class BrokenLedger:
            def __init__(self, init: Dict[str, int]) -> None:
                self._bal = dict(init)

            def transfer(self, src: str, dst: str, amt: int) -> None:
                if src == dst:
                    return  # Bug: skips insufficient balance check!
                self._bal[src] -= amt
                self._bal[dst] += amt

            def balances(self) -> Dict[str, int]:
                return dict(self._bal)

        class FixedLedger:
            def __init__(self, init: Dict[str, int]) -> None:
                self._bal = dict(init)
                self._locks = {k: threading.Lock() for k in init}

            def transfer(self, src: str, dst: str, amt: int) -> None:
                if amt <= 0:
                    raise ValueError("amount must be positive")
                if src == dst:
                    with self._locks[src]:
                        if self._bal[src] < amt:
                            raise ValueError("insufficient balance")
                        return
                a, b = sorted((src, dst))
                with self._locks[a]:
                    with self._locks[b]:
                        if self._bal[src] < amt:
                            raise ValueError("insufficient balance")
                        self._bal[src] -= amt
                        self._bal[dst] += amt

            def balances(self) -> Dict[str, int]:
                return dict(self._bal)

        self.assertEqual(verify_contract_mm_ledger_conservation(BrokenLedger)["outcome"], RuntimeOutcome.EXPECTED_PROPERTY_FAIL)
        self.assertEqual(verify_contract_mm_ledger_conservation(FixedLedger)["outcome"], RuntimeOutcome.PASSED)

        # Ledger Truth Gate + Held-Out Utility Gate + 2-Strike Auto-Freeze!
        ledger = ContractLedger(self.tmp / "contract_ledger.json")
        cand = ContractCandidate(
            contract_id="CONTRACT-MM-ERC4626-BOUNDED",
            domain="fintech-vault",
            source_task_id="task_vault_01",
            precondition="total_assets + V_ASSETS <= assets * (total_shares + V_SHARES)",
            invariant_text="Reject shares <= 0 when donation exceeds virtual shares offset.",
            oracle_digest="sha256:pinned_erc4626",
            proposer_model="GPT-5.4",
            proposer_origin="openai_codex_official",
            endpoint_url="https://chatgpt.com/backend-api/codex/responses",
        )
        # Same task ID in held-out ablation MUST be rejected!
        r_self = ledger.evaluate_and_promote(
            cand,
            broken_oracle_result=verify_contract_mm_erc4626_bounded(old_flawed_erc4626),
            fixed_oracle_result=mm_erc_ok,
            pinned_oracle_digest="sha256:pinned_erc4626",
            held_out_ablation={"eval_task_id": "task_vault_01", "off_score": 0.5, "on_score": 0.9, "regressions": 0},
        )
        self.assertEqual(r_self["status"], "QUARANTINED_UTILITY_GATE_FAILED")

        # Distinct held-out task with positive uplift & 0 regressions -> PROMOTED_ACTIVE!
        r_prom = ledger.evaluate_and_promote(
            cand,
            broken_oracle_result=verify_contract_mm_erc4626_bounded(old_flawed_erc4626),
            fixed_oracle_result=mm_erc_ok,
            pinned_oracle_digest="sha256:pinned_erc4626",
            held_out_ablation={"eval_task_id": "task_vault_heldout_02", "off_score": 0.6, "on_score": 0.95, "regressions": 0},
        )
        self.assertEqual(r_prom["status"], "PROMOTED_ACTIVE")
        self.assertFalse(ledger.record_outcome(cand.contract_id, False)["frozen"])
        self.assertTrue(ledger.record_outcome(cand.contract_id, False)["frozen"])

    # -----------------------------------------------------------------------
    # Mũi A + B + Low-Tier Lexicon CLI & MCP v3 Verification
    # -----------------------------------------------------------------------
    def test_03_rust_cli_context_lexicon_taskpack_postread_and_mcp_v3_compat(self) -> None:
        self.assertEqual(set(CLIENT_SUPPORT_MATRIX.keys()), {"claude_code", "antigravity", "local_cli", "cloud_sandbox"})

        sample = self.tmp / "deepseek_sql.py"
        sample.write_text(
            "import subprocess\n"
            "def query_receipt_by_id(cursor, receipt_id):\n"
            "    sql = 'SELECT payload_json FROM settlement_receipts WHERE receipt_id = ?'\n"
            "    cursor.execute(sql, (receipt_id,))\n"
            "    return cursor.fetchone()\n\n"
            "def run_tool(bin_real, target_real):\n"
            "    return subprocess.run(\n"
            "        [bin_real, '--verify', target_real],\n"
            "        capture_output=True,\n"
            "        text=True,\n"
            "        timeout=5,\n"
            "        check=False,\n"
            "        shell=False,\n"
            "    )\n",
            encoding="utf-8",
        )

        # 1. Native Rust s3-audit --strict-proven MUST PASS on DeepSeek SQL var + 7-line subprocess.run!
        p_s3 = subprocess.run([str(KBIN), "s3-audit", str(sample), "--strict-proven", "--format", "json"], capture_output=True, text=True, shell=False, check=True)
        j_s3 = json.loads(p_s3.stdout)
        self.assertEqual(j_s3["verdict"], "PASS_S3_LOCKED")
        self.assertEqual(j_s3["strict_verdict"], "PASS_S3_PROVEN")
        self.assertEqual(j_s3["proven_s3_seams"], 2)

        # 2. Native Rust context envelope with --low-tier
        p_ctx = subprocess.run([str(KBIN), "context", str(sample), "--low-tier", "--format", "json"], capture_output=True, text=True, shell=False, check=True)
        j_ctx = json.loads(p_ctx.stdout)
        self.assertEqual(j_ctx["schema"], "ContextEnvelope/3")
        self.assertEqual(j_ctx["receipt_stage"], "issued")
        self.assertLessEqual(j_ctx["estimated_tokens"], 320)
        self.assertTrue(len(j_ctx["lexicon_ids"]) >= 1)

        # 3. Native Rust lexicon --all returns 62 pitfalls (LT-001..LT-062)
        p_lex = subprocess.run([str(KBIN), "lexicon", "--all", "--format", "json"], capture_output=True, text=True, shell=False, check=True)
        j_lex = json.loads(p_lex.stdout)
        self.assertEqual(j_lex["total_lexicon_entries"], 62)

        # 4. Claude Code PostToolUse(Read) hook emits additionalContext + bound source_digest
        hook_payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": str(sample)}})
        p_hook = subprocess.run([str(KBIN), "hook", "claude-post-read", "--low-tier"], input=hook_payload, capture_output=True, text=True, shell=False, check=True)
        j_hook = json.loads(p_hook.stdout)
        self.assertEqual(j_hook["hookSpecificOutput"]["hookEventName"], "PostToolUse")
        self.assertEqual(j_hook["kintsugiEnvelope"]["source_digest"], j_ctx["source_digest"])

        # 5. MCP profile backward compatibility (downstream pins default=9, nextgen=19, build3=23) + v3=25!
        scars_p = self.tmp / "scars.json"
        counts = {}
        for prof in ("default", "nextgen", "build3", "v3"):
            srv = KintsugiMCPServer(scars_p, profile=prof)
            counts[prof] = len(srv.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"])
        self.assertEqual(counts, {"default": 9, "nextgen": 19, "build3": 23, "v3": 25})

        srv_v3 = KintsugiMCPServer(scars_p, profile="v3")
        mcp_resp = srv_v3.handle_request({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "kintsugi_read_with_context", "arguments": {"file_path": str(sample), "low_tier": True}},
        })
        self.assertFalse(mcp_resp["result"]["isError"])
        mcp_data = json.loads(mcp_resp["result"]["content"][0]["text"])
        self.assertEqual(mcp_data["envelope"]["receipt_stage"], "included_in_input")
        self.assertEqual(mcp_data["envelope"]["source_digest"], j_ctx["source_digest"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
