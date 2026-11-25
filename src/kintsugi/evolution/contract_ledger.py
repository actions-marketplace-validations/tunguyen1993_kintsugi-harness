#!/usr/bin/env python3
"""Kintsugi v3.0 Counterexample-to-Contract Ledger (`src/kintsugi/evolution/contract_ledger.py`).

Implements Track D of the Kintsugi v3.0 architecture:
  1. 4 Falsifiable Domain Contracts (Commerce ERP + FinTech DeFi), each equipped with
     positive control, negative control (counterexample), near-miss outside precondition,
     and conservation checks:
       - `CONTRACT-CM-IDEMPOTENCY`: Commerce ERP Order/Stock Idempotency
       - `CONTRACT-CM-DECIMAL-FX`: Commerce MySQL Decimal Round-Trip & FX Rounding Conservation
       - `CONTRACT-MM-ERC4626-BOUNDED`: FinTech ERC-4626 Quote/Share Rounding with explicit
         mathematical precondition (`total_assets + V_ASSETS <= assets * (total_shares + V_SHARES)`)
       - `CONTRACT-MM-LEDGER-CONSERVATION`: FinTech Double-Entry Transfer & Self-Transfer Conservation
  2. Universal `Truth Gate` + Held-Out `Utility Gate` + 2-Strike Circuit-Breaker applying equally
     to EVERY proposer (Frontier AND Low-Tier alike — no model self-certifies!).
  3. Honest Multi-Client Delivery Support Matrix (`claude_code`, `antigravity`, `local_cli`, `cloud_sandbox`).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from kintsugi.evolution.fast_learner import RuntimeOutcome, validate_teacher_provenance


CLIENT_SUPPORT_MATRIX: Dict[str, Dict[str, Any]] = {
    "claude_code": {
        "mode": "integrated",
        "mechanism": "PostToolUse(Read) -> kintsugi-rs hook claude-post-read + PreToolUse(Write/Edit/Bash)",
        "auto_inject": True,
        "low_tier_lexicon_supported": True,
        "receipt_stages": ["issued", "included_in_input", "patch_bound"],
    },
    "antigravity": {
        "mode": "integrated",
        "mechanism": "MCP profile 'v3' -> kintsugi_read_with_context + kintsugi_low_tier_lexicon + kintsugi-rs gate",
        "auto_inject": True,
        "low_tier_lexicon_supported": True,
        "receipt_stages": ["issued", "included_in_input", "patch_bound"],
    },
    "local_cli": {
        "mode": "mediated",
        "mechanism": "MCP v3 OR CLI `kintsugi-rs task-pack <files...> --low-tier` for GLM-4-Flash / GLM-4-Flash",
        "auto_inject": False,
        "low_tier_lexicon_supported": True,
        "receipt_stages": ["issued", "included_in_input", "patch_bound"],
    },
    "cloud_sandbox": {
        "mode": "manual",
        "mechanism": "Manual task-pack paste + local `dot_preflight_guard.py` / `kintsugi-rs s3-audit --strict-proven`",
        "auto_inject": False,
        "low_tier_lexicon_supported": True,
        "receipt_stages": ["issued", "patch_bound"],
    },
}


# ---------------------------------------------------------------------------
# 4 Falsifiable Domain Contract Reference Oracles (Commerce ERP + FinTech DeFi)
# ---------------------------------------------------------------------------


def verify_contract_cm_idempotency(handler_factory: Callable[[], Any]) -> Dict[str, Any]:
    """CONTRACT-CM-IDEMPOTENCY: Commerce ERP Order/Stock Idempotency.

    Expected interface on `svc = handler_factory()`:
      - `svc.fulfill_order(idempotency_key: str, sku: str, qty: int) -> dict`
      - `svc.stock_of(sku: str) -> int` (initialized with >= 100 units for 'SKU-TEE-01')
      - `svc.movements_count() -> int`
    Controls:
      - Positive control: 1st delivery decrements stock by 3 and creates EXACTLY 1 movement (blocks no-op!).
      - Negative control (replay): 2nd identical delivery creates 0 new movements, preserves stock & receipt.
      - Conflict control: same idempotency_key with different qty/sku MUST raise ValueError!
      - Near-miss control: different idempotency_key for another order creates a 2nd distinct movement.
    """
    svc = handler_factory()
    start_stock = svc.stock_of("SKU-TEE-01")
    r1 = svc.fulfill_order("idem-ord-1001", "SKU-TEE-01", 3)
    pos_ok = (svc.stock_of("SKU-TEE-01") == start_stock - 3) and (svc.movements_count() == 1)

    r2 = svc.fulfill_order("idem-ord-1001", "SKU-TEE-01", 3)
    neg_replay_ok = (svc.stock_of("SKU-TEE-01") == start_stock - 3) and (svc.movements_count() == 1) and (r2 == r1)

    conflict_blocked = False
    try:
        svc.fulfill_order("idem-ord-1001", "SKU-TEE-01", 5)
    except ValueError:
        conflict_blocked = True

    svc.fulfill_order("idem-ord-1002", "SKU-TEE-01", 2)
    near_miss_ok = (svc.stock_of("SKU-TEE-01") == start_stock - 5) and (svc.movements_count() == 2)

    passed = pos_ok and neg_replay_ok and conflict_blocked and near_miss_ok
    return {
        "contract_id": "CONTRACT-CM-IDEMPOTENCY",
        "outcome": RuntimeOutcome.PASSED if passed else RuntimeOutcome.EXPECTED_PROPERTY_FAIL,
        "positive_control": pos_ok,
        "negative_control": neg_replay_ok and conflict_blocked,
        "near_miss_control": near_miss_ok,
        "conservation": (svc.stock_of("SKU-TEE-01") + 5 == start_stock),
    }


def verify_contract_cm_decimal_fx(convert_and_sum_fn: Callable[[List[str], str], Tuple[List[Decimal], Decimal]]) -> Dict[str, Any]:
    """CONTRACT-CM-DECIMAL-FX: Commerce MySQL DECIMAL round-trip & FX rounding conservation.

    `convert_and_sum_fn(raw_usd_strings, fx_rate_str) -> (line_totals_vnd, grand_total_vnd)`
    Must use exact Decimal (never binary float) and preserve `sum(line_totals) == grand_total`.
    """
    # Classic float trap: 0.1 + 0.2 = 0.30000000000000004 and 19.99 * 25450.335
    raw_lines = ["0.10", "0.20", "19.99", "33.33"]
    fx = "25450.335"
    lines, grand = convert_and_sum_fn(raw_lines, fx)

    exact_type_ok = isinstance(grand, Decimal) and all(isinstance(x, Decimal) for x in lines)
    expected_lines = [
        (Decimal(r) * Decimal(fx)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        for r in raw_lines
    ]
    expected_grand = sum(expected_lines, Decimal("0.00"))
    pos_ok = exact_type_ok and (lines == expected_lines) and (grand == expected_grand)
    conservation_ok = exact_type_ok and (sum(lines, Decimal("0.00")) == grand)

    # Near-miss: zero amount line must stay exact Decimal("0.00")
    z_lines, z_grand = convert_and_sum_fn(["0.00"], fx)
    near_miss_ok = (z_lines == [Decimal("0.00")]) and (z_grand == Decimal("0.00"))

    passed = pos_ok and conservation_ok and near_miss_ok
    return {
        "contract_id": "CONTRACT-CM-DECIMAL-FX",
        "outcome": RuntimeOutcome.PASSED if passed else RuntimeOutcome.EXPECTED_PROPERTY_FAIL,
        "positive_control": pos_ok,
        "negative_control": exact_type_ok and (grand == expected_grand),
        "near_miss_control": near_miss_ok,
        "conservation": conservation_ok,
    }


def verify_contract_mm_erc4626_bounded(mint_shares_fn: Callable[[int, int, int], int]) -> Dict[str, Any]:
    """CONTRACT-MM-ERC4626-BOUNDED: FinTech ERC-4626 Virtual Offset with explicit mathematical precondition.

    `mint_shares_fn(assets, total_shares, total_assets) -> shares` (V_SHARES=10**6, V_ASSETS=1).
    Explicit Precondition for `shares > 0`:
        `total_assets + V_ASSETS <= assets * (total_shares + V_SHARES)`
    Controls:
      - Positive control (within precondition): `assets=1, total_shares=0, total_assets=500_000` -> `shares == 1` (`> 0`).
      - Negative control (GPT-5.4's counterexample OUTSIDE precondition!):
        `assets=1, total_shares=0, total_assets=2_000_000` -> floor formula gives `0`;
        function MUST raise `ValueError` (explicit zero-share rejection), NEVER mint 0 shares silently!
      - Near-miss boundary: exact equality `total_assets = 999_999` (`999_999 + 1 == 1_000_000`) -> `shares == 1`.
    """
    s_pos = mint_shares_fn(1, 0, 500_000)
    pos_ok = (s_pos == 1)

    s_boundary = mint_shares_fn(1, 0, 999_999)
    near_miss_ok = (s_boundary == 1)

    # Counterexample from GPT-5.4: 1 * 1_000_000 // (2_000_000 + 1) == 0 -> must reject!
    zero_share_rejected = False
    try:
        res_oob = mint_shares_fn(1, 0, 2_000_000)
        zero_share_rejected = False if res_oob == 0 else False
    except ValueError:
        zero_share_rejected = True

    passed = pos_ok and near_miss_ok and zero_share_rejected
    return {
        "contract_id": "CONTRACT-MM-ERC4626-BOUNDED",
        "outcome": RuntimeOutcome.PASSED if passed else RuntimeOutcome.EXPECTED_PROPERTY_FAIL,
        "positive_control": pos_ok,
        "negative_control": zero_share_rejected,
        "near_miss_control": near_miss_ok,
        "conservation": pos_ok and zero_share_rejected,
    }


def verify_contract_mm_ledger_conservation(ledger_factory: Callable[[Dict[str, int]], Any]) -> Dict[str, Any]:
    """CONTRACT-MM-LEDGER-CONSERVATION: FinTech Double-Entry Transfer & Self-Transfer Invariance.

    Expected interface on `led = ledger_factory({"alice": 100, "bob": 50})`:
      - `led.transfer(src: str, dst: str, amount: int) -> None`
      - `led.balances() -> Dict[str, int]`
    Controls:
      - Positive control: transfer("alice", "bob", 40) updates balances to (60, 90), total == 150.
      - Self-transfer control (no deadlock + balance check): transfer("alice", "alice", 20) succeeds,
        balances remain (60, 90); transfer("alice", "alice", 999) raises ValueError!
      - Concurrency AB-BA deadlock control: 2 threads simultaneously doing alice->bob and bob->alice
        must terminate cleanly within 2s and preserve total == 150!
    """
    led = ledger_factory({"alice": 100, "bob": 50})
    total0 = sum(led.balances().values())
    led.transfer("alice", "bob", 40)
    b1 = led.balances()
    pos_ok = (b1["alice"] == 60 and b1["bob"] == 90 and sum(b1.values()) == total0)

    # Self-transfer valid & insufficient
    led.transfer("alice", "alice", 20)
    self_ok = (led.balances()["alice"] == 60)
    overdraw_blocked = False
    try:
        led.transfer("alice", "alice", 999)
    except ValueError:
        overdraw_blocked = True

    # AB-BA concurrency test
    errs: List[Exception] = []

    def worker(src: str, dst: str) -> None:
        try:
            for _ in range(25):
                led.transfer(src, dst, 1)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    t1 = threading.Thread(target=worker, args=("alice", "bob"))
    t2 = threading.Thread(target=worker, args=("bob", "alice"))
    t1.start()
    t2.start()
    t1.join(timeout=2.0)
    t2.join(timeout=2.0)
    no_deadlock = (not t1.is_alive()) and (not t2.is_alive()) and len(errs) == 0
    conservation_ok = sum(led.balances().values()) == total0

    passed = pos_ok and self_ok and overdraw_blocked and no_deadlock and conservation_ok
    return {
        "contract_id": "CONTRACT-MM-LEDGER-CONSERVATION",
        "outcome": RuntimeOutcome.PASSED if passed else RuntimeOutcome.EXPECTED_PROPERTY_FAIL,
        "positive_control": pos_ok,
        "negative_control": overdraw_blocked and no_deadlock,
        "near_miss_control": self_ok,
        "conservation": conservation_ok,
    }


# ---------------------------------------------------------------------------
# Truth Gate + Held-Out Utility Gate + 2-Strike Circuit-Breaker Ledger
# ---------------------------------------------------------------------------


@dataclass
class ContractCandidate:
    contract_id: str
    domain: str
    source_task_id: str
    precondition: str
    invariant_text: str
    oracle_digest: str
    proposer_model: str
    proposer_origin: str
    endpoint_url: str = ""
    thinking_signature_verified: Optional[bool] = None


class ContractLedger:
    """Persistent ledger enforcing Universal Truth Gate + Held-Out Utility Gate + 2-Strike Auto-Freeze."""

    def __init__(self, ledger_path: Path) -> None:
        self.ledger_path = ledger_path
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.write_text(json.dumps({"schema": "ContractLedger/3", "contracts": []}, indent=2) + "\n", encoding="utf-8")

    def _load(self) -> Dict[str, Any]:
        return json.loads(self.ledger_path.read_text(encoding="utf-8"))

    def _save(self, doc: Dict[str, Any]) -> None:
        self.ledger_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def evaluate_and_promote(
        self,
        candidate: ContractCandidate,
        *,
        broken_oracle_result: Dict[str, Any],
        fixed_oracle_result: Dict[str, Any],
        pinned_oracle_digest: str,
        held_out_ablation: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Promote candidate ONLY if BOTH Truth Gate AND Held-Out Utility Gate pass (for ALL models, incl. Frontier!)."""
        prov = validate_teacher_provenance(
            teacher_model=candidate.proposer_model,
            teacher_origin=candidate.proposer_origin,
            endpoint_url=candidate.endpoint_url,
            thinking_signature_verified=candidate.thinking_signature_verified,
        )

        # Gate 1: Universal Truth Gate (pinned oracle digest + counterexample fails + fixed passes all controls)
        truth_reasons: List[str] = []
        if candidate.oracle_digest != pinned_oracle_digest:
            truth_reasons.append("ORACLE_DIGEST_MISMATCH")
        if broken_oracle_result.get("outcome") != RuntimeOutcome.EXPECTED_PROPERTY_FAIL:
            truth_reasons.append(f"BROKEN_COUNTEREXAMPLE_INVALID:{broken_oracle_result.get('outcome')}")
        if fixed_oracle_result.get("outcome") != RuntimeOutcome.PASSED:
            truth_reasons.append(f"FIXED_ORACLE_FAILED:{fixed_oracle_result.get('outcome')}")
        for ctrl in ("positive_control", "negative_control", "near_miss_control", "conservation"):
            if not bool(fixed_oracle_result.get(ctrl)):
                truth_reasons.append(f"FIXED_CONTROL_FAILED:{ctrl}")
        truth_ok = len(truth_reasons) == 0

        if not truth_ok:
            return {
                "contract_id": candidate.contract_id,
                "status": "QUARANTINED_TRUTH_GATE_FAILED",
                "truth_ok": False,
                "truth_reasons": truth_reasons,
                "utility_ok": False,
                "proposer_provenance": prov,
            }

        # Gate 2: Held-Out Utility Gate (paired on/off ablation on a DIFFERENT held-out task!)
        utility_reasons: List[str] = []
        if not held_out_ablation:
            utility_reasons.append("MISSING_HELD_OUT_ABLATION")
        else:
            eval_task_id = str(held_out_ablation.get("eval_task_id") or "")
            if not eval_task_id or eval_task_id == candidate.source_task_id:
                utility_reasons.append("SELF_TASK_EVALUATION_FORBIDDEN")
            off_score = float(held_out_ablation.get("off_score", 0.0))
            on_score = float(held_out_ablation.get("on_score", 0.0))
            regressions = int(held_out_ablation.get("regressions", 0))
            out_of_domain_spam = int(held_out_ablation.get("out_of_domain_spam", 0))
            if regressions > 0:
                utility_reasons.append(f"HELD_OUT_REGRESSIONS:{regressions}")
            if out_of_domain_spam > 0:
                utility_reasons.append(f"OUT_OF_DOMAIN_SPAM:{out_of_domain_spam}")
            if on_score <= off_score:
                utility_reasons.append(f"NO_POSITIVE_UPLIFT:{on_score}<={off_score}")
        utility_ok = len(utility_reasons) == 0

        if not utility_ok:
            return {
                "contract_id": candidate.contract_id,
                "status": "QUARANTINED_UTILITY_GATE_FAILED",
                "truth_ok": True,
                "utility_ok": False,
                "utility_reasons": utility_reasons,
                "proposer_provenance": prov,
            }

        record = {
            "contract_id": candidate.contract_id,
            "domain": candidate.domain,
            "source_task_id": candidate.source_task_id,
            "precondition": candidate.precondition,
            "invariant_text": candidate.invariant_text,
            "oracle_digest": pinned_oracle_digest,
            "proposer_provenance": prov,
            "held_out_ablation": held_out_ablation,
            "wins": 1,
            "losses": 0,
            "consecutive_losses": 0,
            "frozen": False,
            "content_sha256": hashlib.sha256(
                f"{candidate.contract_id}:{candidate.precondition}:{candidate.invariant_text}".encode("utf-8")
            ).hexdigest()[:16],
        }
        doc = self._load()
        items = [c for c in doc.get("contracts", []) if c.get("contract_id") != candidate.contract_id]
        items.append(record)
        doc["contracts"] = items
        self._save(doc)
        return {
            "contract_id": candidate.contract_id,
            "status": "PROMOTED_ACTIVE",
            "truth_ok": True,
            "utility_ok": True,
            "proposer_provenance": prov,
            "record": record,
        }

    def record_outcome(self, contract_id: str, success: bool) -> Optional[Dict[str, Any]]:
        """2-Strike Consecutive Regression Auto-Freeze circuit-breaker (`consecutive_losses >= 2`)."""
        doc = self._load()
        updated = None
        for c in doc.get("contracts", []):
            if c.get("contract_id") == contract_id:
                if success:
                    c["wins"] = int(c.get("wins", 0)) + 1
                    c["consecutive_losses"] = 0
                else:
                    c["losses"] = int(c.get("losses", 0)) + 1
                    c["consecutive_losses"] = int(c.get("consecutive_losses", 0)) + 1
                if c["consecutive_losses"] >= 2:
                    c["frozen"] = True
                updated = c
                break
        if updated is not None:
            self._save(doc)
        return updated
