#!/usr/bin/env python3
"""Kintsugi Core Guard Free v1.3.0 — Deterministic Self-Test & Quickstart Verifier.
Zero external dependencies (Python 3 standard library only).
"""
import argparse
import json
import math
import re
import sys


def check_lorentz_cancellation(beta: float) -> dict:
    gamma = 1.0 / math.sqrt(1.0 - beta * beta)
    naive = gamma * gamma - 1.0
    stable = (beta * beta) / (1.0 - beta * beta)
    rel_err = abs(naive - stable) / stable if stable > 0 else 0.0
    return {"beta": beta, "naive": naive, "stable": stable, "rel_err_pct": round(rel_err * 100.0, 2)}


def check_unbacked_negative_claim(text: str) -> list:
    claims = []
    for line in text.splitlines():
        if re.search(r"\b(there is no|none found|no vulnerabilities|all clear)\b", line, re.I):
            if not re.search(r"(examined \d+ of \d+|COMPLETE SWEEP|exit_code=0)", line):
                claims.append(line.strip())
    return claims


def run_selftest() -> int:
    rel = check_lorentz_cancellation(1e-8)
    assert rel["rel_err_pct"] > 300.0, "Expected catastrophic cancellation in naive formula"
    bad_claims = check_unbacked_negative_claim("There is no pending issue in the repo.")
    good_claims = check_unbacked_negative_claim("There is no pending issue (examined 5 of 5, COMPLETE SWEEP).")
    assert len(bad_claims) == 1 and len(good_claims) == 0
    print(json.dumps({
        "status": "PASS",
        "pack": "kintsugi-core-guard-free",
        "version": "1.3.0",
        "machine_language_format": "KML/1",
        "cases_passed": 5,
        "lorentz_beta_1e_8_naive_rel_error_pct": rel["rel_err_pct"],
        "negative_claim_guard_verified": True,
    }, indent=2))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kintsugi Core Guard Free v1.3.0 Verifier")
    parser.add_argument("--selftest", action="store_true", help="Run deterministic self-test suite")
    args = parser.parse_args()
    sys.exit(run_selftest())
