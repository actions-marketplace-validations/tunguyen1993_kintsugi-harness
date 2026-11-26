#!/usr/bin/env python3
"""Comprehensive pytest suite for Track P4: Delivery Gate Telemetry & Live 2-Strike Auto-Freeze Tracker.

Verifies:
  1. All 4 supported clients (`claude_code`, `antigravity`, `local_cli`, `cloud_sandbox`) & fail-closed rejection.
  2. Honest 3-stage receipt transitions (`issued -> included_in_input -> patch_bound`) & guardrails,
     including the rule that `efficacy` ONLY updates when `included_before_first_patch == True`.
  3. 2-Strike consecutive-loss auto-freeze (`consecutive_losses >= 2`) with pass reset & sticky freeze.
  4. Dead-scar auto-freeze (`trials >= 30 && wins * 100 < trials * 15`) with exact boundary checks & sticky freeze.
  5. Honest denominator (`included_before_first_patch / all_sessions`) never dropping failed/unincluded sessions,
     never exceeding 1.0 on multi-envelope sessions, and enforcing `gate_3_min_10_sessions_met`.
  6. Atomic persistence (`0o600`), no leftover temp files, symlink/dangling-symlink/parent-symlink/ancestor-symlink
     rejection, and duplicate-JSON-key / corrupt-store / integer-overflow rejection.
  7. Live MCP `kintsugi_delivery_telemetry` (`profile="v3"`) default store path, record/report, and strict input checks.
  8. Multi-process concurrent RMW locking (`<store>.lock`) with 0 lost updates.
  9. Rust (`rust/src/audit/delivery_telemetry.rs`) and Python (`delivery_telemetry.py`) 100% schema & live
     read/write cross-compatibility!
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

OSS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(OSS_ROOT / "src"))

from kintsugi import __version__ as KINTSUGI_VERSION
import kintsugi.evolution.delivery_telemetry as dt_mod
from kintsugi.evolution.delivery_telemetry import (
    DELIVERY_TELEMETRY_SCHEMA,
    GATE_3_MIN_SESSIONS,
    SCHEMA_VERSION,
    SUPPORTED_CLIENTS,
    DeliveryTelemetryTracker,
    _dedupe_ids,
    atomic_write_text_secure,
    build_telemetry_report,
    is_supported_client,
    load_frozen_ids,
    read_regular_text_secure,
    record_telemetry_event,
    render_telemetry_report_json,
)
from kintsugi.mcp_server import KintsugiMCPServer


def _read_cargo_pkg_version() -> str:
    cargo_toml = (OSS_ROOT / "Cargo.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', cargo_toml, flags=re.MULTILINE)
    assert m is not None, "Could not parse version from Cargo.toml"
    return m.group(1)


def _find_rustc() -> str | None:
    rustc = shutil.which("rustc")
    if rustc is None:
        cand = Path.home() / ".cargo/bin/rustc"
        if cand.is_file():
            rustc = str(cand)
    return rustc


def _compile_rust_driver(tmp_path: Path, name: str, main_body: str) -> Path:
    rustc = _find_rustc()
    if rustc is None:
        pytest.skip("rustc unavailable for live Rust interop test")
    driver_rs = tmp_path / f"{name}.rs"
    driver_bin = tmp_path / name
    io_escaped = str(OSS_ROOT / "rust/src/io_json.rs").replace("\\", "\\\\").replace('"', '\\"')
    dom_escaped = str(OSS_ROOT / "rust/src/json_dom.rs").replace("\\", "\\\\").replace('"', '\\"')
    rs_escaped = str(OSS_ROOT / "rust/src/audit/delivery_telemetry.rs").replace("\\", "\\\\").replace('"', '\\"')
    driver_rs.write_text(
        f'#![allow(dead_code)]\n'
        f'#[path = "{io_escaped}"]\n'
        f'pub mod io_json;\n'
        f'pub mod policy {{ pub fn sha256_hex(_: &[u8]) -> String {{ String::new() }} }}\n'
        f'#[path = "{dom_escaped}"]\n'
        f'pub mod json_dom;\n'
        f'#[path = "{rs_escaped}"]\n'
        f'pub mod delivery_telemetry;\n'
        f'fn main() {{\n{main_body}\n}}\n',
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["CARGO_PKG_VERSION"] = _read_cargo_pkg_version()
    comp = subprocess.run(
        [rustc, "--edition", "2021", "-D", "warnings", str(driver_rs), "-o", str(driver_bin)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert comp.returncode == 0, f"rustc -D warnings failed:\n{comp.stderr}"
    return driver_bin


# ---------------------------------------------------------------------------
# 1. Client Allowlist & Fail-Closed Validation
# ---------------------------------------------------------------------------


def test_supported_clients_allowlist_and_fail_closed_rejection(tmp_path: Path) -> None:
    store = tmp_path / "telemetry.json"
    assert SUPPORTED_CLIENTS == ("claude_code", "antigravity", "local_cli", "cloud_sandbox")
    for client in SUPPORTED_CLIENTS:
        assert is_supported_client(client) is True
        res = record_telemetry_event(
            store,
            client=client,
            stage="issued",
            session_id=f"sess-{client}",
            envelope_id=f"env-{client}",
            source_digest=f"sha-{client}",
            capsule_ids=["CAP-SQL-PARAM"],
            pitfall_ids=["LT-003"],
            estimated_tokens=120,
            timestamp_utc=1_730_000_000,
        )
        assert res["ok"] is True
        assert res["client"] == client
        assert res["stage"] == "issued"
        assert res["included_before_first_patch"] is False
        assert res["efficacy_updated"] is False

    for bad_client in ("", "cursor", "windsurf", "CLAUDE_CODE", "claude_code\n", "unknown", "chatgpt_" + "dot", "zcode_" + "glm"):
        assert is_supported_client(bad_client) is False
        with pytest.raises(ValueError, match="UNSUPPORTED_CLIENT"):
            record_telemetry_event(
                store,
                client=bad_client,
                stage="issued",
                session_id="sess-bad",
                envelope_id="env-bad",
                source_digest="sha-bad",
            )

    with pytest.raises(ValueError, match="UNSUPPORTED_STAGE"):
        record_telemetry_event(
            store,
            client="claude_code",
            stage="invented_stage",
            session_id="s1",
            envelope_id="e1",
        )


# ---------------------------------------------------------------------------
# 2. Honest 3-Stage Receipt Transitions & Unshown-Capsule Efficacy Guard
# ---------------------------------------------------------------------------


def test_receipt_transitions_mismatches_and_late_inclusion_honesty(tmp_path: Path) -> None:
    store = tmp_path / "telemetry.json"
    tracker = DeliveryTelemetryTracker(store)

    # Reject unknown envelope on included_in_input and patch_bound
    with pytest.raises(ValueError, match="UNKNOWN_ENVELOPE_ID"):
        tracker.record_included_in_input(client="claude_code", envelope_id="env-missing")
    with pytest.raises(ValueError, match="UNKNOWN_ENVELOPE_ID"):
        tracker.record_patch_bound(client="claude_code", envelope_id="env-missing", patch_digest="p0", passed=True)

    # Issue env-1 with duplicate capsule/pitfall entries -> deduplicated cleanly
    tracker.record_issued(
        client="claude_code",
        session_id="sess-1",
        envelope_id="env-1",
        source_digest="src-aaa",
        capsule_ids=["CAP-1", "CAP-1"],
        pitfall_ids=["LT-001", "LT-001"],
        estimated_tokens=150,
        timestamp_utc=1_730_000_010,
    )

    # Duplicate issued must fail closed
    with pytest.raises(ValueError, match="DUPLICATE_ENVELOPE_ID"):
        tracker.record_issued(
            client="claude_code",
            session_id="sess-1",
            envelope_id="env-1",
            source_digest="src-aaa",
        )

    # Mismatched client, session, and source_digest must fail closed
    with pytest.raises(ValueError, match="CLIENT_MISMATCH"):
        tracker.record_included_in_input(client="antigravity", envelope_id="env-1")
    with pytest.raises(ValueError, match="SESSION_MISMATCH"):
        tracker.record_included_in_input(client="claude_code", envelope_id="env-1", session_id="sess-other")
    with pytest.raises(ValueError, match="SOURCE_DIGEST_MISMATCH"):
        tracker.record_included_in_input(client="claude_code", envelope_id="env-1", source_digest="src-stale")

    # Happy path: issued -> included_in_input (idempotent retry) -> patch_bound
    inc1 = tracker.record_included_in_input(client="claude_code", envelope_id="env-1", timestamp_utc=1_730_000_011)
    assert inc1["included_before_first_patch"] is True
    assert inc1["efficacy_updated"] is False
    inc_retry = tracker.record_included_in_input(client="claude_code", envelope_id="env-1", timestamp_utc=1_730_000_012)
    assert inc_retry["included_before_first_patch"] is True

    # Missing patch_digest or non-bool passed fails closed
    with pytest.raises(ValueError, match="MISSING_PATCH_DIGEST"):
        tracker.record_patch_bound(client="claude_code", envelope_id="env-1", patch_digest="", passed=True)
    with pytest.raises(ValueError, match="MISSING_PASSED_FLAG"):
        record_telemetry_event(
            store, client="claude_code", stage="patch_bound", envelope_id="env-1", patch_digest="p1", passed=None
        )

    pb1 = tracker.record_patch_bound(
        client="claude_code", envelope_id="env-1", patch_digest="patch-1", passed=True, timestamp_utc=1_730_000_015
    )
    assert pb1["first_patch"] is True
    assert pb1["passed"] is True
    assert pb1["included_before_first_patch"] is True
    assert pb1["efficacy_updated"] is True

    # Duplicate patch_bound on same envelope must fail closed (no replay inflation!)
    with pytest.raises(ValueError, match="ENVELOPE_ALREADY_PATCH_BOUND"):
        tracker.record_patch_bound(client="claude_code", envelope_id="env-1", patch_digest="patch-1b", passed=True)

    # Second envelope in SAME session AFTER first patch -> included_in_input MUST NOT claim included_before_first_patch!
    tracker.record_issued(
        client="claude_code", session_id="sess-1", envelope_id="env-2", source_digest="src-bbb", capsule_ids=["CAP-1"]
    )
    inc2 = tracker.record_included_in_input(client="claude_code", envelope_id="env-2")
    assert inc2["included_before_first_patch"] is False
    pb2 = tracker.record_patch_bound(client="claude_code", envelope_id="env-2", patch_digest="patch-2", passed=True)
    assert pb2["first_patch"] is False
    assert pb2["efficacy_updated"] is False

    # Manual flow (cloud_sandbox): issued -> patch_bound directly, then late included_in_input stays False!
    # Unshown CAP-2 MUST NOT get credited/penalized in efficacy!
    tracker.record_issued(
        client="cloud_sandbox", session_id="csb-s1", envelope_id="csb-e1", source_digest="src-csb", capsule_ids=["CAP-2"]
    )
    pb_csb = tracker.record_patch_bound(
        client="cloud_sandbox", envelope_id="csb-e1", patch_digest="patch-csb", passed=True
    )
    assert pb_csb["included_before_first_patch"] is False
    assert pb_csb["first_patch"] is True
    assert pb_csb["efficacy_updated"] is False
    late_inc = tracker.record_included_in_input(client="cloud_sandbox", envelope_id="csb-e1")
    assert late_inc["included_before_first_patch"] is False

    eff_ids = {row["id"] for row in tracker.report()["efficacy_table"]}
    assert "CAP-1" in eff_ids
    assert "CAP-2" not in eff_ids


def test_unshown_patch_bound_preserves_denominator_without_freezing_capsule(tmp_path: Path) -> None:
    store = tmp_path / "telemetry.json"
    tracker = DeliveryTelemetryTracker(store)

    # 2 sessions where CAP-UNSHOWN is issued -> patch_bound(passed=False) WITHOUT included_in_input:
    # Must count in total_sessions & patch_bound_count, MUST NOT increment losses or trigger 2-strike freeze!
    for i in (1, 2):
        tracker.record_issued(
            client="claude_code",
            session_id=f"unshown-s-{i}",
            envelope_id=f"unshown-e-{i}",
            source_digest=f"d-{i}",
            capsule_ids=["CAP-UNSHOWN"],
            pitfall_ids=["LT-UNSHOWN"],
        )
        res = tracker.record_patch_bound(
            client="claude_code", envelope_id=f"unshown-e-{i}", patch_digest=f"p-{i}", passed=False
        )
        assert res["included_before_first_patch"] is False
        assert res["efficacy_updated"] is False
        assert res["newly_frozen_ids"] == []

    rep_mid = tracker.report()
    assert rep_mid["clients"]["claude_code"]["total_sessions"] == 2
    assert rep_mid["clients"]["claude_code"]["patch_bound_count"] == 2
    assert rep_mid["clients"]["claude_code"]["included_before_first_patch_count"] == 0
    assert rep_mid["efficacy_table"] == []
    assert load_frozen_ids(store) == set()

    # 2 sessions where CAP-SHOWN IS shown before first patch -> MUST increment losses and trigger 2-strike freeze!
    for i in (3, 4):
        tracker.record_issued(
            client="claude_code",
            session_id=f"shown-s-{i}",
            envelope_id=f"shown-e-{i}",
            source_digest=f"d-{i}",
            capsule_ids=["CAP-SHOWN"],
        )
        tracker.record_included_in_input(client="claude_code", envelope_id=f"shown-e-{i}")
        res = tracker.record_patch_bound(
            client="claude_code", envelope_id=f"shown-e-{i}", patch_digest=f"p-{i}", passed=False
        )
        assert res["included_before_first_patch"] is True
        assert res["efficacy_updated"] is True
        if i == 3:
            assert res["newly_frozen_ids"] == []
        else:
            assert res["newly_frozen_ids"] == ["CAP-SHOWN"]

    rep_end = tracker.report()
    assert rep_end["clients"]["claude_code"]["total_sessions"] == 4
    assert rep_end["clients"]["claude_code"]["patch_bound_count"] == 4
    assert rep_end["clients"]["claude_code"]["included_before_first_patch_count"] == 2
    assert rep_end["frozen_ids"] == ["CAP-SHOWN"]


# ---------------------------------------------------------------------------
# 3. 2-Strike Auto-Freeze & Reset & Sticky Invariant
# ---------------------------------------------------------------------------


def test_two_strike_auto_freeze_reset_and_sticky_persistence(tmp_path: Path) -> None:
    store = tmp_path / "telemetry.json"
    tracker = DeliveryTelemetryTracker(store)

    def run_trial(idx: int, passed: bool, caps: list[str], pits: list[str]) -> dict:
        eid = f"env-{idx}"
        tracker.record_issued(
            client="antigravity",
            session_id=f"sess-{idx}",
            envelope_id=eid,
            source_digest=f"src-{idx}",
            capsule_ids=caps,
            pitfall_ids=pits,
        )
        tracker.record_included_in_input(client="antigravity", envelope_id=eid)
        return tracker.record_patch_bound(
            client="antigravity", envelope_id=eid, patch_digest=f"patch-{idx}", passed=passed
        )

    # Strike 1 -> NOT frozen
    r1 = run_trial(1, False, ["CAP-ALPHA", "CAP-BETA"], ["LT-005"])
    assert r1["efficacy_updated"] is True
    assert r1["newly_frozen_ids"] == []
    assert load_frozen_ids(store) == set()

    # Pass resets consecutive_losses for CAP-ALPHA and LT-005 (not CAP-BETA!)
    r2 = run_trial(2, True, ["CAP-ALPHA"], ["LT-005"])
    assert r2["newly_frozen_ids"] == []

    # Loss on CAP-ALPHA (consecutive=1) + CAP-BETA (consecutive=2 -> FREEZE!)
    r3 = run_trial(3, False, ["CAP-ALPHA", "CAP-BETA"], [])
    assert r3["newly_frozen_ids"] == ["CAP-BETA"]
    assert load_frozen_ids(store) == {"CAP-BETA"}

    # Second consecutive loss on CAP-ALPHA + first loss on LT-005 -> CAP-ALPHA freezes, LT-005 still active
    r4 = run_trial(4, False, ["CAP-ALPHA"], ["LT-005"])
    assert r4["newly_frozen_ids"] == ["CAP-ALPHA"]
    assert load_frozen_ids(store) == {"CAP-ALPHA", "CAP-BETA"}

    # Subsequent win on CAP-BETA MUST NOT unfreeze it (sticky freeze invariant!)
    r5 = run_trial(5, True, ["CAP-BETA"], ["LT-005"])
    assert r5["newly_frozen_ids"] == []
    assert "CAP-BETA" in load_frozen_ids(store)

    rep = tracker.report()
    eff_by_id = {row["id"]: row for row in rep["efficacy_table"]}
    assert eff_by_id["CAP-ALPHA"] == {
        "id": "CAP-ALPHA",
        "wins": 1,
        "losses": 3,
        "trials": 4,
        "consecutive_losses": 2,
        "efficacy_pct": 25.0,
        "frozen": True,
        "freeze_reason": "two_strike_consecutive_losses",
    }
    assert eff_by_id["CAP-BETA"]["frozen"] is True
    assert eff_by_id["CAP-BETA"]["consecutive_losses"] == 0
    assert eff_by_id["CAP-BETA"]["freeze_reason"] == "two_strike_consecutive_losses"
    assert eff_by_id["LT-005"]["frozen"] is False


# ---------------------------------------------------------------------------
# 4. Dead-Scar Auto-Freeze & Sticky-Freeze Parity (Python + Rust)
# ---------------------------------------------------------------------------


def test_dead_scar_auto_freeze_exact_boundaries(tmp_path: Path) -> None:
    store = tmp_path / "telemetry.json"
    seeded = {
        "schema": DELIVERY_TELEMETRY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "updated_at_utc": 1_730_000_000,
        "envelopes": {},
        "efficacy": {
            "CAP-DEAD-NEXT": {
                "id": "CAP-DEAD-NEXT", "wins": 4, "losses": 25, "trials": 29,
                "consecutive_losses": 0, "frozen": False, "freeze_reason": None,
            },
            "CAP-SAFE-15PCT": {
                "id": "CAP-SAFE-15PCT", "wins": 6, "losses": 34, "trials": 40,
                "consecutive_losses": 0, "frozen": False, "freeze_reason": None,
            },
            "CAP-SAFE-30": {
                "id": "CAP-SAFE-30", "wins": 5, "losses": 25, "trials": 30,
                "consecutive_losses": 0, "frozen": False, "freeze_reason": None,
            },
            "CAP-UNFLAGGED-DEAD": {
                "id": "CAP-UNFLAGGED-DEAD", "wins": 4, "losses": 26, "trials": 30,
                "consecutive_losses": 0, "frozen": False, "freeze_reason": None,
            },
        },
    }
    atomic_write_text_secure(store, json.dumps(seeded) + "\n", mode=0o600)

    # Before 30th trial: only CAP-UNFLAGGED-DEAD is frozen
    assert load_frozen_ids(store) == {"CAP-UNFLAGGED-DEAD"}

    # Trigger 30th trial on CAP-DEAD-NEXT with 1 loss (shown before patch!)
    tracker = DeliveryTelemetryTracker(store)
    tracker.record_issued(
        client="local_cli", session_id="s-30", envelope_id="e-30", source_digest="d-30", capsule_ids=["CAP-DEAD-NEXT"]
    )
    tracker.record_included_in_input(client="local_cli", envelope_id="e-30")
    res = tracker.record_patch_bound(client="local_cli", envelope_id="e-30", patch_digest="p-30", passed=False)
    assert res["efficacy_updated"] is True
    assert res["newly_frozen_ids"] == ["CAP-DEAD-NEXT"]
    assert load_frozen_ids(store) == {"CAP-DEAD-NEXT", "CAP-UNFLAGGED-DEAD"}

    rep = tracker.report()
    eff_map = {row["id"]: row for row in rep["efficacy_table"]}
    assert eff_map["CAP-DEAD-NEXT"]["frozen"] is True
    assert eff_map["CAP-DEAD-NEXT"]["consecutive_losses"] == 1
    assert eff_map["CAP-DEAD-NEXT"]["efficacy_pct"] == 13.33
    assert eff_map["CAP-DEAD-NEXT"]["freeze_reason"] == "dead_scar_low_efficacy"
    assert eff_map["CAP-SAFE-15PCT"]["frozen"] is False
    assert eff_map["CAP-SAFE-30"]["frozen"] is False
    assert eff_map["CAP-UNFLAGGED-DEAD"]["frozen"] is True
    assert eff_map["CAP-UNFLAGGED-DEAD"]["freeze_reason"] == "dead_scar_low_efficacy"


def test_sticky_freeze_preseeded_dead_scar_and_two_strike_python_and_rust(tmp_path: Path) -> None:
    seeded = {
        "schema": DELIVERY_TELEMETRY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "updated_at_utc": 1_730_000_000,
        "envelopes": {},
        "efficacy": {
            "CAP-DEAD-4-30": {
                "id": "CAP-DEAD-4-30", "wins": 4, "losses": 26, "trials": 30,
                "consecutive_losses": 0, "frozen": False, "freeze_reason": None,
            },
            "CAP-TWO-STRIKE-UNFLAGGED": {
                "id": "CAP-TWO-STRIKE-UNFLAGGED", "wins": 0, "losses": 2, "trials": 2,
                "consecutive_losses": 2, "frozen": False, "freeze_reason": None,
            },
        },
    }

    # Python verification: passed=True on pre-seeded 4/30 dead scar & consecutive_losses=2 MUST stay frozen!
    py_store = tmp_path / "sticky_py.json"
    atomic_write_text_secure(py_store, json.dumps(seeded) + "\n", mode=0o600)
    tracker = DeliveryTelemetryTracker(py_store)
    tracker.record_issued(
        client="claude_code", session_id="s-sticky", envelope_id="e-sticky", source_digest="d-s",
        capsule_ids=["CAP-DEAD-4-30", "CAP-TWO-STRIKE-UNFLAGGED"],
    )
    tracker.record_included_in_input(client="claude_code", envelope_id="e-sticky")
    res = tracker.record_patch_bound(client="claude_code", envelope_id="e-sticky", patch_digest="p-s", passed=True)
    assert res["efficacy_updated"] is True
    assert res["newly_frozen_ids"] == []
    assert set(res["frozen_ids"]) == {"CAP-DEAD-4-30", "CAP-TWO-STRIKE-UNFLAGGED"}
    py_eff = {r["id"]: r for r in tracker.report()["efficacy_table"]}
    assert py_eff["CAP-DEAD-4-30"]["wins"] == 5 and py_eff["CAP-DEAD-4-30"]["trials"] == 31
    assert py_eff["CAP-DEAD-4-30"]["frozen"] is True
    assert py_eff["CAP-DEAD-4-30"]["freeze_reason"] == "dead_scar_low_efficacy"
    assert py_eff["CAP-TWO-STRIKE-UNFLAGGED"]["consecutive_losses"] == 0
    assert py_eff["CAP-TWO-STRIKE-UNFLAGGED"]["frozen"] is True
    assert py_eff["CAP-TWO-STRIKE-UNFLAGGED"]["freeze_reason"] == "two_strike_consecutive_losses"

    # Rust verification on identical pre-seeded store!
    rs_store = tmp_path / "sticky_rs.json"
    atomic_write_text_secure(rs_store, json.dumps(seeded) + "\n", mode=0o600)
    rs_escaped = str(rs_store).replace("\\", "\\\\").replace('"', '\\"')
    driver_bin = _compile_rust_driver(
        tmp_path,
        "rust_sticky_driver",
        f'let p = std::path::Path::new("{rs_escaped}");\n'
        f'let caps = vec!["CAP-DEAD-4-30".to_string(), "CAP-TWO-STRIKE-UNFLAGGED".to_string()];\n'
        f'delivery_telemetry::record_telemetry_event(p, "claude_code", "issued", "s-sticky", "e-sticky", "d-s", "", &caps, &[], 50, None).unwrap();\n'
        f'delivery_telemetry::record_telemetry_event(p, "claude_code", "included_in_input", "s-sticky", "e-sticky", "", "", &[], &[], 0, None).unwrap();\n'
        f'let res = delivery_telemetry::record_telemetry_event(p, "claude_code", "patch_bound", "s-sticky", "e-sticky", "", "p-s", &[], &[], 0, Some(true)).unwrap();\n'
        f'assert!(res.contains("\\"newly_frozen_ids\\":[]") && res.contains("\\"efficacy_updated\\":true"));\n'
        f'println!("{{}}", delivery_telemetry::render_telemetry_report_json(p).unwrap());',
    )
    run = subprocess.run([str(driver_bin)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    rs_rep = json.loads(run.stdout)
    rs_eff = {r["id"]: r for r in rs_rep["efficacy_table"]}
    assert rs_eff == py_eff


# ---------------------------------------------------------------------------
# 5. Honest Denominator & Gate #3 (>= 10 sessions per client)
# ---------------------------------------------------------------------------


def test_honest_denominator_and_gate_3_min_10_sessions(tmp_path: Path) -> None:
    store = tmp_path / "telemetry.json"
    tracker = DeliveryTelemetryTracker(store)

    for i in range(7):
        eid = f"cc-env-{i}"
        tracker.record_issued(
            client="claude_code", session_id=f"cc-s-{i}", envelope_id=eid, source_digest=f"d-{i}", capsule_ids=["CAP-OK"]
        )
        tracker.record_included_in_input(client="claude_code", envelope_id=eid)
        if i == 0:
            tracker.record_issued(
                client="claude_code", session_id="cc-s-0", envelope_id="cc-env-0b", source_digest="d-0b"
            )
            tracker.record_included_in_input(client="claude_code", envelope_id="cc-env-0b")
        tracker.record_patch_bound(
            client="claude_code", envelope_id=eid, patch_digest=f"p-{i}", passed=(i < 5)
        )

    for i in (7, 8):
        tracker.record_issued(
            client="claude_code", session_id=f"cc-s-{i}", envelope_id=f"cc-env-{i}", source_digest=f"d-{i}"
        )

    tracker.record_issued(
        client="claude_code", session_id="cc-s-9", envelope_id="cc-env-9", source_digest="d-9"
    )
    tracker.record_patch_bound(
        client="claude_code", envelope_id="cc-env-9", patch_digest="p-9", passed=False
    )

    for i in range(9):
        eid = f"lc-env-{i}"
        tracker.record_issued(
            client="local_cli", session_id=f"lc-s-{i}", envelope_id=eid, source_digest=f"ld-{i}"
        )
        if i < 3:
            tracker.record_included_in_input(client="local_cli", envelope_id=eid)

    rep = tracker.report()
    assert rep["ok"] is True
    assert rep["schema"] == DELIVERY_TELEMETRY_SCHEMA
    assert rep["total_sessions"] == 19
    assert rep["total_envelopes"] == 20

    cc = rep["clients"]["claude_code"]
    assert cc["total_sessions"] == 10
    assert cc["issued_count"] == 11
    assert cc["included_before_first_patch_count"] == 7
    assert cc["included_before_first_patch_rate"] == 0.7
    assert cc["patch_bound_count"] == 8
    assert cc["patch_passed_count"] == 5
    assert cc["patch_pass_rate"] == 0.625
    assert cc["gate_3_min_10_sessions_met"] is True
    assert GATE_3_MIN_SESSIONS == 10

    lc = rep["clients"]["local_cli"]
    assert lc["total_sessions"] == 9
    assert lc["included_before_first_patch_count"] == 3
    assert lc["included_before_first_patch_rate"] == 0.3333
    assert lc["patch_bound_count"] == 0
    assert lc["patch_pass_rate"] == 0.0
    assert lc["gate_3_min_10_sessions_met"] is False

    assert rep["clients"]["antigravity"]["total_sessions"] == 0
    assert rep["clients"]["cloud_sandbox"]["total_sessions"] == 0


# ---------------------------------------------------------------------------
# 6. Atomic 0o600 Persistence, Symlink / Ancestor Symlink & Corrupt Store Defense
# ---------------------------------------------------------------------------


def test_atomic_0600_persistence_symlink_and_corrupt_store_rejection(tmp_path: Path) -> None:
    store = tmp_path / "secure" / "delivery_telemetry.json"
    record_telemetry_event(
        store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", source_digest="d1"
    )
    assert store.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(os.lstat(store).st_mode) == 0o600
    assert list(store.parent.glob("*.tmp")) == []

    if os.name == "posix":
        live_sym = tmp_path / "live_sym.json"
        live_sym.symlink_to(store)
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            build_telemetry_report(live_sym)
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            record_telemetry_event(live_sym, client="claude_code", stage="issued", session_id="s2", envelope_id="e2")
        assert load_frozen_ids(live_sym) == set()

        dangling = tmp_path / "dangling_sym.json"
        dangling.symlink_to(tmp_path / "nonexistent_target.json")
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            read_regular_text_secure(dangling)
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            record_telemetry_event(dangling, client="claude_code", stage="issued", session_id="s3", envelope_id="e3")

        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        sym_dir = tmp_path / "sym_dir"
        sym_dir.symlink_to(real_dir)
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            record_telemetry_event(
                sym_dir / "telemetry.json", client="claude_code", stage="issued", session_id="s4", envelope_id="e4"
            )

        # Intermediate ancestor symlink (`safe_dir/sym_sub/nested/delivery_telemetry.json`) rejected in Python & Rust!
        outside = tmp_path / "outside_target"
        outside.mkdir()
        safe_dir = tmp_path / "safe_dir"
        safe_dir.mkdir()
        (safe_dir / "sym_sub").symlink_to(outside)
        nested = safe_dir / "sym_sub" / "nested" / "delivery_telemetry.json"
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            record_telemetry_event(nested, client="claude_code", stage="issued", session_id="s5", envelope_id="e5")
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            build_telemetry_report(nested)
        assert not (outside / "nested").exists()

        nested_esc = str(nested).replace("\\", "\\\\").replace('"', '\\"')
        sym_driver = _compile_rust_driver(
            tmp_path,
            "rust_sym_ancestor_driver",
            f'let p = std::path::Path::new("{nested_esc}");\n'
            f'assert!(delivery_telemetry::record_telemetry_event(p, "claude_code", "issued", "s5", "e5", "d5", "", &[], &[], 0, None).is_err());\n'
            f'assert!(delivery_telemetry::render_telemetry_report_json(p).is_err());',
        )
        run_sym = subprocess.run([str(sym_driver)], capture_output=True, text=True, check=False)
        assert run_sym.returncode == 0, run_sym.stderr
        assert not (outside / "nested").exists()

        # Symlink on sibling `<store>.lock` rejected fail-closed in Python & Rust!
        lock_store = tmp_path / "lock_target.json"
        lock_file = tmp_path / "lock_target.json.lock"
        lock_file.symlink_to(outside / "pwn.lock")
        with pytest.raises(PermissionError, match="REFUSING_SYMLINK"):
            record_telemetry_event(lock_store, client="claude_code", stage="issued", session_id="s6", envelope_id="e6")
        lock_store_esc = str(lock_store).replace("\\", "\\\\").replace('"', '\\"')
        lock_driver = _compile_rust_driver(
            tmp_path,
            "rust_sym_lock_driver",
            f'let p = std::path::Path::new("{lock_store_esc}");\n'
            f'assert!(delivery_telemetry::record_telemetry_event(p, "claude_code", "issued", "s6", "e6", "d6", "", &[], &[], 0, None).is_err());',
        )
        run_lock = subprocess.run([str(lock_driver)], capture_output=True, text=True, check=False)
        assert run_lock.returncode == 0, run_lock.stderr
        assert not (outside / "pwn.lock").exists()

    # Duplicate JSON keys rejected
    dup_store = tmp_path / "dup.json"
    dup_store.write_text('{"schema":"DeliveryTelemetry/1","schema":"DeliveryTelemetry/1"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="DUPLICATE_JSON_KEY"):
        build_telemetry_report(dup_store)

    # Unsupported schema rejected
    bad_schema = tmp_path / "bad_schema.json"
    bad_schema.write_text('{"schema":"WrongSchema/99","envelopes":{},"efficacy":{}}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="UNSUPPORTED_SCHEMA"):
        build_telemetry_report(bad_schema)


def test_corrupt_store_and_u32_overflow_fail_closed_python_and_rust(tmp_path: Path) -> None:
    corrupt_payloads = [
        '{"schema":123,"envelopes":[],"efficacy":"corrupt"}\n',
        '{"schema":"DeliveryTelemetry/1","envelopes":[],"efficacy":{}}\n',
        '{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":"corrupt"}\n',
        '{"schema":"DeliveryTelemetry/1","updated_at_utc":true,"envelopes":{},"efficacy":{}}\n',
        '{"schema":"DeliveryTelemetry/1","updated_at_utc":-1,"envelopes":{},"efficacy":{}}\n',
        '{"schema":"DeliveryTelemetry/1","envelopes":{"e1":{"client":"claude_code","stage":"issued","session_id":"","envelope_id":"e1"}},"efficacy":{}}\n',
        '{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":{"CAP-X":{"wins":true,"losses":0,"trials":1,"consecutive_losses":0}}}\n',
        '{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":{"CAP-Y":{"wins":-1,"losses":0,"trials":1,"consecutive_losses":0}}}\n',
    ]
    paths: list[Path] = []
    for idx, body in enumerate(corrupt_payloads):
        p = tmp_path / f"corrupt_{idx}.json"
        p.write_text(body, encoding="utf-8")
        paths.append(p)
        with pytest.raises(ValueError):
            build_telemetry_report(p)

    # 2^32 (4294967296) integer overflow files for Python & Rust fail-closed verification
    ovf_trials = tmp_path / "ovf_trials.json"
    ovf_trials.write_text(
        '{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":{"CAP-OVF":{"id":"CAP-OVF","wins":0,"losses":0,"trials":4294967296,"consecutive_losses":0,"frozen":false}}}\n',
        encoding="utf-8",
    )
    ovf_losses = tmp_path / "ovf_losses.json"
    ovf_losses.write_text(
        '{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":{"CAP-OVF2":{"id":"CAP-OVF2","wins":0,"losses":0,"trials":2,"consecutive_losses":4294967296,"frozen":false}}}\n',
        encoding="utf-8",
    )
    for ovf_p in (ovf_trials, ovf_losses):
        with pytest.raises(ValueError, match="INT_OVERFLOW"):
            build_telemetry_report(ovf_p)
    paths.extend([ovf_trials, ovf_losses])

    checks = []
    for p in paths:
        pe = str(p).replace("\\", "\\\\").replace('"', '\\"')
        checks.append(f'assert!(delivery_telemetry::render_telemetry_report_json(std::path::Path::new("{pe}")).is_err(), "expected err for {pe}");')
    ovf1_e = str(ovf_trials).replace("\\", "\\\\").replace('"', '\\"')
    ovf2_e = str(ovf_losses).replace("\\", "\\\\").replace('"', '\\"')
    checks.append(f'assert!(delivery_telemetry::render_telemetry_report_json(std::path::Path::new("{ovf1_e}")).unwrap_err().contains("INT_OVERFLOW"));')
    checks.append(f'assert!(delivery_telemetry::render_telemetry_report_json(std::path::Path::new("{ovf2_e}")).unwrap_err().contains("INT_OVERFLOW"));')
    driver_bin = _compile_rust_driver(tmp_path, "rust_corrupt_driver", "\n".join(checks))
    run = subprocess.run([str(driver_bin)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr


# ---------------------------------------------------------------------------
# 7. Python Validation Gaps (`timestamp_utc`, `updated_at_utc=None`, `_dedupe_ids`)
# ---------------------------------------------------------------------------


def test_python_validation_timestamp_updated_at_none_and_dedupe_ids(tmp_path: Path) -> None:
    store = tmp_path / "val.json"
    # updated_at_utc: null accepted as 0
    store.write_text('{"schema":"DeliveryTelemetry/1","updated_at_utc":null,"envelopes":{},"efficacy":{}}\n', encoding="utf-8")
    rep = build_telemetry_report(store)
    assert rep["ok"] is True and rep["total_envelopes"] == 0

    # timestamp_utc negative / bool / non-int rejected
    for bad_ts in (-5, True, False, "1730000000", 1.5):
        with pytest.raises(ValueError, match="INVALID_TIMESTAMP_UTC"):
            record_telemetry_event(
                store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", timestamp_utc=bad_ts  # type: ignore[arg-type]
            )

    # _dedupe_ids rejects bare str / bytes
    with pytest.raises(ValueError, match="INVALID_IDS"):
        _dedupe_ids("CAP-1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="INVALID_IDS"):
        _dedupe_ids(b"CAP-1")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="INVALID_IDS"):
        record_telemetry_event(
            store, client="claude_code", stage="issued", session_id="s2", envelope_id="e2", capsule_ids="CAP-1"  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# 8. Live MCP Server (`profile="v3"`) `kintsugi_delivery_telemetry`
# ---------------------------------------------------------------------------


def test_mcp_v3_delivery_telemetry_live_record_report_and_validation(tmp_path: Path) -> None:
    scars_path = tmp_path / ".kintsugi" / "scars.json"
    srv = KintsugiMCPServer(scars_path, profile="v3")
    expected_default_store = scars_path.parent / "delivery_telemetry.json"

    def call(arguments: dict) -> dict:
        return srv.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "kintsugi_delivery_telemetry", "arguments": arguments},
            }
        )

    # Record via default store_path (omitted -> self.ledger.path.parent / "delivery_telemetry.json")
    r_iss = call(
        {
            "action": "record",
            "client": "claude_code",
            "stage": "issued",
            "session_id": "mcp-s1",
            "envelope_id": "mcp-e1",
            "source_digest": "mcp-d1",
            "capsule_ids": ["CAP-MCP-1"],
            "pitfall_ids": ["LT-003"],
            "estimated_tokens": 128,
        }
    )
    assert r_iss["result"]["isError"] is False, r_iss
    assert expected_default_store.is_file()
    iss_data = json.loads(r_iss["result"]["content"][0]["text"])
    assert iss_data["ok"] is True and iss_data["stage"] == "issued"

    r_inc = call({"action": "record", "client": "claude_code", "stage": "included_in_input", "envelope_id": "mcp-e1"})
    assert r_inc["result"]["isError"] is False, r_inc
    r_pb = call(
        {
            "action": "record",
            "client": "claude_code",
            "stage": "patch_bound",
            "envelope_id": "mcp-e1",
            "patch_digest": "mcp-p1",
            "passed": True,
        }
    )
    assert r_pb["result"]["isError"] is False, r_pb
    pb_data = json.loads(r_pb["result"]["content"][0]["text"])
    assert pb_data["efficacy_updated"] is True

    # Report via default store_path (action omitted -> defaults to "report")
    r_rep = call({})
    assert r_rep["result"]["isError"] is False, r_rep
    rep_data = json.loads(r_rep["result"]["content"][0]["text"])
    assert rep_data["total_envelopes"] == 1
    assert rep_data["clients"]["claude_code"]["patch_passed_count"] == 1

    # Reject bare string capsule_ids & pitfall_ids
    bad_caps = call(
        {
            "action": "record",
            "client": "claude_code",
            "stage": "issued",
            "session_id": "mcp-s2",
            "envelope_id": "mcp-e2",
            "capsule_ids": "CAP-1",
        }
    )
    assert bad_caps["result"]["isError"] is True

    bad_pits = call(
        {
            "action": "record",
            "client": "claude_code",
            "stage": "issued",
            "session_id": "mcp-s2",
            "envelope_id": "mcp-e2",
            "pitfall_ids": "LT-003",
        }
    )
    assert bad_pits["result"]["isError"] is True

    # Reject bool estimated_tokens=True
    bad_tok = call(
        {
            "action": "record",
            "client": "claude_code",
            "stage": "issued",
            "session_id": "mcp-s3",
            "envelope_id": "mcp-e3",
            "estimated_tokens": True,
        }
    )
    assert bad_tok["result"]["isError"] is True

    # Reject unknown / empty action
    for bad_act in ("delete", "reset", ""):
        r_bad = call({"action": bad_act})
        assert r_bad["result"]["isError"] is True
        assert "Unsupported telemetry action" in r_bad["result"]["content"][0]["text"]


# ---------------------------------------------------------------------------
# 9. Multi-Process Concurrent RMW Locking (`<store>.lock`) — Zero Lost Updates
# ---------------------------------------------------------------------------


def test_multiprocess_concurrent_record_telemetry_zero_lost_updates(tmp_path: Path) -> None:
    store = tmp_path / "concurrent_telemetry.json"
    workers = 4
    per_worker = 10
    worker_code = (
        "import sys\n"
        "from pathlib import Path\n"
        f"sys.path.insert(0, {str(OSS_ROOT / 'src')!r})\n"
        "from kintsugi.evolution.delivery_telemetry import record_telemetry_event\n"
        "store, wid, n = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])\n"
        "for i in range(n):\n"
        "    record_telemetry_event(\n"
        "        store, client='claude_code', stage='issued',\n"
        "        session_id=f's-{wid}-{i}', envelope_id=f'e-{wid}-{i}',\n"
        "        source_digest=f'd-{wid}-{i}', estimated_tokens=10,\n"
        "    )\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", worker_code, str(store), str(w), str(per_worker)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for w in range(workers)
    ]
    rust_expected: set[str] = set()
    if _find_rustc() is not None:
        store_esc = str(store).replace("\\", "\\\\").replace('"', '\\"')
        rs_worker = _compile_rust_driver(
            tmp_path,
            "rust_concurrent_worker",
            f'let p = std::path::Path::new("{store_esc}");\n'
            f'for i in 0..{per_worker}usize {{\n'
            f'    let s = format!("s-rs-{{i}}");\n'
            f'    let e = format!("e-rs-{{i}}");\n'
            f'    let d = format!("d-rs-{{i}}");\n'
            f'    delivery_telemetry::record_telemetry_event(p, "local_cli", "issued", &s, &e, &d, "", &[], &[], 10, None).unwrap();\n'
            f'}}',
        )
        procs.append(
            subprocess.Popen([str(rs_worker)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        )
        rust_expected = {f"e-rs-{i}" for i in range(per_worker)}

    for p in procs:
        out, err = p.communicate(timeout=30)
        assert p.returncode == 0, f"Worker failed:\nstdout={out}\nstderr={err}"

    rep = build_telemetry_report(store)
    expected_ids = {f"e-{w}-{i}" for w in range(workers) for i in range(per_worker)} | rust_expected
    assert rep["total_envelopes"] == len(expected_ids)
    assert rep["total_sessions"] == len(expected_ids)
    raw_doc = json.loads(store.read_text(encoding="utf-8"))
    assert set(raw_doc["envelopes"].keys()) == expected_ids
    assert list(store.parent.glob("*.tmp")) == []


# ---------------------------------------------------------------------------
# 10. Rust / Python 100% Schema Compatibility & Live Cross-Language Parity
# ---------------------------------------------------------------------------


def test_rust_python_schema_and_live_interop_parity(tmp_path: Path) -> None:
    rs_path = OSS_ROOT / "rust/src/audit/delivery_telemetry.rs"
    assert rs_path.is_file()
    rs_src = rs_path.read_text(encoding="utf-8")
    for required_sym in (
        'pub const DELIVERY_TELEMETRY_SCHEMA: &str = "DeliveryTelemetry/1";',
        '"claude_code", "antigravity", "local_cli", "cloud_sandbox"',
        "pub fn record_telemetry_event(",
        "pub fn render_telemetry_report_json(",
        "pub fn load_frozen_ids(",
        "pub fn atomic_write_file_secure(",
    ):
        assert required_sym in rs_src, f"Missing expected Rust export/constant: {required_sym}"

    # Verify strict line-count budgets
    py_path = OSS_ROOT / "src/kintsugi/evolution/delivery_telemetry.py"
    assert len(rs_src.splitlines()) <= 800
    assert len(py_path.read_text(encoding="utf-8").splitlines()) <= 600

    store = tmp_path / "interop_telemetry.json"
    # Step A: Python writes events for claude_code
    tracker = DeliveryTelemetryTracker(store)
    tracker.record_issued(
        client="claude_code",
        session_id="s-py-1",
        envelope_id="env-py-1",
        source_digest="src-py-1",
        capsule_ids=["CAP-SHARED"],
        pitfall_ids=["LT-003"],
        estimated_tokens=110,
    )
    tracker.record_included_in_input(client="claude_code", envelope_id="env-py-1")
    tracker.record_patch_bound(client="claude_code", envelope_id="env-py-1", patch_digest="p-py-1", passed=False)

    # Step B: Rust reads Python's store, appends a 2nd failing event (2-strike freeze), and prints report.
    store_escaped = str(store).replace("\\", "\\\\").replace('"', '\\"')
    driver_bin = _compile_rust_driver(
        tmp_path,
        "rust_parity_driver",
        f'let p = std::path::Path::new("{store_escaped}");\n'
        f'let caps = vec!["CAP-SHARED".to_string()];\n'
        f'let pits = vec!["LT-003".to_string()];\n'
        f'delivery_telemetry::record_telemetry_event(p, "local_cli", "issued", "s-rs-2", "env-rs-2", "src-rs-2", "", &caps, &pits, 95, None).unwrap();\n'
        f'delivery_telemetry::record_telemetry_event(p, "local_cli", "included_in_input", "s-rs-2", "env-rs-2", "", "", &[], &[], 0, None).unwrap();\n'
        f'let r2 = delivery_telemetry::record_telemetry_event(p, "local_cli", "patch_bound", "s-rs-2", "env-rs-2", "", "p-rs-2", &[], &[], 0, Some(false)).unwrap();\n'
        f'assert!(r2.contains("\\"efficacy_updated\\":true"));\n'
        f'delivery_telemetry::record_telemetry_event(p, "cloud_sandbox", "issued", "s-rs-3", "env-rs-3", "src-rs-3", "", &[], &[], 40, None).unwrap();\n'
        f'let frozen: Vec<String> = delivery_telemetry::load_frozen_ids(p).into_iter().collect();\n'
        f'assert_eq!(frozen, vec!["CAP-SHARED".to_string(), "LT-003".to_string()]);\n'
        f'println!("{{}}", delivery_telemetry::render_telemetry_report_json(p).unwrap());',
    )
    run = subprocess.run([str(driver_bin)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, f"Rust driver failed:\n{run.stderr}"

    # Step C: Compare Rust-rendered report JSON vs Python-rendered report JSON on the exact same store!
    rust_report = json.loads(run.stdout)
    py_report = json.loads(render_telemetry_report_json(store))
    assert rust_report == py_report
    assert py_report["frozen_ids"] == ["CAP-SHARED", "LT-003"]
    assert load_frozen_ids(store) == {"CAP-SHARED", "LT-003"}
    assert py_report["clients"]["claude_code"]["included_before_first_patch_rate"] == 1.0
    assert py_report["clients"]["local_cli"]["included_before_first_patch_rate"] == 1.0
    assert py_report["clients"]["cloud_sandbox"]["included_before_first_patch_rate"] == 0.0
    assert py_report["total_sessions"] == 3


# ---------------------------------------------------------------------------
# 11. v3.0.1 Principal Arbiter Regression Suite (HIGH #5, HIGH #6, MEDIUM #9)
# ---------------------------------------------------------------------------


def test_unrecognized_existing_json_fails_closed_without_overwrite_python_and_rust(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign.json"
    original = b'{"note":1}'
    foreign.write_bytes(original)

    with pytest.raises(ValueError, match="UNRECOGNIZED_TELEMETRY_STORE"):
        record_telemetry_event(
            foreign, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", source_digest="d1"
        )
    assert foreign.read_bytes() == original
    with pytest.raises(ValueError, match="UNRECOGNIZED_TELEMETRY_STORE"):
        build_telemetry_report(foreign)
    assert foreign.read_bytes() == original

    # Missing required envelopes/efficacy objects or empty {} also fail closed without modification
    for idx, payload in enumerate((b"{}", b'{"schema":"DeliveryTelemetry/1"}', b'{"schema":"DeliveryTelemetry/1","envelopes":null,"efficacy":{}}')):
        p = tmp_path / f"unrec_{idx}.json"
        p.write_bytes(payload)
        with pytest.raises(ValueError, match="UNRECOGNIZED_TELEMETRY_STORE"):
            record_telemetry_event(p, client="claude_code", stage="issued", session_id="s1", envelope_id="e1")
        assert p.read_bytes() == payload

    # Existing 0-byte or whitespace-only file MUST fail closed even on stage="issued" (no silent overwrite!)
    zero_py = tmp_path / "zero_py.json"
    zero_py.write_bytes(b"")
    ws_py = tmp_path / "ws_py.json"
    ws_py.write_bytes(b"  \n\t ")
    for empty_p in (zero_py, ws_py):
        orig_bytes = empty_p.read_bytes()
        with pytest.raises(ValueError, match="CORRUPT_EMPTY_TELEMETRY_STORE"):
            record_telemetry_event(empty_p, client="claude_code", stage="issued", session_id="s0", envelope_id="e0")
        with pytest.raises(ValueError, match="CORRUPT_EMPTY_TELEMETRY_STORE"):
            build_telemetry_report(empty_p)
        assert empty_p.read_bytes() == orig_bytes

    # Absent telemetry path auto-initializes cleanly on stage="issued" in Python
    fresh_py = tmp_path / "fresh_py.json"
    assert not fresh_py.exists()
    res = record_telemetry_event(fresh_py, client="cloud_sandbox", stage="issued", session_id="s0", envelope_id="e0")
    assert res["ok"] is True and res["client"] == "cloud_sandbox"

    # Rust parity on {"note":1}, existing 0-byte / whitespace-only fail-closed (even on issued), and absent path init
    foreign_esc = str(foreign).replace("\\", "\\\\").replace('"', '\\"')
    zero_rs = tmp_path / "zero_rs.json"
    zero_rs.write_bytes(b"")
    zero_rs_esc = str(zero_rs).replace("\\", "\\\\").replace('"', '\\"')
    ws_rs = tmp_path / "ws_rs.json"
    ws_rs.write_bytes(b" \n ")
    ws_rs_esc = str(ws_rs).replace("\\", "\\\\").replace('"', '\\"')
    fresh_rs = tmp_path / "fresh_rs.json"
    fresh_rs_esc = str(fresh_rs).replace("\\", "\\\\").replace('"', '\\"')
    driver = _compile_rust_driver(
        tmp_path,
        "rust_high5_driver",
        f'let f = std::path::Path::new("{foreign_esc}");\n'
        f'let err = delivery_telemetry::record_telemetry_event(f, "claude_code", "issued", "s1", "e1", "d1", "", &[], &[], 10, None).unwrap_err();\n'
        f'assert!(err.contains("UNRECOGNIZED_TELEMETRY_STORE"), "{{err}}");\n'
        f'assert_eq!(std::fs::read(f).unwrap(), br#"{{"note":1}}"#);\n'
        f'for ep in [std::path::Path::new("{zero_rs_esc}"), std::path::Path::new("{ws_rs_esc}")] {{\n'
        f'    let e1 = delivery_telemetry::record_telemetry_event(ep, "claude_code", "issued", "s0", "e0", "d0", "", &[], &[], 10, None).unwrap_err();\n'
        f'    assert!(e1.contains("CORRUPT_EMPTY_TELEMETRY_STORE"), "{{e1}}");\n'
        f'    let e2 = delivery_telemetry::render_telemetry_report_json(ep).unwrap_err();\n'
        f'    assert!(e2.contains("CORRUPT_EMPTY_TELEMETRY_STORE"), "{{e2}}");\n'
        f'    let e3 = delivery_telemetry::try_load_frozen_ids(ep).unwrap_err();\n'
        f'    assert!(e3.contains("CORRUPT_EMPTY_TELEMETRY_STORE"), "{{e3}}");\n'
        f'}}\n'
        f'assert_eq!(std::fs::read(std::path::Path::new("{zero_rs_esc}")).unwrap(), b"");\n'
        f'let fr = std::path::Path::new("{fresh_rs_esc}");\n'
        f'delivery_telemetry::record_telemetry_event(fr, "cloud_sandbox", "issued", "s0", "e0", "d0", "", &[], &[], 10, None).unwrap();',
    )
    run = subprocess.run([str(driver)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    assert foreign.read_bytes() == original
    assert zero_rs.read_bytes() == b""
    assert fresh_rs.is_file()


def test_multifile_same_patch_deduplicates_efficacy_python_and_rust(tmp_path: Path) -> None:
    # Python: e1 & e2 in same session bound to same patch_digest="p" (passed=False) -> losses=1, trials=1, frozen=False
    py_store = tmp_path / "dedup_py.json"
    tr = DeliveryTelemetryTracker(py_store)
    for eid in ("e1", "e2"):
        tr.record_issued(
            client="claude_code", session_id="s1", envelope_id=eid, source_digest=f"src-{eid}",
            capsule_ids=["CAP-DEDUP"], pitfall_ids=["LT-003"],
        )
        tr.record_included_in_input(client="claude_code", envelope_id=eid)
    pb1 = tr.record_patch_bound(client="claude_code", envelope_id="e1", patch_digest="p", passed=False)
    pb2 = tr.record_patch_bound(client="claude_code", envelope_id="e2", patch_digest="p", passed=False)
    assert pb1["efficacy_updated"] is True
    assert pb2["efficacy_updated"] is False
    rep1 = tr.report()
    assert rep1["total_envelopes"] == 2
    eff1 = {r["id"]: r for r in rep1["efficacy_table"]}
    assert eff1["CAP-DEDUP"]["losses"] == 1 and eff1["CAP-DEDUP"]["trials"] == 1 and eff1["CAP-DEDUP"]["frozen"] is False
    assert eff1["LT-003"]["losses"] == 1 and eff1["LT-003"]["trials"] == 1 and eff1["LT-003"]["frozen"] is False

    # 2nd distinct failing patch "p2" -> losses=2, trials=2, frozen=True
    tr.record_issued(
        client="claude_code", session_id="s2", envelope_id="e3", source_digest="src-e3",
        capsule_ids=["CAP-DEDUP"], pitfall_ids=["LT-003"],
    )
    tr.record_included_in_input(client="claude_code", envelope_id="e3")
    pb3 = tr.record_patch_bound(client="claude_code", envelope_id="e3", patch_digest="p2", passed=False)
    assert pb3["efficacy_updated"] is True
    assert pb3["newly_frozen_ids"] == ["CAP-DEDUP", "LT-003"]
    eff2 = {r["id"]: r for r in tr.report()["efficacy_table"]}
    assert eff2["CAP-DEDUP"]["losses"] == 2 and eff2["CAP-DEDUP"]["trials"] == 2 and eff2["CAP-DEDUP"]["frozen"] is True

    # Cross-language dedup: Python binds e1 to patch "p", Rust binds e2 to same patch "p" -> STILL deduplicated!
    cross_store = tmp_path / "dedup_cross.json"
    ctr = DeliveryTelemetryTracker(cross_store)
    for eid in ("e1", "e2"):
        ctr.record_issued(client="claude_code", session_id="s1", envelope_id=eid, capsule_ids=["CAP-X"])
        ctr.record_included_in_input(client="claude_code", envelope_id=eid)
    ctr.record_patch_bound(client="claude_code", envelope_id="e1", patch_digest="p", passed=False)
    cross_esc = str(cross_store).replace("\\", "\\\\").replace('"', '\\"')
    driver = _compile_rust_driver(
        tmp_path,
        "rust_high6_driver",
        f'let p = std::path::Path::new("{cross_esc}");\n'
        f'let r2 = delivery_telemetry::record_telemetry_event(p, "claude_code", "patch_bound", "s1", "e2", "", "p", &[], &[], 0, Some(false)).unwrap();\n'
        f'assert!(r2.contains("\\"efficacy_updated\\":false"), "expected dedup skip: {{r2}}");\n'
        f'assert!(delivery_telemetry::load_frozen_ids(p).is_empty());\n'
        f'let caps = vec!["CAP-X".to_string()];\n'
        f'delivery_telemetry::record_telemetry_event(p, "claude_code", "issued", "s2", "e3", "d3", "", &caps, &[], 40, None).unwrap();\n'
        f'delivery_telemetry::record_telemetry_event(p, "claude_code", "included_in_input", "s2", "e3", "", "", &[], &[], 0, None).unwrap();\n'
        f'let r3 = delivery_telemetry::record_telemetry_event(p, "claude_code", "patch_bound", "s2", "e3", "", "p2", &[], &[], 0, Some(false)).unwrap();\n'
        f'assert!(r3.contains("\\"newly_frozen_ids\\":[\\"CAP-X\\"]"), "expected freeze on p2: {{r3}}");\n'
        f'println!("{{}}", delivery_telemetry::render_telemetry_report_json(p).unwrap());',
    )
    run = subprocess.run([str(driver)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout) == build_telemetry_report(cross_store)

    # Legacy v3.0.0 store without applied_outcomes key loads cleanly in Python & Rust
    legacy = tmp_path / "legacy_v300.json"
    legacy.write_text(
        json.dumps({"schema": DELIVERY_TELEMETRY_SCHEMA, "schema_version": SCHEMA_VERSION, "updated_at_utc": 100, "envelopes": {}, "efficacy": {}}) + "\n",
        encoding="utf-8",
    )
    assert build_telemetry_report(legacy)["ok"] is True


def test_medium9_schema_version_u64_bounds_late_stage_and_nonunix_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Dynamic schema_version parity with kintsugi.__version__ and Cargo.toml
    assert SCHEMA_VERSION == KINTSUGI_VERSION == _read_cargo_pkg_version()

    store = tmp_path / "m9.json"
    # u64 upper bound checks
    with pytest.raises(ValueError, match="INT_OVERFLOW"):
        record_telemetry_event(
            store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", estimated_tokens=1 << 64
        )
    with pytest.raises(ValueError, match="INT_OVERFLOW"):
        record_telemetry_event(
            store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", timestamp_utc=1 << 64
        )
    ok_max = record_telemetry_event(
        store, client="claude_code", stage="issued", session_id="s_max", envelope_id="e_max",
        estimated_tokens=(1 << 64) - 1, timestamp_utc=(1 << 64) - 1,
    )
    assert ok_max["ok"] is True and ok_max["schema_version"] == SCHEMA_VERSION

    # Late included_in_input after session already had patch updates disk stage to "included_in_input"
    tr = DeliveryTelemetryTracker(store)
    tr.record_issued(client="claude_code", session_id="s1", envelope_id="e1")
    tr.record_patch_bound(client="claude_code", envelope_id="e1", patch_digest="p1", passed=True)
    tr.record_issued(client="claude_code", session_id="s1", envelope_id="e2")
    late_res = tr.record_included_in_input(client="claude_code", envelope_id="e2")
    assert late_res["stage"] == "included_in_input"
    assert late_res["included_before_first_patch"] is False
    disk_e2 = json.loads(store.read_text(encoding="utf-8"))["envelopes"]["e2"]
    assert disk_e2["stage"] == "included_in_input"
    assert disk_e2["included_in_input"] is True
    assert disk_e2["included_before_first_patch"] is False

    # Non-Unix fallback lockfile MUST NEVER delete existing lockfile by mtime -> raises TELEMETRY_LOCK_TIMEOUT
    lock_store = tmp_path / "nonunix.json"
    lock_file = Path(f"{lock_store}.lock")
    lock_file.write_text("held-by-live-writer", encoding="utf-8")
    old_ts = time.time() - 7200.0
    os.utime(lock_file, (old_ts, old_ts))
    monkeypatch.setattr(dt_mod, "fcntl", None)
    monkeypatch.setattr(dt_mod.time, "sleep", lambda _: None)
    with pytest.raises(TimeoutError, match="TELEMETRY_LOCK_TIMEOUT"):
        record_telemetry_event(lock_store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1")
    assert lock_file.is_file() and lock_file.read_text(encoding="utf-8") == "held-by-live-writer"


# ---------------------------------------------------------------------------
# 12. v3.0.1 Round-2 Blind-Audit Regression Suite (MEDIUM #6..#11, LOW #13..#15)
# ---------------------------------------------------------------------------


def _find_kintsugi_rs_bin() -> Path | None:
    for cand in (OSS_ROOT / "target/debug/kintsugi-rs", OSS_ROOT / "target/release/kintsugi-rs"):
        if cand.is_file():
            return cand
    return None


def test_round2_malformed_envelope_u32_saturating_pipe_and_legacy_backfill_python_and_rust(tmp_path: Path) -> None:
    # 1. Malformed envelope & efficacy field types fail closed in BOTH Python and Rust!
    malformed_cases = [
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "patch_bound": "false"}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "capsule_ids": "CAP-1"}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "pitfall_ids": "LT-003"}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "estimated_tokens": None}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "timestamp_utc": None}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "included_in_input": 1}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "included_before_first_patch": "yes"}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "passed": "true"}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "patch_passed": "true"}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "source_digest": None}}, "efficacy": {}},
        {"envelopes": {"e1": {"envelope_id": "e1", "session_id": "s1", "client": "claude_code", "stage": "issued", "patch_digest": 123}}, "efficacy": {}},
        {"envelopes": {}, "efficacy": {"CAP-1": {"id": "CAP-1", "wins": 0, "losses": 0, "trials": 1, "consecutive_losses": 0, "frozen": False, "last_updated_utc": -1}}},
        {"envelopes": {}, "efficacy": {}, "applied_outcomes": "not-a-list"},
    ]
    bad_paths: list[Path] = []
    for idx, body in enumerate(malformed_cases):
        p = tmp_path / f"malformed_{idx}.json"
        doc = {"schema": DELIVERY_TELEMETRY_SCHEMA, **body}
        p.write_text(json.dumps(doc) + "\n", encoding="utf-8")
        bad_paths.append(p)
        with pytest.raises(ValueError, match="INVALID_TELEMETRY_STORE"):
            build_telemetry_report(p)

    # 2. Pipe '|' rejected in session_id, patch_digest, capsule_ids, pitfall_ids (Python)
    pipe_store = tmp_path / "pipe.json"
    with pytest.raises(ValueError, match="INVALID_SESSION_ID"):
        record_telemetry_event(pipe_store, client="claude_code", stage="issued", session_id="s|1", envelope_id="e1")
    with pytest.raises(ValueError, match="INVALID_ITEM_ID"):
        record_telemetry_event(pipe_store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", capsule_ids=["CAP|1"])
    with pytest.raises(ValueError, match="INVALID_ITEM_ID"):
        record_telemetry_event(pipe_store, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", pitfall_ids=["LT|1"])
    record_telemetry_event(pipe_store, client="claude_code", stage="issued", session_id="s1", envelope_id="e_ok")
    with pytest.raises(ValueError, match="INVALID_PATCH_DIGEST"):
        record_telemetry_event(pipe_store, client="claude_code", stage="patch_bound", session_id="s1", envelope_id="e_ok", patch_digest="p|1", passed=True)

    # 3. u32::MAX saturating increment parity (Python)
    u32_max = (1 << 32) - 1
    sat_doc = {
        "schema": DELIVERY_TELEMETRY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "updated_at_utc": 100,
        "envelopes": {},
        "efficacy": {
            "CAP-SAT": {
                "id": "CAP-SAT", "wins": u32_max, "losses": u32_max, "trials": u32_max,
                "consecutive_losses": u32_max, "frozen": False, "freeze_reason": None,
            }
        },
        "applied_outcomes": [],
    }
    sat_py = tmp_path / "sat_py.json"
    sat_py.write_text(json.dumps(sat_doc) + "\n", encoding="utf-8")
    record_telemetry_event(sat_py, client="claude_code", stage="issued", session_id="s1", envelope_id="e1", capsule_ids=["CAP-SAT"])
    record_telemetry_event(sat_py, client="claude_code", stage="included_in_input", session_id="s1", envelope_id="e1")
    record_telemetry_event(sat_py, client="claude_code", stage="patch_bound", session_id="s1", envelope_id="e1", patch_digest="p1", passed=False)
    py_sat_rep = build_telemetry_report(sat_py)
    py_sat_eff = {r["id"]: r for r in py_sat_rep["efficacy_table"]}["CAP-SAT"]
    assert (py_sat_eff["trials"], py_sat_eff["losses"], py_sat_eff["consecutive_losses"]) == (u32_max, u32_max, u32_max)

    # 4. Legacy v3.0.0 store without applied_outcomes key backfills and prevents double-counting (Python)
    legacy_doc = {
        "schema": DELIVERY_TELEMETRY_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "updated_at_utc": 100,
        "envelopes": {
            "e1": {
                "envelope_id": "e1", "session_id": "s1", "client": "claude_code", "source_digest": "d1",
                "capsule_ids": ["CAP-LEG"], "pitfall_ids": ["LT-003"], "estimated_tokens": 50,
                "stage": "patch_bound", "timestamp_utc": 90, "included_in_input": True,
                "included_before_first_patch": True, "included_at_utc": 91, "patch_bound": True,
                "patch_digest": "p1", "passed": False, "first_patch": True, "patch_bound_at_utc": 92,
            },
            "e2": {
                "envelope_id": "e2", "session_id": "s1", "client": "claude_code", "source_digest": "d2",
                "capsule_ids": ["CAP-LEG"], "pitfall_ids": ["LT-003"], "estimated_tokens": 50,
                "stage": "included_in_input", "timestamp_utc": 90, "included_in_input": True,
                "included_before_first_patch": True, "included_at_utc": 91, "patch_bound": False,
                "patch_digest": "", "passed": None, "first_patch": False, "patch_bound_at_utc": None,
            },
        },
        "efficacy": {
            "CAP-LEG": {"id": "CAP-LEG", "wins": 0, "losses": 1, "trials": 1, "consecutive_losses": 1, "frozen": False, "freeze_reason": None},
            "LT-003": {"id": "LT-003", "wins": 0, "losses": 1, "trials": 1, "consecutive_losses": 1, "frozen": False, "freeze_reason": None},
        },
    }
    leg_py = tmp_path / "leg_py.json"
    leg_py.write_text(json.dumps(legacy_doc) + "\n", encoding="utf-8")
    pb_leg = record_telemetry_event(leg_py, client="claude_code", stage="patch_bound", session_id="s1", envelope_id="e2", patch_digest="p1", passed=False)
    assert pb_leg["efficacy_updated"] is False
    assert pb_leg["newly_frozen_ids"] == []
    assert load_frozen_ids(leg_py) == set()
    leg_py_eff = {r["id"]: r for r in build_telemetry_report(leg_py)["efficacy_table"]}
    assert leg_py_eff["CAP-LEG"]["losses"] == 1 and leg_py_eff["CAP-LEG"]["trials"] == 1

    # 5. Live Rust parity on ALL 4 checks (malformed stores, pipe rejection, u32::MAX saturation, legacy backfill)
    sat_rs = tmp_path / "sat_rs.json"
    sat_rs.write_text(json.dumps(sat_doc) + "\n", encoding="utf-8")
    leg_rs = tmp_path / "leg_rs.json"
    leg_rs.write_text(json.dumps(legacy_doc) + "\n", encoding="utf-8")
    pipe_rs = tmp_path / "pipe_rs.json"

    rs_lines = []
    for bp in bad_paths:
        pe = str(bp).replace("\\", "\\\\").replace('"', '\\"')
        rs_lines.append(f'assert!(delivery_telemetry::render_telemetry_report_json(std::path::Path::new("{pe}")).is_err(), "expected err for {pe}");')
    pipe_e = str(pipe_rs).replace("\\", "\\\\").replace('"', '\\"')
    sat_e = str(sat_rs).replace("\\", "\\\\").replace('"', '\\"')
    leg_e = str(leg_rs).replace("\\", "\\\\").replace('"', '\\"')
    rs_lines.extend([
        f'let pp = std::path::Path::new("{pipe_e}");',
        'assert!(delivery_telemetry::record_telemetry_event(pp, "claude_code", "issued", "s|1", "e1", "", "", &[], &[], 0, None).is_err());',
        'assert!(delivery_telemetry::record_telemetry_event(pp, "claude_code", "issued", "s1", "e1", "", "", &["CAP|1".to_string()], &[], 0, None).is_err());',
        'delivery_telemetry::record_telemetry_event(pp, "claude_code", "issued", "s1", "e_ok", "", "", &[], &[], 0, None).unwrap();',
        'assert!(delivery_telemetry::record_telemetry_event(pp, "claude_code", "patch_bound", "s1", "e_ok", "", "p|1", &[], &[], 0, Some(true)).is_err());',
        f'let sp = std::path::Path::new("{sat_e}");',
        'delivery_telemetry::record_telemetry_event(sp, "claude_code", "issued", "s1", "e1", "", "", &["CAP-SAT".to_string()], &[], 0, None).unwrap();',
        'delivery_telemetry::record_telemetry_event(sp, "claude_code", "included_in_input", "s1", "e1", "", "", &[], &[], 0, None).unwrap();',
        'delivery_telemetry::record_telemetry_event(sp, "claude_code", "patch_bound", "s1", "e1", "", "p1", &[], &[], 0, Some(false)).unwrap();',
        f'let lp = std::path::Path::new("{leg_e}");',
        'let lres = delivery_telemetry::record_telemetry_event(lp, "claude_code", "patch_bound", "s1", "e2", "", "p1", &[], &[], 0, Some(false)).unwrap();',
        'assert!(lres.contains("\\"efficacy_updated\\":false"), "expected legacy backfill skip: {lres}");',
        'assert!(delivery_telemetry::load_frozen_ids(lp).is_empty());',
    ])
    driver = _compile_rust_driver(tmp_path, "rust_round2_driver", "\n".join(rs_lines))
    run = subprocess.run([str(driver)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    assert build_telemetry_report(sat_rs) == py_sat_rep
    assert build_telemetry_report(leg_rs) == build_telemetry_report(leg_py)


def test_round2_cli_task_pack_s3_multi_target_and_hook_workspace(tmp_path: Path) -> None:
    kbin = _find_kintsugi_rs_bin()
    if kbin is None:
        pytest.skip("kintsugi-rs binary unavailable")

    # 1. Live CLI task-pack --max-tokens 32 on src/kintsugi/cli.py -> total_tokens <= 32 AND packet <= 32 tokens
    cli_py = OSS_ROOT / "src/kintsugi/cli.py"
    p_tp = subprocess.run(
        [str(kbin), "task-pack", str(cli_py), "--max-tokens", "32", "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    assert p_tp.returncode == 0, p_tp.stderr
    j_tp = json.loads(p_tp.stdout)
    assert j_tp["ok"] is True
    assert j_tp["total_tokens"] <= 32
    assert j_tp["estimated_tokens"] == j_tp["total_tokens"] <= 32
    assert isinstance(j_tp["files"], list)
    for f_env in j_tp["files"]:
        for cid in f_env["capsule_ids"]:
            assert cid in j_tp["packet"]
        for lid in f_env["lexicon_ids"]:
            assert lid in j_tp["packet"]

    # Multi-file task-pack: 10 files with --max-tokens 200 -> total_tokens <= 200 and honest files list
    sample_code = (
        "import subprocess\n"
        "def query_and_run(cur, uid, bin_path):\n"
        "    sql = 'SELECT * FROM orders WHERE id = ?'\n"
        "    cur.execute(sql, (uid,))\n"
        "    subprocess.run([bin_path, '--check'], shell=False)\n"
    )
    ten_files = []
    for i in range(10):
        fp = tmp_path / f"f{i}.py"
        fp.write_text(sample_code, encoding="utf-8")
        ten_files.append(str(fp))
    p_tp10 = subprocess.run(
        [str(kbin), "task-pack", *ten_files, "--max-tokens", "200", "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    assert p_tp10.returncode == 0, p_tp10.stderr
    j_tp10 = json.loads(p_tp10.stdout)
    assert j_tp10["total_tokens"] <= 200
    assert j_tp10["files_count"] == len(j_tp10["files"])
    for f_env in j_tp10["files"]:
        assert f_env["path"] in j_tp10["packet"]

    # 2. Live CLI multi-target s3-audit populates missing_targets & NO_INPUT tier/strict_verdict!
    missing_path = str(tmp_path / "does_not_exist_target.py")
    p_s3 = subprocess.run(
        [str(kbin), "s3-audit", ten_files[0], missing_path, "--format", "json"],
        capture_output=True, text=True, check=False,
    )
    assert p_s3.returncode == 2, f"expected rc=2 for NO_INPUT, got {p_s3.returncode}: {p_s3.stdout} {p_s3.stderr}"
    j_s3 = json.loads(p_s3.stdout)
    assert j_s3["missing_targets"] == [missing_path]
    assert j_s3["assurance_tier"] == "NO_INPUT"
    assert j_s3["verdict"] == "FAIL_NO_INPUT"
    assert j_s3["strict_verdict"] == "NO_INPUT"

    # 3. Live CLI hook claude-post-read --workspace <ws> from ANOTHER CWD excludes frozen IDs!
    ws = tmp_path / "hook_ws"
    other_cwd = tmp_path / "other_cwd"
    (ws / ".kintsugi").mkdir(parents=True)
    other_cwd.mkdir(parents=True)
    sample_ws = ws / "sample.py"
    sample_ws.write_text(sample_code, encoding="utf-8")
    ws_store = ws / ".kintsugi" / "delivery_telemetry.json"
    for idx in (1, 2):
        record_telemetry_event(
            ws_store, client="claude_code", stage="issued", session_id=f"s{idx}", envelope_id=f"e{idx}",
            source_digest="d1", capsule_ids=["CAP-SEC-SUBPROCESS-ARGV"], pitfall_ids=["LT-003"],
        )
        record_telemetry_event(ws_store, client="claude_code", stage="included_in_input", session_id=f"s{idx}", envelope_id=f"e{idx}")
        record_telemetry_event(ws_store, client="claude_code", stage="patch_bound", session_id=f"s{idx}", envelope_id=f"e{idx}", patch_digest=f"p{idx}", passed=False)

    hook_stdin = json.dumps({"tool_name": "Read", "tool_input": {"file_path": str(sample_ws)}})
    p_hook = subprocess.run(
        [str(kbin), "hook", "claude-post-read", "--low-tier", "--max-tokens", "640", "--workspace", str(ws)],
        input=hook_stdin, cwd=str(other_cwd), capture_output=True, text=True, check=False,
    )
    assert p_hook.returncode == 0, p_hook.stderr
    j_hook = json.loads(p_hook.stdout)
    env_out = j_hook["kintsugiEnvelope"]
    assert "CAP-SEC-SUBPROCESS-ARGV" not in env_out["capsule_ids"]
    assert "LT-003" not in env_out["lexicon_ids"]
    assert "CAP-SEC-SUBPROCESS-ARGV" not in p_hook.stdout
    assert "LT-003" not in p_hook.stdout
