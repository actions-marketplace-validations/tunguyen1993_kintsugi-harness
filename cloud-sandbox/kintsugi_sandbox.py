#!/usr/bin/env python3
"""Kintsugi Harness v3.1.1 — Cloud Sandbox Edition (Zero-Dependency Cloud Sandbox CLI).

Self-contained pure-Python stdlib orchestrator built for cloud sandboxes and coding-agent
containers (zero external pip installs, zero Rust toolchain, zero secrets, zero host paths).
Delegates IO/DLP (`security_io`), supply-chain updates (`bootstrap`), Truth Gate
(`truth_gate`), self-evolution (`evolution_loop`), and scanning/masking (`scanner_sandbox`).
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import secrets
import sys
import tempfile
import time
import unicodedata
from decimal import Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

sys.dont_write_bytecode = True

BUNDLE_ROOT = Path(__file__).resolve().parent
if (BUNDLE_ROOT / "src" / "kintsugi").is_dir():
    SRC_DIR, SRC_ROOT_DIR, LAYOUT_MODE = BUNDLE_ROOT / "src", BUNDLE_ROOT, "standalone_bundle"
elif (BUNDLE_ROOT.parent / "src" / "kintsugi").is_dir():
    SRC_DIR, SRC_ROOT_DIR, LAYOUT_MODE = BUNDLE_ROOT.parent / "src", BUNDLE_ROOT.parent, "github_repo"
else:
    SRC_DIR, SRC_ROOT_DIR, LAYOUT_MODE = BUNDLE_ROOT / "src", BUNDLE_ROOT, "unknown"
DATA_DIR = BUNDLE_ROOT / "data"
for _p in (BUNDLE_ROOT, SRC_DIR):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
os.environ.setdefault("KINTSUGI_DISABLE_NATIVE", "1")

import security_io  # noqa: E402
from bootstrap import (  # noqa: E402
    REPO_URL as GITHUB_REPO_URL,
    install_or_update as bootstrap_install_or_update,
    verify_manifest_tree,
)
from evolution_loop import (  # noqa: E402
    DEFAULT_EVOLUTION_STORE, DEFAULT_STATE_DIR, DEFAULT_TELEMETRY_STORE,
    evolve_export_patch, evolve_import_patch, evolve_learn, evolve_status,
    load_active_learned_scars, resolve_state_paths,
)
from scanner_sandbox import (  # noqa: E402
    EDITION_NAME, KINTSUGI_VERSION, TASK_SYNONYMS, audit_deliverable,
    expand_task_tokens, extract_code_capsule_signals, extract_symbol_blocks,
    infer_lang_from_path, mask_code_lines, pack_brief_within_budget,
    push_ident_subtokens, scan_target,
)
from truth_gate import run_builtin_truth_gate, run_custom_truth_gate  # noqa: E402

from kintsugi.compressor import estimate_tokens  # noqa: E402
import kintsugi.evolution.delivery_telemetry as delivery_telemetry  # noqa: E402
from kintsugi.evolution.delivery_telemetry import (  # noqa: E402
    build_telemetry_report, record_telemetry_event, try_load_frozen_ids,
)
from kintsugi.evolution.fast_learner import validate_teacher_provenance  # noqa: E402
from kintsugi.starter_pack import get_full_crs_scars  # noqa: E402
from kintsugi.tools.repo_scout import RepoScout  # noqa: E402

CAPSULES_PATH = DATA_DIR / "invariant_capsules_v3.json"
LEXICON_PATH = DATA_DIR / "low_tier_pitfall_lexicon_v3.json"
_SUPPORTED_CLIENTS = tuple(getattr(delivery_telemetry, "SUPPORTED_CLIENTS", ("cloud_sandbox",)))
DEFAULT_TELEMETRY_CLIENT = (
    "cloud_sandbox"
    if "cloud_sandbox" in _SUPPORTED_CLIENTS
    else ("antigravity" if "antigravity" in _SUPPORTED_CLIENTS else _SUPPORTED_CLIENTS[0])
)
MAX_NUM_STR_LEN, MAX_NUM_ADJUSTED, MAX_META_DEPTH, MAX_META_NODES = 80, 60, 16, 2000
_CARD_WORD_RE = re.compile(r"(?<![a-z])(?:visa|mastercard)(?![a-z])")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_HEX_INT_RE = re.compile(r"^[+-]?0x[0-9a-f]+$")
_PEM_BEGIN_LINE_RE = re.compile("-----BEG" + r"IN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_END_LINE_RE = re.compile("-----END" + r" [A-Z0-9 ]*PRIVATE KEY-----")
_SCAN_RULE_TO_SCAR_PREFIXES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("KS-001", ("LT-062",)),
    ("DLP-PEM-PRIVATE-KEY", ("LT-062",)),
    ("DLP-API-TOKEN", ("LT-062",)),
    ("DLP-JWT", ("LT-062",)),
    ("DLP-SECRET-ASSIGNMENT", ("LT-062",)),
    ("DLP-SECRET-KV-PAIR", ("LT-062",)),
    ("DLP-RFC1918-IP", ("LT-062",)),
    ("DLP-HOST-USER-PATH", ("LT-062",)),
    ("DLP-HEX-KEY-OR-WALLET", ("LT-062",)),
    ("DLP-BIDI-OR-NUL", ("CAP-SEC-RUNTIME-BIDI-MAC", "LT-015")),
    ("KS-003", ("CAP-SEC-SUBPROCESS-ARGV", "LT-005")),
    ("KS-004", ("LT-008",)),
    ("KS-005", ("LT-007",)),
    ("LT-007", ("LT-007",)),
    ("KS-007", ("LT-003", "LT-041")),
    ("SEC-SQL-", ("LT-003", "LT-041")),
    ("KS-013", ("CAP-SEC-SUBPROCESS-ARGV", "LT-005")),
    ("KS-016", ("LT-072",)),
    ("KS-017", ("CAP-SEC-SUBPROCESS-ARGV", "LT-005")),
    ("SEC-SHELL-", ("CAP-SEC-SUBPROCESS-ARGV", "LT-005")),
    ("KS-019", ("CAP-SEC-RUNTIME-BIDI-MAC", "LT-015")),
    ("SEC-BIDI-", ("CAP-SEC-RUNTIME-BIDI-MAC", "LT-015")),
    ("KS-020", ("LT-021",)),
    ("SYMLINK-", ("CAP-SEC-PATH-NOFOLLOW-0600", "LT-004", "LT-020", "LT-076")),
)


def _load_json(path: Path) -> Dict[str, Any]:
    raw = security_io.read_regular_bytes_secure(path, max_bytes=security_io.MAX_STORE_BYTES)
    return security_io.strict_json_loads(raw.decode("utf-8"))


def _verify_manifest_strict(
    bundle_dir: Path,
    *,
    src_root: Optional[Path] = None,
    expected_manifest_sha256: str = "",
    reject_extra_files: bool = False,
    allow_pycache: bool = False,
) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "src_root": src_root,
        "expected_manifest_sha256": expected_manifest_sha256,
        "reject_extra_files": reject_extra_files,
    }
    if "allow_pycache" in inspect.signature(verify_manifest_tree).parameters:
        kwargs["allow_pycache"] = allow_pycache
    return verify_manifest_tree(bundle_dir, **kwargs)


def _load_telemetry_store_strict(tel_store: Path) -> Dict[str, Any]:
    loader = getattr(delivery_telemetry, "load_telemetry_store", None)
    if callable(loader):
        return loader(tel_store)
    if tel_store.exists():
        raw = delivery_telemetry.read_regular_text_secure(tel_store, delivery_telemetry.MAX_TELEMETRY_FILE_BYTES)
        if raw is not None and len(raw) == 0:
            raise ValueError(f"CORRUPT_EMPTY_TELEMETRY_STORE: {tel_store}")
    return delivery_telemetry._load_store(tel_store)


def _load_frozen_ids_strict(tel_store: Path) -> Set[str]:
    strict_fn = getattr(delivery_telemetry, "load_frozen_ids_strict", None)
    if callable(strict_fn):
        return {str(x).strip().upper() for x in strict_fn(tel_store) if str(x).strip()}
    if tel_store.exists():
        raw = delivery_telemetry.read_regular_text_secure(tel_store, delivery_telemetry.MAX_TELEMETRY_FILE_BYTES)
        if raw is not None and len(raw) == 0:
            raise ValueError(f"CORRUPT_EMPTY_TELEMETRY_STORE: {tel_store}")
    return {str(x).strip().upper() for x in try_load_frozen_ids(tel_store) if str(x).strip()}


def _redact_multiline_pem_blocks(raw: str) -> str:
    """Linear-time O(n) pre-strip redactor for multiline PEM private-key blocks."""
    out: List[str] = []
    in_pem = False
    for line in raw.splitlines():
        if _PEM_BEGIN_LINE_RE.search(line):
            in_pem = True
            out.append("[REDACTED_DLP]")
            if _PEM_END_LINE_RE.search(line):
                in_pem = False
            continue
        if in_pem:
            if _PEM_END_LINE_RE.search(line):
                in_pem = False
            continue
        out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# JIT Pre-Read Brief (<500 Token Budget + Single Snapshot + Auto-Telemetry)
# ---------------------------------------------------------------------------


def build_brief(
    target_path: Optional[Path] = None, code_override: Optional[str] = None, task_text: str = "",
    lang_hint: str = "auto", category_filter: str = "", max_capsules: int = 4, max_pitfalls: int = 6,
    max_tokens: int = 480, evolution_store: Optional[Path] = None, telemetry_store: Optional[Path] = None,
    auto_record_telemetry: bool = False, mark_included: bool = False, session_id: str = "", client: str = DEFAULT_TELEMETRY_CLIENT,
) -> Dict[str, Any]:
    """Build JIT Pre-Read Brief with strict token cap, single frozen snapshot, and auto-telemetry."""
    t0 = time.perf_counter()
    for name, val, lo, hi in (("MAX_PITFALLS", max_pitfalls, 1, 20), ("MAX_TOKENS", max_tokens, 50, 4000), ("MAX_CAPSULES", max_capsules, 0, 20)):
        if isinstance(val, bool) or not isinstance(val, int) or not (lo <= val <= hi):
            raise ValueError(f"INVALID_{name}: must be an integer in {lo}..{hi}")

    code_text = code_override or ""
    if code_override is None and target_path is not None:
        security_io.reject_symlink(target_path)
        security_io.reject_symlink_ancestors(target_path.parent if str(target_path.parent) else Path("."))
        if not target_path.exists():
            raise FileNotFoundError(f"BRIEF_TARGET_NOT_FOUND: {target_path}")
        if not target_path.is_file():
            raise ValueError(f"BRIEF_TARGET_NOT_FILE: {target_path}")
        code_text = security_io.read_regular_bytes_secure(target_path, max_bytes=security_io.MAX_DEFAULT_FILE_BYTES).decode("utf-8", errors="replace")

    cap_doc, lex_doc = _load_json(CAPSULES_PATH), _load_json(LEXICON_PATH)
    frozen_ids: Set[str] = set()
    if telemetry_store is not None and telemetry_store.exists():
        frozen_ids = _load_frozen_ids_strict(telemetry_store)

    def _active(rec: Dict[str, Any]) -> bool:
        return (str(rec.get("id", "")).strip().upper() not in frozen_ids) and (not rec.get("frozen")) and (int(rec.get("consecutive_losses", 0)) < 2)

    capsules = [c for c in cap_doc["capsules"] if _active(c)]
    entries = [e for e in lex_doc["entries"] if _active(e)]
    learned_ids: Set[str] = set()
    if evolution_store is not None and evolution_store.exists():
        existing = {str(e["id"]).upper() for e in entries}
        for item in load_active_learned_scars(evolution_store, telemetry_store=None):
            iid = str(item["id"]).upper()
            if iid not in existing and _active(item):
                entries.append(item)
                existing.add(iid)
                learned_ids.add(iid)

    lang = infer_lang_from_path(target_path) if lang_hint == "auto" else lang_hint.lower()
    cand_caps: List[Tuple[Dict[str, Any], str]] = []
    cand_pits: List[Tuple[Dict[str, Any], str]] = []
    struct_tags: List[str] = []

    def _entry_ok(e: Dict[str, Any]) -> bool:
        if category_filter and e["category"].lower() != category_filter.lower():
            return False
        langs = e.get("languages", ["*"])
        return lang == "*" or "*" in langs or lang in langs

    if code_text:
        signals, struct_tags = extract_code_capsule_signals(code_text, lang=lang)
        cand_caps = [(c, "code") for c in capsules if all(any(t in signals for t in g) for g in c["trigger_groups"])][:max_capsules]
        scored_p = []
        for e in entries:
            groups = e.get("trigger_groups") or []
            if _entry_ok(e) and groups and all(any(t in signals for t in g) for g in groups):
                score = sum(1 + (4 if t.startswith("@struct_") else 0) for g in groups for t in g if t in signals)
                scored_p.append((score, e))
        scored_p.sort(key=lambda x: (-x[0], x[1]["id"]))
        cand_pits = [(e, "code") for _, e in scored_p[:max_pitfalls]]

    if task_text or category_filter:
        task_low, q_toks = task_text.lower(), expand_task_tokens(task_text)
        seen_c, seen_p = {c["id"] for c, _ in cand_caps}, {p["id"] for p, _ in cand_pits}
        scored_c = sorted(
            ((ov, c) for c in capsules if c["id"] not in seen_c and (ov := len(q_toks & expand_task_tokens(f"{c['id']} {c['domain']} {c['when_clause']} " + " ".join(t for g in c["trigger_groups"] for t in g if not t.startswith("@struct_"))))) >= 1),
            key=lambda x: (-x[0], x[1]["id"]),
        )
        cand_caps.extend((c, "task") for _, c in scored_c[: max(0, max_capsules - len(cand_caps))])

        scored_tp = []
        for e in entries:
            if e["id"] in seen_p or not _entry_ok(e):
                continue
            ov = len(q_toks & expand_task_tokens(f"{e['id']} {e['slug']} {e['category']} {e['precondition']} " + " ".join(t for g in e["trigger_groups"] for t in g if not t.startswith("@struct_"))))
            exact = (e["id"].lower() in task_low) or (e["slug"].lower() in task_low)
            if category_filter and not task_text:
                scored_tp.append((1, e))
            elif str(e["id"]).upper() in learned_ids:
                if ov >= 2 or exact:
                    scored_tp.append((ov + (2 if exact else 0), e))
            elif ov >= 1:
                scored_tp.append((ov, e))
        scored_tp.sort(key=lambda x: (-x[0], x[1]["id"]))
        cand_pits.extend((e, "task") for _, e in scored_tp[: max(0, max_pitfalls - len(cand_pits))])

    sel_caps, sel_pits, compact_text, dropped = pack_brief_within_budget(cand_caps, cand_pits, max_tokens)
    est_tokens = 0 if not compact_text else estimate_tokens(compact_text)

    envelope_id, telemetry_recorded, marked_included = "", False, False
    if auto_record_telemetry and telemetry_store is not None and (sel_caps or sel_pits):
        envelope_id, sess = f"env-{secrets.token_hex(6)}", session_id or f"sess-{secrets.token_hex(4)}"
        src_dig = security_io.sha256_bytes((code_text or task_text or category_filter).encode("utf-8"))[:16]
        record_telemetry_event(
            telemetry_store, client=client, stage="issued", session_id=sess, envelope_id=envelope_id,
            source_digest=src_dig, capsule_ids=[c["id"] for c, _ in sel_caps],
            pitfall_ids=[p["id"] for p, _ in sel_pits], estimated_tokens=est_tokens,
        )
        telemetry_recorded = True
        if mark_included:
            record_telemetry_event(telemetry_store, client=client, stage="included_in_input", session_id=sess, envelope_id=envelope_id)
            marked_included = True

    return {
        "ok": True, "edition": EDITION_NAME, "kintsugi_version": KINTSUGI_VERSION, "client": client, "lang": lang,
        "structural_tags": struct_tags, "learned_scars_loaded": len(learned_ids),
        "matched_capsules_count": len(sel_caps), "matched_pitfalls_count": len(sel_pits),
        "dropped_by_token_budget": dropped, "max_tokens": max_tokens, "estimated_tokens": est_tokens,
        "envelope_id": envelope_id, "telemetry_recorded": telemetry_recorded, "marked_included": marked_included,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        "capsules": [{"id": c["id"], "domain": c["domain"], "match_source": s} for c, s in sel_caps],
        "pitfalls": [{"id": p["id"], "slug": p["slug"], "category": p["category"], "match_source": s} for p, s in sel_pits],
        "compact": compact_text,
    }


# ---------------------------------------------------------------------------
# Bounded Decimal Parser & NFKC Zero-Outbound Agent Transaction & Policy Guard
# ---------------------------------------------------------------------------


def _parse_bounded_decimal(raw_val: Any, label: str) -> Decimal:
    if isinstance(raw_val, bool) or raw_val is None or isinstance(raw_val, (dict, list, tuple, set)):
        raise ValueError(f"INVALID_NUMERIC({label}): {raw_val!r}")
    s = unicodedata.normalize("NFKC", str(raw_val)).strip()
    if not s or len(s) > MAX_NUM_STR_LEN:
        raise ValueError(f"NUMERIC_LENGTH_INVALID({label}): len={len(s)}")
    try:
        dec = Decimal(s)
    except InvalidOperation as exc:
        raise ValueError(f"INVALID_DECIMAL({label}): {s!r}") from exc
    if not dec.is_finite() or abs(dec.adjusted()) > MAX_NUM_ADJUSTED:
        raise ValueError(f"NON_FINITE_OR_EXTREME_DECIMAL({label}): {s!r}")
    return dec


def _nfkc_low(s: str) -> str:
    cleaned = "".join(ch for ch in unicodedata.normalize("NFKC", s) if unicodedata.category(ch) != "Cf")
    return cleaned.strip().lower()


def _canon_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", _nfkc_low(name))


def evaluate_tx_guard_json(raw_json: str) -> Dict[str, Any]:
    """Parse raw JSON strictly (Decimal floats, no duplicate keys/NaN), then run fail-closed tx-guard."""
    try:
        parsed = security_io.strict_json_loads(raw_json, parse_float=Decimal)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "verdict": "BLOCKED", "blocks": [f"BLOCK_INVALID_JSON: {exc}"], "owner_decisions": []}
    return evaluate_tx_guard(parsed)


def evaluate_tx_guard(payload: Any) -> Dict[str, Any]:
    """Fail-closed NFKC-normalized Zero-Outbound Agent Transaction & Policy Guard."""
    if not isinstance(payload, dict):
        return {
            "ok": False, "verdict": "BLOCKED",
            "blocks": [f"BLOCK_INVALID_METADATA: expected JSON object, got {type(payload).__name__}"],
            "owner_decisions": [],
        }
    if not payload:
        return {
            "ok": False, "verdict": "BLOCKED",
            "blocks": ["BLOCK_INVALID_METADATA: empty payload; explicit action declaration is required"],
            "owner_decisions": [],
        }

    blocks: List[str] = []
    owner_decisions: List[str] = []
    fee_canons = {"entryfee", "upfrontfee", "deposit", "collateral", "bond"}
    fee_words = ("entryfee", "upfrontfee", "collateral", "bond")
    card_sub_toks = (
        "payment_card", "payment card", "credit_card", "credit card",
        "debit_card", "debit card", "card_identity", "card_verification",
    )
    dlp_toks = ("internal transcript", "chat transcript", "private cookie", "seed phrase", "private key")
    outbound_toks = (
        "erc20.transfer", "erc20_transfer", "erc20.approve", "erc20_approve",
        "transferwithauthorization", "eth_sendrawtransaction", "eth_sendtransaction",
        "solana_transfer", "sign_and_send_transaction", "post /api/loans",
        "send outbound", "outbound tx", "outbound transfer",
    )
    outbound_flag_canons = {
        "transfersfunds", "transferfunds", "movesfunds", "movesassets",
        "sendvalue", "outboundtransfer",
    }
    tx_ctx_canons = {
        "transaction", "transactions", "tx", "txs", "signing", "signature",
        "payload", "call", "calls", "operations", "instructions", "messages",
    }
    tx_val_canons = {"value", "txvalue", "transactionvalue", "wei", "amountwei", "gasvalue", "lamports"}
    always_tx_val_canons = {"txvalue", "transactionvalue"}
    tx_act_canons = {"action", "txaction", "signingaction", "method", "operation"}
    always_tx_act_canons = {"signingaction", "txmethod", "txaction"}
    safe_tx_actions = {"personalsign", "eip191", "ed25519auth", "siwe", "readonly", "none"}
    blocked_tx_actions = {
        "ethsendtransaction", "ethsendrawtransaction", "erc20transfer", "erc20approve",
        "transferwithauthorization", "solanatransfer", "signandsendtransaction",
        "transfer", "send", "withdraw", "approve", "swap", "bridge", "stake", "deposit", "loan",
    }
    identity_ctx_canons = {"verifiedby", "identitygate", "authmethod"}

    def _is_fee_or_deposit(ck: str) -> bool:
        if ck == "depositrequired":
            return False
        return ck in fee_canons or any(w in ck for w in fee_words) or ("deposit" in ck)

    def _chk_fee_or_deposit(loc: str, raw_val: Any) -> Optional[Decimal]:
        try:
            dec = _parse_bounded_decimal(raw_val, loc)
        except ValueError as exc:
            blocks.append(f"BLOCK_INVALID_METADATA: {exc}")
            return None
        if dec < Decimal("0"):
            blocks.append(f"BLOCK_INVALID_METADATA: negative {loc}={raw_val!r}")
            return None
        if dec > Decimal("0"):
            blocks.append(f"BLOCK_DEPOSIT_REQUIRED: {loc}={raw_val} > 0")
        return dec

    def _chk_deposit_required(loc: str, val: Any) -> None:
        if val is False:
            return
        if val is True or (isinstance(val, str) and _nfkc_low(val) in ("true", "1", "yes", "on")):
            blocks.append(f"BLOCK_DEPOSIT_REQUIRED: {loc} is true")
            return
        blocks.append(f"BLOCK_DEPOSIT_REQUIRED: {loc} must be boolean false, got {val!r}")

    def _chk_outbound_flag(loc: str, val: Any) -> None:
        if val is False or val is None:
            return
        if val is True:
            blocks.append(f"BLOCK_OUTBOUND_TRANSFER: {loc}=true moves funds/assets")
            return
        if isinstance(val, str):
            low = _nfkc_low(val)
            if low in ("false", "0", "no", "none", ""):
                return
            if low in ("true", "1", "yes", "on"):
                blocks.append(f"BLOCK_OUTBOUND_TRANSFER: {loc}={val!r} moves funds/assets")
                return
            if _HEX_INT_RE.fullmatch(low) and len(low) <= MAX_NUM_STR_LEN:
                if int(low, 16) != 0:
                    blocks.append(f"BLOCK_OUTBOUND_TRANSFER: {loc}={val!r} != 0 moves funds/assets")
                return
        try:
            dec = _parse_bounded_decimal(val, loc)
        except ValueError:
            blocks.append(f"BLOCK_OUTBOUND_TRANSFER: unparseable outbound flag {loc}={val!r}")
            return
        if dec != Decimal("0"):
            blocks.append(f"BLOCK_OUTBOUND_TRANSFER: {loc}={val!r} != 0 moves funds/assets")

    def _chk_tx_value(loc: str, val: Any) -> None:
        if isinstance(val, str):
            low = _nfkc_low(val)
            if _HEX_INT_RE.fullmatch(low) and len(low) <= MAX_NUM_STR_LEN:
                if int(low, 16) != 0:
                    blocks.append(f"BLOCK_OUTBOUND_TRANSFER: non-zero outbound value {loc}={val!r}")
                return
        try:
            dec = _parse_bounded_decimal(val, loc)
        except ValueError:
            blocks.append(f"BLOCK_OUTBOUND_TRANSFER: unparseable outbound value {loc}={val!r}")
            return
        if dec != Decimal("0"):
            blocks.append(f"BLOCK_OUTBOUND_TRANSFER: non-zero outbound value {loc}={val!r}")

    actions_seen = 0

    def _chk_tx_action(loc: str, val: Any) -> None:
        nonlocal actions_seen
        actions_seen += 1
        if not isinstance(val, str) or not _canon_key(val):
            owner_decisions.append(f"NEEDS_OWNER_DECISION(TX_ACTION): non-string or empty signing/tx action at {loc}")
            return
        act = _canon_key(val)
        if act in blocked_tx_actions:
            blocks.append(f"BLOCK_OUTBOUND_TRANSFER: outbound tx/signing action {loc}={val!r}")
        elif act not in safe_tx_actions:
            owner_decisions.append(f"NEEDS_OWNER_DECISION(TX_ACTION): unknown signing/tx action {loc}={val!r}")

    nodes = 0

    def _walk(obj: Any, path: str, depth: int, in_id_ctx: bool, in_tx_ctx: bool) -> None:
        nonlocal nodes, actions_seen
        nodes += 1
        if depth > MAX_META_DEPTH or nodes > MAX_META_NODES:
            blocks.append("BLOCK_INVALID_METADATA: metadata nesting/size limit exceeded")
            return
        if isinstance(obj, str):
            low = _nfkc_low(obj)
            loc = path or "root"
            if any(t in low for t in card_sub_toks) or bool(_CARD_WORD_RE.search(low)) or (in_id_ctx and "card" in low):
                blocks.append(f"BLOCK_CARD_GATE: payment-card identity verification at {loc}")
            if any(t in low for t in dlp_toks):
                blocks.append(f"BLOCK_DLP_VIOLATION: requests internal transcripts/secrets at {loc}")
            if any(t in low for t in outbound_toks):
                blocks.append(f"BLOCK_OUTBOUND_TRANSFER: requests outbound transfer/approval/loan at {loc}")
            if re.search(r"\bkyc\b", low):
                owner_decisions.append("NEEDS_OWNER_DECISION(KYC): owner must review/perform KYC personally")
            return
        if isinstance(obj, list):
            for idx, item in enumerate(obj):
                _walk(item, f"{path}[{idx}]", depth + 1, in_id_ctx, in_tx_ctx)
            return
        if isinstance(obj, dict):
            local_c: Dict[str, List[str]] = {}
            for k, v in obj.items():
                if not isinstance(k, str) or not (ck := _canon_key(k)):
                    blocks.append(f"BLOCK_INVALID_METADATA: invalid key {k!r} at {path or 'root'}")
                    continue
                local_c.setdefault(ck, []).append(k)
                sub = f"{path}.{k}" if path else k
                if ck == "depositrequired":
                    _chk_deposit_required(sub, v)
                elif ck in outbound_flag_canons:
                    _chk_outbound_flag(sub, v)
                elif _is_fee_or_deposit(ck):
                    _chk_fee_or_deposit(sub, v)
                if ((in_tx_ctx or depth == 0) and ck in tx_val_canons) or (ck in always_tx_val_canons):
                    _chk_tx_value(sub, v)
                if (((in_tx_ctx or depth == 0) and ck in tx_act_canons) or (ck in always_tx_act_canons)) and not isinstance(v, dict):
                    _chk_tx_action(sub, v)
                if depth == 0 and ck == "mode" and isinstance(v, str) and _canon_key(v) == "readonly":
                    actions_seen += 1
                if ck == "kycrequired" and v is True:
                    owner_decisions.append("NEEDS_OWNER_DECISION(KYC): owner must review/perform KYC personally")
                if ck == "ownerapprovalrequired" and v is True:
                    owner_decisions.append("NEEDS_OWNER_DECISION(OWNER_APPROVAL): explicit owner approval required")
                _walk(v, sub, depth + 1, in_id_ctx or ck in identity_ctx_canons, in_tx_ctx or ck in tx_ctx_canons)
            for ck, keys in local_c.items():
                if len(keys) > 1:
                    blocks.append(f"BLOCK_ALIAS_CONFLICT: multiple variant keys for {ck!r} at {path or 'root'}: {keys}")

    _walk(payload, "", 0, False, False)

    by_c: Dict[str, List[Tuple[str, Any]]] = {}
    for k, v in payload.items():
        if isinstance(k, str) and (ck := _canon_key(k)):
            by_c.setdefault(ck, []).append((k, v))

    status_items = by_c.get("status", []) + by_c.get("state", [])
    if status_items:
        seen_statuses: Set[str] = set()
        for ok_k, sv in status_items:
            norm_s = _nfkc_low(sv) if isinstance(sv, str) else repr(sv)
            seen_statuses.add(norm_s)
            if not isinstance(sv, str) or norm_s not in ("open", "active", "ready", "pending", "published"):
                blocks.append(f"BLOCK_CLOSED_OR_INVALID_STATUS: {ok_k}={sv!r}")
        if len(seen_statuses) > 1:
            blocks.append("BLOCK_CONFLICTING_FIELDS: conflicting status/state values")

    for ok_k, vv in by_c.get("verifiedby", []):
        if vv is not None and not isinstance(vv, (str, dict, list)):
            blocks.append(f"BLOCK_INVALID_METADATA: {ok_k} has invalid type {type(vv).__name__}")

    if actions_seen == 0:
        blocks.append("BLOCK_INVALID_METADATA: explicit action declaration is required")

    blocks, owner_decisions = list(dict.fromkeys(blocks)), list(dict.fromkeys(owner_decisions))
    verdict = "BLOCKED" if blocks else ("NEEDS_OWNER_DECISION" if owner_decisions else "PASS_READONLY_0_OUTBOUND")
    return {"ok": verdict == "PASS_READONLY_0_OUTBOUND", "verdict": verdict, "blocks": blocks, "owner_decisions": owner_decisions}


# ---------------------------------------------------------------------------
# Exact Decimal Ledger Check & Honest Delivery Verification (`verify-delivery`)
# ---------------------------------------------------------------------------


def _round_fraction_to_step(val_f: Fraction, step_f: Fraction) -> Fraction:
    """Exact infinite-precision rational ROUND_HALF_UP (away from zero) onto multiples of `step_f`."""
    ratio = val_f / step_f
    sign = -1 if ratio.numerator < 0 else 1
    q, r = divmod(abs(ratio.numerator), ratio.denominator)
    if 2 * r >= ratio.denominator:
        q += 1
    return Fraction(sign * q, 1) * step_f


def _format_fraction_fixed(val_f: Fraction, frac_digits: int) -> str:
    """Format an exact terminating rational `val_f` at `frac_digits` decimal places without precision loss."""
    scaled = val_f * (10 ** frac_digits)
    if scaled.denominator != 1:
        raise ValueError(f"NON_EXACT_DECIMAL_SCALE: {val_f!r} at 10^-{frac_digits}")
    n = scaled.numerator
    neg = n < 0
    s = str(abs(n))
    if frac_digits == 0:
        out = s
    else:
        if len(s) <= frac_digits:
            s = s.zfill(frac_digits + 1)
        out = f"{s[:-frac_digits]}.{s[-frac_digits:]}"
    return f"-{out}" if (neg and n != 0) else out


def verify_decimal_ledger(raw_lines: List[Any], expected_total: Any, fx_rate: Any = "1", quant: Any = "0.01") -> Dict[str, Any]:
    """Exact rational FX conversion + true tick-step ROUND_HALF_UP + conservation self-check."""
    if not isinstance(raw_lines, list) or not raw_lines:
        raise ValueError("INVALID_LINES: raw_lines must be a non-empty list")
    step_dec = _parse_bounded_decimal(quant, "quant")
    fx_dec = _parse_bounded_decimal(fx_rate, "fx_rate")
    if step_dec <= Decimal("0"):
        raise ValueError("INVALID_QUANT_STEP: quant must be > 0")
    if fx_dec <= Decimal("0"):
        raise ValueError("INVALID_FX_RATE: fx_rate must be > 0")
    exp_dec = _parse_bounded_decimal(expected_total, "expected_total")
    step_f, fx_f, exp_f = Fraction(step_dec), Fraction(fx_dec), Fraction(exp_dec)
    scale = min(0, int(step_dec.as_tuple().exponent))
    frac_digits = -scale
    converted_f = [
        _round_fraction_to_step(Fraction(_parse_bounded_decimal(v, f"line[{i}]")) * fx_f, step_f)
        for i, v in enumerate(raw_lines)
    ]
    computed_f = _round_fraction_to_step(sum(converted_f, Fraction(0)), step_f)
    diff_f = computed_f - exp_f
    exp_frac = max(0, -int(exp_dec.as_tuple().exponent))
    diff_digits = max(frac_digits, exp_frac)
    ok = diff_f == 0
    return {
        "ok": ok, "status": "MATCH_EXACT" if ok else "MISMATCH",
        "line_count": len(converted_f),
        "converted_lines": [_format_fraction_fixed(x, frac_digits) for x in converted_f],
        "computed_total": _format_fraction_fixed(computed_f, frac_digits),
        "expected_total": str(exp_dec),
        "delta": _format_fraction_fixed(diff_f, diff_digits),
    }


def _attribute_findings_to_tracked(findings: Sequence[Dict[str, Any]], tracked: Sequence[str]) -> List[str]:
    tmap = {t.upper(): t for t in tracked}
    matched: Set[str] = set()
    for f in findings:
        ru = str(f.get("rule", "")).upper()
        for up, orig in tmap.items():
            if ru == up or ru.startswith(f"{up}-"):
                matched.add(orig)
        for rule_key, scar_prefs in _SCAN_RULE_TO_SCAR_PREFIXES:
            hit = ru.startswith(rule_key) if rule_key.endswith("-") else (ru == rule_key or ru.startswith(f"{rule_key}-"))
            if not hit:
                continue
            for pref in scar_prefs:
                for up, orig in tmap.items():
                    if up == pref or up.startswith(f"{pref}-"):
                        matched.add(orig)
    return sorted(matched)


def verify_delivery(
    target_path: Path, *, envelope_id: str, telemetry_store: Path, client: str = DEFAULT_TELEMETRY_CLIENT,
    session_id: str = "", capsule_ids: Sequence[str] = (), pitfall_ids: Sequence[str] = (),
    relevant_ids: Sequence[str] = (), include_self: bool = False, confirm_included: bool = False,
) -> Dict[str, Any]:
    """Scan deliverable and bind `patch_bound` with content-byte digest, strict 8 MiB telemetry, and atomic lock."""
    scan_res = scan_target(target_path, include_self=include_self, include_build_dirs=True)
    scan_ok = bool(scan_res.get("ok"))
    patch_digest = str(scan_res.get("content_sha256") or "").strip().lower()
    if not _HEX64_RE.fullmatch(patch_digest):
        return {
            "ok": False, "status": "DELIVERY_FAILED_UNATTRIBUTED",
            "envelope_id": envelope_id, "session_id": session_id or f"sess-{secrets.token_hex(4)}",
            "patch_digest": "", "attributed_ids": [], "unattributed_failure": True,
            "telemetry_note": "MISSING_SCAN_CONTENT_SHA256_FAIL_CLOSED",
            "scan": scan_res, "telemetry": {"included": None, "patch_bound": None},
        }

    # Acquire distinct `<telemetry_store>.delivery.lock` (never `<telemetry_store>.lock`) to serialize
    # read-check-allocate-record across processes with zero nested self-deadlock against delivery_telemetry.
    delivery_lock_target = Path(f"{telemetry_store}.delivery")
    with security_io.file_lock(delivery_lock_target):
        envelopes_map: Dict[str, Any] = {}
        if telemetry_store.exists():
            raw_envs = _load_telemetry_store_strict(telemetry_store).get("envelopes")
            envelopes_map = raw_envs if isinstance(raw_envs, dict) else {}

        env_obj = envelopes_map.get(envelope_id)
        if isinstance(env_obj, dict):
            env_session = str(env_obj.get("session_id") or "") or session_id or f"sess-{secrets.token_hex(4)}"
            env_caps, env_pits = list(env_obj.get("capsule_ids") or []), list(env_obj.get("pitfall_ids") or [])
            already_included, already_patch_bound = bool(env_obj.get("included_in_input")), bool(env_obj.get("patch_bound"))
        else:
            env_session = session_id or f"sess-{secrets.token_hex(4)}"
            env_caps, env_pits, already_included, already_patch_bound = list(capsule_ids), list(pitfall_ids), False, False
            record_telemetry_event(telemetry_store, client=client, stage="issued", session_id=env_session, envelope_id=envelope_id, source_digest=patch_digest, capsule_ids=env_caps, pitfall_ids=env_pits)
        env_tracked = sorted(set(env_caps) | set(env_pits))

        inc_res: Optional[Dict[str, Any]] = None
        telemetry_note = ""
        if already_included:
            effective_included = True
        elif confirm_included:
            effective_included = True
            if not already_patch_bound:
                inc_res = record_telemetry_event(telemetry_store, client=client, stage="included_in_input", session_id=env_session, envelope_id=envelope_id)
        else:
            effective_included, telemetry_note = False, "NOT_MARKED_INCLUDED_EFFICACY_SKIPPED"

        def _next_retry_id() -> str:
            cand = f"{envelope_id}:retry-{secrets.token_hex(4)}"
            while cand in envelopes_map:
                cand = f"{envelope_id}:retry-{secrets.token_hex(4)}"
            return cand

        def _bind_followup(target_env: str, caps: Sequence[str], pits: Sequence[str], passed: bool) -> Dict[str, Any]:
            nonlocal inc_res
            record_telemetry_event(telemetry_store, client=client, stage="issued", session_id=env_session, envelope_id=target_env, source_digest=patch_digest, capsule_ids=list(caps), pitfall_ids=list(pits))
            if effective_included:
                inc_res = record_telemetry_event(telemetry_store, client=client, stage="included_in_input", session_id=env_session, envelope_id=target_env)
            return record_telemetry_event(telemetry_store, client=client, stage="patch_bound", session_id=env_session, envelope_id=target_env, patch_digest=patch_digest, passed=passed)

        def _ret(ok: bool, status: str, eid: str, attr_ids: List[str], unattr: bool, pb: Optional[Dict[str, Any]]) -> Dict[str, Any]:
            out: Dict[str, Any] = {
                "ok": ok, "status": status, "envelope_id": eid, "session_id": env_session, "patch_digest": patch_digest,
                "attributed_ids": attr_ids, "unattributed_failure": unattr, "scan": scan_res, "telemetry": {"included": inc_res, "patch_bound": pb},
            }
            if telemetry_note:
                out["telemetry_note"] = telemetry_note
            return out

        if scan_ok:
            if already_patch_bound:
                target_env = _next_retry_id()
                pb_res = _bind_followup(target_env, env_caps, env_pits, True)
            else:
                target_env = envelope_id
                pb_res = record_telemetry_event(telemetry_store, client=client, stage="patch_bound", session_id=env_session, envelope_id=target_env, patch_digest=patch_digest, passed=True)
            return _ret(True, "DELIVERY_VERIFIED_PASS", target_env, env_tracked, False, pb_res)

        rel = [r.strip().upper() for r in relevant_ids if r.strip()] or _attribute_findings_to_tracked(scan_res.get("findings", []), env_tracked)
        is_infra = scan_res.get("status") in {"PATH_NOT_FOUND", "EMPTY_OR_UNINSPECTED", "IO_ERROR", "INCOMPLETE_SCAN"} or (
            bool(scan_res.get("findings")) and all(f.get("rule") == "IO-READ-ERR" for f in scan_res["findings"])
        )
        tmap = {t.upper(): t for t in env_tracked}
        scoped = [tmap.get(r.upper(), r) for r in rel if (not tmap) or (r.upper() in tmap)]
        if is_infra or not scoped:
            return _ret(False, "DELIVERY_FAILED_UNATTRIBUTED", envelope_id, [], True, None)

        if (not already_patch_bound) and tmap and {r.upper() for r in scoped} == set(tmap.keys()):
            target_env = envelope_id
            pb_res = record_telemetry_event(telemetry_store, client=client, stage="patch_bound", session_id=env_session, envelope_id=target_env, patch_digest=patch_digest, passed=False)
        else:
            target_env = _next_retry_id() if already_patch_bound else f"{envelope_id}:attr-{secrets.token_hex(4)}"
            pb_res = _bind_followup(target_env, [x for x in scoped if x.upper().startswith("CAP-")], [x for x in scoped if not x.upper().startswith("CAP-")], False)
        return _ret(False, "DELIVERY_FAILED_ATTRIBUTED", target_env, scoped, False, pb_res)


# ---------------------------------------------------------------------------
# End-to-End Self-Test Suite (v3.1.1)
# ---------------------------------------------------------------------------


def run_self_test() -> Dict[str, Any]:
    checks: List[Dict[str, Any]] = []

    def _rec(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    caps, lex = _load_json(CAPSULES_PATH)["capsules"], _load_json(LEXICON_PATH)["entries"]
    _rec("data_9_capsules_80_pitfalls", len(caps) == 9 and len(lex) == 80 and all(e.get("trigger_groups") for e in lex), f"caps={len(caps)}, pitfalls={len(lex)}")

    b0 = build_brief(code_override="from dataclasses import dataclass\n@dataclass\nclass Point:\n    x: int\n    y: int\n", lang_hint="python")
    _rec("brief_zero_bloat_benign", b0["matched_capsules_count"] == 0 and b0["matched_pitfalls_count"] == 0 and b0["estimated_tokens"] == 0, f"tokens={b0['estimated_tokens']}")

    b_iso = build_brief(code_override="import hashlib\ndef fn_a(items):\n    while items:\n        items.pop()\ndef fn_b(n):\n    return n % 2\ndef fn_c(data):\n    # open(p, 'w')\n    with open('r.txt', 'r') as fh:\n        return hashlib.sha256(fh.read().encode()).hexdigest()\n", lang_hint="python")
    _rec("brief_symbol_scope_no_bleed", "@struct_halving_hash_tree" not in b_iso["structural_tags"] and "@struct_fs_persistence" not in b_iso["structural_tags"], f"tags={b_iso['structural_tags']}")
    b_v = build_brief(code_override="def preview_deposit(assets: int, total_shares: int, total_assets: int) -> int:\n    return (assets * (total_shares + 10**6)) // (total_assets + 1)\n", lang_hint="python")
    _rec("brief_python_floor_div_preserved", "@struct_share_vault_ratio" in b_v["structural_tags"] and any(c["id"] == "CAP-FIN-ERC4626" for c in b_v["capsules"]), f"tags={b_v['structural_tags']}")
    b_m = build_brief(code_override="import hashlib\ndef build_tree(arr):\n    while len(arr) > 1:\n        if len(arr) % 2 == 1: arr.append(arr[-1])\n        arr = [hashlib.sha256(arr[i] + arr[i+1]).digest() for i in range(0, len(arr), 2)]\n    return arr[0]\n", lang_hint="python")
    _rec("brief_merkle_ast_match", any(c["id"] == "CAP-CRYPTO-RFC6962-MERKLE" for c in b_m["capsules"]), f"caps={[c['id'] for c in b_m['capsules']]}")
    b_en = build_brief(task_text="Audit ERC-4626 vault share math and multi-currency FX tax ledger", lang_hint="python")
    _rec("brief_en_task_under_500_tokens", b_en["matched_capsules_count"] >= 1 and b_en["matched_pitfalls_count"] >= 1 and b_en["estimated_tokens"] < 500, f"tokens={b_en['estimated_tokens']}")
    typo_ok = False
    try:
        build_brief(target_path=BUNDLE_ROOT / "nonexistent_typo_path_xyz.py")
    except FileNotFoundError:
        typo_ok = True
    _rec("brief_typo_path_fail_closed", typo_ok, f"raised={typo_ok}")

    with tempfile.TemporaryDirectory() as tmp:
        tp = Path(tmp)
        secret_tok = "sk-" + "A" * 24
        bad_py = tp / "bad.py"
        bad_py.write_text("\n".join([
            "import os, subprocess as sp", "from os import " + "sys" + "tem as x", "from yaml import " + "lo" + "ad as yl",
            f"SECRET = '{secret_tok}'", f"BIDI = 'ok{chr(0x202E)}evil'", "def f(c, u, dyn_flag):", "    x('hi')",
            "    getattr(os, '" + "sys" + "tem')('id')", "    yl(u)", "    sp.run(u, sh" + "ell=True)",
            "    sp.run(u, sh" + "ell=dyn_flag)",
            "    c." + "execute(" + "f'SEL" + "ECT * FROM t WHERE id={u}')", "    try:\n        return 1\n    except Exception:\n        pass",
        ]) + "\n", encoding="utf-8")
        s_bad = scan_target(bad_py)
        rules_hit = {x["rule"] for x in s_bad["findings"]}
        empty_d, bin_d, mixed_d, dist_d, good_py = tp / "empty", tp / "bin_only", tp / "mixed_bin", tp / "dist", tp / "good.py"
        for d in (empty_d, bin_d, mixed_d, dist_d):
            d.mkdir()
        (bin_d / "a.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
        (mixed_d / "README.md").write_text("# Clean readme\n", encoding="utf-8")
        (mixed_d / "archive.zip").write_bytes(b"PK\x03\x04\x00\x00")
        (dist_d / "out.py").write_text("x = 1\n", encoding="utf-8")
        good_py.write_text("from decimal import Decimal\nimport subprocess\ndef add(a: Decimal, b: Decimal) -> Decimal:\n    safe = False\n    _ = subprocess.run(['true'], sh" + "ell=safe)\n    return a + b\n", encoding="utf-8")
        sym_p = tp / "link.py"
        sym_p.symlink_to(good_py)
        s_empty, s_bin, s_mix_fail, s_mix_ok = scan_target(empty_d), scan_target(bin_d), scan_target(mixed_d), scan_target(mixed_d, allow_binary=True)
        s_good, s_sym, s_dist = scan_target(good_py), scan_target(sym_p), scan_target(tp / "dist")
        _rec(
            "scan_alias_ast_dlp_symlink_coverage",
            (not s_bad["ok"]) and (secret_tok not in json.dumps(s_bad))
            and {"DLP-API-TOKEN", "SEC-BIDI-TROJAN", "SEC-FORBIDDEN-CALL", "SEC-YAML-UNSAFE", "SEC-SHELL-TRUE", "SEC-SHELL-DYNAMIC", "SEC-SQL-CONCAT", "LT-007-SILENT-EXCEPT"}.issubset(rules_hit)
            and (s_empty["status"] == "EMPTY_OR_UNINSPECTED") and (s_bin["status"] == "INCOMPLETE_SCAN")
            and (s_mix_fail["status"] == "INCOMPLETE_SCAN") and (not s_mix_fail["ok"]) and s_mix_ok["ok"] and bool(_HEX64_RE.fullmatch(s_mix_ok.get("content_sha256", "")))
            and (len(s_bin["unsupported_binary_files"]) == 1) and any(f["rule"] == "SYMLINK-REJECTED" for f in s_sym["findings"])
            and s_good["ok"] and (s_good.get("content_sha256") == security_io.sha256_file_secure(good_py)) and s_dist["inspected_files"] == 1,
            f"rules={sorted(rules_hit)}",
        )
        bom_json = tp / "out.json"
        bom_json.write_bytes(b'\xef\xbb\xbf{"note": "require' + b'ments met; TO' + b'DO: finish"}\n')
        aud_bad, aud_good = audit_deliverable(bom_json), audit_deliverable(good_py)
        aud_rules = {f["rule"] for f in aud_bad["deliverable_findings"]}
        _rec("deliverable_audit_controls", (not aud_bad["ok"]) and {"LT-053", "LT-054", "LT-055"}.issubset(aud_rules) and aud_good["ok"], f"rules={sorted(aud_rules)}")

    base_ok = {"status": "open", "deposit_required": False, "entry_fee": 0, "transfers_funds": False, "signing": {"action": "personal_sign", "value": 0}}
    safe_auths = [
        {"action": "personal_sign", "transaction": {"value": 0}},
        {"action": "eip191", "transaction": {"value": "0x0"}},
        {"action": "ed25519_auth", "transfers_funds": False},
        {"action": "siwe", "send_value": 0},
        {"action": "read_only"},
        {"action": "none"},
    ]
    neg = [
        {}, [], {"description": "missing action"},
        {**base_ok, "deposit_required": True},
        {**base_ok, "entry_fee": 5},
        {**base_ok, "entry_fee": "9" * 90},
        {**base_ok, "meta": {"deposit_required": True}},
        {**base_ok, "verified_by": "\uff50\uff41\uff59\uff4d\uff45\uff4e\uff54\uff3f\uff43\uff41\uff52\uff44"},
        {**base_ok, "status": "closed"},
        {**base_ok, "transaction": {"value": 1}},
        {**base_ok, "transaction": {"value": "0x1"}},
        {**base_ok, "transfers_funds": True},
        {**base_ok, "send_value": 1},
        {**base_ok, "outbound_transfer": True},
        {**base_ok, "signing": {"action": "eth_sendTransaction"}},
        {**base_ok, "signing": {"action": "erc20_transfer"}},
        {**base_ok, "signing": {"action": "swap"}},
    ]
    j_kyc = evaluate_tx_guard({**base_ok, "kyc_required": True})
    j_unk_act = evaluate_tx_guard({**base_ok, "signing": {"action": "custom_unknown_op"}})
    j_dup = evaluate_tx_guard_json('{"action": "personal_sign", "deposit_required": true, "deposit_required": false}')
    _rec(
        "tx_guard_nfkc_nested_and_outbound_controls",
        all(evaluate_tx_guard(c)["verdict"] == "BLOCKED" for c in neg)
        and j_dup["verdict"] == "BLOCKED" and j_kyc["verdict"] == "NEEDS_OWNER_DECISION"
        and j_unk_act["verdict"] == "NEEDS_OWNER_DECISION"
        and evaluate_tx_guard_json(json.dumps(base_ok))["verdict"] == "PASS_READONLY_0_OUTBOUND"
        and all(evaluate_tx_guard(c)["verdict"] == "PASS_READONLY_0_OUTBOUND" for c in safe_auths),
        f"kyc={j_kyc['verdict']}, unk_act={j_unk_act['verdict']}",
    )

    tg = run_builtin_truth_gate("all")
    _rec("truth_gate_4_contracts", bool(tg.get("ok")), f"contracts={len(tg.get('contracts', []))}")

    prov = validate_teacher_provenance("claude-opus-4-6-thinking", "third_party_relay", "https://example.invalid/v1", thinking_signature_verified=False)
    _rec("teacher_provenance_fail_closed", prov["tier"] == "REQUIRES_RUNTIME_PROOF", f"tier={prov['tier']}")

    lc_ok = verify_decimal_ledger(["0.10", "0.20", "19.99", "33.33"], "1364646.97", fx_rate="25450.335")
    lc_tick = verify_decimal_ledger(["1.03", "2.02"], "3.05", quant="0.05")
    lc_bad = verify_decimal_ledger(["0.10", "0.20"], "0.31")
    lc_28 = verify_decimal_ledger(["1000000000000000000000000000.00", "0.50"], "1000000000000000000000000000.50", quant="0.01")
    lc_sci = verify_decimal_ledger(["151"], "200", quant="1E+2")
    lc_exact_ok = verify_decimal_ledger(["0." + "9" * 50], "0", fx_rate="1." + "0" * 49 + "1", quant="2")
    lc_exact_bad = verify_decimal_ledger(["0." + "9" * 50], "2", fx_rate="1." + "0" * 49 + "1", quant="2")
    fx0_rej = False
    try:
        verify_decimal_ledger(["1.00"], "0.00", fx_rate="0")
    except ValueError:
        fx0_rej = True
    _rec(
        "decimal_ledger_tick_and_fx_guard",
        lc_ok["ok"] and lc_tick["ok"] and (not lc_bad["ok"]) and lc_28["ok"] and lc_sci["ok"] and lc_sci["computed_total"] == "200"
        and lc_exact_ok["ok"] and lc_exact_ok["computed_total"] == "0" and (not lc_exact_bad["ok"]) and lc_exact_bad["status"] == "MISMATCH" and fx0_rej,
        f"tick={lc_tick['converted_lines']}, sci={lc_sci['computed_total']}, exact={lc_exact_ok['computed_total']}",
    )

    with tempfile.TemporaryDirectory() as tel_tmp:
        tstore = Path(tel_tmp) / "tel.json"
        record_telemetry_event(tstore, client=DEFAULT_TELEMETRY_CLIENT, stage="issued", session_id="s-u", envelope_id="e-u", source_digest="d0", capsule_ids=["CAP-SAFE"])
        r_un = record_telemetry_event(tstore, client=DEFAULT_TELEMETRY_CLIENT, stage="patch_bound", session_id="s-u", envelope_id="e-u", patch_digest="p0", passed=False)
        for i in (1, 2):
            record_telemetry_event(tstore, client=DEFAULT_TELEMETRY_CLIENT, stage="issued", session_id=f"s-{i}", envelope_id=f"e-{i}", source_digest=f"d{i}", capsule_ids=["CAP-FLAKY"])
            record_telemetry_event(tstore, client=DEFAULT_TELEMETRY_CLIENT, stage="included_in_input", session_id=f"s-{i}", envelope_id=f"e-{i}")
            record_telemetry_event(tstore, client=DEFAULT_TELEMETRY_CLIENT, stage="patch_bound", session_id=f"s-{i}", envelope_id=f"e-{i}", patch_digest=f"p{i}", passed=False)
        trep = build_telemetry_report(tstore)
        _rec("delivery_telemetry_2strike_and_unshown_guard", (r_un.get("efficacy_updated") is False) and ("CAP-SAFE" not in trep["frozen_ids"]) and ("CAP-FLAKY" in trep["frozen_ids"]), f"frozen={trep['frozen_ids']}")

    s_bundle = scan_target(BUNDLE_ROOT, include_self=True)
    _rec("bundle_zero_dlp_and_clean", s_bundle["ok"], f"inspected={s_bundle['inspected_files']}, blocking={s_bundle['blocking_count']}")

    try:
        m_res = _verify_manifest_strict(BUNDLE_ROOT, src_root=SRC_ROOT_DIR, reject_extra_files=(LAYOUT_MODE == "standalone_bundle"), allow_pycache=False)
        _rec("manifest_integrity_verified", bool(m_res.get("ok")), f"files={m_res.get('files_verified')}")
    except Exception as exc:
        _rec("manifest_integrity_verified", False, f"error={exc}")

    with tempfile.TemporaryDirectory() as evo_tmp:
        et = Path(evo_tmp)
        evo_store, tel_store, imp_store = et / "learned.json", et / "telemetry.json", et / "imported.json"
        b_py, f_py, t_py, patch_p = et / "broken.py", et / "fixed.py", et / "test_oracle.py", et / "patch.json"
        b_py.write_text("def parse_tag(s: str) -> str:\n    return s.lstrip()\n", encoding="utf-8")
        f_py.write_text("def parse_tag(s: str) -> str:\n    return s.strip().lower()\n", encoding="utf-8")
        t_py.write_text("import candidate\nassert candidate.parse_tag('  AbC ') == 'abc'\n", encoding="utf-8")
        lr = evolve_learn(
            store_path=evo_store, scar_id="CSB-SELF-001", slug="tag_casefold_norm", category="logic",
            languages=["python"], trigger_groups=[["parse_tag", "normalize_tag"], ["lstrip", "swapcase"]],
            bad_pattern="Returning mixed-case tag via lstrip without full strip/lower", good_pattern="Normalize tags with .strip().lower() before lookup",
            precondition="Normalizing case-insensitive lookup tags", broken_path=b_py, fixed_path=f_py, test_path=t_py,
            role="detect_bug", runner="python", kintsugi_version=KINTSUGI_VERSION, telemetry_store=tel_store,
        )
        br_on = build_brief(code_override="def parse_tag(v):\n    return v.lstrip()\n", lang_hint="python", evolution_store=evo_store, telemetry_store=tel_store)
        exp_on = evolve_export_patch(store_path=evo_store, telemetry_store=tel_store, out_path=patch_p)
        imp_kwargs: Dict[str, Any] = {
            "store_path": imp_store,
            "telemetry_store": tel_store,
            "expected_patch_sha256": str(exp_on.get("patch_sha256", "")),
            "quarantine": False,
        }
        if "trust_unverified_proof" in inspect.signature(evolve_import_patch).parameters:
            imp_kwargs["trust_unverified_proof"] = True
        imp_res = evolve_import_patch(patch_p, **imp_kwargs)
        for i in (1, 2):
            record_telemetry_event(tel_store, client=DEFAULT_TELEMETRY_CLIENT, stage="issued", session_id=f"es-{i}", envelope_id=f"ee-{i}", source_digest="d", pitfall_ids=["CSB-SELF-001"])
            record_telemetry_event(tel_store, client=DEFAULT_TELEMETRY_CLIENT, stage="included_in_input", session_id=f"es-{i}", envelope_id=f"ee-{i}")
            record_telemetry_event(tel_store, client=DEFAULT_TELEMETRY_CLIENT, stage="patch_bound", session_id=f"es-{i}", envelope_id=f"ee-{i}", patch_digest=f"ep-{i}", passed=False)
        br_fr = build_brief(code_override="def parse_tag(v):\n    return v.lstrip()\n", lang_hint="python", evolution_store=evo_store, telemetry_store=tel_store)
        exp_fr = evolve_export_patch(store_path=evo_store, telemetry_store=tel_store, out_path=None)
        _rec(
            "self_evolution_loop_export_freeze_import",
            bool(lr.get("ok")) and ("CSB-SELF-001" in [p["id"] for p in br_on["pitfalls"]]) and ("CSB-SELF-001" not in [p["id"] for p in br_fr["pitfalls"]])
            and bool(exp_on.get("ok")) and (exp_on.get("scars_count") == 1) and bool(imp_res.get("ok")) and (imp_res.get("imported") == 1) and (exp_fr.get("scars_count") == 0),
            f"learn={lr.get('ok')}, imp={imp_res.get('ok')}, exp_on={exp_on.get('scars_count')}, exp_fr={exp_fr.get('scars_count')}",
        )

    all_ok = all(c["passed"] for c in checks)
    return {"ok": all_ok, "status": "PASS_100" if all_ok else "SELF_TEST_FAILED", "edition": EDITION_NAME, "kintsugi_version": KINTSUGI_VERSION, "layout": LAYOUT_MODE, "passed": sum(1 for c in checks if c["passed"]), "total": len(checks), "checks": checks}


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------


def _out(obj: Dict[str, Any]) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def _stores(args: argparse.Namespace) -> Tuple[Path, Path]:
    st_dir = Path(args.state_dir) if getattr(args, "state_dir", "") else None
    ev = getattr(args, "store", "") or getattr(args, "evolution_store", "")
    tel = getattr(args, "telemetry_store", "")
    return resolve_state_paths(state_dir=st_dir, store_path=Path(ev) if ev else None, telemetry_store=Path(tel) if tel else None)


def _evolve_learn_cli(args: argparse.Namespace, evo_p: Path, tel_p: Path) -> Dict[str, Any]:
    spec: Dict[str, Any] = {}
    if args.spec:
        parsed = security_io.strict_json_loads(security_io.read_regular_bytes_secure(Path(args.spec), max_bytes=security_io.MAX_DEFAULT_FILE_BYTES).decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("EVOLVE_SPEC_MUST_BE_JSON_OBJECT")
        spec = parsed
    trigs = security_io.strict_json_loads(args.triggers) if args.triggers else spec.get("trigger_groups", [])
    raw_langs = args.languages if args.languages else spec.get("languages", ["python"])
    langs = [x.strip() for x in raw_langs.split(",") if x.strip()] if isinstance(raw_langs, str) else list(raw_langs)
    return evolve_learn(
        store_path=evo_p, scar_id=args.id or str(spec.get("id") or spec.get("scar_id") or ""),
        slug=args.slug or str(spec.get("slug") or ""), category=args.category or str(spec.get("category") or "logic"),
        languages=langs, trigger_groups=trigs, bad_pattern=args.bad or str(spec.get("bad_pattern") or ""),
        good_pattern=args.good or str(spec.get("good_pattern") or ""), precondition=args.when or str(spec.get("precondition") or ""),
        broken_path=Path(args.broken or str(spec.get("broken_path") or spec.get("broken") or "")),
        fixed_path=Path(args.fixed or str(spec.get("fixed_path") or spec.get("fixed") or "")),
        test_path=Path(args.test or str(spec.get("test_path") or spec.get("test") or "")),
        role=args.role or str(spec.get("role") or "detect_bug"), runner=args.runner or str(spec.get("runner") or "auto"),
        kintsugi_version=KINTSUGI_VERSION, telemetry_store=tel_p,
    )


def _add_str_flags(parser: argparse.ArgumentParser, *flags: str) -> None:
    for fl in flags:
        parser.add_argument(fl, default="")


def _add_bool_flags(parser: argparse.ArgumentParser, *flags: str) -> None:
    for fl in flags:
        parser.add_argument(fl, action="store_true")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kintsugi_sandbox.py", description=EDITION_NAME)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("boot", help="Quick readiness & self-check")
    sub.add_parser("self-test", help="Run full v3.1.1 test suite")
    sub.add_parser("verify-manifest", help="Fail-closed SHA-256 manifest check").add_argument("--expected-sha256", default="")

    p_u = sub.add_parser("update", help="Self-update with SHA-256 verification")
    p_u.add_argument("--ref", default="main")
    p_u.add_argument("--dest", default="/tmp/kintsugi_sandbox" if LAYOUT_MODE == "github_repo" else str(BUNDLE_ROOT))
    p_u.add_argument("--timeout", type=int, default=30)
    _add_str_flags(p_u, "--source-archive", "--expected-manifest-sha256", "--expected-bootstrap-sha256")
    _add_bool_flags(p_u, "--require-pin", "--require-full-sha", "--allow-unpinned-downgrade")

    p_b = sub.add_parser("brief", help="JIT Pre-Read Brief (<500 tokens)")
    p_b.add_argument("path", nargs="?", default="")
    _add_str_flags(p_b, "--task", "--category", "--state-dir", "--evolution-store", "--telemetry-store", "--session-id")
    p_b.add_argument("--client", default=DEFAULT_TELEMETRY_CLIENT)
    p_b.add_argument("--lang", default="auto")
    p_b.add_argument("--top-k", type=int, default=6)
    p_b.add_argument("--max-tokens", type=int, default=480)
    _add_bool_flags(p_b, "--no-telemetry", "--mark-included", "--compact-only")

    p_e = sub.add_parser("evolve", help="Self-learning (learn|status|export-patch|import-patch)")
    p_e.add_argument("action", choices=["learn", "status", "export-patch", "import-patch"])
    _add_str_flags(p_e, "--state-dir", "--store", "--telemetry-store", "--spec", "--id", "--slug", "--category", "--languages", "--triggers", "--bad", "--good", "--when", "--broken", "--fixed", "--test", "--out", "--file", "--expected-sha256")
    p_e.add_argument("--role", default="", choices=["", "detect_bug", "context_reminder"])
    p_e.add_argument("--runner", default="", choices=["", "auto", "python", "node", "sqlite"])
    _add_bool_flags(p_e, "--quarantine", "--apply", "--trust-unverified-proof")

    p_scan = sub.add_parser("scan", help="Security + DLP + Alias AST Scan")
    p_scan.add_argument("path", nargs="?", default=".")
    _add_bool_flags(p_scan, "--include-self", "--exclude-build-dirs", "--allow-binary")
    p_aud = sub.add_parser("audit-deliverable", help="Security scan + LT-053/054/055/062 audit")
    p_aud.add_argument("path", nargs="?", default=".")
    _add_bool_flags(p_aud, "--include-self")

    p_vd = sub.add_parser("verify-delivery", help="Scan deliverable + bind DeliveryTelemetry/1")
    p_vd.add_argument("path")
    p_vd.add_argument("--envelope-id", required=True)
    _add_str_flags(p_vd, "--state-dir", "--telemetry-store", "--session-id", "--capsule-ids", "--pitfall-ids", "--relevant-ids")
    p_vd.add_argument("--client", default=DEFAULT_TELEMETRY_CLIENT)
    _add_bool_flags(p_vd, "--include-self", "--confirm-included")

    p_tx = sub.add_parser("tx-guard", help="Zero-Outbound Agent Transaction & Policy Guard")
    p_tx.add_argument("--meta", "--payload", dest="meta", default="")
    p_tx.add_argument("--file", default="")
    p_tg = sub.add_parser("truth-gate", help="Universal Truth Gate runtime verifier")
    p_tg.add_argument("--contract", default="all", choices=["all", "idempotency", "decimal_fx", "erc4626", "ledger"])
    _add_str_flags(p_tg, "--broken", "--fixed", "--test")
    p_tg.add_argument("--runner", default="auto", choices=["auto", "python", "node", "sqlite"])
    p_lc = sub.add_parser("ledger-check", help="Exact Decimal sum/FX/tick conservation check")
    for fl, kw in (("--lines", {"required": True}), ("--total", {"required": True}), ("--fx", {"default": "1"}), ("--quant", {"default": "0.01"})):
        p_lc.add_argument(fl, **kw)
    p_sc = sub.add_parser("scout", help="Pure-Python RepoScout symbol/file index")
    p_sc.add_argument("dir", default=".", nargs="?")
    p_sc.add_argument("--symbol", default="")
    p_c = sub.add_parser("compact", help="Compact long file with DLP redaction")
    p_c.add_argument("file")
    p_c.add_argument("--max-lines", type=int, default=120)
    p_t = sub.add_parser("telemetry", help="Delivery Gate Telemetry (DeliveryTelemetry/1)")
    p_t.add_argument("action", nargs="?", default="report", choices=["record", "report"])
    _add_str_flags(p_t, "--state-dir", "--store", "--session-id", "--envelope-id", "--source-digest", "--patch-digest", "--capsule-ids", "--pitfall-ids")
    p_t.add_argument("--client", default=DEFAULT_TELEMETRY_CLIENT)
    p_t.add_argument("--stage", default="issued", choices=["issued", "included_in_input", "patch_bound"])
    p_t.add_argument("--tokens", type=int, default=0)
    p_t.add_argument("--passed", default="", choices=["", "true", "false"])
    return p


def _split_csv(val: str) -> List[str]:
    return [x.strip() for x in val.split(",") if x.strip()]


def _emit_rc(res: Dict[str, Any], fail_rc: int = 1) -> int:
    _out(res)
    return 0 if res.get("ok") else fail_rc


def main(argv: List[str]) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.cmd == "boot":
            caps, lex = _load_json(CAPSULES_PATH)["capsules"], _load_json(LEXICON_PATH)["entries"]
            return _emit_rc({
                "ok": True, "status": "READY", "edition": EDITION_NAME, "kintsugi_version": KINTSUGI_VERSION,
                "layout": LAYOUT_MODE, "github_repo": GITHUB_REPO_URL, "state_dir": str(DEFAULT_STATE_DIR),
                "python": sys.version.split()[0], "native_rust_required": False,
                "capsules_loaded": len(caps), "pitfalls_loaded": len(lex), "crs_scars_loaded": len(get_full_crs_scars()),
            })
        if args.cmd == "verify-manifest":
            _out(_verify_manifest_strict(BUNDLE_ROOT, src_root=SRC_ROOT_DIR, expected_manifest_sha256=args.expected_sha256, reject_extra_files=(LAYOUT_MODE == "standalone_bundle"), allow_pycache=False))
            return 0
        if args.cmd == "update":
            return _emit_rc(bootstrap_install_or_update(
                ref=args.ref, dest=Path(args.dest), source_archive=Path(args.source_archive) if args.source_archive else None,
                expected_manifest_sha256=args.expected_manifest_sha256,
                expected_bootstrap_sha256=args.expected_bootstrap_sha256,
                require_pin=args.require_pin,
                require_full_sha=args.require_full_sha,
                allow_downgrade_to_tofu=args.allow_unpinned_downgrade,
                timeout=args.timeout,
            ), fail_rc=2)
        if args.cmd == "self-test":
            return _emit_rc(run_self_test())
        if args.cmd == "brief":
            evo_p, tel_p = _stores(args)
            res = build_brief(
                target_path=Path(args.path) if args.path else None, task_text=args.task, lang_hint=args.lang,
                category_filter=args.category, max_pitfalls=args.top_k, max_tokens=args.max_tokens,
                evolution_store=evo_p, telemetry_store=tel_p, auto_record_telemetry=(not args.no_telemetry),
                mark_included=args.mark_included, session_id=args.session_id, client=args.client,
            )
            print(res["compact"]) if args.compact_only else _out(res)
            return 0
        if args.cmd == "evolve":
            evo_p, tel_p = _stores(args)
            if args.action == "status":
                out = evolve_status(evo_p, tel_p)
            elif args.action == "export-patch":
                out = evolve_export_patch(store_path=evo_p, telemetry_store=tel_p, out_path=Path(args.out) if args.out else None)
            elif args.action == "import-patch":
                if not args.file:
                    raise ValueError("MISSING_PATCH_FILE: provide --file <patch.json>")
                use_quarantine = True if args.quarantine else (not args.apply)
                imp_kwargs: Dict[str, Any] = {
                    "store_path": evo_p, "telemetry_store": tel_p,
                    "expected_patch_sha256": args.expected_sha256, "quarantine": use_quarantine,
                }
                if "trust_unverified_proof" in inspect.signature(evolve_import_patch).parameters:
                    imp_kwargs["trust_unverified_proof"] = bool(args.trust_unverified_proof)
                out = evolve_import_patch(Path(args.file), **imp_kwargs)
            else:
                out = _evolve_learn_cli(args, evo_p, tel_p)
            return _emit_rc(out)
        if args.cmd == "scan":
            return _emit_rc(scan_target(Path(args.path), include_self=args.include_self, include_build_dirs=(not args.exclude_build_dirs), allow_binary=args.allow_binary))
        if args.cmd == "audit-deliverable":
            return _emit_rc(audit_deliverable(Path(args.path), include_self=args.include_self))
        if args.cmd == "verify-delivery":
            _, tel_p = _stores(args)
            return _emit_rc(verify_delivery(
                Path(args.path), envelope_id=args.envelope_id, telemetry_store=tel_p, client=args.client,
                session_id=args.session_id, capsule_ids=_split_csv(args.capsule_ids), pitfall_ids=_split_csv(args.pitfall_ids),
                relevant_ids=_split_csv(args.relevant_ids), include_self=args.include_self, confirm_included=args.confirm_included,
            ))
        if args.cmd == "tx-guard":
            if args.file:
                raw_meta = security_io.read_regular_bytes_secure(Path(args.file), max_bytes=security_io.MAX_DEFAULT_FILE_BYTES).decode("utf-8")
            elif args.meta:
                raw_meta = args.meta
            else:
                return _emit_rc({"ok": False, "verdict": "BLOCKED", "blocks": ["BLOCK_INVALID_METADATA: Provide --meta/--payload or --file"], "owner_decisions": []}, fail_rc=2)
            return _emit_rc(evaluate_tx_guard_json(raw_meta))
        if args.cmd == "truth-gate":
            custom = [bool(args.broken), bool(args.fixed), bool(args.test)]
            if any(custom) and not all(custom):
                return _emit_rc({"ok": False, "status": "MISSING_CUSTOM_TRUTH_GATE_FLAGS", "error": "Provide all three flags: --broken, --fixed, and --test"}, fail_rc=2)
            return _emit_rc(run_custom_truth_gate(Path(args.broken), Path(args.fixed), Path(args.test), runner=args.runner) if all(custom) else run_builtin_truth_gate(args.contract))
        if args.cmd == "ledger-check":
            parsed = security_io.strict_json_loads(args.lines, parse_float=Decimal)
            if not isinstance(parsed, list) or not parsed:
                raise ValueError("--lines must be a non-empty JSON array")
            return _emit_rc(verify_decimal_ledger(parsed, args.total, fx_rate=args.fx, quant=args.quant))
        if args.cmd == "scout":
            target_d = Path(args.dir)
            security_io.reject_symlink(target_d)
            scout = RepoScout(target_d.resolve())
            scout.build()
            return _emit_rc({"ok": True, "symbol": args.symbol, "matches": scout.find_symbol(args.symbol)[:25]} if args.symbol else {"ok": True, "summary": scout.to_grounding_summary()})
        if args.cmd == "compact":
            if isinstance(args.max_lines, bool) or not isinstance(args.max_lines, int) or not (1 <= args.max_lines <= 2000):
                raise ValueError("INVALID_MAX_LINES: --max-lines must be an integer in 1..2000")
            fp = Path(args.file)
            raw = security_io.read_regular_bytes_secure(fp, max_bytes=security_io.MAX_DEFAULT_FILE_BYTES).decode("utf-8", errors="replace")
            raw_toks = estimate_tokens(raw)
            redacted_raw = security_io.dlp_redact_output(_redact_multiline_pem_blocks(raw))
            lines = [ln.rstrip() for ln in redacted_raw.splitlines() if ln.strip() and not ln.strip().startswith(("---", "==="))]
            trimmed = security_io.dlp_redact_output("\n".join(lines[: args.max_lines]))
            new_toks = estimate_tokens(trimmed)
            return _emit_rc({"ok": True, "file": security_io.dlp_redact_output(str(fp)), "raw_tokens": raw_toks, "compact_tokens": new_toks, "savings_pct": round((1.0 - (new_toks / max(raw_toks, 1))) * 100.0, 1), "content": trimmed})
        if args.cmd == "telemetry":
            _, store_p = resolve_state_paths(state_dir=Path(args.state_dir) if args.state_dir else None, telemetry_store=Path(args.store) if args.store else None)
            out = record_telemetry_event(
                store_path=store_p, client=args.client, stage=args.stage, session_id=args.session_id,
                envelope_id=args.envelope_id, source_digest=args.source_digest, patch_digest=args.patch_digest,
                capsule_ids=_split_csv(args.capsule_ids), pitfall_ids=_split_csv(args.pitfall_ids),
                estimated_tokens=args.tokens, passed=(None if args.passed == "" else (args.passed == "true")),
            ) if args.action == "record" else build_telemetry_report(store_p)
            _out(out)
            return 0
    except (OSError, PermissionError, ValueError, InvalidOperation) as exc:
        return _emit_rc({"ok": False, "status": f"{args.cmd.upper().replace('-', '_')}_FAILED_CLOSED", "error": security_io.dlp_redact_output(str(exc))})
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
