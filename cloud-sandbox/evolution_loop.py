#!/usr/bin/env python3
"""Closed-Loop Self-Learning & Evolution Engine for Kintsugi Harness — Cloud Sandbox Edition (v3.1.1).

Enables cloud-sandbox coding agents to learn, verify, persist, export, and import scars fail-closed:
  1. `evolve_learn(...)` — Forges a new pitfall/scar ONLY after passing ALL 5 gates:
       - Gate 1 (Schema, Language Allowlist & DLP): Valid non-reserved ID/slug/category/role/languages
         + recursive fail-closed DLP check (`security_io.dlp_scan_object`).
       - Gate 2 (Zero-Bloat Disjoint Triggers + 16-Sample Multi-Canary Gate): 2..6 disjoint
         non-stopword trigger groups verified against `data/canary_corpus_v3.json` (0% FP).
       - Gate 3 (Trusted Internal Universal Truth Gate): ALWAYS invokes `truth_gate.run_custom_truth_gate`
         directly (never accepts caller-injected fake proof callbacks) and verifies language-proof parity.
       - Gate 4 (Matcher-on-Broken Verification): Delegates to `scanner_sandbox.extract_code_capsule_signals`
         (100% parity with live `brief`, including symbol-block scoping and `@struct_*` tags) to confirm
         `trigger_groups` fires on `broken_code` (and does NOT match `fixed_code` for `role == "detect_bug"`).
       - Gate 5 (Immutable Revision Digest & Locked Atomic Persistence): Computes canonical
         `revision_sha256`, rebuilds `compact` from validated fields, tracks revision history
         (`revision`, `revision_id`, `previous_revisions`), and writes via `security_io.file_lock` +
         `security_io.atomic_write_json_secure`.
  2. `load_active_learned_scars(...)` — Fail-closed verifies `revision_sha256`, rebuilds `compact`,
     deduplicates IDs, enforces 64-scar cap, checks 16-sample canary + DLP, and excludes frozen IDs.
  3. `evolve_status(...)` — Summarizes active, frozen, duplicate, and rejected-invalid learned scars.
  4. `evolve_export_patch(...)` — Refuses output aliasing with state/lock files; exports SHA-256
     integrity-hashed, DLP-clean `KintsugiCloudSandboxEvolutionPatch/1` including `frozen_ids` snapshot.
  5. `evolve_import_patch(...)` — Verifies canonical `patch_sha256` (+ optional expected hash),
     DLP, per-scar `revision_sha256` & canary corpus, honors local+patch `frozen_ids`, blocks
     revision downgrades, and stages into `quarantine_scars.json` by default (`quarantine=True`;
     pass `quarantine=False` with `expected_patch_sha256` or `trust_unverified_proof=True` to merge live).
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

BUNDLE_ROOT = Path(__file__).resolve().parent
if (BUNDLE_ROOT / "src" / "kintsugi").is_dir():
    _SRC_DIR = BUNDLE_ROOT / "src"
elif (BUNDLE_ROOT.parent / "src" / "kintsugi").is_dir():
    _SRC_DIR = BUNDLE_ROOT.parent / "src"
else:
    _SRC_DIR = BUNDLE_ROOT / "src"

if str(BUNDLE_ROOT) not in sys.path:
    sys.path.insert(0, str(BUNDLE_ROOT))
if _SRC_DIR.is_dir() and str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
os.environ.setdefault("KINTSUGI_DISABLE_NATIVE", "1")

from scanner_sandbox import extract_code_capsule_signals  # noqa: E402
from security_io import (  # noqa: E402
    MAX_STORE_BYTES,
    atomic_write_json_secure,
    dlp_scan_object,
    file_lock,
    read_regular_bytes_secure,
    reject_symlink,
    reject_symlink_ancestors,
    sha256_bytes,
    strict_json_loads,
)
from truth_gate import MAX_TRUTH_GATE_BYTES, run_custom_truth_gate  # noqa: E402

EVOLUTION_SCHEMA = "KintsugiCloudSandboxEvolution/1"
PATCH_SCHEMA = "KintsugiCloudSandboxEvolutionPatch/1"
QUARANTINE_SCHEMA = "KintsugiCloudSandboxQuarantine/1"
CANARY_SCHEMA = "KintsugiCloudSandboxCanaryCorpus/1"

DEFAULT_STATE_DIR = Path("/tmp/kintsugi_sandbox_state")
DEFAULT_EVOLUTION_STORE = DEFAULT_STATE_DIR / "learned_scars.json"
DEFAULT_TELEMETRY_STORE = DEFAULT_STATE_DIR / "delivery_telemetry.json"
DEFAULT_CANARY_CORPUS = BUNDLE_ROOT / "data" / "canary_corpus_v3.json"

MAX_DESC_CHARS = 320
MAX_TRIGGER_GROUPS = 6
MAX_TOKENS_PER_GROUP = 12
MAX_ACTIVE_LEARNED_SCARS = 64
MAX_PREVIOUS_REVISIONS = 64

ID_RE = re.compile(r"^[A-Z]{2,8}-[A-Z0-9-]{2,32}$")
SLUG_RE = re.compile(r"^[a-z][a-z0-9_]{2,48}$")
CATEGORY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TRIGGER_TOKEN_RE = re.compile(r"^(?:@struct_[a-z0-9_]{2,48}|[a-z][a-z0-9_$]{1,63})$")
RESERVED_ID_PREFIXES = ("LT-", "CAP-")

ALLOWED_LANGUAGES = frozenset(
    {"python", "typescript", "javascript", "solidity", "sql", "bash", "markdown", "json", "*"}
)
ALLOWED_ROLES = frozenset({"detect_bug", "context_reminder"})

COMMON_STOPWORDS = frozenset(
    {
        "def", "class", "return", "import", "from", "self", "cls", "if", "else", "elif",
        "for", "while", "in", "is", "not", "and", "or", "try", "except", "finally",
        "with", "as", "pass", "none", "true", "false", "int", "str", "dict", "list",
        "set", "tuple", "bool", "float", "bytes", "any", "function", "const", "let",
        "var", "fn", "pub", "async", "await", "new", "this", "value", "data", "item",
    }
)

_CANARY_CACHE: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}


def resolve_state_paths(
    state_dir: Optional[Path] = None,
    store_path: Optional[Path] = None,
    telemetry_store: Optional[Path] = None,
) -> Tuple[Path, Path]:
    """Resolve evolution store and telemetry store paths consistently."""
    base = Path(state_dir) if state_dir is not None else DEFAULT_STATE_DIR
    evo = Path(store_path) if store_path is not None else (base / "learned_scars.json")
    tel = Path(telemetry_store) if telemetry_store is not None else (base / "delivery_telemetry.json")
    return evo, tel


def _extract_signals_for_lang(code_text: str, lang: str) -> Set[str]:
    """Delegate signal extraction to `scanner_sandbox.extract_code_capsule_signals` for 100% live-brief parity."""
    norm_lang = (lang or "*").strip().lower()
    return extract_code_capsule_signals(code_text, lang=norm_lang)[0]


# ---------------------------------------------------------------------------
# Canary Corpus, Language/Role, Revision Digest & Validation
# ---------------------------------------------------------------------------


def _load_canary_corpus(canary_path: Path = DEFAULT_CANARY_CORPUS) -> List[Dict[str, Any]]:
    cpath = Path(canary_path)
    raw = read_regular_bytes_secure(cpath, max_bytes=MAX_STORE_BYTES)
    if len(raw) == 0:
        raise ValueError(f"CORRUPT_EMPTY_CANARY_CORPUS: {cpath}")
    cache_key = (str(cpath.resolve()), sha256_bytes(raw))
    cached = _CANARY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    doc = strict_json_loads(raw.decode("utf-8"))
    if (
        not isinstance(doc, dict)
        or doc.get("schema") != CANARY_SCHEMA
        or not isinstance(doc.get("samples"), list)
        or len(doc["samples"]) < 16
    ):
        raise ValueError(f"INVALID_CANARY_CORPUS: expected {CANARY_SCHEMA} with >= 16 samples")

    parsed: List[Dict[str, Any]] = []
    for item in doc["samples"]:
        if not isinstance(item, dict):
            raise ValueError("INVALID_CANARY_SAMPLE_ENTRY")
        sid = str(item.get("id") or "").strip()
        slang = str(item.get("language") or "").strip().lower()
        code = item.get("code")
        if not sid or slang not in ALLOWED_LANGUAGES or slang == "*" or not isinstance(code, str) or not code.strip():
            raise ValueError(f"INVALID_CANARY_SAMPLE: {sid!r}")
        parsed.append(
            {
                "id": sid,
                "language": slang,
                "signals": extract_code_capsule_signals(code, lang=slang)[0],
            }
        )
    _CANARY_CACHE.clear()
    _CANARY_CACHE[cache_key] = parsed
    return parsed


def _language_matches_sample(declared_langs: Sequence[str], sample_lang: str) -> bool:
    if "*" in declared_langs:
        return True
    if sample_lang in declared_langs:
        return True
    if sample_lang == "javascript" and "typescript" in declared_langs:
        return True
    if sample_lang == "typescript" and "javascript" in declared_langs:
        return True
    return False


def _is_verified_lang_compatible(
    verified_lang: str,
    declared_langs: Sequence[str],
    *,
    role: str = "detect_bug",
) -> bool:
    v = (verified_lang or "").strip().lower()
    if v not in ALLOWED_LANGUAGES or v == "*":
        return False
    role_norm = (role or "detect_bug").strip().lower()
    if role_norm == "detect_bug":
        return bool(declared_langs) and all(ln == v for ln in declared_langs)
    if "*" in declared_langs:
        return True
    if v in declared_langs:
        return True
    if v == "javascript" and "typescript" in declared_langs:
        return True
    return False


def _build_compact(sid: str, slug: str, cat: str, bad_p: str, good_p: str, pre_p: str) -> str:
    return f"@PITFALL[{sid}|{slug}|{cat}] AVOID: {bad_p} -> DO: {good_p} | WHEN: {pre_p}"


def _canonical_proof_for_hash(proof: Dict[str, Any]) -> Dict[str, Any]:
    """Strip non-content timestamps (`verified_utc`, `learned_utc`) for deterministic revision hashing."""
    return {k: v for k, v in proof.items() if k not in ("verified_utc", "learned_utc")}


def _compute_revision_sha256(record_core: Dict[str, Any]) -> str:
    payload = {
        "id": record_core["id"],
        "slug": record_core["slug"],
        "category": record_core["category"],
        "languages": record_core["languages"],
        "role": record_core["role"],
        "trigger_groups": record_core["trigger_groups"],
        "bad_pattern": record_core["bad_pattern"],
        "good_pattern": record_core["good_pattern"],
        "precondition": record_core["precondition"],
        "truth_gate_proof": _canonical_proof_for_hash(record_core["truth_gate_proof"]),
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(canonical)


def _compute_patch_sha256(payload: Dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "patch_sha256"}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(canonical)


def _check_dlp_clean(obj: Any, *, err_code: str = "DLP_BLOCKED_LEARNED_SCAR") -> None:
    findings = dlp_scan_object(obj)
    if findings:
        first = findings[0]
        rule_name = first.get("rule") or first.get("rule_id") or "DLP"
        raise ValueError(f"{err_code}: {rule_name} ({len(findings)} finding(s))")


def _check_single_line_text(val: Any, field_name: str) -> str:
    if not isinstance(val, str):
        raise ValueError(f"INVALID_{field_name.upper()}: must be string")
    s = val.strip()
    if not s or len(s) > MAX_DESC_CHARS:
        raise ValueError(f"INVALID_{field_name.upper()}: length must be 1..{MAX_DESC_CHARS}")
    if any(ch in s for ch in ("\n", "\r", "\x00")):
        raise ValueError(f"INVALID_{field_name.upper()}: control characters/newlines forbidden")
    return s


def _validate_languages_and_role(
    languages: Sequence[str],
    role: str,
    trigger_groups: Sequence[Sequence[str]],
) -> Tuple[List[str], str]:
    role_norm = (role or "detect_bug").strip().lower()
    if role_norm not in ALLOWED_ROLES:
        raise ValueError(f"INVALID_ROLE: {role!r} (expected one of {sorted(ALLOWED_ROLES)})")

    if not isinstance(languages, (list, tuple)) or not languages:
        raise ValueError("LANGUAGES_REQUIRED: must provide at least one allowlisted language")

    cleaned_langs: List[str] = []
    for raw_l in languages:
        if not isinstance(raw_l, str):
            raise ValueError("NON_STRING_LANGUAGE")
        ln = raw_l.strip().lower()
        if ln not in ALLOWED_LANGUAGES:
            raise ValueError(f"UNSUPPORTED_LANGUAGE: {raw_l!r} (allowed: {sorted(ALLOWED_LANGUAGES)})")
        if ln not in cleaned_langs:
            cleaned_langs.append(ln)

    if "*" in cleaned_langs and role_norm == "detect_bug":
        raise ValueError(
            "WILDCARD_LANGUAGE_FORBIDDEN_FOR_DETECT_BUG: specify concrete language(s) or use role='context_reminder'"
        )
    return cleaned_langs, role_norm


def _validate_trigger_groups(
    trigger_groups: Sequence[Sequence[str]],
    *,
    languages: Sequence[str] = ("*",),
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> List[List[str]]:
    if not isinstance(trigger_groups, (list, tuple)) or len(trigger_groups) < 2:
        raise ValueError("TRIGGER_GROUPS_REQUIRE_AT_LEAST_2_DISJOINT_GROUPS")
    if len(trigger_groups) > MAX_TRIGGER_GROUPS:
        raise ValueError(f"TOO_MANY_TRIGGER_GROUPS: {len(trigger_groups)} > {MAX_TRIGGER_GROUPS}")

    cleaned: List[List[str]] = []
    seen_across: Set[str] = set()
    for g_idx, grp in enumerate(trigger_groups):
        if not isinstance(grp, (list, tuple)) or not grp:
            raise ValueError(f"EMPTY_TRIGGER_GROUP: index={g_idx}")
        if len(grp) > MAX_TOKENS_PER_GROUP:
            raise ValueError(f"TOO_MANY_TOKENS_IN_GROUP: {len(grp)} > {MAX_TOKENS_PER_GROUP}")
        norm: List[str] = []
        for tok in grp:
            if not isinstance(tok, str):
                raise ValueError("NON_STRING_TRIGGER_TOKEN")
            t = tok.strip().lower()
            if not TRIGGER_TOKEN_RE.fullmatch(t):
                raise ValueError(f"INVALID_TRIGGER_TOKEN: {tok!r}")
            if t in COMMON_STOPWORDS:
                raise ValueError(f"STOPWORD_TRIGGER_REJECTED: {t!r}")
            if t not in norm:
                norm.append(t)
        overlap = seen_across.intersection(norm)
        if overlap:
            raise ValueError(f"OVERLAPPING_TRIGGER_GROUPS: {sorted(overlap)}")
        seen_across.update(norm)
        cleaned.append(norm)

    # Multi-canary 0% FP verification across all matching benign samples.
    canaries = _load_canary_corpus(canary_path)
    for sample in canaries:
        if not _language_matches_sample(languages, sample["language"]):
            continue
        if all(any(tok in sample["signals"] for tok in grp) for grp in cleaned):
            raise ValueError(
                f"TRIGGER_GROUPS_FIRE_ON_BENIGN_CANARY: {sample['id']} ({sample['language']})"
            )
    return cleaned


def _validate_stored_scar(
    entry: Any,
    *,
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> Optional[Dict[str, Any]]:
    """Fail-closed validation of a persisted scar record (verifies revision_sha256 & rebuilds compact)."""
    if not isinstance(entry, dict):
        return None
    raw_id = entry.get("id")
    if not isinstance(raw_id, str):
        return None
    sid = raw_id.strip().upper()
    if not ID_RE.fullmatch(sid) or sid.startswith(RESERVED_ID_PREFIXES):
        return None

    slug = entry.get("slug")
    cat = entry.get("category")
    if (
        not isinstance(slug, str)
        or not SLUG_RE.fullmatch(slug)
        or not isinstance(cat, str)
        or not CATEGORY_RE.fullmatch(cat)
    ):
        return None

    try:
        bad_p = _check_single_line_text(entry.get("bad_pattern"), "bad_pattern")
        good_p = _check_single_line_text(entry.get("good_pattern"), "good_pattern")
        pre_p = _check_single_line_text(entry.get("precondition"), "precondition")
    except ValueError:
        return None

    raw_role = entry.get("role")
    if not isinstance(raw_role, str) or raw_role.strip().lower() not in ALLOWED_ROLES:
        return None

    raw_langs = entry.get("languages")
    if not isinstance(raw_langs, list) or not raw_langs:
        return None

    proof = entry.get("truth_gate_proof")
    if not isinstance(proof, dict) or proof.get("verdict") != "PROMOTE_ELIGIBLE":
        return None
    b_sha = proof.get("broken_sha256")
    f_sha = proof.get("fixed_sha256")
    t_sha = proof.get("test_sha256")
    v_lang = proof.get("verified_language")
    if (
        not isinstance(b_sha, str)
        or not HEX64_RE.fullmatch(b_sha)
        or not isinstance(f_sha, str)
        or not HEX64_RE.fullmatch(f_sha)
        or not isinstance(t_sha, str)
        or not HEX64_RE.fullmatch(t_sha)
        or b_sha == f_sha
        or not isinstance(v_lang, str)
        or v_lang.strip().lower() not in ALLOWED_LANGUAGES
        or v_lang.strip().lower() == "*"
    ):
        return None

    try:
        langs, role = _validate_languages_and_role(
            raw_langs, raw_role, entry.get("trigger_groups") or []  # type: ignore[arg-type]
        )
        if not _is_verified_lang_compatible(v_lang, langs, role=role):
            return None
        groups = _validate_trigger_groups(
            entry.get("trigger_groups"),  # type: ignore[arg-type]
            languages=langs,
            canary_path=canary_path,
        )
        _check_dlp_clean(entry)
    except (ValueError, OSError, PermissionError):
        return None

    rev_sha = entry.get("revision_sha256")
    if not isinstance(rev_sha, str) or not HEX64_RE.fullmatch(rev_sha):
        return None

    core = {
        "id": sid,
        "slug": slug,
        "category": cat,
        "languages": langs,
        "role": role,
        "trigger_groups": groups,
        "bad_pattern": bad_p,
        "good_pattern": good_p,
        "precondition": pre_p,
        "truth_gate_proof": proof,
    }
    expected_rev_sha = _compute_revision_sha256(core)
    if rev_sha != expected_rev_sha:
        return None

    rev_num = entry.get("revision", 1)
    if not isinstance(rev_num, int) or isinstance(rev_num, bool) or rev_num < 1:
        return None
    prev_revs_raw = entry.get("previous_revisions", [])
    if not isinstance(prev_revs_raw, list) or not all(
        isinstance(h, str) and HEX64_RE.fullmatch(h) for h in prev_revs_raw
    ):
        return None
    raw_parent_rev = entry.get("parent_revision_sha256", "")
    if not isinstance(raw_parent_rev, str) or (raw_parent_rev != "" and not HEX64_RE.fullmatch(raw_parent_rev)):
        return None

    clean = dict(entry)
    clean["id"] = sid
    clean["slug"] = slug
    clean["category"] = cat
    clean["languages"] = langs
    clean["role"] = role
    clean["trigger_groups"] = groups
    clean["bad_pattern"] = bad_p
    clean["good_pattern"] = good_p
    clean["precondition"] = pre_p
    clean["revision"] = rev_num
    clean["revision_id"] = f"{sid}@r{rev_num}"
    clean["revision_sha256"] = expected_rev_sha
    clean["parent_revision_sha256"] = raw_parent_rev
    clean["previous_revisions"] = list(prev_revs_raw[-MAX_PREVIOUS_REVISIONS:])
    # Always rebuild compact from validated fields; ignore tampered on-disk compact text.
    clean["compact"] = _build_compact(sid, slug, cat, bad_p, good_p, pre_p)
    return clean


# ---------------------------------------------------------------------------
# Store Persistence & Active Loader
# ---------------------------------------------------------------------------


def load_evolution_store(store_path: Path) -> Dict[str, Any]:
    spath = Path(store_path)
    reject_symlink(spath)
    reject_symlink_ancestors(spath.parent)
    if not spath.exists():
        return {"schema": EVOLUTION_SCHEMA, "version": "3.1.1", "scars": []}
    raw = read_regular_bytes_secure(spath, max_bytes=MAX_STORE_BYTES)
    if len(raw) == 0:
        raise ValueError("CORRUPT_EMPTY_STORE")
    doc = strict_json_loads(raw.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != EVOLUTION_SCHEMA or not isinstance(doc.get("scars"), list):
        raise ValueError(f"UNRECOGNIZED_EVOLUTION_STORE: expected schema {EVOLUTION_SCHEMA}")
    return doc


def _load_frozen_ids_safe(telemetry_store: Optional[Path]) -> Set[str]:
    if telemetry_store is None:
        return set()
    tpath = Path(telemetry_store)
    from kintsugi.evolution.delivery_telemetry import load_frozen_ids_strict

    return {str(x).strip().upper() for x in load_frozen_ids_strict(tpath) if str(x).strip()}


def load_active_learned_scars(
    store_path: Path = DEFAULT_EVOLUTION_STORE,
    telemetry_store: Optional[Path] = DEFAULT_TELEMETRY_STORE,
    *,
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> List[Dict[str, Any]]:
    """Return validated, deduplicated, Truth-Gate-verified, non-frozen learned scars (capped at 64)."""
    spath = Path(store_path)
    if not spath.exists():
        return []
    doc = load_evolution_store(spath)
    frozen = _load_frozen_ids_safe(telemetry_store)
    seen_ids: Set[str] = set()
    active: List[Dict[str, Any]] = []
    for entry in doc.get("scars", []):
        valid = _validate_stored_scar(entry, canary_path=canary_path)
        if valid is None:
            continue
        sid = valid["id"]
        if sid in seen_ids:
            continue
        seen_ids.add(sid)
        if sid in frozen or valid.get("frozen"):
            continue
        active.append(valid)
        if len(active) >= MAX_ACTIVE_LEARNED_SCARS:
            break
    return active


# ---------------------------------------------------------------------------
# Closed-Loop Learn, Status, Export & Import Patch
# ---------------------------------------------------------------------------


def evolve_learn(
    *,
    store_path: Path = DEFAULT_EVOLUTION_STORE,
    scar_id: str,
    slug: str,
    category: str,
    languages: Sequence[str],
    trigger_groups: Sequence[Sequence[str]],
    bad_pattern: str,
    good_pattern: str,
    precondition: str,
    broken_path: Path,
    fixed_path: Path,
    test_path: Path,
    role: str = "detect_bug",
    runner: str = "auto",
    timeout_s: int = 15,
    kintsugi_version: str = "3.1.1",
    telemetry_store: Optional[Path] = DEFAULT_TELEMETRY_STORE,
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> Dict[str, Any]:
    """Verify a candidate scar via trusted internal Truth Gate + Matcher-on-Broken + Multi-Canary + DLP."""
    sid = (scar_id or "").strip().upper()
    if not ID_RE.fullmatch(sid):
        raise ValueError(f"INVALID_SCAR_ID: {scar_id!r} (expected e.g. CSB-001)")
    if sid.startswith(RESERVED_ID_PREFIXES):
        raise ValueError(f"RESERVED_SCAR_PREFIX: {sid!r} (cannot collide with built-in LT-/CAP- IDs)")
    if sid in _load_frozen_ids_safe(telemetry_store):
        raise ValueError(f"SCAR_ID_ALREADY_FROZEN: {sid!r}")

    sl = (slug or "").strip().lower()
    if not SLUG_RE.fullmatch(sl):
        raise ValueError(f"INVALID_SLUG: {slug!r}")
    cat = (category or "").strip().lower()
    if not CATEGORY_RE.fullmatch(cat):
        raise ValueError(f"INVALID_CATEGORY: {category!r}")

    langs, role_norm = _validate_languages_and_role(languages, role, trigger_groups)
    groups = _validate_trigger_groups(trigger_groups, languages=langs, canary_path=canary_path)
    bad_p = _check_single_line_text(bad_pattern, "bad_pattern")
    good_p = _check_single_line_text(good_pattern, "good_pattern")
    pre_p = _check_single_line_text(precondition, "precondition")

    candidate_fields: Dict[str, Any] = {
        "id": sid,
        "slug": sl,
        "category": cat,
        "languages": langs,
        "role": role_norm,
        "trigger_groups": groups,
        "bad_pattern": bad_p,
        "good_pattern": good_p,
        "precondition": pre_p,
    }
    _check_dlp_clean(candidate_fields)

    b_path = Path(broken_path)
    f_path = Path(fixed_path)
    t_path = Path(test_path)
    for p in (b_path, f_path, t_path):
        reject_symlink(p)
        reject_symlink_ancestors(p.parent)
        if not p.is_file():
            raise FileNotFoundError(f"TRUTH_GATE_FILE_MISSING: {p}")

    # Gate 3: Trusted internal Universal Truth Gate (never accepts caller-injected callback).
    tg = run_custom_truth_gate(b_path, f_path, t_path, runner=runner, timeout_s=timeout_s)
    tg_verdict = str(tg.get("verdict") or tg.get("status") or "")
    if not tg.get("ok") or tg_verdict != "PROMOTE_ELIGIBLE":
        return {"ok": False, "status": "REJECTED_BY_UNIVERSAL_TRUTH_GATE", "scar_id": sid, "truth_gate": tg}

    verified_lang = str(tg.get("verified_language") or "").strip().lower()
    if not _is_verified_lang_compatible(verified_lang, langs, role=role_norm):
        return {
            "ok": False,
            "status": "REJECTED_LANGUAGE_PROOF_MISMATCH",
            "scar_id": sid,
            "role": role_norm,
            "declared_languages": langs,
            "verified_language": verified_lang,
            "truth_gate": tg,
        }

    b_sha, f_sha, t_sha = str(tg.get("broken_sha256") or ""), str(tg.get("fixed_sha256") or ""), str(tg.get("test_sha256") or "")
    if not (HEX64_RE.fullmatch(b_sha) and HEX64_RE.fullmatch(f_sha) and HEX64_RE.fullmatch(t_sha)) or b_sha == f_sha:
        return {"ok": False, "status": "REJECTED_BY_UNIVERSAL_TRUTH_GATE", "scar_id": sid, "truth_gate": {"ok": False, "error": "INVALID_OR_IDENTICAL_PROOF_HASHES"}}

    # Gate 4: Matcher-on-Broken + Negative-Control-on-Fixed (SHA-256 parity against Truth Gate proof).
    broken_bytes = read_regular_bytes_secure(b_path, max_bytes=MAX_TRUTH_GATE_BYTES)
    if sha256_bytes(broken_bytes) != b_sha:
        return {"ok": False, "status": "REJECTED_BROKEN_FILE_MODIFIED_TOCTOU", "scar_id": sid}
    fixed_bytes = read_regular_bytes_secure(f_path, max_bytes=MAX_TRUTH_GATE_BYTES)
    if sha256_bytes(fixed_bytes) != f_sha:
        return {"ok": False, "status": "REJECTED_FIXED_FILE_MODIFIED_TOCTOU", "scar_id": sid}

    broken_signals = extract_code_capsule_signals(broken_bytes.decode("utf-8"), lang=verified_lang)[0]
    missed_groups = [grp for grp in groups if not any(tok in broken_signals for tok in grp)]
    if missed_groups:
        return {
            "ok": False,
            "status": "REJECTED_TRIGGERS_MISS_BROKEN_REPRO",
            "scar_id": sid,
            "role": role_norm,
            "verified_language": verified_lang,
            "missed_groups": missed_groups,
            "broken_signals_sample": sorted(broken_signals)[:40],
        }

    if role_norm == "detect_bug":
        fixed_signals = extract_code_capsule_signals(fixed_bytes.decode("utf-8"), lang=verified_lang)[0]
        if all(any(tok in fixed_signals for tok in grp) for grp in groups):
            return {
                "ok": False,
                "status": "REJECTED_TRIGGERS_STILL_MATCH_FIXED",
                "scar_id": sid,
                "verified_language": verified_lang,
                "hint": "Tighten trigger_groups to match only the buggy construct, or pass role='context_reminder'",
                "fixed_signals_sample": sorted(fixed_signals)[:40],
            }

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    truth_gate_proof = {
        "verdict": "PROMOTE_ELIGIBLE",
        "runner": str(tg.get("runner") or runner),
        "verified_language": verified_lang,
        "property_id": str(tg.get("fixed_property_id") or "ASSERTION"),
        "assertions_run": int(tg.get("fixed_assertions_run") or 1),
        "broken_sha256": b_sha,
        "fixed_sha256": f_sha,
        "test_sha256": t_sha,
        "verified_utc": now_utc,
    }

    core_for_hash = {**candidate_fields, "truth_gate_proof": truth_gate_proof}
    rev_sha = _compute_revision_sha256(core_for_hash)
    compact = _build_compact(sid, sl, cat, bad_p, good_p, pre_p)

    spath = Path(store_path)
    with file_lock(spath):
        store = load_evolution_store(spath)
        existing_match: Optional[Dict[str, Any]] = None
        others: List[Dict[str, Any]] = []
        seen_other_ids: Set[str] = set()
        for s in store["scars"]:
            if not isinstance(s, dict):
                continue
            eid = str(s.get("id", "")).strip().upper()
            if eid == sid:
                if existing_match is None:
                    existing_match = s
            elif eid and eid not in seen_other_ids:
                seen_other_ids.add(eid)
                others.append(s)

        if existing_match is None and len(others) >= MAX_ACTIVE_LEARNED_SCARS:
            raise ValueError(f"EVOLUTION_STORE_CAPACITY_REACHED: max {MAX_ACTIVE_LEARNED_SCARS} learned scars")

        prev_revs: List[str] = []
        parent_rev_sha = ""
        if existing_match is not None:
            raw_prev_rev = existing_match.get("revision", 1)
            prev_rev_num = raw_prev_rev if (isinstance(raw_prev_rev, int) and not isinstance(raw_prev_rev, bool) and raw_prev_rev >= 1) else 1
            raw_hist = existing_match.get("previous_revisions", [])
            if isinstance(raw_hist, list):
                for h in raw_hist:
                    if isinstance(h, str) and HEX64_RE.fullmatch(h) and h not in prev_revs:
                        prev_revs.append(h)
            old_sha = existing_match.get("revision_sha256")
            if isinstance(old_sha, str) and HEX64_RE.fullmatch(old_sha):
                if old_sha == rev_sha:
                    rev_num = prev_rev_num
                    raw_old_parent = existing_match.get("parent_revision_sha256", "")
                    parent_rev_sha = raw_old_parent if (isinstance(raw_old_parent, str) and HEX64_RE.fullmatch(raw_old_parent)) else ""
                else:
                    if old_sha not in prev_revs:
                        prev_revs.append(old_sha)
                    prev_revs = prev_revs[-MAX_PREVIOUS_REVISIONS:]
                    parent_rev_sha = old_sha
                    rev_num = prev_rev_num + 1
            else:
                rev_num = prev_rev_num + 1
        else:
            rev_num = 1

        record: Dict[str, Any] = {
            **candidate_fields,
            "compact": compact,
            "revision": rev_num,
            "revision_id": f"{sid}@r{rev_num}",
            "revision_sha256": rev_sha,
            "parent_revision_sha256": parent_rev_sha,
            "previous_revisions": prev_revs,
            "learned_utc": now_utc,
            "kintsugi_version": kintsugi_version,
            "truth_gate_proof": truth_gate_proof,
        }
        _check_dlp_clean(record)

        scars = others + [record]
        scars.sort(key=lambda x: str(x.get("id", "")))
        store["scars"] = scars
        store["version"] = kintsugi_version
        store["updated_utc"] = now_utc
        atomic_write_json_secure(spath, store, mode=0o600, max_bytes=MAX_STORE_BYTES)

    return {
        "ok": True,
        "status": "PROMOTED_TO_LIVE_EVOLUTION_STORE",
        "store": str(spath),
        "scar": record,
        "total_learned": len(scars),
    }


def evolve_status(
    store_path: Path = DEFAULT_EVOLUTION_STORE,
    telemetry_store: Optional[Path] = DEFAULT_TELEMETRY_STORE,
    *,
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> Dict[str, Any]:
    spath = Path(store_path)
    store = load_evolution_store(spath)
    frozen = _load_frozen_ids_safe(telemetry_store)
    active_ids: List[str] = []
    frozen_learned: List[str] = []
    seen_ids: Set[str] = set()
    invalid_count = 0
    duplicate_count = 0

    for raw in store.get("scars", []):
        valid = _validate_stored_scar(raw, canary_path=canary_path)
        if valid is None:
            invalid_count += 1
            continue
        sid = valid["id"]
        if sid in seen_ids:
            duplicate_count += 1
            invalid_count += 1
            continue
        seen_ids.add(sid)
        if sid in frozen or valid.get("frozen"):
            frozen_learned.append(sid)
        else:
            active_ids.append(sid)

    return {
        "ok": True,
        "schema": EVOLUTION_SCHEMA,
        "store": str(spath),
        "total_learned": len(active_ids) + len(frozen_learned),
        "active_learned_count": len(active_ids),
        "frozen_learned_count": len(frozen_learned),
        "rejected_invalid_count": invalid_count,
        "duplicate_id_count": duplicate_count,
        "active_learned_ids": active_ids,
        "frozen_learned_ids": frozen_learned,
        "telemetry_frozen_ids": sorted(frozen),
    }


def _reject_state_file_alias(
    out_path: Path,
    store_path: Path,
    telemetry_store: Optional[Path],
) -> None:
    opath = Path(out_path)
    reject_symlink(opath)
    reject_symlink_ancestors(opath.parent)
    if opath.name.endswith(".lock"):
        raise ValueError(f"OUTPUT_ALIASES_STATE_FILE: refusing .lock output path {opath}")

    def _norm(p: Path) -> str:
        return os.path.realpath(str(p))

    forbidden = {
        _norm(store_path),
        _norm(Path(f"{store_path}.lock")),
        _norm(store_path.parent / "quarantine_scars.json"),
        _norm(Path(f"{store_path.parent / 'quarantine_scars.json'}.lock")),
    }
    if telemetry_store is not None:
        forbidden.add(_norm(telemetry_store))
        forbidden.add(_norm(Path(f"{telemetry_store}.lock")))
    if _norm(opath) in forbidden:
        raise ValueError(f"OUTPUT_ALIASES_STATE_FILE: {opath} aliases internal state file")


def evolve_export_patch(
    *,
    store_path: Path = DEFAULT_EVOLUTION_STORE,
    telemetry_store: Optional[Path] = DEFAULT_TELEMETRY_STORE,
    out_path: Optional[Path] = None,
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> Dict[str, Any]:
    """Export active, validated, Truth-Gate-attested, DLP-clean learned scars as a SHA-256 integrity-hashed JSON delta."""
    spath = Path(store_path)
    tpath = Path(telemetry_store) if telemetry_store is not None else None
    if out_path is not None:
        _reject_state_file_alias(Path(out_path), spath, tpath)

    active = load_active_learned_scars(spath, tpath, canary_path=canary_path)
    frozen_ids = sorted(_load_frozen_ids_safe(tpath))

    payload: Dict[str, Any] = {
        "schema": PATCH_SCHEMA,
        "exported_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target_repo": "https://github.com/tunguyen1993/kintsugi-harness",
        "scars_count": len(active),
        "frozen_ids": frozen_ids,
        "scars": active,
    }
    _check_dlp_clean(payload, err_code="DLP_BLOCKED_EVOLUTION_PATCH")
    patch_sha = _compute_patch_sha256(payload)
    payload["patch_sha256"] = patch_sha

    if out_path is not None:
        atomic_write_json_secure(Path(out_path), payload, mode=0o600, max_bytes=MAX_STORE_BYTES)

    return {
        "ok": True,
        "status": "EXPORTED_ATTESTED_EVOLUTION_PATCH",
        "out_path": str(out_path) if out_path else "",
        "scars_count": len(active),
        "frozen_ids": frozen_ids,
        "patch_sha256": patch_sha,
        "patch": payload,
    }


def _load_quarantine_store(q_path: Path) -> Dict[str, Any]:
    reject_symlink(q_path)
    reject_symlink_ancestors(q_path.parent)
    if not q_path.exists():
        return {"schema": QUARANTINE_SCHEMA, "version": "3.1.1", "scars": []}
    raw = read_regular_bytes_secure(q_path, max_bytes=MAX_STORE_BYTES)
    if len(raw) == 0:
        raise ValueError("CORRUPT_EMPTY_QUARANTINE_STORE")
    doc = strict_json_loads(raw.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != QUARANTINE_SCHEMA or not isinstance(doc.get("scars"), list):
        raise ValueError(f"UNRECOGNIZED_QUARANTINE_STORE: expected schema {QUARANTINE_SCHEMA}")
    return doc


def _known_ancestor_revisions(rec: Dict[str, Any]) -> Set[str]:
    known: Set[str] = set()
    for h in rec.get("previous_revisions", []):
        if isinstance(h, str) and HEX64_RE.fullmatch(h):
            known.add(h)
    parent = rec.get("parent_revision_sha256", "")
    if isinstance(parent, str) and HEX64_RE.fullmatch(parent):
        known.add(parent)
    return known


def evolve_import_patch(
    patch_path: Path,
    store_path: Path = DEFAULT_EVOLUTION_STORE,
    telemetry_store: Optional[Path] = DEFAULT_TELEMETRY_STORE,
    expected_patch_sha256: str = "",
    quarantine: bool = True,
    *,
    trust_unverified_proof: bool = False,
    canary_path: Path = DEFAULT_CANARY_CORPUS,
) -> Dict[str, Any]:
    """Fail-closed verify and quarantine (default) or live-merge (`quarantine=False`) an evolution patch."""
    if not quarantine and not (isinstance(expected_patch_sha256, str) and expected_patch_sha256.strip()) and not trust_unverified_proof:
        raise PermissionError(
            "REFUSING_UNPINNED_LIVE_IMPORT: pass expected_patch_sha256 or use quarantine=True"
        )
    ppath = Path(patch_path)
    spath = Path(store_path)
    tpath = Path(telemetry_store) if telemetry_store is not None else None

    raw = read_regular_bytes_secure(ppath, max_bytes=MAX_STORE_BYTES)
    if len(raw) == 0:
        raise ValueError("CORRUPT_EMPTY_PATCH_FILE")
    doc = strict_json_loads(raw.decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != PATCH_SCHEMA or not isinstance(doc.get("scars"), list):
        raise ValueError(f"INVALID_EVOLUTION_PATCH: expected schema {PATCH_SCHEMA}")

    claimed_sha = doc.get("patch_sha256")
    if not isinstance(claimed_sha, str) or not HEX64_RE.fullmatch(claimed_sha):
        raise ValueError("INVALID_PATCH_SHA256_FORMAT")
    computed_sha = _compute_patch_sha256(doc)
    if computed_sha != claimed_sha:
        raise ValueError("PATCH_SHA256_MISMATCH")

    if expected_patch_sha256:
        exp_norm = expected_patch_sha256.strip().lower()
        if not HEX64_RE.fullmatch(exp_norm) or computed_sha != exp_norm:
            raise ValueError("EXPECTED_PATCH_SHA256_MISMATCH")

    _check_dlp_clean(doc, err_code="DLP_BLOCKED_EVOLUTION_PATCH")

    raw_patch_frozen = doc.get("frozen_ids", [])
    if not isinstance(raw_patch_frozen, list) or not all(isinstance(x, str) for x in raw_patch_frozen):
        raise ValueError("INVALID_PATCH_FROZEN_IDS")
    patch_frozen = {x.strip().upper() for x in raw_patch_frozen if x.strip()}
    all_frozen = _load_frozen_ids_safe(tpath) | patch_frozen

    accepted: List[Dict[str, Any]] = []
    seen_in_patch: Set[str] = set()
    skipped_frozen = 0
    rejected_invalid = 0

    for raw_scar in doc["scars"]:
        valid = _validate_stored_scar(raw_scar, canary_path=canary_path)
        if valid is None:
            rejected_invalid += 1
            continue
        sid = valid["id"]
        if sid in seen_in_patch:
            rejected_invalid += 1
            continue
        seen_in_patch.add(sid)
        if sid in all_frozen or valid.get("frozen"):
            skipped_frozen += 1
            continue
        accepted.append(valid)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    imported = 0
    already_present = 0
    already_superseded = 0

    if quarantine:
        q_path = spath.parent / "quarantine_scars.json"
        with file_lock(q_path):
            q_doc = _load_quarantine_store(q_path)
            by_id: Dict[str, Dict[str, Any]] = {}
            for existing in q_doc["scars"]:
                ev = _validate_stored_scar(existing, canary_path=canary_path)
                if ev is not None and ev["id"] not in by_id:
                    by_id[ev["id"]] = ev
            for cand in accepted:
                cid = cand["id"]
                cur = by_id.get(cid)
                if cur is not None:
                    if cur.get("revision_sha256") == cand["revision_sha256"]:
                        already_present += 1
                        continue
                    if cand["revision_sha256"] in _known_ancestor_revisions(cur):
                        already_superseded += 1
                        continue
                if cur is None and len(by_id) >= MAX_ACTIVE_LEARNED_SCARS:
                    rejected_invalid += 1
                    continue
                by_id[cid] = cand
                imported += 1
            scars_out = sorted(by_id.values(), key=lambda x: x["id"])
            q_doc["scars"] = scars_out
            q_doc["updated_utc"] = now_utc
            atomic_write_json_secure(q_path, q_doc, mode=0o600, max_bytes=MAX_STORE_BYTES)
        return {
            "ok": True,
            "status": "QUARANTINED_EVOLUTION_PATCH",
            "quarantine_store": str(q_path),
            "patch_sha256": computed_sha,
            "imported": imported,
            "already_present": already_present,
            "already_superseded": already_superseded,
            "skipped_frozen": skipped_frozen,
            "rejected_invalid": rejected_invalid,
            "total_quarantined": len(scars_out),
        }

    with file_lock(spath):
        store = load_evolution_store(spath)
        by_id = {}
        for existing in store["scars"]:
            ev = _validate_stored_scar(existing, canary_path=canary_path)
            if ev is not None and ev["id"] not in by_id:
                by_id[ev["id"]] = ev

        for cand in accepted:
            cid = cand["id"]
            cur = by_id.get(cid)
            if cur is not None:
                if cur.get("revision_sha256") == cand["revision_sha256"]:
                    already_present += 1
                    continue
                if cand["revision_sha256"] in _known_ancestor_revisions(cur):
                    already_superseded += 1
                    continue
                # Preserve revision history when updating to a newer valid revision.
                prev_hist: List[str] = []
                for h in (
                    *cur.get("previous_revisions", []),
                    cur.get("parent_revision_sha256", ""),
                    cur.get("revision_sha256", ""),
                ):
                    if isinstance(h, str) and HEX64_RE.fullmatch(h) and h not in prev_hist:
                        prev_hist.append(h)
                cur_sha = cur.get("revision_sha256", "")
                merged = dict(cand)
                new_rev = max(int(cur.get("revision", 1)) + 1, int(cand.get("revision", 1)))
                merged["revision"] = new_rev
                merged["revision_id"] = f"{cid}@r{new_rev}"
                merged["parent_revision_sha256"] = cur_sha if (isinstance(cur_sha, str) and HEX64_RE.fullmatch(cur_sha)) else ""
                merged["previous_revisions"] = prev_hist[-MAX_PREVIOUS_REVISIONS:]
                by_id[cid] = merged
                imported += 1
            else:
                if len(by_id) >= MAX_ACTIVE_LEARNED_SCARS:
                    rejected_invalid += 1
                    continue
                by_id[cid] = cand
                imported += 1

        scars_out = sorted(by_id.values(), key=lambda x: x["id"])
        if imported > 0 or not spath.exists():
            store["scars"] = scars_out
            store["updated_utc"] = now_utc
            atomic_write_json_secure(spath, store, mode=0o600, max_bytes=MAX_STORE_BYTES)

    return {
        "ok": True,
        "status": "IMPORTED_EVOLUTION_PATCH",
        "store": str(spath),
        "patch_sha256": computed_sha,
        "imported": imported,
        "already_present": already_present,
        "already_superseded": already_superseded,
        "skipped_frozen": skipped_frozen,
        "rejected_invalid": rejected_invalid,
        "total_learned": len(scars_out),
    }
