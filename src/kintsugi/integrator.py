# kintsugi: ignore-file
"""
Kintsugi Harness v1.8.0 — Universal Drop-In Harness Integrator & Federation Engine (`kintsugi.integrator`).

Enables effortless, fail-closed discovery, quarantine, parsing, conflict verification,
and reversible mounting of existing or user-downloaded agent harnesses:
  - `CLAUDE.md`, `.claude/settings.json`, `.claude/skills/**/SKILL.md`, `SKILL.md`
  - `AGENTS.md`, `CONVENTIONS.md`
  - `.cursorrules`, `.cursor/rules/*.mdc`
  - `.windsurfrules`, `.clinerules`, `.roo/rules/*.md`
  - `.github/copilot-instructions.md`, `.aider.conf.yml`
  - Declarative subsets of OpenHands / CrewAI / AutoGen YAML & JSON configs
  - Local directories, `.zip`, and `.tar.gz` / `.tgz` archives

Enforces all 10 Council-Mandated v1.8.0 Ingest & Formal Verification Invariants:
  1. Streaming archive bounds (size, ratio, file count, depth, path length), rejecting nested archives,
     path traversal (`..`, absolute, drive/UNC, NUL), symlinks/hardlinks/devices/FIFOs, and case-folded
     Unicode NFC duplicate path collisions.
  2. Strict JSON duplicate-key rejection & safe YAML subset parser (no custom tags or alias bombs).
  3. 7-Layer Zero-Trust Quarantine (`0o400` read-only artifacts), preserving raw bytes + normalized view,
     flagging Trojan bidi/zero-width Unicode (`KS-019`) and prompt-injection attempts (`HELD_FOR_REVIEW`),
     and redacting contextual secrets before persistence without ever echoing secret values.
  4. Zero-Execution Capability Classification: hooks, shell pipelines (`curl|sh`), and MCP server spawns
     are classified as `elevate_required` and NEVER executed or mounted in v1.8.0.
  5. 3-Stratum Authority Model (`Stratum A` Hard Core `KS-*`, `Stratum B` Imported Mandatory,
     `Stratum C` Imported Preferences/Defaults) + Joint DPLL(DL) Boolean-Activated Exact Rational/Integer
     Difference-Logic Solver (using exact `(Fraction, strict_bool)` semiring with zero epsilon hacks).
  6. Honest Token & Translation Accounting (`exact` | `conservative` | `opaque` translation status;
     uncompiled `opaque` prose goes to `residual.md` and is excluded from compiled `@KML/1` savings claims).
  7. Domain-separated, length-delimited `@PROOF_DAG/1` supply-chain receipts with 4 provenance labels
     (`unsigned_third_party`, `upstream_signed_unverified`, `upstream_signed_verified`, `kintsugi_accepted`),
     scanner-upgrade revalidation, and non-destructive cross-IDE mount + clean `--eject`.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import math
import os
import re
import shutil
import stat
import tarfile
import time
import unicodedata
import zipfile
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from kintsugi.logic import DPLLSatSolver
from kintsugi.shield import (
    GOOD_CODE_MALWARE_RE,
    OUTBOUND_DLP_SECRET_RE,
    PROMPT_INJECTION_RE,
    TROJAN_UNICODE_RE,
    redact_high_entropy_secrets,
    scan_high_entropy_secrets,
)

INTEGRATOR_VERSION = "1.8.0"
SCANNER_POLICY_VERSION = "2026.11.v180.1"
SOLVER_VERSION = "DPLL-DL-EXACT-SEMIRING/1.8.0"
EXTRACTOR_POLICY_VERSION = "FAIL-CLOSED-ARCHIVE/1.8.0"

# Archive & Ingest Streaming Limits
MAX_COMPRESSED_BYTES = 10 * 1024 * 1024      # 10 MB
MAX_INFLATED_BYTES = 25 * 1024 * 1024        # 25 MB
MAX_SINGLE_FILE_BYTES = 2 * 1024 * 1024      # 2 MB
MAX_ARCHIVE_FILES = 250
MAX_PATH_DEPTH = 12
MAX_PATH_LENGTH = 240
MAX_COMPRESSION_RATIO = 50.0

NESTED_ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".kpack"}

# State Machine States
STATE_RECEIVED = "RECEIVED"
STATE_QUARANTINED = "QUARANTINED"
STATE_PARSED = "PARSED"
STATE_ANALYZED = "ANALYZED"
STATE_HELD_FOR_REVIEW = "HELD_FOR_REVIEW"
STATE_REVIEWED = "REVIEWED"
STATE_APPROVED = "APPROVED"
STATE_MOUNTED = "MOUNTED"
STATE_REJECTED = "REJECTED"
STATE_REVOKED = "REVOKED"

# Provenance Labels
LABEL_UNSIGNED_THIRD_PARTY = "unsigned_third_party"
LABEL_UPSTREAM_SIGNED_UNVERIFIED = "upstream_signed_unverified"
LABEL_UPSTREAM_SIGNED_VERIFIED = "upstream_signed_verified"
LABEL_KINTSUGI_ACCEPTED = "kintsugi_accepted"

# Stratum A: Hard Non-Abducible Core Propositions (always True in Kintsugi Core)
# Format: proposition -> (scar_id, description, negated_conflict_prop)
STRATUM_A_CORE_INVARIANTS: Dict[str, Tuple[str, str]] = {
    "no_shell_true": ("KS-002", "Subprocess execution must never enable shell=True"),
    "no_eval_exec": ("KS-003", "Dynamic eval()/exec()/pickle.loads() on untrusted input is forbidden"),
    "no_hardcoded_secret": ("KS-001", "Hardcoded API keys, tokens, or private keys are forbidden"),
    "no_sql_fstring": ("KS-007", "SQL queries must use parameterized statements, never f-strings"),
    "require_tls_verify": ("KS-011", "TLS certificate verification must remain enabled (verify=True)"),
    "no_force_push_main": ("KS-014", "Destructive git push --force to main or rm -rf / is forbidden"),
    "no_ssrf_metadata": ("KS-016", "Cloud metadata SSRF (169.254.169.254) and non-HTTPS schemes are blocked"),
    "no_outbound_wallet_tx": ("R101", "Receive-only wallet guard: outbound eth_sendRawTransaction / transfer is forbidden"),
}

# Core numeric bounds in Stratum A: key -> (op, value, domain)
STRATUM_A_NUMERIC_BOUNDS: Dict[str, Tuple[str, Fraction, str]] = {
    "http_timeout_sec": ("<=", Fraction(120, 1), "int"),
    "max_agent_steps": ("<=", Fraction(500, 1), "int"),
    "otp_window_sec": ("<=", Fraction(300, 1), "int"),
}


@dataclass
class ImportedRuleIR:
    """Normalized representation of a single rule extracted from an external harness."""

    rule_id: str
    modality: str                # "require" | "prohibit" | "permit" | "prefer" | "advice"
    stratum: str                 # "A" | "B" | "C"
    scope: str                   # glob or domain scope, e.g. "**/*" or "*.py"
    conditions: List[str]        # antecedent propositions P_1, P_2 (empty = unconditional)
    proposition: str             # consequent literal, e.g. "no_shell_true" or "-no_shell_true"
    raw_text: str
    origin_file: str
    origin_line: int
    translation_status: str      # "exact" | "conservative" | "opaque"
    kml_wire: Optional[str] = None
    regex_guard: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "modality": self.modality,
            "stratum": self.stratum,
            "scope": self.scope,
            "conditions": list(self.conditions),
            "proposition": self.proposition,
            "raw_text": self.raw_text,
            "origin_file": self.origin_file,
            "origin_line": self.origin_line,
            "translation_status": self.translation_status,
            "kml_wire": self.kml_wire,
            "regex_guard": self.regex_guard,
        }


@dataclass
class NumericBoundIR:
    """Normalized numeric bound extracted from an external harness (with optional Boolean activator)."""

    bound_id: str
    key: str                     # e.g. "http_timeout_sec", "max_retries", "otp_window_sec"
    op: str                      # "<=" | "<" | ">=" | ">" | "=="
    value: Fraction
    unit: str
    domain: str                  # "int" | "rational"
    stratum: str                 # "A" | "B" | "C"
    activated_by: Optional[str] = None   # Optional Boolean literal activating this bound
    origin_file: str = ""
    origin_line: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bound_id": self.bound_id,
            "key": self.key,
            "op": self.op,
            "value": str(self.value),
            "unit": self.unit,
            "domain": self.domain,
            "stratum": self.stratum,
            "activated_by": self.activated_by,
            "origin_file": self.origin_file,
            "origin_line": self.origin_line,
        }


@dataclass
class CapabilityFinding:
    """Classified capability detected inside an imported harness (never executed during ingest/mount)."""

    capability_type: str         # "shell" | "net" | "write" | "secret" | "mcp" | "hook"
    disposition: str             # "elevate_required" | "declarative_info" | "blocked_malicious"
    evidence_summary: str
    origin_file: str
    origin_line: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability_type": self.capability_type,
            "disposition": self.disposition,
            "evidence_summary": self.evidence_summary,
            "origin_file": self.origin_file,
            "origin_line": self.origin_line,
        }


@dataclass
class HarnessIR:
    """Unified Intermediate Representation produced by versioned harness adapters."""

    harness_id: str
    title: str
    source_path: str
    adapter_id: str
    adapter_version: str
    detected_formats: List[str]
    raw_byte_sha256: str
    normalized_sha256: str
    rules: List[ImportedRuleIR] = field(default_factory=list)
    bounds: List[NumericBoundIR] = field(default_factory=list)
    capabilities: List[CapabilityFinding] = field(default_factory=list)
    security_findings: List[Dict[str, Any]] = field(default_factory=list)
    secrets_found: bool = False
    secrets_redacted_count: int = 0
    files_inventoried: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "harness_id": self.harness_id,
            "title": self.title,
            "source_path": self.source_path,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "detected_formats": list(self.detected_formats),
            "raw_byte_sha256": self.raw_byte_sha256,
            "normalized_sha256": self.normalized_sha256,
            "rules": [r.to_dict() for r in self.rules],
            "bounds": [b.to_dict() for b in self.bounds],
            "capabilities": [c.to_dict() for c in self.capabilities],
            "security_findings": list(self.security_findings),
            "secrets_found": self.secrets_found,
            "secrets_redacted_count": self.secrets_redacted_count,
            "files_inventoried": list(self.files_inventoried),
        }


# ---------------------------------------------------------------------------
# Fail-Closed Path, JSON & Safe YAML Helpers
# ---------------------------------------------------------------------------

WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def _validate_relative_member_path(rel_path: str) -> str:
    """
    Validate an archive or directory relative path against zip-slip, absolute paths,
    Windows drive/UNC prefixes, alternate data streams (`:`), reserved device names,
    NUL bytes, path depth, and length limits.
    """
    if "\x00" in rel_path or ":" in rel_path:
        raise ValueError("INGEST_PATH_NUL_OR_ADS_COLON_FORBIDDEN")
    cleaned = rel_path.replace("\\", "/")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned) or cleaned.startswith("//"):
        raise ValueError(f"INGEST_ABSOLUTE_OR_UNC_PATH_FORBIDDEN: {rel_path}")
    parts = [p for p in cleaned.split("/") if p and p != "."]
    if not parts:
        raise ValueError("INGEST_EMPTY_PATH")
    if any(p == ".." for p in parts):
        raise ValueError(f"INGEST_PATH_TRAVERSAL_FORBIDDEN: {rel_path}")
    for p in parts:
        stem = p.split(".", 1)[0].strip().lower()
        if stem in WINDOWS_RESERVED_NAMES:
            raise ValueError(f"INGEST_WINDOWS_RESERVED_NAME_FORBIDDEN: {p}")
    if len(parts) > MAX_PATH_DEPTH:
        raise ValueError(f"INGEST_PATH_DEPTH_EXCEEDED: {len(parts)} > {MAX_PATH_DEPTH}")
    norm_rel = "/".join(parts)
    if len(norm_rel) > MAX_PATH_LENGTH:
        raise ValueError(f"INGEST_PATH_LENGTH_EXCEEDED: {len(norm_rel)} > {MAX_PATH_LENGTH}")
    return norm_rel


def _canonical_collision_key(rel_path: str) -> str:
    """Case-folded Unicode NFC key to detect duplicate path collisions across OS filesystems."""
    return unicodedata.normalize("NFC", rel_path).casefold()


def parse_json_strict_no_dup_keys(raw_text: str) -> Any:
    """Parse JSON while rejecting duplicate keys in any object (prevents security policy shadowing)."""

    def _no_dups_hook(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"DUPLICATE_JSON_KEY_FORBIDDEN: {k}")
            out[k] = v
        return out

    return json.loads(raw_text, object_pairs_hook=_no_dups_hook)


def parse_safe_yaml_subset(raw_text: str) -> Dict[str, Any]:
    """
    Safe, zero-execution declarative YAML subset parser for `.aider.conf.yml`, CrewAI,
    AutoGen, and OpenHands configs. Explicitly rejects custom YAML tags (`!`, `!!python`),
    alias/anchor bombs (`&`, `*`, `<<:`), and duplicate keys at any indentation level.
    """
    result: Dict[str, Any] = {}
    current_list_key: Optional[str] = None
    nested_seen_keys: Dict[str, Set[str]] = {}

    for line_no, raw_line in enumerate(raw_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Reject custom YAML tags or object construction
        if re.search(r"(?:^|\s)![!A-Za-z0-9_/-]+", stripped):
            raise ValueError(f"UNSAFE_YAML_TAG_FORBIDDEN at line {line_no}")
        # Reject YAML anchors, aliases, or merge keys (alias bomb defense)
        if re.search(r"(?:^|\s)[&*][A-Za-z0-9_-]+|<<\s*:", stripped):
            raise ValueError(f"UNSAFE_YAML_ALIAS_OR_ANCHOR_FORBIDDEN at line {line_no}")

        if stripped.startswith("- ") and current_list_key is not None:
            item_val = stripped[2:].strip().strip("'\"")
            if isinstance(result.get(current_list_key), list):
                result[current_list_key].append(item_val)
            continue

        if ":" in stripped:
            key_part, val_part = stripped.split(":", 1)
            key = key_part.strip().strip("'\"")
            val = val_part.strip()
            if not key:
                continue
            if not raw_line.startswith((" ", "\t")):
                if key in result:
                    raise ValueError(f"DUPLICATE_YAML_KEY_FORBIDDEN: {key} at line {line_no}")
                nested_seen_keys[key] = set()
                if not val:
                    result[key] = []
                    current_list_key = key
                else:
                    current_list_key = None
                    clean_v = val.strip("'\"")
                    if clean_v.lower() in {"true", "yes"}:
                        result[key] = True
                    elif clean_v.lower() in {"false", "no"}:
                        result[key] = False
                    elif re.fullmatch(r"-?\d+", clean_v):
                        result[key] = int(clean_v)
                    else:
                        result[key] = clean_v
            elif current_list_key is not None and isinstance(result.get(current_list_key), list):
                seen_sub = nested_seen_keys.setdefault(current_list_key, set())
                if key in seen_sub:
                    raise ValueError(f"DUPLICATE_NESTED_YAML_KEY_FORBIDDEN: {current_list_key}.{key} at line {line_no}")
                seen_sub.add(key)
                result[current_list_key].append(f"{key}:{val.strip()}")

    return result


# ---------------------------------------------------------------------------
# Exact Semiring Difference-Logic + Joint Boolean SAT(DL) Solver
# ---------------------------------------------------------------------------

class ExactSemiringDifferenceSolver:
    """
    Exact Rational & Integer Difference-Logic Solver over constraints `x_j - x_i <= c` or `< c`.
    Uses the `(Fraction, strict_bool)` ordered semiring where:
      - Edge weight is `(w: Fraction, strict: bool)`.
      - Path composition: `(w1, s1) + (w2, s2) = (w1 + w2, s1 or s2)`.
      - Relaxation: `(w_new, s_new)` is strictly tighter than `(w_old, s_old)` iff
        `w_new < w_old` or (`w_new == w_old` and `s_new > s_old`).
      - Infeasible negative/strict cycle iff `cycle_w < 0` or (`cycle_w == 0` and `cycle_strict`).
    For `domain == "int"`:
      - `x <= c` tightens to `x <= floor(c)`
      - `x < c`  tightens to `x <= ceil(c) - 1` (so `2 < x < 3` -> `x >= 3` and `x <= 2` -> UNSAT!)
      - `x >= c` tightens to `x >= ceil(c)`
      - `x > c`  tightens to `x >= floor(c) + 1`
      - `x == c` with non-integer `c` immediately adds an infeasible `-1` cycle (`UNSAT`).
    For `domain == "rational"`, strictness is preserved exactly in the semiring without epsilon hacks!
    """

    def __init__(self) -> None:
        self.edges: List[Dict[str, Any]] = []
        self.variables: Set[str] = {"__ZERO__"}

    def add_bound(self, bound: NumericBoundIR) -> None:
        var = bound.key
        self.variables.add(var)
        val = Fraction(bound.value)
        is_int = bound.domain == "int"

        # Represent x <= c as var - __ZERO__ <= c
        # Represent x >= c as __ZERO__ - var <= -c
        if bound.op == "<=":
            if is_int:
                self._add_edge("__ZERO__", var, Fraction(math.floor(val), 1), False, bound.bound_id, bound.stratum)
            else:
                self._add_edge("__ZERO__", var, val, False, bound.bound_id, bound.stratum)
        elif bound.op == "<":
            if is_int:
                self._add_edge("__ZERO__", var, Fraction(math.ceil(val) - 1, 1), False, bound.bound_id, bound.stratum)
            else:
                self._add_edge("__ZERO__", var, val, True, bound.bound_id, bound.stratum)
        elif bound.op == ">=":
            if is_int:
                self._add_edge(var, "__ZERO__", -Fraction(math.ceil(val), 1), False, bound.bound_id, bound.stratum)
            else:
                self._add_edge(var, "__ZERO__", -val, False, bound.bound_id, bound.stratum)
        elif bound.op == ">":
            if is_int:
                self._add_edge(var, "__ZERO__", -Fraction(math.floor(val) + 1, 1), False, bound.bound_id, bound.stratum)
            else:
                self._add_edge(var, "__ZERO__", -val, True, bound.bound_id, bound.stratum)
        elif bound.op == "==":
            if is_int and val.denominator != 1:
                # Non-integral equality on an integer variable is impossible: emit direct negative cycle
                self._add_edge("__ZERO__", var, Fraction(math.floor(val), 1), False, f"{bound.bound_id}:le", bound.stratum)
                self._add_edge(var, "__ZERO__", -Fraction(math.ceil(val), 1), False, f"{bound.bound_id}:ge", bound.stratum)
            else:
                self._add_edge("__ZERO__", var, val, False, f"{bound.bound_id}:le", bound.stratum)
                self._add_edge(var, "__ZERO__", -val, False, f"{bound.bound_id}:ge", bound.stratum)

    def _add_edge(
        self,
        u: str,
        v: str,
        weight: Fraction,
        strict: bool,
        cid: str,
        stratum: str,
    ) -> None:
        self.edges.append(
            {
                "u": u,
                "v": v,
                "weight": weight,
                "strict": strict,
                "cid": cid,
                "stratum": stratum,
            }
        )

    @staticmethod
    def _is_tighter(w_new: Fraction, s_new: bool, w_old: Fraction, s_old: bool) -> bool:
        if w_new < w_old:
            return True
        if w_new == w_old and s_new and not s_old:
            return True
        return False

    def solve(self) -> Dict[str, Any]:
        nodes = sorted(self.variables)
        n = len(nodes)
        dist: Dict[str, Tuple[Fraction, bool]] = {v: (Fraction(0, 1), False) for v in nodes}
        pred: Dict[str, Optional[Tuple[str, Dict[str, Any]]]] = {v: None for v in nodes}

        last_updated: Optional[str] = None
        for step in range(n):
            last_updated = None
            for e in self.edges:
                u, v = e["u"], e["v"]
                du_w, du_s = dist[u]
                dv_w, dv_s = dist[v]
                cand_w = du_w + e["weight"]
                cand_s = du_s or e["strict"]
                if self._is_tighter(cand_w, cand_s, dv_w, dv_s):
                    dist[v] = (cand_w, cand_s)
                    pred[v] = (u, e)
                    last_updated = v
            if last_updated is None:
                break

        if last_updated is not None:
            curr = last_updated
            for _ in range(n):
                p_info = pred[curr]
                if p_info is None:
                    break
                curr = p_info[0]
            cycle_edges: List[Dict[str, Any]] = []
            visited: Set[str] = set()
            node = curr
            while node not in visited:
                visited.add(node)
                p_info = pred[node]
                if p_info is None:
                    break
                parent, edge = p_info
                cycle_edges.append(edge)
                node = parent
                if node == curr:
                    break
            cycle_w = sum((e["weight"] for e in cycle_edges), Fraction(0, 1))
            cycle_strict = any(e["strict"] for e in cycle_edges)
            if cycle_w < 0 or (cycle_w == 0 and cycle_strict):
                return {
                    "status": "UNSAT",
                    "satisfiable": False,
                    "cycle_weight": str(cycle_w),
                    "cycle_strict": cycle_strict,
                    "conflict_bound_ids": sorted({e["cid"].split(":")[0] for e in cycle_edges}),
                }

        z_w = dist["__ZERO__"][0]
        model = {v: str(dist[v][0] - z_w) for v in nodes if v != "__ZERO__"}
        return {
            "status": "SAT",
            "satisfiable": True,
            "model": model,
            "conflict_bound_ids": [],
        }


def _build_dpll_solver(clause_specs: Sequence[Tuple[str, Sequence[str]]]) -> DPLLSatSolver:
    solver = DPLLSatSolver()
    seen_ids: Set[str] = set()
    for idx, (cid, lits) in enumerate(clause_specs, start=1):
        unique_cid = cid if cid not in seen_ids else f"{cid}_{idx}"
        seen_ids.add(unique_cid)
        solver.add_clause(list(lits), clause_id=unique_cid)
    return solver


class JointSATDifferenceVerifier:
    """
    Joint Boolean SAT + Exact Semiring Difference-Logic Conflict & Scenario Analyzer.
    Correctly handles:
      1. Unconditional contradictions `S & -S` -> `UNSAT` (with inclusion-minimal MUS).
      2. Conditional rules `P -> S` (`-P | S`) with Core `-S` when `P` is NOT asserted ->
         `SAT` with derived blocked scenario `-P` (`CONDITIONAL_BLOCKED_SCENARIO`), NOT a false global reject!
      3. Conditional rule `P -> S` + Core `-S` + required `P` -> `UNSAT` with 3-clause MUS `{P, -P|S, -S}`.
      4. Boolean choices that activate numeric bounds `B -> (x <= c)` inside the joint DPLL(DL) loop!
    """

    def verify_joint(
        self,
        clauses: List[Tuple[str, Tuple[str, ...]]],
        bounds: List[NumericBoundIR],
        conditional_implications: Optional[List[Tuple[str, List[str], str]]] = None,
    ) -> Dict[str, Any]:
        sat_solver = _build_dpll_solver(clauses)
        sat_res = sat_solver.solve()
        if sat_res["status"] != "SAT":
            mus = sat_res.get("unsat_core") or sat_solver.extract_minimal_unsat_core()
            return {
                "status": sat_res["status"],
                "satisfiable": False,
                "failure_domain": "BOOLEAN_SAT",
                "inclusion_minimal_mus": mus.get("mus_clause_ids", []),
                "is_inclusion_minimal": mus.get("subset_minimality_verified", False),
                "conflict_bound_ids": [],
                "blocked_scenarios": [],
            }

        # Check whether unconditional + Boolean-activated numeric bounds are jointly satisfiable
        activator_vars = sorted(
            {
                b.activated_by.lstrip("-")
                for b in bounds
                if b.activated_by
            }
        )
        learned_nogoods: List[Tuple[str, Tuple[str, ...]]] = list(clauses)
        last_dl_conflict: List[str] = []

        for attempt in range(32):
            cur_solver = _build_dpll_solver(learned_nogoods)
            for av in activator_vars:
                cur_solver.declare_var(av)
            cur_sat = cur_solver.solve()
            if cur_sat["status"] != "SAT":
                mus = cur_sat.get("unsat_core") or cur_solver.extract_minimal_unsat_core()
                return {
                    "status": cur_sat["status"],
                    "satisfiable": False,
                    "failure_domain": "JOINT_SAT_DL",
                    "inclusion_minimal_mus": mus.get("mus_clause_ids", []),
                    "is_inclusion_minimal": mus.get("subset_minimality_verified", False),
                    "conflict_bound_ids": last_dl_conflict,
                    "blocked_scenarios": [],
                }

            bool_model: Dict[str, bool] = cur_sat["model"]
            dl_solver = ExactSemiringDifferenceSolver()
            active_activators: List[str] = []
            for b in bounds:
                if b.activated_by is None:
                    dl_solver.add_bound(b)
                else:
                    act_lit = b.activated_by.strip()
                    is_neg = act_lit.startswith("-")
                    var_name = act_lit[1:] if is_neg else act_lit
                    val = bool_model.get(var_name, False)
                    if (val and not is_neg) or (not val and is_neg):
                        dl_solver.add_bound(b)
                        active_activators.append(act_lit)

            dl_res = dl_solver.solve()
            if dl_res["satisfiable"]:
                # Compute conditional blocked scenarios (e.g. P -> S with core -S forces -P)
                blocked_scenarios: List[Dict[str, Any]] = []
                for rule_id, conds, cons_prop in (conditional_implications or []):
                    if not conds:
                        continue
                    probe_clauses = list(learned_nogoods)
                    for idx_c, c_lit in enumerate(conds):
                        probe_clauses.append((f"PROBE_{rule_id}_{idx_c}", (c_lit,)))
                    probe_solver = _build_dpll_solver(probe_clauses)
                    probe_sat = probe_solver.solve()
                    if probe_sat["status"] != "SAT":
                        mus = probe_sat.get("unsat_core") or probe_solver.extract_minimal_unsat_core()
                        blocked_scenarios.append(
                            {
                                "rule_id": rule_id,
                                "blocked_conditions": list(conds),
                                "entailed_avoidance": [
                                    c[1:] if c.startswith("-") else f"-{c}" for c in conds
                                ],
                                "triggered_consequent": cons_prop,
                                "scenario_mus_clause_ids": mus.get("mus_clause_ids", []),
                            }
                        )

                return {
                    "status": "SAT",
                    "satisfiable": True,
                    "boolean_model": bool_model,
                    "numeric_model": dl_res["model"],
                    "inclusion_minimal_mus": [],
                    "conflict_bound_ids": [],
                    "blocked_scenarios": blocked_scenarios,
                }

            # DL subsystem was UNSAT under this Boolean assignment!
            last_dl_conflict = dl_res["conflict_bound_ids"]
            if not active_activators or not activator_vars:
                return {
                    "status": "UNSAT",
                    "satisfiable": False,
                    "failure_domain": "DIFFERENCE_LOGIC",
                    "cycle_weight": dl_res.get("cycle_weight"),
                    "cycle_strict": dl_res.get("cycle_strict"),
                    "inclusion_minimal_mus": [],
                    "conflict_bound_ids": last_dl_conflict,
                    "blocked_scenarios": [],
                }
            # Add theory blocking clause (nogood) negating the active Boolean activators
            negated_lits = tuple(
                a[1:] if a.startswith("-") else f"-{a}" for a in sorted(set(active_activators))
            )
            learned_nogoods.append(
                (f"DL_THEORY_LEMMA_{attempt}_{'_'.join(last_dl_conflict)}", negated_lits)
            )

        return {
            "status": "UNKNOWN",
            "satisfiable": False,
            "failure_domain": "SOLVER_STEP_LIMIT",
            "inclusion_minimal_mus": [],
            "conflict_bound_ids": last_dl_conflict,
            "blocked_scenarios": [],
        }


# ---------------------------------------------------------------------------
# Prose-to-IR Rule Classifier & Universal Adapter Engine
# ---------------------------------------------------------------------------

# Declarative rule pattern table mapping common harness instructions to canonical propositions
DECLARATIVE_PROPOSITION_PATTERNS: List[Tuple[re.Pattern[str], str, str, Optional[str]]] = [
    (
        re.compile(r"\bshell\s*=\s*True\b", re.IGNORECASE),
        "shell_true",
        "KS-002(subprocess!shell=True->argv_list)",
        r"subprocess\.(?:run|Popen|call)\([^\n]*shell\s*=\s*True",
    ),
    (
        re.compile(r"\b(?:eval|exec)\s*\(|pickle\.loads?\b", re.IGNORECASE),
        "eval_exec",
        "KS-003(no_eval_exec_pickle->literal_eval)",
        r"\b(?:eval|exec|pickle\.loads?)\s*\(",
    ),
    (
        re.compile(r"\b(?:hardcoded?\s+(?:secret|api\s*key|token)|os\.environ)\b", re.IGNORECASE),
        "hardcoded_secret",
        "KS-001(secret!=literal->os.environ)",
        r"(?:api_key|secret_key)\s*=\s*['\"][A-Za-z0-9_-]{16,}['\"]",
    ),
    (
        re.compile(r"\b(?:sql\s+injection|parameterized\s+quer|f-string\s+sql)\b", re.IGNORECASE),
        "sql_fstring",
        "KS-007(sql!fstring->param_query)",
        r"execute\(\s*f['\"](?:SELECT|INSERT|UPDATE|DELETE)\b",
    ),
    (
        re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false", re.IGNORECASE),
        "tls_verify_disabled",
        "KS-011(tls!verify=False->verify=True)",
        r"verify\s*=\s*False",
    ),
    (
        re.compile(r"\bgit\s+push\s+--force\b|rm\s+-rf\s+/", re.IGNORECASE),
        "force_push_main",
        "KS-014(sh!no_force_push_or_rm_rf_root)",
        r"git\s+push\s+--force(?!-with-lease)",
    ),
    (
        re.compile(r"\b169\.254\.169\.254\b|metadata\s+ssrf", re.IGNORECASE),
        "ssrf_metadata",
        "KS-016(ssrf!allowlist_https_scheme)",
        r"169\.254\.169\.254",
    ),
    (
        re.compile(r"\b(?:pytest|unit\s+test|run\s+tests)\b", re.IGNORECASE),
        "require_unit_tests",
        "EXT-TEST(require_unit_tests_before_commit)",
        None,
    ),
    (
        re.compile(r"\btype\s+annotations?\b|type\s+hints?\b|mypy\b", re.IGNORECASE),
        "require_type_hints",
        "EXT-TYPE(require_type_annotations)",
        None,
    ),
]

# Maps positive violation propositions to Stratum A core invariant names
VIOLATION_TO_CORE_MAP: Dict[str, str] = {
    "shell_true": "no_shell_true",
    "eval_exec": "no_eval_exec",
    "hardcoded_secret": "no_hardcoded_secret",
    "sql_fstring": "no_sql_fstring",
    "tls_verify_disabled": "require_tls_verify",
    "force_push_main": "no_force_push_main",
    "ssrf_metadata": "no_ssrf_metadata",
}

NUMERIC_BOUND_LINE_RE = re.compile(
    r"\b(?P<key>http_timeout_sec|timeout|max_agent_steps|max_retries|otp_window_sec)\b"
    r"[^\n<>=!]{0,25}?"
    r"(?P<op><=|>=|<|>|==|=)\s*"
    r"(?P<val>\d+(?:\.\d+)?)\s*(?P<unit>s|sec|seconds|ms|steps|retries)?",
    re.IGNORECASE,
)


def _classify_line_into_rule_or_bound(
    line: str,
    origin_file: str,
    line_no: int,
    rule_seq: int,
    scope: str = "**/*",
) -> Tuple[Optional[ImportedRuleIR], Optional[NumericBoundIR], List[CapabilityFinding]]:
    """Classify a single declarative line into an ImportedRuleIR, NumericBoundIR, and/or CapabilityFindings."""
    stripped = line.strip().lstrip("-*•0123456789.) ").strip()
    if len(stripped) < 6 or stripped.startswith(("```", "---", "<!--")):
        return None, None, []

    caps: List[CapabilityFinding] = []
    lower = stripped.lower()

    # Capability classification (never executed)
    if GOOD_CODE_MALWARE_RE.search(stripped) or re.search(r"\b(?:curl|wget)\b[^\n]*\|\s*(?:ba)?sh\b", stripped, re.I):
        caps.append(
            CapabilityFinding(
                capability_type="shell",
                disposition="elevate_required",
                evidence_summary="Shell pipeline or dynamic execution primitive detected; not mounted in v1.8.0",
                origin_file=origin_file,
                origin_line=line_no,
            )
        )

    # Check numeric bound
    m_num = NUMERIC_BOUND_LINE_RE.search(stripped)
    bound_ir: Optional[NumericBoundIR] = None
    if m_num:
        raw_key = m_num.group("key").lower()
        canonical_key = "http_timeout_sec" if raw_key == "timeout" else raw_key
        raw_op = m_num.group("op")
        if raw_op == "=":
            raw_op = "=="
        raw_val = m_num.group("val")
        unit = (m_num.group("unit") or "sec").lower()
        frac_val = Fraction(raw_val)
        domain = "rational" if "." in raw_val else "int"
        activator: Optional[str] = None
        m_when = re.search(r"\b(?:when|if)\s+([a-z0-9_]+)\b", lower)
        if m_when and m_when.group(1) not in {"timeout", "http", "the", "a"}:
            activator = f"cond_{m_when.group(1)}"
        bound_ir = NumericBoundIR(
            bound_id=f"BND-{rule_seq:03d}",
            key=canonical_key,
            op=raw_op,
            value=frac_val,
            unit=unit,
            domain=domain,
            stratum="B",
            activated_by=activator,
            origin_file=origin_file,
            origin_line=line_no,
        )

    # Determine modality
    is_prefer = bool(re.search(r"\b(?:prefer|recommend|consider|ideally|optionally|tip)\b", lower))
    is_prohibit = bool(
        re.search(r"\b(?:never|forbid|forbidden|prohibit|must\s+not|do\s+not|don't|disallow|ban|avoid)\b", lower)
    )
    is_require = bool(re.search(r"\b(?:always|must|require|required|mandatory|enforce|shall)\b", lower))

    if is_prefer and not is_prohibit and not is_require:
        modality = "prefer"
        stratum = "C"
    elif is_prohibit:
        modality = "prohibit"
        stratum = "B"
    elif is_require:
        modality = "require"
        stratum = "B"
    else:
        modality = "advice"
        stratum = "C"

    # Extract conditional antecedents (e.g., "for pipes", "when pipe_mode", "if streaming")
    conditions: List[str] = []
    if re.search(r"\b(?:for\s+pipes|when\s+using\s+pipes|in\s+pipe\s+mode|when\s+pipe_mode)\b", lower):
        conditions.append("cond_pipe_mode")
    elif re.search(r"\b(?:when\s+require_pipes|assert_pipe_mode)\b", lower):
        conditions.append("cond_pipe_mode")

    # Match against canonical proposition patterns
    for rx, violation_prop, op_token, rgx_guard in DECLARATIVE_PROPOSITION_PATTERNS:
        if rx.search(stripped):
            core_inv = VIOLATION_TO_CORE_MAP.get(violation_prop)
            if core_inv is not None:
                # If the line says "never use shell=True", it agrees with `no_shell_true`
                # If the line says "always use shell=True", it asserts `-no_shell_true`
                mentions_false = "shell=false" in lower or "verify=true" in lower
                if is_prohibit or mentions_false:
                    prop = core_inv
                elif is_require:
                    prop = f"-{core_inv}"
                else:
                    prop = core_inv if not ("shell=true" in lower or "verify=false" in lower) else f"-{core_inv}"
            else:
                prop = f"-{violation_prop}" if is_prohibit else violation_prop

            rid = f"IMP-R{rule_seq:03d}"
            t_status = "exact" if rgx_guard else "conservative"
            safe_neg = stripped.replace("|", "/").replace("«", "").replace("»", "")[:90]
            kml_wire = (
                f"@KML/1|id={rid}|sev={'H' if stratum == 'B' else 'L'}|cat=imported"
                f"|lang=py,js,ts,sh|op={op_token}|guard={'REGEX' if rgx_guard else 'DECLARATIVE'}"
                f"|neg=«{safe_neg}»|pos=«@POS_AST{{{prop}}}»|fp=imp_{rid.lower().replace('-', '_')}"
            )
            return (
                ImportedRuleIR(
                    rule_id=rid,
                    modality=modality,
                    stratum=stratum,
                    scope=scope,
                    conditions=conditions,
                    proposition=prop,
                    raw_text=stripped,
                    origin_file=origin_file,
                    origin_line=line_no,
                    translation_status=t_status,
                    kml_wire=kml_wire if prop and not prop.startswith("-") else None,
                    regex_guard=rgx_guard if prop and not prop.startswith("-") else None,
                ),
                bound_ir,
                caps,
            )

    # Check if the line explicitly asserts requiring pipes ("require pipe_mode" / "always use pipes")
    if is_require and re.search(r"\b(?:require\s+pipes|must\s+use\s+pipes|enable\s+pipe_mode)\b", lower):
        rid = f"IMP-R{rule_seq:03d}"
        return (
            ImportedRuleIR(
                rule_id=rid,
                modality="require",
                stratum="B",
                scope=scope,
                conditions=[],
                proposition="cond_pipe_mode",
                raw_text=stripped,
                origin_file=origin_file,
                origin_line=line_no,
                translation_status="conservative",
                kml_wire=None,
                regex_guard=None,
            ),
            bound_ir,
            caps,
        )

    # Otherwise, if it looks like a bulleted rule, keep it as `opaque` (inactive in residual.md)
    if line.lstrip().startswith(("-", "*", "•")) or is_require or is_prohibit:
        rid = f"IMP-R{rule_seq:03d}"
        return (
            ImportedRuleIR(
                rule_id=rid,
                modality=modality,
                stratum=stratum,
                scope=scope,
                conditions=conditions,
                proposition=f"opaque_rule_{rule_seq:03d}",
                raw_text=stripped,
                origin_file=origin_file,
                origin_line=line_no,
                translation_status="opaque",
                kml_wire=None,
                regex_guard=None,
            ),
            bound_ir,
            caps,
        )

    return None, bound_ir, caps


# ---------------------------------------------------------------------------
# Universal Harness Integrator Engine
# ---------------------------------------------------------------------------

RECOGNIZED_HARNESS_FILENAMES: Dict[str, Tuple[str, str]] = {
    "claude.md": ("claude-md", "1.0"),
    "agents.md": ("agents-md", "1.0"),
    "conventions.md": ("conventions-md", "1.0"),
    "skill.md": ("agent-skill", "1.0"),
    ".cursorrules": ("cursor-rules", "1.0"),
    ".windsurfrules": ("windsurf-rules", "1.0"),
    ".clinerules": ("cline-roo-rules", "1.0"),
    "copilot-instructions.md": ("copilot-instructions", "1.0"),
    ".aider.conf.yml": ("aider-config", "1.0"),
    "settings.json": ("claude-settings", "1.0"),
    "crew.yaml": ("agent-framework-config", "1.0"),
    "agents.yaml": ("agent-framework-config", "1.0"),
    "openhands.json": ("agent-framework-config", "1.0"),
    "autogen.json": ("agent-framework-config", "1.0"),
}


class UniversalHarnessIntegrator:
    """
    Universal Drop-In Harness Integrator & Federation Engine (`v1.8.0`).
    Manages the full lifecycle:
      `discover` -> `ingest_and_analyze` -> `mount_harness` -> `revalidate_all` -> `eject_harness`
    """

    def __init__(self, workspace_root: str | Path = ".") -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.kintsugi_dir = self.workspace_root / ".kintsugi"
        self.quarantine_root = self.kintsugi_dir / "quarantine"
        self.objects_root = self.kintsugi_dir / "objects"
        self.integrated_root = self.kintsugi_dir / "integrated_harnesses"
        self.active_registry_path = self.kintsugi_dir / "active_integrations.json"
        self.waivers_path = self.kintsugi_dir / "integration_waivers.json"

    def _get_signing_key(self) -> Tuple[bytes, str, str]:
        env_key = os.environ.get("KINTSUGI_COMPLIANCE_SIGNING_KEY", "").strip()
        if env_key and len(env_key) >= 16:
            raw = env_key.encode("utf-8")
            kid = hashlib.sha256(b"KINTSUGI_INT_KEY_ID|" + raw).hexdigest()[:16]
            return raw, kid, LABEL_KINTSUGI_ACCEPTED
        seed_path = self.kintsugi_dir / ".compliance_local_seed"
        seed_path.parent.mkdir(parents=True, exist_ok=True)
        if not seed_path.exists():
            seed_path.write_text(hashlib.sha256(os.urandom(32)).hexdigest(), encoding="utf-8")
            try:
                os.chmod(seed_path, 0o600)
            except OSError:
                pass
        raw = seed_path.read_text(encoding="utf-8").strip().encode("utf-8")
        kid = hashlib.sha256(b"KINTSUGI_INT_LOCAL_ID|" + raw).hexdigest()[:16]
        return raw, kid, LABEL_UNSIGNED_THIRD_PARTY

    # ------------------------------------------------------------------
    # 1. Auto-Discovery (`kintsugi integrate scan`)
    # ------------------------------------------------------------------
    def discover_harnesses(self, search_root: Optional[str | Path] = None) -> Dict[str, Any]:
        """
        Recursively scan `search_root` (without following symlinks or escaping root)
        for existing IDE/Agent harnesses, skill packs, and `.zip`/`.tar.gz` bundles.
        """
        root = Path(search_root).resolve() if search_root else self.workspace_root
        skip_dirs = {
            ".git",
            ".hg",
            ".svn",
            "node_modules",
            ".venv",
            "venv",
            "__pycache__",
            "target",
            "dist",
            "build",
            ".kintsugi",
        }
        candidates: List[Dict[str, Any]] = []

        if root.is_file():
            candidates.append(self._describe_candidate_file(root, root.parent))
            return {
                "ok": True,
                "search_root": str(root),
                "candidates_count": len(candidates),
                "candidates": candidates,
                "star_cta": "⭐ If Kintsugi saves your context tokens or catches a rule conflict, please Star: https://github.com/tunguyen1993/kintsugi-harness",
            }

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            cur_dir = Path(dirpath)
            rel_parts = cur_dir.relative_to(root).parts if cur_dir != root else ()
            if len(rel_parts) > MAX_PATH_DEPTH:
                dirnames[:] = []
                continue
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in skip_dirs and not (cur_dir / d).is_symlink()
            ]
            for fname in sorted(filenames):
                fpath = cur_dir / fname
                if fpath.is_symlink():
                    continue
                rel_str = str(fpath.relative_to(root)).replace("\\", "/")
                lower_name = fname.lower()
                is_match = (
                    lower_name in RECOGNIZED_HARNESS_FILENAMES
                    or (lower_name.endswith(".mdc") and ".cursor/rules" in rel_str)
                    or (lower_name.endswith(".md") and ".roo/rules" in rel_str)
                    or (lower_name.endswith(".md") and ".claude/commands" in rel_str)
                    or lower_name.endswith((".zip", ".tar.gz", ".tgz"))
                )
                if is_match:
                    candidates.append(self._describe_candidate_file(fpath, root))

        return {
            "ok": True,
            "search_root": str(root),
            "candidates_count": len(candidates),
            "candidates": candidates,
            "star_cta": "⭐ If Kintsugi saves your context tokens or catches a rule conflict, please Star: https://github.com/tunguyen1993/kintsugi-harness",
        }

    def _describe_candidate_file(self, fpath: Path, base_root: Path) -> Dict[str, Any]:
        lower_name = fpath.name.lower()
        rel_str = str(fpath.relative_to(base_root)).replace("\\", "/") if fpath != base_root else fpath.name
        if lower_name in RECOGNIZED_HARNESS_FILENAMES:
            adapter_id, ver = RECOGNIZED_HARNESS_FILENAMES[lower_name]
        elif lower_name.endswith(".mdc"):
            adapter_id, ver = ("cursor-rules-mdc", "1.0")
        elif ".roo/rules" in rel_str:
            adapter_id, ver = ("cline-roo-rules", "1.0")
        elif lower_name.endswith((".zip", ".tar.gz", ".tgz")):
            adapter_id, ver = ("archive-bundle", "1.0")
        else:
            adapter_id, ver = ("markdown-rules", "1.0")
        size_b = fpath.stat().st_size if fpath.exists() else 0
        return {
            "path": str(fpath),
            "relative_path": rel_str,
            "adapter_id": f"{adapter_id}@{ver}",
            "size_bytes": size_b,
        }

    # ------------------------------------------------------------------
    # 2. Fail-Closed Archive / Directory Reader & 7-Layer Quarantine
    # ------------------------------------------------------------------
    def _load_raw_entries(self, source: Path) -> Tuple[List[Tuple[str, bytes]], str]:
        """
        Read files from a single file, directory, `.zip`, or `.tar.gz`/`.tgz` while enforcing
        streaming size/ratio/depth/collision/symlink invariants. Never executes anything.
        Returns `(entries, raw_container_sha256)`.
        """
        if not source.exists():
            raise FileNotFoundError(f"Harness source not found: {source}")
        if source.is_symlink():
            raise ValueError("INGEST_SYMLINK_SOURCE_FORBIDDEN")

        entries: List[Tuple[str, bytes]] = []
        seen_collision_keys: Set[str] = set()
        total_inflated = 0
        lower_name = source.name.lower()

        if source.is_file() and (lower_name.endswith(".zip") or lower_name.endswith((".tar.gz", ".tgz"))):
            comp_size = source.stat().st_size
            if comp_size > MAX_COMPRESSED_BYTES:
                raise ValueError(f"INGEST_COMPRESSED_SIZE_EXCEEDED: {comp_size} > {MAX_COMPRESSED_BYTES}")
            raw_archive_bytes = source.read_bytes()
            container_sha = hashlib.sha256(raw_archive_bytes).hexdigest()

            if lower_name.endswith(".zip"):
                with zipfile.ZipFile(io.BytesIO(raw_archive_bytes), "r") as zf:
                    infolist = zf.infolist()
                    if len(infolist) > MAX_ARCHIVE_FILES:
                        raise ValueError(f"INGEST_FILE_COUNT_EXCEEDED: {len(infolist)} > {MAX_ARCHIVE_FILES}")
                    for info in infolist:
                        if info.is_dir():
                            continue
                        # Reject encrypted zip entries
                        if info.flag_bits & 0x1:
                            raise ValueError(f"INGEST_ENCRYPTED_ARCHIVE_FORBIDDEN: {info.filename}")
                        # Reject UNIX symlinks or special files inside zip
                        unix_mode = (info.external_attr >> 16) & 0o170000
                        if unix_mode in {stat.S_IFLNK, stat.S_IFIFO, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFSOCK}:
                            raise ValueError(f"INGEST_SYMLINK_OR_SPECIAL_ENTRY_FORBIDDEN: {info.filename}")
                        norm_rel = _validate_relative_member_path(info.filename)
                        ext = Path(norm_rel).suffix.lower()
                        if ext in NESTED_ARCHIVE_SUFFIXES or norm_rel.lower().endswith(".tar.gz"):
                            raise ValueError(f"INGEST_NESTED_ARCHIVE_FORBIDDEN: {norm_rel}")
                        ckey = _canonical_collision_key(norm_rel)
                        if ckey in seen_collision_keys:
                            raise ValueError(f"INGEST_DUPLICATE_NORMALIZED_PATH_COLLISION: {norm_rel}")
                        seen_collision_keys.add(ckey)

                        if info.file_size > MAX_SINGLE_FILE_BYTES:
                            raise ValueError(f"INGEST_SINGLE_FILE_SIZE_EXCEEDED: {norm_rel}")
                        comp_entry = max(info.compress_size, 1)
                        if (info.file_size / comp_entry) > MAX_COMPRESSION_RATIO and info.file_size > 65536:
                            raise ValueError(f"INGEST_ARCHIVE_BOMB_RATIO_EXCEEDED: {norm_rel}")

                        # Stream-read with hard cap
                        with zf.open(info, "r") as fp:
                            data = fp.read(MAX_SINGLE_FILE_BYTES + 1)
                        if len(data) > MAX_SINGLE_FILE_BYTES:
                            raise ValueError(f"INGEST_STREAM_FILE_SIZE_EXCEEDED: {norm_rel}")
                        total_inflated += len(data)
                        if total_inflated > MAX_INFLATED_BYTES:
                            raise ValueError("INGEST_TOTAL_INFLATED_SIZE_EXCEEDED")
                        entries.append((norm_rel, data))
            else:
                with tarfile.open(fileobj=io.BytesIO(raw_archive_bytes), mode="r:gz") as tf:
                    members = tf.getmembers()
                    if len(members) > MAX_ARCHIVE_FILES:
                        raise ValueError(f"INGEST_FILE_COUNT_EXCEEDED: {len(members)} > {MAX_ARCHIVE_FILES}")
                    for m in members:
                        if m.isdir():
                            continue
                        if m.issym() or m.islnk() or m.isdev() or m.isfifo():
                            raise ValueError(f"INGEST_TAR_SYMLINK_OR_DEVICE_FORBIDDEN: {m.name}")
                        norm_rel = _validate_relative_member_path(m.name)
                        ext = Path(norm_rel).suffix.lower()
                        if ext in NESTED_ARCHIVE_SUFFIXES or norm_rel.lower().endswith(".tar.gz"):
                            raise ValueError(f"INGEST_NESTED_ARCHIVE_FORBIDDEN: {norm_rel}")
                        ckey = _canonical_collision_key(norm_rel)
                        if ckey in seen_collision_keys:
                            raise ValueError(f"INGEST_DUPLICATE_NORMALIZED_PATH_COLLISION: {norm_rel}")
                        seen_collision_keys.add(ckey)
                        if m.size > MAX_SINGLE_FILE_BYTES:
                            raise ValueError(f"INGEST_SINGLE_FILE_SIZE_EXCEEDED: {norm_rel}")
                        fobj = tf.extractfile(m)
                        if fobj is None:
                            continue
                        data = fobj.read(MAX_SINGLE_FILE_BYTES + 1)
                        if len(data) > MAX_SINGLE_FILE_BYTES:
                            raise ValueError(f"INGEST_STREAM_FILE_SIZE_EXCEEDED: {norm_rel}")
                        total_inflated += len(data)
                        if total_inflated > MAX_INFLATED_BYTES:
                            raise ValueError("INGEST_TOTAL_INFLATED_SIZE_EXCEEDED")
                        if (total_inflated / max(comp_size, 1)) > MAX_COMPRESSION_RATIO and total_inflated > 65536:
                            raise ValueError(f"INGEST_ARCHIVE_BOMB_RATIO_EXCEEDED: {norm_rel}")
                        entries.append((norm_rel, data))

            return entries, container_sha

        if source.is_file():
            fsize = source.stat().st_size
            if fsize > MAX_SINGLE_FILE_BYTES:
                raise ValueError(f"INGEST_SINGLE_FILE_SIZE_EXCEEDED: {source.name}")
            raw_b = source.read_bytes()
            return [(source.name, raw_b)], hashlib.sha256(raw_b).hexdigest()

        # Directory source
        hasher = hashlib.sha256()
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
            cur = Path(dirpath)
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in {".git", "node_modules", "__pycache__", ".venv", ".kintsugi"}
            ]
            for d in list(dirnames):
                if (cur / d).is_symlink():
                    raise ValueError(f"INGEST_DIRECTORY_SYMLINK_FORBIDDEN: {cur / d}")
            for fname in sorted(filenames):
                fpath = cur / fname
                if fpath.is_symlink():
                    raise ValueError(f"INGEST_FILE_SYMLINK_FORBIDDEN: {fpath}")
                rel_p = str(fpath.relative_to(source)).replace("\\", "/")
                norm_rel = _validate_relative_member_path(rel_p)
                ext = Path(norm_rel).suffix.lower()
                if ext in NESTED_ARCHIVE_SUFFIXES or norm_rel.lower().endswith(".tar.gz"):
                    raise ValueError(f"INGEST_NESTED_ARCHIVE_FORBIDDEN: {norm_rel}")
                ckey = _canonical_collision_key(norm_rel)
                if ckey in seen_collision_keys:
                    raise ValueError(f"INGEST_DUPLICATE_NORMALIZED_PATH_COLLISION: {norm_rel}")
                seen_collision_keys.add(ckey)
                file_count += 1
                if file_count > MAX_ARCHIVE_FILES:
                    raise ValueError(f"INGEST_FILE_COUNT_EXCEEDED: {file_count} > {MAX_ARCHIVE_FILES}")
                fsize = fpath.stat().st_size
                if fsize > MAX_SINGLE_FILE_BYTES:
                    raise ValueError(f"INGEST_SINGLE_FILE_SIZE_EXCEEDED: {norm_rel}")
                data = fpath.read_bytes()
                total_inflated += len(data)
                if total_inflated > MAX_INFLATED_BYTES:
                    raise ValueError("INGEST_TOTAL_INFLATED_SIZE_EXCEEDED")
                hasher.update(norm_rel.encode("utf-8") + b"\x00" + data + b"\x00")
                entries.append((norm_rel, data))

        return entries, hasher.hexdigest()

    # ------------------------------------------------------------------
    # 3. Parse, Quarantine, Redact & Conflict-Check (`ingest_and_analyze`)
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_nested_capabilities(obj: Any, rel_path: str) -> List[CapabilityFinding]:
        found: List[CapabilityFinding] = []
        hook_keys = {
            "hooks", "pretooluse", "posttooluse", "sessionstart",
            "userpromptsubmit", "stop", "subagentstop", "precompact", "notification",
        }
        mcp_keys = {"mcpservers", "mcp_servers", "mcp"}

        def _walk(node: Any) -> None:
            if isinstance(node, dict):
                for k, v in node.items():
                    kl = str(k).lower()
                    if kl in hook_keys and v:
                        found.append(
                            CapabilityFinding(
                                capability_type="hook",
                                disposition="elevate_required",
                                evidence_summary=f"Lifecycle hook key '{k}' declared in config; never mounted in v1.8.0",
                                origin_file=rel_path,
                                origin_line=1,
                            )
                        )
                    elif kl in mcp_keys and v:
                        found.append(
                            CapabilityFinding(
                                capability_type="mcp",
                                disposition="elevate_required",
                                evidence_summary=f"MCP server key '{k}' declared in config; never mounted in v1.8.0",
                                origin_file=rel_path,
                                origin_line=1,
                            )
                        )
                    _walk(v)
            elif isinstance(node, list):
                for item in node:
                    _walk(item)

        _walk(obj)
        return found

    def ingest_and_analyze(
        self,
        source_path: str | Path,
        *,
        harness_id: Optional[str] = None,
        waiver_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Pure-function pipeline up to quarantine storage:
        `acquire -> bound -> quarantine -> inventory -> parse -> classify -> normalize -> propose IR -> check conflicts`
        Never modifies IDE files or mounts rules until `mount_harness` is explicitly called.
        """
        raw_src = Path(source_path)
        if raw_src.is_symlink():
            raise ValueError("INGEST_SYMLINK_SOURCE_FORBIDDEN")
        src = raw_src.resolve()
        entries, raw_container_sha256 = self._load_raw_entries(src)

        clean_stem = re.sub(r"[^a-z0-9-]+", "-", src.stem.lower()).strip("-") or "imported-harness"
        hid = harness_id or f"{clean_stem}-{raw_container_sha256[:8]}"

        rules: List[ImportedRuleIR] = []
        bounds: List[NumericBoundIR] = []
        capabilities: List[CapabilityFinding] = []
        security_findings: List[Dict[str, Any]] = []
        files_inventory: List[Dict[str, Any]] = []
        detected_formats: Set[str] = set()
        secrets_found = False
        secrets_redacted_total = 0
        norm_hasher = hashlib.sha256()
        rule_seq = 1

        quarantine_dir = self.quarantine_root / hid
        if quarantine_dir.exists():
            for old_f in quarantine_dir.rglob("*"):
                if old_f.is_file():
                    try:
                        os.chmod(old_f, 0o600)
                    except OSError:
                        pass
            shutil.rmtree(quarantine_dir, ignore_errors=True)
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        for rel_path, raw_bytes in entries:
            file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            raw_text = raw_bytes.decode("utf-8", errors="replace")

            # Layer 2: Check Trojan Source bidi / zero-width control chars without silently deleting
            if TROJAN_UNICODE_RE.search(raw_text):
                security_findings.append(
                    {
                        "rule_id": "KS-019",
                        "class": "TROJAN_BIDI_OR_ZERO_WIDTH_UNICODE",
                        "severity": "CRITICAL",
                        "file": rel_path,
                    }
                )

            # Layer 3: Check Indirect Prompt Injection / Override Attempts
            if PROMPT_INJECTION_RE.search(raw_text):
                security_findings.append(
                    {
                        "rule_id": "KS-022",
                        "class": "PROMPT_INJECTION_OR_POLICY_OVERRIDE",
                        "severity": "CRITICAL",
                        "file": rel_path,
                    }
                )

            # Layer 6: Detect & Redact contextual high-entropy secrets or DLP tokens before persisting!
            ent_hits = scan_high_entropy_secrets(raw_text)
            m_dlp = OUTBOUND_DLP_SECRET_RE.search(raw_text)
            sanitized_text = redact_high_entropy_secrets(raw_text)
            if m_dlp:
                sanitized_text = OUTBOUND_DLP_SECRET_RE.sub("[REDACTED_DLP_TOKEN]", sanitized_text)
            if ent_hits or m_dlp:
                secrets_found = True
                secrets_redacted_total += len(ent_hits) + (1 if m_dlp else 0)
                capabilities.append(
                    CapabilityFinding(
                        capability_type="secret",
                        disposition="elevate_required",
                        evidence_summary="Redacted secret/DLP literal before persistence (value never stored)",
                        origin_file=rel_path,
                        origin_line=1,
                    )
                )

            norm_text = unicodedata.normalize("NFC", sanitized_text).replace("\r\n", "\n")
            norm_hasher.update(rel_path.encode("utf-8") + b"\x00" + norm_text.encode("utf-8") + b"\x00")

            # Write sanitized read-only (`0o400`) copy into quarantine
            q_file = quarantine_dir / rel_path
            q_file.parent.mkdir(parents=True, exist_ok=True)
            q_file.write_text(norm_text, encoding="utf-8")
            try:
                os.chmod(q_file, 0o400)
            except OSError:
                pass

            # Parse according to format adapter
            lower_base = Path(rel_path).name.lower()
            scope = "**/*"
            if lower_base.endswith(".json"):
                detected_formats.add("json-config")
                parsed_json = parse_json_strict_no_dup_keys(norm_text)
                if isinstance(parsed_json, dict):
                    capabilities.extend(self._scan_nested_capabilities(parsed_json, rel_path))
                    for r_line in parsed_json.get("rules", []):
                        if isinstance(r_line, str):
                            r_ir, b_ir, c_list = _classify_line_into_rule_or_bound(
                                r_line, rel_path, 1, rule_seq, scope
                            )
                            if r_ir:
                                rules.append(r_ir)
                                rule_seq += 1
                            if b_ir:
                                bounds.append(b_ir)
                            capabilities.extend(c_list)
            elif lower_base.endswith((".yml", ".yaml")):
                detected_formats.add("yaml-config")
                parsed_yaml = parse_safe_yaml_subset(norm_text)
                capabilities.extend(self._scan_nested_capabilities(parsed_yaml, rel_path))
                for k, v in parsed_yaml.items():
                    synth_line = f"require {k} = {v}" if not isinstance(v, list) else " ".join(str(x) for x in v)
                    r_ir, b_ir, c_list = _classify_line_into_rule_or_bound(
                        synth_line, rel_path, 1, rule_seq, scope
                    )
                    if r_ir:
                        rules.append(r_ir)
                        rule_seq += 1
                    if b_ir:
                        bounds.append(b_ir)
                    capabilities.extend(c_list)
            else:
                # Markdown / `.cursorrules` / `.mdc` / `.windsurfrules` / `.clinerules`
                if lower_base in RECOGNIZED_HARNESS_FILENAMES:
                    detected_formats.add(RECOGNIZED_HARNESS_FILENAMES[lower_base][0])
                elif lower_base.endswith(".mdc"):
                    detected_formats.add("cursor-rules-mdc")
                else:
                    detected_formats.add("markdown-rules")

                # Extract `.mdc` frontmatter globs if present
                m_globs = re.search(r"^globs:\s*([^\n]+)", norm_text, re.MULTILINE)
                if m_globs:
                    scope = m_globs.group(1).strip().strip("'\"")

                for line_idx, line_str in enumerate(norm_text.splitlines(), start=1):
                    r_ir, b_ir, c_list = _classify_line_into_rule_or_bound(
                        line_str, rel_path, line_idx, rule_seq, scope
                    )
                    if r_ir:
                        rules.append(r_ir)
                        rule_seq += 1
                    if b_ir:
                        bounds.append(b_ir)
                    capabilities.extend(c_list)

            files_inventory.append(
                {
                    "relative_path": rel_path,
                    "raw_sha256": file_sha256,
                    "bytes": len(raw_bytes),
                }
            )

        ir = HarnessIR(
            harness_id=hid,
            title=f"Integrated Harness ({src.name})",
            source_path=str(src),
            adapter_id="universal-harness-adapter",
            adapter_version=INTEGRATOR_VERSION,
            detected_formats=sorted(detected_formats) or ["declarative-text"],
            raw_byte_sha256=raw_container_sha256,
            normalized_sha256=norm_hasher.hexdigest(),
            rules=rules,
            bounds=bounds,
            capabilities=capabilities,
            security_findings=security_findings,
            secrets_found=secrets_found,
            secrets_redacted_count=secrets_redacted_total,
            files_inventoried=files_inventory,
        )

        conflict_report = self.analyze_conflicts_and_strata(ir, waiver_ids=waiver_ids)

        # Determine state machine state
        if security_findings:
            state = STATE_HELD_FOR_REVIEW
            mountable = False
        elif not conflict_report["mountable"]:
            state = STATE_REJECTED
            mountable = False
        else:
            state = STATE_ANALYZED
            mountable = True

        # Honest token & translation accounting (only compiled guards count!)
        compiled_rules = [
            r for r in ir.rules
            if r.translation_status in {"exact", "conservative"}
            and r.kml_wire is not None
            and r.rule_id not in conflict_report["dropped_rule_ids"]
        ]
        opaque_rules = [r for r in ir.rules if r.translation_status == "opaque"]
        total_rules_count = len(ir.rules)
        unsupported_rate_pct = (
            round((len(opaque_rules) / total_rules_count) * 100.0, 2)
            if total_rules_count > 0
            else 0.0
        )
        compiled_prose_tokens = sum(max(1, len(r.raw_text) // 4) for r in compiled_rules)
        compiled_kml_tokens = sum(max(1, len(r.kml_wire or "") // 12) for r in compiled_rules)
        compiled_reduction_pct = (
            round((1.0 - (compiled_kml_tokens / max(1, compiled_prose_tokens))) * 100.0, 2)
            if compiled_rules
            else 0.0
        )

        accounting = {
            "tokenizer": "cl100k_heuristic_4char",
            "total_extracted_rules": total_rules_count,
            "compiled_enforceable_guards": len(compiled_rules),
            "opaque_inactive_rules": len(opaque_rules),
            "dropped_conflicting_rules": len(conflict_report["dropped_rule_ids"]),
            "unsupported_opaque_rate_pct": unsupported_rate_pct,
            "compiled_guards_only_token_reduction_pct": compiled_reduction_pct,
            "uncompiled_spans_excluded_from_savings": True,
        }

        receipt = self._build_attestation_receipt(ir, conflict_report, accounting, state, waiver_ids or [])

        return {
            "ok": mountable,
            "state": state,
            "mountable": mountable,
            "harness_ir": ir.to_dict(),
            "conflict_report": conflict_report,
            "translation_accounting": accounting,
            "attestation_receipt": receipt,
        }

    # ------------------------------------------------------------------
    # 4. 3-Stratum Logic & Joint SAT+DL Conflict Analyzer
    # ------------------------------------------------------------------
    def analyze_conflicts_and_strata(
        self,
        ir: HarnessIR,
        *,
        waiver_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluate `ir` against Stratum A (Hard Core `KS-*` & numeric caps), check internal
        consistency (`SELF_UNSAT`), auto-resolve Stratum C preference collisions, and run
        the Joint Boolean SAT + Exact Semiring Difference-Logic Solver.
        """
        active_waivers = self._load_valid_waivers(ir.raw_byte_sha256, waiver_ids or [])

        # 0. Check if any requested waiver illegally targets Stratum A
        for wid in (waiver_ids or []):
            if wid.startswith("KS-") or wid in STRATUM_A_CORE_INVARIANTS:
                raise PermissionError(f"WAIVER_TARGET_IN_STRATUM_A_FORBIDDEN: {wid}")

        # 1. Check internal self-consistency of the imported pack alone (`SELF_UNSAT`)
        self_clauses: List[Tuple[str, Tuple[str, ...]]] = []
        for r in ir.rules:
            if r.stratum == "B" and r.translation_status != "opaque":
                lits = tuple([*(f"-{c}" if not c.startswith("-") else c[1:] for c in r.conditions), r.proposition])
                self_clauses.append((r.rule_id, lits))
        self_verifier = JointSATDifferenceVerifier()
        self_check = self_verifier.verify_joint(self_clauses, ir.bounds)
        if not self_check["satisfiable"]:
            return {
                "verdict": "SELF_UNSAT",
                "solver_status": "UNSAT",
                "mountable": False,
                "failure_domain": self_check.get("failure_domain", "SELF_CONFLICT"),
                "inclusion_minimal_mus": self_check.get("inclusion_minimal_mus", []),
                "conflict_bound_ids": self_check.get("conflict_bound_ids", []),
                "unconditional_core_conflicts": [],
                "stratum_c_auto_dropped": [],
                "blocked_scenarios": [],
                "dropped_rule_ids": [r.rule_id for r in ir.rules],
            }

        # 2. Build Stratum A Core Unit Clauses & Bounds
        core_clauses: List[Tuple[str, Tuple[str, ...]]] = []
        for prop_name, (ks_id, _desc) in STRATUM_A_CORE_INVARIANTS.items():
            core_clauses.append((f"CORE_{ks_id}_{prop_name}", (prop_name,)))

        core_bounds: List[NumericBoundIR] = []
        for b_key, (b_op, b_val, b_dom) in STRATUM_A_NUMERIC_BOUNDS.items():
            core_bounds.append(
                NumericBoundIR(
                    bound_id=f"CORE_BND_{b_key}",
                    key=b_key,
                    op=b_op,
                    value=b_val,
                    unit="sec",
                    domain=b_dom,
                    stratum="A",
                )
            )

        unconditional_core_conflicts: List[Dict[str, Any]] = []
        stratum_c_auto_dropped: List[str] = []
        dropped_rule_ids: Set[str] = set()
        kept_clauses: List[Tuple[str, Tuple[str, ...]]] = list(core_clauses)
        conditional_implications: List[Tuple[str, List[str], str]] = []

        non_opaque_rules = [r for r in ir.rules if r.translation_status != "opaque"]
        sole_effect_negates_core = bool(non_opaque_rules) and all(
            r.proposition.startswith("-") and r.proposition[1:] in STRATUM_A_CORE_INVARIANTS
            for r in non_opaque_rules
        )

        # Pass 2a: Process Stratum B (hard imported rules) first
        for r in non_opaque_rules:
            if r.stratum == "C":
                continue
            if r.rule_id in active_waivers and r.stratum != "A":
                dropped_rule_ids.add(r.rule_id)
                continue

            lits = tuple([*(f"-{c}" if not c.startswith("-") else c[1:] for c in r.conditions), r.proposition])
            candidate_clause = (r.rule_id, lits)

            # Check if this single unconditional Stratum B rule directly contradicts Stratum A
            if not r.conditions and r.proposition.startswith("-") and r.proposition[1:] in STRATUM_A_CORE_INVARIANTS:
                ks_id, _ks_desc = STRATUM_A_CORE_INVARIANTS[r.proposition[1:]]
                probe = _build_dpll_solver([*core_clauses, candidate_clause])
                probe_res = probe.solve()
                unconditional_core_conflicts.append(
                    {
                        "rule_id": r.rule_id,
                        "contradicted_core_scar": ks_id,
                        "core_proposition": r.proposition[1:],
                        "imported_proposition": r.proposition,
                        "resolution": "CORE_KEPT_OVERRIDE_DROPPED",
                        "inclusion_minimal_mus": probe_res.get("unsat_core", []),
                    }
                )
                dropped_rule_ids.add(r.rule_id)
                continue

            kept_clauses.append(candidate_clause)
            if r.conditions:
                conditional_implications.append((r.rule_id, r.conditions, r.proposition))

        # Pass 2b: Process Stratum C (`prefer` / `advice`) — never overrides Stratum A or Stratum B!
        for r in non_opaque_rules:
            if r.stratum != "C":
                continue
            if r.rule_id in active_waivers:
                dropped_rule_ids.add(r.rule_id)
                continue
            if r.proposition.startswith("-") and r.proposition[1:] in STRATUM_A_CORE_INVARIANTS:
                stratum_c_auto_dropped.append(r.rule_id)
                dropped_rule_ids.add(r.rule_id)
                continue
            lits = tuple([*(f"-{c}" if not c.startswith("-") else c[1:] for c in r.conditions), r.proposition])
            candidate_c = (r.rule_id, lits)
            probe_c = self_verifier.verify_joint(
                [*kept_clauses, candidate_c],
                [*core_bounds, *ir.bounds],
            )
            if not probe_c["satisfiable"]:
                stratum_c_auto_dropped.append(r.rule_id)
                dropped_rule_ids.add(r.rule_id)
                continue
            kept_clauses.append(candidate_c)
            if r.conditions:
                conditional_implications.append((r.rule_id, r.conditions, r.proposition))

        # 3. Run Joint SAT + Exact Semiring Difference-Logic Solver on kept clauses + all bounds
        joint_res = self_verifier.verify_joint(
            kept_clauses,
            [*core_bounds, *ir.bounds],
            conditional_implications=conditional_implications,
        )

        if sole_effect_negates_core and not ir.bounds:
            return {
                "verdict": "SOLE_EFFECT_NEGATES_STRATUM_A",
                "solver_status": "UNSAT",
                "mountable": False,
                "failure_domain": "STRATUM_A_OVERRIDE_ONLY",
                "inclusion_minimal_mus": (
                    unconditional_core_conflicts[0]["inclusion_minimal_mus"]
                    if unconditional_core_conflicts
                    else []
                ),
                "conflict_bound_ids": [],
                "unconditional_core_conflicts": unconditional_core_conflicts,
                "stratum_c_auto_dropped": stratum_c_auto_dropped,
                "blocked_scenarios": [],
                "dropped_rule_ids": sorted(dropped_rule_ids),
            }

        if not joint_res["satisfiable"]:
            return {
                "verdict": "JOINT_CONFLICT_UNSAT",
                "solver_status": joint_res["status"],
                "mountable": False,
                "failure_domain": joint_res.get("failure_domain", "JOINT_SAT_DL"),
                "inclusion_minimal_mus": joint_res.get("inclusion_minimal_mus", []),
                "conflict_bound_ids": joint_res.get("conflict_bound_ids", []),
                "unconditional_core_conflicts": unconditional_core_conflicts,
                "stratum_c_auto_dropped": stratum_c_auto_dropped,
                "blocked_scenarios": [],
                "dropped_rule_ids": sorted(dropped_rule_ids),
            }

        verdict = "CONDITIONAL_BLOCKED_SCENARIO" if joint_res["blocked_scenarios"] else "COMPATIBLE_SAT"
        return {
            "verdict": verdict,
            "solver_status": "SAT",
            "mountable": True,
            "boolean_model": joint_res.get("boolean_model", {}),
            "numeric_model": joint_res.get("numeric_model", {}),
            "inclusion_minimal_mus": [],
            "conflict_bound_ids": [],
            "unconditional_core_conflicts": unconditional_core_conflicts,
            "stratum_c_auto_dropped": stratum_c_auto_dropped,
            "blocked_scenarios": joint_res["blocked_scenarios"],
            "dropped_rule_ids": sorted(dropped_rule_ids),
        }

    # ------------------------------------------------------------------
    # 5. Expiring Hash-Bound Waivers (Stratum B Only; Stratum A Forbidden)
    # ------------------------------------------------------------------
    def create_waiver(
        self,
        *,
        target_rule_id: str,
        pack_raw_sha256: str,
        reason: str,
        ttl_seconds: int = 86400 * 7,
    ) -> Dict[str, Any]:
        """Create an expiring waiver bound to `pack_raw_sha256` for a Stratum B rule (rejects Stratum A)."""
        if (
            target_rule_id.startswith(("KS-", "CORE_"))
            or target_rule_id in STRATUM_A_CORE_INVARIANTS
        ):
            raise PermissionError(f"WAIVER_TARGET_IN_STRATUM_A_FORBIDDEN: {target_rule_id}")
        now = int(time.time())
        waiver = {
            "waiver_id": f"WVR-{hashlib.sha256(f'{target_rule_id}|{pack_raw_sha256}|{now}'.encode()).hexdigest()[:10].upper()}",
            "target_rule_id": target_rule_id,
            "pack_raw_sha256": pack_raw_sha256,
            "reason": reason,
            "created_at_unix": now,
            "expires_at_unix": now + max(60, ttl_seconds),
        }
        all_waivers = self._read_waivers_file()
        all_waivers[waiver["waiver_id"]] = waiver
        self.waivers_path.parent.mkdir(parents=True, exist_ok=True)
        self.waivers_path.write_text(json.dumps(all_waivers, indent=2) + "\n", encoding="utf-8")
        return waiver

    def _read_waivers_file(self) -> Dict[str, Dict[str, Any]]:
        if not self.waivers_path.exists():
            return {}
        try:
            return json.loads(self.waivers_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _load_valid_waivers(self, pack_raw_sha256: str, requested_ids: Sequence[str]) -> Set[str]:
        all_w = self._read_waivers_file()
        now = int(time.time())
        waived_rules: Set[str] = set()
        for wid in requested_ids:
            w = all_w.get(wid)
            if not w:
                continue
            if w.get("pack_raw_sha256") != pack_raw_sha256:
                continue
            if int(w.get("expires_at_unix", 0)) < now:
                continue
            target = str(w.get("target_rule_id", ""))
            if target.startswith(("KS-", "CORE_")) or target in STRATUM_A_CORE_INVARIANTS:
                raise PermissionError(f"WAIVER_TARGET_IN_STRATUM_A_FORBIDDEN: {target}")
            waived_rules.add(target)
        return waived_rules

    # ------------------------------------------------------------------
    # 6. Domain-Separated Length-Delimited `@PROOF_DAG/1` Receipt
    # ------------------------------------------------------------------
    @staticmethod
    def _canonical_length_delimited_bytes(fields: Sequence[Tuple[str, Any]]) -> bytes:
        """Domain-separated, length-delimited canonical encoding immune to field-concatenation ambiguity."""
        parts: List[bytes] = [b"KINTSUGI_HARNESS_INTEGRATION_RECEIPT_V180\x00"]
        for key, val in fields:
            k_bytes = key.encode("utf-8")
            v_str = json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            v_bytes = v_str.encode("utf-8")
            parts.append(f"{len(k_bytes)}:".encode("ascii") + k_bytes + f"={len(v_bytes)}:".encode("ascii") + v_bytes + b"\n")
        return b"".join(parts)

    def _build_attestation_receipt(
        self,
        ir: HarnessIR,
        conflict_report: Dict[str, Any],
        accounting: Dict[str, Any],
        state: str,
        waiver_ids: List[str],
    ) -> Dict[str, Any]:
        signing_key, key_id, provenance_label = self._get_signing_key()
        ir_digest = hashlib.sha256(
            json.dumps(ir.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        subject_fields: List[Tuple[str, Any]] = [
            ("harness_id", ir.harness_id),
            ("raw_byte_sha256", ir.raw_byte_sha256),
            ("normalized_sha256", ir.normalized_sha256),
            ("ir_sha256", ir_digest),
            ("extractor_policy_version", EXTRACTOR_POLICY_VERSION),
            ("adapter_id", f"{ir.adapter_id}@{ir.adapter_version}"),
            ("scanner_version", SCANNER_POLICY_VERSION),
            ("solver_version", SOLVER_VERSION),
            ("state", state),
            ("solver_status", conflict_report["solver_status"]),
            ("verdict", conflict_report["verdict"]),
            ("certificate_mus", conflict_report.get("inclusion_minimal_mus", [])),
            ("certificate_dl_conflict", conflict_report.get("conflict_bound_ids", [])),
            ("waiver_ids", sorted(waiver_ids)),
            ("capabilities_granted", []),
            ("provenance_label", provenance_label),
            ("compiled_guards_count", accounting["compiled_enforceable_guards"]),
        ]
        canonical_payload = self._canonical_length_delimited_bytes(subject_fields)
        payload_sha256 = hashlib.sha256(canonical_payload).hexdigest()
        mac_hex = hmac.new(signing_key, canonical_payload, hashlib.sha256).hexdigest()

        wire = (
            f"@PROOF_DAG/1[profile=HARNESS_INTEGRATION_V180|id={ir.harness_id}"
            f"|state={state}|verdict={conflict_report['verdict']}"
            f"|label={provenance_label}|guards={accounting['compiled_enforceable_guards']}"
            f"|caps_granted=0|sha={payload_sha256[:12]}]"
        )
        return {
            "schema": "KintsugiIntegrationReceipt/1.8.0",
            "profile": "in-toto-dsse-compatible/@PROOF_DAG/1",
            "harness_id": ir.harness_id,
            "state": state,
            "verdict": conflict_report["verdict"],
            "provenance_label": provenance_label,
            "key_id": key_id,
            "raw_byte_sha256": ir.raw_byte_sha256,
            "normalized_sha256": ir.normalized_sha256,
            "ir_sha256": ir_digest,
            "extractor_policy_version": EXTRACTOR_POLICY_VERSION,
            "adapter_id": f"{ir.adapter_id}@{ir.adapter_version}",
            "scanner_version": SCANNER_POLICY_VERSION,
            "solver_version": SOLVER_VERSION,
            "solver_status": conflict_report["solver_status"],
            "certificate_mus": conflict_report.get("inclusion_minimal_mus", []),
            "certificate_dl_conflict": conflict_report.get("conflict_bound_ids", []),
            "waiver_ids": sorted(waiver_ids),
            "capabilities_granted": [],
            "compiled_guards_count": accounting["compiled_enforceable_guards"],
            "payload_sha256": payload_sha256,
            "hmac_sha256": mac_hex,
            "wire": wire,
        }

    def verify_attestation_receipt(
        self,
        receipt: Dict[str, Any],
        *,
        revoked_key_ids: Optional[Set[str]] = None,
        expected_raw_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify a `@PROOF_DAG/1` integration receipt against tampering, subject swap, or key revocation."""
        signing_key, active_key_id, expected_label = self._get_signing_key()
        if receipt.get("schema") != "KintsugiIntegrationReceipt/1.8.0":
            return {"ok": False, "reason": "RECEIPT_INVALID_SCHEMA"}
        if receipt.get("profile") != "in-toto-dsse-compatible/@PROOF_DAG/1":
            return {"ok": False, "reason": "RECEIPT_INVALID_PROFILE"}
        if receipt.get("capabilities_granted") != []:
            return {"ok": False, "reason": "RECEIPT_CAPABILITIES_GRANTED_MUST_BE_EMPTY"}
        if receipt.get("provenance_label") != expected_label:
            return {"ok": False, "reason": "RECEIPT_PROVENANCE_LABEL_MISMATCH"}
        r_key_id = str(receipt.get("key_id", ""))
        if revoked_key_ids and r_key_id in revoked_key_ids:
            return {"ok": False, "reason": "RECEIPT_KEY_REVOKED"}
        if r_key_id != active_key_id:
            return {"ok": False, "reason": "RECEIPT_UNTRUSTED_KEY_ID"}
        if expected_raw_sha256 and receipt.get("raw_byte_sha256") != expected_raw_sha256:
            return {"ok": False, "reason": "RECEIPT_SUBJECT_HASH_MISMATCH"}

        subject_fields: List[Tuple[str, Any]] = [
            ("harness_id", receipt.get("harness_id")),
            ("raw_byte_sha256", receipt.get("raw_byte_sha256")),
            ("normalized_sha256", receipt.get("normalized_sha256")),
            ("ir_sha256", receipt.get("ir_sha256")),
            ("extractor_policy_version", receipt.get("extractor_policy_version")),
            ("adapter_id", receipt.get("adapter_id")),
            ("scanner_version", receipt.get("scanner_version")),
            ("solver_version", receipt.get("solver_version")),
            ("state", receipt.get("state")),
            ("solver_status", receipt.get("solver_status")),
            ("verdict", receipt.get("verdict")),
            ("certificate_mus", receipt.get("certificate_mus", [])),
            ("certificate_dl_conflict", receipt.get("certificate_dl_conflict", [])),
            ("waiver_ids", receipt.get("waiver_ids", [])),
            ("capabilities_granted", receipt.get("capabilities_granted", [])),
            ("provenance_label", receipt.get("provenance_label")),
            ("compiled_guards_count", receipt.get("compiled_guards_count")),
        ]
        canonical_payload = self._canonical_length_delimited_bytes(subject_fields)
        recomputed_sha = hashlib.sha256(canonical_payload).hexdigest()
        if recomputed_sha != receipt.get("payload_sha256"):
            return {"ok": False, "reason": "RECEIPT_PAYLOAD_SHA256_MISMATCH"}
        recomputed_mac = hmac.new(signing_key, canonical_payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(recomputed_mac, str(receipt.get("hmac_sha256", ""))):
            return {"ok": False, "reason": "RECEIPT_HMAC_SIGNATURE_MISMATCH"}
        return {
            "ok": True,
            "status": "RECEIPT_VERIFIED_PASS_100%",
            "provenance_label": receipt.get("provenance_label"),
            "payload_sha256": recomputed_sha,
        }

    # ------------------------------------------------------------------
    # 7. Mount Compiled Declarative Guards & Reversible `--eject`
    # ------------------------------------------------------------------
    def mount_harness(
        self,
        source_path: str | Path,
        *,
        harness_id: Optional[str] = None,
        waiver_ids: Optional[List[str]] = None,
        sync_ide_targets: bool = True,
    ) -> Dict[str, Any]:
        """
        Ingest, analyze, and mount ONLY compiled declarative guards into
        `.kintsugi/integrated_harnesses/<id>/` and bounded sections in `AGENTS.md`/`CLAUDE.md`.
        Enforces commercial tier quota (`FREE_STARTER` = 1 mounted harness; Pro/Enterprise = multi-pack federation).
        Never mounts or executes hooks or MCP servers.
        """
        analysis = self.ingest_and_analyze(source_path, harness_id=harness_id, waiver_ids=waiver_ids)
        if not analysis["mountable"]:
            return analysis

        ir_dict = analysis["harness_ir"]
        hid = ir_dict["harness_id"]

        # Check commercial tier entitlement for multi-harness federation
        active_reg = self._load_active_registry()
        already_mounted = [k for k in active_reg.get("mounted_harnesses", {}) if k != hid]
        max_allowed = self._resolve_max_mounted_harnesses()
        if len(already_mounted) >= max_allowed:
            return {
                "ok": False,
                "state": STATE_HELD_FOR_REVIEW,
                "mountable": False,
                "reason": (
                    f"TIER_FEDERATION_LIMIT_REACHED: Active tier allows {max_allowed} mounted third-party harness "
                    f"(currently mounted: {already_mounted}). Upgrade to Kintsugi Pro ($15/$19) or Enterprise ($29) "
                    f"to unlock multi-harness federation."
                ),
                "harness_id": hid,
            }

        target_dir = self.integrated_root / hid
        target_dir.mkdir(parents=True, exist_ok=True)

        dropped_ids = set(analysis["conflict_report"]["dropped_rule_ids"])
        compiled_kml_lines: List[str] = [
            f"# @KML/1.0|schema=KINTSUGI_INTEGRATED_HARNESS|id={hid}|prose=0"
        ]
        residual_lines: List[str] = [
            f"# Residual Inactive Rules for `{hid}` (Not Compiled / Not Executed)",
            "",
        ]
        for r in ir_dict["rules"]:
            if r["rule_id"] in dropped_ids:
                continue
            if r["translation_status"] in {"exact", "conservative"} and r.get("kml_wire"):
                compiled_kml_lines.append(r["kml_wire"])
            else:
                residual_lines.append(f"- `{r['rule_id']}` ({r['origin_file']}:{r['origin_line']}): {r['raw_text']}")

        (target_dir / "compiled.kml").write_text("\n".join(compiled_kml_lines) + "\n", encoding="utf-8")
        (target_dir / "residual.md").write_text("\n".join(residual_lines) + "\n", encoding="utf-8")
        (target_dir / "conflict_report.json").write_text(
            json.dumps(analysis["conflict_report"], indent=2) + "\n", encoding="utf-8"
        )

        # Update receipt state to MOUNTED
        ir_obj = self._reconstruct_ir_from_dict(ir_dict)
        mounted_receipt = self._build_attestation_receipt(
            ir_obj,
            analysis["conflict_report"],
            analysis["translation_accounting"],
            STATE_MOUNTED,
            waiver_ids or [],
        )
        (target_dir / "receipt.proof").write_text(
            json.dumps(mounted_receipt, indent=2) + "\n", encoding="utf-8"
        )
        (target_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "harness_id": hid,
                    "state": STATE_MOUNTED,
                    "scanner_version": SCANNER_POLICY_VERSION,
                    "harness_ir": ir_dict,
                    "translation_accounting": analysis["translation_accounting"],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        # Update atomic active registry
        active_reg.setdefault("mounted_harnesses", {})[hid] = {
            "harness_id": hid,
            "source_path": ir_dict["source_path"],
            "raw_byte_sha256": ir_dict["raw_byte_sha256"],
            "scanner_version": SCANNER_POLICY_VERSION,
            "compiled_guards_count": analysis["translation_accounting"]["compiled_enforceable_guards"],
            "mounted_at_unix": int(time.time()),
            "state": STATE_MOUNTED,
        }
        self._save_active_registry(active_reg)

        if sync_ide_targets:
            self._upsert_ide_bounded_block(hid, compiled_kml_lines[1:])

        analysis["ok"] = True
        analysis["state"] = STATE_MOUNTED
        analysis["attestation_receipt"] = mounted_receipt
        return analysis

    def eject_harness(self, harness_id: str) -> Dict[str, Any]:
        """
        Cleanly eject a mounted harness (`--eject`), removing its bounded Kintsugi block
        from `AGENTS.md`/`CLAUDE.md` while preserving 100% of user-authored content and edits!
        """
        self._remove_ide_bounded_block(harness_id)
        target_dir = self.integrated_root / harness_id
        removed_files = False
        if target_dir.exists():
            shutil.rmtree(target_dir, ignore_errors=True)
            removed_files = True

        active_reg = self._load_active_registry()
        was_active = harness_id in active_reg.get("mounted_harnesses", {})
        active_reg.get("mounted_harnesses", {}).pop(harness_id, None)
        self._save_active_registry(active_reg)

        return {
            "ok": True,
            "harness_id": harness_id,
            "state": STATE_REVOKED,
            "removed_mount_dir": removed_files,
            "removed_from_active_registry": was_active,
            "user_edits_preserved": True,
        }

    def revalidate_mounted_on_scanner_upgrade(
        self,
        new_scanner_version: str,
        custom_Forbidden_regex: Optional[re.Pattern[str]] = None,
    ) -> Dict[str, Any]:
        """
        Invariant 8: When upgrading from Scanner N to Scanner N+1, re-scan all mounted
        quarantined packs; if a newly added detector fires, automatically transition the
        pack from `MOUNTED` to `HELD_FOR_REVIEW` and unmount its active guards!
        """
        active_reg = self._load_active_registry()
        held_ids: List[str] = []
        verified_ids: List[str] = []

        for hid, meta in list(active_reg.get("mounted_harnesses", {}).items()):
            q_dir = self.quarantine_root / hid
            fired = False
            if q_dir.exists():
                for qf in q_dir.rglob("*"):
                    if qf.is_file():
                        txt = qf.read_text(encoding="utf-8", errors="replace")
                        if (
                            TROJAN_UNICODE_RE.search(txt)
                            or PROMPT_INJECTION_RE.search(txt)
                            or (custom_Forbidden_regex is not None and custom_Forbidden_regex.search(txt))
                        ):
                            fired = True
                            break
            if fired:
                held_ids.append(hid)
                self._remove_ide_bounded_block(hid)
                meta["state"] = STATE_HELD_FOR_REVIEW
                meta["reheld_by_scanner_version"] = new_scanner_version
                active_reg["mounted_harnesses"].pop(hid, None)
                t_dir = self.integrated_root / hid
                m_path = t_dir / "manifest.json"
                if m_path.exists():
                    try:
                        m_obj = json.loads(m_path.read_text(encoding="utf-8"))
                        m_obj["state"] = STATE_HELD_FOR_REVIEW
                        m_obj["reheld_by_scanner_version"] = new_scanner_version
                        m_path.write_text(json.dumps(m_obj, indent=2) + "\n", encoding="utf-8")
                    except Exception:
                        pass
            else:
                meta["scanner_version"] = new_scanner_version
                verified_ids.append(hid)

        self._save_active_registry(active_reg)
        return {
            "ok": True,
            "new_scanner_version": new_scanner_version,
            "reheld_harnesses": held_ids,
            "verified_harnesses": verified_ids,
        }

    def list_integrated_harnesses(self) -> Dict[str, Any]:
        reg = self._load_active_registry()
        mounted = reg.get("mounted_harnesses", {})
        return {
            "ok": True,
            "integrator_version": INTEGRATOR_VERSION,
            "max_mounted_harnesses_entitlement": self._resolve_max_mounted_harnesses(),
            "mounted_count": len(mounted),
            "mounted_harnesses": list(mounted.values()),
        }

    def _resolve_max_mounted_harnesses(self) -> int:
        try:
            from kintsugi.packs import resolve_workspace_co_execution_entitlement

            ent = resolve_workspace_co_execution_entitlement(self.workspace_root)
            tier = ent.get("co_execution_tier", "FREE_STARTER")
            if tier == "ENTERPRISE_PAID_COUNCIL":
                return 100
            if tier == "PRO_MULTI_FREE":
                return 10
        except Exception:
            pass
        return 1

    def _load_active_registry(self) -> Dict[str, Any]:
        if not self.active_registry_path.exists():
            return {"schema": "ActiveIntegrations/1.8.0", "mounted_harnesses": {}}
        try:
            return json.loads(self.active_registry_path.read_text(encoding="utf-8"))
        except Exception:
            return {"schema": "ActiveIntegrations/1.8.0", "mounted_harnesses": {}}

    def _save_active_registry(self, reg: Dict[str, Any]) -> None:
        self.active_registry_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.active_registry_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(reg, indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(self.active_registry_path)

    def _upsert_ide_bounded_block(self, harness_id: str, kml_lines: List[str]) -> None:
        start_tag = f"<!-- KINTSUGI:INTEGRATED:{harness_id}:START -->"
        end_tag = f"<!-- KINTSUGI:INTEGRATED:{harness_id}:END -->"
        body_lines = [
            start_tag,
            f"### Integrated Third-Party Harness: `{harness_id}` (`@HARNESS_BRIDGE/1`)",
            "```text",
            *(kml_lines or ["# (0 enforceable guards compiled; see .kintsugi/integrated_harnesses/ residual.md)"]),
            "```",
            end_tag,
        ]
        block = "\n".join(body_lines)
        target_doc = self.workspace_root / "AGENTS.md"
        existing = target_doc.read_text(encoding="utf-8") if target_doc.exists() else ""
        pattern = re.compile(rf"{re.escape(start_tag)}[\s\S]*?{re.escape(end_tag)}", re.MULTILINE)
        if pattern.search(existing):
            updated = pattern.sub(lambda _: block, existing, count=1)
        elif existing.strip():
            updated = existing.rstrip("\n") + "\n\n" + block + "\n"
        else:
            updated = block + "\n"
        target_doc.write_text(updated, encoding="utf-8")

    def _remove_ide_bounded_block(self, harness_id: str) -> None:
        start_tag = f"<!-- KINTSUGI:INTEGRATED:{harness_id}:START -->"
        end_tag = f"<!-- KINTSUGI:INTEGRATED:{harness_id}:END -->"
        target_doc = self.workspace_root / "AGENTS.md"
        if not target_doc.exists():
            return
        existing = target_doc.read_text(encoding="utf-8")
        pattern = re.compile(rf"\n?{re.escape(start_tag)}[\s\S]*?{re.escape(end_tag)}\n?", re.MULTILINE)
        updated = pattern.sub("\n", existing)
        target_doc.write_text(updated, encoding="utf-8")

    @staticmethod
    def _reconstruct_ir_from_dict(d: Dict[str, Any]) -> HarnessIR:
        return HarnessIR(
            harness_id=d["harness_id"],
            title=d["title"],
            source_path=d["source_path"],
            adapter_id=d["adapter_id"],
            adapter_version=d["adapter_version"],
            detected_formats=d["detected_formats"],
            raw_byte_sha256=d["raw_byte_sha256"],
            normalized_sha256=d["normalized_sha256"],
            rules=[ImportedRuleIR(**r) for r in d.get("rules", [])],
            bounds=[
                NumericBoundIR(
                    bound_id=b["bound_id"],
                    key=b["key"],
                    op=b["op"],
                    value=Fraction(b["value"]),
                    unit=b["unit"],
                    domain=b["domain"],
                    stratum=b["stratum"],
                    activated_by=b.get("activated_by"),
                    origin_file=b.get("origin_file", ""),
                    origin_line=b.get("origin_line", 0),
                )
                for b in d.get("bounds", [])
            ],
            capabilities=[CapabilityFinding(**c) for c in d.get("capabilities", [])],
            security_findings=d.get("security_findings", []),
            secrets_found=d.get("secrets_found", False),
            secrets_redacted_count=d.get("secrets_redacted_count", 0),
            files_inventoried=d.get("files_inventoried", []),
        )


def discover_harnesses(search_root: Optional[Path | str] = None) -> Dict[str, Any]:
    """Top-level helper to discover recognizable third-party harnesses in `search_root`."""
    root = Path(search_root or ".").resolve()
    return UniversalHarnessIntegrator(root).discover_harnesses(root)
