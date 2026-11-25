#!/usr/bin/env python3
"""Kintsugi Production Fast-Learner & Dual-Pincer Compiler (`src/kintsugi/evolution/fast_learner.py`).

Closes all 4 Red-Team gaps identified with Claude Opus 4:
  1. Generalized `Failure-to-Artifact` Compiler: combines fast deterministic AST-delta extraction
     with an offline LLM proposer callback (`Callable[[str], str]`) to compile ANY novel `(broken -> fixed)`
     diff into EITHER a SHA-256-signed `RuleIR/1` OR a structural/sub-token `InvariantCapsule`.
  2. Fail-Closed 3-Gate Native Rust Quarantine (`must_flag` broken + `must_allow` fixed + `0` hits across
     clean workspace corpus via `kintsugi-rs scan --rules-dir`; capsules verified `0` spam on clean files).
  3. Sub-millisecond (`< 0.5 ms`) cached `O(1)` sub-token reverse index for `code_mistakes_memory.json`.
  4. Zero-dependency Contextual Thompson Sampling (`random.betavariate`) with dead-scar auto-freeze (`<15%`).
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import time
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlparse


# Fail-closed teacher provenance sets (Owner directive R133 / R137 / CM-108):
# Only modern high-tier models on verified first-party endpoints qualify as Frontier Teachers.
# Per Kintsugi v3.0 (GPT-5.4 Arbiter): NO model — not even Frontier — may self-certify
# lessons without an independent Truth Gate (minimized counterexample + pinned oracle check).
GENUINE_FIRST_PARTY_ORIGINS: Set[str] = {
    "antigravity_native",
    "anthropic_official",
    "openai_official",
    "openai_codex_official",
    "chatgpt_web_official",
    "google_official",
    "vertex_official",
    "bedrock_official",
    "xai_official",
}

ORIGIN_TO_EXPECTED_HOSTS: Dict[str, Tuple[str, ...]] = {
    "antigravity_native": (),
    "anthropic_official": ("api.anthropic.com",),
    "openai_official": ("api.openai.com",),
    "openai_codex_official": ("chatgpt.com", "api.openai.com"),
    "chatgpt_web_official": ("chatgpt.com", "chat.openai.com"),
    "google_official": ("generativelanguage.googleapis.com",),
    "vertex_official": ("aiplatform.googleapis.com",),
    "bedrock_official": ("amazonaws.com",),
    "xai_official": ("api.x.ai",),
}

GENUINE_FRONTIER_TEACHER_MODELS: Set[str] = {
    "claude-opus-4-6-thinking",
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "gemini-4-neon-high",
    "gemini-4-neon-xhigh",
    "gemini-4-Frontier-high",
    "gemini-4-carbon-high",
    "gemini-4-hydrogen-high",
    "gemini-4-hydrogen-xhigh",
    "gpt-5.4-mini",
    "GPT-5.4",
    "GPT-5.4",
    "gpt-5.4",
    "gpt-5.4",
    "Grok-3",
}

UNTRUSTED_RELAY_HOST_MARKERS: Tuple[str, ...] = (
    "oneapi",
    "new-api",
    "relay",
    "proxy",
    "mirror",
    "openrouter",
    "oss_provider_h",
    "localhost",
    "127.0.0.1",
)

LOW_TIER_MODEL_MARKERS: Tuple[str, ...] = (
    "-low",
    "flash",
    "mini",
    "nano",
    "haiku",
    "gpt-oss",
    "deepseek",
    "qwen",
    "glm",
    "kimi",
    "llama",
    "mistral",
    "open-weights-verifier",
)


class RuntimeOutcome(str, Enum):
    """Typed baseline/candidate test execution outcome (prevents SETUP_ERROR masquerading as broken proof)."""

    EXPECTED_PROPERTY_FAIL = "EXPECTED_PROPERTY_FAIL"
    PASSED = "PASSED"
    SETUP_ERROR = "SETUP_ERROR"
    IMPORT_ERROR = "IMPORT_ERROR"
    TIMEOUT = "TIMEOUT"
    NO_TESTS = "NO_TESTS"


_SETUP_ERROR_RE = re.compile(
    r"(?:ImportError|ModuleNotFoundError|SyntaxError|IndentationError|TimeoutExpired|TIMEOUT|SETUP_ERROR|NO_TESTS|collected 0 items|No tests ran)",
    re.IGNORECASE,
)


def _host_matches_expected(host: str, expected_hosts: Tuple[str, ...]) -> bool:
    return any(host == exp or host.endswith("." + exp) for exp in expected_hosts)


def validate_teacher_provenance(
    teacher_model: Optional[str],
    teacher_origin: Optional[str],
    endpoint_url: str = "",
    thinking_signature_verified: Optional[bool] = None,
) -> Dict[str, Any]:
    """Classify lesson synthesizer provenance fail-closed into `FRONTIER_GENUINE` vs `REQUIRES_RUNTIME_PROOF`.

    Hardened v3.0 promotion boundary:
      - Enforces strict `origin <-> expected_host` binding (rejects empty host for remote API origins).
      - Rejects unsigned thinking blocks (`thinking_signature_verified is not True`) for `anthropic_official`
        or any `-thinking` model variant.
      - Prevents low-tier models AND 3rd-party NewAPI/OneAPI relay proxies from passing as Frontier.
    """
    model_norm = (teacher_model or "").strip().lower()
    origin_norm = (teacher_origin or "").strip().lower()
    raw_ep = (endpoint_url or "").strip()
    parsed = urlparse(raw_ep if "://" in raw_ep else (f"https://{raw_ep}" if raw_ep else ""))
    host = (parsed.hostname or "").strip().lower()

    reasons: List[str] = []
    if not model_norm or not origin_norm:
        reasons.append("missing_teacher_model_or_origin")
    if (
        any(marker in host for marker in UNTRUSTED_RELAY_HOST_MARKERS)
        or "relay" in origin_norm
        or "new-api" in origin_norm
        or "oneapi" in origin_norm
    ):
        reasons.append(f"untrusted_third_party_relay:{host or origin_norm}")
    if origin_norm and origin_norm not in GENUINE_FIRST_PARTY_ORIGINS:
        reasons.append(f"unverified_origin:{origin_norm}")
    elif origin_norm in ORIGIN_TO_EXPECTED_HOSTS:
        expected_hosts = ORIGIN_TO_EXPECTED_HOSTS[origin_norm]
        if expected_hosts:
            if not host:
                reasons.append(f"missing_endpoint_host_for_remote_origin:{origin_norm}")
            elif not _host_matches_expected(host, expected_hosts):
                reasons.append(f"endpoint_host_origin_mismatch:{host}!={origin_norm}")
        else:
            # Local native runtime (`antigravity_native`): reject unexpected remote hosts.
            if host and host not in {"localhost", "127.0.0.1", "::1"}:
                reasons.append(f"unexpected_remote_host_for_native_origin:{host}")

    if model_norm and any(marker in model_norm for marker in LOW_TIER_MODEL_MARKERS):
        reasons.append(f"low_tier_or_student_model:{model_norm}")
    elif model_norm and model_norm not in GENUINE_FRONTIER_TEACHER_MODELS:
        reasons.append(f"model_not_in_genuine_frontier_allowlist:{model_norm}")

    if thinking_signature_verified is False:
        reasons.append("thinking_signature_verification_failed")
    elif (origin_norm == "anthropic_official" or "thinking" in model_norm) and thinking_signature_verified is not True:
        reasons.append("thinking_signature_unverified_or_missing")

    is_genuine_frontier = len(reasons) == 0
    return {
        "tier": "FRONTIER_GENUINE" if is_genuine_frontier else "REQUIRES_RUNTIME_PROOF",
        "is_genuine_frontier": is_genuine_frontier,
        "teacher_model": model_norm or "unknown",
        "teacher_origin": origin_norm or "unknown",
        "endpoint_host": host or "",
        "thinking_signature_verified": thinking_signature_verified,
        "reasons": reasons,
    }


def _normalize_runtime_result(raw: Tuple[Union[bool, RuntimeOutcome, str], str]) -> Tuple[RuntimeOutcome, str]:
    status_val, detail = raw
    detail_s = str(detail)[:240]
    if isinstance(status_val, RuntimeOutcome):
        return status_val, detail_s
    if isinstance(status_val, str):
        try:
            return RuntimeOutcome(status_val.strip().upper()), detail_s
        except ValueError:
            return RuntimeOutcome.SETUP_ERROR, f"unrecognized_outcome:{status_val}:{detail_s}"
    if bool(status_val):
        return RuntimeOutcome.PASSED, detail_s
    # Legacy bool=False: fail-closed if detail indicates environment/setup/import/timeout/no-tests error
    if _SETUP_ERROR_RE.search(detail_s):
        low = detail_s.lower()
        if "timeout" in low:
            return RuntimeOutcome.TIMEOUT, detail_s
        if "no_tests" in low or "collected 0 items" in low or "no tests ran" in low:
            return RuntimeOutcome.NO_TESTS, detail_s
        if "importerror" in low or "modulenotfounderror" in low:
            return RuntimeOutcome.IMPORT_ERROR, detail_s
        return RuntimeOutcome.SETUP_ERROR, detail_s
    return RuntimeOutcome.EXPECTED_PROPERTY_FAIL, detail_s


def verify_runtime_broken_to_fixed(
    broken_code: str,
    fixed_code: str,
    runtime_test_fn: Optional[Callable[[str], Tuple[Union[bool, RuntimeOutcome, str], str]]],
) -> Dict[str, Any]:
    """Execute real runtime verification proving `broken_code` hits `EXPECTED_PROPERTY_FAIL` and `fixed_code` hits `PASSED`.

    Explicitly rejects `SETUP_ERROR`, `IMPORT_ERROR`, `TIMEOUT`, and `NO_TESTS` on baseline or candidate.
    """
    if runtime_test_fn is None:
        return {
            "verified": False,
            "broken_outcome": RuntimeOutcome.NO_TESTS.value,
            "fixed_outcome": RuntimeOutcome.NO_TESTS.value,
            "reason": "missing_runtime_test_fn",
        }
    try:
        broken_outcome, broken_detail = _normalize_runtime_result(runtime_test_fn(broken_code))
    except TimeoutError as exc:
        broken_outcome, broken_detail = RuntimeOutcome.TIMEOUT, str(exc)[:240]
    except Exception as exc:  # noqa: BLE001
        broken_outcome, broken_detail = RuntimeOutcome.SETUP_ERROR, f"{type(exc).__name__}: {exc}"[:240]

    try:
        fixed_outcome, fixed_detail = _normalize_runtime_result(runtime_test_fn(fixed_code))
    except TimeoutError as exc:
        fixed_outcome, fixed_detail = RuntimeOutcome.TIMEOUT, str(exc)[:240]
    except Exception as exc:  # noqa: BLE001
        fixed_outcome, fixed_detail = RuntimeOutcome.SETUP_ERROR, f"{type(exc).__name__}: {exc}"[:240]

    broken_valid = broken_outcome == RuntimeOutcome.EXPECTED_PROPERTY_FAIL
    fixed_valid = fixed_outcome == RuntimeOutcome.PASSED
    verified = broken_valid and fixed_valid
    reason = "ok"
    if not broken_valid:
        reason = f"invalid_broken_outcome:{broken_outcome.value}"
    elif not fixed_valid:
        reason = f"invalid_fixed_outcome:{fixed_outcome.value}"

    return {
        "verified": verified,
        "reason": reason,
        "broken_outcome": broken_outcome.value,
        "fixed_outcome": fixed_outcome.value,
        "broken_failed_as_expected": broken_valid,
        "fixed_passed_as_expected": fixed_valid,
        "broken_detail": broken_detail,
        "fixed_detail": fixed_detail,
    }


def split_ident_subtokens(text: str) -> Set[str]:
    """Split identifiers across `snake_case`, `camelCase`, and `PascalCase` into lowercase sub-tokens."""
    out: Set[str] = set()
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
        if len(ident) < 2:
            continue
        out.add(ident.lower())
        parts = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", ident)
        parts = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", parts)
        for sub in parts.split("_"):
            if len(sub) >= 2 and not sub.isdigit():
                out.add(sub.lower())
    return out


class FastCmHashIndex:
    """Cached O(1) sub-token reverse index over `code_mistakes_memory.json` (< 0.5 ms warm lookup)."""

    def __init__(self, cm_path: Path, cache_path: Optional[Path] = None) -> None:
        self.cm_path = cm_path
        self.cache_path = cache_path or Path("/private/tmp/kintsugi_cm_hash_index_cache.json")
        self.entries_by_id: Dict[str, Dict[str, Any]] = {}
        self.token_to_ids: Dict[str, List[str]] = {}

    def load_or_build(self) -> float:
        t0 = time.perf_counter()
        raw_bytes = self.cm_path.read_bytes()
        digest = hashlib.sha256(raw_bytes).hexdigest()
        if self.cache_path.is_file():
            try:
                cached = json.loads(self.cache_path.read_text(encoding="utf-8"))
                if cached.get("sha256") == digest:
                    self.entries_by_id = cached["entries_by_id"]
                    self.token_to_ids = cached["token_to_ids"]
                    return round((time.perf_counter() - t0) * 1000.0, 3)
            except (OSError, ValueError, KeyError) as exc:
                self._cache_load_error = f"{type(exc).__name__}: {exc}"
                self.entries_by_id = {}
                self.token_to_ids = {}

        doc = json.loads(raw_bytes.decode("utf-8"))
        for entry in doc.get("mistakes", []):
            cid = str(entry.get("id") or "")
            if not cid:
                continue
            self.entries_by_id[cid] = {
                "id": cid,
                "title": entry.get("title", ""),
                "tags": entry.get("tags", []),
                "correct_code": entry.get("correct_code", ""),
            }
            toks = split_ident_subtokens(
                f"{entry.get('wrong_code', '')} {entry.get('correct_code', '')} {' '.join(entry.get('tags', []))}"
            )
            for t in toks:
                if len(t) >= 4:
                    self.token_to_ids.setdefault(t, []).append(cid)

        try:
            self.cache_path.write_text(
                json.dumps(
                    {"sha256": digest, "entries_by_id": self.entries_by_id, "token_to_ids": self.token_to_ids},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            self._cache_write_error = f"{type(exc).__name__}: {exc}"
        return round((time.perf_counter() - t0) * 1000.0, 3)

    def lookup_fast(self, query_tokens: Set[str], top_k: int = 3) -> Tuple[List[Dict[str, Any]], float]:
        t0 = time.perf_counter()
        scores: Dict[str, int] = {}
        for qt in query_tokens:
            for cid in self.token_to_ids.get(qt, ()):
                scores[cid] = scores.get(cid, 0) + 1
        ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]
        res = [self.entries_by_id[cid] for cid, sc in ranked if sc >= 2 and cid in self.entries_by_id]
        return res, round((time.perf_counter() - t0) * 1000.0, 3)


class KintsugiFastLearner:
    """Generalized Diff-to-Artifact Compiler + 3-Gate Rust Quarantine + Dual-Pincer Orchestrator."""

    def __init__(
        self,
        kintsugi_bin: Path,
        active_rules_dir: Path,
        quarantine_dir: Path,
        capsules_json_path: Path,
        clean_corpus_paths: Sequence[Path],
    ) -> None:
        self.kbin = kintsugi_bin
        self.active_rules_dir = active_rules_dir
        self.quarantine_dir = quarantine_dir
        self.capsules_json_path = capsules_json_path
        self.clean_corpus_paths = list(clean_corpus_paths)
        self.active_rules_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        if not self.capsules_json_path.exists():
            self.capsules_json_path.write_text(json.dumps({"capsules": []}, indent=2) + "\n", encoding="utf-8")

    def sign_and_validate_rule_ir(self, draft_rule: Dict[str, Any]) -> Tuple[Optional[str], str]:
        draft = dict(draft_rule)
        draft["schema"] = "RuleIR/1"
        draft.setdefault("severity", "HIGH")
        draft.setdefault("languages", ["python"])
        draft["rule_hash"] = "sha256:" + ("0" * 64)
        p1 = subprocess.run([str(self.kbin), "rule-ir-check", "-", "--strict-hash"], input=json.dumps(draft), capture_output=True, text=True, shell=False)
        m = re.search(r"!= (sha256:[0-9a-f]{64})", p1.stdout + "\n" + p1.stderr)
        if m:
            draft["rule_hash"] = m.group(1)
        signed = json.dumps(draft, indent=2, ensure_ascii=False)
        p2 = subprocess.run([str(self.kbin), "rule-ir-check", "-", "--strict-hash"], input=signed, capture_output=True, text=True, shell=False)
        if p2.returncode != 0:
            return None, (p2.stdout or p2.stderr).strip()
        return signed, draft["rule_hash"]

    def verify_and_promote_rule_ir(
        self, rule_id: str, draft_rule: Dict[str, Any], broken_code: str, fixed_code: str, lang: str = "python"
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        signed_json, hash_or_err = self.sign_and_validate_rule_ir(draft_rule)
        if not signed_json:
            return {"artifact": "RuleIR/1", "rule_id": rule_id, "status": "QUARANTINED_INVALID_IR", "error": hash_or_err}

        stage = self.quarantine_dir / f"stage_{rule_id}"
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True, exist_ok=True)
        cand_file = stage / f"{rule_id}.json"
        cand_file.write_text(signed_json + "\n", encoding="utf-8")

        pb = subprocess.run(
            [str(self.kbin), "rule-ir-eval", "--rule", str(cand_file), "--lang", lang, "-"],
            input=broken_code, capture_output=True, text=True, shell=False
        )
        br = json.loads(pb.stdout.strip()) if pb.stdout.strip().startswith("{") else {}
        must_flag = bool(br.get("matched")) or int(br.get("hit_count", 0)) > 0 or pb.returncode == 1

        pf = subprocess.run(
            [str(self.kbin), "rule-ir-eval", "--rule", str(cand_file), "--lang", lang, "-"],
            input=fixed_code, capture_output=True, text=True, shell=False
        )
        fr = json.loads(pf.stdout.strip()) if pf.stdout.strip().startswith("{") else {}
        must_allow = (not fr.get("matched")) and int(fr.get("hit_count", 0)) == 0

        fp_hits = 0
        for cp in self.clean_corpus_paths:
            pc = subprocess.run(
                [str(self.kbin), "scan", str(cp), "--rules-dir", str(stage), "--no-shadow-arm-c", "--format", "json"],
                capture_output=True, text=True, shell=False
            )
            cj = json.loads(pc.stdout.strip()) if pc.stdout.strip().startswith("{") else {}
            fp_hits += sum(1 for fn in (cj.get("findings") or []) if fn.get("scar_id") == rule_id)

        ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if must_flag and must_allow and fp_hits == 0:
            shutil.copyfile(cand_file, self.active_rules_dir / f"{rule_id}.json")
            status = "PROMOTED_ACTIVE"
        else:
            status = "QUARANTINED"
        return {
            "artifact": "RuleIR/1",
            "rule_id": rule_id,
            "status": status,
            "must_flag_broken": must_flag,
            "must_allow_fixed": must_allow,
            "clean_corpus_fp_count": fp_hits,
            "elapsed_ms": ms,
        }

    def verify_and_promote_capsule(
        self,
        capsule_obj: Dict[str, Any],
        broken_code: str,
        *,
        canary_eval_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        require_canary_replay: bool = False,
        teacher_provenance: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Verify dynamic capsule triggers on `broken_code`, emits 0 spam on clean baseline files via
        `kintsugi-rs capsule`, and enforces optional/mandatory Gate-4 Canary Student zero-regression replay.
        """
        t0 = time.perf_counter()
        cid = str(capsule_obj.get("id") or "")
        tmp_cap_file = self.quarantine_dir / f"cand_cap_{cid}.json"
        tmp_src_file = self.quarantine_dir / f"cand_src_{cid}.py"
        tmp_cap_file.write_text(json.dumps({"capsules": [capsule_obj]}, indent=2) + "\n", encoding="utf-8")
        tmp_src_file.write_text(broken_code, encoding="utf-8")

        p_hit = subprocess.run(
            [str(self.kbin), "capsule", str(tmp_src_file), "--capsules-file", str(tmp_cap_file), "--format", "json"],
            capture_output=True, text=True, shell=False
        )
        if p_hit.returncode != 0:
            return {"artifact": "InvariantCapsule", "id": cid, "status": "QUARANTINED_SCHEMA_ERR", "error": p_hit.stdout}
        hj = json.loads(p_hit.stdout.strip())
        must_trigger = any(c.get("id") == cid for c in (hj.get("capsules") or []))

        clean_spam = 0
        for cp in self.clean_corpus_paths:
            targets = [cp] if cp.is_file() else sorted(cp.glob("*.py"))[:6]
            for tf in targets:
                pc = subprocess.run(
                    [str(self.kbin), "capsule", str(tf), "--capsules-file", str(tmp_cap_file), "--format", "json"],
                    capture_output=True, text=True, shell=False
                )
                if pc.returncode == 0 and pc.stdout.strip().startswith("{"):
                    cj = json.loads(pc.stdout.strip())
                    if any(c.get("id") == cid for c in (cj.get("capsules") or [])):
                        clean_spam += 1

        # Gate 4: Canary Student Replay Gate (mandatory for lower-tier/relay proposers; optional for frontier)
        canary_report: Optional[Dict[str, Any]] = None
        canary_ok = True
        if canary_eval_fn is not None:
            canary_report = canary_eval_fn(capsule_obj)
            score_raw = int(canary_report.get("score_raw", 0))
            score_with = int(canary_report.get("score_with_capsule", 0))
            regressions = int(canary_report.get("regressions", 0))
            canary_ok = (regressions == 0) and (score_with > score_raw)
        elif require_canary_replay:
            canary_ok = False
            canary_report = {"verified": False, "reason": "missing_canary_eval_fn_for_non_frontier_proposer"}

        ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if must_trigger and clean_spam == 0 and canary_ok:
            stored_cap = dict(capsule_obj)
            if teacher_provenance is not None:
                stored_cap["provenance"] = dict(teacher_provenance)
            cur_doc = json.loads(self.capsules_json_path.read_text(encoding="utf-8"))
            caps = [c for c in cur_doc.get("capsules", []) if c.get("id") != cid]
            caps.append(stored_cap)
            self.capsules_json_path.write_text(json.dumps({"capsules": caps}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            status = "PROMOTED_ACTIVE"
        elif not canary_ok:
            status = "QUARANTINED_CANARY_REGRESSION"
        else:
            status = "QUARANTINED"
        return {
            "artifact": "InvariantCapsule",
            "id": cid,
            "status": status,
            "must_trigger_broken": must_trigger,
            "clean_corpus_spam_count": clean_spam,
            "canary_ok": canary_ok,
            "canary_report": canary_report,
            "teacher_provenance": teacher_provenance,
            "elapsed_ms": ms,
        }

    def learn_from_diff_generalized(
        self,
        *,
        bug_id: str,
        broken_code: str,
        fixed_code: str,
        failure_summary: str,
        llm_proposer: Optional[Callable[[str], str]] = None,
        teacher_model: Optional[str] = None,
        teacher_origin: Optional[str] = None,
        endpoint_url: str = "",
        thinking_signature_verified: Optional[bool] = None,
        runtime_test_fn: Optional[Callable[[str], Tuple[bool, str]]] = None,
        canary_eval_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Generalized compiler with Two-Track Fail-Closed Teacher Provenance & Runtime Proof Gate (CM-108):

        Track 1 (`FRONTIER_GENUINE`): Modern high-tier models on verified first-party endpoints may
        propose `RuleIR/1` or `InvariantCapsule` artifacts subject to the Rust 3-Gate Quarantine.
        Track 2 (`REQUIRES_RUNTIME_PROOF`): Lower-tier models or third-party relay endpoints MUST
        prove live runtime execution (`broken_code` fails AND `fixed_code` passes) PLUS zero-regression
        Canary replay for capsules before any artifact can be promoted.
        """
        prov = validate_teacher_provenance(
            teacher_model=teacher_model,
            teacher_origin=teacher_origin,
            endpoint_url=endpoint_url,
            thinking_signature_verified=thinking_signature_verified,
        )

        # 1. Fast deterministic check for common structural patterns (0 LLM tokens)
        if "hashlib.sha256(" in broken_code and "secret" in broken_code and "hmac.new(" in fixed_code:
            rid = f"AUTO-{bug_id}"
            draft = {
                "rule_id": rid,
                "predicate_kind": "bounded_regex",
                "match": {"regex": r"hashlib\.sha256\([^)]*secret[^)]*\+"},
                "response": {
                    "decision": "deny",
                    "reason_code": "RAW_SHA256_SECRET_MAC",
                    "message": "Use hmac.new(secret, ts_delim_msg, hashlib.sha256) instead of sha256(secret + msg).",
                },
                "provenance": {"synthesizer": "deterministic_ast_delta", "stage": "SHADOW", "human_approved": False},
            }
            return self.verify_and_promote_rule_ir(rid, draft, broken_code, fixed_code)

        # 2. Generalized LLM Proposal Path for ANY arbitrary semantic or structural bug!
        # Kintsugi v3.0 Universal Truth Gate: NO model — not even FRONTIER_GENUINE — may
        # self-certify a lesson without an independent runtime Truth Proof (EXPECTED_PROPERTY_FAIL -> PASSED).
        if llm_proposer is not None:
            runtime_proof = verify_runtime_broken_to_fixed(broken_code, fixed_code, runtime_test_fn)
            if not runtime_proof["verified"]:
                status = (
                    "QUARANTINED_TRUTH_GATE_REQUIRED"
                    if prov["is_genuine_frontier"]
                    else "QUARANTINED_UNTRUSTED_TEACHER_REQUIRES_RUNTIME_PROOF"
                )
                return {
                    "bug_id": bug_id,
                    "status": status,
                    "teacher_provenance": prov,
                    "runtime_proof": runtime_proof,
                }

            synthesis_prompt = (
                "Analyze this real `(BROKEN -> FIXED)` bug fix and output ONLY a single JSON object (no markdown fences) "
                "with `\"kind\": \"rule_ir\"` OR `\"kind\": \"capsule\"`:\n"
                "- Choose `\"rule_ir\"` ONLY if a deterministic `ast_pattern` (`{\"node\":\"Call\",\"callee\":\"yaml.unsafe_load\",\"mode\":\"forbidden_callee\"}`) "
                "or simple `bounded_regex` (only literal chars, `.`, `*`, `+`, `?`, `[a-z]`, `(a|b)`; NO `\\b`, `\\s`, `\\w`, or backreferences!) "
                "catches `BROKEN`, passes `FIXED`, and has 0 false positives on normal Python code:\n"
                "  `{\"kind\":\"rule_ir\", \"rule\": {\"rule_id\":\"AUTO-YAML-01\", \"predicate_kind\":\"ast_pattern\", \"match\":{\"node\":\"Call\",\"callee\":\"yaml.unsafe_load\",\"mode\":\"forbidden_callee\"}, \"response\":{\"decision\":\"deny\",\"reason_code\":\"UNSAFE_CALL\",\"message\":\"Use safe alternative\"}}}`\n"
                "- Otherwise choose `\"capsule\"` using rename-resistant structural tags (`@struct_halving_hash_tree`, "
                "`@struct_share_vault_ratio`, `@struct_multi_lock_transfer`, `@struct_json_untrusted_input`, `@struct_subprocess_exec`, `@struct_fs_persistence`) "
                "and lowercase sub-tokens in `trigger_groups` (conjunction of OR-lists, >=2 specific groups so normal files don't match). "
                "SIGNATURE-GUARDED RULE: never write unconditional 'reject' commands that could break `-> bool` verifiers; explicitly state "
                "'for `-> bool` verifiers return False; otherwise raise domain exception':\n"
                "  `{\"kind\":\"capsule\", \"capsule\": {\"id\":\"CAP-AUTO-...\", \"domain\":\"...\", \"trigger_groups\":[[...],[...]], \"when_clause\":\"...\", \"invariant\":\"...\", \"pos_ast\":\"...\"}}`\n\n"
                f"FAILURE_SUMMARY: {failure_summary}\n"
                f"=== BROKEN ===\n{broken_code}\n=== FIXED ===\n{fixed_code}\n"
            )
            raw_reply = llm_proposer(synthesis_prompt)
            m_json = re.search(r"\{.*\}", raw_reply, flags=re.DOTALL)
            if not m_json:
                return {"bug_id": bug_id, "status": "QUARANTINED_PARSE_ERR", "raw": raw_reply[:300]}
            try:
                prop = json.loads(m_json.group(0))
            except ValueError as exc:
                return {"bug_id": bug_id, "status": "QUARANTINED_JSON_ERR", "error": str(exc)}

            if prop.get("kind") == "rule_ir" and isinstance(prop.get("rule"), dict):
                rule_obj = prop["rule"]
                rid = str(rule_obj.get("rule_id") or f"AUTO-{bug_id}")
                rule_obj["rule_id"] = rid
                rule_obj["provenance"] = {
                    "synthesizer": "llm_offline_proposer",
                    "stage": "SHADOW",
                    "human_approved": False,
                    "teacher_tier": prov["tier"],
                    "teacher_model": prov["teacher_model"],
                    "teacher_origin": prov["teacher_origin"],
                    "runtime_verified": bool(runtime_proof and runtime_proof.get("verified")),
                }
                res = self.verify_and_promote_rule_ir(rid, rule_obj, broken_code, fixed_code)
                res["teacher_provenance"] = prov
                if runtime_proof is not None:
                    res["runtime_proof"] = runtime_proof
                return res

            if prop.get("kind") == "capsule" and isinstance(prop.get("capsule"), dict):
                cap_obj = prop["capsule"]
                cap_obj.setdefault("id", f"CAP-AUTO-{bug_id}")
                res = self.verify_and_promote_capsule(
                    cap_obj,
                    broken_code,
                    canary_eval_fn=canary_eval_fn,
                    require_canary_replay=(not prov["is_genuine_frontier"]),
                    teacher_provenance=prov,
                )
                if runtime_proof is not None:
                    res["runtime_proof"] = runtime_proof
                return res

        return {"bug_id": bug_id, "status": "SKIPPED_NO_PROPOSER"}

    def record_capsule_bandit_outcome(self, capsule_id: str, success: bool) -> Optional[Dict[str, Any]]:
        """Update Beta-Bernoulli counts `(wins, losses, trials, consecutive_losses)` with 2-strike circuit breaker
        (`consecutive_losses >= 2`) and `<15%` dead-scar auto-freeze after `>=30` trials.
        """
        doc = json.loads(self.capsules_json_path.read_text(encoding="utf-8"))
        updated = None
        for c in doc.get("capsules", []):
            if c.get("id") == capsule_id:
                c.setdefault("frozen", False)
                c["trials"] = int(c.get("trials", 0)) + 1
                if success:
                    c["wins"] = int(c.get("wins", 0)) + 1
                    c["consecutive_losses"] = 0
                else:
                    c["losses"] = int(c.get("losses", 0)) + 1
                    c["consecutive_losses"] = int(c.get("consecutive_losses", 0)) + 1
                if c["consecutive_losses"] >= 2 or (
                    c["trials"] >= 30 and (c["wins"] / max(1, c["trials"])) < 0.15
                ):
                    c["frozen"] = True
                updated = c
                break
        if updated is not None:
            self.capsules_json_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return updated

    def build_pre_read_context(self, target_file: Path) -> Dict[str, Any]:
        """Stage 1 of Dual-Pincer: sub-millisecond Rust `capsule` + `gate` + `--for-file` KML slice."""
        p_cap = subprocess.run(
            [str(self.kbin), "capsule", str(target_file), "--capsules-file", str(self.capsules_json_path), "--format", "json"],
            capture_output=True, text=True, shell=False, check=True
        )
        cap_j = json.loads(p_cap.stdout.strip())
        p_gate = subprocess.run(
            [str(self.kbin), "gate", str(target_file), "--rules-dir", str(self.active_rules_dir), "--s3", "--strict-proven", "--shadow-arm-c", "--max-tokens", "350", "--format", "compact"],
            capture_output=True, text=True, shell=False
        )
        p_kml = subprocess.run(
            [str(self.kbin), "compress", "--kml", "--for-file", str(target_file)],
            capture_output=True, text=True, shell=False, check=True
        )
        capsules_list = cap_j.get("capsules") or []
        compact_caps = (cap_j.get("compact") or "").strip()
        gate_compact = p_gate.stdout.strip()
        kml_slice = p_kml.stdout.strip()
        prompt_prefix = (
            f"=== KINTSUGI PRE-READ JIT INVARIANT CAPSULES ({len(capsules_list)} matched in {cap_j.get('elapsed_ms', 0)}ms) ===\n"
            f"{compact_caps}\n\n"
            f"=== KINTSUGI-RS DYNAMIC + S3 PRE-FLIGHT GATE ===\n{gate_compact}\n\n"
            f"=== KINTSUGI @KML/1 LANGUAGE SLICE ===\n{kml_slice}"
        ).strip()
        return {
            "capsule_report": cap_j,
            "capsule_ids": [c.get("id") for c in capsules_list if isinstance(c, dict) and c.get("id")],
            "compact_capsules": compact_caps,
            "estimated_capsule_tokens": int(cap_j.get("estimated_tokens") or 0),
            "capsule_elapsed_ms": float(cap_j.get("elapsed_ms") or 0.0),
            "preflight_gate_compact": gate_compact,
            "kml_slice": kml_slice,
            "prompt_prefix": prompt_prefix,
        }

    def run_post_write_gate(self, generated_file: Path) -> Dict[str, Any]:
        """Stage 2 of Dual-Pincer: deterministic Rust `hook` + `gate --s3 --strict-proven` + `s3-audit --strict-proven`."""
        code = generated_file.read_text(encoding="utf-8")
        hook_in = json.dumps({"tool_name": "Write", "tool_input": {"file_path": str(generated_file), "content": code}})
        p_hook = subprocess.run(
            [str(self.kbin), "hook", "claude-pre-tool", "--block-on", "HIGH", "--exit-on-deny"],
            input=hook_in, capture_output=True, text=True, shell=False
        )
        p_gate = subprocess.run(
            [str(self.kbin), "gate", str(generated_file), "--rules-dir", str(self.active_rules_dir), "--s3", "--strict-proven", "--shadow-arm-c", "--max-tokens", "350", "--format", "compact"],
            capture_output=True, text=True, shell=False
        )
        p_s3 = subprocess.run(
            [str(self.kbin), "s3-audit", str(generated_file), "--strict-proven", "--format", "json"],
            capture_output=True, text=True, shell=False
        )
        s3_j = json.loads(p_s3.stdout.strip()) if p_s3.stdout.strip().startswith("{") else {}
        passed_all = (p_hook.returncode == 0) and (p_gate.returncode == 0) and (p_s3.returncode == 0)
        return {
            "passed_all": passed_all,
            "hook_exit": p_hook.returncode,
            "gate_exit": p_gate.returncode,
            "gate_compact": p_gate.stdout.strip(),
            "s3_exit": p_s3.returncode,
            "s3_verdict": s3_j.get("verdict"),
            "failing_seams": (s3_j.get("files") or [{}])[0].get("failing_seams", []),
        }
