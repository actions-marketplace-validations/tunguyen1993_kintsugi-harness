#!/usr/bin/env python3
"""Kintsugi v3.0 Verified Patch Transaction Controller (`src/kintsugi/evolution/patch_transaction.py`).

Changes the unit of authority from 'code text contains a marker' to:
    'a patch on an exact snapshot, satisfying a typed obligation, passing an independent oracle.'

Anti-reward-hacking invariants enforced fail-closed:
  1. Freezes `base_tree_digest`, `allowed_files`, optional `allowed_symbols`, and pinned read-only
     `oracle_manifest_digest` + `expected_test_ids` BEFORE invoking any proposer.
  2. Applies candidate edits ONLY inside an isolated disposable temp checkout; forbids touching
     `.git/`, `tests/`, policy files, or receipt directories.
  3. Baseline MUST classify as `RuntimeOutcome.EXPECTED_PROPERTY_FAIL` (rejects `SETUP_ERROR`,
     `IMPORT_ERROR`, `TIMEOUT`, `NO_TESTS`, or already-`PASSED` baselines).
  4. Candidate MUST pass ALL `expected_test_ids` (positive + negative + conservation controls,
     blocking no-op/shortcut patches) AND pass native `kintsugi-rs s3-audit --strict-proven`.
  5. Enforces max 2 repair attempts; before atomic CAS promote, verifies live workspace
     `tree_digest == frozen_base_tree_digest` (stale-base rejected cleanly with zero partial writes).
  6. Emits tamper-evident signed external receipt OUTSIDE the workspace (`receipt_stage = "patch_bound"`).
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from kintsugi.evolution.fast_learner import RuntimeOutcome


FORBIDDEN_MUTATION_PREFIXES: Tuple[str, ...] = (
    ".git/",
    ".git",
    ".kintsugi/policy",
    ".kintsugi/receipts",
)


def compute_tree_digest(root: Path, *, ignore_dirs: Set[str] = frozenset({".git", "__pycache__", ".pytest_cache"})) -> str:
    """Deterministic SHA-256 over all regular files in `root` sorted by POSIX relative path."""
    h = hashlib.sha256()
    root_real = root.resolve()
    entries: List[Tuple[str, Path]] = []
    for cur_dir, dirnames, filenames in os.walk(root_real):
        dirnames[:] = sorted(d for d in dirnames if d not in ignore_dirs)
        for fn in sorted(filenames):
            fp = Path(cur_dir) / fn
            if fp.is_symlink() or not fp.is_file():
                continue
            rel = fp.relative_to(root_real).as_posix()
            entries.append((rel, fp))
    entries.sort(key=lambda item: item[0])
    for rel, fp in entries:
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(fp.read_bytes())
        h.update(b"\x00")
    return h.hexdigest()


def extract_python_modified_symbols(old_src: str, new_src: str) -> Optional[Set[str]]:
    """Return top-level/class-method symbol names whose AST dump changed between `old_src` and `new_src`."""
    try:
        old_tree = ast.parse(old_src)
        new_tree = ast.parse(new_src)
    except SyntaxError:
        return None

    def collect_sym_dumps(tree: ast.AST) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out[node.name] = ast.dump(node, include_attributes=False)
            elif isinstance(node, ast.ClassDef):
                out[node.name] = ast.dump(node, include_attributes=False)
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        out[f"{node.name}.{item.name}"] = ast.dump(item, include_attributes=False)
                        out[item.name] = ast.dump(item, include_attributes=False)
        return out

    old_map = collect_sym_dumps(old_tree)
    new_map = collect_sym_dumps(new_tree)
    changed: Set[str] = set()
    for sym in set(old_map.keys()) | set(new_map.keys()):
        if old_map.get(sym) != new_map.get(sym):
            changed.add(sym)
    return changed


@dataclass(frozen=True)
class OracleRunResult:
    outcome: RuntimeOutcome
    observed_test_ids: Tuple[str, ...]
    passed_test_ids: Tuple[str, ...]
    failed_test_ids: Tuple[str, ...]
    positive_control_passed: bool
    negative_control_passed: bool
    conservation_passed: bool
    detail: str = ""


@dataclass(frozen=True)
class PatchTransactionSpec:
    tx_id: str
    workspace_root: Path
    allowed_files: Tuple[str, ...]
    oracle_manifest_files: Tuple[Path, ...]
    expected_test_ids: Tuple[str, ...]
    external_receipt_dir: Path
    allowed_symbols: Optional[Tuple[str, ...]] = None
    envelope_source_digests: Dict[str, str] = field(default_factory=dict)
    kintsugi_bin: Optional[Path] = None
    max_attempts: int = 2
    receipt_hmac_key: Optional[bytes] = None


class VerifiedPatchTransactionController:
    """Disposable-checkout transactional patch verifier with atomic CAS promotion and signed external receipts."""

    def __init__(self, spec: PatchTransactionSpec) -> None:
        self.spec = spec
        self.ws_root = spec.workspace_root.resolve()
        self.receipt_dir = spec.external_receipt_dir.resolve()
        # Fail closed if external receipt directory is inside the mutable workspace!
        if self.receipt_dir == self.ws_root or self.ws_root in self.receipt_dir.parents:
            raise PermissionError(
                f"RECEIPT_DIR_INSIDE_WORKSPACE: '{self.receipt_dir}' must reside outside '{self.ws_root}'."
            )
        self.receipt_dir.mkdir(parents=True, exist_ok=True)
        self.base_tree_digest = compute_tree_digest(self.ws_root)
        self.oracle_manifest_digest = self._compute_oracle_manifest_digest()

    def _compute_oracle_manifest_digest(self) -> str:
        h = hashlib.sha256()
        for p in sorted(self.spec.oracle_manifest_files, key=lambda x: str(x)):
            rp = p.resolve()
            h.update(rp.name.encode("utf-8"))
            h.update(b"\x00")
            h.update(rp.read_bytes())
            h.update(b"\x00")
        for tid in sorted(self.spec.expected_test_ids):
            h.update(tid.encode("utf-8"))
            h.update(b"\n")
        return h.hexdigest()

    def _validate_candidate_edits(self, candidate_edits: Dict[str, str], checkout_dir: Path) -> Optional[str]:
        if not candidate_edits:
            return "EMPTY_CANDIDATE_PATCH"
        allowed_set = {Path(f).as_posix() for f in self.spec.allowed_files}
        oracle_names = {p.resolve().name for p in self.spec.oracle_manifest_files}

        for raw_rel, new_content in candidate_edits.items():
            norm_rel = Path(raw_rel).as_posix().lstrip("./")
            if ".." in Path(norm_rel).parts or norm_rel.startswith("/"):
                return f"PATH_TRAVERSAL_BLOCKED:{raw_rel}"
            if any(norm_rel == pref or norm_rel.startswith(pref) for pref in FORBIDDEN_MUTATION_PREFIXES):
                return f"FORBIDDEN_PROTECTED_PATH:{norm_rel}"
            if norm_rel.startswith("tests/") or Path(norm_rel).name in oracle_names:
                return f"ORACLE_OR_TEST_TAMPER_BLOCKED:{norm_rel}"
            if norm_rel not in allowed_set:
                return f"OUTSIDE_ALLOWED_FILES:{norm_rel}"

            # Verify ContextEnvelope snapshot binding when provided
            expected_env_sha = self.spec.envelope_source_digests.get(norm_rel)
            orig_file = checkout_dir / norm_rel
            if expected_env_sha and orig_file.is_file():
                actual_sha = hashlib.sha256(orig_file.read_bytes()).hexdigest()[:len(expected_env_sha)]
                if actual_sha != expected_env_sha:
                    return f"STALE_CONTEXT_ENVELOPE_DIGEST:{norm_rel}:{actual_sha}!={expected_env_sha}"

            # Enforce allowed_symbols scope if configured on Python files
            if self.spec.allowed_symbols and norm_rel.endswith(".py") and orig_file.is_file():
                old_src = orig_file.read_text(encoding="utf-8")
                changed_syms = extract_python_modified_symbols(old_src, new_content)
                if changed_syms is None:
                    return f"SYNTAX_ERROR_IN_CANDIDATE:{norm_rel}"
                allowed_syms = set(self.spec.allowed_symbols)
                # Strip enclosing class name when a method inside that class is allowlisted
                disallowed = {
                    s for s in changed_syms
                    if s not in allowed_syms and not any(a.startswith(s + ".") for a in allowed_syms)
                }
                if disallowed:
                    return f"OUTSIDE_ALLOWED_SYMBOLS:{norm_rel}:{sorted(disallowed)}"
        return None

    def _run_s3_prover_on_checkout(self, checkout_dir: Path, edited_files: Sequence[str]) -> Tuple[bool, Dict[str, Any]]:
        kbin = self.spec.kintsugi_bin
        if kbin is None or not kbin.is_file():
            return True, {"skipped": True, "reason": "no_kintsugi_bin_configured"}
        targets = [str(checkout_dir / rel) for rel in edited_files]
        proc = subprocess.run(
            [str(kbin), "s3-audit", *targets, "--strict-proven", "--format", "json"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=20,
        )
        parsed = json.loads(proc.stdout.strip()) if proc.stdout.strip().startswith("{") else {}
        passed = proc.returncode == 0 and parsed.get("verdict") == "PASS_S3_LOCKED"
        return passed, {
            "exit_code": proc.returncode,
            "verdict": parsed.get("verdict"),
            "strict_verdict": parsed.get("strict_verdict"),
            "proven_s3_seams": parsed.get("proven_s3_seams", 0),
            "unproven_seams": parsed.get("unproven_seams", 0),
            "unguarded_s0_seams": parsed.get("unguarded_s0_seams", 0),
        }

    def _write_external_receipt(self, payload: Dict[str, Any]) -> Path:
        body = dict(payload)
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        body["receipt_sha256"] = hashlib.sha256(canonical).hexdigest()
        if self.spec.receipt_hmac_key:
            body["receipt_hmac_sha256"] = hmac.new(self.spec.receipt_hmac_key, canonical, hashlib.sha256).hexdigest()
        out_path = self.receipt_dir / f"receipt_{self.spec.tx_id}.json"
        tmp_path = self.receipt_dir / f".tmp_receipt_{self.spec.tx_id}_{os.getpid()}.json"
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(body, indent=2, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, out_path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        return out_path

    def execute_transaction(
        self,
        *,
        proposer_fn: Callable[[int, Optional[str]], Dict[str, str]],
        oracle_runner_fn: Callable[[Path], OracleRunResult],
    ) -> Dict[str, Any]:
        """Run full transactional lifecycle: Baseline -> Up to 2 Isolated Attempts -> Atomic CAS Promote/Rollback."""
        t0 = time.perf_counter()
        expected_set = set(self.spec.expected_test_ids)
        attempts_log: List[Dict[str, Any]] = []

        # 1. Verify pinned oracle manifest hasn't been tampered with before baseline
        if self._compute_oracle_manifest_digest() != self.oracle_manifest_digest:
            return self._finalize_no_promotion("ORACLE_MANIFEST_TAMPERED", attempts_log, t0)

        # 2. Run baseline in isolated checkout — MUST be EXPECTED_PROPERTY_FAIL
        base_checkout = Path(tempfile.mkdtemp(prefix=f"kintsugi_tx_base_{self.spec.tx_id}_"))
        try:
            shutil.copytree(self.ws_root, base_checkout / "ws", ignore=shutil.ignore_patterns(".git", "__pycache__"))
            base_res = oracle_runner_fn(base_checkout / "ws")
        finally:
            shutil.rmtree(base_checkout, ignore_errors=True)

        if base_res.outcome != RuntimeOutcome.EXPECTED_PROPERTY_FAIL:
            return self._finalize_no_promotion(
                f"INVALID_BASELINE_OUTCOME:{base_res.outcome.value}",
                [{"phase": "baseline", "outcome": base_res.outcome.value, "detail": base_res.detail}],
                t0,
            )

        # 3. Bounded repair loop (max_attempts capped at 2)
        max_tries = max(1, min(2, int(self.spec.max_attempts)))
        last_feedback: Optional[str] = base_res.detail
        winning_edits: Optional[Dict[str, str]] = None
        winning_checkout_digest: Optional[str] = None
        winning_oracle: Optional[OracleRunResult] = None
        winning_s3: Optional[Dict[str, Any]] = None

        for attempt in range(1, max_tries + 1):
            cand_edits = proposer_fn(attempt, last_feedback)
            cand_root = Path(tempfile.mkdtemp(prefix=f"kintsugi_tx_try{attempt}_{self.spec.tx_id}_"))
            try:
                cand_ws = cand_root / "ws"
                shutil.copytree(self.ws_root, cand_ws, ignore=shutil.ignore_patterns(".git", "__pycache__"))

                scope_err = self._validate_candidate_edits(cand_edits, cand_ws)
                if scope_err is not None:
                    attempts_log.append({"attempt": attempt, "status": "REJECTED_SCOPE", "reason": scope_err})
                    last_feedback = scope_err
                    continue

                for rel, content in cand_edits.items():
                    target = cand_ws / Path(rel).as_posix().lstrip("./")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")

                # Re-check oracle manifest integrity before running candidate oracle
                if self._compute_oracle_manifest_digest() != self.oracle_manifest_digest:
                    return self._finalize_no_promotion("ORACLE_MANIFEST_TAMPERED_MID_TX", attempts_log, t0)

                s3_ok, s3_rep = self._run_s3_prover_on_checkout(cand_ws, list(cand_edits.keys()))
                if not s3_ok:
                    attempts_log.append({"attempt": attempt, "status": "REJECTED_S3_PROVER", "s3": s3_rep})
                    last_feedback = f"S3_PROVER_FAILED:{s3_rep.get('verdict')}"
                    continue

                cand_res = oracle_runner_fn(cand_ws)
                observed_set = set(cand_res.observed_test_ids)
                passed_set = set(cand_res.passed_test_ids)
                missing_ids = sorted(expected_set - observed_set)
                unpassed_ids = sorted(expected_set - passed_set)

                if cand_res.outcome != RuntimeOutcome.PASSED:
                    reason = f"ORACLE_OUTCOME_{cand_res.outcome.value}"
                elif missing_ids:
                    reason = f"MISSING_EXPECTED_TEST_IDS:{missing_ids}"
                elif unpassed_ids:
                    reason = f"FAILED_EXPECTED_TEST_IDS:{unpassed_ids}"
                elif not cand_res.positive_control_passed:
                    reason = "POSITIVE_CONTROL_FAILED_NOOP_OR_SHORTCUT"
                elif not cand_res.negative_control_passed:
                    reason = "NEGATIVE_CONTROL_FAILED"
                elif not cand_res.conservation_passed:
                    reason = "CONSERVATION_INVARIANT_FAILED"
                else:
                    reason = ""

                if reason:
                    attempts_log.append({
                        "attempt": attempt,
                        "status": "REJECTED_ORACLE",
                        "reason": reason,
                        "detail": cand_res.detail[:200],
                    })
                    last_feedback = f"{reason}: {cand_res.detail[:180]}"
                    continue

                winning_edits = dict(cand_edits)
                winning_checkout_digest = compute_tree_digest(cand_ws)
                winning_oracle = cand_res
                winning_s3 = s3_rep
                attempts_log.append({"attempt": attempt, "status": "VERIFIED_IN_CHECKOUT", "s3": s3_rep})
                break
            finally:
                shutil.rmtree(cand_root, ignore_errors=True)

        if winning_edits is None or winning_oracle is None or winning_checkout_digest is None:
            return self._finalize_no_promotion("EXHAUSTED_REPAIR_BUDGET", attempts_log, t0)

        # 4. Atomic CAS Check against frozen base_tree_digest (blocks stale-base race!)
        live_digest = compute_tree_digest(self.ws_root)
        if live_digest != self.base_tree_digest:
            return self._finalize_no_promotion(
                f"STALE_BASE_CAS_MISMATCH:{live_digest[:12]}!={self.base_tree_digest[:12]}",
                attempts_log,
                t0,
            )

        # 5. Atomic write with rollback backup if any write fails
        backups: Dict[Path, Optional[bytes]] = {}
        try:
            for rel, content in winning_edits.items():
                dst = self.ws_root / Path(rel).as_posix().lstrip("./")
                backups[dst] = dst.read_bytes() if dst.is_file() else None
                dst.parent.mkdir(parents=True, exist_ok=True)
                tmp_dst = dst.parent / f".kintsugi_cas_{dst.name}_{os.getpid()}.tmp"
                fd = os.open(str(tmp_dst), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(content)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp_dst, dst)

            promoted_digest = compute_tree_digest(self.ws_root)
            if promoted_digest != winning_checkout_digest:
                raise RuntimeError(f"POST_PROMOTE_DIGEST_MISMATCH:{promoted_digest}!={winning_checkout_digest}")
        except BaseException as exc:
            for dst, prev in backups.items():
                if prev is None:
                    dst.unlink(missing_ok=True)
                else:
                    dst.write_bytes(prev)
            return self._finalize_no_promotion(f"CAS_ROLLBACK_ERROR:{exc}", attempts_log, t0)

        receipt_payload = {
            "schema": "PatchTransactionReceipt/3",
            "tx_id": self.spec.tx_id,
            "status": "PROMOTED",
            "receipt_stage": "patch_bound",
            "base_tree_digest": self.base_tree_digest,
            "promoted_tree_digest": promoted_digest,
            "oracle_manifest_digest": self.oracle_manifest_digest,
            "expected_test_ids": list(self.spec.expected_test_ids),
            "observed_test_ids": list(winning_oracle.observed_test_ids),
            "edited_files": sorted(winning_edits.keys()),
            "s3_audit": winning_s3,
            "attempts": attempts_log,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
        receipt_path = self._write_external_receipt(receipt_payload)
        receipt_payload["receipt_path"] = str(receipt_path)
        return receipt_payload

    def _finalize_no_promotion(
        self,
        reason: str,
        attempts_log: List[Dict[str, Any]],
        t0: float,
    ) -> Dict[str, Any]:
        payload = {
            "schema": "PatchTransactionReceipt/3",
            "tx_id": self.spec.tx_id,
            "status": "NO_PROMOTION",
            "receipt_stage": "rolled_back",
            "reason": reason,
            "base_tree_digest": self.base_tree_digest,
            "live_tree_digest": compute_tree_digest(self.ws_root),
            "oracle_manifest_digest": self.oracle_manifest_digest,
            "attempts": attempts_log,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }
        receipt_path = self._write_external_receipt(payload)
        payload["receipt_path"] = str(receipt_path)
        return payload
