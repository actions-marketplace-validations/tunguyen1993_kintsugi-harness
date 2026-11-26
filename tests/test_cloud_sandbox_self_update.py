#!/usr/bin/env python3
"""Unit & security tests for `cloud-sandbox/bootstrap.py`, `cloud-sandbox/evolution_loop.py`, and `cloud-sandbox/kintsugi_sandbox.py` (v3.1.1)."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_DIR = REPO_ROOT / "cloud-sandbox"
SYNTHETIC_RFC1918_IP = ".".join(("10", "254", "99", "42"))


def _load_bootstrap() -> Any:
    spec = importlib.util.spec_from_file_location("kintsugi_cloud_sandbox_bootstrap", str(SANDBOX_DIR / "bootstrap.py"))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _collect_repo_bundle_files(
    *,
    file_overrides: Optional[Dict[str, bytes]] = None,
    manifest_overrides: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, bytes], bytes, str]:
    """Collect live repo `cloud-sandbox/` + `src/kintsugi/*.py` bytes and compute a fresh `manifest.json`."""
    overrides = dict(file_overrides or {})
    entries: Dict[str, bytes] = {}
    for p in sorted(SANDBOX_DIR.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts or p.name in (".DS_Store", "manifest.json", ".kintsugi_sandbox_install.json"):
            continue
        rel_key = p.relative_to(SANDBOX_DIR).as_posix()
        entries[rel_key] = overrides.get(rel_key, p.read_bytes())

    for p in sorted((REPO_ROOT / "src" / "kintsugi").rglob("*.py")):
        if "__pycache__" in p.parts or p.name == ".DS_Store":
            continue
        rel_key = p.relative_to(REPO_ROOT).as_posix()
        entries[rel_key] = overrides.get(rel_key, p.read_bytes())

    caps_doc = json.loads(entries["data/invariant_capsules_v3.json"].decode("utf-8"))
    pits_doc = json.loads(entries["data/low_tier_pitfall_lexicon_v3.json"].decode("utf-8"))
    files_map = {k: hashlib.sha256(v).hexdigest() for k, v in sorted(entries.items())}
    manifest_doc: Dict[str, Any] = {
        "schema": "KintsugiCloudSandboxManifest/1",
        "version": "3.1.1",
        "cloud_sandbox_edition_version": "3.1.1",
        "repo": "https://github.com/tunguyen1993/kintsugi-harness",
        "generated_utc": "2026-01-01T00:00:00Z",
        "capsules_count": len(caps_doc["capsules"]),
        "pitfalls_count": len(pits_doc["entries"]),
        "total_files": len(files_map),
        "files": files_map,
    }
    if manifest_overrides:
        manifest_doc.update(manifest_overrides)
    manifest_bytes = (json.dumps(manifest_doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    return entries, manifest_bytes, manifest_sha


def _build_repo_tar_gz(
    out_path: Path,
    *,
    corrupt_file: str = "",
    inject_member: Optional[Tuple[str, str, bytes]] = None,
) -> str:
    """Create a realistic GitHub archive tar.gz (`kintsugi-harness-main/...`) and return manifest SHA-256."""
    prefix = "kintsugi-harness-main"
    entries, manifest_bytes, manifest_sha = _collect_repo_bundle_files()
    with tarfile.open(out_path, "w:gz") as tf:
        ti_m = tarfile.TarInfo(name=f"{prefix}/cloud-sandbox/manifest.json")
        ti_m.size = len(manifest_bytes)
        tf.addfile(ti_m, io.BytesIO(manifest_bytes))

        for rel_key, data in sorted(entries.items()):
            payload = data + b"\n# tampered\n" if (corrupt_file and rel_key == corrupt_file) else data
            arc_rel = rel_key if rel_key.startswith("src/kintsugi/") else f"cloud-sandbox/{rel_key}"
            ti = tarfile.TarInfo(name=f"{prefix}/{arc_rel}")
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))

        if inject_member is not None:
            kind, name, payload = inject_member
            ti = tarfile.TarInfo(name=name)
            if kind == "symlink":
                ti.type = tarfile.SYMTYPE
                ti.linkname = payload.decode("utf-8")
                tf.addfile(ti)
            else:
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
    return manifest_sha


def _build_repo_zip(out_path: Path) -> str:
    """Create a realistic GitHub archive `.zip` (`kintsugi-harness-main/...`) and return manifest SHA-256."""
    prefix = "kintsugi-harness-main"
    entries, manifest_bytes, manifest_sha = _collect_repo_bundle_files()
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{prefix}/cloud-sandbox/manifest.json", manifest_bytes)
        for rel_key, data in sorted(entries.items()):
            arc_rel = rel_key if rel_key.startswith("src/kintsugi/") else f"cloud-sandbox/{rel_key}"
            zf.writestr(f"{prefix}/{arc_rel}", data)
    return manifest_sha


def _build_flat_standalone_zip(
    out_path: Path,
    *,
    prefix: str = "kintsugi-cloud-sandbox-v3.1.1",
    corrupt_file: str = "",
    extra_members: Sequence[Tuple[str, bytes]] = (),
) -> str:
    """Create a flat standalone offline bundle `.zip` (`<prefix>/kintsugi_sandbox.py`, `<prefix>/manifest.json`, ...)."""
    entries, manifest_bytes, manifest_sha = _collect_repo_bundle_files()
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{prefix}/manifest.json", manifest_bytes)
        for rel_key, data in sorted(entries.items()):
            payload = data + b"\n# tampered\n" if (corrupt_file and rel_key == corrupt_file) else data
            zf.writestr(f"{prefix}/{rel_key}", payload)
        for name, payload in extra_members:
            zf.writestr(name, payload)
    return manifest_sha


class TestCloudSandboxSelfUpdateSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self.boot = _load_bootstrap()
        self.tmp_ctx = tempfile.TemporaryDirectory(prefix="test_cloud_sandbox_upd_")
        self.tmp = Path(self.tmp_ctx.name)

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()

    def test_01_repo_layout_verify_manifest_and_self_test_pass_100(self) -> None:
        res = self.boot.verify_manifest_tree(SANDBOX_DIR, src_root=REPO_ROOT)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "PASS_MANIFEST_VERIFIED")
        self.assertGreaterEqual(res["files_verified"], 80)
        self.assertEqual(res["capsules_count"], 9)
        self.assertEqual(res["pitfalls_count"], 80)

        p_boot = subprocess.run(
            [sys.executable, str(SANDBOX_DIR / "kintsugi_sandbox.py"), "boot"],
            capture_output=True, text=True, check=True,
        )
        j_boot = json.loads(p_boot.stdout)
        self.assertEqual(j_boot["layout"], "github_repo")
        self.assertEqual(j_boot["kintsugi_version"], "3.1.1")
        self.assertEqual(j_boot["capsules_loaded"], 9)
        self.assertEqual(j_boot["pitfalls_loaded"], 80)

        p_st = subprocess.run(
            [sys.executable, str(SANDBOX_DIR / "kintsugi_sandbox.py"), "self-test"],
            capture_output=True, text=True, check=True,
        )
        j_st = json.loads(p_st.stdout)
        self.assertTrue(j_st["ok"], j_st)
        self.assertEqual(j_st["status"], "PASS_100")
        self.assertEqual(j_st["passed"], j_st["total"])
        self.assertGreaterEqual(j_st["passed"], 17)

    def test_02_url_allowlist_ref_and_timeout_validation_fail_closed(self) -> None:
        self.assertTrue(
            self.boot.validate_allowed_https_url(
                "https://github.com/tunguyen1993/kintsugi-harness/archive/refs/heads/main.tar.gz"
            ).startswith("https://")
        )
        self.assertTrue(
            self.boot.validate_allowed_https_url(
                "https://raw.githubusercontent.com/tunguyen1993/kintsugi-harness/main/cloud-sandbox/bootstrap.py"
            ).startswith("https://")
        )
        for bad_url in (
            "http://github.com/tunguyen1993/kintsugi-harness/archive/refs/heads/main.tar.gz",
            "https://evil.example/tunguyen1993/kintsugi-harness/archive/main.tar.gz",
            "https://github.com/otheruser/kintsugi-harness/archive/refs/heads/main.tar.gz",
            "https://github.com:8443/tunguyen1993/kintsugi-harness/archive/refs/heads/main.tar.gz",
            "https://github.com/tunguyen1993/kintsugi-harness/../../attacker/evil/archive/main.tar.gz",
            "https://github.com/tunguyen1993/kintsugi-harness/%2e%2e/%2e%2e/attacker/evil.tar.gz",
            "https://user:pass@github.com/tunguyen1993/kintsugi-harness/archive/refs/heads/main.tar.gz",
            "https://github.com/tunguyen1993/kintsugi-harness/archive/main.tar.gz\r\nX-Inject: 1",
        ):
            with self.assertRaises(ValueError, msg=bad_url):
                self.boot.validate_allowed_https_url(bad_url)

        for bad_ref in ("", "--upload-pack=evil", "../etc/passwd", "main;id", "/main", "main.lock"):
            with self.assertRaises(ValueError, msg=bad_ref):
                self.boot.validate_git_ref(bad_ref)

        # v3.1 full-commit-SHA pinning mode rejects branch/tag/short SHA and accepts 40-hex SHA.
        for non_full_sha in ("main", "v3.1.0", "1a2b3c4"):
            with self.assertRaises(ValueError, msg=non_full_sha) as ctx_sha:
                self.boot.validate_git_ref(non_full_sha, require_full_sha=True)
            self.assertIn("FULL_COMMIT_SHA_REQUIRED", str(ctx_sha.exception))
        full_sha = "0123456789abcdef" * 2 + "01234567"
        self.assertEqual(self.boot.validate_git_ref(full_sha, require_full_sha=True), full_sha)

        for bad_timeout in (0, -1, 999):
            with self.assertRaises(ValueError, msg=str(bad_timeout)) as ctx_to:
                self.boot._validate_timeout(bad_timeout)
            self.assertIn("INVALID_TIMEOUT", str(ctx_to.exception))

    def test_03_tar_slip_symlink_bomb_tamper_and_dest_protection_fail_closed(self) -> None:
        dest = self.tmp / "installed_dot"
        dest.mkdir()
        sentinel = dest / "sentinel.txt"
        sentinel.write_text("original_intact\n", encoding="utf-8")

        # (a) Tar-Slip traversal member rejected without modifying dest
        tar_slip = self.tmp / "slip.tar.gz"
        _build_repo_tar_gz(tar_slip, inject_member=("file", "kintsugi-harness-main/cloud-sandbox/../../escape.py", b"bad"))
        with self.assertRaises(ValueError) as ctx1:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=tar_slip)
        self.assertIn("TAR_SLIP_TRAVERSAL", str(ctx1.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "original_intact\n")

        # (b) Symlink member inside tar rejected fail-closed
        tar_sym = self.tmp / "sym.tar.gz"
        _build_repo_tar_gz(tar_sym, inject_member=("symlink", "kintsugi-harness-main/cloud-sandbox/evil_link", b"/etc/passwd"))
        with self.assertRaises(PermissionError) as ctx2:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=tar_sym)
        self.assertIn("TAR_SYMLINK_REJECTED", str(ctx2.exception))

        # (c) Single tampered byte in any file fails SHA-256 manifest verification without touching dest
        tar_tamper = self.tmp / "tamper.tar.gz"
        _build_repo_tar_gz(tar_tamper, corrupt_file="TASKS.md")
        with self.assertRaises(ValueError) as ctx3:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=tar_tamper)
        self.assertIn("MANIFEST_HASH_MISMATCH", str(ctx3.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "original_intact\n")

        # (d) Unmanifested extra file injection (e.g., sitecustomize.py) fails closed without touching dest
        tar_extra = self.tmp / "extra.tar.gz"
        _build_repo_tar_gz(tar_extra, inject_member=("file", "kintsugi-harness-main/cloud-sandbox/sitecustomize.py", b"x = 1\n"))
        with self.assertRaises(ValueError) as ctx4:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=tar_extra)
        self.assertIn("MANIFEST_UNEXPECTED_EXTRA_FILES", str(ctx4.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "original_intact\n")

        # (e) Gzip decompression bomb (> 64 MiB zero-filled unwanted file) aborts streaming read fail-closed
        tar_bomb = self.tmp / "bomb.tar.gz"
        with tarfile.open(tar_bomb, "w:gz") as tf:
            ti = tarfile.TarInfo(name="kintsugi-harness-main/junk_bomb.bin")
            blob = b"\x00" * (65 * 1024 * 1024)
            ti.size = len(blob)
            tf.addfile(ti, io.BytesIO(blob))
        with self.assertRaises(ValueError) as ctx5:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=tar_bomb)
        self.assertIn("TAR_DECOMPRESSED_LIMIT_EXCEEDED", str(ctx5.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "original_intact\n")

        # (f) Even a valid archive refuses to clobber a non-empty non-Kintsugi project directory!
        good_tar = self.tmp / "good_dest_guard.tar.gz"
        good_sha = _build_repo_tar_gz(good_tar)
        with self.assertRaises(PermissionError) as ctx6:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=good_tar, expected_manifest_sha256=good_sha)
        self.assertIn("REFUSING_NON_KINTSUGI_NONEMPTY_DEST", str(ctx6.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "original_intact\n")

    def test_04_clean_archive_tar_zip_pin_and_standalone_self_test(self) -> None:
        good_tar = self.tmp / "good.tar.gz"
        manifest_sha = _build_repo_tar_gz(good_tar)
        dest = self.tmp / "cloud_kintsugi_sandbox"

        # --require-pin without --expected-manifest-sha256 MUST fail closed
        with self.assertRaises(ValueError) as ctx_pin:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=good_tar, require_pin=True)
        self.assertIn("UNTRUSTED_UPDATE_MANIFEST_PIN_REQUIRED", str(ctx_pin.exception))
        self.assertFalse(dest.exists())

        # Wrong pinned manifest SHA MUST fail closed
        with self.assertRaises(ValueError):
            self.boot.install_or_update(
                ref="main", dest=dest, source_archive=good_tar, expected_manifest_sha256="0" * 64
            )
        self.assertFalse(dest.exists())

        # Exact pinned manifest SHA succeeds atomically, sets trust_mode & install marker, and passes self-test
        res = self.boot.install_or_update(
            ref="main", dest=dest, source_archive=good_tar, expected_manifest_sha256=manifest_sha, require_pin=True
        )
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["status"], "UPDATED_AND_VERIFIED")
        self.assertEqual(res["trust_mode"], "PINNED_MANIFEST_SHA256")
        self.assertTrue(res["smoke_test_passed"])
        self.assertTrue((dest / "kintsugi_sandbox.py").is_file())
        self.assertTrue((dest / "src" / "kintsugi" / "__init__.py").is_file())
        self.assertTrue((dest / ".kintsugi_sandbox_install.json").is_file())

        p_vm = subprocess.run(
            [sys.executable, str(dest / "kintsugi_sandbox.py"), "verify-manifest", "--expected-sha256", manifest_sha],
            capture_output=True, text=True, check=True,
        )
        self.assertTrue(json.loads(p_vm.stdout)["ok"])

        # Planted extra file in standalone bundle MUST fail verify-manifest fail-closed
        rogue = dest / "rogue_extra.py"
        rogue.write_text("x = 1\n", encoding="utf-8")
        p_vm_bad = subprocess.run(
            [sys.executable, str(dest / "kintsugi_sandbox.py"), "verify-manifest"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p_vm_bad.returncode, 0)
        self.assertIn("MANIFEST_UNEXPECTED_EXTRA_FILES", p_vm_bad.stdout)
        rogue.unlink()

        p_st = subprocess.run(
            [sys.executable, str(dest / "kintsugi_sandbox.py"), "self-test"],
            capture_output=True, text=True, check=True,
        )
        j_st = json.loads(p_st.stdout)
        self.assertTrue(j_st["ok"], j_st)
        self.assertEqual(j_st["layout"], "standalone_bundle")
        self.assertEqual(j_st["passed"], j_st["total"])
        self.assertGreaterEqual(j_st["passed"], 17)

        # Updating a pinned Kintsugi install via unpinned `.zip` MUST fail closed unless explicitly opted in.
        good_zip = self.tmp / "good.zip"
        zip_sha = _build_repo_zip(good_zip)
        self.assertEqual(zip_sha, manifest_sha)
        with self.assertRaises(PermissionError) as ctx_dg:
            self.boot.install_or_update(ref="main", dest=dest, source_archive=good_zip)
        self.assertIn("REFUSING_PIN_DOWNGRADE_TO_TOFU", str(ctx_dg.exception))
        marker_pinned = json.loads((dest / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual(marker_pinned["trust_mode"], "PINNED_MANIFEST_SHA256")

        res_zip = self.boot.install_or_update(
            ref="main", dest=dest, source_archive=good_zip, allow_downgrade_to_tofu=True
        )
        self.assertTrue(res_zip["ok"], res_zip)
        self.assertEqual(res_zip["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")
        marker = json.loads((dest / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["manifest_sha256"], zip_sha)
        self.assertEqual(marker["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")
        self.assertEqual(marker["requested_ref"], "main")
        self.assertEqual(marker["verified_commit_sha"], "")

    def test_05_closed_loop_self_evolution_gates_and_cli_e2e(self) -> None:
        evo_store = self.tmp / "sandbox_learned.json"
        tel_store = self.tmp / "sandbox_tel.json"
        imp_store = self.tmp / "sandbox_imported.json"
        patch_out = self.tmp / "sandbox_patch.json"
        sandbox_cli = str(SANDBOX_DIR / "kintsugi_sandbox.py")

        b_bare = self.tmp / "broken_bare.py"
        b_py = self.tmp / "broken.py"
        f_py = self.tmp / "fixed.py"
        t_py = self.tmp / "test_oracle.py"
        # Plant a decoy candidate.py beside test_oracle.py to prove sys.path[0] shadowing is blocked!
        (self.tmp / "candidate.py").write_text("def clean_sku(s):\n    return 'SHADOWED_WRONG'\n", encoding="utf-8")
        b_bare.write_text("def clean_sku(s: str) -> str:\n    return s\n", encoding="utf-8")
        b_py.write_text("def clean_sku(s: str) -> str:\n    return s.lstrip()\n", encoding="utf-8")
        f_py.write_text("def clean_sku(s: str) -> str:\n    return s.strip().upper()\n", encoding="utf-8")
        t_py.write_text("import candidate\nassert candidate.clean_sku(' abc ') == 'ABC'\n", encoding="utf-8")

        # (a) Reject overlapping trigger groups, stopword bloat, and reserved LT-/CAP- prefix
        for args_extra, expect_msg in (
            (["--id", "CSB-OV-1", "--triggers", '[["clean_sku", "sku"], ["sku", "strip"]]'], "OVERLAPPING_TRIGGER_GROUPS"),
            (["--id", "CSB-SW-1", "--triggers", '[["def"], ["return"]]'], "STOPWORD_TRIGGER_REJECTED"),
            (["--id", "LT-999", "--triggers", '[["clean_sku"], ["strip"]]'], "RESERVED_SCAR_PREFIX"),
        ):
            p_rej = subprocess.run(
                [
                    sys.executable, sandbox_cli, "evolve", "learn",
                    "--store", str(evo_store), "--telemetry-store", str(tel_store),
                    "--slug", "bad_case", "--bad", "b", "--good", "g", "--when", "w",
                    "--broken", str(b_py), "--fixed", str(f_py), "--test", str(t_py),
                    *args_extra,
                ],
                capture_output=True, text=True,
            )
            self.assertNotEqual(p_rej.returncode, 0, expect_msg)
            self.assertIn(expect_msg, p_rej.stdout)

        # (b) Reject DLP-tainted scar (synthetic private RFC1918 IP)
        p_dlp = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "learn",
                "--store", str(evo_store), "--telemetry-store", str(tel_store),
                "--id", "CSB-DLP-1", "--slug", "dlp_bad",
                "--triggers", '[["clean_sku"], ["strip"]]',
                "--bad", f"leaked {SYNTHETIC_RFC1918_IP}", "--good", "g", "--when", "w",
                "--broken", str(b_py), "--fixed", str(f_py), "--test", str(t_py),
            ],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p_dlp.returncode, 0)
        self.assertIn("DLP_BLOCKED_LEARNED_SCAR", p_dlp.stdout)

        # (c) Reject Truth Gate cheats: path-name cheat and TabError broken file
        t_cheat = self.tmp / "cheat_oracle.py"
        t_cheat.write_text("import sys\nassert 'fixed' in sys.argv[1]\n", encoding="utf-8")
        p_cheat = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "learn",
                "--store", str(evo_store), "--telemetry-store", str(tel_store),
                "--id", "CSB-CHEAT-1", "--slug", "cheat_proof",
                "--triggers", '[["clean_sku"], ["strip"]]',
                "--bad", "b", "--good", "g", "--when", "w",
                "--broken", str(b_py), "--fixed", str(f_py), "--test", str(t_cheat),
            ],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p_cheat.returncode, 0)
        self.assertIn("REJECTED_BY_UNIVERSAL_TRUTH_GATE", p_cheat.stdout)

        b_tab = self.tmp / "broken_tab.py"
        b_tab.write_text("def clean_sku(s):\n\treturn s\n    return s\n", encoding="utf-8")
        p_tab = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "learn",
                "--store", str(evo_store), "--telemetry-store", str(tel_store),
                "--id", "CSB-TAB-1", "--slug", "tab_err",
                "--triggers", '[["clean_sku"], ["strip"]]',
                "--bad", "b", "--good", "g", "--when", "w",
                "--broken", str(b_tab), "--fixed", str(f_py), "--test", str(t_py),
            ],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p_tab.returncode, 0)
        self.assertIn("REJECTED_BY_UNIVERSAL_TRUTH_GATE", p_tab.stdout)

        # (d) Gate 4 Matcher-on-Broken: bare `return s` with `[["clean_sku"], ["lstrip", "swapcase"]]` MUST fail closed!
        p_miss = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "learn",
                "--store", str(evo_store), "--telemetry-store", str(tel_store),
                "--id", "CSB-SKU-MISS", "--slug", "clean_sku_miss",
                "--category", "logic", "--languages", "python", "--role", "detect_bug",
                "--triggers", '[["clean_sku"], ["lstrip", "swapcase"]]',
                "--bad", "Skipping strip and upper on SKU",
                "--good", "Normalize SKU via s.strip().upper()",
                "--when", "Normalizing product SKU identifiers",
                "--broken", str(b_bare), "--fixed", str(f_py), "--test", str(t_py),
            ],
            capture_output=True, text=True,
        )
        self.assertNotEqual(p_miss.returncode, 0)
        self.assertIn("REJECTED_TRIGGERS_MISS_BROKEN_REPRO", p_miss.stdout)

        # (e) Genuine buggy `broken.py` (`s.lstrip()` missing full strip + upper) promotes cleanly even with decoy candidate.py!
        p_ok = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "learn",
                "--store", str(evo_store), "--telemetry-store", str(tel_store),
                "--id", "CSB-SKU-001", "--slug", "clean_sku_norm",
                "--category", "logic", "--languages", "python", "--role", "detect_bug",
                "--triggers", '[["clean_sku"], ["lstrip", "swapcase"]]',
                "--bad", "Calling lstrip without full strip and uppercase on SKU",
                "--good", "Normalize SKU via s.strip().upper()",
                "--when", "Normalizing product SKU identifiers",
                "--broken", str(b_py), "--fixed", str(f_py), "--test", str(t_py),
            ],
            capture_output=True, text=True, check=True,
        )
        j_ok = json.loads(p_ok.stdout)
        self.assertTrue(j_ok["ok"])
        self.assertEqual(j_ok["status"], "PROMOTED_TO_LIVE_EVOLUTION_STORE")

        # (f) Tampered unverified/empty-trigger record injected into store MUST be ignored by brief & status
        raw_store = json.loads(evo_store.read_text(encoding="utf-8"))
        raw_store["scars"].append({
            "id": "csb-tamper-1",
            "slug": "tampered_bloat",
            "category": "logic",
            "languages": ["python"],
            "role": "detect_bug",
            "trigger_groups": [],
            "bad_pattern": "x",
            "good_pattern": "y",
            "precondition": "z",
            "compact": "TAMPERED",
            "truth_gate_proof": {"verdict": "PROMOTE_ELIGIBLE"},
        })
        evo_store.write_text(json.dumps(raw_store), encoding="utf-8")

        benign_py = self.tmp / "benign.py"
        benign_py.write_text("from dataclasses import dataclass\n@dataclass\nclass P:\n    x: int\n", encoding="utf-8")
        p_ben = subprocess.run(
            [
                sys.executable, sandbox_cli, "brief", str(benign_py),
                "--evolution-store", str(evo_store), "--telemetry-store", str(tel_store), "--no-telemetry",
            ],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(json.loads(p_ben.stdout)["matched_pitfalls_count"], 0)

        # Live brief injection hits CSB-SKU-001 immediately on matching source
        sample_py = self.tmp / "sku_caller.py"
        sample_py.write_text("def clean_sku(v):\n    return v.lstrip()\n", encoding="utf-8")
        p_br = subprocess.run(
            [
                sys.executable, sandbox_cli, "brief", str(sample_py),
                "--evolution-store", str(evo_store), "--telemetry-store", str(tel_store), "--no-telemetry",
            ],
            capture_output=True, text=True, check=True,
        )
        br_ids = [e["id"] for e in json.loads(p_br.stdout)["pitfalls"]]
        self.assertIn("CSB-SKU-001", br_ids)

        # Status reports 1 active & 1 rejected_invalid; export-patch + import-patch round-trip succeeds idempotently
        p_st = subprocess.run(
            [sys.executable, sandbox_cli, "evolve", "status", "--store", str(evo_store), "--telemetry-store", str(tel_store)],
            capture_output=True, text=True, check=True,
        )
        j_evo_st = json.loads(p_st.stdout)
        self.assertEqual(j_evo_st["active_learned_count"], 1)
        self.assertEqual(j_evo_st["rejected_invalid_count"], 1)

        p_ex = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "export-patch",
                "--store", str(evo_store), "--telemetry-store", str(tel_store),
                "--out", str(patch_out),
            ],
            capture_output=True, text=True, check=True,
        )
        j_ex = json.loads(p_ex.stdout)
        self.assertTrue(j_ex["ok"])
        self.assertEqual(j_ex["scars_count"], 1)
        self.assertTrue(patch_out.is_file())

        # Default import-patch stages safely into quarantine; explicit --apply merges live idempotently.
        p_imp_q = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "import-patch",
                "--file", str(patch_out),
                "--store", str(imp_store), "--telemetry-store", str(tel_store),
                "--expected-sha256", j_ex["patch_sha256"],
            ],
            capture_output=True, text=True, check=True,
        )
        j_imp_q = json.loads(p_imp_q.stdout)
        self.assertTrue(j_imp_q["ok"])
        self.assertEqual(j_imp_q["status"], "QUARANTINED_EVOLUTION_PATCH")
        self.assertEqual(j_imp_q["imported"], 1)
        self.assertFalse(imp_store.exists())

        p_imp1 = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "import-patch",
                "--file", str(patch_out),
                "--store", str(imp_store), "--telemetry-store", str(tel_store),
                "--expected-sha256", j_ex["patch_sha256"],
                "--apply",
            ],
            capture_output=True, text=True, check=True,
        )
        j_imp1 = json.loads(p_imp1.stdout)
        self.assertTrue(j_imp1["ok"])
        self.assertEqual(j_imp1["status"], "IMPORTED_EVOLUTION_PATCH")
        self.assertEqual(j_imp1["imported"], 1)
        self.assertEqual(j_imp1["already_present"], 0)

        p_imp2 = subprocess.run(
            [
                sys.executable, sandbox_cli, "evolve", "import-patch",
                "--file", str(patch_out),
                "--store", str(imp_store), "--telemetry-store", str(tel_store),
                "--expected-sha256", j_ex["patch_sha256"],
                "--apply",
            ],
            capture_output=True, text=True, check=True,
        )
        j_imp2 = json.loads(p_imp2.stdout)
        self.assertTrue(j_imp2["ok"])
        self.assertEqual(j_imp2["imported"], 0)
        self.assertEqual(j_imp2["already_present"], 1)

    def test_06_v311_bootstrap_hardening_self_sha_dest_guards_and_flat_zip(self) -> None:
        good_tar = self.tmp / "v311_good.tar.gz"
        sha = _build_repo_tar_gz(good_tar)
        boot_cli = str(SANDBOX_DIR / "bootstrap.py")
        actual_boot_sha = hashlib.sha256((SANDBOX_DIR / "bootstrap.py").read_bytes()).hexdigest()

        # (a) verify_self_sha256 and CLI --expected-bootstrap-sha256
        self.assertEqual(self.boot.verify_self_sha256(actual_boot_sha), actual_boot_sha)
        with self.assertRaises(ValueError) as ctx_bsha:
            self.boot.verify_self_sha256("0" * 64)
        self.assertIn("BOOTSTRAP_SELF_SHA256_MISMATCH", str(ctx_bsha.exception))

        dest_cli = self.tmp / "cli_boot_sha_dest"
        p_bad_bsha = subprocess.run(
            [
                sys.executable, boot_cli, "--dest", str(dest_cli), "--source-archive", str(good_tar),
                "--expected-manifest-sha256", sha, "--expected-bootstrap-sha256", "0" * 64,
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(p_bad_bsha.returncode, 0)
        self.assertIn("BOOTSTRAP_SELF_SHA256_MISMATCH", p_bad_bsha.stdout)
        self.assertFalse(dest_cli.exists())

        p_ok_bsha = subprocess.run(
            [
                sys.executable, boot_cli, "--dest", str(dest_cli), "--source-archive", str(good_tar),
                "--expected-manifest-sha256", sha, "--require-pin",
                "--expected-bootstrap-sha256", actual_boot_sha,
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(p_ok_bsha.returncode, 0, p_ok_bsha.stdout + p_ok_bsha.stderr)
        self.assertTrue(json.loads(p_ok_bsha.stdout)["ok"])

        # CLI pin downgrade refusal vs explicit --allow-unpinned-downgrade
        p_dg_blk = subprocess.run(
            [sys.executable, boot_cli, "--dest", str(dest_cli), "--source-archive", str(good_tar)],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(p_dg_blk.returncode, 0)
        self.assertIn("REFUSING_PIN_DOWNGRADE_TO_TOFU", p_dg_blk.stdout)

        p_dg_ok = subprocess.run(
            [
                sys.executable, boot_cli, "--dest", str(dest_cli), "--source-archive", str(good_tar),
                "--allow-unpinned-downgrade",
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(p_dg_ok.returncode, 0, p_dg_ok.stdout + p_dg_ok.stderr)
        self.assertEqual(json.loads(p_dg_ok.stdout)["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")

        # (b) REFUSING_GIT_CHECKOUT_DEST on repo root (.git), <repo>/cloud-sandbox, and ANY <repo>/<custom_dir> (../.git)
        fake_repo = self.tmp / "fake_git_repo"
        (fake_repo / ".git").mkdir(parents=True)
        (fake_repo / "cloud-sandbox").mkdir()
        (fake_repo / "custom_dir").mkdir()
        for git_dest in (fake_repo, fake_repo / "cloud-sandbox", fake_repo / "custom_dir", fake_repo / "uncreated_custom_dir"):
            with self.assertRaises(PermissionError, msg=str(git_dest)) as ctx_git:
                self.boot.install_or_update(
                    ref="main", dest=git_dest, source_archive=good_tar, expected_manifest_sha256=sha
                )
            self.assertIn("REFUSING_GIT_CHECKOUT_DEST", str(ctx_git.exception))

        # (c) REFUSING_NON_KINTSUGI_NONEMPTY_DEST when dest has bare kintsugi_sandbox.py + manifest.json without valid marker
        bare_dest = self.tmp / "bare_non_marker"
        bare_dest.mkdir()
        (bare_dest / "kintsugi_sandbox.py").write_text("# user file\n", encoding="utf-8")
        (bare_dest / "manifest.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_nm:
            self.boot.install_or_update(ref="main", dest=bare_dest, source_archive=good_tar, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_NON_KINTSUGI_NONEMPTY_DEST", str(ctx_nm.exception))

        (bare_dest / ".kintsugi_sandbox_install.json").write_text('{"schema":"WrongMarker/1"}\n', encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_ws:
            self.boot.install_or_update(ref="main", dest=bare_dest, source_archive=good_tar, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_NON_KINTSUGI_NONEMPTY_DEST", str(ctx_ws.exception))

        # (d) REFUSING_DEST_WITH_USER_FILES preserves extra user file untouched
        user_file = dest_cli / "my_notes.txt"
        user_file.write_text("user_data_must_survive\n", encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_uf:
            self.boot.install_or_update(ref="main", dest=dest_cli, source_archive=good_tar, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_DEST_WITH_USER_FILES", str(ctx_uf.exception))
        self.assertEqual(user_file.read_text(encoding="utf-8"), "user_data_must_survive\n")
        user_file.unlink()

        # (e) Flat standalone offline bundle ZIP installs cleanly and rejects tamper / extra files
        flat_zip = self.tmp / "flat_standalone.zip"
        flat_sha = _build_flat_standalone_zip(flat_zip)
        self.assertEqual(flat_sha, sha)
        flat_dest = self.tmp / "flat_dest"
        res_flat = self.boot.install_or_update(
            ref="main", dest=flat_dest, source_archive=flat_zip, expected_manifest_sha256=flat_sha, require_pin=True
        )
        self.assertTrue(res_flat["ok"], res_flat)
        self.assertTrue(res_flat["smoke_test_passed"])

        flat_tamper = self.tmp / "flat_tamper.zip"
        _build_flat_standalone_zip(flat_tamper, corrupt_file="TASKS.md")
        with self.assertRaises(ValueError) as ctx_ft:
            self.boot.install_or_update(ref="main", dest=self.tmp / "flat_t", source_archive=flat_tamper)
        self.assertIn("MANIFEST_HASH_MISMATCH", str(ctx_ft.exception))

        flat_extra = self.tmp / "flat_extra.zip"
        _build_flat_standalone_zip(flat_extra, extra_members=[("kintsugi-cloud-sandbox-v3.1.1/rogue_extra.py", b"x = 1\n")])
        with self.assertRaises(ValueError) as ctx_fe:
            self.boot.install_or_update(ref="main", dest=self.tmp / "flat_e", source_archive=flat_extra)
        self.assertIn("MANIFEST_UNEXPECTED_EXTRA_FILES", str(ctx_fe.exception))

        # (f) requested_ref vs verified_commit_sha recorded separately
        full_sha = "0123456789abcdef" * 2 + "01234567"
        dest_loc_sha = self.tmp / "loc_sha_dest"
        res_loc = self.boot.install_or_update(
            ref=full_sha, dest=dest_loc_sha, source_archive=good_tar,
            expected_manifest_sha256=sha, require_pin=True, require_full_sha=True,
        )
        self.assertEqual((res_loc["requested_ref"], res_loc["verified_commit_sha"]), (full_sha, ""))
        loc_marker = json.loads((dest_loc_sha / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual((loc_marker["requested_ref"], loc_marker["verified_commit_sha"]), (full_sha, ""))

        dest_https_sha = self.tmp / "https_sha_dest"
        with mock.patch.object(self.boot, "_download_bounded_bytes", return_value=good_tar.read_bytes()):
            res_https = self.boot.install_or_update(
                ref=full_sha, dest=dest_https_sha, expected_manifest_sha256=sha,
                require_pin=True, require_full_sha=True, run_post_stage_smoke=False,
            )
        self.assertEqual((res_https["requested_ref"], res_https["verified_commit_sha"]), (full_sha, full_sha))
        https_marker = json.loads((dest_https_sha / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual((https_marker["requested_ref"], https_marker["verified_commit_sha"]), (full_sha, full_sha))

        # (g) sys.dont_write_bytecode is True in isolated imports of bootstrap and kintsugi_sandbox
        for mod_name in ("bootstrap", "kintsugi_sandbox"):
            p_bc = subprocess.run(
                [
                    sys.executable, "-c",
                    f"import sys; sys.path.insert(0, {str(SANDBOX_DIR)!r}); import {mod_name}; assert sys.dont_write_bytecode is True",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(p_bc.returncode, 0, f"{mod_name}: {p_bc.stderr}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
