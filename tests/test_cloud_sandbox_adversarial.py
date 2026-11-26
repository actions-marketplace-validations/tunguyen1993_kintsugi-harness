#!/usr/bin/env python3
"""Adversarial regression suite for Kintsugi Harness — Cloud Sandbox Edition v3.1.1.

100% pure Python 3.9+ stdlib, zero external secrets, zero private host paths,
and self-contained (synthetic manifests are generated dynamically from live repo files).
Covers every security boundary across:
  1. Supply-chain & Bootstrap (`bootstrap.py`)
  2. Universal Truth Gate & Self-Evolution (`truth_gate.py`, `evolution_loop.py`)
  3. Dual-Engine Scanner, Matcher, Tx-Guard, Decimal Ledger, Brief, Auto-Telemetry,
     Deliverable Hygiene Audit, and DLP Compact (`scanner_sandbox.py`, `kintsugi_sandbox.py`).
"""

from __future__ import annotations

import errno
import hashlib
import importlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SANDBOX_DIR = REPO_ROOT / "cloud-sandbox"
SRC_DIR = REPO_ROOT / "src"

for _p in (SANDBOX_DIR, SRC_DIR):
    if _p.is_dir() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
os.environ.setdefault("KINTSUGI_DISABLE_NATIVE", "1")

bootstrap_mod = importlib.import_module("bootstrap")
evolution_mod = importlib.import_module("evolution_loop")
kintsugi_sandbox_mod = importlib.import_module("kintsugi_sandbox")
scanner_mod = importlib.import_module("scanner_sandbox")
security_io_mod = importlib.import_module("security_io")
truth_gate_mod = importlib.import_module("truth_gate")
telemetry_mod = importlib.import_module("kintsugi.evolution.delivery_telemetry")

# Synthetic negative-control tokens assembled dynamically so static DLP scanners pass 100%.
SYNTH_RFC1918_IP = ".".join(("10", "254", "99", "42"))
SYNTH_API_SECRET = "sk-" + "live-" + "AbCdEf1234567890"
SANDBOX_CLI = str(SANDBOX_DIR / "kintsugi_sandbox.py")
BOOT_CLI = str(SANDBOX_DIR / "bootstrap.py")


def _compute_bundle_manifest(
    *,
    file_overrides: Optional[Dict[str, bytes]] = None,
    manifest_overrides: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, bytes], bytes, str]:
    overrides = dict(file_overrides or {})
    entries: Dict[str, bytes] = {}
    for p in sorted(SANDBOX_DIR.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts or p.name in (".DS_Store", "manifest.json", ".kintsugi_sandbox_install.json"):
            continue
        rel = p.relative_to(SANDBOX_DIR).as_posix()
        entries[rel] = overrides.get(rel, p.read_bytes())
    for p in sorted((REPO_ROOT / "src" / "kintsugi").rglob("*.py")):
        if "__pycache__" in p.parts or p.name == ".DS_Store":
            continue
        rel = p.relative_to(REPO_ROOT).as_posix()
        entries[rel] = overrides.get(rel, p.read_bytes())

    caps = json.loads(entries["data/invariant_capsules_v3.json"].decode("utf-8"))["capsules"]
    pits = json.loads(entries["data/low_tier_pitfall_lexicon_v3.json"].decode("utf-8"))["entries"]
    fmap = {k: hashlib.sha256(v).hexdigest() for k, v in sorted(entries.items())}
    mdoc: Dict[str, Any] = {
        "schema": "KintsugiCloudSandboxManifest/1",
        "version": "3.1.1",
        "cloud_sandbox_edition_version": "3.1.1",
        "repo": "https://github.com/tunguyen1993/kintsugi-harness",
        "generated_utc": "2026-01-01T00:00:00Z",
        "capsules_count": len(caps),
        "pitfalls_count": len(pits),
        "total_files": len(fmap),
        "files": fmap,
    }
    if manifest_overrides:
        mdoc.update(manifest_overrides)
    mbytes = (json.dumps(mdoc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return entries, mbytes, hashlib.sha256(mbytes).hexdigest()


def _build_synthetic_archive(
    out_path: Path,
    *,
    fmt: str = "tar.gz",
    prefix: str = "kintsugi-harness-main",
    file_overrides: Optional[Dict[str, bytes]] = None,
    manifest_overrides: Optional[Dict[str, Any]] = None,
    corrupt_file: str = "",
    extra_members: Sequence[Tuple[str, str, bytes]] = (),
) -> str:
    entries, mbytes, msha = _compute_bundle_manifest(
        file_overrides=file_overrides, manifest_overrides=manifest_overrides
    )
    items: List[Tuple[str, bytes]] = [(f"{prefix}/cloud-sandbox/manifest.json", mbytes)]
    for rel, data in sorted(entries.items()):
        payload = data + b"\n# tampered\n" if (corrupt_file and rel == corrupt_file) else data
        arc_rel = rel if rel.startswith("src/kintsugi/") else f"cloud-sandbox/{rel}"
        items.append((f"{prefix}/{arc_rel}", payload))

    if fmt == "tar.gz":
        with tarfile.open(out_path, "w:gz") as tf:
            for arcname, payload in items:
                ti = tarfile.TarInfo(name=arcname)
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
            for kind, name, payload in extra_members:
                ti = tarfile.TarInfo(name=name)
                if kind == "symlink":
                    ti.type, ti.linkname = tarfile.SYMTYPE, payload.decode("utf-8")
                    tf.addfile(ti)
                else:
                    ti.size = len(payload)
                    tf.addfile(ti, io.BytesIO(payload))
    elif fmt == "zip":
        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for arcname, payload in items:
                zf.writestr(arcname, payload)
            for kind, name, payload in extra_members:
                zi = zipfile.ZipInfo(filename=name)
                zi.external_attr = (0o120777 << 16) if kind == "symlink" else (0o100644 << 16)
                zf.writestr(zi, payload)
    else:
        raise ValueError(f"Unsupported fmt: {fmt}")
    return msha


def _build_flat_standalone_zip(
    out_path: Path,
    *,
    prefix: str = "kintsugi-cloud-sandbox-v3.1.1",
    corrupt_file: str = "",
    extra_members: Sequence[Tuple[str, bytes]] = (),
) -> str:
    entries, mbytes, msha = _compute_bundle_manifest()
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{prefix}/manifest.json", mbytes)
        for rel, data in sorted(entries.items()):
            payload = data + b"\n# tampered\n" if (corrupt_file and rel == corrupt_file) else data
            zf.writestr(f"{prefix}/{rel}", payload)
        for name, payload in extra_members:
            zf.writestr(name, payload)
    return msha


def _run_sandbox_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, SANDBOX_CLI, *args], capture_output=True, text=True, check=False)


def _record_two_strike_freeze(tel_store: Path, item_id: str, prefix: str = "frz") -> None:
    client = kintsugi_sandbox_mod.DEFAULT_TELEMETRY_CLIENT
    for i in (1, 2):
        telemetry_mod.record_telemetry_event(
            tel_store, client=client, stage="issued", session_id=f"{prefix}-s{i}",
            envelope_id=f"{prefix}-e{i}", source_digest="d0", pitfall_ids=[item_id],
        )
        telemetry_mod.record_telemetry_event(
            tel_store, client=client, stage="included_in_input",
            session_id=f"{prefix}-s{i}", envelope_id=f"{prefix}-e{i}",
        )
        telemetry_mod.record_telemetry_event(
            tel_store, client=client, stage="patch_bound",
            session_id=f"{prefix}-s{i}", envelope_id=f"{prefix}-e{i}",
            patch_digest=f"{prefix}-p{i}", passed=False,
        )


# ===========================================================================
# 1. Supply-Chain & Bootstrap Adversarial Tests (`bootstrap.py`)
# ===========================================================================


class TestBootstrapSupplyChainAdversarial(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_ctx = tempfile.TemporaryDirectory(prefix="kintsugi_adv_boot_")
        self.tmp = Path(self.tmp_ctx.name)

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()

    def test_01_require_pin_require_full_sha_and_trust_mode_honesty(self) -> None:
        tar_p = self.tmp / "valid.tar.gz"
        sha = _build_synthetic_archive(tar_p, fmt="tar.gz")
        dest_pin, dest_tofu = self.tmp / "dest_pin", self.tmp / "dest_tofu"

        with self.assertRaises(ValueError) as ctx:
            bootstrap_mod.install_or_update(ref="main", dest=dest_pin, source_archive=tar_p, require_pin=True)
        self.assertIn("UNTRUSTED_UPDATE_MANIFEST_PIN_REQUIRED", str(ctx.exception))

        for cmd in (
            [sys.executable, BOOT_CLI, "--dest", str(dest_pin), "--source-archive", str(tar_p), "--require-pin"],
            [sys.executable, SANDBOX_CLI, "update", "--dest", str(dest_pin), "--source-archive", str(tar_p), "--require-pin"],
        ):
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("UNTRUSTED_UPDATE_MANIFEST_PIN_REQUIRED", proc.stdout)

        for bad_ref in ("main", "v3.1.1", "abcdef1"):
            with self.assertRaises(ValueError, msg=bad_ref) as ctx_s:
                bootstrap_mod.install_or_update(
                    ref=bad_ref, dest=dest_pin, source_archive=tar_p,
                    expected_manifest_sha256=sha, require_full_sha=True,
                )
            self.assertIn("FULL_COMMIT_SHA_REQUIRED", str(ctx_s.exception))

        full_sha = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        res_pin = bootstrap_mod.install_or_update(
            ref=full_sha, dest=dest_pin, source_archive=tar_p,
            expected_manifest_sha256=sha, require_pin=True, require_full_sha=True,
        )
        self.assertTrue(res_pin["ok"])
        self.assertEqual(res_pin["trust_mode"], "PINNED_MANIFEST_SHA256")
        self.assertEqual(json.loads((dest_pin / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))["trust_mode"], "PINNED_MANIFEST_SHA256")

        res_tofu = bootstrap_mod.install_or_update(ref="main", dest=dest_tofu, source_archive=tar_p)
        self.assertTrue(res_tofu["ok"])
        self.assertEqual(res_tofu["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")
        self.assertEqual(json.loads((dest_tofu / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")

    def test_02_offline_tar_gz_zip_and_unknown_archive_magic(self) -> None:
        tar_p, zip_p = self.tmp / "bundle.tar.gz", self.tmp / "bundle.zip"
        tar_sha = _build_synthetic_archive(tar_p, fmt="tar.gz")
        zip_sha = _build_synthetic_archive(zip_p, fmt="zip")
        self.assertEqual(tar_sha, zip_sha)

        for label, arc_p, sha in (("tar.gz", tar_p, tar_sha), ("zip", zip_p, zip_sha)):
            dest = self.tmp / f"inst_{label}"
            res = bootstrap_mod.install_or_update(
                ref="main", dest=dest, source_archive=arc_p, expected_manifest_sha256=sha, require_pin=True
            )
            self.assertTrue(res["ok"], label)
            self.assertEqual(res["status"], "UPDATED_AND_VERIFIED")
            self.assertTrue(res["smoke_test_passed"])

        bad_magic = self.tmp / "unknown.bin"
        bad_magic.write_bytes(b"Rar!\x1a\x07\x00not_a_tar_or_zip")
        dest_bad = self.tmp / "inst_bad"
        with self.assertRaises(ValueError) as ctx_m:
            bootstrap_mod.install_or_update(ref="main", dest=dest_bad, source_archive=bad_magic)
        self.assertIn("UNSUPPORTED_ARCHIVE_FORMAT", str(ctx_m.exception))
        self.assertFalse(dest_bad.exists())

    def test_03_archive_slip_symlinks_multiroot_and_unicode_casefold_dups(self) -> None:
        dest = self.tmp / "untouched_dest"
        dest.mkdir()
        sentinel = dest / "keep.txt"
        sentinel.write_text("intact_sentinel\n", encoding="utf-8")

        nfc = "kintsugi-harness-main/cloud-sandbox/caf\u00e9.txt"
        nfd_up = "kintsugi-harness-main/cloud-sandbox/CAFE\u0301.txt"
        attacks: List[Tuple[str, str, Sequence[Tuple[str, str, bytes]], Any, str]] = [
            ("tar_slip", "tar.gz", [("file", "kintsugi-harness-main/cloud-sandbox/../../evil.py", b"x=1")], ValueError, "TAR_SLIP_TRAVERSAL"),
            ("zip_slip", "zip", [("file", "kintsugi-harness-main/cloud-sandbox/../../evil.py", b"x=1")], ValueError, "ZIP_SLIP_TRAVERSAL"),
            ("tar_sym", "tar.gz", [("symlink", "kintsugi-harness-main/cloud-sandbox/bad_link", b"/etc/passwd")], PermissionError, "TAR_SYMLINK_REJECTED"),
            ("zip_sym", "zip", [("symlink", "kintsugi-harness-main/cloud-sandbox/bad_link", b"/etc/passwd")], PermissionError, "ZIP_SYMLINK_REJECTED"),
            ("tar_multiroot", "tar.gz", [("file", "other-root/cloud-sandbox/x.txt", b"hi")], ValueError, "TAR_INCONSISTENT_ROOT_PREFIX"),
            ("zip_multiroot", "zip", [("file", "other-root/cloud-sandbox/x.txt", b"hi")], ValueError, "ZIP_INCONSISTENT_ROOT_PREFIX"),
            ("tar_unicode_dup", "tar.gz", [("file", nfc, b"a"), ("file", nfd_up, b"b")], ValueError, "TAR_DUPLICATE_MEMBER"),
            ("zip_unicode_dup", "zip", [("file", nfc, b"a"), ("file", nfd_up, b"b")], ValueError, "ZIP_DUPLICATE_MEMBER"),
        ]
        for label, fmt, members, exc_cls, code in attacks:
            with self.subTest(case=label):
                arc_p = self.tmp / f"{label}.{fmt}"
                _build_synthetic_archive(arc_p, fmt=fmt, extra_members=members)
                with self.assertRaises(exc_cls) as ctx:
                    bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=arc_p)
                self.assertIn(code, str(ctx.exception))
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "intact_sentinel\n")

    def test_04_decompression_bombs_65mib_and_over_4000_members_tar_and_zip(self) -> None:
        dest = self.tmp / "bomb_dest"
        dest.mkdir()
        sentinel = dest / "sentinel.txt"
        sentinel.write_text("still_here\n", encoding="utf-8")
        bomb_blob = b"\x00" * (65 * 1024 * 1024)

        tar_bomb = self.tmp / "bomb65.tar.gz"
        with tarfile.open(tar_bomb, "w:gz") as tf:
            ti = tarfile.TarInfo(name="kintsugi-harness-main/bomb.bin")
            ti.size = len(bomb_blob)
            tf.addfile(ti, io.BytesIO(bomb_blob))
        with self.assertRaises(ValueError) as ctx_tb:
            bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=tar_bomb)
        self.assertIn("TAR_DECOMPRESSED_LIMIT_EXCEEDED", str(ctx_tb.exception))

        zip_bomb = self.tmp / "bomb65.zip"
        with zipfile.ZipFile(zip_bomb, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("kintsugi-harness-main/bomb.bin", bomb_blob)
        with self.assertRaises(ValueError) as ctx_zb:
            bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=zip_bomb)
        self.assertIn("ZIP_DECOMPRESSED_LIMIT_EXCEEDED", str(ctx_zb.exception))

        tar_many = self.tmp / "many4001.tar.gz"
        with tarfile.open(tar_many, "w:gz") as tf:
            for idx in range(4001):
                ti = tarfile.TarInfo(name=f"kintsugi-harness-main/docs/m_{idx:04d}.txt")
                ti.size = 0
                tf.addfile(ti, io.BytesIO(b""))
        with self.assertRaises(ValueError) as ctx_tm:
            bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=tar_many)
        self.assertIn("TAR_TOO_MANY_MEMBERS", str(ctx_tm.exception))

        zip_many = self.tmp / "many4001.zip"
        with zipfile.ZipFile(zip_many, "w", compression=zipfile.ZIP_STORED) as zf:
            for idx in range(4001):
                zf.writestr(f"kintsugi-harness-main/docs/m_{idx:04d}.txt", b"")
        with self.assertRaises(ValueError) as ctx_zm:
            bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=zip_many)
        self.assertIn("ZIP_TOO_MANY_MEMBERS", str(ctx_zm.exception))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "still_here\n")

    def test_05_tamper_extra_file_empty_dir_pycache_sneaky_and_count_mismatch(self) -> None:
        dest = self.tmp / "manifest_dest"
        bad_cases: List[Tuple[str, Dict[str, Any], str]] = [
            ("tamper", {"corrupt_file": "TASKS.md"}, "MANIFEST_HASH_MISMATCH"),
            ("extra_file", {"extra_members": [("file", "kintsugi-harness-main/cloud-sandbox/sitecustomize.py", b"x=1\n")]}, "MANIFEST_UNEXPECTED_EXTRA_FILES"),
            ("bad_caps", {"manifest_overrides": {"capsules_count": 999}}, "MANIFEST_CAPSULES_COUNT_MISMATCH"),
            ("bad_pits", {"manifest_overrides": {"pitfalls_count": 123}}, "MANIFEST_PITFALLS_COUNT_MISMATCH"),
        ]
        for label, kw, code in bad_cases:
            arc_p = self.tmp / f"{label}.tar.gz"
            _build_synthetic_archive(arc_p, fmt="tar.gz", **kw)
            with self.assertRaises(ValueError, msg=label) as ctx:
                bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=arc_p)
            self.assertIn(code, str(ctx.exception))

        p_ok = self.tmp / "clean.tar.gz"
        sha = _build_synthetic_archive(p_ok, fmt="tar.gz")
        self.assertTrue(bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=p_ok, expected_manifest_sha256=sha)["ok"])

        pycache = dest / "__pycache__"
        pycache.mkdir(exist_ok=True)
        (pycache / "kintsugi_sandbox.cpython-311.pyc").write_bytes(b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError) as ctx_pyc:
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True)
        self.assertIn("UNVERIFIED_BYTECODE_REJECTED:__pycache__", str(ctx_pyc.exception))
        self.assertTrue(
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True, allow_pycache=True)["ok"]
        )

        sneaky = pycache / "evil_payload.py"
        sneaky.write_text("x = 1\n", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx_sn:
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True, allow_pycache=True)
        self.assertIn("__pycache__/evil_payload.py", str(ctx_sn.exception))
        shutil.rmtree(pycache)

        (dest / "stray_empty_dir").mkdir()
        with self.assertRaises(ValueError) as ctx_ed:
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True)
        self.assertIn("UNEXPECTED_DIR:stray_empty_dir", str(ctx_ed.exception))

    def test_06_non_bundle_symlink_outside_scope_does_not_break_update(self) -> None:
        for fmt in ("tar.gz", "zip"):
            arc_p = self.tmp / f"out_sym.{fmt}"
            sha = _build_synthetic_archive(
                arc_p, fmt=fmt, extra_members=[("symlink", "kintsugi-harness-main/docs/readme_link", b"../README.md")]
            )
            dest = self.tmp / f"dest_out_sym_{fmt}"
            res = bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=arc_p, expected_manifest_sha256=sha)
            self.assertTrue(res["ok"], fmt)
            self.assertFalse((dest / "docs").exists())

    def test_07_dest_safety_and_existing_install_atomic_upgrade(self) -> None:
        good_tar = self.tmp / "good.tar.gz"
        sha = _build_synthetic_archive(good_tar, fmt="tar.gz")

        user_proj = self.tmp / "user_project"
        user_proj.mkdir()
        app_py, readme_md = user_proj / "app.py", user_proj / "README.md"
        app_py.write_text("print('important user code')\n", encoding="utf-8")
        readme_md.write_text("# User Project\n", encoding="utf-8")

        with self.assertRaises(PermissionError) as ctx_proj:
            bootstrap_mod.install_or_update(ref="main", dest=user_proj, source_archive=good_tar, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_NON_KINTSUGI_NONEMPTY_DEST", str(ctx_proj.exception))
        self.assertEqual(app_py.read_text(encoding="utf-8"), "print('important user code')\n")
        self.assertEqual(readme_md.read_text(encoding="utf-8"), "# User Project\n")
        self.assertFalse((user_proj / "kintsugi_sandbox.py").exists())

        sym_dest = self.tmp / "sym_dest"
        sym_dest.symlink_to(user_proj)
        with self.assertRaises(PermissionError) as ctx_sd:
            bootstrap_mod.install_or_update(ref="main", dest=sym_dest, source_archive=good_tar, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_SYMLINK_DEST", str(ctx_sd.exception))

        valid_dest = self.tmp / "valid_kintsugi_install"
        self.assertTrue(bootstrap_mod.install_or_update(ref="main", dest=valid_dest, source_archive=good_tar, expected_manifest_sha256=sha)["ok"])
        self.assertTrue(bootstrap_mod.install_or_update(ref="v3.1.1", dest=valid_dest, source_archive=good_tar, expected_manifest_sha256=sha)["ok"])
        marker = json.loads((valid_dest / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["schema"], "KintsugiSandboxInstallMarker/1")
        self.assertEqual(marker["ref"], "v3.1.1")
        self.assertEqual(marker["manifest_sha256"], sha)
        self.assertEqual([p.name for p in self.tmp.iterdir() if ".old." in p.name or ".failed." in p.name], [])

    def test_08_post_stage_smoke_failure_aborts_before_swap(self) -> None:
        good_tar = self.tmp / "good_live.tar.gz"
        good_sha = _build_synthetic_archive(good_tar, fmt="tar.gz")
        dest = self.tmp / "live_install"
        self.assertTrue(bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=good_tar, expected_manifest_sha256=good_sha)["ok"])
        orig_cli = (dest / "kintsugi_sandbox.py").read_bytes()
        orig_marker = (dest / ".kintsugi_sandbox_install.json").read_bytes()

        bad_tar = self.tmp / "bad_smoke.tar.gz"
        bad_sha = _build_synthetic_archive(
            bad_tar, fmt="tar.gz",
            file_overrides={"kintsugi_sandbox.py": b"#!/usr/bin/env python3\nimport sys\nsys.stderr.write('BOOT_FAIL\\n')\nraise SystemExit(1)\n"},
        )
        with self.assertRaises(RuntimeError) as ctx_sm:
            bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=bad_tar, expected_manifest_sha256=bad_sha, run_post_stage_smoke=True)
        self.assertIn("POST_STAGE_SMOKE_FAILED", str(ctx_sm.exception))
        self.assertEqual((dest / "kintsugi_sandbox.py").read_bytes(), orig_cli)
        self.assertEqual((dest / ".kintsugi_sandbox_install.json").read_bytes(), orig_marker)

    def test_09_redirect_handler_hops_allowlist_and_header_stripping(self) -> None:
        base_url = "https://github.com/tunguyen1993/kintsugi-harness/archive/refs/heads/main.tar.gz"
        next_url = "https://codeload.github.com/tunguyen1993/kintsugi-harness/legacy.tar.gz/refs/heads/main"

        handler = bootstrap_mod._AllowlistedRedirectHandler()
        req = urllib.request.Request(
            base_url,
            headers={"Authorization": "Bearer secret", "Cookie": "sid=1", "X-API-Key": "k1", "Proxy-Authorization": "Basic eA=="},
        )
        req.add_unredirected_header("Authorization", "Bearer unredir")
        req.add_unredirected_header("Cookie", "unredir=1")
        new_req = handler.redirect_request(req, None, 302, "Found", {}, next_url)
        all_hdrs = {k.lower() for k in new_req.headers} | {k.lower() for k in new_req.unredirected_hdrs}
        for sensitive in ("authorization", "cookie", "x-api-key", "proxy-authorization"):
            self.assertNotIn(sensitive, all_hdrs)

        hop_h = bootstrap_mod._AllowlistedRedirectHandler()
        cur = urllib.request.Request(base_url)
        for _ in range(5):
            cur = hop_h.redirect_request(cur, None, 302, "Found", {}, next_url)
        with self.assertRaises(ValueError) as ctx_hops:
            hop_h.redirect_request(cur, None, 302, "Found", {}, next_url)
        self.assertIn("TOO_MANY_REDIRECTS", str(ctx_hops.exception))

        for bad_target in (
            "https://evil.example/tunguyen1993/kintsugi-harness/archive/main.tar.gz",
            "https://github.com:8443/tunguyen1993/kintsugi-harness/archive/main.tar.gz",
            "http://github.com/tunguyen1993/kintsugi-harness/archive/main.tar.gz",
            "https://github.com/tunguyen1993/kintsugi-harness/../../other/repo/archive/main.tar.gz",
        ):
            with self.assertRaises(ValueError, msg=bad_target):
                bootstrap_mod._AllowlistedRedirectHandler().redirect_request(urllib.request.Request(base_url), None, 302, "Found", {}, bad_target)

    def test_10_http_403_404_network_fallback_and_timeout_validation(self) -> None:
        dest = self.tmp / "net_fallback_dest"
        pin, full_ref = "a" * 64, "0123456789abcdef" * 2 + "01234567"
        url = "https://github.com/tunguyen1993/kintsugi-harness/archive/main.tar.gz"

        for err, exp_status in (
            (urllib.error.HTTPError(url, 403, "Forbidden", Message(), None), "ACCESS_DENIED_USE_CLOUD_BROWSER"),
            (urllib.error.HTTPError(url, 404, "Not Found", Message(), None), "REF_NOT_FOUND"),
            (urllib.error.URLError("offline"), "NETWORK_BLOCKED_USE_CLOUD_BROWSER"),
        ):
            with mock.patch.object(bootstrap_mod, "_download_bounded_bytes", side_effect=err):
                res = bootstrap_mod.install_or_update(
                    ref=full_ref, dest=dest, expected_manifest_sha256=pin,
                    require_pin=True, require_full_sha=True, timeout=15,
                )
            self.assertFalse(res["ok"])
            self.assertEqual(res["status"], exp_status)
            for key in ("install_downloaded_archive_cmd", "install_downloaded_zip_cmd"):
                cmd_s = res["cloud_browser_fallback"][key]
                self.assertIn("/tmp/k_boot.py", cmd_s)
                self.assertNotIn("kintsugi_sandbox.py", cmd_s)
                self.assertIn(f"--ref {full_ref}", cmd_s)
                self.assertIn(f"--expected-manifest-sha256 {pin}", cmd_s)

        for bad_t in (0, -1, 999, True):
            with self.assertRaises(ValueError, msg=str(bad_t)) as ctx_t:
                bootstrap_mod.install_or_update(ref="main", dest=dest, timeout=bad_t)  # type: ignore[arg-type]
            self.assertIn("INVALID_TIMEOUT", str(ctx_t.exception))

    def test_11_round2_orphan_pyc_edition_version_and_security_io_nfkc_redaction(self) -> None:
        tar_p = self.tmp / "r2_boot.tar.gz"
        sha = _build_synthetic_archive(tar_p, fmt="tar.gz")
        dest = self.tmp / "r2_inst"
        res_unpinned = bootstrap_mod.install_or_update(ref="main", dest=dest, source_archive=tar_p)
        self.assertTrue(res_unpinned["ok"])
        self.assertEqual(res_unpinned["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")

        vm_standalone = bootstrap_mod.verify_manifest_tree(dest, src_root=dest, expected_manifest_sha256=sha, reject_extra_files=True)
        self.assertEqual(vm_standalone["cloud_sandbox_edition_version"], "3.1.1")

        pycache = dest / "__pycache__"
        pycache.mkdir(exist_ok=True)
        orphan = pycache / "ghost_unmanifested.cpython-311.pyc"
        orphan.write_bytes(b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError) as ctx_strict_pyc:
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True)
        self.assertIn("UNVERIFIED_BYTECODE_REJECTED:__pycache__", str(ctx_strict_pyc.exception))

        with self.assertRaises(ValueError) as ctx_orp:
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True, allow_pycache=True)
        self.assertIn("ORPHAN_PYC:__pycache__/ghost_unmanifested.cpython-311.pyc", str(ctx_orp.exception))
        shutil.rmtree(pycache)

        loose_pyc = dest / "loose_ghost.pyc"
        loose_pyc.write_bytes(b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError) as ctx_lpyc:
            bootstrap_mod.verify_manifest_tree(dest, src_root=dest, reject_extra_files=True, allow_pycache=False)
        self.assertIn("UNVERIFIED_BYTECODE_REJECTED:loose_ghost.pyc", str(ctx_lpyc.exception))
        loose_pyc.unlink()

        # security_io.dlp_redact_output: fail-closed on NFKC-obfuscated secrets while preserving safe non-ASCII prose
        fullwidth_secret = "".join(chr(ord(ch) + 0xFEE0) if 0x21 <= ord(ch) <= 0x7E else ch for ch in SYNTH_API_SECRET)
        redacted = security_io_mod.dlp_redact_output(f"leaked={fullwidth_secret}")
        self.assertEqual(redacted, "[REDACTED_DLP]")
        self.assertNotIn(fullwidth_secret, redacted)

        safe_prose = "Caf\u00e9 r\u00e9sum\u00e9 \u2014 2\u00b2 = 4 (\u00bd) safe prose."
        self.assertEqual(security_io_mod.dlp_redact_output(safe_prose), safe_prose)

        vm_repo = bootstrap_mod.verify_manifest_tree(SANDBOX_DIR, src_root=REPO_ROOT)
        self.assertEqual(vm_repo["cloud_sandbox_edition_version"], "3.1.1")

    def test_12_v311_bootstrap_pin_self_sha_git_user_files_flat_zip_and_dir_fd(self) -> None:
        # (a) HIGH #4: security_io POSIX dir_fd enabled and atomic_write_bytes_secure overwrites cleanly
        if os.name == "posix":
            self.assertTrue(security_io_mod._SUPPORTS_DIR_FD)
        aw_target = self.tmp / "atomic_overwrite.bin"
        security_io_mod.atomic_write_bytes_secure(aw_target, b"first_payload\n", mode=0o600)
        self.assertEqual(aw_target.read_bytes(), b"first_payload\n")
        security_io_mod.atomic_write_bytes_secure(aw_target, b"second_payload\n", mode=0o600)
        self.assertEqual(aw_target.read_bytes(), b"second_payload\n")
        if os.name == "posix":
            self.assertEqual(os.stat(aw_target).st_mode & 0o777, 0o600)

        # (b) CRITICAL #1: verify_self_sha256 & CLI --expected-bootstrap-sha256
        tar_p = self.tmp / "v311_boot.tar.gz"
        sha = _build_synthetic_archive(tar_p, fmt="tar.gz")
        boot_sha = hashlib.sha256((SANDBOX_DIR / "bootstrap.py").read_bytes()).hexdigest()
        self.assertEqual(bootstrap_mod.verify_self_sha256(boot_sha), boot_sha)
        with self.assertRaises(ValueError) as ctx_bs:
            bootstrap_mod.verify_self_sha256("f" * 64)
        self.assertIn("BOOTSTRAP_SELF_SHA256_MISMATCH", str(ctx_bs.exception))

        dest_pin = self.tmp / "v311_pinned"
        p_bad_bs = subprocess.run(
            [
                sys.executable, BOOT_CLI, "--dest", str(dest_pin), "--source-archive", str(tar_p),
                "--expected-manifest-sha256", sha, "--expected-bootstrap-sha256", "a" * 64,
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(p_bad_bs.returncode, 0)
        self.assertIn("BOOTSTRAP_SELF_SHA256_MISMATCH", p_bad_bs.stdout)
        self.assertFalse(dest_pin.exists())

        p_ok_bs = subprocess.run(
            [
                sys.executable, BOOT_CLI, "--dest", str(dest_pin), "--source-archive", str(tar_p),
                "--expected-manifest-sha256", sha, "--require-pin", "--expected-bootstrap-sha256", boot_sha,
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(p_ok_bs.returncode, 0, p_ok_bs.stdout + p_ok_bs.stderr)
        self.assertEqual(json.loads(p_ok_bs.stdout)["trust_mode"], "PINNED_MANIFEST_SHA256")

        # (c) Pin downgrade refusal unless allow_downgrade_to_tofu=True / --allow-unpinned-downgrade
        with self.assertRaises(PermissionError) as ctx_dg:
            bootstrap_mod.install_or_update(ref="main", dest=dest_pin, source_archive=tar_p)
        self.assertIn("REFUSING_PIN_DOWNGRADE_TO_TOFU", str(ctx_dg.exception))

        p_dg = subprocess.run(
            [sys.executable, BOOT_CLI, "--dest", str(dest_pin), "--source-archive", str(tar_p), "--allow-unpinned-downgrade"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(p_dg.returncode, 0, p_dg.stdout + p_dg.stderr)
        self.assertEqual(json.loads(p_dg.stdout)["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")

        # (c2) kintsugi_sandbox.py update CLI forwards --expected-bootstrap-sha256 and --allow-unpinned-downgrade
        dest_upd = self.tmp / "sandbox_cli_update_flags"
        p_upd_bad_bs = _run_sandbox_cli(
            "update", "--dest", str(dest_upd), "--source-archive", str(tar_p),
            "--expected-manifest-sha256", sha, "--require-pin", "--expected-bootstrap-sha256", "0" * 64,
        )
        self.assertNotEqual(p_upd_bad_bs.returncode, 0)
        self.assertIn("BOOTSTRAP_SELF_SHA256_MISMATCH", p_upd_bad_bs.stdout)
        self.assertFalse(dest_upd.exists())

        p_upd_ok_bs = _run_sandbox_cli(
            "update", "--dest", str(dest_upd), "--source-archive", str(tar_p),
            "--expected-manifest-sha256", sha, "--require-pin", "--expected-bootstrap-sha256", boot_sha,
        )
        self.assertEqual(p_upd_ok_bs.returncode, 0, p_upd_ok_bs.stdout + p_upd_ok_bs.stderr)
        self.assertEqual(json.loads(p_upd_ok_bs.stdout)["trust_mode"], "PINNED_MANIFEST_SHA256")

        p_upd_dg_blk = _run_sandbox_cli("update", "--dest", str(dest_upd), "--source-archive", str(tar_p))
        self.assertNotEqual(p_upd_dg_blk.returncode, 0)
        self.assertIn("REFUSING_PIN_DOWNGRADE_TO_TOFU", p_upd_dg_blk.stdout)

        p_upd_dg_ok = _run_sandbox_cli(
            "update", "--dest", str(dest_upd), "--source-archive", str(tar_p), "--allow-unpinned-downgrade",
        )
        self.assertEqual(p_upd_dg_ok.returncode, 0, p_upd_dg_ok.stdout + p_upd_dg_ok.stderr)
        self.assertEqual(json.loads(p_upd_dg_ok.stdout)["trust_mode"], "TOFU_UNPINNED_LOCAL_ARCHIVE")

        # (d) REFUSING_GIT_CHECKOUT_DEST on repo root (.git), <repo>/cloud-sandbox, and ANY <repo>/<custom_dir> (../.git)
        fake_repo = self.tmp / "git_checkout_sim"
        (fake_repo / ".git").mkdir(parents=True)
        (fake_repo / "cloud-sandbox").mkdir()
        (fake_repo / "custom_dir").mkdir()
        for gdest in (fake_repo, fake_repo / "cloud-sandbox", fake_repo / "custom_dir", fake_repo / "uncreated_custom_dir"):
            with self.assertRaises(PermissionError, msg=str(gdest)) as ctx_git:
                bootstrap_mod.install_or_update(ref="main", dest=gdest, source_archive=tar_p, expected_manifest_sha256=sha)
            self.assertIn("REFUSING_GIT_CHECKOUT_DEST", str(ctx_git.exception))

        # (e) REFUSING_NON_KINTSUGI_NONEMPTY_DEST when bare kintsugi_sandbox.py + manifest.json lack valid install marker
        bare = self.tmp / "bare_pair_dest"
        bare.mkdir()
        (bare / "kintsugi_sandbox.py").write_text("# decoy\n", encoding="utf-8")
        (bare / "manifest.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_nm:
            bootstrap_mod.install_or_update(ref="main", dest=bare, source_archive=tar_p, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_NON_KINTSUGI_NONEMPTY_DEST", str(ctx_nm.exception))
        (bare / ".kintsugi_sandbox_install.json").write_text('{"schema":"InvalidSchema/9"}\n', encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_bad_m:
            bootstrap_mod.install_or_update(ref="main", dest=bare, source_archive=tar_p, expected_manifest_sha256=sha)
        self.assertIn("REFUSING_NON_KINTSUGI_NONEMPTY_DEST", str(ctx_bad_m.exception))

        # (f) REFUSING_DEST_WITH_USER_FILES preserves user file untouched
        extra_user = dest_pin / "user_report.txt"
        extra_user.write_text("keep_me_safe\n", encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_uf:
            bootstrap_mod.install_or_update(
                ref="main", dest=dest_pin, source_archive=tar_p, expected_manifest_sha256=sha
            )
        self.assertIn("REFUSING_DEST_WITH_USER_FILES", str(ctx_uf.exception))
        self.assertEqual(extra_user.read_text(encoding="utf-8"), "keep_me_safe\n")
        extra_user.unlink()

        # (g) Dual ZIP layout: flat standalone offline bundle ZIP installs cleanly and rejects tamper/extra
        flat_zip = self.tmp / "flat_bundle.zip"
        flat_sha = _build_flat_standalone_zip(flat_zip)
        self.assertEqual(flat_sha, sha)
        flat_dest = self.tmp / "flat_dest"
        r_flat = bootstrap_mod.install_or_update(
            ref="main", dest=flat_dest, source_archive=flat_zip, expected_manifest_sha256=flat_sha, require_pin=True
        )
        self.assertTrue(r_flat["ok"] and r_flat["smoke_test_passed"])

        flat_bad = self.tmp / "flat_tampered.zip"
        _build_flat_standalone_zip(flat_bad, corrupt_file="TASKS.md")
        with self.assertRaises(ValueError) as ctx_fb:
            bootstrap_mod.install_or_update(ref="main", dest=self.tmp / "flat_bad_dest", source_archive=flat_bad)
        self.assertIn("MANIFEST_HASH_MISMATCH", str(ctx_fb.exception))

        flat_ext = self.tmp / "flat_extra.zip"
        _build_flat_standalone_zip(flat_ext, extra_members=[("kintsugi-cloud-sandbox-v3.1.1/injected.py", b"x=1\n")])
        with self.assertRaises(ValueError) as ctx_fe:
            bootstrap_mod.install_or_update(ref="main", dest=self.tmp / "flat_ext_dest", source_archive=flat_ext)
        self.assertIn("MANIFEST_UNEXPECTED_EXTRA_FILES", str(ctx_fe.exception))

        # (h) requested_ref vs verified_commit_sha recorded separately
        full_sha = "abcdef0123456789" * 2 + "abcdef01"
        loc_dest = self.tmp / "loc_ref_dest"
        r_loc = bootstrap_mod.install_or_update(
            ref=full_sha, dest=loc_dest, source_archive=tar_p,
            expected_manifest_sha256=sha, require_pin=True, require_full_sha=True,
        )
        loc_m = json.loads((loc_dest / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual((r_loc["requested_ref"], r_loc["verified_commit_sha"]), (full_sha, ""))
        self.assertEqual((loc_m["requested_ref"], loc_m["verified_commit_sha"]), (full_sha, ""))

        https_dest = self.tmp / "https_ref_dest"
        with mock.patch.object(bootstrap_mod, "_download_bounded_bytes", return_value=tar_p.read_bytes()):
            r_net = bootstrap_mod.install_or_update(
                ref=full_sha, dest=https_dest, expected_manifest_sha256=sha,
                require_pin=True, require_full_sha=True, run_post_stage_smoke=False,
            )
        net_m = json.loads((https_dest / ".kintsugi_sandbox_install.json").read_text(encoding="utf-8"))
        self.assertEqual((r_net["requested_ref"], r_net["verified_commit_sha"]), (full_sha, full_sha))
        self.assertEqual((net_m["requested_ref"], net_m["verified_commit_sha"]), (full_sha, full_sha))

        # (i) sys.dont_write_bytecode is True in isolated imports of bootstrap and kintsugi_sandbox
        for mod_name in ("bootstrap", "kintsugi_sandbox"):
            p_bc = subprocess.run(
                [
                    sys.executable, "-c",
                    f"import sys; sys.path.insert(0, {str(SANDBOX_DIR)!r}); import {mod_name}; assert sys.dont_write_bytecode is True",
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(p_bc.returncode, 0, f"{mod_name}: {p_bc.stderr}")


# ===========================================================================
# 2. Universal Truth Gate & Self-Evolution Adversarial Tests
# ===========================================================================


class TestTruthGateAndEvolutionAdversarial(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_ctx = tempfile.TemporaryDirectory(prefix="kintsugi_adv_evo_")
        self.tmp = Path(self.tmp_ctx.name)

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()

    def _w(self, name: str, text: str) -> Path:
        p = self.tmp / name
        p.write_text(text, encoding="utf-8")
        return p

    def _sku_files(self) -> Tuple[Path, Path, Path, Path]:
        return (
            self._w("sku_bare.py", "def clean_sku(s: str) -> str:\n    return s\n"),
            self._w("sku_real.py", "def clean_sku(s: str) -> str:\n    return s.lstrip()\n"),
            self._w("sku_fixed.py", "def clean_sku(s: str) -> str:\n    return s.strip().upper()\n"),
            self._w("sku_test.py", "import candidate\nassert candidate.clean_sku(' ab ') == 'AB'\n"),
        )

    def test_01_env_isolation_parent_canary_secret_unreadable(self) -> None:
        b = self._w("b_env.py", "import os\ndef dbl(x: int) -> int:\n    return x * 2 if os.environ.get('KINTSUGI_PARENT_CANARY_SECRET') else x + 1\n")
        f = self._w("f_env.py", "import os\ndef dbl(x: int) -> int:\n    return -1 if os.environ.get('KINTSUGI_PARENT_CANARY_SECRET') else x * 2\n")
        t = self._w("t_env.py", "import os, candidate\nassert os.environ.get('KINTSUGI_PARENT_CANARY_SECRET') is None\nassert candidate.dbl(5) == 10\n")
        old_val = os.environ.get("KINTSUGI_PARENT_CANARY_SECRET")
        os.environ["KINTSUGI_PARENT_CANARY_SECRET"] = "topsecret_xyz"
        try:
            res = truth_gate_mod.run_custom_truth_gate(b, f, t, runner="python")
        finally:
            if old_val is None:
                os.environ.pop("KINTSUGI_PARENT_CANARY_SECRET", None)
            else:
                os.environ["KINTSUGI_PARENT_CANARY_SECRET"] = old_val
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["verdict"], "PROMOTE_ELIGIBLE")

    def test_02_reward_hacking_blocked_crash_exit_and_forged_verdict(self) -> None:
        f = self._w("f_rh.py", "def calc(x: int) -> int:\n    return x * 2\n")
        t = self._w("t_rh.py", "import candidate\nassert candidate.calc(4) == 8\n")
        forged_pfx = "KINTSUGI_" + "VERDICT:"
        forged_json = '{"property_id":"ASSERTION","verdict":"EXPECTED_PROPERTY_FAIL","assertions_run":1}'

        cases = [
            ("runtime_err", "def calc(x: int) -> int:\n    raise RuntimeError('fake')\n", "INFRA_ERROR"),
            ("sys_exit", "import sys\ndef calc(x: int) -> int:\n    sys.exit(1)\n", "INFRA_ERROR"),
            ("os_exit", "import os\ndef calc(x: int) -> int:\n    os._exit(1)\n", "INFRA_ERROR"),
            ("dyn_forge_crash", f"def calc(x: int) -> int:\n    print('KINTSUGI_' + 'VERDICT:' + '{forged_json}')\n    raise RuntimeError('boom')\n", "INFRA_ERROR"),
        ]
        for label, src, exp_broken_verdict in cases:
            with self.subTest(case=label):
                res = truth_gate_mod.run_custom_truth_gate(self._w(f"b_{label}.py", src), f, t, runner="python")
                self.assertFalse(res["ok"])
                self.assertEqual(res["verdict"], "REJECTED_TRUTH_GATE")
                self.assertEqual(res["broken_verdict"], exp_broken_verdict)
                self.assertTrue(res["broken_setup_error"])

        b_lit = self._w("b_lit_forge.py", f"def calc(x: int) -> int:\n    print('{forged_pfx}{forged_json}')\n    return x * 2\n")
        r_lit = truth_gate_mod.run_custom_truth_gate(b_lit, f, t, runner="python")
        self.assertFalse(r_lit["ok"])
        self.assertEqual(r_lit["verdict"], "REJECTED_TRUTH_GATE")
        self.assertIn("CANDIDATE_SPOOFED_VERDICT_MARKER_IN_BROKEN", r_lit["error"])

    def test_03_vacuous_oracles_blocked(self) -> None:
        b = self._w("b_vac.py", "def f(x: int) -> int:\n    return x\n")
        f = self._w("f_vac.py", "def f(x: int) -> int:\n    return x + 1\n")

        r_empty = truth_gate_mod.run_custom_truth_gate(b, f, self._w("t_empty.py", ""), runner="python")
        self.assertFalse(r_empty["ok"])
        self.assertEqual(r_empty["error"], "EMPTY_TRUTH_GATE_INPUT")

        for name, code in (
            ("t_comment.py", "# comment only\n"),
            ("t_true.py", "import candidate\nassert True\n"),
            ("t_const.py", "import candidate\nassert 1 + 1 == 2\n"),
            ("t_nocand.py", "v = 7\nassert v == 7\n"),
        ):
            res = truth_gate_mod.run_custom_truth_gate(b, f, self._w(name, code), runner="python")
            self.assertFalse(res["ok"], name)
            self.assertEqual(res["status"], "VACUOUS_ORACLE_REJECTED")

    def test_04_timeout_kills_forked_process_group_sigkill(self) -> None:
        b_hang = self._w(
            "b_hang.py",
            "import subprocess, sys, time\n"
            "def slow() -> int:\n"
            "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "    sys.stderr.write(f'CHILD_PID={child.pid}\\n'); sys.stderr.flush()\n"
            "    time.sleep(60)\n    return 0\n",
        )
        f_fast = self._w("f_fast.py", "def slow() -> int:\n    return 42\n")
        t_hang = self._w("t_hang.py", "import candidate\nassert candidate.slow() == 42\n")

        t0 = time.monotonic()
        res = truth_gate_mod.run_custom_truth_gate(b_hang, f_fast, t_hang, runner="python", timeout_s=1)
        self.assertFalse(res["ok"])
        self.assertEqual(res["broken_rc"], 124)
        self.assertEqual(res["error"], "TRUTH_GATE_TIMEOUT")
        self.assertLess(time.monotonic() - t0, 8.0)

        m = re.search(r"CHILD_PID=(\d+)", res.get("broken_stderr", ""))
        self.assertIsNotNone(m)
        assert m is not None
        child_pid = int(m.group(1))
        dead = False
        for _ in range(25):
            try:
                os.kill(child_pid, 0)
                time.sleep(0.05)
            except ProcessLookupError:
                dead = True
                break
        self.assertTrue(dead, f"grandchild {child_pid} survived SIGKILL")

    def test_05_partial_cli_flags_truth_gate_exits_2_no_builtin_fallback(self) -> None:
        b, f = self._w("bp.py", "x = 1\n"), self._w("fp.py", "x = 2\n")
        for cli_args in (
            ("truth-gate", "--broken", str(b), "--fixed", str(f)),
            ("truth-gate", "--broken", str(b)),
            ("truth-gate", "--test", str(f)),
        ):
            proc = _run_sandbox_cli(*cli_args)
            self.assertEqual(proc.returncode, 2)
            doc = json.loads(proc.stdout)
            self.assertFalse(doc["ok"])
            self.assertEqual(doc["status"], "MISSING_CUSTOM_TRUTH_GATE_FLAGS")
            self.assertNotIn("contracts", doc)

    def test_06_multilanguage_sqlite_node_and_unsupported_extension(self) -> None:
        b_sql = self._w("b.sql", "SELECT region, SUM(units) FROM shipments ORDER BY region;\n")
        f_sql = self._w("f.sql", "SELECT region, SUM(units) FROM shipments GROUP BY region ORDER BY region;\n")
        t_sql = self._w(
            "t_sql.py",
            "import os, sqlite3\n"
            "c = sqlite3.connect(':memory:')\n"
            "c.execute('CREATE TABLE shipments (region TEXT, units INTEGER)')\n"
            "c.executemany('INSERT INTO shipments VALUES (?, ?)', [('N', 3), ('N', 4), ('S', 5)])\n"
            "assert c.execute(os.environ['KINTSUGI_CANDIDATE_SQL']).fetchall() == [('N', 7), ('S', 5)]\n",
        )
        r_sql = truth_gate_mod.run_custom_truth_gate(b_sql, f_sql, t_sql, runner="auto")
        self.assertTrue(r_sql["ok"], r_sql)
        self.assertEqual((r_sql["runner"], r_sql["verified_language"]), ("sqlite", "sql"))

        if shutil.which("node"):
            b_js = self._w("b.mjs", "export function padCode(s) { return s.trim(); }\n")
            f_js = self._w("f.mjs", "export function padCode(s) { return s.trim().toUpperCase(); }\n")
            t_js = self._w("t.mjs", "import assert from 'node:assert/strict';\nimport { padCode } from './candidate.mjs';\nassert.strictEqual(padCode(' ab '), 'AB');\n")
            r_js = truth_gate_mod.run_custom_truth_gate(b_js, f_js, t_js, runner="auto")
            self.assertTrue(r_js["ok"], r_js)
            self.assertEqual((r_js["runner"], r_js["verified_language"]), ("node", "javascript"))

        r_rb = truth_gate_mod.run_custom_truth_gate(
            self._w("b.rb", "def f; 1; end\n"), self._w("f.rb", "def f; 2; end\n"),
            self._w("t_rb.py", "import candidate\nassert candidate.f() == 2\n"), runner="auto",
        )
        self.assertFalse(r_rb["ok"])
        self.assertEqual(r_rb["status"], "UNSUPPORTED_RUNNER")

    def test_07_sku_regression_and_16_sample_canary_corpus(self) -> None:
        canary_doc = json.loads((SANDBOX_DIR / "data" / "canary_corpus_v3.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(canary_doc["samples"]), 16)

        store, tel = self.tmp / "evo_sku.json", self.tmp / "tel_sku.json"
        b_bare, b_real, f_sku, t_sku = self._sku_files()

        for broad_groups in ([["point"], ["abs"]], [["strip"], ["lower"]]):
            with self.assertRaises(ValueError, msg=str(broad_groups)) as ctx_c:
                evolution_mod.evolve_learn(
                    store_path=store, telemetry_store=tel, scar_id="CSB-CANARY-1", slug="broad_fp",
                    category="logic", languages=["python"], trigger_groups=broad_groups,
                    bad_pattern="b", good_pattern="g", precondition="w",
                    broken_path=b_real, fixed_path=f_sku, test_path=t_sku,
                )
            self.assertIn("TRIGGER_GROUPS_FIRE_ON_BENIGN_CANARY", str(ctx_c.exception))

        r_miss = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-SKU-MISS", slug="sku_miss",
            category="logic", languages=["python"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
            bad_pattern="Bare SKU", good_pattern="s.strip().upper()", precondition="SKU cleanup",
            broken_path=b_bare, fixed_path=f_sku, test_path=t_sku, role="detect_bug", runner="python",
        )
        self.assertFalse(r_miss["ok"])
        self.assertEqual(r_miss["status"], "REJECTED_TRIGGERS_MISS_BROKEN_REPRO")

        r_ok = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-SKU-OK", slug="sku_ok",
            category="logic", languages=["python"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
            bad_pattern="lstrip without full strip and upper", good_pattern="s.strip().upper()", precondition="SKU cleanup",
            broken_path=b_real, fixed_path=f_sku, test_path=t_sku, role="detect_bug", runner="python",
        )
        self.assertTrue(r_ok["ok"], r_ok)
        self.assertEqual(r_ok["status"], "PROMOTED_TO_LIVE_EVOLUTION_STORE")

    def test_08_corrupt_empty_store_and_tampered_store_defenses(self) -> None:
        empty_store = self.tmp / "empty_corrupt.json"
        empty_store.write_bytes(b"")
        with self.assertRaises(ValueError) as ctx_e1:
            evolution_mod.load_evolution_store(empty_store)
        self.assertIn("CORRUPT_EMPTY_STORE", str(ctx_e1.exception))
        with self.assertRaises(ValueError) as ctx_e2:
            evolution_mod.load_active_learned_scars(empty_store, telemetry_store=None)
        self.assertIn("CORRUPT_EMPTY_STORE", str(ctx_e2.exception))

        store, tel = self.tmp / "tamper_store.json", self.tmp / "tamper_tel.json"
        _b_bare, b_real, f_sku, t_sku = self._sku_files()

        with self.assertRaises(ValueError) as ctx_wc:
            evolution_mod.evolve_learn(
                store_path=store, telemetry_store=tel, scar_id="CSB-WC-001", slug="wc_detect_bug",
                category="logic", languages=["*"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                bad_pattern="b", good_pattern="g", precondition="w",
                broken_path=b_real, fixed_path=f_sku, test_path=t_sku, role="detect_bug",
            )
        self.assertIn("WILDCARD_LANGUAGE_FORBIDDEN_FOR_DETECT_BUG", str(ctx_wc.exception))

        lr = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-TAMPER-OK", slug="tamper_base",
            category="logic", languages=["python"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
            bad_pattern="Original bad", good_pattern="Original good", precondition="SKU",
            broken_path=b_real, fixed_path=f_sku, test_path=t_sku,
        )
        orig_compact = lr["scar"]["compact"]

        doc = json.loads(store.read_text(encoding="utf-8"))
        doc["scars"][0]["compact"] = "TAMPERED_COMPACT_TEXT"
        doc["scars"].append(dict(doc["scars"][0]))  # duplicate ID
        mutated = dict(doc["scars"][0])
        mutated["id"] = "CSB-TAMPER-MUT"
        mutated["bad_pattern"] = "Modified bad breaks revision_sha256"
        doc["scars"].append(mutated)
        store.write_text(json.dumps(doc), encoding="utf-8")

        active = evolution_mod.load_active_learned_scars(store, telemetry_store=tel)
        self.assertEqual([a["id"] for a in active], ["CSB-TAMPER-OK"])
        self.assertEqual(active[0]["compact"], orig_compact)
        st = evolution_mod.evolve_status(store, tel)
        self.assertEqual((st["active_learned_count"], st["duplicate_id_count"], st["rejected_invalid_count"]), (1, 1, 2))

    def test_09_export_aliasing_and_import_patch_roundtrip_frozen_quarantine_idempotent(self) -> None:
        src_store, src_tel = self.tmp / "src_learned.json", self.tmp / "src_tel.json"
        dst_store, dst_tel = self.tmp / "dst_learned.json", self.tmp / "dst_tel.json"
        patch_p = self.tmp / "export_patch.json"
        _b_bare, b_real, f_sku, t_sku = self._sku_files()

        for sid, sl in (("CSB-EXP-001", "sku_exp_one"), ("CSB-EXP-002", "sku_exp_two")):
            self.assertTrue(
                evolution_mod.evolve_learn(
                    store_path=src_store, telemetry_store=src_tel, scar_id=sid, slug=sl,
                    category="logic", languages=["python"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                    bad_pattern="b", good_pattern="g", precondition="w",
                    broken_path=b_real, fixed_path=f_sku, test_path=t_sku,
                )["ok"]
            )

        for alias in (src_store, src_tel, Path(f"{src_store}.lock"), self.tmp / "custom.lock"):
            with self.assertRaises(ValueError, msg=str(alias)) as ctx_al:
                evolution_mod.evolve_export_patch(store_path=src_store, telemetry_store=src_tel, out_path=alias)
            self.assertIn("OUTPUT_ALIASES_STATE_FILE", str(ctx_al.exception))

        ex = evolution_mod.evolve_export_patch(store_path=src_store, telemetry_store=src_tel, out_path=patch_p)
        self.assertTrue(ex["ok"] and ex["scars_count"] == 2)
        patch_sha = ex["patch_sha256"]

        tamp_p = self.tmp / "tampered_patch.json"
        tdoc = json.loads(patch_p.read_text(encoding="utf-8"))
        tdoc["scars_count"] = 99
        tamp_p.write_text(json.dumps(tdoc), encoding="utf-8")
        with self.assertRaises(ValueError) as ctx_tp:
            evolution_mod.evolve_import_patch(tamp_p, store_path=dst_store, telemetry_store=dst_tel)
        self.assertIn("PATCH_SHA256_MISMATCH", str(ctx_tp.exception))

        with self.assertRaises(ValueError) as ctx_ep:
            evolution_mod.evolve_import_patch(patch_p, store_path=dst_store, telemetry_store=dst_tel, expected_patch_sha256="f" * 64)
        self.assertIn("EXPECTED_PATCH_SHA256_MISMATCH", str(ctx_ep.exception))

        _record_two_strike_freeze(dst_tel, "CSB-EXP-002", prefix="loc")

        pf_p = self.tmp / "patch_with_frozen.json"
        pf_doc = json.loads(patch_p.read_text(encoding="utf-8"))
        pf_doc["frozen_ids"] = ["CSB-EXP-001"]
        pf_doc["patch_sha256"] = evolution_mod._compute_patch_sha256(pf_doc)
        pf_p.write_text(json.dumps(pf_doc), encoding="utf-8")
        with self.assertRaises(PermissionError) as ctx_unp:
            evolution_mod.evolve_import_patch(pf_p, store_path=self.tmp / "dst_fr.json", telemetry_store=dst_tel, quarantine=False)
        self.assertIn("REFUSING_UNPINNED_LIVE_IMPORT", str(ctx_unp.exception))
        imp_fr = evolution_mod.evolve_import_patch(
            pf_p, store_path=self.tmp / "dst_fr.json", telemetry_store=dst_tel,
            expected_patch_sha256=pf_doc["patch_sha256"], quarantine=False,
        )
        self.assertEqual((imp_fr["imported"], imp_fr["skipped_frozen"]), (0, 2))

        # Default quarantine=True stages safely without touching live dst_store.
        imp_q = evolution_mod.evolve_import_patch(
            patch_p, store_path=dst_store, telemetry_store=dst_tel, expected_patch_sha256=patch_sha
        )
        self.assertEqual((imp_q["status"], imp_q["imported"], imp_q["skipped_frozen"]), ("QUARANTINED_EVOLUTION_PATCH", 1, 1))
        self.assertTrue((dst_store.parent / "quarantine_scars.json").is_file() and not dst_store.exists())

        imp1 = evolution_mod.evolve_import_patch(
            patch_p, store_path=dst_store, telemetry_store=dst_tel, expected_patch_sha256=patch_sha, quarantine=False
        )
        imp2 = evolution_mod.evolve_import_patch(
            patch_p, store_path=dst_store, telemetry_store=dst_tel, expected_patch_sha256=patch_sha, quarantine=False
        )
        self.assertEqual((imp1["imported"], imp1["already_present"], imp1["skipped_frozen"]), (1, 0, 1))
        self.assertEqual((imp2["imported"], imp2["already_present"], imp2["skipped_frozen"]), (0, 1, 1))

    def test_10_truth_gate_dlp_output_redaction(self) -> None:
        b = self._w("b_dlp.py", f"import sys\ndef f() -> int:\n    sys.stderr.write('t={SYNTH_API_SECRET} i={SYNTH_RFC1918_IP}\\n')\n    return 1\n")
        f = self._w("f_dlp.py", f"import sys\ndef f() -> int:\n    print('t={SYNTH_API_SECRET} i={SYNTH_RFC1918_IP}')\n    sys.stderr.write('e={SYNTH_API_SECRET} i={SYNTH_RFC1918_IP}\\n')\n    return 2\n")
        t = self._w("t_dlp.py", "import candidate\nassert candidate.f() == 2\n")
        res = truth_gate_mod.run_custom_truth_gate(b, f, t, runner="python")
        self.assertTrue(res["ok"], res)
        for field in ("broken_stderr", "fixed_stdout", "fixed_stderr"):
            self.assertIn("[REDACTED_DLP]", res[field])
            self.assertNotIn(SYNTH_API_SECRET, res[field])
            self.assertNotIn(SYNTH_RFC1918_IP, res[field])

    def test_11_round2_truth_gate_sys_exit_verdict_fd_candidate_assert_and_nul(self) -> None:
        b_ok = self._w("r2_b_ok.py", "def dbl(x: int) -> int:\n    return x + 1\n")
        f_ok = self._w("r2_f_ok.py", "def dbl(x: int) -> int:\n    return x * 2\n")
        t_ok = self._w("r2_t_ok.py", "import candidate\nassert candidate.dbl(4) == 8\n")

        # (a) fixed.py calling sys.exit(0) at call time AND import time -> INFRA_ERROR (CandidateSystemExit)
        for label, f_src in (
            ("call_exit", "import sys\ndef dbl(x: int) -> int:\n    sys.exit(0)\n"),
            ("import_exit", "import sys\nsys.exit(0)\ndef dbl(x: int) -> int:\n    return x * 2\n"),
        ):
            with self.subTest(case=label):
                seen_pipes: List[str] = []
                orig_extract = truth_gate_mod._extract_run_verdict

                def _spy_extract(*a: Any, **kw: Any) -> Any:
                    seen_pipes.append(str(a[0]))
                    return orig_extract(*a, **kw)

                with mock.patch.object(truth_gate_mod, "_extract_run_verdict", side_effect=_spy_extract):
                    res = truth_gate_mod.run_custom_truth_gate(b_ok, self._w(f"r2_{label}.py", f_src), t_ok, runner="python")
                self.assertFalse(res["ok"])
                self.assertEqual(res["verdict"], "REJECTED_TRUTH_GATE")
                self.assertEqual(res["fixed_verdict"], "INFRA_ERROR")
                self.assertEqual(res["fixed_rc"], 20)
                self.assertTrue(any("CandidateSystemExit" in p for p in seen_pipes), seen_pipes)

        # (b) Forged stdout KINTSUGI_VERDICT on rc==0 broken run cannot override private-FD verdict
        forged_json = '{"property_id":"ASSERTION","verdict":"EXPECTED_PROPERTY_FAIL","assertions_run":1}'
        b_rc0_forge = self._w(
            "r2_b_rc0_forge.py",
            f"def dbl(x: int) -> int:\n    print('KINTSUGI_' + 'VERDICT:' + '{forged_json}')\n    return x * 2\n",
        )
        r_forge = truth_gate_mod.run_custom_truth_gate(b_rc0_forge, f_ok, t_ok, runner="python")
        self.assertFalse(r_forge["ok"])
        self.assertEqual(r_forge["verdict"], "REJECTED_TRUTH_GATE")
        self.assertEqual((r_forge["broken_rc"], r_forge["broken_verdict"]), (0, "PROPERTY_PASSED"))

        # (c) Vacuous verdict-only oracle rejected by AST inspection
        t_verdict_only = self._w(
            "r2_t_verdict_only.py",
            "import candidate\ncandidate.dbl(4)\n"
            "print('KINTSUGI_' + 'VERDICT:{\"property_id\":\"P1\",\"verdict\":\"PROPERTY_PASSED\",\"assertions_run\":1}')\n",
        )
        r_vac = truth_gate_mod.run_custom_truth_gate(b_ok, f_ok, t_verdict_only, runner="python")
        self.assertFalse(r_vac["ok"])
        self.assertEqual(r_vac["status"], "VACUOUS_ORACLE_REJECTED")

        # (d) Private verdict FD env var stripped before oracle/candidate runs; oracle path hidden from candidate worker
        f_env_chk = self._w(
            "r2_f_env_chk.py",
            "import os, sys\n"
            "def check_iso(x: int) -> int:\n"
            "    if ('KINTSUGI_' + 'VERDICT_FD') in os.environ:\n"
            "        return -1\n"
            "    if sys.argv != ['candidate.py']:\n"
            "        return -2\n"
            "    return x * 2\n",
        )
        b_env_chk = self._w("r2_b_env_chk.py", "def check_iso(x: int) -> int:\n    return x + 1\n")
        t_env_chk = self._w(
            "r2_t_env_chk.py",
            "import os, sys, candidate\n"
            "assert ('KINTSUGI_' + 'VERDICT_FD') not in os.environ\n"
            "assert len(sys.argv) == 2\n"
            "assert candidate.check_iso(4) == 8\n",
        )
        r_iso = truth_gate_mod.run_custom_truth_gate(b_env_chk, f_env_chk, t_env_chk, runner="python")
        self.assertTrue(r_iso["ok"], r_iso)
        self.assertEqual(r_iso["verdict"], "PROMOTE_ELIGIBLE")

        # (e) broken.py raising AssertionError internally -> INFRA_ERROR (CandidateAssertionError)
        b_fake_assert = self._w("r2_b_assert.py", "def dbl(x: int) -> int:\n    raise AssertionError('fake')\n")
        py_pipes: List[str] = []
        orig_extract = truth_gate_mod._extract_run_verdict

        def _spy_py(*a: Any, **kw: Any) -> Any:
            py_pipes.append(str(a[0]))
            return orig_extract(*a, **kw)

        with mock.patch.object(truth_gate_mod, "_extract_run_verdict", side_effect=_spy_py):
            r_ba = truth_gate_mod.run_custom_truth_gate(b_fake_assert, f_ok, t_ok, runner="python")
        self.assertFalse(r_ba["ok"])
        self.assertEqual(r_ba["broken_verdict"], "INFRA_ERROR")
        self.assertTrue(r_ba["broken_setup_error"])
        self.assertEqual(r_ba["broken_rc"], 20)
        self.assertTrue(any("CandidateAssertionError" in p for p in py_pipes), py_pipes)

        # (f) Node .mjs candidate throwing AssertionError with spoofed `at _oracle_test.mjs` in message -> INFRA_ERROR
        if shutil.which("node"):
            b_js = self._w(
                "r2_b_spoof.mjs",
                "import { AssertionError } from 'node:assert';\n"
                "export function dbl(x) {\n"
                "  throw new AssertionError({ message: 'spoof\\n    at _oracle_test.mjs:1:1' });\n"
                "}\n",
            )
            f_js = self._w("r2_f_spoof.mjs", "export function dbl(x) { return x * 2; }\n")
            t_js = self._w(
                "r2_t_spoof.mjs",
                "import assert from 'node:assert/strict';\n"
                "import { dbl } from './candidate.mjs';\n"
                "assert.strictEqual(dbl(4), 8);\n",
            )
            js_pipes: List[str] = []

            def _spy_js(*a: Any, **kw: Any) -> Any:
                js_pipes.append(str(a[0]))
                return orig_extract(*a, **kw)

            with mock.patch.object(truth_gate_mod, "_extract_run_verdict", side_effect=_spy_js):
                r_js = truth_gate_mod.run_custom_truth_gate(b_js, f_js, t_js, runner="node")
            self.assertFalse(r_js["ok"])
            self.assertEqual(r_js["broken_verdict"], "INFRA_ERROR")
            self.assertTrue(r_js["broken_setup_error"])
            self.assertEqual(r_js["broken_rc"], 20)
            self.assertTrue(any("CandidateAssertionError" in p for p in js_pipes), js_pipes)

        # (g) NUL byte in .py or .sql returns clean structured REJECTED_TRUTH_GATE (NUL_BYTE_IN_INPUT)
        b_nul_py = self.tmp / "r2_nul.py"
        b_nul_py.write_bytes(b"def dbl(x):\n    return x\x00\n")
        r_nul_py = truth_gate_mod.run_custom_truth_gate(b_nul_py, f_ok, t_ok, runner="python")
        self.assertEqual((r_nul_py["ok"], r_nul_py["status"], r_nul_py["error"]), (False, "REJECTED_TRUTH_GATE", "NUL_BYTE_IN_INPUT"))

        b_nul_sql = self.tmp / "r2_nul.sql"
        b_nul_sql.write_bytes(b"SELECT 1;\x00\n")
        f_sql = self._w("r2_f_ok.sql", "SELECT 2;\n")
        t_sql = self._w("r2_t_sql.py", "import os, sqlite3\nassert sqlite3.connect(':memory:').execute(os.environ['KINTSUGI_CANDIDATE_SQL']).fetchone()[0] == 2\n")
        r_nul_sql = truth_gate_mod.run_custom_truth_gate(b_nul_sql, f_sql, t_sql, runner="sqlite")
        self.assertEqual((r_nul_sql["ok"], r_nul_sql["status"], r_nul_sql["error"]), (False, "REJECTED_TRUTH_GATE", "NUL_BYTE_IN_INPUT"))

    def test_12_round2_evolution_matcher_parity_spec_role_wildcard_and_superseded_patch(self) -> None:
        # (a) Gate-4 Matcher-on-Broken matches @struct_halving_hash_tree & @struct_json_untrusted_input identically to scanner_sandbox
        merkle_broken_code = (
            "import hashlib\n"
            "def fold_merkle_audit(nodes):\n"
            "    while len(nodes) > 1:\n"
            "        if len(nodes) % 2 == 1:\n"
            "            odd_dup = nodes[-1]\n"
            "            nodes = nodes + [odd_dup]\n"
            "        nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest() for i in range(0, len(nodes), 2)]\n"
            "    return nodes[0]\n"
        )
        merkle_fixed_code = (
            "import hashlib\n"
            "def fold_merkle_audit(nodes):\n"
            "    while len(nodes) > 1:\n"
            "        nxt = []\n"
            "        for i in range(0, len(nodes), 2):\n"
            "            nxt.append(hashlib.sha256(nodes[i] + nodes[i + 1]).digest() if i + 1 < len(nodes) else nodes[i])\n"
            "        nodes = nxt\n"
            "    return nodes[0]\n"
        )
        json_broken_code = (
            "import json\n"
            "def parse_untrusted_cfg(raw: str) -> dict:\n"
            "    return json.loads(raw)\n"
        )
        self.assertEqual(
            evolution_mod._extract_signals_for_lang(merkle_broken_code, "python"),
            scanner_mod.extract_code_capsule_signals(merkle_broken_code, lang="python")[0],
        )
        self.assertIn("@struct_halving_hash_tree", evolution_mod._extract_signals_for_lang(merkle_broken_code, "python"))
        self.assertEqual(
            evolution_mod._extract_signals_for_lang(json_broken_code, "python"),
            scanner_mod.extract_code_capsule_signals(json_broken_code, lang="python")[0],
        )
        self.assertIn("@struct_json_untrusted_input", evolution_mod._extract_signals_for_lang(json_broken_code, "python"))

        store, tel = self.tmp / "r2_evo.json", self.tmp / "r2_tel.json"
        bm = self._w("r2_merkle_b.py", merkle_broken_code)
        fm = self._w("r2_merkle_f.py", merkle_fixed_code)
        tm = self._w(
            "r2_merkle_t.py",
            "import candidate\nassert candidate.fold_merkle_audit([b'a', b'b', b'c']) != candidate.fold_merkle_audit([b'a', b'b', b'c', b'c'])\n",
        )
        r_m = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-MERKLE-R2", slug="merkle_odd_promotion",
            category="crypto", languages=["python"], role="detect_bug",
            trigger_groups=[["@struct_halving_hash_tree"], ["odd_dup"]],
            bad_pattern="Duplicating odd tail leaf", good_pattern="Promote odd node untouched", precondition="Merkle folding",
            broken_path=bm, fixed_path=fm, test_path=tm, runner="python",
        )
        self.assertTrue(r_m["ok"], r_m)

        # (b) CLI evolve learn --spec with role="context_reminder" & languages=["*"] succeeds (H-4)
        _b_bare, b_real, f_sku, t_sku = self._sku_files()
        b_strip = self._w("r2_sku_strip.py", "def clean_sku(s: str) -> str:\n    return s.strip()\n")
        spec_p = self._w(
            "r2_spec_ctx.json",
            json.dumps({
                "id": "CSB-CTX-R2", "slug": "sku_ctx_reminder", "category": "logic",
                "languages": ["*"], "role": "context_reminder", "runner": "python",
                "trigger_groups": [["clean_sku"], ["strip", "upper"]],
                "bad_pattern": "Skipping uppercase SKU normalization",
                "good_pattern": "Normalize SKU via strip().upper()",
                "precondition": "SKU handling reminder",
                "broken_path": str(b_strip), "fixed_path": str(f_sku), "test_path": str(t_sku),
            }),
        )
        p_spec = _run_sandbox_cli("evolve", "learn", "--spec", str(spec_p), "--store", str(store), "--telemetry-store", str(tel))
        self.assertEqual(p_spec.returncode, 0, p_spec.stdout + p_spec.stderr)
        j_spec = json.loads(p_spec.stdout)
        self.assertTrue(j_spec["ok"])
        self.assertEqual((j_spec["scar"]["role"], j_spec["scar"]["languages"]), ("context_reminder", ["*"]))

        # (c) Wildcard ["*", "python"] rejected for detect_bug (M-3)
        with self.assertRaises(ValueError) as ctx_wc2:
            evolution_mod.evolve_learn(
                store_path=store, telemetry_store=tel, scar_id="CSB-WC-R2", slug="wc_mixed_detect",
                category="logic", languages=["*", "python"], role="detect_bug",
                trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                bad_pattern="b", good_pattern="g", precondition="w",
                broken_path=b_real, fixed_path=f_sku, test_path=t_sku,
            )
        self.assertIn("WILDCARD_LANGUAGE_FORBIDDEN_FOR_DETECT_BUG", str(ctx_wc2.exception))

        # (d) Re-importing an older superseded patch skips with already_superseded == 1 (M-3)
        s_src, t_src = self.tmp / "sup_src.json", self.tmp / "sup_src_tel.json"
        s_dst, t_dst = self.tmp / "sup_dst.json", self.tmp / "sup_dst_tel.json"
        p_v1, p_v2 = self.tmp / "patch_v1.json", self.tmp / "patch_v2.json"

        self.assertTrue(
            evolution_mod.evolve_learn(
                store_path=s_src, telemetry_store=t_src, scar_id="CSB-SUP-001", slug="sku_superseded",
                category="logic", languages=["python"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                bad_pattern="Old revision description v1", good_pattern="Normalize v1", precondition="SKU v1",
                broken_path=b_real, fixed_path=f_sku, test_path=t_sku,
            )["ok"]
        )
        ex1 = evolution_mod.evolve_export_patch(store_path=s_src, telemetry_store=t_src, out_path=p_v1)

        self.assertTrue(
            evolution_mod.evolve_learn(
                store_path=s_src, telemetry_store=t_src, scar_id="CSB-SUP-001", slug="sku_superseded",
                category="logic", languages=["python"], trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                bad_pattern="Newer revision description v2", good_pattern="Normalize v2", precondition="SKU v2",
                broken_path=b_real, fixed_path=f_sku, test_path=t_sku,
            )["ok"]
        )
        ex2 = evolution_mod.evolve_export_patch(store_path=s_src, telemetry_store=t_src, out_path=p_v2)

        r_i1 = evolution_mod.evolve_import_patch(p_v1, store_path=s_dst, telemetry_store=t_dst, expected_patch_sha256=ex1["patch_sha256"], quarantine=False)
        r_i2 = evolution_mod.evolve_import_patch(p_v2, store_path=s_dst, telemetry_store=t_dst, expected_patch_sha256=ex2["patch_sha256"], quarantine=False)
        r_replay_v1 = evolution_mod.evolve_import_patch(p_v1, store_path=s_dst, telemetry_store=t_dst, expected_patch_sha256=ex1["patch_sha256"], quarantine=False)
        self.assertEqual((r_i1["imported"], r_i2["imported"]), (1, 1))
        self.assertEqual((r_replay_v1["imported"], r_replay_v1["already_present"], r_replay_v1["already_superseded"]), (0, 0, 1))

    def test_13_v311_truth_gate_isolation_unittest_runtime_asserts_node_ipc_and_rss(self) -> None:
        # (a) isolation_level + candidate worker sys.argv == ["candidate.py"]
        b_arg = self._w("a311_b_arg.py", "def get_argv():\n    return ['wrong']\n")
        f_arg = self._w("a311_f_arg.py", "import sys\ndef get_argv():\n    return list(sys.argv)\n")
        t_arg = self._w(
            "a311_t_arg.py",
            "import candidate\nargv = candidate.get_argv()\n"
            "assert argv == ['candidate.py'], f'got {argv}'\n"
            "assert '_oracle_test' not in ' '.join(argv)\n",
        )
        r_arg = truth_gate_mod.run_custom_truth_gate(b_arg, f_arg, t_arg, runner="python")
        self.assertTrue(r_arg["ok"], r_arg)
        self.assertEqual(r_arg["isolation_level"], "OS_SUBPROCESS_IPC_SAME_UID")
        self.assertTrue(bool(r_arg.get("isolation_note")))

        # (b) Python fixed skipping assertions OR decoy `assert True` -> NO_ASSERTIONS_EXECUTED (assertions_run=0)
        b_flg = self._w("a311_b_flg.py", "def flag():\n    return True\ndef val():\n    return 0\n")
        f_flg = self._w("a311_f_flg.py", "def flag():\n    return False\ndef val():\n    return 1\n")
        for label, t_src in (
            ("skip_branch", "import candidate\nif candidate.flag():\n    assert False\n"),
            ("decoy_true", "import candidate\nassert True\nif candidate.flag():\n    assert candidate.val() == 1\n"),
        ):
            with self.subTest(py_no_assert=label):
                r_na = truth_gate_mod.run_custom_truth_gate(b_flg, f_flg, self._w(f"a311_t_{label}.py", t_src), runner="python")
                self.assertFalse(r_na["ok"], r_na)
                self.assertEqual(r_na["verdict"], "REJECTED_TRUTH_GATE")
                self.assertEqual(r_na["isolation_level"], "OS_SUBPROCESS_IPC_SAME_UID")
                self.assertEqual(r_na["fixed_verdict"], "NO_ASSERTIONS_EXECUTED")
                self.assertEqual(r_na["fixed_assertions_run"], 0)

        # (c) Real unittest.TestCase + unittest.main() oracle: broken fails cleanly, fixed passes, cand errors -> INFRA_ERROR
        t_ut = self._w(
            "a311_t_ut.py",
            "import unittest, candidate\n"
            "class TestDouble(unittest.TestCase):\n"
            "    def test_dbl(self):\n"
            "        self.assertEqual(candidate.dbl(4), 8)\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
        )
        b_ut = self._w("a311_b_ut.py", "def dbl(x: int) -> int:\n    return x + 1\n")
        f_ut = self._w("a311_f_ut.py", "def dbl(x: int) -> int:\n    return x * 2\n")
        r_ut = truth_gate_mod.run_custom_truth_gate(b_ut, f_ut, t_ut, runner="python")
        self.assertTrue(r_ut["ok"], r_ut)
        self.assertEqual((r_ut["broken_verdict"], r_ut["broken_setup_error"]), ("EXPECTED_PROPERTY_FAIL", False))
        self.assertEqual(r_ut["fixed_verdict"], "PROPERTY_PASSED")
        self.assertEqual(r_ut["fixed_assertions_run"], 1)

        # (c2) unittest.TestCase with skipped assertions MUST be rejected as NO_ASSERTIONS_EXECUTED (assertions_run=0)
        t_ut_skip = self._w(
            "a311_t_ut_skip.py",
            "import unittest, candidate\n"
            "class TestSkipAssert(unittest.TestCase):\n"
            "    def test_skipped(self):\n"
            "        if candidate.flag():\n"
            "            self.assertEqual(1, 2)\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
        )
        r_ut_skip = truth_gate_mod.run_custom_truth_gate(b_flg, f_flg, t_ut_skip, runner="python")
        self.assertFalse(r_ut_skip["ok"], r_ut_skip)
        self.assertEqual(r_ut_skip["verdict"], "REJECTED_TRUTH_GATE")
        self.assertEqual(r_ut_skip["fixed_verdict"], "NO_ASSERTIONS_EXECUTED")
        self.assertEqual(r_ut_skip["fixed_assertions_run"], 0)

        for label, bad_src in (
            ("ut_runtime_err", "def dbl(x: int) -> int:\n    raise RuntimeError('cand_boom')\n"),
            ("ut_assert_err", "def dbl(x: int) -> int:\n    raise AssertionError('cand_fake_assert')\n"),
        ):
            with self.subTest(ut_err=label):
                r_err = truth_gate_mod.run_custom_truth_gate(self._w(f"a311_{label}.py", bad_src), f_ut, t_ut, runner="python")
                self.assertFalse(r_err["ok"], r_err)
                self.assertEqual(r_err["broken_verdict"], "INFRA_ERROR")
                self.assertTrue(r_err["broken_setup_error"])

        # (d) Candidate stdout printing dynamically assembled KINTSUGI_VERDICT JSON cannot hijack oracle property_id
        b_hj = self._w(
            "a311_b_hj.py",
            "import json\n"
            "def calc(x):\n"
            "    print('KINTSUGI_' + 'VERDICT:' + json.dumps({'property_id':'HIJACKED_B','verdict':'EXPECTED_PROPERTY_FAIL','assertions_run':99}))\n"
            "    return x + 1\n",
        )
        f_hj = self._w(
            "a311_f_hj.py",
            "import json\n"
            "def calc(x):\n"
            "    print('KINTSUGI_' + 'VERDICT:' + json.dumps({'property_id':'HIJACKED_F','verdict':'PROPERTY_PASSED','assertions_run':99}))\n"
            "    return x * 2\n",
        )
        t_hj = self._w(
            "a311_t_hj.py",
            "import json, candidate\n"
            "v = candidate.calc(4)\n"
            "if v != 8:\n"
            "    print('KINTSUGI_VERDICT:' + json.dumps({'property_id':'REAL_PROP_42','verdict':'EXPECTED_PROPERTY_FAIL','assertions_run':1}))\n"
            "    assert v == 8\n"
            "print('KINTSUGI_VERDICT:' + json.dumps({'property_id':'REAL_PROP_42','verdict':'PROPERTY_PASSED','assertions_run':1}))\n"
            "assert v == 8\n",
        )
        r_hj = truth_gate_mod.run_custom_truth_gate(b_hj, f_hj, t_hj, runner="python")
        self.assertTrue(r_hj["ok"], r_hj)
        self.assertEqual((r_hj["broken_property_id"], r_hj["fixed_property_id"]), ("REAL_PROP_42", "REAL_PROP_42"))

        # (e) Node.js 2-process IPC (distinct PID, FD 3..32 forgery blocked, process.exit(0) -> INFRA_ERROR, async .then, skipped assert)
        if shutil.which("node") is not None:
            b_pid = self._w("a311_b_pid.mjs", "export function getPid() { return -1; }\n")
            f_pid = self._w("a311_f_pid.mjs", "export function getPid() { return process.pid; }\n")
            t_pid = self._w(
                "a311_t_pid.mjs",
                "import assert from 'node:assert/strict';\n"
                "import { getPid } from './candidate.mjs';\n"
                "const cpid = getPid();\n"
                "assert.ok(cpid > 0);\n"
                "assert.notStrictEqual(cpid, process.pid);\n",
            )
            r_npid = truth_gate_mod.run_custom_truth_gate(b_pid, f_pid, t_pid, runner="node")
            self.assertTrue(r_npid["ok"], r_npid)
            self.assertEqual(r_npid["isolation_level"], "OS_SUBPROCESS_IPC_SAME_UID")

            b_nval = self._w("a311_b_nval.mjs", "export function calc(x) { return 0; }\n")
            f_nfd = self._w(
                "a311_f_nfd.mjs",
                "import fs from 'node:fs';\n"
                "export function calc(x) {\n"
                "  const line = JSON.stringify({property_id:'ASSERTION',verdict:'PROPERTY_PASSED',assertions_run:1}) + '\\n';\n"
                "  for (let fd = 3; fd <= 32; fd++) { try { fs.writeSync(fd, line); } catch {} }\n"
                "  return 0;\n"
                "}\n",
            )
            t_nval = self._w(
                "a311_t_nval.mjs",
                "import assert from 'node:assert/strict';\nimport { calc } from './candidate.mjs';\nassert.strictEqual(calc(4), 8);\n",
            )
            r_nfd = truth_gate_mod.run_custom_truth_gate(b_nval, f_nfd, t_nval, runner="node")
            self.assertFalse(r_nfd["ok"], r_nfd)
            self.assertEqual(r_nfd["fixed_verdict"], "EXPECTED_PROPERTY_FAIL")

            f_nexit = self._w("a311_f_nexit.mjs", "export function calc(x) { process.exit(0); }\n")
            r_nexit = truth_gate_mod.run_custom_truth_gate(b_nval, f_nexit, t_nval, runner="node")
            self.assertFalse(r_nexit["ok"], r_nexit)
            self.assertEqual(r_nexit["fixed_verdict"], "INFRA_ERROR")

            b_async = self._w("a311_b_async.mjs", "export async function fetchNum() { return 1; }\n")
            f_async = self._w("a311_f_async.mjs", "export async function fetchNum() { return 42; }\n")
            t_async = self._w(
                "a311_t_async.mjs",
                "import assert from 'node:assert/strict';\n"
                "import { fetchNum } from './candidate.mjs';\n"
                "fetchNum().then((v) => { assert.strictEqual(v, 42); });\n",
            )
            r_async = truth_gate_mod.run_custom_truth_gate(b_async, f_async, t_async, runner="node")
            self.assertTrue(r_async["ok"], r_async)
            self.assertGreaterEqual(r_async["fixed_assertions_run"], 1)

            b_nskip = self._w("a311_b_nskip.mjs", "export function flag() { return true; }\n")
            f_nskip = self._w("a311_f_nskip.mjs", "export function flag() { return false; }\n")
            t_nskip = self._w(
                "a311_t_nskip.mjs",
                "import assert from 'node:assert/strict';\n"
                "import { flag } from './candidate.mjs';\n"
                "if (flag()) { assert.strictEqual(1, 2); }\n",
            )
            r_nskip = truth_gate_mod.run_custom_truth_gate(b_nskip, f_nskip, t_nskip, runner="node")
            self.assertFalse(r_nskip["ok"], r_nskip)
            self.assertEqual(r_nskip["fixed_verdict"], "NO_ASSERTIONS_EXECUTED")
            self.assertEqual(r_nskip["fixed_assertions_run"], 0)

        # (f) Linux VmRSS watchdog unit test (RSS_LIMIT_EXCEEDED -> INFRA_ERROR)
        self.assertEqual(
            truth_gate_mod._extract_run_verdict("", False, "", -9, False, False, rss_exceeded=True),
            ("INFRA_ERROR", "RSS_LIMIT_EXCEEDED", 0, True, False),
        )
        with (
            mock.patch.object(truth_gate_mod.sys, "platform", "linux"),
            mock.patch.object(truth_gate_mod, "_read_proc_rss_kib", return_value=truth_gate_mod.NODE_RSS_LIMIT_KIB + 4096),
        ):
            rc, _out, err, _ver, _ov, _to, rss_hit, _nonce = truth_gate_mod._run_bounded_subprocess(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                cwd=str(self.tmp),
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                timeout_s=5,
                apply_rlimit_as=False,
            )
        self.assertTrue(rss_hit)
        self.assertIn("RSS_LIMIT_EXCEEDED", err)
        self.assertNotEqual(rc, 0)

    def test_14_v311_evolution_lang_scope_neg_control_det_rev_history_and_unpinned_import(self) -> None:
        store, tel = self.tmp / "a311_evo.json", self.tmp / "a311_tel.json"
        _b_bare, b_real, f_sku, t_sku = self._sku_files()
        b_strip = self._w("a311_sku_strip.py", "def clean_sku(s: str) -> str:\n    return s.strip()\n")

        # (a) Python proof rejected for languages=["python", "sql"] under detect_bug
        r_lang = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-LANG-001", slug="multi_lang_bad",
            category="logic", languages=["python", "sql"], role="detect_bug",
            trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
            bad_pattern="b", good_pattern="g", precondition="w",
            broken_path=b_real, fixed_path=f_sku, test_path=t_sku, runner="python",
        )
        self.assertFalse(r_lang["ok"])
        self.assertEqual(r_lang["status"], "REJECTED_LANGUAGE_PROOF_MISMATCH")

        # (b) detect_bug rejects triggers still matching fixed; context_reminder allows matching fixed (requiring broken match)
        r_still = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-NEG-001", slug="still_matches_fixed",
            category="logic", languages=["python"], role="detect_bug",
            trigger_groups=[["clean_sku"], ["strip", "upper"]],
            bad_pattern="strip without upper", good_pattern="s.strip().upper()", precondition="SKU",
            broken_path=b_strip, fixed_path=f_sku, test_path=t_sku, runner="python",
        )
        self.assertFalse(r_still["ok"])
        self.assertEqual(r_still["status"], "REJECTED_TRIGGERS_STILL_MATCH_FIXED")

        r_ctx_miss = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-CTX-MISS", slug="ctx_misses_broken",
            category="logic", languages=["python"], role="context_reminder",
            trigger_groups=[["clean_sku"], ["nonexistent_marker_xyz"]],
            bad_pattern="strip without upper", good_pattern="s.strip().upper()", precondition="SKU",
            broken_path=b_strip, fixed_path=f_sku, test_path=t_sku, runner="python",
        )
        self.assertFalse(r_ctx_miss["ok"])
        self.assertEqual(r_ctx_miss["status"], "REJECTED_TRIGGERS_MISS_BROKEN_REPRO")

        r_ctx_ok = evolution_mod.evolve_learn(
            store_path=store, telemetry_store=tel, scar_id="CSB-CTX-OK", slug="ctx_allows_fixed",
            category="logic", languages=["python"], role="context_reminder",
            trigger_groups=[["clean_sku"], ["strip", "upper"]],
            bad_pattern="strip without upper", good_pattern="s.strip().upper()", precondition="SKU",
            broken_path=b_strip, fixed_path=f_sku, test_path=t_sku, runner="python",
        )
        self.assertTrue(r_ctx_ok["ok"], r_ctx_ok)

        # (c) Deterministic revision_sha256 independent of verified_utc + parent_revision_sha256 persisted
        det_store, det_tel = self.tmp / "a311_det.json", self.tmp / "a311_det_tel.json"
        r_d1 = evolution_mod.evolve_learn(
            store_path=det_store, telemetry_store=det_tel, scar_id="CSB-DET-001", slug="det_rev_sku",
            category="logic", languages=["python"], role="detect_bug",
            trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
            bad_pattern="Deterministic rev 1", good_pattern="s.strip().upper()", precondition="SKU",
            broken_path=b_real, fixed_path=f_sku, test_path=t_sku, runner="python",
        )
        self.assertTrue(r_d1["ok"], r_d1)
        rev1_sha = r_d1["scar"]["revision_sha256"]
        rev1_utc = r_d1["scar"]["truth_gate_proof"]["verified_utc"]
        self.assertEqual(r_d1["scar"]["revision"], 1)
        self.assertEqual(r_d1["scar"]["parent_revision_sha256"], "")

        real_tg_res = truth_gate_mod.run_custom_truth_gate(b_real, f_sku, t_sku, runner="python")
        self.assertTrue(real_tg_res["ok"], real_tg_res)
        _real_dt = evolution_mod.datetime

        class _FutureDatetime:
            @staticmethod
            def now(_tz: Any = None) -> Any:
                return _real_dt(2099, 12, 31, 23, 59, 59, tzinfo=evolution_mod.timezone.utc)

        with (
            mock.patch.object(evolution_mod, "run_custom_truth_gate", return_value=real_tg_res),
            mock.patch.object(evolution_mod, "datetime", _FutureDatetime),
        ):
            r_d1_again = evolution_mod.evolve_learn(
                store_path=det_store, telemetry_store=det_tel, scar_id="CSB-DET-001", slug="det_rev_sku",
                category="logic", languages=["python"], role="detect_bug",
                trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                bad_pattern="Deterministic rev 1", good_pattern="s.strip().upper()", precondition="SKU",
                broken_path=b_real, fixed_path=f_sku, test_path=t_sku, runner="python",
            )
        self.assertNotEqual(r_d1_again["scar"]["truth_gate_proof"]["verified_utc"], rev1_utc)
        self.assertEqual(r_d1_again["scar"]["revision_sha256"], rev1_sha)
        self.assertEqual(r_d1_again["scar"]["revision"], 1)

        # (d) 14+ revisions retained in previous_revisions (up to 64) blocking rev-1 downgrade replay
        p_rev1 = self.tmp / "det_rev1_patch.json"
        ex_rev1 = evolution_mod.evolve_export_patch(store_path=det_store, telemetry_store=det_tel, out_path=p_rev1)
        prev_sha = rev1_sha
        last_scar: Dict[str, Any] = r_d1["scar"]
        with mock.patch.object(evolution_mod, "run_custom_truth_gate", return_value=real_tg_res):
            for idx in range(2, 16):
                r_next = evolution_mod.evolve_learn(
                    store_path=det_store, telemetry_store=det_tel, scar_id="CSB-DET-001", slug="det_rev_sku",
                    category="logic", languages=["python"], role="detect_bug",
                    trigger_groups=[["clean_sku"], ["lstrip", "swapcase"]],
                    bad_pattern=f"Deterministic rev {idx}", good_pattern="s.strip().upper()", precondition="SKU",
                    broken_path=b_real, fixed_path=f_sku, test_path=t_sku, runner="python",
                )
                self.assertTrue(r_next["ok"], r_next)
                last_scar = r_next["scar"]
                self.assertEqual(last_scar["parent_revision_sha256"], prev_sha)
                prev_sha = last_scar["revision_sha256"]
        self.assertEqual(last_scar["revision"], 15)
        self.assertEqual(len(last_scar["previous_revisions"]), 14)
        self.assertIn(rev1_sha, last_scar["previous_revisions"])

        r_dg_replay = evolution_mod.evolve_import_patch(
            p_rev1, store_path=det_store, telemetry_store=det_tel,
            expected_patch_sha256=ex_rev1["patch_sha256"], quarantine=False,
        )
        self.assertEqual((r_dg_replay["imported"], r_dg_replay["already_superseded"]), (0, 1))

        # (e) Unpinned live import raises REFUSING_UNPINNED_LIVE_IMPORT unless expected_patch_sha256 or trust_unverified_proof=True
        fresh_dst = self.tmp / "unpinned_dst.json"
        with self.assertRaises(PermissionError) as ctx_up:
            evolution_mod.evolve_import_patch(p_rev1, store_path=fresh_dst, telemetry_store=det_tel, quarantine=False)
        self.assertIn("REFUSING_UNPINNED_LIVE_IMPORT", str(ctx_up.exception))
        self.assertFalse(fresh_dst.exists())

        r_trust = evolution_mod.evolve_import_patch(
            p_rev1, store_path=fresh_dst, telemetry_store=det_tel, quarantine=False, trust_unverified_proof=True,
        )
        self.assertTrue(r_trust["ok"] and r_trust["imported"] == 1)


# ===========================================================================
# 3. Scanner, Matcher, Tx-Guard, Ledger, Brief, Auto-Telemetry & Audit Tests
# ===========================================================================


class TestScannerMatcherGateLedgerBriefAuditAdversarial(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_ctx = tempfile.TemporaryDirectory(prefix="kintsugi_adv_scan_")
        self.tmp = Path(self.tmp_ctx.name)

    def tearDown(self) -> None:
        self.tmp_ctx.cleanup()

    def test_01_scan_target_symlinks_empty_binary_only_and_dist_dir(self) -> None:
        real_f = self.tmp / "real.py"
        real_f.write_text("x = 1\n", encoding="utf-8")
        sym_f = self.tmp / "sym_target.py"
        sym_f.symlink_to(real_f)
        s_sym = scanner_mod.scan_target(sym_f)
        self.assertFalse(s_sym["ok"])
        self.assertTrue(any(f["rule"] == "SYMLINK-REJECTED" for f in s_sym["findings"]))

        outside = self.tmp / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        ws = self.tmp / "ws_sym"
        ws.mkdir()
        (ws / "clean.py").write_text("x = 1\n", encoding="utf-8")
        (ws / "escape.py").symlink_to(outside)
        s_ws = scanner_mod.scan_target(ws)
        self.assertFalse(s_ws["ok"])
        self.assertTrue(any(f["rule"] == "SYMLINK-REJECTED" for f in s_ws["findings"]))
        self.assertGreaterEqual(len(s_ws["symlink_rejections"]), 1)

        empty_d = self.tmp / "empty_dir"
        empty_d.mkdir()
        s_emp = scanner_mod.scan_target(empty_d)
        self.assertEqual((s_emp["ok"], s_emp["status"], s_emp["inspected_files"]), (False, "EMPTY_OR_UNINSPECTED", 0))

        bin_d = self.tmp / "bin_dir"
        bin_d.mkdir()
        (bin_d / "ledger.xlsx").write_bytes(b"PK\x03\x04\x00\x00xlsx")
        (bin_d / "pack.zip").write_bytes(b"PK\x03\x04\x00\x00zip")
        s_bin = scanner_mod.scan_target(bin_d)
        self.assertEqual((s_bin["ok"], s_bin["status"], s_bin["inspected_files"]), (False, "INCOMPLETE_SCAN", 0))
        self.assertGreaterEqual(len(s_bin["unsupported_binary_files"]), 2)
        s_bin_allow = scanner_mod.scan_target(bin_d, allow_binary=True)
        self.assertEqual((s_bin_allow["ok"], s_bin_allow["status"], s_bin_allow["inspected_files"]), (False, "EMPTY_OR_UNINSPECTED", 0))

        proj = self.tmp / "proj_dist"
        (proj / "dist").mkdir(parents=True)
        (proj / "dist" / "out.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
        s_dist = scanner_mod.scan_target(proj)
        self.assertEqual((s_dist["ok"], s_dist["inspected_files"]), (True, 1))

    def test_02_python_ast_alias_bypasses_all_caught(self) -> None:
        cases = [
            ("alias_from_os.py", "from os import " + "sys" + "tem as x\nx('id')\n", "SEC-FORBIDDEN-CALL"),
            ("alias_subproc.py", "import subprocess as sp\nsp.run('id', sh" + "ell=True)\n", "SEC-SHELL-TRUE"),
            ("alias_getattr.py", "import os\ngetattr(os, '" + "sys" + "tem')('id')\n", "SEC-FORBIDDEN-CALL"),
            ("alias_yaml.py", "from yaml import " + "lo" + "ad as yl\ndef parse(u):\n    return yl(u)\n", "SEC-YAML-UNSAFE"),
        ]
        for fname, src, rule in cases:
            p = self.tmp / fname
            p.write_text(src, encoding="utf-8")
            res = scanner_mod.scan_target(p)
            self.assertFalse(res["ok"], fname)
            self.assertIn(rule, {f["rule"] for f in res["findings"]})

        safe_y = self.tmp / "safe_yaml.py"
        safe_y.write_text("import yaml\ndef parse(u):\n    return yaml." + "lo" + "ad(u, Loader=yaml.SafeLoader)\n", encoding="utf-8")
        self.assertTrue(scanner_mod.scan_target(safe_y)["ok"])

    def test_03_python_floor_division_preserved_in_mask_and_erc4626_merkle_matching(self) -> None:
        masked = scanner_mod.mask_code_lines("shares = (assets * total_shares) // (total_assets + 1)  # comment\n", lang="python")
        self.assertIn("// (total_assets + 1)", masked[0])
        self.assertNotIn("comment", masked[0])

        vault_py = "def preview_deposit(assets: int, total_shares: int, total_assets: int) -> int:\n    return (assets * (total_shares + 10**6)) // (total_assets + 1)\n"
        b_v = kintsugi_sandbox_mod.build_brief(code_override=vault_py, lang_hint="python")
        self.assertIn("@struct_share_vault_ratio", b_v["structural_tags"])
        self.assertIn("CAP-FIN-ERC4626", [c["id"] for c in b_v["capsules"]])

        merkle_py = "import hashlib\ndef fold(nodes):\n    while len(nodes) > 1:\n        half = len(nodes) // 2\n        nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest() for i in range(0, half * 2, 2)]\n    return nodes[0]\n"
        b_m = kintsugi_sandbox_mod.build_brief(code_override=merkle_py, lang_hint="python")
        self.assertIn("@struct_halving_hash_tree", b_m["structural_tags"])
        self.assertIn("CAP-CRYPTO-RFC6962-MERKLE", [c["id"] for c in b_m["capsules"]])

    def test_04_tx_guard_nested_nfkc_zerowidth_and_numeric_dos(self) -> None:
        base_ok = {
            "status": "open", "deposit_required": False, "entry_fee": 0, "transfers_funds": False,
            "signing": {"action": "personal_sign", "value": 0},
        }
        r_ok = kintsugi_sandbox_mod.evaluate_tx_guard(base_ok)
        self.assertEqual((r_ok["ok"], r_ok["verdict"]), (True, "PASS_READONLY_0_OUTBOUND"))

        r_kyc = kintsugi_sandbox_mod.evaluate_tx_guard({**base_ok, "kyc_required": True})
        self.assertEqual((r_kyc["ok"], r_kyc["verdict"]), (False, "NEEDS_OWNER_DECISION"))
        self.assertTrue(any("KYC" in d for d in r_kyc["owner_decisions"]))

        for label, meta, expect_substr in (
            ("nested_card", {**base_ok, "requirements": [{"note": "requires payment_card verification"}]}, "BLOCK_CARD_GATE"),
            ("nfkc_val", {**base_ok, "verified_by": "\uff50\uff41\uff59\uff4d\uff45\uff4e\uff54\uff3f\uff43\uff41\uff52\uff44"}, "BLOCK_CARD_GATE"),
            ("nfkc_key", {**base_ok, "\uff44eposit_required": True}, "BLOCK_DEPOSIT_REQUIRED"),
            ("zw_key", {**base_ok, "deposit\u200b_required": True}, "BLOCK_DEPOSIT_REQUIRED"),
            ("zw_fee", {**base_ok, "entry\u200b_fee": 10}, "BLOCK_DEPOSIT_REQUIRED"),
            ("dos_100digits", {**base_ok, "entry_fee": "9" * 100}, "NUMERIC_LENGTH_INVALID"),
        ):
            r = kintsugi_sandbox_mod.evaluate_tx_guard(meta)
            self.assertEqual((r["ok"], r["verdict"]), (False, "BLOCKED"), label)
            self.assertTrue(any(expect_substr in b for b in r["blocks"]), f"{label}: {r['blocks']}")

    def test_05_ledger_check_float_precision_invalid_fx_quant_and_tick_rounding(self) -> None:
        p_ok = _run_sandbox_cli("ledger-check", "--lines", "[0.1, 0.2]", "--total", "0.30")
        self.assertEqual(p_ok.returncode, 0, p_ok.stdout)
        j_ok = json.loads(p_ok.stdout)
        self.assertEqual((j_ok["ok"], j_ok["status"], j_ok["computed_total"]), (True, "MATCH_EXACT", "0.30"))

        for bad_fx in ("0", "-1"):
            with self.assertRaises(ValueError) as ctx_fx:
                kintsugi_sandbox_mod.verify_decimal_ledger(["1.00"], "0.00", fx_rate=bad_fx)
            self.assertIn("INVALID_FX_RATE", str(ctx_fx.exception))
            p_fx = _run_sandbox_cli("ledger-check", "--lines", '["1.00"]', "--total", "0.00", "--fx", bad_fx)
            self.assertEqual(p_fx.returncode, 1)
            self.assertIn("INVALID_FX_RATE", p_fx.stdout)

        with self.assertRaises(ValueError) as ctx_q:
            kintsugi_sandbox_mod.verify_decimal_ledger(["1.00"], "1.00", quant="0")
        self.assertIn("INVALID_QUANT_STEP", str(ctx_q.exception))

        tick = kintsugi_sandbox_mod.verify_decimal_ledger(["1.03", "1.02"], "2.05", quant="0.05")
        self.assertEqual((tick["ok"], tick["converted_lines"], tick["computed_total"]), (True, ["1.05", "1.00"], "2.05"))

    def test_06_brief_en_budget_missing_file_auto_telemetry_and_verify_delivery_attribution(self) -> None:
        state_dir = self.tmp / "sandbox_state"
        p_en = _run_sandbox_cli(
            "brief", "--task", "Audit ERC-4626 vault share math and multi-currency FX tax ledger",
            "--lang", "python", "--state-dir", str(state_dir), "--session-id", "sess-en-01",
        )
        self.assertEqual(p_en.returncode, 0, p_en.stdout + p_en.stderr)
        j_en = json.loads(p_en.stdout)
        self.assertTrue(j_en["ok"] and j_en["telemetry_recorded"] and j_en["envelope_id"].startswith("env-"))
        self.assertGreaterEqual(j_en["matched_capsules_count"], 1)
        self.assertGreaterEqual(j_en["matched_pitfalls_count"], 1)
        self.assertLess(j_en["estimated_tokens"], 500)

        p_miss = _run_sandbox_cli("brief", str(self.tmp / "nonexistent_file.py"), "--state-dir", str(state_dir))
        self.assertEqual(p_miss.returncode, 1)
        self.assertIn("BRIEF_TARGET_NOT_FOUND", p_miss.stdout)

        clean_py = self.tmp / "clean_delivery.py"
        clean_py.write_text("from decimal import Decimal\ndef total(a: Decimal, b: Decimal) -> Decimal:\n    return a + b\n", encoding="utf-8")
        p_vd_ok = _run_sandbox_cli("verify-delivery", str(clean_py), "--envelope-id", j_en["envelope_id"], "--state-dir", str(state_dir))
        self.assertEqual(p_vd_ok.returncode, 0, p_vd_ok.stdout)
        self.assertEqual(json.loads(p_vd_ok.stdout)["status"], "DELIVERY_VERIFIED_PASS")

        tel_inf = self.tmp / "tel_infra.json"
        empty_d = self.tmp / "empty_deliv"
        empty_d.mkdir()
        for idx in range(3):
            res_inf = kintsugi_sandbox_mod.verify_delivery(
                empty_d, envelope_id=f"env-inf-{idx}", telemetry_store=tel_inf,
                session_id=f"s-inf-{idx}", capsule_ids=["CAP-FIN-ERC4626"], pitfall_ids=["LT-007"],
            )
            self.assertEqual((res_inf["ok"], res_inf["status"], res_inf["unattributed_failure"]), (False, "DELIVERY_FAILED_UNATTRIBUTED", True))
        self.assertEqual(telemetry_mod.build_telemetry_report(tel_inf)["frozen_ids"], [])

        tel_sc = self.tmp / "tel_scoped.json"
        bad_ex = self.tmp / "bad_except.py"
        bad_ex.write_text("def run():\n    try:\n        return 1\n    except Exception:\n        pass\n", encoding="utf-8")
        for idx in (1, 2):
            res_sc = kintsugi_sandbox_mod.verify_delivery(
                bad_ex, envelope_id=f"env-sc-{idx}", telemetry_store=tel_sc,
                session_id=f"s-sc-{idx}", capsule_ids=["CAP-FIN-ERC4626"], pitfall_ids=["LT-007"],
                confirm_included=True,
            )
            self.assertEqual((res_sc["status"], res_sc["attributed_ids"]), ("DELIVERY_FAILED_ATTRIBUTED", ["LT-007"]))
        frozen_sc = telemetry_mod.build_telemetry_report(tel_sc)["frozen_ids"]
        self.assertIn("LT-007", frozen_sc)
        self.assertNotIn("CAP-FIN-ERC4626", frozen_sc)

    def test_07_audit_deliverable_bom_meta_words_and_placeholders(self) -> None:
        meta_eval, meta_disp, todo_tok = "evalu" + "ator", "disp" + "ute", "TO" + "DO:"
        bom_json = self.tmp / "out.json"
        bom_json.write_bytes(b"\xef\xbb\xbf" + f'{{"note": "{meta_eval} {meta_disp} {todo_tok} fix"}}\n'.encode("utf-8"))
        r_j = scanner_mod.audit_deliverable(bom_json)
        self.assertFalse(r_j["ok"])
        self.assertTrue({"LT-053", "LT-054", "LT-055"}.issubset({f["rule"] for f in r_j["deliverable_findings"]}))

        bom_csv = self.tmp / "table.csv"
        bom_csv.write_bytes(b"\xef\xbb\xbfcol1,col2\n1,2\n")
        r_c = scanner_mod.audit_deliverable(bom_csv)
        self.assertFalse(r_c["ok"])
        self.assertIn("LT-053", {f["rule"] for f in r_c["deliverable_findings"]})

        clean_json = self.tmp / "clean.json"
        clean_json.write_text('{"status": "complete", "rows": 2}\n', encoding="utf-8")
        self.assertEqual(scanner_mod.audit_deliverable(clean_json)["status"], "PASS_DELIVERABLE_AUDIT")

    def test_08_compact_redacts_synthetic_secret_via_dlp(self) -> None:
        doc_p = self.tmp / "notes.txt"
        doc_p.write_text(f"Summary\n---\nToken: {SYNTH_API_SECRET}\nHost: {SYNTH_RFC1918_IP}\nDone\n", encoding="utf-8")
        proc = _run_sandbox_cli("compact", str(doc_p), "--max-lines", "50")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        res = json.loads(proc.stdout)
        self.assertTrue(res["ok"] and "[REDACTED_DLP]" in res["content"])
        self.assertNotIn(SYNTH_API_SECRET, proc.stdout)
        self.assertNotIn(SYNTH_RFC1918_IP, proc.stdout)

    def test_09_round2_scanner_nul_incomplete_ast_bypasses_junk_and_auto_mask(self) -> None:
        # (a) NUL byte smuggled inside evil.py or .env -> CRITICAL DLP-BIDI-OR-NUL, ok=False (even beside clean file)
        for fname, payload in (("evil.py", b"x = 1\x00\n"), (".env", b"APP_MODE=prod\x00\n")):
            with self.subTest(nul_case=fname):
                d = self.tmp / f"nul_{fname.replace('.', '_')}"
                d.mkdir()
                (d / "good.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
                (d / fname).write_bytes(payload)
                res = scanner_mod.scan_target(d)
                self.assertFalse(res["ok"])
                self.assertTrue(
                    any(f["rule"] == "DLP-BIDI-OR-NUL" and f["severity"] == "CRITICAL" for f in res["findings"]),
                    res["findings"],
                )

        # (b) Oversized >2 MiB .py file -> ok=False, status=INCOMPLETE_SCAN (never PASS_100)
        d_big = self.tmp / "oversized_dir"
        d_big.mkdir()
        (d_big / "good.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
        (d_big / "huge.py").write_bytes(b"x = 1\n" * ((2 * 1024 * 1024 // 6) + 200))
        res_big = scanner_mod.scan_target(d_big)
        self.assertEqual((res_big["ok"], res_big["status"]), (False, "INCOMPLETE_SCAN"))
        self.assertGreaterEqual(len(res_big["skipped_files"]), 1)

        # (c) Unreadable chmod 0o000 subdir -> ok=False, status=INCOMPLETE_SCAN (always restore 0o700)
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            d_unr = self.tmp / "unreadable_root"
            d_unr.mkdir()
            (d_unr / "good.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
            locked = d_unr / "secret_sub"
            locked.mkdir()
            (locked / "hidden.py").write_text("x = 1\n", encoding="utf-8")
            os.chmod(locked, 0o000)
            try:
                res_unr = scanner_mod.scan_target(d_unr)
            finally:
                os.chmod(locked, 0o700)
            self.assertEqual((res_unr["ok"], res_unr["status"]), (False, "INCOMPLETE_SCAN"))
            self.assertGreaterEqual(len(res_unr["unreadable_dirs"]), 1)

        # (d) All 6 Python AST bypasses caught + non-SQL runner.execute returns PASS_100 (0 FP)
        ast_bypasses = [
            ("kw_shell.py", 'import subprocess\nsubprocess.run(["id"], **{"sh' + 'ell": True})\n', "SEC-SHELL-TRUE"),
            ("getattr_concat.py", 'import os\ngetattr(os, "sys"+"tem")("id")\n', "SEC-FORBIDDEN-CALL"),
            ("getattr_alias.py", 'import os\ng = getattr\ng(os, "sys' + 'tem")("id")\n', "SEC-FORBIDDEN-CALL"),
            ("tuple_unpack.py", 'import os\nrun, _ = os.' + 'sys' + 'tem, None\nrun("id")\n', "SEC-FORBIDDEN-CALL"),
            ("wildcard_os.py", "from os import *\n", "SEC-WILDCARD-IMPORT"),
            ("aug_sql.py", 'def fetch(cur, u):\n    q = "SELECT * FROM t WHERE id="\n    q += u\n    return cur.execute(q)\n', "SEC-SQL-CONCAT"),
        ]
        for fname, src, rule in ast_bypasses:
            with self.subTest(ast_bypass=fname):
                fp = self.tmp / fname
                fp.write_text(src, encoding="utf-8")
                res = scanner_mod.scan_target(fp)
                self.assertFalse(res["ok"], f"{fname}: {res}")
                self.assertIn(rule, {f["rule"] for f in res["findings"]}, res["findings"])

        safe_exec = self.tmp / "non_sql_exec.py"
        safe_exec.write_text('def dispatch(runner, name: str):\n    return runner.execute("cmd_" + name)\n', encoding="utf-8")
        res_safe = scanner_mod.scan_target(safe_exec)
        self.assertEqual((res_safe["ok"], res_safe["status"], res_safe["total_findings"]), (True, "PASS_100", 0))

        # (e) audit-deliverable flags LT-062 on .env, .DS_Store, __pycache__, .coverage
        junk_d = self.tmp / "junk_deliv"
        junk_d.mkdir()
        (junk_d / "app.py").write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
        (junk_d / ".env").write_text("MODE=dev\n", encoding="utf-8")
        (junk_d / ".DS_Store").write_text("ds\n", encoding="utf-8")
        (junk_d / ".coverage").write_text("cov\n", encoding="utf-8")
        pc = junk_d / "__pycache__"
        pc.mkdir()
        (pc / "app.cpython-311.pyc").write_bytes(b"\x00\x00\x00\x00")
        aud = scanner_mod.audit_deliverable(junk_d)
        self.assertEqual((aud["ok"], aud["status"]), (False, "DELIVERABLE_ISSUES_FOUND"))
        lt62_files = {f["file"] for f in aud["deliverable_findings"] if f["rule"] == "LT-062"}
        for expected_junk in (".env", ".DS_Store", "__pycache__", ".coverage"):
            self.assertIn(expected_junk, lt62_files, lt62_files)

        # (f) mask_code_lines(..., lang="auto") preserves Python floor division `//`
        masked_auto = scanner_mod.mask_code_lines("shares = (assets * total) // total_assets", lang="auto")
        self.assertIn("// total_assets", masked_auto[0])

    def test_10_round2_tx_guard_ledger_verify_delivery_and_compact(self) -> None:
        # (a) tx-guard stricter policy rules (HIGH-1)
        base_ok = {
            "status": "open", "deposit_required": False, "entry_fee": 0, "transfers_funds": False,
            "signing": {"action": "personal_sign", "value": 0},
        }
        r_missing_act = kintsugi_sandbox_mod.evaluate_tx_guard({"status": "open", "deposit_required": False})
        self.assertEqual((r_missing_act["ok"], r_missing_act["verdict"]), (False, "BLOCKED"))
        self.assertTrue(any("BLOCK_INVALID_METADATA" in b for b in r_missing_act["blocks"]))

        r_conflict = kintsugi_sandbox_mod.evaluate_tx_guard({**base_ok, "state": "closed"})
        self.assertEqual((r_conflict["ok"], r_conflict["verdict"]), (False, "BLOCKED"))
        self.assertTrue(any("BLOCK_CONFLICTING_FIELDS" in b for b in r_conflict["blocks"]))

        r_ro = kintsugi_sandbox_mod.evaluate_tx_guard({"mode": "read_only", "deposit_required": False})
        self.assertEqual((r_ro["ok"], r_ro["verdict"]), (True, "PASS_READONLY_0_OUTBOUND"))

        r_visa = kintsugi_sandbox_mod.evaluate_tx_guard({**base_ok, "description": "Bind Visa credit card"})
        self.assertEqual((r_visa["ok"], r_visa["verdict"]), (False, "BLOCKED"))
        self.assertTrue(any("BLOCK_CARD_GATE" in b for b in r_visa["blocks"]))

        r_out = kintsugi_sandbox_mod.evaluate_tx_guard({**base_ok, "description": "call erc20_transfer and eth_sendRawTransaction"})
        self.assertEqual((r_out["ok"], r_out["verdict"]), (False, "BLOCKED"))
        self.assertTrue(any("BLOCK_OUTBOUND_TRANSFER" in b for b in r_out["blocks"]))

        # (b) verify-delivery: auto-attribution, no phantom sessions, clean retry, honest inclusion skip (H-5 / M-4)
        sql_bad = self.tmp / "vd_sql.py"
        sql_bad.write_text('def run(cur, u):\n    return cur.execute("SELECT * FROM t WHERE id=" + u)\n', encoding="utf-8")
        sh_bad = self.tmp / "vd_sh.py"
        sh_bad.write_text('import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, **{"sh' + 'ell": True})\n', encoding="utf-8")

        tel_attr = self.tmp / "vd_attr_tel.json"
        r_sql_vd = kintsugi_sandbox_mod.verify_delivery(
            sql_bad, envelope_id="env-sql-1", telemetry_store=tel_attr, session_id="sess-sql-only",
            capsule_ids=["CAP-ERP-MYSQL-DECIMAL-FX", "CAP-FIN-ERC4626"], pitfall_ids=["LT-003", "LT-007"],
            confirm_included=True,
        )
        self.assertEqual(r_sql_vd["status"], "DELIVERY_FAILED_ATTRIBUTED")
        self.assertEqual(set(r_sql_vd["attributed_ids"]), {"LT-003"})
        # Must NOT inflate total_sessions with phantom `:attr` session
        self.assertEqual(telemetry_mod.build_telemetry_report(tel_attr)["total_sessions"], 1)

        # Retry after fixing code on the SAME envelope_id succeeds without ENVELOPE_ALREADY_PATCH_BOUND
        # (both after subset `:attr` binding and when the primary envelope is already `patch_bound`)
        sql_bad.write_text('def run(cur, u):\n    return cur.execute("SELECT * FROM t WHERE id=?", (u,))\n', encoding="utf-8")
        r_retry = kintsugi_sandbox_mod.verify_delivery(
            sql_bad, envelope_id="env-sql-1", telemetry_store=tel_attr, session_id="sess-sql-only",
            confirm_included=True,
        )
        self.assertTrue(r_retry["ok"], r_retry)
        self.assertEqual(r_retry["status"], "DELIVERY_VERIFIED_PASS")
        self.assertEqual(r_retry["envelope_id"], "env-sql-1")

        r_retry_bound = kintsugi_sandbox_mod.verify_delivery(
            sql_bad, envelope_id="env-sql-1", telemetry_store=tel_attr, session_id="sess-sql-only",
            confirm_included=True,
        )
        self.assertTrue(r_retry_bound["ok"], r_retry_bound)
        self.assertEqual(r_retry_bound["status"], "DELIVERY_VERIFIED_PASS")
        self.assertTrue(r_retry_bound["envelope_id"].startswith("env-sql-1:retry-"), r_retry_bound["envelope_id"])
        self.assertEqual(telemetry_mod.build_telemetry_report(tel_attr)["total_sessions"], 1)

        # Full-envelope failure (`patch_bound=True` directly on `env-sh-retry`) -> fix -> clean `:retry-*` pass
        sh_retry = self.tmp / "vd_sh_retry.py"
        sh_retry.write_text('import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, **{"sh' + 'ell": True})\n', encoding="utf-8")
        tel_sh_retry = self.tmp / "vd_sh_retry_tel.json"
        r_fail_full = kintsugi_sandbox_mod.verify_delivery(
            sh_retry, envelope_id="env-sh-retry", telemetry_store=tel_sh_retry, session_id="sess-sh-retry",
            capsule_ids=["CAP-SEC-SUBPROCESS-ARGV"], pitfall_ids=["LT-005"], confirm_included=True,
        )
        self.assertEqual((r_fail_full["status"], r_fail_full["envelope_id"]), ("DELIVERY_FAILED_ATTRIBUTED", "env-sh-retry"))
        sh_retry.write_text('import subprocess\ndef run(cmd):\n    return subprocess.run(["echo", cmd], check=True)\n', encoding="utf-8")
        r_pass_retry = kintsugi_sandbox_mod.verify_delivery(
            sh_retry, envelope_id="env-sh-retry", telemetry_store=tel_sh_retry, session_id="sess-sh-retry",
            confirm_included=True,
        )
        self.assertEqual((r_pass_retry["ok"], r_pass_retry["status"]), (True, "DELIVERY_VERIFIED_PASS"))
        self.assertTrue(r_pass_retry["envelope_id"].startswith("env-sh-retry:retry-"), r_pass_retry["envelope_id"])
        self.assertEqual(telemetry_mod.build_telemetry_report(tel_sh_retry)["total_sessions"], 1)

        # Auto-attributes SEC-SHELL-TRUE without manual relevant_ids
        tel_sh = self.tmp / "vd_sh_tel.json"
        r_sh_vd = kintsugi_sandbox_mod.verify_delivery(
            sh_bad, envelope_id="env-sh-1", telemetry_store=tel_sh, session_id="sess-sh-1",
            capsule_ids=["CAP-SEC-SUBPROCESS-ARGV", "CAP-FIN-ERC4626"], pitfall_ids=["LT-005"],
            confirm_included=True,
        )
        self.assertEqual(r_sh_vd["status"], "DELIVERY_FAILED_ATTRIBUTED")
        self.assertEqual(set(r_sh_vd["attributed_ids"]), {"CAP-SEC-SUBPROCESS-ARGV", "LT-005"})

        # Honest inclusion skip: without --mark-included or --confirm-included, efficacy is skipped & nothing freezes
        tel_uninc = self.tmp / "vd_uninc_tel.json"
        for idx in (1, 2):
            r_u = kintsugi_sandbox_mod.verify_delivery(
                sh_bad, envelope_id=f"env-uninc-{idx}", telemetry_store=tel_uninc, session_id=f"s-uninc-{idx}",
                capsule_ids=["CAP-SEC-SUBPROCESS-ARGV"], pitfall_ids=["LT-005"],
            )
            self.assertEqual(r_u["status"], "DELIVERY_FAILED_ATTRIBUTED")
            self.assertEqual(r_u.get("telemetry_note"), "NOT_MARKED_INCLUDED_EFFICACY_SKIPPED")
            self.assertIsNone(r_u["telemetry"]["included"])
        self.assertEqual(telemetry_mod.build_telemetry_report(tel_uninc)["frozen_ids"], [])

        # CLI brief --mark-included carries honest inclusion into verify-delivery without --confirm-included
        st_inc = self.tmp / "state_mark_inc"
        p_b_inc = _run_sandbox_cli("brief", str(sh_bad), "--lang", "python", "--state-dir", str(st_inc), "--mark-included")
        self.assertEqual(p_b_inc.returncode, 0, p_b_inc.stdout)
        j_b_inc = json.loads(p_b_inc.stdout)
        self.assertTrue(j_b_inc["marked_included"])
        p_vd_inc = _run_sandbox_cli("verify-delivery", str(sh_bad), "--envelope-id", j_b_inc["envelope_id"], "--state-dir", str(st_inc))
        j_vd_inc = json.loads(p_vd_inc.stdout)
        self.assertNotIn("telemetry_note", j_vd_inc)

        # (c) compact: --max-lines -5 rejected (INVALID_MAX_LINES, exit 1) & host path redacted in "file"
        p_neg = _run_sandbox_cli("compact", str(sql_bad), "--max-lines", "-5")
        self.assertEqual(p_neg.returncode, 1)
        self.assertIn("INVALID_MAX_LINES", p_neg.stdout)

        host_dir = self.tmp / ("ho" + "me") / "alice"
        host_dir.mkdir(parents=True)
        host_note = host_dir / "note.txt"
        host_note.write_text("Clean note line\n", encoding="utf-8")
        p_hp = _run_sandbox_cli("compact", str(host_note), "--max-lines", "10")
        self.assertEqual(p_hp.returncode, 0, p_hp.stdout)
        j_hp = json.loads(p_hp.stdout)
        self.assertIn("[REDACTED_DLP]", j_hp["file"])
        self.assertNotIn("/" + "ho" + "me/alice/", j_hp["file"])

        # (d) ledger-check: 28-digit exact Decimal & quant="1E+2" formats "200" (not "2E+2")
        r_big_dec = kintsugi_sandbox_mod.verify_decimal_ledger(
            ["12345678901234567890123456.78", "0.22"],
            "12345678901234567890123457.00",
            quant="0.01",
        )
        self.assertEqual((r_big_dec["ok"], r_big_dec["status"], r_big_dec["computed_total"]), (True, "MATCH_EXACT", "12345678901234567890123457.00"))

        r_e2 = kintsugi_sandbox_mod.verify_decimal_ledger(["150"], "200", quant="1E+2")
        self.assertEqual((r_e2["ok"], r_e2["converted_lines"], r_e2["computed_total"]), (True, ["200"], "200"))

    def test_11_round3_two_process_ipc_node_linux_and_bootstrap_dir_fd(self) -> None:
        from unittest import mock as _mock
        # (a) 2-Process OS-level IPC isolation: distinct PID, 0 leaked FDs 3..64, __main__ mutation & os._exit(0) blocked
        b_ok = self.tmp / "ipc_broken.py"
        f_ok = self.tmp / "ipc_fixed.py"
        t_pid = self.tmp / "ipc_oracle_pid.py"
        b_ok.write_text("import os\ndef probe():\n    return (-1, [1])\n", encoding="utf-8")
        f_ok.write_text(
            "import os\ndef probe():\n    open_fds = []\n    for fd in range(3, 64):\n"
            "        try:\n            os.fstat(fd)\n            open_fds.append(fd)\n"
            "        except OSError:\n            continue\n    return (os.getpid(), open_fds)\n",
            encoding="utf-8",
        )
        t_pid.write_text(
            "import os, candidate\npid, fds = candidate.probe()\n"
            "assert pid != os.getpid(), 'candidate must run in separate OS process'\n"
            "assert fds == [], f'leaked fds in worker: {fds}'\n",
            encoding="utf-8",
        )
        r_pid = truth_gate_mod.run_custom_truth_gate(b_ok, f_ok, t_pid, runner="python")
        self.assertTrue(r_pid["ok"], r_pid)
        self.assertEqual(r_pid["verdict"], "PROMOTE_ELIGIBLE")

        # (b) Candidate scanning range(3, 64) to forge KINTSUGI_VERDICT_FD fails closed!
        f_forge = self.tmp / "ipc_forge_fd.py"
        t_val = self.tmp / "ipc_oracle_val.py"
        f_forge.write_text(
            "import json, os\n"
            "def calc(x):\n"
            "    payload = (json.dumps({'property_id':'ASSERTION','verdict':'PROPERTY_PASSED','assertions_run':1}) + '\\n').encode()\n"
            "    for fd in range(3, 64):\n"
            "        try:\n            os.write(fd, payload)\n        except OSError:\n            continue\n"
            "    return 0\n",
            encoding="utf-8",
        )
        b_val = self.tmp / "ipc_broken_val.py"
        b_val.write_text("def calc(x):\n    return 0\n", encoding="utf-8")
        t_val.write_text("import candidate\nassert candidate.calc(4) == 8\n", encoding="utf-8")
        r_forge = truth_gate_mod.run_custom_truth_gate(b_val, f_forge, t_val, runner="python")
        self.assertFalse(r_forge["ok"], r_forge)
        self.assertEqual(r_forge["fixed_verdict"], "EXPECTED_PROPERTY_FAIL")

        # (c) Candidate mutating sys.modules['__main__'] or calling os._exit(0) fails closed!
        f_main = self.tmp / "ipc_main_tamper.py"
        f_main.write_text(
            "import sys\ndef calc(x):\n    sys.modules['__main__'].__dict__.clear()\n    return 8\n",
            encoding="utf-8",
        )
        r_main = truth_gate_mod.run_custom_truth_gate(b_val, f_main, t_val, runner="python")
        self.assertFalse(r_main["ok"], r_main)
        self.assertEqual(r_main["fixed_verdict"], "INFRA_ERROR")

        f_osexit = self.tmp / "ipc_osexit.py"
        f_osexit.write_text("import os\ndef calc(x):\n    os._exit(0)\n", encoding="utf-8")
        r_osexit = truth_gate_mod.run_custom_truth_gate(b_val, f_osexit, t_val, runner="python")
        self.assertFalse(r_osexit["ok"], r_osexit)
        self.assertEqual(r_osexit["fixed_verdict"], "INFRA_ERROR")

        # (d) Class handle + Decimal/bytes/tuple/set + ValueError propagation over 2-process IPC works cleanly!
        b_cls = self.tmp / "ipc_cls_b.py"
        f_cls = self.tmp / "ipc_cls_f.py"
        t_cls = self.tmp / "ipc_cls_t.py"
        b_cls.write_text(
            "from decimal import Decimal\nclass Vault:\n    def __init__(self, bal):\n        self.bal = Decimal(bal)\n"
            "    def withdraw(self, amt):\n        self.bal -= Decimal(amt)\n        return (self.bal, b'ok', {'a'})\n",
            encoding="utf-8",
        )
        f_cls.write_text(
            "from decimal import Decimal\nclass Vault:\n    def __init__(self, bal):\n        self.bal = Decimal(bal)\n"
            "    def withdraw(self, amt):\n        a = Decimal(amt)\n"
            "        if a > self.bal:\n            raise ValueError('insufficient')\n"
            "        self.bal -= a\n        return (self.bal, b'ok', {'a'})\n",
            encoding="utf-8",
        )
        t_cls.write_text(
            "from decimal import Decimal\nimport candidate\nv = candidate.Vault(Decimal('10.00'))\n"
            "bal, tag, tags = v.withdraw(Decimal('2.50'))\nassert bal == Decimal('7.50') and tag == b'ok' and tags == {'a'}\n"
            "raised = False\ntry:\n    v.withdraw(Decimal('99.00'))\nexcept ValueError:\n    raised = True\nassert raised\n",
            encoding="utf-8",
        )
        r_cls = truth_gate_mod.run_custom_truth_gate(b_cls, f_cls, t_cls, runner="python")
        self.assertTrue(r_cls["ok"], r_cls)

        # (e) Linux Node RLIMIT_AS fix: verify Node runner passes --max-old-space-size=256 and apply_rlimit_as=False
        captured: List[Tuple[List[str], bool]] = []
        orig_run = truth_gate_mod._run_bounded_subprocess

        def _spy_run(cmd, **kwargs):
            captured.append((list(cmd), bool(kwargs.get("apply_rlimit_as", True))))
            return orig_run(cmd, **kwargs)

        if shutil.which("node"):
            b_js = self.tmp / "node_b.mjs"
            f_js = self.tmp / "node_f.mjs"
            t_js = self.tmp / "node_t.mjs"
            b_js.write_text("export function dbl(n) { return n; }\n", encoding="utf-8")
            f_js.write_text("export function dbl(n) { return n * 2; }\n", encoding="utf-8")
            t_js.write_text("import assert from 'node:assert/strict';\nimport { dbl } from './candidate.mjs';\nassert.equal(dbl(3), 6);\n", encoding="utf-8")
            with _mock.patch.object(truth_gate_mod, "_run_bounded_subprocess", side_effect=_spy_run):
                r_js = truth_gate_mod.run_custom_truth_gate(b_js, f_js, t_js, runner="node")
            self.assertTrue(r_js["ok"], r_js)
            self.assertTrue(captured and all("--max-old-space-size=256" in c and (not rlim) for c, rlim in captured), captured)

        # (f) Bootstrap POSIX dir_fd swap uses int src_dir_fd/dst_dir_fd on POSIX
        if getattr(bootstrap_mod, "_SUPPORTS_DIR_FD", False):
            tar_p = self.tmp / "dirfd_good.tar.gz"
            m_sha = _build_synthetic_archive(tar_p, fmt="tar.gz")
            dst_dir = self.tmp / "dirfd_install"
            renames: List[Tuple[Any, Any]] = []
            orig_rename = os.rename

            def _spy_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
                renames.append((src_dir_fd, dst_dir_fd))
                return orig_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

            with _mock.patch.object(bootstrap_mod.os, "rename", side_effect=_spy_rename):
                r_ins = bootstrap_mod.install_or_update(
                    ref="main", dest=dst_dir, source_archive=tar_p,
                    expected_manifest_sha256=m_sha, require_pin=True, run_post_stage_smoke=False,
                )
            self.assertTrue(r_ins["ok"], r_ins)
            self.assertTrue(renames and all(isinstance(s, int) and isinstance(d, int) for s, d in renames), renames)

            # (g) Round-4 FD-pinned verify_manifest_tree: dir_fd-only os.open, 0 FD leaks, and ancestor-symlink swap proof
            def _snapshot_open_fds() -> List[int]:
                fds: List[int] = []
                for fd_num in range(3, 256):
                    try:
                        os.fstat(fd_num)
                        fds.append(fd_num)
                    except OSError:
                        continue
                return fds

            open_calls: List[Tuple[str, int, Any]] = []
            orig_open = os.open

            def _spy_open(path, flags, mode=0o777, *, dir_fd=None):
                open_calls.append((str(path), int(flags), dir_fd))
                return orig_open(path, flags, mode, dir_fd=dir_fd)

            fds_before = _snapshot_open_fds()
            with _mock.patch.object(bootstrap_mod.os, "open", side_effect=_spy_open):
                vm_res = bootstrap_mod.verify_manifest_tree(
                    dst_dir, src_root=dst_dir, expected_manifest_sha256=m_sha, reject_extra_files=True,
                )
            fds_after = _snapshot_open_fds()
            self.assertTrue(vm_res["ok"], vm_res)
            self.assertEqual(fds_after, fds_before, f"FD leak in verify_manifest_tree: before={fds_before} after={fds_after}")

            # Only root anchor "/" (or ".") may omit dir_fd; manifest.json and every verified file MUST use int dir_fd + O_NOFOLLOW
            non_root_path_opens = [(p, d) for p, _f, d in open_calls if d is None and p not in ("/", ".")]
            self.assertEqual(non_root_path_opens, [], f"Unexpected path-based os.open: {non_root_path_opens}")

            o_dir = getattr(os, "O_DIRECTORY", 0)
            o_nofollow = getattr(os, "O_NOFOLLOW", 0)
            manifest_opens = [(p, f, d) for p, f, d in open_calls if p == "manifest.json"]
            self.assertEqual(len(manifest_opens), 1, manifest_opens)
            self.assertIsInstance(manifest_opens[0][2], int)
            self.assertTrue(bool(manifest_opens[0][1] & o_nofollow), manifest_opens)

            file_opens = [(p, f, d) for p, f, d in open_calls if not (f & o_dir)]
            self.assertGreaterEqual(len(file_opens), int(vm_res["files_verified"]) + 1)
            self.assertTrue(
                all(isinstance(d, int) and "/" not in p and not os.path.isabs(p) and bool(f & o_nofollow) for p, f, d in file_opens),
                [x for x in file_opens if not (isinstance(x[2], int) and "/" not in x[0] and bool(x[1] & o_nofollow))][:8],
            )

            # Also verify passing pinned bundle_fd directly (as _atomic_swap_and_verify does) performs ZERO dir_fd=None opens!
            pinned_calls: List[Tuple[str, int, Any]] = []

            def _spy_pinned_open(path, flags, mode=0o777, *, dir_fd=None):
                pinned_calls.append((str(path), int(flags), dir_fd))
                return orig_open(path, flags, mode, dir_fd=dir_fd)

            dir_open_flags = os.O_RDONLY | o_dir | o_nofollow | getattr(os, "O_CLOEXEC", 0)
            direct_fd = orig_open(str(dst_dir), dir_open_flags)
            try:
                fds_pinned_before = _snapshot_open_fds()
                with _mock.patch.object(bootstrap_mod.os, "open", side_effect=_spy_pinned_open):
                    vm_pinned = bootstrap_mod.verify_manifest_tree(
                        dst_dir, src_root=dst_dir, expected_manifest_sha256=m_sha,
                        reject_extra_files=True, bundle_fd=direct_fd,
                    )
                fds_pinned_after = _snapshot_open_fds()
            finally:
                os.close(direct_fd)
            self.assertTrue(vm_pinned["ok"], vm_pinned)
            self.assertEqual(fds_pinned_after, fds_pinned_before)
            self.assertTrue(pinned_calls and all(isinstance(d, int) for _p, _f, d in pinned_calls), pinned_calls[:8])

            # Ancestor-symlink swap race proof: replace `data/` with symlink to external dir holding valid files -> fail-closed!
            sym_bundle = self.tmp / "dirfd_sym_swap_bundle"
            shutil.copytree(dst_dir, sym_bundle)
            ext_data = self.tmp / "external_valid_data"
            shutil.move(str(sym_bundle / "data"), str(ext_data))
            (sym_bundle / "data").symlink_to(ext_data)

            fds_sym_before = _snapshot_open_fds()
            with self.assertRaises(PermissionError) as ctx_sym:
                bootstrap_mod.verify_manifest_tree(
                    sym_bundle, src_root=sym_bundle, expected_manifest_sha256=m_sha, reject_extra_files=True,
                )
            fds_sym_after = _snapshot_open_fds()
            self.assertEqual(fds_sym_after, fds_sym_before, "FD leak on symlink rejection path")
            self.assertIn("REFUSING_SYMLINK", str(ctx_sym.exception))
            self.assertIsInstance(ctx_sym.exception.__cause__, OSError)
            self.assertIn(
                ctx_sym.exception.__cause__.errno,
                (errno.ELOOP, getattr(errno, "EMLINK", errno.ELOOP), errno.ENOTDIR),
            )

    def test_12_v311_scanner_coverage_fifo_entry_cap_exp_ast_and_dynamic_shell(self) -> None:
        # (a) HIGH #8: Clean README.md + uninspected .zip/.xlsx -> INCOMPLETE_SCAN by default; passes ONLY with allow_binary
        mix_d = self.tmp / "mixed_readme_bin"
        mix_d.mkdir()
        (mix_d / "README.md").write_text("# Clean Documentation\n", encoding="utf-8")
        (mix_d / "report.xlsx").write_bytes(b"PK\x03\x04\x00\x00xlsx")
        (mix_d / "bundle.zip").write_bytes(b"PK\x03\x04\x00\x00zip")

        r_mix_def = scanner_mod.scan_target(mix_d)
        self.assertEqual((r_mix_def["ok"], r_mix_def["status"]), (False, "INCOMPLETE_SCAN"))
        self.assertEqual(len(r_mix_def["unsupported_binary_files"]), 2)

        r_mix_allow = scanner_mod.scan_target(mix_d, allow_binary=True)
        self.assertEqual((r_mix_allow["ok"], r_mix_allow["status"], r_mix_allow["inspected_files"]), (True, "PASS_100", 1))

        p_cli_def = _run_sandbox_cli("scan", str(mix_d))
        self.assertEqual(p_cli_def.returncode, 1)
        self.assertEqual(json.loads(p_cli_def.stdout)["status"], "INCOMPLETE_SCAN")
        p_cli_allow = _run_sandbox_cli("scan", str(mix_d), "--allow-binary")
        self.assertEqual(p_cli_allow.returncode, 0, p_cli_allow.stdout)
        self.assertEqual(json.loads(p_cli_allow.stdout)["status"], "PASS_100")

        # (b) HIGH #8: FIFO special inode -> INCOMPLETE_SCAN with special_inodes non-empty
        if hasattr(os, "mkfifo"):
            fifo_d = self.tmp / "fifo_scan_dir"
            fifo_d.mkdir()
            (fifo_d / "clean.py").write_text("x = 1\n", encoding="utf-8")
            os.mkfifo(str(fifo_d / "stream.fifo"))
            r_fifo = scanner_mod.scan_target(fifo_d)
            self.assertEqual((r_fifo["ok"], r_fifo["status"]), (False, "INCOMPLETE_SCAN"))
            self.assertIn("stream.fifo", r_fifo["special_inodes"])

        # (c) HIGH #9: iter_safe_files bounds scanning via entry cap without reading/statting all entries in a large dir
        big_d = self.tmp / "large_dir_cap"
        big_d.mkdir()
        for idx in range(40):
            (big_d / f"f_{idx:03d}.py").write_text("x = 1\n", encoding="utf-8")
        walk_cap = security_io_mod.iter_safe_files(big_d, max_files=5)
        self.assertEqual(len(walk_cap["files"]), 5)
        self.assertTrue(walk_cap["truncated"])

        # Streaming cap proof via mocked 5000-entry os.scandir: stops well before yielding all 5000 entries
        yielded = [0]
        fake_reg_st = os.lstat(str(big_d / "f_000.py"))

        class _FakeEntry:
            def __init__(self, idx: int) -> None:
                self.name = f"m_{idx:04d}.py"
                self.path = str(big_d / self.name)

            def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
                return fake_reg_st

        class _FakeScandir:
            def __enter__(self) -> "_FakeScandir":
                return self

            def __exit__(self, *_a: Any) -> bool:
                return False

            def __iter__(self) -> Any:
                for i in range(5000):
                    yielded[0] += 1
                    yield _FakeEntry(i)

        with mock.patch.object(security_io_mod.os, "scandir", return_value=_FakeScandir()):
            walk_stream = security_io_mod.iter_safe_files(big_d, max_files=5)
        self.assertEqual(len(walk_stream["files"]), 5)
        self.assertTrue(walk_stream["truncated"])
        self.assertLess(yielded[0], 50)

        # (d) HIGH #9: Exponential AST string concat completes fast (< 2.0s) without OOM/hang
        exp_src = 's = "' + ("A" * 100) + '"\n' + ("s = s + s\n" * 30) + ("s += s\n" * 30)
        t0 = time.monotonic()
        ast_hits = scanner_mod._scan_python_ast_extra(exp_src, "exp_concat.py")
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertEqual(ast_hits, [])

        exp_file = self.tmp / "exp_concat.py"
        exp_file.write_text(exp_src, encoding="utf-8")
        t1 = time.monotonic()
        r_exp = scanner_mod.scan_target(exp_file)
        self.assertLess(time.monotonic() - t1, 2.0)
        self.assertEqual((r_exp["ok"], r_exp["status"]), (True, "PASS_100"))

        # (e) MEDIUM #6: Dynamic subprocess shell=flag -> SEC-SHELL-DYNAMIC (HIGH, blocking); proven shell=False clean
        dyn_direct = self.tmp / "dyn_shell_direct.py"
        dyn_direct.write_text("import subprocess\ndef run(cmd, flag):\n    return subprocess.run(cmd, sh" + "ell=flag)\n", encoding="utf-8")
        r_dd = scanner_mod.scan_target(dyn_direct)
        self.assertFalse(r_dd["ok"])
        self.assertTrue(
            any(f["rule"] == "SEC-SHELL-DYNAMIC" and f["severity"] == "HIGH" for f in r_dd["findings"]),
            r_dd["findings"],
        )

        dyn_kw = self.tmp / "dyn_shell_kwargs.py"
        dyn_kw.write_text('import subprocess\ndef run(cmd, flag):\n    opts = {"sh' + 'ell": flag}\n    return subprocess.run(cmd, **opts)\n', encoding="utf-8")
        r_dkw = scanner_mod.scan_target(dyn_kw)
        self.assertFalse(r_dkw["ok"])
        self.assertTrue(
            any(f["rule"] == "SEC-SHELL-DYNAMIC" and f["severity"] == "HIGH" for f in r_dkw["findings"]),
            r_dkw["findings"],
        )

        safe_sh = self.tmp / "safe_shell_false.py"
        safe_sh.write_text("import subprocess\ndef run():\n    safe = False\n    subprocess.run(['echo', 'ok'], sh" + "ell=False)\n    return subprocess.run(['echo', 'ok'], sh" + "ell=safe)\n", encoding="utf-8")
        r_ssh = scanner_mod.scan_target(safe_sh)
        self.assertEqual((r_ssh["ok"], r_ssh["status"], r_ssh["total_findings"]), (True, "PASS_100", 0))

    def test_13_v311_dlp_pem_kv_path_tx_guard_and_exact_rational_ledger(self) -> None:
        # (a) HIGH #10: Full multiline PEM AND truncated PEM redacted completely in dlp_redact_output, compact, and truth_gate
        pem_hdr = "-----BEG" + "IN RSA PRIVATE KEY-----"
        pem_ftr = "-----E" + "ND RSA PRIVATE KEY-----"
        pem_body_tok = "SYNTHKEYBODYMARKER9876543210"
        full_pem = f"{pem_hdr}\nLINE1_{pem_body_tok}\nLINE2_MORE_SECRET_DATA\n{pem_ftr}"
        trunc_pem = f"{pem_hdr}\nTRUNC_{pem_body_tok}\nNO_END_MARKER_BODY"

        for label, blob in (("full", full_pem), ("truncated", trunc_pem)):
            red = security_io_mod.dlp_redact_output(f"prefix\n{blob}\nsuffix")
            self.assertIn("[REDACTED_DLP]", red, label)
            self.assertNotIn(pem_body_tok, red, label)
            self.assertNotIn(pem_hdr, red, label)

        # CLI compact MUST redact multiline & truncated PEM BEFORE stripping `---` header lines
        for label, blob in (("full", full_pem), ("truncated", trunc_pem)):
            note_p = self.tmp / f"pem_note_{label}.txt"
            note_p.write_text(f"Header line\n{blob}\nFooter line\n", encoding="utf-8")
            p_cmp = _run_sandbox_cli("compact", str(note_p), "--max-lines", "50")
            self.assertEqual(p_cmp.returncode, 0, p_cmp.stdout + p_cmp.stderr)
            j_cmp = json.loads(p_cmp.stdout)
            self.assertIn("[REDACTED_DLP]", j_cmp["content"], label)
            self.assertNotIn(pem_body_tok, p_cmp.stdout, label)

        # truth_gate MUST redact >500-char PEM BEFORE [-400:] tail slice
        long_pem_lines = "\\n".join([f"B{i:03d}_" + ("Q" * 32) for i in range(18)])
        b_pem = self.tmp / "b_pem_tg.py"
        f_pem = self.tmp / "f_pem_tg.py"
        t_pem = self.tmp / "t_pem_tg.py"
        b_pem.write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")
        f_pem.write_text(
            "import sys\n"
            "def ok() -> int:\n"
            f"    blob = ('-----BEG' + 'IN RSA PRIVATE KEY-----\\n{long_pem_lines}\\nTAIL_{pem_body_tok}\\n-----E' + 'ND RSA PRIVATE KEY-----')\n"
            "    print(blob)\n"
            "    sys.stderr.write(blob + '\\n')\n"
            "    return 2\n",
            encoding="utf-8",
        )
        t_pem.write_text("import candidate\nassert candidate.ok() == 2\n", encoding="utf-8")
        r_tg_pem = truth_gate_mod.run_custom_truth_gate(b_pem, f_pem, t_pem, runner="python")
        self.assertTrue(r_tg_pem["ok"], r_tg_pem)
        for fld in ("fixed_stdout", "fixed_stderr"):
            self.assertIn("[REDACTED_DLP]", r_tg_pem[fld], fld)
            self.assertNotIn(pem_body_tok, r_tg_pem[fld], fld)

        # (b) HIGH #10: JSON dict with synthetic sensitive key/value pair caught by dlp_scan_object & scan_target without echoing value
        synth_priv = "dead" + "beef" + "12345678"
        kv_hits = security_io_mod.dlp_scan_object({"private_key": synth_priv})
        self.assertIn("DLP-SECRET-KV-PAIR", {h["rule"] for h in kv_hits})
        self.assertNotIn(synth_priv, json.dumps(kv_hits))
        self.assertEqual(security_io_mod.dlp_scan_object({"private_key": "[REDACTED_DLP]"}), [])

        synth_api_val = "my_super_secret_" + "key_value_999"
        json_kv_dir = self.tmp / "json_kv_scan" / ("ho" + "me") / "alice" / "cfg"
        json_kv_dir.mkdir(parents=True)
        json_kv_file = json_kv_dir / "secrets.json"
        json_kv_file.write_text(json.dumps({"api_key": synth_api_val}) + "\n", encoding="utf-8")
        r_jkv = scanner_mod.scan_target(json_kv_file)
        self.assertFalse(r_jkv["ok"], r_jkv)
        self.assertEqual(r_jkv["status"], "BLOCKED_FINDINGS")
        self.assertTrue(
            any(f["rule"] == "DLP-SECRET-KV-PAIR" and f["severity"] == "CRITICAL" for f in r_jkv["findings"]),
            r_jkv["findings"],
        )
        self.assertNotIn(synth_api_val, json.dumps(r_jkv))
        for f_kv in r_jkv["findings"]:
            self.assertNotIn("/" + "ho" + "me/alice/", f_kv["file"])

        # (c) HIGH #10: scanner_sandbox finding "file" field DLP-redacted on synthetic /home/alice/... path
        scan_root = self.tmp / "dlp_path_root"
        alice_dir = scan_root / "nest" / ("ho" + "me") / "alice" / "proj"
        alice_dir.mkdir(parents=True)
        bad_alice = alice_dir / "bad_cmd.py"
        bad_alice.write_text("import subprocess\nsubprocess.run('id', sh" + "ell=True)\n", encoding="utf-8")
        r_path = scanner_mod.scan_target(scan_root)
        self.assertFalse(r_path["ok"])
        self.assertGreaterEqual(len(r_path["findings"]), 1)
        for finding in r_path["findings"]:
            self.assertIn("[REDACTED_DLP]", finding["file"])
            self.assertNotIn("/" + "ho" + "me/alice/", finding["file"])

        # (d) HIGH #11: tx-guard structured outbound value / transfers_funds / action checks
        base_ok = {
            "status": "open", "deposit_required": False, "entry_fee": 0, "transfers_funds": False,
            "signing": {"action": "personal_sign", "value": 0},
        }
        for label, extra in (
            ("tx_val_int", {"transaction": {"value": 1}}),
            ("tx_val_hex", {"transaction": {"value": "0x1"}}),
            ("transfers_funds", {"transfers_funds": True}),
            ("send_value", {"send_value": 1}),
            ("outbound_transfer", {"outbound_transfer": True}),
            ("top_action", {"action": "eth_sendTransaction"}),
            ("signing_action", {"signing": {"action": "erc20_transfer"}}),
            ("swap_action", {"signing": {"action": "swap"}}),
            ("bridge_action", {"signing": {"action": "bridge"}}),
            ("stake_action", {"signing": {"action": "stake"}}),
            ("deposit_action", {"signing": {"action": "deposit"}}),
            ("loan_action", {"signing": {"action": "loan"}}),
            ("plural_transactions", {"transactions": [{"value": 1}]}),
            ("plural_txs", {"txs": [{"value": 1}]}),
            ("plural_calls", {"calls": [{"value": 1}]}),
            ("plural_operations", {"operations": [{"value": 1}]}),
            ("plural_instructions", {"instructions": [{"value": 1}]}),
            ("plural_messages", {"messages": [{"value": 1}]}),
        ):
            r_blk = kintsugi_sandbox_mod.evaluate_tx_guard({**base_ok, **extra})
            self.assertEqual((r_blk["ok"], r_blk["verdict"]), (False, "BLOCKED"), label)
            self.assertTrue(any("BLOCK_OUTBOUND_TRANSFER" in b for b in r_blk["blocks"]), f"{label}: {r_blk['blocks']}")

        r_plural_min = kintsugi_sandbox_mod.evaluate_tx_guard({"action": "personal_sign", "transactions": [{"value": 1}]})
        self.assertEqual((r_plural_min["ok"], r_plural_min["verdict"]), (False, "BLOCKED"))
        self.assertTrue(any("BLOCK_OUTBOUND_TRANSFER" in b for b in r_plural_min["blocks"]), r_plural_min["blocks"])

        r_unk = kintsugi_sandbox_mod.evaluate_tx_guard({**base_ok, "signing": {"action": "mystery_sign"}})
        self.assertEqual((r_unk["ok"], r_unk["verdict"]), (False, "NEEDS_OWNER_DECISION"))

        for safe_act in ("personal_sign", "eip191", "ed25519_auth", "siwe", "read_only", "none"):
            r_safe_sign = kintsugi_sandbox_mod.evaluate_tx_guard(
                {**base_ok, "signing": {"action": safe_act, "value": "0x0"}}
            )
            self.assertEqual((r_safe_sign["ok"], r_safe_sign["verdict"]), (True, "PASS_READONLY_0_OUTBOUND"), safe_act)

        p_tx_cli = _run_sandbox_cli("tx-guard", "--payload", json.dumps(base_ok))
        self.assertEqual(p_tx_cli.returncode, 0, p_tx_cli.stdout)
        self.assertEqual(json.loads(p_tx_cli.stdout)["verdict"], "PASS_READONLY_0_OUTBOUND")

        # (e) HIGH #12: exact rational ledger-check (50-digit repro + exact half on tick 2)
        amt_50 = "0." + ("9" * 50)
        rate_50 = "1." + ("0" * 49) + "1"
        r_lc_ok = kintsugi_sandbox_mod.verify_decimal_ledger([amt_50], "0", fx_rate=rate_50, quant="2")
        self.assertEqual((r_lc_ok["ok"], r_lc_ok["status"], r_lc_ok["computed_total"]), (True, "MATCH_EXACT", "0"))
        r_lc_bad = kintsugi_sandbox_mod.verify_decimal_ledger([amt_50], "2", fx_rate=rate_50, quant="2")
        self.assertEqual((r_lc_bad["ok"], r_lc_bad["status"], r_lc_bad["computed_total"]), (False, "MISMATCH", "0"))

        p_lc_bad = _run_sandbox_cli("ledger-check", "--lines", json.dumps([amt_50]), "--total", "2", "--fx", rate_50, "--quant", "2")
        self.assertEqual(p_lc_bad.returncode, 1)
        self.assertEqual(json.loads(p_lc_bad.stdout)["status"], "MISMATCH")
        p_lc_ok = _run_sandbox_cli("ledger-check", "--lines", json.dumps([amt_50]), "--total", "0", "--fx", rate_50, "--quant", "2")
        self.assertEqual(p_lc_ok.returncode, 0, p_lc_ok.stdout)
        self.assertEqual(json.loads(p_lc_ok.stdout)["status"], "MATCH_EXACT")

        r_half = kintsugi_sandbox_mod.verify_decimal_ledger(["1"], "2", quant="2")
        self.assertEqual((r_half["ok"], r_half["status"], r_half["computed_total"]), (True, "MATCH_EXACT", "2"))

    def test_14_v311_content_digest_attribution_empty_telemetry_and_brief_budget(self) -> None:
        # (a) HIGH #13: verify-delivery hashes actual scanned file bytes across dirs with identical names/status
        d1, d2 = self.tmp / "deliv_bytes_a", self.tmp / "deliv_bytes_b"
        d1.mkdir()
        d2.mkdir()
        (d1 / "app.py").write_text("def compute() -> int:\n    return 101\n", encoding="utf-8")
        (d2 / "app.py").write_text("def compute() -> int:\n    return 202\n", encoding="utf-8")
        tel_dig = self.tmp / "tel_digest.json"
        r_d1 = kintsugi_sandbox_mod.verify_delivery(d1, envelope_id="env-dig-1", telemetry_store=tel_dig, session_id="s-dig-1", confirm_included=True)
        r_d2 = kintsugi_sandbox_mod.verify_delivery(d2, envelope_id="env-dig-2", telemetry_store=tel_dig, session_id="s-dig-2", confirm_included=True)
        self.assertTrue(r_d1["ok"] and r_d2["ok"])
        self.assertEqual(len(r_d1["patch_digest"]), 64)
        self.assertEqual(len(r_d2["patch_digest"]), 64)
        self.assertNotEqual(r_d1["patch_digest"], r_d2["patch_digest"])

        # (b) HIGH #14: Rule->scar mapping negative controls (YAML does NOT freeze LT-006; SQL does NOT freeze FX capsule)
        yaml_bad = self.tmp / "bad_yaml_attr.py"
        yaml_bad.write_text("import yaml\ndef parse(u):\n    return yaml." + "lo" + "ad(u)\n", encoding="utf-8")
        tel_yaml = self.tmp / "tel_yaml_neg.json"
        for idx in (1, 2):
            r_y = kintsugi_sandbox_mod.verify_delivery(
                yaml_bad, envelope_id=f"env-yaml-{idx}", telemetry_store=tel_yaml, session_id=f"s-yaml-{idx}",
                pitfall_ids=["LT-006", "LT-021"], confirm_included=True,
            )
            self.assertNotIn("LT-006", r_y["attributed_ids"])
        self.assertNotIn("LT-006", telemetry_mod.build_telemetry_report(tel_yaml)["frozen_ids"])

        sql_bad = self.tmp / "bad_sql_attr.py"
        sql_bad.write_text('def fetch(cur, u):\n    return cur.execute("SELECT * FROM orders WHERE id=" + u)\n', encoding="utf-8")
        tel_sql = self.tmp / "tel_sql_neg.json"
        for idx in (1, 2):
            r_s = kintsugi_sandbox_mod.verify_delivery(
                sql_bad, envelope_id=f"env-sqlneg-{idx}", telemetry_store=tel_sql, session_id=f"s-sqlneg-{idx}",
                capsule_ids=["CAP-ERP-MYSQL-DECIMAL-FX"], pitfall_ids=["LT-003"], confirm_included=True,
            )
            self.assertNotIn("CAP-ERP-MYSQL-DECIMAL-FX", r_s["attributed_ids"])
            self.assertIn("LT-003", r_s["attributed_ids"])
        frozen_sql = telemetry_mod.build_telemetry_report(tel_sql)["frozen_ids"]
        self.assertNotIn("CAP-ERP-MYSQL-DECIMAL-FX", frozen_sql)
        self.assertIn("LT-003", frozen_sql)

        # (c) HIGH #15: 0-byte telemetry store raises CORRUPT_EMPTY_TELEMETRY_STORE across all 4 entry points
        empty_tel = self.tmp / "zero_byte_tel.json"
        empty_tel.write_bytes(b"")
        evo_valid = self.tmp / "valid_evo_for_empty_tel.json"
        evo_valid.write_text('{"schema":"KintsugiCloudSandboxEvolution/1","version":"3.1.1","scars":[]}\n', encoding="utf-8")

        with self.assertRaises(ValueError) as ctx_t1:
            telemetry_mod.load_frozen_ids_strict(empty_tel)
        self.assertIn("CORRUPT_EMPTY_TELEMETRY_STORE", str(ctx_t1.exception))

        with self.assertRaises(ValueError) as ctx_t2:
            evolution_mod.load_active_learned_scars(evo_valid, telemetry_store=empty_tel)
        self.assertIn("CORRUPT_EMPTY_TELEMETRY_STORE", str(ctx_t2.exception))

        with self.assertRaises(ValueError) as ctx_t3:
            kintsugi_sandbox_mod.build_brief(code_override="x = 1\n", lang_hint="python", telemetry_store=empty_tel)
        self.assertIn("CORRUPT_EMPTY_TELEMETRY_STORE", str(ctx_t3.exception))

        with self.assertRaises(ValueError) as ctx_t4:
            kintsugi_sandbox_mod.verify_delivery(d1 / "app.py", envelope_id="env-z0", telemetry_store=empty_tel, session_id="s-z0")
        self.assertIn("CORRUPT_EMPTY_TELEMETRY_STORE", str(ctx_t4.exception))

        # (d) MEDIUM #3: pack_brief_within_budget never slices a rule mid-text while keeping its ID,
        #     and build_brief JSON drops duplicate per-item compact/invariant strings.
        sample_cap = {
            "id": "CAP-TEST-BUDGET", "domain": "finance", "when_clause": "Calculating vault share ratio",
            "invariant": "Always round down on deposit and round up on redeem to protect vault liquidity.",
            "pos_ast": "shares = (assets * supply) // total_assets",
        }
        sample_pit = {
            "id": "LT-TEST-BUDGET", "slug": "budget_pit", "category": "logic",
            "compact": "@PITFALL[LT-TEST-BUDGET|budget_pit|logic] AVOID: slicing rules mid-sentence -> DO: drop whole rule",
        }
        sel_c, sel_p, packed_txt, dropped_n = scanner_mod.pack_brief_within_budget(
            [(sample_cap, "test")], [(sample_pit, "test")], max_tokens=5
        )
        self.assertEqual((sel_c, sel_p, packed_txt, dropped_n), ([], [], "", 2))

        br = kintsugi_sandbox_mod.build_brief(
            task_text="Audit ERC-4626 vault share math and multi-currency FX tax ledger",
            lang_hint="python",
            auto_record_telemetry=False,
        )
        self.assertGreaterEqual(len(br["capsules"]), 1)
        self.assertGreaterEqual(len(br["pitfalls"]), 1)
        for cap_item in br["capsules"]:
            self.assertNotIn("invariant", cap_item)
            self.assertNotIn("pos_ast", cap_item)
        for pit_item in br["pitfalls"]:
            self.assertNotIn("compact", pit_item)
        self.assertTrue(bool(br["compact"]))
        self.assertEqual(br["client"], "cloud_sandbox")

        # (e) CLI brief --state-dir emits "client": "cloud_sandbox" (NOT "antigravity") in stdout & telemetry store
        brief_state = self.tmp / "brief_client_state"
        p_br_cli = _run_sandbox_cli(
            "brief", "--task", "Audit ERC-4626 vault share math", "--state-dir", str(brief_state),
        )
        self.assertEqual(p_br_cli.returncode, 0, p_br_cli.stdout + p_br_cli.stderr)
        j_br_cli = json.loads(p_br_cli.stdout)
        self.assertEqual(j_br_cli["client"], "cloud_sandbox")
        self.assertTrue(j_br_cli["telemetry_recorded"])
        tel_doc = json.loads((brief_state / "delivery_telemetry.json").read_text(encoding="utf-8"))
        self.assertEqual(tel_doc["envelopes"][j_br_cli["envelope_id"]]["client"], "cloud_sandbox")


if __name__ == "__main__":
    unittest.main(verbosity=2)
