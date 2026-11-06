"""
External & Premium Skill Pack Manager (`kintsugi install-pack` / `kintsugi list-packs`).

Allows developers using the open-source Kintsugi CLI to install standalone or
commercial Skill Packs (`.zip` or `.json`, such as Kintsugi Pro packs from Agensi.io)
into `.kintsugi/packs/`, automatically unlocking additional Golden Scars,
deterministic Auto-Fix playbooks, and `.claude/commands/` workflows.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from kintsugi.compressor import render_kml_ledger
from kintsugi.ledger import ScarLedger
from kintsugi.models import GoldenScar

KPACK_MAGIC = "KINTSUGI-KPACK-AEAD/1"
PBKDF2_ITERATIONS = 200_000


def _xor_keystream(data: bytes, enc_key: bytes, nonce: bytes) -> bytes:
    """Deterministic SHA-256 Counter-Mode (CTR) stream cipher using stdlib hmac/sha256."""
    out = bytearray(len(data))
    block_size = 32
    num_blocks = (len(data) + block_size - 1) // block_size
    for counter in range(num_blocks):
        ks_block = hmac.new(
            enc_key,
            nonce + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        start = counter * block_size
        end = min(len(data), start + block_size)
        for idx in range(start, end):
            out[idx] = data[idx] ^ ks_block[idx - start]
    return bytes(out)


def encrypt_pro_kpack_bytes(
    zip_bytes: bytes,
    license_key: str,
    *,
    pack_id: str = "kintsugi-pro-complete-bundle",
    tier: str = "pro-encrypted",
) -> bytes:
    """
    Encrypts a commercial Pro Skill Pack `.zip` archive into an authenticated `.kpack`
    envelope (`PBKDF2-HMAC-SHA256` 200k iterations + `SHA256-CTR` + `Encrypt-then-HMAC-SHA256`).
    Only customers holding the matching `license_key` can decrypt or install the `.kpack`.
    """
    clean_key = (license_key or "").strip()
    if len(clean_key) < 12:
        raise ValueError("Pro license key must be at least 12 characters long.")

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", clean_key.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=64)
    enc_key, mac_key = derived[:32], derived[32:]

    ciphertext = _xor_keystream(zip_bytes, enc_key, nonce)
    aad = f"{KPACK_MAGIC}|{pack_id}|{tier}".encode("utf-8")
    mac_tag = hmac.new(mac_key, aad + salt + nonce + ciphertext, hashlib.sha256).digest()

    envelope = {
        "kpack_format": KPACK_MAGIC,
        "pack_id": pack_id,
        "tier": tier,
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": PBKDF2_ITERATIONS,
        "cipher": "SHA256-CTR-HMAC-SHA256-ETM",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "mac_tag_hex": mac_tag.hex(),
    }
    return (json.dumps(envelope, indent=2) + "\n").encode("utf-8")


def decrypt_pro_kpack_bytes(kpack_bytes: bytes, license_key: Optional[str]) -> bytes:
    """
    Verifies the Encrypt-then-MAC tag in constant time (`hmac.compare_digest`) and decrypts
    an encrypted `.kpack` Skill Pack back into its in-memory `.zip` bytes.
    """
    clean_key = (license_key or os.environ.get("KINTSUGI_LICENSE_KEY") or "").strip()
    if not clean_key:
        raise PermissionError(
            "KINTSUGI_PRO_LICENSE_REQUIRED: This is an encrypted Kintsugi Pro Skill Pack (.kpack). "
            "Pass your customer unlock key via `--license-key <KEY>` or set `KINTSUGI_LICENSE_KEY`."
        )

    try:
        envelope = json.loads(kpack_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Malformed .kpack envelope: {exc}") from exc

    if envelope.get("kpack_format") != KPACK_MAGIC:
        raise ValueError("Unsupported .kpack format version.")

    pack_id = str(envelope.get("pack_id", ""))
    tier = str(envelope.get("tier", "pro-encrypted"))
    iterations = int(envelope.get("kdf_iterations", PBKDF2_ITERATIONS))
    salt = base64.b64decode(envelope["salt_b64"])
    nonce = base64.b64decode(envelope["nonce_b64"])
    ciphertext = base64.b64decode(envelope["ciphertext_b64"])
    expected_mac_hex = str(envelope.get("mac_tag_hex", ""))

    derived = hashlib.pbkdf2_hmac("sha256", clean_key.encode("utf-8"), salt, iterations, dklen=64)
    enc_key, mac_key = derived[:32], derived[32:]
    aad = f"{KPACK_MAGIC}|{pack_id}|{tier}".encode("utf-8")
    computed_mac_hex = hmac.new(mac_key, aad + salt + nonce + ciphertext, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed_mac_hex, expected_mac_hex):
        raise PermissionError(
            "KINTSUGI_PRO_LICENSE_INVALID: License key verification failed (HMAC-SHA256 mismatch). "
            "Please verify your customer license key from Agensi.io / Gumroad."
        )

    return _xor_keystream(ciphertext, enc_key, nonce)


def get_packs_dir(workspace_root: str | Path = ".") -> Path:
    return Path(workspace_root) / ".kintsugi" / "packs"


def list_installed_packs(workspace_root: str | Path = ".") -> List[Dict[str, Any]]:
    packs_dir = get_packs_dir(workspace_root)
    if not packs_dir.exists():
        return []
    installed: List[Dict[str, Any]] = []
    for manifest_file in sorted(packs_dir.glob("*.json")):
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            installed.append(
                {
                    "pack_id": data.get("name", manifest_file.stem),
                    "title": data.get("title", manifest_file.stem),
                    "version": data.get("version", "0.3.0"),
                    "tier": data.get("tier", "community"),
                    "scars_count": len(data.get("scars", [])),
                    "autofix_rules": len(data.get("autofix_playbooks", [])),
                    "slash_commands": data.get("slash_commands", []),
                    "path": str(manifest_file),
                }
            )
        except Exception:
            continue
    return installed


def load_installed_pack_scars(workspace_root: str | Path = ".") -> List[GoldenScar]:
    packs_dir = get_packs_dir(workspace_root)
    if not packs_dir.exists():
        return []
    scars: List[GoldenScar] = []
    for manifest_file in sorted(packs_dir.glob("*.json")):
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            for item in data.get("scars", []):
                scars.append(GoldenScar.from_dict(item))
        except Exception:
            continue
    return scars


def load_installed_autofix_playbooks(workspace_root: str | Path = ".") -> List[Dict[str, Any]]:
    packs_dir = get_packs_dir(workspace_root)
    if not packs_dir.exists():
        return []
    playbooks: List[Dict[str, Any]] = []
    for manifest_file in sorted(packs_dir.glob("*.json")):
        try:
            data = json.loads(manifest_file.read_text(encoding="utf-8"))
            for pb in data.get("autofix_playbooks", []):
                if isinstance(pb, dict):
                    playbooks.append(pb)
        except Exception:
            continue
    return playbooks


def install_skill_pack(
    pack_source: str | Path,
    *,
    workspace_root: str | Path = ".",
    ledger_path: str | Path = ".kintsugi/scars.json",
    license_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Install a `.kpack` (encrypted Pro bundle), `.zip`, or `.json` Skill Pack into `.kintsugi/packs/`,
    merge its verified Golden Scars into the active ledger, and extract any slash commands.
    """
    src = Path(pack_source)
    ws = Path(workspace_root)
    if not src.exists():
        raise FileNotFoundError(f"Skill pack not found: {src}")

    packs_dir = get_packs_dir(ws)
    packs_dir.mkdir(parents=True, exist_ok=True)
    ledger = ScarLedger(ledger_path)

    extracted_commands: List[str] = []
    pack_payload: Dict[str, Any] = {}
    suffix = src.suffix.lower()

    if suffix in {".zip", ".kpack"}:
        if suffix == ".kpack":
            decrypted_zip = decrypt_pro_kpack_bytes(src.read_bytes(), license_key)
            zf_ctx = zipfile.ZipFile(io.BytesIO(decrypted_zip), "r")
        else:
            zf_ctx = zipfile.ZipFile(src, "r")

        with zf_ctx as zf:
            names = zf.namelist()
            # Locate agensi-manifest.json or pack.json + scars.json inside the archive
            manifest_data: Dict[str, Any] = {}
            scars_list: List[Dict[str, Any]] = []
            playbooks_list: List[Dict[str, Any]] = []
            kml_wire_text: Optional[str] = None

            for member in names:
                base = Path(member).name
                if base in {"agensi-manifest.json", "kintsugi-pack.json"}:
                    manifest_data = json.loads(zf.read(member).decode("utf-8"))
                elif base == "scars.json":
                    raw_scars = json.loads(zf.read(member).decode("utf-8"))
                    scars_list = raw_scars.get("scars", []) if isinstance(raw_scars, dict) else raw_scars
                elif base == "scars.kml":
                    kml_wire_text = zf.read(member).decode("utf-8")
                elif base == "autofix_playbooks.json":
                    raw_pb = json.loads(zf.read(member).decode("utf-8"))
                    playbooks_list = raw_pb.get("playbooks", []) if isinstance(raw_pb, dict) else raw_pb
                elif ".claude/commands/" in member and member.endswith(".md"):
                    cmd_dest = ws / ".claude" / "commands" / base
                    cmd_dest.parent.mkdir(parents=True, exist_ok=True)
                    cmd_dest.write_bytes(zf.read(member))
                    extracted_commands.append(f"/{cmd_dest.stem}")
                elif ".claude/skills/" in member and member.endswith(".md"):
                    rel_idx = member.find(".claude/skills/")
                    rel_sub = member[rel_idx:]
                    skill_dest = ws / rel_sub
                    skill_dest.parent.mkdir(parents=True, exist_ok=True)
                    skill_dest.write_bytes(zf.read(member))

            pack_slug = manifest_data.get("name", src.stem)
            if kml_wire_text:
                (packs_dir / f"{pack_slug}.kml").write_text(kml_wire_text, encoding="utf-8")
            pack_payload = {
                "name": pack_slug,
                "title": manifest_data.get("title", pack_slug),
                "version": manifest_data.get("version", "1.3.0"),
                "tier": manifest_data.get("tier", "premium"),
                "machine_language_format": manifest_data.get("machine_language_format", "KML/1"),
                "scars": scars_list,
                "autofix_playbooks": playbooks_list,
                "slash_commands": sorted(extracted_commands),
            }
    else:
        raw = json.loads(src.read_text(encoding="utf-8"))
        pack_slug = raw.get("name", src.stem)
        pack_payload = {
            "name": pack_slug,
            "title": raw.get("title", pack_slug),
            "version": raw.get("version", "0.3.0"),
            "tier": raw.get("tier", "community"),
            "scars": raw.get("scars", []),
            "autofix_playbooks": raw.get("autofix_playbooks", []),
            "slash_commands": raw.get("slash_commands", []),
        }

    dest_file = packs_dir / f"{pack_payload['name']}.json"
    dest_file.write_text(
        json.dumps(pack_payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    added_scars = 0
    for item in pack_payload.get("scars", []):
        scar = GoldenScar.from_dict(item)
        is_new, _ = ledger.upsert(scar)
        if is_new:
            added_scars += 1
    ledger.save()
    try:
        kml_dest = Path(ledger_path).with_suffix(".kml")
        kml_dest.write_text(render_kml_ledger(ledger.all()), encoding="utf-8")
    except OSError as exc:
        _ = str(exc)

    return {
        "pack_id": pack_payload["name"],
        "tier": pack_payload["tier"],
        "scars_in_pack": len(pack_payload.get("scars", [])),
        "newly_unlocked_scars": added_scars,
        "autofix_playbooks": len(pack_payload.get("autofix_playbooks", [])),
        "slash_commands": pack_payload.get("slash_commands", []),
        "installed_to": str(dest_file),
    }
