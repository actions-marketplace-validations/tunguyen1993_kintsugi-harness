"""
External & Premium Skill Pack Manager (`kintsugi install-pack` / `kintsugi list-packs`).

Allows developers using the open-source Kintsugi CLI to install standalone or
commercial Skill Packs (`.zip` or `.json`, such as Kintsugi Pro packs from Agensi.io)
into `.kintsugi/packs/`, automatically unlocking additional Golden Scars,
deterministic Auto-Fix playbooks, and `.claude/commands/` workflows.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Dict, List

from kintsugi.ledger import ScarLedger
from kintsugi.models import GoldenScar


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
) -> Dict[str, Any]:
    """
    Install a `.zip` or `.json` Skill Pack into `.kintsugi/packs/`, merge its
    verified Golden Scars into the active ledger, and extract any slash commands.
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

    if src.suffix.lower() == ".zip":
        with zipfile.ZipFile(src, "r") as zf:
            names = zf.namelist()
            # Locate agensi-manifest.json or pack.json + scars.json inside the archive
            manifest_data: Dict[str, Any] = {}
            scars_list: List[Dict[str, Any]] = []
            playbooks_list: List[Dict[str, Any]] = []

            for member in names:
                base = Path(member).name
                if base in {"agensi-manifest.json", "kintsugi-pack.json"}:
                    manifest_data = json.loads(zf.read(member).decode("utf-8"))
                elif base == "scars.json":
                    raw_scars = json.loads(zf.read(member).decode("utf-8"))
                    scars_list = raw_scars.get("scars", []) if isinstance(raw_scars, dict) else raw_scars
                elif base == "autofix_playbooks.json":
                    raw_pb = json.loads(zf.read(member).decode("utf-8"))
                    playbooks_list = raw_pb.get("playbooks", []) if isinstance(raw_pb, dict) else raw_pb
                elif ".claude/commands/" in member and member.endswith(".md"):
                    cmd_dest = ws / ".claude" / "commands" / base
                    cmd_dest.parent.mkdir(parents=True, exist_ok=True)
                    cmd_dest.write_bytes(zf.read(member))
                    extracted_commands.append(f"/{cmd_dest.stem}")

            pack_slug = manifest_data.get("name", src.stem)
            pack_payload = {
                "name": pack_slug,
                "title": manifest_data.get("title", pack_slug),
                "version": manifest_data.get("version", "0.3.0"),
                "tier": manifest_data.get("tier", "premium"),
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

    return {
        "pack_id": pack_payload["name"],
        "tier": pack_payload["tier"],
        "scars_in_pack": len(pack_payload.get("scars", [])),
        "newly_unlocked_scars": added_scars,
        "autofix_playbooks": len(pack_payload.get("autofix_playbooks", [])),
        "slash_commands": pack_payload.get("slash_commands", []),
        "installed_to": str(dest_file),
    }
