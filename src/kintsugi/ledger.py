"""Persistent Golden Scar Ledger with SHA-256 deduplication and budget pruning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from kintsugi.models import GoldenScar, Severity
from kintsugi.starter_pack import get_starter_scars


class ScarLedger:
    """Manages `.kintsugi/scars.json` with deterministic ordering and zero duplicates."""

    SCHEMA_VERSION = "1.0"

    def __init__(self, path: Path | str = ".kintsugi/scars.json") -> None:
        self.path = Path(path)
        self._scars: Dict[str, GoldenScar] = {}
        self._fingerprints: Dict[str, str] = {}
        if self.path.exists():
            self.load()

    def load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        entries = raw.get("scars", []) if isinstance(raw, dict) else raw
        self._scars.clear()
        self._fingerprints.clear()
        for item in entries:
            scar = GoldenScar.from_dict(item)
            self._scars[scar.id] = scar
            self._fingerprints[scar.fingerprint] = scar.id

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(self._scars.values(), key=lambda s: s.id)
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "total_scars": len(ordered),
            "scars": [s.to_dict() for s in ordered],
        }
        self.path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def bootstrap_starter_pack(self) -> int:
        """Seed baseline starter scars if missing; returns count of newly added scars."""
        added = 0
        for scar in get_starter_scars():
            is_new, _ = self.upsert(scar)
            if is_new:
                added += 1
        self.save()
        return added

    def next_id(self, prefix: str = "KS") -> str:
        max_num = 0
        for scar_id in self._scars:
            if scar_id.startswith(f"{prefix}-"):
                suffix = scar_id.split("-", 1)[1]
                if suffix.isdigit():
                    max_num = max(max_num, int(suffix))
        return f"{prefix}-{max_num + 1:03d}"

    def upsert(self, scar: GoldenScar) -> Tuple[bool, GoldenScar]:
        """
        Insert a new GoldenScar or merge with an existing identical fingerprint
        so repeated failures strengthen hit counters instead of bloating context.
        """
        existing_id = self._fingerprints.get(scar.fingerprint)
        if existing_id and existing_id in self._scars:
            existing = self._scars[existing_id]
            existing.hits += max(1, scar.hits)
            for verifier in scar.verified_by:
                if verifier not in existing.verified_by:
                    existing.verified_by.append(verifier)
            return False, existing

        if not scar.id or scar.id in self._scars:
            if scar.id not in self._scars:
                scar.id = self.next_id()
        self._scars[scar.id] = scar
        self._fingerprints[scar.fingerprint] = scar.id
        return True, scar

    def record_hits(self, scar_ids: Iterable[str]) -> None:
        changed = False
        for scar_id in scar_ids:
            if scar_id in self._scars:
                self._scars[scar_id].hits += 1
                changed = True
        if changed and self.path.exists():
            self.save()

    def list_scars(
        self,
        *,
        language: Optional[str] = None,
        tag: Optional[str] = None,
        min_severity: Optional[Severity] = None,
    ) -> List[GoldenScar]:
        results = sorted(
            self._scars.values(),
            key=lambda s: (-s.severity.rank, -s.hits, s.id),
        )
        if language:
            lang = language.lower()
            results = [s for s in results if lang in [x.lower() for x in s.languages]]
        if tag:
            needle = tag.lower()
            results = [
                s
                for s in results
                if needle in [t.lower() for t in s.tags] or needle == s.category.lower()
            ]
        if min_severity:
            results = [s for s in results if s.severity.meets(min_severity)]
        return results

    def all(self) -> List[GoldenScar]:
        return sorted(self._scars.values(), key=lambda s: s.id)
