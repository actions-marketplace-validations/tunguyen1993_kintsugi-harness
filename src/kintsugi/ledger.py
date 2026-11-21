"""Persistent Golden Scar Ledger with SHA-256 deduplication and budget pruning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from kintsugi.models import GoldenScar, Severity
from kintsugi.shield import audit_scar_security, assert_not_symlink, atomic_write_text
from kintsugi.starter_pack import get_full_crs_scars, get_starter_scars


class ScarLedger:
    """Manages `.kintsugi/scars.json` with deterministic ordering and zero duplicates."""

    SCHEMA_VERSION = "1.0"

    def __init__(self, path: Path | str = ".kintsugi/scars.json", *, ensure_builtin_crs: bool = False) -> None:
        self.path = Path(path)
        self._ensure_builtin_crs = bool(ensure_builtin_crs)
        self._scars: Dict[str, GoldenScar] = {}
        self._fingerprints: Dict[str, str] = {}
        self.quarantined: List[Tuple[str, str]] = []
        if self.path.exists():
            self.load(ensure_builtin_crs=self._ensure_builtin_crs)

    def load(self, *, ensure_builtin_crs: Optional[bool] = None) -> None:
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        entries = raw.get("scars", []) if isinstance(raw, dict) else raw
        self._scars.clear()
        self._fingerprints.clear()
        self.quarantined.clear()
        for item in entries:
            scar = GoldenScar.from_dict(item)
            ok, reason = audit_scar_security(scar)
            if not ok:
                self.quarantined.append((scar.id, reason))
                continue
            if scar.id in self._scars and self._scars[scar.id].fingerprint != scar.fingerprint:
                self.quarantined.append((scar.id, "DUPLICATE_ID_CONFLICT"))
                continue
            self._scars[scar.id] = scar
            self._fingerprints[scar.fingerprint] = scar.id
        use_crs = self._ensure_builtin_crs if ensure_builtin_crs is None else bool(ensure_builtin_crs)
        if use_crs:
            self.ensure_builtin_crs_rules(persist=False)

    def ensure_builtin_crs_rules(self, *, persist: bool = False) -> int:
        """Merge any missing built-in CRS baseline rules (`KS-001..KS-024`) without overwriting custom scars."""
        added = 0
        for scar in get_full_crs_scars():
            if scar.id in self._scars:
                continue
            existing_fp_id = self._fingerprints.get(scar.fingerprint)
            if existing_fp_id and existing_fp_id in self._scars:
                continue
            ok, _reason = audit_scar_security(scar)
            if not ok:
                continue
            self._scars[scar.id] = scar
            self._fingerprints[scar.fingerprint] = scar.id
            added += 1
        if persist and added > 0:
            self.save()
        return added

    def save(self) -> None:
        assert_not_symlink(self.path.parent)
        assert_not_symlink(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ordered = sorted(self._scars.values(), key=lambda s: s.id)
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "total_scars": len(ordered),
            "scars": [s.to_dict() for s in ordered],
        }
        raw_text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        # Escape bidirectional control characters so Trojan Source fixtures don't store raw bidi bytes on disk
        for cp in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)):
            ch = chr(cp)
            if ch in raw_text:
                raw_text = raw_text.replace(ch, f"\\u{cp:04x}")
        atomic_write_text(self.path, raw_text, mode=0o600)

    def bootstrap_starter_pack(self, *, include_crs: bool = True) -> int:
        """Seed baseline scars (`KS-001..KS-024` by default) if missing; returns count of newly added scars."""
        corpus = get_full_crs_scars() if include_crs else get_starter_scars()
        added = 0
        for scar in corpus:
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
        Enforces the 7-Layer Zero-Trust Evolution Shield (`audit_scar_security`).
        """
        if not scar.id:
            scar.id = self.next_id()
        elif scar.id in self._scars and self._scars[scar.id].fingerprint != scar.fingerprint:
            # Never allow a newly synthesized rule to replace an existing guard by ID.
            raise ValueError(f"SCAR_ID_CONFLICT: {scar.id} already belongs to a different rule")
        ok, reason = audit_scar_security(scar)
        if not ok:
            raise ValueError(f"Zero-Trust Evolution Shield blocked scar '{scar.id}': {reason}")

        existing_id = self._fingerprints.get(scar.fingerprint)
        if existing_id and existing_id in self._scars:
            existing = self._scars[existing_id]
            existing.hits += max(1, scar.hits)
            for verifier in scar.verified_by:
                if verifier not in existing.verified_by:
                    existing.verified_by.append(verifier)
            return False, existing

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

    @property
    def scars(self) -> List[GoldenScar]:
        return self.all()
