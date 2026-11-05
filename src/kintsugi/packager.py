"""
Marketplace Skill Pack Bundler (`kintsugi package-skills`).

Packages verified GoldenScars into standalone, multi-agent installable Skill Packs
(compatible with Agensi.io, Claude Code `.claude/skills/`, Cursor `.cursor/rules/`,
GitHub Copilot `.github/instructions/`, Windsurf `.windsurfrules`, and Codex `AGENTS.md`)
both as directory trees and ready-to-upload `.zip` archives.
"""

from __future__ import annotations

import json
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Sequence

from kintsugi import __version__
from kintsugi.compiler import SkillCompiler
from kintsugi.models import GoldenScar


class SkillPackager:
    """Builds vertical and full-suite Skill Packs for distribution and marketplaces."""

    def __init__(self, scars: Sequence[GoldenScar]) -> None:
        self.scars = sorted(
            scars,
            key=lambda s: (-s.severity.rank, -s.hits, s.id),
        )

    def _build_pack_tree(
        self,
        pack_slug: str,
        title: str,
        summary: str,
        scars: Sequence[GoldenScar],
        out_root: Path,
    ) -> Dict[str, Any]:
        pack_dir = out_root / pack_slug
        pack_dir.mkdir(parents=True, exist_ok=True)
        compiler = SkillCompiler(scars)

        # 1. Root SKILL.md (Agensi.io / Claude Code / Universal Agent Skills standard)
        skill_md_path = pack_dir / "SKILL.md"
        skill_md_path.write_text(
            compiler.render_skill_markdown(pack_slug, summary, scars),
            encoding="utf-8",
        )

        # 2. Multi-agent drop-in layouts inside the bundle
        claude_skill = pack_dir / ".claude" / "skills" / pack_slug / "SKILL.md"
        claude_skill.parent.mkdir(parents=True, exist_ok=True)
        claude_skill.write_text(skill_md_path.read_text(encoding="utf-8"), encoding="utf-8")

        cursor_rule = pack_dir / ".cursor" / "rules" / f"{pack_slug}.mdc"
        cursor_rule.parent.mkdir(parents=True, exist_ok=True)
        cursor_rule.write_text(compiler.render_cursor_mdc(), encoding="utf-8")

        copilot_inst = pack_dir / ".github" / "instructions" / f"{pack_slug}.instructions.md"
        copilot_inst.parent.mkdir(parents=True, exist_ok=True)
        copilot_inst.write_text(compiler.render_copilot_instructions(), encoding="utf-8")

        windsurf_file = pack_dir / ".windsurfrules"
        windsurf_file.write_text(compiler.render_windsurf_rules(), encoding="utf-8")

        manifest = {
            "name": pack_slug,
            "title": title,
            "version": __version__,
            "description": summary,
            "standard": "SKILL.md/1.0",
            "compatible_agents": [
                "claude-code",
                "cursor",
                "github-copilot",
                "windsurf",
                "codex-cli",
                "antigravity",
                "openhands",
                "cline",
            ],
            "scars_count": len(scars),
            "scar_ids": [s.id for s in scars],
            "languages": sorted({lang for s in scars for lang in s.languages}),
            "tags": sorted({tag for s in scars for tag in s.tags}),
            "PoweredBy": "https://github.com/tunguyen1993/kintsugi-harness",
        }
        manifest_path = pack_dir / "agensi-manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

        # 3. Create deterministic .zip archive for one-click upload
        zip_path = out_root / f"{pack_slug}-v{__version__}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for file_path in sorted(pack_dir.rglob("*")):
                if file_path.is_file():
                    arcname = f"{pack_slug}/{file_path.relative_to(pack_dir).as_posix()}"
                    zf.writestr(arcname, file_path.read_bytes())

        return {
            "slug": pack_slug,
            "title": title,
            "scars_count": len(scars),
            "directory": str(pack_dir),
            "zip_archive": str(zip_path),
            "skill_md": str(skill_md_path),
        }

    def build_all_packs(self, output_dir: str | Path) -> List[Dict[str, Any]]:
        out_root = Path(output_dir)
        out_root.mkdir(parents=True, exist_ok=True)
        built: List[Dict[str, Any]] = []

        # 1. Flagship Complete Pack
        built.append(
            self._build_pack_tree(
                pack_slug="kintsugi-complete-guardrails-pro",
                title="Kintsugi Complete Deterministic Guardrails & Self-Evolving Harness",
                summary=(
                    "Complete suite of AST and Regex verified coding-agent guardrails preventing "
                    "secret leaks, command/SQL injection, silent exception swallowing, unbounded HTTP hangs, "
                    "and destructive shell operations across Claude Code, Cursor, Copilot, and Windsurf."
                ),
                scars=self.scars,
                out_root=out_root,
            )
        )

        # 2. Category-specific specialized packs
        by_category: Dict[str, List[GoldenScar]] = defaultdict(list)
        for scar in self.scars:
            by_category[scar.category.lower()].append(scar)

        category_titles = {
            "security": (
                "kintsugi-zero-trust-security-pack",
                "Kintsugi Zero-Trust AppSec & DLP Guardrails for AI Agents",
                "Prevents hardcoded credentials, SQL/command injection, unsafe deserialization, weak PRNG tokens, TLS bypasses, and indirect prompt injection.",
            ),
            "reliability": (
                "kintsugi-production-reliability-pack",
                "Kintsugi Production Reliability & Anti-Hang Guardrails",
                "Eliminates unbounded HTTP timeouts, silent exception swallowing, zombie headless browser leaks, and unhandled runtime crashes.",
            ),
            "correctness": (
                "kintsugi-code-correctness-pack",
                "Kintsugi Code Correctness & Anti-Hallucination Pack",
                "Catches mutable default state leaks, unfinished placeholder stubs, and subtle cross-platform regressions.",
            ),
        }

        for cat, cat_scars in sorted(by_category.items()):
            if not cat_scars:
                continue
            slug, title, desc = category_titles.get(
                cat,
                (
                    f"kintsugi-{cat}-pack",
                    f"Kintsugi {cat.title()} Guardrail Skill Pack",
                    f"Verified {cat} anti-patterns and deterministic fixes compiled by Kintsugi Harness.",
                ),
            )
            built.append(
                self._build_pack_tree(
                    pack_slug=slug,
                    title=title,
                    summary=desc,
                    scars=cat_scars,
                    out_root=out_root,
                )
            )

        index_path = out_root / "catalog-index.json"
        index_path.write_text(
            json.dumps({"version": __version__, "packs": built}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return built
