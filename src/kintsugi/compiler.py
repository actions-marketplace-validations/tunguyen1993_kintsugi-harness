"""Cross-agent Harness & Skill Compiler (Claude Code SKILL.md, CLAUDE.md, AGENTS.md, Cursor .mdc)."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from kintsugi.models import GoldenScar

BOUNDARY_START = "<!-- KINTSUGI:START -->"
BOUNDARY_END = "<!-- KINTSUGI:END -->"


def _upsert_bounded_section(existing_text: str, section_body: str) -> str:
    wrapped = f"{BOUNDARY_START}\n{section_body.rstrip()}\n{BOUNDARY_END}"
    pattern = re.compile(
        rf"{re.escape(BOUNDARY_START)}[\s\S]*?{re.escape(BOUNDARY_END)}",
        re.MULTILINE,
    )
    if pattern.search(existing_text):
        return pattern.sub(lambda _: wrapped, existing_text, count=1)
    trimmed = existing_text.rstrip()
    if not trimmed:
        return wrapped + "\n"
    return f"{trimmed}\n\n{wrapped}\n"


class SkillCompiler:
    """
    Compiles verified GoldenScars into portable, token-budgeted agent skill files
    and IDE governance configs without bloating context windows.
    """

    def __init__(self, scars: Sequence[GoldenScar], *, max_scars_in_root_doc: int = 15) -> None:
        self.scars = sorted(
            scars,
            key=lambda s: (-s.severity.rank, -s.hits, s.id),
        )
        self.max_scars_in_root_doc = max_scars_in_root_doc

    def render_root_governance_block(self) -> str:
        """Render compact index table for CLAUDE.md / AGENTS.md (< 40 tokens per rule)."""
        top_scars = self.scars[: self.max_scars_in_root_doc]
        lines = [
            "## Kintsugi Self-Evolved Guardrails (Auto-Compiled)",
            "",
            "> Managed by `kintsugi-harness`. Run `kintsugi scan .` before committing or opening PRs.",
            "> Full paired anti-patterns (`❌ Bad` vs `✅ Good`) live in `.claude/skills/kintsugi-guardrails/SKILL.md`.",
            "",
            "| ID | Severity | Category | Anti-Pattern to Avoid |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for s in top_scars:
            lines.append(f"| `{s.id}` | `{s.severity.value}` | `{s.category}` | {s.title} |")
        if len(self.scars) > len(top_scars):
            omitted = len(self.scars) - len(top_scars)
            lines.append(
                f"\n*+{omitted} additional domain scars compiled in `.claude/skills/`.*"
            )
        return "\n".join(lines)

    def render_skill_markdown(self, skill_name: str, description: str, scars: Sequence[GoldenScar]) -> str:
        """Render an Agent Skills compliant SKILL.md with paired code examples and verification steps."""
        lines = [
            "---",
            f"name: {skill_name}",
            f'description: "{description}"',
            "---",
            "",
            f"# {skill_name}",
            "",
            "Use this skill before writing, refactoring, or reviewing code in this repository.",
            "Every rule below was compiled from a verified failure trace and is enforced deterministically via `kintsugi scan`.",
            "",
            "## Verification Gate",
            "",
            "```bash",
            "kintsugi scan . --fail-on HIGH",
            "```",
            "",
            "## Verified Golden Scars (`❌ Anti-Pattern` vs `✅ Verified Fix`)",
            "",
        ]
        for scar in scars:
            lang_hint = scar.languages[0] if scar.languages else "text"
            lines.extend(
                [
                    f"### `{scar.id}` · [{scar.severity.value}] {scar.title}",
                    f"- **Root cause:** {scar.root_cause}",
                    f"- **Why this matters:** {scar.rationale}",
                    "",
                    "**Avoid (`❌ Anti-Pattern`):**",
                    f"```{lang_hint}",
                    scar.bad_code.rstrip(),
                    "```",
                    "",
                    "**Prefer (`✅ Verified Pattern`):**",
                    f"```{lang_hint}",
                    scar.good_code.rstrip(),
                    "```",
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"

    def render_cursor_mdc(self) -> str:
        """Render `.cursor/rules/kintsugi-guardrails.mdc` for Cursor IDE."""
        body = self.render_root_governance_block()
        return (
            "---\n"
            "description: Kintsugi deterministic safety, security, and reliability guardrails\n"
            "globs: **/*\n"
            "alwaysApply: true\n"
            "---\n\n"
            f"{body}\n"
        )

    def compile_all(
        self,
        workspace_root: str | Path,
        *,
        targets: Iterable[str] = ("skills", "claude", "agents", "cursor"),
    ) -> List[Path]:
        root = Path(workspace_root)
        target_set = {t.strip().lower() for t in targets}
        written: List[Path] = []

        if "skills" in target_set:
            # 1. Master consolidated skill
            master_skill = root / ".claude" / "skills" / "kintsugi-guardrails" / "SKILL.md"
            master_skill.parent.mkdir(parents=True, exist_ok=True)
            master_skill.write_text(
                self.render_skill_markdown(
                    "kintsugi-guardrails",
                    "Self-evolved security, reliability, and correctness guardrails enforced by Kintsugi AST/Regex scanner. Activate before editing code or running shell commands.",
                    self.scars,
                ),
                encoding="utf-8",
            )
            written.append(master_skill)

            # 2. Category-specific modular skills when >= 2 scars exist in a category
            by_cat: Dict[str, List[GoldenScar]] = defaultdict(list)
            for scar in self.scars:
                by_cat[scar.category.lower()].append(scar)
            for cat, cat_scars in sorted(by_cat.items()):
                if len(cat_scars) < 2:
                    continue
                cat_skill = root / ".claude" / "skills" / f"kintsugi-{cat}" / "SKILL.md"
                cat_skill.parent.mkdir(parents=True, exist_ok=True)
                cat_skill.write_text(
                    self.render_skill_markdown(
                        f"kintsugi-{cat}",
                        f"Focused {cat} anti-patterns and verified code templates compiled by Kintsugi Harness.",
                        cat_scars,
                    ),
                    encoding="utf-8",
                )
                written.append(cat_skill)

        block = self.render_root_governance_block()

        if "claude" in target_set:
            claude_md = root / "CLAUDE.md"
            existing = claude_md.read_text(encoding="utf-8") if claude_md.exists() else "# CLAUDE.md\n"
            claude_md.write_text(_upsert_bounded_section(existing, block), encoding="utf-8")
            written.append(claude_md)

        if "agents" in target_set:
            agents_md = root / "AGENTS.md"
            existing = agents_md.read_text(encoding="utf-8") if agents_md.exists() else "# AGENTS.md\n"
            agents_md.write_text(_upsert_bounded_section(existing, block), encoding="utf-8")
            written.append(agents_md)

        if "cursor" in target_set:
            cursor_mdc = root / ".cursor" / "rules" / "kintsugi-guardrails.mdc"
            cursor_mdc.parent.mkdir(parents=True, exist_ok=True)
            cursor_mdc.write_text(self.render_cursor_mdc(), encoding="utf-8")
            written.append(cursor_mdc)

        return written
