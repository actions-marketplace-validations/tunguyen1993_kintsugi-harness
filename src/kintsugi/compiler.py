"""Cross-agent Harness & Skill Compiler (Claude Code, Cursor, GitHub Copilot, Windsurf, Codex/AGENTS.md)."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from kintsugi.compressor import render_kmi_index, render_kml_corpus, scar_to_kml_wire
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
    and IDE governance configs across Claude Code, Cursor, Copilot, Windsurf, and Codex.
    """

    def __init__(
        self,
        scars: Sequence[GoldenScar],
        *,
        max_scars_in_root_doc: int = 18,
        compact_kmi: bool = False,
    ) -> None:
        self.scars = sorted(
            scars,
            key=lambda s: (-s.severity.rank, -s.hits, s.id),
        )
        self.max_scars_in_root_doc = max_scars_in_root_doc
        self.compact_kmi = compact_kmi

    def render_root_governance_block(self) -> str:
        """Render KMI/1 ultra-low-token index or KML/1 Machine-Native Opcode Table."""
        if self.compact_kmi:
            return render_kmi_index(self.scars)
        top_scars = self.scars[: self.max_scars_in_root_doc]
        lines = [
            "## Kintsugi Machine-Language Guardrail Index (`@KML/1`)",
            "",
            "> `@GATE: kintsugi scan --staged --fail-on HIGH | @CORPUS: .kintsugi/scars.kml | @SKILLS: .claude/skills/kintsugi-guardrails/SKILL.md`",
            "",
            "| ID | SEV | CAT | KML/1 Symbolic Opcode (`@OP/1`) |",
            "| :--- | :--- | :--- | :--- |",
        ]
        for s in top_scars:
            lines.append(f"| `{s.id}` | `{s.severity.value}` | `{s.category}` | `{s.title}` |")
        if len(self.scars) > len(top_scars):
            omitted = len(self.scars) - len(top_scars)
            lines.append(
                f"\n*`@DEFERRED_RECORDS: +{omitted} in .kintsugi/scars.kml & .claude/skills/`*"
            )
        return "\n".join(lines)

    def render_skill_markdown(self, skill_name: str, description: str, scars: Sequence[GoldenScar]) -> str:
        """Render an Agent Skills compliant SKILL.md in KML/1 Universal Agent Machine Language."""
        all_tags = sorted({t for s in scars for t in s.tags})[:10]
        tags_yaml = ", ".join(f'"{t}"' for t in all_tags)
        lines = [
            "---",
            f"name: {skill_name}",
            f'description: "{description}"',
            f"tags: [{tags_yaml}]",
            "---",
            "",
            f"# {skill_name} (`@KML/1` Machine-Native AST-IR)",
            "",
            "```bash",
            "kintsugi scan --staged --fail-on HIGH",
            "```",
            "",
            "## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)",
            "",
        ]
        for scar in scars:
            lang_hint = scar.languages[0] if scar.languages else "text"
            lines.extend(
                [
                    f"### `{scar.id}` · `{scar.title}`",
                    f"- `@WIRE`: `{scar_to_kml_wire(scar)}`",
                    f"- `@TRAP`: `{scar.root_cause}`",
                    f"- `@LAW`: `{scar.rationale}`",
                    "",
                    "`@NEG_AST` (`❌ FORBIDDEN`):",
                    f"```{lang_hint}",
                    scar.bad_code.rstrip(),
                    "```",
                    "",
                    "`@POS_AST` (`✅ REQUIRED`):",
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

    def render_copilot_instructions(self) -> str:
        """Render `.github/instructions/kintsugi-guardrails.instructions.md` for GitHub Copilot."""
        body = self.render_root_governance_block()
        return (
            "---\n"
            'applyTo: "**/*"\n'
            "---\n\n"
            f"{body}\n"
        )

    def render_windsurf_rules(self) -> str:
        """Render `.windsurfrules` governance block for Windsurf IDE."""
        return self.render_root_governance_block() + "\n"

    def compile_all(
        self,
        workspace_root: str | Path,
        *,
        targets: Iterable[str] = ("skills", "claude", "agents", "cursor"),
    ) -> List[Path]:
        root = Path(workspace_root)
        target_set = {t.strip().lower() for t in targets}
        if "all" in target_set:
            target_set = {"skills", "claude", "agents", "cursor", "copilot", "windsurf"}
        written: List[Path] = []

        if "skills" in target_set:
            kml_file = root / ".kintsugi" / "scars.kml"
            kml_file.parent.mkdir(parents=True, exist_ok=True)
            kml_file.write_text(render_kml_corpus(self.scars), encoding="utf-8")
            written.append(kml_file)

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

            by_cat: Dict[str, List[GoldenScar]] = defaultdict(list)
            for scar in self.scars:
                slug_cat = re.sub(r"[^a-z0-9]+", "-", scar.category.lower()).strip("-") or "general"
                by_cat[slug_cat].append(scar)
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

        if "copilot" in target_set:
            copilot_file = root / ".github" / "instructions" / "kintsugi-guardrails.instructions.md"
            copilot_file.parent.mkdir(parents=True, exist_ok=True)
            copilot_file.write_text(self.render_copilot_instructions(), encoding="utf-8")
            written.append(copilot_file)

        if "windsurf" in target_set:
            windsurf_path = root / ".windsurfrules"
            existing = windsurf_path.read_text(encoding="utf-8") if windsurf_path.exists() else ""
            windsurf_path.write_text(_upsert_bounded_section(existing, block), encoding="utf-8")
            written.append(windsurf_path)

        return written
