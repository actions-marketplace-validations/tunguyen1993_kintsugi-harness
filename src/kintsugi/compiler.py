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
        lines.extend(
            [
                "",
                "### `@GUIDE/1` & `@COMPACT/1` Machine-Native Execution Protocol",
                "",
                "```text",
                '@GUIDE/1[cmd="kintsugi guide \\"<question>\\"" | mcp="kintsugi_multi_model_guide"]',
                '@TIERS/1[FREE_STARTER="$0: Primary + 1 Free (--register-deepseek-free, --co-run)" | PRO_MULTI_FREE="$15/$19: Primary + 2..5 Free (--free-runners 5)" | ENTERPRISE_PAID_COUNCIL="$29: Primary + 5 Free + 6 BYOK Paid Seats"]',
                '@BYOK/1[store=".kintsugi/paid_council_pool.json(0600)" | add="kintsugi swarm --add-paid-key <anthropic_opus|openai_frontier|xai_grok_paid> <KEY>" | status="--paid-council-status" | run="--co-run --free-runners 5 --paid-council"]',
                '@COMPACT/1[trigger="pressure>=70%_soft|>=85%_hard" | cmd="kintsugi compact --inject-agents" | mcp="kintsugi_compact_context" | preserve="@USER_INTENTS,@HARD_ANCHORS,@ERRORS_AND_FIXES" | out=".kintsugi/context_checkpoints/latest_checkpoint.{md,kml}"]',
                "```",
                "",
                "### 5-Pillar Autopoietic Evolution Creed (`@CREED/1` Machine-Native IR)",
                "",
                '> `@CREED/1[ver=2.1|axiom="MUTATE_OR_STALL: identical_input => identical_failure | TRY_ALL_PICK_BEST: no_new_way => select_best_tested"|p1=2_STRIKE_PIVOT|p2=2X_TOOL_SYNTH|p3=CRACK_TO_SCAR|p4=SELF_OVERWRITE|p5=TRY_ALL_PICK_BEST]`',
                "",
                "| Pillar | `@OP/1` Symbolic Gate | Agent Execution Law (English) |",
                "| :--- | :--- | :--- |",
                "| `P1:MUTATE` | `IF fail(path, n>=2) => KILL(root_assumption) && PIVOT(new_vector)` | Repeating a failed action is a system bug; mutating the approach is intelligence. If two attempts on the same path stall, that path is dead—destroy your root assumption, change the question, and pivot instead of forcing new problems into old tools. |",
                "| `P2:SYNTH` | `IF manual_workaround(count>=2) => SYNTHESIZE(cli_tool \\| skill_1step)` | A missing tool is not a blocker; it is a command to synthesize a new one. Any manual workaround executed twice must be distilled into a single-step reusable skill—solving the problem is survival; codifying the capability is evolution. |",
                "| `P3:SCAR` | `ON error_trace(bug) => FIX(bug) && CODIFY(rule -> extinct(bug_class))` | Every error trace is a blueprint for the next version. Fixing a bug is half the work; upgrading internal rules (`scars.kml` / `CM-*`) so that entire class of bug goes extinct is completion. Where a workflow breaks, forge a stronger capability. |",
                "| `P4:PRUNE` | `WHILE verbose(skill) \\|\\| faster_path_exists => OVERWRITE(yesterday_skill)` | Yesterday's skill is a stepping stone, not a monument. Working code is not the finish line—doubt your defaults, treat every current method as a rough draft, and overwrite fragile or verbose workflows whenever a cleaner, faster path exists. |",
                "| `P5:CONVERGE` | `TRY_ALL(ways) && IF no_new_way_left => PICK_BEST(fastest, cleanest, most_effective)` | Do not hesitate to try every possible way; to find the best approach, dare to test them all. If you have tried every way and no new path remains, do not get stuck—compare what you tested and pick the single most optimal one. |",
            ]
        )
        return "\n".join(lines)

    def render_multi_model_guide_skill(self) -> str:
        """Render `.claude/skills/kintsugi-multi-model-council/SKILL.md` in `@GUIDE/1` Machine-Native IR."""
        return (
            "---\n"
            "name: kintsugi-multi-model-council\n"
            'description: "Machine-Native Spec (@GUIDE/1 + @COMPACT/1) for Kintsugi 3-Tier Multi-Model Co-Execution (FREE_STARTER, PRO_MULTI_FREE, ENTERPRISE_PAID_COUNCIL), BYOK Paid Council, and Zero-Loss Anti-Overflow Compaction."\n'
            'tags: ["multi-model", "byok", "council", "onboarding", "user-guide", "anti-overflow", "compact"]\n'
            "---\n\n"
            "# `@GUIDE/1` & `@COMPACT/1` Machine-Native Skill Spec\n\n"
            "```text\n"
            '@DISPATCH[on_user_question="kintsugi guide \\"<user_question>\\"" | on_overflow="kintsugi compact --inject-agents"]\n'
            "@TIERS[\n"
            '  FREE_STARTER:            "$0 | max_free_co_runners=1 | kintsugi swarm --register-deepseek-free && kintsugi swarm . --co-run"\n'
            '  PRO_MULTI_FREE:          "$15/$19 | max_free_co_runners=5 | kintsugi install-pack <pro.kpack> --license-key <KEY> && kintsugi swarm . --co-run --free-runners 5"\n'
            '  ENTERPRISE_PAID_COUNCIL: "$29 | 5 Free + 6 BYOK Paid | kintsugi install-pack <ent.kpack> --license-key <KEY>"\n'
            "]\n"
            "@BYOK_COMMANDS[\n"
            '  store:  ".kintsugi/paid_council_pool.json (chmod 0600, local-only, masked)"\n'
            '  add:    "kintsugi swarm --add-paid-key <anthropic_opus|openai_frontier|xai_grok_paid|google_gemini_paid|deepseek_paid> <API_KEY>"\n'
            '  status: "kintsugi swarm --paid-council-status"\n'
            '  exec:   "kintsugi swarm . --co-run --free-runners 5 --paid-council"\n'
            "]\n"
            "@COMPACT_PROTOCOL[\n"
            '  watermarks: "soft>=70% | hard>=85%"\n'
            '  strip:      "verbose_logs, polling_loops, superseded_reads, thinking_chaff"\n'
            '  preserve:   "@USER_INTENTS, @HARD_ANCHORS, @ERRORS_AND_FIXES"\n'
            '  commands:   "kintsugi compact --inject-agents | kintsugi compact --wire"\n'
            "]\n"
            "```\n"
        )

    def render_skill_markdown(self, skill_name: str, description: str, scars: Sequence[GoldenScar]) -> str:
        """Render an Agent Skills compliant SKILL.md in KML/1 Universal Agent Machine Language."""
        all_tags = sorted({t for s in scars for t in s.tags})[:10]
        tags_yaml = ", ".join(f'"{t}"' for t in all_tags)
        lines = [
            "---",
            f"name: {skill_name}",
            f'description: "{description}"',
            f"tags: [{tags_yaml}]",
            "# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)",
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
            'globs: "**/*"\n'
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

            guide_skill = root / ".claude" / "skills" / "kintsugi-multi-model-council" / "SKILL.md"
            guide_skill.parent.mkdir(parents=True, exist_ok=True)
            guide_skill.write_text(self.render_multi_model_guide_skill(), encoding="utf-8")
            written.append(guide_skill)

            guide_cmd = root / ".claude" / "commands" / "kintsugi-multi-model-council.md"
            guide_cmd.parent.mkdir(parents=True, exist_ok=True)
            guide_cmd.write_text(self.render_multi_model_guide_skill(), encoding="utf-8")
            written.append(guide_cmd)

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
