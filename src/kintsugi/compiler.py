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
                "### Multi-Model Co-Execution & User Onboarding Protocol (`@GUIDE/1` — When User Asks)",
                "",
                "- **Always-On Rule for the AI Agent:** Whenever the user asks how to use Kintsugi Multi-Model Co-Execution, how many Free models they can run, why `--free-runners` is clamped, how to upgrade tiers, or how to add their own Paid Frontier Council API keys (`BYOK`), you **MUST proactively guide the user step-by-step in their language (Vietnamese or English)**:",
                "  1. Run `kintsugi guide \"<user_question>\"` (or `kintsugi swarm --guide`, or MCP tool `kintsugi_multi_model_guide`) to inspect their live workspace tier and configured seats.",
                "  2. Explain the 3 commercial tiers clearly:",
                "     - **Free / OSS (`$0` — `FREE_STARTER`):** Locked to `Primary Model + 1 Free Model ($0)` (`max_free_co_runners = 1`). Run `kintsugi swarm --register-deepseek-free` to auto-register a live $0 DeepSeek Free API key (262K context), then `kintsugi swarm . --co-run`.",
                "     - **Pro (`$15` FinOps / `$19` AppSec — `PRO_MULTI_FREE`):** Unlocks `Primary Model + 2..5 Parallel Free Models ($0)` with automatic HTTP 429 failover (`kintsugi swarm . --co-run --free-runners 5`).",
                "     - **Enterprise (`$29` — `ENTERPRISE_PAID_COUNCIL`):** Unlocks `Primary Model + 5 Free Models ($0) + 6-Seat BYOK Paid Frontier Council`.",
                "  3. Guide the user to add their own API keys (`BYOK`, saved locally with `chmod 0600` in `.kintsugi/paid_council_pool.json`):",
                "     - `kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>`",
                "     - `kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>`",
                "     - `kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>`",
                "     - `kintsugi swarm --paid-council-status`",
                "     - `kintsugi swarm . --co-run --free-runners 5 --paid-council`",
                "  4. **Anti-Overflow Conversation Compaction (`@COMPACT/1`):** When a conversation approaches context overflow (`>=70%` soft / `>=85%` hard watermark) or when the user asks to compress/save context without losing main points, immediately run `kintsugi compact --inject-agents` (or call MCP tool `kintsugi_compact_context`) to strip 4 classes of noise (verbose logs, polling loops, superseded file reads, thinking chaff) while locking 100% of `@USER_INTENTS`, `@HARD_ANCHORS` (`file:line`, commits, rules, IPs), and `@ERRORS_AND_FIXES` into `.kintsugi/context_checkpoints/latest_checkpoint.md` and `.kintsugi/context_checkpoints/latest_checkpoint.kml`.",
            ]
        )
        return "\n".join(lines)

    def render_multi_model_guide_skill(self) -> str:
        """Render `.claude/skills/kintsugi-multi-model-council/SKILL.md` for conversational user Q&A."""
        return (
            "---\n"
            "name: kintsugi-multi-model-council\n"
            'description: "Interactive Bilingual (VI/EN) User Onboarding & Q&A Guide for Kintsugi 3-Tier Multi-Model Co-Execution (Primary + 1..5 Free Models + BYOK Paid Frontier Council) and Zero-Loss Anti-Overflow Conversation Compaction (@COMPACT/1). Activate whenever the user asks how to use multi-model, add API keys, upgrade tiers, or prevent context overflow."\n'
            'tags: ["multi-model", "byok", "council", "onboarding", "user-guide", "anti-overflow", "compact"]\n'
            "---\n\n"
            "# Kintsugi Multi-Model Co-Execution, BYOK Paid Council & Anti-Overflow Compaction — Agent Skill\n\n"
            "Whenever the user asks **how to run multi-model**, **how many free models are included**, **how to add API keys for the Paid Council**, **how Free vs Pro vs Enterprise work**, or **how to prevent context overflow / auto-compact conversations**, immediately run:\n\n"
            "```bash\n"
            'kintsugi guide "<user_question>"\n'
            "# or to auto-compact the active conversation with zero context loss:\n"
            "kintsugi compact --inject-agents\n"
            "```\n\n"
            "And guide the user clearly in their language (**Tiếng Việt** or **English**):\n\n"
            "## 1. Bảng Phân Tầng 3 Gói (`3-Tier Commercial Matrix`)\n\n"
            "- **Bản Free (`$0` — `FREE_STARTER`):** Khóa cứng chạy **`Model gốc + 1 Model Free ($0)`** (`max_free_co_runners = 1`).\n"
            "  - Lệnh chạy: `kintsugi swarm . --co-run`\n"
            "- **Bản Pro (`$15` FinOps Pro / `$19` AppSec Pro — `PRO_MULTI_FREE`):** Mở khóa chạy song song **`Model gốc + 2..5 Model Free ($0)`**, tự động xoay vòng khi gặp `HTTP 429`.\n"
            "  - Mở khóa: `kintsugi install-pack <pro-pack.kpack> --license-key <PRO_KEY>`\n"
            "  - Cấp quyền lấy pool Free `$0`: `kintsugi swarm --authorize-auto-provision`\n"
            "  - Lệnh chạy: `kintsugi swarm . --co-run --free-runners 5`\n"
            "- **Bản Enterprise (`$29` — `ENTERPRISE_PAID_COUNCIL`):** Mở khóa **`Model gốc + 5 Model Free ($0) + 6 Ghế Hội Đồng Thu Phí (BYOK)`**.\n"
            "  - Mở khóa: `kintsugi install-pack <enterprise-pack.kpack> --license-key <ENT_KEY>`\n\n"
            "## 2. Cách Hướng Dẫn Người Dùng Tự Thêm Key Hội Đồng Thu Phí (`BYOK`)\n\n"
            "Giải thích rõ cho người dùng: Với Hội Đồng Thu Phí, người dùng **tự thêm API key cá nhân** (key được lưu cục bộ `chmod 0600` tại `.kintsugi/paid_council_pool.json` trên máy của họ, che kín khi hiển thị và không bao giờ gửi đi đâu):\n\n"
            "```bash\n"
            "kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>\n"
            "kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>\n"
            "kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>\n"
            "kintsugi swarm --add-paid-key google_gemini_paid <YOUR_GEMINI_KEY>\n"
            "kintsugi swarm --add-paid-key deepseek_paid <YOUR_DEEPSEEK_KEY>\n"
            "kintsugi swarm --paid-council-status\n"
            "kintsugi swarm . --co-run --free-runners 5 --paid-council\n"
            "```\n\n"
            "## 3. Cơ Chế Chống Tràn Nén & Giữ 100% Ý Chính (`@COMPACT/1` — Zero-Loss Anti-Overflow)\n\n"
            "Khi hội thoại dài dần hoặc chạm ngưỡng cảnh báo (`70%` Soft Watermark / `85%` Hard Watermark), chạy lệnh:\n\n"
            "```bash\n"
            "# Tự động lọc bỏ 4 nguồn gây nhiễu (log dài, vòng lặp poll, đọc trùng file, nháp thừa)\n"
            "# và khóa cứng 100% Ý chính (@USER_INTENTS), Mỏ neo kỹ thuật (@HARD_ANCHORS) & Lỗi đã sửa (@ERRORS_AND_FIXES):\n"
            "kintsugi compact --inject-agents\n"
            "kintsugi compact --wire\n"
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
