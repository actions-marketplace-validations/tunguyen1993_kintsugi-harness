# Changelog

All notable changes to `kintsugi-harness` are documented in this file.

## [0.1.0] - 2026-11-04

### Added
- **Zero-Dependency Core Engine (`src/kintsugi/`):** Dual-engine Python AST + Multi-Language Regex scanner (`< 25ms` cold execution) with `# kintsugi: ignore[KS-XXX]` and `# kintsugi: ignore-file` pragmas.
- **Starter Pack (`KS-001`..`KS-012`):** 12 self-verified security, safety, reliability, and correctness Golden Scars for AI coding agents.
- **Claude Code Native Integration:** `kintsugi hook claude-pre-tool` stdin/stdout decision engine and `kintsugi install-hooks` installer for `.claude/settings.json` and `.git/hooks/pre-commit`.
- **Cross-Agent Skill Compiler:** Generates `.claude/skills/*/SKILL.md`, bounded `CLAUDE.md` / `AGENTS.md` governance sections, and `.cursor/rules/kintsugi-guardrails.mdc`.
- **3-Agent Adversarial Evolution Council:** Multi-model (`Architect` -> `Synthesizer` -> `Red-Team Critic`) + offline fallback with mandatory in-memory `verify_candidate_scar` true-positive / zero-false-positive gate.
- **MCP Server & SARIF 2.1.0 Action:** `kintsugi mcp` stdio JSON-RPC 2.0 server and composite GitHub Action (`action.yml`).
