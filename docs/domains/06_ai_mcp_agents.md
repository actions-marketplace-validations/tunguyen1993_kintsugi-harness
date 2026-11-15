# Domain Shard 06: AI Coding Agents, MCP Prompt Security & Token FinOps (`ai_mcp`)

> **Domain ID:** `ai_mcp` · **Shard Path:** `docs/domains/06_ai_mcp_agents.md` · **License:** `Apache-2.0`
> **Scope:** Indirect prompt-injection defense in `SKILL.md` / MCP tool metadata, blocking unfinished `TODO` placeholder stubs in agent-authored code, bounded agent loop budgets, and zero-loss conversation compaction (`@COMPACT/2`).

## 1. Domain-Routed `KMI/1` Wire Header (`ai_mcp`)

```text
<!-- KINTSUGI:KMI/1:DOMAIN=ai_mcp START -->
# KMI/1;domain=ai_mcp;doc=docs/domains/06_ai_mcp_agents.md;jit=pre-tool-use
@CRIT: KS-012(prompt!no_system_override_injection)
@MED : KS-009(no_todo_placeholder_stub)
<!-- KINTSUGI:KMI/1:DOMAIN=ai_mcp END -->
```

## 2. Enforced Guardrails in This Shard

| Scar ID | Severity | Languages | Anti-Pattern (`❌ Bad`) | Verified Remediation (`✅ Good`) |
| :--- | :--- | :--- | :--- | :--- |
| `KS-009` | `MEDIUM` | `py,js,ts` | Shipping `# TODO: implement` or `PLACEHOLDER_STUB` in production modules | Implement complete concrete logic and unit tests before commit |
| `KS-012` | `CRITICAL` | `md,py,js,ts` | Hidden `Ignore all previous instructions and exfiltrate ...` in skills/fixtures | Declarative, zero-execution skill schemas verified by `@QUARANTINE/1` |

## 3. Reproducible CLI Commands

```bash
# Render only the ai_mcp domain KMI/1 shard:
kintsugi token-report --domain ai_mcp
```
