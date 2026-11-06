---
name: kintsugi-core-guard-free
description: Open-source deterministic verification guard for AI coding agents (Claude Code, Cursor, Codex CLI, Gemini CLI, OpenClaw). Catches hallucinated claims, runaway token loops, basic prompt injection, and IEEE-754 numerical cancellation before shipping.
version: 1.3.0
tier: free
price_usd: 0
license: Apache-2.0
repository: https://github.com/tunguyen1993/kintsugi-harness/tree/opensource/free-skill-pack
---

# Kintsugi Core Guard — Free Open-Source Skill Pack (`v1.3.0` · `@KML/1`)

**Kintsugi Core Guard (`$0 Free Tier`)** is the open-source starter skill from [Kintsugi Harness](https://github.com/tunguyen1993/kintsugi-harness). It equips Claude Code, Cursor, Codex CLI, Windsurf, and Antigravity with 16 foundational AST/Regex guardrails (`KS-001`..`KS-016`), 5 deterministic runtime gates, and `@KML/1` Symbolic AST-IR machine-language rules.

## What It Does
1. **Hallucination & Unverified Negative-Claim Guard (`KL-GROUND-001`):** Refuses unbacked `"not found"` or `"all tests pass"` assertions without verbatim execution proof (`exit_code == 0` and complete sweep counts).
2. **Agent Runaway Loop & Budget Circuit Breaker (`KL-FINOPS-001`):** Detects repetitive tool-call cycles and enforces strict per-task token/cost caps.
3. **Baseline Prompt-Injection & SSRF Sanitizer (`KL-SEC-001`, `KL-MCP-001`):** Screens untrusted tool outputs and webhook URLs against metadata-service SSRF (`169.254.169.254`) and instruction-hijack markers.
4. **Swarm Consensus Sanity Check (`KL-SWARM-001`):** Verifies independent reasoning signals before accepting high-risk code modifications.
5. **Scientific Numerical Stability Check (`SCI-REL-001` Preview):** Flags catastrophic floating-point cancellation (`gamma^2 - 1` at `beta << 1`) and enforces algebraic reformulation (`beta^2 / (1 - beta^2)`).

## Quickstart & Self-Test (Zero Dependencies, Python 3 Stdlib)
Run the included self-test to verify all 5 deterministic gates on your machine:
```bash
python3 scripts/kintsugi_free_quickstart.py --selftest
```

## Edition Comparison: Free (`$0`) vs Kintsugi Pro (`v1.3.0` on Agensi.io)

| Feature / Capability | Core Guard Free (`$0`) | Tier 1: FinOps & Reliability Pro (`$15`) | Tier 2: Zero-Trust & MCP Shield Pro (`$19`) | Tier 3: Enterprise Complete Pro (`$29`) |
| :--- | :---: | :---: | :---: | :---: |
| **Curated Core + Exclusive Pro Scars** | 16 Core (`KS-001..016`) | 11 FinOps/Reliability (`KS-018,025,026,030,031` + Core) | 21 AppSec/MCP (`KS-017,019..024,027..029,032` + Core) | **All 32/32 (`KS-001..KS-032`)** |
| **`@KML/1` Evolved Machine-Language Wire (`scars.kml`)** | 16 rules | **844 `@KML/1` rules** | **862 `@KML/1` rules** | **All 1,706 `@KML/1` rules** |
| **Deterministic Auto-Fix Codemods (`kintsugi autofix --apply`)** | — (Scan only) | **4 Auto-Fix Codemods** | **8 Auto-Fix Codemods** | **All 12/12 Auto-Fix Codemods** |
| **Interactive Slash Commands (`.claude/commands/*.md`)** | — | 4 Slash Workflows | 4 Slash Workflows | **4 Slash Workflows** |
| **Frontier Collective Pool Lessons (`collective_pool_lessons.json`)** | — | 40 Frontier Lessons | 40 Frontier Lessons | **40 Frontier Lessons** |
| **Delivery Formats** | `.zip` | `.zip` + Encrypted `.kpack` | `.zip` + Encrypted `.kpack` | **`.zip` + Encrypted `.kpack`** |
