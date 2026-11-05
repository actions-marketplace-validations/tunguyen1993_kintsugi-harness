---
name: kintsugi-core-guard-free
description: Open-source deterministic verification guard for AI coding agents (Claude Code, Cursor, Codex CLI, Gemini CLI, OpenClaw). Catches hallucinated claims, runaway token loops, basic prompt injection, and IEEE-754 numerical cancellation before shipping.
version: 1.2.0
tier: free
price_usd: 0
license: Apache-2.0
repository: https://github.com/tunguyen1993/kintsugi-harness/tree/opensource/free-skill-pack
---

# Kintsugi Core Guard — Free Open-Source Skill Pack (`v1.2.0`)

**Kintsugi Core Guard (`$0 Free Tier`)** is the open-source starter skill from [Kintsugi Harness](https://github.com/tunguyen1993/kintsugi-harness) (`opensource` branch). It equips Claude Code, Cursor, Codex CLI, Gemini CLI, and OpenClaw with 5 foundational deterministic gates and a zero-dependency `--selftest` verifier script.

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

## Need Production-Grade Protection? Upgrade to Kintsugi Pro (`v1.2.0`) on Agensi.io
While **Kintsugi Core Guard (`$0`)** covers the 5 foundational checks, production AI teams can unlock the full **40-lesson Frontier Collective Pool**, **Covariance-Aware BFT Swarm (`N_eff = 3.39`)**, **Disjoint Generator/Verifier Scar Holdout Gate (`T_gen != T_ver`)**, **Alpha-Normalized AST Quotient (`ASTQ/1`)**, and **5-Domain Hard Scientific Literature Verifier** on Agensi.io or via the encrypted `premium` vault (`pro-vault/*.kpack`):
- **Tier 1 — Agent FinOps & Reliability Pro (`$15`):** 14 deep FinOps, RAG grounding, and covariance-aware BFT swarm gates (`KL-MCP-007`).
- **Tier 2 — Zero-Trust MCP & Security Pro (`$19`):** 14 deep MCP tool-poisoning, cryptographic signature (`EIP-191`/`Ed25519`), and interprocedural AST taint gates.
- **Tier 3 — Enterprise Complete All-in-One Pro Bundle (`$29`, Save 41% off `$49`):** All 40 verified Frontier lessons across all 15 engineering domains + full scientific corpus verifier.
