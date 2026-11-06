---
name: kintsugi-core-guard-free
description: Open-source deterministic verification guard for AI coding agents (Claude Code, Cursor, Codex CLI, Gemini CLI, OpenClaw). Catches hallucinated claims, runaway token loops, basic prompt injection, and IEEE-754 numerical cancellation before shipping.
version: 1.7.0
tier: free
price_usd: 0
license: Apache-2.0
repository: https://github.com/tunguyen1993/kintsugi-harness/tree/opensource/free-skill-pack
---

# Kintsugi Core Guard — Free Open-Source Skill Pack (`v1.7.0` · `@KML/1` · `@LOGIC/2` · `@PROOF_DAG/1`)

**Kintsugi Core Guard (`$0 Free Tier`)** is the open-source starter skill from [Kintsugi Harness](https://github.com/tunguyen1993/kintsugi-harness). It equips Claude Code, Cursor, Codex CLI, Windsurf, and Antigravity with 16 foundational AST/Regex guardrails (`KS-001`..`KS-016`), `@LOGIC/2` 5-Pillar Neuro-Symbolic Verification, `@PROOF_DAG/1` Signed Compliance Proofs, `@COMPACT/2` Zero-Amnesia Conversation & Excel Compaction, and `@KML/1` Symbolic AST-IR machine-language rules.

## What It Does
1. **Hallucination & Unverified Negative-Claim Guard (`KL-GROUND-001`):** Refuses unbacked `"not found"` or `"all tests pass"` assertions without verbatim execution proof (`exit_code == 0` and complete sweep counts).
2. **Agent Runaway Loop & Budget Circuit Breaker (`KL-FINOPS-001`):** Detects repetitive tool-call cycles and enforces strict per-task token/cost caps.
3. **Baseline Prompt-Injection & SSRF Sanitizer (`KL-SEC-001`, `KL-MCP-001`):** Screens untrusted tool outputs and webhook URLs against metadata-service SSRF (`169.254.169.254`) and instruction-hijack markers.
4. **5-Pillar Neuro-Symbolic Logic & Signed Compliance Proofs (`@LOGIC/2` + `@PROOF_DAG/1`):** DPLL SAT/MUS, Stratified Datalog `ProofDAG/1`, Exact Rational Difference Logic, `@FALLACY_GUARD/1`, Reiter's MHS Abduction, and `.kintsugi/audit.proof` SOC2/ISO27001/EU-AI-Act compliance bundles.
5. **Scientific Numerical Stability Check (`SCI-REL-001` Preview):** Flags catastrophic floating-point cancellation (`gamma^2 - 1` at `beta << 1`) and enforces algebraic reformulation (`beta^2 / (1 - beta^2)`).

## Quickstart & Self-Test (Zero Dependencies, Python 3 Stdlib)
Run the included self-test to verify all deterministic gates on your machine:
```bash
python3 scripts/kintsugi_free_quickstart.py --selftest
```

## Edition Comparison: Free (`$0`) vs Kintsugi Pro (`v1.7.0` on Agensi.io & GitHub Releases)

| Feature / Capability | Core Guard Free (`$0`) | Tier 1: FinOps & Reliability Pro (`$15`) | Tier 2: Zero-Trust & MCP Shield Pro (`$19`) | Tier 3: Enterprise Complete Pro (`$29`) |
| :--- | :---: | :---: | :---: | :---: |
| **Multi-Model Co-Execution (`--co-run`)** | **Locked: `Primary + 1 Free Model`** | **Unlocked: `Primary + 2..5 Free Models`** | **Unlocked: `Primary + 2..5 Free Models`** | **Unlocked: `Primary + 5 Free + 6-Seat BYOK Paid Council`** |
| **`@LOGIC/2` 5-Pillar Reasoning & `@PROOF_DAG/1` Signed Compliance** | Included (`LOCAL_DEV_ATTESTATION`) | Included (`+ FinOps Policies`) | Included (`+ AppSec/MCP Policies`) | **Included (`ENTERPRISE_PROVISIONED_SEAL` SOC2/ISO/EU-AI-Act)** |
| **Curated Core + Exclusive Pro Scars** | 16 Core (`KS-001..016`) | 11 FinOps/Reliability (`KS-018,025,026,030,031` + Core) | 21 AppSec/MCP (`KS-017,019..024,027..029,032` + Core) | **All 32/32 (`KS-001..KS-032`)** |
| **`@KML/1` Evolved Machine-Language Wire (`scars.kml`)** | 16 rules | **844 `@KML/1` rules** | **862 `@KML/1` rules** | **All 1,742 `@KML/1` rules** |
| **Deterministic Auto-Fix Codemods (`kintsugi autofix --apply`)** | — (Scan only) | **4 Auto-Fix Codemods** | **8 Auto-Fix Codemods** | **All 12/12 Auto-Fix Codemods** |
| **Interactive Slash Commands (`.claude/commands/*.md`)** | — | 5 Slash Workflows | 5 Slash Workflows | **5 Slash Workflows** |
| **Frontier Collective Pool Lessons (`collective_pool_lessons.json`)** | — | 41 Frontier Lessons | 41 Frontier Lessons | **41 Frontier Lessons** |
| **Delivery Formats** | `.zip` | `.zip` + Encrypted `.kpack` | `.zip` + Encrypted `.kpack` | **`.zip` + Encrypted `.kpack`** |
