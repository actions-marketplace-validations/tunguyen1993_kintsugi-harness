---
name: kintsugi-core-guard-free
description: Open-source deterministic verification guard for AI coding agents (Claude Code, Cursor, Codex CLI, Gemini CLI, OpenClaw). Enforces @KML/1 AST-IR guardrails, @LOGIC/2 5-Pillar Neuro-Symbolic Verification, @PROOF_DAG/1 Compliance Proofs, and @CREED/1 Autopoietic Evolution.
version: 2.0.0
tier: free
price_usd: 0
license: Apache-2.0
repository: https://github.com/tunguyen1993/kintsugi-harness/tree/opensource/free-skill-pack
---

# @SKILL_PACK_IR/1 [KINTSUGI_CORE_GUARD_FREE_V2_0_0]

```text
@META[pack="kintsugi-core-guard-free" | ver="2.0.0" | tier="FREE_STARTER ($0)" | license="Apache-2.0"]
@GATES[
  KL-GROUND-001: "Refuse unverified 'not found' or 'all tests pass' claims without exit_code==0 & sweep counts"
  KL-FINOPS-001: "Circuit-break repetitive tool-call loops & enforce per-task token/cost budgets"
  KL-SEC-001:    "Block pickle RCE (require weights_only=True), SSRF (169.254.169.254), and Bidi Trojan Source"
  LOGIC_2:       "DPLL SAT/MUS + Stratified Datalog ProofDAG/1 + Exact Rational Difference Logic + @FALLACY_GUARD/1 + MHS Abduction"
  AST_LITE_V2:   "Zero-dependency Structural AST-Lite across Python, JS/TS, Go, and Rust (strips comments/strings, indexes symbols & calls)"
  CREED_1:       "P1:MUTATE(fail>=2->pivot) | P2:SYNTH(manual>=2->1step_tool) | P3:SCAR(bug->rule) | P4:PRUNE(overwrite_verbose)"
]
@SELFTEST[cmd="python3 scripts/kintsugi_free_quickstart.py --selftest"]
```

## @EDITION_MATRIX/1 (`Free $0` vs `Pro $15/$19` vs `Enterprise $29`)

| Capability | Core Guard Free (`$0`) | Tier 1 FinOps Pro (`$15`) | Tier 2 Zero-Trust Pro (`$19`) | Tier 3 Enterprise (`$29`) |
| :--- | :---: | :---: | :---: | :---: |
| `CO_EXECUTION` | `Primary + 1 Free` | `Primary + 2..5 Free` | `Primary + 2..5 Free` | `Primary + 5 Free + 6 BYOK Paid` |
| `PROOF_DAG_1` | `LOCAL_DEV_ATTESTATION` | `+ FinOps Policies` | `+ AppSec/MCP Policies` | `ENTERPRISE_PROVISIONED_SEAL` |
| `SCARS` | `KS-001..016` (16) | `KS-018,025,026,030,031` + Core | `KS-017,019..024,027..029,032` + Core | `KS-001..KS-032` (32/32) |
| `KML_1_WIRE` | `16` rules | `844` rules | `862` rules | `1,742` rules |
| `AUTOFIX` | Scan only | `4` codemods | `8` codemods | `12/12` codemods |
