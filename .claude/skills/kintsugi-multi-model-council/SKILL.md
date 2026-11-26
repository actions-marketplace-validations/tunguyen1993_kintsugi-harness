---
name: kintsugi-multi-model-council
description: "Machine-Native Spec (@GUIDE/1 + @COMPACT/1) for Kintsugi 100% Apache-2.0 Offline-First Guardrails, Optional BYOK Multi-Model Co-Review, and Zero-Loss Anti-Overflow Compaction."
tags: ["multi-model", "byok", "council", "onboarding", "user-guide", "anti-overflow", "compact"]
---

# `@GUIDE/1` & `@COMPACT/1` Machine-Native Skill Spec

```text
@DISPATCH[on_user_question="kintsugi guide \"<user_question>\"" | on_overflow="kintsugi compact --inject-agents"]
@MODES[
  OFFLINE_DEFAULT: "100% Apache-2.0 local Rust + Python static guardrails, 7-domain prover, and MCP server (zero API keys required)"
  BYOK_CO_REVIEW:  "Optional user-supplied official API keys (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, DEEPSEEK_API_KEY) for multi-model second-opinion review"
  CLOUD_SANDBOX:   "Standalone Python 3.9+ stdlib edition in cloud-sandbox/ with pinned SHA-256 bootstrap and 2-process OS IPC Truth Gate"
]
@BYOK_COMMANDS[
  store:  ".kintsugi/paid_council_pool.json (chmod 0600, local-only, masked)"
  add:    "kintsugi swarm --add-paid-key <openai|anthropic|gemini|deepseek> <API_KEY>"
  status: "kintsugi swarm --paid-council-status"
  exec:   "kintsugi swarm . --co-run --paid-council"
]
@COMPACT_PROTOCOL[
  watermarks: "soft>=70% | hard>=85%"
  strip:      "verbose_logs, polling_loops, superseded_reads, thinking_chaff"
  preserve:   "@USER_INTENTS, @HARD_ANCHORS, @ERRORS_AND_FIXES"
  commands:   "kintsugi compact --inject-agents | kintsugi compact --wire"
]
```
