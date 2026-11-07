---
name: kintsugi-multi-model-council
description: "Machine-Native Spec (@GUIDE/1 + @COMPACT/1) for Kintsugi 3-Tier Multi-Model Co-Execution (FREE_STARTER, PRO_MULTI_FREE, ENTERPRISE_PAID_COUNCIL), BYOK Paid Council, and Zero-Loss Anti-Overflow Compaction."
tags: ["multi-model", "byok", "council", "onboarding", "user-guide", "anti-overflow", "compact"]
---

# `@GUIDE/1` & `@COMPACT/1` Machine-Native Skill Spec

```text
@DISPATCH[on_user_question="kintsugi guide \"<user_question>\"" | on_overflow="kintsugi compact --inject-agents"]
@TIERS[
  FREE_STARTER:            "$0 | max_free_co_runners=1 | kintsugi swarm --register-deepseek-free && kintsugi swarm . --co-run"
  PRO_MULTI_FREE:          "$15/$19 | max_free_co_runners=5 | kintsugi install-pack <pro.kpack> --license-key <KEY> && kintsugi swarm . --co-run --free-runners 5"
  ENTERPRISE_PAID_COUNCIL: "$29 | 5 Free + 6 BYOK Paid | kintsugi install-pack <ent.kpack> --license-key <KEY>"
]
@BYOK_COMMANDS[
  store:  ".kintsugi/paid_council_pool.json (chmod 0600, local-only, masked)"
  add:    "kintsugi swarm --add-paid-key <anthropic_opus|openai_frontier|xai_grok_paid|google_gemini_paid|deepseek_paid> <API_KEY>"
  status: "kintsugi swarm --paid-council-status"
  exec:   "kintsugi swarm . --co-run --free-runners 5 --paid-council"
]
@COMPACT_PROTOCOL[
  watermarks: "soft>=70% | hard>=85%"
  strip:      "verbose_logs, polling_loops, superseded_reads, thinking_chaff"
  preserve:   "@USER_INTENTS, @HARD_ANCHORS, @ERRORS_AND_FIXES"
  commands:   "kintsugi compact --inject-agents | kintsugi compact --wire"
]
```
