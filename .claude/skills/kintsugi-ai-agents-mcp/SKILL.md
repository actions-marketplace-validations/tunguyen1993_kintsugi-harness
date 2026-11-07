---
name: kintsugi-ai-agents-mcp
description: "Focused ai-agents-mcp anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["agent-loop", "agent-recovery", "ai-agents-mcp", "anti-downgrade", "anti-sycophancy", "ast-quotient", "bft-consensus", "brier-second-moment", "claude-api", "covariance-bft"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-ai-agents-mcp (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-HIGH-001` · `No Unsupported Promotion Across Scopes or Evidence Types (Lakatosian CEGIS, 4-State Symbolic Path & Brier Second-Moment Guard)`
- `@WIRE`: `@KML/1|id=KL-HIGH-001|sev=C|cat=ai-agents-mcp|lang=py|op=NO_UNSUPPORTED_PROMOTION_ACROSS_SCOP|guard=RX#b0891781|neg=«status = 'PROVED' if empirical_vote_prob > 0.99 or len(retained_domain_errors) == 0 else '»|pos=«cert = enforce_kl_high_001_promotion_guard(claim_id, source_scope, target_scope, assumptio»|fp=e86d43cf3ba35440`
- `@TRAP`: `[Cognitive Trap] Upgraded a domain-cut CONDITIONAL claim, an timed-out SURRENDER refutation, an UNKNOWN interval enclosure, a confounded regression, or an empirical ensemble vote (`EMPIRICAL_CONFIDENCE`) into a universal `PROVED` certificate.`
- `@LAW`: `[Mental Model] Carry `(claim_id, scope, assumptions, evidence_lineage, status)` on every output: enforce Lakatosian anti-goalpost-moving (`CONDITIONAL` on domain cuts, `SURRENDER` on incomplete refuter), 4-state outward-rounded symbolic path evaluation (`UNREACHABLE`/`HOLDS`/`VIOLATED`/`UNKNOWN`), moralized ancestral d-separation, and uncentered Brier second-moment shrinkage (`w^T E[e e^T] w`).`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
status = 'PROVED' if empirical_vote_prob > 0.99 or len(retained_domain_errors) == 0 else 'REFUTED'  # UNSUPPORTED_SCOPE_OR_EVIDENCE_PROMOTION
```

`@POS_AST` (`✅ REQUIRED`):
```python
cert = enforce_kl_high_001_promotion_guard(claim_id, source_scope, target_scope, assumptions, lineage, current_status, 'PROVED')
```

### `KL-MCP-007` · `Covariance-Aware Equicorrelation BFT Merge (N_eff), Disjoint Scar Holdout & Alpha-Normalized AST Quotient`
- `@WIRE`: `@KML/1|id=KL-MCP-007|sev=C|cat=ai-agents-mcp|lang=py|op=COVARIANCE-AWARE_EQUICORRELATION_BFT|guard=RX#e3937c51|neg=«n_eff = len(clone_votes)  # CORRELATED_CLONE_INDEPENDENCE_FALLACY»|pos=«n_eff = len(clone_votes) / (1.0 + (len(clone_votes) - 1) * rho_hat)  # Covariance-discount»|fp=f93d8c8eaa1fbc9d`
- `@TRAP`: `[Cognitive Trap] Treated K correlated subagent votes from identical model families as independent (`N_eff = K`), verified synthesized regex scars using the same generator tier without a disjoint paraphrase-mutated negative holdout (`T_gen == T_ver`), or hashed raw AST identifier strings that break under alpha-renaming.`
- `@LAW`: `[Mental Model] Discount correlated votes via Equicorrelation Inverse Log-Odds (`N_eff = K / (1 + (K - 1) * rho_hat)`), enforce `DisjointScarHoldoutVerifier` (`T_gen != T_ver`, `precision >= 0.95`, `0` paraphrase FPs), and verify semantic equivalence via alpha-normalized De Bruijn AST quotient hashes.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
n_eff = len(clone_votes)  # CORRELATED_CLONE_INDEPENDENCE_FALLACY
```

`@POS_AST` (`✅ REQUIRED`):
```python
n_eff = len(clone_votes) / (1.0 + (len(clone_votes) - 1) * rho_hat)  # Covariance-discounted N_eff
```

### `KL-MCP-006` · `Shadow-Clone Parallel Epistemic Swarm & BFT Synaptic Merge (K=3f+1 Quorum)`
- `@WIRE`: `@KML/1|id=KL-MCP-006|sev=C|cat=ai-agents-mcp|lang=py|op=SHADOW-CLONE_PARALLEL_EPISTEMIC_SWAR|guard=RX#8ddb8c6f|neg=«playbook = subagents[0].unverified_draft_conclusion  # UNGROUNDED_SINGLE_CLONE_ACCEPT»|pos=«playbook = bft_merge_clones(clone_reports, quorum_threshold=3)  # K=3f+1 verified quorum»|fp=d011e508028c224b`
- `@TRAP`: `[Cognitive Trap] Allowed parallel subagents to share intermediate drafts before independent grounding or accepted a single unverified subagent conclusion without a Byzantine-tolerant quorum (`s_p >= 3` of `K=4`).`
- `@LAW`: `[Mental Model] Enforce orthogonal clone tracks with zero inter-clone communication during exploration, ground every clone proposition via the <5ms 3-State Gate + Counterfactual Sandbox, quarantine refuted traps into a Negative Tabu List, and merge only propositions achieving `s_p >= 3` quorum (`K=3f+1`).`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
playbook = subagents[0].unverified_draft_conclusion  # UNGROUNDED_SINGLE_CLONE_ACCEPT
```

`@POS_AST` (`✅ REQUIRED`):
```python
playbook = bft_merge_clones(clone_reports, quorum_threshold=3)  # K=3f+1 verified quorum
```

### `KL-MCP-001` · `Strip bidirectional Unicode overrides in MCP tool inputs and prompts (CVE-2021-42574)`
- `@WIRE`: `@KML/1|id=KL-MCP-001|sev=C|cat=ai-agents-mcp|lang=py,ts,js|op=STRIP_BIDIRECTIONAL_UNICODE_OVERRIDE|guard=RX#7e5e71d7|neg=«tool_prompt = "Summarize file‮"  # hidden RLO char»|pos=«tool_prompt = "Summarize file" ; assert not any(0x202A <= ord(c) <= 0x202E for c in tool_p»|fp=d2d09181df34d9ca`
- `@TRAP`: `[Cognitive Trap] Assumed visually inspected strings in MCP tool arguments or skill files match the byte stream interpreted by the LLM and runtime.`
- `@LAW`: `[Mental Model] Invisible Unicode Bidi overrides (U+202A..U+202E, U+2066..U+2069) invert token order visually while executing hidden directives; reject them at the ingestion boundary.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
tool_prompt = "Summarize file‮"  # hidden RLO char
```

`@POS_AST` (`✅ REQUIRED`):
```python
tool_prompt = "Summarize file"
assert not any(0x202A <= ord(c) <= 0x202E for c in tool_prompt)
```

### `KL-MCP-002` · `Enforce hard iteration and token ceilings on autonomous agent tool loops`
- `@WIRE`: `@KML/1|id=KL-MCP-002|sev=H|cat=ai-agents-mcp|lang=py|op=ENFORCE_HARD_ITERATION_AND_TOKEN_CEI|guard=RX#2106e642|neg=«while True:  # UNBOUNDED_AGENT_LOOP ; response = step_agent()»|pos=«for step in range(MAX_AGENT_STEPS): ; response = step_agent()»|fp=6494c41976f46a69`
- `@TRAP`: `[Cognitive Trap] Wrote `while True:` around an LLM tool-calling loop assuming the model will always emit a final stop token.`
- `@LAW`: `[Mental Model] When an upstream tool returns a transient error, LLMs frequently enter infinite retry oscillations; every agent loop must be bounded by `range(MAX_STEPS)`.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
while True:  # UNBOUNDED_AGENT_LOOP
    response = step_agent()
```

`@POS_AST` (`✅ REQUIRED`):
```python
for step in range(MAX_AGENT_STEPS):
    response = step_agent()
```

### `KL-MCP-005` · `Anti-Silent-Model-Downgrade Gate: Verify upstream routed model identity instead of masking with fallback`
- `@WIRE`: `@KML/1|id=KL-MCP-005|sev=H|cat=ai-agents-mcp|lang=py|op=ANTI-SILENT-MODEL-DOWNGRADE_GATE_VER|guard=RX#d207e8c7|neg=«model_used = response_data.get("model") or target_frontier_model  # SILENT_MODEL_DOWNGRADE»|pos=«reported = str(response_data.get("model") or "") ; assert reported.startswith(expected_fam»|fp=95e899177000b8a7`
- `@TRAP`: `[Cognitive Trap] Wrote `model_used = data.get('model') or requested_model`, silently attributing a low-tier 20B/mini fallback response to a requested Frontier reasoning model.`
- `@LAW`: `[Mental Model] Proxy gateways frequently substitute cheaper models under load; explicitly verify that `data.get('model')` is present and matches the requested Frontier family before trusting high-stakes reasoning output.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
model_used = response_data.get("model") or target_frontier_model  # SILENT_MODEL_DOWNGRADE_MASK
```

`@POS_AST` (`✅ REQUIRED`):
```python
reported = str(response_data.get("model") or "")
assert reported.startswith(expected_family), f"Unexpected routed model: {reported}"
```

### `KL-MCP-003` · `Return structured isError=True MCP tool responses instead of raising raw unhandled exceptions`
- `@WIRE`: `@KML/1|id=KL-MCP-003|sev=H|cat=ai-agents-mcp|lang=py,ts|op=RETURN_STRUCTURED_ISERROR_TRUE_MCP_T|guard=RX#f73af1d8|neg=«raise RuntimeError("MCP_RAW_UNHANDLED_TOOL_ERROR: rate limit exceeded")»|pos=«return {"isError": True, "content": [{"type": "text", "text": "Rate limit exceeded; retry »|fp=c302664641493626`
- `@TRAP`: `[Cognitive Trap] Raised raw unhandled runtime exceptions inside an MCP tool handler assuming the host client will format them into actionable guidance for the LLM.`
- `@LAW`: `[Mental Model] Harvested from anthropics/skills (mcp-builder): MCP tools must return structured `isError: True` payloads with actionable recovery hints so the calling agent can self-correct without crashing the transport.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
raise RuntimeError("MCP_RAW_UNHANDLED_TOOL_ERROR: rate limit exceeded")
```

`@POS_AST` (`✅ REQUIRED`):
```python
return {"isError": True, "content": [{"type": "text", "text": "Rate limit exceeded; retry after 5s with smaller page_size."}]}
```

### `KL-MCP-004` · `Enable prompt caching (cache_control ephemeral) on static system instructions and tool catalogs`
- `@WIRE`: `@KML/1|id=KL-MCP-004|sev=M|cat=ai-agents-mcp|lang=py,ts|op=ENABLE_PROMPT_CACHING_CACHE_CONTROL_|guard=RX#fa5d8899|neg=«system_blocks = [{"type": "text", "text": STATIC_AGENT_CONSTITUTION}]  # MISSING_PROMPT_CA»|pos=«system_blocks = [{"type": "text", "text": STATIC_AGENT_CONSTITUTION, "cache_control": {"ty»|fp=eac9d0cb43fa591f`
- `@TRAP`: `[Cognitive Trap] Sent the full 20,000-token system prompt and MCP tool schema un-cached on every multi-turn agent step, paying 10x input token costs.`
- `@LAW`: `[Mental Model] Harvested from anthropics/skills (claude-api): Mark static system prompts and tool definitions with `cache_control: {'type': 'ephemeral'}` to cut repeated input token latency and cost by up to 90%.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
system_blocks = [{"type": "text", "text": STATIC_AGENT_CONSTITUTION}]  # MISSING_PROMPT_CACHE
```

`@POS_AST` (`✅ REQUIRED`):
```python
system_blocks = [{"type": "text", "text": STATIC_AGENT_CONSTITUTION, "cache_control": {"type": "ephemeral"}}]
```
