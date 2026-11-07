---
name: kintsugi-business-negotiation
description: "Focused business-negotiation anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["anchoring", "b2b-sales", "business-negotiation", "model:claude-frontier", "model:grok-frontier", "negotiation", "pillar:life-and-business", "pricing", "pricing-psychology", "sales"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-business-negotiation (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-BIZ-001` · `Anti-Scope-Creep Gate: Bind every out-of-scope client request to a written change order and fee/timeline delta`
- `@WIRE`: `@KML/1|id=KL-BIZ-001|sev=H|cat=business-negotiation|lang=deci,mark,cont|op=ANTI-SCOPE-CREEP_GATE_BIND_EVERY_OUT|guard=RX#4ac2378b|neg=«RESPONSE: ACCEPT_UNBILLED_SCOPE_ADDITION(extra_deliverables=True, fee_delta=0)»|pos=«RESPONSE: PROPOSE_CHANGE_ORDER(extra_deliverables=True, fee_delta=1500, timeline_extension»|fp=92ba7b0b6fa4ca84`
- `@TRAP`: `[Cognitive Trap] Said 'Sure, we can throw in that extra module for free' to please a client during delivery, eroding project margin and delaying core milestones.`
- `@LAW`: `[Mental Model] Unpriced concessions train clients that your time has zero marginal cost. Always welcome new ideas warmly while anchoring them to a formal Change Order (`CHANGE_ORDER_WITH_FEE_AND_TIMELINE`).`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
RESPONSE: ACCEPT_UNBILLED_SCOPE_ADDITION(extra_deliverables=True, fee_delta=0)
```

`@POS_AST` (`✅ REQUIRED`):
```decision
RESPONSE: PROPOSE_CHANGE_ORDER(extra_deliverables=True, fee_delta=1500, timeline_extension_days=5)
```

### `KL-BIZ-002` · `Never volunteer a unilateral price discount before establishing ROI and receiving a concrete counter-commitment`
- `@WIRE`: `@KML/1|id=KL-BIZ-002|sev=H|cat=business-negotiation|lang=deci,mark|op=NEVER_VOLUNTEER_A_UNILATERAL_PRICE_D|guard=RX#71d443c5|neg=«PITCH: UNILATERAL_PREEMPTIVE_DISCOUNT(discount_pct=40, counter_commitment=None)»|pos=«PITCH: ANCHOR_VALUE_WITH_QUID_PRO_QUO(discount_pct=15, counter_commitment='annual_upfront_»|fp=aba7ebc96be0dd2a`
- `@TRAP`: `[Cognitive Trap] Offered an immediate 40% discount in the first outreach message out of fear that the prospect might find the full price too high.`
- `@LAW`: `[Mental Model] Pre-emptive discounting signals low confidence in product value. Anchor on quantified ROI first; if trading price down, always extract a concrete quid-pro-quo (annual prepay, case study, or volume commitment).`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
PITCH: UNILATERAL_PREEMPTIVE_DISCOUNT(discount_pct=40, counter_commitment=None)
```

`@POS_AST` (`✅ REQUIRED`):
```decision
PITCH: ANCHOR_VALUE_WITH_QUID_PRO_QUO(discount_pct=15, counter_commitment='annual_upfront_and_case_study')
```
