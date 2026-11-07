---
name: kintsugi-decision-strategy
description: "Focused decision-strategy anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["anti-overengineering", "architecture", "decision-strategy", "discernment", "mental-models", "model:claude-frontier", "model:gpt-6-frontier", "one-way-door", "pillar:life-and-business", "pre-mortem"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-decision-strategy (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-DEC-002` · `Anti-Over-Engineering Gate: Reject speculative abstractions, kitchen-sink wrappers, and unrequested features`
- `@WIRE`: `@KML/1|id=KL-DEC-002|sev=H|cat=decision-strategy|lang=deci,py,mark|op=ANTI-OVER-ENGINEERING_GATE_REJECT_SP|guard=RX#0ed9cfa1|neg=«ARCHITECTURE: CREATE_SPECULATIVE_KITCHEN_SINK_ABSTRACTION(unrequested_features=10)»|pos=«ARCHITECTURE: IMPLEMENT_MINIMAL_DETERMINISTIC_SOLUTION(unrequested_features=0)»|fp=f8cba14ca3b08db6`
- `@TRAP`: `[Cognitive Trap] Built an abstract 5-layer factory framework and 12 speculative config flags for a problem that only needed one deterministic 20-line function.`
- `@LAW`: `[Mental Model] Harvested from patrickjs/awesome-cursorrules (anti-overengineering): Complexity is a permanent maintenance tax. Solve only what was asked with the simplest deterministic mechanism first.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
ARCHITECTURE: CREATE_SPECULATIVE_KITCHEN_SINK_ABSTRACTION(unrequested_features=10)
```

`@POS_AST` (`✅ REQUIRED`):
```decision
ARCHITECTURE: IMPLEMENT_MINIMAL_DETERMINISTIC_SOLUTION(unrequested_features=0)
```

### `KL-DEC-001` · `One-Way Door Pre-Mortem Gate: Require explicit downside bounds and kill-criteria before irreversible decisions`
- `@WIRE`: `@KML/1|id=KL-DEC-001|sev=H|cat=decision-strategy|lang=deci,mark|op=ONE-WAY_DOOR_PRE-MORTEM_GATE_REQUIRE|guard=RX#6c24936f|neg=«DECISION_COMMIT: EXECUTE_IRREVERSIBLE_ONE_WAY_DOOR(pre_mortem=None, kill_criteria=None)»|pos=«DECISION_COMMIT: EXECUTE_WITH_PRE_MORTEM(max_downside_capped=True, kill_criteria='abort_if»|fp=e7480afe781b04ad`
- `@TRAP`: `[Cognitive Trap] Treated an irreversible Type-1 ('One-Way Door') commitment with the same casual speed as a reversible Type-2 experiment, without defining a pre-mortem or exit trigger.`
- `@LAW`: `[Mental Model] Harvested from anthropics/skills (discernment-nudge): Before executing any irreversible decision, explicitly write down the worst-case downside, key unverified assumptions, and concrete kill-criteria.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
DECISION_COMMIT: EXECUTE_IRREVERSIBLE_ONE_WAY_DOOR(pre_mortem=None, kill_criteria=None)
```

`@POS_AST` (`✅ REQUIRED`):
```decision
DECISION_COMMIT: EXECUTE_WITH_PRE_MORTEM(max_downside_capped=True, kill_criteria='abort_if_metric_below_threshold_at_day_30')
```
