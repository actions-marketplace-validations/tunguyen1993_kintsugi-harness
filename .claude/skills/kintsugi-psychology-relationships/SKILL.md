---
name: kintsugi-psychology-relationships
description: "Focused psychology-relationships anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["attraction", "communication", "conflict-resolution", "dating-social", "emotional-intelligence", "leadership", "model:claude-frontier", "model:grok-frontier", "pillar:life-and-business", "psychology"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-psychology-relationships (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-PSY-001` · `Emotional Calibration & Anti-Chasing: Never send needy double/triple follow-ups when counterpart investment drops`
- `@WIRE`: `@KML/1|id=KL-PSY-001|sev=H|cat=psychology-relationships|lang=deci,mark|op=EMOTIONAL_CALIBRATION_ANTI-CHASING_N|guard=RX#ed752601|neg=«MESSAGE_ACTION: SEND_NEEDY_TRIPLE_TEXT(consecutive_unanswered=3, tone='anxious_validation_»|pos=«MESSAGE_ACTION: HOLD_COMPOSURED_SILENCE(consecutive_unanswered=1, focus='personal_mission_»|fp=63a0c8e5435a7131`
- `@TRAP`: `[Cognitive Trap] Felt anxious when a romantic interest or high-value contact took hours to reply, sending multiple needy check-in texts ('Why are you ignoring me???').`
- `@LAW`: `[Mental Model] Attraction and respect require balanced investment velocity (`ping-pong reciprocity`). Chasing silence with needy pressure destroys perceived status; mirror their pace and stay grounded in your own mission.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
MESSAGE_ACTION: SEND_NEEDY_TRIPLE_TEXT(consecutive_unanswered=3, tone='anxious_validation_seeking')
```

`@POS_AST` (`✅ REQUIRED`):
```decision
MESSAGE_ACTION: HOLD_COMPOSURED_SILENCE(consecutive_unanswered=1, focus='personal_mission_and_reciprocity')
```

### `KL-PSY-002` · `Conflict De-escalation: Enforce a cool-down pause and replace 'You always/never' accusations with factual observations`
- `@WIRE`: `@KML/1|id=KL-PSY-002|sev=M|cat=psychology-relationships|lang=deci,mark|op=CONFLICT_DE-ESCALATION_ENFORCE_A_COO|guard=RX#9d75308d|neg=«CONFLICT_REPLY: SEND_IMMEDIATELY_WHILE_ANGRY(phrasing='You always ruin everything')»|pos=«CONFLICT_REPLY: PAUSE_AND_STATE_OBSERVATION(cooldown_minutes=30, phrasing='When X happened»|fp=1ea272d261ae0555`
- `@TRAP`: `[Cognitive Trap] Replied immediately while angry using absolute character attacks ('You always ruin everything'), triggering amygdala defensiveness in the other person.`
- `@LAW`: `[Mental Model] During emotional spikes, prefrontal reasoning is offline. Enforce a mandatory cool-down interval and frame feedback around specific observable events and shared solutions.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
CONFLICT_REPLY: SEND_IMMEDIATELY_WHILE_ANGRY(phrasing='You always ruin everything')
```

`@POS_AST` (`✅ REQUIRED`):
```decision
CONFLICT_REPLY: PAUSE_AND_STATE_OBSERVATION(cooldown_minutes=30, phrasing='When X happened, it impacted Y; let us align on Z')
```
