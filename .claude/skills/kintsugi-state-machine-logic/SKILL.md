---
name: kintsugi-state-machine-logic
description: "Focused state-machine-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["duplicate-payout", "gemini38-deepseek", "idempotency", "kml:v1", "logic-evolution", "monotonic-version", "out-of-order-event", "retry-idempotency", "state-machine"]
---

# kintsugi-state-machine-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-001` · `@OP/1[ID:KS-LOGIC-001|SEV:CRITICAL|CAT:state-machine-logic|LANG:py|OP:NON_ATOMIC_STATE_MUTATION->COMPARE_A]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-001|sev=C|cat=state-machine-logic|lang=py|op=NON_ATOMIC_STATE_MUTATION->COMPARE_A|guard=RX#1702b294|neg=«if order.status == 'PENDING':  # NON_ATOMIC_STATE_TRANSITION ; order.status = 'PAID' ; set»|pos=«if atomic_compare_and_swap(order, expected='PENDING', target='PAID'): ; settle_ledger(orde»|fp=204f24f3c1ccaea8`
- `@TRAP`: `@TRAP/1{guard:RX#1702b294,fault:STATE-MACHINE-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,state-machine,idempotency,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_atomic_compare_and_swap_order,_expected_P,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if order.status == 'PENDING':  # NON_ATOMIC_STATE_TRANSITION
    order.status = 'PAID'
     settle_ledger(order)
```

`@POS_AST` (`✅ REQUIRED`):
```python
if atomic_compare_and_swap(order, expected='PENDING', target='PAID'):
    settle_ledger(order)
```

### `KS-LOGIC-002` · `@OP/1[ID:KS-LOGIC-002|SEV:HIGH|CAT:state-machine-logic|LANG:py|OP:UNKEYED_RETRY_DISPATCH->IDEMPOTENCY]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-002|sev=H|cat=state-machine-logic|lang=py|op=UNKEYED_RETRY_DISPATCH->IDEMPOTENCY|guard=RX#de887c65|neg=«for attempt in range(max_retries): ; resp = post_webhook(payload)  # UNKEYED_RETRY_SIDE_EF»|pos=«for attempt in range(max_retries): ; resp = post_webhook(payload, idempotency_key= derive_»|fp=8fbafb3c85dc067c`
- `@TRAP`: `@TRAP/1{guard:RX#de887c65,fault:STATE-MACHINE-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,retry-idempotency,duplicate-payout,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:for_attempt_in_range_max_retries_:,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
for attempt in range(max_retries):
    resp = post_webhook(payload)  # UNKEYED_RETRY_SIDE_EFFECT
```

`@POS_AST` (`✅ REQUIRED`):
```python
for attempt in range(max_retries):
    resp = post_webhook(payload, idempotency_key= derive_idempotency_key(payload))
```

### `KS-LOGIC-003` · `@OP/1[ID:KS-LOGIC-003|SEV:HIGH|CAT:state-machine-logic|LANG:py|OP:fn:apply_event!enforce_invariant]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-003|sev=H|cat=state-machine-logic|lang=py|op=fn:apply_event!enforce_invariant|guard=RX#db2b2ff9|neg=«def apply_event(entity, evt): ; entity.balance = evt.new_balance  # STALE_EVENT_OVERWRITE_»|pos=«def apply_event(entity, evt): ; if evt.sequence_id > entity.last_sequence_id: ; entity.bal»|fp=3434110ac9e90140`
- `@TRAP`: `@TRAP/1{guard:RX#db2b2ff9,fault:STATE-MACHINE-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,out-of-order-event,monotonic-version,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:def_apply_event_entity,_evt_:,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
def apply_event(entity, evt):
    entity.balance = evt.new_balance  # STALE_EVENT_OVERWRITE_LOGIC
```

`@POS_AST` (`✅ REQUIRED`):
```python
def apply_event(entity, evt):
    if evt.sequence_id > entity.last_sequence_id:
        entity.balance = evt.new_balance
        entity.last_sequence_id = evt.sequence_id
```
