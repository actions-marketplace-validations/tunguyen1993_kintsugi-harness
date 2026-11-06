---
name: kintsugi-concurrency-logic
description: "Focused concurrency-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["asyncio-toctou", "await-interleaving", "background-task-gc", "canonical-lock-sort", "gemini38-deepseek", "kml:v1", "lock-order-deadlock", "logic-evolution", "task-orphan"]
---

# kintsugi-concurrency-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-004` · `@OP/1[ID:KS-LOGIC-004|SEV:CRITICAL|CAT:concurrency-logic|LANG:py|OP:CHECK_THEN_AWAIT_MUTATE->ASYNC_LOCK]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-004|sev=C|cat=concurrency-logic|lang=py|op=CHECK_THEN_AWAIT_MUTATE->ASYNC_LOCK|guard=RX#e3f29dd6|neg=«if quota_remaining >= cost: ; await verify_remote_policy(user_id)  # ASYNC_AWAIT_TOCTOU_IN»|pos=«async with quota_lock: ; if quota_remaining >= cost: ; await verify_remote_policy(user_id)»|fp=07bacf73780df5a1`
- `@TRAP`: `@TRAP/1{guard:RX#e3f29dd6,fault:CONCURRENCY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,asyncio-toctou,await-interleaving,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:async_with_quota_lock:,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if quota_remaining >= cost:
    await verify_remote_policy(user_id)  # ASYNC_AWAIT_TOCTOU_INTERLEAVING
    quota_remaining -= cost
```

`@POS_AST` (`✅ REQUIRED`):
```python
async with quota_lock:
    if quota_remaining >= cost:
        await verify_remote_policy(user_id)
        quota_remaining -= cost
```

### `KS-LOGIC-005` · `@OP/1[ID:KS-LOGIC-005|SEV:HIGH|CAT:concurrency-logic|LANG:py|OP:UNREFERENCED_CREATE_TASK->STRONG_REF]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-005|sev=H|cat=concurrency-logic|lang=py|op=UNREFERENCED_CREATE_TASK->STRONG_REF|guard=RX#92fc4754|neg=«asyncio.create_task(flush_audit_batch(records))  # UNREFERENCED_ASYNCIO_CREATE_TASK_GC»|pos=«task = asyncio.create_task(flush_audit_batch(records)) ; background_tasks.add(task) ; task»|fp=019d5e138d503712`
- `@TRAP`: `@TRAP/1{guard:RX#92fc4754,fault:CONCURRENCY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,task-orphan,background-task-gc,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:task_asyncio.create_task_flush_audit_batch_r,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
asyncio.create_task(flush_audit_batch(records))  # UNREFERENCED_ASYNCIO_CREATE_TASK_GC
```

`@POS_AST` (`✅ REQUIRED`):
```python
task = asyncio.create_task(flush_audit_batch(records))
background_tasks.add(task)
task.add_done_callback(background_tasks.discard)
```

### `KS-LOGIC-006` · `@OP/1[ID:KS-LOGIC-006|SEV:HIGH|CAT:concurrency-logic|LANG:py|OP:UNORDERED_DUAL_LOCK_ACQUIRE->CANONIC]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-006|sev=H|cat=concurrency-logic|lang=py|op=UNORDERED_DUAL_LOCK_ACQUIRE->CANONIC|guard=RX#516e9b11|neg=«with lock_map[src_id], lock_map[dst_id]:  # AB_BA_LOCK_INVERSION_DEADLOCK ; transfer_units»|pos=«first_id, second_id = sorted((src_id, dst_id)) ; with lock_map[first_id], lock_map[second_»|fp=bd1422d6aa487cff`
- `@TRAP`: `@TRAP/1{guard:RX#516e9b11,fault:CONCURRENCY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,lock-order-deadlock,canonical-lock-sort,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:first_id,_second_id_sorted_src_id,_dst_id,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
with lock_map[src_id], lock_map[dst_id]:  # AB_BA_LOCK_INVERSION_DEADLOCK
    transfer_units(src_id, dst_id, qty)
```

`@POS_AST` (`✅ REQUIRED`):
```python
first_id, second_id = sorted((src_id, dst_id))
with lock_map[first_id], lock_map[second_id]:
    transfer_units(src_id, dst_id, qty)
```
