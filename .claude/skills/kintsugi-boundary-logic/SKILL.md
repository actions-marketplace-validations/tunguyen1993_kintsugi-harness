---
name: kintsugi-boundary-logic
description: "Focused boundary-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["binary-search-overflow", "cursor-pagination", "gemini38-deepseek", "half-open-interval", "interval-closure", "kml:v1", "logic-evolution", "sliding-window", "tie-breaker-key"]
---

# kintsugi-boundary-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-010` · `@OP/1[ID:KS-LOGIC-010|SEV:HIGH|CAT:boundary-logic|LANG:py|OP:TIMESTAMP_ONLY_PAGINATION->COMPOSITE]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-010|sev=H|cat=boundary-logic|lang=py|op=TIMESTAMP_ONLY_PAGINATION->COMPOSITE|guard=RX#fcbcb2ca|neg=«rows = db.query('SELECT * FROM events WHERE created_at > ? ORDER BY created_at LIMIT 100',»|pos=«rows = db.query('SELECT * FROM events WHERE (created_at, id) > (?, ?) ORDER BY created_at,»|fp=230cf0357ce9c1f7`
- `@TRAP`: `@TRAP/1{guard:RX#fcbcb2ca,fault:BOUNDARY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,cursor-pagination,tie-breaker-key,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:rows_db.query_SELECT_FROM_events_WHERE_creat,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
rows = db.query('SELECT * FROM events WHERE created_at > ? ORDER BY created_at LIMIT 100', [last_ts])  # NON_UNIQUE_TIMESTAMP_PAGINATION_SKIP
```

`@POS_AST` (`✅ REQUIRED`):
```python
rows = db.query('SELECT * FROM events WHERE (created_at, id) > (?, ?) ORDER BY created_at, id LIMIT 100', [last_ts, last_id])
```

### `KS-LOGIC-012` · `@OP/1[ID:KS-LOGIC-012|SEV:HIGH|CAT:boundary-logic|LANG:py|OP:INCLUSIVE_BOTH_ENDS_CHUNKING->HALF_O]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-012|sev=H|cat=boundary-logic|lang=py|op=INCLUSIVE_BOTH_ENDS_CHUNKING->HALF_O|guard=RX#8a6ff049|neg=«chunks = [items[i : i + step + 1] for i in range(0, len(items), step)]  # OVERLAPPING_CHUN»|pos=«chunks = [items[i : i + step] for i in range(0, len(items), step)]»|fp=c77a2751ee536f99`
- `@TRAP`: `@TRAP/1{guard:RX#8a6ff049,fault:BOUNDARY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,sliding-window,half-open-interval,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:chunks_items_i_:_i_+_step_for_i_in_range_0,_,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
chunks = [items[i : i + step + 1] for i in range(0, len(items), step)]  # OVERLAPPING_CHUNK_BOUNDARY_DUPLICATION
```

`@POS_AST` (`✅ REQUIRED`):
```python
chunks = [items[i : i + step] for i in range(0, len(items), step)]
```

### `KS-LOGIC-011` · `@OP/1[ID:KS-LOGIC-011|SEV:MEDIUM|CAT:boundary-logic|LANG:py|OP:UNPROGRESSED_BINARY_SEARCH_MID->STRI]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-011|sev=M|cat=boundary-logic|lang=py|op=UNPROGRESSED_BINARY_SEARCH_MID->STRI|guard=RX#3fd89db4|neg=«while lo < hi: ; mid = (lo + hi) // 2 ; if check(mid): ; lo = mid  # BINARY_SEARCH_INFINIT»|pos=«while lo < hi: ; mid = (lo + hi + 1) // 2 ; if check(mid): ; lo = mid ; else: ; hi = mid -»|fp=1d1710060a49351d`
- `@TRAP`: `@TRAP/1{guard:RX#3fd89db4,fault:BOUNDARY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,binary-search-overflow,interval-closure,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:while_lo_hi:,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
while lo < hi:
    mid = (lo + hi) // 2
    if check(mid):
        lo = mid  # BINARY_SEARCH_INFINITE_BOUND_STALL
    else:
        hi = mid - 1
```

`@POS_AST` (`✅ REQUIRED`):
```python
while lo < hi:
    mid = (lo + hi + 1) // 2
    if check(mid):
        lo = mid
    else:
        hi = mid - 1
```
