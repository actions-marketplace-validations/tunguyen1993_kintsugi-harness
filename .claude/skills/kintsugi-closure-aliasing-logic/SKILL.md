---
name: kintsugi-closure-aliasing-logic
description: "Focused closure-aliasing-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["gemini38-deepseek", "iterator-exhaustion", "kml:v1", "lambda-capture", "late-binding-closure", "logic-evolution", "matrix-aliasing", "shallow-row-multiplication", "single-pass-generator"]
---

# kintsugi-closure-aliasing-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-013` · `@OP/1[ID:KS-LOGIC-013|SEV:HIGH|CAT:closure-aliasing-logic|LANG:py|OP:LATE_BINDING_LOOP_LAMBDA->DEFAULT_AR]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-013|sev=H|cat=closure-aliasing-logic|lang=py|op=LATE_BINDING_LOOP_LAMBDA->DEFAULT_AR|guard=RX#8c072a29|neg=«handlers = [lambda evt: dispatch(evt, route_id) for route_id in routes]  # LATE_BINDING_LO»|pos=«handlers = [lambda evt, r=route_id: dispatch(evt, r) for route_id in routes]»|fp=5e1472f378d91828`
- `@TRAP`: `@TRAP/1{guard:RX#8c072a29,fault:CLOSURE-ALIASING-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,late-binding-closure,lambda-capture,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:handlers_lambda_evt,_r_route_id:_dispatch_ev,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
handlers = [lambda evt: dispatch(evt, route_id) for route_id in routes]  # LATE_BINDING_LOOP_CLOSURE_CAPTURE
```

`@POS_AST` (`✅ REQUIRED`):
```python
handlers = [lambda evt, r=route_id: dispatch(evt, r) for route_id in routes]
```

### `KS-LOGIC-014` · `@OP/1[ID:KS-LOGIC-014|SEV:HIGH|CAT:closure-aliasing-logic|LANG:py|OP:LIST_MULTIPLY_NESTED_ROW_ALIASING->L]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-014|sev=H|cat=closure-aliasing-logic|lang=py|op=LIST_MULTIPLY_NESTED_ROW_ALIASING->L|guard=RX#eafd5c14|neg=«grid = [[0] * cols] * rows  # ALIASED_NESTED_LIST_MULTIPLICATION»|pos=«grid = [[0] * cols for _ in range(rows)]»|fp=34cfdb56d8bea8f6`
- `@TRAP`: `@TRAP/1{guard:RX#eafd5c14,fault:CLOSURE-ALIASING-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,shallow-row-multiplicati,matrix-aliasing,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:grid_0_cols_for___in_range_rows,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
grid = [[0] * cols] * rows  # ALIASED_NESTED_LIST_MULTIPLICATION
```

`@POS_AST` (`✅ REQUIRED`):
```python
grid = [[0] * cols for _ in range(rows)]
```

### `KS-LOGIC-015` · `@OP/1[ID:KS-LOGIC-015|SEV:MEDIUM|CAT:closure-aliasing-logic|LANG:py|OP:RE_ITERATING_EXHAUSTED_GENERATOR->MA]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-015|sev=M|cat=closure-aliasing-logic|lang=py|op=RE_ITERATING_EXHAUSTED_GENERATOR->MA|guard=RX#a3222e51|neg=«filtered = (x for x in data if x > 0) ; total = sum(filtered) ; count = sum(1 for _ in fil»|pos=«filtered = tuple(x for x in data if x > 0) ; total = sum(filtered) ; count = len(filtered)»|fp=e70a1f9d78c9be26`
- `@TRAP`: `@TRAP/1{guard:RX#a3222e51,fault:CLOSURE-ALIASING-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,iterator-exhaustion,single-pass-generator,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:filtered_tuple_x_for_x_in_data_if_x_0,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
filtered = (x for x in data if x > 0)
total = sum(filtered)
count = sum(1 for _ in filtered)  # EXHAUSTED_GENERATOR_SECOND_PASS
```

`@POS_AST` (`✅ REQUIRED`):
```python
filtered = tuple(x for x in data if x > 0)
total = sum(filtered)
count = len(filtered)
```
