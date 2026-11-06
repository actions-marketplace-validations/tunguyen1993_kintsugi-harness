---
name: kintsugi-causal-temporal-logic
description: "Focused causal-temporal-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["collider-conditioning", "gemini38-deepseek", "kml:v1", "logic-evolution", "lookahead-bias", "monotonic-clock", "pearl-do-calculus", "train-test-leakage", "wall-clock-skew"]
---

# kintsugi-causal-temporal-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-016` · `@OP/1[ID:KS-LOGIC-016|SEV:CRITICAL|CAT:causal-temporal-logic|LANG:py|OP:FULL_CORPUS_SCALER_FIT_BEFORE_SPLIT-]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-016|sev=C|cat=causal-temporal-logic|lang=py|op=FULL_CORPUS_SCALER_FIT_BEFORE_SPLIT-|guard=RX#cf97d2a8|neg=«X_scaled = scaler.fit_transform(X_all)  # PRE_SPLIT_GLOBAL_NORMALIZATION_LEAK ; X_train, X»|pos=«X_train_raw, X_test_raw = split_temporal(X_all) ; X_train = scaler.fit_transform(X_train_r»|fp=2f97b675fef06394`
- `@TRAP`: `@TRAP/1{guard:RX#cf97d2a8,fault:CAUSAL-TEMPORAL-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,lookahead-bias,train-test-leakage,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:X_train_raw,_X_test_raw_split_temporal_X_all,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
X_scaled = scaler.fit_transform(X_all)  # PRE_SPLIT_GLOBAL_NORMALIZATION_LEAK
X_train, X_test = split_temporal(X_scaled)
```

`@POS_AST` (`✅ REQUIRED`):
```python
X_train_raw, X_test_raw = split_temporal(X_all)
X_train = scaler.fit_transform(X_train_raw)
X_test = scaler.transform(X_test_raw)
```

### `KS-LOGIC-017` · `@OP/1[ID:KS-LOGIC-017|SEV:HIGH|CAT:causal-temporal-logic|LANG:py|OP:WALL_CLOCK_TIME_ELAPSED_DIFF->MONOTO]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-017|sev=H|cat=causal-temporal-logic|lang=py|op=WALL_CLOCK_TIME_ELAPSED_DIFF->MONOTO|guard=RX#5c12b927|neg=«t_start = time.time() ; run_step() ; elapsed_ms = (time.time() - t_start) * 1000.0  # WALL»|pos=«t_start = time.monotonic() ; run_step() ; elapsed_ms = (time.monotonic() - t_start) * 1000»|fp=d4d7ed7baa3a0d58`
- `@TRAP`: `@TRAP/1{guard:RX#5c12b927,fault:CAUSAL-TEMPORAL-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,monotonic-clock,wall-clock-skew,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:t_start_time.monotonic,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
t_start = time.time()
run_step()
elapsed_ms = (time.time() - t_start) * 1000.0  # WALL_CLOCK_NTP_BACKWARD_JUMP_BUG
```

`@POS_AST` (`✅ REQUIRED`):
```python
t_start = time.monotonic()
run_step()
elapsed_ms = (time.monotonic() - t_start) * 1000.0
```

### `KS-LOGIC-018` · `@OP/1[ID:KS-LOGIC-018|SEV:HIGH|CAT:causal-temporal-logic|LANG:py|OP:CONDITION_ON_POST_TREATMENT_COLLIDER]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-018|sev=H|cat=causal-temporal-logic|lang=py|op=CONDITION_ON_POST_TREATMENT_COLLIDER|guard=RX#00858a98|neg=«adj_set = pre_confounders | post_treatment_colliders  # POST_TREATMENT_COLLIDER_BIAS_CONDI»|pos=«adj_set = pre_confounders - descendants_of_treatment»|fp=a3088db4077f1351`
- `@TRAP`: `@TRAP/1{guard:RX#00858a98,fault:CAUSAL-TEMPORAL-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,collider-conditioning,pearl-do-calculus,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:adj_set_pre_confounders_-_descendants_of_tre,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
adj_set = pre_confounders | post_treatment_colliders  # POST_TREATMENT_COLLIDER_BIAS_CONDITIONING
```

`@POS_AST` (`✅ REQUIRED`):
```python
adj_set = pre_confounders - descendants_of_treatment
```
