---
name: kintsugi-numerical-logic
description: "Focused numerical-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["basis-points", "catastrophic-cancellation", "gemini38-deepseek", "integer-division-rounding", "kahan-summation", "kml:v1", "logic-evolution", "logsumexp", "softmax-overflow"]
---

# kintsugi-numerical-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-009` · `@OP/1[ID:KS-LOGIC-009|SEV:CRITICAL|CAT:numerical-logic|LANG:py|OP:PREMATURE_INTEGER_FLOOR_DIV->MULTIPL]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-009|sev=C|cat=numerical-logic|lang=py|op=PREMATURE_INTEGER_FLOOR_DIV->MULTIPL|guard=RX#3225cdd4|neg=«fee_units = (amount_units // 10000) * bps_rate  # PREMATURE_FLOOR_DIVISION_LOSS»|pos=«fee_units = (amount_units * bps_rate) // 10000»|fp=5da5ffbf9360f58b`
- `@TRAP`: `@TRAP/1{guard:RX#3225cdd4,fault:NUMERICAL-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,integer-division-roundin,basis-points,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:fee_units_amount_units_bps_rate_//_10000,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
fee_units = (amount_units // 10000) * bps_rate  # PREMATURE_FLOOR_DIVISION_LOSS
```

`@POS_AST` (`✅ REQUIRED`):
```python
fee_units = (amount_units * bps_rate) // 10000
```

### `KS-LOGIC-007` · `@OP/1[ID:KS-LOGIC-007|SEV:HIGH|CAT:numerical-logic|LANG:py|OP:NAIVE_EXP_SOFTMAX->SHIFTED_MAX_LOGSU]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-007|sev=H|cat=numerical-logic|lang=py|op=NAIVE_EXP_SOFTMAX->SHIFTED_MAX_LOGSU|guard=RX#6b45d960|neg=«probs = [math.exp(z) / sum(math.exp(x) for x in logits) for z in logits]  # UNSHIFTED_EXP_»|pos=«m = max(logits) ; exps = [math.exp(z - m) for z in logits] ; z_sum = sum(exps) ; probs = [»|fp=c68443c3c0a526fe`
- `@TRAP`: `@TRAP/1{guard:RX#6b45d960,fault:NUMERICAL-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,logsumexp,softmax-overflow,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:m_max_logits,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
probs = [math.exp(z) / sum(math.exp(x) for x in logits) for z in logits]  # UNSHIFTED_EXP_SOFTMAX_OVERFLOW
```

`@POS_AST` (`✅ REQUIRED`):
```python
m = max(logits)
exps = [math.exp(z - m) for z in logits]
z_sum = sum(exps)
probs = [e / z_sum for e in exps]
```

### `KS-LOGIC-008` · `@OP/1[ID:KS-LOGIC-008|SEV:HIGH|CAT:numerical-logic|LANG:py|OP:SINGLE_PASS_VARIANCE_DIFF->WELFORD_O]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-008|sev=H|cat=numerical-logic|lang=py|op=SINGLE_PASS_VARIANCE_DIFF->WELFORD_O|guard=RX#35fb0ebf|neg=«var = (sum(x * x for x in xs) / n) - (sum(xs) / n) ** 2  # CATASTROPHIC_VARIANCE_CANCELLAT»|pos=«mean = sum(xs) / n ; var = sum((x - mean) ** 2 for x in xs) / n»|fp=a86148e6ecc9cfcc`
- `@TRAP`: `@TRAP/1{guard:RX#35fb0ebf,fault:NUMERICAL-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,kahan-summation,catastrophic-cancellatio,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:mean_sum_xs_/_n,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
var = (sum(x * x for x in xs) / n) - (sum(xs) / n) ** 2  # CATASTROPHIC_VARIANCE_CANCELLATION
```

`@POS_AST` (`✅ REQUIRED`):
```python
mean = sum(xs) / n
var = sum((x - mean) ** 2 for x in xs) / n
```
