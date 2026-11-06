---
name: kintsugi-fintech-web3
description: "Focused fintech-web3 anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["github-opensource", "github-roamer", "learn-and-practice"]
---

# kintsugi-fintech-web3 (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-WILD-503` · `@OP/1[ID:KS-WILD-503|SEV:HIGH|CAT:fintech-web3|LANG:py|OP:usdc!float->Decimal_exact]`
- `@WIRE`: `@KML/1|id=KS-WILD-503|sev=H|cat=fintech-web3|lang=py|op=usdc!float->Decimal_exact|guard=RX#3b4115bb|neg=«payout_atomic = int(float(amount_usd) * 1000000)  # FLOAT_USDC_TRUNCATION»|pos=«payout_atomic = int((Decimal(str(amount_usd)) * Decimal('1000000')).to_integral_exact())»|fp=478e144e8f7736e1`
- `@TRAP`: `@TRAP/1{guard:RX#3b4115bb,fault:FINTECH-WEB3_VIOLATION,origin:OP/1,tags:[github-roamer,learn-and-practice,github-opensource]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:payout_atomic_int_Decimal_str_amount_usd_Dec,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
payout_atomic = int(float(amount_usd) * 1000000)  # FLOAT_USDC_TRUNCATION
```

`@POS_AST` (`✅ REQUIRED`):
```python
payout_atomic = int((Decimal(str(amount_usd)) * Decimal('1000000')).to_integral_exact())
```

### `KS-WILD-505` · `@OP/1[ID:KS-WILD-505|SEV:HIGH|CAT:fintech-web3|LANG:py|OP:math!div_first->mul_before_div]`
- `@WIRE`: `@KML/1|id=KS-WILD-505|sev=H|cat=fintech-web3|lang=py|op=math!div_first->mul_before_div|guard=RX#03fe77a6|neg=«reward_share = (gross_atomic // 10000) * share_bps  # DIV_BEFORE_MUL_LOSS»|pos=«reward_share = (gross_atomic * share_bps) // 10000»|fp=b110d58993059763`
- `@TRAP`: `@TRAP/1{guard:RX#03fe77a6,fault:FINTECH-WEB3_VIOLATION,origin:OP/1,tags:[github-roamer,learn-and-practice,github-opensource]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:reward_share_gross_atomic_share_bps_//_10000,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
reward_share = (gross_atomic // 10000) * share_bps  # DIV_BEFORE_MUL_LOSS
```

`@POS_AST` (`✅ REQUIRED`):
```python
reward_share = (gross_atomic * share_bps) // 10000
```

### `KS-WILD-518` · `@OP/1[ID:KS-WILD-518|SEV:HIGH|CAT:fintech-web3|LANG:py|OP:fp!wild_eq->math_isclose]`
- `@WIRE`: `@KML/1|id=KS-WILD-518|sev=H|cat=fintech-web3|lang=py|op=fp!wild_eq->math_isclose|guard=RX#80ddb003|neg=«if computed_rate_float == target_rate_float:  # WILD_FLOAT_DIRECT_EQ»|pos=«if math.isclose(computed_rate_float, target_rate_float, rel_tol=1e-9):»|fp=b2a4997828de9032`
- `@TRAP`: `@TRAP/1{guard:RX#80ddb003,fault:FINTECH-WEB3_VIOLATION,origin:OP/1,tags:[github-roamer,learn-and-practice,github-opensource]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:if_math.isclose_computed_rate_float,_target_,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
if computed_rate_float == target_rate_float:  # WILD_FLOAT_DIRECT_EQ
```

`@POS_AST` (`✅ REQUIRED`):
```python
if math.isclose(computed_rate_float, target_rate_float, rel_tol=1e-9):
```
