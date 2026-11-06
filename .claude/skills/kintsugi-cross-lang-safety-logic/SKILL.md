---
name: kintsugi-cross-lang-safety-logic
description: "Focused cross-lang-safety-logic anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["allsettled-isolation", "falsy-zero-clobber", "gemini38-deepseek", "kml:v1", "logic-evolution", "nullish-coalescing", "promise-all-unhandled", "saturating-arithmetic", "unsigned-underflow"]
---

# kintsugi-cross-lang-safety-logic (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KS-LOGIC-034` · `@OP/1[ID:KS-LOGIC-034|SEV:HIGH|CAT:cross-lang-safety-logic|LANG:rs,py|OP:UNCHECKED_U64_SUBTRACTION->CHECKED_O]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-034|sev=H|cat=cross-lang-safety-logic|lang=rs,py|op=UNCHECKED_U64_SUBTRACTION->CHECKED_O|guard=RX#a2c20a0c|neg=«let remaining: u64 = total_budget - spent_amount;  // UNSIGNED_U64_UNDERFLOW_WRAP»|pos=«let remaining: u64 = total_budget.saturating_sub(spent_amount);»|fp=80dae2356016b3b4`
- `@TRAP`: `@TRAP/1{guard:RX#a2c20a0c,fault:CROSS-LANG-SAFETY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,unsigned-underflow,saturating-arithmetic,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:let_remaining:_u64_total_budget.saturating_s,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```rust
let remaining: u64 = total_budget - spent_amount;  // UNSIGNED_U64_UNDERFLOW_WRAP
```

`@POS_AST` (`✅ REQUIRED`):
```rust
let remaining: u64 = total_budget.saturating_sub(spent_amount);
```

### `KS-LOGIC-035` · `@OP/1[ID:KS-LOGIC-035|SEV:HIGH|CAT:cross-lang-safety-logic|LANG:ts,js,py|OP:PROMISE_ALL_BATCH_ABORT->PROMISE_ALL]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-035|sev=H|cat=cross-lang-safety-logic|lang=ts,js,py|op=PROMISE_ALL_BATCH_ABORT->PROMISE_ALL|guard=RX#3b136c25|neg=«const results = await Promise.all(workerPromises);  // PROMISE_ALL_SINGLE_REJECTION_BATCH_»|pos=«const results = await Promise.allSettled(workerPromises);»|fp=f2ab358fc48d5301`
- `@TRAP`: `@TRAP/1{guard:RX#3b136c25,fault:CROSS-LANG-SAFETY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,promise-all-unhandled,allsettled-isolation,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:const_results_await_Promise.allSettled_worke,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```typescript
const results = await Promise.all(workerPromises);  // PROMISE_ALL_SINGLE_REJECTION_BATCH_ABORT
```

`@POS_AST` (`✅ REQUIRED`):
```typescript
const results = await Promise.allSettled(workerPromises);
```

### `KS-LOGIC-036` · `@OP/1[ID:KS-LOGIC-036|SEV:HIGH|CAT:cross-lang-safety-logic|LANG:ts,js,py|OP:LOGICAL_OR_FALSY_ZERO_CLOBBER->NULLI]`
- `@WIRE`: `@KML/1|id=KS-LOGIC-036|sev=H|cat=cross-lang-safety-logic|lang=ts,js,py|op=LOGICAL_OR_FALSY_ZERO_CLOBBER->NULLI|guard=RX#ed46e8aa|neg=«const timeoutMs = config.timeoutMs || 5000;  // LOGICAL_OR_FALSY_ZERO_OVERRIDE»|pos=«const timeoutMs = config.timeoutMs ?? 5000;»|fp=c886b22afcb0e153`
- `@TRAP`: `@TRAP/1{guard:RX#ed46e8aa,fault:CROSS-LANG-SAFETY-LOGIC_VIOLATION,origin:OP/1,tags:[logic-evolution,nullish-coalescing,falsy-zero-clobber,gemini38-deepseek,kml:v1]}`
- `@LAW`: `@LAW/1{inv:ZERO_MATCH(NEG_AST)&&SATISFY(POS_AST),xform:NEG_AST=>POS_AST,pos_sig:const_timeoutMs_config.timeoutMs_5000,verify:DETERMINISTIC_PASS}`

`@NEG_AST` (`❌ FORBIDDEN`):
```typescript
const timeoutMs = config.timeoutMs || 5000;  // LOGICAL_OR_FALSY_ZERO_OVERRIDE
```

`@POS_AST` (`✅ REQUIRED`):
```typescript
const timeoutMs = config.timeoutMs ?? 5000;
```
