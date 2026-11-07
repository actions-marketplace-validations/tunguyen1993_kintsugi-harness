---
name: kintsugi-finance-capital
description: "Focused finance-capital anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["anti-martingale", "anti-scam", "capital-protection", "finance-capital", "kelly-criterion", "model:deepseek-r1", "model:gpt-6-frontier", "personal-finance", "pillar:life-and-business", "position-sizing"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-finance-capital (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-CAP-001` · `Zero-Advance-Fee Capital Guard: Reject any contract or opportunity requiring an upfront verification deposit`
- `@WIRE`: `@KML/1|id=KL-CAP-001|sev=C|cat=finance-capital|lang=deci,mark,py|op=ZERO-ADVANCE-FEE_CAPITAL_GUARD_REJEC|guard=RX#f444c7ed|neg=«DECISION: APPROVE_ACTION(upfront_fee_usd=25.0, action='SEND_UPFRONT_STAKING_DEPOSIT')»|pos=«DECISION: REJECT_ACTION(upfront_fee_usd=0.0, policy='ZERO_ADVANCE_FEE_CAPITAL_GUARD')»|fp=b4125ec8a629ba72`
- `@TRAP`: `[Cognitive Trap] Felt tempted by a high promised payout (`$500 return`) to pay a 'small refundable verification deposit or staking fee' (`upfront_fee_usd > 0`).`
- `@LAW`: `[Mental Model] Legitimate commercial counterparties deduct service fees from gross settlements or pay inbound; any requirement to send upfront principal (`UPFRONT_DEPOSIT_REQUIRED` / `upfront_fee_usd > 0`) is an asymmetric principal-loss trap.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
DECISION: APPROVE_ACTION(upfront_fee_usd=25.0, action='SEND_UPFRONT_STAKING_DEPOSIT')
```

`@POS_AST` (`✅ REQUIRED`):
```decision
DECISION: REJECT_ACTION(upfront_fee_usd=0.0, policy='ZERO_ADVANCE_FEE_CAPITAL_GUARD')
```

### `KL-CAP-002` · `Anti-Martingale Position Sizing: Never double exposure after a losing trade or drawdown`
- `@WIRE`: `@KML/1|id=KL-CAP-002|sev=C|cat=finance-capital|lang=deci,py,mark|op=ANTI-MARTINGALE_POSITION_SIZING_NEVE|guard=RX#c63a2389|neg=«STRATEGY: position_size = previous_losing_size * 2  # MARTINGALE_DOUBLE_DOWN»|pos=«STRATEGY: position_size = min(account_equity * 0.01, max_risk_cap)»|fp=d1c11ad6f37f1a70`
- `@TRAP`: `[Cognitive Trap] Doubled position size after a loss (`next_bet = last_bet * 2`) to 'win back losses in one trade' due to loss-aversion panic.`
- `@LAW`: `[Mental Model] Volatility clusters in real life and markets; Martingale doubling (`MARTINGALE_DOUBLE_DOWN`) guarantees ruin under finite capital. Cap every single-decision risk to <= 1%–2% of liquid net worth.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
STRATEGY: position_size = previous_losing_size * 2  # MARTINGALE_DOUBLE_DOWN
```

`@POS_AST` (`✅ REQUIRED`):
```decision
STRATEGY: position_size = min(account_equity * 0.01, max_risk_cap)
```
