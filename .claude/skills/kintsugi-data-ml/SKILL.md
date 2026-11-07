---
name: kintsugi-data-ml
description: "Focused data-ml anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["backtest", "catastrophic-cancellation", "causality", "data-leakage", "data-ml", "fsum", "look-ahead-bias", "ml-security", "model:deepseek-r1", "model:gemini-pro"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-data-ml (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-ML-003` · `Causal Light-Cone Non-Lookahead, 2nd Law Entropy & Compensated Floating-Point Guard`
- `@WIRE`: `@KML/1|id=KL-ML-003|sev=C|cat=data-ml|lang=py|op=CAUSAL_LIGHT-CONE_NON-LOOKAHEAD_2ND_|guard=RX#10d16b55|neg=«pred_t = 0.5 * signal_series[idx_t] + 0.5 * signal_series[idx_t + 1]  # CAUSAL_ARROW_LOOKA»|pos=«pred_t = 0.5 * signal_series[max(0, idx_t - 1)] + 0.5 * signal_series[idx_t] ; total_energ»|fp=aa1cc4d93e2a0829`
- `@TRAP`: `[Cognitive Trap] Accessed future time index `signal_series[idx_t + 1]` at step `idx_t` (violating relativistic causal arrow `t_cause <= t_effect`), decreased isolated entropy, or evaluated `gamma ** 2 - 1.0` at `v << c`.`
- `@LAW`: `[Mental Model] Enforce strict past-only causal masks (`indices <= idx_t`), non-negative isolated entropy production (`dS >= 0`), algebraic factorization (`v_sq / (1.0 - v_sq)`), and Kahan `math.fsum()`.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
pred_t = 0.5 * signal_series[idx_t] + 0.5 * signal_series[idx_t + 1]  # CAUSAL_ARROW_LOOKAHEAD_LEAK
```

`@POS_AST` (`✅ REQUIRED`):
```python
pred_t = 0.5 * signal_series[max(0, idx_t - 1)] + 0.5 * signal_series[idx_t]
total_energy = math.fsum([rest_energy_j] + list(micro_fluxes))
```

### `KL-SEC-001` · `Require weights_only=True in PyTorch torch.load() to block pickle RCE`
- `@WIRE`: `@KML/1|id=KL-SEC-001|sev=C|cat=data-ml|lang=py|op=REQUIRE_WEIGHTS_ONLY_TRUE_IN_PYTORCH|guard=RX#713facc5|neg=«ckpt = torch.load("weights.pt")»|pos=«ckpt = torch.load("weights.pt", weights_only=True)»|fp=f9f078c18c545202`
- `@TRAP`: `[Cognitive Trap] Treated `.pt` / `.bin` model checkpoints as passive weight tensors rather than executable Python pickle bytecode.`
- `@LAW`: `[Mental Model] Default `torch.load()` invokes `pickle.Unpickler`, allowing arbitrary OS command execution during checkpoint deserialization unless `weights_only=True` is set.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
ckpt = torch.load("weights.pt")
```

`@POS_AST` (`✅ REQUIRED`):
```python
ckpt = torch.load("weights.pt", weights_only=True)
```

### `KL-ML-002` · `Block look-ahead bias (.shift(-1)) inside feature engineering columns`
- `@WIRE`: `@KML/1|id=KL-ML-002|sev=C|cat=data-ml|lang=py|op=BLOCK_LOOK-AHEAD_BIAS_SHIFT_-1_INSID|guard=RX#8dd599ac|neg=«df["alpha_feature"] = df["close"].shift(-1) / df["close"] - 1.0»|pos=«df["alpha_feature"] = df["close"] / df["close"].shift(1) - 1.0»|fp=a02e21ea6fbfd078`
- `@TRAP`: `[Cognitive Trap] Used `df['close'].shift(-1)` when constructing an alpha feature column, inadvertently leaking tomorrow's price into today's prediction.`
- `@LAW`: `[Mental Model] Harvested from patrickjs/awesome-cursorrules (alpha-skills-quant-factor-research): Feature matrices X_t must strictly use lagging data (.shift(1) or rolling past windows); negative shifts belong exclusively in label targets Y_t.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
df["alpha_feature"] = df["close"].shift(-1) / df["close"] - 1.0
```

`@POS_AST` (`✅ REQUIRED`):
```python
df["alpha_feature"] = df["close"] / df["close"].shift(1) - 1.0
```
