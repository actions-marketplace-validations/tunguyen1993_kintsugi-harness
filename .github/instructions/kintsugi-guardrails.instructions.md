---
applyTo: "**/*"
---

## Kintsugi Self-Evolved Guardrails (Auto-Compiled)

> Managed by `kintsugi-harness`. Run `kintsugi scan .` or `kintsugi scan --staged` before committing.
> Full paired anti-patterns (`❌ Bad` vs `✅ Good`) live in `.claude/skills/kintsugi-guardrails/SKILL.md`.

| ID | Severity | Category | Anti-Pattern to Avoid |
| :--- | :--- | :--- | :--- |
| `KS-001` | `CRITICAL` | `security` | Hardcoded API credential or private key literal |
| `KS-002` | `CRITICAL` | `safety` | Destructive shell or irreversible git history wipe |
| `KS-006` | `CRITICAL` | `security` | Unsafe dynamic code execution or untrusted deserialization |
| `KS-007` | `CRITICAL` | `security` | Raw SQL string interpolation via f-string or format |
| `KS-012` | `CRITICAL` | `security` | Prompt-injection or system-override directive embedded in skill or fixture |
| `KS-014` | `CRITICAL` | `security` | Global TLS certificate verification disabled in Node.js process |
| `KS-003` | `HIGH` | `security` | Subprocess execution with shell=True |
| `KS-005` | `HIGH` | `reliability` | Silent exception swallowing (bare except or except-pass) |
| `KS-008` | `HIGH` | `reliability` | Unbounded synchronous HTTP call missing explicit timeout |
| `KS-011` | `HIGH` | `security` | Non-cryptographic PRNG used for security token, nonce, or secret |
| `KS-013` | `HIGH` | `security` | Potential shell command injection through interpolated exec command |
| `KS-015` | `HIGH` | `security` | Permissive CORS wildcard origin combined with allow_credentials=True |
| `KS-016` | `HIGH` | `reliability` | Go net/http DefaultClient call without bounded timeout |
| `KS-OSS-1000` | `HIGH` | `reliability` | Open-Source Runtime Invariant Guard Distilled from Solrikk/Cripto-Boats (fetcher.py) |
| `KS-OSS-1001` | `HIGH` | `reliability` | Open-Source Runtime Invariant Guard Distilled from veighna-global/vnpy_bybit (run.py) |
| `KS-OSS-1002` | `HIGH` | `reliability` | Open-Source Runtime Invariant Guard Distilled from CryptoNawwa/nawwa_scalper_tool (exchange.py) |
| `KS-OSS-1003` | `HIGH` | `reliability` | Open-Source Runtime Invariant Guard Distilled from zabor-crypto/zaBor (main_backtest.py) |
| `KS-OSS-1004` | `HIGH` | `reliability` | Open-Source Runtime Invariant Guard Distilled from tfrmma/game-theory-trading-strats (RL_tuner.py) |

*+1672 additional domain scars compiled in `.claude/skills/`.*
