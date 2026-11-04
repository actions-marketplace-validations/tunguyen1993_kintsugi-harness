# AGENTS.md

<!-- KINTSUGI:START -->
## Kintsugi Self-Evolved Guardrails (Auto-Compiled)

> Managed by `kintsugi-harness`. Run `kintsugi scan .` before committing or opening PRs.
> Full paired anti-patterns (`❌ Bad` vs `✅ Good`) live in `.claude/skills/kintsugi-guardrails/SKILL.md`.

| ID | Severity | Category | Anti-Pattern to Avoid |
| :--- | :--- | :--- | :--- |
| `KS-001` | `CRITICAL` | `security` | Hardcoded API credential or private key literal |
| `KS-002` | `CRITICAL` | `safety` | Destructive shell or irreversible git history wipe |
| `KS-006` | `CRITICAL` | `security` | Unsafe dynamic code execution or untrusted deserialization |
| `KS-007` | `CRITICAL` | `security` | Raw SQL string interpolation via f-string or format |
| `KS-012` | `CRITICAL` | `security` | Prompt-injection or system-override directive embedded in skill or fixture |
| `KS-003` | `HIGH` | `security` | Subprocess execution with shell=True |
| `KS-005` | `HIGH` | `reliability` | Silent exception swallowing (bare except or except-pass) |
| `KS-008` | `HIGH` | `reliability` | Unbounded synchronous HTTP call missing explicit timeout |
| `KS-011` | `HIGH` | `security` | Non-cryptographic PRNG used for security token, nonce, or secret |
| `KS-013` | `HIGH` | `Command Injection` | Potential shell command injection through interpolated exec command |
| `KS-004` | `MEDIUM` | `correctness` | Python mutable default argument in function signature |
| `KS-009` | `MEDIUM` | `quality` | Unfinished TODO stub or placeholder implementation shipped in module |
| `KS-010` | `MEDIUM` | `reliability` | Headless browser launch without deterministic finally teardown |
<!-- KINTSUGI:END -->
