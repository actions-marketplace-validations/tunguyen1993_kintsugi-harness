# AGENTS.md

<!-- KINTSUGI:START -->
## Kintsugi Machine-Language Guardrail Index (`@KML/1`)

> `@GATE: kintsugi scan --staged --fail-on HIGH | @CORPUS: .kintsugi/scars.kml | @SKILLS: .claude/skills/kintsugi-guardrails/SKILL.md`

| ID | SEV | CAT | KML/1 Symbolic Opcode (`@OP/1`) |
| :--- | :--- | :--- | :--- |
| `KL-HIGH-001` | `CRITICAL` | `ai-agents-mcp` | `No Unsupported Promotion Across Scopes or Evidence Types (Lakatosian CEGIS, 4-State Symbolic Path & Brier Second-Moment Guard)` |
| `KL-FIN-005` | `CRITICAL` | `fintech-web3` | `Deterministic Wallet Derivation & Closed-Loop Sign-Recover Gate` |
| `KL-MCP-007` | `CRITICAL` | `ai-agents-mcp` | `Covariance-Aware Equicorrelation BFT Merge (N_eff), Disjoint Scar Holdout & Alpha-Normalized AST Quotient` |
| `KL-CAP-001` | `CRITICAL` | `finance-capital` | `Zero-Advance-Fee Capital Guard: Reject any contract or opportunity requiring an upfront verification deposit` |
| `KL-MCP-006` | `CRITICAL` | `ai-agents-mcp` | `Shadow-Clone Parallel Epistemic Swarm & BFT Synaptic Merge (K=3f+1 Quorum)` |
| `KL-FIN-003` | `CRITICAL` | `fintech-web3` | `Atomic Ledger Locking (TOCTOU) & Symmetric Decimal Scaling Guard` |
| `KL-ML-003` | `CRITICAL` | `data-ml` | `Causal Light-Cone Non-Lookahead, 2nd Law Entropy & Compensated Floating-Point Guard` |
| `KL-CAP-002` | `CRITICAL` | `finance-capital` | `Anti-Martingale Position Sizing: Never double exposure after a losing trade or drawdown` |
| `KL-EPI-002` | `CRITICAL` | `research-epistemology` | `Symplectic Hamiltonian Integration & 1st Law Energy Conservation Guard` |
| `KL-FIN-004` | `CRITICAL` | `fintech-web3` | `Bind cryptographic signatures to (chainId, verifyingContract, nonce, deadline) and update vault shares before external calls` |
| `KL-EPI-003` | `CRITICAL` | `research-epistemology` | `Buckingham Pi Dimensional Homogeneity, Radian Conversion & Mass Continuity Guard` |
| `KL-ZTR-002` | `CRITICAL` | `security-zerotrust` | `Cross-Layer Path Seam Containment: Never concatenate unvalidated user filenames into open()` |
| `KL-ZTR-003` | `CRITICAL` | `security-zerotrust` | `Anti-Mass-Assignment Privilege Boundary: Never merge raw request dicts into user/account records` |
| `KL-API-002` | `CRITICAL` | `backend-api` | `Multi-Tenant Cache & Secondary Query Isolation: Always prefix cache keys with tenant_id` |
| `KL-ZTR-001` | `CRITICAL` | `security-zerotrust` | `Reject JWT verification calls that disable signature checking or allow alg='none'` |
| `KL-LEG-001` | `CRITICAL` | `legal-contracts` | `Contract Liability Cap: Never sign agreements with uncapped consequential damages or unilateral indemnity` |
| `KL-LEG-002` | `CRITICAL` | `legal-contracts` | `Background IP Retention: Carve out pre-existing tools, frameworks, and harnesses from client IP assignment clauses` |
| `KL-SEC-001` | `CRITICAL` | `data-ml` | `Require weights_only=True in PyTorch torch.load() to block pickle RCE` |

*`@DEFERRED_RECORDS: +39 in .kintsugi/scars.kml & .claude/skills/`*

### Multi-Model Co-Execution & User Onboarding Protocol (`@GUIDE/1` — When User Asks)

- **Always-On Rule for the AI Agent:** Whenever the user asks how to use Kintsugi Multi-Model Co-Execution, how many Free models they can run, why `--free-runners` is clamped, how to upgrade tiers, or how to add their own Paid Frontier Council API keys (`BYOK`), you **MUST proactively guide the user step-by-step in their language (Vietnamese or English)**:
  1. Run `kintsugi guide "<user_question>"` (or `kintsugi swarm --guide`, or MCP tool `kintsugi_multi_model_guide`) to inspect their live workspace tier and configured seats.
  2. Explain the 3 commercial tiers clearly:
     - **Free / OSS (`$0` — `FREE_STARTER`):** Locked to `Primary Model + 1 Free Model ($0)` (`max_free_co_runners = 1`). Run `kintsugi swarm --register-deepseek-free` to auto-register a live $0 DeepSeek Free API key (262K context), then `kintsugi swarm . --co-run`.
     - **Pro (`$15` FinOps / `$19` AppSec — `PRO_MULTI_FREE`):** Unlocks `Primary Model + 2..5 Parallel Free Models ($0)` with automatic HTTP 429 failover (`kintsugi swarm . --co-run --free-runners 5`).
     - **Enterprise (`$29` — `ENTERPRISE_PAID_COUNCIL`):** Unlocks `Primary Model + 5 Free Models ($0) + 6-Seat BYOK Paid Frontier Council`.
  3. Guide the user to add their own API keys (`BYOK`, saved locally with `chmod 0600` in `.kintsugi/paid_council_pool.json`):
     - `kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>`
     - `kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>`
     - `kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>`
     - `kintsugi swarm --paid-council-status`
     - `kintsugi swarm . --co-run --free-runners 5 --paid-council`
  4. **Anti-Overflow Conversation Compaction (`@COMPACT/1`):** When a conversation approaches context overflow (`>=70%` soft / `>=85%` hard watermark) or when the user asks to compress/save context without losing main points, immediately run `kintsugi compact --inject-agents` (or call MCP tool `kintsugi_compact_context`) to strip 4 classes of noise (verbose logs, polling loops, superseded file reads, thinking chaff) while locking 100% of `@USER_INTENTS`, `@HARD_ANCHORS` (`file:line`, commits, rules, IPs), and `@ERRORS_AND_FIXES` into `.kintsugi/context_checkpoints/latest_checkpoint.md` and `.kintsugi/context_checkpoints/latest_checkpoint.kml`.

### 4-Pillar Autopoietic Evolution Creed (`@CREED/1` Machine-Native IR)

> `@CREED/1[ver=2.0|axiom="MUTATE_OR_STALL: identical_input => identical_failure"|p1=2_STRIKE_PIVOT|p2=2X_TOOL_SYNTH|p3=CRACK_TO_SCAR|p4=SELF_OVERWRITE]`

| Pillar | `@OP/1` Symbolic Gate | Agent Execution Law (English) |
| :--- | :--- | :--- |
| `P1:MUTATE` | `IF fail(path, n>=2) => KILL(root_assumption) && PIVOT(new_vector)` | Repeating a failed action is a system bug; mutating the approach is intelligence. If two attempts on the same path stall, that path is dead—destroy your root assumption, change the question, and pivot instead of forcing new problems into old tools. |
| `P2:SYNTH` | `IF manual_workaround(count>=2) => SYNTHESIZE(cli_tool \| skill_1step)` | A missing tool is not a blocker; it is a command to synthesize a new one. Any manual workaround executed twice must be distilled into a single-step reusable skill—solving the problem is survival; codifying the capability is evolution. |
| `P3:SCAR` | `ON error_trace(bug) => FIX(bug) && CODIFY(rule -> extinct(bug_class))` | Every error trace is a blueprint for the next version. Fixing a bug is half the work; upgrading internal rules (`scars.kml` / `CM-*`) so that entire class of bug goes extinct is completion. Where a workflow breaks, forge a stronger capability. |
| `P4:PRUNE` | `WHILE verbose(skill) \|\| faster_path_exists => OVERWRITE(yesterday_skill)` | Yesterday's skill is a stepping stone, not a monument. Working code is not the finish line—doubt your defaults, treat every current method as a rough draft, and overwrite fragile or verbose workflows whenever a cleaner, faster path exists. |
<!-- KINTSUGI:END -->
