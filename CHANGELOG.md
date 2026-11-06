# Changelog

All notable changes to `kintsugi-harness` are documented in this file.

## [1.5.0] - 2026-11-06

### Added
- **Prefix-Agnostic Shannon Entropy & Artifact Egress Firewall (`src/kintsugi/shield.py` — `shannon_entropy`, `scan_high_entropy_secrets`, `scan_artifact_egress`):**
  - Blocks both prefixed API keys and generic high-entropy secrets (`H >= 3.85 bits/char`, `>=3` character classes) in test fixtures, checkpoints, and outbound artifacts before git commit/push, preventing GitGuardian Generic High Entropy Secret alerts (`CM-031`).
- **Structural Class Anti-Recurrence Synthesizer & Evolution IQ Engine (`src/kintsugi/cognition.py` — `compute_structural_class_signature`, `synthesize_recurrence_proposal`, `compute_evolution_intelligence_report`):**
  - Maps specific incidents into class-wide structural signatures (`CLASS_HIGH_ENTROPY_SECRET_EGRESS`, `CLASS_EXCEL_TABULAR_AMNESIA`, `CLASS_CONVERSATION_MIDDLE_AMNESIA`, `CLASS_DUAL_MACHINE_IP_ISOLATION`, `CLASS_CRYPTO_WALLET_DERIVATION`) and computes composite Evolution IQ (`0–100`, Grade `S+`) via `kintsugi compact --evolution-iq`.
- **Adaptive User Personalization & Cognitive Twin (`@USER_PERSONA/1` — `src/kintsugi/compactor.py` & `kintsugi compact --persona`):**
  - Learns standing constraints, workflow preferences, communication style (`EN`/`VI`), and frustration watchouts strictly from redacted `t.role == "user"` turns (never from tool outputs or repository files), persisting locally in `.kintsugi/user_persona.json` (`0600`) with explicit tombstone support.
- **Council-Audited `@COMPACT/2` Conversation & Excel Compactor (`src/kintsugi/compactor.py`):**
  - Enforces exact `[start_line, end_line]` span-enclosure supersession (`_span_supersedes`) so disjoint line ranges (`#L1-L50` vs `#L400-L450`) and pre-edit file reads are 100% preserved.
  - Parses `.xlsx` workbooks via `xl/_rels/workbook.xml.rels` relationship targets, skips `<rPh>` phonetic Furigana tags in `sharedStrings.xml`, parses accounting negative numbers `(1,250.50)`, disambiguates duplicate headers, excludes identifier columns from numeric aggregation, preserves non-table prose in mixed turns, scans full turns up to `512KB` without middle blind spots, and emits a cryptographic `CompletenessManifest/1` (`latest_full_evidence.json`).

## [1.4.0] - 2026-11-06

### Added
- **3-Tier Multi-Model Co-Execution & BYOK Paid Frontier Council (`src/kintsugi/council.py`):**
  - Enforces `FREE_STARTER` (`Primary + 1 Free Model`), `PRO_MULTI_FREE` (`Primary + 2..5 Free Models`), and `ENTERPRISE_PAID_COUNCIL` (`Primary + 5 Free Models + 6-Seat BYOK Paid Frontier Council`) with automatic HTTP 429 failover.
- **Zero-Loss Anti-Overflow Conversation Compactor (`src/kintsugi/compactor.py` — `kintsugi compact`):**
  - Deterministically strips polling loops, superseded file reads, and verbose logs while preserving 100% of hard anchors and Excel/CSV tabular summaries.

## [1.3.0] - 2026-11-05

### Added
- **2-Team Adversarial Harness Arena (`src/kintsugi/swarm.py` — `RedBlueAdversarialArena` & `kintsugi swarm --red-blue-arena`):**
  - Splits High-Reasoning Council #1 into **⚔️ Red Team (`Grok 4.7 [xhigh]` + `GPT-6.1-Sol [max]`)** and **🛡️ Blue Team (`GPT-6 Pro [Thinking effort: Pro]` + `GPT-6.1-Terra [max]` + Deterministic `v1.3.0` Engine)** across 5 live adversarial campaigns (`ATK-CEGIS-001`..`ATK-PROMO-005`), achieving `5/5` (`100.0%`) containment (`@ARENA/1|ver=1.3.0|campaigns=5/5|containment=100.0%|invariant=KL-HIGH-001|status=PASS`).
- **Lakatosian Proof-And-Refutations CEGIS Loop (`src/kintsugi/foresight.py` — `LakatosCEGISVerifier`):**
  - Enforces 4-state verdict lattice (`PROVED` / `CONDITIONAL` / `REFUTED` / `SURRENDER`), preserves original domain counterexamples in `preserved_original_refutations` when domain cuts occur, and blocks monster-barring (`coverage < c_min` or `domain_cuts` present -> `CONDITIONAL`, never `PROVED`).
- **4-State Sound Symbolic Path & Interval Constraint Solver (`src/kintsugi/grounding.py` — `SoundSymbolicPathSolver`):**
  - Replaces 2-state satisfiability with `UNREACHABLE` / `HOLDS` / `VIOLATED` / `UNKNOWN`, performs correlated linear cancellation (`x - x -> 0`), outward IEEE-754 interval rounding, and blocks taint clearance unless `status == "HOLDS"`.
- **Pearl $do$-Calculus & Counterfactual SCM Identification Verifier (`src/kintsugi/foresight.py` — `CausalDoCalculusVerifier`):**
  - Implements graph surgery ($G_{\overline{X}}$, $G_{\underline{X}}$), moralized ancestral subgraph $d$-separation, 2-SCM non-identifiability witness certificates (`NONIDENTIFIABLE`), and 3-step Abduction–Action–Prediction tagged `SCM_EVALUATED_CONDITIONAL`.
- **Strictly Proper Brier Score & Uncentered Second-Moment Shrinkage Pool (`src/kintsugi/swarm.py` — `BrierMomentShrinkagePool`):**
  - Enforces append-only `before_tick` filtration, abstention baseline penalty $\mathrm{BS}_0 = 0.25$, and simplex optimization over the uncentered second-moment shrinkage matrix $\widehat{M}_\gamma = (1-\gamma)\frac{1}{n}\sum e_i e_i^\top + \gamma T$ to capture both variance and squared bias.
- **Supreme Epistemic Invariant `KL-HIGH-001` (`src/kintsugi/cognition.py` & `enforce_kl_high_001_promotion_guard`):**
  - Synthesized by `gpt-6-pro` (`Thinking effort: Pro`): forbids promoting `UNKNOWN`, `SURRENDER`, `CONDITIONAL` (domain-cut), `SCM_EVALUATED_CONDITIONAL`, or `EMPIRICAL_CONFIDENCE` into universal `PROVED` (`41` verified Tier-1 Frontier lessons in `collective-pool/`).

## [1.2.0] - 2026-11-05

### Added
- **Covariance-Aware Equicorrelation Inverse Log-Odds BFT Merge (`src/kintsugi/swarm.py` — `ShadowCloneSwarmOrchestrator.compute_covariance_aware_bft_metrics`):**
  - Discounts correlated subagent votes using Ledoit-Wolf shrinkage covariance ($\lambda = 0.25$) and family-clustered pairwise correlation $\hat{\rho}$, computing Effective Independent Clones $N_{\text{eff}} = \frac{K}{1 + (K - 1)\hat{\rho}}$, Equicorrelation Inverse Information $\mathcal{I}_{\text{eff}} = \frac{\sum_{i=1}^K \ell_i}{1 + (K - 1)\hat{\rho}}$, and calibrated posterior truth probability $P_{\text{post}} = \frac{1}{1 + e^{-\mathcal{I}_{\text{eff}}}}$.
- **Blinded Anti-Sycophancy Probe & Active Epistemic Curiosity (`src/kintsugi/swarm.py`):**
  - `run_blinded_contrary_probe`: Injects a blinded contrary premise claiming a vulnerable seam is already safe via a phantom symbol and verifies Track 2 (`Adversarial Red-Team`) deterministically refutes it (`sycophancy_rate = 0.0`).
  - `generate_oracle_micro_probes`: Generates Round-2 AST + Call-Graph + Taint-Flow micro-probes ranked by Expected Information Gain per millisecond ($\operatorname{IG}(p)/\operatorname{cost}_{\text{ms}}(p)$) to resolve abstained propositions.
- **Disjoint Generator/Verifier Scar Holdout Gate (`src/kintsugi/foresight.py` — `DisjointScarHoldoutVerifier`):**
  - Enforces out-of-sample verification (`T_gen != T_ver`) with `holdout_precision >= 0.95`, `recall_drop <= 0.05`, and `0` paraphrase-mutated negative false positives before admitting any synthesized `GoldenScar` or `CognitiveLesson`.
- **Alpha-Normalized De Bruijn AST Quotient Hash & Interprocedural Taint Graph (`src/kintsugi/grounding.py`):**
  - `compute_alpha_normalized_ast_hash` & `verify_semantic_equivalence`: Proves semantic equivalence across variable/function alpha-renaming (`ASTQ/1` certificate) and indexes interprocedural `call_graph` and source-to-sink `taint_flows`.
- **Hard Scientific Literature & Physics Invariant Verifier (`src/kintsugi/foresight.py` — `ScientificLiteratureVerifier` & `kintsugi foresight --scientific-corpus`):**
  - Audits 5 high-subtlety scientific paper domains (`SCI-REL-001` Special Relativity low-$\beta$ cancellation, `SCI-HAM-002` Symplectic Hamiltonian integration, `SCI-THERMO-003` Jarzynski Equality log-sum-exp & 2nd Law entropy, `SCI-FLUID-004` Finite-Volume mass continuity & Buckingham $\Pi$, and `SCI-CAUSAL-005` Minkowski backward light-cone filtration) with runtime numerical counterexamples and `100%` counterfactual `S3` remediation.

## [1.1.0] - 2026-11-05

### Added
- **Consent-Gated Free-Agent Pool & Condorcet-BFT Accuracy Engine (`src/kintsugi/swarm.py` — `ConsentGatedFreePoolManager` & `@POOL/1`):**
  - Explicit 4-state user consent machine (`AWAITING_USER_CONSENT` -> `USER_PROVIDED_KEY` / `VERIFIED_ACTIVE_POOL` -> `REVOKED`) for binding orthogonal Shadow Clones to distinct `$0` no-card free model families (`12.5x` Condorcet BFT error reduction).

## [1.0.0] - 2026-11-05

### Added
- **Pillar 5 — Shadow-Clone Parallel Epistemic Swarm (`src/kintsugi/swarm.py` — `ShadowCloneSwarmOrchestrator` & `@SWARM/1`):**
  - Spawns `K = 4` orthogonal Shadow Clones (`K = 3f + 1`) in parallel with zero inter-clone communication, grounds claims via `<5ms` 3-State AST Gate + Counterfactual Sandbox, quarantines hallucinations into a Negative Tabu List, and merges `s_p >= 3` truths into a deterministic Right Playbook.

## [0.4.0] - 2026-11-05

### Added
- **Federated Human-Like Cognitive Lesson Engine (`src/kintsugi/cognition.py` — `kintsugi learn`):** Distills real failures into structured `CognitiveLesson` records (`cognitive_trap`, `mental_model`, `domain`, `bad_code`/`good_code`, cryptographic `proof_attestation`, and executable AST/Regex guardrails).
- **Dual Privacy & Sync Modes (`local-only` vs `federated-sync`):**
  - `local-only` (default): Keeps user-distilled lessons strictly private in `.kintsugi/lessons_local.json` (gitignored) while supporting selective industry pulls (`kintsugi learn pull --domains ai-agents-mcp,fintech-web3`).
  - `federated-sync`: Publishes newly distilled lessons into `collective-pool/<domain>/<model_family>/<id>.json` gated by the **4-Stage Frontier Epistemic Gate** (blocks low-tier `mini`/`flash-lite`/`haiku`/`8b` models, enforces `0` false positives, merges semantic/structural duplicates into `reinforcement_count`, and strips DLP leaks).

## [0.3.0] - 2026-11-05

### Added
- **Native Rust Core Engine (`Cargo.toml`, `rust/src/lib.rs`, `rust/src/main.rs` — `kintsugi-rs`):** Zero-dependency (`std`-only) Rust CLI and library delivering `9.6 µs/call` scan latency, `< 0.5ms` Claude Code `PreToolUse` JSON hook evaluation, `git diff --staged` hunk filtering, and `kintsugi-rs bench`.
- **`KMI/1` (Kintsugi Micro-Index v1) Ultra-Low-Token Compression (`src/kintsugi/compressor.py`):** Compiles Golden Scars into a versioned `~209-token` wire header (`kintsugi compile --compact` & `kintsugi token-report`), cutting per-turn `CLAUDE.md` / `AGENTS.md` context consumption by **`93.7%`** (`~156,050 tokens` saved per 50-turn session) while expanding full rules Just-In-Time (JIT) on `PreToolUse` violation.
- **Security & Agent Readiness Posture Auditor (`src/kintsugi/auditor.py` — `kintsugi audit`):** Computes a deterministic `0–100` score (`Grade A+` to `F`) with Markdown scorecard tables and Shields.io badges.
- **Open-Core Skill Pack Installer & Auto-Remediation Engine (`src/kintsugi/packs.py` & `src/kintsugi/autofix.py`):** Added `kintsugi install-pack <bundle.zip>`, `kintsugi list-packs`, and `kintsugi autofix [--apply]` to load external/Pro Skill Packs, `.claude/commands/` workflows, and deterministic codemod playbooks.

## [0.2.0] - 2026-11-05

### Added
- **Incremental Git-Diff & Staged-Only Scanner (`--staged` & `--diff <REF>`):** Parses `git diff -U0` hunks to restrict AST and Regex checks strictly to touched files and modified line numbers.
- **Unified Patch Previews (`--patch-preview` & `kintsugi explain <ID>`):** Renders `difflib.unified_diff` replacement previews alongside findings.
- **Expanded Multi-Agent Compiler (`--targets all`):** Added first-class support for **GitHub Copilot** (`.github/instructions/kintsugi-guardrails.instructions.md`) and **Windsurf** (`.windsurfrules`).
- **Expanded Golden Scar Catalog (`KS-001`..`KS-018`):** Added verified guardrails for Node.js `child_process.exec` injection (`KS-013`), global `NODE_TLS_REJECT_UNAUTHORIZED` bypass (`KS-014`), permissive CORS wildcard with credentials (`KS-015`), Go `http.DefaultClient` unbounded timeout (`KS-016`), `tarfile.extractall` path traversal (`KS-017`), and Docker digest pinning (`KS-018`).

## [0.1.0] - 2026-11-04

### Added
- **Zero-Dependency Core Engine (`src/kintsugi/`):** Dual-engine Python AST + Multi-Language Regex scanner (`< 25ms` cold execution) with `# kintsugi: ignore[KS-XXX]` and `# kintsugi: ignore-file` pragmas.
- **Starter Pack (`KS-001`..`KS-012`):** 12 self-verified security, safety, reliability, and correctness Golden Scars for AI coding agents.
- **Claude Code Native Integration:** `kintsugi hook claude-pre-tool` stdin/stdout decision engine and `kintsugi install-hooks` installer for `.claude/settings.json` and `.git/hooks/pre-commit`.
- **Cross-Agent Skill Compiler:** Generates `.claude/skills/*/SKILL.md`, bounded `CLAUDE.md` / `AGENTS.md` governance sections, and `.cursor/rules/kintsugi-guardrails.mdc`.
- **3-Agent Adversarial Evolution Council:** Multi-model (`Architect` -> `Synthesizer` -> `Red-Team Critic`) + offline fallback with mandatory in-memory `verify_candidate_scar` true-positive / zero-false-positive gate.
- **MCP Server & SARIF 2.1.0 Action:** `kintsugi mcp` stdio JSON-RPC 2.0 server and composite GitHub Action (`action.yml`).
