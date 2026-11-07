# Changelog

All notable changes to `kintsugi-harness` are documented in this file.

## [2.0.0] - 2026-11-07

### Added
- **Multi-Language Zero-Dependency Structural AST-Lite Analyzer (`_StructuralCallExtractor` in `src/kintsugi/scanner.py`):**
  - Replaces fragile character-distance regex caps on JS/TS/Go/Rust files with deterministic balanced-delimiter scope extraction (`_StructuralScope`), comment masking that preserves exact line numbers and template-literal `${...}` expressions (`_mask_comments_preserve_newlines`), and whitespace-verified call/object span extraction across arbitrarily deep nested callbacks and multi-kilobyte comments (`<0.2ms` per file).
  - Enforces structural verification for `KS-013` (Node.js `exec`/`execSync` template-literal command injection), `KS-014` (`NODE_TLS_REJECT_UNAUTHORIZED = '0'` global TLS bypass), `KS-015` (permissive wildcard CORS `origin: "*"` + `credentials: true` across arbitrary property ordering and nested middleware objects), and `KS-016` (Go `http.Get`/`http.Post`/`http.DefaultClient` calls missing bounded `http.Client{Timeout: ...}`).
- **4-Pillar Autopoietic Evolution Creed (`@CREED/1` in `src/kintsugi/compiler.py`):**
  - Embeds the bilingual (VI/EN) 4-Pillar Self-Evolving Philosophy (*"không có kết quả mới cho cách làm cũ"*: 1. Break the Rut / 2-Strike Pivot, 2. Tool Synthesis & Skill Codification, 3. Evolve from Cracks & Errors, 4. Self-Pruning & Natural Selection) into `SkillCompiler.render_root_governance_block()` across `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/kintsugi-guardrails.mdc`, `.github/instructions/kintsugi-guardrails.instructions.md`, and `.windsurfrules`.
- **1-Step Clean Open-Source Skill Compilation (`kintsugi compile --starter-only` in `src/kintsugi/cli.py`):**
  - Compiles strictly from the 16 public starter scars (`get_starter_scars()`) without merging local workspace private scars, ensuring zero private data leakage in open-source repositories in a single command.
- **Expanded Unit Test Suite (`tests/test_kintsugi.py`):**
  - Added 4 structural AST-Lite & performance benchmark unit tests (`43/43` tests passing).

## [1.9.0] - 2026-11-07

### Added
- **OpenMontage Cinema Director's Cut Extension Package (`@OPENMONTAGE_CINEMA/1` — `src/kintsugi/cinema.py`, `kintsugi cinema`, and MCP tool `kintsugi_cinema_produce`):**
  - **Live 3-Minute Director's Cut Demo Video Showcase:** Published full 24-shot (`180.0s`) showcase at `https://www.youtube.com/watch?v=tfo2QYUU-c8`.
  - **Hardened On-Demand OpenMontage Auto-Puller (`OpenMontagePackageManager` · `I-PULL-1..8`):** Automatically clones `https://github.com/calesthio/OpenMontage.git` into `.kintsugi/extensions/openmontage/` with git hooks, submodules, symlinks, and file protocols disabled (`-c core.hooksPath=/dev/null -c submodule.recurse=false -c core.symlinks=false -c protocol.file.allow=never`), strips symlink escapes, and mounts the `kintsugi-directors-cut-v4.yaml` chapter-chunked pipeline definition.
  - **Multi-Provider Video Generation Router (`MultiProviderVideoRouter` · `I-R-1..7`):** Supports `veo` (`Google Veo 3.1 Quality`), `muse` (`Meta Muse AI 2B Free Pool`), `kling` (`Kling 2.0 Master`), `runway` (`Runway Gen-3 Alpha Turbo`), `luma` (`Luma Ray2`), `pika` (`Pika 2.2`), `hailuo` (`Hailuo MiniMax Director`), `sora` (`OpenAI Sora`), and `wan` (`Alibaba Wan 2.1 Open-Source`), with runtime `capabilities()` and non-stretching `chapter_subchunks` (`playback_rate = 1.0`).
  - **Dual Visual Style Optimizer (`VisualStyleOptimizer` · `I-S-1..4`):** Optimizes prompts, camera/lens physics, and deterministic RGB LUTs for user-selected `live_action` (Photorealistic Human Cinema on ARRI Alexa LF + `LUT_KODAK_2383_ARRI_ALEXA_LF_V4`) vs `animation` (2D/3D Studio Animation + `LUT_ANIMATION_CEL_VIBRANCE_V4`), strictly isolating positive DNA from `negative_guardrail` and stripping control/prompt-injection sequences.
  - **Mandatory 6-Gate Component Video QA Verifier (`ComponentVideoQAVerifier`):** Enforces (1) Script-to-Frame Discrepancy Verification, (2) Borderless Frame Hygiene (`0%` 35mm sprocket holes), (3) Character Wardrobe & Collar DNA Lock (`LONG-SLEEVED full-length sleeves buttoned at wrists`, `clean bare throat`, `0` logos), (4) Visual Style Fidelity, (5) Inter-Frame Motion Energy Integrity (`0` frozen clips), and (6) Integer-Tick Audio-First Sync (`|video_ticks - audio_ticks| <= 1` frame) + sample-exact J-cut (`-16320` samples @ 48kHz) / L-cut (`+21600` samples @ 48kHz) timeline bridges.
  - **Self-Evolving Filmmaking Engine (`CinemaEvolutionEngine` · `@CINEMA_EVOLVE/1`):** Seeded with 12 battle-tested Cinema Golden Scars (`CS-001`..`CS-012`) distilled from 4 rounds of Multi-Agent Council audits, emitting a 4-hash cryptographic `certificate_bundle` (`pull_pin_hash`, `adapter_capabilities_hash`, `gate_certificate_hash`, `scar_set_hash`).

## [1.8.0] - 2026-11-07

### Added
- **Universal Drop-In Third-Party Harness Integrator & Federation Engine (`@HARNESS_BRIDGE/1` — `src/kintsugi/integrator.py` & `kintsugi integrate`):**
  - **10-Format Auto-Discovery & Pure-Function Quarantine Pipeline (`discover_harnesses`, `ingest_and_analyze`):** Automatically discovers and parses `CLAUDE.md`, `.claude/settings.json`, `SKILL.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules`, `.roo/rules/*.md`, `.github/copilot-instructions.md`, `.aider.conf.yml`, and `.zip`/`.tar.gz` archives into canonical `HarnessIR` without mutating user files.
  - **7-Layer Zero-Trust Quarantine & Non-Execution Invariant:** Blocks `zip-slip` (`../`), Windows reserved device names (`CON`, `NUL`, `COM1`..`LPT9`, ADS `:`), symlinks, archive bombs (`MAX_COMPRESSED_BYTES = 10 MB`, `MAX_INFLATED_BYTES = 25 MB`, `MAX_COMPRESSION_RATIO = 25:1`), nested archives, duplicate JSON/YAML keys, unsafe YAML tags (`!!python/object`), Trojan Source bidi overrides (`KS-019`), and prompt injection (`KS-022`). Redacts high-entropy secrets before persistence and classifies third-party hooks/MCP servers as `elevate_required` (`capabilities_granted = []`, never auto-executed).
  - **3-Stratum Authority Model ($A \succ B \succ C$) & Joint `DPLL SAT` + `Exact Semiring Difference Logic` Verifier (`ExactSemiringDifferenceSolver`, `JointSATDifferenceVerifier`):** Protects Stratum A (`KS-*` core invariants) as non-abducible, solves conditional rules $P \rightarrow S$ with Core $\neg S$ as `CONDITIONAL_BLOCKED_SCENARIO` when $P$ is absent, auto-drops conflicting Stratum C preferences, and solves integer (`math.floor`/`math.ceil` bound tightening) and rational (`(Fraction, strict_bool)`) difference constraints without floating-point epsilon hacks.
  - **Signed `@PROOF_DAG/1` Integration Receipts & Reversible Bounded Mount/Eject (`mount_harness`, `eject_harness`, `revalidate_mounted_on_scanner_upgrade`):** Emits length-delimited HMAC-SHA256 receipts (`receipt.proof`), mounts compiled `@KML/1` guards inside bounded `<!-- KINTSUGI:INTEGRATED:<id>:START/END -->` blocks preserving 100% of user edits on `--eject`, and automatically re-scans mounted packs upon scanner upgrades.

## [1.7.0] - 2026-11-07

### Added
- **Direction 5 — Cryptographically Signed Compliance & Change Evidence Bundles (`@PROOF_DAG/1` & `.kintsugi/audit.proof` — `src/kintsugi/compliance.py` & `kintsugi verify`):**
  - Emits full-envelope HMAC-SHA256 signed compliance manifests binding exact patch digests (`patch_sha256`), source-bound `@LOGIC/2` SAT/MUS & Stratified Datalog proofs, `@RECURRENCE_SHIELD/1` (`CM-031`) entropy scans, and `@ZK_AST_DIFF/1` structural commitments to **5 mandatory regulatory controls**:
    1. **SOC2 Type II `CC6.1`:** Logical Access Security & MFA Step-Up Enforcement.
    2. **SOC2 Type II `CC6.6`:** Session Revocation After Credential Rotation & OTP Replay Prevention.
    3. **SOC2 Type II `CC7.2`:** Outbound Secret & High-Entropy Leak Prevention (`CM-031`).
    4. **ISO/IEC 27001:2022 `A.8.28`:** Zero-Knowledge Secure Coding & Structural AST Gate Preservation.
    5. **EU AI Act `Article 15`:** Accuracy, Robustness & Fallacy-Free Automated Reasoning.
  - Separates provisioned enterprise keys (`ENTERPRISE_PROVISIONED_SEAL` with `require_provisioned_key=True`) from local development keys (`LOCAL_DEV_ATTESTATION`) and invalidates immediately if any outer or inner field is modified.
- **Scope- & Reachability-Aware Structural AST Commitment (`@ZK_AST_DIFF/1` — `ZeroKnowledgeASTDiffVerifier`):**
  - Resolves `import` / `from ... import ... as ...` aliases, detects local gate shadowing (`def verify_mfa`), and performs control-flow reachability analysis so security gates placed after `return`/`raise` or inside `if False:` dead branches are rejected (`COUNTEREXAMPLE_FOUND`).
- **Open Reproducible Autonomous Engineering Benchmark & Deterministic Replay Suite (`@EVAL_SUITE/1` — `ReproducibleEvalSuite` & `kintsugi eval`):**
  - Evaluates 6 deterministic security & patch regression tasks (`EVAL-AUTH-001` .. `EVAL-MHS-006`) plus 3 benign negative controls with measured 3-arm ablations (`6/6 PASS 100.0%`, `0.0%` false-positive rate, `6/6` signed compliance proofs emitted).

## [1.6.0] - 2026-11-06

### Added
- **5-Pillar Neuro-Symbolic Logical Reasoning Engine (`@LOGIC/2` — `src/kintsugi/logic.py` & `kintsugi logic --benchmark`):**
  1. **`DPLLSatSolver` (Propositional SAT/UNSAT & Subset-Minimal Unsatisfiable Core `MUS`):** Deterministic DPLL solver with Unit Propagation, reason-clause tracking, total model completion & independent verification, and deletion-filtered Subset-Minimal Unsatisfiable Core (`MUS`) extraction with `subset_minimality_verified` proof certificates.
  2. **`StratifiedDatalogEngine` (First-Order Horn-Clause & Stratified Negation-as-Failure Reasoner):** Enforces Datalog Range-Restriction (`Safety`), predicate arity consistency, and exact Stratification via Strongly Connected Components (rejecting unstratified negative recursion cycles). Executes Semi-Naive Least-Fixed-Point Forward Chaining and Cycle-Safe Backward Chaining with Proof-Carrying Derivation DAGs (`ProofDAG/1`) and Closed-World Negation Certificates.
  3. **`DifferenceLogicSolver` (Multi-Variable Relational & Difference Logic $x_i - x_j \le c$):** Uses exact rational + symbolic infinitesimal lexicographic arithmetic `(Fraction, int)` over a super-sourced potential graph (handling strict `<`, `<=`, `>=`, and `==` with zero IEEE-754 floating-point roundoff). Emits verified rational potential assignments on `SAT` and exact negative-weight directed cycle certificates + subset-minimal conflict cores on `UNSAT`.
  4. **`FormalFallacyAndCoTAuditor` (`@FALLACY_GUARD/1` — Formal Argument & CoT Verifier):** Audits structured reasoning steps for Affirming the Consequent, Denying the Antecedent, Circular Reasoning (`Petitio Principii`), Contradictory Premises (`Ex Falso Quodlibet`), and Non-Exhaustive Case Partitions, emitting concrete countermodels when invalid.
  5. **`AbductiveHittingSetDiagnoser` (Reiter's Subset-Minimal Hitting-Set Root-Cause Abduction):** Computes all subset-minimal hitting-set diagnoses over observed symptoms, certifying both symptom coverage and element-by-element necessity (`H \ {h}` witness).

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
