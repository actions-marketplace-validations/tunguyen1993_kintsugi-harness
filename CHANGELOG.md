# Changelog

All notable changes to `kintsugi-harness` are documented in this file.

## [3.1.1] - 2026-11-26

### Added & Hardened
- **Zero-Dependency Cloud Sandbox Edition (`cloud-sandbox/`):**
  - Hardened standalone Python `3.9+` stdlib edition with pinned SHA-256 GitHub self-updater (`bootstrap.py --require-pin --require-full-sha --expected-bootstrap-sha256 ... --expected-manifest-sha256 ...`), POSIX `dir_fd` (`O_NOFOLLOW`) safe extraction, offline `.tar.gz`/`.zip` archive fallback (`--source-archive`), and clean-environment boot smoke verification prior to atomic swap.
  - Added **2-Process OS Subprocess IPC Truth Gate** (Python and Node.js isolated runners with runtime-counted assertions) verifying real `BROKEN -> FIXED` state transitions inside the 5-gate closed-loop scar evolution pipeline.
  - Upgraded the sandbox AST+regex security scanner with `INCOMPLETE_SCAN` fail-closed defaults, exact rational `fractions.Fraction` financial conservation/FX/tick verification, and a read-only transaction policy guard (`tx-guard`).
- **Apache-2.0 Open Source Cleanup & CI Reliability (`.github/workflows/ci-and-arena-verification.yml`, `README.md`, `AGENTS.md`, `CLAUDE.md`):**
  - Rewrote `README.md` into a concise, developer-first Apache-2.0 open-source reference covering OpenAI Codex CLI (`~/.codex/config.toml`), Claude Code, Cursor, Windsurf, Cline, Zed, MCP (`kintsugi mcp --profile v3`), and optional local-only BYOK multi-model review (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`).
  - Removed legacy tiered paywall pricing copy, external token-provisioning flows, and unreleased model codenames across docs, rules, and skill templates.
  - Hardened `.github/workflows/ci-and-arena-verification.yml` with `timeout-minutes: 45` on both jobs, `PYTHONDONTWRITEBYTECODE: "1"` in the pytest step, and hybrid `test` (masks `0,1,2,4,8,16,31`) + `check --all-targets` (remaining 25 masks) on `aarch64-apple-darwin` while keeping the full 32-mask `cargo +stable test` powerset on Linux `x86_64` and `aarch64` runners.

## [3.0.1] - 2026-11-25

### Security & Soundness Hardening
- **Fail-Closed `s3-audit` Missing/Unreadable/`..`/Empty Targets & Multi-Call Exact Suppression (`rust/src/audit/s3.rs`, `rust/src/cli/audit_cmds.rs`, `rust/src/audit/prover_extensions.rs`):**
  - Eliminated false `PASS_S3_PROVEN` on missing, unreadable, symlink, `..` parent-dir, or 0-file directory targets: now emits `assurance_tier = "NO_INPUT"`, `verdict = "FAIL_NO_INPUT"`, `strict_verdict = "NO_INPUT"`, `missing_targets`, and exit code `2` (merged cleanly across multi-target invocations).
  - Replaced single-match per-line scanning and range-containment suppression with per-column `(line, col, kind)` seam tracking, multi-sink `extract_write_sinks`, and exact call-identity legacy suppression so sibling and nested unguarded reads (e.g. `open(safe, "w", encoding=open(other).read())`, `fs.writeFileSync(safe, fs.readFileSync(other))`) are never suppressed.
- **7-Domain Obligation Prover Hardening (`rust/src/audit/{obligation_prover,prover_extensions}.rs`):**
  - `SOL_SAFE_ERC20`: Requires exact unaliased `SafeERC20.sol` import, contract-scoped (or `global`) `using SafeERC20 for <ERC20Type>`, fail-closed verified receiver typing (local/state declaration or explicit `IERC20(...)` cast), rejection of `this`/`super`/local `function safeTransfer`, and general typed variable/parameter shadowing detection.
  - TypeScript/JS `CMD_EXEC`: Replaced heuristic options checks with a depth-0 options-object parser handling 2-arg/3-arg/4-arg overloads, spreads, shorthand `{ shell }`, getters/setters/methods/quoted generators (`*"shell"()`), quoted/computed keys, `__proto__`, and inline comments without cross-arg or nested-object downgrades.
- **Freeze-Aware `ContextEnvelope/3`, Strict `--max-tokens`, Disjoint Lexicon & Cross-Runtime `DeliveryTelemetry/1` Parity (`rust/src/audit/{capsules,low_tier_lexicon,context_envelope,delivery_telemetry}.rs`, `rust/src/cli/audit_cmds.rs`, `src/kintsugi/evolution/delivery_telemetry.py`):**
  - Wired `try_load_frozen_ids` / `--telemetry-store` into `context`, `task-pack`, and `hook claude-post-read --workspace` (excluding frozen IDs before ranking & budgeting), enforced strict `estimated_tokens <= max_tokens` with UTF-8-safe clipping and honest `capsule_ids`/`lexicon_ids` across both `context` and `task-pack`, and eliminated overlapping triggers in `LT-009` and benign false-fires in `LT-016`/`LT-074`.
  - Protected arbitrary non-telemetry JSON files (`UNRECOGNIZED_TELEMETRY_STORE`), deduplicated multi-file patch outcomes per `(client, session_id, patch_digest, item_id)` via `applied_outcomes` (with legacy `v3.0.0` backfill and `|` banned in IDs), synchronized strict Rust↔Python envelope/efficacy field validation, `u32` saturating counters, late `included_in_input` persistence, and fail-closed non-Unix lock timeout.
- **MCP `kintsugi_read_with_context` POSIX `dir_fd` Traversal, Bounded Read & CRLF Snapshot Parity (`src/kintsugi/mcp_server.py`):**
  - Replaced `.resolve()` + unbounded `read_bytes()` with kernel-enforced step-by-step POSIX `dir_fd` (`O_DIRECTORY | O_NOFOLLOW`) traversal, `fstat` `S_ISREG` verification, `10 MiB` bounded reads, strict `max_tokens > 0` validation, CRLF-verbatim SHA-256 `source_digest` parity (1 retry + fail-closed `SNAPSHOT_DIGEST_MISMATCH`), and default `telemetry_store` pointing to `<ledger_dir>/delivery_telemetry.json`.

### Added & Fixed
- **CLI `--profile v3` Enablement (`src/kintsugi/cli.py`, `tests/test_v3_breakthrough_suite.py`):**
  - Added `"v3"` to `kintsugi mcp --profile` choices so `python3 -m kintsugi mcp --profile v3` serves all `26` MCP tools end-to-end over stdio (while preserving `default=9`, `nextgen=19`, `build3=23`) with a live stdio JSON-RPC subprocess test and CRLF/TOCTOU regression tests.
- **Sanitized Low-Tier Lexicon Benchmark Artifact & Honest Claim Scoping (`benchmarks/low_tier_lexicon_ab_results_v3.json`, `README.md`, `CHANGELOG.md`):**
  - Published the DLP-sanitized 4-round (`56 × 3 = 168` synthetic/held-out blind zero-hint runs: `49.4% → 95.8%`, `+46.4 pp`) + Round 5 Go/Docker/CI (`0/7 → 6/7`, `+85.7 pp`) benchmark artifact with explicit non-leaderboard caveats, scoped `"0 false PROVEN"` to the negative corpus and `"0 tokens"` to the benign fixture corpus, and synchronized `3.0.1` version metadata across Rust, Python, Cortex manifest, and tests.

## [3.0.0] - 2026-11-25

### Added
- **7-Domain Typed Obligation Prover (`rust/src/audit/{obligation_prover,prover_extensions}.rs`, `s3.rs`):**
  - Expanded honest 4-way static verification (`PROVEN | VIOLATED | UNKNOWN | UNSUPPORTED`, `0` false `PROVEN` on negative corpus) beyond `CMD_EXEC` and `SQL_EXEC` to five new high-impact security domains: `TSX_XSS` (React `.tsx`/`.jsx`), `PATH_CONFINE` (Python/TS/JS/Rust), `CRYPTO_MAC_BIDI` (Python/TS/JS), `SOL_REENTRANCY_CEI` (Solidity `.sol`), and `SOL_SAFE_ERC20` (Solidity `.sol`).
  - Hardened TypeScript `CMD_EXEC` against shell trampolines (`spawnSync('/bin/sh', ['-c', ...])`) and opaque options variables, and narrowed `s3.rs` legacy seam dedup so intermediate unguarded reads/comparisons are never suppressed.
- **80-Entry Low-Tier Model Failure Lexicon (`LT-001..LT-080`, `rust/src/audit/low_tier_lexicon.rs`, `rules/matcher.rs`):**
  - Added symbol-scoped, zero-bloat JIT failure lexicon (`kintsugi-rs lexicon`) spanning Python, OWASP Security, TypeScript/NestJS/MySQL (`LT-035..LT-042`), Solidity 0.8.24/DeFi (`LT-043..LT-050`), Online Bounty/Audit Scars (`LT-051..LT-062`), React/Next.js/Vue FE V2 (`LT-063..LT-070`), and Go/Rust/Docker/GitHub Actions Supply-Chain (`LT-071..LT-080`).
  - Added polyglot extension detection (`.sol`, `.vue`, `.yml`/`.yaml`, `Dockerfile.*`) and verified `0` matches / `0` tokens on benign fixture corpus across Python, TS, Rust, and Go.
- **Universal Truth Gate, 9 Signature-Guarded Capsules & Transactional Patch Controller (`src/kintsugi/evolution/{contract_ledger,fast_learner,patch_transaction}.py`, `rust/src/audit/capsules.rs`):**
  - Enforced fail-closed teacher provenance (`ALLOWED_FIRST_PARTY_HOSTS` + cryptographic thinking signature verification), explicit mathematical precondition on `CAP-FIN-ERC4626`, 4 falsifiable domain contracts (`CONTRACT-CM-IDEMPOTENCY`, `CONTRACT-CM-DECIMAL-FX`, `CONTRACT-MM-ERC4626-BOUNDED`, `CONTRACT-MM-LEDGER-CONSERVATION`), and 2-Strike / Dead-Scar Auto-Freeze.
- **Multi-Client `ContextEnvelope/3` & `DeliveryTelemetry/1` (`rust/src/audit/{context_envelope,delivery_telemetry}.rs`, `src/kintsugi/evolution/delivery_telemetry.py`, `src/kintsugi/mcp_server.py`):**
  - Added `kintsugi-rs context`, `kintsugi-rs task-pack`, `kintsugi-rs hook claude-post-read`, `kintsugi-rs telemetry record|report`, and MCP `v3` profile (`26` tools: `kintsugi_read_with_context`, `kintsugi_low_tier_lexicon`, `kintsugi_delivery_telemetry`) while preserving backward-compatible counts for `default=9`, `nextgen=19`, `build3=23`.
  - Enforced cross-process `<store>.lock` (`flock` on Unix + atomic fallback), top-down ancestor symlink rejection, 8 MiB pre-write cap, `try_load_frozen_ids` fail-closed loader, sticky-freeze latching, and unshown-capsule efficacy protection (`efficacy_updated` only when `included_before_first_patch == true`).

### Fixed
- **UTF-8 Byte Alignment in `StatefulMasker` & Call Extractors (`rust/src/audit/{ct2_seams,obligation_prover,prover_extensions}.rs`):**
  - Emitted `ch.len_utf8()` ASCII spaces per masked multi-byte UTF-8 character and stepped balanced extractors by `rch.len_utf8()` with `.get(...)` bounds checking, eliminating UTF-8 char-boundary panics and offset drift on Unicode/emoji strings and comments.
- **Cross-Platform CI Hardening (`.github/workflows/ci-and-arena-verification.yml`, `tests/security/test_hermetic_worker.py`, `rust/tests/c_abi_and_mutation_suite.rs`):**
  - Upgraded `macos-14` → `macos-15` (`aarch64-apple-darwin`), caught Linux Landlock/seccomp `PermissionError` on `socket.socket()`, guaranteed kernel `EPIPE` confirmation prior to `BrokenPipe` tests, and constructed synthetic redaction fixtures dynamically.

## [2.4.1] - 2026-11-21

### Security & Guardrails Hardening
- **Argv / AST Shell Protection (`KH-SEC-001`, `KH-R2-SEC-01`):** Replaced naive string regex matching with structured quote-aware POSIX shell tokenization & canonical path auditing across both Python (`src/kintsugi/hooks.py`) and Rust (`rust/src/lib.rs`), blocking split/merged `rm` flags, wrapper verbs (`timeout`, `sudo`, `env`, `nohup`, `nice`, `xargs`), `sh -c`/`bash -c` nesting, `git -C` global flags (`reset --hard`, `push -f` without `--force-with-lease`, `clean -fd`), pipe-to-shell fetch/base64 chains, symlink traversals, and destructive operations on OS/user roots (`/home`, `/root`, `/var/lib`, `/var/log`, `$HOME/...`, `${HOME}/...`, `~/...`) while permitting scoped build/cache and temp directories.
- **Python Constant Folding & Indirect `shell=` Prevention (`KH-SEC-004`, `KH-R2-SEC-02`):** Upgraded `_PythonASTVisitor` (`_const_eval`, `_const_bool`) and Rust `KS-002` checks to fold comparison/boolean expressions (`shell=(1 == 1)`, `shell=not False`, `shell=bool(1)`), module/symbol aliases, `getattr(__builtins__, ...)`, `py_sql_injection_concat`, JS/TS structural `new Function` / SQL string concatenation, and fail-closed rejection when `subprocess(..., shell=...)` cannot be proven statically `False`/`0`/`None`.
- **Untrusted Inline Ignore & Natural-Language Prompt Injection Defense (`KH-SEC-002`, `KH-R2-SEC-03`, `B19`, `B20`):** Disabled untrusted `kintsugi: ignore-file` directives by default in `KintsugiScanner`, CLI `scan` (both inline and file-level ignores disabled unless explicitly opted in or listed in external `.kintsugi/policy.json`), MCP `kintsugi_scan_code` / `kintsugi_verify_logic`, PreToolUse hooks (`KS-S3-IGNORE-BYPASS`), and Rust `scan_path`/`evaluate_pre_tool_json`; added cross-line natural-language indirect prompt-injection detection under `KS-012` / `KS-S3-01`.
- **Full Ledger & Fail-Closed Hook Parity (`KH-SEC-003`, `KH-HOOK-001`):** Persisted all `KS-001..KS-024` built-in CRS rules (`1,797` verified scars) into `.kintsugi/scars.json` & `.kintsugi/scars.kml` (escaping raw bidirectional Unicode control characters safely), enabled `ensure_builtin_crs=True` on runtime CLI & MCP entrypoints, and rejected non-object `tool_input` / `toolCall` / `args` payloads fail-closed.

### Fixed
- **MCP Server, Cross-Platform CRS, Evolution, Swarm, Benchmarks & CI (`KH-MCP-001..003`, `KH-FUNC-001`, `KH-R2-FUNC-04`, `KH-EVO-001..002`, `KH-SWARM-001`, `KH-BENCH-001..002`, `KH-R2-BENCH-05`, `KH-REL-06`, `KH-CI-01`, `KH-CI-07`):**
  - Added `python3 -m kintsugi.mcp_server` stdio entrypoint, real AST+scanner code analysis in `kintsugi_verify_logic`, and in-memory telemetry for read-only `kintsugi_scan_code`.
  - Added Linux GCC/Clang + pure-Python ELF64 `.kint_ro` fallback in `crs_engine.py`, plus dependency-free `finite_domain_patch_equivalence_verified` proof & honest `z3_available` reporting when optional `z3-solver` is absent.
  - Enabled auto-loading `evolution_memory/lessons_local.json` (`41` empirical lessons), upgraded `EvolutionCouncil._synthesize_generalized_pattern` semantic/boolean/quote generalization (`KH-EVO-002`), and made `transpile_scar_dict_to_kml` idempotent.
  - Enforced `FREE` tier parallel cap (`<= 2` subagents + deferred queue), removed fake verbose token baseline floor in `compressor.py`, synchronized `2.4.1` version metadata everywhere, clearly labeled local SWE-like / GAIA-like evaluation artifacts as `synthetic` suites, and added `.github/workflows/{ci-and-arena-verification,scorecard}.yml` with Z3 proof extra & `cargo test --all-targets`.

## [2.4.0] - 2026-11-15

### Added
- **Synthesized Empirical Cortex (`collective-pool/synthesized-empirical-cortex/`) & 63 `KS-EMP-*` Empirical Engineering Scars (`.kintsugi/scars.json`, `.kintsugi/scars.kml`):**
  - Distills `972` Cognitive Axioms and `1,581` Causal Atoms across `48` completed verification suites and `85` security/systems research topics, alongside `41` Local Cognitive Lessons, `7` BFT Swarm Playbooks, and `63` `KS-EMP-001..KS-EMP-063` empirical engineering guardrails (expanding the verified ledger to `1,789` scars with `0` shield quarantines) into `collective-pool/synthesized-empirical-cortex/empirical_cortex_v240.kml` and `MANIFEST.json`.
- **Harness Architecture Evolutions (`@CREED/1 v2.1`, `@SWARM_DISPATCH/1`, `@MODEL_MATRIX/1`, `@DUAL_COUNCIL/1`, `@NEVER_SOLO_GATE/1`, `@HARNESS_HOT_RELOAD/1`, `@OSS_PR_LIFECYCLE_GUARD/1`):**
  - Upgrades `@CREED/1` to all **5 Pillars** (`P1:MUTATE` 2-strike dead-path pivot, `P2:SYNTH` 2x manual workaround $\to$ 1-step tool, `P3:SCAR` error trace $\to$ verified rule, `P4:PRUNE` overwrite verbose paths, and `P5:CONVERGE` `TRY_ALL(ways) && IF no_new_way_left => PICK_BEST(fastest, cleanest, most_effective)`).
  - Adds Subscription-Aware Parallel Swarm Dispatcher (`compute_swarm_dispatch_plan`, `kintsugi swarm --swarm-plan "<task>"`) and 6-Tier Model Capability Matrix (`get_model_capability_matrix`, `kintsugi swarm --model-matrix`) with automatic task-to-domain shard routing (`route_task_to_domain_shards`), dispatching parallel subagents at `>=3` independent subtasks or `>120s`.
  - Adds **FrontierHarness Eval v1.1 Step-Economics Auditor (`@STEP_ECONOMICS/1`, `R132`)** across both Python (`kintsugi swarm --step-audit <path>`) and Native Rust (`kintsugi-rs step-audit` & `kintsugi-rs swarm-plan`) enforcing `>=60%` shell-batching targets, `<=12` subagent steps, `<=25` task steps/turn, and 2-strike fail-fast pivoting.
  - Encodes `@DUAL_COUNCIL/1`, `@NEVER_SOLO_GATE/1`, `@HARNESS_HOT_RELOAD/1` (zero-token SHA-256 live sync hook), and `@OSS_PR_LIFECYCLE_GUARD/1` (`KS-EMP-062`).
- **Domain-Partitioned Context Compression (`src/kintsugi/compressor.py`, `src/kintsugi/cli.py`, `docs/domains/01..06_*.{md,kml}`, `docs/domains/domain_manifest.json`):**
  - Partitions rules, documentation, and pre-compiled `@KML/1` shards across 6 software engineering domains (`security`, `backend`, `database`, `frontend`, `devops`, `ai_mcp`) via `partition_by_domain()` and `render_domain_kmi_pack()`.
  - Reduces per-turn active token footprint from `3,641 tokens` (16-scar starter pack) to `226 tokens` (`93.8%` global `KMI/1` reduction) or **`~80.5 tokens/turn` (`97.79%` reduction per domain shard)**, and from `414,267 tokens` (`1,789`-scar evolved ledger) to `24,967 tokens` (`94.0%` global `KMI/1` reduction) or **`~175.7 tokens/turn` (`99.96%` reduction per domain shard)**.
- **Bilingual Model Context Protocol (`kintsugi mcp`) Documentation & Domain Filtering (`src/kintsugi/mcp_server.py`, `README.md`):**
  - Documents all **9 MCP Tools**, **2 MCP Resources**, **2 MCP Prompts**, and ready-to-paste `mcpServers` JSON config at the top of `README.md`, and adds optional `domain` filtering to `kintsugi_list_scars`.
- **Unified Reproducible Benchmark Suite (`56/56` tests passing — `49` Python `unittest` + `7` Rust `cargo test`, `~16.2 µs/call` Rust `kintsugi-rs bench` across 36 built-in rules, `Apache-2.0` license).**

## [2.0.0] - 2026-11-07

### Added
- **Multi-Language Zero-Dependency Structural AST-Lite Analyzer (`_StructuralCallExtractor` in `src/kintsugi/scanner.py`):**
  - Replaces fragile character-distance regex caps on JS/TS/Go/Rust files with deterministic balanced-delimiter scope extraction (`_StructuralScope`), comment masking that preserves exact line numbers and template-literal `${...}` expressions (`_mask_comments_preserve_newlines`), and whitespace-verified call/object span extraction across arbitrarily deep nested callbacks and multi-kilobyte comments (`<0.2ms` per file).
  - Enforces structural verification for `KS-013` (Node.js `exec`/`execSync` template-literal command injection), `KS-014` (`NODE_TLS_REJECT_UNAUTHORIZED = '0'` global TLS bypass), `KS-015` (permissive wildcard CORS `origin: "*"` + `credentials: true` across arbitrary property ordering and nested middleware objects), and `KS-016` (Go `http.Get`/`http.Post`/`http.DefaultClient` calls missing bounded `http.Client{Timeout: ...}`).
- **4-Pillar Autopoietic Evolution Creed (`@CREED/1` Machine-Native IR in `src/kintsugi/compiler.py`):**
  - Embeds the 4-Pillar Self-Evolving Philosophy in ultra-dense `@CREED/1` / `@OP/1` machine-native symbolic grammar + English execution laws (`P1:MUTATE` 2-Strike Pivot, `P2:SYNTH` 2x Tool Synthesis, `P3:SCAR` Crack-to-Scar Extinction, `P4:PRUNE` Natural Selection Overwrite) into `SkillCompiler.render_root_governance_block()` across `CLAUDE.md`, `AGENTS.md`, `.cursor/rules/kintsugi-guardrails.mdc`, `.github/instructions/kintsugi-guardrails.instructions.md`, and `.windsurfrules`.
- **1-Step Clean Open-Source Skill Compilation (`kintsugi compile --starter-only` in `src/kintsugi/cli.py`):**
  - Compiles strictly from the 16 public starter scars (`get_starter_scars()`) without merging local workspace private scars, ensuring zero private data leakage in open-source repositories in a single command.
- **Expanded Unit Test Suite (`tests/test_kintsugi.py`):**
  - Added 4 structural AST-Lite & performance benchmark unit tests (`43/43` tests passing).

## [1.9.0] - 2026-11-07

### Added
- **OpenMontage Cinema Director's Cut Extension Package (`@OPENMONTAGE_CINEMA/1` — `src/kintsugi/cinema.py`, `kintsugi cinema`, and MCP tool `kintsugi_cinema_produce`):**
  - **Live 3-Minute Director's Cut Demo Video Showcase:** Published full 24-shot (`180.0s`) showcase at `https://www.youtube.com/watch?v=tfo2QYUU-c8`.
  - **Hardened On-Demand OpenMontage Auto-Puller (`OpenMontagePackageManager` · `I-PULL-1..8`):** Automatically clones `https://github.com/calesthio/OpenMontage.git` into `.kintsugi/extensions/openmontage/` with git hooks, submodules, symlinks, and file protocols disabled (`-c core.hooksPath=/dev/null -c submodule.recurse=false -c core.symlinks=false -c protocol.file.allow=never`), strips symlink escapes, and mounts the `kintsugi-directors-cut-v4.yaml` chapter-chunked pipeline definition.
  - **Multi-Provider Video Generation Router (`MultiProviderVideoRouter` · `I-R-1..7`):** Supports `veo` (`Google Veo 3.1 Quality`), `muse` (`Open-Weights Keyframe Engine`), `kling` (`Kling 2.0 Master`), `runway` (`Runway Gen-3 Alpha Turbo`), `luma` (`Luma Ray2`), `pika` (`Pika 2.2`), `hailuo` (`Hailuo MiniMax Director`), `sora` (`OpenAI Sora`), and `wan` (`Alibaba Wan 2.1 Open-Source`), with runtime `capabilities()` and non-stretching `chapter_subchunks` (`playback_rate = 1.0`).
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
- **Optional BYOK Multi-Model Co-Review (`src/kintsugi/council.py`):**
  - Supports optional multi-provider Bring-Your-Own-Key (BYOK) co-execution (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`) with automatic HTTP 429 failover and local `0600` credential storage.
- **Zero-Loss Anti-Overflow Conversation Compactor (`src/kintsugi/compactor.py` — `kintsugi compact`):**
  - Deterministically strips polling loops, superseded file reads, and verbose logs while preserving 100% of hard anchors and Excel/CSV tabular summaries.

## [1.3.0] - 2026-11-05

### Added
- **2-Team Adversarial Harness Arena (`src/kintsugi/swarm.py` — `RedBlueAdversarialArena` & `kintsugi swarm --red-blue-arena`):**
  - Splits adversarial verification into **Red Team** and **Blue Team** (deterministic `v1.3.0` engine + optional BYOK frontier reviewers) across 5 adversarial campaigns (`ATK-CEGIS-001`..`ATK-PROMO-005`), achieving `5/5` (`100.0%`) containment (`@ARENA/1|ver=1.3.0|campaigns=5/5|containment=100.0%|invariant=KL-HIGH-001|status=PASS`).
- **Lakatosian Proof-And-Refutations CEGIS Loop (`src/kintsugi/foresight.py` — `LakatosCEGISVerifier`):**
  - Enforces 4-state verdict lattice (`PROVED` / `CONDITIONAL` / `REFUTED` / `SURRENDER`), preserves original domain counterexamples in `preserved_original_refutations` when domain cuts occur, and blocks monster-barring (`coverage < c_min` or `domain_cuts` present -> `CONDITIONAL`, never `PROVED`).
- **4-State Sound Symbolic Path & Interval Constraint Solver (`src/kintsugi/grounding.py` — `SoundSymbolicPathSolver`):**
  - Replaces 2-state satisfiability with `UNREACHABLE` / `HOLDS` / `VIOLATED` / `UNKNOWN`, performs correlated linear cancellation (`x - x -> 0`), outward IEEE-754 interval rounding, and blocks taint clearance unless `status == "HOLDS"`.
- **Pearl $do$-Calculus & Counterfactual SCM Identification Verifier (`src/kintsugi/foresight.py` — `CausalDoCalculusVerifier`):**
  - Implements graph surgery ($G_{\overline{X}}$, $G_{\underline{X}}$), moralized ancestral subgraph $d$-separation, 2-SCM non-identifiability witness certificates (`NONIDENTIFIABLE`), and 3-step Abduction–Action–Prediction tagged `SCM_EVALUATED_CONDITIONAL`.
- **Strictly Proper Brier Score & Uncentered Second-Moment Shrinkage Pool (`src/kintsugi/swarm.py` — `BrierMomentShrinkagePool`):**
  - Enforces append-only `before_tick` filtration, abstention baseline penalty $\mathrm{BS}_0 = 0.25$, and simplex optimization over the uncentered second-moment shrinkage matrix $\widehat{M}_\gamma = (1-\gamma)\frac{1}{n}\sum e_i e_i^\top + \gamma T$ to capture both variance and squared bias.
- **Supreme Epistemic Invariant `KL-HIGH-001` (`src/kintsugi/cognition.py` & `enforce_kl_high_001_promotion_guard`):**
  - Forbids promoting `UNKNOWN`, `SURRENDER`, `CONDITIONAL` (domain-cut), `SCM_EVALUATED_CONDITIONAL`, or `EMPIRICAL_CONFIDENCE` into universal `PROVED` (`41` verified frontier lessons in `collective-pool/`).

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
- **Consent-Gated Multi-Model Review Pool & Condorcet-BFT Accuracy Engine (`src/kintsugi/swarm.py` — `@POOL/1`):**
  - Explicit 4-state user consent machine (`AWAITING_USER_CONSENT` -> `USER_PROVIDED_KEY` / `VERIFIED_ACTIVE_POOL` -> `REVOKED`) for binding orthogonal Shadow Clones to distinct user-configured BYOK model families (`12.5x` Condorcet BFT error reduction).

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
- **Skill Pack Installer & Auto-Remediation Engine (`src/kintsugi/packs.py` & `src/kintsugi/autofix.py`):** Added `kintsugi install-pack <bundle.zip>`, `kintsugi list-packs`, and `kintsugi autofix [--apply]` to load external Skill Packs, `.claude/commands/` workflows, and deterministic codemod playbooks.

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
