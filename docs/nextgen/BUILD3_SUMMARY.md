# Kintsugi Build #3 — Cognitive Forge Summary (`feature/build3-cognitive-forge`)

- **Branch:** `feature/build3-cognitive-forge` (branched from Build #2 Round-14 baseline `f21dba0bd9bc3f264d37bb19fa3bcf4ae5eaad54` on `feature/capability-composition-forge`)
- **Build #2 Baseline Status:** Round-14 (`f21dba0`) verified `VERIFIED COMPLETE` (`KH-B2-R13-SEC-001 — VERIFIED CLOSED`) on Linux Python `3.13.5` by independent external audit.
- **Governance:** Owner-gated (maintainer release gate); local commits and local archive only until repository maintainer approves any remote `git push` or merge into `main`.

## 1. Integrated Build #3 Tracks (`Agent A..E`)

1. **Agent A — Hermetic Spawn Worker (`src/kintsugi/runtime/hermetic_worker.py`) & Lifecycle Guard (`src/kintsugi/capability/schemas.py`)**
   - Exports: `HermeticEntrypointSpec`, `HermeticExecutionResult`, `HermeticSpawnRunner`, `PinnedModuleFile`, `pin_module_file`, `build_hermetic_seatbelt_profile`, `probe_linux_landlock_available`, `validate_allowed_import_prefixes`, `validate_safe_callable_attr`, `validate_safe_module_path`.
   - Executes pinned workspace modules inside a fresh `python3 -I -S --worker-mode` OS sandbox (`seatbelt` on macOS, Landlock + seccomp-BPF fail-closed on Linux) over length-prefixed JSON pipes with `O_NOFOLLOW` + `(st_dev, st_ino)` pre/post-execution pinning.
   - **Round-14 Zero-Hook & Primitive-Only IPC Hardening:**
     - Added `extract_exact_hermetic_spec_dict()`, `assert_hermetic_result_type_unmodified()`, and `_normalize_hermetic_context()` using raw `tp_dict` / `safe_exact_str_dict_view` and exact `type(x) is ...` identity checks (eliminating host `isinstance(SecurityContext)` / `.validate_path` preflight leaks).
     - Hardened `_validate_strict_json_value()` with exact primitive type checks, active-ID cycle rejection, and `_MAX_PAYLOAD_NODES = 4096` cap.
     - Tightened `schemas.snapshot_class_lifecycle(cls)` with an internal `absent = object()` closure sentinel so newly injected `_PINNED_LIFECYCLE_ATTRS` (such as monkeypatching `__post_init__` onto `HermeticExecutionResult`) fail closed with `PermissionError` (`UNTRUSTED_CONTRACT_CLASS_TAMPERED`).

2. **Agent B — Typed Capability Graph Synthesis (`src/kintsugi/synthesis/capability_graph.py`)**
   - Exports: `TypedCapabilityGraph`, `SynthesisGoal`, `SynthesisBlueprint`, `SafePathResult`, `TypedPort`, `ExclusionRecord`, `GapKind`, `ParetoCandidate`, `RankedCandidateEntry`, `RankedSynthesisPlan`, `rank_pareto_candidates`, `CANONICAL_UNIT_ALIASES`, `DECLASSIFY_TRANSFORMS`, `SENSITIVITY_LEVELS`.
   - Routes multi-hop `VERIFIED` attested tool paths, excludes `DISCOVERED`/`QUARANTINED`/`RETIRED` tools, tracks sensitivity taint & declassifier gates, detects capability gaps, and ranks candidates via exact `Decimal`/`int` Pareto ordering.

3. **Agent C — ASM / NEON Native Forge (`src/kintsugi/forge/asm_native_forge.py`)**
   - Exports: `AsmNativeForge`, `AsmKernelSpec`, `AsmForgeResult`, `AsmDifferentialReport`, `AsmBenchmarkReport`, `AsmBuildManifest`, `BuildManifestStore`, `LoadedAsmKernel`, `build_delim_scan_kernel_spec`, `build_crc32c_fnv64_kernel_spec`, `detect_host_arch`, `resolve_asm_backend`, `scan_asm_source_safety`, `validate_asm_abi_version`.
   - Synthesizes ABI-versioned ARM64 NEON/CRC32C & portable C99 scalar kernels with pre-compile static syscall/DLP safety checks, reproducible SHA-256 build manifests, 200-case fuzz differential parity vs Python reference oracles, and 1 MiB throughput benchmarking.

4. **Agent D — Neuro-Symbolic SMT Plan Verifier (`src/kintsugi/composition/smt_plan_verifier.py`)**
   - Exports: `verify_plan_formal`, `FormalVerificationBundle`, `SMTProofCertificate`, `prove_acyclic_and_total_order`, `prove_no_secret_escalation`, `prove_permission_monotonicity`, `prove_effect_idempotency`, `verify_bundle_digest`, `verify_certificate_digest`, `is_z3_available`.
   - Generates cryptographic `SMTProofCertificate`s (`acyclic_total_order`, `no_secret_escalation`, `permission_monotonicity`, `effect_idempotency`) backed by `z3-5.3.3` with a deterministic pure-Python parity fallback.

5. **Agent E — Evolution v4 Causal Ablation & Adaptive Budget (`src/kintsugi/evolution/evolution_v4.py`)**
   - Exports: `EvolutionEngineV4`, `AdaptiveBudgetController`, `MonotonicPromotionLedger`, `CausalAblationResult`, `MatchedTaskTrial`, `ExplorationPlan`, `CauseLocalization`, `ExecutionMode`, `CorpusLeakageError`, `ImmutableGuardrailError`, `PromotionGateError`, `verify_disjoint_families`, `compute_wilson_interval`, `honest_metric_summary`, `assert_strategy_respects_guardrails`.
   - Enforces disjoint train/held-out family leakage guards, Wilson lower-bound causal uplift gates, immutable guardrail protection, and monotonic promotion with automatic canary rollback.

## 2. Package Exports, CLI Subcommands & MCP Profile Parity

- **Package Exports:** Updated `src/kintsugi/__init__.py`, `runtime/__init__.py`, `synthesis/__init__.py`, `forge/__init__.py`, `composition/__init__.py`, and `evolution/__init__.py`.
- **CLI (`src/kintsugi/cli.py`, `src/kintsugi/cli_nextgen.py`):**
  - Added `synthesize` (`--goal-file`, `--tools-file`, `--context-file`, `--registry`), `smt-verify` (`--plan-file`, `--tools-file`, `--adapters-file`, `--context-file`, `--registry`), `asm-forge` (`info` | `build` | `benchmark`, `--kernel`), and `evolve-v4` (`--trials-file`, `--mode`).
  - Fixed `run_build3_asm_forge_helper` to invoke `resolve_asm_backend(target_arch=arch)` via keyword arguments and aligned `synthesize` / `smt-verify` helpers with MCP dispatch.
- **MCP Server (`src/kintsugi/mcp_nextgen.py`, `src/kintsugi/mcp_server.py`):**
  - Preserved existing profiles: `default` = `9` tools; `nextgen` / `coding` = `19` tools.
  - Added `build3` / `cognitive` profile = `23` tools (+4 read-only `readOnlyHint: True` tools: `kintsugi_build3_synthesize_plan`, `kintsugi_build3_smt_verify_plan`, `kintsugi_build3_asm_arch_status`, `kintsugi_build3_evolution_v4_ablate`).

## 3. Post-Final-Edit Verification Matrix (Apple M2 Pro `Darwin 25.4.0 arm64`)

- **Harness Code-Mistake & Rust Gate (`external host code-mistake gate (--scan-code)`):** `22/22` modified and new Build #3 `src/` & `tests/` files -> `PASS_100` (`0` Rust findings).
- **Build #3 Suite (`6` files: `test_hermetic_worker.py`, `test_capability_graph_synthesis.py`, `test_asm_native_forge.py`, `test_smt_plan_verifier.py`, `test_evolution_v4.py`, `test_build3_e2e_integration.py`):**
  - Python `3.9.6`: **`32/32 PASS`** (`10.005 s`, `0` skips)
  - Python `3.11.15`: **`32/32 PASS`** (`7.435 s`, `0` skips)
- **Full Combined Suite (`35` files = `29` Build #2 + `6` Build #3, Python `3.9.6`):** **`285/285 PASS`** (`171.425 s`, wall `171.698 s`, `0` fail, `0` error, `0` skip).
- **Targeted Python `3.11.15` Suite (`21` files: `test_round3..14_remediation.py`, `test_tool_wire_and_adapter.py`, `test_build1_cli_mcp.py`, `test_nextgen_demos_2_3_4.py`, + `6` Build #3 files):** **`102/102 PASS`** (`50.277 s`, `0` fail, `0` error, `0` skip).
- **Rust / Cargo Tests (`cargo test --all-targets`):** **`35/35 PASS`** (`32` in `5.84 s`, `0` in `0.00 s`, `3` in `0.00 s`).
- **Isolated `72`-File `src/` Security Scans (`<temp_dir>/kintsugi_b3_src_check/src`):**
  - `kintsugi-rs` default (`36` scars): **`0` violations** (`95.914 ms`).
  - `kintsugi-rs` external policy (`36` scars, `--policy-sha256 87242c667d1c48190e8e8a16489038f62fb118156d39bf6518a009b7eda4c40c`): **`0` violations** (`97.727 ms`).
  - Python `1,797`-scar CLI scan: **`0` violations** (`25,440.3 ms`).
- **Rust `s3-audit` Across `16` Build #2 + Build #3 `src/` Targets:** **`315/315` seams `PASS_S3_LOCKED`** (`0` `unguarded_s0_seams`: `capability` `32/32`, `composition` `60/60`, `forge` `55/55`, `runtime` `79/79`, `tools` `25/25`, `evolution` `15/15`, `synthesis` `2/2`, root Build #2/#3 modules `47/47`). *(Note: scanning the entire `src/kintsugi` folder still surfaces 5 pre-existing Build #1 unguarded seams in legacy `council.py`=2, `grounding.py`=1, and `starter_pack.py`=2 out of 445 total seams.)*
- **Scar Ledger, Wire Eval & Parent Harness:**
  - `verify-ledger`: **`1,797 PASS`**, `0` failures.
  - `eval --wire`: **`6/6 PASS`** (`false_pos=0.0%`, `repro=dbd8f3b55430`).
  - Parent `<external_host_workspace>` `host_harness_regression_suite`: **`13/13 PASS`** (`1.917 s`).
