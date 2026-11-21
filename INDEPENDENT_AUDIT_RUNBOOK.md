# Kintsugi Harness v2.4.1 — Independent Security & Reproducibility Audit Runbook

All Round-1 through Round-5 audit findings (`KH-SEC-*`, `KH-R2-*`, `KH-R3-*`, `KH-R4-SEC-01` .. `KH-R4-DOC-09`, `KH-R5-SEC-01` .. `KH-R5-AI-04`) have been remediated and verified across BOTH Rust (`18` unit tests) and Python (`60` unit tests) engines, plus Self-Evolution v2 (`RuleIR/1`, `FailureEnvelope/1`, counterfactuals, live parity, and consolidation).

## Key Security & Evolution Boundaries in v2.4.1 (Final)
- **Out-of-Repo Trust Policy Only (`KH-R3-SEC-01`, `KH-R4-SEC-05`, `KH-R4-SEC-06`):** `.kintsugi/policy.json` inside an untrusted repository checkout is NEVER auto-loaded, and enclosing checkout root detection rejects explicit in-repo `--policy-file` flags even during single-file scans. Both Python and Rust CLI enforce SHA-256 verification and reject unknown `--*` flags (Rust exits `2`).
- **Top-Level Build Root, Symlink+`..` Traversal & `rm -f` Confinement (`KH-R4-SEC-01/02/04`, `KH-R5-SEC-01`):** Path segments are walked component-by-component on disk BEFORE collapsing `..`, only top-level disposable build/cache roots (`./build`, `./target`, etc.) are authorized (nested `./other/build` denied), substring `rm -f` bypasses are removed, and agent `tool_input.cwd` cannot override the runner-bound workspace root.
- **Immutable Ledger & Symlink-Safe Atomic Persistence (`KH-R5-EVO-02`, `KH-R5-SEC-03`):** Conflicting duplicate scar IDs raise `SCAR_ID_CONFLICT` / quarantine on load, and ledger/memory/BYOK config writes refuse symlinks (`assert_not_symlink` + `atomic_write_text`).
- **Scanner Symlink Confinement & B19 Heuristic (`KH-R4-SEC-03`, `KH-R4-AI-07`, `KH-R5-AI-04`):** Python (`O_NOFOLLOW` + `resolve()`) and Rust (`collect_files_confined`) skip external symlinks; `KS-012` / `KS-S3-01` prompt-injection matching is a deterministic heuristic separating standalone safety prohibitions from compound/expired exfil instructions.
- **Self-Evolution v2 (`src/kintsugi/evolution_v2.py` & `kintsugi-rs rule-ir-check`):** Declarative `RuleIR/1` AST-first synthesis, metamorphic counterfactual validation with honest Rule-of-Three FP upper bounds, append-only `EvolutionRegistry` promotion/rollback gates, `ConsolidationPlan/1`, and live Python <-> Rust differential parity verification.
- **Dual Cargo Targets (`KH-R3-PKG-04`):** Both `kintsugi-rs` (`rust/src/main.rs`) and `rust-neuro-symbolic-core` (`rust/src/neuro_symbolic_core.rs`) are declared `[[bin]]` targets in `Cargo.toml`.

## Offline Verification Commands
```bash
# Rust (requires cargo/rustc):
cargo test --all-targets
cargo build --release --bins
./target/release/kintsugi-rs scan src/ --fail-on HIGH
./target/release/kintsugi-rs bench

# Python core suite (zero mandatory external deps; also passes with sys.modules['z3']=None):
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v
PYTHONPATH=src python3 -m kintsugi.cli verify-ledger
PYTHONPATH=src python3 -m kintsugi.cli eval
PYTHONPATH=src python3 -m kintsugi.cli mcp   # stdio JSON-RPC server (9 tools)

# Optional Z3 patch-equivalence proof (requires .[proof] / z3-solver):
pip install -e ".[proof]"
PYTHONPATH=src python3 -c "from kintsugi.crs_engine import NativeSanitizerCoverageCRS; print(NativeSanitizerCoverageCRS.run_discover_patch_verify_campaign()['z3_patch_equivalence_verified'])"
```

## Reproducible Artifact SHA-256 Manifest
- `Cargo.toml`: `11af15d5a51652d36abc6cfea8841e62f36f6b74751d886316fcbf4347c3f1e7`
- `pyproject.toml`: `4649755607b1de94494f0b78e6334f1c41ddd3892d3065a30a88cfbc10733f39`
- `config/runtime_config.example.json`: `f59f33e90d8df237f100c930cd2a27114f53ed3c06084c32b9a368db2c8a6668`
- `config/mcp_server.example.json`: `fa164972c3fe29275becc4c2b97c439350cd514f7d38e902873a49f2799d09a6`
- `artifacts/audit.proof`: `c7503d161c3d2dc3d8b2401f7be196c577cc05885d917dd680b5a3128b28312c`
- `artifacts/eval_report.json`: `8dcb2e6e864b8667aab3e5eeb28662745a7cf6e53664aa62231e438c9657225a`
- `artifacts/evolution_iq.json`: `ac6057b82a7c6c26c642c8f18ac070f1504840b6fa50a6cc782ab1b26cf3e903`
- `artifacts/z3_crs_proof.json`: `c73910669dd65e6e13a86a91521046bc95be620775783b1b19b8d1de67dddb20`
