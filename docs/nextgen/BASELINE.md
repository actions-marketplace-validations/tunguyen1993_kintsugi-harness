# Kintsugi Harness — Stage 0 Frozen Baseline (`e151d886`)

> Captured on branch `feature/capability-fabric-stage1` at commit `e151d886e22a7a2e9c163f8b284f2c9bca729a7d` prior to Deliverable PR-01a additions.
> Machine-readable counterpart: [TEST_RESULTS.json](../../artifacts/nextgen/TEST_RESULTS.json)

## 1. Host & Toolchain Environment

| Component | Observed Value |
| :--- | :--- |
| **Git Branch** | `feature/capability-fabric-stage1` |
| **Git Commit (`HEAD`)** | `e151d886e22a7a2e9c163f8b284f2c9bca729a7d` |
| **OS / Kernel (`uname -a`)** | `Darwin Tu-2.local 25.4.0 Darwin Kernel Version 25.4.0: Thu Mar 19 19:31:17 PDT 2026; root:xnu-12377.101.15~1/RELEASE_ARM64_T6020 arm64` |
| **CPU / Architecture** | `Apple M2 Pro` (`arm64`) |
| **Python** | `Python 3.9.6` |
| **Rust Compiler (`rustc`)** | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| **Cargo** | `cargo 1.99.1 (5f94df478 2026-08-27)` |
| **C/C++ Compiler (`clang`)** | `Apple clang version 21.0.0 (clang-2100.1.1.101)` (`arm64-apple-darwin25.4.0`) |
| **Z3 Solver (`z3-solver`)** | `5.3.3` (`PASS`) |

## 2. Release Binary SHA-256 Digests

- `target/release/kintsugi-rs`: `1dc152825cf7da3f420dacded9f9114dd0f1b84b84f1c8fc8b309e90f3aa3e7b`
- `target/release/rust-neuro-symbolic-core`: `850a9524e476061eb21551690ea85008971a71093adb083ba1a08f6538af0806`

## 3. Executed Baseline Verification Matrix

| Check | Exact Command | Exit Code | Status | Observed Summary |
| :--- | :--- | :---: | :---: | :--- |
| **Python Unit Suite** | `PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v` | `0` | `PASS` | `60` tests ran in `16.376s`; `60` passed, `0` failed |
| **Rust Cargo Suite** | `PATH="$HOME/.cargo/bin:$PATH" cargo test --all-targets` (in `rust/`) | `0` | `PASS` | `18` passed, `0` failed (`15` `kintsugi_core`, `0` `kintsugi_rs`, `3` `rust_neuro_symbolic_core`) |
| **Rust Native Scan** | `./target/release/kintsugi-rs scan src/ --fail-on HIGH` | `0` | `PASS` | `27` file(s) checked against `36` scars in `781.887ms` (`781887 µs`); `0` violations |
| **Rust Benchmark** | `./target/release/kintsugi-rs bench` | `0` | `PASS` | `36` rules; `79.38 µs/call` (`200` iters); `93.8%` token reduction (`~6840` -> `~424` tok/turn); `1797` `.kintsugi/scars.kml` records in `1969 µs` |
| **Ledger Self-Check** | `PYTHONPATH=src python3 -m kintsugi.cli verify-ledger` | `0` | `PASS` | `1797` scars verified (`1797` `[PASS]`, `0` `[FAIL]`) |
| **Evaluation Suite** | `PYTHONPATH=src python3 -m kintsugi.cli eval` | `0` | `PASS` | `6/6` cases passed (`100.0%`); `0.0%` false positive rate across `3` benign controls; `6` signed proofs; `reproducibility_sha256=dbd8f3b55430476b31c389ed54dcbcf297384c231f7360e875c6923a32329a11` |
| **Z3 SMT Solver** | `PYTHONPATH=src python3 -c "import z3; from kintsugi.crs_engine import BitVectorSMTVerifier; ..."` | `0` | `PASS` | `z3` `5.3.3` imported; `BitVectorSMTVerifier().verify_allocation_mul_add_overflow()` returned `z3_status="sat"`, `z3_dpll_cross_verified=true`, `safe_count_ceiling=268435453` |

## 4. Notes on Frozen Scope

- All measurements above were observed directly on clean commit `e151d886e22a7a2e9c163f8b284f2c9bca729a7d` before introducing `src/kintsugi/config.py`, `schemas/*.v1.schema.json`, or `tests/security/test_config_profiles.py`.
- In particular, `kintsugi-rs scan src/ --fail-on HIGH` checked `27` source files in Stage 0; subsequent stages add modules under `src/kintsugi/` and record updated counts separately.
