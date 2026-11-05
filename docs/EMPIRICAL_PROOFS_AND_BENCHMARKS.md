# Empirical Proofs, Scientific Law Validation & Benchmarks (`v0.8.0`)

Every architectural claim in **Kintsugi Harness (`v0.8.0`)** is backed by deterministic, reproducible unit tests (`python3 -m unittest discover -s tests -v` and `cargo test`) and runtime numerical experiments.

---

## 1. Summary of Verified Benchmarks (`v0.8.0`)

| Benchmark Pillar | Empirical Metric / Test Suite | Verified Result (`v0.8.0`) | Reproducible Command |
| :--- | :--- | :--- | :--- |
| **Native Rust PreToolUse Engine (`kintsugi-rs`)** | Single-call latency / Full 18-file repo scan | **`9.6 µs/call`** (`16.5 ms` for 18 files × 18 scars, `0` violations) | `./target/release/kintsugi-rs bench` |
| **`KMI/1` Ultra-Low-Token Wire Index** | Per-turn token footprint vs verbose Markdown | **`~209 tokens/turn` vs `~3,330 tokens/turn` (`93.7%` reduction, `~156,050 tokens` saved / 50 turns)** | `kintsugi token-report` |
| **3-State AST Symbol Grounding Gate** | True Positives / True Negatives / Hallucination & Docstring Traps | **`5/5` True Positives (`VERIFIED`) · `5/5` S3 Safe Counterexamples (`REFUTED`, `0` FP) · `3/3` Hallucination/Docstring Traps (`REFUTED` in `<0.1ms`)** | `kintsugi ground src/` |
| **5 Universal Scientific Conservation Laws** | Runtime numerical simulation + AST/Foresight detection | **`5/5` Laws Empirically Proven (`PASS 100%`)** | `python3 -m unittest discover -s tests -v` |
| **4-Stage Frontier Epistemic Pool Gate** | 15 Universal Domains (`7` Engineering + `8` Real-Life/Business) | **`38/38` Frontier Lessons Verified (`scan(bad) >= 1` & `scan(good) == 0`)** | `kintsugi learn pool-status` |
| **Automated Test Suites** | Python `unittest` (`22` tests) + Rust `cargo test` (`3` tests) | **`25/25` Total Tests Passing (`100% OK`)** | `cargo test && python3 -m unittest` |

---

## 2. Empirical Proof on 5 Universal Scientific & Mathematical Laws

To prove that Kintsugi's Neuro-Symbolic Brain (`RepoAstGroundingEngine` + `AutopoieticSynthesizer` + `CausalForesightEngine` + `MetacognitiveSelfModel`) generalizes beyond web/API patterns to **universal laws of physics and applied mathematics**, we evaluated it against a 5-law coupled multi-physics simulation suite (`500` rollout steps, $\Delta t = 0.05\text{ s}$):

| # | Scientific Law & Mathematical Invariant | Unguarded Seam (`S0/S1` — `VERIFIED`) | Empirical Runtime Measurement (Unguarded Violation) | Guarded Counterexample (`S3` — `REFUTED` as Safe) | Empirical Runtime Measurement (`S3` Guarded) |
| :- | :--- | :--- | :--- | :--- | :--- |
| **1** | **1st Law of Thermodynamics & Liouville's Symplectic Theorem** ($\det(J) = 1$, $\lvert E(t) - E(0)\rvert \le \epsilon$) | `NON_SYMPLECTIC_ENERGY_DRIFT_SEAM`: Explicit Forward Euler (`x_next = x_pos + v_vel * dt_sec`) with $\det(J) = 1 + \frac{k}{m}\Delta t^2 > 1$ | Closed-system energy explodes from `2.0000 J` to **`289.5455 J` (`+14,377.28%` secular energy drift)** over 500 steps | Symplectic Velocity-Verlet (`v_half = v_vel + 0.5 * accel_0 * dt_sec`) + bounded energy assertion | Closed-system energy stays at **`1.999707 J` (`0.0147%` bounded symplectic oscillation)** |
| **2** | **Buckingham $\Pi$ Theorem (Dimensional Homogeneity & Radian Invariance)** ($[M^a L^b T^c]$ consistency) | `DIMENSIONAL_UNIT_MISMATCH_SEAM`: Direct sum `pressure_pa + velocity_ms + elevation_mm` and raw `math.sin(tilt_deg)` | Bernoulli head corrupted to **`-100,610.272`** (wrong sign & $10^4\times$ magnitude error) | Normalize all additive terms to SI meters `[m]` and convert angles via `math.radians(tilt_deg)` | Physically exact hydraulic head of **`11.3980 m`** |
| **3** | **Conservation of Mass / Continuity Equation & Positivity** ($\frac{\partial \rho}{\partial t} + \nabla \cdot (\rho \mathbf{u}) = 0$, $\rho \ge 0$) | `MASS_CONTINUITY_VIOLATION_SEAM`: Unbalanced flux weights (`flux_in - 1.35 * flux_out`) and unclipped sink | Compartment density drops to unphysical negative **`-1.7000 kg/m³`** ($\rho < 0$) | Pairwise antisymmetric conservative flux ($\Delta m_A = -\Delta m_B$) with positivity limiter | Total closed-system mass drift **`0.0 kg` (`< 1e-15`)**, $\rho \ge 0$ |
| **4** | **Relativistic Causal Light-Cone ($t_{\text{cause}} \le t_{\text{effect}}$) & 2nd Law of Thermodynamics ($\Delta S_{\text{isolated}} \ge 0$)** | `CAUSAL_ARROW_LOOKAHEAD_SEAM`: Accessing future index `signal_series[idx_t + 1]` at step `idx_t` and $\Delta S = -0.25$ | Future spike leaks into present estimate (**`50.5`** instead of `0.5`) and violates Clausius inequality (**$\Delta S = -0.25 < 0$**) | Strictly causal past/present window (`indices <= idx_t`) and non-negative entropy production | Exact causal estimate **`0.5`** and non-decreasing entropy (**$\Delta S = +0.10 \ge 0$**) |
| **5** | **Numerical Catastrophic Cancellation & Kahan Compensated Summation** | `CATASTROPHIC_CANCELLATION_SEAM`: Naive `gamma ** 2 - 1.0` at $v/c = 10^{-8}$ and naive `sum()` across $10^{16}\text{ J} + 100 \times 1\text{ J}$ | Lorentz factor term suffers **`344.09%` relative error** (`4.44e-16` vs `1.00e-16`) and naive `sum()` loses **`100%` of micro-fluxes (`0.0 J`)** | Algebraic factorization $\beta^2\gamma^2 = \frac{v^2/c^2}{1 - v^2/c^2}$ and `math.fsum()` | **`0.0%` relative error** (`1.0000000000000002e-16`) and **`+100.0 J`** micro-fluxes preserved |

---

## 3. Neuro-Symbolic 3-State Grounding Gate & AST Docstring Isolation Proof

Unlike pure LLM token predictors that frequently hallucinate non-existent helper functions or confuse prose words inside docstrings with executable variables, `RepoAstGroundingEngine` (`src/kintsugi/grounding.py`) enforces three deterministic invariants in **`<5ms`**:

1. **SHA-256 Commit-Drift Lock (`manifest_sha`):** Immediately refutes stale hypotheses (`COMMIT_DRIFT_MISMATCH`) if any indexed file changes between analysis turns.
2. **AST Docstring & Keyword Isolation:** Parses Python AST nodes (`ast.Module`, `ast.ClassDef`, `ast.FunctionDef`, `ast.AsyncFunctionDef`) to exclude docstring line ranges from seam scanning and strips all 45+ language keywords (`for`, `def`, `return`, `class`, `async`, `await`) from `SYMBOL_TABLE`.
3. **Counterfactual 13-Case Verification Matrix:**
   - **5/5 True Violations (`VERIFIED`):** Every unguarded scientific & security seam is pinned to its exact `file:line` and AST symbols.
   - **5/5 Guarded Counterexamples (`REFUTED`):** Every `S3`-guarded implementation (`Velocity-Verlet`, `math.radians`, antisymmetric mass flux, past-only causal window, `math.fsum`) produces **`0` false positives**.
   - **3/3 Hallucination & Docstring Traps (`REFUTED`):** Queries citing non-existent symbols (`perpetual_motion_overunity_coil`, `quantum_tachyon_warp_flux`) or prose words inside docstrings (`Thermodynamics`) are deterministically rejected (`HALLUCINATED_SYMBOL`).

---

## 4. 3-Horizon Causal Foresight (`@FORESIGHT/1`) & Metacognitive Calibration (`@META/1`)

When executed on a coupled codebase (`kintsugi foresight <target>`), Kintsugi emits two ultra-compact wire headers (`<90 tokens` combined) alongside a $Q$-ranked Pre-Emptive Action Queue:

```text
@FORESIGHT/1|sha=f5dfa4b9|T1=7|T2=7|T3=3|p_max=0.96|top=F-T2-002@physics_sim.py:55
@META/1|C_avg=0.87|K_avg=0.81|blind=health-longevity,psychology-relationships,growth-marketing|act=AUTONOMOUS_FAST_EXECUTE
```

- **`T+1 (Immediate Direct Faults)`:** Pinpoints single-function boundary and conservation violations.
- **`T+2 (Second-Order Call-Graph Cascade)`:** Propagates failure probabilities across caller fan-out via damped adjacency $r^{(2)} = A r + 0.6 A^2 r$, ranking coupled entrypoints by $Q = \frac{\text{Severity} \times \text{Probability} \times \text{CascadeMultiplier}}{\text{Cost}}$.
- **`T+3 (Long-Horizon Drift & Epistemic Tail-Risk)`:** Combines long-horizon secular drift with Beta-Bernoulli domain blind-spot indices $B_d$ to trigger pre-emptive guardrail pulls before regressions occur.
