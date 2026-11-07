# @BENCH_IR/1 [EMPIRICAL_PROOFS_SCIENTIFIC_LAWS_EDITION_BENCHMARKS_V2_0_0]

```text
@META[doc="docs/EMPIRICAL_PROOFS_AND_BENCHMARKS.md" | ver="2.0.0" | schema="@KML/1+@LOGIC/2+@CREED/1"]
@VERIFY_CMD[
  unit_py:   "python3 -m unittest discover -s tests -v"
  unit_rs:   "cargo test"
  editions:  "python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py"
  foresight: "kintsugi foresight --scientific-corpus"
  bft_swarm: "kintsugi swarm <target> --byzantine-test"
]
```

## 1. @BENCHMARK_MATRIX/1 (`v2.0.0` Verified Results)

| Pillar | Metric | Verified Result | Command |
| :--- | :--- | :--- | :--- |
| `kintsugi-rs` (`@CT2`) | Single-call / `1,742`-record `@KML/1` audit | `7.6 µs/call` · `1.83 ms` (`0` quarantined) | `./target/release/kintsugi-rs kml .kintsugi/scars.kml` |
| `@KML/1` Wire | Symbolic AST-IR vs Human JSON | `1.81 MB` -> `469.7 KB` raw (`-74.06%`) -> `66.5 KB` zlib (`-96.33%`) · `0.82 ms` parse | `python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py` |
| `KMI/1` & `KMI/2` | Per-turn prompt tokens vs verbose MD | `~209 tok/turn` vs `~4,450 tok/turn` (`-95.3%`, `~212k tok` saved / 50 turns) | `kintsugi token-report` |
| `4_EDITIONS` | Free `$0` / `$15` / `$19` / `$29` AEAD `.kpack` | `100% TP`, `0.0% FP`, `12/12` Auto-Fix, `200k`-iter `PBKDF2-HMAC-SHA256` | `python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py` |
| `AST_GROUNDING_V2` | Multi-Language (`py,js,ts,go,rs`) + `ASTQ/1` | `5/5 TP` (`VERIFIED`) · `5/5 S3` (`REFUTED`, `0 FP`) · `100%` Alpha-Rename Equivalence | `kintsugi ground src/` |
| `SCI_CORPUS_5` | 5 Coupled Multi-Physics Conservation Laws | `6 -> 0` seams (`100.0%` Q-risk reduction) | `kintsugi foresight --scientific-corpus` |
| `BFT_SWARM_1` | `K=4` Clones + Ledoit-Wolf $N_{\text{eff}}$ | `N_eff = 3.39` ($\hat{\rho}=0.06$, $P_{\text{post}}=0.9999$), `0.0%` Sycophancy, `100%` BFT ($f=1$) | `kintsugi swarm <target> --byzantine-test` |
| `HOLDOUT_GATE` | Disjoint `T_gen != T_ver` | `precision = 1.00 >= 0.95` · `recall_drop = 0.00 <= 0.05` · `0` Paraphrase FP | `python3 -m unittest discover -s tests -v` |
| `TEST_SUITES` | Python `unittest` (`43`) + Rust `cargo test` (`4`) | `47/47 PASS (100%)` | `cargo test && python3 -m unittest` |

## 2. @SCIENTIFIC_LAWS_IR/1 (`500` Rollout Steps, $\Delta t = 0.05\text{ s}$)

| ID | Law / Invariant | Unguarded Seam (`VERIFIED`) | Unguarded Drift | Guarded Counterexample (`S3 REFUTED`) | Guarded Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SCI-HAM-002` | 1st Law & Liouville Symplectic ($\det(J)=1$) | `NON_SYMPLECTIC_ENERGY_DRIFT_SEAM` (Forward Euler) | `2.0000 J -> 289.5455 J` (`+14,377%`) | Velocity-Verlet | `1.999707 J` (`0.0147%` bounded) |
| `SCI-FLUID-004` | Buckingham $\Pi$ & Radian Invariance | `DIMENSIONAL_UNIT_MISMATCH_SEAM` (`pa+ms+mm`, `sin(deg)`) | `-100,610.272` ($10^4\times$ error) | SI `[m]` + `math.radians()` | `11.3980 m` exact |
| `SCI-MASS-003` | Continuity & Positivity ($\partial_t\rho+\nabla\cdot(\rho\mathbf{u})=0, \rho\ge0$) | `MASS_CONTINUITY_VIOLATION_SEAM` (`1.35 * flux_out`) | `-1.7000 kg/m³` ($\rho<0$) | Antisymmetric flux ($\Delta m_A=-\Delta m_B$) | `0.0 kg` drift (`<1e-15`) |
| `SCI-CAUSAL-005` | Light-Cone ($t_{\text{cause}}\le t_{\text{effect}}$) & 2nd Law ($\Delta S\ge0$) | `CAUSAL_ARROW_LOOKAHEAD_SEAM` (`idx_t + 1`, $\Delta S=-0.25$) | `50.5` lookahead leak | Past window (`<= idx_t`) | `0.5` exact, $\Delta S=+0.10\ge0$ |
| `SCI-REL-001` | Lorentz Low-$\beta$ & Kahan Summation | `CATASTROPHIC_CANCELLATION_SEAM` (`gamma**2 - 1.0`, `sum()`) | `344.09%` error, `0.0 J` micro-flux | $\frac{\beta^2}{1-\beta^2}$ + `math.fsum()` | `0.0%` error, `+100.0 J` preserved |

## 3. @WIRE_HEADERS_SPEC/1
```text
@FORESIGHT/1|sha=f5dfa4b9|T1=7|T2=7|T3=3|p_max=0.96|top=F-T2-002@physics_sim.py:55
@META/1|C_avg=0.87|K_avg=0.81|blind=health-longevity,psychology-relationships,growth-marketing|act=AUTONOMOUS_FAST_EXECUTE
@DREAM/1|sha=f5dfa4b9|seams=7->0|p_max=0.96->0.00|q_red=100.0%|iso=5|status=VERIFIED
@SWARM/1|sha=f5dfa4b9|clones=4|accepted=7|tabu=1|bft=PASS|c_gain=+0.0243|playbook=VERIFIED
@CREED/1[ver=2.0|axiom="MUTATE_OR_STALL: identical_input => identical_failure"|p1=2_STRIKE_PIVOT|p2=2X_TOOL_SYNTH|p3=CRACK_TO_SCAR|p4=SELF_OVERWRITE]
```
