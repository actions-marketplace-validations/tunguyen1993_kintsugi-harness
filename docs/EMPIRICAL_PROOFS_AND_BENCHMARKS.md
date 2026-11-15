# @BENCH_IR/1 [EMPIRICAL_PROOFS_SCIENTIFIC_LAWS_EDITION_BENCHMARKS_V2_4_0]

```text
@META[doc="docs/EMPIRICAL_PROOFS_AND_BENCHMARKS.md" | ver="2.4.0" | license="Apache-2.0" | schema="@KML/1+@LOGIC/2+@CREED/1+@DOMAIN_KMI/1"]
@VERIFY_CMD[
  unit_py:      "PYTHONPATH=src python3 -m unittest discover -s tests -v"
  unit_rs:      "cargo test"
  rust_bench:   "./target/release/kintsugi-rs bench"
  token_starter:"PYTHONPATH=src python3 -m kintsugi.cli token-report --starter-only"
  token_full:   "PYTHONPATH=src python3 -m kintsugi.cli token-report --domain security"
  editions:     "python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py"
  foresight:    "kintsugi foresight --scientific-corpus"
  bft_swarm:    "kintsugi swarm <target> --byzantine-test"
]
```

## 1. @BENCHMARK_MATRIX/1 (`v2.4.0` Reproducible Verified Results)

| Pillar | Metric | Verified Result | Exact Reproduction Command |
| :--- | :--- | :--- | :--- |
| `kintsugi-rs` (`@CT2`) | `36`-rule single-file scan (`200` iters) & `1,789`-record `.kintsugi/scars.kml` audit | `~16.2 µs/call` (`0.0162 ms`) · `0` quarantined KML records | `./target/release/kintsugi-rs bench` |
| `KMI/1` (Starter `16`) | Global `KMI/1` vs Verbose Markdown (`16` Core Scars) | `226 tok/turn` vs `3,641 tok/turn` (`93.8%` reduction, `170,750 tok` saved / 50 turns) | `PYTHONPATH=src python3 -m kintsugi.cli token-report --starter-only` |
| `KMI/1` (Ledger `1,789`) | Global `KMI/1` vs Verbose Markdown (`1,789` Evolved Scars) | `24,967 tok/turn` vs `414,267 tok/turn` (`94.0%` reduction, `19,465,000 tok` saved / 50 turns) | `PYTHONPATH=src python3 -m kintsugi.cli token-report` |
| `DOMAIN_KMI/1` (`6` Shards) | Domain-Partitioned Shards (`docs/domains/01..06`) vs Full Verbose MD | Starter `16`: `80.5 tok/turn` avg (`97.79%` reduction) · Full `1,789`: `175.7 tok/turn` avg (`99.96%` reduction) | `PYTHONPATH=src python3 -m kintsugi.cli token-report --domain security` |
| `EMPIRICAL_CORTEX` | Synthesized Empirical Cortex (`collective-pool/synthesized-empirical-cortex/`) | `972` Cognitive Axioms + `1,581` Causal Atoms (`48` suites, `85` topics) + `63` `KS-EMP-*` scars | `PYTHONPATH=src python3 -m kintsugi.cli swarm --model-matrix` |
| `@KML/1` Wire | Symbolic AST-IR vs Human JSON (`1.81 MB` baseline) | `496.5 KB` raw (`-72.58%`) -> `75.1 KB` zlib (`-95.85%`) · `0.96 ms` parse | `python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py` |
| `4_EDITIONS` | Free `$0` / `Apache-2.0` / `Apache-2.0` / `Apache-2.0` AEAD `.kpack` | `100% TP`, `0.0% FP`, `12/12` Auto-Fix, `200k`-iter `PBKDF2-HMAC-SHA256` | `python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py` |
| `AST_GROUNDING_V2` | Multi-Language (`py,js,ts,go,rs`) + `ASTQ/1` | `5/5 TP` (`VERIFIED`) · `5/5 S3` (`REFUTED`, `0 FP`) · `100%` Alpha-Rename Equivalence | `kintsugi ground src/` |
| `SCI_CORPUS_5` | 5 Coupled Multi-Physics Conservation Laws | `6 -> 0` seams (`100.0%` Q-risk reduction) | `kintsugi foresight --scientific-corpus` |
| `BFT_SWARM_1` | `K=4` Clones + Ledoit-Wolf $N_{\text{eff}}$ | `N_eff = 3.39` ($\hat{\rho}=0.06$, $P_{\text{post}}=0.9999$), `0.0%` Sycophancy, `100%` BFT ($f=1$) | `kintsugi swarm <target> --byzantine-test` |
| `HOLDOUT_GATE` | Disjoint `T_gen != T_ver` | `precision = 1.00 >= 0.95` · `recall_drop = 0.00 <= 0.05` · `0` Paraphrase FP | `PYTHONPATH=src python3 -m unittest discover -s tests -v` |
| `TEST_SUITES` | Python `unittest` (`47/47`) + Rust `cargo test` (`5/5`) | `52/52 PASS (100%)` | `cargo test && PYTHONPATH=src python3 -m unittest discover -s tests -v` |

## 2. @DOMAIN_PARTITION_BENCHMARK/1 (`docs/domains/01..06` Context Compression Math)

Token counts are computed deterministically by `src/kintsugi/compressor.py:estimate_tokens` (`max((len(text) + 3) // 4, int(word_tokens * 0.78))`) and reduction percentages follow exact arithmetic `round(((verbose - compact) / verbose) * 100.0, 2)`:

| Domain Key | Documentation Shard (`docs/domains/`) | Starter Rules (`16` Total) | Starter Shard Tokens/Turn | Starter Reduction vs `3,641` Verbose | Full Ledger Rules (`1,789` Total) | Full Ledger Shard Tokens/Turn (Top-8 + `@DEFERRED`) | Full Ledger Reduction vs `414,267` Verbose |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `security` | [`docs/domains/01_security_appsec.md`](domains/01_security_appsec.md) | `4` | `95 tok` | `97.39%` (`177,300` saved/50t) | `322` | `164 tok` | `99.96%` (`20,705,150` saved/50t) |
| `backend` | [`docs/domains/02_backend_api.md`](domains/02_backend_api.md) | `4` | `94 tok` | `97.42%` (`177,350` saved/50t) | `327` | `183 tok` | `99.96%` (`20,704,200` saved/50t) |
| `database` | [`docs/domains/03_database_sql.md`](domains/03_database_sql.md) | `1` | `65 tok` | `98.21%` (`178,800` saved/50t) | `291` | `179 tok` | `99.96%` (`20,704,400` saved/50t) |
| `frontend` | [`docs/domains/04_frontend_ui.md`](domains/04_frontend_ui.md) | `2` | `74 tok` | `97.97%` (`178,350` saved/50t) | `287` | `180 tok` | `99.96%` (`20,704,350` saved/50t) |
| `devops` | [`docs/domains/05_devops_cloud.md`](domains/05_devops_cloud.md) | `3` | `85 tok` | `97.67%` (`177,800` saved/50t) | `267` | `166 tok` | `99.96%` (`20,705,050` saved/50t) |
| `ai_mcp` | [`docs/domains/06_ai_mcp_agents.md`](domains/06_ai_mcp_agents.md) | `2` | `70 tok` | `98.08%` (`178,550` saved/50t) | `295` | `182 tok` | `99.96%` (`20,704,250` saved/50t) |
| **Average / Total** | **All 6 Domain Shards** | **`16`** | **`80.5 tok`** | **`97.79%`** | **`1,789`** | **`175.7 tok`** | **`99.96%`** |

## 3. @SCIENTIFIC_LAWS_IR/1 (`500` Rollout Steps, $\Delta t = 0.05\text{ s}$)

| ID | Law / Invariant | Unguarded Seam (`VERIFIED`) | Unguarded Drift | Guarded Counterexample (`S3 REFUTED`) | Guarded Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SCI-HAM-002` | 1st Law & Liouville Symplectic ($\det(J)=1$) | `NON_SYMPLECTIC_ENERGY_DRIFT_SEAM` (Forward Euler) | `2.0000 J -> 289.5455 J` (`+14,377%`) | Velocity-Verlet | `1.999707 J` (`0.0147%` bounded) |
| `SCI-FLUID-004` | Buckingham $\Pi$ & Radian Invariance | `DIMENSIONAL_UNIT_MISMATCH_SEAM` (`pa+ms+mm`, `sin(deg)`) | `-100,610.272` ($10^4\times$ error) | SI `[m]` + `math.radians()` | `11.3980 m` exact |
| `SCI-MASS-003` | Continuity & Positivity ($\partial_t\rho+\nabla\cdot(\rho\mathbf{u})=0, \rho\ge0$) | `MASS_CONTINUITY_VIOLATION_SEAM` (`1.35 * flux_out`) | `-1.7000 kg/m³` ($\rho<0$) | Antisymmetric flux ($\Delta m_A=-\Delta m_B$) | `0.0 kg` drift (`<1e-15`) |
| `SCI-CAUSAL-005` | Light-Cone ($t_{\text{cause}}\le t_{\text{effect}}$) & 2nd Law ($\Delta S\ge0$) | `CAUSAL_ARROW_LOOKAHEAD_SEAM` (`idx_t + 1`, $\Delta S=-0.25$) | `50.5` lookahead leak | Past window (`<= idx_t`) | `0.5` exact, $\Delta S=+0.10\ge0$ |
| `SCI-REL-001` | Lorentz Low-$\beta$ & Kahan Summation | `CATASTROPHIC_CANCELLATION_SEAM` (`gamma**2 - 1.0`, `sum()`) | `344.09%` error, `0.0 J` micro-flux | $\frac{\beta^2}{1-\beta^2}$ + `math.fsum()` | `0.0%` error, `+100.0 J` preserved |

## 4. @WIRE_HEADERS_SPEC/1
```text
@FORESIGHT/1|sha=f5dfa4b9|T1=7|T2=7|T3=3|p_max=0.96|top=F-T2-002@physics_sim.py:55
@META/1|C_avg=0.87|K_avg=0.81|blind=health-longevity,psychology-relationships,growth-marketing|act=AUTONOMOUS_FAST_EXECUTE
@DREAM/1|sha=f5dfa4b9|seams=7->0|p_max=0.96->0.00|q_red=100.0%|iso=5|status=VERIFIED
@SWARM/1|sha=f5dfa4b9|clones=4|accepted=7|tabu=1|bft=PASS|c_gain=+0.0243|playbook=VERIFIED
@CREED/1[ver=2.1|axiom="MUTATE_OR_STALL: identical_input => identical_failure | TRY_ALL_PICK_BEST: no_new_way => select_best_tested"|p1=2_STRIKE_PIVOT|p2=2X_TOOL_SYNTH|p3=CRACK_TO_SCAR|p4=SELF_OVERWRITE|p5=TRY_ALL_PICK_BEST]
```
