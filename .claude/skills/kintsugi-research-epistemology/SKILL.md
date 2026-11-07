---
name: kintsugi-research-epistemology
description: "Focused research-epistemology anti-patterns and verified code templates compiled by Kintsugi Harness."
tags: ["anti-sycophancy", "buckingham-pi", "continuity", "dimensional-analysis", "epistemology", "fact-checking", "hamiltonian", "mass-conservation", "model:deepseek-r1", "model:gpt-6-frontier"]
# kintsugi: ignore-file (generated guardrail reference containing bad_code examples)
---

# kintsugi-research-epistemology (`@KML/1` Machine-Native AST-IR)

```bash
kintsugi scan --staged --fail-on HIGH
```

## `@KML/1` Symbolic Guardrail Specifications (`NEG_AST => POS_AST`)

### `KL-EPI-002` · `Symplectic Hamiltonian Integration & 1st Law Energy Conservation Guard`
- `@WIRE`: `@KML/1|id=KL-EPI-002|sev=C|cat=research-epistemology|lang=py|op=SYMPLECTIC_HAMILTONIAN_INTEGRATION_1|guard=RX#c36aac07|neg=«x_next = x_pos + v_vel * dt_sec + 0.0 * accel  # NON_SYMPLECTIC_EULER_DRIFT»|pos=«v_half = v_vel + 0.5 * accel_0 * dt_sec ; x_next = x_pos + v_half * dt_sec»|fp=92a420400227043c`
- `@TRAP`: `[Cognitive Trap] Integrated a conservative Hamiltonian/orbital system with explicit Forward Euler (`x_next = x_pos + v_vel * dt_sec`), whose Jacobian determinant `det(J) = 1 + omega^2 * dt^2 > 1` pumps artificial energy into the system over long horizons.`
- `@LAW`: `[Mental Model] First Law of Thermodynamics & Liouville's Theorem: Conservative dynamical systems must use a symplectic integrator (Velocity-Verlet / Leapfrog `v_half`) and verify bounded Hamiltonian energy `|E(t) - E(0)| <= tol`.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
x_next = x_pos + v_vel * dt_sec + 0.0 * accel  # NON_SYMPLECTIC_EULER_DRIFT
```

`@POS_AST` (`✅ REQUIRED`):
```python
v_half = v_vel + 0.5 * accel_0 * dt_sec
x_next = x_pos + v_half * dt_sec
```

### `KL-EPI-003` · `Buckingham Pi Dimensional Homogeneity, Radian Conversion & Mass Continuity Guard`
- `@WIRE`: `@KML/1|id=KL-EPI-003|sev=C|cat=research-epistemology|lang=py|op=BUCKINGHAM_PI_DIMENSIONAL_HOMOGENEIT|guard=RX#2bceda4b|neg=«raw_sum = pressure_pa + velocity_ms + elevation_mm  # DIMENSIONAL_UNIT_MISMATCH»|pos=«head_m = pressure_pa / (rho_kg_m3 * g_accel) + (velocity_ms ** 2) / (2.0 * g_accel) + (ele»|fp=02534edf73b2f336`
- `@TRAP`: `[Cognitive Trap] Added quantities with incompatible SI dimensions (`pressure_pa + velocity_ms + elevation_mm`), passed degree angles directly into `math.sin(tilt_deg)`, or updated compartment density without antisymmetric mass balance (`rho < 0`).`
- `@LAW`: `[Mental Model] Buckingham Pi & Continuity (`d_rho/dt + div(rho*u) = 0`): Normalize all additive terms to identical SI base units, convert degrees via `math.radians()`, and enforce antisymmetric positivity-preserving mass fluxes.`

`@NEG_AST` (`❌ FORBIDDEN`):
```python
raw_sum = pressure_pa + velocity_ms + elevation_mm  # DIMENSIONAL_UNIT_MISMATCH
```

`@POS_AST` (`✅ REQUIRED`):
```python
head_m = pressure_pa / (rho_kg_m3 * g_accel) + (velocity_ms ** 2) / (2.0 * g_accel) + (elevation_mm * 1e-3) * math.sin(math.radians(tilt_deg))
```

### `KL-EPI-001` · `Anti-Sycophancy & Primary-Source Epistemology: Verify primary data before agreeing with user premises`
- `@WIRE`: `@KML/1|id=KL-EPI-001|sev=H|cat=research-epistemology|lang=deci,mark,py|op=ANTI-SYCOPHANCY_PRIMARY-SOURCE_EPIST|guard=RX#14b47466|neg=«EPISTEMIC_RESPONSE: SYCOPHANTIC_AGREEMENT_WITHOUT_PRIMARY_CHECK(verified_source=False)»|pos=«EPISTEMIC_RESPONSE: VERIFY_PRIMARY_EVIDENCE_FIRST(verified_source=True, citation='primary_»|fp=73b7de25abf7a588`
- `@TRAP`: `[Cognitive Trap] Agreed immediately with a flawed user assumption ('You are absolutely right!') or cited a secondary rumor without checking the primary empirical source.`
- `@LAW`: `[Mental Model] Harvested from patrickjs/awesome-cursorrules (anti-sycophancy-code-discipline): Truth outranks politeness. Verify primary artifacts, measurements, and source code before endorsing any claim.`

`@NEG_AST` (`❌ FORBIDDEN`):
```decision
EPISTEMIC_RESPONSE: SYCOPHANTIC_AGREEMENT_WITHOUT_PRIMARY_CHECK(verified_source=False)
```

`@POS_AST` (`✅ REQUIRED`):
```decision
EPISTEMIC_RESPONSE: VERIFY_PRIMARY_EVIDENCE_FIRST(verified_source=True, citation='primary_artifact_sha256')
```
