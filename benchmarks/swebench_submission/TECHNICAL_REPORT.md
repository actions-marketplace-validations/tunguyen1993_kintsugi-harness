# Technical Report: Kintsugi-Harness v1.9.0 — 5-Pillar Neuro-Symbolic Pareto Swarm for Autonomous Software Engineering

**Author:** Nguyen Duc Tu ([@tunguyen1993](https://github.com/tunguyen1993))  
**Repository:** [https://github.com/tunguyen1993/kintsugi-harness](https://github.com/tunguyen1993/kintsugi-harness)  
**Date:** November 8, 2026

## 1. Abstract
We present **Kintsugi-Harness v1.9.0**, an open-source neuro-symbolic agent harness combining:
1. **Native Rust AST Symbol & Seam Grounding (`kintsugi-rs` & `RepoAstGroundingEngine`)** operating in `<5ms` to eliminate hallucinated identifiers and commit drift prior to patch emission.
2. **The 5-Pillar Autopoietic Evolution Creed (`@CREED/1`)**:
   - `P1:MUTATE` (2-Strike Dead-Path Pivot)
   - `P2:SYNTH` (1-Step Deterministic Tool Synthesis)
   - `P3:SCAR` (Kintsugi Machine-Language `@KML/1` Guardrail Codification)
   - `P4:PRUNE` (Minimal AST Diff & LOC Optimization)
   - `P5:CONVERGE` (`Best@3` Pareto-Optimal Candidate Selection across `Way 1`, `Way 2`, and `Way 3` rollouts without access to held-out evaluation tests).

## 2. Best@3 Trajectory Selection Without Test Oracle Leakage
For each task instance, Kintsugi-Harness explores three candidate repair trajectories (`Way 1`: Naive Baseline, `Way 2`: Heuristic Workaround, `Way 3`: Invariant-Locked S3 Patch). The deterministic 3-State Grounding Gate (`VERIFIED`, `REFUTED`, `UNKNOWN`) refutes candidates that violate type/AST invariants and selects the Pareto-optimal patch maximizing invariant preservation and minimal diff complexity (`LOC`). All rollouts and selection traces are archived in [`trajs/`](./trajs/).

## 3. Reproducibility & Verification
Every prediction in [`all_preds.jsonl`](./all_preds.jsonl) is accompanied by its applied diff, evaluation report, and compressed test output in [`logs/`](./logs/).
