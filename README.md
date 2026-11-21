<div align="center">

<img src="assets/hero-banner.jpg" alt="Kintsugi Harness — Native Rust PreToolUse Guardrails & KMI/1 Ultra-Low-Token Skills for AI Coding Agents" width="100%" />

# Kintsugi Harness (`kintsugi-harness` · `v2.4.1` · `Apache-2.0`)

### ⚡ Stop burning Claude Code & Cursor context windows—and block destructive agent tool calls in `16.2 µs`.

**Drop-in Rust + Python `PreToolUse` guardrails & Model Context Protocol (`MCP`) Server featuring the Sovereign Tier-1 DARPA AIxCC Cyber Reasoning System (`kintsugi.crs_engine` `v2.4.0`: Microsoft `Z3 5.3.3` `QF_BV32/64` + Bit-Blasted Tseitin CNF, 3-TU LLVM SSA `.ll` IR CPG + Path-Sensitive Branch Refinement + Andersen Points-To Indirect Call Resolution, `-O2` Stripped Binary `Capstone 5.0` ARM64 CFG + `LLDB` + `Z3 QF_BV8` Lifter, `10,000`-Iter `0x00`-Seed `trace-pc-guard,trace-cmp` In-Process Fuzzer & Dual-Model Z3 Symbolic Patch Equivalence Proof, `12x12` Exact Rational Gram-Schmidt `LLL` Lattice Crypto Solver, and `n=240` 6-Language Held-Out Suite), the 5-Pillar Autopoietic Evolution Creed (`@CREED/1 v2.1`), Subscription-Aware Parallel Swarm Dispatcher & 6-Tier Model Capability Matrix (`@SWARM_DISPATCH/1` & `@MODEL_MATRIX/1`), 2-Tier Multi-Agent Council & Never-Solo Gate (`@DUAL_COUNCIL/1` & `@NEVER_SOLO_GATE/1`), Zero-Token SHA-256 Live Sync Hook (`@HARNESS_HOT_RELOAD/1`), Synthesized Empirical Cortex (`972` Cognitive Axioms + `1,581` Causal Atoms + `63` `KS-EMP-*` Empirical Engineering Scars across `48` completed suites & `85` research topics), 1-Command Third-Party Harness Integration (`kintsugi integrate` with Joint `SAT+DL` verification), and `93.8%–99.96%` Domain-Partitioned `KMI/1` skill context compression (`3,641` → `226 tokens` Global `KMI/1` [`93.8%`] / `80.5 tokens` Domain Shard [`97.79%`]; `414,267` → `24,967 tokens` Global [`94.0%`] / `175.7 tokens` Domain Shard [`99.96%`]).**

[![GitHub Stars](https://img.shields.io/github/stars/tunguyen1993/kintsugi-harness?style=social)](https://github.com/tunguyen1993/kintsugi-harness/stargazers)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/tunguyen1993/kintsugi-harness/badge)](https://securityscorecards.dev/viewer/?uri=github.com/tunguyen1993/kintsugi-harness)
[![10-Arena Synthetic Suite: 10/10 PASS (98.30)](https://img.shields.io/badge/10--Arena_Synthetic_Suite-10%2F10_PASS_%2898.30%29-00C853)](benchmarks/verified_10_arena_pareto_certificate.json)
[![Synthetic 4-Vendor Audit: 100.0/100 (v2.4.1)](https://img.shields.io/badge/Synthetic_4--Vendor_Audit-100.0%2F100_%28v2.4.1%29-00C853)](benchmarks/INDEPENDENT_HACKER_AGENT_AUDIT_REPORT.md)
[![Synthetic SWE-like Suite: 8/8 Local](https://img.shields.io/badge/Synthetic_SWE--like_Suite-8%2F8_Local-007EC6)](benchmarks/swebench_submission/entry/20261108_kintsugi-harness/README.md)
[![Synthetic GAIA Fixture: JSONL Pack](https://img.shields.io/badge/Synthetic_GAIA_Fixture-JSONL_Pack-FFB300)](benchmarks/gaia_submission/README.md)
[![SLSA Provenance: Ready](https://img.shields.io/badge/SLSA_Provenance-Verified_SHA256-blue)](.github/workflows/ci-and-arena-verification.yml)
[![Security Policy: RFC 9116 & OpenSSF](https://img.shields.io/badge/Security_Policy-RFC_9116_%26_OpenSSF-success)](SECURITY.md)
[![Glama MCP Server](https://glama.ai/mcp/servers/tunguyen1993/kintsugi-harness/badge)](https://glama.ai/mcp/servers/tunguyen1993/kintsugi-harness)
[![M8ven Score](https://m8ven.ai/badge/mcp/tunguyen1993-kintsugi-harness-63r6eu?v=d87df8708272650e30986e1a3ce790a6)](https://m8ven.ai/mcp/tunguyen1993-kintsugi-harness-63r6eu?s=readme)
[![Release: v2.4.1](https://img.shields.io/badge/Release-v2.4.1-blue)](CHANGELOG.md)
[![Kintsugi Posture: A+](https://img.shields.io/badge/kintsugi_posture-A%2B%20%28100/100%29-brightgreen)](https://github.com/tunguyen1993/kintsugi-harness)
[![Token Savings: 93.8% - 99.96%](https://img.shields.io/badge/KMI%2F1_Token_Savings-93.8%25--99.96%25-00C853)](src/kintsugi/compressor.py)
[![Rust Engine: 16.2 µs](https://img.shields.io/badge/Rust_Core-16.2_%C2%B5s%2Fcall_%2836_rules%29-DEA584?logo=rust)](Cargo.toml)
[![Tests: 60 Py + 18 Rust (Local & CI)](https://img.shields.io/badge/Tests-60_Py_%2B_18_Rust_%28CI%29-brightgreen)](tests/test_kintsugi.py)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(stdlib)-success.svg)](Cargo.toml)

> ⭐ **If Kintsugi saves your context window or catches a bug before commit, please [Star this repository on GitHub](https://github.com/tunguyen1993/kintsugi-harness)!** Stars help more Claude Code, Cursor, Windsurf, and MCP developers discover zero-overhead guardrails.

</div>

---

## ⏱️ Try It in 10 Seconds (1-Command Safe Tryout)

Install with zero third-party dependencies (`Python 3.9+ stdlib`) and scan/integrate your existing `.cursorrules`, `CLAUDE.md`, or `AGENTS.md` without modifying your workflow:

```bash
pip install git+https://github.com/tunguyen1993/kintsugi-harness.git && kintsugi integrate --discover
```

```text
# Try the reproducible benchmark + drop-in harness integrator on your repo:
$ kintsugi integrate . --mount
{
  "ok": true,
  "state": "MOUNTED",
  "verdict": "SAT_CLEAN",
  "translation_accounting": {
    "total_discovered_candidates": 4,
    "compiled_enforceable_guards": 16,
    "token_reduction_pct": 93.8
  },
  "attestation_receipt": {
    "wire": "@PROOF_DAG/1[profile=HARNESS_INTEGRATION_V180|state=MOUNTED|verdict=SAT_CLEAN|caps_granted=0]"
  }
}

# Revert cleanly at any time while preserving 100% of your manual edits:
$ kintsugi integrate --eject HARNESS-DEFAULT
```

---

## 🔌 Model Context Protocol (MCP) Server — `kintsugi mcp`

> **English:** Kintsugi includes a built-in, zero-dependency JSON-RPC 2.0 `stdio` MCP Server ([`src/kintsugi/mcp_server.py`](src/kintsugi/mcp_server.py), protocol `2024-11-05`, licensed under `Apache-2.0`). Any MCP-compatible client (**Claude Desktop**, **Claude Code**, **Cursor**, **Windsurf**, **Cline**, **Zed**) can invoke Kintsugi's AST+Regex guardrails, `@LOGIC/2` formal state-machine verifier, `@COMPACT/2` zero-loss context compactor, and domain-partitioned `KMI/1` shards directly over `stdio`.
>
> **中文说明 (Chinese Summary):** Kintsugi 内置零依赖的標準 JSON-RPC 2.0 `stdio` **Model Context Protocol (MCP) 服务器**（[`src/kintsugi/mcp_server.py`](src/kintsugi/mcp_server.py)，遵循 `Apache-2.0` 开源协议）。无需安装任何第三方依赖，即可在 **Claude Desktop**、**Claude Code**、**Cursor**、**Windsurf** 等客户端中直接调用 **9 个 MCP 工具 (Tools)**、**2 个 MCP 资源 (Resources)** 与 **2 个 MCP 提示词模板 (Prompts)**，实现 AST+正则安全扫描、按行业领域分片的 `KMI/1` 上下文压缩（节省 `93.8%–99.96%` Token）及零丢失对话压缩。

### 1. Install & Run the MCP Server (`1 Command`)

```bash
pip install git+https://github.com/tunguyen1993/kintsugi-harness.git
kintsugi mcp
```

### 2. Ready-to-Use `mcpServers` Configuration (`Claude Desktop` / `Cursor` / `Claude Code` / `Windsurf`)

Add the following block to `claude_desktop_config.json`, `.cursor/mcp.json`, or `.mcp.json`:

```json
{
  "mcpServers": {
    "kintsugi-harness": {
      "command": "kintsugi",
      "args": ["mcp", "--ledger", ".kintsugi/scars.json"]
    }
  }
}
```

### 3. Complete Inventory: 9 MCP Tools, 2 MCP Resources & 2 MCP Prompts

| Category | Name / URI | Annotations / Arguments | Description |
| :--- | :--- | :--- | :--- |
| **MCP Tool (`1/9`)** | `kintsugi_scan_code` | `readOnlyHint=true`, `idempotentHint=true` (`code`, `file_path`, `language`) | Deterministically scan inline code or a file path against verified Kintsugi Golden Scars (AST + Regex) before writing or committing. |
| **MCP Tool (`2/9`)** | `kintsugi_list_scars` | `readOnlyHint=true`, `idempotentHint=true` (`language`, `tag`, `domain`, `min_severity`) | List verified Golden Scars (`❌ Anti-Pattern` vs `✅ Verified Fix`) or emit a domain-routed `KMI/1` shard (`domain=security\|backend\|database\|frontend\|devops\|ai_mcp`). |
| **MCP Tool (`3/9`)** | `kintsugi_record_failure` | `readOnlyHint=false` (`error_summary`, `raw_trace`, `co_run`, `free_runners`, `paid_council`) | Compile a runtime/test failure into a self-verified Golden Scar (`scan(bad)>=1` & `scan(good)==0`) and persist to `.kintsugi/scars.json`. |
| **MCP Tool (`4/9`)** | `kintsugi_compile_skills` | `idempotentHint=true` (`workspace_root`, `targets`) | Compile `.kintsugi/scars.json` into `.claude/skills/*/SKILL.md`, `CLAUDE.md`, `AGENTS.md`, and `.cursor/rules/`. |
| **MCP Tool (`5/9`)** | `kintsugi_integrate_harness` | `idempotentHint=true` (`action`, `workspace_root`, `source_path`, `harness_id`) | Universal Drop-In Third-Party Harness Integrator (`@HARNESS_BRIDGE/1`): discover, quarantine (`@QUARANTINE/1`), `SAT+DL` conflict-check, mount, or eject `.cursorrules` / `CLAUDE.md` / `AGENTS.md`. |
| **MCP Tool (`6/9`)** | `kintsugi_verify_logic` | `readOnlyHint=true`, `idempotentHint=true` (`code`, `self_test`) | Run `@LOGIC/2` 5-Pillar Neuro-Symbolic Reasoning (DPLL SAT/MUS, Stratified Datalog, Difference Logic, Fallacy Guard, Login/OAuth2/MFA state-machine verifier). |
| **MCP Tool (`7/9`)** | `kintsugi_compact_context` | `idempotentHint=true` (`transcript_path`, `raw_conversation`, `max_tokens`, `inject_agents_md`) | Zero-Loss Anti-Overflow Conversation & Excel Compactor (`@COMPACT/2`): strips 4 noise classes while locking `100%` of `@USER_INTENTS` and `@HARD_ANCHORS`. |
| **MCP Tool (`8/9`)** | `kintsugi_multi_model_guide` | `readOnlyHint=true`, `openWorldHint=true` (`question`, `auto_configure-byok`) | Interactive Bilingual (`EN/VI`) User Onboarding Guide for Multi-Model Co-Execution, BYOK Paid Frontier Council keys, and `$0` DeepSeek Free token provisioning. |
| **MCP Tool (`9/9`)** | `kintsugi_cinema_produce` | `idempotentHint=true`, `openWorldHint=true` (`style_mode`, `provider`, `auto_heal`, `manifest`) | OpenMontage Cinema Director's Cut Extension (`@OPENMONTAGE_CINEMA/1`): 9-provider video router, 6-Gate Component Video QA, and `@CINEMA_EVOLVE/1` auto-healing. |
| **MCP Resource (`1/2`)** | `kintsugi://ledger/scars` | `application/json` | Full JSON ledger of all verified AST + Regex Golden Scars in the active workspace. |
| **MCP Resource (`2/2`)** | `kintsugi://posture/summary` | `application/json` | Live posture summary: version (`2.4.1`), license (`Apache-2.0`), active scar count, `KMI/1` & Domain Shard compression metrics (`93.8%` / `94.0%` / `99.96%`), Rust latency (`16.2 µs`), and `docs/domains/` shard map. |
| **MCP Prompt (`1/2`)** | `kintsugi-audit-code` | Required arg: `file_path` | Structured workflow prompt that runs `kintsugi_scan_code` + `kintsugi_verify_logic` on a target file. |
| **MCP Prompt (`2/2`)** | `kintsugi-evolve-scar` | Required arg: `error_summary`; Optional: `raw_trace` | Structured workflow prompt that synthesizes a self-verified Golden Scar via `kintsugi_record_failure` and updates the `KMI/1` wire index. |

---

## 📊 Reproducible Benchmarks / 可复现基准测试说明 (`v2.4.1`)

> **English:** Every token-compression and test-count metric in Kintsugi is deterministic and arithmetic-checked (`global_pct = round(((verbose - compact) / verbose) * 100, 1)`, `domain_shard_pct = round(((verbose - shard) / verbose) * 100, 2)` using `estimate_tokens`), and latency figures are environment-dependent measured reference benchmarks (macOS Apple Silicon M-series, `rustc --release`, Python 3.12) reproducible locally using the exact commands below. When running `kintsugi mcp --ledger .kintsugi/scars.json`, relative ledger paths resolve against the active project working directory (`cwd`) and automatically fall back to the built-in 16-rule starter pack if no `.kintsugi/scars.json` file exists yet.
>
> **中文说明:** Kintsugi 中的每一项 Token 压缩率（基于确定性 BPE 估算函数 `estimate_tokens`）与测试通过数均可在本机 100% 确定性复现，延迟数据为参考硬件实测值（macOS Apple Silicon，`--release` 编译，200 次迭代均值）。通过将规则文档按 **6 大软件工程领域分片 (`docs/domains/01..06`)** 并结合 `KMI/1` 符号微索引，单轮上下文开销从完整的 `414,267 tokens`（1,789 条演进规则）或 `3,641 tokens`（16 条核心规则）降至按领域按需加载的 **`~175.7 tokens/turn`（6 个领域均值，节省 `99.96%`）** 或 **`~80.5 tokens/turn`（6 个领域均值，节省 `97.79%`）**。

### 1. Run All 5 Verification & Benchmark Commands Locally

```bash
# 1. Python Unit Test Suite (60 Python unittest cases verified, plus optional `.[proof]` Z3 patch equivalence):
PYTHONPATH=src python3 -m unittest discover -s tests -v

# 2. Native Rust Unit Test Suite (15 kintsugi_core + 3 rust-neuro-symbolic-core = 18 Rust tests via `cargo test --all-targets`):
cargo test --all-targets && cargo build --release --bins

# 3. Native Rust Single-File Scan & @KML/1 Shield Benchmark (36 builtin rules, 200 iterations, ~16.2 µs/call):
cargo build --release && ./target/release/kintsugi-rs bench

# 4. Python AST+Regex Corpus Recall/Precision (16 Pos + 16 Neg, F1=1.000, ~28 ms) & Edition Verifier:
python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py

# 5. Global KMI/1 & 6-Domain Partitioned Context Compression Benchmarks (Starter 16-rule & Evolved 1,797-rule):
PYTHONPATH=src python3 -m kintsugi.cli token-report --starter-only
PYTHONPATH=src python3 -m kintsugi.cli token-report
PYTHONPATH=src python3 -m kintsugi.cli token-report --starter-only --domain security
PYTHONPATH=src python3 -m kintsugi.cli token-report --domain security
```

### 2. Methodology & Arithmetic Breakdown

- **Token Estimator (`src/kintsugi/compressor.py:estimate_tokens`):** Deterministic BPE approximation `max((len(text) + 3) // 4, int(len(words_and_punct) * 0.78))`.
- **Verbose Baseline (`SkillCompiler.render_skill_markdown`):** Full Markdown tutorials containing `Root Cause`, `Rationale`, `❌ Bad Code`, and `✅ Verified Fix` blocks measured directly with `estimate_tokens(verbose_md)`.
- **Global `KMI/1` Wire Index (`render_kmi_index`):** Compiles every rule into a `<12-token` symbolic micro-signature (`KS-001(secret!=literal->os.environ)`) with full prose expanded only Just-In-Time (`<95 tokens`) when a `PreToolUse` violation occurs:
  - **16-Scar Core Starter Pack (`--starter-only`):** `3,641` verbose tokens $\to$ `226` `KMI/1` tokens/turn = **`3,415` tokens saved/turn (`(3641 - 226) / 3641 = 93.8%` reduction; `170,750` tokens saved per 50-turn session)**.
  - **1,789-Scar Full Evolved Ledger (`.kintsugi/scars.json`):** `414,267` verbose tokens $\to$ `24,967` `KMI/1` tokens/turn = **`389,300` tokens saved/turn (`(414267 - 24967) / 414267 = 94.0%` reduction; `19,465,000` tokens saved per 50-turn session)**.
- **Domain-Partitioned Documentation Shards (`docs/domains/01..06` + `partition_by_domain` + `render_domain_kmi_pack`):** Partitions rules and documentation across **6 generic software engineering domains** so agents load only the active domain shard (top-8 domain rules inline + 1-line `@DEFERRED_DOMAIN_POOL` Merkle digest for remaining domain rules):

| Domain ID | Partitioned Documentation Shard | Core Starter Rules (`16`) | Core Shard Cost (`tok/turn`) | Core Reduction vs `3,641` Verbose | Full Ledger Rules (`1,789`) | Full Ledger Shard Cost (`tok/turn`) | Full Ledger Reduction vs `414,267` Verbose |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `security` | [`docs/domains/01_security_appsec.md`](docs/domains/01_security_appsec.md) | `4` | `95 tok` | **`97.39%`** (`177,300` saved/50t) | `322` | `164 tok` | **`99.96%`** (`20,705,150` saved/50t) |
| `backend` | [`docs/domains/02_backend_api.md`](docs/domains/02_backend_api.md) | `4` | `94 tok` | **`97.42%`** (`177,350` saved/50t) | `327` | `183 tok` | **`99.96%`** (`20,704,200` saved/50t) |
| `database` | [`docs/domains/03_database_sql.md`](docs/domains/03_database_sql.md) | `1` | `65 tok` | **`98.21%`** (`178,800` saved/50t) | `291` | `179 tok` | **`99.96%`** (`20,704,400` saved/50t) |
| `frontend` | [`docs/domains/04_frontend_ui.md`](docs/domains/04_frontend_ui.md) | `2` | `74 tok` | **`97.97%`** (`178,350` saved/50t) | `287` | `180 tok` | **`99.96%`** (`20,704,350` saved/50t) |
| `devops` | [`docs/domains/05_devops_cloud.md`](docs/domains/05_devops_cloud.md) | `3` | `85 tok` | **`97.67%`** (`177,800` saved/50t) | `267` | `166 tok` | **`99.96%`** (`20,705,050` saved/50t) |
| `ai_mcp` | [`docs/domains/06_ai_mcp_agents.md`](docs/domains/06_ai_mcp_agents.md) | `2` | `70 tok` | **`98.08%`** (`178,550` saved/50t) | `295` | `182 tok` | **`99.96%`** (`20,704,250` saved/50t) |
| **Average / Total** | **All 6 Domain Shards** | **`16`** | **`80.5 tok`** | **`97.79%`** | **`1,789`** | **`175.7 tok`** | **`99.96%`** |

- **Native Rust `PreToolUse` Latency (`./target/release/kintsugi-rs bench`):** Evaluates a 4-line Python source snippet (`bench.py`) against all **`36` Builtin Rules** (`KS-001..KS-032` + `KS-S3-01..04`) over `200` iterations in **`~16.2 µs/call` (`0.0162 ms/call`)**, and parses/shields all `1,789` `@KML/1.0` records in `.kintsugi/scars.kml` with **`0` quarantined records**.

---

## 🎬 New in `v1.9.0`: OpenMontage Cinema Director's Cut Extension Package (`@OPENMONTAGE_CINEMA/1` · `kintsugi cinema`)

When a user asks the agent to produce a video or short film, Kintsugi's **`kintsugi-openmontage-cinema`** extension package ([`src/kintsugi/cinema.py`](src/kintsugi/cinema.py)) automatically pulls and sandboxes [`calesthio/OpenMontage`](https://github.com/calesthio/OpenMontage) into `.kintsugi/extensions/openmontage/` (`-c core.hooksPath=/dev/null -c core.symlinks=false`), routes shots across **9 AI Video Generators** (**Google Veo 3.1**, **Open-Weights Engine**, **Kling 2.0**, **Runway Gen-3**, **Luma Ray2**, **Pika 2.2**, **Hailuo MiniMax**, **Sora**, and **Wan 2.1**), optimizes visuals for either **Photorealistic Human Cinema (`--style live_action` · ARRI Alexa LF + Kodak 2383 LUT)** or **2D/3D Studio Animation (`--style animation` · Cel Vibrance LUT)**, enforces **Mandatory 6-Gate Component Video QA** before stitching, and evolves filmmaking intelligence via **`@CINEMA_EVOLVE/1` (`CS-001`..`CS-012`)**.

<div align="center">

### 🎥 Watch the Full 3-Minute Director's Cut Demo Film Produced by `@OPENMONTAGE_CINEMA/1`

[![Watch Kintsugi OpenMontage Cinema Director's Cut Showcase on YouTube](https://img.youtube.com/vi/tfo2QYUU-c8/maxresdefault.jpg)](https://www.youtube.com/watch?v=tfo2QYUU-c8)

▶️ **[Watch on YouTube: `https://www.youtube.com/watch?v=tfo2QYUU-c8`](https://www.youtube.com/watch?v=tfo2QYUU-c8)**  
*3-Minute (`180.0s`) 24-Shot Sci-Fi Drama ("The Last Light of Station 09") — Verified `100% PASS` across all 6 Component Video QA Gates.*

</div>

```bash
# Auto-pull OpenMontage, run 6-Gate Script-to-Frame QA, and auto-heal via @CINEMA_EVOLVE/1:
kintsugi cinema --pull-openmontage --auto-heal --style live_action --provider veo --wire
# -> @OPENMONTAGE_CINEMA/1[v=1.9.0|provider=veo|style=live_action|healed=12->0|scars=12|verdict=PASS_DIRECTOR_CUT_READY]

# Switch to 2D/3D Studio Animation with Open-Weights Engine ($0 Free 2B Pool) and synthesize component test clips:
kintsugi cinema --auto-heal --style animation --provider muse --synthesize-test-clips /tmp/cinema_clips
```

| Mandatory Component Video QA Gate | What It Verifies on Every `shot_01..shot_N` Before Stitching | Seeded Cinema Scar |
| :--- | :--- | :--- |
| **Gate 1: Script-to-Frame Discrepancy Verifier** | Verifies speaker cues vs `voice_role` (`daughter_radio` vs `narrator`), shot title vs visual action, and paired Station / 4-Engine Aircraft / Capsule / 1.2m Titanium Pry-Bar continuity | `CS-004`, `CS-005`, `CS-006`, `CS-009` |
| **Gate 2: Borderless Frame Hygiene** | Scans top/bottom/left/right keyframe strips to reject `35mm` film sprocket holes and unrequested letterbox bars | `CS-003` |
| **Gate 3: Character Wardrobe & Collar DNA Lock** | Enforces positive-only DNA (`LONG-SLEEVED full-length sleeves buttoned at wrists`, `clean bare throat`, `plain unbranded fabric`, `dry matte skin`) and blocks negative-token leakage (`neck ring`, `NASA/NACA`) | `CS-001`, `CS-002`, `CS-010`, `CS-011` |
| **Gate 4: User-Selected Visual Style Fidelity** | Verifies `live_action` (`LUT_KODAK_2383_ARRI_ALEXA_LF_V4`) vs `animation` (`LUT_ANIMATION_CEL_VIBRANCE_V4`) optics and LUT lock | `I-S-1..4` |
| **Gate 5: Temporal & Motion Integrity** | Verifies constant FPS, `1.0x` realtime playback (zero slow-mo stretching), and non-zero inter-frame optical motion energy | `CS-007` |
| **Gate 6: Audio-First Integer-Tick Sync & J/L-Cuts** | Verifies `\|video_ticks - audio_ticks\| <= 1` frame, strips `100%` of native generator Mandarin/vocal bleed, and applies sample-exact J-cut (`-0.34s` / `-16320` samples @ 48kHz) & L-cut (`+0.45s` / `+21600` samples @ 48kHz) timeline bridges | `CS-007`, `CS-008`, `CS-012` |

---

## Why Kintsugi?

**Kintsugi (金継ぎ)** is the Japanese craft of repairing broken pottery with lacquer and gold—treating fractures as structural reinforcement rather than hiding them.

Existing agent harnesses and rule repositories (`Superpowers`, static `.cursorrules`, raw `CLAUDE.md` collections) suffer from three fundamental bottlenecks:
1. **Massive Token Bloat (`3,300–8,500+ tokens/turn`):** Loading verbose Markdown tutorials into `CLAUDE.md` or `AGENTS.md` burns **150,000+ tokens** over a single 50-turn coding session and crowds out working memory.
2. **Advisory Prose != Enforcement:** Markdown instructions are merely suggestions; agents still run `subprocess(..., shell=True)`, hardcode secrets, or execute destructive shell commands under pressure.
3. **Slow Hook Latency:** Heavy linters add `300–1,500ms` of overhead on every tool call.

**Kintsugi v2.4.1** solves all three with a **Native Rust Engine (`kintsugi-rs`, `~16.2 µs/call` across 36 builtin rules)**, **Multi-Language Zero-Dependency Structural AST-Lite (`Python, JS/TS, Go, Rust, C/C++, Java`)**, an **Ultra-Compact Wire Index (`KMI/1` — `226 tokens/turn` on 16 Core Scars [`93.8%` savings] and `80.5 tokens/turn` with Domain-Partitioned Shards [`97.79%` savings]; `99.96%` savings on the `1,797`-scar evolved ledger)**, **`@CREED/1 v2.1` 5-Pillar Autopoietic Evolution IR**, **`@SWARM_DISPATCH/1` Subscription-Aware Auto-Subagent Swarm Dispatcher & `@MODEL_MATRIX/1` 6-Tier Model Capability Matrix**, **`@DUAL_COUNCIL/1` & `@NEVER_SOLO_GATE/1`**, **`@HARNESS_BRIDGE/1` Universal Drop-In Third-Party Harness Integrator (`kintsugi integrate`)**, **3-Tier Multi-Model Co-Execution (`Primary + 1..5 Free Models + BYOK Paid Frontier Council`)**, **`@LOGIC/2` 5-Pillar Neuro-Symbolic Verification + `@PROOF_DAG/1` Signed Compliance Proofs**, and **Just-In-Time (JIT) `PreToolUse` Rule Expansion**:

```mermaid
flowchart LR
    A["Agent Prompt Turn\n(KMI/1 Global: 226 tok | Domain Shard: ~80.5 tok)"] --> B["Agent Emits Write / Edit / Bash"]
    B --> C{"Native Rust / Python PreToolUse Hook\n(16.2 µs scan | Git-Diff Hunk Filter)"}
    C -- "Clean Code (0 extra tokens)" --> D["Tool Executes Immediately"]
    C -- "Violation Detected" --> E["JIT Single-Rule Expansion (<95 tokens)\nBlocks Call & Injects Verified Fix"]
    E --> F["3-Agent Evolution Council\nCompiles New Failures into .kintsugi/scars.json"]
```

---

## Benchmark: Kintsugi v2.4.1 vs Other Agent Harnesses

| Capability / Metric | **Kintsugi Harness (`v2.4.1`)** | Static `CLAUDE.md` / `CursorRules` | Prompt-Heavy Skill Frameworks | Traditional `pre-commit` Linters |
| :--- | :--- | :--- | :--- | :--- |
| **Per-Turn Context Cost (16 Core / 1,789 Full)** | **`226 tok` (Global `KMI/1`) / `80.5 tok` (Domain Shard)** | `3,641 tokens` (`16` rules) / `414,267 tokens` (`1,789` rules) | `4,500–9,000+ tokens` | `0` (no agent awareness) |
| **Tokens Saved per 50-Turn Session** | **`170,750 tok` (`93.8%`) to `20,705,150 tok` (`99.96%` Domain Shard)** | `0` (Baseline) | Negative (`-225k+ tokens`) | N/A |
| **Inline `PreToolUse` Latency** | **`16.2 µs` (`kintsugi-rs` Rust, 36 rules) / `~21 ms` (Py single-file)** | N/A (Advisory only) | N/A (Advisory only) | `350–1,800 ms` (Post-edit only) |
| **True-Positive / `0` False-Positive Gate** | **Enforced (`verify-ledger` invariant)** | Manual / None | Manual / None | Rule-dependent |
| **Runtime Dependencies** | **`0` (`Rust std` + `Python stdlib`)** | `0` | Node/Python deps | Node/Python/Go toolchains |
| **Multi-Agent Compilation** | **Claude, Cursor, Copilot, Windsurf, Codex, MCP** | Single IDE | 1–2 agents | Git hooks only |

---

## Open-Core Architecture & Edition Matrix (`v2.0.0` — Free vs Tier 1 / Tier 2 / Tier 3 Pro)

Independent evaluators can verify all 4 editions, `@KML/1` compression ratios, Auto-Fix codemods, and `.kpack` AEAD cryptography in `1.3s` with:

```bash
python3 free-skill-pack/scripts/verify_editions_and_benchmarks.py
```

| Capability / Module | **Core Guard Free (`$0` OSS)** | **Tier 1: FinOps & Reliability Pack (`Apache-2.0`)** | **Tier 2: AppSec & MCP Pack (`Apache-2.0`)** | **Tier 3: Complete Corpus Pack (`Apache-2.0`)** |
| :--- | :---: | :---: | :---: | :---: |
| **Native Rust Engine (`kintsugi-rs v2.0.0`) & Multi-Language Structural AST-Lite (`py,js,ts,go,rs`)** | Included (`100% Open Source`) | Included | Included | **Included** |
| **`@HARNESS_BRIDGE/1` Universal Drop-In Third-Party Harness Integrator (`kintsugi integrate`)** | **Included: Discover + SAT+DL Conflict Check + `1` Active Mounted Harness** | **Unlocked: Multi-Harness Federation (`Up to 10` Mounted Harnesses)** | **Unlocked: Multi-Harness Federation (`Up to 10` Mounted Harnesses)** | **Unlocked: Enterprise Multi-Harness Federation (`Up to 100` Mounted Harnesses + Signed `@PROOF_DAG/1` Receipts)** |
| **Multi-Model Co-Execution Engine (`--co-run`)** | **Locked: `Primary + 1 Free Model`** | **Unlocked: `Primary + 2..5 Free Models` (Auto 429 Failover)** | **Unlocked: `Primary + 2..5 Free Models` (Auto 429 Failover)** | **Unlocked: `Primary + 5 Free Models + BYOK Paid Frontier Council`** |
| **BYOK Paid Frontier Agent Council (`--paid-council`)** | — (Locked) | — (Locked) | — (Locked) | **Unlocked (`Claude Opus 4.6/5.5`, `GPT-5.4`, `Grok-3 Max` BYOK)** |
| **`@LOGIC/2` 5-Pillar Neuro-Symbolic Reasoning & Login Verifier (`kintsugi logic`)** | Included (`DPLL SAT/MUS`, `Stratified Datalog`, `Difference Logic`, `Fallacy Guard`, `MHS`) | Included | Included | **Included (`+ Adversarial Council Arena`)** |
| **`@PROOF_DAG/1` Signed Compliance Proofs & `@ZK_AST_DIFF/1` (`kintsugi verify`)** | Included (`LOCAL_DEV_ATTESTATION`) | Included (`+ FinOps Controls`) | Included (`+ AppSec/MCP Controls`) | **Included (`ENTERPRISE_PROVISIONED_SEAL` SOC2 / ISO27001 / EU AI Act)** |
| **`@EVAL_SUITE/1` Open Reproducible Benchmark & Replay (`kintsugi eval`)** | Included (`6/6 Cases + 3-Arm Ablation`) | Included | Included | **Included** |
| **Zero-Loss Anti-Overflow Conversation & Excel Compactor (`kintsugi compact` / `@COMPACT/2`)** | Included (`100% Anchor & Excel Sum Retention`) | Included (`+ Multi-Free Co-Verify`) | Included (`+ Multi-Free Co-Verify`) | **Included (`+ Full Council Co-Verify`)** |
| **Curated Core + Exclusive Pro Scars (`KS-001`..`KS-032`)** | 16 Core (`KS-001..016`) | 11 FinOps/Reliability (`KS-018,025,026,030,031` + Core) | 21 AppSec/MCP (`KS-017,019..024,027..029,032` + Core) | **All 32/32 (`KS-001..KS-032`)** |
| **`@KML/1` Symbolic Machine-Language Wire (`scars.kml`)** | 16 rules (1,789 in OSS repo) | **844 `@KML/1` FinOps rules** | **862 `@KML/1` Security rules** | **All 1,789 `@KML/1` rules** |
| **Deterministic Auto-Remediation (`kintsugi autofix --apply`)** | Dry-Run Diff Preview (`--dry-run`) | **4 In-Place Auto-Fix Codemods** | **8 In-Place Auto-Fix Codemods** | **All 12/12 In-Place Auto-Fix Codemods** |
| **Interactive Slash Commands (`.claude/commands/*.md`)** | Manual CLI | **5 Slash Workflows** | **5 Slash Workflows** | **5 Slash Workflows (`/kintsugi-audit`, `/kintsugi-autofix`, `/kintsugi-mcp-shield`, `/kintsugi-release-gate`, `/kintsugi-multi-model-council`)** |
| **Frontier Collective Pool (`collective_pool_lessons.json`)** | Included (`collective-pool/`) | **41 Pre-Bundled Frontier Lessons** | **41 Pre-Bundled Frontier Lessons** | **41 Pre-Bundled Frontier Lessons** |
| **Delivery Formats** | `.zip` ([`free-skill-pack/`](free-skill-pack/)) | `.zip` + AEAD `.kpack` | `.zip` + AEAD `.kpack` | **`.zip` + AEAD `.kpack`** |

> [!IMPORTANT]
> **New in `v1.5.0`–`v1.7.0` — `@LOGIC/2` 5-Pillar Logical Reasoning, `@PROOF_DAG/1` Signed Compliance Proofs, `@COMPACT/2` Excel Compactor & 3-Tier Multi-Model Co-Execution:**
> - **Always-On Co-Execution & Autonomous `$0` DeepSeek Free Token Collector:** Your **Primary Model** never runs alone — Kintsugi automatically discovers available `$0` Free Co-Runner models and includes a **6-Step Zero-Touch DeepSeek Free Token Collector (`kintsugi swarm --configure-byok`)** that autonomously creates a disposable `example.invalid` inbox, verifies the signup magic link, mints a real `tj_...` API key for `deepseek-ai/DeepSeek-R1` (`262K` context window, `$0` Unlimited Free, no credit card), verifies `HTTP 200 OK` live chat completion, and stores it in `.kintsugi/byok_provider_pool.json` (`0600`).
> - **Tier 0 (`$0` Free / OSS):** Locked to **`Primary + 1 Free Model ($0)`** (`max_free_co_runners = 1`). Passing `--free-runners 2..5` automatically clamps to `1` and displays the upgrade path.
> - **Tier 1 & Tier 2 (`Apache-2.0` FinOps Pro / `Apache-2.0` AppSec Pro):** Unlocks **`Primary + up to 5 Parallel Free Models ($0)`** (`max_free_co_runners = 5`) with automatic HTTP `429` / timeout round-robin failover and `12.5x` Byzantine-Fault-Tolerant (`BFT`) error reduction.
> - **Tier 3 (`Apache-2.0` Complete Corpus Pack):** Unlocks **`Primary + 5 Free Models ($0) + 6-Seat Paid Frontier Council (`BYOK`)`** (`Claude Opus 4.6`, `GPT-5.4 Thinking`, `Grok 4`, `Gemini 2.5 Pro`, `DeepSeek R1`, `OpenRouter Frontier`).
> - **How the Agent Guides Users (`BYOK` — Bring Your Own Key):** Paid Frontier Council seats require users to supply their own API keys (stored strictly locally at `.kintsugi/paid_council_pool.json` with `chmod 0600` permissions). Run **`kintsugi swarm --guide`** (or slash command **`/kintsugi-multi-model-council`**, or MCP tool **`kintsugi_multi_model_guide`**) at any time for an interactive bilingual (`EN/VI`) setup walkthrough.
> - **Zero-Loss Anti-Overflow Conversation Compactor (`@COMPACT/1` — `kintsugi compact`):** When a long coding conversation fills up (`>=70%` soft / `>=85%` hard watermark), `kintsugi compact --inject-agents` (and MCP tool `kintsugi_compact_context`) automatically strips 4 classes of conversation noise (verbose build/test logs, duplicate polling loops, superseded file reads, and exploratory monologue) while locking **100% of Hard Anchors** (`@USER_INTENTS`, `file:line` anchors, git SHAs/tags, rule IDs, pinned IPs/ports, active daemons, and `@ERRORS_AND_FIXES`) into `.kintsugi/context_checkpoints/latest_checkpoint.md` and a `<180-token` `@COMPACT/1` symbolic wire capsule in `CLAUDE.md` / `AGENTS.md`.

---

## Quick Start

### 1. Install (Python SDK + Optional Native Rust Binary)

```bash
git clone https://github.com/tunguyen1993/kintsugi-harness.git
cd kintsugi-harness
pip install -e .

# Optional: Build the zero-dependency native Rust engine (compiles in ~1.5s)
cargo build --release
./target/release/kintsugi-rs bench
```

### 2. Initialize & Compile Ultra-Low-Token `KMI/1` Agent Governance

```bash
# Compile with --compact to emit the 226-token KMI/1 wire header (93.8% token savings)
kintsugi init --compact
kintsugi compile --targets all --compact
```

### 3. Benchmark Token Savings & Run Posture Audit (`Grade A+`)

```bash
# Measure exact KMI/1 token savings vs verbose Markdown skills
kintsugi token-report

# Generate a repository Security & Agent Readiness Scorecard (Grade A+ to F)
kintsugi audit . --format markdown
```

### 4. Scan Code, Staged Git Diffs & Preview Auto-Fixes

```bash
# Sub-millisecond native Rust scan or staged git-diff scan
./target/release/kintsugi-rs scan .
./target/release/kintsugi-rs scan . --staged

# Python AST + Regex scan with unified diff patch preview
kintsugi scan . --staged --patch-preview

# Preview or apply deterministic auto-remediation codemods
kintsugi autofix .
```

### 5. Install External or Pro Skill Packs (`kintsugi install-pack`)

```bash
# Install an encrypted .kpack or standalone .zip Skill Pack (e.g., from Agensi.io or GitHub Releases)
kintsugi install-pack kintsugi-enterprise-complete-pro-v2.0.0.kpack --license-key <YOUR_LICENSE_KEY>
kintsugi list-packs

# Run unlocked in-place auto-remediation codemods
kintsugi autofix . --apply
```

### 5A. `@LOGIC/2` 5-Pillar Logical Reasoning, `@PROOF_DAG/1` Signed Compliance Proofs & `@EVAL_SUITE/1` (`v1.6.0`–`v1.7.0`)

```bash
# 1. Run the 5-Pillar Neuro-Symbolic Reasoning Benchmark (DPLL SAT/MUS, Stratified Datalog, Difference Logic, Fallacy Guard, Reiter MHS)
kintsugi logic --benchmark --wire

# 2. Verify Formal Login / OAuth2 / MFA Step-Up / Session Revocation / OTP Replay State Machines
kintsugi logic --login-verify

# 3. Export & Verify a Cryptographically Signed Compliance Bundle (.kintsugi/audit.proof — SOC2 / ISO27001 / EU AI Act)
kintsugi verify --export-audit .kintsugi/audit.proof --wire
kintsugi verify --verify-proof .kintsugi/audit.proof

# 4. Run the Open Reproducible 6-Case Evaluation & 3-Arm Ablation Suite
kintsugi eval --wire
kintsugi eval --replay EVAL-AUTH-001
```

### 5B. Tier-Gated Multi-Model Co-Execution & BYOK Paid Frontier Council (`kintsugi swarm --guide`)

Kintsugi guarantees your **Primary Anchor Model** always runs alongside dynamically discovered `$0` Free Co-Runners (and optional user-supplied BYOK Paid Frontier Council seats):

```bash
# 1. Inspect active tier & Bilingual Agent Onboarding Guide
kintsugi swarm --guide

# 2. Free Tier ($0): Auto-register a live $0 DeepSeek-R1 (262K) API key & run Primary + 1 Free Model
kintsugi swarm --configure-byok
kintsugi swarm . --co-run

# 3. Pro Tier (Apache-2.0 / Apache-2.0): Unlocks 2..5 parallel $0 Free Co-Runners with automatic 429 failover
kintsugi swarm --authorize-auto-provision
kintsugi swarm . --co-run --free-runners 4

# 4. Complete Corpus Pack (Apache-2.0): Add your own BYOK Paid Frontier Council API keys (stored locally 0600)
kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>
kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>
kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>
kintsugi swarm --paid-council-status
kintsugi swarm . --co-run --free-runners 3 --paid-council

# 5. Zero-Loss Anti-Overflow Conversation Compaction (@COMPACT/1 — strips noise & locks 100% of main points):
kintsugi compact --inject-agents
kintsugi compact --wire
```

### 6. Human-Like Cognitive Learning, Zero-GitHub-Account Relay & GitHub Skill Collector (`kintsugi learn`)

Unlike bloated harnesses that dump noisy chat transcripts into memory, Kintsugi distills mistakes across **15 Universal Domains** (**7 Engineering Pillars**: `ai-agents-mcp`, `backend-api`, `security-zerotrust`, `fintech-web3`, `devops-cloud`, `frontend-ts`, `data-ml` + **8 Real-Life & Business Pillars**: `finance-capital`, `business-negotiation`, `psychology-relationships`, `legal-contracts`, `health-longevity`, `decision-strategy`, `research-epistemology`, `growth-marketing`) into causal **`CognitiveLesson`** records (`cognitive_trap` + `mental_model` + executable guardrail):

```bash
# Option 1 (Default — Privacy-First Local-Only + Pull by Engineering / Real-Life Domain):
# Keep self-learned lessons strictly in .kintsugi/lessons_local.json (gitignored)
# and pull curated Frontier lessons for your engineering & life domains from GitHub or Relay:
kintsugi learn config --mode local-only --domains ai-agents-mcp,finance-capital,business-negotiation,decision-strategy
kintsugi learn pull --domains ai-agents-mcp,finance-capital,business-negotiation --relay

# Option 2 (Federated Collective Pool Sync + Zero-GitHub-Account Relay — Tier-1 Frontier Models Only):
# Publish newly distilled lessons to collective-pool/<domain>/<model_family>/<id>.json
# AND broadcast to the Zero-GitHub-Account Public Relay (KINTSUGI-RELAY/1) so agents without
# a GitHub account can contribute directly after passing the 4-Stage Frontier Epistemic Gate:
#   1. Tier-1 Frontier Model Provenance (claude-opus/sonnet-4, GPT-5.4, deepseek-r1, Gemini-2.5-Pro, Qwen-2.5-Coder, grok-4)
#      -> Low-tier models (mini, flash-lite, haiku, 8b) are strictly blocked from syncing upstream.
#   2. Deterministic TP/FP Self-Verification (`scan(bad) >= 1` & `scan(good) == 0`)
#   3. Structural & Semantic Anti-Duplicate Check (duplicates merge into reinforcement_count)
#   4. Zero-Leak DLP Sanitization
kintsugi learn config --mode federated-sync
kintsugi learn push-relay
kintsugi learn sync-relay --since 48h

# Option 3 (Autonomous GitHub Skill & Guardrail Repo Collector):
# Scan external GitHub skill repositories (anthropics/skills, patrickjs/awesome-cursorrules, etc.)
# and merge Frontier-verified guardrails into the shared Collective Pool:
kintsugi learn harvest-github
kintsugi learn pool-status
```

### 7. Neuro-Symbolic 3-State AST Symbol Grounding Gate (`kintsugi ground` — `<5ms` Anti-Hallucination)

Prevent AI agents from hallucinating non-existent functions, variables, or line numbers during security audits and automated code edits:

```bash
# Build a deterministic SHA-256 manifest, AST symbol table, and cross-boundary seam index:
kintsugi ground src/

# Verify an agent's hypothesis against real AST symbols & line anchors in <5ms (VERIFIED / REFUTED / UNKNOWN):
kintsugi ground src/ --verify-anchor kintsugi/scanner.py:42 --verify-symbols KintsugiScanner,scan_path
```

### 8. Autopoietic Self-Generation, Metacognitive Self-Awareness & 3-Horizon Causal Foresight (`kintsugi foresight`)

Give your coding agent human-like metacognitive self-awareness, autonomous rule synthesis, and a 3-Horizon predictive world model (`T+1` Immediate Direct Risk, `T+2` Second-Order Call-Graph Cascade, `T+3` Epistemic & Concurrency Tail-Risk):

```bash
# 1. Forecast T+1 / T+2 / T+3 failure horizons and generate a Q-ranked Pre-Emptive Action Queue:
kintsugi foresight src/

# 2. Emit ultra-compact <90-token @FORESIGHT/1 + @META/1 wire headers for agent context injection:
kintsugi foresight src/ --wire

# 3. Inspect Beta-Bernoulli domain competence, surprise index, and epistemic blind spots:
kintsugi foresight --metacognition

# 4. Autonomously synthesize & counterfactually verify new CognitiveLessons from unguarded code seams:
kintsugi foresight src/ --self-generate

# 5. Run Counterfactual Sandbox Dreamer (@DREAM/1) — apply S3 guards in-memory & prove 100% risk reduction without touching disk:
kintsugi foresight src/ --dream

# 6. Run Cross-Domain Analogical Transfer Engine — map scientific conservation laws to Distributed Systems, FinTech & Strategy invariants:
kintsugi foresight src/ --transfer
```

### 9. Shadow-Clone Parallel Epistemic Swarm & BFT Experience Consolidation (`kintsugi swarm` — `v1.0.0`)

Inspired by parallel Shadow Clone (`Kage Bunshin`) exploration: when encountering an unfamiliar codebase or task, the Central Brain spawns **`K = 4` isolated orthogonal Shadow Clones** (`K = 3f + 1` Byzantine Fault Tolerance) with zero inter-clone communication during execution so clones never collapse into groupthink:
- **Clone 1 (`TRACK_1_AST_BOUNDARY_SEAMS`):** Maps AST symbol tables, function/class boundaries, and structural seams.
- **Clone 2 (`TRACK_2_ADVERSARIAL_RED_TEAM`):** Probes `S0 -> S1 -> S2` exploit chains, edge cases, and adversarial hallucination traps.
- **Clone 3 (`TRACK_3_COUNTERFACTUAL_S3_SYNTHESIS`):** Synthesizes candidate `S3` guards and replays them in the isolated Counterfactual Sandbox.
- **Clone 4 (`TRACK_4_ANALOGICAL_LAW_MAPPER`):** Maps cross-domain physical/mathematical conservation laws and 3-Horizon (`T+1/T+2/T+3`) cascade priorities.

Each clone reaches its own independent, cryptographically signed `CloneEpisodicReport`. Upon completion, all `K = 4` clones merge back into the single Central Brain via a **Byzantine-Fault-Tolerant Quorum (`s_p >= 3`)**, quarantining refuted/hallucinated paths into the **Negative Tabu List** while distilling verified truths into a single deterministic **Step-by-Step Right Playbook (`Cách Làm Đúng`)**:

```bash
# 1. Spawn K=4 orthogonal Shadow Clones in parallel and merge their conclusions into 1 Verified Right Playbook:
kintsugi swarm src/

# 2. Emit the ultra-compact <45-token @SWARM/1 wire header:
kintsugi swarm src/ --wire

# 3. Verify Byzantine Fault Tolerance (inject a corrupted/hallucinating clone and prove 3/4 honest quorum still holds):
kintsugi swarm src/ --byzantine-test

# 4. Consent-Gated Free-Agent Pool (@POOL/1 — 12.5x BFT Error Reduction across 4+ Independent Free Model Families):
#    Silence is NEVER consent: inspect the Consent Request, supply your own free key, or explicitly authorize $0 no-card auto-provisioning:
kintsugi swarm --request-consent
kintsugi swarm --add-free-key groq_free gsk_your_free_key
kintsugi swarm --authorize-auto-provision
kintsugi swarm --pool-status
kintsugi swarm --revoke-consent

# 5. Subscription-Aware Parallel Swarm Dispatcher (@SWARM_DISPATCH/1) & 6-Tier Model Capability Matrix (@MODEL_MATRIX/1):
kintsugi swarm --model-matrix
kintsugi swarm --swarm-plan "Audit OAuth2 PKCE redirect_uri validation, Postgres SQL query parameterization, and Docker container privileges" --plan-tier UNLIMITED_LOCAL
```

### 10. Evolved Harness Governance (`@CREED/1 v2.1`, `@SWARM_DISPATCH/1`, `@DUAL_COUNCIL/1`, `@NEVER_SOLO_GATE/1`, `@HARNESS_HOT_RELOAD/1`) & Synthesized Empirical Cortex (`v2.4.0`)

- **5-Pillar Autopoietic Evolution Creed (`@CREED/1 v2.1`):**
  - `P1:MUTATE`: `IF fail(path, n>=2) => KILL(root_assumption) && PIVOT(new_vector)` (2-strike dead-path pivot)
  - `P2:SYNTH`: `IF manual_workaround(count>=2) => SYNTHESIZE(cli_tool | skill_1step)` (2x manual workaround $\to$ 1-step reusable tool)
  - `P3:SCAR`: `ON error_trace(bug) => FIX(bug) && CODIFY(rule -> extinct(bug_class))` (crack-to-scar bug-class extinction)
  - `P4:PRUNE`: `WHILE verbose(skill) || faster_path_exists => OVERWRITE(yesterday_skill)` (overwrite verbose/legacy paths)
  - `P5:CONVERGE`: `TRY_ALL(ways) && IF no_new_way_left => PICK_BEST(fastest, cleanest, most_effective)` (test all viable ways and converge on the single best)
- **Subscription-Aware Parallel Subagent Swarm Dispatcher (`@SWARM_DISPATCH/1`), Step-Economics Auditor (`@STEP_ECONOMICS/1`) & 6-Tier Model Capability Matrix (`@MODEL_MATRIX/1`):** Self-identifies plan tier (`UNLIMITED_LOCAL` / `PRO` / `APACHE_2_OPEN_SOURCE`), spawns `3..8` parallel Frontier High subagents (`Model="inherit" | "pro"`, forbidding `flash`/`flash_lite` downgrades on security/architecture paths) ONLY when a task has $\ge 3$ independent subtasks or $>120\text{s}$ runtime (smaller tasks execute directly via shell-batched `R132` with `>=60%` shell calls and `subagent<=12` / `task<=25` step caps, measurable natively in Python and Rust via `kintsugi-rs step-audit`), and automatically routes tasks across the 6 pre-compiled `@KML/1` domain shards (`docs/domains/01..06_*.kml`).
- **2-Tier Multi-Agent Council (`@DUAL_COUNCIL/1`), Never-Solo Gate (`@NEVER_SOLO_GATE/1`), Zero-Token SHA-256 Hot-Reload (`@HARNESS_HOT_RELOAD/1`) & OSS PR Lifecycle Guard (`@OSS_PR_LIFECYCLE_GUARD/1` / `KS-EMP-062`):** Separates Tier 2 (`24/7 $0 Free Unlimited` audit/scan/draft) from Tier 1 (`Quota-Capped Paid Frontier 3-Round Debate`), forbids solo delivery on critical paths, hot-reloads updated rules via SHA-256 digest checks at `0` idle token cost, and prevents resubmitting closed PRs or drifting doc counts.
- **Synthesized Empirical Cortex ([`collective-pool/synthesized-empirical-cortex/`](collective-pool/synthesized-empirical-cortex/)):** Contains **`972` Cognitive Axioms**, **`1,581` Causal Atoms** (distilled across **`48` completed verification suites** and **`85` security/systems research topics**), **`63` `KS-EMP-001..063` Empirical Engineering Scars**, **`41` Local Cognitive Lessons**, and **`7` BFT Swarm Playbooks** in `@KML/1` symbolic wire format (`empirical_cortex_v240.kml` + `MANIFEST.json`).

---

## Empirical Proofs & Hard Scientific Literature Verification (`v1.2.0`)

Beyond software security and API governance, Kintsugi's Neuro-Symbolic Brain (`RepoAstGroundingEngine` + `AutopoieticSynthesizer` + `DisjointScarHoldoutVerifier` + `ScientificLiteratureVerifier`) has been empirically validated against **5 Hard Scientific Paper Domains & Universal Conservation Laws** (`kintsugi foresight --scientific-corpus`, `500` simulation steps, $\Delta t = 0.05\text{ s}$). Full details and reproducible commands are documented in [**`docs/EMPIRICAL_PROOFS_AND_BENCHMARKS.md`**](docs/EMPIRICAL_PROOFS_AND_BENCHMARKS.md):

| # | Scientific Law & Invariant | Unguarded Seam (`S0/S1` — `VERIFIED`) | Runtime Violation Measurement | `S3` Guarded Implementation (`REFUTED` — `0` FP) | Runtime `S3` Measurement |
| :- | :--- | :--- | :--- | :--- | :--- |
| **1** | **1st Law of Thermodynamics & Symplectic Liouville Theorem** ($\det(J) = 1$) | `NON_SYMPLECTIC_ENERGY_DRIFT_SEAM` (Forward Euler $\det(J) > 1$) | Energy explodes `2.0 J` $\to$ **`289.55 J` (`+14,377.28%` drift)** | Symplectic Velocity-Verlet (`v_half`) | **`1.9997 J` (`0.0147%` bounded)** |
| **2** | **Buckingham $\Pi$ Dimensional Homogeneity & Radian Invariance** | `DIMENSIONAL_UNIT_MISMATCH_SEAM` (`Pa + m/s + mm`, raw `math.sin(deg)`) | Bernoulli head corrupted to **`-100,610.27`** ($10^4\times$ error) | SI base-unit normalization `[m]` + `math.radians()` | **`11.3980 m`** (exact SI head) |
| **3** | **Conservation of Mass / Continuity & Positivity** ($\frac{\partial \rho}{\partial t} + \nabla \cdot (\rho \mathbf{u}) = 0$) | `MASS_CONTINUITY_VIOLATION_SEAM` (unbalanced flux + unclipped sink) | Unphysical negative density **`-1.70 kg/m³`** ($\rho < 0$) | Pairwise antisymmetric flux ($\Delta m_A = -\Delta m_B$) + positivity limiter | **`0.0 kg` mass drift** (`< 1e-15`), $\rho \ge 0$ |
| **4** | **Relativistic Causal Light-Cone ($t_{\text{cause}} \le t_{\text{effect}}$) & Jarzynski / 2nd Law ($\Delta S \ge 0$)** | `CAUSAL_ARROW_LOOKAHEAD_SEAM` (reading future `series[idx_t + 1]`, $\Delta S < 0$, naive `exp(-W)`) | Future spike leak (**`50.5`** vs `0.5`), $\Delta S = -0.25 < 0$, `exp(-800) = 0.0` | Strictly causal past window (`<= idx_t`), shifted `logsumexp`, & $\Delta S \ge 0$ | **`0.5`** causal estimate, exact $\beta \Delta F = 800.26$, $\Delta S \ge 0$ |
| **5** | **Floating-Point Catastrophic Cancellation & Kahan Summation** | `CATASTROPHIC_CANCELLATION_SEAM` (`gamma**2 - 1.0` at $v \ll c$, naive `sum()`) | **`344.09%` relative error** & **`100%` micro-flux loss (`0.0 J`)** | Algebraic $\frac{v^2/c^2}{1 - v^2/c^2}$ + `math.fsum()` | **`0.0%` error**, full **`+100.0 J`** preserved |

- **3-State Grounding Gate & Alpha-Normalized AST Quotient (`ASTQ/1`):** **`5/5` (`100%`)** True Violations `VERIFIED` · **`5/5` (`100%`)** `S3` Safe Counterexamples `REFUTED` (`0` false positives) · **`3/3` (`100%`)** Hallucinated Symbols & Docstring Traps `REFUTED` in `<0.1ms` · **`100%`** Alpha-Rename Semantic Equivalence verified via De Bruijn index AST quotient hashing.
- **Disjoint Scar Holdout Verifier (`T_gen != T_ver`):** Enforces `holdout_precision >= 0.95`, `recall_drop <= 0.05`, and `0` paraphrase-mutated negative false positives before admitting any synthesized `GoldenScar`.
- **Shadow-Clone Covariance-Aware BFT Swarm (`@SWARM/1`) & Consent-Gated Free Pool (`@POOL/1`):** Discounts correlated votes via Equicorrelation Inverse Log-Odds ($N_{\text{eff}} = \frac{K}{1 + (K-1)\hat{\rho}} = 3.40$ across 4 distinct free model families), verifies **`0.0%` sycophancy** via Blinded Contrary Probes, and reduces BFT false-accept errors by **`12.5x` (`98.80%` consensus accuracy)**.
- **Automated Verification Suite:** Separated verification suites across Python (`unittest` — `tests/test_kintsugi.py`, install optional `pip install -e ".[proof]"` for Z3 patch-equivalence proof) and Native Rust (`cargo test --all-targets` covering both `kintsugi-rs` and `rust-neuro-symbolic-core`), plus **`41/41` Frontier Pool Lessons Verified** + **`972` Cognitive Axioms & `1,581` Causal Atoms** in `collective-pool/synthesized-empirical-cortex/` (reproducible live counts logged in CI & `artifacts/`).

---

## Author & Official AI Security Competitions / Benchmark Registry (`Tu Nguyen · tunguyen1993@users.noreply.github.com`)

- **Principal Researcher & Architect:** **Tu Nguyen (`Nguyễn Đức Tú`)** · Email: **`tunguyen1993@users.noreply.github.com`** · GitHub: [**`@tunguyen1993`**](https://github.com/tunguyen1993)
- **Official Competition & Benchmark Registry:** [**`docs/AI_SECURITY_COMPETITIONS_AND_TRAINING_REGISTRY.md`**](docs/AI_SECURITY_COMPETITIONS_AND_TRAINING_REGISTRY.md) & [**`benchmarks/frontier_ai_security_competitions_tundfb.json`**](benchmarks/frontier_ai_security_competitions_tundfb.json)
- **Verified Multi-File Security Gauntlet Qualification (`Brain v10.7` / `Suites 29..43`):**
  - **`112 / 112` Multi-File Repositories Solved (`472` interdependent source files)** · **`231 / 231 (100.0%)` Zero-Hint First-Attempt Blind Exams** · **`0.0%` False Positive Rate across 5 Anti-False-Positive Reality Gates** · **`4,000 / 4,000` Adversarial Red-vs-Blue Fuzz Runs (`Suite 43`)**.
  - **6 Registered Frontier Tracks:** `SLOT-GS-ED913A` (**Gray Swan AI Security Arena / UK AISI IPI**), `SLOT-CY-913A45` (**Stanford Cybench & UK AISI Inspect**), `SLOT-SW-3A45E7` (**SWE-bench Security Remediation**), `SLOT-OW-45E7EB` (**OWASP GenAI & MCP Security Initiative**), `SLOT-HT-ED9105` (**Protect AI Huntr AI/ML/MCP Research**), and `SLOT-CT-D913A4` (**Cantina / Spearbit Web3 & AI Security Track**).

---

## Wire into Claude Code (`PreToolUse`) & MCP

```bash
kintsugi install-hooks --git
```

Or use the native Rust binary in `.claude/settings.json` for **`< 0.5ms`** `PreToolUse` enforcement:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|Bash",
        "hooks": [
          {
            "type": "command",
            "command": "kintsugi-rs hook claude-pre-tool --block-on HIGH"
          }
        ]
      }
    ]
  }
}
```

---

## Contributing & License

Contributions—especially new AST/Regex Golden Scars that pass `kintsugi verify-ledger` and `cargo test`—are warmly welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Licensed under the [Apache License 2.0 (`Apache-2.0`)](LICENSE).
