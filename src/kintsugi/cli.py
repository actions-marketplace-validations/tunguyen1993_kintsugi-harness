"""Command-line interface for Kintsugi Harness (`kintsugi`)."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import List, Optional

from kintsugi import __version__
from kintsugi.auditor import render_audit_markdown, run_posture_audit
from kintsugi.autofix import run_autofix
from kintsugi.cognition import (
    SUPPORTED_DOMAINS,
    CognitiveLesson,
    CognitiveMemoryManager,
    SyncMode,
    get_seed_frontier_lessons,
)
from kintsugi.compactor import ConversationCompactor
from kintsugi.compiler import SkillCompiler
from kintsugi.compressor import compute_token_savings_report, render_kmi_index
from kintsugi.council import (
    EvolutionCouncil,
    PaidFrontierCouncilBYOKRegistry,
    PrimaryPlusFreeCoExecutor,
    answer_user_multi_model_question,
    build_multi_model_agent_guide,
    verify_candidate_scar,
)
from kintsugi.foresight import (
    AnalogicalTransferEngine,
    AutopoieticSynthesizer,
    CausalForesightEngine,
    CounterfactualDreamSimulator,
    MetacognitiveSelfModel,
    ScientificLiteratureVerifier,
)
from kintsugi.grounding import RepoAstGroundingEngine
from kintsugi.hooks import (
    evaluate_claude_pre_tool_payload,
    install_claude_settings_hook,
    install_git_pre_commit_hook,
)
from kintsugi.ledger import ScarLedger
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.models import FailureTrace, Severity
from kintsugi.packs import (
    install_skill_pack,
    list_installed_packs,
    load_installed_pack_scars,
)
from kintsugi.scanner import KintsugiScanner, render_patch_preview, report_to_sarif
from kintsugi.swarm import (
    AIProviderBenchmarkSuite,
    BYOKProviderPoolManager,
    ClosedLoopEvolutionArena,
    ControlledInternetForager,
    RedBlueAdversarialArena,
    ShadowCloneSwarmOrchestrator,
    audit_step_economics,
    compute_swarm_dispatch_plan,
    get_model_capability_matrix,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kintsugi",
        description="Kintsugi Harness — Hybrid Rust/Python PreToolUse guardrail engine and KMI/1 ultra-low-token skill compiler.",
    )
    parser.add_argument("--version", action="version", version=f"kintsugi-harness {__version__}")
    parser.add_argument(
        "--profile",
        choices=["LOCAL_RESEARCH", "GITHUB_PUBLIC"],
        default=None,
        help="Operating profile override (LOCAL_RESEARCH unconstrained local dev vs GITHUB_PUBLIC bounded defaults)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Bootstrap .kintsugi/scars.json starter pack and compile skills")
    p_init.add_argument("--workspace", default=".", help="Target repository root")
    p_init.add_argument("--ledger", default=None, help="Custom path to scars.json")
    p_init.add_argument("--compact", action="store_true", help="Compile KMI/1 ultra-low-token governance headers")
    p_init.add_argument("--no-compile", action="store_true", help="Skip generating SKILL.md / CLAUDE.md")

    # scan
    p_scan = sub.add_parser("scan", help="Scan files, directories, or git diffs against verified Golden Scars")
    p_scan.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    p_scan.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_scan.add_argument("--staged", action="store_true", help="Scan only staged git diff lines (git diff --staged)")
    p_scan.add_argument("--diff", default=None, metavar="REF", help="Scan only lines changed relative to git REF (e.g. origin/main)")
    p_scan.add_argument("--patch-preview", action="store_true", help="Display unified diff replacement preview for each finding")
    p_scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_scan.add_argument("--output", default=None, help="Optional file path to write scan output")
    p_scan.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="LOW",
    )
    p_scan.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="HIGH",
    )
    p_scan.add_argument(
        "--allow-inline-ignores",
        action="store_true",
        help="Opt-in to honor line-level `# kintsugi: ignore[...]` comments (disabled by default for security)",
    )
    p_scan.add_argument(
        "--policy-file",
        default=None,
        help="Explicit out-of-repo trusted ignore policy JSON (KH-R3-SEC-01: in-repo policy files are never trusted)",
    )
    p_scan.add_argument(
        "--policy-sha256",
        default=None,
        help="Optional expected SHA-256 hex digest of --policy-file",
    )

    # audit
    p_audit = sub.add_parser("audit", help="Run repository Security & Agent Readiness Posture Audit (Grade A+ to F)")
    p_audit.add_argument("target", nargs="?", default=".", help="Target repository root")
    p_audit.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_audit.add_argument("--format", choices=["text", "markdown", "json"], default="markdown")

    # token-report
    p_tok = sub.add_parser(
        "token-report",
        help="Benchmark Global KMI/1 & Domain-Partitioned KMI/1 Shards vs verbose Markdown skills",
    )
    p_tok.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_tok.add_argument("--turns", type=int, default=50, help="Number of turns per coding session")
    p_tok.add_argument(
        "--domain",
        default=None,
        help="Optional active domain shard (security, backend, database, frontend, devops, ai_mcp)",
    )
    p_tok.add_argument(
        "--starter-only",
        action="store_true",
        help="Benchmark strictly the 16 Core Starter Scars (get_starter_scars)",
    )
    p_tok.add_argument("--format", choices=["text", "json"], default="text")

    # autofix
    p_fix = sub.add_parser("autofix", help="Preview patches (--dry-run) or apply deterministic codemods (--apply with installed Pack)")
    p_fix.add_argument("target", nargs="?", default=".", help="File or directory to remediate")
    p_fix.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_fix.add_argument("--workspace", default=".", help="Workspace root containing .kintsugi/packs")
    p_fix.add_argument("--apply", action="store_true", help="Apply in-place codemods (unlocked via installed Skill Packs)")

    # install-pack
    p_ipack = sub.add_parser("install-pack", help="Install an external or authenticated Skill Pack (.kpack, .zip, or .json) into .kintsugi/packs/")
    p_ipack.add_argument("pack_path", help="Path to Skill Pack .kpack, .zip, or .json bundle")
    p_ipack.add_argument("--workspace", default=".", help="Target workspace root")
    p_ipack.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_ipack.add_argument("--license-key", default=None, help="Decryption key for encrypted .kpack bundles (or set KINTSUGI_LICENSE_KEY)")

    # list-packs
    p_lpacks = sub.add_parser("list-packs", help="List installed Skill Packs")
    p_lpacks.add_argument("--workspace", default=".", help="Target workspace root")

    # learn (Human-like Federated Cognitive Lesson Engine & Frontier-Gated GitHub Pool)
    p_learn = sub.add_parser(
        "learn",
        help="Manage human-like Cognitive Lessons, local-only privacy mode, domain pulls, and Frontier-gated GitHub Pool sync",
    )
    learn_sub = p_learn.add_subparsers(dest="learn_action", required=True)

    p_lcfg = learn_sub.add_parser("config", help="Configure local-only vs federated-sync mode and subscribed industry domains")
    p_lcfg.add_argument("--workspace", default=".", help="Workspace root")
    p_lcfg.add_argument("--mode", choices=["local-only", "federated-sync"], default=None, help="Sync mode")
    p_lcfg.add_argument("--domains", default=None, help=f"Comma-separated industry domains ({', '.join(SUPPORTED_DOMAINS)})")
    p_lcfg.add_argument("--auto-push", dest="auto_push", action="store_true", default=None, help="Enable automatic git push on Frontier lesson creation")
    p_lcfg.add_argument("--no-auto-push", dest="auto_push", action="store_false", help="Disable automatic git push")

    p_ldist = learn_sub.add_parser("distill", help="Distill a failure into a CognitiveLesson (Frontier-gated for pool sync)")
    p_ldist.add_argument("--workspace", default=".", help="Workspace root")
    p_ldist.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_ldist.add_argument("--id", required=True, help="Lesson ID (e.g. KL-API-002)")
    p_ldist.add_argument("--title", required=True, help="One-line lesson title")
    p_ldist.add_argument("--domain", default="ai-agents-mcp", choices=list(SUPPORTED_DOMAINS), help="Industry domain")
    p_ldist.add_argument("--severity", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    p_ldist.add_argument("--language", default="python", help="Target language")
    p_ldist.add_argument("--model", required=True, help="Synthesizing model identifier (e.g. deepseek-r1, gpt-5.4, claude-opus-4)")
    p_ldist.add_argument("--trap", required=True, help="Cognitive trap: why the agent thought the wrong code was right")
    p_ldist.add_argument("--mental-model", required=True, help="Reusable engineering heuristic learned")
    p_ldist.add_argument("--bad-code", required=True, help="Minimal offending code snippet")
    p_ldist.add_argument("--good-code", required=True, help="Minimal verified replacement snippet")
    p_ldist.add_argument("--regex", default=None, help="Deterministic regex guardrail pattern")
    p_ldist.add_argument("--ast-rule", default=None, help="Optional Python AST rule")
    p_ldist.add_argument("--local-only", action="store_true", help="Force saving strictly locally even if federated-sync is active")
    p_ldist.add_argument("--git-push", action="store_true", help="Commit and push to GitHub Collective Pool if Frontier Gate passes")
    p_ldist.add_argument("--relay-push", action="store_true", help="Broadcast to Zero-GitHub-Account Public Relay (no GitHub account needed)")

    p_lpull = learn_sub.add_parser("pull", help="Pull Frontier-verified lessons for your industry/life domains from the Collective Pool")
    p_lpull.add_argument("--workspace", default=".", help="Workspace root")
    p_lpull.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_lpull.add_argument("--domains", default=None, help="Comma-separated industry/life domains to pull")
    p_lpull.add_argument("--model-family", default=None, help="Filter by Frontier model family (e.g. deepseek-r1, openai-frontier, open-weights-frontier)")
    p_lpull.add_argument("--remote", action="store_true", help="Fetch directly from remote GitHub repository raw API")
    p_lpull.add_argument("--relay", action="store_true", help="Also ingest pending lessons from Zero-GitHub-Account Public Relay")

    p_lrpush = learn_sub.add_parser("push-relay", help="Broadcast local Frontier-verified lessons to Zero-GitHub-Account Public Relay")
    p_lrpush.add_argument("--workspace", default=".", help="Workspace root")
    p_lrpush.add_argument("--relay-url", default=None, help="Custom relay URL (default: https://ntfy.sh/kintsugi-collective-pool-v1)")
    p_lrpush.add_argument("--offline-outbox", action="store_true", help="Write to local relay outbox without HTTP POST")

    p_lrsync = learn_sub.add_parser("sync-relay", help="Ingest and 4-Stage-verify lessons from Zero-GitHub-Account Public Relay into Pool")
    p_lrsync.add_argument("--workspace", default=".", help="Workspace root")
    p_lrsync.add_argument("--relay-url", default=None, help="Custom relay URL")
    p_lrsync.add_argument("--since", default="48h", help="Lookback window (e.g. 24h, 48h, all)")
    p_lrsync.add_argument("--local-outbox-only", action="store_true", help="Ingest only from local relay_outbox.jsonl")

    p_lharv = learn_sub.add_parser("harvest-github", help="Autonomously scan external GitHub Skill repos and merge Frontier-verified lessons into Pool")
    p_lharv.add_argument("--workspace", default=".", help="Workspace root")
    p_lharv.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_lharv.add_argument("--repos", default=None, help="Comma-separated GitHub owner/repo slugs (default: anthropics/skills,patrickjs/awesome-cursorrules)")
    p_lharv.add_argument("--offline", action="store_true", help="Use curated verified fallback without network calls")

    p_lseed = learn_sub.add_parser("seed-pool", help="Seed the partitioned GitHub Collective Pool with curated Frontier lessons")
    p_lseed.add_argument("--workspace", default=".", help="Workspace root")

    p_lstat = learn_sub.add_parser("pool-status", help="Inspect partitioned Collective Pool by pillar, domain, and Frontier model family")
    p_lstat.add_argument("--workspace", default=".", help="Workspace root")

    # compile
    p_comp = sub.add_parser("compile", help="Compile Golden Scars into SKILL.md, CLAUDE.md, AGENTS.md, Cursor, Copilot, and Windsurf rules")
    p_comp.add_argument("--workspace", default=".", help="Target repository root")
    p_comp.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_comp.add_argument("--compact", action="store_true", help="Emit ultra-low-token KMI/1 wire index (>93%% token savings)")
    p_comp.add_argument(
        "--starter-only",
        action="store_true",
        help="Compile strictly from the 16 public starter scars (get_starter_scars) without merging local private workspace scars",
    )
    p_comp.add_argument(
        "--targets",
        default="skills,claude,agents,cursor",
        help="Comma-separated targets: skills,claude,agents,cursor,copilot,windsurf,all",
    )

    # explain
    p_exp = sub.add_parser("explain", help="Inspect a specific Golden Scar with root cause and verified replacement")
    p_exp.add_argument("scar_id", help="Scar identifier (e.g. KS-003)")
    p_exp.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")

    # evolve
    p_evo = sub.add_parser("evolve", help="Evolve a new self-verified Golden Scar from a failure log or snippet pair")
    p_evo.add_argument("--workspace", default=".", help="Workspace root for .kintsugi tier entitlement")
    p_evo.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_evo.add_argument("--summary", required=False, default="", help="One-line failure summary")
    p_evo.add_argument("--from-log", default=None, help="Path to traceback/CI log file")
    p_evo.add_argument("--language", default="python", help="Target language")
    p_evo.add_argument("--bad-code", default="", help="Offending code snippet")
    p_evo.add_argument("--good-code", default="", help="Verified replacement snippet")
    p_evo.add_argument("--compile-workspace", default=None, help="Auto-recompile skills in workspace after evolving")
    p_evo.add_argument("--ir-synthesize", action="store_true", help="Synthesize typed RuleIR/1 and counterfactual validation attestation")
    p_evo.add_argument("--consolidate-dry-run", action="store_true", help="Report behavioral duplicate clusters and conflicts across the ledger without mutating baselines")
    p_evo.add_argument("--parity-check", action="store_true", help="Run live Python vs native Rust differential parity check over shared fixtures")
    p_evo.add_argument("--rust-bin", default=None, help="Optional path to compiled kintsugi-rs binary for differential parity check")
    p_evo.add_argument(
        "--co-run",
        action="store_true",
        help="Run Primary Anchor model alongside local/BYOK co-runner(s) (1..5 parallel seats, Apache-2.0 unlocked)",
    )
    p_evo.add_argument(
        "--free-runners",
        type=int,
        default=None,
        help="Requested number of local/BYOK co-runners (1..5 parallel seats, Apache-2.0 unlocked)",
    )
    p_evo.add_argument(
        "--paid-council",
        action="store_true",
        help="Include user-supplied BYOK official provider council seats (OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter)",
    )

    from kintsugi.cli_nextgen import register_nextgen_parsers

    register_nextgen_parsers(sub, p_evo)

    # verify-ledger
    p_ver = sub.add_parser("verify-ledger", help="Run true-positive & zero-false-positive self-check across every scar in the ledger")
    p_ver.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")

    # hook
    p_hook = sub.add_parser("hook", help="Run as an inline coding-agent PreToolUse hook")
    p_hook.add_argument("kind", choices=["claude-pre-tool"], help="Hook protocol")
    p_hook.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_hook.add_argument("--block-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="HIGH")
    p_hook.add_argument("--workspace", default=None, help="Trusted workspace root bound by runner (KH-R4-SEC-04)")

    # install-hooks
    p_inst = sub.add_parser("install-hooks", help="Wire Kintsugi into .claude/settings.json and .git/hooks/pre-commit")
    p_inst.add_argument("--workspace", default=".", help="Target repository root")
    p_inst.add_argument("--git", action="store_true", help="Also install .git/hooks/pre-commit")

    # mcp
    p_mcp = sub.add_parser("mcp", help="Start Kintsugi stdio Model Context Protocol (MCP) server")
    p_mcp.add_argument("mcp_action", nargs="?", default="serve", help="Optional action (default: serve)")
    p_mcp.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_mcp.add_argument(
        "--profile",
        dest="mcp_profile",
        choices=["default", "nextgen", "coding", "build3", "cognitive", "v3"],
        default="default",
        help="MCP tool surface profile (default: 9 core tools; nextgen/coding: 19 tools; build3/cognitive: 23 tools; v3: 26 tools)",
    )

    # stats
    p_stats = sub.add_parser("stats", help="Display Golden Scar ledger summary and verification health")
    p_stats.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")

    # ground (Neuro-Symbolic AST Symbol Table & 3-State Hypothesis Grounding Gate)
    p_gnd = sub.add_parser("ground", help="Run <5ms AST Symbol Table & Seam extraction + 3-State Hypothesis Grounding Gate")
    p_gnd.add_argument("target", nargs="?", default=".", help="Repository or file to index")
    p_gnd.add_argument("--anchor", default=None, help="Optional file:line anchor to verify (e.g. src/app.py:42)")
    p_gnd.add_argument("--symbols", default=None, help="Comma-separated symbol names to verify at anchor")
    p_gnd.add_argument("--manifest-sha", default=None, help="Optional expected manifest SHA-256 to check for commit drift")

    # foresight (3-Horizon Causal Foresight, Metacognitive Self-Awareness, Autopoiesis & Counterfactual Dreaming)
    p_for = sub.add_parser(
        "foresight",
        help="Run 3-Horizon (T+1/T+2/T+3) Causal Foresight, Metacognition, Autopoiesis, Analogical Transfer & Counterfactual Dreaming",
    )
    p_for.add_argument("target", nargs="?", default=".", help="Repository or file to forecast")
    p_for.add_argument("--workspace", default=".", help="Workspace root for .kintsugi state")
    p_for.add_argument("--self-generate", action="store_true", help="Autopoietically synthesize and verify new lessons from unguarded seams")
    p_for.add_argument("--metacognition", action="store_true", help="Output Beta-Bernoulli domain competence & blind-spot calibration report")
    p_for.add_argument("--dream", action="store_true", help="Run Counterfactual Sandbox Dreamer (apply S3 guards in-memory & compute delta_seams / delta_p_max)")
    p_for.add_argument("--transfer", action="store_true", help="Run Cross-Domain Analogical Transfer Engine (map scientific/system invariants across domains)")
    p_for.add_argument("--swarm", action="store_true", help="Run Kage Bunshin Shadow-Clone Parallel Epistemic Swarm & BFT Playbook Consolidation")
    p_for.add_argument("--scientific-corpus", action="store_true", help="Audit the 5-Paper Hard Scientific Literature & Physics Invariant Corpus")
    p_for.add_argument("--wire", action="store_true", help="Output ultra-compact @FORESIGHT/1 + @META/1 + @DREAM/1 + @SWARM/1 wire headers")
    p_for.add_argument("--top-k", type=int, default=8, help="Max ranked pre-emptive actions to emit (default: 8)")

    # swarm (Pillar 5 & 5B: Shadow-Clone Parallel Epistemic Swarm, BFT Synaptic Merge & BYOK Provider Pool)
    p_swm = sub.add_parser(
        "swarm",
        help="Spawn K=4 orthogonal Shadow Clones in parallel, manage BYOK/local provider config, and merge into 1 Verified Playbook",
    )
    p_swm.add_argument("target", nargs="?", default=".", help="Repository or file for the Shadow-Clone Swarm to explore")
    p_swm.add_argument("--workspace", default=".", help="Workspace root for .kintsugi state")
    p_swm.add_argument("--clones", type=int, default=4, help="Number of orthogonal Shadow Clones to spawn (default: 4)")
    p_swm.add_argument("--no-consolidate", action="store_true", help="Run swarm without writing newly distilled lessons to .kintsugi")
    p_swm.add_argument("--byzantine-test", action="store_true", help="Inject a Byzantine fault into 1 clone to verify K=3f+1 fault-tolerant consensus")
    p_swm.add_argument("--pool-status", action="store_true", help="Show BYOK & local provider pool status and Condorcet BFT accuracy metrics")
    p_swm.add_argument("--request-consent", action="store_true", help="Display structured BYOK & local provider setup prompt")
    p_swm.add_argument("--authorize-auto-provision", action="store_true", help="Configure local Ollama / environment-key providers into .kintsugi/byok_provider_pool.json")
    p_swm.add_argument("--scope", default="", help="Optional comma-separated provider_ids for --authorize-auto-provision")
    p_swm.add_argument("--add-free-key", nargs=2, metavar=("PROVIDER_ID", "API_KEY"), help="Supply a user-provided BYOK provider API key (e.g. groq_byok <API_KEY>)")
    p_swm.add_argument("--revoke-consent", action="store_true", help="Clear stored local provider keys in .kintsugi/byok_provider_pool.json")
    p_swm.add_argument("--red-blue-arena", action="store_true", help="Run v1.3.0 2-Team Adversarial Arena (Red Team Attack vs Blue Team Defense across 6 formal campaigns)")
    p_swm.add_argument("--evolution-proof", action="store_true", help="Run 5-Wave Closed-Loop Self-Learning & Self-Healing Proof (Epoch 0 Breach -> Scar Synthesis -> Autofix -> Epoch 5 Unseen Variant Immunity)")
    p_swm.add_argument("--forage-internet", action="store_true", help="Run the Controlled Security Advisory Forager (OSV.dev, GitHub Advisories, ArXiv) and 10-Challenge Evolution Gauntlet")
    p_swm.add_argument("--provider-benchmarks", action="store_true", help="Run the 8-Facet Official AI Provider Benchmark Suite (SWE-bench Verified, LiveCodeBench, GPQA Diamond, AIME/MATH-500, CyberSecEval 3, TAU-bench/BFCL, SimpleQA/FACTS, IFEval)")
    p_swm.add_argument("--co-run", action="store_true", help="Execute Apache-2.0 Multi-Model Co-Execution (Primary Model + 1..5 local/BYOK co-runners + optional BYOK Council)")
    p_swm.add_argument("--free-runners", type=int, default=None, help="Requested number of local/BYOK co-runners (1..5 parallel seats)")
    p_swm.add_argument("--paid-council", action="store_true", help="Include user-supplied BYOK official Frontier Council seats")
    p_swm.add_argument("--add-paid-key", nargs=2, metavar=("PROVIDER_ID", "API_KEY"), help="Add user-owned BYOK API key for the Frontier Council (e.g. openai_frontier <YOUR_API_KEY>)")
    p_swm.add_argument("--remove-paid-key", metavar="PROVIDER_ID", default=None, help="Remove a stored Frontier Council BYOK API key")
    p_swm.add_argument("--paid-council-status", action="store_true", help="Show Frontier Council BYOK status and supported official provider seats")
    p_swm.add_argument("--guide", action="store_true", help="Display the Multi-Model BYOK & Offline Local Setup Guide")
    p_swm.add_argument("--ask", metavar="QUESTION", default=None, help="Answer user questions about Multi-Model Co-Execution, BYOK Official API keys, and Local Ollama setup")
    p_swm.add_argument("--model-matrix", action="store_true", help="Display the 6-Tier Model Capability Matrix (@MODEL_MATRIX/1) & Harness Architecture Evolutions")
    p_swm.add_argument("--swarm-plan", metavar="TASK", default=None, help="Compute Parallel Subagent Swarm Dispatch Plan (@SWARM_DISPATCH/1) & Domain Shard Routing")
    p_swm.add_argument("--plan-tier", default="UNLIMITED_LOCAL", choices=["UNLIMITED_LOCAL", "HIGH_CONCURRENCY", "STANDARD"], help="Parallelism profile for --swarm-plan (default: UNLIMITED_LOCAL)")
    p_swm.add_argument("--step-audit", metavar="PATH", default=None, help="Audit agent transcript (.jsonl or dir) for step-economics (@STEP_ECONOMICS/1: steps, shell ratio, error burn)")
    p_swm.add_argument("--wire", action="store_true", help="Output compact <45-token @SWARM/1 + @POOL/1 wire headers")

    p_gde = sub.add_parser("guide", help="Interactive User Onboarding & Q&A Guide (BYOK Official APIs & Offline Local Multi-Model setup)")
    p_gde.add_argument("question", nargs="*", help="Optional natural-language question from the user (e.g. 'How do I configure OpenAI and Anthropic BYOK keys?')")
    p_gde.add_argument("--workspace", default=".", help="Workspace root directory")
    p_gde.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format (markdown for human/chat display, json for programmatic tools)")

    p_cmp = sub.add_parser(
        "compact",
        help="Anti-Overflow Conversation & Excel Compactor (@COMPACT/2 + @USER_PERSONA/1 + @RECURRENCE_SHIELD/1)",
    )
    p_cmp.add_argument("source", nargs="?", default=None, help="Optional path to conversation transcript (.jsonl, .json, .md) or Excel/tabular file (.xlsx, .csv, .tsv). Auto-discovers active session if omitted.")
    p_cmp.add_argument("--workspace", default=".", help="Workspace root directory")
    p_cmp.add_argument("--max-tokens", type=int, default=128000, help="Target context window capacity in tokens (default: 128000)")
    p_cmp.add_argument("--soft-watermark", type=float, default=0.70, help="Soft watermark ratio for pre-emptive noise pruning (default: 0.70)")
    p_cmp.add_argument("--hard-watermark", type=float, default=0.85, help="Hard watermark ratio for automatic full compaction (default: 0.85)")
    p_cmp.add_argument("--inject-agents", action="store_true", help="Inject <180-token @COMPACT/1 memory capsule into CLAUDE.md and AGENTS.md")
    p_cmp.add_argument("--co-run", action="store_true", help="Include Multi-Model Co-Execution verification metadata")
    p_cmp.add_argument("--evolution-iq", action="store_true", help="Compute and display the 5-Pillar Evolution Intelligence Report (@EVOLUTION_IQ/1 + @RECURRENCE_SHIELD/1)")
    p_cmp.add_argument("--persona", action="store_true", help="Display the learned Adaptive User Persona & Cognitive Twin Profile (@USER_PERSONA/1)")
    p_cmp.add_argument("--no-persist", action="store_true", help="Run in-memory without writing .kintsugi/context_checkpoints/")
    p_cmp.add_argument("--wire", action="store_true", help="Output ultra-dense <180-token @COMPACT/1 symbolic wire capsule")
    p_cmp.add_argument("--format", choices=["markdown", "json", "wire"], default="markdown", help="Output format (markdown, json, or wire)")

    p_log = sub.add_parser(
        "logic",
        help="5-Pillar Neuro-Symbolic Logical Reasoning Engine (@LOGIC/2: DPLL SAT/MUS, Stratified Datalog + Proof DAG, Difference Logic, Fallacy Guard, Abductive MHS, Login Auth & GitHub Forager)",
    )
    p_log.add_argument("--benchmark", action="store_true", help="Run the 5-Pillar @LOGIC/2 verification benchmark suite")
    p_log.add_argument("--login-verify", action="store_true", help="Run the Formal Login & Authentication State-Machine Verifier (MFA Step-Up, Session Revocation, OTP Window, Fallacy Guard)")
    p_log.add_argument("--arena", action="store_true", help="Run the 5-Round Adversarial Logic & Login Arena: (Qwen-2.5-Coder + GPT-5.4 + Kintsugi @LOGIC/2) vs Raw Unassisted Council")
    p_log.add_argument("--forage-github-harnesses", action="store_true", help="Study high-star GitHub agent harnesses (Claude Code, DeepSeek R1, OpenHands, Aider, Cline)")
    p_log.add_argument("--wire", action="store_true", help="Output compact @LOGIC/2 symbolic wire summary")

    p_ver = sub.add_parser(
        "verify",
        help="Proof-Carrying Change & Signed Compliance Verifier (@PROOF_DAG/1 + @ZK_AST_DIFF/1 + SOC2/ISO27001/EU-AI-Act .kintsugi/audit.proof)",
    )
    p_ver.add_argument("--target", default=None, help="Optional Python file path to verify and bind into the compliance proof bundle")
    p_ver.add_argument("--export-audit", default=None, help="Optional path to export signed .kintsugi/audit.proof JSON bundle")
    p_ver.add_argument("--verify-proof", default=None, help="Path to an existing .kintsugi/audit.proof bundle to verify cryptographically")
    p_ver.add_argument("--zk-diff", action="store_true", help="Emit only the Zero-Knowledge AST Structural Proof (@ZK_AST_DIFF/1)")
    p_ver.add_argument("--wire", action="store_true", help="Output compact @PROOF_DAG/1 symbolic wire header")

    p_evl = sub.add_parser(
        "eval",
        help="Open Reproducible Autonomous Engineering Benchmark & Deterministic Replay Suite (@EVAL_SUITE/1)",
    )
    p_evl.add_argument("--replay", default=None, metavar="CASE_ID", help="Replay a specific benchmark case (e.g. EVAL-AUTH-001 .. EVAL-MHS-006)")
    p_evl.add_argument("--no-ablation", action="store_true", help="Omit ablation table from output")
    p_evl.add_argument("--wire", action="store_true", help="Output compact @EVAL_SUITE/1 symbolic wire summary")

    p_int = sub.add_parser(
        "integrate",
        help="Universal Drop-In Harness Integrator & Federation Engine (@HARNESS_BRIDGE/1: auto-discover, 7-layer quarantine, SAT+DL conflict check, mount & eject third-party harnesses)",
    )
    p_int.add_argument("target", nargs="?", default=None, help="Path to existing or downloaded harness file, directory, .zip, or .tar.gz")
    p_int.add_argument("--workspace", default=".", help="Workspace root directory (default: .)")
    p_int.add_argument("--scan", "--discover", dest="scan", action="store_true", help="Discover all recognizable agent harnesses in target/workspace")
    p_int.add_argument("--preview", action="store_true", help="Quarantine, parse, and conflict-check target without mounting")
    p_int.add_argument("--mount", action="store_true", help="Approve and mount compiled declarative guards from target")
    p_int.add_argument("--eject", default=None, metavar="HARNESS_ID", help="Reversibly eject a mounted harness and restore clean state")
    p_int.add_argument("--list", action="store_true", help="List currently mounted third-party harnesses and tier quota")
    p_int.add_argument("--harness-id", default=None, help="Optional explicit identifier for the imported harness")
    p_int.add_argument("--wire", action="store_true", help="Output compact @PROOF_DAG/1 integration receipt wire")

    p_cin = sub.add_parser(
        "cinema",
        help="OpenMontage Cinema Director's Cut Extension Package (@OPENMONTAGE_CINEMA/1: auto-pull OpenMontage, Veo/Muse/Multi-Web video router, 6-Gate script-to-frame QA, Live-Action vs Animation LUT optimizer, and @CINEMA_EVOLVE/1 film evolution)",
    )
    p_cin.add_argument("--workspace", default=".", help="Workspace root directory (default: .)")
    p_cin.add_argument("--pull-openmontage", action="store_true", help="Auto-pull and sandbox calesthio/OpenMontage into .kintsugi/extensions/openmontage/")
    p_cin.add_argument("--offline-pull", action="store_true", help="Initialize deterministic offline OpenMontage extension scaffold without network git clone")
    p_cin.add_argument("--manifest", default=None, help="Path to production screenplay/shot manifest JSON (uses built-in Station 09 demo manifest if omitted)")
    p_cin.add_argument("--verify-manifest", action="store_true", help="Run mandatory 6-Gate Script-to-Frame & Continuity QA Verifier on manifest")
    p_cin.add_argument("--auto-heal", action="store_true", help="Auto-heal screenplay/frame/wardrobe/prop/timing discrepancies via @CINEMA_EVOLVE/1")
    p_cin.add_argument("--style", choices=["live_action", "animation"], default="live_action", help="Visual optimization mode: live_action (Human Cinema ARRI/Kodak 2383 LUT) or animation (2D/3D Studio Cel LUT)")
    p_cin.add_argument("--provider", choices=["veo", "muse", "kling", "runway", "luma", "pika", "hailuo", "sora", "wan"], default="veo", help="Video generation provider router target (default: veo)")
    p_cin.add_argument("--synthesize-test-clips", default=None, metavar="OUT_DIR", help="Synthesize deterministic component WAV + 3-keyframe test clips into OUT_DIR and run 6-Gate QA")
    p_cin.add_argument("--scars", action="store_true", help="List the 12 seeded + evolved Cinema Golden Scars (CS-001..CS-012)")
    p_cin.add_argument("--output", default=None, help="Optional path to write healed manifest JSON")
    p_cin.add_argument("--wire", action="store_true", help="Output compact @OPENMONTAGE_CINEMA/1 symbolic wire receipt")

    # config (KINTSUGI-NEXTGEN/1 operating profiles & security baseline)
    p_cfg = sub.add_parser("config", help="Show or validate KintsugiConfig/1 (LOCAL_RESEARCH vs GITHUB_PUBLIC)")
    p_cfg.add_argument("config_action", choices=["show", "validate"], help="Action to run on config")
    p_cfg.add_argument("--workspace", default=".", help="Target repository root")
    p_cfg.add_argument("--external-config", default=None, help="Trusted config JSON path strictly outside target workspace")
    p_cfg.add_argument("--file", default=None, help="Config JSON file to validate")
    p_cfg.add_argument("--format", choices=["json", "text"], default="json")

    # tools (Stage 1 Capability Fabric & vertical slice runner)
    p_tls = sub.add_parser("tools", help="Stage 1 ToolRegistry, passive discovery, verification & vertical slice execution")
    p_tls.add_argument(
        "tools_action",
        choices=["discover", "list", "inspect", "verify", "vertical-slice"],
        help="Capability Fabric operation",
    )
    p_tls.add_argument("tool_id_pos", nargs="?", default=None, help="Optional tool_id for inspect/verify")
    p_tls.add_argument("--workspace", default=".", help="Trusted workspace root")
    p_tls.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Tool registry JSON path")
    p_tls.add_argument("--experience-store", default=".kintsugi/experience_store.json", help="ExperienceStore JSON path")
    p_tls.add_argument("--tool-id", default=None, help="Tool ID")
    p_tls.add_argument("--capability", default=None, help="Capability to filter or resolve")
    p_tls.add_argument("--task", default=None, help="Task description or JSON string for vertical-slice")
    p_tls.add_argument("--path", action="append", default=None, help="Allowlisted directory for passive discovery")
    p_tls.add_argument("--save", action="store_true", help="Persist registry updates atomically")
    p_tls.add_argument("--verify-digest", default=None, help="Trusted verification_attestation sha256:<hex>")
    p_tls.add_argument("--verifier-id", default="cli_operator", help="Trusted verifier identity")
    p_tls.add_argument(
        "--verifier-key-file",
        default=None,
        help="External 0o600 verifier HMAC key JSON file outside workspace (required for tools verify)",
    )
    p_tls.add_argument(
        "--attestation-signature",
        default=None,
        help="HMAC-SHA256 verification signature ('hmac-sha256:<hex>')",
    )
    p_tls.add_argument(
        "--attestation-file",
        default=None,
        help="Optional signed verification attestation JSON file",
    )

    # capability (Stage 1 Gap Analysis & Deterministic Resolution)
    p_cap = sub.add_parser("capability", help="Stage 1 CapabilityGapDetector and deterministic ToolResolver")
    p_cap.add_argument("capability_action", choices=["analyze"], help="Analyze goal against registry")
    p_cap.add_argument("--workspace", default=".", help="Trusted workspace root")
    p_cap.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Tool registry JSON path")
    p_cap.add_argument("--goal-file", default=None, help="Path to goal contract JSON inside workspace")
    p_cap.add_argument("--capability", action="append", default=None, help="Required capability (repeatable)")
    p_cap.add_argument("--goal-id", default="cli-goal-001", help="Goal identifier")

    # logforge (Working Tool #1: LogForge NEON + Differential Byte Scanner)
    p_lfg = sub.add_parser("logforge", help="LogForge streaming delimiter scanner & Rust ARM64 NEON / Scalar differential tool")
    p_lfg.add_argument("--input", default=None, help="Input file inside workspace (reads small sample if omitted)")
    p_lfg.add_argument("--workspace", default=".", help="Workspace root for confined input reads")
    p_lfg.add_argument("--delim", default="\\n", help="Single-byte delimiter (default: \\n)")
    p_lfg.add_argument("--tier", choices=["auto", "python", "rust_neon", "rust_scalar"], default="auto")
    p_lfg.add_argument("--disable-simd", action="store_true", help="Force scalar fallback for testing/comparison")
    p_lfg.add_argument("--normalize", action="store_true", help="Normalize structured log records")

    # reposcout (Working Tool #2: RepoScout Incremental AST & Test Impact Tool)
    p_rsc = sub.add_parser("reposcout", help="RepoScout symlink-confined AST index & changed-file test-impact slicer")
    p_rsc.add_argument("--workspace", default=".", help="Target repository root")
    p_rsc.add_argument("--index", default=".kintsugi/repo_scout_index.json", help="Incremental index cache path")
    p_rsc.add_argument("--changed", nargs="*", default=None, help="Changed workspace-relative file paths for test impact")
    p_rsc.add_argument("--symbol", default=None, help="Symbol name to search")
    p_rsc.add_argument("--save", action="store_true", help="Persist updated index cache cleanly")

    return parser


def _load_or_seed_ledger(ledger_path: str | Path, workspace_root: str | Path = ".") -> ScarLedger:
    ledger = ScarLedger(ledger_path, ensure_builtin_crs=True)
    if not ledger.all():
        ledger.bootstrap_starter_pack()
    for pack_scar in load_installed_pack_scars(workspace_root):
        ledger.upsert(pack_scar)
    return ledger


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        ws = Path(args.workspace)
        ledger_path = Path(args.ledger) if args.ledger else (ws / ".kintsugi" / "scars.json")
        ledger = ScarLedger(ledger_path)
        added = ledger.bootstrap_starter_pack()
        print(f"[kintsugi] Initialized {ledger_path} ({len(ledger.all())} total scars, {added} newly seeded).")
        if not args.no_compile:
            written = SkillCompiler(ledger.all(), compact_kmi=bool(args.compact)).compile_all(ws)
            for p in written:
                print(f"[kintsugi] Compiled -> {p}")
        return 0

    if args.command == "scan":
        ledger = _load_or_seed_ledger(args.ledger)
        scanner = KintsugiScanner(
            ledger.all(),
            min_severity=Severity(args.min_severity),
            allow_inline_ignores=bool(getattr(args, "allow_inline_ignores", False)),
            allow_file_ignores=False,
            trusted_policy_path=getattr(args, "policy_file", None),
            trusted_policy_sha256=getattr(args, "policy_sha256", None),
        )
        if args.staged or args.diff:
            report = scanner.scan_git_changes(
                args.target,
                staged=bool(args.staged),
                diff_ref=args.diff,
            )
        else:
            report = scanner.scan_path(args.target)
        ledger.record_hits([f.scar_id for f in report.findings])

        if args.format == "json":
            rendered = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
        elif args.format == "sarif":
            rendered = json.dumps(report_to_sarif(report, ledger.all()), indent=2, ensure_ascii=False)
        else:
            lines = [
                f"Kintsugi Scan: {report.scanned_files} file(s) checked against {report.active_scars} scars in {report.elapsed_ms:.1f}ms"
            ]
            if not report.findings:
                lines.append("PASS: 0 anti-pattern violations found.")
            else:
                for f in report.findings:
                    lines.append(
                        f"  [{f.severity.value}] {f.scar_id} {f.file_path}:{f.line}:{f.column} — {f.title}\n"
                        f"    Snippet : {f.snippet}\n"
                        f"    Fix     : {f.good_code_hint.splitlines()[0]}"
                    )
                    if args.patch_preview:
                        preview = render_patch_preview(f)
                        indented = "\n".join(f"      {ln}" for ln in preview.splitlines())
                        lines.append(f"    Patch Preview:\n{indented}")
            rendered = "\n".join(lines)

        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)

        if args.fail_on != "NONE" and report.has_blocking_findings(Severity(args.fail_on)):
            return 1
        return 0

    if args.command == "audit":
        ledger = _load_or_seed_ledger(args.ledger, args.target)
        audit = run_posture_audit(args.target, ledger.all())
        if args.format == "json":
            print(json.dumps(audit, indent=2, ensure_ascii=False))
        else:
            print(render_audit_markdown(audit))
        return 0

    if args.command == "token-report":
        if getattr(args, "starter_only", False):
            from kintsugi.starter_pack import get_starter_scars

            scars = get_starter_scars()
        else:
            ledger = _load_or_seed_ledger(args.ledger)
            scars = ledger.all()
        verbose_md = SkillCompiler(scars).render_skill_markdown(
            "kintsugi-guardrails",
            "Verbose baseline comparison",
            scars,
        )
        stats = compute_token_savings_report(
            scars,
            verbose_md,
            turns_per_session=args.turns,
            active_domain=getattr(args, "domain", None),
        )
        if args.format == "json":
            print(json.dumps(stats, indent=2, ensure_ascii=False))
        else:
            dom_rows = []
            for dom_key, dinfo in stats["domain_partitions"].items():
                dom_rows.append(
                    f"  | {dom_key:<10} | {dinfo['doc_path']:<35} | {dinfo['rules_count']:>5} | "
                    f"~{dinfo['domain_kmi_tokens_per_turn']:>4} tok/turn | "
                    f"{dinfo['domain_reduction_percent']:>6.2f}% | "
                    f"~{dinfo['domain_tokens_saved_per_session']:>10,} tok |"
                )
            dom_table = "\n".join(dom_rows)
            preview_block = (
                stats["active_domain_report"]["domain_kmi_preview"]
                if stats.get("active_domain_report")
                else stats["kmi_preview"]
            )
            print(
                f"=== Kintsugi KMI/1 & Domain-Partitioned Token-Compression Benchmark ({stats['rules_compiled']} active scars) ===\n"
                f"• 1. Full Verbose Markdown (All Domains) : ~{stats['verbose_tokens_per_turn']} tokens/turn\n"
                f"• 2. Global KMI/1 Compressed Wire Index  : ~{stats['kmi_tokens_per_turn']} tokens/turn "
                f"({stats['reduction_percent']}% reduction, {stats['tokens_saved_per_turn']} tokens saved/turn, ~{stats['tokens_saved_per_session']:,} tokens/{stats['turns_per_session']} turns)\n"
                f"• 3. Domain-Routed KMI/1 Shard (Avg)     : ~{stats['avg_domain_kmi_tokens_per_turn']} tokens/turn "
                f"({stats['avg_domain_reduction_percent']}% reduction vs Full Verbose Markdown)\n\n"
                f"--- Domain-Partitioned Documentation Shards (`docs/domains/`) ---\n"
                f"  | Domain     | Documentation Shard                 | Rules | Shard Cost     | Reduction | {stats['turns_per_session']}-Turn Saved |\n"
                f"  | :--------- | :---------------------------------- | ----: | -------------: | --------: | ------------: |\n"
                f"{dom_table}\n\n"
                f"{preview_block}"
            )
        return 0

    if args.command == "autofix":
        ledger = _load_or_seed_ledger(args.ledger, args.workspace)
        res = run_autofix(
            args.target,
            ledger.all(),
            workspace_root=args.workspace,
            apply_changes=bool(args.apply),
        )
        print(
            f"[kintsugi autofix] Mode={res['mode']} | Findings={res['findings_count']} | "
            f"Loaded Playbooks={res['premium_playbooks_loaded']} | Applied={res['applied_fixes']}"
        )
        if args.apply and res["premium_playbooks_loaded"] == 0:
            print(
                "  [i] Live codemod rewrites (--apply) require an installed Kintsugi Skill Pack "
                "with autofix_playbooks (`kintsugi install-pack <bundle.zip>`). Showing dry-run previews:"
            )
        for item in res["items"]:
            print(f"\n--- {item['scar_id']} ({item['status']}) at {item['file_path']}:{item['line']} ---")
            print(item["patch_preview"])
        return 0

    if args.command == "install-pack":
        info = install_skill_pack(
            args.pack_path,
            workspace_root=args.workspace,
            ledger_path=args.ledger,
            license_key=args.license_key,
        )
        print(
            f"[kintsugi] Installed pack '{info['pack_id']}' ({info['tier']}) -> {info['installed_to']}\n"
            f"  • Scars in pack       : {info['scars_in_pack']} ({info['newly_unlocked_scars']} newly unlocked)\n"
            f"  • Auto-fix playbooks  : {info['autofix_playbooks']}\n"
            f"  • Slash commands      : {', '.join(info['slash_commands']) or 'none'}"
        )
        return 0

    if args.command == "list-packs":
        packs = list_installed_packs(args.workspace)
        print(json.dumps({"installed_packs": packs}, indent=2, ensure_ascii=False))
        return 0

    if args.command == "learn":
        mgr = CognitiveMemoryManager(args.workspace)
        if args.learn_action == "config":
            doms = [d.strip() for d in args.domains.split(",") if d.strip()] if args.domains else None
            cfg = mgr.save_config(
                sync_mode=args.mode,
                subscribed_domains=doms,
                auto_push_to_github=args.auto_push,
            )
            print(json.dumps(cfg, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "distill":
            lesson = CognitiveLesson(
                id=args.id.strip().upper(),
                title=args.title.strip(),
                domain=args.domain,
                severity=Severity(args.severity),
                languages=[args.language.lower()],
                tags=[args.domain, args.language.lower()],
                cognitive_trap=args.trap.strip(),
                mental_model=args.mental_model.strip(),
                bad_code=args.bad_code,
                good_code=args.good_code,
                regex_pattern=args.regex,
                ast_rule=args.ast_rule,
                synthesized_by_model=args.model,
            )
            res = mgr.record_lesson(
                lesson,
                force_local_only=bool(args.local_only),
                git_push=bool(args.git_push),
                relay_push=bool(args.relay_push),
            )
            ledger = _load_or_seed_ledger(args.ledger, args.workspace)
            ledger.upsert(lesson.to_golden_scar())
            ledger.save()
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "pull":
            doms = [d.strip() for d in args.domains.split(",") if d.strip()] if args.domains else None
            res = mgr.pull_lessons_by_domain(
                doms,
                model_family=args.model_family,
                fetch_remote_github=bool(args.remote),
                include_relay=bool(args.relay),
            )
            ledger = _load_or_seed_ledger(args.ledger, args.workspace)
            for l in mgr.load_local_lessons():
                ledger.upsert(l.to_golden_scar())
            ledger.save()
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "push-relay":
            dispatched = []
            for local_lesson in mgr.load_local_lessons():
                r = mgr.push_to_zero_auth_relay(
                    local_lesson,
                    relay_url=args.relay_url,
                    network_send=not bool(args.offline_outbox),
                )
                dispatched.append({"id": local_lesson.id, **r})
            print(json.dumps({"total_checked": len(dispatched), "results": dispatched}, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "sync-relay":
            res = mgr.sync_from_zero_auth_relay(
                relay_url=args.relay_url,
                since=args.since,
                fetch_network=not bool(args.local_outbox_only),
            )
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "harvest-github":
            repo_list = [r.strip() for r in args.repos.split(",") if r.strip()] if args.repos else None
            res = mgr.harvest_github_skill_repos(
                repos=repo_list,
                fetch_live_github=not bool(args.offline),
            )
            ledger = _load_or_seed_ledger(args.ledger, args.workspace)
            for l in mgr.load_pool_lessons():
                ledger.upsert(l.to_golden_scar())
            ledger.save()
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "seed-pool":
            mgr.save_config(sync_mode=SyncMode.FEDERATED_SYNC.value)
            published = []
            for seed in get_seed_frontier_lessons():
                r = mgr.record_lesson(seed, force_local_only=False, git_push=False)
                published.append(r)
            mgr.save_config(sync_mode=SyncMode.LOCAL_ONLY.value)
            print(json.dumps({"seeded": len(published), "results": published}, indent=2, ensure_ascii=False))
            return 0

        if args.learn_action == "pool-status":
            cfg = mgr.load_config()
            local_lessons = mgr.load_local_lessons()
            pool_lessons = mgr.load_pool_lessons()
            by_pillar = {"engineering": 0, "life-and-business": 0}
            by_domain = {}
            by_model = {}
            by_source = {}
            for l in pool_lessons:
                by_pillar[l.domain_pillar] = by_pillar.get(l.domain_pillar, 0) + 1
                by_domain[l.domain] = by_domain.get(l.domain, 0) + 1
                by_model[l.model_family] = by_model.get(l.model_family, 0) + 1
                by_source[l.source_repo] = by_source.get(l.source_repo, 0) + 1
            print(
                json.dumps(
                    {
                        "user_config": cfg,
                        "local_private_lessons": len(local_lessons),
                        "collective_pool_total": len(pool_lessons),
                        "pool_by_pillar": by_pillar,
                        "pool_by_domain": by_domain,
                        "pool_by_frontier_model_family": by_model,
                        "pool_by_source_repo": by_source,
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0

    if args.command == "compile":
        if getattr(args, "starter_only", False):
            from kintsugi.starter_pack import get_starter_scars
            import shutil

            seed_map = {s.id: s for s in get_starter_scars()}
            for fl in get_seed_frontier_lessons():
                gs = fl.to_golden_scar()
                seed_map.setdefault(gs.id, gs)
            scars_to_compile = sorted(seed_map.values(), key=lambda s: s.id)
            allowed_cats = {s.category for s in scars_to_compile}
            skills_root = Path(args.workspace) / ".claude" / "skills"
            if skills_root.exists():
                for child in skills_root.iterdir():
                    if (
                        child.is_dir()
                        and child.name.startswith("kintsugi-")
                        and child.name not in {"kintsugi-guardrails", "kintsugi-multi-model-council"}
                        and child.name.removeprefix("kintsugi-") not in allowed_cats
                    ):
                        shutil.rmtree(child, ignore_errors=True)
        else:
            ledger = _load_or_seed_ledger(args.ledger, args.workspace)
            scars_to_compile = ledger.all()
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        written = SkillCompiler(scars_to_compile, compact_kmi=bool(args.compact)).compile_all(
            args.workspace,
            targets=targets,
        )
        for p in written:
            print(f"[kintsugi] Compiled -> {p}")
        return 0

    if args.command == "explain":
        ledger = _load_or_seed_ledger(args.ledger)
        target_id = args.scar_id.strip().upper()
        matches = [s for s in ledger.all() if s.id.upper() == target_id]
        if not matches:
            print(f"Scar not found: {target_id}", file=sys.stderr)
            return 1
        scar = matches[0]
        print(
            f"{scar.id} · [{scar.severity.value}] {scar.title}\n"
            f"Category  : {scar.category}\n"
            f"Languages : {', '.join(scar.languages)}\n"
            f"Root Cause: {scar.root_cause}\n"
            f"Rationale : {scar.rationale}\n\n"
            f"❌ Bad Code:\n{scar.bad_code}\n\n"
            f"✅ Verified Fix:\n{scar.good_code}"
        )
        return 0

    if args.command == "evolve":
        from kintsugi.cli_nextgen import handle_evolve_v3_flags

        v3_rc = handle_evolve_v3_flags(args)
        if v3_rc is not None:
            return v3_rc
        ledger = _load_or_seed_ledger(args.ledger, args.workspace)
        if getattr(args, "consolidate_dry_run", False):
            from kintsugi.evolution_v2 import plan_ledger_consolidation

            plan = plan_ledger_consolidation(ledger.all())
            print(json.dumps(plan, indent=2, ensure_ascii=False))
            return 0
        if getattr(args, "parity_check", False):
            from kintsugi.evolution_v2 import default_parity_fixtures, run_python_rust_parity

            rep = run_python_rust_parity(
                default_parity_fixtures(),
                rust_bin_path=getattr(args, "rust_bin", None),
                scars=ledger.all(),
            )
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            return 0 if rep.get("mismatches", 0) == 0 else 1
        if not args.summary and not getattr(args, "ir_synthesize", False):
            print("[kintsugi] Error: --summary is required unless using --consolidate-dry-run or --parity-check.", file=sys.stderr)
            return 2
        if getattr(args, "ir_synthesize", False):
            from kintsugi.evolution_v2 import (
                FailureEnvelope,
                generate_counterfactuals,
                synthesize_rule_ir,
                validate_candidate_rule,
            )

            env = FailureEnvelope.create(
                task_id="cli-ir-evolve",
                language=args.language,
                offending_snippet=args.bad_code,
                fixed_snippet=args.good_code,
                error_summary=args.summary or "CLI Evolution v2 candidate",
            )
            rule_ir = synthesize_rule_ir(env, rule_id=ledger.next_id())
            pos, neg = generate_counterfactuals(rule_ir, args.bad_code, args.good_code)
            att = validate_candidate_rule(rule_ir, pos, neg)
            print(json.dumps({"envelope": env.to_dict(), "rule_ir": rule_ir.to_dict(), "attestation": att.to_dict()}, indent=2, ensure_ascii=False))
            return 0 if att.status != "REJECTED" else 1
        raw_log = ""
        if args.from_log:
            raw_log = Path(args.from_log).read_text(encoding="utf-8")
        trace = FailureTrace(
            source=args.from_log or "cli",
            error_summary=args.summary,
            raw_trace=raw_log,
            language=args.language,
            offending_snippet=args.bad_code,
            fixed_snippet=args.good_code,
        )
        council = EvolutionCouncil(workspace_root=args.workspace)
        if args.co_run or args.free_runners is not None or args.paid_council:
            scar, co_rep = council.evolve_with_co_runners(
                trace,
                scar_id=ledger.next_id(),
                num_free_runners=args.free_runners,
                include_paid_council=bool(args.paid_council),
            )
            msg = co_rep["kmi_corun_wire"]
        else:
            scar, msg = council.evolve(trace, scar_id=ledger.next_id())
        is_new, stored = ledger.upsert(scar)
        ledger.save()
        status = "Created" if is_new else "Merged duplicate into"
        print(f"[kintsugi] {status} {stored.id}: {stored.title} ({msg})")
        if args.compile_workspace:
            SkillCompiler(ledger.all()).compile_all(args.compile_workspace)
        return 0

    if args.command == "verify-ledger":
        ledger = _load_or_seed_ledger(args.ledger)
        failures = 0
        for scar in ledger.all():
            ok, msg = verify_candidate_scar(scar)
            mark = "PASS" if ok else "FAIL"
            print(f"[{mark}] {scar.id} ({scar.severity.value}) {scar.title} — {msg}")
            if not ok:
                failures += 1
        return 1 if failures else 0

    if args.command == "hook":
        ledger = _load_or_seed_ledger(args.ledger)
        raw_stdin = sys.stdin.read().strip()
        try:
            payload = json.loads(raw_stdin) if raw_stdin else {}
        except Exception:
            print(
                json.dumps(
                    {
                        "decision": "deny",
                        "reason": "FAIL-CLOSED HOOK GUARD: Invalid stdin JSON payload.",
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "deny",
                            "permissionDecisionReason": "FAIL-CLOSED HOOK GUARD: Invalid stdin JSON payload.",
                        },
                    }
                )
            )
            return 0
        decision = evaluate_claude_pre_tool_payload(
            payload,
            ledger.all(),
            block_threshold=Severity(args.block_on),
            trusted_workspace_root=getattr(args, "workspace", None),
        )
        print(json.dumps(decision))
        return 0

    if args.command == "install-hooks":
        settings_file = install_claude_settings_hook(args.workspace)
        print(f"[kintsugi] Installed Claude Code PreToolUse hook -> {settings_file}")
        if args.git:
            git_hook = install_git_pre_commit_hook(args.workspace)
            print(f"[kintsugi] Installed git pre-commit hook -> {git_hook}")
        return 0

    if args.command == "mcp":
        server = KintsugiMCPServer(
            args.ledger,
            profile=getattr(args, "mcp_profile", "default"),
        )
        server.serve_stdio()
        return 0

    if args.command == "stats":
        ledger = _load_or_seed_ledger(args.ledger)
        scars = ledger.all()
        by_sev = {s.value: 0 for s in Severity}
        for s in scars:
            by_sev[s.severity.value] += 1
        print(
            json.dumps(
                {
                    "ledger": str(ledger.path),
                    "total_scars": len(scars),
                    "by_severity": by_sev,
                    "total_prevented_hits": sum(s.hits for s in scars),
                    "kmi_wire_index": render_kmi_index(scars),
                },
                indent=2,
            )
        )
        return 0

    if args.command == "ground":
        engine = RepoAstGroundingEngine(args.target)
        if args.anchor:
            syms = [s.strip() for s in (args.symbols or "").split(",") if s.strip()]
            verdict = engine.verify_hypothesis(
                {"anchor": args.anchor, "symbols": syms},
                expected_manifest_sha=args.manifest_sha,
            )
            print(json.dumps(verdict, indent=2, ensure_ascii=False))
            return 0 if verdict["status"] == "VERIFIED" else 1
        print(json.dumps(engine.summary(), indent=2, ensure_ascii=False))
        return 0

    if args.command == "foresight":
        if args.scientific_corpus:
            verifier = ScientificLiteratureVerifier(args.workspace)
            print(json.dumps(verifier.verify_scientific_corpus(), indent=2, ensure_ascii=False))
            return 0
        if args.metacognition:
            meta = MetacognitiveSelfModel(args.workspace)
            print(json.dumps(meta.build_self_awareness_report(), indent=2, ensure_ascii=False))
            return 0
        if args.self_generate:
            synth = AutopoieticSynthesizer(args.workspace)
            res = synth.synthesize_from_target(args.target)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0
        if args.transfer:
            transfer = AnalogicalTransferEngine()
            print(json.dumps(transfer.transfer_from_target(args.target), indent=2, ensure_ascii=False))
            return 0
        if args.dream:
            dreamer = CounterfactualDreamSimulator(args.workspace)
            d_rep = dreamer.simulate_dream(args.target)
            if args.wire:
                print(d_rep["kmi_dream_wire"])
                return 0
            print(json.dumps(d_rep, indent=2, ensure_ascii=False))
            return 0
        if args.swarm:
            swarm_orch = ShadowCloneSwarmOrchestrator(args.workspace)
            s_rep = swarm_orch.run_swarm(args.target)
            if args.wire:
                print(s_rep["kmi_swarm_wire"])
                return 0
            print(json.dumps(s_rep, indent=2, ensure_ascii=False))
            return 0
        forecaster = CausalForesightEngine(args.workspace)
        rep = forecaster.forecast(args.target, top_k_actions=args.top_k)
        if args.wire:
            dream_wire = CounterfactualDreamSimulator(args.workspace).simulate_dream(args.target)["kmi_dream_wire"]
            swarm_wire = ShadowCloneSwarmOrchestrator(args.workspace).run_swarm(args.target, consolidate_to_memory=False)["kmi_swarm_wire"]
            print(f"{rep['kmi_foresight_wire']}\n{rep['metacognitive_wire']}\n{dream_wire}\n{swarm_wire}")
            return 0
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0

    if args.command == "swarm":
        if getattr(args, "model_matrix", False):
            mat_rep = get_model_capability_matrix()
            if args.wire:
                print(mat_rep["kmi_matrix_wire"])
                return 0
            print(json.dumps(mat_rep, indent=2, ensure_ascii=False))
            return 0
        if getattr(args, "swarm_plan", None) is not None:
            plan_rep = compute_swarm_dispatch_plan(
                args.swarm_plan,
                plan_tier=getattr(args, "plan_tier", "UNLIMITED_LOCAL"),
            )
            if args.wire:
                print(plan_rep["kmi_dispatch_wire"])
                return 0
            print(json.dumps(plan_rep, indent=2, ensure_ascii=False))
            return 0
        if getattr(args, "step_audit", None) is not None:
            step_rep = audit_step_economics(args.step_audit)
            if args.wire:
                print(step_rep["kmi_step_wire"])
                return 0
            print(json.dumps(step_rep, indent=2, ensure_ascii=False))
            return 0
        if args.provider_benchmarks:
            pb_rep = AIProviderBenchmarkSuite().run_all_provider_benchmarks(fetch_live_network=True)
            print(json.dumps(pb_rep, indent=2, ensure_ascii=False))
            return 0 if pb_rep["all_8_harnesses_executed_and_verified"] else 1
        if args.forage_internet:
            fg_rep = ControlledInternetForager().forage_and_evolve_small_vs_frontier(fetch_live_network=True)
            if args.wire:
                print(fg_rep["kmi_forage_wire"])
                return 0
            print(json.dumps(fg_rep, indent=2, ensure_ascii=False))
            return 0
        if args.evolution_proof:
            ev_rep = ClosedLoopEvolutionArena().run_evolution_proof()
            if args.wire:
                print(ev_rep["kmi_evolve_wire"])
                return 0
            print(json.dumps(ev_rep, indent=2, ensure_ascii=False))
            return 0 if ev_rep["all_invariants_verified"] else 1
        if args.red_blue_arena:
            arena_rep = RedBlueAdversarialArena().run_arena()
            if args.wire:
                print(arena_rep["kmi_arena_wire"])
                return 0
            print(json.dumps(arena_rep, indent=2, ensure_ascii=False))
            return 0 if arena_rep["all_attacks_neutralized"] else 1
        pool_mgr = BYOKProviderPoolManager(args.workspace)
        paid_reg = PaidFrontierCouncilBYOKRegistry(args.workspace)
        if args.ask is not None:
            print(json.dumps(answer_user_multi_model_question(args.ask, args.workspace), indent=2, ensure_ascii=False))
            return 0
        if args.guide:
            print(json.dumps(answer_user_multi_model_question("", args.workspace), indent=2, ensure_ascii=False))
            return 0
        if args.paid_council_status:
            print(json.dumps(paid_reg.get_status(), indent=2, ensure_ascii=False))
            return 0
        if args.add_paid_key:
            pid, key_val = args.add_paid_key
            print(json.dumps(paid_reg.add_paid_key(pid, key_val), indent=2, ensure_ascii=False))
            return 0
        if args.remove_paid_key:
            print(json.dumps(paid_reg.remove_paid_key(args.remove_paid_key), indent=2, ensure_ascii=False))
            return 0
        if args.co_run or args.free_runners is not None or args.paid_council:
            co_exec = PrimaryPlusFreeCoExecutor(args.workspace)
            plan = co_exec.resolve_execution_plan(
                requested_free_runners=args.free_runners,
                include_paid_council=bool(args.paid_council),
            )
            plan.pop("_free_slot_objects", None)
            plan.pop("_paid_slot_objects", None)
            plan["agent_onboarding_guide"] = build_multi_model_agent_guide(args.workspace)
            print(json.dumps(plan, indent=2, ensure_ascii=False))
            return 0
        if args.revoke_consent:
            print(json.dumps(pool_mgr.revoke_consent(), indent=2, ensure_ascii=False))
            return 0
        if args.add_free_key:
            pid, key_val = args.add_free_key
            print(json.dumps(pool_mgr.add_user_provided_key(pid, key_val), indent=2, ensure_ascii=False))
            return 0
        if args.authorize_auto_provision:
            scope_list = [s.strip() for s in args.scope.split(",") if s.strip()] if args.scope else None
            res = pool_mgr.authorize_auto_provision(confirmed_by_user=True, allowed_providers=scope_list)
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0
        if args.request_consent:
            print(json.dumps(pool_mgr.build_user_consent_prompt(target_clones=args.clones), indent=2, ensure_ascii=False))
            return 0
        if args.pool_status:
            st = pool_mgr.get_pool_status(target_clones=args.clones)
            if args.wire:
                print(st["kmi_pool_wire"])
                return 0
            print(json.dumps(st, indent=2, ensure_ascii=False))
            return 0

        swarm_orch = ShadowCloneSwarmOrchestrator(args.workspace)
        s_rep = swarm_orch.run_swarm(
            args.target,
            num_clones=args.clones,
            consolidate_to_memory=not bool(args.no_consolidate),
            inject_byzantine_fault=bool(args.byzantine_test),
        )
        if args.wire:
            print(f"{s_rep['kmi_swarm_wire']}\n{s_rep['kmi_pool_wire']}")
            return 0
        print(json.dumps(s_rep, indent=2, ensure_ascii=False))
        return 0

    if args.command == "guide":
        q_text = " ".join(args.question).strip() if args.question else ""
        qa_res = answer_user_multi_model_question(q_text, args.workspace)
        if args.format == "json":
            print(json.dumps(qa_res, indent=2, ensure_ascii=False))
        else:
            print(qa_res["direct_answer_markdown"])
        return 0

    if args.command == "compact":
        if getattr(args, "evolution_iq", False):
            from kintsugi.cognition import compute_evolution_intelligence_report

            iq_rep = compute_evolution_intelligence_report(args.workspace)
            print(json.dumps(iq_rep, indent=2, ensure_ascii=False))
            return 0
        compactor = ConversationCompactor(
            args.workspace,
            max_context_tokens=args.max_tokens,
            soft_watermark=args.soft_watermark,
            hard_watermark=args.hard_watermark,
        )
        res = compactor.compact_from_source(
            explicit_path=args.source,
            persist=not bool(args.no_persist),
            inject_agents_md=bool(args.inject_agents),
            co_run=bool(args.co_run),
        )
        if getattr(args, "persona", False):
            print(json.dumps(res.get("user_persona") or {}, indent=2, ensure_ascii=False))
            return 0
        if args.wire or args.format == "wire":
            print(res["kmi_compact_wire"])
        elif args.format == "json":
            print(json.dumps(res, indent=2, ensure_ascii=False))
        else:
            print(res["checkpoint_markdown"])
        return 0

    if args.command == "logic":
        from kintsugi.logic import (
            LoginAuthLogicVerifier,
            forage_github_star_harnesses,
            run_logical_reasoning_benchmark,
            run_neuro_symbolic_vs_raw_council_logic_arena,
        )

        if getattr(args, "login_verify", False):
            rep = LoginAuthLogicVerifier().verify_login_security_suite()
        elif getattr(args, "arena", False):
            rep = run_neuro_symbolic_vs_raw_council_logic_arena()
        elif getattr(args, "forage_github_harnesses", False):
            rep = forage_github_star_harnesses(live_github_probe=True)
        else:
            rep = run_logical_reasoning_benchmark()

        if getattr(args, "wire", False) and "wire" in rep:
            print(rep["wire"])
        else:
            print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0 if rep.get("ok") else 1

    if args.command == "verify":
        from kintsugi.compliance import SignedComplianceProofExporter, ZeroKnowledgeASTDiffVerifier

        exporter = SignedComplianceProofExporter()
        target_code = None
        if getattr(args, "target", None):
            target_code = Path(args.target).read_text(encoding="utf-8")
        if getattr(args, "verify_proof", None):
            loaded = json.loads(Path(args.verify_proof).read_text(encoding="utf-8"))
            v_res = exporter.verify_compliance_proof_bundle(loaded, expected_patch_code=target_code)
            print(json.dumps(v_res, indent=2, ensure_ascii=False))
            return 0 if v_res.get("ok") else 1
        if getattr(args, "zk_diff", False):
            zk_res = ZeroKnowledgeASTDiffVerifier().build_zk_ast_proof(
                target_code
                or (
                    "def authenticate_request(account_id, active_sess, otp_elapsed):\n"
                    "    verify_mfa(account_id)\n"
                    "    revoke_session(active_sess)\n"
                    "    check_otp_window(otp_elapsed)\n"
                    "    return True\n"
                )
            )
            print(json.dumps(zk_res, indent=2, ensure_ascii=False))
            return 0 if zk_res.get("ok") else 1

        out_path = Path(args.export_audit) if getattr(args, "export_audit", None) else None
        bundle = exporter.generate_compliance_proof_bundle(
            target_code=target_code,
            output_path=out_path,
        )
        if getattr(args, "wire", False):
            print(bundle["wire"])
        else:
            print(json.dumps(bundle, indent=2, ensure_ascii=False))
        return 0 if bundle.get("ok") else 1

    if args.command == "eval":
        from kintsugi.compliance import ReproducibleEvalSuite

        suite = ReproducibleEvalSuite()
        if getattr(args, "replay", None):
            rep = suite.replay_eval_case(args.replay)
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            return 0 if rep.get("ok") else 1
        rep = suite.run_full_evaluation_suite(include_ablation=not bool(getattr(args, "no_ablation", False)))
        if getattr(args, "wire", False):
            print(rep["wire"])
        else:
            print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0 if rep.get("ok") else 1

    if args.command == "integrate":
        from kintsugi.integrator import UniversalHarnessIntegrator

        integrator = UniversalHarnessIntegrator(getattr(args, "workspace", "."))
        if getattr(args, "eject", None):
            rep = integrator.eject_harness(args.eject)
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            return 0 if rep.get("ok") else 1
        if getattr(args, "list", False):
            rep = integrator.list_integrated_harnesses()
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            return 0
        target_arg = getattr(args, "target", None)
        if getattr(args, "scan", False) or not target_arg:
            rep = integrator.discover_harnesses(target_arg)
            print(json.dumps(rep, indent=2, ensure_ascii=False))
            return 0
        if getattr(args, "mount", False):
            rep = integrator.mount_harness(target_arg, harness_id=getattr(args, "harness_id", None))
        else:
            rep = integrator.ingest_and_analyze(target_arg, harness_id=getattr(args, "harness_id", None))
        if getattr(args, "wire", False) and "attestation_receipt" in rep:
            print(rep["attestation_receipt"]["wire"])
        else:
            print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0 if rep.get("ok") else 1

    if args.command == "cinema":
        from kintsugi.cinema import (
            CinemaEvolutionEngine,
            ComponentVideoQAVerifier,
            MultiProviderVideoRouter,
            OpenMontagePackageManager,
            build_demo_flawed_openmontage_manifest,
        )

        ws = Path(getattr(args, "workspace", ".")).resolve()
        pkg_mgr = OpenMontagePackageManager(ws)
        evo = CinemaEvolutionEngine(ws)

        if getattr(args, "scars", False):
            scars_payload = {
                "package_id": "kintsugi-openmontage-cinema",
                "count": len(evo.scars),
                "cinema_scars": [s.to_dict() for s in sorted(evo.scars.values(), key=lambda x: x.scar_id)],
            }
            print(json.dumps(scars_payload, indent=2, ensure_ascii=False))
            return 0

        pull_meta = None
        if getattr(args, "pull_openmontage", False) or getattr(args, "offline_pull", False):
            pull_meta = pkg_mgr.ensure_openmontage_installed(
                auto_pull_remote=not bool(getattr(args, "offline_pull", False))
            )
            if (
                not getattr(args, "verify_manifest", False)
                and not getattr(args, "auto_heal", False)
                and not getattr(args, "manifest", None)
                and not getattr(args, "synthesize_test_clips", None)
            ):
                print(json.dumps(pull_meta, indent=2, ensure_ascii=False))
                return 0

        if getattr(args, "manifest", None):
            manifest_data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        else:
            manifest_data = build_demo_flawed_openmontage_manifest()

        style_mode = getattr(args, "style", "live_action")
        provider = getattr(args, "provider", "veo")

        # Always ensure OpenMontage extension package is mounted when running cinema workflows
        if pull_meta is None:
            pull_meta = pkg_mgr.ensure_openmontage_installed(auto_pull_remote=False)

        if getattr(args, "auto_heal", False) or not getattr(args, "verify_manifest", False):
            healed_manifest, evo_rep = evo.auto_heal_and_evolve_manifest(
                manifest_data,
                style_mode=style_mode,
                provider=provider,
            )
            clips_dir = getattr(args, "synthesize_test_clips", None)
            if clips_dir:
                for sh in healed_manifest.get("shots", []):
                    MultiProviderVideoRouter.synthesize_component_test_media(
                        clips_dir,
                        sh,
                        style_mode=style_mode,
                        provider=provider,
                    )
            final_qa = ComponentVideoQAVerifier().verify_production_manifest_and_clips(
                healed_manifest,
                clips_dir=clips_dir,
                style_mode=style_mode,
            )
            if getattr(args, "output", None):
                Path(args.output).write_text(
                    json.dumps(healed_manifest, indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
            out_payload = {
                "ok": final_qa["ok"],
                "openmontage_package": pull_meta,
                "evolution_report": evo_rep,
                "qa_report": final_qa,
            }
            if getattr(args, "wire", False):
                print(evo_rep["wire"])
            else:
                print(json.dumps(out_payload, indent=2, ensure_ascii=False))
            return 0 if final_qa["ok"] else 1

        qa_rep = ComponentVideoQAVerifier().verify_production_manifest_and_clips(
            manifest_data,
            clips_dir=getattr(args, "synthesize_test_clips", None),
            style_mode=style_mode,
        )
        print(json.dumps(qa_rep, indent=2, ensure_ascii=False))
        return 0 if qa_rep["ok"] else 1

    if args.command == "config":
        from kintsugi.config import (
            canonical_config_hash,
            resolve_kintsugi_config,
            validate_config_dict,
        )
        from kintsugi.shield import assert_not_symlink

        ws = Path(getattr(args, "workspace", ".")).resolve()
        if args.config_action == "validate":
            target_cfg = getattr(args, "file", None) or getattr(args, "external_config", None)
            if not target_cfg:
                print(json.dumps({"ok": False, "error": "Missing --file or --external-config"}))
                return 2
            cfg_path = Path(target_cfg)
            assert_not_symlink(cfg_path)
            raw_obj = json.loads(cfg_path.read_text(encoding="utf-8"))
            validated = validate_config_dict(raw_obj)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "status": "VALID",
                        "config_schema": validated.get("config_schema"),
                        "profile": validated.get("profile"),
                        "config_hash": canonical_config_hash(validated),
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
            return 0
        cfg = resolve_kintsugi_config(
            external_config_path=getattr(args, "external_config", None),
            cli_profile=getattr(args, "profile", None),
            target_repo_root=ws,
        )
        cfg_dict = cfg.to_dict()
        cfg_dict["config_hash"] = canonical_config_hash(cfg)
        print(json.dumps(cfg_dict, indent=2, ensure_ascii=False))
        return 0

    if args.command in {"tools", "capability"}:
        from kintsugi.capability import (
            AttestationAuthority,
            CapabilityGapDetector,
            SecurityContext,
            ToolRegistry,
            ToolResolver,
            ToolSpec,
            TrustStatus,
            compute_tool_spec_security_digest,
            sha256_digest,
        )
        from kintsugi.config import resolve_kintsugi_config
        from kintsugi.runtime import ExperienceStore, SecureRunner, run_stage1_vertical_slice
        from kintsugi.shield import assert_not_symlink, resolve_safe_child_path
        from kintsugi.tools import LogForge, RepoScout

        ws = Path(getattr(args, "workspace", ".")).resolve()
        cfg = resolve_kintsugi_config(cli_profile=getattr(args, "profile", None), target_repo_root=ws)
        sec_ctx = SecurityContext(
            workspace_root=str(ws),
            profile=cfg.profile.value,
            allowed_permissions=["read_workspace", "scan_code", "read_logs"],
            network_allowed=False,
            allow_untrusted_native=False,
        )
        reg_arg = Path(getattr(args, "registry", ".kintsugi/tool_registry.json"))
        reg_path = reg_arg if reg_arg.is_absolute() else (ws / reg_arg)
        verifier_key_file = getattr(args, "verifier_key_file", None)
        authority: Optional[AttestationAuthority] = None
        if verifier_key_file:
            try:
                authority = AttestationAuthority.from_key_file(verifier_key_file, workspace_root=ws)
            except (PermissionError, ValueError, OSError, json.JSONDecodeError) as exc:
                print(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
                return 1
        registry = ToolRegistry(authority=authority)
        if reg_path.exists():
            assert_not_symlink(reg_path)
            registry.load(reg_path)

        if args.command == "tools":
            action = args.tools_action
            if action == "discover":
                discovered = registry.discover_local(sec_ctx, allowlisted_paths=getattr(args, "path", None))
                if getattr(args, "save", False):
                    registry.save(reg_path)
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "discovered_count": len(discovered),
                            "total_registry": len(registry.list_tools()),
                            "tools": [t.to_dict() for t in discovered],
                        },
                        indent=2,
                        ensure_ascii=False,
                    )
                )
                return 0
            if action == "list":
                items = (
                    registry.search_capability(args.capability)
                    if getattr(args, "capability", None)
                    else registry.list_tools()
                )
                print(json.dumps({"ok": True, "count": len(items), "tools": [t.to_dict() for t in items]}, indent=2, ensure_ascii=False))
                return 0
            tid = getattr(args, "tool_id", None) or getattr(args, "tool_id_pos", None)
            if action == "inspect":
                spec = registry.get(str(tid or ""))
                if spec is None:
                    print(json.dumps({"ok": False, "status": "NO_VERIFIED_TOOL", "tool_id": tid}))
                    return 1
                print(json.dumps({"ok": True, "tool": spec.to_dict()}, indent=2, ensure_ascii=False))
                return 0
            if action == "verify":
                if not verifier_key_file or authority is None or not authority.has_registered_verifiers:
                    print(
                        json.dumps(
                            {
                                "ok": False,
                                "error": (
                                    "VERIFIER_KEY_FILE_REQUIRED: --verifier-key-file outside workspace "
                                    "is mandatory for tools verify."
                                ),
                            },
                            indent=2,
                            ensure_ascii=False,
                        )
                    )
                    return 1
                loaded_att: Optional[Dict[str, Any]] = None
                att_file = getattr(args, "attestation_file", None)
                try:
                    if att_file:
                        att_path = Path(str(att_file))
                        assert_not_symlink(att_path)
                        raw_att = json.loads(att_path.read_text(encoding="utf-8"))
                        if not isinstance(raw_att, dict):
                            raise ValueError("INVALID_ATTESTATION_FILE: expected JSON object.")
                        loaded_att = raw_att
                    spec = registry.verify_tool(
                        str(tid or ""),
                        str(getattr(args, "verify_digest", "") or ""),
                        str(getattr(args, "verifier_id", "cli_operator")),
                        attestation_signature=getattr(args, "attestation_signature", None),
                        attestation=loaded_att,
                    )
                    if getattr(args, "save", False):
                        registry.save(reg_path)
                except (PermissionError, ValueError, KeyError, OSError, json.JSONDecodeError) as exc:
                    print(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
                    return 1
                print(json.dumps({"ok": True, "tool": spec.to_dict()}, indent=2, ensure_ascii=False))
                return 0

            # vertical-slice deterministic Stage 1 demo (no LLM calls)
            cap = str(getattr(args, "capability", None) or "log.scan_delimiters")
            exp_arg = Path(getattr(args, "experience_store", ".kintsugi/experience_store.json"))
            exp_path = exp_arg if exp_arg.is_absolute() else (ws / exp_arg)
            exp_store = ExperienceStore(exp_path)
            runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
            logforge = LogForge()
            def _run_logforge_slice(task_args: Dict[str, Any]) -> Dict[str, Any]:
                return {
                    "offsets": logforge.scan_delimiters(
                        str(task_args.get("data", "")).encode("utf-8"),
                        delim=int(task_args.get("delim", 10)),
                        tier="python_oracle",
                    ).offsets
                }

            callable_hash = runner.register_trusted_host_callable("local.logforge", _run_logforge_slice)
            registry.authority.register_verifier("stage1_cli", secrets.token_bytes(32))
            builtin_spec = ToolSpec(
                tool_id="local.logforge",
                version="1.0.0",
                source="host_trusted",
                binary_hash=callable_hash,
                capabilities=["log.scan_delimiters"],
                input_schema={"type": "object", "required": ["data"]},
                output_schema={"type": "object", "required": ["offsets"]},
                semantic_contract={"output_semantics": "exact_byte_offsets"},
                preconditions=["non_empty_or_empty_bytes"],
                postconditions=["sorted_offsets"],
                side_effects=[],
                required_permissions=["read_logs"],
                runtime_requirements={"platform": ["darwin-arm64", "linux-x86_64"], "network": False},
                trust_status=TrustStatus.VERIFIED,
                latency_estimate_ms=2.0,
                memory_estimate_mb=8.0,
                api_token_estimate=0,
                verification_attestation={
                    "verifier_id": "stage1_cli",
                    "verification_digest": sha256_digest({"tool_id": "local.logforge", "binary_hash": callable_hash}),
                    "binary_hash": callable_hash,
                    "tool_id": "local.logforge",
                    "source": "builtin_verifier",
                },
                provenance={"origin": "builtin_kintsugi_tools", "verified_by": "stage1_cli"},
            )
            builtin_spec.verification_attestation = registry.authority.issue_attestation(
                builtin_spec.tool_id, builtin_spec.binary_hash,
                sha256_digest({"tool_id": builtin_spec.tool_id, "binary_hash": builtin_spec.binary_hash}),
                "stage1_cli", spec_digest=compute_tool_spec_security_digest(builtin_spec),
            )
            registry.register(builtin_spec, trusted_attestor=True)

            def _oracle_check(exec_summary: Any, _tool: Any, _args: Dict[str, Any]) -> bool:
                payload = exec_summary.get("output") if isinstance(exec_summary, dict) else None
                return isinstance(payload, dict) and isinstance(payload.get("offsets"), list)

            raw_task = getattr(args, "task", None)
            if raw_task:
                try:
                    task_obj: Any = json.loads(raw_task)
                except json.JSONDecodeError:
                    task_obj = {
                        "task_id": "cli-slice-001",
                        "intent": raw_task,
                        "capability": cap,
                        "args": {"data": "line1\nline2\n"},
                    }
            else:
                task_obj = {
                    "task_id": "cli-slice-001",
                    "intent": "Scan delimiter byte offsets in log stream",
                    "capability": cap,
                    "args": {"data": "alpha\nbeta\ngamma\n"},
                }
            res = run_stage1_vertical_slice(
                task_obj,
                security_context=sec_ctx,
                registry=registry,
                runner=runner,
                experience_store=exp_store,
                oracle=_oracle_check,
                config=cfg,
            )
            print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
            return 0 if res.status == "PASS" else 1

        # capability analyze
        goal_obj: Dict[str, Any]
        if getattr(args, "goal_file", None):
            safe_gf = resolve_safe_child_path(ws, str(args.goal_file))
            if safe_gf is None or not safe_gf.exists():
                print(json.dumps({"ok": False, "status": "PERMISSION_DENIED", "error": "Unsafe or missing goal file"}))
                return 1
            assert_not_symlink(safe_gf)
            goal_obj = json.loads(safe_gf.read_text(encoding="utf-8"))
        else:
            caps = list(getattr(args, "capability", None) or ["general.execute"])
            goal_obj = {"goal_id": args.goal_id, "required_capabilities": caps}
        gap = CapabilityGapDetector().analyze(goal_obj, registry, sec_ctx)
        resolution = ToolResolver().resolve(gap, registry, sec_ctx)
        print(
            json.dumps(
                {
                    "ok": resolution.executable,
                    "capability_gap": gap.to_dict(),
                    "resolution": resolution.to_dict(),
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0 if resolution.executable else 1

    if args.command == "logforge":
        from kintsugi.shield import assert_not_symlink, resolve_safe_child_path
        from kintsugi.tools import LogForge

        ws = Path(getattr(args, "workspace", ".")).resolve()
        raw_delim = str(getattr(args, "delim", "\\n"))
        delim_str = "\\n" if raw_delim == "\\n" else raw_delim
        delim_byte = 10 if delim_str == "\\n" else ord(delim_str[0])
        payload_bytes = b"ts=2026-11-22T01:00:00Z level=INFO msg=boot\nts=2026-11-22T01:00:01Z level=WARN msg=retry\n"
        if getattr(args, "input", None):
            safe_in = resolve_safe_child_path(ws, str(args.input))
            if safe_in is None or not safe_in.exists():
                print(json.dumps({"ok": False, "status": "PERMISSION_DENIED", "error": "Unsafe or missing input path"}))
                return 1
            assert_not_symlink(safe_in)
            payload_bytes = safe_in.read_bytes()
        forge = LogForge()
        tier_map = {"python": "python_oracle", "rust_neon": "rust_simd"}
        req_tier = tier_map.get(getattr(args, "tier", "auto"), getattr(args, "tier", "auto"))
        scan_res = forge.scan_delimiters(
            payload_bytes,
            delim=delim_byte,
            tier=req_tier,
            disable_simd=bool(getattr(args, "disable_simd", False)),
            normalize=bool(getattr(args, "normalize", False)),
        )
        print(json.dumps(scan_res.to_dict(), indent=2, ensure_ascii=False))
        return 0

    if args.command == "reposcout":
        from kintsugi.tools import RepoScout

        ws = Path(getattr(args, "workspace", ".")).resolve()
        scout = RepoScout(ws, index_path=getattr(args, "index", ".kintsugi/repo_scout_index.json"))
        index_data = scout.load_or_update()
        if getattr(args, "save", False):
            scout.save()
        out: Dict[str, Any] = {
            "ok": True,
            "file_count": len(index_data.get("files", {})),
            "index_digest": index_data.get("index_digest"),
        }
        if getattr(args, "changed", None):
            out["impact"] = scout.map_changed_files_to_tests(args.changed)
        if getattr(args, "symbol", None):
            out["symbols"] = scout.find_symbol(args.symbol)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    from kintsugi.cli_nextgen import handle_nextgen_command

    ng_rc = handle_nextgen_command(args)
    if ng_rc is not None:
        return ng_rc

    return 0


if __name__ == "__main__":
    sys.exit(main())
