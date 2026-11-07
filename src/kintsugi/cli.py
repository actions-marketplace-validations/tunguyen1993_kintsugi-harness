"""Command-line interface for Kintsugi Harness (`kintsugi`)."""

from __future__ import annotations

import argparse
import json
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
    ClosedLoopEvolutionArena,
    ConsentGatedFreePoolManager,
    ControlledInternetForager,
    RedBlueAdversarialArena,
    ShadowCloneSwarmOrchestrator,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kintsugi",
        description="Kintsugi Harness — Hybrid Rust/Python PreToolUse guardrail engine and KMI/1 ultra-low-token skill compiler.",
    )
    parser.add_argument("--version", action="version", version=f"kintsugi-harness {__version__}")
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

    # audit
    p_audit = sub.add_parser("audit", help="Run repository Security & Agent Readiness Posture Audit (Grade A+ to F)")
    p_audit.add_argument("target", nargs="?", default=".", help="Target repository root")
    p_audit.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_audit.add_argument("--format", choices=["text", "markdown", "json"], default="markdown")

    # token-report
    p_tok = sub.add_parser("token-report", help="Benchmark KMI/1 ultra-low-token compression vs verbose Markdown skills")
    p_tok.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_tok.add_argument("--turns", type=int, default=50, help="Number of turns per coding session")
    p_tok.add_argument("--format", choices=["text", "json"], default="text")

    # autofix
    p_fix = sub.add_parser("autofix", help="Preview patches (--dry-run) or apply deterministic codemods (--apply with installed Pack)")
    p_fix.add_argument("target", nargs="?", default=".", help="File or directory to remediate")
    p_fix.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_fix.add_argument("--workspace", default=".", help="Workspace root containing .kintsugi/packs")
    p_fix.add_argument("--apply", action="store_true", help="Apply in-place codemods (unlocked via installed Skill Packs)")

    # install-pack
    p_ipack = sub.add_parser("install-pack", help="Install an external or encrypted Premium Skill Pack (.kpack, .zip, or .json) into .kintsugi/packs/")
    p_ipack.add_argument("pack_path", help="Path to Skill Pack .kpack, .zip, or .json bundle")
    p_ipack.add_argument("--workspace", default=".", help="Target workspace root")
    p_ipack.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_ipack.add_argument("--license-key", default=None, help="Customer unlock key for encrypted Kintsugi Pro .kpack bundles (or set KINTSUGI_LICENSE_KEY)")

    # list-packs
    p_lpacks = sub.add_parser("list-packs", help="List installed external and Premium Skill Packs")
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
    p_ldist.add_argument("--model", required=True, help="Synthesizing model identifier (e.g. deepseek-r1, gpt-6.1, claude-opus-4)")
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
    p_lpull.add_argument("--model-family", default=None, help="Filter by Frontier model family (e.g. deepseek-r1, gpt-6-frontier)")
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
    p_evo.add_argument("--summary", required=True, help="One-line failure summary")
    p_evo.add_argument("--from-log", default=None, help="Path to traceback/CI log file")
    p_evo.add_argument("--language", default="python", help="Target language")
    p_evo.add_argument("--bad-code", default="", help="Offending code snippet")
    p_evo.add_argument("--good-code", default="", help="Verified replacement snippet")
    p_evo.add_argument("--compile-workspace", default=None, help="Auto-recompile skills in workspace after evolving")
    p_evo.add_argument(
        "--co-run",
        action="store_true",
        help="Run Primary Anchor model alongside discovered $0 Free Co-Runner(s) (1 on Free tier, up to 5 on Pro/Enterprise)",
    )
    p_evo.add_argument(
        "--free-runners",
        type=int,
        default=None,
        help="Requested number of $0 Free Co-Runners (locked to 1 on Free tier, up to 5 on Pro/Enterprise)",
    )
    p_evo.add_argument(
        "--paid-council",
        action="store_true",
        help="Include user-supplied BYOK Paid Frontier Council seats (requires Enterprise Complete Pro)",
    )

    # verify-ledger
    p_ver = sub.add_parser("verify-ledger", help="Run true-positive & zero-false-positive self-check across every scar in the ledger")
    p_ver.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")

    # hook
    p_hook = sub.add_parser("hook", help="Run as an inline coding-agent PreToolUse hook")
    p_hook.add_argument("kind", choices=["claude-pre-tool"], help="Hook protocol")
    p_hook.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_hook.add_argument("--block-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="HIGH")

    # install-hooks
    p_inst = sub.add_parser("install-hooks", help="Wire Kintsugi into .claude/settings.json and .git/hooks/pre-commit")
    p_inst.add_argument("--workspace", default=".", help="Target repository root")
    p_inst.add_argument("--git", action="store_true", help="Also install .git/hooks/pre-commit")

    # mcp
    p_mcp = sub.add_parser("mcp", help="Start Kintsugi stdio Model Context Protocol (MCP) server")
    p_mcp.add_argument("mcp_action", nargs="?", default="serve", help="Optional action (default: serve)")
    p_mcp.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")

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

    # swarm (Pillar 5 & 5B: Shadow-Clone Parallel Epistemic Swarm, BFT Synaptic Merge & Consent-Gated Free Agent Pool)
    p_swm = sub.add_parser(
        "swarm",
        help="Spawn K=4 orthogonal Shadow Clones in parallel, manage the Consent-Gated Free Agent Pool, and merge into 1 Verified Right Playbook",
    )
    p_swm.add_argument("target", nargs="?", default=".", help="Repository or file for the Shadow-Clone Swarm to explore")
    p_swm.add_argument("--workspace", default=".", help="Workspace root for .kintsugi state")
    p_swm.add_argument("--clones", type=int, default=4, help="Number of orthogonal Shadow Clones to spawn (default: 4)")
    p_swm.add_argument("--no-consolidate", action="store_true", help="Run swarm without writing newly distilled lessons to .kintsugi")
    p_swm.add_argument("--byzantine-test", action="store_true", help="Inject a Byzantine fault into 1 clone to verify K=3f+1 fault-tolerant consensus")
    p_swm.add_argument("--pool-status", action="store_true", help="Show Consent-Gated Free-Agent Pool status & Condorcet BFT accuracy metrics")
    p_swm.add_argument("--request-consent", action="store_true", help="Display structured User Consent Prompt for supplying keys or authorizing $0 auto-provisioning")
    p_swm.add_argument("--authorize-auto-provision", action="store_true", help="Grant explicit user consent for Kintsugi to autonomously provision $0 no-card free-tier endpoints")
    p_swm.add_argument("--register-deepseek-free", action="store_true", help="Autonomously register a disposable mail.tm inbox, verify magic link, mint a live $0 DeepSeek Free API key (262K context), verify HTTP 200 OK chat completion, and save to .kintsugi/free_agent_pool.json")
    p_swm.add_argument("--deepseek-count", type=int, default=1, help="Number of independent DeepSeek Free accounts/tokens to auto-register (1..5, default: 1)")
    p_swm.add_argument("--scope", default="", help="Optional comma-separated provider_ids for --authorize-auto-provision")
    p_swm.add_argument("--add-free-key", nargs=2, metavar=("PROVIDER_ID", "API_KEY"), help="Supply a user-provided $0 free-tier API key (e.g. groq_free gsk_...)")
    p_swm.add_argument("--revoke-consent", action="store_true", help="Immediately revoke auto-provisioning consent and purge stored keys in .kintsugi/free_agent_pool.json")
    p_swm.add_argument("--red-blue-arena", action="store_true", help="Run v1.3.0 2-Team Adversarial Arena (Red Team Attack vs Blue Team Defense across 6 High-Reasoning Council campaigns)")
    p_swm.add_argument("--evolution-proof", action="store_true", help="Run 5-Wave Closed-Loop Self-Learning & Self-Healing Proof (Epoch 0 Breach -> Scar Synthesis -> Autofix -> Epoch 5 Unseen Variant Immunity)")
    p_swm.add_argument("--forage-internet", action="store_true", help="Release DeepSeek Free + Gemini 3.8B pair onto the controlled internet sandbox (OSV.dev, GitHub Advisories, ArXiv) and run the 3.8B-vs-Opus-5.5 Evolution Gauntlet")
    p_swm.add_argument("--provider-benchmarks", action="store_true", help="Run the 8-Facet Official AI Provider Benchmark Suite (SWE-bench Verified, LiveCodeBench, GPQA Diamond, AIME/MATH-500, CyberSecEval 3, TAU-bench/BFCL, SimpleQA/FACTS, IFEval)")
    p_swm.add_argument("--co-run", action="store_true", help="Execute Tier-Gated Multi-Model Co-Execution (Primary Model + 1..5 Free Models + optional BYOK Paid Council)")
    p_swm.add_argument("--free-runners", type=int, default=None, help="Requested number of $0 Free Co-Runners (locked to 1 on Free tier, up to 5 on Pro/Enterprise)")
    p_swm.add_argument("--paid-council", action="store_true", help="Include user-supplied BYOK Paid Frontier Council seats (requires Enterprise Complete Pro)")
    p_swm.add_argument("--add-paid-key", nargs=2, metavar=("PROVIDER_ID", "API_KEY"), help="Add user-owned BYOK API key for the Paid Frontier Council (e.g. anthropic_opus <YOUR_API_KEY>)")
    p_swm.add_argument("--remove-paid-key", metavar="PROVIDER_ID", default=None, help="Remove a stored Paid Frontier Council BYOK API key")
    p_swm.add_argument("--paid-council-status", action="store_true", help="Show Paid Frontier Council BYOK status and supported seats")
    p_swm.add_argument("--guide", action="store_true", help="Display the Bilingual Agent Onboarding & Tier-Upgrade Guide (Free vs Pro Multi-Free vs Enterprise Paid Council)")
    p_swm.add_argument("--ask", metavar="QUESTION", default=None, help="Answer any user question in Vietnamese/English about Multi-Model Co-Execution, BYOK Paid Council keys, or Edition Tiers")
    p_swm.add_argument("--wire", action="store_true", help="Output compact <45-token @SWARM/1 + @POOL/1 wire headers")

    p_gde = sub.add_parser("guide", help="Interactive User Onboarding & Q&A Guide (answers user questions about Multi-Model, Free Models, and BYOK Paid Council)")
    p_gde.add_argument("question", nargs="*", help="Optional natural-language question from the user (e.g. 'làm sao thêm key hội đồng thu phí?')")
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
    p_log.add_argument("--arena", action="store_true", help="Run the 5-Round Adversarial Logic & Login Arena: (Gemini-3.8B + GPT-6-Luna + Kintsugi @LOGIC/2) vs Raw Free Agent Council")
    p_log.add_argument("--forage-github-harnesses", action="store_true", help="Release Gemini-3.8B + Grok 4.7 to study high-star GitHub agent harnesses (Claude Code, DeepSeek R1, OpenHands, Aider, Cline)")
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

    return parser


def _load_or_seed_ledger(ledger_path: str | Path, workspace_root: str | Path = ".") -> ScarLedger:
    ledger = ScarLedger(ledger_path)
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
        ledger = _load_or_seed_ledger(args.ledger)
        scars = ledger.all()
        verbose_md = SkillCompiler(scars).render_skill_markdown(
            "kintsugi-guardrails",
            "Verbose baseline comparison",
            scars,
        )
        stats = compute_token_savings_report(scars, verbose_md, turns_per_session=args.turns)
        if args.format == "json":
            print(json.dumps(stats, indent=2, ensure_ascii=False))
        else:
            print(
                f"=== Kintsugi KMI/1 Token-Compression Benchmark ({stats['rules_compiled']} active scars) ===\n"
                f"• Verbose Markdown Context : ~{stats['verbose_tokens_per_turn']} tokens/turn\n"
                f"• Kintsugi KMI/1 Wire Index: ~{stats['kmi_tokens_per_turn']} tokens/turn\n"
                f"• Per-Turn Token Reduction : {stats['reduction_percent']}% ({stats['tokens_saved_per_turn']} tokens saved/turn)\n"
                f"• {stats['turns_per_session']}-Turn Session Savings  : ~{stats['tokens_saved_per_session']:,} tokens\n\n"
                f"{stats['kmi_preview']}"
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

            scars_to_compile = get_starter_scars()
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
        ledger = _load_or_seed_ledger(args.ledger, args.workspace)
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
        payload = json.loads(raw_stdin) if raw_stdin else {}
        decision = evaluate_claude_pre_tool_payload(
            payload,
            ledger.all(),
            block_threshold=Severity(args.block_on),
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
        server = KintsugiMCPServer(args.ledger)
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
        if args.provider_benchmarks:
            pb_rep = AIProviderBenchmarkSuite().run_all_provider_benchmarks(fetch_live_network=True)
            print(json.dumps(pb_rep, indent=2, ensure_ascii=False))
            return 0 if pb_rep["all_8_harnesses_executed_and_verified"] else 1
        if args.forage_internet:
            fg_rep = ControlledInternetForager().forage_and_evolve_3b8_vs_opus(fetch_live_network=True)
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
        pool_mgr = ConsentGatedFreePoolManager(args.workspace)
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
        if args.register_deepseek_free:
            res = pool_mgr.auto_register_deepseek_free(
                confirmed_by_user=True,
                count=int(args.deepseek_count or 1),
                verify_chat=True,
            )
            print(json.dumps(res, indent=2, ensure_ascii=False))
            return 0 if res.get("ok") else 1
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
            forage_github_star_harnesses_with_gemini_grok,
            run_gemini38_luna_vs_free_council_logic_arena,
            run_logical_reasoning_benchmark,
        )

        if getattr(args, "login_verify", False):
            rep = LoginAuthLogicVerifier().verify_login_security_suite()
        elif getattr(args, "arena", False):
            rep = run_gemini38_luna_vs_free_council_logic_arena()
        elif getattr(args, "forage_github_harnesses", False):
            rep = forage_github_star_harnesses_with_gemini_grok(live_github_probe=True)
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
