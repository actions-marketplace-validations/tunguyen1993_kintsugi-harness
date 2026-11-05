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
from kintsugi.compiler import SkillCompiler
from kintsugi.compressor import compute_token_savings_report, render_kmi_index
from kintsugi.council import EvolutionCouncil, verify_candidate_scar
from kintsugi.foresight import (
    AnalogicalTransferEngine,
    AutopoieticSynthesizer,
    CausalForesightEngine,
    CounterfactualDreamSimulator,
    MetacognitiveSelfModel,
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
from kintsugi.swarm import ConsentGatedFreePoolManager, ShadowCloneSwarmOrchestrator


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
    p_ipack = sub.add_parser("install-pack", help="Install an external or Premium Skill Pack (.zip or .json) into .kintsugi/packs/")
    p_ipack.add_argument("pack_path", help="Path to Skill Pack .zip or .json bundle")
    p_ipack.add_argument("--workspace", default=".", help="Target workspace root")
    p_ipack.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")

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
    p_comp.add_argument("--compact", action="store_true", help="Emit ultra-low-token KMI/1 wire index (>93% token savings)")
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
    p_evo.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_evo.add_argument("--summary", required=True, help="One-line failure summary")
    p_evo.add_argument("--from-log", default=None, help="Path to traceback/CI log file")
    p_evo.add_argument("--language", default="python", help="Target language")
    p_evo.add_argument("--bad-code", default="", help="Offending code snippet")
    p_evo.add_argument("--good-code", default="", help="Verified replacement snippet")
    p_evo.add_argument("--compile-workspace", default=None, help="Auto-recompile skills in workspace after evolving")

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
    p_swm.add_argument("--scope", default="", help="Optional comma-separated provider_ids for --authorize-auto-provision")
    p_swm.add_argument("--add-free-key", nargs=2, metavar=("PROVIDER_ID", "API_KEY"), help="Supply a user-provided $0 free-tier API key (e.g. groq_free gsk_...)")
    p_swm.add_argument("--revoke-consent", action="store_true", help="Immediately revoke auto-provisioning consent and purge stored keys in .kintsugi/free_agent_pool.json")
    p_swm.add_argument("--wire", action="store_true", help="Output compact <45-token @SWARM/1 + @POOL/1 wire headers")

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
        ledger = _load_or_seed_ledger(args.ledger, args.workspace)
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        written = SkillCompiler(ledger.all(), compact_kmi=bool(args.compact)).compile_all(
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
        ledger = _load_or_seed_ledger(args.ledger)
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
        council = EvolutionCouncil()
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
        pool_mgr = ConsentGatedFreePoolManager(args.workspace)
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
