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
from kintsugi.compiler import SkillCompiler
from kintsugi.compressor import compute_token_savings_report, render_kmi_index
from kintsugi.council import EvolutionCouncil, verify_candidate_scar
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

    return 0
