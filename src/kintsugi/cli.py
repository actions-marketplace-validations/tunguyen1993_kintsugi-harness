"""Command-line interface for Kintsugi Harness (`kintsugi`)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from kintsugi import __version__
from kintsugi.compiler import SkillCompiler
from kintsugi.council import EvolutionCouncil, verify_candidate_scar
from kintsugi.hooks import (
    evaluate_claude_pre_tool_payload,
    install_claude_settings_hook,
    install_git_pre_commit_hook,
)
from kintsugi.ledger import ScarLedger
from kintsugi.mcp_server import KintsugiMCPServer
from kintsugi.models import FailureTrace, Severity
from kintsugi.scanner import KintsugiScanner, report_to_sarif


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kintsugi",
        description="Kintsugi Harness — Turn coding agent failures into deterministic PreToolUse guardrails and portable SKILL.md skills.",
    )
    parser.add_argument("--version", action="version", version=f"kintsugi-harness {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Bootstrap .kintsugi/scars.json starter pack and compile skills")
    p_init.add_argument("--workspace", default=".", help="Target repository root")
    p_init.add_argument("--ledger", default=None, help="Custom path to scars.json")
    p_init.add_argument("--no-compile", action="store_true", help="Skip generating SKILL.md / CLAUDE.md")

    # scan
    p_scan = sub.add_parser("scan", help="Scan files or directories against verified Golden Scars")
    p_scan.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    p_scan.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
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

    # compile
    p_comp = sub.add_parser("compile", help="Compile Golden Scars into SKILL.md, CLAUDE.md, AGENTS.md, and Cursor rules")
    p_comp.add_argument("--workspace", default=".", help="Target repository root")
    p_comp.add_argument("--ledger", default=".kintsugi/scars.json", help="Path to scars.json")
    p_comp.add_argument(
        "--targets",
        default="skills,claude,agents,cursor",
        help="Comma-separated targets: skills,claude,agents,cursor",
    )

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


def _load_or_seed_ledger(ledger_path: str | Path) -> ScarLedger:
    ledger = ScarLedger(ledger_path)
    if not ledger.all():
        ledger.bootstrap_starter_pack()
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
            written = SkillCompiler(ledger.all()).compile_all(ws)
            for p in written:
                print(f"[kintsugi] Compiled -> {p}")
        return 0

    if args.command == "scan":
        ledger = _load_or_seed_ledger(args.ledger)
        scanner = KintsugiScanner(
            ledger.all(),
            min_severity=Severity(args.min_severity),
        )
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
            rendered = "\n".join(lines)

        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)

        if args.fail_on != "NONE" and report.has_blocking_findings(Severity(args.fail_on)):
            return 1
        return 0

    if args.command == "compile":
        ledger = _load_or_seed_ledger(args.ledger)
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        written = SkillCompiler(ledger.all()).compile_all(args.workspace, targets=targets)
        for p in written:
            print(f"[kintsugi] Compiled -> {p}")
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
                },
                indent=2,
            )
        )
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
