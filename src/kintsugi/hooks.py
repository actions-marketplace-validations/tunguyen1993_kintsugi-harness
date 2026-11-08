"""Claude Code PreToolUse Hook handler and `.claude/settings.json` / git pre-commit installer."""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Sequence

from kintsugi.models import GoldenScar, ScanFinding, Severity
from kintsugi.scanner import KintsugiScanner
from kintsugi.shield import assert_not_symlink, atomic_write_text, normalize_shell_command

HEX_OCTAL_MAPPED_IP_RE = re.compile(
    r"\b0x[0-9a-fA-F]{4,}\b|::ffff:|\b0\d{2,3}\.\d+",
    re.IGNORECASE,
)
NETWORK_VERB_RE = re.compile(
    r"\b(?:ssh|scp|sftp|sshpass|rsync|curl|wget)\b",
    re.IGNORECASE,
)


def evaluate_claude_pre_tool_payload(
    payload: Dict[str, Any],
    scars: Sequence[GoldenScar],
    *,
    block_threshold: Severity = Severity.HIGH,
) -> Dict[str, Any]:
    """
    Evaluate a Claude Code or Antigravity `PreToolUse` JSON event in-memory (< 15ms)
    with Grade S3 NFKC/Bidi/quote-splitting normalization and Hex/Octal IP blocking.
    """
    if not isinstance(payload, dict):
        return {
            "decision": "deny",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "FAIL-CLOSED HOOK GUARD: Payload must be a JSON object.",
            },
        }

    tool_call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
    tool_name = str(payload.get("tool_name") or tool_call.get("name") or "")
    tool_input = payload.get("tool_input") or tool_call.get("args") or {}
    if not isinstance(tool_input, dict):
        return {
            "decision": "deny",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "FAIL-CLOSED HOOK GUARD: tool_input must be a JSON object.",
            },
        }

    if not tool_name and ("CommandLine" in tool_input or "command" in tool_input):
        tool_name = "run_command"

    scanner = KintsugiScanner(scars)
    findings: List[ScanFinding] = []

    if tool_name in {"Write", "CreateFile", "write_file"}:
        fpath = str(tool_input.get("file_path") or tool_input.get("path") or "<write>")
        content = str(tool_input.get("content") or "")
        findings.extend(scanner.scan_text(content, file_path=fpath))

    elif tool_name in {"Edit", "Replace", "edit_file"}:
        fpath = str(tool_input.get("file_path") or tool_input.get("path") or "<edit>")
        new_str = str(tool_input.get("new_string") or tool_input.get("replacement") or "")
        findings.extend(scanner.scan_text(new_str, file_path=fpath))

    elif tool_name == "MultiEdit":
        fpath = str(tool_input.get("file_path") or "<multiedit>")
        edits = tool_input.get("edits") or []
        if isinstance(edits, list):
            combined = "\n".join(
                str(ed.get("new_string") or "") for ed in edits if isinstance(ed, dict)
            )
            findings.extend(scanner.scan_text(combined, file_path=fpath))

    elif tool_name in {"Bash", "run_command"}:
        raw_cmd = str(tool_input.get("command") or tool_input.get("CommandLine") or "")
        cmd = normalize_shell_command(raw_cmd)
        if NETWORK_VERB_RE.search(cmd) and HEX_OCTAL_MAPPED_IP_RE.search(cmd):
            findings.append(
                ScanFinding(
                    scar_id="KS-S3-IP-OBFUSCATION",
                    title="Obfuscated Hex/Octal/IPv6-Mapped IP in Network Command",
                    severity=Severity.CRITICAL,
                    category="security",
                    file_path="<bash>",
                    line=1,
                    column=1,
                    snippet=cmd[:140],
                    rationale="Hex (0x...), octal (0177...), or IPv6-mapped (::ffff:) IP notation used to bypass host/SSRF allowlists. Use canonical dotted-decimal IPv4 or verified domain names only.",
                    good_code_hint="ssh user@192.0.2.10",
                    engine="s3-hook-guard",
                )
            )
        findings.extend(scanner.scan_text(cmd, file_path="<bash>", language="shell"))

    blocking = [f for f in findings if f.severity.meets(block_threshold)]
    if not blocking:
        # Leave permissionDecision unset on clean calls so Claude Code's normal
        # user permission prompt remains intact (never auto-approve clean tool calls).
        return {
            "continue": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
            },
        }

    reason_lines = [
        f"Kintsugi PreToolUse Guard blocked {len(blocking)} violation(s):"
    ]
    for f in blocking[:3]:
        reason_lines.append(
            f"- [{f.scar_id} / {f.severity.value}] {f.title} (line {f.line}): `{f.snippet}`\n"
            f"  Why: {f.rationale}\n"
            f"  Verified Fix:\n  {f.good_code_hint}"
        )

    return {
        "decision": "deny",
        "reason": "\n".join(reason_lines),
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "\n".join(reason_lines),
        },
    }


def install_claude_settings_hook(workspace_root: str | Path) -> Path:
    """Register `kintsugi hook claude-pre-tool` inside `.claude/settings.json` idempotently."""
    root = Path(workspace_root)
    settings_path = root / ".claude" / "settings.json"
    assert_not_symlink(settings_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    data: Dict[str, Any] = {}
    if settings_path.exists():
        raw_settings = settings_path.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw_settings)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Refusing to overwrite malformed .claude/settings.json ({settings_path}): {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ValueError(
                f"Refusing to overwrite non-object .claude/settings.json ({settings_path})"
            )
        # Write a .bak backup before modifying existing settings.json
        backup_path = settings_path.with_suffix(".json.bak")
        atomic_write_text(backup_path, raw_settings, mode=0o600)
        data = parsed

    hooks_obj = data.setdefault("hooks", {})
    pre_tool_list = hooks_obj.setdefault("PreToolUse", [])
    hook_cmd = "kintsugi hook claude-pre-tool"

    already_installed = any(
        isinstance(entry, dict)
        and any(
            isinstance(h, dict) and hook_cmd in str(h.get("command", ""))
            for h in (entry.get("hooks") or [])
        )
        for entry in pre_tool_list
    )
    if not already_installed:
        pre_tool_list.append(
            {
                "matcher": "Write|Edit|MultiEdit|Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": hook_cmd,
                    }
                ],
            }
        )

    atomic_write_text(settings_path, json.dumps(data, indent=2) + "\n", mode=0o600)
    return settings_path


def _resolve_git_hooks_dir(workspace_root: Path) -> Path:
    """Resolve Git's active hooks directory (honoring `core.hooksPath` and linked worktrees)."""
    import subprocess

    proc = subprocess.run(
        ["git", "-C", str(workspace_root), "rev-parse", "--git-path", "hooks"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        candidate = Path(proc.stdout.strip())
        if candidate.is_absolute():
            return candidate
        return (workspace_root / candidate).resolve()
    return workspace_root / ".git" / "hooks"


def install_git_pre_commit_hook(workspace_root: str | Path) -> Path:
    """
    Install a lightweight git pre-commit hook running index-safe
    `kintsugi scan . --ledger .kintsugi/scars.json --staged --fail-on HIGH`,
    honoring `git rev-parse --git-path hooks` and preserving/chaining any existing hook.
    """
    root = Path(workspace_root)
    hooks_dir = _resolve_git_hooks_dir(root)
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    backup_hook = hooks_dir / "pre-commit.pre-kintsugi"

    if hook_path.exists():
        existing_text = hook_path.read_text(encoding="utf-8", errors="replace")
        if "# Managed by kintsugi-harness" not in existing_text:
            backup_hook.write_text(existing_text, encoding="utf-8")
            backup_mode = hook_path.stat().st_mode
            backup_hook.chmod(backup_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    script = (
        "#!/usr/bin/env sh\n"
        "# Managed by kintsugi-harness\n"
        "set -e\n"
        'HOOK_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\n'
        'if [ -x "$HOOK_DIR/pre-commit.pre-kintsugi" ]; then\n'
        '  "$HOOK_DIR/pre-commit.pre-kintsugi" "$@"\n'
        "fi\n"
        "kintsugi scan . --ledger .kintsugi/scars.json --staged --fail-on HIGH\n"
    )
    hook_path.write_text(script, encoding="utf-8")
    mode = hook_path.stat().st_mode
    hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path
