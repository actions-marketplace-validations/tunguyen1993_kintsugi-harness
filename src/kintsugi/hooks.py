"""Claude Code PreToolUse Hook handler and `.claude/settings.json` / git pre-commit installer."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, Dict, List, Sequence

from kintsugi.models import GoldenScar, ScanFinding, Severity
from kintsugi.scanner import KintsugiScanner


def evaluate_claude_pre_tool_payload(
    payload: Dict[str, Any],
    scars: Sequence[GoldenScar],
    *,
    block_threshold: Severity = Severity.HIGH,
) -> Dict[str, Any]:
    """
    Evaluate a Claude Code `PreToolUse` JSON event in-memory (< 15ms) and return
    a compliant hook decision dictionary.
    """
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return {"continue": True}

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
        cmd = str(tool_input.get("command") or tool_input.get("CommandLine") or "")
        findings.extend(scanner.scan_text(cmd, file_path="<bash>", language="shell"))

    blocking = [f for f in findings if f.severity.meets(block_threshold)]
    if not blocking:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
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
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "\n".join(reason_lines),
        }
    }


def install_claude_settings_hook(workspace_root: str | Path) -> Path:
    """Register `kintsugi hook claude-pre-tool` inside `.claude/settings.json` idempotently."""
    root = Path(workspace_root)
    settings_path = root / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    data: Dict[str, Any] = {}
    if settings_path.exists():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}

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

    settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return settings_path


def install_git_pre_commit_hook(workspace_root: str | Path) -> Path:
    """Install a lightweight git pre-commit hook running `kintsugi scan . --fail-on HIGH`."""
    root = Path(workspace_root)
    hook_path = root / ".git" / "hooks" / "pre-commit"
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "#!/usr/bin/env sh\n"
        "# Managed by kintsugi-harness\n"
        "set -e\n"
        "kintsugi scan . --fail-on HIGH\n"
    )
    hook_path.write_text(script, encoding="utf-8")
    mode = hook_path.stat().st_mode
    hook_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path
