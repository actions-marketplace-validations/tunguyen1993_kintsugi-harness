"""
Deterministic Auto-Remediation Engine (`kintsugi autofix`).

Open-Core Architecture:
- Community Open-Source Edition: Runs in safe Dry-Run Patch Preview mode (`--dry-run`).
- Premium Pack Edition (`kintsugi install-pack <bundle.zip>`): Unlocks automated
  in-place AST/Regex codemod rewrites (`--apply`) via `autofix_playbooks`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Sequence

from kintsugi.models import GoldenScar, Severity
from kintsugi.packs import load_installed_autofix_playbooks
from kintsugi.scanner import KintsugiScanner, render_patch_preview


def run_autofix(
    target: str | Path,
    scars: Sequence[GoldenScar],
    *,
    workspace_root: str | Path = ".",
    apply_changes: bool = False,
) -> Dict[str, Any]:
    scanner = KintsugiScanner(scars, min_severity=Severity.LOW)
    report = scanner.scan_path(target)
    playbooks = load_installed_autofix_playbooks(workspace_root)
    playbook_by_id = {pb.get("scar_id"): pb for pb in playbooks if pb.get("scar_id")}

    previews: List[Dict[str, Any]] = []
    applied_count = 0

    for finding in report.findings:
        pb = playbook_by_id.get(finding.scar_id)
        preview_diff = render_patch_preview(finding)
        status = "preview_only"

        if apply_changes and pb:
            fpath = Path(finding.file_path)
            if fpath.is_file():
                lines = fpath.read_text(encoding="utf-8").splitlines(keepends=True)
                idx = finding.line - 1
                if 0 <= idx < len(lines):
                    orig_line = lines[idx]
                    pattern = pb.get("search_regex")
                    replacement = pb.get("replace_expr")
                    if pattern and replacement is not None:
                        new_line, count = re.subn(pattern, replacement, orig_line)
                        if count > 0 and new_line != orig_line:
                            lines[idx] = new_line
                            fpath.write_text("".join(lines), encoding="utf-8")
                            status = "applied"
                            applied_count += 1

        previews.append(
            {
                "scar_id": finding.scar_id,
                "file_path": finding.file_path,
                "line": finding.line,
                "status": status,
                "has_premium_codemod": bool(pb),
                "patch_preview": preview_diff,
            }
        )

    return {
        "scanned_files": report.scanned_files,
        "findings_count": len(report.findings),
        "premium_playbooks_loaded": len(playbook_by_id),
        "applied_fixes": applied_count,
        "mode": "apply" if apply_changes else "dry-run",
        "items": previews,
    }
