"""
Repository Security & Agent Readiness Posture Auditor (`kintsugi audit`).

Computes a deterministic 0-100 posture score (`Grade A+` to `F`), token-compression
efficiency metrics (`KMI/1`), and generates Markdown scorecards + Shields.io badges.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Sequence, Tuple
from urllib.parse import quote

from kintsugi.compressor import compute_token_savings_report
from kintsugi.models import GoldenScar, Severity
from kintsugi.packs import list_installed_packs
from kintsugi.scanner import KintsugiScanner


def _score_to_grade(score: int) -> Tuple[str, str]:
    if score >= 97:
        return "A+", "brightgreen"
    if score >= 90:
        return "A", "green"
    if score >= 80:
        return "B", "yellowgreen"
    if score >= 70:
        return "C", "yellow"
    if score >= 60:
        return "D", "orange"
    return "F", "red"


def run_posture_audit(
    target_root: str | Path,
    scars: Sequence[GoldenScar],
) -> Dict[str, Any]:
    root = Path(target_root).resolve()
    scanner = KintsugiScanner(scars, min_severity=Severity.LOW)
    report = scanner.scan_path(root)
    counts = report.counts_by_severity()

    # 1. Codebase violation score (max 55)
    penalty = (
        counts.get("CRITICAL", 0) * 15
        + counts.get("HIGH", 0) * 8
        + counts.get("MEDIUM", 0) * 3
        + counts.get("LOW", 0) * 1
    )
    code_score = max(0, 55 - penalty)

    # 2. Multi-agent governance coverage (max 25)
    governance_files = {
        "claude_md": (root / "CLAUDE.md").exists(),
        "agents_md": (root / "AGENTS.md").exists(),
        "claude_skills": (root / ".claude" / "skills").exists(),
        "cursor_rules": (root / ".cursor" / "rules").exists(),
        "copilot_instructions": (root / ".github" / "instructions").exists(),
        "windsurf_rules": (root / ".windsurfrules").exists(),
    }
    present_count = sum(1 for v in governance_files.values() if v)
    gov_score = min(25, int(round((present_count / len(governance_files)) * 25)))

    # 3. Token efficiency & ledger density (max 20)
    token_stats = compute_token_savings_report(scars, "")
    token_score = 20 if token_stats["reduction_percent"] >= 85.0 and len(scars) >= 12 else 12

    total_score = min(100, code_score + gov_score + token_score)
    grade, color = _score_to_grade(total_score)
    badge_label = quote(f"{grade} ({total_score}/100)")
    badge_url = f"https://img.shields.io/badge/kintsugi_posture-{badge_label}-{color}"

    return {
        "workspace": str(root),
        "score": total_score,
        "grade": grade,
        "badge_url": badge_url,
        "badge_markdown": f"[![Kintsugi Posture: {grade}]({badge_url})](https://github.com/tunguyen1993/kintsugi-harness)",
        "scanned_files": report.scanned_files,
        "active_scars": len(scars),
        "elapsed_ms": round(report.elapsed_ms, 2),
        "findings_by_severity": counts,
        "governance_coverage": governance_files,
        "token_efficiency": {
            "kmi_tokens_per_turn": token_stats["kmi_tokens_per_turn"],
            "verbose_tokens_per_turn": token_stats["verbose_tokens_per_turn"],
            "reduction_percent": token_stats["reduction_percent"],
            "tokens_saved_50_turns": token_stats["tokens_saved_per_session"],
        },
        "installed_packs": list_installed_packs(root),
    }


def render_audit_markdown(audit: Dict[str, Any]) -> str:
    te = audit["token_efficiency"]
    counts = audit["findings_by_severity"]
    cov = audit["governance_coverage"]
    cov_str = ", ".join(k for k, v in cov.items() if v) or "none"

    lines = [
        f"# Kintsugi Security & Agent Readiness Scorecard — Grade `{audit['grade']}` (`{audit['score']}/100`)",
        "",
        audit["badge_markdown"],
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Posture Score & Grade** | **`{audit['score']}/100` (`{audit['grade']}`)** |",
        f"| **Files Scanned** | `{audit['scanned_files']}` files in `{audit['elapsed_ms']}ms` |",
        f"| **Active Verified Scars** | `{audit['active_scars']}` rules |",
        f"| **Violations (`CRIT` / `HIGH` / `MED` / `LOW`)** | `{counts['CRITICAL']}` / `{counts['HIGH']}` / `{counts['MEDIUM']}` / `{counts['LOW']}` |",
        f"| **Active IDE/Agent Targets** | `{cov_str}` |",
        f"| **`KMI/1` Per-Turn Context Cost** | **`~{te['kmi_tokens_per_turn']} tokens`** (vs `~{te['verbose_tokens_per_turn']}` verbose — **`{te['reduction_percent']}%` saved**) |",
        f"| **Tokens Saved per 50-Turn Session** | **`~{te['tokens_saved_50_turns']:,} tokens`** |",
    ]
    return "\n".join(lines)
