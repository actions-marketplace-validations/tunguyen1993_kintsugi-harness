"""Core domain models for Kintsugi Harness."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Rule severity ordered by enforcement priority."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }[self]

    @property
    def sarif_level(self) -> str:
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
        }[self]

    def meets(self, threshold: "Severity") -> bool:
        return self.rank >= threshold.rank


@dataclass
class FailureTrace:
    """Structured representation of a runtime, CI, test, or tool-call failure."""

    source: str
    error_summary: str
    raw_trace: str
    file_path: Optional[str] = None
    language: str = "python"
    offending_snippet: str = ""
    fixed_snippet: str = ""
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@dataclass
class GoldenScar:
    """
    Atomic unit of evolved agent memory: pairs a concrete anti-pattern with its
    verified fix and an executable AST or Regex guardrail.
    """

    id: str
    title: str
    severity: Severity
    category: str
    languages: List[str]
    tags: List[str]
    root_cause: str
    bad_code: str
    good_code: str
    rationale: str
    regex_pattern: Optional[str] = None
    ast_rule: Optional[str] = None
    verified_by: List[str] = field(default_factory=list)
    hits: int = 0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())

    @property
    def fingerprint(self) -> str:
        basis = f"{self.category}|{self.ast_rule or ''}|{self.regex_pattern or ''}|{self.title.lower().strip()}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        payload["fingerprint"] = self.fingerprint
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GoldenScar":
        clean = {k: v for k, v in data.items() if k != "fingerprint"}
        clean["severity"] = Severity(str(clean["severity"]).upper())
        return cls(**clean)


@dataclass
class ScanFinding:
    """Single deterministic rule match inside a scanned file or tool buffer."""

    scar_id: str
    title: str
    severity: Severity
    category: str
    file_path: str
    line: int
    column: int
    engine: str
    snippet: str
    rationale: str
    good_code_hint: str

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["severity"] = self.severity.value
        return out


@dataclass
class ScanReport:
    """Aggregated deterministic scan output across files or snippets."""

    scanned_files: int
    active_scars: int
    findings: List[ScanFinding] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def has_blocking_findings(self, threshold: Severity = Severity.HIGH) -> bool:
        return any(f.severity.meets(threshold) for f in self.findings)

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned_files": self.scanned_files,
            "active_scars": self.active_scars,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "counts": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
