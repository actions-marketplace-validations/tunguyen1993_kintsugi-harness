"""Kintsugi Harness — Self-evolving failure-to-skill, Rust/Python PreToolUse guardrail engine, and KMI/1 token compressor."""

__version__ = "0.5.0"

from kintsugi.auditor import render_audit_markdown, run_posture_audit
from kintsugi.autofix import run_autofix
from kintsugi.cognition import (
    CognitiveLesson,
    CognitiveMemoryManager,
    ModelTier,
    SyncMode,
    classify_model_provenance,
    verify_frontier_sync_gate,
)
from kintsugi.compiler import SkillCompiler
from kintsugi.compressor import compute_token_savings_report, render_jit_stub, render_kmi_index
from kintsugi.council import EvolutionCouncil
from kintsugi.ledger import ScarLedger
from kintsugi.models import FailureTrace, GoldenScar, ScanFinding, ScanReport, Severity
from kintsugi.packs import install_skill_pack, list_installed_packs
from kintsugi.scanner import KintsugiScanner

__all__ = [
    "__version__",
    "Severity",
    "FailureTrace",
    "GoldenScar",
    "ScanFinding",
    "ScanReport",
    "ScarLedger",
    "KintsugiScanner",
    "SkillCompiler",
    "EvolutionCouncil",
    "render_kmi_index",
    "render_jit_stub",
    "compute_token_savings_report",
    "run_posture_audit",
    "render_audit_markdown",
    "run_autofix",
    "install_skill_pack",
    "list_installed_packs",
]
