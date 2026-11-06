"""Kintsugi Harness — Self-evolving failure-to-skill, Rust/Python PreToolUse guardrail engine, and KMI/1 token compressor."""

__version__ = "1.3.0"

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
from kintsugi.council import (
    PAID_FRONTIER_COUNCIL_CATALOG,
    EvolutionCouncil,
    FreeCoRunnerPoolRegistry,
    FreePoolSlot,
    PaidFrontierCouncilBYOKRegistry,
    PrimaryPlusFreeCoExecutor,
    build_multi_model_agent_guide,
)
from kintsugi.foresight import (
    AnalogicalTransferEngine,
    AutopoieticSynthesizer,
    CausalDoCalculusVerifier,
    CausalForesightEngine,
    CounterfactualDreamSimulator,
    DisjointScarHoldoutVerifier,
    LakatosCEGISVerifier,
    MetacognitiveSelfModel,
    ScientificLiteratureVerifier,
)
from kintsugi.grounding import RepoAstGroundingEngine, SoundSymbolicPathSolver
from kintsugi.ledger import ScarLedger
from kintsugi.models import FailureTrace, GoldenScar, ScanFinding, ScanReport, Severity
from kintsugi.packs import (
    decrypt_pro_kpack_bytes,
    encrypt_pro_kpack_bytes,
    install_skill_pack,
    list_installed_packs,
    resolve_workspace_co_execution_entitlement,
)
from kintsugi.scanner import KintsugiScanner
from kintsugi.swarm import (
    FREE_ZERO_CARD_PROVIDER_CATALOG,
    AIProviderBenchmarkSuite,
    BrierMomentShrinkagePool,
    CloneEpisodicReport,
    ClonePropositionVote,
    ClosedLoopEvolutionArena,
    ConsentGatedFreePoolManager,
    ControlledInternetForager,
    PlaybookStep,
    RedBlueAdversarialArena,
    ShadowCloneSwarmOrchestrator,
    enforce_kl_high_001_promotion_guard,
)

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
    "FREE_ZERO_CARD_PROVIDER_CATALOG",
    "CloneEpisodicReport",
    "ClonePropositionVote",
    "ConsentGatedFreePoolManager",
    "PlaybookStep",
    "ShadowCloneSwarmOrchestrator",
    "SoundSymbolicPathSolver",
    "LakatosCEGISVerifier",
    "CausalDoCalculusVerifier",
    "BrierMomentShrinkagePool",
    "RedBlueAdversarialArena",
    "enforce_kl_high_001_promotion_guard",
]
