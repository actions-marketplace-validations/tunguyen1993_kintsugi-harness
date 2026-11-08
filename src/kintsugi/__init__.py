"""Kintsugi Harness — Self-evolving failure-to-skill, Rust/Python PreToolUse guardrail engine, and KMI/1 token compressor."""

__version__ = "2.0.0"

from kintsugi.auditor import render_audit_markdown, run_posture_audit
from kintsugi.shield import (
    ZeroTrustSameOriginRedirectHandler,
    assert_not_symlink,
    atomic_write_json,
    atomic_write_text,
    is_public_non_ssrf_host,
    is_strictly_zero_bond,
    locked_cortex_transaction,
    normalize_shell_command,
    sanitize_external_untrusted_text,
)
from kintsugi.autofix import run_autofix
from kintsugi.cinema import (
    SUPPORTED_VIDEO_PROVIDERS,
    CinemaEvolutionEngine,
    CinemaScar,
    ComponentVideoQAVerifier,
    MultiProviderVideoRouter,
    OpenMontagePackageManager,
    VisualStyleOptimizer,
    build_demo_flawed_openmontage_manifest,
)
from kintsugi.integrator import (
    ExactSemiringDifferenceSolver,
    HarnessIR,
    ImportedRuleIR,
    JointSATDifferenceVerifier,
    NumericBoundIR,
    UniversalHarnessIntegrator,
)
from kintsugi.cognition import (
    CognitiveLesson,
    CognitiveMemoryManager,
    ModelTier,
    SyncMode,
    classify_model_provenance,
    compute_evolution_intelligence_report,
    compute_structural_class_signature,
    synthesize_recurrence_proposal,
    verify_frontier_sync_gate,
)
from kintsugi.compactor import (
    ConversationCompactor,
    DistilledContext,
    UserPersonaProfile,
    extract_and_update_user_persona,
    extract_core_context,
    parse_conversation_source,
    strip_conversation_noise,
)
from kintsugi.logic import (
    AbductiveHittingSetDiagnoser,
    CNFClause,
    DatalogAtom,
    DatalogRule,
    DifferenceLogicSolver,
    DPLLSatSolver,
    FormalFallacyAndCoTAuditor,
    LoginAuthLogicVerifier,
    StratifiedDatalogEngine,
    forage_github_star_harnesses_with_gemini_grok,
    run_gemini38_luna_vs_free_council_logic_arena,
    run_logical_reasoning_benchmark,
)
from kintsugi.compliance import (
    EvalBenchmarkCase,
    ReproducibleEvalSuite,
    SignedComplianceProofExporter,
    ZeroKnowledgeASTDiffVerifier,
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
    answer_user_multi_model_question,
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
    harvest_deepseek_free_api_key,
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
    "harvest_deepseek_free_api_key",
    "build_multi_model_agent_guide",
    "answer_user_multi_model_question",
    "resolve_workspace_co_execution_entitlement",
    "ConversationCompactor",
    "parse_conversation_source",
    "strip_conversation_noise",
    "extract_core_context",
    "SUPPORTED_VIDEO_PROVIDERS",
    "CinemaEvolutionEngine",
    "CinemaScar",
    "ComponentVideoQAVerifier",
    "MultiProviderVideoRouter",
    "OpenMontagePackageManager",
    "VisualStyleOptimizer",
    "build_demo_flawed_openmontage_manifest",
]
