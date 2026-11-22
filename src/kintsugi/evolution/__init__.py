"""Stage 5 Verified Self-Evolution v3 & Tier-3 Strategy Memory exports (`kintsugi.evolution`)."""

from __future__ import annotations

from kintsugi.evolution.evolution_v3 import (
    EVOLUTION_STAGES,
    EVOLUTION_V3_SCHEMA,
    IMMUTABLE_BASELINE_IDS,
    IMMUTABLE_HOOK_TARGETS,
    PROTECTED_BASELINE_IDS,
    BlindTransferReport,
    CanarySoakReport,
    CauseLocalization,
    EvolutionCandidateResult,
    SelfEvolutionEngineV3,
    UnseenFailure,
    honest_metric_summary,
)
from kintsugi.evolution.strategy_memory import (
    DEFAULT_STRATEGY_MEMORY_REL_PATH,
    STRATEGY_MEMORY_SCHEMA,
    STRATEGY_RECORD_SCHEMA,
    StrategyMemory,
    StrategyRecord,
    compute_wilson_interval,
)

__all__ = [
    "DEFAULT_STRATEGY_MEMORY_REL_PATH",
    "EVOLUTION_STAGES",
    "EVOLUTION_V3_SCHEMA",
    "IMMUTABLE_BASELINE_IDS",
    "IMMUTABLE_HOOK_TARGETS",
    "PROTECTED_BASELINE_IDS",
    "STRATEGY_MEMORY_SCHEMA",
    "STRATEGY_RECORD_SCHEMA",
    "BlindTransferReport",
    "CanarySoakReport",
    "CauseLocalization",
    "EvolutionCandidateResult",
    "SelfEvolutionEngineV3",
    "StrategyMemory",
    "StrategyRecord",
    "UnseenFailure",
    "compute_wilson_interval",
    "honest_metric_summary",
]
