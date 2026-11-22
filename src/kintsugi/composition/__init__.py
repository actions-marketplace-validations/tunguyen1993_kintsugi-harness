"""Stage 2 LEGO Tool Synthesis & Composition exports (`kintsugi.composition`)."""

from __future__ import annotations

from kintsugi.composition.adapter_synthesizer import (
    AdapterCatalog,
    AdapterOracleReport,
    AdapterOracleVerifier,
    AdapterProposalResult,
    AdapterProposalStatus,
    AdapterSynthesizer,
)
from kintsugi.composition.composition_memory import (
    CompositionMemory,
    CompositionProvenance,
)
from kintsugi.composition.composition_verifier import (
    CompositionVerificationResult,
    CompositionVerifier,
    parallel_execution_groups,
)
from kintsugi.composition.tool_composer import (
    CompositionPlanResult,
    MissingAdapterGap,
    ToolComposer,
    extract_tool_effect_contract,
)

__all__ = [
    "AdapterCatalog",
    "AdapterOracleReport",
    "AdapterOracleVerifier",
    "AdapterProposalResult",
    "AdapterProposalStatus",
    "AdapterSynthesizer",
    "CompositionMemory",
    "CompositionPlanResult",
    "CompositionProvenance",
    "CompositionVerificationResult",
    "CompositionVerifier",
    "MissingAdapterGap",
    "ToolComposer",
    "extract_tool_effect_contract",
    "parallel_execution_groups",
]
