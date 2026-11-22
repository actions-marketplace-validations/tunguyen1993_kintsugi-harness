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
from kintsugi.composition.smt_plan_verifier import (
    FormalVerificationBundle,
    SMTProofCertificate,
    is_z3_available,
    prove_acyclic_and_total_order,
    prove_effect_idempotency,
    prove_no_secret_escalation,
    prove_permission_monotonicity,
    verify_bundle_digest,
    verify_certificate_digest,
    verify_plan_formal,
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
    "FormalVerificationBundle",
    "MissingAdapterGap",
    "SMTProofCertificate",
    "ToolComposer",
    "extract_tool_effect_contract",
    "is_z3_available",
    "parallel_execution_groups",
    "prove_acyclic_and_total_order",
    "prove_effect_idempotency",
    "prove_no_secret_escalation",
    "prove_permission_monotonicity",
    "verify_bundle_digest",
    "verify_certificate_digest",
    "verify_plan_formal",
]
