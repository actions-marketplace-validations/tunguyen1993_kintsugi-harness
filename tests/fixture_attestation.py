"""Explicit test-only HMAC attestation for verified fixture tools.

This never changes production ToolRegistry behavior. Tests exercising rejected
promotion MUST call ToolRegistry.register directly instead of this helper.
"""
from kintsugi.capability.contracts_v2 import AdapterSpec
from kintsugi.capability.schemas import (
    TrustStatus, compute_tool_spec_security_digest, sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority

TEST_VERIFIER_ID = "fixture-test-attestor"
TEST_VERIFIER_KEY = b"kintsugi-round3-test-fixture-signing-key-32bytes"


def make_fixture_authority() -> AttestationAuthority:
    return AttestationAuthority({TEST_VERIFIER_ID: TEST_VERIFIER_KEY})


def sign_fixture_spec(authority: AttestationAuthority, spec):
    if spec.trust_status == TrustStatus.VERIFIED:
        if not authority.has_verifier(TEST_VERIFIER_ID):
            authority.register_verifier(TEST_VERIFIER_ID, TEST_VERIFIER_KEY)
        old_att = spec.verification_attestation or {}
        verification_digest = old_att.get("verification_digest") or sha256_digest(spec.tool_id)
        spec.verification_attestation = authority.issue_attestation(
            spec.tool_id, spec.binary_hash, verification_digest,
            TEST_VERIFIER_ID, spec_digest=compute_tool_spec_security_digest(spec),
        )
    return spec


def sign_fixture_tool(registry, spec):
    sign_fixture_spec(registry.authority, spec)
    return registry.register(spec, trusted_attestor=True)


def sign_fixture_adapter(
    registry_or_authority,
    adapter: AdapterSpec,
    *,
    callable_hash: str = "",
) -> AdapterSpec:
    auth = getattr(registry_or_authority, "authority", registry_or_authority)
    if adapter.trust_status == TrustStatus.VERIFIED:
        if not auth.has_verifier(TEST_VERIFIER_ID):
            auth.register_verifier(TEST_VERIFIER_ID, TEST_VERIFIER_KEY)
        old_att = adapter.verification_attestation or {}
        verification_digest = old_att.get("verification_digest") or sha256_digest(
            {"adapter_id": adapter.adapter_id, "adapter_hash": adapter.adapter_hash}
        )
        attestation = auth.issue_adapter_attestation(
            adapter.adapter_id,
            adapter.adapter_hash,
            adapter.verification_corpus_hash,
            verification_digest,
            TEST_VERIFIER_ID,
            callable_hash=callable_hash,
        )
        return AdapterSpec(
            adapter_id=adapter.adapter_id,
            version=adapter.version,
            source_port=adapter.source_port,
            target_port=adapter.target_port,
            mapping=dict(adapter.mapping),
            unit_conversion=dict(adapter.unit_conversion) if adapter.unit_conversion is not None else None,
            lossless=adapter.lossless,
            preconditions=list(adapter.preconditions),
            verification_corpus_hash=adapter.verification_corpus_hash,
            adapter_hash=adapter.adapter_hash,
            trust_status=TrustStatus.VERIFIED,
            verification_attestation=attestation,
        )
    return adapter
