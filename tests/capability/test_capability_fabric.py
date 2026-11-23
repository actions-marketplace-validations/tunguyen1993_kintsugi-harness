"""Unit and negative security tests for Stage 1 Capability Fabric."""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_tool

import json
import os
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from kintsugi.capability import (
    VALID_EXECUTION_STATUSES,
    AttestationAuthority,
    CapabilityGap,
    CapabilityGapDetector,
    CapabilityGraph,
    ExecutionReceipt,
    ExecutionStatus,
    Experience,
    ResolutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolRegistry,
    ToolResolver,
    ToolSpec,
    TrustStatus,
    sha256_digest,
    compute_tool_spec_security_digest,
)
from kintsugi.shield import scan_high_entropy_secrets

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_ZERO = "sha256:" + "0" * 64


def _make_verified_spec(
    tool_id: str,
    capabilities: list,
    *,
    binary_hash: str = HASH_A,
    permissions: list = None,
    side_effects: list = None,
    input_schema: dict = None,
    output_schema: dict = None,
    semantic_contract: dict = None,
    latency_ms: float = 10.0,
    memory_mb: float = 32.0,
    api_tokens: int = 0,
    verifier_id: str = "ci-attestor",
) -> ToolSpec:
    return ToolSpec(
        tool_id=tool_id,
        version="1.0.0",
        source="internal_verified",
        binary_hash=binary_hash,
        capabilities=capabilities,
        input_schema=input_schema or {"type": "json", "encoding": "utf-8"},
        output_schema=output_schema or {"type": "sarif", "encoding": "utf-8"},
        semantic_contract=semantic_contract or {"domain": "appsec", "kind": "findings"},
        side_effects=side_effects if side_effects is not None else ["none"],
        required_permissions=permissions if permissions is not None else ["fs.read"],
        trust_status=TrustStatus.VERIFIED,
        latency_estimate_ms=latency_ms,
        memory_estimate_mb=memory_mb,
        api_token_estimate=api_tokens,
        verification_attestation={
            "verifier_id": verifier_id,
            "verification_digest": HASH_B,
            "binary_hash": binary_hash,
            "tool_id": tool_id,
        },
    )


class TestSchemasAndSecurity(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "ast.scan"],
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_canonical_serialization_and_roundtrip(self) -> None:
        spec = _make_verified_spec("scanner.core", ["static.scan"])
        reloaded = ToolSpec.from_dict(json.loads(spec.to_canonical_json()))
        self.assertEqual(spec.content_hash(), reloaded.content_hash())
        self.assertEqual(reloaded.trust_status, TrustStatus.VERIFIED)

        receipt = ExecutionReceipt(
            run_id="run-001",
            status=ExecutionStatus.PASS,
            plan_hash=HASH_A,
            tool_hash=HASH_B,
            policy_hash=self.sec_ctx.policy_hash,
            environment_hash=HASH_C,
            exit_status=0,
            verification_status="VERIFIED",
            artifact_digests={"sarif": HASH_A},
        )
        self.assertEqual(receipt.schema, "ExecutionReceipt/1")
        self.assertEqual(
            ExecutionReceipt.from_dict(json.loads(receipt.to_canonical_json())).content_hash(),
            receipt.content_hash(),
        )
        self.assertEqual(
            VALID_EXECUTION_STATUSES,
            {
                "PASS",
                "FAIL",
                "NOT_VERIFIED",
                "INSUFFICIENT_EVIDENCE",
                "NO_VERIFIED_TOOL",
                "PERMISSION_DENIED",
                "WAITING_APPROVAL",
                "SANDBOX_UNAVAILABLE",
                "RECONCILIATION_REQUIRED",
                "ROLLED_BACK",
            },
        )

    def test_secret_redaction_never_persists_raw_secrets(self) -> None:
        fake_sk = "sk-" + "live-" + "AlphaBetaGamma9988776655"
        fake_assign_val = "Zx9Qw2Er5Ty8Ui1Op4As"
        fake_pem = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END " + "PRIVATE KEY-----"

        receipt = ExecutionReceipt(
            run_id="run-secret-check",
            status=ExecutionStatus.FAIL,
            plan_hash=HASH_A,
            tool_hash=HASH_B,
            policy_hash=self.sec_ctx.policy_hash,
            environment_hash=HASH_C,
            exit_status=1,
            verification_status="FAILED",
            stdout_excerpt=f"Bearer {fake_assign_val} api_key=\"{fake_assign_val}\"",
            stderr_excerpt=f"leak={fake_sk} {fake_pem}",
            resource_metrics={"secret": fake_assign_val},
        )
        canon_receipt = receipt.to_canonical_json()
        self.assertNotIn(fake_sk, canon_receipt)
        self.assertNotIn(fake_assign_val, canon_receipt)
        self.assertNotIn("MIIEvQIBADANBg", canon_receipt)
        self.assertEqual(scan_high_entropy_secrets(canon_receipt), [])

        exp = Experience(
            task_fingerprint="fp-1",
            failure_class="auth",
            tool_or_plan_id="tool.a",
            input_characteristics={"api_key": fake_assign_val},
            verified_outcome=True,
            failure_reasons=[f"token={fake_sk}"],
            cross_task_transfer_evidence=[{"header": f"Bearer {fake_assign_val}"}],
            security_profile=SecurityProfile.GITHUB_PUBLIC,
        )
        canon_exp = exp.to_canonical_json()
        self.assertNotIn(fake_assign_val, canon_exp)
        self.assertNotIn(fake_sk, canon_exp)
        self.assertEqual(scan_high_entropy_secrets(canon_exp), [])

    def test_rejects_traversal_tool_ids_and_unverified_trust_escalation(self) -> None:
        for bad_id in ("../evil", "dir/tool", "dir\\tool", "", ".dotstart", "bad\u202eid"):
            with self.assertRaises(ValueError):
                ToolSpec(
                    tool_id=bad_id,
                    version="1.0",
                    source="local",
                    binary_hash=HASH_A,
                    capabilities=["scan"],
                )

        # Direct VERIFIED without attestation must fail
        with self.assertRaises(ValueError):
            ToolSpec(
                tool_id="evil.tool",
                version="1.0",
                source="local",
                binary_hash=HASH_A,
                capabilities=["scan"],
                trust_status=TrustStatus.VERIFIED,
                verification_attestation=None,
            )

        # Self-asserted verifier_id == "self" must fail
        with self.assertRaises(ValueError):
            ToolSpec(
                tool_id="evil.self",
                version="1.0",
                source="local",
                binary_hash=HASH_A,
                capabilities=["scan"],
                trust_status=TrustStatus.VERIFIED,
                verification_attestation={
                    "verifier_id": "self",
                    "verification_digest": HASH_B,
                    "binary_hash": HASH_A,
                },
            )

        # Discovery metadata claiming VERIFIED must downgrade to QUARANTINED
        downgraded = ToolSpec.from_dict(
            {
                "tool_id": "sneaky.tool",
                "version": "1.0",
                "source": "discovery",
                "binary_hash": HASH_A,
                "capabilities": ["scan"],
                "trust_status": "VERIFIED",
            },
            from_discovery=True,
        )
        self.assertEqual(downgraded.trust_status, TrustStatus.QUARANTINED)
        self.assertIsNone(downgraded.verification_attestation)

    def test_security_context_symlink_and_workspace_containment(self) -> None:
        outside = Path(self._tmp.name) / "outside_secret.txt"
        outside.write_text("outside", encoding="utf-8")

        link_ws = Path(self._tmp.name) / "ws_symlink"
        link_ws.symlink_to(self.ws)
        with self.assertRaises(PermissionError):
            SecurityContext(workspace_root=str(link_ws))

        inner_link = self.ws / "escape_link"
        inner_link.symlink_to(outside)
        with self.assertRaises(PermissionError):
            self.sec_ctx.validate_path("escape_link")
        with self.assertRaises(PermissionError):
            self.sec_ctx.validate_path("../outside_secret.txt")

        # Invalid PASS receipt cannot bypass verification_status
        with self.assertRaises(ValueError):
            ExecutionReceipt(
                run_id="bad-pass",
                status=ExecutionStatus.PASS,
                plan_hash=HASH_A,
                tool_hash=HASH_B,
                policy_hash=self.sec_ctx.policy_hash,
                environment_hash=HASH_C,
                exit_status=0,
                verification_status="NOT_VERIFIED",
            )


class TestToolRegistryAndStaticDiscovery(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "process.exec", "mcp.invoke"],
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_register_untrusted_attestor_downgrades_and_blocks_overwrite(self) -> None:
        reg = ToolRegistry()
        forged = _make_verified_spec("core.scanner", ["scan"])
        reg.register(forged, trusted_attestor=False)
        stored = reg.get("core.scanner")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.trust_status, TrustStatus.QUARANTINED)

        reg2 = ToolRegistry()
        verified = _make_verified_spec("core.scanner", ["scan"], binary_hash=HASH_A)
        sign_fixture_tool(reg2, verified)
        self.assertEqual(reg2.get("core.scanner").trust_status, TrustStatus.VERIFIED)

        hijack = ToolSpec(
            tool_id="core.scanner",
            version="9.9.9",
            source="untrusted",
            binary_hash=HASH_C,
            capabilities=["scan"],
            trust_status=TrustStatus.DISCOVERED,
        )
        with self.assertRaises(PermissionError):
            reg2.register(hijack, trusted_attestor=False)

    def test_discover_local_never_executes_and_blocks_symlinks_and_trust_escalation(self) -> None:
        tools_dir = self.ws / "tools"
        tools_dir.mkdir()
        marker_file = self.ws / "executed.marker"

        # Executable script that creates marker_file if ever executed (even with --help)
        script_path = tools_dir / "untrusted_probe.py"
        script_path.write_text(
            "#!/usr/bin/env python3\n"
            f"from pathlib import Path\nPath({str(marker_file)!r}).write_text('RAN')\n",
            encoding="utf-8",
        )
        os.chmod(script_path, 0o755)

        # Manifest attempting trust escalation via JSON
        malicious_manifest = tools_dir / "escalate.tool.json"
        malicious_manifest.write_text(
            json.dumps(
                {
                    "tool_id": "escalate.tool",
                    "version": "1.0.0",
                    "capabilities": ["scan.static"],
                    "trust_status": "VERIFIED",
                    "entrypoint": "untrusted_probe.py",
                }
            ),
            encoding="utf-8",
        )

        # Manifest with binary_hash mismatch
        mismatch_target = tools_dir / "helper.py"
        mismatch_target.write_text("print('helper')\n", encoding="utf-8")
        mismatch_manifest = tools_dir / "mismatch.tool.json"
        mismatch_manifest.write_text(
            json.dumps(
                {
                    "tool_id": "mismatch.tool",
                    "version": "1.0.0",
                    "capabilities": ["scan.static"],
                    "binary_hash": HASH_ZERO,
                    "entrypoint": "helper.py",
                }
            ),
            encoding="utf-8",
        )

        # Symlink inside allowlisted dir pointing outside workspace
        outside = Path(self._tmp.name) / "outside_bin.py"
        outside.write_text("print('outside')\n", encoding="utf-8")
        sym_bin = tools_dir / "sym_evil.py"
        sym_bin.symlink_to(outside)

        # Clean standalone executable
        clean_bin = tools_dir / "clean_tool.py"
        clean_bin.write_text("def run():\n    return 1\n", encoding="utf-8")

        reg = ToolRegistry()
        with unittest.mock.patch.object(subprocess, "run", side_effect=AssertionError("MUST NOT EXEC")):
            with unittest.mock.patch.object(subprocess, "Popen", side_effect=AssertionError("MUST NOT EXEC")):
                found = reg.discover_local(self.sec_ctx, allowlisted_paths=[tools_dir])

        self.assertFalse(marker_file.exists(), "discover_local executed an untrusted script!")
        self.assertIsNone(reg.get("sym_evil"))
        self.assertTrue(any(r["reason"] == "SYMLINK_REFUSED" for r in reg.discovery_rejections))

        escalated = reg.get("escalate.tool")
        self.assertIsNotNone(escalated)
        self.assertEqual(escalated.trust_status, TrustStatus.QUARANTINED)
        self.assertEqual(escalated.binary_hash, sha256_digest(script_path.read_bytes()))

        mismatched = reg.get("mismatch.tool")
        self.assertIsNotNone(mismatched)
        self.assertEqual(mismatched.trust_status, TrustStatus.QUARANTINED)
        self.assertEqual(mismatched.provenance["quarantine_reason"], "BINARY_HASH_MISMATCH")

        clean = reg.get("clean_tool")
        self.assertIsNotNone(clean)
        self.assertEqual(clean.trust_status, TrustStatus.DISCOVERED)
        self.assertEqual(clean.binary_hash, sha256_digest(clean_bin.read_bytes()))
        self.assertTrue(all(t.trust_status != TrustStatus.VERIFIED for t in found))

        # Symlinked allowlisted path itself must be refused
        sym_dir = Path(self._tmp.name) / "sym_tools_dir"
        sym_dir.symlink_to(tools_dir)
        with self.assertRaises(PermissionError):
            reg.discover_local(self.sec_ctx, allowlisted_paths=[sym_dir])

    def test_mcp_config_discovery_redacts_secrets_and_quarantines_shell_metachars(self) -> None:
        fake_key = "".join(["Zx9Qw2Er", "5Ty8Ui1Op4As"])
        mcp_cfg = {
            "mcpServers": {
                "safe_ast": {
                    "command": "python3",
                    "args": ["-m", "ast_server"],
                    "capabilities": ["ast.parse"],
                    "env": {"SERVICE_API_KEY": fake_key},
                    "trust_status": "VERIFIED",  # self-asserted -> must be downgraded!
                },
                "cmd_inj": {
                    "command": "sh -c 'echo pwn | cat'",
                    "capabilities": ["evil.run"],
                },
            }
        }
        reg = ToolRegistry()
        discovered = reg.discover_local(self.sec_ctx, allowlisted_paths=[], mcp_configs=[mcp_cfg])
        self.assertEqual(len(discovered), 2)
        for spec in discovered:
            self.assertEqual(spec.trust_status, TrustStatus.QUARANTINED)
            canon = spec.to_canonical_json()
            self.assertNotIn(fake_key, canon)
            self.assertEqual(scan_high_entropy_secrets(canon), [])

        # Clean MCP entry with no suspicious traits must be DISCOVERED (never VERIFIED)
        clean_cfg = {
            "mcpServers": {
                "clean_srv": {
                    "command": "python3",
                    "args": ["-m", "clean_mcp"],
                    "capabilities": ["docs.read"],
                    "env": {"API_TOKEN": fake_key},
                }
            }
        }
        reg.discover_local(self.sec_ctx, allowlisted_paths=[], mcp_configs=[clean_cfg])
        clean_spec = reg.get("mcp.clean_srv")
        self.assertIsNotNone(clean_spec)
        self.assertEqual(clean_spec.trust_status, TrustStatus.DISCOVERED)
        self.assertNotIn(fake_key, clean_spec.to_canonical_json())

    def test_verify_quarantine_and_tampered_disk_load_guard(self) -> None:
        reg_path = self.ws / "registry.json"
        verifier_secret = b"release-bot-hmac-key-material-alpha"
        auth = AttestationAuthority({"release-bot": verifier_secret})
        reg = ToolRegistry(reg_path, authority=auth)
        disc = ToolSpec(
            tool_id="local.lint",
            version="1.0.0",
            source="local_discovery",
            binary_hash=HASH_A,
            capabilities=["lint.py"],
            trust_status=TrustStatus.DISCOVERED,
        )
        reg.register(disc)
        issued = auth.issue_attestation("local.lint", HASH_A, HASH_B, "release-bot", spec_digest=compute_tool_spec_security_digest(reg.get("local.lint")))
        verified = reg.verify_tool(
            "local.lint",
            HASH_B,
            "release-bot",
            expected_binary_hash=HASH_A,
            attestation_signature=issued["signature"],
        )
        self.assertEqual(verified.trust_status, TrustStatus.VERIFIED)
        self.assertEqual(verified.verification_attestation.get("signature"), issued["signature"])
        reg.save()

        # Signing keys must never be persisted inside workspace tool_registry.json
        saved_text = reg_path.read_text(encoding="utf-8")
        self.assertNotIn("release-bot-hmac-key-material-alpha", saved_text)

        reloaded = ToolRegistry(reg_path, authority=auth)
        self.assertEqual(reloaded.get("local.lint").trust_status, TrustStatus.VERIFIED)

        # Tamper JSON on disk: (a) unsigned self-asserted entry, (b) forged signature on release-bot entry
        raw = json.loads(saved_text)
        raw["tools"][0]["verification_attestation"]["signature"] = "hmac-sha256:" + ("f" * 64)
        raw["tools"].append(
            {
                "schema": "ToolSpec/1",
                "tool_id": "tampered.tool",
                "version": "1.0.0",
                "source": "tampered",
                "binary_hash": HASH_C,
                "capabilities": ["scan"],
                "trust_status": "VERIFIED",
                "verification_attestation": {"verifier_id": "self", "verification_digest": HASH_A},
            }
        )
        reg_path.write_text(json.dumps(raw), encoding="utf-8")
        tampered_reg = ToolRegistry(reg_path, authority=auth)
        self.assertEqual(tampered_reg.get("tampered.tool").trust_status, TrustStatus.QUARANTINED)
        self.assertEqual(tampered_reg.get("local.lint").trust_status, TrustStatus.QUARANTINED)
        self.assertEqual(
            tampered_reg.get("local.lint").provenance.get("quarantine_reason"),
            "TAMPERED_OR_UNTRUSTED_ATTESTATION",
        )

        # Quarantine prevents direct re-verification
        reloaded.quarantine("local.lint", "regression_found")
        self.assertEqual(reloaded.get("local.lint").trust_status, TrustStatus.QUARANTINED)
        issued_c = auth.issue_attestation("local.lint", HASH_A, HASH_C, "release-bot", spec_digest=compute_tool_spec_security_digest(reloaded.get("local.lint")))
        with self.assertRaises(ValueError):
            reloaded.verify_tool(
                "local.lint",
                HASH_C,
                "release-bot",
                attestation_signature=issued_c["signature"],
            )

    def test_verify_tool_rejects_self_declared_digest_and_untrusted_verifier(self) -> None:
        # Reproduce KH-B2-SEC-001 PoC: bare digest + "self-verifier" on empty authority MUST fail closed
        reg = ToolRegistry()
        disc = ToolSpec(
            tool_id="poc.untrusted_tool",
            version="1.0.0",
            source="local_discovery",
            binary_hash=HASH_A,
            capabilities=["scan.poc"],
            trust_status=TrustStatus.DISCOVERED,
        )
        reg.register(disc)

        with self.assertRaises(PermissionError) as ctx:
            reg.verify_tool(
                "poc.untrusted_tool",
                HASH_B,
                "self-verifier",
                expected_binary_hash=HASH_A,
            )
        self.assertIn("UNTRUSTED_OR_INVALID_ATTESTATION_AUTHORITY", str(ctx.exception))
        # Tool status MUST remain DISCOVERED (never promoted!)
        self.assertEqual(reg.get("poc.untrusted_tool").trust_status, TrustStatus.DISCOVERED)

        # Forged signature without registered verifier also fails closed
        with self.assertRaises(PermissionError):
            reg.verify_tool(
                "poc.untrusted_tool",
                HASH_B,
                "ci-signer",
                expected_binary_hash=HASH_A,
                attestation_signature="hmac-sha256:" + ("0" * 64),
            )
        self.assertEqual(reg.get("poc.untrusted_tool").trust_status, TrustStatus.DISCOVERED)

        # Register trusted verifier; unsigned, wrong-digest, wrong-tool, and forged-signature attempts MUST fail
        verifier_secret = b"trusted-ci-verifier-secret-alpha"
        reg.register_trusted_verifier("ci-signer", verifier_secret)

        with self.assertRaises(PermissionError):
            reg.verify_tool("poc.untrusted_tool", HASH_B, "ci-signer", expected_binary_hash=HASH_A)
        self.assertEqual(reg.get("poc.untrusted_tool").trust_status, TrustStatus.DISCOVERED)

        valid_att = reg.authority.issue_attestation("poc.untrusted_tool", HASH_A, HASH_B, "ci-signer", spec_digest=compute_tool_spec_security_digest(reg.get("poc.untrusted_tool")))
        # Tampered digest fails constant-time HMAC check
        with self.assertRaises(PermissionError):
            reg.verify_tool(
                "poc.untrusted_tool",
                HASH_C,
                "ci-signer",
                expected_binary_hash=HASH_A,
                attestation_signature=valid_att["signature"],
            )
        self.assertEqual(reg.get("poc.untrusted_tool").trust_status, TrustStatus.DISCOVERED)

        # Attestation issued for a different tool_id cannot be replayed
        other_att = reg.authority.issue_attestation("other.tool", HASH_A, HASH_B, "ci-signer", spec_digest=compute_tool_spec_security_digest(reg.get("poc.untrusted_tool")))
        with self.assertRaises(PermissionError):
            reg.verify_tool(
                "poc.untrusted_tool",
                HASH_B,
                "ci-signer",
                expected_binary_hash=HASH_A,
                attestation_signature=other_att["signature"],
            )
        self.assertEqual(reg.get("poc.untrusted_tool").trust_status, TrustStatus.DISCOVERED)

        # Valid HMAC-signed attestation promotes cleanly to VERIFIED
        verified = reg.verify_tool(
            "poc.untrusted_tool",
            HASH_B,
            "ci-signer",
            expected_binary_hash=HASH_A,
            attestation=valid_att,
        )
        self.assertEqual(verified.trust_status, TrustStatus.VERIFIED)
        self.assertEqual(verified.verification_attestation.get("signature"), valid_att["signature"])

        # Hardened register(trusted_attestor=True) enforces signature for registered verifiers or signed payloads
        unsigned_claimed = _make_verified_spec(
            "claimed.signed",
            ["scan.claimed"],
            binary_hash=HASH_A,
            verifier_id="ci-signer",
        )
        with self.assertRaises(PermissionError):
            reg.register(unsigned_claimed, trusted_attestor=True)

        bad_signed = _make_verified_spec("forged.sig", ["scan.forged"], binary_hash=HASH_A, verifier_id="ci-signer")
        bad_signed.verification_attestation["signature"] = "hmac-sha256:" + ("e" * 64)
        with self.assertRaises(PermissionError):
            reg.register(bad_signed, trusted_attestor=True)

        good_signed = _make_verified_spec("valid.signed", ["scan.valid"], binary_hash=HASH_A, verifier_id="ci-signer")
        good_signed.verification_attestation = reg.authority.issue_attestation(
            "valid.signed", HASH_A, HASH_B, "ci-signer", spec_digest=compute_tool_spec_security_digest(good_signed)
        )
        reg.register(good_signed, trusted_attestor=True)
        self.assertEqual(reg.get("valid.signed").trust_status, TrustStatus.VERIFIED)

        # External key file security guards: must be outside workspace, non-symlink, regular, and 0o600
        outside_dir = Path(self._tmp.name) / "owner_keys"
        outside_dir.mkdir(parents=True, exist_ok=True)
        ext_key_file = outside_dir / "verifiers.json"
        ext_key_file.write_text(
            json.dumps({"verifiers": {"ext-verifier": "external-owner-hmac-key-material"}}),
            encoding="utf-8",
        )
        os.chmod(ext_key_file, 0o644)
        with self.assertRaises(PermissionError):
            AttestationAuthority.from_key_file(ext_key_file, workspace_root=self.ws)

        os.chmod(ext_key_file, 0o600)
        ext_auth = AttestationAuthority.from_key_file(ext_key_file, workspace_root=self.ws)
        self.assertTrue(ext_auth.has_verifier("ext-verifier"))

        inside_key_file = self.ws / ".kintsugi" / "verifiers.json"
        inside_key_file.parent.mkdir(parents=True, exist_ok=True)
        inside_key_file.write_text(
            json.dumps({"verifiers": {"ext-verifier": "external-owner-hmac-key-material"}}),
            encoding="utf-8",
        )
        os.chmod(inside_key_file, 0o600)
        with self.assertRaises(PermissionError):
            AttestationAuthority.from_key_file(inside_key_file, workspace_root=self.ws)

        sym_key_file = outside_dir / "sym_verifiers.json"
        sym_key_file.symlink_to(ext_key_file)
        with self.assertRaises(PermissionError):
            AttestationAuthority.from_key_file(sym_key_file, workspace_root=self.ws)

        with self.assertRaises(ValueError):
            AttestationAuthority({"weak": "short"})
        with self.assertRaises(ValueError):
            AttestationAuthority({"self": "self-verifier-cannot-be-trusted"})

        # Unregistered verifier_id (without signature) MUST be rejected by register() and quarantined by load()
        evil_unreg = _make_verified_spec(
            "evil.unregistered",
            ["scan.evil"],
            binary_hash=HASH_A,
            verifier_id="evil-unregistered",
        )
        with self.assertRaises(PermissionError):
            reg.register(evil_unreg, trusted_attestor=True)

        tampered_reg_file = outside_dir / "tampered_unregistered.json"
        tampered_reg_file.write_text(
            json.dumps({"schema": ToolRegistry.SCHEMA_VERSION, "tools": [evil_unreg.to_dict()]}),
            encoding="utf-8",
        )
        strict_reg = ToolRegistry(authority=reg.authority)
        strict_reg.load(tampered_reg_file)
        loaded_evil = strict_reg.get("evil.unregistered")
        self.assertIsNotNone(loaded_evil)
        self.assertEqual(loaded_evil.trust_status, TrustStatus.QUARANTINED)
        self.assertEqual(loaded_evil.provenance.get("quarantine_reason"), "TAMPERED_OR_UNTRUSTED_ATTESTATION")


class TestCapabilityGraphGapAndResolver(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "ast.scan"],
            network_allowed=False,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_capability_graph_6_dimensions_and_deterministic_index(self) -> None:
        producer = _make_verified_spec(
            "ast.extractor",
            ["ast.extract"],
            input_schema={"type": "python_source"},
            output_schema={
                "type": "json",
                "properties": {"nodes": {}},
                "encoding": "utf-8",
                "units": "bytes",
                "ordering": "sorted_asc",
            },
            semantic_contract={"domain": "appsec", "kind": "ast", "invariants": ["no_cycles"]},
            side_effects=["none"],
            permissions=["fs.read"],
        )
        consumer_ok = _make_verified_spec(
            "rule.checker",
            ["rule.check"],
            input_schema={
                "type": "json",
                "required": ["nodes"],
                "encoding": "utf-8",
                "units": "bytes",
                "ordering": "sorted_asc",
            },
            output_schema={"type": "sarif"},
            semantic_contract={
                "domain": "appsec",
                "kind": "ast",
                "invariants": ["no_cycles"],
                "allowed_producer_side_effects": ["none"],
            },
            permissions=["ast.scan"],
        )
        graph1 = CapabilityGraph([producer, consumer_ok])
        graph2 = CapabilityGraph([consumer_ok, producer])
        self.assertEqual(graph1.content_hash(), graph2.content_hash())
        self.assertEqual(graph1.get_tools_for_capability("ast.extract"), ["ast.extractor"])
        self.assertTrue(graph1.can_compose("ast.extractor", "rule.checker", self.sec_ctx).compatible)

        # Test mismatch across each dimension: type, semantic_contract, encoding, units, ordering, permissions
        bad_variants = [
            ("type", {"input_schema": {"type": "csv"}}, {}),
            ("semantic", {}, {"semantic_contract": {"domain": "weather", "kind": "ast"}}),
            ("encoding", {"input_schema": {"type": "json", "encoding": "latin-1"}}, {}),
            ("units", {"input_schema": {"type": "json", "units": "milliseconds"}}, {}),
            ("ordering", {"input_schema": {"type": "json", "ordering": "sorted_desc"}}, {}),
            ("permissions", {}, {"permissions": ["fs.write"]}),
        ]
        for label, schema_kw, extra_kw in bad_variants:
            bad_consumer = _make_verified_spec(
                f"bad.{label}",
                ["rule.check"],
                input_schema=schema_kw.get("input_schema", {"type": "json", "encoding": "utf-8"}),
                semantic_contract=extra_kw.get("semantic_contract", {"domain": "appsec", "kind": "ast"}),
                permissions=extra_kw.get("permissions", ["ast.scan"]),
            )
            res = graph1.check_edge_compatibility(producer, bad_consumer, self.sec_ctx)
            self.assertFalse(res.compatible, f"{label} mismatch should fail compatibility!")

    def test_gap_detector_distinguishes_all_capability_states(self) -> None:
        reg = ToolRegistry()
        sign_fixture_tool(reg, _make_verified_spec("t.ver", ["cap.verified"], permissions=["fs.read"]))
        reg.register(
            ToolSpec(
                tool_id="t.disc",
                version="1.0",
                source="local_discovery",
                binary_hash=HASH_A,
                capabilities=["cap.discovered"],
                required_permissions=["fs.read"],
                trust_status=TrustStatus.DISCOVERED,
            )
        )
        reg.register(
            ToolSpec(
                tool_id="t.quar",
                version="1.0",
                source="local_discovery",
                binary_hash=HASH_A,
                capabilities=["cap.quarantined"],
                trust_status=TrustStatus.QUARANTINED,
            )
        )
        sign_fixture_tool(reg, _make_verified_spec(
                "t.net",
                ["cap.blocked"],
                permissions=["fs.read", "network.outbound"],
                side_effects=["network.outbound"],
            ))
        reg.register(
            ToolSpec(
                tool_id="t.ret",
                version="1.0",
                source="internal",
                binary_hash=HASH_A,
                capabilities=["cap.missing"],
                trust_status=TrustStatus.RETIRED,
            )
        )

        detector = CapabilityGapDetector()
        gap = detector.analyze(
            {
                "goal_id": "goal-partition",
                "required_capabilities": [
                    "cap.verified",
                    "cap.discovered",
                    "cap.quarantined",
                    "cap.blocked",
                    "cap.missing",
                ],
            },
            reg,
            self.sec_ctx,
        )
        self.assertFalse(gap.is_satisfied)
        self.assertEqual(gap.available_capabilities, ["cap.verified"])
        self.assertEqual(gap.discovered_unverified_capabilities, ["cap.discovered"])
        self.assertEqual(gap.quarantined_capabilities, ["cap.quarantined"])
        self.assertEqual(gap.blocked_by_policy_capabilities, ["cap.blocked"])
        self.assertEqual(gap.missing_capabilities, ["cap.missing"])

    def test_resolver_blocks_quarantined_unverified_and_overprivileged_tools(self) -> None:
        resolver = ToolResolver()

        # 1. Quarantined only -> QUARANTINED
        reg_q = ToolRegistry()
        reg_q.register(
            ToolSpec(
                tool_id="q.only",
                version="1.0",
                source="local",
                binary_hash=HASH_A,
                capabilities=["scan.static"],
                trust_status=TrustStatus.QUARANTINED,
            )
        )
        res_q = resolver.resolve({"goal_id": "g-q", "required_capabilities": ["scan.static"]}, reg_q, self.sec_ctx)
        self.assertEqual(res_q.status, ResolutionStatus.QUARANTINED)
        self.assertFalse(res_q.executable)
        self.assertEqual(res_q.selected_tools, {})
        self.assertEqual(res_q.llm_calls, 0)

        # 2. Discovered only -> NO_VERIFIED_TOOL
        reg_d = ToolRegistry()
        reg_d.register(
            ToolSpec(
                tool_id="d.only",
                version="1.0",
                source="local_discovery",
                binary_hash=HASH_A,
                capabilities=["scan.static"],
                required_permissions=["fs.read"],
                trust_status=TrustStatus.DISCOVERED,
            )
        )
        res_d = resolver.resolve({"goal_id": "g-d", "required_capabilities": ["scan.static"]}, reg_d, self.sec_ctx)
        self.assertEqual(res_d.status, ResolutionStatus.NO_VERIFIED_TOOL)
        self.assertFalse(res_d.executable)
        self.assertEqual(res_d.selected_tools, {})

        # 3. Over-privileged VERIFIED tool -> NO_VERIFIED_TOOL
        reg_p = ToolRegistry()
        sign_fixture_tool(reg_p, _make_verified_spec("priv.too_high", ["scan.static"], permissions=["fs.read", "fs.write"]))
        res_p = resolver.resolve({"goal_id": "g-p", "required_capabilities": ["scan.static"]}, reg_p, self.sec_ctx)
        self.assertEqual(res_p.status, ResolutionStatus.NO_VERIFIED_TOOL)
        self.assertFalse(res_p.executable)
        self.assertIn(
            "OVER_PRIVILEGED_PERMISSIONS:fs.write",
            res_p.per_capability["scan.static"].rejected_candidates[0]["reasons"],
        )

    def test_resolver_deterministic_ranking_precedence(self) -> None:
        resolver = ToolResolver()
        reg = ToolRegistry()

        # Candidate A: higher latency & 2 perms, BUT has verified positive Experience
        t_exp = _make_verified_spec(
            "tool.experienced",
            ["scan.static"],
            binary_hash=HASH_A,
            permissions=["fs.read", "ast.scan"],
            latency_ms=80.0,
            api_tokens=10,
            output_schema={"type": "sarif", "encoding": "utf-8"},
        )
        # Candidate B: fast, least-privilege (1 perm), better schema fit, 0 experience
        t_least = _make_verified_spec(
            "tool.least_priv",
            ["scan.static"],
            binary_hash=HASH_B,
            permissions=["fs.read"],
            latency_ms=50.0,
            api_tokens=5,
            output_schema={"type": "sarif", "encoding": "utf-8", "units": "count"},
        )
        # Candidate C: same 0 experience & schema fit as B? No, extra permission vs B, faster latency
        t_more_priv = _make_verified_spec(
            "tool.more_priv",
            ["scan.static"],
            binary_hash=HASH_C,
            permissions=["fs.read", "ast.scan"],
            latency_ms=5.0,
            api_tokens=0,
            output_schema={"type": "sarif", "encoding": "utf-8", "units": "count"},
        )
        for spec in (t_more_priv, t_least, t_exp):
            sign_fixture_tool(reg, spec)

        goal = {
            "goal_id": "g-rank",
            "required_capabilities": ["scan.static"],
            "expected_outputs": [{"type": "sarif", "encoding": "utf-8"}],
        }

        # Without experience: tool.least_priv beats tool.more_priv (permissions least-privilege > lower latency)
        res_no_exp = resolver.resolve(goal, reg, self.sec_ctx, experience_store=[])
        self.assertEqual(res_no_exp.status, ResolutionStatus.VERIFIED)
        self.assertTrue(res_no_exp.executable)
        self.assertEqual(res_no_exp.selected_tools["scan.static"].tool_id, "tool.least_priv")
        self.assertEqual(res_no_exp.llm_calls, 0)

        # With positive verified Experience matching binary_hash: tool.experienced wins
        exp_ok = Experience(
            task_fingerprint="task-sarif",
            failure_class="none",
            tool_or_plan_id="tool.experienced",
            verified_outcome=True,
            reuse_count=4,
            tool_hash=HASH_A,
            security_profile=SecurityProfile.LOCAL_RESEARCH,
        )
        res_with_exp = resolver.resolve(goal, reg, self.sec_ctx, experience_store=[exp_ok])
        self.assertEqual(res_with_exp.selected_tools["scan.static"].tool_id, "tool.experienced")

        # Stale experience with mismatched tool_hash must NOT boost tool.experienced
        exp_stale = Experience(
            task_fingerprint="task-sarif",
            failure_class="none",
            tool_or_plan_id="tool.experienced",
            verified_outcome=True,
            reuse_count=10,
            tool_hash=HASH_ZERO,
            security_profile=SecurityProfile.LOCAL_RESEARCH,
        )
        res_stale = resolver.resolve(goal, reg, self.sec_ctx, experience_store=[exp_stale])
        self.assertEqual(res_stale.selected_tools["scan.static"].tool_id, "tool.least_priv")

        # Failed experience penalizes candidate below untried candidates
        exp_fail = Experience(
            task_fingerprint="task-sarif",
            failure_class="timeout",
            tool_or_plan_id="tool.least_priv",
            verified_outcome=False,
            failure_reasons=["exceeded_deadline"],
            tool_hash=HASH_B,
            security_profile=SecurityProfile.LOCAL_RESEARCH,
        )
        res_fail = resolver.resolve(goal, reg, self.sec_ctx, experience_store=[exp_fail])
        self.assertEqual(res_fail.selected_tools["scan.static"].tool_id, "tool.more_priv")
        self.assertEqual(
            [c.tool_id for c in res_fail.per_capability["scan.static"].ranked_candidates],
            ["tool.more_priv", "tool.experienced", "tool.least_priv"],
        )

    def test_budget_untrusted_native_symlink_save_and_verified_collision_guards(self) -> None:
        resolver = ToolResolver()
        reg = ToolRegistry()

        # 1. Verified tool with budget limit & untrusted_native check
        heavy = _make_verified_spec(
            "heavy.scanner",
            ["scan.static"],
            binary_hash=HASH_A,
            permissions=["fs.read"],
            latency_ms=500.0,
        )
        sign_fixture_tool(reg, heavy)
        res_budget = resolver.resolve(
            {
                "goal_id": "g-budget",
                "required_capabilities": ["scan.static"],
                "budget": {"max_latency_ms": 100.0},
            },
            reg,
            self.sec_ctx,
        )
        self.assertEqual(res_budget.status, ResolutionStatus.NO_VERIFIED_TOOL)
        self.assertIn(
            "BUDGET_LATENCY_EXCEEDED:500.0>100.0",
            res_budget.per_capability["scan.static"].rejected_candidates[0]["reasons"],
        )

        # 2. allow_untrusted_native=False blocks tool tagged untrusted_native
        native_spec = ToolSpec(
            tool_id="native.bin",
            version="1.0",
            source="untrusted_native",
            binary_hash=HASH_B,
            capabilities=["native.exec"],
            required_permissions=["fs.read"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "ci",
                "verification_digest": HASH_C,
                "binary_hash": HASH_B,
                "tool_id": "native.bin",
            },
        )
        sign_fixture_tool(reg, native_spec)
        res_native = resolver.resolve(
            {"goal_id": "g-native", "required_capabilities": ["native.exec"]},
            reg,
            self.sec_ctx,
        )
        self.assertEqual(res_native.status, ResolutionStatus.NO_VERIFIED_TOOL)
        self.assertIn(
            "UNTRUSTED_NATIVE_DISALLOWED_BY_POLICY",
            res_native.per_capability["native.exec"].rejected_candidates[0]["reasons"],
        )

        # 3. discover_local never overwrites existing VERIFIED tool on name collision
        tools_dir = self.ws / "tools"
        tools_dir.mkdir()
        (tools_dir / "heavy.scanner.py").write_text("print('hijack')\n", encoding="utf-8")
        reg.discover_local(self.sec_ctx, allowlisted_paths=[tools_dir])
        self.assertEqual(reg.get("heavy.scanner").trust_status, TrustStatus.VERIFIED)
        self.assertEqual(reg.get("heavy.scanner").binary_hash, HASH_A)
        conflict_tools = [t for t in reg.list_tools() if t.tool_id.startswith("heavy.scanner.conflict.")]
        self.assertEqual(len(conflict_tools), 1)
        self.assertEqual(conflict_tools[0].trust_status, TrustStatus.QUARANTINED)

        # 4. GITHUB_PUBLIC blocks allowlisted_paths outside workspace_root
        outside_dir = Path(self._tmp.name) / "outside_tools"
        outside_dir.mkdir()
        gh_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.GITHUB_PUBLIC,
            allowed_permissions=["fs.read"],
        )
        with self.assertRaises(PermissionError):
            reg.discover_local(gh_ctx, allowlisted_paths=[outside_dir])

        # 5. save/load refuse symlink targets
        real_reg_file = self.ws / "real_reg.json"
        real_reg_file.write_text("{}", encoding="utf-8")
        sym_reg_file = self.ws / "sym_reg.json"
        sym_reg_file.symlink_to(real_reg_file)
        with self.assertRaises(PermissionError):
            reg.save(sym_reg_file)
        with self.assertRaises(PermissionError):
            reg.load(sym_reg_file)


if __name__ == "__main__":
    unittest.main()
