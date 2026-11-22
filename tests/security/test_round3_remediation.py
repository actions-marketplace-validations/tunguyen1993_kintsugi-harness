"""Independent regression probes for Build #2 Round-3 trust, process, WAL gates."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from kintsugi.capability.schemas import (
    ExecutionStatus, SecurityContext, SecurityProfile, ToolSpec,
    TrustStatus, compute_tool_spec_security_digest, sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.capability.contracts_v2 import PortContract
from kintsugi.composition.tool_composer import ToolComposer
from kintsugi.forge.tool_sandbox import run_subprocess_streaming_bounded
from kintsugi.runtime.secure_runner import SecureRunner

_KEY = b"kintsugi-round3-independent-fixture-hmac-key"


def _authority():
    return AttestationAuthority({"round3-ci": _KEY})


def _verified_spec(registry, tool_id, binary_hash, *, source="host_trusted", req=None, permissions=None, side_effects=None):
    spec = ToolSpec(
        tool_id=tool_id, version="1.0.0", source=source,
        binary_hash=binary_hash, capabilities=["test.probe"],
        required_permissions=permissions if permissions is not None else ["fs.read", "process.exec"],
        runtime_requirements=req or {"callable_name": tool_id},
        side_effects=side_effects if side_effects is not None else ["none"],
        trust_status=TrustStatus.VERIFIED,
        verification_attestation={"tool_id": tool_id, "binary_hash": binary_hash, "verifier_id": "round3-ci", "verification_digest": sha256_digest(tool_id)},
    )
    spec.verification_attestation = registry.authority.issue_attestation(
        spec.tool_id, spec.binary_hash, sha256_digest(tool_id), "round3-ci",
        spec_digest=compute_tool_spec_security_digest(spec),
    )
    registry.register(spec, trusted_attestor=True)
    return spec


class TestRound3Remediation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.ws = self.base / "ws"
        self.ws.mkdir()
        self.ctx = SecurityContext(
            workspace_root=str(self.ws), profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=["fs.read", "fs.write", "process.exec"],
            network_allowed=False, allow_untrusted_native=False,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_unsigned_promotion_rejected_without_authority(self):
        registry = ToolRegistry()
        spec = ToolSpec(
            tool_id="test.unsigned", version="1", source="host_trusted",
            binary_hash="sha256:" + "a" * 64, capabilities=["test.probe"],
            trust_status=TrustStatus.VERIFIED,
        verification_attestation={"tool_id": "test.unsigned", "binary_hash": "sha256:"+"a"*64, "verifier_id": "round3-ci", "verification_digest": sha256_digest("test.unsigned")},
        )
        with self.assertRaises(PermissionError):
            registry.register(spec, trusted_attestor=True)

    def test_full_spec_security_digest_rejects_metadata_tampering(self):
        registry_file = self.ws / "registry.json"
        registry = ToolRegistry(registry_file, auto_load=False, authority=_authority())
        _verified_spec(registry, "test.signed", "sha256:" + "b" * 64)
        registry.save()
        signed = json.loads(registry_file.read_text(encoding="utf-8"))
        attacks = [
            ("source", "local"),
            ("required_permissions", []),
            ("command", ["/bin/echo", "CHANGED"]),
            ("runtime_requirements", {"callable_name": "another"}),
            ("capabilities", ["arbitrary.exec"]),
            ("side_effects", ["network.write"]),
        ]
        for field, value in attacks:
            with self.subTest(field=field):
                raw = json.loads(json.dumps(signed))
                raw["tools"][0][field] = value
                registry_file.write_text(json.dumps(raw), encoding="utf-8")
                loaded = ToolRegistry(registry_file, authority=_authority())
                result = loaded.get("test.signed")
                self.assertIsNotNone(result)
                self.assertEqual(result.trust_status, TrustStatus.QUARANTINED)
                self.assertEqual(result.provenance.get("quarantine_reason"), "TAMPERED_OR_UNTRUSTED_ATTESTATION")
        registry_file.write_text(json.dumps(signed), encoding="utf-8")
        self.assertEqual(ToolRegistry(registry_file, authority=_authority()).get("test.signed").trust_status, TrustStatus.VERIFIED)
        self.assertEqual(ToolRegistry(registry_file).get("test.signed").trust_status, TrustStatus.QUARANTINED)

    def test_composer_rejects_signed_spec_changed_in_memory(self):
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        tool_id = "test.tamper_in_memory"
        marker = self.ws / "should_never_execute"
        def fn(_args):
            marker.write_text("executed", encoding="utf-8")
            return {"ok": True}
        digest = runner.register_trusted_host_callable(tool_id, fn)
        spec = _verified_spec(registry, tool_id, digest)
        out_port = PortContract(schema_ref="json:object", semantic_type="memory_tamper_result", unit="none")
        spec.semantic_contract["output_port"] = out_port.to_dict()
        spec.verification_attestation = registry.authority.issue_attestation(
            spec.tool_id, spec.binary_hash, sha256_digest(spec.tool_id), "round3-ci",
            spec_digest=compute_tool_spec_security_digest(spec),
        )
        registry.register(spec, trusted_attestor=True)
        composer = ToolComposer()
        planned = composer.plan(
            {"goal_id": "r3-trust", "required_capabilities": ["test.probe"],
             "expected_outputs": [out_port]}, registry, self.ctx,
        )
        self.assertTrue(planned.ok, planned.reasons)
        registry.get(tool_id).source = "local"
        receipt, _ = composer.execute_plan(planned.plan, registry, self.ctx, runner=runner)
        self.assertEqual(receipt.status, ExecutionStatus.PERMISSION_DENIED)
        self.assertFalse(marker.exists())

    def test_untrusted_callable_fails_closed_by_default(self):
        marker = self.ws / "unexpected_marker"
        def func(_args):
            marker.write_text("EXECUTED", encoding="utf-8")
            return {"ok": True}
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(attestation_authority=registry.authority)
        digest = runner.register_callable("test.callable", func)
        spec = _verified_spec(registry, "test.callable", digest)
        receipt = runner.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(receipt.status, ExecutionStatus.SANDBOX_UNAVAILABLE)
        self.assertFalse(marker.exists())
        trusted = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        digest2 = trusted.register_trusted_host_callable("test.callable", func)
        self.assertEqual(digest, digest2)
        trusted_receipt = trusted.run(spec, {}, self.ctx, oracle=lambda _: True)
        self.assertEqual(trusted_receipt.status, ExecutionStatus.PASS)
        self.assertTrue(marker.exists())

    @unittest.skipUnless(
        sys.platform.startswith(("linux", "darwin")),
        "detached process probing requires /proc on Linux or ps -E on macOS",
    )
    def test_detached_callable_child_does_not_survive_timeout(self):
        marker = self.ws / "detached_callable_marker"
        # Only privileged, host-controlled test fixture may use the unsandboxed callable route.
        def host_func(_args):
            payload = (
                "import time,pathlib;"
                "time.sleep(0.65);"
                f"pathlib.Path({str(marker)!r}).write_text('escaped')"
            )
            subprocess.Popen([sys.executable, "-c", payload], start_new_session=True)
            time.sleep(5)
            return {"ok": True}
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(
            allow_trusted_host_callables=True,
            default_timeout_seconds=0.15,
            attestation_authority=registry.authority,
        )
        digest = runner.register_trusted_host_callable("test.detached", host_func)
        spec = _verified_spec(registry, "test.detached", digest)
        receipt = runner.run(spec, {}, self.ctx, oracle=lambda _: True, timeout_seconds=0.15)
        self.assertNotEqual(receipt.status, ExecutionStatus.PASS)
        time.sleep(0.8)
        self.assertFalse(marker.exists(), "detached child survived callable timeout")

    @unittest.skipUnless(
        sys.platform.startswith(("linux", "darwin")),
        "detached process probing requires /proc on Linux or ps -E on macOS",
    )
    def test_detached_subprocess_child_does_not_survive_timeout(self):
        marker = self.ws / "detached_subprocess_marker"
        payload = (
            "import subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-c',\"import time,pathlib;time.sleep(0.65);pathlib.Path({str(marker)!r}).write_text('escaped')\"],start_new_session=True);"
            "time.sleep(5)"
        )
        exit_code, out, err, timed_out, trunc = run_subprocess_streaming_bounded(
            [sys.executable, "-c", payload], cwd=self.ws,
            timeout_s=0.15, max_output_bytes=1024,
        )
        self.assertTrue(timed_out)
        time.sleep(0.8)
        self.assertFalse(marker.exists(), "detached child survived subprocess timeout")

    @unittest.skipUnless(
        sys.platform.startswith(("linux", "darwin")),
        "detached orphan probing requires /proc on Linux or ps -E on macOS",
    )
    def test_detached_orphan_grandchild_does_not_survive_timeout(self):
        marker = self.ws / "detached_orphan_grandchild_marker"
        inner_code = (
            "import time, pathlib; "
            "time.sleep(0.70); "
            f"pathlib.Path({str(marker)!r}).write_text('orphan_escaped')"
        )
        mid_code = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {inner_code!r}], start_new_session=True)"
        )
        outer_code = (
            "import subprocess, sys, time; "
            f"p = subprocess.Popen([sys.executable, '-c', {mid_code!r}], start_new_session=True); "
            "p.wait(); "
            "time.sleep(5)"
        )
        _rc, _out, _err, timed_out, _trunc = run_subprocess_streaming_bounded(
            [sys.executable, "-c", outer_code],
            cwd=self.ws,
            timeout_s=0.25,
            max_output_bytes=1024,
        )
        self.assertTrue(timed_out)
        time.sleep(0.85)
        self.assertFalse(marker.exists(), "orphaned PPID=1 detached grandchild survived timeout!")

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_composer_real_sigkill_after_side_effect_requires_reconciliation(self):
        marker = self.ws / "irreversible_counter"
        ready_flag = self.ws / "side_effect_committed.flag"
        journal = self.ws / "checkpoint"
        registry = ToolRegistry(authority=_authority())
        runner = SecureRunner(allow_trusted_host_callables=True, attestation_authority=registry.authority)
        tool_id = "test.irreversible"

        def side_effect(_args):
            current = int(marker.read_text() if marker.exists() else "0")
            marker.write_text(str(current + 1), encoding="utf-8")
            ready_flag.write_text("ready", encoding="utf-8")
            # Wait for external SIGKILL from parent test supervisor (sandbox blocks child->parent kill).
            time.sleep(5.0)
            return {"done": True}

        digest = runner.register_trusted_host_callable(tool_id, side_effect)
        spec = _verified_spec(
            registry, tool_id, digest,
            req={"callable_name": tool_id}, permissions=["fs.read", "fs.write", "process.exec"],
            side_effects=["fs.write"],
        )
        out_port = PortContract(schema_ref="json:object", semantic_type="irreversible_result", unit="none")
        # Supply a well-typed zero-input capability for the planner.
        spec.semantic_contract["output_port"] = out_port.to_dict()
        spec.verification_attestation = registry.authority.issue_attestation(
            spec.tool_id, spec.binary_hash, sha256_digest(spec.tool_id), "round3-ci",
            spec_digest=compute_tool_spec_security_digest(spec),
        )
        registry.register(spec, trusted_attestor=True)
        composer = ToolComposer()
        pres = composer.plan(
            {"goal_id": "r3-kill", "required_capabilities": ["test.probe"],
             "expected_outputs": [out_port], "oracle_ref": "oracle:r3"},
            registry, self.ctx,
        )
        self.assertTrue(pres.ok, pres.reasons)
        plan = pres.plan
        self.assertIsNotNone(plan)
        run_id = "r3-kill-run"
        pid = os.fork()
        if pid == 0:
            composer.execute_plan(
                plan, registry, self.ctx, runner=runner,
                checkpoint_store_path=journal, resume_run_id=run_id,
                oracle=lambda _v: True,
            )
            os._exit(2)
        deadline = time.monotonic() + 10.0
        while not ready_flag.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready_flag.exists(), "side-effect child did not signal readiness")
        os.kill(pid, signal.SIGKILL)
        _, wait_status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(wait_status), wait_status)
        self.assertEqual(int(marker.read_text()), 1)
        receipt, events = composer.execute_plan(
            plan, registry, self.ctx, runner=runner,
            checkpoint_store_path=journal, resume_run_id=run_id,
            oracle=lambda _v: True,
        )
        self.assertEqual(receipt.status, ExecutionStatus.RECONCILIATION_REQUIRED)
        self.assertTrue(receipt.unresolved_nodes)
        self.assertEqual(int(marker.read_text()), 1)
        self.assertIn("PLAN_RECONCILIATION_REQUIRED", [event.state for event in events])
        node_id = receipt.unresolved_nodes[0]
        with self.assertRaises(PermissionError):
            composer.reconcile_checkpoint_node(
                checkpoint_store_path=journal, run_id=run_id, node_id=node_id,
                outcome="COMMITTED", security_context=self.ctx,
                verified_output={"done": True},
                verified_receipt={"verification_status": "PASS"},
            )
        composer.reconcile_checkpoint_node(
            checkpoint_store_path=journal, run_id=run_id, node_id=node_id,
            outcome="COMMITTED", security_context=self.ctx,
            verified_output={"done": True},
            verified_receipt={"verification_status": "PASS", "node_id": node_id, "status": "PASS"},
            operator_confirmed=True,
        )
        final, _ = composer.execute_plan(
            plan, registry, self.ctx, runner=runner,
            checkpoint_store_path=journal, resume_run_id=run_id,
            oracle=lambda _: True,
        )
        self.assertEqual(final.status, ExecutionStatus.PASS)
        self.assertEqual(int(marker.read_text()), 1)


if __name__ == "__main__":
    unittest.main()
