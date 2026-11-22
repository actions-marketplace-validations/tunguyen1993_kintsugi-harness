"""Tests for Stage 3 Autonomous Native Tool Forge, Empirically Probed OS Sandbox,
Benchmarks/Economics, Atomic Build Manifests & Rollback, and End-to-End Demo 3 (`kvpipe.v1`).
"""

from __future__ import annotations

try:
    from fixture_attestation import sign_fixture_tool
except ImportError:
    from tests.fixture_attestation import sign_fixture_tool
from kintsugi.capability.schemas import compute_tool_spec_security_digest

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from kintsugi.capability.capability_gap import CapabilityGapDetector
from kintsugi.capability.contracts_v2 import (
    ForgeState,
    ToolBuild,
    validate_forge_transition,
)
from kintsugi.capability.schemas import (
    CapabilityGap,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    sha256_digest,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.capability.tool_resolver import ResolutionStatus, ToolResolver
from kintsugi.forge import (
    FORGE_TEMPLATE_REGISTRY,
    FORGE_VERIFIER_ID,
    BuildManifestStore,
    ForgeEscalationTier,
    NativeToolForge,
    SandboxReceipt,
    ToolBenchmark,
    ToolSandbox,
    build_csv_sum_task_spec,
    build_jsonl_level_filter_task_spec,
    build_kvpipe_v1_task_spec,
    evaluate_economic_criterion,
    filter_jsonl_level_python,
    parse_kvpipe_v1_python,
    scan_forged_source_safety,
    sum_csv_python,
)
from kintsugi.runtime.secure_runner import SecureRunner

REPO_ROOT = Path(__file__).resolve().parents[2]


class ForgeAndSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_forge_test_")
        self.ws = Path(self._tmp.name).resolve() / "workspace"
        self.ws.mkdir(parents=True, exist_ok=True)
        self.outside = Path(self._tmp.name).resolve() / "outside"
        self.outside.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_strict_forge_state_transition_enforcement(self) -> None:
        for prev_state, next_state in (
            (ForgeState.GENERATED, ForgeState.VERIFIED),
            (ForgeState.PROPOSED, ForgeState.COMPILED),
            (ForgeState.SPECIFIED, ForgeState.GENERATED),
            (ForgeState.SANDBOX_TESTED, ForgeState.VERIFIED),
            (ForgeState.BENCHMARKED, ForgeState.VERIFIED),
            (ForgeState.VERIFIED, ForgeState.VERIFIED),
            (ForgeState.REJECTED, ForgeState.VERIFIED),
            (ForgeState.ROLLED_BACK, ForgeState.VERIFIED),
            (ForgeState.VERIFIED, ForgeState.REJECTED),
        ):
            with self.assertRaises(ValueError, msg=f"Allowed invalid skip {prev_state} -> {next_state}"):
                validate_forge_transition(prev_state, next_state)

        build = ToolBuild(
            build_id="bld-skip-check",
            tool_id="forge.demo",
            state=ForgeState.GENERATED,
            oracle_hash="sha256:" + "b" * 64,
            source_hash="sha256:" + "a" * 64,
        )
        with self.assertRaises(ValueError):
            build.transition_to(ForgeState.VERIFIED)

        with self.assertRaises(ValueError):
            ToolBuild(build_id="bld-noprovenance", tool_id="forge.demo", state=ForgeState.VERIFIED)

    def test_seatbelt_profile_excludes_general_users_and_tmp(self) -> None:
        sb = ToolSandbox(self.ws / "sb")
        profile = sb.seatbelt_profile()
        self.assertIn("(deny default)", profile)
        self.assertIn("(deny network*)", profile)
        self.assertIn(f'(subpath "{sb.workspace_root}")', profile)
        self.assertNotIn('(subpath "/Users")', profile)
        self.assertNotIn('(subpath "/private/tmp")', profile)
        self.assertNotIn('(subpath "/tmp")', profile)

    @unittest.skipUnless(sys.platform == "darwin", "macOS Seatbelt test requires Darwin host")
    def test_adversarial_sandbox_escape_probes_and_unavailable_mode(self) -> None:
        sb = ToolSandbox(self.ws / "sb")
        probe = sb.probe_isolation()
        self.assertTrue(probe.all_passed, msg=f"Expected all 4 isolation probes to pass: {probe.to_dict()}")
        self.assertEqual(set(probe.checks.keys()), {
            "confined_rw_inside",
            "deny_read_outside",
            "deny_write_outside",
            "deny_network_egress",
        })
        self.assertTrue(sb.is_ready)

        # Compile adversarial C escape binary inside sandbox and prove kernel blocks all 3 escapes.
        outside_secret = Path("/private/tmp") / f"kintsugi_escape_secret_{os.getpid()}.txt"
        outside_write = Path("/private/tmp") / f"kintsugi_escape_write_{os.getpid()}.txt"
        canary = "TOP_SECRET_CANARY_OUTSIDE_SANDBOX_771"
        outside_secret.write_text(canary, encoding="utf-8")
        if outside_write.exists():
            outside_write.unlink()

        try:
            malicious_c = """
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *mode = argv[1];
    if (strcmp(mode, "read_secret") == 0) {
        FILE *f = fopen(argv[2], "r");
        if (f) {
            char buf[128];
            if (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
            fclose(f);
            return 0;
        }
        return errno == 0 ? 1 : errno;
    }
    if (strcmp(mode, "write_outside") == 0) {
        FILE *f = fopen(argv[2], "w");
        if (f) {
            fputs("pwned\\n", f);
            fclose(f);
            return 0;
        }
        return errno == 0 ? 1 : errno;
    }
    if (strcmp(mode, "net_connect") == 0) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return errno == 0 ? 1 : errno;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);
        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        int err = errno;
        close(fd);
        return rc == 0 ? 0 : (err == 0 ? 1 : err);
    }
    return 3;
}
"""
            src_file = sb.workspace_root / "escape_probe.c"
            bin_file = sb.workspace_root / "escape_probe"
            src_file.write_text(malicious_c, encoding="utf-8")
            comp_res, _, _, _ = sb.compile_c(src_file, bin_file, flags=("-O2", "-std=c99"))
            self.assertTrue(comp_res.passed, msg=comp_res.stderr)

            r_read = sb.execute([str(bin_file), "read_secret", str(outside_secret)])
            self.assertNotEqual(r_read.exit_code, 0)
            self.assertEqual(r_read.execution_status, ExecutionStatus.FAIL)
            self.assertNotIn(canary, r_read.stdout)

            r_write = sb.execute([str(bin_file), "write_outside", str(outside_write)])
            self.assertNotEqual(r_write.exit_code, 0)
            self.assertEqual(r_write.execution_status, ExecutionStatus.FAIL)
            self.assertFalse(outside_write.exists())

            r_net = sb.execute([str(bin_file), "net_connect", "1.1.1.1"])
            self.assertNotEqual(r_net.exit_code, 0)
            self.assertEqual(r_net.execution_status, ExecutionStatus.FAIL)
        finally:
            if outside_secret.exists():
                outside_secret.unlink()
            if outside_write.exists():
                outside_write.unlink()

        # Unavailable sandbox MUST fail closed with SANDBOX_UNAVAILABLE (never silent pass!)
        unavail_sb = ToolSandbox(self.ws / "sb_disabled", force_unavailable=True)
        unavail_probe = unavail_sb.probe_isolation()
        self.assertFalse(unavail_probe.all_passed)
        unavail_res = unavail_sb.execute(["/bin/echo", "should_not_run"])
        self.assertEqual(unavail_res.execution_status, ExecutionStatus.SANDBOX_UNAVAILABLE)
        self.assertFalse(unavail_res.receipt.isolated)
        self.assertEqual(unavail_res.receipt.status, "SANDBOX_UNAVAILABLE")
        self.assertFalse(unavail_res.receipt.passed)

        # NativeToolForge MUST reject with SANDBOX_UNAVAILABLE when sandbox is unavailable
        forge_unavail = NativeToolForge(
            self.ws / "forge_unavail",
            sandbox=unavail_sb,
        )
        res_unavail = forge_unavail.forge_tool(build_kvpipe_v1_task_spec(benchmark_lines=200))
        self.assertFalse(res_unavail.verified)
        self.assertEqual(res_unavail.execution_status, ExecutionStatus.SANDBOX_UNAVAILABLE)
        self.assertEqual(res_unavail.build.state, ForgeState.REJECTED)
        self.assertIsNone(res_unavail.tool_spec)

    def test_static_safety_scan_and_escalation_ladder_and_economics(self) -> None:
        # Static safety scan rejects unsafe primitives before compilation
        bad_c = "#include <sys/socket.h>\nint main(void){return socket(2,1,0);}\n"
        ok, reasons = scan_forged_source_safety(bad_c, language="c")
        self.assertFalse(ok)
        self.assertIn("FORBIDDEN_C_NETWORK_HEADER", reasons)
        self.assertIn("FORBIDDEN_C_NETWORK_CALL", reasons)

        # Escalation ladder respects priority: existing tool -> adapter -> composition -> rust_c
        reg = ToolRegistry()
        existing_bin = self.ws / "existing.py"
        existing_bin.write_text("print('ok')\n", encoding="utf-8")
        bin_hash = sha256_digest(existing_bin.read_bytes())
        existing_spec = ToolSpec(
            tool_id="tool.existing.hash",
            version="1.0.0",
            source="local",
            binary_hash=bin_hash,
            capabilities=["hash.sha256"],
            trust_status=TrustStatus.VERIFIED,
            verification_attestation={
                "verifier_id": "ci-verifier",
                "verification_digest": sha256_digest({"tool_id": "tool.existing.hash", "binary_hash": bin_hash}),
                "binary_hash": bin_hash,
                "tool_id": "tool.existing.hash",
            },
            entrypoint="existing.py",
        )
        sign_fixture_tool(reg, existing_spec)
        sec_ctx = SecurityContext(workspace_root=str(self.ws))

        forge = NativeToolForge(self.ws)
        d1 = forge.evaluate_escalation_ladder(["hash.sha256"], registry=reg, security_context=sec_ctx)
        self.assertEqual(d1.selected_tier, ForgeEscalationTier.EXISTING_TOOL)
        self.assertEqual(d1.existing_tool_id, "tool.existing.hash")

        d2 = forge.evaluate_escalation_ladder(["missing.cap"], registry=reg, security_context=sec_ctx)
        self.assertEqual(d2.selected_tier, ForgeEscalationTier.RUST_OR_C)

        # Economic criterion: default rule in GITHUB_PUBLIC vs exploratory permission in LOCAL_RESEARCH
        neg_pub = evaluate_economic_criterion(
            expected_reuses=10,
            old_cost="1.0",
            new_cost="0.9",
            build_cost="5.0",
            verify_cost="2.0",
            maintenance_reserve="1.0",
            profile=SecurityProfile.GITHUB_PUBLIC,
        )
        self.assertFalse(neg_pub.economically_justified)
        self.assertFalse(neg_pub.selected)

        neg_local = evaluate_economic_criterion(
            expected_reuses=10,
            old_cost="1.0",
            new_cost="0.9",
            build_cost="5.0",
            verify_cost="2.0",
            maintenance_reserve="1.0",
            profile=SecurityProfile.LOCAL_RESEARCH,
        )
        self.assertFalse(neg_local.economically_justified)
        self.assertFalse(neg_local.default_selection)
        self.assertTrue(neg_local.research_mode_permitted)
        self.assertTrue(neg_local.selected)

        pos_pub = evaluate_economic_criterion(
            expected_reuses=1000,
            old_cost="2.0",
            new_cost="0.2",
            build_cost="5.0",
            verify_cost="2.0",
            maintenance_reserve="1.0",
            profile=SecurityProfile.GITHUB_PUBLIC,
        )
        self.assertTrue(pos_pub.economically_justified)
        self.assertTrue(pos_pub.selected)

    def test_build_manifest_symlink_guard_and_tamper_detection(self) -> None:
        manifest_path = self.ws / ".kintsugi" / "build_manifests.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        target = self.outside / "evil.json"
        target.write_text("{}", encoding="utf-8")
        manifest_path.symlink_to(target)
        with self.assertRaises(PermissionError):
            BuildManifestStore(manifest_path)
        manifest_path.unlink()

        store = BuildManifestStore(manifest_path)
        b = ToolBuild(
            build_id="bld-manifest-1",
            tool_id="forge.sample",
            tool_version="1.0.0",
            state=ForgeState.PROPOSED,
        )
        recorded = store.record_build(b, set_active=False)
        self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
        self.assertIsNotNone(recorded.build_hash)

        # Tamper with persisted JSON -> load MUST fail closed
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        raw["builds"]["bld-manifest-1"]["tool_version"] = "9.9.9"
        manifest_path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ValueError):
            BuildManifestStore(manifest_path)

    @unittest.skipUnless(sys.platform == "darwin", "End-to-End Demo 3 OS sandbox requires Darwin Seatbelt host")
    def test_end_to_end_demo3_kvpipe_v1_forge_benchmark_compose_and_rollback(self) -> None:
        sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=[],
            network_allowed=False,
            allow_untrusted_native=False,
        )
        registry = ToolRegistry()
        registry.authority.register_verifier(FORGE_VERIFIER_ID, b"test-forge-hmac-authority-key-for-suite")
        gap_detector = CapabilityGapDetector()

        goal = {
            "goal_id": "goal-demo3-kvpipe-v1",
            "required_capabilities": ["log.parse.kvpipe.v1"],
            "input_artifacts": [{"capability": "log.parse.kvpipe.v1", "type": "string", "encoding": "utf-8"}],
            "expected_outputs": [{"capability": "log.parse.kvpipe.v1", "type": "object", "encoding": "json"}],
        }
        initial_gap = gap_detector.analyze(goal, registry, sec_ctx)
        self.assertFalse(initial_gap.is_satisfied)
        self.assertEqual(initial_gap.missing_capabilities, ["log.parse.kvpipe.v1"])

        forge = NativeToolForge(self.ws, profile=SecurityProfile.LOCAL_RESEARCH)
        task_v1 = build_kvpipe_v1_task_spec(
            tool_id="forge.kvpipe_v1_parser",
            version="1.0.0",
            gap_id=initial_gap.goal_id,
            fuzz_count=120,
            benchmark_lines=20000,
        )
        res_v1 = forge.forge_from_gap(initial_gap, registry=registry, task_spec=task_v1)

        self.assertTrue(res_v1.verified, msg=f"Demo 3 forge failed: {res_v1.reason}")
        self.assertEqual(res_v1.execution_status, ExecutionStatus.PASS)
        self.assertEqual(res_v1.build.state, ForgeState.VERIFIED)
        self.assertIsNotNone(res_v1.tool_spec)
        self.assertEqual(res_v1.tool_spec.trust_status, TrustStatus.VERIFIED)
        self.assertTrue(res_v1.tool_spec.runtime_requirements.get("ffi_forbidden"))
        self.assertTrue(res_v1.tool_spec.runtime_requirements.get("sandbox_required"))
        self.assertTrue(res_v1.sandbox_receipt is not None and res_v1.sandbox_receipt.isolated)

        # Verify all ToolBuild/1 provenance digests and schema required keys
        schema_path = REPO_ROOT / "schemas" / "tool_build.v1.schema.json"
        tb_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        build_dict = res_v1.build.to_dict()
        for req_key in tb_schema["required"]:
            self.assertIn(req_key, build_dict)
            self.assertTrue(build_dict[req_key] not in ("", None), msg=f"Empty {req_key}")

        # Verify benchmark metadata and positive speedup / non-regression
        self.assertIsNotNone(res_v1.benchmark_report)
        bench_dict = res_v1.benchmark_report.to_dict()
        self.assertIn("median_ms", bench_dict)
        self.assertIn("p95_ms", bench_dict)
        self.assertIn("cpu_arch", bench_dict)
        self.assertIn("seed", bench_dict)
        self.assertIn("input_distribution", bench_dict)
        self.assertIn("dataset", bench_dict)
        self.assertIn("economics", bench_dict)
        self.assertFalse(res_v1.benchmark_report.regressed)
        self.assertGreater(res_v1.benchmark_report.speedup_median, 1.0)

        # Capability gap is now satisfied and ToolResolver selects the newly forged verified tool
        post_gap = gap_detector.analyze(goal, registry, sec_ctx)
        self.assertTrue(post_gap.is_satisfied)
        resolver = ToolResolver()
        resolution = resolver.resolve(goal, registry, sec_ctx)
        self.assertEqual(resolution.status, ResolutionStatus.VERIFIED)
        self.assertEqual(
            resolution.selected_tools["log.parse.kvpipe.v1"].tool_id,
            "forge.kvpipe_v1_parser",
        )

        # Forged binary executes via SecureRunner (sandboxed binary execution, zero FFI)
        sample_log = self.ws / "sample.kvpipe"
        sample_log_bytes = b"TS=2026-11-21T19:00:00Z|LEVEL=INFO|MSG=hello\nBAD_LINE\n"
        sample_log.write_bytes(sample_log_bytes)
        runner = SecureRunner(attestation_authority=registry.authority)
        run_receipt = runner.run(
            res_v1.tool_spec,
            args={"path": "sample.kvpipe"},
            security_context=sec_ctx,
            argv=[str(res_v1.binary_path), str(sample_log)],
            oracle=lambda exec_res: json.loads(exec_res["stdout"]) == parse_kvpipe_v1_python(sample_log_bytes),
        )
        self.assertEqual(run_receipt.status, ExecutionStatus.PASS)

        # Verify ToolSpec output port is ready for composition via PortContract/1
        from kintsugi.capability.contracts_v2 import PortContract, ports_compatible

        consumer_port = PortContract(
            schema_ref="kvpipe.v1.parsed_records",
            semantic_type="parsed_log_records",
            encoding="json",
            unit="records",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
        )
        self.assertTrue(ports_compatible(res_v1.tool_spec.semantic_contract["output_port"], consumer_port).compatible)

        # Forge v1.1.0 (with genuine binary change via --version flag) and test atomic rollback to v1.0.0
        task_v2 = build_kvpipe_v1_task_spec(
            tool_id="forge.kvpipe_v1_parser",
            version="1.1.0",
            gap_id=initial_gap.goal_id,
            fuzz_count=110,
            benchmark_lines=20000,
        )
        task_v2.source_code = task_v2.source_code.replace(
            'FILE *in_fp = stdin;',
            'if (argc > 1 && strcmp(argv[1], "--version") == 0) { puts("1.1.0"); return 0; }\n    FILE *in_fp = stdin;',
            1,
        )
        res_v2 = forge.forge_tool(task_v2, registry=registry, security_context=sec_ctx)
        self.assertTrue(res_v2.verified, msg=res_v2.reason)
        self.assertNotEqual(res_v1.build.artifact_hash, res_v2.build.artifact_hash)
        self.assertEqual(
            res_v2.build.rollback_metadata.get("previous_artifact_hash"),
            res_v1.build.artifact_hash,
        )
        self.assertEqual(
            forge.manifest_store.get_active_build("forge.kvpipe_v1_parser").artifact_hash,
            res_v2.build.artifact_hash,
        )

        rb = forge.rollback(
            "forge.kvpipe_v1_parser",
            reason="regression_on_canary",
            registry=registry,
        )
        self.assertEqual(rb.rolled_back_build.state, ForgeState.ROLLED_BACK)
        self.assertEqual(rb.restored_artifact_hash, res_v1.build.artifact_hash)
        self.assertEqual(
            forge.manifest_store.get_active_build("forge.kvpipe_v1_parser").artifact_hash,
            res_v1.build.artifact_hash,
        )
        self.assertEqual(
            registry.get("forge.kvpipe_v1_parser").binary_hash,
            res_v1.build.artifact_hash,
        )

        # Reload manifest from disk to prove persistence & integrity check pass
        reloaded_store = BuildManifestStore(workspace_root=self.ws)
        self.assertEqual(
            reloaded_store.get_active_build("forge.kvpipe_v1_parser").artifact_hash,
            res_v1.build.artifact_hash,
        )

    def test_benchmark_regression_static_reject_and_docker_unavailable(self) -> None:
        # 1. Docker backend without configured image MUST return SANDBOX_UNAVAILABLE cleanly
        docker_sb = ToolSandbox(self.ws / "sb_docker", backend="docker", docker_image=None)
        d_probe = docker_sb.probe_isolation()
        self.assertFalse(d_probe.all_passed)
        d_res = docker_sb.execute(["/bin/echo", "hi"])
        self.assertEqual(d_res.execution_status, ExecutionStatus.SANDBOX_UNAVAILABLE)
        self.assertFalse(d_res.receipt.isolated)

        # 2. Static safety failure transitions build cleanly to REJECTED before compilation
        forge = NativeToolForge(self.ws / "forge_static_reject")
        bad_spec = build_kvpipe_v1_task_spec(tool_id="forge.bad_c", fuzz_count=100, benchmark_lines=200)
        bad_spec.source_code = "#include <sys/socket.h>\nint main(void){return 0;}\n"
        bad_res = forge.forge_tool(bad_spec)
        self.assertFalse(bad_res.verified)
        self.assertEqual(bad_res.build.state, ForgeState.REJECTED)
        self.assertIn("STATIC_SAFETY_SCAN_REJECTED", bad_res.reason)

        # 3. Benchmark detects latency regression and enforces economic criterion in GITHUB_PUBLIC
        import time

        bench = ToolBenchmark(warmup_iterations=1, measured_iterations=3, profile=SecurityProfile.GITHUB_PUBLIC)
        slow_report = bench.run(
            candidate_fn=lambda x: (time.sleep(0.01), x)[1],
            baseline_fn=lambda x: x,
            payload=b"abc",
            dataset_name="micro",
            input_distribution="constant",
            seed=1,
            compiler="clang",
            compiler_version="15.0",
            flags=["-O2"],
        )
        self.assertTrue(slow_report.regressed)
        self.assertFalse(slow_report.passed)

    @unittest.skipUnless(sys.platform == "darwin", "Multi-template OS sandbox requires Darwin Seatbelt host")
    def test_forge_from_gap_multi_template_jsonl_filter_and_csv_sum(self) -> None:
        sec_ctx = SecurityContext(
            workspace_root=str(self.ws),
            profile=SecurityProfile.LOCAL_RESEARCH,
            allowed_permissions=[],
            network_allowed=False,
            allow_untrusted_native=False,
        )
        forge = NativeToolForge(self.ws, profile=SecurityProfile.LOCAL_RESEARCH)
        expected_caps = {
            "log.parse.kvpipe.v1",
            "kvpipe.v1",
            "log.filter.jsonl_level.v1",
            "jsonl.filter",
            "data.csv_sum.v1",
            "csv.aggregate",
        }
        self.assertTrue(expected_caps.issubset(set(FORGE_TEMPLATE_REGISTRY.keys())))
        self.assertTrue(expected_caps.issubset(set(forge.list_templates())))

        # Custom template registration is exposed in list_templates()
        forge.register_template("custom.demo.v1", lambda gap_id=None: build_csv_sum_task_spec(gap_id=gap_id))
        self.assertIn("custom.demo.v1", forge.list_templates())

        # Unknown capability without task_spec raises cleanly
        gap_detector = CapabilityGapDetector()
        auth = AttestationAuthority({FORGE_VERIFIER_ID: b"native-forge-hmac-signing-key-alpha"})
        reg_path = self.ws / ".kintsugi" / "tool_registry.json"
        registry = ToolRegistry(reg_path, authority=auth)
        unknown_gap = gap_detector.analyze(
            {"goal_id": "goal-unknown-cap", "required_capabilities": ["unknown.capability.v99"]},
            registry,
            sec_ctx,
        )
        with self.assertRaises(ValueError) as ctx:
            forge.forge_from_gap(unknown_gap, registry=registry)
        self.assertIn("NO_SYNTHESIS_TEMPLATE_FOR_CAPABILITIES", str(ctx.exception))

        resolver = ToolResolver()
        runner = SecureRunner(attestation_authority=registry.authority)

        # 1. Dynamic forge_from_gap() synthesis for log.filter.jsonl_level.v1
        goal_jsonl = {
            "goal_id": "goal-jsonl-filter",
            "required_capabilities": ["log.filter.jsonl_level.v1"],
            "input_artifacts": [{"capability": "log.filter.jsonl_level.v1", "type": "string", "encoding": "utf-8"}],
            "expected_outputs": [{"capability": "log.filter.jsonl_level.v1", "type": "object", "encoding": "json"}],
        }
        gap_jsonl = gap_detector.analyze(goal_jsonl, registry, sec_ctx)
        self.assertEqual(gap_jsonl.missing_capabilities, ["log.filter.jsonl_level.v1"])

        res_jsonl = forge.forge_from_gap(gap_jsonl, registry=registry)
        self.assertTrue(res_jsonl.verified, msg=f"jsonl_level forge failed: {res_jsonl.reason}")
        self.assertEqual(res_jsonl.execution_status, ExecutionStatus.PASS)
        self.assertEqual(res_jsonl.build.state, ForgeState.VERIFIED)
        self.assertIsNotNone(res_jsonl.tool_spec)
        self.assertEqual(res_jsonl.tool_spec.trust_status, TrustStatus.VERIFIED)
        self.assertTrue(res_jsonl.sandbox_receipt is not None and res_jsonl.sandbox_receipt.isolated)
        self.assertIsNotNone(res_jsonl.benchmark_report)
        self.assertFalse(res_jsonl.benchmark_report.regressed)
        self.assertGreater(res_jsonl.benchmark_report.speedup_median, 1.0)
        self.assertTrue(
            auth.verify_attestation(
                res_jsonl.tool_spec.verification_attestation,
                expected_tool_id=res_jsonl.tool_spec.tool_id,
                expected_binary_hash=res_jsonl.tool_spec.binary_hash,
                expected_spec_digest=compute_tool_spec_security_digest(res_jsonl.tool_spec),
            )
        )
        self.assertEqual(
            resolver.resolve(goal_jsonl, registry, sec_ctx).selected_tools["log.filter.jsonl_level.v1"].tool_id,
            "forge.jsonl_level_filter",
        )

        sample_jsonl = self.ws / "sample.jsonl"
        sample_jsonl_bytes = (
            b'{"ts":1,"level":"INFO"}\n'
            b'{"ts":2,"level":"ERROR","msg":"boom"}\n'
            b'BAD_JSON_LINE\n'
            b'{"ts":4,"level":"critical"}\n'
        )
        sample_jsonl.write_bytes(sample_jsonl_bytes)
        run_jsonl = runner.run(
            res_jsonl.tool_spec,
            args={"path": "sample.jsonl"},
            security_context=sec_ctx,
            argv=[str(res_jsonl.binary_path), str(sample_jsonl)],
            oracle=lambda exec_res: json.loads(exec_res["stdout"]) == filter_jsonl_level_python(sample_jsonl_bytes),
        )
        self.assertEqual(run_jsonl.status, ExecutionStatus.PASS)

        # 2. Dynamic forge_from_gap() synthesis for data.csv_sum.v1 (including int64 overflow boundaries)
        goal_csv = {
            "goal_id": "goal-csv-sum",
            "required_capabilities": ["data.csv_sum.v1"],
            "input_artifacts": [{"capability": "data.csv_sum.v1", "type": "string", "encoding": "utf-8"}],
            "expected_outputs": [{"capability": "data.csv_sum.v1", "type": "object", "encoding": "json"}],
        }
        gap_csv = gap_detector.analyze(goal_csv, registry, sec_ctx)
        self.assertEqual(gap_csv.missing_capabilities, ["data.csv_sum.v1"])

        res_csv = forge.forge_from_gap(gap_csv, registry=registry)
        self.assertTrue(res_csv.verified, msg=f"csv_sum forge failed: {res_csv.reason}")
        self.assertEqual(res_csv.execution_status, ExecutionStatus.PASS)
        self.assertEqual(res_csv.build.state, ForgeState.VERIFIED)
        self.assertIsNotNone(res_csv.tool_spec)
        self.assertEqual(res_csv.tool_spec.trust_status, TrustStatus.VERIFIED)
        self.assertTrue(res_csv.sandbox_receipt is not None and res_csv.sandbox_receipt.isolated)
        self.assertIsNotNone(res_csv.benchmark_report)
        self.assertFalse(res_csv.benchmark_report.regressed)
        self.assertGreater(res_csv.benchmark_report.speedup_median, 1.0)
        self.assertTrue(
            auth.verify_attestation(
                res_csv.tool_spec.verification_attestation,
                expected_tool_id=res_csv.tool_spec.tool_id,
                expected_binary_hash=res_csv.tool_spec.binary_hash,
                expected_spec_digest=compute_tool_spec_security_digest(res_csv.tool_spec),
            )
        )
        self.assertEqual(
            resolver.resolve(goal_csv, registry, sec_ctx).selected_tools["data.csv_sum.v1"].tool_id,
            "forge.csv_sum",
        )

        sample_csv = self.ws / "sample.csv"
        sample_csv_bytes = b"10,20,30\r\n-5,15\r\nbad,row\r\n100\n"
        sample_csv.write_bytes(sample_csv_bytes)
        run_csv = runner.run(
            res_csv.tool_spec,
            args={"path": "sample.csv"},
            security_context=sec_ctx,
            argv=[str(res_csv.binary_path), str(sample_csv)],
            oracle=lambda exec_res: json.loads(exec_res["stdout"]) == sum_csv_python(sample_csv_bytes),
        )
        self.assertEqual(run_csv.status, ExecutionStatus.PASS)

        overflow_csv = self.ws / "overflow.csv"
        overflow_csv_bytes = b"9223372036854775807\n1\n"
        overflow_csv.write_bytes(overflow_csv_bytes)
        run_overflow = runner.run(
            res_csv.tool_spec,
            args={"path": "overflow.csv"},
            security_context=sec_ctx,
            argv=[str(res_csv.binary_path), str(overflow_csv)],
            oracle=lambda exec_res: (
                json.loads(exec_res["stdout"]) == sum_csv_python(overflow_csv_bytes)
                and json.loads(exec_res["stdout"])["overflow"] is True
            ),
        )
        self.assertEqual(run_overflow.status, ExecutionStatus.PASS)

        # Save and reload registry under same AttestationAuthority: signed forged tools verify cleanly
        registry.save()
        reloaded = ToolRegistry(reg_path, authority=auth)
        self.assertEqual(reloaded.get("forge.jsonl_level_filter").trust_status, TrustStatus.VERIFIED)
        self.assertEqual(reloaded.get("forge.csv_sum").trust_status, TrustStatus.VERIFIED)


if __name__ == "__main__":
    unittest.main()
