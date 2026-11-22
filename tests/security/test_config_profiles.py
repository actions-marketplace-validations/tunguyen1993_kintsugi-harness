"""Security and profile contract tests for `kintsugi.config` and `schemas/*.v1.schema.json`."""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path

from kintsugi.config import (
    CONFIG_SCHEMA_VERSION,
    SECURITY_BASELINE_VALUES,
    GithubPublicConfig,
    KintsugiConfig,
    LocalResearchConfig,
    OperatingProfile,
    SecurityBaselineConfig,
    canonical_config_hash,
    resolve_kintsugi_config,
    validate_config_dict,
)
from kintsugi.evolution_v2 import FailureEnvelope, synthesize_rule_ir

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "schemas"

EXPECTED_SCHEMA_FILES = (
    "kintsugi_config.v1.schema.json",
    "tool_spec.v1.schema.json",
    "capability_gap.v1.schema.json",
    "security_context.v1.schema.json",
    "execution_receipt.v1.schema.json",
    "experience.v1.schema.json",
    "composition_plan.v1.schema.json",
    "tool_build.v1.schema.json",
    "run_event.v1.schema.json",
    "rule_ir.v1.schema.json",
)


class TestKintsugiConfigProfilesAndSecurity(unittest.TestCase):
    """Verify operating profiles, immutable security invariants, and KH-R3-SEC-01 isolation."""

    def test_local_research_defaults(self) -> None:
        cfg = KintsugiConfig.for_profile("LOCAL_RESEARCH")
        self.assertEqual(cfg.config_schema, CONFIG_SCHEMA_VERSION)
        self.assertEqual(cfg.profile, OperatingProfile.LOCAL_RESEARCH)
        self.assertEqual(cfg.profile, "LOCAL_RESEARCH")

        lr = cfg.local_research
        self.assertIsNone(lr.artificial_token_limit)
        self.assertIsNone(lr.hard_model_call_limit)
        self.assertIsNone(lr.hard_agent_count_limit)
        self.assertIsNone(lr.hard_iteration_limit)
        self.assertIsNone(lr.hard_tool_candidate_limit)
        self.assertIsNone(lr.hard_composition_depth_limit)
        self.assertTrue(lr.allow_exploratory_research_after_milestone)
        self.assertTrue(lr.deterministic_first)
        self.assertTrue(lr.adaptive_resource_scheduling)
        self.assertTrue(lr.checkpoint_and_resume)
        self.assertTrue(lr.resource_telemetry)
        self.assertTrue(lr.watchdog_enabled)
        self.assertTrue(lr.cancellation_enabled)
        self.assertTrue(cfg.runtime.watchdog_enabled)
        self.assertEqual(cfg.active_profile_settings(), lr)

    def test_github_public_defaults(self) -> None:
        cfg = resolve_kintsugi_config(env={})
        self.assertEqual(cfg.config_schema, "KintsugiConfig/1")
        self.assertEqual(cfg.profile, OperatingProfile.GITHUB_PUBLIC)

        gp = cfg.github_public
        self.assertEqual(gp.token_budget, 20000)
        self.assertEqual(gp.max_parallel_agents, 2)
        self.assertEqual(gp.max_tool_probes, 5)
        self.assertEqual(gp.max_composition_depth, 4)
        self.assertEqual(gp.max_runtime_seconds, 900)
        self.assertEqual(gp.max_memory_mb, 1024)
        self.assertFalse(gp.network_access)
        self.assertFalse(gp.automatic_package_installation)
        self.assertTrue(gp.require_approval_for_native_execution)
        self.assertEqual(cfg.active_profile_settings(), gp)

    def test_security_baseline_enforced_across_both_profiles(self) -> None:
        for profile in ("LOCAL_RESEARCH", "GITHUB_PUBLIC"):
            cfg = KintsugiConfig.for_profile(profile)
            sec = cfg.security
            self.assertTrue(sec.enforce_pretooluse)
            self.assertTrue(sec.enforce_trusted_workspace)
            self.assertTrue(sec.external_trusted_policy_only)
            self.assertTrue(sec.deny_untrusted_network)
            self.assertTrue(sec.deny_host_admin)
            self.assertTrue(sec.protect_secrets)
            self.assertTrue(sec.require_approval_for_sensitive_actions)
            self.assertFalse(sec.allow_untrusted_native_on_host)
            self.assertTrue(sec.require_sandbox_for_untrusted_code)
            self.assertTrue(sec.prevent_rule_self_promotion)

    def test_rejects_weakening_every_security_boolean_via_config_and_owner_policy(self) -> None:
        for key, baseline_val in SECURITY_BASELINE_VALUES.items():
            weakened_val = not baseline_val
            with self.assertRaises(PermissionError):
                SecurityBaselineConfig(**{key: weakened_val})
            for profile in ("LOCAL_RESEARCH", "GITHUB_PUBLIC"):
                payload = {
                    "config_schema": "KintsugiConfig/1",
                    "profile": profile,
                    "security": {key: weakened_val},
                }
                with self.assertRaises(PermissionError):
                    validate_config_dict(payload)
                with self.assertRaises(PermissionError):
                    resolve_kintsugi_config(
                        owner_policy={"profile": profile, "security": {key: weakened_val}},
                        env={},
                    )

    def test_rejects_weakening_security_via_env(self) -> None:
        for key, baseline_val in SECURITY_BASELINE_VALUES.items():
            weakened_str = "false" if baseline_val else "true"
            for prefix in ("KINTSUGI_", "KINTSUGI_SECURITY_"):
                with self.assertRaises(PermissionError):
                    resolve_kintsugi_config(env={f"{prefix}{key.upper()}": weakened_str})
        with self.assertRaises(PermissionError):
            resolve_kintsugi_config(env={"KINTSUGI_DISABLE_PRETOOLUSE": "1"})

    def test_rejects_external_config_symlink_and_in_repo_paths_kh_r3_sec_01(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo_dir = tmp_path / "target_repo"
            repo_dir.mkdir(parents=True)
            trusted_dir = tmp_path / "trusted_outside"
            trusted_dir.mkdir(parents=True)

            valid_cfg_payload = {
                "config_schema": "KintsugiConfig/1",
                "profile": "LOCAL_RESEARCH",
            }
            outside_cfg = trusted_dir / "kintsugi.config.json"
            outside_cfg.write_text(json.dumps(valid_cfg_payload), encoding="utf-8")

            in_repo_cfg = repo_dir / ".kintsugi" / "config.json"
            in_repo_cfg.parent.mkdir(parents=True)
            in_repo_cfg.write_text(json.dumps(valid_cfg_payload), encoding="utf-8")

            # 1. Valid external config outside target_repo_root works.
            resolved = resolve_kintsugi_config(
                external_config_path=outside_cfg,
                target_repo_root=repo_dir,
                env={},
            )
            self.assertEqual(resolved.profile, OperatingProfile.LOCAL_RESEARCH)

            # 2. In-repo config path rejected fail-closed.
            with self.assertRaises(PermissionError):
                resolve_kintsugi_config(
                    external_config_path=in_repo_cfg,
                    target_repo_root=repo_dir,
                    env={},
                )

            # 3. Symlink file pointing to valid out-of-repo file rejected.
            symlink_cfg = trusted_dir / "link.config.json"
            os.symlink(str(outside_cfg), str(symlink_cfg))
            with self.assertRaises(PermissionError):
                resolve_kintsugi_config(
                    external_config_path=symlink_cfg,
                    target_repo_root=repo_dir,
                    env={},
                )

            # 4. Symlinked parent directory pointing into target_repo_root rejected.
            escaped_dir = tmp_path / "escaped_dir"
            os.symlink(str(repo_dir / ".kintsugi"), str(escaped_dir))
            with self.assertRaises(PermissionError):
                resolve_kintsugi_config(
                    external_config_path=escaped_dir / "config.json",
                    target_repo_root=repo_dir,
                    env={},
                )

            # 5. External config with weakened security rejected.
            weak_cfg = trusted_dir / "weak.config.json"
            weak_cfg.write_text(
                json.dumps(
                    {
                        "config_schema": "KintsugiConfig/1",
                        "profile": "GITHUB_PUBLIC",
                        "security": {"enforce_pretooluse": False},
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(PermissionError):
                resolve_kintsugi_config(
                    external_config_path=weak_cfg,
                    target_repo_root=repo_dir,
                    env={},
                )

    def test_rejects_untrusted_metadata_overrides(self) -> None:
        with self.assertRaises(PermissionError):
            resolve_kintsugi_config(
                env={},
                untrusted_metadata={"profile": "LOCAL_RESEARCH"},
            )
        with self.assertRaises(PermissionError):
            resolve_kintsugi_config(
                env={},
                untrusted_metadata={"nested": {"security": {"protect_secrets": False}}},
            )
        with self.assertRaises(PermissionError):
            validate_config_dict(
                {
                    "config_schema": "KintsugiConfig/1",
                    "profile": "GITHUB_PUBLIC",
                    "untrusted_metadata": {"profile": "LOCAL_RESEARCH"},
                }
            )
        # Non-override tool metadata does not block legitimate config resolution.
        cfg = resolve_kintsugi_config(
            env={},
            untrusted_metadata={"tool_name": "read_file", "trace": [{"step": 1}]},
        )
        self.assertEqual(cfg.profile, OperatingProfile.GITHUB_PUBLIC)

    def test_precedence_and_partial_layering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ext_cfg = tmp_path / "ext.json"
            ext_cfg.write_text(
                json.dumps(
                    {
                        "config_schema": "KintsugiConfig/1",
                        "profile": "LOCAL_RESEARCH",
                        "github_public": {"token_budget": 15000},
                    }
                ),
                encoding="utf-8",
            )
            # env overrides external_config_path profile
            c_env = resolve_kintsugi_config(
                external_config_path=ext_cfg,
                env={"KINTSUGI_PROFILE": "GITHUB_PUBLIC"},
            )
            self.assertEqual(c_env.profile, OperatingProfile.GITHUB_PUBLIC)
            self.assertEqual(c_env.github_public.token_budget, 15000)

            # cli_profile overrides env
            c_cli = resolve_kintsugi_config(
                external_config_path=ext_cfg,
                env={"KINTSUGI_PROFILE": "GITHUB_PUBLIC"},
                cli_profile="LOCAL_RESEARCH",
            )
            self.assertEqual(c_cli.profile, OperatingProfile.LOCAL_RESEARCH)

            # owner_policy overrides cli_profile and env
            c_owner = resolve_kintsugi_config(
                owner_policy={"profile": "GITHUB_PUBLIC", "github_public": {"max_parallel_agents": 1}},
                external_config_path=ext_cfg,
                env={"KINTSUGI_PROFILE": "LOCAL_RESEARCH"},
                cli_profile="LOCAL_RESEARCH",
            )
            self.assertEqual(c_owner.profile, OperatingProfile.GITHUB_PUBLIC)
            self.assertEqual(c_owner.github_public.token_budget, 15000)
            self.assertEqual(c_owner.github_public.max_parallel_agents, 1)

    def test_validation_rejects_bad_types_and_canonical_hash_is_deterministic(self) -> None:
        with self.assertRaises(ValueError):
            validate_config_dict({"config_schema": "Wrong/1", "profile": "GITHUB_PUBLIC"})
        with self.assertRaises(ValueError):
            validate_config_dict({"config_schema": "KintsugiConfig/1", "profile": "UNKNOWN"})
        with self.assertRaises(ValueError):
            validate_config_dict(
                {"config_schema": "KintsugiConfig/1", "profile": "GITHUB_PUBLIC", "extra_key": 1}
            )
        with self.assertRaises(ValueError):
            GithubPublicConfig(token_budget=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            LocalResearchConfig(artificial_token_limit=0)

        d1 = {"profile": "LOCAL_RESEARCH", "config_schema": "KintsugiConfig/1"}
        d2 = {"config_schema": "KintsugiConfig/1", "profile": "LOCAL_RESEARCH"}
        h1 = canonical_config_hash(d1)
        h2 = canonical_config_hash(KintsugiConfig.from_dict(d2))
        self.assertEqual(h1, h2)
        self.assertRegex(h1, r"^sha256:[0-9a-f]{64}$")
        self.assertNotEqual(h1, canonical_config_hash(KintsugiConfig.for_profile("GITHUB_PUBLIC")))

    def test_all_ten_v1_schemas_valid_and_match_config_and_rule_ir(self) -> None:
        for fname in EXPECTED_SCHEMA_FILES:
            fpath = SCHEMAS_DIR / fname
            self.assertTrue(fpath.is_file(), f"Missing schema file: {fpath}")
            doc = json.loads(fpath.read_text(encoding="utf-8"))
            self.assertEqual(doc["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(doc["type"], "object")
            self.assertIn("required", doc)
            self.assertIn("properties", doc)

        # Verify KintsugiConfig.to_dict() keys and security constants match kintsugi_config.v1.schema.json
        cfg_schema = json.loads((SCHEMAS_DIR / "kintsugi_config.v1.schema.json").read_text(encoding="utf-8"))
        cfg_dict = KintsugiConfig.for_profile("LOCAL_RESEARCH").to_dict()
        self.assertEqual(set(cfg_dict.keys()), set(cfg_schema["properties"].keys()))
        for req_key in cfg_schema["required"]:
            self.assertIn(req_key, cfg_dict)
        for sec_k, sec_prop in cfg_schema["properties"]["security"]["properties"].items():
            self.assertEqual(cfg_dict["security"][sec_k], sec_prop["const"])

        # Verify RuleIR.to_dict() matches rule_ir.v1.schema.json
        rule_schema = json.loads((SCHEMAS_DIR / "rule_ir.v1.schema.json").read_text(encoding="utf-8"))
        env = FailureEnvelope.create(
            task_id="schema-parity-check",
            language="python",
            offending_snippet="cfg = yaml.load(raw, Loader=yaml.Loader)",
            fixed_snippet="cfg = yaml.safe_load(raw)",
            error_summary="Unsafe YAML load",
        )
        rule = synthesize_rule_ir(
            env,
            bad_code="cfg = yaml.load(raw, Loader=yaml.Loader)",
            good_code="cfg = yaml.safe_load(raw)",
            rule_id="KS-EVO-900123",
        )
        rule_dict = rule.to_dict()
        self.assertTrue(set(rule_dict.keys()).issubset(set(rule_schema["properties"].keys())))
        for req_key in rule_schema["required"]:
            self.assertIn(req_key, rule_dict)
        self.assertRegex(rule_dict["rule_hash"], rule_schema["properties"]["rule_hash"]["pattern"])
        self.assertTrue(re.match(rule_schema["properties"]["rule_id"]["pattern"], rule_dict["rule_id"]))


if __name__ == "__main__":
    unittest.main()
