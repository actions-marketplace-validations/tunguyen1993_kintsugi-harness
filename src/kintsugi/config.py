"""Operating profile configuration and immutable security baseline (`kintsugi.config`)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, Mapping, Optional, Tuple, Union

from kintsugi.shield import assert_not_symlink

CONFIG_SCHEMA_VERSION = "KintsugiConfig/1"
PROFILE_LOCAL_RESEARCH = "LOCAL_RESEARCH"
PROFILE_GITHUB_PUBLIC = "GITHUB_PUBLIC"
_MAX_CONFIG_BYTES = 1024 * 1024

SECURITY_BASELINE_VALUES: Dict[str, bool] = {
    "enforce_pretooluse": True,
    "enforce_trusted_workspace": True,
    "external_trusted_policy_only": True,
    "deny_untrusted_network": True,
    "deny_host_admin": True,
    "protect_secrets": True,
    "require_approval_for_sensitive_actions": True,
    "allow_untrusted_native_on_host": False,
    "require_sandbox_for_untrusted_code": True,
    "prevent_rule_self_promotion": True,
}

_LOCAL_RESEARCH_SPECS: Dict[str, str] = {
    "artificial_token_limit": "opt_pos_int",
    "hard_model_call_limit": "opt_pos_int",
    "hard_agent_count_limit": "opt_pos_int",
    "hard_iteration_limit": "opt_pos_int",
    "hard_tool_candidate_limit": "opt_pos_int",
    "hard_composition_depth_limit": "opt_pos_int",
    "allow_exploratory_research_after_milestone": "bool",
    "deterministic_first": "bool",
    "adaptive_resource_scheduling": "bool",
    "checkpoint_and_resume": "bool",
    "resource_telemetry": "bool",
    "watchdog_enabled": "bool",
    "cancellation_enabled": "bool",
}

_GITHUB_PUBLIC_SPECS: Dict[str, str] = {
    "token_budget": "pos_int",
    "max_parallel_agents": "pos_int",
    "max_tool_probes": "pos_int",
    "max_composition_depth": "pos_int",
    "max_runtime_seconds": "pos_int",
    "max_memory_mb": "pos_int",
    "network_access": "bool",
    "automatic_package_installation": "bool",
    "require_approval_for_native_execution": "bool",
}

_TOP_LEVEL_KEYS: FrozenSet[str] = frozenset(
    {"config_schema", "profile", "local_research", "github_public", "security"}
)

_UNTRUSTED_FORBIDDEN_KEYS: FrozenSet[str] = frozenset(
    {
        "profile",
        "operating_profile",
        "config_schema",
        "security",
        "local_research",
        "github_public",
        "runtime",
        "limits",
        "policy",
        *SECURITY_BASELINE_VALUES.keys(),
    }
)

_DISABLE_SECURITY_ENV_FLAGS: FrozenSet[str] = frozenset(
    {
        "KINTSUGI_DISABLE_PRETOOLUSE",
        "KINTSUGI_BYPASS_SECURITY",
        "KINTSUGI_SKIP_SECURITY",
    }
)


class OperatingProfile(str, Enum):
    """Supported execution and resource-governance profiles."""

    LOCAL_RESEARCH = PROFILE_LOCAL_RESEARCH
    GITHUB_PUBLIC = PROFILE_GITHUB_PUBLIC


@dataclass(frozen=True)
class RuntimeFlags:
    """Runtime execution flags for scheduling, telemetry, watchdog, and cancellation."""

    deterministic_first: bool = True
    adaptive_resource_scheduling: bool = True
    checkpoint_and_resume: bool = True
    resource_telemetry: bool = True
    watchdog_enabled: bool = True
    cancellation_enabled: bool = True


@dataclass(frozen=True)
class LocalResearchConfig:
    """Unbounded local research defaults with deterministic-first runtime flags."""

    artificial_token_limit: Optional[int] = None
    hard_model_call_limit: Optional[int] = None
    hard_agent_count_limit: Optional[int] = None
    hard_iteration_limit: Optional[int] = None
    hard_tool_candidate_limit: Optional[int] = None
    hard_composition_depth_limit: Optional[int] = None
    allow_exploratory_research_after_milestone: bool = True
    deterministic_first: bool = True
    adaptive_resource_scheduling: bool = True
    checkpoint_and_resume: bool = True
    resource_telemetry: bool = True
    watchdog_enabled: bool = True
    cancellation_enabled: bool = True

    def __post_init__(self) -> None:
        _validate_typed_section("local_research", asdict(self), _LOCAL_RESEARCH_SPECS)


@dataclass(frozen=True)
class GithubPublicConfig:
    """Bounded, zero-network-by-default defaults for public GitHub / untrusted repos."""

    token_budget: int = 20000
    max_parallel_agents: int = 2
    max_tool_probes: int = 5
    max_composition_depth: int = 4
    max_runtime_seconds: int = 900
    max_memory_mb: int = 1024
    network_access: bool = False
    automatic_package_installation: bool = False
    require_approval_for_native_execution: bool = True

    def __post_init__(self) -> None:
        _validate_typed_section("github_public", asdict(self), _GITHUB_PUBLIC_SPECS)


@dataclass(frozen=True)
class SecurityBaselineConfig:
    """Immutable security invariants always enforced across all profiles."""

    enforce_pretooluse: bool = True
    enforce_trusted_workspace: bool = True
    external_trusted_policy_only: bool = True
    deny_untrusted_network: bool = True
    deny_host_admin: bool = True
    protect_secrets: bool = True
    require_approval_for_sensitive_actions: bool = True
    allow_untrusted_native_on_host: bool = False
    require_sandbox_for_untrusted_code: bool = True
    prevent_rule_self_promotion: bool = True

    def __post_init__(self) -> None:
        _validate_security_section(asdict(self))


@dataclass(frozen=True)
class KintsugiConfig:
    """Top-level Kintsugi Harness configuration (`KintsugiConfig/1`)."""

    config_schema: str = CONFIG_SCHEMA_VERSION
    profile: OperatingProfile = OperatingProfile.GITHUB_PUBLIC
    local_research: LocalResearchConfig = field(default_factory=LocalResearchConfig)
    github_public: GithubPublicConfig = field(default_factory=GithubPublicConfig)
    security: SecurityBaselineConfig = field(default_factory=SecurityBaselineConfig)

    def __post_init__(self) -> None:
        if self.config_schema != CONFIG_SCHEMA_VERSION:
            raise ValueError(f"Unsupported config_schema: {self.config_schema!r}")
        normalized_profile = _normalize_profile(self.profile)
        object.__setattr__(self, "profile", normalized_profile)
        if not isinstance(self.local_research, LocalResearchConfig):
            raise ValueError("local_research must be a LocalResearchConfig instance")
        if not isinstance(self.github_public, GithubPublicConfig):
            raise ValueError("github_public must be a GithubPublicConfig instance")
        if not isinstance(self.security, SecurityBaselineConfig):
            raise ValueError("security must be a SecurityBaselineConfig instance")
        _validate_security_section(asdict(self.security))

    @property
    def runtime(self) -> RuntimeFlags:
        """Return runtime orchestration flags derived from active configuration."""
        return RuntimeFlags(
            deterministic_first=self.local_research.deterministic_first,
            adaptive_resource_scheduling=self.local_research.adaptive_resource_scheduling,
            checkpoint_and_resume=self.local_research.checkpoint_and_resume,
            resource_telemetry=self.local_research.resource_telemetry,
            watchdog_enabled=self.local_research.watchdog_enabled,
            cancellation_enabled=self.local_research.cancellation_enabled,
        )

    def active_profile_settings(self) -> Union[LocalResearchConfig, GithubPublicConfig]:
        """Return the settings object corresponding to the currently active profile."""
        if self.profile == OperatingProfile.LOCAL_RESEARCH:
            return self.local_research
        return self.github_public

    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration to a schema-compliant JSON-ready dictionary."""
        return {
            "config_schema": self.config_schema,
            "profile": self.profile.value,
            "local_research": asdict(self.local_research),
            "github_public": asdict(self.github_public),
            "security": asdict(self.security),
        }

    def canonical_hash(self) -> str:
        """Compute deterministic SHA-256 content digest for this configuration."""
        return canonical_config_hash(self)

    @classmethod
    def for_profile(cls, profile: Union[str, OperatingProfile]) -> "KintsugiConfig":
        """Construct a default configuration for the given operating profile."""
        return cls(profile=_normalize_profile(profile))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "KintsugiConfig":
        """Validate a raw mapping against `KintsugiConfig/1` and instantiate."""
        validated = validate_config_dict(data)
        return cls(
            config_schema=validated["config_schema"],
            profile=OperatingProfile(validated["profile"]),
            local_research=LocalResearchConfig(**validated["local_research"]),
            github_public=GithubPublicConfig(**validated["github_public"]),
            security=SecurityBaselineConfig(**validated["security"]),
        )


def _normalize_profile(raw: Any) -> OperatingProfile:
    if isinstance(raw, OperatingProfile):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"Invalid operating profile: {raw!r}")
    token = raw.strip().upper()
    try:
        return OperatingProfile(token)
    except ValueError as exc:
        raise ValueError(
            f"Unsupported profile {raw!r}; expected LOCAL_RESEARCH or GITHUB_PUBLIC"
        ) from exc


def _validate_value_kind(section: str, key: str, value: Any, kind: str) -> None:
    if kind == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{section}.{key} must be a boolean, got {type(value).__name__}")
        return
    if kind == "pos_int":
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{section}.{key} must be a positive integer >= 1, got {value!r}")
        return
    if kind == "opt_pos_int":
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 1):
            raise ValueError(f"{section}.{key} must be None or a positive integer >= 1, got {value!r}")
        return
    raise ValueError(f"Unknown field spec kind {kind!r} for {section}.{key}")


def _validate_typed_section(
    section_name: str,
    raw_section: Mapping[str, Any],
    specs: Mapping[str, str],
) -> Dict[str, Any]:
    if not isinstance(raw_section, Mapping):
        raise ValueError(f"{section_name} must be a mapping")
    unknown = sorted(set(raw_section.keys()) - set(specs.keys()))
    if unknown:
        raise ValueError(f"Unknown keys in {section_name}: {unknown}")
    out: Dict[str, Any] = {}
    for key, value in raw_section.items():
        _validate_value_kind(section_name, key, value, specs[key])
        out[key] = value
    return out


def _validate_security_section(raw_security: Mapping[str, Any]) -> Dict[str, bool]:
    if not isinstance(raw_security, Mapping):
        raise ValueError("security section must be a mapping")
    unknown = sorted(set(raw_security.keys()) - set(SECURITY_BASELINE_VALUES.keys()))
    if unknown:
        raise ValueError(f"Unknown keys in security section: {unknown}")
    out = dict(SECURITY_BASELINE_VALUES)
    for key, val in raw_security.items():
        if not isinstance(val, bool):
            raise ValueError(f"security.{key} must be a boolean, got {type(val).__name__}")
        expected = SECURITY_BASELINE_VALUES[key]
        if val is not expected:
            raise PermissionError(
                f"SECURITY_BASELINE_LOCKED: Cannot weaken security.{key} "
                f"(required={expected}, got={val})"
            )
        out[key] = val
    return out


def _default_config_dict(profile: OperatingProfile = OperatingProfile.GITHUB_PUBLIC) -> Dict[str, Any]:
    return {
        "config_schema": CONFIG_SCHEMA_VERSION,
        "profile": profile.value,
        "local_research": asdict(LocalResearchConfig()),
        "github_public": asdict(GithubPublicConfig()),
        "security": dict(SECURITY_BASELINE_VALUES),
    }


def _validate_raw_config_mapping(
    data: Mapping[str, Any],
    *,
    require_schema: bool,
    require_profile: bool,
) -> Dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ValueError("Configuration payload must be a JSON object / mapping")
    if "untrusted_metadata" in data:
        raise PermissionError("UNTRUSTED_CONFIG_OVERRIDE_REJECTED: untrusted_metadata is forbidden inside config")
    unknown = sorted(set(data.keys()) - _TOP_LEVEL_KEYS)
    if unknown:
        raise ValueError(f"Unknown top-level configuration keys: {unknown}")

    if require_schema or "config_schema" in data:
        schema_val = data.get("config_schema")
        if schema_val != CONFIG_SCHEMA_VERSION:
            raise ValueError(f"Invalid config_schema {schema_val!r}; expected {CONFIG_SCHEMA_VERSION!r}")

    if require_profile or "profile" in data:
        profile_val = _normalize_profile(data.get("profile")).value
    else:
        profile_val = OperatingProfile.GITHUB_PUBLIC.value

    normalized = _default_config_dict(OperatingProfile(profile_val))
    if "local_research" in data:
        lr_validated = _validate_typed_section("local_research", data["local_research"], _LOCAL_RESEARCH_SPECS)
        normalized["local_research"].update(lr_validated)
    if "github_public" in data:
        gp_validated = _validate_typed_section("github_public", data["github_public"], _GITHUB_PUBLIC_SPECS)
        normalized["github_public"].update(gp_validated)
    if "security" in data:
        normalized["security"] = _validate_security_section(data["security"])
    return normalized


def validate_config_dict(data: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Validate a complete `KintsugiConfig/1` mapping with strict key allowlists and
    immutable security baseline checks, returning the normalized dictionary.
    """
    return _validate_raw_config_mapping(data, require_schema=True, require_profile=True)


def canonical_config_hash(cfg: Union[KintsugiConfig, Mapping[str, Any]]) -> str:
    """Return deterministic `sha256:...` digest of a validated `KintsugiConfig/1`."""
    if isinstance(cfg, KintsugiConfig):
        payload = cfg.to_dict()
    elif isinstance(cfg, Mapping):
        payload = validate_config_dict(cfg)
    else:
        raise TypeError(f"Expected KintsugiConfig or Mapping, got {type(cfg).__name__}")
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _is_path_within(candidate: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(root), str(candidate)]) == str(root)
    except ValueError:
        return False


def _load_external_config_file(
    external_config_path: Union[str, Path],
    target_repo_root: Optional[Union[str, Path]],
) -> Dict[str, Any]:
    raw_str = str(external_config_path).strip()
    if not raw_str:
        raise ValueError("external_config_path must not be blank")
    cfg_path = Path(raw_str)
    assert_not_symlink(cfg_path)
    if cfg_path.parent.is_symlink():
        raise PermissionError(
            f"SECURITY_SYMLINK_REFUSED: Parent directory of external_config_path is a symlink: {cfg_path.parent}"
        )

    if target_repo_root is not None:
        repo_path = Path(str(target_repo_root))
        repo_abs = Path(os.path.abspath(str(repo_path)))
        repo_real = Path(os.path.realpath(str(repo_path)))
        cfg_abs = Path(os.path.abspath(str(cfg_path)))
        cfg_real = Path(os.path.realpath(str(cfg_path)))
        in_kintsugi_ancestor = (
            cfg_real.parent.name == ".kintsugi"
            and _is_path_within(repo_real, cfg_real.parent.parent)
        )
        if (
            _is_path_within(cfg_abs, repo_abs)
            or _is_path_within(cfg_real, repo_real)
            or in_kintsugi_ancestor
        ):
            raise PermissionError(
                f"KH-R3-SEC-01: Refusing external_config_path inside target_repo_root ({cfg_real})."
            )

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(cfg_path), open_flags)
    except OSError as exc:
        if cfg_path.is_symlink():
            raise PermissionError(f"SECURITY_SYMLINK_REFUSED: {cfg_path}") from exc
        raise
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"KH-R3-SEC-01: external_config_path must be a regular file: {cfg_path}")
        raw_bytes = handle.read(_MAX_CONFIG_BYTES + 1)
    if len(raw_bytes) > _MAX_CONFIG_BYTES:
        raise ValueError(f"external_config_path exceeds maximum allowed size ({_MAX_CONFIG_BYTES} bytes)")
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid UTF-8 JSON in external_config_path {cfg_path}: {exc}") from exc
    return validate_config_dict(parsed)


def _parse_env_bool(name: str, raw_val: str) -> bool:
    token = raw_val.strip().lower()
    if token in {"1", "true", "yes", "on"}:
        return True
    if token in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value for environment variable {name}: {raw_val!r}")


def _extract_env_overrides(env: Optional[Mapping[str, str]]) -> Optional[OperatingProfile]:
    env_map: Mapping[str, str] = os.environ if env is None else env
    if not isinstance(env_map, Mapping):
        raise ValueError("env must be a mapping of string keys to string values")

    for flag_name in _DISABLE_SECURITY_ENV_FLAGS:
        if flag_name in env_map and str(env_map[flag_name]).strip():
            if _parse_env_bool(flag_name, str(env_map[flag_name])):
                raise PermissionError(
                    f"SECURITY_BASELINE_LOCKED: Environment variable {flag_name} is forbidden"
                )

    for sec_key, required_val in SECURITY_BASELINE_VALUES.items():
        for prefix in ("KINTSUGI_", "KINTSUGI_SECURITY_"):
            env_key = f"{prefix}{sec_key.upper()}"
            if env_key in env_map and str(env_map[env_key]).strip():
                parsed = _parse_env_bool(env_key, str(env_map[env_key]))
                if parsed is not required_val:
                    raise PermissionError(
                        f"SECURITY_BASELINE_LOCKED: Environment variable {env_key} "
                        f"cannot weaken {sec_key} (required={required_val}, got={parsed})"
                    )

    raw_profile = str(env_map.get("KINTSUGI_PROFILE", "")).strip()
    if raw_profile:
        return _normalize_profile(raw_profile)
    return None


def _reject_untrusted_metadata(untrusted_metadata: Optional[Mapping[str, Any]], depth: int = 0) -> None:
    if untrusted_metadata is None:
        return
    if depth > 16:
        raise ValueError("untrusted_metadata nesting exceeds maximum depth")
    if not isinstance(untrusted_metadata, Mapping):
        raise ValueError("untrusted_metadata must be a mapping when provided")
    for raw_key, val in untrusted_metadata.items():
        key_lower = str(raw_key).strip().lower()
        if key_lower in _UNTRUSTED_FORBIDDEN_KEYS:
            raise PermissionError(
                f"UNTRUSTED_CONFIG_OVERRIDE_REJECTED: untrusted_metadata cannot supply '{raw_key}'"
            )
        if isinstance(val, Mapping):
            _reject_untrusted_metadata(val, depth=depth + 1)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, Mapping):
                    _reject_untrusted_metadata(item, depth=depth + 1)


def _merge_layer(
    merged: Dict[str, Any],
    layer: Mapping[str, Any],
    *,
    allow_partial: bool,
) -> None:
    if "profile" in layer:
        merged["profile"] = _normalize_profile(layer["profile"]).value
    for section in ("local_research", "github_public"):
        if section in layer:
            specs = _LOCAL_RESEARCH_SPECS if section == "local_research" else _GITHUB_PUBLIC_SPECS
            validated = _validate_typed_section(section, layer[section], specs)
            merged[section].update(validated)
    if "security" in layer:
        merged["security"] = _validate_security_section(layer["security"])
    if not allow_partial and "config_schema" not in layer:
        raise ValueError("Full config layer must declare config_schema")


def resolve_kintsugi_config(
    owner_policy: Optional[Mapping[str, Any]] = None,
    external_config_path: Optional[Union[str, Path]] = None,
    cli_profile: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    target_repo_root: Optional[Union[str, Path]] = None,
    untrusted_metadata: Optional[Mapping[str, Any]] = None,
) -> KintsugiConfig:
    """
    Resolve effective `KintsugiConfig/1` with strict trust boundaries and precedence:
      default (GITHUB_PUBLIC) < external_config_path < env < cli_profile < owner_policy.

    Security baseline flags are immutable across all profiles and layers.
    Untrusted metadata overrides and symlinks / in-repo external configs (`KH-R3-SEC-01`)
    are strictly rejected fail-closed.
    """
    _reject_untrusted_metadata(untrusted_metadata)
    merged = _default_config_dict(OperatingProfile.GITHUB_PUBLIC)

    if external_config_path is not None:
        ext_data = _load_external_config_file(external_config_path, target_repo_root)
        _merge_layer(merged, ext_data, allow_partial=False)

    env_profile = _extract_env_overrides(env)
    if env_profile is not None:
        merged["profile"] = env_profile.value

    if cli_profile is not None and str(cli_profile).strip():
        merged["profile"] = _normalize_profile(cli_profile).value

    if owner_policy is not None:
        _validate_raw_config_mapping(owner_policy, require_schema=False, require_profile=False)
        _merge_layer(merged, owner_policy, allow_partial=True)

    return KintsugiConfig.from_dict(merged)
