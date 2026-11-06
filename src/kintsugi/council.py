"""
Three-Agent Adversarial Self-Evolution Council + Deterministic Self-Verification Gate.

Architecture:
1. Architect Agent (e.g. Gemini)   -> Diagnoses root cause & extracts clean bad/good code pairs.
2. Synthesizer Agent (e.g. DeepSeek)-> Synthesizes deterministic AST or Regex rule + GoldenScar JSON.
3. Red-Team Critic (e.g. Muse)      -> Challenges false positives, evasion vectors, and context bloat.
4. Deterministic Verification Gate  -> Runs KintsugiScanner in-memory:
     - `scan(bad_code)` MUST detect >= 1 violation (True Positive guaranteed).
     - `scan(good_code)` MUST detect 0 violations (Zero False Positive guaranteed).
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from kintsugi.models import FailureTrace, GoldenScar, Severity
from kintsugi.scanner import KintsugiScanner
from kintsugi.shield import audit_scar_security


@dataclass
class AgentEndpoint:
    """OpenAI-compatible chat completion endpoint configuration for one Council or Co-Runner seat."""

    role: str
    model: str
    base_url: str
    api_key: str
    timeout_sec: int = 45
    provider_id: str = "custom"
    model_family: str = "independent"
    source: str = "PRIMARY_ANCHOR"
    billing_usd: float = 0.0
    extra_body: Optional[Dict[str, Any]] = None


def verify_candidate_scar(scar: GoldenScar) -> Tuple[bool, str]:
    """
    Deterministic self-check gate: a GoldenScar is only accepted if:
    1. It passes the 7-Layer Zero-Trust Evolution Shield (`audit_scar_security`).
    2. Its executable AST/Regex rule catches `scar.bad_code` AND stays silent on `scar.good_code`.
    """
    shield_ok, shield_msg = audit_scar_security(scar)
    if not shield_ok:
        return False, f"Security shield rejected scar: {shield_msg}"
    if not scar.regex_pattern and not scar.ast_rule:
        return False, "Candidate scar must define either `regex_pattern` or `ast_rule`."
    if not scar.bad_code.strip() or not scar.good_code.strip():
        return False, "Candidate scar must include non-empty `bad_code` and `good_code`."

    try:
        scanner = KintsugiScanner([scar])
    except re.error as exc:
        return False, f"Invalid regex_pattern: {exc}"

    primary_lang = scar.languages[0] if scar.languages else "python"
    bad_hits = scanner.scan_text(scar.bad_code, file_path=f"<bad.{primary_lang}>", language=primary_lang)
    if not bad_hits:
        return False, "True-positive check failed: scanner produced 0 findings on `bad_code`."

    good_hits = scanner.scan_text(scar.good_code, file_path=f"<good.{primary_lang}>", language=primary_lang)
    if good_hits:
        return False, (
            f"False-positive check failed: scanner matched `good_code` on line {good_hits[0].line}."
        )

    return True, "PASS: True-positive and zero-false-positive invariants verified."


def _extract_json_object(raw_text: str) -> Dict[str, Any]:
    """
    Robustly locate and parse a GoldenScar JSON dictionary even when surrounding
    model reasoning contains `${template}` braces or non-JSON code blocks.
    """
    cleaned = re.sub(r"<think(?:ing)?>[\s\S]*?</think(?:ing)?>", "", raw_text, flags=re.IGNORECASE)
    decoder = json.JSONDecoder()
    best_dict: Optional[Dict[str, Any]] = None

    for match in re.finditer(r"\{", cleaned):
        start_idx = match.start()
        try:
            obj, _ = decoder.raw_decode(cleaned, start_idx)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            if "title" in obj and ("bad_code" in obj or "regex_pattern" in obj or "ast_rule" in obj):
                return obj
            best_dict = obj

    if best_dict is not None:
        return best_dict
    raise ValueError("Model response did not contain a valid JSON object.")


def call_openai_compatible(endpoint: AgentEndpoint, system_prompt: str, user_prompt: str) -> str:
    """Invoke any OpenAI-compatible `/chat/completions` API using pure stdlib urllib."""
    url = endpoint.base_url.rstrip("/") + "/chat/completions"
    payload_dict: Dict[str, Any] = {
        "model": endpoint.model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }
    if endpoint.extra_body:
        payload_dict.update(endpoint.extra_body)
    body = json.dumps(payload_dict).encode("utf-8")
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "kintsugi-harness/1.3.0",
    }
    if endpoint.api_key:
        headers["Authorization"] = f"Bearer {endpoint.api_key}"
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(req, timeout=endpoint.timeout_sec) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("Empty choices returned by model endpoint.")
    msg = choices[0].get("message") or {}
    return str(msg.get("content") or "")


@dataclass
class FreePoolSlot:
    """Normalized descriptor for a discovered $0 Free Co-Runner or BYOK Paid Council seat."""

    slot_id: str
    provider_id: str
    model: str
    model_family: str
    base_url: str
    api_key: str
    source: str
    billing_usd: float = 0.0
    credit_card_required: bool = False
    is_paid_byok: bool = False
    bft_weight: float = 1.0
    timeout_sec: int = 25
    extra_body: Optional[Dict[str, Any]] = None
    failure_count: int = 0
    cooldown_until: float = 0.0
    last_latency_ms: float = 0.0

    def is_available(self, now_mono: Optional[float] = None) -> bool:
        now_val = time.monotonic() if now_mono is None else now_mono
        return now_val >= self.cooldown_until

    def to_endpoint(self, role: str = "free_corunner") -> AgentEndpoint:
        return AgentEndpoint(
            role=role,
            model=self.model,
            base_url=self.base_url,
            api_key=self.api_key,
            timeout_sec=self.timeout_sec,
            provider_id=self.provider_id,
            model_family=self.model_family,
            source=self.source,
            billing_usd=self.billing_usd,
            extra_body=self.extra_body,
        )

    def to_public_dict(self) -> Dict[str, Any]:
        masked = "keyless"
        if self.api_key and self.api_key not in ("free-local", "keyless"):
            k = self.api_key.strip()
            masked = f"{k[:4]}***{k[-4:]}" if len(k) > 8 else "***"
        return {
            "slot_id": self.slot_id,
            "provider_id": self.provider_id,
            "model": self.model,
            "model_family": self.model_family,
            "base_url": self.base_url,
            "source": self.source,
            "masked_key": masked,
            "billing_usd": self.billing_usd,
            "credit_card_required": self.credit_card_required,
            "is_paid_byok": self.is_paid_byok,
            "bft_weight": self.bft_weight,
            "available": self.is_available(),
            "failure_count": self.failure_count,
            "last_latency_ms": round(self.last_latency_ms, 2),
        }


PAID_FRONTIER_COUNCIL_CATALOG: List[Dict[str, Any]] = [
    {
        "provider_id": "anthropic_opus",
        "name": "Anthropic Claude Opus 4.6 / 5.5 (OpenAI-Compatible Gateway / Direct)",
        "model_family": "anthropic-claude-opus",
        "default_model": "claude-opus-4-6",
        "base_url": "https://api.anthropic.com/v1",
        "env_var": "ANTHROPIC_API_KEY",
        "bft_weight": 1.40,
        "key_prefix_hint": "<YOUR_ANTHROPIC_API_KEY>",
        "docs_url": "https://console.anthropic.com/settings/keys",
    },
    {
        "provider_id": "openai_frontier",
        "name": "OpenAI GPT-5.4 / GPT-6 Thinking Frontier",
        "model_family": "openai-gpt-frontier",
        "default_model": "gpt-5.4-thinking",
        "base_url": "https://api.openai.com/v1",
        "env_var": "OPENAI_API_KEY",
        "bft_weight": 1.35,
        "key_prefix_hint": "<YOUR_OPENAI_API_KEY>",
        "docs_url": "https://platform.openai.com/api-keys",
    },
    {
        "provider_id": "xai_grok_paid",
        "name": "xAI Grok 4.7 Max Reasoning",
        "model_family": "xai-grok-frontier",
        "default_model": "grok-4.7",
        "base_url": "https://api.x.ai/v1",
        "env_var": "XAI_API_KEY",
        "bft_weight": 1.35,
        "key_prefix_hint": "<YOUR_XAI_API_KEY>",
        "docs_url": "https://console.x.ai/",
    },
    {
        "provider_id": "google_gemini_paid",
        "name": "Google Gemini 2.5 Pro Paid Tier",
        "model_family": "google-gemini-frontier",
        "default_model": "gemini-2.5-pro",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "env_var": "GEMINI_PAID_API_KEY",
        "bft_weight": 1.30,
        "key_prefix_hint": "<YOUR_GEMINI_API_KEY>",
        "docs_url": "https://aistudio.google.com/app/apikey",
    },
    {
        "provider_id": "deepseek_paid",
        "name": "DeepSeek R1 / Reasoner Paid API",
        "model_family": "deepseek-r1-frontier",
        "default_model": "deepseek-reasoner",
        "base_url": "https://api.deepseek.com/v1",
        "env_var": "DEEPSEEK_PAID_API_KEY",
        "bft_weight": 1.30,
        "key_prefix_hint": "<YOUR_DEEPSEEK_API_KEY>",
        "docs_url": "https://platform.deepseek.com/api_keys",
    },
    {
        "provider_id": "openrouter_frontier",
        "name": "OpenRouter Frontier Multi-Model Paid Router",
        "model_family": "openrouter-frontier",
        "default_model": "anthropic/claude-opus-4.6",
        "base_url": "https://openrouter.ai/api/v1",
        "env_var": "OPENROUTER_PAID_API_KEY",
        "bft_weight": 1.30,
        "key_prefix_hint": "<YOUR_OPENROUTER_API_KEY>",
        "docs_url": "https://openrouter.ai/keys",
    },
]


class FreeCoRunnerPoolRegistry:
    """
    4-Source Dynamic $0 Free Model Discovery & Circuit-Breaker Registry
    ====================================================================
    Discovers all available $0 Free Co-Runner models (`billing_usd == 0.0`, `credit_card_required == False`)
    to run alongside the Primary Anchor Model (`model gốc`):
      1. `LOCAL_FREE_GATEWAY`     : Local AI Router (`127.0.0.1:8897/v1` or `KINTSUGI_FREE_GATEWAY_URL`)
                                    with `"allow_pro": False, "no_daily_opus": True` (0 paid tokens burned).
      2. `CONSENT_GATED_FREE_POOL`: Verified $0 providers in `.kintsugi/free_agent_pool.json`.
      3. `ENV_FREE_KEYS`          : Free-tier API keys in env (`GROQ_API_KEY`, `CEREBRAS_API_KEY`,
                                    `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, `GITHUB_TOKEN`).
      4. `KEYLESS_COMMUNITY_FREE` : Zero-signup OpenAI-compatible $0 community endpoints so at least 1
                                    Free Co-Runner is ALWAYS available even on a fresh install.
    """

    def __init__(
        self,
        workspace_root: str | Path = ".",
        *,
        probe_local_gateway: bool = True,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.kintsugi_dir = self.workspace_root / ".kintsugi"
        self.free_pool_path = self.kintsugi_dir / "free_agent_pool.json"
        self.probe_local_gateway = probe_local_gateway
        self._slot_health: Dict[str, Tuple[int, float, float]] = {}

    @staticmethod
    def _local_gateway_reachable(base_url: str, timeout_sec: float = 0.45) -> bool:
        root = base_url.rstrip("/")
        if root.endswith("/v1"):
            health_url = root[:-3] + "/health"
        else:
            health_url = root + "/health"
        try:
            req = urllib.request.Request(health_url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                return 200 <= int(getattr(resp, "status", 200)) < 500
        except Exception:
            return False

    def discover_free_slots(self, exclude_model: str = "") -> List[FreePoolSlot]:
        """Return all $0 Free Co-Runner slots ordered by reliability and family diversity."""
        slots: List[FreePoolSlot] = []
        seen_slot_ids = set()
        excl = (exclude_model or "").strip().lower()

        def _add_slot(slot: FreePoolSlot) -> None:
            if slot.billing_usd > 0.0 or slot.credit_card_required:
                return
            if excl and slot.model.strip().lower() == excl:
                return
            if slot.slot_id in seen_slot_ids:
                return
            seen_slot_ids.add(slot.slot_id)
            if slot.slot_id in self._slot_health:
                fc, cd, lat = self._slot_health[slot.slot_id]
                slot.failure_count = fc
                slot.cooldown_until = cd
                slot.last_latency_ms = lat
            slots.append(slot)

        # 1. Source 1: Local Free Gateway (:8897 or KINTSUGI_FREE_GATEWAY_URL)
        gw_url = os.environ.get("KINTSUGI_FREE_GATEWAY_URL", "http://127.0.0.1:8897/v1").strip()
        if self.probe_local_gateway and self._local_gateway_reachable(gw_url):
            gw_free_models = [
                ("local_gw_deepseek", "deepseek-v4.1-flash", "deepseek-r1"),
                ("local_gw_luna", "gpt-6-luna", "openai-codex-free"),
                ("local_gw_terra", "gpt-6.1-terra", "openai-terra-free"),
                ("local_gw_grok_fast", "grok-4.7-fast", "xai-grok-free"),
                ("local_gw_gemini_flash", "agy-gemini-3.8-flash-high", "google-gemini"),
                ("local_gw_muse", "muse-2b", "meta-muse-free"),
            ]
            for pid, m_name, fam in gw_free_models:
                _add_slot(
                    FreePoolSlot(
                        slot_id=f"{pid}:{m_name}",
                        provider_id=pid,
                        model=m_name,
                        model_family=fam,
                        base_url=gw_url,
                        api_key="free-local",
                        source="LOCAL_FREE_GATEWAY",
                        billing_usd=0.0,
                        credit_card_required=False,
                        extra_body={"allow_pro": False, "no_daily_opus": True},
                    )
                )

        # 2. Source 2: Consent-Gated Free Pool (.kintsugi/free_agent_pool.json)
        if self.free_pool_path.is_file():
            try:
                pool_data = json.loads(self.free_pool_path.read_text(encoding="utf-8"))
                for pid, info in sorted((pool_data.get("providers") or {}).items()):
                    if not isinstance(info, dict) or not info.get("verified_healthy", True):
                        continue
                    if float(info.get("billing_usd", 0.0)) > 0.0 or bool(info.get("credit_card_required", False)):
                        continue
                    m_name = str(info.get("default_model") or "").strip()
                    b_url = str(info.get("base_url") or "").strip()
                    if not m_name or not b_url:
                        continue
                    _add_slot(
                        FreePoolSlot(
                            slot_id=f"{pid}:{m_name}",
                            provider_id=str(pid),
                            model=m_name,
                            model_family=str(info.get("model_family") or pid),
                            base_url=b_url,
                            api_key=str(info.get("api_key") or "free-local"),
                            source=str(info.get("source") or "CONSENT_GATED_FREE_POOL"),
                            billing_usd=0.0,
                            credit_card_required=False,
                        )
                    )
            except (OSError, ValueError) as exc:
                _ = str(exc)

        # 3. Source 3: Environment Free Keys
        env_specs = [
            ("groq_free", "GROQ_API_KEY", "llama-3.3-70b-versatile", "meta-llama-3.3", "https://api.groq.com/openai/v1"),
            ("cerebras_free", "CEREBRAS_API_KEY", "llama-3.3-70b", "cerebras-llama-qwen", "https://api.cerebras.ai/v1"),
            ("openrouter_free", "OPENROUTER_API_KEY", "deepseek/deepseek-r1:free", "deepseek-r1", "https://openrouter.ai/api/v1"),
            ("gemini_aistudio_free", "GEMINI_API_KEY", "gemini-2.5-flash", "google-gemini", "https://generativelanguage.googleapis.com/v1beta/openai"),
            ("github_models_free", "GITHUB_TOKEN", "gpt-4o-mini", "github-models", "https://models.inference.ai.azure.com"),
        ]
        for pid, env_name, m_name, fam, b_url in env_specs:
            val = os.environ.get(env_name, "").strip()
            if val:
                _add_slot(
                    FreePoolSlot(
                        slot_id=f"{pid}:{m_name}",
                        provider_id=pid,
                        model=m_name,
                        model_family=fam,
                        base_url=b_url,
                        api_key=val,
                        source="ENV_FREE_KEYS",
                        billing_usd=0.0,
                        credit_card_required=False,
                    )
                )

        # 4. Source 4: Zero-Signup Keyless / Community $0 Free Fallbacks (Always available)
        keyless_specs = [
            (
                "pollinations_keyless_free",
                "openai-large",
                "pollinations-independent",
                "https://text.pollinations.ai/openai",
            ),
            (
                "deepseek_free_community",
                "deepseek-r1-distill-qwen-32b",
                "deepseek-r1",
                "https://text.pollinations.ai/openai",
            ),
            (
                "gemini_flash_free_community",
                "gemini-2.5-flash-free",
                "google-gemini",
                "https://text.pollinations.ai/openai",
            ),
            (
                "llama_free_community",
                "llama-3.3-70b-free",
                "meta-llama-3.3",
                "https://text.pollinations.ai/openai",
            ),
            (
                "qwen_coder_free_community",
                "qwen-2.5-coder-32b-free",
                "alibaba-qwen-coder",
                "https://text.pollinations.ai/openai",
            ),
        ]
        for pid, m_name, fam, b_url in keyless_specs:
            _add_slot(
                FreePoolSlot(
                    slot_id=f"{pid}:{m_name}",
                    provider_id=pid,
                    model=m_name,
                    model_family=fam,
                    base_url=b_url,
                    api_key="keyless",
                    source="KEYLESS_COMMUNITY_FREE",
                    billing_usd=0.0,
                    credit_card_required=False,
                )
            )

        return slots

    def select_co_runners(
        self,
        count: int = 1,
        *,
        exclude_model: str = "",
        exclude_slot_ids: Optional[Sequence[str]] = None,
        prefer_distinct_families: bool = True,
    ) -> List[FreePoolSlot]:
        """Select up to `count` healthy $0 Free Co-Runners, prioritizing distinct model families."""
        target_n = max(1, int(count))
        excl_ids = set(exclude_slot_ids or [])
        now_mono = time.monotonic()
        all_slots = [
            s
            for s in self.discover_free_slots(exclude_model=exclude_model)
            if s.slot_id not in excl_ids
        ]
        healthy = [s for s in all_slots if s.is_available(now_mono)]
        candidates = healthy if healthy else all_slots

        selected: List[FreePoolSlot] = []
        used_families = set()
        if prefer_distinct_families:
            for slot in candidates:
                if slot.model_family not in used_families:
                    selected.append(slot)
                    used_families.add(slot.model_family)
                    if len(selected) >= target_n:
                        return selected

        for slot in candidates:
            if slot not in selected:
                selected.append(slot)
                if len(selected) >= target_n:
                    break
        return selected

    def mark_failure(self, slot_id: str) -> None:
        fc, _, lat = self._slot_health.get(slot_id, (0, 0.0, 0.0))
        new_fc = fc + 1
        backoff = min(60.0, 5.0 * (2 ** min(4, new_fc - 1)))
        self._slot_health[slot_id] = (new_fc, time.monotonic() + backoff, lat)

    def mark_success(self, slot_id: str, latency_ms: float) -> None:
        self._slot_health[slot_id] = (0, 0.0, float(latency_ms))


class PaidFrontierCouncilBYOKRegistry:
    """
    Bring-Your-Own-Key (BYOK) Paid Frontier Agent Council Registry (`$29 Enterprise Complete Pro`)
    ==============================================================================================
    For the Paid Frontier Agent Council (`Claude Opus 4.6/5.5`, `GPT-5.4/GPT-6 Thinking`, `Grok 4.7 Max`,
    `Gemini 2.5 Pro Paid`, `DeepSeek R1 Paid`), the user MUST supply their own API keys (`BYOK`).
    Keys are stored strictly locally in `.kintsugi/paid_council_pool.json` with `chmod 0600` permissions.
    """

    def __init__(self, workspace_root: str | Path = ".", *, include_env_keys: bool = False) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.kintsugi_dir = self.workspace_root / ".kintsugi"
        self.pool_path = self.kintsugi_dir / "paid_council_pool.json"
        self.include_env_keys = include_env_keys

    @staticmethod
    def _mask_key(raw_key: str) -> str:
        clean = (raw_key or "").strip()
        if len(clean) <= 8:
            return "***"
        return f"{clean[:5]}***{clean[-4:]}"

    def _write_secure_json(self, payload: Dict[str, Any]) -> None:
        self.kintsugi_dir.mkdir(parents=True, exist_ok=True)
        self.pool_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            os.chmod(self.pool_path, 0o600)
        except OSError as exc:
            _ = str(exc)

    def load_state(self) -> Dict[str, Any]:
        default_state: Dict[str, Any] = {
            "schema_version": "1.0",
            "key_policy": "USER_BYOK_LOCAL_0600_ONLY",
            "providers": {},
        }
        if self.pool_path.is_file():
            try:
                return json.loads(self.pool_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return default_state
        return default_state

    def add_paid_key(
        self,
        provider_id: str,
        api_key: str,
        *,
        custom_model: Optional[str] = None,
        custom_base_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Store a user-supplied Paid Frontier Council API key (`BYOK`) in `.kintsugi/paid_council_pool.json` (`0600`)."""
        pid = provider_id.strip().lower()
        cat_map = {c["provider_id"]: c for c in PAID_FRONTIER_COUNCIL_CATALOG}
        if pid not in cat_map:
            raise ValueError(
                f"Unknown paid provider_id '{provider_id}'. Supported Paid Council seats: "
                f"{', '.join(sorted(cat_map.keys()))}"
            )
        clean_key = (api_key or "").strip()
        if len(clean_key) < 8:
            raise ValueError("Paid Council API key must be at least 8 characters long.")

        spec = cat_map[pid]
        state = self.load_state()
        model_val = (custom_model or spec["default_model"]).strip()
        url_val = (custom_base_url or spec["base_url"]).strip()
        state.setdefault("providers", {})[pid] = {
            "provider_id": pid,
            "name": spec["name"],
            "model_family": spec["model_family"],
            "model": model_val,
            "base_url": url_val,
            "api_key": clean_key,
            "masked_key": self._mask_key(clean_key),
            "bft_weight": float(spec.get("bft_weight", 1.35)),
            "source": "USER_BYOK_PAID_KEY",
            "verified_ready": True,
        }
        self._write_secure_json(state)
        return self.get_status()

    def remove_paid_key(self, provider_id: str) -> Dict[str, Any]:
        pid = provider_id.strip().lower()
        state = self.load_state()
        providers = state.get("providers") or {}
        if pid in providers:
            del providers[pid]
            self._write_secure_json(state)
        return self.get_status()

    def discover_paid_seats(self) -> List[FreePoolSlot]:
        """Return all user-configured BYOK Paid Frontier Council seats (from `.kintsugi/paid_council_pool.json` + env)."""
        state = self.load_state()
        saved = state.get("providers") or {}
        seats: List[FreePoolSlot] = []
        seen_pids = set()

        for pid, info in sorted(saved.items()):
            if not isinstance(info, dict):
                continue
            key_val = str(info.get("api_key") or "").strip()
            if not key_val:
                continue
            m_name = str(info.get("model") or "gpt-5.4-thinking").strip()
            seen_pids.add(pid)
            seats.append(
                FreePoolSlot(
                    slot_id=f"paid_byok:{pid}:{m_name}",
                    provider_id=pid,
                    model=m_name,
                    model_family=str(info.get("model_family") or pid),
                    base_url=str(info.get("base_url") or "https://api.openai.com/v1"),
                    api_key=key_val,
                    source="USER_BYOK_PAID_COUNCIL",
                    billing_usd=0.0,
                    credit_card_required=False,
                    is_paid_byok=True,
                    bft_weight=float(info.get("bft_weight", 1.35)),
                )
            )

        if self.include_env_keys:
            for spec in PAID_FRONTIER_COUNCIL_CATALOG:
                pid = spec["provider_id"]
                if pid in seen_pids:
                    continue
                env_val = os.environ.get(spec["env_var"], "").strip()
                if env_val:
                    m_name = spec["default_model"]
                    seats.append(
                        FreePoolSlot(
                            slot_id=f"paid_env:{pid}:{m_name}",
                            provider_id=pid,
                            model=m_name,
                            model_family=spec["model_family"],
                            base_url=spec["base_url"],
                            api_key=env_val,
                            source=f"USER_ENV_{spec['env_var']}",
                            billing_usd=0.0,
                            credit_card_required=False,
                            is_paid_byok=True,
                            bft_weight=float(spec.get("bft_weight", 1.35)),
                        )
                    )
        return seats

    def get_status(self) -> Dict[str, Any]:
        from kintsugi.packs import resolve_workspace_co_execution_entitlement

        entitlement = resolve_workspace_co_execution_entitlement(self.workspace_root)
        seats = self.discover_paid_seats()
        unlocked = bool(entitlement["paid_council_byok_unlocked"])
        if not unlocked:
            council_state = "LOCKED_REQUIRES_ENTERPRISE_PRO_29"
        elif not seats:
            council_state = "UNLOCKED_AWAITING_USER_BYOK_KEYS"
        else:
            council_state = "ACTIVE_READY"

        return {
            "paid_council_state": council_state,
            "entitlement_tier": entitlement["tier_id"],
            "entitlement_label": entitlement["tier_label"],
            "paid_council_byok_unlocked": unlocked,
            "configured_paid_seats_count": len(seats),
            "configured_paid_seats": [s.to_public_dict() for s in seats],
            "supported_paid_council_catalog": [
                {
                    "provider_id": c["provider_id"],
                    "name": c["name"],
                    "default_model": c["default_model"],
                    "model_family": c["model_family"],
                    "env_var": c["env_var"],
                    "key_prefix_hint": c["key_prefix_hint"],
                    "docs_url": c["docs_url"],
                    "cli_add_command": f"kintsugi swarm --add-paid-key {c['provider_id']} <YOUR_API_KEY>",
                }
                for c in PAID_FRONTIER_COUNCIL_CATALOG
            ],
        }


def build_multi_model_agent_guide(workspace_root: str | Path = ".") -> Dict[str, Any]:
    """
    Generate the structured Bilingual Agent Onboarding & Tier-Upgrade Guide (`VI` / `EN`)
    so the AI Coding Agent can guide the user step-by-step on:
      - How the current tier runs (`Free = Primary + 1 Free Model` vs `Pro = Primary + Multi-Model Free`
        vs `Enterprise = Primary + Multi-Model Free + BYOK Paid Frontier Council`)
      - How to add $0 Free keys or authorize $0 auto-provisioning
      - How to add user-owned API keys (`BYOK`) for the Paid Frontier Agent Council
      - How to unlock higher tiers via `.kpack` license keys.
    """
    from kintsugi.packs import resolve_workspace_co_execution_entitlement

    ws = Path(workspace_root).resolve()
    entitlement = resolve_workspace_co_execution_entitlement(ws)
    free_reg = FreeCoRunnerPoolRegistry(ws)
    free_slots = free_reg.discover_free_slots()
    paid_reg = PaidFrontierCouncilBYOKRegistry(ws)
    paid_status = paid_reg.get_status()

    tier_id = entitlement["tier_id"]
    if tier_id == "FREE_STARTER":
        active_behavior_vi = (
            "Đang ở bản FREE ($0): Model gốc (Primary Anchor) luôn chạy song song với ĐÚNG 1 Model Miễn Phí "
            "get được (khóa trần 1 model free). Để mở khóa chạy 2–5 Model Miễn Phí cùng lúc (Multi-Model Free Swarm), "
            "hãy nâng cấp gói Pro ($15 / $19). Để mở khóa thêm Hội Đồng Agent Thu Phí (Claude Opus / GPT-6 / Grok Max), "
            "hãy nâng cấp gói Enterprise Complete Pro ($29)."
        )
        active_behavior_en = (
            "Currently on FREE Tier ($0): Your Primary Anchor model always runs alongside EXACTLY 1 discovered $0 Free model "
            "(hard-locked to 1 free co-runner). Upgrade to Pro ($15 / $19) to unlock 2–5 parallel Multi-Model Free Co-Runners, "
            "or upgrade to Enterprise Complete Pro ($29) to also unlock the BYOK Paid Frontier Agent Council."
        )
    elif tier_id == "PRO_MULTI_FREE":
        active_behavior_vi = (
            "Đang ở bản PRO MULTI-MODEL FREE ($15 / $19): Đã mở khóa cho phép Model gốc chạy song song cùng "
            "2–5 Model Miễn Phí thuộc các họ độc lập (DeepSeek, Gemini, Grok Fast, Llama/Cerebras, Qwen) kèm tự động "
            "xoay vòng khi chạm giới hạn 429. Hội Đồng Agent Thu Phí hiện đang khóa (cần bản Enterprise Complete Pro $29)."
        )
        active_behavior_en = (
            "Currently on PRO MULTI-MODEL FREE ($15 / $19): Unlocked parallel execution of your Primary Anchor model "
            "with 2–5 independent $0 Free Co-Runners plus automatic 429 round-robin failover. Paid Frontier Council "
            "requires upgrading to Enterprise Complete Pro ($29)."
        )
    else:
        if paid_status["configured_paid_seats_count"] == 0:
            active_behavior_vi = (
                "Đang ở bản ENTERPRISE COMPLETE PRO ($29): Đã mở khóa toàn bộ Multi-Model Free (tối đa 5 model free) "
                "VÀ Hội Đồng Agent Thu Phí (Paid Frontier Council). Tuy nhiên bạn chưa thêm API Key cho Hội Đồng Thu Phí. "
                "Hãy làm theo Bước 3 bên dưới (`kintsugi swarm --add-paid-key <provider_id> <api_key>`) để tự thêm key của bạn."
            )
            active_behavior_en = (
                "Currently on ENTERPRISE COMPLETE PRO ($29): Both Multi-Model Free (up to 5 free models) AND the "
                "Paid Frontier Agent Council are unlocked! However, no Paid Council BYOK API keys are configured yet. "
                "Follow Step 3 below (`kintsugi swarm --add-paid-key <provider_id> <api_key>`) to add your own keys."
            )
        else:
            active_behavior_vi = (
                f"Đang ở bản ENTERPRISE COMPLETE PRO ($29): Đã mở khóa đầy đủ và gắn sẵn "
                f"{paid_status['configured_paid_seats_count']} ghế Hội Đồng Agent Thu Phí (BYOK) chạy song song cùng "
                f"Model Gốc + dàn Multi-Model Free!"
            )
            active_behavior_en = (
                f"Currently on ENTERPRISE COMPLETE PRO ($29): Fully unlocked with "
                f"{paid_status['configured_paid_seats_count']} BYOK Paid Frontier Council seat(s) running alongside "
                f"your Primary Anchor + Multi-Model Free Swarm!"
            )

    return {
        "current_entitlement": entitlement,
        "discovered_free_models_count": len(free_slots),
        "paid_council_status": paid_status["paid_council_state"],
        "configured_paid_seats_count": paid_status["configured_paid_seats_count"],
        "agent_explanation_vi": active_behavior_vi,
        "agent_explanation_en": active_behavior_en,
        "tier_comparison_matrix": [
            {
                "tier_id": "FREE_STARTER",
                "edition": "Free Open-Source Starter ($0)",
                "execution_topology": "1 Primary Model + 1 Free Model (Locked to 1 Free Co-Runner)",
                "max_free_co_runners": 1,
                "paid_council_byok": False,
                "how_to_unlock": "Default included in open-source `pip install kintsugi-harness`",
            },
            {
                "tier_id": "PRO_MULTI_FREE",
                "edition": "Pro Skill Packs ($15 FinOps Pro / $19 AppSec Pro)",
                "execution_topology": "1 Primary Model + 2..5 Multi-Model Free Co-Runners (Auto 429 Rotation)",
                "max_free_co_runners": 5,
                "paid_council_byok": False,
                "how_to_unlock": "kintsugi install-pack kintsugi-zero-trust-mcp-security-pro-v1.3.0.kpack --license-key <PRO_KEY>",
            },
            {
                "tier_id": "ENTERPRISE_PAID_COUNCIL",
                "edition": "Enterprise Complete Pro ($29)",
                "execution_topology": "1 Primary Model + 2..5 Free Co-Runners + 1..6 Paid Frontier Council Seats (BYOK)",
                "max_free_co_runners": 5,
                "paid_council_byok": True,
                "how_to_unlock": "kintsugi install-pack kintsugi-enterprise-complete-pro-v1.3.0.kpack --license-key <ENT_KEY>",
            },
        ],
        "step_by_step_user_guide_vi": {
            "step_1_free_tier_1_corunner": (
                "Chạy ngay ở bản Free ($0) — Model gốc tự động chạy kèm 1 Model Free: "
                "`kintsugi swarm . --co-run`"
            ),
            "step_2_unlock_multi_model_free": (
                "Mở khóa chạy 2–5 Model Free cùng lúc (Gói $15/$19): "
                "`kintsugi install-pack <pro-pack.kpack> --license-key <KEY>` rồi chạy "
                "`kintsugi swarm --authorize-auto-provision` và `kintsugi swarm . --co-run --free-runners 4`"
            ),
            "step_3_setup_paid_council_byok_keys": (
                "Với Hội Đồng Agent Thu Phí (Gói Enterprise $29), người dùng TỰ THÊM API KEY của chính mình "
                "(lưu cục bộ 0600 tại `.kintsugi/paid_council_pool.json`):\n"
                "  • Thêm Claude Opus : `kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>`\n"
                "  • Thêm OpenAI GPT-6: `kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>`\n"
                "  • Thêm xAI Grok 4.7: `kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>`\n"
                "  • Thêm Gemini Paid : `kintsugi swarm --add-paid-key google_gemini_paid <YOUR_GEMINI_KEY>`\n"
                "  • Thêm DeepSeek R1 : `kintsugi swarm --add-paid-key deepseek_paid <YOUR_DEEPSEEK_KEY>`"
            ),
            "step_4_run_full_hybrid_council": (
                "Chạy đồng thời Model Gốc + Multi-Model Free + Hội Đồng Thu Phí: "
                "`kintsugi swarm . --co-run --free-runners 3 --paid-council`"
            ),
        },
        "step_by_step_user_guide_en": {
            "step_1_free_tier_1_corunner": (
                "Run on Free Tier ($0) — Primary model automatically co-executes with 1 Free model: "
                "`kintsugi swarm . --co-run`"
            ),
            "step_2_unlock_multi_model_free": (
                "Unlock 2–5 parallel Free Co-Runners ($15/$19 Pro Pack): "
                "`kintsugi install-pack <pro-pack.kpack> --license-key <KEY>`, then run "
                "`kintsugi swarm --authorize-auto-provision` and `kintsugi swarm . --co-run --free-runners 4`"
            ),
            "step_3_setup_paid_council_byok_keys": (
                "For the Paid Frontier Agent Council ($29 Enterprise Pro), users ADD THEIR OWN API KEYS (BYOK, stored locally with 0600 permissions in `.kintsugi/paid_council_pool.json`):\n"
                "  • Add Claude Opus : `kintsugi swarm --add-paid-key anthropic_opus <YOUR_ANTHROPIC_KEY>`\n"
                "  • Add OpenAI GPT-6: `kintsugi swarm --add-paid-key openai_frontier <YOUR_OPENAI_KEY>`\n"
                "  • Add xAI Grok 4.7: `kintsugi swarm --add-paid-key xai_grok_paid <YOUR_XAI_KEY>`\n"
                "  • Add Gemini Paid : `kintsugi swarm --add-paid-key google_gemini_paid <YOUR_GEMINI_KEY>`\n"
                "  • Add DeepSeek R1 : `kintsugi swarm --add-paid-key deepseek_paid <YOUR_DEEPSEEK_KEY>`"
            ),
            "step_4_run_full_hybrid_council": (
                "Run Primary Anchor + Multi-Model Free + Paid Frontier Council in parallel: "
                "`kintsugi swarm . --co-run --free-runners 3 --paid-council`"
            ),
        },
    }


class PrimaryPlusFreeCoExecutor:
    """
    Tier-Gated Multi-Model Co-Execution Engine (`v1.3.0`)
    =====================================================
    Guarantees that the Primary Anchor Model (`model gốc`) ALWAYS runs alongside:
      - Tier 0 (`FREE_STARTER`, `$0`)            : Hard-locked to `1` discovered $0 Free Co-Runner (`Primary + 1 Free`).
      - Tier 1 (`PRO_MULTI_FREE`, `$15 / $19`)   : `1..5` parallel $0 Free Co-Runners across distinct model families
                                                   with automatic round-robin failover on HTTP 429 / timeouts.
      - Tier 2 (`ENTERPRISE_PAID_COUNCIL`, `$29`): `1..5` $0 Free Co-Runners PLUS `1..6` user-supplied BYOK
                                                   Paid Frontier Agent Council seats (`Claude Opus`, `GPT-6`, `Grok 4.7`).
    """

    def __init__(
        self,
        workspace_root: str | Path = ".",
        *,
        primary_endpoint: Optional[AgentEndpoint] = None,
        free_registry: Optional[FreeCoRunnerPoolRegistry] = None,
        paid_registry: Optional[PaidFrontierCouncilBYOKRegistry] = None,
        completion_fn: Optional[Callable[[AgentEndpoint, str, str], str]] = None,
        max_rotations_per_seat: int = 2,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.free_registry = free_registry or FreeCoRunnerPoolRegistry(self.workspace_root)
        self.paid_registry = paid_registry or PaidFrontierCouncilBYOKRegistry(self.workspace_root)
        self.primary_endpoint = primary_endpoint or self._default_primary_endpoint()
        self._complete = completion_fn or call_openai_compatible
        self.max_rotations_per_seat = max(0, int(max_rotations_per_seat))

    @staticmethod
    def _default_primary_endpoint() -> AgentEndpoint:
        model = os.environ.get("KINTSUGI_PRIMARY_MODEL") or os.environ.get("KINTSUGI_ARCHITECT_MODEL") or "primary-anchor-model"
        base_url = (
            os.environ.get("KINTSUGI_PRIMARY_BASE_URL")
            or os.environ.get("KINTSUGI_ARCHITECT_BASE_URL")
            or "http://127.0.0.1:8897/v1"
        )
        api_key = (
            os.environ.get("KINTSUGI_PRIMARY_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or "primary-session"
        )
        fam = model.split("-")[0].lower() if "-" in model else "primary-anchor"
        return AgentEndpoint(
            role="primary_anchor",
            model=model,
            base_url=base_url,
            api_key=api_key,
            provider_id="primary_anchor",
            model_family=fam,
            source="PRIMARY_ANCHOR",
            billing_usd=0.0,
            extra_body={"allow_pro": False, "no_daily_opus": True},
        )

    def resolve_execution_plan(
        self,
        requested_free_runners: Optional[int] = None,
        include_paid_council: bool = False,
    ) -> Dict[str, Any]:
        """
        Apply the 3-Tier Commercial Entitlement Gate to determine exact co-execution seats:
        - `FREE_STARTER` ($0) clamps `effective_free_runners = 1` and blocks `include_paid_council`.
        - `PRO_MULTI_FREE` ($15/$19) allows `1..5` free co-runners and blocks `include_paid_council`.
        - `ENTERPRISE_PAID_COUNCIL` ($29) allows `1..5` free co-runners AND `include_paid_council` (requires BYOK keys).
        """
        from kintsugi.packs import resolve_workspace_co_execution_entitlement

        entitlement = resolve_workspace_co_execution_entitlement(self.workspace_root)
        max_free_allowed = int(entitlement["max_free_co_runners"])
        req_free = int(requested_free_runners) if requested_free_runners is not None else max_free_allowed
        req_free = max(1, req_free)

        notices: List[str] = []
        if req_free > max_free_allowed:
            notices.append(
                f"TIER_GATE_CLAMPED_FREE_MODELS: Requested {req_free} free models, but current tier "
                f"'{entitlement['tier_id']}' ({entitlement['tier_label']}) is locked to {max_free_allowed} free model(s). "
                f"Install a Pro Skill Pack ($15 / $19 / $29) to unlock up to 5 parallel free models."
            )
        effective_free = max(1, min(req_free, max_free_allowed))

        free_slots = self.free_registry.select_co_runners(
            count=effective_free,
            exclude_model=self.primary_endpoint.model,
            prefer_distinct_families=True,
        )

        paid_slots: List[FreePoolSlot] = []
        paid_council_status = "NOT_REQUESTED"
        if include_paid_council:
            if not entitlement["paid_council_byok_unlocked"]:
                paid_council_status = "LOCKED_REQUIRES_ENTERPRISE_PRO_29"
                notices.append(
                    f"TIER_GATE_BLOCKED_PAID_COUNCIL: Paid Frontier Agent Council requires "
                    f"'kintsugi-enterprise-complete-pro' ($29). Current tier is '{entitlement['tier_id']}'."
                )
            else:
                paid_slots = self.paid_registry.discover_paid_seats()
                if not paid_slots:
                    paid_council_status = "AWAITING_USER_BYOK_KEYS"
                    notices.append(
                        "PAID_COUNCIL_BYOK_REQUIRED: Enterprise Complete Pro ($29) is unlocked, but you have not added "
                        "your Paid Frontier API keys yet. Run `kintsugi swarm --add-paid-key <provider_id> <api_key>`."
                    )
                else:
                    paid_council_status = "ACTIVE_BYOK_READY"

        return {
            "entitlement": entitlement,
            "requested_free_runners": req_free,
            "effective_free_runners": len(free_slots),
            "include_paid_council_requested": include_paid_council,
            "paid_council_status": paid_council_status,
            "active_paid_council_seats_count": len(paid_slots),
            "tier_enforcement_notices": notices,
            "primary_anchor": {
                "role": "primary_anchor",
                "model": self.primary_endpoint.model,
                "model_family": self.primary_endpoint.model_family,
                "source": self.primary_endpoint.source,
            },
            "selected_free_co_runners": [s.to_public_dict() for s in free_slots],
            "selected_paid_council_seats": [s.to_public_dict() for s in paid_slots],
            "_free_slot_objects": free_slots,
            "_paid_slot_objects": paid_slots,
        }

    def _execute_free_seat_with_failover(
        self,
        seat_index: int,
        initial_slot: FreePoolSlot,
        system_prompt: str,
        user_prompt: str,
        already_assigned_ids: Sequence[str],
    ) -> Dict[str, Any]:
        """Run one Free Co-Runner seat with automatic round-robin failover on HTTP 429/5xx/timeout."""
        tried_ids = set(already_assigned_ids)
        tried_ids.add(initial_slot.slot_id)
        current_slot = initial_slot
        rotations: List[Dict[str, str]] = []

        for attempt_idx in range(self.max_rotations_per_seat + 1):
            t0 = time.perf_counter()
            ep = current_slot.to_endpoint(role=f"free_corunner_{seat_index}")
            try:
                reply = self._complete(ep, system_prompt, user_prompt)
                lat_ms = round((time.perf_counter() - t0) * 1000.0, 2)
                self.free_registry.mark_success(current_slot.slot_id, lat_ms)
                return {
                    "seat_role": f"free_corunner_{seat_index}",
                    "slot_id": current_slot.slot_id,
                    "provider_id": current_slot.provider_id,
                    "model": current_slot.model,
                    "model_family": current_slot.model_family,
                    "source": current_slot.source,
                    "is_paid_byok": False,
                    "bft_weight": current_slot.bft_weight,
                    "status": "SUCCEEDED",
                    "latency_ms": lat_ms,
                    "rotations_used": len(rotations),
                    "rotation_history": rotations,
                    "content": reply,
                }
            except Exception as exc:  # noqa: BLE001
                self.free_registry.mark_failure(current_slot.slot_id)
                err_text = str(exc)
                if attempt_idx >= self.max_rotations_per_seat:
                    return {
                        "seat_role": f"free_corunner_{seat_index}",
                        "slot_id": current_slot.slot_id,
                        "provider_id": current_slot.provider_id,
                        "model": current_slot.model,
                        "model_family": current_slot.model_family,
                        "source": current_slot.source,
                        "is_paid_byok": False,
                        "bft_weight": current_slot.bft_weight,
                        "status": "FAILED",
                        "error": err_text[:200],
                        "rotations_used": len(rotations),
                        "rotation_history": rotations,
                        "content": "",
                    }
                backups = self.free_registry.select_co_runners(
                    count=1,
                    exclude_model=self.primary_endpoint.model,
                    exclude_slot_ids=list(tried_ids),
                    prefer_distinct_families=True,
                )
                if not backups:
                    return {
                        "seat_role": f"free_corunner_{seat_index}",
                        "slot_id": current_slot.slot_id,
                        "provider_id": current_slot.provider_id,
                        "model": current_slot.model,
                        "model_family": current_slot.model_family,
                        "source": current_slot.source,
                        "is_paid_byok": False,
                        "bft_weight": current_slot.bft_weight,
                        "status": "FAILED",
                        "error": err_text[:200],
                        "rotations_used": len(rotations),
                        "rotation_history": rotations,
                        "content": "",
                    }
                next_slot = backups[0]
                rotations.append(
                    {
                        "from_slot": current_slot.slot_id,
                        "to_slot": next_slot.slot_id,
                        "reason": err_text[:120],
                    }
                )
                tried_ids.add(next_slot.slot_id)
                current_slot = next_slot

        return {"seat_role": f"free_corunner_{seat_index}", "status": "FAILED", "content": ""}

    def _execute_primary_or_paid_seat(
        self,
        endpoint: AgentEndpoint,
        seat_role: str,
        system_prompt: str,
        user_prompt: str,
        *,
        is_paid_byok: bool = False,
        bft_weight: float = 1.0,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        try:
            reply = self._complete(endpoint, system_prompt, user_prompt)
            lat_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return {
                "seat_role": seat_role,
                "slot_id": f"{endpoint.provider_id}:{endpoint.model}",
                "provider_id": endpoint.provider_id,
                "model": endpoint.model,
                "model_family": endpoint.model_family,
                "source": endpoint.source,
                "is_paid_byok": is_paid_byok,
                "bft_weight": bft_weight,
                "status": "SUCCEEDED",
                "latency_ms": lat_ms,
                "rotations_used": 0,
                "rotation_history": [],
                "content": reply,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "seat_role": seat_role,
                "slot_id": f"{endpoint.provider_id}:{endpoint.model}",
                "provider_id": endpoint.provider_id,
                "model": endpoint.model,
                "model_family": endpoint.model_family,
                "source": endpoint.source,
                "is_paid_byok": is_paid_byok,
                "bft_weight": bft_weight,
                "status": "FAILED",
                "error": str(exc)[:200],
                "rotations_used": 0,
                "rotation_history": [],
                "content": "",
            }

    def co_execute_prompt(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        num_free_runners: Optional[int] = None,
        include_paid_council: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute `system_prompt` + `user_prompt` in parallel across:
          - Seat 0: `PRIMARY_ANCHOR` (`model gốc`)
          - Seats 1..M: `$0` Free Co-Runners (`1` on Free tier, `1..5` on Pro/Enterprise tiers)
          - Seats M+1..K: BYOK Paid Frontier Council seats (when `include_paid_council=True` on `$29` Enterprise tier)
        """
        t_start = time.perf_counter()
        plan = self.resolve_execution_plan(
            requested_free_runners=num_free_runners,
            include_paid_council=include_paid_council,
        )
        free_slots: List[FreePoolSlot] = plan.pop("_free_slot_objects")
        paid_slots: List[FreePoolSlot] = plan.pop("_paid_slot_objects")
        assigned_free_ids = [s.slot_id for s in free_slots]

        total_workers = 1 + len(free_slots) + len(paid_slots)
        seat_results: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=max(2, total_workers)) as pool:
            fut_map = {}
            fut_primary = pool.submit(
                self._execute_primary_or_paid_seat,
                self.primary_endpoint,
                "primary_anchor",
                system_prompt,
                user_prompt,
                is_paid_byok=False,
                bft_weight=1.15,
            )
            fut_map[fut_primary] = 0

            for idx, f_slot in enumerate(free_slots, start=1):
                fut = pool.submit(
                    self._execute_free_seat_with_failover,
                    idx,
                    f_slot,
                    system_prompt,
                    user_prompt,
                    assigned_free_ids,
                )
                fut_map[fut] = idx

            for p_idx, p_slot in enumerate(paid_slots, start=1):
                p_ep = p_slot.to_endpoint(role=f"paid_council_{p_idx}")
                fut = pool.submit(
                    self._execute_primary_or_paid_seat,
                    p_ep,
                    f"paid_council_{p_idx}",
                    system_prompt,
                    user_prompt,
                    is_paid_byok=True,
                    bft_weight=p_slot.bft_weight,
                )
                fut_map[fut] = 100 + p_idx

            ordered_pairs = []
            for fut in as_completed(fut_map):
                ordered_pairs.append((fut_map[fut], fut.result()))
            ordered_pairs.sort(key=lambda item: item[0])
            seat_results = [r for _, r in ordered_pairs]

        succeeded = [r for r in seat_results if r.get("status") == "SUCCEEDED"]
        free_succeeded = [r for r in succeeded if r["seat_role"].startswith("free_corunner_")]
        paid_succeeded = [r for r in succeeded if r["seat_role"].startswith("paid_council_")]
        distinct_families = sorted({r["model_family"] for r in succeeded})

        if len(succeeded) >= 2 and paid_succeeded:
            exec_mode = "primary+free+paid-frontier-council"
        elif len(succeeded) >= 2 and free_succeeded:
            exec_mode = "primary+free-co-execution"
        elif succeeded:
            exec_mode = "degraded-single-model"
        else:
            exec_mode = "all-seats-failed"

        elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        tier_id = plan["entitlement"]["tier_id"]
        corun_wire = (
            f"@CORUN/1|tier={tier_id}|mode={exec_mode}|primary={self.primary_endpoint.model}|"
            f"free={len(free_succeeded)}/{len(free_slots)}|paid={len(paid_succeeded)}/{len(paid_slots)}|"
            f"families={len(distinct_families)}|ms={elapsed_ms}"
        )

        return {
            "kmi_corun_wire": corun_wire,
            "execution_mode": exec_mode,
            "elapsed_ms": elapsed_ms,
            "entitlement": plan["entitlement"],
            "tier_enforcement_notices": plan["tier_enforcement_notices"],
            "paid_council_status": plan["paid_council_status"],
            "seats_total": len(seat_results),
            "seats_succeeded": len(succeeded),
            "free_co_runners_succeeded": len(free_succeeded),
            "paid_council_seats_succeeded": len(paid_succeeded),
            "distinct_model_families": distinct_families,
            "seat_results": seat_results,
            "agent_onboarding_guide": build_multi_model_agent_guide(self.workspace_root),
        }

    def co_evolve_scar(
        self,
        trace: FailureTrace,
        *,
        scar_id: str = "KS-900",
        num_free_runners: Optional[int] = None,
        include_paid_council: bool = False,
    ) -> Tuple[GoldenScar, Dict[str, Any]]:
        """
        Synthesize and verify a `GoldenScar` by running the Primary Anchor Model (`model gốc`)
        in parallel with `1..N` $0 Free Co-Runners (and optional BYOK Paid Frontier Council seats).
        Every candidate must pass `verify_candidate_scar()` (7-Layer Shield + TP >= 1 + FP == 0).
        """
        sys_prompt = (
            "You are a Kintsugi Co-Execution Synthesizer Seat. Emit strictly valid JSON defining a deterministic "
            "GoldenScar that catches the offending failure trace with zero false positives."
        )
        user_prompt = (
            f"Failure Summary: {trace.error_summary}\n"
            f"Language: {trace.language}\n"
            f"Raw Trace:\n{trace.raw_trace}\n"
            f"Offending Snippet:\n{trace.offending_snippet}\n"
            f"Fixed Snippet:\n{trace.fixed_snippet}\n"
            "Return ONLY valid JSON with keys: "
            "title, severity (CRITICAL|HIGH|MEDIUM|LOW), category, languages (list), tags (list), "
            "root_cause, bad_code, good_code, rationale, regex_pattern (string or null), ast_rule (string or null)."
        )

        co_rep = self.co_execute_prompt(
            sys_prompt,
            user_prompt,
            num_free_runners=num_free_runners,
            include_paid_council=include_paid_council,
        )

        verified_candidates: List[Tuple[float, GoldenScar, Dict[str, Any]]] = []
        verifying_tags: List[str] = []
        verifying_families = set()

        for seat in co_rep["seat_results"]:
            if seat.get("status") != "SUCCEEDED" or not seat.get("content"):
                continue
            try:
                parsed = _extract_json_object(str(seat["content"]))
                cand = GoldenScar(
                    id=scar_id,
                    title=str(parsed["title"]),
                    severity=Severity(str(parsed.get("severity", "HIGH")).upper()),
                    category=str(parsed.get("category", "reliability")),
                    languages=list(parsed.get("languages") or [trace.language]),
                    tags=list(parsed.get("tags") or ["co-evolved"]),
                    root_cause=str(parsed["root_cause"]),
                    bad_code=str(parsed["bad_code"]),
                    good_code=str(parsed["good_code"]),
                    rationale=str(parsed["rationale"]),
                    regex_pattern=parsed.get("regex_pattern"),
                    ast_rule=parsed.get("ast_rule"),
                )
            except (KeyError, ValueError, TypeError):
                continue

            ok, _ = verify_candidate_scar(cand)
            if not ok:
                continue

            role = str(seat["seat_role"])
            if role == "primary_anchor":
                tag = f"primary:{seat['model']}"
            elif role.startswith("paid_council_"):
                tag = f"paid-council:{seat['provider_id']}:{seat['model']}"
            else:
                tag = f"free-corunner:{seat['provider_id']}:{seat['model']}"
            if tag not in verifying_tags:
                verifying_tags.append(tag)
            verifying_families.add(str(seat["model_family"]))

            # Specificity & seat weight score (AST rules and Paid Council seats receive higher weight)
            spec_score = float(seat.get("bft_weight", 1.0))
            if cand.ast_rule:
                spec_score += 0.35
            if cand.regex_pattern and len(cand.regex_pattern) >= 10:
                spec_score += 0.15
            verified_candidates.append((spec_score, cand, seat))

        if not verified_candidates:
            offline_scar = EvolutionCouncil.evolve_offline(trace, scar_id=scar_id)
            ok, msg = verify_candidate_scar(offline_scar)
            if not ok:
                raise ValueError(f"Co-execution and offline fallback failed self-verification: {msg}")
            offline_scar.verified_by = [
                "offline-heuristic",
                f"tier:{co_rep['entitlement']['tier_id']}",
                "self-check",
            ]
            co_rep["winning_source"] = "offline-heuristic-fallback"
            return offline_scar, co_rep

        verified_candidates.sort(key=lambda item: item[0], reverse=True)
        best_score, winning_scar, winning_seat = verified_candidates[0]
        winning_scar.verified_by = verifying_tags + [
            f"mode:{co_rep['execution_mode']}",
            f"tier:{co_rep['entitlement']['tier_id']}",
            f"families:{len(verifying_families)}",
            "self-check",
        ]
        co_rep["winning_source"] = winning_seat["slot_id"]
        co_rep["winning_specificity_score"] = round(best_score, 4)
        co_rep["verified_candidates_count"] = len(verified_candidates)
        return winning_scar, co_rep


class EvolutionCouncil:
    """
    Coordinates 3 specialized LLM seats (or Primary + Free Co-Runners / deterministic offline fallback)
    to compile a `FailureTrace` into a verified `GoldenScar`.
    """

    def __init__(
        self,
        endpoints: Optional[List[AgentEndpoint]] = None,
        *,
        completion_fn: Optional[Callable[[AgentEndpoint, str, str], str]] = None,
        workspace_root: str | Path = ".",
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.endpoints = endpoints if endpoints is not None else self.from_env()
        self._complete = completion_fn or call_openai_compatible
        self.free_registry = FreeCoRunnerPoolRegistry(self.workspace_root, probe_local_gateway=False)

    @staticmethod
    def from_env() -> List[AgentEndpoint]:
        """Auto-discover Architect (Gemini), Synthesizer (DeepSeek), and Critic (Muse/OpenAI) seats."""
        seats: List[AgentEndpoint] = []
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if gemini_key:
            seats.append(
                AgentEndpoint(
                    role="architect",
                    model=os.environ.get("KINTSUGI_ARCHITECT_MODEL", "gemini-2.5-pro"),
                    base_url=os.environ.get(
                        "KINTSUGI_ARCHITECT_BASE_URL",
                        "https://generativelanguage.googleapis.com/v1beta/openai",
                    ),
                    api_key=gemini_key,
                    provider_id="gemini",
                    model_family="google-gemini",
                )
            )

        deepseek_key = os.environ.get("DEEPSEEK_API_KEY")
        if deepseek_key:
            seats.append(
                AgentEndpoint(
                    role="synthesizer",
                    model=os.environ.get("KINTSUGI_SYNTHESIZER_MODEL", "deepseek-reasoner"),
                    base_url=os.environ.get(
                        "KINTSUGI_SYNTHESIZER_BASE_URL", "https://api.deepseek.com/v1"
                    ),
                    api_key=deepseek_key,
                    provider_id="deepseek",
                    model_family="deepseek-r1",
                )
            )

        critic_key = os.environ.get("MUSE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if critic_key:
            seats.append(
                AgentEndpoint(
                    role="critic",
                    model=os.environ.get("KINTSUGI_CRITIC_MODEL", "gpt-4.1"),
                    base_url=os.environ.get("KINTSUGI_CRITIC_BASE_URL", "https://api.openai.com/v1"),
                    api_key=critic_key,
                    provider_id="openai",
                    model_family="openai-gpt",
                )
            )
        return seats

    def evolve_with_co_runners(
        self,
        trace: FailureTrace,
        *,
        scar_id: str = "KS-900",
        num_free_runners: Optional[int] = None,
        include_paid_council: bool = False,
    ) -> Tuple[GoldenScar, Dict[str, Any]]:
        """
        Run the Tier-Gated `PrimaryPlusFreeCoExecutor` so the Primary Model always executes
        alongside 1 Free model (Free tier), 2..5 Free models (Pro tier), or Free + BYOK Paid Council (Enterprise tier).
        """
        primary_ep = self.endpoints[0] if self.endpoints else None
        executor = PrimaryPlusFreeCoExecutor(
            self.workspace_root,
            primary_endpoint=primary_ep,
            completion_fn=self._complete,
        )
        return executor.co_evolve_scar(
            trace,
            scar_id=scar_id,
            num_free_runners=num_free_runners,
            include_paid_council=include_paid_council,
        )

    def evolve(
        self,
        trace: FailureTrace,
        *,
        scar_id: str = "KS-900",
        max_attempts: int = 2,
    ) -> Tuple[GoldenScar, str]:
        """
        Synthesize and deterministically verify a GoldenScar from `trace`.
        Uses the 3-Agent Council when configured, otherwise falls back to offline heuristics.
        """
        if not self.endpoints:
            scar = self.evolve_offline(trace, scar_id=scar_id)
            ok, msg = verify_candidate_scar(scar)
            if not ok:
                raise ValueError(f"Offline scar synthesis failed self-verification: {msg}")
            return scar, msg

        by_role = {ep.role: ep for ep in self.endpoints}
        architect = by_role.get("architect", self.endpoints[0])
        synthesizer = by_role.get("synthesizer", self.endpoints[min(1, len(self.endpoints) - 1)])
        critic = by_role.get("critic", self.endpoints[-1])

        arch_notes = self._complete(
            architect,
            "You are the Kintsugi Architect Agent. Diagnose the exact root cause of the coding agent failure and output concise minimal bad_code vs good_code examples.",
            f"Language: {trace.language}\nSummary: {trace.error_summary}\nRaw Trace:\n{trace.raw_trace}\nOffending Snippet:\n{trace.offending_snippet}",
        )

        feedback = ""
        last_error = "No attempts run"
        for _ in range(max_attempts):
            synth_prompt = (
                f"Failure Summary: {trace.error_summary}\n"
                f"Language: {trace.language}\n"
                f"Architect Analysis:\n{arch_notes}\n"
                f"{feedback}\n"
                "Return ONLY valid JSON with keys: "
                "title, severity (CRITICAL|HIGH|MEDIUM|LOW), category, languages (list), tags (list), "
                "root_cause, bad_code, good_code, rationale, regex_pattern (string or null), ast_rule (string or null).\n"
                "Note: regex_pattern MUST match `bad_code` and MUST NOT match `good_code`. "
                "Supported Python ast_rule values: py_subprocess_shell_true, py_mutable_default_arg, "
                "py_silent_except_swallow, py_unsafe_dynamic_exec, py_http_missing_timeout, "
                "py_insecure_random_for_secret, call:<dotted_fn>, missing_kwarg:<dotted_fn>:<kwarg>."
            )
            raw_json_reply = self._complete(
                synthesizer,
                "You are the Kintsugi Synthesizer Agent. Emit strictly valid JSON defining a deterministic GoldenScar.",
                synth_prompt,
            )

            critic_reply = self._complete(
                critic,
                "You are the Kintsugi Red-Team Critic Agent. Audit the proposed GoldenScar JSON for false positives on idiomatic code, bypass vectors, or broken regex syntax. Return the refined GoldenScar JSON only.",
                f"Proposed GoldenScar:\n{raw_json_reply}\nOriginal Trace:\n{trace.error_summary}",
            )

            try:
                critic_verified = True
                try:
                    parsed = _extract_json_object(critic_reply)
                    if "title" not in parsed or "bad_code" not in parsed:
                        parsed = _extract_json_object(raw_json_reply)
                        critic_verified = False
                except ValueError:
                    parsed = _extract_json_object(raw_json_reply)
                    critic_verified = False
                provenance = [
                    f"architect:{architect.model}",
                    f"synthesizer:{synthesizer.model}",
                ]
                if critic_verified:
                    provenance.append(f"critic:{critic.model}")
                provenance.append("self-check")
                candidate = GoldenScar(
                    id=scar_id,
                    title=str(parsed["title"]),
                    severity=Severity(str(parsed.get("severity", "HIGH")).upper()),
                    category=str(parsed.get("category", "reliability")),
                    languages=list(parsed.get("languages") or [trace.language]),
                    tags=list(parsed.get("tags") or ["evolved"]),
                    root_cause=str(parsed["root_cause"]),
                    bad_code=str(parsed["bad_code"]),
                    good_code=str(parsed["good_code"]),
                    rationale=str(parsed["rationale"]),
                    regex_pattern=parsed.get("regex_pattern"),
                    ast_rule=parsed.get("ast_rule"),
                    verified_by=provenance,
                )
            except (KeyError, ValueError, TypeError) as exc:
                last_error = f"JSON schema parse error: {exc}"
                feedback = f"Previous attempt failed schema parsing: {last_error}"
                continue

            ok, msg = verify_candidate_scar(candidate)
            if ok:
                return candidate, msg
            last_error = msg
            feedback = f"Previous attempt failed deterministic self-check: {msg}. Fix regex_pattern/ast_rule and snippets."

        raise ValueError(f"Council failed to produce a self-verifying scar: {last_error}")

    @staticmethod
    def evolve_offline(trace: FailureTrace, *, scar_id: str = "KS-900") -> GoldenScar:
        """
        Deterministic zero-API-key heuristic synthesis from common failure traces
        and offending/fixed snippet pairs.
        """
        combined = f"{trace.error_summary}\n{trace.raw_trace}\n{trace.offending_snippet}"

        if "yaml.load(" in combined and "Loader" not in combined:
            return GoldenScar(
                id=scar_id,
                title="Unsafe yaml.load() call without SafeLoader",
                severity=Severity.CRITICAL,
                category="security",
                languages=["python"],
                tags=["yaml", "deserialization", "rce", "offline-evolved"],
                root_cause="Calling PyYAML yaml.load() without SafeLoader permits arbitrary Python object instantiation.",
                bad_code="import yaml\ncfg = yaml.load(raw_yaml)",
                good_code="import yaml\ncfg = yaml.safe_load(raw_yaml)",
                rationale="Enforces yaml.safe_load() to block arbitrary object execution.",
                ast_rule="py_unsafe_dynamic_exec",
                verified_by=["offline-heuristic", "self-check"],
            )

        if "shell=True" in combined:
            return GoldenScar(
                id=scar_id,
                title="Unsafe subprocess invocation with shell=True",
                severity=Severity.HIGH,
                category="security",
                languages=["python"],
                tags=["subprocess", "shell", "offline-evolved"],
                root_cause="Passing shell=True invokes /bin/sh on interpolated command strings.",
                bad_code='import subprocess\nsubprocess.run("ls " + user_dir, shell=True)',
                good_code='import subprocess\nsubprocess.run(["ls", user_dir], check=True)',
                rationale="Passes argument vectors directly to execve without shell expansion.",
                ast_rule="py_subprocess_shell_true",
                verified_by=["offline-heuristic", "self-check"],
            )

        if trace.offending_snippet.strip() and trace.fixed_snippet.strip():
            bad_line = next(
                (ln.strip() for ln in trace.offending_snippet.splitlines() if ln.strip()),
                trace.offending_snippet.strip(),
            )
            escaped = re.escape(bad_line)
            return GoldenScar(
                id=scar_id,
                title=trace.error_summary[:90] or "Regression pattern captured from failure trace",
                severity=Severity.MEDIUM,
                category="correctness",
                languages=[trace.language],
                tags=["regression", "offline-evolved"],
                root_cause=trace.error_summary or "Captured from failing execution trace.",
                bad_code=trace.offending_snippet.strip(),
                good_code=trace.fixed_snippet.strip(),
                rationale="Prevents re-introducing an exact verified regression line.",
                regex_pattern=escaped,
                verified_by=["offline-heuristic", "self-check"],
            )

        # Fallback: extract fatal call pattern from Python traceback line if present
        tb_code_lines = [
            ln.strip()
            for ln in trace.raw_trace.splitlines()
            if ln.startswith("    ") and not ln.strip().startswith(("File ", "^", "~"))
        ]
        if tb_code_lines:
            culprit = tb_code_lines[-1]
            return GoldenScar(
                id=scar_id,
                title=f"Prevent recurring crash: {trace.error_summary[:64]}",
                severity=Severity.MEDIUM,
                category="reliability",
                languages=[trace.language],
                tags=["traceback", "offline-evolved"],
                root_cause=trace.error_summary,
                bad_code=culprit,
                good_code=trace.fixed_snippet.strip() or f"# Guarded replacement for: {culprit.split('(')[0]}_safe()",
                rationale="Compiled directly from unhandled runtime traceback.",
                regex_pattern=re.escape(culprit),
                verified_by=["offline-heuristic", "self-check"],
            )

        raise ValueError(
            "Offline evolution requires either a recognized anti-pattern, a traceback code line, "
            "or both `offending_snippet` and `fixed_snippet`."
        )
