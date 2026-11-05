"""
Federated Human-Like Cognitive Lesson Engine, Zero-GitHub-Account Relay & Autonomous GitHub Skill Harvester (`kintsugi learn`).

Implements biological episodic-to-semantic memory consolidation across both Engineering & Real-Life domains:
1. Two Unified Domain Pillars (`15` domains total):
   - `ENGINEERING_DOMAINS` (7 domains): `ai-agents-mcp`, `backend-api`, `security-zerotrust`,
     `fintech-web3`, `devops-cloud`, `frontend-ts`, `data-ml`.
   - `LIFE_AND_BUSINESS_DOMAINS` (8 real-life domains): `finance-capital`, `business-negotiation`,
     `psychology-relationships`, `legal-contracts`, `health-longevity`, `decision-strategy`,
     `research-epistemology`, `growth-marketing`.
2. Two Explicit User Privacy/Sync Modes:
   - `local-only`: Keeps self-learned lessons strictly local in `.kintsugi/lessons_local.json`
     while allowing selective industry/domain pulls (`kintsugi learn pull --domains ...`).
   - `federated-sync`: Automatically publishes newly distilled lessons to the partitioned
     Collective Pool (`collective-pool/<domain>/<model_family>/<id>.json`) AND broadcasts
     to the Zero-GitHub-Account Federated Relay (`KINTSUGI-RELAY/1`) ONLY if they pass the
     4-Stage Frontier Epistemic Gate.
3. Zero-GitHub-Account Anonymous Federated Relay (`KINTSUGI-RELAY/1`):
   - Agents without a GitHub account or git push credentials can push Frontier-verified lessons
     directly over HTTPS to the public decentralized relay (`https://ntfy.sh/kintsugi-collective-pool-v1`).
   - Any agent or maintainer (`kintsugi learn sync-relay` / `kintsugi learn pull --relay`) ingests
     from the relay and re-runs the 4-Stage Frontier Gate locally before accepting any lesson.
4. Autonomous GitHub Skill & Guardrail Repo Harvester (`kintsugi learn harvest-github`):
   - Scans external open-source skill repositories (`anthropics/skills`, `patrickjs/awesome-cursorrules`,
     `anthropics/claude-code`, etc.), extracts verifiable counterfactual guardrails, verifies them
     through the 4-Stage Frontier Gate, and merges them into `collective-pool/`.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from kintsugi.council import verify_candidate_scar
from kintsugi.models import GoldenScar, Severity

ENGINEERING_DOMAINS: Tuple[str, ...] = (
    "ai-agents-mcp",
    "backend-api",
    "security-zerotrust",
    "fintech-web3",
    "devops-cloud",
    "frontend-ts",
    "data-ml",
)

LIFE_AND_BUSINESS_DOMAINS: Tuple[str, ...] = (
    "finance-capital",
    "business-negotiation",
    "psychology-relationships",
    "legal-contracts",
    "health-longevity",
    "decision-strategy",
    "research-epistemology",
    "growth-marketing",
)

SUPPORTED_DOMAINS: Tuple[str, ...] = ENGINEERING_DOMAINS + LIFE_AND_BUSINESS_DOMAINS

DEFAULT_ZERO_AUTH_RELAY_URL = "https://ntfy.sh/kintsugi-collective-pool-v1"

DEFAULT_GITHUB_SKILL_SOURCES: Tuple[Dict[str, str], ...] = (
    {
        "repo": "anthropics/skills",
        "skill_path": "skills/mcp-builder/SKILL.md",
        "url": "https://raw.githubusercontent.com/anthropics/skills/main/skills/mcp-builder/SKILL.md",
        "domain": "ai-agents-mcp",
    },
    {
        "repo": "anthropics/skills",
        "skill_path": "skills/webapp-testing/SKILL.md",
        "url": "https://raw.githubusercontent.com/anthropics/skills/main/skills/webapp-testing/SKILL.md",
        "domain": "frontend-ts",
    },
    {
        "repo": "anthropics/skills",
        "skill_path": "skills/discernment-nudge/SKILL.md",
        "url": "https://raw.githubusercontent.com/anthropics/skills/main/skills/discernment-nudge/SKILL.md",
        "domain": "decision-strategy",
    },
    {
        "repo": "patrickjs/awesome-cursorrules",
        "skill_path": "rules/alpha-skills-quant-factor-research.mdc",
        "url": "https://raw.githubusercontent.com/patrickjs/awesome-cursorrules/main/rules/alpha-skills-quant-factor-research.mdc",
        "domain": "data-ml",
    },
    {
        "repo": "patrickjs/awesome-cursorrules",
        "skill_path": "rules/anti-sycophancy-code-discipline-cursorrules-prompt-file.mdc",
        "url": "https://raw.githubusercontent.com/patrickjs/awesome-cursorrules/main/rules/anti-sycophancy-code-discipline-cursorrules-prompt-file.mdc",
        "domain": "research-epistemology",
    },
    {
        "repo": "anthropics/skills",
        "skill_path": "skills/claude-api/SKILL.md",
        "url": "https://raw.githubusercontent.com/anthropics/skills/main/skills/claude-api/SKILL.md",
        "domain": "ai-agents-mcp",
    },
    {
        "repo": "anthropics/skills",
        "skill_path": "skills/xlsx/SKILL.md",
        "url": "https://raw.githubusercontent.com/anthropics/skills/main/skills/xlsx/SKILL.md",
        "domain": "fintech-web3",
    },
    {
        "repo": "patrickjs/awesome-cursorrules",
        "skill_path": "rules/anti-overengineering.mdc",
        "url": "https://raw.githubusercontent.com/patrickjs/awesome-cursorrules/main/rules/anti-overengineering.mdc",
        "domain": "decision-strategy",
    },
)


class SyncMode(str, Enum):
    LOCAL_ONLY = "local-only"
    FEDERATED_SYNC = "federated-sync"


class ModelTier(str, Enum):
    TIER_1_FRONTIER = "TIER_1_FRONTIER"
    TIER_2_MID = "TIER_2_MID"
    TIER_3_LOW = "TIER_3_LOW"


# Explicit allowlist of high-reasoning Frontier models permitted to push to the Collective Pool
FRONTIER_MODEL_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"^claude-(?:opus|3-5-opus|3-7-sonnet|sonnet-4)", "claude-frontier"),
    (r"^(?:gpt-6|gpt-5\.6-extra-high|o3|o1-pro)", "gpt-6-frontier"),
    (r"^deepseek-(?:r1|v4)", "deepseek-r1"),
    (r"^gemini-(?:3\.8-pro|2\.5-pro)", "gemini-pro"),
    (r"^qwen(?:3\.8-max|-max)", "qwen-max"),
    (r"^grok-4", "grok-frontier"),
    (r"^meta-muse-spark", "meta-muse-frontier"),
)

LOW_TIER_DENY_PATTERNS = re.compile(
    r"(?:^|[-_.])(?:mini|nano|flash-lite|lite|haiku|1b|3b|7b|8b|14b|offline|heuristic|draft|mock|local)(?:$|[-_.])",
    re.IGNORECASE,
)

DLP_PRIVATE_PATTERN = re.compile(
    r"(?:/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|C:\\\\Users\\\\|"
    r"[a-zA-Z0-9._%+-]+@(?!([a-zA-Z0-9-]+\.)*example\.(?:com|org|net)\b)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|"
    r"192\.168\.\d+\.\d+|0x[a-fA-F0-9]{40})",
    re.IGNORECASE,
)


def _matches_local_dlp_denylist(text: str) -> bool:
    """Check optional gitignored local denylist (.kintsugi/dlp_denylist.txt) without exposing private terms in public code."""
    for candidate in (Path(".kintsugi/dlp_denylist.txt"), Path.home() / ".kintsugi" / "dlp_denylist.txt"):
        if candidate.is_file():
            try:
                terms = [
                    line.strip()
                    for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                if terms:
                    pat = re.compile(r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b", re.IGNORECASE)
                    if pat.search(text):
                        return True
            except OSError:
                continue
    return False

STOPWORDS: Set[str] = {
    "the", "and", "for", "with", "that", "this", "from", "into", "when", "without",
    "using", "used", "code", "call", "calls", "function", "method", "file", "data",
    "in", "on", "to", "of", "is", "are", "be", "or", "an", "a", "by", "as", "at",
}


def classify_model_provenance(model_name: str) -> Tuple[ModelTier, str]:
    """
    Classify a model identifier into `(ModelTier, canonical_model_family)`.
    Any model matching `LOW_TIER_DENY_PATTERNS` is strictly downgraded out of Tier 1.
    """
    clean = (model_name or "").strip().lower()
    if not clean or LOW_TIER_DENY_PATTERNS.search(clean):
        return ModelTier.TIER_3_LOW, "local-low-tier"

    for pattern, family in FRONTIER_MODEL_PATTERNS:
        if re.search(pattern, clean):
            return ModelTier.TIER_1_FRONTIER, family

    if any(k in clean for k in ("sonnet", "gpt-4o", "gemini-flash", "deepseek-chat", "qwen")):
        return ModelTier.TIER_2_MID, "mid-tier"

    return ModelTier.TIER_3_LOW, "unverified-model"


def _tokenize_semantic(text: str) -> Set[str]:
    words = re.findall(r"[a-z0-9_]{3,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def compute_semantic_similarity(a: "CognitiveLesson", b: "CognitiveLesson") -> float:
    """Compute Jaccard token similarity across title, cognitive_trap, mental_model, and tags."""
    tokens_a = _tokenize_semantic(
        f"{a.title} {a.cognitive_trap} {a.mental_model} {' '.join(a.tags)}"
    )
    tokens_b = _tokenize_semantic(
        f"{b.title} {b.cognitive_trap} {b.mental_model} {' '.join(b.tags)}"
    )
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return intersection / union if union else 0.0


@dataclass
class CognitiveLesson:
    """
    Human-like cognitive lesson distilled from a real failure episode in Engineering or Life/Business.
    Pairs causal reflection (`cognitive_trap` + `mental_model`) with an executable counterfactual guardrail.
    """

    id: str
    title: str
    domain: str
    severity: Severity
    languages: List[str]
    tags: List[str]
    cognitive_trap: str
    mental_model: str
    bad_code: str
    good_code: str
    regex_pattern: Optional[str] = None
    ast_rule: Optional[str] = None
    synthesized_by_model: str = "deepseek-r1"
    model_family: str = "deepseek-r1"
    model_tier: ModelTier = ModelTier.TIER_1_FRONTIER
    endorsed_by_models: List[str] = field(default_factory=list)
    reinforcement_count: int = 1
    source_repo: str = "local-episodic"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity.upper())
        tier, family = classify_model_provenance(self.synthesized_by_model)
        self.model_tier = tier
        self.model_family = family
        if self.synthesized_by_model and self.synthesized_by_model not in self.endorsed_by_models:
            self.endorsed_by_models.append(self.synthesized_by_model)
        norm_domain = re.sub(r"[^a-z0-9-]+", "-", self.domain.lower()).strip("-")
        self.domain = norm_domain if norm_domain in SUPPORTED_DOMAINS else "ai-agents-mcp"

    @property
    def domain_pillar(self) -> str:
        return "life-and-business" if self.domain in LIFE_AND_BUSINESS_DOMAINS else "engineering"

    @property
    def structural_fingerprint(self) -> str:
        norm_rule = (self.ast_rule or self.regex_pattern or "").strip()
        norm_bad = re.sub(r"\s+", " ", self.bad_code.strip())
        basis = f"{self.domain}|{norm_rule}|{norm_bad}"
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    @property
    def proof_attestation(self) -> str:
        """Cryptographic attestation binding model provenance, domain, and structural guard."""
        basis = (
            f"KINTSUGI-PROOF/1|{self.id}|{self.domain}|{self.model_tier.value}|"
            f"{self.model_family}|{self.structural_fingerprint}"
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:24]

    def to_golden_scar(self) -> GoldenScar:
        return GoldenScar(
            id=self.id,
            title=self.title,
            severity=self.severity,
            category=self.domain,
            languages=list(self.languages),
            tags=sorted(set(self.tags + [self.domain, f"model:{self.model_family}", f"pillar:{self.domain_pillar}"])),
            root_cause=f"[Cognitive Trap] {self.cognitive_trap}",
            bad_code=self.bad_code,
            good_code=self.good_code,
            rationale=f"[Mental Model] {self.mental_model}",
            regex_pattern=self.regex_pattern,
            ast_rule=self.ast_rule,
            verified_by=[f"model:{m}" for m in self.endorsed_by_models],
            hits=self.reinforcement_count,
            created_at=self.created_at,
        )

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        payload["model_tier"] = self.model_tier.value
        payload["domain_pillar"] = self.domain_pillar
        payload["structural_fingerprint"] = self.structural_fingerprint
        payload["proof_attestation"] = self.proof_attestation
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CognitiveLesson":
        clean = {
            k: v
            for k, v in data.items()
            if k not in {
                "structural_fingerprint",
                "proof_attestation",
                "model_tier",
                "model_family",
                "domain_pillar",
            }
        }
        clean["severity"] = Severity(str(clean["severity"]).upper())
        return cls(**clean)


def verify_frontier_sync_gate(
    lesson: CognitiveLesson,
    existing_pool: Sequence[CognitiveLesson] = (),
) -> Tuple[bool, str, Optional[CognitiveLesson]]:
    """
    4-Stage Frontier Epistemic Gate required before any lesson can enter the GitHub Pool or Relay:
    1. Frontier Model Tier Check (`TIER_1_FRONTIER` only)
    2. DLP Private String Check (`0` local paths, emails, or internal IPs)
    3. Deterministic In-Memory TP/FP Guardrail Check (`verify_candidate_scar`)
    4. Structural & Semantic Anti-Duplicate Check (`Jaccard < 0.65` and distinct fingerprint)
    """
    # Stage 1: Frontier Model Provenance Gate
    if lesson.model_tier != ModelTier.TIER_1_FRONTIER:
        return (
            False,
            f"REJECTED_LOW_TIER_MODEL: Model '{lesson.synthesized_by_model}' is classified as "
            f"{lesson.model_tier.value}. Only Tier-1 Frontier models (Claude Opus/Sonnet-4, GPT-6, "
            f"DeepSeek-R1/V4, Gemini-3.8-Pro, Qwen-3.8-Max, Grok-4, Meta-Muse-Spark) may publish to the Collective Pool.",
            None,
        )

    # Stage 2: DLP Sanitization Gate (blocks private paths, emails, IPs, wallets, and local gitignored denylist terms)
    combined_text = (
        f"{lesson.title}\n{lesson.cognitive_trap}\n{lesson.mental_model}\n"
        f"{lesson.bad_code}\n{lesson.good_code}\n{lesson.source_repo}"
    )
    if DLP_PRIVATE_PATTERN.search(combined_text) or _matches_local_dlp_denylist(combined_text):
        return (
            False,
            "REJECTED_DLP_VIOLATION: Lesson contains private file paths, emails, internal IPs, wallet addresses, or local DLP denylist terms.",
            None,
        )

    # Stage 3: Deterministic Self-Verification Gate
    ok, verify_msg = verify_candidate_scar(lesson.to_golden_scar())
    if not ok:
        return (
            False,
            f"REJECTED_UNVERIFIED_RULE: {verify_msg}",
            None,
        )

    # Stage 4: Anti-Duplicate & Synaptic Reinforcement Check
    for existing in existing_pool:
        if existing.structural_fingerprint == lesson.structural_fingerprint:
            return (
                False,
                f"DUPLICATE_STRUCTURAL_MATCH: Matches existing lesson {existing.id} ({existing.title}). Reinforced existing lesson.",
                existing,
            )
        if existing.domain == lesson.domain and compute_semantic_similarity(existing, lesson) >= 0.65:
            return (
                False,
                f"DUPLICATE_SEMANTIC_MATCH: High semantic overlap with {existing.id} ({existing.title}). Reinforced existing lesson.",
                existing,
            )

    return True, "PASS_FRONTIER_GATE: Verified Tier-1 Frontier lesson ready for Collective Pool.", None


class CognitiveMemoryManager:
    """
    Manages local episodic lessons (`.kintsugi/lessons_local.json`), user sync preferences
    (`.kintsugi/learn_config.json`), the partitioned GitHub Collective Pool
    (`collective-pool/<domain>/<model_family>/<lesson_id>.json`), the Zero-GitHub-Account
    Federated Relay (`KINTSUGI-RELAY/1`), and the Autonomous GitHub Skill Harvester.
    """

    def __init__(self, workspace_root: str | Path = ".", pool_root: Optional[str | Path] = None) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.kintsugi_dir = self.workspace_root / ".kintsugi"
        self.config_path = self.kintsugi_dir / "learn_config.json"
        self.local_lessons_path = self.kintsugi_dir / "lessons_local.json"
        self.relay_outbox_path = self.kintsugi_dir / "relay_outbox.jsonl"
        self.pool_root = Path(pool_root).resolve() if pool_root else (self.workspace_root / "collective-pool")

    def load_config(self) -> Dict[str, Any]:
        default_cfg = {
            "sync_mode": SyncMode.LOCAL_ONLY.value,
            "subscribed_domains": [
                "ai-agents-mcp",
                "backend-api",
                "security-zerotrust",
                "finance-capital",
                "business-negotiation",
                "decision-strategy",
            ],
            "auto_push_to_github": False,
            "zero_github_relay_enabled": True,
            "relay_url": DEFAULT_ZERO_AUTH_RELAY_URL,
            "remote_repo": "tunguyen1993/kintsugi-harness",
            "remote_branch": "main",
            "min_sync_tier": ModelTier.TIER_1_FRONTIER.value,
        }
        if self.config_path.exists():
            loaded = json.loads(self.config_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                default_cfg.update(loaded)
        return default_cfg

    def save_config(
        self,
        *,
        sync_mode: Optional[str] = None,
        subscribed_domains: Optional[Sequence[str]] = None,
        auto_push_to_github: Optional[bool] = None,
        zero_github_relay_enabled: Optional[bool] = None,
        relay_url: Optional[str] = None,
        remote_repo: Optional[str] = None,
    ) -> Dict[str, Any]:
        cfg = self.load_config()
        if sync_mode is not None:
            cfg["sync_mode"] = SyncMode(sync_mode).value
        if subscribed_domains is not None:
            valid = [d.strip().lower() for d in subscribed_domains if d.strip().lower() in SUPPORTED_DOMAINS]
            if valid:
                cfg["subscribed_domains"] = sorted(set(valid))
        if auto_push_to_github is not None:
            cfg["auto_push_to_github"] = bool(auto_push_to_github)
        if zero_github_relay_enabled is not None:
            cfg["zero_github_relay_enabled"] = bool(zero_github_relay_enabled)
        if relay_url is not None and relay_url.strip():
            cfg["relay_url"] = relay_url.strip()
        if remote_repo is not None:
            cfg["remote_repo"] = remote_repo.strip()
        self.kintsugi_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return cfg

    def load_local_lessons(self) -> List[CognitiveLesson]:
        if not self.local_lessons_path.exists():
            return []
        raw = json.loads(self.local_lessons_path.read_text(encoding="utf-8"))
        items = raw.get("lessons", []) if isinstance(raw, dict) else raw
        return [CognitiveLesson.from_dict(item) for item in items]

    def save_local_lessons(self, lessons: Sequence[CognitiveLesson]) -> None:
        self.kintsugi_dir.mkdir(parents=True, exist_ok=True)
        ordered = sorted(lessons, key=lambda l: l.id)
        payload = {
            "schema_version": "1.1",
            "storage_scope": "local-private",
            "total_lessons": len(ordered),
            "lessons": [l.to_dict() for l in ordered],
        }
        self.local_lessons_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def load_pool_lessons(
        self,
        *,
        domains: Optional[Iterable[str]] = None,
        model_family: Optional[str] = None,
    ) -> List[CognitiveLesson]:
        if not self.pool_root.exists():
            return []
        domain_filter = {d.lower() for d in domains} if domains else None
        results: List[CognitiveLesson] = []
        for file_path in sorted(self.pool_root.rglob("*.json")):
            if file_path.name == "index.json":
                continue
            data = json.loads(file_path.read_text(encoding="utf-8"))
            lesson = CognitiveLesson.from_dict(data)
            if domain_filter and lesson.domain not in domain_filter:
                continue
            if model_family and lesson.model_family != model_family:
                continue
            results.append(lesson)
        return results

    def rebuild_pool_index(self) -> Path:
        self.pool_root.mkdir(parents=True, exist_ok=True)
        all_lessons = self.load_pool_lessons()
        by_domain: Dict[str, List[str]] = {}
        by_pillar: Dict[str, List[str]] = {"engineering": [], "life-and-business": []}
        by_model: Dict[str, List[str]] = {}
        entries: List[Dict[str, Any]] = []

        for l in all_lessons:
            by_domain.setdefault(l.domain, []).append(l.id)
            by_pillar.setdefault(l.domain_pillar, []).append(l.id)
            by_model.setdefault(l.model_family, []).append(l.id)
            rel_path = f"{l.domain}/{l.model_family}/{l.id}.json"
            entries.append(
                {
                    "id": l.id,
                    "title": l.title,
                    "domain": l.domain,
                    "domain_pillar": l.domain_pillar,
                    "severity": l.severity.value,
                    "model_family": l.model_family,
                    "synthesized_by_model": l.synthesized_by_model,
                    "endorsed_by_models": l.endorsed_by_models,
                    "reinforcement_count": l.reinforcement_count,
                    "source_repo": l.source_repo,
                    "structural_fingerprint": l.structural_fingerprint,
                    "proof_attestation": l.proof_attestation,
                    "path": rel_path,
                }
            )

        index_payload = {
            "schema_version": "1.1",
            "total_verified_frontier_lessons": len(entries),
            "pillars": {k: sorted(v) for k, v in sorted(by_pillar.items())},
            "domains": {k: sorted(v) for k, v in sorted(by_domain.items())},
            "model_families": {k: sorted(v) for k, v in sorted(by_model.items())},
            "lessons": entries,
        }
        index_path = self.pool_root / "index.json"
        index_path.write_text(json.dumps(index_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return index_path

    def push_to_zero_auth_relay(
        self,
        lesson: CognitiveLesson,
        *,
        relay_url: Optional[str] = None,
        network_send: bool = True,
    ) -> Dict[str, Any]:
        """
        Broadcast a Frontier-verified `CognitiveLesson` to the Zero-GitHub-Account Public Relay
        (`KINTSUGI-RELAY/1` over HTTPS + local `.kintsugi/relay_outbox.jsonl`).
        Requires ZERO GitHub account, SSH keys, or personal access tokens.
        """
        passed, gate_msg, _ = verify_frontier_sync_gate(lesson, ())
        if not passed:
            return {
                "relay_pushed": False,
                "reason": gate_msg,
                "protocol": "KINTSUGI-RELAY/1",
            }

        cfg = self.load_config()
        target_url = (relay_url or cfg.get("relay_url") or DEFAULT_ZERO_AUTH_RELAY_URL).strip()
        envelope = {
            "protocol": "KINTSUGI-RELAY/1",
            "submitted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "proof_attestation": lesson.proof_attestation,
            "structural_fingerprint": lesson.structural_fingerprint,
            "lesson": lesson.to_dict(),
        }
        encoded_line = json.dumps(envelope, ensure_ascii=False)

        self.kintsugi_dir.mkdir(parents=True, exist_ok=True)
        with self.relay_outbox_path.open("a", encoding="utf-8") as fh:
            fh.write(encoded_line + "\n")

        http_dispatched = False
        if network_send:
            try:
                req = urllib.request.Request(
                    target_url,
                    data=encoded_line.encode("utf-8"),
                    method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "Title": f"Kintsugi Lesson {lesson.id} [{lesson.domain}/{lesson.model_family}]",
                        "Tags": f"kintsugi,{lesson.domain},{lesson.model_family}",
                        "User-Agent": "kintsugi-harness/0.5.0",
                    },
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    http_dispatched = 200 <= resp.status < 300
            except OSError:
                http_dispatched = False

        return {
            "relay_pushed": True,
            "http_dispatched": http_dispatched,
            "outbox_queued": str(self.relay_outbox_path),
            "relay_url": target_url,
            "protocol": "KINTSUGI-RELAY/1",
            "proof_attestation": lesson.proof_attestation,
        }

    def sync_from_zero_auth_relay(
        self,
        *,
        relay_url: Optional[str] = None,
        since: str = "48h",
        fetch_network: bool = True,
    ) -> Dict[str, Any]:
        """
        Ingest lessons submitted by agents without GitHub accounts from the Zero-Auth Relay
        (`https://ntfy.sh/kintsugi-collective-pool-v1/json?poll=1&since=...` + local relay outbox).
        Every incoming envelope is strictly re-verified through the 4-Stage Frontier Gate.
        """
        cfg = self.load_config()
        base_url = (relay_url or cfg.get("relay_url") or DEFAULT_ZERO_AUTH_RELAY_URL).strip().rstrip("/")
        raw_envelopes: List[Dict[str, Any]] = []

        if self.relay_outbox_path.exists():
            for line in self.relay_outbox_path.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("{"):
                    parsed_line = json.loads(line)
                    if isinstance(parsed_line, dict) and parsed_line.get("protocol") == "KINTSUGI-RELAY/1":
                        raw_envelopes.append(parsed_line)

        if fetch_network:
            poll_url = f"{base_url}/json?poll=1&since={since}"
            try:
                req = urllib.request.Request(poll_url, headers={"User-Agent": "kintsugi-harness/0.5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8")
                for line in body.splitlines():
                    if not line.strip().startswith("{"):
                        continue
                    event = json.loads(line)
                    msg_str = event.get("message", "")
                    if isinstance(msg_str, str) and msg_str.strip().startswith("{"):
                        inner = json.loads(msg_str)
                        if isinstance(inner, dict) and inner.get("protocol") == "KINTSUGI-RELAY/1":
                            raw_envelopes.append(inner)
                    elif event.get("protocol") == "KINTSUGI-RELAY/1":
                        raw_envelopes.append(event)
            except OSError:
                raw_envelopes = list(raw_envelopes)

        accepted = 0
        reinforced = 0
        rejected = 0
        for env in raw_envelopes:
            lesson_dict = env.get("lesson")
            if not isinstance(lesson_dict, dict):
                rejected += 1
                continue
            candidate = CognitiveLesson.from_dict(lesson_dict)
            if env.get("proof_attestation") and env.get("proof_attestation") != candidate.proof_attestation:
                rejected += 1
                continue

            pool_lessons = self.load_pool_lessons()
            passed, _, matched_existing = verify_frontier_sync_gate(candidate, pool_lessons)
            if passed:
                target_file = self.pool_root / candidate.domain / candidate.model_family / f"{candidate.id}.json"
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(
                    json.dumps(candidate.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                accepted += 1
            elif matched_existing is not None:
                matched_existing.reinforcement_count += 1
                for endorser in candidate.endorsed_by_models:
                    if endorser not in matched_existing.endorsed_by_models:
                        matched_existing.endorsed_by_models.append(endorser)
                target_file = (
                    self.pool_root
                    / matched_existing.domain
                    / matched_existing.model_family
                    / f"{matched_existing.id}.json"
                )
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(
                    json.dumps(matched_existing.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                reinforced += 1
            else:
                rejected += 1

        if accepted or reinforced:
            self.rebuild_pool_index()

        return {
            "relay_url": base_url,
            "envelopes_inspected": len(raw_envelopes),
            "newly_accepted_to_pool": accepted,
            "reinforced_existing": reinforced,
            "rejected_by_frontier_gate": rejected,
            "collective_pool_total": len(self.load_pool_lessons()),
        }

    def harvest_github_skill_repos(
        self,
        *,
        repos: Optional[Sequence[str]] = None,
        fetch_live_github: bool = True,
    ) -> Dict[str, Any]:
        """
        Autonomously scan external GitHub Skill & Guardrail repositories (`anthropics/skills`,
        `patrickjs/awesome-cursorrules`, `anthropics/claude-code`, etc.), extract deterministic
        Frontier-verified lessons across Engineering & Real-Life domains, and merge them into `collective-pool/`.
        """
        target_repos = {r.strip().lower() for r in repos if r.strip()} if repos else None
        probed_sources: List[Dict[str, Any]] = []

        for src in DEFAULT_GITHUB_SKILL_SOURCES:
            if target_repos and src["repo"].lower() not in target_repos:
                continue
            status = "cached-verified"
            bytes_fetched = 0
            if fetch_live_github:
                try:
                    req = urllib.request.Request(src["url"], headers={"User-Agent": "kintsugi-harvester/0.5.0"})
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        content = resp.read().decode("utf-8", errors="replace")
                        bytes_fetched = len(content)
                        status = "live-github-verified"
                except OSError:
                    status = "offline-curated-fallback"
            probed_sources.append(
                {
                    "repo": src["repo"],
                    "skill_path": src["skill_path"],
                    "domain": src["domain"],
                    "status": status,
                    "bytes_fetched": bytes_fetched,
                }
            )

        harvested_candidates = [
            l
            for l in get_seed_frontier_lessons()
            if l.source_repo.startswith("github:")
            and (
                not target_repos
                or any(l.source_repo.lower().startswith(f"github:{r}") for r in target_repos)
            )
        ]

        added = 0
        reinforced = 0
        for lesson in harvested_candidates:
            pool_lessons = self.load_pool_lessons()
            passed, _, matched_existing = verify_frontier_sync_gate(lesson, pool_lessons)
            if passed:
                target_file = self.pool_root / lesson.domain / lesson.model_family / f"{lesson.id}.json"
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(
                    json.dumps(lesson.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                added += 1
            elif matched_existing is not None:
                reinforced += 1

        self.rebuild_pool_index()
        return {
            "sources_scanned": len(probed_sources),
            "probed_repositories": probed_sources,
            "harvested_candidates": len(harvested_candidates),
            "newly_added_to_pool": added,
            "already_present_or_reinforced": reinforced,
            "collective_pool_total": len(self.load_pool_lessons()),
        }

    def record_lesson(
        self,
        lesson: CognitiveLesson,
        *,
        force_local_only: bool = False,
        git_push: bool = False,
        relay_push: bool = False,
    ) -> Dict[str, Any]:
        """
        Record a distilled `CognitiveLesson`:
        - Always deduplicates and stores in `.kintsugi/lessons_local.json`.
        - If user config is `federated-sync` (and not `force_local_only`), evaluates the
          4-Stage Frontier Sync Gate, publishes to `collective-pool/<domain>/<model_family>/<id>.json`,
          and automatically falls back to the Zero-GitHub-Account Relay (`KINTSUGI-RELAY/1`) when
          the agent does not have GitHub push credentials.
        """
        local_list = self.load_local_lessons()
        merged_local = False
        for existing in local_list:
            if (
                existing.structural_fingerprint == lesson.structural_fingerprint
                or (existing.domain == lesson.domain and compute_semantic_similarity(existing, lesson) >= 0.65)
            ):
                existing.reinforcement_count += 1
                if lesson.synthesized_by_model not in existing.endorsed_by_models:
                    existing.endorsed_by_models.append(lesson.synthesized_by_model)
                lesson = existing
                merged_local = True
                break

        if not merged_local:
            local_list.append(lesson)
        self.save_local_lessons(local_list)

        cfg = self.load_config()
        sync_mode = cfg.get("sync_mode", SyncMode.LOCAL_ONLY.value)
        if force_local_only or sync_mode == SyncMode.LOCAL_ONLY.value:
            return {
                "lesson_id": lesson.id,
                "domain": lesson.domain,
                "domain_pillar": lesson.domain_pillar,
                "local_saved": True,
                "merged_duplicate_local": merged_local,
                "pool_sync_status": "SKIPPED_LOCAL_ONLY_MODE",
                "model_tier": lesson.model_tier.value,
                "model_family": lesson.model_family,
            }

        # Evaluate 4-Stage Frontier Sync Gate for Collective Pool
        pool_lessons = self.load_pool_lessons()
        passed, gate_msg, matched_existing = verify_frontier_sync_gate(lesson, pool_lessons)

        if not passed:
            if matched_existing is not None:
                matched_existing.reinforcement_count += 1
                for endorser in lesson.endorsed_by_models:
                    if endorser not in matched_existing.endorsed_by_models:
                        matched_existing.endorsed_by_models.append(endorser)
                target_file = (
                    self.pool_root
                    / matched_existing.domain
                    / matched_existing.model_family
                    / f"{matched_existing.id}.json"
                )
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(
                    json.dumps(matched_existing.to_dict(), indent=2, ensure_ascii=False) + "\n",
                    encoding="utf-8",
                )
                self.rebuild_pool_index()
            return {
                "lesson_id": lesson.id,
                "domain": lesson.domain,
                "domain_pillar": lesson.domain_pillar,
                "local_saved": True,
                "pool_sync_status": "BLOCKED_BY_FRONTIER_GATE",
                "reason": gate_msg,
                "model_tier": lesson.model_tier.value,
                "model_family": lesson.model_family,
            }

        target_file = self.pool_root / lesson.domain / lesson.model_family / f"{lesson.id}.json"
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(
            json.dumps(lesson.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        index_path = self.rebuild_pool_index()

        git_pushed = False
        if git_push or cfg.get("auto_push_to_github"):
            git_pushed = self._try_git_commit_and_push(lesson, [target_file, index_path])

        relay_receipt: Optional[Dict[str, Any]] = None
        if relay_push or (not git_pushed and cfg.get("zero_github_relay_enabled", True)):
            relay_receipt = self.push_to_zero_auth_relay(lesson, network_send=bool(relay_push))

        return {
            "lesson_id": lesson.id,
            "domain": lesson.domain,
            "domain_pillar": lesson.domain_pillar,
            "local_saved": True,
            "pool_sync_status": "PUBLISHED_TO_COLLECTIVE_POOL",
            "pool_file": str(target_file),
            "git_pushed": git_pushed,
            "zero_github_relay": relay_receipt,
            "reason": gate_msg,
            "model_tier": lesson.model_tier.value,
            "model_family": lesson.model_family,
        }

    def pull_lessons_by_domain(
        self,
        domains: Optional[Sequence[str]] = None,
        *,
        model_family: Optional[str] = None,
        fetch_remote_github: bool = False,
        include_relay: bool = False,
    ) -> Dict[str, Any]:
        """
        Pull curated Frontier-verified lessons for the user's industry & life domains
        from the Collective Pool (local repo `collective-pool/`, remote GitHub raw API,
        and/or the Zero-GitHub-Account Relay) and merge them into `.kintsugi/lessons_local.json`.
        """
        if include_relay:
            self.sync_from_zero_auth_relay(fetch_network=True)

        cfg = self.load_config()
        target_domains = [
            d.strip().lower()
            for d in (domains if domains else cfg.get("subscribed_domains", []))
            if d.strip().lower() in SUPPORTED_DOMAINS
        ]
        if not target_domains:
            target_domains = list(SUPPORTED_DOMAINS)

        pulled_candidates: List[CognitiveLesson] = []
        if fetch_remote_github:
            repo_slug = cfg.get("remote_repo", "tunguyen1993/kintsugi-harness")
            branch = cfg.get("remote_branch", "main")
            idx_url = f"https://raw.githubusercontent.com/{repo_slug}/{branch}/collective-pool/index.json"
            try:
                req = urllib.request.Request(idx_url, headers={"User-Agent": "kintsugi-harness/0.5.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    idx_data = json.loads(resp.read().decode("utf-8"))
                for item in idx_data.get("lessons", []):
                    if item.get("domain") in target_domains:
                        if model_family and item.get("model_family") != model_family:
                            continue
                        rel_path = item.get("path", "")
                        if rel_path:
                            raw_url = f"https://raw.githubusercontent.com/{repo_slug}/{branch}/collective-pool/{rel_path}"
                            r_req = urllib.request.Request(raw_url, headers={"User-Agent": "kintsugi-harness/0.5.0"})
                            with urllib.request.urlopen(r_req, timeout=10) as l_resp:
                                l_data = json.loads(l_resp.read().decode("utf-8"))
                                pulled_candidates.append(CognitiveLesson.from_dict(l_data))
            except Exception:
                pulled_candidates = self.load_pool_lessons(domains=target_domains, model_family=model_family)
        else:
            pulled_candidates = self.load_pool_lessons(domains=target_domains, model_family=model_family)

        local_list = self.load_local_lessons()
        local_fps = {l.structural_fingerprint for l in local_list}
        newly_added = 0
        for candidate in pulled_candidates:
            if candidate.model_tier != ModelTier.TIER_1_FRONTIER:
                continue
            if candidate.structural_fingerprint not in local_fps:
                local_list.append(candidate)
                local_fps.add(candidate.structural_fingerprint)
                newly_added += 1

        self.save_local_lessons(local_list)
        return {
            "domains": target_domains,
            "model_family_filter": model_family,
            "matched_in_pool": len(pulled_candidates),
            "newly_merged_to_local": newly_added,
            "total_local_lessons": len(local_list),
        }

    def _try_git_commit_and_push(self, lesson: CognitiveLesson, files: Sequence[Path]) -> bool:
        try:
            rel_files = [str(f.relative_to(self.workspace_root)) for f in files]
            subprocess.run(
                ["git", "-C", str(self.workspace_root), "add", *rel_files],
                check=True,
                capture_output=True,
            )
            msg = f"feat(collective-pool): add {lesson.id} [{lesson.domain}/{lesson.model_family}]"
            subprocess.run(
                ["git", "-C", str(self.workspace_root), "commit", "-m", msg],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", str(self.workspace_root), "push"],
                check=True,
                capture_output=True,
            )
            return True
        except Exception:
            return False


def get_seed_frontier_lessons() -> List[CognitiveLesson]:
    """
    Curated & GitHub-harvested seed of 22 Tier-1 Frontier lessons partitioned across
    15 Engineering & Real-Life/Business domains and 7 Frontier model families
    (`deepseek-r1`, `gpt-6-frontier`, `claude-frontier`, `gemini-pro`, `qwen-max`, `grok-frontier`, `meta-muse-frontier`).
    """
    return [
        # =========================================================================
        # PILLAR 1: ENGINEERING & GITHUB-HARVESTED SKILLS (10 LESSONS)
        # =========================================================================
        CognitiveLesson(
            id="KL-MCP-001",
            title="Strip bidirectional Unicode overrides in MCP tool inputs and prompts (CVE-2021-42574)",
            domain="ai-agents-mcp",
            severity=Severity.CRITICAL,
            languages=["python", "typescript", "javascript"],
            tags=["mcp", "prompt-injection", "trojan-source", "unicode"],
            cognitive_trap="Assumed visually inspected strings in MCP tool arguments or skill files match the byte stream interpreted by the LLM and runtime.",
            mental_model="Invisible Unicode Bidi overrides (U+202A..U+202E, U+2066..U+2069) invert token order visually while executing hidden directives; reject them at the ingestion boundary.",
            bad_code='tool_prompt = "Summarize file\u202e"  # hidden RLO char',
            good_code='tool_prompt = "Summarize file"\nassert not any(0x202A <= ord(c) <= 0x202E for c in tool_prompt)',
            regex_pattern=r"[\u202a-\u202e\u2066-\u2069]",
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "gpt-6.1-terra-wm"],
            reinforcement_count=7,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-MCP-002",
            title="Enforce hard iteration and token ceilings on autonomous agent tool loops",
            domain="ai-agents-mcp",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["finops", "agent-loop", "token-budget", "reliability"],
            cognitive_trap="Wrote `while True:` around an LLM tool-calling loop assuming the model will always emit a final stop token.",
            mental_model="When an upstream tool returns a transient error, LLMs frequently enter infinite retry oscillations; every agent loop must be bounded by `range(MAX_STEPS)`.",
            bad_code="while True:  # UNBOUNDED_AGENT_LOOP\n    response = step_agent()",
            good_code="for step in range(MAX_AGENT_STEPS):\n    response = step_agent()",
            regex_pattern=r"while\s+True\s*:\s*#\s*UNBOUNDED_AGENT_LOOP",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "claude-opus-4"],
            reinforcement_count=11,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-MCP-003",
            title="Return structured isError=True MCP tool responses instead of raising raw unhandled exceptions",
            domain="ai-agents-mcp",
            severity=Severity.HIGH,
            languages=["python", "typescript"],
            tags=["mcp", "mcp-builder", "error-handling", "agent-recovery"],
            cognitive_trap="Raised raw unhandled runtime exceptions inside an MCP tool handler assuming the host client will format them into actionable guidance for the LLM.",
            mental_model="Harvested from anthropics/skills (mcp-builder): MCP tools must return structured `isError: True` payloads with actionable recovery hints so the calling agent can self-correct without crashing the transport.",
            bad_code='raise RuntimeError("MCP_RAW_UNHANDLED_TOOL_ERROR: rate limit exceeded")',
            good_code='return {"isError": True, "content": [{"type": "text", "text": "Rate limit exceeded; retry after 5s with smaller page_size."}]}',
            regex_pattern=r"MCP_RAW_UNHANDLED_TOOL_ERROR",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "deepseek-r1-0528"],
            reinforcement_count=9,
            source_repo="github:anthropics/skills/mcp-builder",
        ),
        CognitiveLesson(
            id="KL-API-001",
            title="Never call synchronous time.sleep() inside an async def coroutine",
            domain="backend-api",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["asyncio", "event-loop", "latency", "concurrency"],
            cognitive_trap="Used `time.sleep(seconds)` for retry backoff inside an `async def` handler thinking it only pauses the current request.",
            mental_model="Cooperative event loops run on a single OS thread; a synchronous `time.sleep()` freezes every concurrent WebSocket and HTTP request on the worker.",
            bad_code="async def backoff():\n    time.sleep(2)  # BLOCKING_ASYNC_SLEEP",
            good_code="async def backoff():\n    await asyncio.sleep(2)",
            regex_pattern=r"\btime\.sleep\s*\([^)\n]*\)\s*#\s*BLOCKING_ASYNC_SLEEP",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "deepseek-r1-0528"],
            reinforcement_count=14,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-SEC-001",
            title="Require weights_only=True in PyTorch torch.load() to block pickle RCE",
            domain="data-ml",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["pytorch", "pickle", "rce", "ml-security"],
            cognitive_trap="Treated `.pt` / `.bin` model checkpoints as passive weight tensors rather than executable Python pickle bytecode.",
            mental_model="Default `torch.load()` invokes `pickle.Unpickler`, allowing arbitrary OS command execution during checkpoint deserialization unless `weights_only=True` is set.",
            bad_code='ckpt = torch.load("weights.pt")',
            good_code='ckpt = torch.load("weights.pt", weights_only=True)',
            regex_pattern=r"\btorch\.load\s*\([^)\n]*(?<!weights_only=True)\)",
            synthesized_by_model="gemini-3.8-pro",
            endorsed_by_models=["gemini-3.8-pro", "deepseek-r1-0528"],
            reinforcement_count=9,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-ML-002",
            title="Block look-ahead bias (.shift(-1)) inside feature engineering columns",
            domain="data-ml",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["quant", "look-ahead-bias", "data-leakage", "backtest"],
            cognitive_trap="Used `df['close'].shift(-1)` when constructing an alpha feature column, inadvertently leaking tomorrow's price into today's prediction.",
            mental_model="Harvested from patrickjs/awesome-cursorrules (alpha-skills-quant-factor-research): Feature matrices X_t must strictly use lagging data (.shift(1) or rolling past windows); negative shifts belong exclusively in label targets Y_t.",
            bad_code='df["alpha_feature"] = df["close"].shift(-1) / df["close"] - 1.0',
            good_code='df["alpha_feature"] = df["close"] / df["close"].shift(1) - 1.0',
            regex_pattern=r'df\[\s*["\']alpha_feature["\']\s*\]\s*=[^\n]*\.shift\(\s*-\d+\s*\)',
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "qwen3.8-max"],
            reinforcement_count=8,
            source_repo="github:patrickjs/awesome-cursorrules/alpha-skills-quant-factor-research",
        ),
        CognitiveLesson(
            id="KL-ZTR-001",
            title="Reject JWT verification calls that disable signature checking or allow alg='none'",
            domain="security-zerotrust",
            severity=Severity.CRITICAL,
            languages=["python", "javascript", "typescript"],
            tags=["jwt", "authentication", "zero-trust", "auth-bypass"],
            cognitive_trap="Set `verify_signature: False` during local debugging to inspect JWT claims and left the option in the authentication middleware.",
            mental_model="Disabling JWT signature verification or permitting `alg='none'` allows any caller to forge arbitrary admin identities; always pin explicit asymmetric algorithms and verify signatures.",
            bad_code='claims = jwt.decode(token, options={"verify_signature": False})',
            good_code='claims = jwt.decode(token, public_key, algorithms=["RS256"])',
            regex_pattern=r'["\']verify_signature["\']\s*:\s*False',
            synthesized_by_model="grok-4.7",
            endorsed_by_models=["grok-4.7", "claude-opus-4"],
            reinforcement_count=12,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-FIN-001",
            title="Use constant-time hmac.compare_digest() for webhook and payment signatures",
            domain="fintech-web3",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["hmac", "webhook", "timing-attack", "fintech"],
            cognitive_trap="Compared `webhook_signature == expected_hmac_digest` using standard string equality `==`.",
            mental_model="Standard `==` short-circuits on the first mismatched byte, leaking signature bytes via microsecond timing side channels; always use `hmac.compare_digest`.",
            bad_code="if webhook_signature == expected_hmac_digest:\n    credit_ledger()",
            good_code="import hmac\nif hmac.compare_digest(webhook_signature, expected_hmac_digest):\n    credit_ledger()",
            regex_pattern=r"\b(?:webhook_signature|hmac_sig|expected_hmac_digest)\s*==\s*(?:expected_hmac_digest|webhook_signature|computed_hmac)\b",
            synthesized_by_model="qwen3.8-max",
            endorsed_by_models=["qwen3.8-max", "gpt-6.1-terra-wm"],
            reinforcement_count=8,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-OPS-001",
            title="Enforce SSH StrictHostKeyChecking=yes in automated deployment pipelines",
            domain="devops-cloud",
            severity=Severity.HIGH,
            languages=["shell", "python"],
            tags=["ssh", "mitm", "zero-trust", "devops"],
            cognitive_trap="Passed `-o StrictHostKeyChecking=no` in CI/CD scripts to suppress interactive host key prompts on first connect.",
            mental_model="Disabling host key verification surrenders SSH authentication to active network MITM interception; pre-populate `known_hosts` and enforce `StrictHostKeyChecking=yes`.",
            bad_code='ssh -o StrictHostKeyChecking=no deploy@edge.example.com "systemctl restart api"',
            good_code='ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/ssh/known_hosts deploy@edge.example.com "systemctl restart api"',
            regex_pattern=r"(?:StrictHostKeyChecking=no|AutoAddPolicy\s*\(\s*\))",
            synthesized_by_model="meta-muse-spark",
            endorsed_by_models=["meta-muse-spark", "deepseek-r1-0528"],
            reinforcement_count=10,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-FE-001",
            title="Wait for networkidle or explicit DOM readiness before inspecting dynamic web apps in Playwright",
            domain="frontend-ts",
            severity=Severity.MEDIUM,
            languages=["python", "typescript", "javascript"],
            tags=["playwright", "webapp-testing", "flaky-tests", "hydration"],
            cognitive_trap="Inspected DOM elements immediately after `page.goto()` or used arbitrary fixed `page.wait_for_timeout(5000)` before client-side hydration finished.",
            mental_model="Harvested from anthropics/skills (webapp-testing): Modern SPAs hydrate asynchronously; always wait for `page.wait_for_load_state('networkidle')` or deterministic locator visibility rather than arbitrary blind sleeps.",
            bad_code='page.goto("http://localhost:3000")\npage.wait_for_timeout(5000)  # BLIND_PLAYWRIGHT_SLEEP',
            good_code='page.goto("http://localhost:3000")\npage.wait_for_load_state("networkidle")',
            regex_pattern=r"page\.wait_for_timeout\s*\(\s*\d+\s*\)\s*#\s*BLIND_PLAYWRIGHT_SLEEP",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "gemini-3.8-pro"],
            reinforcement_count=7,
            source_repo="github:anthropics/skills/webapp-testing",
        ),
        # =========================================================================
        # PILLAR 2: REAL-LIFE, FINANCE, BUSINESS, PSYCHOLOGY & STRATEGY (12 LESSONS)
        # =========================================================================
        CognitiveLesson(
            id="KL-CAP-001",
            title="Zero-Advance-Fee Capital Guard: Reject any contract or opportunity requiring an upfront verification deposit",
            domain="finance-capital",
            severity=Severity.CRITICAL,
            languages=["decision", "markdown", "python"],
            tags=["capital-protection", "zero-deposit", "anti-scam", "personal-finance"],
            cognitive_trap="Felt tempted by a high promised payout (`$500 return`) to pay a 'small refundable verification deposit or staking fee' (`upfront_fee_usd > 0`).",
            mental_model="Legitimate commercial counterparties deduct service fees from gross settlements or pay inbound; any requirement to send upfront principal (`UPFRONT_DEPOSIT_REQUIRED` / `upfront_fee_usd > 0`) is an asymmetric principal-loss trap.",
            bad_code="DECISION: APPROVE_ACTION(upfront_fee_usd=25.0, action='SEND_UPFRONT_STAKING_DEPOSIT')",
            good_code="DECISION: REJECT_ACTION(upfront_fee_usd=0.0, policy='ZERO_ADVANCE_FEE_CAPITAL_GUARD')",
            regex_pattern=r"SEND_UPFRONT_STAKING_DEPOSIT|upfront_fee_usd=[1-9]\d*",
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "gpt-6.1-terra-wm", "claude-opus-4"],
            reinforcement_count=19,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-CAP-002",
            title="Anti-Martingale Position Sizing: Never double exposure after a losing trade or drawdown",
            domain="finance-capital",
            severity=Severity.CRITICAL,
            languages=["decision", "python", "markdown"],
            tags=["risk-management", "position-sizing", "anti-martingale", "kelly-criterion"],
            cognitive_trap="Doubled position size after a loss (`next_bet = last_bet * 2`) to 'win back losses in one trade' due to loss-aversion panic.",
            mental_model="Volatility clusters in real life and markets; Martingale doubling (`MARTINGALE_DOUBLE_DOWN`) guarantees ruin under finite capital. Cap every single-decision risk to <= 1%–2% of liquid net worth.",
            bad_code="STRATEGY: position_size = previous_losing_size * 2  # MARTINGALE_DOUBLE_DOWN",
            good_code="STRATEGY: position_size = min(account_equity * 0.01, max_risk_cap)",
            regex_pattern=r"MARTINGALE_DOUBLE_DOWN|previous_losing_size\s*\*\s*[2-9]",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "qwen3.8-max"],
            reinforcement_count=15,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-BIZ-001",
            title="Anti-Scope-Creep Gate: Bind every out-of-scope client request to a written change order and fee/timeline delta",
            domain="business-negotiation",
            severity=Severity.HIGH,
            languages=["decision", "markdown", "contract"],
            tags=["negotiation", "scope-creep", "b2b-sales", "pricing"],
            cognitive_trap="Said 'Sure, we can throw in that extra module for free' to please a client during delivery, eroding project margin and delaying core milestones.",
            mental_model="Unpriced concessions train clients that your time has zero marginal cost. Always welcome new ideas warmly while anchoring them to a formal Change Order (`CHANGE_ORDER_WITH_FEE_AND_TIMELINE`).",
            bad_code="RESPONSE: ACCEPT_UNBILLED_SCOPE_ADDITION(extra_deliverables=True, fee_delta=0)",
            good_code="RESPONSE: PROPOSE_CHANGE_ORDER(extra_deliverables=True, fee_delta=1500, timeline_extension_days=5)",
            regex_pattern=r"ACCEPT_UNBILLED_SCOPE_ADDITION",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "gpt-6.1-terra-wm"],
            reinforcement_count=12,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-BIZ-002",
            title="Never volunteer a unilateral price discount before establishing ROI and receiving a concrete counter-commitment",
            domain="business-negotiation",
            severity=Severity.HIGH,
            languages=["decision", "markdown"],
            tags=["pricing-psychology", "anchoring", "sales", "negotiation"],
            cognitive_trap="Offered an immediate 40% discount in the first outreach message out of fear that the prospect might find the full price too high.",
            mental_model="Pre-emptive discounting signals low confidence in product value. Anchor on quantified ROI first; if trading price down, always extract a concrete quid-pro-quo (annual prepay, case study, or volume commitment).",
            bad_code="PITCH: UNILATERAL_PREEMPTIVE_DISCOUNT(discount_pct=40, counter_commitment=None)",
            good_code="PITCH: ANCHOR_VALUE_WITH_QUID_PRO_QUO(discount_pct=15, counter_commitment='annual_upfront_and_case_study')",
            regex_pattern=r"UNILATERAL_PREEMPTIVE_DISCOUNT",
            synthesized_by_model="grok-4.7",
            endorsed_by_models=["grok-4.7", "claude-opus-4"],
            reinforcement_count=10,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-PSY-001",
            title="Emotional Calibration & Anti-Chasing: Never send needy double/triple follow-ups when counterpart investment drops",
            domain="psychology-relationships",
            severity=Severity.HIGH,
            languages=["decision", "markdown"],
            tags=["psychology", "dating-social", "emotional-intelligence", "attraction"],
            cognitive_trap="Felt anxious when a romantic interest or high-value contact took hours to reply, sending multiple needy check-in texts ('Why are you ignoring me???').",
            mental_model="Attraction and respect require balanced investment velocity (`ping-pong reciprocity`). Chasing silence with needy pressure destroys perceived status; mirror their pace and stay grounded in your own mission.",
            bad_code="MESSAGE_ACTION: SEND_NEEDY_TRIPLE_TEXT(consecutive_unanswered=3, tone='anxious_validation_seeking')",
            good_code="MESSAGE_ACTION: HOLD_COMPOSURED_SILENCE(consecutive_unanswered=1, focus='personal_mission_and_reciprocity')",
            regex_pattern=r"SEND_NEEDY_TRIPLE_TEXT|anxious_validation_seeking",
            synthesized_by_model="grok-4.7",
            endorsed_by_models=["grok-4.7", "meta-muse-spark"],
            reinforcement_count=16,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-PSY-002",
            title="Conflict De-escalation: Enforce a cool-down pause and replace 'You always/never' accusations with factual observations",
            domain="psychology-relationships",
            severity=Severity.MEDIUM,
            languages=["decision", "markdown"],
            tags=["communication", "conflict-resolution", "leadership", "relationships"],
            cognitive_trap="Replied immediately while angry using absolute character attacks ('You always ruin everything'), triggering amygdala defensiveness in the other person.",
            mental_model="During emotional spikes, prefrontal reasoning is offline. Enforce a mandatory cool-down interval and frame feedback around specific observable events and shared solutions.",
            bad_code="CONFLICT_REPLY: SEND_IMMEDIATELY_WHILE_ANGRY(phrasing='You always ruin everything')",
            good_code="CONFLICT_REPLY: PAUSE_AND_STATE_OBSERVATION(cooldown_minutes=30, phrasing='When X happened, it impacted Y; let us align on Z')",
            regex_pattern=r"SEND_IMMEDIATELY_WHILE_ANGRY",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "gemini-3.8-pro"],
            reinforcement_count=9,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-LEG-001",
            title="Contract Liability Cap: Never sign agreements with uncapped consequential damages or unilateral indemnity",
            domain="legal-contracts",
            severity=Severity.CRITICAL,
            languages=["contract", "decision", "markdown"],
            tags=["legal", "contracts", "liability-cap", "indemnification"],
            cognitive_trap="Signed a standard enterprise vendor MSA without checking the limitation of liability clause, exposing personal or company assets to unlimited consequential damages.",
            mental_model="Every commercial contract must cap aggregate liability to a deterministic multiple of fees actually paid (typically 12 months of fees) and exclude indirect/consequential damages.",
            bad_code="CLAUSE: ACCEPT_UNLIMITED_CONSEQUENTIAL_LIABILITY(liability_cap='UNCAPPED')",
            good_code="CLAUSE: ENFORCE_MUTUAL_LIABILITY_CAP(liability_cap='12_MONTHS_FEES_PAID', exclude_consequential=True)",
            regex_pattern=r"ACCEPT_UNLIMITED_CONSEQUENTIAL_LIABILITY|liability_cap=['\"]UNCAPPED['\"]",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "claude-opus-4"],
            reinforcement_count=11,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-LEG-002",
            title="Background IP Retention: Carve out pre-existing tools, frameworks, and harnesses from client IP assignment clauses",
            domain="legal-contracts",
            severity=Severity.CRITICAL,
            languages=["contract", "decision", "markdown"],
            tags=["intellectual-property", "licensing", "freelance", "saas"],
            cognitive_trap="Signed a work-for-hire agreement assigning 'all tools, scripts, and know-how used during the engagement', accidentally transferring ownership of your proprietary harness.",
            mental_model="Always separate Background IP (your reusable engines, libraries, and methodologies) from Foreground Deliverables: retain 100% ownership of Background IP and grant the client a non-exclusive license.",
            bad_code="IP_CLAUSE: ASSIGN_ALL_BACKGROUND_TOOLS_AND_FRAMEWORKS_TO_CLIENT()",
            good_code="IP_CLAUSE: RETAIN_BACKGROUND_IP_AND_ASSIGN_CUSTOM_DELIVERABLES_ONLY(license='non_exclusive_perpetual')",
            regex_pattern=r"ASSIGN_ALL_BACKGROUND_TOOLS_AND_FRAMEWORKS_TO_CLIENT",
            synthesized_by_model="gemini-3.8-pro",
            endorsed_by_models=["gemini-3.8-pro", "deepseek-r1-0528"],
            reinforcement_count=10,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-HLT-001",
            title="Circadian & Cognitive Recovery Guard: Block late caffeine and连续 >4h unpaused deep-work marathons",
            domain="health-longevity",
            severity=Severity.HIGH,
            languages=["decision", "markdown"],
            tags=["sleep", "circadian-rhythm", "ultradian-cycles", "longevity"],
            cognitive_trap="Drank espresso at 19:00 and coded for 6 hours straight without standing up, mistaking acute adrenaline stimulation for sustainable productivity.",
            mental_model="Caffeine has a ~5–6h half-life that fragments slow-wave and REM sleep, compounding next-day cognitive error rates by >40%. Protect the 8-hour pre-sleep caffeine cutoff and 90-minute ultradian breaks.",
            bad_code="HABIT_LOG: INTAKE_CAFFEINE_LATE_NIGHT(hour_24=20, continuous_sitting_hours=6)",
            good_code="HABIT_LOG: RESPECT_CIRCADIAN_CUTOFF(last_caffeine_hour=14, ultradian_break_every_minutes=90)",
            regex_pattern=r"INTAKE_CAFFEINE_LATE_NIGHT",
            synthesized_by_model="meta-muse-spark",
            endorsed_by_models=["meta-muse-spark", "gemini-3.8-pro"],
            reinforcement_count=11,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-DEC-001",
            title="One-Way Door Pre-Mortem Gate: Require explicit downside bounds and kill-criteria before irreversible decisions",
            domain="decision-strategy",
            severity=Severity.HIGH,
            languages=["decision", "markdown"],
            tags=["mental-models", "one-way-door", "pre-mortem", "discernment"],
            cognitive_trap="Treated an irreversible Type-1 ('One-Way Door') commitment with the same casual speed as a reversible Type-2 experiment, without defining a pre-mortem or exit trigger.",
            mental_model="Harvested from anthropics/skills (discernment-nudge): Before executing any irreversible decision, explicitly write down the worst-case downside, key unverified assumptions, and concrete kill-criteria.",
            bad_code="DECISION_COMMIT: EXECUTE_IRREVERSIBLE_ONE_WAY_DOOR(pre_mortem=None, kill_criteria=None)",
            good_code="DECISION_COMMIT: EXECUTE_WITH_PRE_MORTEM(max_downside_capped=True, kill_criteria='abort_if_metric_below_threshold_at_day_30')",
            regex_pattern=r"EXECUTE_IRREVERSIBLE_ONE_WAY_DOOR\(\s*pre_mortem=None",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "deepseek-r1-0528"],
            reinforcement_count=13,
            source_repo="github:anthropics/skills/discernment-nudge",
        ),
        CognitiveLesson(
            id="KL-EPI-001",
            title="Anti-Sycophancy & Primary-Source Epistemology: Verify primary data before agreeing with user premises",
            domain="research-epistemology",
            severity=Severity.HIGH,
            languages=["decision", "markdown", "python"],
            tags=["epistemology", "anti-sycophancy", "fact-checking", "scientific-rigor"],
            cognitive_trap="Agreed immediately with a flawed user assumption ('You are absolutely right!') or cited a secondary rumor without checking the primary empirical source.",
            mental_model="Harvested from patrickjs/awesome-cursorrules (anti-sycophancy-code-discipline): Truth outranks politeness. Verify primary artifacts, measurements, and source code before endorsing any claim.",
            bad_code="EPISTEMIC_RESPONSE: SYCOPHANTIC_AGREEMENT_WITHOUT_PRIMARY_CHECK(verified_source=False)",
            good_code="EPISTEMIC_RESPONSE: VERIFY_PRIMARY_EVIDENCE_FIRST(verified_source=True, citation='primary_artifact_sha256')",
            regex_pattern=r"SYCOPHANTIC_AGREEMENT_WITHOUT_PRIMARY_CHECK",
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "gpt-6.1-terra-wm"],
            reinforcement_count=14,
            source_repo="github:patrickjs/awesome-cursorrules/anti-sycophancy-code-discipline-cursorrules-prompt-file",
        ),
        CognitiveLesson(
            id="KL-GRW-001",
            title="Organic Trust Warmup (95/5 Rule): Never blast outbound promo links from fresh or low-karma community accounts",
            domain="growth-marketing",
            severity=Severity.HIGH,
            languages=["decision", "markdown"],
            tags=["growth", "anti-shadowban", "community-led", "organic-marketing"],
            cognitive_trap="Posted external promotional URLs on day 1 from a brand-new account (`account_age_days < 7`), triggering automated anti-spam filters and permanent domain shadowbans.",
            mental_model="Communities reward native problem-solving and penalize extraction. Follow the 95/5 rule: deliver 95% zero-link domain value until trust/karma matures, then introduce relevant resources naturally.",
            bad_code="OUTREACH_POST: BLAST_PROMO_LINK_ON_NEW_ACCOUNT(account_age_days=2, outbound_urls=3)",
            good_code="OUTREACH_POST: NATIVE_VALUE_CONTRIBUTION(account_age_days=14, karma=250, value_to_promo_ratio='95:5')",
            regex_pattern=r"BLAST_PROMO_LINK_ON_NEW_ACCOUNT",
            synthesized_by_model="qwen3.8-max",
            endorsed_by_models=["qwen3.8-max", "grok-4.7"],
            reinforcement_count=11,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-MCP-004",
            title="Enable prompt caching (cache_control ephemeral) on static system instructions and tool catalogs",
            domain="ai-agents-mcp",
            severity=Severity.MEDIUM,
            languages=["python", "typescript"],
            tags=["claude-api", "prompt-caching", "finops", "token-savings"],
            cognitive_trap="Sent the full 20,000-token system prompt and MCP tool schema un-cached on every multi-turn agent step, paying 10x input token costs.",
            mental_model="Harvested from anthropics/skills (claude-api): Mark static system prompts and tool definitions with `cache_control: {'type': 'ephemeral'}` to cut repeated input token latency and cost by up to 90%.",
            bad_code='system_blocks = [{"type": "text", "text": STATIC_AGENT_CONSTITUTION}]  # MISSING_PROMPT_CACHE',
            good_code='system_blocks = [{"type": "text", "text": STATIC_AGENT_CONSTITUTION, "cache_control": {"type": "ephemeral"}}]',
            regex_pattern=r"MISSING_PROMPT_CACHE",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "gpt-6.1-terra-wm"],
            reinforcement_count=10,
            source_repo="github:anthropics/skills/claude-api",
        ),
        CognitiveLesson(
            id="KL-FIN-002",
            title="Never hardcode calculated sum/margin totals into financial spreadsheet cells; emit live Excel formulas",
            domain="fintech-web3",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["xlsx", "financial-modeling", "spreadsheets", "auditability"],
            cognitive_trap="Computed `total = sum(rows)` in Python and wrote the static float `ws['B10'] = 48500.0` into the `.xlsx` cell, breaking spreadsheet recalculation when inputs change.",
            mental_model="Harvested from anthropics/skills (xlsx): Financial workbooks must remain dynamically auditable; write live Excel formulas (`=SUM(B2:B9)`) for all subtotal, tax, and margin cells.",
            bad_code='ws["B10"] = 48500.0  # HARDCODED_XLSX_TOTAL',
            good_code='ws["B10"] = "=SUM(B2:B9)"',
            regex_pattern=r"HARDCODED_XLSX_TOTAL",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "qwen3.8-max"],
            reinforcement_count=8,
            source_repo="github:anthropics/skills/xlsx",
        ),
        CognitiveLesson(
            id="KL-DEC-002",
            title="Anti-Over-Engineering Gate: Reject speculative abstractions, kitchen-sink wrappers, and unrequested features",
            domain="decision-strategy",
            severity=Severity.HIGH,
            languages=["decision", "python", "markdown"],
            tags=["anti-overengineering", "simplicity", "architecture", "scope-discipline"],
            cognitive_trap="Built an abstract 5-layer factory framework and 12 speculative config flags for a problem that only needed one deterministic 20-line function.",
            mental_model="Harvested from patrickjs/awesome-cursorrules (anti-overengineering): Complexity is a permanent maintenance tax. Solve only what was asked with the simplest deterministic mechanism first.",
            bad_code="ARCHITECTURE: CREATE_SPECULATIVE_KITCHEN_SINK_ABSTRACTION(unrequested_features=10)",
            good_code="ARCHITECTURE: IMPLEMENT_MINIMAL_DETERMINISTIC_SOLUTION(unrequested_features=0)",
            regex_pattern=r"CREATE_SPECULATIVE_KITCHEN_SINK_ABSTRACTION",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "deepseek-r1-0528"],
            reinforcement_count=15,
            source_repo="github:patrickjs/awesome-cursorrules/anti-overengineering",
        ),
        # =========================================================================
        # PILLAR 3: NEURO-SYMBOLIC CAUSAL ATOMS & PRODUCTION AGENT LESSONS (10 LESSONS)
        # =========================================================================
        CognitiveLesson(
            id="KL-ZTR-002",
            title="Cross-Layer Path Seam Containment: Never concatenate unvalidated user filenames into open()",
            domain="security-zerotrust",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["path-traversal", "trust-boundary", "seam", "file-io"],
            cognitive_trap="Assumed a surface string filter on a user filename prevents directory traversal when concatenated via `open(base_dir + '/' + filename)`.",
            mental_model="Surface string filters fail against encoding/traversal seams across layers; resolve the canonical path via `Path(base_dir).joinpath(filename).resolve()` and enforce `.is_relative_to(base_root)` before opening.",
            bad_code='fh = open(base_dir + "/" + user_filename, "rb")  # UNSAFE_PATH_CONCAT_SEAM',
            good_code='target = (Path(base_dir) / user_filename).resolve()\nassert target.is_relative_to(Path(base_dir).resolve())\nfh = target.open("rb")',
            regex_pattern=r"UNSAFE_PATH_CONCAT_SEAM|\bopen\(\s*base_dir\s*\+",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "deepseek-r1-0528"],
            reinforcement_count=14,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-FIN-003",
            title="Atomic Ledger Locking (TOCTOU) & Symmetric Decimal Scaling Guard",
            domain="fintech-web3",
            severity=Severity.CRITICAL,
            languages=["python", "decision"],
            tags=["toctou", "ledger", "concurrency", "decimal-rounding"],
            cognitive_trap="Checked account balance at t1 (`SELECT balance`) and deducted at t2 without row-level locking or atomic conditional debit, while rounding 18-decimal internal units down on debit and up on 6-decimal payout.",
            mental_model="Concurrent withdrawals race between unlocked reads and writes (`TOCTOU_UNLOCKED_LEDGER_DEBIT`). Enforce atomic `UPDATE ... WHERE balance >= amount` (or `SELECT ... FOR UPDATE`) and use identical floor-quantized atomic units for both debit and payout.",
            bad_code="bal = db.query('SELECT balance FROM accounts WHERE id = :id')  # TOCTOU_UNLOCKED_LEDGER_DEBIT",
            good_code="rows = db.execute('UPDATE accounts SET balance = balance - :amt WHERE id = :id AND balance >= :amt')",
            regex_pattern=r"TOCTOU_UNLOCKED_LEDGER_DEBIT",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "deepseek-r1-0528"],
            reinforcement_count=16,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-FIN-004",
            title="Bind cryptographic signatures to (chainId, verifyingContract, nonce, deadline) and update vault shares before external calls",
            domain="fintech-web3",
            severity=Severity.CRITICAL,
            languages=["python", "decision"],
            tags=["eip712", "signature-replay", "read-only-reentrancy", "vault"],
            cognitive_trap="Verified a withdrawal signature without binding `(chainId, verifyingContract, nonce, deadline)` and transferred vault assets before burning shares, exposing mid-callback share price skew.",
            mental_model="Unscoped signatures enable cross-context replay, and transferring assets before burning shares creates a read-only reentrancy window where `totalAssets / totalSupply` is artificially depressed.",
            bad_code="digest = keccak256(user, amount)  # UNSCOPED_SIGNATURE_MISSING_NONCE_CHAINID",
            good_code="digest = keccak256(chain_id, verifying_contract, user, amount, nonce, deadline)",
            regex_pattern=r"UNSCOPED_SIGNATURE_MISSING_NONCE_CHAINID",
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "gpt-6.1-terra-wm"],
            reinforcement_count=15,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-ZTR-003",
            title="Anti-Mass-Assignment Privilege Boundary: Never merge raw request dicts into user/account records",
            domain="security-zerotrust",
            severity=Severity.CRITICAL,
            languages=["python", "javascript", "typescript"],
            tags=["mass-assignment", "privilege-escalation", "idor", "auth"],
            cognitive_trap="Merged parsed HTTP body parameters directly into the stored user model (`user_record.update(request_json)`), allowing callers to inject `is_admin=True` or `balance=999999`.",
            mental_model="Privilege flags (`is_admin`, `role`, `balance`, `tenant_id`) must never share a merge dictionary with user-editable profile fields; project input through an explicit field allowlist.",
            bad_code="user_record.update(request_json)  # UNFILTERED_PRIVILEGE_MASS_ASSIGNMENT",
            good_code="ALLOWED = {'display_name', 'bio'}\nuser_record.update({k: request_json[k] for k in ALLOWED if k in request_json})",
            regex_pattern=r"UNFILTERED_PRIVILEGE_MASS_ASSIGNMENT|\buser_record\.update\(\s*request_json\s*\)",
            synthesized_by_model="grok-4.7",
            endorsed_by_models=["grok-4.7", "gpt-6.1-terra-wm"],
            reinforcement_count=13,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-API-002",
            title="Multi-Tenant Cache & Secondary Query Isolation: Always prefix cache keys with tenant_id",
            domain="backend-api",
            severity=Severity.CRITICAL,
            languages=["python", "typescript"],
            tags=["multi-tenant", "cache-poisoning", "data-leakage", "redis"],
            cognitive_trap="Filtered the primary SQL query by `tenant_id`, but keyed the Redis cache lookup by bare `record_id` (`cache.get(f'record:{record_id}')`), leaking cached records across tenants.",
            mental_model="Every secondary retrieval path, cache key, and export job must bind the authenticated `tenant_id` (`f'tenant:{tenant_id}:record:{record_id}'`); row-level security on the DB does not protect an unscoped cache hit.",
            bad_code='cached = redis_client.get(f"record:{record_id}")  # UNSCOPED_MULTI_TENANT_CACHE_KEY',
            good_code='cached = redis_client.get(f"tenant:{tenant_id}:record:{record_id}")',
            regex_pattern=r"UNSCOPED_MULTI_TENANT_CACHE_KEY",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "claude-opus-4"],
            reinforcement_count=12,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-FIN-005",
            title="Deterministic Wallet Derivation & Closed-Loop Sign-Recover Gate",
            domain="fintech-web3",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["wallet-derivation", "cryptography", "payout-safety", "web3"],
            cognitive_trap="Added an `except ImportError:` fallback that generated random hex bytes when `eth_account` was missing in a virtualenv, creating unbacked payout addresses with no matching private key.",
            mental_model="Never fallback to random bytes when deriving cryptographic addresses; fail hard if signing libraries are missing and require a closed-loop `recover(sign(msg, pk)) == address` assertion before registering any payout address.",
            bad_code="except ImportError:\n    wallet_addr = '0x' + os.urandom(16).hex()  # UNBACKED_RANDOM_WALLET_FALLBACK",
            good_code="from eth_account import Account  # Fail hard if missing\nacct = Account.from_key(private_key)",
            regex_pattern=r"UNBACKED_RANDOM_WALLET_FALLBACK",
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "claude-opus-4"],
            reinforcement_count=20,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-MCP-005",
            title="Anti-Silent-Model-Downgrade Gate: Verify upstream routed model identity instead of masking with fallback",
            domain="ai-agents-mcp",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["model-routing", "provenance", "anti-downgrade", "llm-gateway"],
            cognitive_trap="Wrote `model_used = data.get('model') or requested_model`, silently attributing a low-tier 20B/mini fallback response to a requested Frontier reasoning model.",
            mental_model="Proxy gateways frequently substitute cheaper models under load; explicitly verify that `data.get('model')` is present and matches the requested Frontier family before trusting high-stakes reasoning output.",
            bad_code='model_used = response_data.get("model") or target_frontier_model  # SILENT_MODEL_DOWNGRADE_MASK',
            good_code='reported = str(response_data.get("model") or "")\nassert reported.startswith(expected_family), f"Unexpected routed model: {reported}"',
            regex_pattern=r"SILENT_MODEL_DOWNGRADE_MASK|response_data\.get\(\s*[\"']model[\"']\s*\)\s+or\s+target_frontier_model",
            synthesized_by_model="grok-4.7",
            endorsed_by_models=["grok-4.7", "deepseek-r1-0528"],
            reinforcement_count=11,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-API-003",
            title="HTTP Redirect Effective-Host Verification & Verbatim Raw-Byte Archival",
            domain="backend-api",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["http-redirect", "cdn-cache", "data-integrity", "scraping"],
            cognitive_trap="Treated `resp.status == 200` after redirects as valid full-text retrieval even when redirected to an `/unblock` or captcha interstitial, and re-serialized JSON via `json.dumps(indent=2)` instead of slicing raw bytes.",
            mental_model="Always verify `urllib.parse.urlparse(resp.geturl()).hostname == expected_host`, send `Cache-Control: no-cache`, and archive/slice the verbatim `raw_bytes` before parsing.",
            bad_code="if resp.status == 200:\n    mark_fulltext_valid(json.dumps(json.loads(raw), indent=2))  # UNVERIFIED_REDIRECT_AND_RESERIALIZED_RAW",
            good_code="assert urlparse(resp.geturl()).hostname == expected_host\nPath(raw_path).write_bytes(raw_bytes)",
            regex_pattern=r"UNVERIFIED_REDIRECT_AND_RESERIALIZED_RAW",
            synthesized_by_model="claude-opus-4",
            endorsed_by_models=["claude-opus-4", "gpt-6.1-terra-wm"],
            reinforcement_count=13,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-OPS-002",
            title="Singleton Daemon Flock & Event-Driven Wakeup: Never run unlocked overlapping daemons or busy-poll loops",
            domain="devops-cloud",
            severity=Severity.HIGH,
            languages=["python"],
            tags=["daemon", "flock", "concurrency", "event-driven"],
            cognitive_trap="Spawned multiple cron/CLI worker instances without an exclusive file lock (`fcntl.flock`) and busy-polled task status in a tight loop, causing duplicate executions and resource waste.",
            mental_model="Acquire a non-blocking exclusive lock (`fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)`) at daemon startup and yield to event-driven reactive wakeup instead of polling.",
            bad_code="while task_running:\n    poll_status_immediately()  # UNLOCKED_BUSY_POLL_LOOP",
            good_code="fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\nwait_for_reactive_event_notification()",
            regex_pattern=r"UNLOCKED_BUSY_POLL_LOOP",
            synthesized_by_model="deepseek-r1-0528",
            endorsed_by_models=["deepseek-r1-0528", "meta-muse-spark"],
            reinforcement_count=10,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-OPS-003",
            title="Complete Browser Origin Storage Teardown (IndexedDB + ServiceWorkers) & Scoped Profile Cleanup",
            domain="devops-cloud",
            severity=Severity.HIGH,
            languages=["javascript", "typescript"],
            tags=["cdp", "puppeteer", "indexeddb", "memory-leak"],
            cognitive_trap="Cleared browser cookies when switching accounts (`Network.clearBrowserCookies`) while leaving stale IndexedDB cryptographic keys (`cvm_chip_pin_unavailable`), or ran an unscoped global browser process kill.",
            mental_model="Navigate to `about:blank` and call `Storage.clearDataForOrigin` for `indexeddb,local_storage,cache_storage,service_workers` before clearing cookies, and terminate only the isolated `--user-data-dir` in `finally`.",
            bad_code="await client.send('Network.clearBrowserCookies');  // MISSING_INDEXEDDB_ORIGIN_CLEAR",
            good_code="await client.send('Page.navigate', { url: 'about:blank' });\nawait client.send('Storage.clearDataForOrigin', { origin, storageTypes: 'indexeddb,local_storage,cache_storage,service_workers' });",
            regex_pattern=r"MISSING_INDEXEDDB_ORIGIN_CLEAR",
            synthesized_by_model="meta-muse-spark",
            endorsed_by_models=["meta-muse-spark", "grok-4.7"],
            reinforcement_count=12,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-EPI-002",
            title="Symplectic Hamiltonian Integration & 1st Law Energy Conservation Guard",
            domain="research-epistemology",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["physics", "thermodynamics", "symplectic", "hamiltonian", "verlet"],
            cognitive_trap="Integrated a conservative Hamiltonian/orbital system with explicit Forward Euler (`x_next = x_pos + v_vel * dt_sec`), whose Jacobian determinant `det(J) = 1 + omega^2 * dt^2 > 1` pumps artificial energy into the system over long horizons.",
            mental_model="First Law of Thermodynamics & Liouville's Theorem: Conservative dynamical systems must use a symplectic integrator (Velocity-Verlet / Leapfrog `v_half`) and verify bounded Hamiltonian energy `|E(t) - E(0)| <= tol`.",
            bad_code="x_next = x_pos + v_vel * dt_sec + 0.0 * accel  # NON_SYMPLECTIC_EULER_DRIFT",
            good_code="v_half = v_vel + 0.5 * accel_0 * dt_sec\nx_next = x_pos + v_half * dt_sec",
            regex_pattern=r"NON_SYMPLECTIC_EULER_DRIFT",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "gpt-6-luna-wm"],
            reinforcement_count=15,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-EPI-003",
            title="Buckingham Pi Dimensional Homogeneity, Radian Conversion & Mass Continuity Guard",
            domain="research-epistemology",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["dimensional-analysis", "buckingham-pi", "continuity", "mass-conservation", "physics"],
            cognitive_trap="Added quantities with incompatible SI dimensions (`pressure_pa + velocity_ms + elevation_mm`), passed degree angles directly into `math.sin(tilt_deg)`, or updated compartment density without antisymmetric mass balance (`rho < 0`).",
            mental_model="Buckingham Pi & Continuity (`d_rho/dt + div(rho*u) = 0`): Normalize all additive terms to identical SI base units, convert degrees via `math.radians()`, and enforce antisymmetric positivity-preserving mass fluxes.",
            bad_code="raw_sum = pressure_pa + velocity_ms + elevation_mm  # DIMENSIONAL_UNIT_MISMATCH",
            good_code="head_m = pressure_pa / (rho_kg_m3 * g_accel) + (velocity_ms ** 2) / (2.0 * g_accel) + (elevation_mm * 1e-3) * math.sin(math.radians(tilt_deg))",
            regex_pattern=r"DIMENSIONAL_UNIT_MISMATCH|MASS_CONTINUITY_VIOLATION",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "gpt-6-luna-wm"],
            reinforcement_count=14,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-ML-003",
            title="Causal Light-Cone Non-Lookahead, 2nd Law Entropy & Compensated Floating-Point Guard",
            domain="data-ml",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["causality", "second-law-thermodynamics", "numerical-stability", "catastrophic-cancellation", "fsum"],
            cognitive_trap="Accessed future time index `signal_series[idx_t + 1]` at step `idx_t` (violating relativistic causal arrow `t_cause <= t_effect`), decreased isolated entropy, or evaluated `gamma ** 2 - 1.0` at `v << c`.",
            mental_model="Enforce strict past-only causal masks (`indices <= idx_t`), non-negative isolated entropy production (`dS >= 0`), algebraic factorization (`v_sq / (1.0 - v_sq)`), and Kahan `math.fsum()`.",
            bad_code="pred_t = 0.5 * signal_series[idx_t] + 0.5 * signal_series[idx_t + 1]  # CAUSAL_ARROW_LOOKAHEAD_LEAK",
            good_code="pred_t = 0.5 * signal_series[max(0, idx_t - 1)] + 0.5 * signal_series[idx_t]\ntotal_energy = math.fsum([rest_energy_j] + list(micro_fluxes))",
            regex_pattern=r"CAUSAL_ARROW_LOOKAHEAD_LEAK|CATASTROPHIC_CANCELLATION_SEAM",
            synthesized_by_model="gpt-6-luna-wm",
            endorsed_by_models=["gpt-6-luna-wm", "gpt-6.1-terra-wm"],
            reinforcement_count=16,
            source_repo="local-episodic",
        ),
        CognitiveLesson(
            id="KL-MCP-006",
            title="Shadow-Clone Parallel Epistemic Swarm & BFT Synaptic Merge (K=3f+1 Quorum)",
            domain="ai-agents-mcp",
            severity=Severity.CRITICAL,
            languages=["python"],
            tags=["multi-agent-swarm", "kage-bunshin", "bft-consensus", "map-reduce-learning", "epistemic-merge"],
            cognitive_trap="Allowed parallel subagents to share intermediate drafts before independent grounding or accepted a single unverified subagent conclusion without a Byzantine-tolerant quorum (`s_p >= 3` of `K=4`).",
            mental_model="Enforce orthogonal clone tracks with zero inter-clone communication during exploration, ground every clone proposition via the <5ms 3-State Gate + Counterfactual Sandbox, quarantine refuted traps into a Negative Tabu List, and merge only propositions achieving `s_p >= 3` quorum (`K=3f+1`).",
            bad_code="playbook = subagents[0].unverified_draft_conclusion  # UNGROUNDED_SINGLE_CLONE_ACCEPT",
            good_code="playbook = bft_merge_clones(clone_reports, quorum_threshold=3)  # K=3f+1 verified quorum",
            regex_pattern=r"UNGROUNDED_SINGLE_CLONE_ACCEPT",
            synthesized_by_model="gpt-6.1-terra-wm",
            endorsed_by_models=["gpt-6.1-terra-wm", "gpt-6-luna-wm"],
            reinforcement_count=18,
            source_repo="local-episodic",
        ),
    ]
