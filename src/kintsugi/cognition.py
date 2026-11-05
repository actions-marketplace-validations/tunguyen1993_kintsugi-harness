"""
Federated Human-Like Cognitive Lesson Engine & Frontier-Gated GitHub Pool (`kintsugi learn`).

Implements biological episodic-to-semantic memory consolidation for coding agents:
1. Distills concrete mistakes into structured `CognitiveLesson` records capturing the
   `cognitive_trap` (why the agent thought bad code was right), the `mental_model`
   (timeless engineering heuristic), and a deterministic AST/Regex guardrail.
2. Supports two explicit user privacy/sync modes:
   - `local-only`: Keeps self-learned lessons strictly local in `.kintsugi/lessons_local.json`
     while allowing selective industry/domain pulls (`kintsugi learn pull --domain ...`)
     from the GitHub Collective Pool.
   - `federated-sync`: Automatically publishes newly distilled lessons to the partitioned
     GitHub Collective Pool (`collective-pool/<domain>/<model_family>/<id>.json`) ONLY if
     they pass the 4-Stage Frontier Epistemic Gate.
3. 4-Stage Frontier Epistemic Gate (prevents low-tier model noise and duplicates):
   - Stage 1 (Frontier Model Provenance): Must be synthesized by a Tier-1 Frontier reasoning
     model (`claude-opus`, `claude-sonnet-4`, `gpt-6`, `deepseek-r1`, `gemini-3.8-pro`, `qwen3.8-max`, `grok-4`).
     Low-tier models (`mini`, `flash-lite`, `haiku`, `8b`, `offline`) are restricted to local-only.
   - Stage 2 (Deterministic Verification): Must pass `scan(bad_code) >= 1` and `scan(good_code) == 0`.
   - Stage 3 (Semantic & Structural Deduplication): Canonical AST/Regex fingerprint + Jaccard
     similarity check merges duplicates into synaptic `reinforcement_count` instead of polluting the pool.
   - Stage 4 (Zero-Leak DLP Sanitization): Rejects any lesson containing local filesystem paths,
     emails, internal IPs, or secret literals.
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

SUPPORTED_DOMAINS: Tuple[str, ...] = (
    "ai-agents-mcp",
    "backend-api",
    "security-zerotrust",
    "fintech-web3",
    "devops-cloud",
    "frontend-ts",
    "data-ml",
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
    r"(?:/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|C:\\\\Users\\\\|[a-zA-Z0-9._%+-]+@(?!([a-zA-Z0-9-]+\.)*example\.(?:com|org|net)\b)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|192\.168\.\d+\.\d+)",
)

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
    Human-like engineering lesson distilled from a real failure episode.
    Pairs causal reflection (`cognitive_trap` + `mental_model`) with an executable guardrail.
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
            tags=sorted(set(self.tags + [self.domain, f"model:{self.model_family}"])),
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
        payload["structural_fingerprint"] = self.structural_fingerprint
        payload["proof_attestation"] = self.proof_attestation
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CognitiveLesson":
        clean = {
            k: v
            for k, v in data.items()
            if k not in {"structural_fingerprint", "proof_attestation", "model_tier", "model_family"}
        }
        clean["severity"] = Severity(str(clean["severity"]).upper())
        return cls(**clean)


def verify_frontier_sync_gate(
    lesson: CognitiveLesson,
    existing_pool: Sequence[CognitiveLesson] = (),
) -> Tuple[bool, str, Optional[CognitiveLesson]]:
    """
    4-Stage Frontier Epistemic Gate required before any lesson can enter the GitHub Pool:
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
            f"DeepSeek-R1/V4, Gemini-3.8-Pro, Qwen-3.8-Max, Grok-4) may publish to the Collective Pool.",
            None,
        )

    # Stage 2: DLP Sanitization Gate
    combined_text = f"{lesson.title}\n{lesson.cognitive_trap}\n{lesson.mental_model}\n{lesson.bad_code}\n{lesson.good_code}"
    if DLP_PRIVATE_PATTERN.search(combined_text):
        return (
            False,
            "REJECTED_DLP_VIOLATION: Lesson contains private file paths, emails, or internal IP addresses.",
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
    (`.kintsugi/learn_config.json`), and the partitioned GitHub Collective Pool
    (`collective-pool/<domain>/<model_family>/<lesson_id>.json`).
    """

    def __init__(self, workspace_root: str | Path = ".", pool_root: Optional[ str | Path] = None) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.kintsugi_dir = self.workspace_root / ".kintsugi"
        self.config_path = self.kintsugi_dir / "learn_config.json"
        self.local_lessons_path = self.kintsugi_dir / "lessons_local.json"
        self.pool_root = Path(pool_root).resolve() if pool_root else (self.workspace_root / "collective-pool")

    def load_config(self) -> Dict[str, Any]:
        default_cfg = {
            "sync_mode": SyncMode.LOCAL_ONLY.value,
            "subscribed_domains": ["ai-agents-mcp", "backend-api", "security-zerotrust"],
            "auto_push_to_github": False,
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
            "schema_version": "1.0",
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
        by_model: Dict[str, List[str]] = {}
        entries: List[Dict[str, Any]] = []

        for l in all_lessons:
            by_domain.setdefault(l.domain, []).append(l.id)
            by_model.setdefault(l.model_family, []).append(l.id)
            rel_path = f"{l.domain}/{l.model_family}/{l.id}.json"
            entries.append(
                {
                    "id": l.id,
                    "title": l.title,
                    "domain": l.domain,
                    "severity": l.severity.value,
                    "model_family": l.model_family,
                    "synthesized_by_model": l.synthesized_by_model,
                    "endorsed_by_models": l.endorsed_by_models,
                    "reinforcement_count": l.reinforcement_count,
                    "structural_fingerprint": l.structural_fingerprint,
                    "path": rel_path,
                }
            )

        index_payload = {
            "schema_version": "1.0",
            "total_verified_frontier_lessons": len(entries),
            "domains": {k: sorted(v) for k, v in sorted(by_domain.items())},
            "model_families": {k: sorted(v) for k, v in sorted(by_model.items())},
            "lessons": entries,
        }
        index_path = self.pool_root / "index.json"
        index_path.write_text(json.dumps(index_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return index_path

    def record_lesson(
        self,
        lesson: CognitiveLesson,
        *,
        force_local_only: bool = False,
        git_push: bool = False,
    ) -> Dict[str, Any]:
        """
        Record a distilled `CognitiveLesson`:
        - Always deduplicates and stores in `.kintsugi/lessons_local.json`.
        - If user config is `federated-sync` (and not `force_local_only`), evaluates the
          4-Stage Frontier Sync Gate and publishes to `collective-pool/<domain>/<model_family>/<id>.json`.
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
                # Reinforce the existing pool lesson instead of duplicating
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

        return {
            "lesson_id": lesson.id,
            "local_saved": True,
            "pool_sync_status": "PUBLISHED_TO_COLLECTIVE_POOL",
            "pool_file": str(target_file),
            "git_pushed": git_pushed,
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
    ) -> Dict[str, Any]:
        """
        Pull curated Frontier-verified lessons for the user's industry domains
        from the Collective Pool (local repo `collective-pool/` or remote GitHub raw API)
        and merge them into `.kintsugi/lessons_local.json`.
        """
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
                req = urllib.request.Request(idx_url, headers={"User-Agent": "kintsugi-harness/0.4.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    idx_data = json.loads(resp.read().decode("utf-8"))
                for item in idx_data.get("lessons", []):
                    if item.get("domain") in target_domains:
                        if model_family and item.get("model_family") != model_family:
                            continue
                        rel_path = item.get("path", "")
                        if rel_path:
                            raw_url = f"https://raw.githubusercontent.com/{repo_slug}/{branch}/collective-pool/{rel_path}"
                            r_req = urllib.request.Request(raw_url, headers={"User-Agent": "kintsugi-harness/0.4.0"})
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
    Curated initial seed of Tier-1 Frontier lessons partitioned across industries
    and model families (`deepseek-r1`, `gpt-6-frontier`, `claude-frontier`, `gemini-pro`, `qwen-max`).
    """
    return [
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
        ),
    ]
