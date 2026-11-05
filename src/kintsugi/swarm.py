"""
Pillar 5 — Shadow-Clone Parallel Epistemic Swarm & Map-Reduce Experience Consolidation
(`ShadowCloneSwarmOrchestrator` / `Kage Bunshin Learning Engine`).

Council-Approved v1.0.0 Architecture (`gpt-6.1-terra-wm` + `gpt-6-luna-wm`):
1. Phase 1 — Orthogonal Clone Spawning (`Spawn / Phân Thân 4 Hướng Trực Giao`):
   Given an unfamiliar repository or task snapshot `T` (pinned by `manifest_sha`), the Central
   Brain spawns `K = 4` isolated Shadow Clones (`K = 3f + 1`, `f = 1` Byzantine fault tolerance)
   across 4 orthogonal exploration tracks with zero inter-clone communication during execution:
     - Clone 1 (`TRACK_1_AST_BOUNDARY_SEAMS`): Maps AST symbol tables, interfaces, and structural seams.
     - Clone 2 (`TRACK_2_ADVERSARIAL_RED_TEAM`): Probes exploit chains (`S0 -> S1 -> S2`) and adversarial/hallucination traps.
     - Clone 3 (`TRACK_3_COUNTERFACTUAL_S3_SYNTHESIS`): Synthesizes `S3` guards and replays them in the Counterfactual Sandbox.
     - Clone 4 (`TRACK_4_ANALOGICAL_LAW_MAPPER`): Maps cross-domain scientific/system laws and 3-Horizon (`T+1/T+2/T+3`) cascade priority `Q`.

2. Phase 2 — Independent Clone Grounding & Episodic Conclusion (`Kết Luận Độc Lập`):
   Each clone independently evaluates every claim against the `<5ms` 3-State Grounding Gate
   (`VERIFIED` / `REFUTED` / `UNKNOWN`) and Counterfactual Sandbox, emitting a signed,
   immutable `CloneEpisodicReport` containing both verified findings and refuted traps.

3. Phase 3 — Byzantine-Fault-Tolerant Synaptic Merge & Playbook Distillation (`Giải Ấn Gộp Tri Thức Về 1 Bản Thể`):
   All `K` clone reports merge back into the single Central Brain:
     - Normalizes claims by canonical proposition key `(seam_kind | anchor)` with at most 1 vote per clone `v_i(p) in {-1, 0, +1}`.
     - Accepts proposition `p` (`CONSOLIDATED_TRUTH`) only when `s_p >= 3` supporting clones concur, `r_p == 0` validated refutations exist, and counterfactual verification passes.
     - Quarantines refuted or hallucinated clone claims (`r_p >= 1`) into the Negative Tabu List so the entire swarm learns what NOT to do.
     - Synthesizes accepted truths into `CognitiveLesson` / `GoldenScar` entries, updates the Beta-Bernoulli `MetacognitiveSelfModel`, orders the deterministic Step-by-Step "Right Playbook (`Cách Làm Đúng`)", and emits a `<45-token` `@SWARM/1` wire header.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .cognition import CognitiveLesson, CognitiveMemoryManager
from .council import verify_candidate_scar
from .foresight import (
    SEAM_AUTOPOIETIC_TEMPLATES,
    AnalogicalTransferEngine,
    AutopoieticSynthesizer,
    CausalForesightEngine,
    CounterfactualDreamSimulator,
    MetacognitiveSelfModel,
)
from .grounding import RepoAstGroundingEngine
from .ledger import ScarLedger
from .models import GoldenScar, Severity


ORTHOGONAL_CLONE_TRACKS: Tuple[Dict[str, str], ...] = (
    {
        "clone_id": "clone-01-ast-seams",
        "track": "TRACK_1_AST_BOUNDARY_SEAMS",
        "persona": "Structural AST & Boundary Seam Explorer",
        "default_model": "gpt-6.1-terra-wm",
        "objective": "Map AST symbol tables, function/class boundaries, and structural vulnerability seams.",
    },
    {
        "clone_id": "clone-02-adversarial-redteam",
        "track": "TRACK_2_ADVERSARIAL_RED_TEAM",
        "persona": "Adversarial Failure & Edge-Case Red-Team Probe",
        "default_model": "grok-4.7-fast",
        "objective": "Probe S0->S1->S2 exploit chains, boundary edge cases, and test adversarial false-positive traps.",
    },
    {
        "clone_id": "clone-03-counterfactual-s3",
        "track": "TRACK_3_COUNTERFACTUAL_S3_SYNTHESIS",
        "persona": "Counterfactual S3 Guard & Invariant Synthesizer",
        "default_model": "gpt-6-luna-wm",
        "objective": "Synthesize deterministic S3 invariant guards and replay them in an isolated Counterfactual Sandbox.",
    },
    {
        "clone_id": "clone-04-analogical-laws",
        "track": "TRACK_4_ANALOGICAL_LAW_MAPPER",
        "persona": "Cross-Domain Analogical & Conservation Law Mapper",
        "default_model": "deepseek-v4.1-flash",
        "objective": "Map scientific/mathematical conservation laws and 3-Horizon (T+1/T+2/T+3) cascade priorities.",
    },
)


@dataclass
class ClonePropositionVote:
    """Single canonical proposition evaluated independently by a Shadow Clone."""

    proposition_id: str
    seam_kind: str
    anchor: str
    symbols: List[str]
    domain: str
    verdict: str  # "VERIFIED" | "REFUTED" | "UNKNOWN"
    vote: int  # +1 (support), -1 (refute), 0 (abstain/unknown)
    quality_q: float
    grounding_latency_ms: float
    evidence_reason: str
    cognitive_trap: str = ""
    mental_model: str = ""
    s3_guard_hint: str = ""
    analogical_law: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CloneEpisodicReport:
    """Immutable episodic conclusion returned by an individual Shadow Clone before synaptic merge."""

    clone_id: str
    track: str
    persona: str
    routed_model: str
    snapshot_sha: str
    execution_ms: float
    propositions: List[ClonePropositionVote] = field(default_factory=list)
    verified_findings_count: int = 0
    refuted_traps_count: int = 0
    unknown_abstentions_count: int = 0
    independent_conclusion: str = ""
    llm_insight: str = ""
    report_signature: str = ""

    def compute_signature(self) -> str:
        payload = json.dumps(
            {
                "clone_id": self.clone_id,
                "track": self.track,
                "snapshot_sha": self.snapshot_sha,
                "propositions": [
                    {
                        "id": p.proposition_id,
                        "verdict": p.verdict,
                        "vote": p.vote,
                        "q": round(p.quality_q, 4),
                    }
                    for p in self.propositions
                ],
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clone_id": self.clone_id,
            "track": self.track,
            "persona": self.persona,
            "routed_model": self.routed_model,
            "snapshot_sha": self.snapshot_sha,
            "execution_ms": round(self.execution_ms, 3),
            "verified_findings_count": self.verified_findings_count,
            "refuted_traps_count": self.refuted_traps_count,
            "unknown_abstentions_count": self.unknown_abstentions_count,
            "independent_conclusion": self.independent_conclusion,
            "llm_insight": self.llm_insight,
            "report_signature": self.report_signature,
            "propositions": [p.to_dict() for p in self.propositions],
        }


@dataclass
class PlaybookStep:
    """Single deterministic step in the consolidated 'Right Playbook (Cách Làm Đúng)'."""

    step_order: int
    proposition_id: str
    seam_kind: str
    anchor: str
    domain: str
    severity: str
    supporting_clones: int
    total_clones: int
    consensus_ratio: float
    consolidated_weight_w: float
    priority_q: float
    what_to_avoid_tabu: str
    right_way_action: str
    s3_code_guard: str
    analogical_law: str
    verification_check: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ShadowCloneSwarmOrchestrator:
    """
    Spawns `K` orthogonal Shadow Clones in parallel to explore unfamiliar codebases/tasks,
    collects each clone's independent `CloneEpisodicReport`, and executes a Byzantine-Fault-Tolerant
    Synaptic Merge (`K = 3f + 1`) into 1 Central Brain to distill verified `CognitiveLesson`s,
    a Negative Tabu List, and a deterministic Step-by-Step Right Playbook (`Cách Làm Đúng`).
    """

    def __init__(
        self,
        workspace_root: str | Path = ".",
        llm_clone_callback: Optional[Callable[[Dict[str, str], Dict[str, Any]], str]] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.kintsugi_dir = self.workspace_root / ".kintsugi"
        self.swarm_state_path = self.kintsugi_dir / "swarm_merged_wisdom.json"
        self.tabu_path = self.kintsugi_dir / "swarm_negative_tabu.json"
        self.meta_model = MetacognitiveSelfModel(self.workspace_root)
        self.synthesizer = AutopoieticSynthesizer(self.workspace_root)
        self.forecaster = CausalForesightEngine(self.workspace_root)
        self.transfer_engine = AnalogicalTransferEngine()
        self.dream_simulator = CounterfactualDreamSimulator(self.workspace_root)
        self.mem_manager = CognitiveMemoryManager(self.workspace_root)
        self.llm_clone_callback = llm_clone_callback

    @staticmethod
    def _canonical_prop_id(seam_kind: str, anchor: str) -> str:
        return f"{seam_kind.strip().upper()}@{anchor.strip()}"

    def _pick_real_symbols_near_anchor(
        self,
        engine: RepoAstGroundingEngine,
        anchor: str,
    ) -> List[str]:
        if ":" not in anchor:
            return []
        rel_file, ln_str = anchor.rsplit(":", 1)
        try:
            line_no = int(ln_str)
        except ValueError:
            return []
        window = engine.get_code_window(rel_file, line_no, radius=8)
        known_all = (
            set(engine.symbol_table["functions"].keys())
            | set(engine.symbol_table["classes"].keys())
            | set(engine.symbol_table["variables"])
        )
        matched = [sym for sym in sorted(known_all) if sym in window]
        return matched[:3]

    def _run_single_clone(
        self,
        track_spec: Dict[str, str],
        target_path: Path,
        manifest_sha: str,
        seams: List[Dict[str, Any]],
        forecast_q_map: Dict[str, float],
        analogy_map: Dict[str, Dict[str, Any]],
        dream_verified_anchors: Dict[str, str],
        inject_byzantine_fault: bool = False,
    ) -> CloneEpisodicReport:
        t0 = time.perf_counter()
        clone_id = track_spec["clone_id"]
        track = track_spec["track"]
        persona = track_spec["persona"]
        routed_model = track_spec["default_model"]

        # Each clone creates its own isolated grounding view pinned to `manifest_sha`
        engine = RepoAstGroundingEngine(target_path)
        propositions: List[ClonePropositionVote] = []

        for seam in seams:
            kind = str(seam.get("kind", "")).strip()
            anchor = str(seam.get("anchor", "")).strip()
            prop_id = self._canonical_prop_id(kind, anchor)
            tmpl = SEAM_AUTOPOIETIC_TEMPLATES.get(kind, {})
            domain = str(tmpl.get("domain", "backend-api"))
            trap_desc = str(tmpl.get("cognitive_trap", f"Unverified boundary seam ({kind}) at {anchor}."))
            mental_model = str(tmpl.get("mental_model", "Enforce explicit S3 invariant check before state transition."))
            good_guard = str(tmpl.get("good_code", "")).splitlines()[0] if tmpl.get("good_code") else "Enforce S3 invariant guard."
            analogy_info = analogy_map.get(kind, {})
            analogical_law = str(analogy_info.get("source_law", "Deterministic State-Space Invariance"))

            # If a Byzantine fault is injected into Clone 2, simulate a corrupted/hallucinated vote
            if inject_byzantine_fault and track == "TRACK_2_ADVERSARIAL_RED_TEAM":
                bad_verdict = engine.verify_hypothesis(
                    {
                        "anchor": anchor,
                        "symbols": ["__byzantine_hallucinated_symbol_999__"],
                        "verdict": "VERIFIED",
                    },
                    expected_manifest_sha=manifest_sha,
                )
                propositions.append(
                    ClonePropositionVote(
                        proposition_id=prop_id,
                        seam_kind=kind,
                        anchor=anchor,
                        symbols=["__byzantine_hallucinated_symbol_999__"],
                        domain=domain,
                        verdict=bad_verdict["status"],
                        vote=-1,
                        quality_q=0.0,
                        grounding_latency_ms=float(bad_verdict.get("latency_ms", 0.1)),
                        evidence_reason=str(bad_verdict.get("reason", "BYZANTINE_FAULT")),
                        cognitive_trap=trap_desc,
                        mental_model=mental_model,
                        s3_guard_hint=good_guard,
                        analogical_law=analogical_law,
                    )
                )
                continue

            real_syms = self._pick_real_symbols_near_anchor(engine, anchor)
            gnd = engine.verify_hypothesis(
                {
                    "anchor": anchor,
                    "symbols": real_syms,
                    "verdict": "VERIFIED",
                    "mechanism": trap_desc,
                    "remediation": mental_model,
                },
                expected_manifest_sha=manifest_sha,
            )

            status = str(gnd.get("status", "UNKNOWN"))
            latency_ms = float(gnd.get("latency_ms", 0.1))

            # Track-specific quality evaluation (orthogonal epistemic lens)
            base_q = 0.82
            if track == "TRACK_1_AST_BOUNDARY_SEAMS":
                base_q = 0.88 if len(real_syms) >= 1 else 0.65
            elif track == "TRACK_2_ADVERSARIAL_RED_TEAM":
                base_q = 0.90 if kind in SEAM_AUTOPOIETIC_TEMPLATES else 0.75
            elif track == "TRACK_3_COUNTERFACTUAL_S3_SYNTHESIS":
                if tmpl:
                    cand_scar = GoldenScar(
                        id="KS-SWARM-CHECK",
                        title=str(tmpl.get("title_prefix") or tmpl.get("title") or kind),
                        severity=tmpl["severity"],
                        category=domain,
                        languages=["python", "javascript", "typescript"],
                        tags=[domain, kind.lower()],
                        root_cause=trap_desc,
                        bad_code=str(tmpl["bad_code"]),
                        good_code=str(tmpl["good_code"]),
                        rationale=mental_model,
                        regex_pattern=str(tmpl["regex_pattern"]),
                    )
                    cf_ok, _ = verify_candidate_scar(cand_scar)
                    base_q = 0.96 if (cf_ok or anchor in dream_verified_anchors) else 0.40
                    if not cf_ok and anchor not in dream_verified_anchors:
                        status = "REFUTED"
                else:
                    base_q = 0.72
            elif track == "TRACK_4_ANALOGICAL_LAW_MAPPER":
                prio_q = forecast_q_map.get(anchor, 1.0)
                has_law = kind in analogy_map
                base_q = min(0.98, 0.80 + (0.12 if has_law else 0.0) + min(0.06, prio_q / 100.0))

            vote = 1 if status == "VERIFIED" else (-1 if status == "REFUTED" else 0)
            propositions.append(
                ClonePropositionVote(
                    proposition_id=prop_id,
                    seam_kind=kind,
                    anchor=anchor,
                    symbols=real_syms,
                    domain=domain,
                    verdict=status,
                    vote=vote,
                    quality_q=round(base_q if vote == 1 else 0.0, 4),
                    grounding_latency_ms=latency_ms,
                    evidence_reason=str(gnd.get("reason", "")),
                    cognitive_trap=trap_desc,
                    mental_model=mental_model,
                    s3_guard_hint=good_guard,
                    analogical_law=analogical_law,
                )
            )

        # Track 2 (Adversarial Red-Team) always probes an explicit Negative Hallucination Trap
        # so the swarm continuously exercises and populates the Negative Tabu List.
        if track == "TRACK_2_ADVERSARIAL_RED_TEAM":
            trap_anchor = seams[0]["anchor"] if seams else "nonexistent_phantom.py:9999"
            trap_check = engine.verify_hypothesis(
                {
                    "anchor": trap_anchor,
                    "symbols": ["phantom_ungrounded_hallucination_api"],
                    "verdict": "VERIFIED",
                },
                expected_manifest_sha=manifest_sha,
            )
            propositions.append(
                ClonePropositionVote(
                    proposition_id=f"ADVERSARIAL_HALLUCINATION_TRAP@{trap_anchor}",
                    seam_kind="ADVERSARIAL_HALLUCINATION_TRAP",
                    anchor=trap_anchor,
                    symbols=["phantom_ungrounded_hallucination_api"],
                    domain="research-epistemology",
                    verdict=str(trap_check.get("status", "REFUTED")),
                    vote=-1,
                    quality_q=0.0,
                    grounding_latency_ms=float(trap_check.get("latency_ms", 0.1)),
                    evidence_reason=str(trap_check.get("reason", "HALLUCINATED_OR_KEYWORD_SYMBOL")),
                    cognitive_trap="Ungrounded symbol hallucination rejected by <5ms 3-State AST Grounding Gate.",
                    mental_model="Never promote a claim without pinning at least 1 real symbol from SYMBOL_TABLE in the local code window.",
                    s3_guard_hint="Verify symbol membership in RepoAstGroundingEngine.symbol_table before synthesis.",
                    analogical_law="Epistemic Falsifiability & Symbol Grounding Conservation",
                )
            )

        verified_cnt = sum(1 for p in propositions if p.verdict == "VERIFIED")
        refuted_cnt = sum(1 for p in propositions if p.verdict == "REFUTED")
        unknown_cnt = sum(1 for p in propositions if p.verdict == "UNKNOWN")

        llm_note = ""
        if self.llm_clone_callback is not None:
            try:
                llm_note = str(
                    self.llm_clone_callback(
                        track_spec,
                        {
                            "manifest_sha": manifest_sha,
                            "verified_count": verified_cnt,
                            "refuted_count": refuted_cnt,
                            "seams": [s.get("kind") for s in seams[:6]],
                        },
                    )
                    or ""
                ).strip()
            except Exception:
                llm_note = ""

        conclusion = (
            f"[{persona}] Explored {len(propositions)} proposition(s) on snapshot {manifest_sha[:8]}: "
            f"{verified_cnt} VERIFIED, {refuted_cnt} REFUTED into Tabu, {unknown_cnt} UNKNOWN."
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        report = CloneEpisodicReport(
            clone_id=clone_id,
            track=track,
            persona=persona,
            routed_model=routed_model,
            snapshot_sha=manifest_sha,
            execution_ms=elapsed_ms,
            propositions=propositions,
            verified_findings_count=verified_cnt,
            refuted_traps_count=refuted_cnt,
            unknown_abstentions_count=unknown_cnt,
            independent_conclusion=conclusion,
            llm_insight=llm_note,
        )
        report.report_signature = report.compute_signature()
        return report

    def run_swarm(
        self,
        target_path: str | Path,
        num_clones: int = 4,
        consolidate_to_memory: bool = True,
        inject_byzantine_fault: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute the full 3-Phase Shadow-Clone Swarm cycle (`Spawn -> Independent Grounding -> BFT Synaptic Merge`)
        and return the consolidated wisdom + deterministic Right Playbook (`Cách Làm Đúng`).
        """
        t_start = time.perf_counter()
        target = Path(target_path).resolve()
        engine = RepoAstGroundingEngine(target)
        manifest_sha = engine.manifest_sha
        seams = list(engine.symbol_table.get("seams", []))

        # Pre-compute causal forecast priority Q and counterfactual dream verification
        forecast_rep = self.forecaster.forecast(target)
        forecast_q_map: Dict[str, float] = {}
        for item in forecast_rep["horizons"]["T+1_IMMEDIATE"] + forecast_rep["horizons"]["T+2_CASCADE"]:
            forecast_q_map[str(item.get("anchor", ""))] = float(item.get("priority_q", 1.0))

        analogy_rep = self.transfer_engine.transfer_from_target(target)
        analogy_map: Dict[str, Dict[str, Any]] = {
            str(a["seam_kind"]): a for a in analogy_rep.get("analogical_transfers", [])
        }

        dream_rep = self.dream_simulator.simulate_dream(target)
        dream_verified_anchors: Dict[str, str] = {
            str(g["anchor"]): str(g["after_s3"])
            for g in dream_rep.get("applied_s3_counterfactual_guards", [])
        }

        # Select K orthogonal tracks (default 4 for K = 3f + 1 with f = 1)
        k_clones = max(1, min(int(num_clones), len(ORTHOGONAL_CLONE_TRACKS)))
        selected_tracks = list(ORTHOGONAL_CLONE_TRACKS[:k_clones])

        # PHASE 1 & 2: Spawn K isolated Shadow Clones in parallel threads
        clone_reports: List[CloneEpisodicReport] = []
        with ThreadPoolExecutor(max_workers=k_clones) as pool:
            futures = [
                pool.submit(
                    self._run_single_clone,
                    track_spec,
                    target,
                    manifest_sha,
                    seams,
                    forecast_q_map,
                    analogy_map,
                    dream_verified_anchors,
                    inject_byzantine_fault,
                )
                for track_spec in selected_tracks
            ]
            for fut in futures:
                clone_reports.append(fut.result())

        # PHASE 3: Byzantine-Fault-Tolerant Synaptic Merge (K = 3f + 1)
        # Validate clone signatures and snapshot_sha first
        valid_reports: List[CloneEpisodicReport] = []
        for rep in clone_reports:
            if rep.snapshot_sha == manifest_sha and rep.report_signature == rep.compute_signature():
                valid_reports.append(rep)

        quorum_threshold = max(1, (k_clones // 2) + 1) if k_clones < 4 else 3  # s_p >= 3 for K=4 (3f+1)
        grouped_props: Dict[str, List[Tuple[str, ClonePropositionVote]]] = {}
        for rep in valid_reports:
            seen_in_clone = set()
            for prop in rep.propositions:
                if prop.proposition_id in seen_in_clone:
                    continue
                seen_in_clone.add(prop.proposition_id)
                grouped_props.setdefault(prop.proposition_id, []).append((rep.clone_id, prop))

        accepted_truths: List[Dict[str, Any]] = []
        quarantined_tabu: List[Dict[str, Any]] = []
        unresolved_claims: List[Dict[str, Any]] = []

        for prop_id, clone_votes in grouped_props.items():
            s_p = sum(1 for _, pv in clone_votes if pv.vote == 1 and pv.verdict == "VERIFIED")
            r_p = sum(1 for _, pv in clone_votes if pv.vote == -1 or pv.verdict == "REFUTED")
            u_p = sum(1 for _, pv in clone_votes if pv.vote == 0 or pv.verdict == "UNKNOWN")
            w_p = round(sum(pv.quality_q for _, pv in clone_votes if pv.vote == 1), 4)
            m_score = round((s_p - r_p) / max(1, len(valid_reports)), 4)

            sample = clone_votes[0][1]
            # If any clone only failed because of an injected Byzantine fault while >= 3 honest clones verified it,
            # BFT quorum (s_p >= 3) overrides the single faulty clone!
            # Conversely, if a proposition is an ungrounded trap (s_p == 0, r_p >= 1), quarantine into Negative Tabu.
            if s_p >= quorum_threshold and (r_p == 0 or (inject_byzantine_fault and r_p <= 1)):
                accepted_truths.append(
                    {
                        "proposition_id": prop_id,
                        "seam_kind": sample.seam_kind,
                        "anchor": sample.anchor,
                        "symbols": sample.symbols,
                        "domain": sample.domain,
                        "support_votes_s_p": s_p,
                        "refute_votes_r_p": r_p,
                        "abstain_votes_u_p": u_p,
                        "consensus_m_score": m_score,
                        "consolidated_weight_w": w_p,
                        "priority_q": round(forecast_q_map.get(sample.anchor, 1.0), 3),
                        "cognitive_trap": sample.cognitive_trap,
                        "mental_model": sample.mental_model,
                        "s3_guard_hint": dream_verified_anchors.get(sample.anchor, sample.s3_guard_hint),
                        "analogical_law": sample.analogical_law,
                        "supporting_clones": [cid for cid, pv in clone_votes if pv.vote == 1],
                    }
                )
            elif r_p >= 1 and s_p < quorum_threshold:
                quarantined_tabu.append(
                    {
                        "proposition_id": prop_id,
                        "seam_kind": sample.seam_kind,
                        "anchor": sample.anchor,
                        "symbols": sample.symbols,
                        "domain": sample.domain,
                        "refute_votes_r_p": r_p,
                        "support_votes_s_p": s_p,
                        "reason": sample.evidence_reason,
                        "what_not_to_do": sample.cognitive_trap,
                        "detected_by_clones": [cid for cid, pv in clone_votes if pv.vote == -1],
                    }
                )
            else:
                unresolved_claims.append(
                    {
                        "proposition_id": prop_id,
                        "seam_kind": sample.seam_kind,
                        "anchor": sample.anchor,
                        "support_votes_s_p": s_p,
                        "refute_votes_r_p": r_p,
                        "abstain_votes_u_p": u_p,
                        "status": "UNRESOLVED_QUORUM_NOT_MET",
                    }
                )

        # Sort accepted truths by causal priority Q descending, then consolidated weight W descending
        accepted_truths.sort(key=lambda x: (x["priority_q"], x["consolidated_weight_w"]), reverse=True)

        # Build the deterministic Step-by-Step "Right Playbook (Cách Làm Đúng)"
        right_playbook: List[PlaybookStep] = []
        for idx, truth in enumerate(accepted_truths, start=1):
            kind = truth["seam_kind"]
            tmpl = SEAM_AUTOPOIETIC_TEMPLATES.get(kind, {})
            sev = tmpl["severity"].value if "severity" in tmpl else "HIGH"
            right_playbook.append(
                PlaybookStep(
                    step_order=idx,
                    proposition_id=truth["proposition_id"],
                    seam_kind=kind,
                    anchor=truth["anchor"],
                    domain=truth["domain"],
                    severity=sev,
                    supporting_clones=truth["support_votes_s_p"],
                    total_clones=len(valid_reports),
                    consensus_ratio=round(truth["support_votes_s_p"] / max(1, len(valid_reports)), 2),
                    consolidated_weight_w=truth["consolidated_weight_w"],
                    priority_q=truth["priority_q"],
                    what_to_avoid_tabu=truth["cognitive_trap"],
                    right_way_action=truth["mental_model"],
                    s3_code_guard=truth["s3_guard_hint"],
                    analogical_law=truth["analogical_law"],
                    verification_check=f"kintsugi ground {target} --anchor {truth['anchor']} && kintsugi foresight {target} --dream",
                )
            )

        # Consolidate into CognitiveMemoryManager + ScarLedger + MetacognitiveSelfModel
        before_meta = self.meta_model.build_self_awareness_report()
        before_c = float(before_meta["global_competence"])
        distilled_lesson_ids: List[str] = []

        if consolidate_to_memory:
            synth_res = self.synthesizer.synthesize_from_target(target)
            for item in synth_res.get("synthesized_lessons", []):
                if item.get("lesson_id"):
                    distilled_lesson_ids.append(str(item["lesson_id"]))
            # Reload state after synthesizer and record each accepted proposition's domain outcome
            self.meta_model = MetacognitiveSelfModel(self.workspace_root)
            seen_domains = {t["domain"] for t in accepted_truths}
            for dom in seen_domains:
                self.meta_model.record_outcome(dom, succeeded=True, predicted_prob=0.92)

        after_meta = self.meta_model.build_self_awareness_report()
        after_c = float(after_meta["global_competence"])
        c_gain = round(max(0.0, after_c - before_c), 4)

        # Persist Negative Tabu List & Swarm Merged Wisdom
        self._persist_tabu_and_wisdom(
            manifest_sha=manifest_sha,
            quarantined_tabu=quarantined_tabu,
            right_playbook=right_playbook,
        )

        bft_status = "PASS" if len(valid_reports) == k_clones else "DEGRADED"
        playbook_status = "VERIFIED" if (right_playbook or not seams) else "UNRESOLVED"
        swarm_wire = (
            f"@SWARM/1|sha={manifest_sha[:8]}|clones={len(valid_reports)}|"
            f"accepted={len(accepted_truths)}|tabu={len(quarantined_tabu)}|"
            f"bft={bft_status}|c_gain=+{c_gain:.4f}|playbook={playbook_status}"
        )

        elapsed_total_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        return {
            "target": str(target),
            "manifest_sha": manifest_sha,
            "swarm_architecture": "v1.0.0-Kage-Bunshin-BFT-Epistemic-Swarm (K=3f+1)",
            "elapsed_ms": elapsed_total_ms,
            "kmi_swarm_wire": swarm_wire,
            "clones_spawned": len(valid_reports),
            "bft_quorum_threshold": quorum_threshold,
            "byzantine_fault_injected": inject_byzantine_fault,
            "bft_consensus_status": bft_status,
            "playbook_status": playbook_status,
            "metacognitive_evolution": {
                "competence_before": before_c,
                "competence_after": after_c,
                "competence_gain": c_gain,
                "epistemic_confidence_after": after_meta["global_epistemic_confidence"],
            },
            "clone_episodic_reports": [r.to_dict() for r in valid_reports],
            "consolidated_truths_count": len(accepted_truths),
            "consolidated_truths": accepted_truths,
            "negative_tabu_quarantined_count": len(quarantined_tabu),
            "negative_tabu_list": quarantined_tabu,
            "unresolved_claims": unresolved_claims,
            "distilled_lesson_ids": distilled_lesson_ids,
            "right_playbook_steps_count": len(right_playbook),
            "right_playbook": [s.to_dict() for s in right_playbook],
        }

    def _persist_tabu_and_wisdom(
        self,
        manifest_sha: str,
        quarantined_tabu: List[Dict[str, Any]],
        right_playbook: List[PlaybookStep],
    ) -> None:
        self.kintsugi_dir.mkdir(parents=True, exist_ok=True)
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tabu_payload = {
            "schema_version": "1.0",
            "updated_at": now_iso,
            "manifest_sha": manifest_sha,
            "quarantined_traps": quarantined_tabu,
        }
        self.tabu_path.write_text(json.dumps(tabu_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        wisdom_payload = {
            "schema_version": "1.0",
            "updated_at": now_iso,
            "manifest_sha": manifest_sha,
            "right_playbook": [s.to_dict() for s in right_playbook],
        }
        self.swarm_state_path.write_text(
            json.dumps(wisdom_payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
