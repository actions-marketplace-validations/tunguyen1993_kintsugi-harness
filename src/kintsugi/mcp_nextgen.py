"""Next-Gen Build #2 MCP tool definitions & handlers (`kintsugi.mcp_nextgen`).

Registered ONLY when `KintsugiMCPServer(..., profile="nextgen" | "coding")`.
Preserves the 9 legacy default tools under `profile="default"`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from kintsugi.capability import CompositionPlan, SecurityContext, ToolRegistry
from kintsugi.cli_nextgen import (
    load_raw_run_events,
    load_workspace_json,
    load_workspace_registry,
    make_security_context,
    run_build3_asm_forge_helper,
    run_build3_evolution_v4_helper,
    run_build3_smt_verify_helper,
    run_build3_synthesize_helper,
)
from kintsugi.composition import (
    CompositionVerifier,
    ToolComposer,
    parallel_execution_groups,
)
from kintsugi.runtime import CheckpointManager, TraceStore
from kintsugi.self_model import FunctionalSelfModel
from kintsugi.tools import ProofPack, TraceDoctor

NEXTGEN_BUILD2_TOOL_NAMES = frozenset(
    {
        "kintsugi_composition_plan",
        "kintsugi_composition_verify",
        "kintsugi_run_status",
        "kintsugi_self_model_inspect",
        "kintsugi_tracedoctor_analyze",
        "kintsugi_proofpack_verify",
    }
)


def nextgen_build2_tool_definitions() -> List[Dict[str, Any]]:
    """Return read-only Next-Gen Working Tools for Build #2 (`profile in {'nextgen', 'coding'}`)."""
    readonly_annotations = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
    }
    return [
        {
            "name": "kintsugi_composition_plan",
            "description": "Stage 2 LEGO Tool Composer: synthesize a verified DAG plan and parallel execution groups for required capabilities.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root", "required_capabilities"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "required_capabilities": {"type": "array", "items": {"type": "string"}},
                    "goal_id": {"type": "string"},
                    "registry_path": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_composition_verify",
            "description": "Stage 2 Composition Verifier: validate structural, type, security, effect, budget, and determinism invariants on a CompositionPlan/1.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root", "plan"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "plan": {"type": "object"},
                    "registry_path": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_run_status",
            "description": "Stage 4 Durable Runtime: inspect run checkpoint state and verify append-only TraceStore SHA-256 hash chain.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "run_id": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_self_model_inspect",
            "description": "Stage 6 Functional Self-Model: query evidence-gated capability readiness and bounded recovery subgoals.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "required_capabilities": {"type": "array", "items": {"type": "string"}},
                    "registry_path": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_tracedoctor_analyze",
            "description": "Working Tool #4 TraceDoctor: verify RunEvent/1 hash chain and localize root-cause failing node with zero LLM calls.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "run_id": {"type": "string"},
                    "events": {"type": "array"},
                },
            },
        },
        {
            "name": "kintsugi_proofpack_verify",
            "description": "Working Tool #5 ProofPack: run independent Python vs Rust parity verification or reproducibility/manifest checks.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "mode": {"type": "string", "enum": ["parity", "manifest", "reproducibility"]},
                    "num_cases": {"type": "integer"},
                    "files": {"type": "array", "items": {"type": "string"}},
                    "receipts": {"type": "array"},
                },
            },
        },
    ]


NEXTGEN_BUILD3_TOOL_NAMES = frozenset(
    {
        "kintsugi_build3_synthesize_plan",
        "kintsugi_build3_smt_verify_plan",
        "kintsugi_build3_asm_arch_status",
        "kintsugi_build3_evolution_v4_ablate",
    }
)


def nextgen_build3_tool_definitions() -> List[Dict[str, Any]]:
    """Return read-only Build #3 Cognitive Forge MCP tools (`profile in {'build3', 'cognitive'}`)."""
    readonly_annotations = {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
    }
    return [
        {
            "name": "kintsugi_build3_synthesize_plan",
            "description": "Build #3 Agent B: Synthesize a typed capability path & gap blueprint from goal + tools.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root", "goal"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "goal": {"type": "object"},
                    "tools": {"type": "array", "items": {"type": "object"}},
                    "security_context": {"type": "object"},
                    "registry_path": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_build3_smt_verify_plan",
            "description": "Build #3 Agent D: Formally verify a composition plan across safety, taint, permissions & idempotency.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root", "plan"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "plan": {"type": "object"},
                    "tools": {"type": "array", "items": {"type": "object"}},
                    "adapters": {"type": "array", "items": {"type": "object"}},
                    "security_context": {"type": "object"},
                    "registry_path": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_build3_asm_arch_status",
            "description": "Build #3 Agent C: Report host architecture, ASM/NEON backend availability & supported kernel templates.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root"],
                "properties": {
                    "workspace_root": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_build3_evolution_v4_ablate",
            "description": "Build #3 Agent E: Evaluate matched causal ablation trials with family disjointness & Wilson lower-bound gates.",
            "annotations": dict(readonly_annotations),
            "inputSchema": {
                "type": "object",
                "required": ["workspace_root", "trials"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "strategy_id": {"type": "string"},
                    "revision": {"type": "integer"},
                    "train_families": {"type": "array", "items": {"type": "string"}},
                    "heldout_families": {"type": "array", "items": {"type": "string"}},
                    "trials": {"type": "array", "items": {"type": "object"}},
                    "mode": {"type": "string", "enum": ["local_research", "github_public"]},
                },
            },
        },
    ]


def dispatch_nextgen_build3_mcp_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle read-only Build #3 Cognitive Forge MCP tool calls."""
    ws = Path(str(args.get("workspace_root") or ".")).resolve()
    if name == "kintsugi_build3_synthesize_plan":
        return run_build3_synthesize_helper(
            ws,
            dict(args.get("goal") or {}),
            tools_data=args.get("tools"),
            registry_path=args.get("registry_path"),
            context_data=args.get("security_context"),
        )
    if name == "kintsugi_build3_smt_verify_plan":
        return run_build3_smt_verify_helper(
            ws,
            dict(args.get("plan") or {}),
            tools_data=args.get("tools"),
            registry_path=args.get("registry_path"),
            adapters_data=args.get("adapters"),
            context_data=args.get("security_context"),
        )
    if name == "kintsugi_build3_asm_arch_status":
        return run_build3_asm_forge_helper(ws, action="info")
    if name == "kintsugi_build3_evolution_v4_ablate":
        return run_build3_evolution_v4_helper(
            ws,
            args,
            mode=str(args.get("mode") or "local_research"),
        )
    raise KeyError(name)


def dispatch_nextgen_build2_mcp_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Handle Next-Gen Build #2 MCP tool calls; raises KeyError if `name` is not handled here."""
    if name == "kintsugi_composition_plan":
        ws = Path(str(args.get("workspace_root") or ".")).resolve()
        sec_ctx = make_security_context(ws, None)
        reg = load_workspace_registry(ws, args.get("registry_path") or ".kintsugi/tool_registry.json")
        goal = {
            "goal_id": str(args.get("goal_id") or "mcp-comp-001"),
            "required_capabilities": list(args.get("required_capabilities") or []),
        }
        res = ToolComposer().plan(goal, reg, sec_ctx)
        out = res.to_dict()
        if res.plan is not None:
            out["parallel_execution_groups"] = parallel_execution_groups(res.plan, reg)
        out["ok"] = res.executable
        return out

    if name == "kintsugi_composition_verify":
        ws = Path(str(args.get("workspace_root") or ".")).resolve()
        sec_ctx = make_security_context(ws, None)
        reg = load_workspace_registry(ws, args.get("registry_path") or ".kintsugi/tool_registry.json")
        plan = CompositionPlan.from_dict(dict(args["plan"]))
        ver = CompositionVerifier().verify(plan, reg, sec_ctx)
        return ver.to_dict()

    if name == "kintsugi_run_status":
        ws = Path(str(args.get("workspace_root") or ".")).resolve()
        tstore = TraceStore(workspace_root=ws)
        ckpt = CheckpointManager(workspace_root=ws, trace_store=tstore)
        run_id = args.get("run_id")
        run_ids = [str(run_id)] if run_id else tstore.list_runs()
        runs = []
        for rid in run_ids:
            cp = ckpt.load_checkpoint(rid)
            chain = tstore.verify_run_chain(rid)
            runs.append(
                {
                    "run_id": rid,
                    "status": (cp or {}).get("status", "UNKNOWN"),
                    "completed_steps": (cp or {}).get("completed_step_ids", []),
                    "chain_valid": chain.valid,
                    "events_checked": chain.checked_count,
                }
            )
        return {"ok": all(r["chain_valid"] for r in runs), "runs_count": len(runs), "runs": runs}

    if name == "kintsugi_self_model_inspect":
        ws = Path(str(args.get("workspace_root") or ".")).resolve()
        sm = FunctionalSelfModel(workspace_root=ws)
        if sm.path.exists() or sm.path.is_symlink():
            sm.load()
        reg_path = args.get("registry_path")
        if reg_path:
            reg = load_workspace_registry(ws, str(reg_path))
            sm.sync_from_registry(reg, save=False)
        out: Dict[str, Any] = {"ok": True, "self_model": sm.to_dict()}
        req = list(args.get("required_capabilities") or [])
        if req:
            sec_ctx = make_security_context(ws, None)
            out["readiness"] = sm.query_readiness(req, sec_ctx).to_dict()
        return out

    if name == "kintsugi_tracedoctor_analyze":
        ws = Path(str(args.get("workspace_root") or ".")).resolve()
        if args.get("run_id"):
            events = load_raw_run_events(ws, str(args["run_id"]))
        else:
            events = list(args.get("events") or [])
        diag = TraceDoctor().diagnose(events)
        return diag.to_dict()

    if name == "kintsugi_proofpack_verify":
        ws = Path(str(args.get("workspace_root") or ".")).resolve()
        pp = ProofPack()
        mode = str(args.get("mode") or "parity")
        if mode == "parity":
            rep = pp.check_python_rust_parity(num_cases=max(1, int(args.get("num_cases", 16))))
            out = rep.to_dict()
            out["ok"] = rep.verified_independently
            return out
        if mode == "manifest":
            files = [str(f) for f in (args.get("files") or [])]
            return {"ok": True, "manifest": pp.build_artifact_manifest(files, ws)}
        rep = pp.verify_reproducibility(list(args.get("receipts") or []))
        out = rep.to_dict()
        out["ok"] = rep.verified_independently
        return out

    raise KeyError(name)
