"""Next-Gen Build #2 CLI subcommand builders & handlers (`kintsugi.cli_nextgen`).

Keeps `kintsugi.cli` concise while exposing Stages 1-6 + Working Tools cleanly:
  - `compose` (`plan`, `verify`, `execute`)
  - `forge` (`propose`, `build`, `benchmark`, `rollback`)
  - `runs` (`status`, `replay`)
  - `self-model` (`inspect`)
  - `toolwire`
  - `tracedoctor`
  - `proofpack`
  - Stage 5 `evolve` v3 flags (`--capture-trace`, `--promote`, `--mode`, `--approve`, `--rollback`, `--registry-status`, `--canary`)
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from kintsugi.capability import (
    AdapterSpec,
    CompositionPlan,
    CompositionReceipt,
    PortContract,
    SecurityContext,
    ToolRegistry,
    ToolSpec,
    TrustStatus,
)
from kintsugi.composition import (
    CompositionVerifier,
    ToolComposer,
    parallel_execution_groups,
)
from kintsugi.config import OperatingProfile, resolve_kintsugi_config
from kintsugi.forge import (
    BuildManifestStore,
    NativeToolForge,
    ToolBenchmark,
    build_kvpipe_v1_task_spec,
    generate_kvpipe_v1_benchmark_payload,
    parse_kvpipe_v1_python,
)
from kintsugi.runtime import (
    CheckpointManager,
    RunStateMachine,
    SecureRunner,
    TraceStore,
)
from kintsugi.runtime.trace_store import read_regular_text_nofollow
from kintsugi.self_model import FunctionalSelfModel
from kintsugi.shield import assert_not_symlink
from kintsugi.tools import ProofPack, ToolWire, TraceDoctor


def resolve_confined_workspace_file(workspace_root: UnionPath, raw_path: str) -> Path:
    """Resolve `raw_path` strictly inside `workspace_root` with symlink checks."""
    ws = Path(workspace_root).resolve()
    assert_not_symlink(ws)
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = ws / candidate
    cur = candidate
    for _ in range(64):
        if cur == ws or cur == cur.parent:
            break
        if cur.exists() or cur.is_symlink():
            assert_not_symlink(cur)
        cur = cur.parent
    resolved = candidate.resolve()
    resolved.relative_to(ws)
    assert_not_symlink(resolved)
    return resolved


UnionPath = Path


def load_workspace_json(workspace_root: Path, raw_path: str) -> Any:
    """Load and parse a confined JSON (or JSONL list) file safely via O_NOFOLLOW."""
    resolved = resolve_confined_workspace_file(workspace_root, raw_path)
    text = read_regular_text_nofollow(resolved)
    stripped = text.strip()
    if not stripped:
        return {}
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return [json.loads(line) for line in stripped.splitlines() if line.strip()]


def load_workspace_registry(workspace_root: Path, registry_path: Optional[str]) -> ToolRegistry:
    """Load `ToolRegistry` from confined `registry_path` if present, else empty registry."""
    registry = ToolRegistry()
    if registry_path:
        rp = resolve_confined_workspace_file(workspace_root, registry_path)
        if rp.exists():
            registry.load(rp)
    return registry


def load_raw_run_events(workspace_root: Path, run_id: str) -> List[Any]:
    """Load run events via TraceStore; if chain is tampered, parse lines safely for TraceDoctor."""
    tstore = TraceStore(workspace_root=workspace_root)
    try:
        return list(tstore.load_events(run_id))
    except ValueError:
        tpath = tstore.trace_path_for(run_id)
        if not tpath.exists():
            return []
        raw_text = read_regular_text_nofollow(tpath)
        return [json.loads(line) for line in raw_text.splitlines() if line.strip()]


def load_adapters(workspace_root: Path, adapters_path: Optional[str]) -> List[AdapterSpec]:
    """Load `AdapterSpec` entries from a JSON file inside `workspace_root`."""
    if not adapters_path:
        return []
    raw = load_workspace_json(workspace_root, adapters_path)
    if isinstance(raw, Mapping):
        raw_items = raw.get("adapters") or ([raw] if "adapter_id" in raw else [])
    elif isinstance(raw, list):
        raw_items = raw
    else:
        raw_items = []
    return [item if isinstance(item, AdapterSpec) else AdapterSpec.from_dict(dict(item)) for item in raw_items]


def make_security_context(workspace_root: Path, profile_name: Optional[str]) -> SecurityContext:
    """Resolve `SecurityContext` matching configured operating profile."""
    cfg = resolve_kintsugi_config(cli_profile=profile_name, target_repo_root=workspace_root)
    prof = "GITHUB_PUBLIC" if cfg.profile == OperatingProfile.GITHUB_PUBLIC else "LOCAL_RESEARCH"
    return SecurityContext(
        workspace_root=str(workspace_root),
        profile=prof,
        network_allowed=False,
    )


def register_nextgen_parsers(sub: Any, p_evo: argparse.ArgumentParser) -> None:
    """Register Build #2 Next-Gen CLI subcommands and Stage 5 evolve flags."""
    # compose (Stage 2 LEGO Composition Fabric)
    p_cmp = sub.add_parser("compose", help="Stage 2 LEGO Tool Composition Fabric (plan, verify, execute)")
    cmp_sub = p_cmp.add_subparsers(dest="compose_action", required=True)

    for action in ("plan", "verify", "execute"):
        sp = cmp_sub.add_parser(action, help=f"{action.capitalize()} a composition DAG")
        sp.add_argument("--workspace", default=".", help="Workspace root directory")
        sp.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Workspace ToolRegistry JSON")
        sp.add_argument("--adapters", default=None, help="Optional JSON file containing AdapterSpec list")
        if action == "plan":
            sp.add_argument("--goal", default=None, help="Goal contract JSON file inside workspace")
            sp.add_argument("--required", nargs="*", default=[], help="Required capabilities if --goal is omitted")
            sp.add_argument("--goal-id", default="cli-goal-001", help="Goal identifier")
        else:
            sp.add_argument("--plan", required=True, help="CompositionPlan/1 JSON file inside workspace")
            if action == "execute":
                sp.add_argument("--inputs", default=None, help="Initial inputs JSON file")
                sp.add_argument("--run-id", default=None, help="Run ID (also used for resume/checkpoints)")

    # forge (Stage 3 Autonomous NativeToolForge + Seatbelt/Bubblewrap Sandbox)
    p_frg = sub.add_parser("forge", help="Stage 3 NativeToolForge escalation ladder, sandboxed build, benchmark & rollback")
    frg_sub = p_frg.add_subparsers(dest="forge_action", required=True)

    p_fp = frg_sub.add_parser("propose", help="Evaluate escalation ladder for required capabilities")
    p_fp.add_argument("--workspace", default=".", help="Workspace root directory")
    p_fp.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Workspace ToolRegistry JSON")
    p_fp.add_argument("--required", nargs="+", required=True, help="Required capabilities")
    p_fp.add_argument("--target-language", default="c", help="Preferred native language (c, rust, python, assembly)")
    p_fp.add_argument("--no-composition", action="store_true", help="Disable multi-tool composition tier")

    p_fb = frg_sub.add_parser("build", help="Forge, statically scan, sandbox-verify, and benchmark a native tool")
    p_fb.add_argument("--workspace", default=".", help="Workspace root directory")
    p_fb.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Workspace ToolRegistry JSON")
    p_fb.add_argument("--demo", choices=["kvpipe"], default="kvpipe", help="Built-in deterministic forge spec")
    p_fb.add_argument("--tool-id", default="forge.kvpipe_v1_parser", help="Target tool_id")
    p_fb.add_argument("--version", default="1.0.0", help="Build semantic version")
    p_fb.add_argument("--force", action="store_true", help="Force forging even if existing tool matches")

    p_fbench = frg_sub.add_parser("benchmark", help="Benchmark forged kvpipe.v1 native binary vs Python oracle")
    p_fbench.add_argument("--workspace", default=".", help="Workspace root directory")
    p_fbench.add_argument("--tool-id", default="forge.kvpipe_v1_parser", help="Tool ID to inspect/benchmark")
    p_fbench.add_argument("--lines", type=int, default=10000, help="Synthetic kvpipe benchmark line count")

    p_frb = frg_sub.add_parser("rollback", help="Rollback an active forged tool build to prior verified build")
    p_frb.add_argument("--workspace", default=".", help="Workspace root directory")
    p_frb.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Workspace ToolRegistry JSON")
    p_frb.add_argument("--tool-id", required=True, help="Target forged tool_id")
    p_frb.add_argument("--build-id", default=None, help="Specific prior build_id target")
    p_frb.add_argument("--reason", default="cli_manual_rollback", help="Rollback audit reason")

    # runs (Stage 4 Durable Runtime, Checkpoint & Deterministic Trace Replay)
    p_runs = sub.add_parser("runs", help="Stage 4 Durable RunStateMachine, CheckpointManager & TraceStore inspection/replay")
    runs_sub = p_runs.add_subparsers(dest="runs_action", required=True)
    for action in ("status", "replay"):
        sp = runs_sub.add_parser(action, help=f"{action.capitalize()} durable runtime runs")
        sp.add_argument("--workspace", default=".", help="Workspace root directory")
        if action == "replay":
            sp.add_argument("--run-id", required=True, help="Run ID to verify & diagnose")
        else:
            sp.add_argument("--run-id", default=None, help="Optional run_id (lists all runs if omitted)")

    # self-model (Stage 6 FunctionalSelfModel)
    p_sm = sub.add_parser("self-model", help="Stage 6 FunctionalSelfModel capability readiness & bounded subgoal inspection")
    sm_sub = p_sm.add_subparsers(dest="self_model_action", required=True)
    p_smi = sm_sub.add_parser("inspect", help="Inspect verified capabilities, readiness & bounded subgoals")
    p_smi.add_argument("--workspace", default=".", help="Workspace root directory")
    p_smi.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Optional ToolRegistry to sync")
    p_smi.add_argument("--required", nargs="*", default=[], help="Capabilities to query readiness for")
    p_smi.add_argument("--save", action="store_true", help="Persist updated self-model state")

    # toolwire (Working Tool #3: Boundary Normalization, Unit & Schema Wire)
    p_tw = sub.add_parser("toolwire", help="Working Tool #3: ToolWire schema/unit validation & zero-float streaming conversion")
    p_tw.add_argument("--workspace", default=".", help="Workspace root directory")
    p_tw.add_argument("--input", default=None, help="Input file inside workspace")
    p_tw.add_argument("--text", default=None, help="Inline payload text when --input is omitted")
    p_tw.add_argument("--source-format", default="jsonl", choices=["jsonl", "typed_event_stream", "csv", "bytes"])
    p_tw.add_argument("--target-format", default="typed_event_stream", choices=["jsonl", "typed_event_stream", "csv", "bytes"])
    p_tw.add_argument("--unit-from", default="none", help="Source physical unit (e.g. ns, ms, s)")
    p_tw.add_argument("--unit-to", default="none", help="Target physical unit (e.g. ns, ms, s)")
    p_tw.add_argument("--field", default=None, help="Field name carrying the unit value")

    # tracedoctor (Working Tool #4: Hash-Chained Execution & Root-Cause Debugger)
    p_td = sub.add_parser("tracedoctor", help="Working Tool #4: TraceDoctor tamper check & root-cause failure diagnosis")
    p_td.add_argument("--workspace", default=".", help="Workspace root directory")
    p_td.add_argument("--run-id", default=None, help="Run ID inside workspace TraceStore")
    p_td.add_argument("--trace", default=None, help="Path to RunEvent/1 JSON/JSONL trace file inside workspace")
    p_td.add_argument("--receipt", default=None, help="Optional ExecutionReceipt/CompositionReceipt JSON path")

    # proofpack (Working Tool #5: Differential, Property & Parity Verifier)
    p_pp = sub.add_parser("proofpack", help="Working Tool #5: ProofPack artifact manifest, reproducibility & Python/Rust parity")
    p_pp.add_argument("--workspace", default=".", help="Workspace root directory")
    p_pp.add_argument("--parity", action="store_true", help="Run Python vs NativeBridge/Rust RuleIR/scanner parity check")
    p_pp.add_argument("--num-cases", type=int, default=32, help="Number of seeded differential corpus cases")
    p_pp.add_argument("--manifest", nargs="*", default=None, help="Workspace-relative file paths for SHA-256 manifest")
    p_pp.add_argument("--receipts", nargs="*", default=None, help="Receipt JSON files inside workspace for reproducibility check")

    # Build #3: synthesize (Typed Capability Graph Synthesis)
    p_syn = sub.add_parser("synthesize", help="Build #3 Agent B: Typed Capability Graph synthesis & safe shortest-path planning")
    p_syn.add_argument("--workspace", default=".", help="Workspace root directory")
    p_syn.add_argument("--goal-file", required=True, help="Goal JSON file inside workspace")
    p_syn.add_argument("--tools-file", default=None, help="Optional ToolSpec JSON list file inside workspace")
    p_syn.add_argument("--context-file", default=None, help="Optional SecurityContext JSON file inside workspace")
    p_syn.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Workspace registry path")

    # Build #3: smt-verify (Neuro-Symbolic SMT Plan Verifier)
    p_smt = sub.add_parser("smt-verify", help="Build #3 Agent D: Formal SMT verification of composition plans")
    p_smt.add_argument("--workspace", default=".", help="Workspace root directory")
    p_smt.add_argument("--plan-file", required=True, help="CompositionPlan JSON file inside workspace")
    p_smt.add_argument("--tools-file", default=None, help="Optional ToolSpec JSON list file inside workspace")
    p_smt.add_argument("--adapters-file", default=None, help="Optional AdapterSpec JSON list file inside workspace")
    p_smt.add_argument("--context-file", default=None, help="Optional SecurityContext JSON file inside workspace")
    p_smt.add_argument("--registry", default=".kintsugi/tool_registry.json", help="Workspace registry path")

    # Build #3: asm-forge (ARM64/NEON & C Native Kernel Forge)
    p_asm = sub.add_parser("asm-forge", help="Build #3 Agent C: ASM/NEON Native Forge status, build & benchmark")
    p_asm.add_argument("action", choices=["info", "build", "benchmark"], help="ASM forge action")
    p_asm.add_argument("--workspace", default=".", help="Workspace root directory")
    p_asm.add_argument("--kernel", default="delim_scan", choices=["delim_scan", "crc32c_fnv64"], help="Kernel template")

    # Build #3: evolve-v4 (Causal Ablation & Adaptive Exploration)
    p_ev4 = sub.add_parser("evolve-v4", help="Build #3 Agent E: Evolution v4 matched causal ablation verifier")
    p_ev4.add_argument("--workspace", default=".", help="Workspace root directory")
    p_ev4.add_argument("--trials-file", required=True, help="JSON file with strategy_id, train_families, heldout_families & trials")
    p_ev4.add_argument("--mode", default="local_research", choices=["local_research", "github_public"], help="Execution budget mode")

    # Stage 5 evolve flags
    p_evo.add_argument("--capture-trace", default=None, help="Stage 5 FailureEnvelope/trace JSON file to ingest via Evolution v3")
    p_evo.add_argument("--promote", action="store_true", help="Run Stage 5 verified promotion gate via Evolution v3")
    p_evo.add_argument("--mode", default="shadow", choices=["shadow", "canary", "enforced"], help="Promotion stage target")
    p_evo.add_argument("--approve", action="store_true", help="Explicit reviewer approval required for enforced mode")
    p_evo.add_argument("--rollback", default=None, metavar="RULE_ID", help="Rollback rule_id in Evolution v3 registry")
    p_evo.add_argument("--to-revision", type=int, default=1, help="Target revision for --rollback")
    p_evo.add_argument("--registry-status", action="store_true", help="Show Evolution v3 promoted rule registry status")
    p_evo.add_argument("--canary", default=None, help="Canary soak corpus JSON list file inside workspace")
    p_evo.add_argument("--rule-id", default=None, help="Explicit rule_id for Stage 5 candidate synthesis/promotion")
    p_evo.add_argument(
        "--sealed-blind-corpus",
        default=None,
        help="External held-out blind corpus JSON file outside workspace for verified sealed eval",
    )
    p_evo.add_argument(
        "--sealed-sha256",
        default=None,
        help="Expected sha256:<hex> pin for --sealed-blind-corpus",
    )
    p_evo.add_argument(
        "--train-corpus",
        default=None,
        help="Optional workspace JSON list of training families paired with --sealed-blind-corpus",
    )


def handle_nextgen_command(args: argparse.Namespace) -> Optional[int]:
    """Dispatch Build #2 commands. Returns exit code if handled, else None."""
    cmd = getattr(args, "command", None)
    if cmd == "compose":
        return _handle_compose(args)
    if cmd == "forge":
        return _handle_forge(args)
    if cmd == "runs":
        return _handle_runs(args)
    if cmd == "self-model":
        return _handle_self_model(args)
    if cmd == "toolwire":
        return _handle_toolwire(args)
    if cmd == "tracedoctor":
        return _handle_tracedoctor(args)
    if cmd == "proofpack":
        return _handle_proofpack(args)
    if cmd == "synthesize":
        return _handle_build3_synthesize(args)
    if cmd == "smt-verify":
        return _handle_build3_smt_verify(args)
    if cmd == "asm-forge":
        return _handle_build3_asm_forge(args)
    if cmd == "evolve-v4":
        return _handle_build3_evolve_v4(args)
    return None


def _json_default(obj: Any) -> Any:
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default))


def _handle_compose(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    profile_name = getattr(args, "profile", None)
    sec_ctx = make_security_context(ws, profile_name)
    cfg = resolve_kintsugi_config(cli_profile=profile_name, target_repo_root=ws)
    registry = load_workspace_registry(ws, args.registry)
    adapters = load_adapters(ws, args.adapters)
    composer = ToolComposer()

    if args.compose_action == "plan":
        if args.goal:
            goal = load_workspace_json(ws, args.goal)
        else:
            goal = {"goal_id": args.goal_id, "required_capabilities": list(args.required or [])}
        res = composer.plan(goal, registry, sec_ctx, adapters=adapters, config=cfg)
        out = res.to_dict()
        if res.plan is not None:
            out["parallel_execution_groups"] = parallel_execution_groups(res.plan, registry)
        _print_json(out)
        return 0 if res.executable else 1

    raw_plan = load_workspace_json(ws, args.plan)
    plan = CompositionPlan.from_dict(dict(raw_plan))

    if args.compose_action == "verify":
        ver = CompositionVerifier().verify(plan, registry, sec_ctx, adapters=adapters)
        _print_json(ver.to_dict())
        return 0 if ver.ok else 1

    inputs = load_workspace_json(ws, args.inputs) if args.inputs else {}
    runner = SecureRunner(attestation_authority=registry.authority)
    receipt, events = composer.execute_plan(
        plan,
        registry,
        sec_ctx,
        runner=runner,
        adapters=adapters,
        initial_inputs=inputs if isinstance(inputs, Mapping) else {},
        checkpoint_store_path=ws / ".kintsugi" / "composition_checkpoints.json",
        resume_run_id=args.run_id,
    )
    _print_json(
        {
            "ok": receipt.status == "PASS",
            "receipt": receipt.to_dict(),
            "events_count": len(events),
            "trace_diagnosis": TraceDoctor().diagnose(events, receipt=receipt, plan=plan).to_dict(),
        }
    )
    return 0 if receipt.status == "PASS" else 1


def _handle_forge(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    cfg = resolve_kintsugi_config(cli_profile=getattr(args, "profile", None), target_repo_root=ws)
    forge = NativeToolForge(ws, profile=cfg.profile.value)

    if args.forge_action == "propose":
        sec_ctx = make_security_context(ws, getattr(args, "profile", None))
        registry = load_workspace_registry(ws, args.registry)
        dec = forge.evaluate_escalation_ladder(
            list(args.required),
            registry=registry,
            security_context=sec_ctx,
            allow_composition=not bool(args.no_composition),
            target_language=args.target_language,
        )
        _print_json(dec.to_dict())
        return 0

    if args.forge_action == "build":
        registry = load_workspace_registry(ws, args.registry)
        sec_ctx = make_security_context(ws, getattr(args, "profile", None))
        spec = build_kvpipe_v1_task_spec(tool_id=args.tool_id, version=args.version)
        res = forge.forge_tool(
            spec,
            registry=registry,
            security_context=sec_ctx,
            force_forge=bool(args.force),
        )
        if args.registry and res.verified:
            rp = resolve_confined_workspace_file(ws, args.registry)
            registry.save(rp)
        _print_json(res.to_dict())
        return 0 if res.verified else 1

    if args.forge_action == "benchmark":
        store = BuildManifestStore(workspace_root=ws)
        active = store.get_active_build(args.tool_id)
        payload = generate_kvpipe_v1_benchmark_payload(args.lines)
        bench = ToolBenchmark(profile=cfg.profile.value)
        if active and active.artifact_path and Path(active.artifact_path).exists():
            def _run_native(raw_bytes: bytes) -> Dict[str, Any]:
                sr = forge.sandbox.execute([active.artifact_path], stdin_data=raw_bytes)
                if sr.returncode != 0:
                    raise RuntimeError(sr.stderr)
                return json.loads(sr.stdout)

            rep = bench.run(
                candidate_fn=_run_native,
                baseline_fn=parse_kvpipe_v1_python,
                payload=payload,
                dataset_name="kvpipe_v1_cli_bench",
                compiler="clang",
                flags=list(active.flags or ()),
            )
            _print_json({"tool_id": args.tool_id, "build_id": active.build_id, "benchmark": rep.to_dict()})
            return 0 if rep.passed else 1

        # No built native binary yet -> benchmark Python reference baseline honesty
        rep = bench.run(
            candidate_fn=parse_kvpipe_v1_python,
            baseline_fn=parse_kvpipe_v1_python,
            payload=payload,
            dataset_name="kvpipe_v1_python_baseline",
            compiler="python",
        )
        _print_json({"tool_id": args.tool_id, "build_id": None, "benchmark": rep.to_dict()})
        return 0

    registry = load_workspace_registry(ws, args.registry)
    rb = forge.rollback(
        args.tool_id,
        target_build_id=args.build_id,
        reason=args.reason,
        registry=registry,
    )
    if args.registry:
        rp = resolve_confined_workspace_file(ws, args.registry)
        registry.save(rp)
    _print_json(rb.to_dict())
    return 0


def _handle_runs(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    tstore = TraceStore(workspace_root=ws)
    ckpt = CheckpointManager(workspace_root=ws, trace_store=tstore)

    if args.runs_action == "status":
        run_ids = [args.run_id] if args.run_id else tstore.list_runs()
        rows = []
        for rid in run_ids:
            cp = ckpt.load_checkpoint(rid)
            chain = tstore.verify_run_chain(rid)
            rows.append(
                {
                    "run_id": rid,
                    "status": (cp or {}).get("status", "UNKNOWN"),
                    "completed_steps": (cp or {}).get("completed_step_ids", []),
                    "chain_valid": chain.valid,
                    "events_checked": chain.checked_count,
                    "chain_errors": list(chain.reasons),
                }
            )
        _print_json({"workspace": str(ws), "runs_count": len(rows), "runs": rows})
        return 0 if all(r["chain_valid"] for r in rows) else 1

    run_id = args.run_id
    chain = tstore.verify_run_chain(run_id)
    events = load_raw_run_events(ws, run_id)
    diag = TraceDoctor().diagnose(events)
    cp = ckpt.load_checkpoint(run_id)
    _print_json(
        {
            "run_id": run_id,
            "checkpoint": cp,
            "chain_verification": chain.to_dict(),
            "diagnosis": diag.to_dict(),
        }
    )
    return 0 if (chain.valid and diag.ok) else 1


def _handle_self_model(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    sm = FunctionalSelfModel(workspace_root=ws)
    if sm.path.exists() or sm.path.is_symlink():
        sm.load()
    if args.registry:
        rp = resolve_confined_workspace_file(ws, args.registry)
        if rp.exists():
            reg = ToolRegistry()
            reg.load(rp)
            sm.sync_from_registry(reg, save=bool(args.save))
    out: Dict[str, Any] = {"self_model": sm.to_dict()}
    if args.required:
        sec_ctx = make_security_context(ws, getattr(args, "profile", None))
        readiness = sm.query_readiness(list(args.required), sec_ctx)
        subgoals = sm.propose_bounded_subgoals(
            {"goal_id": "cli-self-model-probe", "required_capabilities": list(args.required)},
            sec_ctx,
        )
        out["readiness"] = readiness.to_dict()
        out["subgoals"] = subgoals.to_dict()
    if args.save:
        sm.save()
    _print_json(out)
    return 0


def _handle_toolwire(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    wire = ToolWire()
    payload_text = args.text
    if payload_text is None and args.input:
        fp = resolve_confined_workspace_file(ws, args.input)
        payload_text = read_regular_text_nofollow(fp)
    if payload_text is None:
        payload_text = ""

    src_port = PortContract(
        schema_ref=args.source_format,
        semantic_type="wire/records",
        encoding="utf-8",
        unit=args.unit_from,
        cardinality="many",
        ordering="ordered",
        precision="int64" if args.unit_from != args.unit_to else None,
    )
    dst_port = PortContract(
        schema_ref=args.target_format,
        semantic_type="wire/records",
        encoding="utf-8",
        unit=args.unit_to,
        cardinality="many",
        ordering="ordered",
        precision="decimal128" if args.unit_from != args.unit_to else None,
    )
    opts: Dict[str, Any] = {
        "source_format": args.source_format,
        "target_format": args.target_format,
    }
    if args.field and args.unit_from != args.unit_to:
        opts["unit_fields"] = [args.field]
        opts["unit_conversion"] = {"from_unit": args.unit_from, "to_unit": args.unit_to}
    validation = wire.validate_boundary(src_port, dst_port, **opts)
    conv_opts = dict(opts)
    conv_opts["decimal_as_string"] = True
    converted = wire.convert(payload_text, source_port=src_port, target_port=dst_port, **conv_opts)
    _print_json(
        {
            "ok": True,
            "validation": validation,
            "records_count": len(converted.records),
            "output": converted.output,
            "provenance": converted.provenance.to_dict(),
        }
    )
    return 0


def _handle_tracedoctor(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    if args.run_id:
        events = load_raw_run_events(ws, args.run_id)
    elif args.trace:
        raw = load_workspace_json(ws, args.trace)
        events = list(raw if isinstance(raw, list) else raw.get("events", []))
    else:
        raise ValueError("TraceDoctor requires --run-id or --trace")
    receipt = load_workspace_json(ws, args.receipt) if args.receipt else None
    diag = TraceDoctor().diagnose(events, receipt=receipt)
    _print_json(diag.to_dict())
    return 0 if diag.ok else 1


def _handle_proofpack(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    pp = ProofPack()
    if args.parity:
        rep = pp.check_python_rust_parity(num_cases=max(1, int(args.num_cases)))
        _print_json(rep.to_dict())
        return 0 if rep.verified_independently else 1
    if args.manifest is not None:
        files = [resolve_confined_workspace_file(ws, f) for f in args.manifest]
        _print_json(pp.build_artifact_manifest(files, ws))
        return 0
    if args.receipts is not None:
        items = [load_workspace_json(ws, r) for r in args.receipts]
        rep = pp.verify_reproducibility(items)
        _print_json(rep.to_dict())
        return 0 if rep.verified_independently else 1
    _print_json({"error": "Specify --parity, --manifest, or --receipts"})
    return 2


def run_build3_synthesize_helper(
    ws: Path,
    goal_payload: Mapping[str, Any],
    *,
    tools_data: Optional[Sequence[Any]] = None,
    registry_path: Optional[str] = None,
    context_data: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Shared Build #3 TypedCapabilityGraph synthesis helper used cleanly by CLI & MCP."""
    from kintsugi.capability.schemas import SecurityContext, ToolSpec
    from kintsugi.synthesis.capability_graph import SynthesisGoal, TypedCapabilityGraph

    sec_ctx = SecurityContext.from_dict(dict(context_data)) if context_data else make_security_context(ws, None)
    if tools_data is not None:
        tools = [item if isinstance(item, ToolSpec) else ToolSpec.from_dict(dict(item)) for item in tools_data]
        graph = TypedCapabilityGraph(tools)
    else:
        reg = load_workspace_registry(ws, registry_path or ".kintsugi/tool_registry.json")
        graph = TypedCapabilityGraph.from_registry(reg)
    goal = SynthesisGoal.coerce(dict(goal_payload))
    safe_path = graph.find_shortest_safe_path(
        goal.source_req,
        goal.target_req,
        sec_ctx,
        require_idempotent=goal.require_idempotent,
        allow_irreversible=goal.allow_irreversible,
        sensitivity_ceiling=goal.sensitivity_ceiling,
        permission_budget=goal.permission_budget,
    )
    blueprints = graph.detect_capability_gaps(goal, sec_ctx)
    return {
        "ok": safe_path.found,
        "goal_id": goal.goal_id,
        "safe_path": safe_path.to_dict(),
        "blueprints": [bp.to_dict() for bp in blueprints],
        "excluded_tools": {k: v.to_dict() for k, v in graph.get_excluded_tools().items()},
    }


def run_build3_smt_verify_helper(
    ws: Path,
    plan_data: Mapping[str, Any],
    *,
    tools_data: Optional[Sequence[Any]] = None,
    registry_path: Optional[str] = None,
    adapters_data: Optional[Sequence[Any]] = None,
    context_data: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Shared Build #3 SMT formal plan verifier helper used cleanly by CLI & MCP."""
    from kintsugi.capability.contracts_v2 import AdapterSpec
    from kintsugi.capability.schemas import SecurityContext, ToolSpec
    from kintsugi.composition.smt_plan_verifier import is_z3_available, verify_plan_formal

    sec_ctx = SecurityContext.from_dict(dict(context_data)) if context_data else make_security_context(ws, None)
    if tools_data is not None:
        reg_arg: Any = {
            t.tool_id: t
            for t in (item if isinstance(item, ToolSpec) else ToolSpec.from_dict(dict(item)) for item in tools_data)
        }
    else:
        reg_arg = load_workspace_registry(ws, registry_path or ".kintsugi/tool_registry.json")
    adapters = [
        item if isinstance(item, AdapterSpec) else AdapterSpec.from_dict(dict(item))
        for item in (adapters_data or ())
    ]
    bundle = verify_plan_formal(dict(plan_data), sec_ctx, registry=reg_arg, adapters=adapters)
    out = bundle.to_dict()
    out["ok"] = bool(bundle.all_proven)
    out["z3_available"] = is_z3_available()
    return out


def run_build3_asm_forge_helper(
    ws: Path,
    *,
    action: str = "info",
    kernel_name: str = "delim_scan",
) -> Dict[str, Any]:
    """Shared Build #3 ASM/NEON Forge info/build helper used cleanly by CLI & MCP."""
    from kintsugi.forge.asm_native_forge import (
        AsmNativeForge,
        build_crc32c_fnv64_kernel_spec,
        build_delim_scan_kernel_spec,
        detect_host_arch,
        resolve_asm_backend,
    )

    arch = detect_host_arch()
    backend = resolve_asm_backend(target_arch=arch)
    if action == "info":
        return {
            "ok": True,
            "arch": arch,
            "backend": backend,
            "available_kernels": ["delim_scan", "crc32c_fnv64"],
        }
    spec = build_crc32c_fnv64_kernel_spec() if kernel_name == "crc32c_fnv64" else build_delim_scan_kernel_spec()
    forge = AsmNativeForge(ws)
    res = forge.forge_kernel(spec)
    out = res.to_dict()
    out["arch"] = arch
    out["backend"] = backend
    out["ok"] = bool(res.verified)
    return out


def run_build3_evolution_v4_helper(
    ws: Path,
    payload: Mapping[str, Any],
    *,
    mode: str = "local_research",
) -> Dict[str, Any]:
    """Shared Build #3 Evolution v4 causal ablation helper used cleanly by CLI & MCP."""
    from kintsugi.evolution.evolution_v4 import EvolutionEngineV4, ExecutionMode

    exec_mode = ExecutionMode(str(mode).strip().upper())
    eng = EvolutionEngineV4(mode=exec_mode, workspace_root=ws)
    ablation = eng.evaluate_ablation_trials(
        strategy_id=str(payload.get("strategy_id") or "cli-b3-strategy"),
        revision=int(payload.get("revision", 1)),
        train_families=list(payload.get("train_families") or ()),
        heldout_families=list(payload.get("heldout_families") or ()),
        trials=list(payload.get("trials") or ()),
        extra_baseline_regressions=int(payload.get("extra_baseline_regressions", 0)),
    )
    out = ablation.to_dict()
    out["ok"] = bool(ablation.passed)
    return out


def _handle_build3_synthesize(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    goal_payload = load_workspace_json(ws, args.goal_file)
    tools_data = load_workspace_json(ws, args.tools_file) if args.tools_file else None
    ctx_data = load_workspace_json(ws, args.context_file) if args.context_file else None
    out = run_build3_synthesize_helper(
        ws,
        dict(goal_payload),
        tools_data=tools_data if isinstance(tools_data, list) else None,
        registry_path=args.registry,
        context_data=dict(ctx_data) if isinstance(ctx_data, Mapping) else None,
    )
    _print_json(out)
    return 0 if out.get("ok") or out.get("blueprints") else 1


def _handle_build3_smt_verify(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    plan_data = load_workspace_json(ws, args.plan_file)
    tools_data = load_workspace_json(ws, args.tools_file) if args.tools_file else None
    adapters_data = load_workspace_json(ws, args.adapters_file) if args.adapters_file else None
    ctx_data = load_workspace_json(ws, args.context_file) if args.context_file else None
    out = run_build3_smt_verify_helper(
        ws,
        dict(plan_data),
        tools_data=tools_data if isinstance(tools_data, list) else None,
        registry_path=args.registry,
        adapters_data=adapters_data if isinstance(adapters_data, list) else None,
        context_data=dict(ctx_data) if isinstance(ctx_data, Mapping) else None,
    )
    _print_json(out)
    return 0 if out.get("ok") else 1


def _handle_build3_asm_forge(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    out = run_build3_asm_forge_helper(ws, action=str(args.action), kernel_name=str(args.kernel))
    _print_json(out)
    return 0 if out.get("ok") else 1


def _handle_build3_evolve_v4(args: argparse.Namespace) -> int:
    ws = Path(args.workspace).resolve()
    payload = load_workspace_json(ws, args.trials_file)
    out = run_build3_evolution_v4_helper(ws, dict(payload), mode=str(args.mode))
    _print_json(out)
    return 0 if out.get("ok") else 1


def handle_evolve_v3_flags(args: argparse.Namespace) -> Optional[int]:
    """Handle Stage 5 Evolution v3 flags attached to `kintsugi evolve`. Returns exit code or None."""
    capture_trace = getattr(args, "capture_trace", None)
    do_promote = bool(getattr(args, "promote", False))
    rollback_id = getattr(args, "rollback", None)
    reg_status = bool(getattr(args, "registry_status", False))
    canary_path = getattr(args, "canary", None)
    sealed_corpus = getattr(args, "sealed_blind_corpus", None)
    sealed_sha = getattr(args, "sealed_sha256", None)
    train_corpus_path = getattr(args, "train_corpus", None)
    if not any([capture_trace, do_promote, rollback_id, reg_status, canary_path, sealed_corpus]):
        return None

    from kintsugi.evolution import SelfEvolutionEngineV3

    ws = Path(getattr(args, "workspace", ".")).resolve()
    eng = SelfEvolutionEngineV3(workspace_root=ws)
    try:
        if sealed_corpus:
            if not sealed_sha:
                _print_json(
                    {
                        "ok": False,
                        "error": "SEALED_SHA256_REQUIRED: --sealed-sha256 is required with --sealed-blind-corpus.",
                    }
                )
                return 2
            train_families: List[Dict[str, Any]] = []
            try:
                if train_corpus_path:
                    loaded_tr = load_workspace_json(ws, train_corpus_path)
                    if not isinstance(loaded_tr, list) or not all(isinstance(x, Mapping) for x in loaded_tr):
                        raise ValueError("INVALID_TRAIN_CORPUS: expected JSON list of family objects.")
                    train_families = [dict(x) for x in loaded_tr]
                report = eng.run_sealed_blind_eval(
                    sealed_corpus,
                    expected_sha256=str(sealed_sha),
                    train_families=train_families,
                )
            except (PermissionError, ValueError, OSError, json.JSONDecodeError) as exc:
                _print_json({"ok": False, "error": str(exc)})
                return 1
            rep_dict = report.to_dict()
            _print_json({"ok": True, "report": rep_dict})
            return 0 if report.parity_mismatches == 0 and report.baseline_regression_count == 0 else 1

        if reg_status:
            active_val = eng.registry.active() if callable(eng.registry.active) else eng.registry.active
            events_val = eng.registry.events() if callable(eng.registry.events) else eng.registry.events
            _print_json(
                {
                    "workspace": str(ws),
                    "hooks_intact": eng.verify_hooks_integrity(),
                    "active_rules": dict(active_val) if isinstance(active_val, Mapping) else active_val,
                    "events_count": len(events_val),
                }
            )
            return 0

        if rollback_id:
            rb = eng.rollback(str(rollback_id), to_revision=int(getattr(args, "to_revision", 1)))
            _print_json(rb)
            return 0 if rb.get("rolled_back") or rb.get("ok") else 1

        if capture_trace or do_promote:
            failure_payload: Dict[str, Any] = {}
            if capture_trace:
                loaded = load_workspace_json(ws, capture_trace)
                if isinstance(loaded, Mapping):
                    failure_payload = dict(loaded)
            else:
                failure_payload = {
                    "task_id": "cli-evolve-v3",
                    "language": getattr(args, "language", "python"),
                    "offending_snippet": getattr(args, "bad_code", ""),
                    "fixed_snippet": getattr(args, "good_code", ""),
                    "error_summary": getattr(args, "summary", "") or "CLI Evolution v3 candidate",
                }
            canary_corpus: Sequence[str] = ()
            if canary_path:
                loaded_c = load_workspace_json(ws, canary_path)
                if isinstance(loaded_c, list):
                    canary_corpus = [str(x) for x in loaded_c]
            if do_promote:
                res = eng.evolve_from_failure(
                    failure_payload,
                    rule_id=getattr(args, "rule_id", None),
                    promote_to=str(getattr(args, "mode", "shadow")),
                    reviewer_approved=bool(getattr(args, "approve", False)),
                    canary_negatives=canary_corpus,
                    persist_trace=True,
                )
                _print_json(res.to_dict())
                ok = res.stage in {"shadow", "canary", "enforced"} and res.parity_mismatches == 0
                return 0 if ok else 1

            env, trace_info = eng.ingest_failure(failure_payload, persist_trace=True)
            _print_json({"envelope": env.to_dict(), "trace": trace_info})
            return 0

        return None
    finally:
        eng.close()
